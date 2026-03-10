// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package maven

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	packages_model "code.gitea.io/gitea/models/packages"
	"code.gitea.io/gitea/modules/globallock"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	packages_module "code.gitea.io/gitea/modules/packages"
	maven_module "code.gitea.io/gitea/modules/packages/maven"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/routers/api/packages/helper"
	"code.gitea.io/gitea/services/context"
	packages_service "code.gitea.io/gitea/services/packages"
)

const (
	mavenMetadataFile = "maven-metadata.xml"
	extensionMD5      = ".md5"
	extensionSHA1     = ".sha1"
	extensionSHA256   = ".sha256"
	extensionSHA512   = ".sha512"
	extensionPom      = ".pom"
	extensionJar      = ".jar"
	contentTypeJar    = "application/java-archive"
	contentTypeXML    = "text/xml"
)

var (
	errInvalidParameters = errors.New("request parameters are invalid")
	illegalCharacters    = regexp.MustCompile(`[\\/:"<>|?*]`)

	// upstreamHTTPClient is used for all upstream proxy requests with a reasonable timeout
	upstreamHTTPClient = &http.Client{
		Timeout: 60 * time.Second,
	}
)

func apiError(ctx *context.Context, status int, obj any) {
	message := helper.ProcessErrorForUser(ctx, status, obj)
	// Maven client doesn't present the error message to end users; site admin can check the server logs that outputted by ProcessErrorForUser
	ctx.PlainText(status, message)
}

// DownloadPackageFile serves the content of a package
func DownloadPackageFile(ctx *context.Context) {
	handlePackageFile(ctx, true)
}

// ProvidePackageFileHeader provides only the headers describing a package
func ProvidePackageFileHeader(ctx *context.Context) {
	handlePackageFile(ctx, false)
}

func handlePackageFile(ctx *context.Context, serveContent bool) {
	params, err := extractPathParameters(ctx)
	if err != nil {
		apiError(ctx, http.StatusBadRequest, err)
		return
	}

	if params.IsMeta && params.Version == "" {
		serveMavenMetadata(ctx, params)
	} else {
		servePackageFile(ctx, params, serveContent)
	}
}

func serveMavenMetadata(ctx *context.Context, params parameters) {
	// path pattern: /com/foo/project/maven-metadata.xml[.md5/.sha1/.sha256/.sha512]
	// in case there are legacy package names ("GroupID-ArtifactID") we need to check both, new packages always use ":" as separator("GroupID:ArtifactID")
	pvsLegacy, err := packages_model.GetVersionsByPackageName(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, params.toInternalPackageNameLegacy())
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	pvs, err := packages_model.GetVersionsByPackageName(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, params.toInternalPackageName())
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	pvs = append(pvsLegacy, pvs...)

	if len(pvs) == 0 {
		// Try upstream proxy if enabled
		if tryServeFromUpstream(ctx, params) {
			return
		}
		apiError(ctx, http.StatusNotFound, packages_model.ErrPackageNotExist)
		return
	}

	pds, err := packages_model.GetPackageDescriptors(ctx, pvs)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	sort.Slice(pds, func(i, j int) bool {
		// Maven and Gradle order packages by their creation timestamp and not by their version string
		return pds[i].Version.CreatedUnix < pds[j].Version.CreatedUnix
	})

	xmlMetadata, err := xml.Marshal(createMetadataResponse(pds, params.GroupID, params.ArtifactID))
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	xmlMetadataWithHeader := append([]byte(xml.Header), xmlMetadata...)

	latest := pds[len(pds)-1]
	// http.TimeFormat required a UTC time, refer to https://pkg.go.dev/net/http#TimeFormat
	lastModified := latest.Version.CreatedUnix.AsTime().UTC().Format(http.TimeFormat)
	ctx.Resp.Header().Set("Last-Modified", lastModified)

	ext := strings.ToLower(path.Ext(params.Filename))
	if isChecksumExtension(ext) {
		var hash []byte
		switch ext {
		case extensionMD5:
			tmp := md5.Sum(xmlMetadataWithHeader)
			hash = tmp[:]
		case extensionSHA1:
			tmp := sha1.Sum(xmlMetadataWithHeader)
			hash = tmp[:]
		case extensionSHA256:
			tmp := sha256.Sum256(xmlMetadataWithHeader)
			hash = tmp[:]
		case extensionSHA512:
			tmp := sha512.Sum512(xmlMetadataWithHeader)
			hash = tmp[:]
		}
		ctx.PlainText(http.StatusOK, hex.EncodeToString(hash))
		return
	}

	ctx.Resp.Header().Set("Content-Length", strconv.Itoa(len(xmlMetadataWithHeader)))
	ctx.Resp.Header().Set("Content-Type", contentTypeXML)

	_, _ = ctx.Resp.Write(xmlMetadataWithHeader)
}

func servePackageFile(ctx *context.Context, params parameters, serveContent bool) {
	pv, err := packages_model.GetVersionByNameAndVersion(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, params.toInternalPackageName(), params.Version)
	if errors.Is(err, util.ErrNotExist) {
		pv, err = packages_model.GetVersionByNameAndVersion(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, params.toInternalPackageNameLegacy(), params.Version)
	}
	if err != nil {
		if errors.Is(err, packages_model.ErrPackageNotExist) {
			// Try upstream proxy if enabled
			if tryFetchAndCacheFromUpstream(ctx, params, serveContent) {
				return
			}
			apiError(ctx, http.StatusNotFound, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	filename := params.Filename

	ext := strings.ToLower(path.Ext(filename))
	if isChecksumExtension(ext) {
		filename = filename[:len(filename)-len(ext)]
	}

	pf, err := packages_model.GetFileForVersionByName(ctx, pv.ID, filename, packages_model.EmptyFileKey)
	if err != nil {
		if errors.Is(err, packages_model.ErrPackageFileNotExist) {
			apiError(ctx, http.StatusNotFound, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	pb, err := packages_model.GetBlobByID(ctx, pf.BlobID)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	if isChecksumExtension(ext) {
		var hash string
		switch ext {
		case extensionMD5:
			hash = pb.HashMD5
		case extensionSHA1:
			hash = pb.HashSHA1
		case extensionSHA256:
			hash = pb.HashSHA256
		case extensionSHA512:
			hash = pb.HashSHA512
		}
		ctx.PlainText(http.StatusOK, hash)
		return
	}

	opts := &context.ServeHeaderOptions{
		ContentLength: &pb.Size,
		LastModified:  pf.CreatedUnix.AsLocalTime(),
	}
	switch ext {
	case extensionJar:
		opts.ContentType = contentTypeJar
	case extensionPom:
		opts.ContentType = contentTypeXML
	}

	if !serveContent {
		ctx.SetServeHeaders(opts)
		ctx.Status(http.StatusOK)
		return
	}

	s, u, _, err := packages_service.OpenBlobForDownload(ctx, pf, pb, ctx.Req.Method, nil)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	opts.Filename = pf.Name

	helper.ServePackageFile(ctx, s, u, pf, opts)
}

// buildUpstreamURL constructs the upstream URL for the given request path
func buildUpstreamURL(upstreamBase, requestPath string) string {
	upstreamBase = strings.TrimRight(upstreamBase, "/")
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	return upstreamBase + requestPath
}

// tryServeFromUpstream attempts to serve a metadata file from the upstream Maven repository.
// It returns true if the response was handled (either served or error written), false if upstream is disabled/unavailable.
func tryServeFromUpstream(ctx *context.Context, params parameters) bool {
	mavenProxy := setting.Config().Packages.MavenProxy.Value(ctx)
	if !mavenProxy.Enabled || mavenProxy.UpstreamURL == "" {
		return false
	}

	// Build the upstream path from the request
	reqPath := ctx.PathParam("*")
	if reqPath == "" {
		return false
	}
	upstreamURL := buildUpstreamURL(mavenProxy.UpstreamURL, reqPath)

	resp, err := upstreamHTTPClient.Get(upstreamURL) //nolint:gosec
	if err != nil {
		log.Warn("Maven upstream proxy: failed to fetch %s: %v", upstreamURL, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug("Maven upstream proxy: upstream returned %d for %s", resp.StatusCode, upstreamURL)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Warn("Maven upstream proxy: failed to read response from %s: %v", upstreamURL, err)
		return false
	}

	ext := strings.ToLower(path.Ext(params.Filename))
	if isChecksumExtension(ext) {
		ctx.PlainText(http.StatusOK, strings.TrimSpace(string(body)))
		return true
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		ctx.Resp.Header().Set("Content-Type", contentType)
	} else {
		ctx.Resp.Header().Set("Content-Type", contentTypeXML)
	}
	ctx.Resp.Header().Set("Content-Length", strconv.Itoa(len(body)))
	ctx.Resp.WriteHeader(http.StatusOK)
	_, _ = ctx.Resp.Write(body)
	return true
}

// tryFetchAndCacheFromUpstream attempts to fetch a package file from the upstream Maven repository,
// caches it locally, and serves it. Returns true if the response was handled.
func tryFetchAndCacheFromUpstream(ctx *context.Context, params parameters, serveContent bool) bool {
	mavenProxy := setting.Config().Packages.MavenProxy.Value(ctx)
	if !mavenProxy.Enabled || mavenProxy.UpstreamURL == "" {
		return false
	}

	reqPath := ctx.PathParam("*")
	if reqPath == "" {
		return false
	}

	ext := strings.ToLower(path.Ext(params.Filename))

	// For checksum files, derive the base file path and serve the checksum from upstream directly
	if isChecksumExtension(ext) {
		upstreamURL := buildUpstreamURL(mavenProxy.UpstreamURL, reqPath)
		resp, err := upstreamHTTPClient.Get(upstreamURL) //nolint:gosec
		if err != nil {
			log.Warn("Maven upstream proxy: failed to fetch checksum %s: %v", upstreamURL, err)
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		ctx.PlainText(http.StatusOK, strings.TrimSpace(string(body)))
		return true
	}

	packageName := params.toInternalPackageName()

	// Use a lock to prevent concurrent fetches of the same package
	releaser, err := globallock.Lock(ctx, mavenPkgNameKey(packageName))
	if err != nil {
		log.Error("Maven upstream proxy: failed to acquire lock for %s, cannot fetch from upstream: %v", packageName, err)
		return false
	}
	defer releaser()

	// Check again after acquiring lock in case another goroutine already cached it
	pv, err := packages_model.GetVersionByNameAndVersion(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, packageName, params.Version)
	if err == nil {
		// Package was cached by another request; fall through to serve it
		filename := params.Filename
		if isChecksumExtension(ext) {
			filename = filename[:len(filename)-len(ext)]
		}
		pf, err := packages_model.GetFileForVersionByName(ctx, pv.ID, filename, packages_model.EmptyFileKey)
		if err == nil {
			pb, err := packages_model.GetBlobByID(ctx, pf.BlobID)
			if err == nil {
				serveLocalFile(ctx, pf, pb, ext, serveContent)
				return true
			}
		}
	}

	// Fetch the file from upstream (without checksum extension)
	baseFilename := params.Filename
	baseFilePath := reqPath
	upstreamURL := buildUpstreamURL(mavenProxy.UpstreamURL, baseFilePath)

	resp, err := upstreamHTTPClient.Get(upstreamURL) //nolint:gosec
	if err != nil {
		log.Warn("Maven upstream proxy: failed to fetch %s: %v", upstreamURL, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug("Maven upstream proxy: upstream returned %d for %s", resp.StatusCode, upstreamURL)
		return false
	}

	buf, err := packages_module.CreateHashedBufferFromReader(resp.Body)
	if err != nil {
		log.Error("Maven upstream proxy: failed to create hashed buffer for %s: %v", upstreamURL, err)
		return false
	}
	defer buf.Close()

	pvci := &packages_service.PackageCreationInfo{
		PackageInfo: packages_service.PackageInfo{
			Owner:       ctx.Package.Owner,
			PackageType: packages_model.TypeMaven,
			Name:        packageName,
			Version:     params.Version,
		},
		SemverCompatible: false,
		Creator:          ctx.Package.Owner,
	}

	pfci := &packages_service.PackageFileCreationInfo{
		PackageFileInfo: packages_service.PackageFileInfo{
			Filename: baseFilename,
		},
		Creator:           ctx.Package.Owner,
		Data:              buf,
		IsLead:            false,
		OverwriteExisting: false,
	}

	// Parse POM metadata if applicable
	if path.Ext(baseFilename) == extensionPom {
		pfci.IsLead = true
		pvci.Metadata, err = maven_module.ParsePackageMetaData(buf)
		if err != nil {
			log.Warn("Maven upstream proxy: failed to parse POM metadata for %s: %v", upstreamURL, err)
			// Continue without metadata
			pvci.Metadata = nil
		}
		if _, err = buf.Seek(0, io.SeekStart); err != nil {
			log.Error("Maven upstream proxy: failed to seek buffer for %s: %v", upstreamURL, err)
			return false
		}
	}

	_, pf, err := packages_service.CreatePackageOrAddFileToExisting(ctx, pvci, pfci)
	if err != nil {
		if err != packages_model.ErrDuplicatePackageFile {
			log.Error("Maven upstream proxy: failed to cache package file %s: %v", upstreamURL, err)
		}
		return false
	}

	pb, err := packages_model.GetBlobByID(ctx, pf.BlobID)
	if err != nil {
		log.Error("Maven upstream proxy: failed to get blob for cached file %s: %v", upstreamURL, err)
		return false
	}

	serveLocalFile(ctx, pf, pb, ext, serveContent)
	return true
}

// serveLocalFile serves a package file from local storage
func serveLocalFile(ctx *context.Context, pf *packages_model.PackageFile, pb *packages_model.PackageBlob, ext string, serveContent bool) {
	opts := &context.ServeHeaderOptions{
		ContentLength: &pb.Size,
		LastModified:  pf.CreatedUnix.AsLocalTime(),
	}
	switch ext {
	case extensionJar:
		opts.ContentType = contentTypeJar
	case extensionPom:
		opts.ContentType = contentTypeXML
	}

	if !serveContent {
		ctx.SetServeHeaders(opts)
		ctx.Status(http.StatusOK)
		return
	}

	s, u, _, err := packages_service.OpenBlobForDownload(ctx, pf, pb, ctx.Req.Method, nil)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	opts.Filename = pf.Name
	helper.ServePackageFile(ctx, s, u, pf, opts)
}

func mavenPkgNameKey(packageName string) string {
	return "pkg_maven_" + packageName
}

// UploadPackageFile adds a file to the package. If the package does not exist, it gets created.
func UploadPackageFile(ctx *context.Context) {
	params, err := extractPathParameters(ctx)
	if err != nil {
		apiError(ctx, http.StatusBadRequest, err)
		return
	}

	// Ignore the package index /<name>/maven-metadata.xml
	if params.IsMeta && params.Version == "" {
		ctx.Status(http.StatusOK)
		return
	}

	packageName := params.toInternalPackageName()
	if ctx.FormBool("use_legacy_package_name") {
		// for testing purpose only
		packageName = params.toInternalPackageNameLegacy()
	}

	// for the same package, only one upload at a time
	releaser, err := globallock.Lock(ctx, mavenPkgNameKey(packageName))
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	defer releaser()

	buf, err := packages_module.CreateHashedBufferFromReader(ctx.Req.Body)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	defer buf.Close()

	pvci := &packages_service.PackageCreationInfo{
		PackageInfo: packages_service.PackageInfo{
			Owner:       ctx.Package.Owner,
			PackageType: packages_model.TypeMaven,
			Name:        packageName,
			Version:     params.Version,
		},
		SemverCompatible: false,
		Creator:          ctx.Doer,
	}

	// old maven package uses "groupId-artifactId" as package name, so we need to update to the new format "groupId:artifactId"
	legacyPackage, err := packages_model.GetPackageByName(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, params.toInternalPackageNameLegacy())
	if err != nil && !errors.Is(err, packages_model.ErrPackageNotExist) {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	} else if legacyPackage != nil {
		err = packages_model.UpdatePackageNameByID(ctx, ctx.Package.Owner.ID, packages_model.TypeMaven, legacyPackage.ID, packageName)
		if err != nil {
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}
	}

	ext := path.Ext(params.Filename)

	// Do not upload checksum files but compare the hashes.
	if isChecksumExtension(ext) {
		pv, err := packages_model.GetVersionByNameAndVersion(ctx, pvci.Owner.ID, pvci.PackageType, pvci.Name, pvci.Version)
		if err != nil {
			if errors.Is(err, packages_model.ErrPackageNotExist) {
				apiError(ctx, http.StatusNotFound, err)
				return
			}
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}
		pf, err := packages_model.GetFileForVersionByName(ctx, pv.ID, params.Filename[:len(params.Filename)-len(ext)], packages_model.EmptyFileKey)
		if err != nil {
			if errors.Is(err, packages_model.ErrPackageFileNotExist) {
				apiError(ctx, http.StatusNotFound, err)
				return
			}
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}
		pb, err := packages_model.GetBlobByID(ctx, pf.BlobID)
		if err != nil {
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}

		hash, err := io.ReadAll(buf)
		if err != nil {
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}

		if (ext == extensionMD5 && pb.HashMD5 != string(hash)) ||
			(ext == extensionSHA1 && pb.HashSHA1 != string(hash)) ||
			(ext == extensionSHA256 && pb.HashSHA256 != string(hash)) ||
			(ext == extensionSHA512 && pb.HashSHA512 != string(hash)) {
			apiError(ctx, http.StatusBadRequest, "hash mismatch")
			return
		}

		ctx.Status(http.StatusOK)
		return
	}

	pfci := &packages_service.PackageFileCreationInfo{
		PackageFileInfo: packages_service.PackageFileInfo{
			Filename: params.Filename,
		},
		Creator:           ctx.Doer,
		Data:              buf,
		IsLead:            false,
		OverwriteExisting: params.IsMeta,
	}

	// If it's the package pom file extract the metadata
	if ext == extensionPom {
		pfci.IsLead = true

		var err error
		pvci.Metadata, err = maven_module.ParsePackageMetaData(buf)
		if err != nil {
			apiError(ctx, http.StatusBadRequest, err)
			return
		}

		if pvci.Metadata != nil {
			pv, err := packages_model.GetVersionByNameAndVersion(ctx, pvci.Owner.ID, pvci.PackageType, pvci.Name, pvci.Version)
			if err != nil && !errors.Is(err, packages_model.ErrPackageNotExist) {
				apiError(ctx, http.StatusInternalServerError, err)
				return
			}
			if pv != nil {
				raw, err := json.Marshal(pvci.Metadata)
				if err != nil {
					apiError(ctx, http.StatusInternalServerError, err)
					return
				}
				pv.MetadataJSON = string(raw)
				if err := packages_model.UpdateVersion(ctx, pv); err != nil {
					apiError(ctx, http.StatusInternalServerError, err)
					return
				}
			}
		}

		if _, err := buf.Seek(0, io.SeekStart); err != nil {
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}
	}

	_, _, err = packages_service.CreatePackageOrAddFileToExisting(
		ctx,
		pvci,
		pfci,
	)
	if err != nil {
		switch err {
		case packages_model.ErrDuplicatePackageFile:
			apiError(ctx, http.StatusConflict, err)
		case packages_service.ErrQuotaTotalCount, packages_service.ErrQuotaTypeSize, packages_service.ErrQuotaTotalSize:
			apiError(ctx, http.StatusForbidden, err)
		default:
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusCreated)
}

func isChecksumExtension(ext string) bool {
	return ext == extensionMD5 || ext == extensionSHA1 || ext == extensionSHA256 || ext == extensionSHA512
}

type parameters struct {
	GroupID    string
	ArtifactID string
	Version    string
	Filename   string
	IsMeta     bool
}

func (p *parameters) toInternalPackageName() string {
	// there cuold be 2 choices: "/" or ":"
	// Maven says: "groupId:artifactId:version" in their document: https://maven.apache.org/pom.html#Maven_Coordinates
	// but it would be slightly ugly in URL: "/-/packages/maven/group-id%3Aartifact-id"
	return p.GroupID + ":" + p.ArtifactID
}

func (p *parameters) toInternalPackageNameLegacy() string {
	return p.GroupID + "-" + p.ArtifactID
}

func extractPathParameters(ctx *context.Context) (parameters, error) {
	parts := strings.Split(ctx.PathParam("*"), "/")

	// formats:
	// * /com/group/id/artifactId/maven-metadata.xml[.md5|.sha1|.sha256|.sha512]
	// * /com/group/id/artifactId/version-SNAPSHOT/maven-metadata.xml[.md5|.sha1|.sha256|.sha512]
	// * /com/group/id/artifactId/version/any-file
	// * /com/group/id/artifactId/version-SNAPSHOT/any-file

	p := parameters{
		Filename: parts[len(parts)-1],
	}

	p.IsMeta = p.Filename == mavenMetadataFile ||
		p.Filename == mavenMetadataFile+extensionMD5 ||
		p.Filename == mavenMetadataFile+extensionSHA1 ||
		p.Filename == mavenMetadataFile+extensionSHA256 ||
		p.Filename == mavenMetadataFile+extensionSHA512

	parts = parts[:len(parts)-1]
	if len(parts) == 0 {
		return p, errInvalidParameters
	}

	p.Version = parts[len(parts)-1]
	if p.IsMeta && !strings.HasSuffix(p.Version, "-SNAPSHOT") {
		p.Version = ""
	} else {
		parts = parts[:len(parts)-1]
	}

	if illegalCharacters.MatchString(p.Version) {
		return p, errInvalidParameters
	}

	if len(parts) < 2 {
		return p, errInvalidParameters
	}

	p.ArtifactID = parts[len(parts)-1]
	p.GroupID = strings.Join(parts[:len(parts)-1], ".")

	if illegalCharacters.MatchString(p.GroupID) || illegalCharacters.MatchString(p.ArtifactID) {
		return p, errInvalidParameters
	}

	return p, nil
}
