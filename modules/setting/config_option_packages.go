// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"code.gitea.io/gitea/modules/setting/config"
)

// MavenProxyType holds settings for Maven upstream proxy
type MavenProxyType struct {
	Enabled     bool
	UpstreamURL string
}

type PackagesStruct struct {
	MavenProxy *config.Option[MavenProxyType]
}
