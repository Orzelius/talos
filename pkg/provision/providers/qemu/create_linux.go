// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

func getPlatformClusterInfo(request vm.ClusterRequest, base provision.ClusterInfo) provision.ClusterInfo {
	base.Network.NoMasqueradeCIDRs = request.Network.NoMasqueradeCIDRs
	return base
}
