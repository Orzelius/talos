// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"net"

	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

func (p *QemuProvisioner) findAPIBind(clusterReq vm.ClusterRequest) (*net.TCPAddr, error) {
	l, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", "0"))
	if err != nil {
		return nil, err
	}

	return l.Addr().(*net.TCPAddr), l.Close()
}

// addPlatformOpts returns a modified launchConfig based on platform specific options
func addPlatformOpts(clusterReq vm.ClusterRequest, launchConfig LaunchConfig, nodeReq vm.NodeRequest, opts provision.Options) (LaunchConfig, error) {
	if nodeReq.Index == 0 {
		launchConfig.PlatformOps.NetworkInitNode = true
	}
	return launchConfig, nil
}
