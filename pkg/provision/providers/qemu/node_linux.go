// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
	"net"

	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

func getLaunchNetworkConfig(state *vm.State, clusterReq provision.ClusterRequest, nodeReq provision.NodeRequest) networkConfig {
	return networkConfig{
		networkConfigBase: getLaunchNetworkConfigBase(state, clusterReq, nodeReq),
		NetworkConfig:     state.VMCNIConfig,
		CNI:               clusterReq.Network.CNI,
		NoMasqueradeCIDRs: clusterReq.Network.NoMasqueradeCIDRs,
		MTU:               clusterReq.Network.MTU,
		Nameservers:       clusterReq.Network.Nameservers,
	}
}

func (p *provisioner) findAPIBindAddrs(clusterReq provision.ClusterRequest) (*net.TCPAddr, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(clusterReq.Network.GatewayAddrs[0].String(), "0"))
	if err != nil {
		return nil, err
	}

	return l.Addr().(*net.TCPAddr), l.Close()
}

func waitForNode(_ context.Context, _ provision.NodeRequest) error {
	return nil
}
