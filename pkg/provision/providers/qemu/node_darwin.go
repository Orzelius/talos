// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/siderolabs/go-retry/retry"

	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

func getLaunchNetworkConfig(state *vm.State, clusterReq provision.ClusterRequest, nodeReq provision.NodeRequest) networkConfig {
	// This ip will be assigned to the bridge
	// The following ips will be assigned to the vms
	startAddr := clusterReq.Nodes[0].IPs[0].Prev()
	endAddr := clusterReq.Nodes[len(clusterReq.Nodes)-1].IPs[0].Next()

	return networkConfig{
		networkConfigBase: getLaunchNetworkConfigBase(state, clusterReq, nodeReq),
		StartAddr:         startAddr,
		EndAddr:           endAddr,
	}
}

func (p *provisioner) findAPIBindAddrs(_ provision.ClusterRequest) (*net.TCPAddr, error) {
	l, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", "0"))
	if err != nil {
		return nil, err
	}

	return l.Addr().(*net.TCPAddr), l.Close()
}

func waitForNode(ctx context.Context, node provision.NodeRequest) error {
	return retry.Constant(2*time.Minute, retry.WithUnits(500*time.Millisecond)).RetryWithContext(ctx, func(ctx context.Context) error {
		data, err := os.ReadFile("/var/db/dhcpd_leases")
		if err != nil {
			// file has not been created yet
			return retry.ExpectedError(err)
		}

		if !strings.Contains(string(data), "ip_address="+node.IPs[0].String()) {
			return retry.ExpectedError(fmt.Errorf("node %s has not been assigned an ip", node.Name))
		}

		return nil
	})
}
