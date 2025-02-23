// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

type networkConfig struct {
	networkConfigBase
	StartAddr netip.Addr
	EndAddr   netip.Addr
}

func checkPartitions(_ *LaunchConfig) (bool, error) {
	// todo: use qemu-img with both darwin and linux
	return false, nil
}

func startQemuCmd(_ *LaunchConfig, cmd *exec.Cmd) error {
	return cmd.Start()
}

func getNetdevParams(networkConfig networkConfig, id string) string {
	netDevArg := "vmnet-shared,id=" + id
	cidr := networkConfig.CIDRs[0]
	m := net.CIDRMask(cidr.Bits(), 32)
	subnetMask := fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	netDevArg += fmt.Sprintf(",start-address=%s,end-address=%s,subnet-mask=%s", networkConfig.StartAddr, networkConfig.EndAddr, subnetMask)

	return netDevArg
}

// withNetworkContext on darwin runs the f on the host network.
func withNetworkContext(_ context.Context, config *LaunchConfig, f func(config *LaunchConfig) error) error {
	return f(config)
}

// getConfigServerAddr returns the ip of the config file accessible to the VM.
// hostAddrs is the address on which the server is accessible from the host network.
func getConfigServerAddr(hostAddrs net.Addr, config LaunchConfig) (net.Addr, error) {
	split := strings.Split(hostAddrs.String(), ":")
	port := split[len(split)-1]
	gateway := config.Network.GatewayAddrs[0]

	addr, err := net.ResolveTCPAddr("tcp", gateway.String()+":"+port)
	if err != nil {
		return nil, fmt.Errorf("failed resolving config server address: %e", err)
	}

	return addr, err
}
