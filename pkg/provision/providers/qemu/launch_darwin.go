// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"go4.org/netipx"
)

type platformOps struct {
	// NetworkInitNode is the node that initialized the qemu network that other nodes join
	NetworkInitNode bool
}

// withNetworkContext on darwin just runs the f on the host network
func withNetworkContext(ctx context.Context, config *LaunchConfig, f func(config *LaunchConfig) error) error {
	config.VmMAC = getRandomMacAddress()
	return f(config)
}

func checkPartitions(config *LaunchConfig) (bool, error) {
	// todo: use qemu-img with both darwin and linux
	return false, nil
}

func cmdStartQemu(config *LaunchConfig, cmd *exec.Cmd) error {
	return cmd.Start()
}

func getPlatformSpecificArgs(config LaunchConfig) (args []string, err error) {
	netDevArg := "vmnet-shared,id=net0"
	if config.PlatformOps.NetworkInitNode {
		cidr := config.CIDRs[0]
		ipnet := netipx.PrefixIPNet(cidr)
		ip := ipnet.IP.To4()
		mask := net.IP(ipnet.Mask).To4()
		n := len(ip)
		broadcast := make(net.IP, n)
		for i := range n {
			broadcast[i] = ip[i] | ^mask[i]
		}
		m := net.CIDRMask(cidr.Bits(), 32)
		subnetMask := fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
		// This ip will be assigned to the bridge
		// The following ips will be assigned to the vms
		startAddr := config.IPs[0].Prev()
		netDevArg += fmt.Sprintf(",start-address=%s,end-address=%s,subnet-mask=%s", startAddr, broadcast, subnetMask)
	}
	args = []string{"-netdev", netDevArg}
	args = append(args, config.ArchitectureData.MachineArgs(MachineArgsParams{kvmEnabled: false, hvfEnabled: true})...)

	return args, nil
}

// getConfigServerAddr returns the ip of the config file accessible to the VM
// hostAddrs is the address on which the server is accessible from the host network
func getConfigServerAddr(hostAddrs net.Addr, config LaunchConfig) (net.Addr, error) {
	split := strings.Split(hostAddrs.String(), ":")
	port := split[len(split)-1]
	gateway := config.IPs[0].Prev() // has access to host through this IP
	addr, err := net.ResolveTCPAddr("tcp", gateway.String()+":"+port)
	if err != nil {
		return nil, fmt.Errorf("failed resolving config server address: %e", err)
	}
	return addr, err
}

// getRandomMacAddress generates a random local MAC address
// https://stackoverflow.com/a/21027407/10938317
func getRandomMacAddress() string {
	const (
		local     = 0b10
		multicast = 0b1
	)

	buf := make([]byte, 6)
	rand.Read(buf)
	// clear multicast bit (&^), ensure local bit (|)
	buf[0] = buf[0]&^multicast | local
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}
