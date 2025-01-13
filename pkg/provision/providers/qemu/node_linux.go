// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

func (p *QemuProvisioner) findAPIBind(clusterReq vm.ClusterRequest) (*net.TCPAddr, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(clusterReq.Network.GatewayAddrs[0].String(), "0"))
	if err != nil {
		return nil, err
	}

	return l.Addr().(*net.TCPAddr), l.Close()
}

// addPlatformOpts returns a modified launchConfig based on platform specific options
func addPlatformOpts(clusterReq vm.ClusterRequest, launchConfig LaunchConfig, nodeReq vm.NodeRequest, opts provision.Options) (LaunchConfig, error) {
	if clusterReq.Network.DHCPSkipHostname {
		launchConfig.Hostname = ""
	}

	kvmErr := checkKVM()
	if kvmErr != nil {
		fmt.Println(kvmErr)
		fmt.Println("running without KVM")
	}
	platformOps := platformOps{
		Nameservers:       clusterReq.Network.Nameservers,
		CNI:               clusterReq.Network.CNI,
		MTU:               clusterReq.Network.MTU,
		NoMasqueradeCIDRs: clusterReq.Network.NoMasqueradeCIDRs,
		EnableKVM:         kvmErr == nil && opts.TargetArch == runtime.GOARCH,
	}

	launchConfig.PlatformOps = platformOps

	return launchConfig, nil
}

func checkKVM() (err error) {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("error opening /dev/kvm, please make sure KVM support is enabled in Linux kernel: %w", err)
	}
	return nil
}
