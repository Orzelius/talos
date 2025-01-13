// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"fmt"
	"net/netip"

	"github.com/siderolabs/siderolink/pkg/wireguard"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

const currentOs = "linux"

func generateRandomNodeAddr(prefix netip.Prefix) (netip.Prefix, error) {
	return wireguard.GenerateRandomNodeAddr(prefix)
}

func networkPrefix(prefix string) (netip.Prefix, error) {
	return wireguard.NetworkPrefix(prefix), nil
}

func getNetworkRequest(base vm.NetworkRequestBase, qemuOps QemuOps) (req vm.NetworkRequest, err error) {
	// Parse nameservers
	nameserverIPs := make([]netip.Addr, len(qemuOps.nameservers))

	for i := range nameserverIPs {
		nameserverIPs[i], err = netip.ParseAddr(qemuOps.nameservers[i])
		if err != nil {
			return req, fmt.Errorf("failed parsing nameserver IP %q: %w", qemuOps.nameservers[i], err)
		}
	}

	noMasqueradeCIDRs := make([]netip.Prefix, 0, len(qemuOps.networkNoMasqueradeCIDRs))

	for _, cidr := range qemuOps.networkNoMasqueradeCIDRs {
		var parsedCIDR netip.Prefix

		parsedCIDR, err = netip.ParsePrefix(cidr)
		if err != nil {
			return req, fmt.Errorf("error parsing non-masquerade CIDR %q: %w", cidr, err)
		}

		noMasqueradeCIDRs = append(noMasqueradeCIDRs, parsedCIDR)
	}

	return vm.NetworkRequest{
		NetworkRequestBase: base,
		Nameservers:        nameserverIPs,
		CNI: vm.CNIConfig{
			BinPath:  qemuOps.cniBinPath,
			ConfDir:  qemuOps.cniConfDir,
			CacheDir: qemuOps.cniCacheDir,

			BundleURL: qemuOps.cniBundleURL,
		},
		DHCPSkipHostname:  qemuOps.dhcpSkipHostname,
		NetworkChaos:      qemuOps.networkChaos,
		Jitter:            qemuOps.jitter,
		Latency:           qemuOps.latency,
		PacketLoss:        qemuOps.packetLoss,
		PacketReorder:     qemuOps.packetReorder,
		PacketCorrupt:     qemuOps.packetCorrupt,
		Bandwidth:         qemuOps.bandwidth,
		NoMasqueradeCIDRs: noMasqueradeCIDRs,
	}, nil

}
