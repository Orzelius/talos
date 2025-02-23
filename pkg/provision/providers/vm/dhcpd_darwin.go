// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"os"

	"github.com/siderolabs/talos/pkg/provision"
)

// CreateDHCPd does nothing on darwin.
func (p *Provisioner) CreateDHCPd(state *State, clusterReq provision.ClusterRequest) error {
	return nil
}

// DestroyDHCPd does nothing on darwin.
func (p *Provisioner) DestroyDHCPd(state *State) error {
	var ips []string

	for _, n := range state.ClusterInfo.Nodes {
		for _, ip := range n.IPs {
			ips = append(ips, ip.String())
		}
	}

	data, err := os.ReadFile("/var/db/dhcpd_leases")
	if err != nil {
		return err
	}

	updated, err := removeIpBindings(string(data), ips)
	if err != nil {
		return err
	}

	err = os.WriteFile("/var/db/dhcpd_leases", []byte(updated), 0o644)
	if err != nil {
		return err
	}

	return nil
}
