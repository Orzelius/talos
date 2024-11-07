// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"github.com/siderolabs/talos/pkg/provision"
)

// CreateDHCPd creates DHCPd.
func (p *Provisioner) CreateDHCPd(state *State, clusterReq provision.ClusterRequest) error {

	return nil
}

// DestroyDHCPd destoys load balancer.
func (p *Provisioner) DestroyDHCPd(state *State) error {
	return nil
}
