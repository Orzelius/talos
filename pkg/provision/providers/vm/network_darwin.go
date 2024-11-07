// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"context"
	"fmt"

	"github.com/siderolabs/talos/pkg/provision"
)

// CreateNetwork builds bridge interface name by taking part of checksum of the network name
// so that interface name is defined by network name, and different networks have
// different bridge interfaces.
//
//nolint:gocyclo
func (p *Provisioner) CreateNetwork(ctx context.Context, state *State, network provision.NetworkRequest, options provision.Options) error {
	fmt.Println("CreateNetwork() called")
	return nil
}

// DestroyNetwork destroy bridge interface by name to clean up.
func (p *Provisioner) DestroyNetwork(state *State) error {
	fmt.Println("DestroyNetwork() called")
	return nil
}
