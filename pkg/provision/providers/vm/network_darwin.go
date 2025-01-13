// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"context"

	"github.com/siderolabs/talos/pkg/provision"
)

// CreateNetwork
func (p *Provisioner) CreateNetwork(ctx context.Context, state *State, network NetworkRequest, options provision.Options) error {
	return nil
}

// DestroyNetwork destroy bridge interface by name to clean up.
func (p *Provisioner) DestroyNetwork(state *State) error {
	return nil
}
