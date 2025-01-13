// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !linux

package create

import (
	"errors"
	"net/netip"

	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

const currentOs = "darwin"

func generateRandomNodeAddr(prefix netip.Prefix) (netip.Prefix, error) {
	return netip.Prefix{}, nil
}

func networkPrefix(prefix string) (netip.Prefix, error) {
	return netip.Prefix{}, errors.New("unsupported platform")
}

func getNetworkRequest(base vm.NetworkRequestBase, qemuOps QemuOps) (req vm.NetworkRequest, err error) {
	return vm.NetworkRequest{
		NetworkRequestBase: base,
	}, nil
}