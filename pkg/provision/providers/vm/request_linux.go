// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"net/netip"
	"time"
)

// NetworkRequest describes cluster network.
type NetworkRequest struct {
	NetworkRequestBase

	MTU               int
	Nameservers       []netip.Addr
	NoMasqueradeCIDRs []netip.Prefix

	// CNI-specific parameters.
	CNI CNIConfig

	// DHCP options
	DHCPSkipHostname bool

	// Network chaos parameters.
	NetworkChaos  bool
	Jitter        time.Duration
	Latency       time.Duration
	PacketLoss    float64
	PacketReorder float64
	PacketCorrupt float64
	Bandwidth     int
}

type NodeRequest struct {
	NodeRequestBase
	IPs []netip.Addr
}

// CNIConfig describes CNI part of NetworkRequest.
type CNIConfig struct {
	BinPath  []string
	ConfDir  string
	CacheDir string

	BundleURL string
}
