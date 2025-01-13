// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package docker implements Provisioner via docker.
package docker

import (
	"net/netip"

	mounttypes "github.com/docker/docker/api/types/mount"
	"github.com/siderolabs/talos/pkg/provision"
)

type ClusterRequest struct {
	provision.ClusterRequestBase

	// Docker specific parameters.
	Image   string
	Network NetworkRequest
	Nodes   NodeRequests
}

type NodeRequests []NodeRequest

type NodeRequest struct {
	provision.NodeRequestBase

	Mounts []mounttypes.Mount
	Ports  []string
	IPs    []netip.Addr
}

type NetworkRequest struct {
	provision.NetworkRequestBase

	DockerDisableIPv6 bool
}
