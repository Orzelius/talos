// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package docker implements Provisioner via docker.
package vm

import (
	"github.com/google/uuid"
	"github.com/siderolabs/gen/xslices"
	"github.com/siderolabs/go-procfs/procfs"
	"github.com/siderolabs/talos/pkg/machinery/config/types/v1alpha1"
	"github.com/siderolabs/talos/pkg/provision"
)

type ClusterRequest struct {
	provision.ClusterRequestBase

	Network NetworkRequest
	Nodes   NodeRequests

	// Boot options
	KernelPath     string
	InitramfsPath  string
	ISOPath        string
	DiskImagePath  string
	IPXEBootScript string

	// Encryption
	KMSEndpoint       string
	SiderolinkRequest provision.SiderolinkRequest
}

// ConfigInjectionMethod describes how to inject configuration into the node.
type ConfigInjectionMethod int

const (
	// ConfigInjectionMethodHTTP injects configuration via HTTP.
	ConfigInjectionMethodHTTP ConfigInjectionMethod = iota
	// ConfigInjectionMethodMetalISO injects configuration via Metal ISO.
	ConfigInjectionMethodMetalISO
)

// Disk represents a disk size and name in NodeRequest.
type Disk struct {
	// Size in bytes.
	Size uint64
	// Whether to skip preallocating the disk space.
	SkipPreallocate bool
	// Partitions represents the list of partitions.
	Partitions []*v1alpha1.DiskPartition
	// Driver for the disk.
	//
	// Supported types: "virtio", "ide", "ahci", "scsi", "nvme".
	Driver string
}

type NodeRequests []NodeRequest

func (n NodeRequests) GetBase() provision.BaseNodeRequests {
	base := xslices.Map(n, func(n NodeRequest) provision.NodeRequestBase {
		return provision.NodeRequestBase(n.NodeRequestBase.NodeRequestBase)
	})
	return provision.BaseNodeRequests(base)
}

// PXENodes returns subset of nodes which are PXE booted.
func (reqs NodeRequests) PXENodes() (nodes NodeRequests) {
	for i := range reqs {
		if reqs[i].PXEBooted {
			nodes = append(nodes, reqs[i])
		}
	}

	return
}

// TODO: think of a different name: currently it's a layer 2 base
type NodeRequestBase struct {
	provision.NodeRequestBase

	ConfigInjectionMethod ConfigInjectionMethod
	// Disks (volumes), if applicable (VM only)
	Disks []*Disk

	// DefaultBootOrder overrides default boot order "cn" (disk, then network boot).
	//
	// BootOrder can be forced to be "nc" (PXE boot) via the API in QEMU provisioner.
	DefaultBootOrder string

	// ExtraKernelArgs passes additional kernel args
	// to the initial boot from initramfs and vmlinuz.
	//
	// This doesn't apply to boots from ISO or from the disk image.
	ExtraKernelArgs *procfs.Cmdline

	// UUID allows to specify the UUID of the node (VMs only).
	//
	// If not specified, a random UUID will be generated.
	UUID *uuid.UUID

	// Testing features

	// BadRTC resets RTC to well known time in the past (QEMU provisioner).
	BadRTC bool

	// PXE-booted VMs
	PXEBooted        bool
	TFTPServer       string
	IPXEBootFilename string
}

// TODO: think of a different name: currently it's a layer 2 base
type NetworkRequestBase struct {
	provision.NetworkRequestBase
	LoadBalancerPorts []int
}
