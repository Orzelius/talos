// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package cluster implements "cluster" subcommands.
package cluster

import (
	"path/filepath"

	"github.com/spf13/cobra"

	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	"github.com/siderolabs/talos/pkg/provision/providers"
)

// Cmd represents the cluster command.
var Cmd = &cobra.Command{
	Use:   "cluster",
	Short: "A collection of commands for managing local docker-based or QEMU-based clusters",
	Long:  ``,
}

type ClusterCmdOps struct {
	ProvisionerName string
	StateDir        string
	ClusterName     string

	DefaultStateDir string
	DefaultCNIDir   string
}

var Flags ClusterCmdOps

func init() {
	talosDir, err := clientconfig.GetTalosDirectory()
	if err == nil {
		Flags.DefaultStateDir = filepath.Join(talosDir, "clusters")
		Flags.DefaultCNIDir = filepath.Join(talosDir, "cni")
	}

	Cmd.PersistentFlags().StringVar(&Flags.ProvisionerName, "provisioner", providers.DockerProviderName, "Talos cluster provisioner to use")
	Cmd.PersistentFlags().StringVar(&Flags.StateDir, "state", Flags.DefaultStateDir, "directory path to store cluster state")
	Cmd.PersistentFlags().StringVar(&Flags.ClusterName, "name", "talos-default", "the name of the cluster")
}
