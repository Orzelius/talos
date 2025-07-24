// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/siderolabs/talos/cmd/talosctl/cmd/mgmt/cluster"
	"github.com/siderolabs/talos/pkg/provision"
)

func runCmd(cmd *cobra.Command, args ...string) (*cobra.Command, string, error) { //nolint:unparam
	outBuf := bytes.NewBufferString("")
	cmd.SetOut(outBuf)
	cmd.SetErr(outBuf)
	cmd.SetArgs(args)
	c, err := cmd.ExecuteC()

	return c, outBuf.String(), err
}

func TestCreateCommandInvalidProvisioner(t *testing.T) {
	_, _, err := runCmd(cluster.Cmd, "create", "--provisioner=asd")
	assert.ErrorContains(t, err, "unsupported provisioner")
}

func TestCreateCommandInvalidProvisionerFlagQemu(t *testing.T) {
	_, _, err := runCmd(cluster.Cmd, "create", "--provisioner=qemu", "--exposed-ports=10:10")
	assert.ErrorContains(t, err, "exposed-ports flag has been set but has no effect with the qemu provisioner")

	_, _, err = runCmd(cluster.Cmd, "create", "qemu", "dev", "--ports=10:10")
	assert.ErrorContains(t, err, "unknown flag")
}

func TestCreateCommandInvalidProvisionerFlagDocker(t *testing.T) {
	_, _, err := runCmd(cluster.Cmd, "create", "--provisioner=docker", "--with-network-chaos=true")
	assert.ErrorContains(t, err, "with-network-chaos flag has been set but has no effect with the docker provisioner")

	_, _, err = runCmd(cluster.Cmd, "create", "docker", "dev", "--with-network-chaos=true")
	assert.ErrorContains(t, err, "unknown flag")
}

func TestCreateSubCommands(t *testing.T) {
	commands := []string{"create docker", "create docker dev", "create qemu", "create qemu dev"}
	cmds := cluster.Cmd.Commands()
	fmt.Print(cmds)

	for _, cmd := range commands {
		_, _, err := runCmd(cluster.Cmd, append(strings.Split(cmd, " "), "--provisioner=docker")...)
		assert.ErrorContains(t, err, "superfluous \"provisioner\" flag")
		assert.NotContains(t, err.Error(), "the \"provisioner\" flag is not supported")
	}
}

func TestCreateBasicCommands(t *testing.T) {
	tests := []struct {
		cmd              []string
		errShouldContain string
	}{
		{
			cmd:              []string{"create", "docker", "--disk=3"},
			errShouldContain: "unknown flag: --disk",
		},
		{
			cmd:              []string{"create", "qemu", "--ports"},
			errShouldContain: "unknown flag: --ports",
		},
		{
			cmd:              []string{"create", "qemu", "--initrd-path=asd"},
			errShouldContain: `the "initrd-path" flag is not supported on the "create qemu" command, use "create qemu dev" instead for advanced functionaliry`,
		},
	}

	for _, test := range tests {
		_, _, err := runCmd(cluster.Cmd, test.cmd...)
		assert.ErrorContains(t, err, test.errShouldContain)
	}
}

func TestGetDisks(t *testing.T) {
	type args struct {
		disks            []string
		preallocateDisks bool
		diskBlockSize    uint
	}

	tests := []struct {
		name            string
		args            args
		wantPrimary     []*provision.Disk
		wantWorkerExtra []*provision.Disk
		wantErr         bool
	}{
		{
			name: "single disk",
			args: args{
				disks:            []string{"virtio:4096"},
				preallocateDisks: true,
				diskBlockSize:    4096,
			},
			wantPrimary: []*provision.Disk{
				{
					Size:            4096 * 1024 * 1024,
					SkipPreallocate: false,
					Driver:          "virtio",
					BlockSize:       4096,
				},
			},
			wantWorkerExtra: nil,
			wantErr:         false,
		},
		{
			name: "multiple disks",
			args: args{
				disks:            []string{"virtio:4096", "sata:2048", "nvme:1024"},
				preallocateDisks: false,
				diskBlockSize:    8192,
			},
			wantPrimary: []*provision.Disk{
				{
					Size:            4096 * 1024 * 1024,
					SkipPreallocate: true,
					Driver:          "virtio",
					BlockSize:       8192,
				},
			},
			wantWorkerExtra: []*provision.Disk{
				{
					Size:            2048 * 1024 * 1024,
					SkipPreallocate: true,
					Driver:          "sata",
					BlockSize:       8192,
				},
				{
					Size:            1024 * 1024 * 1024,
					SkipPreallocate: true,
					Driver:          "nvme",
					BlockSize:       8192,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid disk format",
			args: args{
				disks:            []string{"badformat"},
				preallocateDisks: false,
				diskBlockSize:    512,
			},
			wantPrimary:     nil,
			wantWorkerExtra: nil,
			wantErr:         true,
		},
		{
			name: "invalid size in disk spec",
			args: args{
				disks:            []string{"virtio:notanumber"},
				preallocateDisks: true,
				diskBlockSize:    512,
			},
			wantPrimary:     nil,
			wantWorkerExtra: nil,
			wantErr:         true,
		},
		{
			name: "no disks specified",
			args: args{
				disks:            []string{},
				preallocateDisks: true,
				diskBlockSize:    512,
			},
			wantPrimary:     nil,
			wantWorkerExtra: nil,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qOps := qemuOps{
				disks:            tt.args.disks,
				preallocateDisks: tt.args.preallocateDisks,
				diskBlockSize:    tt.args.diskBlockSize,
			}

			gotPrimary, gotWorkerExtra, err := GetDisks(qOps)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, gotPrimary, tt.wantPrimary)
			assert.Equal(t, gotWorkerExtra, tt.wantWorkerExtra)
		})
	}
}
