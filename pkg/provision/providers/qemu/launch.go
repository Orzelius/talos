// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package qemu

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/google/uuid"
	"github.com/siderolabs/go-blockdevice/v2/blkid"

	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

// LaunchConfig is passed in to the Launch function over stdin.
type LaunchConfig struct {
	StatePath string

	// VM options
	DiskPaths         []string
	DiskDrivers       []string
	VCPUCount         int64
	MemSize           int64
	KernelImagePath   string
	InitrdPath        string
	ISOPath           string
	PFlashImages      []string
	KernelArgs        string
	MonitorPath       string
	DefaultBootOrder  string
	EnableKVM         bool
	BootloaderEnabled bool
	TPM2Config        tpm2Config
	NodeUUID          uuid.UUID
	BadRTC            bool
	ArchitectureData  Arch

	// Talos config
	Config string

	// Network
	BridgeName        string
	NetworkConfig     *libcni.NetworkConfigList
	CNI               provision.CNIConfig
	IPs               []netip.Addr
	CIDRs             []netip.Prefix
	NoMasqueradeCIDRs []netip.Prefix
	Hostname          string
	GatewayAddrs      []netip.Addr
	MTU               int
	Nameservers       []netip.Addr

	// PXE
	TFTPServer       string
	BootFilename     string
	IPXEBootFileName string

	// API
	APIPort int

	// filled by CNI invocation
	tapName string
	vmMAC   string
	nsPath  string

	// signals
	c chan os.Signal

	// controller
	controller *Controller
}

type tpm2Config struct {
	NodeName string
	StateDir string
}

func checkPartitions(config *LaunchConfig) (bool, error) {
	fmt.Printf("checkPartitions, %s\n", config.DiskPaths[0])
	// todo: use qemu-img
	return false, nil
	info, err := blkid.ProbePath(config.DiskPaths[0])
	if err != nil {
		return false, fmt.Errorf("error probing disk: %w", err)
	}

	return info.Name == "gpt" && len(info.Parts) > 0, nil
}

// launchVM runs qemu with args built based on config.
//
//nolint:gocyclo,cyclop
func launchVM(config *LaunchConfig) error {
	bootOrder := config.DefaultBootOrder

	if config.controller.ForcePXEBoot() {
		bootOrder = "nc"
	}

	cpuArg := "max"

	if config.BadRTC {
		cpuArg += ",-kvmclock"
	}

	args := []string{
		"-m", strconv.FormatInt(config.MemSize, 10),
		"-smp", fmt.Sprintf("cpus=%d", config.VCPUCount),
		"-cpu", cpuArg,
		"-nographic",
		"-netdev", fmt.Sprintf("tap,id=net0,ifname=%s,script=no,downscript=no", config.tapName),
		"-device", fmt.Sprintf("virtio-net-pci,netdev=net0,mac=%s", config.vmMAC),
		// TODO: uncomment the following line to get another eth interface not connected to anything
		// "-nic", "tap,model=virtio-net-pci",
		"-device", "virtio-rng-pci",
		"-device", "virtio-balloon,deflate-on-oom=on",
		"-monitor", fmt.Sprintf("unix:%s,server,nowait", config.MonitorPath),
		"-no-reboot",
		"-boot", fmt.Sprintf("order=%s,reboot-timeout=5000", bootOrder),
		"-smbios", fmt.Sprintf("type=1,uuid=%s", config.NodeUUID),
		"-chardev", fmt.Sprintf("socket,path=%s/%s.sock,server=on,wait=off,id=qga0", config.StatePath, config.Hostname),
		"-device", "virtio-serial",
		"-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
		"-device", "i6300esb,id=watchdog0",
		"-watchdog-action",
		"pause",
	}

	var (
		scsiAttached, ahciAttached, nvmeAttached bool
		ahciBus                                  int
	)

	for i, disk := range config.DiskPaths {
		driver := config.DiskDrivers[i]

		switch driver {
		case "virtio":
			args = append(args, "-drive", fmt.Sprintf("format=raw,if=virtio,file=%s,cache=none,", disk))
		case "ide":
			args = append(args, "-drive", fmt.Sprintf("format=raw,if=ide,file=%s,cache=none,", disk))
		case "ahci":
			if !ahciAttached {
				args = append(args, "-device", "ahci,id=ahci0")
				ahciAttached = true
			}

			args = append(args,
				"-drive", fmt.Sprintf("id=ide%d,format=raw,if=none,file=%s", i, disk),
				"-device", fmt.Sprintf("ide-hd,drive=ide%d,bus=ahci0.%d", i, ahciBus),
			)

			ahciBus++
		case "scsi":
			if !scsiAttached {
				args = append(args, "-device", "virtio-scsi-pci,id=scsi0")
				scsiAttached = true
			}

			args = append(args,
				"-drive", fmt.Sprintf("id=scsi%d,format=raw,if=none,file=%s,discard=unmap,aio=native,cache=none", i, disk),
				"-device", fmt.Sprintf("scsi-hd,drive=scsi%d,bus=scsi0.0", i),
			)
		case "nvme":
			if !nvmeAttached {
				// [TODO]: once Talos is fixed, use multipath NVME: https://qemu-project.gitlab.io/qemu/system/devices/nvme.html
				args = append(args,
					"-device", "nvme,id=nvme-ctrl-0,serial=deadbeef",
				)
				nvmeAttached = true
			}

			args = append(args,
				"-drive", fmt.Sprintf("id=nvme%d,format=raw,if=none,file=%s,discard=unmap,aio=native,cache=none", i, disk),
				"-device", fmt.Sprintf("nvme-ns,drive=nvme%d", i),
			)
		default:
			return fmt.Errorf("unsupported disk driver %q", driver)
		}
	}

	args = append(args, config.ArchitectureData.KVMArgs(config.EnableKVM)...)

	pflashArgs := make([]string, 2*len(config.PFlashImages))
	for i := range config.PFlashImages {
		pflashArgs[2*i] = "-drive"
		pflashArgs[2*i+1] = fmt.Sprintf("file=%s,format=raw,if=pflash", config.PFlashImages[i])
	}

	args = append(args, pflashArgs...)

	// check if disk is empty/wiped
	diskBootable, err := checkPartitions(config)
	if err != nil {
		return err
	}

	if config.TPM2Config.NodeName != "" {
		tpm2SocketPath := filepath.Join(config.TPM2Config.StateDir, "swtpm.sock")

		cmd := exec.Command("swtpm", []string{
			"socket",
			"--tpmstate",
			fmt.Sprintf("dir=%s,mode=0644", config.TPM2Config.StateDir),
			"--ctrl",
			fmt.Sprintf("type=unixio,path=%s", tpm2SocketPath),
			"--tpm2",
			"--pid",
			fmt.Sprintf("file=%s", filepath.Join(config.TPM2Config.StateDir, "swtpm.pid")),
			"--log",
			fmt.Sprintf("file=%s,level=20", filepath.Join(config.TPM2Config.StateDir, "swtpm.log")),
		}...)

		log.Printf("starting swtpm: %s", cmd.String())

		if err := cmd.Start(); err != nil {
			return err
		}

		args = append(args,
			config.ArchitectureData.TPMDeviceArgs(tpm2SocketPath)...,
		)
	}

	if !diskBootable || !config.BootloaderEnabled {
		if config.ISOPath != "" {
			args = append(args,
				"-cdrom", config.ISOPath,
			)
		} else if config.KernelImagePath != "" {
			args = append(args,
				"-kernel", config.KernelImagePath,
				"-initrd", config.InitrdPath,
				"-append", config.KernelArgs,
			)
		}
	}

	if config.BadRTC {
		args = append(args,
			"-rtc",
			"base=2011-11-11T11:11:00,clock=rt",
		)
	}

	fmt.Fprintf(os.Stderr, "starting %s with args:\n%s\n", config.ArchitectureData.QemuExecutable(), strings.Join(args, " "))
	cmd := exec.Command(
		config.ArchitectureData.QemuExecutable(),
		args...,
	)

	fmt.Printf("Would run qemu with:\n%s %v", config.ArchitectureData.QemuExecutable(), args)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	shouldReturn, returnValue := cmdStart(config, cmd)
	if shouldReturn {
		return returnValue
	}

	done := make(chan error)

	go func() {
		done <- cmd.Wait()
	}()

	for {
		select {
		case sig := <-config.c:
			fmt.Fprintf(os.Stderr, "exiting VM as signal %s was received\n", sig)

			if err := cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill process %w", err)
			}

			<-done

			return errors.New("process stopped")
		case err := <-done:
			if err != nil {
				return fmt.Errorf("process exited with error %s", err)
			}

			// graceful exit
			return nil
		case command := <-config.controller.CommandsCh():
			if command == VMCommandStop {
				fmt.Fprintf(os.Stderr, "exiting VM as stop command via API was received\n")

				if err := cmd.Process.Kill(); err != nil {
					return fmt.Errorf("failed to kill process %w", err)
				}

				<-done

				return nil
			}
		}
	}
}

// Launch a control process around qemu VM manager.
//
// This function is invoked from 'talosctl qemu-launch' hidden command
// and wraps starting, controlling 'qemu' VM process.
//
// Launch restarts VM forever until control process is stopped itself with a signal.
//
// Process is expected to receive configuration on stdin. Current working directory
// should be cluster state directory, process output should be redirected to the
// logfile in state directory.
//
// When signals SIGINT, SIGTERM are received, control process stops qemu and exits.
func Launch() error {
	fmt.Println("Launch()")
	var config LaunchConfig

	ctx := context.Background()

	if err := vm.ReadConfig(&config); err != nil {
		return err
	}
	fmt.Println("Launch() 1")
	config.c = vm.ConfigureSignals()
	config.controller = NewController()
	fmt.Println("Launch() 2")

	httpServer, err := vm.NewHTTPServer(config.GatewayAddrs[0], config.APIPort, []byte(config.Config), config.controller)
	if err != nil {
		return err
	}
	fmt.Println("Launch() 3")

	httpServer.Serve()
	defer httpServer.Shutdown(ctx) //nolint:errcheck

	// patch kernel args
	config.KernelArgs = strings.ReplaceAll(config.KernelArgs, "{TALOS_CONFIG_URL}", fmt.Sprintf("http://%s/config.yaml", httpServer.GetAddr()))
	fmt.Println("Launch() 4")

	return withCNI(ctx, &config, func(config *LaunchConfig) error {
		for {
			for config.controller.PowerState() != PoweredOn {
				select {
				case <-config.controller.CommandsCh():
					// machine might have been powered on
				case sig := <-config.c:
					fmt.Fprintf(os.Stderr, "exiting stopped launcher as signal %s was received\n", sig)

					return errors.New("process stopped")
				}
			}

			if err := launchVM(config); err != nil {
				return err
			}
		}
	})
}
