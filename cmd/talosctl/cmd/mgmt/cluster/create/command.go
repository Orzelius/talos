// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/docker/cli/opts"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	clustercmd "github.com/siderolabs/talos/cmd/talosctl/cmd/mgmt/cluster"
	"github.com/siderolabs/talos/cmd/talosctl/pkg/mgmt/helpers"
	"github.com/siderolabs/talos/pkg/cli"
	"github.com/siderolabs/talos/pkg/images"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/version"
	"github.com/siderolabs/talos/pkg/provision/providers"
)

// commonOps are the options common between all the providers.
type commonOps struct {
	// RootOps are the options from the root cluster command
	rootOps                   *clustercmd.CmdOps
	talosconfigDestination    string
	registryMirrors           []string
	registryInsecure          []string
	kubernetesVersion         string
	applyConfigEnabled        bool
	configDebug               bool
	networkCIDR               string
	networkMTU                int
	networkIPv4               bool
	dnsDomain                 string
	workers                   int
	controlplanes             int
	controlPlaneCpus          string
	workersCpus               string
	controlPlaneMemory        int
	workersMemory             int
	clusterWait               bool
	clusterWaitTimeout        time.Duration
	forceInitNodeAsEndpoint   bool
	forceEndpoint             string
	inputDir                  string
	controlPlanePort          int
	withInitNode              bool
	customCNIUrl              string
	skipKubeconfig            bool
	skipInjectingConfig       bool
	talosconfigVersion        string
	enableKubeSpan            bool
	enableClusterDiscovery    bool
	configPatch               []string
	configPatchControlPlane   []string
	configPatchWorker         []string
	kubePrismPort             int
	skipK8sNodeReadinessCheck bool
	withJSONLogs              bool
	wireguardCIDR             string

	// IPv6 networking is suported only on qemu, but it doesn't make sense to separate the logic
	networkIPv6 bool
}

type qemuOps struct {
	installerImage            string
	nodeVmlinuzPath           string
	nodeInitramfsPath         string
	nodeISOPath               string
	nodeUSBPath               string
	nodeUKIPath               string
	nodeDiskImagePath         string
	nodeIPXEBootScript        string
	bootloaderEnabled         bool
	uefiEnabled               bool
	tpm1_2Enabled             bool
	tpm2Enabled               bool
	extraUEFISearchPaths      []string
	networkNoMasqueradeCIDRs  []string
	nameservers               []string
	diskBlockSize             uint
	disks                     []string
	preallocateDisks          bool
	clusterUserVolumes        []string
	targetArch                string
	cniBinPath                []string
	cniConfDir                string
	cniCacheDir               string
	cniBundleURL              string
	encryptStatePartition     bool
	encryptEphemeralPartition bool
	encryptUserVolumes        bool
	useVIP                    bool
	badRTC                    bool
	extraBootKernelArgs       string
	dhcpSkipHostname          bool
	networkChaos              bool
	jitter                    time.Duration
	latency                   time.Duration
	packetLoss                float64
	packetReorder             float64
	packetCorrupt             float64
	bandwidth                 int
	diskEncryptionKeyTypes    []string
	withFirewall              string
	withUUIDHostnames         bool
	withSiderolinkAgent       agentFlag
	debugShellEnabled         bool
	withIOMMU                 bool
	configInjectionMethod     string
}

// for options that don't exist on the new commands at all
type legacyOps struct {
	primaryDiskSize   int
	extraDisks        int
	extraDiskSize     int
	extraDisksDrivers []string
}

type dockerOps struct {
	hostIP      string
	disableIPv6 bool
	mountOpts   opts.MountOpt
	ports       string
	nodeImage   string
}

type createOps struct {
	common commonOps
	docker dockerOps
	qemu   qemuOps
}

//nolint:gocyclo
func init() {
	const (
		dockerHostIPFlag                 = "host-ip"
		dockerHostIPFlagLegacy           = "docker-host-ip"
		nodeImageFlag                    = "image"
		dockerPortsFlag                  = "exposed-ports"
		dockerDisableIPv6Flag            = "docker-disable-ipv6"
		dockerDisableIPv6FlagLegacy      = "disable-ipv6"
		mountOptsFlag                    = "mount"
		inputDirFlag                     = "input-dir"
		networkIPv4Flag                  = "ipv4"
		networkIPv6Flag                  = "ipv6"
		networkMTUFlag                   = "mtu"
		networkCIDRFlag                  = "cidr"
		networkNoMasqueradeCIDRsFlag     = "no-masquerade-cidrs"
		nameserversFlag                  = "nameservers"
		preallocateDisksFlag             = "disk-preallocate"
		clusterUserVolumesFlag           = "user-volumes"
		disksFlag                        = "disks"
		primaryDiskSizeFlagLegacy        = "disk"
		diskBlockSizeFlag                = "disk-block-size"
		useVIPFlag                       = "use-vip"
		bootloaderEnabledFlag            = "with-bootloader"
		controlPlanePortFlag             = "control-plane-port"
		firewallFlag                     = "with-firewall"
		tpmEnabledFlag                   = "with-tpm1_2"
		tpm2EnabledFlag                  = "with-tpm2"
		withDebugShellFlag               = "with-debug-shell"
		withIOMMUFlag                    = "with-iommu"
		talosconfigDestinationFlagLegacy = "talosconfig"
		talosconfigDestinationFlag       = "talosconfig-destination"
		applyConfigEnabledFlag           = "with-apply-config"
		wireguardCIDRFlag                = "wireguard-cidr"
		workersFlag                      = "workers"
		controlplanesFlag                = "controlplanes"
		controlPlaneCpusFlag             = "cpus"
		workersCpusFlag                  = "cpus-workers"
		controlPlaneMemoryFlag           = "memory"
		workersMemoryFlag                = "memory-workers"
		clusterWaitFlag                  = "wait"
		clusterWaitTimeoutFlag           = "wait-timeout"
		forceInitNodeAsEndpointFlag      = "init-node-as-endpoint"
		kubernetesVersionFlag            = "kubernetes-version"
		withInitNodeFlag                 = "with-init-node"
		skipKubeconfigFlag               = "skip-kubeconfig"
		skipInjectingConfigFlag          = "skip-injecting-config"
		configPatchFlag                  = "config-patch"
		configPatchControlPlaneFlag      = "config-patch-control-plane"
		configPatchWorkerFlag            = "config-patch-worker"
		skipK8sNodeReadinessCheckFlag    = "skip-k8s-node-readiness-check"
		withJSONLogsFlag                 = "with-json-logs"
		nodeVmlinuzPathFlag              = "vmlinuz-path"
		nodeISOPathFlag                  = "iso-path"
		nodeUSBPathFlag                  = "usb-path"
		nodeUKIPathFlag                  = "uki-path"
		nodeInitramfsPathFlag            = "initrd-path"
		nodeDiskImagePathFlag            = "disk-image-path"
		nodeIPXEBootScriptFlag           = "ipxe-boot-script"
		uefiEnabledFlag                  = "with-uefi"
		extraUEFISearchPathsFlag         = "extra-uefi-search-paths"
		extraDisksFlagLegacy             = "extra-disks"
		extraDisksDriversFlagLegacy      = "extra-disks-drivers"
		extraDiskSizeFlagLegacy          = "extra-disks-size"
		targetArchFlag                   = "arch"
		cniBinPathFlag                   = "cni-bin-path"
		cniConfDirFlag                   = "cni-conf-dir"
		cniCacheDirFlag                  = "cni-cache-dir"
		cniBundleURLFlag                 = "cni-bundle-url"
		badRTCFlag                       = "bad-rtc"
		extraBootKernelArgsFlag          = "extra-boot-kernel-args"
		dhcpSkipHostnameFlag             = "disable-dhcp-hostname"
		networkChaosFlag                 = "with-network-chaos"
		jitterFlag                       = "with-network-jitter"
		latencyFlag                      = "with-network-latency"
		packetLossFlag                   = "with-network-packet-loss"
		packetReorderFlag                = "with-network-packet-reorder"
		packetCorruptFlag                = "with-network-packet-corrupt"
		bandwidthFlag                    = "with-network-bandwidth"
		withUUIDHostnamesFlag            = "with-uuid-hostnames"
		withSiderolinkAgentFlag          = "with-siderolink"
		configInjectionMethodFlag        = "config-injection-method"

		// The following flags are the gen options - the options that are only used in machine configuration (i.e., not during the qemu/docker provisioning).
		// They are not applicable when no machine configuration is generated, hence mutually exclusive with the --input-dir flag.

		installerImageFlag            = "installer-image"
		installerImageFlagLegacy      = "install-image"
		configDebugFlag               = "with-debug"
		dnsDomainFlag                 = "dns-domain"
		withClusterDiscoveryFlag      = "with-cluster-discovery"
		registryMirrorFlag            = "registry-mirror"
		registryInsecureFlag          = "registry-insecure-skip-verify"
		customCNIUrlFlag              = "custom-cni-url"
		talosConfigVersionFlagLegacy  = "talos-version"
		talosConfigVersionFlag        = "talosconfig-version"
		encryptStatePartitionFlag     = "encrypt-state"
		encryptEphemeralPartitionFlag = "encrypt-ephemeral"
		encryptUserVolumeFlag         = "encrypt-user-volumes"
		enableKubeSpanFlag            = "with-kubespan"
		forceEndpointFlag             = "endpoint"
		kubePrismFlag                 = "kubeprism-port"
		diskEncryptionKeyTypesFlag    = "disk-encryption-key-types"

		// flags exclusive to the non-dev commands
		talosVersionFlag = "talos-version"
		bootMethodFlag   = "boot-method"
	)

	unImplementedQemuFlagsDarwin := []string{
		networkNoMasqueradeCIDRsFlag,
		cniBinPathFlag,
		cniConfDirFlag,
		cniCacheDirFlag,
		cniBundleURLFlag,
		badRTCFlag,
		networkChaosFlag,
		jitterFlag,
		latencyFlag,
		packetLossFlag,
		packetReorderFlag,
		packetCorruptFlag,
		bandwidthFlag,

		// The following might work but need testing first.
		configInjectionMethodFlag,
	}

	// flags which are supported on the non-dev cluster create commands
	basicCommonFlags := []string{
		// todo: add talos version flag
		// todo: add skip-machineconfig flag
		networkCIDRFlag,
		controlPlanePortFlag,
		controlplanesFlag,
		workersFlag,
		kubernetesVersionFlag,
		talosconfigDestinationFlag,
		enableKubeSpanFlag,

		controlPlaneCpusFlag,
		controlPlaneMemoryFlag,
		workersCpusFlag,
		workersMemoryFlag,
	}
	basicQemuFlags := []string{
		// todo: add boot-method flag
		preallocateDisksFlag,
		clusterUserVolumesFlag,
		skipInjectingConfigFlag,
	}

	ops := &createOps{
		common: commonOps{},
		docker: dockerOps{},
		qemu:   qemuOps{},
	}
	legacyOps := &legacyOps{} // todo add a backport

	getCommonFlags := func(legacy bool) *pflag.FlagSet {
		common := pflag.NewFlagSet("common", pflag.PanicOnError)

		common.BoolVar(&ops.common.applyConfigEnabled, applyConfigEnabledFlag, false, "enable apply config when the VM is starting in maintenance mode")
		common.StringSliceVar(&ops.common.registryMirrors, registryMirrorFlag, []string{}, "list of registry mirrors to use in format: <registry host>=<mirror URL>")
		common.StringSliceVar(&ops.common.registryInsecure, registryInsecureFlag, []string{}, "list of registry hostnames to skip TLS verification for")
		common.BoolVar(&ops.common.configDebug, configDebugFlag, false, "enable debug in Talos config to send service logs to the console")
		common.IntVar(&ops.common.networkMTU, networkMTUFlag, 1500, "MTU of the cluster network")
		common.StringVar(&ops.common.networkCIDR, networkCIDRFlag, "10.5.0.0/24", "CIDR of the cluster network (IPv4, ULA network for IPv6 is derived in automated way)")
		common.BoolVar(&ops.common.networkIPv4, networkIPv4Flag, true, "enable IPv4 network in the cluster")
		common.StringVar(&ops.common.wireguardCIDR, wireguardCIDRFlag, "", "CIDR of the wireguard network")
		common.IntVar(&ops.common.workers, workersFlag, 1, "the number of workers to create")
		common.IntVar(&ops.common.controlplanes, controlplanesFlag, 1, "the number of controlplanes to create")
		common.StringVar(&ops.common.controlPlaneCpus, controlPlaneCpusFlag, "2.0", "the share of CPUs as fraction (each control plane/VM)")
		common.StringVar(&ops.common.workersCpus, workersCpusFlag, "2.0", "the share of CPUs as fraction (each worker/VM)")
		common.IntVar(&ops.common.controlPlaneMemory, controlPlaneMemoryFlag, 2048, "the limit on memory usage in MB (each control plane/VM)")
		common.IntVar(&ops.common.workersMemory, workersMemoryFlag, 2048, "the limit on memory usage in MB (each worker/VM)")
		common.BoolVar(&ops.common.clusterWait, clusterWaitFlag, true, "wait for the cluster to be ready before returning")
		common.DurationVar(&ops.common.clusterWaitTimeout, clusterWaitTimeoutFlag, 20*time.Minute, "timeout to wait for the cluster to be ready")
		common.BoolVar(&ops.common.forceInitNodeAsEndpoint, forceInitNodeAsEndpointFlag, false, "use init node as endpoint instead of any load balancer endpoint")
		common.StringVar(&ops.common.forceEndpoint, forceEndpointFlag, "", "use endpoint instead of provider defaults")
		common.StringVar(&ops.common.kubernetesVersion, kubernetesVersionFlag, constants.DefaultKubernetesVersion, "desired kubernetes version to run")
		common.StringVarP(&ops.common.inputDir, inputDirFlag, "i", "", "location of pre-generated config files")
		common.BoolVar(&ops.common.withInitNode, withInitNodeFlag, false, "create the cluster with an init node")
		common.StringVar(&ops.common.customCNIUrl, customCNIUrlFlag, "", "install custom CNI from the URL (Talos cluster)")
		common.StringVar(&ops.common.dnsDomain, dnsDomainFlag, "cluster.local", "the dns domain to use for cluster")
		common.BoolVar(&ops.common.skipKubeconfig, skipKubeconfigFlag, false, "skip merging kubeconfig from the created cluster")
		common.BoolVar(&ops.common.skipInjectingConfig, skipInjectingConfigFlag, false, "skip injecting config from embedded metadata server, write config files to current directory")
		common.BoolVar(&ops.common.enableClusterDiscovery, withClusterDiscoveryFlag, true, "enable cluster discovery")
		common.BoolVar(&ops.common.enableKubeSpan, enableKubeSpanFlag, false, "enable KubeSpan system")
		common.StringArrayVar(&ops.common.configPatch, configPatchFlag, nil, "patch generated machineconfigs (applied to all node types), use @file to read a patch from file")
		common.StringArrayVar(&ops.common.configPatchControlPlane, configPatchControlPlaneFlag, nil, "patch generated machineconfigs (applied to 'init' and 'controlplane' types)")
		common.StringArrayVar(&ops.common.configPatchWorker, configPatchWorkerFlag, nil, "patch generated machineconfigs (applied to 'worker' type)")
		common.IntVar(&ops.common.controlPlanePort, controlPlanePortFlag, constants.DefaultControlPlanePort, "control plane port (load balancer and local API port)")
		common.IntVar(&ops.common.kubePrismPort, kubePrismFlag, constants.DefaultKubePrismPort, "KubePrism port (set to 0 to disable)")
		common.BoolVar(&ops.common.skipK8sNodeReadinessCheck, skipK8sNodeReadinessCheckFlag, false, "skip k8s node readiness checks")
		common.BoolVar(&ops.common.withJSONLogs, withJSONLogsFlag, false, "enable JSON logs receiver and configure Talos to send logs there")

		if legacy {
			common.StringVar(&ops.common.talosconfigVersion, talosConfigVersionFlagLegacy, "", "the desired Talos version to generate config for (if not set, defaults to image version)")
			common.StringVar(&ops.common.talosconfigDestination, talosconfigDestinationFlagLegacy, "",
				fmt.Sprintf("The path to the Talos configuration file. Defaults to '%s' env variable if set, otherwise '%s' and '%s' in order.",
					constants.TalosConfigEnvVar,
					filepath.Join("$HOME", constants.TalosDir, constants.TalosconfigFilename),
					filepath.Join(constants.ServiceAccountMountPath, constants.TalosconfigFilename),
				),
			)
		} else {
			common.StringVar(&ops.common.talosconfigVersion, talosConfigVersionFlag, "", "the desired Talos version to generate config for (if not set, defaults to image version)")
			common.StringVar(&ops.common.talosconfigDestination, talosconfigDestinationFlag, "",
				fmt.Sprintf("The path to the Talos configuration file. Defaults to '%s' env variable if set, otherwise '%s' and '%s' in order.",
					constants.TalosConfigEnvVar,
					filepath.Join("$HOME", constants.TalosDir, constants.TalosconfigFilename),
					filepath.Join(constants.ServiceAccountMountPath, constants.TalosconfigFilename),
				),
			)
		}

		return common
	}

	getQemuFlags := func(legacy bool) *pflag.FlagSet {
		qemu := pflag.NewFlagSet("common", pflag.PanicOnError)

		qemu.StringVar(&ops.qemu.nodeVmlinuzPath, nodeVmlinuzPathFlag, helpers.ArtifactPath(constants.KernelAssetWithArch), "the compressed kernel image to use")
		qemu.StringVar(&ops.qemu.nodeISOPath, nodeISOPathFlag, "", "the ISO path to use for the initial boot")
		qemu.StringVar(&ops.qemu.nodeUSBPath, nodeUSBPathFlag, "", "the USB stick image path to use for the initial boot")
		qemu.StringVar(&ops.qemu.nodeUKIPath, nodeUKIPathFlag, "", "the UKI image path to use for the initial boot")
		qemu.StringVar(&ops.qemu.nodeInitramfsPath, nodeInitramfsPathFlag, helpers.ArtifactPath(constants.InitramfsAssetWithArch), "initramfs image to use")
		qemu.StringVar(&ops.qemu.nodeDiskImagePath, nodeDiskImagePathFlag, "", "disk image to use")
		qemu.StringVar(&ops.qemu.nodeIPXEBootScript, nodeIPXEBootScriptFlag, "", "iPXE boot script (URL) to use")
		qemu.BoolVar(&ops.qemu.bootloaderEnabled, bootloaderEnabledFlag, true, "enable bootloader to load kernel and initramfs from disk image after install")
		qemu.BoolVar(&ops.qemu.uefiEnabled, uefiEnabledFlag, true, "enable UEFI on x86_64 architecture")
		qemu.BoolVar(&ops.qemu.tpm1_2Enabled, tpmEnabledFlag, false, "enable TPM 1.2 emulation support using swtpm")
		qemu.BoolVar(&ops.qemu.tpm2Enabled, tpm2EnabledFlag, false, "enable TPM 2.0 emulation support using swtpm")
		qemu.BoolVar(&ops.qemu.debugShellEnabled, withDebugShellFlag, false, "drop talos into a maintenance shell on boot, this is for advanced debugging for developers only")
		qemu.BoolVar(&ops.qemu.withIOMMU, withIOMMUFlag, false, "enable IOMMU support, this also add a new PCI root port and an interface attached to it")
		qemu.MarkHidden("with-debug-shell") //nolint:errcheck
		qemu.StringSliceVar(&ops.qemu.extraUEFISearchPaths, extraUEFISearchPathsFlag, []string{}, "additional search paths for UEFI firmware (only applies when UEFI is enabled)")
		qemu.StringSliceVar(&ops.qemu.networkNoMasqueradeCIDRs, networkNoMasqueradeCIDRsFlag, []string{}, "list of CIDRs to exclude from NAT")
		qemu.StringSliceVar(&ops.qemu.nameservers, nameserversFlag, []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"}, "list of nameservers to use")
		qemu.UintVar(&ops.qemu.diskBlockSize, diskBlockSizeFlag, 512, "disk block size")
		qemu.BoolVar(&ops.qemu.preallocateDisks, preallocateDisksFlag, true, "whether disk space should be preallocated")
		qemu.StringSliceVar(&ops.qemu.clusterUserVolumes, clusterUserVolumesFlag, []string{}, "list of user volumes to create for each VM in format: <name1>:<size1>:<name2>:<size2>")
		qemu.StringVar(&ops.qemu.targetArch, targetArchFlag, runtime.GOARCH, "cluster architecture")
		qemu.StringSliceVar(&ops.qemu.cniBinPath, cniBinPathFlag, []string{filepath.Join(clustercmd.DefaultCNIDir, "bin")}, "search path for CNI binaries")
		qemu.StringVar(&ops.qemu.cniConfDir, cniConfDirFlag, filepath.Join(clustercmd.DefaultCNIDir, "conf.d"), "CNI config directory path")
		qemu.StringVar(&ops.qemu.cniCacheDir, cniCacheDirFlag, filepath.Join(clustercmd.DefaultCNIDir, "cache"), "CNI cache directory path")
		qemu.StringVar(&ops.qemu.cniBundleURL, cniBundleURLFlag, fmt.Sprintf("https://github.com/%s/talos/releases/download/%s/talosctl-cni-bundle-%s.tar.gz",
			images.Username, version.Trim(version.Tag), constants.ArchVariable), "URL to download CNI bundle from")
		qemu.BoolVar(&ops.qemu.encryptStatePartition, encryptStatePartitionFlag, false, "enable state partition encryption")
		qemu.BoolVar(&ops.qemu.encryptEphemeralPartition, encryptEphemeralPartitionFlag, false, "enable ephemeral partition encryption")
		qemu.BoolVar(&ops.qemu.encryptUserVolumes, encryptUserVolumeFlag, false, "enable ephemeral partition encryption")
		qemu.StringArrayVar(&ops.qemu.diskEncryptionKeyTypes, diskEncryptionKeyTypesFlag, []string{"uuid"}, "encryption key types to use for disk encryption (uuid, kms)")
		// This flag is currently only supported on qemu, but the internal logic still assumes the possibility of ipv6 on other providers.
		qemu.BoolVar(&ops.common.networkIPv6, networkIPv6Flag, false, "enable IPv6 network in the cluster")
		qemu.BoolVar(&ops.qemu.useVIP, useVIPFlag, false, "use a virtual IP for the controlplane endpoint instead of the loadbalancer")
		qemu.BoolVar(&ops.qemu.badRTC, badRTCFlag, false, "launch VM with bad RTC state")
		qemu.StringVar(&ops.qemu.extraBootKernelArgs, extraBootKernelArgsFlag, "", "add extra kernel args to the initial boot from vmlinuz and initramfs")
		qemu.BoolVar(&ops.qemu.dhcpSkipHostname, dhcpSkipHostnameFlag, false, "skip announcing hostname via DHCP")
		qemu.BoolVar(&ops.qemu.networkChaos, networkChaosFlag, false, "enable to use network chaos parameters")
		qemu.DurationVar(&ops.qemu.jitter, jitterFlag, 0, "specify jitter on the bridge interface")
		qemu.DurationVar(&ops.qemu.latency, latencyFlag, 0, "specify latency on the bridge interface")
		qemu.Float64Var(&ops.qemu.packetLoss, packetLossFlag, 0.0,
			"specify percent of packet loss on the bridge interface. e.g. 50% = 0.50 (default: 0.0)")
		qemu.Float64Var(&ops.qemu.packetReorder, packetReorderFlag, 0.0,
			"specify percent of reordered packets on the bridge interface. e.g. 50% = 0.50 (default: 0.0)")
		qemu.Float64Var(&ops.qemu.packetCorrupt, packetCorruptFlag, 0.0,
			"specify percent of corrupt packets on the bridge interface. e.g. 50% = 0.50 (default: 0.0)")
		qemu.IntVar(&ops.qemu.bandwidth, bandwidthFlag, 0, "specify bandwidth restriction (in kbps) on the bridge interface")
		qemu.StringVar(&ops.qemu.withFirewall, firewallFlag, "", "inject firewall rules into the cluster, value is default policy - accept/block")
		qemu.BoolVar(&ops.qemu.withUUIDHostnames, withUUIDHostnamesFlag, false, "use machine UUIDs as default hostnames")
		qemu.Var(&ops.qemu.withSiderolinkAgent, withSiderolinkAgentFlag,
			"enables the use of siderolink agent as configuration apply mechanism. `true` or `wireguard` enables the agent, `tunnel` enables the agent with grpc tunneling")
		qemu.StringVar(&ops.qemu.configInjectionMethod,
			configInjectionMethodFlag, "", "a method to inject machine config: default is HTTP server, 'metal-iso' to mount an ISO")

		qemu.VisitAll(func(f *pflag.Flag) {
			f.Usage = "(qemu) " + f.Usage
		})

		if legacy {
			qemu.StringVar(&ops.qemu.installerImage, installerImageFlagLegacy, helpers.DefaultImage(images.DefaultInstallerImageRepository), "the installer image to use")
			qemu.IntVar(&legacyOps.primaryDiskSize, primaryDiskSizeFlagLegacy, 6*1024, "default limit for the primary disk size in MB (each VM)")
			qemu.IntVar(&legacyOps.extraDisks, extraDisksFlagLegacy, 0, "number of extra disks to create for each worker VM")
			qemu.StringSliceVar(&legacyOps.extraDisksDrivers, extraDisksDriversFlagLegacy, nil, "driver for each extra disk (virtio, ide, ahci, scsi, nvme, megaraid)")
			qemu.IntVar(&legacyOps.extraDiskSize, extraDiskSizeFlagLegacy, 5*1024, "default limit on disk size in MB (each VM)")
		} else {
			qemu.StringVar(&ops.qemu.installerImage, installerImageFlag, helpers.DefaultImage(images.DefaultInstallerImageRepository), "the installer image to use")
			qemu.StringSliceVar(&ops.qemu.disks, disksFlag, []string{"virtio:" + strconv.Itoa(6*1024)},
				"list of disks to create in format: <driver>:<size> (size is specified in megabytes) (disks after the first one are added only to worker machines)")
		}

		return qemu
	}

	getDockerFlags := func(legacy bool) *pflag.FlagSet {
		docker := pflag.NewFlagSet("common", pflag.PanicOnError)

		docker.StringVarP(&ops.docker.ports, dockerPortsFlag, "p", "",
			"Comma-separated list of ports/protocols to expose on init node. Ex -p <hostPort>:<containerPort>/<protocol (tcp or udp)>")
		docker.StringVar(&ops.docker.nodeImage, nodeImageFlag, helpers.DefaultImage(images.DefaultTalosImageRepository), "the image to use")

		docker.Var(&ops.docker.mountOpts, mountOptsFlag, "attach a mount to the container")

		docker.VisitAll(func(f *pflag.Flag) {
			f.Usage = "(docker) " + f.Usage
		})

		if legacy {
			docker.StringVar(&ops.docker.hostIP, dockerHostIPFlagLegacy, "0.0.0.0", "Host IP to forward exposed ports to")
			docker.BoolVar(&ops.docker.disableIPv6, dockerDisableIPv6FlagLegacy, false, "skip enabling IPv6 in containers")
		} else {
			docker.StringVar(&ops.docker.hostIP, dockerHostIPFlag, "0.0.0.0", "Host IP to forward exposed ports to")
			docker.BoolVar(&ops.docker.disableIPv6, dockerDisableIPv6Flag, false, "skip enabling IPv6 in containers")
		}

		return docker
	}

	allDockerFlagNames := []string{}

	getDockerFlags(false).VisitAll(func(f *pflag.Flag) { allDockerFlagNames = append(allDockerFlagNames, f.Name) })

	ops.common.rootOps = &clustercmd.Flags

	// createCmd is the legacy create command which takes the --provisioner flag.
	createCmd := &cobra.Command{
		Use:    "create",
		Short:  "Creates a local docker-based or QEMU-based kubernetes cluster",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				fmt.Println("WARNING: the \"cluster create\" command has been deprecated, please use \"cluster create qemu\" or \"cluster create docker\" instead")

				if err := providers.IsValidProvider(ops.common.rootOps.ProvisionerName); err != nil {
					return err
				}

				errOnProviderFlagPassed := false
				if err := validateFlags(
					ops.common.rootOps.ProvisionerName,
					cmd.Flags(), getQemuFlags(true), getDockerFlags(true),
					unImplementedQemuFlagsDarwin,
					errOnProviderFlagPassed,
					cmd,
				); err != nil {
					return err
				}

				return create(ctx, *ops)
			})
		},
	}

	createQemuCmd := &cobra.Command{
		Use:   providers.QemuProviderName,
		Short: "Create a local QEMU based kubernetes cluster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				ops.common.rootOps.ProvisionerName = providers.QemuProviderName
				allowedFlags := append(basicCommonFlags, basicQemuFlags...) // nolint

				if err := validateBasicFlags(cmd, allowedFlags, ops.common.rootOps.ProvisionerName); err != nil {
					return err
				}

				return create(ctx, *ops)
			})
		},
	}

	createQemuDevCmd := &cobra.Command{
		Use:   "dev",
		Short: "Create a local QEMU based kubernetes cluster for Talos development",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				ops.common.rootOps.ProvisionerName = providers.QemuProviderName
				errOnProviderFlagPassed := true

				if err := validateFlags(
					ops.common.rootOps.ProvisionerName,
					cmd.Flags(), getQemuFlags(false), getDockerFlags(false),
					unImplementedQemuFlagsDarwin,
					errOnProviderFlagPassed,
					cmd,
				); err != nil {
					return err
				}

				return create(ctx, *ops)
			})
		},
	}

	createDockerCmd := &cobra.Command{
		Use:   providers.DockerProviderName,
		Short: "Create a local Docker based kubernetes cluster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				ops.common.rootOps.ProvisionerName = providers.DockerProviderName
				allowedFlags := append(basicCommonFlags, allDockerFlagNames...) // nolint

				if err := validateBasicFlags(cmd, allowedFlags, ops.common.rootOps.ProvisionerName); err != nil {
					return err
				}

				return create(ctx, *ops)
			})
		},
	}

	createDockerDevCmd := &cobra.Command{
		Use:   "dev",
		Short: "Create a local QEMU based kubernetes cluster for Talos development",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				ops.common.rootOps.ProvisionerName = providers.DockerProviderName
				errOnProviderFlagPassed := true

				if err := validateFlags(
					ops.common.rootOps.ProvisionerName,
					cmd.Flags(), getQemuFlags(false), getDockerFlags(false),
					unImplementedQemuFlagsDarwin,
					errOnProviderFlagPassed,
					cmd,
				); err != nil {
					return err
				}

				return create(ctx, *ops)
			})
		},
	}

	createCmd.Flags().AddFlagSet(getCommonFlags(true))
	createCmd.Flags().AddFlagSet(getQemuFlags(true))
	createCmd.Flags().AddFlagSet(getDockerFlags(true))

	createQemuCmd.Flags().AddFlagSet(getCommonFlags(false))
	createQemuCmd.Flags().AddFlagSet(getQemuFlags(false))
	createQemuDevCmd.Flags().AddFlagSet(getCommonFlags(false))
	createQemuDevCmd.Flags().AddFlagSet(getQemuFlags(false))

	createDockerCmd.Flags().AddFlagSet(getCommonFlags(false))
	createDockerCmd.Flags().AddFlagSet(getDockerFlags(false))
	createDockerDevCmd.Flags().AddFlagSet(getCommonFlags(false))
	createDockerDevCmd.Flags().AddFlagSet(getDockerFlags(false))

	// disable top-level flag sorting.
	// The flags within flagsets are still sorted.
	// This results in the flags being in the order the flagsets were added, but still sorted within the flagset groups.
	createCmd.Flags().SortFlags = false
	createQemuCmd.Flags().SortFlags = false
	createQemuDevCmd.Flags().SortFlags = false
	createDockerCmd.Flags().SortFlags = false
	createDockerDevCmd.Flags().SortFlags = false

	markFlagsMutuallyExclusive := func(cmd *cobra.Command, legacy bool) {
		if legacy {
			cmd.MarkFlagsMutuallyExclusive(inputDirFlag, installerImageFlagLegacy)
			cmd.MarkFlagsMutuallyExclusive(inputDirFlag, talosConfigVersionFlagLegacy)
		} else {
			cmd.MarkFlagsMutuallyExclusive(inputDirFlag, installerImageFlag)
			cmd.MarkFlagsMutuallyExclusive(inputDirFlag, talosConfigVersionFlag)
		}

		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, configDebugFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, dnsDomainFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, withClusterDiscoveryFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, registryMirrorFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, registryInsecureFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, customCNIUrlFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, encryptStatePartitionFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, encryptEphemeralPartitionFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, encryptUserVolumeFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, enableKubeSpanFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, forceEndpointFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, kubePrismFlag)
		cmd.MarkFlagsMutuallyExclusive(inputDirFlag, diskEncryptionKeyTypesFlag)

		cmd.MarkFlagsMutuallyExclusive(tpmEnabledFlag, tpm2EnabledFlag)
	}

	markFlagsMutuallyExclusive(createCmd, true)
	markFlagsMutuallyExclusive(createQemuDevCmd, false)

	hideUnimplementedQemuFlags(createCmd, unImplementedQemuFlagsDarwin)
	hideNonBasicFlags(createQemuCmd, append(basicCommonFlags, basicQemuFlags...)...)
	hideNonBasicFlags(createDockerCmd, append(basicCommonFlags, basicQemuFlags...)...)

	createQemuCmd.AddCommand(createQemuDevCmd)
	createDockerCmd.AddCommand(createDockerDevCmd)
	createCmd.AddCommand(createQemuCmd)
	createCmd.AddCommand(createDockerCmd)
	clustercmd.Cmd.AddCommand(createCmd)

	createQemuCmd.Flag(clustercmd.ProvisionerFlagName).Hidden = true
	createDockerCmd.Flag(clustercmd.ProvisionerFlagName).Hidden = true
}

func validateBasicFlags(cmd *cobra.Command, allowedFlags []string, provisioner string) error {
	errMsg := ""

	if cmd.Flag(clustercmd.ProvisionerFlagName).Changed {
		errMsg += "\nerror: superfluous \"provisioner\" flag found"
	}

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Changed && !slices.Contains(allowedFlags, f.Name) && f.Name != clustercmd.ProvisionerFlagName {
			errMsg += fmt.Sprintf("\nthe \"%s\" flag is not supported on the \"create %s\" command, use \"create %s dev\" instead for advanced functionaliry", f.Name, provisioner, provisioner)
		}
	})

	if errMsg != "" {
		return fmt.Errorf("invalid flag(s) found:%s", errMsg)
	}

	return nil
}

func hideNonBasicFlags(cmd *cobra.Command, allowedFlags ...string) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !slices.Contains(allowedFlags, f.Name) {
			f.Hidden = true
		}
	})
}

// validateFlags checks if flags not applicable for the given provisioner are passed.
//
//nolint:gocyclo
func validateFlags(
	provisioner string,
	allCmdFlags, qemuFlags, dockerFlags *pflag.FlagSet,
	unImplementedQemuFlagsDarwin []string,
	errOnProviderFlag bool,
	cmd *cobra.Command,
) error {
	var invalidFlags *pflag.FlagSet

	errMsg := ""

	if errOnProviderFlag && cmd.Flag(clustercmd.ProvisionerFlagName).Changed {
		errMsg += "error: superfluous \"provisioner\" flag found \n"
	}

	switch provisioner {
	case providers.DockerProviderName:
		invalidFlags = qemuFlags
	case providers.QemuProviderName:
		invalidFlags = dockerFlags
	}

	allCmdFlags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			if runtime.GOOS == "darwin" && slices.Contains(unImplementedQemuFlagsDarwin, f.Name) {
				errMsg += fmt.Sprintf("the \"%s\" flag is not supported on macos\n", f.Name)
			}

			if invalidFlags.Lookup(f.Name) != nil && f.Name != clustercmd.ProvisionerFlagName {
				errMsg += fmt.Sprintf("%s flag has been set but has no effect with the %s provisioner\n", f.Name, provisioner)
			}
		}
	})

	if errMsg != "" {
		return fmt.Errorf("%sinvalid flags found", errMsg)
	}

	return nil
}

func hideUnimplementedQemuFlags(cmd *cobra.Command, unImplementedQemuFlagsDarwin []string) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if runtime.GOOS != "darwin" {
			return
		}

		for _, unimplemented := range unImplementedQemuFlagsDarwin {
			if f.Name == unimplemented {
				f.Hidden = true
			}
		}
	})
}
