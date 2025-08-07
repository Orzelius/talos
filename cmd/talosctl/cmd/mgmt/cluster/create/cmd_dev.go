// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/docker/cli/opts"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	clustercmd "github.com/siderolabs/talos/cmd/talosctl/cmd/mgmt/cluster"
	"github.com/siderolabs/talos/cmd/talosctl/pkg/mgmt/helpers"
	"github.com/siderolabs/talos/pkg/cli"
	"github.com/siderolabs/talos/pkg/images"
	"github.com/siderolabs/talos/pkg/machinery/config"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/version"
	"github.com/siderolabs/talos/pkg/provision/providers"
)

var (
	workersFlagName           = "workers"
	controlplanesFlagName     = "controlplanes"
	kubernetesVersionFlagName = "kubernetes-version"
	registryMirrorFlagName    = "registry-mirror"

	// user facing command flags.
	talosconfigDestinationFlagName = "talosconfig-destination"
	taloscoVersionFlagName         = "talos-version"
	disksFlagName                  = "disks"
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
	controlplaneResources     nodeResources
	workerResources           nodeResources
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
	talosVersion              string
	enableKubeSpan            bool
	enableClusterDiscovery    bool
	configPatch               []string
	configPatchControlPlane   []string
	configPatchWorker         []string
	kubePrismPort             int
	skipK8sNodeReadinessCheck bool
	withJSONLogs              bool
	wireguardCIDR             string
}

type qemuOps struct {
	nodeInstallImage          string
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
	disks                     []string
	diskBlockSize             uint
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
	networkIPv6               bool
}

type legacyOps struct {
	clusterDiskSize   int
	extraDisks        int
	extraDiskSize     int
	extraDisksDrivers []string
}

type dockerOps struct {
	hostIP      string
	disableIPv6 bool
	mountOpts   opts.MountOpt
	ports       string
}

type createOps struct {
	common commonOps
	docker dockerOps
	qemu   qemuOps
}

//nolint:gocyclo
func init() {
	const (
		inputDirFlag                  = "input-dir"
		networkIPv4Flag               = "ipv4"
		networkIPv6Flag               = "ipv6"
		networkMTUFlag                = "mtu"
		networkCIDRFlag               = "cidr"
		networkNoMasqueradeCIDRsFlag  = "no-masquerade-cidrs"
		nameserversFlag               = "nameservers"
		preallocateDisksFlag          = "disk-preallocate"
		clusterUserVolumesFlag        = "user-volumes"
		clusterDiskSizeFlag           = "disk"
		diskBlockSizeFlag             = "disk-block-size"
		useVIPFlag                    = "use-vip"
		bootloaderEnabledFlag         = "with-bootloader"
		controlPlanePortFlag          = "control-plane-port"
		firewallFlag                  = "with-firewall"
		tpmEnabledFlag                = "with-tpm1_2"
		tpm2EnabledFlag               = "with-tpm2"
		withDebugShellFlag            = "with-debug-shell"
		withIOMMUFlag                 = "with-iommu"
		talosconfigFlag               = "talosconfig"
		applyConfigEnabledFlag        = "with-apply-config"
		wireguardCIDRFlag             = "wireguard-cidr"
		controlPlaneCpusFlag          = "cpus"
		workersCpusFlag               = "cpus-workers"
		controlPlaneMemoryFlag        = "memory"
		workersMemoryFlag             = "memory-workers"
		clusterWaitFlag               = "wait"
		clusterWaitTimeoutFlag        = "wait-timeout"
		forceInitNodeAsEndpointFlag   = "init-node-as-endpoint"
		withInitNodeFlag              = "with-init-node"
		skipKubeconfigFlag            = "skip-kubeconfig"
		skipInjectingConfigFlag       = "skip-injecting-config"
		configPatchFlag               = "config-patch"
		configPatchControlPlaneFlag   = "config-patch-control-plane"
		configPatchWorkerFlag         = "config-patch-worker"
		skipK8sNodeReadinessCheckFlag = "skip-k8s-node-readiness-check"
		withJSONLogsFlag              = "with-json-logs"
		nodeVmlinuzPathFlag           = "vmlinuz-path"
		nodeISOPathFlag               = "iso-path"
		nodeUSBPathFlag               = "usb-path"
		nodeUKIPathFlag               = "uki-path"
		nodeInitramfsPathFlag         = "initrd-path"
		nodeDiskImagePathFlag         = "disk-image-path"
		nodeIPXEBootScriptFlag        = "ipxe-boot-script"
		uefiEnabledFlag               = "with-uefi"
		extraUEFISearchPathsFlag      = "extra-uefi-search-paths"
		extraDisksFlag                = "extra-disks"
		extraDisksDriversFlag         = "extra-disks-drivers"
		extraDiskSizeFlag             = "extra-disks-size"
		targetArchFlag                = "arch"
		cniBinPathFlag                = "cni-bin-path"
		cniConfDirFlag                = "cni-conf-dir"
		cniCacheDirFlag               = "cni-cache-dir"
		cniBundleURLFlag              = "cni-bundle-url"
		badRTCFlag                    = "bad-rtc"
		extraBootKernelArgsFlag       = "extra-boot-kernel-args"
		dhcpSkipHostnameFlag          = "disable-dhcp-hostname"
		networkChaosFlag              = "with-network-chaos"
		jitterFlag                    = "with-network-jitter"
		latencyFlag                   = "with-network-latency"
		packetLossFlag                = "with-network-packet-loss"
		packetReorderFlag             = "with-network-packet-reorder"
		packetCorruptFlag             = "with-network-packet-corrupt"
		bandwidthFlag                 = "with-network-bandwidth"
		withUUIDHostnamesFlag         = "with-uuid-hostnames"
		withSiderolinkAgentFlag       = "with-siderolink"
		configInjectionMethodFlag     = "config-injection-method"

		// The following flags are the gen options - the options that are only used in machine configuration (i.e., not during the qemu/docker provisioning).
		// They are not applicable when no machine configuration is generated, hence mutually exclusive with the --input-dir flag.

		nodeInstallImageFlag          = "install-image"
		configDebugFlag               = "with-debug"
		dnsDomainFlag                 = "dns-domain"
		withClusterDiscoveryFlag      = "with-cluster-discovery"
		registryInsecureFlag          = "registry-insecure-skip-verify"
		customCNIUrlFlag              = "custom-cni-url"
		talosconfigVersionFlag        = "talos-version"
		encryptStatePartitionFlag     = "encrypt-state"
		encryptEphemeralPartitionFlag = "encrypt-ephemeral"
		encryptUserVolumeFlag         = "encrypt-user-volumes"
		enableKubeSpanFlag            = "with-kubespan"
		forceEndpointFlag             = "endpoint"
		kubePrismFlag                 = "kubeprism-port"
		diskEncryptionKeyTypesFlag    = "disk-encryption-key-types"
	)

	unImplementedFlagsDarwin := []string{
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

	ops := &createOps{
		common: commonOps{},
		docker: dockerOps{},
		qemu:   qemuOps{},
	}
	legacyOps := legacyOps{}

	getCommonFlags := func() *pflag.FlagSet {
		common := pflag.NewFlagSet("common", pflag.PanicOnError)

		addControlplaneCpusFlag(common, &ops.common.controlplaneResources.cpu, controlPlaneCpusFlag)
		addWorkersCpusFlag(common, &ops.common.workerResources.cpu, workersCpusFlag)
		addControlPlaneMemoryFlag(common, &ops.common.controlplaneResources.memory, controlPlaneMemoryFlag)
		addWorkersMemoryFlag(common, &ops.common.workerResources.memory, workersMemoryFlag)

		addWorkersFlag(common, &ops.common.workers)
		addControlplanesFlag(common, &ops.common.controlplanes)
		addKubernetesVersionFlag(common, &ops.common.kubernetesVersion)
		addTalosconfigDestinationFlag(common, &ops.common.talosconfigDestination, talosconfigFlag)
		addConfigPatchFlag(common, &ops.common.configPatch, configPatchFlag)
		addConfigPatchControlPlaneFlag(common, &ops.common.configPatchControlPlane, configPatchControlPlaneFlag)
		addConfigPatchWorkerFlag(common, &ops.common.configPatchWorker, configPatchWorkerFlag)
		addRegistryMirrorFlag(common, &ops.common.registryMirrors)

		common.StringVar(&ops.common.networkCIDR, networkCIDRFlag, "10.5.0.0/24", "CIDR of the cluster network (IPv4, ULA network for IPv6 is derived in automated way)")
		common.StringVar(&ops.common.wireguardCIDR, wireguardCIDRFlag, "", "CIDR of the wireguard network")
		common.BoolVar(&ops.common.applyConfigEnabled, applyConfigEnabledFlag, false, "enable apply config when the VM is starting in maintenance mode")
		common.StringSliceVar(&ops.common.registryInsecure, registryInsecureFlag, []string{}, "list of registry hostnames to skip TLS verification for")
		common.IntVar(&ops.common.controlPlanePort, controlPlanePortFlag, constants.DefaultControlPlanePort, "control plane port (load balancer and local API port)")
		common.BoolVar(&ops.common.configDebug, configDebugFlag, false, "enable debug in Talos config to send service logs to the console")
		common.IntVar(&ops.common.networkMTU, networkMTUFlag, 1500, "MTU of the cluster network")
		common.BoolVar(&ops.common.networkIPv4, networkIPv4Flag, true, "enable IPv4 network in the cluster")
		common.BoolVar(&ops.common.clusterWait, clusterWaitFlag, true, "wait for the cluster to be ready before returning")
		common.DurationVar(&ops.common.clusterWaitTimeout, clusterWaitTimeoutFlag, 20*time.Minute, "timeout to wait for the cluster to be ready")
		common.BoolVar(&ops.common.forceInitNodeAsEndpoint, forceInitNodeAsEndpointFlag, false, "use init node as endpoint instead of any load balancer endpoint")
		common.StringVar(&ops.common.forceEndpoint, forceEndpointFlag, "", "use endpoint instead of provider defaults")
		common.StringVarP(&ops.common.inputDir, inputDirFlag, "i", "", "location of pre-generated config files")
		common.BoolVar(&ops.common.withInitNode, withInitNodeFlag, false, "create the cluster with an init node")
		common.StringVar(&ops.common.customCNIUrl, customCNIUrlFlag, "", "install custom CNI from the URL (Talos cluster)")
		common.StringVar(&ops.common.dnsDomain, dnsDomainFlag, "cluster.local", "the dns domain to use for cluster")
		common.BoolVar(&ops.common.skipKubeconfig, skipKubeconfigFlag, false, "skip merging kubeconfig from the created cluster")
		common.BoolVar(&ops.common.skipInjectingConfig, skipInjectingConfigFlag, false, "skip injecting config from embedded metadata server, write config files to current directory")
		common.BoolVar(&ops.common.enableClusterDiscovery, withClusterDiscoveryFlag, true, "enable cluster discovery")
		common.BoolVar(&ops.common.enableKubeSpan, enableKubeSpanFlag, false, "enable KubeSpan system")
		common.IntVar(&ops.common.kubePrismPort, kubePrismFlag, constants.DefaultKubePrismPort, "KubePrism port (set to 0 to disable)")
		common.BoolVar(&ops.common.skipK8sNodeReadinessCheck, skipK8sNodeReadinessCheckFlag, false, "skip k8s node readiness checks")
		common.BoolVar(&ops.common.withJSONLogs, withJSONLogsFlag, false, "enable JSON logs receiver and configure Talos to send logs there")
		common.StringVar(&ops.common.talosVersion, talosconfigVersionFlag, "", "the desired Talos version to generate config for (if not set, defaults to image version)")

		return common
	}

	// getBasicQemuFlags returns the qemu flags that are also present on the user-facing qemu command
	getBasicQemuFlags := func() *pflag.FlagSet {
		qemu := pflag.NewFlagSet("qemu", pflag.PanicOnError)

		qemu.BoolVar(&ops.qemu.preallocateDisks, preallocateDisksFlag, true, "whether disk space should be preallocated")
		qemu.StringSliceVar(&ops.qemu.clusterUserVolumes, clusterUserVolumesFlag, []string{}, "list of user volumes to create for each VM in format: <name1>:<size1>:<name2>:<size2>")

		return qemu
	}

	// getUserQemuFlags returns the common flags that are only present on the user-facing qemu command.
	// getUserQemuFlags := func() *pflag.FlagSet {
	// 	qemu := getBasicQemuFlags()

	// 	qemu.StringSliceVar(&ops.qemu.disks, disksFlagName, []string{"virtio:" + strconv.Itoa(6*1024)},
	// 		`list of disks to create in format "<driver1>:<size1>" (size is specified in megabytes) (disks after the first one are added only to worker machines)`)

	// 	return qemu
	// }

	getQemuFlags := func() *pflag.FlagSet {
		qemu := getBasicQemuFlags()

		qemu.StringVar(&ops.qemu.nodeInstallImage, nodeInstallImageFlag, helpers.DefaultImage(images.DefaultInstallerImageRepository), "the installer image to use")
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
		qemu.IntVar(&legacyOps.clusterDiskSize, clusterDiskSizeFlag, 6*1024, "default limit on disk size in MB (each VM)")
		qemu.UintVar(&ops.qemu.diskBlockSize, diskBlockSizeFlag, 512, "disk block size")
		qemu.IntVar(&legacyOps.extraDisks, extraDisksFlag, 0, "number of extra disks to create for each worker VM")
		qemu.StringSliceVar(&legacyOps.extraDisksDrivers, "extra-disks-drivers", nil, "driver for each extra disk (virtio, ide, ahci, scsi, nvme, megaraid)")
		qemu.IntVar(&legacyOps.extraDiskSize, extraDiskSizeFlag, 5*1024, "default limit on disk size in MB (each VM)")
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
		qemu.BoolVar(&ops.qemu.networkIPv6, networkIPv6Flag, false, "enable IPv6 network in the cluster")
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

		return qemu
	}

	ops.common.rootOps = &clustercmd.Flags

	// createCmd is the developer oriented create command.
	createCmd := &cobra.Command{
		Use:    "create",
		Hidden: false, // todo: set to true once create-qemu command is implemented
		Short:  "Creates a local cluster for Talos development",
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				if err := providers.IsValidProvider(ops.common.rootOps.ProvisionerName); err != nil {
					return err
				}
				if err := validateQemuFlags(cmd.Flags(), unImplementedFlagsDarwin); err != nil {
					return err
				}

				ops.qemu.disks = append(ops.qemu.disks, fmt.Sprintf("virtio:%d", legacyOps.clusterDiskSize))

				for i := range legacyOps.extraDisks {
					driver := "ide"

					// ide driver is not supported on arm64
					if ops.qemu.targetArch == "arm64" {
						driver = "virtio"
					}

					if i < len(legacyOps.extraDisksDrivers) {
						driver = legacyOps.extraDisksDrivers[i]
					}

					ops.qemu.disks = append(ops.qemu.disks, fmt.Sprintf("%s:%d", driver, legacyOps.extraDiskSize))
				}

				return create(ctx, *ops)
			})
		},
	}

	createQemuCmd := &cobra.Command{
		Use:    providers.QemuProviderName,
		Short:  "Create a local Qemu based kubernetes cluster",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				if cmd.Flag(clustercmd.ProvisionerFlag).Changed {
					return errors.New("superfluous \"provisioner\" flag found")
				}

				ops.common.rootOps.ProvisionerName = providers.QemuProviderName

				_, err := config.ParseContractFromVersion(ops.common.talosVersion)
				if err != nil {
					return fmt.Errorf("error parsing Talos version %q: %w", ops.common.talosVersion, err)
				}

				ops.qemu.nodeInstallImage = fmt.Sprintf("%s:%s", images.DefaultInstallerImageRepository, ops.common.talosVersion)
				ops.qemu.nodeISOPath = fmt.Sprintf("https://github.com/siderolabs/talos/releases/download/%s/metal-%s.iso", ops.common.talosVersion, runtime.GOARCH)

				return create(ctx, *ops)
			})
		},
	}

	createCmd.Flags().AddFlagSet(getCommonFlags())
	createCmd.Flags().AddFlagSet(getQemuFlags())

	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, nodeInstallImageFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, configDebugFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, dnsDomainFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, withClusterDiscoveryFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, registryMirrorFlagName)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, registryInsecureFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, customCNIUrlFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, talosconfigVersionFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, encryptStatePartitionFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, encryptEphemeralPartitionFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, encryptUserVolumeFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, enableKubeSpanFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, forceEndpointFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, kubePrismFlag)
	createCmd.MarkFlagsMutuallyExclusive(inputDirFlag, diskEncryptionKeyTypesFlag)

	createCmd.MarkFlagsMutuallyExclusive(tpmEnabledFlag, tpm2EnabledFlag)

	hideUnimplementedQemuFlags(createCmd, unImplementedFlagsDarwin)

	createCmd.AddCommand(createQemuCmd)
	clustercmd.Cmd.AddCommand(createCmd)
}

func validateQemuFlags(allCmdFlags *pflag.FlagSet, unImplementedQemuFlagsDarwin []string) error {
	errMsg := ""

	allCmdFlags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			if runtime.GOOS == "darwin" && slices.Contains(unImplementedQemuFlagsDarwin, f.Name) {
				errMsg += fmt.Sprintf("the \"%s\" flag is not supported on macos\n", f.Name)
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

func addTalosconfigDestinationFlag(flagset *pflag.FlagSet, bind *string, flagName string) {
	flagset.StringVar(bind, flagName, "",
		fmt.Sprintf("The location to save the generated Talos configuration file to. Defaults to '%s' env variable if set, otherwise '%s' and '%s' in order.",
			constants.TalosConfigEnvVar,
			filepath.Join("$HOME", constants.TalosDir, constants.TalosconfigFilename),
			filepath.Join(constants.ServiceAccountMountPath, constants.TalosconfigFilename),
		),
	)
}

func addControlplaneCpusFlag(flagset *pflag.FlagSet, bind *string, flagName string) {
	flagset.StringVar(bind, flagName, "2.0", "the share of CPUs as fraction (each control plane/VM)")
}

func addWorkersCpusFlag(flagset *pflag.FlagSet, bind *string, flagName string) {
	flagset.StringVar(bind, flagName, "2.0", "the share of CPUs as fraction (each worker/VM)")
}

func addControlPlaneMemoryFlag(flagset *pflag.FlagSet, bind *int, flagName string) {
	flagset.IntVar(bind, flagName, 2048, "the limit on memory usage in MB (each control plane/VM)")
}

func addWorkersMemoryFlag(flagset *pflag.FlagSet, bind *int, flagName string) {
	flagset.IntVar(bind, flagName, 2048, "the limit on memory usage in MB (each worker/VM)")
}

func addConfigPatchFlag(flagset *pflag.FlagSet, bind *[]string, flagName string) {
	flagset.StringArrayVar(bind, flagName, nil, "patch generated machineconfigs (applied to all node types), use @file to read a patch from file")
}

func addConfigPatchControlPlaneFlag(flagset *pflag.FlagSet, bind *[]string, flagName string) {
	flagset.StringArrayVar(bind, flagName, nil, "patch generated machineconfigs (applied to 'init' and 'controlplane' types)")
}

func addConfigPatchWorkerFlag(flagset *pflag.FlagSet, bind *[]string, flagName string) {
	flagset.StringArrayVar(bind, flagName, nil, "patch generated machineconfigs (applied to 'worker' type)")
}

func addWorkersFlag(flagset *pflag.FlagSet, bind *int) {
	flagset.IntVar(bind, workersFlagName, 1, "the number of workers to create")
}

func addControlplanesFlag(flagset *pflag.FlagSet, bind *int) {
	flagset.IntVar(bind, controlplanesFlagName, 1, "the number of controlplanes to create")
}

func addKubernetesVersionFlag(flagset *pflag.FlagSet, bind *string) {
	flagset.StringVar(bind, kubernetesVersionFlagName, constants.DefaultKubernetesVersion, "desired kubernetes version to run")
}

func addTalosVersionFlag(flagset *pflag.FlagSet, bind *string) {
	flagset.StringVar(bind, taloscoVersionFlagName, helpers.GetTag(), "the desired Talos version")
}

func addRegistryMirrorFlag(flagset *pflag.FlagSet, bind *[]string) {
	flagset.StringSliceVar(bind, registryMirrorFlagName, []string{}, "list of registry mirrors to use in format: <registry host>=<mirror URL>")
}
