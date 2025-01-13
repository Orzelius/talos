// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	stdruntime "runtime"

	"github.com/docker/cli/opts"
	"github.com/siderolabs/talos/cmd/talosctl/cmd/mgmt/cluster"
	"github.com/siderolabs/talos/cmd/talosctl/pkg/mgmt/helpers"
	"github.com/siderolabs/talos/pkg/cli"
	"github.com/siderolabs/talos/pkg/images"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/version"
	"github.com/siderolabs/talos/pkg/provision/providers"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type CommonOps struct {
	// rootOps are the options from the root cluster command
	rootOps                   *cluster.ClusterCmdOps
	talosconfig               string
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
	crashdumpOnFailure        bool
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

type QemuOps struct {
	nodeInstallImage             string
	nodeVmlinuzPath              string
	nodeInitramfsPath            string
	nodeISOPath                  string
	nodeDiskImagePath            string
	nodeIPXEBootScript           string
	bootloaderEnabled            bool
	uefiEnabled                  bool
	tpm2Enabled                  bool
	extraUEFISearchPaths         []string
	networkNoMasqueradeCIDRs     []string
	networkIPv6                  bool
	nameservers                  []string
	clusterDiskSize              int
	clusterDiskPreallocate       bool
	clusterDisks                 []string
	extraDisks                   int
	extraDiskSize                int
	extraDisksDrivers            []string
	targetArch                   string
	cniBinPath                   []string
	cniConfDir                   string
	cniCacheDir                  string
	cniBundleURL                 string
	encryptStatePartition        bool
	encryptEphemeralPartition    bool
	useVIP                       bool
	badRTC                       bool
	extraBootKernelArgs          string
	dhcpSkipHostname             bool
	networkChaos                 bool
	jitter                       time.Duration
	latency                      time.Duration
	packetLoss                   float64
	packetReorder                float64
	packetCorrupt                float64
	bandwidth                    int
	diskEncryptionKeyTypes       []string
	withFirewall                 string
	withUUIDHostnames            bool
	withSiderolinkAgent          agentFlag
	debugShellEnabled            bool
	configInjectionMethodFlagVal string
}

type DockerOps struct {
	dockerHostIP      string
	dockerDisableIPv6 bool
	mountOpts         opts.MountOpt
	ports             string
	nodeImage         string
}

func init() {
	const (
		// Docker
		dockerHostIPFlag      = "docker-host-ip"
		nodeImageFlag         = "image"
		portsFlag             = "exposed-ports"
		dockerDisableIPv6Flag = "docker-disable-ipv6"
		mountOptsFlag         = "mount"

		// TODO sort
		inputDirFlag                  = "input-dir"
		networkIPv4Flag               = "ipv4"
		networkIPv6Flag               = "ipv6"
		networkMTUFlag                = "mtu"
		networkCIDRFlag               = "cidr"
		networkNoMasqueradeCIDRsFlag  = "no-masquerade-cidrs"
		nameserversFlag               = "nameservers"
		clusterDiskPreallocateFlag    = "disk-preallocate"
		clusterDisksFlag              = "user-disk"
		clusterDiskSizeFlag           = "disk"
		useVIPFlag                    = "use-vip"
		bootloaderEnabledFlag         = "with-bootloader"
		controlPlanePortFlag          = "control-plane-port"
		firewallFlag                  = "with-firewall"
		tpm2EnabledFlag               = "with-tpm2"
		withDebugShellFlag            = "with-debug-shell"
		talosconfigFlag               = "talosconfig"
		applyConfigEnabledFlag        = "with-apply-config"
		wireguardCIDRFlag             = "wireguard-cidr"
		workersFlag                   = "workers"
		mastersFlag                   = "masters"
		controlplanesFlag             = "controlplanes"
		controlPlaneCpusFlag          = "cpus"
		workersCpusFlag               = "cpus-workers"
		controlPlaneMemoryFlag        = "memory"
		workersMemoryFlag             = "memory-workers"
		clusterWaitFlag               = "wait"
		clusterWaitTimeoutFlag        = "wait-timeout"
		forceInitNodeAsEndpointFlag   = "init-node-as-endpoint"
		kubernetesVersionFlag         = "kubernetes-version"
		withInitNodeFlag              = "with-init-node"
		crashdumpOnFailureFlag        = "crashdump"
		skipKubeconfigFlag            = "skip-kubeconfig"
		skipInjectingConfigFlag       = "skip-injecting-config"
		configPatchFlag               = "config-patch"
		configPatchControlPlaneFlag   = "config-patch-control-plane"
		configPatchWorkerFlag         = "config-patch-worker"
		skipK8sNodeReadinessCheckFlag = "skip-k8s-node-readiness-check"
		withJSONLogsFlag              = "with-json-logs"

		// qemu
		nodeVmlinuzPathFlag       = "vmlinuz-path"
		nodeISOPathFlag           = "iso-path"
		nodeInitramfsPathFlag     = "initrd-path"
		nodeDiskImagePathFlag     = "disk-image-path"
		nodeIPXEBootScriptFlag    = "ipxe-boot-script"
		uefiEnabledFlag           = "with-uefi"
		extraUEFISearchPathsFlag  = "extra-uefi-search-paths"
		extraDisksFlag            = "extra-disks"
		extraDisksDriversFlag     = "extra-disks-drivers"
		extraDiskSizeFlag         = "extra-disks-size"
		targetArchFlag            = "arch"
		cniBinPathFlag            = "cni-bin-path"
		cniConfDirFlag            = "cni-conf-dir"
		cniCacheDirFlag           = "cni-cache-dir"
		cniBundleURLFlag          = "cni-bundle-url"
		badRTCFlag                = "bad-rtc"
		extraBootKernelArgsFlag   = "extra-boot-kernel-args"
		dhcpSkipHostnameFlag      = "disable-dhcp-hostname"
		networkChaosFlag          = "with-network-chaos"
		jitterFlag                = "with-network-jitter"
		latencyFlag               = "with-network-latency"
		packetLossFlag            = "with-network-packet-loss"
		packetReorderFlag         = "with-network-packet-reorder"
		packetCorruptFlag         = "with-network-packet-corrupt"
		bandwidthFlag             = "with-network-bandwidth"
		withUUIDHostnamesFlag     = "with-uuid-hostnames"
		withSiderolinkAgentFlag   = "with-siderolink"
		configInjectionMethodFlag = "config-injection-method"

		// The following flags are the gen options - the options that are only used in machine configuration (i.e., not during the qemu/docker provisioning).
		// They are not applicable when no machine configuration is generated, hence mutually exclusive with the --input-dir flag.

		nodeInstallImageFlag          = "install-image"
		configDebugFlag               = "with-debug"
		dnsDomainFlag                 = "dns-domain"
		withClusterDiscoveryFlag      = "with-cluster-discovery"
		registryMirrorFlag            = "registry-mirror"
		registryInsecureFlag          = "registry-insecure-skip-verify"
		customCNIUrlFlag              = "custom-cni-url"
		talosVersionFlag              = "talos-version"
		encryptStatePartitionFlag     = "encrypt-state"
		encryptEphemeralPartitionFlag = "encrypt-ephemeral"
		enableKubeSpanFlag            = "with-kubespan"
		forceEndpointFlag             = "endpoint"
		kubePrismFlag                 = "kubeprism-port"
		diskEncryptionKeyTypesFlag    = "disk-encryption-key-types"
	)

	unImplementedQemuFlagsDarwin := []string{
		nodeIPXEBootScriptFlag,
		bootloaderEnabledFlag,
		tpm2EnabledFlag,
		withDebugShellFlag,
		networkNoMasqueradeCIDRsFlag,
		networkIPv6Flag,
		nameserversFlag,
		wireguardCIDRFlag,
		cniBinPathFlag,
		cniConfDirFlag,
		cniCacheDirFlag,
		cniBundleURLFlag,
		useVIPFlag,
		badRTCFlag,
		dhcpSkipHostnameFlag,
		networkChaosFlag,
		jitterFlag,
		latencyFlag,
		packetLossFlag,
		packetReorderFlag,
		packetCorruptFlag,
		bandwidthFlag,
		firewallFlag,
		withUUIDHostnamesFlag,
		withSiderolinkAgentFlag,
		configInjectionMethodFlag,
	}
	unImplementedQemuFlagsLinux := []string{}

	var commonOps = CommonOps{}
	commonOps.rootOps = &cluster.Flags
	var qemuOps = QemuOps{}
	var dockerOps = DockerOps{}

	getDockerFlags := func() *pflag.FlagSet {
		dockerFlags := pflag.NewFlagSet("", pflag.PanicOnError)
		// Flags specific to the Docker provider
		dockerFlags.StringVar(&dockerOps.dockerHostIP, dockerHostIPFlag, "0.0.0.0", "Host IP to forward exposed ports to")
		dockerFlags.StringVar(&dockerOps.nodeImage, nodeImageFlag, helpers.DefaultImage(images.DefaultTalosImageRepository), "the image to use")
		dockerFlags.StringVarP(&dockerOps.ports, portsFlag, "p", "",
			"Comma-separated list of ports/protocols to expose on init node. Ex -p <hostPort>:<containerPort>/<protocol (tcp or udp)>")
		dockerFlags.BoolVar(&dockerOps.dockerDisableIPv6, dockerDisableIPv6Flag, false, "skip enabling IPv6 in containers")
		dockerFlags.Var(&dockerOps.mountOpts, mountOptsFlag, "attach a mount to the container (Docker only)")

		dockerFlags.VisitAll(func(f *pflag.Flag) {
			f.Usage = "(docker only) " + f.Usage
		})
		return dockerFlags
	}

	getQemuFlags := func() *pflag.FlagSet {
		qemuFlags := pflag.NewFlagSet("", pflag.PanicOnError)
		// Flags specific to the QEMU provider
		qemuFlags.StringVar(&qemuOps.nodeInstallImage, nodeInstallImageFlag, helpers.DefaultImage(images.DefaultInstallerImageRepository), "the installer image to use")
		qemuFlags.StringVar(&qemuOps.nodeVmlinuzPath, nodeVmlinuzPathFlag, helpers.ArtifactPath(constants.KernelAssetWithArch), "the compressed kernel image to use")
		qemuFlags.StringVar(&qemuOps.nodeISOPath, nodeISOPathFlag, "", "the ISO path to use for the initial boot")
		qemuFlags.StringVar(&qemuOps.nodeInitramfsPath, nodeInitramfsPathFlag, helpers.ArtifactPath(constants.InitramfsAssetWithArch), "initramfs image to use")
		qemuFlags.StringVar(&qemuOps.nodeDiskImagePath, nodeDiskImagePathFlag, "", "disk image to use")
		qemuFlags.StringVar(&qemuOps.nodeIPXEBootScript, nodeIPXEBootScriptFlag, "", "iPXE boot script (URL) to use")
		qemuFlags.BoolVar(&qemuOps.bootloaderEnabled, bootloaderEnabledFlag, true, "enable bootloader to load kernel and initramfs from disk image after install")
		qemuFlags.BoolVar(&qemuOps.uefiEnabled, uefiEnabledFlag, true, "enable UEFI on x86_64 architecture")
		qemuFlags.BoolVar(&qemuOps.tpm2Enabled, tpm2EnabledFlag, false, "enable TPM2 emulation support using swtpm")
		qemuFlags.BoolVar(&qemuOps.debugShellEnabled, withDebugShellFlag, false, "drop talos into a maintenance shell on boot, this is for advanced debugging for developers only")
		qemuFlags.MarkHidden("with-debug-shell") //nolint:errcheck
		qemuFlags.StringSliceVar(&qemuOps.extraUEFISearchPaths, extraUEFISearchPathsFlag, []string{}, "additional search paths for UEFI firmware (only applies when UEFI is enabled)")
		qemuFlags.StringSliceVar(&qemuOps.networkNoMasqueradeCIDRs, networkNoMasqueradeCIDRsFlag, []string{}, "list of CIDRs to exclude from NAT")
		qemuFlags.BoolVar(&qemuOps.networkIPv6, networkIPv6Flag, false, "enable IPv6 network in the cluster")
		qemuFlags.StringSliceVar(&qemuOps.nameservers, nameserversFlag, []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"}, "list of nameservers to use")
		qemuFlags.IntVar(&qemuOps.clusterDiskSize, clusterDiskSizeFlag, 6*1024, "default limit on disk size in MB (each VM)")
		qemuFlags.BoolVar(&qemuOps.clusterDiskPreallocate, clusterDiskPreallocateFlag, true, "whether disk space should be preallocated")
		qemuFlags.StringSliceVar(&qemuOps.clusterDisks, clusterDisksFlag, []string{}, "list of disks to create for each VM in format: <mount_point1>:<size1>:<mount_point2>:<size2>")
		qemuFlags.IntVar(&qemuOps.extraDisks, extraDisksFlag, 0, "number of extra disks to create for each worker VM")
		qemuFlags.StringSliceVar(&qemuOps.extraDisksDrivers, extraDisksDriversFlag, nil, "driver for each extra disk (virtio, ide, ahci, scsi, nvme)")
		qemuFlags.IntVar(&qemuOps.extraDiskSize, extraDiskSizeFlag, 5*1024, "default limit on disk size in MB (each VM)")
		qemuFlags.StringVar(&qemuOps.targetArch, targetArchFlag, stdruntime.GOARCH, "cluster architecture")
		qemuFlags.StringSliceVar(&qemuOps.cniBinPath, cniBinPathFlag, []string{filepath.Join(commonOps.rootOps.DefaultCNIDir, "bin")}, "search path for CNI binaries")
		qemuFlags.StringVar(&qemuOps.cniConfDir, cniConfDirFlag, filepath.Join(commonOps.rootOps.DefaultCNIDir, "conf.d"), "CNI config directory path")
		qemuFlags.StringVar(&qemuOps.cniCacheDir, cniCacheDirFlag, filepath.Join(commonOps.rootOps.DefaultCNIDir, "cache"), "CNI cache directory path")
		qemuFlags.StringVar(&qemuOps.cniBundleURL, cniBundleURLFlag, fmt.Sprintf("https://github.com/%s/talos/releases/download/%s/talosctl-cni-bundle-%s.tar.gz",
			images.Username, version.Trim(version.Tag), constants.ArchVariable), "URL to download CNI bundle from")
		qemuFlags.BoolVar(&qemuOps.encryptStatePartition, encryptStatePartitionFlag, false, "enable state partition encryption")
		qemuFlags.BoolVar(&qemuOps.encryptEphemeralPartition, encryptEphemeralPartitionFlag, false, "enable ephemeral partition encryption")
		qemuFlags.StringArrayVar(&qemuOps.diskEncryptionKeyTypes, diskEncryptionKeyTypesFlag, []string{"uuid"}, "encryption key types to use for disk encryption (uuid, kms)")
		qemuFlags.BoolVar(&qemuOps.useVIP, useVIPFlag, false, "use a virtual IP for the controlplane endpoint instead of the loadbalancer")
		qemuFlags.BoolVar(&qemuOps.badRTC, badRTCFlag, false, "launch VM with bad RTC state")
		qemuFlags.StringVar(&qemuOps.extraBootKernelArgs, extraBootKernelArgsFlag, "", "add extra kernel args to the initial boot from vmlinuz and initramfs")
		qemuFlags.BoolVar(&qemuOps.dhcpSkipHostname, dhcpSkipHostnameFlag, false, "skip announcing hostname via DHCP")
		qemuFlags.BoolVar(&qemuOps.networkChaos, networkChaosFlag, false, "enable network chaos parameters when creating a qemu cluster")
		qemuFlags.DurationVar(&qemuOps.jitter, jitterFlag, 0, "specify jitter on the bridge interface")
		qemuFlags.DurationVar(&qemuOps.latency, latencyFlag, 0, "specify latency on the bridge interface")
		qemuFlags.Float64Var(&qemuOps.packetLoss, packetLossFlag, 0.0, "specify percent of packet loss on the bridge interface. e.g. 50% = 0.50 (default: 0.0)")
		qemuFlags.Float64Var(&qemuOps.packetReorder, packetReorderFlag, 0.0, "specify percent of reordered packets on the bridge interface. e.g. 50% = 0.50 (default: 0.0)")
		qemuFlags.Float64Var(&qemuOps.packetCorrupt, packetCorruptFlag, 0.0, "specify percent of corrupt packets on the bridge interface. e.g. 50% = 0.50 (default: 0.0)")
		qemuFlags.IntVar(&qemuOps.bandwidth, bandwidthFlag, 0, "specify bandwidth restriction (in kbps) on the bridge interface")
		qemuFlags.StringVar(&qemuOps.withFirewall, firewallFlag, "", "inject firewall rules into the cluster, value is default policy - accept/block")
		qemuFlags.BoolVar(&qemuOps.withUUIDHostnames, withUUIDHostnamesFlag, false, "use machine UUIDs as default hostnames")
		qemuFlags.Var(&qemuOps.withSiderolinkAgent, withSiderolinkAgentFlag, "enables the use of siderolink agent as configuration apply mechanism. `true` or `wireguard` enables the agent, `tunnel` enables the agent with grpc tunneling") //nolint:lll
		qemuFlags.StringVar(&qemuOps.configInjectionMethodFlagVal, configInjectionMethodFlag, "", "a method to inject machine config: default is HTTP server, 'metal-iso' to mount an ISO")

		return qemuFlags
	}

	getCommonFlags := func() *pflag.FlagSet {
		commonFlags := pflag.NewFlagSet("", pflag.PanicOnError)
		commonFlags.StringVar(&commonOps.talosconfig, talosconfigFlag, "",
			fmt.Sprintf("The path to the Talos configuration file. Defaults to '%s' env variable if set, otherwise '%s' and '%s' in order.",
				constants.TalosConfigEnvVar,
				filepath.Join("$HOME", constants.TalosDir, constants.TalosconfigFilename),
				filepath.Join(constants.ServiceAccountMountPath, constants.TalosconfigFilename),
			),
		)
		commonFlags.BoolVar(&commonOps.applyConfigEnabled, applyConfigEnabledFlag, false, "enable apply config when the VM is starting in maintenance mode")
		commonFlags.StringSliceVar(&commonOps.registryMirrors, registryMirrorFlag, []string{}, "list of registry mirrors to use in format: <registry host>=<mirror URL>")
		commonFlags.StringSliceVar(&commonOps.registryInsecure, registryInsecureFlag, []string{}, "list of registry hostnames to skip TLS verification for")
		commonFlags.BoolVar(&commonOps.configDebug, configDebugFlag, false, "enable debug in Talos config to send service logs to the console")
		commonFlags.IntVar(&commonOps.networkMTU, networkMTUFlag, 1500, "MTU of the cluster network")
		commonFlags.StringVar(&commonOps.networkCIDR, networkCIDRFlag, "10.5.0.0/24", "CIDR of the cluster network (IPv4, ULA network for IPv6 is derived in automated way)")
		commonFlags.IntVar(&commonOps.controlPlanePort, controlPlanePortFlag, constants.DefaultControlPlanePort, "control plane port (load balancer and local API port)")
		commonFlags.BoolVar(&commonOps.networkIPv4, networkIPv4Flag, true, "enable IPv4 network in the cluster")
		commonFlags.StringVar(&commonOps.wireguardCIDR, wireguardCIDRFlag, "", "CIDR of the wireguard network")
		commonFlags.IntVar(&commonOps.workers, workersFlag, 1, "the number of workers to create")
		commonFlags.IntVar(&commonOps.controlplanes, mastersFlag, 1, "the number of masters to create")
		commonFlags.MarkDeprecated("commonOps.masters", "use --controlplanes instead") //nolint:errcheck
		commonFlags.IntVar(&commonOps.controlplanes, controlplanesFlag, 1, "the number of controlplanes to create")
		commonFlags.StringVar(&commonOps.controlPlaneCpus, controlPlaneCpusFlag, "2.0", "the share of CPUs as fraction (each control plane/VM)")
		commonFlags.StringVar(&commonOps.workersCpus, workersCpusFlag, "2.0", "the share of CPUs as fraction (each worker/VM)")
		commonFlags.IntVar(&commonOps.controlPlaneMemory, controlPlaneMemoryFlag, 2048, "the limit on memory usage in MB (each control plane/VM)")
		commonFlags.IntVar(&commonOps.workersMemory, workersMemoryFlag, 2048, "the limit on memory usage in MB (each worker/VM)")
		commonFlags.BoolVar(&commonOps.clusterWait, clusterWaitFlag, true, "wait for the cluster to be ready before returning")
		commonFlags.DurationVar(&commonOps.clusterWaitTimeout, clusterWaitTimeoutFlag, 20*time.Minute, "timeout to wait for the cluster to be ready")
		commonFlags.BoolVar(&commonOps.forceInitNodeAsEndpoint, forceInitNodeAsEndpointFlag, false, "use init node as endpoint instead of any load balancer endpoint")
		commonFlags.StringVar(&commonOps.forceEndpoint, forceEndpointFlag, "", "use endpoint instead of provider defaults")
		commonFlags.StringVar(&commonOps.kubernetesVersion, kubernetesVersionFlag, constants.DefaultKubernetesVersion, "desired kubernetes version to run")
		commonFlags.StringVarP(&commonOps.inputDir, inputDirFlag, "i", "", "location of pre-generated config files")
		commonFlags.BoolVar(&commonOps.withInitNode, withInitNodeFlag, false, "create the cluster with an init node")
		commonFlags.StringVar(&commonOps.customCNIUrl, customCNIUrlFlag, "", "install custom CNI from the URL (Talos cluster)")
		commonFlags.StringVar(&commonOps.dnsDomain, dnsDomainFlag, "cluster.local", "the dns domain to use for cluster")
		commonFlags.BoolVar(&commonOps.crashdumpOnFailure, crashdumpOnFailureFlag, false, "generate support zip when cluster startup fails")
		commonFlags.BoolVar(&commonOps.skipKubeconfig, skipKubeconfigFlag, false, "skip merging kubeconfig from the created cluster")
		commonFlags.BoolVar(&commonOps.skipInjectingConfig, skipInjectingConfigFlag, false, "skip injecting config from embedded metadata server, write config files to current directory")
		commonFlags.StringVar(&commonOps.talosVersion, talosVersionFlag, "", "the desired Talos version to generate config for (if not set, defaults to image version)")
		commonFlags.BoolVar(&commonOps.enableClusterDiscovery, withClusterDiscoveryFlag, true, "enable cluster discovery")
		commonFlags.BoolVar(&commonOps.enableKubeSpan, enableKubeSpanFlag, false, "enable KubeSpan system")
		commonFlags.StringArrayVar(&commonOps.configPatch, configPatchFlag, nil, "patch generated machineconfigs (applied to all node types), use @file to read a patch from file")
		commonFlags.StringArrayVar(&commonOps.configPatchControlPlane, configPatchControlPlaneFlag, nil, "patch generated machineconfigs (applied to 'init' and 'controlplane' types)")
		commonFlags.StringArrayVar(&commonOps.configPatchWorker, configPatchWorkerFlag, nil, "patch generated machineconfigs (applied to 'worker' type)")
		commonFlags.IntVar(&commonOps.kubePrismPort, kubePrismFlag, constants.DefaultKubePrismPort, "KubePrism port (set to 0 to disable)")
		commonFlags.BoolVar(&commonOps.skipK8sNodeReadinessCheck, skipK8sNodeReadinessCheckFlag, false, "skip k8s node readiness checks")
		commonFlags.BoolVar(&commonOps.withJSONLogs, withJSONLogsFlag, false, "enable JSON logs receiver and configure Talos to send logs there")

		return commonFlags
	}

	var commonFlags = getCommonFlags()
	var qemuFlags = getQemuFlags()
	var dockerFlags = getDockerFlags()
	var rootCmdQemuFlags = getQemuFlags()

	// validateProviderFlags checks if flags not applicable for the given provisioner and OS are passed
	validateProviderFlags := func(flags *pflag.FlagSet) error {
		var unImplemented []string = make([]string, 0)
		var invalidFlags *pflag.FlagSet
		switch commonOps.rootOps.ProvisionerName {
		case providers.DockerProviderName:
			invalidFlags = rootCmdQemuFlags
		case providers.QemuProviderName:
			invalidFlags = dockerFlags
			if currentOs == "darwin" {
				unImplemented = unImplementedQemuFlagsDarwin
			} else {
				unImplemented = unImplementedQemuFlagsLinux
			}
		}
		errLogged := false
		invalidFlags.VisitAll(func(invalidFlag *pflag.Flag) {
			if invalidFlag.Changed {
				fmt.Printf("%s flag has been set but has no effect with the %s provisioner\n", invalidFlag.Name, commonOps.rootOps.ProvisionerName)
				errLogged = true
			}
		})
		if errLogged {
			fmt.Println()
			return fmt.Errorf("Invalid provisioner flags founds")
		}

		err := validateFlags(flags, unImplemented, currentOs)
		return err
	}

	var createQemuCmd = &cobra.Command{
		Use:   providers.QemuProviderName,
		Short: "Creates a local qemu based kubernetes cluster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			validateCmdProvisioner(commonOps.rootOps.ProvisionerName, providers.QemuProviderName)
			commonOps.rootOps.ProvisionerName = providers.QemuProviderName
			if err := validateProviderFlags(cmd.Flags()); err != nil {
				return err
			}
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				return CreateQemuCluster(ctx, commonOps, qemuOps)
			})
		},
	}

	var createDockerCmd = &cobra.Command{
		Use:   providers.DockerProviderName,
		Short: "Creates a local docker based kubernetes cluster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			validateCmdProvisioner(commonOps.rootOps.ProvisionerName, providers.DockerProviderName)
			if err := validateProviderFlags(cmd.Flags()); err != nil {
				return err
			}
			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				return CreateDockerCluster(ctx, commonOps, dockerOps)
			})
		},
	}

	// createCmd represents the cluster up command.
	var createCmd = &cobra.Command{
		Use:   "create",
		Short: "Creates a local docker-based or QEMU-based kubernetes cluster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := providers.IsValidProvider(commonOps.rootOps.ProvisionerName); err != nil {
				return err
			}
			if err := validateProviderFlags(cmd.Flags()); err != nil {
				return err
			}

			return cli.WithContext(context.Background(), func(ctx context.Context) error {
				if commonOps.rootOps.ProvisionerName == providers.DockerProviderName {
					return CreateDockerCluster(ctx, commonOps, dockerOps)
				} else {
					return CreateQemuCluster(ctx, commonOps, qemuOps)
				}
			})
		},
	}

	qemuFlags.VisitAll(func(f *pflag.Flag) {
		isUnimplementedOnDarwin := slices.Contains(unImplementedQemuFlagsDarwin, f.Name)
		if isUnimplementedOnDarwin && currentOs == "darwin" {
			f.Usage = "(linux only) " + f.Usage
		}
	})
	rootCmdQemuFlags.VisitAll(func(f *pflag.Flag) {
		isUnimplemented := slices.Contains(unImplementedQemuFlagsDarwin, f.Name)
		if isUnimplemented {
			f.Usage = "(QEMU with linux only) " + f.Usage
		} else {
			f.Usage = "(QEMU only) " + f.Usage
		}
	})

	createCmd.Flags().AddFlagSet(commonFlags)
	createCmd.Flags().AddFlagSet(dockerFlags)
	createCmd.Flags().AddFlagSet(rootCmdQemuFlags)

	// The individual flagsets are still sorted
	createCmd.Flags().SortFlags = false
	createDockerCmd.Flags().SortFlags = false
	createQemuCmd.Flags().SortFlags = false

	markInputDirFlagsExclusive := func(cmd *cobra.Command) {
		exclusiveFlags := []string{
			nodeInstallImageFlag,
			configDebugFlag,
			dnsDomainFlag,
			withClusterDiscoveryFlag,
			registryMirrorFlag,
			registryInsecureFlag,
			customCNIUrlFlag,
			talosVersionFlag,
			encryptStatePartitionFlag,
			encryptEphemeralPartitionFlag,
			enableKubeSpanFlag,
			forceEndpointFlag,
			kubePrismFlag,
			diskEncryptionKeyTypesFlag}

		for _, f := range exclusiveFlags {
			if cmd.Flag(f) != nil {
				cmd.MarkFlagsMutuallyExclusive(inputDirFlag, f)
			}
		}
	}
	markInputDirFlagsExclusive(createCmd)
	markInputDirFlagsExclusive(createQemuCmd)
	markInputDirFlagsExclusive(createDockerCmd)

	createDockerCmd.Flags().AddFlagSet(commonFlags)
	createDockerCmd.Flags().AddFlagSet(dockerFlags)
	createQemuCmd.Flags().AddFlagSet(commonFlags)
	createQemuCmd.Flags().AddFlagSet(qemuFlags)

	createCmd.AddCommand(createDockerCmd)
	createCmd.AddCommand(createQemuCmd)

	cluster.Cmd.AddCommand(createCmd)
}

// validateCmdProvisioner checks if the passed provisioner matches the command provisioner
func validateCmdProvisioner(passedProvisioner, cmdProvisioner string) error {
	if passedProvisioner == "" {
		return nil
	}
	if err := providers.IsValidProvider(passedProvisioner); err != nil {
		return err
	}

	if cmdProvisioner != passedProvisioner {
		return fmt.Errorf("Invalid provisioner: \"%s\"\n--provisioner must be %s when using cluster create %s\n", passedProvisioner, cmdProvisioner, cmdProvisioner)
	}
	return nil
}

type agentFlag uint8

func (a *agentFlag) String() string {
	switch *a {
	case 1:
		return "wireguard"
	case 2:
		return "grpc-tunnel"
	case 3:
		return "wireguard+tls"
	case 4:
		return "grpc-tunnel+tls"
	default:
		return "none"
	}
}

func (a *agentFlag) Set(s string) error {
	switch s {
	case "true", "wireguard":
		*a = 1
	case "tunnel":
		*a = 2
	case "wireguard+tls":
		*a = 3
	case "grpc-tunnel+tls":
		*a = 4
	default:
		return fmt.Errorf("unknown type: %s, possible values: 'true', 'wireguard' for the usual WG; 'tunnel' for WG over GRPC, add '+tls' to enable TLS for API", s)
	}

	return nil
}

func (a *agentFlag) Type() string    { return "agent" }
func (a *agentFlag) IsEnabled() bool { return *a != 0 }
func (a *agentFlag) IsTunnel() bool  { return *a == 2 || *a == 4 }
func (a *agentFlag) IsTLS() bool     { return *a == 3 || *a == 4 }

func validateFlags(flags *pflag.FlagSet, unImplementedFlags []string, currentOs string) error {
	invalidFound := false
	errMsg := ""
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed && slices.Contains(unImplementedFlags, f.Name) {
			errMsg += fmt.Sprintf("%s flag is not supported on %s\n", f.Name, currentOs)
			invalidFound = true
		}
	})
	if invalidFound {
		errMsg += "error: unsupported flags found"
		return errors.New(errMsg)
	}
	return nil
}
