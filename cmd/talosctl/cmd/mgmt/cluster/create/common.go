// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/siderolabs/go-kubeconfig"
	sideronet "github.com/siderolabs/net"
	"github.com/siderolabs/talos/pkg/cluster/check"
	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	"github.com/siderolabs/talos/pkg/machinery/config"
	"github.com/siderolabs/talos/pkg/machinery/config/bundle"
	"github.com/siderolabs/talos/pkg/machinery/config/configpatcher"
	"github.com/siderolabs/talos/pkg/machinery/config/container"
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
	"github.com/siderolabs/talos/pkg/machinery/config/generate"
	"github.com/siderolabs/talos/pkg/machinery/config/machine"
	"github.com/siderolabs/talos/pkg/machinery/config/types/v1alpha1"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/nethelpers"
	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/access"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// gatewayOffset is the offset from the network address of the IP address of the network gateway.
	gatewayOffset = 1

	// nodesOffset is the offset from the network address of the beginning of the IP addresses to be used for nodes.
	nodesOffset  = 2
	jsonLogsPort = 4003
)

// getNetworkRequestBase validates network related ops and creates a base network request
func getNetworkRequestBase(cOps CommonOps) (req provision.NetworkRequestBase, cidr4 netip.Prefix, err error) {
	cidr4, err = netip.ParsePrefix(cOps.networkCIDR)
	if err != nil {
		return req, cidr4, fmt.Errorf("error validating cidr block: %w", err)
	}

	if !cidr4.Addr().Is4() {
		return req, cidr4, errors.New("--cidr is expected to be IPV4 CIDR")
	}
	var cidrs []netip.Prefix
	if cOps.networkIPv4 {
		cidrs = append(cidrs, cidr4)
	}

	// Gateway addr at 1st IP in range, ex. 192.168.0.1
	gatewayIPs := make([]netip.Addr, len(cidrs))

	for j := range gatewayIPs {
		gatewayIPs[j], err = sideronet.NthIPInNetwork(cidrs[j], gatewayOffset)
		if err != nil {
			return req, cidr4, err
		}
	}

	return provision.NetworkRequestBase{
		Name:         cOps.rootOps.ClusterName,
		CIDRs:        cidrs,
		GatewayAddrs: gatewayIPs,
		MTU:          cOps.networkMTU,
	}, cidr4, nil
}

func getBaseNodeRequests(params CommonOps) (controls, workers provision.BaseNodeRequests, err error) {
	if params.controlplanes < 1 {
		return controls, workers, errors.New("number of controlplanes can't be less than 1")
	}

	controlPlaneNanoCPUs, err := parseCPUShare(params.controlPlaneCpus)
	if err != nil {
		return controls, workers, fmt.Errorf("error parsing --cpus: %s", err)
	}

	workerNanoCPUs, err := parseCPUShare(params.workersCpus)
	if err != nil {
		return controls, workers, fmt.Errorf("error parsing --cpus-workers: %s", err)
	}

	controlPlaneMemory := int64(params.controlPlaneMemory) * 1024 * 1024
	workerMemory := int64(params.workersMemory) * 1024 * 1024

	for i := range params.controlplanes {
		controls = append(controls, provision.NodeRequestBase{
			Index:               i,
			Name:                fmt.Sprintf("%s-%s-%d", params.rootOps.ClusterName, "controlplane", i+1),
			Type:                machine.TypeControlPlane,
			Memory:              controlPlaneMemory,
			NanoCPUs:            controlPlaneNanoCPUs,
			SkipInjectingConfig: params.skipInjectingConfig,
		})
	}
	for i := range params.workers {
		controls = append(controls, provision.NodeRequestBase{
			Index:               params.controlplanes - 1 + i,
			Name:                fmt.Sprintf("%s-%s-%d", params.rootOps.ClusterName, "worker", i+1),
			Type:                machine.TypeWorker,
			Memory:              workerMemory,
			NanoCPUs:            workerNanoCPUs,
			SkipInjectingConfig: params.skipInjectingConfig,
		})
	}

	return controls, workers, nil
}

func getBase(cOps CommonOps) (baseRequest provision.ClusterRequestBase, provisionOptions []provision.Option, cidr4 netip.Prefix, err error) {
	networkRequestBase, _, err := getNetworkRequestBase(cOps)
	if err != nil {
		return
	}
	controlplanes, workers, err := getBaseNodeRequests(cOps)
	if err != nil {
		return
	}
	baseRequest = provision.ClusterRequestBase{
		Name:           cOps.rootOps.ClusterName,
		SelfExecutable: os.Args[0],
		StateDirectory: cOps.rootOps.StateDir,
		Workers:        workers,
		Controlplanes:  controlplanes,
		Network:        networkRequestBase,
	}
	provisionOptions = getCommonProvisionOps(cOps, networkRequestBase.GatewayAddrs[0].String())
	return
}

func postCreate(ctx context.Context, clusterAccess *access.Adapter, commonOps CommonOps) error {
	if !commonOps.withInitNode {
		if err := clusterAccess.Bootstrap(ctx, os.Stdout); err != nil {
			return fmt.Errorf("bootstrap error: %w", err)
		}
	}

	if !commonOps.clusterWait {
		return nil
	}

	// Run cluster readiness checks
	checkCtx, checkCtxCancel := context.WithTimeout(ctx, commonOps.clusterWaitTimeout)
	defer checkCtxCancel()

	checks := check.DefaultClusterChecks()

	if commonOps.skipK8sNodeReadinessCheck {
		checks = slices.Concat(check.PreBootSequenceChecks(), check.K8sComponentsReadinessChecks())
	}

	checks = append(checks, check.ExtraClusterChecks()...)

	if err := check.Wait(checkCtx, clusterAccess, checks, check.StderrReporter()); err != nil {
		return err
	}

	if !commonOps.skipKubeconfig {
		if err := mergeKubeconfig(ctx, clusterAccess); err != nil {
			return err
		}
	}

	return nil
}

func saveConfig(talosConfigObj *clientconfig.Config, commonOps CommonOps) (err error) {
	c, err := clientconfig.Open(commonOps.talosconfig)
	if err != nil {
		return fmt.Errorf("error opening talos config: %w", err)
	}

	renames := c.Merge(talosConfigObj)
	for _, rename := range renames {
		fmt.Fprintf(os.Stderr, "renamed talosconfig context %s\n", rename.String())
	}

	return c.Save(commonOps.talosconfig)
}

func mergeKubeconfig(ctx context.Context, clusterAccess *access.Adapter) error {
	// TODO: the change below in different commit
	kubeconfigPath, err := kubeconfig.DefaultPath()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nmerging kubeconfig into %q\n", kubeconfigPath)

	k8sconfig, err := clusterAccess.Kubeconfig(ctx)
	if err != nil {
		return fmt.Errorf("error fetching kubeconfig: %w", err)
	}

	kubeConfig, err := clientcmd.Load(k8sconfig)
	if err != nil {
		return fmt.Errorf("error parsing kubeconfig: %w", err)
	}

	if clusterAccess.ForceEndpoint != "" {
		for name := range kubeConfig.Clusters {
			kubeConfig.Clusters[name].Server = clusterAccess.ForceEndpoint
		}
	}

	_, err = os.Stat(kubeconfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		return clientcmd.WriteToFile(*kubeConfig, kubeconfigPath)
	}

	merger, err := kubeconfig.Load(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("error loading existing kubeconfig: %w", err)
	}

	err = merger.Merge(kubeConfig, kubeconfig.MergeOptions{
		ActivateContext: true,
		OutputWriter:    os.Stdout,
		ConflictHandler: func(component kubeconfig.ConfigComponent, name string) (kubeconfig.ConflictDecision, error) {
			return kubeconfig.RenameDecision, nil
		},
	})
	if err != nil {
		return fmt.Errorf("error merging kubeconfig: %w", err)
	}

	return merger.Write(kubeconfigPath)
}

func parseCPUShare(cpus string) (int64, error) {
	cpu, ok := new(big.Rat).SetString(cpus)
	if !ok {
		return 0, fmt.Errorf("failed to parsing as a rational number: %s", cpus)
	}

	nano := cpu.Mul(cpu, big.NewRat(1e9, 1))
	if !nano.IsInt() {
		return 0, errors.New("value is too precise")
	}

	return nano.Num().Int64(), nil
}

// getIps calculates ips for nodes and the virtual ip
// preallocIps is false ips are nil and should not be preallocated
func getIps(cidrs []netip.Prefix, commonOps CommonOps) (ips [][]netip.Addr, err error) {
	// Set starting ip at 2nd ip in range, ex: 192.168.0.2
	ips = make([][]netip.Addr, len(cidrs))

	for j := range cidrs {
		ips[j] = make([]netip.Addr, commonOps.controlplanes+commonOps.workers)

		for i := range ips[j] {
			ips[j][i], err = sideronet.NthIPInNetwork(cidrs[j], nodesOffset+i)
			if err != nil {
				return ips, err
			}
		}
	}

	return ips, err
}

func getCommonGenOptions(cOps CommonOps) ([]generate.Option, *config.VersionContract, error) {
	genOptions := []generate.Option{
		generate.WithDebug(cOps.configDebug),
		generate.WithDNSDomain(cOps.dnsDomain),
		generate.WithClusterDiscovery(cOps.enableClusterDiscovery),
	}

	for _, registryMirror := range cOps.registryMirrors {
		components := strings.SplitN(registryMirror, "=", 2)
		if len(components) != 2 {
			return genOptions, nil, fmt.Errorf("invalid registry mirror spec: %q", registryMirror)
		}

		genOptions = append(genOptions, generate.WithRegistryMirror(components[0], components[1]))
	}

	for _, registryHost := range cOps.registryInsecure {
		genOptions = append(genOptions, generate.WithRegistryInsecureSkipVerify(registryHost))
	}

	if cOps.customCNIUrl != "" {
		genOptions = append(genOptions, generate.WithClusterCNIConfig(&v1alpha1.CNIConfig{
			CNIName: constants.CustomCNI,
			CNIUrls: []string{cOps.customCNIUrl},
		}))
	}

	var versionContract *config.VersionContract
	if cOps.talosVersion != "latest" {
		versionContract, err := config.ParseContractFromVersion(cOps.talosVersion)
		if err != nil {
			return genOptions, nil, fmt.Errorf("error parsing Talos version %q: %w", cOps.talosVersion, err)
		}

		genOptions = append(genOptions, generate.WithVersionContract(versionContract))
	}

	if cOps.kubePrismPort != constants.DefaultKubePrismPort {
		genOptions = append(genOptions,
			generate.WithKubePrismPort(cOps.kubePrismPort),
		)
	}

	if cOps.controlPlanePort != constants.DefaultControlPlanePort {
		genOptions = append(genOptions,
			generate.WithLocalAPIServerPort(cOps.controlPlanePort),
		)
	}

	if cOps.enableKubeSpan {
		genOptions = append(genOptions,
			generate.WithNetworkOptions(
				v1alpha1.WithKubeSpan(),
			),
		)
	}

	return genOptions, versionContract, nil
}

func getEnpointListGenOption(cOps CommonOps, endpointList []string, ips [][]netip.Addr) []generate.Option {
	genOptions := []generate.Option{}
	switch {
	case cOps.forceEndpoint != "":
		// using non-default endpoints, provision additional cert SANs and fix endpoint list
		endpointList = []string{cOps.forceEndpoint}
		genOptions = append(genOptions, generate.WithAdditionalSubjectAltNames(endpointList))
	case cOps.forceInitNodeAsEndpoint:
		endpointList = []string{ips[0][0].String()}
	case len(endpointList) > 0:
		for _, endpointHostPort := range endpointList {
			endpointHost, _, err := net.SplitHostPort(endpointHostPort)
			if err != nil {
				endpointHost = endpointHostPort
			}

			genOptions = append(genOptions, generate.WithAdditionalSubjectAltNames([]string{endpointHost}))
		}
	case endpointList == nil:
		// use control plane nodes as endpoints, client-side load-balancing
		for i := range cOps.controlplanes {
			endpointList = append(endpointList, ips[0][i].String())
		}
	}
	return append(genOptions, generate.WithEndpointList(endpointList))
}

func getCommonConfigBundleOps(cOps CommonOps, gatewayIP string) ([]bundle.Option, error) {
	var configBundleOpts []bundle.Option
	addConfigPatch := func(configPatches []string, configOpt func([]configpatcher.Patch) bundle.Option) error {
		var patches []configpatcher.Patch
		patches, err := configpatcher.LoadPatches(configPatches)
		if err != nil {
			return fmt.Errorf("error parsing config JSON patch: %w", err)
		}
		configBundleOpts = append(configBundleOpts, configOpt(patches))
		return nil
	}

	if err := addConfigPatch(cOps.configPatch, bundle.WithPatch); err != nil {
		return configBundleOpts, err
	}
	if err := addConfigPatch(cOps.configPatchControlPlane, bundle.WithPatchControlPlane); err != nil {
		return configBundleOpts, err
	}
	if err := addConfigPatch(cOps.configPatchWorker, bundle.WithPatchWorker); err != nil {
		return configBundleOpts, err
	}

	if cOps.withJSONLogs {
		cfg := container.NewV1Alpha1(
			&v1alpha1.Config{
				ConfigVersion: "v1alpha1",
				MachineConfig: &v1alpha1.MachineConfig{
					MachineLogging: &v1alpha1.LoggingConfig{
						LoggingDestinations: []v1alpha1.LoggingDestination{
							{
								LoggingEndpoint: &v1alpha1.Endpoint{
									URL: &url.URL{
										Scheme: "tcp",
										Host:   nethelpers.JoinHostPort(gatewayIP, jsonLogsPort),
									},
								},
								LoggingFormat: "json_lines",
							},
						},
					},
				},
			})
		configBundleOpts = append(configBundleOpts, bundle.WithPatch([]configpatcher.Patch{configpatcher.NewStrategicMergePatch(cfg)}))
	}

	return configBundleOpts, nil
}

func getNewConfigBundle(configBundleOpts []bundle.Option, cOps CommonOps, inClusterEndpoint string, genOptions []generate.Option) []bundle.Option {
	configBundleOpts = append(configBundleOpts,
		bundle.WithInputOptions(
			&bundle.InputOptions{
				ClusterName: cOps.rootOps.ClusterName,
				Endpoint:    inClusterEndpoint,
				KubeVersion: strings.TrimPrefix(cOps.kubernetesVersion, "v"),
				GenOptions:  genOptions,
			}),
	)
	return configBundleOpts
}

func getCommonProvisionOps(cOps CommonOps, gatewayIP string) []provision.Option {
	provisionOptions := []provision.Option{}
	if cOps.withJSONLogs {
		provisionOptions = append(provisionOptions, provision.WithJSONLogs(nethelpers.JoinHostPort(gatewayIP, jsonLogsPort)))
	}
	return provisionOptions
}

func getConfigBundle(cOps CommonOps, configBundleOpts []bundle.Option) (configBundle *bundle.Bundle, bundleTalosconfig *clientconfig.Config, err error) {
	configBundle, err = bundle.NewBundle(configBundleOpts...)
	if err != nil {
		return nil, nil, err
	}

	bundleTalosconfig = configBundle.TalosConfig()
	if bundleTalosconfig == nil {
		if cOps.clusterWait {
			return nil, nil, errors.New("no talosconfig in the config bundle: cannot wait for cluster")
		}

		if cOps.applyConfigEnabled {
			return nil, nil, errors.New("no talosconfig in the config bundle: cannot apply config")
		}
	}

	if cOps.skipInjectingConfig {
		types := []machine.Type{machine.TypeControlPlane, machine.TypeWorker}

		if cOps.withInitNode {
			types = slices.Insert(types, 0, machine.TypeInit)
		}

		if err = configBundle.Write(".", encoder.CommentsAll, types...); err != nil {
			return nil, nil, err
		}
	}

	return
}

func getNodeIp(CIDRs []netip.Prefix, ips [][]netip.Addr, nodeIndex int) []netip.Addr {
	nodeIPs := make([]netip.Addr, len(CIDRs))
	for j := range nodeIPs {
		nodeIPs[j] = ips[j][nodeIndex]
	}
	return nodeIPs
}
