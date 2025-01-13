// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package create

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/siderolabs/gen/xslices"
	clustercmd "github.com/siderolabs/talos/cmd/talosctl/cmd/mgmt/cluster"
	clusterpkg "github.com/siderolabs/talos/pkg/cluster"
	"github.com/siderolabs/talos/pkg/machinery/config"
	"github.com/siderolabs/talos/pkg/machinery/config/bundle"
	"github.com/siderolabs/talos/pkg/machinery/config/machine"
	"github.com/siderolabs/talos/pkg/provision"
	"github.com/siderolabs/talos/pkg/provision/access"
	"github.com/siderolabs/talos/pkg/provision/providers/docker"
)

func CreateDockerCluster(ctx context.Context, cOps CommonOps, dOps DockerOps) error {
	clusterReqBase, provisionOptions, _, err := getBase(cOps)
	networkRequestBase := clusterReqBase.Network

	ips, err := getIps(networkRequestBase.CIDRs, cOps)
	if err != nil {
		return fmt.Errorf("failed to get ips: %w", err)
	}

	provisionOptions = append(provisionOptions, provision.WithDockerPortsHostIP(dOps.dockerHostIP))

	portList := []string{}
	if dOps.ports != "" {
		portList = strings.Split(dOps.ports, ",")
		provisionOptions = append(provisionOptions, provision.WithDockerPorts(portList))
	}

	if cOps.talosVersion == "" {
		parts := strings.Split(dOps.nodeImage, ":")

		cOps.talosVersion = parts[len(parts)-1]
	}

	var configBundleOpts []bundle.Option

	provisioner, err := docker.NewDockerProvisioner(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := provisioner.Close(); err != nil {
			fmt.Printf("failed to close docker provisioner: %v", err)
		}
	}()

	request := docker.ClusterRequest{
		ClusterRequestBase: clusterReqBase,
		Image:              dOps.nodeImage,
		Network: docker.NetworkRequest{
			NetworkRequestBase: networkRequestBase,
			DockerDisableIPv6:  dOps.dockerDisableIPv6,
		},
		Nodes: docker.NodeRequests{},
	}

	if cOps.inputDir != "" {
		configBundleOpts = append(configBundleOpts, bundle.WithExistingConfigs(cOps.inputDir))
	} else {
		genOptions, _, err := getCommonGenOptions(cOps)
		if err != nil {
			return err
		}
		genOptions = append(genOptions, provisioner.GenOptions(networkRequestBase)...)
		externalKubernetesEndpoint := provisioner.GetExternalKubernetesControlPlaneEndpoint(networkRequestBase)
		provisionOptions = append(provisionOptions, provision.WithKubernetesEndpoint(externalKubernetesEndpoint))
		endpointList := provisioner.GetTalosAPIEndpoints(networkRequestBase)
		genOptions = append(genOptions, getEnpointListGenOption(cOps, endpointList, ips)...)
		inClusterEndpoint := provisioner.GetInClusterKubernetesControlPlaneEndpoint(networkRequestBase, cOps.controlPlanePort)
		configBundleOpts = getNewConfigBundle(configBundleOpts, cOps, inClusterEndpoint, genOptions)
	}
	commonConfigBundleOps, err := getCommonConfigBundleOps(cOps, networkRequestBase.GatewayAddrs[0].String())
	if err != nil {
		return err
	}
	configBundleOpts = append(configBundleOpts, commonConfigBundleOps...)
	configBundle, bundleTalosconfig, err := getConfigBundle(cOps, configBundleOpts)
	if err != nil {
		return err
	}
	// Add talosconfig to provision options, so we'll have it to parse there
	provisionOptions = append(provisionOptions, provision.WithTalosConfig(configBundle.TalosConfig()))

	baseNodes := append(clusterReqBase.Controlplanes, clusterReqBase.Workers...)
	for _, n := range baseNodes {
		var cfg config.Provider

		nodeIPs := getNodeIp(networkRequestBase.CIDRs, ips, n.Index)

		node := docker.NodeRequest{
			NodeRequestBase: n,
			Mounts:          dOps.mountOpts.Value(),
			IPs:             nodeIPs,
			Ports:           portList,
		}

		if cOps.withInitNode && n.Index == 0 {
			cfg = configBundle.Init()
			node.Type = machine.TypeInit
		} else if node.Type == machine.TypeControlPlane {
			cfg = configBundle.ControlPlane()
		} else if node.Type == machine.TypeWorker {
			cfg = configBundle.Worker()
		}
		node.Config = cfg
		request.Nodes = append(request.Nodes, node)
	}

	cluster, err := provisioner.Create(ctx, request, provisionOptions...)
	if err != nil {
		return err
	}

	// No talosconfig in the bundle - skip the operations below
	if bundleTalosconfig == nil {
		return nil
	}
	clusterAccess := access.NewAdapter(cluster, provisionOptions...)

	// Create and save the talosctl configuration file.
	if err = saveConfig(bundleTalosconfig, cOps); err != nil {
		return err
	}

	if cOps.applyConfigEnabled {
		nodeApplyCfgs := xslices.Map(request.Nodes, func(n docker.NodeRequest) clusterpkg.NodeApplyConfig {
			return clusterpkg.NodeApplyConfig{NodeAddress: clusterpkg.NodeAddress{IP: n.IPs[0]}, Config: n.Config}
		})
		err = clusterAccess.ApplyConfig(ctx, nodeApplyCfgs, nil, os.Stdout)
		if err != nil {
			return err
		}
	}

	defer clusterAccess.Close() //nolint:errcheck
	if err = postCreate(ctx, clusterAccess, cOps); err != nil {
		if cOps.crashdumpOnFailure {
			provisioner.CrashDump(ctx, cluster, os.Stderr)
		}

		return err
	}

	return clustercmd.ShowCluster(cluster)
}

func init() {
}
