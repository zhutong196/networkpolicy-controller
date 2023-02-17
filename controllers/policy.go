package controllers

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"strconv"
	"strings"
	"time"
)

type numericPort2eps map[string]*endPoints
type protocol2eps map[string]numericPort2eps
type namedPort2eps map[string]protocol2eps

func (ntpc *NetworkPolicyController) newNetworkPolicyEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ntpc.OnNetworkPolicyUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ntpc.OnNetworkPolicyUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			ntpc.handleNetworkPolicyDelete(obj)

		},
	}
}

func (ntpc *NetworkPolicyController) OnNetworkPolicyUpdate(obj interface{}) {
	netpol := obj.(*networking.NetworkPolicy)
	klog.V(2).Infof("Received update for network policy: %s/%s", netpol.Namespace, netpol.Name)

	ntpc.RequestFullSync()
}

func (ntpc *NetworkPolicyController) handleNetworkPolicyDelete(obj interface{}) {
	netpol, ok := obj.(*networking.NetworkPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if netpol, ok = tombstone.Obj.(*networking.NetworkPolicy); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	klog.V(2).Infof("Received network policy: %s/%s delete event", netpol.Namespace, netpol.Name)

	ntpc.RequestFullSync()
}

func (ntpc *NetworkPolicyController) buildNetworkPoliciesInfo() ([]networkPolicyInfo, error) {

	NetworkPolicies := make([]networkPolicyInfo, 0)

	for _, policyObj := range ntpc.npLister.List() {

		policy, ok := policyObj.(*networking.NetworkPolicy)
		podSelector, _ := v1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if !ok {
			return nil, fmt.Errorf("failed to convert")
		}
		newPolicy := networkPolicyInfo{
			name:        policy.Name,
			namespace:   policy.Namespace,
			podSelector: podSelector,
			policyType:  kubeIngressPolicyType,
		}

		ingressType, egressType := false, false
		for _, policyType := range policy.Spec.PolicyTypes {
			if policyType == networking.PolicyTypeIngress {
				ingressType = true
			}
			if policyType == networking.PolicyTypeEgress {
				egressType = true
			}
		}
		switch {
		case ingressType && egressType:
			newPolicy.policyType = kubeBothPolicyType
		case egressType:
			newPolicy.policyType = kubeEgressPolicyType
		case ingressType:
			newPolicy.policyType = kubeIngressPolicyType
		}

		matchingPods, err := ntpc.ListPodsByNamespaceAndLabels(policy.Namespace, podSelector)
		newPolicy.targetPods = make(map[string]podInfo)
		namedPort2IngressEps := make(namedPort2eps)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if !isOpenNetworkPolicy(matchingPod) {
					continue
				}
				newPolicy.targetPods[matchingPod.Status.PodIP] = podInfo{ip: matchingPod.Status.PodIP,
					name:      matchingPod.ObjectMeta.Name,
					namespace: matchingPod.ObjectMeta.Namespace,
					labels:    matchingPod.ObjectMeta.Labels}
				ntpc.grabNamedPortFromPod(matchingPod, &namedPort2IngressEps)
			}
		}

		if policy.Spec.Ingress == nil {
			newPolicy.ingressRules = nil
		} else {
			newPolicy.ingressRules = make([]ingressRule, 0)
		}

		if policy.Spec.Egress == nil {
			newPolicy.egressRules = nil
		} else {
			newPolicy.egressRules = make([]egressRule, 0)
		}

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := ingressRule{}
			ingressRule.srcPods = make([]podInfo, 0)
			ingressRule.srcIPBlocks = make([][]string, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specIngressRule.From) == 0 {
				ingressRule.matchAllSource = true
			} else {
				ingressRule.matchAllSource = false
				for _, peer := range specIngressRule.From {
					if peerPods, err := ntpc.evalPodPeer(policy, peer); err == nil {
						for _, peerPod := range peerPods {
							if !isOpenNetworkPolicy(peerPod) {
								continue
							}
							ingressRule.srcPods = append(ingressRule.srcPods,
								podInfo{ip: peerPod.Status.PodIP,
									name:      peerPod.ObjectMeta.Name,
									namespace: peerPod.ObjectMeta.Namespace,
									labels:    peerPod.ObjectMeta.Labels})
						}
					}
					ingressRule.srcIPBlocks = append(ingressRule.srcIPBlocks, ntpc.evalIPBlockPeer(peer)...)
				}
			}

			ingressRule.ports = make([]protocolAndPort, 0)
			ingressRule.namedPorts = make([]endPoints, 0)
			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specIngressRule.Ports) == 0 {
				ingressRule.matchAllPorts = true
			} else {
				ingressRule.matchAllPorts = false
				ingressRule.ports, ingressRule.namedPorts = ntpc.processNetworkPolicyPorts(
					specIngressRule.Ports, namedPort2IngressEps)
			}

			newPolicy.ingressRules = append(newPolicy.ingressRules, ingressRule)
		}

		for _, specEgressRule := range policy.Spec.Egress {
			egressRule := egressRule{}
			egressRule.dstPods = make([]podInfo, 0)
			egressRule.dstIPBlocks = make([][]string, 0)
			namedPort2EgressEps := make(namedPort2eps)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specEgressRule.To) == 0 {
				egressRule.matchAllDestinations = true
				// if rule.To is empty but rule.Ports not, we must try to grab NamedPort from pods that in same
				// namespace, so that we can design iptables rule to describe "match all dst but match some named
				// dst-port" egress rule
				if policyRulePortsHasNamedPort(specEgressRule.Ports) {
					matchingPeerPods, _ := ntpc.ListPodsByNamespaceAndLabels(policy.Namespace, labels.Everything())
					for _, peerPod := range matchingPeerPods {
						if !isOpenNetworkPolicy(peerPod) {
							continue
						}
						ntpc.grabNamedPortFromPod(peerPod, &namedPort2EgressEps)
					}
				}
			} else {
				egressRule.matchAllDestinations = false
				for _, peer := range specEgressRule.To {
					if peerPods, err := ntpc.evalPodPeer(policy, peer); err == nil {
						for _, peerPod := range peerPods {
							if !isOpenNetworkPolicy(peerPod) {
								continue
							}
							egressRule.dstPods = append(egressRule.dstPods,
								podInfo{ip: peerPod.Status.PodIP,
									name:      peerPod.ObjectMeta.Name,
									namespace: peerPod.ObjectMeta.Namespace,
									labels:    peerPod.ObjectMeta.Labels})
							ntpc.grabNamedPortFromPod(peerPod, &namedPort2EgressEps)
						}

					}
					egressRule.dstIPBlocks = append(egressRule.dstIPBlocks, ntpc.evalIPBlockPeer(peer)...)
				}
			}

			egressRule.ports = make([]protocolAndPort, 0)
			egressRule.namedPorts = make([]endPoints, 0)
			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specEgressRule.Ports) == 0 {
				egressRule.matchAllPorts = true
			} else {
				egressRule.matchAllPorts = false
				egressRule.ports, egressRule.namedPorts = ntpc.processNetworkPolicyPorts(
					specEgressRule.Ports, namedPort2EgressEps)
			}

			newPolicy.egressRules = append(newPolicy.egressRules, egressRule)
		}
		NetworkPolicies = append(NetworkPolicies, newPolicy)
	}

	return NetworkPolicies, nil
}

func (ntpc *NetworkPolicyController) evalIPBlockPeer(peer networking.NetworkPolicyPeer) [][]string {
	ipBlock := make([][]string, 0)
	if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.IPBlock != nil {
		if cidr := peer.IPBlock.CIDR; strings.HasSuffix(cidr, "/0") {
			ipBlock = append(ipBlock, []string{"0.0.0.0/1", utils.OptionTimeout, "0"},
				[]string{"128.0.0.0/1", utils.OptionTimeout, "0"})
		} else {
			ipBlock = append(ipBlock, []string{cidr, utils.OptionTimeout, "0"})
		}
		for _, except := range peer.IPBlock.Except {
			if strings.HasSuffix(except, "/0") {
				ipBlock = append(ipBlock, []string{"0.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch},
					[]string{"128.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch})
			} else {
				ipBlock = append(ipBlock, []string{except, utils.OptionTimeout, "0", utils.OptionNoMatch})
			}
		}
	}
	return ipBlock
}

// Configure iptables rules representing each network policy. All pod's matched by
// network policy spec podselector labels are grouped together in one ipset which
// is used for matching destination ip address. Each ingress rule in the network
// policyspec is evaluated to set of matching pods, which are grouped in to a
// ipset used for source ip addr matching.
func (npc *NetworkPolicyController) syncNetworkPolicyChains(networkPoliciesInfo []networkPolicyInfo,
	version string) (map[string]bool, map[string]bool, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		//metrics.ControllerPolicyChainsSyncTime.Observe(endTime.Seconds())
		klog.V(2).Infof("Syncing network policy chains took %v", endTime)
	}()

	klog.V(1).Infof("Attempting to attain ipset mutex lock")
	npc.ipsetMutex.Lock()
	klog.V(1).Infof("Attained ipset mutex lock, continuing...")
	defer func() {
		npc.ipsetMutex.Unlock()
		klog.V(1).Infof("Returned ipset mutex lock")
	}()

	ipset, err := utils.NewIPSet(false)
	if err != nil {
		return nil, nil, err
	}
	err = ipset.Save()
	if err != nil {
		return nil, nil, err
	}
	npc.ipSetHandler = ipset

	activePolicyChains := make(map[string]bool)
	activePolicyIPSets := make(map[string]bool)

	// run through all network policies
	for _, policy := range networkPoliciesInfo {

		// ensure there is a unique chain per network policy in filter table
		policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)
		npc.filterTableRules.WriteString(":" + policyChainName + "\n")

		activePolicyChains[policyChainName] = true

		currentPodIPs := make([]string, 0, len(policy.targetPods))
		for ip := range policy.targetPods {
			currentPodIPs = append(currentPodIPs, ip)
		}

		if policy.policyType == kubeBothPolicyType || policy.policyType == kubeIngressPolicyType {
			// create a ipset for all destination pod ip's matched by the policy spec PodSelector
			targetDestPodIPSetName := policyDestinationPodIPSetName(policy.namespace, policy.name)
			npc.createGenericHashIPSet(targetDestPodIPSetName, utils.TypeHashIP, currentPodIPs)
			err = npc.processIngressRules(policy, targetDestPodIPSetName, activePolicyIPSets, version)
			if err != nil {
				return nil, nil, err
			}
			activePolicyIPSets[targetDestPodIPSetName] = true
		}
		if policy.policyType == kubeBothPolicyType || policy.policyType == kubeEgressPolicyType {
			// create a ipset for all source pod ip's matched by the policy spec PodSelector
			targetSourcePodIPSetName := policySourcePodIPSetName(policy.namespace, policy.name)
			npc.createGenericHashIPSet(targetSourcePodIPSetName, utils.TypeHashIP, currentPodIPs)
			err = npc.processEgressRules(policy, targetSourcePodIPSetName, activePolicyIPSets, version)
			if err != nil {
				return nil, nil, err
			}
			activePolicyIPSets[targetSourcePodIPSetName] = true
		}
	}

	err = npc.ipSetHandler.Restore()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform ipset restore: %s", err.Error())
	}

	klog.V(2).Infof("Iptables chains in the filter table are synchronized with the network policies.")

	return activePolicyChains, activePolicyIPSets, nil
}

//nolint:dupl // This is as simple as this function gets even though it repeats some of ProcessIngressRules
func (npc *NetworkPolicyController) processEgressRules(policy networkPolicyInfo,
	targetSourcePodIPSetName string, activePolicyIPSets map[string]bool, version string) error {

	// From network policy spec: "If field 'Ingress' is empty then this NetworkPolicy does not allow any traffic "
	// so no whitelist rules to be added to the network policy
	if policy.egressRules == nil {
		return nil
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)

	// run through all the egress rules in the spec and create iptables rules
	// in the chain for the network policy
	for ruleIdx, egressRule := range policy.egressRules {

		if len(egressRule.dstPods) != 0 {
			dstPodIPSetName := policyIndexedDestinationPodIPSetName(policy.namespace, policy.name, ruleIdx)

			// Create policy based ipset with destination pod IPs
			npc.createPolicyIndexedIPSet(activePolicyIPSets, dstPodIPSetName, utils.TypeHashIP,
				getIPsFromPods(egressRule.dstPods))

			// If the egress policy contains port declarations, we need to make sure that we match on pod IP and port
			if len(egressRule.ports) != 0 {
				if err := npc.createPodWithPortPolicyRule(egressRule.ports, policy, policyChainName,
					targetSourcePodIPSetName, dstPodIPSetName); err != nil {
					return err
				}
			}

			// If the egress policy contains named port declarations, we need to make sure that we match on pod IP and
			// the resolved port number
			if len(egressRule.namedPorts) != 0 {
				for portIdx, eps := range egressRule.namedPorts {
					namedPortIPSetName := policyIndexedEgressNamedPortIPSetName(policy.namespace, policy.name, ruleIdx,
						portIdx)
					npc.createPolicyIndexedIPSet(activePolicyIPSets, namedPortIPSetName, utils.TypeHashIP, eps.ips)

					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
						namedPortIPSetName, eps.protocol, eps.port, eps.endport); err != nil {
						return err
					}
				}
			}

			// If the egress policy contains no ports at all create the policy based only on IP
			if len(egressRule.ports) == 0 && len(egressRule.namedPorts) == 0 {
				// case where no 'ports' details specified in the ingress rule but 'from' details specified
				// so match on specified source and destination ip with all port and protocol
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
					dstPodIPSetName, "", "", ""); err != nil {
					return err
				}
			}
		}

		// case where only 'ports' details specified but no 'to' details in the egress rule so match on all sources,
		// with specified port (if any) and protocol
		if egressRule.matchAllDestinations && !egressRule.matchAllPorts {
			for _, portProtocol := range egressRule.ports {
				comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
					"", portProtocol.protocol, portProtocol.port, portProtocol.endport); err != nil {
					return err
				}
			}
			for _, portProtocol := range egressRule.namedPorts {
				comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
					"", portProtocol.protocol, portProtocol.port, portProtocol.endport); err != nil {
					return err
				}
			}
		}

		// case where neither ports nor from details are specified in the egress rule so match on all ports, protocol,
		// source IP's
		if egressRule.matchAllDestinations && egressRule.matchAllPorts {
			comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
				policy.name + " namespace " + policy.namespace
			if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
				"", "", "", ""); err != nil {
				return err
			}
		}

		if len(egressRule.dstIPBlocks) != 0 {
			dstIPBlockIPSetName := policyIndexedDestinationIPBlockIPSetName(policy.namespace, policy.name, ruleIdx)
			activePolicyIPSets[dstIPBlockIPSetName] = true
			npc.ipSetHandler.RefreshSet(dstIPBlockIPSetName, egressRule.dstIPBlocks, utils.TypeHashNet)
			if !egressRule.matchAllPorts {
				for _, portProtocol := range egressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
						dstIPBlockIPSetName, portProtocol.protocol, portProtocol.port,
						portProtocol.endport); err != nil {
						return err
					}
				}
			}
			if egressRule.matchAllPorts {
				comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(policyChainName, comment, targetSourcePodIPSetName,
					dstIPBlockIPSetName, "", "", ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (npc *NetworkPolicyController) appendRuleToPolicyChain(policyChainName, comment, srcIPSetName, dstIPSetName,
	protocol, dPort, endDport string) error {

	args := make([]string, 0)
	args = append(args, "-A", policyChainName)

	if comment != "" {
		args = append(args, "-m", "comment", "--comment", "\""+comment+"\"")
	}
	if srcIPSetName != "" {
		args = append(args, "-m", "set", "--match-set", srcIPSetName, "src")
	}
	if dstIPSetName != "" {
		args = append(args, "-m", "set", "--match-set", dstIPSetName, "dst")
	}
	if protocol != "" {
		args = append(args, "-p", protocol)
	}
	if dPort != "" {
		if endDport != "" {
			multiport := fmt.Sprintf("%s:%s", dPort, endDport)
			args = append(args, "--dport", multiport)
		} else {
			args = append(args, "--dport", dPort)
		}
	}

	// nolint:gocritic // we want to append to a separate array here so that we can re-use args below
	markArgs := append(args, "-j", "MARK", "--set-xmark", "0x10000/0x10000", "\n")
	npc.filterTableRules.WriteString(strings.Join(markArgs, " "))

	args = append(args, "-m", "mark", "--mark", "0x10000/0x10000", "-j", "RETURN", "\n")
	npc.filterTableRules.WriteString(strings.Join(args, " "))

	return nil
}

func (npc *NetworkPolicyController) processNetworkPolicyPorts(npPorts []networking.NetworkPolicyPort,
	namedPort2eps namedPort2eps) (numericPorts []protocolAndPort, namedPorts []endPoints) {
	numericPorts, namedPorts = make([]protocolAndPort, 0), make([]endPoints, 0)
	for _, npPort := range npPorts {
		var protocol string
		if npPort.Protocol != nil {
			protocol = string(*npPort.Protocol)
		}
		if npPort.Port == nil {
			numericPorts = append(numericPorts, protocolAndPort{port: "", protocol: protocol})
		} else if npPort.Port.Type == intstr.Int {
			var portProto protocolAndPort
			if npPort.EndPort != nil {
				if *npPort.EndPort >= npPort.Port.IntVal {
					portProto.endport = strconv.Itoa(int(*npPort.EndPort))
				}
			}
			portProto.protocol, portProto.port = protocol, npPort.Port.String()
			numericPorts = append(numericPorts, portProto)
		} else if protocol2eps, ok := namedPort2eps[npPort.Port.String()]; ok {
			if numericPort2eps, ok := protocol2eps[protocol]; ok {
				for _, eps := range numericPort2eps {
					namedPorts = append(namedPorts, *eps)
				}
			}
		}
	}
	return
}

func (ntpc *NetworkPolicyController) processIngressRules(policy networkPolicyInfo,
	targetDestPodIPSetName string, activePolicyIPSets map[string]bool, version string) error {

	// From network policy spec: "If field 'Ingress' is empty then this NetworkPolicy does not allow any traffic "
	// so no whitelist rules to be added to the network policy
	if policy.ingressRules == nil {
		return nil
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)

	// run through all the ingress rules in the spec and create iptables rules
	// in the chain for the network policy
	for ruleIdx, ingressRule := range policy.ingressRules {

		if len(ingressRule.srcPods) != 0 {
			srcPodIPSetName := policyIndexedSourcePodIPSetName(policy.namespace, policy.name, ruleIdx)

			// Create policy based ipset with source pod IPs
			ntpc.createPolicyIndexedIPSet(activePolicyIPSets, srcPodIPSetName, utils.TypeHashIP,
				getIPsFromPods(ingressRule.srcPods))

			// If the ingress policy contains port declarations, we need to make sure that we match on pod IP and port
			if len(ingressRule.ports) != 0 {
				if err := ntpc.createPodWithPortPolicyRule(ingressRule.ports, policy, policyChainName,
					srcPodIPSetName, targetDestPodIPSetName); err != nil {
					return err
				}
			}

			// If the ingress policy contains named port declarations, we need to make sure that we match on pod IP and
			// the resolved port number
			if len(ingressRule.namedPorts) != 0 {
				for portIdx, eps := range ingressRule.namedPorts {
					namedPortIPSetName := policyIndexedIngressNamedPortIPSetName(policy.namespace, policy.name, ruleIdx,
						portIdx)
					ntpc.createPolicyIndexedIPSet(activePolicyIPSets, namedPortIPSetName, utils.TypeHashIP, eps.ips)

					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, srcPodIPSetName, namedPortIPSetName,
						eps.protocol, eps.port, eps.endport); err != nil {
						return err
					}
				}
			}

			// If the ingress policy contains no ports at all create the policy based only on IP
			if len(ingressRule.ports) == 0 && len(ingressRule.namedPorts) == 0 {
				// case where no 'ports' details specified in the ingress rule but 'from' details specified
				// so match on specified source and destination ip with all port and protocol
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.name + " namespace " + policy.namespace
				if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, srcPodIPSetName, targetDestPodIPSetName,
					"", "", ""); err != nil {
					return err
				}
			}
		}

		// case where only 'ports' details specified but no 'from' details in the ingress rule so match on all sources,
		// with specified port (if any) and protocol
		if ingressRule.matchAllSource && !ingressRule.matchAllPorts {
			for _, portProtocol := range ingressRule.ports {
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, "", targetDestPodIPSetName,
					portProtocol.protocol, portProtocol.port, portProtocol.endport); err != nil {
					return err
				}
			}

			for portIdx, eps := range ingressRule.namedPorts {
				namedPortIPSetName := policyIndexedIngressNamedPortIPSetName(policy.namespace, policy.name, ruleIdx,
					portIdx)
				ntpc.createPolicyIndexedIPSet(activePolicyIPSets, namedPortIPSetName, utils.TypeHashIP, eps.ips)

				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, "", namedPortIPSetName,
					eps.protocol, eps.port, eps.endport); err != nil {
					return err
				}
			}
		}

		// case where neither ports nor from details are specified in the ingress rule so match on all ports, protocol,
		// source IP's
		if ingressRule.matchAllSource && ingressRule.matchAllPorts {
			comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
				policy.name + " namespace " + policy.namespace
			if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, "", targetDestPodIPSetName,
				"", "", ""); err != nil {
				return err
			}
		}

		if len(ingressRule.srcIPBlocks) != 0 {
			srcIPBlockIPSetName := policyIndexedSourceIPBlockIPSetName(policy.namespace, policy.name, ruleIdx)
			activePolicyIPSets[srcIPBlockIPSetName] = true
			ntpc.ipSetHandler.RefreshSet(srcIPBlockIPSetName, ingressRule.srcIPBlocks, utils.TypeHashNet)

			if !ingressRule.matchAllPorts {
				for _, portProtocol := range ingressRule.ports {
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, srcIPBlockIPSetName,
						targetDestPodIPSetName, portProtocol.protocol, portProtocol.port,
						portProtocol.endport); err != nil {
						return err
					}
				}

				for portIdx, eps := range ingressRule.namedPorts {
					namedPortIPSetName := policyIndexedIngressNamedPortIPSetName(policy.namespace, policy.name, ruleIdx,
						portIdx)
					ntpc.createPolicyIndexedIPSet(activePolicyIPSets, namedPortIPSetName, utils.TypeHashNet, eps.ips)

					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, srcIPBlockIPSetName,
						namedPortIPSetName, eps.protocol, eps.port, eps.endport); err != nil {
						return err
					}
				}
			}
			if ingressRule.matchAllPorts {
				comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := ntpc.appendRuleToPolicyChain(policyChainName, comment, srcIPBlockIPSetName,
					targetDestPodIPSetName, "", "", ""); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func networkPolicyChainName(namespace, policyName string, version string) string {
	hash := sha256.Sum256([]byte(namespace + policyName + version))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeNetworkPolicyChainPrefix + encoded[:16]
}

func policySourcePodIPSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func policyDestinationPodIPSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedSourcePodIPSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func policyIndexedDestinationPodIPSetName(namespace, policyName string, egressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedSourceIPBlockIPSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func policyIndexedDestinationIPBlockIPSetName(namespace, policyName string, egressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedIngressNamedPortIPSetName(namespace, policyName string, ingressRuleNo, namedPortNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		strconv.Itoa(namedPortNo) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedEgressNamedPortIPSetName(namespace, policyName string, egressRuleNo, namedPortNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		strconv.Itoa(namedPortNo) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func (npc *NetworkPolicyController) evalPodPeer(policy *networking.NetworkPolicy,
	peer networking.NetworkPolicyPeer) ([]*api.Pod, error) {

	var matchingPods []*api.Pod
	matchingPods = make([]*api.Pod, 0)
	var err error
	// spec can have both PodSelector AND NamespaceSelector
	if peer.NamespaceSelector != nil {
		namespaceSelector, _ := v1.LabelSelectorAsSelector(peer.NamespaceSelector)
		namespaces, err := npc.ListNamespaceByLabels(namespaceSelector)
		if err != nil {
			return nil, errors.New("Failed to build network policies info due to " + err.Error())
		}

		podSelector := labels.Everything()
		if peer.PodSelector != nil {
			podSelector, _ = v1.LabelSelectorAsSelector(peer.PodSelector)
		}
		for _, namespace := range namespaces {
			namespacePods, err := npc.ListPodsByNamespaceAndLabels(namespace.Name, podSelector)
			if err != nil {
				return nil, errors.New("Failed to build network policies info due to " + err.Error())
			}
			matchingPods = append(matchingPods, namespacePods...)
		}
	} else if peer.PodSelector != nil {
		podSelector, _ := v1.LabelSelectorAsSelector(peer.PodSelector)
		matchingPods, err = npc.ListPodsByNamespaceAndLabels(policy.Namespace, podSelector)
	}

	return matchingPods, err
}

func (ntpc *NetworkPolicyController) grabNamedPortFromPod(pod *api.Pod, namedPort2eps *namedPort2eps) {
	if pod == nil || namedPort2eps == nil {
		return
	}
	for k := range pod.Spec.Containers {
		for _, port := range pod.Spec.Containers[k].Ports {
			name := port.Name
			protocol := string(port.Protocol)
			containerPort := strconv.Itoa(int(port.ContainerPort))

			if (*namedPort2eps)[name] == nil {
				(*namedPort2eps)[name] = make(protocol2eps)
			}
			if (*namedPort2eps)[name][protocol] == nil {
				(*namedPort2eps)[name][protocol] = make(numericPort2eps)
			}
			if eps, ok := (*namedPort2eps)[name][protocol][containerPort]; !ok {
				(*namedPort2eps)[name][protocol][containerPort] = &endPoints{
					ips:             []string{pod.Status.PodIP},
					protocolAndPort: protocolAndPort{port: containerPort, protocol: protocol},
				}
			} else {
				eps.ips = append(eps.ips, pod.Status.PodIP)
			}
		}
	}
}

func policyRulePortsHasNamedPort(npPorts []networking.NetworkPolicyPort) bool {
	for _, npPort := range npPorts {
		if npPort.Port != nil && npPort.Port.Type == intstr.String {
			return true
		}
	}
	return false
}