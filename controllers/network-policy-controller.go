package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	_ "github.com/coreos/go-iptables/iptables"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"net"
	"npController/options"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIPSetPrefix        = "KUBE-SRC-"
	kubeDestinationIPSetPrefix   = "KUBE-DST-"
	kubeInputChainName           = "KUBE-DANDELION-INPUT"
	kubeForwardChainName         = "KUBE-DANDELION-FORWARD"
	kubeOutputChainName          = "KUBE-DANDELION-OUTPUT"
	kubeDefaultNetpolChain       = "KUBE-DANDELION-DEFAULT"

	kubeIngressPolicyType = "ingress"
	kubeEgressPolicyType  = "egress"
	kubeBothPolicyType    = "both"

	syncVersionBase = 10
)

var (
	defaultChains = map[string]string{
		"INPUT":   kubeInputChainName,
		"FORWARD": kubeForwardChainName,
		"OUTPUT":  kubeOutputChainName,
	}
)

type NetworkPolicyController struct {
	nodeIP                  net.IP
	nodeHostName            string
	serviceClusterIPRange   net.IPNet
	serviceExternalIPRanges []net.IPNet
	serviceNodePortRange    string
	mu                      sync.Mutex
	syncPeriod              time.Duration
	MetricsEnabled          bool
	//healthChan              chan<- *healthcheck.ControllerHeartbeat
	fullSyncRequestChan chan struct{}
	ipsetMutex          *sync.Mutex

	ipSetHandler *utils.IPSet

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler

	filterTableRules bytes.Buffer
}

//申明结构体解析 network policy策略
type networkPolicyInfo struct {
	name        string
	namespace   string
	podSelector labels.Selector

	// set of pods matching network policy spec podselector label selector
	targetPods map[string]podInfo

	// whitelist ingress rules from the network policy spec
	ingressRules []ingressRule

	// whitelist egress rules from the network policy spec
	egressRules []egressRule

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType string
}

type podInfo struct {
	ip        string
	name      string
	namespace string
	labels    map[string]string
}

type ingressRule struct {
	matchAllPorts  bool
	ports          []protocolAndPort
	namedPorts     []endPoints
	matchAllSource bool
	srcPods        []podInfo
	srcIPBlocks    [][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	namedPorts           []endPoints
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          [][]string
}
type protocolAndPort struct {
	protocol string
	port     string
	endport  string
}

type endPoints struct {
	ips []string
	protocolAndPort
}

func (ntpc *NetworkPolicyController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(ntpc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Info("Starting network policy controller")
	//klog.Info("Starting network policy controller")
	//npc.healthChan = healthChan

	// setup kube-router specific top level custom chains (KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT)
	klog.Info("安装顶级自定义链(KUBE-DANDELION-INPUT, KUBE-DANDELION-FORWARD, KUBE-DANDELION-OUTPUT)")
	ntpc.setupTopLevelChains()

	// setup default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	klog.Info("安装默认链，将所有通过pod的流量由此收集")
	ntpc.setupDefaultNetworkPolicyChain()

	// Full syncs of the network policy controller take a lot of time and can only be processed one at a time,
	// therefore, we start it in it's own goroutine and request a sync through a single item channel
	klog.Info("Starting network policy controller full sync goroutine")
	wg.Add(1)
	go func(fullSyncRequest <-chan struct{}, stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			// Add an additional non-blocking select to ensure that if the stopCh channel is closed it is handled first
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			default:
			}
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			case <-fullSyncRequest: // 接收到下面监听请求发送到管道的数据
				klog.V(3).Info("Received request for a full sync, processing")
				ntpc.fullPolicySync() // fullPolicySync() is a blocking request here
			}
		}
	}(ntpc.fullSyncRequestChan, stopCh, wg)

	// 循环监听 fullsync的请求 发送到管道 fullSyncRequest
	for {
		klog.V(1).Info("Requesting periodic sync of iptables to reflect network policies")
		ntpc.RequestFullSync()
		select {
		case <-stopCh:
			klog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}

}

// 在filter表中安装顶级自定义链 KUBE-DANDELION-INPUT, KUBE-DANDELION-FORWARD, KUBE-DANDELION-OUTPUT
// 以下的规则将从内置链 跳到自定义链
// -A INPUT   -m comment --comment "kube-router netpol" -j KUBE-DANDELION-INPUT
// -A FORWARD -m comment --comment "kube-router netpol" -j KUBE-DANDELION-FORWARD
// -A OUTPUT  -m comment --comment "kube-router netpol" -j KUBE-DANDELION-OUTPUT
func (ntpc *NetworkPolicyController) setupTopLevelChains() {
	const serviceVIPPosition = 1
	const whitelistTCPNodePortsPosition = 2
	const whitelistUDPNodePortsPosition = 3
	const externalIPPositionAdditive = 4

	iptablesCmd, err := iptables.New()
	if err != nil {
		klog.Fatalf("Failed to initialize iptables executor due to %s", err.Error())
	}

	//在每一个规则中有comment字段的后面添加sum256的uuid
	addUUIDForRuleSpec := func(chain string, ruleSpec *[]string) (string, error) {
		hash := sha256.Sum256([]byte(chain + strings.Join(*ruleSpec, "")))
		encoded := base32.StdEncoding.EncodeToString(hash[:])[:16]
		for idx, part := range *ruleSpec {
			if part == "--comment" {
				(*ruleSpec)[idx+1] = (*ruleSpec)[idx+1] + " - " + encoded
				return encoded, nil
			}
		}
		return "", fmt.Errorf("could not find a comment in the ruleSpec string given: %s", strings.Join(*ruleSpec, " "))
	}

	ensureRuleAtPosition := func(chain string, ruleSpec []string, uuid string, position int) {
		//1.检查规则
		exists, err := iptablesCmd.Exists("filter", chain, ruleSpec...)
		if err != nil {
			klog.Fatalf("检查规则是否存在链 %s 中失败，由于 %s", chain, err.Error())
		}
		//2.不存在则插入规则
		if !exists {
			err := iptablesCmd.Insert("filter", chain, position, ruleSpec...)
			if err != nil {
				klog.Fatalf("插入规则到 %s 链中失败，由于 %s", chain, err.Error())
			}
			return
		}
		//3.查看规则
		rules, err := iptablesCmd.List("filter", chain)
		if err != nil {
			klog.Fatalf("failed to list rules in filter table %s chain due to %s", chain, err.Error())
		}

		var ruleNo, ruleIndexOffset int
		for i, rule := range rules {
			rule = strings.Replace(rule, "\"", "", 2) // 从 comment string中删除引号
			if strings.HasPrefix(rule, "-P") || strings.HasPrefix(rule, "-N") {
				// 如果这个链有一个默认的策略，当iptables List出来时将会显示为 #1；所以我们为这个偏移量加一
				ruleIndexOffset++
				continue
			}
			if strings.Contains(rule, uuid) {
				// range uses a 0 index, but iptables uses a 1 index so we need to increase ruleNo by 1
				ruleNo = i + 1 - ruleIndexOffset
				break
			}
		}
		if ruleNo != position {
			err = iptablesCmd.Insert("filter", chain, position, ruleSpec...)
			if err != nil {
				klog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
			}
			err = iptablesCmd.Delete("filter", chain, strconv.Itoa(ruleNo+1))
			if err != nil {
				klog.Fatalf("Failed to delete incorrect rule in %s chain due to %s", chain, err.Error())
			}
		}
	}
	for builtinChain, customChain := range defaultChains {
		exists, err := iptablesCmd.ChainExists("filter", customChain)
		if err != nil {
			klog.Fatalf("failed to check for the existence of chain %s, error: %v", customChain, err)
		}
		if !exists {
			err = iptablesCmd.NewChain("filter", customChain)
			if err != nil {
				klog.Fatalf("failed to run iptables command to create %s chain due to %s", customChain,
					err.Error())
			}
		}
		args := []string{"-m", "comment", "--comment", "kube-dandelion netpol", "-j", customChain}
		uuid, err := addUUIDForRuleSpec(builtinChain, &args)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(builtinChain, args, uuid, 1)
	}

	//允许pod访问service
	whitelistServiceVips := []string{"-m", "comment", "--comment", "allow traffic to cluster IP", "-d", "10.96.0.0/12", "-j", "RETURN"}
	uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
	if err != nil {
		klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}

	//fmt.Println("插入规则: ",)
	ensureRuleAtPosition(kubeInputChainName, whitelistServiceVips, uuid, serviceVIPPosition)

	// tcp nodeport 白名单
	whitelistTCPNodeports := []string{"-p", "tcp", "-m", "comment", "--comment",
		"allow LOCAL TCP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "multiport", "--dports", "30000:32767", "-j", "RETURN"}
	uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistTCPNodeports)
	if err != nil {
		klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}
	ensureRuleAtPosition(kubeInputChainName, whitelistTCPNodeports, uuid, whitelistTCPNodePortsPosition)

	//udp nodeport 白名单
	whitelistUDPNodeports := []string{"-p", "udp", "-m", "comment", "--comment",
		"allow LOCAL UDP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "multiport", "--dports", "30000:32767", "-j", "RETURN"}
	uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistUDPNodeports)
	if err != nil {
		klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}
	ensureRuleAtPosition(kubeInputChainName, whitelistUDPNodeports, uuid, whitelistUDPNodePortsPosition)

}

//安装默认np链
//Chain KUBE-DANDELION-DEFAULT (0 references)
//MARK  all  --  0.0.0.0/0   0.0.0.0/0   /* rule to mark traffic matching a network policy */ MARK or 0x10000
func (ntpc *NetworkPolicyController) setupDefaultNetworkPolicyChain() {
	iptablesCmd, err := iptables.New()
	if err != nil {
		klog.Fatalf("Failed to initialize iptables executor due to %s", err.Error())
	}

	markArgs := make([]string, 0)
	markComment := "rule to mark traffic matching a network policy by zhutong"
	markArgs = append(markArgs, "-j", "MARK", "-m", "comment", "--comment", markComment, "--set-xmark", "0x10000/0x10000")

	exists, err := iptablesCmd.ChainExists("filter", kubeDefaultNetpolChain)
	if err != nil {
		klog.Fatalf("failed to check for the existence of chain %s, error: %v", kubeDefaultNetpolChain, err)
	}
	if !exists {
		err = iptablesCmd.NewChain("filter", kubeDefaultNetpolChain)
		if err != nil {
			klog.Fatalf("failed to run iptables command to create %s chain due to %s", kubeDefaultNetpolChain, err.Error())
		}
	}

	err = iptablesCmd.AppendUnique("filter", kubeDefaultNetpolChain, markArgs...)
	if err != nil {
		klog.Fatalf("Failed to run iptables command: %s", err.Error())
	}
}

func NewNetworkPolicyController(clientset kubernetes.Interface, config *options.NetworkPolicyControllerConfig,
	podInformer cache.SharedIndexInformer, npInformer cache.SharedIndexInformer,
	nsInformer cache.SharedIndexInformer, ipsetMutex *sync.Mutex) (*NetworkPolicyController, error) {

	ntpc := NetworkPolicyController{ipsetMutex: ipsetMutex}
	// Creating a single-item buffered channel to ensure that we only keep a single full sync request at a time,
	// additional requests would be pointless to queue since after the first one was processed the system would already
	// be up to date with all of the policy changes from any enqueued request after that
	ntpc.fullSyncRequestChan = make(chan struct{}, 1)

	// Validate and parse ClusterIP service range
	_, ipnet, err := net.ParseCIDR(config.ClusterIPCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: %s", err.Error())
	}
	ntpc.serviceClusterIPRange = *ipnet

	// Validate and parse NodePort range
	if ntpc.serviceNodePortRange, err = validateNodePortRange(config.NodePortRange); err != nil {
		return nil, err
	}

	// Validate and parse ExternalIP service range
	//for _, externalIPRange := range config.ExternalIPCIDRs {
	//	_, ipnet, err := net.ParseCIDR(externalIPRange)
	//	if err != nil {
	//		return nil, fmt.Errorf("failed to get parse --service-external-ip-range parameter: '%s'. Error: %s",
	//			externalIPRange, err.Error())
	//	}
	//	npc.serviceExternalIPRanges = append(npc.serviceExternalIPRanges, *ipnet)
	//}

	ntpc.syncPeriod = config.IPTablesSyncPeriod

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	ntpc.nodeHostName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}
	ntpc.nodeIP = nodeIP

	ntpc.podLister = podInformer.GetIndexer()
	ntpc.PodEventHandler = ntpc.newPodEventHandler()

	ntpc.nsLister = nsInformer.GetIndexer()
	ntpc.NamespaceEventHandler = ntpc.newNamespaceEventHandler()

	ntpc.npLister = npInformer.GetIndexer()
	ntpc.NetworkPolicyEventHandler = ntpc.newNetworkPolicyEventHandler()

	return &ntpc, nil
}

// RequestFullSync allows the request of a full network policy sync without blocking the callee
func (ntpc *NetworkPolicyController) RequestFullSync() {
	select {
	case ntpc.fullSyncRequestChan <- struct{}{}:
		klog.V(3).Info("Full sync request queue was empty so a full sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		klog.V(1).Info("Full sync request queue was full, skipping...")
	}
}

// Sync synchronizes iptables to desired state of network policies
func (ntpc *NetworkPolicyController) fullPolicySync() {

	var err error
	var networkPoliciesInfo []networkPolicyInfo
	ntpc.mu.Lock()
	defer ntpc.mu.Unlock()

	//healthcheck.SendHeartBeat(npc.healthChan, "NPC")
	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), syncVersionBase)
	defer func() {
		endTime := time.Since(start)
		klog.V(1).Infof("sync iptables took %v", endTime)
	}()

	klog.V(1).Infof("Starting sync of iptables with version: %s", syncVersion)

	// ensure kube-router specific top level chains and corresponding rules exist
	ntpc.setupTopLevelChains()

	// ensure default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	ntpc.setupDefaultNetworkPolicyChain()

	networkPoliciesInfo, err = ntpc.buildNetworkPoliciesInfo()
	if err != nil {
		klog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
		return
	}

	ntpc.filterTableRules.Reset()
	if err := utils.SaveInto("filter", &ntpc.filterTableRules); err != nil {
		klog.Errorf("Aborting sync. Failed to run iptables-save: %v" + err.Error())
		return
	}

	activePolicyChains, activePolicyIPSets, err := ntpc.syncNetworkPolicyChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to sync network policy chains: %v" + err.Error())
		return
	}

	activePodFwChains := ntpc.syncPodFirewallChains(networkPoliciesInfo, syncVersion)

	// Makes sure that the ACCEPT rules for packets marked with "0x20000" are added to the end of each of kube-router's
	// top level chains
	ntpc.ensureExplicitAccept()

	err = ntpc.cleanupStaleRules(activePolicyChains, activePodFwChains, false)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to cleanup stale iptables rules: %v", err.Error())
		return
	}

	if err := utils.Restore("filter", ntpc.filterTableRules.Bytes()); err != nil {
		klog.Errorf("Aborting sync. Failed to run iptables-restore: %v\n%s",
			err.Error(), ntpc.filterTableRules.String())
		return
	}

	err = ntpc.cleanupStaleIPSets(activePolicyIPSets)
	if err != nil {
		klog.Errorf("Failed to cleanup stale ipsets: %v", err.Error())
		return
	}
}
func (npc *NetworkPolicyController) ensureExplicitAccept() {
	// for the traffic to/from the local pod's let network policy controller be
	// authoritative entity to ACCEPT the traffic if it complies to network policies
	for _, chain := range defaultChains {
		args := []string{"-m", "comment", "--comment", "\"explicitly ACCEPT traffic that complies with network policies\"",
			"-m", "mark", "--mark", "0x20000/0x20000", "-j", "ACCEPT"}
		npc.filterTableRules = utils.AppendUnique(npc.filterTableRules, chain, args)
	}
}
func (npc *NetworkPolicyController) cleanupStaleRules(activePolicyChains, activePodFwChains map[string]bool,
	deleteDefaultChains bool) error {

	cleanupPodFwChains := make([]string, 0)
	cleanupPolicyChains := make([]string, 0)

	// initialize tool sets for working with iptables and ipset
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to initialize iptables command executor due to %s", err.Error())
	}

	// find iptables chains and ipsets that are no longer used by comparing current to the active maps we were passed
	chains, err := iptablesCmdHandler.ListChains("filter")
	if err != nil {
		return fmt.Errorf("unable to list chains: %s", err)
	}
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
			if chain == kubeDefaultNetpolChain {
				continue
			}
			if _, ok := activePolicyChains[chain]; !ok {
				cleanupPolicyChains = append(cleanupPolicyChains, chain)
				continue
			}
		}
		if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
			if _, ok := activePodFwChains[chain]; !ok {
				cleanupPodFwChains = append(cleanupPodFwChains, chain)
				continue
			}
		}
	}

	var newChains, newRules, desiredFilterTable bytes.Buffer
	rules := strings.Split(npc.filterTableRules.String(), "\n")
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}
	for _, rule := range rules {
		skipRule := false
		for _, podFWChainName := range cleanupPodFwChains {
			if strings.Contains(rule, podFWChainName) {
				skipRule = true
				break
			}
		}
		for _, policyChainName := range cleanupPolicyChains {
			if strings.Contains(rule, policyChainName) {
				skipRule = true
				break
			}
		}
		if deleteDefaultChains {
			for _, chain := range []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName,
				kubeDefaultNetpolChain} {
				if strings.Contains(rule, chain) {
					skipRule = true
					break
				}
			}
		}
		if strings.Contains(rule, "COMMIT") || strings.HasPrefix(rule, "# ") {
			skipRule = true
		}
		if skipRule {
			continue
		}
		if strings.HasPrefix(rule, ":") {
			newChains.WriteString(rule + " - [0:0]\n")
		}
		if strings.HasPrefix(rule, "-") {
			newRules.WriteString(rule + "\n")
		}
	}
	desiredFilterTable.WriteString("*filter" + "\n")
	desiredFilterTable.Write(newChains.Bytes())
	desiredFilterTable.Write(newRules.Bytes())
	desiredFilterTable.WriteString("COMMIT" + "\n")
	npc.filterTableRules = desiredFilterTable

	return nil
}
func (ntpc *NetworkPolicyController) cleanupStaleIPSets(activePolicyIPSets map[string]bool) error {
	cleanupPolicyIPSets := make([]*utils.Set, 0)

	// There are certain actions like Cleanup() actions that aren't working with full instantiations of the controller
	// and in these instances the mutex may not be present and may not need to be present as they are operating out of a
	// single goroutine where there is no need for locking
	if nil != ntpc.ipsetMutex {
		klog.V(1).Infof("Attempting to attain ipset mutex lock")
		ntpc.ipsetMutex.Lock()
		klog.V(1).Infof("Attained ipset mutex lock, continuing...")
		defer func() {
			ntpc.ipsetMutex.Unlock()
			klog.V(1).Infof("Returned ipset mutex lock")
		}()
	}

	ipsets, err := utils.NewIPSet(false)
	if err != nil {
		return fmt.Errorf("failed to create ipsets command executor due to %s", err.Error())
	}
	err = ipsets.Save()
	if err != nil {
		klog.Fatalf("failed to initialize ipsets command executor due to %s", err.Error())
	}
	for _, set := range ipsets.Sets {
		if strings.HasPrefix(set.Name, kubeSourceIPSetPrefix) ||
			strings.HasPrefix(set.Name, kubeDestinationIPSetPrefix) {
			if _, ok := activePolicyIPSets[set.Name]; !ok {
				cleanupPolicyIPSets = append(cleanupPolicyIPSets, set)
			}
		}
	}
	// cleanup network policy ipsets
	for _, set := range cleanupPolicyIPSets {
		err = set.Destroy()
		if err != nil {
			return fmt.Errorf("failed to delete ipset %s due to %s", set.Name, err)
		}
	}
	return nil
}

func (ntpc *NetworkPolicyController) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*api.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if pod, ok = tombstone.Obj.(*api.Pod); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	klog.V(2).Infof("Received pod: %s/%s delete event", pod.Namespace, pod.Name)

	ntpc.RequestFullSync()
}

func (ntpc *NetworkPolicyController) ListPodsByNamespaceAndLabels(namespace string,
	podSelector labels.Selector) (ret []*api.Pod, err error) {
	podLister := listers.NewPodLister(ntpc.podLister)
	allMatchedNameSpacePods, err := podLister.Pods(namespace).List(podSelector)
	if err != nil {
		return nil, err
	}
	return allMatchedNameSpacePods, nil
}

func (ntpc *NetworkPolicyController) ListNamespaceByLabels(namespaceSelector labels.Selector) ([]*api.Namespace, error) {
	namespaceLister := listers.NewNamespaceLister(ntpc.nsLister)
	matchedNamespaces, err := namespaceLister.List(namespaceSelector)
	if err != nil {
		return nil, err
	}
	return matchedNamespaces, nil
}
