package controllers

import (
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	api "k8s.io/api/core/v1"
	"reflect"
	"regexp"
	"strconv"
)

const (
	PodCompleted api.PodPhase = "Completed"
)

func isFinished(pod *api.Pod) bool {
	// nolint:exhaustive // We don't care about PodPending, PodRunning, PodUnknown here as we want those to fall
	// into the false case
	switch pod.Status.Phase {
	case api.PodFailed, api.PodSucceeded, PodCompleted:
		return true
	}
	return false
}

func validateNodePortRange(nodePortOption string) (string, error) {
	const portBitSize = 16

	nodePortValidator := regexp.MustCompile(`^([0-9]+)[:-]([0-9]+)$`)
	if matched := nodePortValidator.MatchString(nodePortOption); !matched {
		return "", fmt.Errorf(
			"failed to parse node port range given: '%s' please see specification in help text", nodePortOption)
	}
	matches := nodePortValidator.FindStringSubmatch(nodePortOption)
	if len(matches) != 3 {
		return "", fmt.Errorf("could not parse port number from range given: '%s'", nodePortOption)
	}
	port1, err := strconv.ParseUint(matches[1], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse first port number from range given: '%s'", nodePortOption)
	}
	port2, err := strconv.ParseUint(matches[2], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse second port number from range given: '%s'", nodePortOption)
	}
	if port1 >= port2 {
		return "", fmt.Errorf("port 1 is greater than or equal to port 2 in range given: '%s'", nodePortOption)
	}
	return fmt.Sprintf("%d:%d", port1, port2), nil
}

//检查pod是否更新networkPolicy相关的属性，查找相关更改，则返回true，否则返回false。我们关心的网络策略：
//1）pod的状态是否发生变化？（捕获已完成、成功或失败作业的事项）
//2）Pod IP是否正在更改？（更改网络策略应用于主机的方式）
//3）pod的主机IP是否正在更改？
//4）Pod的标签是否正在更改？（可能会更改选择此pod的网络策略。）
func isPodUpdateNetPolicyRelevant(oldPod, newPod *api.Pod) bool {
	return newPod.Status.Phase != oldPod.Status.Phase ||
		newPod.Status.PodIP != oldPod.Status.PodIP ||
		!reflect.DeepEqual(newPod.Status.PodIPs, oldPod.Status.PodIPs) ||
		newPod.Status.HostIP != oldPod.Status.HostIP ||
		!reflect.DeepEqual(newPod.Labels, oldPod.Labels)
}

func (npc *NetworkPolicyController) createGenericHashIPSet(ipsetName, hashType string, ips []string) {
	setEntries := make([][]string, 0)
	for _, ip := range ips {
		setEntries = append(setEntries, []string{ip, utils.OptionTimeout, "0"})
	}
	npc.ipSetHandler.RefreshSet(ipsetName, setEntries, hashType)
}

// createPolicyIndexedIPSet creates a policy based ipset and indexes it as an active ipset
func (npc *NetworkPolicyController) createPolicyIndexedIPSet(
	activePolicyIPSets map[string]bool, ipsetName, hashType string, ips []string) {
	activePolicyIPSets[ipsetName] = true
	npc.createGenericHashIPSet(ipsetName, hashType, ips)
}

// createPodWithPortPolicyRule handles the case where port details are provided by the ingress/egress rule and creates
// an iptables rule that matches on both the source/dest IPs and the port
func (npc *NetworkPolicyController) createPodWithPortPolicyRule(
	ports []protocolAndPort, policy networkPolicyInfo, policyName string, srcSetName string, dstSetName string) error {
	for _, portProtocol := range ports {
		comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
			policy.name + " namespace " + policy.namespace
		if err := npc.appendRuleToPolicyChain(policyName, comment, srcSetName, dstSetName, portProtocol.protocol,
			portProtocol.port, portProtocol.endport); err != nil {
			return err
		}
	}
	return nil
}

func getIPsFromPods(pods []podInfo) []string {
	ips := make([]string, len(pods))
	for idx, pod := range pods {
		ips[idx] = pod.ip
	}
	return ips
}
