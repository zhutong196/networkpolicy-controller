package controllers

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog/v2"
	"strconv"
	"strings"
)

// 查看filter表
//Chain INPUT (policy ACCEPT)
//KUBE-DANDELION-INPUT  all  --  anywhere   anywhere    /* kube-dandelion netpol - RLCOZSWW5IFKBXWF */
//Chain FORWARD (policy ACCEPT)
//KUBE-DANDELION-FORWARD  all  --  anywhere  anywhere   /* kube-dandelion netpol - VFRR5KNV4OT7AAX6 */
//Chain OUTPUT (policy ACCEPT)
//KUBE-DANDELION-OUTPUT  all  --  anywhere   anywhere   /* kube-dandelion netpol - 3TITXDA3F4NZD62R */

//Chain KUBE-DANDELION-FORWARD (1 references)
//target     prot opt source               destination

//Chain KUBE-DANDELION-INPUT (1 references)
//target     prot opt source      destination
//RETURN     all  --  anywhere    10.96.0.0/12   /* allow traffic to cluster IP - I2F3FSZJYC6YZS7C */
//RETURN     tcp  --  anywhere    anywhere       /* allow LOCAL TCP traffic to node ports - BEFLEX3B4LAGGPAF */ ADDRTYPE match dst-type LOCAL multiport dports ndmps:filenet-powsrm
//RETURN     udp  --  anywhere    anywhere       /* allow LOCAL UDP traffic to node ports - Y3BVZIFPNOYUKLZX */ ADDRTYPE match dst-type LOCAL multiport dports 30000:filenet-powsrm

//Chain KUBE-DANDELION-OUTPUT (1 references)
//target     prot opt source               destination
func TestSetTopLevelChain() {
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

	//for externalIPIndex, externalIPRange := range npc.serviceExternalIPRanges {
	//	whitelistServiceVips := []string{"-m", "comment", "--comment",
	//		"allow traffic to external IP range: " + externalIPRange.String(), "-d", externalIPRange.String(),
	//		"-j", "RETURN"}
	//	uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
	//	if err != nil {
	//		klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	//	}
	//	ensureRuleAtPosition(kubeInputChainName, whitelistServiceVips, uuid, externalIPIndex+externalIPPositionAdditive)
	//}
}

//安装默认np链
//Chain KUBE-DANDELION-DEFAULT (0 references)
//MARK    all  --  0.0.0.0/0      0.0.0.0/0   /* rule to mark traffic matching a network policy */ MARK or 0x10000
func TestsetupDefaultNetworkPolicyChain() {
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
