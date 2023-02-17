package main

import (
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
	"npController/cmd"
	"npController/options"
	"os"
)

func main() {
	//controllers.TestSetTopLevelChain()
	//controllers.TestsetupDefaultNetworkPolicyChain()

	klog.InitFlags(nil)

	//1.解析命令行配置
	config := options.NewNetworkPolicyControllerConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.Parse()

	if config.HelpRequested {
		pflag.Usage()
		os.Exit(1)
	}

	if os.Getuid() != 0 {
		klog.Error("networkPolicyController must run with privileges")
		os.Exit(1)
	}

	//2. 根据配置创建app实例
	networkApp, err := cmd.NewNetworkPolicyAppDefault(config)
	if err != nil {
		klog.Errorf("failed to parse network-policy-controller config: %v", err)
		os.Exit(1)
	}

	err = networkApp.Run()
	if err != nil {
		klog.Errorf("failed to run network-policy-controller: %v", err)
		os.Exit(1)
	}

}
