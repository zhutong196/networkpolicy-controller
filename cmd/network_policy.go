package cmd

import (
	"errors"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"npController/controllers"
	"npController/options"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type NetworkPolicyApp struct {
	Client kubernetes.Interface
	Config *options.NetworkPolicyControllerConfig
}

func NewNetworkPolicyAppDefault(config *options.NetworkPolicyControllerConfig) (*NetworkPolicyApp, error) {
	var clientconfig *rest.Config
	var err error

	//version.PrintVersion(true)
	// Use out of cluster config if the URL or kubeconfig have been specified. Otherwise use incluster config.
	if len(config.Master) != 0 || len(config.Kubeconfig) != 0 {
		clientconfig, err = clientcmd.BuildConfigFromFlags(config.Master, config.Kubeconfig)
		if err != nil {
			return nil, errors.New("Failed to build configuration from CLI: " + err.Error())
		}
	} else {
		clientconfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("unable to initialize inclusterconfig: " + err.Error())
		}
	}

	clientset, err := kubernetes.NewForConfig(clientconfig)
	if err != nil {
		return nil, errors.New("Failed to create Kubernetes client: " + err.Error())
	}

	return &NetworkPolicyApp{Client: clientset, Config: config}, nil
}

func (npa *NetworkPolicyApp) Run() error {
	var err error
	var ipsetMutex sync.Mutex
	var wg sync.WaitGroup

	stopCh := make(chan struct{})

	// 初始化informer 监听svc，ep，等资源
	informerFactory := informers.NewSharedInformerFactory(npa.Client, 0)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	informerFactory.Start(stopCh)

	// 启动informer
	err = npa.CacheSyncOrTimeout(informerFactory, stopCh)
	if err != nil {
		return errors.New("Failed to synchronize cache: " + err.Error())
	}

	ntpc, err := controllers.NewNetworkPolicyController(npa.Client,
		npa.Config, podInformer, npInformer, nsInformer, &ipsetMutex)
	if err != nil {
		return errors.New("Failed to create network policy controller: " + err.Error())
	}

	podInformer.AddEventHandler(ntpc.PodEventHandler)
	nsInformer.AddEventHandler(ntpc.NamespaceEventHandler)
	npInformer.AddEventHandler(ntpc.NetworkPolicyEventHandler)

	wg.Add(1)
	go ntpc.Run(stopCh, &wg)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	klog.Infof("Shutting down the controllers")
	close(stopCh)

	wg.Wait()
	return nil
}

func (npa *NetworkPolicyApp) CacheSyncOrTimeout(informerFactory informers.SharedInformerFactory,
	stopCh <-chan struct{}) error {
	syncOverCh := make(chan struct{})
	go func() {
		informerFactory.WaitForCacheSync(stopCh)
		close(syncOverCh)
	}()

	select {
	case <-time.After(npa.Config.CacheSyncTimeout):
		return errors.New(npa.Config.CacheSyncTimeout.String() + " timeout")
	case <-syncOverCh:
		return nil
	}
}
