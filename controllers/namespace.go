package controllers

import (
	"reflect"

	api "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

//这里只关注namespace 标签的增删改查
func (ntpc *NetworkPolicyController) newNamespaceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ntpc.handleNamespaceAdd(obj.(*api.Namespace))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ntpc.handleNamespaceUpdate(oldObj.(*api.Namespace), newObj.(*api.Namespace))
		},
		DeleteFunc: func(obj interface{}) {
			switch obj := obj.(type) {
			case *api.Namespace:
				ntpc.handleNamespaceDelete(obj)
				return
			case cache.DeletedFinalStateUnknown:
				if namespace, ok := obj.Obj.(*api.Namespace); ok {
					ntpc.handleNamespaceDelete(namespace)
					return
				}
			default:
				klog.Errorf("unexpected object type: %v", obj)
			}
		},
	}
}

func (ntpc *NetworkPolicyController) handleNamespaceAdd(obj *api.Namespace) {
	if obj.Labels == nil {
		return
	}
	klog.V(2).Infof("Received update for namespace: %s", obj.Name)

	ntpc.RequestFullSync()
}

func (ntpc *NetworkPolicyController) handleNamespaceUpdate(oldObj, newObj *api.Namespace) {
	if reflect.DeepEqual(oldObj.Labels, newObj.Labels) {
		return
	}
	klog.V(2).Infof("Received update for namespace: %s", newObj.Name)

	ntpc.RequestFullSync()
}

func (ntpc *NetworkPolicyController) handleNamespaceDelete(obj *api.Namespace) {
	if obj.Labels == nil {
		return
	}
	klog.V(2).Infof("Received namespace: %s delete event", obj.Name)

	ntpc.RequestFullSync()
}
