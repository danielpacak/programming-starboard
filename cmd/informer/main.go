package main

import (
	"fmt"
	"log"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/generated/informers/externalversions"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			report := obj.(*v1alpha1.ConfigAuditReport)
			fmt.Printf("ConfigAuditReport has been created: %q\n", report.Namespace+"/"+report.Name)
		},
		UpdateFunc: func(_ interface{}, newObj interface{}) {
			report := newObj.(*v1alpha1.ConfigAuditReport)
			fmt.Printf("ConfigAuditReport has been updated: %q\n", report.Namespace+"/"+report.Name)
		},
		DeleteFunc: func(obj interface{}) {
			report := obj.(*v1alpha1.ConfigAuditReport)
			fmt.Printf("ConfigAuditReport has bee deleted: %q\n", report.Namespace+"/"+report.Name)
		},
	}

	stopCh := wait.NeverStop
	if err := run(stopCh, handler); err != nil {
		log.Fatal(err.Error())
	}
	<-stopCh
}

func run(stopCh <-chan struct{}, handler cache.ResourceEventHandler) error {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", "/Users/dpacak/.kube/config")
	if err != nil {
		return err
	}
	kubeClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}
	informerFactory := externalversions.NewSharedInformerFactory(kubeClient, time.Second*30)
	informer := informerFactory.Aquasecurity().V1alpha1().ConfigAuditReports()
	informer.Informer().AddEventHandler(handler)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	return nil
}
