package kubecollect

import (
	//"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"sdc_internal"
	"fmt"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/cache"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"reflect"
)

var kubeClient kubeclient.Interface = nil
//var kubestop := make(chan struct{})
var pinf cache.SharedInformer = nil

var downstream = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
var fifo = cache.NewDeltaFIFO(cache.MetaNamespaceKeyFunc, nil, downstream)
var cfg = &cache.Config{
	Queue: fifo,
//	ListerWatcher: plw,
	ObjectType: &v1.Pod{},
	//FullResyncPeriod: time.Millisecond * 100,
	FullResyncPeriod: time.Second * 20,
	//FullResyncPeriod: resyncPeriod,
	RetryOnError: false,
	Process: func(obj interface{}) error {
		log.Infof("inside Process() for %d deltas", len(obj.(cache.Deltas)))
		/*
		for _, podKey := range fifo.ListKeys() {
			log.Infof("podKey: %v", podKey)
		}
*/
/*
		bbtest := obj.(cache.Deltas).Newest()
		log.Infof("Action: %v for pod: %v",
			bbtest.Type,
			(bbtest.Object).(*v1.Pod).GetName())
*/
/*
		for _, newest := range obj.(cache.Deltas) {
			log.Infof("DeltaType: %v for pod: %v",
				newest.Type,
				(newest.Object).(*v1.Pod).GetName())
		}
*/
		return nil
	},
}
var stop = make(chan struct{})

func HelloPods(ctx context.Context, cmd *sdc_internal.KubeHelloCommand) (*sdc_internal.KubeHelloResult, error) {
	//log.Debugf("Received Kube Hello message: %s", cmd.String())

	apiserver := "http://127.0.0.1:8080"

	if kubeClient == nil {
		kClient, err := createKubeClient(apiserver)
		if err != nil {
			return nil, fmt.Errorf("ERROR during createKubeClient: %v", err)
		} else {
			kubeClient = kClient
		}

		// Informers don't seem to do a good job logging error messages when it
		// can't reach the server, making debugging hard. This makes it easier to
		// figure out if apiserver is configured incorrectly.
		log.Infof("Testing communication with server")
		srvVersion, err := kubeClient.Discovery().ServerVersion()
		if err != nil {
			return nil, fmt.Errorf("ERROR communicating with apiserver: %v", err)
		}
		log.Infof("Communication with server successful: %v", srvVersion)

		client := kubeClient.CoreV1().RESTClient()
		plw := cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, nil)
		// do delta fifo instead
		//cfg.ListerWatcher = cache.NewListWatchFromClient(client, "pods", v1meta.NamespaceAll, nil)

		log.Infof("Launching the goroutine using seelog")
		//go cache.New(cfg).Run(context.Background().Done())
		//go cache.New(cfg).Run(stop)

		resyncPeriod := time.Duration(10) * time.Second;
		pinf = cache.NewSharedInformer(plw, &v1.Pod{}, resyncPeriod)
		pinf.AddEventHandler(
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					log.Infof("AddFunc for pod: %v",
						obj.(*v1.Pod).GetName())
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					oldPod := oldObj.(*v1.Pod)
					newPod := newObj.(*v1.Pod)
					if oldPod.GetResourceVersion() != newPod.GetResourceVersion() {
						log.Infof("UpdateFunc for pod %v: old (%v) and new (%v)",
							newPod.GetName(),
							oldPod.GetResourceVersion(),
							newPod.GetResourceVersion())
					}
				},
				DeleteFunc: func(obj interface{}) {
					log.Infof("DeleteFunc for pod: %v",
						obj.(*v1.Pod).GetName())				},
			},
		)

		go pinf.Run(context.Background().Done())
		//log.Debugf("HelloPods in steady state: %v", pinf.GetStore().ListKeys())
		//go pinf.Run(kubestop)
	} else {
		log.Infof("informer hasSynced() is %v", pinf.HasSynced())

		if pinf == nil {
			log.Infof("wtf pinf is NULL?")
		} else if pinf.GetStore() == nil {
			log.Infof("how is the store nil?!")
//		} else if pinf.GetStore().ListKeys() == nil {
//			log.Infof("seriously??!")
		}
		//log.Infof("HelloPods in steady state: %v", somePodNotReally)
		for _, m := range pinf.GetStore().List() {
			log.Infof("Store has pod: %v", m.(*v1.Pod).GetName())
		}
	}

	
	res := &sdc_internal.KubeHelloResult{}
	res.Successful = proto.Bool(true)
	return res, nil
}

/*
func createFifoQueue(apiserver string) (kubeClient kubeclient.Interface, err error) {
	log.Infof("HelloPods: calling createFifoQueue")

}
*/

func createKubeClient(apiserver string) (kubeClient kubeclient.Interface, err error) {
	log.Info("HelloPods: calling createKubeClient")

	baseConfig := clientcmdapi.NewConfig()
	configOverrides := &clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: apiserver}}
	kubeConfig := clientcmd.NewDefaultClientConfig(*baseConfig, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Infof("HelloPods error: can't create config")
		return nil, err
	}

	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Infof("HelloPods error: NewForConfig fails")
		return nil, err
	}

	// Informers don't seem to do a good job logging error messages when it
	// can't reach the server, making debugging hard. This makes it easier to
	// figure out if apiserver is configured incorrectly.
	//log.Infof("Testing communication with server")
	_, err = kubeClient.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("ERROR communicating with apiserver: %v", err)
	}
	//log.Infof("INSIDE - Communication with server successful")

	return kubeClient, nil
}
