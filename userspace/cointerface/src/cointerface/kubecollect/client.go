package kubecollect

import (
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/rest"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apimachinery/pkg/fields"
	"cointerface/draiosproto"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
	"golang.org/x/net/context"
	"strings"
	"sync"
	"regexp"
)

var compatibilityMap map[string]bool

const RsyncInterval = 10 * time.Minute

// The input context is passed to all goroutines created by this function.
// The caller is responsible for draining messages from the returned channel
// until the channel is closed, otherwise the component goroutines may block
func WatchCluster(parentCtx context.Context, url string, ca_cert string, client_cert string, client_key string) (<-chan draiosproto.CongroupUpdateEvent, error) {
	setErrorLogHandler()

	// TODO: refactor error messages
	var kubeClient kubeclient.Interface

	if url != "" {
		log.Infof("Connecting to k8s server at %s", url)
		var err error
		kubeClient, err = createKubeClient(url, ca_cert,
			client_cert, client_key)
		if err != nil {
			log.Errorf("Cannot create k8s client: %s", err)
			return nil, err
		}
	} else {
		log.Infof("Connecting to k8s server using inCluster config")
		var err error
		kubeClient, err = createInClusterKubeClient()
		if err != nil {
			log.Errorf("Cannot create k8s client: %s", err)
			return nil, err
		}
	}
	log.Infof("Testing communication with server")
	srvVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		log.Errorf("K8s server not responding: %s", err)
		return nil, err
	}
	log.Infof("Communication with server successful: %v", srvVersion)

	resources, err := kubeClient.Discovery().ServerResources()
	if err != nil {
		log.Errorf("K8s server returned error: %s", err)
		return nil, err
	}

	compatibilityMap = make(map[string]bool)
	for _, resourceList := range resources {
		for _, resource := range resourceList.APIResources {
			verbStr := ""
			for _, verb := range resource.Verbs {
				verbStr += verb
				verbStr += ","
			}
			verbStr = strings.Trim(verbStr, ",")
			log.Debugf("K8s API server supports %s/%s: %s",
				resourceList.GroupVersion, resource.Name, verbStr)

			if resource.Name == "cronjobs" &&
				resourceList.GroupVersion != "batch/v2alpha1" {
				continue
			}
			compatibilityMap[resource.Name] = true
		}
	}

	// Caller is responsible for draining the chan
	evtc := make(chan draiosproto.CongroupUpdateEvent)
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(parentCtx)
	// Start a routine to do a watch on namespaces
	// to detect api server connection errors because
	// SharedInformers don't surface errors
	go func() {
		defer cancel()
		log.Debugf("Creating K8s watchdog thread")

		client := kubeClient.CoreV1().RESTClient()
		lw := cache.NewListWatchFromClient(client, "namespaces", v1meta.NamespaceAll, fields.Everything())
		watcher, err := lw.Watch(v1meta.ListOptions{})
		if err != nil {
			log.Errorf("K8s watchdog, error creating api server watchdog: %v", err)
			return
		}
		defer watcher.Stop()

		for {
			select {
			case event, ok := <-watcher.ResultChan():
				if !ok {
					log.Warnf("K8s watchdog received a watch error")
					return
				}
				if event.Type == watch.Error {
					log.Errorf("K8s watchdog received watch error: %v",
						apierrs.FromObject(event.Object))
					return
				}
			case <-parentCtx.Done():
				log.Infof("K8s watchdog, parent context cancelled")
				return
			}
		}
	}()

	// The informers are responsible for Add()'ing to the wg
	if compatibilityMap["namespaces"] {
		startNamespacesSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have namespaces API support.")
	}
	if compatibilityMap["deployments"] {
		startDeploymentsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have deployments API support.")
	}
	if compatibilityMap["replicasets"] {
		startReplicaSetsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have replicasets API support.")
	}
	if compatibilityMap["services"] {
		startServicesSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have services API support.")
	}
	if compatibilityMap["ingress"] {
		startIngressSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have ingress API support.")
	}
	if compatibilityMap["daemonsets"] {
		startDaemonSetsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have daemonsets API support.")
	}
	if compatibilityMap["nodes"] {
		startNodesSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have nodes API support.")
	}
	if compatibilityMap["jobs"] {
		startJobsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have jobs API support.")
	}
	if compatibilityMap["cronjobs"] {
		startCronJobsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have v2alpha1 cronjobs API support.")
	}
	if compatibilityMap["replicationcontrollers"] {
		startReplicationControllersSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have replicationcontrollers API support.")
	}
	if compatibilityMap["statefulsets"] {
		startStatefulSetsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have statefulsets API support.")
	}
	if compatibilityMap["resourcequotas"] {
		startResourceQuotasSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have resourcequotas API support.")
	}
	if compatibilityMap["pods"] {
		startPodsSInformer(ctx, kubeClient, &wg)
	} else {
		log.Warnf("K8s server doesn't have pods API support.")
	}

	if compatibilityMap["namespaces"] {
		watchNamespaces(evtc)
	}
	if compatibilityMap["deployments"] {
		watchDeployments(evtc)
	}
	if compatibilityMap["replicasets"] {
		watchReplicaSets(evtc)
	}
	if compatibilityMap["services"] {
		watchServices(evtc)
	}
	if compatibilityMap["ingress"] {
		watchIngress(evtc)
	}
	if compatibilityMap["daemonsets"] {
		watchDaemonSets(evtc)
	}
	if compatibilityMap["nodes"] {
		watchNodes(evtc)
	}
	if compatibilityMap["jobs"] {
		watchJobs(evtc)
	}
	if compatibilityMap["cronjobs"] {
		watchCronJobs(evtc)
	}
	if compatibilityMap["replicationcontrollers"] {
		watchReplicationControllers(evtc)
	}
	if compatibilityMap["statefulsets"] {
		watchStatefulSets(evtc)
	}
	if compatibilityMap["resourcequotas"] {
		watchResourceQuotas(evtc)
	}
	if compatibilityMap["pods"] {
		watchPods(evtc)
	}
	/*watch, _ := kubeClient.CoreV1().Events("").Watch(metav1.ListOptions{})

	go func() {
		select {
		case evt := <-watch.ResultChan():
			log.Infof("Received k8s event %v", evt)
		}
	}()*/

	// In a separate goroutine, wait for the informers and
	// close evtc once they're done to notify the caller
	go func() {
		wg.Wait()
		log.Infof("All informers have exited, closing the events channel")
		close(evtc)
	}()

	return evtc, nil
}

func createKubeClient(apiserver string, ca_cert string, client_cert string, client_key string) (kubeClient kubeclient.Interface, err error) {
	baseConfig := clientcmdapi.NewConfig()
	configOverrides := &clientcmd.ConfigOverrides{
		ClusterInfo: clientcmdapi.Cluster{
			Server: apiserver,
			CertificateAuthority: ca_cert,
		},
		AuthInfo: clientcmdapi.AuthInfo{
			ClientCertificate: client_cert,
			ClientKey: client_key,
		},
	}
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

	return kubeClient, nil
}

func createInClusterKubeClient() (kubeClient kubeclient.Interface, err error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("Cannot create InCluster config: ", err)
		return nil, err
	}
	// creates the clientset
	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Errorf("Cannot create client using cluster config", err)
		return nil, err
	}
	return
}

// The default logger for client-go errors logs them to stderr in a format
// the C++ side can't parse, so intercept them and re-log them correctly
func setErrorLogHandler() {
	// Remove the leading filename + line number
	// Example: "cointerface/kubecollect/pods.go:123: "
	errRegex, err := regexp.Compile(`^cointerface/\S+\.go:\d+: `)
	if err != nil {
		log.Errorf("Unable to create error log regex: %v", err)
		return
	}

	// We intentionally reassign ErrorHandlers so it both
	// adds our handler and removes the existing handlers
	runtime.ErrorHandlers = []func(error) {
		func(err error) {
			startIdx := 0
			loc := errRegex.FindStringIndex(err.Error())
			if loc != nil {
				startIdx = loc[1]
			}
			log.Error(err.Error()[startIdx:])
		},
	}
}

func GetTags(obj v1meta.ObjectMeta, prefix string) map[string]string {
	tags := make(map[string]string)
	for k, v := range obj.GetLabels() {
		tags[prefix+"label." + k] = v
	}
	tags[prefix+"name"] = obj.GetName()
	return tags
}

func GetAnnotations(obj v1meta.ObjectMeta, prefix string) map[string]string {
	tags := make(map[string]string)
	for k, v := range obj.GetAnnotations() {
		tags[prefix+"annotation." + k] = v
	}
	tags[prefix+"name"] = obj.GetName()
	return tags
}

func EqualLabels(lhs v1meta.ObjectMeta, rhs v1meta.ObjectMeta) bool {
	left := lhs.GetLabels()
	right := rhs.GetLabels()
	if (len(left) != len(right)) {
		return false
	}
	for k,v := range left {
		if right[k] != v {
			return false
		}
	}
	return true
}

func EqualAnnotations(lhs v1meta.ObjectMeta, rhs v1meta.ObjectMeta) bool {
	left := lhs.GetAnnotations()
	right := rhs.GetAnnotations()
	if (len(left) != len(right)) {
		return false
	}
	for k,v := range left {
		if right[k] != v {
			return false
		}
	}
	return true
}

func AppendMetric(metrics *[]*draiosproto.AppMetric, name string, val float64) {
	*metrics = append(*metrics, &draiosproto.AppMetric{
		Name:proto.String(name),
		Type:draiosproto.AppMetricType_APP_METRIC_TYPE_GAUGE.Enum(),
		Value:proto.Float64(val),
	})
}

func AppendMetricInt32(metrics *[]*draiosproto.AppMetric, name string, val int32) {
	AppendMetric(metrics, name, float64(val))
}

func AppendMetricPtrInt32(metrics *[]*draiosproto.AppMetric, name string, val *int32) {
	v := int32(0)
	if val != nil {
		v = *val
	}
	AppendMetricInt32(metrics, name, v)
}

func AppendMetricBool(metrics *[]*draiosproto.AppMetric, name string, val bool) {
	v := float64(0)
	if val == true {
		v = 1
	}
	AppendMetric(metrics, name, v)
}

func appendMetricResource(metrics *[]*draiosproto.AppMetric, name string, rList v1.ResourceList, rName v1.ResourceName) {
	v := float64(0)
	qty, ok := rList[rName]
	if ok {
		// Take MilliValue() and divide because
		// we could lose precision with Value()
		v = float64(qty.MilliValue())/1000
	}
	AppendMetric(metrics, name, v)
}
