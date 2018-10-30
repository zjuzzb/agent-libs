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
	"cointerface/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"io/ioutil"
	"time"
	"golang.org/x/net/context"
	"strings"
	"sync"
	"regexp"
	"runtime/debug"
)

// XXX make these into one map and/or remove them if
// HasSynced checking works instead of using receiveMap
var startedMap map[string]bool
var startedMutex sync.RWMutex
var receiveMap map[string]bool
var receiveMutex sync.RWMutex
var prometheusEnabled bool

const RsyncInterval = 10 * time.Minute

// The input context is passed to all goroutines created by this function.
// The caller is responsible for draining messages from the returned channel
// until the channel is closed, otherwise the component goroutines may block.
// The empty struct chan notifies the caller that the initial event fetch
// is complete by closing the chan.
func WatchCluster(parentCtx context.Context, opts *sdc_internal.OrchestratorEventsStreamCommand) (<-chan draiosproto.CongroupUpdateEvent, <-chan struct{}, error) {
	setErrorLogHandler()
	prometheusEnabled = opts.GetPrometheus()

	// TODO: refactor error messages
	var kubeClient kubeclient.Interface

	if opts.GetUrl() != "" {
		log.Infof("Connecting to k8s server at %s", opts.GetUrl())
		var err error
		kubeClient, err = createKubeClient(opts.GetUrl(), opts.GetCaCert(),
			opts.GetClientCert(), opts.GetClientKey(),
			opts.GetSslVerifyCertificate(), opts.GetAuthToken())
		if err != nil {
			log.Errorf("Cannot create k8s client: %s", err)
			return nil, nil, err
		}
	} else {
		log.Infof("Connecting to k8s server using inCluster config")
		var err error
		kubeClient, err = createInClusterKubeClient()
		if err != nil {
			log.Errorf("Cannot create k8s client: %s", err)
			return nil, nil, err
		}
	}
	log.Infof("Testing communication with server")
	srvVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		log.Errorf("K8s server not responding: %s", err)
		return nil, nil, err
	}
	log.Infof("Communication with server successful: %v", srvVersion)

	resources, err := kubeClient.Discovery().ServerResources()
	if err != nil {
		log.Errorf("K8s server returned error: %s", err)
		return nil, nil, err
	}

	// Reset all globals
	// XXX better yet, make them not package globals
	startedMap = make(map[string]bool)
	receiveMap = make(map[string]bool)

	// Initialize a local vector of all resource types
	var resourceTypes []string
	
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

			// If the resource type is "nodes" or "namespaces" we
			// PREPEND them. (we want to process those first). Else
			// append the other resource types.
			if(resource.Name == "nodes" || resource.Name == "namespaces") {
				resourceTypes = append([]string{resource.Name}, resourceTypes...)
			} else {
				resourceTypes = append(resourceTypes, resource.Name)
			}
		}
	}

	// Caller is responsible for draining the chan
	evtc := make(chan draiosproto.CongroupUpdateEvent, opts.GetQueueLen())

	ctx, cancel := context.WithCancel(parentCtx)
	// Start a routine to do a watch on namespaces
	// to detect api server connection errors because
	// SharedInformers don't surface errors
	//
	// Returns synchronously with err set if the initial watch fails
	// Else, return nil and spawn a goroutine to monitor the watch
	err = startWatchdog(parentCtx, cancel, kubeClient)
	if err != nil {
		// startWatchdog() may later hit an async error,
		// so it's responsible for all error logging
		return nil, nil, err
	}

	fetchDone := make(chan struct{})
	var wg sync.WaitGroup
	// Start informers in a separate routine so we can return the
	// evt chan and let the caller start reading/draining events
	go startInformers(ctx, kubeClient, &wg, evtc, fetchDone, opts, resourceTypes)

	return evtc, fetchDone, nil
}

func startWatchdog(parentCtx context.Context, cancel context.CancelFunc, kubeClient kubeclient.Interface) error {
	log.Debug("Starting K8s watchdog")

	client := kubeClient.CoreV1().RESTClient()
	// We don't care about what we watch, so limit to a single namespace
	fSelector, _ := fields.ParseSelector("metadata.name=default")
	lw := cache.NewListWatchFromClient(client, "namespaces", v1meta.NamespaceAll, fSelector)
	watcher, err := lw.Watch(v1meta.ListOptions{})
	if err != nil {
		fullErrString := err.Error()
		// Watch errors report "unknown" in some cases where the list
		// error is more descriptive, so check if there's a list error
		// XXX this may be fixed by upgrading client-go
		if strings.HasPrefix(fullErrString, "unknown") {
			_, listErr := lw.List(v1meta.ListOptions{})
			if listErr != nil {
				fullErrString += ", additional details: " + listErr.Error()
			}
		}

		log.Errorf("K8s watchdog, error creating api server watchdog: %v", fullErrString)
		cancel()
		return err
	}
	// defer watcher.Stop() from the new goroutine

	go func() {
		log.Debug("Creating K8s watchdog thread")

		// cancel() unless we timeout and successfully create a new watchdog
		doCancel := true
		defer func() {
			log.Debug("K8s watchdog thread exiting")
			watcher.Stop()
			if doCancel {
				cancel()
			}
		}()

		for {
			select {
			case event, ok := <-watcher.ResultChan():
				if !ok {
					// The API server can timeout the watch during normal,
					// operation, so launch a new watchdog connection
					log.Debug("K8s watchdog received a watch timeout, restarting")
					err := startWatchdog(parentCtx, cancel, kubeClient)
					if err == nil {
						doCancel = false
					}
					return
				}
				if event.Type == watch.Error {
					log.Errorf("K8s watchdog received watch error: %v",
						apierrs.FromObject(event.Object))
					return
				}
			case <-parentCtx.Done():
				log.Info("K8s watchdog, parent context cancelled")
				return
			}
		}
	}()

	return nil
}

func startInformers(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent, fetchDone chan<- struct{}, opts *sdc_internal.OrchestratorEventsStreamCommand, resourceTypes []string) {
	filterEmpty := opts.GetFilterEmpty()

	for _, resource := range resourceTypes {

		interrupted := false
		select {
		case <-ctx.Done():
			interrupted = true
		default:
		}
		if interrupted {
			log.Warn("K8s informer startup interrupted by cancelled context")
			break
		}

		log.Debugf("Checking kubecollect support for %v", resource)

		// The informers are responsible for Add()'ing to the wg
		infStarted := true
		switch resource {
		case "cronjobs":
			startCronJobsSInformer(ctx, kubeClient, wg, evtc)
		case "daemonsets":
			startDaemonSetsSInformer(ctx, kubeClient, wg, evtc)
		case "deployments":
			startDeploymentsSInformer(ctx, kubeClient, wg, evtc)
		case "horizontalpodautoscalers":
			startHorizontalPodAutoscalersSInformer(ctx, kubeClient, wg, evtc)
		case "ingress":
			startIngressSInformer(ctx, kubeClient, wg, evtc)
		case "jobs":
			startJobsSInformer(ctx, kubeClient, wg, evtc)
		case "namespaces":
			startNamespacesSInformer(ctx, kubeClient, wg, evtc)
		case "nodes":
			startNodesSInformer(ctx, kubeClient, wg, evtc)
		case "pods":
			startPodsSInformer(ctx, kubeClient, wg, evtc)
		case "replicasets":
			startReplicaSetsSInformer(ctx, kubeClient, wg, evtc, filterEmpty)
		case "replicationcontrollers":
			startReplicationControllersSInformer(ctx, kubeClient, wg, evtc, filterEmpty)
		case "resourcequotas":
			startResourceQuotasSInformer(ctx, kubeClient, wg, evtc)
		case "services":
			startServicesSInformer(ctx, kubeClient, wg, evtc)
		case "statefulsets":
			startStatefulSetsSInformer(ctx, kubeClient, wg, evtc)
		default:
			log.Debugf("No kubecollect support for %v", resource)
			infStarted = false
		}

		if infStarted {
			// assume it's still startup if len(evtc) > threshold
			totalWaitTime := time.Duration(opts.GetStartupInfWaitTimeS()) * time.Second
			tickInterval := time.Duration(opts.GetStartupTickIntervalMs()) * time.Millisecond
			lowTicksNeeded := int(opts.GetStartupLowTicksNeeded())
			evtcThreshold := int(opts.GetStartupLowEvtThreshold())
			ticksBelowThreshold := 0

			ticker := time.NewTicker(tickInterval)
			defer ticker.Stop()
			tickerStart := time.Now()
			for {
				var lastTick time.Time
				evtcLen := 0
				select {
				case lastTick = <-ticker.C:
					evtcLen = len(evtc)
				}

				// XXX should use resourceReady()
				if receivedEvent(resource) && evtcLen <= evtcThreshold {
					ticksBelowThreshold++
				} else {
					ticksBelowThreshold = 0
				}
				log.Tracef("Got a tick, evtcLen: %v, ticksBelowThreshold: %v",
					evtcLen, ticksBelowThreshold)

				if ticksBelowThreshold >= lowTicksNeeded {
					break
				}

				if lastTick.Sub(tickerStart) >= totalWaitTime {
					if receivedEvent(resource) {
						log.Warnf("High activity during initial fetch of %v objects",
							resource)
					}
					break
				}
			}

			log.Infof("Started %v informer", resource)
			log.Debug("Calling debug.FreeOSMemory()")
			debug.FreeOSMemory()

			startedMutex.Lock()
			startedMap[resource] = true
			startedMutex.Unlock()
		}
	}

	close(fetchDone)

	// In a separate goroutine, wait for the informers and
	// close evtc once they're done to notify the caller
	go func() {
		wg.Wait()
		log.Info("All K8s informers have exited, closing the events channel")
		close(evtc)
	}()
}

func eventReceived(resource string) {
	receiveMutex.Lock()
	receiveMap[resource] = true
	receiveMutex.Unlock()
}

func receivedEvent(resource string) bool {
	receiveMutex.RLock()
	ret := receiveMap[resource]
	receiveMutex.RUnlock()
	return ret
}

func resourceReady(resource string) bool {
	startedMutex.RLock()
	ret := startedMap[resource]
	startedMutex.RUnlock()
	return ret

/*
	switch resource {
	case "cronjobs":
		return cronJobInf != nil && cronJobInf.HasSynced()
	case "daemonsets":
		return daemonSetInf != nil && daemonSetInf.HasSynced()
	case "deployments":
		return deploymentInf != nil && deploymentInf.HasSynced()
	case "ingress":
		return ingressInf != nil && ingressInf.HasSynced()
	case "jobs":
		return jobInf != nil && jobInf.HasSynced()
	case "namespaces":
		return namespaceInf != nil && namespaceInf.HasSynced()
	case "nodes":
		return nodeInf != nil && nodeInf.HasSynced()
	case "pods":
		return podInf != nil && podInf.HasSynced()
	case "replicasets":
		return replicaSetInf != nil && replicaSetInf.HasSynced()
	case "replicationcontrollers":
		return replicationControllerInf != nil && replicationControllerInf.HasSynced()
	case "resourcequotas":
		return resourceQuotaInf != nil && resourceQuotaInf.HasSynced()
	case "services":
		return serviceInf != nil && serviceInf.HasSynced()
	case "statefulsets":
		return statefulSetInf != nil && statefulSetInf.HasSynced()
	default:
		return false
	}
*/
}

func createKubeClient(apiServer string, caCert string, clientCert string, clientKey string, sslVerify bool, authToken string) (kubeClient kubeclient.Interface, err error) {
	skipVerify := !sslVerify
	if skipVerify {
		caCert = ""
	}
	tokenStr := ""
	if authToken != "" {
		tokenBytes, err := ioutil.ReadFile(authToken)
		if err != nil {
			log.Warnf("Unable to read bearer token from %v", authToken)
		} else {
			tokenStr = string(tokenBytes[:])
			// Trailing newlines cause the api server to reject the token
			tokenStr = strings.TrimRight(tokenStr, "\n")
			if tokenStr == "" {
				log.Warn("No token found in bearer token file")
			}
		}
	}

	baseConfig := clientcmdapi.NewConfig()
	configOverrides := &clientcmd.ConfigOverrides{
		ClusterInfo: clientcmdapi.Cluster{
			Server: apiServer,
			InsecureSkipTLSVerify: skipVerify,
			CertificateAuthority: caCert,
		},
		AuthInfo: clientcmdapi.AuthInfo{
			ClientCertificate: clientCert,
			ClientKey: clientKey,
			Token: tokenStr,
		},
	}
	kubeConfig := clientcmd.NewDefaultClientConfig(*baseConfig, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Errorf("kubecollect can't create config")
		return nil, err
	}

	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Errorf("kubecollect NewForConfig fails")
		return nil, err
	}

	return kubeClient, nil
}

func createInClusterKubeClient() (kubeClient kubeclient.Interface, err error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("Cannot create InCluster config: %s", err)
		return nil, err
	}
	log.Debugf("InCluster k8s server: %s", config.Host);
	// creates the clientset
	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Errorf("Cannot create client using cluster config, server %s: %s",
				   config.Host, err)
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
	if !prometheusEnabled {
		return nil
	}
	tags := make(map[string]string)
	for k, v := range obj.GetAnnotations() {
		if strings.Contains(k, "prometheus") {
			tags[prefix+"annotation." + k] = v
		}
	}
	if len(tags) == 0 {
		return nil
	}
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
	if !prometheusEnabled {
		return true
	}

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

func equalResourceList(lhs v1.ResourceList, rhs v1.ResourceList) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for k, lhsVal := range lhs {
		rhsVal, ok := rhs[k]
		if !ok || rhsVal.Cmp(lhsVal) != 0 {
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
