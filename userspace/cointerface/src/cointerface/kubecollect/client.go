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
	"cointerface/profile"
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

const (
	EVENT_ADD = iota
	EVENT_UPDATE = iota
	EVENT_UPDATE_AND_SEND = iota
	EVENT_DELETE = iota
)

// stores which informers have been allocated, so at least we don't segfault
// does not imply we've successfully registered with the API server
var startedMap map[string]bool
var startedMutex sync.RWMutex

var receiveMap map[string]bool
var receiveMutex sync.RWMutex
var annotFilter map[string]bool

var eventCountsLogTime uint32
var eventMapAdd map[string]int
var emAddMutex sync.RWMutex
var eventMapUpd map[string]int
var emUpdMutex sync.RWMutex
var eventMapUpds map[string]int
var emUpdsMutex sync.RWMutex
var eventMapDel map[string]int
var emDelMutex sync.RWMutex

const (
	ChannelTypeInformer = iota
	ChannelTypeUserEvent = iota
)

// Given that we depend on global contexts, we need a hard guarantee that we won't have
// two users trying to attach to channels at the same time. Further, we need to ensure
// that we're not trying to attach to both channels at the same time (informer must happen
// before user). These things enable that.
var ChannelMutex sync.Mutex

// Represents both whether the informer is attached, and equivalently, whether the user
// event channel exists
var InformerChannelInUse = false

// Represents whether the user event channel is attached
var UserEventChannelInUse = false

// Represents whether the dummy user event channel is in use
// this must be separate from the above because of the multiple ways the dummy can exit...
// graceful or not
var DummyEventChannelActive = false

var InformerChannel chan draiosproto.CongroupUpdateEvent
var UserEventChannel chan sdc_internal.K8SUserEvent

func addEvent(restype string, evtype int) {
	profile.NewEvent()
	if (eventCountsLogTime < 1) {
		return
	}
	if (evtype == EVENT_ADD) {
		emAddMutex.Lock()
		eventMapAdd[restype] = eventMapAdd[restype] + 1
		emAddMutex.Unlock()
	} else if (evtype == EVENT_UPDATE) {
		emUpdMutex.Lock()
		eventMapUpd[restype] = eventMapUpd[restype] + 1
		emUpdMutex.Unlock()
	} else if (evtype == EVENT_UPDATE_AND_SEND) {
		emUpdsMutex.Lock()
		eventMapUpds[restype] = eventMapUpds[restype] + 1
		emUpdsMutex.Unlock()
	} else if (evtype == EVENT_DELETE) {
		emDelMutex.Lock()
		eventMapDel[restype] = eventMapDel[restype] + 1
		emDelMutex.Unlock()
	} else {
		log.Warnf("addEvent, unknown event type %d", evtype)
	}
}

func logEvents() {
	if (eventCountsLogTime < 1) {
		return
	}

	emAddMutex.RLock()
	emUpdMutex.RLock()
	emUpdsMutex.RLock()
	emDelMutex.RLock()

	for k := range eventMapAdd {
		log.Infof("%s Events: %d adds, %d updates, %d updates sent, %d deletes",
			  k,
			  eventMapAdd[k],
			  eventMapUpd[k],
			  eventMapUpds[k],
			  eventMapDel[k])
	}

	emDelMutex.RUnlock()
	emUpdsMutex.RUnlock()
	emUpdMutex.RUnlock()
	emAddMutex.RUnlock()
}

const RsyncInterval = 10 * time.Minute

func in_array(s string, arr []string) bool {
	for _, a := range arr {
		if s == a {
			return true
		}
	}
	return false
}

func getResourceTypes(resources []*v1meta.APIResourceList, includeTypes []string) ([]string) {

	// Return a vector of all resourceType names
	var resourceTypes []string
	resourceMap := make(map[string]bool)

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
			// Exclude services, resourcequotas and hpas unless explicitly requested
			// We'll probably want to change this
			if (resource.Name == "services" || resource.Name == "resourcequotas" || resource.Name == "horizontalpodautoscalers") && !in_array(resource.Name, includeTypes) {
				log.Debugf("K8s: Exclude resourcetype %s", resource.Name)
				continue
			}

			if(!resourceMap[resource.Name]) {
				// This resource hasn't been added. Added it now
				resourceMap[resource.Name] = true

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
	}

	return resourceTypes
}

// The input context is passed to all goroutines created by this function.
// The caller is responsible for draining messages from the returned channel
// until the channel is closed, otherwise the component goroutines may block.
// The empty struct chan notifies the caller that the initial event fetch
// is complete by closing the chan.
func WatchCluster(parentCtx context.Context,
		  opts *sdc_internal.OrchestratorEventsStreamCommand) (<-chan struct{}, error) {
	setErrorLogHandler()

	// TODO: refactor error messages
	var kubeClient kubeclient.Interface

	if opts.GetUrl() != "" {
		log.Infof("Connecting to k8s server at %s", opts.GetUrl())
		var err error
		kubeClient, err = createKubeClient(opts.GetUrl(),
						   opts.GetCaCert(),
						   opts.GetClientCert(),
						   opts.GetClientKey(),
						   opts.GetSslVerifyCertificate(),
						   opts.GetAuthToken())
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

	// These get reset when either events or listeners channel is reset
	startedMap = make(map[string]bool)
	receiveMap = make(map[string]bool)
	setAnnotFilt( opts.AnnotationFilter)

	eventMapAdd = make(map[string]int)
	eventMapUpd = make(map[string]int)
	eventMapUpds = make(map[string]int)
	eventMapDel = make(map[string]int)
	eventCountsLogTime = opts.GetEventCountsLogTime()
	log.Infof("Event Counts log time: %d s", eventCountsLogTime)


	// Get a vector of all resource types
	// from the resourceList in resources.
	resourceTypes := getResourceTypes(resources, opts.IncludeTypes)

	// if dragent asks for events, we spin up the channel here, and then they can attach to it later
	if (opts.GetCollectEvents()) {
		resourceTypes = append(resourceTypes, "events")
	}

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
		return nil, err
	}

	InformerChannel = make(chan draiosproto.CongroupUpdateEvent,
			       opts.GetQueueLen())

	// create even if we don't use it just to make tear-down logic easier
        UserEventChannel = make(chan sdc_internal.K8SUserEvent, opts.GetUserEventQueueLen())


	fetchDone := make(chan struct{})
	var wg sync.WaitGroup
	// Start informers in a separate routine so we can return the
	// evt chan and let the caller start reading/draining events
	go startInformers(ctx, kubeClient, &wg, fetchDone, opts, resourceTypes)

	if (eventCountsLogTime > 0) {
		go func() {
			for {
				time.Sleep(time.Duration(eventCountsLogTime) * time.Second)
				logEvents()
			}
		}()
	}

	return fetchDone, nil
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

func startInformers(ctx context.Context,
		    kubeClient kubeclient.Interface,
		    wg *sync.WaitGroup,
		    fetchDone chan<- struct{},
		    opts *sdc_internal.OrchestratorEventsStreamCommand,
		    resourceTypes []string) {
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
		channelType := ChannelTypeInformer
		switch resource {
		case "cronjobs":
			startCronJobsSInformer(ctx, kubeClient, wg, InformerChannel)
		case "daemonsets":
			startDaemonSetsSInformer(ctx, kubeClient, wg, InformerChannel)
		case "deployments":
			startDeploymentsSInformer(ctx, kubeClient, wg, InformerChannel)
		case "horizontalpodautoscalers":
			startHorizontalPodAutoscalersSInformer(ctx, kubeClient, wg, InformerChannel)
		case "ingress":
			startIngressSInformer(ctx, kubeClient, wg, InformerChannel)
		case "jobs":
			startJobsSInformer(ctx, kubeClient, wg, InformerChannel)
		case "namespaces":
			startNamespacesSInformer(ctx, kubeClient, wg, InformerChannel)
		case "nodes":
			startNodesSInformer(ctx, kubeClient, wg, InformerChannel)
		case "pods":
			startPodsSInformer(ctx, kubeClient, wg, InformerChannel)
		case "replicasets":
			startReplicaSetsSInformer(ctx, kubeClient, wg, InformerChannel, filterEmpty)
		case "replicationcontrollers":
			startReplicationControllersSInformer(ctx, kubeClient, wg, InformerChannel, filterEmpty)
		case "services":
			startServicesSInformer(ctx, kubeClient, wg, InformerChannel)
		case "statefulsets":
			startStatefulSetsSInformer(ctx, kubeClient, wg, InformerChannel)
		case "resourcequotas":
			startResourceQuotasSInformer(ctx, kubeClient, wg, InformerChannel)
		case "events":
			startUserEventsSInformer(ctx, kubeClient, wg, UserEventChannel)
			channelType = ChannelTypeUserEvent
		default:
			log.Debugf("No kubecollect support for %v", resource)
			infStarted = false
		}

		if infStarted {
			// assume it's still startup if len(channel) > threshold
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
					if (channelType == ChannelTypeInformer) {
						evtcLen = len(InformerChannel)
					} else {
						evtcLen = len(UserEventChannel)
					}
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

		// don't THINK we need to flush channels here...assume go does this
		// when we close

		InformerChannelInUse = false
		close(InformerChannel)
		close(UserEventChannel)
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

// This needs to be called before any informers are started as the map is
// not thread-safe for mixing reads & writes.
func setAnnotFilt(annots []string) {
	if len(startedMap) != 0 {
		log.Error("Writing to annotation filter map after multi-threading start")
	}
	annotFilter = make(map[string]bool)
	for _, v := range annots {
		annotFilter[v] = true
	}
}

func GetAnnotations(obj v1meta.ObjectMeta, prefix string) map[string]string {
	if len(annotFilter) == 0 {
		return nil
	}
	tags := make(map[string]string)
	for k, v := range obj.GetAnnotations() {
		// Only get selected annotations
		annot := prefix + "annotation." + k
		if annotFilter[annot] {
			tags[annot] = v
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
	if len(annotFilter) == 0 {
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

func appendRateMetric(metrics *[]*draiosproto.AppMetric, name string, val float64) {
	*metrics = append(*metrics, &draiosproto.AppMetric{
		Name:proto.String(name),
		Type:draiosproto.AppMetricType_APP_METRIC_TYPE_RATE.Enum(),
		Value:proto.Float64(val),
	})
}

func AppendMetricInt64(metrics *[]*draiosproto.AppMetric, name string, val int64) {
	AppendMetric(metrics, name, float64(val))
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
