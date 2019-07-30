package kubecollect

import (
	"golang.org/x/net/context"
	"io/ioutil"
	"reflect"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"math/rand"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"cointerface/draiosproto"
	"cointerface/profile"
	"cointerface/sdc_internal"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
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
// before user). These things enable that. Note the informer-before-user is implicit since
// the user channel will return an error if you try to listen to it without having
// created it yet.
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
			// Exclude services, rqs, hpas, pvs and pvcs unless explicitly requested
			// We'll probably want to change this
			// Note that PVCs may depend on PVs
			if (resource.Name == "services" ||
				resource.Name == "resourcequotas" ||
				resource.Name == "horizontalpodautoscalers" ||
				resource.Name == "persistentvolumes" ||
				resource.Name == "persistentvolumeclaims") &&
				!in_array(resource.Name, includeTypes) {

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

// Generic function used to drain any receive chan( <-chan)
// This method ensures that by fully draining the chan,
// we help unblock any other routines/methods that are blocked
// on sending on these chans. This is called during cleanup
func DrainChan(in interface{}) {
	log.Debugf("[DrainChan]: Entering drain chan loop")
	
	cin := reflect.ValueOf(in)
	if cin.Kind() != reflect.Chan {
		log.Warnf("[DrainChan]: can't drain a : %v", cin.Kind())
		return
	}
	if (cin.Type()).ChanDir() != reflect.RecvDir {
		log.Warnf("[DrainChan]: can't drain a chan other than RecvDir Chan: %v",(cin.Type()).ChanDir().String())
		return
	}

	for {
		x, ok := cin.Recv()
		if !ok {
			log.Debugf("[DrainChan]: end of draining chan")
			return
		}
		log.Debugf("[DrainChan]: draining : %v", x)
	}
}

// The input context is passed to all goroutines created by this function.
// The caller is responsible for draining messages from the returned channel
// until the channel is closed, otherwise the component goroutines may block.
// The empty struct chan notifies the caller that the initial event fetch
// is complete by closing the chan.
func WatchCluster(parentCtx context.Context, opts *sdc_internal.OrchestratorEventsStreamCommand) (<-chan sdc_internal.ArrayCongroupUpdateEvent, <-chan struct{}, error) {
	setErrorLogHandler()

	// TODO: refactor error messages
	var kubeClient kubeclient.Interface

	if opts.GetMaxRndConnDelay() != 0 {
		rand.Seed(time.Now().UnixNano())
		delay := rand.Uint32() % opts.GetMaxRndConnDelay()
		log.Infof("Waiting to connect to k8s server for %d seconds", delay)
		time.Sleep(time.Duration(delay) * time.Second)
	}

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
			InformerChannelInUse = false
			log.Errorf("Cannot create k8s client: %s", err)
			return nil, nil, err
		}
	} else {
		log.Infof("Connecting to k8s server using inCluster config")
		var err error
		kubeClient, err = createInClusterKubeClient()
		if err != nil {
			InformerChannelInUse = false
			log.Errorf("Cannot create k8s client: %s", err)
			return nil, nil, err
		}
	}
	log.Infof("Testing communication with server")
	srvVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		InformerChannelInUse = false
		log.Errorf("K8s server not responding: %s", err)
		return nil, nil, err
	}
	log.Infof("Communication with server successful: %v", srvVersion)

	resources, err := kubeClient.Discovery().ServerResources()
	if err != nil {
		InformerChannelInUse = false
		log.Errorf("K8s server returned error: %s", err)
		return nil, nil, err
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

	// Make a channel that takes in an Array of CongroupUpdateEvents
	// Make it of capacity 1. At any given instance we should send
	// only 1 event on it. This happens in batchEvents
	// What this ensures is that the calculation for length of how
	// many events in the queue becomes trivial in startInformers
	// Else we will be forced to perform a deep len calculation. 
	evtArrayChan := make(chan sdc_internal.ArrayCongroupUpdateEvent, 1)

	// Batch cointerface messages options
	// Get the config values for batching cointerface msgs and sanity check the values.
	batchMsgsQueueLen := opts.GetBatchMsgsQueueLen()
	if(batchMsgsQueueLen <= 0) {
		log.Warnf("A value less than 1 entered for the orch_batch_msgs_queue_len configuration property. Setting the value to 1.")
		batchMsgsQueueLen = 1
	}
	batchMsgsTickMs := opts.GetBatchMsgsTickIntervalMs()
	if(batchMsgsTickMs <= 0) {
		log.Warnf("A value less than 1 entered for the orch_batch_msgs_tick_interval configuration property. Setting the value to 1.")
		batchMsgsTickMs = 1
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
		InformerChannelInUse = false
		// startWatchdog() may later hit an async error,
		// so it's responsible for all error logging
		return nil, nil, err
	}

	InformerChannel = make(chan draiosproto.CongroupUpdateEvent,
			       opts.GetQueueLen())

	// create even if we don't use it just to make tear-down logic easier
        UserEventChannel = make(chan sdc_internal.K8SUserEvent, opts.GetUserEventQueueLen())


	fetchDone := make(chan struct{})
	var wg sync.WaitGroup

	// A var that will be accessed atomically in both
	// batchEvents and startInformers. This var will hold
	// the length of the sdcEvtArray at any given time.
	queueLength := uint32(0)

	// Start informers in a separate routine so we can return the
	// evt chan and let the below goroutine start reading/draining events
	go startInformers(ctx, kubeClient, &wg, fetchDone, opts, resourceTypes, &queueLength)

	// as soon as we start the go routine to start informers;
	// we need to kick off the routine to start reading events
	// from Informerchannel and then batching them into an array and sending
	// that array on the evtArrayChan
	go batchEvents(ctx, evtArrayChan, batchMsgsQueueLen, batchMsgsTickMs, &queueLength)

	if (eventCountsLogTime > 0) {
		go func() {
			for {
				time.Sleep(time.Duration(eventCountsLogTime) * time.Second)
				logEvents()
			}
		}()
	}

	return evtArrayChan, fetchDone, nil
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

// Go routine that is responsible for reading events off the Informer channel
// and batching them into an array of CongroupUpdateEvents. Then send this
// array on the evtArrayChan.
// Perform this periodically (based on a timer) or if the array is full.
func batchEvents(
	ctx context.Context,
	evtArrayChan chan<- sdc_internal.ArrayCongroupUpdateEvent,
	batchMsgsQueueLen uint32,
	batchMsgsTickMs uint32,
	queueLength *uint32) {

	// Periodic timer to drain the events
	msTickTimer := time.NewTicker(time.Duration(batchMsgsTickMs) * time.Millisecond)
	defer msTickTimer.Stop()

	// before reading defer a function to completely
	// drain Informer channel to unblock informers
	// Also close the evtArrayChan
	defer func() {
		// Drain the Informer channel fully
		DrainChan(InformerChannel)

		// Close the evtArrayChan
		close(evtArrayChan)
	}()

	sdcEvtArray := sdc_internal.ArrayCongroupUpdateEvent{
		Events: make([]*draiosproto.CongroupUpdateEvent, 0, batchMsgsQueueLen)}

	for {
		timerTick := false
		select {
		case evt, ok := <-InformerChannel:
			if !ok {
				log.Debugf("[PerformOrchestratorEventsStream] event stream is closed")
				return
			}

			// append incoming evt to the sdcEvtArray's Event field
			sdcEvtArray.Events = append(sdcEvtArray.Events, &evt)
		case <-msTickTimer.C:
			// We drain the event queue every batchMsgsTickMs milliseconds
			// This prevents msgs that are old to wait around
			// forever if we don't fill the event queue
			// Here we just set a boolean flag to let the flush code (at the
			// end of the select know that we are flushing due to timer)
			// 
			timerTick = true
		case <-ctx.Done():
			log.Debugf("[PerformOrchestratorEventsStream] context cancelled")
			return
		}

		// We need to flush in 1 of 2 cases:
		// 1.) Either we reached full capacity of the queue
		// 2.) Or timer tick went off 
		if((len(sdcEvtArray.Events) >= int(batchMsgsQueueLen)) ||
			(timerTick && (len(sdcEvtArray.Events) > 0))) {
			evtArrayChan <- sdcEvtArray
			// Now reset this sdcEvtArray before reuse
			sdcEvtArray = sdc_internal.ArrayCongroupUpdateEvent{
				Events: make([]*draiosproto.CongroupUpdateEvent, 0, batchMsgsQueueLen)}

			// Reset timerTick to false always
			timerTick = false
		}
		// Write out the length before leaving this current select cycle
		atomic.StoreUint32(queueLength, uint32(len(sdcEvtArray.Events)))
	}
}

func startInformers(
	ctx context.Context,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
	fetchDone chan<- struct{},
	opts *sdc_internal.OrchestratorEventsStreamCommand,
	resourceTypes []string,
	queueLength *uint32) {

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
			startUserEventsSInformer(ctx,
						 kubeClient,
						 wg,
						 UserEventChannel,
						 opts.GetCollectDebugEvents())
			channelType = ChannelTypeUserEvent
		case "persistentvolumes":
			startPersistentVolumesInformer(ctx, kubeClient, wg, InformerChannel)
		case "persistentvolumeclaims":
			startPersistentVolumeClaimsInformer(ctx, kubeClient, wg, InformerChannel)
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
						// Number of events is length of Informer channel
						// plus length of events in SdcEvtArray
						lenQueue := int(atomic.LoadUint32(queueLength))
						evtcLen = len(InformerChannel) + lenQueue
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
	// close Informer channel once they're done to notify the caller
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
