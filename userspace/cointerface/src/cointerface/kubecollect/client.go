package kubecollect

import (
	"cointerface/kubecollect_common"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/draios/protorepo/sdc_internal"
	"golang.org/x/net/context"
	kubeclient "k8s.io/client-go/kubernetes"

	log "github.com/cihub/seelog"
)

func startInformers(
	ctx context.Context,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
	fetchDone chan<- struct{},
	opts *sdc_internal.OrchestratorEventsStreamCommand,
	resourceTypes []string,
	queueLength *uint32) {

	filterEmpty := opts.GetFilterEmpty()

	interrupted := false
	for _, resource := range resourceTypes {
		select {
		case <-ctx.Done():
			interrupted = true
		default:
		}
		if interrupted {
			_ = log.Warn("K8s informer startup interrupted by cancelled context")
			break
		}

		log.Debugf("Checking kubecollect support for %v", resource)
		// The informers are responsible for Add()'ing to the wg
		infStarted := true
		channelType := kubecollect_common.ChannelTypeInformer
		switch resource {
		case "cronjobs":
			StartCronJobsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "daemonsets":
			startDaemonSetsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "deployments":
			startDeploymentsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "endpoints":
			kubecollect_common.StartEndpointsWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "horizontalpodautoscalers":
			startHorizontalPodAutoscalersSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "ingress":
			StartIngressSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "jobs":
			startJobsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "namespaces":
			StartNamespacesSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "nodes":
			startNodesSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "networkpolicies": // placed before pods to register as a delegate
			StartNetworkPoliciesSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "pods":
			startPodsSInformer(ctx, opts, kubeClient, wg, kubecollect_common.InformerChannel)
		case "replicasets":
			startReplicaSetsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel, filterEmpty)
		case "replicationcontrollers":
			startReplicationControllersSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel, filterEmpty)
		case "services":
			startServicesSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "statefulsets":
			startStatefulSetsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "resourcequotas":
			StartResourceQuotasSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "persistentvolumes":
			StartPersistentVolumesInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "persistentvolumeclaims":
			StartPersistentVolumeClaimsInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "podstatuscounter":
			StartPodStatusWatcher(ctx, opts, kubeClient, wg, kubecollect_common.InformerChannel)
		case "storageclasses":
			StartStorageClassInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
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
				lastTick = <-ticker.C
				if channelType == kubecollect_common.ChannelTypeInformer {
					// Number of events is length of Informer channel
					// plus length of events in SdcEvtArray
					lenQueue := int(atomic.LoadUint32(queueLength))
					evtcLen = len(kubecollect_common.InformerChannel) + lenQueue
				}

				// XXX should use resourceReady()
				if kubecollect_common.ReceivedEvent(resource) && evtcLen <= evtcThreshold {
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
					if kubecollect_common.ReceivedEvent(resource) {
						_ = log.Warnf("High activity during initial fetch of %v objects",
							resource)
					}
					break
				}
			}

			log.Infof("Started %v informer", resource)
			log.Debug("Calling debug.FreeOSMemory()")
			debug.FreeOSMemory()

			kubecollect_common.StartedMutex.Lock()
			kubecollect_common.StartedMap[resource] = true
			kubecollect_common.StartedMutex.Unlock()
		}
	}

	if !interrupted {
		fetchDone <- struct{}{}
	} else {
		// Inititial fetch has been aborted.
		// Notify it by closing the channel
		close(fetchDone)
	}

	// In a separate goroutine, wait for the informers and
	// close Informer channel once they're done to notify the caller
	go func() {
		wg.Wait()
		log.Info("All K8s informers have exited, closing the events channel")

		// don't THINK we need to flush channels here...assume go does this
		// when we close

		kubecollect_common.InformerChannelInUse = false
		close(kubecollect_common.InformerChannel)
	}()
}

type KubecollectClient struct{}

func (c KubecollectClient) StartInformers(
	ctx context.Context,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
	fetchDone chan<- struct{},
	opts *sdc_internal.OrchestratorEventsStreamCommand,
	resourceTypes []string,
	queueLength *uint32) {
	startInformers(ctx, kubeClient, wg, fetchDone, opts, resourceTypes, queueLength)
}
