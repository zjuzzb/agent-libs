package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"k8s.io/client-go/tools/cache"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"

	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	kubeclient "k8s.io/client-go/kubernetes"
)

func startWatcherAndInformers(
	ctx context.Context,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
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
			kubecollect.StartCronJobsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "daemonsets":
			startDaemonSetsWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "deployments":
			startDeploymentsWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "endpoints":
			kubecollect_common.StartEndpointsWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "horizontalpodautoscalers":
			startHPAWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "ingress":
			kubecollect.StartIngressSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "jobs":
			startJobsWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "namespaces":
			kubecollect.StartNamespacesSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "nodes":
			startNodesSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "pods":
			startPodWatcher(ctx, opts, kubeClient, wg, kubecollect_common.InformerChannel)
		case "replicasets":
			startReplicaSetWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel, filterEmpty)
		case "replicationcontrollers":
			startReplicationControllerWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel, filterEmpty)
		case "services":
			startServicesWatcher(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "statefulsets":
			startStatefulSetsSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "resourcequotas":
			kubecollect.StartResourceQuotasSInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "persistentvolumes":
			kubecollect.StartPersistentVolumesInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "persistentvolumeclaims":
			kubecollect.StartPersistentVolumeClaimsInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
		case "podstatuscounter":
			kubecollect.StartPodStatusWatcher(ctx, opts, kubeClient, wg, kubecollect_common.InformerChannel)
		case "storageclasses":
			kubecollect.StartStorageClassInformer(ctx, kubeClient, wg, kubecollect_common.InformerChannel)
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
				evtcLen := 0
				lastTick := <-ticker.C
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

type KubecollectClientTc struct{}

func (c KubecollectClientTc) StartInformers(
	ctx context.Context,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
	opts *sdc_internal.OrchestratorEventsStreamCommand,
	resourceTypes []string,
	queueLength *uint32) {
	startWatcherAndInformers(ctx, kubeClient, wg, opts, resourceTypes, queueLength)
}

func (c KubecollectClientTc) CreateHasSyncedFuncs()[]cache.InformerSynced {
	return []cache.InformerSynced {
		func() bool {
			return true
		},
	}
}
