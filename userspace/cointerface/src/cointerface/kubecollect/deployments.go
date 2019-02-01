package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	"reflect"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
)

// Globals are reset in startDeploymentsSInformer
var deploymentInf cache.SharedInformer
var deploySelectors map[string]labels.Selector
var deployCacheMutex sync.RWMutex

func deploymentEvent(dep *v1beta1.Deployment, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDeploymentCongroup(dep, setLinks),
	}
}

// sameEntity will always be false when sameLinks is false
func deploymentEquals(lhs *v1beta1.Deployment, rhs *v1beta1.Deployment) (sameEntity bool, sameLinks bool) {
	// Check sameLinks fields first
	if lhs.GetNamespace() != rhs.GetNamespace() {
		return false, false
	}
	if !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		return false, false
	}
	// This is the last sameLinks check because it sometimes
	// returns sameLinks == true unlike the above checks
	if lhs.Status.Replicas != rhs.Status.Replicas {
		if (lhs.Status.Replicas == 0) || (rhs.Status.Replicas == 0) {
			return false, false
		} else {
			return false, true
		}
	}

	// Now check sameEntity, sameLinks is always true from here out
	if lhs.GetName() != rhs.GetName() {
		return false, true
	}
	if !reflect.DeepEqual(lhs.Spec.Replicas, rhs.Spec.Replicas) ||
		lhs.Spec.Paused != rhs.Spec.Paused ||
		lhs.Status.AvailableReplicas != rhs.Status.AvailableReplicas ||
		lhs.Status.UnavailableReplicas != rhs.Status.UnavailableReplicas ||
		lhs.Status.UpdatedReplicas != rhs.Status.UpdatedReplicas {
		return false, true
	}
	if !EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta) ||
		!EqualAnnotations(lhs.ObjectMeta, rhs.ObjectMeta) {
		return false, true
	}

	return true, true
}

func newDeploymentCongroup(deployment *v1beta1.Deployment, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_deployment"),
			Id:proto.String(string(deployment.GetUID()))},
	}

	ret.Tags = GetTags(deployment.ObjectMeta, "kubernetes.deployment.")
	ret.InternalTags = GetAnnotations(deployment.ObjectMeta, "kubernetes.deployment.")
	addDeploymentMetrics(&ret.Metrics, deployment)
	if setLinks {
		AddNSParents(&ret.Parents, deployment.GetNamespace())
		selector, ok := getDeployChildSelector(deployment)
		if ok {
			AddReplicaSetChildren(&ret.Children, selector, deployment.GetNamespace())
		}
		AddHorizontalPodAutoscalerParents(&ret.Parents, deployment.GetNamespace(), deployment.APIVersion, deployment.Kind, deployment.GetName() )
	}
	return ret
}

func addDeploymentMetrics(metrics *[]*draiosproto.AppMetric, deployment *v1beta1.Deployment) {
	prefix := "kubernetes.deployment."
	AppendMetricInt32(metrics, prefix+"status.replicas", deployment.Status.Replicas)
	// kube-state-metrics uses "kube_deployment_status_replicas_available" but
	// we use availableReplicas instead of replicasAvailable because it matches
	// the name in DeploymentStatus and other resources like ReplicationControllers
	AppendMetricInt32(metrics, prefix+"status.availableReplicas", deployment.Status.AvailableReplicas)
	AppendMetricInt32(metrics, prefix+"status.unavailableReplicas", deployment.Status.UnavailableReplicas)
	AppendMetricInt32(metrics, prefix+"status.updatedReplicas", deployment.Status.UpdatedReplicas)
	AppendMetricPtrInt32(metrics, prefix+"spec.replicas", deployment.Spec.Replicas)
	AppendMetricBool(metrics, prefix+"spec.paused", deployment.Spec.Paused)
	//if deployment.Spec.Strategy.RollingUpdate != nil {
	//	metrics[prefix + "spec.strategy.rollingupdate.max.unavailable"] = uint32(deployment.Spec.Strategy.RollingUpdate.MaxUnavailable)
	//}
}

func AddDeploymentParents(parents *[]*draiosproto.CongroupUid, replicaSet *v1beta1.ReplicaSet) {
	if !resourceReady("deployments") {
		return
	}

	rsLabels := labels.Set(replicaSet.GetLabels())
	for _, obj := range deploymentInf.GetStore().List() {
		deployment := obj.(*v1beta1.Deployment)
		if replicaSet.GetNamespace() != deployment.GetNamespace() {
			continue
		}

		selector, ok := getDeployChildSelector(deployment)
		if ok && selector.Matches(rsLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_deployment"),
				Id:proto.String(string(deployment.GetUID()))})
			break
		}
	}
}

func AddDeploymentChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("deployments") {
		return
	}

	for _, obj := range deploymentInf.GetStore().List() {
		deployment := obj.(*v1beta1.Deployment)
		if deployment.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_deployment"),
				Id:proto.String(string(deployment.GetUID()))})
		}
	}
}

func AddDeploymentChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !resourceReady("deployments") {
		return
	}

	for _, obj := range deploymentInf.GetStore().List() {
		deployment := obj.(*v1beta1.Deployment)
		if (deployment.GetNamespace() == namespace) &&
			(deployment.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_deployment"),
				Id:proto.String(string(deployment.GetUID()))})
		}
	}
}

func startDeploymentsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	deploySelectors = make(map[string]labels.Selector)
	client := kubeClient.ExtensionsV1beta1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "Deployments", v1meta.NamespaceAll, fields.Everything())
	deploymentInf = cache.NewSharedInformer(lw, &v1beta1.Deployment{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchDeployments(evtc)
		deploymentInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchDeployments(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchDeployments()")

	deploymentInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("deployments")
				evtc <- deploymentEvent(obj.(*v1beta1.Deployment),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("Deployment", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("Deployment", EVENT_UPDATE)
				oldDeployment := oldObj.(*v1beta1.Deployment)
				newDeployment := newObj.(*v1beta1.Deployment)
				if oldDeployment.GetResourceVersion() == newDeployment.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := deploymentEquals(oldDeployment, newDeployment)
				if !sameLinks {
					updateDeploySelectorCache(newDeployment)
				}
				if !sameEntity || !sameLinks {
					evtc <- deploymentEvent(newDeployment,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("Deployment", EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldDeployment := obj.(*v1beta1.Deployment)
				clearDeploySelectorCache(oldDeployment)
				evtc <- draiosproto.CongroupUpdateEvent {
					Type: draiosproto.CongroupEventType_REMOVED.Enum(),
					Object: &draiosproto.ContainerGroup{
						Uid: &draiosproto.CongroupUid{
							Kind:proto.String("k8s_deployment"),
							Id:proto.String(string(oldDeployment.GetUID()))},
					},
				}
				addEvent("Deployment", EVENT_DELETE)
			},
		},
	)
}

func getDeployChildSelector(deploy *v1beta1.Deployment) (labels.Selector, bool) {
	// Only cache selectors for deploy with pods currently scheduled
	if deploy.Status.Replicas == 0 {
		var zeroVal labels.Selector
		return zeroVal, false
	}

	deployCacheMutex.RLock()
	s, ok := deploySelectors[string(deploy.GetUID())]
	deployCacheMutex.RUnlock()

	if !ok {
		s = populateDeploySelectorCache(deploy)
	}
	return s, true
}

func populateDeploySelectorCache(deploy *v1beta1.Deployment) labels.Selector {
	// This is the cpu-heavy piece, so keep it outside the lock
	s, _ := v1meta.LabelSelectorAsSelector(deploy.Spec.Selector)

	deployCacheMutex.Lock()
	// It's possible another thread added the selector between
	// locks, but checking requires a second lookup in most cases
	// so always copy the newly created selector
	deploySelectors[string(deploy.GetUID())] = s
	deployCacheMutex.Unlock()
	return s
}

func clearDeploySelectorCache(deploy *v1beta1.Deployment) {
	deployCacheMutex.Lock()
	delete(deploySelectors, string(deploy.GetUID()))
	deployCacheMutex.Unlock()
}

// If we know the selector will be used again,
// it's cheaper to update while we have the lock
func updateDeploySelectorCache(deploy *v1beta1.Deployment) {
	if deploy.Status.Replicas == 0 {
		clearDeploySelectorCache(deploy)
	} else {
		populateDeploySelectorCache(deploy)
	}
}
