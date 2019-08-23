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
var deploySelectorCache *selectorCache

type coDeployment struct {
	*v1beta1.Deployment
}

func (deploy coDeployment) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(deploy.Spec.Selector)
	return s
}

func (deploy coDeployment) Filtered() bool {
	return false
}

func (deploy coDeployment) ActiveChildren() int32 {
	return deploy.Status.Replicas
}

func deploymentEvent(dep coDeployment, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newDeploymentCongroup(dep, setLinks),
	}
}

// sameEntity will always be false when sameLinks is false
func deploymentEquals(lhs coDeployment, rhs coDeployment) (sameEntity bool, sameLinks bool) {
	if rhs.Deployment == nil || lhs.Deployment == nil {
		return false, false
	}

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

func newDeploymentCongroup(deployment coDeployment, setLinks bool) (*draiosproto.ContainerGroup) {
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
		selector, ok := deploySelectorCache.Get(deployment)
		if ok {
			AddReplicaSetChildren(&ret.Children, selector, deployment.GetNamespace())
		}
		AddHorizontalPodAutoscalerParents(&ret.Parents, deployment.GetNamespace(), deployment.APIVersion, deployment.Kind, deployment.GetName() )
	}
	return ret
}

func addDeploymentMetrics(metrics *[]*draiosproto.AppMetric, deployment coDeployment) {
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

func AddDeploymentParents(parents *[]*draiosproto.CongroupUid, rs coReplicaSet) {
	if !resourceReady("deployments") {
		return
	}

	rsLabels := labels.Set(rs.GetLabels())
	for _, obj := range deploymentInf.GetStore().List() {
		deploy := coDeployment{obj.(*v1beta1.Deployment)}
		if rs.GetNamespace() != deploy.GetNamespace() {
			continue
		}

		selector, ok := deploySelectorCache.Get(deploy)
		if ok && selector.Matches(rsLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_deployment"),
				Id:proto.String(string(deploy.GetUID()))})
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
	deploySelectorCache = newSelectorCache()
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
				evtc <- deploymentEvent(coDeployment{obj.(*v1beta1.Deployment)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("Deployment", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("Deployment", EVENT_UPDATE)
				oldDeployment := coDeployment{oldObj.(*v1beta1.Deployment)}
				newDeployment := coDeployment{newObj.(*v1beta1.Deployment)}
				if oldDeployment.GetResourceVersion() == newDeployment.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := deploymentEquals(oldDeployment, newDeployment)
				if !sameLinks {
					deploySelectorCache.Update(newDeployment)
				}
				if !sameEntity || !sameLinks {
					evtc <- deploymentEvent(newDeployment,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("Deployment", EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				oldDeployment := coDeployment{nil}
				switch obj.(type) {
				case *v1beta1.Deployment:
					oldDeployment = coDeployment{obj.(*v1beta1.Deployment)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1beta1.Deployment)
					if ok {
						oldDeployment = coDeployment{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without deployment object")
					}
				default:
					log.Warn("Unknown object type in deployment DeleteFunc")
				}
				if oldDeployment.Deployment == nil {
					return
				}
				deploySelectorCache.Remove(oldDeployment)
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
