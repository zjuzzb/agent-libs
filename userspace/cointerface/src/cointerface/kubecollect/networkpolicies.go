package kubecollect


import (
	"cointerface/kubecollect_common"
	"context"
	"encoding/json"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	draiosproto "protorepo/agent-be/proto"

	"k8s.io/api/networking/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sync"
)

var networkPolicyInf cache.SharedInformer

// make this a library function?
func networkPolicyEvent(rq *v1.NetworkPolicy, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newNetworkPolicyCongroup(rq),
	}
}

func setScopev(tags map[string]string, networkpolicy *v1.NetworkPolicy) () {
}

func networkPolicyEquals(oldNetworkPolicy *v1.NetworkPolicy, newNetworkPolicy *v1.NetworkPolicy) bool {
	ret := true
	if oldNetworkPolicy.GetName() != newNetworkPolicy.GetName() ||
		!kubecollect_common.EqualLabels(oldNetworkPolicy.ObjectMeta, newNetworkPolicy.ObjectMeta) ||
		!kubecollect_common.EqualAnnotations(oldNetworkPolicy.ObjectMeta, newNetworkPolicy.ObjectMeta) {
		ret = false
	}
	return ret
}

func newNetworkPolicyCongroup(networkPolicy *v1.NetworkPolicy) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range networkPolicy.GetLabels() {
		tags["kubernetes.networkpolicy.label." + k] = v
	}

	setScopev(tags, networkPolicy)
	tags["kubernetes.networkpolicy.name"] = networkPolicy.GetName()
	tags["kubernetes.networkpolicy.version"] = "networking.k8s.io/v1"

	bytes, err :=json.Marshal( networkPolicy.Spec)
	inttags := make(map[string]string)

	if err == nil {
		inttags["kubernetes.networkpolicy.spec"] = string(bytes)
	}

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_networkpolicy"),
			Id:proto.String(string(networkPolicy.GetUID()))},
		Tags: tags,
		InternalTags: inttags,
		Namespace:proto.String(networkPolicy.GetNamespace()),
	}

	AddNetworkPolicyMetrics(&ret.Metrics, networkPolicy)
	return ret
}

func AddNetworkPolicyMetrics(metrics *[]*draiosproto.AppMetric, networkPolicy *v1.NetworkPolicy) {

}


func StartNetworkPoliciesSInformer(ctx context.Context, kubeClient kubeclient.Interface,
	wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {

	informer := func(stopCh <-chan struct{}) {

		client := kubeClient.NetworkingV1().RESTClient()
		lw := cache.NewListWatchFromClient(client, "NetworkPolicies", v1meta.NamespaceAll, fields.Everything())
		networkPolicyInf = cache.NewSharedInformer(lw, &v1.NetworkPolicy{}, kubecollect_common.RsyncInterval)
		watchNetworkPolicies(evtc)
		networkPolicyInf.Run(stopCh)

	}

	delegatedInformers = append(delegatedInformers, informer)
}

func watchNetworkPolicies(evtc chan<- draiosproto.CongroupUpdateEvent) {

	log.Debugf("In WatchNetworkPolicies()")

	networkPolicyInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{

			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("networkpolicies")
				evtc <- networkPolicyEvent(obj.(*v1.NetworkPolicy),
					draiosproto.CongroupEventType_ADDED.Enum())
				kubecollect_common.AddEvent("NetworkPolicy", kubecollect_common.EVENT_ADD)
			},

			UpdateFunc: func(oldObj, newObj interface{}) {

				oldNetworkPolicy := oldObj.(*v1.NetworkPolicy)
				newNetworkPolicy := newObj.(*v1.NetworkPolicy)

				if (oldNetworkPolicy.GetResourceVersion() != newNetworkPolicy.GetResourceVersion()) ||
					!networkPolicyEquals(oldNetworkPolicy, newNetworkPolicy) {

					evtc <- networkPolicyEvent(newNetworkPolicy,
						draiosproto.CongroupEventType_UPDATED.Enum())
					kubecollect_common.AddEvent("NetworkPolicy", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
				kubecollect_common.AddEvent("NetworkPolicy", kubecollect_common.EVENT_UPDATE)
			},

			DeleteFunc: func(obj interface{}) {

				oldRQ := (*v1.NetworkPolicy)(nil)

				switch obj.(type) {
				case *v1.NetworkPolicy:
					oldRQ = obj.(*v1.NetworkPolicy)

				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1.NetworkPolicy)
					if ok {
						oldRQ = o
					} else {
						log.Warn("DeletedFinalStateUnknown without networkpolicy object")
					}

				default:
					log.Warn("Unknown object type in networkpolicy DeleteFunc")
				}

				if oldRQ == nil {
					return
				}

				evtc <- networkPolicyEvent(oldRQ,
					draiosproto.CongroupEventType_REMOVED.Enum())

				kubecollect_common.AddEvent("NetworkPolicy", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
