package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"

	"github.com/gogo/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
)

func deploymentEvent(dep kubecollect.CoDeployment, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newDeploymentCongroup(dep, setLinks),
	}
}

func newDeploymentCongroup(deployment kubecollect.CoDeployment, setLinks bool) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_deployment"),
			Id:   proto.String(string(deployment.GetUID()))},
		Namespace: proto.String(deployment.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(deployment, "kubernetes.deployment.")
	ret.InternalTags = kubecollect_common.GetAnnotations(deployment.ObjectMeta, "kubernetes.deployment.")
	kubecollect.AddDeploymentMetrics(&ret.Metrics, deployment)
	if setLinks {
		kubecollect_common.OwnerReferencesToParents(deployment.GetOwnerReferences(), &ret.Parents, nil)
	}
	ret.LabelSelector = kubecollect_common.GetLabelSelector(*deployment.Spec.Selector)
	return ret
}

func startDeploymentsWatcher(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	kubecollect_common.StartWatcher(ctx, kubeClient.AppsV1().RESTClient(), "Deployments", wg, evtc, fields.Everything(), handleDeploymentEvent)
}

func handleDeploymentEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {
	deployment, ok := event.Object.(*appsv1.Deployment)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("deployments")
		evtc <- deploymentEvent(kubecollect.CoDeployment{Deployment: deployment}, draiosproto.CongroupEventType_ADDED.Enum(), true)
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_UPDATE)
		evtc <- deploymentEvent(kubecollect.CoDeployment{Deployment: deployment}, draiosproto.CongroupEventType_UPDATED.Enum(), true)
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_UPDATE_AND_SEND)
	} else if event.Type == watch.Deleted {
		evtc <- deploymentEvent(kubecollect.CoDeployment{Deployment: deployment}, draiosproto.CongroupEventType_REMOVED.Enum(), false)
		kubecollect_common.AddEvent("deployment", kubecollect_common.EVENT_DELETE)
	}
}
