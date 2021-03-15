package kubecollect_tc

import (
	"cointerface/kubecollect"
	"cointerface/kubecollect_common"
	"context"
	"github.com/gogo/protobuf/proto"
	v1batch "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	draiosproto "protorepo/agent-be/proto"
	"sync"
)

func jobEvent(job kubecollect.CoJob, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newJobConGroup(job, setLinks),
	}
}

func newJobConGroup(job kubecollect.CoJob, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_job"),
			Id:proto.String(string(job.GetUID()))},
			Namespace:proto.String(job.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(job.ObjectMeta, "kubernetes.job.")
	kubecollect.AddJobMetrics(&ret.Metrics, job)
	if setLinks {
		kubecollect_common.OwnerReferencesToParents(job.GetOwnerReferences(), &ret.Parents, &map[string]bool{"CronJob" : true})
	}
	ret.LabelSelector = kubecollect_common.GetLabelSelector(*job.Spec.Selector)
	return ret
}

func startJobsWatcher(ctx context.Context,
			kubeClient kubeclient.Interface,
			wg *sync.WaitGroup,
			evtc chan<- draiosproto.CongroupUpdateEvent) {

	kubecollect_common.StartWatcher(ctx, kubeClient.BatchV1().RESTClient(), "Jobs", wg, evtc, fields.Everything(), true /*retryAtBoot*/, handleJobEvent)
}

func handleJobEvent(event watch.Event, evtc chan<- draiosproto.CongroupUpdateEvent) {

	job, ok := event.Object.(*v1batch.Job)

	if !ok {
		return
	}

	if event.Type == watch.Added {
		kubecollect_common.EventReceived("jobs")
		evtc <- jobEvent(kubecollect.CoJob{job}, draiosproto.CongroupEventType_ADDED.Enum(), true)
		kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_ADD)
	} else if event.Type == watch.Modified {
		kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_UPDATE)
		evtc <- jobEvent(kubecollect.CoJob{job}, draiosproto.CongroupEventType_UPDATED.Enum(), true)
		kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_UPDATE_AND_SEND)
	} else if event.Type == watch.Deleted {
		evtc <- jobEvent(kubecollect.CoJob{job}, draiosproto.CongroupEventType_REMOVED.Enum(), false)
		kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_DELETE)
	}
}
