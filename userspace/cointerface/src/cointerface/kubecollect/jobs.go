package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"reflect"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	v1batch "k8s.io/api/batch/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Globals are reset in startJobsSInformer
var jobInf cache.SharedInformer

type CoJob struct {
	*v1batch.Job
}

func (job CoJob) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(job.Spec.Selector)
	return s
}

func (job CoJob) Filtered() bool {
	return false
}

func (job CoJob) ActiveChildren() int32 {
	return job.Status.Active
}

// make this a library function?
func jobEvent(job CoJob, eventType *draiosproto.CongroupEventType, setLinks bool) draiosproto.CongroupUpdateEvent {
	return draiosproto.CongroupUpdateEvent{
		Type:   eventType,
		Object: newJobConGroup(job, setLinks),
	}
}

func jobEquals(lhs CoJob, rhs CoJob) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && kubecollect_common.EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta)

	if lhs.Status.Active != rhs.Status.Active {
		sameEntity = false
		if (lhs.Status.Active == 0) || (rhs.Status.Active == 0) {
			sameLinks = false
		}
	}

	if sameEntity {
		if (lhs.Spec.Parallelism != rhs.Spec.Parallelism) ||
			(lhs.Spec.Completions != rhs.Spec.Completions) ||
			(lhs.Status.Succeeded != rhs.Status.Succeeded) ||
			(lhs.Status.Failed != rhs.Status.Failed) {
			sameEntity = false
		}
	}

	if sameLinks && lhs.GetNamespace() != rhs.GetNamespace() {
		sameLinks = false
	}

	if sameLinks && !reflect.DeepEqual(lhs.Spec.Selector, rhs.Spec.Selector) {
		sameLinks = false
	}

	return sameEntity, sameLinks
}

func newJobConGroup(job CoJob, setLinks bool) *draiosproto.ContainerGroup {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: proto.String("k8s_job"),
			Id:   proto.String(string(job.GetUID()))},
		Namespace: proto.String(job.GetNamespace()),
	}

	ret.Tags = kubecollect_common.GetTags(job, "kubernetes.job.")
	AddJobMetrics(&ret.Metrics, job)
	if setLinks {
		AddPodChildrenFromOwnerRef(&ret.Children, job.ObjectMeta)
		AddCronJobParent(&ret.Parents, job)
	}
	ret.LabelSelector = kubecollect_common.GetLabelSelector(*job.Spec.Selector)
	return ret
}

func AddJobMetrics(metrics *[]*draiosproto.AppMetric, job CoJob) {
	prefix := "kubernetes.job."

	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"spec.parallelism", job.Spec.Parallelism)
	kubecollect_common.AppendMetricPtrInt32(metrics, prefix+"spec.completions", job.Spec.Completions)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.active", job.Status.Active)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.succeeded", job.Status.Succeeded)
	kubecollect_common.AppendMetricInt32(metrics, prefix+"status.failed", job.Status.Failed)
}

func startJobsSInformer(ctx context.Context,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
	evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.BatchV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "jobs", v1meta.NamespaceAll, fields.Everything())
	jobInf = cache.NewSharedInformer(lw, &v1batch.Job{}, kubecollect_common.RsyncInterval)

	wg.Add(1)
	go func() {
		watchJobs(evtc)
		jobInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchJobs(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchJobs()")

	jobInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				kubecollect_common.EventReceived("jobs")
				evtc <- jobEvent(CoJob{obj.(*v1batch.Job)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_UPDATE)
				oldJob := CoJob{oldObj.(*v1batch.Job)}
				newJob := CoJob{newObj.(*v1batch.Job)}
				if oldJob.GetResourceVersion() == newJob.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := jobEquals(oldJob, newJob)
				if !sameEntity || !sameLinks {
					evtc <- jobEvent(newJob,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				job := CoJob{nil}
				switch obj := obj.(type) {
				case *v1batch.Job:
					job = CoJob{Job: obj}
				case cache.DeletedFinalStateUnknown:
					d := obj
					o, ok := (d.Obj).(*v1batch.Job)
					if ok {
						job = CoJob{o}
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without job object")
					}
				default:
					_ = log.Warn("Unknown object type in job DeleteFunc")
				}
				if job.Job == nil {
					return
				}

				evtc <- jobEvent(job,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}
