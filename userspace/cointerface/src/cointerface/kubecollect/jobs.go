package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"reflect"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	v1batch "k8s.io/api/batch/v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Globals are reset in startJobsSInformer
var jobInf cache.SharedInformer
var jobSelectorCache *selectorCache

type coJob struct {
	*v1batch.Job
}

func (job coJob) Selector() labels.Selector {
	s, _ := v1meta.LabelSelectorAsSelector(job.Spec.Selector)
	return s
}

func (job coJob) Filtered() bool {
	return false
}

func (job coJob) ActiveChildren() int32 {
	return job.Status.Active
}

// make this a library function?
func jobEvent(job coJob, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newJobConGroup(job, setLinks),
	}
}

func jobEquals(lhs coJob, rhs coJob) (bool, bool) {
	sameEntity := true
	sameLinks := true

	if lhs.GetName() != rhs.GetName() {
		sameEntity = false
	}

	sameEntity = sameEntity && EqualLabels(lhs.ObjectMeta, rhs.ObjectMeta)

	if lhs.Status.Active != rhs.Status.Active {
		sameEntity = false
		if (lhs.Status.Active == 0) || (rhs.Status.Active == 0) {
			sameLinks = false;
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

func newJobConGroup(job coJob, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_job"),
			Id:proto.String(string(job.GetUID()))},
	}

	ret.Tags = GetTags(job.ObjectMeta, "kubernetes.job.")
	addJobMetrics(&ret.Metrics, job)
	if setLinks {
		AddNSParents(&ret.Parents, job.GetNamespace())
		selector, ok := jobSelectorCache.Get(job)
		if ok {
			AddPodChildren(&ret.Children, selector, job.GetNamespace())
		}
		AddCronJobParent(&ret.Parents, job)
	}
	return ret
}

func addJobMetrics(metrics *[]*draiosproto.AppMetric, job coJob) {
	prefix := "kubernetes.job."

	AppendMetricPtrInt32(metrics, prefix+"spec.parallelism", job.Spec.Parallelism)
	AppendMetricPtrInt32(metrics, prefix+"spec.completions", job.Spec.Completions)
	AppendMetricInt32(metrics, prefix+"status.active", job.Status.Active)
	AppendMetricInt32(metrics, prefix+"status.succeeded", job.Status.Succeeded)
	AppendMetricInt32(metrics, prefix+"status.failed", job.Status.Failed)
}

func AddJobParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !resourceReady("jobs") {
		return
	}

	podLabels := labels.Set(pod.GetLabels())
	for _, obj := range jobInf.GetStore().List() {
		job := coJob{obj.(*v1batch.Job)}
		if pod.GetNamespace() != job.GetNamespace() {
			continue
		}

		selector, ok := jobSelectorCache.Get(job)
		if ok && selector.Matches(podLabels) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_job"),
				Id:proto.String(string(job.GetUID()))})
			break
		}
	}
}

func AddJobChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("jobs") {
		return
	}

	for _, obj := range jobInf.GetStore().List() {
		job := coJob{obj.(*v1batch.Job)}
		if job.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_job"),
				Id:proto.String(string(job.GetUID()))})
		}
	}
}

func startJobsSInformer(ctx context.Context,
			kubeClient kubeclient.Interface,
			wg *sync.WaitGroup,
			evtc chan<- draiosproto.CongroupUpdateEvent) {
	jobSelectorCache = newSelectorCache()
	client := kubeClient.BatchV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "jobs", v1meta.NamespaceAll, fields.Everything())
	jobInf = cache.NewSharedInformer(lw, &v1batch.Job{}, RsyncInterval)

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
				eventReceived("jobs")
				evtc <- jobEvent(coJob{obj.(*v1batch.Job)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("Job", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("Job", EVENT_UPDATE)
				oldJob := coJob{oldObj.(*v1batch.Job)}
				newJob := coJob{newObj.(*v1batch.Job)}
				if oldJob.GetResourceVersion() == newJob.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := jobEquals(oldJob, newJob)
				if !sameLinks ||
					(!sameEntity &&
					oldJob.Status.Active > 0 &&
					newJob.Status.Active == 0) {
					jobSelectorCache.Update(newJob)
				}
				if !sameEntity || !sameLinks {
					evtc <- jobEvent(newJob,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("Job", EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				job := coJob{nil}
				switch obj.(type) {
				case *v1batch.Job:
					job = coJob{obj.(*v1batch.Job)}
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v1batch.Job)
					if ok {
						job = coJob{o}
					} else {
						log.Warn("DeletedFinalStateUnknown without job object")
					}
				default:
					log.Warn("Unknown object type in job DeleteFunc")
				}
				if job.Job == nil {
					return
				}

				jobSelectorCache.Remove(job)
				evtc <- jobEvent(job,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				addEvent("Job", EVENT_DELETE)
			},
		},
	)
}
