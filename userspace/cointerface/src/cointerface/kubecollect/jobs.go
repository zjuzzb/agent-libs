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
var jobSelectors map[string]labels.Selector
var jobCacheMutex sync.RWMutex

// make this a library function?
func jobEvent(job *v1batch.Job, eventType *draiosproto.CongroupEventType, setLinks bool) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newJobConGroup(job, setLinks),
	}
}

func jobEquals(lhs *v1batch.Job, rhs *v1batch.Job) (bool, bool) {
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

func newJobConGroup(job *v1batch.Job, setLinks bool) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_job"),
			Id:proto.String(string(job.GetUID()))},
	}

	ret.Tags = GetTags(job.ObjectMeta, "kubernetes.job.")
	addJobMetrics(&ret.Metrics, job)
	if setLinks {
		AddNSParents(&ret.Parents, job.GetNamespace())
		selector, ok := getJobChildSelector(job)
		if ok {
			AddPodChildren(&ret.Children, selector, job.GetNamespace())
		}
		AddCronJobParent(&ret.Parents, job)
	}
	return ret
}

func addJobMetrics(metrics *[]*draiosproto.AppMetric, job *v1batch.Job) {
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
		job := obj.(*v1batch.Job)
		if pod.GetNamespace() != job.GetNamespace() {
			continue
		}

		selector, ok := getJobChildSelector(job)
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
		job := obj.(*v1batch.Job)
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
	jobSelectors = make(map[string]labels.Selector)
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
				evtc <- jobEvent(obj.(*v1batch.Job),
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				addEvent("Job", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				addEvent("Job", EVENT_UPDATE)
				oldJob := oldObj.(*v1batch.Job)
				newJob := newObj.(*v1batch.Job)
				if oldJob.GetResourceVersion() == newJob.GetResourceVersion() {
					return
				}

				sameEntity, sameLinks := jobEquals(oldJob, newJob)
				if !sameLinks ||
					(!sameEntity &&
					oldJob.Status.Active > 0 &&
					newJob.Status.Active == 0) {
					updateJobSelectorCache(newJob)
				}
				if !sameEntity || !sameLinks {
					evtc <- jobEvent(newJob,
						draiosproto.CongroupEventType_UPDATED.Enum(), !sameLinks)
					addEvent("Job", EVENT_UPDATE_AND_SEND)
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ReplicaSet: %v", obj.(*v1.Job))
				job := obj.(*v1batch.Job)
				clearJobSelectorCache(job)
				evtc <- jobEvent(job,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				addEvent("Job", EVENT_DELETE)
			},
		},
	)
}

func getJobChildSelector(job *v1batch.Job) (labels.Selector, bool) {
	// Only cache selectors for jobs with pods currently scheduled
	if job.Status.Active == 0 {
		var zeroVal labels.Selector
		return zeroVal, false
	}

	jobCacheMutex.RLock()
	s, ok := jobSelectors[string(job.GetUID())]
	jobCacheMutex.RUnlock()

	if !ok {
		s = populateJobSelectorCache(job)
	}
	return s, true
}

func populateJobSelectorCache(job *v1batch.Job) labels.Selector {
	// This is the cpu-heavy piece, so keep it outside the lock
	s, _ := v1meta.LabelSelectorAsSelector(job.Spec.Selector)

	jobCacheMutex.Lock()
	// It's possible another thread added the selector between
	// locks, but checking requires a second lookup in most cases
	// so always copy the newly created selector
	jobSelectors[string(job.GetUID())] = s
	jobCacheMutex.Unlock()
	return s
}

func clearJobSelectorCache(job *v1batch.Job) {
	jobCacheMutex.Lock()
	delete(jobSelectors, string(job.GetUID()))
	jobCacheMutex.Unlock()
}

// If we know the selector will be used again,
// it's cheaper to update while we have the lock
func updateJobSelectorCache(job *v1batch.Job) {
	if job.Status.Active == 0 {
		clearJobSelectorCache(job)
	} else {
		populateJobSelectorCache(job)
	}
}
