package kubecollect

import (
	"cointerface/kubecollect_common"
	"context"
	draiosproto "protorepo/agent-be/proto"
	"reflect"
	"sync"

	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Globals are reset in startJobsSInformer
var jobInf cache.SharedInformer

type CoJob struct {
	*batchv1.Job
}

func (job CoJob) Selector() labels.Selector {
	s, _ := metav1.LabelSelectorAsSelector(job.Spec.Selector)
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
	opts *sdc_internal.OrchestratorEventsStreamCommand,
	kubeClient kubeclient.Interface,
	wg *sync.WaitGroup,
	evtc chan<- draiosproto.CongroupUpdateEvent) {
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			obj, err := kubeClient.BatchV1().Jobs(metav1.NamespaceAll).List(options)
			return runtime.Object(obj), err
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return kubeClient.BatchV1().Jobs(metav1.NamespaceAll).Watch(options)
		},
	}
	jobInf = cache.NewSharedInformer(lw, &batchv1.Job{}, kubecollect_common.RsyncInterval)

	var completedJobs bool
	if opts.CompletedJobsEnabled != nil {
		completedJobs = *opts.CompletedJobsEnabled
	}
	wg.Add(1)
	go func() {
		watchJobs(evtc, completedJobs)
		jobInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchJobs(evtc chan<- draiosproto.CongroupUpdateEvent, completedJobsEnabled bool) {
	log.Debugf("In WatchJobs()")

	jobInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				job := obj.(*batchv1.Job)
				kubecollect_common.EventReceived("jobs")
				if !completedJobsEnabled && IsJobFinished(job) {
					log.Debug("Ignoring finished job %s added in namespace %s", job.Name, job.Namespace)
					return
				}
				evtc <- jobEvent(CoJob{obj.(*batchv1.Job)},
					draiosproto.CongroupEventType_ADDED.Enum(), true)
				kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_UPDATE)
				oldJob := CoJob{oldObj.(*batchv1.Job)}
				newJob := CoJob{newObj.(*batchv1.Job)}
				if oldJob.GetResourceVersion() == newJob.GetResourceVersion() {
					return
				}
				if !completedJobsEnabled && IsJobFinished(newJob.Job) && !IsJobFinished(oldJob.Job) {
					// If job finishes we don't need it any longer, we can
					// generate a syntetic REMOVED event to trigger removal
					// from infrastructure state.
					evtc <- jobEvent(newJob,
						draiosproto.CongroupEventType_REMOVED.Enum(), false)
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
				var job CoJob
				switch obj := obj.(type) {
				case *batchv1.Job:
					job.Job = obj
				case cache.DeletedFinalStateUnknown:
					if o, ok := (obj.Obj).(*batchv1.Job); ok {
						// We don't need to process deletion of finished Jobs, as
						// in the happy path we already sent a REMOVED event when
						// the Job transitioned to finished.
						log.Debugf("Job deletion detected after re-list for job %s in namespace %s", o.Name, o.Namespace)
						job.Job = o
					} else {
						_ = log.Warn("DeletedFinalStateUnknown without job object")
						return
					}
				default:
					// Should never happen
					_ = log.Warn("Unknown object type in job DeleteFunc")
					return
				}

				// We don't need to process deletion of finished Jobs, as
				// we already sent a REMOVED event when the Job transitioned
				// to finished.
				if !completedJobsEnabled && IsJobFinished(job.Job) {
					log.Debug("Ignoring finished job %s added in namespace %s", job.Job.Name, job.Job.Namespace)
					return
				}
				// In case we missed the transition of the Job to complete we
				// send the REMOVED event on deletion.
				evtc <- jobEvent(job,
					draiosproto.CongroupEventType_REMOVED.Enum(), false)
				kubecollect_common.AddEvent("Job", kubecollect_common.EVENT_DELETE)
			},
		},
	)
}

// IsJobFinished checks whether the given Job has finished execution.
// It does not discriminate between successful and failed terminations.
// Based on:
// https://github.com/kubernetes/kubernetes/blob/c9ddd248b6d58c4c973d507be07261b96ef0cfbc/pkg/controller/job/utils.go#L24-L33
func IsJobFinished(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
