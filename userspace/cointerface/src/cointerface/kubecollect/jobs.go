package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	v1batch "k8s.io/api/batch/v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// make this a library function?
func jobEvent(job *v1batch.Job, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newJobConGroup(job),
	}
}

func newJobConGroup(job *v1batch.Job) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range job.GetLabels() {
		tags["kubernetes.job.label." + k] = v
	}
	tags["kubernetes.job.name"] = job.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_job"),
			Id:proto.String(string(job.GetUID()))},
		Tags: tags,
	}
	AddNSParents(&ret.Parents, job.GetNamespace())
	selector, _ := v1meta.LabelSelectorAsSelector(job.Spec.Selector)
	AddPodChildren(&ret.Children, selector, job.GetNamespace())
	AddCronJobParent(&ret.Parents, job)
	return ret
}

var jobInf cache.SharedInformer

func AddJobParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if CompatibilityMap["jobs"] {
		for _, obj := range jobInf.GetStore().List() {
			job := obj.(*v1batch.Job)
			selector, _ := v1meta.LabelSelectorAsSelector(job.Spec.Selector)
			if pod.GetNamespace() == job.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
				*parents = append(*parents, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_job"),
					Id:proto.String(string(job.GetUID()))})
			}
		}
	}
}

func AddJobChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if CompatibilityMap["jobs"] {
		for _, obj := range jobInf.GetStore().List() {
			job := obj.(*v1batch.Job)
			if job.GetNamespace() == namespaceName {
				*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_job"),
					Id:proto.String(string(job.GetUID()))})
			}
		}
	}
}

func StartJobsSInformer(ctx context.Context, kubeClient kubeclient.Interface) {
	client := kubeClient.BatchV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "jobs", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second
	jobInf = cache.NewSharedInformer(lw, &v1batch.Job{}, resyncPeriod)
	go jobInf.Run(ctx.Done())
}

func WatchJobs(evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchReplicaSets()")

	jobInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- jobEvent(obj.(*v1batch.Job),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldJob := oldObj.(*v1batch.Job)
				newJob := newObj.(*v1batch.Job)
				if oldJob.GetResourceVersion() != newJob.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping Job oldJob %v", oldJob)
					//log.Debugf("UpdateFunc dumping Job newJob %v", newJob)
					evtc <- jobEvent(newJob,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ReplicaSet: %v", obj.(*v1.Job))
				evtc <- jobEvent(obj.(*v1batch.Job),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	return jobInf
}
