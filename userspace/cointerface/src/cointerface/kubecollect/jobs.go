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
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/api/core/v1"
	v1batch "k8s.io/api/batch/v1"
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
	return ret
}

var jobInf cache.SharedInformer

func WatchJobs(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	log.Debugf("In WatchReplicaSets()")
	client := kubeClient.BatchV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "jobs", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	jobInf = cache.NewSharedInformer(lw, &v1batch.Job{}, resyncPeriod)

	jobInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- replicaSetEvent(obj.(*v1batch.Job),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldReplicaSet := oldObj.(*v1batch.Job)
				newReplicaSet := newObj.(*v1batch.Job)
				if oldReplicaSet.GetResourceVersion() != newReplicaSet.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping ReplicaSet oldReplicaSet %v", oldReplicaSet)
					//log.Debugf("UpdateFunc dumping ReplicaSet newReplicaSet %v", newReplicaSet)
					evtc <- replicaSetEvent(newReplicaSet,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ReplicaSet: %v", obj.(*v1.ReplicaSet))
				evtc <- replicaSetEvent(obj.(*v1batch.Job),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go jobInf.Run(ctx.Done())

	return jobInf
}
