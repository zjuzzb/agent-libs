package kubecollect

import (
	"draiosproto"
	"context"
	"github.com/gogo/protobuf/proto"
	"time"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	v1batch "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v2alpha1"
)

// make this a library function?
func cronJobEvent(cronjob *v2alpha1.CronJob, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newCronJobConGroup(cronjob),
	}
}

func newCronJobConGroup(cronjob *v2alpha1.CronJob) (*draiosproto.ContainerGroup) {
	// Need a way to distinguish them
	// ... and make merging annotations+labels it a library function?
	//     should work on all v1.Object types
	tags := make(map[string]string)
	for k, v := range cronjob.GetLabels() {
		tags["kubernetes.cronJob.label." + k] = v
	}
	tags["kubernetes.cronJob.name"] = cronjob.GetName()

	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_cronjob"),
			Id:proto.String(string(cronjob.GetUID()))},
		Tags: tags,
	}
	AddNSParents(&ret.Parents, cronjob.GetNamespace())
	for _, job := range cronjob.Status.Active {
		ret.Children = append(ret.Children, &draiosproto.CongroupUid{
			Kind:proto.String("k8s_job"),
			Id:proto.String(string(job.UID))})
	}
	return ret
}

var cronJobInf cache.SharedInformer

func AddCronJobParent(parents *[]*draiosproto.CongroupUid, job *v1batch.Job) {
	for _, item := range cronJobInf.GetStore().List() {
		cronJob := item.(*v2alpha1.CronJob)
		for _, activeJob := range cronJob.Status.Active {
			if activeJob.UID == job.GetUID() {
				*parents = append(*parents, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_cronjob"),
					Id:proto.String(string(cronJob.UID))})
			}
		}
	}
}

func AddCronJobChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	for _, obj := range cronJobInf.GetStore().List() {
		cronJob := obj.(*v2alpha1.CronJob)
		if cronJob.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_cronjob"),
				Id:proto.String(string(cronJob.GetUID()))})
		}
	}
}

func WatchCronJobs(ctx context.Context, kubeClient kubeclient.Interface, evtc chan<- draiosproto.CongroupUpdateEvent) cache.SharedInformer {
	client := kubeClient.BatchV2alpha1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "cronjobs", v1meta.NamespaceAll, fields.Everything())
	resyncPeriod := time.Duration(10) * time.Second;
	cronJobInf = cache.NewSharedInformer(lw, &v2alpha1.CronJob{}, resyncPeriod)

	cronJobInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				evtc <- cronJobEvent(obj.(*v2alpha1.CronJob),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldJob := oldObj.(*v2alpha1.CronJob)
				newJob := newObj.(*v2alpha1.CronJob)
				if oldJob.GetResourceVersion() != newJob.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping ReplicaSet oldJob %v", oldJob)
					//log.Debugf("UpdateFunc dumping ReplicaSet newJob %v", newJob)
					evtc <- cronJobEvent(newJob,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ReplicaSet: %v", obj.(*v1.ReplicaSet))
				evtc <- cronJobEvent(obj.(*v2alpha1.CronJob),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)

	go cronJobInf.Run(ctx.Done())

	return cronJobInf
}
