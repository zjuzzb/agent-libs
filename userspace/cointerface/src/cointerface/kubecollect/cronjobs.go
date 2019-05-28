package kubecollect

import (
	"context"
	"sync"

	v1batch "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v2alpha1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
	kubeclient "k8s.io/client-go/kubernetes"

	"cointerface/draiosproto"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
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
	if !resourceReady("cronjobs") {
		return
	}

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
	if !resourceReady("cronjobs") {
		return
	}

	for _, obj := range cronJobInf.GetStore().List() {
		cronJob := obj.(*v2alpha1.CronJob)
		if cronJob.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_cronjob"),
				Id:proto.String(string(cronJob.GetUID()))})
		}
	}
}

func startCronJobsSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.BatchV2alpha1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "cronjobs", v1meta.NamespaceAll, fields.Everything())
	cronJobInf = cache.NewSharedInformer(lw, &v2alpha1.CronJob{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchCronJobs(evtc)
		cronJobInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchCronJobs(evtc chan<- draiosproto.CongroupUpdateEvent) {

	// fold, _ := os.Create("/tmp/cronjob_updates_old.json")
	// fnew, _ := os.Create("/tmp/cronjob_updates_new.json")

	cronJobInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("cronjobs")
				evtc <- cronJobEvent(obj.(*v2alpha1.CronJob),
					draiosproto.CongroupEventType_ADDED.Enum())
				addEvent("Cronjob", EVENT_ADD)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldJob := oldObj.(*v2alpha1.CronJob)
				newJob := newObj.(*v2alpha1.CronJob)
				if oldJob.GetResourceVersion() != newJob.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping ReplicaSet oldJob %v", oldJob)
					//log.Debugf("UpdateFunc dumping ReplicaSet newJob %v", newJob)
					// oldJson, _ := json.Marshal(oldJob)
					// fold.Write(oldJson)
					// fold.WriteString("\n")
					// newJson, _ := json.Marshal(newJob)
					// fnew.Write(newJson)
					// fnew.WriteString("\n")
					evtc <- cronJobEvent(newJob,
						draiosproto.CongroupEventType_UPDATED.Enum())
					addEvent("Cronjob", EVENT_UPDATE_AND_SEND)
				}
				addEvent("Cronjob", EVENT_UPDATE)
			},
			DeleteFunc: func(obj interface{}) {
				oldCronJob := (*v2alpha1.CronJob)(nil)
				switch obj.(type) {
				case *v2alpha1.CronJob:
					oldCronJob = obj.(*v2alpha1.CronJob)
				case cache.DeletedFinalStateUnknown:
					d := obj.(cache.DeletedFinalStateUnknown)
					o, ok := (d.Obj).(*v2alpha1.CronJob)
					if ok {
						oldCronJob = o
					} else {
						log.Warn("DeletedFinalStateUnknown without cronjob object")
					}
				default:
					log.Warn("Unknown object type in cronjob DeleteFunc")
				}
				if oldCronJob == nil {
					return
				}

				evtc <- cronJobEvent(oldCronJob,
					draiosproto.CongroupEventType_REMOVED.Enum())
				addEvent("Cronjob", EVENT_DELETE)
			},
		},
	)
}
