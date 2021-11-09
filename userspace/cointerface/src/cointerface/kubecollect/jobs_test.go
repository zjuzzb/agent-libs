package kubecollect

import (
	"context"
	draiosproto "protorepo/agent-be/proto"
	"sync"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/draios/protorepo/sdc_internal"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestStartJobInformer(t *testing.T) {
	tests := []struct {
		name                 string
		initialList          []*batchv1.Job
		expEvents            []draiosproto.CongroupUpdateEvent
		completedJobsEnabled bool
		// scenarioFunc plays the sequence of operations related to the test
		// case once the watch starts (i.e. after the initial listing).
		scenarioFunc func(*fake.Clientset, *watch.FakeWatcher)
	}{
		{
			name: "Two added, two existing",
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo1", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo2", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo3", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo4", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
			},
			initialList: []*batchv1.Job{
				newJob(metav1.ObjectMeta{Name: "foo1", Namespace: "bar"}, batchv1.JobStatus{}),
				newJob(metav1.ObjectMeta{Name: "foo2", Namespace: "bar"}, batchv1.JobStatus{}),
			},
			scenarioFunc: func(_ *fake.Clientset, fw *watch.FakeWatcher) {
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo3", Namespace: "bar"}, batchv1.JobStatus{}))
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo4", Namespace: "bar"}, batchv1.JobStatus{}))
			},
		},
		{
			name: "Completed jobs are not considered",
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo3", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo4", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
			},
			initialList: []*batchv1.Job{
				newJob(metav1.ObjectMeta{Name: "foo1", Namespace: "bar"}, batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{
						{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
					},
				}),
				newJob(metav1.ObjectMeta{Name: "foo2", Namespace: "bar"}, batchv1.JobStatus{
					Conditions: []batchv1.JobCondition{
						{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
					},
				}),
			},
			scenarioFunc: func(_ *fake.Clientset, fw *watch.FakeWatcher) {
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo3", Namespace: "bar"}, batchv1.JobStatus{}))
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo4", Namespace: "bar"}, batchv1.JobStatus{}))
			},
		},
		{
			name:                 "Completed jobs are considered when completedJobsEnabled set to true",
			completedJobsEnabled: true,
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(
					metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
						},
					})}, draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(
					metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
					})}, draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo3", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo4", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
			},
			initialList: []*batchv1.Job{
				newJob(
					metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
						},
					}),
				newJob(
					metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
					}),
			},
			scenarioFunc: func(_ *fake.Clientset, fw *watch.FakeWatcher) {
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo3", Namespace: "bar"}, batchv1.JobStatus{}))
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo4", Namespace: "bar"}, batchv1.JobStatus{}))
			},
		},
		{
			name: "Job completion triggers update",
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					},
				)}, draiosproto.CongroupEventType_UPDATED.Enum(), false),
				jobEvent(CoJob{Job: newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					},
				)}, draiosproto.CongroupEventType_REMOVED.Enum(), false),
			},
			initialList: []*batchv1.Job{},
			scenarioFunc: func(c *fake.Clientset, fw *watch.FakeWatcher) {
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "0"}, batchv1.JobStatus{}))
				fw.Modify(newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "1"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					}))
				fw.Delete(newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "2"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					}))
			},
		},
		{
			name:                 "Job completion and removal when completedJobsEnabled set to true",
			completedJobsEnabled: true,
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					},
				)}, draiosproto.CongroupEventType_UPDATED.Enum(), false),
				jobEvent(CoJob{Job: newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					},
				)}, draiosproto.CongroupEventType_REMOVED.Enum(), false),
			},
			initialList: []*batchv1.Job{},
			scenarioFunc: func(c *fake.Clientset, fw *watch.FakeWatcher) {
				fw.Add(newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "0"}, batchv1.JobStatus{}))
				fw.Modify(newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "1"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					},
				))
				fw.Delete(newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "2"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
						Failed: 1,
					},
				))
			},
		},
		{
			name: "Job deleted before completion triggers removed event",
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_REMOVED.Enum(), false),
			},
			initialList: []*batchv1.Job{},
			scenarioFunc: func(_ *fake.Clientset, fw *watch.FakeWatcher) {
				fw.Add(newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "0"},
					batchv1.JobStatus{},
				))
				fw.Delete(newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "0"},
					batchv1.JobStatus{},
				))
			},
		},
		{
			name: "Lost delete on not terminated job triggers deletion",
			expEvents: []draiosproto.CongroupUpdateEvent{
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_ADDED.Enum(), false),
				jobEvent(CoJob{Job: newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar"}, batchv1.JobStatus{})},
					draiosproto.CongroupEventType_REMOVED.Enum(), false),
			},
			initialList: []*batchv1.Job{
				newJob(metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "0"}, batchv1.JobStatus{}),
			},
			scenarioFunc: func(cli *fake.Clientset, fw *watch.FakeWatcher) {
				// simulate error
				// TODO(irozzo) After watch error the reflector waits, check if
				// timer can be mocked somehow.
				fw.Error(&metav1.Status{Reason: metav1.StatusReasonTimeout})
				// delete the job, this is supposed to happen before the
				// re-list.
				_ = cli.BatchV1().Jobs("bar").Delete("foo", &metav1.DeleteOptions{})
			},
		},
		{
			name:      "Lost delete on terminated job does not triggers deletion",
			expEvents: []draiosproto.CongroupUpdateEvent{},
			initialList: []*batchv1.Job{
				newJob(
					metav1.ObjectMeta{Name: "foo", Namespace: "bar", ResourceVersion: "1"},
					batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
						},
					},
				),
			},
			scenarioFunc: func(cli *fake.Clientset, fw *watch.FakeWatcher) {
				//simulate error
				fw.Error(&metav1.Status{Reason: metav1.StatusReasonTimeout})
				// delete the job, this is supposed to happen before the
				// re-list.
				_ = cli.BatchV1().Jobs("bar").Delete("foo", &metav1.DeleteOptions{})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			watcherStarted := make(chan struct{})
			objs := make([]runtime.Object, 0, len(tc.initialList))
			for _, j := range tc.initialList {
				objs = append(objs, j)
			}
			client := fake.NewSimpleClientset(objs...)
			fakeJobsWatch := watch.NewFake()
			client.PrependWatchReactor("jobs", func(action clienttesting.Action) (handled bool, ret watch.Interface, err error) {
				watcherStarted <- struct{}{}

				return true, fakeJobsWatch, nil
			})
			wg := &sync.WaitGroup{}
			evtc := make(chan draiosproto.CongroupUpdateEvent)
			startJobsSInformer(context.TODO(), &sdc_internal.OrchestratorEventsStreamCommand{CompletedJobsEnabled: &tc.completedJobsEnabled}, client, wg, evtc)
			<-watcherStarted
			go tc.scenarioFunc(client, fakeJobsWatch)
			for observedEvents := 0; observedEvents < len(tc.expEvents); {
				select {
				case evt := <-evtc:
					t.Logf("New event received: %v", evt)
					if diff := cmp.Diff(evt, tc.expEvents[observedEvents], cmpopts.IgnoreFields(draiosproto.CongroupUpdateEvent{}, "Object.Children")); diff != "" {
						t.Fatalf("A difference was detected with the expected event #%d: %s", observedEvents, diff)
					}
					observedEvents++
				case <-watcherStarted:
					t.Log("New watch started.")
				case <-time.After(wait.ForeverTestTimeout):
					t.Fatalf("Timeout while waiting for event #%d", observedEvents)
				}
			}
			// Wait a little bit to check that no additional events are received
			select {
			case evt := <-evtc:
				t.Fatalf("Received unexpected event: %v", evt)
			case <-time.After(10 * time.Millisecond):
			}
		})
	}
}

func newJob(meta metav1.ObjectMeta, status batchv1.JobStatus) *batchv1.Job {
	job := batchv1.Job{
		ObjectMeta: meta,
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{},
		},
		Status: status,
	}
	return &job
}
