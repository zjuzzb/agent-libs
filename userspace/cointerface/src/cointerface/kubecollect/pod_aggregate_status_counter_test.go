package kubecollect

import (
	"k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"
)

// Create a pod with status Pending and two containers in Waiting state (reason  ContainerCreating)
func createPod() *v1.Pod {
	ret := &v1.Pod{
		TypeMeta: v12.TypeMeta{
			Kind:       "",
			APIVersion: "",
		},
		ObjectMeta: v12.ObjectMeta{
			Name:            "FunnyPod",
			GenerateName:    "",
			Namespace:       "",
			SelfLink:        "",
			UID:             "",
			ResourceVersion: "",
			Generation:      0,
			CreationTimestamp: v12.Time{
				Time: time.Time{},
			},
			DeletionTimestamp: nil,
		},
		Status: v1.PodStatus{
			Phase:             v1.PodPending,
			Conditions:        nil,
			Message:           "",
			Reason:            "",
			NominatedNodeName: "",
			HostIP:            "",
			PodIP:             "",
			StartTime: &v12.Time{
				Time: time.Time{},
			},
			InitContainerStatuses: nil,
			QOSClass:              "",
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name: "sometimeCrashingPod",
					State: v1.ContainerState{
						Waiting: &v1.ContainerStateWaiting{
							Reason:  "ContainerCreating",
							Message: "",
						},
						Running:    nil,
						Terminated: nil,
					},
					LastTerminationState: v1.ContainerState{},
					Ready:                false,
					RestartCount:         0,
					Image:                "",
					ImageID:              "",
					ContainerID:          "",
				},
				{
					Name:                 "GoodBoyPod",
					State:                v1.ContainerState{},
					LastTerminationState: v1.ContainerState{},
					Ready:                false,
					RestartCount:         0,
					Image:                "",
					ImageID:              "",
					ContainerID:          "",
				},
			},
		},
	}

	return ret
}

func setPodStatus(status v1.PodPhase, state *v1.ContainerState, pod *v1.Pod) {
	pod.Status.Phase = status

	if state != nil {
		pod.Status.ContainerStatuses[0].State = *state
	}

}

func checkAggregateStatus(expected string, actual string, t *testing.T) {
	if expected != actual {
		t.Logf("Got %s, expecting %s", actual, expected)
		t.Fail()
	}
}

func TestMain(m *testing.M) {
	// Setup
	podStatusAllowed = []string{"Error", "CrashLoopBackOff", "Evicted", "DeadlineExceed", "ContainerCreating", "Running", "Pending"}
	podStatusAllowed = toLowerArray(podStatusAllowed)
	sort.Strings(podStatusAllowed)

	deployment_fixture()
	replicaset_fixture()

	initStructures()

	//Run test
	res := m.Run()

	//Teardown

	// Exit
	os.Exit(res)
}

func TestGetStatusFromPod(t *testing.T) {
	// These are a number of real use cases

	//
	// Check a pod in Pending phase with a container that is in Waiting status
	//
	pod := createPod()
	checkAggregateStatus("containercreating", getStatusFromPod(pod), t)

	//
	// Check a running pod with all containers in running state
	//
	setPodStatus(v1.PodRunning,
		&v1.ContainerState{
			Waiting:    nil,
			Running:    &v1.ContainerStateRunning{},
			Terminated: nil,
		},
		pod)
	checkAggregateStatus("running", getStatusFromPod(pod), t)

	//
	// Check a container that crashes passing to status Terminate with reason Error. Pod phase is Running
	//
	setPodStatus(v1.PodRunning,
		&v1.ContainerState{
			Waiting:    nil,
			Running:    nil,
			Terminated: &v1.ContainerStateTerminated{Reason: "Error"},
		},
		pod)
	checkAggregateStatus("error", getStatusFromPod(pod), t)

	//
	// Check a pod in Running phase with a container in CrashLoopBackOff status
	//
	setPodStatus(v1.PodRunning,
		&v1.ContainerState{
			Waiting:    &v1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
			Running:    nil,
			Terminated: nil,
		},
		pod)
	checkAggregateStatus("crashloopbackoff", getStatusFromPod(pod), t)

	//
	// Check a pod having a non white listed aggr status
	//
	setPodStatus(v1.PodRunning,
		&v1.ContainerState{
			Waiting:    &v1.ContainerStateWaiting{Reason: "LunchTime"},
			Running:    nil,
			Terminated: nil,
		},
		pod)
	checkAggregateStatus("othererrors", getStatusFromPod(pod), t)

	//
	// Check a pod in Pending phase without any container yet. Expected value is Pending
	//
	setPodStatus(v1.PodPending, nil, pod)
	pod.Status.ContainerStatuses = nil
	checkAggregateStatus("pending", getStatusFromPod(pod), t)
}

func createPodData(namespace string, uid int) *v1.Pod {
	pod := createPod()
	pod.Namespace = namespace
	pod.UID = types.UID(strconv.Itoa(uid))
	return pod
}

func TestHandleEvent(t *testing.T) {
	// Simulate 100 Event type ADD of pod in ContainerCreating aggregate status

	for i := 0; i < 100; i++ {
		pod := createPodData("namespace1", i)

		event := watch.Event{
			Type:   watch.Added,
			Object: pod,
		}

		handleEvent(event)
	}
	if statusMap["namespace1"]["containercreating"] != 100 {
		t.Fail()
	}

	// Update pod with uid from 0 to 9 to AggrStatus Running
	for i := 0; i < 10; i++ {
		pod := createPodData("namespace1", i)

		setPodStatus(v1.PodRunning,
			&v1.ContainerState{
				Waiting:    nil,
				Running:    &v1.ContainerStateRunning{},
				Terminated: nil,
			},
			pod)

		event := watch.Event{
			Type:   watch.Modified,
			Object: pod,
		}

		handleEvent(event)
	}
	if !(statusMap["namespace1"]["containercreating"] == 90 &&
		statusMap["namespace1"]["running"] == 10) {
		t.Logf("%v", statusMap)
		t.Fail()
	}

	// Delete pod with uid from 0 to 19
	for i := 0; i < 20; i++ {
		pod := createPodData("namespace1", i)

		event := watch.Event{
			Type:   watch.Deleted,
			Object: pod,
		}

		handleEvent(event)
	}

	if !(statusMap["namespace1"]["running"] == 0 &&
		statusMap["namespace1"]["containercreating"] == 80) {
		t.Logf("%v", statusMap)
		t.Fail()
	}

	// Try to update a non existing pod (i.e. uid 0)
	pod := createPodData("namespace1", 0)
	setPodStatus(v1.PodRunning,
		&v1.ContainerState{
			Waiting:    nil,
			Running:    nil,
			Terminated: &v1.ContainerStateTerminated{Reason: "ByeBye"},
		},
		pod)

	event := watch.Event{
		Type:   watch.Modified,
		Object: pod,
	}

	handleEvent(event)
	// We expect nothing had changed
	if !(statusMap["namespace1"]["running"] == 0 &&
		statusMap["namespace1"]["containercreating"] == 80) {
		t.Logf("%v", statusMap)
		t.Fail()
	}

	// Add 3 pod to another namespace
	for i := 0; i < 3; i++ {
		pod := createPodData("namespace2", i)

		event := watch.Event{
			Type:   watch.Added,
			Object: pod,
		}

		handleEvent(event)
	}

	if !(statusMap["namespace1"]["running"] == 0 &&
		statusMap["namespace1"]["containercreating"] == 80 &&
		statusMap["namespace2"]["containercreating"] == 3) {
		t.Logf("%v", statusMap)
		t.Fail()
	}
}
