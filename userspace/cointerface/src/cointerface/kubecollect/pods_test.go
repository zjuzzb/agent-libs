package kubecollect

import (
	"testing"
	. "test_helpers"

	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/tools/cache"

	"cointerface/draiosproto"
)

// Creates two pod objects that are DeepEqual
func createPodCopies() (*v1.Pod, *v1.Pod) {
	orig := &v1.Pod{
		ObjectMeta: v1meta.ObjectMeta{
			Name: "oldPod",
			Labels: map[string]string{
				"label_key0":"label_val0",
				"label_key1":"label_val1",
				"label_key2":"label_val2",
			},
			Annotations: map[string]string{
				"annotation_key0":"annotation_val0",
				"annotation_key1":"annotation_val1",
				"annotation_key2":"annotation_val2",
			},
		},
		Spec: v1.PodSpec{
			InitContainers: []v1.Container{
				v1.Container{
					Name: "init_container1",
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("250m"),
							v1.ResourceMemory: resource.MustParse("512Mi"),
						},
						Requests: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("200m"),
							v1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
				},
				v1.Container{
					Name: "init_container2",
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("150m"),
							v1.ResourceMemory: resource.MustParse("768Mi"),
						},
						Requests: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("100m"),
							v1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				},
			},
			Containers: []v1.Container{
				v1.Container{
					Name: "container1",
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("1"),
							v1.ResourceMemory: resource.MustParse("0.5Gi"),
						},
						Requests: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("0.5"),
							v1.ResourceMemory: resource.MustParse("1Gi"),
						},
					},
				},
				v1.Container{
					Name: "container2",
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("2.5"),
							v1.ResourceMemory: resource.MustParse("4Gi"),
						},
						Requests: v1.ResourceList{
							v1.ResourceCPU: resource.MustParse("1.5"),
							v1.ResourceMemory: resource.MustParse("3Gi"),
						},
					},
				},
			},
			NodeName: "oldNode",
		},
		Status: v1.PodStatus{
			Conditions: []v1.PodCondition{
				v1.PodCondition{
					Type: v1.PodReady,
					Status: v1.ConditionTrue,
				},
			},
			InitContainerStatuses: []v1.ContainerStatus{
				v1.ContainerStatus{
					Name: "init_container1",
					State: v1.ContainerState{
						Waiting: &v1.ContainerStateWaiting{
							Reason: "ut",
							Message: "we need a waiting container for the ut",
						},
						Running: nil,
						Terminated: nil,
					},
					RestartCount: 0,
				},
				v1.ContainerStatus{
					Name: "init_container2",
					State: v1.ContainerState{
						Waiting: &v1.ContainerStateWaiting{
							Reason: "ut",
							Message: "we need a waiting container for the ut",
						},
						Running: nil,
						Terminated: nil,
					},
					RestartCount: 2,
				},
			},
			ContainerStatuses: []v1.ContainerStatus{
				v1.ContainerStatus{
					Name: "container1",
					State: v1.ContainerState{
						Waiting: &v1.ContainerStateWaiting{
							Reason: "ut",
							Message: "we need a waiting container for the ut",
						},
						Running: nil,
						Terminated: nil,
					},
					RestartCount: 0,
				},
				v1.ContainerStatus{
					Name: "container2",
					State: v1.ContainerState{
						Waiting: &v1.ContainerStateWaiting{
							Reason: "ut",
							Message: "we need a waiting container for the ut",
						},
						Running: nil,
						Terminated: nil,
					},
					RestartCount: 1,
				},
			},
		},
	}
	copy := orig.DeepCopy()
	return orig, copy
}

func podEqualsHelper(t *testing.T, old *v1.Pod, new *v1.Pod, expected bool) {
	sameEntity, sameLinks := podEquals(old, new)
	res := sameEntity && sameLinks
	if (!sameLinks && sameEntity) || (res != expected)  {
		t.Logf("podEquals expected %v, got %v", expected, res)
		t.Logf("sameEntity is %v, sameLinks is %v", sameEntity, sameLinks)
		t.Logf("oldPod: %#v", old)
		t.Logf("newPod: %#v", new)
		t.Fail()
	}
}

func TestPodEqualsUnchanged(t *testing.T) {
	oldPod, newPod := createPodCopies()

	podEqualsHelper(t, oldPod, newPod, true)
}

func TestPodEqualsName(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Name = "newPod"

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsStatusReady(t *testing.T) {
	oldPod, newPod := createPodCopies()

	found := false
	for idx, _ := range newPod.Status.Conditions {
		if newPod.Status.Conditions[idx].Type == v1.PodReady {
			found = true
			if newPod.Status.Conditions[idx].Status != v1.ConditionTrue {
				t.Error("expected v1.PodReady to be true")
				t.FailNow()
			}
			newPod.Status.Conditions[idx].Status = v1.ConditionFalse
			break
		}
	}
	if !found {
		t.Error("couldn't find v1.PodReady condition")
		t.FailNow()
	}

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsRestartCount(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Status.ContainerStatuses[1].RestartCount += 1;

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsWaiting(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Status.ContainerStatuses[1].State.Waiting = nil;
	// we don't look at the vals, just needs to be non-nil
	newPod.Status.ContainerStatuses[1].State.Running = &v1.ContainerStateRunning{}

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsInitRestartCount(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Status.InitContainerStatuses[1].RestartCount += 1;

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsInitWaiting(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Status.InitContainerStatuses[1].State.Waiting = nil;
	// we don't look at the vals, just needs to be non-nil
	newPod.Status.InitContainerStatuses[1].State.Running = &v1.ContainerStateRunning{}

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsResourceLimitsCPU(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Spec.Containers[1].Resources.Limits[v1.ResourceCPU] = resource.MustParse("3")

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsResourceRequestsCPU(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Spec.Containers[1].Resources.Requests[v1.ResourceCPU] = resource.MustParse("2")

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsResourceLimitsMem(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Spec.Containers[1].Resources.Limits[v1.ResourceMemory] = resource.MustParse("6")

	podEqualsHelper(t, oldPod, newPod, false)
}

func TestPodEqualsResourceRequestsMem(t *testing.T) {
	oldPod, newPod := createPodCopies()
	newPod.Spec.Containers[1].Resources.Requests[v1.ResourceMemory] = resource.MustParse("5")

	podEqualsHelper(t, oldPod, newPod, false)
}

func Test_parseContainerID (t *testing.T) {

	result,err := parseContainerID("docker://0123456789abbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	AssertEqual(t, err, nil)
	AssertEqual(t, "0123456789ab", result)

	// Unknown what exactly a legitimate rkt id looks like but this tests
	// the existing code
	result,err = parseContainerID("rkt://1234:app")
	AssertEqual(t, err, nil)
	AssertEqual(t, "1234:app", result)

	result,err = parseContainerID("rkt://")
	AssertEqual(t, "rkt://", result)
	AssertEqual(t, "ID too short for rkt format", err.Error())

	// Missing slash
	result,err = parseContainerID("docker:/0123456789abbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	AssertEqual(t, "docker:/0123456789abbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", result)
	AssertEqual(t, "Unknown containerID format", err.Error())
}

func podDeleteFuncHelper(t *testing.T, obj interface{}, evtExpected bool) {
	evtReceiver := make(chan draiosproto.CongroupUpdateEvent, 1)
	podEvtcHandle = evtReceiver

	podDeleteFunc(obj)
	evtReceived := false
	select {
	case _, ok := <-evtReceiver:
		if !ok {
			t.Log("podEvtcHandle was closed unexpectedly")
			t.Fail()
		}
		evtReceived = true
	default:
		t.Log("Pod delete event wasn't created")
	}
	if evtExpected != evtReceived {
		t.Fail()
	}
}

func TestPodDeleteFunc(t *testing.T) {
	oldPod, _ := createPodCopies()
	podDeleteFuncHelper(t, oldPod, true)
}

func TestPodDeleteFuncDeletedFinalStateUnknown(t *testing.T) {
	oldPod, _ := createPodCopies()
	unk := cache.DeletedFinalStateUnknown{
		//Key: "" // XXX do we need to set/use this?
		Obj: oldPod,
	}
	podDeleteFuncHelper(t, unk, true)
}

func TestPodDeleteFuncBadType(t *testing.T) {
	podDeleteFuncHelper(t, nil, false)
	var someInt int = 0
	podDeleteFuncHelper(t, someInt, false)
}
