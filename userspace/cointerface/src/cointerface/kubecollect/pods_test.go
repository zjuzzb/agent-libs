package kubecollect

import (
	"testing"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			NodeName: "oldNode",
		},
		Status: v1.PodStatus{
			Conditions: []v1.PodCondition{
				v1.PodCondition{
					Type: v1.PodReady,
					Status: v1.ConditionTrue,
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
