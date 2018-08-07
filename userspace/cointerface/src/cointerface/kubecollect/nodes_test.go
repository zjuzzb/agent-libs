package kubecollect

import (
	"testing"
	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// Creates two node objects that are DeepEqual
func createNodeCopies() (*v1.Node, *v1.Node) {
	orig := &v1.Node{
		ObjectMeta: v1meta.ObjectMeta{
			Name: "oldNode",
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
		Spec: v1.NodeSpec{
			Unschedulable: true,
		},
		Status: v1.NodeStatus{
			Capacity: map[v1.ResourceName]resource.Quantity{
				v1.ResourceCPU:*resource.NewQuantity(1024, resource.DecimalSI),
				v1.ResourceMemory:*resource.NewQuantity(1024*1024, resource.DecimalSI),
				v1.ResourceStorage:*resource.NewQuantity(1024*1024*1024, resource.DecimalSI),
			},
			Allocatable: map[v1.ResourceName]resource.Quantity{
				v1.ResourceCPU:*resource.NewQuantity(1024, resource.DecimalSI),
				v1.ResourceMemory:*resource.NewQuantity(1024*1024, resource.DecimalSI),
				v1.ResourceStorage:*resource.NewQuantity(1024*1024*1024, resource.DecimalSI),
			},
			Conditions: []v1.NodeCondition{
				v1.NodeCondition{
					Type: v1.NodeReady,
					Status: v1.ConditionTrue,
				},
				v1.NodeCondition{
					Type: v1.NodeOutOfDisk,
					Status: v1.ConditionTrue,
				},
				v1.NodeCondition{
					Type: v1.NodeMemoryPressure,
					Status: v1.ConditionFalse,
				},
				v1.NodeCondition{
					Type: v1.NodeDiskPressure,
					Status: v1.ConditionUnknown,
				},
			},
		},
	}
	copy := orig.DeepCopy()
	return orig, copy
}

func nodeEqualsHelper(t *testing.T, oldNode *v1.Node, newNode *v1.Node, expected bool) {
	res := nodeEquals(oldNode, newNode)
	if res != expected  {
		t.Logf("nodeEquals expected %v, got %v", expected, res)
		t.Logf("oldNode: %#v", oldNode)
		t.Logf("newNode: %#v", newNode)
		t.Fail()
	}
}

func TestNodeEqualsUnchanged(t *testing.T) {
	oldNode, newNode := createNodeCopies()

	nodeEqualsHelper(t, oldNode, newNode, true)
}

func TestNodeEqualsName(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Name = "newNode"

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsLabelsExtra(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Labels["extra_key"] = "extra_val"

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsLabelsModified(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Labels["label_key1"] = "modified_val"

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func helperNodeEqualsAnnotationsExtra(t *testing.T, usePrometheus bool) {
	origVal := prometheusEnabled
	prometheusEnabled = usePrometheus;
	oldNode, newNode := createNodeCopies()
	newNode.Annotations["extra_key"] = "extra_val"

	nodeEqualsHelper(t, oldNode, newNode, !usePrometheus)
	prometheusEnabled = origVal
}

func TestNodeEqualsAnnotationsExtra(t *testing.T) {
	helperNodeEqualsAnnotationsExtra(t, true);
}

func TestNodeEqualsAnnotationsExtraPromDisabled(t *testing.T) {
	helperNodeEqualsAnnotationsExtra(t, false);
}

func helperNodeEqualsAnnotationsModified(t *testing.T, usePrometheus bool) {
	origVal := prometheusEnabled
	prometheusEnabled = usePrometheus;
	oldNode, newNode := createNodeCopies()
	newNode.Annotations["annotation_key1"] = "modified_val"

	nodeEqualsHelper(t, oldNode, newNode, !usePrometheus)
	prometheusEnabled = origVal
}

func TestNodeEqualsAnnotationsModified(t *testing.T) {
	helperNodeEqualsAnnotationsModified(t, true);
}

func TestNodeEqualsAnnotationsModifiedPromDisabled(t *testing.T) {
	helperNodeEqualsAnnotationsModified(t, false);
}

func TestNodeEqualsUnschedulable(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Spec.Unschedulable = !newNode.Spec.Unschedulable

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func modifyResourceList(t *testing.T, r v1.ResourceList) {
	target := v1.ResourceMemory
	modified, ok := r[target]
	if !ok {
		t.Errorf("Couldn't find %v in v1.ResourceList", target)
		t.FailNow()
	}
	modified.Add(*resource.NewQuantity(512, resource.DecimalSI))
	r[target] = modified
}

func TestNodeEqualsCapacity(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	modifyResourceList(t, newNode.Status.Capacity)

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsCapacityNull(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Status.Capacity = nil

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsAllocatable(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	modifyResourceList(t, newNode.Status.Allocatable)

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsAllocatableNull(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Status.Allocatable = nil

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func helperNodeEqualsConditions(t *testing.T,
	expType v1.NodeConditionType,
	expStatus v1.ConditionStatus,
	newStatus v1.ConditionStatus) {

	oldNode, newNode := createNodeCopies()
	for idx, _ := range newNode.Status.Conditions {
		if newNode.Status.Conditions[idx].Type == expType {
			if newNode.Status.Conditions[idx].Status != expStatus {
				t.Errorf("Expected %v for %v, %v instead", expStatus,
					newNode.Status.Conditions[idx].Type,
					newNode.Status.Conditions[idx].Status)
				t.FailNow()
			}
			newNode.Status.Conditions[idx].Status = newStatus
		}
	}

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsConditionsTrueToFalse(t *testing.T) {
	helperNodeEqualsConditions(t, v1.NodeOutOfDisk, v1.ConditionTrue, v1.ConditionFalse)
}

func TestNodeEqualsConditionsTrueToUnknown(t *testing.T) {
	helperNodeEqualsConditions(t, v1.NodeOutOfDisk, v1.ConditionTrue, v1.ConditionUnknown)
}

func TestNodeEqualsConditionsFalseToTrue(t *testing.T) {
	helperNodeEqualsConditions(t, v1.NodeMemoryPressure, v1.ConditionFalse, v1.ConditionTrue)
}

func TestNodeEqualsConditionsFalseToUnknown(t *testing.T) {
	helperNodeEqualsConditions(t, v1.NodeMemoryPressure, v1.ConditionFalse, v1.ConditionUnknown)
}

func TestNodeEqualsConditionsUnknownToTrue(t *testing.T) {
	helperNodeEqualsConditions(t, v1.NodeDiskPressure, v1.ConditionUnknown, v1.ConditionTrue)
}

func TestNodeEqualsConditionsUnknownToFalse(t *testing.T) {
	helperNodeEqualsConditions(t, v1.NodeDiskPressure, v1.ConditionUnknown, v1.ConditionFalse)
}

func TestNodeEqualsConditionsExtra(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Status.Conditions = append(newNode.Status.Conditions, v1.NodeCondition{})

	nodeEqualsHelper(t, oldNode, newNode, false)
}

func TestNodeEqualsConditionsNull(t *testing.T) {
	oldNode, newNode := createNodeCopies()
	newNode.Status.Conditions = []v1.NodeCondition{}

	nodeEqualsHelper(t, oldNode, newNode, false)
}
