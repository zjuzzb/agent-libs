package kubecollect

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)



func createResourceQuotaCopies() (*v1.ResourceQuota, *v1.ResourceQuota) {
	orig := &v1.ResourceQuota{
		ObjectMeta: v1meta.ObjectMeta{
			Name: "oldResourceQuota",
			Labels: map[string]string {
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
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				"limits.cpu": *resource.NewQuantity(100, resource.DecimalSI),
				"configmap": *resource.NewMilliQuantity(10, resource.DecimalSI),
			},
		},
		Status: v1.ResourceQuotaStatus{
			Hard: v1.ResourceList{},
			Used: v1.ResourceList{
				"limits.cpu": *resource.NewQuantity(1, resource.DecimalSI),
				"configmaps": *resource.NewMilliQuantity(2, resource.DecimalSI),
			},
		},
	}
	copy := orig.DeepCopy()
	return orig, copy
}

func resourceQuotaEqualHelper(t *testing.T, oldResourceQuota *v1.ResourceQuota, newResourceQuota *v1.ResourceQuota, expected bool) {
	res := resourceQuotaEquals(oldResourceQuota, newResourceQuota)
	if res != expected {
		t.Logf("resourceQuotaEquals expected %v, got %v", expected, res)
		t.Logf("oldResourceQuota: %#v", oldResourceQuota)
		t.Logf("newResourceQuota: %#v", newResourceQuota)
		t.Fail()
	}
}

func TestResourceQuotaEqualsUnchanged(t *testing.T) {
	old, new := createResourceQuotaCopies()

	resourceQuotaEqualHelper(t, old, new, true)
}

func TestResourceQuotaEqualsNames(t *testing.T) {
	old, new := createResourceQuotaCopies()
	new.Name = "ANewName"

	resourceQuotaEqualHelper(t, old, new, false)
}

func TestResourceQuotaEqualsLabelsExtra(t *testing.T) {
	old, new := createResourceQuotaCopies()

	new.Labels["anotherOne"] = "anotherOne"
	resourceQuotaEqualHelper(t, old, new, false)
}

func TestResourceQuotaEqualsLabelsModified(t *testing.T) {
	old, new := createResourceQuotaCopies()
	new.Labels["label_key1"] = "modified"

	resourceQuotaEqualHelper(t, old, new, false)
}

func TestResourceQuotaEqualsChangedCPU(t *testing.T) {
	old, new := createResourceQuotaCopies()
	new.Status.Used["limits.cpu"] = *resource.NewQuantity(62, resource.DecimalSI)

	resourceQuotaEqualHelper(t, old, new, false)
}

func TestReourcceQuotaEqualsChangedConfigMaps(t *testing.T) {
	old, new := createResourceQuotaCopies()
	new.Status.Used["cofigmaps"] = *resource.NewQuantity(3, resource.DecimalSI)

	resourceQuotaEqualHelper(t, old, new, false)

}

func TestResourceQuotaEqualsAddedAResource(t *testing.T) {
	old, new := createResourceQuotaCopies()
	new.Status.Used["aNewResource"] = *resource.NewQuantity(1, resource.DecimalSI)

	resourceQuotaEqualHelper(t, old, new, false)
}
