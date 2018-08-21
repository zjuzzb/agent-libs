package kubecollect
import (
	"testing"
	"k8s.io/api/extensions/v1beta1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Creates two replicaset objects that are DeepEqual
func createReplicaSetCopies() (*v1beta1.ReplicaSet, *v1beta1.ReplicaSet) {
	var numReplicas int32 = 5
	orig := &v1beta1.ReplicaSet{
		ObjectMeta: v1meta.ObjectMeta{
			Name: "oldReplicaSet",
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
		Spec: v1beta1.ReplicaSetSpec{
			Replicas: &numReplicas,
		},
		Status: v1beta1.ReplicaSetStatus{
			Replicas: numReplicas,
			FullyLabeledReplicas: numReplicas,
			ReadyReplicas: numReplicas,
		},
	}
	copy := orig.DeepCopy()
	return orig, copy
}

func replicaSetEqualsHelper(t *testing.T, old *v1beta1.ReplicaSet, new *v1beta1.ReplicaSet, expected bool) {
	sameEntity, sameLinks := replicaSetEquals(old, new)
	res := sameEntity && sameLinks
	if (!sameLinks && sameEntity) || (res != expected)  {
		t.Logf("replicaSetEquals expected %v, got %v", expected, res)
		t.Logf("sameEntity is %v, sameLinks is %v", sameEntity, sameLinks)
		t.Logf("oldReplicaSet: %#v", old)
		t.Logf("newReplicaSet: %#v", new)
		t.Fail()
	}
}

func TestReplicaSetEqualsUnchanged(t *testing.T) {
	old, new := createReplicaSetCopies()

	replicaSetEqualsHelper(t, old, new, true)
}

func TestReplicaSetEqualsName(t *testing.T) {
	old, new := createReplicaSetCopies()
	new.Name = "newReplicaSet"

	replicaSetEqualsHelper(t, old, new, false)
}

func TestReplicaSetEqualsSpecReplicas(t *testing.T) {
	old, new := createReplicaSetCopies()
	*new.Spec.Replicas = int32(2)

	replicaSetEqualsHelper(t, old, new, false)
}

func TestReplicaSetEqualsSpecReplicasNil(t *testing.T) {
	old, new := createReplicaSetCopies()
	new.Spec.Replicas = nil

	replicaSetEqualsHelper(t, old, new, false)
}

func TestReplicaSetEqualsStatusReplicas(t *testing.T) {
	old, new := createReplicaSetCopies()
	new.Status.Replicas = 2

	replicaSetEqualsHelper(t, old, new, false)
}

func TestReplicaSetEqualsStatusFullyLabeledReplicas(t *testing.T) {
	old, new := createReplicaSetCopies()
	new.Status.FullyLabeledReplicas = 2

	replicaSetEqualsHelper(t, old, new, false)
}

func TestReplicaSetEqualsStatusReadyReplicas(t *testing.T) {
	old, new := createReplicaSetCopies()
	new.Status.ReadyReplicas = 2

	replicaSetEqualsHelper(t, old, new, false)
}
