package kubecollect
import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoInformersLib "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/draios/protorepo/draiosproto"
)

var rsTestreplicaset coReplicaSet

func replicaset_fixture() {
	// Initialize some variables used in kubecollect package
	if startedMap == nil {
		startedMap = make(map[string]bool)
	}

	// Make resource "pod" ready
	startedMap["pods"] = true

	// Create a selector cache
	deploySelectorCache = newSelectorCache()

	// Run the pod informer with a fake client.
	// This is needed by AddPodChildrenFromOwnerRef to work properly
	client := fake.NewSimpleClientset()
	informers := clientgoInformersLib.NewSharedInformerFactory(client, 0)
	podInf = informers.Core().V1().Pods().Informer()
	rsTestreplicaset, _ = createReplicaSetCopies()
	podOwned, podNotOwned := createPodCopies()

	isController := true

	// Change pods a little bit
	podOwned.OwnerReferences = append(podOwned.OwnerReferences, metav1.OwnerReference{
		APIVersion:         "",
		Kind:               "Replicaset",
		Name:               rsTestreplicaset.GetName(),
		UID:                rsTestreplicaset.GetUID(),
		Controller:         &isController,
		BlockOwnerDeletion: nil,
	})
	podNotOwned.OwnerReferences = append(podNotOwned.OwnerReferences, metav1.OwnerReference{
		APIVersion:         "",
		Kind:               "Replicaset",
		Name:               "Maramap",
		UID:                "percheSeiMorto",
		Controller:         &isController,
		BlockOwnerDeletion: nil,
	})

	podNotOwned.UID = "pastaCaSassa"
	podNotOwned.Name = "BondJamesBond"
	podOwned.UID = "podOwnedUID"
	podOwned.Name = "podOwnedName"

	// Add the pods in the informe
	podInf.GetStore().Add(podOwned)
	podInf.GetStore().Add(podNotOwned)
}

// Creates two replicaset objects that are DeepEqual
func createReplicaSetCopies() (coReplicaSet, coReplicaSet) {
	var numReplicas int32 = 5
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
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
		Spec: appsv1.ReplicaSetSpec{
			Replicas: &numReplicas,
		},
		Status: appsv1.ReplicaSetStatus{
			Replicas: numReplicas,
			FullyLabeledReplicas: numReplicas,
			ReadyReplicas: numReplicas,
		},
	}

	orig := coReplicaSet{ ReplicaSet: rs }
	copy := coReplicaSet{ ReplicaSet: rs.DeepCopy() }
	return orig, copy
}

func replicaSetEqualsHelper(t *testing.T, old coReplicaSet, new coReplicaSet, expected bool) {
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

func TestAddPodChildrenFromOwnerRef(t *testing.T) {
	var children []*draiosproto.CongroupUid
	AddPodChildrenFromOwnerRef(&children, rsTestreplicaset.ObjectMeta)

	if len(children) != 1 && *children[0].Id != "podOwnedUID" {
		t.Fail()
	}
}
