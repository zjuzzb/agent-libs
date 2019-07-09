package kubecollect

import (
	"cointerface/draiosproto"
	"encoding/json"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	informers2 "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

var namespaceName string
var namespaceKind string
var namespaceUID string

func fixture() {
	// Inizialize globals
	namespaceName = "MytestNamespace"
	namespaceKind = "k8s_namespace"
	namespaceUID = namespaceName

	// Inizialize some variables used in kubecollect package
	// Make resource "namespace" ready
	startedMap = make(map[string]bool)
	startedMap["namespaces"] = true
	// Add a namespace in the namespace informer. Otherwise
	// AddNSParents does not work
	namespace := &v1.Namespace{
		TypeMeta: v1meta.TypeMeta{},
		ObjectMeta: v1meta.ObjectMeta{
			Name: namespaceName,
			UID: types.UID(namespaceUID),
		},
		Spec:   v1.NamespaceSpec{},
		Status: v1.NamespaceStatus{},
	}

	// Run the namespace informer with a fake client.
	// This is needed by AddNSParents to work properly
	client := fake.NewSimpleClientset()
	informers := informers2.NewSharedInformerFactory(client, 0)
	namespaceInf = informers.Core().V1().Namespaces().Informer()
	// Add the previously created namespace to the informer
	namespaceInf.GetStore().Add(namespace)
}


// if pointers argmument is false, do not instantiate pointer type members.
// This will help to test versus null pointer dereferencing
func createV1PersistentVolumeClaim(pointers bool)(*v1.PersistentVolumeClaim) {
	storageClassName := "StorageClassName"
	ret := &v1.PersistentVolumeClaim{
		ObjectMeta: v1meta.ObjectMeta {
			Name: string("SamePVC"),
			ResourceVersion: string("abcd"),
			Labels: map[string]string{
				"label_key1":"label_value1",
				"label_key2":"label_value2",
			},
		},

		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes:[]v1.PersistentVolumeAccessMode {
				v1.ReadWriteOnce,
			},
			VolumeName: "ATestVolume",
		},
		Status: v1.PersistentVolumeClaimStatus{
			Phase: v1.ClaimBound,
			AccessModes: [] v1.PersistentVolumeAccessMode {
					v1.ReadOnlyMany,
			},
			Capacity: v1.ResourceList{
				"storage": resource.MustParse("500M"),
			},
			Conditions: []v1.PersistentVolumeClaimCondition{
				{
					Type: v1.PersistentVolumeClaimConditionType(v1.PersistentVolumeClaimResizing),
					Status: v1.ConditionStatus(v1.ConditionUnknown),
					Reason: "NoSacciu",
					Message: "NoComment",
				},
			},
		},
	}

	ret.SetNamespace(namespaceName)

	if pointers == true {
		ret.Spec.StorageClassName = &storageClassName

		ret.Spec.Selector = &v1meta.LabelSelector{
			MatchLabels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			MatchExpressions: []v1meta.LabelSelectorRequirement{
				{
					Key:      "laChiave",
					Operator: v1meta.LabelSelectorOpIn,
					Values: []string {"maramao", "perche", "sei", "morto"},
				},
			},
		}

		vm := v1.PersistentVolumeBlock
		ret.Spec.VolumeMode = &vm

		ag := "apiGroup"
		ret.Spec.DataSource = &v1.TypedLocalObjectReference{
			APIGroup: &ag,
			Kind:     "",
			Name:     "",
		}
	}

	return ret
}

func create_pvc_label_key (name string) string {
	return "kubernetes.persistentvolumeclaim.label." + name
}

func getPVCExpected() *draiosproto.ContainerGroup {
	tags := make(map[string]string)
	tags[create_pvc_label_key("label_key1")] = "label_value1"
	tags[create_pvc_label_key("label_key2")] = "label_value2"
	tags[create_pvc_label_key("accessmode")] = "ReadWriteOnce"
	tags[create_pvc_label_key("volumename")] = "ATestVolume"
	tags[create_pvc_label_key("storageclassname")] = "StorageClassName"
	tags[create_pvc_label_key("status.phase")] = "Bound"
	tags[create_pvc_label_key("storage")] = "500M"
	tags["kubernetes.persistentvolumeclaim.name"] = "SamePVC"

	kind_pv := "k8s_persistentvolumeclaim"
	id_pv := ""
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind: &kind_pv,
			Id: &id_pv,
		},
		Tags: tags,
		Parents: []* draiosproto.CongroupUid {
			{
				Kind: &namespaceKind,
				Id: &namespaceName,
			},
		},
	}

	AppendMetricInt64(&ret.Metrics, "kubernetes.persistentvolumeclaim.storage", 500000000)
	return ret
}

func checkEquality(t *testing.T, expected *draiosproto.ContainerGroup, pvcCongroup *draiosproto.ContainerGroup) {
	if !areEqual(expected, pvcCongroup, t) {
		// For a better understanding of differences, output the two object
		// in json form
		tmp_exp, _ := json.Marshal(expected)
		tmp_act, _ := json.Marshal(pvcCongroup)
		t.Logf("Expected: %s\n\nActual: %s", string(tmp_exp), string(tmp_act))
		t.Fail()
	}
}

func TestPVCCreation(t *testing.T) {
	fixture()
	pvcCongroup := newPersistentVolumeClaimCongroup(createV1PersistentVolumeClaim(true))
	expected := getPVCExpected()

	checkEquality(t, expected, pvcCongroup)

	// Now creates pvc leaving all pointers as nil
	nilPvcCongroup := newPersistentVolumeClaimCongroup(createV1PersistentVolumeClaim(false))
	// nilPvcCongoup created with pointers false does not have StorageClassName
	delete(expected.Tags, create_pvc_label_key("storageclassname"))
	checkEquality(t, expected, nilPvcCongroup)
}
