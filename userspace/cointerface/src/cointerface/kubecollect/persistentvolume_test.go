package kubecollect

import (
	"cointerface/draiosproto"
	"encoding/json"
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"testing"
)

func createV1PersistentVolume()(*v1.PersistentVolume) {
	ret := &v1.PersistentVolume{
		ObjectMeta: v1meta.ObjectMeta {
			Name: string("SamePV"),
			ResourceVersion: string("abcd"),
			Labels: map[string]string{
				"label_key1":"label_value1",
				"label_key2":"label_value2",
			},
		},

		Spec: v1.PersistentVolumeSpec {
			Capacity: v1.ResourceList{
				"storage": resource.MustParse("500M"),

			},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				GCEPersistentDisk: &v1.GCEPersistentDiskVolumeSource{},
			},
			AccessModes: []v1.PersistentVolumeAccessMode {
				v1.ReadWriteOnce,
			},
			StorageClassName: "StorageClassName",
			MountOptions: []string {"ro", "soft"},
			PersistentVolumeReclaimPolicy: v1.PersistentVolumeReclaimPolicy(
				v1.PersistentVolumeReclaimRecycle,
			),
			ClaimRef: &v1.ObjectReference{
				Kind: "persistentvolumeclaim",
				Name: "MiAllippai",
			},

		},
		Status: v1.PersistentVolumeStatus{
			Phase: v1.VolumeBound,
			Message: "vattene amore",
			Reason: "mio barbaro invasore",
		},
	}
	return ret
}

func create_label_key (name string) string {
	return "kubernetes.persistentvolume.label." + name
}

func getExpected() *draiosproto.ContainerGroup {
	tags := make(map[string]string)
	tags[create_label_key("label_key1")] = "label_value1"
	tags[create_label_key("label_key2")] = "label_value2"
	tags[create_label_key("storageclass")] = "StorageClassName"
	tags[create_label_key("status.phase")] = "Bound"
	tags[create_label_key("claim")] = "MiAllippai"
	tags[create_label_key("reclaimpolicy")] = "Recycle"
	tags[create_label_key("accessmode")] = "ReadWriteOnce"
	tags[create_label_key("source.type")] = "GCEPersistentDisk"
	tags["kubernetes.persistentvolume.name"] = "SamePV"

	ret := &draiosproto.ContainerGroup{
		Uid:                  &draiosproto.CongroupUid{
			Kind:                 proto.String("k8s_persistentvolume"),
			Id:                   proto.String(""),
		},
		Tags:                 tags,
	}

	AppendMetricInt64(&ret.Metrics, "kubernetes.persistentvolume.storage", 500000000)
	AppendMetricInt32(&ret.Metrics, "kubernetes.persistentvolume.count", 1)

	return ret
}

func areEqual(expected *draiosproto.ContainerGroup, actual  *draiosproto.ContainerGroup, t* testing.T) bool {
	ret := false

	if reflect.DeepEqual(expected, actual) {
		ret = true
	}

	return ret
}

func TestCoGroupCreation(t *testing.T) {
	pvCongroup := newPersistentVolumeCongroup(createV1PersistentVolume())

	expected := getExpected()
	if !areEqual(expected, pvCongroup, t) {
		// For a better understanding of differences, output the two object
		// in json form
		tmp_exp, _ := json.Marshal(expected)
		tmp_act, _ := json.Marshal(pvCongroup)
		t.Logf("Expected: %s\n\nActual: %s", string(tmp_exp), string(tmp_act))
		t.Fail()
	}

}

// Test that newPersistentVolumeCongroup when ClaimRef is nil (SMAGENT-1579)
// works without errors
func TestClaimRefNil(t *testing.T) {
	pv := createV1PersistentVolume()
	pv.Spec.ClaimRef = nil
	newPersistentVolumeCongroup(pv)
}