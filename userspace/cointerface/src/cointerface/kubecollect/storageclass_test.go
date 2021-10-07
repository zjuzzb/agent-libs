package kubecollect

import (
	"encoding/json"
	"github.com/gogo/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	draiosproto "protorepo/agent-be/proto"
	"testing"
	"time"
)

func TestNewStorageClassCongroup(t *testing.T) {
	cases := []struct {
		name                      string
		namespace                 string
		uid                       types.UID
		creationTs                time.Time
		labels                    map[string]string
		annotations               map[string]string
		provisioner               string
		reclaimPolicy             v1.PersistentVolumeReclaimPolicy
		volumeBindignMode         storagev1.VolumeBindingMode
		expectedReclaimPolicy     draiosproto.K8SStorageClassReclaimPolicy
		expectedVolumeBindingMode draiosproto.K8SVolumeBindingMode
	}{
		{
			name:       "scname",
			namespace:  "scnamespace",
			uid:        types.UID("scuid"),
			creationTs: time.Unix(100, 0),
			labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			annotations: map[string]string{
				"annKey1": "annValue1",
			},
			provisioner:               "AWS-DA-PLAYA",
			reclaimPolicy:             v1.PersistentVolumeReclaimRecycle,
			volumeBindignMode:         storagev1.VolumeBindingImmediate,
			expectedReclaimPolicy:     draiosproto.K8SStorageClassReclaimPolicy_STORAGE_CLASS_RECLAIM_POLICY_RECYCLE,
			expectedVolumeBindingMode: draiosproto.K8SVolumeBindingMode_VOLUME_BINDING_MODE_IMMEDIATE,
		},
		{
			name:                      "scname",
			namespace:                 "scnamespace",
			uid:                       types.UID("scuid"),
			creationTs:                time.Unix(100, 0),
			labels:                    nil,
			annotations:               nil,
			provisioner:               "AWS-DA-PLAYA",
			reclaimPolicy:             v1.PersistentVolumeReclaimDelete,
			volumeBindignMode:         storagev1.VolumeBindingImmediate,
			expectedReclaimPolicy:     draiosproto.K8SStorageClassReclaimPolicy_STORAGE_CLASS_RECLAIM_POLICY_DELETE,
			expectedVolumeBindingMode: draiosproto.K8SVolumeBindingMode_VOLUME_BINDING_MODE_IMMEDIATE,
		},
	}

	for k, currentCase := range cases {
		k8sObj := storagev1.StorageClass{
			ObjectMeta: v1meta.ObjectMeta{
				Name:              currentCase.name,
				Namespace:         currentCase.namespace,
				UID:               currentCase.uid,
				CreationTimestamp: v1meta.Time{currentCase.creationTs},
				Labels:            currentCase.labels,
				Annotations:       currentCase.annotations,
			},
			Provisioner:       currentCase.provisioner,
			ReclaimPolicy:     &currentCase.reclaimPolicy,
			VolumeBindingMode: &currentCase.volumeBindignMode,
		}

		cg, err := newStorageClassConGroup(&k8sObj)

		if err != nil {
			t.Logf("Test case %d failed", k)
		}

		const KIND = "k8s_storageclass"
		expectedCg := draiosproto.ContainerGroup{
			Uid: &draiosproto.CongroupUid{
				Kind: proto.String(KIND),
				Id:   proto.String(string(currentCase.uid)),
			},
			Tags:      nil,
			Namespace: proto.String(currentCase.namespace),
			K8SObject: &draiosproto.K8SType{TypeList: &draiosproto.K8SType_Sc{Sc: &draiosproto.K8SStorageClass{
				Common: &draiosproto.K8SCommon{
					Name:      proto.String(currentCase.name),
					Uid:       proto.String(string(currentCase.uid)),
					Namespace: proto.String(currentCase.namespace),
				},
				Created:           proto.Uint32(uint32(currentCase.creationTs.Unix())),
				Provisioner:       proto.String(currentCase.provisioner),
				ReclaimPolicy:     &currentCase.expectedReclaimPolicy,
				VolumeBindingMode: &currentCase.expectedVolumeBindingMode,
			}}},
		}

		tags := make(map[string]string)
		for key, val := range currentCase.labels {
			tags["kubernetes.storageclass.label."+key] = val
		}
		tags["kubernetes.storageclass.name"] = currentCase.name
		expectedCg.Tags = tags

		if !proto.Equal(&expectedCg, cg) {
			expectedJson, _ := json.Marshal(expectedCg)
			actualJson, _ := json.Marshal(cg)
			t.Logf("test %d failed\nExpected: %s\nActual: %s", k, expectedJson, actualJson)
			t.Fail()
		}
	}
}
