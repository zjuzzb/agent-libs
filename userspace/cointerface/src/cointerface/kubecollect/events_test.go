package kubecollect

import (
	"testing"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/draios/protorepo/sdc_internal"
)

func makeInvolvedObject() v1.ObjectReference {
	return v1.ObjectReference{
		Kind:            "Pod",
		Namespace:       "default",
		Name:            "sysdig-agent-abcde",
		UID:             "400959da-1234-5678-b90f-2d1ddaccd694",
		APIVersion:      "v1",
		ResourceVersion: "107288",
		FieldPath:       "spec.containers{sysdig-agent}",
	}
}

func makeV1EventObject() *v1.Event {

	obj := makeInvolvedObject()

	return &v1.Event{
		InvolvedObject: obj,
		Reason:         "Test Event",
		Message:        "Let's test time stamps",
		FirstTimestamp: metav1.NewTime(time.Date(2010, time.October, 10, 0, 0, 0, 0, time.UTC)),
		LastTimestamp:  metav1.NewTime(time.Date(2010, time.October, 10, 0, 0, 0, 0, time.UTC)),
		Count:          1,
		Type:           "Normal",
	}
}

func TestNewUserEvent(t *testing.T) {
	// This test ensures "LastTimestamp" is a valid
	// field no matter what values exist in EventTime
	// and LastTimestamp fields

	var k8sUserEvt sdc_internal.K8SUserEvent

	// Make a k8s user event object
	v1evt := makeV1EventObject()
	// Make eventTime a bogus value
	v1evt.EventTime = metav1.NewMicroTime(time.Date(0001, time.January, 1, 0, 0, 0, 0, time.UTC))
	k8sUserEvt = newUserEvent(v1evt)

	// Check to make sure a valid time stamp exists
	if *(k8sUserEvt.LastTimestamp) < int64(0) {
		t.Errorf("LastTimestamp is negative : %v", *(k8sUserEvt.LastTimestamp))
		t.Fail()
	}

	// Now mangle values of LastTimestamp also
	v1evt.LastTimestamp = metav1.NewTime(time.Date(0001, time.January, 1, 0, 0, 0, 0, time.UTC))
	k8sUserEvt = newUserEvent(v1evt)
	if *(k8sUserEvt.LastTimestamp) < int64(0) {
		t.Errorf("LastTimestamp is negative : %v", *(k8sUserEvt.LastTimestamp))
		t.Fail()
	}
}
