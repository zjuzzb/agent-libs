package kubecollect_common

import "testing"

func TestMapInsert(t *testing.T) {
	var m map[string]string

	MapInsert(&m, "good", "bye")

	if m["good"] != "bye" {
		t.Fail()
	}
}
