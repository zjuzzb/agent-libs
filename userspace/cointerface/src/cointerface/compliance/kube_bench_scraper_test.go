package compliance

import (
	"github.com/draios/protorepo/sdc_internal"
	"os"
	draiosproto "protorepo/agent-be/proto"
	"reflect"
	"testing"
	"time"
)

func TestKubeBenchImpl_GenArgs(t *testing.T) {
	kbImpl := KubeBenchImpl{
		customerId: "1",
		machineId:  "2",
		variant:    "node",
	}
	var x uint64 = 1
	tName := "test"
	tEnabled := true
	tParamKey := "benchmark"
	tParamVal := "cis-1.6"
	tParam := draiosproto.CompTaskParam{
		Key: &tParamKey,
		Val: &tParamVal,
	}
	task := draiosproto.CompTask{
		Id:                   &x,
		Name:                 &tName,
		ModName:              &tName,
		Enabled:              &tEnabled,
		ScopePredicates:      nil,
		Schedule:             nil,
		TaskParams:           []*draiosproto.CompTaskParam{&tParam},
		XXX_NoUnkeyedLiteral: struct{}{},
		XXX_unrecognized:     nil,
		XXX_sizecache:        0,
	}
	sTask := ScheduledTask{
		mgr:          nil,
		task:         &task,
		cmd:          nil,
		cmdStartTime: time.Time{},
		module:       nil,
		env:          nil,
		intervals:    nil,
	}

	res, err := kbImpl.GenArgs(&sTask)
	if err != nil {
		t.Fatal(err)
	}
	expect := []string{"--json", "--benchmark", "cis-1.6", "run", "--targets", "node,policies"}
	if !reflect.DeepEqual(res, expect) {
		t.Fatalf("expected: %v, got %v", expect, res)
	}

	kbImpl.variant = "master"
	res, err = kbImpl.GenArgs(&sTask)
	if err != nil {
		t.Fatal(err)
	}
	expect = []string{"--json", "--benchmark", "cis-1.6", "run", "--targets", "master,controlplane,etcd,policies"}
	if !reflect.DeepEqual(res, expect) {
		t.Fatalf("expected: %v, got %v", expect, res)
	}

	task.TaskParams = nil
	res, err = kbImpl.GenArgs(&sTask)
	if err != nil {
		t.Fatal(err)
	}
	expect = []string{"--json", "master"}
	if !reflect.DeepEqual(res, expect) {
		t.Fatalf("expected: %v, got %v", expect, res)
	}

	_, err = os.Stat("../stdout.txt")
	if !os.IsNotExist(err) {
		events := make(chan *sdc_internal.CompTaskEvent)

		testF := func() {
			err1 := kbImpl.Scrape("../", "", &task, true, events)
			if err1 != nil {
				t.Fatal(err1)
			}
		}

		go testF()
		event := <-events
		t.Logf("results: %v", *event.Results.Results[0].ExtResult)
	}
}
