package compliance

import (
	"encoding/json"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	draiosproto "protorepo/agent-be/proto"
	"strconv"
	"time"
)

func (impl *TestModuleImpl) GenArgs(stask *ScheduledTask) ([]string, error) {
	sleepTime := "5"
	rc := "0"

	for _, param := range stask.task.TaskParams {
		if *param.Key == "sleepTime" {
			sleepTime = *param.Val
		}
		if *param.Key == "rc" {
			rc = *param.Val
		}
	}

	return []string{"run.sh", sleepTime, rc}, nil
}

func (impl *TestModuleImpl) ShouldRun(stask *ScheduledTask) bool {
	return true
}

type TestModuleImpl struct {
	customerId string `json:"customerId"`
	machineId  string `json:"machineId"`
}

func (impl *TestModuleImpl) Scrape(rootPath string, moduleName string,
	task *draiosproto.CompTask,
	includeDesc bool,
	evtsChannel chan *sdc_internal.CompTaskEvent) error {

	// Look for a parameter named "iter". This is used to change
	// the output slightly from one task to another.
	curIter := "1"
	for _, param := range task.TaskParams {
		if *param.Key == "iter" {
			curIter = *param.Val
		}
	}

	curIterNum, err := strconv.ParseUint(curIter, 10, 32)

	if err != nil {
		return err
	}

	log.Debugf("Scraping output for task %s iter %s",
		*task.Name,
		curIter)

	evt := &sdc_internal.CompTaskEvent{
		TaskName:       proto.String(*task.Name),
		InitSuccessful: proto.Bool(true),
	}

	events := &draiosproto.CompEvents{
		MachineId:  proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	fields := map[string]string{
		"task": *task.Name,
		"iter": curIter,
	}

	event := &draiosproto.CompEvent{
		TimestampNs: proto.Uint64(uint64(time.Now().UnixNano())),
		TaskName:    proto.String(*task.Name),
		ContainerId: proto.String("test-container"),
		Output: proto.String(fmt.Sprintf("test output (task=%s iter=%s)",
			*task.Name,
			curIter)),
		OutputFields: fields,
	}

	events.Events = append(events.Events, event)

	evt.Events = events

	results := &draiosproto.CompResults{
		MachineId:  proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	result := &ExtendedTaskResult{
		Id:          *task.Id,
		TimestampNS: uint64(time.Now().UnixNano()),
		HostMac:     impl.machineId,
		TaskName:    *task.Name,
		TestsRun:    uint64(curIterNum),
		PassCount:   uint64(curIterNum),
		FailCount:   0,
		WarnCount:   0,
		Risk:        low,
	}

	section := &TaskResultSection{
		SectionId: "1",
		TestsRun:  uint64(curIterNum),
		PassCount: uint64(curIterNum),
		FailCount: 0,
		WarnCount: 0,
	}

	test := &TaskResultTest{
		TestNumber: "1.1",
		Details:    curIter,
	}

	section.Results = append(section.Results, *test)
	result.Tests = append(result.Tests, *section)

	ofbytes, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Could not serialize test result: %v", err.Error())
		return err
	}

	comp_result := &draiosproto.CompResult{
		TimestampNs: proto.Uint64(result.TimestampNS),
		TaskName:    proto.String(result.TaskName),
		ModName:     task.ModName,
		TaskId:      proto.Uint64(result.Id),
		Successful:  proto.Bool(true),
		ExtResult:   proto.String(string(ofbytes[:])),
	}

	results.Results = append(results.Results, comp_result)

	metrics := []string{}

	// This is a bit unlike the docker/k8s scrapers where the
	// metrics are independent of task name. We include the task
	// name here to make tests easier
	metrics = append(metrics, fmt.Sprintf("compliance.%s:tests_pass:%s|g", *task.Name, curIter))

	evt.Results = results
	evt.Metrics = metrics

	log.Debugf("Sending test-module comp_evt: %v", evt)

	evtsChannel <- evt

	return nil
}
