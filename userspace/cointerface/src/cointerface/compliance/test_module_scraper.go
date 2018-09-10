package compliance

import (
	"cointerface/draiosproto"
	"cointerface/sdc_internal"
	"fmt"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	"strconv"
	"time"
)

func (impl *TestModuleImpl) GenArgs(task *draiosproto.CompTask) ([]string, error) {
	sleepTime := "5"

	for _, param := range task.TaskParams {
		if *param.Key == "sleepTime" {
			sleepTime = *param.Val
		}
	}

	return []string{sleepTime}, nil
}

func (impl *TestModuleImpl) ShouldRun(task *draiosproto.CompTask) (bool, error) {
	return true, nil
}

type TestModuleImpl struct {
	customerId string `json:"customerId"`
	machineId string `json:"machineId"`
}

func (impl *TestModuleImpl) Scrape(rootPath string, moduleName string,
	task *draiosproto.CompTask,
	evtsChannel chan *sdc_internal.CompTaskEvent,
	metricsChannel chan string) error {

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
		TaskName: proto.String(*task.Name),
		Successful: proto.Bool(true),
	}

	events := &draiosproto.CompEvents{
		MachineId: proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	fields := map[string]string {
		"task": *task.Name,
		"iter": curIter,
	}

	event := &draiosproto.CompEvent{
		TimestampNs: proto.Uint64(uint64(time.Now().UnixNano())),
		TaskName: proto.String(*task.Name),
		ContainerId: proto.String("test-container"),
		Output: proto.String(fmt.Sprintf("test output (task=%s iter=%s)",
			*task.Name,
			curIter)),
		OutputFields: fields,
	}

	events.Events = append(events.Events, event)

	evt.Events = events

	results := &draiosproto.CompResults{
		MachineId: proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	result := &draiosproto.CompResult{
		TimestampNs: proto.Uint64(uint64(time.Now().UnixNano())),
		TaskName: proto.String(*task.Name),
		TestsRun: proto.Uint32(uint32(curIterNum)),
		TestsPassed: proto.Uint32(uint32(curIterNum)),
		Risk: proto.String("low"),
		OutputFields: proto.String(fmt.Sprintf("{\"task\":\"%s\", \"iter\": %s}",
			*task.Name,
			curIter)),
	};

	results.Results = append(results.Results, result)

	evt.Results = results

	log.Debugf("Sending test-module comp_evt: %v", evt)

	evtsChannel <- evt

	metrics := []string{}

	// This is a bit unlike the docker/k8s scrapers where the
	// metrics are independent of task name. We include the task
	// name here to make tests easier
	metrics = append(metrics, fmt.Sprintf("compliance.%s:tests_pass:%s|g", *task.Name, curIter))

	for _, metric := range metrics {
		log.Debugf("Sending test-module metric: %v", metric)
		metricsChannel <- metric
	}

	return nil
}
