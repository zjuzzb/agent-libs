package compliance

import (
	"cointerface/draiosproto"
	"cointerface/sdc_internal"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ModuleMgr struct {
	ModulesDir string `json:"modules_dir"`
	initialized bool
	customerId string
	machineId string
	Calendar *draiosproto.CompCalendar
	Tasks map[uint64]*draiosproto.CompTask
	IncludeDesc bool
	SendFailedResults bool
	SaveTempFiles bool
	availModules map[string]*Module
	evtsChannel chan *sdc_internal.CompTaskEvent
	metricsChannel chan string
	metricsResetChannel chan bool

	// A cancel function used to cancel background operations
	// spawned in Start()
	cancel context.CancelFunc

	scheduleRegexp *regexp.Regexp
	scheduleRegexpNames []string

	scheduleListRegexp *regexp.Regexp
}

func emitStatsdForever(mgr *ModuleMgr) {

	conn, err := net.Dial("udp", "127.0.0.1:8125")
	if err != nil {
		log.Errorf("Could not connect to 127.0.0.1:8125 (%v)", err.Error());
	}

	// Maps from metric name to complete statsd line
	cur_metrics := make(map[string]string)

	for {
		// Every second, wake up and send new
		// metrics. Otherwise, accept new metrics from
		// metricsChannel as they become available.
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case metric := <- mgr.metricsChannel:
				parts := strings.Split(metric, ":")
				cur_metrics[parts[0]] = metric

				// Also send the metric immediately
				log.Debugf("Writing to statsd: %v", string(metric))
				_, err := conn.Write([]byte(metric + "\n"))
				if err != nil {
					log.Errorf("Could not send metrics to 127.0.0.1:8125 (%v)", err.Error())
				}
			case <- mgr.metricsResetChannel:
				cur_metrics = make(map[string]string)
			case <-ticker.C:
				// Send the current set of metrics
				for _, metric := range cur_metrics {
					log.Debugf("Writing to statsd: %v", string(metric))
					_, err := conn.Write([]byte(metric + "\n"))
					if err != nil {
						log.Errorf("Could not send metrics to 127.0.0.1:8125 (%v)", err.Error())
					}
				}
			}
		}
	}
}

func (mgr *ModuleMgr) FailResult(stask *ScheduledTask, err error) {

	if !mgr.SendFailedResults {
		return
	}

	timestamp_ns := uint64(time.Now().UnixNano())

	// In this struct, CallSuccessful refers to the grpc, not the
	// execution of any task.
	evt := &sdc_internal.CompTaskEvent{
		TaskName: stask.task.Name,
		CallSuccessful: proto.Bool(true),
	}

	results := &draiosproto.CompResults{
		MachineId: proto.String(mgr.machineId),
		CustomerId: proto.String(mgr.customerId),
	}

	comp_result := &draiosproto.CompResult{
		TimestampNs: proto.Uint64(timestamp_ns),
		TaskName: stask.task.Name,
		ModName: stask.task.ModName,
		TaskId: stask.task.Id,
		Successful: proto.Bool(false),
		FailureDetails: proto.String(err.Error()),
	};

	results.Results = append(results.Results, comp_result)
	evt.Results = results

	mgr.evtsChannel <- evt
}

func (mgr *ModuleMgr) Init(customerId string, machineId string) error {
	mgr.Tasks = make(map[uint64]*draiosproto.CompTask)
	mgr.availModules = make(map[string]*Module)
	mgr.evtsChannel = make(chan *sdc_internal.CompTaskEvent, 1000)
	mgr.metricsChannel = make(chan string, 1000)
	mgr.metricsResetChannel = make(chan bool)
	mgr.machineId = machineId
	mgr.customerId = customerId

	mgr.availModules["docker-bench-security"] = &Module{
		Name: "docker-bench-security",
		Prog: "bash",
		Impl: &DockerBenchImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	mgr.availModules["kube-bench"] = &Module{
		Name: "kube-bench",
		Prog: "MODULE_DIR/kube-bench",
		Impl: &KubeBenchImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	mgr.availModules["test-module"] = &Module{
		Name: "test-module",
		Prog: "MODULE_DIR/run.sh",
		Impl: &TestModuleImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	mgr.availModules["fail-module"] = &Module{
		Name: "fail-module",
		Prog: "MODULE_DIR/not-runnable",
		Impl: &TestModuleImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	// Start a goroutine that reads from the metrics channel and
	// forwards to statsd
	go emitStatsdForever(mgr)

	mgr.initialized = true

	return nil
}

// Generally errors related to the Module Manager itself are returned
// as errors from the function. Errors related to a given task
// (improperly formed calendar, bad module, etc). are returned as
// CompTaskEvents with successful=false.

func (mgr *ModuleMgr) Start(start *sdc_internal.CompStart, stream sdc_internal.ComplianceModuleMgr_StartServer) error {
	log.Debugf("Received Start message: %s", start.String())

	if ! mgr.initialized {
		if start.CustomerId == nil || start.MachineId == nil {
			return fmt.Errorf("Start() without a prior Load() must contain customer id/machine id")
		}

		if err := mgr.Init(*start.CustomerId, *start.MachineId); err != nil {
			return err
		}
	}

	if mgr.cancel != nil {
		// Start() was previously called. Stop those tasks first.
		mgr.cancel()
		mgr.cancel = nil
	}

	mgr.Calendar = start.Calendar
	mgr.IncludeDesc = start.GetIncludeDesc()
	mgr.SendFailedResults = start.GetSendFailedResults()
	mgr.SaveTempFiles = start.GetSaveTempFiles()
	mgr.Tasks = make(map[uint64]*draiosproto.CompTask)

	ctx, cancel := context.WithCancel(context.Background())

	mgr.cancel = cancel

	for _, module := range mgr.availModules {
		module.RunModules(ctx)
	}

	for _, task := range mgr.Calendar.Tasks {

		var stask *ScheduledTask
		var err error

		mgr.Tasks[*task.Id] = task

		module, ok := mgr.availModules[*task.ModName]
		if ! ok {
			err = fmt.Errorf("Module %s does not exist",
				*task.ModName)
		} else if _, err = os.Stat(path.Join(mgr.ModulesDir, *task.ModName)); os.IsNotExist(err) {
			err = fmt.Errorf("Path for module %s not found",
				*task.ModName)
		} else {
			stask = NewScheduledTask(mgr, task, module.Env(mgr))
			log.Debugf("Parsing schedule %s", *task.Schedule)
			err = stask.ParseSchedule(*task.Schedule, time.Now())
		}

		if err != nil {
			evt := &sdc_internal.CompTaskEvent{
				TaskName: task.Name,
				CallSuccessful: proto.Bool(false),
				Errstr: proto.String(fmt.Sprintf("Could not schedule task %s: %s", *task.Name, err.Error())),
			}

			log.Errorf("Could not schedule task %s: %s", *task.Name, err.Error())

			if err := stream.Send(evt); err != nil {
				log.Errorf("Could not send event %s: %v",
					evt.String(), err.Error())
				mgr.Calendar = nil
				return err
			}

		} else {

			log.Debugf("Scheduling task %s", *task.Name)
			go stask.RunForever(ctx)
		}
	}

	log.Infof("Starting all tasks")

	// Now wait forever, reading events from the channel and
	// passing them back to the stream
	RunTasks:
	for {
		select {
		case evt := <- mgr.evtsChannel:
			if err := stream.Send(evt); err != nil {
				log.Errorf("Could not send event %s: %v",
					evt.String(), err.Error())
				mgr.Calendar = nil
				return err
			}
		case <- ctx.Done():
			break RunTasks

		}
	}

	log.Infof("Tasks done, exiting")

	return nil
}

func (mgr *ModuleMgr) Load(ctx context.Context, load *sdc_internal.CompLoad) (*sdc_internal.CompLoadResult, error) {
	log.Debugf("Received Load message: %s", load.String())

	if ! mgr.initialized {
		if err := mgr.Init(*load.CustomerId, *load.MachineId); err != nil {
			return nil, err
		}
	}

	result := &sdc_internal.CompLoadResult{}

	for _, module := range mgr.availModules {

		result.Statuses = append(result.Statuses, &sdc_internal.CompModuleStatus{
			ModName: proto.String(module.Name),
			Running: proto.Bool(true),
		})
	}

	log.Debugf("Returning from Load: %v", result)

	return result, nil
}

func (mgr *ModuleMgr) Stop(ctx context.Context, stop *sdc_internal.CompStop) (*sdc_internal.CompStopResult, error) {
	log.Debugf("Received Stop message: %s", stop.String())

	result := &sdc_internal.CompStopResult{
		Successful: proto.Bool(true),
	}

	if ! mgr.initialized {
		return result, nil
	}

	if mgr.cancel != nil {
		mgr.cancel()
		mgr.cancel = nil
	}

	for _, module := range mgr.availModules {
		if module.LastOutputDir != "" {
			err := os.RemoveAll(module.LastOutputDir); if err != nil {
				return nil, err
			}
		}
	}

	log.Debugf("Returning from Stop: %v", result)

	return result, nil
}

func (mgr *ModuleMgr) GetFutureRuns(ctx context.Context, req *sdc_internal.CompGetFutureRuns) (*sdc_internal.CompFutureRuns, error) {
	log.Debugf("Received GetFutureRuns message: %s", req.String())

	ret := &sdc_internal.CompFutureRuns{
		Successful: proto.Bool(true),
	}

	start, err := time.Parse(time.RFC3339, *req.Start); if err != nil {
		ret.Successful = proto.Bool(false)
		ret.Errstr = proto.String("Could not parse start time " + *req.Start)
		log.Errorf("Returning from GetFutureRuns: %v", ret)
		return ret, nil
	}

	log.Debugf("Parsed start time as %v", start)

	stask := NewScheduledTask(mgr, req.Task, nil)
	err = stask.ParseSchedule(*req.Task.Schedule, start)

	ret.Runs = stask.FutureRuns(start, *req.NumRuns)

	log.Debugf("Returning from GetFutureRuns: %v", ret)

	return ret, nil
}

func (mgr *ModuleMgr) RunTasks(ctx context.Context, req *draiosproto.CompRun) (*sdc_internal.CompRunResult, error) {
	log.Debugf("Received RunTasks message: %s", req.String())

	ret := &sdc_internal.CompRunResult{
		Successful: proto.Bool(true),
	}

	for _, taskId := range req.TaskIds {

		var task *draiosproto.CompTask
		var stask *ScheduledTask
		var err error

		if task = mgr.Tasks[taskId]; task == nil {
			ret.Successful = proto.Bool(false)
			ret.Errstr = proto.String(fmt.Sprintf("No task matching task id %d", taskId))
			return ret, nil;
		}

		module, ok := mgr.availModules[*task.ModName]
		if ! ok {
			err = fmt.Errorf("Module %s does not exist",
				*task.ModName)
		} else if _, err = os.Stat(path.Join(mgr.ModulesDir, *task.ModName)); os.IsNotExist(err) {
			err = fmt.Errorf("Path for module %s not found",
				*task.ModName)
		}

		if err != nil {
			ret.Successful = proto.Bool(false)
			ret.Errstr = proto.String(fmt.Sprintf("Could not create context for task %s: %s", *task.Name, err.Error()))

			return ret, nil
		}

		stask = NewScheduledTask(mgr, task, module.Env(mgr))

		if err = stask.RunNow(ctx); err != nil {
			ret.Successful = proto.Bool(false)
			ret.Errstr = proto.String(fmt.Sprintf("Could not run task %s: %s", *task.Name, err.Error()))

			return ret, nil
		}

		// Results will be sent via the channels created in Start()
	}

	log.Debugf("Returning from RunTasks: %v", ret)

	return ret, nil
}

func Register(grpcServer *grpc.Server, modulesDir string) error {

	if absDir, err := filepath.Abs(modulesDir); err != nil {
		return err
	} else {
		modulesDir = absDir
	}

	mgr := &ModuleMgr{
		ModulesDir: modulesDir,
	}

	// The true spec doesn't allow mixing Week intervals and any other
	// interval, but we just combine them in the regex and check for
	// incompatible combinations elsewhere.
	re, err := regexp.Compile(`^(?:R(?P<repeat>\d+)/)?(?:(?P<start>[^/]+)/)?P(?:(?P<year>\d+)Y)?(?:(?P<month>\d+)M)?(?:(?P<day>\d+)D)?(?:(?P<week>\d+)W)?(?:T(?:(?P<hour>\d+)H)?(?:(?P<minute>\d+)M)?(?:(?P<second>\d+)S)?)?$`); if err != nil {
		return fmt.Errorf("Could not compile schedule regexp: %s", err.Error())
	}

	mgr.scheduleRegexp = re
	mgr.scheduleRegexpNames = re.SubexpNames()

	re, err = regexp.Compile(`\s*,\s*`); if err != nil {
		return fmt.Errorf("Could not compile schedule regexp: %s", err.Error())
	}

	mgr.scheduleListRegexp = re

	sdc_internal.RegisterComplianceModuleMgrServer(grpcServer, mgr)

	return nil
}


