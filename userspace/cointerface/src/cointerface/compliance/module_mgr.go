package compliance

import (
	"cointerface/draiosproto"
	"cointerface/sdc_internal"
	duration "github.com/channelmeter/iso8601duration"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	gocron "github.com/jasonlvhit/gocron"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ModuleMgr struct {
	ModulesDir string `json:"modules_dir"`
	initialized bool
	customerId string
	machineId string
	Calendar *draiosproto.CompCalendar
	availModules map[string]Module
	evtsChannel chan *sdc_internal.CompTaskEvent
	metricsChannel chan string
	metricsResetChannel chan bool

	// Send a value to this channel to stop any previous start
	stopTasksChannel chan bool

	// Read the results of the stop from this channel after writing to tasksChannel
	stopTasksDoneChannel chan error

	scheduledTasks map[string] *ScheduledTask

	durationRegexp *regexp.Regexp
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

func runTask(mgr *ModuleMgr, stask *ScheduledTask) error {
	module := mgr.availModules[*stask.task.ModName]

	shouldRun, err := module.Impl.ShouldRun(stask); if err != nil {
		return err
	}

	if !shouldRun {
		log.Infof("Not running task %s (ShouldRun false)", *stask.task.Name);
		return nil
	} else {
		log.Infof("Running task %s", *stask.task.Name)
	}

	stask.numTimesRun++

	// If a task with the provided name is already running, log a warning and return
	stask.cmdLock.Lock()
	if stask.cmd != nil {
		log.Warnf("Task %s already running (pid %d)", *stask.task.Name, stask.cmd.Process.Pid)
		stask.cmdLock.Unlock()
		return nil
	}
	stask.cmdLock.Unlock()

	// If we have already run this task the specified number of times, do nothing
	if stask.maxTimesRun > 0 && stask.numTimesRun > stask.maxTimesRun {
		log.Infof("Task already run max times %d, not doing anything", stask.maxTimesRun)
		return nil
	}

	if err := module.Run(mgr, stask); err != nil {
		log.Errorf("module.Run returned error: %v", err.Error())
		return err
	}

	return nil
}

func (mgr *ModuleMgr) Init(customerId string, machineId string) error {
	mgr.availModules = make(map[string]Module)
	mgr.evtsChannel = make(chan *sdc_internal.CompTaskEvent, 1000)
	mgr.metricsChannel = make(chan string, 1000)
	mgr.metricsResetChannel = make(chan bool)
	mgr.stopTasksChannel = make(chan bool)
	mgr.stopTasksDoneChannel = make(chan error)
	mgr.scheduledTasks = make(map[string]*ScheduledTask)

	mgr.availModules["docker-bench-security"] = Module{
		Name: "docker-bench-security",
		Prog: "bash",
		Impl: &DockerBenchImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	mgr.availModules["kube-bench"] = Module{
		Name: "kube-bench",
		Prog: "MODULE_DIR/kube-bench",
		Impl: &KubeBenchImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	mgr.availModules["test-module"] = Module{
		Name: "test-module",
		Prog: "MODULE_DIR/run.sh",
		Impl: &TestModuleImpl{
			customerId: customerId,
			machineId: machineId,
		},
	}

	// This regex is intentionally not as exact as the regex in
	// iso8601duration. It focuses on ensuring no text before/after
	// the repeating duration, something the regex within
	// iso8601duration does not do.
	if re, err := regexp.Compile("^(?:R(\\d+)/)?(P(?:\\d+[YMDW])*(?:T(?:\\d+[HMS])+)?)$"); err != nil {
		return err
	} else {
		mgr.durationRegexp = re
	}

	// Start a goroutine that reads from the metrics channel and
	// forwards to statsd
	go emitStatsdForever(mgr)

	mgr.initialized = true

	return nil
}

// Parse an ISO8601 Repeating Duration string into a number of times
// to run + a duration. We do this outside of the duration package as
// it doesn't handle repeating intervals and allows leading/trailing
// junk in the regexes.
func (mgr *ModuleMgr) ParseSchedule(schedule string) (int, *duration.Duration, error) {

	maxTimesRun := -1

	// If the schedule starts with "R[n]/", it means the task
	// should be run a set number of times.
	if matches := mgr.durationRegexp.FindStringSubmatch(schedule); matches != nil {
		if matches[1] != "" {
			if parsed, err := strconv.ParseUint(matches[1], 10, 64); err != nil {
				return 0, nil, fmt.Errorf("Could not parse repeated duration from schedule %s: %s",
					schedule, err.Error())
			} else {
				maxTimesRun = int(parsed)
			}
		}

		schedule = matches[2]
	} else {
		return 0, nil, fmt.Errorf("Could not parse duration from schedule %s: did not match expected pattern",
			schedule)
	}

	dur, err := duration.FromString(schedule)

	if err != nil {
		return 0, nil, fmt.Errorf("Could not parse duration from schedule %s: %s",
			schedule, err.Error())
	}

	return maxTimesRun, dur, nil
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

	if mgr.Calendar != nil {
		// Start() was previously called. Stop those tasks first.
		if err := mgr.StopAllTasks(); err != nil {
			log.Errorf("Could not stop previously started tasks: %v",
				err.Error())
			return err
		}
	}

	mgr.Calendar = start.Calendar

	// Create a scheduler for the tasks we will run
	scheduler := gocron.NewScheduler()

	for _, task := range mgr.Calendar.Tasks {

		var maxTimesRun int
		var dur *duration.Duration
		var err error

		module, ok := mgr.availModules[*task.ModName]
		if ! ok {
			err = fmt.Errorf("Module %s does not exist",
				*task.ModName)
		} else if _, err = os.Stat(path.Join(mgr.ModulesDir, *task.ModName)); os.IsNotExist(err) {
			err = fmt.Errorf("Path for module %s not found",
				*task.ModName)
		} else if err == nil {
			log.Debugf("Parsing schedule %s", *task.Schedule)
			maxTimesRun, dur, err = mgr.ParseSchedule(*task.Schedule)
		}

		if err != nil {
			evt := &sdc_internal.CompTaskEvent{
				TaskName: task.Name,
				Successful: proto.Bool(false),
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
			stask := &ScheduledTask{
				task: task,
				cmd: nil,
				env: module.Env(mgr),
				maxTimesRun: maxTimesRun,
				numTimesRun: 0,
			}

			mgr.scheduledTasks[*task.Name] = stask

			// Run the task immediately, and then on its schedule
			runTask(mgr, stask)
			scheduler.Every(uint64(dur.ToDuration().Seconds())).Seconds().Do(runTask, mgr, stask)
		}
	}

	log.Infof("Starting all tasks")

	// Now wait forever, reading events from the channel and
	// passing them back to the stream
	ticker := time.NewTicker(1 * time.Second)

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
		case <-ticker.C:
			scheduler.RunPending()
		case <- mgr.stopTasksChannel:
			mgr.Calendar = nil
			mgr.stopTasksDoneChannel <- mgr.StopTasks()
			break RunTasks

		}
	}

	log.Infof("Tasks done, exiting")

	return nil
}

func (mgr *ModuleMgr) StopAllTasks() error {
	mgr.stopTasksChannel <- true
	err := <- mgr.stopTasksDoneChannel

	if err != nil {
		log.Errorf("Got error %v from stopTasksDoneChannel", err.Error())
	}

	mgr.metricsResetChannel <- true

	return err
}

func (mgr *ModuleMgr) StopTasks() error {

	for _, stask := range mgr.scheduledTasks {
		stask.cmdLock.Lock()
		defer stask.cmdLock.Unlock()

		if stask.cmd != nil {
			stask.activelyStopped = true
			log.Infof("Received stop request for task %s, killing pid %d",
				*stask.task.Name,
				stask.cmd.Process.Pid)
			err := stask.cmd.Process.Kill(); if err != nil {
				return err
			}
		}
	}

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

func (mgr *ModuleMgr) Stop(ctx context.Context, load *sdc_internal.CompStop) (*sdc_internal.CompStopResult, error) {
	log.Debugf("Received Stop message: %s", load.String())

	result := &sdc_internal.CompStopResult{
		Successful: proto.Bool(true),
	}

	if ! mgr.initialized {
		return result, nil
	}

	if mgr.Calendar != nil {
		if err := mgr.StopAllTasks(); err != nil {
			result.Successful = proto.Bool(false)
			result.Errstr = proto.String(fmt.Sprintf("Could not stop previously started tasks: %v",
				err.Error()))
			log.Errorf(*result.Errstr)
		}
	}

	log.Debugf("Returning from Stop: %v", result)

	return result, nil
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

	sdc_internal.RegisterComplianceModuleMgrServer(grpcServer, mgr)

	return nil
}


