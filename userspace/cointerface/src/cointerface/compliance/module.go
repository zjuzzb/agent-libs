package compliance

import (
	"bytes"
	"cointerface/sdc_internal"
	"cointerface/draiosproto"
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"io/ioutil"
	log "github.com/cihub/seelog"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Scraper interface {
	Scrape(rootPath string, moduleName string,
		task *draiosproto.CompTask,
		includeDesc bool,
		evtsChannel chan *sdc_internal.CompTaskEvent,
		metricsChannel chan string) error
}

type TaskArgsGenerator interface {
	GenArgs(stask *ScheduledTask) ([]string, error)
}

type TaskShouldRun interface {
	ShouldRun(stask *ScheduledTask) bool
}

type ModuleImpl interface {
	Scraper
	TaskArgsGenerator
	TaskShouldRun
}

type Module struct {
	Name string `json:"name"`
	Prog string `json:"prog"`
	Impl ModuleImpl `json:"impl"`
}

// Represents the periodic interval for how often/when a task should
// run.
type TaskInterval struct {

	id int

	// The year/month/days component of the interval between
	// tasks. golang's native types don't have any way to store a
	// combined date + time duration.
	intYear int
	intMonth int
	intDay int
	intWeek int

	// The hour/minutes/seconds component of the interval between tasks.
	intTime time.Duration

	// The number of times this scheduled task should run.
	maxTimesRun int

	// The next time this task should run
	nextRunTime time.Time

	// The number of times this task has run so far.
	numTimesRun int
}

// Increment nextRunTime until it's in the future.
func (sint *TaskInterval) FindNextRun(now time.Time) {

	t := sint.nextRunTime

	for t.Before(now) {
		t = t.AddDate(sint.intYear, sint.intMonth, sint.intDay + (sint.intWeek * 7))
		t = t.Add(sint.intTime)
	}

	sint.nextRunTime = t
}

type ScheduledTask struct {
	mgr *ModuleMgr
	task *draiosproto.CompTask
	cmd *exec.Cmd
	cmdStartTime time.Time
	module *Module
	env []string

	intervals []*TaskInterval
}

func NewScheduledTask(mgr *ModuleMgr, task *draiosproto.CompTask, env []string) *ScheduledTask {
	s := &ScheduledTask{
		mgr: mgr,
		task: task,
		env: env,
		module: mgr.availModules[*task.ModName],
	}

	return s
}

// Parse a string representing one, or a list of, ISO8601 Repeating
// Duration strings into the intervals field of the task.
func (stask *ScheduledTask) ParseSchedule(schedule string, now time.Time) error {

	var specs []string

	// If the schedule starts with '[', assume it's an array of
	// repeating durations.
	if strings.HasPrefix(schedule, "[") {
		if ! strings.HasSuffix(schedule, "]") {
			return fmt.Errorf("Invalid schedule specification %s", schedule)
		}

		schedule = strings.TrimPrefix(schedule, "[")
		schedule = strings.TrimSuffix(schedule, "]")

		specs = stask.mgr.scheduleListRegexp.Split(schedule, -1)
	} else {
		specs = append(specs, schedule)
	}

	for num, spec := range specs {
		sint := &TaskInterval{id: num}

		// If not otherwise specified, tasks are run relative to the current time
		sint.nextRunTime = time.Now()

		// We'll build the duration string on the fly
		dstr := ""

		matches := stask.mgr.scheduleRegexp.FindAllStringSubmatch(spec, -1)

		if matches == nil {
			return fmt.Errorf("Could not parse duration from schedule %s: did not match expected pattern",
				schedule)
		}

		for _, match := range matches {
			for j, submatch := range match {
				if j != 0 && submatch != "" {

					var num int
					var err error

					if stask.mgr.scheduleRegexpNames[j] != "start" {
						parsed, err := strconv.ParseInt(submatch, 10, 64); if err != nil {
							return fmt.Errorf("Could not parse numeric value from schedule %s: %s", schedule, err.Error())
						}
						num = int(parsed)
					}

					switch stask.mgr.scheduleRegexpNames[j] {
					case "repeat":
						sint.maxTimesRun = num
					case "start":

						// We handle a valid RFC3339 timestamp (YYYY-MM-DDTHH:MM:SSZ) or
						// just a time portion, which is ISO 8601 compatible (HH:MM:SSZ).
						if len(submatch) == 20 {
							sint.nextRunTime, err = time.Parse(time.RFC3339, submatch)
							if err != nil {
								return fmt.Errorf("Could not parse start time from schedule %s: %s", schedule, err.Error())
							}
						} else {
							// Add the current date (UTC) and try to parse as RFC3339
							date_added := now.UTC().Format("2006-01-02") + "T" + submatch

							log.Debugf("Creating RFC3339-compatible time as: %s", date_added)

							sint.nextRunTime, err = time.Parse(time.RFC3339, date_added)
							if err != nil {
								return fmt.Errorf("Could not parse start time from schedule %s, after adding implicit date for %s: %s", schedule, date_added, err.Error())
							}
						}
					case "year":
						sint.intYear = num
					case "month":
						sint.intMonth = num
					case "day":
						sint.intDay = num
					case "week":
						sint.intWeek = num
					case "hour":
						dstr += submatch + "h"
					case "minute":
						dstr += submatch + "m"
					case "second":
						dstr += submatch + "s"
					default:
						return fmt.Errorf("Unexpected regex field %s when parsing schedule %s", stask.mgr.scheduleRegexpNames[j], schedule)
					}
				}
			}
		}

		if dstr != "" {
			parsed, err := time.ParseDuration(dstr); if err != nil {
				return err
			}

			sint.intTime = parsed
		}

		stask.intervals = append(stask.intervals, sint)
	}

	return nil
}

func (stask *ScheduledTask) RunNow(ctx context.Context) error {

	if shouldRun := stask.module.Impl.ShouldRun(stask); !shouldRun {
		log.Infof("Not running task %s (ShouldRun false)", *stask.task.Name);
		return nil
	}

	log.Infof("Running task %s", *stask.task.Name)

	if err := stask.module.Run(ctx, stask); err != nil {
		log.Errorf("module.Run returned error: %v", err.Error())
		stask.mgr.FailResult(stask, err)
		return err
	}

	return nil
}

// Return the interval whose nextRunTime is closest to now
func (stask *ScheduledTask) NextInterval(now time.Time) *TaskInterval {

	// Only consider those intervals that have run fewer than
	// their maximum number of times.
	filt := make([]*TaskInterval, 0)

	for _, sint := range stask.intervals {
		sint.FindNextRun(now)
		considered := false
		if sint.maxTimesRun == 0 || sint.numTimesRun < sint.maxTimesRun {
			filt = append(filt, sint)
			considered = true
		}
		log.Debugf("Interval %d considered=%v nextRun=%s numTimesRun=%d maxTimesRun=%d",
			sint.id, considered, sint.nextRunTime.String(), sint.numTimesRun, sint.maxTimesRun)
	}

	// Find the next interval for this task
	sort.Slice(filt, func(i, j int) bool {
		return filt[i].nextRunTime.Before(filt[j].nextRunTime)
	})

	if len(filt) == 0 {
		// This occurs if all intervals have already run their
		// maximum number of times. Pick any interval, it will
		// be ignored later.
		return stask.intervals[0]
	}

	return filt[0]
}

func (stask *ScheduledTask) RunForever(ctx context.Context) {

	// We run the task once immediately without any consideration
	// of maxTimesRun or schedule, and then afterwards on its
	// schedule.
	ch := make(chan error)

	running := false
	go func() {
		log.Debugf("Running task immediately")
		running = true
		ch <- stask.RunNow(ctx)
	}()

	for _, sint := range stask.intervals {
		// Move nextRunTime forward until it's in the future
		sint.FindNextRun(time.Now())
	}

	sint := stask.NextInterval(time.Now())
	timer := time.NewTimer(time.Until(sint.nextRunTime))

	for {
		select {
		case <- ch:
			log.Debugf("Task completed (Ran for %s)", time.Since(stask.cmdStartTime).String())
			running = false

		case <- ctx.Done():
			// Don't need to stop any in-progress
			// task. That is handled through the context.
			timer.Stop()
			return

		case <- timer.C:

			log.Debugf("Timer expired, will try using interval %d (run %d times so far)", sint.id, sint.numTimesRun)

			if sint.maxTimesRun > 0 && sint.numTimesRun >= sint.maxTimesRun {
				log.Infof("Task already run max times %d, not doing anything", sint.maxTimesRun)
			} else {
				sint.numTimesRun++

				if running {
					log.Warnf("Task %s already running (pid %d, started %s)", *stask.task.Name, stask.cmd.Process.Pid, stask.cmdStartTime.String())
				} else {
					go func() {
						running = true
						ch <- stask.RunNow(ctx)
					}()
				}
			}

			sint = stask.NextInterval(time.Now())
			timer = time.NewTimer(time.Until(sint.nextRunTime))
		}
	}
}

func (stask *ScheduledTask) FutureRuns(start time.Time, count uint32) []string {
	now := start

	ret := make([]string, 0)

	var i uint32

	for i = 0; i < count; i++ {
		sint := stask.NextInterval(now)
		ret = append(ret, sint.nextRunTime.Format(time.RFC3339))
		now = sint.nextRunTime

		now = now.Add(1 * time.Second)
	}

	return ret
}

// For now, all compliance result json objects have a consistent
// structure, namely `ExtendedComplianceResult` in the swagger
// definition. These structs implement that structure.

type ResultStatus int

const (
	pass ResultStatus = iota
	fail
	warn
	info
)

func (s ResultStatus) String() string {
	return [...]string{"pass", "fail", "warn", "info"}[s]
}

func (d *ResultStatus) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(d.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (d *ResultStatus) UnmarshalJSON(b []byte) error {
	// unmarshal as string
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	// lookup value
	switch s {
	case "pass":
		*d = pass
	case "fail":
		*d = fail
	case "warn":
		*d = warn
	case "info":
		*d = info
	default:
		return fmt.Errorf("Unknown ResultStatus string %s", s)
	}
	return nil
}

type ResultRisk int

const (
	low ResultRisk = iota
	medium
	high
)

func (s ResultRisk) String() string {
	return [...]string{"low", "medium", "high"}[s]
}

func (d *ResultRisk) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(d.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (d *ResultRisk) UnmarshalJSON(b []byte) error {
	// unmarshal as string
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	// lookup value
	switch s {
	case "low":
		*d = low
	case "medium":
		*d = medium
	case "high":
		*d = high
	default:
		return fmt.Errorf("Unknown ResultRisk string %s", s)
	}
	return nil
}

// A Prettier summary of a Cmd than what you get with %v
func CmdString(c *exec.Cmd) string {
	return fmt.Sprintf("{Path=%s Args=[%s] Env=[%s] Dir=%s}",
		c.Path, strings.Join(c.Args," "), strings.Join(c.Env, " "), c.Dir)
}

type TaskResultTest struct {
	TestNumber string `json:"testNumber"`
	Description string `json:"description,omitempty"`
	Status ResultStatus `json:"status"`
	Details string `json:"details,omitempty"`
	Items []string `json:"items,omitempty"`
}

type TaskResultSection struct {
	SectionId string `json:"sectionId"`
	Description string `json:"description,omitempty"`
	TestsRun uint64 `json:"testsRun"`
	PassCount uint64 `json:"passCount"`
	FailCount uint64 `json:"failCount"`
	WarnCount uint64 `json:"warnCount"`
	Results []TaskResultTest `json:"results,omitempty"`
}

type TaskResultAttribute struct {
	K8sNodeType string `json:"k8sNodeType,omitempty"`
	DockerBenchScore *int64 `json:"dockerBenchScore,omitempty"`
}

type ExtendedTaskResult struct {
	Id uint64 `json:"id"`
	TimestampNS uint64 `json:"timestampNs"`
	HostMac string `json:"hostMac"`
	TaskName string `json:"taskName"`
	ResultSchema string `json:"resultSchema,omitempty"`
	TestsRun uint64 `json:"testsRun"`
	PassCount uint64 `json:"passCount"`
	FailCount uint64 `json:"failCount"`
	WarnCount uint64 `json:"warnCount"`
	Risk ResultRisk `json:"risk"`
	Tests []TaskResultSection `json:"tests,omitempty"`
	Attributes []TaskResultAttribute `json:"attributes,omitempty"`
}

func (module *Module) Env(mgr *ModuleMgr) []string {

	moduleDir := path.Join(mgr.ModulesDir, module.Name)

	// Add the module dir to PATH
	env := os.Environ()
	var newenv []string
	for _, item := range env {
		splits := strings.Split(item, "=")
		key := splits[0]
		val := splits[1]
		if key == "PATH" {
			val = val + ":" + moduleDir
		}
		newenv = append(newenv, key + "=" + val)
	}

	// If SYSDIG_HOST_ROOT is set, use that as a part of the socket path.
	sysdigRoot := os.Getenv("SYSDIG_HOST_ROOT")
	if sysdigRoot != "" {
		sysdigRoot = sysdigRoot + "/"
	}
	dockerSock := fmt.Sprintf("unix:///%svar/run/docker.sock", sysdigRoot)
	newenv = append(newenv, "DOCKER_HOST=" + dockerSock);

	return newenv
}

func (module *Module) Run(start_ctx context.Context, stask *ScheduledTask) error {

	// Create a temporary directory where this module's output will go
	outputDir, err := ioutil.TempDir("", "module-" + module.Name + "-output"); if err != nil {
		err = fmt.Errorf("Could not create temporary directory (%s)", err.Error());
		return err
	}

	moduleDir := path.Join(stask.mgr.ModulesDir, module.Name)

	// Replace MODULE_DIR with the path to the module and
	// OUTPUT_DIR with the temporary output directory.

	prog :=	strings.Replace(strings.Replace(module.Prog, "MODULE_DIR", moduleDir, -1),
		"OUTPUT_DIR", outputDir, -1)

	args, err := module.Impl.GenArgs(stask); if err != nil {
		return err
	}

	var subArgs []string

	for _, arg := range args {
		subArgs = append(subArgs,
			strings.Replace(strings.Replace(arg, "MODULE_DIR", moduleDir, -1),
				"OUTPUT_DIR", outputDir, -1))
	}

	// Note that this is intentionally a separate context so if
	// start_ctx is cancelled, we can cancel the command context
	// and not consider the non-zero result as an error.

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, prog, subArgs...)
	cmd.Env = module.Env(stask.mgr)
	cmd.Dir = moduleDir

	stask.cmd = cmd

	log.Debugf("Running: %s", CmdString(cmd))

	stderrFileName := path.Join(outputDir, "stderr.txt")
	stderrFile, err := os.Create(stderrFileName); if err != nil {
		err = fmt.Errorf("Could not create stderr file (%s)", err.Error());
		return err
	}

	cmd.Stderr = stderrFile

	stdoutFileName := path.Join(outputDir, "stdout.txt")
	stdoutFile, err := os.Create(stdoutFileName); if err != nil {
		err = fmt.Errorf("Could not create stdout file (%s)", err.Error());
		return err
	}

	cmd.Stdout = stdoutFile

	stask.cmdStartTime = time.Now()

	if err = cmd.Start(); err != nil {
		err = fmt.Errorf("Could not start module %s via %s (%s)",
			module.Name, CmdString(cmd), err)
		return err
	}

	// Wait for the command to complete or for us to be cancelled

	defer os.RemoveAll(outputDir)

	activelyStopped := false

	// Start the command in the background
	ch := make(chan error)
	go func() {
		ch <- cmd.Wait()
	}()

	// Wait for the command to complete or for us to be cancelled
	WAIT:
	for {
		select {
		case err = <- ch:
			break WAIT
		case <- start_ctx.Done():
			activelyStopped = true
			cancel()
		}
	}

	stderrFile.Close()
	stdoutFile.Close()

	if err != nil {

		stderrBuf, _ := ioutil.ReadFile(stderrFileName)
		stdoutBuf, _ := ioutil.ReadFile(stdoutFileName)

		err = fmt.Errorf("module %s via %s exited with error (%s) Stdout: \"%s\" Stderr: \"%s\"",
			module.Name, CmdString(cmd), err, string(stdoutBuf), string(stderrBuf))

		if ! activelyStopped {
			return err
		} else {
			log.Debugf(err.Error())

			// From the caller's perspective, being
			// cancelled shouldn't count as an error
			err = nil
		}
	} else {
		err = module.Impl.Scrape(outputDir, module.Name,
			stask.task,
			stask.mgr.IncludeDesc,
			stask.mgr.evtsChannel, stask.mgr.metricsChannel); if err != nil {
				err = fmt.Errorf("Could not scrape module %s output (%s)",
					module.Name, err);
			}
	}

	log.Infof("Completed task %s", *stask.task.Name)

	return err
}
