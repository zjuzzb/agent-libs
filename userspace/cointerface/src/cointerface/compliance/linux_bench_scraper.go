package compliance

import (
	"encoding/json"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/draiosproto"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"io/ioutil"
	"strings"
	"time"
)

func (impl *LinuxBenchImpl) GenArgs(stask *ScheduledTask) ([]string, error) {
	args := []string{"--json", "--outputfile", "OUTPUT_DIR/linux-bench_results.json"}

	impl.variant = "1.1.0" // linux-bench runs CIS benchmark 1.1.0 by default

	// If "benchmark" was provided as a param, add it as a benchmark argument.
	for _, param := range stask.task.TaskParams {
		if *param.Key == "benchmark" {
			args = append(args, "--version", *param.Val)
			impl.variant = *param.Val
		}
	}

	return args, nil
}

func (impl *LinuxBenchImpl) ShouldRun(stask *ScheduledTask) bool {
	//Task can always run
	return true
}

type LinuxBenchImpl struct {
	customerId string `json:"customerId"`
	machineId  string `json:"machineId"`
	variant    string `json:"variant"`
}

type linuxTestResult struct {
	TestNumber string   `json:"test_number"`
	TestDesc   string   `json:"test_desc"`
	Type       string   `json:"type"`
	TestInfo   []string `json:"test_info"`
	Status     string   `json:"status"`
}

type linuxTestSection struct {
	Section string            `json:"section"`
	Desc    string            `json:"desc"`
	Results []linuxTestResult `json:"results"`
	Pass    uint64            `json:"pass"`
	Fail    uint64            `json:"fail"`
	Warn    uint64            `json:"warn"`
}

type linuxBenchResults struct {
	Id        string             `json:"id"`
	Text      string             `json:"text"`
	Tests     []linuxTestSection `json:"tests"`
	TotalPass uint64             `json:"total_pass"`
	TotalFail uint64             `json:"total_fail"`
	TotalWarn uint64             `json:"total_warn"`
}

func (impl *LinuxBenchImpl) AssignRisk(id string, result string, curRisk ResultRisk) ResultRisk {
	//TODO
}

func (impl *LinuxBenchImpl) Scrape(rootPath string, moduleName string,
	task *draiosproto.CompTask,
	includeDesc bool,
	evtsChannel chan *sdc_internal.CompTaskEvent,
	metricsChannel chan string) error {

	evt := &sdc_internal.CompTaskEvent{
		TaskName:       proto.String(moduleName),
		InitSuccessful: proto.Bool(true),
	}
	cevts := &draiosproto.CompEvents{
		MachineId:  proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}
	results := &draiosproto.CompResults{
		MachineId:  proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	metrics := []string{}

	// Read linux-bench's output files
	raw, err := ioutil.ReadFile(rootPath + "/linux-bench_results.json")
	if err != nil {
		log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	var bres linuxBenchResults
	err = json.Unmarshal(raw, &bres)

	if err != nil {
		log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	timestampNs := uint64(time.Now().UnixNano())

	result := &ExtendedTaskResult{
		Id:           *task.Id,
		TimestampNS:  timestampNs,
		HostMac:      impl.machineId,
		TaskName:     *task.Name,
		ResultSchema: impl.variant,
		TestsRun:     0,
		PassCount:    0,
		FailCount:    0,
		WarnCount:    0,
		Risk:         low,
	}

	for _, section := range bres.Tests {

		resSection := &TaskResultSection{
			SectionId: section.Section,
			TestsRun:  section.Pass + section.Fail + section.Warn,
			PassCount: section.Pass,
			FailCount: section.Fail,
			WarnCount: section.Warn,
		}

		if includeDesc {
			resSection.Description = section.Desc
		}

		benchVersion := strings.Replace(impl.variant, ".", "-", -1)
		sectionId := strings.Replace(section.Section, ".", "-", -1)
		sectionDesc := strings.ToLower(strings.Replace(section.Desc, " ", "-", -1))
		metricsPrefix := fmt.Sprintf("compliance.linux-bench.%v.%v.%v", benchVersion, sectionId, sectionDesc)
		metrics = append(metrics, fmt.Sprintf("%v.tests_fail:%d|g", metricsPrefix, resSection.FailCount))
		metrics = append(metrics, fmt.Sprintf("%v.tests_warn:%d|g", metricsPrefix, resSection.WarnCount))
		metrics = append(metrics, fmt.Sprintf("%v.tests_pass:%d|g", metricsPrefix, resSection.PassCount))
		metrics = append(metrics, fmt.Sprintf("%v.tests_total:%d|g", metricsPrefix, resSection.TestsRun))
		metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metricsPrefix, (100.0*float64(resSection.PassCount))/float64(resSection.TestsRun)))

		for _, test := range section.Results {

			result.Risk = impl.AssignRisk(test.TestNumber, test.Status, result.Risk)

			resTest := &TaskResultTest{
				TestNumber: test.TestNumber,
			}

			if includeDesc {
				resTest.Description = test.TestDesc
			}

			switch test.Status {
			case "PASS":
				resTest.Status = pass
			case "WARN":
				resTest.Status = warn
			default:
				resTest.Status = fail
			}

			resSection.Results = append(resSection.Results, *resTest)
		}

		result.Tests = append(result.Tests, *resSection)
	}

	ofbytes, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Could not serialize test result: %v", err.Error())
		return err
	}

	compResult := &draiosproto.CompResult{
		TimestampNs: proto.Uint64(result.TimestampNS),
		TaskName:    proto.String(result.TaskName),
		ModName:     task.ModName,
		TaskId:      proto.Uint64(result.Id),
		Successful:  proto.Bool(true),
		ExtResult:   proto.String(string(ofbytes[:])),
	}

	results.Results = append(results.Results, compResult)

	evt.Events = cevts
	evt.Results = results

	log.Debugf("Sending linux-bench comp_evt: %v", evt)
	evtsChannel <- evt

	metricsPrefix := fmt.Sprintf("compliance.linux-bench.%v", strings.Replace(impl.variant, ".", "-", -1))
	metrics = append(metrics, fmt.Sprintf("%v.tests_pass:%d|g", metricsPrefix, result.PassCount))
	metrics = append(metrics, fmt.Sprintf("%v.tests_fail:%d|g", metricsPrefix, result.FailCount))
	metrics = append(metrics, fmt.Sprintf("%v.tests_warn:%d|g", metricsPrefix, result.WarnCount))
	metrics = append(metrics, fmt.Sprintf("%v.tests_total:%d|g", metricsPrefix, result.TestsRun))
	metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metricsPrefix, (100.0*float64(result.PassCount))/float64(result.TestsRun)))

	for _, metric := range metrics {
		log.Debugf("Sending linux-bench metric: %v", metric)
		metricsChannel <- metric
	}

	return nil
}
