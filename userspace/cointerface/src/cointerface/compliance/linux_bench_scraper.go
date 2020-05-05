package compliance

import (
	"encoding/json"
	"fmt"
	log "github.com/cihub/seelog"
	draiosproto "protorepo/agent-be/proto"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (impl *LinuxBenchImpl) GenArgs(stask *ScheduledTask) ([]string, error) {
	args := []string{"--json", "--outputfile", "OUTPUT_DIR/linux-bench_results.json"}

	impl.variant = "2.0.0" // Run CIS benchmark 2.0.0 by default

	// If "benchmark" was provided as a param, add it as a benchmark argument.
	for _, param := range stask.task.TaskParams {

		if *param.Key == "benchmark" {
			switch *param.Val {
			case "cis-1.1":
				impl.variant = "1.1.0"
			case "cis-2.0":
				impl.variant = "2.0.0"
			default:
				impl.variant = "2.0.0"
			}
		}
	}

	args = append(args, "--version", impl.variant)

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

// Given a test id, result, and current risk, assign a new risk based
// on the result of the test.
func (impl *LinuxBenchImpl) AssignRisk(id string, result string, curRisk ResultRisk) ResultRisk {
	newRisk := low

	if (result != "PASS" && impl.isHighRiskTest(id)) {
		newRisk = high
	} else if (result != "PASS") {
		newRisk = medium
	}

	if (newRisk == high || (newRisk == medium && curRisk == low)) {
		return newRisk
	}

	return curRisk
}

// The risk defaults to low and becomes medium/high if:
// - medium: any test has a WARN result
// - high: any of the following tests has a non-PASS result:
//
//    CIS Benchmark 1.1.0:
//    - Anything in section 1.6 (Mandatory Access Control)
//    - Anything in section 5 (Access, Authentication and Authorization)
//    - 6.1.1-9 (Ensure critical file permissions are set)
//    - Anything in section 6.2 (User and Group Settings)
//
//    CIS Benchmark 2.0.0:
//    - Anything in section 1.6 (Mandatory Access Control)
//    - Anything in section 5 (Access, Authentication and Authorization)
//    - 6.1.1-9 (Ensure critical file permissions are set)
//    - Anything in section 6.2 (User and Group Settings)
func (impl *LinuxBenchImpl) isHighRiskTest(id string) bool {
	switch impl.variant {
	case "1.1.0":
		highTestIds := map[string]int {
			"6.1.1": 1,
			"6.1.2": 1,
			"6.1.3": 1,
			"6.1.4": 1,
			"6.1.5": 1,
			"6.1.6": 1,
			"6.1.7": 1,
			"6.1.8": 1,
			"6.1.9": 1,
		}

		return highTestIds[id] == 1 ||
			strings.HasPrefix(id, "1.6") ||
			strings.HasPrefix(id, "5") ||
			strings.HasPrefix(id, "6.2")
	case "2.0.0":
		highTestIds := map[string]int {
			"6.1.1": 1,
			"6.1.2": 1,
			"6.1.3": 1,
			"6.1.4": 1,
			"6.1.5": 1,
			"6.1.6": 1,
			"6.1.7": 1,
			"6.1.8": 1,
			"6.1.9": 1,
		}

		return highTestIds[id] == 1 ||
			strings.HasPrefix(id, "1.6") ||
			strings.HasPrefix(id, "5") ||
			strings.HasPrefix(id, "6.2")
	default:
		return false
	}
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
		TestsRun:     bres.TotalPass + bres.TotalFail + bres.TotalWarn,
		PassCount:    bres.TotalPass,
		FailCount:    bres.TotalFail,
		WarnCount:    bres.TotalWarn,
		Risk:         low,
	}

	// Normalize sections
	sectionMap := make(map[string]linuxTestSection)
	for _, section := range bres.Tests {
		sectionParts := strings.Split(section.Section, ".")

		// Ignore top level sections and empty sections
		if len(sectionParts) >= 2 && len(section.Results) > 0 {
			sectionNumber := fmt.Sprintf("%s.%s", sectionParts[0], sectionParts[1])

			normalizedSection, sectionExists := sectionMap[sectionNumber]

			if sectionExists {
				normalizedSection.Pass += section.Pass
				normalizedSection.Warn += section.Warn
				normalizedSection.Fail += section.Fail
				normalizedSection.Results = append(normalizedSection.Results, section.Results...)

				// When merging, sort like semantic version i.e. make sure 4.1.1.a comes before 4.1.2
				sort.Slice(normalizedSection.Results, func(i, j int) bool {
					partsA := strings.Split(normalizedSection.Results[i].TestNumber, ".")
					partsB := strings.Split(normalizedSection.Results[j].TestNumber, ".")

					return sortByTestNumber(partsA, partsB)
				})
			} else {
				normalizedSection = section
			}

			normalizedSection.Section = sectionNumber
			sectionMap[sectionNumber] = normalizedSection
		}
	}

	for _, section := range sectionMap {

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
		if resSection.TestsRun == 0 {
			metrics = append(metrics, fmt.Sprintf("%v.pass_pct:0|g", metricsPrefix))
		} else {
			metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metricsPrefix, (100.0*float64(resSection.PassCount))/float64(resSection.TestsRun)))
		}

		for _, test := range section.Results {

			result.Risk = impl.AssignRisk(test.TestNumber, test.Status, result.Risk)

			if strings.Compare(test.TestNumber, resSection.SectionId) == 0 {
				test.TestNumber = fmt.Sprintf("%s.1", test.TestNumber)
			}

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

	sort.Slice(result.Tests, func(i, j int) bool {
		return result.Tests[i].SectionId < result.Tests[j].SectionId
	})

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
	if result.TestsRun == 0 {
		metrics = append(metrics, fmt.Sprintf("%v.pass_pct:0|g", metricsPrefix))
	} else {
		metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metricsPrefix, (100.0*float64(result.PassCount))/float64(result.TestsRun)))
	}

	for _, metric := range metrics {
		log.Debugf("Sending linux-bench metric: %v", metric)
		metricsChannel <- metric
	}

	return nil
}

func sortByTestNumber(a, b []string) bool {
	if a == nil {
		return true
	}

	if b == nil {
		return false
	}

	if a[0] == b[0] {
		return sortByTestNumber(a[1:], b[1:])
	}

	intA, errA := strconv.Atoi(a[0])
	intB, errB := strconv.Atoi(b[0])

	if errA == nil { // A is number
		if errB == nil { // A and B are numbers
			return intA < intB
		} else { // A is number, B is letter
			return true
		}
	} else { // A is letter
		if errB == nil { // A is letter, B is number
			return false
		} else { // A and B are letters
			return a[0] < b[0]
		}
	}
}