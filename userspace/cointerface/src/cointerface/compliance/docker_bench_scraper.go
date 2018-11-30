package compliance

import (
	"bytes"
	"cointerface/draiosproto"
	"cointerface/sdc_internal"
	"encoding/json"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"io/ioutil"
	log "github.com/cihub/seelog"
	"os/exec"
	"strings"
	"text/template"
)

func (impl *DockerBenchImpl) GenArgs(stask *ScheduledTask) ([]string, error) {
	return []string{"MODULE_DIR/docker-bench-security.sh", "-l", "OUTPUT_DIR/docker-bench.log"}, nil
}

func (impl *DockerBenchImpl) ShouldRun(stask *ScheduledTask) bool {

	// If docker ps -q runs without errors, we assume the task can run
	cmd := exec.Command("docker", "ps", "-q")
	cmd.Env = stask.env

	out, err := cmd.Output()

	if(err == nil) {
		log.Debugf("Output from docker ps -q: %s %v", out, err)
	} else {
		log.Infof("Output from docker ps -q: %s %v", out, err)
	}

	return (err == nil)
}

type DockerBenchImpl struct {
	customerId string `json:"customerId"`
	machineId string `json:"machineId"`
}

// Used to parse the json output of the docker-bench-security script
type dockerTestResult struct {
	Id string `json:"id"`
	Desc string `json:"desc,omitempty"`
	Result string `json:"result"`
	Details string `json:"details,omitempty"`
	Items []string `json:"items,omitempty"`
}

type dockerTestSection struct {
	Id string `json:"id"`
	Desc string `json:"desc"`
	Results []dockerTestResult `json:"results"`
}

type dockerBenchResults struct {
	DockerBenchSecurity string `json:"dockerbenchsecurity"`
	Start uint64 `json:"start"`
	Tests []dockerTestSection `json:"tests"`
	Checks uint64 `json:"checks"`
	Score int64 `json:"score"`
	End uint64 `json:"end"`
}

// Given a test id, result, and current risk, assign a new risk based
// on the result of the test.
// The risk defaults to low and becomes medium/high if:
// - medium: any test has a WARN result
// - high: any of the following tests has a non-PASS result:
//    - 2.4 (Ensure insecure registries are not used)
//    - Anything in section 3 (Docker daemon configuration files)
//    - 5.1 (Ensure AppArmor Profile is Enabled)
//    - 5.2 (Ensure SELinux security options are set, if applicable")
//    - 5.3 (Ensure Linux Kernel Capabilities are restricted within containers)
//    - 5.15-17,30 (Ensure the host's process/ipc/user ns, devices are not shared)
//    - 5.21 (Ensure the default seccomp profile is not Disabled)
//    - 5.22 (Ensure docker exec commands are not used with privileged option)
//    - 5.25 (Ensure the container is restricted from acquiring additional privileges)
func (impl *DockerBenchImpl) AssignRisk(id string, result string, curRisk ResultRisk) ResultRisk {
	newRisk := low

	highTestIds := map[string]int {
		"2.4": 1,
		"5.1": 1,
		"5.2": 1,
		"5.3": 1,
		"5.15": 1,
		"5.16": 1,
		"5.17": 1,
		"5.30": 1,
		"5.21": 1,
		"5.22": 1,
		"5.25": 1,
	}

	if (result != "PASS" && (highTestIds[id] == 1 || strings.HasPrefix(id, "3"))) {
		newRisk = high
	} else if (result != "PASS") {
		newRisk = medium
	}

	if (newRisk == high || (newRisk == medium && curRisk == low)) {
		return newRisk
	}

	return curRisk
}

func (impl *DockerBenchImpl) Scrape(rootPath string, moduleName string,
	task *draiosproto.CompTask,
	includeDesc bool,
	evtsChannel chan *sdc_internal.CompTaskEvent,
	metricsChannel chan string) error {

	evt := &sdc_internal.CompTaskEvent{
		TaskName: proto.String(moduleName),
		CallSuccessful: proto.Bool(true),
	}

	cevts := &draiosproto.CompEvents{
		MachineId: proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}
	results := &draiosproto.CompResults{
		MachineId: proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	metrics := []string{}

	// Read /tmp/docker-bench.log.json to find any events.
	raw, err := ioutil.ReadFile(rootPath + "/docker-bench.log.json")
	if err != nil {
		log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	var bres dockerBenchResults
	err = json.Unmarshal(raw, &bres)

	if err != nil {
		log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	result := &ExtendedTaskResult{
		Id: *task.Id,
		TimestampNS: bres.Start * 1e9,
		HostMac: impl.machineId,
		TaskName: *task.Name,
		ResultSchema: bres.DockerBenchSecurity,
		TestsRun: 0,
		PassCount: 0,
		FailCount: 0,
		WarnCount: 0,
		Risk: low,
	}

	// For those tests where the test can return a number of
	// items, maps from test id to a description of the items
	// suitable for inclusion in statsd metrics.
	item_tests := map[string]string {
		"1.4": "docker-users",
		"4.1": "img-running-root",
		"4.6": "img-no-healthcheck",
		"4.7": "img-update-insts-found",
		"4.9": "img-images-using-add",
		"5.1": "c-no-apparmor",
		"5.2": "c-no-securityopts",
		"5.3": "c-caps-added",
		"5.4": "c-running-privileged",
		"5.5": "c-sensitive-dirs",
		"5.6": "c-sshd-docker-exec-failures",
		"5.7": "c-privileged-ports",
		"5.9": "c-networking-host",
		"5.10": "c-no-mem-limits",
		"5.11": "c-no-cpu-limits",
		"5.12": "c-root-mounted-rw",
		"5.13": "c-wildcard-bound-port",
		"5.14": "c-maxretry-not-set",
		"5.15": "c-sharing-host-pid-ns",
		"5.16": "c-sharing-host-ipc-ns",
		"5.17": "c-sharing-host-devs",
		"5.18": "c-no-ulimit-override",
		"5.19": "c-mount-prop-shared",
		"5.20": "c-sharing-host-uts-ns",
		"5.21": "c-no-seccomp",
		"5.24": "c-unexpected-cgroup",
		"5.25": "c-no-restricted-privs",
		"5.26": "c-no-health-check",
		"5.28": "c-no-pids-cgroup-limit",
		"5.29": "c-using-docker0-net",
		"5.30": "c-sharing-host-user-ns",
		"5.31": "c-sharing-docker-sock",
	}

	for _, section := range bres.Tests {

		res_section := &TaskResultSection {
			SectionId: section.Id,
			TestsRun: 0,
			PassCount: 0,
			FailCount: 0,
			WarnCount: 0,
		}

		if includeDesc {
			res_section.Description = section.Desc
		}

		for _, test := range section.Results {

			res_section.TestsRun++

			res_test := &TaskResultTest {
				TestNumber: test.Id,
				Items: test.Items,
			}

			if includeDesc {
				res_test.Description = test.Desc
			}

			// If Items is empty, include Details
			// as-is. Otherwise, assume that Details has a
			// preface e.g. "Images w/o HEALTHCHECK:" and
			// include *only* the preface.
			if len(test.Items) == 0 {
				res_test.Details = test.Details
			} else {
				parts := strings.Split(test.Details, ":")
				res_test.Details = parts[0] + ":"
			}

			// Generally, PASS or INFO results are considered passing.
			// However, there are some tests for which
			// INFO results are returned, that are considered warnings
			//  - 4.7: Ensure update instructions are not use alone in the Dockerfile
			//  - 5.17: Ensure host devices are not directly exposed to containers
			//  - 5.18: Ensure the default ulimit is overwritten at runtime, only if needed
			//  - 5.29: Ensure Docker's default bridge docker0 is not used

			result.Risk = impl.AssignRisk(test.Id, test.Result, result.Risk)

			if ((test.Result == "WARN") ||
				(test.Result == "INFO" &&
				(test.Id == "4.7" ||
				test.Id == "5.17" ||
				test.Id == "5.18" ||
				test.Id == "5.29"))) {
				res_test.Status = warn
				res_section.WarnCount++
			} else if (test.Result == "NOTE") {
				res_test.Status = pass
				res_section.PassCount++
			} else if ((test.Result != "PASS" && test.Result != "INFO")) {
				fields := map[string]string{
					"Task": moduleName,
					"TestId": test.Id,
					"TestDesc": test.Desc,
					"TestResult": test.Result,
					"TestDetails": test.Details,
					"falco.rule": "compliance_modules",
				}
				tmplstr := "Compliance task \"{{.Task}}\" test {{.TestId}} ({{.TestDesc}}) result: {{.TestResult}}."
				if test.Details != "" {
					tmplstr += " Details: {{.TestDetails}}"
				}
				tmpl, err := template.New("test").Parse(tmplstr)
				if err != nil {
					log.Errorf("Could not format output string: %v", err.Error())
					return err
				}
				var outputString bytes.Buffer
				err = tmpl.Execute(&outputString, fields)
				if err != nil {
					log.Errorf("Could not format output string: %v", err.Error())
					return err
				}

				// XXX/mstemm disabled pending expanded event stream work.
				if false {
					cevt := &draiosproto.CompEvent{
						TimestampNs: proto.Uint64(bres.Start * 1e9),
						TaskName: proto.String(*task.Name),
						Output: proto.String(outputString.String()),
						OutputFields: fields,
					};

					cevts.Events = append(cevts.Events, cevt);
				}

				res_test.Status = fail
				res_section.FailCount++
			} else {
				res_test.Status = pass
				res_section.PassCount++
			}

			// For certain sections, we parse the details field to get counts of items.
			mname, ok := item_tests[test.Id]; if (ok && test.Items != nil) {
				metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.%v:%d|g", mname, len(test.Items)))
			}

			res_section.Results = append(res_section.Results, *res_test)
		}
		result.Tests = append(result.Tests, *res_section)
		result.PassCount += res_section.PassCount
		result.FailCount += res_section.FailCount
		result.WarnCount += res_section.WarnCount
		result.TestsRun = (result.PassCount + result.WarnCount + result.FailCount)

		metrics_prefix := fmt.Sprintf("compliance.docker-bench.%v.%v", strings.Split(section.Id, ".")[0], strings.ToLower(strings.Replace(section.Desc, " ", "-", -1)))
		metrics = append(metrics, fmt.Sprintf("%v.tests_pass:%d|g", metrics_prefix, res_section.PassCount))
		metrics = append(metrics, fmt.Sprintf("%v.tests_warn:%d|g", metrics_prefix, res_section.WarnCount))
		metrics = append(metrics, fmt.Sprintf("%v.tests_fail:%d|g", metrics_prefix, res_section.FailCount))
		metrics = append(metrics, fmt.Sprintf("%v.tests_total:%d|g", metrics_prefix, res_section.TestsRun))
		metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metrics_prefix, (100.0*float64(res_section.PassCount)) / float64(res_section.TestsRun)))
	}

	ofbytes, err := json.Marshal(result); if err != nil {
		log.Errorf("Could not serialize test result: %v", err.Error())
		return err
	}

	comp_result := &draiosproto.CompResult{
		TimestampNs: proto.Uint64(result.TimestampNS),
		TaskName: proto.String(result.TaskName),
		ModName: task.ModName,
		TaskId: proto.Uint64(result.Id),
		Successful: proto.Bool(true),
		ExtResult: proto.String(string(ofbytes[:])),
	}

	results.Results = append(results.Results, comp_result)

	evt.Events = cevts
	evt.Results = results

	log.Debugf("Sending docker-bench comp_evt: %v", evt)
	evtsChannel <- evt

	// Metrics we emit:
	//  Overall, and for each section: Tests Ran/Tests Passed/% of Tests Passing

	metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.score:%d|g", bres.Score))
	metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.tests_pass:%d|g", result.PassCount))
	metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.tests_warn:%d|g", result.WarnCount))
	metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.tests_fail:%d|g", result.FailCount))
	metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.tests_total:%d|g", result.TestsRun))
	metrics = append(metrics, fmt.Sprintf("compliance.docker-bench.pass_pct:%f|g", (100.0*float64(result.PassCount)) / float64(result.TestsRun)))

	for _, metric := range metrics {
		log.Debugf("Sending docker-bench metric: %v", metric)
		metricsChannel <- metric
	}

	return nil
}
