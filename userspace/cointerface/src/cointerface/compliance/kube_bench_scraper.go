package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	draiosproto "protorepo/agent-be/proto"
	"strings"
	"text/template"
	"time"

	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
)

func findProcess(candidates []string, env []string) bool {
	for _, cand := range candidates {
		// Check for the candidate at the beginning of the
		// line, with an optional path
		prefix := "^(/[^/[:space:]]*)*" + cand
		cmd := exec.Command("pgrep", "-f", prefix)
		cmd.Env = env

		out, err := cmd.Output()

		log.Debugf("Output from checking %s: %s %v", cand, out, err)

		if err == nil {
			return true
		}
	}

	return false
}

var (
	//
	// Figure out which way to run by looking for an apiserver
	// process. kube-bench requires additional services such as
	// the scheduler, etcd, etc to be running on the master, but
	// at this level we only need to distinguish between master
	// and node versions.
	// [vz] now we distinguish targets based on cis version
	serverCmds = []string{
		"kube-apiserver",
		"hyperkube apiserver",
		"hyperkube kube-apiserver",
		"apiserver",
		//OpenShift specific checks
		"hypershift openshift-kube-apiserver",
		"openshift start master api",
		"etcd",
	}
	nodeCmds = []string{
		"hyperkube kubelet",
		"kubelet",
	}
)

func (impl *KubeBenchImpl) Variant(stask *ScheduledTask) string {

	if impl.variant != "" {
		return impl.variant
	}

	// kube-bench can either perform master or node checks,
	// depending on whether the program is running on the host
	// where the api server is running, or any other node.

	impl.variant = "none"

	// If a variant was explicitly provided, use it
	for _, param := range stask.task.TaskParams {
		if *param.Key == "variant" {
			if *param.Val != "master" && *param.Val != "node" {
				_ = log.Errorf("Ignoring configured variant %s, as it is not \"master\" or \"node\"", *param.Val)
			} else {
				impl.variant = *param.Val
				break
			}
		}
	}

	if impl.variant == "none" {
		if findProcess(serverCmds, stask.env) {
			impl.variant = "master"
		} else {
			if findProcess(nodeCmds, stask.env) {
				impl.variant = "node"
			}
		}
	}

	log.Debugf("Variant %s", impl.variant)
	return impl.variant
}

func (impl *KubeBenchImpl) getBenchmark(task *draiosproto.CompTask) string {
	for _, param := range task.TaskParams {
		if *param.Key == "benchmark" {
			return *param.Val
		}
	}
	return "none"
}

func (impl *KubeBenchImpl) genTargets(benchmark, variant string) string {

	switch benchmark {
	case "cis-1.6":
		if variant == "node" {
			return "node,policies"
		} else {
			return "master,controlplane,etcd,policies"
		}
	case "gke-1.0":
		if variant == "node" {
			return "node,policies"
		} else {
			return "master,controlplane,etcd,policies,managedservices"
		}
	case "eks-1.0":
		if variant == "node" {
			return "node,policies"
		} else {
			return "controlplane,etcd,policies,managedservices"
		}
	}
	return "none"
}

func (impl *KubeBenchImpl) GenArgs(stask *ScheduledTask) ([]string, error) {
	args := []string{"--json"}
	benchmark := impl.getBenchmark(stask.task)
	if benchmark != "none" {
		args = append(args, "--benchmark", benchmark)
	}

	targets := impl.genTargets(benchmark, impl.Variant(stask))
	if targets != "none" {
		args = append(args, "run", "--targets", targets)
	} else {
		args = append(args, impl.Variant(stask))
	}

	return args, nil
}

func (impl *KubeBenchImpl) ShouldRun(stask *ScheduledTask) bool {
	return impl.Variant(stask) != "none"
}

type KubeBenchImpl struct {
	customerId string `json:"customerId"`
	machineId  string `json:"machineId"`
	variant    string `json:"variant"`
}

type kubeTestResult struct {
	TestNumber string   `json:"test_number"`
	TestDesc   string   `json:"test_desc"`
	Type       string   `json:"type"`
	TestInfo   []string `json:"test_info"`
	Status     string   `json:"status"`
}

type kubeTestSection struct {
	Section string           `json:"section"`
	Pass    uint64           `json:"pass"`
	Fail    uint64           `json:"fail"`
	Warn    uint64           `json:"warn"`
	Info    uint64           `json:"info"`
	Desc    string           `json:"desc"`
	Results []kubeTestResult `json:"results"`
}

type kubeBenchResults struct {
	Id        string            `json:"id"`
	Version   string            `json:"version"`
	Text      string            `json:"text"`
	NodeType  string            `json:"node_type"`
	Tests     []kubeTestSection `json:"tests"`
	TotalPass uint64            `json:"total_pass"`
	TotalFail uint64            `json:"total_fail"`
	TotalWarn uint64            `json:"total_warn"`
	TotalInfo uint64            `json:"total_info"`
}

// Given a test id, result, and current risk, assign a new risk based
// on the result of the test.
// The risk defaults to low and becomes medium/high if:
// - medium: any test has a WARN or FAIL result
// - high: any of the following tests has a non-PASS result:
//     - 1.1.5-8 (Insecure kubelet api access)
//     - 1.1.11 (Allow all images unconditionally)
//     - 1.1.22 (Ensure that the --kubelet-certificate-authority argument is set as appropriate)
//     - 1.1.29 (Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate)
//     - 1.1.30 (Ensure that the --client-ca-file argument is set as appropriate)
//     - 1.3.3 (Ensure that the --insecure-experimental-approve-all-kubelet-csrs-for-group argument is not set)
//     - 2.1.2 (Ensure that the --anonymous-auth argument is set to false (Scored))
//     - 2.1.3 (Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored))
//     - 2.1.4 (Ensure that the --client-ca-file argument is set as appropriate (Scored))
//     - 2.1.12 (Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Scored))
//     - Anything in 1.4 or 2.2
// this risk calculation is obsolete, generally should be performed on BE side given benchmark Levels

func (impl *KubeBenchImpl) AssignRisk(id string, result string, curRisk ResultRisk) ResultRisk {
	newRisk := low

	highTestIds := map[string]int{
		"1.1.5":  1,
		"1.1.6":  1,
		"1.1.7":  1,
		"1.1.8":  1,
		"1.1.11": 1,
		"1.1.22": 1,
		"1.1.29": 1,
		"1.1.30": 1,
		"1.3.3":  1,
		"2.1.2":  1,
		"2.1.3":  1,
		"2.1.4":  1,
		"2.1.12": 1,
	}

	if result != "PASS" &&
		((highTestIds[id] == 1 || strings.HasPrefix(id, "1.4")) ||
			(highTestIds[id] == 2 || strings.HasPrefix(id, "2.2"))) {
		newRisk = high
	} else if result != "PASS" {
		newRisk = medium
	}

	if newRisk == high || (newRisk == medium && curRisk == low) {
		return newRisk
	}

	return curRisk
}

func (impl *KubeBenchImpl) Scrape(
	rootPath string,
	moduleName string,
	task *draiosproto.CompTask,
	includeDesc bool,
	evtsChannel chan *sdc_internal.CompTaskEvent,
) error {

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
	// Read kube-bench's stdout, which contains the test results as json
	raw, err := ioutil.ReadFile(rootPath + "/stdout.txt")
	if err != nil {
		_ = log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	// raw is a json array for new aqua kube-bench or a single object for v0.2.4
	var targets []kubeBenchResults
	err = json.Unmarshal(raw, &targets)
	if err != nil {
		var bRes kubeBenchResults
		switch err.(type) {
		case *json.SyntaxError: // broken json array, kube-bench .024
			err = json.Unmarshal(raw[:err.(*json.SyntaxError).Offset-1], &bRes)
		case *json.UnmarshalTypeError: // single object, kube-bench .024
			err = json.Unmarshal(raw, &bRes)
		}
		if err != nil {
			_ = log.Errorf("Could not read json output: %v", err.Error())
			return err
		}
		targets = append(targets, bRes)
	}

	timestamp_ns := uint64(time.Now().UnixNano())

	result := &ExtendedTaskResult{
		Id:          *task.Id,
		TimestampNS: timestamp_ns,
		HostMac:     impl.machineId,
		TaskName:    *task.Name,
		Risk:        low,
	}

	// If "benchmark" was provided as a param, set the ResultSchema to that value.
	for _, param := range task.TaskParams {
		if *param.Key == "benchmark" {
			result.ResultSchema = *param.Val
		}
	}

	for _, nodeResult := range targets {

		// The Monitor API is expecting openshift benchmarks to have a Version of "rh-0.7", but the results contain
		// "3.10". Doing the transformation here to avoid forcing customers to upgrade their BE.
		if nodeResult.Version == "3.10" {
			result.ResultSchema = "rh-0.7"
		} else if nodeResult.Version != "" {
			result.ResultSchema = nodeResult.Version
		} else {
			result.ResultSchema = impl.getBenchmark(task)
		}

		result.TestsRun += nodeResult.TotalPass + nodeResult.TotalFail + nodeResult.TotalWarn + nodeResult.TotalInfo
		result.PassCount += nodeResult.TotalPass + nodeResult.TotalInfo
		result.FailCount += nodeResult.TotalFail
		result.WarnCount += nodeResult.TotalWarn

		attr := &TaskResultAttribute{
			K8sNodeType: nodeResult.NodeType,
		}

		result.Attributes = append(result.Attributes, *attr)

		for _, section := range nodeResult.Tests {

			res_section := &TaskResultSection{
				SectionId: section.Section,
				TestsRun:  section.Pass + section.Fail + section.Warn + section.Info,
				PassCount: section.Pass + section.Info,
				FailCount: section.Fail,
				WarnCount: section.Warn,
			}

			if includeDesc {
				res_section.Description = section.Desc
			}

			metrics_prefix := fmt.Sprintf("compliance.k8s-bench.%v.%v", section.Section, strings.ToLower(strings.Replace(section.Desc, " ", "-", -1)))
			metrics = append(metrics, fmt.Sprintf("%v.tests_fail:%d|g", metrics_prefix, res_section.FailCount))
			metrics = append(metrics, fmt.Sprintf("%v.tests_warn:%d|g", metrics_prefix, res_section.WarnCount))
			metrics = append(metrics, fmt.Sprintf("%v.tests_pass:%d|g", metrics_prefix, res_section.PassCount))
			metrics = append(metrics, fmt.Sprintf("%v.tests_total:%d|g", metrics_prefix, res_section.TestsRun))
			metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metrics_prefix, (100.0*float64(res_section.PassCount))/float64(res_section.TestsRun)))

			for _, test := range section.Results {

				result.Risk = impl.AssignRisk(test.TestNumber, test.Status, result.Risk)

				res_test := &TaskResultTest{
					TestNumber: test.TestNumber,
				}

				if includeDesc {
					res_test.Description = test.TestDesc
				}

				if test.Status != "PASS" && test.Status != "INFO" {

					// XXX/mstemm this needs to change pending expanded event stream work.
					if false {
						fields := map[string]string{
							"Task":        moduleName,
							"SectionDesc": section.Desc,
							"TestId":      test.TestNumber,
							"TestDesc":    test.TestDesc,
							"TestResult":  test.Status,
							"falco.rule":  "compliance_modules",
						}
						tmplstr := "Compliance task \"{{.Task}}\" test {{.SectionDesc}}/{{.TestId}} ({{.TestDesc}}) result: {{.TestResult}}."
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

						cevt := &draiosproto.CompEvent{
							TimestampNs:  proto.Uint64(timestamp_ns),
							TaskName:     proto.String(*task.Name),
							Output:       proto.String(outputString.String()),
							OutputFields: fields,
						}

						cevts.Events = append(cevts.Events, cevt)
					}
					if test.Status == "WARN" {
						res_test.Status = warn
					} else {
						res_test.Status = fail
					}
				} else {
					res_test.Status = pass
				}
				res_section.Results = append(res_section.Results, *res_test)
			}
			result.Tests = append(result.Tests, *res_section)
		}
	}
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

	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_pass:%d|g", result.PassCount))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_fail:%d|g", result.FailCount))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_warn:%d|g", result.WarnCount))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_total:%d|g", result.TestsRun))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.pass_pct:%f|g", (100.0*float64(result.PassCount))/float64(result.TestsRun)))

	evt.Events = cevts
	evt.Results = results
	evt.Metrics = metrics

	log.Infof("Sending kube-bench comp_evt: %v", evt)
	evtsChannel <- evt

	return nil
}
