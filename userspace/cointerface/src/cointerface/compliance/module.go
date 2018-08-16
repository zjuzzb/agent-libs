package compliance

import (
	"bufio"
	"cointerface/sdc_internal"
	"cointerface/draiosproto"
	"fmt"
	"io"
	"io/ioutil"
	log "github.com/cihub/seelog"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
)

type Scraper interface {
	Scrape(rootPath string, moduleName string,
		task *draiosproto.CompTask,
		evtsChannel chan *sdc_internal.CompTaskEvent,
		metricsChannel chan string) error
}

type TaskArgsGenerator interface {
	GenArgs(task *draiosproto.CompTask) ([]string, error)
}

type Module struct {
	Name string `json:"name"`
	Prog string `json:"prog"`
	Args TaskArgsGenerator `json:"args"`
	Scrapr Scraper `json:"scraper"`
}

type ScheduledTask struct {
	task *draiosproto.CompTask
	cmd *exec.Cmd
	cmdLock sync.Mutex
	stopChan chan bool
	maxTimesRun int
	numTimesRun int
	activelyStopped bool
}

func (module *Module) Run(mgr *ModuleMgr, stask *ScheduledTask) error {

	// Create a temporary directory where this module's output will go
	outputDir, err := ioutil.TempDir("", "module-" + module.Name + "-output"); if err != nil {
		log.Errorf("Could not create temporary directory (%s)", err.Error());
		return err
	}

	moduleDir := path.Join(mgr.ModulesDir, module.Name)

	// Replace MODULE_DIR with the path to the module and
	// OUTPUT_DIR with the temporary output directory.

	prog :=	strings.Replace(strings.Replace(module.Prog, "MODULE_DIR", moduleDir, -1),
		"OUTPUT_DIR", outputDir, -1)

	args, err := module.Args.GenArgs(stask.task); if err != nil {
		return err
	}

	var subArgs []string

	for _, arg := range args {
		subArgs = append(subArgs,
			strings.Replace(strings.Replace(arg, "MODULE_DIR", moduleDir, -1),
				"OUTPUT_DIR", outputDir, -1))
	}

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

	cmd := exec.Command(prog, subArgs...)
	cmd.Env = newenv
	cmd.Dir = moduleDir

	log.Debugf("Running: %v", cmd)

	stderrPipe, err := cmd.StderrPipe(); if err != nil {
		log.Errorf("Could not create pipe for cmd stderr (%s)", err.Error());
		return err
	}

	stderrFileName := path.Join(outputDir, "stderr.txt")
	stderrFile, err := os.Create(stderrFileName); if err != nil {
		log.Errorf("Could not create stderr file (%s)", err.Error());
		return err
	}

	stderrWriter := bufio.NewWriter(stderrFile)

	stdoutPipe, err := cmd.StdoutPipe(); if err != nil {
		log.Errorf("Could not create pipe for cmd stdout (%s)", err.Error());
		return err
	}

	stdoutFileName := path.Join(outputDir, "stdout.txt")
	stdoutFile, err := os.Create(stdoutFileName); if err != nil {
		log.Errorf("Could not create stdout file (%s)", err.Error());
		return err
	}

	stdoutWriter := bufio.NewWriter(stdoutFile)

	if err = cmd.Start(); err != nil {
		log.Errorf("Could not start module %s via %v (%s)",
			module.Name, cmd, err)
		return err
	}

	stask.cmdLock.Lock()
	stask.cmd = cmd
	stask.activelyStopped = false
	stask.cmdLock.Unlock()

	go io.Copy(stderrWriter, stderrPipe)
	go io.Copy(stdoutWriter, stdoutPipe)

	// Wait for the pid in the background
	go func() {
		defer os.RemoveAll(outputDir)

		err := cmd.Wait()

		stderrWriter.Flush()
		stdoutWriter.Flush()
		stderrFile.Close()
		stdoutFile.Close()

		if err != nil {
			stderrBuf, _ := ioutil.ReadFile(stderrFileName)
			stdoutBuf, _ := ioutil.ReadFile(stdoutFileName)

			msg := fmt.Sprintf("module %s via %v exited with error (%s) Stdout: \"%s\" Stderr: \"%s\"",
				module.Name, cmd, err, string(stderrBuf), string(stdoutBuf))

			if ! stask.activelyStopped {
				log.Error(msg)
			} else {
				log.Debugf(msg)
			}

			stask.cmdLock.Lock()
			stask.cmd = nil
			stask.cmdLock.Unlock()

			return
		}

		err = module.Scrapr.Scrape(outputDir, module.Name,
			stask.task,
			mgr.evtsChannel, mgr.metricsChannel); if err != nil {
				log.Errorf("Could not scrape module %s output (%s)",
					module.Name, err);
			}
		log.Infof("Completed task %s", *stask.task.Name)

		stask.cmdLock.Lock()
		stask.cmd = nil
		stask.cmdLock.Unlock()
		return
	}()

	return nil
}
