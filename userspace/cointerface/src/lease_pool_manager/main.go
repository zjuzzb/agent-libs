package main

import (
	"coldstart_manager/server"
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/install_prefix"
	"github.com/wojas/genericr"
	"k8s.io/klog/v2"
	"os"
	"sync"
)

type LogMsg struct {
	Pid     int    `json:"pid"`
	Level   string `json:"level"`
	Message string `json:"message"`
}
var COLDSTART_SOCK = "coldstart.sock"
var DELEGATION_SOCK = "delegation.sock"

func createJSONEscapeFormatter(params string) log.FormatterFunc {
	return func(message string, level log.LogLevel, context log.LogContextInterface) interface{} {
		bytes, err := json.Marshal(LogMsg{
			Pid:     os.Getpid(),
			Level:   level.String(),
			Message: message,
		})
		// Turn the json into jsonl by appending a newline
		endl := "\n"
		bytes = append(bytes, endl...)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not format log message: %s\n", err)
			return message
		}

		return string(bytes)
	}
}

func initLogging(useJson bool) {

	err := log.RegisterCustomFormatter("JSONEscapeMsg", createJSONEscapeFormatter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create escaping formatter: %s", err)
		os.Exit(1)
	}

	config := `
<seelog>
  <formats>
    <format id="agent-plain" format="%Msg%n"/>
  </formats>
  <outputs>
    <console formatid="agent-plain"/>
  </outputs>
</seelog>
`
	if useJson {
		config = `
<seelog>
  <formats>
    <format id="agent-json" format="%JSONEscapeMsg"/>
  </formats>
  <outputs>
    <console formatid="agent-json"/>
  </outputs>
</seelog>
`
	}

	logger, err := log.LoggerFromConfigAsBytes([]byte(config))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not initialize logger: %s\n", err)
		os.Exit(1)
	}
	log.ReplaceLogger(logger)
}

func createKlogLogger() genericr.Logger {
	handler := func(e genericr.Entry) {
		bytes, err := json.Marshal(LogMsg{
			Pid:     os.Getpid(),
			Level:   "debug", // Level is always 0 (maybe a bug?), therefore send DEBUG to dragent
			Message: fmt.Sprintf("[leaderelection] %s", e.Message),
		})

		endl := "\n"
		bytes = append(bytes, endl...)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not format log message: %s\n", err)
		}

		fmt.Fprintln(os.Stderr, string(bytes))
	}

	return genericr.New(handler)
}

func remove_old_sock(sockName string) error {
	_, err := os.Stat(sockName)

	if err != nil {
		// sock does not exist
		return nil
	}

	log.Debugf("Removing existing socket %s", sockName)
	err = os.Remove(sockName)

	if err != nil {
		log.Errorf("Could not remove exiting socket %s: %s. Exiting.", sockName, err)
		return err
	}

	return nil
}

func mymain() int {
	klog.InitFlags(nil)

	flag.Set("logtostderr", "true")
	sock_dir := flag.String("socket-dir", "", "directory where unix sockets will be created")
	flag.Parse()

	klog.SetLogger(createKlogLogger())

	var coldstart_sock string;
	var delegation_sock string;

	if *sock_dir != "" {
		coldstart_sock = fmt.Sprintf("%s/%s", *sock_dir, COLDSTART_SOCK)
		delegation_sock = fmt.Sprintf("%s/%s", *sock_dir, DELEGATION_SOCK)
	} else {
		prefix, err := install_prefix.GetInstallPrefix()
		if err != nil {
			log.Errorf("Could not determine installation directory: %s", err)
			return 1
		}
		coldstart_sock = fmt.Sprintf("%s/run/%s", prefix, COLDSTART_SOCK)
		delegation_sock = fmt.Sprintf("%s/run/%s", prefix, DELEGATION_SOCK)
	}

	// Try to remove any existing socket
	if err := remove_old_sock(coldstart_sock); err != nil {
		log.Errorf("Exit process")
		return 1
	}

	if err := remove_old_sock(delegation_sock); err != nil {
		log.Errorf("Exit process")
		return 1
	}

	// Only returns when server is killed
	wg := sync.WaitGroup{}

	// cold start server
	wg.Add(1)
	go server.StartServer(coldstart_sock, &wg)

	// delegation server
	wg.Add(1)
	go server.StartServer(delegation_sock, &wg)

	wg.Wait()
	log.Debugf("Process ended")

	return 0
}

func main() {
	initLogging(true)
	defer log.Flush()
	os.Exit(mymain())
}
