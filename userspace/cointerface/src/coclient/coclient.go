package main

import (
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"sdc_internal"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: coclient [-sock=<path>] [-msg=<msg>] [-docker_cmd=<command>] [-container=<container id>]\n")
	fmt.Fprintf(os.Stderr, "   <msg> is one of \"ping\", \"docker_command\"")
	flag.PrintDefaults()
	os.Exit(1)
}

func initLogging() {
	testConfig := `
<seelog>
  <formats>
    <format id="common" format="%UTCDate(2006-01-02 15:04:05.0000) [%Level] %Msg%n"/>
  </formats>
  <outputs formatid="common">
    <console formatid="common"/>
  </outputs>
</seelog>
`
	logger, err := log.LoggerFromConfigAsBytes([]byte(testConfig))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not initialize logger: %s\n", err)
		os.Exit(1)
	}
	log.ReplaceLogger(logger)

}

func unixDialer(addr string, timeout time.Duration) (net.Conn, error) {
	log.Debugf("Connecting unix socket: addr=%v, timeout=%v", addr, timeout)
	sock, err := net.DialTimeout("unix", addr, timeout)
	return sock, err
}

func performDockerCommand(client sdc_internal.CoInterfaceClient, dockerCommand string, container string) int {
	cmd := &sdc_internal.DockerCommand{}

	dcmd := sdc_internal.DockerCmdType(sdc_internal.DockerCmdType_value[dockerCommand])
	cmd.Cmd = &dcmd
	cmd.ContainerId = proto.String(container)

	log.Debugf("Docker Command=%s", cmd.String())

	res, err := client.PerformDockerCommand(context.Background(), cmd)

	if err != nil {
		log.Errorf("Could not perform docker command: %s", err)
		return 1
	}

	log.Infof("Result of performing docker command: %s", res.String())

	return 0
}

func performPing(client sdc_internal.CoInterfaceClient, token int64) int {
	cmd := &sdc_internal.Ping{}

	cmd.Token = proto.Int64(token)

	log.Debugf("Ping=%s", cmd.String())

	res, err := client.PerformPing(context.Background(), cmd)

	if err != nil {
		log.Errorf("Could not perform ping: %s", err)
		return 1
	}

	log.Infof("Pong response: %s", res.String())

	return 0
}

func mymain() int {
	flag.Usage = usage
	sockPtr := flag.String("sock", "/opt/draios/run/cointerface.sock", "domain socket for messages")
	msgPtr := flag.String("msg", "ping", "Message to send to cointerface")
	tokenPtr := flag.Int64("token", 0, "Token to include in ping message")
	dockerCmdPtr := flag.String("docker_cmd", "", "docker operation to perform on container")
	containerPtr := flag.String("container", "", "container on which to run docker command")

	flag.Parse()

	// If msg is docker_command, a container must be provided
	if *msgPtr == "docker_command" && *containerPtr == "" {
		fmt.Fprintf(os.Stderr, "A container must be provided when msg==docker_command\n")
		usage()
	}

	initLogging()
	defer log.Flush()

	conn, err := grpc.Dial(*sockPtr, grpc.WithInsecure(), grpc.WithDialer(unixDialer))
	if err != nil {
		log.Errorf("Could not connect to server at %s: %s", *sockPtr, err)
		return 1
	}
	defer conn.Close()

	client := sdc_internal.NewCoInterfaceClient(conn)

	switch *msgPtr {
	case "ping":
		return performPing(client, *tokenPtr)

	case "docker_command":
		return performDockerCommand(client, *dockerCmdPtr, *containerPtr)

	default:
		fmt.Fprintf(os.Stderr, "Unknown message"+*msgPtr+"\n")
		usage()
	}

	return 0
}

func main() {
	os.Exit(mymain())
}
