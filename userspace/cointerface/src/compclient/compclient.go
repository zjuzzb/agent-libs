package main

import (
	"compclient/draiosproto"
	"compclient/sdc_internal"
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"os"
	"time"
	"install_prefix"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: compclient [-sock=<path>] [-msg=<msg>]\n")
	fmt.Fprintf(os.Stderr, "   <msg> is one of \"start\", \"stop\"")
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

func performStart(client sdc_internal.ComplianceModuleMgrClient) int {
	start := &sdc_internal.CompStart{
		MachineId:         proto.String("my-machine-id"),
		CustomerId:        proto.String("my-customer-id"),
		Calendar:          &draiosproto.CompCalendar{},
	}
	start.Calendar.Tasks = append(start.Calendar.Tasks, &draiosproto.CompTask{
		Id:                proto.Uint64(1),
		Name:              proto.String("Check Docker Environment"),
		ModName:           proto.String("docker-bench-security"),
		Enabled:           proto.Bool(true),
		Schedule:          proto.String("PT1H"),
	})

	start.Calendar.Tasks = append(start.Calendar.Tasks, &draiosproto.CompTask{
		Id:                proto.Uint64(2),
		Name:              proto.String("Check K8s Environment"),
		ModName:           proto.String("kube-bench"),
		Enabled:           proto.Bool(true),
		Schedule:          proto.String("PT1H"),
	})

	log.Debugf("Start=%s", start.String())

	stream, err := client.Start(context.Background(), start)

	if err != nil {
		log.Errorf("%v.performStart(_) = _, %v", client, err)
		return 1
	}
	for {
		evt, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Errorf("%v.performStart(_) = _, %v", client, err)
			return 1
		}
		log.Infof("Got Compliance Event: %v", *evt)
	}

	return 0
}

func performStop(client sdc_internal.ComplianceModuleMgrClient) int {
	stop := &sdc_internal.CompStop{}

	log.Debugf("Stop=%s", stop.String())

	res, err := client.Stop(context.Background(), stop)

	if err != nil {
		log.Errorf("Could not stop: %s", err)
		return 1
	}

	log.Infof("Result of stop: %s", res.String())

	return 0
}

func mymain() int {
	flag.Usage = usage
	prefix, err := install_prefix.GetInstallPrefix()
	if err != nil {
		log.Errorf("Could not determine installation directory: %s", err)
		return 1
	}
	sockPtr := flag.String("sock", prefix + "/run/cointerface.sock", "domain socket for messages")
	msgPtr := flag.String("msg", "start", "Message to send to server. Can be one of \"start\", \"stop\".")

	flag.Parse()

	initLogging()
	defer log.Flush()

	conn, err := grpc.Dial(*sockPtr, grpc.WithInsecure(), grpc.WithDialer(unixDialer))
	if err != nil {
		log.Errorf("Could not connect to server at %s: %s", *sockPtr, err)
		return 1
	}
	defer conn.Close()

	client := sdc_internal.NewComplianceModuleMgrClient(conn)

	switch *msgPtr {
	case "start":
		return performStart(client)
	case "stop":
		return performStop(client)
	default:
		fmt.Fprintf(os.Stderr, "Unknown message"+*msgPtr+"\n")
		usage()
	}

	return 0
}

func main() {
	os.Exit(mymain())
}
