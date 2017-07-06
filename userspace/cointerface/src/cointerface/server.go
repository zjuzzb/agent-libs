package main

import (
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/docker/docker/client"
	"github.com/gogo/protobuf/proto"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"io"
	"crypto/rand"
	"os/signal"
	"draiosproto"
	"sdc_internal"
	"sync"
	"time"
)

// Reusing docker clients, so we don't need to reconnect to docker daemon
// for every request and also because connections don't appear to get closed
// when the docker client goes out of scope
// We keep one per version, they're supposed to be thread-safe
var dockerClientMapMutex = &sync.Mutex{}
var dockerClientMap = make(map[string]*client.Client)

func GetDockerClient(ver string) (*client.Client, error) {
	dockerClientMapMutex.Lock()
	if cli, exists := dockerClientMap[ver]; exists {
		dockerClientMapMutex.Unlock()
		return cli, nil
	}
	// If SYSDIG_HOST_ROOT is set, use that as a part of the socket path.
	sysdigRoot := os.Getenv("SYSDIG_HOST_ROOT")
	if sysdigRoot != "" {
		sysdigRoot = sysdigRoot + "/"
	}
	dockerSock := fmt.Sprintf("unix:///%svar/run/docker.sock", sysdigRoot)

	cli, err := client.NewClient(dockerSock, ver, nil, nil)
	if err != nil {
		dockerClientMapMutex.Unlock()
		ferr := fmt.Errorf("Could not create docker client: %s", err)
		return nil, ferr
	}
	dockerClientMap[ver] = cli
	dockerClientMapMutex.Unlock()
	return cli, nil
}

type coInterfaceServer struct {
}

func (c *coInterfaceServer) PerformDockerCommand(ctx context.Context, cmd *sdc_internal.DockerCommand) (*sdc_internal.DockerCommandResult, error) {
	log.Debugf("Received docker command message: %s", cmd.String())

	cli, err := GetDockerClient("v1.18")
	if err != nil {
		return nil, err
	}

	thirty_secs := time.Second * 30
	switch cmd.GetCmd() {
	case sdc_internal.DockerCmdType_STOP:
		err = cli.ContainerStop(ctx, cmd.GetContainerId(), &thirty_secs)

	case sdc_internal.DockerCmdType_PAUSE:
		err = cli.ContainerPause(ctx, cmd.GetContainerId())

	case sdc_internal.DockerCmdType_UNPAUSE:
		err = cli.ContainerUnpause(ctx, cmd.GetContainerId())

	default:
		ferr := fmt.Errorf("Unknown docker command %u", int(cmd.GetCmd()))
		log.Errorf(ferr.Error())
		return nil, ferr
	}

	res := &sdc_internal.DockerCommandResult{}
	res.Successful = proto.Bool(err == nil)
	if err != nil {
		res.Errstr = proto.String(err.Error())
	}

	log.Debugf("Sending response: %s", res.String())

	return res, nil
}

func (c *coInterfaceServer) PerformPing(ctx context.Context, cmd *sdc_internal.Ping) (*sdc_internal.Pong, error) {
	log.Debugf("Received ping message: %s", cmd.String())

	res := &sdc_internal.Pong{}
	res.Token = proto.Int64(cmd.GetToken())
	pid := int32(os.Getpid())
	res.Pid = proto.Int32(pid)
	res.MemoryUsed = proto.Uint64(0)

	// Try to get our own process's memory usage. If this results
	// in an error, we still let the ping succeed but use a memory
	// usage of 0.
	self, err := process.NewProcess(pid)
	if err != nil {
		log.Errorf("Could not get process info for self: %s", err)
	} else {
		stat, err := self.MemoryInfo()

		if err != nil {
			log.Errorf("Could not get memory usage for self: %s", err)
		} else {
			res.MemoryUsed = proto.Uint64(stat.RSS / 1024)
		}
	}

	log.Debugf("Sending response: %s", res.String())

	return res, nil
}

func (c *coInterfaceServer) PerformSwarmState(ctx context.Context, cmd *sdc_internal.SwarmStateCommand) (*sdc_internal.SwarmStateResult, error) {
	return getSwarmState(ctx, cmd)
}

func newUUID() string {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return ""
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func newCongroup(uid *draiosproto.CongroupUid, parents []*draiosproto.CongroupUid) (*draiosproto.ContainerGroup) {
	return &draiosproto.ContainerGroup{
	     	Uid:  uid,
		Tags: map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		},
		IpAddresses: []string{"1.2.3.4"},
		// Ports
		Metrics: map[string]uint32{
			"key4": 0,
			"key5": 0,
		},
		// Children: <- we could probably avoid to pass this info on the wire
		Parents: parents,
	}
}

func (c *coInterfaceServer) PerformOrchestratorEventsStream(cmd *sdc_internal.OrchestratorEventsStreamCommand, stream sdc_internal.CoInterface_PerformOrchestratorEventsStreamServer) error {
	log.Infof("[PerformOrchestratorEventsStream] Starting orchestrator events stream.")

	uids := []*draiosproto.CongroupUid {
		&draiosproto.CongroupUid{Kind:proto.String("k8s_namespace"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_deployment"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_service"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_replicaset"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_pod"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_pod"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_pod"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("k8s_pod"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("container"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("container"),Id:proto.String("testUUID")},
		&draiosproto.CongroupUid{Kind:proto.String("container"),Id:proto.String(newUUID())},
		&draiosproto.CongroupUid{Kind:proto.String("container"),Id:proto.String(newUUID())},
	}
	parents := [][]*draiosproto.CongroupUid {
		{},				// namespace
		{uids[0]},			// deployment
		{uids[0]},			// service
		{uids[0], uids[1]},		// replicaset
		{uids[0], uids[2], uids[3]},	// pod1
		{uids[0], uids[2], uids[3]},	// pod2
		{uids[0], uids[2], uids[3]},	// pod3
		{uids[0]},			// pod4
		{uids[4]},	   		// container1
		{uids[5]},	   		// container2
		{uids[6]},	   		// container3
		{uids[7]},	   		// container3
	}
	objects := []*draiosproto.ContainerGroup {}
	// Add all the components
	for i := 0; i < len(uids); i++ {
		log.Infof(fmt.Sprintf("[PerformOrchestratorEventsStream] Starting to create event #%d.", i+1))
		objects = append(objects, newCongroup(uids[i], parents[i]))
		evt := &draiosproto.CongroupUpdateEvent{
			Type :   draiosproto.CongroupEventType_ADDED.Enum(),
			Object : objects[i],
		}
		log.Infof("[PerformOrchestratorEventsStream] evt created.")
		log.Infof("[PerformOrchestratorEventsStream] " + evt.String())
		if err := stream.Send(evt); err != nil {
			return err
		}
		log.Infof(fmt.Sprintf("[PerformOrchestratorEventsStream] Event #%d sent.", i+1))
		//time.Sleep(time.Second)
	}

	// Remove 1 Pod
	//time.Sleep(time.Second*2)
	if err := stream.Send(&draiosproto.CongroupUpdateEvent {
		Type :   draiosproto.CongroupEventType_REMOVED.Enum(),
		Object : objects[6],
	}); err != nil {
		return err
	}

	// Update the replicaset
	//time.Sleep(time.Second*2)
	objects[3] = &draiosproto.ContainerGroup{
		Uid:  objects[3].Uid,
		Tags: map[string]string{
			"test_equal": "equaltothis",
			"test_contains": "first second third",
			"test_startswith": "prefixfoo",
			"test_in": "bar",
		},
		Metrics: map[string]uint32{
			"replicas_desired": 5,
			"replicas_running": 5,
		},
		Parents: objects[3].Parents,
	}
	if err := stream.Send(&draiosproto.CongroupUpdateEvent {
		Type :   draiosproto.CongroupEventType_UPDATED.Enum(),
		Object : objects[3],
	}); err != nil {
		return err
	}

	// Update the namespace
	//time.Sleep(time.Second*2)
	objects[0] = &draiosproto.ContainerGroup{
		Uid:  objects[0].Uid,
		Tags: map[string]string{
			"test_equal_ns": "equaltothis",
			"test_contains_ns": "first second third",
			"test_startswith_ns": "prefixfoo",
			"test_in_ns": "bar",
		},
		Metrics: objects[0].Metrics,
		Parents: objects[0].Parents,
	}
	if err := stream.Send(&draiosproto.CongroupUpdateEvent {
		Type :   draiosproto.CongroupEventType_UPDATED.Enum(),
		Object : objects[0],
	}); err != nil {
		return err
	}

	// Add the pod again
	//time.Sleep(time.Second*2)
	if err := stream.Send(&draiosproto.CongroupUpdateEvent {
		Type :   draiosproto.CongroupEventType_ADDED.Enum(),
		Object : objects[6],
	}); err != nil {
		return err
	}

	log.Infof("[PerformOrchestratorEventsStream] All events sent. Exiting.")
	return nil
}

func startServer(sock string) int {

	// Try to remove any existing socket
	_, err := os.Stat(sock)
	if err == nil {
		log.Debugf("Removing existing socket %s", sock)
		err := os.Remove(sock)

		if err != nil {
			log.Errorf("Could not remove exiting socket %s: %s. Exiting.", sock, err)
			return 1
		}
	}

	listener, err := net.Listen("unix", sock)

	if err != nil {
		log.Criticalf("Could not listen on socket %s: %s", sock, err)
		return (1)
	}

	defer listener.Close()
	defer os.Remove(sock)

	log.Infof("Listening on %s for messages", sock)

	grpcServer := grpc.NewServer()
	sdc_internal.RegisterCoInterfaceServer(grpcServer, &coInterfaceServer{})

	// Capture SIGINT and exit gracefully
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	go func() {
		for {
			sig := <-signals
			log.Debugf("Received signal %s, closing listener", sig)
			listener.Close()
		}
	}()

	grpcServer.Serve(listener)

	return 0
}
