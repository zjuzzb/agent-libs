package main

import (
	"cointerface/compliance"
	"cointerface/kubecollect"
	"cointerface/sdc_internal"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/docker/docker/client"
	"github.com/gogo/protobuf/proto"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
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
		ferr := fmt.Errorf("Unknown docker command %d", int(cmd.GetCmd()))
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

func (c *coInterfaceServer) PerformOrchestratorEventsStream(cmd *sdc_internal.OrchestratorEventsStreamCommand, stream sdc_internal.CoInterface_PerformOrchestratorEventsStreamServer) error {
	log.Infof("[PerformOrchestratorEventsStream] Starting orchestrator events stream.")
	log.Debugf("[PerformOrchestratorEventsStream] using options: %v", cmd)

	// Golang's default garbage collection allows for a lot of bloat,
	// so we set a more aggressive garbage collection because the initial
	// list of all k8s components can cause memory to balloon. After startup
	// is complete, set it back to the original value to keep CPU low.
	//
	// This changes the garbage collection value for the entire process.
	// It's possible that another RPC could alter these GC values, so do lots
	// of checking and complain loudly if the values aren't what we expect.
	initGC := int(cmd.GetStartupGc())
	origGC := setGC(initGC)
	// Other RPCs, including earlier orch calls, could have bloated
	// memory usage, so run the GC before we start our initial fetch
	log.Debug("Calling debug.FreeOSMemory()")
	debug.FreeOSMemory()

	ctx, ctxCancel := context.WithCancel(stream.Context())
	// Don't defer ctxCancel() yet
	evtc, fetchDone, err := kubecollect.WatchCluster(ctx, cmd)
	if err != nil {
		ctxCancel()
		cleanupGC(origGC, initGC)
		return err
	}

	rpcDone := make(chan struct{})
	defer func() {
		// After cancelling the context, drain incoming messages
		// so all senders can unblock and exit their goroutines
		ctxCancel()
		select {
		case evt, ok := <-evtc:
			if !ok {
				break
			} else {
				log.Debugf("Draining event for {%v:%v}",
					evt.Object.GetUid().GetKind(), evt.Object.GetUid().GetId())
			}
		}
		// Close after draining in case this gets invoked while
		// we're draining events during the initial fetch
		close(rpcDone)
	}()

	// Reset the GC settings after the initial fetch
	// completes or the RPC exits
	go func() {
		select {
		case <-fetchDone:
			log.Info("Orch events initial fetch complete")
		case <-rpcDone:
			log.Debug("Orch events RPC exiting")
		}

		cleanupGC(origGC, initGC)
	}()

	log.Infof("[PerformOrchestratorEventsStream] Entering select loop.")
	for {
		select {
		case evt, ok := <-evtc:
			if !ok {
				log.Debugf("[PerformOrchestratorEventsStream] event stream finished")
				return nil
			} else if err := stream.Send(&evt); err != nil {
				log.Errorf("Stream response for {%v:%v} failed: %v",
					evt.Object.GetUid().GetKind(), evt.Object.GetUid().GetId(), err)
				return err
			}
		case <-ctx.Done():
			log.Debugf("[PerformOrchestratorEventsStream] context cancelled")
			return nil
		}
	}

	return nil
}

// The GC helpers only support PerformOrchestratorEventsStream currently
// Using them with another RPC could lead to races in changing/restoring
func setGC(newGC int) int {
	prevGC := debug.SetGCPercent(newGC)
	log.Debugf("Orch events RPC, setting GC to %v (was %v)",
		newGC, prevGC)

	const defaultGC = 100
	if prevGC != defaultGC {
		log.Warnf("Starting orch events RPC, orig GC was %v instead of %v",
			prevGC, defaultGC)
	}

	return prevGC
}

func cleanupGC(origGC int, initGC int) {
	prevGC := debug.SetGCPercent(origGC)
	log.Debugf("Orch events RPC, setting GC to %v (was %v)",
		origGC, prevGC)

	if prevGC != initGC {
		log.Errorf("Cleaning up orch events RPC, GC val was %v, expected %v",
			prevGC, initGC)
	}

	log.Debug("Calling debug.FreeOSMemory()")
	debug.FreeOSMemory()
}

func startServer(sock string, modulesDir string) int {
	log.Tracef("Starting cointerface server, grpc version %s", grpc.Version)

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
	if err = compliance.Register(grpcServer, modulesDir); err != nil {
		log.Errorf("Could not initialize compliance grpc server: %s. Exiting.", err.Error())
		return 1
	}

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
