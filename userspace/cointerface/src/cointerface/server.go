package main

import (
	"cointerface/kubecollect"
	"cointerface/draiosproto"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/docker/docker/client"
	"github.com/gogo/protobuf/proto"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"net"
	"os"
	"os/signal"
	"cointerface/sdc_internal"
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

func (c *coInterfaceServer) PerformOrchestratorEventsStream(cmd *sdc_internal.OrchestratorEventsStreamCommand, stream sdc_internal.CoInterface_PerformOrchestratorEventsStreamServer) error {
	log.Infof("[PerformOrchestratorEventsStream] Starting orchestrator events stream.")

	// TODO: refactor error messages
	var kubeClient kubernetes.Interface

	if cmd.Url != nil && *cmd.Url != "" {
		log.Infof("Connecting to k8s server at %s", *cmd.Url)
		var err error
		kubeClient, err = kubecollect.CreateKubeClient(*cmd.Url)
		if err != nil {
			log.Errorf("Cannot create k8s client: %s", err)
			return err
		}
	} else {
		log.Infof("Connecting to k8s server using inCluster config")
		var err error
		kubeClient, err = kubecollect.CreateInClusterKubeClient()
		if err != nil {
			log.Errorf("Cannot create k8s client: %s", err)
			return err
		}
	}
	log.Infof("Testing communication with server")
	srvVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		log.Errorf("K8s server not responding: %s", err)
		return err
	}
	log.Infof("Communication with server successful: %v", srvVersion)

	resources, err := kubeClient.Discovery().ServerResources()
	if err != nil {
		log.Errorf("K8s server returned error: %s", err)
		return err
	}

	kubecollect.CompatibilityMap = make(map[string]bool)
	for _, resourceList := range resources {
		for _, resource := range resourceList.APIResources {
			kubecollect.CompatibilityMap[resource.Name] = true
			log.Debugf("K8s server has %s API support.", resource.Name)
		}
	}

	// make sure we can cancel stuff later
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// let's talk
	evtc := make(chan draiosproto.CongroupUpdateEvent)
	defer close(evtc)

	// start watching some stuff
	if kubecollect.CompatibilityMap["namespaces"] {
		kubecollect.StartNamespacesSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have namespaces API support.")
	}
	if kubecollect.CompatibilityMap["deployments"] {
		kubecollect.StartDeploymentsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have deployments API support.")
	}
	if kubecollect.CompatibilityMap["replicasets"] {
		kubecollect.StartReplicaSetsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have replicasets API support.")
	}
	if kubecollect.CompatibilityMap["services"] {
		kubecollect.StartServicesSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have services API support.")
	}
	if kubecollect.CompatibilityMap["ingress"] {
		kubecollect.StartIngressSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have ingress API support.")
	}
	if kubecollect.CompatibilityMap["daemonsets"] {
		kubecollect.StartDaemonSetsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have daemonsets API support.")
	}
	if kubecollect.CompatibilityMap["nodes"] {
		kubecollect.StartNodesSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have nodes API support.")
	}
	if kubecollect.CompatibilityMap["jobs"] {
		kubecollect.StartJobsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have jobs API support.")
	}
	if kubecollect.CompatibilityMap["cronjobs"] {
		kubecollect.StartCronJobsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have cronjobs API support.")
	}
	if kubecollect.CompatibilityMap["replicationcontrollers"] {
		kubecollect.StartReplicationControllersSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have replicationcontrollers API support.")
	}
	if kubecollect.CompatibilityMap["statefulsets"] {
		kubecollect.StartStatefulSetsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have statefulsets API support.")
	}
	if kubecollect.CompatibilityMap["resourcequotas"] {
		kubecollect.StartResourceQuotasSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have resourcequotas API support.")
	}
	if kubecollect.CompatibilityMap["pods"] {
		kubecollect.StartPodsSInformer(ctx, kubeClient)
	} else {
		log.Warnf("K8s server doesn't have pods API support.")
	}

	if kubecollect.CompatibilityMap["namespaces"] {
		kubecollect.WatchNamespaces(evtc)
	}
	if kubecollect.CompatibilityMap["deployments"] {
		kubecollect.WatchDeployments(evtc)
	}
	if kubecollect.CompatibilityMap["replicasets"] {
		kubecollect.WatchReplicaSets(evtc)
	}
	if kubecollect.CompatibilityMap["services"] {
		kubecollect.WatchServices(evtc)
	}
	if kubecollect.CompatibilityMap["ingress"] {
		kubecollect.WatchIngress(evtc)
	}
	if kubecollect.CompatibilityMap["daemonsets"] {
		kubecollect.WatchDaemonSets(evtc)
	}
	if kubecollect.CompatibilityMap["nodes"] {
		kubecollect.WatchNodes(evtc)
	}
	if kubecollect.CompatibilityMap["jobs"] {
		kubecollect.WatchJobs(evtc)
	}
	if kubecollect.CompatibilityMap["cronjobs"] {
		kubecollect.WatchCronJobs(evtc)
	}
	if kubecollect.CompatibilityMap["replicationcontrollers"] {
		kubecollect.WatchReplicationControllers(evtc)
	}
	if kubecollect.CompatibilityMap["statefulsets"] {
		kubecollect.WatchStatefulSets(evtc)
	}
	if kubecollect.CompatibilityMap["resourcequotas"] {
		kubecollect.WatchResourceQuotas(evtc)
	}
	if kubecollect.CompatibilityMap["pods"] {
		kubecollect.WatchPods(evtc)
	}
	/*watch, _ := kubeClient.CoreV1().Events("").Watch(metav1.ListOptions{})

	go func() {
		select {
		case evt := <-watch.ResultChan():
			log.Infof("Received k8s event %v", evt)
		}
	}()*/

	log.Infof("[PerformOrchestratorEventsStream] Entering select loop.")
	for {
		select {
		case evt := <-evtc:
			if err := stream.Send(&evt); err != nil {
				log.Errorf("Stream response for {%v:%v} failed: %v",
					evt.Object.GetUid().GetKind(), evt.Object.GetUid().GetId(), err)

				// The C++ side will be out of sync, so
				// kill the stream and force a full resync?
			}
		case <-ctx.Done():
			return nil
		}
	}

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
