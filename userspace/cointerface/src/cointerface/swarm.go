package main

import (
	"context"
	"fmt"

	"draiosproto"
	"sdc_internal"
	log "github.com/cihub/seelog"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
	"github.com/golang/protobuf/proto"
	"os"
	"strings"
)

/*
type PosixQueue struct {
	fd C.mqd_t
}

func NewPosixQueue(name string) PosixQueue {
	queue_name := C.CString(name)
	defer C.free(unsafe.Pointer(queue_name))
	var fd C.mqd_t = C.mqopen(queue_name, C.O_CREAT|C.O_WRONLY|C.O_NONBLOCK, C.S_IRWXU)
	return PosixQueue{fd}
}

func (q *PosixQueue) Send(data []byte) {
	C.mq_send(q.fd, (*C.char)(unsafe.Pointer(&data[0])), C.size_t(len(data)), 0)
}
*/

func labelsToProtobuf(labels map[string]string) (ret []*draiosproto.SwarmPair) {
	for k, v := range labels {
		ret = append(ret, &draiosproto.SwarmPair{Key: proto.String(k), Value: proto.String(v)})
	}
	return
}

func virtualIPsToProtobuf(vIPs []swarm.EndpointVirtualIP) (ret []string) {
	for _, vip := range vIPs {
		ret = append(ret, vip.Addr)
	}
	return
}

func portsToProtobuf(ports []swarm.PortConfig) (ret []*draiosproto.SwarmPort) {
	for _, port := range ports {
		ret = append(ret, &draiosproto.SwarmPort{Port: proto.Uint32(port.TargetPort),
			PublishedPort: proto.Uint32(port.PublishedPort),
			Protocol:      proto.String(string(port.Protocol))})
	}
	return
}

func serviceToProtobuf(service swarm.Service) *draiosproto.SwarmService {
	return &draiosproto.SwarmService{Common: &draiosproto.SwarmCommon{
			Id:     proto.String(service.ID),
			Name:   proto.String(service.Spec.Name),
			Labels: labelsToProtobuf(service.Spec.Labels)},
		VirtualIps: virtualIPsToProtobuf(service.Endpoint.VirtualIPs),
		Ports:      portsToProtobuf(service.Endpoint.Ports),
	}
}

func taskToProtobuf(task swarm.Task) *draiosproto.SwarmTask {
	return &draiosproto.SwarmTask{Common: &draiosproto.SwarmCommon{
			Id: proto.String(task.ID),
		},
		ServiceId:   proto.String(task.ServiceID),
		NodeId:      proto.String(task.NodeID),
		ContainerId: proto.String(task.Status.ContainerStatus.ContainerID[:12])}
}

func nodeToProtobuf(node swarm.Node) *draiosproto.SwarmNode {
	var addr string
	// It looks that sometimes node.Status.Addr is 127.0.0.1
	// on managers, so for them report the ManagerStatus.Addr
	if node.ManagerStatus != nil {
		addr = strings.Split(node.ManagerStatus.Addr, ":")[0]
	} else {
		addr = node.Status.Addr
	}
	return &draiosproto.SwarmNode{Common: &draiosproto.SwarmCommon{
		Id:     proto.String(node.ID),
		Name:   proto.String(node.Description.Hostname),
		Labels: labelsToProtobuf(node.Spec.Labels),
	}, Role: proto.String(string(node.Spec.Role)), IpAddress: proto.String(addr)}
}

func getSwarmState(ctx context.Context, cmd *sdc_internal.SwarmStateCommand) (*sdc_internal.SwarmStateResult, error) {
	log.Debugf("Received swarmstate command message: %s", cmd.String())

	// If SYSDIG_HOST_ROOT is set, use that as a part of the
	// socket path.

	sysdigRoot := os.Getenv("SYSDIG_HOST_ROOT")
	if sysdigRoot != "" {
		sysdigRoot = sysdigRoot + "/"
	}
	dockerSock := fmt.Sprintf("unix:///%svar/run/docker.sock", sysdigRoot)
	cli, err := client.NewClient(dockerSock, "v1.26", nil, nil)
	if err != nil {
		ferr := fmt.Errorf("Could not create docker client: %s", err)
		log.Errorf(ferr.Error())
		return nil, ferr
	}

	info, err := cli.Info(context.Background())
	if err != nil {
		ferr := fmt.Errorf("Could not get docker client info: %s", err)
		return nil, ferr
	}
	clusterId := proto.String(info.Swarm.Cluster.ID)
	isManager := info.Swarm.ControlAvailable

	m := &draiosproto.SwarmState{ClusterId: clusterId}

	if isManager {
		if services, err := cli.ServiceList(ctx, types.ServiceListOptions{}); err == nil {
			for _, service := range services {
				m.Services = append(m.Services, serviceToProtobuf(service))
				stack := service.Spec.Labels["com.docker.stack.namespace"]
				if stack == "" {
					stack = "none"
				}
				// fmt.Printf("service id=%s name=%s stack=%s ip=%s\n", service.ID[:10], service.Spec.Name, stack, virtualIPsToProtobuf(service.Endpoint.VirtualIPs))
			}
		} else {
			fmt.Printf("Error fetching services: %s\n", err)
		}

		if nodes, err := cli.NodeList(ctx, types.NodeListOptions{}); err == nil {
			for _, node := range nodes {
				m.Nodes = append(m.Nodes, nodeToProtobuf(node))
				// fmt.Printf("node id=%s name=%s role=%s availability=%s\n", node.ID, node.Description.Hostname, node.Spec.Role, node.Spec.Availability)
			}
		} else {
			fmt.Printf("Error fetching nodes: %s\n", err)
		}

		args := filters.NewArgs()
		args.Add("desired-state", "running")
		args.Add("desired-state", "accepted")
		if tasks, err := cli.TaskList(ctx, types.TaskListOptions{Filters: args}); err == nil {
			for _, task := range tasks {
				m.Tasks = append(m.Tasks, taskToProtobuf(task))
				// fmt.Printf("task id=%s name=%s service=%s node=%s status=%s containerid=%s\n", task.ID, task.Name, task.ServiceID, task.NodeID, task.Status.State, task.Status.ContainerStatus.ContainerID[:12])
			}
		} else {
			fmt.Printf("Error fetching tasks: %s\n", err)
		}
	}

    res := &sdc_internal.SwarmStateResult{}
    res.Successful = proto.Bool(err == nil)
    if err != nil {
        res.Errstr = proto.String(err.Error())
    }
	res.State = m;

    log.Debugf("SwarmState Sending response: %s", res.String())

    return res, nil
}
