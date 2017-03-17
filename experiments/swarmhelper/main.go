package main

// #cgo LDFLAGS: -lrt
// #include <mqueue.h>
// #include <fcntl.h>
// #include <sys/stat.h>
// #include <stdlib.h>
// mqd_t mqopen(const char* s, int f, mode_t mode) { return mq_open(s, f, mode, 0); }
import "C"

import (
	"./draiosproto"
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
	"github.com/golang/protobuf/proto"
	"os"
	"time"
	"unsafe"
)

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
	return &draiosproto.SwarmNode{Common: &draiosproto.SwarmCommon{
		Id:     proto.String(node.ID),
		Name:   proto.String(node.Description.Hostname),
		Labels: labelsToProtobuf(node.Spec.Labels),
	}, Role: proto.String(string(node.Spec.Role)), IpAddress: proto.String(node.Status.Addr)}
}

func main() {
	q := NewPosixQueue("/test")

	sysdigRoot := os.Getenv("SYSDIG_HOST_ROOT")
	dockerSock := fmt.Sprintf("unix:///%s/var/run/docker.sock", sysdigRoot)
	cli, err := client.NewClient(dockerSock, "v1.26", nil, nil)
	if err != nil {
		panic(err)
	}

	timer := time.NewTicker(time.Second * 10)
	for {
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		info, err := cli.Info(context.Background())
		if err != nil {
			continue
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
					fmt.Printf("service id=%s name=%s stack=%s ip=%s\n", service.ID[:10], service.Spec.Name, stack, virtualIPsToProtobuf(service.Endpoint.VirtualIPs))
				}
			} else {
				fmt.Printf("Error fetching services: %s\n", err)
			}

			if nodes, err := cli.NodeList(ctx, types.NodeListOptions{}); err == nil {
				for _, node := range nodes {
					m.Nodes = append(m.Nodes, nodeToProtobuf(node))
					fmt.Printf("node id=%s name=%s role=%s availability=%s\n", node.ID, node.Description.Hostname, node.Spec.Role, node.Spec.Availability)
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
					fmt.Printf("task id=%s name=%s service=%s node=%s status=%s containerid=%s\n", task.ID, task.Name, task.ServiceID, task.NodeID, task.Status.State, task.Status.ContainerStatus.ContainerID[:12])
				}
			} else {
				fmt.Printf("Error fetching tasks: %s\n", err)
			}
		}

		fmt.Printf("Protobuf %s\n", proto.MarshalTextString(m))
		if data, err := proto.Marshal(m); err == nil {
			q.Send(data)
		}
		<-timer.C
	}
}
