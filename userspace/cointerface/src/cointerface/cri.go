package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/containerd/cgroups"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"io"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"os"
	"strings"
)

type CriClient struct {
	conn          *grpc.ClientConn
	runtimeClient pb.RuntimeServiceClient
}

func NewCriClient(socket string) (*CriClient, error) {
	c := &CriClient{}
	var err error
	c.conn, err = grpc.Dial(socket, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("could not connect to the cri-o endpoint: %v", err)
	}

	c.runtimeClient = pb.NewRuntimeServiceClient(c.conn)
	return c, nil
}

func (c *CriClient) Close() error {
	return c.conn.Close()
}

func (c *CriClient) StopContainer(containerID string, timeout int64) error {
	if containerID == "" {
		return nil
	}

	request := &pb.StopContainerRequest{
		ContainerId: containerID,
		Timeout:     timeout,
	}

	_, err := c.runtimeClient.StopContainer(context.Background(), request)
	if err != nil {
		return err
	}
	return nil
}

func (c *CriClient) PauseContainer(containerID string) error {
	control, err := cgroups.Load(cgroups.V1, c.cgroupPathForContainer(containerID))
	if err != nil {
		return err
	}

	if err = control.Freeze(); err != nil {
		return err
	}

	return nil
}

func (c *CriClient) UnpauseContainer(containerID string) error {
	control, err := cgroups.Load(cgroups.V1, c.cgroupPathForContainer(containerID))
	if err != nil {
		return err
	}

	if err = control.Thaw(); err != nil {
		return err
	}

	return nil
}

// cgroupPathForContainer creates an object that conforms to the cgroups.Path interface
// from a cri-o container ID. cgroups can deal with both systemd and non-systemd cgroups
// but has issues locating the right path in the agent container env.
func (c *CriClient) cgroupPathForContainer(containerID string) (cgroups.Path) {
	req := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	resp, err := c.runtimeClient.ContainerStatus(context.Background(), req)
	if err != nil {
		return errorPath(fmt.Errorf("could not request ContainerStatus for %s: %s", containerID, err))
	}

	pid, ok := resp.GetInfo()["pid"]
	if !ok {
		return errorPath(fmt.Errorf("could not get pid for container %s", containerID))
	}

	p := fmt.Sprintf("/proc/%s/cgroup", pid)
	paths, err := parseCgroupFile(p)
	if err != nil {
		return errorPath(errors.Wrapf(err, "parse cgroup file %s", p))
	}

	return func(name cgroups.Name) (string, error) {
		root, ok := paths[string(name)]
		if !ok {
			if root, ok = paths[fmt.Sprintf("name=%s", name)]; !ok {
				return "", cgroups.ErrControllerNotActive
			}
		}
		return root, nil
	}
}

// Helper functions from github.com/containerd/cgroups. We need these to implement our custom Path function but
// the library does not expose them, therefore we need to replicate them here.
func errorPath(err error) cgroups.Path {
	return func(_ cgroups.Name) (string, error) {
		return "", err
	}
}

func parseCgroupFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCgroupFromReader(f)
}

func parseCgroupFromReader(r io.Reader) (map[string]string, error) {
	var (
		cgroups = make(map[string]string)
		s       = bufio.NewScanner(r)
	)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}
		var (
			text  = s.Text()
			parts = strings.SplitN(text, ":", 3)
		)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid cgroup entry: %q", text)
		}
		for _, subs := range strings.Split(parts[1], ",") {
			if subs != "" {
				cgroups[subs] = parts[2]
			}
		}
	}
	return cgroups, nil
}
