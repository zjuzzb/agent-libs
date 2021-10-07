package kubecollect_common

import (
	"context"
	"errors"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/install_prefix"
	"github.com/draios/protorepo/sdc_internal"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"os"
	"sync/atomic"
	"time"
)

var cointdeleg bool = false
var numdeleg int32 = 0

// Atomic doesn't have booleans, we'll use int32 instead
var delegated int32 = 0
var listeners []chan bool
var delegated_nodes atomic.Value
var delegationFailure int32 = 0

func SetCointDelegation(enable bool, num int32) {
	cointdeleg = enable
	numdeleg = num

	if !cointdeleg {
		// Make sure these defaults are set appropriately if not enabled
		atomic.StoreInt32(&delegated, 1)
		atomic.StoreInt32(&delegationFailure, 1)
	}
}

func GetCointDelegation() bool {
	return cointdeleg
}

func GetNumDelegated() int32 {
	return numdeleg
}

func IsDelegated() bool {
	return atomic.LoadInt32(&delegated) != 0
}

func setDelegated(enable bool) {
	i := int32(0)
	if enable {
		log.Debugf("Setting delegated")
		i = 1
	} else {
		log.Debugf("Setting not delegated")
	}
	old := atomic.SwapInt32(&delegated, i)
	if old != i {
		for _, ch := range listeners {
			ch <- enable
		}
	}
}

func setDelegationFailure(fail bool) {
	i := int32(0)
	if fail {
		log.Infof("Delegation using leader election failed, getting all pods")
		i = 1
		// Also setting Delegated to true locally, so that we end up collecting
		// all pods as the old delegation mechanism we use for fallback relies on them.
		setDelegated(true)
	}
	atomic.StoreInt32(&delegationFailure, i)
}

func GetDelegationFailure() bool {
	return atomic.LoadInt32(&delegationFailure) != 0
}

func SetDelegatedNodes(nodes []string) {
	delegated_nodes.Store(nodes)
}

func GetDelegatedNodes() []string {
	nodes := delegated_nodes.Load()
	if nodes == nil {
		return nil
	}
	return nodes.([]string)
}

func GetDelegateChan() chan bool {
	listener := make(chan bool, 1)
	listeners = append(listeners, listener)
	return listener
}

var delegatedNodesStarted bool = false

func runDelegatedNodes(ctx context.Context, client *sdc_internal.LeasePoolManagerClient) {
	time.Sleep(time.Second)
	for {
		nodes, err := (*client).GetNodesWithLease(ctx, &sdc_internal.LeasePoolNull{})
		if err != nil {
			log.Errorf("Error while getting nodes: %s", err.Error())
			return
		}

		for {
			res, err := nodes.Recv()
			if err != nil {
				log.Debug("GetNodes stream closed. restarting")
				break
			}
			log.Debug("GetNodes got: %v+", *res)
			SetDelegatedNodes(res.Node)
		}
		time.Sleep(time.Second * 10)
	}
}

func StartDelegatedNodes(ctx context.Context, cmd *sdc_internal.OrchestratorEventsStreamCommand, prefix string) {
	if delegatedNodesStarted {
		return
	}
	nodesClient, conn, err := createLeasePoolClient(ctx, fmt.Sprintf("unix:%s/%s", prefix, DELEGATION_SOCK), DELEGATION_LEASENAME, uint32(*cmd.DelegatedNum), cmd)

	if nodesClient == nil || err != nil {
		log.Error("Failed to get lease pool client for delegated nodes!")
		return
	}

	go func() {
		runDelegatedNodes(ctx, nodesClient)
		conn.Close()
	}()
}

// Currently blocking
func RunDelegation(ctx context.Context, opts *sdc_internal.OrchestratorEventsStreamCommand) {
	if !GetCointDelegation() {
		return
	}
	// Create a delegation client
	var delegationClient *sdc_internal.LeasePoolManagerClient
	var conn *grpc.ClientConn
	var err error
	if *opts.DelegatedNum < 0 {
		log.Info("Forcing on delegation by configuration, num.delegated =", *opts.DelegatedNum)
		setDelegated(true)
		return
	}
	prefix, err := install_prefix.GetInstallPrefix()
	if err != nil {
		log.Warnf("Could not get installation directory. Skipping wait lease")
		// Can't use leases. Fallback to nodename-based delegation
		// This ends up setting delegation to true as well in cointerface so we still
		// get all pods as they are required for the fallback delegation to work.
		setDelegationFailure(true)
		return
	}

	delegationClient, conn, err = createLeasePoolClient(ctx, fmt.Sprintf("unix:%s/%s", prefix, DELEGATION_SOCK), DELEGATION_LEASENAME, uint32(*opts.DelegatedNum), opts)

	if delegationClient == nil || err != nil {
		log.Error("Failed to get lease pool client for delegation!")
		setDelegationFailure(true)
		return
	}

	defer conn.Close()
	StartDelegatedNodes(ctx, opts, prefix)

	log.Debug("Delegation: getting lease")
	wait, err := (*delegationClient).WaitLease(ctx, &sdc_internal.LeasePoolNull{})

	if err != nil {
		log.Errorf("Error while waiting for delegation lease: %s", err.Error())
		setDelegationFailure(true)
		return
	}

	log.Info("Delegation: waiting for lease")
	for {
		res, err := wait.Recv()
		if err != nil {
			log.Error("Delegation stream closed.")
			setDelegationFailure(true)
			return
		}

		if *res.Successful == true {
			log.Debugf("Got the lease. I am delegated!")
			setDelegated(true)
			break
		} else {
			log.Debugf("Didn't get the lease, error: %v", *res.Reason)
			setDelegationFailure(true)
			return
		}
	}
	// Staying in here so that we don't close the connection as that would cancel
	// the server side context
	<-ctx.Done()
}

var nodename atomic.Value

func HaveNode() bool {
	return nodename.Load() != nil
}

// This may block
func GetNode() string {
	InitNode()
	node, ok := nodename.Load().(string)
	if !ok {
		return ""
	}
	return node
}

func SetNode(node string) {
	nodename.Store(node)
}

var initedNode bool = false

// This may block
func InitNode() {
	if initedNode {
		return
	}
	initedNode = true
	log.Info("InitNode()")
	var node = os.Getenv("K8S_NODE")
	if node != "" {
		SetNode(node)
		log.Info("Found node from K8S_NODE variable: " + node)
		return
	}
	log.Info("No node found in K8S_NODE variable, trying API server")

	hostname, err := os.Hostname()
	if err != nil {
		log.Warn("couldn't retrieve hostname")
		return
	}

	kubeClient, _ := GetKubeClient()
	if kubeClient == nil {
		log.Warn("No kubeclient found, can't get node list")
		return
	}
	nodes, _ := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
	if nodes == nil {
		log.Warn("Failed to get node list")
		return
	}
	ips, err := externalIPs()
	if err != nil {
		log.Warnf("Couldn't get IP addresses: %v", err)
	}
	// log.Infof("Node list: %+v", nodes)
	for _, node := range nodes.Items {
		for _, nodeAddress := range node.Status.Addresses {
			_, found := ips[nodeAddress.Address]
			if found {
				log.Infof("found IP address %v in node %v", nodeAddress.Address, node.ObjectMeta.GetName())
				SetNode(node.ObjectMeta.GetName())
				return
			}
			if nodeAddress.Address == hostname {
				log.Infof("found hostname %v in node %v", hostname, node.ObjectMeta.GetName())
				SetNode(node.ObjectMeta.GetName())
				return
			}
		}
	}
	log.Info("Didn't find hostname in node list")
}

func externalIPs() (map[string]struct{}, error) {
	ips := make(map[string]struct{})

	ifaces, err := net.Interfaces()
	if err != nil {
		return ips, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return ips, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			ips[ip.String()] = struct{}{}
		}
	}
	if len(ips) > 0 {
		return ips, nil
	}
	return ips, errors.New("No external active IP addresses found")
}
