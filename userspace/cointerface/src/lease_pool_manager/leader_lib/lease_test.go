package leader_lib

import (
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"testing"
	"time"
)

func createClientSet() *kubernetes.Clientset {
	kubeconfig := "./test/config"

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err)
	}

	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		panic(err)
	}

	return clientset
}

// These tests need a running cluster. Skipping
func TestBasic(t *testing.T) {

	t.Skip()
	release := make(chan struct{})
	mycallback := func(leader *Lease) {
		log.Debugf("I am leader!!!!")
		release <- struct{}{}
	}

	//client := fake.NewSimpleClientset()
	client := createClientSet()

	s, _ := NewLease(client, "host-1", "coldstart", sdc_internal.LeaderElectionConf{}, mycallback)

	s.Run()

	<-release
	log.Debugf("Releasing the lease")
	time.Sleep(time.Second)
	s.Release()
}

func TestManyHosts(t *testing.T) {
	t.Skip()
	// Create a cluster with some nodes
	// Each node is represented by different Leases all with the same Lease name
	leaderChan := make(chan *Lease, 1)
	callback := func(leaseLeader *Lease) {
		log.Debugf("And the leader is %s", leaseLeader.id)
		leaderChan <- leaseLeader
	}

	var hosts []*Lease
	clientset := createClientSet()

	// Create the hosts
	for i := 0; i < 10; i++ {
		host, _ := NewLease(clientset, fmt.Sprintf("host-%d", i), "coldstart", sdc_internal.LeaderElectionConf{}, callback)
		hosts = append(hosts, host)
	}

	// Run the leader election on each node
	for _, host := range hosts {
		go host.Run()
		defer host.Release()
	}

	// Store the list of elected node here
	leaderList := make(map[string]bool)

	for i := 0; i < len(hosts); i++ {
		// wait for the current leader
		leader := <-leaderChan
		log.Debugf("Got leader %s", leader.id)
		time.Sleep(time.Second)
		// store the leader
		leaderList[leader.id] = true
		// Release the lock so we can se another host becoming leader
		leader.Release()
	}

	// We expect exactlty 10 leaders
	if len(leaderList) != len(hosts) {
		t.Fail()
	}
}
