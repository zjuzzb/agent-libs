package leader_lib

import (
	"context"
	"fmt"
	log "github.com/cihub/seelog"
	"sync"
	"testing"
	"time"
)

func TestHugeCluster(t *testing.T) {

	hostNum:= 10
	leaseNum:= 4
	// This test requires Kubernetes. Skipping
	// t.Skip()
	// Let simulate some nodes. We want to do "N" (leaseNum) coldstarts at the same time
	client := createClientSet()
	var wg sync.WaitGroup

	hostSimulator := func(i int) {
		defer wg.Done()
		coldstartManager := LeasePoolManager{}
		coldstartManager.Init(fmt.Sprintf("host-%d", i), "coldstart", uint32(leaseNum), client)
		log.Debugf("Host %s starts waiting for the lock at %d", coldstartManager.GetId(), time.Now().Unix())
		coldstartManager.WaitLock(0, context.TODO())
		log.Debugf("Host %s starts the coldstart at %d", coldstartManager.GetId(), time.Now().Unix())
		// Keep the lock for same time
		time.Sleep(time.Second * 60)
		coldstartManager.Release()
		log.Debugf("Host %s ends the coldstart at %d", coldstartManager.GetId(), time.Now().Unix())
	}

	start := time.Now().Unix()

	for i := 0; i< hostNum; i++ {
		wg.Add(1)
		go hostSimulator(i)
	}

	wg.Wait()

	end := time.Now().Unix()

	log.Debugf("Coldstarts completed in %d secs", end - start)
}
