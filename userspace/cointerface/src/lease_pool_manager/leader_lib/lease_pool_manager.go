package leader_lib

import (
	"context"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	kubeclient "k8s.io/client-go/kubernetes"
	"sync"
	"time"
)

type LeasePoolManager struct {
	id            string
	leasePoolName string
	leases        map[string]*Lease
	acquiredLease string
	lockAcquired  chan string
	released      bool
}

type ColdStartManagerInterface interface {
	Init(id string, leaseName string, numLeases uint32, leaderElectionConfig sdc_internal.LeaderElectionConf, p kubeclient.Interface)
	// Blocking wait until a Lease gain the lock
	WaitLock(maxWaitSecs uint32, ctx context.Context) error
	Release()
	GetId() string
	GetHolderIdentities() []string
}

func(cs *LeasePoolManager) GetHolderIdentities() []string {
	var ret []string

	for _, lease := range cs.leases {
		if leader := lease.GetLeader(); leader != "" {
			ret = append(ret, leader)
		}
	}

	return ret
}

func (cs *LeasePoolManager) GetId() string {
	return cs.id
}

func (cs *LeasePoolManager) Init(id string, leasePoolName string, numLeases uint32, leaderElectionConfig sdc_internal.LeaderElectionConf,p kubeclient.Interface) {
	var once sync.Once
	cs.id = id
	cs.leasePoolName = leasePoolName
	log.Debugf("Creating leasePoolManager %s with uuid %s", cs.leasePoolName, cs.id)
	cs.lockAcquired = make(chan string)
	cs.leases = make(map[string]*Lease)
	for i := 0; i < int(numLeases); i++ {
		leaseName := fmt.Sprintf("%s-%d", leasePoolName, i)
		newSerializer, err := NewLease(p, cs.id, leaseName, leaderElectionConfig, func(lease *Lease){
			once.Do(func(){
				cs.lockAcquired <- lease.leaseName
			})
		})

		if err != nil {
			log.Warnf("%s Could not create lease %s: %s", cs.leasePoolName, leaseName, err.Error())
		} else {
			log.Debugf("%s adding Lease %s", cs.leasePoolName, leaseName)
			cs.leases[leaseName] = newSerializer
		}
	}
}

func (cs *LeasePoolManager) WaitLock(maxWaitSecs uint32, parentCtx context.Context) error {
	if len(cs.leases) == 0 {
		return fmt.Errorf("No leases to wait for")
	}
	ctx, _ := context.WithCancel(parentCtx)

	done := make(chan struct{})
	go func() {
		cs.acquiredLease = <-cs.lockAcquired
		log.Debugf("%s Acquired lock on Lease %s", cs.leasePoolName, cs.acquiredLease)
		done <- struct{}{}
	} ()

	giveUp := make(chan struct{})
	if maxWaitSecs != 0 {
		go func() {
			select {
			case <- time.After(time.Duration(maxWaitSecs) * time.Second):
				// time to give up
				giveUp <- struct{}{}
			}
		} ()
	}

	for _, lease := range cs.leases {
		lease.Run()
	}

	select {
	case <-done:
		// Do not run the other Lease. Already acquired one
		// Release leases that could have been acquired
		for key, lease := range cs.leases {
			if key == cs.acquiredLease {
				continue
			} else {
				lease.Release()
			}
		}
	case <-ctx.Done():
		log.Debugf("%s Wait Lock operation cancelled", cs.leasePoolName)
		cs.Release()
		return nil
	case <-giveUp:
		log.Debugf("%s waited %d seconds for acquiring a lock. Giving up.", cs.leasePoolName, maxWaitSecs)
		cs.Release()
		return fmt.Errorf("Time out expired")
	}

	return nil
}

func (cs *LeasePoolManager) Release() {
	if cs.released {
		log.Debugf("lease_pool_manager %s already released", cs.leasePoolName)
	} else {
		log.Debugf("%s Releasing every lease", cs.leasePoolName)
		for _, lease := range cs.leases {
			lease.Release()
		}
		cs.released = true
	}
}
