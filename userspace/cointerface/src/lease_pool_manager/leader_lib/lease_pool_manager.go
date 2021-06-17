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

func(lpm *LeasePoolManager) GetHolderIdentities() []string {
	var ret []string

	for _, lease := range lpm.leases {
		if leader := lease.GetLeader(); leader != "" {
			ret = append(ret, leader)
		}
	}

	return ret
}

func (lpm *LeasePoolManager) GetId() string {
	return lpm.id
}

func (lpm *LeasePoolManager) haveLeasePermission(p kubeclient.Interface, leaderElectionConfig *sdc_internal.LeaderElectionConf) error {
	_, err := p.CoordinationV1().Leases(leaderElectionConfig.GetNamespace()).List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		log.Errorf("Cannot access leases objects: %s", err.Error())
	}

	return err
}

func (lpm *LeasePoolManager) Init(id string, leasePoolName string, numLeases uint32, leaderElectionConfig sdc_internal.LeaderElectionConf,p kubeclient.Interface) {
	err := lpm.haveLeasePermission(p, &leaderElectionConfig)

	if err != nil {
		log.Errorf("Unable to Init leasePoolManager")
		return
	}

	// Get the namespace where creating leader election leases
	lpm.setLeaseNamespace(&leaderElectionConfig, nil)

	var once sync.Once
	lpm.id = id
	lpm.leasePoolName = leasePoolName
	log.Debugf("Creating leasePoolManager %s with uuid %s", lpm.leasePoolName, lpm.id)
	lpm.lockAcquired = make(chan string)
	lpm.leases = make(map[string]*Lease)
	for i := 0; i < int(numLeases); i++ {
		leaseName := fmt.Sprintf("%s-%d", leasePoolName, i)
		newSerializer, err := NewLease(p, lpm.id, leaseName, leaderElectionConfig, func(lease *Lease){
			once.Do(func(){
				lpm.lockAcquired <- lease.leaseName
			})
		})

		if err != nil {
			log.Warnf("%s Could not create lease %s: %s", lpm.leasePoolName, leaseName, err.Error())
		} else {
			log.Debugf("%s adding Lease %s", lpm.leasePoolName, leaseName)
			lpm.leases[leaseName] = newSerializer
		}
	}
}

func (lpm *LeasePoolManager) WaitLock(maxWaitSecs uint32, parentCtx context.Context) error {
	if len(lpm.leases) == 0 {
		return fmt.Errorf("No leases to wait for")
	}
	ctx, _ := context.WithCancel(parentCtx)

	done := make(chan struct{})
	go func() {
		lpm.acquiredLease = <-lpm.lockAcquired
		log.Debugf("%s Acquired lock on Lease %s", lpm.leasePoolName, lpm.acquiredLease)
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

	for _, lease := range lpm.leases {
		lease.Run()
	}

	select {
	case <-done:
		// Do not run the other Lease. Already acquired one
		// Release leases that could have been acquired
		for key, lease := range lpm.leases {
			if key == lpm.acquiredLease {
				continue
			} else {
				lease.Release()
			}
		}
	case <-ctx.Done():
		log.Debugf("%s Wait Lock operation cancelled", lpm.leasePoolName)
		lpm.Release()
		return nil
	case <-giveUp:
		log.Debugf("%s waited %d seconds for acquiring a lock. Giving up.", lpm.leasePoolName, maxWaitSecs)
		lpm.Release()
		return fmt.Errorf("Time out expired")
	}

	return nil
}

func (lpm *LeasePoolManager) Release() {
	if lpm.released {
		log.Debugf("lease_pool_manager %s already released", lpm.leasePoolName)
	} else {
		log.Debugf("%s Releasing every lease", lpm.leasePoolName)
		for _, lease := range lpm.leases {
			lease.Release()
		}
		lpm.released = true
	}
}
