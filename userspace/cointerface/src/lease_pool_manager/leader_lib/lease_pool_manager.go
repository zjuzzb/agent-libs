package leader_lib

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	authorizationv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

const PODINFO_DIR = "/etc/podinfo"
const NAMESPACE_FILE = "namespace"
const DEFAULT_LEASE_NAMESPACE = "sysdig-agent"

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

func (lpm *LeasePoolManager) GetHolderIdentities() []string {
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

func (lpm *LeasePoolManager) haveLeasePermission(authClient authorizationv1client.AuthorizationV1Interface, verb string, leaderElectionConfig *sdc_internal.LeaderElectionConf) error {
	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: *leaderElectionConfig.Namespace,
				Verb:      verb,
				Group:     "coordination.k8s.io",
				Resource:  "leases",
			},
		},
	}

	response, err := authClient.SelfSubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		log.Errorf("Cannot check authorization: %s", err.Error())
		return err
	}

	if !response.Status.Allowed {
		log.Warnf("Cannot %s leases: %s, %s", verb, response.Status.Reason, response.Status.EvaluationError)

		return errors.New("cannot access leases")
	}

	return nil
}

func (lpm *LeasePoolManager) haveLeasePermissions(client kubeclient.Interface, leaderElectionConfig *sdc_internal.LeaderElectionConf) error {
	verbs := []string{"get", "list", "create", "update", "watch"}

	authClient := client.AuthorizationV1()

	for _, verb := range verbs {
		err := lpm.haveLeasePermission(authClient, verb, leaderElectionConfig)
		if err != nil {
			return err
		}
	}

	return nil
}

func (lpm *LeasePoolManager) supportLeaseResource(client kubeclient.Interface) error {
	resourceList, err := client.Discovery().ServerResourcesForGroupVersion("coordination.k8s.io/v1")
	if err != nil {
		return err
	}

	for _, resource := range resourceList.APIResources {
		if resource.Name == "leases" {
			return nil
		}
	}

	return errors.New("cluster doesn't support leases")
}

// This function choose and set in leaderElectionConf, the namespace where leases objects are going to be created
// If the customer set k8s_coldstart.namespace config paramenter, that value will be used. Otherwise,
// we try to grab the namespace from /etc/podinfo/namespace. This requires the daemonset to use the downwardAPI.
// Eventually we fallback to sysdig-agent
func (lpm LeasePoolManager) setLeaseNamespace(leaderElectionConf *sdc_internal.LeaderElectionConf, nsPath *string) {
	if *leaderElectionConf.Namespace != "" {
		return
	}

	var _nsPath string
	if nsPath != nil {
		_nsPath = *nsPath
	} else {
		_nsPath = fmt.Sprintf("%s/%s", PODINFO_DIR, NAMESPACE_FILE)
	}

	// Try to grab the namespace leveraging downwardAPI
	ret, err := ioutil.ReadFile(_nsPath)

	if err != nil {
		log.Warnf("unable to get my pod namespace: %s. Try using k8s_coldstart.namespace configuration parameter", err.Error())
		*leaderElectionConf.Namespace = DEFAULT_LEASE_NAMESPACE
	} else {
		*leaderElectionConf.Namespace = string(ret)
	}
}

func (lpm *LeasePoolManager) Init(id string, leasePoolName string, numLeases uint32, leaderElectionConfig sdc_internal.LeaderElectionConf, p kubeclient.Interface) {
	// Get the namespace where creating leader election leases
	lpm.setLeaseNamespace(&leaderElectionConfig, nil)

	if err := lpm.supportLeaseResource(p); err != nil {
		log.Warnf("Unable to Init leasePoolManager as cluster doesn't support leases: %v", err)
		return
	}

	if err := lpm.haveLeasePermissions(p, &leaderElectionConfig); err != nil {
		log.Warn("Unable to Init leasePoolManager as agent doesn't have lease permissions")
		return
	}

	var once sync.Once
	lpm.id = id
	lpm.leasePoolName = leasePoolName
	log.Debugf("Creating leasePoolManager %s with uuid %s", lpm.leasePoolName, lpm.id)
	lpm.lockAcquired = make(chan string)
	lpm.leases = make(map[string]*Lease)
	for i := 0; i < int(numLeases); i++ {
		leaseName := fmt.Sprintf("%s-%d", leasePoolName, i)
		newSerializer, err := NewLease(p, lpm.id, leaseName, leaderElectionConfig, func(lease *Lease) {
			once.Do(func() {
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
	}()

	giveUp := make(chan struct{})
	if maxWaitSecs != 0 {
		go func() {
			select {
			case <-time.After(time.Duration(maxWaitSecs) * time.Second):
				// time to give up
				giveUp <- struct{}{}
			}
		}()
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
