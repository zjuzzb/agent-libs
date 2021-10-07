package leader_lib

import (
	"context"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"time"
)

type Lease struct {
	id         string // The group id this lease belongs to
	leaseName  string
	lock       resourcelock.LeaseLock
	ctx        context.Context
	cancel     context.CancelFunc
	config     leaderelection.LeaderElectionConfig
	elector    *leaderelection.LeaderElector
	alreadyRun bool
}

func NewLease(p kubeclient.Interface, id string, leaseName string, leaderElectionConfig sdc_internal.LeaderElectionConf, callback func(*Lease)) (*Lease, error) {
	serializer := &Lease{}
	err := serializer.init(p, id, leaseName, leaderElectionConfig, callback)
	return serializer, err
}

type (
	LeaseManager interface {
		Run()
		Release()
		GetLeader() string
	}
)

func (s *Lease) init(p kubeclient.Interface, id string, leaseName string, leaderElectionConfig sdc_internal.LeaderElectionConf, callback func(theLeader *Lease)) error {
	s.id = id
	s.leaseName = leaseName
	s.lock = resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseName,
			Namespace: leaderElectionConfig.GetNamespace(),
		},
		Client: p.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: s.id,
		},
	}

	s.config = leaderelection.LeaderElectionConfig{
		Lock: &s.lock,

		ReleaseOnCancel: true,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				callback(s)
			},
			OnStoppedLeading: func() {
			},
			OnNewLeader: func(identity string) {
			},
		},
	}

	if leaderElectionConfig.LeaseDuration != nil && *leaderElectionConfig.LeaseDuration > 0 {
		s.config.LeaseDuration = time.Duration(*leaderElectionConfig.LeaseDuration) * time.Second
	}

	if leaderElectionConfig.RenewDeadline != nil && *leaderElectionConfig.RenewDeadline > 0 {
		s.config.RenewDeadline = time.Duration(*leaderElectionConfig.RenewDeadline) * time.Second
	}

	if leaderElectionConfig.RetryPeriod != nil && *leaderElectionConfig.RetryPeriod > 0 {
		s.config.RetryPeriod = time.Duration(*leaderElectionConfig.RetryPeriod) * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	log.Debugf("Creating leaderElector with leaseDuration: %d, renewDeadline: %d, retryPeriod: %d", *leaderElectionConfig.LeaseDuration, *leaderElectionConfig.RenewDeadline, *leaderElectionConfig.RetryPeriod)
	var err error
	s.elector, err = leaderelection.NewLeaderElector(s.config)

	if err != nil {
		log.Warnf("Got error creating leaderElector: %s", err.Error())
		return err
	}

	// Let's do an initial cleanup. Dragent use to kill this process sending SIGKILL which does not give it
	// a chance to gracefully shutdown (eg. Lease.identityHolder == "")
	// Check if this lease has an IdentityHolder equal to leasename and delete it
	// This will speed up the leader acquire process
	lease, err := p.CoordinationV1().Leases(leaderElectionConfig.GetNamespace()).Get(context.TODO(), s.leaseName, metav1.GetOptions{})

	if err == nil && *lease.Spec.HolderIdentity == s.id {
		*lease.Spec.HolderIdentity = ""
		lease, err = p.CoordinationV1().Leases(leaderElectionConfig.GetNamespace()).Update(context.TODO(), lease, metav1.UpdateOptions{})
		if err == nil {
			log.Debugf("cleaned up lease %s", s.leaseName)
		} else {
			log.Debugf("Unable to cleanup lease %s: %s", s.leaseName, err)
		}
	}
	return nil
}

func (s *Lease) Run() {
	if s.alreadyRun {
		log.Debugf("Lease %s has been already run. Skip running again", s.leaseName)
		return
	}

	if s.ctx.Err() == context.Canceled {
		log.Debugf("Lease %s has been already released. Cannot run again", s.leaseName)
		return
	}

	log.Debugf("Running Lease %s:%s", s.leaseName, s.id)
	s.alreadyRun = true
	go s.elector.Run(s.ctx)
}

func (s *Lease) Release() {
	if s.ctx.Err() == context.Canceled {
		return
	}

	log.Debugf("Releasing Lease %s:%s", s.leaseName, s.id)
	s.cancel()
	s.alreadyRun = false

	maxWait := time.NewTimer(time.Second * 30)
	for {
		if s.GetLeader() != s.id {
			log.Debugf("Release %s %s done", s.leaseName, s.id)
			return
		} else {
			log.Debugf("Trying to release leader %s from lease %s", s.id, s.leaseName)
			select {
			case <-maxWait.C:
				log.Debug("Could not release. Timer expired")
				return
			case <-time.After(time.Second * 1):
				//Give another try
			}
		}
	}
}

func (s *Lease) GetLeader() string {
	return s.elector.GetLeader()
}
