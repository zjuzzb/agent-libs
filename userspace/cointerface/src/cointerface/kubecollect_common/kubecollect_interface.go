package kubecollect_common

import (
	"context"
	"github.com/draios/protorepo/sdc_internal"
	kubeclient "k8s.io/client-go/kubernetes"
	"sync"
)

type KubecollectInterface interface {
	StartInformers(
		ctx context.Context,
		kubeClient kubeclient.Interface,
		wg *sync.WaitGroup,
		fetchDone chan<- struct{},
		opts *sdc_internal.OrchestratorEventsStreamCommand,
		resourceTypes []string,
		queueLength *uint32)
}
