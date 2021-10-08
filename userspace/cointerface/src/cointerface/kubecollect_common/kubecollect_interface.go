package kubecollect_common

import (
	"context"
	"sync"

	"github.com/draios/protorepo/sdc_internal"
	kubeclient "k8s.io/client-go/kubernetes"
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
