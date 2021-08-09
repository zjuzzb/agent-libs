package kubecollect_common

import (
	"context"
	"k8s.io/client-go/tools/cache"
	"sync"

	"github.com/draios/protorepo/sdc_internal"
	kubeclient "k8s.io/client-go/kubernetes"
)

type KubecollectInterface interface {
	StartInformers(
		ctx context.Context,
		kubeClient kubeclient.Interface,
		wg *sync.WaitGroup,
		opts *sdc_internal.OrchestratorEventsStreamCommand,
		resourceTypes []string,
		queueLength *uint32)
	CreateHasSyncedFuncs()[]cache.InformerSynced
}
