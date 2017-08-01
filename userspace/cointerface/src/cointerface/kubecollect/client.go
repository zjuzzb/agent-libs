package kubecollect

import (
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/rest"
	"draiosproto"
	"github.com/gogo/protobuf/proto"
)

var CompatibilityMap map[string]bool

func CreateKubeClient(apiserver string) (kubeClient kubeclient.Interface, err error) {
	baseConfig := clientcmdapi.NewConfig()
	configOverrides := &clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: apiserver}}
	kubeConfig := clientcmd.NewDefaultClientConfig(*baseConfig, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Infof("HelloPods error: can't create config")
		return nil, err
	}

	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Infof("HelloPods error: NewForConfig fails")
		return nil, err
	}

	return kubeClient, nil
}

func CreateInClusterKubeClient() (kubeClient kubeclient.Interface, err error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("Cannot create InCluster config: ", err)
		return nil, err
	}
	// creates the clientset
	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Errorf("Cannot create client using cluster config", err)
		return nil, err
	}
	return
}

func AppendMetricInt32(metrics *[]*draiosproto.AppMetric, name string, val int32) {
	log.Errorf("Adding metric with val: %v", val)
	*metrics = append(*metrics, &draiosproto.AppMetric{
		Name:proto.String(name),
		Type:draiosproto.AppMetricType_APP_METRIC_TYPE_GAUGE.Enum(),
		Value:proto.Float64(float64(val)),
	})
}

func AppendMetricPtrInt32(metrics *[]*draiosproto.AppMetric, name string, val *int32) {
	v := int32(0)
	if val != nil {
		v = *val
	}
	AppendMetricInt32(metrics, name, v)
}
