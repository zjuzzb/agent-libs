package kubecollect_common

import (
	"github.com/gogo/protobuf/proto"
	"k8s.io/api/core/v1"
	"strings"
	draiosproto "protorepo/agent-be/proto"
)

// Unfortunately, kubernetes doesn't exposes networking cidr
// information through a clean API. This logic relies on parsing the
// command arguments of k8s control plane pods (configurable through
// `network_topology.pod_prefix_for_cidr_retrieval' entry), in search of the
// arguments `--cluster-cidr' and `--service-cluster-ip-range'.

// PodPrefixes keeps the pod prefixes name of the pods where we expect
// the network cidr information to be retrieved. In most of the
// kubernetes distributions, we expect it to be on: `kube-apiserver'
// and `kube-controller-manager'.
var PodPrefixes []string

// SetPodPrefixForCidrRetrieval sets the global variable used by
// ParseCidr for cidr retrieval.
func SetPodPrefixForCidrRetrieval(podPrefixes []string) {
	PodPrefixes = podPrefixes
}

// ParseCidr tries to discover cluster and service network cidr
// information from the command of the pod. The Pod prefixes need to
// be previously set using the SetPodPrefixForCidrRetrieval function.
// The function returns the cidrs if any is found.
//
// e.g.
//   inttags:
//     kubernetes.cluster_cidr: 100.1.0.0/24
//     kubernetes.service_cidr: 100.2.0.0/24
func parseCidr(pod *v1.Pod) (map[string]string, bool) {
	cidrs := make(map[string]string)
	has_cidrs := false

	// control plane pods can't live anywhere else
	if pod.GetNamespace() != "kube-system" {
		return nil, false
	}

	for _, prefix := range PodPrefixes {
		if strings.HasPrefix(pod.Name, prefix) {
			for _, c := range pod.Spec.Containers {
				// We use Contains as the container
				// name is generally prefixed by
				// registry information (e.g.
				// `k8s.gcr.io/').
				if strings.Contains(c.Image, prefix) {
					for _, line := range append(c.Command, c.Args...) {
						for _, w := range strings.Fields(line) {
							if strings.HasPrefix(w, "--cluster-cidr") {
								cls := strings.Split(w, "=")
								if cidrs == nil {
									cidrs = make(map[string]string, 1)
								}

								cidrs["kubernetes.cluster_cidr"] = cls[1]
								has_cidrs = true
							} else if strings.HasPrefix(w, "--service-cluster-ip-range") {
								svc := strings.Split(w, "=")
								if cidrs == nil {
									cidrs = make(map[string]string, 1)
								}

								cidrs["kubernetes.service_cidr"] = svc[1]
								has_cidrs = true
							}
						}
					}
				}
			}
		}
	}

	return cidrs, has_cidrs
}

type CoClusterCidr struct {
	Uid string
	Cidrs map[string]string
}

func ClusterCidrEvent(cc CoClusterCidr, eventType draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: newClusterCidrCongroup(cc),
	}
}

func newClusterCidrCongroup(cc CoClusterCidr) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_cluster_cidr"),
			Id:proto.String(cc.Uid),
		},
		InternalTags: cc.Cidrs,
	}
	return ret
}

func SendClusterCidrEvent(pod *v1.Pod, eventType draiosproto.CongroupEventType, c chan <- draiosproto.CongroupUpdateEvent) {
	cidrs, has_cidrs := parseCidr(pod)

	if has_cidrs == false {
		return
	}

	clusterCidr := CoClusterCidr{
		Uid: string(pod.GetUID()),
		Cidrs: cidrs,
	}

	c <- draiosproto.CongroupUpdateEvent {
		Type: eventType.Enum(),
		Object: newClusterCidrCongroup(clusterCidr),
	}
	AddEvent("ClusterCidr", EVENT_ADD)
}
