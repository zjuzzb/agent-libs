#include "common_logger.h"
#include "draios.pb.h"
#include "legacy_k8s_protobuf.h"
#include "infrastructure_state.h"

#include <unordered_map>

using namespace draiosproto;
using namespace std;

namespace
{
COMMON_LOGGER();
}

namespace legacy_k8s
{
void fill_common(const uid_set_t& parents,
                 const container_group* congroup,
                 k8s_common* common,
                 const string& tag_prefix)
{
	const string& kind = congroup->uid().kind();
	const string& id = congroup->uid().id();

	common->set_uid(id);
	if (!tag_prefix.empty())
	{
		const string label_prefix = tag_prefix + "label.";
		const string name_tag = tag_prefix + "name";

		for (const auto& tag : congroup->tags())
		{
			const auto& tag_name = tag.first;
			const auto& tag_value = tag.second;

			if (tag_name == name_tag)
			{
				common->set_name(tag_value);
			}
			else if (tag_name.rfind(label_prefix, 0) == 0)
			{
				const string label(tag_name, label_prefix.size());
				auto pair = common->add_labels();
				pair->set_key(label);
				pair->set_value(tag_value);
			}
			else
			{
				static std::unordered_map<std::string, ratelimit> ignored_tags;
				auto it = ignored_tags.find(tag_name);
				if(it == ignored_tags.end())
				{
					ignored_tags[tag_name] = ratelimit(1, LOG_INTERVAL_NSEC);
				}
				ignored_tags[tag_name].run([&]
							   {
								   LOG_NOTICE("ignoring tag <%s> = <%s> for %s %s",
									      tag_name.c_str(),
									      tag_value.c_str(),
									      kind.c_str(),
									      id.c_str());
							   });
			}
		}
	}

	if (kind == "k8s_namespace")
	{
		common->set_namespace_(common->name());
	}

	for (const auto& parent : parents)
	{
		if (parent.first == "k8s_namespace")
		{
			common->set_namespace_(parent.second);
		}
		else
		{
			auto pair = common->add_parents();
			pair->set_key(parent.first);
			pair->set_value(parent.second);
		}
	}
}

void set_namespace(draiosproto::k8s_common* common,
                   const std::unordered_map<std::string, std::string>& ns_names)
{
	const auto& ns_name = ns_names.find(common->namespace_());
	if (ns_name != ns_names.end())
	{
		common->set_namespace_(ns_name->second);
	}
}

#define SETTER(cls, method) [](cls* pb, double value) -> void { pb->method(value); }
#define IGNORE(cls) [](cls* pb, double value) -> void {}

template<>
const string K8sResource<k8s_persistentvolume>::tag_prefix = "kubernetes.persistentvolume.";
template<>
const unordered_map<string, setter_t<k8s_persistentvolume>>
    K8sResource<k8s_persistentvolume>::metrics({
        {"kubernetes.persistentvolume.storage", SETTER(k8s_persistentvolume, set_storage)},
        {"kubernetes.persistentvolume.count", IGNORE(k8s_persistentvolume)},
    });

template<>
const string K8sResource<k8s_persistentvolumeclaim>::tag_prefix =
    "kubernetes.persistentvolumeclaim.";
template<>
const unordered_map<string, setter_t<k8s_persistentvolumeclaim>>
    K8sResource<k8s_persistentvolumeclaim>::metrics(
        {{"kubernetes.persistentvolumeclaim.storage",
          SETTER(k8s_persistentvolumeclaim, set_storage)},
         {"kubernetes.persistentvolumeclaim.requests.storage",
          SETTER(k8s_persistentvolumeclaim, set_requests_storage)}});

template<>
const string K8sResource<k8s_statefulset>::tag_prefix = "kubernetes.statefulset.";
template<>
const unordered_map<string, setter_t<k8s_statefulset>> K8sResource<k8s_statefulset>::metrics({
    {"kubernetes.statefulset.replicas", SETTER(k8s_statefulset, set_replicas)},
    {"kubernetes.statefulset.status.replicas", SETTER(k8s_statefulset, set_status_replicas)},
    {"kubernetes.statefulset.status.replicas.current",
     SETTER(k8s_statefulset, set_status_replicas_current)},
    {"kubernetes.statefulset.status.replicas.ready",
     SETTER(k8s_statefulset, set_status_replicas_ready)},
    {"kubernetes.statefulset.status.replicas.updated",
     SETTER(k8s_statefulset, set_status_replicas_updated)},
});

template<>
const string K8sResource<k8s_replication_controller>::tag_prefix =
    "kubernetes.replicationController.";
template<>
const unordered_map<string, setter_t<k8s_replication_controller>>
    K8sResource<k8s_replication_controller>::metrics({
        {"kubernetes.replicationController.spec.replicas",
         SETTER(k8s_replication_controller, set_replicas_desired)},
        {"kubernetes.replicationController.status.replicas",
         SETTER(k8s_replication_controller, set_replicas_running)},
        {"kubernetes.replicationController.status.availableReplicas",
         SETTER(k8s_replication_controller, set_replicas_available)},
        {"kubernetes.replicationController.status.fullyLabeledReplicas",
         SETTER(k8s_replication_controller, set_replicas_fully_labeled)},
        {"kubernetes.replicationController.status.readyReplicas",
         SETTER(k8s_replication_controller, set_replicas_ready)},
    });

template<>
const string K8sResource<k8s_hpa>::tag_prefix = "kubernetes.hpa.";
template<>
const unordered_map<string, setter_t<k8s_hpa>> K8sResource<k8s_hpa>::metrics({
    {"kubernetes.hpa.replicas.min", SETTER(k8s_hpa, set_replicas_min)},
    {"kubernetes.hpa.replicas.max", SETTER(k8s_hpa, set_replicas_max)},
    {"kubernetes.hpa.replicas.current", SETTER(k8s_hpa, set_replicas_current)},
    {"kubernetes.hpa.replicas.desired", SETTER(k8s_hpa, set_replicas_desired)},
});

template<>
const string K8sResource<k8s_deployment>::tag_prefix = "kubernetes.deployment.";
template<>
const unordered_map<string, setter_t<k8s_deployment>> K8sResource<k8s_deployment>::metrics({
    {"kubernetes.deployment.spec.replicas", SETTER(k8s_deployment, set_replicas_desired)},
    {"kubernetes.deployment.status.replicas", SETTER(k8s_deployment, set_replicas_running)},
    {"kubernetes.deployment.status.availableReplicas",
     SETTER(k8s_deployment, set_replicas_available)},
    {"kubernetes.deployment.status.unavailableReplicas",
     SETTER(k8s_deployment, set_replicas_unavailable)},
    {"kubernetes.deployment.status.updatedReplicas", SETTER(k8s_deployment, set_replicas_updated)},
    {"kubernetes.deployment.spec.paused", SETTER(k8s_deployment, set_replicas_paused)},  // ???
});

template<>
const string K8sResource<k8s_daemonset>::tag_prefix = "kubernetes.daemonSet.";
template<>
const unordered_map<string, setter_t<k8s_daemonset>> K8sResource<k8s_daemonset>::metrics({
    {"kubernetes.daemonSet.status.currentNumberScheduled",
     SETTER(k8s_daemonset, set_current_scheduled)},
    {"kubernetes.daemonSet.status.desiredNumberScheduled",
     SETTER(k8s_daemonset, set_desired_scheduled)},
    {"kubernetes.daemonSet.status.numberMisscheduled",
     SETTER(k8s_daemonset, set_pods_misscheduled)},
    {"kubernetes.daemonSet.status.numberReady", SETTER(k8s_daemonset, set_pods_ready)},
});

template<>
const string K8sResource<k8s_job>::tag_prefix = "kubernetes.job.";
template<>
const unordered_map<string, setter_t<k8s_job>> K8sResource<k8s_job>::metrics({
    {"kubernetes.job.spec.parallelism", SETTER(k8s_job, set_parallelism)},
    {"kubernetes.job.spec.completions", SETTER(k8s_job, set_completions)},
    {"kubernetes.job.status.active", SETTER(k8s_job, set_status_active)},
    {"kubernetes.job.status.succeeded", SETTER(k8s_job, set_num_succeeded)},
    {"kubernetes.job.status.failed", SETTER(k8s_job, set_num_failed)},
});

template<>
const string K8sResource<k8s_node>::tag_prefix = "kubernetes.node.";
template<>
const unordered_map<string, setter_t<k8s_node>> K8sResource<k8s_node>::metrics({
    {"kubernetes.node.status.capacity.cpuCores", SETTER(k8s_node, set_capacity_cpu_cores)},
    {"kubernetes.node.status.capacity.memoryBytes", SETTER(k8s_node, set_capacity_mem_bytes)},
    {"kubernetes.node.status.capacity.pods", SETTER(k8s_node, set_capacity_pods)},

    {"kubernetes.node.status.allocatable.cpuCores", SETTER(k8s_node, set_allocatable_cpu_cores)},
    {"kubernetes.node.status.allocatable.memoryBytes", SETTER(k8s_node, set_allocatable_mem_bytes)},
    {"kubernetes.node.status.allocatable.pods", SETTER(k8s_node, set_allocatable_pods)},

    {"kubernetes.node.spec.unschedulable", SETTER(k8s_node, set_unschedulable)},

    {"kubernetes.node.status.ready", SETTER(k8s_node, set_ready)},
    {"kubernetes.node.status.outOfDisk", SETTER(k8s_node, set_out_of_disk)},
    {"kubernetes.node.status.memoryPressure", SETTER(k8s_node, set_mem_pressure)},
    {"kubernetes.node.status.diskPressure", SETTER(k8s_node, set_disk_pressure)},
    {"kubernetes.node.status.networkUnavailable", SETTER(k8s_node, set_net_unavailable)},
});

template<>
const string K8sResource<k8s_pod>::tag_prefix = "kubernetes.pod.";
template<>
const unordered_map<string, setter_t<k8s_pod>> K8sResource<k8s_pod>::metrics({
    {"kubernetes.pod.status.ready", SETTER(k8s_pod, set_status_ready)},

    {"kubernetes.pod.resourceRequests.cpuCores", SETTER(k8s_pod, set_requests_cpu_cores)},
    {"kubernetes.pod.resourceLimits.cpuCores", SETTER(k8s_pod, set_limits_cpu_cores)},
    {"kubernetes.pod.resourceRequests.memoryBytes", SETTER(k8s_pod, set_requests_mem_bytes)},
    {"kubernetes.pod.resourceLimits.memoryBytes", SETTER(k8s_pod, set_limits_mem_bytes)},

    {"kubernetes.pod.container.status.restarts", SETTER(k8s_pod, set_restart_count)},
    {"kubernetes.pod.container.status.restart_rate", SETTER(k8s_pod, set_restart_rate)},
    {"kubernetes.pod.container.status.waiting", SETTER(k8s_pod, set_containers_waiting)},
});

// yes, the capitalization is inconsistent
template<>
const string K8sResource<k8s_replica_set>::tag_prefix = "kubernetes.replicaSet.";
template<>
const unordered_map<string, setter_t<k8s_replica_set>> K8sResource<k8s_replica_set>::metrics({
    {"kubernetes.replicaset.spec.replicas", SETTER(k8s_replica_set, set_replicas_desired)},
    {"kubernetes.replicaset.status.replicas", SETTER(k8s_replica_set, set_replicas_running)},
    {"kubernetes.replicaset.status.fullyLabeledReplicas",
     SETTER(k8s_replica_set, set_replicas_fully_labeled)},
    {"kubernetes.replicaset.status.readyReplicas", SETTER(k8s_replica_set, set_replicas_ready)},
});

template<>
const string K8sResource<k8s_resourcequota>::tag_prefix = "kubernetes.resourcequota.";
template<>
const unordered_map<string, setter_t<k8s_resourcequota>> K8sResource<k8s_resourcequota>::metrics({
    // compute
    {"kubernetes.resourcequota.limits.cpu.hard",
     [](k8s_resourcequota* pb, double value) -> void {
	     pb->set_limits_cpu_hard(value);
	     pb->set_double_limits_cpu_hard(value);
     }},
    {"kubernetes.resourcequota.requests.cpu.hard",
     [](k8s_resourcequota* pb, double value) -> void {
	     pb->set_requests_cpu_hard(value);
	     pb->set_double_request_cpu_hard(value);
     }},
    {"kubernetes.resourcequota.cpu.hard",
     [](k8s_resourcequota* pb, double value) -> void {
	     pb->set_requests_cpu_hard(value);
	     pb->set_double_request_cpu_hard(value);
     }},
    {"kubernetes.resourcequota.limits.cpu.used",
     [](k8s_resourcequota* pb, double value) -> void {
	     pb->set_limits_cpu_used(value);
	     pb->set_double_limits_cpu_used(value);
     }},
    {"kubernetes.resourcequota.requests.cpu.used",
     [](k8s_resourcequota* pb, double value) -> void {
	     pb->set_requests_cpu_used(value);
	     pb->set_double_request_cpu_used(value);
     }},
    {"kubernetes.resourcequota.cpu.used",
     [](k8s_resourcequota* pb, double value) -> void {
	     pb->set_requests_cpu_used(value);
	     pb->set_double_request_cpu_used(value);
     }},

    {"kubernetes.resourcequota.limits.memory.hard",
     SETTER(k8s_resourcequota, set_limits_memory_hard)},
    {"kubernetes.resourcequota.requests.memory.hard",
     SETTER(k8s_resourcequota, set_requests_memory_hard)},
    {"kubernetes.resourcequota.memory.hard",
     SETTER(k8s_resourcequota, set_requests_memory_hard)},
    {"kubernetes.resourcequota.limits.memory.used",
     SETTER(k8s_resourcequota, set_limits_memory_used)},
    {"kubernetes.resourcequota.requests.memory.used",
     SETTER(k8s_resourcequota, set_requests_memory_used)},
    {"kubernetes.resourcequota.memory.used",
     SETTER(k8s_resourcequota, set_requests_memory_used)},

    // storage
    {"kubernetes.resourcequota.requests.storage.hard",
     SETTER(k8s_resourcequota, set_requests_storage_hard)},
    {"kubernetes.resourcequota.storage.hard",
     SETTER(k8s_resourcequota, set_requests_storage_hard)},
    {"kubernetes.resourcequota.requests.storage.used",
     SETTER(k8s_resourcequota, set_requests_storage_used)},
    {"kubernetes.resourcequota.storage.used",
     SETTER(k8s_resourcequota, set_requests_storage_used)},

    // count
    {"kubernetes.resourcequota.configmaps.hard", SETTER(k8s_resourcequota, set_configmaps_hard)},
    {"kubernetes.resourcequota.persistentvolumeclaims.hard",
     SETTER(k8s_resourcequota, set_persistentvolumeclaims_hard)},
    {"kubernetes.resourcequota.pods.hard", SETTER(k8s_resourcequota, set_pods_hard)},
    {"kubernetes.resourcequota.replicationcontrollers.hard",
     SETTER(k8s_resourcequota, set_replicationcontrollers_hard)},
    {"kubernetes.resourcequota.resourcequotas.hard",
     SETTER(k8s_resourcequota, set_resourcequotas_hard)},
    {"kubernetes.resourcequota.services.hard", SETTER(k8s_resourcequota, set_services_hard)},
    {"kubernetes.resourcequota.services.loadbalancers.hard",
     SETTER(k8s_resourcequota, set_services_loadbalancers_hard)},
    {"kubernetes.resourcequota.services.nodeports.hard",
     SETTER(k8s_resourcequota, set_services_nodeports_hard)},
    {"kubernetes.resourcequota.secrets.hard", SETTER(k8s_resourcequota, set_secrets_hard)},

    {"kubernetes.resourcequota.configmaps.used", SETTER(k8s_resourcequota, set_configmaps_used)},
    {"kubernetes.resourcequota.persistentvolumeclaims.used",
     SETTER(k8s_resourcequota, set_persistentvolumeclaims_used)},
    {"kubernetes.resourcequota.pods.used", SETTER(k8s_resourcequota, set_pods_used)},
    {"kubernetes.resourcequota.replicationcontrollers.used",
     SETTER(k8s_resourcequota, set_replicationcontrollers_used)},
    {"kubernetes.resourcequota.resourcequotas.used",
     SETTER(k8s_resourcequota, set_resourcequotas_used)},
    {"kubernetes.resourcequota.services.used", SETTER(k8s_resourcequota, set_services_used)},
    {"kubernetes.resourcequota.services.loadbalancers.used",
     SETTER(k8s_resourcequota, set_services_loadbalancers_used)},
    {"kubernetes.resourcequota.services.nodeports.used",
     SETTER(k8s_resourcequota, set_services_nodeports_used)},
    {"kubernetes.resourcequota.secrets.used", SETTER(k8s_resourcequota, set_secrets_used)},
});

template<>
void export_k8s_object<draiosproto::pod_status_count>(const uid_set_t& parents,
                                                      const draiosproto::container_group* src,
                                                      draiosproto::pod_status_count* obj)
{
	for (const auto& tag : src->tags())
	{
		if (tag.first == "kubernetes.podstatuscounter.label.status")
		{
			obj->set_status(tag.second);
			break;
		}
	}

	for (const auto& metric : src->metrics())
	{
		if (metric.name() == "kubernetes.podstatuscounter.count")
		{
			obj->set_count(metric.value());
			break;
		}
	}
}

template<>
void enrich_k8s_object<draiosproto::k8s_pod>(const draiosproto::container_group* src,
                                             draiosproto::k8s_pod* obj)
{
	for (const auto& metric : src->metrics())
	{
		draiosproto::k8s_container_status_details* container = nullptr;
		if (metric.name() == infrastructure_state::CONTAINER_WAITING_METRIC_NAME)
		{
			container = obj->mutable_pod_status()->mutable_containers()->Add();
			container->set_status("waiting");
		}
		else if (metric.name() == infrastructure_state::CONTAINER_TERMINATED_METRIC_NAME)
		{
			container = obj->mutable_pod_status()->mutable_containers()->Add();
			container->set_status("terminated");
		}

		if (container != nullptr)
		{
			for (const auto& tag : metric.tags())
			{
				if (tag.key() == infrastructure_state::CONTAINER_ID_TAG)
				{
					container->set_id(tag.value());
				}
				else if (tag.key() == infrastructure_state::CONTAINER_STATUS_REASON_TAG)
				{
					container->set_status_reason(tag.value());
				}
			}
		}
	}
}
}  // namespace legacy_k8s
