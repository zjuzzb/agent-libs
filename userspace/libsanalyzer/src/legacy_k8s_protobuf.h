#pragma once

#include "analyzer_utils.h"
#include "draios.pb.h"
#include "type_config.h"

#include <functional>
#include <logger.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

extern type_config<bool> c_k8s_send_all_containers;

namespace legacy_k8s
{

static const uint64_t LOG_INTERVAL_NSEC = 10 * 60 * NSECS_PER_SEC;
using uid_set_t = std::unordered_set<std::pair<std::string, std::string>>;
void fill_common(const uid_set_t& parents,
                 const draiosproto::container_group* congroup,
                 draiosproto::k8s_common* common,
                 const std::string& tag_prefix);
void set_namespace(draiosproto::k8s_common* common,
                   const std::unordered_map<std::string, std::string>& ns_names);

template<class Protobuf>
using setter_t = std::function<void(Protobuf*, double)>;

template<class Protobuf>
class K8sResource
{
public:
	static const std::unordered_map<std::string, setter_t<Protobuf>> metrics;
	static const std::string tag_prefix;
};

template<class Protobuf>
void enrich_k8s_common(const draiosproto::container_group* src, Protobuf* obj)
{
}

template<class Protobuf>
void enrich_k8s_global(const draiosproto::container_group* src, Protobuf* obj)
{
}

template<class Protobuf>
void enrich_k8s_local(const draiosproto::container_group* src, Protobuf* obj)
{
}

template<class Protobuf>
void export_k8s_object(const uid_set_t& parents,
                       const draiosproto::container_group* src,
                       Protobuf* obj,
                       bool is_global_export)
{
	fill_common(parents, src, obj->mutable_common(), K8sResource<Protobuf>::tag_prefix);

	static std::unordered_map<std::string, ratelimit> dropped_metrics;

	for (const auto& metric : src->metrics())
	{
		const std::string& name = metric.name();
		double value = metric.value();
		auto setter = K8sResource<Protobuf>::metrics.find(name);
		if (setter != K8sResource<Protobuf>::metrics.end())
		{
			setter->second(obj, value);
		}
		else
		{
			auto it = dropped_metrics.find(name);
			if (it == dropped_metrics.end())
			{
				dropped_metrics[name] = ratelimit(1, LOG_INTERVAL_NSEC);
			}
			dropped_metrics[name].run([&] {
				g_logger.format(sinsp_logger::SEV_NOTICE,
				                "Dropping metric %s=%lf from %s",
				                name.c_str(),
				                value,
				                obj->common().name().c_str());
			});
		}
	}
	
	enrich_k8s_common(src, obj);
	
	if (is_global_export)
	{
		enrich_k8s_global(src, obj);
	}
	else
	{
		enrich_k8s_local(src, obj);
	}
}

template<>
void export_k8s_object<draiosproto::pod_status_count>(const uid_set_t& parents,
                                                      const draiosproto::container_group* src,
                                                      draiosproto::pod_status_count* obj,
                                                      bool is_global_export);

template<>
void enrich_k8s_common<draiosproto::k8s_pod>(const draiosproto::container_group* src,
                                             draiosproto::k8s_pod* obj);

template<>
void enrich_k8s_global<draiosproto::k8s_pod>(const draiosproto::container_group* src,
                                             draiosproto::k8s_pod* obj);

template<>
void enrich_k8s_local<draiosproto::k8s_pod>(const draiosproto::container_group* src,
                                             draiosproto::k8s_pod* obj);

template<>
void enrich_k8s_common<draiosproto::k8s_persistentvolumeclaim>(
    const draiosproto::container_group* src,
    draiosproto::k8s_persistentvolumeclaim* obj);

template<>
void enrich_k8s_common<draiosproto::k8s_persistentvolume>(const draiosproto::container_group* src,
                                                          draiosproto::k8s_persistentvolume* obj);

template<>
void enrich_k8s_common<draiosproto::k8s_storage_class>(const draiosproto::container_group* src,
							  draiosproto::k8s_storage_class * obj);

}  // namespace legacy_k8s
