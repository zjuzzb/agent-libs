#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <logger.h>
#include "analyzer_utils.h"
#include "draios.pb.h"

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
void export_k8s_object(const uid_set_t& parents,
                       const draiosproto::container_group* src,
                       Protobuf* obj)
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
}

template<>
void export_k8s_object<draiosproto::pod_status_count>(const uid_set_t& parents,
                                                      const draiosproto::container_group* src,
                                                      draiosproto::pod_status_count* obj);

}  // namespace legacy_k8s
