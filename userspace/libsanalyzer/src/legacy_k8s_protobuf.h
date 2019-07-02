#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include <logger.h>
#include "draios.pb.h"

namespace legacy_k8s
{
void fill_common(const draiosproto::container_group *congroup, draiosproto::k8s_common *common, const std::string& tag_prefix);
void set_namespace(draiosproto::k8s_common *common, const std::unordered_map<std::string, std::string>& ns_names);

template<class Protobuf>
using setter_t = std::function<void(Protobuf*, double)>;

template<class Protobuf>
class K8sResource {
public:
	static const std::unordered_map<std::string, setter_t<Protobuf>> metrics;
	static const std::string tag_prefix;
};

template<class Protobuf>
void export_k8s_object(const draiosproto::container_group* src, Protobuf* obj)
{
	fill_common(src, obj->mutable_common(), K8sResource<Protobuf>::tag_prefix);

	for(const auto& metric : src->metrics())
	{
		const std::string& name = metric.name();
		double value = metric.value();
		auto setter = K8sResource<Protobuf>::metrics.find(name);
		if(setter != K8sResource<Protobuf>::metrics.end())
		{
			setter->second(obj, value);
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_NOTICE, "Dropping metric %s=%lf from %s",
					name.c_str(), value, obj->common().name().c_str());
		}
	}
}
}
