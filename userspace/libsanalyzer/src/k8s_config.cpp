#include "k8s_config.h"

namespace {
inline bool k8s_export_format_from_string(const std::string& str, k8s_export_format& value)
{
	bool parse_successful = true;
	std::string lower_str = str;

	std::transform(lower_str.begin(),
		       lower_str.end(),
		       lower_str.begin(),
		       [](char c) { return std::tolower(c); });

	if(lower_str == "dedicated")
	{
		value = k8s_export_format::DEDICATED;
	}
	else if(lower_str == "generic")
	{
		value = k8s_export_format::GENERIC;
	}
	else
	{
		parse_successful = false;
	}

	return parse_successful;
}
}

template<>
inline bool configuration_unit::get_value<k8s_export_format>(const std::string& str, k8s_export_format& value)
{
	return k8s_export_format_from_string(str, value);
}

template<>
std::string configuration_unit::get_value_string<k8s_export_format>(const k8s_export_format& fmt)
{
	switch(fmt)
	{
	case k8s_export_format::DEDICATED: return "dedicated";
	case k8s_export_format::GENERIC: return "generic";
	default: return "(invalid)";
	}
}

namespace YAML {

template<>
struct convert<k8s_export_format>{
	static bool decode(const Node &node, k8s_export_format &rhs)
	{
		if(!node.IsScalar())
			return false;

		auto node_as_string = node.as<std::string>();
		return k8s_export_format_from_string(node_as_string, rhs);
	}
};

}
type_config<k8s_export_format> c_new_k8s_global_export_format(
	k8s_export_format::GENERIC,
	"Format of k8s global orchestrator state",
	"k8s_export_format", "global");

type_config<k8s_export_format> c_new_k8s_local_export_format(
	k8s_export_format::GENERIC,
	"Format of k8s local orchestrator state",
	"k8s_export_format", "local");

