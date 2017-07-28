#pragma once
#ifndef _WIN32

#include <string>
#include <map>
#include <vector>

#include "third-party/jsoncpp/json/json.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include "draios.pb.h"
// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop


Json::Value yaml_to_json(const YAML::Node& node);
class sinsp_container_info;

class prometheus_conf
{
public:
	struct filter_condition {
		enum param_type {
			string,
			port,
			container_image,
			container_name,
			container_label,
			process_name,
			process_cmdline,
		};
		static param_type param2type(std::string);
		
		param_type m_param_type;
		std::string m_param;
		std::string m_pattern;
	};
	struct filter_rule {
		explicit filter_rule() : m_include(false) { }

		bool m_include;
		vector<filter_condition> m_cond;
	};

	explicit prometheus_conf():
		m_enabled(false),
		m_log_errors(true),
		m_interval(-1)
	{}

	bool match(sinsp_threadinfo* tinfo, sinsp_container_info *container) const;

	bool enabled() const {
		return m_enabled;
	}

	// Json::Value to_json() const;

private:
	friend class YAML::convert<prometheus_conf>;

	bool m_enabled;
	bool m_log_errors;
	int m_interval;
	vector<filter_rule> m_rules;
};

namespace YAML {
	template<>
	struct convert<prometheus_conf> {
		static Node encode(const prometheus_conf& rhs);

		static bool decode(const Node& node, prometheus_conf& rhs);
	};
}

class prom_process
{
public:
	explicit prom_process(sinsp_threadinfo *tinfo);

	Json::Value to_json() const;
private:
	int m_pid;
	int m_vpid;
	set<uint16_t> m_ports;
};

#endif // _WIN32
