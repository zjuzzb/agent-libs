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
	struct port_filter_rule {
		explicit port_filter_rule() : m_include(false) { }
		bool m_include;
		bool m_use_set; // Use set instead of range
		// Start and end are inclusive
		uint16_t m_range_start;
		uint16_t m_range_end;
		set<uint16_t> m_port_set;
	};
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
		m_interval(-1),
		m_max_metrics_per_proc(40),
		m_max_tags_per_metric(20)
	{}

	bool match(const sinsp_threadinfo* tinfo, const sinsp_container_info *container, set<uint16_t> &ports) const;

	bool enabled() const {
		return m_enabled;
	}

	// Json::Value to_json() const;

private:
	friend class YAML::convert<prometheus_conf>;

	bool m_enabled;
	bool m_log_errors;
	int m_interval;
	int m_max_metrics_per_proc;
	int m_max_tags_per_metric;
	vector<port_filter_rule> m_port_rules;
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
	explicit prom_process(string name, int pid, int vpid, const set<uint16_t> &ports) :
		m_name(name), m_pid(pid), m_vpid(vpid), m_ports(ports) { }

	Json::Value to_json() const;
private:
	string m_name;	// Just for debugging
	int m_pid;
	int m_vpid;
	set<uint16_t> m_ports;
};

#endif // _WIN32
