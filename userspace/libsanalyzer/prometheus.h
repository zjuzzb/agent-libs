#pragma once
#ifndef _WIN32

#include <string>
#include <map>
#include <vector>
#include <algorithm>

#include "third-party/jsoncpp/json/json.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include "draios.pb.h"
#include "analyzer_settings.h"
// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop


Json::Value yaml_to_json(const YAML::Node& node);
class sinsp_container_info;
class yaml_configuration;
class infrastructure_state;

class prometheus_conf
{
public:
	struct port_filter_rule {
		explicit port_filter_rule() : m_include(false), m_use_set(false),
			m_range_start(0), m_range_end(0) { }
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
			app_check_match,
			k8s_annotation
		};
		static param_type param2type(std::string);
		
		param_type m_param_type;
		std::string m_param;
		std::string m_pattern;
		// Using port_filter_rules to implement port matching conditions
		// so we don't have to parse the pattern string every time
		vector<port_filter_rule> m_port_match;
	};
	struct rule_config {
		std::string m_port;
		bool m_port_subst;		// port contains {token(s)}
		std::string m_path;
		bool m_path_subst;		// path contains {token(s)}
		vector<port_filter_rule> m_port_rules;
	};
	struct filter_rule {
		explicit filter_rule() : m_include(false) { }

		bool m_include;
		vector<filter_condition> m_cond;
		rule_config m_config;
	};

	explicit prometheus_conf():
		m_enabled(false),
		m_log_errors(true),
		m_interval(-1),
		m_max_metrics(PROM_METRICS_HARD_LIMIT),
		m_max_metrics_per_proc(-1),
		m_max_tags_per_metric(-1),
		m_k8s_get_config(true)
	{}

	bool match(const sinsp_threadinfo* tinfo, const sinsp_threadinfo* mtinfo,
		const sinsp_container_info *container, infrastructure_state *is, set<uint16_t> &ports, string &path) const;

	bool enabled() const {
		return m_enabled;
	}

	unsigned max_metrics() const {
		return m_max_metrics;
	}

	void set_max_metrics(int i) {
		m_max_metrics = ((i<0) ? PROM_METRICS_HARD_LIMIT : min((unsigned)i, PROM_METRICS_HARD_LIMIT));
	}

	static set<uint16_t> filter_ports(const set<uint16_t>& ports,
		const vector<port_filter_rule>& rules);

	static bool portdef_to_pfrule(const string& str, port_filter_rule &pfr);
	static bool portdef_to_pfrule(const YAML::Node& node, port_filter_rule &pfr);
private:
	friend class YAML::convert<prometheus_conf>;
	friend class prom_process;
	friend class dragent_configuration;

	bool m_enabled;
	bool m_log_errors;
	int m_interval;
	unsigned m_max_metrics;
	int m_max_metrics_per_proc;
	int m_max_tags_per_metric;
	// vector<port_filter_rule> m_port_rules;
	vector<filter_rule> m_rules;

	bool m_k8s_get_config;
};

namespace YAML {
	template<>
	struct convert<prometheus_conf::port_filter_rule> {
		static Node encode(const prometheus_conf::port_filter_rule& rhs);
		static bool decode(const Node& node, prometheus_conf::port_filter_rule& rhs);
	};
	template<>
	struct convert<prometheus_conf::rule_config> {
		static Node encode(const prometheus_conf::rule_config& rhs);
		static bool decode(const Node& node, prometheus_conf::rule_config& rhs);
	};
	template<>
	struct convert<prometheus_conf::filter_rule> {
		static Node encode(const prometheus_conf::filter_rule& rhs);
		static bool decode(const Node& node, prometheus_conf::filter_rule& rhs);
	};
}

class prom_process
{
public:
	explicit prom_process(string name, int pid, int vpid, const set<uint16_t> &ports, string path) :
		m_name(name), m_pid(pid), m_vpid(vpid), m_ports(ports), m_path(path) { }

	Json::Value to_json(const prometheus_conf &conf) const;
private:
	string m_name;	// Just for debugging
	int m_pid;
	int m_vpid;
	set<uint16_t> m_ports;
	string m_path;
};

#endif // _WIN32
