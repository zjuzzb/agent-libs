#pragma once
#ifndef CYGWING_AGENT
#ifndef _WIN32

#include "analyzer_settings.h"
#include "app_checks_proxy_interface.h"
#include "draios.pb.h"
#include "metric_forwarding_configuration.h"
#include "metric_limits.h"
#include "posix_queue.h"
#include "proc_filter.h"

#include "third-party/jsoncpp/json/json.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

Json::Value yaml_to_json(const YAML::Node& node);
class sinsp_container_info;
class yaml_configuration;
class infrastructure_state;

class prometheus_conf : public proc_filter::conf
{
	using base = proc_filter::conf;

public:
	explicit prometheus_conf()
	    : base("Prometheus autodetection"),
	      m_log_errors(true),
	      m_interval(-1),
	      m_max_metrics_per_proc(-1),
	      m_max_tags_per_metric(-1),
	      m_histograms(false),
	      m_ingest_raw(false),
	      m_ingest_calculated(false),
	      m_prom_sd(false)
	{
	}

	typedef struct
	{
		std::set<uint16_t> ports;
		std::string path;
		std::map<std::string, std::string> options;
		std::map<std::string, std::string> tags;
	} prom_params_t;

	// match_and_fill() finds if the current process matches a filtering rule and
	// if so, adds a prom_process to prom_procs.
	// If use_host_filter is enabled multiple rules can match resulting in multiple
	// additions to prom_procs
	bool match_and_fill(const thread_analyzer_info* tinfo,
	                    thread_analyzer_info* mtinfo,
	                    const sinsp_container_info* container,
	                    const infrastructure_state& is,
	                    std::vector<prom_process>& prom_procs,
	                    bool use_host_filter) const;

private:
	// Function to get called when a filtering rule matches in order to determine
	// the configuration parameters for this process
	bool get_rule_params(const object_filter_config::filter_rule& rule,
	                     const thread_analyzer_info* tinfo,
	                     const sinsp_container_info* container,
	                     const infrastructure_state& infra_state,
	                     bool use_host_filter,
	                     prom_params_t& out_params) const;

public:
	// Configuration parameter that controls prometheus timeout
	static type_config<uint32_t>::ptr c_prometheus_timeout;

	bool log_errors() const { return m_log_errors; }
	void set_log_errors(bool val) { m_log_errors = val; }

	int interval() const { return m_interval; }
	void set_interval(int val) { m_interval = val; }

	/**
	 * Returns the the maximum number of prometheus metrics to
	 * forward.
	 */
	unsigned max_metrics() const
	{
		return static_cast<unsigned>(
		    metric_forwarding_configuration::c_prometheus_max->get_value());
	}

	int max_metrics_per_proc() const { return m_max_metrics_per_proc; }
	void set_max_metrics_per_proc(int val) { m_max_metrics_per_proc = val; }

	int max_tags_per_metric() const { return m_max_tags_per_metric; }
	void set_max_tags_per_metric(int val) { m_max_tags_per_metric = val; }

	bool histograms() const { return m_histograms; }
	void set_histograms(bool val) { m_histograms = val; }

	bool ingest_raw() const { return m_ingest_raw; }
	void set_ingest_raw(bool val) { m_ingest_raw = val; }

	bool ingest_calculated() const { return m_ingest_calculated; }
	void set_ingest_calculated(bool val) { m_ingest_calculated = val; }

	// Set whether or not we do service discovery through prometheus (promscrape v2)
	bool prom_sd() const { return m_prom_sd; }
	void set_prom_sd(bool val) { m_prom_sd = val; }
	int metric_expiration() const { return m_metric_expiration; }
	void set_metric_expiration(int sec) { m_metric_expiration = sec; }

	void set_host_rules(std::vector<object_filter_config::filter_rule> rules)
	{
		m_host_rules = std::move(rules);
	}
	const std::vector<object_filter_config::filter_rule>& host_rules() const
	{
		return m_host_rules;
	}

	// Overloaded from the base class to include host rules
	void register_annotations(std::function<void(const std::string& str)> reg);

	// Validate config. Log and correct inconsistencies as needed
	void validate_config(const std::string &root_dir);

private:
	bool m_log_errors;
	int m_interval;
	int m_max_metrics_per_proc;
	int m_max_tags_per_metric;
	bool m_histograms;
	bool m_ingest_raw;
	bool m_ingest_calculated;
	std::vector<object_filter_config::filter_rule> m_host_rules;
	bool m_prom_sd;
	int m_metric_expiration;
};

class prom_process
{
public:
	explicit prom_process(const std::string &name,
	                      int pid,
	                      int vpid,
	                      const std::string &container_id,
	                      const std::set<uint16_t>& ports,
	                      const std::string &path,
	                      const std::map<std::string, std::string>& options,
	                      const std::map<std::string, std::string>& tags,
	                      std::unordered_map<std::string, std::string>&& infra_tags)
	    : m_name(name),
	      m_pid(pid),
	      m_vpid(vpid),
	      m_container_id(container_id),
	      m_ports(ports),
	      m_path(path),
	      m_options(options),
	      m_tags(tags),
	      m_infra_tags(std::move(infra_tags))
	{
	}

	Json::Value to_json(const prometheus_conf& conf) const;

	static void filter_procs(std::vector<prom_process>& procs,
	                         threadinfo_map_t& threadtable,
	                         const app_checks_proxy_interface::raw_metric_map_t& app_metrics,
	                         uint64_t now);

	inline bool operator==(const prom_process &rhs) const
	{
		return (m_pid == rhs.m_pid) && (m_vpid == rhs.m_vpid) &&
			(m_ports == rhs.m_ports) && (m_name == rhs.m_name) &&
			(m_container_id == rhs.m_container_id) &&
			(m_path == rhs.m_path) && (m_options == rhs.m_options) &&
			(m_tags == rhs.m_tags) && (m_infra_tags == rhs.m_infra_tags);
	}

	const std::string &name() const { return m_name; }
	int pid() const { return m_pid; }
	int vpid() const { return m_vpid; }
	const std::string &container_id() const { return m_container_id; }
	const std::set<uint16_t> &ports() const { return m_ports; }
	const std::string &path() const { return m_path; }
	const std::map<std::string, std::string> &options() const { return m_options; }
	const std::map<std::string, std::string> &tags() const { return m_tags; }
	const std::unordered_map<std::string, std::string> &infra_tags() const { return m_infra_tags; }
private:
	std::string m_name;  // Just for debugging
	int m_pid;
	int m_vpid;
	std::string m_container_id;
	std::set<uint16_t> m_ports;
	std::string m_path;
	std::map<std::string, std::string> m_options;
	std::map<std::string, std::string> m_tags;
	std::unordered_map<std::string, std::string> m_infra_tags;
};

#endif  // _WIN32
#endif  // CYGWING_AGENT
