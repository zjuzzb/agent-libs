#pragma once
#ifndef CYGWING_AGENT
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
#include "proc_filter.h"
#include "app_checks.h"
#include "metric_forwarding_configuration.h"

Json::Value yaml_to_json(const YAML::Node& node);
class sinsp_container_info;
class yaml_configuration;
class infrastructure_state;

class prometheus_conf: public proc_filter::conf
{
	using base = proc_filter::conf;
public:
	explicit prometheus_conf():
		base("Prometheus autodetection"),
		m_log_errors(true),
		m_interval(-1),
		m_max_metrics_per_proc(-1),
		m_max_tags_per_metric(-1),
		m_histograms(false),
		m_ingest_raw(false),
		m_ingest_calculated(false)
	{}

	typedef struct {
		set<uint16_t> ports;
        string path;
        map<string, string> options;
        map<string, string> tags;
	} prom_params_t;

	// match_and_fill() finds if the current process matches a filtering rule and
	// if so, adds a prom_process to prom_procs.
	// If use_host_filter is enabled multiple rules can match resulting in multiple
	// additions to prom_procs
	bool match_and_fill(const sinsp_threadinfo* tinfo, sinsp_threadinfo* mtinfo,
		const sinsp_container_info *container, const infrastructure_state &is,
		vector<prom_process> &prom_procs, bool use_host_filter) const;

private:
	// Function to get called when a filtering rule matches in order to determine
	// the configuration parameters for this process
	bool get_rule_params(const object_filter_config::filter_rule &rule, const sinsp_threadinfo *tinfo,
		const sinsp_container_info *container, const infrastructure_state &infra_state,
		bool use_host_filter, prom_params_t &out_params);

public:
	bool log_errors() const { return m_log_errors; }
	void set_log_errors(bool val) { m_log_errors = val; }

	int interval() const { return m_interval; }
	void set_interval(int val) { m_interval = val; }

	/**
	 * Returns the the maximum number of prometheus metrics to
	 * forward.
	 */
	unsigned max_metrics() const { return static_cast<unsigned>(metric_forwarding_configuration::c_prometheus_max->get()); }

	int max_metrics_per_proc() const { return m_max_metrics_per_proc; }
	void set_max_metrics_per_proc(int val) { m_max_metrics_per_proc = val; }

	int max_tags_per_metric() const { return m_max_tags_per_metric; }
	void set_max_tags_per_metric(int val) { m_max_tags_per_metric = val; }

	bool histograms() const { return m_histograms; }
	void set_histograms(bool val) { m_histograms = val; }

	bool ingest_raw() const { return m_ingest_raw ; }
	void set_ingest_raw(bool val) { m_ingest_raw = val; }

	bool ingest_calculated() const { return m_ingest_calculated ; }
	void set_ingest_calculated(bool val) { m_ingest_calculated = val; }

	void set_host_rules(std::vector<object_filter_config::filter_rule> rules) { m_host_rules = std::move(rules); }
	const std::vector<object_filter_config::filter_rule>& host_rules() const { return m_host_rules; }

	// Overloaded from the base class to include host rules
	void register_annotations(std::function<void (const std::string &str)> reg);
private:
	bool m_log_errors;
	int m_interval;
	int m_max_metrics_per_proc;
	int m_max_tags_per_metric;
	bool m_histograms;
	bool m_ingest_raw;
	bool m_ingest_calculated;
	vector<object_filter_config::filter_rule> m_host_rules;
};

class prom_process
{
public:
	explicit prom_process(const string name, int pid, int vpid, const set<uint16_t> &ports, const string path, const map<string, string> &options, const map<string, string> &tags) :
		m_name(name), m_pid(pid), m_vpid(vpid), m_ports(ports), m_path(path), m_options(options), m_tags(tags) { }

	Json::Value to_json(const prometheus_conf &conf) const;

	static void filter_procs(vector<prom_process> &procs, threadinfo_map_t &threadtable, const app_checks_proxy::metric_map_t &app_metrics, uint64_t now);
private:
	string m_name;	// Just for debugging
	int m_pid;
	int m_vpid;
	set<uint16_t> m_ports;
	string m_path;
	map<string, string> m_options;
	map<string, string> m_tags;
};

#endif // _WIN32
#endif // CYGWING_AGENT
