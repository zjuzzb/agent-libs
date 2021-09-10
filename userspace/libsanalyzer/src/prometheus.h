#pragma once
#ifndef CYGWING_AGENT
#ifndef _WIN32

#include "analyzer_settings.h"
#include "app_checks_proxy_interface.h"
#include "draios.pb.h"
#include "limits/metric_limits.h"
#include "posix_queue.h"
#include "proc_filter.h"
#include "promscrape_conf.h"

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
	      m_max_metrics_per_proc(-1),
	      m_max_tags_per_metric(-1)
	{
		init_command_line();
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

	static void filter_prom_procs(std::vector<prom_process>& procs,
	                         threadinfo_map_t& threadtable,
	                         const app_checks_proxy_interface::raw_metric_map_t& app_metrics,
	                         uint64_t now);

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
	void to_json(Json::Value& ret) const;

	bool log_errors() const { return m_log_errors; }
	void set_log_errors(bool val) { m_log_errors = val; }

	int max_metrics_per_proc() const { return m_max_metrics_per_proc; }
	void set_max_metrics_per_proc(int val) { m_max_metrics_per_proc = val; }

	int max_tags_per_metric() const { return m_max_tags_per_metric; }
	void set_max_tags_per_metric(int val) { m_max_tags_per_metric = val; }

	unsigned max_metrics() const { return m_scrape_conf.max_metrics(); }
	
	// Set whether or not we do service discovery through prometheus (promscrape v2)
	bool prom_sd() const { return m_scrape_conf.prom_sd(); }
	void set_prom_sd(bool val) { m_scrape_conf.set_prom_sd(val); }

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

	void show_config(std::string &output);
	void init_command_line();

	promscrape_conf get_scrape_conf() const
	{ 
		return m_scrape_conf;
	}

	void set_scrape_conf(const promscrape_conf&& conf)
	{ 
		m_scrape_conf = conf;
	}

private:
	bool m_log_errors;
	int m_max_metrics_per_proc;
	int m_max_tags_per_metric;
	std::vector<object_filter_config::filter_rule> m_host_rules;
	promscrape_conf m_scrape_conf;
};

#endif  // _WIN32
#endif  // CYGWING_AGENT
