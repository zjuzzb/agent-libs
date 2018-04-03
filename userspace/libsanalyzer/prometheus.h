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
		m_max_metrics(PROM_METRICS_HARD_LIMIT),
		m_max_metrics_per_proc(-1),
		m_max_tags_per_metric(-1),
		m_histograms(false)
	{}

	bool match(const sinsp_threadinfo* tinfo, const sinsp_threadinfo* mtinfo,
		const sinsp_container_info *container, const infrastructure_state &is,
		set<uint16_t> &ports, string &path, map<string, string> &opts) const;

	bool log_errors() const { return m_log_errors; }
	void set_log_errors(bool val) { m_log_errors = val; }

	int interval() const { return m_interval; }
	void set_interval(int val) { m_interval = val; }

	unsigned max_metrics() const { return m_max_metrics; }
	void set_max_metrics(int i) {
		m_max_metrics = ((i<0) ? PROM_METRICS_HARD_LIMIT : min((unsigned)i, PROM_METRICS_HARD_LIMIT));
	}

	int max_metrics_per_proc() const { return m_max_metrics_per_proc; }
	void set_max_metrics_per_proc(int val) { m_max_metrics_per_proc = val; }

	int max_tags_per_metric() const { return m_max_tags_per_metric; }
	void set_max_tags_per_metric(int val) { m_max_tags_per_metric = val; }

	bool histograms() const { return m_histograms; }
	void set_histograms(bool val) { m_histograms = val; }

private:
	bool m_log_errors;
	int m_interval;
	unsigned m_max_metrics;
	int m_max_metrics_per_proc;
	int m_max_tags_per_metric;
	bool m_histograms;
};

class prom_process
{
public:
	explicit prom_process(string name, int pid, int vpid, const set<uint16_t> &ports, string path, const map<string, string> &options) :
		m_name(name), m_pid(pid), m_vpid(vpid), m_ports(ports), m_path(path), m_options(options) { }

	Json::Value to_json(const prometheus_conf &conf) const;
private:
	string m_name;	// Just for debugging
	int m_pid;
	int m_vpid;
	set<uint16_t> m_ports;
	string m_path;
	map<string, string> m_options;
};

#endif // _WIN32
#endif // CYGWING_AGENT
