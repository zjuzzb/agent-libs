#pragma once

#include "draios.pb.h"
#include "limits/metric_forwarding_configuration.h"
#include "type_config.h"

#include "third-party/jsoncpp/json/json.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

class promscrape_conf
{
public:
	// Configuration parameter that controls prometheus timeout
	static type_config<uint32_t>::ptr c_promscrape_timeout;

	explicit promscrape_conf(): 
		m_interval(-1),
		m_histograms(false),
		m_ingest_raw(false),
	    m_ingest_calculated(false),
		m_metric_expiration(-1),
		m_prom_sd(false)
	{
	}

	/**
	 * Returns the the maximum number of prometheus metrics to
	 * forward.
	 */
	unsigned max_metrics() const
	{
		return static_cast<unsigned>(
		    metric_forwarding_configuration::instance().prometheus_limit());
	}

	int interval() const { return m_interval; }
	void set_interval(int val) { m_interval = val; }

	int metric_expiration() const { return m_metric_expiration; }
	void set_metric_expiration(int sec) { m_metric_expiration = sec; }

	bool histograms() const { return m_histograms; }
	void set_histograms(bool val) { m_histograms = val; }

	bool ingest_raw() const { return m_ingest_raw; }
	void set_ingest_raw(bool val) { m_ingest_raw = val; }

	bool ingest_calculated() const { return m_ingest_calculated; }
	void set_ingest_calculated(bool val) { m_ingest_calculated = val; }

	bool prom_sd() const { return m_prom_sd; }
	void set_prom_sd(bool val) { m_prom_sd = val; }

private:
	int m_interval;
	bool m_histograms;
	bool m_ingest_raw;
	bool m_ingest_calculated;
	int m_metric_expiration;
	bool m_prom_sd;
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

	Json::Value to_json() const;


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
	std::set<uint16_t> &ports() { return const_cast<std::set<uint16_t> &> (const_cast<const prom_process*>(this)->ports()); }
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

