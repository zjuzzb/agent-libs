//
// Created by Luca Marturana on 23/06/15.
//
#pragma once

#include <memory>

#include "sinsp.h"

#ifndef _WIN32
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
class prometheus_conf;
class prom_process;

class app_check
{
public:
	explicit app_check():
		m_port_pattern(0),
		m_enabled(true),
		m_log_errors(true),
		m_retry(true),
		m_interval(-1),
		m_conf(Json::objectValue)
	{}

	bool match(sinsp_threadinfo* tinfo) const;

	const string& name() const
	{
		return m_name;
	}

	const string& module() const
	{
		return m_check_module;
	}

	bool enabled() const {
		return m_enabled;
	}

	Json::Value to_json() const;

private:
	friend class YAML::convert<app_check>;

	string m_comm_pattern;
	string m_exe_pattern;
	uint16_t m_port_pattern;
	string m_arg_pattern;
	string m_name;
	string m_check_module;
	bool m_enabled;
	bool m_log_errors;
	bool m_retry;
	int m_interval;
	Json::Value m_conf;
};

namespace YAML {
	template<>
	struct convert<app_check> {
		static Node encode(const app_check& rhs);

		static bool decode(const Node& node, app_check& rhs);
	};
}

// In some cases, an app check may want to have a custom way to
// generate config values to match against the check's config. This
// class allows a way to do that.

class app_process_conf_vals
{
public:
	app_process_conf_vals() {}
	virtual ~app_process_conf_vals() {};

	virtual Json::Value vals() = 0;
};

class app_process
{
public:
	explicit app_process(const app_check& check, sinsp_threadinfo* tinfo);

	void set_conf_vals(shared_ptr<app_process_conf_vals> &conf_vals);

	Json::Value to_json() const;

	inline const string& name() const
	{
		return m_check.name();
	}

private:
	int m_pid;
	int m_vpid;
	set<uint16_t> m_ports;
	const app_check& m_check;
	shared_ptr<app_process_conf_vals> m_conf_vals;
};


class app_metric
{
public:
	enum class type_t
	{
		GAUGE = 1,
		RATE
	};
	explicit app_metric(const Json::Value& obj);
	void to_protobuf(draiosproto::app_metric* proto) const;
	const std::string& name() const;
private:
	string m_name;
	double m_value;
	type_t m_type;
	map<string, string> m_tags;
};

inline const std::string& app_metric::name() const
{
	return m_name;
}

class app_service_check
{
public:
	enum status_t
	{
		OK = 0,
		WARNING = 1,
		CRITICAL = 2,
		UNKNOWN = 3,
	};
	explicit app_service_check(const Json::Value& obj);
	void to_protobuf(draiosproto::app_check* proto) const;
	void to_protobuf_as_metric(draiosproto::app_metric* proto) const;
	const std::string& name() const;
private:
	status_t m_status;
	map<string, string> m_tags;
	string m_name;
	string m_message;
};

inline const std::string& app_service_check::name() const
{
	return m_name;
}

class app_check_data
{
public:
	typedef vector<app_metric> metrics_t;
	typedef vector<app_service_check> services_t;

	enum check_type
	{
		APPCHECK,
		PROMETHEUS
	};

	// Added for unordered_map::operator[]
	app_check_data():
			m_pid(0),
			m_expiration_ts(0),
			m_total_metrics(0)
	{};

	explicit app_check_data(const Json::Value& obj, metric_limits::cref_sptr_t ml = nullptr);

	check_type type() const
	{
		return m_type;
	}

	void set_type(const check_type t)
	{
		m_type = t;
	}

	int pid() const
	{
		return m_pid;
	}

	uint64_t expiration_ts() const
	{
		return m_expiration_ts;
	}

	unsigned to_protobuf(draiosproto::app_info *proto, uint16_t& limit, uint16_t max_limit) const;


	const string& name() const
	{
		return m_process_name;
	}

	const metrics_t& metrics() const
	{
		return m_metrics;
	}

	const services_t& services() const
	{
		return m_service_checks;
	}

	unsigned total_metrics() const
	{
		return m_total_metrics;
	}

private:
	check_type m_type;
	int m_pid;
	string m_process_name;
	metrics_t m_metrics;
	services_t m_service_checks;
	uint64_t m_expiration_ts;
	unsigned m_total_metrics;
};

class app_checks_proxy
{
public:
	// hash table keyed by PID, containing maps keyed by app_check name
	typedef unordered_map<int, map<string, app_check_data>> metric_map_t;

	app_checks_proxy();

	// void send_get_metrics_cmd(const vector<app_process>& processes);
	void send_get_metrics_cmd(const vector<app_process>& processes,
		const vector<prom_process>& prom_procs, const prometheus_conf &conf);

	metric_map_t read_metrics(metric_limits::cref_sptr_t ml = nullptr);

private:
	posix_queue m_outqueue;
	posix_queue m_inqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};

#endif // _WIN32
