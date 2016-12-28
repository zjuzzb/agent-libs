//
// Created by Luca Marturana on 23/06/15.
//
#pragma once

#include <memory>

#include "sinsp.h"

#ifndef _WIN32
#include "third-party/jsoncpp/json/json.h"
#include "posix_queue.h"
#include "draios.pb.h"
// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

Json::Value yaml_to_json(const YAML::Node& node);

class app_check
{
public:
	explicit app_check():
		m_port_pattern(0),
		m_enabled(true),
		m_interval(-1),
		m_conf(Json::objectValue)
	{}

	bool match(sinsp_threadinfo* tinfo) const;

	const string& name() const
	{
		return m_name;
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
private:
	string m_name;
	double m_value;
	type_t m_type;
	map<string, string> m_tags;
};

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
private:
	status_t m_status;
	map<string, string> m_tags;
	string m_name;
	string m_message;
};

class app_check_data
{
public:
	// Added for unordered_map::operator[]
	explicit app_check_data():
			m_pid(0),
			m_expiration_ts(0)
	{};

	explicit app_check_data(const Json::Value& obj);

	int pid() const
	{
		return m_pid;
	}

	uint64_t expiration_ts() const
	{
		return m_expiration_ts;
	}

	uint16_t to_protobuf(draiosproto::app_info *proto, uint16_t limit) const;

private:
	int m_pid;
	string m_process_name;
	vector<app_metric> m_metrics;
	vector<app_service_check> m_service_checks;
	uint64_t m_expiration_ts;
};

class app_checks_proxy
{
public:
	app_checks_proxy();

	void send_get_metrics_cmd(const vector<app_process>& processes);

	unordered_map<int, app_check_data> read_metrics();

private:
	posix_queue m_outqueue;
	posix_queue m_inqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};

#endif // _WIN32
