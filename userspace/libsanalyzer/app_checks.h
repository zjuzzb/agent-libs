//
// Created by Luca Marturana on 23/06/15.
//
#pragma once

#include "sinsp.h"
#include "third-party/jsoncpp/json/json.h"
#include "posix_queue.h"
#include "draios.pb.h"

namespace YAML
{
template<typename T>
struct convert;
}

class app_check
{
public:
	explicit app_check():
		m_port_pattern(0)
	{}

	bool match(sinsp_threadinfo* tinfo) const;

	const string& name() const
	{
		return m_name;
	}

private:
	friend class YAML::convert<app_check>;

	string m_comm_pattern;
	string m_exe_pattern;
	uint16_t m_port_pattern;
	string m_name;
};

class app_process
{
public:
	explicit app_process(string check_name, sinsp_threadinfo* tinfo);

	Json::Value to_json() const;

private:
	int m_pid;
	int m_vpid;
	string m_check_name;
	set<uint16_t> m_ports;
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
	explicit app_check_data(const Json::Value& obj);

	int pid() const
	{
		return m_pid;
	}

	uint16_t to_protobuf(draiosproto::app_info *proto, uint16_t limit) const;
private:
	int m_pid;
	string m_process_name;
	vector<app_metric> m_metrics;
	vector<app_service_check> m_service_checks;
};

class app_checks_proxy
{
public:
	app_checks_proxy();

	void send_get_metrics_cmd(uint64_t id, const vector<app_process>& processes);

	unordered_map<int, app_check_data> read_metrics(uint64_t id);

private:
	posix_queue m_outqueue;
	posix_queue m_inqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};