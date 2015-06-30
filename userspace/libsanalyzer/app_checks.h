//
// Created by Luca Marturana on 23/06/15.
//
#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "third-party/jsoncpp/json/json.h"
#include "analyzer_thread.h"
#include "posix_queue.h"

namespace YAML
{
template<typename T>
struct convert;
}

class app_check
{
public:
	app_check():
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
	app_process(string check_name, sinsp_threadinfo* tinfo):
			m_pid(tinfo->m_pid),
			m_vpid(tinfo->m_vpid),
			m_check_name(move(check_name)),
			m_ports(tinfo->m_ainfo->listening_ports())
	{

	}

	Json::Value to_json() const;

private:
	int m_pid;
	int m_vpid;
	string m_check_name;
	set<uint16_t> m_ports;
};

class app_process_metrics
{
private:
	int m_pid;

};

class app_checks_proxy
{
public:
	app_checks_proxy();

	void send_get_metrics_cmd(uint64_t id, const vector<app_process>& processes);

	unordered_map<int, app_process_metrics> read_metrics(uint64_t id);

private:
	posix_queue m_outqueue;
	posix_queue m_inqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};