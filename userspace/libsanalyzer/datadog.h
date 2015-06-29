//
// Created by Luca Marturana on 23/06/15.
//
#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "third-party/jsoncpp/json/json.h"
#include <mqueue.h>
#include "analyzer_thread.h"

namespace YAML
{
template<typename T>
struct convert;
}

class datadog_check
{
public:
	bool match(sinsp_threadinfo* tinfo) const;

	const string& name() const
	{
		return m_name;
	}

private:
	friend class YAML::convert<datadog_check>;

	string m_comm_pattern;
	string m_exe_pattern;
	uint16_t m_port_pattern;
	string m_name;
};

class datadog_process
{
public:
	datadog_process(string check_name, sinsp_threadinfo* tinfo):
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

class datadog_process_metrics
{
private:
	int m_pid;

};

class datadog_checks_proxy
{
public:
	datadog_checks_proxy()
	{
		m_outqueue = mq_open("/sdchecks", O_WRONLY);
	}

	~datadog_checks_proxy()
	{
		mq_close(m_outqueue);
	}

	void send_get_metrics_cmd(uint64_t id, const vector<datadog_process>& processes);

	pair<uint64_t, unordered_map<int, datadog_process_metrics>> read_metrics();

private:
	mqd_t m_outqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};