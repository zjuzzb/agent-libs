//
// Created by Luca Marturana on 29/06/15.
//

#include "app_checks.h"

bool app_check::match(sinsp_threadinfo *tinfo) const
{
	bool ret = true;
	if(!m_comm_pattern.empty())
	{
		ret &= tinfo->m_comm.find(m_comm_pattern) != string::npos;
	}
	if(!m_exe_pattern.empty())
	{
		ret &= tinfo->m_exe.find(m_exe_pattern) != string::npos;
	}
	if(m_port_pattern > 0)
	{
		auto ports = tinfo->m_ainfo->listening_ports();
		ret &= ports.find(m_port_pattern) != ports.end();
	}
	return ret;
}

Json::Value app_process::to_json() const
{
	Json::Value ret;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["check"] = m_check_name;
	ret["ports"] = Json::Value(Json::arrayValue);
	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}
	return ret;
}

void app_checks_proxy::send_get_metrics_cmd(uint64_t id, const vector<app_process> &processes)
{
	Json::Value command;
	command["id"] = Json::UInt64(id);
	command["body"] = Json::Value(Json::arrayValue);
	for(const auto& p : processes)
	{
		command["body"].append(p.to_json());
	}
	string data = m_json_writer.write(command);
	g_logger.format(sinsp_logger::SEV_INFO, "Send to sdchecks: %s", data.c_str());
	mq_send(m_outqueue, data.c_str(), data.size(), 0);
}