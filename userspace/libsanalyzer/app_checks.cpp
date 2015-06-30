//
// Created by Luca Marturana on 29/06/15.
//

#include "app_checks.h"
#include <utils.h>

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

app_checks_proxy::app_checks_proxy():
	m_outqueue("/sdchecks", posix_queue::SEND),
	m_inqueue("/dragent_app_checks", posix_queue::RECEIVE)
{
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
	m_outqueue.send(data);
}

unordered_map<int, app_check_data> app_checks_proxy::read_metrics(uint64_t id)
{
	unordered_map<int, app_check_data> ret;
	auto msg = m_inqueue.receive();
	while(!msg.empty())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks: %s", msg.c_str());
		Json::Value response_obj;
		m_json_reader.parse(msg, response_obj, false);
		if(response_obj["id"].asUInt64() == id)
		{
			// Parse data
			for(auto process : response_obj["body"])
			{
				app_check_data data(process);
				ret.emplace(make_pair(data.pid(), move(data)));
			}
			break;
		}
	}
	return ret;
}

app_check_data::app_check_data(const Json::Value &obj):
	m_pid(obj["pid"].asInt())
{
	if(obj.isMember("process_name"))
	{
		m_process_name = obj["process_name"].asString();
	}
	if(obj.isMember("metrics"))
	{
		auto metrics = obj["metrics"];
		transform(metrics.begin(), metrics.end(), m_metrics.begin(),[](const Json::Value& v)
		{
			return app_metric(v);
		});
	}
	if(obj.isMember("service_checks"))
	{
		auto service_checks = obj["service_checks"];
		transform(service_checks.begin(), service_checks.end(), m_service_checks.begin(),[](const Json::Value& v)
		{
			return app_service_check(v);
		});
	}
}

app_metric::app_metric(const Json::Value &obj):
	m_name(obj[0].asString()),
	m_value(obj[2].asDouble())
{
	auto metadata = obj[3];
	if(metadata.isMember("type"))
	{
		auto type = metadata["type"].asString();
		if(type == "gauge")
		{
			m_type = type_t::GAUGE;
		}
		else if (type == "rate")
		{
			m_type = type_t::RATE;
		}
	}
	if(metadata.isMember("tags"))
	{
		for(auto tag_obj : metadata["tags"])
		{
			auto tag_as_str = tag_obj.asString();
			auto tag_parsed = sinsp_split(tag_as_str, ':');
			m_tags[tag_parsed.at(0)] = tag_parsed.size() > 1 ? tag_parsed.at(1) : "";
		}
	}
}

app_service_check::app_service_check(const Json::Value &obj)
{

}