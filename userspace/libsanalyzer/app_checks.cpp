//
// Created by Luca Marturana on 29/06/15.
//

#include "app_checks.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include <utils.h>

bool app_check::match(sinsp_threadinfo *tinfo) const
{
	// At least a pattern should be specified
	bool ret = (!m_comm_pattern.empty() || !m_exe_pattern.empty() || m_port_pattern > 0 || !m_arg_pattern.empty());
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
	if(!m_arg_pattern.empty())
	{
		ret &= find_if(tinfo->m_args.begin(), tinfo->m_args.end(), [this](const string& arg)
		{
			return arg.find(m_arg_pattern) != string::npos;
		}) != tinfo->m_args.end();
	}
	return ret;
}

app_process::app_process(string check_name, sinsp_threadinfo *tinfo):
	m_pid(tinfo->m_pid),
	m_vpid(tinfo->m_vpid),
	m_check_name(move(check_name)),
	m_ports(tinfo->m_ainfo->listening_ports())
{

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
	m_outqueue("/sdc_app_checks_in", posix_queue::SEND, 1),
	m_inqueue("/sdc_app_checks_out", posix_queue::RECEIVE, 1)
{
}

void app_checks_proxy::send_get_metrics_cmd(const vector<app_process> &processes)
{
	Json::Value command = Json::Value(Json::arrayValue);
	for(const auto& p : processes)
	{
		command.append(p.to_json());
	}
	string data = m_json_writer.write(command);
	g_logger.format(sinsp_logger::SEV_DEBUG, "Send to sdchecks: %s", data.c_str());
	m_outqueue.send(data);
}

unordered_map<int, app_check_data> app_checks_proxy::read_metrics()
{
	unordered_map<int, app_check_data> ret;
	auto msg = m_inqueue.receive();
	if(!msg.empty())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks: %lu bytes", msg.size());
		// g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks: %s", msg.c_str());
		Json::Value response_obj;
		m_json_reader.parse(msg, response_obj, false);
		// Parse data
		for(const auto& process : response_obj)
		{
			app_check_data data(process);
			ret.emplace(data.pid(), move(data));
		}
	}
	return ret;
}

app_check_data::app_check_data(const Json::Value &obj):
	m_pid(obj["pid"].asInt()),
	m_expiration_ts(obj["expiration_ts"].asUInt64())
{
	if(obj.isMember("display_name"))
	{
		m_process_name = obj["display_name"].asString();
	}
	if(obj.isMember("metrics"))
	{
		for(const auto& m : obj["metrics"])
		{
			m_metrics.emplace_back(m);
		}
	}
	if(obj.isMember("service_checks"))
	{
		for(const auto& s : obj["service_checks"])
		{
			m_service_checks.emplace_back(s);
		}
	}
}

uint16_t app_check_data::to_protobuf(draiosproto::app_info *proto, uint16_t limit) const
{
	// Right now process name is not used by backend
	//proto->set_process_name(m_process_name);
	uint16_t limit_used = 0;
	for(const auto& m : m_metrics)
	{
		if(limit_used >= limit)
		{
			break;
		}
		m.to_protobuf(proto->add_metrics());
		++limit_used;
	}
	/*
	 * Right now service checks are not supported by the backend
	 * we are sending them as 1/0 metrics
	 */
	for(const auto& s : m_service_checks)
	{
		if(limit_used >= limit)
		{
			break;
		}
		s.to_protobuf_as_metric(proto->add_metrics());
		++limit_used;
	}
	return limit_used;
}

app_metric::app_metric(const Json::Value &obj):
	m_name(obj[0].asString()),
	m_value(obj[2].asDouble()),
	m_type(type_t::GAUGE)
{
	auto metadata = obj[3];
	if(metadata.isMember("type"))
	{
		auto type = metadata["type"].asString();
		if(type == "gauge")
		{
			m_type = type_t::GAUGE;
		}
		else if(type == "rate")
		{
			m_type = type_t::RATE;
		}
	}
	if(metadata.isMember("tags"))
	{
		for(const auto& tag_obj : metadata["tags"])
		{
			auto tag_as_str = tag_obj.asString();
			auto colon = tag_as_str.find(':');
			if(colon != string::npos)
			{
				m_tags[tag_as_str.substr(0, colon)] = tag_as_str.substr(colon+1, tag_as_str.size()-colon);
			}
			else
			{
				m_tags[tag_as_str] = "";
			}
		}
	}
}

void app_metric::to_protobuf(draiosproto::app_metric *proto) const
{
	proto->set_name(m_name);
	proto->set_value(m_value);
	proto->set_type(static_cast<draiosproto::app_metric_type>(m_type));
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}
}

/*
 * example:
 * {"status": 0, "tags": ["redis_host:127.0.0.1", "redis_port:6379"],
 *   "timestamp": 1435684284.087451, "check": "redis.can_connect",
 *   "host_name": "vagrant-ubuntu-vivid-64", "message": null, "id": 44}
 */
app_service_check::app_service_check(const Json::Value &obj):
	m_status(static_cast<status_t>(obj["status"].asUInt())),
	m_name(obj["check"].asString())
{
	if(obj.isMember("tags"))
	{
		for(const auto& tag_obj : obj["tags"])
		{
			auto tag_as_str = tag_obj.asString();
			auto colon = tag_as_str.find(':');
			if(colon != string::npos)
			{
				m_tags[tag_as_str.substr(0, colon)] = tag_as_str.substr(colon+1, tag_as_str.size()-colon);
			}
			else
			{
				m_tags[tag_as_str] = "";
			}
		}
	}
	if(obj.isMember("message") && obj["message"].isString())
	{
		m_message = obj["message"].asString();
	}
}

void app_service_check::to_protobuf(draiosproto::app_check *proto) const
{
	proto->set_name(m_name);
	proto->set_value(static_cast<draiosproto::app_check_value>(m_status));
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}
}

void app_service_check::to_protobuf_as_metric(draiosproto::app_metric *proto) const
{
	proto->set_name(m_name);
	if(m_status == status_t::OK)
	{
		proto->set_value(1.0);
	}
	else
	{
		proto->set_value(0.0);
	}
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}
}