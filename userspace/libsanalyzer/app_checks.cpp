//
// Created by Luca Marturana on 29/06/15.
//

#include "app_checks.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include <utils.h>

Json::Value yaml_to_json(const YAML::Node& yaml)
{
	Json::Value ret;
	switch(yaml.Type())
	{
	case YAML::NodeType::Scalar:
	{
		try
		{
			ret = yaml.as<int>();
		}
		catch (const YAML::BadConversion& ex)
		{
			try
			{
				ret = yaml.as<double>();
			}
			catch (const YAML::BadConversion& ex)
			{
				ret = yaml.as<string>();
			}
		}
		break;
	}
	case YAML::NodeType::Sequence:
	{
		for(auto it = yaml.begin(); it != yaml.end(); ++it)
		{
			ret.append(yaml_to_json(*it));
		}
		break;
	}
	case YAML::NodeType::Map:
	{
		for(auto it = yaml.begin(); it != yaml.end(); ++it)
		{
			ret[it->first.as<string>()] = yaml_to_json(it->second);
		}
		break;
	}
	default:
		// Other types are null and undefined
		break;
	}
	return ret;
}

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

Json::Value app_check::to_json() const
{
	Json::Value ret;
	ret["name"] = m_name;
	if(!m_check_module.empty())
	{
		ret["check_module"] = m_check_module;
	}
	ret["conf"] = m_conf;
	if(m_interval > 0)
	{
		ret["interval"] = m_interval;
	}
	ret["log_errors"] = m_log_errors;
	return ret;
}
bool YAML::convert<app_check>::decode(const YAML::Node &node, app_check &rhs)
{
	/*
	 * Example:
	 * name: redisdb
	 *	pattern:
	 *	  comm: redis-server
	 *	conf:
	 *	  host: 127.0.0.1
	 *	  port: {port}
	 *
	 *	The conf part is not used by dragent
	 */
	rhs.m_name = node["name"].as<string>();
	auto check_module_node = node["check_module"];
	if(check_module_node.IsScalar())
	{
		rhs.m_check_module = check_module_node.as<string>();
	}
	auto enabled_node = node["enabled"];
	if(enabled_node.IsScalar())
	{
		rhs.m_enabled = enabled_node.as<bool>();
	}
	auto log_errors_node = node["log_errors"];
	if(log_errors_node.IsScalar())
	{
		rhs.m_log_errors = log_errors_node.as<bool>();
	}

	auto pattern_node = node["pattern"];
	if(pattern_node.IsMap())
	{
		auto comm_node = pattern_node["comm"];
		if(comm_node.IsScalar())
		{
			rhs.m_comm_pattern = comm_node.as<string>();
		}
		auto exe_node = pattern_node["exe"];
		if(exe_node.IsScalar())
		{
			rhs.m_exe_pattern = exe_node.as<string>();
		}
		auto port_node = pattern_node["port"];
		if(port_node.IsScalar())
		{
			rhs.m_port_pattern = port_node.as<uint16_t>();
		}
		auto arg_node = pattern_node["arg"];
		if(arg_node.IsScalar())
		{
			rhs.m_arg_pattern = arg_node.as<string>();
		}
	}

	auto interval_node = node["interval"];
	if(interval_node.IsScalar())
	{
		rhs.m_interval = interval_node.as<int>();
	}

	auto conf_node = node["conf"];
	if (conf_node.IsMap())
	{
		rhs.m_conf = yaml_to_json(conf_node);
	}
	return true;
}

app_process::app_process(const app_check& check, sinsp_threadinfo *tinfo):
	m_pid(tinfo->m_pid),
	m_vpid(tinfo->m_vpid),
	m_ports(tinfo->m_ainfo->listening_ports()),
	m_check(check)
{
}

void app_process::set_conf_vals(shared_ptr<app_process_conf_vals> &conf_vals)
{
	m_conf_vals = conf_vals;
}

Json::Value app_process::to_json() const
{
	Json::Value ret;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["check"] = m_check.to_json();
	ret["ports"] = Json::Value(Json::arrayValue);
	for(auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}
	Json::Value conf_vals;
	if(m_conf_vals)
	{
		conf_vals = m_conf_vals->vals();
	}
	else
	{
		conf_vals = Json::objectValue;
	}

	ret["conf_vals"] = conf_vals;

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

app_checks_proxy::metric_map_t app_checks_proxy::read_metrics(metric_limits::cref_sptr_t ml)
{
	metric_map_t ret;
	try
	{
		auto msg = m_inqueue.receive();
		if(!msg.empty())
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks: %lu bytes", msg.size());
			//g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from sdchecks: %s", msg.c_str());
			Json::Value response_obj;
			if(m_json_reader.parse(msg, response_obj, false))
			{
				for(const auto& process : response_obj)
				{
					app_check_data data(process, ml);
					// only add if there are metrics or services
					if(data.metrics().size() || data.services().size())
					{
						ret[data.pid()][data.name()] = move(data);
					}
				}
			}
			else
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "app_checks_proxy::read_metrics: JSON parsing error:");
				g_logger.format(sinsp_logger::SEV_DEBUG, "%s", msg.c_str());
			}
		}
	}
	catch(std::exception& ex)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "app_checks_proxy::read_metrics error: %s", ex.what());
	}
	return ret;
}

app_check_data::app_check_data(const Json::Value &obj, metric_limits::cref_sptr_t ml):
	m_pid(obj["pid"].asInt()),
	m_expiration_ts(obj["expiration_ts"].asUInt64())
{
	if(obj.isMember("display_name"))
	{
		m_process_name = obj["display_name"].asString();
	}
	if(obj.isMember("metrics"))
	{
		const Json::Value& metrics = obj["metrics"];
		if(!metrics.isNull() && metrics.isArray() && metrics.size() >= 4u)
		{
			for(const auto& m : metrics)
			{
				if(m[0].isConvertibleTo(Json::stringValue))
				{
					if(!ml || ml->allow(m[0].asString()))
					{
						m_metrics.emplace_back(m);
						g_logger.format(sinsp_logger::SEV_TRACE, "app_check metric allowed: %s", m[0].asCString());
					}
					else
					{
						g_logger.format(sinsp_logger::SEV_TRACE, "app_check metric not allowed: %s", m[0].asCString());
					}
				}
				else
				{
					g_logger.format(sinsp_logger::SEV_WARNING, "app_check %s service metric name not found", m_process_name.c_str());
				}
			}
		}
	}

	if(obj.isMember("service_checks"))
	{
		const Json::Value& service_checks = obj["service_checks"];
		if(!service_checks.isNull() && service_checks.isArray())
		{
			for(const auto& s : service_checks)
			{
				// "status" and "check" used in service_check constructor
				if(s.isMember("check") && s.isMember("status"))
				{
					if(s["check"].isConvertibleTo(Json::stringValue))
					{
						if(!ml || ml->allow(s["check"].asString()))
						{
							m_service_checks.emplace_back(s);
							g_logger.format(sinsp_logger::SEV_TRACE, "app_check service check allowed: %s", s["check"].asCString());
						}
						else
						{
							g_logger.format(sinsp_logger::SEV_TRACE, "app_check service check not allowed: %s", s["check"].asCString());
						}
					}
					else
					{
						g_logger.format(sinsp_logger::SEV_WARNING, "app_check %s service check name not found", m_process_name.c_str());
					}
				}
				else
				{
					g_logger.format(sinsp_logger::SEV_WARNING, "app_check %s service check JSON has no 'check' or status 'field': %s",
									m_process_name.c_str(), s["check"].asCString());
				}
			}
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
			g_logger.format(sinsp_logger::SEV_TRACE, "service_checks metrics limit (%u) reached.", limit);
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
	if(obj.isMember("tags") && obj.isArray())
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
