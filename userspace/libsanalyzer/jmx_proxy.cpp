#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "jmx_proxy.h"

#ifndef _WIN32
#include <unistd.h>
#include "logger.h"
#include "fcntl.h"

java_bean_attribute::java_bean_attribute(const Json::Value& json):
	m_name(json["name"].asString()),
	m_value(0),
	m_unit(0),
	m_scale(0),
	m_type(0)
{
	if(json.isMember("alias"))
	{
		m_alias = json["alias"].asString();
	}
	if(check_member(json, "unit", Json::uintValue))
	{
		m_unit = json["unit"].asUInt();
	}
	if(check_member(json, "scale", Json::uintValue))
	{
		m_scale = json["scale"].asUInt();
	}
	//TODO: type can be a string
	if(check_member(json, "type", Json::uintValue))
	{
		m_type = json["type"].asUInt();
	}
	if (json.isMember("value"))
	{
		const auto& value_node = json["value"];
		if(value_node.isDouble())
		{
			m_value = value_node.asDouble();
		}
		// Otherwise leave 0 as default and go on
		// this is a very rare situation
	} else if (json.isMember("subattributes"))
	{
		for(const auto& subattribute : json["subattributes"])
		{
			m_subattributes.emplace_back(subattribute);
		}
	}
}

void
java_bean_attribute::to_protobuf(draiosproto::jmx_attribute *attribute, unsigned sampling) const
{
	attribute->set_name(m_name);
	if(!m_alias.empty())
	{
		attribute->set_alias(m_alias);
	}
	if(m_unit > 0)
	{
		attribute->set_unit(static_cast<draiosproto::unit>(m_unit));
	}
	if(m_scale > 0)
	{
		attribute->set_scale(static_cast<draiosproto::scale>(m_scale));
	}
	if(m_type > 0)
	{
		attribute->set_type(static_cast<draiosproto::jmx_metric_type>(m_type));
	}
	if (m_subattributes.empty())
	{
		if(m_type == draiosproto::jmx_metric_type::JMX_METRIC_TYPE_COUNTER)
		{
			attribute->set_value(m_value/sampling);
		}
		else
		{
			attribute->set_value(m_value);
		}
	}
	else
	{
		for(const auto& subattribute : m_subattributes)
		{
			draiosproto::jmx_attribute* subattribute_proto = attribute->add_subattributes();
			subattribute.to_protobuf(subattribute_proto, sampling);
		}
	}
}

java_bean::java_bean(const Json::Value& json, metric_limits::cref_sptr_t ml):
	m_name(json["name"].asString())
{
	for(const auto& attribute : json["attributes"])
	{
		std::string n;
		if(!attribute["name"].isNull())
		{
			n = attribute["name"].asString();
		}
		std::string a;
		if(!attribute["alias"].isNull())
		{
			a = attribute["alias"].asString();
		}
		if(ml && ((!n.empty() && !ml->allow(n)) || (!a.empty() && !ml->allow(a))))
		{
			SINSP_LOG("jmx metric not allowed: " + n, SEV_TRACE);
			continue;
		}
		else
		{
			SINSP_LOG("jmx metric allowed: " + n, SEV_TRACE);
		}
		m_attributes.emplace_back(attribute);
	}
}

unsigned int java_bean::to_protobuf(draiosproto::jmx_bean *proto_bean, unsigned sampling, unsigned limit) const
{
	proto_bean->mutable_name()->assign(m_name);
	unsigned emitted_attributes = 0;
	for(auto it = m_attributes.cbegin(); it != m_attributes.cend() && limit > emitted_attributes; ++it)
	{
		draiosproto::jmx_attribute* attribute_proto = proto_bean->add_attributes();
		it->to_protobuf(attribute_proto, sampling);
		emitted_attributes += 1;
	}
	return emitted_attributes;
}

java_process::java_process(const Json::Value& json, metric_limits::cref_sptr_t ml):
	m_pid(json["pid"].asInt()),
	m_name(json["name"].asString())
{
	for(const auto& bean : json["beans"])
	{
		java_bean jb = java_bean(bean, ml);
		if(jb.attribute_count())
		{
			m_beans.push_back(move(jb));
		}
	}
}

unsigned int java_process::to_protobuf(draiosproto::java_info *protobuf, unsigned sampling, unsigned limit) const
{
	protobuf->set_process_name(m_name);
	unsigned emitted_attributes = 0;
	for(auto bean_it = m_beans.cbegin(); bean_it != m_beans.cend() && limit > emitted_attributes; ++bean_it)
	{
		draiosproto::jmx_bean* protobean = protobuf->add_beans();
		emitted_attributes += bean_it->to_protobuf(protobean, sampling, limit-emitted_attributes);
	}
	return emitted_attributes;
}

jmx_proxy::jmx_proxy(): m_print_json(false),
		m_outqueue("/sdc_sdjagent_in", posix_queue::SEND, 1),
		m_inqueue("/sdc_sdjagent_out", posix_queue::RECEIVE, 1)
{
}

Json::Value jmx_proxy::tinfo_to_json(sinsp_threadinfo *tinfo)
{
	static const unsigned MAX_ARG_SIZE = 100;
	Json::Value ret;
	ret["pid"] = static_cast<Json::Value::Int64>(tinfo->m_pid);
	ret["vpid"] = static_cast<Json::Value::Int64>(tinfo->m_vpid);
	ret["root"] = tinfo->m_root;

	// Serializing all args leds very big Json > 4kb, so try to
	// do a gross filtering and let sdjagent parse them
	// otherwise we can move the whole parsing here
	Json::Value args_json(Json::arrayValue);
	for(const auto& arg : tinfo->m_args) {
		// Do a gross filtering of args
		if(arg.find("-D") == 0 && arg.find("jmx") != string::npos && arg.size() < MAX_ARG_SIZE)
		{
			args_json.append(arg);
		}
	}
	// Last non empty arg is usually the main class
	for(auto it = tinfo->m_args.rbegin(); it != tinfo->m_args.rend(); ++it)
	{
		// Do a simple sanity check by ensuring:
		// - the arg is not empty
		// - the arg is not too big
		// - the arg contains only . and alphanumeric chars
		if(!it->empty() && it->size() < MAX_ARG_SIZE &&
		   find_if_not(it->begin(), it->end(), [](char ch) {
			return ch == '.' || ch == '/' || isalnum(ch);
			}) == it->end())
		{
			args_json.append(*it);
			break;
		}
	}
	ret["args"] = args_json;
	return ret;
}

void jmx_proxy::send_get_metrics(const vector<sinsp_threadinfo*>& processes)
{
	Json::Value command_obj;
	command_obj["command"] = "getMetrics";
	Json::Value body(Json::arrayValue);
	for(auto tinfo : processes)
	{
		body.append(tinfo_to_json(tinfo));
	}
	command_obj["body"] = body;
	string command_data = m_json_writer.write(command_obj);
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending get metric command to JMX: %s", command_data.c_str());
	m_outqueue.send(command_data);
}

unordered_map<int, java_process> jmx_proxy::read_metrics(metric_limits::cref_sptr_t ml)
{
	unordered_map<int, java_process> processes;
	try
	{
		auto json_data = m_inqueue.receive();

		if (json_data.size() > 0)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics json size is: %d", json_data.size());
			if(m_print_json) {
				g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics json: %s", json_data.c_str());
			}
			Json::Value json_obj;

			bool parse_ok = m_json_reader.parse(json_data, json_obj, false);
			if(parse_ok && json_obj.isObject() && json_obj.isMember("body"))
			{
				for(const auto& process_data : json_obj["body"])
				{
					java_process process(process_data, ml);
					processes.emplace(process.pid(), move(process));
				}
			}
			else
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "Cannot deserialize JMX metrics");
				g_logger.format(sinsp_logger::SEV_DEBUG, "%s", json_data.c_str());
			}
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics are not ready");
		}
	}
	catch(std::exception& ex)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "jmx_proxy::read_metrics eror: %s", ex.what());
	}
	return processes;
}

#endif // _WIN32
