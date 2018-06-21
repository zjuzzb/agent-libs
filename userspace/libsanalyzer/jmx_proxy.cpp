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

	if(json.isMember("segment_by"))
	{
		for(auto member : json["segment_by"].getMemberNames())
		{
			m_segment_by[member] = json["segment_by"][member].asString();
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
	if(!m_segment_by.empty())
	{
		for(auto seg : m_segment_by)
		{
			auto new_segment_by = attribute->add_segment_by();
			new_segment_by->set_key(seg.first);
			new_segment_by->set_value(seg.second);
		}
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
	m_name(json["name"].asString()), m_total_metrics(0)
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
		bool metric_included = true;
		bool allow_name = true, allow_alias = true;
		int name_pos = 0, alias_pos = 0;
		int nopos = metric_limits::NO_FILTER_POSITION;
		std::string name_filter, alias_filter;

		if(ml)
		{
			//
			// for jmx , we support both names and aliases, which somewhat complicates things here
			// eg. when alias is excluded on the list but name is not on the list at all (thus allowed by default),
			// metric is still allowed by the name absence from the list; so, we have to find out whether the filter
			// permission status is explicit (filter pattern) or implicit (not on the list) and apply folowing logic:
			//
			// 1. if name nor alias is found in the list, metric is included
			// 2. if [alias OR name OR both] are found in the list, metric is included/excluded based on first found
			//
			name_pos = 0;
			allow_name = false;
			if(!n.empty())
			{
				allow_name = ml->allow(n, name_filter, &name_pos);
			}
			alias_pos = 0;
			allow_alias = false;
			if(!a.empty())
			{
				allow_alias = ml->allow(a, alias_filter, &alias_pos);
			}
			nopos = metric_limits::NO_FILTER_POSITION;
			metric_included = ((alias_pos == nopos) && (name_pos == nopos)); // 1. (neither in the list)
			if(!metric_included && ((name_pos) || (alias_pos))) // 2. (one or both found)
			{
				// name and alias position must always be different, except for {*, false}
				// filter, when they will both match first pattern
				ASSERT((name_pos != alias_pos) || ((name_pos == 1) && (alias_pos == 1)));
				if(name_pos && !alias_pos) // name in, alias not
				{
					metric_included = allow_name;
				}
				else if(alias_pos && !name_pos) // alias in, name not
				{
					metric_included = allow_alias;
				}
				else // both in, take first one
				{
					if(alias_pos < name_pos)
					{
						metric_included = allow_alias;
					}
					else
					{
						metric_included = allow_name;
					}
				}
			}
		}

		if(metric_limits::log_enabled())
		{
			// jmx is a special case because filter can specify either metric name or alias
			// we indicate in the log which criteria was used to include/exclude metric:
			// [+] - explicitly included by filter
			// [-] - explicitly excluded by filter
			// [ ] - no filter (metric included by default)
			bool name_found = (name_pos != nopos);
			bool alias_found = (alias_pos != nopos);
			bool by_name = name_found || (name_pos < alias_pos);
			bool by_alias = alias_found || (alias_pos < name_pos);
			const std::string& filter = by_name ? name_filter : (by_alias ? alias_filter : " ");
			char name_flag = (by_name ? (allow_name ? (name_found ? '+' : ' ') : '-') : ' ');
			char alias_flag = (by_alias ? (allow_alias ? (alias_found ? '+' : ' ') : '-') : ' ');
			char filter_flag = metric_included ? '+' : '-';
			std::ostringstream os;
			os << "filter: " << filter_flag << '[' << filter << "], "
				"criteria: (" << n << '[' << name_flag << "], " << a << '[' << alias_flag << ']' << ')';
			metric_limits::log(n.c_str(), "jmx", metric_included, true, os.str());
		}
		if(metric_included)
		{
			m_attributes.emplace_back(attribute);
		}
		++m_total_metrics;
	}
}

unsigned int java_bean::to_protobuf(draiosproto::jmx_bean *proto_bean, unsigned sampling, unsigned limit, const std::string& limit_type, unsigned max_limit) const
{
	unsigned emitted_attributes = 0;
	if(proto_bean)
	{
		proto_bean->mutable_name()->assign(m_name);

		for(auto it = m_attributes.cbegin(); it != m_attributes.cend(); ++it)
		{
			if(limit > emitted_attributes)
			{
				draiosproto::jmx_attribute* attribute_proto = proto_bean->add_attributes();
				it->to_protobuf(attribute_proto, sampling);
				emitted_attributes += 1;
			}
			else if(metric_limits::log_enabled())
			{
				g_logger.format(sinsp_logger::SEV_INFO, "[jmx] metric over limit (%s, %u max): %s (%s)",
						limit_type.c_str(), max_limit, it->name().c_str(), it->alias().c_str());
			}
			else { break; }
		}
	}
	return emitted_attributes;
}

java_process::java_process(const Json::Value& json, metric_limits::cref_sptr_t ml):
	m_pid(json["pid"].asInt()),
	m_name(json["name"].asString()),
	m_total_metrics(0)
{
	for(const auto& bean : json["beans"])
	{
		java_bean jb = java_bean(bean, ml);
		m_total_metrics += jb.total_metrics();
		if(jb.attribute_count())
		{
			m_beans.push_back(move(jb));
		}
	}
}

unsigned int java_process::to_protobuf(draiosproto::java_info *protobuf, unsigned sampling, unsigned limit, const std::string& limit_type, unsigned max_limit) const
{
	if(protobuf)
	{
		protobuf->set_process_name(m_name);
	}
	unsigned emitted_attributes = 0;
	for(auto bean_it = m_beans.cbegin(); bean_it != m_beans.cend(); ++bean_it)
	{
		if(protobuf && (limit > emitted_attributes))
		{
			draiosproto::jmx_bean* protobean = protobuf->add_beans();
			emitted_attributes += bean_it->to_protobuf(protobean, sampling, limit-emitted_attributes, limit_type, max_limit);
		}
		else if(metric_limits::log_enabled())
		{
			bean_it->to_protobuf(nullptr, 0, max_limit, limit_type, max_limit);
		}
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
	string args;
	bool take_next_arg = false;
	for(const auto& arg : tinfo->m_args) {
		// Do a gross filtering of args
		if((arg.find("-D") == 0 && arg.find("jmx") != string::npos && arg.size() < MAX_ARG_SIZE) ||
		   (arg.find("UsePerfData") != string::npos) ||
		   (take_next_arg == true))
		{
			args_json.append(take_next_arg ? "-jar:" + arg : arg);
			args += arg + " ";
			take_next_arg =  false;
		}
		else if(arg == "-jar")
		{
			take_next_arg = true;
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
			args += *it;
			break;
		}
	}
	ret["args"] = args_json;

	g_logger.format(sinsp_logger::SEV_DEBUG, "Adding process for JMX getMetrics command: "
					"pid: %" PRIu64 " vpid: %" PRIu64 " root: %s args: %s", tinfo->m_pid,
					tinfo->m_vpid, tinfo->m_root.c_str(), args.c_str());
	return ret;
}

void jmx_proxy::send_get_metrics(const vector<sinsp_threadinfo*>& processes)
{
	Json::Value command_obj;
	command_obj["command"] = "getMetrics";
	Json::Value body(Json::arrayValue);

	g_logger.log("Generating JMX getMetrics command", sinsp_logger::SEV_DEBUG);
	unsigned tinfo_count = 0;
	for(auto tinfo : processes)
	{
		Json::Value tinfo_json = tinfo_to_json(tinfo);
		body.append(tinfo_json);
		++tinfo_count;
	}
	command_obj["body"] = body;
	string command_data = m_json_writer.write(command_obj);
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending JMX getMetrics command for %u "
					"processes, command size %u bytes", tinfo_count, command_data.size());

	m_outqueue.send(command_data);
}


unordered_map<int, java_process> jmx_proxy::read_metrics(metric_limits::cref_sptr_t ml)
{
	process_map_t processes;
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
		g_logger.format(sinsp_logger::SEV_ERROR, "jmx_proxy::read_metrics error: %s", ex.what());
	}
	return processes;
}

#endif // _WIN32
