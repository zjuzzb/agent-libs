#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "jmx_proxy.h"

#ifndef _WIN32
#include <unistd.h>

#endif
#include "logger.h"
#include "fcntl.h"

java_bean_attribute::java_bean_attribute(const Json::Value& json):
	m_name(json["name"].asString()),
	m_unit(0),
	m_scale(0),
	m_type(0)
{
	if(json.isMember("alias"))
	{
		m_alias = json["alias"].asString();
	}
	if(json.isMember("unit"))
	{
		m_unit = json["unit"].asUInt();
	}
	if(json.isMember("scale"))
	{
		m_scale = json["scale"].asUInt();
	}
	if(json.isMember("type"))
	{
		m_type = json["type"].asUInt();
	}
	if (json.isMember("value"))
	{
		m_value = json["value"].asDouble();
	} else if (json.isMember("subattributes"))
	{
		for(const auto& subattribute : json["subattributes"])
		{
			m_subattributes.emplace_back(subattribute);
		}
	}
}

void java_bean_attribute::to_protobuf(draiosproto::jmx_attribute *attribute) const
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
		attribute->set_value(m_value);
	}
	else
	{
		for(const auto& subattribute : m_subattributes)
		{
			draiosproto::jmx_attribute* subattribute_proto = attribute->add_subattributes();
			subattribute.to_protobuf(subattribute_proto);
		}
	}
}

java_bean::java_bean(const Json::Value& json):
	m_name(json["name"].asString())
{
	for(auto attribute : json["attributes"])
	{
		m_attributes.emplace_back(attribute);
	}
}

void java_bean::to_protobuf(draiosproto::jmx_bean *proto_bean) const
{
	proto_bean->mutable_name()->assign(m_name);
	for(const auto& attribute : m_attributes)
	{
		draiosproto::jmx_attribute* attribute_proto = proto_bean->add_attributes();
		attribute.to_protobuf(attribute_proto);
	}
}

java_process::java_process(const Json::Value& json):
	m_pid(json["pid"].asInt()),
	m_name(json["name"].asString())
{
	for(const auto& bean : json["beans"])
	{
		m_beans.push_back(java_bean(bean));
	}
}

void java_process::to_protobuf(draiosproto::java_info *protobuf) const
{
	protobuf->set_process_name(m_name);
	for(const auto& bean : m_beans)
	{
		draiosproto::jmx_bean* protobean = protobuf->add_beans();
		bean.to_protobuf(protobean);
	}
}

jmx_proxy::jmx_proxy(const std::pair<FILE*, FILE*>& fds):
		m_print_json(false),
		m_input_fd(fds.first),
		m_output_fd(fds.second)
{
}

Json::Value java_process_request::to_json() const
{
	Json::Value ret;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	return ret;
}

void jmx_proxy::send_get_metrics(uint64_t id, const vector<java_process_request>& processes)
{
	Json::Value command_obj;
	command_obj["id"] = Json::UInt64(id);
	command_obj["command"] = "getMetrics";
	Json::Value body(Json::arrayValue);
	for(const auto& process : processes)
	{
		body.append(process.to_json());
	}
	command_obj["body"] = body;
	string command_data = m_json_writer.write(command_obj);
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending get metric command to JMX: %s", command_data.c_str());
	fprintf(m_input_fd, "%s", command_data.c_str());
	fflush(m_input_fd);
}

pair<uint64_t, unordered_map<int, java_process>> jmx_proxy::read_metrics()
{
	uint64_t response_id = 0;
	unordered_map<int, java_process> processes;

	string json_data;
	static const int READ_BUFFER_SIZE = 1024;
	char buffer[READ_BUFFER_SIZE] = "";
	char* fgets_res = fgets_unlocked(buffer, READ_BUFFER_SIZE, m_output_fd);
	while (fgets_res != NULL && strstr(buffer, "\n") == NULL)
	{
		json_data.append(buffer);
		buffer[0] = '\0'; // Consume the buffer
		fgets_res = fgets_unlocked(buffer, READ_BUFFER_SIZE, m_output_fd);
	}
	json_data.append(buffer);

	if (json_data.size() > 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics json size is: %d", json_data.size());
		if(m_print_json) {
			g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics json: %s", json_data.c_str());
		}
		Json::Value json_obj;
		bool parse_ok = m_json_reader.parse(json_data, json_obj, false);
		if(parse_ok && json_obj.isObject() && json_obj.isMember("id") && json_obj.isMember("body"))
		{
			response_id = json_obj["id"].asUInt64();
			for(auto process_data : json_obj["body"])
			{
				java_process process(process_data);
				processes.insert(std::make_pair(process.pid(), process));
			}
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "Cannot deserialize JMX metrics");
		}
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics are not ready");
	}
	return make_pair(response_id, processes);
}
