#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "jmx_proxy.h"

#include <unistd.h>
#include "logger.h"
#include "fcntl.h"


java_bean::java_bean(const Json::Value& json):
	m_name(json["name"].asString())
{
	const Json::Value& attributes_obj = json["attributes"];
	for(auto attribute_name : attributes_obj.getMemberNames())
	{
		const Json::Value & attribute_obj = attributes_obj[attribute_name];
		if (attribute_obj.isDouble())
		{
			m_simple_attributes[attribute_name] = attribute_obj.asDouble();
		}
		else
		{
			map<string, double> subattributes;
			for(auto subattribute_name : attribute_obj.getMemberNames())
			{
				subattributes[subattribute_name] = attribute_obj[subattribute_name].asDouble();
			}
			m_nested_attributes[attribute_name] = subattributes;
		}
	}
}

void java_bean::to_protobuf(draiosproto::jmx_bean *proto_bean) const
{
	proto_bean->mutable_name()->assign(m_name);
	for(auto simple_attribute : m_simple_attributes)
	{
		draiosproto::jmx_attribute* proto_attribute = proto_bean->add_attributes();
		proto_attribute->set_name(simple_attribute.first);
		proto_attribute->set_value(simple_attribute.second);
	}
	for(auto nested_attribute : m_nested_attributes)
	{
		draiosproto::jmx_attribute* proto_attribute = proto_bean->add_attributes();
		proto_attribute->set_name(nested_attribute.first);
		for(auto subattribute : nested_attribute.second)
		{
			draiosproto::jmx_attribute* proto_subattribute = proto_attribute->add_subattributes();
			proto_subattribute->set_name(subattribute.first);
			proto_subattribute->set_value(subattribute.second);
		}
	}
}

java_process::java_process(const Json::Value& json):
	m_pid(json["pid"].asInt()),
	m_name(json["name"].asString())
{
	for(auto bean : json["beans"])
	{
		m_beans.push_back(java_bean(bean));
	}
}

void java_process::to_protobuf(draiosproto::java_info *protobuf) const
{
	protobuf->set_process_name(m_name);
	for(auto bean : m_beans)
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

void jmx_proxy::send_get_metrics(uint64_t id)
{
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending get metric command to JMX with id %u", id);
	Json::Value command_obj;
	command_obj["id"] = Json::UInt64(id);
	command_obj["command"] = "getMetrics";
	string command_data = m_json_writer.write(command_obj);
	fprintf(m_input_fd, "%s", command_data.c_str());
	fflush(m_input_fd);
}

pair<uint64_t, unordered_map<int, java_process> > jmx_proxy::read_metrics()
{
	uint64_t response_id = 0;
	unordered_map<int, java_process> processes;
	// Select call
//	int output_fd_int = fileno(m_output_fd);
//	fd_set readset;
//	FD_ZERO(&readset);
//	FD_SET(output_fd_int, &readset);
//	struct timeval timeout;
//	memset(&timeout, 0, sizeof(struct timeval));
//	int result = select(output_fd_int+1, &readset, NULL, NULL, &timeout);
	string json_data;
	char buffer[READ_BUFFER_SIZE] = "";
	char* fgets_res = fgets(buffer, READ_BUFFER_SIZE, m_output_fd);
	while (fgets_res != NULL && strstr(buffer, "\n") == NULL)
	{
		json_data.append(buffer);
		buffer[0] = '\0'; // Consume the buffer
		fgets_res = fgets(buffer, READ_BUFFER_SIZE, m_output_fd);
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
		if(parse_ok)
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
