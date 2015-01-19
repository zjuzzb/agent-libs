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

java_process::java_process(const Json::Value& json):
	m_pid(json["pid"].asInt()),
	m_name(json["name"].asString())
{
	for(auto bean : json["beans"])
	{
		m_beans.push_back(java_bean(bean));
	}
}
jmx_proxy::jmx_proxy(const std::pair<FILE*, FILE*>& fds):
	m_input_fd(fds.first),
	m_output_fd(fds.second)
{
}

void jmx_proxy::send_get_metrics()
{
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending get metric command to JMX");
	fprintf(m_input_fd, "getMetrics\n");
	fflush(m_input_fd);
}

unordered_map<int, java_process> jmx_proxy::read_metrics()
{
	unordered_map<int, java_process> processes;
	int output_fd_int = fileno(m_output_fd);
	fd_set readset;
	FD_ZERO(&readset);
	FD_SET(output_fd_int, &readset);
	struct timeval timeout;
	memset(&timeout, 0, sizeof(struct timeval));
	int result = select(output_fd_int+1, &readset, NULL, NULL, &timeout);
	if (result > 0)
	{
		char buffer[2048];
		fgets(buffer, 2048, m_output_fd);
		g_logger.format(sinsp_logger::SEV_DEBUG, "Received JMX metrics: %s", buffer);
		Json::Value json;
		m_json_reader.parse(buffer, buffer+2048, json, false);
		for(auto process_data : json)
		{
			java_process process(process_data);
			processes.insert(std::make_pair(process.pid(), process));
		}
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics are not ready");
	}
	return processes;
}
