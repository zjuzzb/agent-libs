#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "third-party/jsoncpp/json/json.h"
#include <utility>

class jmx_proxy;
class java_process;

class java_bean {
public:

	inline const string& name() const
	{
		return m_name;
	}

	inline const map<string, double>& simple_attributes() const
	{
		return m_simple_attributes;
	}

	inline const map<string, map<string, double>>& nested_attributes() const
	{
		return m_nested_attributes;
	}

	void to_protobuf(draiosproto::jmx_bean *proto_bean) const;
private:
	explicit java_bean(const Json::Value&);
	string m_name;
	map<string, double> m_simple_attributes;
	map<string, map<string, double>> m_nested_attributes;
	friend class java_process;
};

class java_process {
public:
	inline int pid() const
	{
		return m_pid;
	}

	inline const string& name() const
	{
		return m_name;
	}

	inline const list<java_bean>& beans() const
	{
		return m_beans;
	}

	void to_protobuf(draiosproto::java_info* protobuf) const;

private:
	explicit java_process(const Json::Value&);
	int m_pid;
	string m_name;
	list<java_bean> m_beans;
	friend class jmx_proxy;
};

class jmx_proxy
{
public:
	jmx_proxy(const std::pair<FILE*, FILE*>& fds);

	void send_get_metrics();
	unordered_map<int, java_process> read_metrics();

private:
	// Input and output of the subprocess
	// so we'll write on input and read from
	// output
	FILE* m_input_fd;
	FILE* m_output_fd;
	Json::Reader m_json_reader;
};
