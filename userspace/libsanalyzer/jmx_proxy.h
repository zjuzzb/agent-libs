#pragma once

#ifndef _WIN32
#include "third-party/jsoncpp/json/json.h"
#include <utility>
#include "threadinfo.h"

class jmx_proxy;
class java_process;
class java_bean;

class java_bean_attribute
{
public:
	void to_protobuf(draiosproto::jmx_attribute *attribute) const;
	explicit java_bean_attribute(const Json::Value&);
private:
	string m_name;
	string m_alias;
	double m_value;
	uint16_t m_unit;
	uint16_t m_scale;
	uint16_t m_type;
	vector<java_bean_attribute> m_subattributes;
};

class java_bean {
public:

	inline const string& name() const
	{
		return m_name;
	}

	void to_protobuf(draiosproto::jmx_bean *proto_bean) const;
private:
	explicit java_bean(const Json::Value&);
	string m_name;
	vector<java_bean_attribute> m_attributes;
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

class java_process_request
{
public:
	explicit java_process_request(sinsp_threadinfo* tinfo):
		m_pid(tinfo->m_pid),
		m_vpid(tinfo->m_vpid)
	{

	}
	inline Json::Value to_json() const;
private:
	int m_pid;
	int m_vpid;
};

class jmx_proxy
{
public:
	jmx_proxy(const std::pair<FILE*, FILE*>& fds);

	void send_get_metrics(uint64_t id, const vector<java_process_request>& processes);

	pair<uint64_t, unordered_map<int, java_process>> read_metrics();

	// This attribute is public because is simply a switch to print
	// JSON on stdout, does not change object behaviour
	bool m_print_json;
private:
	// Input and output of the subprocess
	// so we'll write on input and read from
	// output
	FILE* m_input_fd;
	FILE* m_output_fd;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};

#endif // _WIN32