#pragma once

#ifndef _WIN32
#include "third-party/jsoncpp/json/json.h"
#include <utility>
#include "threadinfo.h"
#include "posix_queue.h"
#include "metric_limits.h"

class jmx_proxy;
class java_process;
class java_bean;

class java_bean_attribute
{
public:
	void to_protobuf(draiosproto::jmx_attribute *attribute, unsigned sampling) const;
	explicit java_bean_attribute(const Json::Value&);
	double value() { return m_value; }
private:
	inline bool check_member(const Json::Value& json, const std::string& name, Json::ValueType type)
	{
		return json.isMember(name) && json[name].isConvertibleTo(type);
	}
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
	java_bean(const Json::Value&, metric_limits::cref_sptr_t ml);

	inline const string& name() const
	{
		return m_name;
	}

	inline size_t attribute_count()
	{
		return m_attributes.size();
	}

	inline const vector<java_bean_attribute>& attributes() const
	{
		return m_attributes;
	}

	unsigned int to_protobuf(draiosproto::jmx_bean *proto_bean, unsigned sampling, unsigned limit) const;

private:
	string m_name;
	vector<java_bean_attribute> m_attributes;
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

	unsigned int to_protobuf(draiosproto::java_info *protobuf, unsigned sampling, unsigned limit) const;

private:
	java_process(const Json::Value&, metric_limits::cref_sptr_t ml);
	int m_pid;
	string m_name;
	list<java_bean> m_beans;
	friend class jmx_proxy;
};

class jmx_proxy
{
public:
	jmx_proxy();

	void send_get_metrics(const vector<sinsp_threadinfo*>& processes);

	unordered_map<int, java_process> read_metrics(metric_limits::cref_sptr_t ml = nullptr);

	// This attribute is public because is simply a switch to print
	// JSON on stdout, does not change object behaviour
	bool m_print_json;
private:
	static Json::Value tinfo_to_json(sinsp_threadinfo* tinfo);
	posix_queue m_outqueue;
	posix_queue m_inqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};

#endif // _WIN32