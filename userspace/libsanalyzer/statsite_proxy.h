//
// Created by Luca Marturana on 30/03/15.
//

#pragma once

class statsite_proxy;
namespace draiosproto
{
	class statsd_metric;
};

class statsd_metric
{
public:
#ifndef _WIN32
	class parse_exception: public sinsp_exception
	{
	public:
		template<typename... T>
		parse_exception(T&&... args):
				sinsp_exception(forward<T>(args)...)
		{}
	};
#endif
	enum class type_t
	{
	NONE=0, COUNT=1, HISTOGRAM=2, GAUGE=3, SET=4
	};

	void to_protobuf(draiosproto::statsd_metric* proto) const;

	bool parse_line(const string& line);

	inline uint64_t timestamp() const
	{
		return m_timestamp;
	}

	inline const string& name() const
	{
		return m_name;
	}

	inline const string& container_id() const
	{
		return m_container_id;
	}

	inline type_t type() const
	{
		return m_type;
	}

	inline double value() const
	{
		return m_value;
	}

	inline double sum() const
	{
		return m_sum;
	}

	inline double median() const
	{
		return m_median;
	}

	inline const map<string, string>& tags() const
	{
		return m_tags;
	}

	statsd_metric():
			m_timestamp(0),
			m_type(type_t::NONE),
			m_full_identifier_parsed(false)
	{}

	static const char CONTAINER_ID_SEPARATOR = '$';
private:
	uint64_t m_timestamp;
	string m_name;
	map<string, string> m_tags;
	string m_container_id;
	type_t m_type;
	bool m_full_identifier_parsed;

	double m_value;

	double m_sum;
	double m_mean;
	double m_min;
	double m_max;
	double m_count;
	double m_stdev;
	double m_median;
	double m_percentile_95;
	double m_percentile_99;

	friend class lua_cbacks;
};

class statsite_proxy
{
public:
	statsite_proxy(const pair<FILE*, FILE*>& pipes);
	unordered_map<string, vector<statsd_metric>> read_metrics();
	void send_metric(const char *buf, uint64_t len);
	void send_container_metric(const string& container_id, const char* data, uint64_t len);
private:
	FILE* m_input_fd;
	FILE* m_output_fd;
	statsd_metric m_metric;
};
