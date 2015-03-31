//
// Created by Luca Marturana on 30/03/15.
//

#pragma once

class statsite_proxy;
class statsd_metric
{
public:
	using ptr_t = shared_ptr<statsd_metric>;
	enum class type_t
	{
	NONE, COUNT, HISTOGRAM, GAUGE, SET
	};

	void to_protobuf(draiosproto::statsd_metric* proto);

	bool parse_line(const string& line);

	static inline ptr_t create()
	{
		return ptr_t(new statsd_metric());
	}

	inline uint64_t timestamp()
	{
		return m_timestamp;
	}

private:
	statsd_metric() = default;

	uint64_t m_timestamp{0};
	string m_name;
	map<string, string> m_tags;
	type_t m_type{type_t::NONE};

	double m_value;

	double m_sum;
	double m_sum_squared;
	double m_mean;
	double m_min;
	double m_max;
	double m_count;
	double m_stdev;
	double m_median;
	double m_percentile_50;
	double m_percentile_95;
	double m_percentile_99;
};

class statsite_proxy
{
public:
	statsite_proxy(const pair<FILE*, FILE*>& pipes);
	vector<statsd_metric::ptr_t> read_metrics();
private:
	FILE* m_input_fd;
	FILE* m_output_fd;
	static const uint32_t READ_BUFFER_SIZE = 200;
	char m_buffer[READ_BUFFER_SIZE];
};
