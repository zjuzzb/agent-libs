//
// Created by Luca Marturana on 30/03/15.
//
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "statsite_proxy.h"

bool statsd_metric::parse_line(const string& line)
{
	// Example:
	// counts.mycounter#xxx,yy|313.000000|1427738072
	// timers.mytime.upper|199.000000|1427738072
	// <type>.<name>[#<tags>].<subvaluetype>|<value>|<timestamp>

	// parse timestamp
	auto timestamp_s = line.substr(line.find_last_of('|'), string::npos);
	auto timestamp = std::stoul(timestamp_s);
	if (m_timestamp == 0)
	{
		m_timestamp = timestamp;
	}

	if (m_timestamp != timestamp)
	{
		return false;
	}

	// parse name
	auto type_end = line.find_first_of('.');
	auto name_and_tags = line.substr(type_end, type_end+line.find_last_of('.'));
	auto dash_pos = name_and_tags.find_last_of('#');
	string name;
	if (dash_pos < string::npos)
	{
		name = line.substr(type_end, dash_pos);
		// TODO: parse tags
	}
	else
	{
		name = name_and_tags;
	}

	if (m_name.empty())
	{
		m_name = name;
	}
	if (m_name != name)
	{
		return false;
	}

	auto type_s = line.substr(0, type_end);
	if (type_s == "counts")
	{
		m_type = type_t::COUNT;
	}
	else if (type_s == "timers")
	{
		m_type = type_t::HISTOGRAM;
	}
	else if (type_s == "gauges")
	{
		m_type = type_t::GAUGE;
	}
	else if (type_s == "sets")
	{
		m_type = type_t::SET;
	}
}

statsite_proxy::statsite_proxy(pair<FILE*, FILE*> const &fds):
		m_input_fd(fds.first),
		m_output_fd(fds.second)
{
	m_buffer[0] = '\0';
}

vector<statsd_metric::ptr_t> statsite_proxy::read_metrics()
{
	vector<statsd_metric::ptr_t> ret;
	auto metric = statsd_metric::create();
	uint64_t timestamp = 0;
	bool continue_read = true;
	if (m_buffer[0] == '\0')
	{
		continue_read = fgets(m_buffer, READ_BUFFER_SIZE, m_output_fd) != NULL;
	}
	while (continue_read)
	{
		bool parsed = metric->parse_line(m_buffer);
		if (parsed)
		{
			m_buffer[0] = '\0';
		}
		else
		{
			if (timestamp == 0)
			{
				timestamp = metric->timestamp();
			}
			ret.push_back(metric);

			metric = statsd_metric::create();
			metric->parse_line(m_buffer);
			if (timestamp < metric->timestamp())
			{
				break;
			}
		}
		continue_read = fgets(m_buffer, READ_BUFFER_SIZE, m_output_fd) != NULL;
	}
	return ret;
}