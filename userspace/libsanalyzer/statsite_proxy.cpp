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
	auto timestamp_s = line.substr(line.find_last_of('|')+1, string::npos);
	auto timestamp = std::stoul(timestamp_s);
	if (m_timestamp == 0)
	{
		m_timestamp = timestamp;
	}
	else if (m_timestamp != timestamp)
	{
		return false;
	}

	// parse name
	auto type_end = line.find_first_of('.');
	auto name_and_tags_end = line.find_first_of('|')-1;
	auto optional_dot_for_subaggregation = line.find_last_of('.',name_and_tags_end);
	if (optional_dot_for_subaggregation != string::npos &&
			optional_dot_for_subaggregation > type_end)
	{
		name_and_tags_end = optional_dot_for_subaggregation-1;
	}
	auto name_and_tags = line.substr(type_end+1, name_and_tags_end-type_end);
	auto dash_pos = name_and_tags.find_last_of('#');
	string name;
	if (dash_pos != string::npos)
	{
		name = name_and_tags.substr(0, dash_pos);
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
	else if (m_name != name)
	{
		return false;
	}

	// Parse type
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

	// Parse value
	return true;
}

void statsd_metric::to_protobuf(draiosproto::statsd_metric *proto)
{
	proto->set_name(m_name);
	for(auto tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if (!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
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