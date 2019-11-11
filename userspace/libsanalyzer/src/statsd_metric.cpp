/**
 * @file
 *
 * Implementation of statsd_metric.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#include "statsd_metric.h"
#include "draios.pb.h"
#include "percentile.h"
#include "utils.h"
#include <string>
#include <sstream>

statsd_metric::statsd_metric():
	m_timestamp(0),
	m_name(),
	m_tags(),
	m_container_id(),
	m_type(type_t::NONE),
	m_full_identifier_parsed(false),
	m_value(0.0),
	m_sum(0.0),
	m_mean(0.0),
	m_min(0.0),
	m_max(0.0),
	m_count(0.0),
	m_stdev(0.0),
	m_percentiles()
{ }

bool statsd_metric::parse_line(const std::string& line)
{
	// WARNING: Parsing is not so optimized, because if it will result
	// a bottleneck, a better option is to use statsite binary based
	// output, or write a protobuf output for it

	// Example:
	// counts.mycounter#xxx,yy|313.000000|1427738072
	// timers.mytime.upper|199.000000|1427738072
	// <type>.[<containerid>$]<name>[#<tags>].<subvaluetype>|<value>|<timestamp>
	try
	{
		using str_vector = std::vector<std::string>;

		const str_vector line_tokens = sinsp_split(line, '|');

		// parse timestamp
		const uint64_t timestamp = std::stoul(line_tokens.at(2));
		if(m_full_identifier_parsed && m_timestamp != timestamp)
		{
			return false;
		}
		m_timestamp = timestamp;

		const str_vector name_tokens = sinsp_split(line_tokens.at(0), '.');

		// Parse type
		const std::string& type_s = name_tokens.at(0);
		type_t new_type = type_t::NONE;

		if(type_s == "counts")
		{
			new_type = type_t::COUNT;
		}
		else if(type_s == "timers")
		{
			new_type = type_t::HISTOGRAM;
		}
		else if(type_s == "gauges")
		{
			new_type = type_t::GAUGE;
		}
		else if(type_s == "sets")
		{
			new_type = type_t::SET;
		}

		if(m_full_identifier_parsed && m_type != new_type)
		{
			return false;
		}
		m_type = new_type;

		// parse name
		auto name_start = name_tokens.begin() + 1;
		auto name_end = name_tokens.end();

		if(m_type == type_t::HISTOGRAM)
		{
			--name_end;
		}

		const auto name_and_tags = sinsp_join(name_start, name_end, '.');
		const auto name_and_tags_tokens = sinsp_split(name_and_tags, '#');
		const auto& name_and_container_id = name_and_tags_tokens.at(0);
		const auto name_and_container_id_split = sinsp_split(name_and_container_id,
		                                                     CONTAINER_ID_SEPARATOR);

		if(name_and_container_id_split.size() > 1)
		{
			const auto& name = name_and_container_id_split.at(1);
			if(m_full_identifier_parsed && m_name != name)
			{
				return false;
			}
			m_name = name;

			auto container_id = desanitize_container_id(name_and_container_id_split.at(0));
			if(m_full_identifier_parsed && m_container_id != container_id)
			{
				return false;
			}
			m_container_id = std::move(container_id);
		}
		else
		{
			const auto& name = name_and_container_id;
			if(m_full_identifier_parsed && m_name != name)
			{
				return false;
			}
			m_name = name;

			if(m_full_identifier_parsed && !m_container_id.empty())
			{
				return false;
			}
		}

		if(name_and_tags_tokens.size() > 1)
		{
			decltype(m_tags) new_tags;
			const auto tags_tokens = sinsp_split(name_and_tags_tokens.at(1), ',');

			for(const auto& tag : tags_tokens)
			{
				auto keyvalues = sinsp_split(tag, ':');
				if(keyvalues.size() > 1)
				{
					new_tags[keyvalues.at(0)] = keyvalues.at(1);
				}
				else
				{
					keyvalues = sinsp_split(tag, '=');
					if(keyvalues.size() > 1 ){
						new_tags[keyvalues.at(0)] = keyvalues.at(1);
					}
					else
					{
						new_tags[keyvalues.at(0)] = "";
					}
				}
			}
			if(m_full_identifier_parsed && m_tags != new_tags)
			{
				return false;
			}
			m_tags = move(new_tags);
		}

		m_full_identifier_parsed = true;

		// Parse value
		const double value = std::stod(line_tokens.at(1));
		if(m_type == type_t::HISTOGRAM)
		{
			const std::string& subtype = name_tokens.back();

			if(subtype == "sum")
			{
				m_sum = value;
			}
			else if(subtype == "mean")
			{
				m_mean = value;
			}
			else if(subtype == "lower")
			{
				m_min = value;
			}
			else if(subtype == "upper")
			{
				m_max = value;
			}
			else if(subtype == "count")
			{
				m_count = value;
			}
			else if(subtype == "stdev")
			{
				m_stdev = value;
			}
			else if(subtype.size() > 1 && subtype[0] == 'p') // percentiles
			{
				long percentile = strtol(&subtype.c_str()[1], nullptr, 10);
				if(0L != percentile)
				{
					m_percentiles[percentile] = value;
				}
			}
			// Skipping "rate" and "sample_rate" right now
		}
		else
		{
			m_value = value;
		}

		return true;
	}
	catch(const std::exception& ex)
	{
		// A lot of exceptions can arise from the parsing; vector
		// indexing, double conversion and so on so catch them and map
		// as parsing exception
		throw parse_exception(ex.what());
	}
}

void statsd_metric::to_protobuf(draiosproto::statsd_metric* const proto) const
{
	ASSERT(m_type != type_t::NONE);

	proto->set_name(m_name);

	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if(!tag.second.empty())
		{
			tag_proto->set_value(tag.second);
		}
	}

	proto->set_type(static_cast<draiosproto::statsd_metric_type>(m_type));
	if(m_type == type_t::HISTOGRAM)
	{
		proto->set_sum(m_sum);
		proto->set_min(m_min);
		proto->set_max(m_max);
		proto->set_count(m_count);

		using CTB = draiosproto::statsd_metric;
		using CP = draiosproto::counter_percentile;

		percentile::to_protobuf<CTB, CP>(m_percentiles,
		                                 proto,
		                                 &CTB::add_percentile);
	}
	else
	{
		proto->set_value(m_value);
	}
}

std::string statsd_metric::sanitize_container_id(std::string container_id)
{
	// Unfortunately rkt container id have `:` char, which is a reserved
	// char in statsd protocol.  As a workaround we translate it to another
	// char
	ASSERT(container_id.find('+') == std::string::npos);
	replace(container_id.begin(), container_id.end(), ':', '+');

	return container_id;
}

std::string statsd_metric::desanitize_container_id(std::string container_id)
{
	// rkt container id has a ':' char that we have translated to "+"
	// because its reserved in statsd protocol, here we put it back to ":"
	replace(container_id.begin(), container_id.end(), '+', ':');

	return container_id;
}

std::string statsd_metric::type_to_string(const statsd_metric::type_t type)
{
	switch(type)
	{
	case statsd_metric::type_t::NONE:
		return "NONE";

	case statsd_metric::type_t::COUNT:
		return "COUNT";

	case statsd_metric::type_t::HISTOGRAM:
		return "HISTOGRAM";

	case statsd_metric::type_t::GAUGE:
		return "GAUGE";

	case statsd_metric::type_t::SET:
		return "SET";
	}

	return "??";
}

uint64_t statsd_metric::timestamp() const
{
	return m_timestamp;
}

const std::string& statsd_metric::name() const
{
	return m_name;
}

const std::string& statsd_metric::container_id() const
{
	return m_container_id;
}

statsd_metric::type_t statsd_metric::type() const
{
	return m_type;
}

double statsd_metric::value() const
{
	return m_value;
}

double statsd_metric::sum() const
{
	return m_sum;
}

double statsd_metric::mean() const
{
	return m_mean;
}

double statsd_metric::min() const
{
	return m_min;
}

double statsd_metric::max() const
{
	return m_max;
}

double statsd_metric::count() const
{
	return m_count;
}

double statsd_metric::stdev() const
{
	return m_stdev;
}

double statsd_metric::percentile(const int index) const
{
	auto i = m_percentiles.find(index);

	if(i == m_percentiles.end())
	{
		return 0.0;
	}

	return i->second;
}

bool statsd_metric::percentile(const int pct, double& val)
{
	auto it = m_percentiles.find(pct);
	if(it != m_percentiles.end())
	{
		val = it->second;
		return true;
	}
	return false;
}
const std::map<std::string, std::string>& statsd_metric::tags() const
{
	return m_tags;
}

std::string statsd_metric::to_debug_string() const
{
	std::stringstream out;

	out << "-- statsd metric --------------------------------" << std::endl;
	out << "timestamp:      " << m_timestamp            << std::endl;
	out << "name:           " << m_name                 << std::endl;
	out << "container_id:   " << m_container_id         << std::endl;
	out << "type:           " << type_to_string(m_type) << std::endl;
	out << "full id parsed: " << (m_full_identifier_parsed ? "true" : "false") << std::endl;
	out << "value:          " << m_value                << std::endl;
	out << "sum:            " << m_sum                  << std::endl;
	out << "mean:           " << m_mean                 << std::endl;
	out << "min:            " << m_min                  << std::endl;
	out << "max:            " << m_max                  << std::endl;
	out << "count:          " << m_count                << std::endl;
	out << "stdev:          " << m_stdev                << std::endl;
	out << "tags: {" << std::endl;
	for(const auto& i : m_tags)
	{
		out << "  [" << i.first << ", " << i.second << "]" << std::endl;
	}
	out << "}" << std::endl;
	out << "percentiles: {" << std::endl;
	for(const auto& i : m_percentiles)
	{
		out << "  [" << i.first << ", " << i.second << "]" << std::endl;
	}
	out << "}" << std::endl;

	return out.str();
}

statsd_metric::parse_exception::parse_exception(const std::string& msg):
	std::runtime_error(msg)
{ }
