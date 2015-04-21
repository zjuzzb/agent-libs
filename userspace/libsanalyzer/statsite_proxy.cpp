//
// Created by Luca Marturana on 30/03/15.
//
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "statsite_proxy.h"

/*
 * Parse a line and fill data structures
 * return false if line does not belong to this object
 * throws an exception if parsing fails
 */
bool statsd_metric::parse_line(const string& line)
{
	// Example:
	// counts.mycounter#xxx,yy|313.000000|1427738072
	// timers.mytime.upper|199.000000|1427738072
	// <type>.<name>[#<tags>].<subvaluetype>|<value>|<timestamp>
	try
	{
		const auto line_tokens = sinsp_split(line, '|');
		//ASSERT(line_tokens.size() == 3);

		// parse timestamp
		const auto timestamp = std::stoul(line_tokens.at(2));
		if (m_timestamp == 0)
		{
			m_timestamp = timestamp;
		}
		else if (m_timestamp != timestamp)
		{
			return false;
		}

		const auto name_tokens = sinsp_split(line_tokens.at(0), '.');

		// Parse type
		const auto& type_s = name_tokens.at(0);
		type_t new_type = type_t::NONE;
		if (type_s == "counts")
		{
			new_type = type_t::COUNT;
		}
		else if (type_s == "timers")
		{
			new_type = type_t::HISTOGRAM;
		}
		else if (type_s == "gauges")
		{
			new_type = type_t::GAUGE;
		}
		else if (type_s == "sets")
		{
			new_type = type_t::SET;
		}
		//ASSERT(new_type != type_t::NONE);

		if(m_type == type_t::NONE)
		{
			m_type = new_type;
		}
		else if(m_type != new_type)
		{
			return false;
		}
		//ASSERT(m_type != type_t::NONE);

		// parse name
		auto name_start = name_tokens.begin()+1;
		auto name_end = name_tokens.end();
		if(m_type == type_t::HISTOGRAM)
		{
			--name_end;
		}

		const auto name_and_tags = sinsp_join(name_start, name_end, '.');
		const auto name_and_tags_tokens = sinsp_split(name_and_tags, '#');
		const auto& name = name_and_tags_tokens.at(0);

		if (m_name.empty())
		{
			m_name = name;
		}
		else if (m_name != name)
		{
			return false;
		}

		if (name_and_tags_tokens.size() > 1)
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
			if(m_tags.empty())
			{
				m_tags = move(new_tags);
			}
			else if(new_tags != m_tags)
			{
				return false;
			}
		}

		// Parse value
		const auto value = std::stod(line_tokens.at(1));
		if(m_type == type_t::HISTOGRAM)
		{
			const auto& subtype = name_tokens.back();
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
			else if(subtype == "median")
			{
				m_median = value;
			}
			else if(subtype == "p95")
			{
				m_percentile_95 = value;
			}
			else if(subtype == "p99")
			{
				m_percentile_99 = value;
			}
			else if(subtype == "p100")
			{
				m_percentile_999 = value;
			}
			// Skipping "rate" and "sample_rate" right now
		}
		else
		{
			m_value = value;
		}
		return true;
	} catch(const std::exception& ex)
	{
		// A lot of exceptions can arise from the parsing;
		// vector indexing, double conversion and so on
		// so catch them and map as parsing exception
		throw parse_exception(ex.what());
	}
}

void statsd_metric::to_protobuf(draiosproto::statsd_metric *proto)
{
	ASSERT(m_type != type_t::NONE);

	proto->set_name(m_name);
	for(const auto& tag : m_tags)
	{
		auto tag_proto = proto->add_tags();
		tag_proto->set_key(tag.first);
		if (!tag.second.empty())
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
		proto->set_median(m_median);
		proto->set_percentile_95(m_percentile_95);
		proto->set_percentile_99(m_percentile_99);
		proto->set_percentile_999(m_percentile_999);
	}
	else
	{
		proto->set_value(m_value);
	}
}

statsite_proxy::statsite_proxy(pair<FILE*, FILE*> const &fds):
		m_input_fd(fds.first),
		m_output_fd(fds.second),
		m_metric(statsd_metric::create())
{
}

vector<statsd_metric::ptr_t> statsite_proxy::read_metrics()
{
	vector<statsd_metric::ptr_t> ret;
	uint64_t timestamp = 0;
	char buffer[300];

	bool continue_read = (fgets_unlocked(buffer, sizeof(buffer), m_output_fd) != NULL);
	while (continue_read)
	{
		try {
			bool parsed = m_metric->parse_line(buffer);
			if(!parsed)
			{
				if(timestamp == 0)
				{
					timestamp = m_metric->timestamp();
				}

				ret.push_back(m_metric);
				m_metric = statsd_metric::create();

				parsed = m_metric->parse_line(buffer);
				ASSERT(parsed == true);
				if(timestamp < m_metric->timestamp())
				{
					break;
				}
			}
		}
		catch(const statsd_metric::parse_exception& ex)
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "parser exception on statsd, buffer: %s", buffer);
		}

		continue_read = (fgets_unlocked(buffer, sizeof(buffer), m_output_fd) != NULL);
	}
	if(timestamp > 0 && timestamp == m_metric->timestamp())
	{
		g_logger.log("statsite_proxy, Adding last sample", sinsp_logger::SEV_DEBUG);
		ret.push_back(m_metric);
		m_metric = statsd_metric::create();
	}
	g_logger.format(sinsp_logger::SEV_DEBUG, "statsite_proxy, Vector size is: %d", ret.size());
	g_logger.format(sinsp_logger::SEV_DEBUG, "statsite_proxy, m_metric timestamp is: %lu, vector timestamp: %lu", m_metric->timestamp(), ret.size() > 0 ? ret.at(0)->timestamp() : 0);
	g_logger.format(sinsp_logger::SEV_DEBUG, "statsite_proxy, m_metric name is: %s", m_metric->name().c_str());
	return ret;
}