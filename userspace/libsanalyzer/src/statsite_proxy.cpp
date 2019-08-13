/**
 * @file
 *
 * Implementation of statsite_proxy.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#include "common_logger.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "statsite_proxy.h"
#include "statsd_logger.h"
#include "subprocess.h"
#include "type_config.h"
#include <algorithm>
#include <Poco/Net/NetException.h>
#include <Poco/Thread.h>

namespace
{

COMMON_LOGGER();

type_config<uint64_t> config_buffer_warning_length(
		512,
		"limit to how long a single entry from statsite is before we log a warning",
		"statsite_buffer_warning_length");

} // end namespace


// Breaking down this regex:
//
// start sentinel and open group for each line: ^(
// match all characters except :, |, and newline one or more times: [^:|\\n]+
// colon: [:]
// same stuff as before: [^:|\\n]+
// pipe: [|]
// same stuff as before: [^:|\\n]+
// optional pipe followed by some stuff: ([|][^:|\\n]+)?
// newline: \\n
// close the line group and repeat: )*
//
// then we have the last line, which is the same except with a ? to indicate the optional concluding newline:
// [^:|\\n]+[:][^:|\\n]+[|][^:|\\n]+\\n?
//
// ending sentinel: $
const std::string statsite_proxy::stats_validator_regex = "^([^:|\\n]+[:][^:|\\n]+[|][^:|\\n]+([|][^:|\\n]+)?\\n)*[^:|\\n]+[:][^:|\\n]+[|][^:|\\n]+([|][^:|\\n]+)?\\n?$";
Poco::RegularExpression statsite_proxy::m_statsd_regex(statsite_proxy::stats_validator_regex);

statsite_proxy::statsite_proxy(std::pair<FILE*, FILE*> const &fds,
			       const bool check_format):
	m_input_fd(fds.first),
	m_output_fd(fds.second),
	m_check_format(check_format)
{
}

statsd_stats_source::container_statsd_map statsite_proxy::read_metrics(
		metric_limits::cref_sptr_t ml)
{
	// Sample data from statsite
	// counts.statsd.test.1|1.000000|1441746724
	// counts.statsd.test.1|1.000000|1441746725
	// counts.statsd.test.1|1.000000|1441746726
	// The logic is a bit complicated here, there are two main problems to address:
	// 1. bunch of metrics with different timestamps are not separated by each other
	// 2. more lines sometimes are parsed to a single metric (eg. histograms)

	statsd_stats_source::container_statsd_map ret;
	uint64_t timestamp = 0;
	unsigned metric_count = 0;
	const std::size_t DEFAULT_BUFFER_SIZE = 300;

	if(m_output_fd)
	{
		bool continue_loop = true;
		while(continue_loop)
		{
			std::vector<char> dyn_buffer(DEFAULT_BUFFER_SIZE);
			char *read_buffer = &dyn_buffer[0];

			if(!fgets_unlocked(read_buffer, DEFAULT_BUFFER_SIZE, m_output_fd))
			{
				break;
			}

			// if the line is longer than the buffer, the following 2 things will be true
			// 1) the last character will be a \0
			// 2) the second to last character will be neither \0 NOR \n
			while(dyn_buffer[dyn_buffer.size() - 2] != '\0' && dyn_buffer[dyn_buffer.size() - 2] != '\n')
			{
				// if we've exceeded our configured buffer size, log it
				if(dyn_buffer.size() >= config_buffer_warning_length.get())
				{
					LOG_ERROR("Trace longer than warning size: %s",
					          &dyn_buffer[0]);
				}

				// we have to grow the buffer. So grow it by the default buffer
				// size, then point the char buffer to where the null terminator
				// previously appeared, since that's where we want to start reading
				dyn_buffer.resize(dyn_buffer.size() + DEFAULT_BUFFER_SIZE);
				read_buffer = &dyn_buffer[dyn_buffer.size() - DEFAULT_BUFFER_SIZE - 1];

				// note have to read 1 extra character since we have the null
				// terminator from the previous read we're going to overwrite
				if(!fgets_unlocked(read_buffer, DEFAULT_BUFFER_SIZE + 1, m_output_fd))
				{
					continue_loop = false;

					if(ferror(m_output_fd))
					{
						// have some data, but read failed. can't
						// reliably parse, so bail
						goto BREAK_LOOP;
					}
					else
					{
						// still have data in buffer to parse
						break;
					}
				}

			}

			// parsing code takes a char*, so just initialize one here and use it
			// Probably should split this function into read/parse halves at some
			// point. -zipper 1/7/19
			char *buffer = &dyn_buffer[0];

			LOG_TRACE("Received from statsite: %s", buffer);
			STATSD_LOG("Received from statsite:\n%s", buffer);
			try {
				bool parsed = m_metric.parse_line(buffer);
				if(!parsed)
				{
					if(timestamp == 0)
					{
						timestamp = m_metric.timestamp();
					}

					if (ret.find(m_metric.container_id()) == ret.end())
						std::get<1>(ret[m_metric.container_id()]) = 0;
					++std::get<1>(ret[m_metric.container_id()]);

					std::string filter;
					if(ml)
					{
						// allow() will log if logging is enabled
						if(ml->allow(m_metric.name(),
							     filter,
							     nullptr,
							     "statsd"))
						{
							std::get<0>(ret[m_metric.container_id()]).push_back(std::move(m_metric));
							++metric_count;
						}
					}
					else // no filtering, add every metric and log explicitly
					{
						metric_limits::log(m_metric.name(),
								   "statsd",
								   true,
								   metric_limits::log_enabled(),
								   " ");
						std::get<0>(ret[m_metric.container_id()]).push_back(std::move(m_metric));
						++metric_count;
					}
					m_metric = statsd_metric();

					parsed = m_metric.parse_line(buffer);
					ASSERT(parsed == true);
					if(timestamp < m_metric.timestamp())
					{
						break;
					}
				}
			}
			catch(const statsd_metric::parse_exception& ex)
			{
				LOG_ERROR("Parser exception on statsd, buffer: %s",
				          buffer);
			}
		}


BREAK_LOOP:
		if(m_metric.timestamp() &&
		   (timestamp == 0 || timestamp == m_metric.timestamp()))
		{
			LOG_DEBUG("Adding last sample");

			std::string filter;
			++std::get<1>(ret[m_metric.container_id()]);

			if(ml)
			{
				// allow() will log if logging is enabled
				if(ml->allow(m_metric.name(), filter, nullptr, "statsd"))
				{
					std::get<0>(ret[m_metric.container_id()]).push_back(std::move(m_metric));
					++metric_count;
				}
			}
			else // otherwise, add indiscriminately and log explicitly
			{
				metric_limits::log(m_metric.name(),
						   "statsd",
						   true,
						   metric_limits::log_enabled(),
						   " ");
				std::get<0>(ret[m_metric.container_id()]).push_back(std::move(m_metric));
				++metric_count;
			}
			m_metric = statsd_metric();
		}

		LOG_DEBUG("Ret vector size is: %u", metric_count);
		STATSD_LOG("Ret vector size is: %u", metric_count);

		if(m_metric.timestamp() > 0)
		{
			LOG_DEBUG("m_metric timestamp is: %lu, vector timestamp: %lu",
			          m_metric.timestamp(),
			          ret.size() > 0 ? std::get<0>(ret.at("")).at(0).timestamp() : 0);
			LOG_DEBUG("m_metric name is: %s",
			          m_metric.name().c_str());
			STATSD_LOG("m_metric timestamp is: %lu, vector timestamp: %lu",
			          m_metric.timestamp(),
			          ret.size() > 0 ? std::get<0>(ret.at("")).at(0).timestamp() : 0);
			STATSD_LOG("m_metric name is: %s",
			          m_metric.name().c_str());
		}
	}
	else
	{
		LOG_ERROR("Cannot read metrics (file is null)");
	}
	return ret;
}

bool statsite_proxy::validate_buffer(const char* const buf, const uint64_t len)
{
	std::string string_buf(buf, len);

	return m_statsd_regex.match(string_buf);
}

void statsite_proxy::send_metric(const char* const buf, const uint64_t len)
{
	if(m_check_format && !validate_buffer(buf, len))
	{
		std::string string_buf(buf, len);

		LOG_ERROR("Invalid buffer format. Dropping. %s", string_buf.c_str());
		return;
	}

	if(buf && len && m_input_fd)
	{
		STATSD_LOG("Sending to statsite:\n%s", std::string(buf, len).c_str());

		fwrite_unlocked(buf, sizeof(char), len, m_input_fd);

		if(buf[len - 1] != '\n')
		{
			fputc_unlocked('\n', m_input_fd);
		}
		fflush_unlocked(m_input_fd);
	}
	else
	{
		LOG_ERROR("Cannot send metrics (file or buf is null)");
	}
}

void statsite_proxy::send_container_metric(const std::string &container_id,
                                           const char* const data,
                                           const uint64_t len)
{
	// Send the metric with containerid prefix
	// Prefix container metrics with containerid and $
	auto container_prefix =
		statsd_metric::sanitize_container_id(container_id) +
		statsd_metric::CONTAINER_ID_SEPARATOR;

	// Init metric data with initial container_prefix
	auto metric_data = container_prefix;
	metric_data.append(data, (size_t)len);

	// Add container prefix to other metrics if they are present
	auto endline_pos = metric_data.find('\n');
	while(endline_pos != std::string::npos && endline_pos+1 < metric_data.size())
	{
		metric_data.insert(endline_pos+1, container_prefix);
		endline_pos = metric_data.find('\n', endline_pos+1);
	}

	send_metric(metric_data.data(), metric_data.size());
}
