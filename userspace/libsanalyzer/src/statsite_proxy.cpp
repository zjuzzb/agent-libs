#include "common_logger.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "statsite_proxy.h"
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

#ifndef _WIN32

statsd_metric::statsd_metric():
			m_timestamp(0),
			m_type(type_t::NONE),
			m_full_identifier_parsed(false)
{
}

/*
 * Parse a line and fill data structures
 * return false if line does not belong to this object
 * throws an exception if parsing fails
 */
bool statsd_metric::parse_line(const string& line)
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
		const auto line_tokens = sinsp_split(line, '|');
		//ASSERT(line_tokens.size() == 3);

		// parse timestamp
		const auto timestamp = std::stoul(line_tokens.at(2));
		if (m_full_identifier_parsed && m_timestamp != timestamp)
		{
			return false;
		}
		m_timestamp = timestamp;

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

		if(m_full_identifier_parsed && m_type != new_type)
		{
			return false;
		}
		m_type = new_type;

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
		const auto& name_and_container_id = name_and_tags_tokens.at(0);
		const auto name_and_container_id_split = sinsp_split(name_and_container_id, CONTAINER_ID_SEPARATOR);

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
			m_container_id = move(container_id);
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
	} catch(const std::exception& ex)
	{
		// A lot of exceptions can arise from the parsing;
		// vector indexing, double conversion and so on
		// so catch them and map as parsing exception
		throw parse_exception(ex.what());
	}
}
#endif // _WIN32

void statsd_metric::to_protobuf(draiosproto::statsd_metric *proto) const
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
		typedef draiosproto::statsd_metric CTB;
		typedef draiosproto::counter_percentile CP;
		percentile::to_protobuf<CTB, CP>(m_percentiles, proto, &CTB::add_percentile);
	}
	else
	{
		proto->set_value(m_value);
	}
}

string statsd_metric::sanitize_container_id(string container_id)
{
	// Unfortunately rkt container id have `:` char which is a reserved char in statsd protocol
	// as a workaround we translate it to another char
	ASSERT(container_id.find('+') == string::npos);
	replace(container_id.begin(), container_id.end(), ':', '+');
	return container_id;
}

string statsd_metric::desanitize_container_id(string container_id)
{
	// rkt containerid has a ':' char that we have translated to "+"
	// because its reserved in statsd protocol, here we put it back to :
	replace(container_id.begin(), container_id.end(), '+', ':');
	return container_id;
}

namespace
{

std::string type_to_string(const statsd_metric::type_t type)
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

statsite_proxy::statsite_proxy(pair<FILE*, FILE*> const &fds,
			       bool check_format):
		m_input_fd(fds.first),
		m_output_fd(fds.second),
		m_check_format(check_format)
{
}

#ifndef _WIN32
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
							std::get<0>(ret[m_metric.container_id()]).push_back(move(m_metric));
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
						std::get<0>(ret[m_metric.container_id()]).push_back(move(m_metric));
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
					std::get<0>(ret[m_metric.container_id()]).push_back(move(m_metric));
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
				std::get<0>(ret[m_metric.container_id()]).push_back(move(m_metric));
				++metric_count;
			}
			m_metric = statsd_metric();
		}

		LOG_DEBUG("Ret vector size is: %u", metric_count);

		if(m_metric.timestamp() > 0)
		{
			LOG_DEBUG("m_metric timestamp is: %lu, vector timestamp: %lu",
			          m_metric.timestamp(),
			          ret.size() > 0 ? std::get<0>(ret.at("")).at(0).timestamp() : 0);
			LOG_DEBUG("m_metric name is: %s",
			          m_metric.name().c_str());
		}
	}
	else
	{
		LOG_ERROR("Cannot read metrics (file is null)");
	}
	return ret;
}

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
bool statsite_proxy::validate_buffer(const char *buf, uint64_t len)
{
	std::string string_buf(buf, len);
	return m_statsd_regex.match(string_buf);
}

void statsite_proxy::send_metric(const char *buf, uint64_t len)
{
	if (m_check_format && !validate_buffer(buf, len))
	{
		std::string string_buf(buf, len);
		LOG_ERROR("Invalid buffer format. Dropping. %s", string_buf.c_str());
		return;
	}

	if(buf && len && m_input_fd)
	{
		fwrite_unlocked(buf, sizeof(char), len, m_input_fd);
		if(buf[len-1] != '\n')
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

void statsite_proxy::send_container_metric(const string &container_id, const char *data, uint64_t len)
{
	// Send the metric with containerid prefix
	// Prefix container metrics with containerid and $
	auto container_prefix = statsd_metric::sanitize_container_id(container_id) +
							statsd_metric::CONTAINER_ID_SEPARATOR;

	// Init metric data with initial container_prefix
	auto metric_data = container_prefix;
	metric_data.append(data, (size_t)len);

	// Add container prefix to other metrics if they are present
	auto endline_pos = metric_data.find('\n');
	while(endline_pos != string::npos && endline_pos+1 < metric_data.size())
	{
		metric_data.insert(endline_pos+1, container_prefix);
		endline_pos = metric_data.find('\n', endline_pos+1);
	}
	send_metric(metric_data.data(), metric_data.size());
}

statsite_forwarder::statsite_forwarder(const pair<FILE *, FILE *> &pipes,
				       uint16_t port,
				       bool check_format):
	m_proxy(pipes, check_format),
	m_inqueue("/sdc_statsite_forwarder_in", posix_queue::RECEIVE, 1),
	m_exitcode(0),
	m_port(port),
	m_terminate(false)
{
	g_logger.add_stderr_log();
}

int statsite_forwarder::run()
{
#ifndef CYGWING_AGENT
	ErrorHandler::set(this);

	LOG_INFO("Info Starting with pid=%d\n", getpid());

	Poco::Thread reactor_thread;
	reactor_thread.start(m_reactor);

	while(!m_terminate)
	{
		if(!reactor_thread.isRunning())
		{
			terminate(1, "unexpected reactor shutdown");
		}
		send_subprocess_heartbeat();
		auto msg = m_inqueue.receive(1);

		if(msg.empty())
		{
			continue;
		}

		LOG_DEBUG("Received msg=%s", msg.c_str());

		Json::Reader json_reader;
		Json::Value root;
		if(!json_reader.parse(msg, root))
		{
			LOG_ERROR("Error parsing msg=%s", msg.c_str());
			continue;
		}

		unordered_set<string> containerids;
		for(const auto& container : root["containers"])
		{
			auto containerid = container["id"].asString();
			auto container_pid = container["pid"].asInt64();
			containerids.emplace(containerid);
			if(m_sockets.find(containerid) == m_sockets.end())
			{
				try
				{
					nsenter enter(container_pid, "net");
					LOG_DEBUG("Starting statsd server on container=%s pid=%lld",
					          containerid.c_str(),
					          container_pid);
					m_sockets[containerid] =
						make_unique<statsd_server>(containerid,
						                           m_proxy,
						                           m_reactor,
						                           m_port);
				}
				catch (const sinsp_exception& ex)
				{
					LOG_WARNING("Cannot init statsd server on container=%s pid=%lld",
					            containerid.c_str(),
					            container_pid);
				}
			}
		}

		auto it = m_sockets.begin();
		while(it != m_sockets.end())
		{
			if(containerids.find(it->first) == containerids.end())
			{
				// This container does not exists anymore,
				// turning off statsd server so we can release
				// resources
				LOG_DEBUG("Stopping statsd server on container=%s",
				          it->first.c_str());
				it = m_sockets.erase(it);
			}
			else
			{
				// container still exists, keep iterating
				++it;
			}
		}
	}
	reactor_thread.join();
	return m_exitcode;
#else // CYGWING_AGENT
	ASSERT(false);
	throw sinsp_exception("statsite_forwarder::run not implemented on Windows");
#endif // CYGWING_AGENT
}

void statsite_forwarder::exception(const Poco::Exception& ex)
{
	terminate(1, ex.displayText());
}

void statsite_forwarder::exception(const std::exception& ex)
{
	terminate(1, ex.what());
}

void statsite_forwarder::exception()
{
	terminate(1, "Unknown exception");
}

void statsite_forwarder::terminate(int code, const string& reason)
{
	LOG_ERROR("Fatal error occurred: %s, terminating", reason.c_str());
	m_reactor.stop();
	m_terminate = true;
	m_exitcode = code;
}

statsd_server::statsd_server(const string &containerid, statsite_proxy &proxy, Poco::Net::SocketReactor& reactor, uint16_t port):
	m_containerid(containerid),
	m_statsite(proxy),
	m_reactor(reactor),
	m_read_obs(*this, &statsd_server::on_read),
	m_error_obs(*this, &statsd_server::on_error),
	m_read_buffer(INITIAL_READ_SIZE)
{
	try
	{
		m_ipv4_socket = make_socket(Poco::Net::SocketAddress("127.0.0.1", port));
	}
	catch (const Poco::Net::NetException& ex)
	{
		LOG_WARNING("Unable to bind ipv4 on containerid=%s reason=%s",
		            containerid.c_str(),
		            ex.displayText().c_str());
	}

	try
	{
		m_ipv6_socket = make_socket(Poco::Net::SocketAddress("::1", port));
	}
	catch (const Poco::Net::NetException& ex)
	{
		LOG_WARNING("Unable to bind ipv6 on containerid=%s reason=%s",
		            containerid.c_str(),
		            ex.displayText().c_str());
	}
}

statsd_server::~statsd_server()
{
	if(m_ipv4_socket)
	{
		m_reactor.removeEventHandler(*m_ipv4_socket, m_read_obs);
		m_reactor.removeEventHandler(*m_ipv4_socket, m_error_obs);
	}
	if(m_ipv6_socket)
	{
		m_reactor.removeEventHandler(*m_ipv6_socket, m_read_obs);
		m_reactor.removeEventHandler(*m_ipv6_socket, m_error_obs);
	}
}

unique_ptr<Poco::Net::DatagramSocket> statsd_server::make_socket(
		const Poco::Net::SocketAddress& address)
{
	std::unique_ptr<Poco::Net::DatagramSocket> socket =
		make_unique<Poco::Net::DatagramSocket>(address);

	socket->setBlocking(false);

	m_reactor.addEventHandler(*socket, m_read_obs);
	m_reactor.addEventHandler(*socket, m_error_obs);

	return socket;
}

void statsd_server::on_read(Poco::Net::ReadableNotification* const notification)
{
	// Either ipv4 or ipv6 datagram socket will come here
	Poco::Net::DatagramSocket datagram_socket(notification->socket());
	const std::vector<char>::size_type bytes_available = datagram_socket.available();

	LOG_DEBUG("bytes_available: %zu", bytes_available);
	LOG_DEBUG("ReceiveBufferSize: %d", datagram_socket.getReceiveBufferSize());

	if(bytes_available > m_read_buffer.capacity())
	{
		LOG_INFO("Resizing data buffer for %s from %zu to %zu",
		         m_containerid.c_str(),
		         m_read_buffer.capacity(),
		         bytes_available);

		// Allocate a little more than bytes_available to give a little
		// extra room so that we can hopefully avoid reallocations if
		// a future packet is just a little bigger.
		m_read_buffer.reserve(bytes_available * 1.2);
	}

	const int bytes_received = datagram_socket.receiveBytes(m_read_buffer.data(),
	                                                        m_read_buffer.capacity());

	if(bytes_received > 0)
	{
		m_statsite.send_container_metric(m_containerid,
		                                 m_read_buffer.data(),
		                                 bytes_received);
		m_statsite.send_metric(m_read_buffer.data(), bytes_received);
	}
}

void statsd_server::on_error(Poco::Net::ErrorNotification* notification)
{
	LOG_ERROR("Unexpected error on statsd server");
}

#endif // _WIN32
