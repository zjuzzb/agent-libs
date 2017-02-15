//
// Created by Luca Marturana on 30/03/15.
//
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "statsite_proxy.h"
#include <Poco/Net/NetException.h>
#include <Poco/Thread.h>

#ifndef _WIN32

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

			const auto& container_id = name_and_container_id_split.at(0);
			if(m_full_identifier_parsed && m_container_id != container_id)
			{
				return false;

			}
			m_container_id = container_id;
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
		proto->set_median(m_median);
		proto->set_percentile_95(m_percentile_95);
		proto->set_percentile_99(m_percentile_99);
	}
	else
	{
		proto->set_value(m_value);
	}
}

statsite_proxy::statsite_proxy(pair<FILE*, FILE*> const &fds):
		m_input_fd(fds.first),
		m_output_fd(fds.second)
{
}

#ifndef _WIN32
unordered_map<string, vector<statsd_metric>> statsite_proxy::read_metrics()
{
	// Sample data from statsite
	// counts.statsd.test.1|1.000000|1441746724
	// counts.statsd.test.1|1.000000|1441746725
	// counts.statsd.test.1|1.000000|1441746726
	// The logic is a bit complicated here, there are two main problems to address:
	// 1. bunch of metrics with different timestamps are not separated by each other
	// 2. more lines sometimes are parsed to a single metric (eg. histograms)

	unordered_map<string, vector<statsd_metric>> ret;
	uint64_t timestamp = 0;
	char buffer[300] = {};
	unsigned metric_count = 0;

	if(m_output_fd)
	{
		bool continue_read = (fgets_unlocked(buffer, sizeof(buffer), m_output_fd) != NULL);
		while (continue_read)
		{
			//g_logger.format(sinsp_logger::SEV_DEBUG, "Received from statsite: %s", buffer);
			//printf(buffer);
			try {
				bool parsed = m_metric.parse_line(buffer);
				if(!parsed)
				{
					if(timestamp == 0)
					{
						timestamp = m_metric.timestamp();
					}

					ret[m_metric.container_id()].push_back(move(m_metric));
					++metric_count;
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
				g_logger.format(sinsp_logger::SEV_ERROR, "parser exception on statsd, buffer: %s", buffer);
			}

			continue_read = (fgets_unlocked(buffer, sizeof(buffer), m_output_fd) != NULL);
		}
		if(m_metric.timestamp() && (timestamp == 0 || timestamp == m_metric.timestamp()))
		{
			g_logger.log("statsite_proxy, Adding last sample", sinsp_logger::SEV_DEBUG);
			ret[m_metric.container_id()].push_back(move(m_metric));
			++metric_count;
			m_metric = statsd_metric();
		}
		g_logger.format(sinsp_logger::SEV_DEBUG, "statsite_proxy, ret vector size is: %u", metric_count);
		if(m_metric.timestamp() > 0)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "statsite_proxy, m_metric timestamp is: %lu, vector timestamp: %lu", m_metric.timestamp(), ret.size() > 0 ? ret.at("").at(0).timestamp() : 0);
			g_logger.format(sinsp_logger::SEV_DEBUG, "statsite_proxy, m_metric name is: %s", m_metric.name().c_str());
		}
	}
	else
	{
		g_logger.log("statsite_proxy: cannot read metrics (file is null)", sinsp_logger::SEV_ERROR);
	}
	return ret;
}

void statsite_proxy::send_metric(const char *buf, uint64_t len)
{
	//string buf_p(buf, len);
	//g_logger.format(sinsp_logger::SEV_INFO, "Sending statsd metric: %s", buf_p.c_str());
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
		g_logger.log("statsite_proxy: cannot send metrics (file or buf is null)", sinsp_logger::SEV_ERROR);
	}
}

void statsite_proxy::send_container_metric(const string &container_id, const char *data, uint64_t len)
{
	// Send the metric with containerid prefix
	// Prefix container metrics with containerid and $
	auto container_prefix = container_id + statsd_metric::CONTAINER_ID_SEPARATOR;

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
	//g_logger.format(sinsp_logger::SEV_DEBUG, "Generated metric for container: %s", metric_data.c_str());
	// send_metric does not need final \0
	send_metric(metric_data.data(), metric_data.size());
}

statsite_forwarder::statsite_forwarder(const pair<FILE *, FILE *> &pipes, uint16_t port):
	m_proxy(pipes),
	m_inqueue("/sdc_statsite_forwarder_in", posix_queue::RECEIVE, 1),
	m_exitcode(0),
	m_port(port),
	m_terminate(false)
{
	g_logger.add_stderr_log();
}

int statsite_forwarder::run()
{
	ErrorHandler::set(this);

	g_logger.format(sinsp_logger::SEV_INFO, "Info Starting with pid=%d\n", getpid());
	
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

		g_logger.format(sinsp_logger::SEV_DEBUG, "Received msg=%s", msg.c_str());

		Json::Reader json_reader;
		Json::Value root;
		if(!json_reader.parse(msg, root))
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "Error parsing msg=%s", msg.c_str());
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
					g_logger.format(sinsp_logger::SEV_DEBUG, "Starting statsd server on container=%s pid=%d", containerid.c_str(), container_pid);
					m_sockets[containerid] = make_unique<statsd_server>(containerid, m_proxy, m_reactor, m_port);
				}
				catch (const sinsp_exception& ex)
				{
					g_logger.format(sinsp_logger::SEV_WARNING, "Warning, cannot init statsd server on container=%s pid=%d", containerid.c_str(), container_pid);
				}
			}
		}

		auto it = m_sockets.begin();
		while(it != m_sockets.end())
		{
			if(containerids.find(it->first) == containerids.end())
			{
				// this container does not exists anymore, turning off statsd
				// server so we can release resources
				g_logger.format(sinsp_logger::SEV_DEBUG, "Stopping statsd server on container=%s", it->first.c_str());
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
	g_logger.format(sinsp_logger::SEV_ERROR, "Fatal error occurred: %s, terminating", reason.c_str());
	m_reactor.stop();
	m_terminate = true;
	m_exitcode = code;
}

statsd_server::statsd_server(const string &containerid, statsite_proxy &proxy, Poco::Net::SocketReactor& reactor, uint16_t port):
	m_containerid(containerid),
	m_statsite(proxy),
	m_reactor(reactor),
	m_read_obs(*this, &statsd_server::on_read),
	m_error_obs(*this, &statsd_server::on_error)
{
	m_read_buffer = new char[MAX_READ_SIZE];
	try
	{
		m_ipv4_socket = make_socket(Poco::Net::SocketAddress("127.0.0.1", port));
	}
	catch (const Poco::Net::NetException& ex)
	{
		auto reason = ex.displayText();
		g_logger.format(sinsp_logger::SEV_WARNING, "statsite_forwarder, Warning, Unable to bind ipv4 on containerid=%s reason=%s", containerid.c_str(), reason.c_str());
	}
	try
	{
		m_ipv6_socket = make_socket(Poco::Net::SocketAddress("::1", port));
	}
	catch (const Poco::Net::NetException& ex)
	{
		auto reason = ex.displayText();
		g_logger.format(sinsp_logger::SEV_WARNING, "statsite_forwarder, Warning, Unable to bind ipv6 on containerid=%s reason=%s", containerid.c_str(), reason.c_str());
	}
}

statsd_server::~statsd_server()
{
	delete[] m_read_buffer;
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

unique_ptr<Poco::Net::DatagramSocket> statsd_server::make_socket(const Poco::Net::SocketAddress& address)
{
	unique_ptr<Poco::Net::DatagramSocket> socket = make_unique<Poco::Net::DatagramSocket>(address);
	socket->setBlocking(false);
	m_reactor.addEventHandler(*socket, m_read_obs);
	m_reactor.addEventHandler(*socket, m_error_obs);
	return socket;
}

void statsd_server::on_read(Poco::Net::ReadableNotification* notification)
{
	//throw sinsp_exception("test");
	// Either ipv4 or ipv6 datagram socket will come here
	Poco::Net::DatagramSocket datagram_socket(notification->socket());
	auto len = datagram_socket.receiveBytes(m_read_buffer, MAX_READ_SIZE);
	if( len > 0)
	{
		m_statsite.send_container_metric(m_containerid, m_read_buffer, len);
		m_statsite.send_metric(m_read_buffer, len);
	}
}

void statsd_server::on_error(Poco::Net::ErrorNotification* notification)
{
	g_logger.format(sinsp_logger::SEV_ERROR, "statsite_forwarder, Unexpected error on statsd server");
}

#endif // _WIN32
