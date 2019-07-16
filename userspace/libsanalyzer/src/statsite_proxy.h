//
// Created by Luca Marturana on 30/03/15.
//

#pragma once

#include "percentile.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include "statsite_proxy.h"
#include <atomic>
#include <vector>
#include <Poco/Net/SocketReactor.h>
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/SocketNotification.h>
#include <Poco/ErrorHandler.h>
#include <Poco/RegularExpression.h>

class statsite_proxy;
namespace draiosproto
{
	class statsd_metric;
};

class statsd_metric
{
public:
#ifndef _WIN32
	typedef std::vector<statsd_metric> list_t;

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
		NONE = 0,
		COUNT = 1,
		HISTOGRAM = 2,
		GAUGE = 3,
		SET = 4,
	};

	void to_protobuf(draiosproto::statsd_metric* proto) const;

	bool parse_line(const std::string& line);

	inline uint64_t timestamp() const
	{
		return m_timestamp;
	}

	inline const std::string& name() const
	{
		return m_name;
	}

	inline const std::string& container_id() const
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

	inline double mean() const
	{
		return m_mean;
	}

	inline double min() const
	{
		return m_min;
	}

	inline double max() const
	{
		return m_max;
	}

	inline double count() const
	{
		return m_count;
	}

	inline double stdev() const
	{
		return m_stdev;
	}

	inline double percentile(int index) const
	{
		auto i = m_percentiles.find(index);

		if(i == m_percentiles.end())
		{
			return 0.0;
		}

		return i->second;
	}

	bool percentile(int pct, double& val)
	{
		auto it = m_percentiles.find(pct);
		if(it != m_percentiles.end())
		{
			val = it->second;
			return true;
		}
		return false;
	}
	inline const std::map<std::string, std::string>& tags() const
	{
		return m_tags;
	}

	statsd_metric();

	static std::string sanitize_container_id(std::string container_id);
	static std::string desanitize_container_id(std::string container_id);

	static const char CONTAINER_ID_SEPARATOR = '$';

	std::string to_debug_string() const;
private:
	uint64_t m_timestamp;
	std::string m_name;
	std::map<std::string, std::string> m_tags;
	std::string m_container_id;
	type_t m_type;
	bool m_full_identifier_parsed;

	double m_value;

	double m_sum;
	double m_mean;
	double m_min;
	double m_max;
	double m_count;
	double m_stdev;
	percentile::p_map_type m_percentiles;

	friend class lua_cbacks;
};

/**
 * Interface to an object that can generate statsd statsd.
 */
class statsd_stats_source
{
public:
	using ptr = std::shared_ptr<statsd_stats_source>;

	/** List of metrics */
	using statsd_metric_list = std::vector<statsd_metric>;

	/** <List of metrics, count> */
	using statsd_list_tuple = std::tuple<statsd_metric_list, unsigned>;

	/** container_id -> <List of metrics, count> */
	using container_statsd_map = std::unordered_map<std::string, statsd_list_tuple>;

	virtual ~statsd_stats_source() = default;

	virtual container_statsd_map read_metrics(metric_limits::cref_sptr_t ml = nullptr) = 0;
};

class statsite_proxy : public statsd_stats_source
{
private:
	bool validate_buffer(const char *buf, uint64_t len);
public:
	typedef std::unordered_map<std::string, std::vector<statsd_metric>> metric_map_t;

	statsite_proxy(const std::pair<FILE*, FILE*>& pipes,
		       bool check_format);
	statsd_stats_source::container_statsd_map read_metrics(
			metric_limits::cref_sptr_t ml = nullptr) override;
	void send_metric(const char *buf, uint64_t len);
	void send_container_metric(const std::string& container_id, const char* data, uint64_t len);

private:
	// This regex SHOULD match strings in such a way that each line goes:
	// stuff : stuff | stuff \n
	// except for the last one, which may or may not have a newline. See
	// the definition for a full breakdown of the regex
	static const std::string stats_validator_regex;
	static Poco::RegularExpression m_statsd_regex;

private:
	FILE* m_input_fd;
	FILE* m_output_fd;
	statsd_metric m_metric;
	bool m_check_format = false;
};

class statsd_server
{
public:
	statsd_server(const std::string& containerid, statsite_proxy& proxy, Poco::Net::SocketReactor& reactor, uint16_t port);
	virtual ~statsd_server();

	statsd_server(const statsd_server&) = delete;
	statsd_server& operator=(const statsd_server&) = delete;
private:
	void on_read(Poco::Net::ReadableNotification* notification);
	void on_error(Poco::Net::ErrorNotification* notification);

	std::unique_ptr<Poco::Net::DatagramSocket> make_socket(const Poco::Net::SocketAddress& address);
	std::string m_containerid;
	statsite_proxy& m_statsite;
	std::unique_ptr<Poco::Net::DatagramSocket> m_ipv4_socket;
	std::unique_ptr<Poco::Net::DatagramSocket> m_ipv6_socket;
	Poco::Net::SocketReactor& m_reactor;
	Poco::Observer<statsd_server, Poco::Net::ReadableNotification> m_read_obs;
	Poco::Observer<statsd_server, Poco::Net::ErrorNotification> m_error_obs;
	static const std::vector<char>::size_type INITIAL_READ_SIZE = 512;
	std::vector<char> m_read_buffer;
};

class statsite_forwarder: public Poco::ErrorHandler
{
public:
	statsite_forwarder(const std::pair<FILE*, FILE*>& pipes,
			   uint16_t statsd_port,
			   bool check_format);
	virtual void exception(const Poco::Exception& ex) override;
	virtual void exception(const std::exception& ex) override;
	virtual void exception() override;
	int run();
private:
	void terminate(int code, const std::string& reason);

	statsite_proxy m_proxy;
	posix_queue m_inqueue;
	std::unordered_map<std::string, std::unique_ptr<statsd_server>> m_sockets;
	Poco::Net::SocketReactor m_reactor;
	int m_exitcode;
	uint16_t m_port;
	std::atomic<bool> m_terminate;
};
