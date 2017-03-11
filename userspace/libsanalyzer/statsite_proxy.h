//
// Created by Luca Marturana on 30/03/15.
//

#pragma once

#include "posix_queue.h"
#include "metric_limits.h"
#include <Poco/Net/SocketReactor.h>
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/SocketNotification.h>
#include <Poco/ErrorHandler.h>
#include <atomic>

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

	unsigned to_protobuf(draiosproto::statsd_metric* proto) const;

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

	statsd_metric();

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
	typedef unordered_map<string, vector<statsd_metric>> metric_map_t;

	statsite_proxy(const pair<FILE*, FILE*>& pipes);
	unordered_map<string, vector<statsd_metric>> read_metrics(metric_limits::cref_sptr_t ml = nullptr);
	void send_metric(const char *buf, uint64_t len);
	void send_container_metric(const string& container_id, const char* data, uint64_t len);
private:
	FILE* m_input_fd;
	FILE* m_output_fd;
	statsd_metric m_metric;
};

class statsd_server
{
public:
	statsd_server(const string& containerid, statsite_proxy& proxy, Poco::Net::SocketReactor& reactor, uint16_t port);
	virtual ~statsd_server();

	statsd_server(const statsd_server&) = delete;
	statsd_server& operator=(const statsd_server&) = delete;
private:
	void on_read(Poco::Net::ReadableNotification* notification);
	void on_error(Poco::Net::ErrorNotification* notification);
	unique_ptr<Poco::Net::DatagramSocket> make_socket(const Poco::Net::SocketAddress& address);
	string m_containerid;
	statsite_proxy& m_statsite;
	unique_ptr<Poco::Net::DatagramSocket> m_ipv4_socket;
	unique_ptr<Poco::Net::DatagramSocket> m_ipv6_socket;
	Poco::Net::SocketReactor& m_reactor;
	Poco::Observer<statsd_server, Poco::Net::ReadableNotification> m_read_obs;
	Poco::Observer<statsd_server, Poco::Net::ErrorNotification> m_error_obs;
	char* m_read_buffer;
	static const unsigned MAX_READ_SIZE = 2048;
};

class statsite_forwarder: public Poco::ErrorHandler
{
public:
	statsite_forwarder(const pair<FILE*, FILE*>& pipes, uint16_t statsd_port);
	virtual void exception(const Poco::Exception& ex) override;
	virtual void exception(const std::exception& ex) override;
	virtual void exception() override;
	int run();
private:
	void terminate(int code, const string& reason);

	statsite_proxy m_proxy;
	posix_queue m_inqueue;
	unordered_map<string, unique_ptr<statsd_server>> m_sockets;
	Poco::Net::SocketReactor m_reactor;
	int m_exitcode;
	uint16_t m_port;
	std::atomic<bool> m_terminate;
};