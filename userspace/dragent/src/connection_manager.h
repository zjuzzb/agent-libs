#pragma once

#include "protocol.h"
#include "watchdog_runnable.h"

#ifndef CYGWING_AGENT
#include "promex.pb.h"
#include "promex.grpc.pb.h"
#endif

#include <chrono>
#include <initializer_list>
#include <memory>
#include <map>

class dragent_configuration;

namespace Poco {
namespace Net {
class StreamSocket;
} // namespace Net
} // namespace Poco


class connection_manager : public dragent::watchdog_runnable
{
public:
	class message_handler
	{
	public:
		using ptr = std::shared_ptr<message_handler>;

		virtual ~message_handler() = default;

		virtual bool handle_message(draiosproto::message_type type,
		                            uint8_t* buffer,
		                            size_t buffer_size) = 0;
	};

	using message_handler_map = std::map<draiosproto::message_type, message_handler::ptr>;

	connection_manager(dragent_configuration* configuration,
			   protocol_queue* queue,
			   std::initializer_list<message_handler_map::value_type> message_handlers = {});
	~connection_manager();

	bool is_connected() const
	{
		return m_connected && m_socket;
	}

	static const uint32_t SOCKET_TIMEOUT_DURING_CONNECT_US = 60 * 1000 * 1000;
	static const uint32_t SOCKET_TIMEOUT_AFTER_CONNECT_US = 100 * 1000;
	static const uint32_t CONNECTION_TIMEOUT_WAIT_S = 10;

#ifdef SYSDIG_TEST
	void test_run() { do_run(); }

	void set_connection_timeout(uint32_t timeout_us) { m_connect_timeout_us = timeout_us; }

	uint32_t m_connect_timeout_us = SOCKET_TIMEOUT_DURING_CONNECT_US;
	volatile bool m_timed_out = false;
#endif

private:
	using socket_ptr = std::shared_ptr<Poco::Net::StreamSocket>;

	bool init();
	void do_run() override;
	bool connect();
	void disconnect();
	void disconnect(socket_ptr& ssp);
	bool transmit_buffer(uint64_t now, std::shared_ptr<protocol_queue_item> &item);
	bool receive_message();

	static const std::string& get_openssldir();
	// Walk over the CA path search list and return the first one that exists
	// Note: we have to return a new string by value as we potentially alter
	// the string in the search path (substituting $OPENSSLDIR with the actual path)
	static std::string find_ca_cert_path(const std::vector<std::string>& search_paths);

#ifndef CYGWING_AGENT
	bool prometheus_connected() const;
#endif
	static const uint32_t MAX_RECEIVER_BUFSIZE = 1 * 1024 * 1024; // 1MiB
	static const uint32_t RECEIVER_BUFSIZE = 32 * 1024;
	static const uint32_t RECONNECT_MIN_INTERVAL_S;
	static const uint32_t RECONNECT_MAX_INTERVAL_S;
	static const unsigned int SOCKET_TCP_TIMEOUT_MS = 60 * 1000;
	static const std::chrono::seconds WORKING_INTERVAL_S;

	message_handler_map m_handler_map;
	socket_ptr m_socket;
	bool m_connected;
	Buffer<uint8_t> m_buffer;
	uint32_t m_buffer_used;
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;

	uint32_t m_reconnect_interval;
	std::chrono::time_point<std::chrono::system_clock> m_last_connection_failure;

#ifndef CYGWING_AGENT
	// communication with Prometheus exporter
	std::shared_ptr<promex_pb::PrometheusExporter::Stub> m_prom_conn;
	std::shared_ptr<grpc::Channel> m_prom_channel;
#endif
};
