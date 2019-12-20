#include "connection_manager.h"
#include "capture_job_handler.h"
#include "common_logger.h"
#include "draios.pb.h"
#include "protocol.h"
#include "security_config.h"
#include "spinlock.h"
#include "utils.h"
#include "watchdog_runnable_fatal_error.h"
#include <future>
#include <errno.h>
#include <memory>
#include <Poco/File.h>
#include <Poco/Net/InvalidCertificateHandler.h>
#include <Poco/Net/SSLException.h>
#include <functional>

#include <grpc_channel_registry.h>

using namespace std;
namespace security_config = libsanalyzer::security_config;

#ifndef TCP_USER_TIMEOUT
// Define it here because old glibc versions do not have this flag (eg, Centos6)
#define TCP_USER_TIMEOUT 18 /* How long for loss retry before timeout */
#endif

#define US_TO_S(_usec) ((_usec) / (1000 * 1000))

COMMON_LOGGER();

const chrono::seconds connection_manager::WORKING_INTERVAL_S(10);
const uint32_t connection_manager::RECONNECT_MIN_INTERVAL_S = 1;
const uint32_t connection_manager::RECONNECT_MAX_INTERVAL_S = 60;

class LoggingCertificateHandler : public Poco::Net::InvalidCertificateHandler
{
public:
	using Poco::Net::InvalidCertificateHandler::InvalidCertificateHandler;

	// Mimicking Poco::Net::ConsoleCertificateHandler but no user input
	virtual void onInvalidCertificate(const void* pSender,
	                                  Poco::Net::VerificationErrorArgs& errorCert)
	{
		LOG_ERROR("Certificate verification failed: " + errorCert.errorMessage() + " (" +
		          NumberFormatter::format(errorCert.errorNumber()) + ")" + ", Issuer: " +
		          errorCert.certificate().issuerName() + ", Subject: " +
		          errorCert.certificate().subjectName() + ", chain position " +
		          NumberFormatter::format(errorCert.errorDepth()));
	}
};


cm_state_machine::state connect_received_in_init(connection_manager* cm)
{
	return cm_state_machine::state::CONNECTING;
}

cm_state_machine::state connect_received_in_retrying(connection_manager* cm)
{
	return cm_state_machine::state::CONNECTING;
}

cm_state_machine::state disconnected_received_in_connecting(connection_manager* cm)
{
	return cm_state_machine::state::RETRYING;
}

cm_state_machine::state v4_connected_received_in_connecting(connection_manager* cm)
{
	return cm_state_machine::state::STEADY_STATE;
}

cm_state_machine::state v5_connected_received_in_connecting(connection_manager* cm)
{
	return cm_state_machine::state::HANDSHAKE;
}

cm_state_machine::state v5_handshake_proto_resp_received_in_handshake(connection_manager* cm)
{
	return cm_state_machine::state::HANDSHAKE;
}

cm_state_machine::state v5_handshake_negotiation_resp_received_in_handshake(connection_manager* cm)
{
	return cm_state_machine::state::STEADY_STATE;
}

cm_state_machine::state v5_disconnected_received_in_handshake(connection_manager* cm)
{
	return cm_state_machine::state::RETRYING;
}

cm_state_machine::state shutdown_received_in_steady_state(connection_manager* cm)
{
	return cm_state_machine::state::TERMINATED;
}

cm_state_machine::state disconnected_received_in_steady_state(connection_manager* cm)
{
	return cm_state_machine::state::CONNECTING;
}
cm_state_machine::state shutdown_received_in_any_state(connection_manager* cm)
{
	return cm_state_machine::state::TERMINATED;
}

std::unique_ptr<cm_state_machine> build_fsm(connection_manager* cm, bool v5)
{
	auto ret = make_unique<cm_state_machine>(cm);

	// Common functions
	ret->register_event_callback(cm_state_machine::state::INIT,
	                             cm_state_machine::event::CONNECT,
	                             connect_received_in_init);
	ret->register_event_callback(cm_state_machine::state::INIT,
	                             cm_state_machine::event::SHUTDOWN,
	                             shutdown_received_in_any_state);
	ret->register_event_callback(cm_state_machine::state::RETRYING,
	                             cm_state_machine::event::CONNECT,
	                             connect_received_in_retrying);
	ret->register_event_callback(cm_state_machine::state::RETRYING,
	                             cm_state_machine::event::SHUTDOWN,
	                             shutdown_received_in_any_state);
	ret->register_event_callback(cm_state_machine::state::CONNECTING,
	                             cm_state_machine::event::DISCONNECTED,
	                             disconnected_received_in_connecting);
	ret->register_event_callback(cm_state_machine::state::CONNECTING,
	                             cm_state_machine::event::SHUTDOWN,
	                             shutdown_received_in_any_state);
	ret->register_event_callback(cm_state_machine::state::STEADY_STATE,
	                             cm_state_machine::event::SHUTDOWN,
	                             shutdown_received_in_steady_state);
	ret->register_event_callback(cm_state_machine::state::STEADY_STATE,
	                             cm_state_machine::event::DISCONNECTED,
	                             disconnected_received_in_steady_state);
	ret->register_event_callback(cm_state_machine::state::STEADY_STATE,
	                             cm_state_machine::event::DISCONNECTED,
	                             disconnected_received_in_steady_state);

	if (!v5) // Functions specific to legacy protocol
	{
		ret->register_event_callback(cm_state_machine::state::CONNECTING,
		                             cm_state_machine::event::CONNECTION_COMPLETE,
		                             v4_connected_received_in_connecting);
	}
	else // Build FSM for protocol v5
	{
		ret->register_event_callback(cm_state_machine::state::CONNECTING,
		                             cm_state_machine::event::CONNECTION_COMPLETE,
		                             v5_connected_received_in_connecting);
		ret->register_event_callback(cm_state_machine::state::HANDSHAKE,
		                             cm_state_machine::event::HANDSHAKE_PROTO_RESP,
		                             v5_handshake_proto_resp_received_in_handshake);
		ret->register_event_callback(cm_state_machine::state::HANDSHAKE,
		                             cm_state_machine::event::HANDSHAKE_NEGOTIATION_RESP,
		                             v5_handshake_negotiation_resp_received_in_handshake);
		ret->register_event_callback(cm_state_machine::state::HANDSHAKE,
		                             cm_state_machine::event::DISCONNECTED,
		                             v5_disconnected_received_in_handshake);
		ret->register_event_callback(cm_state_machine::state::HANDSHAKE,
		                             cm_state_machine::event::SHUTDOWN,
		                             shutdown_received_in_any_state);
	}
	return ret;
}

/*
 * Connection manager workflow:
 * - constructor: Initialize SSL
 * - do_run(): Start the connection manager
 * -- init(): Set up socket (including SSL if enabled)
 * -- connect(): start connect thread: Asynchronously attempt to connect to the backend
 * -- wait until connected
 * -- while connected:
 * --- Receive and dispatch one incoming message, if present
 * --- Send one message from the outgoing queue
 *
 * If the connection is lost, do_run() will loop back to the top and try to
 * connect again, looping until the agent is terminated.
 */

connection_manager::connection_manager(
    dragent_configuration* configuration,
    protocol_queue* queue,
    bool use_handshake,
    std::initializer_list<message_handler_map::value_type> message_handlers)
    : dragent::watchdog_runnable("connection_manager"),
      m_handler_map(message_handlers),
      m_socket(nullptr),
      m_use_handshake(use_handshake),
      m_generation(0),
      m_sequence(0),
      m_configuration(configuration),
      m_queue(queue),
      m_negotiated_aggregation_interval(UINT32_MAX),
      m_negotiated_compression_method(nullptr),
      m_reconnect_interval(0)
{
	Poco::Net::initializeSSL();
	m_fsm = build_fsm(this, false);
}

connection_manager::~connection_manager()
{
	Poco::Net::uninitializeSSL();
}

bool connection_manager::init()
{
	if (m_configuration->m_server_addr == "" || m_configuration->m_server_port == 0)
	{
		LOG_WARNING("Server address has not been specified");
		return false;
	}

	if (!m_configuration->m_ssl_enabled)
	{
		return true;
	}

	LOG_INFO("SSL enabled, initializing context");

	Poco::Net::Context::VerificationMode verification_mode;
	SharedPtr<LoggingCertificateHandler> invalid_cert_handler = nullptr;
	std::string cert_path;

	if (m_configuration->m_ssl_verify_certificate)
	{
		verification_mode = Poco::Net::Context::VERIFY_STRICT;
		invalid_cert_handler = new LoggingCertificateHandler(false);
		cert_path = find_ca_cert_path(m_configuration->m_ssl_ca_cert_paths);
		LOG_INFO("SSL CA cert path: " + cert_path);
	}
	else
	{
		verification_mode = Poco::Net::Context::VERIFY_NONE;
	}

	Poco::Net::Context::Ptr ptrContext =
	    new Poco::Net::Context(Poco::Net::Context::CLIENT_USE,
	                           "",
	                           "",
	                           cert_path,
	                           verification_mode,
	                           9,
	                           false,
	                           "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

	try
	{
		LOG_INFO("openssl loading cert: " + m_configuration->m_ssl_ca_certificate);
		Poco::Crypto::X509Certificate ca_cert(m_configuration->m_ssl_ca_certificate);
		ptrContext->addCertificateAuthority(ca_cert);
	}
	catch (const Poco::Net::SSLException& e)
	{
		// thrown by addCertificateAuthority()
		LOG_ERROR("Unable to add ssl ca certificate: " + e.message());
	}
	catch (const Poco::IOException& e)
	{
		// thrown by X509Certificate constructor
		LOG_ERROR("Unable to read ssl ca certificate: " + e.message());
	}
	catch (...)
	{
		LOG_ERROR("Unable to load ssl ca certificate: " + m_configuration->m_ssl_ca_certificate);
	}

	Poco::Net::SSLManager::instance().initializeClient(0, invalid_cert_handler, ptrContext);

	return true;
}

// Find the host's default OPENSSLDIR
// This is best effort for now, so don't log at warn/error
const std::string& connection_manager::get_openssldir()
{
	static std::string path;

	if (!path.empty())
	{
		return path;
	}

	errno = 0;
	FILE* out = popen("openssl version -d 2>&1", "r");
	if (!out)
	{
		LOG_INFO(string("openssl popen() failed: ") + strerror(errno));
		return path;
	}

	// Sample output:
	// $ openssl version -d
	// OPENSSLDIR: "/usr/lib/ssl"
	//
	// It should only be one line, but read multiple lines in case the
	// format changes. Also the while control structure works better
	char buf[256];
	int ii = 0;
	const int max_lines = 10;
	while (ii < max_lines && fgets(buf, sizeof(buf), out))
	{
		ii++;
		std::string out_str(buf);
		LOG_DEBUG("openssl read from popen(): " + out_str);

		// Would use std::regex if we had compiler support
		std::string start_targ("OPENSSLDIR: \"");
		auto start_pos = out_str.find(start_targ);
		if (start_pos == std::string::npos)
		{
			continue;
		}
		start_pos += start_targ.size();
		std::string end_targ("\"");
		auto end_pos = out_str.find(end_targ, start_pos);
		if (end_pos == std::string::npos)
		{
			continue;
		}

		path = out_str.substr(start_pos, end_pos - start_pos);
		LOG_DEBUG("found OPENSSLDIR: " + path);
		break;
	}

	int ret = pclose(out);
	LOG_DEBUG(string("openssl pclose() exit code: ") + std::to_string(WEXITSTATUS(ret)));
	return path;
}

std::string connection_manager::find_ca_cert_path(const std::vector<std::string>& search_paths)
{
	std::vector<std::string> failed_paths;
	for (auto path : search_paths)
	{
		auto pos = path.find("$OPENSSLDIR");
		if (pos != std::string::npos)
		{
			path.replace(pos, strlen("$OPENSSLDIR"), get_openssldir());
		}

		LOG_DEBUG("Checking CA path: " + path);
		if (Poco::File(path).exists())
		{
			return path;
		}

		failed_paths.emplace_back(path);
	}

	std::string msg("Could not find any valid CA path, tried:");
	for (const auto& path : failed_paths)
	{
		msg.append(' ' + path);
	}
	LOG_WARNING(msg);
	return "";
}

bool connection_manager::connect()
{
	m_last_connection_failure = chrono::system_clock::now();
	uint32_t connect_timeout_us = connection_manager::SOCKET_TIMEOUT_DURING_CONNECT_US;
#ifdef SYSDIG_TEST
	connect_timeout_us = m_connect_timeout_us;
#endif

	LOG_INFO("Initiating connection to collector (trying for %u seconds)",
	         US_TO_S(connect_timeout_us));
	ASSERT(m_fsm->get_state() == cm_state_machine::state::CONNECTING);

	std::promise<socket_ptr> sock_promise;
	std::future<socket_ptr> future_sock = sock_promise.get_future();

	//
	// Asynchronously connect to the collector
	//
	// Since sock_promise is captured by reference, need to ensure that it
	// doesn't go out of scope until the thread ends.
	//
	std::thread connect_thread([&sock_promise](const string& hostname,
	                                           const uint16_t port,
	                                           bool ssl_enabled,
	                                           const uint32_t transmit_buffer_size,
	                                           const uint32_t reconnect_interval,
	                                           const uint32_t connect_timeout_us)
	{
		StreamSocket* ssp = nullptr;

		try
		{
			// Reconnect backoff
			// How reconnect backoff works, briefly:
			//  * The backoff starts at 0
			//  * The first disconnect(), the backoff is set to RECONNECT_MIN_INTERVAL_S (currently
			// 1 second)
			//  * Every subsequent disconnect, the backoff is doubled
			//  * If the connection has been active for over WORKING_INTERVAL_S (currently 10
			// seconds),
			//    reset the backoff to RECONNECT_MIN_INTERVAL_S on the next disconnect()
			//  * last_connection_failure is updated above in the call to connect()
			std::chrono::seconds time_slept = std::chrono::seconds(0);
			while (time_slept < std::chrono::seconds(reconnect_interval))
			{
				std::chrono::seconds time_to_sleep = std::chrono::seconds(1);
				std::this_thread::sleep_for(time_to_sleep);
				time_slept += time_to_sleep;
			}
			SocketAddress sa(hostname, port);
			// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
			LOG_INFO("Connecting to collector " + sa.toString());

			if (ssl_enabled)
			{
				auto sss = new Poco::Net::SecureStreamSocket();

				sss->setLazyHandshake(true);
				sss->setPeerHostName(hostname);
				sss->connect(sa, connect_timeout_us);
				//
				// This is done to prevent getting stuck forever waiting during the handshake
				// if the server doesn't speak to us
				//
				sss->setSendTimeout(connect_timeout_us);
				sss->setReceiveTimeout(connect_timeout_us);

				LOG_INFO("Performing SSL handshake");
				int32_t ret = sss->completeHandshake();

				if (ret == 1)
				{
					sss->verifyPeerCertificate();
					LOG_INFO("SSL identity verified");
				}
				else
				{
					LOG_ERROR("SSL Handshake didn't complete");
					sock_promise.set_value(nullptr);
					return;  // This will restart the connection process
				}
				ssp = sss;
			}
			else
			{
				ssp = new Poco::Net::StreamSocket();
				ssp->connect(sa, connect_timeout_us);
			}

			// Set additional socket options post-connect
			ssp->setSendBufferSize(transmit_buffer_size);
			ssp->setSendTimeout(connection_manager::SOCKET_TIMEOUT_AFTER_CONNECT_US);
			ssp->setReceiveTimeout(connection_manager::SOCKET_TIMEOUT_AFTER_CONNECT_US);

			try
			{
				// This option makes the connection fail earlier in case of unplugged cable
				ssp->setOption(
				    IPPROTO_TCP, TCP_USER_TIMEOUT, connection_manager::SOCKET_TCP_TIMEOUT_MS);
			}
			catch (const std::exception&)
			{
				// ignore if kernel does not support this
				// alternatively, could be a setsockopt() call to avoid exception
			}

			LOG_INFO("Connected to collector");

			sock_promise.set_value(socket_ptr(ssp));
		}
		catch (const Poco::IOException& e)
		{
			// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
			LOG_ERROR(":connect():IOException: " + e.displayText());
			sock_promise.set_value(nullptr);
		}
		catch (const Poco::TimeoutException& e)
		{
			// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
			LOG_ERROR("connect():Timeout: " + e.displayText());
			sock_promise.set_value(nullptr);
		}
		catch (const Poco::InvalidArgumentException& e)
		{
			// SMAGENT-1617
			// In short, this shouldn't happen but it did. Try again and hope for the best!
			LOG_ERROR("connect():InvalidArgument: " + e.displayText());
			LOG_ERROR("\tHost: %s, port %hu", hostname.c_str(), port);
			sock_promise.set_value(nullptr);
			return;
		}
		catch (const std::future_error& e)
		{
			LOG_ERROR("connect():future_error: %s", e.what());
			// We can't touch sock_promise any more in this state
		}
	},
	                           std::ref(m_configuration->m_server_addr),
	                           m_configuration->m_server_port,
	                           m_configuration->m_ssl_enabled,
	                           m_configuration->m_transmitbuffer_size,
	                           m_reconnect_interval,
	                           connect_timeout_us);

	//
	// End thread
	//

	uint32_t waited_time_s = 0;
	const uint32_t wait_for_s = US_TO_S(connect_timeout_us);

	LOG_INFO("Waiting to connect %u s", wait_for_s);
	for (waited_time_s = 0; waited_time_s <= wait_for_s; ++waited_time_s)
	{
		// SMAGENT-1449
		// We can't break out of this loop even if the program is being terminated
		// because the thread has captured some local variables. Come what may, we
		// have to ride out this attempt to connect until the bitter end.
		(void)heartbeat();
		if (future_sock.wait_for(std::chrono::seconds(1)) == std::future_status::ready)
		{
			break;
		}
		++waited_time_s;
	}

	// By calling thread.join(), we are opening up to the possibility that the join()
	// takes so long we get killed by the watchdog. However, keeping in mind we've
	// already waited the entire timeout duration above, if that happens then we're
	// almost certainly hosed anyway.
	connect_thread.join();

	if (waited_time_s >= wait_for_s)
	{
#ifdef SYSDIG_TEST
		m_timed_out = true;
#endif
		LOG_WARNING("Connection attempt timed out. Retrying...");
		disconnect();
		return false;
	}

	if (dragent_configuration::m_terminate)
	{
		LOG_WARNING("Terminated during connection. Aborting.");
		disconnect();
		return false;
	}

	// This shouldn't block at this point
	m_socket = std::move(future_sock.get());

	if (!m_socket)
	{
		LOG_WARNING("Connection attempt failed. Retrying...");
		disconnect();
		return false;
	}
	return m_fsm->send_event(cm_state_machine::event::CONNECTION_COMPLETE);
}

void connection_manager::disconnect()
{
	disconnect(m_socket);
}

void connection_manager::disconnect(socket_ptr& ssp)
{
	if (chrono::system_clock::now() - m_last_connection_failure >= WORKING_INTERVAL_S)
	{
		m_reconnect_interval = RECONNECT_MIN_INTERVAL_S;
	}
	else
	{
		m_reconnect_interval = std::min(
		    std::max(connection_manager::RECONNECT_MIN_INTERVAL_S, m_reconnect_interval * 2),
		    RECONNECT_MAX_INTERVAL_S);
	}

	if (ssp)
	{
		LOG_INFO("Disconnecting from collector");
		ssp->close();
		ssp.reset();
		m_pending_message.reset();
	}
	if (m_fsm)
	{
		m_fsm->send_event(cm_state_machine::event::DISCONNECTED);
	}

#ifndef CYGWING_AGENT
	m_prom_channel = nullptr;
	m_prom_conn = nullptr;
#endif
}

#ifndef CYGWING_AGENT
bool connection_manager::prometheus_connected() const
{
	if (!m_prom_conn)
	{
		return false;
	}

	auto state = m_prom_channel->GetState(true);
	switch (state)
	{
		case GRPC_CHANNEL_IDLE:
		case GRPC_CHANNEL_READY:
			return true;
		default:
			g_logger.format(sinsp_logger::SEV_INFO,
			                "Connection to prometheus exporter in state %d",
			                (int)state);
			return false;
	}
}
#endif

void connection_manager::fsm_reinit()
{
	m_fsm = build_fsm(this, false);
}

void connection_manager::do_run()
{
	if (!init())
	{
		THROW_DRAGENT_WR_FATAL_ERROR("initialization failed");
	}
	ASSERT(m_fsm->get_state() == cm_state_machine::state::INIT);

	std::shared_ptr<serialized_buffer> item;

	while (heartbeat())
	{
		//
		// Make sure we have a valid connection
		//
		if (!is_connected())
		{
			if (!m_fsm->send_event(cm_state_machine::event::CONNECT))
			{
				LOG_WARNING("Attempting to connect in bogus state " +
				             to_string((int)m_fsm->get_state()));
				fsm_reinit();
				continue;
			}
			if (!heartbeat())
			{
				break;
			}

#ifndef CYGWING_AGENT
			if (m_configuration->m_promex_enabled)
			{
				const string& url =
				    m_configuration->m_promex_connect_url.empty()
				        ? "unix:" + m_configuration->c_root_dir.get_value() + "/run/promex.sock"
				        : m_configuration->m_promex_connect_url;
				m_prom_channel = libsinsp::grpc_channel_registry::get_channel(url);
				m_prom_conn = make_shared<promex_pb::PrometheusExporter::Stub>(m_prom_channel);
			}
#endif
			if (!connect())
			{
				continue;
			}
		}

		ASSERT(m_fsm->get_state() == cm_state_machine::state::STEADY_STATE);
		LOG_INFO("Processing messages");

		//
		// The main loop while the connection is established
		//
		while (heartbeat() && is_connected())
		{
			//
			// Check if we received a message. It is possible that the elastic load
			// balancers could cause connect() to succeed but then cause a
			// disconnect on first I/O, so we make sure to do a read before removing
			// an item from the queue.
			//
			if (!receive_message())
			{
				LOG_WARNING("Receive failed. Looping back to reconnect.");
				break;
			}

			if (m_pending_message.is_complete())
			{
				// Now the message is complete. Process it and reset the buffer.
				(void)handle_message();
				m_pending_message.reset();
			}

			if (!item)
			{
				//
				// Try for 300ms to get a message from the queue
				//
				m_queue->get(&item, 300);
			}

			if (item)
			{
				if (m_use_handshake && item->message_type == draiosproto::message_type::METRICS)
				{
					dragent_protocol::populate_ids(item, m_generation, ++m_sequence);
				}

				//
				// Got a message, transmit it
				//
				if (transmit_buffer(sinsp_utils::get_current_time_ns(), item))
				{
					item = nullptr;
				}
				// If the transmit is unsuccessful, we fall out of the loop
				// (due to no longer being connected) and hold on to the
				// item we popped so we can send it once we've reconnected.
			}
		}  // End while (main loop)
	}      // End while (heartbeat)
	m_fsm->send_event(cm_state_machine::event::SHUTDOWN);
}

bool connection_manager::transmit_buffer(uint64_t now, std::shared_ptr<serialized_buffer>& item)
{
	// Sometimes now can be less than ts_ns. The timestamp in
	// metrics messages is rounded up to the following metrics
	// interval.

	if (now > item->ts_ns && (now - item->ts_ns) > 5000000000UL)
	{
		LOG_WARNING("Transmitting delayed message. type=" + to_string(item->message_type) +
		            ", now=" + to_string(now) + ", ts=" + to_string(item->ts_ns) + ", delay_ms=" +
		            to_string((now - item->ts_ns) / 1000000.0));
	}

	// Build a header for the item
	dragent_protocol_header_v4 header;

	header.messagetype = item->message_type;
	header.len = htonl(sizeof(header) + item->buffer.size());
	header.version = dragent_protocol::PROTOCOL_VERSION_NUMBER;

#ifndef CYGWING_AGENT
	if (item->message_type == draiosproto::message_type::METRICS && prometheus_connected())
	{
		grpc::ClientContext context;
		auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(20);
		context.set_deadline(deadline);

		draiosproto::metrics msg;
		promex_pb::PrometheusExporterResponse response;

		try
		{
			parse_protocol_queue_item(*item, &msg);
			// XXX: this is blocking
			m_prom_conn->EmitMetrics(&context, msg, &response);
		}
		catch (const dragent_protocol::protocol_error& ex)
		{
			LOG_WARNING("%s", ex.what());
		}
	}
#endif

	try
	{
		if (!m_socket)
		{
			return false;
		}

		int32_t res = m_socket->sendBytes((uint8_t*)&header, sizeof(header));
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
		    res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			return false;
		}
		if (res != (int32_t)sizeof(header))
		{
			LOG_ERROR("sendBytes sent just " + NumberFormatter::format(res) + ", expected " +
			          NumberFormatter::format(item->buffer.size()));

			disconnect();

			ASSERT(false);
			return false;
		}

		res = m_socket->sendBytes(item->buffer.data(), item->buffer.size());
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
		    res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			return false;
		}

		if (res != (int32_t)item->buffer.size())
		{
			LOG_ERROR("sendBytes sent just " + NumberFormatter::format(res) + ", expected " +
			          NumberFormatter::format(item->buffer.size()));

			disconnect();

			ASSERT(false);
			return false;
		}

		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		LOG_INFO("Sent msgtype=" + to_string((int)item->message_type) + " len=" +
		         Poco::NumberFormatter::format(sizeof(header) + item->buffer.size()) +
		         " to collector");

		return true;
	}
	catch (const Poco::IOException& e)
	{
		// When the underlying socket times out without sending data, this
		// results in a TimeoutException for SSL connections and EWOULDBLOCK
		// for non-SSL connections, so we'll treat them the same.
		if ((e.code() == POCO_EWOULDBLOCK) || (e.code() == POCO_EAGAIN))
		{
			// We shouldn't risk hanging indefinitely if the EWOULDBLOCK is
			// caused by an attempted send larger than the buffer size
			if (item->buffer.size() > m_configuration->m_transmitbuffer_size)
			{
				LOG_ERROR("transmit larger than bufsize failed (" +
				          NumberFormatter::format(item->buffer.size()) + ">" +
				          NumberFormatter::format(m_configuration->m_transmitbuffer_size) + "): " +
				          e.displayText());
				disconnect();
			}
			else
			{
				LOG_DEBUG("transmit: Ignoring: " + e.displayText());
			}
		}
		else
		{
			LOG_ERROR("transmit:IOException: " + e.displayText());
			disconnect();
		}
	}
	catch (const Poco::TimeoutException& e)
	{
		LOG_DEBUG("transmit:Timeout: " + e.displayText());
	}

	return false;
}

bool connection_manager::receive_message()
{
	dragent_protocol_header_v4* v4_hdr = nullptr;

	try
	{
		if (!m_socket)
		{
			return false;
		}

		// If the socket has nothing readable, return
		// immediately. This ensures that when the queue has
		// multiple items queued we don't limit the rate at
		// which we dequeue and send messages.
		if (!m_socket->poll(Poco::Timespan(), Poco::Net::Socket::SELECT_READ))
		{
			return true;
		}

		if (!m_pending_message.m_pending)
		{
			ASSERT(m_pending_message.m_buffer_used == 0);

			// We begin by reading and processing the protocol header
			uint32_t bytes_read = 0;
			const uint32_t bytes_to_read = sizeof(dragent_protocol_header_v4);
			while (bytes_read < bytes_to_read)
			{
				int32_t res =
				    m_socket->receiveBytes(m_pending_message.m_buffer.begin() + bytes_read,
				                           bytes_to_read - bytes_read,
				                           MSG_WAITALL);
				if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ)
				{
					// But we just did a read?
					LOG_ERROR("SSL handshake error (reading message)");
					disconnect();
					ASSERT(false);
					return false;
				}
				if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
				{
					// This case will return true so we can go to the write case
					return true;
				}

				if (res == 0)
				{
					LOG_ERROR("Lost connection (reading header)");
					disconnect();
					return false;
				}
				if (res > 0)
				{
					bytes_read += res;
				}
				if (res < 0)
				{
					LOG_ERROR("Connection error while reading: " + NumberFormatter::format(res));
					disconnect();
					ASSERT(false);
					return false;
				}
			}

			ASSERT(bytes_read == bytes_to_read);
			m_pending_message.m_pending = true;
			v4_hdr = (dragent_protocol_header_v4*)m_pending_message.m_buffer.begin();
			v4_hdr->len = ntohl(v4_hdr->len);

			if ((v4_hdr->len < sizeof(dragent_protocol_header_v4)) ||
			    (v4_hdr->len > MAX_RECEIVER_BUFSIZE))
			{
				LOG_ERROR("Protocol error: invalid header length " +
				          NumberFormatter::format(v4_hdr->len));
				ASSERT(false);
				disconnect();
				return false;
			}

			if (v4_hdr->len > m_pending_message.m_buffer.size())
			{
				m_pending_message.m_buffer.resize(v4_hdr->len);
			}

			m_pending_message.m_buffer_used = bytes_read;
		}

		// Then we read the actual message, it may arrive in
		// several chunks, in this case the function will be called
		// at the next loop cycle and will continue reading
		v4_hdr = (dragent_protocol_header_v4*)m_pending_message.m_buffer.begin();
		uint32_t used_buf = m_pending_message.m_buffer_used;

		auto res = m_socket->receiveBytes(m_pending_message.m_buffer.begin() + used_buf,
		                                  v4_hdr->len - used_buf,
		                                  MSG_WAITALL);

		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ)
		{
			// But we just did a read?
			LOG_ERROR("SSL handshake error (reading message)");
			disconnect();
			ASSERT(false);
			return false;
		}
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			// This case will return true so we can go to the write case
			return true;
		}

		if (res <= 0)
		{
			std::string error_msg = "Lost connection (reading message)";

			if (res < 0)
			{
				error_msg = "Connection error while reading: " + NumberFormatter::format(res);
			}
			LOG_ERROR("%s", error_msg.c_str());
			disconnect();
			ASSERT(false);
			return false;
		}

		m_pending_message.m_buffer_used += res;
		LOG_DEBUG("Receiving message version=" + NumberFormatter::format(v4_hdr->version) +
		          " len=" + NumberFormatter::format(v4_hdr->len) + " messagetype=" +
		          NumberFormatter::format(v4_hdr->messagetype) + " received=" +
		          NumberFormatter::format(m_pending_message.m_buffer_used));

		if (m_pending_message.m_buffer_used > v4_hdr->len)
		{
			LOG_ERROR("Protocol out of sync, disconnecting");
			disconnect();
			ASSERT(false);
			return false;
		}
	}
	catch (const dragent_protocol::protocol_error& e)
	{
		// The message handle failed to take the buffer and convert it
		// into the relevant message type.
		LOG_ERROR("Protocol error: %s", e.what());
	}
	catch (const Poco::IOException& e)
	{
		LOG_ERROR("receive:IOException: " + e.displayText());
		disconnect();
		return false;
	}
	catch (const Poco::TimeoutException& e)
	{
		LOG_DEBUG("receive:Timeout: " + e.displayText());
		// Timeout currently returns true on purpose
	}
	return true;
}

bool connection_manager::handle_message()
{
	if (!m_pending_message.m_pending || !m_pending_message.v4_header())
	{
		return false;
	}

	if (m_pending_message.get_version() != dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		LOG_ERROR("Received command for incompatible version protocol " +
		          NumberFormatter::format(m_pending_message.get_version()));
		return false;
	}

	draiosproto::message_type type =
	    static_cast<draiosproto::message_type>(m_pending_message.get_type());

	LOG_INFO("Received command " +
	         NumberFormatter::format(m_pending_message.get_type()) +
	         " (" + draiosproto::message_type_Name(type) + ")");

	uint32_t header_len = dragent_protocol::header_len(*m_pending_message.v4_header());

	message_handler_map::const_iterator itr = m_handler_map.find(type);
	if (itr != m_handler_map.end())
	{
		uint32_t payload_len = m_pending_message.get_total_length() - header_len;
		uint8_t* payload = m_pending_message.payload();

		ASSERT(m_pending_message.m_buffer_used == header_len + payload_len);
		if (payload_len > 0 && payload)
		{
			itr->second->handle_message(type, payload, payload_len);
		}
	}
	else
	{
		LOG_ERROR("Unknown message type: %d", m_pending_message.get_type());
		return false;
	}
	return true;
}
