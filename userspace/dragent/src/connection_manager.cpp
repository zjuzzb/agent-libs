#include "connection_manager.h"
#include "capture_job_handler.h"
#include "common_logger.h"
#include "handshake.pb.h"
#include "draios.pb.h"
#include "feature_manager.h"
#include "protocol.h"
#include "protobuf_compression.h"
#include "running_state.h"
#include "spinlock.h"
#include "uptime.h"
#include "utils.h"
#include "watchdog_runnable_fatal_error.h"
#include "async_aggregator.h" // For aggregator limits
#include "cm_proxy_tunnel.h"
#include "cm_socket.h"
#include <future>
#include <errno.h>
#include <memory>
#include <Poco/Net/SSLException.h>
#include <functional>
#include <chrono>

#include <grpc_channel_registry.h>

type_config<uint32_t> c_unacked_message_slots(
        3,
        "Number of slots for metrics messages with pending acknowledgements",
        "unacked_message_slots");

type_config<uint32_t> c_reconnect_max_backoff_s(
        360,
        "The ceiling for the exponential backoff on error, in seconds.",
        "reconnect_max_backoff");

type_config<uint32_t> c_transmit_delay_ms(
        1,
        "Timeout for send and receive operations to the collector, in milliseconds.",
        "transmit_delay");

type_config<std::string> c_proxy_host(
        "",
        "Address or hostname of an HTTP proxy server to connect through. "
        "Requires proxy_port to also be set.",
        "http_proxy",
        "proxy_host");

type_config<uint32_t> c_proxy_port(
        0,
        "Port of an HTTP proxy server to connect through. "
        "Requires proxy_host to also be set.",
        "http_proxy",
        "proxy_port");

type_config<std::string> c_proxy_user(
        "",
        "Username for HTTP authentication. "
        "Setting the username enables sending proxy authentication credentials.",
        "http_proxy",
        "proxy_user");

type_config<std::string> c_proxy_password(
        "",
        "Password for HTTP authentication.",
        "http_proxy",
        "proxy_password");

type_config<bool> c_proxy_ssl(
        false,
        "Use SSL to connect to proxy.",
        "http_proxy",
        "ssl");

type_config<uint64_t>::ptr c_unacked_message_timeout = type_config_builder<uint64_t>(
        8*60 /*8 minute default*/,
        "Timeout for unacked metrics messages.",
        "watchdog",
        "connection_manager_unacked_timeout_s")
	.min(60 /*1 minute min*/)
	.build();

using namespace std;
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::time_point;

#define US_TO_S(_usec) ((_usec) / (1000 * 1000))

COMMON_LOGGER();

const seconds connection_manager::RECONNECT_MIN_INTERVAL(1);
const seconds DEFAULT_WORKING_INTERVAL(10);
const milliseconds SEND_TIME_LOG_INTERVAL(500);

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
	return cm_state_machine::state::RETRYING;
}
cm_state_machine::state shutdown_received_in_any_state(connection_manager* cm)
{
	return cm_state_machine::state::TERMINATED;
}

std::unique_ptr<cm_state_machine> build_fsm(connection_manager* cm,
                                            bool v5,
                                            cm_state_machine::state state = cm_state_machine::state::INIT)
{
	auto ret = make_unique<cm_state_machine>(cm, state);

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
 * --- Receive and (optionally) dispatch one incoming message, if present
 * --- Send one message from the outgoing queue
 *
 * If the connection is lost, do_run() will loop back to the top and try to
 * connect again, looping until the agent is terminated.
 *
 * NOTE: receive works in chunks. The received data are aggregated in the
 *       m_pending_message structure until all data have been received. At
 *       that point, the now-complete message is passed to handle_message to be
 *       handled appropriately.
 */

connection_manager::connection_manager(dragent_configuration* configuration,
    protocol_queue* queue,
    std::initializer_list<dragent_protocol::protocol_version> supported_protocol_versions,
    std::initializer_list<message_handler_map::value_type> message_handlers)
    : dragent::running_state_runnable("connection_manager"),
      m_handler_map(message_handlers),
      m_supported_protocol_versions(supported_protocol_versions),
      // Why isn't this configurable via the constructor?
      // Because right now there's not really a good use case for it. I'm
      // including the infrastructure here so that if there's a later need
      // to plumb it through it will be easy than if it were a hard coded
      // list in the protocol hander.
      m_supported_compression_methods({protocol_compression_method::NONE,
                                       protocol_compression_method::GZIP}),
      m_supported_aggregation_intervals({10}),
      m_supported_custom_metric_limits({draiosproto::custom_metric_limit_value::CUSTOM_METRIC_DEFAULT, 
                                        draiosproto::custom_metric_limit_value::CUSTOM_METRIC_10k, 
                                        draiosproto::custom_metric_limit_value::CUSTOM_METRIC_20k,
                                        draiosproto::custom_metric_limit_value::CUSTOM_METRIC_50k,
                                        draiosproto::custom_metric_limit_value::CUSTOM_METRIC_100k}),
      m_socket(nullptr),
      m_generation(1),
      m_sequence(1),
      m_configuration(configuration),
      m_queue(queue),
      m_negotiated_aggregation_interval(UINT32_MAX),
      m_negotiated_compression_method(nullptr),
      m_negotiated_protocol_version(0),
      m_reconnect_interval(0),
      m_working_interval(DEFAULT_WORKING_INTERVAL),
      m_last_metrics_ack_uptime_s(0)
{
	Poco::Net::initializeSSL();

	set_message_handler(draiosproto::message_type::ERROR_MESSAGE,
	                    std::make_shared<error_message_handler>(this));

	dragent_protocol::protocol_version ver = get_max_supported_protocol_version();

	fsm_reinit(ver);

	if (ver == dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		// If forced into legacy mode, there is no negotiation.
		m_negotiated_protocol_version = dragent_protocol::PROTOCOL_VERSION_NUMBER;
	}
}

connection_manager::~connection_manager()
{
	Poco::Net::uninitializeSSL();
}

bool connection_manager::init()
{

	m_protobuf_file_emitter.reset(new dragent::protobuf_file_emitter(m_configuration->c_root_dir.get_value()));

	if (m_configuration->m_server_addr == "" || m_configuration->m_server_port == 0)
	{
		LOG_WARNING("Server address has not been specified");
		return false;
	}

	return true;
}

bool connection_manager::connect()
{
	LOG_INFO("Initiating connection to collector");
	ASSERT(m_fsm->get_state() == cm_state_machine::state::CONNECTING);

	std::promise<cm_socket::ptr> sock_promise;
	std::future<cm_socket::ptr> future_sock = sock_promise.get_future();
	std::atomic<bool> terminate(false);

	//
	// Asynchronously connect to the collector
	//
	// Since sock_promise is captured by reference, need to ensure that it
	// doesn't go out of scope until the thread ends.
	//
	std::thread connect_thread([&sock_promise, &terminate](const string& hostname,
	                                                       const uint16_t port,
	                                                       bool ssl_enabled,
	                                                       const seconds reconnect_interval,
	                                                       std::vector<std::string>& ca_cert_paths,
	                                                       std::string& ssl_ca_certificate)
	{
		cm_socket::ptr sockptr = nullptr;

		try
		{
			// Reconnect backoff
			// How reconnect backoff works, briefly:
			//  * The backoff starts at 0
			//  * The first disconnect(), the backoff is set to RECONNECT_MIN_INTERVAL
			//    (currently 1 second)
			//  * Every subsequent disconnect, the backoff is doubled
			//  * If the connection is determined to be working, reset to 0
			//     * For protocol v4, working means connected for more than
			//       m_working_interval
			//     * For protocol v5, working means successful handshake
			std::chrono::seconds time_slept = std::chrono::seconds(0);
			LOG_INFO("Connect backoff: waiting for %ld seconds",
			         reconnect_interval.count());
			while (time_slept < reconnect_interval && !terminate)
			{
				std::chrono::seconds time_to_sleep = std::chrono::seconds(1);
				std::this_thread::sleep_for(time_to_sleep);
				time_slept += time_to_sleep;
			}

			if (terminate)
			{
				LOG_INFO("Aborting connection attempt because agent is terminating.");
				sock_promise.set_value(nullptr);
				return;
			}

			// Choose which type of socket we're using

			if (!c_proxy_host.get_value().empty() && c_proxy_port.get_value() != 0)
			{
				// Connect through proxy
				sockptr = http_tunnel::establish_tunnel({c_proxy_host.get_value(),
				                                         (uint16_t)c_proxy_port.get_value(),
				                                         hostname,
				                                         port,
				                                         c_proxy_user.get_value(),
				                                         c_proxy_password.get_value(),
				                                         ssl_enabled,
				                                         c_proxy_ssl.get_value(),
				                                         ca_cert_paths,
				                                         ssl_ca_certificate});
			}
			else if (ssl_enabled)
			{
				// Connect through encrypted socket
				sockptr = std::make_shared<cm_poco_secure_socket>(ca_cert_paths,
				                                                  ssl_ca_certificate);
				if (sockptr && !sockptr->connect(hostname, port))
				{
					sockptr = nullptr;
				}
			}
			else
			{
				// Unencrypted socket
				sockptr = std::make_shared<cm_poco_socket>();
				if (sockptr && !sockptr->connect(hostname, port))
				{
					sockptr = nullptr;
				}
			}

			if (sockptr == nullptr)
			{
				sock_promise.set_value(nullptr);
				return;
			}
			LOG_INFO("Connected to collector");

			sock_promise.set_value(sockptr);
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
	                           m_reconnect_interval,
	                           std::ref(m_configuration->m_ssl_ca_cert_paths),
	                           std::ref(m_configuration->m_ssl_ca_certificate));
	//
	// End thread
	//

	uint32_t waited_time_s = 0;
	const seconds wait_for = duration_cast<seconds>(cm_socket::get_default_connect_timeout() +
	                                                m_reconnect_interval);

	LOG_INFO("Waiting to connect %ld s", wait_for.count());
	for (waited_time_s = 0; waited_time_s <= wait_for.count(); ++waited_time_s)
	{
		// SMAGENT-1449
		// We can't break out of this loop even if the program is being terminated
		// because the thread has captured some local variables. Come what may, we
		// have to ride out this attempt to connect until the std::future is set.
		if (!heartbeat())
		{
			terminate = true;
		}
		if (future_sock.wait_for(std::chrono::seconds(1)) == std::future_status::ready)
		{
			break;
		}
	}

	// By calling thread.join(), we are opening up to the possibility that the join()
	// takes so long we get killed by the watchdog. However, keeping in mind we've
	// already waited the entire timeout duration above, if that happens then we're
	// almost certainly hosed anyway.
	connect_thread.join();

	if (waited_time_s >= wait_for.count())
	{
#ifdef SYSDIG_TEST
		m_timed_out = true;
#endif
		LOG_WARNING("Connection attempt timed out. Retrying...");
		disconnect();
		return false;
	}

	if (dragent::running_state::instance().is_terminated())
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
	if (m_reconnect_interval.count() == 0)
	{
		// Back off slightly just to prevent slamming the collector
		// with reconnects in the case the collector is down
		m_reconnect_interval = RECONNECT_MIN_INTERVAL;
	}
	if (m_socket)
	{
		LOG_INFO("Disconnecting from collector");
		m_socket->close();
	}
	if (m_fsm)
	{
		m_fsm->send_event(cm_state_machine::event::DISCONNECTED);
	}

	m_pending_message.reset();

#ifndef CYGWING_AGENT
	m_prom_channel = nullptr;
	m_prom_conn = nullptr;
#endif
	m_last_metrics_ack_uptime_s = 0;
}

void connection_manager::disconnect_and_backoff()
{
	// Update exponential backoff
	if (m_reconnect_interval.count() == 0)
	{
		m_reconnect_interval = RECONNECT_MIN_INTERVAL;
	}
	else
	{
		m_reconnect_interval *= 2;
		m_reconnect_interval = std::max(connection_manager::RECONNECT_MIN_INTERVAL,
		                                m_reconnect_interval);
		m_reconnect_interval = std::min(seconds(c_reconnect_max_backoff_s.get_value()),
		                                m_reconnect_interval);
	}
	disconnect();
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

void connection_manager::fsm_reinit(dragent_protocol::protocol_version working_protocol_version,
                                    cm_state_machine::state state)
{
	bool v5 = true;
	if (working_protocol_version == dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		v5 = false;
	}

	m_fsm = build_fsm(this, v5, state);
}

void connection_manager::do_run()
{
	if (!init())
	{
		THROW_WATCHDOG_RUNNABLE_FATAL_ERROR("initialization failed");
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
				fsm_reinit(get_max_supported_protocol_version());
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

		//
		// Send the handshake in the case of >= v5 protocol
		//
		if (m_fsm->get_state() == cm_state_machine::state::HANDSHAKE)
		{
			LOG_INFO("Performing protocol handshake");
			// Handshake logic for handshake-enabled protocol
			if (m_sequence > 1)
			{
				// Generation number is only increased if the agent has sent
				// a single non-protocol message
				m_generation++;
			}
			m_sequence = 1;

			if (!perform_handshake())
			{
				// Handshake failed. Try again.
				// NOTE: It's very possible that the connect() succeeds due to
				//       elastic load balancers but then the handshake fails.
				continue;
			}
		}

		ASSERT(m_fsm->get_state() == cm_state_machine::state::STEADY_STATE);
		LOG_INFO("Processing messages");

		//
		// The main loop while the connection is established
		//
		m_last_connect = steady_clock::now();
		milliseconds transmit_delay = milliseconds(c_transmit_delay_ms.get_value());
		while (heartbeat() && is_connected())
		{
			// Check if we received a message
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
				//
				// Got a message, transmit it
				//

				// SMAGENT-2427
				// Don't overwhelm OpenSSL and the network stack when we have
				// a lot of messages to send at once.
				std::this_thread::sleep_for(milliseconds(transmit_delay));

				// Build the header
				// Note that we use the v5 header here, but if the protocol
				// version is v4 then we just use the legacy fields of the
				// header.
				dragent_protocol_header_v5 header;
				if (!build_protocol_header(item,
				                           get_current_protocol_version(),
				                           header,
				                           m_generation,
				                           m_sequence))
				{
					LOG_ERROR("Error building protocol header. Reconnecting");
					disconnect();
					continue;
				}
				if (transmit_buffer(sinsp_utils::get_current_time_ns(),
				                    &header,
				                    item))
				{
					if (item->message_type == draiosproto::message_type::METRICS)
					{
						on_metrics_send(header, item);
					}

					// Possibly write to local files
					if(!m_protobuf_file_emitter->emit(item))
					{
						LOG_DEBUG("Protobuf file not written");
					}

					item = nullptr;
				}
				// If the transmit is unsuccessful, we fall out of the loop
				// (due to no longer being connected) and hold on to the
				// item we popped so we can send it once we've reconnected.
			}
		}  // End while (main loop)
	}      // End while (heartbeat)
	disconnect();
	m_fsm->send_event(cm_state_machine::event::SHUTDOWN);
}

/**
 * Returns the protocol version the connection manager is currently running.
 *
 * Getting this number is a little bit more complicated than it may seem, and
 * is subject to a couple of rules that may not be intuitive at first.
 *
 * - A connection must be established for there to be a current version. If a
 *   connection has not been established or if the connection has dropped, the
 *   current version is 0, denoting that the version is not known.
 *
 * - If a connection has been established and a handshake is being performed,
 *   the current version is still 0 as the version has not been negotiated yet.
 *   The exception to this rule is if the connection manager has been forced into
 *   legacy mode via a configuration. In that case, after the connection has
 *   been established the current version will immediately become the legacy
 *   version (4).
 *
 * A return value of 0 denotes that there is no current protocol version (or,
 * more specifically, that the current protocol version is unknown).
 */
dragent_protocol::protocol_version connection_manager::get_current_protocol_version()
{
	switch (m_fsm->get_state())
	{
	case cm_state_machine::state::STEADY_STATE:
		// This case is easy. Just return the negotiated protocol version.
		return m_negotiated_protocol_version;
	case cm_state_machine::state::HANDSHAKE:
		// We *might* have a protocol version in handshake, depending on
		// what phase we're in. The handshake code will explicitly set
		// the negotiated version to 0 to ensure we can always rely on
		// this field
		return m_negotiated_protocol_version;
	case cm_state_machine::state::NONE:
	case cm_state_machine::state::NUM_STATES:
		// This shouldn't happen
		ASSERT(m_fsm->get_state() != cm_state_machine::state::NONE);
		ASSERT(m_fsm->get_state() < cm_state_machine::state::NUM_STATES);
		// Fallthrough
	case cm_state_machine::state::CONNECTING:
	case cm_state_machine::state::RETRYING:
	case cm_state_machine::state::TERMINATED:
	case cm_state_machine::state::INIT:
		return 0;
	}

	ASSERT("How did we get here?" == 0);
	return 0;
}

/**
 * Returns the highest protocol version this connection manager supports.
 *
 * In the bogus case when there are no supported protocol versions, returns 0.
 */
dragent_protocol::protocol_version connection_manager::get_max_supported_protocol_version()
{
	dragent_protocol::protocol_version max_ver = 0;

	for(auto& v: m_supported_protocol_versions)
	{
		ASSERT(v == dragent_protocol::PROTOCOL_VERSION_NUMBER ||
		       v == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);
		if (v > max_ver)
		{
			max_ver = v;
		}
	}
	return max_ver;
}

bool connection_manager::send_proto_init()
{
	uint64_t now = sinsp_utils::get_current_time_ns();
	const string& customer_id = m_configuration->m_customer_id;
	const string& machine_id = m_configuration->machine_id();

	draiosproto::protocol_init msg_pi;

	msg_pi.set_timestamp_ns(now);
	msg_pi.set_machine_id(machine_id);
	msg_pi.set_customer_id(customer_id);
	ASSERT(m_supported_protocol_versions.size() > 0);
	for (auto v: m_supported_protocol_versions)
	{
		msg_pi.add_supported_protocol_versions(v);
	}

	// Get the default compressor
	auto compressor =
	        protobuf_compressor_factory::get(protobuf_compressor_factory::get_default());

	// Serialize the message
	std::shared_ptr<serialized_buffer>
	msg_buf = dragent_protocol::message_to_buffer(now,
	                                              draiosproto::message_type::PROTOCOL_INIT,
	                                              msg_pi,
	                  /* Send uncompressed */     compressor);
	if (!msg_buf)
	{
		LOG_ERROR("Fatal error serializing first handshake message");
		return false;
	}

	dragent_protocol_header_v5 header;
	bool ret = build_protocol_header(msg_buf,
	                                 dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                 header);

	if (!ret)
	{
		LOG_ERROR("Fatal error building first handshake message header");
		return false;
	}

	return transmit_buffer(now, &header.hdr, msg_buf);
}

bool connection_manager::send_handshake_negotiation()
{
	uint64_t now = sinsp_utils::get_current_time_ns();
	const string& customer_id = m_configuration->m_customer_id;
	const string& machine_id = m_configuration->machine_id();

	draiosproto::handshake_v1 msg_hs;

	msg_hs.set_timestamp_ns(now);
	msg_hs.set_machine_id(machine_id);
	msg_hs.set_customer_id(customer_id);

	// Figure out what our supported compression methods are
	for (auto c: m_supported_compression_methods)
	{
		switch (c)
		{
		case protocol_compression_method::NONE:
			msg_hs.add_supported_compressions(draiosproto::compression::COMPRESSION_NONE);
			break;
		case protocol_compression_method::GZIP:
			msg_hs.add_supported_compressions(draiosproto::compression::COMPRESSION_GZIP);
			break;
		}
	}

	// Add supported aggregation intervals
	for (auto i: m_supported_aggregation_intervals)
	{
		msg_hs.add_supported_agg_intervals(i);
	}

	// Add supported custom metric limits
	for (auto l: m_supported_custom_metric_limits)
	{
		msg_hs.add_supported_custom_metric_limits(l);
	}

	// Get the default compressor
	auto compressor =
	        protobuf_compressor_factory::get(protobuf_compressor_factory::get_default());

	feature_manager::instance().to_protobuf(*msg_hs.mutable_features());

	// Serialize the message
	std::shared_ptr<serialized_buffer>
	msg_buf = dragent_protocol::message_to_buffer(now,
	                                              draiosproto::message_type::PROTOCOL_HANDSHAKE_V1,
	                                              msg_hs,
	                                              compressor);
	if (!msg_buf)
	{
		LOG_ERROR("Fatal error serializing second handshake message");
		return false;
	}

	ASSERT(m_sequence == 1);
	ASSERT(get_current_protocol_version() ==
	        dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);
	dragent_protocol_header_v5 header;
	bool ret = build_protocol_header(msg_buf,
	                                 get_current_protocol_version(),
	                                 header,
	                                 m_generation,
	                                 m_sequence);

	if (!ret)
	{
		LOG_ERROR("Fatal error building first handshake message header");
		return false;
	}
	return transmit_buffer(sinsp_utils::get_current_time_ns(),
	                       &header,
	                       msg_buf);
}

bool connection_manager::perform_handshake()
{
	//
	// Phase 1
	//

	// Set this to 0 since we don't have a version yet
	m_negotiated_protocol_version = 0;

	// Send the first handshake message
	if (!send_proto_init())
	{
		LOG_ERROR("Could not send initial handshake message. Disconnecting");
		disconnect();
		return false;
	}

	// Receive and process response
	time_point<steady_clock> start = steady_clock::now();
	const seconds timeout = duration_cast<seconds>(m_socket->get_connect_timeout());
	LOG_INFO("Waiting for %d seconds for handshake to complete", (int)timeout.count());
	do {
		bool ret = receive_message();
		if (!ret)
		{
			LOG_ERROR("Receive failed on handshake. Looping back to reconnect.");
			disconnect();
			return false;
		}
		if (!m_pending_message.is_complete())
		{
			std::this_thread::sleep_for(milliseconds(5));
		}
		// Check for timeout
		milliseconds elapsed = duration_cast<milliseconds>(steady_clock::now() - start);
		if (elapsed > m_socket->get_connect_timeout())
		{
			LOG_ERROR("Handshake timed out after %d seconds. Reconnecting.",
			          (int)timeout.count());
			disconnect();
			return false;
		}
	} while (!m_pending_message.is_complete() && heartbeat());

	if (!heartbeat())
	{
		// We connected successfully but the agent is terminating
		return false;
	}

	const dragent_protocol_header_v4* header = m_pending_message.v4_header();

	if (header->messagetype != draiosproto::message_type::PROTOCOL_INIT_RESP)
	{
		if (header->messagetype == draiosproto::message_type::ERROR_MESSAGE)
		{
			// Parse the error message to see what it is
			draiosproto::error_message err_msg;
			uint32_t payload_len = m_pending_message.get_total_length() -
			                       dragent_protocol::header_len(*header);
			dragent_protocol::buffer_to_protobuf(m_pending_message.payload(),
			                                     payload_len,
			                                     &err_msg);
			m_pending_message.reset();

			draiosproto::error_type err_type = err_msg.type();
			switch (err_type)
			{
			// PROTO_MISMATCH is sent by the backend when it doesn't understand
			// a message it's received. Seeing it here either means that the
			// collector does not speak proto v5 or that the collector saw
			// something in the proto_init that it didn't like and wants to
			// fallback to legacy.
			case draiosproto::error_type::ERR_PROTO_MISMATCH:
				LOG_WARNING("Protocol mismatch: Received error attempting handshake. "
				            "Falling back to legacy mode.");

				// Change configs
				set_legacy_mode();

				// Reset the FSM
				// Why reset the FSM rather than having this be a valid transition?
				// Because the FSM needs to be reinitialized for the new protocol
				// version.
				fsm_reinit(m_negotiated_protocol_version,
				           cm_state_machine::state::STEADY_STATE);
				return true;

			case draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY:
				// Perform exponential backoff
				LOG_ERROR("Received error message: INVALID_CUSTOMER_KEY");
				disconnect_and_backoff();
				return false;

			default:
				// This is a different error
				std::string err_string = draiosproto::error_type_Name(err_type);
				LOG_ERROR("Protocol error: received error message from collector: " +
				          err_string + ": " + err_msg.description());
				disconnect();
				return false;
			}
		}
		else
		{
			LOG_ERROR("Protocol error: unexpected handshake response (%d)",
			          (int)header->messagetype);
		}
		disconnect();
		return false;
	}
	if (!m_fsm->send_event(cm_state_machine::event::HANDSHAKE_PROTO_RESP) ||
	    m_fsm->get_state() != cm_state_machine::state::HANDSHAKE)
	{
		LOG_ERROR("Protocol error: Handshake interrupted");
		disconnect();
		return false;
	}

	// Handle response
	LOG_INFO("Received response of type %d (ver: %d len: %u)",
	         (int)m_pending_message.get_type(),
	         (int)header->version,
	          m_pending_message.m_buffer_used);
	draiosproto::protocol_init_response resp;
	uint32_t payload_len = m_pending_message.get_total_length() -
	                       dragent_protocol::header_len(*header);
	dragent_protocol::buffer_to_protobuf(m_pending_message.payload(),
	                                     payload_len,
	                                     &resp,
	                                     protobuf_compressor_factory::get_default());
	m_pending_message.reset();

	dragent_protocol::protocol_version version = resp.protocol_version();
	bool version_supported = false;
	for (auto supported_version: m_supported_protocol_versions)
	{
		if (version == supported_version)
		{
			version_supported = true;
			break;
		}
	}
	if (!version_supported)
	{
		// Unsupported version
		LOG_ERROR("Protocol error: Unsupported version number " +
		          NumberFormatter::format(version));
		disconnect();
		return false;
	}

	// Set the protocol version
	m_negotiated_protocol_version = version;

	if (version <= dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		// Not supposed to happen
		LOG_ERROR("Protocol error: Version mismatch (legacy protocol selected)");
		set_legacy_mode();
		fsm_reinit(m_negotiated_protocol_version, cm_state_machine::state::STEADY_STATE);
		return true;
	}


	//
	// Phase 2
	//

	if (!send_handshake_negotiation())
	{
		disconnect();
		return false;
	}

	// Receive response
	start = steady_clock::now();
	do {
		bool ret = receive_message();
		if (!ret)
		{
			LOG_WARNING("Receive failed on handshake phase 2. Looping back to reconnect.");
			disconnect();
			return false;
		}

		// Check for timeout
		milliseconds elapsed = duration_cast<milliseconds>(steady_clock::now() - start);
		if (elapsed > m_socket->get_connect_timeout())
		{
			LOG_ERROR("Handshake phase 2 timed out after %d seconds. Reconnecting.",
			          (int)timeout.count());
			disconnect();
			return false;
		}
	} while (!m_pending_message.is_complete() && heartbeat());

	if (!heartbeat())
	{
		disconnect();
		return false;
	}

	header = m_pending_message.v4_header();
	LOG_INFO("Received response of type %d (ver: %d len: %u)",
	         (int)m_pending_message.get_type(),
	         (int)header->version,
	          m_pending_message.m_buffer_used);
	if (header->messagetype != draiosproto::message_type::PROTOCOL_HANDSHAKE_V1_RESP)
	{
		LOG_ERROR("Protocol error: unexpected handshake response");
	}

	if (!m_fsm->send_event(cm_state_machine::event::HANDSHAKE_NEGOTIATION_RESP))
	{
		LOG_ERROR("Protocol error: Handshake failed");
		disconnect();
		return false;
	}

	// Handle response
	draiosproto::handshake_v1_response hs_resp;
	payload_len = m_pending_message.get_total_length() -
	                       dragent_protocol::header_len(*header);
	dragent_protocol::buffer_to_protobuf(m_pending_message.payload(),
	                                     payload_len,
	                                     &hs_resp,
	                                     protobuf_compressor_factory::get_default());
	m_pending_message.reset();

	// Update the negotiated parameters
	{
		protocol_compression_method method = protocol_compression_method::NONE;
		switch(hs_resp.compression())
		{
		case draiosproto::compression::COMPRESSION_NONE:
			method = protocol_compression_method::NONE;
			break;

		case draiosproto::compression::COMPRESSION_GZIP:
			method = protocol_compression_method::GZIP;
			break;

		case draiosproto::compression::COMPRESSION_LZ4:
			// Currently unsupported
			LOG_ERROR("Backend specified unsupported compression method");
			disconnect();
			return false;
		}

		scoped_spinlock lock(m_parameter_update_lock);
		m_negotiated_compression_method = protobuf_compressor_factory::get(method);
		m_negotiated_aggregation_interval = hs_resp.agg_interval();
	}

	// Update the limits
	dragent::aggregator_limits::global_limits->cache_limits(hs_resp.agg_context());

	// Process unacked messages
	process_ack_queue_on_reconnect(hs_resp.last_acked_gen_num(),
	                               hs_resp.last_acked_seq_num());

	set_metric_limit(hs_resp);

	// Reset the exponential backoff
	reset_backoff();

	return true;
}

int32_t connection_manager::send_bytes(uint8_t* buf, uint32_t len)
{
	if (!m_socket)
	{
		return false;
	}
	int64_t res = 0;

	res = m_socket->send(buf, len);
	if (res == -ETIMEDOUT && heartbeat()) // Handle timeout
	{
		// Try again
		LOG_WARNING("Send operation timed out. Retrying...");
		res = m_socket->send(buf, len);
		if (res == -ETIMEDOUT)
		{
			// Already retried once. Kill the connection.
			LOG_ERROR("Internal error: Send operation timed out multiple times.");
			return res;
		}
	}

	if (res < 0)
	{
		// We don't explicitly disconnect here because the error might be
		// recoverable. The caller can choose to disconnect, or not, as
		// desired.
		LOG_ERROR("Error sending message to collector: %d", (int)res);
	}
	else if (res == 0)
	{
		LOG_ERROR("Connection terminated remotely. Reconnecting...");
		// Call disconnect() and update our internal state to match reality
		disconnect();
		return -1;
	}
	else if (res != len)
	{
		// I don't expect us to ever hit this case, but might as well
		// raise a big flag in case we do. If we do hit this case it's
		// probably because the user change the transmit buffer length.
		LOG_ERROR("sendBytes returned %u, expected %u", (uint32_t)res, len);

		disconnect();

		ASSERT(false);
		return -1;
	}

	return res;
}

bool connection_manager::transmit_buffer(uint64_t now,
                                         dragent_protocol_header_v4* header,
                                         std::shared_ptr<serialized_buffer>& item)
{
	ASSERT(header->version == dragent_protocol::PROTOCOL_VERSION_NUMBER);
	// transmit_buffer uses the header's version field to know how much
	// to transmit, so we can safely pass the v4 header as v5 and it won't
	// read the last bytes at all
	return transmit_buffer(now, (dragent_protocol_header_v5*)header, item);
}

bool connection_manager::transmit_buffer(uint64_t now,
                                         dragent_protocol_header_v5* header,
                                         std::shared_ptr<serialized_buffer> &item)
{
	ASSERT(header->hdr.version == dragent_protocol::PROTOCOL_VERSION_NUMBER ||
	       header->hdr.version == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);

	// Sometimes now can be less than ts_ns. The timestamp in
	// metrics messages is rounded up to the following metrics
	// interval.
	if (header->hdr.messagetype == draiosproto::message_type::METRICS &&
	    now > item->ts_ns &&
	    (now - item->ts_ns) > 5000000000UL)
	{
		LOG_WARNING("Transmitting delayed message. type=" + to_string(item->message_type) +
		            ", now=" + to_string(now) + ", ts=" + to_string(item->ts_ns) + ", delay_ms=" +
		            to_string((now - item->ts_ns) / 1000000.0));
	}


#ifndef CYGWING_AGENT
	if (item->message_type == draiosproto::message_type::METRICS && prometheus_connected())
	{
		grpc::ClientContext context;
		auto deadline = std::chrono::system_clock::now() + milliseconds(20);
		context.set_deadline(deadline);

		draiosproto::metrics msg;
		promex_pb::PrometheusExporterResponse response;

		try
		{
			// Deserialize the just-serialized buffer
			parse_protocol_queue_item(*item,
			                          &msg);
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
		// Only send the bits of the header that are appropriate for
		// this header version
		uint32_t send_len = dragent_protocol::header_len(header->hdr);
		if (send_len == 0)
		{
			LOG_ERROR("Incorrect header length detected. Discarding metrics");
			return true; // Returning true will drop the metrics and continue
		}
		LOG_DEBUG("Sending header length %u", send_len);
		int32_t res = send_bytes((uint8_t*)header, send_len);
		if (res < 0)
		{
			return false;
		}

		// Send the payload
		ASSERT(item->buffer.size() <= INT32_MAX);
		LOG_DEBUG("Sending buffer length %u", (uint32_t)item->buffer.size());
		std::chrono::time_point<steady_clock> start = steady_clock::now();

		res = send_bytes((uint8_t*)item->buffer.data(), item->buffer.size());

		milliseconds elapsed =
		    duration_cast<milliseconds>(steady_clock::now() - start);

		if (elapsed > SEND_TIME_LOG_INTERVAL)
		{
			LOG_WARNING("Sending data took %ld ms", elapsed.count());
		}

		if (res == -ETIMEDOUT)
		{
			LOG_WARNING("Transmission timed out (took longer than %u ms). If this "
			            "occurs frequently, increase socket_timeout setting in "
			            "the agent configuration. Attempting reconnect.",
			            (uint32_t)m_socket->get_send_recv_timeout().count());
			// This code used to fall out of this function and retry the send later.
			// However, this will not work anymore as messages are transmitted across
			// two send operations and if the second one timed out, retrying would
			// erroneously send the header twice. Since we've already retried once in
			// send_bytes(), at this point we'll just drop the connection and hope
			// it works better on reconnect.
			disconnect();
		}

		if (res < 0)
		{
			return false;
		}

		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		LOG_INFO("Sent msgtype=" + to_string((int)item->message_type) + " len=" +
		         Poco::NumberFormatter::format(dragent_protocol::header_len(header->hdr) +
		         item->buffer.size()) + " to collector");
		if (header->hdr.version == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH)
		{
			uint64_t gen = ntohll(header->generation);
			uint64_t seq = ntohll(header->sequence);
			LOG_DEBUG("\tGeneration: " + Poco::NumberFormatter::format(gen) +
			         "  Sequence: " + Poco::NumberFormatter::format(seq));
		}

		return true;
	}
	catch (const Poco::IOException& e)
	{
		if ((e.code() == POCO_EWOULDBLOCK) || (e.code() == POCO_EAGAIN))
		{
			LOG_INFO("transmit: Ignoring: " + e.displayText());
		}
		else
		{
			LOG_ERROR("transmit:IOException: " + e.displayText());
			disconnect();
		}
	}
	catch (const Poco::TimeoutException& e)
	{
		// We should have handled this further up the chain...
		LOG_ERROR("transmit: Internal error: received unexpected Poco timeout");
		disconnect();
	}

	return false;
}

bool connection_manager::receive_message()
{
	const dragent_protocol_header_v5* v5_hdr = nullptr;
	const dragent_protocol_header_v4* v4_hdr = nullptr;
	uint32_t msg_len = 0;

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
		if (!m_socket->has_pending())
		{
			return true;
		}

		if (!m_pending_message.m_pending)
		{
			ASSERT(m_pending_message.m_buffer_used == 0);

			//
			// Read the header
			//
			uint32_t bytes_read = 0;
			uint32_t bytes_to_read = sizeof(dragent_protocol_header_v4);
			while (bytes_read < bytes_to_read)
			{
				int64_t res = m_socket->receive(m_pending_message.m_buffer.begin() + bytes_read,
				                                bytes_to_read - bytes_read);
				if (res == 0)
				{
					LOG_ERROR("Lost connection (reading header)");
					disconnect();
					return false;
				}
				if (res < 0)
				{
					LOG_ERROR("Socket error on header read: %d", (int)res);
					disconnect();
					return false;
				}
				if (res > 0)
				{
					// Any sort of overflow here should be impossible, but
					// just to be extra cautious...
					ASSERT(res < UINT32_MAX);
					ASSERT(UINT32_MAX - bytes_read > res);
					bytes_read += res;
				}

				// Check the message version -- may have to read more header bytes
				if (bytes_read >= offsetof(dragent_protocol_header_v4, version))
				{
					auto* v4_hdr = (dragent_protocol_header_v4*)m_pending_message.m_buffer.begin();
					bytes_to_read = dragent_protocol::header_len(*v4_hdr);
					if (bytes_to_read == 0)
					{
						// Whoops, invalid version. We'll sort it out later.
						// The header contains the total length of the message, so
						// one way or another we're going to get it all read.
						bytes_to_read = bytes_read;
					}
				}
			}

			ASSERT(bytes_read == bytes_to_read);
			m_pending_message.m_pending = true;
			v5_hdr = (dragent_protocol_header_v5*)m_pending_message.m_buffer.begin();
			v4_hdr = &v5_hdr->hdr;
			msg_len = ntohl(v4_hdr->len);

			if ((msg_len < sizeof(dragent_protocol_header_v4)) ||
			    (msg_len > MAX_RECEIVER_BUFSIZE))
			{
				LOG_ERROR("Protocol error: invalid header length " +
				          NumberFormatter::format(msg_len));
				ASSERT(false);
				disconnect();
				return false;
			}

			if (msg_len > m_pending_message.m_buffer.size())
			{
				m_pending_message.m_buffer.resize(msg_len);
			}

			m_pending_message.m_buffer_used = bytes_read;
		}

		if (msg_len == m_pending_message.m_buffer_used)
		{
			// Oh hey, we're done!
			// This means the message was an ACK, which is just a header.
			return true;
		}

		// Then we read the actual message, it may arrive in
		// several chunks, in this case the function will be called
		// at the next loop cycle and will continue reading
		v4_hdr = (dragent_protocol_header_v4*)m_pending_message.m_buffer.begin();
		msg_len = ntohl(v4_hdr->len);
		uint32_t used_buf = m_pending_message.m_buffer_used;

		int64_t res;
		bool retry = false;
		do
		{
			res = m_socket->receive(m_pending_message.m_buffer.begin() + used_buf,
			                        msg_len - used_buf);
			if (res == 0)
			{
				LOG_ERROR("Lost connection (reading message body)");
				disconnect();
				return false;
			}
			if (res < 0)
			{
				LOG_ERROR("Socket error on message body read: %d", (int)res);
				disconnect();
				return false;
			}
		} while (retry && heartbeat());

		m_pending_message.m_buffer_used += res;
		LOG_DEBUG("Incoming message version=%d messagetype=%d received=%u / len=%u",
		          (int)v4_hdr->version,
		          (int)v4_hdr->messagetype,
		          m_pending_message.m_buffer_used,
		          msg_len);

		if (m_pending_message.m_buffer_used > msg_len)
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

	if (!dragent_protocol::version_is_valid(m_pending_message.get_version()))
	{
		return handle_invalid_version();
	}

	draiosproto::message_type type =
	    static_cast<draiosproto::message_type>(m_pending_message.get_type());

	// ACK messages are handled specially
	if (type == draiosproto::message_type::PROTOCOL_ACK)
	{
		// Handle the ACK
		auto* v5_hdr = (dragent_protocol_header_v5*)m_pending_message.m_buffer.begin();
		bool ret = on_ack_received(*v5_hdr);
		if (!ret)
		{
			// This can happen in some cases. Example: the connection drops and
			// the agent begins buffering. On reconnect it sends all the buffered
			// messages, then begins sending real-time messages. The un-ACKed
			// messages fill the buffer, pushing the oldest ones out. The
			// collector finally catches up and ACKs a message that was pushed
			// out of the buffer, bringing us to this point.
			// It's an unexpected enough condition that we should log it, but
			// at this point cycling the connection will just make things worse.
			LOG_WARNING("Protocol error: ACK received for unknown message (%llu, %llu). Continuing.",
			            (long long unsigned)ntohll(v5_hdr->generation),
			            (long long unsigned)ntohll(v5_hdr->sequence));
			return true;
		}
		return true;
	}

	LOG_INFO("Received command " +
	         NumberFormatter::format(m_pending_message.get_type()) +
	         " (" + draiosproto::message_type_Name(type) + ")");

	uint32_t header_len = dragent_protocol::header_len(*m_pending_message.v4_header());

	LOG_INFO("    header_len: " +
	         NumberFormatter::format(header_len) +
	         "    length field: " +
	         NumberFormatter::format(m_pending_message.get_total_length()) +
	         "    version field: " +
	         NumberFormatter::format(m_pending_message.get_version())
	         );
	{
		std::lock_guard<std::mutex> lock(m_handler_map_lock);

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
}

void connection_manager::set_message_handler(draiosproto::message_type type, message_handler::ptr handler)
{
	std::lock_guard<std::mutex> lock(m_handler_map_lock);

	if (m_handler_map.find(type) != m_handler_map.end())
	{
		LOG_WARNING("multiple handlers attempting registration for type %d", type);
	}

	m_handler_map[type] = handler;
}

bool connection_manager::handle_invalid_version()
{
#ifdef SYSDIG_TEST
	++m_num_invalid_messages;
#endif
	auto type = static_cast<draiosproto::message_type>(m_pending_message.get_type());
	dragent_protocol::protocol_version version = m_pending_message.get_version();

	LOG_WARNING("Processing message with invalid version field %d", (int)version);

	if (version > dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH)
	{
		// This version is greater than this agent understands. Don't try
		// to do something with it, as it could be anything.
		LOG_ERROR("Protocol error: Received command %d for incompatible protocol version %d",
		          (int)type,
		          (int)version);
		return false;
	}

	// If the backend doesn't know what protocol version this session is it
	// will send a message with the lowest version it supports, which might
	// be lower than what the agent supports.

	if (type == draiosproto::message_type::ERROR_MESSAGE)
	{
		draiosproto::error_message err_msg;
		uint32_t header_len = dragent_protocol::header_len(*m_pending_message.v4_header());
		if (header_len == 0)
		{
			auto v = dragent_protocol::PROTOCOL_VERSION_NUMBER;
			header_len = dragent_protocol::header_len(v);
		}
		uint32_t payload_len = m_pending_message.get_total_length() - header_len;

		// Try to handle the error message
		try
		{
			// payload() is invalid thanks to the invalid header length
			uint8_t* buf = m_pending_message.payload();
			dragent_protocol::buffer_to_protobuf(&buf[header_len],
			                                     payload_len,
			                                     &err_msg);
		}
		catch (const dragent_protocol::protocol_error& ex)
		{
			// It's a lost cause
			LOG_ERROR("Protocol error: Received unparseable error message "
			          "(Type: %d, version %d)",
			          (int)type,
			          (int)version);
			return false;
		}

		handle_collector_error(err_msg);
		return true;
	}

	LOG_ERROR("Protocol error: Received command %d for incompatible protocol version %d",
	          (int)type,
	          (int)version);
	return false;
}

void connection_manager::on_metrics_send(dragent_protocol_header_v5& header,
                                         std::shared_ptr<serialized_buffer> &metrics)
{
	ASSERT(metrics->message_type == draiosproto::message_type::METRICS);

	if (get_current_protocol_version() == dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		seconds elapsed =
		    duration_cast<seconds>(steady_clock::now() - m_last_connect);
		// Check to see how long we've been functional
		if (elapsed >= m_working_interval)
		{
			reset_backoff();
		}
		return;
	}

	// Increment the sequence number
	++m_sequence;

	// Build the unacked message struct
	unacked_message msg = {header, metrics};

	while(m_messages_awaiting_ack.size() >= c_unacked_message_slots.get_value())
	{
		// The unacked list is full. Drop the oldest message from the list.
		unacked_message& msg = m_messages_awaiting_ack.front();
		LOG_WARNING("Did not receive ACK for message %llu, %llu",
		            (long long unsigned)ntohll(msg.header.generation),
		            (long long unsigned)ntohll(msg.header.sequence));
		m_messages_awaiting_ack.pop_front();
	}

	if (m_messages_awaiting_ack.size() > 0)
	{
		unacked_message& msg = m_messages_awaiting_ack.front();
		LOG_INFO("Message %llu, %llu has not seen an ACK yet",
		         (long long unsigned)ntohll(msg.header.generation),
	             (long long unsigned)ntohll(msg.header.sequence));
	}

	// Store it
	m_messages_awaiting_ack.push_back(msg);
}

bool connection_manager::on_ack_received(const dragent_protocol_header_v5& header)
{
	// Current protocol behavior is that an ACK will ACK the message it describes
	// with <gen, seq>, but also implicitly ACKs all previous messages. In other
	// words, if I'm holding on to <1, 5> and <1, 6> and I receive an ACK for
	// <1, 6>, I should discard <1, 5>.
	bool removed = false;
	for(auto it = m_messages_awaiting_ack.begin(); it != m_messages_awaiting_ack.end();)
	{
		// Check if the header on the stored metrics is covered by the received ACK
		if (sequence_less_or_equal(&it->header, &header))
		{

			m_last_metrics_ack_uptime_s = uptime::seconds();
			removed = true;
			m_messages_awaiting_ack.erase(it++);
		}
		else
		{
			it++;
		}
	}
	return removed;
}

void connection_manager::process_ack_queue_on_reconnect(uint64_t last_acked_gen,
                                                        uint64_t last_acked_seq)
{
	dragent_protocol_header_v5 tmp_header {
		{},
		last_acked_gen,
		last_acked_seq
	};
	for(auto it = m_messages_awaiting_ack.begin(); it != m_messages_awaiting_ack.end();)
	{
		if(sequence_less_or_equal(&it->header, &tmp_header))
		{
			// Remove this message. The collector thinks it was acked.
			m_messages_awaiting_ack.erase(it++);
		}
		else
		{
			// Need to retransmit
			transmit_buffer(sinsp_utils::get_current_time_ns(),
			                &it->header,
			                it->buffer);
			it++;
		}
	}
}

bool connection_manager::build_protocol_header(std::shared_ptr<serialized_buffer> &item,
                                               dragent_protocol::protocol_version version,
                                               dragent_protocol_header_v5 &header,
                                               uint64_t generation,
                                               uint64_t sequence)
{
	ASSERT(version == dragent_protocol::PROTOCOL_VERSION_NUMBER ||
	            version == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);
	ASSERT(item);
	if (!item)
	{
		return false;
	}

	// First fill out the legacy fields
	uint32_t header_len = dragent_protocol::header_len(version);

	header.hdr.version = version;
	header.hdr.messagetype = item->message_type;
	header.hdr.len = htonl(header_len + item->buffer.size());

	// Now the v5 fields
	if (version > dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		ASSERT(generation > 0);
		ASSERT(sequence > 0);
		header.generation = htonll(generation);
		header.sequence = htonll(sequence);
	}

	return true;
}

void connection_manager::set_legacy_mode()
{
	if (m_negotiated_aggregation_interval == 0 &&
	    m_negotiated_protocol_version == dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		// Nothing to do here
		return;
	}
	m_negotiated_aggregation_interval = 0;
	m_negotiated_protocol_version = dragent_protocol::PROTOCOL_VERSION_NUMBER;

	// Clear the input queue
	m_queue->clear();
}

void connection_manager::handle_collector_error(draiosproto::error_message& msg)
{
	// Weed out bogus messages
	if(!msg.has_type())
	{
		LOG_ERROR("Protocol error: Received error message with unset type.");
		return;
	}
	const draiosproto::error_type err_type = msg.type();

	if(!draiosproto::error_type_IsValid(err_type))
	{
		LOG_ERROR("Protocol error: received invalid error type: %s",
		          std::to_string(err_type).c_str());
		return;
	}

	// Handle the error message
	std::string err_str = draiosproto::error_type_Name(err_type);

	if(msg.has_description() && !msg.description().empty())
	{
		err_str += " (" + msg.description() + ")";
	}

	LOG_ERROR("Received error message: " + err_str);

	if(err_type == draiosproto::error_type::ERR_PROTO_MISMATCH)
	{
		LOG_ERROR("Received a PROTO_MISMATCH error from the backend. This is "
			  "unexpected behavior and the agent will restart to get back "
			  "into a stable state. Contact Sysdig Support for additional "
			  "help.");
		dragent::running_state::instance().restart();
		return;
	}

	if(err_type == draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY)
	{
		// Exponential backoff on INVALID_CUSTOMER_KEY
		// Sometimes customers will decide to no longer be customers
		// but will leave an agent running for some reason. The agent
		// will just pound away trying to connect to the collector.
		// Make the agent backoff in this case.
		disconnect_and_backoff();
	}
}

bool connection_manager::is_component_healthy() const 
{
	// If we've never received an ack then report healthy
	if (0 == m_last_metrics_ack_uptime_s) {
		return true;
	}

	const uint64_t now = uptime::seconds();
	const uint64_t seconds_since_last_ack = now - m_last_metrics_ack_uptime_s;

	if (seconds_since_last_ack > c_unacked_message_timeout->get_value()) 
	{
		LOG_FATAL("A metrics ACK has not been received for %lu seconds "
			  "which is greater than the timeout of %lu seconds. "
			  "This can happen if networking issues cause the agent "
			  "to believe it has an active connection when the "
			  "backend has closed the connection. The agent will be "
			  "restarted to fix the issue. If this continues to "
			  "occur, contact Sysdig support for assistance.",
			  seconds_since_last_ack,
			  c_unacked_message_timeout->get_value());

		return false;
	}

	return true;

}
