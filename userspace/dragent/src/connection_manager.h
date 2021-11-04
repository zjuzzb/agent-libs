#pragma once

#include "protocol.h"
#include "spinlock.h"
#include "running_state_runnable.h"
#include "dragent_message_queues.h"
#include "dragent_settings_interface.h"
#include "handshake.pb.h"
#include "protobuf_file_emitter.h"

#ifndef CYGWING_AGENT
#include "promex.pb.h"
#include "promex.grpc.pb.h"
#endif

#include <arpa/inet.h>
#include <initializer_list>
#include <memory>
#include <map>
#include <functional>
#include <chrono>
#include <list>

#include <Poco/Buffer.h>

#include "cm_proxy_tunnel.h"

class connection_manager;

namespace Poco {
namespace Net {
class StreamSocket;
} // namespace Net
} // namespace Poco

namespace grpc {
	class ChannelInterface;
}

/**
 * Configuration options for the connection manager
 */
struct cm_config
{
	std::string m_root_dir;
	std::string m_server_addr;
	uint16_t m_server_port;
	bool m_ssl_enabled;
	std::vector<std::string> m_ssl_ca_cert_paths;
	std::string m_ssl_ca_certificate;
	bool m_promex_enabled;
	std::string m_promex_connect_url;
	std::string m_customer_id;
	std::string m_machine_id;
	const std::string root_dir;
};

/**
 * Base class implementing state machine behavior for the connection manager.
 */
class cm_state_machine
{
public:
	enum class event
	{
		CONNECT,       // Connection initiated
		CONNECTION_COMPLETE,  // Connection established
		HANDSHAKE_PROTO_RESP, // Received response to HS phase 1
		HANDSHAKE_NEGOTIATION_RESP, // Received response to HS phase 2
		DISCONNECTED,  // Previously established connection has dropped
		SHUTDOWN,      // Agent shutting down

		NUM_EVENTS
	};

	enum class state
	{
		NONE,
		INIT,          // Initial state
		RETRYING,      // Connection dropped, starting from scratch
		CONNECTING,    // Attempting to establish connection
		HANDSHAKE,     // Performing handshake
		STEADY_STATE,  // Connected, sending metrics
		TERMINATED,    // Disconnected, no longer reconnecting

		NUM_STATES
	};

	using callback = std::function<state(connection_manager*)>;

	cm_state_machine(connection_manager* cm = nullptr,
	                 state st = state::INIT) :
	    m_state(st),
	    m_cm(cm)
	{}

	/**
	 * Sends an event into the state machine.
	 *
	 * @param[in]  ev  The event received
	 *
	 * @return The new state for the state machine
	 */
	bool send_event(event ev)
	{
		if (m_state == state::NONE)
		{
			// Uninitialized or bogus FSM
			return false;
		}

		auto it = m_cb_table.find(m_state);
		if (it == m_cb_table.end())
		{
			return false;
		}

		auto inner = it->second.find(ev);
		if (inner == it->second.end())
		{
			return false;
		}

		// Transition to a (potentially) new state
		m_state = inner->second.operator()(m_cm);

		return true;
	}

	/**
	 * Returns the current state of the state machine.
	 */
	state get_state() const { return m_state; }

	/**
	 * Registers a transition function for the state machine.
	 *
	 * @param st    The state to which the function applies
	 * @param ev    The event on which to trigger the transition function
	 * @param func  The function to call when the transition occurs
	 */
	void register_event_callback(state st, event ev, callback func)
	{
		m_cb_table[st].insert(std::make_pair(ev, func));
	}

private:

	state m_state;
	std::map<state, std::map<event, callback>> m_cb_table;
	connection_manager* m_cm;
};

class connection_manager : public dragent::running_state_runnable,
                           public aggregation_interval_source,
                           public compression_method_source,
                           public metric_limit_source
{

public:
	using socket_ptr = std::shared_ptr<Poco::Net::StreamSocket>;

	class message_handler
	{
	public:
		using ptr = std::shared_ptr<message_handler>;

		virtual ~message_handler() = default;

		/**
		 * @param type
		 * @param buffer
		 * @param buffer_size
		 *
		 * @return bool this value is ignored
		 */
		virtual bool handle_message(draiosproto::message_type type,
		                            const uint8_t* buffer,
		                            size_t buffer_size) = 0;
	};

	using message_handler_map = std::map<draiosproto::message_type, message_handler::ptr>;

	struct pending_message
	{
		bool m_pending;
		Poco::Buffer<uint8_t> m_buffer;
		uint32_t m_buffer_used;

		pending_message():
		    m_pending(false),
		    m_buffer(RECEIVER_BUFSIZE),
		    m_buffer_used(0)
		{}

		/**
		 * Gets the header for the stored message.
		 *
		 * Returns nullptr if no stored header.
		 */
		inline const dragent_protocol_header_v4* v4_header() const
		{
			if (m_pending && m_buffer_used >= sizeof(dragent_protocol_header_v4))
			{
				return (dragent_protocol_header_v4*)m_buffer.begin();
			}
			return nullptr;
		}

		/**
		 * Gets a pointer to the beginning of the message payload.
		 *
		 * Returns nullptr if there is no payload or if the message is not valid.
		 */
		inline uint8_t* payload()
		{
			if (!v4_header())
			{
				return nullptr;
			}

			uint32_t header_len = dragent_protocol::header_len(*v4_header());

			ASSERT(m_buffer_used >= header_len);
			if (m_buffer_used == header_len)
			{
				return nullptr;
			}

			return m_buffer.begin() + header_len;
		}

		/**
		 * Gets the version of the message from the header.
		 *
		 * Returns 0 if no valid header.
		 */
		inline dragent_protocol::protocol_version get_version() const
		{
			auto* header = v4_header();
			if (header)
			{
				return header->version;
			}
			return 0;
		}

		/**
		 * Gets the total length of the message from the header.
		 *
		 * Length includes the length of the header as well as the length
		 * of the payload.
		 *
		 * Returns 0 if no valid header.
		 */
		inline uint32_t get_total_length() const
		{
			auto* header = v4_header();
			if (header)
			{
				return ntohl(header->len);
			}
			return 0;
		}

		/**
		 * Gets the message type from the header.
		 *
		 * Returns 0 if no valid header.
		 */
		inline uint8_t get_type() const
		{
			auto* header = v4_header();
			if (header)
			{
				return header->messagetype;
			}
			return 0;
		}

		/**
		 * Has the message been fully read
		 */
		inline bool is_complete() const
		{
			return m_pending && m_buffer_used == get_total_length();
		}

		/**
		 * Reset the buffer and all internal tracking.
		 */
		inline void reset()
		{
			m_pending = false;
			m_buffer_used = 0;
		}
	};

private:
	/**
	 * Handles messages of type ERROR_MESSAGE that the connection_manager receives
	 * from the backend.
	 */
	class error_message_handler : public connection_manager::message_handler
	{
	public:

		error_message_handler(connection_manager* cm)
		    : m_connection_manager(cm)
		{
		}

		bool handle_message(const draiosproto::message_type,
		                    const uint8_t* buffer,
		                    size_t buffer_size) override
		{
			draiosproto::error_message err_msg;
			dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &err_msg);

			if (m_connection_manager)
			{
				m_connection_manager->handle_collector_error(err_msg);
			}

			return true;
		}

	private:
		connection_manager* m_connection_manager;
	};

public:

	/**
	 * @param configuration  The config params for the CM
	 * @param queue  The input queue for the CM
	 * @param supported_protocol_versions  The versions the CM should report.
	 *        This parameter cam be used to force the CM to use a subset of 
	 *        protocol version. If the server supports none of these, no 
	 *        connection can be formed.
	 * @param message_handlers  Callbacks for given message types. These may 
	 *                          also be registered later dynamically
	 * @param use_agentino_handshake  Indicates to use the 1-phase handshake generally
	 *        used for agentinos instead of the regular one
	 * @param decorate_handshake_data  A callback to allow the client to populate the hand-
	 *        shake data with additional data. the type varies on the type of handshake used,
	 *        and will always be the "most" relevant message type for that handshake
	 */
	connection_manager(const cm_config& configuration,
	       protocol_queue* queue,
	       std::initializer_list<dragent_protocol::protocol_version> supported_protocol_versions,
	       std::initializer_list<message_handler_map::value_type> message_handlers = {},
	       bool use_agentino_handshake = false,
	       std::function<void(void*)> decorate_handshake_data = nullptr);
	~connection_manager();

	bool is_connected() const;

#ifdef SYSDIG_TEST
	void test_run() { do_run(); }

	void set_aggregation_interval(uint32_t interval)
	{
		m_negotiated_aggregation_interval = interval;
	}

	cm_state_machine::state get_state() const
	{
		return m_fsm->get_state();
	}

	uint32_t num_unacked_messages()
	{
		return m_messages_awaiting_ack.size();
	}

	dragent_protocol_header_v5 first_unacked_header()
	{
		return m_messages_awaiting_ack.front().header;
	}

	dragent_protocol::protocol_version get_negotiated_protocol_version()
	{
		return get_current_protocol_version();
	}

	bool test_sequence_less_or_equal(dragent_protocol_header_v5* first,
	                                 dragent_protocol_header_v5* second)
	{
		return sequence_less_or_equal(first, second);
	}

	uint32_t get_reconnect_interval() const
	{
		return m_reconnect_interval.count();
	}

	void set_working_interval(uint32_t new_interval)
	{
		m_working_interval = std::chrono::seconds(new_interval);
	}

	volatile bool m_timed_out = false;
	uint32_t m_num_invalid_messages = 0;
#endif

	uint64_t get_sequence() const
	{
		return m_sequence;
	}
	uint64_t get_generation() const
	{
		return m_generation;
	}

	std::chrono::seconds get_negotiated_aggregation_interval() const
	{
		scoped_spinlock lock(m_parameter_update_lock);
		if (m_negotiated_aggregation_interval == UINT32_MAX)
		{
			return std::chrono::seconds::max();
		}
		return std::chrono::seconds(m_negotiated_aggregation_interval);
	}

	std::shared_ptr<protobuf_compressor>& get_negotiated_compression_method()
	{
		scoped_spinlock lock(m_parameter_update_lock);
		return m_negotiated_compression_method;
	}

	bool get_negotiated_raw_prometheus_support() const
	{
		return m_negotiated_raw_prometheus_support;
	}

	/**
	 * Changes or adds a message handler for the given message type.
	 *
	 * Changing this function will only apply to messages received after the
	 * change takes effect. If it is important for your component to receive
	 * all messages of the given type, register your message handler in the
	 * constructor.
	 */
	void set_message_handler(draiosproto::message_type type, message_handler::ptr handler);

private:
	struct unacked_message
	{
		dragent_protocol_header_v5 header;
		std::shared_ptr<serialized_buffer> buffer;
	};

	bool init();
	void fsm_reinit(dragent_protocol::protocol_version working_protocol_version,
	                cm_state_machine::state state = cm_state_machine::state::INIT);
	void do_run() override;
	bool connect();
	bool connect_to_collector();

	bool is_connected_to_collector() const
	{
		return (m_fsm->get_state() == cm_state_machine::state::STEADY_STATE) && m_socket;
	}

	/**
	 * Send a byte buffer out on the wire.
	 */
	bool transmit_buffer(uint64_t now,
	                     dragent_protocol_header_v4* header,
	                     std::shared_ptr<serialized_buffer> &item);
	bool transmit_buffer(uint64_t now,
	                     dragent_protocol_header_v5* header,
	                     std::shared_ptr<serialized_buffer> &item);
	int32_t send_bytes(uint8_t* buf, uint32_t len);


	/**
	 * Receive a message from the collector.
	 *
	 * This function receives the message in chunks as they arrive on
	 * the socket. The message is aggregated in m_pending_message and is only
	 * complete when m_pending_message.is_complete() returns true.
	 *
	 * @retval  true   Socket operating normally
	 * @retval  false  Connection has dropped
	 */
	bool receive_message();

	/**
	 * Handle a message received from the collector.
	 *
	 * Handles the message stored in m_pending_message.
	 *
	 * @retval  true   Message was valid and handled appropriately
	 * @retval  false  Invalid message or not able to be handled
	 */
	bool handle_message();

	/**
	 * Handle a message with an invalid version number.
	 *
	 * A message with an invalid version number is a protocol error, but we
	 * might be able to extract just enough information from it to write a
	 * useful log message.
	 *
	 * @retval  true   Was able to extract enough to process a message
	 * @retval  false  The message should be considered a failure
	 */
	bool handle_invalid_version();

	/**
	 * Executes a protocol handshake.
	 *
	 * @retval  true   Handshake completed successfully
	 * @retval  false  Handshake error
	 */
	bool perform_handshake();

	/**
	 * Executes an agentino protocol handshake.
	 *
	 * @retval  true   Handshake completed successfully
	 * @retval  false  Handshake error
	 */
	bool perform_agentino_handshake();

	/**
	 * Sends the proto_init phase of the handshake (phase 1).
	 *
	 * @retval  true   Message sent successfully
	 * @retval  false  Message send failed (socket error)
	 */
	bool send_proto_init();

	/**
	 * Sends the agentino specific handshake request
	 *
	 * @retval  true   Message sent successfully
	 * @retval  false  Message send failed (socket error)
	 */
	bool send_agentino_handshake_request();

	/**
	 * Builds a header for a protocol message.
	 *
	 * @param item         The message to build a header for.
	 * @param version      The version number of the header to build.
	 * @param header       [out] The header to fill in
	 * @param generation   [optional]  The generation number for the header
	 * @param sequence     [optional]  The sequence number for the header
	 *
	 * @retval  true   The header was built successfully
	 * @retval  false  The header could not be build (invalid parameter)
	 */
	bool build_protocol_header(std::shared_ptr<serialized_buffer>& item,
	                           dragent_protocol::protocol_version version,
	                           dragent_protocol_header_v5& header,
	                           uint64_t generation = 0,
	                           uint64_t sequence = 0);

	/**
	 * Sends the handshake_v? phase of the handshake (phase 2)
	 *
	 * @retval  true   Message sent successfully
	 * @retval  false  Message send failed (socket error)
	 */
	bool send_handshake_negotiation();

	/**
	 * Perform bookkeeping tasks related to sending a metrics message.
	 */
	void on_metrics_send(dragent_protocol_header_v5& header,
	                     std::shared_ptr<serialized_buffer>& metrics);

	/**
	 * Process a received ACK message.
	 *
	 * @retval  true   The ACK was for a pending metrics message.
	 * @retval  false  Could not find the associated metrics message.
	 */
	bool on_ack_received(const dragent_protocol_header_v5& header);
	// Returns version, or 0 if unknown
	dragent_protocol::protocol_version get_current_protocol_version();
	dragent_protocol::protocol_version get_max_supported_protocol_version();

	/**
	 * Adjusts the ACK queue based on information received in handshake.
	 *
	 * The protocol handshake involves receiving the last acked <seq, gen> pair
	 * from the collector. As this pair might not match the agent's view of
	 * the system, this function will discard any messages waiting for ACKs
	 * which will never come.
	 */
	void process_ack_queue_on_reconnect(uint64_t last_acked_gen,
	                                    uint64_t last_acked_seq);

	/**
	 * Is the <gen, seq> pair in the first header less than or equal to the second?
	 *
	 * The headers are assumed to be in wire order.
	 */
	bool sequence_less_or_equal(const dragent_protocol_header_v5* first,
	                            const dragent_protocol_header_v5* second) const
	{
		uint64_t generation = ntohll(second->generation);
		uint64_t sequence = ntohll(second->sequence);
		uint64_t comp_gen = ntohll(first->generation);
		uint64_t comp_seq = ntohll(first->sequence);

		return  comp_gen < generation ||
		       (comp_gen == generation && comp_seq <= sequence);
	}

	/**
	 * Set the system into legacy mode.
	 *
	 * This will:
	 * - Set the negotiated aggregation interval to 0
	 * - Set the working version to 4
	 * - Clear the input queue
	 *
	 * This function will only do the last step (clearing the input queue) if
	 * the system wasn't already in legacy mode.
	 */
	void set_legacy_mode();

	/**
	 * The agent is successfully operating again. Reset reconnect backoff.
	 */
	void reset_backoff()
	{
		m_reconnect_interval = std::chrono::seconds(0);
	}

	/**
	 * Handles an error message from the collector.
	 *
	 * The error message is first given to the message handler, where it's
	 * deserialized and then sent back into the CM via this function.
	 */
	void handle_collector_error(draiosproto::error_message& msg, bool in_handshake = false);

	void disconnect();
	void disconnect_and_backoff();
	bool should_backoff(draiosproto::error_type err);
	bool use_proxy();

#ifndef CYGWING_AGENT
	bool prometheus_connected() const;
	bool prometheus_send(std::shared_ptr<serialized_buffer> &item);
#endif
public:
	static const uint32_t MAX_RECEIVER_BUFSIZE = 1 * 1024 * 1024; // 1MiB
	static const uint32_t RECEIVER_BUFSIZE = 32 * 1024;
	static const std::chrono::seconds RECONNECT_MIN_INTERVAL;

private:

	/**
	 * Validate that the internals of the connection manager appear 
	 * to be healthy. 
	 */
	bool is_component_healthy() const override;

	std::mutex m_handler_map_lock;
	message_handler_map m_handler_map;
	std::vector<dragent_protocol::protocol_version> m_supported_protocol_versions;
	std::vector<protocol_compression_method> m_supported_compression_methods;
	std::vector<uint32_t> m_supported_aggregation_intervals;
	std::vector<draiosproto::custom_metric_limit_value> m_supported_custom_metric_limits;
	cm_socket::ptr m_socket;
	uint64_t m_generation;
	uint64_t m_sequence;
	cm_config m_configuration;
	protocol_queue* m_queue;
	std::unique_ptr<dragent::protobuf_file_emitter> m_protobuf_file_emitter;
	pending_message m_pending_message;
	uint32_t m_negotiated_aggregation_interval;
	std::shared_ptr<protobuf_compressor> m_negotiated_compression_method;
	// Lock protecting updates to negotiated parameters
	// The CM serves as the source of truth for handshake-negotiated fields,
	// and this lock ensures that those fields are protected from reads while
	// they're being updated concurrently.
	mutable spinlock m_parameter_update_lock;
	dragent_protocol::protocol_version m_negotiated_protocol_version;

	std::atomic<bool> m_negotiated_raw_prometheus_support;

	std::chrono::seconds m_reconnect_interval;
	std::chrono::time_point<std::chrono::steady_clock> m_last_connect;
	std::chrono::seconds m_working_interval;

	std::unique_ptr<cm_state_machine> m_fsm;

	std::list<unacked_message> m_messages_awaiting_ack;
	std::chrono::milliseconds m_send_recv_timeout;

	// Used for last line of defense watchdog. If there is an active
	// connection but an ACK hasn't been received for a very long time then
	// we force the entire application to exit and restart. This must be
	// atomic because it is read from a remote thread.
	std::atomic<uint64_t> m_last_metrics_ack_uptime_s;

	// Agentino communication uses a different handshake. This indicates which to use
	bool m_use_agentino_handshake;

	// During handshake, the client may request to decorate the message with some additional
	// information. This allows us that opportunity. Due to having a few different
	// handshakes, we pass a void* and it's expected the caller will RTTI cast to the 
	// type for the specified handshake. In a perfect world, the handshake is
	// managed by a helper class that can deal with the type situation.
	std::function<void(void*)> m_decorate_handshake_data;

#ifndef CYGWING_AGENT
	// communication with Prometheus exporter
	std::shared_ptr<promex_pb::PrometheusExporter::Stub> m_prom_conn;
	std::shared_ptr<grpc::ChannelInterface> m_prom_channel;
#endif
};
