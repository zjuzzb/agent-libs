#pragma once

#include "protocol.h"
#include "watchdog_runnable.h"
#include "dragent_message_queues.h"

#ifndef CYGWING_AGENT
#include "promex.pb.h"
#include "promex.grpc.pb.h"
#endif

#include <initializer_list>
#include <memory>
#include <map>

#include <Poco/Buffer.h>

class dragent_configuration;
class connection_manager;

namespace Poco {
namespace Net {
class StreamSocket;
} // namespace Net
} // namespace Poco

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

	cm_state_machine(connection_manager* cm = nullptr) :
	    m_state(state::INIT),
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


class connection_manager : public dragent::watchdog_runnable
{
public:
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
		                            uint8_t* buffer,
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
		inline uint8_t get_version() const
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
				// The length should already be ntohl'd when it was read off the wire
				return header->len;
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

	connection_manager(dragent_configuration* configuration,
			   protocol_queue* queue,
			   bool use_handshake,
			   std::initializer_list<message_handler_map::value_type> message_handlers = {});
	~connection_manager();

	bool is_connected() const
	{
		return (m_fsm->get_state() == cm_state_machine::state::STEADY_STATE) && m_socket;
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

	uint64_t get_sequence() const
	{
		return m_sequence;
	}
	uint64_t get_generation() const
	{
		return m_generation;
	}

	void disconnect();

private:
	using socket_ptr = std::shared_ptr<Poco::Net::StreamSocket>;

	bool init();
	void fsm_reinit();
	void do_run() override;
	bool connect();
	void disconnect(socket_ptr& ssp);
	bool transmit_buffer(uint64_t now, std::shared_ptr<serialized_buffer> &item);
	bool receive_message();
	bool handle_message();
	void perform_handshake();

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
	bool m_use_handshake;
	uint64_t m_generation;
	uint64_t m_sequence;
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	pending_message m_pending_message;

	uint32_t m_reconnect_interval;
	std::chrono::time_point<std::chrono::system_clock> m_last_connection_failure;
	std::unique_ptr<cm_state_machine> m_fsm;

#ifndef CYGWING_AGENT
	// communication with Prometheus exporter
	std::shared_ptr<promex_pb::PrometheusExporter::Stub> m_prom_conn;
	std::shared_ptr<grpc::Channel> m_prom_channel;
#endif
};
