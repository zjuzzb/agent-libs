#pragma once

#include <cstdint>
#include <queue>
#include <string>
#include <stdexcept>
#include <chrono>
#include <unordered_map>
#include "protocol.h"
#include "spinlock.h"
#include <unistd.h>
#include <arpa/inet.h>
#include "protobuf_compression.h"

/**
 * Unit test mock which emulates an agentino.
 */
class fake_agentino
{
public:
	enum server_status
	{
		NOT_STARTED,
		CONNECTING,
		CONNECTED,
		HANDSHAKING,
		RUNNING,
		ERRORED,
		DISCONNECTED,
		SHUTDOWN
	};

	/**
	 * One data buffer received by the server.
	 */
	struct buf
	{
		uint8_t* ptr;
		union
		{
			dragent_protocol_header_v4 v4;
			dragent_protocol_header_v5 v5;
		} hdr;
		uint32_t payload_len;

		buf(uint8_t* _ptr, dragent_protocol_header_v5 _hdr, uint32_t _len):
		    ptr(_ptr),
		    payload_len(_len)
		{
			hdr.v5 = _hdr;
		}

		buf(uint8_t* _ptr, dragent_protocol_header_v5 _hdr):
		    ptr(_ptr)
		{
			hdr.v5 = _hdr;
		}

		buf() {}
	};

	/**
	 * @param[in] auto_respond indicates whether the agentino will automatically
	 *            respond to handshake messages and ack. If false, client is
	 *            responsible for responding to those messages as appropriate
	 */
	fake_agentino(bool auto_respond,
	              bool auto_reconnect,
	              bool silent=true,
	              const std::string& id=""):
	    m_received_data(),
	    m_status(server_status::NOT_STARTED),
	    m_error_code(0),
	    m_error_msg(""),
	    m_id(id),
	    m_run_loop(false),
	    m_port(0),
	    m_drop_connection(false),
	    m_auto_respond(auto_respond),
	    m_auto_reconnect(auto_reconnect),
	    m_last_gen_num(0),
	    m_last_seq_num(0),
	    m_last_index(0),
	    m_working_version(0),
	    m_delay_acks(false),
	    m_num_disconnects(0),
	    m_num_connects(0),
	    m_num_sent_msgs(0),
	    m_num_sent_heartbeats(0),
	    m_silent(silent),
	    m_pause(false),
	    m_heartbeat(false)
	{}

	~fake_agentino();

	/**
	 * Starts a new thread running the client loop on the given port.
	 *
	 * The client will connect to localhost:<port>. If auto response is on,
	 * the client will initiate a handshake. If off, the caller must initiate
	 * the handshake and change the internal state accordingly. Once handshake
	 * is sent, the fake agentino client will run the main client loop.
	 *
	 * @param port  The port to connect on.
	 *
	 * @return  true  connected successfully
	 * @return  false on error
	 */
	bool start(uint16_t port);
	void stop();

	/**
	 * Pause the fake agentino.
	 *
	 * A paused fake agentino will not send or receive any messages.
	 *
	 * If the connection drops and auto_reconnect is on, it will still
	 * reconnect.
	 */
	void pause(bool should_pause);

	/**
	 * Removes and returns the data at the head of the data list.
	 *
	 * Ownership of the pointer transfers to the caller.
	 *
	 * @return  The client data
	 */
	buf pop_data()
	{
		buf ret = m_received_data.front();

		m_received_data.pop();
		return ret;
	}

	/**
	 * Returns the number of data packets received from agentone.
	 *
	 * @return  Amount of data in the list
	 */
	uint32_t data_len() const
	{
		return m_received_data.size();
	}

	/**
	 * Gets the port the agentone is using to connect.
	 *
	 * @return The connected port
	 */
	uint16_t get_port() const
	{
		return m_port;
	}

	/**
	 * Gets the status of the client.
	 *
	 * @retval  NOT_STARTED  The initial state
	 * @retval  CONNECTING   Attempting to connect
	 * @retval  CONNECTED    Client has connected but not send handshake
	 * @retval  HANDSHAKING  Client is awaiting a handshake response
	 * @retval  RUNNING      Client is awaiting input
	 * @retval  ERRORED      Client attempted to start but encountered an error
	 * @retval  SHUTDOWN     Client started and then cleanly shut down
	 * @retval  DISCONNECTED Client terminated the connection remotely
	 */
	server_status get_status() const
	{
		return m_status;
	}

	bool connected() const
	{
		return m_status > server_status::CONNECTING &&
		       m_status < server_status:: ERRORED;
	}

	/**
	 * The fake agentino should drop the connection to the agentone.
	 */
	void drop_connection()
	{
		m_drop_connection = true;
	}

	/**
	 * Serialize a protobuf into a byte buf.
	 */
	template<typename T>
	buf build_buf(uint8_t message_type,
	              dragent_protocol::protocol_version version,
	              T& msg,
	              uint64_t generation = 0,
	              uint64_t sequence = 0);
	buf build_buf(uint8_t message_type,
	              dragent_protocol::protocol_version version,
	              uint8_t* buf,
	              uint32_t buf_len,
	              uint64_t generation = 0,
	              uint64_t sequence = 0);

	/**
	 * Enqueue the message into the send queue.
	 */
	bool enqueue_agentone_message(buf& b);

	/**
	 * Send the given byte buf out on the given socket.
	 */
	bool transmit_buf(buf& b, int sockfd);

	/**
	 * Send the initial message in the agentino / agentone handshake.
	 */
	bool send_handshake_message(int sockfd);

	/**
	 * Get the number of disconnects seen by the agentino.
	 *
	 * This number is both agent-initiated disconnects and disconnects caused
	 * by fake collector clients calling drop_connection().
	 */
	uint32_t get_num_disconnects() const
	{
		return m_num_disconnects;
	}

	/**
	 * Get the number of connects seen by the collector.
	 */
	uint32_t get_num_connects() const
	{
		return m_num_connects;
	}

	/**
	 * Get the number of messages sent from this fake agentino.
	 */
	uint32_t get_num_sent_messages() const
	{
		return m_num_sent_msgs;
	}

	/**
	 * Get the number of heartbeats sent from this fake agentino.
	 */
	uint32_t get_num_sent_heartbeats() const
	{
		return m_num_sent_heartbeats;
	}

	void turn_on_heartbeats()
	{
		m_heartbeat = true;
	}

	/**
	 *	Deserialize a buffer into a protobuf
	 */
	template<typename T>
	bool parse_protobuf(uint8_t* buffer, uint32_t buf_len, T& msg);

private:
	const uint32_t MAX_STORED_DATAGRAMS = 32;
	std::queue<buf> m_received_data;
	std::queue<buf> m_send_queue; // Messages to send to the agent
	server_status m_status;
	int m_error_code;        // Currently internal-only for debugging
	std::string m_error_msg; // Currently internal-only for debugging
	std::string m_id;

	bool m_run_loop; // Control variable

	uint16_t m_port;   // The port the server is listening on

	volatile bool m_drop_connection;
	bool m_auto_respond;
	bool m_auto_reconnect;
	std::unordered_map<int, std::chrono::system_clock::time_point> wait_list; // Internal tracking of connect delays
	spinlock m_send_queue_lock;
	uint64_t m_last_gen_num;
	uint64_t m_last_seq_num;
	uint64_t m_last_index;
	uint8_t m_working_version;
	bool m_delay_acks;
	std::queue<buf> m_delayed_metrics;
	uint32_t m_num_disconnects;
	uint32_t m_num_connects;
	uint32_t m_num_sent_msgs;
	uint32_t m_num_sent_heartbeats;
	bool m_silent;
	bool m_pause;
	bool m_heartbeat;

public:
	draiosproto::policies_v2 m_most_recent_received_policies;

private:
	/**
	 * Reads one from the given file descriptor and internally handles it
	 *
	 * @param[in]  fd       The file descriptor to read from
	 *
	 * @return  Success or failure
	 */
	bool handle_one_message(int fd);

	/**
	 * Determine how to respond to the given message and take the action.
	 */
	bool process_auto_response(buf& b);

	/**
	 * Is the given version number supported by this fake agentino?
	 */
	bool version_is_supported(uint8_t ver);

	/**
	 * Main execution loop for fake agentino
	 */
	static void thread_loop(uint16_t port, fake_agentino& fa);
};

template<typename T>
fake_agentino::buf fake_agentino::build_buf(uint8_t message_type,
                                            dragent_protocol::protocol_version version,
                                            T& msg,
                                            uint64_t generation,
                                            uint64_t sequence)
{
	std::shared_ptr<protobuf_compressor> compressor;
	compressor = gzip_protobuf_compressor::get(-1);

	// Serialize the message
	std::shared_ptr<serialized_buffer> msg_buf;
	msg_buf = dragent_protocol::message_to_buffer(0,
	                                              message_type,
	                                              msg,
	                                              compressor);
	if (!msg_buf)
	{
		return {};
	}

	// Copy the std::string we get from message_to_buffer to something less stupid
	uint8_t* bytes = new uint8_t[msg_buf->buffer.length()];
	memcpy(bytes, msg_buf->buffer.c_str(), msg_buf->buffer.length());

	return build_buf(message_type,
	                 version,
	                 bytes,
	                 msg_buf->buffer.length(),
	                 generation,
	                 sequence);
}

template <typename T>
bool fake_agentino::parse_protobuf(uint8_t* buffer, uint32_t buf_len, T& msg)
{
	   google::protobuf::io::ArrayInputStream stream(buffer, buf_len);
	   google::protobuf::io::GzipInputStream gzstream(&stream);

	   if(!msg.ParseFromZeroCopyStream(&gzstream))
	   {
		       return false;
	   }
	   return true;
}
