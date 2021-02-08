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
 * Unit test mock which interfaces with the connection manager.
 *
 * This class will listen on a port and store every message it is given
 * for verification purposes.
 */
class fake_collector
{
public:
	enum server_status
	{
		NOT_STARTED = 0,
		RUNNING = 1,
		ERRORED = 2,
		SHUTDOWN = 3
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

		buf(uint8_t* _ptr, dragent_protocol_header_v4 _hdr):
		    ptr(_ptr)
		{
			hdr.v4 = _hdr;
		}

		buf(uint8_t* _ptr, dragent_protocol_header_v5 _hdr):
		    ptr(_ptr)
		{
			hdr.v5 = _hdr;
		}

		buf() {}
	};

	/**
	 * @param[in] auto_respond indicates whether the collector will automatically
	 *            respond to handshake messages and ack. If false, client is
	 *            responsible for responding to those messages as appropriate
	 */
	fake_collector(bool auto_respond, bool silent=true):
		m_received_data(),
		m_status(server_status::NOT_STARTED),
		m_error_code(0),
		m_error_msg(""),
		m_run_server(false),
		m_port(0),
		m_delayed_connection(0),
	    m_drop_connection(false),
	    m_reset_connection(false),
	    m_auto_respond(auto_respond),
	    m_last_gen_num(0),
	    m_last_seq_num(0),
	    m_last_index(0),
	    m_working_version(0),
	    m_delay_acks(false),
	    m_num_disconnects(0),
	    m_num_connects(0),
		m_silent(silent)
	{}

	/**
	 * Starts a new thread running the server loop on the given port.
	 *
	 * The server will listen on localhost:<port> and accept incoming
	 * connections (current limitation of one active connection at once).
	 * It will then run the server loop, receiving data and storing them.
	 *
	 * @param port  The port to listen on (use 0 for an ephemeral port)
	 *
	 * @return  true  server started successfully
	 * @return  false on error
	 */
	bool start(uint16_t port = 0);
	void stop();

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
	 * Returns whether the fake collector has received any data from the agent.
	 *
	 * @return  Amount of data in the list
	 */
	uint32_t has_data() const
	{
		return m_received_data.size();
	}

	/**
	 * Gets the port the collector is listening on, if available
	 *
	 * @return The listening port, or 0 if not active
	 */
	uint16_t get_port() const
	{
		return m_port;
	}

	/**
	 * Gets the status of the server socket.
	 *
	 * @retval  NOT_STARTED  The initial state
	 * @retval  RUNNING      Server is actively accepting connections and / or data
	 * @retval  ERRORED      Server attempted to start but encountered an error
	 * @retval  SHUTDOWN     Server started and then cleanly shut down
	 */
	server_status get_status() const
	{
		return m_status;
	}

	/**
	 * Sets an artifical delay in accepting the connection.
	 *
	 * @param delay   The delay before a connection is accepted.
	 */
	void set_connection_delay(std::chrono::milliseconds delay)
	{
		m_delayed_connection = delay;
	}

	/**
	 * The fake collector should drop the connection to the agent.
	 */
	void drop_connection()
	{
		m_drop_connection = true;
	}

	/**
	 * The fake collector should send a TCP RST to the agent.
	 */
	void reset_connection()
	{
		m_reset_connection = true;
	}

	/**
	 * Takes a message protobuf and serializes it into a message, then enqueues
	 * the message on the send queue.
	 */
	template<typename T>
	bool send_collector_message(uint8_t message_type,
	                            dragent_protocol::protocol_version version,
	                            T& msg,
	                            uint64_t generation = 0,
	                            uint64_t sequence = 0,
	                            protocol_compression_method compression =
	                                    protocol_compression_method::GZIP);
	bool send_collector_message(uint8_t message_type,
	                            dragent_protocol::protocol_version version,
	                            uint8_t* buf,
	                            uint32_t buf_len,
	                            uint64_t generation = 0,
	                            uint64_t sequence = 0);

	/**
	 * Set the last ACKed <gen, seq> pair (given on handshake)
	 */
	void set_last_ack(uint64_t generation, uint64_t sequence)
	{
		m_last_gen_num = generation;
		m_last_seq_num = sequence;
	}

	/**
	 * Turn ACK delay on or off
	 */
	void delay_acks(bool should_delay)
	{
		m_delay_acks = should_delay;

		if (!should_delay)
		{
			// Send delayed acks
			while (!m_delayed_metrics.empty())
			{
				auto m = m_delayed_metrics.front();
				(void)process_auto_response(m);
				m_delayed_metrics.pop();
			}
		}
	}

	/**
	 * Get the number of disconnects seen by the collector.
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

	bool m_run_server; // Control variable

	uint16_t m_port;   // The port the server is listening on

	std::chrono::milliseconds m_delayed_connection; // Length of time to delay the connection
	bool m_drop_connection;
	bool m_reset_connection;
	bool m_auto_respond;
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
	bool m_silent;

	/**
	 * Reads one from the given file descriptor and internally handles it
	 *
	 * @param[in]  fd       The file descriptor to read from
	 *
	 * @return  Success or failure
	 */
	bool handle_one_message(int fd);

	/**
	 * In the case of a connect delay, should the server accept a connection.
	 *
	 * @param fd  The file descriptor for the socket
	 * @return  Whether the connection delay has passed
	 */
	bool should_connect(int fd);

	/**
	 * Determine what action a backend collector would take in response to the
	 * given message and take an equivalent action.
	 */
	bool process_auto_response(buf& b);

	/**
	 * Is the given version number supported by this fake collector?
	 */
	bool version_is_supported(uint8_t ver);

	/**
	 * Main execution loop for fake collector
	 */
	static void thread_loop(int sock_fd, struct sockaddr_in addr, fake_collector& fc);
};


template<typename T>
bool fake_collector::send_collector_message(uint8_t message_type,
                                            dragent_protocol::protocol_version version,
                                            T& msg,
                                            uint64_t generation,
                                            uint64_t sequence,
                                            protocol_compression_method compression)
{
	std::shared_ptr<protobuf_compressor> compressor;
	if (compression == protocol_compression_method::NONE)
	{
		compressor = null_protobuf_compressor::get();
	}
	else
	{
		compressor = gzip_protobuf_compressor::get(-1);
	}
	// Serialize the message
	std::shared_ptr<serialized_buffer> msg_buf;
	msg_buf = dragent_protocol::message_to_buffer(0,
	                                              message_type,
	                                              msg,
	                                              compressor);
	if (!msg_buf)
	{
		return false;
	}

	// Copy the std::string we get from message_to_buffer to something less stupid
	uint8_t* bytes = new uint8_t[msg_buf->buffer.length()];
	memcpy(bytes, msg_buf->buffer.c_str(), msg_buf->buffer.length());

	return send_collector_message(message_type,
	                              version,
	                              bytes,
	                              msg_buf->buffer.length(),
	                              generation,
	                              sequence);
}

template <typename T>
bool fake_collector::parse_protobuf(uint8_t* buffer, uint32_t buf_len, T& msg)
{
	   google::protobuf::io::ArrayInputStream stream(buffer, buf_len);
	   google::protobuf::io::GzipInputStream gzstream(&stream);

	   if(!msg.ParseFromZeroCopyStream(&gzstream))
	   {
		       return false;
	   }
	   return true;
}
