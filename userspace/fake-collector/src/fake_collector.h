#pragma once

#include <cstdint>
#include <queue>
#include <string>
#include <stdexcept>
#include <chrono>
#include <unordered_map>
#include "protocol.h"

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
		dragent_protocol_header_v5 hdr;
		buf(uint8_t* _ptr, dragent_protocol_header_v5 _hdr):
			ptr(_ptr), hdr(_hdr) {}
	};

	fake_collector():
		m_received_data(),
		m_status(server_status::NOT_STARTED),
		m_error_code(0),
		m_error_msg(""),
		m_run_server(false),
		m_port(0),
		m_delayed_connection(0)
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

private:
	const uint32_t MAX_STORED_DATAGRAMS = 32;
	std::queue<buf> m_received_data;
	server_status m_status;
	int m_error_code;        // Currently internal-only for debugging
	std::string m_error_msg; // Currently internal-only for debugging

	bool m_run_server; // Control variable

	uint16_t m_port;   // The port the server is listening on

	std::chrono::milliseconds m_delayed_connection; // Length of time to delay the connection
	std::unordered_map<int, std::chrono::system_clock::time_point> wait_list; // Internal tracking of connect delays

	/**
	 * Reads one from the given file descriptor
	 *
	 * @param[in]  fd       The file descriptor to read from
	 * @param[out] buffer   The buffer to read the data into
	 * @param[in]  buf_len  The max length of the buffer
	 * @param[out] hdr		The header data for this message. Values for fields not contained
	 * 						in the received message are undefined.
	 *
	 * @return  The length of data read. Zero indicates a read failure.
	 */
	uint32_t read_one_message(int fd,
							  char* buffer,
							  uint32_t buf_len,
							  dragent_protocol_header_v5* hdr);

	/**
	 * In the case of a connect delay, should the server accept a connection.
	 *
	 * @param fd  The file descriptor for the socket
	 * @return  Whether the connection delay has passed
	 */
	bool should_connect(int fd);

	static void thread_loop(int sock_fd, struct sockaddr_in* addr, fake_collector& fc);
};
