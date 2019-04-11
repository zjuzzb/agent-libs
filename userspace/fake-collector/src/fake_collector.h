#pragma once

#include <cstdint>
#include <queue>
#include <string>
#include <stdexcept>


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
		uint32_t buf_len;
		buf(uint8_t* _ptr, uint32_t _len):
			ptr(_ptr), buf_len(_len) {}
	};

	fake_collector():
		m_received_data(),
		m_status(server_status::NOT_STARTED),
		m_error_code(0),
		m_error_msg(""),
		m_run_server(false),
		m_port(0)
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
	buf& pop_data()
	{
		buf&& ret = std::move(m_received_data.front());

		m_received_data.pop();
		return ret;
	}

	/**
	 * Returns whether the fake collector has received any data from the agent.
	 *
	 * @return  Is there data in the data list?
	 */
	bool has_data() const
	{
		return !m_received_data.empty();
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

private:
	const uint32_t MAX_STORED_DATAGRAMS = 32;
	std::queue<buf> m_received_data;
	server_status m_status;
	int m_error_code;        // Currently internal-only for debugging
	std::string m_error_msg; // Currently internal-only for debugging

	bool m_run_server; // Control variable

	uint16_t m_port;   // The port the server is listening on

	/**
	 * Reads one from the given file descriptor
	 *
	 * @param[in]  fd       The file descriptor to read from
	 * @param[out] buffer   The buffer to read the data into
	 * @param[in]  buf_len  The max length of the buffer
	 *
	 * @return  The length of data read. Zero indicates a read failure.
	 */
	uint32_t read_one_message(int fd, char* buffer, uint32_t buf_len);

};
