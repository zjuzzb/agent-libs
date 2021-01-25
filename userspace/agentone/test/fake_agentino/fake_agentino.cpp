/**
 * @file
 *
 * Implements a fake collector for unit testing the connection manager.
 *
 * Copyright (c) 2019 Sysdig, Inc. All rights reserved.
 */

#include "draios.pb.h"
#include "agentino.pb.h"
#include "fake_agentino.h"

#include <thread>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unordered_map>
#include <chrono>

// Server / socket stuff
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#include <protocol.h>
#include "spinlock.h"

using msecs = std::chrono::milliseconds;


bool fake_agentino::process_auto_response(buf& b)
{
	if (!version_is_supported(b.hdr.v4.version))
	{
		return false;
	}

	switch (b.hdr.v4.messagetype)
	{
	case draiosproto::message_type::AGENTINO_HANDSHAKE_RESPONSE:
	{
		if (m_status != server_status::HANDSHAKING)
		{
			if (!m_silent)
			{
				std::cerr << "FA> Unexpected handshake response message received\n";
			}
			return false;
		}

		// Parse the message
		draiosproto::agentino_handshake_response msg;
		uint32_t message_len = ntohl(b.hdr.v4.len);
		uint32_t payload_len = message_len - dragent_protocol::header_len(b.hdr.v4);
		assert(payload_len == b.payload_len);
		if(!parse_protobuf(b.ptr, payload_len, msg))
		{
			if (!m_silent)
			{
				std::cerr << "FA> Error parsing handshake response protobuf\n";
			}
			return false;
		}

		// Complete the handshake

		m_most_recent_received_policies = msg.policies();

		m_status = server_status::RUNNING;

		return true;
	}
	case draiosproto::message_type::POLICIES_V2:
	{
		// Parse policies message
		dragent_protocol::buffer_to_protobuf(b.ptr,
		                                     b.payload_len,
		                                     &m_most_recent_received_policies,
		                                     protocol_compression_method::GZIP);

		return true;
	}
	default:
		if (!m_silent)
		{
			std::cerr << "FA> Unknown message type " << (int)b.hdr.v4.messagetype << std::endl;
		}
		return false;
	}

	return true;
}

void fake_agentino::thread_loop(uint16_t port, fake_agentino& fa)
{
	int res;
	bool ret;
	const int timeout_ms = 100;

	assert(fa.m_status == server_status::NOT_STARTED);

	while(fa.m_run_loop)
	{
		fa.m_status = server_status::CONNECTING;

		//
		// Outer loop -- connect / reconnect
		//
		int sockfd;
		struct sockaddr_in addr;
		sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		memset(&addr, 0, sizeof(addr));
		addr.sin_family      = AF_INET;
		addr.sin_port        = htons(port);
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");

		res = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
		if (res != 0)
		{
		  fa.m_error_code = errno;
		  fa.m_error_msg = strerror(errno);
		  fa.m_status = server_status::ERRORED;
		  if (!fa.m_silent)
		  {
			  std::cerr << "FA> Error connecting to agentone: " << errno
			            << strerror(errno) << std::endl;
		  }
		  return;
		}

		fa.m_status = server_status::CONNECTED;

		if (fa.m_auto_respond)
		{
			ret = fa.send_handshake_message(sockfd);
			if (!ret)
			{
				if (fa.m_error_msg.empty())
				{
					fa.m_error_msg = "Error sending handshake";
				}
				fa.m_status = server_status::ERRORED;
				if (!fa.m_silent)
				{
					std::cerr << "FA> Error in handshake message: " << fa.m_error_msg
					          << std::endl;
				}
				return;
			}
			fa.m_status = server_status::HANDSHAKING;
		}

		nfds_t nfds = 1;
		struct pollfd fds[1] = {{sockfd, POLLIN | POLLERR}};

		bool connected = true;
		while (connected && fa.m_run_loop)
		{
			// Inner loop -- send / receive while connected

			// If paused, sleep and restart the loop
			if (fa.m_pause)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				continue;
			}

			// Start with a poll for socket readiness
			res = poll(fds, nfds, timeout_ms);
			if (res < 0)
			{
				fa.m_error_msg = strerror(errno);
				fa.m_error_code = errno;
				if (!fa.m_silent)
				{
					std::cerr << "FA> Error polling for data: " << errno
					          << strerror(errno) << std::endl;
				}
				fa.m_status = server_status::ERRORED;
				return;
			}

			// Check if fake agentino has shut down
			if (!connected || !fa.m_run_loop)
			{
				continue;
			}

			// Check if we need to drop a connection
			if (fa.m_drop_connection)
			{
				connected = false;
				fa.m_drop_connection = false;
				continue;
			}

			// Send data if we have it
			{
				buf b;
				scoped_spinlock s(fa.m_send_queue_lock);
				if (!fa.m_send_queue.empty() && !fa.m_drop_connection)
				{
					b = fa.m_send_queue.front();
					bool ret = fa.transmit_buf(b, sockfd);

					++fa.m_num_sent_msgs;
					if (!ret)
					{
						if (!fa.m_silent)
						{
							std::cerr << "FA> Error sending data to agentone: "
							          << strerror(errno) << std::endl;
						}
						fa.m_status = server_status::ERRORED;
						connected = false;
						continue;
					}
					fa.m_send_queue.pop();
				}
			}

			// res is the return value from poll(); 0 means timeout
			if (res == 0 || fds[0].revents == 0)
			{
				continue;
			}

			// Receive data
			ret = fa.handle_one_message(fds[0].fd);
			if (!ret)
			{
				if (fa.m_error_code != 0)
				{
					// Bad thing happened
					fa.m_status = server_status::ERRORED;
					if (!fa.m_silent)
					{
						std::cerr << "FA> Error handling message: "
								  << strerror(errno) << std::endl;
					}

				}
				else
				{
					// Agentone disconnected
					fa.m_status = server_status::DISCONNECTED;
				}
				connected = false;
				continue;
			}

		} // End inner loop

		// Post-disconnect cleanup
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
		++fa.m_num_disconnects;
		while (fa.m_send_queue.size() > 0)
		{
			fa.m_send_queue.pop();
		}

		// If no auto reconnect, just drop out of the loop and shut down
		if (!fa.m_auto_reconnect)
		{
			fa.m_run_loop = false;
		}
	} // End outer loop
	if (fa.m_status != server_status::ERRORED && fa.m_status != server_status::DISCONNECTED)
	{
		fa.m_status = server_status::SHUTDOWN;
	}
	fa.m_port = 0;
}

fake_agentino::~fake_agentino()
{
	while (!m_received_data.empty())
	{
		delete[] m_received_data.front().ptr;
		m_received_data.pop();
	}
}

bool fake_agentino::start(uint16_t port)
{
	m_run_loop = true;
	m_port = port;

	//
	// Server loop
	//
	std::thread t = std::thread(fake_agentino::thread_loop, port, std::ref(*this));

	t.detach();
	return true;
}

void fake_agentino::stop()
{
	m_run_loop = false;
	m_port = 0;

	// The poor man's join
	while (m_status != server_status::SHUTDOWN &&
	       m_status != server_status::DISCONNECTED &&
	       m_status != server_status::ERRORED)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

void fake_agentino::pause(bool should_pause)
{
	m_pause = should_pause;
}

bool fake_agentino::version_is_supported(uint8_t ver)
{
	return ver == 5;
}

bool fake_agentino::handle_one_message(int fd)
{
	uint32_t header_len = sizeof(dragent_protocol_header_v5);
	dragent_protocol_header_v5* hdr;
	uint32_t payload_len = 0;
	uint32_t payload_bytes_read = 0;
	uint8_t header_buf[sizeof(dragent_protocol_header_v5)];
	uint32_t msg_len = 0;
	uint8_t* payload_buf;
	buf b;

	// Read the header
	int read_ret = read(fd, header_buf, header_len);
	if (read_ret <= 0)
	{
		goto read_error;
	}
	if (read_ret < header_len)
	{
		if (!m_silent)
		{
			std::cerr << "FA> Did not receive a full header\n";
		}
		goto read_error;
	}
	hdr = (dragent_protocol_header_v5*)header_buf;
	msg_len = ntohl(hdr->hdr.len);

	if (msg_len < header_len)
	{
		if (!m_silent)
		{
			std::cerr << "FA> Protocol error: Invalid length in header: " << msg_len << std::endl;
		}
		return false;
	}

	payload_len = msg_len - header_len;

	// Allocate the buffer for the payload
	payload_buf = new uint8_t[payload_len];

	// Now read the body
	while (payload_bytes_read < payload_len)
	{
		read_ret = read(fd,
		                &payload_buf[payload_bytes_read],
		                payload_len - payload_bytes_read);
		if(read_ret <= 0)
		{
			goto read_error;
		}
		payload_bytes_read += read_ret;
	}
	b.hdr.v5 = *hdr;
	b.ptr = payload_buf;
	b.payload_len = payload_bytes_read;
	m_received_data.push(b);

	if (m_auto_respond)
	{
		(void)process_auto_response(b); // Handle errors?
	}

	return true;

read_error:
	if(read_ret == 0)
	{
		// Socket disconnected (this could be fine or could be very bad)
		if (!m_silent)
		{
			std::cout << "FA> agentino socket closed" << std::endl;
		}
	}
	if(read_ret < 0)
	{
		m_error_code = read_ret;
		m_error_msg = strerror(read_ret);
		if (!m_silent)
		{
			std::cerr << "FA> Error " << errno << " on read: " << strerror(errno) << std::endl;
		}
	}
	return false;
}

fake_agentino::buf fake_agentino::build_buf(uint8_t message_type,
                                            dragent_protocol::protocol_version version,
                                            uint8_t* buffer,
                                            uint32_t buf_len,
                                            uint64_t generation,
                                            uint64_t sequence)
{
	int32_t header_len = dragent_protocol::header_len(version);
	if (header_len == 0)
	{
		// We were given an invalid version. That's OK, it's probably
		// for testing. Just use v4.
		header_len = sizeof(dragent_protocol_header_v4);
	}

	// Build the header
	dragent_protocol_header_v5 hdr =
	{
	    {
	        htonl(header_len + buf_len),
	        version,
	        message_type
	    },
	    htonll(generation),
	    htonll(sequence),
	};

	return {buffer, hdr, buf_len};
}

bool fake_agentino::enqueue_agentone_message(fake_agentino::buf& b)
{
	scoped_spinlock s(m_send_queue_lock);
	m_send_queue.push(b);
	return true;
}

bool fake_agentino::transmit_buf(fake_agentino::buf& b, int sockfd)
{
	int write_ret = 0;
	if (b.hdr.v4.version == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH)
	{
		write_ret = write(sockfd, (uint8_t*)&b.hdr, sizeof(b.hdr.v5));
	}
	else if (b.hdr.v4.version <= dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		// Handle sending headers with invalid version numbers
		write_ret = write(sockfd, (uint8_t*)&b.hdr, sizeof(b.hdr.v4));
	}

	if (write_ret < 0)
	{
		m_error_msg = strerror(errno);
		m_error_code = errno;
		return false;
	}
	if (write_ret == 0)
	{
		return false;
	}
	write_ret = write(sockfd, b.ptr, b.payload_len);
	if (write_ret < 0)
	{
		m_error_msg = strerror(errno);
		m_error_code = errno;
		return false;
	}
	if (write_ret == 0)
	{
		return false;
	}
	return true;
}

bool fake_agentino::send_handshake_message(int sockfd)
{
	static uint64_t ts_ns = 1000;

	draiosproto::agentino_handshake hs;
	hs.set_timestamp_ns(++ts_ns);
	hs.mutable_metadata()->set_container_id("FA id");
	hs.mutable_metadata()->set_container_image("FA image");
	hs.mutable_metadata()->set_container_name("FA");

	// Use the send_message function to build a buf
	buf b = build_buf(draiosproto::message_type::AGENTINO_HANDSHAKE,
	                  dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH,
	                  hs,
	                  0,
	                  0);
	if (!b.ptr)
	{
		return false;
	}

	bool ret = transmit_buf(b, sockfd);
	delete[] b.ptr;
	return ret;
}
