/**
 * @file
 *
 * Implements a fake collector for unit testing the connection manager.
 *
 * Copyright (c) 2019 Sysdig, Inc. All rights reserved.
 */

#include "handshake.pb.h"
#include "draios.pb.h"
#include "fake_collector.h"

#include <thread>
#include <iostream>
#include <cstdint>

// Server / socket stuff
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <unordered_map>
#include <chrono>

#include <protocol.h>
#include "spinlock.h"

using msecs = std::chrono::milliseconds;

bool fake_collector::should_connect(int fd)
{
	auto start_time = wait_list.find(fd);

	if(start_time == wait_list.end())
	{
		wait_list.insert({fd, std::chrono::system_clock::now()});
		return false;
	}
	msecs m = std::chrono::duration_cast<msecs>(std::chrono::system_clock::now() - start_time->second);
	if(m >= m_delayed_connection)
	{
		wait_list.erase(fd);
		return true;
	}
	return false;
}

bool fake_collector::process_auto_response(buf& b)
{

	if (b.hdr.v4.version == dragent_protocol::PROTOCOL_VERSION_NUMBER)
	{
		return true;
	}

	switch (b.hdr.v4.messagetype)
	{
	case draiosproto::message_type::METRICS:
	{
		// generation must never go down
		// seqence can go down if generation increases
		if (b.hdr.v5.generation < m_last_gen_num ||
			(b.hdr.v5.generation == m_last_gen_num &&
			 b.hdr.v5.sequence <= m_last_seq_num))
		{
			return false; // DOFL: drop on the floor...laughing
		}
		m_last_gen_num = b.hdr.v5.generation;
		m_last_seq_num = b.hdr.v5.sequence;
		send_collector_message(draiosproto::message_type::METRICS_ACK,
							   true,
							   nullptr,
							   0,
							   m_last_gen_num,
							   m_last_seq_num);
		return true;
	}
	case draiosproto::message_type::PROTOCOL_INIT:
	{
		draiosproto::protocol_init pi;
		dragent_protocol::buffer_to_protobuf(b.ptr, b.payload_len, &pi);
		draiosproto::protocol_init_response pir;
		pir.set_timestamp_ns(pi.timestamp_ns());
		pir.set_machine_id(pi.machine_id());
		pir.set_customer_id(pi.customer_id());
		pir.set_protocol_version(std::max(m_protocol_version, pi.max_protocol_version()));
		send_collector_message(draiosproto::message_type::PROTOCOL_INIT_RESP,
							   false,
							   pir);

		return false;
	}
	case draiosproto::message_type::PROTOCOL_HANDSHAKE_V1:
	{
		draiosproto::handshake_v1 h;
		dragent_protocol::buffer_to_protobuf(b.ptr, b.payload_len, &h);
		draiosproto::handshake_v1_response hr;
		hr.set_timestamp_ns(h.timestamp_ns());
		hr.set_machine_id(h.machine_id());
		hr.set_customer_id(h.customer_id());
		// if this is first connection from agent, reset everything
		if (h.generation_num() == 1)
		{
			m_last_gen_num = 0;
			m_last_seq_num = 0;
		}
		hr.set_last_acked_gen_num(m_last_gen_num);
		hr.set_last_acked_seq_num(m_last_seq_num);
		hr.set_compression(draiosproto::compression::COMPRESSION_NONE);
		for (auto i : h.supported_compressions())
		{
			if (i == draiosproto::compression::COMPRESSION_GZIP)
			{
				hr.set_compression(draiosproto::compression::COMPRESSION_GZIP);
			}
		}
		hr.set_agg_interval(1);
		for (auto i : h.supported_agg_intervals())
		{
			hr.set_agg_interval(std::max(hr.agg_interval(), i));
		}
		hr.mutable_agg_context()->set_enforce(false);
		send_collector_message(draiosproto::message_type::PROTOCOL_HANDSHAKE_V1_RESP,
							   false,
							   hr);

		return false;
	}
	}

	return true;
}

void fake_collector::thread_loop(int listen_sock_fd, sockaddr_in addr, fake_collector& fc)
{
	const uint32_t MAX_SOCKETS = 2;
	struct pollfd fds[MAX_SOCKETS] = {};
	const int timeout = 1000;
	nfds_t nfds = 1;
	int agent_fd = -1;

	fds[0].fd = listen_sock_fd;
	fds[0].events = POLLIN;


	while(fc.m_run_server)
	{
		//
		// Server loop
		//
		socklen_t addr_len = sizeof(addr);
		int ret = poll(fds, nfds, timeout);

		if(ret < 0)
		{
			fc.m_error_msg = strerror(errno);
			fc.m_error_code = errno;
			fc.m_status = server_status::ERRORED;
			return;
		}

		// Check to see if we have data to send
		buf b;
		bool send = false;
		fc.m_send_queue_lock.lock();
		if (!fc.m_send_queue.empty() && agent_fd > 0)
		{
			send = true;
			b = fc.m_send_queue.front();
			fc.m_send_queue.pop();
		}
		fc.m_send_queue_lock.unlock();

		// Send one pending message if we have one
		if (send)
		{
			uint32_t buf_len = ntohl(b.hdr.v4.len);
			int write_ret = 0;
			if (b.hdr.v4.version == dragent_protocol::PROTOCOL_VERSION_NUMBER)
			{
				write_ret = write(agent_fd, (uint8_t*)&b.hdr, sizeof(b.hdr.v4));
			}
			else
			{
				write_ret = write(agent_fd, (uint8_t*)&b.hdr, sizeof(b.hdr.v5));
			}
			if (write_ret < 0)
			{
				fc.m_error_msg = strerror(errno);
				fc.m_error_code = errno;
				fc.m_status = server_status::ERRORED;
				return;
			}
			buf_len -= write_ret;
			write(agent_fd, b.ptr, buf_len);
		}

		if(ret == 0)
		{
			continue;
		}

		nfds_t polled_fds = nfds;
		// Process all the polled descriptors for valid events
		for(nfds_t fd = 0; fd < polled_fds; ++fd)
		{
			if(fds[fd].revents == 0)
			{
				continue;
			}

			// We have an incoming connection. Accept it, build a new socket, and add it to the list
			if(fds[fd].fd == listen_sock_fd)
			{
				if(!fc.should_connect(fds[fd].fd))
				{
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
					continue;
				}
				agent_fd = accept(listen_sock_fd, (struct sockaddr *)&addr, &addr_len);
				if(agent_fd < 0)
				{
					fc.m_error_msg = strerror(errno);
					fc.m_error_code = errno;
					fc.m_status = server_status::ERRORED;
					return;
				}
				if(nfds > MAX_SOCKETS)
				{
					// Too many sockets; can't accept this connection
					close(agent_fd);
					continue;
				}
				fds[nfds].fd = agent_fd;
				fds[nfds].events = POLLIN;
				++nfds;
			}
			else // Descriptor is for a client connection that's become readable
			{
				buf b = {};
				uint32_t read_ret = fc.read_one_message(fds[fd].fd, &b);
				if(read_ret == 0)
				{
					fds[fd].fd = -1;
					// We'll need to compact the FD list if we start supporting multiple agent connections
					--nfds;
					continue;
				}

				bool should_enqueue = true;
				if (fc.m_auto_respond)
				{
					should_enqueue = fc.process_auto_response(b);
				}

				if (should_enqueue)
				{
					fc.m_received_data.push(b);
				}
			}
		}
	}
	fc.m_status = server_status::SHUTDOWN;
	fc.m_port = 0;
	shutdown(listen_sock_fd, SHUT_RDWR);
	close(listen_sock_fd);
}

bool fake_collector::start(uint16_t port)
{
	m_run_server = true;
	struct sockaddr_in addr = {};
	socklen_t addr_len = 0;
	std::thread t;
	int opt = 0;
	int ret = 0;

	//
	// Create, configure, and bind the listening socket
	//
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd < 0)
	{
		goto handle_error;
	}

	opt = 1;
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
	if(ret < 0)
	{
		goto handle_error;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	ret = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
	if(ret < 0)
	{
		goto handle_error;
	}

	// Find out which port we got
	addr_len = sizeof(addr);
	ret = getsockname(sock_fd, (struct sockaddr *)&addr, &addr_len);
	this->m_port = ntohs(addr.sin_port);

	//
	// Set listening mode on the socket
	//
	if(listen(sock_fd, 1) < 0)
	{
		goto handle_error;
	}

	m_status = server_status::RUNNING;

	//
	// Server loop
	//
	t = std::thread(fake_collector::thread_loop, sock_fd, addr, std::ref(*this));

	t.detach();
	return true;

handle_error:
	m_error_msg = strerror(errno);
	m_error_code = errno;
	m_status = server_status::ERRORED;
	return false;
}

void fake_collector::stop()
{
	m_run_server = false;

	while(m_status == server_status::RUNNING)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

uint32_t fake_collector::read_one_message(int fd, buf* out_buf)
{
	uint32_t header_len = sizeof(dragent_protocol_header_v4);
	dragent_protocol_header_v4* hdr;
	uint32_t payload_len = 0;
	uint32_t payload_bytes_read = 0;
	uint8_t header_buf[sizeof(dragent_protocol_header_v5)];

	// Read the header
	int read_ret = read(fd, header_buf, header_len);
	if(read_ret <= 0)
	{
		goto read_error;
	}

	hdr = (dragent_protocol_header_v4*)header_buf;
	out_buf->hdr.v4.len = htonl(hdr->len);
	out_buf->hdr.v4.messagetype = hdr->messagetype;
	out_buf->hdr.v4.version = hdr->version;

	if(htonl(hdr->len) <= 0)
	{
		return 0;
	}

	if (hdr->version == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH)
	{
		dragent_protocol_header_v5* v5_hdr;
		// Read the additional fields for the new header
		read_ret = read(fd,
		                header_buf + header_len,
						sizeof(dragent_protocol_header_v5) - header_len);
		header_len = sizeof(dragent_protocol_header_v5);
		if(read_ret <= 0)
		{
			goto read_error;
		}
		v5_hdr = (dragent_protocol_header_v5*)header_buf;
		out_buf->hdr.v5.sequence = htonll(v5_hdr->sequence);
		out_buf->hdr.v5.generation = htonll(v5_hdr->generation);
	}
	payload_len = out_buf->hdr.v4.len - header_len;

	// Allocate the buffer for the payload
	out_buf->ptr = new uint8_t[payload_len];

	// Now read the body
	while (payload_bytes_read < payload_len)
	{
		read_ret = read(fd,
		                &out_buf->ptr[payload_bytes_read],
		                payload_len - payload_bytes_read);
		if(read_ret <= 0)
		{
			goto read_error;
		}
		payload_bytes_read += read_ret;
	}

	out_buf->payload_len = payload_bytes_read;
	return read_ret;

read_error:
	if(read_ret < 0)
	{
		m_error_code = read_ret;
		m_error_msg = strerror(read_ret);
	}
	return 0;
}

bool fake_collector::send_collector_message(uint8_t message_type,
                                            bool v5,
                                            uint8_t* buffer,
                                            uint32_t buf_len,
                                            uint64_t generation,
                                            uint64_t sequence)
{
	int32_t header_len = v5 ? sizeof(dragent_protocol_header_v5)
	                             : sizeof(dragent_protocol_header_v4);

	// Build the header
	dragent_protocol_header_v5 hdr =
	{
	    {
	        htonl(header_len + buf_len),
	        v5 ? dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH
	           : dragent_protocol::PROTOCOL_VERSION_NUMBER,
	        message_type
	    },
	    generation,
	    sequence,
	};

	// Fire away
	buf b(buffer, hdr);
	{
		scoped_spinlock s(m_send_queue_lock);
		m_send_queue.push(b);
	}

	return true;
}
