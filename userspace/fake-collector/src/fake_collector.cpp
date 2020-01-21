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
	if (b.hdr.v4.version == dragent_protocol::PROTOCOL_VERSION_NUMBER &&
	    b.hdr.v4.messagetype != draiosproto::message_type::PROTOCOL_INIT)
	{
		return true;
	}

	uint64_t generation = ntohll(b.hdr.v5.generation);
	uint64_t sequence = ntohll(b.hdr.v5.sequence);

	switch (b.hdr.v4.messagetype)
	{
	case draiosproto::message_type::METRICS:
	{
		// generation must never go down
		// seqence can go down if generation increases
		if (generation < m_last_gen_num ||
		    (generation == m_last_gen_num && sequence <= m_last_seq_num))
		{
			if (!m_silent) {
				std::cerr << "FC> Received metrics message with bogus gen, seq <"
						  << generation << ", " << sequence << ">" << std::endl;
			}
			// Continue processing (this may be a delayed ACK or might be part of the test)
		}
		else
		{
			m_last_gen_num = generation;
			m_last_seq_num = sequence;
		}

		if (m_delay_acks)
		{
			// Keep for later
			m_delayed_metrics.push(b);
		}
		else
		{
			send_collector_message(draiosproto::message_type::PROTOCOL_ACK,
			                       true,
			                       nullptr,
			                       0,
			                       m_last_gen_num,
			                       m_last_seq_num);
		}

		// Parse the message to validate the index number
		draiosproto::metrics msg;
		uint32_t message_len = ntohl(b.hdr.v4.len);
		uint32_t payload_len = message_len - dragent_protocol::header_len(b.hdr.v4);
		// Parse the protobuf (this might fail if it's a bogus protobuf
		// built by a unit test. That's OK).
		if(!parse_protobuf(b.ptr, payload_len, msg))
		{
			return true;
		}
		ASSERT(msg.index() == m_last_index + 1 || msg.index() == 1);
		if (!m_silent) {
			std::cout << "FC> " << "Received metrics message with index "
			          << msg.index() << std::endl;
		}
		if (msg.index() != m_last_index + 1)
		{
			if (!m_silent) {
				std::cerr << "FC> Metrics index mismatch (" << (m_last_index + 1)
						  << " expected but received " << msg.index() << ")" << std::endl;
			}
			return false;
		}
		m_last_index = msg.index();
		return true;
	}
	case draiosproto::message_type::PROTOCOL_INIT:
	{
		draiosproto::protocol_init pi;
		dragent_protocol::buffer_to_protobuf(b.ptr,
		                                     b.payload_len,
		                                     &pi,
		                                     protobuf_compressor_factory::get_default());
		draiosproto::protocol_init_response pir;

		// Get the versions supported and choose the highest one we support
		m_working_version = 0;
		for(auto v: pi.supported_protocol_versions())
		{
			if (version_is_supported(v) && v > m_working_version)
			{
				m_working_version = v;
			}
		}

		if (m_working_version == 0)
		{
			// We don't support any of the versions provided
			ASSERT(m_working_version != 0);
			return false;
		}

		pir.set_timestamp_ns(pi.timestamp_ns() + 1); // Fastest response in the West
		pir.set_machine_id(pi.machine_id());
		pir.set_customer_id(pi.customer_id());
		pir.set_protocol_version(m_working_version);
		send_collector_message(draiosproto::message_type::PROTOCOL_INIT_RESP,
							   false,
		                       pir,
		                       0,
		                       0,
		                       protobuf_compressor_factory::get_default());

		return true;
	}
	case draiosproto::message_type::PROTOCOL_HANDSHAKE_V1:
	{
		ASSERT(b.hdr.v4.version == 5);
		draiosproto::handshake_v1 h;
		dragent_protocol::buffer_to_protobuf(b.ptr,
		                                     b.payload_len,
		                                     &h,
		                                     protobuf_compressor_factory::get_default());
		draiosproto::handshake_v1_response hr;
		hr.set_timestamp_ns(h.timestamp_ns());
		hr.set_machine_id(h.machine_id());
		hr.set_customer_id(h.customer_id());
		// if this is first connection from agent, reset everything
		if (generation == 1)
		{
			ASSERT(sequence == 1);
			if (sequence != 1)
			{
				if (!m_silent) {
					std::cerr << "FC> Sequence number error: expected 1, got " << sequence << std::endl;
				}
				return false;
			}
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
		hr.set_agg_interval(0);
		for (auto i : h.supported_agg_intervals())
		{
			hr.set_agg_interval(std::max(hr.agg_interval(), i));
		}
		hr.mutable_agg_context()->set_enforce(false);
		hr.mutable_agg_context()->set_timestamp_ns(hr.timestamp_ns());
		hr.mutable_agg_context()->set_machine_id(hr.machine_id());
		send_collector_message(draiosproto::message_type::PROTOCOL_HANDSHAKE_V1_RESP,
							   false,
		                       hr,
		                       0,
		                       0,
		                       protobuf_compressor_factory::get_default());

		return true;
	}
	default:
		if (!m_silent) {
			std::cerr << "FC> Unknown message type " << (int)b.hdr.v4.messagetype << std::endl;
		}
		return false;
	}

	return true;
}

void fake_collector::thread_loop(int listen_sock_fd, sockaddr_in addr, fake_collector& fc)
{
	const uint32_t MAX_SOCKETS = 2;
	struct pollfd fds[MAX_SOCKETS] = {};
	const int timeout = 300;
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

		// Check if we need to drop a connection
		if (fc.m_drop_connection)
		{
			if (agent_fd != -1)
			{
				close(agent_fd);
				agent_fd = -1;
				fc.m_drop_connection = false;
			}
			continue;
		}

		// Check to see if we have data to send
		buf b;
		bool send = false;
		fc.m_send_queue_lock.lock();
		if (!fc.m_send_queue.empty() && agent_fd > 0 && !fc.m_drop_connection)
		{
			send = true;
			b = fc.m_send_queue.front();
			fc.m_send_queue.pop();
		}
		fc.m_send_queue_lock.unlock();

		// Send one pending message if we have one
		if (send && agent_fd > 0)
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

		if(ret == 0 || fc.m_drop_connection) // ret should be the return from poll() above
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
				if(!fc.handle_one_message(fds[fd].fd))
				{
					fds[fd].fd = -1;
					// We'll need to compact the FD list if we start supporting multiple agent connections
					--nfds;
					++fc.m_num_disconnects;
					// Dropped connection = start over, no pending messages
					while(fc.m_send_queue.size() > 0)
					{
						fc.m_send_queue.pop();
					}
					continue;
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

bool fake_collector::version_is_supported(uint8_t ver)
{
	return ver == 4 || ver == 5;
}

bool fake_collector::handle_one_message(int fd)
{
	uint32_t header_len = sizeof(dragent_protocol_header_v4);
	buf b;
	dragent_protocol_header_v4* hdr;
	uint32_t payload_len = 0;
	uint32_t payload_bytes_read = 0;
	uint8_t header_buf[sizeof(dragent_protocol_header_v5)];
	uint32_t msg_len = 0;

	// Read the header
	int read_ret = read(fd, header_buf, header_len);
	if(read_ret <= 0)
	{
		goto read_error;
	}

	hdr = (dragent_protocol_header_v4*)header_buf;
	msg_len = ntohl(hdr->len);
	b.hdr.v4.len = hdr->len;
	b.hdr.v4.messagetype = hdr->messagetype;
	b.hdr.v4.version = hdr->version;

	if(msg_len <= 0)
	{
		if (!m_silent) {
			std::cerr << "FC> Invalid length in header " << msg_len << std::endl;
		}
		return false;
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
		b.hdr.v5.sequence = v5_hdr->sequence;
		b.hdr.v5.generation = v5_hdr->generation;
	}
	payload_len = msg_len - header_len;

	// Allocate the buffer for the payload
	b.ptr = new uint8_t[payload_len];

	// Now read the body
	while (payload_bytes_read < payload_len)
	{
		read_ret = read(fd,
		                &b.ptr[payload_bytes_read],
		                payload_len - payload_bytes_read);
		if(read_ret <= 0)
		{
			goto read_error;
		}
		payload_bytes_read += read_ret;
	}

	b.payload_len = payload_bytes_read;
	m_received_data.push(b);

	if (m_auto_respond)
	{
		// If it's a protobuf, handle it. If not, just store it in the queue
		// of received data
		(void)process_auto_response(b); // Handle errors?
	}

	return true;

read_error:
	if(read_ret == -1)
	{
		// Socket disconnected (this could be fine or could be very bad)
		if (!m_silent) {
			std::cout << "FC> agent socket closed" << std::endl;
		}
	}
	if(read_ret < 0)
	{
		m_error_code = read_ret;
		m_error_msg = strerror(read_ret);
		if (!m_silent) {
			std::cerr << "FC> Error " << read_ret << " on read: " << m_error_msg << std::endl;
		}
	}
	return false;
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
	    htonll(generation),
	    htonll(sequence),
	};

	// Fire away
	buf b(buffer, hdr);
	{
		scoped_spinlock s(m_send_queue_lock);
		m_send_queue.push(b);
	}

	return true;
}
