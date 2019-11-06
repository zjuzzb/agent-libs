/**
 * @file
 *
 * Implements a fake collector for unit testing the connection manager.
 *
 * Copyright (c) 2019 Sysdig, Inc. All rights reserved.
 */

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

void fake_collector::thread_loop(int sock_fd, struct sockaddr_in* addr, fake_collector& fc)
{
	const uint32_t MAX_SOCKETS = 2;
	char temp_buf[1024] = {};
	struct pollfd fds[MAX_SOCKETS] = {};
	const int timeout = 1000;
	nfds_t nfds = 1;
	int agent_fd = -1;

	fds[0].fd = sock_fd;
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
			if(fds[fd].fd == sock_fd)
			{
				if(!fc.should_connect(fds[fd].fd))
				{
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
					continue;
				}
				agent_fd = accept(sock_fd, (struct sockaddr *)&addr, &addr_len);
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
				dragent_protocol_header_v5 hdr = {{0}};
				uint32_t read_ret = fc.read_one_message(fds[fd].fd, temp_buf, sizeof(temp_buf), &hdr);
				if(read_ret == 0)
				{
					fds[fd].fd = -1;
					// We'll need to compact the FD list if we start supporting multiple agent connections
					--nfds;
					continue;
				}

				// Yay inefficient
				uint8_t* bufp = new uint8_t[read_ret];
				memcpy(bufp, temp_buf, read_ret);

				fc.m_received_data.push(buf(bufp, hdr));
			}
		}
	}
	fc.m_status = server_status::SHUTDOWN;
	fc.m_port = 0;
	shutdown(sock_fd, SHUT_RDWR);
	close(sock_fd);
}

bool fake_collector::start(uint16_t port)
{
	m_run_server = true;
	struct sockaddr_in addr = {};

	//
	// Create, configure, and bind the socket
	//
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd < 0)
	{
		m_error_msg = strerror(errno);
		m_error_code = errno;
		m_status = server_status::ERRORED;
		return false;
	}

	int opt = 1;
	int ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
	if(ret < 0)
	{
		m_error_msg = strerror(errno);
		m_error_code = errno;
		m_status = server_status::ERRORED;
		return false;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	ret = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
	if(ret < 0)
	{
		m_error_msg = strerror(errno);
		m_error_code = errno;
		m_status = server_status::ERRORED;
		return false;
	}

	// Find out which port we got
	socklen_t addr_len = sizeof(addr);
	ret = getsockname(sock_fd, (struct sockaddr *)&addr, &addr_len);
	this->m_port = ntohs(addr.sin_port);

	//
	// Set listening mode on the socket
	//
	if(listen(sock_fd, 1) < 0)
	{
		m_error_msg = strerror(errno);
		m_error_code = errno;
		m_status = server_status::ERRORED;
		return false;
	}

	m_status = server_status::RUNNING;

	//
	// Server loop
	//
	std::thread t(fake_collector::thread_loop, sock_fd, &addr, std::ref(*this));

	t.detach();
	return true;
}

void fake_collector::stop()
{
	m_run_server = false;

	while(m_status == server_status::RUNNING)
	{
	    std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}

uint32_t fake_collector::read_one_message(int fd,
										  char* buffer,
										  uint32_t buf_len,
										  dragent_protocol_header_v5* hdr)
{
	uint32_t header_len = sizeof(dragent_protocol_header_v4);

	if(buf_len < (header_len + 1) || !buffer)
	{
		return 0;
	}

	// Read the header
	int read_ret = read(fd, buffer, header_len);
	if(read_ret <= 0)
	{
		goto read_error;
	}

	hdr->hdr = *(dragent_protocol_header_v4*)buffer;
	hdr->hdr.len = htonl(hdr->hdr.len);
	if(htonl(hdr->hdr.len) <= 0)
	{
		return 0;
	}

	if (hdr->hdr.version == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH)
	{
		read_ret = read(fd,
						buffer + header_len,
						sizeof(dragent_protocol_header_v5) - header_len);
		header_len = sizeof(dragent_protocol_header_v5);
		if(read_ret <= 0)
		{
			goto read_error;
		}
		*hdr = *(dragent_protocol_header_v5*)buffer;
		hdr->hdr.len = htonl(hdr->hdr.len);
		hdr->sequence = htonll(hdr->sequence);
		hdr->generation = htonll(hdr->generation);
	}
	// Now read the body
	read_ret = read(fd, buffer, hdr->hdr.len - header_len);
	if(read_ret <= 0)
	{
		goto read_error;
	}

	return read_ret;

read_error:
	if(read_ret < 0)
	{
		m_error_code = read_ret;
		m_error_msg = strerror(read_ret);
	}
	return 0;
}
