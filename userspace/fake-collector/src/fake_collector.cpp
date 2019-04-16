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
	std::thread t([sock_fd, &addr, this]()
	{
		const uint32_t MAX_SOCKETS = 2;
		char temp_buf[1024] = {};
		struct pollfd fds[MAX_SOCKETS] = {};
		const int timeout = 1000;
		nfds_t nfds = 1;
		int agent_fd = -1;

		fds[0].fd = sock_fd;
		fds[0].events = POLLIN;


		while(m_run_server)
		{
			//
			// Server loop
			//
			socklen_t addr_len = sizeof(addr);
			int ret = poll(fds, nfds, timeout);

			if(ret < 0)
			{
				m_error_msg = strerror(errno);
				m_error_code = errno;
				m_status = server_status::ERRORED;
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
					agent_fd = accept(sock_fd, (struct sockaddr *)&addr, &addr_len);
					if(agent_fd < 0)
					{
						m_error_msg = strerror(errno);
						m_error_code = errno;
						m_status = server_status::ERRORED;
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
					uint32_t read_ret = read_one_message(fds[fd].fd, temp_buf, sizeof(temp_buf));
					if(read_ret == 0)
					{
						fds[fd].fd = -1;
						// We'll need to compact the FD list if we start supporting multiple agent connections
						--nfds;
						continue;
					}

					// Yay inefficient
					uint8_t* bufp = new uint8_t[read_ret + 1];
					memcpy(bufp, temp_buf, read_ret + 1);

					m_received_data.push(buf(bufp, read_ret + 1));
				}
			}
		}
		m_status = server_status::SHUTDOWN;
		this->m_port = 0;
		shutdown(sock_fd, SHUT_RDWR);
		close(sock_fd);
	});

	t.detach();
	return true;
}

void fake_collector::stop()
{
	m_run_server = false;
}

uint32_t fake_collector::read_one_message(int fd, char* buffer, uint32_t buf_len)
{
	const uint32_t header_len = 5;
	int len = 0;

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
	buffer[read_ret] = '\0';

	len = std::stoi(buffer);

	if(len <= 0)
	{
		return 0;
	}

	if(buf_len < (uint32_t)len + 1)
	{
		return 0;
	}

	// Now read the body
	read_ret = read(fd, buffer, len);
	if(read_ret <= 0)
	{
		goto read_error;
	}
	buffer[read_ret] = '\0';

	return read_ret;

read_error:
	if(read_ret < 0)
	{
		m_error_code = read_ret;
		m_error_msg = strerror(read_ret);
	}
	return 0;
}
