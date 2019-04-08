//
// Created by Luca Marturana on 30/06/15.
//

#pragma once

#ifndef _WIN32
#include <string>
#include <mqueue.h>
#include <fcntl.h>

#include "noncopyable.h"

class posix_queue: noncopyable
{
public:
	static constexpr unsigned long min_msgqueue_limit() {
		return MAX_QUEUES * (MAX_MSGS+2) * MAX_MSGSIZE;
	}

	enum direction_t
	{
		SEND = O_WRONLY, RECEIVE = O_RDONLY
	};
	/**
	 * @param name use format: sdc_<module>_{in|out}
	 */
	posix_queue(std::string name, direction_t dir, long maxmsgs=MAX_MSGS);
	~posix_queue();

	bool send(const std::string& msg);
	std::string receive(uint64_t timeout_s=0);
	static bool remove(const std::string& name);
private:
	mqd_t m_queue_d;
	direction_t m_direction;
	std::string m_name;
	char* m_readbuffer;
	static const long MAX_MSGSIZE = 3 << 20; // 3 MiB
	static const long MAX_QUEUES = 10;
	static const long MAX_MSGS = 3;
};
#endif // _WIN32