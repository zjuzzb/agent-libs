//
// Created by Luca Marturana on 30/06/15.
//

#pragma once

#include <sinsp.h>
#include "analyzer_utils.h"
#include <string>
#include <mqueue.h>
#include <fcntl.h>

class posix_queue: noncopyable
{
public:
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
	string receive(const uint64_t timeout_s=0);
	static bool remove(const string& name);
private:
	static bool limits_set;
	static bool set_queue_limits();
	mqd_t m_queue_d;
	direction_t m_direction;
	string m_name;
	static const long MAX_MSGSIZE = 3 << 20; // 3 MiB
	static const long MAX_QUEUES = 10;
	static const long MAX_MSGS = 3;
};
