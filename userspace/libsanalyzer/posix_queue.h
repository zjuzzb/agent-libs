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
	posix_queue(std::string name, direction_t dir, long maxmsgs=3);
	~posix_queue();

	bool send(const std::string& msg);
	string receive();
	string receive(const uint64_t timeout_s);
	static bool remove(const string& name);
private:
	static bool limits_set;
	static bool set_queue_limits();
	mqd_t m_queue_d;
	direction_t m_direction;
	string m_name;
	static const long MAX_MSGSIZE = 1 << 20; // 1 MiB
};
