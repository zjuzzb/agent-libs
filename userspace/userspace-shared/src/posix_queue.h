#pragma once

#ifndef _WIN32
#include <string>
#include <vector>
#include <mqueue.h>
#include <fcntl.h>

#include "noncopyable.h"

/**
 * A queue to pass string between processes. 
 *  
 *  Expected usage is for two components to have two queues each
 *  where one goes from A->B and the other from B->A.
 *  
 */
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

	/**
	 * Send a string from a SEND queue
	 */
	bool send(const std::string& msg);

	/**
	 * Receive arbitrary data from a RECEIVE queue
	 */
	std::vector<char> receive(uint64_t timeout_s=0);

	/**
	 * Remove the queue from the underlying OS
	 */
	static bool remove(const std::string& name);
private:
	mqd_t m_queue_d;
	direction_t m_direction;
	std::string m_name;
	std::vector<char> m_buf;
	static const long MAX_MSGSIZE = 3 << 20; // 3 MiB
	static const long MAX_QUEUES = 10;
	static const long MAX_MSGS = 3;
};
#endif // _WIN32