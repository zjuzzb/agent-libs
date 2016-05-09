//
// Created by Luca Marturana on 30/06/15.
//

#include "posix_queue.h"
#include <sinsp_int.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <limits.h>

posix_queue::posix_queue(string name, direction_t dir, long maxmsgs):
	m_direction(dir),
	m_name(move(name))
{
	ASSERT(name.size() <= NAME_MAX);
	if(!set_queue_limits())
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "Error: Cannot increase posix queue limits");
	}
	int flags = dir | O_CREAT;
	struct mq_attr queue_attrs = {0};
	if(m_direction == SEND)
	{
		// We need non_blocking mode only for send
		// on receive we use a timeout
		flags |= O_NONBLOCK;
		queue_attrs.mq_flags = O_NONBLOCK;
	}
	queue_attrs.mq_maxmsg = maxmsgs;
	queue_attrs.mq_msgsize = MAX_MSGSIZE;
	queue_attrs.mq_curmsgs = 0;
	m_queue_d = mq_open(m_name.c_str(), flags, S_IRWXU, &queue_attrs);
	if(m_queue_d < 0)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "Error: Cannot create queue %s, errno: %s", m_name.c_str(), strerror(errno));
	}
}

posix_queue::~posix_queue()
{
	if(m_queue_d > 0)
	{
		mq_close(m_queue_d);
	}
}

bool posix_queue::send(const string &msg)
{
	if(m_queue_d)
	{
		auto res = mq_send(m_queue_d, msg.c_str(), msg.size(), 0);
		if(res == 0)
		{
			return true;
		}
		else
		{
			switch(errno)
			{
			case EAGAIN:
				g_logger.format(sinsp_logger::SEV_DEBUG, "Debug: Cannot send on queue %s, is full", m_name.c_str());
				break;
			case EMSGSIZE:
				g_logger.format(sinsp_logger::SEV_WARNING, "Warning: Cannot send on queue %s, msg too big", m_name.c_str());
				break;
			default:
				g_logger.format(sinsp_logger::SEV_WARNING, "Warning: Cannot send on queue %s, errno: %s", m_name.c_str(), strerror(errno));
				break;
			}
			return false;
		}
	}

	g_logger.log("Error: posix_queue[" + m_name + "]: cannot send (no queue)", sinsp_logger::SEV_ERROR);
	return false;
}

string posix_queue::receive(uint64_t timeout_s)
{
	if(m_queue_d)
	{
		char msgbuffer[MAX_MSGSIZE] = {};
		struct timespec ts = {0};
		uint64_t now = sinsp_utils::get_current_time_ns();
		ts.tv_sec = now / ONE_SECOND_IN_NS + timeout_s;
		unsigned int prio = 0;
		auto res = mq_timedreceive(m_queue_d, msgbuffer, MAX_MSGSIZE, &prio, &ts);
		if(res > 0)
		{
			return string(msgbuffer, res);
		}
	}

	g_logger.log("Error: posix_queue[" + m_name + "]: cannot receive (no queue)", sinsp_logger::SEV_ERROR);
	return "";

}

bool posix_queue::limits_set = false;

bool posix_queue::set_queue_limits()
{
	if(!limits_set)
	{
		struct rlimit r;
		r.rlim_cur = MAX_QUEUES * (MAX_MSGS+2) * MAX_MSGSIZE;
		r.rlim_max = MAX_QUEUES * (MAX_MSGS+2) * MAX_MSGSIZE;

		int res = setrlimit(RLIMIT_MSGQUEUE, &r);
		if(res != 0)
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "Error: Cannot set queue limits, errno: %s", strerror(errno));
		}
		limits_set = (res == 0);
	}
	return limits_set;
}

bool posix_queue::remove(const string &name)
{
	return mq_unlink(name.c_str()) == 0;
}