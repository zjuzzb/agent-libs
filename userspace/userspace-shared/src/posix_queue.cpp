#include "posix_queue.h"
#include "common_logger.h"
#include "wall_time.h"
#include <sys/stat.h>
#include <sys/resource.h>
#include <limits.h>
#include <string.h>
#include <stdexcept>

COMMON_LOGGER();

posix_queue::posix_queue(std::string name, direction_t dir, long maxmsgs):
	m_direction(dir),
	m_name(std::move(name)),
	m_buf()
{
	ASSERT(name.size() <= NAME_MAX);
	int flags = dir | O_CREAT;
	struct mq_attr queue_attrs = {0};
	if(m_direction == SEND)
	{
		// We need non_blocking mode only for send
		// on receive we use a timeout
		flags |= O_NONBLOCK;
		queue_attrs.mq_flags = O_NONBLOCK;
	}
	else
	{
		m_buf.resize(MAX_MSGSIZE);
	}
	queue_attrs.mq_maxmsg = maxmsgs;
	queue_attrs.mq_msgsize = MAX_MSGSIZE;
	queue_attrs.mq_curmsgs = 0;
	m_queue_d = mq_open(m_name.c_str(), flags, S_IRWXU, &queue_attrs);
	if(m_queue_d < 0)
	{
		LOG_ERROR("Cannot create queue %s, errno: %s", m_name.c_str(), strerror(errno));
	}
}

posix_queue::~posix_queue()
{
	if(m_queue_d > 0)
	{
		mq_close(m_queue_d);
	}
}

bool posix_queue::send(const std::string &msg)
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
				LOG_DEBUG("Cannot send on queue %s, is full", m_name.c_str());
				break;
			case EMSGSIZE:
				LOG_WARNING("Cannot send on queue %s, msg too big size=%zu", m_name.c_str(), msg.size());
				break;
			default:
				LOG_WARNING("Cannot send on queue %s, errno: %s", m_name.c_str(), strerror(errno));
				break;
			}
			return false;
		}
	}

	LOG_ERROR("[" + m_name + "]: cannot send (no queue)");
	return false;
}

std::vector<char> posix_queue::receive(uint64_t timeout_s)
{
	if(!m_queue_d)
	{
		LOG_ERROR("[" + m_name + "]: cannot receive (no queue)");
		return std::vector<char>();
	}

	struct timespec ts = {0};
	ts.tv_sec = wall_time::seconds() + timeout_s;
	unsigned int prio = 0;

	auto res = mq_timedreceive(m_queue_d, &m_buf[0], MAX_MSGSIZE, &prio, &ts);

	if(res >= 0)
	{
		return std::vector<char>(m_buf.begin(), m_buf.begin() + res);
	} else if (errno == ETIMEDOUT || errno == EINTR) {
		return std::vector<char>();
	} else {
		LOG_ERROR("Unexpected error on posix queue receive: %s", strerror(errno));
		if(timeout_s > 0)
		{
			// At this point the application may go to infinite loop if it relies
			// on the timeout provided, eg:
			// while(true)
			// {
			//   auto msg = receive(1)
			//   do stuff...
			// }
			// in this case is better to crash
			// otherwise if timeout=0 like our dragent. let's keep it running
			// as posix queue healthness is not vital
			throw std::runtime_error("Unexpected error on posix queue receive");
		}
		return std::vector<char>();
	}
}

bool posix_queue::remove(const std::string &name)
{
	return mq_unlink(name.c_str()) == 0;
}
