#pragma once

#include <exception>

// Shorthand macro to log and throw a fatal exception when executing on a
// watchdog runnable.
#define THROW_DRAGENT_WR_FATAL_ERROR(__fmt, ...)                               \
do {                                                                           \
	std::string c_err_ = s_log_sink.build(__fmt,                           \
					      ##__VA_ARGS__);                  \
	s_log_sink.log(Poco::Message::Priority::PRIO_ERROR,                    \
		       __LINE__,                                               \
		       "Throwing: " + c_err_);                                 \
	throw dragent::watchdog_runnable_fatal_error(c_err_.c_str(),           \
						     s_log_sink.tag());        \
} while(false)

namespace dragent
{

class watchdog_runnable_fatal_error : public std::runtime_error
{
public:
	watchdog_runnable_fatal_error(const std::string &what, const std::string &where) :
		std::runtime_error(what),
		m_where(where)
	{
	}

	const char* where() const
	{
		return m_where.c_str();
	}
private:
	const std::string m_where;
};

}
