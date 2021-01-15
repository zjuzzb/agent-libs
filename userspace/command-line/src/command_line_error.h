#pragma once
#include <exception>

#define THROW_CLI_ERROR(__fmt, ...)                                            \
do {                                                                           \
        std::string c_err_ = s_log_sink.build(__fmt,                           \
                                              ##__VA_ARGS__);                  \
        s_log_sink.log(Poco::Message::Priority::PRIO_ERROR,                    \
                       __LINE__,                                               \
                       "Throwing: " + c_err_);                                 \
        throw command_line_error(c_err_.c_str());                              \
} while(false)

/**
 * Error that is caught by the command_line_manager. Any handler 
 * can throw this to return an error back to the client.
 */  
class command_line_error : public std::runtime_error
{
public:
	command_line_error(const std::string &what) : std::runtime_error(what)
	{
	}
};

