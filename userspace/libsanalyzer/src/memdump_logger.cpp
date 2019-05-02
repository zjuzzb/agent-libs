/**
 * @file
 *
 * Implementation of memdump_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "memdump_logger.h"

namespace
{

/**
 * A do-nothing realization of the memdump_logger::callback interface.
 */
class null_callback : public memdump_logger::callback
{
public:
        void log(const std::string& source, const std::string& msg) override
	{ }

        bool is_null() const override { return true; }
};

memdump_logger::callback::ptr_t s_callback = std::make_shared<null_callback>();

} // end namespace


void memdump_logger::log(const std::string& source, const std::string& msg)
{
	s_callback->log(source, msg);
}

void memdump_logger::register_callback(memdump_logger::callback::ptr_t callback)
{
	if(callback)
	{
		s_callback = callback;
	}
	else
	{
		s_callback = std::make_shared<null_callback>();
	}
}

const memdump_logger::callback& memdump_logger::get_callback()
{
	return *s_callback;
}
