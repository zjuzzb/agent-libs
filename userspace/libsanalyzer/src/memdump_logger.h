/**
 * @file
 *
 * Interface to memdump_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <memory>
#include <string>

namespace memdump_logger
{

/**
 * Interface to a callback handler for dealing with memdump logs.
 */
class callback
{
public:
	using ptr_t = std::shared_ptr<callback>;

	virtual ~callback() = default;

	virtual void log(const std::string& source, const std::string& msg) = 0;
	virtual bool is_null() const { return false; }
};

/**
 * Write the given msg from the given source to memdump.
 */
void log(const std::string& source, const std::string& msg);

/**
 * Register the given callback.  If a callback is already registered, it will
 * be replaced with the given callback.  The given callback may be nullptr,
 * in which case the registered callback will be replaced with a null
 * callback handler.
 */
void register_callback(memdump_logger::callback::ptr_t callback);

/**
 * Returns a reference to the current callback handler.  Use the is_null()
 * method on the returned object to determine if the handler is expected to
 * perform useful logging.
 */
const memdump_logger::callback& get_callback();

} // end namespace memdump_logger
