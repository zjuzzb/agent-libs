/**
 * @file
 *
 * Interface to dragent_memdump_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include "memdump_logger.h"
#include <string>

namespace dragent
{
class infra_event_sink;
}

/**
 * A memdump_logger callback for dragent.  Instances of this class will
 * push events to the associated infra_event_sink.
 */
class dragent_memdump_logger : public memdump_logger::callback
{
public:
	/**
	 * Initialize this dragent_memdump_logger with the given
	 * infra_event_sink.  The given handler may be nullptr; however,
	 * if it is, then this dragent_memdump_logger will do nothing.
	 */
	dragent_memdump_logger(dragent::infra_event_sink* handler);

	/**
	 * Write the given msg from the given source to the memdump log.
	 */
	void log(const std::string& source, const sinsp_user_event& evt) override;

private:
	/**
	 * A pointer to an existing infra_event_sink.  This object does
	 * not own the memory to which this points and is not responsible for
	 * deleting it.
	 */
	dragent::infra_event_sink* m_event_sink;
};
