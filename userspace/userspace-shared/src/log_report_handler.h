#pragma once

#include <memory>

namespace draiosproto {
class dirty_shutdown_report;
}

struct serialized_buffer;

/**
 * virtual class that defines the API invoked when a log report is complete.
 * Courtesy default implementations are provided.
 */
class log_report_handler
{
public:
	virtual std::shared_ptr<serialized_buffer> handle_log_report(uint64_t ts_ns,
				       const draiosproto::dirty_shutdown_report& report) = 0;
};

class log_report_handler_dummy : public log_report_handler
{
public:
	virtual std::shared_ptr<serialized_buffer> handle_log_report(uint64_t ts_ns,
				       const draiosproto::dirty_shutdown_report& report)
	{
		return nullptr;
	}
};
