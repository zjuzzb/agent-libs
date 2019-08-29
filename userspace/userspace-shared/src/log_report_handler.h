#pragma once

namespace draiosproto {
class dirty_shutdown_report;
}

/**
 * virtual class that defines the API invoked when a log report is complete.
 * Courtesy default implementations are provided.
 */
class log_report_handler
{
public:
	virtual void handle_log_report(uint64_t ts_ns,
				       const draiosproto::dirty_shutdown_report& report) = 0;
};

class log_report_handler_dummy : public log_report_handler
{
public:
	virtual void handle_log_report(uint64_t ts_ns,
				       const draiosproto::dirty_shutdown_report& report)
	{
	}
};
