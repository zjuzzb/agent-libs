#pragma once
#include "object_filter.h"

/**
 * process_manager class exists to manage all long-lived global state which pertains to processes
 */
class process_manager {
public:
	process_manager();

public: // configuration objects
	static object_filter_config::object_filter_config_data c_process_filter;
	static type_config<bool> c_process_flush_filter_enabled;

private:
	object_filter m_flush_filter;
};
