#pragma once
#include "object_filter.h"

/**
 * process_manager class exists to manage all long-lived global state which pertains to processes
 */
class process_manager {
public:
	process_manager();

	const object_filter& get_flush_filter() const;

public: // configuration objects
	static object_filter_config::object_filter_config_data c_process_filter;
	static type_config<bool> c_process_flush_filter_enabled;
	static type_config<uint32_t> c_top_processes_per_host;
	static type_config<uint32_t> c_top_processes_per_container;
	static type_config<uint32_t> c_process_limit;
	static type_config<bool> c_always_send_app_checks;

private:
	object_filter m_flush_filter;

	friend class test_helper;
};
