#include "process_manager.h"

object_filter_config::object_filter_config_data process_manager::c_process_filter("definition of process filter to be used during flush",
										  "process"
										  "flush_filter");

type_config<bool> process_manager::c_process_flush_filter_enabled(false,
								  "enable process flush filtering",
								  "process",
								  "flush_filter_enabled");

process_manager::process_manager()
	: m_flush_filter("process flush filter")
{
	m_flush_filter.set_rules(c_process_filter.get());
}
