#include "library_configs.h"
#include "sinsp.h"
#include "scap.h"

// This file exists exclusively to hold configuration objects that are passed to
// third party libraries

type_config<uint32_t> sinsp_library_config::c_thread_purge_interval_s(
    1200,
    "argument to set_thread_purge_interval_s",
    "sinsp",
    "thread_purge_interval_s");
type_config<uint32_t> sinsp_library_config::c_thread_timeout_s(1800,
                                                               "argument to set_thread_timeout_s",
                                                               "sinsp",
                                                               "thread_timeout_s");
type_config<uint64_t> c_config_proc_scan_timeout_ms(
    SCAP_PROC_SCAN_TIMEOUT_NONE,
    "Timeout in msecs for /proc scan",
    "proc_scan_timeout_ms");

type_config<uint64_t> c_config_proc_scan_log_interval_ms(
    SCAP_PROC_SCAN_LOG_NONE,
    "Interval in msecs for logging /proc scan progress",
    "proc_scan_log_interval_ms");

void sinsp_library_config::init_library_configs(sinsp& lib)
{
	lib.set_thread_purge_interval_s(c_thread_purge_interval_s.get_value());
	lib.set_thread_timeout_s(c_thread_timeout_s.get_value());
	lib.set_proc_scan_timeout_ms(c_config_proc_scan_timeout_ms.get_value());
	lib.set_proc_scan_log_interval_ms(c_config_proc_scan_log_interval_ms.get_value());
	sinsp_thread_manager_library_config::init_library_configs(*lib.m_thread_manager);
}

/**
 * When a tid is looked up in the thread table and not found we
 * will explicitly search '/proc' to try to find it.  This value
 * determines the number of times that we will search '/proc'
 * before logging a message.
 */
type_config<int32_t> sinsp_thread_manager_library_config::c_max_n_proc_lookups(
    1,
    "argument to set_m_max_n_proc_lookups",
    "max_n_proc_lookups");

/**
 * When a tid is looked up in the thread table and not found we
 * will explicitly search '/proc' to try to find it (and
 * sometimes that lookup involves reading sockets). This value
 * determines the number of times that we will search '/proc'
 * (involving sockets) before logging a message.
 */
type_config<int32_t> sinsp_thread_manager_library_config::c_max_n_proc_socket_lookups(
    1,
    "argument to set_m_max_n_proc_socket_lookups",
    "max_n_proc_socket_lookups");

type_config<uint32_t> sinsp_thread_manager_library_config::c_max_thread_table_size(
    131072,
    "argument to set_max_thread_table_size",
    "max_thread_table_size");

void sinsp_thread_manager_library_config::init_library_configs(sinsp_thread_manager& lib)
{
	lib.set_max_thread_table_size(c_max_thread_table_size.get_value());
	lib.set_m_max_n_proc_lookups(c_max_n_proc_lookups.get_value());
	lib.set_m_max_n_proc_socket_lookups(c_max_n_proc_socket_lookups.get_value());
}
