#pragma once
#include "type_config.h"

//
// The classes that exist in this file are solely for mapping our config infrastructure
// onto external libraries. If it is not taking a config that exists only for that library
// and calling the api to set it, then it probably doesn't belong here. Any other setup or
// initialization should be done by the client of the library. This infrastructure is
// necessary since our configs are global, and thus we need a global infrastructure
// to map those configs onto the other libraries
//
// External libraries here MAY initialize the configs of other libraries on which
// they depend: e.g. sinsp_library on sinsp_thread_manager_library.
//
// If a library has a dedicated global owner (such as infrastructure_state owning cointerface),
// that owner should also own the configs. In reality the use cases here might be limited
//
class sinsp;
class sinsp_thread_manager;

class sinsp_library_config
{
public:
	static void init_library_configs(sinsp& lib);

private:
	static type_config<uint32_t> c_thread_purge_interval_s;
	static type_config<uint32_t> c_thread_timeout_s;
};

class sinsp_thread_manager_library_config
{
public:
	static void init_library_configs(sinsp_thread_manager& lib);

private:
	static type_config<int32_t> c_max_n_proc_lookups;
	static type_config<int32_t> c_max_n_proc_socket_lookups;
	static type_config<uint32_t> c_max_thread_table_size;
};
