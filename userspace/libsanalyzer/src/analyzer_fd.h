#pragma once

#include "analyzer_file_stat.h"
#include "analyzer_thread.h"
#include "protostate.h"

#include <sinsp_int.h>

class sinsp_ipv4_connection_manager;

///////////////////////////////////////////////////////////////////////////////
// This class listens on FD activity and performs advanced analysis
///////////////////////////////////////////////////////////////////////////////
class sinsp_analyzer_fd_listener : public sinsp_fd_listener
{
public:
	sinsp_analyzer_fd_listener(sinsp* inspector,
	                           sinsp_analyzer* analyzer,
	                           sinsp_baseliner* falco_baseliner);

	// XXX this functions have way too many parameters. Fix it.
	void on_read(sinsp_evt* evt,
	             int64_t tid,
	             int64_t fd,
	             sinsp_fdinfo_t* fdinfo,
	             char* data,
	             uint32_t original_len,
	             uint32_t len);
	void on_write(sinsp_evt* evt,
	              int64_t tid,
	              int64_t fd,
	              sinsp_fdinfo_t* fdinfo,
	              char* data,
	              uint32_t original_len,
	              uint32_t len);
	void on_rw_error(sinsp_evt* evt, int64_t fd, sinsp_fdinfo_t* fdinfo);
	void on_sendfile(sinsp_evt* evt, int64_t fdin, uint32_t len);
	void on_connect(sinsp_evt* evt, uint8_t* packed_data);
	void on_accept(sinsp_evt* evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo);
	void on_file_open(sinsp_evt* evt, const std::string& fullpath, uint32_t flags);
	void on_error(sinsp_evt* evt);
	void on_erase_fd(erase_fd_params* params);
	void on_socket_shutdown(sinsp_evt* evt);
	void on_execve(sinsp_evt* evt);
	void on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo);
	void on_bind(sinsp_evt* evt);
	bool on_resolve_container(sinsp_container_manager* manager,
	                          sinsp_threadinfo* tinfo,
	                          bool query_os_for_missing_info);
	void on_socket_status_changed(sinsp_evt* evt);
	bool patch_network_role(THREAD_TYPE* ptinfo, sinsp_fdinfo_t* pfdinfo, bool incoming);
	void set_ipv4_connection_manager(sinsp_ipv4_connection_manager* ipv4_connection_manager);

	using on_file_open_cb = std::function<
	    void(THREAD_TYPE* tinfo, uint64_t ts, const std::string& fullpath, uint32_t flags)>;
	// Register a callback for every file opened for writing
	void subscribe_on_file_open_write(on_file_open_cb callback)
	{
		m_on_file_open_write_cb.emplace_back(callback);
	}

	analyzer_top_file_stat_map m_files_stat;
	analyzer_top_device_stat_map m_devs_stat;

private:
	inline bool should_report_network(sinsp_fdinfo_t* fdinfo);
	inline bool should_account_io(const THREAD_TYPE* tinfo);
	void flush_transaction(erase_fd_params* params);
	sinsp_connection* get_ipv4_connection(sinsp_fdinfo_t* fdinfo,
	                                      const ipv4tuple& tuple,
	                                      sinsp_evt* evt,
	                                      int64_t tid,
	                                      int64_t fd,
	                                      bool incoming);
	void add_client_ipv4_connection(sinsp_evt* evt);

	void account_io(THREAD_TYPE* tinfo,
	                const std::string& name,
	                uint32_t dev,
	                uint32_t bytes,
	                uint64_t time_ns,
	                analyzer_file_stat::io_direction direction);
	void account_file_open(THREAD_TYPE* tinfo, const std::string& name, uint32_t dev);
	void account_error(THREAD_TYPE* tinfo, const std::string& name, uint32_t dev);

#ifndef _WIN32
	void handle_statsd_write(sinsp_evt* evt,
	                         sinsp_fdinfo_t* fdinfo,
	                         const char* data,
	                         uint32_t len) const;
#endif

	void update_transaction(sinsp_evt* evt,
	                        int64_t fd,
	                        sinsp_fdinfo_t* fdinfo,
	                        char* data,
	                        uint32_t original_len,
	                        uint32_t len,
	                        sinsp_connection* connection,
	                        sinsp_partial_transaction::direction trdir);

	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_baseliner* m_falco_baseliner;
	sinsp_proto_detector m_proto_detector;
	sinsp_configuration* m_sinsp_config;
	sinsp_ipv4_connection_manager* m_ipv4_connections;
	std::list<on_file_open_cb> m_on_file_open_write_cb;
};
