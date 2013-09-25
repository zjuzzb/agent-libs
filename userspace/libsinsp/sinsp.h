////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#pragma once
#ifdef _WIN32
#pragma warning(disable: 4251)
#endif

#ifdef _WIN32
#define SINSP_PUBLIC __declspec(dllexport)
#include <Ws2tcpip.h>
#else
#define SINSP_PUBLIC
#include <arpa/inet.h>
#endif

#define __STDC_FORMAT_MACROS

#include <string>
#include <unordered_map>
#include <map>
#include <queue>
#include <vector>

using namespace std;

#include <scap.h>
#include "settings.h"
#include "logger.h"
#include "event.h"
#include "stats.h"
#include "config.h"

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

#define ONE_SECOND_IN_NS 1000000000LL

//
// An IPv4 tuple
//
typedef union _ipv4tuple
{
	struct 
	{
		uint32_t m_sip;
		uint32_t m_dip;
		uint16_t m_sport;
		uint16_t m_dport;
		uint8_t m_l4proto;
	}m_fields;
	uint8_t m_all[13];
}ipv4tuple;

typedef union _ipv6tuple
{
	struct
	{
		uint32_t m_sip[4];
		uint32_t m_dip[4];
		uint16_t m_sport;
		uint16_t m_dport;
		uint8_t m_l6proto;
	} m_fields;
} ipv6tuple;

//
// A Unix tuple
//
typedef union _unix_tuple
{
	struct
	{
		uint64_t m_source;
		uint64_t m_dest;
	} m_fields;
	uint8_t m_all[16];
} unix_tuple;

#include "transactinfo.h"
#include "fdinfo.h"
#include "metrics.h"
#include "threadinfo.h"
#include "ifinfo.h"

template<typename OBJ> class simple_lifo_queue;
class sinsp_partial_transaction;
class sinsp_fdinfo;
class sinsp_parser;
class sinsp_analyzer;
class sinsp_filter;

//
// Exception class
//
struct sinsp_exception : std::exception
{
	sinsp_exception()
	{
	}

	~sinsp_exception() throw() 
	{
	}

	sinsp_exception(string error_str)
	{
		m_error_str = error_str;
	}

	char const* what() const throw()
	{ 
		return m_error_str.c_str();
	}

	string m_error_str;
};

#ifdef HAS_ANALYZER
//
// Prototype of the callback invoked by the analyzer when a sample is ready
//
class analyzer_callback_interface
{
public:
	virtual void sinsp_analyzer_data_ready(uint64_t ts_ns, char* buffer) = 0;
};

typedef void (*sinsp_analyzer_callback)(char* buffer, uint32_t buflen);
#endif

//
// The root system inspection class
//
class SINSP_PUBLIC sinsp
{
public:
	typedef class sinsp_ipv4_connection_manager sinsp_ipv4_connection_manager;
	typedef class sinsp_unix_connection_manager sinsp_unix_connection_manager;
	typedef class sinsp_pipe_connection_manager sinsp_pipe_connection_manager;
	typedef class sinsp_connection sinsp_connection;

	
	sinsp();
	~sinsp();
	//
	// Start a live capture
	//
	void open(uint32_t timeout_ms = SCAP_TIMEOUT_MS);

	//
	// Open a capture file
	//
	void open(string filename);

	//
	// Close capture file and release all
	// resources
	//
	void close();

	//
	// Get the next event
	//
	int32_t next(OUT sinsp_evt** evt);

	//
	// Get the number of captured events
	//
	uint64_t get_num_events();

	//
	// Get the transaction list
	//
	sinsp_transaction_table* get_transactions();

	//
	// Stop event capture
	//
	void stop_capture();

	//
	// Start event capture
	//
	void start_capture();

#ifdef _DEBUG
	//
	// Set the capture filter. Only in debug mode for the moment.
	//
	void set_filter(string filter);
#endif

	//
	// Set the callback that receives the analyzer output
	//
	void set_analyzer_callback(analyzer_callback_interface* cb);

	//
	// Get processing stats
	//
#ifdef GATHER_INTERNAL_STATS
	sinsp_stats get_stats();
#endif

	//
	// Get the last error
	//
	string getlasterr()
	{
		return m_lasterr;
	}

	//
	// Set the target for the log strings
	//
	void set_log_callback(sinsp_logger_callback cb);

	//
	// Start dumping events to a capture file
	//
	void start_dump(string dump_filename);

	sinsp_configuration* get_configuration();
	void set_configuration(const sinsp_configuration& configuration);

	bool has_metrics();

	const scap_machine_info* get_machine_info();

VISIBILITY_PRIVATE

	void init();
	void import_proc_table();
	void import_ifaddr_list();

	sinsp_threadinfo* get_thread(int64_t tid, bool query_os_if_not_found);
	void add_thread(const sinsp_threadinfo& procinfo);
	void remove_thread(int64_t tid);

	//
	// Push an fd operation into the fifo queue for a thread
	//
	void push_fdop(int64_t tid, sinsp_fdinfo* fdinfo, sinsp_fdop& op);

	sinsp_connection* get_connection(const ipv4tuple& tuple, uint64_t timestamp);
	sinsp_connection* get_connection(const unix_tuple& tuple, uint64_t timestamp);
	sinsp_connection* get_connection(const uint64_t ino, uint64_t timestamp);
	void remove_expired_connections(uint64_t ts);

	scap_t* m_h;
	sinsp_evt m_evt;
	string m_lasterr;
	int64_t m_tid_to_remove;
	vector<int64_t>* m_fds_to_remove;
	int64_t m_tid_of_fd_to_remove;
	uint64_t m_lastevent_ts;
	// the parsing engine
	sinsp_parser* m_parser;
	// the statistics analysis engine
	sinsp_analyzer* m_analyzer;
	sinsp_transaction_table* m_trans_table;
	sinsp_ipv4_connection_manager* m_ipv4_connections;
	sinsp_unix_connection_manager* m_unix_connections;
	sinsp_pipe_connection_manager* m_pipe_connections;
	scap_dumper_t* m_dumper;
	const scap_machine_info* m_machine_info;
	uint32_t m_num_cpus;

	sinsp_network_interfaces* m_network_interfaces;

	// Used by the analyzer
	vector<pair<uint64_t,pair<uint64_t, uint16_t>>> m_transactions_with_cpu;

#ifdef GATHER_INTERNAL_STATS
	sinsp_stats m_stats;
#endif

	sinsp_thread_manager* m_thread_manager;
	sinsp_configuration m_configuration;
	analyzer_callback_interface* m_analyzer_callback;
#ifdef HAS_FILTERING
	sinsp_filter* m_filter;
#endif

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_evt;
	friend class sinsp_threadinfo;
	friend class sinsp_transaction_manager;
	friend class sinsp_transactemitter_unbuffered;
	friend class sinsp_transaction_table;
	friend class sinsp_partial_transaction;
	friend class sinsp_fdtable;
	friend class sinsp_thread_manager;
	template<class TKey,class THash,class TCompare> friend class sinsp_connection_manager;
};
