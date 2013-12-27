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
#include <set>

using namespace std;

#include <scap.h>
#include "settings.h"
#include "logger.h"
#include "event.h"
#include "stats.h"
#include "config.h"
#include "ifinfo.h"

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
		uint8_t m_l4proto;
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
#include "eventformatter.h"

template<typename OBJ> class simple_lifo_queue;
class sinsp_partial_transaction;
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

//
// Filter check information
//
class filter_check_info
{
public:
	string m_name;
	int32_t m_nfiedls;
	const filtercheck_field_info* m_fields;
};

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
	// Stop event capture
	//
	void set_snaplen(uint32_t snaplen);

	//
	// Stop event capture
	//
	void stop_capture();

	//
	// Start event capture
	//
	void start_capture();
	
	//
	// Drop mode control
	//
	void stop_dropping_mode();
	void start_dropping_mode();
	
#ifdef HAS_FILTERING
	//
	// Set the capture filter. Only in debug mode for the moment.
	//
	void set_filter(string filter);
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

	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);

	//
	// Start dumping events to a capture file
	//
	void start_dump(const string& dump_filename);
	void stop_dump();

	//
	// Populate the given vector with the full list of filter check fields
	//
	static void get_filtercheck_fields_info(vector<const filter_check_info*>* list);

	//
	// Get and set the library configuration settings
	//
	sinsp_configuration* get_configuration();
	void set_configuration(const sinsp_configuration& configuration);

	bool has_metrics();

	//
	// Get information about the physical machine generating the events
	//
	const scap_machine_info* get_machine_info();

	//
	// Return a thread's information given its tid
	//
	sinsp_threadinfo* get_thread(int64_t tid, bool query_os_if_not_found);
	sinsp_threadinfo* get_thread(int64_t tid);

	const unordered_map<uint32_t, scap_userinfo*>* get_userlist();
	const unordered_map<uint32_t, scap_groupinfo*>* get_grouplist();

	//
	// Allocates private state in the thread info class.
	// Returns the ID to use when retrieving the memory area.
	// Will fail if called after the capture starts.
	//
	uint32_t reserve_thread_memory(uint32_t size);

#ifdef GATHER_INTERNAL_STATS
	sinsp_stats get_stats();
#endif

#ifdef HAS_ANALYZER
	sinsp_analyzer* m_analyzer;
#endif

VISIBILITY_PRIVATE

	void init();
	void import_thread_table();
	void import_ifaddr_list();
	void import_user_list();

	void add_thread(const sinsp_threadinfo& ptinfo);
	void remove_thread(int64_t tid);

	scap_t* m_h;
	bool m_islive;
	sinsp_evt m_evt;
	string m_lasterr;
	int64_t m_tid_to_remove;
	int64_t m_tid_of_fd_to_remove;
	vector<int64_t>* m_fds_to_remove;
	uint64_t m_lastevent_ts;
	// the parsing engine
	sinsp_parser* m_parser;
	// the statistics analysis engine
	scap_dumper_t* m_dumper;
	const scap_machine_info* m_machine_info;
	uint32_t m_num_cpus;
	sinsp_thread_privatestate_manager m_thread_privatestate_manager;

	sinsp_network_interfaces* m_network_interfaces;

	sinsp_thread_manager* m_thread_manager;
	sinsp_configuration m_configuration;

#ifdef HAS_FILTERING
	uint64_t m_firstevent_ts;
	sinsp_filter* m_filter;
#endif

	//
	// Internal stats
	//
#ifdef GATHER_INTERNAL_STATS
	sinsp_stats m_stats;
#endif

	unordered_map<uint32_t, scap_userinfo*> m_userlist;
	unordered_map<uint32_t, scap_groupinfo*> m_grouplist;

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_sched_analyzer;
	friend class sinsp_sched_analyzer2;
	friend class sinsp_scores;
	friend class sinsp_evt;
	friend class sinsp_threadinfo;
	friend class sinsp_transaction_manager;
	friend class sinsp_transactemitter_unbuffered;
	friend class sinsp_transaction_table;
	friend class sinsp_partial_transaction;
	friend class sinsp_fdtable;
	friend class sinsp_thread_manager;
	friend class sinsp_delays;

	template<class TKey,class THash,class TCompare> friend class sinsp_connection_manager;
};
