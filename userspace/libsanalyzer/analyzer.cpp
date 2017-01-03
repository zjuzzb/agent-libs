#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <process.h>
#include <time.h>
#define getpid _getpid
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <endian.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif // _WIN32
#include <google/protobuf/io/coded_stream.h>
#ifndef _WIN32
#include <google/protobuf/io/gzip_stream.h>
#endif
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using namespace google::protobuf::io;

#include "Poco/File.h"

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#ifdef HAS_ANALYZER
#include "json_query.h"
#include "parsers.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"
#include "metrics.h"
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "analyzer_thread.h"
#include "analyzer_fd.h"
#include "analyzer_parsers.h"
#include "chisel.h"
#include "docker.h"
#include "k8s.h"
#include "k8s_delegator.h"
#include "k8s_state.h"
#include "k8s_proto.h"
#include "mesos.h"
#include "mesos_state.h"
#include "mesos_proto.h"
#include "baseliner.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "uri.h"
#include "third-party/jsoncpp/json/json.h"
#define DUMP_TO_DISK
#include <memory>
#include <iostream>
#include <numeric>
#include "falco_engine.h"
#include "falco_events.h"
#include "proc_config.h"

bool sinsp_analyzer::m_mesos_bad_config = false;

sinsp_analyzer::sinsp_analyzer(sinsp* inspector)
{
	m_initialized = false;
	m_inspector = inspector;
	m_n_flushes = 0;
	m_prev_flushes_duration_ns = 0;
	m_prev_flush_cpu_pct = 0.0;
	m_next_flush_time_ns = 0;
	m_prev_flush_time_ns = 0;
	m_last_proclist_refresh = 0;
	m_metrics = new draiosproto::metrics;
	m_serialization_buffer = (char*)malloc(MIN_SERIALIZATION_BUF_SIZE_BYTES);
	if(!m_serialization_buffer)
	{
		char tbuf[256];
		snprintf(tbuf, sizeof(tbuf), "memory allocation error at %s:%d", __FILE__, __LINE__);
		throw sinsp_exception(string(tbuf));
	}
	m_serialization_buffer_size = MIN_SERIALIZATION_BUF_SIZE_BYTES;
	m_sample_callback = NULL;
	m_protobuf_fp = NULL;
	m_prev_sample_evtnum = 0;
	m_serialize_prev_sample_evtnum = 0;
	m_serialize_prev_sample_time = 0;
	m_client_tr_time_by_servers = 0;
	m_total_process_cpu = 0;

	m_reduced_ipv4_connections = new unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp>();
	m_procfs_parser = NULL;
	m_sched_analyzer2 = NULL;
	m_score_calculator = NULL;
	m_delay_calculator = NULL;

	m_ipv4_connections = NULL;
#ifdef HAS_UNIX_CONNECTIONS
	m_unix_connections = NULL;
#endif
#ifdef HAS_PIPE_CONNECTIONS
	m_pipe_connections = NULL;
#endif
	m_trans_table = NULL;
	m_is_sampling = false;
	m_driver_stopped_dropping = false;
	m_sampling_ratio = 1;
	m_new_sampling_ratio = m_sampling_ratio;
	m_last_dropmode_switch_time = 0;
	m_seconds_above_thresholds = 0;
	m_seconds_below_thresholds = 0;
	m_my_cpuload = -1;
	m_last_system_cpuload = 0;
	m_skip_proc_parsing = false;
	m_prev_flush_wall_time = 0;
	m_die = false;
	m_run_chisels = false;

	m_falco_engine = NULL;
	m_falco_events = NULL;

	inspector->m_max_n_proc_lookups = 5;
	inspector->m_max_n_proc_socket_lookups = 3;

	m_configuration = new sinsp_configuration();

	m_parser = new sinsp_analyzer_parsers(this);

	m_falco_baseliner = new sisnp_baseliner();

	//
	// Listeners
	//
	m_thread_memory_id = inspector->reserve_thread_memory(sizeof(thread_analyzer_info));

	m_threadtable_listener = new analyzer_threadtable_listener(inspector, this);
	inspector->m_thread_manager->set_listener((sinsp_threadtable_listener*)m_threadtable_listener);

	m_fd_listener = new sinsp_analyzer_fd_listener(inspector, this);
	inspector->m_parser->m_fd_listener = m_fd_listener;
#ifndef _WIN32
	m_jmx_sampling = 1;
#endif

	m_protocols_enabled = true;
	m_remotefs_enabled = false;
	m_containers_limit = CONTAINERS_HARD_LIMIT;

	//
	// Docker
	//
	m_has_docker = Poco::File(docker::get_socket_file()).exists();

	//
	// Chisels init
	//
	add_chisel_dirs();

	m_dcos_enterprise_last_token_refresh_s = 0;
	m_mesos_last_failure_ns = 0;
}

sinsp_analyzer::~sinsp_analyzer()
{
	delete m_metrics;
	free(m_serialization_buffer);
	delete m_score_calculator;
	delete m_procfs_parser;
	delete m_sched_analyzer2;
	delete m_delay_calculator;
	delete m_threadtable_listener;
	delete m_fd_listener;
	delete m_reduced_ipv4_connections;
	delete m_ipv4_connections;

#ifdef HAS_UNIX_CONNECTIONS
	delete m_unix_connections;
#endif

#ifdef HAS_PIPE_CONNECTIONS
	delete m_pipe_connections;
#endif

	delete m_trans_table;
	delete m_configuration;
	delete m_parser;

	if(m_protobuf_fp != NULL)
	{
		fclose(m_protobuf_fp);
	}

	for(vector<sinsp_chisel*>::iterator it = m_chisels.begin();
	it != m_chisels.end(); ++it)
	{
		delete *it;
	}
	m_chisels.clear();

	if(m_falco_baseliner != NULL)
	{
		delete m_falco_baseliner;
	}

	google::protobuf::ShutdownProtobufLibrary();
}

void sinsp_analyzer::on_capture_start()
{
	m_initialized = true;

	if(m_procfs_parser != NULL)
	{
		throw sinsp_exception("analyzer can be opened only once");
	}

	//
	// Start dropping of non-critical events
	//
	if(m_configuration->get_autodrop_enabled())
	{
		start_dropping_mode(1);
		m_is_sampling = true;
	}
	else
	{
		m_is_sampling = false;
	}

	//
	// Enable dynamic snaplen on live captures
	//
	if(m_inspector->is_live())
	{
		if(scap_enable_dynamic_snaplen(m_inspector->m_h) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
		}
	}

	//
	// Hardware-dependent inits
	//
	m_machine_info = m_inspector->get_machine_info();
	if(m_machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("machine info missing, analyzer can't start");
	}

	m_procfs_parser = new sinsp_procfs_parser(m_machine_info->num_cpus, m_machine_info->memory_size_bytes / 1024, !m_inspector->is_offline());
	m_procfs_parser->get_global_cpu_load(&m_old_global_total_jiffies);

	m_sched_analyzer2 = new sinsp_sched_analyzer2(m_inspector, m_machine_info->num_cpus);
	m_score_calculator = new sinsp_scores(m_inspector, m_sched_analyzer2);
	m_delay_calculator = new sinsp_delays(m_machine_info->num_cpus);

	//
	// Allocations
	//
	ASSERT(m_ipv4_connections == NULL);
	m_ipv4_connections = new sinsp_ipv4_connection_manager(m_inspector);
#ifdef HAS_UNIX_CONNECTIONS
	m_unix_connections = new sinsp_unix_connection_manager(m_inspector);
#endif
#ifdef HAS_PIPE_CONNECTIONS
	m_pipe_connections = new sinsp_pipe_connection_manager(m_inspector);
#endif
	m_trans_table = new sinsp_transaction_table(m_inspector);

	//
	// Notify the scheduler analyzer
	//
	ASSERT(m_sched_analyzer2 != NULL);
	m_sched_analyzer2->on_capture_start();
	m_parser->on_capture_start();

	//
	// Call the chisels on_capture_start callback
	//
	chisels_on_capture_start();

	//
	// Start the falco baseliner
	//
	m_do_baseline_calculation = m_configuration->get_falco_baselining_enabled();
	m_falco_baseliner->init(m_inspector);
}

void sinsp_analyzer::set_sample_callback(analyzer_callback_interface* cb)
{
	ASSERT(cb != NULL);
	ASSERT(m_sample_callback == NULL);
	m_sample_callback = cb;
}

void sinsp_analyzer::add_chisel_dirs()
{
	m_inspector->add_chisel_dir("/opt/draios/share/chisels", false);

	//
	// sysdig that comes with dragent is always installed in /usr
	//
	m_inspector->add_chisel_dir("/usr" CHISELS_INSTALLATION_DIR, false);

	//
	// Add the directories configured in the SYSDIG_CHISEL_DIR environment variable
	//
	char* s_user_cdirs = getenv("SYSDIG_CHISEL_DIR");

	if(s_user_cdirs != NULL)
	{
		vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

		for(uint32_t j = 0; j < user_cdirs.size(); j++)
		{
			m_inspector->add_chisel_dir(user_cdirs[j], true);
		}
	}
}

void sinsp_analyzer::initialize_chisels()
{
	for(auto it = m_chisels.begin(); it != m_chisels.end();)
	{
		try
		{
			(*it)->on_init();
			++it;
		}
		catch(sinsp_exception e)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": " + e.what(),
				sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
		catch(...)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": unknown error",
				sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
	}
}

void sinsp_analyzer::add_chisel(sinsp_chisel* ch)
{
	m_chisels.push_back(ch);
	m_run_chisels = true;
}

void sinsp_analyzer::add_chisel(sinsp_chisel_details* cd)
{
	try
	{
		sinsp_chisel* ch = new sinsp_chisel(m_inspector, cd->m_name);
		ch->set_args(cd->m_args);
		add_chisel(ch);
	}
	catch(sinsp_exception e)
	{
		g_logger.log("unable to start chisel " + cd->m_name + ": " + e.what(),
			sinsp_logger::SEV_WARNING);
	}
	catch(...)
	{
		g_logger.log("unable to start chisel " + cd->m_name + ": unknown error",
			sinsp_logger::SEV_WARNING);
	}
}

void sinsp_analyzer::chisels_on_capture_start()
{
	for(auto it = m_chisels.begin(); it != m_chisels.end();)
	{
		try
		{
			(*it)->on_capture_start();
			++it;
		}
		catch(sinsp_exception e)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": " + e.what(),
				sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
		}
		catch(...)
		{
			g_logger.log("unable to start chisel " + (*it)->get_name() + ": unknown error",
				sinsp_logger::SEV_WARNING);

			delete (*it);
			m_chisels.erase(it);
			}
	}
}

void sinsp_analyzer::chisels_on_capture_end()
{
	for(vector<sinsp_chisel*>::iterator it = m_chisels.begin();
	it != m_chisels.end(); ++it)
	{
		(*it)->on_capture_end();
	}
}

void sinsp_analyzer::chisels_do_timeout(sinsp_evt* ev)
{
	for(vector<sinsp_chisel*>::iterator it = m_chisels.begin();
	it != m_chisels.end(); ++it)
	{
		(*it)->do_timeout(ev);
	}
}

sinsp_configuration* sinsp_analyzer::get_configuration()
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if(m_inspector->m_h != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("Attempting to set the configuration while the inspector is capturing");
	}

	return m_configuration;
}

void sinsp_analyzer::set_configuration(const sinsp_configuration& configuration)
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if(m_inspector->m_h != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("Attempting to set the configuration while the inspector is capturing");
	}

	*m_configuration = configuration;
}

void sinsp_analyzer::remove_expired_connections(uint64_t ts)
{
	m_ipv4_connections->remove_expired_connections(ts);
#ifdef HAS_UNIX_CONNECTIONS
	m_unix_connections->remove_expired_connections(ts);
#endif
#ifdef HAS_PIPE_CONNECTIONS
	m_pipe_connections->remove_expired_connections(ts);
#endif
}

sinsp_connection* sinsp_analyzer::get_connection(const ipv4tuple& tuple, uint64_t timestamp)
{
	sinsp_connection* connection = m_ipv4_connections->get_connection(tuple, timestamp);
	if(NULL == connection)
	{
		// try to find the connection with source/destination reversed
		ipv4tuple tuple_reversed;
		tuple_reversed.m_fields.m_sip = tuple.m_fields.m_dip;
		tuple_reversed.m_fields.m_dip = tuple.m_fields.m_sip;
		tuple_reversed.m_fields.m_sport = tuple.m_fields.m_dport;
		tuple_reversed.m_fields.m_dport = tuple.m_fields.m_sport;
		tuple_reversed.m_fields.m_l4proto = tuple.m_fields.m_l4proto;
		connection = m_ipv4_connections->get_connection(tuple_reversed, timestamp);
		if(NULL != connection)
		{
			((ipv4tuple*)&tuple)->m_fields = tuple_reversed.m_fields;
		}
	}

	return connection;
}

#ifdef HAS_UNIX_CONNECTIONS
sinsp_connection* sinsp_analyzer::get_connection(const unix_tuple& tuple, uint64_t timestamp)
{
	return m_unix_connections->get_connection(tuple, timestamp);
}

sinsp_connection* sinsp_analyzer::get_connection(const uint64_t ino, uint64_t timestamp)
{
	return m_pipe_connections->get_connection(ino, timestamp);
}
#endif

char* sinsp_analyzer::serialize_to_bytebuf(OUT uint32_t *len, bool compressed)
{
	//
	// Find out how many bytes we need for the serialization
	//
	uint32_t full_len = m_metrics->ByteSize();

	//
	// If the buffer is not big enough, expand it
	//
	if(m_serialization_buffer_size < full_len)
	{
		if(full_len >= MAX_SERIALIZATION_BUF_SIZE_BYTES)
		{
			g_logger.log("Metrics sample too big. Dropping it.", sinsp_logger::SEV_ERROR);
			return NULL;
		}

		m_serialization_buffer = (char*)realloc(m_serialization_buffer, full_len);

		if(!m_serialization_buffer)
		{
			char *estr = g_logger.format(sinsp_logger::SEV_CRITICAL, "memory allocation error at %s:%d", __FILE__, __LINE__);
			throw sinsp_exception(estr);
		}

		m_serialization_buffer_size = full_len;
	}

	//
	// Do the serialization
	//
	if(compressed)
	{
#ifdef _WIN32
		ASSERT(false);
		throw sinsp_exception("compression in agent protocol not implemented under windows");
		return NULL;
#else
		ArrayOutputStream array_output(m_serialization_buffer, full_len);
		GzipOutputStream gzip_output(&array_output);

		m_metrics->SerializeToZeroCopyStream(&gzip_output);
		gzip_output.Close();

		uint32_t compressed_size = (uint32_t) array_output.ByteCount();
		if(compressed_size > full_len)
		{
			ASSERT(false);
			char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "unexpected serialization buffer size");
			throw sinsp_exception(estr);
		}

		*len = compressed_size;
		return m_serialization_buffer;
#endif
	}
	else
	{
		//
		// Reserve 4 bytes at the beginning of the string for the length
		//
		ArrayOutputStream array_output(m_serialization_buffer, full_len);
		m_metrics->SerializeToZeroCopyStream(&array_output);

		*len = full_len;
		return m_serialization_buffer;
	}
}

void sinsp_analyzer::serialize(sinsp_evt* evt, uint64_t ts)
{

	uint64_t nevts = 0;

	if(evt)
	{
		nevts = evt->get_num() - m_serialize_prev_sample_evtnum;
		m_serialize_prev_sample_evtnum = evt->get_num();

		//
		// Subsampling can cause repeated samples, which we skip here
		//
		if(m_serialize_prev_sample_time != 0)
		{
			if(ts == m_serialize_prev_sample_time)
			{
				return;
			}
		}

		m_serialize_prev_sample_time = ts;
	}

	if(m_sample_callback != NULL)
	{
		m_sample_callback->sinsp_analyzer_data_ready(ts, nevts, m_metrics, m_sampling_ratio, m_my_cpuload,
													 m_prev_flush_cpu_pct, m_prev_flushes_duration_ns);
		m_prev_flushes_duration_ns = 0;
	}

	if(m_configuration->get_emit_metrics_to_file())
	{
		char fname[128];
		uint32_t buflen;

		//
		// Serialize the protobuf
		//
		char* buf = sinsp_analyzer::serialize_to_bytebuf(&buflen,
			m_configuration->get_compress_metrics());

		g_logger.format(sinsp_logger::SEV_INFO,
			"to_file ts=%" PRIu64 ", len=%" PRIu32 ", ne=%" PRIu64 ", c=%.2lf, sr=%" PRIu32,
			ts / 100000000,
			buflen, nevts,
			m_my_cpuload,
			m_sampling_ratio);

		if(!buf)
		{
			return;
		}

		snprintf(fname, sizeof(fname), "%s%" PRIu64 ".dam",
			m_configuration->get_metrics_directory().c_str(),
			ts / 1000000000);

		//
		// Write the data to file
		//
		//fp = fopen(fname, "wb");

		//if(!fp)
		//{
		//	char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't open file %s", fname);
		//	throw sinsp_exception(estr);
		//}

		//if(fwrite(buf, buflen, 1, fp) != 1)
		//{
		//	ASSERT(false);
		//	char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't write actual data to file %s", fname);
		//	throw sinsp_exception(estr);
		//}

		//fclose(fp);

		//
		// Write the string version to file
		//
		string pbstr = m_metrics->DebugString();

		snprintf(fname, sizeof(fname), "%s%" PRIu64 ".dams",
			m_configuration->get_metrics_directory().c_str(),
			ts / 1000000000);

		if(m_protobuf_fp == NULL)
		{
			m_protobuf_fp = fopen(fname, "w");

			if(!m_protobuf_fp)
			{
				char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't open file %s", fname);
				throw sinsp_exception(estr);
			}
		}

		if(fwrite(pbstr.c_str(), pbstr.length(), 1, m_protobuf_fp) != 1)
		{
			ASSERT(false);
			char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't write actual data to file %s", fname);
			throw sinsp_exception(estr);
		}
	}
}

template<class Iterator>
void sinsp_analyzer::filter_top_programs(Iterator progtable_begin, Iterator progtable_end, bool cs_only, uint32_t howmany)
{
	uint32_t j;

	vector<sinsp_threadinfo*> prog_sortable_list;

	for(auto ptit = progtable_begin; ptit != progtable_end; (++ptit))
	{
		if(cs_only)
		{
			int is_cs = ((*ptit)->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
					thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT | thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT));

			if(is_cs)
			{
				prog_sortable_list.push_back(*ptit);
			}
		}
		else
		{
			prog_sortable_list.push_back(*ptit);
		}
	}

	if(prog_sortable_list.size() <= howmany)
	{
		for(j = 0; j < prog_sortable_list.size(); j++)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}

		return;
	}

	//
	// Mark the top CPU consumers
	//
	partial_sort(prog_sortable_list.begin(),
		prog_sortable_list.begin() + howmany,
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_cpu_cs:threadinfo_cmp_cpu);

	for(j = 0; j < howmany; j++)
	{
		if(prog_sortable_list[j]->m_ainfo->m_cpuload > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top memory consumers
	//
	partial_sort(prog_sortable_list.begin(),
		prog_sortable_list.begin() + howmany,
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_memory_cs:threadinfo_cmp_memory);

	for(j = 0; j < howmany; j++)
	{
		if(prog_sortable_list[j]->m_vmsize_kb > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top disk I/O consumers
	//
	partial_sort(prog_sortable_list.begin(),
		prog_sortable_list.begin() + howmany,
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_io_cs:threadinfo_cmp_io);

	for(j = 0; j < howmany; j++)
	{
		ASSERT(prog_sortable_list[j]->m_ainfo->m_procinfo != NULL);

		if(prog_sortable_list[j]->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top network I/O consumers
	//
	partial_sort(prog_sortable_list.begin(),
		prog_sortable_list.begin() + howmany,
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_net_cs:threadinfo_cmp_net);

	for(j = 0; j < howmany; j++)
	{
		ASSERT(prog_sortable_list[j]->m_ainfo->m_procinfo != NULL);

		if(prog_sortable_list[j]->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top transaction generators
	//
	//partial_sort(prog_sortable_list.begin(),
	//	prog_sortable_list.begin() + howmany,
	//	prog_sortable_list.end(),
	//	threadinfo_cmp_transactions);

	//for(j = 0; j < howmany; j++)
	//{
	//	if(prog_sortable_list[j]->m_ainfo->m_procinfo->m_proc_transaction_metrics.m_counter.get_tot_count() > 0)
	//	{
	//		prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
	//	}
	//	else
	//	{
	//		break;
	//	}
	//}
}

bool sinsp_analyzer::check_k8s_server(string& addr)
{
	string path = "/api";
	uri url(addr + path);
	g_logger.log("Preparing to detect K8S at [" + url.to_string(false) + "] ...", sinsp_logger::SEV_TRACE);
	std::unique_ptr<sinsp_curl> sc;
	if(url.is_secure() && !m_k8s_ssl)
	{
		const std::string& cert          = m_configuration->get_k8s_ssl_cert();
		const std::string& key           = m_configuration->get_k8s_ssl_key();
		const std::string& key_pwd       = m_configuration->get_k8s_ssl_key_password();
		const std::string& ca_cert       = m_configuration->get_k8s_ssl_ca_certificate();
		bool verify_cert                 = m_configuration->get_k8s_ssl_verify_certificate();
		const std::string& cert_type     = m_configuration->get_k8s_ssl_cert_type();
		m_k8s_ssl = std::make_shared<sinsp_curl::ssl>(cert, key, key_pwd, ca_cert, verify_cert, cert_type);
	}
	const std::string& bt_auth_token = m_configuration->get_k8s_bt_auth_token();
	if(!bt_auth_token.empty())
	{
		m_k8s_bt = std::make_shared<sinsp_curl::bearer_token>(bt_auth_token);
	}
	sc.reset(new sinsp_curl(url, m_k8s_ssl, m_k8s_bt, 500, m_configuration->get_curl_debug()));
	string json = sc->get_data(false);
	if(!json.empty())
	{
		g_logger.log("Detecting K8S at [" + url.to_string(false) + ']', sinsp_logger::SEV_DEBUG);
		Json::Value root;
		Json::Reader reader;
		if(reader.parse(json, root))
		{
			const Json::Value& vers = root["versions"];
			if(vers.isArray())
			{
				for (const auto& ver : vers)
				{
					if(ver.asString() == "v1")
					{
						return true;
					}
				}
			}
		}
	}
	return false;
}

bool sinsp_analyzer::check_mesos_server(string& addr)
{
	uri url(addr);
	url.set_path(mesos::default_version_api);
	g_logger.log("Preparing to detect Mesos at [" + url.to_string(false) + "] ...", sinsp_logger::SEV_TRACE);
	const mesos::credentials_t& creds = m_configuration->get_mesos_credentials();
	if(!creds.first.empty())
	{
		url.set_credentials(creds);
	}
	Json::Value root;
	Json::Reader reader;
	sinsp_curl sc(url, 500);
	sc.setopt(CURLOPT_SSL_VERIFYPEER, 0);
	sc.setopt(CURLOPT_SSL_VERIFYHOST, 0);
	if(reader.parse(sc.get_data(false), root))
	{
		g_logger.log("Detecting Mesos at [" + url.to_string(false) + ']', sinsp_logger::SEV_DEBUG);
		Json::Value ver = root["version"];
		if(!ver.isNull() && ver.isString())
		{
			if(!ver.asString().empty())
			{
				// Change path, to state api instead of version
				url.set_path(mesos::default_state_api);
				addr = url.to_string(true);
				m_configuration->set_mesos_state_uri(addr); // set globally in config
				return true;
			}
		}
	}
	return false;
}

string sinsp_analyzer::detect_local_server(const string& protocol, uint32_t port, server_check_func_t check_func)
{
	if(m_inspector && m_inspector->m_network_interfaces)
	{
		for (const auto& iface : *m_inspector->m_network_interfaces->get_ipv4_list())
		{
			std::string addr(protocol);
			addr.append("://").append(iface.address()).append(1, ':').append(std::to_string(port));
			if((this->*check_func)(addr))
			{
				return addr;
			}
		}
	}
	else
	{
		g_logger.log("Local server detection failed.", sinsp_logger::SEV_ERROR);
	}
	return "";
}

void sinsp_analyzer::make_mesos(string&& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		Json::Value ver = root["version"];
		if(!ver.isNull())
		{
			const std::string& version = ver.asString();
			if(!version.empty())
			{
				string mesos_state = m_configuration->get_mesos_state_uri();
				vector<string> marathon_uris = m_configuration->get_marathon_uris();

				g_logger.log("Mesos master version [" + version + "] found at " + uri(mesos_state).to_string(false),
					sinsp_logger::SEV_INFO);
				g_logger.log("Mesos state: [" + uri(mesos_state + mesos::default_state_api).to_string(false) + ']',
					sinsp_logger::SEV_INFO);
				for(const auto& marathon_uri : marathon_uris)
				{
					g_logger.log("Mesos (Marathon) groups: [" + uri(marathon_uri + mesos::default_groups_api).to_string(false) + ']',
						sinsp_logger::SEV_INFO);
					g_logger.log("Mesos (Marathon) apps: [" + uri(marathon_uri + mesos::default_apps_api).to_string(false) + ']',
						sinsp_logger::SEV_INFO);
				}

				m_mesos_present = true;
				if(m_mesos) { m_mesos.reset(); }
				if(!m_configuration->get_dcos_enterprise_credentials().first.empty())
				{
					time(&m_dcos_enterprise_last_token_refresh_s);
					m_mesos.reset(new mesos(mesos_state,
											marathon_uris,
											m_configuration->get_mesos_follow_leader(),
											m_configuration->get_marathon_follow_leader(),
											m_configuration->get_dcos_enterprise_credentials(),
											m_configuration->get_mesos_timeout_ms()));
				}
				else
				{
					m_mesos.reset(new mesos(mesos_state,
											marathon_uris,
											m_configuration->get_mesos_follow_leader(),
											m_configuration->get_marathon_follow_leader(),
											m_configuration->get_mesos_credentials(),
											m_configuration->get_marathon_credentials(),
											m_configuration->get_mesos_timeout_ms()));
				}
			}
		}
	}
}

void sinsp_analyzer::get_mesos(const string& mesos_uri)
{
	m_mesos.reset();
	uri url(mesos_uri);
	url.set_path(mesos::default_version_api);
	long tout = m_configuration->get_mesos_timeout_ms();

	try
	{
		sinsp_curl sc(url, tout);
		sc.setopt(CURLOPT_SSL_VERIFYPEER, 0);
		sc.setopt(CURLOPT_SSL_VERIFYHOST, 0);
		std::string json = sc.get_data();
		url.set_path(mesos::default_state_api);
		m_configuration->set_mesos_state_uri(url.to_string(true));
		make_mesos(std::move(json));
	}
	catch(std::exception& ex)
	{
		g_logger.log("Error connecting to Mesos at [" + uri(mesos_uri).to_string(false) + "]. Error: " + ex.what(),
					sinsp_logger::SEV_ERROR);
	}
}

sinsp_analyzer::k8s_ext_list_ptr_t sinsp_analyzer::k8s_discover_ext(const std::string& k8s_api)
{
	const k8s_ext_list_t& ext_list = m_configuration->get_k8s_extensions();
	if(ext_list.size())
	{
		m_ext_list_ptr.reset(new k8s_ext_list_t(ext_list));
		m_k8s_ext_detect_done = true;
	}
	else
	{
		try
		{
			if(!m_k8s && !m_k8s_ext_detect_done)
			{
				g_logger.log("K8s API extensions handler: detecting extensions.", sinsp_logger::SEV_TRACE);
				if(!m_k8s_ext_handler)
				{
					if(!m_k8s_collector)
					{
						m_k8s_collector = std::make_shared<k8s_handler::collector_t>();
					}
					if(uri(k8s_api).is_secure()) { init_k8s_ssl(k8s_api); }
					m_k8s_ext_handler.reset(new k8s_api_handler(m_k8s_collector, k8s_api,
																"/apis/extensions/v1beta1", "[.resources[].name]", "1.1",
																m_k8s_ssl, m_k8s_bt, false));
					g_logger.log("K8s API extensions handler: collector created.", sinsp_logger::SEV_TRACE);
					return nullptr;
				}
				else
				{
					g_logger.log("K8s API extensions handler: collecting data.", sinsp_logger::SEV_TRACE);
					m_k8s_ext_handler->collect_data();
					if(m_k8s_ext_handler->connection_error())
					{
						throw sinsp_exception(" connection error.");
					}
					else if(m_k8s_ext_handler->ready())
					{
						g_logger.log("K8s API extensions handler: data received.", sinsp_logger::SEV_TRACE);
						if(m_k8s_ext_handler->error())
						{
							g_logger.log("K8s API extensions handler: data error occurred while detecting API extensions.",
										 sinsp_logger::SEV_WARNING);
							m_ext_list_ptr.reset();
						}
						else
						{
							const k8s_api_handler::api_list_t& exts = m_k8s_ext_handler->extensions();
							std::ostringstream ostr;
							k8s_ext_list_t ext_list;
							for(const auto& ext : exts)
							{
								ext_list.insert(ext);
								ostr << std::endl << ext;
							}
							if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
							{
								g_logger.log("K8s API extensions handler: extensions found: " + ostr.str(),
											 sinsp_logger::SEV_DEBUG);
							}
							else
							{
								g_logger.log("K8s API extensions detected: " + ostr.str(),
											 sinsp_logger::SEV_INFO);
							}
							m_ext_list_ptr.reset(new k8s_ext_list_t(ext_list));
						}
						m_k8s_ext_detect_done = true;
						m_k8s_collector.reset();
						m_k8s_ext_handler.reset();
					}
					else
					{
						g_logger.log("K8s API extensions handler: not ready.", sinsp_logger::SEV_TRACE);
						return nullptr;
					}
				}
			}
		}
		catch(std::exception& ex)
		{
			static time_t last_attempt;
			reset_k8s(last_attempt, std::string("K8s API extensions handler error: ").append(ex.what()));
			throw;
		}
	}
	return m_ext_list_ptr;
}

void sinsp_analyzer::init_k8s_ssl(const uri& url)
{
	if(url.is_secure() && !m_k8s_ssl)
	{
		const std::string& cert      = m_configuration->get_k8s_ssl_cert();
		const std::string& key       = m_configuration->get_k8s_ssl_key();
		const std::string& key_pwd   = m_configuration->get_k8s_ssl_key_password();
		const std::string& ca_cert   = m_configuration->get_k8s_ssl_ca_certificate();
		bool verify_cert             = m_configuration->get_k8s_ssl_verify_certificate();
		const std::string& cert_type = m_configuration->get_k8s_ssl_cert_type();
		m_k8s_ssl = std::make_shared<sinsp_ssl>(cert, key, key_pwd, ca_cert, verify_cert, cert_type);
	}
	const std::string& bt_auth_token = m_configuration->get_k8s_bt_auth_token();
	if(!bt_auth_token.empty() && !m_k8s_bt)
	{
		m_k8s_bt = std::make_shared<sinsp_bearer_token>(bt_auth_token);
	}
}

k8s* sinsp_analyzer::get_k8s(const uri& k8s_api, const std::string& msg)
{
	try
	{
		if(k8s_api.is_secure()) { init_k8s_ssl(k8s_api); }
		k8s_discover_ext(k8s_api.to_string());
		if(m_k8s_ext_detect_done)
		{
			m_k8s_ext_detect_done = false;
			g_logger.log(msg, sinsp_logger::SEV_INFO);
			return new k8s(k8s_api.to_string(), false /*not captured*/,
						   m_k8s_ssl, m_k8s_bt, false,
						   m_configuration->get_k8s_event_filter(),
						   m_ext_list_ptr);
		}
	}
	catch(std::exception& ex)
	{
		static time_t last_connect_attempt;
		time_t now; time(&now);
		if(difftime(now, last_connect_attempt) > m_k8s_retry_seconds)
		{
			last_connect_attempt = now;
			g_logger.log(std::string("K8s framework creation error: ").append(ex.what()), sinsp_logger::SEV_ERROR);
		}
	}
	return nullptr;
}

std::string sinsp_analyzer::get_k8s_api_server_proc(sinsp_threadinfo* main_tinfo)
{
	if(main_tinfo)
	{
		if(main_tinfo->m_exe.find("kube-apiserver") != std::string::npos)
		{
			return "kube-apiserver";
		}
		else if(main_tinfo->m_exe.find("hyperkube") != std::string::npos)
		{
			for(const auto& arg : main_tinfo->m_args)
			{
				if(arg == "apiserver")
				{
					return "hyperkube apiserver";
				}
			}
		}
	}
	return "";
}

std::string sinsp_analyzer::detect_k8s(std::string& k8s_api_server)
{
	k8s_api_server = detect_local_server("http", 8080, &sinsp_analyzer::check_k8s_server);
	if(k8s_api_server.empty())
	{
		k8s_api_server = detect_local_server("https", 443, &sinsp_analyzer::check_k8s_server);
	}

	if(!k8s_api_server.empty())
	{
		m_configuration->set_k8s_api_server(k8s_api_server);
		g_logger.log("K8S API server auto-detected and set to: " + k8s_api_server, sinsp_logger::SEV_INFO);
	}
	else
	{
		g_logger.log("K8S API server not found.", sinsp_logger::SEV_WARNING);
	}
	if(m_configuration->get_k8s_autodetect_enabled())
	{
		m_configuration->set_k8s_api_server(k8s_api_server);
	}
	return k8s_api_server;
}

std::string sinsp_analyzer::detect_k8s(sinsp_threadinfo* main_tinfo)
{
	string k8s_api_server = m_configuration->get_k8s_api_server();
	if(m_configuration->get_k8s_autodetect_enabled())
	{
		if(k8s_api_server.empty() || !m_k8s)
		{
			if(main_tinfo)
			{
				string kube_apiserver_process = get_k8s_api_server_proc(main_tinfo);

				if(kube_apiserver_process.empty())
				{
					k8s_api_server.clear();
				}

				if(!kube_apiserver_process.empty())
				{
					g_logger.log("K8S: Detected [" + kube_apiserver_process + "] process", sinsp_logger::SEV_INFO);
					detect_k8s(k8s_api_server);
				}
			}
			else if(m_k8s_proc_detected)
			{
				g_logger.log("K8S: Detected API server process", sinsp_logger::SEV_INFO);
				detect_k8s(k8s_api_server);
			}
		}
		m_configuration->set_k8s_api_server(k8s_api_server);
	}
	return k8s_api_server;
}

std::string& sinsp_analyzer::detect_mesos(std::string& mesos_api_server)
{
	if(!m_mesos)
	{
		auto protocol = m_configuration->get_dcos_enterprise_credentials().first.empty() ? "http" : "https";
		mesos_api_server = detect_local_server(protocol, 5050, &sinsp_analyzer::check_mesos_server);
		if(!mesos_api_server.empty())
		{
			m_configuration->set_mesos_state_uri(mesos_api_server);
			g_logger.log("Mesos API server set to: " + uri(mesos_api_server).to_string(false), sinsp_logger::SEV_INFO);
			m_configuration->set_mesos_follow_leader(true);
			if(m_configuration->get_marathon_uris().empty())
			{
				m_configuration->set_marathon_follow_leader(true);
			}
			g_logger.log("Mesos API server failover discovery enabled for: " + mesos_api_server,
						 sinsp_logger::SEV_INFO);
		}
		else
		{
			// not to flood logs, log only once a minute
			static time_t last_log;
			time_t now; time(&now);
			if(m_mesos_present && (difftime(now, last_log) > m_detect_retry_seconds))
			{
				last_log = now;
				g_logger.log("Mesos API server not found.", sinsp_logger::SEV_WARNING);
			}
		}
	}
	return mesos_api_server;
}

std::string sinsp_analyzer::detect_mesos(sinsp_threadinfo* main_tinfo)
{
	string mesos_apiserver_process;

	string mesos_api_server = m_configuration->get_mesos_state_uri();
	if(!m_mesos)
	{
		if((mesos_api_server.empty() || m_configuration->get_mesos_state_original_uri().empty()) &&
		   m_configuration->get_mesos_autodetect_enabled() && !m_mesos_bad_config)
		{
			if(main_tinfo && main_tinfo->m_exe.find("mesos-master") != std::string::npos)
			{
				mesos_apiserver_process = "mesos-master";
			}
			if(!mesos_apiserver_process.empty())
			{
				g_logger.log("Mesos: Detected '"+ mesos_apiserver_process + "' process", sinsp_logger::SEV_INFO);
				detect_mesos(mesos_api_server);
			}
		}
	}
	return mesos_api_server;
}

void sinsp_analyzer::emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof, sinsp_analyzer::flush_flags flshflags)
{
	int64_t delta;
	sinsp_evt::category* cat;
	sinsp_evt::category tcat;
	m_server_programs.clear();
	threadinfo_map_iterator_t it;
	set<uint64_t> proctids;
	auto prog_hasher = [](sinsp_threadinfo* tinfo)
	{
		return tinfo->get_main_thread()->m_program_hash;
	};
	auto prog_cmp = [](sinsp_threadinfo* lhs, sinsp_threadinfo* rhs)
	{
		return lhs->get_main_thread()->m_program_hash == rhs->get_main_thread()->m_program_hash;
	};
	unordered_set<sinsp_threadinfo*, decltype(prog_hasher), decltype(prog_cmp)> progtable(TOP_PROCESSES_IN_SAMPLE, prog_hasher, prog_cmp);
	progtable_by_container_t progtable_by_container;
#ifndef _WIN32
	vector<sinsp_threadinfo*> java_process_requests;
	vector<app_process> app_checks_processes;
	uint16_t app_checks_limit = APP_METRICS_LIMIT;

	// Get metrics from JMX until we found id 0 or timestamp-1
	// with id 0, means that sdjagent is not working or metrics are not ready
	// id = timestamp-1 are what we need now
	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		if(m_jmx_proxy)
		{
			auto jmx_metrics = m_jmx_proxy->read_metrics();
			if(!jmx_metrics.empty())
			{
				// m_jmx_metrics is cleared by flush() because they are used
				// by falco baseliner, outside emit_processes
				m_jmx_metrics = move(jmx_metrics);
			}
		}
		if(m_app_proxy)
		{
			for(auto it = m_app_metrics.begin(); it != m_app_metrics.end();)
			{
				auto flush_time_s = m_prev_flush_time_ns/ONE_SECOND_IN_NS;
				if(flush_time_s > it->second.expiration_ts() &&
				   flush_time_s - it->second.expiration_ts() > APP_METRICS_EXPIRATION_TIMEOUT_S)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG, "App metrics for pid %d expired %u s ago, forcing wipe", it->first, flush_time_s - it->second.expiration_ts());
					it = m_app_metrics.erase(it);
				}
				else
				{
					++it;
				}
			}
			auto app_metrics = m_app_proxy->read_metrics();
			for(auto& item : app_metrics)
			{

				m_app_metrics[item.first] = move(item.second);
			}
		}
	}
#endif

	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
			"thread table size:%d",
			m_inspector->m_thread_manager->get_thread_count());
	}

	if(m_ipv4_connections->get_n_drops() != 0)
	{
		if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
				"IPv4 table size:%d",
				m_ipv4_connections->m_connections.size());
		}

		m_ipv4_connections->clear_n_drops();
	}

	//
	// Run the periodic /proc scan and use it to prune the process table
	//
	if(m_inspector->is_live() && m_n_flushes % PROC_BASED_THREAD_PRUNING_INTERVAL ==
		(PROC_BASED_THREAD_PRUNING_INTERVAL - 1))
	{
		m_procfs_parser->get_tid_list(&proctids);
	}

	//
	// Extract global CPU info
	//
	uint64_t cur_global_total_jiffies;
	if(!m_inspector->is_offline())
	{
		if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			if(!m_skip_proc_parsing)
			{
				m_procfs_parser->get_global_cpu_load(&cur_global_total_jiffies);
			}
		}
	}
	else
	{
		cur_global_total_jiffies = 0;
	}

	bool try_detect_mesos = (m_configuration->get_mesos_autodetect_enabled() &&
							 m_configuration->get_mesos_state_original_uri().empty() &&
							 !m_mesos && !m_mesos_bad_config);
	bool try_detect_k8s = (m_configuration->get_k8s_autodetect_enabled() && !m_k8s &&
						   m_configuration->get_k8s_api_server().empty());
	bool mesos_detected = false, k8s_detected = false;
	static bool mesos_been_here = false, k8s_been_here = false;
	if(m_k8s_proc_detected && !m_configuration->get_k8s_api_server().empty())
	{
		m_k8s_proc_detected = false;
	}
	// Emit process has 3 cycles on thread_table:
	// 1. Aggregate process into programs
	// 2. (only on programs) aggregate programs metrics to host and container ones
	// 3. (only on programs) Write programs on protobuf

	///////////////////////////////////////////////////////////////////////////
	// First pass of the list of threads: emit the metrics (if defined)
	// and aggregate them into processes
	///////////////////////////////////////////////////////////////////////////
	for(it = m_inspector->m_thread_manager->m_threadtable.begin();
		it != m_inspector->m_thread_manager->m_threadtable.end(); ++it)
	{
		sinsp_threadinfo* tinfo = &it->second;
		thread_analyzer_info* ainfo = tinfo->m_ainfo;

		sinsp_threadinfo* main_tinfo = tinfo->get_main_thread();
		thread_analyzer_info* main_ainfo = main_tinfo->m_ainfo;

		analyzer_container_state* container = NULL;

		if(!tinfo->m_container_id.empty())
		{
			container = &m_containers[tinfo->m_container_id];
			if(container->m_memory_cgroup.empty())
			{
				auto memory_cgroup_it = find_if(tinfo->m_cgroups.cbegin(), tinfo->m_cgroups.cend(),
												[](const pair<string, string>& cgroup)
												{
													return cgroup.first == "memory";
												});
				if(memory_cgroup_it != tinfo->m_cgroups.cend())
				{
					container->m_memory_cgroup = memory_cgroup_it->second;
				}
			}
		}

		// We need to reread cmdline only in live mode, with nodriver mode
		// proc is reread every sample anyway
		if(m_inspector->m_mode == SCAP_MODE_LIVE && (tinfo->m_flags & PPM_CL_CLOSED) == 0 &&
				m_prev_flush_time_ns - main_ainfo->m_last_cmdline_sync_ns > CMDLINE_UPDATE_INTERVAL_S*ONE_SECOND_IN_NS)
		{
			string proc_name = m_procfs_parser->read_process_name(main_tinfo->m_pid);
			if(!proc_name.empty())
			{
				main_tinfo->m_comm = proc_name;
			}
			vector<string> proc_args = m_procfs_parser->read_process_cmdline(main_tinfo->m_pid);
			if(!proc_args.empty())
			{
				main_tinfo->m_exe = proc_args.at(0);
				main_tinfo->m_args.clear();
				main_tinfo->m_args.insert(main_tinfo->m_args.begin(), ++proc_args.begin(), proc_args.end());

				// TODO: move k8s and mesos stuff out of here
				if(!m_k8s_proc_detected)
				{
					m_k8s_proc_detected = !(get_k8s_api_server_proc(main_tinfo).empty());
				}
				if(m_k8s_proc_detected && try_detect_k8s)
				{
					k8s_detected = !(detect_k8s(main_tinfo).empty());
				}
				if(try_detect_mesos)
				{
					mesos_detected = !(detect_mesos(main_tinfo).empty());
				}
			}
			main_tinfo->compute_program_hash();
			main_ainfo->m_last_cmdline_sync_ns = m_prev_flush_time_ns;
		}

		//
		// Attribute the last pending event to this second
		//
		if(m_prev_flush_time_ns != 0)
		{
			delta = m_prev_flush_time_ns - tinfo->m_lastevent_ts;

			if(delta > (int64_t)sample_duration)
			{
				delta = (tinfo->m_lastevent_ts / sample_duration * sample_duration + sample_duration) -
					tinfo->m_lastevent_ts;
			}

			tinfo->m_lastevent_ts = m_prev_flush_time_ns;

			if(PPME_IS_ENTER(tinfo->m_lastevent_type))
			{
				cat = &tinfo->m_lastevent_category;
			}
			else
			{
				tcat.m_category = EC_PROCESSING;
				tcat.m_subcategory = sinsp_evt::SC_NONE;
				cat = &tcat;
			}

			add_syscall_time(&ainfo->m_metrics,
				cat,
				delta,
				0,
				false);

			//
			// Flag the thread so we know that part of this event has already been attributed
			//
			ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_PARTIAL_METRIC;
		}

		//
		// Some assertions to validate that everything looks like expected
		//
#ifdef _DEBUG
		sinsp_counter_time ttot;
		ainfo->m_metrics.get_total(&ttot);
//		if(!m_inspector->m_islive)
//		{
//			ASSERT(is_eof || ttot.m_time_ns % sample_duration == 0);
//		}
#endif

		//
		// Go through the FD list to flush the transactions that haven't been active for a while
		//
		uint64_t trtimeout;
		bool is_subsampling;

		if(flshflags == sinsp_analyzer::DF_NONE)
		{
			trtimeout = TRANSACTION_TIMEOUT_NS;
			is_subsampling = false;
		}
		else
		{
			trtimeout = TRANSACTION_TIMEOUT_SUBSAMPLING_NS;
			is_subsampling = true;
		}

		ainfo->flush_inactive_transactions(m_prev_flush_time_ns, trtimeout, is_subsampling);

		//
		// If this is a process, compute CPU load and memory usage
		//
		ainfo->m_cpuload = 0;

		if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			if(tinfo->is_main_thread())
			{
				if(!m_inspector->is_offline())
				{
					//
					// It's pointless to try to get the CPU load if the process has been closed
					//
					if((tinfo->m_flags & PPM_CL_CLOSED) == 0)
					{
						if(!m_skip_proc_parsing)
						{
							ainfo->m_cpuload = m_procfs_parser->get_process_cpu_load(tinfo->m_pid,
								&ainfo->m_old_proc_jiffies,
								cur_global_total_jiffies - m_old_global_total_jiffies);
						}

						if(ainfo->m_cpuload >= 0)
						{
							m_total_process_cpu += ainfo->m_cpuload;
						}
#if defined(HAS_CAPTURE)
						if(it->first == m_inspector->m_sysdig_pid)
						{
							m_my_cpuload = ainfo->m_cpuload;
						}
#else
						m_my_cpuload = 0;
#endif
					}
				}
			}
		}

		if(tinfo->m_flags & PPM_CL_CLOSED &&
				!(evt != NULL &&
				  (evt->get_type() == PPME_PROCEXIT_E || evt->get_type() == PPME_PROCEXIT_1_E)
				  && evt->m_tinfo == tinfo))
		{
			//
			// Yes, remove the thread from the table, but NOT if the event currently under processing is
			// an exit for this process. In that case we wait until next sample.
			// Note: we clear the metrics no matter what because m_thread_manager->remove_thread might
			//       not actually remove the thread if it has childs.
			//
			m_threads_to_remove.push_back(tinfo);
		}

		if(proctids.size() != 0 && proctids.find(tinfo->m_pid) == proctids.end())
		{
			tinfo->m_flags |= PPM_CL_CLOSED;
		}
		//
		// Add this thread's counters to the process ones...
		//
		ASSERT(tinfo->m_program_hash != 0);

		auto emplaced = progtable.emplace(tinfo);
		auto mtinfo = *emplaced.first;
		// Use first found thread of a program to collect all metrics
		if(emplaced.second)
		{
			if(container)
			{
				progtable_by_container[mtinfo->m_container_id].emplace_back(mtinfo);
			}
			ainfo->set_main_program_thread(true);
		}
		else
		{
			ainfo->set_main_program_thread(false);
		}

		ASSERT(mtinfo != NULL);

		ainfo->m_main_thread_pid = mtinfo->m_pid;

		mtinfo->m_ainfo->add_all_metrics(ainfo);

		if(!emplaced.second)
		{
			ainfo->clear_all_metrics();
		}
#ifndef _WIN32
		if(tinfo->is_main_thread() && !(tinfo->m_flags & PPM_CL_CLOSED) &&
		   (m_next_flush_time_ns - tinfo->m_clone_ts) > ASSUME_LONG_LIVING_PROCESS_UPTIME_S*ONE_SECOND_IN_NS &&
				tinfo->m_vpid > 0)
		{
			if(m_jmx_proxy && tinfo->get_comm() == "java")
			{
				java_process_requests.emplace_back(tinfo);
			}
			// May happen that for processes like apache with mpm_prefork there are hundred of
			// apache processes with same comm, cmdline and ports, some of them are always alive,
			// some die and are recreated.
			// We send to app_checks only processes up at least for 10 seconds. But the programs aggregation
			// may choose the young one.
			// So now we are trying to match a check for every process in the program grouping and
			// when we find a matching check, we mark it on the main_thread of the group as
			// we don't need more checks instances for each process.
			if(m_app_proxy && !mtinfo->m_ainfo->app_check_found())
			{
				auto app_metrics_it = m_app_metrics.find(tinfo->m_pid);
				if(app_metrics_it != m_app_metrics.end() &&
				   app_metrics_it->second.expiration_ts() > (m_prev_flush_time_ns/ONE_SECOND_IN_NS))
				{
					// Found app metrics for this pid that are not expired
					// so we can use them instead of running the check again
					g_logger.format(sinsp_logger::SEV_DEBUG, "App metrics for %d are still good", tinfo->m_pid);
					mtinfo->m_ainfo->set_app_check_found();
				}
				else
				{
					// First check if the process has custom config for checks
					// and use it
					const auto& custom_checks = mtinfo->m_ainfo->get_proc_config().app_checks();
					for(const auto& check : custom_checks)
					{
						if(check.match(tinfo))
						{
							g_logger.format(sinsp_logger::SEV_DEBUG, "Found check %s for process %d:%d from env",
											check.name().c_str(), tinfo->m_pid, tinfo->m_vpid);
							app_checks_processes.emplace_back(check, tinfo);
							mtinfo->m_ainfo->set_app_check_found();
							break;
						}
					}
					// If still no matches found, go ahead with the global list
					if(!mtinfo->m_ainfo->app_check_found())
					{
						for(const auto &check : m_app_checks)
						{
							if(check.match(tinfo))
							{
								g_logger.format(sinsp_logger::SEV_DEBUG, "Found check %s for process %d:%d",
												check.name().c_str(), tinfo->m_pid, tinfo->m_vpid);
								app_checks_processes.emplace_back(check, tinfo);
								mtinfo->m_ainfo->set_app_check_found();
								break;
							}
						}
					}
				}
			}
		}
#endif
	}

	if(!mesos_been_here && try_detect_mesos && !mesos_detected)
	{
		mesos_been_here = true;
		g_logger.log("Mesos API server not configured or auto-detected at this time; "
					 "Mesos information may not be available.",
					 sinsp_logger::SEV_INFO);
	}

	if(!k8s_been_here && try_detect_k8s && !k8s_detected)
	{
		k8s_been_here = true;
		g_logger.log("K8s API server not configured or auto-detected at this time; "
					 "K8s information may not be available.",
					 sinsp_logger::SEV_INFO);
	}

	for(auto it = progtable.begin(); it != progtable.end(); ++it)
	{
		sinsp_threadinfo* tinfo = *it;
		analyzer_container_state* container = NULL;
		if(!tinfo->m_container_id.empty())
		{
			container = &m_containers[tinfo->m_container_id];
		}

		sinsp_procinfo* procinfo = tinfo->m_ainfo->m_procinfo;

		//
		// ... And to the host ones
		//
		m_host_transaction_counters.add(&procinfo->m_external_transaction_metrics);

		if(container)
		{
			container->m_transaction_counters.add(&procinfo->m_proc_transaction_metrics);
		}

		if(procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
		{
			m_server_programs.insert(tinfo->m_tid);
			m_client_tr_time_by_servers += procinfo->m_external_transaction_metrics.get_counter()->m_time_ns_out;
		}

		sinsp_counter_time tot;

		ASSERT(procinfo != NULL);

		procinfo->m_proc_metrics.get_total(&tot);
//		if(!m_inspector->m_islive)
//		{
//			ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);
//		}

		if(tot.m_count != 0)
		{
			sinsp_delays_info* prog_delays = &procinfo->m_transaction_delays;
			if(container)
			{
				m_delay_calculator->compute_program_delays(&m_host_client_transactions, &m_host_server_transactions,
														   &container->m_client_transactions, &container->m_server_transactions, tinfo, prog_delays);
			}
			else
			{
				m_delay_calculator->compute_program_delays(&m_host_client_transactions, &m_host_server_transactions, NULL, NULL, tinfo, prog_delays);
			}

#ifdef _DEBUG
			procinfo->m_proc_metrics.calculate_totals();
			double totpct = procinfo->m_proc_metrics.get_processing_percentage() +
							procinfo->m_proc_metrics.get_file_percentage() +
							procinfo->m_proc_metrics.get_net_percentage() +
							procinfo->m_proc_metrics.get_other_percentage();
			ASSERT(totpct == 0 || (totpct > 0.99 && totpct < 1.01));
#endif // _DEBUG

			//
			// Main metrics
			//
			// NOTE ABOUT THE FOLLOWING TWO LINES: computing processing time by looking at gaps
			// among system calls doesn't work if we are dropping all the non essential events,
			// which the aagent does by default, because a ton of time gets accountd as processing.
			// To avoid the issue, we patch the processing time with the actual CPU time for the
			// process, normalized accodring to the sampling ratio
			//
			procinfo->m_proc_metrics.m_processing.clear();
			procinfo->m_proc_metrics.m_processing.add(1, (uint64_t)(procinfo->m_cpuload * (1000000000 / 100) / m_sampling_ratio));

			//
			// Health-related metrics
			//
			if(m_inspector->m_thread_manager->get_thread_count() < DROP_SCHED_ANALYZER_THRESHOLD &&
					procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
			{
				sinsp_score_info scores = m_score_calculator->get_process_capacity_score(tinfo,
																						 prog_delays,
																						 (uint32_t)tinfo->m_ainfo->m_procinfo->m_n_transaction_threads,
																						 m_prev_flush_time_ns, sample_duration);

				procinfo->m_capacity_score = scores.m_current_capacity;
				procinfo->m_stolen_capacity_score = scores.m_stolen_capacity;
			}
			else
			{
				procinfo->m_capacity_score = -1;
				procinfo->m_stolen_capacity_score = 0;
			}

			//
			// Update the host capcity score
			//
			if(procinfo->m_capacity_score != -1)
			{
				m_host_metrics.add_capacity_score(procinfo->m_capacity_score,
												  procinfo->m_stolen_capacity_score,
												  procinfo->m_external_transaction_metrics.get_counter()->m_count_in);

				if(container)
				{
					container->m_metrics.add_capacity_score(procinfo->m_capacity_score,
															procinfo->m_stolen_capacity_score,
															procinfo->m_external_transaction_metrics.get_counter()->m_count_in);
				}
			}

#if 1
			if(procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
			{
				uint64_t trtimein = procinfo->m_proc_transaction_metrics.get_counter()->m_time_ns_in;
				uint64_t trtimeout = procinfo->m_proc_transaction_metrics.get_counter()->m_time_ns_out;
				uint32_t trcountin = procinfo->m_proc_transaction_metrics.get_counter()->m_count_in;
				uint32_t trcountout = procinfo->m_proc_transaction_metrics.get_counter()->m_count_out;

				if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
									" %s (%" PRIu64 ")%" PRIu64 " h:%.2f(s:%.2f) cpu:%.2f %%f:%" PRIu32 " %%c:%" PRIu32,
									tinfo->m_comm.c_str(),
									tinfo->m_tid,
									(uint64_t)tinfo->m_ainfo->m_procinfo->m_program_pids.size(),
									procinfo->m_capacity_score,
									procinfo->m_stolen_capacity_score,
									(float)procinfo->m_cpuload,
									procinfo->m_fd_usage_pct,
									procinfo->m_connection_queue_usage_pct);

					g_logger.format(sinsp_logger::SEV_DEBUG,
									"  trans)in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
									procinfo->m_proc_transaction_metrics.get_counter()->m_count_in * m_sampling_ratio,
									procinfo->m_proc_transaction_metrics.get_counter()->m_count_out * m_sampling_ratio,
									trcountin? ((double)trtimein) / sample_duration : 0,
									trcountout? ((double)trtimeout) / sample_duration : 0,
									(prog_delays)?((double)prog_delays->m_merged_server_delay) / sample_duration : 0,
									(prog_delays)?((double)prog_delays->m_merged_client_delay) / sample_duration : 0,
									(prog_delays)?((double)prog_delays->m_local_processing_delay_ns) / sample_duration : 0);

					g_logger.format(sinsp_logger::SEV_DEBUG,
									"  time)proc:%.2lf%% file:%.2lf%%(in:%" PRIu32 "b/%" PRIu32" out:%" PRIu32 "b/%" PRIu32 ") net:%.2lf%% other:%.2lf%%",
							//(double)procinfo->m_proc_metrics.m_processing.m_time_ns,
							//(double)procinfo->m_proc_metrics.m_file.m_time_ns,
									procinfo->m_proc_metrics.get_processing_percentage() * 100,
									procinfo->m_proc_metrics.get_file_percentage() * 100,
									procinfo->m_proc_metrics.m_tot_io_file.m_bytes_in,
									procinfo->m_proc_metrics.m_tot_io_file.m_count_in,
									procinfo->m_proc_metrics.m_tot_io_file.m_bytes_out,
									procinfo->m_proc_metrics.m_tot_io_file.m_count_out,
									procinfo->m_proc_metrics.get_net_percentage() * 100,
							//(double)procinfo->m_proc_metrics.m_net.m_time_ns,
									procinfo->m_proc_metrics.get_other_percentage() * 100);
				}
			}
#endif
		}

		//
		// Update the host metrics with the info coming from this process
		//
		if(procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
		{
			m_host_req_metrics.add(&procinfo->m_proc_metrics);

			if(container)
			{
				container->m_req_metrics.add(&procinfo->m_proc_metrics);
			}
		}

		//
		// Note how we only include server processes.
		// That's because these are transaction time metrics, and therefore we don't
		// want to use processes that don't serve transactions.
		//
		m_host_metrics.add(procinfo);

		if(container)
		{
			container->m_metrics.add(procinfo);
		}
	}

	////////////////////////////////////////////////////////////////////////////
	// EMIT CONNECTIONS
	////////////////////////////////////////////////////////////////////////////
	// This code has been moved here because it needs the processes already
	// grouped by programs (to use the correct pid for connections) but also needs to
	// run before emit_containers, because it aggregates network connections by server port
	// per each container
	// WARNING: the following methods emit but also clear the metrics
	if(m_configuration->get_aggregate_connections_in_proto())
	{
		//
		// Aggregate external connections and limit the number of entries in the connection table
		//
		emit_aggregated_connections();
	}
	else
	{
		//
		// Emit all the connections
		//
		emit_full_connections();
	}


	// Filter and emit containers, we do it now because when filtering processes we add
	// at least one process for each container
	auto emitted_containers = emit_containers(progtable_by_container);
	bool progtable_needs_filtering = false;

	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "progtable size: %u", progtable.size());
	}

	//
	// Filter out the programs that didn't generate enough activity to go in the sample.
	// Note: we only do this when we're live, because in offline captures we don't have
	//       process CPU and memory.
	//
	if(!m_inspector->is_offline())
	{
		progtable_needs_filtering = progtable.size() > TOP_PROCESSES_IN_SAMPLE;
		if(progtable_needs_filtering)
		{
			// Filter top active programs
			filter_top_programs(progtable.begin(),
								progtable.end(),
								false,
								TOP_PROCESSES_IN_SAMPLE);
			// Filter top client/server programs
			filter_top_programs(progtable.begin(),
								progtable.end(),
								true,
								TOP_PROCESSES_IN_SAMPLE);
			// Add at least one process per emitted_container
			for(const auto& container_id : emitted_containers)
			{
				auto progs_it = progtable_by_container.find(container_id);
				if(progs_it != progtable_by_container.end())
				{
					auto progs = progs_it->second;
					filter_top_programs(progs.begin(), progs.end(), false, TOP_PROCESSES_PER_CONTAINER);
				}
			}
		}

		if(m_mounted_fs_proxy)
		{
			vector<sinsp_threadinfo*> containers_for_mounted_fs;
			for(auto it = progtable_by_container.begin(); it != progtable_by_container.end(); ++it)
			{
				sinsp_container_info container_info;
				m_inspector->m_container_manager.get_container(it->first, &container_info);
				if(container_info.m_name.find("k8s_POD") == std::string::npos)
				{
					auto long_running_proc = find_if(it->second.begin(), it->second.end(), [this](sinsp_threadinfo* tinfo)
					{
						return !(tinfo->m_flags & PPM_CL_CLOSED) && (m_next_flush_time_ns - tinfo->get_main_thread()->m_clone_ts) >= ASSUME_LONG_LIVING_PROCESS_UPTIME_S*ONE_SECOND_IN_NS;
					});
					if(long_running_proc != it->second.end())
					{
						containers_for_mounted_fs.push_back(*long_running_proc);
					}
				}
			}
			m_mounted_fs_proxy->send_container_list(containers_for_mounted_fs);
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// Second pass of the list of threads: aggregate threads into processes
	// or programs.
	///////////////////////////////////////////////////////////////////////////
	auto jmx_limit = m_configuration->get_jmx_limit();
	for(auto it = progtable.begin(); it != progtable.end(); ++it)
	{
		sinsp_threadinfo* tinfo = *it;

		//
		// If this is the main thread of a process, add an entry into the processes
		// section too
		//
		sinsp_procinfo* procinfo = tinfo->m_ainfo->m_procinfo;

#ifdef ANALYZER_EMITS_PROCESSES
		sinsp_counter_time tot;

		ASSERT(procinfo != NULL);

		procinfo->m_proc_metrics.get_total(&tot);
//		if(!m_inspector->m_islive)
//		{
//			ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);
//		}
		//
		// Inclusion logic
		//
		// Keep:
		//  - top 30 clients/servers
		//  - top 30 programs that were active

		if(!tinfo->m_ainfo->m_procinfo->m_exclude_from_sample || !progtable_needs_filtering)
		{
#ifdef ANALYZER_EMITS_PROGRAMS
			draiosproto::program* prog = m_metrics->add_programs();
			draiosproto::process* proc = prog->mutable_procinfo();

			//for(int64_t pid : procinfo->m_program_pids)
			//{
			//	prog->add_pids(pid);
			//}
			prog->add_pids(tinfo->m_pid);
#else // ANALYZER_EMITS_PROGRAMS
			draiosproto::process* proc = m_metrics->add_processes();
#endif // ANALYZER_EMITS_PROGRAMS

			//
			// Basic values
			//
			if((tinfo->m_flags & PPM_CL_NAME_CHANGED) ||
				(m_n_flushes % PROCINFO_IN_SAMPLE_INTERVAL == (PROCINFO_IN_SAMPLE_INTERVAL - 1)))
			{
				proc->mutable_details()->set_comm(tinfo->get_main_thread()->m_comm);
				proc->mutable_details()->set_exe(tinfo->get_main_thread()->m_exe);
				for(vector<string>::const_iterator arg_it = tinfo->get_main_thread()->m_args.begin();
					arg_it != tinfo->get_main_thread()->m_args.end(); ++arg_it)
				{
					if(*arg_it != "")
					{
						if (arg_it->size() <= ARG_SIZE_LIMIT)
						{
							proc->mutable_details()->add_args(*arg_it);
						}
						else
						{
							auto arg_capped = arg_it->substr(0, ARG_SIZE_LIMIT);
							proc->mutable_details()->add_args(arg_capped);
						}
					}
				}

				if(!tinfo->get_main_thread()->m_container_id.empty())
				{
					proc->mutable_details()->set_container_id(tinfo->get_main_thread()->m_container_id);
				}

				tinfo->m_flags &= ~PPM_CL_NAME_CHANGED;
			}

			//
			// client-server role
			//
			uint32_t netrole = 0;

			if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER)
			{
				netrole |= draiosproto::IS_REMOTE_IPV4_SERVER;
			}
			else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER)
			{
				netrole |= draiosproto::IS_LOCAL_IPV4_SERVER;
			}
			else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_SERVER)
			{
				netrole |= draiosproto::IS_UNIX_SERVER;
			}

			if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT)
			{
				netrole |= draiosproto::IS_REMOTE_IPV4_CLIENT;
			}
			else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT)
			{
				netrole |= draiosproto::IS_LOCAL_IPV4_CLIENT;
			}
			else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_CLIENT)
			{
				netrole |= draiosproto::IS_UNIX_CLIENT;
			}

			proc->set_netrole(netrole);

#ifndef _WIN32
			// Add JMX metrics
			if (m_jmx_proxy && jmx_limit > 0)
			{
				unsigned jmx_proc_limit = std::min(jmx_limit, JMX_METRICS_HARD_LIMIT_PER_PROC);
				auto jmx_metrics_it = m_jmx_metrics.end();
				for(auto pid_it = procinfo->m_program_pids.begin();
						pid_it != procinfo->m_program_pids.end() && jmx_metrics_it == m_jmx_metrics.end();
						++pid_it)
				{
					jmx_metrics_it = m_jmx_metrics.find(*pid_it);
				}
				if(jmx_metrics_it != m_jmx_metrics.end())
				{
					g_logger.format(sinsp_logger::SEV_DEBUG, "Found JMX metrics for pid %d", tinfo->m_pid);
					auto java_proto = proc->mutable_protos()->mutable_java();
					jmx_limit -= jmx_metrics_it->second.to_protobuf(java_proto, m_jmx_sampling, jmx_proc_limit);
					if(jmx_limit == 0)
					{
						g_logger.format(sinsp_logger::SEV_WARNING, "JMX metrics reached limit, remaining ones will be dropped");
					}
				}
			}
			if(m_app_proxy)
			{
				auto app_data_it = m_app_metrics.end();
				for(auto pid_it = procinfo->m_program_pids.begin();
					pid_it != procinfo->m_program_pids.end() && app_data_it == m_app_metrics.end();
					++pid_it)
				{
					app_data_it = m_app_metrics.find(*pid_it);
				}
				if(app_data_it != m_app_metrics.end())
				{
					g_logger.format(sinsp_logger::SEV_DEBUG, "Found app metrics for pid %d", tinfo->m_pid);
					app_checks_limit -= app_data_it->second.to_protobuf(proc->mutable_protos()->mutable_app(), app_checks_limit);
				}
			}
#endif

			//
			// CPU utilization
			//
			if(procinfo->m_cpuload >= 0)
			{
				if(procinfo->m_cpuload > (int32_t)(100 * m_machine_info->num_cpus))
				{
					procinfo->m_cpuload = (int32_t)100 * m_machine_info->num_cpus;
				}

				proc->mutable_resource_counters()->set_cpu_pct((uint32_t)(procinfo->m_cpuload * 100));
			}
			else
			{
				proc->mutable_resource_counters()->set_cpu_pct(0);
			}

			proc->mutable_resource_counters()->set_resident_memory_usage_kb(procinfo->m_vmrss_kb);
			proc->mutable_resource_counters()->set_virtual_memory_usage_kb(procinfo->m_vmsize_kb);
			proc->mutable_resource_counters()->set_swap_memory_usage_kb(procinfo->m_vmswap_kb);
			proc->mutable_resource_counters()->set_major_pagefaults(procinfo->m_pfmajor);
			proc->mutable_resource_counters()->set_minor_pagefaults(procinfo->m_pfminor);

			if(tot.m_count != 0)
			{
				sinsp_delays_info* prog_delays = &procinfo->m_transaction_delays;

				//
				// Main metrics

				procinfo->m_proc_metrics.to_protobuf(proc->mutable_tcounters(), m_sampling_ratio);

				//
				// Transaction-related metrics
				//
				if(prog_delays->m_local_processing_delay_ns != -1)
				{
					proc->set_transaction_processing_delay(prog_delays->m_local_processing_delay_ns * m_sampling_ratio);
					proc->set_next_tiers_delay(prog_delays->m_merged_client_delay * m_sampling_ratio);
				}

				procinfo->m_proc_transaction_metrics.to_protobuf(proc->mutable_transaction_counters(),
					proc->mutable_min_transaction_counters(),
					proc->mutable_max_transaction_counters(),
					m_sampling_ratio);

				proc->mutable_resource_counters()->set_capacity_score((uint32_t)(procinfo->m_capacity_score * 100));
				proc->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(procinfo->m_stolen_capacity_score * 100));
				proc->mutable_resource_counters()->set_connection_queue_usage_pct(procinfo->m_connection_queue_usage_pct);
				proc->mutable_resource_counters()->set_fd_usage_pct(procinfo->m_fd_usage_pct);
				proc->mutable_resource_counters()->set_fd_count(procinfo->m_fd_count);

				//
				// Error-related metrics
				//
				procinfo->m_syscall_errors.to_protobuf(proc->mutable_syscall_errors(), m_sampling_ratio);

				//
				// Protocol tables
				//
//					procinfo->m_protostate.to_protobuf(proc->mutable_protos(),
//						m_sampling_ratio);
				proc->set_start_count(procinfo->m_start_count);
				proc->set_count_processes(procinfo->m_proc_count);
			}
#endif // ANALYZER_EMITS_PROCESSES
		}
		//
		// Clear the thread metrics, so we're ready for the next sample
		//
		tinfo->m_ainfo->clear_all_metrics();
	}

	if(app_checks_limit == 0)
	{
		g_logger.log("App checks metrics limit reached", sinsp_logger::SEV_WARNING);
	}

	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		m_old_global_total_jiffies = cur_global_total_jiffies;
	}

#ifndef _WIN32
	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		if(m_jmx_proxy && is_jmx_flushtime() && !java_process_requests.empty())
		{
			m_jmx_proxy->send_get_metrics(java_process_requests);
		}
		if(m_app_proxy && !app_checks_processes.empty())
		{
			m_app_proxy->send_get_metrics_cmd(app_checks_processes);
		}
	}
#endif
}

void sinsp_analyzer::flush_processes()
{
	for(vector<sinsp_threadinfo*>::const_iterator it = m_threads_to_remove.begin();
		it != m_threads_to_remove.end(); ++it)
	{
		m_inspector->m_thread_manager->remove_thread((*it)->m_tid, false);
	}

	m_threads_to_remove.clear();
}

bool conn_cmp_bytes(pair<const process_tuple*, sinsp_connection*>& src,
					pair<const process_tuple*, sinsp_connection*>& dst)
{
	uint64_t s = src.second->m_metrics.m_client.m_bytes_in +
		src.second->m_metrics.m_client.m_bytes_out +
		src.second->m_metrics.m_server.m_bytes_in +
		src.second->m_metrics.m_server.m_bytes_out;

	uint64_t d = dst.second->m_metrics.m_client.m_bytes_in +
		dst.second->m_metrics.m_client.m_bytes_out +
		dst.second->m_metrics.m_server.m_bytes_in +
		dst.second->m_metrics.m_server.m_bytes_out;

	return (s > d);
}

bool conn_cmp_n_aggregated_connections(pair<const process_tuple*, sinsp_connection*>& src,
					pair<const process_tuple*, sinsp_connection*>& dst)
{
	uint64_t s = src.second->m_timestamp;
	uint64_t d = dst.second->m_timestamp;

	return (s > d);
}

//
// Strategy:
//  - sport is *always* masked to zero
//  - if there are more than MAX_N_EXTERNAL_CLIENTS external client connections,
//    external client IPs are masked to zero
//
void sinsp_analyzer::emit_aggregated_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
	process_tuple tuple;
	bool aggregate_external_clients = false;
	set<uint32_t> unique_external_ips;

	m_reduced_ipv4_connections->clear();
	unordered_map<uint16_t, sinsp_connection_aggregator> connections_by_serverport;

	//
	// First partial pass to determine if external connections need to be coalesced
	//
	for(cit = m_ipv4_connections->m_connections.begin();
		cit != m_ipv4_connections->m_connections.end();
		++cit)
	{
		if(cit->second.is_server_only())
		{
			uint32_t sip = cit->first.m_fields.m_sip;

			if(!m_inspector->m_network_interfaces->is_ipv4addr_in_subnet(sip))
			{
				unique_external_ips.insert(sip);

				if(unique_external_ips.size() > MAX_N_EXTERNAL_CLIENTS)
				{
					aggregate_external_clients = true;
					break;
				}
			}
		}
	}

	//
	// Second pass to perform the aggegation
	//
	for(cit = m_ipv4_connections->m_connections.begin();
		cit != m_ipv4_connections->m_connections.end();)
	{
		//
		// Find the main program pids
		//
		int64_t prog_spid = 0;
		int64_t prog_dpid = 0;
		string prog_scontainerid;
		string prog_dcontainerid;

		if(cit->second.m_spid != 0)
		{
			auto tinfo = m_inspector->get_thread(cit->second.m_spid, false, true);
			if(tinfo == NULL)
			{
				//
				// No thread info for this connection?
				//
				++cit;
				continue;
			}

			prog_spid = tinfo->m_ainfo->m_main_thread_pid;
			prog_scontainerid = tinfo->m_container_id;
		}

		if(cit->second.m_dpid != 0)
		{
			auto tinfo = m_inspector->get_thread(cit->second.m_dpid, false, true);
			if(tinfo == NULL)
			{
				//
				// No thread info for this connection?
				//
				++cit;
				continue;
			}

			prog_dpid = tinfo->m_ainfo->m_main_thread_pid;
			prog_dcontainerid = tinfo->m_container_id;
		}

		tuple.m_fields.m_spid = prog_spid;
		tuple.m_fields.m_dpid = prog_dpid;
		tuple.m_fields.m_sip = cit->first.m_fields.m_sip;
		tuple.m_fields.m_dip = cit->first.m_fields.m_dip;
		tuple.m_fields.m_sport = 0;
		tuple.m_fields.m_dport = cit->first.m_fields.m_dport;
		tuple.m_fields.m_l4proto = cit->first.m_fields.m_l4proto;

		if(tuple.m_fields.m_sip != 0 && tuple.m_fields.m_dip != 0)
		{
			if(!cit->second.is_client_and_server())
			{
				if(cit->second.is_server_only())
				{
					//
					// If external client aggregation is enabled, this is a server connection, and
					// the client address is outside the subnet, mask it so it gets aggregated
					//
					if(aggregate_external_clients)
					{
						if(!m_inspector->m_network_interfaces->is_ipv4addr_in_subnet(cit->first.m_fields.m_sip))
						{
							tuple.m_fields.m_sip = 0;
						}
					}

					//
					// Add this connection's bytes to the host network volume
					//
					m_io_net.add_in(cit->second.m_metrics.m_server.m_count_in, 0, cit->second.m_metrics.m_server.m_bytes_in);
					m_io_net.add_out(cit->second.m_metrics.m_server.m_count_out, 0, cit->second.m_metrics.m_server.m_bytes_out);
				}
				else
				{
					//
					// Add this connection's bytes to the host network volume
					//
					ASSERT(cit->second.is_client_only())
					m_io_net.add_in(cit->second.m_metrics.m_client.m_count_in, 0, cit->second.m_metrics.m_client.m_bytes_in);
					m_io_net.add_out(cit->second.m_metrics.m_client.m_count_out, 0, cit->second.m_metrics.m_client.m_bytes_out);
				}
			}

			//
			// Look for the entry in the reduced connection table.
			// Note: we don't export connections whose sip or dip is zero.
			//
			sinsp_connection& conn = (*m_reduced_ipv4_connections)[tuple];

			if(conn.m_timestamp == 0)
			{
				//
				// New entry.
				// Structure copy the connection info.
				//
				conn = cit->second;
				conn.m_timestamp = 1;
			}
			else
			{
				//
				// Existing entry.
				// Add this connection's metrics to the aggregated connection's ones.
				//
				conn.m_metrics.add(&cit->second.m_metrics);
				conn.m_transaction_metrics.add(&cit->second.m_transaction_metrics);
				conn.m_timestamp++;
			}

			// same thing by server port per host
			connections_by_serverport[tuple.m_fields.m_dport].add(&cit->second);

			// same thing by server port per container
			if(!prog_scontainerid.empty() && prog_scontainerid == prog_dcontainerid)
			{
				auto &conn_aggr = (*m_containers[prog_scontainerid].m_connections_by_serverport)[tuple.m_fields.m_dport];
				conn_aggr.add(&cit->second);
			}
			else
			{
				if(!prog_scontainerid.empty())
				{
					auto &conn_aggr = (*m_containers[prog_scontainerid].m_connections_by_serverport)[tuple.m_fields.m_dport];
					conn_aggr.add_client(&cit->second);
				}
				if(!prog_dcontainerid.empty())
				{
					auto &conn_aggr = (*m_containers[prog_dcontainerid].m_connections_by_serverport)[tuple.m_fields.m_dport];
					conn_aggr.add_server(&cit->second);
				}
			}
		}
		//
		// Has this connection been closed druring this sample?
		//
		if(cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_ipv4_connections->m_connections.erase(cit++);
		}
		else
		{
			//
			// Clear the transaction metrics, so we're ready for the next sample
			//
			cit->second.clear();
			++cit;
		}
	}

	sinsp_connection_aggregator::filter_and_emit(connections_by_serverport, m_metrics->mutable_hostinfo(), TOP_SERVER_PORTS_IN_SAMPLE, m_sampling_ratio);

	//
	// If the table is still too big, sort it and pick only the top connections
	//
	vector<pair<const process_tuple*, sinsp_connection*>> sortable_conns;
	pair<const process_tuple*, sinsp_connection*> sortable_conns_entry;
	unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp> reduced_and_filtered_ipv4_connections;
	auto connection_to_emit = m_reduced_ipv4_connections;

	if(m_reduced_ipv4_connections->size() > TOP_CONNECTIONS_IN_SAMPLE)
	{
		//
		// Prepare the sortable list
		//
		for(auto sit = m_reduced_ipv4_connections->begin();
			sit != m_reduced_ipv4_connections->end(); ++sit)
		{
			sortable_conns_entry.first = &(sit->first);
			sortable_conns_entry.second = &(sit->second);

			sortable_conns.push_back(sortable_conns_entry);
		}

		//
		// Sort by number of sub-connections and pick the TOP_CONNECTIONS_IN_SAMPLE
		// connections
		//
		partial_sort(sortable_conns.begin(),
			sortable_conns.begin() + TOP_CONNECTIONS_IN_SAMPLE,
			sortable_conns.end(),
			conn_cmp_n_aggregated_connections);

		for(uint32_t j = 0; j < TOP_CONNECTIONS_IN_SAMPLE; j++)
		{
			//process_tuple* pt = (process_tuple*)sortable_conns[j].first;

			reduced_and_filtered_ipv4_connections[*(sortable_conns[j].first)] =
				*(sortable_conns[j].second);
		}

		//
		// Sort by total bytes and pick the TOP_CONNECTIONS_IN_SAMPLE connections
		//
		partial_sort(sortable_conns.begin(),
			sortable_conns.begin() + TOP_CONNECTIONS_IN_SAMPLE,
			sortable_conns.end(),
			conn_cmp_bytes);

		for(uint32_t j = 0; j < TOP_CONNECTIONS_IN_SAMPLE; j++)
		{
			reduced_and_filtered_ipv4_connections[*(sortable_conns[j].first)] =
				*(sortable_conns[j].second);
		}

		connection_to_emit = &reduced_and_filtered_ipv4_connections;
	}

	//
	// Emit the aggregated table into the sample
	//
	unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp>::iterator acit;
	for(acit = connection_to_emit->begin();
		acit != connection_to_emit->end(); ++acit)
	{
		//
		// Skip connection that had no activity during the sample
		//
		if(!acit->second.is_active())
		{
			continue;
		}

		//
		// Add the connection to the protobuf
		//
		draiosproto::ipv4_connection* conn = m_metrics->add_ipv4_connections();
		draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

		tuple->set_sip(htonl(acit->first.m_fields.m_sip));
		tuple->set_dip(htonl(acit->first.m_fields.m_dip));
		tuple->set_sport(acit->first.m_fields.m_sport);
		tuple->set_dport(acit->first.m_fields.m_dport);
		tuple->set_l4proto(acit->first.m_fields.m_l4proto);

		conn->set_spid(acit->first.m_fields.m_spid);
		conn->set_dpid(acit->first.m_fields.m_dpid);

		acit->second.m_metrics.to_protobuf(conn->mutable_counters(), m_sampling_ratio);
		acit->second.m_transaction_metrics.to_protobuf(conn->mutable_counters()->mutable_transaction_counters(),
			conn->mutable_counters()->mutable_min_transaction_counters(),
			conn->mutable_counters()->mutable_max_transaction_counters(),
			m_sampling_ratio);

		//
		// The timestamp field is used to count the number of sub-connections
		//
		conn->mutable_counters()->set_n_aggregated_connections((uint32_t)acit->second.m_timestamp);
	}
}

void sinsp_analyzer::emit_full_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;

	for(cit = m_ipv4_connections->m_connections.begin();
		cit != m_ipv4_connections->m_connections.end();)
	{
		//
		// We only include connections that had activity during the sample
		//
		if(cit->second.is_active())
		{
			draiosproto::ipv4_connection* conn = m_metrics->add_ipv4_connections();
			draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

			tuple->set_sip(htonl(cit->first.m_fields.m_sip));
			tuple->set_dip(htonl(cit->first.m_fields.m_dip));
			tuple->set_sport(cit->first.m_fields.m_sport);
			tuple->set_dport(cit->first.m_fields.m_dport);
			tuple->set_l4proto(cit->first.m_fields.m_l4proto);

			conn->set_spid(cit->second.m_spid);
			conn->set_dpid(cit->second.m_dpid);

			cit->second.m_metrics.to_protobuf(conn->mutable_counters(), m_sampling_ratio);
			cit->second.m_transaction_metrics.to_protobuf(conn->mutable_counters()->mutable_transaction_counters(),
				conn->mutable_counters()->mutable_min_transaction_counters(),
				conn->mutable_counters()->mutable_max_transaction_counters(),
				m_sampling_ratio);
		}

		//
		// Add this connection's bytes to the host network volume
		//
		if(!cit->second.is_client_and_server())
		{
			if(cit->second.is_server_only())
			{
				m_io_net.add_in(cit->second.m_metrics.m_server.m_count_in, 0, cit->second.m_metrics.m_server.m_bytes_in);
				m_io_net.add_out(cit->second.m_metrics.m_server.m_count_out, 0, cit->second.m_metrics.m_server.m_bytes_out);
			}
			else
			{
				ASSERT(cit->second.is_client_only())
				m_io_net.add_in(cit->second.m_metrics.m_client.m_count_in, 0, cit->second.m_metrics.m_client.m_bytes_in);
				m_io_net.add_out(cit->second.m_metrics.m_client.m_count_out, 0, cit->second.m_metrics.m_client.m_bytes_out);
			}
		}

		//
		// Has this connection been closed druring this sample?
		//
		if(cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_ipv4_connections->m_connections.erase(cit++);
		}
		else
		{
			//
			// Clear the transaction metrics, so we're ready for the next sample
			//
			cit->second.clear();
			++cit;
		}
	}
}

void sinsp_analyzer::tune_drop_mode(flush_flags flshflags, double threshold_metric)
{
	//
	// Drop mode logic:
	// if we stay above DROP_UPPER_THRESHOLD for DROP_THRESHOLD_CONSECUTIVE_SECONDS, we increase the sampling,
	// if we stay above DROP_LOWER_THRESHOLD for DROP_THRESHOLD_CONSECUTIVE_SECONDS, we decrease the sampling,
	//
	uint32_t j;

	if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		if(threshold_metric >= (double)m_configuration->get_drop_upper_threshold(m_machine_info->num_cpus))
		{
			m_seconds_above_thresholds++;

			g_logger.format(sinsp_logger::SEV_INFO, "sinsp above drop threshold %d secs: %" PRIu32 ":%" PRIu32,
				(int)m_configuration->get_drop_upper_threshold(m_machine_info->num_cpus), m_seconds_above_thresholds,
				m_configuration->get_drop_threshold_consecutive_seconds());
		}
		else
		{
			m_seconds_above_thresholds = 0;
		}

		if(m_seconds_above_thresholds >= m_configuration->get_drop_threshold_consecutive_seconds())
		{
			m_last_system_cpuload = 0;

			for(j = 0; j < m_proc_stat.m_loads.size(); j++)
			{
				m_last_system_cpuload += m_proc_stat.m_loads[j];
			}

			m_seconds_above_thresholds = 0;

			if(m_sampling_ratio < 128)
			{
				if(!m_is_sampling)
				{
					m_new_sampling_ratio = 1;
					m_is_sampling = true;
				}
				else
				{
					m_new_sampling_ratio = m_sampling_ratio * 2;
				}

				if(m_new_sampling_ratio == 2)
				{
					g_logger.format(sinsp_logger::SEV_WARNING, "disabling falco baseliling");
					m_do_baseline_calculation = false;
					m_falco_baseliner->clear_tables();
				}

				start_dropping_mode(m_new_sampling_ratio);
			}
			else
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "sinsp Reached maximum sampling ratio and still too high");
			}
		}

		if(threshold_metric <= (double)m_configuration->get_drop_lower_threshold(m_machine_info->num_cpus))
		{
			m_seconds_below_thresholds++;

			if(m_is_sampling && m_sampling_ratio > 1)
			{
				g_logger.format(sinsp_logger::SEV_INFO, "sinsp below drop threshold %d secs: %" PRIu32 ":%" PRIu32,
					(int)m_configuration->get_drop_lower_threshold(m_machine_info->num_cpus), m_seconds_below_thresholds,
					m_configuration->get_drop_threshold_consecutive_seconds());
			}
		}
		else
		{
			m_seconds_below_thresholds = 0;
		}

		if(m_seconds_below_thresholds >= m_configuration->get_drop_threshold_consecutive_seconds() &&
			m_is_sampling)
		{
			double totcpuload = 0;
			bool skip = false;

			for(j = 0; j < m_proc_stat.m_loads.size(); j++)
			{
				totcpuload += m_proc_stat.m_loads[j];
			}

			if(m_last_system_cpuload != 0)
			{
				if(fabs(totcpuload - m_last_system_cpuload) / min(totcpuload, m_last_system_cpuload) < 0.15)
				{
					if(m_seconds_below_thresholds <= m_configuration->get_drop_threshold_consecutive_seconds() * 50)
					{
						skip = true;
					}
				}
			}

			if(!skip)
			{
				m_last_system_cpuload = 0;

				m_seconds_below_thresholds = 0;
				m_new_sampling_ratio = m_sampling_ratio / 2;

				if(m_new_sampling_ratio >= 1)
				{
					if(m_is_sampling)
					{
						g_logger.format(sinsp_logger::SEV_INFO, "sinsp -- Setting drop mode to %" PRIu32, m_new_sampling_ratio);
						start_dropping_mode(m_new_sampling_ratio);
					}
					else
					{
						ASSERT(m_new_sampling_ratio == 1);
						stop_dropping_mode();
					}
				}
			}
		}
	}
}

bool executed_command_cmp(const sinsp_executed_command& src, const sinsp_executed_command& dst)
{
	return (src.m_ts < dst.m_ts);
}

void sinsp_analyzer::emit_executed_commands()
{
	uint32_t j;
	int32_t last_pipe_head = -1;

	if(m_executed_commands.size() != 0)
	{
		sort(m_executed_commands.begin(),
			m_executed_commands.end(),
			executed_command_cmp);

		//
		// Consolidate command with pipes
		//
		for(j = 0; j < m_executed_commands.size(); j++)
		{
			uint32_t flags = m_executed_commands[j].m_flags;

			if(flags & sinsp_executed_command::FL_PIPE_HEAD)
			{
				last_pipe_head = j;
			}
			else if(flags & (sinsp_executed_command::FL_PIPE_MIDDLE | sinsp_executed_command::FL_PIPE_TAIL))
			{
				if(last_pipe_head != -1)
				{
					m_executed_commands[last_pipe_head].m_cmdline += " | ";
					m_executed_commands[last_pipe_head].m_cmdline += m_executed_commands[j].m_cmdline;
					m_executed_commands[j].m_flags |= sinsp_executed_command::FL_EXCLUDED;
				}
				else
				{
//					ASSERT(false);
				}

				if(flags & sinsp_executed_command::FL_PIPE_TAIL)
				{
					last_pipe_head = -1;
				}
			}
		}

		//
		// If there are too many commands, try to aggregate by command line
		//
		uint32_t cmdcnt = 0;

		vector<sinsp_executed_command>::iterator it;

		for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
		{
			if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;
			}
		}

		if(cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
		{
			map<string, sinsp_executed_command*> cmdlines;

			for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
			{
				if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
				{
					map<string, sinsp_executed_command*>::iterator eit = cmdlines.find(it->m_cmdline);
					if(eit == cmdlines.end())
					{
						cmdlines[it->m_cmdline] = &(*it);
					}
					else
					{
						eit->second->m_count++;
						it->m_flags |= sinsp_executed_command::FL_EXCLUDED;
					}
				}
			}
		}

		//
		// If there are STILL too many commands, try to aggregate by executable
		//
		cmdcnt = 0;

		for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
		{
			if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;
			}
		}

		if(cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
		{
			map<string, sinsp_executed_command*> exes;

			for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
			{
				if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
				{
					map<string, sinsp_executed_command*>::iterator eit = exes.find(it->m_exe);
					if(eit == exes.end())
					{
						exes[it->m_exe] = &(*it);
						it->m_flags |= sinsp_executed_command::FL_EXEONLY;
					}
					else
					{
						eit->second->m_count += it->m_count;
						it->m_flags |= sinsp_executed_command::FL_EXCLUDED;
					}
				}
			}
		}

		cmdcnt = 0;
		for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
		{
			if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;

				if(cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
				{
					break;
				}

				draiosproto::command_details* cd = m_metrics->add_commands();

				cd->set_timestamp(it->m_ts);
				cd->set_exe(it->m_exe);
				if(it->m_parent_comm != "")
				{
					cd->set_parentcomm(it->m_parent_comm);
				}
				cd->set_count(it->m_count);

				if(it->m_flags & sinsp_executed_command::FL_EXEONLY)
				{
					cd->set_cmdline(it->m_comm);
				}
				else
				{
					cd->set_cmdline(it->m_cmdline);
				}
			}
		}
	}
}

void sinsp_analyzer::flush(sinsp_evt* evt, uint64_t ts, bool is_eof, flush_flags flshflags)
{
	m_cputime_analyzer.begin_flush();
	//g_logger.format(sinsp_logger::SEV_INFO, "Called flush with ts=%lu is_eof=%s flshflags=%d", ts, is_eof? "true" : "false", flshflags);
	uint32_t j;
	uint64_t nevts_in_last_sample;
	uint64_t flush_start_ns = sinsp_utils::get_current_time_ns();

	//
	// Skip the events if the analyzer has not been initialized yet
	//
	if(!m_initialized)
	{
		return;
	}
	
	if(evt != NULL)
	{
		nevts_in_last_sample = evt->get_num() - m_prev_sample_evtnum;
	}
	else
	{
		nevts_in_last_sample = 0;
	}

	if(flshflags == DF_FORCE_NOFLUSH)
	{
		return;
	}

	for(j = 0; ; j++)
	{
		if(flshflags == DF_FORCE_FLUSH ||
			flshflags == DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			//
			// Make sure we don't generate too many samples in case of subsampling
			//
			if(j > 0)
			{
				break;
			}
		}
		else
		{
			if(m_next_flush_time_ns > ts)
			{
				break;
			}
		}

		uint64_t sample_duration = m_configuration->get_analyzer_sample_len_ns();

		if(m_next_flush_time_ns == 0)
		{
			//
			// This is the very first event, just initialize the times for future use
			//
			m_next_flush_time_ns = ts - ts % sample_duration + sample_duration;
			m_prev_flush_time_ns = m_next_flush_time_ns - sample_duration;
		}
		else
		{
			m_n_flushes++;

			//
			// Update the times
			//
			m_prev_flush_time_ns = ts - ts % sample_duration;
			m_next_flush_time_ns = m_prev_flush_time_ns + sample_duration;

			ASSERT(m_next_flush_time_ns / sample_duration * sample_duration == m_next_flush_time_ns);
			ASSERT(m_prev_flush_time_ns / sample_duration * sample_duration == m_prev_flush_time_ns);


			if(m_inspector->m_mode == SCAP_MODE_NODRIVER &&
				m_prev_flush_time_ns - m_last_proclist_refresh > NODRIVER_PROCLIST_REFRESH_INTERVAL_NS)
			{
				g_logger.log("Refreshing proclist", sinsp_logger::SEV_DEBUG);
				m_inspector->refresh_proc_list();
				m_last_proclist_refresh = m_prev_flush_time_ns;
			}

			//
			// Run the periodic connection and thread table cleanup
			// This is run on every sample for NODRIVER mode
			// by forcing interval to 0
			//
			remove_expired_connections(ts);
			m_inspector->remove_inactive_threads();
			m_inspector->m_container_manager.remove_inactive_containers();

			//
			// Calculate CPU load
			//
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				//
				// Make sure that there's been enough time since the previous call to justify getting
				// CPU info from proc
				//
				uint64_t wall_time = sinsp_utils::get_current_time_ns();

				if((int64_t)(wall_time - m_prev_flush_wall_time) < 500000000 || m_inspector->is_offline())
				{
					if(!m_inspector->is_offline())
					{
						g_logger.format(sinsp_logger::SEV_ERROR,
							"sample emission too fast (%" PRId64 "), skipping scanning proc",
							(int64_t)(wall_time - m_prev_flush_wall_time));
					}

					m_skip_proc_parsing = true;
				}
				else
				{
					m_prev_flush_wall_time = wall_time;
					m_skip_proc_parsing = false;
					m_procfs_parser->get_proc_stat(&m_proc_stat);
				}
			}

			m_total_process_cpu = 0; // this will be calculated when scanning the processes

			//
			// Flush the scheduler analyzer
			//
			if(m_inspector->m_thread_manager->get_thread_count() < DROP_SCHED_ANALYZER_THRESHOLD)
			{
				m_sched_analyzer2->flush(evt, m_prev_flush_time_ns, is_eof, flshflags);
			}

			//
			// Reset the protobuffer
			//
			m_metrics->Clear();

			if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT && !m_inspector->is_offline())
			{
				get_statsd();
				if(m_mounted_fs_proxy)
				{
					// Get last filesystem stats, list of containers is sent on emit_processes
					auto new_fs_map = m_mounted_fs_proxy->receive_mounted_fs_list();
					if(!new_fs_map.empty())
					{
						m_mounted_fs_map = move(new_fs_map);
					}
				}
			}

			////////////////////////////////////////////////////////////////////////////
			// EMIT PROCESSES
			////////////////////////////////////////////////////////////////////////////
			emit_processes(evt, sample_duration, is_eof, flshflags);

			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"IPv4 table size:%d",
					m_ipv4_connections->m_connections.size());

				if(m_ipv4_connections->get_n_drops() != 0)
				{
					g_logger.format(sinsp_logger::SEV_ERROR,
						"IPv4 table drops:%d",
						m_ipv4_connections->get_n_drops());

					m_ipv4_connections->clear_n_drops();
				}
			}

			//
			// Go though the list of unix connections and for the moment just clean it up
			//
#ifdef HAS_UNIX_CONNECTIONS
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"unix table size:%d",
					m_unix_connections->m_connections.size());

				if(m_unix_connections->get_n_drops() != 0)
				{
					g_logger.format(sinsp_logger::SEV_ERROR,
						"IPv4 table size:%d",
						m_unix_connections->m_connections.size());

					m_unix_connections->clear_n_drops();
				}
			}

			unordered_map<unix_tuple, sinsp_connection, unixt_hash, unixt_cmp>::iterator ucit;
			for(ucit = m_unix_connections->m_connections.begin();
				ucit != m_unix_connections->m_connections.end();)
			{
				//
				// Has this connection been closed druring this sample?
				//
				if(ucit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					//
					// Yes, remove the connection from the table
					//
					m_unix_connections->m_connections.erase(ucit++);
				}
				else
				{
					++ucit;
				}
			}
#endif // HAS_UNIX_CONNECTIONS

#ifdef HAS_PIPE_CONNECTIONS
			//
			// Go though the list of pipe connections and for the moment just clean it up
			//
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"pipe table size:%d",
					m_pipe_connections->m_connections.size());
			}

			unordered_map<uint64_t, sinsp_connection, hash<uint64_t>, equal_to<uint64_t>>::iterator pcit;
			for(pcit = m_pipe_connections->m_connections.begin();
				pcit != m_pipe_connections->m_connections.end();)
			{
				//
				// Has this connection been closed druring this sample?
				//
				if(pcit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					//
					// Yes, remove the connection from the table
					//
					m_pipe_connections->m_connections.erase(pcit++);
				}
				else
				{
					++pcit;
				}
			}
#endif // HAS_PIPE_CONNECTIONS

			flush_processes();

			////////////////////////////////////////////////////////////////////////////
			// EMIT THE LIST OF INTERFACES
			////////////////////////////////////////////////////////////////////////////
			vector<sinsp_ipv4_ifinfo>* v4iflist = m_inspector->m_network_interfaces->get_ipv4_list();
			for(uint32_t k = 0; k < v4iflist->size(); k++)
			{
				draiosproto::ipv4_network_interface* ni = m_metrics->add_ipv4_network_interfaces();

				ni->set_name(v4iflist->at(k).m_name);
				ni->set_addr(htonl(v4iflist->at(k).m_addr));
				ni->set_netmask(htonl(v4iflist->at(k).m_netmask));
			}

			////////////////////////////////////////////////////////////////////////////
			// emit host stuff
			////////////////////////////////////////////////////////////////////////////
			m_metrics->set_machine_id(m_configuration->get_machine_id());
			m_metrics->set_customer_id(m_configuration->get_customer_id());
			m_metrics->set_timestamp_ns(m_prev_flush_time_ns);
			m_metrics->set_sampling_ratio(m_sampling_ratio);

			m_metrics->mutable_hostinfo()->set_hostname(sinsp_gethostname());
			m_metrics->mutable_hostinfo()->set_num_cpus(m_machine_info->num_cpus);
			m_metrics->mutable_hostinfo()->set_physical_memory_size_bytes(m_inspector->m_machine_info->memory_size_bytes);

			//
			// Map customizations coming from the analyzer.
			//
			m_metrics->set_host_custom_name(m_configuration->get_host_custom_name());
			m_metrics->set_host_tags(m_configuration->get_host_tags());
			m_metrics->set_is_host_hidden(m_configuration->get_host_hidden());
			m_metrics->set_hidden_processes(m_configuration->get_hidden_processes());
			m_metrics->set_version(m_configuration->get_version());
			if(!m_configuration->get_instance_id().empty())
			{
				m_metrics->set_instance_id(m_configuration->get_instance_id());
			}

			ASSERT(m_proc_stat.m_loads.size() == 0 || m_proc_stat.m_loads.size() == m_machine_info->num_cpus);
			ASSERT(m_proc_stat.m_loads.size() == m_proc_stat.m_steals.size());
			string cpustr;

			double totcpuload = 0;
			double totcpusteal = 0;

			for(uint32_t k = 0; k < m_proc_stat.m_loads.size(); k++)
			{
				cpustr += to_string((long double) m_proc_stat.m_loads[k]) + "(" + to_string((long double) m_proc_stat.m_steals[k]) + ") ";
				m_metrics->mutable_hostinfo()->add_cpu_loads((uint32_t)(m_proc_stat.m_loads[k] * 100));
				m_metrics->mutable_hostinfo()->add_cpu_steal((uint32_t)(m_proc_stat.m_steals[k] * 100));
				m_metrics->mutable_hostinfo()->add_cpu_idle((uint32_t)(m_proc_stat.m_idle[k] * 100));
				m_metrics->mutable_hostinfo()->add_user_cpu((uint32_t)(m_proc_stat.m_user[k] * 100));
				m_metrics->mutable_hostinfo()->add_nice_cpu((uint32_t)(m_proc_stat.m_nice[k] * 100));
				m_metrics->mutable_hostinfo()->add_system_cpu((uint32_t)(m_proc_stat.m_system[k] * 100));
				m_metrics->mutable_hostinfo()->add_iowait_cpu((uint32_t)(m_proc_stat.m_iowait[k] * 100));

				totcpuload += m_proc_stat.m_loads[k];
				totcpusteal += m_proc_stat.m_steals[k];
			}

			m_metrics->mutable_hostinfo()->set_uptime(m_proc_stat.m_uptime);

			ASSERT(totcpuload <= 100 * m_proc_stat.m_loads.size());
			ASSERT(totcpusteal <= 100 * m_proc_stat.m_loads.size());

			if(totcpuload < m_total_process_cpu)
			{
				totcpuload = m_total_process_cpu;
			}
			double loadavg[3] = {0};
			if(getloadavg(loadavg, 3) != -1)
			{
				m_metrics->mutable_hostinfo()->set_system_load_1(loadavg[0] * 100);
				m_metrics->mutable_hostinfo()->set_system_load_5(loadavg[1] * 100);
				m_metrics->mutable_hostinfo()->set_system_load_15(loadavg[2] * 100);
			}
			else
			{
				g_logger.log("Could not obtain load averages", sinsp_logger::SEV_WARNING);
			}

			if(m_proc_stat.m_loads.size() != 0)
			{
				if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG, "CPU:%s", cpustr.c_str());
				}
			}

			m_procfs_parser->get_global_mem_usage_kb(&m_host_metrics.m_res_memory_used_kb,
													 &m_host_metrics.m_res_memory_free_kb,
													 &m_host_metrics.m_res_memory_avail_kb,
													 &m_host_metrics.m_swap_memory_used_kb,
													 &m_host_metrics.m_swap_memory_total_kb,
													 &m_host_metrics.m_swap_memory_avail_kb);

			if(m_protocols_enabled)
			{
				sinsp_protostate_marker host_marker;
				host_marker.add(m_host_metrics.m_protostate);
				host_marker.mark_top(HOST_PROTOS_LIMIT);
				m_host_metrics.m_protostate->to_protobuf(m_metrics->mutable_protos(),
						m_sampling_ratio, HOST_PROTOS_LIMIT);
			}

			//
			// host info
			//
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_capacity_score((uint32_t)(m_host_metrics.get_capacity_score() * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(m_host_metrics.get_stolen_score() * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_connection_queue_usage_pct(m_host_metrics.m_connection_queue_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_usage_pct(m_host_metrics.m_fd_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_resident_memory_usage_kb((uint32_t)m_host_metrics.m_res_memory_used_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_swap_memory_usage_kb((uint32_t)m_host_metrics.m_swap_memory_used_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_swap_memory_total_kb((uint32_t)m_host_metrics.m_swap_memory_total_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_swap_memory_available_kb(m_host_metrics.m_swap_memory_avail_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_major_pagefaults(m_host_metrics.m_pfmajor);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_minor_pagefaults(m_host_metrics.m_pfminor);
			m_host_metrics.m_syscall_errors.to_protobuf(m_metrics->mutable_hostinfo()->mutable_syscall_errors(), m_sampling_ratio);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_count(m_host_metrics.m_fd_count);
			m_metrics->mutable_hostinfo()->set_memory_bytes_available_kb(m_host_metrics.m_res_memory_avail_kb);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_count_processes(m_host_metrics.get_process_count());
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_proc_start_count(m_host_metrics.get_process_start_count());

			if(m_mounted_fs_proxy)
			{
				auto fs_list = m_mounted_fs_map.find("host");
				if(fs_list != m_mounted_fs_map.end())
				{
					for(auto it = fs_list->second.begin(); it != fs_list->second.end(); ++it)
					{
						draiosproto::mounted_fs* fs = m_metrics->add_mounts();
						it->to_protobuf(fs);
					}
				}
			}
			else if(!m_inspector->is_offline()) // When not live, fs stats break regression tests causing false positives
			{
				auto fs_list = m_procfs_parser->get_mounted_fs_list(m_remotefs_enabled);
				for(auto it = fs_list.begin(); it != fs_list.end(); ++it)
				{
					draiosproto::mounted_fs* fs = m_metrics->add_mounts();
					it->to_protobuf(fs);
				}
			}
			//
			// Executed commands
			//
			//emit_executed_commands();

			//
			// Kubernetes
			//
			emit_k8s();

			//
			// Mesos
			//
			emit_mesos();

			//
			// Docker
			//
			m_has_docker = Poco::File(docker::get_socket_file()).exists();
			static bool first_time = true;
			if(!m_has_docker)
			{
				if(first_time)
				{
					g_logger.log("Docker service not running, events will not be available.", sinsp_logger::SEV_INFO);
				}
				first_time = false;
			}
			else if(m_configuration->get_docker_event_filter())
			{
				emit_docker_events();
			}

			emit_top_files();

			//
			// Statsd metrics
			//
#ifndef _WIN32
			if(m_statsd_metrics.find("") != m_statsd_metrics.end())
			{
				emit_statsd(m_statsd_metrics.at(""), m_metrics->mutable_protos()->mutable_statsd(), m_configuration->get_statsd_limit());
			}
#endif

			//
			// Metrics coming from chisels
			//
			emit_chisel_metrics();

			//
			// User-configured events
			//
			emit_user_events();

			//
			// Transactions
			//
			m_delay_calculator->compute_host_container_delays(&m_host_transaction_counters, &m_host_client_transactions, &m_host_server_transactions, &m_host_transaction_delays);

			m_host_transaction_counters.to_protobuf(m_metrics->mutable_hostinfo()->mutable_transaction_counters(),
				m_metrics->mutable_hostinfo()->mutable_min_transaction_counters(),
				m_metrics->mutable_hostinfo()->mutable_max_transaction_counters(),
				m_sampling_ratio);

			if(m_host_transaction_delays.m_local_processing_delay_ns != -1)
			{
				m_metrics->mutable_hostinfo()->set_transaction_processing_delay(m_host_transaction_delays.m_local_processing_delay_ns * m_sampling_ratio);
				m_metrics->mutable_hostinfo()->set_next_tiers_delay(m_host_transaction_delays.m_merged_client_delay * m_sampling_ratio);
			}

			//
			// Time splits
			//
			m_host_metrics.m_metrics.to_protobuf(m_metrics->mutable_hostinfo()->mutable_tcounters(), m_sampling_ratio);

			m_host_req_metrics.to_reqprotobuf(m_metrics->mutable_hostinfo()->mutable_reqcounters(), m_sampling_ratio);

			auto external_io_net = m_metrics->mutable_hostinfo()->mutable_external_io_net();
			m_io_net.to_protobuf(external_io_net, 1, m_sampling_ratio);

			// We decided to patch host network metrics using data from /proc, because using only
			// sysdig metrics we miss kernel threads activity
			// In this case, sampling_ratio is not evaluated
			auto interfaces_stats = m_procfs_parser->read_network_interfaces_stats();
			if(interfaces_stats.first > 0 || interfaces_stats.second > 0)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "Patching host external networking, from (%u, %u) to (%u, %u)",
								m_io_net.m_bytes_in, m_io_net.m_bytes_out,
								interfaces_stats.first, interfaces_stats.second);
				external_io_net->set_bytes_in(interfaces_stats.first);
				external_io_net->set_bytes_out(interfaces_stats.second);
			}
			m_metrics->mutable_hostinfo()->mutable_external_io_net()->set_time_ns_out(0);

			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"sinsp cpu: %lf", m_my_cpuload);

				g_logger.format(sinsp_logger::SEV_DEBUG,
					"host times: %.2lf%% file:%.2lf%%(in:%" PRIu32 "b/%" PRIu32" out:%" PRIu32 "b/%" PRIu32 ") net:%.2lf%% other:%.2lf%%",
					m_host_metrics.m_metrics.get_processing_percentage() * 100,
					m_host_metrics.m_metrics.get_file_percentage() * 100,
					m_host_metrics.m_metrics.m_tot_io_file.m_bytes_in,
					m_host_metrics.m_metrics.m_tot_io_file.m_count_in,
					m_host_metrics.m_metrics.m_tot_io_file.m_bytes_out,
					m_host_metrics.m_metrics.m_tot_io_file.m_count_out,
					m_host_metrics.m_metrics.get_net_percentage() * 100,
					m_host_metrics.m_metrics.get_other_percentage() * 100);
			}

			if(m_host_transaction_counters.get_counter()->m_count_in + m_host_transaction_counters.get_counter()->m_count_out != 0)
			{
				if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
						" host h:%.2f(s:%.2f)",
						m_host_metrics.get_capacity_score(),
						m_host_metrics.get_stolen_score());

					g_logger.format(sinsp_logger::SEV_DEBUG,
						"  trans)in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
						m_host_transaction_counters.get_counter()->m_count_in * m_sampling_ratio,
						m_host_transaction_counters.get_counter()->m_count_out * m_sampling_ratio,
						(float)m_host_transaction_counters.get_counter()->m_time_ns_in / sample_duration,
						(float)m_client_tr_time_by_servers / sample_duration,
						(m_host_transaction_delays.m_local_processing_delay_ns != -1)?((double)m_host_transaction_delays.m_merged_server_delay) / sample_duration : -1,
						(m_host_transaction_delays.m_local_processing_delay_ns != -1)?((double)m_host_transaction_delays.m_merged_client_delay) / sample_duration : -1,
						(m_host_transaction_delays.m_local_processing_delay_ns != -1)?((double)m_host_transaction_delays.m_local_processing_delay_ns) / sample_duration : -1);

					g_logger.format(sinsp_logger::SEV_DEBUG,
						"host transaction times: proc:%.2lf%% file:%.2lf%% net:%.2lf%% other:%.2lf%%",
						m_host_req_metrics.get_processing_percentage() * 100,
						m_host_req_metrics.get_file_percentage() * 100,
						m_host_req_metrics.get_net_percentage() * 100,
						m_host_req_metrics.get_other_percentage() * 100);
				}
			}

			//
			// If it's time to emit the falco baseline, do the serialization and then restart it
			//
			if(m_do_baseline_calculation)
			{
				if(is_eof)
				{
					//
					// Make sure to push a baseline when reading from file and we reached EOF
					//
					m_falco_baseliner->emit_as_protobuf(0, m_metrics->mutable_falcobl());
				}
//				else if(evt != NULL && evt->get_ts() - m_last_falco_dump_ts > 5000000000)
				else if(evt != NULL && evt->get_ts() - m_last_falco_dump_ts > FALCOBL_DUMP_DELTA_NS)
				{
					if(m_last_falco_dump_ts != 0)
					{
						m_falco_baseliner->emit_as_protobuf(evt->get_ts(), m_metrics->mutable_falcobl());
					}

					m_last_falco_dump_ts = evt->get_ts();
				}
			}
			else
			{
				if(m_configuration->get_falco_baselining_enabled())
				{
					//
					// Once in a while, try to turn baseline calculation on again
					//
					if(m_sampling_ratio == 1)
					{
						if(evt != NULL && evt->get_ts() - m_last_falco_dump_ts > FALCOBL_DISABLE_TIME)
						{
							//
							// It's safe to turn baselining on again.
							// Reset the tables and restart the baseline time counter.
							//
							m_do_baseline_calculation = true;
							m_falco_baseliner->clear_tables();
							m_falco_baseliner->load_tables(evt->get_ts());
							m_last_falco_dump_ts = evt->get_ts();
							g_logger.format("enabling falco baselining creation after %lus pause",
								FALCOBL_DISABLE_TIME / 1000000000);
						}
					}
					else
					{
						//
						// Sampling ratio is still high, reset the baseline counter
						//
						m_last_falco_dump_ts = evt->get_ts();					
					}
				}
			}

			////////////////////////////////////////////////////////////////////////////
			// Serialize the whole crap
			////////////////////////////////////////////////////////////////////////////
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				uint64_t serialize_sample_time =
				m_prev_flush_time_ns - m_prev_flush_time_ns % m_configuration->get_analyzer_original_sample_len_ns();

				serialize(evt, serialize_sample_time);
			}

			//
			// Reset the aggregated host metrics
			//
			m_host_metrics.clear();
			m_host_req_metrics.clear();
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// CLEANUPS
	///////////////////////////////////////////////////////////////////////////

	//
	// Clear the transaction state
	//
	if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
			"# Client Transactions:%d",
			m_trans_table->m_n_client_transactions * m_sampling_ratio);
		g_logger.format(sinsp_logger::SEV_DEBUG,
			"# Server Transactions:%d",
			m_trans_table->m_n_server_transactions * m_sampling_ratio);
	}

	m_trans_table->m_n_client_transactions = 0;
	m_trans_table->m_n_server_transactions = 0;

	m_host_transaction_counters.clear();
	m_client_tr_time_by_servers = 0;

	for(j = 0; j < m_host_server_transactions.size(); ++j)
	{
		m_host_server_transactions[j].clear();
	}

	for(j = 0; j < m_host_client_transactions.size(); ++j)
	{
		m_host_client_transactions[j].clear();
	}

	//
	// Reset the proc lookup counter
	//
	m_inspector->m_n_proc_lookups = 0;
	m_inspector->m_n_proc_lookups_duration_ns = 0;

	//
	// Clear the network I/O counter
	//
	m_io_net.clear();

	//
	// Clear the executed command list
	//
	m_executed_commands.clear();

	if(is_jmx_flushtime())
	{
		m_jmx_metrics.clear();
	}
	//
	// If there were tid collisions report them in the log and then clear the list
	//
	if(m_inspector->m_tid_collisions.size() != 0)
	{
		string tcb;

		for(j = 0; j < MIN(m_inspector->m_tid_collisions.size(), 16); j++)
		{
			tcb += to_string(m_inspector->m_tid_collisions[j]);
			tcb += " ";
		}

		g_logger.format(sinsp_logger::SEV_INFO,
			"%d TID collisions (%s)", (int)m_inspector->m_tid_collisions.size(),
			tcb.c_str());

		if(m_inspector->m_tid_collisions.size() >= MAX_TID_COLLISIONS_IN_SAMPLE)
		{
			m_die = true;
		}

		m_inspector->m_tid_collisions.clear();
	}

	if(evt)
	{
		if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "----- %" PRIu64 "", nevts_in_last_sample);
		}

		m_prev_sample_evtnum = evt->get_num();

		//
		// This thread might be removed, either by a procexit or by thread table
		// cleanup process
		// In either case, evt->m_tinfo would become invalid.
		// To avoid that, we refresh evt->m_tinfo.
		//
		evt->m_tinfo = NULL;	// This is important to avoid using a stale cached value!
		evt->m_tinfo = evt->get_thread_info();
	}

	m_prev_flushes_duration_ns += sinsp_utils::get_current_time_ns() - flush_start_ns;
	m_cputime_analyzer.end_flush();
	if(m_configuration->get_autodrop_enabled())
	{
		m_prev_flush_cpu_pct = m_cputime_analyzer.calc_flush_percent();
		tune_drop_mode(flshflags, m_my_cpuload*(1-m_prev_flush_cpu_pct));
	}
}

//
// Parses a previous select/poll/epoll and account its time based on the successive I/O operation
//
void sinsp_analyzer::add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat)
{
	thread_analyzer_info* tainfo = evt->m_tinfo->m_ainfo;
	int64_t wd = evt->m_tinfo->m_ainfo->m_last_wait_duration_ns;

	ASSERT(tainfo != NULL);

	if(wd != 0)
	{
		uint64_t we = tainfo->m_last_wait_end_time_ns;

		if(we >= m_prev_flush_time_ns)
		{
			uint64_t ws;
			uint64_t delta;

			if(wd > 0)
			{
				ws = we - wd;
			}
			else
			{
				ws = we + wd;
			}

			delta = we - MAX(ws, m_prev_flush_time_ns);

			sinsp_counters* metrics = &tainfo->m_metrics;

			//
			// This can happen in case of event drops
			//
			if(delta > metrics->m_wait_other.m_time_ns)
			{
				tainfo->m_last_wait_duration_ns = 0;
				tainfo->m_last_wait_end_time_ns = 0;
				return;
			}

			if(cat->m_category == EC_FILE)
			{
				metrics->m_wait_file.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else if(cat->m_category == EC_NET)
			{
				metrics->m_wait_net.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else if(cat->m_category == EC_IPC)
			{
				metrics->m_wait_ipc.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_NET:
					if(cat->m_category == EC_IO_READ)
					{
						break;
					}
					else if(cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_net.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_net.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				case sinsp_evt::SC_FILE:
					if(cat->m_category == EC_IO_READ)
					{
						metrics->m_wait_file.add_in(1, delta);
					}
					else if(cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_file.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_file.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				case sinsp_evt::SC_IPC:
					if(cat->m_category == EC_IO_READ)
					{
						metrics->m_wait_ipc.add_in(1, delta);
					}
					else if(cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_ipc.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_ipc.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				default:
					break;
				}
			}
		}

		tainfo->m_last_wait_duration_ns = 0;
		tainfo->m_last_wait_end_time_ns = 0;
	}
}

//
// Analyzer event processing entry point
//
void sinsp_analyzer::process_event(sinsp_evt* evt, flush_flags flshflags)
{
	uint64_t ts;
	uint64_t delta;
	sinsp_evt::category cat;
	uint16_t etype;
	thread_analyzer_info* tainfo;

	//
	// If there is no event, assume that this is an EOF and use the
	// next sample event as target time
	//
	if(evt != NULL)
	{
		ts = evt->get_ts();
		etype = evt->get_type();

		if(m_parser->process_event(evt) == false)
		{
			return;
		}

		//
		// if there are chisels to run, run them now, before going into the analyzer logic
		//
		if(m_run_chisels)
		{
			for(auto it = m_chisels.begin(); it != m_chisels.end(); ++it)
			{
				if((*it)->run(evt) == false)
				{
					continue;
				}
			}
		}
	}
	else
	{
		if(m_sampling_ratio == 1)
		{
			if(flshflags == DF_EOF)
			{
				ts = m_next_flush_time_ns;
				flush(evt, ts, true, flshflags);

				if(m_run_chisels)
				{
					chisels_on_capture_end();
				}

				return;
			}
			else if(flshflags == DF_TIMEOUT)
			{
				if(m_inspector->is_live() && m_inspector->m_lastevent_ts != 0)
				{
					ts = sinsp_utils::get_current_time_ns() - 500000000;
					etype = 0; // this avoids a compiler warning
				}
				else
				{
					return;
				}
			}
			else
			{
				ASSERT(false);
				return;
			}
		}
		else
		{
			return;
		}
	}

	if (m_sampling_ratio != 1 && ts - m_last_dropmode_switch_time > ONE_SECOND_IN_NS*3/2 ) // 1.5 seconds
	{
		// Passed too much time since last drop event
		// Probably driver switched to sampling=1 without
		// sending a drop_event with an updated sampleratio.
		// forcing it
		g_logger.log("Did not receive drop event to confirm sampling_ratio, forcing update", sinsp_logger::SEV_WARNING);
		set_sampling_ratio(m_new_sampling_ratio);
		m_last_dropmode_switch_time = ts;
	}

	//
	// Check if it's time to flush
	//
	if(ts >= m_next_flush_time_ns)
	{
		bool do_flush = true;

		if(m_sampling_ratio != 1)
		{
			do_flush = false;
		}

		if(do_flush)
		{
			//g_logger.log("Executing flush (do_flush=true)", sinsp_logger::SEV_INFO);
			flush(evt, ts, false, flshflags);
		}
	}

	//
	// This happens if the flush was generated by a timeout
	//
	if(evt == NULL)
	{
		return;
	}

	//
	// This is where normal event parsing starts.
	// The following code is executed for every event
	//
	if(evt->m_tinfo == NULL ||
		etype == PPME_SCHEDSWITCH_1_E ||
		etype == PPME_SCHEDSWITCH_6_E)
	{
		//
		// No thread associated to this event, nothing to do
		//
		return;
	}

	tainfo = evt->m_tinfo->m_ainfo;

	if(tainfo == NULL)
	{
		//
		// No analyzer state associated to this thread.
		// This should never happen. If it does, skip the event.
		//
		ASSERT(false);
		return;
	}

	if(m_falco_engine && ((evt->get_info_flags() & EF_DROP_FALCO) == 0))
	{
		try {

			unique_ptr<falco_engine::rule_result> res = m_falco_engine->process_event(evt);
			if(res && m_falco_events)
			{
				m_falco_events->generate_user_event(res);
			}
		}
		catch (falco_exception& e)
		{
			g_logger.log("Error processing event against falco engine: " + string(e.what()));
		}
	}

	//
	// Get the event category and type
	//
	evt->get_category(&cat);

	//
	// For our purposes, accept() is wait, not networking
	//
	if(etype == PPME_SOCKET_ACCEPT_E || etype == PPME_SOCKET_ACCEPT_X
		|| etype == PPME_SOCKET_ACCEPT_5_E || etype == PPME_SOCKET_ACCEPT_5_X)
	{
		cat.m_category = EC_WAIT;
	}

	//
	// Check if this is an event that goes across sample boundaries
	//
	if((tainfo->m_th_analysis_flags & thread_analyzer_info::AF_PARTIAL_METRIC) != 0)
	{
		//
		// Part of this event has already been attributed to the previous sample,
		// we just include the remaining part
		//
		tainfo->m_th_analysis_flags &= ~(thread_analyzer_info::AF_PARTIAL_METRIC);

		delta = ts - m_prev_flush_time_ns;
	}
	else
	{
		//
		// Normal event that falls completely inside this sample
		//
		delta = ts - evt->m_tinfo->m_lastevent_ts;
	}

	//
	// Add this event time to the right category in the metrics array
	//
	if(PPME_IS_ENTER(etype))
	{
		//
		// remember the category in the thread info. We'll use
		// it if we need to flush the sample.
		//
		evt->m_tinfo->m_lastevent_category = cat;

		//
		// Switch the category to processing
		//
		cat.m_category = EC_PROCESSING;
	}
	else
	{
		if(!evt->m_tinfo->is_lastevent_data_valid())
		{
			//
			// There was some kind of drop and the enter event is not matching
			//
			cat.m_category = EC_UNKNOWN;
		}

		//
		// If a sample flush happens after this event, the time will have to
		// be attributed to processing.
		//
		evt->m_tinfo->m_lastevent_category.m_category = EC_PROCESSING;

		//
		// If this is an fd-based syscall that comes after a wait, update the wait time
		//
		ppm_event_flags eflags = evt->get_info_flags();
		if(eflags & EF_USES_FD)
		{
			add_wait_time(evt, &cat);
		}
	}

	//
	// Increase the counter
	//
	bool do_inc_counter = (cat.m_category != EC_PROCESSING);

	add_syscall_time(&tainfo->m_metrics,
		&cat,
		delta,
		evt->get_iosize(),
		do_inc_counter);

	//
	// If this is an error syscall, add the error to the process and host table
	//
	if(evt->m_errorcode != 0)
	{
		if((evt->m_errorcode != SE_EINPROGRESS) &&
			(evt->m_errorcode != SE_EAGAIN) &&
			(evt->m_errorcode != SE_ETIMEDOUT))
		{
			m_host_metrics.m_syscall_errors.add(evt);

			ASSERT(evt->m_tinfo);
			ASSERT(evt->m_tinfo->m_ainfo);

			evt->m_tinfo->m_ainfo->m_dynstate->m_syscall_errors.add(evt);

			if(!evt->m_tinfo->m_container_id.empty())
			{
				m_containers[evt->m_tinfo->m_container_id].m_metrics.m_syscall_errors.add(evt);
			}
		}
	}
}

void sinsp_analyzer::add_syscall_time(sinsp_counters* metrics,
									  sinsp_evt::category* cat,
									  uint64_t delta,
									  uint32_t bytes,
									  bool inc_count)
{
	uint32_t cnt_delta = (inc_count)? 1 : 0;

	switch(cat->m_category)
	{
		case EC_UNKNOWN:
			metrics->m_unknown.add(cnt_delta, delta);
			break;
		case EC_OTHER:
			metrics->m_other.add(cnt_delta, delta);
			break;
		case EC_FILE:
			metrics->m_file.add(cnt_delta, delta);
			break;
		case EC_NET:
			metrics->m_net.add(cnt_delta, delta);
			break;
		case EC_IPC:
			metrics->m_ipc.add(cnt_delta, delta);
			break;
		case EC_MEMORY:
			metrics->m_memory.add(cnt_delta, delta);
			break;
		case EC_PROCESS:
			metrics->m_process.add(cnt_delta, delta);
			break;
		case EC_SLEEP:
			metrics->m_sleep.add(cnt_delta, delta);
			break;
		case EC_SYSTEM:
			metrics->m_system.add(cnt_delta, delta);
			break;
		case EC_SIGNAL:
			metrics->m_signal.add(cnt_delta, delta);
			break;
		case EC_USER:
			metrics->m_user.add(cnt_delta, delta);
			break;
		case EC_TIME:
			metrics->m_time.add(cnt_delta, delta);
			break;
		case EC_PROCESSING:
			metrics->m_processing.add(cnt_delta, delta);
			break;
		case EC_IO_READ:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add_in(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add_in(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add_in(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add_in(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add_in(cnt_delta, delta, bytes);
					break;
				}
			}
			break;
		case EC_IO_WRITE:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add_out(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add_out(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add_out(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add_out(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add_out(cnt_delta, delta, bytes);
					break;
				}
			}
			break;
		case EC_IO_OTHER:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add_other(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add_other(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add_other(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add_other(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add_other(cnt_delta, delta, bytes);
					break;
				}
			}
			break;
		case EC_WAIT:
			metrics->m_wait_other.add(cnt_delta, delta);
			break;
		case EC_SCHEDULER:
		case EC_INTERNAL:
			break;
		default:
			ASSERT(false);
	}
}

void sinsp_analyzer::get_k8s_data()
{
	if(m_k8s)
	{
		m_k8s->watch();
		if(m_metrics)
		{
			k8s_proto(*m_metrics).get_proto(m_k8s->get_state());
			if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE && m_metrics->has_kubernetes())
			{
				g_logger.log("K8s proto data:", sinsp_logger::SEV_TRACE);
				g_logger.log(m_metrics->kubernetes().DebugString(), sinsp_logger::SEV_TRACE);
			}
		}
		else
		{
			g_logger.log("Proto metrics are NULL.", sinsp_logger::SEV_ERROR);
		}
	}
}

void sinsp_analyzer::reset_k8s(time_t& last_attempt, const std::string& err)
{
	log_timed_error(last_attempt, err);
	m_k8s_api_detected = false;
	m_k8s_ext_detect_done = false;
	m_k8s_delegator.reset();
	m_k8s_collector.reset();
	m_k8s_api_handler.reset();
	m_k8s_ext_handler.reset();
	m_ext_list_ptr.reset();
	m_k8s.reset();
	if(m_configuration->get_k8s_autodetect_enabled())
	{
		m_configuration->set_k8s_api_server("");
	}
}

void sinsp_analyzer::collect_k8s(const std::string& k8s_api)
{
	if(!k8s_api.empty())
	{
		uri k8s_uri(k8s_api);
		try
		{
			std::ostringstream log;
			if(!m_k8s)
			{
				log << "Connecting to K8S API server at: [" << k8s_uri.to_string(false) << ']';
				m_k8s.reset(get_k8s(k8s_uri, log.str()));
			}

			if(m_k8s)
			{
				get_k8s_data();
				if(m_k8s->get_machine_id().empty() && !m_configuration->get_machine_id().empty())
				{
					m_k8s->set_machine_id(m_configuration->get_machine_id());
				}
			}
		}
		catch(std::exception& ex)
		{
			static time_t last_attempt;
			reset_k8s(last_attempt, std::string("Error collecting K8s data:").append(ex.what()));
		}
	}
}

void sinsp_analyzer::emit_k8s()
{
	// k8s_uri string config setting can be set:
	//
	//    - explicitly in configuration file; when present, this setting has priority
	//      over anything else in regards to presence/location of the api server
	//
	//    - implicitly, by k8s autodetect flag (which defaults to true);
	//      when k8s_uri is empty, autodetect is true and api server is detected on the
	//      local machine, uri will be automatically set to "http://{address}:8080", where
	//      {address} is the IP address of the interface on which API server is listening
	//
	// so, at runtime, k8s_uri being empty or not determines whether k8s data
	// will be collected and emitted; the connection to k8s api server is entirely managed
	// in this function - if it is dropped, the attempts to re-establish it will keep on going
	// forever, once per cycle, until either connection is re-established or agent shut down

	try
	{
		std::string k8s_api = m_configuration->get_k8s_api_server();
		if(!k8s_api.empty())
		{
			if(uri(k8s_api).is_local())
			{
				static bool logged = false;
				if(!logged && m_configuration->get_k8s_delegated_nodes() && !m_configuration->get_k8s_simulate_delegation())
				{
					g_logger.log(std::string("K8s: incompatible settings (local URI and node auto-delegation), "
											 "node auto-delegation ignored"),
								 sinsp_logger::SEV_WARNING);
					logged = true;
				}
				else if(m_configuration->get_k8s_simulate_delegation() && m_configuration->get_k8s_delegated_nodes())
				{
					// simulation, force delegation check
					if(!check_k8s_delegation()) { return; }
				}
			}
			else if(m_configuration->get_k8s_delegated_nodes())
			{
				if(!check_k8s_delegation()) { return; }
			}
		}
		else
		{
			if(m_configuration->get_k8s_autodetect_enabled())
			{
				k8s_api = detect_k8s();
			}
		}
		if(!k8s_api.empty())
		{
			if(!m_k8s_api_detected)
			{
				if(!m_k8s_api_handler)
				{
					if(!m_k8s_collector)
					{
						m_k8s_collector = std::make_shared<k8s_handler::collector_t>();
					}
					if(uri(k8s_api).is_secure()) { init_k8s_ssl(k8s_api); }
					m_k8s_api_handler.reset(new k8s_api_handler(m_k8s_collector, k8s_api,
																"/api", ".versions", "1.1",
																m_k8s_ssl, m_k8s_bt, false));
				}
				else
				{
					m_k8s_api_handler->collect_data();
					if(m_k8s_api_handler->connection_error())
					{
						throw sinsp_exception("K8s API handler connection error.");
					}
					else if(m_k8s_api_handler->ready())
					{
						g_logger.log("K8s API handler data received.", sinsp_logger::SEV_TRACE);
						if(m_k8s_api_handler->error())
						{
							g_logger.log("K8s API handler data error occurred while detecting API versions.",
										 sinsp_logger::SEV_ERROR);
						}
						else
						{
							m_k8s_api_detected = m_k8s_api_handler->has("v1");// TODO: make version configurable
						}
						m_k8s_collector.reset();
						m_k8s_api_handler.reset();
					}
					else
					{
						g_logger.log("K8s API handler: not ready.", sinsp_logger::SEV_TRACE);
					}
				}
			}
			if(m_k8s_api_detected)
			{
				collect_k8s(k8s_api);
			}
		}
	}
	catch(std::exception& ex)
	{
		static time_t last_attempt;
		reset_k8s(last_attempt, std::string("Error emitting K8s data:").append(ex.what()));
		throw;
	}
}

void sinsp_analyzer::get_mesos_data()
{
	static time_t last_mesos_refresh = 0;
	ASSERT(m_mesos);
	ASSERT(m_mesos->is_alive());

	time_t now; time(&now);
	if(m_mesos && last_mesos_refresh)
	{
		m_mesos->collect_data();
	}
	if(m_mesos && m_dcos_enterprise_last_token_refresh_s > 0 &&
		difftime(now, m_dcos_enterprise_last_token_refresh_s) > DCOS_ENTERPRISE_TOKEN_REFRESH_S)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Regenerating Mesos token");
		m_mesos->refresh_token();
		m_dcos_enterprise_last_token_refresh_s = now;
	}
	if(m_mesos && difftime(now, last_mesos_refresh) > MESOS_STATE_REFRESH_INTERVAL_S)
	{
		m_mesos->send_data_request();
		last_mesos_refresh = now;
	}
	if(m_mesos && m_mesos->get_state().has_data())
	{
		ASSERT(m_metrics);
		mesos_proto(*m_metrics, m_mesos->get_state()).get_proto();

		if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE && m_metrics->has_mesos())
		{
			g_logger.log(m_metrics->mesos().DebugString(), sinsp_logger::SEV_TRACE);
		}

	}
	else
	{
		throw sinsp_exception("Mesos state empty (will retry later).");
	}
}

void sinsp_analyzer::reset_mesos(const std::string& errmsg)
{
	if(!errmsg.empty())
	{
		g_logger.log(errmsg, sinsp_logger::SEV_ERROR);
	}
	m_mesos_last_failure_ns = m_prev_flush_time_ns;
	m_mesos.reset();
	m_configuration->set_mesos_state_uri(m_configuration->get_mesos_state_original_uri());
}

void sinsp_analyzer::emit_mesos()
{
	// mesos uri config settings can be set:
	//
	//    - explicitly in configuration file; when present, this setting has priority
	//      over anything else in regards to presence/location of the api server
	//
	//    - implicitly, by mesos autodetect flag (which defaults to true);
	//      when mesos_state_uri is empty, autodetect is true and api server is detected on the
	//      local machine, uris will be automatically set to:
	//
	//      mesos state:     "http://{IP_ADDR}:5050/state.json"
	//                       with {IP_ADDR} being interface where Mesos is found listening
	//      marathon groups: will be discovered automatically from mesos master state
	//                       (eg. "http://localhost:8080/v2/groups")
	//      marathon uri:    will be discovered automatically from mesos master state
	//                       (eg. "http://localhost:8080/v2/apps?embed=apps.tasks")
	//
	// so, at runtime, mesos_state_uri being empty or not determines whether mesos data
	// will be collected and emitted; the connection to mesos api server is entirely managed
	// in this function - if it is dropped, the attempts to re-establish it will keep on going
	// forever, once per cycle, until either connection is re-established or agent shut down
	
	string mesos_uri = m_configuration->get_mesos_state_uri();

	try
	{
		if(!mesos_uri.empty())
		{
			g_logger.log("Emitting Mesos ...", sinsp_logger::SEV_DEBUG);
			if(!m_mesos && !m_mesos_bad_config)
			{
				g_logger.log("Connecting to Mesos API server at [" + uri(mesos_uri).to_string(false) + "] ...", sinsp_logger::SEV_INFO);
				get_mesos(mesos_uri);
			}
			else if(m_mesos && !m_mesos->is_alive() && !m_mesos_bad_config)
			{
				g_logger.log("Existing Mesos connection error detected (not alive). Trying to reconnect ...", sinsp_logger::SEV_ERROR);
				get_mesos(mesos_uri);
			}

			if(m_mesos)
			{
				if(m_mesos->is_alive())
				{
					get_mesos_data();
				}
				if(!m_mesos->is_alive() && !m_mesos_bad_config)
				{
					g_logger.log("Existing Mesos connection error detected (not alive). Trying to reconnect ...", sinsp_logger::SEV_ERROR);
					get_mesos(mesos_uri);
					if(m_mesos && m_mesos->is_alive())
					{
						g_logger.log("Mesos connection re-established.", sinsp_logger::SEV_INFO);
						get_mesos_data();
					}
					else
					{
						reset_mesos("Mesos connection attempt failed. Will retry in next cycle.");
					}
				}
			}
			else
			{
				reset_mesos("Mesos connection not established.");
			}
		}
		else if(m_configuration->get_mesos_autodetect_enabled() && (m_prev_flush_time_ns - m_mesos_last_failure_ns) > MESOS_RETRY_ON_ERRORS_TIMEOUT_NS)
		{
			detect_mesos(mesos_uri);
		}
	}
	catch(std::exception& e)
	{
		reset_mesos(std::string("Error fetching Mesos state: ").append(e.what()));
	}
}

void sinsp_analyzer::log_timed_error(time_t& last_attempt, const std::string& err)
{
	time_t now; time(&now);
	if(difftime(now, last_attempt) > m_k8s_retry_seconds)
	{
		last_attempt = now;
		g_logger.log(err, sinsp_logger::SEV_ERROR);
	}
}

bool sinsp_analyzer::check_k8s_delegation()
{
	const std::string& k8s_uri = m_configuration->get_k8s_api_server();
	int delegated_nodes = m_configuration->get_k8s_delegated_nodes();
	if(!k8s_uri.empty())
	{
		if(uri(k8s_uri).is_local() && !m_configuration->get_k8s_simulate_delegation())
		{
			static bool logged = false;
			if(!logged && delegated_nodes)
			{
				g_logger.log(std::string("K8s: incompatible settings (local URI and auto-delegation), auto-delegation ignored"),
							sinsp_logger::SEV_WARNING);
				logged = true;
			}
			return true;
		}
		else if(delegated_nodes)
		{
			try
			{
				static time_t last_attempt;
				if(m_k8s_delegator)
				{
					m_k8s_delegator->collect_data();
					return m_k8s_delegator->is_delegated();
				}
				else
				{
					bool log = false;
					time_t now; time(&now);
					if(difftime(now, last_attempt) > m_k8s_retry_seconds)
					{
						log = true;
						last_attempt = now;
					}
					if(log)
					{
						g_logger.log("Creating K8s delegator object ...", sinsp_logger::SEV_INFO);
					}
					if(uri(k8s_uri).is_secure()) { init_k8s_ssl(k8s_uri); }
					m_k8s_delegator.reset(new k8s_delegator(m_inspector,
															k8s_uri,
															delegated_nodes,
															"1.1", // http version
															m_k8s_ssl,
															m_k8s_bt));
					if(m_k8s_delegator)
					{
						if(m_k8s_delegator->connection_error())
						{
							throw sinsp_exception("K8s delegator connection error.");
						}
						if(log)
						{
							g_logger.log("Created K8s delegator object, collecting data...", sinsp_logger::SEV_INFO);
						}
						m_k8s_delegator->collect_data();
						return m_k8s_delegator->is_delegated();
					}
					else
					{
						if(log)
						{
							g_logger.log("Can't create K8s delegator object.", sinsp_logger::SEV_ERROR);
						}
						m_k8s_delegator.reset();
					}
				}
			}
			catch(std::exception& ex)
			{
				static time_t last_attempt;
				reset_k8s(last_attempt, std::string("K8s delegator error: ") + ex.what());
			}
		}
	}
	return false;
}

void sinsp_analyzer::emit_docker_events()
{
	try
	{
		if(m_docker)
		{
			m_docker->collect_data();
		}
		else
		{
			g_logger.log("Creating Docker object ...", sinsp_logger::SEV_INFO);
			m_docker.reset(new docker());
			if(m_docker)
			{
				m_docker->set_event_filter(m_configuration->get_docker_event_filter());
				m_docker->set_machine_id(m_configuration->get_machine_id());
				g_logger.log("Created Docker object, collecting data...", sinsp_logger::SEV_INFO);
				m_docker->collect_data();
				return;
			}
			else
			{
				g_logger.log("Can't create Docker events object.", sinsp_logger::SEV_ERROR);
				m_docker.reset();
			}
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Docker events error: ") + ex.what(), sinsp_logger::SEV_ERROR);
		m_docker.reset();
	}
}

void sinsp_analyzer::emit_top_files()
{
	vector<analyzer_file_stat*> files_sortable_list;

	for(unordered_map<string, analyzer_file_stat>::iterator it = m_fd_listener->m_files_stat.begin();
		it != m_fd_listener->m_files_stat.end(); ++it)
	{
		files_sortable_list.push_back(&it->second);
	}

	if(files_sortable_list.size() > TOP_FILES_IN_SAMPLE)
	{
		partial_sort(files_sortable_list.begin(),
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE,
			files_sortable_list.end(),
			analyzer_file_stat::cmp_bytes);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}

		partial_sort(files_sortable_list.begin(),
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE,
			files_sortable_list.end(),
			analyzer_file_stat::cmp_time);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}

		partial_sort(files_sortable_list.begin(),
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE,
			files_sortable_list.end(),
			analyzer_file_stat::cmp_errors);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}

		partial_sort(files_sortable_list.begin(),
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE,
			files_sortable_list.end(),
			analyzer_file_stat::cmp_open_count);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}
	}
	else
	{
		for(vector<analyzer_file_stat*>::const_iterator it = files_sortable_list.begin();
			it != files_sortable_list.end(); ++it)
		{
			(*it)->m_exclude_from_sample = false;
		}
	}

	for(vector<analyzer_file_stat*>::const_iterator it = files_sortable_list.begin();
		it != files_sortable_list.end(); ++it)
	{
		if((*it)->m_exclude_from_sample == false)
		{
			draiosproto::file_stat* top_file = m_metrics->add_top_files();

			top_file->set_name((*it)->m_name);
			top_file->set_bytes((*it)->m_bytes);
			top_file->set_time_ns((*it)->m_time_ns);
			top_file->set_open_count((*it)->m_open_count);
			top_file->set_errors((*it)->m_errors);
		}
	}

	m_fd_listener->m_files_stat.clear();
}

template<typename Extractor>
class containers_cmp
{
public:
	containers_cmp(unordered_map<string, analyzer_container_state>* containers, Extractor&& extractor):
		m_containers(containers),
		m_extractor(extractor)
	{}

	bool operator()(const string& lhs, const string& rhs)
	{
		const auto it_analyzer_lhs = m_containers->find(lhs);
		const auto it_analyzer_rhs = m_containers->find(rhs);
		decltype(m_extractor(it_analyzer_lhs->second)) cmp_lhs = 0;
		if(it_analyzer_lhs != m_containers->end())
		{
			cmp_lhs = m_extractor(it_analyzer_lhs->second);
		}
		decltype(m_extractor(it_analyzer_rhs->second)) cmp_rhs = 0;
		if(it_analyzer_rhs != m_containers->end())
		{
			cmp_rhs = m_extractor(it_analyzer_rhs->second);
		}
		return cmp_lhs > cmp_rhs;
	}
private:
	unordered_map<string, analyzer_container_state>* m_containers;
	Extractor m_extractor;
};

vector<string> sinsp_analyzer::emit_containers(const progtable_by_container_t& progtable_by_container)
{
	// Containers are ordered by cpu, mem, file_io and net_io, these lambda extract
	// that value from analyzer_container_state
	auto cpu_extractor = [](const analyzer_container_state& analyzer_state)
	{
		return analyzer_state.m_metrics.m_cpuload;
	};

	auto mem_extractor = [](const analyzer_container_state& analyzer_state)
	{
		return analyzer_state.m_metrics.m_res_memory_used_kb;
	};

	auto file_io_extractor = [](const analyzer_container_state& analyzer_state)
	{
		return analyzer_state.m_req_metrics.m_io_file.get_tot_bytes();
	};

	auto net_io_extractor = [](const analyzer_container_state& analyzer_state)
	{
		return analyzer_state.m_req_metrics.m_io_file.get_tot_bytes();
	};

	vector<string> emitted_containers;
	vector<string> containers_ids;
	containers_ids.reserve(m_containers.size());
	sinsp_protostate_marker containers_protostate_marker;

	uint64_t total_cpu_shares = 0;
	for(const auto& item : progtable_by_container)
	{
		const auto& container_id = item.first;
		sinsp_container_info container_info;
		if(m_inspector->m_container_manager.get_container(container_id, &container_info))
		{

			if(container_info.m_name.find("k8s_POD") == std::string::npos)
			{
				if((m_container_patterns.empty() ||
					std::find_if(m_container_patterns.begin(), m_container_patterns.end(),
								 [&container_info](const string& pattern)
								 {
									 return container_info.m_name.find(pattern) != string::npos ||
											container_info.m_image.find(pattern) != string::npos;
								 }) != m_container_patterns.end())
						)
				{
					auto analyzer_it = m_containers.find(container_id);
					if(analyzer_it != m_containers.end())
					{
						containers_ids.push_back(container_id);
						containers_protostate_marker.add(analyzer_it->second.m_metrics.m_protostate);
					}
				}

				// This count it's easy to be affected by a lot of noise, for example:
				// 1. k8s_POD pods
				// 2. custom containers run from cmdline with no --cpu-shares flag,
				//    in this case the kernel defaults to 1024
				// 3. system containers like kubernetes proxy
				//
				// we decided to skip 1. to avoid noise (they have usually shares=2,
				// does not affect so much the calc but they may be a lot)
				// Right now we decided to keep 2. But may be changed in the future
				// because usually if --cpu-shares flag is not set, it is meant for troubleshooting
				// containers with few cpu usage or system containers
				// with a default of 1024 given by the kernel, they pollute a lot the calculation
				total_cpu_shares += container_info.m_cpu_shares;
			}
		}
	}

	g_logger.format(sinsp_logger::SEV_DEBUG, "total_cpu_shares=%lu", total_cpu_shares);
	containers_protostate_marker.mark_top(CONTAINERS_PROTOS_TOP_LIMIT);
	// Emit containers on protobuf, our logic is:
	// Pick top N from top_by_cpu
	// Pick top N from top_by_mem which are not already taken by top_cpu
	// Pick top N from top_by_file_io which are not already taken by top_cpu and top_mem
	// Etc ...

	const auto containers_limit_by_type = m_containers_limit/4;
	const auto containers_limit_by_type_remainder = m_containers_limit % 4;
	unsigned statsd_limit = m_configuration->get_statsd_limit();
	auto check_and_emit_containers = [&containers_ids, this, &statsd_limit,
									&emitted_containers, &total_cpu_shares, &progtable_by_container]
			(const uint32_t containers_limit)
	{
		for(uint32_t j = 0; j < containers_limit && !containers_ids.empty(); ++j)
		{
			const auto& containerid = containers_ids.front();
			// We need any pid of a process running within this container
			// to get net stats via /proc, using .at() because it will never fail
			// since we are getting containerids from that table
			auto pid = progtable_by_container.at(containerid).front()->m_pid;
			this->emit_container(containerid, &statsd_limit, total_cpu_shares, pid);
			emitted_containers.emplace_back(containerid);
			containers_ids.erase(containers_ids.begin());
		}
	};

	if(containers_ids.size() > containers_limit_by_type + containers_limit_by_type_remainder)
	{
		partial_sort(containers_ids.begin(),
					 containers_ids.begin() + containers_limit_by_type + containers_limit_by_type_remainder,
					 containers_ids.end(),
					 containers_cmp<decltype(mem_extractor)>(&m_containers, move(mem_extractor)));
	}
	check_and_emit_containers(containers_limit_by_type+containers_limit_by_type_remainder);

	if(containers_ids.size() > containers_limit_by_type)
	{
		partial_sort(containers_ids.begin(),
					 containers_ids.begin() + containers_limit_by_type,
					 containers_ids.end(),
					 containers_cmp<decltype(file_io_extractor)>(&m_containers, move(file_io_extractor)));
	}
	check_and_emit_containers(containers_limit_by_type);

	if(containers_ids.size() > containers_limit_by_type)
	{
		partial_sort(containers_ids.begin(),
					 containers_ids.begin() + containers_limit_by_type,
					 containers_ids.end(),
					 containers_cmp<decltype(net_io_extractor)>(&m_containers, move(net_io_extractor)));
	}
	check_and_emit_containers(containers_limit_by_type);

	if(containers_ids.size() > containers_limit_by_type)
	{
		partial_sort(containers_ids.begin(),
					 containers_ids.begin() + containers_limit_by_type,
					 containers_ids.end(),
					 containers_cmp<decltype(cpu_extractor)>(&m_containers, move(cpu_extractor)));
	}
	check_and_emit_containers(containers_limit_by_type);
/*
	g_logger.log("Found " + std::to_string(m_metrics->containers().size()) + " containers.", sinsp_logger::SEV_DEBUG);
	for(const auto& c : m_metrics->containers())
	{
		g_logger.log(c.DebugString(), sinsp_logger::SEV_TRACE);
	}
*/
	static run_on_interval analyzer_containers_cleaner(30*ONE_SECOND_IN_NS, [this, &progtable_by_container]()
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Flushing analyzer container table");
		auto it = this->m_containers.begin();
		while(it != this->m_containers.end())
		{
			if(progtable_by_container.find(it->first) == progtable_by_container.end())
			{
				it = this->m_containers.erase(it);
			}
			else
			{
				++it;
			}
		}
	});
	analyzer_containers_cleaner.run(m_prev_flush_time_ns);
	return emitted_containers;
}

void
sinsp_analyzer::emit_container(const string &container_id, unsigned *statsd_limit, uint64_t total_cpu_shares,
							   int64_t pid)
{
	const auto containers_info = m_inspector->m_container_manager.get_containers();
	auto it = containers_info->find(container_id);
	if(it == containers_info->end())
	{
		return;
	}
	unordered_map<string, analyzer_container_state>::iterator it_analyzer = m_containers.find(it->second.m_id);
	if(it_analyzer == m_containers.end())
	{
		return;
	}

	draiosproto::container* container = m_metrics->add_containers();

	container->set_id(it->second.m_id);

	switch(it->second.m_type)
	{
	case CT_DOCKER:
		container->set_type(draiosproto::DOCKER);
		break;
	case CT_LXC:
		container->set_type(draiosproto::LXC);
		break;
	case CT_LIBVIRT_LXC:
		container->set_type(draiosproto::LIBVIRT_LXC);
		break;
	case CT_MESOS:
		container->set_type(draiosproto::MESOS);
		break;
	case CT_RKT:
		container->set_type(draiosproto::RKT);
		break;
	default:
		ASSERT(false);
	}

	if(!it->second.m_name.empty())
	{
		container->set_name(it->second.m_name);
	}

	if(!it->second.m_image.empty())
	{
		container->set_image(it->second.m_image);
	}

	if(!it->second.m_imageid.empty())
	{
		container->set_image_id(it->second.m_imageid.substr(0, 12));
	}

	if(!it->second.m_mesos_task_id.empty())
	{
		container->set_mesos_task_id(it->second.m_mesos_task_id);
	}

	for(vector<sinsp_container_info::container_port_mapping>::const_iterator it_ports = it->second.m_port_mappings.begin();
		it_ports != it->second.m_port_mappings.end(); ++it_ports)
	{
		draiosproto::container_port_mapping* mapping = container->add_port_mappings();

		mapping->set_host_ip(it_ports->m_host_ip);
		mapping->set_host_port(it_ports->m_host_port);
		mapping->set_container_ip(it->second.m_container_ip);
		mapping->set_container_port(it_ports->m_container_port);
	}

	for(map<string, string>::const_iterator it_labels = it->second.m_labels.begin();
		it_labels != it->second.m_labels.end(); ++it_labels)
	{
		draiosproto::container_label* label = container->add_labels();

		label->set_key(it_labels->first);
		label->set_value(it_labels->second);
	}

	container->mutable_resource_counters()->set_capacity_score(it_analyzer->second.m_metrics.get_capacity_score() * 100);
	container->mutable_resource_counters()->set_stolen_capacity_score(it_analyzer->second.m_metrics.get_stolen_score() * 100);
	container->mutable_resource_counters()->set_connection_queue_usage_pct(it_analyzer->second.m_metrics.m_connection_queue_usage_pct);
	container->mutable_resource_counters()->set_fd_usage_pct(it_analyzer->second.m_metrics.m_fd_usage_pct);
	uint32_t res_memory_kb = it_analyzer->second.m_metrics.m_res_memory_used_kb;
	if(!it_analyzer->second.m_memory_cgroup.empty())
	{
		const auto cgroup_memory = m_procfs_parser->read_cgroup_used_memory(it_analyzer->second.m_memory_cgroup);
		if(cgroup_memory > 0)
		{
			res_memory_kb = cgroup_memory / 1024;
		}
	}
	container->mutable_resource_counters()->set_resident_memory_usage_kb(res_memory_kb);
	container->mutable_resource_counters()->set_swap_memory_usage_kb(it_analyzer->second.m_metrics.m_swap_memory_used_kb);
	container->mutable_resource_counters()->set_major_pagefaults(it_analyzer->second.m_metrics.m_pfmajor);
	container->mutable_resource_counters()->set_minor_pagefaults(it_analyzer->second.m_metrics.m_pfminor);
	it_analyzer->second.m_metrics.m_syscall_errors.to_protobuf(container->mutable_syscall_errors(), m_sampling_ratio);
	container->mutable_resource_counters()->set_fd_count(it_analyzer->second.m_metrics.m_fd_count);
	container->mutable_resource_counters()->set_cpu_pct(it_analyzer->second.m_metrics.m_cpuload * 100);
	container->mutable_resource_counters()->set_count_processes(it_analyzer->second.m_metrics.get_process_count());
	container->mutable_resource_counters()->set_proc_start_count(it_analyzer->second.m_metrics.get_process_start_count());

	const auto cpu_shares = it->second.m_cpu_shares;
	if(cpu_shares > 0)
	{
		const double cpu_shares_usage_pct = it_analyzer->second.m_metrics.m_cpuload/m_inspector->m_num_cpus*total_cpu_shares/cpu_shares;
		//g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s cpu_shares=%u used_pct=%.2f", container_id.c_str(), cpu_shares, cpu_shares_usage_pct);
		container->mutable_resource_counters()->set_cpu_shares(cpu_shares);
		container->mutable_resource_counters()->set_cpu_shares_usage_pct(cpu_shares_usage_pct*100); // * 100 because we convert double to .2 fixed decimal
	}

	if(it->second.m_cpu_quota > 0 && it->second.m_cpu_period > 0)
	{
		const double cpu_quota_used_pct = it_analyzer->second.m_metrics.m_cpuload*it->second.m_cpu_period/it->second.m_cpu_quota;
		//g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s cpu_quota=%ld cpu_period=%ld used_pct=%.2f", container_id.c_str(), it->second.m_cpu_quota, it->second.m_cpu_period, cpu_quota_used_pct);
		container->mutable_resource_counters()->set_cpu_quota_used_pct(cpu_quota_used_pct*100);
	}

	if(it->second.m_memory_limit > 0)
	{
		container->mutable_resource_counters()->set_memory_limit_kb(it->second.m_memory_limit/1024);
		//g_logger.format(sinsp_logger::SEV_DEBUG, "container=%s memory=%u/%u", container_id.c_str(), res_memory_kb, it->second.m_memory_limit/1024);
	}

	if(it->second.m_swap_limit > 0)
	{
		container->mutable_resource_counters()->set_swap_limit_kb(it->second.m_swap_limit/1024);
	}

	auto tcounters = container->mutable_tcounters();
	it_analyzer->second.m_metrics.m_metrics.to_protobuf(tcounters, m_sampling_ratio);
	if(m_inspector->m_mode == SCAP_MODE_NODRIVER)
	{
		// We need to patch network metrics reading from /proc
		// since we don't have sysdig events in this case
		auto io_net = tcounters->mutable_io_net();
		auto net_bytes = m_procfs_parser->read_proc_network_stats(pid, &it_analyzer->second.m_last_bytes_in, &it_analyzer->second.m_last_bytes_out);
		g_logger.format(sinsp_logger::SEV_INFO, "Patching container=%s pid=%ld networking from (%u, %u) to (%u, %u)",
						container_id.c_str(), pid, io_net->bytes_in(), io_net->bytes_out(),
						net_bytes.first, net_bytes.second);
		io_net->set_bytes_in(net_bytes.first);
		io_net->set_bytes_out(net_bytes.second);
	}

	if(m_protocols_enabled)
	{
		it_analyzer->second.m_metrics.m_protostate->to_protobuf(container->mutable_protos(), m_sampling_ratio, CONTAINERS_PROTOS_TOP_LIMIT);
	}

	it_analyzer->second.m_req_metrics.to_reqprotobuf(container->mutable_reqcounters(), m_sampling_ratio);

	it_analyzer->second.m_transaction_counters.to_protobuf(container->mutable_transaction_counters(),
														   container->mutable_min_transaction_counters(),
														   container->mutable_max_transaction_counters(),
														   m_sampling_ratio);

	m_delay_calculator->compute_host_container_delays(&it_analyzer->second.m_transaction_counters,
													  &it_analyzer->second.m_client_transactions, &it_analyzer->second.m_server_transactions,
													  &it_analyzer->second.m_transaction_delays);

	if(it_analyzer->second.m_transaction_delays.m_local_processing_delay_ns != -1)
	{
		container->set_transaction_processing_delay(it_analyzer->second.m_transaction_delays.m_local_processing_delay_ns * m_sampling_ratio);
		container->set_next_tiers_delay(it_analyzer->second.m_transaction_delays.m_merged_client_delay * m_sampling_ratio);
	}
#ifndef _WIN32
	if(m_statsd_metrics.find(it->second.m_id) != m_statsd_metrics.end())
	{
		auto statsd_emitted = emit_statsd(m_statsd_metrics.at(it->second.m_id), container->mutable_protos()->mutable_statsd(), *statsd_limit);
		*statsd_limit -= statsd_emitted;
	}
#endif
	auto fs_list = m_mounted_fs_map.find(it->second.m_id);
	if(fs_list != m_mounted_fs_map.end())
	{
		for(auto it = fs_list->second.begin(); it != fs_list->second.end(); ++it)
		{
			auto proto_fs = container->add_mounts();
			it->to_protobuf(proto_fs);
		}
	}

	sinsp_connection_aggregator::filter_and_emit(*it_analyzer->second.m_connections_by_serverport,
												 container, TOP_SERVER_PORTS_IN_SAMPLE_PER_CONTAINER, m_sampling_ratio);

	it_analyzer->second.clear();
}

void sinsp_analyzer::get_statsd()
{
#ifndef _WIN32
	if (m_statsite_proxy)
	{
		// Look for statsite sample m_prev_flush_time_ns (now) - 1s which should be
		// always ready
		auto look_for_ts = ((m_prev_flush_time_ns - ONE_SECOND_IN_NS) / ONE_SECOND_IN_NS);
		if(m_statsd_metrics.empty())
		{
			m_statsd_metrics = m_statsite_proxy->read_metrics();
		}
		while(!m_statsd_metrics.empty() && m_statsd_metrics.begin()->second.at(0).timestamp() < look_for_ts)
		{
			m_statsd_metrics = m_statsite_proxy->read_metrics();
		}
	}
#endif
}

#ifndef _WIN32
unsigned sinsp_analyzer::emit_statsd(const vector <statsd_metric> &statsd_metrics, draiosproto::statsd_info *statsd_info,
					   unsigned limit)
{
	unsigned j = 0;
	for(const auto& metric : statsd_metrics)
	{
		if(j >= limit)
		{
			g_logger.log("statsd metrics limit reached, skipping remaining ones", sinsp_logger::SEV_WARNING);
			break;
		}
		auto statsd_proto = statsd_info->add_statsd_metrics();
		metric.to_protobuf(statsd_proto);
		++j;
	}
	if (j > 0)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Added %d statsd metrics", j);
	}
	return j;
}
#endif

void sinsp_analyzer::emit_chisel_metrics()
{
	uint32_t j = 0;

	m_chisel_metrics.clear();

	for(const auto& chisel : m_chisels)
	{
		chisel->do_end_of_sample();
	}

	for(const auto& metric : m_chisel_metrics)
	{
		auto statsd_proto = m_metrics->mutable_protos()->mutable_statsd()->add_statsd_metrics();
		metric.to_protobuf(statsd_proto);
		++j;

		if(j >= CHISEL_METRIC_LIMIT)
		{
			g_logger.log("statsd metrics limit reached, skipping remaining ones", sinsp_logger::SEV_WARNING);
			break;
		}
	}

	if(j > 0)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Added %d chisel metrics", j);
	}
}

void sinsp_analyzer::emit_user_events()
{
	if(m_user_event_queue && m_user_event_queue->count())
	{
		sinsp_user_event evt;
		while(m_user_event_queue->get(evt))
		{
			auto user_event = m_metrics->add_events();
			user_event->set_timestamp_sec(evt.epoch_time_s());
			user_event->set_severity(evt.severity());
			const string& n = evt.name();
			if(!n.empty())
			{
				user_event->set_title(n);
			}
			const string& desc = evt.description();
			if(!desc.empty())
			{
				user_event->set_description(desc);
			}
			const string& sc = evt.scope();
			if(!sc.empty())
			{
				user_event->set_scope(sc);
			}
			for(const auto& p : evt.tags())
			{
				auto tags = user_event->add_tags();
				tags->set_key(p.first);
				tags->set_value(p.second);
			}
		}
		if(m_k8s)
		{
			m_k8s->clear_events();
		}
		if(m_docker)
		{
			m_docker->reset_event_counter();
		}
		if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
		{
			std::ostringstream ostr;
			ostr << "User event Proto:" << std::endl;
			for(const auto& e : m_metrics->events())
			{
				ostr << e.DebugString() << std::endl;
			}
			g_logger.log(ostr.str(), sinsp_logger::SEV_TRACE);
		}
	}
}

#define MR_UPDATE_POS { if(len == -1) return -1; pos += len;}

int32_t sinsp_analyzer::generate_memory_report(OUT char* reportbuf, uint32_t reportbuflen, bool do_complete_report)
{
	int len;
	uint32_t pos = 0;
	uint32_t nfds = 0;
	uint32_t nfds_file = 0;
	uint32_t nfds_ipv4 = 0;
	uint32_t nfds_ipv6 = 0;
	uint32_t nfds_dir = 0;
	uint32_t nfds_ipv4s = 0;
	uint32_t nfds_ipv6s = 0;
	uint32_t nfds_fifo = 0;
	uint32_t nfds_unix = 0;
	uint32_t nfds_event = 0;
	uint32_t nfds_unknown = 0;
	uint32_t nfds_unsupported = 0;
	uint32_t nfds_signal = 0;
	uint32_t nfds_evtpoll = 0;
	uint32_t nfds_inotify = 0;
	uint32_t nfds_timerfd = 0;
	uint32_t ntransactions = 0;
	uint32_t ntransactions_http = 0;
	uint32_t ntransactions_mysql = 0;
	uint32_t ntransactions_postgres = 0;
	uint32_t ntransactions_mongodb = 0;
	uint32_t nqueuedtransactions_client = 0;
	uint32_t nqueuedtransactions_server = 0;
	uint32_t nqueuedtransactions_client_capacity = 0;
	uint32_t nqueuedtransactions_server_capacity = 0;

	len = snprintf(reportbuf + pos, reportbuflen - pos,
		"threads: %d\n", (int)m_inspector->m_thread_manager->m_threadtable.size());
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"connections: %d\n", (int)m_ipv4_connections->size());
	MR_UPDATE_POS;

	for(auto it = m_inspector->m_thread_manager->m_threadtable.begin();
		it != m_inspector->m_thread_manager->m_threadtable.end(); ++it)
	{
		thread_analyzer_info* ainfo = it->second.m_ainfo;

		for(uint32_t j = 0; j < ainfo->m_dynstate->m_server_transactions_per_cpu.size(); j++)
		{
			nqueuedtransactions_server += ainfo->m_dynstate->m_server_transactions_per_cpu[j].size();
			nqueuedtransactions_server_capacity +=
				ainfo->m_dynstate->m_server_transactions_per_cpu[j].capacity();
		}

		for(uint32_t j = 0; j < ainfo->m_dynstate->m_client_transactions_per_cpu.size(); j++)
		{
			nqueuedtransactions_client += ainfo->m_dynstate->m_client_transactions_per_cpu[j].size();
			nqueuedtransactions_client_capacity +=
				ainfo->m_dynstate->m_client_transactions_per_cpu[j].capacity();
		}

		if(do_complete_report)
		{
			len =  snprintf(reportbuf + pos, reportbuflen - pos,
				"    tid: %d comm: %s nfds:%d\n", (int)it->first, it->second.m_comm.c_str(), (int)it->second.m_fdtable.size());
			MR_UPDATE_POS;
		}

		for(auto fdit = it->second.m_fdtable.m_table.begin();
			fdit != it->second.m_fdtable.m_table.end(); ++fdit)
		{
			nfds++;

			switch(fdit->second.m_type)
			{
				case SCAP_FD_FILE:
					nfds_file++;
					break;
				case SCAP_FD_IPV4_SOCK:
					nfds_ipv4++;
					break;
				case SCAP_FD_IPV6_SOCK:
					nfds_ipv6++;
					break;
				case SCAP_FD_DIRECTORY:
					nfds_dir++;
					break;
				case SCAP_FD_IPV4_SERVSOCK:
					nfds_ipv4s++;
					break;
				case SCAP_FD_IPV6_SERVSOCK:
					nfds_ipv6s++;
					break;
				case SCAP_FD_FIFO:
					nfds_fifo++;
					break;
				case SCAP_FD_UNIX_SOCK:
					nfds_unix++;
					break;
				case SCAP_FD_EVENT:
					nfds_event++;
					break;
				case SCAP_FD_UNKNOWN:
					nfds_unknown++;
					break;
				case SCAP_FD_UNSUPPORTED:
					nfds_unsupported++;
					break;
				case SCAP_FD_SIGNALFD:
					nfds_signal++;
					break;
				case SCAP_FD_EVENTPOLL:
					nfds_evtpoll++;
					break;
				case SCAP_FD_INOTIFY:
					nfds_inotify++;
					break;
				case SCAP_FD_TIMERFD:
					nfds_timerfd++;
					break;
				default:
					nfds_unknown++;
			}

			if(fdit->second.is_transaction())
			{
				ntransactions++;

				if(fdit->second.m_usrstate != NULL)
				{
					if(fdit->second.m_usrstate->m_protoparser != NULL)
					{
						switch(fdit->second.m_usrstate->m_protoparser->get_type())
						{
						case sinsp_protocol_parser::PROTO_HTTP:
							ntransactions_http++;
							break;
						case sinsp_protocol_parser::PROTO_MYSQL:
							ntransactions_mysql++;
							break;
						case sinsp_protocol_parser::PROTO_POSTGRES:
							ntransactions_postgres++;
							break;
						case sinsp_protocol_parser::PROTO_MONGODB:
							ntransactions_mongodb++;
							break;
						case sinsp_protocol_parser::PROTO_TLS:
							break;
						default:
							ASSERT(false);
							break;
						}
					}
				}
			}
		}
	}

	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"FDs: %d\n", (int)nfds);
	MR_UPDATE_POS;

	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  ipv4: %d\n", (int)nfds_ipv4);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  ipv6: %d\n", (int)nfds_ipv6);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  dir: %d\n", (int)nfds_dir);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  ipv4s: %d\n", (int)nfds_ipv4s);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  ipv6s: %d\n", (int)nfds_ipv6s);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  fifo: %d\n", (int)nfds_fifo);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  unix: %d\n", (int)nfds_unix);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  event: %d\n", (int)nfds_event);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  file: %d\n", (int)nfds_file);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  unknown: %d\n", (int)nfds_unknown);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  unsupported: %d\n", (int)nfds_unsupported);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  signal: %d\n", (int)nfds_signal);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  evtpoll: %d\n", (int)nfds_evtpoll);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  inotify: %d\n", (int)nfds_inotify);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  timerfd: %d\n", (int)nfds_timerfd);
	MR_UPDATE_POS;

	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"transactions: %d\n", (int)ntransactions);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  http: %d\n", (int)ntransactions_http);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  mysql: %d\n", (int)ntransactions_mysql);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  postgres: %d\n", (int)ntransactions_postgres);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  mongodb: %d\n", (int)ntransactions_mongodb);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  queued client: %d\n", (int)nqueuedtransactions_client);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  queued server: %d\n", (int)nqueuedtransactions_server);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  queue client capacity: %d\n", (int)nqueuedtransactions_client_capacity);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos,
		"  queue server capacity: %d\n", (int)nqueuedtransactions_server_capacity);
	MR_UPDATE_POS;

	//fprintf(stdout, "%s", reportbuf);
	return pos;
}

void sinsp_analyzer::set_autodrop_enabled(bool enabled)
{
	m_configuration->set_autodrop_enabled(enabled);
	m_seconds_above_thresholds = 0;
	m_seconds_below_thresholds = 0;
}

void sinsp_analyzer::stop_dropping_mode()
{
	m_inspector->stop_dropping_mode();
	m_driver_stopped_dropping = false;

	if(m_falco_engine)
	{
		m_falco_engine->set_sampling_ratio(1);
	}
}

void sinsp_analyzer::start_dropping_mode(uint32_t sampling_ratio)
{
	m_inspector->start_dropping_mode(sampling_ratio);

	if(m_falco_engine)
	{
		m_falco_engine->set_sampling_ratio(sampling_ratio);
	}
}

bool sinsp_analyzer::driver_stopped_dropping()
{
	return m_driver_stopped_dropping;
}

#ifndef _WIN32
void sinsp_analyzer::set_statsd_iofds(pair<FILE *, FILE *> const &iofds)
{
	m_statsite_proxy = make_unique<statsite_proxy>(iofds);
}
#endif // _WIN32

void sinsp_analyzer::set_fs_usage_from_external_proc(bool value)
{
	if(value)
	{
		m_mounted_fs_proxy = make_unique<mounted_fs_proxy>();
	}
	else
	{
		m_mounted_fs_proxy.reset();
	}
}

void sinsp_analyzer::enable_falco(const string &default_rules_filename,
				  const string &auto_rules_filename,
				  const string &rules_filename,
				  set<string> &disabled_rule_patterns,
				  double sampling_multiplier)
{
	bool verbose = false;
	bool all_events = true;

	m_falco_engine = make_unique<falco_engine>();
	m_falco_engine->set_inspector(m_inspector);
	m_falco_engine->set_sampling_multiplier(sampling_multiplier);

	// If the auto rules file exists, it is loaded instead of the
	// default rules file
	Poco::File auto_rules_file(auto_rules_filename);
	if(auto_rules_file.exists())
	{
		m_falco_engine->load_rules_file(auto_rules_filename, verbose, all_events);
	}
	else
	{
		m_falco_engine->load_rules_file(default_rules_filename, verbose, all_events);
	}

	//
	// Only load the user rules file if it exists
	//
	Poco::File user_rules_file(rules_filename);
	if(user_rules_file.exists())
	{
		m_falco_engine->load_rules_file(rules_filename, verbose, all_events);
	}

	for (auto pattern : disabled_rule_patterns)
	{
		m_falco_engine->enable_rule(pattern, false);
	}

	m_falco_events = make_unique<falco_events>();
	m_falco_events->init(m_inspector, m_configuration->get_machine_id());
}

void sinsp_analyzer::disable_falco()
{
	m_falco_engine = NULL;
	m_falco_events = NULL;
}

uint64_t self_cputime_analyzer::read_cputime()
{
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	uint64_t total_cputime_us = ru.ru_utime.tv_sec*1000000 + ru.ru_utime.tv_usec +
								ru.ru_stime.tv_sec*1000000 + ru.ru_stime.tv_usec;
	auto ret = total_cputime_us - m_previouscputime;
	m_previouscputime = total_cputime_us;
	return ret;
}

void self_cputime_analyzer::begin_flush()
{
	auto cputime = read_cputime();
	m_othertime[m_index] = cputime;
}

void self_cputime_analyzer::end_flush()
{
	auto cputime = read_cputime();
	m_flushtime[m_index] = cputime;
	incr_index();
}

double self_cputime_analyzer::calc_flush_percent()
{
	double tot_flushtime = accumulate(m_flushtime.begin(), m_flushtime.end(), 0);
	double tot_othertime = accumulate(m_othertime.begin(), m_othertime.end(), 0);
	return tot_flushtime/(tot_flushtime+tot_othertime);
}

// This method is here because analyzer_container_state has not a .cpp file and
// adding it just for this constructor seemed an overkill
analyzer_container_state::analyzer_container_state()
{
	m_connections_by_serverport = make_unique<decltype(m_connections_by_serverport)::element_type>();
	m_last_bytes_in = 0;
	m_last_bytes_out = 0;
}

void analyzer_container_state::clear()
{
	m_metrics.clear();
	m_req_metrics.clear();
	m_transaction_counters.clear();
	m_transaction_delays.clear();
	m_server_transactions.clear();
	m_client_transactions.clear();
	m_connections_by_serverport->clear();
}

#endif // HAS_ANALYZER
