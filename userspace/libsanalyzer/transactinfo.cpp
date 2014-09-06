#include <algorithm>

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

#define VISIBILITY_PRIVATE

#include "sinsp.h"
#include "sinsp_int.h"
#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#include "analyzer_int.h"
#include "connectinfo.h"
#include "analyzer_thread.h"
#include "parser_http.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_transact_table implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_transaction_table::sinsp_transaction_table(sinsp* inspector)
{
	m_inspector = inspector;
	m_n_client_transactions = 0;
	m_n_server_transactions = 0;
}

sinsp_transaction_table::~sinsp_transaction_table()
{
}

bool sinsp_transaction_table::is_transaction_server(sinsp_threadinfo *ptinfo)
{
	if(ptinfo->m_ainfo->m_transaction_metrics.get_counter()->m_count_in >= TRANSACTION_SERVER_EURISTIC_MIN_CONNECTIONS &&
		ptinfo->m_ainfo->m_transaction_metrics.get_counter()->m_time_ns_in / ptinfo->m_ainfo->m_transaction_metrics.get_counter()->m_count_in < TRANSACTION_SERVER_EURISTIC_MAX_DELAY_NS)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_transaction_table::emit(sinsp_threadinfo* ptinfo,
								   void* fdinfo,
								   sinsp_connection* pconn,
								   sinsp_partial_transaction* tr
#if _DEBUG
									, sinsp_evt *evt,
									uint64_t fd,
									uint64_t ts
#endif
									)
{
	unordered_map<int64_t, vector<sinsp_transaction > >::iterator it;

	sinsp_partial_transaction::direction startdir;
	sinsp_partial_transaction::direction enddir;

	sinsp_fdinfo_t* ffdinfo = (sinsp_fdinfo_t*)fdinfo; 

	//
	// Detect the side and and determine the trigger directions
	//
	ASSERT(ffdinfo->m_flags & (sinsp_fdinfo_t::FLAGS_ROLE_CLIENT | sinsp_fdinfo_t::FLAGS_ROLE_SERVER));
	if(ffdinfo->m_flags & sinsp_fdinfo_t::FLAGS_ROLE_SERVER)
	{
		startdir = sinsp_partial_transaction::DIR_IN;
		enddir = sinsp_partial_transaction::DIR_OUT;
	}
	else
	{
		startdir = sinsp_partial_transaction::DIR_OUT;
		enddir = sinsp_partial_transaction::DIR_IN;
	}

	//
	// Based on the direction, add the transaction
	//
	if(tr->m_prev_direction == startdir)
	{
		tr->m_prev_prev_start_time = tr->m_prev_start_time;
		tr->m_prev_prev_end_time = tr->m_prev_end_time;
		tr->m_prev_prev_start_of_transaction_time = tr->m_prev_start_of_transaction_time;
	}
	else if(tr->m_prev_direction == enddir ||
	        tr->m_prev_direction == sinsp_partial_transaction::DIR_CLOSE)
	{
		if(tr->m_prev_prev_start_time == 0)
		{
			//
			// This can happen if we drop events or if a connection
			// starts with a write, which can happen with fucked up protocols
			// like the mysql one
			//
			return;
		}

		//
		// Update the metrics related to this transaction
		//
		ASSERT(ptinfo != NULL);
		ASSERT(tr->m_prev_end_time > tr->m_prev_prev_start_of_transaction_time);

		uint64_t delta = tr->m_prev_end_time - tr->m_prev_prev_start_of_transaction_time;
		sinsp_threadinfo* tinfo = ptinfo->m_ainfo->get_main_program_thread();
		ASSERT(tinfo != NULL);
		sinsp_threadinfo* proginfo = ptinfo->m_ainfo->get_main_program_thread();
		ASSERT(proginfo != NULL);

		if(ffdinfo->m_flags & sinsp_fdinfo_t::FLAGS_ROLE_SERVER)
		{
			bool isexternal = pconn->is_server_only();
			m_n_server_transactions++;

			if(ffdinfo->m_type == SCAP_FD_IPV4_SOCK)
			{
				if(isexternal)
				{
					ptinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER;
				}
				else
				{
					ptinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER;
				}
			}
			else if(ffdinfo->m_type == SCAP_FD_UNIX_SOCK)
			{
				ptinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_UNIX_SERVER;
			}
			else
			{
				ASSERT(false);
			}

			ptinfo->m_ainfo->m_transaction_metrics.add_in(1, delta);
			pconn->m_transaction_metrics.add_in(1, delta);

			if(isexternal)
			{
				ptinfo->m_ainfo->m_external_transaction_metrics.add_in(1, delta);
			}

			if(tinfo != NULL && proginfo != NULL)
			{
				proginfo->m_ainfo->add_completed_server_transaction(tr, isexternal);

				if(tr->m_protoparser != NULL)
				{
					tr->update_proto_tables(proginfo->m_ainfo->m_procinfo, delta, true);
				}
			}
		}
		else
		{
			bool isexternal = pconn->is_client_only();
			m_n_client_transactions++;

			if(ffdinfo->m_type == SCAP_FD_IPV4_SOCK)
			{
				if(isexternal)
				{
					ptinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT;
				}
				else
				{
					ptinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT;
				}
			}
			else if(ffdinfo->m_type == SCAP_FD_UNIX_SOCK)
			{
				ptinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_UNIX_CLIENT;
			}
			else
			{
				ASSERT(false);
			}

			ptinfo->m_ainfo->m_transaction_metrics.add_out(1, delta);
			pconn->m_transaction_metrics.add_out(1, delta);

			if(isexternal)
			{
				ptinfo->m_ainfo->m_external_transaction_metrics.add_out(1, delta);
			}

			if(tinfo != NULL && proginfo != NULL)
			{
				proginfo->m_ainfo->add_completed_client_transaction(tr, isexternal);

				if(tr->m_protoparser != NULL)
				{
					tr->update_proto_tables(proginfo->m_ainfo->m_procinfo, delta, false);
				}
			}
		}

//
// NOTE: this is disabled because for the moment we only gather summaries about
//       transaction activity, not every single transaction.
#if 0
		//
		// Init the new table entry
		//
		sinsp_transaction tfi;
		tfi.m_trinfo = *tr;

		tfi.m_trinfo.m_start_time = tfi.m_trinfo.m_prev_start_time;
		tfi.m_trinfo.m_end_time = tfi.m_trinfo.m_prev_end_time;
		tfi.m_trinfo.m_prev_start_time = tr->m_prev_prev_start_time;
		tfi.m_trinfo.m_prev_end_time = tr->m_prev_prev_end_time;

		if(ptinfo)
		{
			tfi.m_pid = ptinfo->m_pid;
			tfi.m_comm = ptinfo->get_comm();
			if(tfi.m_trinfo.is_unix_flow())
			{
				string &name = ptinfo->get_fd(tr->m_fd)->m_name;
				tfi.m_fd_desc = name.substr(name.find_first_of(' ') + 1);
			}
		}
		else
		{
			tfi.m_pid = -1;
			tfi.m_comm = "";
			tfi.m_fd_desc = "";
			ASSERT(false);
		}

		//
		// Get the connection information and, if we get it, resolve the other
		// endpoint's process info
		//
		if(pconn)
		{
			tfi.m_peer_tid = pconn->m_stid;
			tfi.m_peer_fd = pconn->m_sfd;
			tfi.m_peer_pid = pconn->m_spid;
			tfi.m_peer_comm = pconn->m_scomm;
		}
		else
		{
			tfi.m_peer_tid = -1;
			tfi.m_peer_fd = -1;
			tfi.m_peer_pid = -1;
			tfi.m_peer_comm = "";
			ASSERT(false);
		}

		//
		// Add the entry to the table
		//
		it = m_table.find(tr->m_tid);
		if(it == m_table.end())
		{
			vector<sinsp_transaction> tv;

			tv.push_back(tfi);
			m_table[tr->m_tid] = tv;
		}
		else
		{
			it->second.push_back(tfi);
		}

		
		 Mark the transaction as done
#endif		

		tr->m_prev_prev_start_time = 0;
	}
}

uint32_t sinsp_transaction_table::get_size()
{
	uint32_t res = 0;
	unordered_map<int64_t, vector<sinsp_transaction > >::iterator it;

	// first try to find exact match
	for(it = m_table.begin(); it != m_table.end(); it++)
	{
		res += (uint32_t)it->second.size();
	}

	return res;
}

void sinsp_transaction_table::clear()
{
	m_table.clear();
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_transactinfo implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_partial_transaction::sinsp_partial_transaction()
{
	m_protoparser = NULL;
	reset();
}

void sinsp_partial_transaction::reset()
{
	m_type = TYPE_UNKNOWN;
	m_direction = DIR_UNKNOWN;
	m_start_time = 0;
	m_end_time = 0;
	m_prev_direction = DIR_UNKNOWN;
	m_prev_start_time = 0;
	m_prev_end_time = 0;
	m_prev_prev_start_time = 0;
	m_prev_prev_end_time = 0;
	m_cpuid = -1;
	m_start_of_transaction_time = 0;
	m_prev_start_of_transaction_time = 0;
	m_prev_prev_start_of_transaction_time = 0;
	m_is_active = false;
}

sinsp_partial_transaction::~sinsp_partial_transaction()
{
	if(m_protoparser)
	{
		if(m_type == TYPE_HTTP)
		{
			delete (sinsp_http_parser*)m_protoparser;			
		}
		else
		{
			ASSERT(false);
			throw sinsp_exception("unsupported transaction protocol");
		}
		
		m_protoparser = NULL;
	}
}

inline sinsp_partial_transaction::updatestate sinsp_partial_transaction::update_int(sinsp_threadinfo* ptinfo,
		uint64_t enter_ts,
		uint64_t exit_ts, 
		direction dir,
		char* data,
		uint32_t original_len,
		uint32_t len,
		bool is_server)
{
	if(dir == DIR_IN)
	{
		m_incoming_bytes += len;

		if(m_direction != DIR_IN)
		{
			updatestate res;

			if(m_direction == DIR_UNKNOWN)
			{
				res = STATE_ONGOING;
			}
			else
			{
				m_prev_direction = m_direction;
				m_prev_start_time = m_start_time;
				m_prev_end_time = m_end_time;
				m_incoming_bytes = len;
				m_prev_start_of_transaction_time = m_start_of_transaction_time;
				res = STATE_SWITCHED;
			}

			m_start_time = enter_ts;
			m_end_time = exit_ts;
			if(len != 0)
			{
				m_direction = dir;

				if(m_incoming_bytes == len)
				{
					m_start_of_transaction_time = exit_ts;
				}
			}
			else
			{
				m_direction = DIR_UNKNOWN;
			}

			return res;
		}
		else
		{
			ASSERT(exit_ts >= m_end_time);

			if(is_server)
			{
				if(exit_ts - m_end_time > TRANSACTION_READ_LIMIT_NS)
				{
					//
					// This server-side transaction has stopped on a read for 
					// a long time. We assume it's not a client server transaction
					// (it could be an upload or a peer to peer application)
					// and we drop it.
					//
					return STATE_NO_TRANSACTION;
				}
			}

			m_end_time = exit_ts;
			return STATE_ONGOING;
		}
	}
	else if(dir == DIR_OUT)
	{
		m_outgoing_bytes += len;

		if(m_direction != DIR_OUT)
		{
			updatestate res;

			if(m_direction == DIR_UNKNOWN)
			{
				res = STATE_ONGOING;
			}
			else
			{
				m_prev_direction = m_direction;
				m_prev_start_time = m_start_time;
				m_prev_end_time = m_end_time;
				m_outgoing_bytes = len;
				m_prev_start_of_transaction_time = m_start_of_transaction_time;
				res = STATE_SWITCHED;
			}

			m_start_time = enter_ts;
			m_end_time = exit_ts;
			if(len != 0)
			{
				m_direction = dir;

				if(m_outgoing_bytes == len)
				{
					m_start_of_transaction_time = exit_ts;
				}
			}
			else
			{
				m_direction = DIR_UNKNOWN;
			}

			return res;
		}
		else
		{
			ASSERT(exit_ts >= m_end_time);

			if(!is_server)
			{
				if(exit_ts - m_end_time > TRANSACTION_READ_LIMIT_NS)
				{
					//
					// This client-side transaction has stopped on a write for 
					// a long time. We assume it's not a client server transaction
					// (it could be an upload or a peer to peer application)
					// and we drop it.
					//
					return STATE_NO_TRANSACTION;
				}
			}

			m_end_time = exit_ts;
			return STATE_ONGOING;
		}
	}
	else if(dir == DIR_CLOSE)
	{
		m_prev_direction = m_direction;
		m_prev_start_time = m_start_time;
		m_prev_end_time = m_end_time;
		m_prev_start_of_transaction_time = m_start_of_transaction_time;

		m_direction = DIR_UNKNOWN;
		return STATE_SWITCHED;
	}
	else
	{
		ASSERT(false);
		return STATE_ONGOING;
	}
}

void sinsp_partial_transaction::update(sinsp_analyzer* analyzer, 
	sinsp_threadinfo* ptinfo,
	void* fdinfo,
	sinsp_connection* pconn,
	uint64_t enter_ts, 
	uint64_t exit_ts, 
	int32_t cpuid,
	direction dir, 
#if _DEBUG
		sinsp_evt *evt,
		uint64_t fd,
#endif
	char* data,
	uint32_t original_len, 
	uint32_t len)
{
	if(pconn == NULL)
	{
		mark_inactive();
		return;
	}

	if(cpuid != -1)
	{
		m_cpuid = cpuid;
	}

	sinsp_fdinfo_t* ffdinfo = (sinsp_fdinfo_t*)fdinfo; 

	sinsp_partial_transaction::updatestate res = update_int(ptinfo, 
		enter_ts, exit_ts, dir, data, len, 
		original_len, ffdinfo->is_role_server());
	if(res == STATE_SWITCHED)
	{
		m_tid = ptinfo->m_tid;
		analyzer->m_trans_table->emit(ptinfo, fdinfo, pconn, this 
#if _DEBUG
			, evt, fd, exit_ts 
#endif	
			);
	}
	else if(res == STATE_NO_TRANSACTION)
	{
		reset();
		return;
	}

	if(m_protoparser != NULL && len >= MIN_VALID_PROTO_BUF_SIZE)
	{
		if(m_protoparser->is_request(data, len))
		{
/*
			sinsp_protocol_parser* tpp;
			tpp = m_protoparser;
			m_protoparser = m_protoparser_old;
			m_protoparser_old = tpp;
*/
			if(m_protoparser->parse_request(data, len))
			{
//				ptinfo->m_ainfo->m_transactions_in_progress.push_back(this);
			}
		}
		else
		{
			m_protoparser->parse_response(data, len);
		}
	}
}

void sinsp_partial_transaction::mark_active_and_reset(sinsp_partial_transaction::type newtype)
{
	m_type = newtype;
	m_incoming_bytes = 0;
	m_outgoing_bytes = 0;
	m_is_active = true;
}

void sinsp_partial_transaction::mark_inactive()
{
	m_is_active = false;
}

inline void sinsp_partial_transaction::update_proto_tables(sinsp_procinfo* mt_procinfo,
														   uint64_t time_delta,
														   bool is_server)
{
	ASSERT(mt_procinfo != NULL);

	if(m_type == TYPE_HTTP)
	{
		ASSERT(m_protoparser != NULL);

		if(m_protoparser->m_is_valid)
		{
			sinsp_http_parser* pp = (sinsp_http_parser*)m_protoparser;
			sinsp_url_info* entry;

			if(is_server)
			{
				entry = &(mt_procinfo->m_server_urls[pp->m_url]);
			}
			else
			{
				entry = &(mt_procinfo->m_client_urls[pp->m_url]);
			}

			if(entry->m_ncalls == 0)
			{
				entry->m_ncalls = 1;
				entry->m_time_tot = time_delta;
				entry->m_time_min = time_delta;
				entry->m_time_max = time_delta;
			}
			else
			{
				entry->m_ncalls++;
				entry->m_time_tot += time_delta;
				entry->m_time_min += time_delta;
				entry->m_time_max += time_delta;
			}

		}
	}
}

#endif
