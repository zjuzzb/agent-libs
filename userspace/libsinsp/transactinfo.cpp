#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer.h"

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
	if(ptinfo->m_transaction_metrics.m_counter.m_count_in >= TRANSACTION_SERVER_EURISTIC_MIN_CONNECTIONS &&
		ptinfo->m_transaction_metrics.m_counter.m_time_ns_in / ptinfo->m_transaction_metrics.m_counter.m_count_in < TRANSACTION_SERVER_EURISTIC_MAX_DELAY_NS)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_transaction_table::emit(sinsp_threadinfo *ptinfo,
								   sinsp_connection *pconn,
								   sinsp_partial_transaction *tr,
								   uint32_t len)
{
	unordered_map<int64_t, vector<sinsp_transaction > >::iterator it;

	sinsp_partial_transaction::direction startdir;
	sinsp_partial_transaction::direction enddir;

	//
	// Detect the side and and determine the trigger directions
	//
	ASSERT(tr->m_side != sinsp_partial_transaction::SIDE_UNKNOWN);
	if(tr->m_side == sinsp_partial_transaction::SIDE_SERVER)
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

		if(tr->m_side == sinsp_partial_transaction::SIDE_SERVER)
		{
			m_n_server_transactions++;
			ptinfo->m_th_analysis_flags |= sinsp_threadinfo::AF_IS_SERVER;
			ptinfo->m_transaction_metrics.m_counter.add_in(1, delta);
			pconn->m_transaction_metrics.m_counter.add_in(1, delta);

			m_inspector->m_analyzer->m_transactions_with_cpu.push_back(
				pair<uint64_t,pair<uint64_t, uint16_t>>(tr->m_prev_prev_start_of_transaction_time, 
				pair<uint64_t,uint16_t>(tr->m_prev_end_time, tr->m_cpuid)));

			m_inspector->m_analyzer->m_server_transactions_per_cpu[tr->m_cpuid].push_back(
				pair<uint64_t, uint64_t>(tr->m_prev_prev_start_of_transaction_time, 
				tr->m_prev_end_time));
		}
		else
		{
			m_n_client_transactions++;
			ptinfo->m_transaction_metrics.m_counter.add_out(1, delta);
			pconn->m_transaction_metrics.m_counter.add_out(1, delta);
/*
			if(ptinfo->m_th_analysis_flags & sinsp_threadinfo::AF_IS_SERVER)
			{
				m_inspector->m_analyzer->m_out_transactions_by_server_per_cpu[tr->m_cpuid].push_back(
					pair<uint64_t, uint64_t>(tr->m_prev_prev_start_of_transaction_time, 
					tr->m_prev_end_time));
			}
*/
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

#define CHECK_FPRINTF(p) if (p < 0) { throw sinsp_exception("can't write to stream"); }

void sinsp_transaction_table::print_on(FILE *stream)
{

	uint32_t j;
	unordered_map<int64_t, vector<sinsp_transaction > >::iterator it;
	uint32_t nfilelines = 0;
	uint32_t ntranslines;

	CHECK_FPRINTF(fprintf(stream, "{\n"));

	for(it = m_table.begin(); it != m_table.end(); it++)
	{
		vector<sinsp_transaction> &trv = it->second;
		ntranslines = 0;

		CHECK_FPRINTF(fprintf(stream,
		                      "%s\"%" PRIu64 "\": [\n",
		                      (nfilelines == 0) ? "" : ",\n",
		                      it->first
		                     ));

		for(j = 0; j < trv.size(); j++)
		{
			sinsp_transaction &tfi = trv[j];
			sinsp_partial_transaction &tr = tfi.m_trinfo;
			if(tr.is_ipv4_flow())
			{
				CHECK_FPRINTF(fprintf(stream,
				                      "%s {\"sip\":\"%u.%u.%u.%u\", \"sport\":%u, \"dip\":\"%u.%u.%u.%u\", \"dport\":%u, \"is\":%" PRIu64 ", \"ie\":%" PRIu64 ", \"os\":%" PRIu64 ", \"oe\":%" PRIu64 "%s%s",
				                      (ntranslines == 0) ? "" : ",\n",
				                      (unsigned int)(*(uint8_t *)&tr.m_ipv4_flow.m_fields.m_sip),
				                      (unsigned int)(*(((uint8_t *)&tr.m_ipv4_flow.m_fields.m_sip) + 1)),
				                      (unsigned int)(*(((uint8_t *)&tr.m_ipv4_flow.m_fields.m_sip) + 2)),
				                      (unsigned int)(*(((uint8_t *)&tr.m_ipv4_flow.m_fields.m_sip) + 3)),
				                      (unsigned int)tr.m_ipv4_flow.m_fields.m_sport,
				                      (unsigned int)(*(uint8_t *)&tr.m_ipv4_flow.m_fields.m_dip),
				                      (unsigned int)(*(((uint8_t *)&tr.m_ipv4_flow.m_fields.m_dip) + 1)),
				                      (unsigned int)(*(((uint8_t *)&tr.m_ipv4_flow.m_fields.m_dip) + 2)),
				                      (unsigned int)(*(((uint8_t *)&tr.m_ipv4_flow.m_fields.m_dip) + 3)),
				                      (unsigned int)tr.m_ipv4_flow.m_fields.m_dport,
				                      tr.m_prev_start_time,
				                      tr.m_prev_end_time,
				                      tr.m_start_time,
				                      tr.m_end_time,
				                      (tr.m_type != sinsp_partial_transaction::TYPE_HTTP) ? "" : (string(", \"url\":\"") + tr.m_protoinfo[0] + "\"").c_str(),
				                      (!((tr.m_type == sinsp_partial_transaction::TYPE_HTTP) && (tr.m_protoinfo.size() > 1))) ? "" : (string(", \"agent\":\"") + tr.m_protoinfo[1] + "\"").c_str()
				                     ));
			}
			else
			{
				CHECK_FPRINTF(fprintf(stream,
				                      "%s {\"name\":\"%s\",\"is\":%" PRIu64 ", \"ie\":%" PRIu64 ", \"os\":%" PRIu64 ", \"oe\":%" PRIu64 "%s%s",
				                      (ntranslines == 0) ? "" : ",\n",
				                      tfi.m_fd_desc.c_str(),
				                      tr.m_prev_start_time,
				                      tr.m_prev_end_time,
				                      tr.m_start_time,
				                      tr.m_end_time,
				                      (tr.m_type != sinsp_partial_transaction::TYPE_HTTP) ? "" : (string(", \"url\":\"") + tr.m_protoinfo[0] + "\"").c_str(),
				                      (!((tr.m_type == sinsp_partial_transaction::TYPE_HTTP) && (tr.m_protoinfo.size() > 1))) ? "" : (string(", \"agent\":\"") + tr.m_protoinfo[1] + "\"").c_str()
				                     ));
			}
			CHECK_FPRINTF(fprintf(stream,
			                      ", \"proc\":{\"pid\":%" PRId64 ", \"name\":\"%s\", \"fd\":%" PRId64 "}",
			                      tfi.m_pid,
			                      tfi.m_comm.c_str(),
			                      tr.m_fd));
			CHECK_FPRINTF(fprintf(stream,
			                      ", \"rproc\":{\"tid\":%" PRId64 ", \"pid\":%" PRId64 ", \"name\":\"%s\", \"fd\":%" PRId64 "}",
			                      tfi.m_peer_tid,
			                      tfi.m_peer_pid,
			                      tfi.m_peer_comm.c_str(),
			                      tfi.m_peer_fd));
			CHECK_FPRINTF(fprintf(stream, "}"));

			ntranslines++;
		}

		CHECK_FPRINTF(fprintf(stream, "\n]"));

		nfilelines++;
	}

	CHECK_FPRINTF(fprintf(stream, "\n}"));
}

void sinsp_transaction_table::save_json(string filename)
{
	FILE *transact_file;

	transact_file = fopen(filename.c_str(), "w");
	if(!transact_file)
	{
		throw sinsp_exception(string("cant't open file ") + filename + " for writing");
	}

	print_on(transact_file);

	fclose(transact_file);
}

uint32_t sinsp_transaction_table::get_size()
{
	uint32_t res = 0;
	unordered_map<int64_t, vector<sinsp_transaction > >::iterator it;

	// first try to find exact match
	for(it = m_table.begin(); it != m_table.end(); it++)
	{
		res += it->second.size();
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
}

sinsp_partial_transaction::~sinsp_partial_transaction()
{
}

sinsp_partial_transaction::updatestate sinsp_partial_transaction::update_int(uint64_t enter_ts, uint64_t exit_ts, direction dir, uint32_t len)
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

void sinsp_partial_transaction::update(sinsp* inspector, 
	sinsp_threadinfo *ptinfo,
	sinsp_connection *pconn,
	uint64_t enter_ts, 
	uint64_t exit_ts, 
	int32_t cpuid,
	direction dir, 
	uint32_t datalen)
{
	if(pconn == NULL)
	{
//		ASSERT(false);
		mark_inactive();
		return;
	}

	if(cpuid != -1)
	{
		m_cpuid = cpuid;
	}

	sinsp_partial_transaction::updatestate res = update_int(enter_ts, exit_ts, dir, datalen);
	if(res == STATE_SWITCHED)
	{
		m_tid = ptinfo->m_tid;
		inspector->m_trans_table->emit(ptinfo, pconn, this, datalen);
	}
}

void sinsp_partial_transaction::mark_active_and_reset(sinsp_partial_transaction::type newtype)
{
	m_type = newtype;
	m_incoming_bytes = 0;
	m_outgoing_bytes = 0;
}

void sinsp_partial_transaction::mark_inactive()
{
	m_type = sinsp_partial_transaction::TYPE_UNKNOWN;
}
