#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"


///////////////////////////////////////////////////////////////////////////////
// sinsp_transact_table implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_transaction_table::sinsp_transaction_table()
{
}

sinsp_transaction_table::~sinsp_transaction_table()
{
}

void sinsp_transaction_table::emit(sinsp_partial_transaction *tr, uint32_t len)
{
	unordered_map<int64_t, vector<sinsp_transaction > >::iterator it;
	unordered_map<int64_t, map<int64_t, sinsp_transaction_time> >::iterator oit;
	map<int64_t, sinsp_transaction_time>::iterator tit;

	if(tr->m_prev_direction == sinsp_partial_transaction::DIR_IN)
	{
		sinsp_transaction_time tinfo(tr->m_prev_start_time, tr->m_prev_end_time);

		oit = m_open_transactions.find(tr->m_tid);
		if(oit == m_open_transactions.end())
		{
			m_open_transactions[tr->m_tid][tr->m_fd] = tinfo;
		}
		else
		{
			oit->second[tr->m_fd] = tinfo;
		}
	}
	else if(tr->m_prev_direction == sinsp_partial_transaction::DIR_OUT ||
	        tr->m_prev_direction == sinsp_partial_transaction::DIR_CLOSE)
	{
		sinsp_transaction_time tinfo(tr->m_prev_start_time, tr->m_prev_end_time);

		oit = m_open_transactions.find(tr->m_tid);
		if(oit == m_open_transactions.end())
		{
			//
			// This can happen if we drop events or if a connection
			// starts with a write, which can happen with fucked up protocols
			// like the mysql one
			//
			return;
		}

		tit = oit->second.find(tr->m_fd);

		if(tit == oit->second.end())
		{
			//
			// See previous comment.
			//
			return;
		}

		//
		// Init the new table entry
		//
		sinsp_transaction tfi;
		tfi.m_trinfo = *tr;

		tfi.m_trinfo.m_start_time = tfi.m_trinfo.m_prev_start_time;
		tfi.m_trinfo.m_end_time = tfi.m_trinfo.m_prev_end_time;
		tfi.m_trinfo.m_prev_start_time = tit->second.m_start_time;
		tfi.m_trinfo.m_prev_end_time = tit->second.m_end_time;

		sinsp_threadinfo *ptinfo = tr->m_manager->m_inspector->get_thread(tr->m_tid, true);
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
		sinsp_connection *pconn = NULL;
		if(tr->is_ipv4_flow())
		{
			pconn = tr->m_manager->m_inspector->get_connection(tr->m_ipv4_flow, tr->m_end_time);
		}
		else if(tr->is_unix_flow())
		{
			pconn = tr->m_manager->m_inspector->get_connection(tr->m_unix_flow, tr->m_end_time);
		}
		else
		{
			ASSERT(false);
		}
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
//			ASSERT(false);
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

		//
		// Do the cleanup in the m_open_transactions table
		//
		oit->second.erase(tit);
		if(oit->second.size() == 0)
		{
			m_open_transactions.erase(oit);
		}
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
	m_type = TYPE_IP;
	m_direction = DIR_UNKNOWN;
	m_start_time = 0;
	m_end_time = 0;
	m_prev_direction = DIR_UNKNOWN;
	m_prev_start_time = 0;
	m_prev_end_time = 0;
}

sinsp_partial_transaction::~sinsp_partial_transaction()
{
}

sinsp_partial_transaction::sinsp_partial_transaction(ipv4tuple *flow)
{
	m_type = TYPE_IP;
	m_direction = DIR_UNKNOWN;
	m_start_time = 0;
	m_end_time = 0;
	m_prev_direction = DIR_UNKNOWN;
	m_prev_start_time = 0;
	m_prev_end_time = 0;
	m_ipv4_flow = *flow;
	m_flow_type = flow_type::IP;
}

sinsp_partial_transaction::sinsp_partial_transaction(unix_tuple *flow)
{
	m_type = TYPE_IP;
	m_direction = DIR_UNKNOWN;
	m_start_time = 0;
	m_end_time = 0;
	m_prev_direction = DIR_UNKNOWN;
	m_prev_start_time = 0;
	m_prev_end_time = 0;
	m_unix_flow = *flow;
	m_flow_type = flow_type::UNIX;
}


sinsp_partial_transaction::updatestate sinsp_partial_transaction::update_int(uint64_t enter_ts, uint64_t exit_ts, direction dir, uint32_t len)
{
	if(dir == DIR_IN)
	{
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
				res = STATE_SWITCHED;
			}

			m_start_time = enter_ts;
			m_end_time = exit_ts;
			if(len != 0)
			{
				m_direction = dir;
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
				res = STATE_SWITCHED;
			}

			m_start_time = enter_ts;
			m_end_time = exit_ts;
			if(len != 0)
			{
				m_direction = dir;
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

		m_direction = DIR_UNKNOWN;
		return STATE_SWITCHED;
	}
	else
	{
		ASSERT(false);
		return STATE_ONGOING;
	}
}

sinsp_partial_transaction::updatestate sinsp_partial_transaction::update(uint64_t enter_ts, uint64_t exit_ts, int64_t tid, direction dir, uint32_t len)
{
	sinsp_partial_transaction::updatestate res = update_int(enter_ts, exit_ts, dir, len);
	if(res == STATE_SWITCHED)
	{
		ASSERT(m_manager);
		m_tid = tid;
		m_manager->m_inspector->m_trans_table->emit(this, len);
	}

	return res;
}
///////////////////////////////////////////////////////////////////////////////
// sinsp_transacttable_manager implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_transaction_manager::sinsp_transaction_manager(sinsp *inspector)
{
	m_inspector = inspector;
}

sinsp_transaction_manager::~sinsp_transaction_manager()
{
}

sinsp_partial_transaction *sinsp_transaction_manager::add_transaction(int64_t fd, ipv4tuple *tuple)
{
	sinsp_partial_transaction tinfo(tuple);
	return add_transaction(fd, &tinfo);
}

sinsp_partial_transaction *sinsp_transaction_manager::add_transaction(int64_t fd, unix_tuple *tuple)
{
	sinsp_partial_transaction tinfo(tuple);
	return add_transaction(fd, &tinfo);
}

sinsp_partial_transaction *sinsp_transaction_manager::add_transaction(int64_t fd,  sinsp_partial_transaction *tinfo)
{
	unordered_map<int64_t, sinsp_partial_transaction>::iterator tit;

	tinfo->m_manager = this;
	tinfo->m_tid = -1;
	tinfo->m_fd = fd;

	//
	// XXX
	// This is a very inefficient way to add an element and then get a pointer to it.
	// We'll have to find a better way to do it.
	//
	m_table[fd] = *tinfo;

	//
	// Update the stats
	//
#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_added_pending_transactions++;
#endif

	return &(m_table[fd]);
}

void sinsp_transaction_manager::remove_transaction(int64_t tid, int64_t fd, uint64_t ts)
{
	unordered_map<int64_t, sinsp_partial_transaction>::iterator tit;

	tit = m_table.find(fd);
	if(tit == m_table.end())
	{
		//ASSERT(false);
		return;
	}

	tit->second.update(ts, ts, tid, sinsp_partial_transaction::DIR_CLOSE, 0);
	m_table.erase(tit);

	//
	// Update the stats
	//
#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_removed_pending_transactions++;
#endif
}

sinsp_partial_transaction *sinsp_transaction_manager::get_transaction(int64_t fd)
{
	unordered_map<int64_t, sinsp_partial_transaction>::iterator tit;

	tit = m_table.find(fd);
	if(tit != m_table.end())
	{
		return &(tit->second);
	}
	else
	{
		return NULL;
	}
}

void sinsp_transaction_manager::push_fd_op(int64_t fd, sinsp_fdinfo *fdinfo)
{
	/*
	    //
	    // Update the transaction table with this fd's info
	    //
	    if(!(fdinfo->m_flags & sinsp_fdinfo::FLAGS_TRANSACTION))
	    {
	        unordered_map<int64_t, sinsp_transactinfo>::iterator trit;

	        for(trit = m_table.begin(); trit != m_table.end(); ++trit)
	        {
	            unordered_map<int64_t, sinsp_transactfd>::iterator fdit;

	            fdit = trit->second.m_fdmap.find(fd);

	            //
	            // Check if this fd is already in the transaction's table
	            //
	            if(fdit == trit->second.m_fdmap.end())
	            {
	                trit->second.m_fdmap[m_fd] = sinsp_transactfd(0);
	            }
	        }
	    }
	*/
}

void sinsp_transaction_manager::remove_fd(int64_t fd, sinsp_fdinfo *fdinfo)
{
}

uint32_t sinsp_transaction_manager::get_size()
{
	return m_table.size();
}
