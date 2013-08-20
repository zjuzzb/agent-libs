#pragma once

//
// Connection information class
//
class SINSP_PUBLIC sinsp_connection
{
public:
	enum analysis_flags
	{
	    AF_NONE = 0,
		// Connection has been closed. It will have to be removed from the 
		// connection table.
	    AF_CLOSED = (1 << 1), 
		// Connection has been closed and reopened with the same key. 
		// I've seen this happen with unix sockets. A successive unix socket pair 
		// can be assigned the same addresses of a just closed one.
		// When that happens, the old connection is removed and the new one is
		// added with the AF_REUSED flag, so that the analyzer can detect that
		// connection is different.
		AF_REUSED = (1 << 2), 
	};

	sinsp_connection();
	sinsp_connection(uint64_t timestamp);
	void reset();
	bool is_client_only();
	bool is_server_only();

	int64_t m_spid;
	int64_t m_stid;
	int64_t m_sfd;
	string m_scomm;

	int64_t m_dpid;
	int64_t m_dtid;
	int64_t m_dfd;
	string m_dcomm;

	int8_t m_refcount;

	uint64_t m_timestamp;

	//
	// Analyzer state
	//
	uint8_t m_analysis_flags; // Flags word used by the analysis engine.
	sinsp_transaction_counters m_transaction_metrics;
};


template<class TKey,class THash,class TCompare>
class SINSP_PUBLIC sinsp_connection_manager
{
public:
#ifndef _WIN32
	typedef class unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator iterator_t;
#endif

	// Returns the pointer to the new connection
	sinsp_connection* add_connection(const TKey& key, sinsp_threadinfo* ptinfo, int64_t tid, int64_t fd, bool isclient, uint64_t timestamp);
	void remove_connection(const TKey& key, bool now = true);
	sinsp_connection* get_connection(const TKey& key, uint64_t timestamp);
	void remove_expired_connections(uint64_t current_ts);

	size_t size()
	{
		return m_connections.size();
	}
	
	const sinsp_configuration& get_configuration()
	{
		return m_inspector->m_configuration;
	}

	unordered_map<TKey, sinsp_connection, THash, TCompare> m_connections;
	sinsp * m_inspector;
	uint64_t m_last_connection_removal_ts;
};

template<class TKey, class THash, class TCompare>
sinsp_connection* sinsp_connection_manager<TKey,THash,TCompare>::add_connection(const TKey& key, sinsp_threadinfo* ptinfo, int64_t tid, int64_t fd, bool isclient, uint64_t timestamp)
{
	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;

	std::pair<typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator,
		bool> element;

	element = m_connections.emplace(key, timestamp);
	sinsp_connection& conn = element.first->second;
	if(element.second == true)
	{
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_added_connections++;
#endif

		conn.m_refcount = 1;
		conn.m_analysis_flags = 0;
		if(isclient)
		{
			conn.m_stid = tid;
			conn.m_sfd = fd;
			conn.m_spid = ptinfo->m_pid;
			conn.m_scomm = ptinfo->get_comm();
			conn.m_dtid = 0;
			conn.m_dfd = 0;
			conn.m_dpid = 0;
		}
		else
		{
			conn.m_stid = 0;
			conn.m_sfd = 0;
			conn.m_spid = 0;
			conn.m_dtid = tid;
			conn.m_dfd = fd;
			conn.m_dpid = ptinfo->m_pid;
			conn.m_dcomm = ptinfo->get_comm();
		}
	}
	else
	{
//		ASSERT(conn.m_analysis_flags != sinsp_connection::AF_CLOSED);
//		ASSERT(conn.m_refcount <= 2);
		if(isclient)
		{
			//ASSERT(conn.m_stid == 0);
			//ASSERT(conn.m_sfd == 0);
			//ASSERT(conn.m_spid == 0);

			//
			// Increment the refcount, but only if this is a brand new connection,
			// not if it's overwriting a new one
			//
			if(conn.m_stid == 0)
			{
				conn.m_refcount++;
			}
			else
			{
				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
				//ASSERT(false);
			}

			conn.m_stid = tid;
			conn.m_sfd = fd;
			conn.m_spid = ptinfo->m_pid;
			conn.m_scomm = ptinfo->get_comm();
		}
		else
		{
			//ASSERT(conn.m_dtid == 0);
			//ASSERT(conn.m_dfd == 0);
			//ASSERT(conn.m_dpid == 0);

			//
			// Increment the refcount, but only if this is a brand new connection,
			// not if it's overwriting a new one
			//
			if(conn.m_dtid == 0)
			{
				conn.m_refcount++;
			}
			else
			{
				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
				//ASSERT(false);
			}

			conn.m_dtid = tid;
			conn.m_dfd = fd;
			conn.m_dpid = ptinfo->m_pid;
			conn.m_dcomm = ptinfo->get_comm();
		}
	}

	return &conn;
};

template<class TKey, class THash, class TCompare>
void sinsp_connection_manager<TKey,THash,TCompare>::remove_connection(const TKey& key, bool now)
{
	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;

	cit = m_connections.find(key);
	if(cit == m_connections.end())
	{
		return;
	}
	else
	{
		cit->second.m_refcount--;
		ASSERT((cit->second.m_refcount >= 0 && cit->second.m_refcount <= 2) || ((cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED) != 0));

		if(cit->second.m_refcount <= 0)
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_removed_connections++;
#endif
			if(now)
			{
				m_connections.erase(cit);
			}
			else
			{
				cit->second.m_analysis_flags |= sinsp_connection::AF_CLOSED;
			}
		}
	}
};

template<class TKey,class THash,class TCompare>
sinsp_connection* sinsp_connection_manager<TKey,THash,TCompare>::get_connection(const TKey& key, uint64_t timestamp)
{
	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;
#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_connection_lookups++;
#endif
	cit = m_connections.find(key);
	if(cit != m_connections.end())
	{
		cit->second.m_timestamp = timestamp;
		return &(cit->second);
	}
	else
	{
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_failed_connection_lookups++;
#endif
		return NULL;
	}
};


template<class TKey,class THash,class TCompare>
void sinsp_connection_manager<TKey,THash,TCompare>::remove_expired_connections(uint64_t current_ts)
{
	if(0 == m_last_connection_removal_ts)
	{
		m_last_connection_removal_ts = current_ts;
		return;
	}

	uint64_t ts = current_ts - m_last_connection_removal_ts;
	
	if(ts <= get_configuration().get_connection_timeout_ns())
	{
		return;
	}

	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit = m_connections.begin();
	while(cit != m_connections.end())
	{
		if(cit->second.m_timestamp < ts)
		{
			cit = m_connections.erase(cit);
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_expired_connections++;
#endif
		}
		else
		{
			cit++;
		}
	}

	m_last_connection_removal_ts = ts;
};


class SINSP_PUBLIC sinsp_ipv4_connection_manager : public sinsp_connection_manager<ipv4tuple, ip4t_hash, ip4t_cmp>
{
public:
	sinsp_ipv4_connection_manager(sinsp* inspector)
	{
		m_inspector = inspector;
		m_last_connection_removal_ts = 0;
	}
};

class SINSP_PUBLIC sinsp_unix_connection_manager : public sinsp_connection_manager<unix_tuple, unixt_hash, unixt_cmp>
{
public:
	sinsp_unix_connection_manager(sinsp* inspector)
	{
		m_inspector = inspector;
		m_last_connection_removal_ts = 0;
	}
};

class SINSP_PUBLIC sinsp_pipe_connection_manager : public sinsp_connection_manager<uint64_t, hash<uint64_t>, equal_to<uint64_t>>
{
public:
	sinsp_pipe_connection_manager(sinsp* inspector)
	{
		m_inspector = inspector;
		m_last_connection_removal_ts = 0;
	}
}; 