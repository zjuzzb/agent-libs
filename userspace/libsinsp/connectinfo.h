#pragma once

#ifdef HAS_ANALYZER

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
	    AF_CLOSED = (1 << 0), 
		// Connection has been closed and reopened with the same key. 
		// I've seen this happen with unix sockets. A successive unix socket pair 
		// can be assigned the same addresses of a just closed one.
		// When that happens, the old connection is removed and the new one is
		// added with the AF_REUSED flag, so that the analyzer can detect that
		// connection is different.
		AF_REUSED = (1 << 1), 
	};

	sinsp_connection();
	sinsp_connection(uint64_t timestamp);
	void reset();
	void clear();
	bool is_active();
	bool is_client_only();
	bool is_server_only();
	bool is_client_and_server();

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
	sinsp_connection_counters m_metrics;
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
	sinsp_connection_manager()
	{
		m_n_drops = 0;
	}
	sinsp_connection* add_connection(const TKey& key, string* comm, int64_t pid, int64_t tid, int64_t fd, bool isclient, uint64_t timestamp);
	void remove_connection(const TKey& key, bool now = true);
	sinsp_connection* get_connection(const TKey& key, uint64_t timestamp);
	void remove_expired_connections(uint64_t current_ts);

	size_t size()
	{
		return m_connections.size();
	}
	
	void clear()
	{
		m_connections.clear();
	}

	const sinsp_configuration* get_configuration()
	{
		return &m_inspector->m_analyzer->m_configuration;
	}

	uint32_t get_n_drops()
	{
		return m_n_drops;
	}

	void clear_n_drops()
	{
		m_n_drops = 0;
	}

	unordered_map<TKey, sinsp_connection, THash, TCompare> m_connections;
	sinsp * m_inspector;
	uint64_t m_last_connection_removal_ts;
	uint32_t m_n_drops;
};

template<class TKey, class THash, class TCompare>
sinsp_connection* sinsp_connection_manager<TKey,THash,TCompare>::add_connection(const TKey& key, string* comm, int64_t pid, int64_t tid, int64_t fd, bool isclient, uint64_t timestamp)
{
	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;

	//
	// First of all, make sure there's space for this connection in the table
	//
	if(m_connections.size() >= m_inspector->m_analyzer->m_configuration.get_max_connection_table_size())
	{
		m_n_drops++;
		return NULL;
	}

	//
	// Insert the new connection
	//
	sinsp_connection& conn = m_connections[key];
	if(conn.m_timestamp == 0)
	{
		conn.m_timestamp = timestamp;
		conn.m_refcount = 1;
		conn.m_analysis_flags = 0;
		if(isclient)
		{
			conn.m_stid = tid;
			conn.m_sfd = fd;
			conn.m_spid = pid;
			conn.m_scomm = *comm;
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
			conn.m_dpid = pid;
			conn.m_dcomm = *comm;
		}
	}
	else
	{
		conn.m_timestamp = timestamp;

//		ASSERT(conn.m_analysis_flags != sinsp_connection::AF_CLOSED);
//		ASSERT(conn.m_refcount <= 2);
		if(isclient)
		{
			//ASSERT(conn.m_stid == 0);
			//ASSERT(conn.m_sfd == 0);
			//ASSERT(conn.m_spid == 0);

			//
			// Increment the refcount, but only if this is a brand new connection,
			// not if it's overwriting a currently open one.
			//
			if(conn.m_stid != 0)
			{
				if(conn.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					conn.m_refcount++;
				}

				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
			}
			else
			{
				conn.m_refcount++;
			}

			conn.m_stid = tid;
			conn.m_sfd = fd;
			conn.m_spid = pid;
			conn.m_scomm = *comm;
		}
		else
		{
			//ASSERT(conn.m_dtid == 0);
			//ASSERT(conn.m_dfd == 0);
			//ASSERT(conn.m_dpid == 0);

			//
			// Increment the refcount, but only if this is a brand new connection,
			// not if it's overwriting a currently open one.
			//
			if(conn.m_dtid != 0)
			{
				if(conn.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					conn.m_refcount++;
				}

				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
			}
			else
			{
				conn.m_refcount++;
			}

			conn.m_dtid = tid;
			conn.m_dfd = fd;
			conn.m_dpid = pid;
			conn.m_dcomm = *comm;
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
	cit = m_connections.find(key);
	if(cit != m_connections.end())
	{
		cit->second.m_timestamp = timestamp;
		return &(cit->second);
	}
	else
	{
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
	
	if(ts <= get_configuration()->get_connection_timeout_ns())
	{
		return;
	}

	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit = m_connections.begin();
	while(cit != m_connections.end())
	{
		if(cit->second.m_timestamp < ts)
		{
			cit = m_connections.erase(cit);
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

#endif // HAS_ANALYZER
