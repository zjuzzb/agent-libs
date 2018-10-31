#pragma once

#ifdef HAS_ANALYZER

class sinsp_analyzer;

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
		// This connection hasn't been established yet (nonblocking connect() was called)
		AF_PENDING = (1 << 2),
		// this connection has failed due to:
		// - connect() error
		// - getsockopt(SOL_SOCKET, SO_ERROR) reporting an error
		// - read/write error
		AF_FAILED = (1 << 3),
	};

	sinsp_connection();
	sinsp_connection(uint64_t timestamp);
	void reset();
	void reset_server();
	void reset_client();
	void clear();
	bool is_active() const;
	bool is_client_only() const;
	bool is_server_only() const;
	bool is_client_and_server() const;

	int64_t m_spid;
	int64_t m_stid;
	int64_t m_sfd;
	string m_scomm;

	int64_t m_dpid;
	int64_t m_dtid;
	int64_t m_dfd;
	string m_dcomm;

	uint64_t m_timestamp;
	int8_t m_refcount;


	//
	// Analyzer state
	//
	uint8_t m_analysis_flags; // Flags word used by the analysis engine.
	int32_t m_error_code; // last syscall error code
	sinsp_connection_counters m_metrics;
	sinsp_transaction_counters m_transaction_metrics;
};

class sinsp_connection_aggregator
{
public:
	sinsp_connection_aggregator(const std::set<double>* percentiles = nullptr):
		m_transaction_metrics(percentiles),
		m_count(0)
	{}
	void clear();
	void to_protobuf(draiosproto::connection_categories* proto, uint32_t sampling_ratio) const;
	void add(sinsp_connection* conn);
	void add_client(sinsp_connection* conn);
	void add_server(sinsp_connection* conn);
	template<typename ProtobufType>
	static void filter_and_emit(const unordered_map<uint16_t, sinsp_connection_aggregator>& map,
							ProtobufType* proto, uint16_t top, uint32_t sampling_ratio);
private:
	bool is_active() const
	{
		uint32_t totops = m_metrics.m_client.m_count_in + m_metrics.m_client.m_count_out +
						  m_metrics.m_server.m_count_in + m_metrics.m_server.m_count_out;

		return (totops != 0);
	}
	bool operator<(const sinsp_connection_aggregator& other) const;
	sinsp_connection_counters m_metrics;
	sinsp_transaction_counters m_transaction_metrics;
	uint32_t m_count;
};

template<typename ProtobufType>
void sinsp_connection_aggregator::filter_and_emit(const unordered_map<uint16_t, sinsp_connection_aggregator> &map,
												  ProtobufType *proto, uint16_t top, uint32_t sampling_ratio)
{
	// Filter the top N
	using map_it_t = unordered_map<uint16_t, sinsp_connection_aggregator>::const_iterator;
	vector<map_it_t> to_emit_connections;
	for(auto agcit = map.begin(); agcit != map.end(); ++agcit)
	{
		to_emit_connections.push_back(agcit);
	}
	auto to_emit_connections_end = to_emit_connections.end();

	if(to_emit_connections.size() > top)
	{
		to_emit_connections_end = to_emit_connections.begin() + top;
		partial_sort(to_emit_connections.begin(),
					 to_emit_connections_end,
					 to_emit_connections.end(), [](const map_it_t& src, const map_it_t& dst)
					 {
						 return dst->second < src->second;
					 });
	}

	for(auto agcit = to_emit_connections.begin(); agcit != to_emit_connections_end; ++agcit)
	{
		if(!(*agcit)->second.is_active())
		{
			continue;
		}
		auto network_by_server_port = proto->add_network_by_serverports();
		network_by_server_port->set_port((*agcit)->first);
		auto counters = network_by_server_port->mutable_counters();
		(*agcit)->second.to_protobuf(counters, sampling_ratio);
	}
}

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
	sinsp_connection* add_connection(const TKey& key, string* comm, int64_t pid, int64_t tid, int64_t fd, bool isclient, uint64_t timestamp, uint8_t flags, int32_t error_code);
	void remove_connection(const TKey& key);
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
		return m_inspector->m_analyzer->m_configuration;
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
	std::set<double> m_percentiles;
};

template<class TKey, class THash, class TCompare>
sinsp_connection* sinsp_connection_manager<TKey,THash,TCompare>::add_connection(
	const TKey& key, string* comm, int64_t pid, int64_t tid, int64_t fd, bool isclient, uint64_t timestamp,
	uint8_t flags, int32_t error_code)
{
	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit;

	//
	// First of all, make sure there's space for this connection in the table
	//
	if(m_connections.size() >= m_inspector->m_analyzer->m_configuration->get_max_connection_table_size())
	{
		m_n_drops++;
		return NULL;
	}

	ASSERT((flags & ~(sinsp_connection::AF_PENDING | sinsp_connection::AF_FAILED)) == 0);

	//
	// Insert the new connection
	//
	sinsp_connection& conn = m_connections[key];

	if(m_percentiles.size() && !conn.m_transaction_metrics.has_percentiles())
	{
		conn.m_transaction_metrics.set_percentiles(m_percentiles);
	}

	if(conn.m_timestamp == 0)
	{
		conn.m_timestamp = timestamp;
		conn.m_refcount = 1;
		conn.m_analysis_flags = flags;
		conn.m_error_code = error_code;
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
		conn.m_error_code = error_code;

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
				if((conn.m_analysis_flags & (sinsp_connection::AF_CLOSED | sinsp_connection::AF_REUSED)) && conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}

				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
			}
			else
			{
				if(conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}
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
				if((conn.m_analysis_flags & (sinsp_connection::AF_CLOSED | sinsp_connection::AF_REUSED)) && conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}

				conn.m_analysis_flags = sinsp_connection::AF_REUSED;
			}
			else
			{
				if(conn.m_refcount <= 2)
				{
					conn.m_refcount++;
				}
			}

			conn.m_dtid = tid;
			conn.m_dfd = fd;
			conn.m_dpid = pid;
			conn.m_dcomm = *comm;
		}
		conn.m_analysis_flags &= ~(sinsp_connection::AF_PENDING | sinsp_connection::AF_FAILED);
		conn.m_analysis_flags |= flags;
	}

	return &conn;
};

template<class TKey, class THash, class TCompare>
void sinsp_connection_manager<TKey,THash,TCompare>::remove_connection(const TKey& key)
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
			cit->second.m_analysis_flags |= sinsp_connection::AF_CLOSED;
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

	uint64_t deltats = current_ts - m_last_connection_removal_ts;
	
	if(deltats <= get_configuration()->get_connection_pruning_interval_ns())
	{
		return;
	}

	uint64_t connection_timeout_ns = get_configuration()->get_connection_timeout_ns();

	typename unordered_map<TKey, sinsp_connection, THash, TCompare>::iterator cit = m_connections.begin();
	while(cit != m_connections.end())
	{
		if(current_ts - cit->second.m_timestamp > connection_timeout_ns)
		{
			cit = m_connections.erase(cit);
		}
		else
		{
			cit++;
		}
	}

	m_last_connection_removal_ts = current_ts;
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
