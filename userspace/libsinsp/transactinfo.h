#pragma once

class sinsp_fdinfo;
class sinsp_transaction_manager;
class sinsp_connection;

//
// This class describes an fd that is active during a transaction
//
class sinsp_transactfd
{
public:
	sinsp_transactfd()
	{
	}

	sinsp_transactfd(uint32_t score)
	{
		m_score = score;
	}

	uint32_t m_score;
};

//
// Transaction information class
//
class SINSP_PUBLIC sinsp_partial_transaction
{
public:
	enum type
	{
	    TYPE_UNKNOWN,
	    TYPE_IP,
	    TYPE_HTTP,
	};

	// XXX get rid of this
	enum flow_type
	{
	    IP,
	    UNIX
	};

	enum direction
	{
	    DIR_UNKNOWN,
	    DIR_IN,
	    DIR_OUT,
	    DIR_CLOSE,  // Not technically a direction, indicates that the connection is being closed
	};

	enum updatestate
	{
	    STATE_ONGOING = (1 << 0),
	    STATE_SWITCHED = (1 << 1),
	};

	sinsp_partial_transaction();
	~sinsp_partial_transaction();
	sinsp_partial_transaction(ipv4tuple *flow);
	sinsp_partial_transaction(unix_tuple *flow);
	sinsp_partial_transaction::updatestate update(sinsp* inspector, 
		sinsp_threadinfo *ptinfo,
		sinsp_connection *pconn,
		uint64_t enter_ts, 
		uint64_t exit_ts, 
		int64_t tid, 
		direction dir, 
		uint32_t len);

	bool is_ipv4_flow()
	{
		return m_flow_type == flow_type::IP;
	}

	bool is_unix_flow()
	{
		return m_flow_type == flow_type::UNIX;
	}

	sinsp_partial_transaction::type m_type;
	direction m_direction;
	int64_t m_tid;
	int64_t m_fd;
	ipv4tuple m_ipv4_flow;
	unix_tuple m_unix_flow;
	vector<string> m_protoinfo;

	uint64_t m_start_time;
	uint64_t m_end_time;

	direction m_prev_direction;
	uint64_t m_prev_start_time;
	uint64_t m_prev_end_time;
	uint64_t m_prev_prev_start_time;
	uint64_t m_prev_prev_end_time;
	flow_type m_flow_type;
	//  unordered_map<int64_t, sinsp_transactfd> m_fdmap;

private:
	sinsp_partial_transaction::updatestate update_int(uint64_t enter_ts, uint64_t exit_ts, direction dir, uint32_t len);
};

//
// Resolved process information for a transaction
//
class SINSP_PUBLIC sinsp_transaction
{
public:
	sinsp_partial_transaction m_trinfo;

	uint64_t m_pid;
	string m_comm;
	uint64_t m_peer_tid;
	uint64_t m_peer_fd;
	uint64_t m_peer_pid;
	string m_peer_comm;

	string m_fd_desc;
};

//
// Transaction table class
// This stores the transactions that have been completed and can be accessed by the user.
//
class SINSP_PUBLIC sinsp_transaction_table
{
public:
	sinsp_transaction_table();
	~sinsp_transaction_table();
	void save_json(string filename);
	void print_on(FILE *stream);
	uint32_t get_size();
	void clear();

	//private:
	void emit(sinsp_threadinfo *ptinfo, 
		sinsp_connection *pconn,
		sinsp_partial_transaction *tr, 
		uint32_t len);

	//
	// Stores the global list of transactions.
	// Key is the tid
	//
	unordered_map<int64_t, vector<sinsp_transaction > > m_table;
	uint32_t m_n_transactions;

	friend class sinsp_partial_transaction;
};
