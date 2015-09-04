#ifdef HAS_ANALYZER

#pragma once

#include <stack>
#include <stdexcept>

class copyexcept : public std::runtime_error {
public:
    copyexcept(const string& message) 
        : std::runtime_error(message) { };
};

template<class T> class sinsp_fdinfo;
class sinsp_transaction_manager;
class sinsp_connection;
class sinsp_analyzer;
class sinsp_threadinfo;
class sinsp;
class sinsp_evt;
class sinsp_protocol_parser;
class sinsp_procinfo;

///////////////////////////////////////////////////////////////////////////////
// Auto-expand buffer
///////////////////////////////////////////////////////////////////////////////
class sinsp_autobuffer
{
public:
	sinsp_autobuffer()
	{
		reset();
	}

	~sinsp_autobuffer()
	{
		if(m_storage != NULL)
		{
			free(m_storage);
		}
	}

	inline void reset()
	{
		m_storage = NULL;
		m_storage_totsize = 0;
		m_storage_cursize = 0;
	}

	//
	// Note: terminate_string is 1 if you want a zero at the end of the string
	//
	inline char* copy(const char* data, uint32_t size, uint32_t terminate_string = 0)
	{
		char* res;

		if(size + terminate_string + m_storage_cursize >= m_storage_totsize)
		{
			m_storage_totsize = m_storage_cursize + size + 256;

			m_storage = (char*)realloc(m_storage, m_storage_totsize);
			if(m_storage == NULL)
			{
				throw copyexcept(string("memory allocation error in sinsp_partial_transaction::copy_to_reassebly_storage"));
			}
		}

		res = m_storage + m_storage_cursize;
		memcpy(m_storage + m_storage_cursize, data, size);
		m_storage_cursize += (size + terminate_string);

		if(terminate_string == 1)
		{
			m_storage[m_storage_cursize - 1] = 0;
		}


		return res;
	}

	inline char* strcopy(char* data, uint32_t maxsize, OUT uint32_t* copied_size)
	{
		char* res;
		uint32_t size = strnlen(data, maxsize);

		if(size > maxsize)
		{
			*copied_size = 0;
			return NULL;
		}

		res = this->copy(data, size, 1);

		*copied_size = size;
		return res;
	}

	inline char* copy_and_trim(char* data, uint32_t size, uint32_t terminate_string = 0)
	{
		//
		// Skip initial spaces
		//
		while(*data == ' ' || *data == '\t' || *data == '\r' || *data == '\n')
		{
			data++;
			size--;

			if(size == 0)
			{
				return NULL;
			}
		}

		//
		// Skip initial spaces
		//
		char* end = data + size - 1;

		while(*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		{
			end--;
			size--;

			if(size == 0)
			{
				return NULL;
			}
		}

		//
		// Copy the string
		//
		return copy(data, size, terminate_string);
	}

	inline char* get_buf()
	{
		return m_storage;
	}

	inline char* get_buf_end()
	{
		return m_storage + m_storage_cursize;
	}

	inline uint32_t get_size()
	{
		return m_storage_cursize;
	}

	inline void clear()
	{
		m_storage_cursize = 0;
	}

private:
	char* m_storage;
	uint32_t m_storage_totsize;
	uint32_t m_storage_cursize;
};

///////////////////////////////////////////////////////////////////////////////
// Transaction information class
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_partial_transaction
{
public:
	enum type
	{
	    TYPE_UNKNOWN = 0, // Unknown protocols, don't count requests
	    TYPE_IP = 1, // Known client/server protocols, count requests
	    TYPE_HTTP = 2, // as for TYPE_IP but also parse protocol
	    TYPE_MYSQL = 3,
		TYPE_POSTGRES = 4,
		TYPE_MONGODB = 5,
	};

	enum family
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
	    STATE_NO_TRANSACTION = (1 << 2),	// Set when, based on timing observation, this is detected as 
											// not being a client/server transaction.
	};

	sinsp_partial_transaction();
	~sinsp_partial_transaction();
	sinsp_partial_transaction(const sinsp_partial_transaction &other);

	void reset();
	void update(sinsp_analyzer* analyzer, 
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
		char *data,
		uint32_t original_len, 
		uint32_t len);
	void mark_active_and_reset(sinsp_partial_transaction::type newtype);
	void mark_inactive();
	inline bool is_active()
	{
		return m_is_active;
	}

	bool is_ipv4_flow()
	{
		return m_family == family::IP;
	}

	bool is_unix_flow()
	{
		return m_family == family::UNIX;
	}

	sinsp_partial_transaction::type m_type;
	direction m_direction;
	int64_t m_tid;
	int64_t m_fd;
	vector<string> m_protoinfo;

	uint64_t m_start_time;
	uint64_t m_end_time;
	uint64_t m_start_of_transaction_time;

	direction m_prev_direction;
	uint64_t m_prev_start_time;
	uint64_t m_prev_end_time;
	uint64_t m_prev_start_of_transaction_time;
	uint64_t m_prev_prev_start_time;
	uint64_t m_prev_prev_end_time;
	uint64_t m_prev_prev_start_of_transaction_time;
	family m_family;
	uint32_t m_bytes_in;
	uint32_t m_bytes_out;
	uint32_t m_prev_bytes_in;
	uint32_t m_prev_bytes_out;
	int32_t m_cpuid;
	uint32_t m_flags;
	uint32_t m_n_direction_switches; // Number of times this transaction has switched direction 
	sinsp_protocol_parser* m_protoparser;
	sinsp_autobuffer m_reassembly_buffer;

private:
	inline sinsp_partial_transaction::updatestate update_int(
		sinsp_threadinfo* ptinfo,
		uint64_t enter_ts, 
		uint64_t exit_ts, direction dir, 
		char* data, uint32_t original_len, uint32_t len, 
		bool is_server);

	bool m_is_active;
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
// This little class describes an entry in the per-cpu transaction list that
// is consumed when a sample is created
//
class SINSP_PUBLIC sinsp_trlist_entry
{
public:
	enum flags
	{
	    FL_NONE = 0,
	    FL_FILTERED_OUT = (1 << 0),
	    FL_EXTERNAL = (1 << 1),
	};

	sinsp_trlist_entry(uint64_t stime, uint64_t etime, flags f)
	{
		m_stime = stime;
		m_etime = etime;
		m_flags = f;
	}

	uint64_t m_stime;	// start time
	uint64_t m_etime;	// end time
	int32_t m_flags;	// pid of the program main process
};

struct sinsp_trlist_entry_comparer
{
    bool operator() (const sinsp_trlist_entry& first, const sinsp_trlist_entry& second) const 
	{
		return first.m_stime < second.m_stime;
	}
};

//
// Transaction table class
// This stores the transactions that have been completed and can be accessed by the user.
//
class SINSP_PUBLIC sinsp_transaction_table
{
public:
	sinsp_transaction_table(sinsp* inspector);
	~sinsp_transaction_table();

	void emit(sinsp_threadinfo* ptinfo, 
		void* fdinfo,
		sinsp_connection* pconn,
		sinsp_partial_transaction* tr
#if _DEBUG
		, sinsp_evt *evt,
		uint64_t fd,
		uint64_t ts
#endif
	);

	//
	// Stores the global list of transactions.
	// Key is the tid
	//
	uint32_t m_n_client_transactions;
	uint32_t m_n_server_transactions;

private:
	bool is_transaction_server(sinsp_threadinfo *ptinfo);

	sinsp* m_inspector;

	friend class sinsp_partial_transaction;
};

#endif
