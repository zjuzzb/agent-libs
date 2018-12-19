#ifdef HAS_ANALYZER

#pragma once

#include <functional> 
#include "percentile.h"

#define SRV_PORT_MYSQL 3306
#define SRV_PORT_POSTGRES 5432

class sinsp_configuration;

///////////////////////////////////////////////////////////////////////////////
// The protocol parser interface class
///////////////////////////////////////////////////////////////////////////////
class sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MSG_NONE = 0,
		MSG_REQUEST,
		MSG_RESPONSE,
	};

	enum proto
	{
		PROTO_NONE = 0,
		PROTO_HTTP,
		PROTO_MYSQL,
		PROTO_POSTGRES,
		PROTO_MONGODB,
		PROTO_TLS
	};

	sinsp_protocol_parser();
	virtual ~sinsp_protocol_parser();
	virtual msg_type should_parse(sinsp_fdinfo_t* fdinfo, 
		sinsp_partial_transaction::direction dir,
		bool is_switched,
		char* buf, uint32_t buflen) = 0;
	virtual bool parse_request(char* buf, uint32_t buflen) = 0;
	virtual bool parse_response(char* buf, uint32_t buflen) = 0;
	virtual proto get_type() = 0;

	bool m_is_valid;
	bool m_is_req_valid;
};

#include "parser_http.h"
#include "parser_mysql.h"
#include "parser_postgres.h"
#include "parser_mongodb.h"
#include "parser_tls.h"
#undef min
#undef max
#include "draios.pb.h"

///////////////////////////////////////////////////////////////////////////////
// The DPI-based protocol detector
///////////////////////////////////////////////////////////////////////////////
class sinsp_proto_detector
{
public:
	sinsp_proto_detector(sinsp_configuration* config);

	sinsp_partial_transaction::type detect_proto(sinsp_evt *evt, 
		sinsp_partial_transaction *trinfo, 
		sinsp_partial_transaction::direction trdir,
		uint8_t* buf, uint32_t buflen);

	bool parse_request(char* buf, uint32_t buflen);

	string m_url;
	string m_agent;

private:
	uint32_t m_http_options_intval;
	uint32_t m_http_get_intval;
	uint32_t m_http_head_intval;
	uint32_t m_http_post_intval;
	uint32_t m_http_put_intval;
	uint32_t m_http_delete_intval;
	uint32_t m_http_trace_intval;
	uint32_t m_http_connect_intval;
	uint32_t m_http_resp_intval;
	sinsp_configuration* m_sinsp_config;
};

///////////////////////////////////////////////////////////////////////////////
// Table entries
///////////////////////////////////////////////////////////////////////////////
typedef enum sinsp_request_flags
{
	SRF_NONE = 0,
	SRF_INCLUDE_IN_SAMPLE = 1
}sinsp_request_flags;

class sinsp_request_details
{
public:
	typedef std::shared_ptr<percentile> percentile_ptr_t;

	sinsp_request_details():
		m_ncalls(0),
		m_nerrors(0),
		m_time_max(0),
		m_bytes_in(0),
		m_bytes_out(0),
		m_flags(SRF_NONE),
		m_time_tot(0),
		m_percentile(nullptr)
	{
	}

	sinsp_request_details(const sinsp_request_details& other):
		m_ncalls(other.m_ncalls),
		m_nerrors(other.m_nerrors),
		m_time_max(other.m_time_max),
		m_bytes_in(other.m_bytes_in),
		m_bytes_out(other.m_bytes_out),
		m_flags(other.m_flags),
		m_time_tot(other.m_time_tot),
		// ensure each instance has its own percentiles
		m_percentile(other.m_percentile ? new percentile(*other.m_percentile) : nullptr)
	{
	}

	sinsp_request_details& operator=(sinsp_request_details other)
	{
		if(this != &other)
		{
			m_ncalls = other.m_ncalls;
			m_nerrors = other.m_nerrors;
			m_time_max = other.m_time_max;
			m_bytes_in = other.m_bytes_in;
			m_bytes_out = other.m_bytes_out;
			m_flags = other.m_flags;
			m_time_tot = other.m_time_tot;
			// since we already have a disposable copy here, it's ok to just move it
			m_percentile = other.m_percentile;
		}
		return *this;
	}

	sinsp_request_details& operator+=(const sinsp_request_details& other)
	{
		if(m_ncalls == 0)
		{
			*this = other;
		}
		else
		{
			m_ncalls += other.m_ncalls;
			m_nerrors += other.m_nerrors;
			add_times(other);
			m_bytes_in += other.m_bytes_in;
			m_bytes_out += other.m_bytes_out;

			if(other.m_time_max > m_time_max)
			{
				m_time_max = other.m_time_max;
			}
		}
		return *this;
	}

	~sinsp_request_details()
	{
	}

	inline void to_protobuf(draiosproto::counter_proto_entry* counters,
			uint32_t sampling_ratio,
			std::function<void (const percentile_ptr_t)> pctl_to_protobuf) const
	{
		counters->set_ncalls(m_ncalls * sampling_ratio);
		counters->set_time_tot(m_time_tot * sampling_ratio);
		counters->set_time_max(m_time_max);
		counters->set_bytes_in(m_bytes_in * sampling_ratio);
		counters->set_bytes_out(m_bytes_out * sampling_ratio);
		counters->set_nerrors(m_nerrors * sampling_ratio);
		pctl_to_protobuf(m_percentile);
	}

	void add_time(uint64_t time_delta)
	{
		m_time_tot += time_delta;
		if(m_percentile)
		{
			m_percentile->add(time_delta);
		}
	}

	void add_times(const sinsp_request_details& other)
	{
		m_time_tot += other.m_time_tot;
		if (m_percentile && other.m_percentile) {
			m_percentile->merge(other.m_percentile.get());
		}
	}

	uint64_t get_ncalls() const
	{
		return m_ncalls;
	}

	uint64_t get_time_tot() const
	{
		return m_time_tot;
	}

	void set_percentiles(const std::set<double>& percentiles)
	{
		if(percentiles.size())
		{
			m_percentile.reset(new percentile(percentiles));
		}
	}

	percentile_ptr_t get_percentiles()
	{
		return m_percentile;
	}

	uint32_t m_ncalls;		// number of times this request has been served
	uint32_t m_nerrors;		// number of times serving this request has generated an error
	uint64_t m_time_max;	// slowest time spent serving this request
	uint32_t m_bytes_in;	// received bytes for this request
	uint32_t m_bytes_out;	// sent bytes for this request
	sinsp_request_flags m_flags;
private:
	uint64_t m_time_tot;	// total time spent serving this request
	percentile_ptr_t m_percentile;
};

class sinsp_url_details : public sinsp_request_details
{
};

class sinsp_query_details : public sinsp_request_details
{
};

///////////////////////////////////////////////////////////////////////////////
// Sorter class
///////////////////////////////////////////////////////////////////////////////
template <typename KT, typename T>
class request_sorter
{
	typedef bool (*request_comparer)(typename unordered_map<KT, T>::iterator src,
		typename unordered_map<KT, T>::iterator dst);

public:
	//
	// Merge two maps by adding the elements of the source to the destination
	//
	inline static void update(T* entry, sinsp_partial_transaction* tr, int64_t time_delta, bool is_failure, const std::set<double>& percentiles)
	{
		if(entry->m_ncalls == 0)
		{
			entry->m_ncalls = 1;
			if(is_failure)
			{
				entry->m_nerrors = 1;
			}
			else
			{
				entry->m_nerrors = 0;
			}
			entry->set_percentiles(percentiles);
			entry->add_time(time_delta);
			entry->m_time_max = time_delta;
			entry->m_bytes_in = tr->m_prev_bytes_in;
			entry->m_bytes_out = tr->m_prev_bytes_out;
		}
		else
		{
			entry->m_ncalls++;
			if(is_failure)
			{
				entry->m_nerrors++;
			}
			entry->add_time(time_delta);
			entry->m_bytes_in += tr->m_prev_bytes_in;
			entry->m_bytes_out += tr->m_prev_bytes_out;

			if((uint64_t)time_delta > entry->m_time_max)
			{
				entry->m_time_max = time_delta;
			}
		}
	}

	//
	// Merge two maps by adding the elements of the source to the destination
	//
#ifdef _WIN32
	static void merge_maps(typename unordered_map<KT, T>* dst, typename unordered_map<KT, T>* src)
#else	
	static void merge_maps(unordered_map<KT, T>* dst, unordered_map<KT, T>* src)
#endif	
	{
#ifdef _WIN32
		unordered_map<KT, T>::iterator uit;
#else	
		typename unordered_map<KT, T>::iterator uit;
#endif

		//
		// Add the server queries
		//
		for(uit = src->begin(); uit != src->end(); ++uit)
		{
			T& entry = (*dst)[uit->first];
			entry += uit->second;
		}
	}

	//
	// Comparers for sorting
	//
	static bool cmp_ncalls(typename unordered_map<KT, T>::iterator src, typename unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_ncalls > dst->second.m_ncalls;
	}

	static bool cmp_nerrors(typename unordered_map<KT, T>::iterator src, typename unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_nerrors > dst->second.m_nerrors;
	}

	static bool cmp_time_avg(typename unordered_map<KT, T>::iterator src, typename unordered_map<KT, T>::iterator dst)
	{
		return (src->second.get_time_tot() / src->second.m_ncalls) > (dst->second.get_time_tot() / dst->second.m_ncalls);
	}

	static bool cmp_time_max(typename unordered_map<KT, T>::iterator src, typename unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_time_max > dst->second.m_time_max;
	}

	static bool cmp_bytes_tot(typename unordered_map<KT, T>::iterator src, typename unordered_map<KT, T>::iterator dst)
	{
		return (src->second.m_bytes_in + src->second.m_bytes_out) > 
			(dst->second.m_bytes_in + dst->second.m_bytes_out);
	}

	//
	// Marking functions
	//
	static void mark_top_by(vector<typename unordered_map<KT, T>::iterator>* sortable_list,
							request_comparer comparer, size_t limit)
	{
		uint32_t j;

		if(sortable_list->size() > limit)
		{
			partial_sort(sortable_list->begin(),
						 sortable_list->begin() + limit,
						 sortable_list->end(),
						 comparer);
		}

		for(j = 0; j < std::min(limit, sortable_list->size()); j++)
		{
			sortable_list->at(j)->second.m_flags =
				(sinsp_request_flags)((uint32_t)sortable_list->at(j)->second.m_flags | SRF_INCLUDE_IN_SAMPLE);
		}
	}

	static void mark_top(vector<typename unordered_map<KT, T>::iterator>* sortable_list, size_t limit)
	{
		//
		// Mark top based on number of calls
		//
		mark_top_by(sortable_list, 
			cmp_ncalls, limit);
						
		//
		// Mark top based on total time
		//
		mark_top_by(sortable_list, 
			cmp_time_avg, limit);

		//
		// Mark top based on max time
		//
		mark_top_by(sortable_list, 
			cmp_time_max, limit);

		//
		// Mark top based on total bytes
		//
		mark_top_by(sortable_list, 
			cmp_bytes_tot, limit);
		
		//
		// Mark top based on number of errors
		// Note: we don't use mark_top_by() because there's a good chance that less than
		//       TOP_URLS_IN_SAMPLE entries have errors, and so we add only the ones that
		//       have m_nerrors > 0.
		//
		if(sortable_list->size() > limit)
		{
			partial_sort(sortable_list->begin(),
						 sortable_list->begin() + limit,
						 sortable_list->end(),
						 cmp_nerrors);
		}

		for(uint32_t j = 0; j < std::min(limit, sortable_list->size()); j++)
		{
			T* entry = &(sortable_list->at(j)->second);

			if(entry->m_nerrors > 0)
			{
				entry->m_flags =
					(sinsp_request_flags)((uint32_t)sortable_list->at(j)->second.m_flags | SRF_INCLUDE_IN_SAMPLE);
			}
			else
			{
				break;
			}
		}
	}
};

class protocol_state
{
public:
	protocol_state()
		: m_serialize_pctl_data(false)
	{}

	void set_serialize_pctl_data(bool val)
	{
		m_serialize_pctl_data = val;
	}

	void set_percentiles(const std::set<double>& pctls)
	{
		m_percentiles = pctls;
	}

	const std::set<double>& get_percentiles()
	{
		return m_percentiles;
	}

	void percentile_to_protobuf(draiosproto::counter_proto_entry* protoent, sinsp_request_details::percentile_ptr_t pct)
	{
		typedef draiosproto::counter_proto_entry CTB;
		typedef draiosproto::counter_percentile CP;
		typedef draiosproto::counter_percentile_data CPD;
		if(pct && pct->sample_count())
		{
			pct->to_protobuf<CTB, CP, CPD>(protoent,
			                               &CTB::add_percentile,
			                               (!m_serialize_pctl_data) ? nullptr :
			                               &CTB::mutable_percentile_data);
		}
	}

protected:
	std::set<double> m_percentiles;
	bool m_serialize_pctl_data;
};

class sql_state : public protocol_state
{
public:
	inline void clear()
	{
		m_server_queries.clear();
		m_client_queries.clear();
		m_server_query_types.clear();
		m_client_query_types.clear();
		m_server_tables.clear();
		m_client_tables.clear();
		m_server_totals = sinsp_request_details();
		m_client_totals = sinsp_request_details();
	}

	void add(sql_state* other);
	template<typename Parser>
	void update(sinsp_partial_transaction* tr,
				uint64_t time_delta, bool is_server, uint32_t truncation_size);

	void to_protobuf(draiosproto::sql_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit);
	inline bool has_data()
	{
		return m_server_queries.size() > 0 ||
			   m_client_queries.size() > 0;
	}

private:
	friend class sinsp_sql_marker;
	void query_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
		unordered_map<string, sinsp_query_details>* table,
		bool is_server,
		uint32_t sampling_ratio,
		bool is_query_table, uint32_t limit);
	void query_type_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
		unordered_map<uint32_t, sinsp_query_details>* table,
		bool is_server,
		uint32_t sampling_ratio, uint32_t limit);

	unordered_map<string, sinsp_query_details> m_server_queries;
	unordered_map<string, sinsp_query_details> m_client_queries;
	unordered_map<uint32_t, sinsp_query_details> m_server_query_types;
	unordered_map<uint32_t, sinsp_query_details> m_client_query_types;
	unordered_map<string, sinsp_query_details> m_server_tables;
	unordered_map<string, sinsp_query_details> m_client_tables;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;
};

class mongodb_state : public protocol_state
{
public:
	inline void clear()
	{
		m_server_ops.clear();
		m_client_ops.clear();
		m_server_collections.clear();
		m_client_collections.clear();
		m_server_totals = sinsp_request_details();
		m_client_totals = sinsp_request_details();
	}

	void add(mongodb_state* other);

	void update(sinsp_partial_transaction* tr,
				uint64_t time_delta, bool is_server, uint32_t truncation_size);

	void to_protobuf(draiosproto::mongodb_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit);

	inline bool has_data()
	{
		return m_server_ops.size() > 0 ||
			   m_client_ops.size() > 0;
	}

private:
	friend class sinsp_mongodb_marker;
	void collections_to_protobuf(unordered_map<string, sinsp_query_details>& map,
									const function<draiosproto::mongodb_collection_details*(void)> get_cd,
								 uint32_t sampling_ratio, uint32_t limit);
	// MongoDB
	unordered_map<uint32_t, sinsp_query_details> m_server_ops;
	unordered_map<uint32_t, sinsp_query_details> m_client_ops;
	unordered_map<string, sinsp_query_details> m_server_collections;
	unordered_map<string, sinsp_query_details> m_client_collections;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;
};

class sinsp_http_state : public protocol_state
{
public:
	void clear()
	{
		m_server_urls.clear();
		m_client_urls.clear();
		m_server_status_codes.clear();
		m_client_status_codes.clear();
		m_server_totals = sinsp_request_details();
		m_client_totals = sinsp_request_details();
	}

	bool has_data()
	{
		return ! m_server_status_codes.empty() || ! m_client_status_codes.empty();
	}

	void add(sinsp_http_state* other);

	inline void update(sinsp_partial_transaction* tr,
				uint64_t time_delta, bool is_server, uint32_t truncation_size);

	inline void to_protobuf(draiosproto::http_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit);

private:
	friend class sinsp_http_marker;
	void url_table_to_protobuf(draiosproto::http_info* protobuf_msg,
							   unordered_map<string, sinsp_url_details>* table,
							   bool is_server,
							   uint32_t sampling_ratio, uint32_t limit);
	void status_code_table_to_protobuf(draiosproto::http_info* protobuf_msg,
									   unordered_map<uint32_t, sinsp_request_details>* table,
									   bool is_server,
									   uint32_t sampling_ratio, uint32_t limit);
	unordered_map<string, sinsp_url_details> m_server_urls;
	unordered_map<string, sinsp_url_details> m_client_urls;
	unordered_map<uint32_t, sinsp_request_details> m_server_status_codes;
	unordered_map<uint32_t, sinsp_request_details> m_client_status_codes;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;
};
///////////////////////////////////////////////////////////////////////////////
// The protocol state class
///////////////////////////////////////////////////////////////////////////////
class sinsp_protostate
{
public:
	void update(sinsp_partial_transaction* tr, uint64_t time_delta, bool is_server, uint32_t truncation_size);

	inline void clear()
	{
		m_http.clear();
		m_mysql.clear();
		m_postgres.clear();
		m_mongodb.clear();
	}

	void add(sinsp_protostate* other);
	void set_percentiles(const std::set<double>& pctls);
	void set_serialize_pctl_data(bool val);
	void to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit);

	sinsp_http_state m_http;
	sql_state m_mysql;
	sql_state m_postgres;
	mongodb_state m_mongodb;
};

class sinsp_http_marker
{
public:
	void add(sinsp_http_state* state)
	{
		for(auto it = state->m_server_status_codes.begin(); it != state->m_server_status_codes.end(); ++it)
		{
			m_server_status_codes.push_back(it);
		}
		for(auto it = state->m_client_status_codes.begin(); it != state->m_client_status_codes.end(); ++it)
		{
			m_client_status_codes.push_back(it);
		}
		for(auto it = state->m_server_urls.begin(); it != state->m_server_urls.end(); ++it)
		{
			m_server_urls.push_back(it);
		}
		for(auto it = state->m_client_urls.begin(); it != state->m_client_urls.end(); ++it)
		{
			m_client_urls.push_back(it);
		}
	}
	void mark_top(size_t limit)
	{
		request_sorter<string, sinsp_url_details>::mark_top(&m_server_urls, limit);
		request_sorter<string, sinsp_url_details>::mark_top(&m_client_urls, limit);
		request_sorter<uint32_t, sinsp_request_details>::mark_top_by(&m_server_status_codes, request_sorter<uint32_t, sinsp_request_details>::cmp_ncalls, limit);
		request_sorter<uint32_t, sinsp_request_details>::mark_top_by(&m_client_status_codes, request_sorter<uint32_t, sinsp_request_details>::cmp_ncalls, limit);
	}

private:
	vector<unordered_map<string, sinsp_url_details>::iterator> m_server_urls;
	vector<unordered_map<string, sinsp_url_details>::iterator> m_client_urls;
	vector<unordered_map<uint32_t, sinsp_request_details>::iterator> m_server_status_codes;
	vector<unordered_map<uint32_t, sinsp_request_details>::iterator> m_client_status_codes;
};

class sinsp_sql_marker
{
public:
	void add(sql_state* state)
	{
		for(auto it = state->m_server_queries.begin(); it != state->m_server_queries.end(); ++it)
		{
			m_server_queries.push_back(it);
		}
		for(auto it = state->m_client_queries.begin(); it != state->m_client_queries.end(); ++it)
		{
			m_client_queries.push_back(it);
		}
		for(auto it = state->m_server_query_types.begin(); it != state->m_server_query_types.end(); ++it)
		{
			m_server_query_types.push_back(it);
		}
		for(auto it = state->m_client_query_types.begin(); it != state->m_client_query_types.end(); ++it)
		{
			m_client_query_types.push_back(it);
		}
		for(auto it = state->m_server_tables.begin(); it != state->m_server_tables.end(); ++it)
		{
			m_server_tables.push_back(it);
		}
		for(auto it = state->m_client_tables.begin(); it != state->m_client_tables.end(); ++it)
		{
			m_client_tables.push_back(it);
		}
	}

	void mark_top(size_t limit)
	{
		request_sorter<string, sinsp_query_details>::mark_top(&m_server_queries, limit);
		request_sorter<string, sinsp_query_details>::mark_top(&m_client_queries, limit);
		request_sorter<uint32_t, sinsp_query_details>::mark_top(&m_server_query_types, limit);
		request_sorter<uint32_t, sinsp_query_details>::mark_top(&m_client_query_types, limit);
		request_sorter<string, sinsp_query_details>::mark_top(&m_server_tables, limit);
		request_sorter<string, sinsp_query_details>::mark_top(&m_client_tables, limit);
	}

private:
	vector<unordered_map<string, sinsp_query_details>::iterator> m_server_queries;
	vector<unordered_map<string, sinsp_query_details>::iterator> m_client_queries;
	vector<unordered_map<uint32_t, sinsp_query_details>::iterator> m_server_query_types;
	vector<unordered_map<uint32_t, sinsp_query_details>::iterator> m_client_query_types;
	vector<unordered_map<string, sinsp_query_details>::iterator> m_server_tables;
	vector<unordered_map<string, sinsp_query_details>::iterator> m_client_tables;
};

class sinsp_mongodb_marker
{
public:
	void add(mongodb_state* state)
	{
		for(auto it = state->m_server_ops.begin(); it != state->m_server_ops.end(); ++it)
		{
			m_server_ops.push_back(it);
		}
		for(auto it = state->m_client_ops.begin(); it != state->m_client_ops.end(); ++it)
		{
			m_client_ops.push_back(it);
		}
		for(auto it = state->m_server_collections.begin(); it != state->m_server_collections.end(); ++it)
		{
			m_server_collections.push_back(it);
		}
		for(auto it = state->m_client_collections.begin(); it != state->m_client_collections.end(); ++it)
		{
			m_client_collections.push_back(it);
		}
	}

	void mark_top(size_t limit)
	{
		request_sorter<uint32_t, sinsp_query_details>::mark_top(&m_server_ops, limit);
		request_sorter<uint32_t, sinsp_query_details>::mark_top(&m_client_ops, limit);
		request_sorter<string, sinsp_query_details>::mark_top(&m_server_collections, limit);
		request_sorter<string, sinsp_query_details>::mark_top(&m_client_collections, limit);
	}

private:
	vector<unordered_map<uint32_t, sinsp_query_details>::iterator> m_server_ops;
	vector<unordered_map<uint32_t, sinsp_query_details>::iterator> m_client_ops;
	vector<unordered_map<string, sinsp_query_details>::iterator> m_server_collections;
	vector<unordered_map<string, sinsp_query_details>::iterator> m_client_collections;
};


class sinsp_protostate_marker
{
public:
	void add(sinsp_protostate* protostate)
	{
		m_http.add(&protostate->m_http);
		m_mysql.add(&protostate->m_mysql);
		m_postgres.add(&protostate->m_postgres);
		m_mongodb.add(&protostate->m_mongodb);
	}

	void mark_top(size_t limit)
	{
		m_http.mark_top(limit);
		m_mysql.mark_top(limit);
		m_postgres.mark_top(limit);
		m_mongodb.mark_top(limit);
	}

private:
	sinsp_http_marker m_http;
	sinsp_sql_marker m_mysql;
	sinsp_sql_marker m_postgres;
	sinsp_mongodb_marker m_mongodb;
};

#endif // HAS_ANALYZER
