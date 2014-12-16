#ifdef HAS_ANALYZER

#pragma once

#define SRV_PORT_MYSQL 3306
#define SRV_PORT_POSTGRES 5432

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
		PROTO_POSTGRES
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
#include "draios.pb.h"

///////////////////////////////////////////////////////////////////////////////
// The DPI-based protocol detector
///////////////////////////////////////////////////////////////////////////////
class sinsp_proto_detector
{
public:
	sinsp_proto_detector();

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
	sinsp_request_details()
	{
		m_ncalls = 0;
		m_flags = SRF_NONE;
	}

	uint32_t m_ncalls;		// number of times this request has been served
	uint32_t m_nerrors;		// number of times serving this request has generated an error
	uint64_t m_time_tot;	// total time spent serving this request
	uint64_t m_time_max;	// slowest time spent serving this request
	uint32_t m_bytes_in;	// received bytes for this request
	uint32_t m_bytes_out;	// sent bytes for this request
	sinsp_request_flags m_flags;
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
	typedef bool (*request_comparer)(typename unordered_map<string, T>::iterator src, 
		typename unordered_map<string, T>::iterator dst);

public:
	//
	// Merge two maps by adding the elements of the source to the destination
	//
	inline static void update(T* entry, sinsp_partial_transaction* tr, int64_t time_delta, bool is_failure)
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
			entry->m_time_tot = time_delta;
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
			entry->m_time_tot += time_delta;
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
			T* entry = &((*dst)[uit->first]);

			if(entry->m_ncalls == 0)
			{
				*entry = uit->second;
			}
			else
			{
				entry->m_ncalls += uit->second.m_ncalls;
				entry->m_nerrors += uit->second.m_nerrors;
				entry->m_time_tot += uit->second.m_time_tot;
				entry->m_bytes_in += uit->second.m_bytes_in;
				entry->m_bytes_out += uit->second.m_bytes_out;
				
				if(uit->second.m_time_max > entry->m_time_max)
				{
					entry->m_time_max = uit->second.m_time_max;
				}
			}
		}
	}

	//
	// Comparers for sorting
	//
	static bool cmp_ncalls(typename unordered_map<string, T>::iterator src, typename unordered_map<string, T>::iterator dst)
	{
		return src->second.m_ncalls > dst->second.m_ncalls;
	}

	static bool cmp_nerrors(typename unordered_map<string, T>::iterator src, typename unordered_map<string, T>::iterator dst)
	{
		return src->second.m_nerrors > dst->second.m_nerrors;
	}

	static bool cmp_time_avg(typename unordered_map<string, T>::iterator src, typename unordered_map<string, T>::iterator dst)
	{
		return (src->second.m_time_tot / src->second.m_ncalls) > (dst->second.m_time_tot / dst->second.m_ncalls);
	}

	static bool cmp_time_max(typename unordered_map<string, T>::iterator src, typename unordered_map<string, T>::iterator dst)
	{
		return src->second.m_time_max > dst->second.m_time_max;
	}

	static bool cmp_bytes_tot(typename unordered_map<string, T>::iterator src, typename unordered_map<string, T>::iterator dst)
	{
		return (src->second.m_bytes_in + src->second.m_bytes_out) > 
			(dst->second.m_bytes_in + dst->second.m_bytes_out);
	}

	//
	// Marking functions
	//
	static void mark_top_by(vector<typename unordered_map<string, T>::iterator>* sortable_list,
							request_comparer comparer)
	{
		uint32_t j;

		partial_sort(sortable_list->begin(), 
			sortable_list->begin() + TOP_URLS_IN_SAMPLE, 
			sortable_list->end(),
			comparer);

		for(j = 0; j < TOP_URLS_IN_SAMPLE; j++)
		{
			sortable_list->at(j)->second.m_flags =
				(sinsp_request_flags)((uint32_t)sortable_list->at(j)->second.m_flags | SRF_INCLUDE_IN_SAMPLE);
		}
	}

	static void mark_top(vector<typename unordered_map<string, T>::iterator>* sortable_list)
	{
		//
		// Mark top based on number of calls
		//
		mark_top_by(sortable_list, 
			cmp_ncalls);
						
		//
		// Mark top based on total time
		//
		mark_top_by(sortable_list, 
			cmp_time_avg);

		//
		// Mark top based on max time
		//
		mark_top_by(sortable_list, 
			cmp_time_max);

		//
		// Mark top based on total bytes
		//
		mark_top_by(sortable_list, 
			cmp_bytes_tot);
		
		//
		// Mark top based on number of errors
		// Note: we don't use mark_top_by() because there's a good chance that less than
		//       TOP_URLS_IN_SAMPLE entries have errors, and so we add only the ones that
		//       have m_nerrors > 0.
		//
		partial_sort(sortable_list->begin(), 
			sortable_list->begin() + TOP_URLS_IN_SAMPLE, 
			sortable_list->end(),
			cmp_nerrors);

		for(uint32_t j = 0; j < TOP_URLS_IN_SAMPLE; j++)
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

class sql_state
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
	}

	void add(sql_state* other);
	template<typename Parser>
	void update(sinsp_partial_transaction* tr,
				uint64_t time_delta, bool is_server);
	void to_protobuf(draiosproto::sql_info* protobuf_msg, uint32_t sampling_ratio);
	inline bool has_data()
	{
		return m_server_queries.size() > 0 ||
			   m_client_queries.size() > 0;
	}

private:
	void query_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
		unordered_map<string, sinsp_query_details>* table,
		bool is_server,
		uint32_t sampling_ratio,
		bool is_query_table);
	void query_type_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
		unordered_map<uint32_t, sinsp_query_details>* table,
		bool is_server,
		uint32_t sampling_ratio);

	unordered_map<string, sinsp_query_details> m_server_queries;
	unordered_map<string, sinsp_query_details> m_client_queries;
	unordered_map<uint32_t, sinsp_query_details> m_server_query_types;
	unordered_map<uint32_t, sinsp_query_details> m_client_query_types;
	unordered_map<string, sinsp_query_details> m_server_tables;
	unordered_map<string, sinsp_query_details> m_client_tables;
};

///////////////////////////////////////////////////////////////////////////////
// The protocol state class
///////////////////////////////////////////////////////////////////////////////
class sinsp_protostate
{
public:
	void update(sinsp_partial_transaction* tr, uint64_t time_delta, bool is_server);

	inline void clear()
	{
		m_server_urls.clear();
		m_client_urls.clear();
		m_server_status_codes.clear();
		m_client_status_codes.clear();

		mysql.clear();
		postgres.clear();
	}

	void add(sinsp_protostate* other);

	void to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio);

	// The list of URLs
	unordered_map<string, sinsp_url_details> m_server_urls;
	unordered_map<string, sinsp_url_details> m_client_urls;
	unordered_map<uint32_t, uint32_t> m_server_status_codes;
	unordered_map<uint32_t, uint32_t> m_client_status_codes;

	sql_state mysql;
	sql_state postgres;
private:
	inline void update_http(sinsp_partial_transaction* tr,
		uint64_t time_delta, bool is_server);
	inline void add_http(sinsp_protostate* other);
	void url_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
		unordered_map<string, sinsp_url_details>* table,
		bool is_server,
		uint32_t sampling_ratio);
	void status_code_table_to_protobuf(draiosproto::proto_info* protobuf_msg, 
		unordered_map<uint32_t, uint32_t>* table,
		bool is_server,
		uint32_t sampling_ratio);

};

#endif // HAS_ANALYZER
