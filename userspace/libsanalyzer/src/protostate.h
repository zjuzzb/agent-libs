#ifdef HAS_ANALYZER

#pragma once

#include <functional> 
#include <Poco/RegularExpression.h>
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
				      const char* buf,
				      uint32_t buflen) = 0;
	virtual bool parse_request(const char* buf, uint32_t buflen) = 0;
	virtual bool parse_response(const char* buf, uint32_t buflen) = 0;
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

class sinsp_configuration;

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

	std::string m_url;
	std::string m_agent;

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

class sinsp_url_group
{
public:
	sinsp_url_group(const std::string& pattern)
		: m_pattern(pattern, Poco::RegularExpression::RE_CASELESS)
	{}

	/// 
	/// determine whether a url, represented by a string, is a member of this group
	/// @param url  string representation of the url to match
	/// @returns    whether the url is a member of the group
	///
	bool contains(std::string url) const
	{
		return m_pattern.match(url);
	}

private:
	Poco::RegularExpression m_pattern; 
};

// holding class for all our URL groups. they exist as either matched or unmatched.
// newly created URL groups are considered unmatched and the next time we grab stats to
// send out, we take all unmatched URLs and attempt to match them against all URLs in the
// table. When new URLs are added, they are matched against all groups in the "matched groups"
// list here.
//
// When a URL group is first matched against URLs, it is moved from the unmatched list to
// the matched list.
class sinsp_url_details;
class sinsp_url_groups
{
public:

	/// matches a url against all known url groups
	///
	/// @param url string representation of the url to match
	/// @param url_details the details of the URL backing the url string
	///
	/// the url_details will be modified with an indication of which groups were matched
	//
	// a bit weird that we take BOTH the URl string AND the details. We need the
	// url in order to actually match against the patterns, and we need the details
	// to register the groups which matched. The details don't have a reference to the
	// string and the lookup is only one way from string->details. We could add a reverse
	// mapping or a reference to the string to avoid storing the string twice.....or we
	// could just pass it in.
	//
	// The latter is simpler.
	void match_new_url(const std::string& url, sinsp_url_details& url_details) const;

	/// update our set of URL groups. expected to only be called once at initialization
	/// time
	/// @param group the set of regexes we that define the groups
	void update_group_set(const std::set<std::string>& group);
private:
	std::map<std::string, shared_ptr<sinsp_url_group>> m_matched_groups; // list of all URL groups which
								   // have been previously matched
								   // with all URLs in the url list
};


class sinsp_url_details : public sinsp_request_details
{
public:
	sinsp_url_details()
		: sinsp_request_details(),
		m_matched(false),
		m_url_groups() {}

	/// takes a URL, and if we haven't compared it to all known URL groups, does so
	/// @param groups the list of groups to match against
	/// @param url the string of the url we want to match
	///
	/// we have to pass in the URL explicitly since it isn't stored as part of
	/// url_details
	void match_url_if_unmatched(const sinsp_url_groups& groups, const std::string& url)
	{
		if (m_matched)
		{
			return;
		}
		groups.match_new_url(url, *this);
		m_matched = true;
	}

	/// adds a group to this URL. Since URL groups are currently static, this
	/// is a permanent action
	void add_group(const shared_ptr<sinsp_url_group>& group)
	{
		m_url_groups.insert(group);
	}

	std::unordered_set<shared_ptr<sinsp_url_group>>* get_group_list()
	{
		return &m_url_groups;
	}

private:
	bool m_matched; // indicates whether this URL has already been matched against existing
	// URL groups
	std::unordered_set<shared_ptr<sinsp_url_group>> m_url_groups; // set of groups this URL matches
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
	typedef bool (*request_comparer)(typename std::unordered_map<KT, T>::iterator src,
		typename std::unordered_map<KT, T>::iterator dst);

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
	static void merge_maps(typename std::unordered_map<KT, T>* dst, typename std::unordered_map<KT, T>* src)
#else	
	static void merge_maps(std::unordered_map<KT, T>* dst, std::unordered_map<KT, T>* src)
#endif	
	{
#ifdef _WIN32
		std::unordered_map<KT, T>::iterator uit;
#else	
		typename std::unordered_map<KT, T>::iterator uit;
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
	static bool cmp_ncalls(typename std::unordered_map<KT, T>::iterator src, typename std::unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_ncalls > dst->second.m_ncalls;
	}

	static bool cmp_nerrors(typename std::unordered_map<KT, T>::iterator src, typename std::unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_nerrors > dst->second.m_nerrors;
	}

	static bool cmp_time_avg(typename std::unordered_map<KT, T>::iterator src, typename std::unordered_map<KT, T>::iterator dst)
	{
		return (src->second.get_time_tot() / src->second.m_ncalls) > (dst->second.get_time_tot() / dst->second.m_ncalls);
	}

	static bool cmp_time_max(typename std::unordered_map<KT, T>::iterator src, typename std::unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_time_max > dst->second.m_time_max;
	}

	static bool cmp_bytes_tot(typename std::unordered_map<KT, T>::iterator src, typename std::unordered_map<KT, T>::iterator dst)
	{
		return (src->second.m_bytes_in + src->second.m_bytes_out) > 
			(dst->second.m_bytes_in + dst->second.m_bytes_out);
	}

	//
	// Marking functions
	//
	static void mark_top_by(std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list,
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

	static void mark_top(std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list, size_t limit)
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

// This class exists to sort a map of items based on the grous they belong to
// The map we will attempt to sort will be of type map<KT, T>. Each T in the map
// is expected to have a get_group_list function which returns an unordered_set
// of the G's to which that T belongs.
template <typename KT, typename T, typename G>
class group_request_sorter : public request_sorter<KT, T>
{
        static bool never_excluder(const T* value)
        {
            return false;
        }

        // allows us to skip any entries which have non-zero errors
        static bool error_excluder(const T* value)
        {
            return value->m_nerrors == 0;
        }

public:
	typedef bool (*request_comparer)(typename std::unordered_map<KT, T>::iterator src,
		      typename std::unordered_map<KT, T>::iterator dst);
	typedef bool (*request_excluder)(const T*);

private:
	/// walks through each {KT, T} pair, where each contains a list of G's, and
	/// marks the top limit pairs for each G. excluder skips certain events as
	/// defined in that function
	///
	/// @param sortable_list the list of things we want to find the top limit of
	/// @param comparer how we want to compare the things in the list
	/// @param limit the top N we want to find from the list
	/// @param excluder a way to skip certain items
	static void mark_top_by(std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list,
				request_comparer comparer,
				size_t limit,
				request_excluder excluder = never_excluder)
	{
		sort(sortable_list->begin(), sortable_list->end(), comparer);

		// map that stores some group identifier (opaque and implementation specific) and the amount we've found for that group
		std::unordered_map<const G*, uint64_t> counts_per_group;
		for (auto item = sortable_list->begin(); item != sortable_list->end(); ++item)
		{
			for (typename std::unordered_set<shared_ptr<G>>::iterator group = (*item)->second.get_group_list()->begin(); group != (*item)->second.get_group_list()->end(); ++group)
			{
				if (!excluder(&((*item)->second)) && counts_per_group[&**group] < limit)
				{
					(*item)->second.m_flags = (sinsp_request_flags)((*item)->second.m_flags | SRF_INCLUDE_IN_SAMPLE);
					++counts_per_group[&**group];
				}
			}
		}
	}

public:
	static void mark_top(std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list, size_t limit)
	{
		//
		// Mark top based on number of calls
		//
		mark_top_by(sortable_list, 
			request_sorter<KT, T>::cmp_ncalls, limit);
						
		//
		// Mark top based on total time
		//
		mark_top_by(sortable_list, 
			request_sorter<KT, T>::cmp_time_avg, limit);

		//
		// Mark top based on max time
		//
		mark_top_by(sortable_list, 
			request_sorter<KT, T>::cmp_time_max, limit);

		//
		// Mark top based on total bytes
		//
		mark_top_by(sortable_list, 
			request_sorter<KT, T>::cmp_bytes_tot, limit);

		//
		// Will have 0 errors a lot, so
		// exclude ones that have none
		//
		mark_top_by(sortable_list,
				request_sorter<KT, T>::cmp_nerrors,
				limit,
				error_excluder);
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
		std::unordered_map<std::string, sinsp_query_details>* table,
		bool is_server,
		uint32_t sampling_ratio,
		bool is_query_table, uint32_t limit);
	void query_type_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
		std::unordered_map<uint32_t, sinsp_query_details>* table,
		bool is_server,
		uint32_t sampling_ratio, uint32_t limit);

	std::unordered_map<std::string, sinsp_query_details> m_server_queries;
	std::unordered_map<std::string, sinsp_query_details> m_client_queries;
	std::unordered_map<uint32_t, sinsp_query_details> m_server_query_types;
	std::unordered_map<uint32_t, sinsp_query_details> m_client_query_types;
	std::unordered_map<std::string, sinsp_query_details> m_server_tables;
	std::unordered_map<std::string, sinsp_query_details> m_client_tables;
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
	void collections_to_protobuf(std::unordered_map<std::string, sinsp_query_details>& map,
									const function<draiosproto::mongodb_collection_details*(void)> get_cd,
								 uint32_t sampling_ratio, uint32_t limit);
	// MongoDB
	std::unordered_map<uint32_t, sinsp_query_details> m_server_ops;
	std::unordered_map<uint32_t, sinsp_query_details> m_client_ops;
	std::unordered_map<std::string, sinsp_query_details> m_server_collections;
	std::unordered_map<std::string, sinsp_query_details> m_client_collections;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;
};

class sinsp_http_state : public protocol_state
{
public:

        // constructor mainly to call clear so we can initialize the URL groups
        sinsp_http_state()
            : m_url_groups_enabled(false),
              m_url_groups()
        {
            clear();
        }

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
							   std::unordered_map<std::string, sinsp_url_details>* table,
							   bool is_server,
							   uint32_t sampling_ratio, uint32_t limit);
	void status_code_table_to_protobuf(draiosproto::http_info* protobuf_msg,
									   std::unordered_map<uint32_t, sinsp_request_details>* table,
									   bool is_server,
									   uint32_t sampling_ratio, uint32_t limit);
	std::unordered_map<std::string, sinsp_url_details> m_server_urls;
	std::unordered_map<std::string, sinsp_url_details> m_client_urls;
	std::unordered_map<uint32_t, sinsp_request_details> m_server_status_codes;
	std::unordered_map<uint32_t, sinsp_request_details> m_client_status_codes;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;

	bool m_url_groups_enabled;
	sinsp_url_groups m_url_groups;

	friend class sinsp_protostate;
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

	// static member to hold the URL groups. Ideally we'd pull this straight from
	// dragent_config, but include issues make that difficult
	static void set_url_groups(const std::set<std::string>& groups);
	static sinsp_url_groups* s_url_groups;
};

class sinsp_http_marker
{
public:
	// give pointers to all URLs to the marker. Also match URLs which haven't been, as the marker will need this info to properly
	// sort and mark
	void add(sinsp_http_state* state)
	{
		if (sinsp_protostate::s_url_groups)
		{
			for (auto url = state->m_server_urls.begin(); url != state->m_server_urls.end(); ++url)
			{
				url->second.match_url_if_unmatched(*sinsp_protostate::s_url_groups, url->first);
			}
			for (auto url = state->m_client_urls.begin(); url != state->m_client_urls.end(); ++url)
			{
				url->second.match_url_if_unmatched(*sinsp_protostate::s_url_groups, url->first);
			}

		}

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
		if (sinsp_protostate::s_url_groups)
		{
			group_request_sorter<std::string, sinsp_url_details, sinsp_url_group>::mark_top(&m_server_urls, limit);
			group_request_sorter<std::string, sinsp_url_details, sinsp_url_group>::mark_top(&m_client_urls, limit);
		}
		else
		{
			request_sorter<std::string, sinsp_url_details>::mark_top(&m_server_urls, limit);
			request_sorter<std::string, sinsp_url_details>::mark_top(&m_client_urls, limit);
		}
		request_sorter<uint32_t, sinsp_request_details>::mark_top_by(&m_server_status_codes, request_sorter<uint32_t, sinsp_request_details>::cmp_ncalls, limit);
		request_sorter<uint32_t, sinsp_request_details>::mark_top_by(&m_client_status_codes, request_sorter<uint32_t, sinsp_request_details>::cmp_ncalls, limit);
	}

private:
	std::vector<std::unordered_map<std::string, sinsp_url_details>::iterator> m_server_urls;
	std::vector<std::unordered_map<std::string, sinsp_url_details>::iterator> m_client_urls;
	std::vector<std::unordered_map<uint32_t, sinsp_request_details>::iterator> m_server_status_codes;
	std::vector<std::unordered_map<uint32_t, sinsp_request_details>::iterator> m_client_status_codes;

        friend class test_helper;
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
		request_sorter<std::string, sinsp_query_details>::mark_top(&m_server_queries, limit);
		request_sorter<std::string, sinsp_query_details>::mark_top(&m_client_queries, limit);
		request_sorter<uint32_t, sinsp_query_details>::mark_top(&m_server_query_types, limit);
		request_sorter<uint32_t, sinsp_query_details>::mark_top(&m_client_query_types, limit);
		request_sorter<std::string, sinsp_query_details>::mark_top(&m_server_tables, limit);
		request_sorter<std::string, sinsp_query_details>::mark_top(&m_client_tables, limit);
	}

private:
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator> m_server_queries;
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator> m_client_queries;
	std::vector<std::unordered_map<uint32_t, sinsp_query_details>::iterator> m_server_query_types;
	std::vector<std::unordered_map<uint32_t, sinsp_query_details>::iterator> m_client_query_types;
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator> m_server_tables;
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator> m_client_tables;
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
		request_sorter<std::string, sinsp_query_details>::mark_top(&m_server_collections, limit);
		request_sorter<std::string, sinsp_query_details>::mark_top(&m_client_collections, limit);
	}

private:
	std::vector<std::unordered_map<uint32_t, sinsp_query_details>::iterator> m_server_ops;
	std::vector<std::unordered_map<uint32_t, sinsp_query_details>::iterator> m_client_ops;
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator> m_server_collections;
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator> m_client_collections;
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

        friend class test_helper;
};

#endif // HAS_ANALYZER
