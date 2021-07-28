#pragma once

#include "percentile.h"

#include <Poco/RegularExpression.h>

#include <functional>

#define SRV_PORT_MYSQL 3306
#define SRV_PORT_POSTGRES 5432

#include "parser_http.h"
#include "parser_mongodb.h"
#include "parser_mysql.h"
#include "parser_postgres.h"
#include "parser_tls.h"
#include "protocol_state.h"
#undef min
#undef max
#include "draios.pb.h"

class sinsp_configuration;

class url_group_config_data : public configuration_unit
{
public:
	url_group_config_data(const std::string& description,
	                      const std::string& key,
	                      const std::string& subkey = "",
	                      const std::string& subsubkey = "");

public:  // stuff for configuration_unit
	std::string value_to_string() const override {return "";}
	std::string value_to_yaml() const override {return "";}
	bool string_to_value(const std::string& value) override { return false;}
	void init(const yaml_configuration& raw_config) override;
	void post_init() override {}

public:  // extracting useful data
	const std::map<std::string, std::shared_ptr<sinsp_url_group>>& get_value() const;

private:
	std::map<std::string, shared_ptr<sinsp_url_group>> m_matched_groups;
};

///////////////////////////////////////////////////////////////////////////////
// Table entries
///////////////////////////////////////////////////////////////////////////////
class sinsp_query_details : public sinsp_request_details
{
};

///////////////////////////////////////////////////////////////////////////////
// Sorter class
///////////////////////////////////////////////////////////////////////////////
template<typename KT, typename T>
class request_sorter
{
	typedef bool (*request_comparer)(typename std::unordered_map<KT, T>::iterator src,
	                                 typename std::unordered_map<KT, T>::iterator dst);

public:
	//
	// Merge two maps by adding the elements of the source to the destination
	//
	inline static void update(T* entry,
	                          sinsp_partial_transaction* tr,
	                          int64_t time_delta,
	                          bool is_failure,
	                          const std::set<double>& percentiles)
	{
		if (entry->m_ncalls == 0)
		{
			entry->m_ncalls = 1;
			if (is_failure)
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
			if (is_failure)
			{
				entry->m_nerrors++;
			}
			entry->add_time(time_delta);
			entry->m_bytes_in += tr->m_prev_bytes_in;
			entry->m_bytes_out += tr->m_prev_bytes_out;

			if ((uint64_t)time_delta > entry->m_time_max)
			{
				entry->m_time_max = time_delta;
			}
		}
	}

	//
	// Merge two maps by adding the elements of the source to the destination
	//
#ifdef _WIN32
	static void merge_maps(typename std::unordered_map<KT, T>* dst,
	                       typename std::unordered_map<KT, T>* src)
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
		for (uit = src->begin(); uit != src->end(); ++uit)
		{
			T& entry = (*dst)[uit->first];
			entry += uit->second;
		}
	}

	//
	// Comparers for sorting
	//
	static bool cmp_ncalls(typename std::unordered_map<KT, T>::iterator src,
	                       typename std::unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_ncalls > dst->second.m_ncalls;
	}

	static bool cmp_nerrors(typename std::unordered_map<KT, T>::iterator src,
	                        typename std::unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_nerrors > dst->second.m_nerrors;
	}

	static bool cmp_time_avg(typename std::unordered_map<KT, T>::iterator src,
	                         typename std::unordered_map<KT, T>::iterator dst)
	{
		return (src->second.get_time_tot() / src->second.m_ncalls) >
		       (dst->second.get_time_tot() / dst->second.m_ncalls);
	}

	static bool cmp_time_max(typename std::unordered_map<KT, T>::iterator src,
	                         typename std::unordered_map<KT, T>::iterator dst)
	{
		return src->second.m_time_max > dst->second.m_time_max;
	}

	static bool cmp_bytes_tot(typename std::unordered_map<KT, T>::iterator src,
	                          typename std::unordered_map<KT, T>::iterator dst)
	{
		return (src->second.m_bytes_in + src->second.m_bytes_out) >
		       (dst->second.m_bytes_in + dst->second.m_bytes_out);
	}

	//
	// Marking functions
	//
	static void mark_top_by(
	    std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list,
	    request_comparer comparer,
	    size_t limit)
	{
		uint32_t j;

		if (sortable_list->size() > limit)
		{
			partial_sort(sortable_list->begin(),
			             sortable_list->begin() + limit,
			             sortable_list->end(),
			             comparer);
		}

		for (j = 0; j < std::min(limit, sortable_list->size()); j++)
		{
			sortable_list->at(j)->second.m_flags =
			    (sinsp_request_flags)((uint32_t)sortable_list->at(j)->second.m_flags |
			                          SRF_INCLUDE_IN_SAMPLE);
		}
	}

	static void mark_top(std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list,
	                     size_t limit)
	{
		//
		// Mark top based on number of calls
		//
		mark_top_by(sortable_list, cmp_ncalls, limit);

		//
		// Mark top based on total time
		//
		mark_top_by(sortable_list, cmp_time_avg, limit);

		//
		// Mark top based on max time
		//
		mark_top_by(sortable_list, cmp_time_max, limit);

		//
		// Mark top based on total bytes
		//
		mark_top_by(sortable_list, cmp_bytes_tot, limit);

		//
		// Mark top based on number of errors
		// Note: we don't use mark_top_by() because there's a good chance that less than
		//       TOP_URLS_IN_SAMPLE entries have errors, and so we add only the ones that
		//       have m_nerrors > 0.
		//
		if (sortable_list->size() > limit)
		{
			partial_sort(sortable_list->begin(),
			             sortable_list->begin() + limit,
			             sortable_list->end(),
			             cmp_nerrors);
		}

		for (uint32_t j = 0; j < std::min(limit, sortable_list->size()); j++)
		{
			T* entry = &(sortable_list->at(j)->second);

			if (entry->m_nerrors > 0)
			{
				entry->m_flags =
				    (sinsp_request_flags)((uint32_t)sortable_list->at(j)->second.m_flags |
				                          SRF_INCLUDE_IN_SAMPLE);
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
template<typename KT, typename T, typename G>
class group_request_sorter : public request_sorter<KT, T>
{
	static bool never_excluder(const T* value) { return false; }

	// allows us to skip any entries which have non-zero errors
	static bool error_excluder(const T* value) { return value->m_nerrors == 0; }

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
	static void mark_top_by(
	    std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list,
	    request_comparer comparer,
	    size_t limit,
	    request_excluder excluder = never_excluder)
	{
		sort(sortable_list->begin(), sortable_list->end(), comparer);

		// map that stores some group identifier (opaque and implementation specific) and the amount
		// we've found for that group
		std::unordered_map<const G*, uint64_t> counts_per_group;
		for (auto item = sortable_list->begin(); item != sortable_list->end(); ++item)
		{
			for (typename std::unordered_set<std::shared_ptr<G>>::iterator group =
			         (*item)->second.get_group_list()->begin();
			     group != (*item)->second.get_group_list()->end();
			     ++group)
			{
				if (!excluder(&((*item)->second)) && counts_per_group[&**group] < limit)
				{
					(*item)->second.m_flags =
					    (sinsp_request_flags)((*item)->second.m_flags | SRF_INCLUDE_IN_SAMPLE);
					++counts_per_group[&**group];
				}
			}
		}
	}

public:
	static void mark_top(std::vector<typename std::unordered_map<KT, T>::iterator>* sortable_list,
	                     size_t limit)
	{
		//
		// Mark top based on number of calls
		//
		mark_top_by(sortable_list, request_sorter<KT, T>::cmp_ncalls, limit);

		//
		// Mark top based on total time
		//
		mark_top_by(sortable_list, request_sorter<KT, T>::cmp_time_avg, limit);

		//
		// Mark top based on max time
		//
		mark_top_by(sortable_list, request_sorter<KT, T>::cmp_time_max, limit);

		//
		// Mark top based on total bytes
		//
		mark_top_by(sortable_list, request_sorter<KT, T>::cmp_bytes_tot, limit);

		//
		// Will have 0 errors a lot, so
		// exclude ones that have none
		//
		mark_top_by(sortable_list, request_sorter<KT, T>::cmp_nerrors, limit, error_excluder);
	}
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
	            uint64_t time_delta,
	            bool is_server,
	            uint32_t truncation_size);

	void to_protobuf(draiosproto::sql_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit);
	void coalesce_protobuf(draiosproto::sql_info* protobuf_msg, uint32_t sampling_ratio);

	inline bool has_data() { return m_server_queries.size() > 0 || m_client_queries.size() > 0; }

private:
	friend class sinsp_sql_marker;
	void query_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
	                             std::unordered_map<std::string, sinsp_query_details>* table,
	                             bool is_server,
	                             uint32_t sampling_ratio,
	                             bool is_query_table,
	                             uint32_t limit);
	void query_type_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
	                                  std::unordered_map<uint32_t, sinsp_query_details>* table,
	                                  bool is_server,
	                                  uint32_t sampling_ratio,
	                                  uint32_t limit);

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
	            uint64_t time_delta,
	            bool is_server,
	            uint32_t truncation_size);

	void to_protobuf(draiosproto::mongodb_info* protobuf_msg,
	                 uint32_t sampling_ratio,
	                 uint32_t limit);
	void coalesce_protobuf(draiosproto::mongodb_info* protobuf_msg, uint32_t sampling_ratio);

	inline bool has_data() { return m_server_ops.size() > 0 || m_client_ops.size() > 0; }

private:
	friend class sinsp_mongodb_marker;
	void collections_to_protobuf(
	    std::unordered_map<std::string, sinsp_query_details>& map,
	    const std::function<draiosproto::mongodb_collection_details*(void)> get_cd,
	    uint32_t sampling_ratio,
	    uint32_t limit);
	// MongoDB
	std::unordered_map<uint32_t, sinsp_query_details> m_server_ops;
	std::unordered_map<uint32_t, sinsp_query_details> m_client_ops;
	std::unordered_map<std::string, sinsp_query_details> m_server_collections;
	std::unordered_map<std::string, sinsp_query_details> m_client_collections;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;
};

///////////////////////////////////////////////////////////////////////////////
// The protocol state class
///////////////////////////////////////////////////////////////////////////////
class sinsp_protostate
{
public:
	void update(sinsp_partial_transaction* tr,
	            uint64_t time_delta,
	            bool is_server,
	            uint32_t truncation_size);

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
	void to_protobuf(draiosproto::proto_info* protobuf_msg,
	                 uint32_t sampling_ratio,
	                 uint32_t limit);
	void coalesce_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio);

	sinsp_http_state m_http;
	sql_state m_mysql;
	sql_state m_postgres;
	mongodb_state m_mongodb;
};

class sinsp_http_marker
{
public:
	// give pointers to all URLs to the marker. Also match URLs which haven't been, as the marker
	// will need this info to properly sort and mark
	void add(sinsp_http_state* state);

	void mark_top(size_t limit);

private:
	std::vector<std::unordered_map<std::string, sinsp_url_details>::iterator> m_server_urls;
	std::vector<std::unordered_map<std::string, sinsp_url_details>::iterator> m_client_urls;
	std::vector<std::unordered_map<uint32_t, sinsp_request_details>::iterator>
	    m_server_status_codes;
	std::vector<std::unordered_map<uint32_t, sinsp_request_details>::iterator>
	    m_client_status_codes;

	friend class test_helper;
};

class sinsp_sql_marker
{
public:
	void add(sql_state* state)
	{
		for (auto it = state->m_server_queries.begin(); it != state->m_server_queries.end(); ++it)
		{
			m_server_queries.push_back(it);
		}
		for (auto it = state->m_client_queries.begin(); it != state->m_client_queries.end(); ++it)
		{
			m_client_queries.push_back(it);
		}
		for (auto it = state->m_server_query_types.begin(); it != state->m_server_query_types.end();
		     ++it)
		{
			m_server_query_types.push_back(it);
		}
		for (auto it = state->m_client_query_types.begin(); it != state->m_client_query_types.end();
		     ++it)
		{
			m_client_query_types.push_back(it);
		}
		for (auto it = state->m_server_tables.begin(); it != state->m_server_tables.end(); ++it)
		{
			m_server_tables.push_back(it);
		}
		for (auto it = state->m_client_tables.begin(); it != state->m_client_tables.end(); ++it)
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
		for (auto it = state->m_server_ops.begin(); it != state->m_server_ops.end(); ++it)
		{
			m_server_ops.push_back(it);
		}
		for (auto it = state->m_client_ops.begin(); it != state->m_client_ops.end(); ++it)
		{
			m_client_ops.push_back(it);
		}
		for (auto it = state->m_server_collections.begin(); it != state->m_server_collections.end();
		     ++it)
		{
			m_server_collections.push_back(it);
		}
		for (auto it = state->m_client_collections.begin(); it != state->m_client_collections.end();
		     ++it)
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
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator>
	    m_server_collections;
	std::vector<std::unordered_map<std::string, sinsp_query_details>::iterator>
	    m_client_collections;
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
