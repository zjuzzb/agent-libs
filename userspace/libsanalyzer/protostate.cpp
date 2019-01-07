#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#include "analyzer_int.h"
#include "parser_http.h"
#include "metrics.h"
#undef min
#undef max
#include "draios.pb.h"
#include "protostate.h"

///////////////////////////////////////////////////////////////////////////////
// Transaction table update support
///////////////////////////////////////////////////////////////////////////////
inline void sinsp_http_state::update(sinsp_partial_transaction* tr,
						uint64_t time_delta, bool is_server, uint32_t truncation_size)
{
	ASSERT(tr->m_protoparser != NULL);

	if(tr->m_protoparser->m_is_valid)
	{
		sinsp_http_parser* pp = (sinsp_http_parser*)tr->m_protoparser;
		auto url = truncate_str(pp->result().url, truncation_size);
		bool is_error = ((pp->result().status_code >= 400) && (pp->result().status_code < 600));

		//
		// Update the URL table
		//
		if(is_server)
		{
			if(m_server_urls.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_server_urls.count(url))
			{
				auto entry = &(m_server_urls[url]);
				request_sorter<string, sinsp_url_details>::update(entry, tr, time_delta, is_error, m_percentiles);
			}
			request_sorter<string, sinsp_request_details>::update(&m_server_totals, tr, time_delta, is_error, m_percentiles);
		}
		else
		{
			if(m_client_urls.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_client_urls.count(url))
			{
				auto entry = &(m_client_urls[url]);
				request_sorter<string, sinsp_url_details>::update(entry, tr, time_delta, is_error, m_percentiles);
			}
			request_sorter<string, sinsp_request_details>::update(&m_client_totals, tr, time_delta, is_error, m_percentiles);
		}

		//
		// Update the status code table
		//
		sinsp_request_details* status_code_entry;
		if(is_server)
		{
			status_code_entry = &(m_server_status_codes[pp->result().status_code]);
		}
		else
		{
			status_code_entry = &(m_client_status_codes[pp->result().status_code]);
		}
		status_code_entry->m_ncalls += 1;

		// we don't add any samples for status codes, hence no need for
		// percentile store
		//status_code_entry->set_percentiles(m_percentiles);
	}
}

template<typename Parser>
inline void sql_state::update(sinsp_partial_transaction* tr,
						uint64_t time_delta, bool is_server, uint32_t truncation_size)
{
	ASSERT(tr->m_protoparser != NULL);

	if(tr->m_protoparser->m_is_valid)
	{
		Parser* pp = (Parser*)tr->m_protoparser;
		bool is_error = (pp->m_error_code != 0);

		//
		// Make sure this is a query
		//
		if(pp->m_msgtype != Parser::MT_QUERY)
		{
			return;
		}

		//
		// Update the tables
		//
		sinsp_query_details* entry;
		sinsp_query_details* type_entry;
		auto tables = pp->m_query_parser.tables();
		auto statement = truncate_str(pp->m_statement, truncation_size);

		if(is_server)
		{
			if(m_server_queries.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_server_queries.count(statement))
			{
				entry = &(m_server_queries[statement]);
				request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error, m_percentiles);
			}

			if(!tables.empty())
			{
				auto trunc_table = truncate_str(tables, truncation_size);
				if (m_server_tables.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_server_tables.count(trunc_table))
				{
					entry = &(m_server_tables[trunc_table]);
					request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error, m_percentiles);
				}
			}

			type_entry = &(m_server_query_types[pp->m_query_parser.m_statement_type]);
			request_sorter<uint32_t, sinsp_query_details>::update(type_entry, tr, time_delta, is_error, m_percentiles);

			request_sorter<uint32_t, sinsp_request_details>::update(&m_server_totals, tr, time_delta, is_error, m_percentiles);
		}
		else
		{
			if(m_client_queries.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_client_queries.count(statement))
			{
				entry = &(m_client_queries[statement]);
				request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error, m_percentiles);
			}

			if(!tables.empty())
			{
				auto trunc_table = truncate_str(tables, truncation_size);
				if(m_client_tables.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_client_tables.count(trunc_table))
				{
					entry = &(m_client_tables[trunc_table]);
					request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error, m_percentiles);
				}
			}

			type_entry = &(m_client_query_types[pp->m_query_parser.m_statement_type]);
			request_sorter<uint32_t, sinsp_query_details>::update(type_entry, tr, time_delta, is_error, m_percentiles);

			request_sorter<uint32_t, sinsp_request_details>::update(&m_client_totals, tr, time_delta, is_error, m_percentiles);
		}
	}
}

void sinsp_protostate::update(sinsp_partial_transaction* tr,
	uint64_t time_delta,
	bool is_server, uint32_t truncation_size)
{
	if(tr->m_type == sinsp_partial_transaction::TYPE_HTTP)
	{
		m_http.update(tr, time_delta, is_server, truncation_size);
	}
	else if(tr->m_type == sinsp_partial_transaction::TYPE_MYSQL)
	{
		m_mysql.update<sinsp_mysql_parser>(tr, time_delta, is_server, truncation_size);
	}
	else if(tr->m_type == sinsp_partial_transaction::TYPE_POSTGRES)
	{
		m_postgres.update<sinsp_postgres_parser>(tr, time_delta, is_server, truncation_size);
	} else if(tr->m_type == sinsp_partial_transaction::TYPE_MONGODB)
	{
		m_mongodb.update(tr, time_delta, is_server, truncation_size);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Aggregation support
///////////////////////////////////////////////////////////////////////////////
inline void sinsp_http_state::add(sinsp_http_state* other)
{
	//
	// Add the URLs
	//
	request_sorter<string, sinsp_url_details>::merge_maps(&m_server_urls, &(other->m_server_urls));
	request_sorter<string, sinsp_url_details>::merge_maps(&m_client_urls, &(other->m_client_urls));
	request_sorter<uint32_t, sinsp_request_details>::merge_maps(&m_server_status_codes, &(other->m_server_status_codes));
	request_sorter<uint32_t, sinsp_request_details>::merge_maps(&m_client_status_codes, &(other->m_client_status_codes));

	m_server_totals += other->m_server_totals;
	m_client_totals += other->m_client_totals;
}

inline void sql_state::add(sql_state* other)
{
	request_sorter<string, sinsp_query_details>::merge_maps(&m_server_queries, &(other->m_server_queries));
	request_sorter<string, sinsp_query_details>::merge_maps(&m_client_queries, &(other->m_client_queries));

	request_sorter<string, sinsp_query_details>::merge_maps(&m_server_tables, &(other->m_server_tables));
	request_sorter<string, sinsp_query_details>::merge_maps(&m_client_tables, &(other->m_client_tables));

	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_server_query_types, &(other->m_server_query_types));
	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_client_query_types, &(other->m_client_query_types));

	m_server_totals += other->m_server_totals;
	m_client_totals += other->m_client_totals;
}

void sinsp_protostate::set_percentiles(const std::set<double>& pctls)
{
	m_http.set_percentiles(pctls);
	m_mysql.set_percentiles(pctls);
	m_postgres.set_percentiles(pctls);
	m_mongodb.set_percentiles(pctls);
}

void sinsp_protostate::set_serialize_pctl_data(bool val)
{
	m_http.set_serialize_pctl_data(val);
	m_mysql.set_serialize_pctl_data(val);
	m_postgres.set_serialize_pctl_data(val);
	m_mongodb.set_serialize_pctl_data(val);
}

void sinsp_protostate::add(sinsp_protostate* other)
{
	m_http.add(&(other->m_http));
	m_mysql.add(&(other->m_mysql));
	m_postgres.add(&(other->m_postgres));
	m_mongodb.add(&(other->m_mongodb));
}

///////////////////////////////////////////////////////////////////////////////
// Protobuf generation
///////////////////////////////////////////////////////////////////////////////
void sinsp_http_state::url_table_to_protobuf(draiosproto::http_info* protobuf_msg,
						   unordered_map<string, sinsp_url_details>* table,
						   bool is_server,
						   uint32_t sampling_ratio, uint32_t limit)
{
	draiosproto::url_details* ud;

	//
	// The table is small enough that we don't need to sort it
	//
	uint32_t j = 0;
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit, ++j)
	{
		if(uit->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			if(is_server)
			{
				ud = protobuf_msg->add_server_urls();
			}
			else
			{
				ud = protobuf_msg->add_client_urls();
			}

			ud->set_url(uit->first);
			uit->second.to_protobuf(ud->mutable_counters(), sampling_ratio,
					[&] (const sinsp_request_details::percentile_ptr_t pct) {
				percentile_to_protobuf(ud->mutable_counters(), pct);
			});
		}
	}
}

void sinsp_http_state::status_code_table_to_protobuf(draiosproto::http_info* protobuf_msg,
	unordered_map<uint32_t, sinsp_request_details>* table,
	bool is_server,
	uint32_t sampling_ratio, uint32_t limit)
{
	draiosproto::status_code_details* ud;
	//
	// The table is small enough that we don't need to sort it
	//
	uint32_t j = 0;
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit, ++j)
	{
		if(uit->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			if(is_server)
			{
				ud = protobuf_msg->add_server_status_codes();
			}
			else
			{
				ud = protobuf_msg->add_client_status_codes();
			}

			ud->set_status_code(uit->first);
			ud->set_ncalls(uit->second.m_ncalls * sampling_ratio);
		}
	}
}

void sql_state::query_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
						   unordered_map<string, sinsp_query_details>* table,
						   bool is_server,
						   uint32_t sampling_ratio,
						   bool is_query_table, uint32_t limit)
{
	draiosproto::sql_entry_details* ud;

	//
	// The table is small enough that we don't need to sort it
	//
	uint32_t j = 0;
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit, ++j)
	{
		if(uit->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			if(is_query_table)
			{
				if(is_server)
				{
					ud = protobuf_msg->add_server_queries();
				}
				else
				{
					ud = protobuf_msg->add_client_queries();
				}
			}
			else
			{
				if(is_server)
				{
					ud = protobuf_msg->add_server_tables();
				}
				else
				{
					ud = protobuf_msg->add_client_tables();
				}
			}

			ud->set_name(uit->first);
			uit->second.to_protobuf(ud->mutable_counters(), sampling_ratio,
					[&] (const sinsp_request_details::percentile_ptr_t pct) {
				percentile_to_protobuf(ud->mutable_counters(), pct);
			});
		}
	}
}

void sql_state::query_type_table_to_protobuf(draiosproto::sql_info* protobuf_msg,
						   unordered_map<uint32_t, sinsp_query_details>* table,
						   bool is_server,
						   uint32_t sampling_ratio, uint32_t limit)
{
	draiosproto::sql_query_type_details* ud;

	//
	// The table is small enough that we don't need to sort it
	//
	uint32_t j = 0;
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit, ++j)
	{
		if(uit->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			if(is_server)
			{
				ud = protobuf_msg->add_server_query_types();
			}
			else
			{
				ud = protobuf_msg->add_client_query_types();
			}

			ud->set_type((draiosproto::sql_statement_type) uit->first);
			uit->second.to_protobuf(ud->mutable_counters(), sampling_ratio,
					[&] (const sinsp_request_details::percentile_ptr_t pct) {
				percentile_to_protobuf(ud->mutable_counters(), pct);
			});
		}
	}
}

void sinsp_http_state::to_protobuf(draiosproto::http_info *protobuf_msg, uint32_t sampling_ratio, uint32_t limit)
{
	if(m_server_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_server_urls, true, sampling_ratio, limit);
	}

	if(m_client_urls.size() != 0)
	{
		url_table_to_protobuf(protobuf_msg, &m_client_urls, false, sampling_ratio, limit);
	}

	if(m_server_status_codes.size() != 0)
	{
		status_code_table_to_protobuf(protobuf_msg, &m_server_status_codes, true, sampling_ratio, limit);
	}

	if(m_client_status_codes.size() != 0)
	{
		status_code_table_to_protobuf(protobuf_msg, &m_client_status_codes, false, sampling_ratio, limit);
	}

	draiosproto::counter_proto_entry* totals;

	if (m_server_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_server_totals();
		m_server_totals.to_protobuf(totals, sampling_ratio,
				[&] (const sinsp_request_details::percentile_ptr_t pct) {
			percentile_to_protobuf(totals, pct);
		});
	}

	if (m_client_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_client_totals();
		m_client_totals.to_protobuf(totals, sampling_ratio,
				[&] (const sinsp_request_details::percentile_ptr_t pct) {
			percentile_to_protobuf(totals, pct);
		});
	}

}

void sinsp_protostate::to_protobuf(draiosproto::proto_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit)
{
	//
	// HTTP
	//
	if(m_http.has_data())
	{
		m_http.to_protobuf(protobuf_msg->mutable_http(), sampling_ratio, limit);
	}
	//
	// mysql
	//
	if(m_mysql.has_data())
	{
		m_mysql.to_protobuf(protobuf_msg->mutable_mysql(), sampling_ratio, limit);
	}
	if(m_postgres.has_data())
	{
		m_postgres.to_protobuf(protobuf_msg->mutable_postgres(), sampling_ratio, limit);
	}
	if(m_mongodb.has_data())
	{
		m_mongodb.to_protobuf(protobuf_msg->mutable_mongodb(), sampling_ratio, limit);
	}
}

void sql_state::to_protobuf(draiosproto::sql_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit)
{
	if(m_server_queries.size() != 0)
	{
		query_table_to_protobuf(protobuf_msg, &m_server_queries, true, sampling_ratio, true, limit);
		query_table_to_protobuf(protobuf_msg, &m_server_tables, true, sampling_ratio, false, limit);
		query_type_table_to_protobuf(protobuf_msg, &m_server_query_types, true, sampling_ratio, limit);
	}

	if(m_client_queries.size() != 0)
	{
		query_table_to_protobuf(protobuf_msg, &m_client_queries, false, sampling_ratio, true, limit);
		query_table_to_protobuf(protobuf_msg, &m_client_tables, false, sampling_ratio, false, limit);
		query_type_table_to_protobuf(protobuf_msg, &m_client_query_types, false, sampling_ratio, limit);
	}

	draiosproto::counter_proto_entry* totals;

	if (m_server_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_server_totals();
		m_server_totals.to_protobuf(totals, sampling_ratio,
				[&] (const sinsp_request_details::percentile_ptr_t pct) {
			percentile_to_protobuf(totals, pct);
		});
	}

	if (m_client_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_client_totals();
		m_client_totals.to_protobuf(totals, sampling_ratio,
				[&] (const sinsp_request_details::percentile_ptr_t pct) {
			percentile_to_protobuf(totals, pct);
		});
	}
}

inline void mongodb_state::add(mongodb_state *other)
{
	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_server_ops, &(other->m_server_ops));
	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_client_ops, &(other->m_client_ops));

	request_sorter<std::string, sinsp_query_details>::merge_maps(&m_server_collections, &(other->m_server_collections));
	request_sorter<std::string, sinsp_query_details>::merge_maps(&m_client_collections, &(other->m_client_collections));

	m_server_totals += other->m_server_totals;
	m_client_totals += other->m_client_totals;
}

inline void mongodb_state::update(sinsp_partial_transaction *tr, uint64_t time_delta, bool is_server, uint32_t truncation_size)
{
	ASSERT(tr->m_protoparser != NULL);

	if(tr->m_protoparser->m_is_valid)
	{
		sinsp_query_details *op_entry;
		sinsp_query_details *collection_entry;
		sinsp_mongodb_parser* pp = static_cast<sinsp_mongodb_parser*>(tr->m_protoparser);
		bool is_error = (pp->m_error_code != 0);
		if(is_server)
		{
			if(pp->m_collection != NULL)
			{
				auto collection = truncate_str(pp->m_collection, truncation_size);
				if(m_server_collections.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_server_collections.count(collection))
				{
					collection_entry =&(m_server_collections[collection]);
					request_sorter<string, sinsp_query_details>::update(collection_entry, tr, time_delta, is_error, m_percentiles);
				}
			}
			op_entry = &(m_server_ops[pp->m_opcode]);
			request_sorter<uint32_t, sinsp_query_details>::update(op_entry, tr, time_delta, is_error, m_percentiles);
			request_sorter<string, sinsp_request_details>::update(&m_server_totals, tr, time_delta, is_error, m_percentiles);
		}
		else
		{
			if(pp->m_collection != NULL) {
				auto collection = truncate_str(pp->m_collection, truncation_size);
				if(m_client_collections.size() < MAX_THREAD_REQUEST_TABLE_SIZE || m_client_collections.count(collection))
				{
					collection_entry =&(m_client_collections[collection]);
					request_sorter<string, sinsp_query_details>::update(collection_entry, tr, time_delta, is_error, m_percentiles);
				}
			}
			op_entry = &(m_client_ops[pp->m_opcode]);
			request_sorter<uint32_t, sinsp_query_details>::update(op_entry, tr, time_delta, is_error, m_percentiles);
			request_sorter<string, sinsp_request_details>::update(&m_client_totals, tr, time_delta, is_error, m_percentiles);
		}
	}
}

void mongodb_state::collections_to_protobuf(unordered_map<string, sinsp_query_details>& map,
										   const function<draiosproto::mongodb_collection_details*(void)> get_cd,
											uint32_t sampling_ratio, uint32_t limit)
{
	uint32_t j = 0;
	for (auto it = map.begin(); j < limit && it != map.end(); ++it)
	{
		if(it->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			auto cd = get_cd();
			cd->set_name(it->first);
			it->second.to_protobuf(cd->mutable_counters(), sampling_ratio,
					[&] (const sinsp_request_details::percentile_ptr_t pct) {
				percentile_to_protobuf(cd->mutable_counters(), pct);
			});

			j += 1;
		}
	}
}

void mongodb_state::to_protobuf(draiosproto::mongodb_info *protobuf_msg, uint32_t sampling_ratio, uint32_t limit)
{
	draiosproto::mongodb_op_type_details *ud;

	uint32_t j = 0;
	for (auto it = m_server_ops.begin(); j < limit && it != m_server_ops.end(); ++it, ++j)
	{
		if(it->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			ud = protobuf_msg->add_servers_ops();
			ud->set_op((draiosproto::mongodb_op_type)it->first);
			it->second.to_protobuf(ud->mutable_counters(), sampling_ratio,
					[&] (const sinsp_request_details::percentile_ptr_t pct) {
				percentile_to_protobuf(ud->mutable_counters(), pct);
			});

		}
	}

	j = 0;
	for (auto it = m_client_ops.begin(); j < limit && it != m_client_ops.end(); ++it, ++j)
	{
		if(it->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			ud = protobuf_msg->add_client_ops();
			ud->set_op((draiosproto::mongodb_op_type) it->first);
			it->second.to_protobuf(ud->mutable_counters(), sampling_ratio,
					[&] (const sinsp_request_details::percentile_ptr_t pct) {
				percentile_to_protobuf(ud->mutable_counters(), pct);
			});

		}
	}

	collections_to_protobuf(m_server_collections,
		[protobuf_msg]() {
			return protobuf_msg->add_server_collections();
		},
		sampling_ratio, limit);
	collections_to_protobuf(m_client_collections,
		[protobuf_msg]() {
			return protobuf_msg->add_client_collections();
		},
		sampling_ratio, limit);

	draiosproto::counter_proto_entry* totals;

	if (m_server_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_server_totals();
		m_server_totals.to_protobuf(totals, sampling_ratio,
				[&] (const sinsp_request_details::percentile_ptr_t pct) {
			percentile_to_protobuf(totals, pct);
		});
	}

	if (m_client_totals.get_time_tot())
	{
		totals = protobuf_msg->mutable_client_totals();
		m_client_totals.to_protobuf(totals, sampling_ratio,
				[&] (const sinsp_request_details::percentile_ptr_t pct) {
			percentile_to_protobuf(totals, pct);
		});
	}

}

#endif // HAS_ANALYZER
