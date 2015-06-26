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
						uint64_t time_delta, bool is_server)
{
	ASSERT(tr->m_protoparser != NULL);

	if(tr->m_protoparser->m_is_valid)
	{
		sinsp_http_parser* pp = (sinsp_http_parser*)tr->m_protoparser;

		//
		// Update the URL table
		//
		sinsp_url_details* entry;

		if(is_server)
		{
			if(m_server_urls.size() > MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				//
				// Table limit reached
				//
				return;
			}

			entry = &(m_server_urls[truncate_str(pp->m_url)]);
		}
		else
		{
			if(m_client_urls.size() > MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				//
				// Table limit reached
				//
				return;
			}

			entry = &(m_client_urls[truncate_str(pp->m_url)]);
		}

		bool is_error = ((pp->m_status_code > 400) && (pp->m_status_code < 600));
		request_sorter<string, sinsp_url_details>::update(entry, tr, time_delta, is_error);

		//
		// Update the status code table
		//
		sinsp_request_details* status_code_entry;
		if(is_server)
		{
			status_code_entry = &(m_server_status_codes[pp->m_status_code]);
		}
		else
		{
			status_code_entry = &(m_client_status_codes[pp->m_status_code]);
		}
		status_code_entry->m_ncalls += 1;
	}
}

template<typename Parser>
inline void sql_state::update(sinsp_partial_transaction* tr,
						uint64_t time_delta, bool is_server)
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
		char* tablename = pp->m_query_parser.m_table;

		if(is_server)
		{
			if(m_server_queries.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				entry = &(m_server_queries[truncate_str(pp->m_statement)]);
				request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error);
			}

			if(tablename != NULL &&
				m_server_tables.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				entry = &(m_server_tables[truncate_str(pp->m_query_parser.m_table)]);
				request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error);
			}

			type_entry = &(m_server_query_types[pp->m_query_parser.m_statement_type]);
			request_sorter<uint32_t, sinsp_query_details>::update(type_entry, tr, time_delta, is_error);
		}
		else
		{
			if(m_client_queries.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				entry = &(m_client_queries[truncate_str(pp->m_statement)]);
				request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error);
			}

			if(tablename != NULL &&
				m_client_tables.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				entry = &(m_client_tables[truncate_str(pp->m_query_parser.m_table)]);
				request_sorter<string, sinsp_query_details>::update(entry, tr, time_delta, is_error);
			}

			type_entry = &(m_client_query_types[pp->m_query_parser.m_statement_type]);
			request_sorter<uint32_t, sinsp_query_details>::update(type_entry, tr, time_delta, is_error);
		}
	}
}

void sinsp_protostate::update(sinsp_partial_transaction* tr,
	uint64_t time_delta,
	bool is_server)
{
	if(tr->m_type == sinsp_partial_transaction::TYPE_HTTP)
	{
		m_http.update(tr, time_delta, is_server);
	}
	else if(tr->m_type == sinsp_partial_transaction::TYPE_MYSQL)
	{
		m_mysql.update<sinsp_mysql_parser>(tr, time_delta, is_server);
	}
	else if(tr->m_type == sinsp_partial_transaction::TYPE_POSTGRES)
	{
		m_postgres.update<sinsp_postgres_parser>(tr, time_delta, is_server);
	} else if(tr->m_type == sinsp_partial_transaction::TYPE_MONGODB)
	{
		m_mongodb.update(tr, time_delta, is_server);
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
}

inline void sql_state::add(sql_state* other)
{
	request_sorter<string, sinsp_query_details>::merge_maps(&m_server_queries, &(other->m_server_queries));
	request_sorter<string, sinsp_query_details>::merge_maps(&m_client_queries, &(other->m_client_queries));

	request_sorter<string, sinsp_query_details>::merge_maps(&m_server_tables, &(other->m_server_tables));
	request_sorter<string, sinsp_query_details>::merge_maps(&m_client_tables, &(other->m_client_tables));

	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_server_query_types, &(other->m_server_query_types));
	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_client_query_types, &(other->m_client_query_types));
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
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit)
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
			ud->mutable_counters()->set_ncalls(uit->second.m_ncalls * sampling_ratio);
			ud->mutable_counters()->set_time_tot(uit->second.m_time_tot * sampling_ratio);
			ud->mutable_counters()->set_time_max(uit->second.m_time_max);
			ud->mutable_counters()->set_bytes_in(uit->second.m_bytes_in * sampling_ratio);
			ud->mutable_counters()->set_bytes_out(uit->second.m_bytes_out * sampling_ratio);
			ud->mutable_counters()->set_nerrors(uit->second.m_nerrors * sampling_ratio);

			j += 1;
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
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit)
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

			j += 1;
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
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit)
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
			ud->mutable_counters()->set_ncalls(uit->second.m_ncalls * sampling_ratio);
			ud->mutable_counters()->set_time_tot(uit->second.m_time_tot * sampling_ratio);
			ud->mutable_counters()->set_time_max(uit->second.m_time_max);
			ud->mutable_counters()->set_bytes_in(uit->second.m_bytes_in * sampling_ratio);
			ud->mutable_counters()->set_bytes_out(uit->second.m_bytes_out * sampling_ratio);
			ud->mutable_counters()->set_nerrors(uit->second.m_nerrors * sampling_ratio);

			j += 1;
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
	for(auto uit = table->begin(); j < limit && uit != table->end(); ++uit)
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
			ud->mutable_counters()->set_ncalls(uit->second.m_ncalls * sampling_ratio);
			ud->mutable_counters()->set_time_tot(uit->second.m_time_tot * sampling_ratio);
			ud->mutable_counters()->set_time_max(uit->second.m_time_max);
			ud->mutable_counters()->set_bytes_in(uit->second.m_bytes_in * sampling_ratio);
			ud->mutable_counters()->set_bytes_out(uit->second.m_bytes_out * sampling_ratio);
			ud->mutable_counters()->set_nerrors(uit->second.m_nerrors * sampling_ratio);

			j += 1;
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
}

inline void mongodb_state::add(mongodb_state *other)
{
	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_server_ops, &(other->m_server_ops));
	request_sorter<uint32_t, sinsp_query_details>::merge_maps(&m_client_ops, &(other->m_client_ops));

	request_sorter<std::string, sinsp_query_details>::merge_maps(&m_server_collections, &(other->m_server_collections));
	request_sorter<std::string, sinsp_query_details>::merge_maps(&m_client_collections, &(other->m_client_collections));
}

inline void mongodb_state::update(sinsp_partial_transaction *tr, uint64_t time_delta, bool is_server)
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
			if(m_server_ops.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				op_entry = &(m_server_ops[pp->m_opcode]);
				request_sorter<uint32_t, sinsp_query_details>::update(op_entry, tr, time_delta, is_error);
			}
			if(pp->m_collection != NULL && m_server_collections.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				collection_entry =&(m_server_collections[truncate_str(pp->m_collection)]);
				request_sorter<string, sinsp_query_details>::update(collection_entry, tr, time_delta, is_error);
			}
		}
		else
		{
			if(m_client_ops.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				op_entry = &(m_client_ops[pp->m_opcode]);
				request_sorter<uint32_t, sinsp_query_details>::update(op_entry, tr, time_delta, is_error);
			}
			if(pp->m_collection != NULL && m_client_collections.size() < MAX_THREAD_REQUEST_TABLE_SIZE)
			{
				collection_entry =&(m_client_collections[truncate_str(pp->m_collection)]);
				request_sorter<string, sinsp_query_details>::update(collection_entry, tr, time_delta, is_error);
			}
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
			it->second.to_protobuf(cd->mutable_counters(), sampling_ratio);
			j += 1;
		}
	}
}

void mongodb_state::to_protobuf(draiosproto::mongodb_info *protobuf_msg, uint32_t sampling_ratio, uint32_t limit)
{
	draiosproto::mongodb_op_type_details *ud;

	uint32_t j = 0;
	for (auto it = m_server_ops.begin(); j < limit && it != m_server_ops.end(); ++it)
	{
		if(it->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			ud = protobuf_msg->add_servers_ops();
			ud->set_op((draiosproto::mongodb_op_type)it->first);
			it->second.to_protobuf(ud->mutable_counters(), sampling_ratio);
			j +=1;
		}
	}

	j = 0;
	for (auto it = m_client_ops.begin(); j < limit && it != m_client_ops.end(); ++it)
	{
		if(it->second.m_flags & (uint32_t)SRF_INCLUDE_IN_SAMPLE)
		{
			ud = protobuf_msg->add_client_ops();
			ud->set_op((draiosproto::mongodb_op_type) it->first);
			it->second.to_protobuf(ud->mutable_counters(), sampling_ratio);
		}
	}

	collections_to_protobuf(m_server_collections,[protobuf_msg]()
	{
		return protobuf_msg->add_server_collections();
	}, sampling_ratio, limit);
	collections_to_protobuf(m_client_collections,[protobuf_msg]()
	{
		return protobuf_msg->add_client_collections();
	}, sampling_ratio, limit);
}

#endif // HAS_ANALYZER
