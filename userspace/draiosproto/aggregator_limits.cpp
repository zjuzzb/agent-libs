#include "aggregator_limits.h"
#include "draios.proto.h"
#include "type_config.h"
#include <google/protobuf/repeated_field.h>
#include <list>

namespace
{

type_config<double> c_prom_metrics_weight(
	1.0,
	"Amount of weight givin to prom metrics relative to app metrics while choosing processes to emit",
	"aggregator",
	"prom_metrics_weight"
);

}

using namespace draiosproto;

namespace aggregator_limits_comparators
{
bool status_code_details_comparator(const draiosproto::status_code_details& lhs,
									const draiosproto::status_code_details& rhs)
{
	uint64_t lhs_value = lhs.aggr_ncalls().sum();
	uint64_t rhs_value = rhs.aggr_ncalls().sum();
	if (lhs_value != rhs_value)
	{   
		return lhs_value > rhs_value;
	}
	return rhs.status_code() > lhs.status_code();
}

bool status_code_details_reverse_comparator(const draiosproto::status_code_details& lhs,
											const draiosproto::status_code_details& rhs)
{
	return !status_code_details_comparator(lhs, rhs);
}

bool container_priority_comparator(const draiosproto::container& lhs,
								   const draiosproto::container& rhs)
{
	uint64_t lhs_value = lhs.container_reporting_group_id().size();
	uint64_t rhs_value = rhs.container_reporting_group_id().size();
	if (lhs_value != rhs_value)
	{
		return lhs_value > rhs_value;
	}
	return rhs.id() > lhs.id();
}

bool program_priority_comparator(const draiosproto::program& lhs,
								 const draiosproto::program& rhs)
{
	uint64_t lhs_value = lhs.program_reporting_group_id().size();
	uint64_t rhs_value = rhs.program_reporting_group_id().size();
	if (lhs_value != rhs_value)
	{
		return lhs_value > rhs_value;
	}

	// since we overwrite the pids during aggregation, there is always guaranteed
	// to be at least one
	return rhs.pids()[0] > lhs.pids()[0];
}

template <typename message>
void file_stat_limiter(message& output,
					   uint32_t limit,
					   std::function<google::protobuf::RepeatedPtrField<draiosproto::file_stat>*(message&)> field_extractor)
{
	auto tiebreaker_extractor = [](const file_stat& a)->const std::string&{return a.name();};
	multi_compare_limiter<message, file_stat>(
		output,
		limit,
		field_extractor,
		{
			message_comparator<file_stat>(
				[](const file_stat& a)->uint64_t{return  a.aggr_time_ns().sum();},
				tiebreaker_extractor),
			message_comparator<file_stat>(
				[](const file_stat& a)->uint64_t{return  a.aggr_open_count().sum();},
				tiebreaker_extractor),
			message_comparator<file_stat>(
				[](const file_stat& a)->uint64_t{return  a.aggr_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<file_stat>(
				[](const file_stat& a)->uint64_t{return  a.aggr_errors().sum();},
				tiebreaker_extractor)
		}
	);
}

template <typename message>
void app_metric_limiter(message& output, uint32_t limit)
{
	multi_compare_limiter<message, app_metric>(
		output,
		limit,
		[](message& a)->google::protobuf::RepeatedPtrField<app_metric>*{return a.mutable_metrics();},
		{
			message_comparator<app_metric>(
				[](const app_metric& a)->uint64_t{return a.aggr_value_double().sum();},
				[](const app_metric& a)->const std::string&{return a.name();}
			)
		}
	);
}

} // aggregator_limits_comparators

// using using to make the code more readable. All the lambdas are ridiculous with fully
// specified types. And lambda auto type inference is not to be trusted, as it is often
// wrong.
using namespace aggregator_limits_comparators;
using namespace google::protobuf;

void statsd_info_message_aggregator::limit_statsd_metrics(statsd_info& output,
														  uint32_t limit)
{
	auto tiebreaker_extractor = [](const statsd_metric& a)->const std::string&{return a.name();};
	multi_compare_limiter<statsd_info, statsd_metric>(
		output,
		limit,
		[](statsd_info& a)->RepeatedPtrField<statsd_metric>*{return a.mutable_statsd_metrics();},
		{
			message_comparator<statsd_metric>(
				[](const statsd_metric& a)->uint64_t{
					return  a.has_aggr_sum() ? a.aggr_sum().sum() : a.aggr_value().sum();
				},
				tiebreaker_extractor
			)
		}
	);
}

void container_message_aggregator::limit_top_devices(container& output, uint32_t limit)
{
	file_stat_limiter<container>(output,
								 limit,
								 [](container& a)->RepeatedPtrField<file_stat>*{return a.mutable_top_devices();});
}

void metrics_message_aggregator::limit_top_devices(metrics& output, uint32_t limit)
{
	file_stat_limiter<metrics>(output,
							   limit,
							   [](metrics& a)->RepeatedPtrField<file_stat>*{return a.mutable_top_devices();});
}

void process_message_aggregator::limit_top_devices(process& output, uint32_t limit)
{
	file_stat_limiter<process>(output,
							   limit,
							   [](process& a)->RepeatedPtrField<file_stat>*{return a.mutable_top_devices();});
}

void process_message_aggregator::limit_top_files(process& output, uint32_t limit)
{
	file_stat_limiter<process>(output,
							   limit,
							   [](process& a)->RepeatedPtrField<file_stat>*{return a.mutable_top_files();});
}

void metrics_message_aggregator::limit_top_files(metrics& output, uint32_t limit)
{
	file_stat_limiter<metrics>(output,
							   limit,
							   [](metrics& a)->RepeatedPtrField<file_stat>*{return a.mutable_top_files();});
}

void container_message_aggregator::limit_top_files(container& output, uint32_t limit)
{
	file_stat_limiter<container>(output,
								 limit,
								 [](container& a)->RepeatedPtrField<file_stat>*{return a.mutable_top_files();});
}

void sql_info_message_aggregator::limit_client_queries(sql_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const sql_entry_details& a)->const std::string&{return a.name();};
	multi_compare_limiter<sql_info, sql_entry_details>(
		output,
		limit,
		[](sql_info& a)->RepeatedPtrField<sql_entry_details>*{return a.mutable_client_queries();},
		{
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void sql_info_message_aggregator::limit_client_tables(sql_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const sql_entry_details& a)->const std::string&{return a.name();};
	multi_compare_limiter<sql_info, sql_entry_details>(
		output,
		limit,
		[](sql_info& a)->RepeatedPtrField<sql_entry_details>*{return a.mutable_client_tables();},
		{
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void sql_info_message_aggregator::limit_server_tables(sql_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const sql_entry_details& a)->const std::string&{return a.name();};
	multi_compare_limiter<sql_info, sql_entry_details>(
		output,
		limit,
		[](sql_info& a)->RepeatedPtrField<sql_entry_details>*{return a.mutable_server_tables();},
		{
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void sql_info_message_aggregator::limit_server_queries(sql_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const sql_entry_details& a)->const std::string&{return a.name();};
	multi_compare_limiter<sql_info, sql_entry_details>(
		output,
		limit,
		[](sql_info& a)->RepeatedPtrField<sql_entry_details>*{return a.mutable_server_queries();},
		{
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<sql_entry_details>(
				[](const sql_entry_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void sql_info_message_aggregator::limit_server_query_types(sql_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const sql_query_type_details& a)->const std::string&{return sql_statement_type_Name(a.type());};
	multi_compare_limiter<sql_info, sql_query_type_details>(
		output,
		limit,
		[](sql_info& a)->RepeatedPtrField<sql_query_type_details>*{return a.mutable_server_query_types();},
		{
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void sql_info_message_aggregator::limit_client_query_types(sql_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const sql_query_type_details& a)->const std::string&{return sql_statement_type_Name(a.type());};
	multi_compare_limiter<sql_info, sql_query_type_details>(
		output,
		limit,
		[](sql_info& a)->RepeatedPtrField<sql_query_type_details>*{return a.mutable_client_query_types();},
		{
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<sql_query_type_details>(
				[](const sql_query_type_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void mongodb_info_message_aggregator::limit_client_ops(mongodb_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const mongodb_op_type_details& a)->const std::string&{return mongodb_op_type_Name(a.op());};
	multi_compare_limiter<mongodb_info, mongodb_op_type_details>(
		output,
		limit,
		[](mongodb_info& a)->RepeatedPtrField<mongodb_op_type_details>*{return a.mutable_client_ops();},
		{
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void mongodb_info_message_aggregator::limit_servers_ops(mongodb_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const mongodb_op_type_details& a)->const std::string&{return mongodb_op_type_Name(a.op());};
	multi_compare_limiter<mongodb_info, mongodb_op_type_details>(
		output,
		limit,
		[](mongodb_info& a)->RepeatedPtrField<mongodb_op_type_details>*{return a.mutable_servers_ops();},
		{
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_op_type_details>(
				[](const mongodb_op_type_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void mongodb_info_message_aggregator::limit_client_collections(mongodb_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const mongodb_collection_details& a)->const std::string&{return a.name();};
	multi_compare_limiter<mongodb_info, mongodb_collection_details>(
		output,
		limit,
		[](mongodb_info& a)->RepeatedPtrField<mongodb_collection_details>*{return a.mutable_client_collections();},
		{
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void mongodb_info_message_aggregator::limit_server_collections(mongodb_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const mongodb_collection_details& a)->const std::string&{return a.name();};
	multi_compare_limiter<mongodb_info, mongodb_collection_details>(
		output,
		limit,
		[](mongodb_info& a)->RepeatedPtrField<mongodb_collection_details>*{return a.mutable_server_collections();},
		{
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<mongodb_collection_details>(
				[](const mongodb_collection_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}
void http_info_message_aggregator::limit_client_urls(http_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const url_details& a)->const std::string&{return a.url();};
	multi_compare_limiter<http_info, url_details>(
		output,
		limit,
		[](http_info& a)->RepeatedPtrField<url_details>*{return a.mutable_client_urls();},
		{
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

void http_info_message_aggregator::limit_server_urls(http_info& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const url_details& a)->const std::string&{return a.url();};
	multi_compare_limiter<http_info, url_details>(
		output,
		limit,
		[](http_info& a)->RepeatedPtrField<url_details>*{return a.mutable_server_urls();},
		{
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{return  a.counters().aggr_time_tot().sum();},
				tiebreaker_extractor),
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{return  a.counters().aggr_time_max().sum();},
				tiebreaker_extractor),
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{return  a.counters().aggr_ncalls().sum();},
				tiebreaker_extractor),
			message_comparator<url_details>(
				[](const url_details& a)->uint64_t{
					return  a.counters().aggr_bytes_in().sum() +
					        a.counters().aggr_bytes_out().sum();
				},
				tiebreaker_extractor)
		}
	);
}

// for some unknown reason, we return the bottom 5 status codes in terms of n-calls
void http_info_message_aggregator::limit_client_status_codes(http_info& output, uint32_t limit)
{
	uint32_t top_limit = 5 * limit / 6;
	uint32_t bottom_limit = limit - top_limit;

	std::partial_sort(output.mutable_client_status_codes()->begin(),
					  output.mutable_client_status_codes()->begin() + top_limit,
					  output.mutable_client_status_codes()->end(),
					  status_code_details_comparator);
	std::partial_sort(output.mutable_client_status_codes()->begin() + top_limit,
					  output.mutable_client_status_codes()->begin() + top_limit + bottom_limit,
					  output.mutable_client_status_codes()->end(),
					  status_code_details_reverse_comparator);

	output.mutable_client_status_codes()->DeleteSubrange(limit, output.mutable_client_status_codes()->size() - limit);
}

void http_info_message_aggregator::limit_server_status_codes(http_info& output, uint32_t limit)
{
	uint32_t top_limit = 5 * limit / 6;
	uint32_t bottom_limit = limit - top_limit;

	std::partial_sort(output.mutable_server_status_codes()->begin(),
					  output.mutable_server_status_codes()->begin() + top_limit,
					  output.mutable_server_status_codes()->end(),
					  status_code_details_comparator);
	std::partial_sort(output.mutable_server_status_codes()->begin() + top_limit,
					  output.mutable_server_status_codes()->begin() + top_limit + bottom_limit,
					  output.mutable_server_status_codes()->end(),
					  status_code_details_reverse_comparator);

	output.mutable_server_status_codes()->DeleteSubrange(limit, output.mutable_server_status_codes()->size() - limit);
}

void container_message_aggregator::limit_mounts(container& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const mounted_fs& a)->const std::string&{return a.mount_dir();};
	multi_compare_limiter<container, mounted_fs>(
		output,
		limit,
		[](container& a)->RepeatedPtrField<mounted_fs>*{return a.mutable_mounts();},
		{
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_size_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_available_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_used_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_total_inodes().sum();},
				tiebreaker_extractor)
		}
	);
}

void metrics_message_aggregator::limit_mounts(metrics& output, uint32_t limit)
{	
	auto tiebreaker_extractor = [](const mounted_fs& a)->const std::string&{return a.mount_dir();};
	multi_compare_limiter<metrics, mounted_fs>(
		output,
		limit,
		[](metrics& a)->RepeatedPtrField<mounted_fs>*{return a.mutable_mounts();},
		{
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_size_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_available_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_used_bytes().sum();},
				tiebreaker_extractor),
			message_comparator<mounted_fs>(
				[](const mounted_fs& a)->uint64_t{return  a.aggr_total_inodes().sum();},
				tiebreaker_extractor)
		}
	);
}

void container_message_aggregator::limit_network_by_serverports(container& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const network_by_port& a)->uint32_t{return a.port();};
	multi_compare_limiter<container, network_by_port, uint32_t>(
		output,
		limit,
		[](container& a)->RepeatedPtrField<network_by_port>*{return a.mutable_network_by_serverports();},
		{
			message_comparator<network_by_port, uint32_t>(
				[](const network_by_port& a)->uint64_t{
					uint64_t result = 0;
					if (a.counters().has_client())
					{
						result += a.counters().client().aggr_bytes_in().sum();
						result += a.counters().client().aggr_bytes_out().sum();
					}
					if (a.counters().has_server())
					{
						result += a.counters().server().aggr_bytes_in().sum();
						result += a.counters().server().aggr_bytes_out().sum();
					}
					return  result;
				},
				tiebreaker_extractor
			)
		}
	);
}

void host_message_aggregator::limit_network_by_serverports(host& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const network_by_port& a)->uint32_t{return a.port();};
	multi_compare_limiter<host, network_by_port, uint32_t>(
		output,
		limit,
		[](host& a)->RepeatedPtrField<network_by_port>*{return a.mutable_network_by_serverports();},
		{
			message_comparator<network_by_port, uint32_t>(
				[](const network_by_port& a)->uint64_t{
					uint64_t result = a.counters().has_client() ? 
						a.counters().client().aggr_bytes_in().sum() + 
						a.counters().client().aggr_bytes_out().sum() : 0;
					result += a.counters().has_server() ? 
						a.counters().server().aggr_bytes_in().sum() + 
						a.counters().server().aggr_bytes_out().sum() : 0;
					return  result;
				},
				tiebreaker_extractor
			)
		}
	);
}

void app_info_message_aggregator::limit_metrics(app_info& output, uint32_t limit)
{
	app_metric_limiter<app_info>(output, limit);
}

void prometheus_info_message_aggregator::limit_metrics(prometheus_info& output, uint32_t limit)
{
	app_metric_limiter<prometheus_info>(output, limit);
}

void metrics_message_aggregator::limit_events(metrics& output, uint32_t limit)
{
	multi_compare_limiter<metrics, agent_event>(
		output,
		limit,
		[](metrics& a)->RepeatedPtrField<agent_event>*{return a.mutable_events();},
		{
			message_comparator<agent_event>(
				[](const agent_event& a)->uint64_t{return UINT64_MAX - a.timestamp_sec();},
				[](const agent_event& a)->const std::string&{return a.title();}
			)
		}
	);
}

void metrics_message_aggregator::limit_ipv4_incomplete_connections_v2(metrics& output,
																	  uint32_t limit)
{
	auto tiebreaker_extractor = [](const ipv4_incomplete_connection& a)->uint64_t{
		return (uint64_t)a.tuple().sip() + a.tuple().sport() + a.tuple().dip() + a.tuple().dport();
	};

	multi_compare_limiter<metrics, ipv4_incomplete_connection, uint64_t>(
		output,
		limit,
		[](metrics& a)->RepeatedPtrField<ipv4_incomplete_connection>*{return a.mutable_ipv4_incomplete_connections_v2();},
		{
			message_comparator<ipv4_incomplete_connection, uint64_t>(
				[](const ipv4_incomplete_connection& a)->uint64_t{
					uint64_t result = a.counters().has_client() ? 
						a.counters().client().aggr_bytes_in().sum() + 
						a.counters().client().aggr_bytes_out().sum() : 0;
					result += a.counters().has_server() ? 
						a.counters().server().aggr_bytes_in().sum() + 
						a.counters().server().aggr_bytes_out().sum() : 0;
					return  result;
				},
				tiebreaker_extractor
			),
			message_comparator<ipv4_incomplete_connection, uint64_t>(
				[](const ipv4_incomplete_connection& a)->uint64_t{
					return (a.has_counters() && a.counters().has_transaction_counters()) ?
						a.counters().transaction_counters().aggr_count_in().sum() +
						a.counters().transaction_counters().aggr_count_out().sum() : 0;
				},
				tiebreaker_extractor
			),
			message_comparator<ipv4_incomplete_connection, uint64_t>(
				[](const ipv4_incomplete_connection& a)->uint64_t{
					uint64_t result =  (a.has_counters() && a.counters().has_min_transaction_counters()) ?
						a.counters().min_transaction_counters().aggr_count_in().sum() +
						a.counters().min_transaction_counters().aggr_count_out().sum() : UINT64_MAX;
					return UINT64_MAX - result;
				},
				tiebreaker_extractor
			),
			message_comparator<ipv4_incomplete_connection, uint64_t>(
				[](const ipv4_incomplete_connection& a)->uint64_t{
					return (a.has_counters() && a.counters().has_max_transaction_counters()) ?
						a.counters().max_transaction_counters().aggr_count_in().sum() +
						a.counters().max_transaction_counters().aggr_count_out().sum() : 0;
				},
				tiebreaker_extractor
			),

		}
	);
}

void metrics_message_aggregator::limit_ipv4_connections(metrics& output, uint32_t limit)
{
	auto tiebreaker_extractor = [](const ipv4_connection& a)->uint64_t{
		return (uint64_t)a.tuple().sip() + a.tuple().sport() + a.tuple().dip() + a.tuple().dport();
	};

	multi_compare_limiter<metrics, ipv4_connection, uint64_t>(
		output,
		limit,
		[](metrics& a)->RepeatedPtrField<ipv4_connection>*{return a.mutable_ipv4_connections();},
		{
			message_comparator<ipv4_connection, uint64_t>(
				[](const ipv4_connection& a)->uint64_t{
					uint64_t result = a.counters().has_client() ? 
						a.counters().client().aggr_bytes_in().sum() + 
						a.counters().client().aggr_bytes_out().sum() : 0;
					result += a.counters().has_server() ? 
						a.counters().server().aggr_bytes_in().sum() + 
						a.counters().server().aggr_bytes_out().sum() : 0;
					return  result;
				},
				tiebreaker_extractor
			),
			message_comparator<ipv4_connection, uint64_t>(
				[](const ipv4_connection& a)->uint64_t{
					return (a.has_counters() && a.counters().has_transaction_counters()) ?
						a.counters().transaction_counters().aggr_count_in().sum() +
						a.counters().transaction_counters().aggr_count_out().sum() : 0;
				},
				tiebreaker_extractor
			),
			message_comparator<ipv4_connection, uint64_t>(
				[](const ipv4_connection& a)->uint64_t{
					uint64_t result =  (a.has_counters() && a.counters().has_min_transaction_counters()) ?
						a.counters().min_transaction_counters().aggr_count_in().sum() +
						a.counters().min_transaction_counters().aggr_count_out().sum() : UINT64_MAX;
					return UINT64_MAX - result;
				},
				tiebreaker_extractor
			),
			message_comparator<ipv4_connection, uint64_t>(
				[](const ipv4_connection& a)->uint64_t{
					return (a.has_counters() && a.counters().has_max_transaction_counters()) ?
						a.counters().max_transaction_counters().aggr_count_in().sum() +
						a.counters().max_transaction_counters().aggr_count_out().sum() : 0;
				},
				tiebreaker_extractor
			),

		}
	);
}

void k8s_state_message_aggregator::limit_pods(draiosproto::k8s_state& output,
											  uint32_t limit)
{
	auto tiebreaker_extractor = [](const k8s_pod& a)->const std::string&{return a.common().name();};

	multi_compare_limiter<k8s_state, k8s_pod>(
		output,
		limit,
		[](k8s_state& a)->RepeatedPtrField<k8s_pod>*{return a.mutable_pods();},
		{
			message_comparator<k8s_pod>(
				[](const k8s_pod& a)->uint64_t{return a.aggr_requests_cpu_cores().sum();},
				tiebreaker_extractor
			),
			message_comparator<k8s_pod>(
				[](const k8s_pod& a)->uint64_t{return a.aggr_limits_cpu_cores().sum();},
				tiebreaker_extractor
			)
		}
	);
}

void k8s_state_message_aggregator::limit_jobs(draiosproto::k8s_state& output,
											  uint32_t limit)
{
	auto tiebreaker_extractor = [](const k8s_job& a)->const std::string&{return a.common().name();};

	multi_compare_limiter<k8s_state, k8s_job>(
		output,
		limit,
		[](k8s_state& a)->RepeatedPtrField<k8s_job>*{return a.mutable_jobs();},
		{
			message_comparator<k8s_job>(
				[](const k8s_job& a)->uint64_t{return a.aggr_completions().sum();},
				tiebreaker_extractor
			)
		}
	);
}

void metrics_message_aggregator::limit_containers(metrics& output, uint32_t limit)
{	
	// 2 step process. First grab all priority containers that fit,
	// then divvy up the rest of the space by stats
	std::sort(output.mutable_containers()->begin(),
			  output.mutable_containers()->end(),
			  container_priority_comparator);

	uint32_t priority_container_count = 0;
	for (auto i : output.containers())
	{
		if (i.container_reporting_group_id().size() > 0)
		{
			priority_container_count++;
		}
	}

	if (priority_container_count >= limit)
	{
		output.mutable_containers()->DeleteSubrange(limit, output.mutable_containers()->size() - limit);
	} else {
		limit -= priority_container_count;

		auto tiebreaker_extractor = [](const container& a)->const std::string&{return a.id();};
		multi_compare_limiter<metrics, container>(
			output,
			limit,
			[](metrics& a)->RepeatedPtrField<container>*{return a.mutable_containers();},
			{
				message_comparator<container>(
					[](const container& a)->uint64_t{return a.resource_counters().aggr_cpu_pct().sum();},
					tiebreaker_extractor
				),
				message_comparator<container>(
					[](const container& a)->uint64_t{return a.resource_counters().aggr_resident_memory_usage_kb().sum();},
					tiebreaker_extractor
				),
				message_comparator<container>(
					[](const container& a)->uint64_t{
						return a.tcounters().io_file().aggr_bytes_in().sum() +
						       a.tcounters().io_file().aggr_bytes_out().sum() +
							   a.tcounters().io_file().aggr_bytes_other().sum();
					},
					tiebreaker_extractor
				),
				message_comparator<container>(
					[](const container& a)->uint64_t{
						return a.tcounters().io_net().aggr_bytes_in().sum() +
						       a.tcounters().io_net().aggr_bytes_out().sum() +
							   a.tcounters().io_net().aggr_bytes_other().sum();
					},
					tiebreaker_extractor
				),
			},
			priority_container_count // need to bypass ones we already committed to send
		);
	}
}

void metrics_message_aggregator::limit_programs(metrics& output, uint32_t limit)
{	
	// 2 step process. First grab all priority programs that fit,
	// then divvy up the rest of the space by stats
	std::sort(output.mutable_programs()->begin(),
			  output.mutable_programs()->end(),
			  program_priority_comparator);

	uint32_t priority_program_count = 0;
	for (auto i : output.programs())
	{
		if (i.program_reporting_group_id().size() > 0)
		{
			priority_program_count++;
		}
	}

	if (priority_program_count >= limit)
	{
		output.mutable_programs()->DeleteSubrange(limit, output.mutable_programs()->size() - limit);
	} else {
		limit -= priority_program_count;

		// we make the pid field unique
		auto tiebreaker_extractor = [](const program& a)->uint64_t{return a.pids()[0];};
		multi_compare_limiter<metrics, program, uint64_t>(
			output,
			limit,
			[](metrics& a)->RepeatedPtrField<program>*{return a.mutable_programs();},
			{
				message_comparator<program, uint64_t>(
					[](const program& a)->uint64_t{return a.procinfo().resource_counters().aggr_cpu_pct().sum();},
					tiebreaker_extractor
				),
				message_comparator<program, uint64_t>(
					[](const program& a)->uint64_t{return a.procinfo().resource_counters().aggr_resident_memory_usage_kb().sum();},
					tiebreaker_extractor
				),
				message_comparator<program, uint64_t>(
					[](const program& a)->uint64_t{
						return a.procinfo().tcounters().io_file().aggr_bytes_in().sum() +
						       a.procinfo().tcounters().io_file().aggr_bytes_out().sum() +
							   a.procinfo().tcounters().io_file().aggr_bytes_other().sum();
					},
					tiebreaker_extractor
				),
				message_comparator<program, uint64_t>(
					[](const program& a)->uint64_t{
						return a.procinfo().tcounters().io_net().aggr_bytes_in().sum() +
						       a.procinfo().tcounters().io_net().aggr_bytes_out().sum() +
							   a.procinfo().tcounters().io_net().aggr_bytes_other().sum();
					},
					tiebreaker_extractor
				),
				message_comparator<program, uint64_t>(
					[](const program& a)->uint64_t{
						if (!a.procinfo().has_protos())
						{
							return 0;
						}
						double value = 0;
						if (a.procinfo().protos().has_app())
						{
							value += a.procinfo().protos().app().metrics().size();
						}
						if (a.procinfo().protos().has_prometheus()) // SMAGENT-1949 correct prom limiter
						{
							value += c_prom_metrics_weight.get_value() * a.procinfo().protos().prometheus().metrics().size();
						}
						return (uint64_t)value;
					},
					tiebreaker_extractor
				),
			},
			priority_program_count // need to bypass ones we already committed to send
		);
	}
}
