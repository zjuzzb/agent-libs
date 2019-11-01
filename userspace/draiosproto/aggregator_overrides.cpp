#include "aggregator_overrides.h"
#include <sstream>

// unlike almost every other repeated non-message field, this is a list, not
// a set. It is also a primary key. So in this case, the first time we call
// into it, copy the list. Then don't do anything further times, as the lists
// would have to be equal anyway (because it's a primary key)
void process_details_message_aggregator_impl::aggregate_args(const draiosproto::process_details& input,
							     draiosproto::process_details& output)
{
	if (output.args().size() == 0)
	{
		for (auto i : input.args())
		{
			output.add_args(i);
		}
	}
}

void process_details_message_aggregator_impl::aggregate_container_id(const draiosproto::process_details& input,
								     draiosproto::process_details& output)
{
	if (!output.has_container_id())
	{
		output.set_container_id("");

	}
	process_details_message_aggregator::aggregate_container_id(input, output);
}

void process_message_aggregator_impl::aggregate_netrole(const draiosproto::process& input,
														draiosproto::process& output)
{
	m_netrole |= input.netrole();
	output.set_netrole(m_netrole);
	output.set_is_ipv4_transaction_client((m_netrole & draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT) != 0);
	output.set_is_ipv4_transaction_server((m_netrole & draiosproto::networkrole::IS_REMOTE_IPV4_SERVER) != 0);
}

void process_message_aggregator_impl::aggregate_is_ipv4_transaction_client(const draiosproto::process& input,
																		   draiosproto::process& output)
{
	if (input.is_ipv4_transaction_client())
	{
		m_netrole |= draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT;
		aggregate_netrole(input, output);
	}
}

void process_message_aggregator_impl::aggregate_is_ipv4_transaction_server(const draiosproto::process& input,
																		   draiosproto::process& output)
{
	if (input.is_ipv4_transaction_server())
	{
		m_netrole |= draiosproto::networkrole::IS_REMOTE_IPV4_SERVER;
		aggregate_netrole(input, output);
	}
}

void metrics_message_aggregator_impl::override_primary_keys(draiosproto::metrics& output)
{
	// java names
	for (uint32_t i = 0; i < output.programs().size(); i++)
	{
		auto proc = (*output.mutable_programs())[i].mutable_procinfo();
		if (proc->has_protos() &&
			proc->protos().has_java() &&
			proc->protos().java().has_process_name() &&
			!proc->protos().java().process_name().empty())
		{
			proc->mutable_details()->set_comm(proc->protos().java().process_name());
		}
	}

	// ipv4_connection pids
	for (uint32_t i = 0; i < output.ipv4_connections().size(); i++)
	{
		auto& connection = (*output.mutable_ipv4_connections())[i];

		// substitute pids
		auto hash = pid_map.find(connection.spid());
		if (hash != pid_map.end())
		{
			connection.set_spid(hash->second);
		}
		hash = pid_map.find(connection.dpid());
		if (hash != pid_map.end())
		{
			connection.set_dpid(hash->second);
		}
	}

	// ipv4_incomplete_connection_v2 pids
	for (uint32_t i = 0; i < output.ipv4_incomplete_connections_v2().size(); i++)
	{
		auto& connection = (*output.mutable_ipv4_incomplete_connections_v2())[i];

		// substitute pids
		auto hash = pid_map.find(connection.spid());
		if (hash != pid_map.end())
		{
			connection.set_spid(hash->second);
		}
		hash = pid_map.find(connection.dpid());
		if (hash != pid_map.end())
		{
			connection.set_dpid(hash->second);
		}
	}
}

void metrics_message_aggregator_impl::aggregate_sampling_ratio(const draiosproto::metrics& input,
														 draiosproto::metrics& output)
{
	if (output.sampling_ratio() == 0)
	{
		output.set_sampling_ratio(input.sampling_ratio());
	}
	metrics_message_aggregator::aggregate_sampling_ratio(input, output);
}

void metrics_message_aggregator_impl::aggregate_programs(const draiosproto::metrics& input,
														 draiosproto::metrics& output)
{
	// don't run a second time, if we've already run.
	if (aggregated_programs)
	{
		return;
	}
	aggregated_programs = true;

	for (auto i : input.programs())
	{
		uint64_t be_hash = 0;
		for (auto j : i.pids())
		{
			if (pid_map.find(j) != pid_map.end())
			{
				be_hash = pid_map[j];
			}
		}

		if (be_hash == 0)
		{
			be_hash = program_java_hasher(i);
		}

		// regardless of whether we had previously calculated the hash,
		// we have to add everything to the pid map, since there might
		// be new pids
		for (auto j : i.pids())
		{
			pid_map[j] = be_hash;
		}

		if (programs_map.find(&i) == programs_map.end())
		{
			auto new_entry = output.add_programs();
			agent_message_aggregator<draiosproto::program>* new_aggregator = &m_builder.build_program();
			new_aggregator->aggregate(i, *new_entry);

			// put the pids in
			new_entry->add_pids(be_hash);

			programs_map.insert(
				std::make_pair<draiosproto::program*, std::pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::program>>>>(
					std::move(new_entry),
					std::make_pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::program>>>(
						output.programs().size() - 1,
						std::unique_ptr<agent_message_aggregator<draiosproto::program>>(new_aggregator)
		    		)
				)
			);
		}
		else
		{
			programs_map[&i].second->aggregate(i,
											   (*output.mutable_programs())[programs_map[&i].first]);
		}
    }
}

void metrics_message_aggregator_impl::aggregate_config_percentiles(const draiosproto::metrics& input,
								   draiosproto::metrics& output)
{
	output.clear_config_percentiles();
	for (auto i : input.config_percentiles())
	{
		output.add_config_percentiles(i);
	}
}

void metrics_message_aggregator_impl::aggregate_falcobl(const draiosproto::metrics& input,
							draiosproto::metrics& output)
{
    if (input.has_falcobl())
    {
	*output.mutable_falcobl() = input.falcobl();
    }
}

void metrics_message_aggregator_impl::aggregate_commands(const draiosproto::metrics& input,
							draiosproto::metrics& output)
{
    for (auto i : input.commands())
    {
	auto command = output.add_commands();
	*command = i;
    }
}

void metrics_message_aggregator_impl::aggregate_swarm(const draiosproto::metrics& input,
													  draiosproto::metrics& output)
{
	if (input.has_swarm() && input.swarm().nodes().size() > 0)
	{
		metrics_message_aggregator::aggregate_swarm(input, output);
	}
}

void metrics_message_aggregator_impl::aggregate_ipv4_connections(const draiosproto::metrics& input,
																 draiosproto::metrics& output)
{
	for (auto i : input.ipv4_connections())
	{
		if (ipv4_connections_map.find(&i) == ipv4_connections_map.end())
		{
			auto new_entry = output.add_ipv4_connections();
			agent_message_aggregator<draiosproto::ipv4_connection>* new_aggregator = &m_builder.build_ipv4_connection();
			new_aggregator->aggregate(i, *new_entry);
			if (i.has_state() && i.state() != draiosproto::connection_state::CONN_SUCCESS)
			{
				new_entry->clear_counters();
				new_entry->clear_state();
			}
			ipv4_connections_map.insert(
				std::make_pair<draiosproto::ipv4_connection*,
							   std::pair<uint32_t,
										 std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>>>(
					std::move(new_entry),
					std::make_pair<uint32_t,
								   std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>>(
						output.ipv4_connections().size() - 1,
						std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>(new_aggregator)
					)
				)
			);
		}
		else
		{
			if (!i.has_state() || i.state() == draiosproto::connection_state::CONN_SUCCESS)
			{
				ipv4_connections_map[&i].second->aggregate(i, (*output.mutable_ipv4_connections())[ipv4_connections_map[&i].first]);
			}
		}
	}
}

void metrics_message_aggregator_impl::aggregate_ipv4_incomplete_connections_v2(const draiosproto::metrics& input,
																			   draiosproto::metrics& output)
{
	for (auto i : input.ipv4_incomplete_connections_v2())
	{
		if (ipv4_incomplete_connections_v2_map.find(&i) == ipv4_incomplete_connections_v2_map.end())
		{
			auto new_entry = output.add_ipv4_incomplete_connections_v2();
			agent_message_aggregator<draiosproto::ipv4_incomplete_connection>* new_aggregator = &m_builder.build_ipv4_incomplete_connection();
			new_aggregator->aggregate(i, *new_entry);
			if (!i.has_state() || i.state() == draiosproto::connection_state::CONN_SUCCESS)
			{
				new_entry->clear_counters();
				new_entry->clear_state();
			}
			ipv4_incomplete_connections_v2_map.insert(
				std::make_pair<draiosproto::ipv4_incomplete_connection*,
							   std::pair<uint32_t,
										 std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>>>(
					std::move(new_entry),
					std::make_pair<uint32_t,
								   std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>>(
						output.ipv4_incomplete_connections_v2().size() - 1,
						std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>(new_aggregator)
					)
				)
			);
		}
		else
		{
			if (i.has_state() && i.state() != draiosproto::connection_state::CONN_SUCCESS)
			{
				ipv4_incomplete_connections_v2_map[&i].second->aggregate(i, (*output.mutable_ipv4_incomplete_connections_v2())[ipv4_incomplete_connections_v2_map[&i].first]);
			}
		}
	}
}

void metrics_message_aggregator_impl::aggregate(const draiosproto::metrics& input,
						draiosproto::metrics& output)
{
	aggregated_programs = false;
	metrics_message_aggregator::aggregate(input, output);
}

void counter_percentile_data_message_aggregator_impl::aggregate(const draiosproto::counter_percentile_data& input,
								draiosproto::counter_percentile_data& output)
{
	// add the input data to the digest
	uint32_t len = input.num_samples();
	uint32_t scale = input.scale();
	if (len > 0)
	{
		double previous_value = input.means()[0];
		double first_value = previous_value / scale;
		m_digest->add(first_value, input.weights()[0]);
		for (uint32_t i = 1; i < len; ++i)
		{
			previous_value = previous_value + input.means()[i];
			double i_value = previous_value / scale;
			m_digest->add(i_value, input.weights()[i]);
		}
	}

	m_digest->compress();

	// dump the data from the digest to the output
	output.Clear();
	const uint32_t digest_scale = 1000; // must match what happens in BE and elsewhere in the kernel
	output.set_scale(digest_scale);
	auto& centroids = m_digest->processed();
	output.set_num_samples(centroids.size());
	int64_t previous_mean = 0;
	for (auto& centroid : centroids)
	{
		double mean = centroid.mean();
		int64_t scaled_mean = ((int64_t)mean) * digest_scale;
		if (output.means().size() == 0)
		{
			output.add_means(scaled_mean);
		} else {
			output.add_means(scaled_mean - previous_mean);
		}
		output.add_weights(centroid.weight());

		previous_mean = scaled_mean;
	}

	output.set_min((int64_t) (m_digest->min() * digest_scale));
	output.set_max((int64_t) (m_digest->max() * digest_scale));
}

void counter_percentile_data_message_aggregator_impl::reset()
{
    m_digest = std::unique_ptr<tdigest::TDigest>(new tdigest::TDigest(200, // compression
								      400, // buffer size
								      5 * 400)); // seems to be what the java impl does
}

void prometheus_info_message_aggregator_impl::aggregate_metrics(const draiosproto::prometheus_info& input,
								draiosproto::prometheus_info& output)
{
    for (auto i : input.metrics())
    {
	// first generate canonical name
	std::string name = i.name();
	for (auto kv : i.tags())
	{
	    name += kv.key();
	    name += kv.value();
	}
	if (i.type() == draiosproto::app_metric_type::APP_METRIC_TYPE_PROMETHEUS_RAW)
	{
	    name = "raw:" + name;
	}

	if (prom_metrics_map.find(name) == prom_metrics_map.end())
	{
	    auto new_entry = output.add_metrics();
	    agent_message_aggregator<draiosproto::app_metric>* new_aggregator = &m_builder.build_app_metric();
	    new_aggregator->aggregate(i, *new_entry);
	    prom_metrics_map.insert(
		std::make_pair<std::string, std::pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::app_metric>>>>(
		    std::move(name),
		    std::make_pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::app_metric>>>(
			output.metrics().size() - 1,
			std::unique_ptr<agent_message_aggregator<draiosproto::app_metric>>(new_aggregator)
		    )
		)
	    );
	}
	else
	{
	    prom_metrics_map[name].second->aggregate(i, (*output.mutable_metrics())[prom_metrics_map[name].first]);
	}
	}
}

void container_message_aggregator_impl::aggregate_commands(const draiosproto::container& input,
							   draiosproto::container& output)
{
	for (auto i : input.commands())
	{
		auto command = output.add_commands();
		*command = i;
	}
}

void agent_event_message_aggregator_impl::aggregate_tags(const draiosproto::agent_event& input,
							 draiosproto::agent_event& output)
{
	// we don't expect to ever have multiple events which aggregate together, but in case
	// we do, just blow away the old tags and take the new ones
	output.clear_tags();
	for (auto i : input.tags())
	{
		output.add_tags()->CopyFrom(i);
	}
}

void resource_categories_message_aggregator_impl::aggregate_capacity_score(const draiosproto::resource_categories& input,
									   draiosproto::resource_categories& output)
{
	if (input.has_capacity_score() && input.capacity_score() != invalid_capacity)
	{
		default_aggregate_value<decltype(input.capacity_score()),
								decltype(*output.mutable_aggr_capacity_score())>(input.capacity_score(),
																				 *output.mutable_aggr_capacity_score());
	}
}

void resource_categories_message_aggregator_impl::aggregate_stolen_capacity_score(const draiosproto::resource_categories& input,
										  draiosproto::resource_categories& output)
{
	if (input.has_stolen_capacity_score() && input.stolen_capacity_score() != invalid_capacity)
	{
		default_aggregate_value<decltype(input.stolen_capacity_score()),
								decltype(*output.mutable_aggr_stolen_capacity_score())>(input.stolen_capacity_score(),
																						*output.mutable_aggr_stolen_capacity_score());
    }
}

void swarm_task_message_aggregator_impl::aggregate_state(const draiosproto::swarm_task& input,
														 draiosproto::swarm_task& output)
{
	if (m_states.find(input.state()) == m_states.end())
	{
		m_states.insert(input.state());
		std::ostringstream stream;
		std::copy(m_states.begin(), m_states.end(), std::ostream_iterator<std::string>(stream, ", "));
		std::string new_state = stream.str();
		output.set_state(new_state.substr(0, new_state.size() - 2));
	}
}

void swarm_node_message_aggregator_impl::aggregate_state(const draiosproto::swarm_node& input,
														 draiosproto::swarm_node& output)
{
	if (m_states.find(input.state()) == m_states.end())
	{
		m_states.insert(input.state());
		std::ostringstream stream;
		std::copy(m_states.begin(), m_states.end(), std::ostream_iterator<std::string>(stream, ", "));
		std::string new_state = stream.str();
		output.set_state(new_state.substr(0, new_state.size() - 2));
	}
}

void swarm_node_message_aggregator_impl::aggregate_availability(const draiosproto::swarm_node& input,
																draiosproto::swarm_node& output)
{
	if (m_availabilities.find(input.availability()) == m_availabilities.end())
	{
		m_availabilities.insert(input.availability());
		std::ostringstream stream;
		std::copy(m_availabilities.begin(), m_availabilities.end(), std::ostream_iterator<std::string>(stream, ", "));
		std::string new_availability = stream.str();
		output.set_availability(new_availability.substr(0, new_availability.size() - 2));
	}
}

void swarm_node_message_aggregator_impl::aggregate_version(const draiosproto::swarm_node& input,
														   draiosproto::swarm_node& output)
{
	if (m_versions.find(input.version()) == m_versions.end())
	{
		m_versions.insert(input.version());
		std::ostringstream stream;
		std::copy(m_versions.begin(), m_versions.end(), std::ostream_iterator<std::string>(stream, ", "));
		std::string new_version = stream.str();
		output.set_version(new_version.substr(0, new_version.size() - 2));
	}
}

void swarm_manager_message_aggregator_impl::aggregate_reachability(const draiosproto::swarm_manager& input,
																   draiosproto::swarm_manager& output)
{
	if (m_reachabilities.find(input.reachability()) == m_reachabilities.end())
	{
		m_reachabilities.insert(input.reachability());
		std::ostringstream stream;
		std::copy(m_reachabilities.begin(), m_reachabilities.end(), std::ostream_iterator<std::string>(stream, ", "));
		std::string new_reachability = stream.str();
		output.set_reachability(new_reachability.substr(0, new_reachability.size() - 2));
	}
}

void statsd_metric_message_aggregator_impl::aggregate_sum(const draiosproto::statsd_metric& input,
														  draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_sum(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_min(const draiosproto::statsd_metric& input,
														  draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_min(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_max(const draiosproto::statsd_metric& input,
														  draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_max(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_count(const draiosproto::statsd_metric& input,
															draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_count(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_median(const draiosproto::statsd_metric& input,
															 draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_median(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_percentile_95(const draiosproto::statsd_metric& input,
														  draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_percentile_95(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_percentile_99(const draiosproto::statsd_metric& input,
														  draiosproto::statsd_metric& output)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_percentile_99(input, output);
	}
}

void statsd_metric_message_aggregator_impl::aggregate_value(const draiosproto::statsd_metric& input,
														  draiosproto::statsd_metric& output)
{
	if (input.type() != draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_value(input, output);
	}
}

void environment_message_aggregator_impl::aggregate(const draiosproto::environment& input,
														  draiosproto::environment& output)
{
	output = input;
}

void jmx_attribute_message_aggregator_impl::aggregate_value(const draiosproto::jmx_attribute& input,
															draiosproto::jmx_attribute& output)
{
	if (output.subattributes().size() == 0)
	{
		jmx_attribute_message_aggregator::aggregate_value(input, output);
	}
}

void jmx_attribute_message_aggregator_impl::aggregate_subattributes(const draiosproto::jmx_attribute& input,
															draiosproto::jmx_attribute& output)
{
	if (input.subattributes().size() != 0)
	{
		output.clear_aggr_value_double();
	}
	jmx_attribute_message_aggregator::aggregate_subattributes(input, output);
}

agent_message_aggregator<draiosproto::process_details>&
message_aggregator_builder_impl::build_process_details() const
{
	return *(new process_details_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::process>&
message_aggregator_builder_impl::build_process() const
{
	return *(new process_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::metrics>&
message_aggregator_builder_impl::build_metrics() const
{
	return *(new metrics_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::counter_percentile_data>&
message_aggregator_builder_impl::build_counter_percentile_data() const
{
	return *(new counter_percentile_data_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::agent_event>&
message_aggregator_builder_impl::build_agent_event() const
{
	return *(new agent_event_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::resource_categories>&
message_aggregator_builder_impl::build_resource_categories() const
{
	return *(new resource_categories_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::container>&
message_aggregator_builder_impl::build_container() const
{
        return *(new container_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::prometheus_info>&
message_aggregator_builder_impl::build_prometheus_info() const
{
        return *(new prometheus_info_message_aggregator_impl(*this));
}
agent_message_aggregator<draiosproto::swarm_task>&
message_aggregator_builder_impl::build_swarm_task() const
{
        return *(new swarm_task_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::swarm_node>&
message_aggregator_builder_impl::build_swarm_node() const
{
        return *(new swarm_node_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::swarm_manager>&
message_aggregator_builder_impl::build_swarm_manager() const
{
        return *(new swarm_manager_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::statsd_metric>&
message_aggregator_builder_impl::build_statsd_metric() const
{
        return *(new statsd_metric_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::program>&
message_aggregator_builder_impl::build_program() const
{
        return *(new program_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::environment>&
message_aggregator_builder_impl::build_environment() const
{
        return *(new environment_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::jmx_attribute>&
message_aggregator_builder_impl::build_jmx_attribute() const
{
        return *(new jmx_attribute_message_aggregator_impl(*this));
}
