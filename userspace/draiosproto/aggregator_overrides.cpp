#include "aggregator_overrides.h"

#include <sstream>

// unlike almost every other repeated non-message field, this is a list, not
// a set. It is also a primary key. So in this case, the first time we call
// into it, copy the list. Then don't do anything further times, as the lists
// would have to be equal anyway (because it's a primary key)
void process_details_message_aggregator_impl::aggregate_args(draiosproto::process_details& input,
                                                             draiosproto::process_details& output,
                                                             bool in_place)
{
	if (!in_place && output.args().size() == 0)
	{
		output.mutable_args()->UnsafeArenaSwap(input.mutable_args());
	}
}

void process_details_message_aggregator_impl::aggregate_container_id(
    draiosproto::process_details& input,
    draiosproto::process_details& output,
    bool in_place)
{
	if ((!output.has_container_id() || output.container_id() == "") && input.has_container_id())
	{
		output.set_allocated_container_id(input.release_container_id());
	}
	if (!output.has_container_id())
	{
		output.set_container_id("");
	}
}

void process_message_aggregator_impl::aggregate_netrole(draiosproto::process& input,
                                                        draiosproto::process& output,
                                                        bool in_place)
{
	m_netrole |= input.netrole();
	if (input.is_ipv4_transaction_client())
	{
		m_netrole |= draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT;
	}
	if (input.is_ipv4_transaction_server())
	{
		m_netrole |= draiosproto::networkrole::IS_REMOTE_IPV4_SERVER;
	}
	output.set_netrole(m_netrole);
	output.set_is_ipv4_transaction_client(
	    (m_netrole & draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT) != 0);
	output.set_is_ipv4_transaction_server(
	    (m_netrole & draiosproto::networkrole::IS_REMOTE_IPV4_SERVER) != 0);
}

void process_message_aggregator_impl::aggregate_is_ipv4_transaction_client(
    draiosproto::process& input,
    draiosproto::process& output,
    bool in_place)
{
	aggregate_netrole(input, output, in_place);
}

void process_message_aggregator_impl::aggregate_is_ipv4_transaction_server(
    draiosproto::process& input,
    draiosproto::process& output,
    bool in_place)
{
	aggregate_netrole(input, output, in_place);
}

void metrics_message_aggregator_impl::override_primary_keys(draiosproto::metrics& output)
{
	// java names
	for (uint32_t i = 0; i < output.programs().size(); i++)
	{
		auto proc = (*output.mutable_programs())[i].mutable_procinfo();
		if (proc->has_protos() && proc->protos().has_java() &&
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

void metrics_message_aggregator_impl::aggregate_sampling_ratio(draiosproto::metrics& input,
                                                               draiosproto::metrics& output,
                                                               bool in_place)
{
	if (in_place)
	{
		default_aggregate_value<decltype(input.sampling_ratio()),
		                        decltype(*output.mutable_aggr_sampling_ratio())>(
		    input.sampling_ratio(),
		    *output.mutable_aggr_sampling_ratio());
	}
	else
	{
		if (output.sampling_ratio() == 0)
		{
			output.set_sampling_ratio(input.sampling_ratio());
		}
		metrics_message_aggregator::aggregate_sampling_ratio(input, output, false);
	}
}

size_t metrics_message_aggregator_impl::process_pids(const draiosproto::program& input)
{
	uint64_t be_hash = 0;
	for (auto j : input.pids())
	{
		if (pid_map.find(j) != pid_map.end())
		{
			be_hash = pid_map[j];
		}
	}

	if (be_hash == 0)
	{
		be_hash = program_java_hasher(input);
	}

	// regardless of whether we had previously calculated the hash,
	// we have to add everything to the pid map, since there might
	// be new pids
	for (auto j : input.pids())
	{
		pid_map[j] = be_hash;
	}

	return be_hash;
}

void metrics_message_aggregator_impl::aggregate_programs(draiosproto::metrics& input,
                                                         draiosproto::metrics& output,
                                                         bool in_place)
{
	// don't run a second time, if we've already run.
	if (aggregated_programs)
	{
		return;
	}
	aggregated_programs = true;

	if (in_place)
	{
		int32_t leader = 0;
		for (int32_t trailer = input.programs().size() - 1; leader <= trailer; leader++)
		{
			// thing is duplicate. swap it with trailer, which is guaranteed to not be
			auto entry = &(*input.mutable_programs())[leader];
			if (programs_map.find(entry) != programs_map.end())
			{
				// We could in theory perform the duplicate aggregation while doing this (or the
				// trailer decrement below)
				// but this code is difficult to reason about as is, so we'll just do them all
				// in one pass at the end
				input.mutable_programs()->SwapElements(leader, trailer);
				entry = &(*input.mutable_programs())[leader];
			}
			// now thing is guaranteed to not be in cache, so add it
			programs_vector.push_back(
			    std::unique_ptr<agent_message_aggregator<draiosproto::program>>(
			        &m_builder.build_program()));
			programs_vector[programs_vector.size() - 1]->aggregate(*entry, *entry, true);
			size_t be_hash = process_pids(*entry);
			// put the pids in
			entry->clear_pids();
			entry->add_pids(be_hash);
			programs_map.insert(std::pair<const draiosproto::program*, uint32_t>(entry, leader));
			// move the trailer to point to a new valid input
			while (trailer >= leader &&
			       programs_map.find(&input.programs()[trailer]) != programs_map.end())
			{
				trailer--;
			}
		}
		// aggregate the duplicates
		for (uint32_t i = programs_map.size(); i < output.programs().size(); i++)
		{
			process_pids(output.programs()[i]);
			uint32_t target_index = programs_map[&output.programs()[i]];
			programs_vector[target_index]->aggregate((*output.mutable_programs())[i],
			                                         (*output.mutable_programs())[target_index],
			                                         false);
		}
		// delete the duplicate subrange
		output.mutable_programs()->DeleteSubrange(programs_map.size(),
		                                          output.programs().size() - programs_map.size());
	}
	else
	{
		for (uint32_t i = 0; i < input.programs().size(); i++)
		{
			auto entry = &(*input.mutable_programs())[i];
			if (programs_map.find(entry) == programs_map.end())
			{
				programs_vector.push_back(
				    std::unique_ptr<agent_message_aggregator<draiosproto::program>>(
				        &m_builder.build_program()));
				auto new_entry = new draiosproto::program(std::move(*entry));
				programs_vector[programs_vector.size() - 1]->aggregate(*new_entry,
				                                                       *new_entry,
				                                                       true);
				// put the pids in
				size_t be_hash = process_pids(*new_entry);
				new_entry->clear_pids();
				new_entry->add_pids(be_hash);
				output.mutable_programs()->UnsafeArenaAddAllocated(new_entry);
				programs_map.insert(std::pair<const draiosproto::program*, uint32_t>(
				    &output.programs()[output.programs().size() - 1],
				    output.programs().size() - 1));
			}
			else
			{
				process_pids(*entry);
				programs_vector[programs_map[entry]]->aggregate(
				    *entry,
				    (*output.mutable_programs())[programs_map[entry]],
				    false);
			}
		}
	}
}

void metrics_message_aggregator_impl::aggregate_config_percentiles(draiosproto::metrics& input,
                                                                   draiosproto::metrics& output,
                                                                   bool in_place)
{
	if (!in_place)
	{
		output.mutable_config_percentiles()->UnsafeArenaSwap(input.mutable_config_percentiles());
	}
}

void metrics_message_aggregator_impl::aggregate_falcobl(draiosproto::metrics& input,
                                                        draiosproto::metrics& output,
                                                        bool in_place)
{
	if (input.has_falcobl() && !in_place)
	{
		output.set_allocated_falcobl(input.release_falcobl());
	}
}

void metrics_message_aggregator_impl::aggregate_commands(draiosproto::metrics& input,
                                                         draiosproto::metrics& output,
                                                         bool in_place)
{
	if (!in_place)
	{
		for (auto& i : input.commands())
		{
			auto new_command = new draiosproto::command_details(std::move(i));
			output.mutable_commands()->UnsafeArenaAddAllocated(new_command);
		}
	}
}

void metrics_message_aggregator_impl::aggregate_swarm(draiosproto::metrics& input,
                                                      draiosproto::metrics& output,
                                                      bool in_place)
{
	if (input.has_swarm() && input.swarm().nodes().size() > 0)
	{
		metrics_message_aggregator::aggregate_swarm(input, output, in_place);
	}
	else
	{
		// if we don't meet the criteria to aggregate AND are in place, have to blow
		// it away
		if (in_place)
		{
			output.clear_swarm();
		}
	}
}

void metrics_message_aggregator_impl::aggregate_ipv4_connections(draiosproto::metrics& input,
                                                                 draiosproto::metrics& output,
                                                                 bool in_place)
{
	if (in_place)
	{
		int32_t leader = 0;
		for (int32_t trailer = input.ipv4_connections().size() - 1; leader <= trailer; leader++)
		{
			// thing is duplicate. swap it with trailer, which is guaranteed to not be
			auto entry = &(*input.mutable_ipv4_connections())[leader];
			if (ipv4_connections_map.find(entry) != ipv4_connections_map.end())
			{
				// We could in theory perform the duplicate aggregation while doing this (or the
				// trailer decrement below)
				// but this code is difficult to reason about as is, so we'll just do them all in
				// one pass at the end
				input.mutable_ipv4_connections()->SwapElements(leader, trailer);
				entry = &(*input.mutable_ipv4_connections())[leader];
			}
			// now thing is guaranteed to not be in cache, so add it
			ipv4_connections_vector.push_back(
			    std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>(
			        &m_builder.build_ipv4_connection()));
			ipv4_connections_vector[ipv4_connections_vector.size() - 1]->aggregate(*entry,
			                                                                       *entry,
			                                                                       true);
			if (entry->has_state() && entry->state() != draiosproto::connection_state::CONN_SUCCESS)
			{
				entry->clear_counters();
				entry->clear_state();
			}

			ipv4_connections_map.insert(
			    std::pair<const draiosproto::ipv4_connection*, uint32_t>(entry, leader));
			// move the trailer to point to a new valid input
			while (trailer >= leader &&
			       ipv4_connections_map.find(&input.ipv4_connections()[trailer]) !=
			           ipv4_connections_map.end())
			{
				trailer--;
			}
		}
		// aggregate the duplicates
		for (uint32_t i = ipv4_connections_map.size(); i < output.ipv4_connections().size(); i++)
		{
			if (!output.ipv4_connections()[i].has_state() ||
			    output.ipv4_connections()[i].state() == draiosproto::connection_state::CONN_SUCCESS)
			{
				uint32_t target_index = ipv4_connections_map[&output.ipv4_connections()[i]];
				ipv4_connections_vector[target_index]->aggregate(
				    (*output.mutable_ipv4_connections())[i],
				    (*output.mutable_ipv4_connections())[target_index],
				    false);
			}
		}
		// delete the duplicate subrange
		output.mutable_ipv4_connections()->DeleteSubrange(
		    ipv4_connections_map.size(),
		    output.ipv4_connections().size() - ipv4_connections_map.size());
	}
	else
	{
		for (uint32_t i = 0; i < input.ipv4_connections().size(); i++)
		{
			auto entry = &(*input.mutable_ipv4_connections())[i];
			if (ipv4_connections_map.find(entry) == ipv4_connections_map.end())
			{
				ipv4_connections_vector.push_back(
				    std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>(
				        &m_builder.build_ipv4_connection()));
				auto new_entry = new draiosproto::ipv4_connection(std::move(*entry));
				ipv4_connections_vector[ipv4_connections_vector.size() - 1]->aggregate(*new_entry,
				                                                                       *new_entry,
				                                                                       true);
				if (new_entry->has_state() &&
				    new_entry->state() != draiosproto::connection_state::CONN_SUCCESS)
				{
					new_entry->clear_counters();
					new_entry->clear_state();
				}

				output.mutable_ipv4_connections()->UnsafeArenaAddAllocated(new_entry);
				ipv4_connections_map.insert(
				    std::pair<const draiosproto::ipv4_connection*, uint32_t>(
				        &output.ipv4_connections()[output.ipv4_connections().size() - 1],
				        output.ipv4_connections().size() - 1));
			}
			else
			{
				if (!entry->has_state() ||
				    entry->state() == draiosproto::connection_state::CONN_SUCCESS)
				{
					ipv4_connections_vector[ipv4_connections_map[entry]]->aggregate(
					    *entry,
					    (*output.mutable_ipv4_connections())[ipv4_connections_map[entry]],
					    false);
				}
			}
		}
	}
}

void metrics_message_aggregator_impl::aggregate_ipv4_incomplete_connections_v2(
    draiosproto::metrics& input,
    draiosproto::metrics& output,
    bool in_place)
{
	if (in_place)
	{
		int32_t leader = 0;
		for (int32_t trailer = input.ipv4_incomplete_connections_v2().size() - 1; leader <= trailer;
		     leader++)
		{
			// thing is duplicate. swap it with trailer, which is guaranteed to not be
			auto entry = &(*input.mutable_ipv4_incomplete_connections_v2())[leader];
			if (ipv4_incomplete_connections_v2_map.find(entry) !=
			    ipv4_incomplete_connections_v2_map.end())
			{
				// We could in theory perform the duplicate aggregation while doing this (or the
				// trailer decrement below)
				// but this code is difficult to reason about as is, so we'll just do them all in
				// one pass at the end
				input.mutable_ipv4_incomplete_connections_v2()->SwapElements(leader, trailer);
				entry = &(*input.mutable_ipv4_incomplete_connections_v2())[leader];
			}
			// now thing is guaranteed to not be in cache, so add it
			ipv4_incomplete_connections_v2_vector.push_back(
			    std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>(
			        &m_builder.build_ipv4_incomplete_connection()));
			ipv4_incomplete_connections_v2_vector[ipv4_incomplete_connections_v2_vector.size() - 1]
			    ->aggregate(*entry, *entry, true);
			if (!entry->has_state() ||
			    entry->state() == draiosproto::connection_state::CONN_SUCCESS)
			{
				entry->clear_counters();
				entry->clear_state();
			}

			ipv4_incomplete_connections_v2_map.insert(
			    std::pair<const draiosproto::ipv4_incomplete_connection*, uint32_t>(entry, leader));
			// move the trailer to point to a new valid input
			while (trailer >= leader && ipv4_incomplete_connections_v2_map.find(
			                                &input.ipv4_incomplete_connections_v2()[trailer]) !=
			                                ipv4_incomplete_connections_v2_map.end())
			{
				trailer--;
			}
		}
		// aggregate the duplicates
		for (uint32_t i = ipv4_incomplete_connections_v2_map.size();
		     i < output.ipv4_incomplete_connections_v2().size();
		     i++)
		{
			if (output.ipv4_incomplete_connections_v2()[i].has_state() &&
			    output.ipv4_incomplete_connections_v2()[i].state() !=
			        draiosproto::connection_state::CONN_SUCCESS)
			{
				uint32_t target_index =
				    ipv4_incomplete_connections_v2_map[&output.ipv4_incomplete_connections_v2()[i]];
				ipv4_incomplete_connections_v2_vector[target_index]->aggregate(
				    (*output.mutable_ipv4_incomplete_connections_v2())[i],
				    (*output.mutable_ipv4_incomplete_connections_v2())[target_index],
				    false);
			}
		}
		// delete the duplicate subrange
		output.mutable_ipv4_incomplete_connections_v2()->DeleteSubrange(
		    ipv4_incomplete_connections_v2_map.size(),
		    output.ipv4_incomplete_connections_v2().size() -
		        ipv4_incomplete_connections_v2_map.size());
	}
	else
	{
		for (uint32_t i = 0; i < input.ipv4_incomplete_connections_v2().size(); i++)
		{
			auto entry = &(*input.mutable_ipv4_incomplete_connections_v2())[i];
			if (ipv4_incomplete_connections_v2_map.find(entry) ==
			    ipv4_incomplete_connections_v2_map.end())
			{
				ipv4_incomplete_connections_v2_vector.push_back(
				    std::unique_ptr<
				        agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>(
				        &m_builder.build_ipv4_incomplete_connection()));
				auto new_entry = new draiosproto::ipv4_incomplete_connection(std::move(*entry));
				ipv4_incomplete_connections_v2_vector[ipv4_incomplete_connections_v2_vector.size() -
				                                      1]
				    ->aggregate(*new_entry, *new_entry, true);
				if (!new_entry->has_state() ||
				    new_entry->state() == draiosproto::connection_state::CONN_SUCCESS)
				{
					new_entry->clear_counters();
					new_entry->clear_state();
				}

				output.mutable_ipv4_incomplete_connections_v2()->UnsafeArenaAddAllocated(new_entry);
				ipv4_incomplete_connections_v2_map.insert(
				    std::pair<const draiosproto::ipv4_incomplete_connection*, uint32_t>(
				        &output.ipv4_incomplete_connections_v2()
				             [output.ipv4_incomplete_connections_v2().size() - 1],
				        output.ipv4_incomplete_connections_v2().size() - 1));
			}
			else
			{
				if (entry->has_state() &&
				    entry->state() != draiosproto::connection_state::CONN_SUCCESS)
				{
					ipv4_incomplete_connections_v2_vector[ipv4_incomplete_connections_v2_map[entry]]
					    ->aggregate(*entry,
					                (*output.mutable_ipv4_incomplete_connections_v2())
					                    [ipv4_incomplete_connections_v2_map[entry]],
					                false);
				}
			}
		}
	}
}

void metrics_message_aggregator_impl::aggregate_prometheus(draiosproto::metrics& input,
                                                           draiosproto::metrics& output,
                                                           bool in_place)
{
	if (!in_place)
	{
		for (auto& i : input.prometheus())
		{
			auto new_prometheus = new draiosproto::prom_metrics(std::move(i));

			for (auto& sample : *(new_prometheus->mutable_samples()))
			{
				default_aggregate_value(sample.value(), *sample.mutable_agg_value());
			}

			output.mutable_prometheus()->UnsafeArenaAddAllocated(new_prometheus);
		}
	}
	else
	{
		for (auto& i : *output.mutable_prometheus())
		{
			for (auto& sample : *i.mutable_samples())
			{
				default_aggregate_value(sample.value(), *sample.mutable_agg_value());
			}
		}
	}
}

void metrics_message_aggregator_impl::aggregate(draiosproto::metrics& input,
                                                draiosproto::metrics& output,
                                                bool in_place)
{
	aggregated_programs = false;
	metrics_message_aggregator::aggregate(input, output, in_place);
}

void counter_percentile_data_message_aggregator_impl::aggregate(
    draiosproto::counter_percentile_data& input,
    draiosproto::counter_percentile_data& output,
    bool in_place)
{
	if (!in_place)
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
		const uint32_t digest_scale =
		    1000;  // must match what happens in BE and elsewhere in the kernel
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
			}
			else
			{
				output.add_means(scaled_mean - previous_mean);
			}
			output.add_weights(centroid.weight());

			previous_mean = scaled_mean;
		}

		output.set_min((int64_t)(m_digest->min() * digest_scale));
		output.set_max((int64_t)(m_digest->max() * digest_scale));
	}
}

void counter_percentile_data_message_aggregator_impl::reset()
{
	m_digest = std::unique_ptr<tdigest::TDigest>(
	    new tdigest::TDigest(200,        // compression
	                         400,        // buffer size
	                         5 * 400));  // seems to be what the java impl does
}

std::string prometheus_info_message_aggregator_impl::get_canonical_name(
    const draiosproto::prom_metric& metric)
{
	std::string name = "";
	if (metric.type() == draiosproto::app_metric_type::APP_METRIC_TYPE_PROMETHEUS_RAW)
	{
		name = "raw:" + name;
	}

	name += metric.name();
	for (auto& kv : metric.tags())
	{
		name += kv.key();
		name += kv.value();
	}

	return name;
}

void prometheus_info_message_aggregator_impl::aggregate_metrics(
    draiosproto::prometheus_info& input,
    draiosproto::prometheus_info& output,
    bool in_place)
{
	if (in_place)
	{
		// create aggregators, recursively invoke
		for (uint32_t i = 0; i < input.metrics().size(); i++)
		{
			metrics_vector.push_back(
			    std::unique_ptr<agent_message_aggregator<draiosproto::prom_metric>>(
			        &m_builder.build_prom_metric()));
			metrics_vector[i]->aggregate((*input.mutable_metrics())[i],
			                             (*output.mutable_metrics())[i],
			                             true);
		}
	}
	else
	{
		// will need to build map on second time through
		if (prom_metrics_map.size() != output.metrics().size())
		{
			for (uint32_t i = 0; i < output.metrics().size(); i++)
			{
				prom_metrics_map.insert(std::pair<std::string, uint32_t>(
				    std::move(get_canonical_name(output.metrics()[i])),
				    i));
			}
		}
		for (uint32_t i = 0; i < input.metrics().size(); i++)
		{
			auto entry = &(*input.mutable_metrics())[i];
			std::string name = get_canonical_name(*entry);
			if (prom_metrics_map.find(name) == prom_metrics_map.end())
			{
				metrics_vector.push_back(
				    std::unique_ptr<agent_message_aggregator<draiosproto::prom_metric>>(
				        &m_builder.build_prom_metric()));
				auto new_entry = new draiosproto::prom_metric(std::move(*entry));
				metrics_vector[metrics_vector.size() - 1]->aggregate(*new_entry, *new_entry, true);
				output.mutable_metrics()->UnsafeArenaAddAllocated(new_entry);
				prom_metrics_map.insert(
				    std::pair<std::string, uint32_t>(std::move(name), output.metrics().size() - 1));
			}
			else
			{
				metrics_vector[prom_metrics_map[name]]->aggregate(
				    *entry,
				    (*output.mutable_metrics())[prom_metrics_map[name]],
				    false);
			}
		}
	}
}

void container_message_aggregator_impl::aggregate_commands(draiosproto::container& input,
                                                           draiosproto::container& output,
                                                           bool in_place)
{
	if (!in_place)
	{
		for (auto& i : input.commands())
		{
			auto command = new draiosproto::command_details(std::move(i));
			output.mutable_commands()->UnsafeArenaAddAllocated(command);
		}
	}
}

void agent_event_message_aggregator_impl::aggregate_tags(draiosproto::agent_event& input,
                                                         draiosproto::agent_event& output,
                                                         bool in_place)
{
	if (!in_place)
	{
		// we don't expect to ever have multiple events which aggregate together, but in case
		// we do, just blow away the old tags and take the new ones
		output.mutable_tags()->UnsafeArenaSwap(input.mutable_tags());
	}
}

void resource_categories_message_aggregator_impl::aggregate_capacity_score(
    draiosproto::resource_categories& input,
    draiosproto::resource_categories& output,
    bool in_place)
{
	if (input.has_capacity_score() && input.capacity_score() != invalid_capacity)
	{
		resource_categories_message_aggregator::aggregate_capacity_score(input, output, in_place);
	}
	else
	{  // blow away if in place and invalid
		if (in_place)
		{
			output.clear_capacity_score();
		}
	}
}

void resource_categories_message_aggregator_impl::aggregate_stolen_capacity_score(
    draiosproto::resource_categories& input,
    draiosproto::resource_categories& output,
    bool in_place)
{
	if (input.has_stolen_capacity_score() && input.stolen_capacity_score() != invalid_capacity)
	{
		resource_categories_message_aggregator::aggregate_stolen_capacity_score(input,
		                                                                        output,
		                                                                        in_place);
	}
	else
	{  // blow away if in place and invalid
		if (in_place)
		{
			output.clear_stolen_capacity_score();
		}
	}
}

void k8s_node_message_aggregator_impl::aggregate_host_ips(draiosproto::k8s_node& input,
                                                          draiosproto::k8s_node& output,
                                                          bool in_place)
{
	if (!in_place && input.host_ips().size() != 0)
	{
		output.mutable_host_ips()->UnsafeArenaSwap(input.mutable_host_ips());
	}
}

void k8s_service_message_aggregator_impl::aggregate_ports(draiosproto::k8s_service& input,
                                                          draiosproto::k8s_service& output,
                                                          bool in_place)
{
	if (!in_place && input.ports().size() != 0)
	{
		output.mutable_ports()->UnsafeArenaSwap(input.mutable_ports());
	}
}

void swarm_task_message_aggregator_impl::aggregate_state(draiosproto::swarm_task& input,
                                                         draiosproto::swarm_task& output,
                                                         bool in_place)
{
	if (m_states.find(input.state()) == m_states.end())
	{
		m_states.insert(input.state());
		std::ostringstream stream;
		std::copy(m_states.begin(),
		          m_states.end(),
		          std::ostream_iterator<std::string>(stream, ", "));
		std::string new_state = stream.str();
		output.set_state(new_state.substr(0, new_state.size() - 2));
	}
}

void swarm_node_message_aggregator_impl::aggregate_state(draiosproto::swarm_node& input,
                                                         draiosproto::swarm_node& output,
                                                         bool in_place)
{
	if (m_states.find(input.state()) == m_states.end())
	{
		m_states.insert(input.state());
		std::ostringstream stream;
		std::copy(m_states.begin(),
		          m_states.end(),
		          std::ostream_iterator<std::string>(stream, ", "));
		std::string new_state = stream.str();
		output.set_state(new_state.substr(0, new_state.size() - 2));
	}
}

void swarm_node_message_aggregator_impl::aggregate_availability(draiosproto::swarm_node& input,
                                                                draiosproto::swarm_node& output,
                                                                bool in_place)
{
	if (m_availabilities.find(input.availability()) == m_availabilities.end())
	{
		m_availabilities.insert(input.availability());
		std::ostringstream stream;
		std::copy(m_availabilities.begin(),
		          m_availabilities.end(),
		          std::ostream_iterator<std::string>(stream, ", "));
		std::string new_availability = stream.str();
		output.set_availability(new_availability.substr(0, new_availability.size() - 2));
	}
}

void swarm_node_message_aggregator_impl::aggregate_version(draiosproto::swarm_node& input,
                                                           draiosproto::swarm_node& output,
                                                           bool in_place)
{
	if (m_versions.find(input.version()) == m_versions.end())
	{
		m_versions.insert(input.version());
		std::ostringstream stream;
		std::copy(m_versions.begin(),
		          m_versions.end(),
		          std::ostream_iterator<std::string>(stream, ", "));
		std::string new_version = stream.str();
		output.set_version(new_version.substr(0, new_version.size() - 2));
	}
}

void swarm_manager_message_aggregator_impl::aggregate_reachability(
    draiosproto::swarm_manager& input,
    draiosproto::swarm_manager& output,
    bool in_place)
{
	if (m_reachabilities.find(input.reachability()) == m_reachabilities.end())
	{
		m_reachabilities.insert(input.reachability());
		std::ostringstream stream;
		std::copy(m_reachabilities.begin(),
		          m_reachabilities.end(),
		          std::ostream_iterator<std::string>(stream, ", "));
		std::string new_reachability = stream.str();
		output.set_reachability(new_reachability.substr(0, new_reachability.size() - 2));
	}
}

void statsd_metric_message_aggregator_impl::aggregate_sum(draiosproto::statsd_metric& input,
                                                          draiosproto::statsd_metric& output,
                                                          bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_sum(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_sum();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_min(draiosproto::statsd_metric& input,
                                                          draiosproto::statsd_metric& output,
                                                          bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_min(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_min();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_max(draiosproto::statsd_metric& input,
                                                          draiosproto::statsd_metric& output,
                                                          bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_max(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_max();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_count(draiosproto::statsd_metric& input,
                                                            draiosproto::statsd_metric& output,
                                                            bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_count(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_count();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_median(draiosproto::statsd_metric& input,
                                                             draiosproto::statsd_metric& output,
                                                             bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_median(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_median();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_percentile_95(
    draiosproto::statsd_metric& input,
    draiosproto::statsd_metric& output,
    bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_percentile_95(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_percentile_95();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_percentile_99(
    draiosproto::statsd_metric& input,
    draiosproto::statsd_metric& output,
    bool in_place)
{
	if (input.type() == draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_percentile_99(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_percentile_99();
		}
	}
}

void statsd_metric_message_aggregator_impl::aggregate_value(draiosproto::statsd_metric& input,
                                                            draiosproto::statsd_metric& output,
                                                            bool in_place)
{
	if (input.type() != draiosproto::statsd_metric_type::STATSD_HISTOGRAM)
	{
		statsd_metric_message_aggregator::aggregate_value(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_value();
		}
	}
}

void environment_message_aggregator_impl::aggregate(draiosproto::environment& input,
                                                    draiosproto::environment& output,
                                                    bool in_place)
{
	if (!in_place)
	{
		output.set_allocated_hash(input.release_hash());
		output.mutable_variables()->UnsafeArenaSwap(input.mutable_variables());
	}
}

void jmx_attribute_message_aggregator_impl::aggregate_value(draiosproto::jmx_attribute& input,
                                                            draiosproto::jmx_attribute& output,
                                                            bool in_place)
{
	if (output.subattributes().size() == 0)
	{
		jmx_attribute_message_aggregator::aggregate_value(input, output, in_place);
	}
	else
	{
		if (in_place)
		{
			output.clear_value();
		}
	}
}

void jmx_attribute_message_aggregator_impl::aggregate_subattributes(
    draiosproto::jmx_attribute& input,
    draiosproto::jmx_attribute& output,
    bool in_place)
{
	if (input.subattributes().size() != 0)
	{
		output.clear_aggr_value_double();
	}
	jmx_attribute_message_aggregator::aggregate_subattributes(input, output, in_place);
}

agent_message_aggregator<draiosproto::process_details>&
message_aggregator_builder_impl::build_process_details() const
{
	return *(new process_details_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::process>& message_aggregator_builder_impl::build_process()
    const
{
	return *(new process_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::metrics>& message_aggregator_builder_impl::build_metrics()
    const
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

agent_message_aggregator<draiosproto::container>& message_aggregator_builder_impl::build_container()
    const
{
	return *(new container_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::k8s_node>& message_aggregator_builder_impl::build_k8s_node()
    const
{
	return *(new k8s_node_message_aggregator_impl(*this));
}

agent_message_aggregator<draiosproto::k8s_service>&
message_aggregator_builder_impl::build_k8s_service() const
{
	return *(new k8s_service_message_aggregator_impl(*this));
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

agent_message_aggregator<draiosproto::program>& message_aggregator_builder_impl::build_program()
    const
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
