#include "aggregator_overrides.h"

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

			// substitute the pids in!
			new_entry->clear_pids();
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

void metrics_message_aggregator_impl::aggregate_ipv4_connections(const draiosproto::metrics& input,
								 draiosproto::metrics& output)
{
	// ensure programs are aggregated first
	aggregate_programs(input, output);

	for (auto i : input.ipv4_connections())
	{
		if (ipv4_connections_map.find(&i) == ipv4_connections_map.end())
		{
			auto new_entry = output.add_ipv4_connections();
			agent_message_aggregator<draiosproto::ipv4_connection>* new_aggregator = &m_builder.build_ipv4_connection();
			new_aggregator->aggregate(i, *new_entry);

			// substitute pids
			auto hash = pid_map.find(i.spid());
			if (hash != pid_map.end())
			{
				new_entry->set_spid(hash->second);
			}
			hash = pid_map.find(i.dpid());
			if (hash != pid_map.end())
			{
				new_entry->set_dpid(hash->second);
			}

			ipv4_connections_map.insert(
				std::make_pair<draiosproto::ipv4_connection*, std::pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>>>(
					std::move(new_entry),
					std::make_pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>>(
						output.ipv4_connections().size() - 1,
						std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_connection>>(new_aggregator)
					)
				)
			);
		}
		else
		{
			ipv4_connections_map[&i].second->aggregate(i, (*output.mutable_ipv4_connections())[ipv4_connections_map[&i].first]);
		}
	}
}

void metrics_message_aggregator_impl::aggregate_ipv4_incomplete_connections_v2(const draiosproto::metrics& input,
																			   draiosproto::metrics& output)
{
	// ensure programs are aggregated first
	aggregate_programs(input, output);

	for (auto i : input.ipv4_incomplete_connections_v2())
	{
		if (ipv4_incomplete_connections_v2_map.find(&i) == ipv4_incomplete_connections_v2_map.end())
		{
			auto new_entry = output.add_ipv4_incomplete_connections_v2();
			agent_message_aggregator<draiosproto::ipv4_incomplete_connection>* new_aggregator = &m_builder.build_ipv4_incomplete_connection();
			new_aggregator->aggregate(i, *new_entry);

			// substitute pids
			auto hash = pid_map.find(i.spid());
			if (hash != pid_map.end())
			{
				new_entry->set_spid(hash->second);
			}
			hash = pid_map.find(i.dpid());
			if (hash != pid_map.end())
			{
				new_entry->set_dpid(hash->second);
			}
    
			ipv4_incomplete_connections_v2_map.insert(
				std::make_pair<draiosproto::ipv4_incomplete_connection*, std::pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>>>(
					std::move(new_entry),
					std::make_pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>>(
						output.ipv4_incomplete_connections_v2().size() - 1,
						std::unique_ptr<agent_message_aggregator<draiosproto::ipv4_incomplete_connection>>(new_aggregator)
					)
				)
			);
		}
		else
		{
			ipv4_incomplete_connections_v2_map[&i].second->aggregate(i, (*output.mutable_ipv4_incomplete_connections_v2())[ipv4_incomplete_connections_v2_map[&i].first]);
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
	if (input.has_capacity_score() && input.capacity_score() != invalid_capacity)
	{
		default_aggregate_value<decltype(input.stolen_capacity_score()),
								decltype(*output.mutable_aggr_stolen_capacity_score())>(input.stolen_capacity_score(),
																						*output.mutable_aggr_stolen_capacity_score());
    }
}

agent_message_aggregator<draiosproto::process_details>&
message_aggregator_builder_impl::build_process_details() const
{
	return *(new process_details_message_aggregator_impl(*this));
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
