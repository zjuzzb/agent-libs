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

void metrics_message_aggregator_impl::aggregate(const draiosproto::metrics& input,
						draiosproto::metrics& output)
{
    aggregated_programs = false;
    metrics_message_aggregator::aggregate(input, output);
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

