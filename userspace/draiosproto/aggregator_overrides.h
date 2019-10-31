#pragma once

#include "draios.proto.h"
#include "tdigest/tdigest.h"

// in order to override any of the generated function,
// 1) create the impl class that derives from the generated aggregator
// 2) write the allocator, and override any functions you need to
// 3) override the appropriate builder function in the builder_impl below

class process_details_message_aggregator_impl : public process_details_message_aggregator
{
public:
	process_details_message_aggregator_impl(const message_aggregator_builder& builder)
	    : process_details_message_aggregator(builder)
	{
	}

private:
	// args need to be treated like a list, not a set, so needs special handling
	virtual void aggregate_args(const draiosproto::process_details& input,
	                            draiosproto::process_details& output);

	// backend always sets container id, even if not set in input, so we do, too
	virtual void aggregate_container_id(const draiosproto::process_details& input,
	                                    draiosproto::process_details& output);
};

class process_message_aggregator_impl : public process_message_aggregator
{
public:
	process_message_aggregator_impl(const message_aggregator_builder& builder)
	    : process_message_aggregator(builder), m_netrole(0)
	{
	}

private:
	uint32_t m_netrole;
	virtual void aggregate_netrole(const draiosproto::process& input,
	                               draiosproto::process& outpout);
	virtual void aggregate_is_ipv4_transaction_client(const draiosproto::process& input,
	                                                  draiosproto::process& outpout);
	virtual void aggregate_is_ipv4_transaction_server(const draiosproto::process& input,
	                                                  draiosproto::process& outpout);

	virtual void reset()
	{
		m_netrole = 0;
		process_message_aggregator::reset();
	}
};

class metrics_message_aggregator_impl : public metrics_message_aggregator
{
public:
	metrics_message_aggregator_impl(const message_aggregator_builder& builder)
	    : metrics_message_aggregator(builder)
	{
	}

public:
	// we have an awkward dependency that the BE depends on a hash of the program. This
	// computes that hash, which is effectively the java hash of the equivalent objects
	static int32_t java_string_hash(const std::string& input, uint32_t end_pos = UINT32_MAX)
	{
		int32_t hash = 0;

		if (end_pos > input.size())
		{
			end_pos = input.size();
		}

		for (uint32_t i = 0; i < end_pos; ++i)
		{
			hash = 31 * hash + input[i];
		}
		return hash;
	}
	static int32_t java_list_hash(const google::protobuf::RepeatedPtrField<std::string>& input)
	{
		int32_t hash = 1;
		for (auto i : input)
		{
			hash = 31 * hash + java_string_hash(i);
		}
		return hash;
	}
	static size_t program_java_hasher(const draiosproto::program& input)
	{
		const draiosproto::process& proc = input.procinfo();
		const draiosproto::process_details& details = proc.details();

		int32_t hash = 0;

		auto separator_loc = details.exe().find(": ");
		hash += java_string_hash(
		    details.exe(),
		    separator_loc == std::string::npos ? details.exe().size() : separator_loc);
		hash = 31 * hash + java_list_hash(details.args());
		hash += java_string_hash(details.container_id());
		hash += java_string_hash(input.environment_hash());

		return hash;
	}

	// Warning: hack here. The BE changes certain values which are also primary keys,
	// so must we also. Therefore the only time we can reasonably
	// change it is just before we emit. Since we don't have a framework for "things to do
	// before emit", we're forced to invoke this function manually. Like limiting,
	// aggregating after performing this operation results in undefined operation, and thus
	// the only valid operation is to reset the aggregator.
	//
	// Ideally, this work should be the responsibility of the agent, not the aggregator.
	void override_primary_keys(draiosproto::metrics& output);

private:
	// mapping from pid to hash. This is used to give us a PID agnostic ID of a process.
	// We store the mapping here until reset
	std::map<uint32_t, size_t> pid_map;

	// we have to ensure we've populated the pid_map before anyone uses it. this tracks
	// whether we've aggregated programs yet. Reset with each call to aggregate()
	bool aggregated_programs;

	// Overrides for program which ensures pid_map is populated
	virtual void aggregate_programs(const draiosproto::metrics& input,
	                                draiosproto::metrics& output);

	// we just copy the last seen value in
	virtual void aggregate_falcobl(const draiosproto::metrics& input, draiosproto::metrics& output);

	// just concatenate command details
	virtual void aggregate_commands(const draiosproto::metrics& input,
	                                draiosproto::metrics& output);

	// just store whatever the most recent list was. don't combine
	virtual void aggregate_config_percentiles(const draiosproto::metrics& input,
	                                          draiosproto::metrics& output);

	// backend sends a raw value for SR as well as the aggregation
	virtual void aggregate_sampling_ratio(const draiosproto::metrics& input,
	                                      draiosproto::metrics& output);

	// backend skips sending swarm if there are no nodes
	virtual void aggregate_swarm(const draiosproto::metrics& input, draiosproto::metrics& output);

	// skip connections that are not successful
	virtual void aggregate_ipv4_connections(const draiosproto::metrics& input,
											draiosproto::metrics& output);
	// skip connections that are not incomplete
	virtual void aggregate_ipv4_incomplete_connections_v2(const draiosproto::metrics& input,
														 draiosproto::metrics& output);
public:
	// need to reset the pid_map field
	virtual void reset()
	{
		pid_map.clear();
		metrics_message_aggregator::reset();
	}

	virtual void aggregate(const draiosproto::metrics& input, draiosproto::metrics& output);

	friend class test_helper;
};

class counter_percentile_data_message_aggregator_impl
    : public counter_percentile_data_message_aggregator
{
public:
	counter_percentile_data_message_aggregator_impl(const message_aggregator_builder& builder)
	    : counter_percentile_data_message_aggregator(builder)
	{
		// this ensures that some of the custom member vars are set up correctly
		reset();
	}

private:
	// counter_percentile_data is effectively an opaque serialization of
	// a tdigest object, so we have to use tdigest to do the aggregation
	// instead of aggregating fields individually
	std::unique_ptr<tdigest::TDigest> m_digest;
	virtual void aggregate(const draiosproto::counter_percentile_data& input,
	                       draiosproto::counter_percentile_data& output);

	// need to reset the tdigest
	virtual void reset();
};

class container_message_aggregator_impl : public container_message_aggregator
{
public:
	container_message_aggregator_impl(const message_aggregator_builder& builder)
	    : container_message_aggregator(builder)
	{
	}

private:
	virtual void aggregate_commands(const draiosproto::container& input,
	                                draiosproto::container& output);
};

class agent_event_message_aggregator_impl : public agent_event_message_aggregator
{
public:
	agent_event_message_aggregator_impl(const message_aggregator_builder& builder)
	    : agent_event_message_aggregator(builder)
	{
	}

private:
	// don't mix tags if we end up aggregating event. just take last set
	virtual void aggregate_tags(const draiosproto::agent_event& input,
	                            draiosproto::agent_event& output);
};

class swarm_task_message_aggregator_impl: public swarm_task_message_aggregator
{
public:
	swarm_task_message_aggregator_impl(const message_aggregator_builder& builder)
		: swarm_task_message_aggregator(builder)
	{}

private:
	std::set<std::string> m_states;
	virtual void aggregate_state(const draiosproto::swarm_task& input,
								 draiosproto::swarm_task& output);

public:
	virtual void reset()
	{
		m_states.clear();
		swarm_task_message_aggregator::reset();
	}
};

class swarm_node_message_aggregator_impl: public swarm_node_message_aggregator
{
public:
	swarm_node_message_aggregator_impl(const message_aggregator_builder& builder)
		: swarm_node_message_aggregator(builder)
	{}

private:
	std::set<std::string> m_states;
	virtual void aggregate_state(const draiosproto::swarm_node& input,
								 draiosproto::swarm_node& output);
	std::set<std::string> m_availabilities;
	virtual void aggregate_availability(const draiosproto::swarm_node& input,
										draiosproto::swarm_node& output);
	std::set<std::string> m_versions;
	virtual void aggregate_version(const draiosproto::swarm_node& input,
								   draiosproto::swarm_node& output);

public:
	virtual void reset()
	{
		m_states.clear();
		m_availabilities.clear();
		m_versions.clear();
		swarm_node_message_aggregator::reset();
	}
};

class swarm_manager_message_aggregator_impl: public swarm_manager_message_aggregator
{
public:
	swarm_manager_message_aggregator_impl(const message_aggregator_builder& builder)
		: swarm_manager_message_aggregator(builder)
	{}

private:
	std::set<std::string> m_reachabilities;
	virtual void aggregate_reachability(const draiosproto::swarm_manager& input,
										draiosproto::swarm_manager& output);
public:
	virtual void reset()
	{
		m_reachabilities.clear();
		swarm_manager_message_aggregator::reset();
	}
};

class resource_categories_message_aggregator_impl : public resource_categories_message_aggregator
{
public:
	resource_categories_message_aggregator_impl(const message_aggregator_builder& builder)
	    : resource_categories_message_aggregator(builder)
	{
	}

private:
	// capacity scores need to ignore "invalid capacity" This number is well known.
	const uint32_t invalid_capacity = UINT32_MAX - 100 + 1;
	virtual void aggregate_capacity_score(const draiosproto::resource_categories& input,
	                                      draiosproto::resource_categories& output);
	virtual void aggregate_stolen_capacity_score(const draiosproto::resource_categories& input,
	                                             draiosproto::resource_categories& output);
};

class statsd_metric_message_aggregator_impl : public statsd_metric_message_aggregator
{
public:
	statsd_metric_message_aggregator_impl(const message_aggregator_builder& builder)
		: statsd_metric_message_aggregator(builder)
	{}

private:
	// we conditionally aggregate certain fields
	virtual void aggregate_sum(const draiosproto::statsd_metric& input,
							   draiosproto::statsd_metric& output);
	virtual void aggregate_min(const draiosproto::statsd_metric& input,
							   draiosproto::statsd_metric& output);
	virtual void aggregate_max(const draiosproto::statsd_metric& input,
							   draiosproto::statsd_metric& output);
	virtual void aggregate_count(const draiosproto::statsd_metric& input,
								 draiosproto::statsd_metric& output);
	virtual void aggregate_median(const draiosproto::statsd_metric& input,
								  draiosproto::statsd_metric& output);
	virtual void aggregate_percentile_95(const draiosproto::statsd_metric& input,
										 draiosproto::statsd_metric& output);
	virtual void aggregate_percentile_99(const draiosproto::statsd_metric& input,
										 draiosproto::statsd_metric& output);
	virtual void aggregate_value(const draiosproto::statsd_metric& input,
								 draiosproto::statsd_metric& output);
};

class program_message_aggregator_impl : public program_message_aggregator
{
public:
	program_message_aggregator_impl(const message_aggregator_builder& builder)
		: program_message_aggregator(builder)
	{}

private:
	// do nothing. caller will set this appropriately
	virtual void aggregate_pids(const draiosproto::program& input,
								draiosproto::program& output) {}
};

class environment_message_aggregator_impl : public environment_message_aggregator
{
public:
	environment_message_aggregator_impl(const message_aggregator_builder& builder)
		: environment_message_aggregator(builder)
	{}

private:
	virtual void aggregate(const draiosproto::environment& input,
						   draiosproto::environment& output);
};

class jmx_attribute_message_aggregator_impl : public jmx_attribute_message_aggregator
{
public:
	jmx_attribute_message_aggregator_impl(const message_aggregator_builder& builder)
		: jmx_attribute_message_aggregator(builder)
	{}

private:
	// somewhat strange interaction. If we have subattributes, we don't send
	// aggr value.
	virtual void aggregate_value(const draiosproto::jmx_attribute& input,
								 draiosproto::jmx_attribute& output);
	virtual void aggregate_subattributes(const draiosproto::jmx_attribute& input,
										 draiosproto::jmx_attribute& output);
};

// for any message type which we've overridden, we have to override it's builder
// function as well
class message_aggregator_builder_impl : public message_aggregator_builder
{
public:
	virtual agent_message_aggregator<draiosproto::process_details>& build_process_details() const;
	virtual agent_message_aggregator<draiosproto::process>& build_process() const;
	virtual agent_message_aggregator<draiosproto::metrics>& build_metrics() const;
	virtual agent_message_aggregator<draiosproto::counter_percentile_data>&
	    build_counter_percentile_data() const;
	virtual agent_message_aggregator<draiosproto::container>& build_container() const;
	virtual agent_message_aggregator<draiosproto::agent_event>& build_agent_event() const;
	virtual agent_message_aggregator<draiosproto::resource_categories>& build_resource_categories() const;
	virtual agent_message_aggregator<draiosproto::swarm_task>& build_swarm_task() const;
	virtual agent_message_aggregator<draiosproto::swarm_manager>& build_swarm_manager() const;
	virtual agent_message_aggregator<draiosproto::swarm_node>& build_swarm_node() const;
	virtual agent_message_aggregator<draiosproto::statsd_metric>& build_statsd_metric() const;
	virtual agent_message_aggregator<draiosproto::program>& build_program() const;
	virtual agent_message_aggregator<draiosproto::environment>& build_environment() const;
	virtual agent_message_aggregator<draiosproto::jmx_attribute>& build_jmx_attribute() const;
};
