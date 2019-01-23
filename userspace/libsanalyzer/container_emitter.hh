
template <typename callback_type, typename callback_arg_type>
container_emitter<callback_type,callback_arg_type>::container_emitter(callback_type& t,
					unordered_map<string, analyzer_container_state>& containers,
					unsigned statsd_limit,
					const unordered_map<string, vector<sinsp_threadinfo*>>& progtable_by_container,
					const vector<string>& container_patterns,
					callback_arg_type flshflags,
					uint32_t limit,
					bool nodriver,
					vector<string>& emitted_containers)
	: m_t(t),
	  m_containers(containers),
	  m_must_report(),
	  m_can_report(),
	  m_statsd_limit(statsd_limit),
	  m_emitted_containers(),
	  m_emitted_containers_out(emitted_containers),
	  m_total_cpu_shares(0),
	  m_progtable_by_container(progtable_by_container),
	  m_flshflags(flshflags),
	  m_container_patterns(container_patterns),
	  m_container_limit(limit),
	  m_used(false),
	  m_nodriver(nodriver)
{
}

template <typename callback_type, typename callback_arg_type>
double container_emitter<callback_type,callback_arg_type>::cpu_extractor(const analyzer_container_state& analyzer_state)
{
	return analyzer_state.m_metrics.m_cpuload;
}

template <typename callback_type, typename callback_arg_type>
int64_t container_emitter<callback_type,callback_arg_type>::mem_extractor(const analyzer_container_state& analyzer_state)
{
	return analyzer_state.m_metrics.m_res_memory_used_kb;
}

template <typename callback_type, typename callback_arg_type>
uint64_t container_emitter<callback_type,callback_arg_type>::file_io_extractor(const analyzer_container_state& analyzer_state)
{
	return analyzer_state.m_req_metrics.m_io_file.get_tot_bytes();
}

template <typename callback_type, typename callback_arg_type>
uint64_t container_emitter<callback_type,callback_arg_type>::net_io_extractor(const analyzer_container_state& analyzer_state)
{
	return analyzer_state.m_req_metrics.m_io_net.get_tot_bytes();
}

template <typename callback_type, typename callback_arg_type>
uint64_t container_emitter<callback_type,callback_arg_type>::age_extractor(const analyzer_container_state& analyzer_state)
{
	return analyzer_state.m_reported_count;
}

template <typename callback_type, typename callback_arg_type>
void container_emitter<callback_type,callback_arg_type>::check_and_emit_containers(vector<string>& containers, const uint32_t containers_limit)
{
	// first sort containers by who has been emitted the longest
	sort(containers.begin(),
	     containers.end(),
	     containers_cmp<decltype(&age_extractor)>(&m_containers, &m_emitted_containers, &age_extractor));

	// now start walking through the list. For each value of age, if we have enough
	// space left in the limit, report it. Otherwise, given the remaining range available,
	// take the top from each stats category
	auto rabbit_it = containers.begin();
	auto turtle_it = containers.begin();
	uint32_t remaining_limit = containers_limit;

	while (remaining_limit != 0 && turtle_it != containers.end())
	{
		uint32_t distance = 0;

		// move rabbit it to the next age category
		while (rabbit_it != containers.end() && age_extractor(m_containers.find(*rabbit_it)->second) == age_extractor(m_containers.find(*turtle_it)->second))
		{
			distance++;
			rabbit_it++;
		}

		// all of them fit. ship it!
		if (remaining_limit >= distance)
		{
			emit_range(turtle_it, distance);
			remaining_limit -= distance;
		}
		else // they all won't fit....sort by stats
		{
			uint32_t limit_per_type = remaining_limit / stat_categories;
			partial_sort(turtle_it,
				    turtle_it + limit_per_type,
				    rabbit_it,
				    containers_cmp<decltype(&mem_extractor)>(&m_containers, &m_emitted_containers, &mem_extractor));
			emit_range(turtle_it, limit_per_type);

			partial_sort(turtle_it,
				    turtle_it + limit_per_type,
				    rabbit_it,
				    containers_cmp<decltype(&file_io_extractor)>(&m_containers, &m_emitted_containers, &file_io_extractor));
			emit_range(turtle_it, limit_per_type);

			// in cases where we have no driver, skip net_io, and emit double cpu
			if (m_nodriver)
			{
				partial_sort(turtle_it,
					    turtle_it + limit_per_type,
					    rabbit_it,
					    containers_cmp<decltype(&cpu_extractor)>(&m_containers, &m_emitted_containers, &cpu_extractor));
			}
			else
			{
				partial_sort(turtle_it,
					    turtle_it + limit_per_type,
					    rabbit_it,
					    containers_cmp<decltype(&net_io_extractor)>(&m_containers, &m_emitted_containers, &net_io_extractor));
			}
			emit_range(turtle_it, limit_per_type);

			partial_sort(turtle_it,
				    turtle_it + limit_per_type,
				    rabbit_it,
				    containers_cmp<decltype(&cpu_extractor)>(&m_containers, &m_emitted_containers, &cpu_extractor));
			emit_range(turtle_it, limit_per_type);

			remaining_limit = 0;
		}

		// set the turtle pointer for the start of the new phase
		turtle_it = rabbit_it;
	}
}

template <typename callback_type, typename callback_arg_type>
void container_emitter<callback_type,callback_arg_type>::emit_containers()
{
	assert(!m_used);
	m_used = true;

	m_must_report.reserve(m_containers.size());
	m_can_report.reserve(m_containers.size());
	sinsp_protostate_marker containers_protostate_marker;

	// we walk through all the containers in the progtable and do the following
	// 1) if it is not a k8s pod, count its CPU time into a total
	// 2) if it's additionally matching a container pattern and the analyzer has specific
	//    info for it, we prepare to emit it by adding it to the list of container IDs
	//    and add its protostate stuff to our global sorting marker
	uint64_t total_cpu_shares = 0;
	for(const auto& item : m_progtable_by_container)
	{
		const string& container_id = item.first;
		const sinsp_container_info* sinsp_container_info_instance = m_t.get_container(container_id);
		if(sinsp_container_info_instance &&
		   !is_kubernetes_pod(*sinsp_container_info_instance))
		{
			if (patterns_contain(*sinsp_container_info_instance))
			{
				auto analyzer_container_info = m_containers.find(container_id);
				bool optional;
				if((analyzer_container_info != m_containers.end()) &&
				   analyzer_container_info->second.should_report_container(m_t.m_configuration,
											   sinsp_container_info_instance,
											   m_t.infra_state(),
											   m_t.m_prev_flush_time_ns,
											   optional))
				{
					if (optional) {
						m_can_report.push_back(container_id);
					} else {
						m_must_report.push_back(container_id);
					}
					containers_protostate_marker.add(analyzer_container_info->second.m_metrics.m_protostate);
				}
			}

			// This count it's easy to be affected by a lot of noise, for example:
			// 1. k8s_POD pods
			// 2. custom containers run from cmdline with no --cpu-shares flag,
			//    in this case the kernel defaults to 1024
			// 3. system containers like kubernetes proxy
			//
			// we decided to skip 1. to avoid noise (they have usually shares=2,
			// does not affect so much the calc but they may be a lot)
			// Right now we decided to keep 2. But may be changed in the future
			// because usually if --cpu-shares flag is not set, it is meant for troubleshooting
			// containers with few cpu usage or system containers
			// with a default of 1024 given by the kernel, they pollute a lot the calculation
			total_cpu_shares += sinsp_container_info_instance->m_cpu_shares;
		}
	}

	m_t.found_emittable_containers(m_t, m_must_report, m_progtable_by_container);
	m_t.found_emittable_containers(m_t, m_can_report, m_progtable_by_container);

	g_logger.format(sinsp_logger::SEV_DEBUG, "total_cpu_shares=%lu", total_cpu_shares);
	containers_protostate_marker.mark_top(CONTAINERS_PROTOS_TOP_LIMIT);
	// Emit m_containers_limit sorted by the following priority:
	// Take containers which match the reporting filters first
	// Take containers which have been previously reported next
	// Take containers which are top in the cpu/mem/file IO
	//
	// By extension, the following is true:
	// -if fewer than <limit> filtered containers exist, all will be reported, and
	//  <limit> - filtered_count containers will be reported
	//
	// -if more than <limit> filtered containers exist, no non-filtered containers will be reported
	//
	// -whenever one of the two classes ultimately spans the <limit>, we report all
	//  previoulsy reported containers before new containers
	//
	// -whenever any of the above classes span the limit, we figure out how many remaining
	//  spots we have to fill in our limit allocation, and then attempt to take the top
	//  from each stat category

	check_and_emit_containers(m_must_report, m_container_limit);
	if (m_container_limit > m_must_report.size())
	{
		check_and_emit_containers(m_can_report, m_container_limit - m_must_report.size());
	}

	for (auto it = m_emitted_containers.begin(); it != m_emitted_containers.end(); ++it)
	{
		m_emitted_containers_out.emplace_back(*it);
		m_containers.find(*it)->second.m_reported_count++;
	}	
}

