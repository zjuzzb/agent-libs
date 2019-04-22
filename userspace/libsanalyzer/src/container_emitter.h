#pragma once

#include <sinsp_int.h>
#include <unordered_map>
#include <container_analyzer.h>

// Class: container Emitter
//
// This class is designed as a single-use ephemeral class for emitting containers. It is expected
// that the life of this class is stack allocated, and thus will exceed the lifetime of any of
// the member pointers.
//
// Usage will generally involve:
// container_emitter emitter(...);
// emitter.emit_containers();
//
// If you're holding onto the emitter for longer than that, you're probably doing it wrong.
//
// Two types for the template:
// callback_type = the thing that implements the callbacks called during emission. They are
// 1) emit_container - called whenever we emit a container
// 2) found_emittable_container  - called on all containers which can be emitted.
//    guaranteed to be called before emit_container, if the container is emitted at all
// 3) get_container - returns the sinsp_container_info for a container
// 4) m_configuration - a sinsp_configuration
// 5) infra_state
// 6) m_prev_flush_time_ns
//
// callback_arg_type = opaque type which is passed into the  emit_container cb
// 
template <typename callback_type, typename callback_arg_type>
class container_emitter {
public:
	container_emitter(callback_type& t,
			  std::unordered_map<std::string, analyzer_container_state>& containers,
			  unsigned statsd_limit,
			  const std::unordered_map<string, vector<sinsp_threadinfo*>>& progtable_by_container,
			  const vector<string>& container_patterns,
			  callback_arg_type flshflags,
			  uint32_t limit,
			  bool nodriver,
			  std::vector<std::string>& emitted_containers);

	void emit_containers();

private:
	static const uint32_t stat_categories = 4; 
	// if you're adding categories, bump the count!
	static double cpu_extractor(const analyzer_container_state& analyzer_state);
	static int64_t mem_extractor(const analyzer_container_state& analyzer_state);
	static uint64_t file_io_extractor(const analyzer_container_state& analyzer_state);
	static uint64_t net_io_extractor(const analyzer_container_state& analyzer_state);
	// if you're adding categories, bump the count!

	static uint64_t age_extractor(const analyzer_container_state& analyzer_state);

	callback_type& m_t;
	std::unordered_map<std::string, analyzer_container_state>& m_containers; // input containers
	std::vector<std::string> m_must_report; // ids of all container which explicitly match filter rules
	std::vector<std::string> m_can_report; // ids of containers which are not must report containers, but are also not explicitly excluded
	unsigned m_statsd_limit;
	std::set<std::string> m_emitted_containers; // set of emitted containers...set for fast lookup
	std::vector<std::string>& m_emitted_containers_out; //ref to std::vector that we ultimately have to return
	uint64_t m_total_cpu_shares;
	const std::unordered_map<string, vector<sinsp_threadinfo*>>& m_progtable_by_container;
	callback_arg_type m_flshflags;
	const std::vector<std::string>& m_container_patterns;
	uint64_t m_container_limit;
	bool m_used;
	bool m_nodriver;

	void check_and_emit_containers(std::vector<std::string>& containers, const uint32_t containers_limit, bool high_priority);

	template<typename Extractor>
	class containers_cmp
	{
	public:
		containers_cmp(const std::unordered_map<std::string, analyzer_container_state>* containers,
			       const std::set<std::string>* emitted_containers,
			       Extractor extractor):
			m_containers(containers),
			m_emitted_containers(emitted_containers),
			m_extractor(extractor)
		{}

		bool operator()(const std::string& lhs, const std::string& rhs)
		{
			// we always want non-emitted containers to come before emitted ones.
			// So if one is emitted and the other isn't, return the non-emitted one.
			// Note that this function returns "true" if LHS comes before RHS, so
			// by returning rhs when they are un equal makes the one who isn't emitted
			// go first. If they are equal, fallback to regular comparison
			bool lhs_emitted = m_emitted_containers->find(lhs) != m_emitted_containers->end();
			bool rhs_emitted = m_emitted_containers->find(rhs) != m_emitted_containers->end();
			if (lhs_emitted != rhs_emitted)
			{
				return rhs_emitted;
			}

			const auto it_analyzer_lhs = m_containers->find(lhs);
			ASSERT(it_analyzer_lhs != m_containers->end());
			decltype(m_extractor(it_analyzer_lhs->second)) cmp_lhs = 0;
			if(it_analyzer_lhs != m_containers->end())
			{
				cmp_lhs = m_extractor(it_analyzer_lhs->second);
			}

			const auto it_analyzer_rhs = m_containers->find(rhs);
			ASSERT(it_analyzer_rhs != m_containers->end());
			decltype(m_extractor(it_analyzer_rhs->second)) cmp_rhs = 0;
			if(it_analyzer_rhs != m_containers->end())
			{
				cmp_rhs = m_extractor(it_analyzer_rhs->second);
			}

			if(cmp_lhs != cmp_rhs)
			{
				return cmp_lhs > cmp_rhs;
			}

			// do it in alphabetical order if all things else are equal. if names are equal, then this doesn't matter
			return lhs.compare(rhs) > 0;
		}
	private:
		// map of IDs to actual container state
		const std::unordered_map<std::string, analyzer_container_state>* m_containers;
		const std::set<std::string>* m_emitted_containers;
		Extractor m_extractor;
	};

	bool patterns_contain(const sinsp_container_info& container_info)
	{
		if (m_container_patterns.empty()) 
		{
			return true;
		}
              
		auto result = std::find_if(m_container_patterns.begin(),
					   m_container_patterns.end(),
					   [&container_info](const std::string& pattern)
					   {
						return container_info.m_name.find(pattern) != std::string::npos ||
						container_info.m_image.find(pattern) != std::string::npos;
					   });

		return result != m_container_patterns.end();
	}

	void emit_range(std::vector<std::string>::iterator it, uint32_t limit, bool high_priority)
	{
		uint32_t count = 0;
		for (auto i = it; count < limit; ++i, ++count)
		{
			// caller responsible for ensuring we only emit containers once
			ASSERT(m_emitted_containers.find(*i) == m_emitted_containers.end());

			// it would be....odd/wrong to have a container without the
			// backing program...
			if (m_progtable_by_container.at(*i).size() == 0)
			{
				ASSERT(false);
				continue;
			}

			//  ideally, we'll pull this out of the filter in order to populate correclt,y
			//  but that's a bit of work and the back-end ignores it anyway. They only care
			//  about the count of groups in terms of priority, so just indicate that it
			//  matched a group
			std::list<uint32_t> groups;
			if (high_priority)
			{
				groups.push_back(1);
			}

			m_t.emit_container(*i,
					   &m_statsd_limit,
					   m_total_cpu_shares,
					   m_progtable_by_container.at(*i).front(),
					   m_flshflags,
					   groups);
			m_emitted_containers.emplace(*i);
		}
	}

};

#include "container_emitter.hh"
