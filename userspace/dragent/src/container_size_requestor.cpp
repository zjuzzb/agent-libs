
#include "container_size_requestor.h"
#include "Poco/Thread.h"
#include <container_info.h>
#include <common_logger.h>
#include <type_config.h>

namespace {

COMMON_LOGGER();

type_config<bool> c_enabled(
   false,
   "Enable the container size request subsystem.",
   "container_size_request",
   "enabled");

type_config<uint64_t>::ptr c_interval_s = type_config_builder<uint64_t>(
   4 * 60 * 60 /*default 4 hours*/,
   "The number of seconds between each request for the size of a container's "
   "container-layer. This is not gathered every second because determining the "
   "size can be time consuming and cpu intensive.",
   "container_size_request",
   "interval_s")
   .min(1).build();

type_config<uint64_t> c_first_request_delay_s(
   30 /*default*/,
   "The number of seconds to wait before requesting container sizes after the "
   "agent boots. This delay allows the agent to reach a steady state before "
   "querying the container socket.",
   "container_size_request",
   "first_request_delay_s");

}

container_size_requestor::container_size_requestor(const sinsp_container_manager& mgr,
						   const update_delegate& delegate) :
   m_manager(mgr),
   update_container_with_size(delegate),
   m_last_cache_update_ms(0),
   m_original_cache_container_count(0)
{
}

void container_size_requestor::request(const uint64_t uptime_ms)
{
	// If enough time has passed then send one or more requests.
	send_requests(uptime_ms);

	// If enough time has passed then update the cache.
	load_container_subset_cache(uptime_ms);
}

bool container_size_requestor::is_time_to_update_cache(const uint64_t uptime_ms)
{
	if(!m_cache.empty())
	{
		return false;
	}

	// For the very first request, wait a bit for the agent to initialize.
	if(0 == m_last_cache_update_ms)
	{
		return uptime_ms > c_first_request_delay_s.get_value() * 1000;
	}

	// Afterwards update at the configured interval.
	const uint64_t time_since_update_ms = uptime_ms - m_last_cache_update_ms;
	return time_since_update_ms >= c_interval_s->get_value() * 1000;
}

void container_size_requestor::load_container_subset_cache(const uint64_t uptime_ms)
{
	if(!is_time_to_update_cache(uptime_ms))
	{
		return;
	}

	{
		// Since this locks the container map, we just copy the
		// data we want and destroy the lock. Container count
		// max is in the hundreds so this is pretty quick.
		auto containers = m_manager.get_containers();
		for(auto it = containers->begin(); it != containers->end(); ++it)
		{
			if(it->second->is_pod_sandbox())
			{
				continue;
			}

			m_cache.push_back(container_info_subset(*it->second));
		}
	}

	if(m_cache.empty())
	{
		return;
	}

	m_original_cache_container_count = m_cache.size();
	m_last_cache_update_ms = uptime_ms;
	const float containers_per_second = float(m_original_cache_container_count) / float(c_interval_s->get_value());
	LOG_INFO("Will request size update for %zu containers at roughly %f "
	         "containers per second",
	         m_cache.size(),
             containers_per_second);
}

void container_size_requestor::send_requests(const uint64_t uptime_ms)
{
	if(m_cache.empty())
	{
		return;
	}

	const float containers_per_second = static_cast<float>(m_original_cache_container_count) / static_cast<float>(c_interval_s->get_value());
	const uint64_t time_passed_since_queue_update_s = (uptime_ms - m_last_cache_update_ms) / 1000;
	const unsigned int containers_to_request_since_queue_update = static_cast<unsigned int>(containers_per_second * time_passed_since_queue_update_s);
	const unsigned int containers_requested_so_far = m_original_cache_container_count - m_cache.size();
	const unsigned int containers_to_request_now = containers_to_request_since_queue_update - containers_requested_so_far;

	// Request a few containers for the cache. Cache should be empty
	// around the time that we need to reload it.
	for(unsigned int i = 0; i < containers_to_request_now; ++i)
	{
		if(m_cache.empty())
		{
			break;
		}

		container_info_subset& current = *m_cache.begin();
		update_container_with_size(current.type, current.id);
		m_cache.pop_front();
	}
}

container_size_requestor::container_info_subset::container_info_subset(const sinsp_container_info& info)
{
	id = info.m_id;
	type = info.m_type;
}

container_size_requestor_runnable::container_size_requestor_runnable(sinsp_container_manager& mgr) :
   watchdog_runnable("container_size_requestor"),
   m_requestor(mgr, std::bind(&sinsp_container_manager::update_container_with_size,
			      &mgr,
			      std::placeholders::_1,
			      std::placeholders::_2))
{ }

// static
bool container_size_requestor_runnable::enabled()
{
	return c_enabled.get_value();
}

void container_size_requestor_runnable::do_run()
{
	while (heartbeat())
	{
		m_requestor.request(last_heartbeat_ms());
		Poco::Thread::sleep(1000 /*one second*/);
	}
}
