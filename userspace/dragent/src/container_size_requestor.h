#pragma once

#include <deque>
#include <container.h>
#include "running_state_runnable.h"

class sinsp_container_info;

/**
 * Class which gets a list of containers and slowly requests the size for
 * each from the container manager. Since the size request is potentially
 * time-consuming and cpu-intensive, this helps to spread out that load.
 */
class container_size_requestor
{
public:
	using update_delegate =  std::function<void(sinsp_container_type type, const std::string& container_id)>;

	container_size_requestor(const sinsp_container_manager &mgr,
				 const update_delegate& delegate);

	/**
	 * If enough time has passed, send requests for the container size to be
	 * updated. This function expected to be called periodically.
	 */
	void request(const uint64_t uptime_ms);

	/**
	 * Return the size of the cache
	 */
	size_t cache_size() const
	{
		return m_cache.size();
	}
private:
	void load_container_subset_cache(const uint64_t uptime_ms);
	bool is_time_to_update_cache(const uint64_t uptime_ms);
	void send_requests(const uint64_t uptime_ms);

	struct container_info_subset
	{
		container_info_subset(const sinsp_container_info &info);

		std::string id;
		sinsp_container_type type;
	};
	std::deque<container_info_subset> m_cache;

	const sinsp_container_manager &m_manager;
	update_delegate update_container_with_size;
	uint64_t m_last_cache_update_ms;
	uint64_t m_original_cache_container_count;

};

/**
 * Runnable to periodically call into the container_size_requestor.
 */
class container_size_requestor_runnable : public dragent::running_state_runnable
{
public:
	container_size_requestor_runnable(sinsp_container_manager& mgr);

	/**
	 * Whether this is enabled via the configuration parameters. This allows the
	 * client to not bother starting the runnable.
	 */
	static bool enabled();

private:
	void do_run() override;

	container_size_requestor m_requestor;

};

