#include "container_start_count.h"
#include "analyzer.h"
#include "analyzer_utils.h"
#include "utils.h"
#include "config.h"
#include <common_logger.h>

COMMON_LOGGER();

type_config<bool> container_start_count::c_enable_container_start_count(
	false,
	"Enable or disable the container start count feature",
	"container_start_count",
	"enable");

container_start_count::container_start_count(const machine_id_delegate& machine_id_func)
	: get_machine_id_delegate(machine_id_func),
	  m_start_time(static_cast<int64_t>(get_epoch_utc_seconds_now()))
{}

container_start_count::~container_start_count() {}

void container_start_count::on_new_container(const sinsp_container_info& container_info,
					     sinsp_threadinfo* tinfo)
{
	if (container_info.is_pod_sandbox() || !container_info.is_successful())
	{
		// filter out k8s internal containers
		// Or if metadata fetch is not successful
		return;
	}

	// If the container was created before the agent start time, ignore it.
	// This means EVEN the agent container will not be counted towards this.
	if(container_info.m_created_time < m_start_time) {
		return;
	}

	// Get the mac id if it is empty.
	// This will be used to populate
	// the count for the entire host.
	if(m_machine_id.empty()) {
		m_machine_id = get_machine_id_delegate();
	}

	{
		// For now scope the lock. This might need to change
		// if and when on_new_container is called multi-threaded way
		std::unique_lock<std::mutex> lock(m_mutex);
		for (const auto& labels : container_info.m_labels)
		{
			if("io.kubernetes.pod.namespace" == labels.first)
			{
				// This is a k8s container in a namespace
				// Store the container count against the namespace
				++m_container_counts[labels.second];
				break;
			}
		}
		// Store the countainer count against the machine id as well.
		++m_container_counts[m_machine_id];
	}

	for(const auto& pr : m_container_counts) {
		LOG_INFO("Container_start_counts: Bucket_name: %s  , container_count: %d", pr.first.c_str(), pr.second);
	}
}

int container_start_count::get_host_container_counts() const
{
	auto map_iter = m_container_counts.find(m_machine_id);
	return (map_iter == m_container_counts.end() ? 0 : map_iter->second);
}

int container_start_count::get_container_counts_for_k8s_namespace(const std::string& namespc) const
{
	auto map_iter = m_container_counts.find(namespc);
	return (map_iter == m_container_counts.end() ? 0 : map_iter->second);
}
