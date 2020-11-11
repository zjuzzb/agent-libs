/**
 * @file
 *
 * Definition of container start count
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#pragma once
#ifndef CONTAINER_START_COUNT_H
#define CONTAINER_START_COUNT_H

#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>

#include "container_info.h"
#include "type_config.h"

/**
 * @brief Maintain count of containers started.
 *
 * After the agent analyzer module has started, this class
 * keeps count of the containers started. We maintain 2 counts:
 * 1.) Counts of all containers started on this host
 * 2.) Counts of containers started per k8s namespace
 *
 * This class provides a way to maintain these counts and 
 * also provides methods to populate them as prometheus metrics
 */
class container_start_count {
public:
	/**
	 * Provide a binding to a function that provides machine id info
	 * Ideally we would bind this to sinsp_configuration::get_machine_id
	 * We are forced to pass in a function delegate as this value is not
	 * yet available at the time of this class instantiation
	 */
	using machine_id_delegate = std::function<const std::string& (void)>;

	explicit container_start_count(const machine_id_delegate& machine_id);
	~container_start_count();

	/**
	 * on_new_container callback - provided to the container manager
	 *
	 * The container manager maintains a list of callbacks with the same
	 * name and signature and which it calls for every new container seen
	 * 
	 * Our callback here checks to see if it is a valid non-pod-sandbox container
	 * and if this container was created after the agent was created and if so
	 * adds this container count to the internal map
	 */
	void on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo);

	/**
	 * Return the number of containers started on this host
	 *
	 * @return uint32_t - Number of containers started on this host
	 */
	uint32_t get_host_container_counts() const;

	/**
	 * Return the number of containers started in a particular namespace
	 *
	 * @param ns [std::string] - The name of the namespace
	 *
	 * @return [uint32_t] - Number of containers started that belong to this namespace
	 */
	uint32_t get_container_counts_for_k8s_namespace(const std::string& ns) const;

	/**
	 * Feature flag that controls the enabled/disabled status of this feature
	 */
	static type_config<bool> c_enable_container_start_count;

private:
	machine_id_delegate get_machine_id_delegate;
	std::string m_machine_id;
	const int64_t m_start_time;
	std::mutex m_mutex;
	std::unordered_map<std::string, uint32_t> m_container_counts;
};

#endif // CONTAINER_COUNT_H
