#pragma once

#include <string>

/**
 * An abstract class providing methods used by promscrape
 * to fetch infromation from infrastructure state.
 */
class prom_infra_iface
{
public:
	using kind_uid_t = std::pair<std::string, std::string>;

	/**
	 * Fetch the cluster name from the underlying orchestration.
	 */
	virtual std::string get_k8s_cluster_name() = 0;

	/**
	 * Fetch the machine id from the underlying orchestration.
	 */
	virtual std::string get_machine_id() const = 0;


	/**
	 * Fetch the container ID based on the given pod kind and uid
	 * and container name.
	 *
	 * @param p_uid Pair of Pod kind and its UID.
	 * @param pod_container_name Container name
	 *
	 * @returns Container ID
	 */
	virtual std::string get_container_id_from_k8s_pod_and_k8s_pod_name(const kind_uid_t& p_uid, const std::string &pod_container_name) const = 0;


	/**
	 * Return if the agent is running in the given host for the
	 * given pod kind and uid.
	 *
	 * @param ip Host IP/name
	 * @param uid Pair of Pod kind and its UID
	 *
	 * @returns true if the ip matches, false otherwise.
	 */
	virtual bool find_local_ip(const std::string &ip, kind_uid_t *uid) const = 0;

	/**
	 * Fetch the cluster ID from the underlying orchestration.
	 */
	virtual std::string get_k8s_cluster_id() const = 0;
};
