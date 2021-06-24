#pragma once

#include <analyzer.h>

/**
 * Parse k8s CIDR string into IP address and netmask
 *
 * @param[in] cidr in the form of <ip-address>/<netmask>
 * @param[out] netip network ordered ip-address
 * @param[out] netmask network ordered netmask
 *
 * @return true if parse was successful, false otherwise
 */

bool parse_k8s_cidr(const std::string& cidr, uint32_t* netip, uint32_t* netmask);

/**
 * Evaluates if and address is in IP CIDR range
 */
static inline bool is_addr_in_cidr(uint32_t netip, uint32_t netmask, uint32_t addr)
{
	return (addr & netmask) == netip;
}

class infrastructure_state;

class secure_netsec_cidr
{
public:
	secure_netsec_cidr() = default;

	explicit secure_netsec_cidr(const infrastructure_state* infra_state) { configure(infra_state); }

	void configure(const infrastructure_state* infra_state);

	bool is_configured() const { return m_k8s_cidrs_configured; }
	/**
	 * Parse k8s CIDR string into IP address and netmask
	 *
	 * @param[in] cidr in the form of <ip-address>/<netmask>
	 * @param[out] netip network ordered ip-address
	 * @param[out] netmask network ordered netmask
	 *
	 * @return true if parse was successful, false otherwise
	 */
	static bool parse_k8s_cidr(const std::string& cidr, uint32_t* netip, uint32_t* netmask)
	{
		return ::parse_k8s_cidr(cidr, netip, netmask);
	}

	/**
	 * Evaluates if and address is in IP CIDR range
	 */
	static inline bool is_addr_in_cidr(uint32_t netip, uint32_t netmask, uint32_t addr)
	{
		return (addr & netmask) == netip;
	}

	bool is_tuple_in_k8s_cidr(const ipv4tuple& tuple) const;

	bool is_addr_in_k8s_cidr(uint32_t addr) const;

	void clear();

private:
	bool m_k8s_cidrs_configured = false;

	uint32_t m_cluster_cidr_netip = 0;
	uint32_t m_cluster_cidr_netmask = 0;

	uint32_t m_service_cidr_netip = 0;
	uint32_t m_service_cidr_netmask = 0;
};