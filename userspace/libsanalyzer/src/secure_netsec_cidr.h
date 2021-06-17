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

bool parse_k8s_cidr(const std::string& cidr, uint32_t *netip, uint32_t *netmask);

/**
 * Evaluates if and address is in IP CIDR range
 */
static inline bool is_addr_in_cidr(uint32_t netip, uint32_t netmask, uint32_t addr)
{
	return (addr & netmask) == netip;
}

