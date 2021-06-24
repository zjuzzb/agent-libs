#include "secure_netsec_cidr.h"

#include "analyzer.h"
#include "common_logger.h"
#include "infrastructure_state.h"
#include "secure_netsec.h"

COMMON_LOGGER();

bool parse_k8s_cidr(const std::string& cidr, uint32_t* netip, uint32_t* netmask)
{
	if (!cidr.length())  // the default value is empty
	{
		return false;
	}

	try
	{
		auto split_idx = cidr.find("/");
		if (split_idx <= 0 || split_idx > cidr.length())
		{
			LOG_ERROR(
			    "CIDR notation <%s> doesn't contain a valid ip/netmask: a valid CIDR must be in "
			    "the form of 100.64.0.0/24",
			    cidr.c_str());
			return false;
		}
		auto netip_str = cidr.substr(0, split_idx);
		auto netmask_str = cidr.substr(split_idx + 1, cidr.length() - split_idx + 1);
		struct in_addr addr;

		if (inet_aton(netip_str.c_str(), &addr) == 0)
		{
			LOG_ERROR("CIDR notation <%s> doesn't contain a valid ip address (%s)",
			          cidr.c_str(),
			          netip_str.c_str());
			return false;
		}
		*netip = htonl(addr.s_addr);

		auto netmask_int = std::stoul(netmask_str.c_str(), 0, 10);
		if (netmask_int < 0 || netmask_int > 32)
		{
			LOG_ERROR("CIDR notation <%s> doesn't contain a valid netmask (%s)",
			          cidr.c_str(),
			          netmask_str.c_str());
			return false;
		}

		uint32_t host_bits = 32 - netmask_int;
		uint32_t host_mask = (1 << host_bits) - 1;
		*netmask = ~host_mask;
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("error while parsing of CIDR <%s>: %s", cidr.c_str(), e.what());
		return false;
	}

	LOG_INFO("Kubernetes CIDR configuration %s has been successfully configured", cidr.c_str());

	return true;
}

void secure_netsec_cidr::configure(const infrastructure_state* infra_state)
{
	if (m_k8s_cidrs_configured)
	{
		return;
	}

	bool k8s_cluster_cidr_configured = false;
	bool k8s_service_cidr_configured = false;

	/* Kubernetes CIDR */
	if (secure_netsec::c_secure_netsec_cluster_cidr.is_set_in_config())
	{
		k8s_cluster_cidr_configured =
		    parse_k8s_cidr(secure_netsec::c_secure_netsec_cluster_cidr.get_value(),
		                   &m_cluster_cidr_netip,
		                   &m_cluster_cidr_netmask);
	}

	if (secure_netsec::c_secure_netsec_service_cidr.is_set_in_config())
	{
		k8s_service_cidr_configured =
		    parse_k8s_cidr(secure_netsec::c_secure_netsec_service_cidr.get_value(),
		                   &m_service_cidr_netip,
		                   &m_service_cidr_netmask);
	}

	m_k8s_cidrs_configured = k8s_cluster_cidr_configured && k8s_service_cidr_configured;

	// If not set in the config, and not already discovered, try
	// and update Cluster/Service CIDR with what's in the
	// infrastructure_state
	if (!m_k8s_cidrs_configured && infra_state != nullptr && infra_state->is_k8s_cidr_discovered())
	{
		k8s_cluster_cidr_configured = k8s_cluster_cidr_configured ||
		                              parse_k8s_cidr(infra_state->get_command_k8s_cluster_cidr(),
		                                             &m_cluster_cidr_netip,
		                                             &m_cluster_cidr_netmask);

		k8s_service_cidr_configured = k8s_service_cidr_configured ||
		                              parse_k8s_cidr(infra_state->get_command_k8s_service_cidr(),
		                                             &m_service_cidr_netip,
		                                             &m_service_cidr_netmask);

		m_k8s_cidrs_configured = k8s_cluster_cidr_configured && k8s_service_cidr_configured;
	}

	if (m_k8s_cidrs_configured)
	{
		LOG_INFO("Kubernetes Cluster/Service CIDR has been discovered");
	}
}

bool secure_netsec_cidr::is_addr_in_k8s_cidr(uint32_t addr) const
{
	auto htonl_addr = htonl(addr);
	return (is_addr_in_cidr(m_cluster_cidr_netip, m_cluster_cidr_netmask, htonl_addr) ||
	        is_addr_in_cidr(m_service_cidr_netip, m_service_cidr_netmask, htonl_addr));
}

bool secure_netsec_cidr::is_tuple_in_k8s_cidr(const ipv4tuple& tuple) const
{
	return is_addr_in_k8s_cidr(tuple.m_fields.m_sip) || is_addr_in_k8s_cidr(tuple.m_fields.m_dip);
}

void secure_netsec_cidr::clear()
{
	m_k8s_cidrs_configured = false;

	m_cluster_cidr_netip = 0;
	m_cluster_cidr_netmask = 0;

	m_service_cidr_netip = 0;
	m_service_cidr_netmask = 0;
}
