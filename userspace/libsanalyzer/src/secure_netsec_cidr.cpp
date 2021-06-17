#include "common_logger.h"
#include "secure_netsec_cidr.h"

COMMON_LOGGER();

bool parse_k8s_cidr(const std::string& cidr, uint32_t *netip, uint32_t *netmask)
{
	if (!cidr.length()) // the default value is empty
	{
		return false;
	}

	try {
		auto split_idx = cidr.find("/");
		if (split_idx <= 0 || split_idx > cidr.length())
		{
			LOG_ERROR("CIDR notation <%s> doesn't contain a valid ip/netmask: a valid CIDR must be in the form of 100.64.0.0/24",
				  cidr.c_str());
			return false;
		}
		auto netip_str = cidr.substr(0, split_idx);
		auto netmask_str = cidr.substr(split_idx + 1, cidr.length() - split_idx + 1);
		struct in_addr addr;

		if (inet_aton(netip_str.c_str(), &addr) == 0)
		{
			LOG_ERROR("CIDR notation <%s> doesn't contain a valid ip address (%s)",
				  cidr.c_str(), netip_str.c_str());
			return false;
		}
		*netip = htonl(addr.s_addr);

		auto netmask_int = std::stoul(netmask_str.c_str(), 0, 10);
		if (netmask_int < 0 || netmask_int > 32)
		{
			LOG_ERROR("CIDR notation <%s> doesn't contain a valid netmask (%s)",
				  cidr.c_str(), netmask_str.c_str());
			return false;
		}

		uint32_t host_bits = 32 - netmask_int;
		uint32_t host_mask = (1 << host_bits) - 1;
		*netmask = ~host_mask;
	}
	catch (const std::exception &e)
	{
		LOG_ERROR("error while parsing of CIDR <%s>: %s",
			  cidr.c_str(), e.what());
		return false;
	}

	LOG_INFO("Kubernetes CIDR configuration %s has been successfully configured",
		 cidr.c_str());

	return true;
}
