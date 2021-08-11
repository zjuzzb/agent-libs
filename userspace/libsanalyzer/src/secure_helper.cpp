#include "secure_helper.h"

using namespace secure_helper;

static const std::unordered_map<uint8_t, uint8_t> l4_proto_scap_to_ip_map = {
	{SCAP_L4_UNKNOWN, IP_PROTO_INVALID},
	{SCAP_L4_NA, IP_PROTO_INVALID},
	{SCAP_L4_TCP, IP_PROTO_TCP},
	{SCAP_L4_UDP, IP_PROTO_UDP},
	{SCAP_L4_ICMP, IP_PROTO_ICMP},
	{SCAP_L4_RAW, IP_PROTO_INVALID}};

uint8_t secure_helper::scap_l4_to_ip_l4(const uint8_t scap_l4)
{
	auto it = l4_proto_scap_to_ip_map.find(scap_l4);
	if (it != l4_proto_scap_to_ip_map.end())
	{
		return it->second;
	}
	else
	{
		return IP_PROTO_INVALID;
	}
}

bool secure_helper::is_valid_tuple(const ipv4tuple tuple)
{
	// check if connection is not 0.0.0.0:0 -> 0.0.0.0:0
	// this could be caused by agent in subsampling mode
	// if so we simply discard this
	if (tuple.m_fields.m_sip == 0 && tuple.m_fields.m_dip == 0 &&
	    tuple.m_fields.m_sport == 0 && tuple.m_fields.m_dport == 0)
	{
		return false;
	}

	return true;
}

bool secure_helper::is_localhost(const ipv4tuple tuple)
{
	auto localhost = ntohl(INADDR_LOOPBACK); // 127.0.0.1 in host byte order
	if (tuple.m_fields.m_sip == localhost || tuple.m_fields.m_dip == localhost)
	{
		return true;
	}

	return false;
}
