#pragma once

#include "sinsp.h"

namespace secure_helper
{
enum ip_proto_l4
{
	IP_PROTO_INVALID = 0,
	IP_PROTO_ICMP = 1,
	IP_PROTO_TCP = 6,
	IP_PROTO_UDP = 17
};

uint8_t scap_l4_to_ip_l4(const uint8_t scap_l4);
bool is_valid_tuple(const ipv4tuple tuple);
bool is_localhost(const ipv4tuple tuple);
} // secure_helper
