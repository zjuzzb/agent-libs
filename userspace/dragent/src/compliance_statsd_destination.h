#pragma once

#include "draios.proto.h"

namespace dragent
{

/**
 * Destination to send compliance statsd metrics to (Interface
 * Segregation Principle).
 */
class compliance_statsd_destination
{
public:
	virtual void send_compliance_statsd(const google::protobuf::RepeatedPtrField<std::string>&) = 0;
};

}
