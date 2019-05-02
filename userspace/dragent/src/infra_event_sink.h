/**
 * @file
 *
 * Interface to infra_event_sink.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace dragent
{

/**
 * Interface to an object to which infra events can be pushed.
 */
class infra_event_sink
{
public:
	virtual ~infra_event_sink() = default;

	virtual void push_infra_event(uint64_t ts,
	                              uint64_t tid,
	                              const std::string& source,
	                              const std::string& name,
	                              const std::string& description,
	                              const std::string& scope) = 0;
};

}
