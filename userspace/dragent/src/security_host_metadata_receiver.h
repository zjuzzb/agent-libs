/**
 * @file
 *
 * Interface to security_host_metadata_receiver.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

namespace draiosproto {
class orchestrator_events;
}

namespace dragent
{

/**
 * Interface to objects that can receive hosts metadata.
 */
class security_host_metadata_receiver
{
public:
	virtual ~security_host_metadata_receiver() = default;

	virtual void receive_hosts_metadata(const draiosproto::orchestrator_events& evts) = 0;
};

} // namespace dragent
