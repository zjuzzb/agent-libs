#pragma once

namespace secure
{
class K8SCommunicationSummary;
}

class secure_netsec_data_ready_handler
{
public:
	virtual ~secure_netsec_data_ready_handler() = default;
	/** secure_netsec_data_ready is an analyzer interface provided to secure_network
	    in order to call secure_netsec_handler
	    \param ts
	    \param netsec_summary */
	virtual void secure_netsec_data_ready(
	    uint64_t ts,
	    const secure::K8SCommunicationSummary* netsec_summary) = 0;
};


