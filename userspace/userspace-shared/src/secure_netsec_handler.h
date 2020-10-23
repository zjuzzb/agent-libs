#pragma once

namespace secure
{
	class K8SCommunicationSummary;
}

class secure_netsec_handler
{
public:
	virtual void secure_netsec_data_ready(uint64_t ts_ns, const secure::K8SCommunicationSummary *k8s_communication_summary) = 0;
};

/**
 * virtual class that defines the API invoked when secure audit data is ready. Courtesy default
 * implementations are provided.
 */
class null_secure_netsec_handler : public secure_netsec_handler
{
public:
	void secure_netsec_data_ready(uint64_t ts_ns, const secure::K8SCommunicationSummary *k8s_communication_summary) override
	{
	}
};
