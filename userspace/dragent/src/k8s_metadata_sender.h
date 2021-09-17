#pragma once

#include "analyzer.h"
#include "feature_manager.h"
#include "protocol_handler.h"

class k8s_metadata_sender : public feature_base
{
private:
	static k8s_metadata_sender* s_k8s_metadata_sender;

public:
	k8s_metadata_sender();

	static k8s_metadata_sender& instance();

	/**
	 * Initialize the instance
	 *
	 * @param analyzer sinsp analyzer from which we can detect if we are delegated
	 * @param protocol_handler protocol handler used to send the message
	 */
	void init(sinsp_analyzer* analyzer, protocol_handler* protocol_handler);

	/**
	 * Send the metadata message as long as the instance is initialized and the
	 * agent is delegated.
	 *
	 * @param now Current timestamp in nanoseconds
	 */
	void send_k8s_metadata_message(uint64_t now);

	/**
	 * Send the metadata message as long as c_k8s_metadata_interval seconds
	 * have elapsed since the last message was sent.
	 *
	 * @param now Current timestamp in nanoseconds
	 */
	void send_k8s_metadata_message_on_interval(uint64_t now);

	/**
	 * Set the analyzer member from which we can detect if we are delegated
	 * @param analyzer sinsp analyzer
	 */
	void set_analyzer(sinsp_analyzer* analyzer) { m_analyzer = analyzer; };

	/**
	 * Set the protocol_handler member used to send the message
	 * @param protocol_handler protocol handler
	 */
	void set_protocol_handler(protocol_handler* protocol_handler)
	{
		m_protocol_handler = protocol_handler;
	};

private:
	sinsp_analyzer* m_analyzer;
	protocol_handler* m_protocol_handler;
	unique_ptr<run_on_interval> m_interval;
};
