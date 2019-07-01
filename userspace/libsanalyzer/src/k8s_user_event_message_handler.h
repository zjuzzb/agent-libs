#pragma once

#ifndef CYGWING_AGENT

#include <string>
#include "sdc_internal.grpc.pb.h"
#include "user_event.h"
#include "coclient.h"
#include "analyzer_utils.h"

class infrastructure_state;

/**
 * class that acquires k8s user events and sends them to a glogger stream
 * attached to  sinsp_logger::SEV_EVT_WARNING or sinsp_logger::SEV_EVT_INFORMATION
 *
 * after initialization, users should set the machine ID and user event queue
 * and then call "subscribe"
 *
 *
 */
class k8s_user_event_message_handler
{
public:
	const uint64_t default_connect_interval = 60LL * 1000 * 1000 * 1000;

	/**
	 * @param refresh_interval the interval to wait before processing the events.
	 *                         This helps batch events. effectively a passthrough
	 * @param install_prefix  root dir of the dragent instance. Ultimately where
	 *                        we'll locate the streams for coclient. mostly
	 *                        a passthru at this level
	 */
	k8s_user_event_message_handler(uint64_t refresh_interval,
		std::string install_prefix, infrastructure_state *infra_state);
	~k8s_user_event_message_handler();

	/**
	 * @brief subscribe start listening to k8s event and sending them to appropriate channel
	 * @param timeout_s timeout before attempting to reconnect to k8s server
	 * @param flt filter to ensure only certain k8s events get through
	 */
	void subscribe(uint64_t timeout_s, user_event_filter_t::ptr_t flt);

	/**
	 * @breif imediately process k8s events using ts as the current time
	 */
	void refresh(uint64_t ts);

	/**
	 * @brief sets the machine ID to be used in any events created
	 */
	void set_machine_id(const std::string &machine_id)
	{
		m_machine_id = machine_id;
	}

	/**
	 * @brief sets the queue that the events should be sent to. if unset, no
	 *        events will be processed
	 */
	void set_user_event_queue(user_event_queue::ptr_t user_event_queue)
	{
		m_user_event_queue = user_event_queue;
		m_event_queue_set = true;
	}

	/**
	 * @brief gets teh current number of events which have been processed since the last queue reset
	 */
	size_t get_user_event_count() const
	{
		if (!m_user_event_queue) {
			ASSERT(false);
			return 0;
		}
		return m_user_event_queue->count();
	}

private:
	void handle_event(sdc_internal::k8s_user_event *evt, infrastructure_state *);
	void connect(uint64_t ts = sinsp_utils::get_current_time_ns());
	void reset_connection();
	std::string translate_name(const std::string &reason) const;


	bool subscribed() const { return m_subscribed; }
private:
	std::string m_machine_id;
	coclient m_coclient;
	coclient::response_cb_t m_callback;

	bool m_subscribed;   // True if we're supposed to connect to k8s
	bool m_connected;    // True if we have an active RPC connection

	user_event_filter_t::ptr_t m_event_filter;
	bool m_event_queue_set = false;
	user_event_queue::ptr_t m_user_event_queue;

	bool m_event_limit_exceeded;

	run_on_interval m_refresh_interval;
	run_on_interval m_connect_interval;

	std::unordered_map<std::string, std::string> m_name_translation;
	infrastructure_state *m_infra_state;

	friend class test_helper;
};

#endif
