#pragma once

#include "event_source.h"
#include "running_state_runnable.h"
#include "sinsp.h"

class sinsp_event_source : public event_source,
                           public libsinsp::event_processor,
                           public dragent::running_state_runnable
{
public:  // ctor/dtor
	sinsp_event_source(bool static_container = false,
	                   const std::string& static_id = "",
	                   const std::string& static_name = "",
	                   const std::string& static_image = "");
	~sinsp_event_source() {}

public:  // functions from event_source
	void start() override;

public:  // functions from libsinsp::event_processor
	void on_capture_start() override {}
	void process_event(sinsp_evt* evt, libsinsp::event_return rc) override;
	void add_chisel_metric(statsd_metric* metric) override {}

public:  // functions from dragent::running_state_runnable
	void do_run() override;

public:  // other functions
	/**
	 * provides a pointer to the sinsp backing this event source. This is a leaky
	 * abstraction, but a temporary necessity given the number of components that
	 * are directly reliant on it
	 */
	sinsp* get_sinsp();

private:
	sinsp m_inspector;
	volatile bool m_shutdown;
};
