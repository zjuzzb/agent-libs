#include "common_logger.h"
#include "running_state.h"
#include "sinsp_event_source.h"
#include "type_config.h"
#include "library_configs.h"

#include <unistd.h>

namespace
{
COMMON_LOGGER();
type_config<uint64_t> c_sinsp_poll_delay_us(
    250 * 1000,
    "set the delay when there are no events to process, in us",
    "sinsp_event_source",
    "delay_us");
}  // namespace

sinsp_event_source::sinsp_event_source(bool static_container,
                                       const std::string static_id,
                                       const std::string static_name,
                                       const std::string static_image)
    : dragent::running_state_runnable("sinsp_event_source"),
      m_inspector(static_container, static_id, static_name, static_image),
      m_shutdown(false)
{
	m_inspector.register_external_event_processor(*this);
	sinsp_library_config::init_library_configs(m_inspector);
}

sinsp* sinsp_event_source::get_sinsp()
{
	return &m_inspector;
}

void sinsp_event_source::start()
{
	m_inspector.open("");
	m_inspector.start_dropping_mode(1);
}

void sinsp_event_source::process_event(sinsp_evt* evt, libsinsp::event_return rc)
{
	if (rc == libsinsp::EVENT_RETURN_NONE)
	{
		LOG_DEBUG("processing event");
		event_source::process_event(evt);
	}
}

void sinsp_event_source::do_run()
{
	while (!dragent::running_state::instance().is_terminated())
	{
		// So this is a little weird. The event comes back two ways:
		// 1) since we registered ourselves as an event processor, sinsp calls
		//    process_event as a part of normal processing
		// 2) sinsp also returns the event populated in the passed in return param
		//
		// So we'll just use the call-back and just....ignore....the returned event, since
		// it's the same.
		sinsp_evt* ev;
		int32_t res = m_inspector.next(&ev);
		if (res != SCAP_SUCCESS)
		{
			LOG_DEBUG("Scap returned %d to next", res);
			usleep(c_sinsp_poll_delay_us.get_value());
		}
	}
}
