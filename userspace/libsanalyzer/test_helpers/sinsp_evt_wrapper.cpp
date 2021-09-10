#include "sinsp_evt_wrapper.h"

namespace test_helpers
{

sinsp_evt_wrapper::sinsp_evt_wrapper(sinsp_threadinfo& tinfo) :
	m_sinsp_threadinfo(tinfo),
	m_sinsp_event(new sinsp_evt()),
	m_scap_event(new scap_evt()),
	m_ppm_event_info(new ppm_event_info()),
	m_sinsp_fdinfo(new sinsp_fdinfo_t())
{
	m_sinsp_event->init(m_scap_event.get(),
			    m_ppm_event_info.get(),
			    &m_sinsp_threadinfo,
			    m_sinsp_fdinfo.get());
}

sinsp_evt *sinsp_evt_wrapper::get()
{
	return m_sinsp_event.get();
}

}
