#include "sinsp.h"
#include "sinsp_int.h"

sisnsp_event_buff::sisnsp_event_buff(sinsp* inspector) :
	m_event(inspector)
{
	m_event.m_pevt = (scap_evt*)m_data;
}

void sisnsp_event_buff::store(sinsp_evt* evt)
{
	uint32_t elen;

	//
	// Make sure the event is going to fit
	//
	elen = scap_event_getlen(evt->m_pevt);

	if(elen > SP_STORAGE_EVT_BUF_SIZE)
	{
		ASSERT(false);
		return;
	}

	memcpy(m_data, evt->m_pevt, elen);

	//
	// Initialize the event
	//
	m_event.init();
}
