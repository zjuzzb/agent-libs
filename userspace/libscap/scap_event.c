#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif // _WIN32

#include "scap.h"
#include "scap-int.h"

// This is defined in the driver
extern const struct ppm_event_info g_event_info[];
extern const struct ppm_syscall_desc g_syscall_info_table[];

//
// Get the event info table
//
const struct ppm_event_info* scap_get_event_info_table()
{
	return g_event_info;
}

//
// Get the syscall info table
//
const struct ppm_syscall_desc* scap_get_syscall_info_table()
{
	return g_syscall_info_table;
}

uint32_t scap_event_compute_len(scap_evt* e)
{
	uint32_t j;
	uint32_t res = 0;
	uint16_t* lens = (uint16_t*)((char*)e + sizeof(struct ppm_evt_hdr));

	ASSERT(e->type < PPM_EVENT_MAX);

	for(j = 0; j < g_event_info[e->type].nparams; j++)
	{
		res += lens[j];
	}

	res += g_event_info[e->type].nparams * sizeof(uint16_t) + sizeof(struct ppm_evt_hdr);

#ifdef PPM_ENABLE_SENTINEL
	res += sizeof(uint32_t);
#endif

	return res;
}

uint32_t scap_event_getlen(scap_evt* e)
{
	return e->len;
}

uint64_t scap_event_get_num(scap_t* handle)
{
	return handle->m_evtcnt;
}

uint64_t scap_event_get_ts(scap_evt* e)
{
	return e->ts;
}

uint16_t scap_event_get_type(scap_evt* e)
{
	return e->type;
}

#ifdef PPM_ENABLE_SENTINEL
uint32_t scap_event_get_sentinel_begin(scap_evt* e)
{
	return e->sentinel_begin;
}
#endif

const char* scap_event_get_name(scap_evt* e)
{
	return g_event_info[e->type].name;
}

ppm_event_category scap_event_get_category(scap_evt* e)
{
	return g_event_info[e->type].category;
}

const struct ppm_event_info* scap_event_getinfo(scap_evt* e)
{
	return &(g_event_info[e->type]);
}

event_direction scap_event_get_direction(scap_evt* e)
{
	return (event_direction)(e->type & PPME_DIRECTION_FLAG);
}

int64_t scap_event_get_tid(scap_evt* e)
{
	return e->tid;
}

uint32_t scap_event_getnumparams(scap_evt* e)
{
	ASSERT(e->type < PPM_EVENT_MAX);

	return g_event_info[e->type].nparams;
}

int32_t scap_event_getparam(scap_evt* e, uint32_t paramid, OUT evt_param_info* param)
{
	ASSERT(e->type < PPM_EVENT_MAX);

	if(paramid < g_event_info[e->type].nparams)
	{
		uint32_t j;
		uint16_t* lens = (uint16_t*)((char*)e + sizeof(struct ppm_evt_hdr));
		char* valptr = (char*)lens + g_event_info[e->type].nparams * sizeof(uint16_t);

		param->name = g_event_info[e->type].params[paramid].name;
		param->type = g_event_info[e->type].params[paramid].type;
		param->len = lens[paramid];

		for(j = 0; j < paramid; j++)
		{
			valptr += lens[j];
		}

		param->val = valptr;

		return SCAP_SUCCESS;
	}
	else
	{
		return SCAP_ILLEGAL_INPUT;
	}
}
