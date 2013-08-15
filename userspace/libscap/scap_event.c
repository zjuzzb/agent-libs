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

uint32_t scap_event_getlen(scap_evt* e)
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

/*
int32_t scap_param_to_str(IN evt_param_info* param, OUT char* str, uint32_t strlen)
{
	switch(param->type)
	{
	case PT_INT8:
		ASSERT(param->len == sizeof(int8_t));
		snprintf(str, strlen, "%d", (int32_t)*(int8_t*)param->val);
		return SCAP_SUCCESS;
	case PT_INT16:
		ASSERT(param->len == sizeof(int16_t));
		snprintf(str, strlen, "%d", (int32_t)*(int16_t*)param->val);
		return SCAP_SUCCESS;
	case PT_INT32:
		ASSERT(param->len == sizeof(int32_t));
		snprintf(str, strlen, "%d", *(int32_t*)param->val);
		return SCAP_SUCCESS;
	case PT_INT64:
		ASSERT(param->len == sizeof(int64_t));
		snprintf(str, strlen, "%d", (int32_t)*(int64_t*)param->val);
		return SCAP_SUCCESS;
	case PT_UINT8:
		ASSERT(param->len == sizeof(uint8_t));
		snprintf(str, strlen, "%d", (uint32_t)*(uint8_t*)param->val);
		return SCAP_SUCCESS;
	case PT_UINT16:
		ASSERT(param->len == sizeof(uint16_t));
		snprintf(str, strlen, "%d", (uint32_t)*(uint16_t*)param->val);
		return SCAP_SUCCESS;
	case PT_UINT32:
	case PT_ERRNO:
		ASSERT(param->len == sizeof(uint32_t));
		snprintf(str, strlen, "%d", *(uint32_t*)param->val);
		return SCAP_SUCCESS;
	case PT_UINT64:
		ASSERT(param->len == sizeof(uint64_t));
		snprintf(str, strlen, "%d", (uint32_t)*(int64_t*)param->val);
		return SCAP_SUCCESS;
	case PT_CHARBUF:
		snprintf(str, strlen, "%s", param->val);
		return SCAP_SUCCESS;
	case PT_BYTEBUF:
		snprintf(str, strlen, "%u", param->len);
		return SCAP_SUCCESS;
	case PT_SOCKTUPLE:
		if(param->val[0] == AF_UNIX)
		{
			snprintf(str, strlen, "%"PRIx64"->%"PRIx64" %s", *(uint64_t*)(param->val + 1),
			         *(uint64_t*)(param->val + 9),
			         param->val + 17);
		}
		else if(param->val[0] == AF_INET)
		{
			ASSERT(param->len == 1 + 4 + 2 + 4 + 2);
			snprintf(str, strlen, "%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
			         (unsigned int)param->val[1],
			         (unsigned int)param->val[2],
			         (unsigned int)param->val[3],
			         (unsigned int)param->val[4],
			         *(uint16_t*)(param->val+5),
			         (unsigned int)param->val[7],
			         (unsigned int)param->val[8],
			         (unsigned int)param->val[9],
			         (unsigned int)param->val[10],
			         *(uint16_t*)(param->val+11));
		}
		else
		{
			snprintf(str, strlen, "family %d", (int)param->val[0]);
		}
		return SCAP_SUCCESS;
	default:
		ASSERT(false);
		snprintf(str, strlen, "(n.a.)");
		return SCAP_FAILURE;
	}
}
*/

/*
struct scap_threadinfo* scap_event_getprocinfo(scap_t* handle, scap_evt* e)
{
	struct scap_threadinfo* pi;

	HASH_FIND_INT64(handle->m_proclist, &(e->tid), pi);
	if(pi == NULL)
	{
		if(e->type == PPME_PROC_EXIT)
		{
			return (scap_threadinfo*)&(handle->m_fake_kernel_proc);
		}
		else
		{
			//
			// This indicates a failure in the proc management infrastructure
			//
//printf("process not found %llu (%u)\n", e->tid, e->type);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "process not found %llu\n", e->tid);
			ASSERT(false);
			return NULL;
		}
	}

	return (scap_threadinfo*)pi;
}
*/

/*
char* scap_event_getparam_as_str(scap_evt* e, uint32_t paramid)
{
	char str[512];	// XXX properly size this
	evt_param_info param;

	if(scap_event_getparam(e, paramid, &param) == SCAP_SUCCESS)
	{
		scap_param_to_str(&param, str, sizeof(str)/sizeof(str[0]));
		return str;
	}
	else
	{
		return "(n.a.)";
	}
}
*/
