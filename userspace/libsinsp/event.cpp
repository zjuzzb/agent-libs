#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/socket.h>
#include <algorithm>
#endif

#include "sinsp.h"
#include "sinsp_int.h"

#include "../libscap/scap.h"

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt_param implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_evt_param::init(char *valptr, uint16_t len)
{
	m_val = valptr;
	m_len = len;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_evt::sinsp_evt()
{
	m_params_loaded = false;
	m_tinfo = NULL;
#ifdef _DEBUG
	m_filtered_out = false;
#endif
}

sinsp_evt::~sinsp_evt()
{
}


sinsp_evt::sinsp_evt(sinsp *inspector)
{
	m_inspector = inspector;
	m_params_loaded = false;
	m_tinfo = NULL;
#ifdef _DEBUG
	m_filtered_out = false;
#endif
}

void sinsp_evt::init()
{
	m_params_loaded = false;
	m_info = scap_event_getinfo(m_pevt);
	m_tinfo = NULL;
	m_fdinfo = NULL;
	m_iosize = 0;
}

void sinsp_evt::init(uint8_t *evdata, uint16_t cpuid)
{
	m_params_loaded = false;
	m_pevt = (scap_evt *)evdata;
	m_info = scap_event_getinfo(m_pevt);
	m_tinfo = NULL;
	m_fdinfo = NULL;
	m_iosize = 0;
	m_cpuid = cpuid;
	m_evtnum = 0;
}

uint64_t sinsp_evt::get_num()
{
	return m_evtnum;
}

int16_t sinsp_evt::get_cpuid()
{
	return m_cpuid;
}

uint16_t sinsp_evt::get_type()
{
	return m_pevt->type;
}

ppm_event_flags sinsp_evt::get_flags()
{
	return m_info->flags;
}

uint64_t sinsp_evt::get_ts()
{
	return m_pevt->ts;
}

const char *sinsp_evt::get_name()
{
	return m_info->name;
}

event_direction sinsp_evt::get_direction()
{
	return (event_direction)(m_pevt->type & PPME_DIRECTION_FLAG);
}

int64_t sinsp_evt::get_tid()
{
	return m_pevt->tid;
}

void sinsp_evt::set_iosize(uint32_t size)
{
	m_iosize = size;
}

uint32_t sinsp_evt::get_iosize()
{
	return m_iosize;
}

sinsp_threadinfo* sinsp_evt::get_thread_info(bool query_os_if_not_found)
{
	if(NULL != m_tinfo)
	{
		return m_tinfo;
	}

	return m_inspector->get_thread(m_pevt->tid, query_os_if_not_found);
}

uint32_t sinsp_evt::get_num_params()
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	return m_params.size();
}

sinsp_evt_param *sinsp_evt::get_param(uint32_t id)
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	return &(m_params[id]);
}

const char *sinsp_evt::get_param_name(uint32_t id)
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	ASSERT(id < m_info->nparams);

	return m_info->params[id].name;
}

const struct ppm_param_info* sinsp_evt::get_param_info(uint32_t id)
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	ASSERT(id < m_info->nparams);

	return &(m_info->params[id]);
}

uint32_t binary_buffer_to_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen)
{
	uint32_t j;
	uint32_t k = 0;

	if(dstlen == 0)
	{
		ASSERT(false);
		return 0;
	}

	if(srclen == 0)
	{
		*dst = 0;
		return 0;
	}

	for(j = 0; j < srclen; j++)
	{
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1)
		{
			dst[k - 1] = 0;
			return k - 1;
		}

		if(isprint((int)(uint8_t)src[j]))
		{
			switch(src[j])
			{
			case '"':
			case '\\':
				dst[k++] = '\\';
				break;
			default:
				break;
			}

			dst[k] = src[j];
		}
		else
		{
			dst[k] = '.';
		}

		k++;
	}

	dst[k] = 0;
	return k;
}

uint32_t strcpy_sanitized(char *dest, char *src, uint32_t dstsize)
{
	volatile char* tmp = (volatile char *)dest;
	size_t j = 0;
	g_invalidchar ic;

	while(j < dstsize)
	{
		if(!ic(*src))
		{
			*tmp = *src;
			tmp++;
			j++;
		}

		if(*src == 0)
		{
			*tmp = 0;
			return j + 1;
		}

		src++;
	}

	//
	// In case there wasn't enough space, null-termninate the destination
	//
	if(dstsize)
	{
		dest[dstsize - 1] = 0;
	}

	return dstsize;
}

const char* sinsp_evt::get_param_as_str(uint32_t id, OUT const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	ASSERT(id < m_info->nparams);
/*
	if(m_evtnum == 6055)
	{
		int a = 0;
	}
*/
	//
	// Make sure the params are actually loaded
	//
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	//
	// Reset the resolved string
	//
	*resolved_str = m_resolved_paramstr_storage;
	m_resolved_paramstr_storage[0] = 0;

	//
	// Get the parameter
	//
	sinsp_evt_param *param = &(m_params[id]);

	switch(m_info->params[id].type)
	{
	case PT_INT8:
		ASSERT(param->m_len == sizeof(int8_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId8, *(int8_t *)param->m_val);
		break;
	case PT_INT16:
		ASSERT(param->m_len == sizeof(int16_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId16, *(int16_t *)param->m_val);
		break;
	case PT_INT32:
		ASSERT(param->m_len == sizeof(int32_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId32, *(int32_t *)param->m_val);
		break;
	case PT_INT64:
		ASSERT(param->m_len == sizeof(int64_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId64, *(int64_t *)param->m_val);
		break;
	case PT_FD:
	{
		int64_t fd;
		ASSERT(param->m_len == sizeof(int64_t));

		fd = *(int64_t*)param->m_val;

		//
		// Add the fd number
		//
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId64, fd);

		sinsp_threadinfo* tinfo = get_thread_info();
		if(tinfo == NULL)
		{
			//
			// no thread. Definitely can't resolve the fd, just return the number
			//
			break;
		}

		if(fd >= 0)
		{
			sinsp_fdinfo *fdinfo = tinfo->get_fd(fd);
			if(fdinfo)
			{
				char tch = fdinfo->get_typechar();

				//
				// Make sure we remove invalid characters from the resolved name
				//
				string sanitized_str = fdinfo->m_name;
				sanitized_str.erase(remove_if(sanitized_str.begin(), sanitized_str.end(), g_invalidchar()), sanitized_str.end());

				snprintf(m_resolved_paramstr_storage,
				         sizeof(m_resolved_paramstr_storage),
				         "%c%s", tch, sanitized_str.c_str());
			}
		}
		else
		{
			//
			// Resolve this as an errno
			//
			string errstr(sinsp_utils::errno_to_str((int32_t)fd));
			if(errstr != "")
			{
				snprintf(m_resolved_paramstr_storage,
				         sizeof(m_resolved_paramstr_storage),
				         "%s", errstr.c_str());
			}
		}
	}
	break;
	case PT_PID:
		ASSERT(param->m_len == sizeof(int64_t));

		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId64, *(int64_t *)param->m_val);


		if(get_thread_info() != NULL)
		{
			snprintf(m_resolved_paramstr_storage,
			         sizeof(m_resolved_paramstr_storage),
			         "%s",
			         get_thread_info()->m_comm.c_str());
		}

		break;
	case PT_UINT8:
		ASSERT(param->m_len == sizeof(uint8_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRIu8, *(uint8_t *)param->m_val);
		break;
	case PT_UINT16:
		ASSERT(param->m_len == sizeof(uint16_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRIu16, *(uint16_t *)param->m_val);
		break;
	case PT_UINT32:
		ASSERT(param->m_len == sizeof(uint32_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRIu32, *(uint32_t *)param->m_val);
		break;
	case PT_ERRNO:
	{
		ASSERT(param->m_len == sizeof(int64_t));

		int64_t val = *(int64_t *)param->m_val;

		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRId64, val);

		//
		// Resolve this as an errno
		//
		string errstr;

		if(val < 0)
		{
			errstr = sinsp_utils::errno_to_str((int32_t)val);

			if(errstr != "")
			{
				snprintf(m_resolved_paramstr_storage,
				         sizeof(m_resolved_paramstr_storage),
				         "%s", errstr.c_str());
			}
		}
	}
	break;
	case PT_UINT64:
		ASSERT(param->m_len == sizeof(uint64_t));
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%" PRIu64, *(int64_t *)param->m_val);
		break;
	case PT_CHARBUF:
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "%s", param->m_val);
		break;
	case PT_FSPATH:
	{
		strcpy_sanitized(m_paramstr_storage,
			param->m_val,
			MIN(param->m_len, sizeof(m_paramstr_storage)));

		sinsp_threadinfo* tinfo = get_thread_info();

		if(tinfo)
		{
			string fullpath;
			string cwd = tinfo->get_cwd();

			if(!sinsp_utils::concatenate_paths(m_resolved_paramstr_storage,
				sizeof(m_resolved_paramstr_storage),
				(char*)cwd.c_str(), 
				cwd.length(), 
				param->m_val, 
				param->m_len))
			{
				*resolved_str = m_paramstr_storage;
			}
		}
		else
		{
			*resolved_str = m_paramstr_storage;
		}
	}
	break;
	case PT_BYTEBUF:
	{
		uint32_t cres;
		/* This would include quotes around the outpur string
		            m_paramstr_storage[0] = '"';
		            cres = binary_buffer_to_string(m_paramstr_storage + 1,
		                param->m_val,
		                sizeof(m_paramstr_storage) - 2,
		                param->m_len);

		            m_paramstr_storage[cres + 1] = '"';
		            m_paramstr_storage[cres + 2] = 0;
		*/
		cres = binary_buffer_to_string(m_paramstr_storage,
		                               param->m_val,
		                               sizeof(m_paramstr_storage) - 1,
		                               param->m_len);

		m_paramstr_storage[cres + 1] = 0;
	}
	break;
	case PT_SOCKADDR:
		if(param->m_len == 0)
		{
			snprintf(m_paramstr_storage,
			         sizeof(m_paramstr_storage),
			         "NULL");

			break;
		}
		else if(param->m_val[0] == AF_UNIX)
		{
			//
			// typestr contains the type character that goes
			// at the beginning of the string if PF_NORMAL or
			// PF_JSON is specified
			//
			char typestr[2] =
			{
				(fmt == PF_SIMPLE)?(char)0:(char)CHAR_FD_UNIX_SOCK,
				0
			};

			ASSERT(param->m_len > 1);

			//
			// Sanitize the file string.
			//
            string sanitized_str = param->m_val + 1;
            sanitized_str.erase(remove_if(sanitized_str.begin(), sanitized_str.end(), g_invalidchar()), sanitized_str.end());

			snprintf(m_paramstr_storage,
				sizeof(m_paramstr_storage), 
				"%s %s",
				typestr,
				sanitized_str.c_str());
		}
		else if(param->m_val[0] == AF_INET)
		{
			if(param->m_len == 1 + 4 + 2)
			{
				//
				// typestr contains the type character that goes
				// at the beginning of the string if PF_NORMAL or
				// PF_JSON is specified
				//
				char typestr[2] =
				{
					(fmt == PF_SIMPLE)?(char)0:(char)CHAR_FD_IPV4_SOCK,
					0
				};

				snprintf(m_paramstr_storage,
				         sizeof(m_paramstr_storage),
				         "%s%u.%u.%u.%u:%u",
				         typestr,
				         (unsigned int)(uint8_t)param->m_val[1],
				         (unsigned int)(uint8_t)param->m_val[2],
				         (unsigned int)(uint8_t)param->m_val[3],
				         (unsigned int)(uint8_t)param->m_val[4],
				         (unsigned int)*(uint16_t*)(param->m_val+5));
			}
			else
			{
				ASSERT(false);
				snprintf(m_paramstr_storage,
				         sizeof(m_paramstr_storage),
				         "INVALID IPv4");
			}
		}
		else
		{
			snprintf(m_paramstr_storage,
			         sizeof(m_paramstr_storage),
			         "family %d", (int)param->m_val[0]);
		}
		break;
	case PT_SOCKTUPLE:
		if(param->m_len == 0)
		{
			snprintf(m_paramstr_storage,
			         sizeof(m_paramstr_storage),
			         "NULL");

			break;
		}
		else if(param->m_val[0] == AF_UNIX)
		{
			//
			// typestr contains the type character that goes
			// at the beginning of the string if PF_NORMAL or
			// PF_JSON is specified
			//
			char typestr[2] =
			{
				(fmt == PF_SIMPLE)?(char)0:(char)CHAR_FD_UNIX_SOCK,
				0
			};

			ASSERT(param->m_len > 17);

			//
			// Sanitize the file string.
			//
            string sanitized_str = param->m_val + 17;
            sanitized_str.erase(remove_if(sanitized_str.begin(), sanitized_str.end(), g_invalidchar()), sanitized_str.end());

			snprintf(m_paramstr_storage,
				sizeof(m_paramstr_storage), 
				"%s%" PRIx64 "->%" PRIx64 " %s", 
				typestr,
				*(uint64_t*)(param->m_val + 1),
				*(uint64_t*)(param->m_val + 9),
				sanitized_str.c_str());
		}
		else if(param->m_val[0] == AF_INET)
		{
			if(param->m_len == 1 + 4 + 2 + 4 + 2)
			{
				//
				// typestr contains the type character that goes
				// at the beginning of the string if PF_NORMAL or
				// PF_JSON is specified
				//
				char typestr[2] =
				{
					(fmt == PF_SIMPLE)?(char)0:(char)CHAR_FD_IPV4_SOCK,
					0
				};

				snprintf(m_paramstr_storage,
				         sizeof(m_paramstr_storage),
				         "%s%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
				         typestr,
				         (unsigned int)(uint8_t)param->m_val[1],
				         (unsigned int)(uint8_t)param->m_val[2],
				         (unsigned int)(uint8_t)param->m_val[3],
				         (unsigned int)(uint8_t)param->m_val[4],
				         (unsigned int)*(uint16_t*)(param->m_val+5),
				         (unsigned int)(uint8_t)param->m_val[7],
				         (unsigned int)(uint8_t)param->m_val[8],
				         (unsigned int)(uint8_t)param->m_val[9],
				         (unsigned int)(uint8_t)param->m_val[10],
				         (unsigned int)*(uint16_t*)(param->m_val+11));
			}
			else
			{
				ASSERT(false);
				snprintf(m_paramstr_storage,
				         sizeof(m_paramstr_storage),
				         "INVALID IPv4");
			}
		}
		else
		{
			snprintf(m_paramstr_storage,
			         sizeof(m_paramstr_storage),
			         "family %d", (int)param->m_val[0]);
		}
		break;
	case PT_FDLIST:
		{
			sinsp_threadinfo* tinfo = get_thread_info();
			if(!tinfo)
			{
				break;
			}

			uint16_t nfds = *(uint16_t *)param->m_val;
			uint32_t pos = 2;
			uint32_t spos = 0;

			m_paramstr_storage[0] = 0;

			for(j = 0; j < nfds; j++)
			{
				char tch;
				int64_t fd = *(int64_t *)(param->m_val + pos);

				sinsp_fdinfo *fdinfo = tinfo->get_fd(fd);
				if(fdinfo)
				{
					tch = fdinfo->get_typechar();
				}
				else
				{
//	                ASSERT(false);
					tch = '?';
				}

				spos += snprintf(m_paramstr_storage + spos,
								 sizeof(m_paramstr_storage) - spos,
								 "%" PRIu64 ":%c%x%c",
								 fd,
								 tch,
								 (uint32_t) * (int16_t *)(param->m_val + pos + 8),
								 (j < (uint32_t)(nfds - 1)) ? ' ' : '\0');

				pos += 10;
			}
		}
		break;
	case PT_SYSCALLID:
		{
			uint16_t scid  = *(uint16_t *)param->m_val;
			if(scid >= PPM_SC_MAX)
			{
				ASSERT(false);
				snprintf(m_paramstr_storage,
						 sizeof(m_paramstr_storage),
						 "<unknown syscall>");
				break;
			}

			const struct ppm_syscall_desc* desc = &(g_infotables.m_syscall_info_table[scid]);

			snprintf(m_paramstr_storage,
				sizeof(m_paramstr_storage),
				"%" PRIu16,
				scid);

			snprintf(m_resolved_paramstr_storage,
				sizeof(m_resolved_paramstr_storage),
				"%s",
				desc->name);
		}
		break;
	case PT_SIGTYPE:
		{
			string sigstr;

			ASSERT(param->m_len == sizeof(uint8_t));
			uint8_t val = *(uint8_t *)param->m_val;

			sigstr = sinsp_utils::signal_to_str(val);

			snprintf(m_paramstr_storage,
					 sizeof(m_paramstr_storage),
					 "%" PRIu8, val);

			snprintf(m_resolved_paramstr_storage,
						sizeof(m_resolved_paramstr_storage),
						"%s", sigstr.c_str());
		}
		break;
	case PT_RELTIME:
		{
			string sigstr;

			ASSERT(param->m_len == sizeof(uint64_t));
			uint64_t val = *(uint64_t *)param->m_val;

			snprintf(m_paramstr_storage,
					 sizeof(m_paramstr_storage),
					 "%" PRIu64, val);

			snprintf(m_resolved_paramstr_storage,
						sizeof(m_resolved_paramstr_storage),
						"%lgs", 
						((double)val) / 1000000000);
		}
		break;
	case PT_ABSTIME:
		//
		// XXX not implemented yet
		//
		ASSERT(false);
	default:
		ASSERT(false);
		snprintf(m_paramstr_storage,
		         sizeof(m_paramstr_storage),
		         "(n.a.)");
		break;
	}

	return m_paramstr_storage;
}

string sinsp_evt::get_param_value_str(string &name, bool resolved)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(name == get_param_name(i))
		{
			return get_param_value_str(i, resolved);
		}
	}
	return string("");
}

string sinsp_evt::get_param_value_str(const char *name, bool resolved)
{
	// TODO fix this !!
	string s_name = string(name);
	return get_param_value_str(s_name, resolved);
}

string sinsp_evt::get_param_value_str(uint32_t i, bool resolved)
{
	const char *param_value_str;
	const char *val_str;
	val_str = get_param_as_str(i, &param_value_str);

	if(resolved)
	{
		return string((*param_value_str == '\0')? val_str : param_value_str);
	}
	else
	{
		return string(val_str);
	}
}

void sinsp_evt::load_params()
{
	uint32_t j;
	uint32_t nparams;
	sinsp_evt_param par;

	nparams = m_info->nparams;
	uint16_t *lens = (uint16_t *)((char *)m_pevt + sizeof(struct ppm_evt_hdr));
	char *valptr = (char *)lens + nparams * sizeof(uint16_t);
	m_params.clear();

	for(j = 0; j < nparams; j++)
	{
		par.init(valptr, lens[j]);
		m_params.push_back(par);
		valptr += lens[j];
	}
}

void sinsp_evt::get_category(OUT sinsp_evt::category* cat)
{
	if(get_type() == PPME_GENERIC_E || 
		get_type() == PPME_GENERIC_X)
	{
		//
		// This event is a syscall that doesn't have a filler yet.
		// The category can be found in g_syscall_info_table.
		//
		sinsp_evt_param *parinfo = get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t id = *(uint16_t *)parinfo->m_val;

		cat->m_category = g_infotables.m_syscall_info_table[id].category;
		cat->m_subcategory = sinsp_evt::SC_NONE;
	}
	else
	{
		//
		// This event has a real filler.
		// The category can be found in the info struct.
		//
		cat->m_category = m_info->category;

		//
		// For EC_IO and EC_WAIT events, we dig into the fd state to get the category
		// and fdtype
		//
		if(cat->m_category == EC_IO)
		{
			if(!m_fdinfo)
			{
				//
				// The fd info is not present, likely because we missed its creation.
				//
				cat->m_subcategory = SC_UNKNOWN;
				return;
			}
			else
			{
				switch(m_fdinfo->m_type)
				{
					case SCAP_FD_FILE:
					case SCAP_FD_DIRECTORY:
						cat->m_subcategory = SC_FILE;
						break;
					case SCAP_FD_IPV4_SOCK:
					case SCAP_FD_IPV6_SOCK:
						cat->m_subcategory = SC_NET;
					case SCAP_FD_IPV4_SERVSOCK:
					case SCAP_FD_IPV6_SERVSOCK:
						cat->m_subcategory = SC_NET;
						break;
					case SCAP_FD_FIFO:
					case SCAP_FD_UNIX_SOCK:
					case SCAP_FD_EVENT:
					case SCAP_FD_SIGNALFD:
					case SCAP_FD_INOTIFY:
						cat->m_subcategory = SC_IPC;
						break;
					case SCAP_FD_UNSUPPORTED:
					case SCAP_FD_EVENTPOLL:
					case SCAP_FD_TIMERFD:
						cat->m_subcategory = SC_OTHER;
						break;
					case SCAP_FD_UNKNOWN:
						cat->m_subcategory = SC_OTHER;
						break;
					default:
						ASSERT(false);
						cat->m_subcategory = SC_UNKNOWN;
						break;
				}
			}
		}
	}
}
