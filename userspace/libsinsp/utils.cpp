#ifndef _WIN32
#include <unistd.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_initializer implementation
///////////////////////////////////////////////////////////////////////////////

//
// These are the libsinsp globals
//
sinsp_evttables g_infotables;
sinsp_logger g_logger;
sinsp_initializer g_initializer;

//
// loading time initializations
//
sinsp_initializer::sinsp_initializer()
{
	//
	// Init the event tables
	//
	g_infotables.m_event_info = scap_get_event_info_table();
	g_infotables.m_syscall_info_table = scap_get_syscall_info_table();

	//
	// Init the logger
	//
	g_logger.set_severity(sinsp_logger::SEV_DEBUG);
//	g_logger.add_file_log("sisnsp.log");
//	g_logger.log("library starting");

	//
	// Sockets initialization on windows
	//
#ifdef _WIN32
	WSADATA wsaData;
	WORD version = MAKEWORD( 2, 0 );
	WSAStartup( version, &wsaData );
#endif
}

///////////////////////////////////////////////////////////////////////////////
// Various helper functions
///////////////////////////////////////////////////////////////////////////////

//
// errno to string conversion.
// Only the first 40 error codes are currently implemented
//
const char* sinsp_utils::errno_to_str(int32_t code)
{
	switch(-code)
	{
	case SE_EPERM:
		return "EPERM";
	case SE_ENOENT:
		return "ENOENT";
	case SE_ESRCH:
		return "ESRCH";
	case SE_EINTR:
		return "EINTR";
	case SE_EIO:
		return "EIO";
	case SE_ENXIO:
		return "ENXIO";
	case SE_E2BIG:
		return "E2BIG";
	case SE_ENOEXEC:
		return "ENOEXEC";
	case SE_EBADF:
		return "EBADF";
	case SE_ECHILD:
		return "ECHILD";
	case SE_EAGAIN:
		return "EAGAIN";
	case SE_ENOMEM:
		return "ENOMEM";
	case SE_EACCES:
		return "EACCES";
	case SE_ENOTBLK:
		return "ENOTBLK";
	case SE_EBUSY:
		return "EBUSY";
	case SE_EEXIST:
		return "EEXIST";
	case SE_EXDEV:
		return "EXDEV";
	case SE_ENODEV:
		return "ENODEV";
	case SE_ENOTDIR:
		return "ENOTDIR";
	case SE_EISDIR:
		return "EISDIR";
	case SE_EINVAL:
		return "EINVAL";
	case SE_ENFILE:
		return "ENFILE";
	case SE_EMFILE:
		return "EMFILE";
	case SE_ENOTTY:
		return "ENOTTY";
	case SE_ETXTBSY:
		return "ETXTBSY";
	case SE_EFBIG:
		return "EFBIG";
	case SE_ENOSPC:
		return "ENOSPC";
	case SE_ESPIPE:
		return "ESPIPE";
	case SE_EROFS:
		return "EROFS";
	case SE_EMLINK:
		return "EMLINK";
	case SE_EPIPE:
		return "EPIPE";
	case SE_EDOM:
		return "EDOM";
	case SE_ERANGE:
		return "ERANGE";
	case SE_EDEADLK:
		return "EDEADLK";
	case SE_ENAMETOOLONG:
		return "ENAMETOOLONG";
	case SE_ENOLCK:
		return "ENOLCK";
	case SE_ENOSYS:
		return "ENOSYS";
	case SE_ENOTEMPTY:
		return "ENOTEMPTY";
	case SE_ELOOP:
		return "ELOOP";
	case SE_ERESTARTSYS:
		return "ERESTARTSYS";
	case SE_ENETUNREACH:
		return "ENETUNREACH";
	case SE_EINPROGRESS:
		return "EINPROGRESS";
	case SE_ETIMEDOUT:
		return "ETIMEDOUT";
	case SE_ECONNRESET:
		return "ECONNRESET";
	case SE_ECONNREFUSED:
		return "ECONNREFUSED";
	case SE_ERESTARTNOHAND:
		return "ERESTARTNOHAND";
	case SE_EADDRNOTAVAIL:
		return "EADDRNOTAVAIL";
	case SE_ENOTCONN:
		return "ENOTCONN";
	case SE_ENETDOWN:
		return "ENETDOWN";
	case SE_EOPNOTSUPP:
		return "EOPNOTSUPP";
	case SE_ENOTSOCK:
		return "ENOTSOCK";
	case SE_ERESTART_RESTARTBLOCK:
		return "ERESTART_RESTARTBLOCK";
	default:
		ASSERT(false);
		return "";
	}
}

//
// errno to string conversion.
// Only the first 40 error codes are currently implemented
//
const char* sinsp_utils::signal_to_str(uint8_t code)
{
	switch(code)
	{
	case SE_SIGHUP:
		return "SIGHUP";
	case SE_SIGINT:
		return "SIGINT";
	case SE_SIGQUIT:
		return "SIGQUIT";
	case SE_SIGILL:
		return "SIGILL";
	case SE_SIGTRAP:
		return "SIGTRAP";
	case SE_SIGABRT:
		return "SIGABRT";
	case SE_SIGBUS:
		return "SIGBUS";
	case SE_SIGFPE:
		return "SIGFPE";
	case SE_SIGKILL:
		return "SIGKILL";
	case SE_SIGUSR1:
		return "SIGUSR1";
	case SE_SIGSEGV:
		return "SIGSEGV";
	case SE_SIGUSR2:
		return "SIGUSR2";
	case SE_SIGPIPE:
		return "SIGPIPE";
	case SE_SIGALRM:
		return "SIGALRM";
	case SE_SIGTERM:
		return "SIGTERM";
	case SE_SIGSTKFLT:
		return "SIGSTKFLT";
	case SE_SIGCHLD:
		return "SIGCHLD";
	case SE_SIGCONT:
		return "SIGCONT";
	case SE_SIGSTOP:
		return "SIGSTOP";
	case SE_SIGTSTP:
		return "SIGTSTP";
	case SE_SIGTTIN:
		return "SIGTTIN";
	case SE_SIGTTOU:
		return "SIGTTOU";
	case SE_SIGURG:
		return "SIGURG";
	case SE_SIGXCPU:
		return "SIGXCPU";
	case SE_SIGXFSZ:
		return "SIGXFSZ";
	case SE_SIGVTALRM:
		return "SIGVTALRM";
	case SE_SIGPROF:
		return "SIGPROF";
	case SE_SIGWINCH:
		return "SIGWINCH";
	case SE_SIGIO:
		return "SIGIO";
	case SE_SIGPWR:
		return "SIGPWR";
	case SE_SIGSYS:
		return "SIGSYS";
	default:
		ASSERT(false);
		return "<invalid>";
	}
}

//
// Helper function to move a directory up in a path string
//
void rewind_to_parent_path(char* targetbase, char** tc, const char** pc, uint32_t delta)
{
	if(*tc <= targetbase + 1)
	{
		(*pc) += delta;
		return;
	}

	(*tc)--;

	while(*((*tc) - 1) != '/' && (*tc) >= targetbase + 1)
	{
		(*tc)--;
	}

	(*pc) += delta;
}

//
// Args:
//  - target: the string where we are supposed to start copying 
//  - targetbase: the base of the path, i.e. the furthest we can go back when 
//                following parent directories 
//  - path: the path to copy 
//
void copy_and_sanitize_path(char* target, char* targetbase, const char* path)
{
	char* tc = target;
	const char* pc = path;
	g_invalidchar ic;

	while(true)
	{
		if(*pc == 0)
		{
			*tc = 0;

			//
			// If the path ends with a '/', remove it, as the OS does.
			//
			if((tc > (targetbase + 1)) && (*(tc - 1) == '/'))
			{
				*(tc - 1) = 0;
			}

			return;
		}

		if(ic(*pc))
		{
			//
			// Invalid char, substitute with a '.'
			//
			*tc = '.';
			tc++;
			pc++;
		}
		else
		{
			if(*pc == '.' && *(pc + 1) == '.' && *(pc + 2) == '/')
			{
				//
				// '../', rewind to the previous '/'
				//
				rewind_to_parent_path(targetbase, &tc, &pc, 3);

			}
			else if(*pc == '.' && *(pc + 1) == '.')
			{
				//
				// '..', with no '/'.
				// This is valid if we are at the end of the string, and in that case we rewind.
				// Otherwise it shouldn't happen and we leave the string intact
				//
				if(*(pc + 2) == 0)
				{
					rewind_to_parent_path(targetbase, &tc, &pc, 2);
				}
				else
				{
					*tc = '.';
					*(tc + 1) = '.';
					pc += 2;
					tc += 2;
				}
			}
			else if(*pc == '.' && *(pc + 1) == '/')
			{
				//
				// './', just skip it
				//
				pc += 2;
			}
			else if(*pc == '.')
			{
				//
				// '.', with no '/'.
				// This is valid if we are at the end of the string, and in that case we rewind.
				// Otherwise it shouldn't happen and we leave the string intact
				//
				if(*(pc + 1) == 0)
				{
					pc++;
				}
				else
				{
					*tc = *pc;
					tc++;
					pc++;
				}
			}
			else if(*pc == '/')
			{
				//
				// '/', if the last char is already a '/', skip it
				//
				if(tc > targetbase && *(tc - 1) == '/')
				{
					pc++;
				}
				else
				{
					*tc = *pc;
					tc++;
					pc++;
				}
			}
			else
			{
				//
				// Normal char, copy it
				//
				*tc = *pc;
				tc++;
				pc++;
			}
		}
	}
}

bool sinsp_utils::concatenate_paths(char* target, 
									uint32_t targetlen, 
									const char* path1, 
									uint32_t len1, 
									const char* path2, 
									uint32_t len2)
{
/*
	char strp[] = "/root/git/";
	char str[] = "/";
//	memcpy(target, strp, sizeof(strp));
//	copy_and_sanitize_path(target + sizeof(strp) - 1, target, str);
	copy_and_sanitize_path(target, target, str);
*/

	if(targetlen < (len1 + len2 + 1))
	{
		ASSERT(false);
		strcpy(target, "/PATH_TOO_LONG");
	}

	if(len2 != 0 && path2[0] != '/')
	{
		memcpy(target, path1, len1);
		copy_and_sanitize_path(target + len1, target, path2);
		return true;
	}
	else
	{
		target[0] = 0;
		copy_and_sanitize_path(target, target, path2);
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////////
// gettimeofday() windows implementation
///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32

#include <time.h>
#include <windows.h> 

const __int64 DELTA_EPOCH_IN_MICROSECS = 11644473600000000;

int gettimeofday(struct timeval *tv, struct timezone2 *tz)
{
	FILETIME ft;
	__int64 tmpres = 0;
	TIME_ZONE_INFORMATION tz_winapi;
	int rez=0;

	ZeroMemory(&ft,sizeof(ft));
	ZeroMemory(&tz_winapi,sizeof(tz_winapi));

	GetSystemTimeAsFileTime(&ft);

	tmpres = ft.dwHighDateTime;
	tmpres <<= 32;
	tmpres |= ft.dwLowDateTime;

	//
	// converting file time to unix epoch
	//
	tmpres /= 10;  // convert into microseconds
	tmpres -= DELTA_EPOCH_IN_MICROSECS; 
	tv->tv_sec = (__int32)(tmpres*0.000001);
	tv->tv_usec =(tmpres%1000000);

	//
	// _tzset(),don't work properly, so we use GetTimeZoneInformation
	//
	if(tz)
	{
		rez=GetTimeZoneInformation(&tz_winapi);
		tz->tz_dsttime=(rez==2)?true:false;
		tz->tz_minuteswest = tz_winapi.Bias + ((rez==2)?tz_winapi.DaylightBias:0);
	}

	return 0;
}
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
string sinsp_gethostname()
{
	char hname[256];
	int res = gethostname(hname, sizeof(hname) / sizeof(hname[0]));

	if(res == 0)
	{
		return hname;
	}
	else
	{
		ASSERT(false);
		return "";
	}
}

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////
string ipv4tuple_to_string(ipv4tuple* tuple)
{
	char buf[50];
	sprintf(
		buf, 
		"%d.%d.%d.%d:%d->%d.%d.%d.%d:%d", 
		(tuple->m_fields.m_sip & 0xFF),
		((tuple->m_fields.m_sip & 0xFF00) >> 8),
		((tuple->m_fields.m_sip & 0xFF0000) >> 16),
		((tuple->m_fields.m_sip & 0xFF000000) >> 24),
		tuple->m_fields.m_sport,
		(tuple->m_fields.m_dip & 0xFF),
		((tuple->m_fields.m_dip & 0xFF00) >> 8),
		((tuple->m_fields.m_dip & 0xFF0000) >> 16),
		((tuple->m_fields.m_dip & 0xFF000000) >> 24),
		tuple->m_fields.m_dport);
	return string(buf);
}

string ipv6tuple_to_string(_ipv6tuple* tuple)
{
	char source_address[100];
	char destination_address[100];
	char buf[200];
	if(NULL == inet_ntop(AF_INET6, tuple->m_fields.m_sip, source_address, 100))
	{
		return string();
	}
	if(NULL == inet_ntop(AF_INET6, tuple->m_fields.m_dip, destination_address, 100))
	{
		return string();
	}
	snprintf(buf,200,"%s:%u->%s:%u",
		source_address,
		tuple->m_fields.m_sport,
		destination_address,
		tuple->m_fields.m_dport);
	return string(buf);
}
