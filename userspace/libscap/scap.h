#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*!
	\mainpage libscap exported interface documentation
	
	\section Introduction

	This document describes the data structures and the functions exported by the CACE Technologies afdxcap library.
	It includes the following sections:
	- \ref scap_defs
	- \ref scap_functs
*/

///////////////////////////////////////////////////////////////////////////////
// Public structs and defines
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_defs public definitions and structures
 *  @{
 */

//
// Core types
//
#include "uthash.h"
#include "../../driver/ppm_events_public.h"
#include "../../driver/ppm_types.h"

//
// Return types
//
#define SCAP_SUCCESS 0
#define SCAP_FAILURE 1
#define SCAP_TIMEOUT -1
#define SCAP_ILLEGAL_INPUT 3
#define SCAP_NOTFOUND 4
#define SCAP_INPUT_TOO_SMALL 5
#define SCAP_EOF 6

//
// Last error string size for scap_open_live()
//
#define SCAP_LASTERR_SIZE 256

/*!
  \brief Statisitcs about an in progress capture
*/
typedef struct scap_stats
{
	uint64_t n_evts; ///< Total number of events that were received by the driver.
	uint64_t n_drops; ///< Number of dropped events.
	uint64_t n_preemptions; ///< Number of preemptions.
}scap_stats;

/*!
  \brief Information about the parameter of an event
*/
typedef struct evt_param_info
{
	const char* name; ///< The event name.
	uint32_t type; ///< The event type. See the ppm_event_type enum in driver/ppm_events_public.h
	uint32_t len; ///< The event total length.
	char* val; ///< The event data.
}evt_param_info;

#define SCAP_MAX_PATH_SIZE 1024

/*!
  \brief File Descriptor type
*/
typedef enum scap_fd_type
{
	SCAP_FD_UNINITIALIZED = -1,
	SCAP_FD_UNKNOWN = 0,
	SCAP_FD_FILE = 1,
	SCAP_FD_DIRECTORY = 2,
	SCAP_FD_IPV4_SOCK = 3,
	SCAP_FD_IPV6_SOCK = 4,
	SCAP_FD_IPV4_SERVSOCK = 5,
	SCAP_FD_IPV6_SERVSOCK = 6,
	SCAP_FD_FIFO = 7,
	SCAP_FD_UNIX_SOCK = 8,
	SCAP_FD_EVENT = 9,
	SCAP_FD_UNSUPPORTED = 10,
	SCAP_FD_SIGNALFD = 11,
	SCAP_FD_EVENTPOLL = 12,
	SCAP_FD_INOTIFY = 13,
	SCAP_FD_TIMERFD = 14
}scap_fd_type;

/*!
  \brief Socket type / transport protocol
*/
typedef enum scap_l4_proto
{
	SCAP_L4_UNKNOWN = 0, ///< unknown protocol, likely caused by some parsing problem
	SCAP_L4_NA = 1, ///< protocol not available, because the fd is not a socket
	SCAP_L4_TCP = 2,
	SCAP_L4_UDP = 3,
	SCAP_L4_ICMP = 4,
	SCAP_L4_RAW = 5, ///< Raw socket
}scap_l4_proto;

/*!
  \brief Information about a file descriptor
*/
typedef struct scap_fdinfo
{
	int64_t fd; ///< The FD number, which uniquely identifies this file descriptor.
	uint64_t ino; ///< For unix sockets, the inode.
	scap_fd_type type; ///< This file descriptor's type.
	union
	{
		struct
		{
		  uint32_t sip; ///< Source IP
		  uint32_t dip; ///< Destination IP
		  uint16_t sport; ///< Source port
		  uint16_t dport; ///< Destination port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4info; ///< Information specific to IPv4 sockets
		struct
		{
			uint32_t sip[4]; ///< Source IP
			uint32_t dip[4]; ///< Destination IP
			uint16_t sport; ///< Source Port
			uint16_t dport; ///< Destination Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6info; ///< Information specific to IPv6 sockets
		struct
		{
		  uint32_t ip; ///< Local IP
		  uint16_t port; ///< Local Port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4serverinfo; ///< Information specific to IPv4 server sockets, e.g. sockets used for bind().
		struct
		{
			uint32_t ip[4]; ///< Local IP
			uint16_t port; ///< Local Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6serverinfo; ///< Information specific to IPv6 server sockets, e.g. sockets used for bind().
		struct
		{
			uint64_t source; ///< Source socket endpoint
		  	uint64_t destination; ///< Destination socket endpoint
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this unix socket
		} unix_socket_info; ///< Information specific to unix sockets
		char fname[SCAP_MAX_PATH_SIZE];  ///< The name for file system FDs
	}info;
	UT_hash_handle hh; ///< makes this structure hashable
}scap_fdinfo;

/*!
  \brief Process information
*/
typedef struct scap_threadinfo
{
	uint64_t tid; ///< The thread/task id.
	uint64_t pid; ///< The id of the process containing this thread. In single thread processes, this is equal to tid.
	uint64_t ptid; ///< The id of the thread that created this thread.
	char comm[SCAP_MAX_PATH_SIZE]; ///< Command name (e.g. "top")
	char exe[SCAP_MAX_PATH_SIZE]; ///< Full command name (e.g. "/bin/top")
	char args[SCAP_MAX_PATH_SIZE]; ///< Command line arguments (e.g. "-d1")
	uint16_t args_len; ///< Command line arguments length
	char cwd[SCAP_MAX_PATH_SIZE]; ///< The current working directory
	int64_t fdlimit; ///< The maximum number of files this thread is allowed to open
	uint32_t flags; ///< the process flags.
	uint32_t uid; ///< user id
	uint32_t gid; ///< group id
	scap_fdinfo* fdlist; ///< The fd table for this process
	UT_hash_handle hh; ///< makes this structure hashable
}scap_threadinfo;

//
// The follwing stuff is byte aligned because we save it to disk.
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/*!
  \brief Machine information
*/
typedef struct _scap_machine_info
{
	uint32_t num_cpus;	///< Number of processors
	uint64_t memory_size_bytes; ///< Physical memory size
	uint64_t max_pid; ///< Highest PID number on this machine
	char hostname[128]; ///< The machine hostname 
	uint64_t reserved1; ///< reserved for fututre use
	uint64_t reserved2; ///< reserved for fututre use
	uint64_t reserved3; ///< reserved for fututre use
	uint64_t reserved4; ///< reserved for fututre use
}scap_machine_info;


#define SCAP_IPV6_ADDR_LEN 16

/*!
  \brief IPv4 interface address information
*/
typedef struct scap_ifinfo_ipv4
{
	uint16_t type; ///< Interface type
	uint16_t ifnamelen;
	uint32_t addr; ///< Interface address
	uint32_t netmask; ///< Interface netmask
	uint32_t bcast; ///< Interface broadcast address
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv4;

/*!
  \brief IPv6 interface address information
*/
typedef struct scap_ifinfo_ipv6
{
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN]; ///< Interface address
	char netmask[SCAP_IPV6_ADDR_LEN]; ///< Interface netmask
	char bcast[SCAP_IPV6_ADDR_LEN]; ///< Interface broadcast address
	char ifname[SCAP_MAX_PATH_SIZE]; ///< interface name (e.g. "eth0")
}scap_ifinfo_ipv6;
#pragma pack(pop)

/*!
  \brief List of the machine network interfaces
*/
typedef struct scap_addrlist
{
	uint32_t n_v4_addrs; ///< Number of IPv4 addresses
	uint32_t n_v6_addrs; ///< Number of IPv6 addresses
	uint32_t totlen; ///< For internal use
	scap_ifinfo_ipv4* v4list; ///< List of IPv4 Addresses
	scap_ifinfo_ipv6* v6list; ///< List of IPv6 Addresses
}scap_addrlist;

#define MAX_CREDENTIALS_STR_LEN 256
#define USERBLOCK_TYPE_USER 0
#define USERBLOCK_TYPE_GROUP 1

/*!
  \brief Information about one of the machine users
*/
typedef struct scap_userinfo
{
	uint32_t uid; ///< User ID
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Username
	char homedir[SCAP_MAX_PATH_SIZE]; ///< Home directory
	char shell[SCAP_MAX_PATH_SIZE]; ///< Shell program
}scap_userinfo;

/*!
  \brief Information about one of the machine user groups
*/
typedef struct scap_groupinfo
{
	uint32_t gid; ///< Group ID
	char name[MAX_CREDENTIALS_STR_LEN]; ///< Group name
}scap_groupinfo;

/*!
  \brief List of the machine users and groups
*/
typedef struct scap_userlist
{
	uint32_t nusers; ///< Number of users
	uint32_t ngroups; ///< Number of groups
	uint32_t totsavelen; ///< For internal use
	scap_userinfo* users;  ///< User list
	scap_groupinfo* groups; ///< Group list
}scap_userlist;

//
// Misc definitions
//

/*!
  \brief The OS on which the capture was made
*/
typedef enum scap_os_patform
{
	SCAP_PFORM_UNKNOWN = 0,
	SCAP_PFORM_LINUX_I386 = 1,
	SCAP_PFORM_LINUX_X64 = 2,
	SCAP_PFORM_WINDOWS_I386 = 3,
	SCAP_PFORM_WINDOWS_X64 = 4,
}scap_os_patform;

/*!
  \brief Indicates if an event is an enter one or an exit one
*/
typedef enum event_direction
{
	SCAP_ED_IN = 0,
	SCAP_ED_OUT = 1
}event_direction;

typedef struct scap_dumper scap_dumper_t;
/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Structs and defines used internally
///////////////////////////////////////////////////////////////////////////////

#define IN
#define OUT

//
// Forward declarations
//
typedef struct scap scap_t;
typedef struct ppm_evt_hdr scap_evt;

///////////////////////////////////////////////////////////////////////////////
// API functions
///////////////////////////////////////////////////////////////////////////////

/** @defgroup scap_functs API Functions
 *  @{
 */

/*!
  \brief Start a live event capture.

  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
			
  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open_live(char *error);

/*!
  \brief Start an event capture from file.

  \param fname The name of the file to open.
  \param error Pointer to a buffer that will contain the error string in case the
    function fails. The buffer must have size SCAP_LASTERR_SIZE.
			
  \return The capture instance handle in case of success. NULL in case of failure.
*/
scap_t* scap_open_offline(char* fname, char *error);

/*!
  \brief Close a capture handle.

  \param handle Handle to the capture instance.
*/
void scap_close(scap_t* handle);

/*!
  \brief Retrieve the OS platform for the given capture handle.

  \param handle Handle to the capture instance.
			
  \return The type of operating system on which the capture was made.

  \note For live handles, the return value indicates the current local OS. 
    For offline handles, the return value indicates the OS where the data was 
	originally captured.
*/
scap_os_patform scap_get_os_platform(scap_t* handle);

/*!
  \brief Return a string with the last error that happened on the given capture.
*/
char* scap_getlasterr(scap_t* handle);

/*!
  \brief Get the next event from the from the given capture instance

  \param handle Handle to the capture instance.
  \param pevent User-provided event pointer that will be initialized with address of the event.
  \param pcpuid User-provided event pointer that will be initialized with the ID if the CPU
    where the event was captured.
			
  \return SCAP_SECCESS if the call is succesful and pevent and pcpuid contain valid data.
   SCAP_TIMEOUT in case the read timeout expired and no event is available.
   SCAP_EOF when the end of an offline capture is reached.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error. 
*/
int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);

/*!
  \brief Get the length of an event

  \param e pointer to an event returned by \ref scap_next.
			
  \return The event length in bytes. 
*/
uint32_t scap_event_getlen(scap_evt* e);

/*!
  \brief Get the timestamp of an event

  \param e pointer to an event returned by \ref scap_next.
			
  \return The event timestamp, in nanoseconds since epoch. 
*/
uint64_t scap_event_get_ts(scap_evt* e);

// Get the number of the last event captured from handle 
uint64_t scap_event_get_num(scap_t* handle);

// Get the event type
uint16_t scap_event_get_type(scap_evt* e);

// Get the human readable event name
const char* scap_event_get_name(scap_evt* e);

// Get the event category
ppm_event_category scap_event_get_category(scap_evt* e);

// Get the event direction. We capture each both the entry and the exit of OS calls.
event_direction scap_event_get_direction(scap_evt* e);

// Get the ID of the process that generated the event
int64_t scap_event_get_tid(scap_evt* e);

// Get the number of arguments that the given event has
uint32_t scap_event_getnumparams(scap_evt* e);

// Fill a evt_param_info structure with the details of one of the event parameters
int32_t scap_event_getparam(scap_evt* e, uint32_t paramid, OUT evt_param_info* param);

// Get the event table entry for the given event
const struct ppm_event_info* scap_event_getinfo(scap_evt* e);

// Open a "savefile" for writing.
scap_dumper_t* scap_dump_open(scap_t *handle, const char *fname);

// Close a "savefile" opened with scap_dump_open
void scap_dump_close(scap_dumper_t *d);

// Write an event to a dump file
int32_t scap_dump(scap_t *handle, scap_dumper_t *d, scap_evt* event, uint16_t cpuid);

// Return the process list for the given handle
scap_threadinfo* scap_get_proc_table(scap_t* handle);

// Return the number of dropped events for the given handle
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats);

// Stop capture the events
int32_t scap_stop_capture(scap_t* handle);

// Start capture the events, if it was stopped with scap_stop_capture
int32_t scap_start_capture(scap_t* handle);

int32_t scap_stop_dropping_mode(scap_t* handle);

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio);

// Return the list of device addresses
scap_addrlist* scap_get_ifaddr_list(scap_t* handle);

// Return the list of machine users
scap_userlist* scap_get_user_list(scap_t* handle);

// set empty buffer timeout in milliseconds
int32_t scap_set_empty_buffer_timeout_ms(scap_t* handle, uint32_t timeout_ms);

// Get the event info table
const struct ppm_event_info* scap_get_event_info_table();

// Get the syscall info table
const struct ppm_syscall_desc* scap_get_syscall_info_table();

// Get the machine information.
// Returns NULL if machine information is not available (which can happen when reading
// from files witthout that information)
const scap_machine_info* scap_get_machine_info(scap_t* handle);

// Set the capture snaplen, i.e. the maximum size after which the driver starts 
// truncating the string or byte buffer arguments
int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen);

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// Non public functions
///////////////////////////////////////////////////////////////////////////////

//
// Return the number of event capture devices that the library is handling. Each processor
// has its own event capture device.
//
uint32_t scap_get_ndevs(scap_t* handle);

// Retrieve a buffer of events from one of the cpus
extern int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, bool blocking, OUT char** buf, OUT uint32_t* len);

#ifdef PPM_ENABLE_SENTINEL
// Get the sentinel at the beginning of the event
uint32_t scap_event_get_sentinel_begin(scap_evt* e);
#endif

// Get the information about a process.
// The returned pointer must be freed via scap_proc_free by the caller.
struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid);

void scap_proc_free(scap_t* handle, struct scap_threadinfo* procinfo);

#ifdef __cplusplus
}
#endif
