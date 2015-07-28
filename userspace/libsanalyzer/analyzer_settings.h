#pragma once

//
// The analyzer emit interval
//
#define ANALYZER_DEFAULT_SAMPLE_LENGTH_NS 1000000000

//
// If this is defined, the analyzer will include process information inside
// the protocol buffers that it sends to the agent
//
#define ANALYZER_EMITS_PROCESSES

//
// If this is defined, the analyzer will include program information inside
// the protocol buffers that it sends to the agent
//
#define ANALYZER_EMITS_PROGRAMS

//
// The min and max size for the memory buffer used as a target for protobuf 
// serialization. Min is the starting value, while max is the growth limit.
// This imposes a limit to the number of bytes that can be sent out by
// the agent.
//
#define MIN_SERIALIZATION_BUF_SIZE_BYTES 128
#define MAX_SERIALIZATION_BUF_SIZE_BYTES 32000000

//
// The time after which a connection is considered stale and is removed from 
// the connection table.
//
#define DEFAULT_CONNECTION_TIMEOUT_SEC 90

//
// Max size that the connection table can reach
//
#define MAX_CONNECTION_TABLE_SIZE 65536

//
// Max number of connections that can go in a sample that is sent to the backend.
// 0 means no limit.
// This can be ovverridden through sinsp_configuration::set_max_connections_in_proto().
//
#define DEFAULT_MAX_CONNECTIONS_IN_PROTO 100

//
// Max number of executed commands that can be included in the protocol
//
#define DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO 30

//
// If this is set, all the connections *coming* from the external world
// are aggreagated into a single connection in the protocol samples.
// This can be overridden by set_aggregate_connections_in_proto().
//
#define AGGREGATE_CONNECTIONS_IN_PROTO true

//
// Transaction constants
//
#define TRANSACTION_TIMEOUT_NS 100000000
#define TRANSACTION_TIMEOUT_SUBSAMPLING_NS 5000000
#define TRANSACTION_SERVER_EURISTIC_MIN_CONNECTIONS 2
#define TRANSACTION_SERVER_EURISTIC_MAX_DELAY_NS (3 * ONE_SECOND_IN_NS)

//
// Max size that a process' url/query... table can reach
//
#define MAX_THREAD_REQUEST_TABLE_SIZE 1024

//
// Process health score calculation constants
//
#define MAX_HEALTH_CONCURRENCY 16
#define CONCURRENCY_OBSERVATION_INTERVAL_NS 1000000

//
// Number of samples after which the process information *of every process* is included in the sample.
// Usually, the sample includes only process information for processes that have been created
// during the sample or that did an execve during the sample.
// Every once in a while, tough, we force the inclusion of every process, to make sure the backend stays
// in sync.
// This constant controls after how many normal samples we include a "full process" sample.
//
#define PROCINFO_IN_SAMPLE_INTERVAL 1

//
// Number of samples after which /proc is scanned to detect processes that ended without being
// removed from out table.
//
#define PROC_BASED_THREAD_PRUNING_INTERVAL 60

//
// Maximum numeber of external TCP/UDP client endpoints that are reported independently.
// If the number goes beyond this treshold, the clients will be aggregated into a single
// 0.0.0.0 endpoint.
//
#define MAX_N_EXTERNAL_CLIENTS 30

//
// Set this to true to enable drop mode support
//
#define AUTODROP_ENABLED false

//
// Maximum numeber of events per CPU that the analyzer sees before it starts putting
// the driver in drop mode.
//
#define DROP_UPPER_THRESHOLD 5
#define DROP_LOWER_THRESHOLD 3

//
// Number of consecutive seconds the number of events must be beyond DROP_THRESHOLD
// before dropping mode is activated.
//
#define DROP_THRESHOLD_CONSECUTIVE_SECONDS 5

//
//	Max number of processes that can go in a sample
//
#define TOP_PROCESSES_IN_SAMPLE 30

//
// Max number of files per category that can go in a sample, so the worst case is 4X
// this number
//
#define TOP_FILES_IN_SAMPLE 10

//
// Max number of connections that can go in a sample.
// We sort by both bytes and number of sub-connections, so this number can double
// in the worst case.
//
#define TOP_CONNECTIONS_IN_SAMPLE 40

//
// Max number of URLS that are reported on a per process and per machine basis
//
#define TOP_URLS_IN_SAMPLE 15

//
// Max number of URLS that are reported on a per process and per machine basis
//
#define TOP_STATUS_CODES_IN_SAMPLE 10

//
// Should the library track unix and FD connections
//
#undef HAS_UNIX_CONNECTIONS
#undef HAS_PIPE_CONNECTIONS

//
// The maximum duration of a socket server-side read after which we
// assume the transaction is not client server
//
#define TRANSACTION_READ_LIMIT_NS 500000000

//
// Minimum size of a socket buffer containing actual protocol information  
//
#define MIN_VALID_PROTO_BUF_SIZE 5

//
// Number of TID collisions in a sample that causes the program to restart
//
#define MAX_TID_COLLISIONS_IN_SAMPLE 64

//
// Max number of chisel-generated metrics that can be transported by a sample
//
#define CHISEL_METRIC_LIMIT 300

//
// FD class customized with the storage we need
//
#include "tuples.h"
#include "transactinfo.h"
class sinsp_partial_transaction;
template<class T> class sinsp_fdinfo;
typedef sinsp_fdinfo<sinsp_partial_transaction> sinsp_fdinfo_t;

#define HAS_CAPTURE_FILTERING

#undef SIMULATE_DROP_MODE

static const auto CONTAINERS_LIMIT = 200;

static const auto HOST_STATSD_METRIC_LIMIT = 100;
static const auto CONTAINERS_STATSD_METRIC_LIMIT = 100;

static const size_t CONTAINERS_PROTOS_TOP_LIMIT = 15;
static const size_t HOST_PROTOS_LIMIT = 15;
static const auto ARG_SIZE_LIMIT = 100;
static const auto ASSUME_LONG_LIVING_PROCESS_UPTIME_S = 10;