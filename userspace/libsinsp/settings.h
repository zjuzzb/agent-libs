//
// This flag can be used to include unsupported or unrecognized sockets
// in the fd tables. It's useful to debug close() leaks
//
#define INCLUDE_UNKNOWN_SOCKET_FDS

//
// Memory storage size for an entry in the event storage LIFO.
// Events bigger than SP_STORAGE_EVT_BUF_SIZE won't be be stored in the LIFO.
//
#define SP_EVT_BUF_SIZE 4096

//
// If defined, the analyzer is compiled
//
#define HAS_ANALYZER

//
// If defined, the filtering system is compiled
//
#ifdef _DEBUG
#define HAS_FILTERING
#endif

//
// The analyzer emit interval
//
#define ANALYZER_SAMPLE_LENGTH_NS 1000000000

//
// If this is defined, the analyzer will include thread information inside
// the protocol buffers that it sends to the agent
//
#undef ANALYZER_EMITS_THREADS

//
// If this is defined, the analyzer will include process information inside
// the protocol buffers that it sends to the agent
//
#define ANALYZER_EMITS_PROCESSES

//
// If this is defined, the analyzer will include program information inside
// the protocol buffers that it sends to the agent
//
#undef ANALYZER_EMITS_PROGRAMS

//
// The min and max size for the memory buffer used as a target for protobuf 
// serialization. Min is the starting value, while max is the growth limit.
// This imposes a limit to the number of bytes that can be sent out by
// the agent.
//
#define MIN_SERIALIZATION_BUF_SIZE_BYTES 32000
#define MAX_SERIALIZATION_BUF_SIZE_BYTES 32000000

//
// If not defined, the analyzer will include simpler counters for each process:
// other, wait, io_file, io_net and processing instead of the full set
//
#undef ANALYZER_EMITS_FULL_PROCESS_COUNTERS

//
// Controls if assertions break execution or if they are just printed to the
// log
//
#define ASSERT_TO_LOG

//
// Controls if the library collects internal performance stats.
//
#define GATHER_INTERNAL_STATS

//
// Read timeout specified when doing scap_open
//
#define SCAP_TIMEOUT_MS 30

//
// The time after which a connection is considered stale and is removed from 
// the connection table.
//
#define DEFAULT_CONNECTION_TIMEOUT_SEC 90

//
// The time after an inactive thread is removed.
//
#define DEFAULT_THREAD_TIMEOUT_SEC 1800

//
// How often the thread table is sacnned for inactive threads
//
#define DEFAULT_INACTIVE_THREAD_SCAN_TIME 600

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
// If this is set, all the connections *coming* from the external world
// are aggreagated into a single connection in the protocol samples.
// This can be overridden by set_aggregate_connections_in_proto().
//
#define AGGREGATE_CONNECTIONS_IN_PROTO true

//
// Max size that the thread table can reach
//
#define MAX_THREAD_TABLE_SIZE 65536

//
// Transaction constants
//
#define TRANSACTION_TIMEOUT_NS 200000000
#define TRANSACTION_SERVER_EURISTIC_MIN_CONNECTIONS 2
#define TRANSACTION_SERVER_EURISTIC_MAX_DELAY_NS (3 * ONE_SECOND_IN_NS)

//
// Process health score calculation constants
//
#define MAX_HEALTH_CONCURRENCY 16
#define CONCURRENCY_OBSERVATION_INTERVAL_NS 1000000

//
// When returning the top error codes for a host or a process,
// this is the max number of entries in the list.
//
#define MAX_N_ERROR_CODES_IN_PROTO 5