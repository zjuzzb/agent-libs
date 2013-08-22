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
// Use this to turn the analyzer on and off
//
#define USE_ANALYZER

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
// The min and max size for the memory buffer used as a target for protobuf 
// serialization. Min is the starting value, while max is the growth limit.
// This imposes a limit to the number of bytes that can be sent out by
// the agent.
//
#define MIN_SERIALIZATION_BUF_SIZE_BYTES 32000
#define MAX_SERIALIZATION_BUF_SIZE_BYTES 32000000

//
// Controls if assertions break execution or if they are just printed to the
// log
//
#undef ASSERT_TO_LOG

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
