#pragma once

// A temporary define used to aid in staging the transition from one to the other.
// Will be removed when transition to thread_analyzer_info is complete
#ifdef USE_AGENT_THREAD
#define THREAD_TYPE thread_analyzer_info
#define GET_AGENT_THREAD(thread) (thread) 
#define GET_SINSP_THREAD(thread) (thread)
#else
#define THREAD_TYPE sinsp_threadinfo
#define GET_AGENT_THREAD(thread) (thread)->m_ainfo
#define GET_SINSP_THREAD(thread) (thread)->m_tinfo
#endif

