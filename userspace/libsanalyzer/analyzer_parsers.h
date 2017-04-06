#pragma once

#include <analyzer_int.h>

#ifdef HAS_ANALYZER

//
// Prototype of the callback invoked by the analyzer when a sample is ready
//
class sinsp_analyzer_parsers
{
public:
	sinsp_analyzer_parsers(sinsp_analyzer* analyzer);
	void on_capture_start();

	void parse_accept_exit(sinsp_evt* evt);
	void parse_select_poll_epollwait_exit(sinsp_evt *evt);
	void parse_execve_exit(sinsp_evt* evt);
	void parse_drop(sinsp_evt* evt);

	bool process_event(sinsp_evt* evt);

private:
	inline void patch_ancestor_chain(vector<thread_analyzer_info*>* ancestor_chain, 
		bool is_interactive, uint64_t session_id);
	void add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat);

	sinsp_analyzer* m_analyzer;
	sinsp_sched_analyzer2* m_sched_analyzer2;
	bool m_last_drop_was_enter;
};

#endif // HAS_ANALYZER

