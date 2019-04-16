#pragma once

#ifdef HAS_ANALYZER

class sinsp_analyzer;
class sinsp_evt;
class sinsp_sched_analyzer2;

//
// Prototype of the callback invoked by the analyzer when a sample is ready
//
class sinsp_analyzer_parsers
{
public:
	sinsp_analyzer_parsers(sinsp_analyzer* analyzer);

	void parse_accept_exit(sinsp_evt* evt);
	void parse_select_poll_epollwait_exit(sinsp_evt *evt);
	bool parse_execve_exit(sinsp_evt* evt);
	void parse_drop(sinsp_evt* evt);

	bool process_event(sinsp_evt* evt);

	void set_sched_analyzer2(sinsp_sched_analyzer2* sched_analyzer2);

private:
	sinsp_analyzer* m_analyzer;
	sinsp_sched_analyzer2* m_sched_analyzer2;
	bool m_last_drop_was_enter;
};

#endif // HAS_ANALYZER

