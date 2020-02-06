#define __STDC_FORMAT_MACROS

#include "analyzer.h"
#include "analyzer_int.h"
#include "analyzer_parsers.h"
#include "metrics.h"
#include "parsers.h"
#include "sinsp.h"
#include "sinsp_int.h"

#include "../../driver/ppm_ringbuffer.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#undef min
#undef max
#include "analyzer_fd.h"
#include "analyzer_thread.h"
#include "delays.h"
#include "draios.pb.h"
#include "infrastructure_state.h"
#include "procfs_parser.h"
#include "sched_analyzer.h"
#include "scores.h"
#include "sinsp_errno.h"

#include <Poco/Path.h>

namespace
{
std::string get_command_basename(std::string command)
{
	// Trim trailing whitespace from command
	command.erase(
	    std::find_if(command.rbegin(), command.rend(), std::bind1st(std::not_equal_to<char>(), ' '))
	        .base(),
	    command.end());

	if (command.find(" ") != std::string::npos)
	{
		std::stringstream sstream(command);
		std::string first_token;
		std::string rest;

		if (std::getline(sstream, first_token, ' ') && std::getline(sstream, rest))
		{
			Poco::Path cmd_path(first_token);

			return cmd_path.getBaseName() + " " + rest;
		}

		// Really ought not get here, maybe ASSERT()?.
		return command;
	}

	Poco::Path cmd_path(command);

	return cmd_path.getBaseName();
}

/**
 * strcmp_relative_path compares two commands, including parameters,
 * that can be passed with different absolute paths
 * e.g. (return true)
 * std::string a = "/bin/bash ./ready.sh 1 2 3";
 * std::string b = "/usr/bin/bash ./ready.sh 1 2 3";
 *
 * @param[in] a first command to compare
 * @param[in] b second command to compare
 */
bool strcmp_relative_path(const std::string& a, const std::string& b)
{
	return get_command_basename(a) == get_command_basename(b);
}

void populate_cmdline_exe(std::string& cmdline_exe, sinsp_threadinfo* tinfo)
{
	cmdline_exe = tinfo->m_exe;

	const std::size_t nargs = tinfo->m_args.size();

	for (size_t j = 0; j < nargs; j++)
	{
		cmdline_exe += " " + tinfo->m_args[j];
	}
}
}  // namespace

sinsp_analyzer_parsers::sinsp_analyzer_parsers(sinsp_analyzer* const analyzer)
    : m_analyzer(analyzer),
      m_sched_analyzer2(nullptr),
      m_last_drop_was_enter(false)
{
}

//
// This is similar to sinsp_parser::process_event, but it's for draios-only event
// processing. Returns false if process_event() should return immediately.
//
bool sinsp_analyzer_parsers::process_event(sinsp_evt* evt)
{
	uint16_t etype = evt->get_type();

	switch (etype)
	{
	case PPME_SCHEDSWITCH_1_E:
	case PPME_SCHEDSWITCH_6_E:
		if (m_analyzer->get_thread_count() < DROP_SCHED_ANALYZER_THRESHOLD)
		{
			m_sched_analyzer2->process_event(evt);
		}
		return false;
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_5_X:
		parse_accept_exit(evt);
		;
		return true;
	case PPME_SYSCALL_SELECT_X:
	case PPME_SYSCALL_POLL_X:
	case PPME_SYSCALL_EPOLLWAIT_X:
		parse_select_poll_epollwait_exit(evt);
		return true;
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		return parse_clone_exit(evt);
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
		return parse_execve_exit(evt);
	case PPME_DROP_E:
		if (!m_last_drop_was_enter)
		{
			parse_drop(evt);
			m_analyzer->simulate_drop_mode(true);

			m_analyzer->flush(evt, evt->get_ts(), false, analyzer_emitter::DF_FORCE_FLUSH);

			m_last_drop_was_enter = true;
		}

		return false;
	case PPME_DROP_X:
		if (m_last_drop_was_enter)
		{
			parse_drop(evt);
			m_analyzer->simulate_drop_mode(false);

			m_analyzer->flush(evt,
			                  evt->get_ts(),
			                  false,
			                  analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT);

			m_last_drop_was_enter = false;
		}

		return false;

	case PPME_SYSDIGEVENT_E:
		return false;
	case PPME_CONTAINER_E:
		return false;
	default:
		return true;
	}
}

void sinsp_analyzer_parsers::set_sched_analyzer2(sinsp_sched_analyzer2* const sched_analyzer2)
{
	m_sched_analyzer2 = sched_analyzer2;
}

void sinsp_analyzer_parsers::parse_accept_exit(sinsp_evt* evt)
{
	//
	// Extract the request queue length
	//
	sinsp_evt_param* parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint8_t));
	uint8_t queueratio = *(uint8_t*)parinfo->m_val;
	ASSERT(queueratio <= 100);

	if (evt->m_tinfo == NULL)
	{
		return;
	}

	if (queueratio > evt->m_tinfo->m_ainfo->m_connection_queue_usage_pct)
	{
		evt->m_tinfo->m_ainfo->m_connection_queue_usage_pct = queueratio;
	}

	//
	// If this comes after a wait, reset the last wait time, since we don't count
	// time waiting for an accept as I/O time
	//
	evt->m_tinfo->m_ainfo->m_last_wait_duration_ns = 0;
}

void sinsp_analyzer_parsers::parse_select_poll_epollwait_exit(sinsp_evt* evt)
{
	sinsp_evt_param* parinfo;
	int64_t retval;
	uint16_t etype = evt->get_type();

	if (evt->m_tinfo == NULL)
	{
		return;
	}

	if (etype != evt->m_tinfo->m_lastevent_type + 1)
	{
		//
		// Packet drop. Previuos event didn't have a chance to
		//
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t*)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if (retval >= 0)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;

		if (tinfo == NULL)
		{
			ASSERT(false);
			return;
		}

		if (tinfo->is_lastevent_data_valid() && evt->m_tinfo->m_lastevent_data)
		{
			//
			// We categorize this based on the next I/O operation only if the number of
			// FDs that were waited for is 1
			//
			if (retval == 0)
			{
				tinfo->m_ainfo->m_last_wait_duration_ns = 0;
			}
			else
			{
				//
				// If this was a wait on a *single* fd, we can easily categorize it with certainty
				// and we encode the delta as a positive number. If this was a wait on multiple FDs,
				// we encode the delta as a negative number so the next steps will know that it
				// needs to be handled with more care.
				//
				uint64_t sample_duration = m_analyzer->get_sample_duration();
				uint64_t ts = evt->get_ts();

				tinfo->m_ainfo->m_last_wait_end_time_ns = ts;
				uint64_t start_time_ns =
				    MAX(ts - ts % sample_duration, *(uint64_t*)evt->m_tinfo->m_lastevent_data);

				if (retval == 1)
				{
					tinfo->m_ainfo->m_last_wait_duration_ns = ts - start_time_ns;
				}
				else
				{
					tinfo->m_ainfo->m_last_wait_duration_ns = start_time_ns - ts;
				}
			}
		}
	}
}

bool sinsp_analyzer_parsers::parse_clone_exit(sinsp_evt* evt)
{
	//
	// For now this only sets the AF_IS_DESCENDENT_OF_CONTAINER_INIT flag, which is only used by
	// Secure Audit, therefore we can avoid running it at all if secure audit is not enabled.
	//
	const sinsp_configuration* sinsp_conf = m_analyzer->get_configuration_read_only();

	if (!sinsp_conf->get_executed_commands_capture_enabled())
	{
		return true;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if (tinfo == nullptr)
	{
		return true;
	}

	//
	// Set the AF_IS_DESCENDANT_OF_CONTAINER_INIT flag to any child of a container init (vpid 1)
	// and propagate the flag to all descendant processes
	//

	// Discard clone calls that create threads of an existing process
	if (!tinfo->is_main_thread())
	{
		return true;
	}

	sinsp_threadinfo* ptinfo = tinfo->get_parent_thread();
	if (ptinfo == nullptr)
	{
		return true;
	}

	auto tainfo = tinfo->m_ainfo;
	if (tainfo == nullptr)
	{
		return true;
	}

	// Set the flag for children of container init processes
	if (ptinfo->m_vpid != ptinfo->m_pid && !ptinfo->m_container_id.empty() && ptinfo->m_vpid == 1)
	{
		tainfo->m_th_analysis_flags |=
		    thread_analyzer_info::flags::AF_IS_DESCENDANT_OF_CONTAINER_INIT;
		return true;
	}

	if (!ptinfo->is_main_thread())
	{
		ptinfo = ptinfo->get_main_thread();
	}

	auto ptainfo = ptinfo->m_ainfo;
	if (ptainfo == nullptr)
	{
		return true;
	}

	// Propagate the flag to their child processes
	if (ptainfo->m_th_analysis_flags &
	    thread_analyzer_info::flags::AF_IS_DESCENDANT_OF_CONTAINER_INIT)
	{
		tainfo->m_th_analysis_flags |=
		    thread_analyzer_info::flags::AF_IS_DESCENDANT_OF_CONTAINER_INIT;
		return true;
	}

	return true;
}

bool sinsp_analyzer_parsers::parse_execve_exit(sinsp_evt* evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if (tinfo == NULL)
	{
		return true;
	}

	//
	// Check the result of the call
	//
	sinsp_evt_param* parinfo;
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t res = *(int64_t*)parinfo->m_val;

	if (res < 0)
	{
		return true;
	}

	thread_analyzer_info* tainfo = evt->m_tinfo->m_ainfo;
	tainfo->m_called_execve = true;

	const sinsp_configuration* sinsp_conf = m_analyzer->get_configuration_read_only();

	//
	// Detect if this is a stress tool and in that case request to go in nodriver mode
	//
	if (m_analyzer->detect_and_match_stress_tool(tinfo->m_comm))
	{
		return true;
	}

	//
	// If executed commands capture is disabled, we stop here
	// and we don't record commands executed by the user
	//
	// executed commands capture can be enabled by
	// - commandlines_capture/enabled - "old" way to send executed commands
	// - secure_audit/executed_commands - "new" audit feature
	//
	if (!sinsp_conf->get_executed_commands_capture_enabled())
	{
		return true;
	}

	//
	// Navigate the parent processes to determine if this is the descendent of a shell
	// and if yes what's the shell ID
	//
	uint32_t shell_dist = 0;
	uint64_t login_shell_id = 0;
	uint32_t cur_dist = 0;
	bool valid_ancestor = false;
	bool found_container_init = false;

	sinsp_threadinfo::visitor_func_t visitor = [sinsp_conf,
	                                            &login_shell_id,
	                                            &shell_dist,
	                                            &cur_dist,
	                                            &valid_ancestor,
	                                            &found_container_init](sinsp_threadinfo* ptinfo) {
		if (cur_dist && sinsp_conf->is_command_lines_valid_ancestor(ptinfo->m_comm))
		{
			valid_ancestor = true;
		}

		if (ptinfo->m_vpid == 1 && !ptinfo->m_container_id.empty())
		{
			found_container_init = true;
		}

		uint32_t cl = ptinfo->m_comm.size();
		if (cl >= 2 && ptinfo->m_comm[cl - 2] == 's' && ptinfo->m_comm[cl - 1] == 'h')
		{
			login_shell_id = ptinfo->m_tid;
			shell_dist = cur_dist;
		}

		cur_dist++;
		return true;
	};

	found_container_init |=
	    ((tainfo->m_th_analysis_flags &
	      thread_analyzer_info::flags::AF_IS_DESCENDANT_OF_CONTAINER_INIT) != 0);

	if (visitor(tinfo))
	{
		tinfo->traverse_parent_state(visitor);
	}

	// If the parents chain is broken, ignore login_shell_id and shell_dist because not meaningful
	if (tinfo->m_parent_loop_detected)
	{
		login_shell_id = 0;
		shell_dist = 0;
	}

	bool mode_ok = false;
	switch (sinsp_conf->get_command_lines_capture_mode())
	{
	case sinsp_configuration::command_capture_mode_t::CM_TTY:
		if (tinfo->m_tty)
		{
			mode_ok = true;
		}
		break;
	case sinsp_configuration::command_capture_mode_t::CM_SHELL_ANCESTOR:
		if (login_shell_id)
		{
			mode_ok = true;
		}
		break;
	case sinsp_configuration::command_capture_mode_t::CM_ALL:
		mode_ok = true;
		break;
	default:
		ASSERT(false);
	}

	//
	// Let a process show up if it was executed inside a container but
	// doesn't have the container init as parent (and it's in a separate
	// pid ns), very likely it comes from docker exec
	//
	bool container_exec = false;
	if (!tinfo->m_container_id.empty() && !found_container_init && tinfo->m_vpid != tinfo->m_pid)
	{
		container_exec = true;
	}

	//
	// Only allow this function to continue if ANY of the following conditions holds true:
	// - mode_ok: this is an interactive process according to config (e.g. we want processes w/ TTYs
	// and this has a TTY)
	// - valid_ancestor: it's a descendant of a process that is one of valid_ancestors in the config
	// - container_exec: it's running in a container and is not a descendant of the container init
	//
	if (!mode_ok && !valid_ancestor && !container_exec)
	{
		return true;
	}

	lookup_k8s_probes(tinfo);

	m_analyzer->incr_command_lines_category(convert_category(tinfo->m_category));

	if (tinfo->is_health_probe() && !sinsp_conf->get_command_lines_include_container_healthchecks())
	{
		return true;
	}

	// store AF_IS_INTERACTIVE_COMMAND in thread_analyzer_info
	if (!tinfo->is_health_probe())
	{
		sinsp_threadinfo* main_thread = tinfo->get_main_thread();
		if (main_thread != nullptr && main_thread->m_ainfo != nullptr)
		{
			main_thread->m_ainfo->m_th_analysis_flags |=
			    thread_analyzer_info::flags::AF_IS_INTERACTIVE_COMMAND;
		}
	}

	//
	// Allocated an executed command storage info and initialize it
	//
	sinsp_executed_command cmdinfo;

	if (tinfo->m_clone_ts != 0)
	{
		cmdinfo.m_ts = tinfo->m_clone_ts;
	}
	else
	{
		cmdinfo.m_ts = evt->get_ts();
	}

	cmdinfo.m_cmdline = tinfo->m_comm;
	cmdinfo.m_exe = tinfo->m_exe;
	cmdinfo.m_comm = tinfo->m_comm;
	cmdinfo.m_pid = tinfo->m_pid;
	cmdinfo.m_ppid = tinfo->m_ptid;
	cmdinfo.m_uid = tinfo->m_uid;
	cmdinfo.m_cwd = tinfo->m_cwd;
	cmdinfo.m_tty = tinfo->m_tty;
	cmdinfo.m_category = convert_category(tinfo->m_category);

	//
	// Build the arguments string
	//
	uint32_t nargs = tinfo->m_args.size();

	for (uint32_t j = 0; j < nargs; j++)
	{
		cmdinfo.m_cmdline += ' ';
		cmdinfo.m_cmdline += tinfo->m_args[j];
	}

	cmdinfo.m_shell_id = login_shell_id;
	cmdinfo.m_login_shell_distance = shell_dist;

	//
	// Determine if this command was executed in a pipe and if yes
	// where it belongs in the pipe
	//
	if ((tinfo->m_flags & (PPM_CL_PIPE_SRC | PPM_CL_PIPE_DST)) ==
	    (PPM_CL_PIPE_SRC | PPM_CL_PIPE_DST))
	{
		cmdinfo.m_flags |= sinsp_executed_command::FL_PIPE_MIDDLE;
	}
	else if ((tinfo->m_flags & (PPM_CL_PIPE_SRC)) == (PPM_CL_PIPE_SRC))
	{
		cmdinfo.m_flags |= sinsp_executed_command::FL_PIPE_HEAD;
	}
	else if ((tinfo->m_flags & (PPM_CL_PIPE_DST)) == (PPM_CL_PIPE_DST))
	{
		cmdinfo.m_flags |= sinsp_executed_command::FL_PIPE_TAIL;
	}

	m_analyzer->add_executed_command(tinfo->m_container_id, cmdinfo);

	return true;
}

void sinsp_analyzer_parsers::parse_drop(sinsp_evt* evt)
{
	m_analyzer->set_last_dropmode_switch_time(evt->get_ts());

	//
	// If required, update the sample length
	//
	sinsp_evt_param* parinfo;
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int32_t));

	if (*(uint32_t*)parinfo->m_val != m_analyzer->get_acked_sampling_ratio())
	{
		g_logger.format(sinsp_logger::SEV_INFO,
		                "sinsp Switching sampling ratio from % " PRIu32 " to %" PRIu32,
		                m_analyzer->get_acked_sampling_ratio(),
		                *(uint32_t*)parinfo->m_val);
	}

	m_analyzer->ack_sampling_ratio(*(uint32_t*)parinfo->m_val);
}

draiosproto::command_category sinsp_analyzer_parsers::convert_category(
    sinsp_threadinfo::command_category& tcat)
{
	// Explicitly converting to point out mismatches
	draiosproto::command_category cat;

	switch (tcat)
	{
	case sinsp_threadinfo::CAT_NONE:
		cat = draiosproto::CAT_NONE;
		break;
	case sinsp_threadinfo::CAT_CONTAINER:
		cat = draiosproto::CAT_CONTAINER;
		break;
	case sinsp_threadinfo::CAT_HEALTHCHECK:
		cat = draiosproto::CAT_HEALTHCHECK;
		break;
	case sinsp_threadinfo::CAT_LIVENESS_PROBE:
		cat = draiosproto::CAT_LIVENESS_PROBE;
		break;
	case sinsp_threadinfo::CAT_READINESS_PROBE:
		cat = draiosproto::CAT_READINESS_PROBE;
		break;
	default:
		g_logger.format(sinsp_logger::SEV_ERROR,
		                "Unknown command category %d, using CAT_NONE",
		                tcat);
		cat = draiosproto::CAT_NONE;
	}

	return cat;
}

void sinsp_analyzer_parsers::lookup_k8s_probes(sinsp_threadinfo* tinfo)
{
	std::pair<std::string, std::string> entry = std::make_pair("container", tinfo->m_container_id);

	std::string value_readiness;
	std::string value_liveness;

	bool found_liveness = m_analyzer->infra_state()->find_tag(
	    entry,
	    "kubernetes.pod.probe.liveness." + tinfo->m_container_id,
	    value_liveness);
	bool found_readiness = m_analyzer->infra_state()->find_tag(
	    entry,
	    "kubernetes.pod.probe.readiness." + tinfo->m_container_id,
	    value_readiness);

	if (!found_liveness && !found_readiness)
	{
		return;
	}

	// populate commandline using m_exe
	// in case of long m_comm this avoids to cut the string at 30 chars
	std::string cmdline_exe;
	populate_cmdline_exe(cmdline_exe, tinfo);

	// populate commandline using m_comm
	std::string cmdline_comm;
	sinsp_threadinfo::populate_cmdline(cmdline_comm, tinfo);

	if (found_liveness)
	{
		if (strcmp_relative_path(cmdline_exe, value_liveness) ||
		    strcmp_relative_path(cmdline_comm, value_liveness))
		{
			tinfo->m_category = sinsp_threadinfo::CAT_LIVENESS_PROBE;
		}
	}

	if (found_readiness)
	{
		if (strcmp_relative_path(cmdline_exe, value_readiness) ||
		    strcmp_relative_path(cmdline_comm, value_readiness))
		{
			tinfo->m_category = sinsp_threadinfo::CAT_READINESS_PROBE;
		}
	}
}
