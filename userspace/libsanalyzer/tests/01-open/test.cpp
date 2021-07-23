#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <sinsp_int.h>
#include <analyzer.h>
#include "chisel.h"
#include "settings.h"
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#pragma warning(disable : 4996)
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#endif

#include "audit_tap_handler.h"
#include "configuration_manager.h"

using namespace std;

static inline string clone_flags_to_str(uint32_t flags);

bool ctrl_c_pressed = false;
bool dropping_mode_enabled = true;
sinsp* g_inspector = NULL;
sinsp_analyzer* g_analyzer = NULL;

static void signal_callback(int signal)
{
	ctrl_c_pressed = true;
}

class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

namespace
{
audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_audit_handler;
null_secure_profiling_handler g_secure_profiling_handler;
null_secure_netsec_handler g_secure_netsec_handler;
sinsp_analyzer::flush_queue g_queue(1000);
}

//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector,
                       uint64_t cnt,
                       bool emitjson,
                       bool quiet,
                       bool statistics,
                       bool absolute_times,
                       uint64_t emit_stats_every_x_sec,
                       uint64_t max_evts_in_file,
                       string dumpfile)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	uint64_t n_printed_evts = 0;
	//	uint32_t evtype;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
	uint64_t screents;
	uint32_t j;
#ifdef GATHER_INTERNAL_STATS
	uint64_t last_stat_ts = 0;
#endif

	if (emitjson)
	{
		printf("[\n");
	}

	//
	// Create the inspector
	//
	while (1)
	{
		if (retval.m_nevts == cnt || ctrl_c_pressed)
		{
			break;
		}

		res = inspector->next(&ev);

		if (res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if (res == SCAP_EOF)
		{
			break;
		}
		else if (res != SCAP_SUCCESS)
		{
			cerr << "res = " << res << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		retval.m_nevts++;

		ts = ev->get_ts();
		if (firstts == 0)
		{
			firstts = ts;
#ifdef GATHER_INTERNAL_STATS
			last_stat_ts = ts;
#endif
		}
		deltats = ts - firstts;

		if (absolute_times)
		{
			screents = ts;
		}
		else
		{
			screents = deltats;
		}

		//
		// Rotate the dump file if required
		//
		if (max_evts_in_file != 0)
		{
			if (retval.m_nevts % max_evts_in_file == max_evts_in_file - 1)
			{
				inspector->autodump_stop();
				inspector->autodump_start(dumpfile, true);
			}
		}

//
// Emit stats if needed
//
#ifdef GATHER_INTERNAL_STATS
		if (statistics && ((ts - last_stat_ts) > emit_stats_every_x_sec * ONE_SECOND_IN_NS))
		{
			printf("\n\n*************************************************");
			inspector->get_stats().emit(stderr);
			last_stat_ts = ts;
		}
#endif

		//
		// When the quiet flag is specified, we don't do any kind of processing other
		// than counting the events.
		//
		if (quiet)
		{
			continue;
		}

//
// Filter based on the event type
//
		//
		// Output the line
		//
		sinsp_threadinfo* tinfo = ev->get_thread_info();
		n_printed_evts++;

		if (emitjson)
		{
			uint32_t npars = ev->get_num_params();

			printf("%s {\"n\":%" PRIu64 ", \"ts\":%" PRIu64 ", \"comm\":\"%s\", \"tid\":%" PRIu64
			       ", \"dir\":\"%s\", \"name\":\"%s\"",
			       (n_printed_evts == 1) ? "" : ",\n",
			       inspector->get_num_events(),
			       ts,
			       (tinfo) ? tinfo->get_comm().c_str() : "<NA>",
			       ev->get_tid(),
			       (ev->get_direction() == SCAP_ED_IN) ? ">" : "<",
			       ev->get_name());

			printf(", \"pars\":{");

			for (j = 0; j < npars; j++)
			{
				const char* paramstr;
				const char* resolved_paramstr;

				paramstr = ev->get_param_as_str(j, &resolved_paramstr, sinsp_evt::PF_JSON);

				if (resolved_paramstr[0] == 0)
				{
					printf("\"%s\":{\"v\":\"%s\"}", ev->get_param_name(j), paramstr);
				}
				else
				{
					printf("\"%s\":{\"v\":\"%s\",\"r\":\"%s\"}",
					       ev->get_param_name(j),
					       paramstr,
					       resolved_paramstr);
				}

				if (j < npars - 1)
				{
					printf(", ");
				}
			}

			printf("}");
			printf("}");
		}
		else
		{
			printf("%" PRIu64 ")%" PRIu64 ".%09" PRIu64 " %" PRIu32 " %s (%" PRId64 ") %s %s",
			       inspector->get_num_events(),
			       screents / 1000000000,
			       screents % 1000000000,
			       (uint32_t)ev->get_cpuid(),
			       (tinfo) ? tinfo->get_comm().c_str() : "<NA>",
			       ev->get_tid(),
			       (ev->get_direction() == SCAP_ED_IN) ? ">" : "<",
			       ev->get_name());

			for (j = 0; j < ev->get_num_params(); j++)
			{
				if (ev->get_type() == 15 && j == 8)  // Custom treatment for CLONE_EXIT
				{
					sinsp_evt_param* param = ev->get_param(j);
					int32_t val = *(int32_t*)param->m_val;
					printf(
					    " %s=(%u)%s", ev->get_param_name(j), val, clone_flags_to_str(val).c_str());
				}
				else
				{
					const char* paramstr;
					const char* resolved_paramstr;

					paramstr = ev->get_param_as_str(j, &resolved_paramstr);

					if (resolved_paramstr[0] == 0)
					{
						printf(" %s=%s", ev->get_param_name(j), paramstr);
					}
					else
					{
						printf(" %s=%s(%s)", ev->get_param_name(j), paramstr, resolved_paramstr);
					}
				}
			}

			printf("\n");
		}
	}

	if (emitjson)
	{
		printf("]\n");
	}

	retval.m_time = deltats;
	return retval;
}

static void usage(char* program_name)
{
	fprintf(stderr, "%s [ -r filename ]\n", program_name);
}

//
// Parse the command line following a chisel to consume the chisel command line.
// We use the following strategy:
//  - if the chisel has no arguments, we don't consume anything
//  - if the chisel has at least one required argument, we consume the next command line token
//  - if the chisel has only optional arguments, we consume the next token, unless
//    - there is no next token
//    - the next token starts with a '-'
//    - the rest of the command line contains a valid filter
//
static void parse_chisel_args(sinsp_chisel* ch,
                              sinsp* inspector,
                              int optind,
                              int argc,
                              char** argv,
                              int32_t* n_filterargs)
{
	uint32_t nargs = ch->get_n_args();
	uint32_t nreqargs = ch->get_n_required_args();
	string args;

	if (nargs != 0)
	{
		if (optind > (int32_t)argc)
		{
			throw sinsp_exception("invalid number of arguments for chisel " + string(optarg) +
			                      ", " + to_string((long long int)nargs) + " expected.");
		}
		else if (optind < (int32_t)argc)
		{
			args = argv[optind];

			if (nreqargs != 0)
			{
				ch->set_args(args);
				(*n_filterargs)++;
			}
			else
			{
				if (args[0] != '-')
				{
					string testflt;

					for (int32_t j = optind; j < argc; j++)
					{
						testflt += argv[j];
						if (j < argc - 1)
						{
							testflt += " ";
						}
					}

					if (nargs == 1 && ch->get_lua_script_info()->m_args[0].m_type == "filter")
					{
						ch->set_args(args);
						(*n_filterargs)++;
					}
					else
					{
						try
						{
							sinsp_filter_compiler compiler(inspector, testflt);
							compiler.compile();
						}
						catch (...)
						{
							ch->set_args(args);
							(*n_filterargs)++;
						}
					}
				}
			}
		}
		else
		{
			if (nreqargs != 0)
			{
				throw sinsp_exception("missing arguments for chisel " + string(optarg));
			}
		}
	}
}

//
// MAIN
//
int main(int argc, char** argv)
{
	int res = EXIT_SUCCESS;
	char* infile = NULL;
	int op;
	uint64_t cnt = -1;
	bool emitjson = false;
	bool quiet = false;
	bool get_stats = false;
	bool absolute_times = false;
	bool verbose = false;
	double duration = 1;
	captureinfo cinfo;
	uint64_t emit_stats_every_x_sec = 0;
	string dumpfile;
	uint64_t max_evts_in_file = 0;
	int32_t n_filterargs = 0;

	{
		g_inspector = new sinsp();
		internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
		g_analyzer = new sinsp_analyzer(g_inspector,
						"/opt/draios",
						int_metrics,
						g_audit_handler,
						g_secure_audit_handler,
						g_secure_profiling_handler,
						g_secure_netsec_handler,
						&g_queue,
						[]()->bool{return true;});

		//
		// Parse the args
		//
		while ((op = getopt(argc, argv, "Aac:C:d:e:f:jl:m:M:np:qr:s:t:vw:W:")) != -1)
		{
			switch (op)
			{
				case 'a':
					absolute_times = true;
					break;
				case 'c':
				{
					sinsp_chisel* ch = new sinsp_chisel(g_inspector, optarg);
					parse_chisel_args(ch, g_inspector, optind, argc, argv, &n_filterargs);
					g_analyzer->add_chisel(ch);
				}
				break;
				case 't':
					g_inspector->m_thread_manager->set_max_thread_table_size(atoi(optarg));
					break;
				case 'C':
					g_analyzer->get_configuration()->set_customer_id(optarg);
					break;
				case 'e':
					configuration_manager::instance()
					    .get_mutable_config<uint64_t>("connection.timeout_ns")
					    ->set(atoi(optarg));
					break;
				case 'j':
					emitjson = true;
					break;
				case 'l':
					if (string(optarg) == "stdout")
					{
						g_logger.add_stdout_log();
					}
					else if (string(optarg) == "stderr")
					{
						g_logger.add_stderr_log();
					}
					else if (string(optarg) == "file")
					{
						g_logger.add_file_log("sinsp.log");
					}
					else if (string(optarg) == "stdout_nots")
					{
						g_logger.add_stdout_log();
						g_logger.disable_timestamps();
					}
					else if (string(optarg) == "stderr_nots")
					{
						g_logger.add_stderr_log();
						g_logger.disable_timestamps();
					}
					else if (string(optarg) == "file_nots")
					{
						g_logger.add_file_log("sinsp.log");
						g_logger.disable_timestamps();
					}
					else
					{
						fprintf(stderr,
						        "wrong -l option %s. Accepted values: stdout, sterr or file.",
						        optarg);
						delete g_analyzer;
						delete g_inspector;
						return EXIT_FAILURE;
					}
					break;
				case 'm':
					g_analyzer->set_metrics_dir(optarg);
					break;
				case 'M':
					g_analyzer->get_configuration()->set_machine_id(optarg);
					break;
				case 'n':
					cnt = atoi(optarg);
					if (cnt <= 0)
					{
						fprintf(stderr, "invalid packet count %s\n", optarg);
						delete g_inspector;
						delete g_analyzer;
						return EXIT_FAILURE;
					}
					break;
				case 'p':
					g_inspector->set_min_log_severity((sinsp_logger::severity)atoi(optarg));
					break;
				case 'r':
					infile = optarg;
					break;
				case 'q':
					quiet = true;
					break;
				case 's':
					get_stats = true;
					if (NULL != optarg)
					{
						emit_stats_every_x_sec = atoi(optarg);
					}
					if (0 == emit_stats_every_x_sec)
					{
						emit_stats_every_x_sec = 360000;
					}
					break;
				case 'v':
					verbose = true;
					break;
				case 'w':
					dumpfile = optarg;
					break;
				case 'W':
					max_evts_in_file = atoi(optarg);
					break;
				default:
					usage(argv[0]);
					delete g_inspector;
					delete g_analyzer;
					return EXIT_SUCCESS;
			}
		}

		//
		// the filter is specified at the end of the command line
		//
		if (optind < argc)
		{
#ifdef HAS_FILTERING
			string filter;

			for (int32_t j = optind; j < argc; j++)
			{
				filter += argv[j];
				if (j < argc)
				{
					filter += " ";
				}
			}

//			g_inspector->set_filter(filter);
#else
			fprintf(stderr, "filtering not supported.\n");
			delete g_inspector;
			delete g_analyzer;
			return EXIT_FAILURE;
#endif
		}

		//
		// Set the CRTL+C signal
		//
		if (signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting a signal handler.\n");
			delete g_inspector;
			delete g_analyzer;
			return EXIT_FAILURE;
		}

//
// Set the SIGUSR1 signal
//
		//
		// Launch the inspeciotn
		//
		try
		{
			g_analyzer->initialize_chisels();

			if (infile)
			{
				g_inspector->open(infile);
			}
			else
			{
#ifndef CYGWING_AGENT
				g_inspector->open("");
#else
				g_inspector->open_nodriver();
#endif
			}

			if (dumpfile != "")
			{
				g_inspector->autodump_start(dumpfile, true);
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;

			cinfo = do_inspect(g_inspector,
			                   cnt,
			                   emitjson,
			                   quiet,
			                   get_stats,
			                   absolute_times,
			                   emit_stats_every_x_sec,
			                   max_evts_in_file,
			                   dumpfile);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			char mrbuf[4096];
			g_analyzer->generate_memory_report(mrbuf, sizeof(mrbuf));
			fprintf(stderr, "%s", mrbuf);
		}
		catch (const sinsp_exception& e)
		{
			if (emitjson)
			{
				printf("]\n");
			}

			cerr << e.what() << endl;
			res = EXIT_FAILURE;
		}
		//		catch(...)
		//		{
		//			res = EXIT_FAILURE;
		//		}

		if (verbose)
		{
			fprintf(stderr,
			        "Elapsed time: %.3lf, %" PRIu64 " events, %.2lf eps\n",
			        duration,
			        cinfo.m_nevts,
			        (double)cinfo.m_nevts / duration);
		}

// fprintf(stderr, "Capture duration: %" PRIu64 ".%" PRIu64 ", %.2lf eps\n",
//	cinfo.m_time / 1000000000,
//	cinfo.m_time % 1000000000,
//	(double)cinfo.m_nevts * 1000000000 / cinfo.m_time);
#ifdef GATHER_INTERNAL_STATS
		if (get_stats)
		{
			g_inspector->get_stats().emit(stderr);
		}
#endif

		delete g_inspector;
		delete g_analyzer;
	}

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif
	return res;
}

static inline string clone_flags_to_str(uint32_t flags)
{
	string res;

	if (flags & PPM_CL_CLONE_FILES)
	{
		res += "|CLONE_FILES";
	}

	if (flags & PPM_CL_CLONE_FS)
	{
		res += "|CLONE_FS";
	}

	if (flags & PPM_CL_CLONE_IO)
	{
		res += "|CLONE_IO";
	}

	if (flags & PPM_CL_CLONE_NEWIPC)
	{
		res += "|CLONE_NEWIPC";
	}

	if (flags & PPM_CL_CLONE_NEWNET)
	{
		res += "|CLONE_NEWNET";
	}

	if (flags & PPM_CL_CLONE_NEWNS)
	{
		res += "|CLONE_NEWNS";
	}

	if (flags & PPM_CL_CLONE_NEWPID)
	{
		res += "|CLONE_NEWPID";
	}

	if (flags & PPM_CL_CLONE_NEWUTS)
	{
		res += "|CLONE_NEWUTS";
	}

	if (flags & PPM_CL_CLONE_PARENT_SETTID)
	{
		res += "|CLONE_PARENT_SETTID";
	}

	if (flags & PPM_CL_CLONE_PARENT)
	{
		res += "|CLONE_PARENT";
	}

	if (flags & PPM_CL_CLONE_PTRACE)
	{
		res += "|CLONE_PTRACE";
	}

	if (flags & PPM_CL_CLONE_SIGHAND)
	{
		res += "|CLONE_SIGHAND";
	}

	if (flags & PPM_CL_CLONE_SYSVSEM)
	{
		res += "|CLONE_SYSVSEM";
	}

	if (flags & PPM_CL_CLONE_THREAD)
	{
		res += "|CLONE_THREAD";
	}

	if (flags & PPM_CL_CLONE_UNTRACED)
	{
		res += "|CLONE_UNTRACED";
	}

	if (flags & PPM_CL_CLONE_VM)
	{
		res += "|CLONE_VM";
	}

	return res;
}
