#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#pragma warning(disable: 4996)
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#endif

static inline string clone_flags_to_str(uint32_t flags);

bool ctrl_c_pressed = false;

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

//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector, 
					   uint64_t cnt, 
					   bool quiet, 
					   bool absolute_times,
					   uint64_t emit_stats_every_x_sec)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	uint64_t n_printed_evts = 0;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
	uint64_t screents;
	uint32_t j;

	//
	// Loop through the events
	//
	while(1)
	{
		if(retval.m_nevts == cnt || ctrl_c_pressed)
		{
			break;
		}

		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			cerr << "res = " << res << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		retval.m_nevts++;

		ts = ev->get_ts();
		if(firstts == 0)
		{
			firstts = ts;
		}
		deltats = ts - firstts;

		if(absolute_times)
		{
			screents = ts;
		}
		else
		{
			screents = deltats;
		}

		//
		// When the quiet flag is specified, we don't do any kind of processing other
		// than counting the events.
		//
		if(quiet)
		{
			continue;
		}

		//
		// Output the line
		//
		sinsp_threadinfo* tinfo = ev->get_thread_info();

		n_printed_evts++;

		printf("%" PRIu64 ")%" PRIu64 ".%09" PRIu64 " %s (%" PRId64 ") %s %s",
			    inspector->get_num_events(),
			    screents / 1000000000,
			    screents % 1000000000,
			    (tinfo)?tinfo->get_comm().c_str():"<NA>",
			    ev->get_tid(),
			    (ev->get_direction() == SCAP_ED_IN)? ">" : "<",
			    ev->get_name()
			    );

		for(j = 0; j < ev->get_num_params(); j++)
		{
			if(ev->get_type() == 15 && j == 7)	// Custom treatment for CLONE_EXIT
			{
				sinsp_evt_param* param = ev->get_param(j);
				int32_t val = *(int32_t*)param->m_val;
				printf(" %s=(%u)%s", ev->get_param_name(j), val, clone_flags_to_str(val).c_str());
			}
			else
			{
				const char* paramstr;
				const char* resolved_paramstr;

				paramstr = ev->get_param_as_str(j, &resolved_paramstr);

				if(resolved_paramstr[0] == 0)
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

	retval.m_time = deltats;
	return retval;
}

static void usage(char *program_name)
{
	fprintf(stderr, "%s [ -r filename ]\n", program_name);
}

//
// MAIN
//
int main(int argc, char **argv)
{
	char *infile = NULL;
	int op;
	uint64_t cnt = -1;
	bool emitjson = false;
	bool quiet = false;
	bool get_stats = false;
	bool absolute_times = false;
	char* transact_fname = NULL;
	double duration = 1;
	captureinfo cinfo;
	string dumpfile;


	{
		sinsp inspector;
inspector.set_events_formatting("ciao  %evt.numaa%evt.num");

		//
		// Parse the args
		//
		while((op = getopt(argc, argv, "ac:f:jl:o:qr:w:")) != -1)
		{
			switch (op)
			{
			case 'a':
				absolute_times = true;
				break;
			case 'c':
				cnt = atoi(optarg);
				if(cnt <= 0)
				{
					fprintf(stderr, "invalid packet count %s\n", optarg);
					return -1;
				}
				break;
			case 'j':
				emitjson = true;
				break;
			case 'l':
				if(string(optarg) == "stdout")
				{
					inspector.get_configuration()->set_log_output_type(sinsp_logger::OT_STDOUT);
				}
				else if(string(optarg) == "stderr")
				{
					inspector.get_configuration()->set_log_output_type(sinsp_logger::OT_STDERR);
				}
				else if(string(optarg) == "file")
				{
					inspector.get_configuration()->set_log_output_type(sinsp_logger::OT_FILE);
				}
				else
				{
					fprintf(stderr, "wrong -l option %s. Accepted values: stdout, sterr or file.", optarg);
					return -1;
				}

				break;
			case 'o':
				inspector.set_events_formatting(optarg);
				break;
			case 'r':
				infile = optarg;
				break;
			case 'q':
				quiet = true;
				break;
			case 'w':
				dumpfile = optarg;
				break;
			default:
				usage(argv[0]);
				return 0;
			}
		}

		//
		// the filter is specified at the end of the command line
		//
		if(optind < argc)
		{
#ifdef _DEBUG
			string filter;

			for(int32_t j = optind; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc)
				{
					filter += " ";
				}
			}

			inspector.set_filter(filter);
#else
			fprintf(stderr, "filtering not supported in release mode.\n");
			return -1;				
#endif
		}

		//
		// Set the CRTL+C signal
		//
		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting a signal handler.\n");
			return EXIT_FAILURE;
		}

		//
		// Launch the inspeciotn
		//
		try
		{
			if(infile)
			{
				inspector.open(infile);
			}
			else
			{
				inspector.open("");
			}

			if(dumpfile != "")
			{
				inspector.start_dump(dumpfile);
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;
			
			cinfo = do_inspect(&inspector, 
				cnt, 
				quiet, 
				get_stats, 
				absolute_times);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;
		}
		catch(sinsp_exception e)
		{
			if(emitjson)
			{
				printf("]\n");
			}

			cerr << e.what() << endl;
		}
		catch(...)
		{
		}

		//
		// If specified on the command line, save the transactions
		//
		if(transact_fname)
		{
			try
			{
				sinsp_transaction_table* ttable = inspector.get_transactions();
				if(ttable)
				{
					ttable->save_json(transact_fname);
				}
				else
				{
					cerr << "error retrieving the transaction table" << endl;
				}
			}
			catch(sinsp_exception e)
			{
				cerr << e.what() << endl;
			}
			catch(...)
			{
			}
		}

		fprintf(stderr, "Elapsed time: %.3lf, %" PRIu64 " events, %.2lf eps\n",
			duration,
			cinfo.m_nevts,
			(double)cinfo.m_nevts / duration);

		fprintf(stderr, "Capture duration: %" PRIu64 ".%" PRIu64 ", %.2lf eps\n",
			cinfo.m_time / 1000000000,
			cinfo.m_time % 1000000000,
			(double)cinfo.m_nevts * 1000000000 / cinfo.m_time);

		if(get_stats)
		{
			inspector.get_stats().emit(stderr);
		}
	}

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif
}

static inline string clone_flags_to_str(uint32_t flags)
{
	string res;

	if(flags & PPM_CL_CLONE_FILES)
	{
		res += "|CLONE_FILES";
	}

	if(flags & PPM_CL_CLONE_FS)
	{
		res += "|CLONE_FS";
	}

	if(flags & PPM_CL_CLONE_IO)
	{
		res += "|CLONE_IO";
	}

	if(flags & PPM_CL_CLONE_NEWIPC)
	{
		res += "|CLONE_NEWIPC";
	}

	if(flags & PPM_CL_CLONE_NEWNET)
	{
		res += "|CLONE_NEWNET";
	}

	if(flags & PPM_CL_CLONE_NEWNS)
	{
		res += "|CLONE_NEWNS";
	}

	if(flags & PPM_CL_CLONE_NEWPID)
	{
		res += "|CLONE_NEWPID";
	}

	if(flags & PPM_CL_CLONE_NEWUTS)
	{
		res += "|CLONE_NEWUTS";
	}

	if(flags & PPM_CL_CLONE_PARENT_SETTID)
	{
		res += "|CLONE_PARENT_SETTID";
	}

	if(flags & PPM_CL_CLONE_PARENT)
	{
		res += "|CLONE_PARENT";
	}

	if(flags & PPM_CL_CLONE_PTRACE)
	{
		res += "|CLONE_PTRACE";
	}

	if(flags & PPM_CL_CLONE_SIGHAND)
	{
		res += "|CLONE_SIGHAND";
	}

	if(flags & PPM_CL_CLONE_SYSVSEM)
	{
		res += "|CLONE_SYSVSEM";
	}

	if(flags & PPM_CL_CLONE_THREAD)
	{
		res += "|CLONE_THREAD";
	}

	if(flags & PPM_CL_CLONE_UNTRACED)
	{
		res += "|CLONE_UNTRACED";
	}

	if(flags & PPM_CL_CLONE_VM)
	{
		res += "|CLONE_VM";
	}

	return res;
}
