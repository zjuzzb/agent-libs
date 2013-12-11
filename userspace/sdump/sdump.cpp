#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

#ifdef _WIN32
#pragma warning(disable: 4996)
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#endif

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

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
					   uint64_t emit_stats_every_x_sec,
					   string format)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
//	uint64_t n_printed_evts = 0;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
	uint64_t screents;
	string line;
	sinsp_evt_formatter formatter(format, inspector);

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
		//ev->tostring(&line);
		formatter.tostring(ev, &line);

		cout << line << endl;
	}

	retval.m_time = deltats;
	return retval;
}

static void usage(char *program_name)
{
	fprintf(stderr, "%s [ -r filename ]\n", program_name);
}

#define DESCRITION_TEXT_START 15
#define CONSOLE_LINE_LEN 79

static void list_fields()
{
	uint32_t j, l, m;
	int32_t k;

	vector<const filter_check_info*> fc_plugins;
	sinsp::get_filtercheck_fields_info(&fc_plugins);

	for(j = 0; j < fc_plugins.size(); j++)
	{
		const filter_check_info* fci = fc_plugins[j];

		printf("\n----------------------\n");
		printf("Field Class: %s\n\n", fci->m_name.c_str());

		for(k = 0; k < fci->m_nfiedls; k++)
		{
			const filtercheck_field_info* fld = &fci->m_fields[k];

			printf("%s", fld->m_name);
			uint32_t namelen = strlen(fld->m_name);

			ASSERT(namelen > DESCRITION_TEXT_START);

			for(l = 0; l < DESCRITION_TEXT_START - namelen; l++)
			{
				printf(" ");
			}
				
			size_t desclen = strlen(fld->m_description);

			for(l = 0; l < desclen; l++)
			{
				if(l % (CONSOLE_LINE_LEN - DESCRITION_TEXT_START) == 0 && l != 0)
				{
					printf("\n");

					for(m = 0; m < DESCRITION_TEXT_START; m++)
					{
						printf(" ");
					}
				}

				printf("%c", fld->m_description[l]);
			}

			printf("\n");
		}
	}
}

//
// MAIN
//
int main(int argc, char **argv)
{
	int res = EXIT_SUCCESS;
	string infile;
	string outfile;
	int op;
	uint64_t cnt = -1;
	bool emitjson = false;
	bool quiet = false;
	bool get_stats = false;
	bool absolute_times = false;
	double duration = 1;
	captureinfo cinfo;
	string output_format;

	{
		sinsp inspector;
		output_format = "%evt.num)%evt.time.s.%evt.time.ns %evt.cpu %comm (%tid) %evt.dir %evt.name %evt.args";

		//
		// Parse the args
		//
		while((op = getopt(argc, argv, "ac:f:hi:jlqr:w:")) != -1)
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
					return EXIT_FAILURE;
				}
				break;
			case 'j':
				emitjson = true;
				break;
			case 'h':
				usage(argv[0]);
				return EXIT_SUCCESS;
			case 'f':
				if(string(optarg) == "f")
				{
					//
					// -ff shows the default output format, useful if the user wants to tweak it.
					//
					printf("%s", output_format.c_str());
					return EXIT_SUCCESS;
				}
				else
				{
					output_format = optarg;
				}
			case 'i':
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
				else if(string(optarg) == "stdout_nots")
				{
					inspector.get_configuration()->set_log_output_type((sinsp_logger::output_type)(sinsp_logger::OT_STDOUT | sinsp_logger::OT_NOTS));
				}
				else if(string(optarg) == "stderr_nots")
				{
					inspector.get_configuration()->set_log_output_type((sinsp_logger::output_type)(sinsp_logger::OT_STDERR | sinsp_logger::OT_NOTS));
				}
				else if(string(optarg) == "file_nots")
				{
					inspector.get_configuration()->set_log_output_type((sinsp_logger::output_type)(sinsp_logger::OT_FILE | sinsp_logger::OT_NOTS));
				}
				else
				{
					fprintf(stderr, "wrong -i option %s. Accepted values: stdout, sterr or file.", optarg);
					return -1;
				}

				break;
			case 'l':
				list_fields();
				return EXIT_SUCCESS;
			case 'r':
				infile = optarg;
				break;
			case 'q':
				quiet = true;
				break;
			case 'w':
				outfile = optarg;
				break;
			default:
				break;
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
			return EXIT_FAILURE;				
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
			if(infile != "")
			{
				inspector.open(infile);
			}
			else
			{
				inspector.open("");
			}

			if(outfile != "")
			{
				inspector.start_dump(outfile);
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;
			
			cinfo = do_inspect(&inspector, 
				cnt, 
				quiet, 
				get_stats, 
				absolute_times,
				output_format);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;
		}
		catch(sinsp_exception e)
		{
			if(emitjson)
			{
				printf("]\n");
			}

			cerr << e.what() << endl;
			res = EXIT_FAILURE;
		}
		catch(...)
		{
			res = EXIT_FAILURE;
		}

		//fprintf(stderr, "Elapsed time: %.3lf, %" PRIu64 " events, %.2lf eps\n",
		//	duration,
		//	cinfo.m_nevts,
		//	(double)cinfo.m_nevts / duration);

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

	return res;
}
