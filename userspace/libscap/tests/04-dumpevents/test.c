#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#ifdef _WIN32
#include "win32/getopt.h"
#else
#include <unistd.h>
#endif

#include <scap.h>

scap_dumper_t* g_dumper = NULL;	// Hate this, but need to access the variable from a signal handler

static void usage(char *program_name)
{
	fprintf(stderr, "%s [ -w filename ]\n", program_name);
}

static void signal_callback(int signal)
{
	if(g_dumper)
	{
		printf("Closing capture file\n");
		scap_dump_close(g_dumper);
		exit(0);
	}
}

int main(int argc, char **argv)
{
	scap_t* h;
	uint64_t cnt = -1;
	uint64_t nevts = 0;
	char error[SCAP_LASTERR_SIZE];
	int32_t res;
	scap_evt* ev;
	uint16_t cpuid;
	char *outfile = NULL;
	char *infile = NULL;
	int op;

	//
	// Parse the args
	//
	while((op = getopt(argc, argv, "c:s:r:w:")) != -1)
	{
		switch (op)
		{
		case 'c':
			cnt = atoi(optarg);
			if(cnt <= 0)
			{
				fprintf(stderr, "invalid packet count %s", optarg);
			}
			break;
		case 'r':
			infile = optarg;
			break;
		case 'w':
			outfile = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	//
	// Start live capture
	//
	if(infile)
	{
		h = scap_open_offline(infile, error);
	}
	else
	{
		h = scap_open_live(error);
	}

	if(h == NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}

	//
	// If an output file has been specified, save the packets to disk
	//
	if(outfile)
	{
		g_dumper = scap_dump_open(h, outfile);
//		scap_track_state(h, false);

		if(!g_dumper)
		{
			fprintf(stderr, "scap_dump_open failure: %s\n", scap_getlasterr(h));
			return -1;
		}
	}

	//
	// Set the CRTL+C signal
	//
	if (signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fputs("An error occurred while setting a signal handler.\n", stderr);
		return EXIT_FAILURE;
	}

	while(1)
	{
		res = scap_next(h, &ev, &cpuid);

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
			fprintf(stderr, "%s\n", scap_getlasterr(h));
			scap_close(h);
			return -1;
		}

		nevts++;
		if(nevts == cnt)
		{
			break;
		}

		//
		// Filter based on the event type
		//
//		evtype = (uint32_t)scap_event_get_type(ev);
		/*
				if(evtype < 2)
				{
					continue;
				}
		*/
		/*
				if(evtype < 18 || evtype > 23)
				{
					continue;
				}
		*/
		//
		// If instructed to do so, write the event to file
		//
		if(g_dumper)
		{
			if(nevts % 1000 == 0)
			{
				scap_stats stats;

				scap_get_stats(h, &stats);

				printf("seen:%"PRIu64", saved:%"PRIu64", drops:%"PRIu64", preempts:%"PRIu64"\n",
						stats.n_evts,
						nevts,
						stats.n_drops,
						stats.n_preemptions);
			}
			scap_dump(h, g_dumper, ev, cpuid);
			continue;
		}
		else
		{
			//
			// Screen display is now done in the 01 libsinsp test
			//
			continue;
		}
	}

	scap_close(h);
	return 0;
}
