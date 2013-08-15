#include <stdio.h>

#include <scap.h>

int main(int argc, char **argv)
{
	scap_t* h;
	char error[SCAP_LASTERR_SIZE];
	int32_t res;
	scap_evt* ev;
	uint16_t cpuid;
	uint64_t ts = 0;
	uint64_t lastts = 0;
	uint64_t totevts = 0;
	uint64_t totoo = 0;

	if(argc == 1)
	{
		h = scap_open_live(error);
	}
	else
	{
		h = scap_open_offline(argv[1], error);
	}

	if(h == NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}

	//
	// Stop scap from tracking state. We don't need it for this test.
	//
	scap_track_state(h, false);

	while(1)
	{
		res = scap_next(h, &ev, &cpuid);

		if(res == SCAP_TIMEOUT)
		{
			continue;
		}

		if(res != SCAP_SUCCESS)
		{
			fprintf(stderr, "%s\n", scap_getlasterr(h));
			scap_close(h);
			return -1;
		}

		totevts++;

		ts = scap_event_get_ts(ev);
		if(ts < lastts)
		{
			totoo++;

			fprintf(stderr, "out of order, curr:%llu prev:%llu, n evts:%llu, n out of order:%llu \n",
			        ts,
			        lastts,
			        totevts,
			        totoo);
		}

		lastts = ts;

		if(totevts % 1000 == 0)
		{
			printf("%"PRIu64" events\n", totevts);
		}
	}

	scap_close(h);
	return 0;
}
