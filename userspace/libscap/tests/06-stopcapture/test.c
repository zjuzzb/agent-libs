#include <stdio.h>
#include <unistd.h>

#include <scap.h>

#define N_EVENTS_TO_WAIT 100000

int main()
{
	char error[SCAP_LASTERR_SIZE];
	uint32_t j;
	int32_t res;
	scap_evt* ev;
	uint16_t cpuid;

	//
	// Start Capturing
	//
	scap_t* h = scap_open_live(error);
	if(h == NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}

	//
	// Wait a bit so we get some data in the buffers
	//
	sleep(1);

	//
	// Interrupt the capture
	//
	if(scap_stop_capture(h) != SCAP_SUCCESS)
	{
		fprintf(stderr, "%s\n", scap_getlasterr(h));
		scap_close(h);
		return -1;
	}

	//
	// Get the events
	//
	for(j = 0; j < N_EVENTS_TO_WAIT; j++)
	{
		res = scap_next(h, &ev, &cpuid);

		if(res == SCAP_TIMEOUT)
		{
			printf("timeout received after %u reads\n", j);
			return 0;
		}
		else if(res > 0)
		{
			fprintf(stderr, "%s\n", scap_getlasterr(h));
			scap_close(h);
			return -1;
		}
	}

	fprintf(stderr, "No timeout after %" PRIu32 " events\n", j);
	scap_close(h);
	return -1;
}
