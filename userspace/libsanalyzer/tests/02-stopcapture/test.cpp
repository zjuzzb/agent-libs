#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <iostream>
#include <unistd.h>

#define N_EVENTS_TO_WAIT 100000

int main(int argc, char **argv)
{
	uint32_t j;
	sinsp_evt* ev;
	int32_t res;

	try
	{
		//
		// Start the capture
		//
		sinsp inspector;
		inspector.open("");

		//
		// Wait a bit so we get some data in the buffers
		//
		sleep(1);

		//
		// Interrupt the capture
		//
		inspector.stop_capture();

		//
		// Get the events
		//
		for(j = 0; j < N_EVENTS_TO_WAIT; j++)
		{
			res = inspector.next(&ev);

			if(res == SCAP_TIMEOUT)
			{
				printf("timeout received after %" PRIu32 " reads\n", j);
				return 0;
			}
			else if(res > 0)
			{
				throw sinsp_exception(inspector.getlasterr().c_str());
			}
		}
	}
	catch(sinsp_exception e)
	{
		cerr << e.what();
		return -1;
	}
	catch(...)
	{
	}

	fprintf(stderr, "No timeout after %" PRIu32 " events\n", j);
	return -1;
}
