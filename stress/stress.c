#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void main(void)
{
	int j = 0;
	float cpu_time;
	FILE *f;

	cpu_time = (float)clock() / CLOCKS_PER_SEC;
	while(1)
	{
		f = fopen("file.txt", "w+");
		for(j = 0; j < 300000; j++)
		{
			fprintf(f, "ciaoz\n");
		}
		fclose(f);
	}

	cpu_time = (float)clock() / CLOCKS_PER_SEC - cpu_time;

	/*
		cpu_time = (float)clock() / CLOCKS_PER_SEC - cpu_time;

		for(j = 0; j < 30; j++)
		{
			f = fopen("/proc/net/if_inet6", "r");
	        fclose(f);
		}

		cpu_time = (float)clock() / CLOCKS_PER_SEC - cpu_time;

	    printf ("time: %5.2f\n", cpu_time);

	//    sleep(10);
	*/
}

