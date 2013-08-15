#include <stdio.h>
#include <malloc.h>
#include <time.h>

void main(void)
{
	int j = 0;
	float cpu_time;
	void *p;

	cpu_time = (float)clock() / CLOCKS_PER_SEC;

	for(j = 0; j < 1000; j++)
	{
		p = malloc(1000);
	}

	cpu_time = (float)clock() / CLOCKS_PER_SEC - cpu_time;

	printf ("time: %5.2f\n", cpu_time);
}

