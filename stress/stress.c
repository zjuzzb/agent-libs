#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void main(void)
{
	int j = 0;
	float cpu_time;
	FILE *f;
	char buf[1024];

	cpu_time = (float)clock() / CLOCKS_PER_SEC - cpu_time;
	for(j = 0; j < 3000000; j++)
	{
		f = fopen("/etc/passwd", "r");
		fread(buf, sizeof(buf), 1, f);
        fclose(f);
	}

	cpu_time = (float)clock() / CLOCKS_PER_SEC - cpu_time;
    printf ("time: %5.2f %d\n", cpu_time, (int)sizeof(buf));
}

