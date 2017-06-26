#include <stdio.h>
#include <time.h>

#define CNT 100000000

int main()
{
	int j;
	double duration;
	FILE* f = fopen("/dev/null", "w");
	if(!f)
	{
		printf("cannot open file\n");
		return -1;
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC;

	for(j = 0; j < CNT; j++)
	{
		fwrite("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 40, 1, f);
		fflush(f);
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("duration:%.3lf %.3f writes/s\n", duration, ((double)CNT) / duration);

	fclose(f);
}