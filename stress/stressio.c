#include <stdio.h>
#include <time.h>

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

	for(j = 0; j < 6000000; j++)
	{
		fwrite("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 40, 1, f);
		fflush(f);
	}

	duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

	printf("%.3lf\n", duration);

	fclose(f);
}