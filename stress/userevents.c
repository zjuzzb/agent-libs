#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>

#define TMP_FILE_NAME "/tmp/sysdig_test.txt"
#define BIGBUFSIZE 5000

void generate_sysdig_event(FILE* f, char* text)
{
	fwrite(text, strlen(text), 1, f);
	fflush(f);
}

int main(void)
{
	int j;
	int res;
	FILE* f = fopen("/dev/sysdig-events", "w");

	clock_t begin = clock();
	printf("%p\n", f);

	char* bigbuf = (char*)malloc(BIGBUFSIZE);
	for(j = 0; j < BIGBUFSIZE; j++)
	{
		bigbuf[j] = '1' + (j % 5);
	}
	bigbuf[BIGBUFSIZE - 1] = 0;

	for(j = 0; j < 5; j++)
	{
		FILE* tf1;

//		generate_sysdig_event(f, bigbuf);
/*
		generate_sysdig_event(f, "[1, >, [\"lori,");
		generate_sysdig_event(f, "sapp\",");
		generate_sysdig_event(f, " \"loop\"], []]");
*/		
		generate_sysdig_event(f, "[\">\", 1, [\"lorisapp\", \"loop\"], []]");

		tf1 = fopen(TMP_FILE_NAME, "w");
		generate_sysdig_event(f, "[\">\", 2, [\"lorisapp\", \"loop\", \"write\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}]]");
		fwrite("hello world", strlen("hello world"), 1, tf1);
		generate_sysdig_event(f, "[\"<\", 2, [\"lorisapp\", \"loop\", \"write\"], []]");
		fclose(tf1);

		unlink(TMP_FILE_NAME);

		generate_sysdig_event(f, "[\"<\", 1, [\"lorisapp\", \"loop\"], []]");
		
		usleep(200000);
	}

	clock_t end = clock();
	double elapsed_secs = ((double)(end - begin)) / CLOCKS_PER_SEC;
	printf("%lf\n", elapsed_secs);
}
