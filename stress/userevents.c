#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>

#define TMP_FILE_NAME "/tmp/sysdig_test.txt"

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

	for(j = 0; j < 1000; j++)
	{
		FILE* tf1;

		generate_sysdig_event(f, "1.0/>/test");

		tf1 = fopen(TMP_FILE_NAME, "w");
		generate_sysdig_event(f, "1.0/>/test/write");
		fwrite("hello world", strlen("hello world"), 1, tf1);
		generate_sysdig_event(f, "1.0/</test/write");
		fclose(tf1);

		unlink(TMP_FILE_NAME);

		generate_sysdig_event(f, "1.0/</test");
	}

	clock_t end = clock();
	double elapsed_secs = ((double)(end - begin)) / CLOCKS_PER_SEC;
	printf("%lf\n", elapsed_secs);
}
