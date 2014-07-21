#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define FIFO_NAME "/tmp/myfifo"
#define MAX_BUF 1024

/*
int main(void)
{
	int j;
	double duration;
	struct timeval start_time, end_time;
	int fd = open(FIFO_NAME, O_WRONLY);

	gettimeofday(&start_time, NULL);

	for(j = 0; j < 1000000; j++)
	{
		if(write(fd, "[\">\", 2, [\"lorisapp\", \"loop\", \"write\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}]]", 
			sizeof("[\">\", 2, [\"lorisapp\", \"loop\", \"write\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}]]")) == -1)
		{
			printf("!\n");
		}
	}

	gettimeofday(&end_time, NULL);
	duration = (end_time.tv_sec - start_time.tv_sec);
	duration += (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
	printf("%lf\n", duration);

	close(fd);

}
/*
int main(void)
{
	int j;
	double duration;
	struct timeval start_time, end_time;
	int fd;
	char buf[MAX_BUF];

	mkfifo(FIFO_NAME, 0666);

	fd = open(FIFO_NAME, O_RDONLY);

	for(j = 0; j < 1000000; j++)
	{
		read(fd, buf, MAX_BUF);
	}

	gettimeofday(&end_time, NULL);
	duration = (end_time.tv_sec - start_time.tv_sec);
	duration += (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
	printf("%lf\n", duration);

	close(fd);	
}

/*
#define NAME "/tmp/python_unix_udp_sockets_example"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"

int main(void)
{
	int j;
	int sock;
	struct sockaddr_un name;
	struct timeval start_time, end_time;
	double duration;

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("opening datagram socket");
		exit(1);
	}

	name.sun_family = AF_UNIX;
	strcpy(name.sun_path, NAME);

	gettimeofday(&start_time, NULL);

	for(j = 0; j < 1000000; j++)
	{
		sendto(sock, PAYLOAD, sizeof(PAYLOAD) - 1, 0, (struct sockaddr *)&name,
			sizeof(struct sockaddr_un));

		sendto(sock, PAYLOAD, sizeof(PAYLOAD) - 1, 0, (struct sockaddr *)&name,
			sizeof(struct sockaddr_un));
	}

	gettimeofday(&end_time, NULL);

	duration = (end_time.tv_sec - start_time.tv_sec);
	duration += (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

	printf("%lf\n", duration);

	close(sock); 
}
*/
#if 1
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
	struct timeval start_time, end_time;
	double duration;
	FILE* f = fopen("/dev/sysdig-events", "w");

	printf("%p\n", f);

	char* bigbuf = (char*)malloc(BIGBUFSIZE);
	for(j = 0; j < BIGBUFSIZE; j++)
	{
		bigbuf[j] = '1' + (j % 5);
	}
	bigbuf[BIGBUFSIZE - 1] = 0;

	gettimeofday(&start_time, NULL);

	for(j = 0; j < 1000000; j++)
	{
		FILE* tf1;

		generate_sysdig_event(f, "[\">\", 1, [\"lorisapp\", \"loop\"], []]");
/*
		tf1 = fopen(TMP_FILE_NAME, "w");
		generate_sysdig_event(f, "[\">\", 2, [\"lorisapp\", \"loop\", \"write\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}]]");
		fwrite("hello world", strlen("hello world"), 1, tf1);
		generate_sysdig_event(f, "[\"<\", 2, [\"lorisapp\", \"loop\", \"write\"], []]");
		fclose(tf1);

		unlink(TMP_FILE_NAME);
		
		usleep(1000);
*/
		generate_sysdig_event(f, "[\"<\", 1, [\"lorisapp\", \"loop\"], []]");		
	}

	gettimeofday(&end_time, NULL);

	duration = (end_time.tv_sec - start_time.tv_sec);
	duration += (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

	printf("%lf\n", duration);
}

#endif

/*
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

#define TMP_FILE_NAME "/tmp/sysdig_test.txt"
#define BIGBUFSIZE 5000

void generate_sysdig_event(int f, char* text)
{
	write(f, text, strlen(text));
//	flush(f);
}

int main(void)
{
	int j;
	int res;
	struct timeval start_time, end_time;
	double duration;
	int f = open("/dev/sysdig-events", O_WRONLY);

	printf("%p\n", f);

	char* bigbuf = (char*)malloc(BIGBUFSIZE);
	for(j = 0; j < BIGBUFSIZE; j++)
	{
		bigbuf[j] = '1' + (j % 5);
	}
	bigbuf[BIGBUFSIZE - 1] = 0;

	gettimeofday(&start_time, NULL);

	for(j = 0; j < 1000000; j++)
	{
		FILE* tf1;

		generate_sysdig_event(f, "[\">\", 1, [\"lorisapp\", \"loop\"], []]");
		generate_sysdig_event(f, "[\"<\", 1, [\"lorisapp\", \"loop\"], []]");		
	}

	gettimeofday(&end_time, NULL);

	duration = (end_time.tv_sec - start_time.tv_sec);
	duration += (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

	printf("%lf\n", duration);
}
*/