#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int fd;

void* callback(void* arg)
{
	char buf[1024];
	sleep(1);
	if(read(fd, buf, sizeof(buf)) < 0)
	{
		perror("read");
	}
	sleep(10);
	return NULL;
}

//
// This is outside the test files because gtest doesn't like
// pthread_exit() since it triggers an exception to unwind the stack
//
int main()
{
	pthread_t thread;

	fd = open("/etc/passwd", O_RDONLY);
	if(fd == -1)
	{
		perror("open");
	}

	pthread_create(&thread, NULL, callback, NULL);
	pthread_exit(NULL);
}
