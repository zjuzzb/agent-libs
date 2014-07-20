#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define NPROCESSES 20

int main()
{
	long ndevs = sysconf(_SC_NPROCESSORS_ONLN);
	
	for(uint32_t j = 0; j < NPROCESSES; ++j)
	{
		if(fork() == 0)
		{
			while(true)
			{
				int fds[ndevs];

				for(uint32_t j = 0; j < ndevs; ++j)
				{
					char dev[255];
					sprintf(dev, "/dev/sysdig%d", j);

					int fd = open(dev, O_RDWR | O_SYNC);
					fds[j] = fd;
					if(fd == -1)
					{
						printf("[%d] open %s failed: %s\n", getpid(), dev, strerror(errno));
					}
					else
					{
						printf("[%d] open %s\n", getpid(), dev);
					}
				}

				for(uint32_t j = 0; j < ndevs; ++j)
				{
					if(fds[j] != -1)
					{
						close(fds[j]);
					}
				}
			}			
		}
	}

	wait(NULL);

	return 0;
}
