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
#include <scap.h>

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
				char error[SCAP_LASTERR_SIZE];
				scap_t* h = scap_open_live(error);
				if(h == NULL)
				{
					printf("[%d] %s\n", getpid(), error);
				}
				else
				{
					printf("[%d] scap_open_live ok\n");
					scap_close(h);
				}
			}			
		}
	}

	wait(NULL);

	return 0;
}
