#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void* callback(void* arg)
{
	return NULL;
}

int main()
{
	int ctid;
	int cctid, cctid1, cctid2, cctid3, cctid4, cctid5;

	ctid = fork();

	if(ctid == 0)
	{
		//
		// CHILD PROCESS
		//
printf("*1\n");
		pthread_t thread;
		pthread_create(&thread, NULL, callback, NULL);

		usleep(100000);
		cctid = fork();

		if(cctid == 0)
		{
			//
			// CHILD PROCESS
			//
printf("*2\n");
			pthread_t thread;
			pthread_create(&thread, NULL, callback, NULL);
			
			usleep(100000);
			cctid1 = fork();
	
			if(cctid1 == 0)
			{
				//
				// CHILD PROCESS
				//
printf("*3\n");
				pthread_t thread;
				pthread_create(&thread, NULL, callback, NULL);
			
				usleep(100000);
				cctid2 = fork();
				
				if(cctid2 == 0)
				{
					//
					// CHILD PROCESS
					//
printf("*4\n");
					pthread_t thread;
					pthread_create(&thread, NULL, callback, NULL);
					
					usleep(100000);
					cctid3 = fork();
					
					if(cctid3 == 0)
					{
printf("*5\n");
						//
						// CHILD PROCESS
						//
						pthread_t thread;
						pthread_create(&thread, NULL, callback, NULL);
						
						usleep(100000);
						cctid4 = fork();
						
						if(cctid4 == 0)
						{
printf("*6\n");
							//
							// CHILD PROCESS
							//
							pthread_t thread;
							pthread_create(&thread, NULL, callback, NULL);
							
							usleep(100000);
							cctid5 = fork();
							
							if(cctid5 == 0)
							{
printf("*7\n");
								return 0;
							}
							else
							{
								return 0;
							}
						}
						else
						{
							return 0;
						}
					}
					else
					{
						return 0;
					}
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
}
