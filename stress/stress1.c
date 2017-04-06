#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

#define NCHILDS 50

main()
{
	pthread_t childs[NCHILDS];
	void *f1();
	int ids[NCHILDS];
	int j;

	for(j = 0; j < NCHILDS; j++)
	{
		ids[j] = j + 1;
		pthread_create(&(childs[j]), NULL, f1, ids + j);
	}

	for(j = 0; j < NCHILDS; j++)
	{
		pthread_join(childs[j],NULL);
	}
}

void *f1(int *x)
{
	int i;
	i = *x;

	printf("child%d\n", i);

	while(*x != 0)
	{
		sleep(1);
	}

	pthread_exit(0);
}

/*
main()
{
	pthread_t f2_thread, f1_thread;
	void *f2(), *f1();
	int i1,i2;
	i1 = 1;
	i2 = 2;

	FILE* f = fopen("pippo.txt", "w");

	printf("parent: %d\n", getpid());

	pthread_create(&f1_thread,NULL,f1,&i1);
	pthread_create(&f2_thread,NULL,f2,&i2);
	pthread_join(f1_thread,NULL);
	pthread_join(f2_thread,NULL);
}

void *f1(int *x)
{
	int i;
	i = *x;
	pthread_t f3_thread;
	void *f3();

	printf("child1: %d\n", getpid());

	pthread_create(&f3_thread,NULL,f3,NULL);
	pthread_join(f3_thread,NULL);

	pthread_exit(0);
}

void *f2(int *x)
{
	int i;
	i = *x;
	printf("child2: %d\n", getpid());
	pthread_exit(0);
}

void *f3(int *x)
{
	printf("child3: %d\n", getpid());
	pthread_exit(0);
}
*/
