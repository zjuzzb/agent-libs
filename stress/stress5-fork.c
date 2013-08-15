#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[])
{
	pid_t cpid;
	FILE* f = fopen("pippo.txt", "w");

	cpid = fork();
	if (cpid == -1)
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (cpid == 0)
	{
		printf("1\n");
	}
	else
	{
		printf("2 %d\n", cpid);
	}
}
