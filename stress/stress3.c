#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char *eargv[] = { "./stress4", "a", NULL };
	char *eenvp[] = { NULL };

	printf("1\n");

	if(argc > 1)
	{
		FILE* f = fopen("pippo.txt", "w");
		printf("4\n");
	}
	else
	{
		printf("2\n");
		execve("./stress4", eargv, eenvp);
		printf("3\n");
	}
}

