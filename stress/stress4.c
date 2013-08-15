#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char *eargv[] = { "a", NULL };
	char *eenvp[] = { NULL };

	if(argc > 1)
	{
		FILE* f = fopen("pippo.txt", "w");
		printf("4\n");
	}
	else
	{
		execve("stress4", eargv, eenvp);
		printf("3\n");
	}
}

