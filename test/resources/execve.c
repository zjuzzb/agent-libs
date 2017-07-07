//
// Created by Luca Marturana on 11/08/15.
//

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char** argv)
{
	if(argc > 1)
	{
		if (execv(argv[1], argv+1) != 0)
		{
			fprintf(stderr, "Can't exec %s: %s\n", argv[1], strerror(errno));
		}
		return 1;
	}
	else
	{
		return 0;
	}
}
