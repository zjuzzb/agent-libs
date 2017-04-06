//
// Created by Luca Marturana on 11/08/15.
//

#include <unistd.h>

int main(int argc, char** argv)
{
	if(argc > 1)
	{
		execv(argv[1], argv+1);
		return 1;
	}
	else
	{
		return 0;
	}
}