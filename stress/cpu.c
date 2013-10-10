#include <stdio.h>

int main()
{
	int j, k;

	while(1)
	{
		for(j = 0; j < 1000000000; j++)
		{
			k += j * j % 37;
		}
	}
}