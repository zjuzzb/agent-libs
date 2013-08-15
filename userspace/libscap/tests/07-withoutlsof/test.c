#include <stdio.h>
#include <unistd.h>

#include <scap.h>
#include <scap-int.h>

int main(int argc, char **argv)
{
	char error[SCAP_LASTERR_SIZE];

	//
	// Start Capturing
	//

	scap_t *h = NULL;
	if(2 == argc)
	{
		h = scap_open_offline(argv[1],error);
	}
	else
	{
		h = scap_open_live(error);
	}
	if(h == NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}

	scap_proc_print_table(h);
	scap_close(h);

	return -1;
}
