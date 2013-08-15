#include <stdio.h>

#include <scap.h>

int main(int argc, char *argv[])
{
	char error[SCAP_LASTERR_SIZE];
	scap_os_patform platform;
	char* platform_str;

	scap_t* h = scap_open_live(error);
	if(h == NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}

	platform = scap_get_os_platform(h);

	switch(platform)
	{
	case SCAP_PFORM_LINUX_I386:
		platform_str = "Linux 32bit";
		break;
	case SCAP_PFORM_LINUX_X64:
		platform_str = "Linux 64bit";
		break;
	default:
		platform_str = "Uknown";
	}

	printf("%s\n", platform_str);

	scap_close(h);
	return 0;
}
