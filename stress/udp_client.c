#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <time.h>

#define SERVER_PORT     3557
#define BUFFER_LENGTH   sizeof("A CLIENT REQUEST")
#define FALSE           0
#define SERVER_NAME     "localhost"

uint32_t get_server_address()
{
	struct ifaddrs *interfaceArray = NULL;
	struct ifaddrs *tempIfAddr = NULL;
	int rc = 0;
	uint32_t address = 0;

	rc = getifaddrs(&interfaceArray);
	if(rc != 0)
	{
		fprintf(stderr,"error getting interfaces");
		return -1;
	}
	for(tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next)
	{
		if(tempIfAddr->ifa_addr->sa_family != AF_INET)
		{
			continue;
		}
		if(0 == strcmp("lo",tempIfAddr->ifa_name))
		{
			continue;
		}
		address = *(uint32_t*)&((struct sockaddr_in *)tempIfAddr->ifa_addr)->sin_addr;
		break;
	}
	freeifaddrs(interfaceArray);

	return address;
}


void main(int argc, char *argv[])
{
	int    sd, rc;
	char   server[256];
	char   buffer[BUFFER_LENGTH];
	struct hostent *hostp;
	struct sockaddr_in serveraddr;
	int    serveraddrlen = sizeof(serveraddr);
	struct sockaddr_in sa;
	int    len = sizeof(struct sockaddr);
	int j;
	double duration;

	do
	{
		printf("STARTED\n");
		fflush(stdout);

		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sd < 0)
		{
			perror("socket() failed");
			break;
		}

		strcpy(server, SERVER_NAME);

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sin_family      = AF_INET;
		serveraddr.sin_port        = htons(SERVER_PORT);
		serveraddr.sin_addr.s_addr = get_server_address();
		if (serveraddr.sin_addr.s_addr == (unsigned long)INADDR_NONE)
		{
			/*****************************************************************/
			/* The server string that was passed into the inet_addr()        */
			/* function was not a dotted decimal IP address.  It must        */
			/* therefore be the hostname of the server.  Use the             */
			/* gethostbyname() function to retrieve the IP address of the    */
			/* server.                                                       */
			/*****************************************************************/
			hostp = gethostbyname(server);
			if (hostp == (struct hostent *)NULL)
			{
				printf("Host not found --> ");
				printf("h_errno = %d\n", h_errno);
				break;
			}

			memcpy(&serveraddr.sin_addr,
			       hostp->h_addr,
			       sizeof(serveraddr.sin_addr));
		}

		memset(buffer, 0, sizeof(buffer));
		strcpy(buffer, "A CLIENT REQUEST");

		/********************************************************************/
		/* Use the sendto() function to send the data to the server.        */
		/********************************************************************/
		duration = ((double)clock()) / CLOCKS_PER_SEC;

		for(j = 0; j < 1500000; j++)
		{		
			rc = sendto(sd, buffer, sizeof(buffer), 0,
			            (struct sockaddr *)&serveraddr,
			            sizeof(serveraddr));
			if (rc < 0)
			{
				perror("sendto() failed");
				break;
			}
		}

		duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

		printf("%.3lf\n", duration);

		/********************************************************************/
		/* Use the recvfrom() function to receive the data back from the    */
		/* server.                                                          */
		/********************************************************************/
/*
		rc = recvfrom(sd, buffer, sizeof(buffer), 0,
		              (struct sockaddr *)&serveraddr,
		              & serveraddrlen);
		if (rc < 0)
		{
			perror("recvfrom() failed");
			break;
		}

		getsockname(sd, (struct sockaddr *) &sa, &len);
		fprintf(stderr, "listening on %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

		printf("client received the following: <%s>\n", buffer);
		printf("from port %d, from address %s\n",
		       ntohs(serveraddr.sin_port),
		       inet_ntoa(serveraddr.sin_addr));
*/		       
	}
	while (FALSE);

	if (sd != -1)
		close(sd);
}
