#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define SERVER_PORT     3557
#define BUFFER_LENGTH    100
#define FALSE              0

void main()
{
	int    sd=-1, rc;
	char   buffer[BUFFER_LENGTH];
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	int    clientaddrlen = sizeof(clientaddr);
	struct sockaddr_in sa;
	int    len = sizeof(struct sockaddr);

	do
	{
		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sd < 0)
		{
			perror("socket() failed");
			break;
		}

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sin_family      = AF_INET;
		serveraddr.sin_port        = htons(SERVER_PORT);
		serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

		rc = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
		if (rc < 0)
		{
			perror("bind() failed");
			break;
		}

		printf("STARTED\n");
		fflush(stdout);

		rc = recvfrom(sd, buffer, sizeof(buffer), 0,
		              (struct sockaddr *)&clientaddr,
		              &clientaddrlen);
		if (rc < 0)
		{
			perror("recvfrom() failed");
			break;
		}

		printf("server received the following: <%s>\n", buffer);
		printf("from port %d and address %s\n",
		       ntohs(clientaddr.sin_port),
		       inet_ntoa(clientaddr.sin_addr));

		/********************************************************************/
		/* Echo the data back to the client                                 */
		/********************************************************************/
		rc = sendto(sd, buffer, sizeof(buffer), 0,
		            (struct sockaddr *)&clientaddr,
		            sizeof(clientaddr));
		if (rc < 0)
		{
			perror("sendto() failed");
			break;
		}

		getsockname(sd, (struct sockaddr *) &sa, &len);
		fprintf(stderr, "listening on %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
//sleep(10000);
	}
	while (FALSE);

	if (sd != -1)
		close(sd);
}
