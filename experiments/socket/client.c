#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>		// SIGTERM
#include <errno.h>

#define T_BUF_SIZE	256

void handler(int v)
{
	signal(SIGTERM, handler);
	fprintf(stderr, "SIGTERM\n");
	exit(0);
}

void send_massages(int socket_fd, int num_messages, int quiet);

int main(int argc, char *argv[])
{
	int pid, socket_fd, port, j, n, num_messages, quiet;
	struct sockaddr_in server_addr;
	struct hostent *server;

	signal(SIGTERM, handler);

	if(argc < 4)
	{
		fprintf(stderr, "usage:\n%s hostname port #messages\n", argv[0]);
		exit(0);
	}

	quiet = 0;
	if((argc == 5) && strcmp(argv[4], "-q") == 0)
	{
		quiet = 1;
	}

	// Sleep 2 seconds to make sure strace can attach to the process before proceeding
	sleep(2);

	// Create a client socket
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	if(socket_fd < 0)
	{
		fprintf(stderr, "[ERROR] impossible to open the socket\n");
		exit(1);
	}

	server = gethostbyname(argv[1]);

	if(server == NULL)
	{
		fprintf(stderr, "[ERROR] impossible to reach the server %s %s\n", argv[1], hstrerror(h_errno));
		exit(1);
	}

	// Set the server adress strct
	memset((char *) &server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	memcpy((char *)&server_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
	port = atoi(argv[2]);
	server_addr.sin_port = htons(port);

	// Connect to the server
	if(connect(socket_fd,(struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "[ERROR] impossible to connect to the server %s %s\n", argv[1], strerror(errno));
		exit(1);
	}

	// Get the number of messages
	num_messages = atoi(argv[3]);

	for(j = 0; j < 5; j++)
	{
		// Create a child process
		pid = fork();

		if(pid < 0)
		{
			fprintf(stderr, "[ERROR] impossible to create a child process\n");
			exit(1);
		}

		if(pid == 0)
		{
			// Child
			send_massages(socket_fd, num_messages, quiet);
			exit(0);
		}
		else
		{
			// Father

			// TEST

		}
	}

	sleep(10);

	// Tell the server thread to stop
	n = write(socket_fd, "stop", 4);

	if(n < 0)
	{
		fprintf(stderr, "[ERROR] impossible to write to the socket\n");
		exit(1);
	}

	close(socket_fd);

	return 0;
}

void send_massages(int socket_fd, int num_messages, int quiet)
{
	// Clean up the buffer
	// memset(buffer, 0, T_BUF_SIZE);
	//fgets(buffer, (T_BUF_SIZE - 1), stdin);
	//n = write(socket_fd, buffer, strlen(buffer));
	char buffer[T_BUF_SIZE];
	int n, count;

	fprintf(stdout, "START PID %d\n", getpid());

	count = 0;
	n = 0;
	while(count < num_messages)
	{
		char b[512];
		sprintf(b, "client up %d", getpid());

		//n = write(socket_fd, "client up", 9);
		n = write(socket_fd, b, strlen(b));

		if(n < 0)
		{
			fprintf(stderr, "[ERROR] impossible to write to the socket\n");
			exit(1);
		}

		// Clean up the buffer
		memset(buffer, 0, T_BUF_SIZE);

		n = read(socket_fd, buffer, (T_BUF_SIZE - 1));

		if(n < 0)
		{
			fprintf(stderr, "[ERROR] impossible to read from the socket\n");
			exit(1);
		}

		if(quiet == 0)
		{
			fprintf(stdout, "%d %s\n", getpid(), buffer);
		}

		// Sleep 1 second
		sleep(1);

		count++;
	}
}