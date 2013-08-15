#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>		// SIGTERM

#define T_BUF_SIZE	256

void handle_connection(int, int, int);
void handler(int v)
{
	signal(SIGTERM, handler);
	fprintf(stderr, "SIGTERM\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int socket_fd, new_socket_fd, port, pid, quiet, keep_forking, j;
	socklen_t client_addr_len;
	struct sockaddr_in server_addr, client_addr;

	signal(SIGTERM, handler);

	if(argc < 2)
	{
		fprintf(stderr, "ERROR, no port provided\n");
		exit(1);
	}

	quiet = 0;
	keep_forking = 0;
	for(j = 2; j < argc; j++)
	{
		if(strcmp(argv[j], "-q") == 0)
		{
			quiet = 1;
		}
		else if(strcmp(argv[j], "-f") == 0)
		{
			keep_forking = 1;
		}
	}

	// Sleep 2 seconds to make sure strace can attach to the process before proceeding
	sleep(2);

	// Create the server socket
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(socket_fd < 0)
	{
		fprintf(stderr, "[ERROR] impossible to open the socket\n");
		exit(1);
	}

	fprintf(stdout, "[INFO] server socket %d PID %d PPID %d\n", socket_fd, getpid(), getppid());

	// Set the server address struct
	memset((char *) &server_addr, 0, sizeof(server_addr));
	port = atoi(argv[1]);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);

	// Bind the server socket
	if(bind(socket_fd, (struct sockaddr *) &server_addr,sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "[ERROR] impossile to bind the socket\n");
		exit(1);
	}

	// Start listening on the server socket
	listen(socket_fd, 5);
	client_addr_len = sizeof(client_addr);
	while(1)
	{
		// Accept a client connection
		new_socket_fd = accept(socket_fd, (struct sockaddr *) &client_addr, &client_addr_len);

		if(new_socket_fd < 0)
		{
			fprintf(stderr, "[ERROR] impossible to accept a connection\n");
			exit(1);
		}

		fprintf(stdout, "[INFO] server new socket %d PID %d PPID %d\n", new_socket_fd, getpid(), getppid());

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
			close(socket_fd);
			handle_connection(new_socket_fd, quiet, keep_forking);
			exit(0);
		}
		else
		{
			// Father

			// TEST

			// Write data to the socket
			write(new_socket_fd, "server up", 9);

			close(new_socket_fd);
		}
	}

	close(socket_fd);

	return 0;
}

void handle_connection(int sock, int quiet, int keep_forking)
{
	int n;
	int pid;
	int fork_count;
	char buffer[T_BUF_SIZE];

	fprintf(stdout, "[INFO] child new socket %d PID %d PPID %d\n", sock, getpid(), getppid());

	fork_count = 0;
	while(1)
	{
		// Clean up the buffer
		memset(buffer, 0, T_BUF_SIZE);

		// Read data from the socket
		n = read(sock, buffer, (T_BUF_SIZE - 1));
		if(n < 0)
		{
			fprintf(stderr, "[ERROR] impossible to read from socket\n");
			exit(1);
		}

		if(quiet == 0)
		{
			fprintf(stdout, "PID %d PPID %d %s\n", getpid(), getppid(), buffer);
		}

		if(strcmp(buffer, "stop") == 0)
		{
			break;
		}

		// Write data to the socket
		n = write(sock, "server up", 9);
		if(n < 0)
		{
			fprintf(stderr, "[ERROR] impossible to write to the socket\n");
			exit(1);
		}

		if(keep_forking > 0 && ((fork_count % 2) == 0))
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
				// Child: nothing to do, just keep going
				;
			}
			else
			{
				// Father, just exit
				//exit(0);
				while(1)
				{
					sleep(2);
				}
			}
		}

	}


	close(sock);
}
