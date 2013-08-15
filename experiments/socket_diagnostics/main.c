#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <dirent.h>
#include <fnmatch.h>
#include <getopt.h>

#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>


void extract_string(char* buffer, struct rtattr* attr)
{
	int len = RTA_PAYLOAD(attr);
	memcpy(buffer, RTA_DATA(attr), len);
	buffer[len] = '\0';
}

int main(int argc, char ** argv)
{
	int fd;
	char buf[2048];
	struct {
		struct nlmsghdr header;
		struct unix_diag_req request; 
	} diag_request;
	int done = 0;

	if((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0)
	{
		return -1;
	}
	memset(&diag_request, 0, sizeof(diag_request));
	diag_request.header.nlmsg_len = sizeof(diag_request);
	diag_request.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	diag_request.header.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	diag_request.header.nlmsg_seq = 0x1A2B3C4D;

	diag_request.request.sdiag_family = AF_UNIX;
	diag_request.request.udiag_states = (1 << TCP_ESTABLISHED);
	diag_request.request.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER;

	if(send(fd, &diag_request, sizeof(diag_request), 0) < 0)
	{
		close(fd);
		return -1;
	}

	while(!done)
	{
		ssize_t status;
		struct nlmsghdr* h;
		struct sockaddr_nl nladdr;
		socklen_t slen = sizeof(nladdr);

		status = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&nladdr, &slen);
		if(status < 0)
		{
			if(errno == EINTR)
			{
				continue;
			}
			printf("error receiving from\n");
			continue;
		}
		if(status == 0)
		{
			printf("EOF\n");
			break;
		}
		h = (struct nlmsghdr*)buf;
		while(NLMSG_OK(h, status))
		{
			int err;

			if(h->nlmsg_seq == 0x1A2B3C4D)
			{
				if(h->nlmsg_type == NLMSG_DONE)
				{
					done = 1;
					break;
				}
				if(h->nlmsg_type == NLMSG_ERROR)
				{
					// TODO handle error
					done = 1;
					break;
				}
				struct unix_diag_msg* r = NLMSG_DATA(h);
				struct rtattr* attr = (struct rtattr*)(r+1);
				int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
				char name_buffer[1024];
				name_buffer[0] = '\0';
				int peer_ino = 0;
				while(RTA_OK(attr,len))
				{
					switch(attr->rta_type)
					{
						case UNIX_DIAG_NAME:
							extract_string(name_buffer,attr);
						break;

						case UNIX_DIAG_PEER:
							peer_ino = *(int*)RTA_DATA(attr);
						break;

						default:
						break;
					}
					attr = RTA_NEXT(attr,len);
				}
				printf("%d -> %d ... %s\n",r->udiag_ino,peer_ino,name_buffer);
			}
			h = NLMSG_NEXT(h, status);
		}
	}

	close(fd);
	return 0;
}