#include <sys/stat.h>
#include <sys/resource.h>
#include <limits.h>
#include <mqueue.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

static const long MAX_MSGSIZE = 3 << 20; // 3 MiB
static const long MAX_QUEUES = 10;
static const long MAX_MSGS = 3;

void set_queue_limits()
{
    struct rlimit r;
    r.rlim_cur = MAX_QUEUES * (MAX_MSGS+2) * MAX_MSGSIZE;
    r.rlim_max = MAX_QUEUES * (MAX_MSGS+2) * MAX_MSGSIZE;

    int res = setrlimit(RLIMIT_MSGQUEUE, &r);
}

mqd_t queue_open(char* name, int flags)
{
	struct mq_attr queue_attrs = {0};
	queue_attrs.mq_maxmsg = 1;
	queue_attrs.mq_msgsize = MAX_MSGSIZE;
	queue_attrs.mq_curmsgs = 0;
	mqd_t m_queue_d = mq_open(name, flags, S_IRUSR /*| S_IWUSR */, &queue_attrs);
	if(m_queue_d < 0)
	{
		fprintf(stderr, "Error: Cannot create queue %s, errno: %s\n", name, strerror(errno));
    }
    return m_queue_d;
}

void queue_send(mqd_t fd, char* msg)
{
    int res = mq_send(fd, msg, strlen(msg), 0);
    if(res != 0)
    {
        fprintf(stderr, "Cannot send on queue %s\n", strerror(errno));
    }
}

void queue_receive(mqd_t fd)
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    unsigned int prio = 0;
    char m_readbuffer[MAX_MSGSIZE];
    int res = mq_timedreceive(fd, m_readbuffer, MAX_MSGSIZE, &prio, &ts);
    if(res >= 0)
    {
        m_readbuffer[res+1] = '\0';
        printf("%s\n", m_readbuffer);
    }
    else
    {
        fprintf(stderr,"Unexpected error on posix queue receive: %s\n", strerror(errno));
    }
}

int perm_to_flags(char* perm)
{
    int flags = 0;
    if(strchr(perm, 'r') != NULL)
    {
        if(strchr(perm, 'w') != NULL)
        {
            flags = O_RDWR;
        }
        else
        {
            flags = O_RDONLY;
        }
    } else if(strchr(perm, 'w') != NULL)
    {
        flags = O_WRONLY;
    }
    if(strchr(perm, 'c') != NULL)
    {
        flags |= O_CREAT;
    }
    if(strchr(perm, 'n') != NULL)
    {
        flags |= O_NONBLOCK;
    }
    return flags;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "invalid arguments, usage: %s queue_name rwcn [msg]\n", argv[0]);
        return 1;
    }
    set_queue_limits();
    char* queue = argv[1];
    char* perm = argv[2];
    mqd_t fd = queue_open(queue, perm_to_flags(perm));
    if(fd <= 0)
    {
        return 1;
    }
    if(argc > 3)
    {
        queue_send(fd, argv[3]);
    }
    else
    {
        queue_receive(fd);
    }
    int res = mq_close(fd);
    if(res != 0)
    {
        fprintf(stderr, "Cannot close queue %s\n", strerror(errno));
    }
}
