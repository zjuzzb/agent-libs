#include <mqueue.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#define MAX_MSGSIZE 3 << 20

int set_queue_limits(int mb)
{
    struct rlimit r;
    r.rlim_cur = mb << 20;
    r.rlim_max = mb << 20;
    return setrlimit(RLIMIT_MSGQUEUE, &r);
}

mqd_t queue_open(int flags, int mb)
{
    struct mq_attr queue_attrs = {0};
    queue_attrs.mq_maxmsg = 1;
    queue_attrs.mq_msgsize = MAX_MSGSIZE;
    queue_attrs.mq_curmsgs = 0;
    return mq_open("/test", flags | O_CREAT, S_IRWXU, &queue_attrs);
}

static const char* MSG = "ping";

int queue_send(mqd_t q)
{
    return mq_send(q, MSG, 5, 0);
}

static char buf[MAX_MSGSIZE];

int queue_receive(mqd_t q)
{
    struct timespec ts = {0};
    unsigned int prio = 0;
    struct timeval t;
    gettimeofday(&t, NULL);
    ts.tv_sec = t.tv_sec;
    int res = mq_timedreceive(q, buf, MAX_MSGSIZE, &prio, &ts);
    if(strncmp(MSG, buf, 5) != 0)
    {
        fprintf(stderr, "msgs are different\n");
    }
    memset(buf, 0, MAX_MSGSIZE);
    return res ;
}

void queue_delete()
{
    mq_unlink("/test");
}

void check_error(int ret, char* msg)
{
    if(ret > 0)
    {
        fprintf(stderr, "%s OK\n", msg);
    }
    else
    {
        fprintf(stderr, "%s failed, errno=%s\n", msg, strerror(errno));
    }
}

int main() 
{
    mqd_t q_w, q_r;
    queue_delete();
    atexit(&queue_delete);
    for(int mb = 4;  mb <= 10; ++mb)
    {
        fprintf(stderr, "Testing with %d MiB\n", mb);
        check_error(set_queue_limits(mb) == 0, "set limits");
        q_r = queue_open(O_RDONLY, mb);
        check_error(q_r, "opened queue read");
        fprintf(stderr, "opened queue read fd=%d\n", (int)q_r);
        q_w = queue_open(O_WRONLY, mb);
        check_error(q_w, "opened queue write");
        fprintf(stderr, "opened queue write fd=%d\n", (int)q_w);
        check_error(queue_send(q_w) == 0, "queue_send");
        check_error(queue_receive(q_r) > 0, "queue_receive");
        check_error(close(q_r) == 0, "close queue read");
        check_error(close(q_w) == 0, "close queue write");
    }
}