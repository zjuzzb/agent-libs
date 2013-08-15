#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>
#include <unistd.h>

typedef struct {        /* For passing info to child startup function */
    int    fd;
    int    signal;
} ChildParams;

void FAIL()
{
   exit(-1);
}

static int clone_callback_1(void *arg)
{
    ChildParams *cp;

    printf("Child:  PID=%ld PPID=%ld\n", (long) getpid(), (long) getppid());

    cp = (ChildParams *) arg;   /* Cast arg to true form */

    /* The following changes may affect parent */

    if (close(cp->fd) == -1)
    {
        FAIL();      
    }
    if (signal(cp->signal, SIG_DFL) == SIG_ERR)
    {
      FAIL;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    const int STACK_SIZE = 65536;       /* Stack size for cloned child */
    char *stack;                        /* Start of stack buffer area */
    char *stackTop;                     /* End of stack buffer area */
    int flags;                          /* Flags for cloning child */
    ChildParams cp;                     /* Passed to child function */
    struct sigaction sa;
    char *p;
    int status;
    ssize_t s;
    pid_t pid;

    printf("Parent: PID=%ld PPID=%ld\n", (long) getpid(), (long) getppid());

    /* Set up an argument structure to be passed to cloned child, and
       set some process attributes that will be modified by child */

    cp.fd = open("/dev/null", O_RDWR);  /* Child will close this fd */
    if (cp.fd == -1)
        FAIL();

    cp.signal = SIGTERM;                /* Child will change disposition */
    if (signal(cp.signal, SIG_IGN) == SIG_ERR)
        FAIL();

    /* Initialize clone flags using command-line argument (if supplied) */

    flags = CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_VM;

    /* Allocate stack for child */

    stack = malloc(STACK_SIZE);
    if (stack == NULL)
        FAIL();
    stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

    /* Create child; child commences execution in childFunc() */

    if (clone(clone_callback_1, stackTop, flags, &cp) == -1)
        FAIL();

    /* Parent falls through to here. Wait for child; __WCLONE option is
       required for child notifying with signal other than SIGCHLD. */

    pid = waitpid(-1, &status, __WCLONE);
    if (pid == -1)
        FAIL();

    printf("Child PID=%ld\n", (long) pid);

    exit(0);
}
