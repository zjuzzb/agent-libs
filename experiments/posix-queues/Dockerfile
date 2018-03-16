FROM centos:6 as build
RUN yum install -y centos-release-scl && yum install -y devtoolset-4-toolchain
ADD posix_queue.c /
RUN source /opt/rh/devtoolset-4/enable && gcc -o posix_queue posix_queue.c -lrt
FROM debian:unstable
COPY --from=build /posix_queue /
RUN apt-get update && apt-get install -y strace
ENTRYPOINT [ "strace", "-e", "mq_open,mq_timedsend,mq_timedreceive", "/posix_queue" ]
