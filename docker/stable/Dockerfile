FROM debian:unstable

MAINTAINER Sysdig <support@sysdig.com>

ENV SYSDIG_REPOSITORY stable

ENV SYSDIG_HOST_ROOT /host

ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

ADD http://download.draios.com/apt-draios-priority /etc/apt/preferences.d/

RUN echo "deb http://deb.debian.org/debian jessie main" > /etc/apt/sources.list.d/jessie.list \
# Stretch doesn't have a gcc-4.9 package, we need to
# fix this before jessie packages start breaking
#RUN echo "deb http://deb.debian.org/debian stretch main" > /etc/apt/sources.list.d/stretch.list \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
	bash-completion \
	clang-7 \
	curl \
	gnupg2 \
	ca-certificates \
	gcc \
	gcc-6 \
	gcc-5 \
	gcc-4.9 \
	libc6-dev \
	libelf-dev \
	libelf1 \
	llvm-7 \
	openjdk-8-jre-headless \
	python bzip2 && rm -rf /var/lib/apt/lists/*

# Since our base Debian image ships with GCC 6 which breaks older kernels, revert the
# default to gcc-4.9. Also, since some customers use some very old distributions whose kernel
# makefile is hardcoded for gcc-4.6 or so (e.g. Debian Wheezy), we pretend to have gcc 4.6/4.7
# by symlinking it to 4.9

RUN rm -rf /usr/bin/gcc \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc-4.8 \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc-4.7 \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc-4.6

RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/$SYSDIG_REPOSITORY/deb/draios.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends draios-agent \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
