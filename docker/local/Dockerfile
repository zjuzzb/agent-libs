FROM debian:unstable

MAINTAINER Sysdig <support@sysdig.com>

ENV SYSDIG_REPOSITORY dev

ENV SYSDIG_HOST_ROOT /host

ENV AGENT_VERSION 0.1.1dev

ENV HOME /root

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN echo "deb http://deb.debian.org/debian jessie main" > /etc/apt/sources.list.d/jessie.list \
# Stretch doesn't have a gcc-4.9 package, we need to
# fix this before jessie packages start breaking
#RUN echo "deb http://deb.debian.org/debian stretch main" > /etc/apt/sources.list.d/stretch.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
	bash-completion \
	curl \
	gnupg2 \
	ca-certificates \
	gcc \
	gcc-6 \
	gcc-5 \
	gcc-4.9 \
	libelf1 \
	openjdk-8-jre-headless \
	python dkms bzip2 && rm -rf /var/lib/apt/lists/*

# Since our base Debian image ships with GCC 6 which breaks older kernels, revert the
# default to gcc-4.9. Also, since some customers use some very old distributions whose kernel
# makefile is hardcoded for gcc-4.6 or so (e.g. Debian Wheezy), we pretend to have gcc 4.6/4.7
# by symlinking it to 4.9

RUN rm -rf /usr/bin/gcc \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc-4.8 \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc-4.7 \
 && ln -s /usr/bin/gcc-4.9 /usr/bin/gcc-4.6

RUN ln -s $SYSDIG_HOST_ROOT/lib/modules /lib/modules

ADD draios-${AGENT_VERSION}-x86_64-agent.deb /
RUN dpkg -i /draios-${AGENT_VERSION}-x86_64-agent.deb
COPY ./docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
