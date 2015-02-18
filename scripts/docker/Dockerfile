FROM debian:wheezy

MAINTAINER Sysdig <support@sysdigcloud.com>

ENV REPO cgroups

RUN apt-get update \
 && apt-get install -y curl

RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/$REPO/deb/draios.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends draios-agent \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/opt/draios/bin/dragent"]
