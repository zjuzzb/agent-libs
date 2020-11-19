from debian:stable

MAINTAINER Sysdig <support@sysdig.com>

ENV SYSDIG_REPOSITORY PLACEHOLDER_SEE_CMAKE_FILE

RUN apt-get update -o Acquire::Check-Valid-Until=false \
 && apt-get dist-upgrade -y \
 && apt-get install -y --no-install-recommends \
 curl \
 ca-certificates \
 gnupg

RUN curl -s https://download.sysdig.com/DRAIOS-GPG-KEY.public | apt-key add - \
 && curl -s -o /etc/apt/sources.list.d/draios.list https://download.sysdig.com/$SYSDIG_REPOSITORY/deb/draios.list \
 && apt-get update -o Acquire::Check-Valid-Until=false \
 && apt-get install -y --no-install-recommends draios-agentino

RUN apt-get remove -y curl

COPY ./agentino-entrypoint.sh /

ENTRYPOINT ["/agentino-entrypoint.sh"]
