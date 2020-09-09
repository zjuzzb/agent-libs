from debian:stable

MAINTAINER Sysdig <support@sysdig.com>

RUN apt-get update -o Acquire::Check-Valid-Until=false \
 && apt-get dist-upgrade -y \
 && apt-get install -y --no-install-recommends \
 curl
