FROM debian:unstable
MAINTAINER Grzegorz Nosek <grzegorz.nosek@sysdig.com>

RUN cd /usr/local && apt-get update && apt-get -y install wget unzip && wget https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip && unzip protoc-3.5.1-linux-x86_64.zip && rm -f protoc-3.5.1-linux-x86_64.zip readme.txt
CMD /usr/local/bin/protoc -I=/draios/agent/userspace/draiosproto --python_out=/draios/agent/scripts/protoanalyzer /draios/agent/userspace/draiosproto/draios.proto
