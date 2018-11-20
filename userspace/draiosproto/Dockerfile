FROM python:2
MAINTAINER Grzegorz Nosek <grzegorz.nosek@sysdig.com>

RUN cd /usr/local && apt-get update && apt-get -y install wget unzip && wget https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip && unzip protoc-3.5.1-linux-x86_64.zip && rm -f protoc-3.5.1-linux-x86_64.zip readme.txt
ADD *.proto /proto/
RUN /usr/local/bin/protoc -I=/proto --python_out=. /proto/draios.proto

ADD protoanalyzer/requirements.txt .
RUN pip install -r requirements.txt
ADD protoanalyzer/protoanalyzer.py .
ENTRYPOINT [ "python", "./protoanalyzer.py" ]
