FROM python:2
RUN apt-get update && apt-get install -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
ADD https://get.docker.com/builds/Linux/x86_64/docker-1.7.1 /usr/bin/docker
RUN chmod +x /usr/bin/docker
RUN pip install docker-compose==1.5.2 protobuf pytest
RUN mkdir /code
ADD docker-entrypoint.sh /
WORKDIR /code
ENTRYPOINT [ "/docker-entrypoint.sh" ]
