FROM debian:latest

RUN apt-get update \
 && apt-get install -y stress-ng \
 && apt-get clean

# io 4 results in about 25k system events per second
CMD stress-ng --io 4

