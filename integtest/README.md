# Requirements

These tests require docker installed on the system

# Run tests

From this directory run:

```
docker build -t integtest . 
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/:/code -e DOCKER_IMAGE=sysdig/agent integtest
```
