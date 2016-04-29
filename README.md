# Docker builder

To build agent using docker checkout agent and sysdig repositories on the same directory (ex `/draios`), then run on from `/draios/agent` directory:

```
docker build -t agent-builder:latest -f Dockerfile.builder .
```

After, to build and install the agent run:

```
docker run -it --name agent-install -v /draios:/draios:ro -v /opt/draios:/opt/draios -v /draios/pkgs:/out -v /var/run/docker.sock:/var/run/docker.sock agent-builder install
```

This command will install agent on `/opt/draios`. To build a package and docker image run:

```
docker run -it --name agent-package -v /draios:/draios:ro -v /opt/draios:/opt/draios -v /draios/pkgs:/out -v /var/run/docker.sock:/var/run/docker.sock agent-builder package
```

It will build a debian and rpm package, they will be put on `/draios/pkgs`. And also it will build a docker image close to the production one, with as name simply `agent`.

You can rerun a build by simply restarting the container with: `docker start -ia agent-install`

# Running

To run the previous built docker image use:

```
docker run -it --rm --name sysdig-agent --privileged --net host --pid host -e ACCESS_KEY=<yourkey> -e COLLECTOR=collector-staging.sysdigcloud.com -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro agent
```
