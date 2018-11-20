[![Docker Repository on Artifactory](https://artifactory.internal.sysdig.com/artifactory/webapp/#/artifacts/browse/tree/General/docker-local/protoanalyzer)

# Protobuf collection analyzer

## How to use (via container)

- pull the image from Artifactory

```
docker pull docker.internal.sysdig.com/protoanalyzer
```

- alternatively, build & tag the image

```
docker build -t protoanalyzer ..
```

- identify the location of your `.dam` files on the host - let's assume it's:

```
/Users/<user>/workspace/SYSDIG/agent/scripts/protoanalyzer/xxxxx/yyyyyy/
```

- run the script making sure the name of the mount point inside the container matches the one used in the `--binary` argument

```
docker run -v /Users/<user>/workspace/SYSDIG/agent/scripts/protoanalyzer/xxxxx/yyyyyy/:/data docker.internal.sysdig.com/protoanalyzer --binary /data/1516220770000000000.dam
```

Note: if you built the image yourself, use just `protoanalyzer` instead of `docker.internal.sysdig.com/protoanalyzer`
