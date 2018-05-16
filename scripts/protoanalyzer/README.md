[![Docker Repository on Quay](https://quay.io/repository/sysdig/protoanalyzer/status?token=48015cd3-0a14-434b-b45d-aeaaa4f4f042 "Docker Repository on Quay")](https://quay.io/repository/sysdig/protoanalyzer)

# Protobuf collection analyzer

## How to use (via container)

- build & tag the image

```
docker build -t protoanalyzer .
```

- identify the location of your `.dam` files on the host - let's assume it's:

```
/Users/<user>/workspace/SYSDIG/agent/scripts/protoanalyzer/xxxxx/yyyyyy/
```
- run the script making sure the name of the mount point inside the container matches the one used in the `--binary` argument

```
docker run -v /Users/<user>/workspace/SYSDIG/agent/scripts/protoanalyzer/xxxxx/yyyyyy/:/data protoanalyzer --binary /data/1516220770000000000.dam
```

TIP: you can also use `quay.io/sysdig/protoanalyzer` available on Quay

## Regenerate protobuf

To regenerate `*_pb2.py` files used by this script use these commands:

```
cd ~/draios/backend/sysdig-backend/agent-protobuf
protoc --python_out=. -Isrc/main/proto src/main/proto/draios.proto
protoc --python_out=. -Isrc/main/proto src/main/proto/common.proto
mv common_pb2.py draios_pb2.py ~/draios/agent/scripts/protoanalyzer
```