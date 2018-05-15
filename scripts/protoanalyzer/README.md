# Protobuf collection analyzer

## How to use (via container)

- build & tag the image

        docker build -t protoanalyzer .

- identify the location of your `.dam` files on the host - let's assume it's:

        /Users/<user>/workspace/SYSDIG/agent/scripts/protoanalyzer/xxxxx/yyyyyy/

- run the script making sure the name of the mount point inside the container matches the one used in the `--binary` argument

        docker run -v /Users/<user>/workspace/SYSDIG/agent/scripts/protoanalyzer/xxxxx/yyyyyy/:/data protoanalyser --binary /data/1516220770000000000.dam
        
# TODO

Install protobuf-to-dict from the code of this [PR}(https://github.com/benhodgson/protobuf-to-dict/pull/18) to make `infrastructure_state` protobuf sections parsable by protoanalyzer
