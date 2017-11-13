FROM debian:unstable AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
ADD main.c /
RUN gcc -O3 main.c -lrt -static -o posix-queue-cli && strip posix-queue-cli
FROM scratch
COPY --from=build /posix-queue-cli /
ENTRYPOINT [ "/posix-queue-cli" ]
