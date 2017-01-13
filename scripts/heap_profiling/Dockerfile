FROM sysdig/agent:dev

ADD https://raw.githubusercontent.com/gperftools/gperftools/gperftools-2.5/src/pprof /usr/local/bin/pprof
RUN chmod +x /usr/local/bin/pprof

RUN apt-get update \
 && apt-get install -y gv graphviz \
 && apt-get clean

COPY ./parse_heap_profiling.py /
ENTRYPOINT ["/parse_heap_profiling.py", "/draios.log"]
