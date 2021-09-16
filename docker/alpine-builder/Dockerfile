FROM alpine:3.13.5

ARG max_parallelism=1

RUN apk add \
        argp-standalone \
        autoconf \
        automake \
        bash \
        cmake \
        docker \
        elfutils-dev \
        g++ \
        gcc \
        git \
        libelf-static \
        libexecinfo-dev \
        libexecinfo-static \
        libtool \
        linux-headers \
        make \
        ncurses-dev \
        openssl-dev \
        patch \
        perl \
        pkgconfig \
        py-pip \
        python3 \
        rsync \
        zlib-dev

RUN ln -s  /usr/bin/python3 /usr/bin/python
# protobuf 3.18 doesn't support python 2. we're using 3 here but keep the version
# consistent with the original centos builder
RUN pip install 'protobuf<3.18'

RUN mkdir -p /code/agent/dependency_install_scripts
ADD dependency_install_scripts/* /code/agent/dependency_install_scripts/
RUN mkdir -p /code/agent/dependencies

ARG PROMSCRAPE_VERSION
RUN /code/agent/dependency_install_scripts/install-deps.sh /code/agent/dependencies ${max_parallelism}

ADD entrypoint.sh /
VOLUME [ "/code/agent/build", "/code/sysdig/build", "/code/libscap-hayabusa/producer_build", "/out", "/root/.cache" ]
ENTRYPOINT [ "/entrypoint.sh" ]
