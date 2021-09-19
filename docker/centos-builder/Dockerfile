FROM centos:6

ARG max_parallelism=1

ADD *.repo /etc/yum.repos.d/

RUN yum install -y ca-certificates && \
    update-ca-trust force-enable && \
    curl -o /etc/pki/ca-trust/source/anchors/lets-encrypt-r3-cross-signed.pem https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem && \
    update-ca-trust extract

# protobuf 3.18 doesn't support python 2. stick to 3.17
RUN curl -o /etc/yum.repos.d/devtools-2.repo https://people.centos.org/tru/devtools-2/devtools-2.repo && \
    rpm -i https://archives.fedoraproject.org/pub/archive/epel/6/i386/epel-release-6-8.noarch.rpm && \
    sed -e 's,$basearch,i386,' -e 's,$releasever\],$releasever-i686\],' /etc/yum.repos.d/devtools-2.repo > /etc/yum.repos.d/devtools-2-i686.repo && \
    yum -y install \
        createrepo \
        devtoolset-2-toolchain \
        dpkg \
        dpkg-devel \
        expect \
        gcc \
        gcc-c++ \
        git \
        glibc-static \
        make \
        pkg-config \
        rpm-build \
        unzip \
        wget \
        tar \
        autoconf \
        automake \
        libtool \
        valgrind \
        centos-release-scl \
        lcov \
        libffi-devel \
        zlib-devel \
        openssl-devel && \
    yum -y install \
        python27 \
        glibc-devel.i686 \
        devtoolset-2-libstdc++-devel.i686 \
        devtoolset-2-elfutils-libelf-devel \
        java-1.8.0-openjdk && \
    scl enable python27 "yum install -y python-pip" && \
    scl enable python27 "pip install 'protobuf<3.18'" && \
    yum clean all

RUN curl -o docker.tgz https://get.docker.com/builds/Linux/x86_64/docker-1.11.0.tgz && \
    tar xfz docker.tgz docker/docker && \
    mv docker/docker /usr/local/bin/docker && \
    chmod +x /usr/local/bin/docker && \
    rm -fr docker.tgz docker/

# For sonar to work, set JAVA_HOME and add it to the PATH
ENV JAVA_HOME=/usr/lib/jvm/jre-openjdk \
    PATH="$JAVA_HOME/bin:${PATH}"

RUN mkdir -p /code/agent/dependency_install_scripts
ADD dependency_install_scripts/* /code/agent/dependency_install_scripts/
RUN mkdir -p /code/agent/dependencies

ARG PROMSCRAPE_VERSION
RUN scl enable devtoolset-2 "/code/agent/dependency_install_scripts/install-deps.sh /code/agent/dependencies ${max_parallelism}"

ADD entrypoint.sh /
VOLUME [ "/code/agent/build", "/code/sysdig/build", "/out", "/root/.cache" ]
ENTRYPOINT [ "/entrypoint.sh" ]
