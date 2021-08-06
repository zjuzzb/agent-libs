#!/bin/bash
#usage install-curl.sh <directory> <version> <url> <parallelism> <cares dir> <openssl dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
CARES_DIRECTORY=$5
OPENSSL_DIRECTORY=$6

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/curl-$VERSION.tar.bz2
tar -xjf curl-$VERSION.tar.bz2
cd curl-$VERSION
./configure --disable-shared  \
    --enable-optimize     \
    --disable-curldebug   \
    --disable-rt          \
    --enable-http         \
    --disable-ftp         \
    --disable-file        \
    --disable-ldap        \
    --disable-ldaps       \
    --disable-rtsp        \
    --disable-telnet      \
    --disable-tftp        \
    --disable-pop3        \
    --disable-imap        \
    --disable-smb         \
    --disable-smtp        \
    --disable-gopher      \
    --disable-sspi        \
    --disable-ntlm-wb     \
    --disable-tls-srp     \
    --without-winssl      \
    --without-darwinssl   \
    --with-ssl=$OPENSSL_DIRECTORY/target \
    --without-polarssl    \
    --without-cyassl      \
    --without-nss         \
    --without-axtls       \
    --without-ca-path     \
    --without-ca-bundle   \
    --without-libmetalink \
    --without-librtmp     \
    --without-winidn      \
    --without-libidn      \
    --without-nghttp2     \
    --enable-ares=$CARES_DIRECTORY/target
make -j $MAKE_JOBS
