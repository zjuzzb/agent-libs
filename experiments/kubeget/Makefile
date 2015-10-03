#
# Makefile
#
# $Id: //poco/1.4/Net/samples/kubeget/Makefile#1 $
#
# Makefile for Poco kubeget
#

LINKMODE = STATIC

include $(POCO_BASE)/build/rules/global

CXXFLAGS += -std=c++11 -fno-omit-frame-pointer

SYSLIBS += -L$(PROJECT_BASE)/../../dependencies/protobuf-2.5.0/src/.libs -lprotobuf -lssl -lcrypto -lz -ldl
INCLUDE += -I$(PROJECT_BASE)/../../dependencies/protobuf-2.5.0/src

objects = kubeget k8s k8s_net k8s_component k8s_dispatcher jsoncpp draios.pb

target         = kubeget
target_version = 1
target_libs    = PocoNetSSL PocoNet PocoUtil PocoXML PocoCrypto PocoFoundation

include $(POCO_BASE)/build/rules/exec
