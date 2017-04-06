MAKEDIR = $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
DEPDIR = $(realpath $(MAKEDIR)/../../dependencies)

DRAIOS_POCO = poco-1.4.6p4-all
DRAIOS_PROTOBUF = protobuf-2.5.0
DRAIOS_CURL = curl-7.52.1
DRAIOS_B64 = libb64-1.2
DRAIOS_OPENNSL = openssl-1.0.2j
DRAIOS_JQ = jq-1.5

SDIR =$(MAKEDIR)/src
IDIR =$(MAKEDIR)/src
CC=g++
CFLAGS =-std=c++11 -Wall -Wextra -I$(IDIR) -DHAS_ANALYZER -DHAS_CAPTURE -DGLIBCXX_FORCE_NEW -DK8S_DISABLE_THREAD -fno-omit-frame-pointer
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_POCO)/Foundation/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_POCO)/Net/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_POCO)/Crypto/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_POCO)/NetSSL_OpenSSL/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_POCO)/XML/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_POCO)/Util/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_PROTOBUF)/src
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_CURL)/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_B64)/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_OPENNSL)/target/include
CFLAGS+=-I$(DEPDIR)/$(DRAIOS_JQ)

LFLAGS =-L$(DEPDIR)/$(DRAIOS_POCO)/lib/Linux/x86_64
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_PROTOBUF)/src/.libs
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_CURL)/lib/.libs
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_B64)/src
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_OPENNSL)/target/lib
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_JQ)/.libs

LIBS=-Wl,-Bstatic -lprotobuf -lPocoNetSSL -lPocoUtil -lPocoXML -lPocoCrypto -lPocoNet -lPocoFoundation -ljq -lcurl -lssl -lcrypto -Wl,-Bdynamic -lpthread -lz -ldl -lb64 -lrt -lanl

ODIR=$(MAKEDIR)/obj

_DEPS = draios.pb.h k8s.h k8s_api_handler.h k8s_event_data.h k8s_component.h k8s_daemonset_handler.h k8s_deployment_handler.h k8s_event_data.h k8s_event_handler.h k8s_handler.h k8s_namespace_handler.h k8s_net.h k8s_node_handler.h k8s_pod_handler.h k8s_proto.h k8s_replicaset_handler.h k8s_replicationcontroller_handler.h k8s_service_handler.h k8s_state.h sinsp_auth.h uri.h user_event.h uri_parser.h json_query.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = draios.pb.o k8s.o k8s_api_handler.o k8s_event_data.o k8s_component.o k8s_daemonset_handler.o k8s_deployment_handler.o k8s_event_data.o k8s_event_handler.o k8s_handler.o k8s_namespace_handler.o k8s_net.o k8s_node_handler.o k8s_pod_handler.o k8s_proto.o k8s_replicaset_handler.o k8s_replicationcontroller_handler.o k8s_service_handler.o k8s_state.o sinsp_auth.o jsoncpp.o uri.o user_event.o uri_parser.o json_query.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all: directory kubeget

kubeget: $(ODIR)/kubeget.o $(OBJ)
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

$(ODIR)/%.o: $(SDIR)/%.cpp $(DEPS)
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

$(ODIR)/kubeget.o: $(SDIR)/kubeget.cpp
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

.PHONY: clean directory

clean:
	rm -f *~ core $(INCDIR)/*~ ./kubeget ./kubegetd && rm -rf $(ODIR) 

directory: $(ODIR)

$(ODIR):
	mkdir -p $(ODIR)

