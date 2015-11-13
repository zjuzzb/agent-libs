MAKEDIR = $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
DEPDIR = $(realpath $(MAKEDIR)/../../dependencies)

DRAIOS_POCO = poco-1.4.6p4-all
DRAIOS_PROTOBUF = protobuf-2.5.0
DRAIOS_CURL = curl-7.45.0
DRAIOS_B64 = libb64-1.2
DRAIOS_OPENNSL = openssl-1.0.2d

SDIR =$(MAKEDIR)/src
IDIR =$(MAKEDIR)/src
CC=g++
CFLAGS =-std=c++11 -Wall -Wextra -I$(IDIR) -DHAS_ANALYZER -DGLIBCXX_FORCE_NEW -DK8S_DISABLE_THREAD -fno-omit-frame-pointer
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

LFLAGS =-L$(DEPDIR)/$(DRAIOS_POCO)/lib/Linux/x86_64
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_PROTOBUF)/src/.libs
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_CURL)/lib/.libs
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_B64)/src
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_OPENNSL)/target/lib

LIBS=-Wl,-Bstatic -lprotobuf -lPocoNetSSL -lPocoUtil -lPocoXML -lPocoCrypto -lPocoNet -lPocoFoundation -lcurl -lssl -lcrypto -Wl,-Bdynamic -lpthread -lz -ldl -lb64

ODIR=$(MAKEDIR)/obj

_DEPS = k8s.h k8s_net.h k8s_event_data.h k8s_dispatcher.h k8s_component.h k8s_proto.h draios.pb.h k8s_http.h k8s_collector.h uri.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = k8s.o k8s_net.o k8s_event_data.o k8s_dispatcher.o k8s_component.o k8s_proto.o jsoncpp.o draios.pb.o k8s_http.o k8s_collector.o uri.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all: directory kubeget

kubeget: $(ODIR)/kubeget.o $(OBJ)
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

$(ODIR)/%.o: $(SDIR)/%.cpp $(DEPS)
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

$(ODIR)/kubeget.o: $(SDIR)/kubeget.cpp
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

.PHONY: clean directory

clean:
	rm -f *~ core $(INCDIR)/*~ ./kubeget ./kubegetd && rm -rf $(ODIR) 

directory: $(ODIR)

$(ODIR):
	mkdir -p $(ODIR)

