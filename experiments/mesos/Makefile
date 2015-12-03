MAKEDIR = $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
DEPDIR = $(realpath $(MAKEDIR)/../../dependencies)
JSONDIR = $(realpath $(MAKEDIR)/../../../sysdig/userspace/libsinsp/third-party/jsoncpp)

DRAIOS_POCO = poco-1.4.6p4-all
DRAIOS_PROTOBUF = protobuf-2.5.0
DRAIOS_CURL = curl-7.45.0
DRAIOS_B64 = libb64-1.2
DRAIOS_OPENNSL = openssl-1.0.2d

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
CFLAGS+=-I$(JSONDIR)

LFLAGS =-L$(DEPDIR)/$(DRAIOS_POCO)/lib/Linux/x86_64
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_PROTOBUF)/src/.libs
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_CURL)/lib/.libs
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_B64)/src
LFLAGS+=-L$(DEPDIR)/$(DRAIOS_OPENNSL)/target/lib

LIBS=-Wl,-Bstatic -lprotobuf -lcurl -lssl -lcrypto -lPocoFoundation -Wl,-Bdynamic -lpthread -lz -ldl -lb64

ODIR=$(MAKEDIR)/obj

_DEPS = mesos.h mesos_state.h mesos_component.h mesos_http.h mesos_proto.h m6n_component.h draios.pb.h uri.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = mesos.o mesos_state.o mesos_component.o mesos_http.o mesos_proto.o m6n_component.o jsoncpp.o draios.pb.o uri.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all: directory mesosget

mesosget: $(ODIR)/mesosget.o $(OBJ)
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS)

$(ODIR)/%.o: $(SDIR)/%.cpp $(DEPS)
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

$(ODIR)/mesosget.o: $(SDIR)/mesosget.cpp
	$(CC) -g3 -c -D_DEBUG -o $@ $< $(CFLAGS)

.PHONY: clean directory

clean:
	rm -f *~ core $(INCDIR)/*~ ./mesosget ./mesosgetd && rm -rf $(ODIR) 

directory: $(ODIR)

$(ODIR):
	mkdir -p $(ODIR)

