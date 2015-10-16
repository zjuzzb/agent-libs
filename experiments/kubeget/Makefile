SDIR =./src
IDIR =./src
CC=g++
CFLAGS=-std=c++11 -Wall -Wextra -I$(IDIR) -DHAS_ANALYZER
#-fno-omit-frame-pointer
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Foundation/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Net/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Crypto/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/NetSSL_OpenSSL/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/XML/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Util/include
CFLAGS+=-I../../dependencies/protobuf-2.5.0/src
CFLAGS+=-I../../dependencies/curl-7.45.0/include
CFLAGS+=-I../../dependencies/libb64-1.2/include

LFLAGS=-L../../dependencies/poco-1.4.6p4-all/lib/Linux/x86_64
LFLAGS+=-L../../dependencies/protobuf-2.5.0/src/.libs
LFLAGS+=-L../../dependencies/curl-7.45.0/lib/.libs
LFLAGS+=-L../../dependencies/libb64-1.2/src
LFLAGS+=-lprotobuf -lPocoNetSSL -lPocoUtil -lPocoXML -lPocoCrypto -lPocoNet -lPocoFoundation -lpthread -lssl -lcrypto -lz -ldl -lcurl -lb64

FLAGS=$(CFLAGS)
FLAGS+=$(LFLAGS)

ODIR=obj

_DEPS = k8s.h k8s_net.h k8s_event_data.h k8s_dispatcher.h k8s_component.h k8s_proto.h draios.pb.h k8s_http.h k8s_poller.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = kubeget.o k8s.o k8s_net.o k8s_event_data.o k8s_dispatcher.o k8s_component.o k8s_proto.o jsoncpp.o draios.pb.o k8s_http.o k8s_poller.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: $(SDIR)/%.cpp $(DEPS)
	$(CC) -g -c -D_DEBUG -o $@ $< $(FLAGS)

kubeget: $(OBJ)
	$(CC) -o $@ $^ $(FLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ ./kubeget ./kubegetd
