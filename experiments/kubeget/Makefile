SDIR =./src
IDIR =./src
CC=g++
CFLAGS=-DK8S_STANDALONE -std=c++11 -Wall -Wextra -I$(IDIR) -lprotobuf -lPocoNetSSL -lPocoUtil -lPocoXML -lPocoCrypto -lPocoNet -lPocoFoundation -lpthread -lssl -lcrypto -lz -ldl
#-fno-omit-frame-pointer
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Foundation/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Net/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Crypto/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/NetSSL_OpenSSL/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/XML/include
CFLAGS+=-I../../dependencies/poco-1.4.6p4-all/Util/include
CFLAGS+=-I../../dependencies/protobuf-2.5.0/src
CFLAGS+=-L../../dependencies/poco-1.4.6p4-all/lib/Linux/x86_64
CFLAGS+=-L../../dependencies/protobuf-2.5.0/src/.libs

ODIR=obj

_DEPS = k8s.h k8s_net.h k8s_event_data.h k8s_dispatcher.h k8s_component.h draios.pb.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = kubeget.o k8s.o k8s_net.o k8s_event_data.o k8s_dispatcher.o k8s_component.o jsoncpp.o draios.pb.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: $(SDIR)/%.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kubeget: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
