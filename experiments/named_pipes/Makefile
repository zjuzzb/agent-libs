CC=cc
CFLAGS=-c -Wall

all: writer reader

writer: writer.o
	$(CC) writer.o -o writer

writer.o: writer.c
	$(CC) $(CFLAGS) writer.c

reader: reader.o
	$(CC) reader.o -o reader

reader.o: reader.c
	$(CC) $(CFLAGS) reader.c


clean:
	rm -rf *.o writer reader
