CC=cc
CFLAGS=-c -Wall

all: main

main: main.o
	$(CC) main.o -o main

	
main.o: main.c
	$(CC) $(CFLAGS) main.c

clean:
	rm -rf *.o main
