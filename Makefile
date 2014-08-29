CC=g++
CFLAGS=-c -Wall

all: sendfile receiver

sendfile: sendfile.o
	$(CC) -pthread sendfile.o -o sendfile

receiver: receiver.o
	$(CC) -pthread receiver.o -o receiver

sendfile.o: sendfile.cpp
	$(CC) $(CFLAGS) sendfile.cpp

receiver.o: receiver.cpp
	$(CC) $(CFLAGS) receiver.cpp

clean:
	$(RM) sendfile receiver receiver.o sendfile.o