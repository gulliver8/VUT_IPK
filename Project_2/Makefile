CC=g++
CFLAGS=-I.

sniffer: ipk-sniffer.o
	$(CC) -o ipk-sniffer ipk-sniffer.o -lpcap
clean: 
	rm *.o ipk-sniffer
