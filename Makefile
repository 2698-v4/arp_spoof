CC=gcc
CFLAGS=-lpcap
OBJS=main.o
TARGET=arp_spoof

$(TARGET):	$(OBJS)
	$(CC) -o $@	$(OBJS) $(CFLAGS)

arp_spoof:	main.o
main.o:	arp_spoof.h main.c
clean:
	rm -f *.o
	rm -f $(TARGET)