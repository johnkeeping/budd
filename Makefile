all:: budd

CFLAGS = -Wall -O2 -g -ggdb

RM ?= rm -f
BUDD_CFLAGS := $(CFLAGS) -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -std=c99
BUDD_CFLAGS += $(shell curl-config --cflags)
BUDD_LDFLAGS := $(LDFLAGS) $(shell curl-config --libs)

clean:
	$(RM) budd *.o

.PHONY: all clean

budd.o: EXTRA_CFLAGS=-DBUDD_VERSION='"0.1"'

%.o: %.c
	$(CC) $(BUDD_CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $<

budd: budd.o
	$(CC) $(BUDD_CFLAGS) -o $@ $^ $(BUDD_LDFLAGS)
