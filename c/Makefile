# created with sys/sdk.sh /tmp/r2-sdk
#SDKDIR=/tmp/r2-sdk
#CFLAGS=-I$(SDKDIR)/include
#LDFLAGS=$(SDKDIR)/lib/lib*.a

CFLAGS=$(shell pkg-config --cflags r_bin r_util)
LDFLAGS=$(shell pkg-config --libs r_bin r_util)

all:
	$(CC) -Os $(CFLAGS) $(LDFLAGS) test-bin.c
