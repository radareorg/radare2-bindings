# created with sys/sdk.sh /tmp/r2-sdk
SDKDIR=/tmp/r2-sdk

CFLAGS=-I$(SDKDIR)/include
LDFLAGS=$(SDKDIR)/lib/lib*.a

all:
	$(CC) -Os $(CFLAGS) $(LDFLAGS) test-bin.c
