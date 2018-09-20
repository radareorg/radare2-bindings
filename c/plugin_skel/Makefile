include foo.mk
include r2.mk

CFLAGS+=$(R2_CFLAGS)
LDFLAGS+=$(R2_LDFLAGS)


all: $(TARGETS)

%.$(SO_EXT): %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(TARGETS) $(R2_USER_PLUGINS)

clean:
	rm -f $(TARGETS)
