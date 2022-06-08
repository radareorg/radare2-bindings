include ../../config.mk

TESTS=core asm lang regs sc hash sc
ALLTESTS=$(TESTS) bin socket search list

all: $(ALLTESTS)
	$(MAKE) plugin.$(SOEXT)
	for a in $(TESTS) ; do echo ==$$a ; ./$$a || exit 1 ; done

all2: bin lang core asmsearch bwdisassemble regs hash sc socket asm search db io list rgot plugin.${SOEXT}
	@true

plugin.${SOEXT}:
	valac plugin.vala pluginwrap.c \
		--library=plugin -o plugin.${SOEXT} \
		--Xcc=-shared --Xcc=-fPIC --vapidir=.. \
		--pkg r_cmd --pkg r_util --pkg r_core

config:
	valac --vapidir=.. cfg.vala --pkg r_config --pkg r_util --pkg r_db

code_search:
	valac --vapidir=.. code_search.vala --pkg r_core --pkg r_bin

rgot:
	valac --vapidir=.. rgot.vala --pkg r_bin --pkg r_util

reloc:
	valac --vapidir=.. reloc.vala --pkg r_bin --pkg r_util

bintest:
	valac --vapidir=.. bintest.vala --pkg r_bin --pkg r_util 

regs:
	valac --vapidir=.. --pkg r_reg regs.vala --pkg r_util

lang:
	valac --vapidir=.. lang.vala --pkg r_lang --pkg r_util

list:
	valac -o list list.vala --pkg r_util --vapidir=..

listc:
	valac -C -o list list.vala --pkg r_util --vapidir=..

genie:
	valac --vapidir=.. --pkg r_asm --pkg libr asm.gs
	valac --vapidir=.. --pkg r_search --pkg libr search.gs

io:
	valac --vapidir=.. --pkg r_io io.vala

db:
	valac --vapidir=.. --pkg r_db db.vala

sc:
	valac --vapidir=.. sc.vala --pkg r_syscall --pkg r_util

core:
	valac --vapidir=.. core.vala --pkg r_asm --pkg r_anal --pkg r_core --pkg r_cons --pkg r_bp

asmsearch:
	valac --vapidir=.. asmsearch.vala --pkg r_core --pkg r_bin -o asmsearch

bwdisassemble:
	valac --vapidir=.. bwdisassemble.vala --pkg r_core --pkg r_bin -o bwdisassemble

search:
	valac --vapidir=.. search.vala --pkg r_search --pkg r_util

asm:
	valac --vapidir=.. --pkg r_asm asm.vala

bin:
	valac --vapidir=.. bin.vala --pkg r_bin --pkg r_util

hash:
	valac --vapidir=.. hash.vala --pkg r_hash

socket:
	valac --vapidir=.. socket.vala --pkg r_socket --pkg posix

clean:
	-rm -f `ls *.c | grep -v wrap` hash sc *.o *.h core socket asm search bin io rgot reloc asmsearch bwdisassemble

# XXX: deprecate??
#array:
#	valac --vapidir=.. --pkg r_util array.vala
#arrayc:
#	valac -C --vapidir=.. --pkg r_util array.vala

