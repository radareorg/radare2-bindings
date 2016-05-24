SDB_VAPI_URL=https://raw.github.com/radare/sdb/master/bindings/vala/sdb.vapi

all:

install:
	cd .. ; ${MAKE} install-vapi

uninstall:
	cd .. ; ${MAKE} uninstall-vapi

sdb-update update-sdb r_db.vapi:
	awk '{if(/SDB/){exit;}print;}' r_db.vapi > r_db.vapi.orig
	wget -O sdb.vapi $(SDB_VAPI_URL)
	cat r_db.vapi.orig sdb.vapi > r_db.vapi
	rm -f sdb.vapi r_db.vapi.orig

.PHONY: r_db.vapi sdb-update update-sdb
