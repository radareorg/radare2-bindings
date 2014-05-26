try:
	from r_bin import *
except:
	from r2.r_bin import *
b = RBin ()

# XXX broken test because now RBin depends on RIO
b.load ("/bin/ls", 0, 0, 0, -1, False)
baddr = b.get_baddr ()
print 'Base Address', baddr
print '-> Sections'
for i in b.get_sections ():
	print 'offset=0x%08x va=0x%08x size=%05i %s' % (
			i.offset, baddr+i.rva, i.size, i.name)

