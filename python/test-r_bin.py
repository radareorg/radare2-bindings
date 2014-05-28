try:
	from r_bin import *
except:
	from r2.r_bin import *

path="/bin/ls"

io = RIO()
desc = io.open(path, 0, 0)
if desc == None:
	print "Cannot open file"
	exit(1)

print "FD", desc.fd

b = RBin ()
b.iobind(io)

# XXX broken test because now RBin depends on RIO
b.load (path, 0, 0, 0, desc.fd, False)
baddr = b.get_baddr ()
print 'Base Address', baddr
print '-> Sections'
for i in b.get_sections ():
	print 'offset=0x%08x va=0x%08x size=%05i %s' % (
			i.paddr, baddr+i.vaddr, i.size, i.name)

