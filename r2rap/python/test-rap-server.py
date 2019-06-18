#!/usr/bin/python
#
# python example using the radapy (remote radare API for python)
#
# -- pancake // nopcode .org
#

from remote import RapServer
from string import *

PORT = 9999

def fun_system(str):
        global rs
	print "system"
        print "CURRENT SEEK IS %d"%rs.offset
	res = rs.system("?e hello world")
	print ("RES %s"%res)
        return str

def fun_open(file,flags):
        return file

def fun_seek(off,type):
	print "seek"
        return off

def fun_write(buf):
	print "write"
        print "WRITING %d bytes (%s)"%(len(buf),buf)
        return 6

def fun_read(size):
        global rs
        # print "READ %d bytes from %d\n"% (size, rs.offset)
        s = "Hello World From RapLand"
        s = s[rs.offset: rs.offset + size]
        return s

# main

#radapy.handle_cmd_open = fun_open
#radapy.handle_cmd_close = fun_close
rs = RapServer()
rs.handle_system = fun_system
rs.handle_read = fun_read
rs.handle_write = fun_write
rs.handle_cmd = fun_system
rs.size = 10
rs.listen_tcp (PORT)
