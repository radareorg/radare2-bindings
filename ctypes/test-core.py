from r_core import *

c = RCore ()

h = c.file_open (b"/bin/ls", 0, 0);
c.bin_load (None, 0)
c.cmd0("s entry0")
print (c.cmd_str (b"px").decode())
#c.cmd0 (b"pd 10 @ entry0")
#c.cmd0 (b"px 20 @ 0")

print ("*** "+c.cmd_str(b'p8 16').decode())
c.cmd0 (b"p8 20")

print("---")
c.cmd0 (b"p8 20 @ $$+1")
c.cons.flush()

c.cmd0 (b"pd 3")
c.cons.flush()
