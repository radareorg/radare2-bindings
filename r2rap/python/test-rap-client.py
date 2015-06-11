from remote import RapClient
import os

port = 9999
cmd = 'r2 rap://:'+str(port)

try:
	rs = RapClient("localhost", port)
	if len(rs.cmd ("o"))<2:
		rs.open ("/bin/ls", 0)
	rs.cmd ("e scr.color=1")
	print (rs.read (10))
	#print (rs.cmd ("x 1024"))
	print (rs.cmd ("x"))
	print (rs.cmd ("pd 3"))
except:
	print ""
	print "You may like to run the same script in another terminal"
	print ""
	os.system(cmd)
