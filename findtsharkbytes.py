#!/usr/bin/python
import sys
import subprocess
import os

input=sys.argv[1]
filter=sys.argv[2]

compare="cp2-5000-anon.pcapng"
comparefilter="tcp.payload"

searchlen = 27*2
searchfile = compare

print "Extracting bytes from "+input+" with filter "+filter
output = subprocess.check_output(["tshark","-r",input,"-T","fields","-e",filter])
output = output.replace('\n', ':')
output = output.replace(':', '')

t = iter(output)
output = ':'.join(a+b for a,b in zip(t, t))

print "Extracted "+str(len(output))+" data "+output[0:30]+"..."

def checkbytes(chars):
		result = subprocess.check_output(["tshark","-r",searchfile,"-Y","frame contains "+chars])
		if result != "":
			print "Found: "+chars[0:11]+"... in "+searchfile
		else:
			print "Did not find: "+chars[0:11]+"..."

for c in xrange(0, len(output), searchlen):
	chars = output[c:c+searchlen-1]
	checkbytes(chars)






	
