# test1.py
from capstone import *
import sys
import os
import binascii

f = sys.argv[1]

def to_hex(s):
    return " ".join("" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK

cache = ""

with open(f, "r") as tempfile:
	cache = tempfile.read()


disuccess=False
counter=0

md = Cs(CS_ARCH_X86, CS_MODE_32)
for n in range(0,len(cache)):
	disuccess=False
	for x in (md.disasm(cache[n:len(cache)], n)):
		disuccess=True
	if disuccess:
		print "Successfully disassembled @"+str(n)
		counter=0
		for i in md.disasm(cache[n:len(cache)], n):
			print "%s | 0x%x:\t%s\t%s" % (to_hex(cache[n+counter:n+counter+i.size]+""), i.address, i.mnemonic, i.op_str)
			counter= counter + 4

