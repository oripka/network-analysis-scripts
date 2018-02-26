#!/usr/bin/python
import sys
import subprocess
import os
import time
from collections import Counter
import binascii
import argparse


"""./matchpayload.py FILE1 FILTER1 FILE2 FILTER2 --chunklen 10 

Matchpayload helps to correlate two trace files taken at different capture points
by payload. This technique is only necessary if all other common correlation 
techniques like ip.id, conversation filter, TCP sequence numbers, ... fail because
the connection travels over NAT, Proxy, devices that refragment packets, etc

Matchpayload correlates packets based on payload bytes following these steps:

1. Extract all payload bytes defined by the Wireshark display filter FILTER1 from FILE1
	- for a SMB connection FILTER1 would be nbss.continuation_data
	- for a TCP connection it would be tcp.payload
	- for FTP-DATA it would be ftp.data

2. Extract all payload bytes define by the Wireshark display filter FILTER2 from FILE2

3. All extracted bytes from FILE1 are merged into one continuous byte string

4. The byte string is then split in chunks defined by --chunklen (10 chars = 5 bytes)

5. The chunks of length --chunklen are then searched in the bytes extracted from FILE2

6. Matches of byte strings are displayed together with the frame.number of the corresponding
   packets in the both trace files 

Example:

./matchpayload.py cp1-5000-anon.pcapng nbss.continuation_data cp2-5000-anon.pcapng tcp.payload --chunklen 10
[+] Comparing cp1-5000-anon.pcapng and cp2-5000-anon.pcapng
[+] ...with chunks of 10 bytes
[+] Extracted 2755 packet data segments a 10 from cp1-5000-anon.pcapng
[+] Extracted 3851 packet data from cp2-5000-anon.pcapng

Packet: 1876 and 4861 match 10 bytes: 86:6f:fc:14:6f
Packet: 1876 and 4861 match 10 bytes: c4:aa:df:b3:6f
Packet: 1876 and 4861 match 10 bytes: ec:9f:ff:00:04
Packet: 1876 and 4861 match 10 bytes: ff:00:f0:8f:c3
Packet: 1877 and 4862 match 10 bytes: 26:93:64:8a:a4
Packet: 1877 and 4862 match 10 bytes: 5b:a6:f9:58:16
Packet: 1877 and 4862 match 10 bytes: ec:a7:a9:15:95
Packet: 1877 and 4862 match 10 bytes: ab:41:3e:89:e2
Packet: 1877 and 4862 match 10 bytes: 39:e1:9a:d5:a5
"""

matches = []

class MatchResult:
	def __init__(self, packet1, packet2, match):
		self.packet1 = packet1
		self.packet2 = packet2
		self.len = len(match)
		self.match = match

	def __str__(self):
		t = iter(self.match)
		hexd = ':'.join(a+b for a,b in zip(t, t))
		return "Packet: "+self.packet1[0]+" and "+self.packet2[0]+" match "+str(self.len)+" bytes: "+hexd

def findbytes(string1, string2):
	if string1 in string2:
		return string1
	else:
		return ""

def addmatch(packet1, packet2, minimalmatch):
	match = findbytes(packet1[1], packet2[1])
	if(match!="") and len(match) >= minimalmatch:
		matches.append(MatchResult(packet1, packet2, match))

def getbytes(filename, filter, searchlen=10000):
	out = []
	output = subprocess.check_output(["tshark","-r",filename,"-T","fields","-e","frame.number","-e",filter])
	output = output.replace(':', '')

	for line in output.split('\n'):
		if '\t' in line:
			pktnum, data = line.split('\t')
			if data != "":
				# chop up data in max searchlen
				for c in xrange(0, len(data), searchlen):
					chars = data[c:c+searchlen]
					out.append([pktnum, chars])

	if searchlen > 9000:
		print "[+] Extracted "+str(len(out))+" packet data from "+filename
	else:	
		print "[+] Extracted "+str(len(out))+" packet data segments a "+str(searchlen)+" from "+filename
	return out

def main(stdin=sys.stdin, args=sys.argv):

	usage = \
"""./matchpayload.py FILE1 FILTER1 FILE2 FILTER2 --chunklen 10

Use --usage to get more help
"""
	
	#example ./matchpayload.py cp1-5000-anon.pcapng nbss.continuation_data cp2-5000-anon.pcapng tcp.payload --chunklen 10

	parser = argparse.ArgumentParser(description='Check for packet bytes of one trace file in another.', usage=usage)

	parser.add_argument('file1', help='file1')
	parser.add_argument('file1filter', help='file1 filter')
	parser.add_argument('file2', help='file2')
	parser.add_argument('file2filter', help='file2 filter')

	parser.add_argument('--chunklen', default=10 , type=int, metavar='n', help='chunk size of data in file1')
	args = parser.parse_args()

	searchlen = args.chunklen

	print "[+] Comparing "+args.file1+" and "+args.file2
	print "[+] ...with chunks of "+str(searchlen)+" bytes"

	out1 = getbytes(args.file1, args.file1filter, searchlen)
	out2 = getbytes(args.file2, args.file2filter)

	for i in range(len(out1)): 
		for j in range(len(out2)):
			addmatch(out1[i], out2[j], searchlen)

	print ""
	for match in matches:
		print match

if __name__ == "__main__":
	main()

sys.exit(0)