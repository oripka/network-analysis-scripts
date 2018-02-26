#!/usr/bin/env python
import os
import sys
from collections import Counter
import binascii
import argparse

def longest_common_substring(s1, s2):
	m = [[0] * (1 + len(s2)) for i in xrange(1 + len(s1))]
	longest, x_longest = 0, 0

	for x in xrange(1, 1 + len(s1)):
		for y in xrange(1, 1 + len(s2)):
			if s1[x - 1] == s2[y - 1]:
				m[x][y] = m[x - 1][y - 1] + 1
				if m[x][y] > longest:
					longest = m[x][y]
					x_longest = x
			else:
				m[x][y] = 0


	return s1[x_longest - longest: x_longest]

def usage():
	print ""


def removesubstring_from_list(cache, common_substrings):
	newcache = []

	if len(common_substrings) == 0:
		return cache

	for data in cache:
		newdata=data
		olddata=data
		for s in common_substrings:
			newdata=newdata.replace(s,'')
			#print ("Before: "+olddata+" after: "+newdata+ " removed: "+s)
		newcache.append(newdata)

	return newcache

#endianess error
def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)


def printresult(strings):
	print "Found "+str(len(strings))+" common substrings"
	for s in strings:
		sys.stdout.write(hexdump(s))
#		print('\t'+binascii.hexlify(s))

def main(stdin=sys.stdin, args=sys.argv):
	
	parser = argparse.ArgumentParser(description='Find longest common substrings in binary files.')

	parser.add_argument('--top', default=3 , type=int, metavar='n', help='print top N common substrings')
	parser.add_argument('inputfiles', metavar='FILE', nargs='+', help='input files')

	args = parser.parse_args()

	cache = []
	common_substrings = []
	for f in args.inputfiles:
		with open(f, "r") as tempfile:
			cache.append(tempfile.read())

	count=0

	for n in range(args.top):
		cache = removesubstring_from_list(cache, common_substrings)
		for i in range(len(cache)): 
			for j in range(len(cache)): 
				data1=cache[i]
				data2=cache[j]
		
				# compare only once and not with itself
				if i != j and i<j:
					stringtmp=longest_common_substring(data1,data2)
					if(len(stringtmp)==0):
						printresult(common_substrings)
						sys.exit(0)
					else:
						count=count+1
						common_substrings.append(longest_common_substring(data1,data2))
					#compares = compares + 1
					#print str(compares)+"\n"


	printresult(common_substrings)

if __name__ == "__main__":
	main()
