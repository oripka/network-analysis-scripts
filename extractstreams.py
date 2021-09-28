#!/usr/bin/python
import sys
import subprocess
import argparse
import os.path
import os

def main(stdin=sys.stdin, args=sys.argv):

	parser = argparse.ArgumentParser(description='Extract streams based on display filter.')

	parser.add_argument('-f' , help='force overwrite existing outfile', action='store_true')	
	parser.add_argument('-v' , help='verbose', action='store_true')	
	parser.add_argument('-o' , help='one file per matched stream', action='store_true')
	parser.add_argument('-Y' , metavar='dfilter', help="display filter", required=True)
	parser.add_argument('-r' , metavar='infile', help='input file', required=True)
	parser.add_argument('-w' , metavar='outfile', help='file name of output file', required=True)
	args = parser.parse_args()

	do_one_file(args.r, args.Y, args.w, args.v, args.f, args.o)

def get_tcp_stream_ids(ifile, dfilter, twopass=False, verbose=False):
	streams = []

	one_pass = ["tshark","-r",ifile,"-Y",dfilter,"-T","fields","-e","tcp.stream"]
	tsharkcmd = one_pass
	result = subprocess.check_output(tsharkcmd)

	if result != "":
		streams = result.decode("utf-8").split("\r\n")

	if verbose:
		print(streams)

	return streams

def build_stream_filter(streams):
	filter = ""
	for stream in streams:
		if stream != "":
			filter = filter+"tcp.stream == "+stream+" or "
	filter = filter.rstrip(" or ")
	return filter

def get_stream_filters(streams):
	sfilters = []
	for stream in streams:
		sfilters.append("tcp.stream=="+stream)
	return sfilters

def extract_streams(ifile, dfilter, ofile):
	result = subprocess.check_output(["tshark","-r",ifile,"-Y",dfilter,"-w",ofile])

def rename_files(ofile, seq):
	if ".pcapng" in ofile:
		fname = ofile.rstrip(".pcapng")
		fname = fname+"-"+str(seq)+".pcapng"	

	if ".pcap" in ofile:
		fname = ofile.rstrip(".pcap")
		fname = fname+"-"+str(seq)+".pcap"	

	os.rename(ofile, fname)
	return fname

def do_one_file(ifile, dfilter, ofile, verbose=False, force=False, oneperfile=False):
	sfilters = []

	if os.path.isfile(ofile) and not force:
		print("[-] "+ofile+" exists. Refusing to overwrite it (use -f)")
		sys.exit(-1)

	print("[1] Getting stream IDs matching: "+dfilter)
	streams = get_tcp_stream_ids(ifile, dfilter, verbose)

	if not oneperfile:
		sfilters.append(build_stream_filter(streams))
	else:
		sfilters = get_stream_filters(streams)

	i = 0
	for filter in sfilters:

		if verbose:
			print("[*] Resulting filter expression: "+sfilter)

		if not oneperfile:
			print("[2] Extracting "+str(len(streams))+" streams from "+ifile+" to "+ofile)
						
		extract_streams(ifile, filter, ofile)
		if oneperfile:
			oname = rename_files(ofile, i)
			print("[2] Extracting "+filter+" from "+ifile+" to "+oname)
		i=i+1


if __name__ == "__main__":
	main()
