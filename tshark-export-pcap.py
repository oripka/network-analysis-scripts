#!/usr/bin/python
import sys
import os

input=str(sys.argv[1])
tcpconnection="tcp"
output="out.json"

fields = [
		"frame.number",
		"frame.time",
		"frame.time_relative",
		"frame.time_delta_displayed",
		"frame.len",
		"frame.cap_len",
		"eth.dst",
		"eth.src",
		"ip.dsfield.dscp",
		"ip.dsfield.ecn",
		"ip.hdr_len",
		"ip.id",
		"ip.flags.rb",
		"ip.flags.df",
		"ip.flags.mf",
		"ip.frag_offset",
		"ip.ttl",
		"ip.proto",
		"ip.src",
		"ip.dst",
		"ip.bogus_ip_length",
		"ip.bogus_ip_version",
		"ip.checksum.status",
		"tcp.srcport",
		"tcp.dstport",
		"tcp.len",
		"tcp.seq",
		"tcp.nxtseq",
		"tcp.hdr_len",
		"tcp.ack",
		"tcp.flags.res",
		"tcp.flags.ns",
		"tcp.flags.ecn",
		"tcp.flags.urg",
		"tcp.flags.ack",
		"tcp.flags.push",
		"tcp.flags.reset",
		"tcp.flags.syn",
		"tcp.flags.fin",
		"tcp.window_size_value",
		"tcp.window_size",
		"tcp.window_size_scalefactor",
		"tcp.urgent_pointer",
		"tcp.analysis.initial_rtt",
		"tcp.analysis.bytes_in_flight",
		"tcp.analysis.push_bytes_sent",
		"tcp.analysis.flags"
	]

fieldsopt = " -e ".join(fields)
fstr = "-e "+str(fieldsopt)

os.system("tshark -r "+input+" -Y "+tcpconnection+" -T fields "+fstr+" > "+output)

print ""
