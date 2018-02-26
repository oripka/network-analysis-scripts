#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
#import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Import scapy
from scapy.all import *

# Set up target IP
ip=IPv6(dst="localhost")

sys.setrecursionlimit(15000000)
for x in range(0,2):
	ip=ip/ip


# Generate random source port number
port=RandNum(1024,65535)

# Create SYN packet
SYN=ip/TCP(sport=port, dport=80, flags="S", seq=42)

# Send SYN and receive SYN,ACK
print "\n[*] Sending SYN packet"
SYNACK=sr1(SYN)
print "\n[*] Receiving SYN,ACK packet"

# Create ACK packet
ACK=ip/TCP(sport=SYNACK.dport, dport=80, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)

# SEND our ACK packet
print "\n[*] Sending ACK packet"
send(ACK)

print "\n[*] Done!"
