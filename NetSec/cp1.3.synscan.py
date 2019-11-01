from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # SYN scan
conf.verb = 0
open_ports = []
for port in range(1,1025):
	response = sr1(IP(src=my_ip, dst=ip_addr)/TCP(dport=port, flags="S"),timeout=.15)
	if(response != None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12):
		open_ports.append(port)
		sr(IP(src=my_ip, dst=ip_addr)/TCP(dport=port,flags="R"),timeout=.15)

for p in open_ports:
	print(ip_addr+","+str(p))
