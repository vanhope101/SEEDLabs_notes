# !/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
# pkt = sniff(filter=' host 182.61.200.6 and tcp and port 23 ', prn=print_pkt)
# pkt = sniff(filter=' host 182.61.200.6 and tcp and port 23 ', prn=print_pkt)
# pkt = sniff(filter='dst net 182.61.200', prn=print_pkt)
pkt = sniff(filter='icmp', prn=print_pkt)

