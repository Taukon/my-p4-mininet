#!/usr/bin/env python

import sys

from scapy.all import sniff, sendp, get_if_hwaddr
from scapy.all import Ether, IP, UDP, Raw
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct
from utils import info

iface = info.recieve_iface

def send_ack_pkt(iface, pkt, delta: float):
    # dst_mac = "ff:ff:ff:ff:ff:ff"
    dst_mac = pkt[Ether].src

    ack = Ether(src=get_if_hwaddr(iface), dst=dst_mac)
    
    ack = ack / \
        IP(dst=pkt[IP].src, proto=17) / \
            UDP(dport=12345, sport=54321) / \
                struct.pack('!d', delta)
        
    # ack.show2()

    sendp(ack, iface=iface, verbose=False)

def handle_pkt(pkt):
    global best_latency
    global pre_timestamp

    print("got a packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp
    print(f"delta: {delta}")

    if 'pre_timestamp' not in globals() or pre_timestamp != timestamp:
        pre_timestamp = timestamp
        best_latency = 100000

    if 'best_latency' not in globals() or best_latency > delta:
        best_latency = delta
        send_ack_pkt(iface, pkt, delta)
        print ("ACK sent")

    print(f"----- dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")


def main():

    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 5432", iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
