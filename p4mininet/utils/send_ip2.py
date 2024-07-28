#!/usr/bin/env python

from multiprocessing import Process
import sys
from time import sleep

from scapy.all import sniff, sendp, send, get_if_hwaddr, conf
from scapy.all import Ether, IP, UDP, Raw
from scapy.fields import *

import struct
import ipaddress

from utils import info


iface = info.send_iface
# dst_mac = info.send_dst_mac
dst_mac = info.get_dst_mac(iface)
addr = info.send_addr

def send():

    iface_tx = iface
    s = conf.L2socket(iface=iface_tx)

    for i in range(0, int(sys.argv[1])):

        pkt = Ether(src=get_if_hwaddr(iface_tx), dst=dst_mac) / \
            IP(dst=addr, proto=17) / \
                UDP(dport=5432, sport=2345) / \
                    struct.pack('!d', time.time())
        
        # pkt.show2()
        s.send(pkt)

        print (f"{i} Send Time: {time.time()}")
        sleep(0.5)


def handle_pkt(ack):
    global total_delta
    global delta_count

    print("[!] Got New Packet: {src} -> {dst}".format(src=ack[IP].src, dst=ack[IP].dst))
    #ack.show2()
    #sys.stdout.flush()

    delta = struct.unpack('!d', ack[Raw].load)[0]
    print(f"delta: {delta}")

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0
    
    total_delta += delta
    delta_count += 1
    print(f"Average Delta: {total_delta / delta_count} | count: {delta_count}")


def receive():    
    iface_rx = iface
    print("sniffing on %s" % iface_rx)
    sys.stdout.flush()
    sniff(filter="udp and port 12345", iface = iface_rx, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':

    Process(target = send).start()
    # Process(target = receive).start()
    receive()
