#!/usr/bin/env python

from multiprocessing import Process
import sys
from time import sleep

from scapy.all import sniff, sendp, send, get_if_hwaddr, bind_layers, conf
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, Raw
from scapy.all import IntField, ShortField, PacketListField
from scapy.fields import *

import struct
import ipaddress

from utils import info


iface = info.send_iface
# dst_mac = info.send_dst_mac
dst_mac = info.get_dst_mac(iface)
addr = info.send_addr

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
   fields_desc = [ ShortField("count", 0),
                   PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1))]

bind_layers(UDP, MRI, dport=5432)
bind_layers(UDP, MRI, dport=12345)

def send_trace():
    iface_tx = iface
    s = conf.L2socket(iface=iface_tx)

    pkt = Ether(src=get_if_hwaddr(iface_tx), dst=dst_mac) / \
        IP(dst=addr, proto=17) / \
            UDP(dport=5432, sport=2345) / \
                MRI(count=0, swtraces=[]) / \
                    struct.pack('!d', time.time())
    # pkt.show2()
    s.send(pkt)

    print (f"TRACE Packet Send Time: {time.time()}")


def send_timestamp():

    iface_tx = iface
    s = conf.L2socket(iface=iface_tx)

    for i in range(0, int(sys.argv[1])):

        pkt = Ether(src=get_if_hwaddr(iface_tx), dst=dst_mac) / \
            IP(dst=addr, proto=17) / \
                UDP(dport=6543, sport=3456) / \
                    struct.pack('!d', time.time())
        
        # pkt.show2()
        s.send(pkt)

        print (f"{i} Send Time: {time.time()}")
        sleep(1)


# def handle_pkt_trace(ack):
#     global total_delta
#     global delta_count

#     print("[!] Got New Packet: {src} -> {dst}".format(src=ack[IP].src, dst=ack[IP].dst))
#     #ack.show2()
#     #sys.stdout.flush()

#     delta = struct.unpack('!d', ack[Raw].load)[0]
#     print(f"delta: {delta}")

#     if 'total_delta' not in globals() or 'delta_count' not in globals():
#         total_delta = 0
#         delta_count = 0
    
#     total_delta += delta
#     delta_count += 1
#     print(f"TRACE Average Delta: {total_delta / delta_count} | count: {delta_count}")

#     print("----- waiting for 2 seconds -----")
#     sleep(2)
#     send_timestamp()


def handle_pkt_trace(ack):
    global total_delta
    global delta_count

    print("[!] Got New Packet: {src} -> {dst}".format(src=ack[IP].src, dst=ack[IP].dst))
    #ack.show2()
    #sys.stdout.flush()
    print(f"----- mri swtraces len: {len(ack[MRI].swtraces)} | dst: {ack[Ether].dst} | src: {ack[Ether].src}")

    delta = struct.unpack('!d', ack[Raw].load)[0]

    for i in range(0, len(ack[MRI].swtraces)): 
        # print(f"swid: {ack[MRI].swtraces[i].swid} | {ipaddress.ip_address(ack[MRI].swtraces[i].swid)}")
        ip_bytes = (ack[MRI].swtraces[i].swid).to_bytes(4, byteorder='big')
        print(f"swid: {ack[MRI].swtraces[i].swid} | {socket.inet_ntoa(ip_bytes)}")

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0
    
    total_delta += delta
    delta_count += 1
    print(f"TRACE delta: {delta} | Average Delta: {total_delta / delta_count} | count: {delta_count}")

    print("----- waiting for 2 seconds -----")
    sleep(2)
    send_timestamp()


def receive():    
    iface_rx = iface
    print("sniffing on %s" % iface_rx)
    sys.stdout.flush()
    sniff(filter="udp and port 12345", iface = iface_rx, prn = lambda x: handle_pkt_trace(x))

if __name__ == '__main__':

    Process(target = send_trace).start()
    # Process(target = receive).start()
    receive()
