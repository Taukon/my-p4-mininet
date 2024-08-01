#!/usr/bin/env python

import sys

from scapy.all import sniff, sendp, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import PacketListField, ShortField, IntField, BitField
from scapy.all import Ether, IP, UDP, Raw
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct

from utils import info

iface = info.recieve_iface

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 8),
                   IntField("swid", 0)]

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

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(UDP, MRI, dport=4321)


def send_ack_pkt(iface, pkt, delta: float):
    # dst_mac = "ff:ff:ff:ff:ff:ff"
    dst_mac = pkt[Ether].src

    ack = Ether(src=get_if_hwaddr(iface), dst=dst_mac)

    for i in range(0, len(pkt[MRI].swtraces)):
        try:
            if(i == len(pkt[MRI].swtraces) - 1):
                ack = ack / SourceRoute(bos=1, swid=pkt[MRI].swtraces[i].swid)
            else:
                ack = ack / SourceRoute(bos=0, swid=pkt[MRI].swtraces[i].swid)
            # print(f"swid: {pkt[MRI].swtraces[i].swid} | {i == len(pkt[MRI].swtraces) - 1}")

        except ValueError:
                pass
        
    # if pkt.haslayer(SourceRoute):
    #     ack.getlayer(SourceRoute, pkt[MRI].count - 1).bos = 1

    ack = ack / \
        IP(dst=pkt[IP].src, proto=17) / \
            UDP(dport=12345, sport=54321) / \
                MRI(count=pkt[MRI].count, swtraces=pkt[MRI].swtraces) / \
                    struct.pack('!d', delta)
    
    # ack.show2()

    sendp(ack, iface=iface, verbose=False)


def handle_pkt_mri(pkt):
    global total_delta
    global delta_count

    # print("got a mri packet")
    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp
    # print(f"mri delta: {delta}")

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0

    # print(f"----- mri swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")
    total_delta += delta
    delta_count += 1
    print(f"MRI delta: {delta} | Average Delta: {total_delta / delta_count} | count: {delta_count}")
    send_ack_pkt(iface, pkt, delta)


def receive_mri():
    print("mri: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface, prn = lambda x: handle_pkt_mri(x))

if __name__ == '__main__':
    receive_mri()
