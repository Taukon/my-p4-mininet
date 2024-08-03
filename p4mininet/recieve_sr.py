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
from multiprocessing import Process

from utils import info

iface = info.recieve_iface

INT_PROTOCOL = 0xfd
TRACE_PROTOCOL = 0xfe

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
bind_layers(IP, MRI, proto=INT_PROTOCOL)


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
    global best_latency_mri
    global pre_timestamp_mri

    print("got a mri packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp
    print(f"mri delta: {delta}")

    if 'pre_timestamp_mri' not in globals() or pre_timestamp_mri < timestamp:
        pre_timestamp_mri = timestamp
        best_latency_mri = 100000

    if 'best_latency_mri' not in globals() or best_latency_mri > delta:
        best_latency_mri = delta
        send_ack_pkt(iface, pkt, delta)

        for i in range(pkt[MRI].count):
            ip_bytes = (pkt[MRI].swtraces[i].swid).to_bytes(4, byteorder='big')
            print(f"swid: {pkt[MRI].swtraces[i].swid} | {socket.inet_ntoa(ip_bytes)}")
        print ("ACK sent")

    print(f"----- mri swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")

    # for i in range(pkt[MRI].count):
    #     ip_bytes = (pkt[MRI].swtraces[i].swid).to_bytes(4, byteorder='big')
    #     print(f"swid: {pkt[MRI].swtraces[i].swid} | {socket.inet_ntoa(ip_bytes)}")


def handle_pkt_sr(pkt):
    global total_delta_sr
    global delta_count_sr

    print("got a sr packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp

    if 'total_delta_sr' not in globals() or 'delta_count_sr' not in globals():
        total_delta_sr = 0
        delta_count_sr = 0
    
    total_delta_sr += delta
    delta_count_sr += 1
    print(f"----- SR delta: {delta} | Average Delta: {total_delta_sr / delta_count_sr} | count: {delta_count_sr} -----")


def receive_mri():
    print("mri: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter=f"ip and proto {INT_PROTOCOL}", iface = iface, prn = lambda x: handle_pkt_mri(x))

def receive_sr():
    print("sr: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 1234", iface = iface, prn = lambda x: handle_pkt_sr(x))

if __name__ == '__main__':
    Process(target = receive_sr).start()
    receive_mri()
