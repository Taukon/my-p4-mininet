#!/usr/bin/env python

from multiprocessing import Process
import sys

from scapy.all import sniff, sendp, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, Raw
from scapy.all import IntField, ShortField, PacketListField
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct
from utils import info

iface = info.recieve_iface

INT_PROTOCOL = 0xfd
TRACE_PROTOCOL = 0xfe

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

# bind_layers(UDP, MRI, dport=5432)
bind_layers(IP, MRI, proto=TRACE_PROTOCOL)


def send_ack_pkt(iface, pkt, delta: float):
    # dst_mac = "ff:ff:ff:ff:ff:ff"
    dst_mac = pkt[Ether].src

    ack = Ether(src=get_if_hwaddr(iface), dst=dst_mac)
    
    ack = ack / \
        IP(dst=pkt[IP].src, proto=17) / \
            UDP(dport=12345, sport=54321) / \
                MRI(count=pkt[MRI].count, swtraces=pkt[MRI].swtraces) / \
                    struct.pack('!d', delta)
        
    # ack.show2()

    sendp(ack, iface=iface, verbose=False)

def handle_pkt_trace(pkt):
    global best_latency
    global pre_timestamp

    print("got a trace packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp
    print(f"delta: {delta}")

    if 'pre_timestamp' not in globals() or pre_timestamp < timestamp:
        pre_timestamp = timestamp
        best_latency = 100000

    if 'best_latency' not in globals() or best_latency > delta:
        best_latency = delta
        send_ack_pkt(iface, pkt, delta)

        for i in range(pkt[MRI].count):
            ip_bytes = (pkt[MRI].swtraces[i].swid).to_bytes(4, byteorder='big')
            print(f"swid: {pkt[MRI].swtraces[i].swid} | {socket.inet_ntoa(ip_bytes)}")
        print ("ACK sent")

    print(f"----- mri swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")


def handle_pkt_timeatamp(pkt):
    global total_delta
    global delta_count

    print("got a timestamp packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0
    
    total_delta += delta
    delta_count += 1
    print(f"----- TM delta: {delta} | Average Delta: {total_delta / delta_count} | count: {delta_count} -----")


def receive_trace():
    print("trace: sniffing on %s" % iface)
    sys.stdout.flush()
    # sniff(filter="udp and port 5432", iface = iface, prn = lambda x: handle_pkt_trace(x))
    sniff(filter=f"ip and proto {TRACE_PROTOCOL}", iface = iface, prn = lambda x: handle_pkt_trace(x))

def receive_timestamp():
    print("timestamp: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 1234", iface = iface, prn = lambda x: handle_pkt_timeatamp(x))

if __name__ == '__main__':
    Process(target = receive_timestamp).start()
    receive_trace()
