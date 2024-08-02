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
from lib.json import load_switch_ip_list


iface = info.send_iface
# dst_mac = info.send_dst_mac
dst_mac = info.get_dst_mac(iface)
addr = info.send_addr

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


def get_city_trace(trace_pkt):
    if len(sys.argv) == 3:
        try:

            switch_ip_list_path = sys.argv[2]
            switch_ip_list = load_switch_ip_list(switch_ip_list_path)

            print("----- Switch IP List -----")
            for i in range(0, len(trace_pkt[MRI].swtraces)): 
                ip_bytes = (trace_pkt[MRI].swtraces[i].swid).to_bytes(4, byteorder='big')
                ip_str = socket.inet_ntoa(ip_bytes)

                for k, v in switch_ip_list.items():
                    if f"{ip_str}/32" == v["lo"]["ip"]:
                        print(f"{k} | {ip_str} | {v['lo']['name']}")
                        break

        except Exception as e:
            print(e)
            return
    else:
        print("No switch ip list path")


def send_sr(trace_pkt):
    iface_tx = iface
    s = conf.L2socket(iface=iface_tx)

    for k in range(0, int(sys.argv[1])):

        dst_mac = trace_pkt[Ether].src
        sr_pkt = Ether(src=get_if_hwaddr(iface), dst=dst_mac)
        for i in range(0, len(trace_pkt[MRI].swtraces)):
            back_i = (len(trace_pkt[MRI].swtraces) - 1) - i
            try:
                if(i == len(trace_pkt[MRI].swtraces) - 1):
                    sr_pkt = sr_pkt / SourceRoute(bos=1, swid=trace_pkt[MRI].swtraces[back_i].swid)
                else:
                    sr_pkt = sr_pkt / SourceRoute(bos=0, swid=trace_pkt[MRI].swtraces[back_i].swid)
            
            except ValueError:
                pass

        sr_pkt = sr_pkt / \
            IP(dst=trace_pkt[IP].src, proto=17) / \
                UDP(dport=6543, sport=3456) / \
                    struct.pack('!d', time.time())
        
        # sr_pkt.show2()
        s.send(sr_pkt)
        print (f"SR {k} Send Time: {time.time()}")
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
    # send_sr(ack)
    get_city_trace(ack)


def receive():    
    iface_rx = iface
    print("sniffing on %s" % iface_rx)
    sys.stdout.flush()
    sniff(filter="udp and port 12345", iface = iface_rx, prn = lambda x: handle_pkt_trace(x))

if __name__ == '__main__':

    Process(target = send_trace).start()
    # Process(target = receive).start()
    receive()
