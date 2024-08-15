#!/usr/bin/env python

from multiprocessing import Process
import sys
from time import sleep

from scapy.all import sniff, get_if_hwaddr, bind_layers, conf
from scapy.all import Packet
from scapy.all import Ether,  UDP, Raw, IPv6
from scapy.all import IntField, ShortField, PacketListField
from scapy.fields import *

import struct
import socket

from utils.json import *
from utils.net import *
from lib.json import load_switch_ip_list

MAX_HOP_LEN = 10
INT_PROTOCOL = 0xfd
TRACE_PROTOCOL = 0xfe
RT_PORT = 1234
RT_ACK_PORT = 12345
DELTA_PORT = 23456

class SwitchTrace(Packet):
    # fields_desc = [ IntField("swid", 0)]
    fields_desc = [ BitField("swid", 0, 128)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
   fields_desc = [ ShortField("count", 0),
                   PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1))]

bind_layers(IPv6, MRI, nh=INT_PROTOCOL)
bind_layers(IPv6, MRI, nh=TRACE_PROTOCOL)
bind_layers(UDP, MRI, dport=RT_ACK_PORT)


def check_mri_hop_enable(dst_idx=None):
     # check max hop len
    if dst_idx is not None:
        trace_hop_len = check_trace_hop_len(dst_idx)
        if trace_hop_len > MAX_HOP_LEN:
            print(f"----- Trace Hop Len: {trace_hop_len} | Over {MAX_HOP_LEN} -----")
            return False
        elif trace_hop_len == -1:
            print(f"----- Trace Hop Len: {trace_hop_len} | Not Found -----")
            return False
        
    return True


def send_mri(iface, dst_mac, dst_addr):

    s = conf.L2socket(iface=iface)

    pkt = Ether(src=get_if_hwaddr(iface), dst=dst_mac) / \
            IPv6(dst=dst_addr, nh=INT_PROTOCOL) / \
                MRI(count=0, swtraces=[]) / \
                    struct.pack('!d', time.time())

    # pkt.show2()
    s.send(pkt)

    print (f"MRI Send Time: {time.time()} | dst_addr: {dst_addr}")


def send_trace(iface, dst_mac, dst_addr):

    s = conf.L2socket(iface=iface)

    pkt = Ether(src=get_if_hwaddr(iface), dst=dst_mac) / \
        IPv6(dst=dst_addr, nh=TRACE_PROTOCOL) / \
            MRI(count=0, swtraces=[]) / \
                struct.pack('!d', time.time())
    
    # pkt.show2()
    s.send(pkt)

    print (f"TRACE Packet Send Time: {time.time()} | dst_addr: {dst_addr}")
    # exit(0)


def get_segment_list(trace_pkt):

    segment_list = []

    for i in reversed(range(0, len(trace_pkt[MRI].swtraces))): 
        ip_bytes = (trace_pkt[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
        ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        segment_list.append(ip_str)

    return segment_list


def get_city_trace(trace_pkt, switch_ip_list_path):

    if switch_ip_list_path is not None:
        try:

            switch_ip_list = load_switch_ip_list(switch_ip_list_path)
            city_list = []

            print(f"----- Switch IP List -----{len(trace_pkt[MRI].swtraces)}")
            for i in range(0, len(trace_pkt[MRI].swtraces)): 
                ip_bytes = (trace_pkt[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
                ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)

                for k, v in switch_ip_list.items():
                    if f"{ip_str}/128" == v["lo"]["ipv6"]:
                        print(f"{k} | {ip_str} | {v['lo']['name']}")
                        city_list.append(f"{k} | {ip_str} | {v['lo']['name']}")
                        # city_list.append(v['lo']['name'])
                        break
                
            return city_list

        except Exception as e:
            print(e)
            return []
    else:
        print(f"No switch ip list path. | '{switch_ip_list_path}'")
        return []


def send_timestamp(timestampID_bytes, count, dst_addr):

    # s = conf.L3socket(iface=get_defalt_ifname())

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
    # s.bind((get_ipv6(), 55555))

    if count > 1:
        count = count + 1
        print(f"add count+1 for skip first delta packet")

    for i in range(0, count):
        payload = timestampID_bytes + struct.pack('!d', time.time())
        # payload = struct.pack('!d', time.time())
        s.sendto(payload, (dst_addr, RT_PORT))

        # pkt = IPv6(dst=dst_addr, nh=17) / \
        #     UDP(dport=RT_PORT, sport=55555) / \
        #         Raw(load=payload)
        # s.send(pkt)

        print (f"{i} Send Time: {time.time()}")
        sleep(0.5)
    
    s.close()


def handle_pkt_trace(ack, timestampID_bytes, count, dst_idx, is_seg6, switch_ip_list_path=None):
    global total_delta
    global delta_count

    print("[!] Got New Packet: {src} -> {dst}".format(src=ack[IPv6].src, dst=ack[IPv6].dst))
    # ack.show2()
    #sys.stdout.flush()
    print(f"----- swtraces len: {len(ack[MRI].swtraces)} | dst: {ack[Ether].dst} | src: {ack[Ether].src}")

    delta = struct.unpack('!d', ack[Raw].load)[0]

    for i in range(0, len(ack[MRI].swtraces)): 
        ip_bytes = (ack[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
        # print(f"swid: {ack[MRI].swtraces[i].swid} | {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
        print(f"swid: {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0
    
    total_delta += delta
    delta_count += 1
    print(f"delta: {delta} | Average Delta: {total_delta / delta_count} | count: {delta_count}")

    city_list = get_city_trace(ack, switch_ip_list_path)
    write_result_city_list(is_seg6, dst_idx, city_list)
    dst_addr = ack[IPv6].src
    print(f"----- dst_addr: {dst_addr} -----")


    # for setting srv6 path
    if is_seg6:
    
        if check_seg6_encap(dst_addr):
            print(f"----- Already Encap -----")
            del_seg6_route(dst_addr)
        print(f"set encap {dst_addr}")

        segment_list = get_segment_list(ack)
        add_seg6_route(dst_addr, segment_list)

    print("----- waiting for 1 seconds -----")
    sleep(1)
    send_timestamp(timestampID_bytes, count, dst_addr)

    if is_seg6 and check_seg6_encap(dst_addr):
        print(f"del encap {dst_addr}")
        del_seg6_route(dst_addr)

    exit(0)


def handle_delta(pkt, timestampID_bytes, count, dst_idx, is_seg6):
    global total_delta
    global delta_count

    print(f"got a timestamp packet | {pkt[IPv6].src}")
    # pkt.show2()

    sys.stdout.flush()

    delta = struct.unpack('!d', pkt[Raw].load[8:])[0]
    timestampID = struct.unpack('!d', pkt[Raw].load[:8])[0]

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0
        if count > 1:
            print(f"skip first delta packet")
            return
    
    if timestampID_bytes != struct.pack('!d', timestampID):
        print("----- InValid Timestamp ID -----")
        exit(1)
    
    total_delta += delta
    delta_count += 1
    print(f"----- TM id: {timestampID} | delta: {delta} | Average Delta: {total_delta / delta_count} | count: {delta_count} -----")

    if(count == delta_count):
        mean_delta = total_delta / delta_count
        write_result_delta(is_seg6, dst_idx, mean_delta, delta_count, delta)
        print("----- Done -----")
        exit(0)


def receive(iface, timestampID_bytes, count, dst_idx, is_seg6, switch_ip_list_path=None):
    print("sniffing on %s trace" % iface)
    sys.stdout.flush()
    sniff(filter=f"udp and port {RT_ACK_PORT}", iface = iface, \
          prn = lambda x: handle_pkt_trace(x, timestampID_bytes, count, dst_idx, is_seg6, switch_ip_list_path))

def receive_delta(iface, timestampID_bytes, count, dst_idx, is_seg6):
    print("sniffing on %s delta" % iface)
    sys.stdout.flush()
    sniff(filter=f"udp and port {DELTA_PORT}", iface = iface, \
          prn = lambda x: handle_delta(x, timestampID_bytes, count, dst_idx, is_seg6))

if __name__ == '__main__':
    # mininet>  h1 python3 send.py -f Abilene_switch_ip_list.json -c 5 -d 5 -mri

    iface = get_defalt_ifname()
    # dst_mac = send_dst_mac
    dst_mac = get_dst_mac(iface)
    count = 1
    dst_idx = 2
    is_seg6 = False
    is_mri_limit_hop = False
    switch_ip_list_path = None

    for i in range(len(sys.argv)):

        if sys.argv[i] == '-c':
            count = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

        if sys.argv[i] == '-d':
            dst_idx = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 2
        
        if sys.argv[i] == '-f':
            switch_ip_list_path = sys.argv[i+1]

        if sys.argv[i] == '-mri':
            is_seg6 = True

        if sys.argv[i] == '-lh':
            is_mri_limit_hop = True

    dst_idx_hex = hex(dst_idx)[2:]
    addr = f'fc00::1:{dst_idx_hex}:2:0:0'
    print(f"addr: {addr}")

    timestampID_bytes = struct.pack('!d', time.time())
    print(f"timestampID: {struct.unpack('!d', timestampID_bytes)[0]}")

    if is_seg6:
        tmp_dst_idx = dst_idx if is_mri_limit_hop else None
        if not check_mri_hop_enable(tmp_dst_idx):
            print("----- Over Hop Limit -----")
            exit(1)
        Process(target=send_mri, args=(iface, dst_mac, addr,)).start()
    else:
        Process(target=send_trace, args=(iface, dst_mac, addr)).start()
        
    Process(target=receive, args=(iface, timestampID_bytes, count, dst_idx, is_seg6, switch_ip_list_path)).start()
    # receive()
    receive_delta(iface, timestampID_bytes, count, dst_idx, is_seg6)
