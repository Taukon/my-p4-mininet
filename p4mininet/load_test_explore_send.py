#!/usr/bin/env python

from multiprocessing import Process
import sys
from time import sleep

from scapy.all import sniff, bind_layers
from scapy.layers.inet6 import Ether, IPv6
from scapy.all import Raw
from scapy.fields import *

import struct
import socket

from utils.json import *
from utils.net import *
from lib.json import load_switch_ip_list
from utils.scapy import *

bind_layers(IPv6, MRI, nh=REFLECT_SWTRACES_PROTOCOL)
bind_layers(IPv6, MRI, nh=NOT_ENCAP_SRV6_REQ_PROTOCOL)
bind_layers(IPv6, MRI, nh=NOT_ENCAP_SRV6_ACK_PROTOCOL)
bind_layers(IPv6, MRI, nh=ENCAP_SRV6_REQ_PROTOCOL)
bind_layers(IPv6, MRI, nh=ENCAP_SRV6_ACK_PROTOCOL)
bind_layers(IPv6, MRI, nh=INT_PROTOCOL)
bind_layers(IPv6, MRI, nh=TRACE_PROTOCOL)


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
    
def receive_reflect_swtraces_pkt(iface, reflect_packet, dst_idx, is_srv6, switch_ip_list_path=None):

    dst_mac = reflect_packet[Ether].src
    dst_addr = reflect_packet[IPv6].src
    count = reflect_packet[MRI].count
    swtraces = reflect_packet[MRI].swtraces

    print("[!] Got Packet: {src} -> {dst}".format(src=reflect_packet[IPv6].src, dst=reflect_packet[IPv6].dst))
    # reflect_packet.show2()

    print(f"----- mri update_timestamp_count: {reflect_packet[MRI].update_timestamp_count} | outgoing_timestamp_src: {reflect_packet[MRI].outgoing_timestamp_src} | incoming_timestamp_dst: {reflect_packet[MRI].incoming_timestamp_dst} | outgoing_timestamp_dst: {reflect_packet[MRI].outgoing_timestamp_dst} | incoming_timestamp_src: {reflect_packet[MRI].incoming_timestamp_src} -----")
    print(f"----- swtraces len: {len(reflect_packet[MRI].swtraces)} | dst: {reflect_packet[Ether].dst} | src: {reflect_packet[Ether].src}")
    src_latency = (reflect_packet[MRI].incoming_timestamp_src - reflect_packet[MRI].outgoing_timestamp_src)
    dst_latency = (reflect_packet[MRI].outgoing_timestamp_dst - reflect_packet[MRI].incoming_timestamp_dst)
    latency = (src_latency - dst_latency) /1000

    dst_addr = reflect_packet[IPv6].src
    print(f"----- dst_addr: {dst_addr} -----")
    # send_req_encap_srv6(iface, dst_mac, dst_addr, count, swtraces, is_srv6)

    print(f"----- total latency: {src_latency} | dst latency: {dst_latency} -----")
    print(f"----- latency: {src_latency - dst_latency} microseconds | {latency} ms ----- ")

    global total_latency
    global list_latency
    global send_total
    if 'total_latency' not in globals() or 'list_latency' not in globals() or 'send_total' not in globals():
        total_latency = 0
        list_latency = []
        send_total = 0

    if send_total == 0:
        city_list = get_city_trace(reflect_packet, switch_ip_list_path)
        write_result_city_list(is_srv6, dst_idx, city_list)
    
    
    if send_total < send_count:

        total_latency = total_latency + latency
        list_latency.append(latency)
        send_total = send_total + 1
        send_explore_pkt(iface, dst_mac, addr, is_srv6)

    else:
        mean_latency = total_latency / send_total
        write_result_load_test_delta(is_srv6, dst_idx, mean_latency, send_total, latency, list_latency)

        print("----- Already Sent -----")
        exit(0)


# def receive_ack_encap_srv6_pkt(ack_encap_packet, timestampID_bytes, send_count):

#     dst_addr = ack_encap_packet[IPv6].src
#     nh = ack_encap_packet[IPv6].nh
#     swtraces = ack_encap_packet[MRI].swtraces

#     # for setting srv6 path
#     if nh == ENCAP_SRV6_ACK_PROTOCOL:
    
#         if check_seg6_encap(dst_addr):
#             print(f"----- Already Encap -----")
#             del_seg6_route(dst_addr)
#         print(f"set encap {dst_addr}")

#         segment_list = get_segment_list_from_pkt_reverse(swtraces)
#         add_seg6_route(dst_addr, segment_list)

#     print("----- waiting for 1 seconds -----")
#     sleep(1)
#     # send_timestamp_pkt(timestampID_bytes, send_count, dst_addr)

#     if nh == ENCAP_SRV6_ACK_PROTOCOL and check_seg6_encap(dst_addr):
#         print(f"del encap {dst_addr}")
#         del_seg6_route(dst_addr)

#     exit(0)



def sniff_reflect_swtraces(iface, dst_idx, is_srv6, switch_ip_list_path=None):
    print("receive_reflect_swtraces: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter=f"ip6 and dst host {get_ipv6()}" + \
          f" and proto {REFLECT_SWTRACES_PROTOCOL}", \
          iface = iface, \
          prn = lambda x: receive_reflect_swtraces_pkt(iface, x, dst_idx, is_srv6, switch_ip_list_path))
    
# def sniff_ack_encap_srv6(iface, timestampID_bytes, send_count):
#     print("receive_reflect_swtraces: sniffing on %s" % iface)
#     sys.stdout.flush()
#     sniff(filter=f"ip6 and dst host {get_ipv6()}" + \
#           f" and (proto {ENCAP_SRV6_ACK_PROTOCOL} or {NOT_ENCAP_SRV6_ACK_PROTOCOL})", \
#           iface = iface, \
#           prn = lambda x: receive_ack_encap_srv6_pkt(x, timestampID_bytes, send_count))


def send_explore_pkt(iface, dst_mac, addr, is_srv6):

    if is_srv6:
        tmp_dst_idx = dst_idx if is_mri_limit_hop else None
        if not check_mri_hop_enable(tmp_dst_idx):
            print("----- Over Hop Limit -----")
            exit(1)
        Process(target=send_mri_pkt, args=(iface, dst_mac, addr,)).start()
    else:
        Process(target=send_trace_pkt, args=(iface, dst_mac, addr)).start()


if __name__ == '__main__':
    # mininet>  h1 python3 load_test_explore_send.py -f load_test_switch_ip_list.json -d 30 -c 5 -mri

    iface = get_defalt_ifname()
    # dst_mac = send_dst_mac
    dst_mac = get_dst_mac(iface)
    send_count = 1
    dst_idx = 2
    is_srv6 = False
    is_mri_limit_hop = False
    switch_ip_list_path = None

    for i in range(len(sys.argv)):

        if sys.argv[i] == '-c':
            send_count = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

        if sys.argv[i] == '-d':
            dst_idx = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 2
        
        if sys.argv[i] == '-f':
            switch_ip_list_path = sys.argv[i+1]

        if sys.argv[i] == '-mri':
            is_srv6 = True

        if sys.argv[i] == '-lh':
            is_mri_limit_hop = True

    dst_idx_hex = hex(dst_idx)[2:]
    addr = f'fc00::1:{dst_idx_hex}:2:0:0'
    print(f"addr: {addr}")

    timestampID_bytes = struct.pack('!d', time.time())
    print(f"timestampID: {struct.unpack('!d', timestampID_bytes)[0]}")

    Process(target=sniff_reflect_swtraces, args=(iface, dst_idx, is_srv6, switch_ip_list_path)).start()
    # Process(target=sniff_ack_encap_srv6, args=(iface, timestampID_bytes, send_count)).start()

    send_explore_pkt(iface, dst_mac, addr, is_srv6)
