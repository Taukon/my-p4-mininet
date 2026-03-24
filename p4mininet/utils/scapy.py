#!/usr/bin/env python

from time import sleep
from scapy.layers.inet6 import Ether, IPv6, IPv6ExtHdrSegmentRouting, UDP
from scapy.all import get_if_hwaddr
from scapy.all import Packet
from scapy.all import ShortField, PacketListField
from scapy.fields import *

MAX_HOP_LEN = 16

NOT_ENCAP_SRV6_REQ_PROTOCOL = 0xf8
NOT_ENCAP_SRV6_ACK_PROTOCOL = 0xf9
REFLECT_SWTRACES_PROTOCOL = 0xfa
ENCAP_SRV6_REQ_PROTOCOL = 0xfb
ENCAP_SRV6_ACK_PROTOCOL = 0xfc

INT_PROTOCOL = 0xfd
TRACE_PROTOCOL = 0xfe
RT_PORT = 1234
# RT_ACK_PORT = 12345
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


def get_segment_list_from_pkt_reverse(swtraces):

    segment_list = []

    for i in reversed(range(0, len(swtraces))): 
        ip_bytes = (swtraces[i].swid).to_bytes(16, byteorder='big')
        ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        segment_list.append(ip_str)

    return segment_list


def get_segment_list_from_pkt(swtraces):

    segment_list = []

    for i in range(0, len(swtraces)): 
        ip_bytes = (swtraces[i].swid).to_bytes(16, byteorder='big')
        ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        segment_list.append(ip_str)

    return segment_list


def send_srv6_pkt(iface, dst_mac, dst_addr, segment_list, packet, nh):
    
    s = conf.L2socket(iface=iface)

    ether_header = Ether(src=get_if_hwaddr(iface), dst=dst_mac)

    # ipv6_header = IPv6(dst=dst_addr, nh=INT_PROTOCOL)

    ipv6_header = IPv6(nh=43)
    # ipv6_header.src = src_addr
    ipv6_header.dst = segment_list[-1] # last list's segment

    # srv6 header added
    srv6_header = IPv6ExtHdrSegmentRouting()
    srv6_header.addresses = segment_list  # no necessary to reverse for reflector
    srv6_header.segleft = len(segment_list) - 1 # -1 because start from 0
    srv6_header.lastentry = len(segment_list) - 1

    ipv6_header_inside = IPv6(nh=nh)
    # ipv6_header_inside.src = src_addr # src ipv6 inner (reflector's addr)
    ipv6_header_inside.dst = dst_addr # dst ipv6 inner (sender's addr)

    pkt = (ether_header / ipv6_header / srv6_header / ipv6_header_inside / packet)

    # pkt.show2()
    s.send(pkt)


# def send_srv6_udp_pkt(iface, dst_mac, dst_addr, segment_list, udp_packet: UDP):
    
#     s = conf.L2socket(iface=iface)

#     ether_header = Ether(src=get_if_hwaddr(iface), dst=dst_mac)

#     # ipv6_header = IPv6(dst=dst_addr, nh=INT_PROTOCOL)

#     ipv6_header = IPv6(nh=43)
#     # ipv6_header.src = src_addr
#     ipv6_header.dst = segment_list[-1] # last list's segment

#     # srv6 header added
#     srv6_header = IPv6ExtHdrSegmentRouting()
#     srv6_header.addresses = segment_list  # no necessary to reverse for reflector
#     srv6_header.segleft = len(segment_list) - 1 # -1 because start from 0
#     srv6_header.lastentry = len(segment_list) - 1

#     ipv6_header_inside = IPv6(nh=17)
#     # ipv6_header_inside.src = src_addr # src ipv6 inner (reflector's addr)
#     ipv6_header_inside.dst = dst_addr # dst ipv6 inner (sender's addr)

#     # udp_packet = UDP(dport=RT_ACK_PORT, sport=55555)

#     pkt = (ether_header / ipv6_header / srv6_header / ipv6_header_inside / udp_packet)

#     pkt.show2()
#     s.send(pkt)

# --------------------------------------------------------
def send_mri_pkt(iface, dst_mac, dst_addr):

    s = conf.L2socket(iface=iface)
    pkt = Ether(src=get_if_hwaddr(iface), dst=dst_mac) / \
            IPv6(dst=dst_addr, nh=INT_PROTOCOL) / \
                MRI(count=0, swtraces=[]) / \
                    struct.pack('!d', time.time())

    # pkt.show2()
    s.send(pkt)

    print (f"MRI Send Time: {time.time()} | dst_addr: {dst_addr}")


def send_trace_pkt(iface, dst_mac, dst_addr):

    s = conf.L2socket(iface=iface)
    pkt = Ether(src=get_if_hwaddr(iface), dst=dst_mac) / \
        IPv6(dst=dst_addr, nh=TRACE_PROTOCOL) / \
            MRI(count=0, swtraces=[]) / \
                struct.pack('!d', time.time())
    
    # pkt.show2()
    s.send(pkt)

    print (f"TRACE Packet Send Time: {time.time()} | dst_addr: {dst_addr}")
    # exit(0)

# def reflect_swtraces_pkt(iface, receive_packet, timestamp):
    
#     dst_mac = receive_packet[Ether].src
#     dst_addr = receive_packet[IPv6].src
#     segment_list = get_segment_list_from_pkt(receive_packet[MRI].swtraces)

#     udp_header = UDP(dport=RT_ACK_PORT, sport=55555)
#     mri_packet =MRI(count=receive_packet[MRI].count, swtraces=receive_packet[MRI].swtraces)
#     # timestamp = struct.unpack('!d', receive_packet[Raw].load)[0]

#     udp_packet = udp_header / mri_packet / timestamp

#     send_srv6_udp_pkt(iface, dst_mac, dst_addr, segment_list, udp_packet)
# -----------------
def reflect_swtraces_pkt(iface, receive_packet, timestamp):
    
    dst_mac = receive_packet[Ether].src
    dst_addr = receive_packet[IPv6].src
    segment_list = get_segment_list_from_pkt(receive_packet[MRI].swtraces)

    mri_packet = MRI(count=receive_packet[MRI].count, swtraces=receive_packet[MRI].swtraces)
    # timestamp_packet = struct.unpack('!d', receive_packet[Raw].load)[0]
    timestamp_packet = struct.pack('!d', timestamp)

    packet = mri_packet / timestamp_packet

    send_srv6_pkt(iface, dst_mac, dst_addr, segment_list, packet, REFLECT_SWTRACES_PROTOCOL)


def send_req_encap_srv6(iface, dst_mac, dst_addr, count, swtraces, is_srv6):

    mri_packet = MRI(count=count, swtraces=swtraces)
    segment_list = get_segment_list_from_pkt_reverse(swtraces)

    if is_srv6:
        send_srv6_pkt(iface, dst_mac, dst_addr, segment_list, mri_packet, ENCAP_SRV6_REQ_PROTOCOL)
    else:
        send_srv6_pkt(iface, dst_mac, dst_addr, segment_list, mri_packet, NOT_ENCAP_SRV6_REQ_PROTOCOL)


def send_ack_encap_srv6_pkt(iface, dst_mac, dst_addr, count, swtraces, is_srv6):

    mri_packet = MRI(count=count, swtraces=swtraces)
    segment_list = get_segment_list_from_pkt(swtraces)
    if is_srv6:
        send_srv6_pkt(iface, dst_mac, dst_addr, segment_list, mri_packet, ENCAP_SRV6_ACK_PROTOCOL) 
    else:
        send_srv6_pkt(iface, dst_mac, dst_addr, segment_list, mri_packet, NOT_ENCAP_SRV6_ACK_PROTOCOL) 


def send_timestamp_pkt(timestampID_bytes, count, dst_addr):

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


def reflect_timestamp_pkt(pkt, timestampID, delta):

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    src_address = (pkt[IPv6].src, DELTA_PORT)

    timestampID_bytes = struct.pack('!d', timestampID)
    delta_bytes = struct.pack('!d', delta)
    s.sendto(timestampID_bytes + delta_bytes, src_address)
    # print(f"reflect timestamp delta sent | {timestampID}")
    s.close()