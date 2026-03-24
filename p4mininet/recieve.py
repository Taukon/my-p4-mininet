#!/usr/bin/env python

from multiprocessing import Process
import sys
from time import sleep

from scapy.all import sniff, bind_layers
from scapy.layers.inet6 import Ether, IPv6
from scapy.all import Raw
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct
from utils.net import *
from utils.scapy import *


bind_layers(IPv6, MRI, nh=REFLECT_SWTRACES_PROTOCOL)
bind_layers(IPv6, MRI, nh=NOT_ENCAP_SRV6_REQ_PROTOCOL)
bind_layers(IPv6, MRI, nh=NOT_ENCAP_SRV6_ACK_PROTOCOL)
bind_layers(IPv6, MRI, nh=ENCAP_SRV6_REQ_PROTOCOL)
bind_layers(IPv6, MRI, nh=ENCAP_SRV6_ACK_PROTOCOL)
bind_layers(IPv6, MRI, nh=INT_PROTOCOL)
bind_layers(IPv6, MRI, nh=TRACE_PROTOCOL)


# def receive_swtraces(iface, pkt):
#     global pre_timestamp

#     print("got a trace packet")
#     # pkt.show2()

#     sys.stdout.flush()

#     timestamp = struct.unpack('!d', pkt[Raw].load)[0]
#     # delta = time.time() - timestamp
#     # print(f"delta: {delta}")

#     if 'pre_timestamp' not in globals() or pre_timestamp != timestamp:
#         pre_timestamp = timestamp

#         # remove seg6 encap
#         dst_addr = pkt[IPv6].src
#         if check_seg6_encap(dst_addr):
#             print(f"----- Delete Encap -----")
#             del_seg6_route(dst_addr)

#         reflect_swtraces_pkt(iface, pkt, timestamp)

#         # pkt.show2()

#         # for i in range(pkt[MRI].count):
#         #     ip_bytes = (pkt[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
#         #     # print(f"swid: {pkt[MRI].swtraces[i].swid} | {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
#         #     print(f"swid: {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
            
#         # print ("ACK sent")

#     print(f"----- swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")


def receive_swtraces(iface, pkt):

    print("got a trace packet")
    # pkt.show2()

    sys.stdout.flush()
    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    # delta = time.time() - timestamp
    # print(f"delta: {delta}")

    # remove seg6 encap
    dst_addr = pkt[IPv6].src
    if check_seg6_encap(dst_addr):
        print(f"----- Delete Encap -----")
        del_seg6_route(dst_addr)

    reflect_swtraces_pkt(iface, pkt, timestamp)

    print(f"----- swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")



def receive_req_encap_srv6_pkt(iface, req_encap_packet):

    print("got a req_encap_srv6 packet")
    # req_encap_packet.show2()

    dst_mac = req_encap_packet[Ether].src
    dst_addr = req_encap_packet[IPv6].src
    nh = req_encap_packet[IPv6].nh
    count = req_encap_packet[MRI].count
    swtraces = req_encap_packet[MRI].swtraces

    if check_seg6_encap(dst_addr):
        del_seg6_route(dst_addr)
        print(f"----- Delete Already Encap -----")

    print(f"set encap {dst_addr}")
    segment_list = get_segment_list_from_pkt(req_encap_packet[MRI].swtraces)
    add_seg6_route(dst_addr, segment_list)

    print("----- waiting for 1 seconds -----")
    sleep(1)

    if nh == ENCAP_SRV6_REQ_PROTOCOL:
        send_ack_encap_srv6_pkt(iface, dst_mac, dst_addr, count, swtraces, True)
    elif nh == NOT_ENCAP_SRV6_REQ_PROTOCOL:
        send_ack_encap_srv6_pkt(iface, dst_mac, dst_addr, count, swtraces, False)


def reflect_timeatamp(pkt):
    global total_delta
    global delta_count
    global pre_timestampID

    # print("got a timestamp packet")
    # pkt.show2()
    # sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load[8:])[0]
    delta = time.time() - timestamp
    timestampID = struct.unpack('!d', pkt[Raw].load[:8])[0]

    if 'total_delta' not in globals() or 'delta_count' not in globals():
        total_delta = 0
        delta_count = 0

    if 'pre_timestampID' not in globals() \
        or pre_timestampID != timestampID:
        pre_timestampID = timestampID
        total_delta = 0
        delta_count = 0
    
    total_delta += delta
    delta_count += 1

    # print(f"----- TM id: {timestampID} | delta: {delta} | Average Delta: {total_delta / delta_count} | count: {delta_count} -----")

    reflect_timestamp_pkt(pkt, timestampID, delta)


def sniff_receive_swtraces(iface):
    print("receive_swtraces: sniffing on %s" % iface)
    sys.stdout.flush()
    print(f"{get_ipv6()}")
    sniff(filter=f"ip6 and dst host {get_ipv6()}" + \
          f" and (proto {TRACE_PROTOCOL} or {INT_PROTOCOL})", \
          iface = iface, prn = lambda x: receive_swtraces(iface, x))
    

def sniff_req_encap_srv6(iface):
    print("req_encap_srv6: sniffing on %s" % iface)
    sys.stdout.flush()
    print(f"{get_ipv6()}")
    sniff(filter=f"ip6 and dst host {get_ipv6()}" + \
          f" and (proto {ENCAP_SRV6_REQ_PROTOCOL} or {NOT_ENCAP_SRV6_REQ_PROTOCOL})", \
          iface = iface, prn = lambda x: receive_req_encap_srv6_pkt(iface, x))


def sniff_reflect_timestamp(iface):
    print("reflect_timestamp: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter=f"ip6 and dst host {get_ipv6()}" + \
          f" and udp and port {RT_PORT}", \
          iface = iface, prn = lambda x: reflect_timeatamp(x))


if __name__ == '__main__':
    iface = get_defalt_ifname()

    Process(target=sniff_req_encap_srv6, args=(iface,)).start()
    Process(target=sniff_reflect_timestamp, args=(iface,)).start()
    
    sniff_receive_swtraces(iface)
    
