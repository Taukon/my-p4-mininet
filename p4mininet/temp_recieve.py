#!/usr/bin/env python

from multiprocessing import Process
import sys

from scapy.all import sniff, sendp, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, UDP, Raw, IPv6
from scapy.all import IntField, ShortField, PacketListField
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct
# from utils.net import *
import utils.net as utils


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


def send_ack_pkt(iface, pkt, delta: float):
    # dst_mac = "ff:ff:ff:ff:ff:ff"
    dst_mac = pkt[Ether].src

    ack = Ether(src=get_if_hwaddr(iface), dst=dst_mac)

    ack = ack / \
        IPv6(dst=pkt[IPv6].src, nh=17) / \
            UDP(dport=RT_ACK_PORT, sport=55555) / \
                MRI(count=pkt[MRI].count, swtraces=pkt[MRI].swtraces) / \
                    struct.pack('!d', delta)
        
    # ack.show2()

    sendp(ack, iface=iface, verbose=False)


def get_segment_list(trace_pkt):

    segment_list = []

    for i in range(0, len(trace_pkt[MRI].swtraces)): 
        ip_bytes = (trace_pkt[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
        ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        segment_list.append(ip_str)

    return segment_list


def handle_pkt_trace(pkt, iface):
    global pre_timestamp

    print("got a trace packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp
    # print(f"delta: {delta}")

    if 'pre_timestamp' not in globals() or pre_timestamp != timestamp:
        pre_timestamp = timestamp

        # remove seg6 encap
        dst_addr = pkt[IPv6].src
        if utils.check_seg6_encap(dst_addr):
            print(f"----- Delete Encap -----")
            utils.del_seg6_route(dst_addr)

        send_ack_pkt(iface, pkt, delta)

        # pkt.show2()

        # for i in range(pkt[MRI].count):
        #     ip_bytes = (pkt[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
        #     # print(f"swid: {pkt[MRI].swtraces[i].swid} | {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
        #     print(f"swid: {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
            
        # print ("ACK sent")

    # print(f"----- swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")


def handle_pkt_mri(pkt, iface):
    global best_latency
    global pre_timestamp

    # print("got a mri packet")
    # pkt.show2()

    sys.stdout.flush()

    timestamp = struct.unpack('!d', pkt[Raw].load)[0]
    delta = time.time() - timestamp
    # print(f"delta: {delta}")

    if 'pre_timestamp' not in globals() or pre_timestamp < timestamp:
        pre_timestamp = timestamp
        best_latency = 100000

    if 'best_latency' not in globals() or best_latency > delta:
        best_latency = delta

        # -------------------------------------
        
        dst_addr = pkt[IPv6].src
        if utils.check_seg6_encap(dst_addr):
            # print(f"----- Already Encap -----")
            utils.del_seg6_route(dst_addr)
        print(f"set encap {dst_addr}")
        segment_list = get_segment_list(pkt)
        utils.add_seg6_route(dst_addr, segment_list)

        send_ack_pkt(iface, pkt, delta)
        # -------------------------------------

        # pkt.show2()

        # for i in range(pkt[MRI].count):
        #     ip_bytes = (pkt[MRI].swtraces[i].swid).to_bytes(16, byteorder='big')
        #     # print(f"swid: {pkt[MRI].swtraces[i].swid} | {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
        #     print(f"swid: {socket.inet_ntop(socket.AF_INET6, ip_bytes)}")
            
        # print ("ACK sent")

    # print(f"----- mri swtraces len: {len(pkt[MRI].swtraces)} | count: {pkt[MRI].count} |  dst: {pkt[Ether].dst} | src: {pkt[Ether].src}")


def reflect_timestamp(pkt, timestampID, delta):

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    src_address = (pkt[IPv6].src, DELTA_PORT)

    timestampID_bytes = struct.pack('!d', timestampID)
    delta_bytes = struct.pack('!d', delta)
    s.sendto(timestampID_bytes + delta_bytes, src_address)
    # print(f"reflect timestamp delta sent | {timestampID}")
    s.close()


def handle_pkt_timeatamp(pkt):
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

    reflect_timestamp(pkt, timestampID, delta)


def receive_trace(iface):
    print("trace: sniffing on %s" % iface)
    sys.stdout.flush()
    print(f"{utils.get_ipv6()}")
    # sniff(filter=f"ip6 and not src host {utils.get_ipv6()} and dst host {utils.get_ipv6()}" + \
    sniff(filter=f"ip6 and dst host {utils.get_ipv6()}" + \
          f" and proto {TRACE_PROTOCOL}", \
          iface = iface, prn = lambda x: handle_pkt_trace(x, iface))

def receive_mri(iface):
    print("mri: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter=f"ip6 and dst host {utils.get_ipv6()}" + \
          f" and proto {INT_PROTOCOL}", \
          iface = iface, prn = lambda x: handle_pkt_mri(x, iface))

def receive_timestamp(iface):
    print("timestamp: sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter=f"ip6 and dst host {utils.get_ipv6()}" + \
          f" and udp and port {RT_PORT}", \
          iface = iface, prn = lambda x: handle_pkt_timeatamp(x))

if __name__ == '__main__':
    iface = utils.get_defalt_ifname()

    Process(target=receive_timestamp, args=(iface,)).start()
    Process(target = receive_trace, args=(iface,)).start()
    # receive_trace()
    receive_mri(iface)
    
