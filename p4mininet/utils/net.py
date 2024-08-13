import subprocess
from pyroute2.iproute import IPRoute

send_dst_mac = "ff:ff:ff:ff:ff:ff"


def get_defalt_ifname():
    with IPRoute() as ipr:
            for x in ipr.get_links():
                ifla_ifname = x.get_attr('IFLA_IFNAME')
                host_name = ifla_ifname.split('-')[0]

                if host_name[0] == 'h' and ifla_ifname[-1] == '0':
                    # print(ifla_ifname)
                    return ifla_ifname


def get_ipv6():
    if_name = get_defalt_ifname()
    
    ipv6_cmd=["ip", "-6", "a", "show", if_name]
    proc = subprocess.Popen(ipv6_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (ipv6_cache, ipv6_err) = proc.communicate()
    ipv6_entries = ipv6_cache.decode().split("\n")
    for entry in ipv6_entries.copy():
        if "inet6" in entry and "global" in entry:
            ipv6_addr = entry.split()[1]
            return ipv6_addr.split("/")[0]


def get_dst_mac(iface: str):
    arp_cmd=["cat", "/proc/net/arp"]
    proc = subprocess.Popen(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (arp_cache, arp_err) = proc.communicate()
    arp_entries = arp_cache.decode().split("\n")
    for entry in arp_entries.copy():
        if not entry.startswith("IP address"):
            if len(entry) > 0:
                flags = entry.split()[2]
                mac = entry.split()[3]
                mac_if = entry.split()[5]
                # print(entry)
                if flags == "0x2" and iface == mac_if:
                    return mac


def add_seg6_route(dst: str, seg_list: list[str]):

    with IPRoute() as ipr:

        oif_idx = None

        for x in ipr.get_links():
                ifla_ifname = x.get_attr('IFLA_IFNAME')
                host_name = ifla_ifname.split('-')[0]
                idx = x.get('index')

                if host_name[0] == 'h' \
                    and ifla_ifname[-1] == '0' \
                        and idx is not None:
                    oif_idx = idx
                    break
                    
        if oif_idx is None:
            print(f"Interface not found")
            return

        ipr.route(
            "add",
            dst=dst,
            oif=oif_idx,
            encap={
                "type": "seg6",
                "mode": "encap",
                "segs": seg_list[::-1],
            },
        )
    
        return
    
def del_seg6_route(dst: str):

    with IPRoute() as ipr:

        ipr.route(
            "del",
            dst=dst,
            encap={
                "type": "seg6",
                "mode": "encap",
            },
        )
    
        return
    
def check_seg6_encap(dst: str):
    seg6_cmd=["ip", "-6", "route"]
    proc = subprocess.Popen(seg6_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (seg6_cache, seg6_err) = proc.communicate()
    seg6_entries = seg6_cache.decode().split("\n")
    for entry in seg6_entries.copy():
            if len(entry) > 0:
                seg6_dst = entry.split()[0]
                seg6_encap = entry.split()[1]
                if seg6_dst == dst and seg6_encap == "encap":
                    print(entry)
                    return True
