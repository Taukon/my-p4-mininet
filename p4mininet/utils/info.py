import subprocess

# send_iface = 'h1-eth0'
# send_addr = '10.0.0.9'
# send_dst_mac = "ff:ff:ff:ff:ff:ff"
# recieve_iface = 'h5-eth0'

send_iface = 'h1-eth0'
# send_addr = '10.1.7.2'
send_dst_mac = "ff:ff:ff:ff:ff:ff"
# recieve_iface = 'h7-eth0'

send_addr = '10.1.2.2'
recieve_iface = 'h2-eth0'


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
                
"""
[!] Got New Packet: 10.0.0.13 -> 10.0.0.1
delta: 0.025179386138916016
Average Delta: 0.02493705749511719 | count: 10
---------------------------------------------
[!] Got New Packet: 10.0.0.13 -> 10.0.0.1
----- mri swtraces len: 5 | dst: f6:ad:4f:59:79:20 | src: b2:67:b9:45:28:f2
delta: 0.032396793365478516
swid: 167773959 | 10.0.7.7
swid: 167773960 | 10.0.7.8
swid: 167773963 | 10.0.7.11
swid: 167773954 | 10.0.7.2
swid: 167773953 | 10.0.7.1
Average Delta: 0.03418066501617432 | count: 10
"""