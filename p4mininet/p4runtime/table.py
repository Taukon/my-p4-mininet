import inspect
import json
import os
import sys
import socket
import binascii
from time import sleep
from logging import getLogger, DEBUG, FileHandler
logger = getLogger(__name__)
logger.setLevel(DEBUG)

if os.path.abspath(os.curdir).split("/")[-1] == 'p4mininet':
    sys.path.append( f"{os.path.abspath(os.curdir)}/p4runtime/p4runtime-shell" )
elif os.path.abspath(os.curdir).split("/")[-1] == 'p4runtime':
    sys.path.append( f"{os.path.abspath(os.curdir)}/p4runtime-shell" )
else:
    logger.error("error")
    sys.exit()
import p4runtime_sh.shell as sh

# ----------------------------------------------------------
from pyroute2.iproute import IPRoute
from pyroute2.ndb.main import NDB
from pyroute2.netlink.rtnl import rt_proto, rtprotos
from socket import AF_INET

def get_ip_bytes(ip: str, subnet: int):
    ip_bytes = socket.inet_aton(ip)
    a = subnet // 8
    b = subnet % 8

    if b > 0 and a == 3:
        ip_bytes = ip_bytes[:a] + bytes([ip_bytes[a] & (0xff << (8 - b))])
    elif b == 0 and a == 3:
        ip_bytes = ip_bytes[:a] + bytes([0x00])
    elif b > 0 and a == 2:
        ip_bytes = ip_bytes[:a] + bytes([ip_bytes[a] & (0xff << (8 - b))], 0x00)
    elif b == 0 and a == 2:
        ip_bytes = ip_bytes[:a] + bytes([0x00][0x00])
    elif b > 0 and a == 1:
        ip_bytes = ip_bytes[:a] + bytes([ip_bytes[a] & (0xff << (8 - b))], 0x00, 0x00)
    elif b == 0 and a == 1:
        ip_bytes = ip_bytes[:a] + bytes([0x00][0x00][0x00])
    elif b > 0 and a == 0:
        ip_bytes = bytes([ip_bytes[a] & (0xff << (8 - b))], 0x00, 0x00, 0x00)
    elif b == 0 and a == 0:
        ip_bytes = bytes([0x00][0x00][0x00][0x00])

    return ip_bytes

def ipv_forward_to_frr_table_insert(ipv4_dst: str):
    table_entry = sh.TableEntry('MyIngress.ipv4_forward_table')(action='MyIngress.ipv4_forward_to_frr')
    table_entry.match['hdr.ipv4.dstAddr'] = f"{ipv4_dst}/32"
    table_entry.insert()

def ipv_forward_table_modify(ipv4_dst: str, port: str, src_mac: str, dst_mac: str):
    table_entry = sh.TableEntry('MyIngress.ipv4_forward_table')(action='MyIngress.ipv4_forward')
    table_entry.match['hdr.ipv4.dstAddr'] = ipv4_dst
    table_entry.action['port'] = port
    table_entry.action['srcAddr'] = src_mac
    table_entry.action['dstAddr'] = dst_mac
    table_entry.modify()


def ipv_forward_table_insert(ipv4_dst: str, port: str, src_mac: str, dst_mac: str):
    table_entry = sh.TableEntry('MyIngress.ipv4_forward_table')(action='MyIngress.ipv4_forward')
    table_entry.match['hdr.ipv4.dstAddr'] = ipv4_dst
    table_entry.action['port'] = port
    table_entry.action['srcAddr'] = src_mac
    table_entry.action['dstAddr'] = dst_mac
    table_entry.insert()

def swtrace_table_modify(swid: str):
    table_entry = sh.TableEntry('MyEgress.swtrace_table')(action='MyEgress.add_swtrace', is_default=True)
    table_entry.action['swid'] = swid
    table_entry.modify()
    logger.debug(f"swtrace_table_modify: {swid}")

def mri_mac_table_insert(port: str, src_mac: str):
    table_entry = sh.TableEntry('MyEgress.mri_mac_table')(action='MyEgress.src_mac_rewrite')
    table_entry.match['standard_metadata.egress_port'] = port
    table_entry.action['srcAddr'] = src_mac
    table_entry.insert()
    logger.debug(f"mri_mac_table_insert: {port} | {src_mac}")

def mri_mac_table_modify(port: str, src_mac: str):
    table_entry = sh.TableEntry('MyEgress.mri_mac_table')(action='MyEgress.src_mac_rewrite')
    table_entry.match['standard_metadata.egress_port'] = port
    table_entry.action['srcAddr'] = src_mac
    table_entry.modify()
    logger.debug(f"mri_mac_table_modify: {port} | {src_mac}")

def mri_is_loop_table_modify(swid: str):
    table_entry = sh.TableEntry('MyIngress.mri_is_loop_table')(action='MyIngress.mri_is_loop', is_default=True)
    table_entry.action['swid'] = swid
    table_entry.modify()
    logger.debug(f"mri_is_loop_table_modify: {swid}")

def mri_clone_table_modify():
    table_entry = sh.TableEntry('MyIngress.mri_clone_table')(action='MyIngress.mri_clone', is_default=True)
    table_entry.action['mcast_grp_id'] = "1"
    table_entry.modify()
    logger.debug("mri_clone_table_modify: 1")

def srcRoute_own_id_table_insert(swid: str):
    table_entry = sh.TableEntry('MyIngress.srcRoute_own_id_table')(action='MyIngress.srcRoute_update')
    table_entry.match['hdr.srcRoutes[0].swid'] = swid
    table_entry.insert()
    logger.debug(f"srcRoute_own_id_table_insert: {swid}")

def srcRoute_nexthop_table_insert(swid: str, port: str, src_mac: str, dst_mac: str):
    table_entry = sh.TableEntry('MyIngress.srcRoute_nexthop_table')(action='MyIngress.srcRoute_nexthop')
    table_entry.match['hdr.srcRoutes[0].swid'] = swid
    table_entry.action['port'] = port
    table_entry.action['srcAddr'] = src_mac
    table_entry.action['dstAddr'] = dst_mac
    table_entry.insert()

def srcRoute_nexthop_table_modify(swid: str, port: str, src_mac: str, dst_mac: str):
    table_entry = sh.TableEntry('MyIngress.srcRoute_nexthop_table')(action='MyIngress.srcRoute_nexthop')
    table_entry.match['hdr.srcRoutes[0].swid'] = swid
    table_entry.action['port'] = port
    table_entry.action['srcAddr'] = src_mac
    table_entry.action['dstAddr'] = dst_mac
    table_entry.modify()

def get_ip_intfs(ipr: IPRoute, switch: dict):

    sw_json_intfs = {}
    intfs = {}

    for if_name, v in switch['intfs'].items():
        port = v.get('port')

        if if_name[0:len('p4rt_')] != 'p4rt_' \
            and if_name[0:len('dummy_')] != 'dummy_' \
                and if_name != 'lo' and port is not None:
            sw_json_intfs[if_name] = {'port': port}

    def addr_ifa_label_match(x, ifa_label: str):
        x_label = x.get_attr('IFA_LABEL')
        if x_label is None or len(x_label) < len(ifa_label):
            return False
        return x_label[-len(ifa_label):] == ifa_label

    # get interface address and index
    for sw_if_name, v in sw_json_intfs.items():     
        x = ipr.get_addr(AF_INET, match=lambda x: addr_ifa_label_match(x, sw_if_name))
        if len(x) > 0:
            x = x[0]
            intfs[x.get('index')] = {
                 'label': x.get_attr('IFA_LABEL'),
                 'port': v.get('port'),
                 'ip': x.get_attr('IFA_ADDRESS')+f"/{x.get('prefixlen')}"
                }

    # get loopback address
    for x in ipr.get_addr(AF_INET, match=lambda x: x.get_attr('IFA_LABEL') == 'lo'):
        if x.get_attr('IFA_ADDRESS') != '127.0.0.1':
            intfs[x.get('index')] = {
                 'label': x.get_attr('IFA_LABEL'),
                 'ip': x.get_attr('IFA_ADDRESS')+f"/{x.get('prefixlen')}"
                }
            break

    # get mac address
    for x in ipr.get_links():
        if_name = x.get_attr('IFLA_IFNAME')
        if_index = x.get('index')
        if if_index in intfs and if_name == intfs[if_index].get('label'):
            intfs[if_index]['mac'] = x.get_attr('IFLA_ADDRESS')
    
    return intfs


def get_neighbours(ipr: IPRoute, ip_intfs: dict):
    neighbours = {}

    def arp_ifindex_match(x, ifindex: int):
            if x.get_attr('NDA_PROBES') == 0:
                return False
            return x.get('ifindex') == ifindex

    for k, v in ip_intfs.items():
        for x in ipr.get_neighbours(AF_INET, match=lambda x: arp_ifindex_match(x, k)):
            # logger.debug(f"ifindex {x.get('ifindex')} | port: {v.get('port')} | dst {x.get_attr('NDA_DST')} | lladdr {x.get_attr('NDA_LLADDR')}")
            prefix_len = v.get('ip').split('/')[1]
            if x.get_attr('NDA_LLADDR') is not None and prefix_len:
                neighbours[x.get_attr('NDA_DST')] = {
                    'index': x.get('ifindex'),
                    'prefix_len': prefix_len,
                    'port': v.get('port'),
                    'dst_mac': x.get_attr('NDA_LLADDR'),
                    'src_mac': v.get('mac')
                }
    return neighbours


def get_routes(ipr: IPRoute, neighbours: dict, proto=None):

    ipr_routes = {}
    if proto is None or type(proto) is not int:
        ipr_routes = ipr.get_routes()
    else:
        ipr_routes = ipr.get_routes(match=lambda x: x['proto'] == proto)
        # ipr_routes = ipr.get_routes(match=lambda x: x['proto'] == 186)
        # ipr_routes = ipr.get_routes(match=lambda x: x['proto'] == 188)

    routes = {}
    for route in ipr_routes:
        # logger.debug(route)
        # logger.debug(f"oif: {route.get_attr('RTA_OIF')} | dst {route.get_attr('RTA_DST')}/{route.get('dst_len')} | proto {route.get('proto')} | gateway {route.get_attr('RTA_GATEWAY')}")
        if route.get_attr('RTA_OIF') is None:
            logger.debug(route)

        gateway = route.get_attr('RTA_GATEWAY')
        if gateway in neighbours and route.get_attr('RTA_OIF') == neighbours[gateway].get('index'):
            dst = f"{route.get_attr('RTA_DST')}/{route.get('dst_len')}"
            routes[dst] = {
                'oif': route.get_attr('RTA_OIF'),
                'port': neighbours[gateway].get('port'),
                'dst_mac': neighbours[gateway].get('dst_mac'),
                'src_mac': neighbours[gateway].get('src_mac')
            }
    
    # logger.debug(f"RTNL routes length: {len(ipr_routes)} | routes length: {len(routes)}")

    return routes

def check_ipv4_forward_entry(ip: str, subnet: int, port: int, src_mac: str, dst_mac: str, ipv4_entries: dict):

    ip_bytes = get_ip_bytes(ip, subnet)
    port_bytes = (port).to_bytes(1, byteorder='big')
    src_mac_bytes = binascii.unhexlify(src_mac.replace(':', ''))
    dst_mac_bytes = binascii.unhexlify(dst_mac.replace(':', ''))
    change_flag = False

    if ip_bytes in ipv4_entries:
        already_entry = ipv4_entries[ip_bytes]

        # update
        if already_entry['port'] != port_bytes or \
            already_entry['srcAddr'] != src_mac_bytes or \
                already_entry['dstAddr'] != dst_mac_bytes:
            
            logger.debug(f"ipv4_forward: update {ip}/{subnet}")
            ipv_forward_table_modify(f"{ip}/{subnet}", str(port), src_mac, dst_mac)
            change_flag = True

        already_entry['is_set'] = True
        
    else:
        logger.debug(f"ipv4_forward: not found {ip}/{subnet}")
        ipv_forward_table_insert(f"{ip}/{subnet}", str(port), src_mac, dst_mac)

        ipv4_entries[ip_bytes] = {
            'port': port_bytes,
            'dstAddr': dst_mac_bytes,
            'srcAddr': src_mac_bytes,
            'is_set': True
            }
        change_flag = True
        
    return ipv4_entries, change_flag

def check_srcRoute_nexthop_entry(swid: str, port: int, src_mac: str, dst_mac: str, sr_nexthop_entries: dict):
    
        swid_bytes = get_ip_bytes(swid, 32)
        port_bytes = (port).to_bytes(1, byteorder='big')
        src_mac_bytes = binascii.unhexlify(src_mac.replace(':', ''))
        dst_mac_bytes = binascii.unhexlify(dst_mac.replace(':', ''))
        change_flag = False
    
        if swid_bytes in sr_nexthop_entries:
            already_entry = sr_nexthop_entries[swid_bytes]
    
            # update
            if already_entry['port'] != port_bytes or \
                already_entry['srcAddr'] != src_mac_bytes or \
                    already_entry['dstAddr'] != dst_mac_bytes:
                
#                 logger.debug(f"srcRoute_nexthop {swid} | update | \
# {already_entry['port'] != port_bytes} || {already_entry['port']}|-|{port_bytes}:{port} | \
# {already_entry['srcAddr'] != src_mac_bytes} || {already_entry['srcAddr']}|-|{src_mac_bytes} | \
# {already_entry['dstAddr'] != dst_mac_bytes} || {already_entry['dstAddr']}|-|{dst_mac_bytes}")
                
                logger.debug(f"srcRoute_nexthop: update {swid}")
                srcRoute_nexthop_table_modify(swid, str(port), src_mac, dst_mac)
                change_flag = True
    
            already_entry['is_set'] = True
            
        else:
            logger.debug(f"srcRoute_nexthop: not found {swid}")
            srcRoute_nexthop_table_insert(swid, str(port), src_mac, dst_mac)
    
            sr_nexthop_entries[swid_bytes] = {
                'port': port_bytes,
                'dstAddr': dst_mac_bytes,
                'srcAddr': src_mac_bytes,
                'is_set': True
                }
            change_flag = True
            
        return sr_nexthop_entries, change_flag


def init_routing_table(switch_name: str, nodes: dict):

    with IPRoute() as ipr:

        ipv4_local_entries = []

        for x in sh.TableEntry('MyIngress.ipv4_forward_table').read():
            
            # logger.debug(x.match['hdr.ipv4.dstAddr'].lpm.value)
            if x.action.action_name == 'MyIngress.ipv4_forward_to_frr':
                # ipv4_local_entries.append(x.match['hdr.ipv4.dstAddr'].lpm.value)
                ipv4_local_entries.append(x.msg().match[0].lpm.value)


        intfs = get_ip_intfs(ipr, nodes[switch_name])

        for k, v in intfs.items():

            # logger.debug(f"intfs: {k}")
            
            # ipv4_forward case: dst_ip is switch ip.
            ip_bytes = get_ip_bytes(v['ip'].split('/')[0], 32)
            if ip_bytes in ipv4_local_entries:
                # logger.debug(f"ipv4_forward_to_frr: found {v['ip']}")
                pass
            else:
                ipv_forward_to_frr_table_insert(v['ip'].split('/')[0])
                logger.debug(f"ipv4_forward_to_frr: not found {v['ip']}")

            # source routing setting
            port = v.get('port')
            if port is None and 'lo' == v.get('label'):
                swid = v['ip'].split('/')[0]

                # srcRoute check own id
                srcRoute_own_id_table_insert(swid)

                # mri loop check
                mri_is_loop_table_modify(swid)

                # mri clone rule
                mri_clone_table_modify()

                # swtrace
                swtrace_table_modify(swid)

            # rewrite src_mac for mri clone
            mac = v.get('mac')
            if port is not None and mac is not None:
                mri_mac_table_insert(str(port), mac)


def update_routing_table(switch_name: str, nodes: dict):

    change_flag = False

    with IPRoute() as ipr:

        ipv4_entries = {}
        for x in sh.TableEntry('MyIngress.ipv4_forward_table').read():
            
            if  hasattr(x.action, 'action_name') and x.action.action_name == 'MyIngress.ipv4_forward':
                # ipv4_entries[x.match['hdr.ipv4.dstAddr'].lpm.value] = {
                #     'port': x.action['port'].value,
                #     'dstAddr': x.action['dstAddr'].value,
                #     'srcAddr': x.action['srcAddr'].value,
                #     'is_set': False
                # }

                params = x.action.msg().params
                ipv4_entries[x.msg().match[0].lpm.value] = {
                    'port': params[0].value,
                    'srcAddr': params[1].value,
                    'dstAddr': params[2].value,
                    'is_set': False
                }


        sr_nexthop_entries = {}
        for x in sh.TableEntry('MyIngress.srcRoute_nexthop_table').read():
            # sr_nexthop_entries[x.match['hdr.srcRoutes[0].swid'].exact.value] = {
            #     'port': x.action['port'].value,
            #     'dstAddr': x.action['dstAddr'].value,
            #     'srcAddr': x.action['srcAddr'].value,
            #     'is_set': False
            # }

            params = x.action.msg().params
            sr_nexthop_entries[x.msg().match[0].exact.value] = {
                'port': params[0].value,
                'srcAddr': params[1].value,
                'dstAddr': params[2].value,
                'is_set': False
            }


        intfs = get_ip_intfs(ipr, nodes[switch_name])
        
        neighbours = get_neighbours(ipr, intfs)
        # ipv4 forwarding for neighbour
        for k, v in neighbours.items():
            subnet = int(v['prefix_len'])
            ipv4_entries, change_flag = check_ipv4_forward_entry(k, subnet, v['port'], v['src_mac'], v['dst_mac'], ipv4_entries)

            if subnet == 32 and k[:len('10.0.')] == '10.0.':
                sr_nexthop_entries, _ = check_srcRoute_nexthop_entry(k, v['port'], v['src_mac'], v['dst_mac'], sr_nexthop_entries)

        if change_flag:
            logger.debug("---------------neighbours update---------------")

        routes = get_routes(ipr, neighbours, 188)
        # ipv4 forwarding for route
        for k, v in routes.items():
            ip = k.split('/')[0]
            subnet = int(k.split('/')[1])
            ipv4_entries, change_flag = check_ipv4_forward_entry(ip, subnet, v['port'], v['src_mac'], v['dst_mac'], ipv4_entries)

            if subnet == 32 and k[:len('10.0.7.')] == '10.0.7.':
                swid = ip
                sr_nexthop_entries, _ = check_srcRoute_nexthop_entry(swid, v['port'], v['src_mac'], v['dst_mac'], sr_nexthop_entries)

        if change_flag:
            logger.debug("---------------routes update---------------")


        for x in sh.TableEntry('MyIngress.ipv4_forward_table').read():

            if x.action.action_name == 'MyIngress.ipv4_forward' and \
                x.msg().match[0].lpm.value  in ipv4_entries:
                ipv4_dst = x.msg().match[0].lpm.value
                # x.match['hdr.ipv4.dstAddr'].lpm.value in ipv4_entries:
                # ipv4_dst = x.match['hdr.ipv4.dstAddr'].lpm.value

                if ipv4_entries[ipv4_dst]['is_set'] == False:
                    x.delete()
                    logger.debug(f"ipv4_forward: delete {ipv4_dst}")
                    change_flag = True
        
        for x in sh.TableEntry('MyIngress.srcRoute_nexthop_table').read():
            if x.msg().match[0].exact.value in sr_nexthop_entries:
                swid_bytes = x.msg().match[0].exact.value
            # if x.match['hdr.srcRoutes[0].swid'].exact.value in sr_nexthop_entries:
                # swid_bytes = x.match['hdr.srcRoutes[0].swid'].exact.value

                if sr_nexthop_entries[swid_bytes]['is_set'] == False:
                    x.delete()
                    logger.debug(f"srcRoute_nexthop: delete {swid_bytes}")
                    change_flag = True
    
    return change_flag


def load_nodes_json(file_path: str):
    with open(file_path, mode="rt", encoding="utf-8") as f:
        nodes = json.load(f)

    return nodes

def cmd_p4runtime_sh(switch_name: str, nodes: dict):
    
    if 'sw_id' not in nodes[switch_name]:
        logger.debug(f"switch {switch_name} was configured, but not found sw_id.")
        return
    
    log_handler = FileHandler(filename=f"log/{switch_name}_table.log", mode="w")
    log_handler.setLevel(DEBUG)
    logger.addHandler(log_handler)

    switch = nodes[switch_name]
    sw_id = switch['sw_id']
    device_id = switch['device_id']
    grpc_addr = switch['grpc_addr']

    # not use config file
    # p4info_path = switch['p4info_path']
    # p4file_path = switch['p4file_path']

    sh.setup(
        device_id=device_id,
        grpc_addr=grpc_addr,
        # election_id=(0, 1), # (high, low)
        # config=sh.FwdPipeConfig(p4info_path, p4file_path)
    )

    init_routing_table(switch_name=switch_name, nodes=nodes)

    while True:
        try:
            result = update_routing_table(switch_name=switch_name, nodes=nodes)
            # result = update_ipv4_forward_table(switch_name=switch_name, nodes=nodes)
            # logger.debug("--------------------sleep 1 sec--------------------")
            sleep(1)
            if result:
                logger.debug("--------------------update table--------------------")

            sys.stdout.flush()

        except Exception as e:
            logger.error(e)
            break

    sh.teardown()


if __name__ == '__main__':

    nodes = load_nodes_json("nodes.json")

    if len(sys.argv) > 1:
        if sys.argv[1] in nodes and 'sw_id' in nodes[sys.argv[1]]:
                cmd_p4runtime_sh(sys.argv[1], nodes)
        else:
            logger.error(f"switch {sys.argv[1]} not found")
