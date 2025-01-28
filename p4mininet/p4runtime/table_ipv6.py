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
from pyroute2.netlink.rtnl import rt_proto, rtprotos
from socket import AF_INET, AF_INET6


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

def get_ip_intfs(ipr: IPRoute, switch: dict):

    sw_json_intfs = {}
    intfs = {}

    for if_name, v in switch['intfs'].items():
        port = v.get('port')

        if if_name[0:len('p4rt_')] != 'p4rt_' \
            and if_name[0:len('dummy_')] != 'dummy_' \
                and if_name != 'lo' and port is not None:
            sw_json_intfs[if_name] = {'port': port}


    # get mac address and interface index
    for x in ipr.get_links():
        if_index = x.get('index')
        ifla_ifname = x.get_attr('IFLA_IFNAME')
        tmp_ifnames = ifla_ifname.split('_')

        if len(tmp_ifnames) == 2 and tmp_ifnames[1] in sw_json_intfs:
            if_name = tmp_ifnames[1]
            v = sw_json_intfs[if_name]

            if_mac = x.get_attr('IFLA_ADDRESS')
            
            intfs[if_index] = {
                'label': ifla_ifname,
                'port': v.get('port'),
                'mac': if_mac
            }
        
        # get loopback
        elif ifla_ifname == 'lo':
            intfs[if_index] = {
                'label': ifla_ifname
            }
            

    # get interface ipv6 address
    for x in ipr.get_addr(AF_INET6):

        # global ipv6 address scope is 0, local is 253
        if x.get('scope') == 0 and x.get('index') in intfs:
            index = x.get('index')
            intfs[index]['ipv6'] = x.get_attr('IFA_ADDRESS')+f"/{x.get('prefixlen')}"
    
    return intfs


def init_routing_table(switch_name: str, nodes: dict):

    with IPRoute() as ipr:

        intfs = get_ip_intfs(ipr, nodes[switch_name])

        for k, v in intfs.items():

            logger.debug(f"intfs: {k} | {v}")
            
            port = v.get('port')
            if port is None and 'lo' == v.get('label'):
                swid = v['ipv6'].split('/')[0]

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

    sh.teardown()


if __name__ == '__main__':

    nodes = load_nodes_json("nodes.json")

    if len(sys.argv) > 1:
        if sys.argv[1] in nodes and 'sw_id' in nodes[sys.argv[1]]:
                cmd_p4runtime_sh(sys.argv[1], nodes)
        else:
            print(f"switch {sys.argv[1]} not found")
    else:
        print("please input switch name")
