#!/usr/bin/python

#################################################################################
#
# GraphML-to-Mininet
#
# Parses Network Topologies in GraphML format from the Internet Topology Zoo.
# A python file for creating Mininet Topologies will be created as Output.
# Files have to be in the same directory.
#
# Arguments:
#   -f              [filename of GraphML input file]
#   --file          [filename of GraphML input file]
#   -o              [filename of GraphML output file]
#   --output        [filename of GraphML output file]
#   -b              [number as integer for DEFAULT bandwidth in mbit]
#   --bw            [number as integer for DEFAULT bandwidth in mbit]
#   --bandwidth     [number as integer for DEFAULT bandwidth in mbit]
#   -c              [controller ip as string]
#   --controller    [controller ip as string]
#   -p 				[port number as string]
#   -port 			[port number as string]
#
# sjas
# Wed Jul 17 02:59:06 PDT 2013
# 
# modified
# Tue Apr 19 2022
#
# python3 test.py -f mini-topologies/Abilene.graphml --cli
#################################################################################

import xml.etree.ElementTree as ET
import numpy as np
import sys
import math
import re
import random
import keyword
from sys import argv

input_file_name = ''
output_file_name = ''
bandwidth_argument = ''

# This is the 17 to 24 digits in the IP address, that is X in 10.0.X.0.
# To handle the situation in which the number of nodes excceed 254.
# Host begin from 10.0.0.1, switch begin from 10.0.8.1.
# IP is limited in the field of 10.0.0.0/12
# If a host IP is 10.0.X.Y, then its corresponding switch node is 10.0.X+8.Y
# Support up to 254 * 8 nodes in current setting
# To change the node number limit, you should modify the '/12' mask setting.
# ip_host_base = -1
ip_host_base = 0
ip_switch_base = 7


# Enable Mininet CLI after simulation code complete, else exit immediately
enable_cli = 0

# Enable tips for user, telling them to add their own simulation code
enable_tip = 1

# Enable ssh access for host nodes
enable_ssh = 0

# First check commandline arguments
for i in range(len(argv)):

    if argv[i] == '-f':
        input_file_name = argv[i+1]
    if argv[i] == '--file':
        input_file_name = argv[i+1]
    if argv[i] == '-o':
        output_file_name = argv[i+1]
    if argv[i] == '--output':
        output_file_name = argv[i+1]
    if argv[i] == '-b':
        bandwidth_argument = argv[i+1]
    if argv[i] == '--bw':
        bandwidth_argument = argv[i+1]
    if argv[i] == '--bandwidth':
        bandwidth_argument = argv[i+1]
    if argv[i] == '--cli':
        enable_cli = 1
    if argv[i] == '--notip':
        enable_tip = 0
    if argv[i] == '--ssh':
        enable_ssh = 1

# Terminate when inputfile is missing
if input_file_name == '':
    sys.exit('\033[1;31mError: No input file was specified as argument!\033[0m')

name = re.split("[\./]", input_file_name)[-2]

# Define string fragments for output later on
outputstring_1 = '''#!/usr/bin/python

"""
Custom topology for Mininet, generated by GraphML-Topo-to-Mininet-Network-Generator.
"""

from mininet.net import Mininet
from mininet.node import CPULimitedHost, Host
# from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call
import time
from lib.node import P4SimpleSwitch
from lib.json import load_switch_ip_list, write_nodes_json
from lib import cli

        
def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                #    ipBase='10.0.0.0/12',
                   ipBase='10.0.0.0/24',
                #    autoSetMacs = True
                 )

    switch_ip_list = load_switch_ip_list("{name}_switch_ip_list.json")
'''

outputstring_2a='''
    info( '\033[1;36m*** Add P4 switches\033[0m\\n')\n
'''
outputstring_2b='''
    info( '\033[1;36m*** Add hosts\033[0m\\n')\n
'''

outputstring_2c='''
    info( '\033[1;36m*** Add P4 controllers\033[0m\\n')\n
'''

outputstring_2d='''
    info( '\033[1;36m*** Add links\033[0m\\n')\n
'''

outputstring_2e='''
    info( '\033[1;36m*** Add Dummy and p4runtime links\033[0m\\n')\n
'''

outputstring_3a='''
    info( '\\n\033[1;36m*** Starting network\033[0m\\n')
    net.build()\n
'''

outputstring_3b='''
    info( '\033[1;36m*** Run simple_switch_grpc\033[0m\\n')\n
'''

outputstring_write_nodes_json = '''
    info( '\\n\033[1;36m*** Write nodes.json \033[0m\\n')
    write_nodes_json(net)\n
'''

outputstring_3c='''
    info( '\033[1;36m*** Set vtysh config\033[0m\\n')\n
'''

outputstring_3d='''
    info( '\033[1;36m*** Set P4 runtime\033[0m\\n')\n
'''

user_simulation_code_area='''
    ####################################
    #### USER SIMULATION CODE HERE #####
    ####################################
    
    # Your automatic simulation code.
    
    ####################################
'''

outputstring_4c='''
    cli.P4CLI(net)
'''

outputstring_4d='''
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
'''

outputstring_5 = '''
'''

# WHERE TO PUT RESULTS
outputstring_to_be_exported = ''
outputstring_to_be_exported += outputstring_1.format(name=name)


# outputstring_to_be_exported += outputstring_controller

# READ FILE AND DO ALL THE ACTUAL PARSING IN THE NEXT PARTS
xml_tree    = ET.parse(input_file_name)
namespace   = "{http://graphml.graphdrawing.org/xmlns}"
ns          = namespace # just doing shortcutting, namespace is needed often.

# GET ALL ELEMENTS THAT ARE PARENTS OF ELEMENTS NEEDED LATER ON
root_element    = xml_tree.getroot()
graph_element   = root_element.find(ns + 'graph')

# GET ALL ELEMENT SETS NEEDED LATER ON
index_values_set    = root_element.findall(ns + 'key')
node_set            = graph_element.findall(ns + 'node')
edge_set            = graph_element.findall(ns + 'edge')

# SET SOME VARIABLES TO SAVE FOUND DATA FIRST
# Memomorize the values' ids to search for in current topology
node_label_name_in_graphml = ''
node_latitude_name_in_graphml = ''
node_longitude_name_in_graphml = ''
node_edge_bandwidth = ''
# For saving the current values
node_index_value     = ''
node_name_value      = ''
node_longitude_value = ''
node_latitude_value  = ''
edge_bandwidth_unit = ''
edge_bandwidth_temp_info = ''
# ID: value dictionaries
id_node_name_dict   = {}     # to hold all 'id: node_name_value' pairs
id_longitude_dict   = {}     # to hold all 'id: node_longitude_value' pairs
id_latitude_dict    = {}     # to hold all 'id: node_latitude_value' pairs

# FIND OUT WHAT KEYS ARE TO BE USED, SINCE THIS DIFFERS IN DIFFERENT GRAPHML TOPOLOGIES
for i in index_values_set:

    if i.attrib['attr.name'] == 'label' and i.attrib['for'] == 'node':
        node_label_name_in_graphml = i.attrib['id']
    if i.attrib['attr.name'] == 'Longitude':
        node_longitude_name_in_graphml = i.attrib['id']
    if i.attrib['attr.name'] == 'Latitude':
        node_latitude_name_in_graphml = i.attrib['id']
    if i.attrib['attr.name'] == 'LinkSpeed' and i.attrib['for'] == 'edge':
        node_edge_bandwidth = i.attrib['id']
    if i.attrib['attr.name'] == 'LinkSpeedUnits' and i.attrib['for'] == 'edge':
        edge_bandwidth_unit = i.attrib['id']
    if i.attrib['attr.name'] == 'LinkLabel' and i.attrib['for'] == 'edge':
        edge_bandwidth_temp_info = i.attrib['id']

# Calculate THE AVERAGE LONGITUDE AND LATITUDE TO COVER NULL GEOGRAPHICAL DATA
longitude_set = []
latitude_set = []

for n in node_set:

    location_set = n.findall(ns + 'data')

    # Finally get all needed values
    for l in location_set:

        # Longitude data
        if l.attrib['key'] == node_longitude_name_in_graphml:
            longitude_set.append(float(l.text))
        # Latitude data
        if l.attrib['key'] == node_latitude_name_in_graphml:
            latitude_set.append(float(l.text))

defalult_longitude = round(np.mean(longitude_set), 5) if len(longitude_set) != 0 else 0.0
defalult_latitude = round(np.mean(latitude_set), 5) if len(latitude_set) != 0 else 0.0

# NOW PARSE ELEMENT SETS TO GET THE DATA FOR THE TOPO
# GET NODE_NAME DATA
# GET LONGITUDE DATK
# GET LATITUDE DATA
node_names = []
node_count = 0

for n in node_set:

    node_index_value = n.attrib['id']
    # Get all data elements residing under all node elements
    data_set = n.findall(ns + 'data')
    node_count = node_count + 1

    # Finally get all needed values
    for d in data_set:

        # Node name in python variable format
        if d.attrib['key'] == node_label_name_in_graphml:
            node_name_value = re.sub('[^a-zA-Z0-9_]', '', d.text)
            node_name_value = re.match('[^0-9_]+[a-zA-Z0-9_]*', node_name_value)
            if node_name_value is None:
                node_name_value = 'NotGiven'
            else:
                node_name_value = node_name_value.group()
                if keyword.iskeyword(node_name_value) or node_name_value == 'None':
                    node_name_value = 'NotGiven'

            node_names.append(node_name_value)
        # Longitude data
        if d.attrib['key'] == node_longitude_name_in_graphml:
            node_longitude_value = d.text
        # Latitude data
        if d.attrib['key'] == node_latitude_name_in_graphml:
            node_latitude_value = d.text

        # Save ID: data couple
        id_node_name_dict[node_index_value] = node_name_value
        id_longitude_dict[node_index_value] = node_longitude_value if node_longitude_value != '' else defalult_longitude
        id_latitude_dict[node_index_value]  = node_latitude_value if node_latitude_value != '' else  defalult_latitude

cur_node = 1
# If the names of some nodes are same,
# They will be regarded as the same node in topology.
# Here checks whether there are same node names.
# If exist, change the node names into standard formant 's + No' (e.g. s11, s12).
if len(set(node_names)) != len(node_names) or 'NotGiven' in node_names:
    id_node_name_dict = {}
    for n in node_set:
        node_index_value = n.attrib['id']
        id_node_name_dict[node_index_value] = 's' + str(cur_node)
        cur_node = cur_node + 1

# STRING CREATION
# FIRST CREATE THE SWITCHES AND HOSTS
tempstring1 = ''
tempstring2 = ''
tempstring3 = ''
tempstring4 = ''
tempstring5 = ''
tempstring6 = ''
tempstring7 = ''
tempstring8 = ''
tempstring9 = ''
local_link_flag = 1

"""
address_list = {
    's1': {
        's2': {
            "ip": '10.255.0.1/24',
            "bw": 1000.0,
        },
        's3': {
            "ip": '10.255.0.3/24',
            "bw": 1000.0,
        },
        'h1': {
            "ip": '10.1.1.1/24',
            "bw": 1000.0,
        }
    }
}
"""
address_list = {}

for i in range(0, len(id_node_name_dict)):

    # Create switch
    temp1 =  '    '
    temp1 += id_node_name_dict[str(i)]
    temp1 += " = net.addSwitch('s"
    temp1 += str(i+1)
    temp1 += "', cls=P4SimpleSwitch)\n"

    # Create corresponding host
    temp2 =  '    '
    temp2 += id_node_name_dict[str(i)]
    temp2 += "_host = net.addHost('h"
    temp2 += str((i+1))
    # if i % 254 == 0:
    #     ip_host_base = ip_host_base + 1
    temp2 += "', cls=Host, ip=None"
    temp2 += ")\n"
    tempstring1 += temp1
    tempstring2 += temp2


    linkname = '    local_link'
    value = " = {'bw':1000.0, 'delay':'0ms'}\n"
    if local_link_flag:
        tempstring3 += linkname
        tempstring3 += value
        local_link_flag = 0
    temp3 =  '    net.addLink('
    temp3 += id_node_name_dict[str(i)]
    temp3 += ', '
    temp3 += id_node_name_dict[str(i)]
    temp3 += "_host, "
    temp3 += "params2={'ip': '10."
# ========================================================================================
    if i % 254 == 0:
        ip_host_base = ip_host_base + 1
    temp3 += str(ip_host_base)
# ========================================================================================
    # temp3 += str(2)
# ========================================================================================
    temp3 += '.'
    temp3 += str(i % 254 + 1)
    temp3 += '.2'
    temp3 += "/24'}, cls=TCLink, **"
    # Temp3 += id_node_name_dict[str(i)] + '_local'
    temp3 += "local_link"
    temp3 += ")"
    temp3 += '\n'
    tempstring3 += temp3

    ipv6_str1 = str(hex(ip_host_base))[2:]
    ipv6_hex2 = hex((i % 254 + 1))
    ipv6_str2 = str(ipv6_hex2)[2:]
    switch_ipv6 =f"fc00::{ipv6_str1}:{ipv6_str2}:1:0:0/80"
    host_ipv6 = f"fc00::{ipv6_str1}:{ipv6_str2}:2:0:0/80"

    cmd_temp4_ipv4 = 'f"' + 'ip route add default dev {' + f'{id_node_name_dict[str(i)]}_host.intfNames()[0]' + '}' + '"'
    temp4 =  f'    {id_node_name_dict[str(i)]}_host.cmd('
    temp4 += f'{cmd_temp4_ipv4})\n'

    cmd_temp4_ipv6 = 'f"' + f'ip -6 addr add {host_ipv6} dev ' + '{' + f'{id_node_name_dict[str(i)]}_host.intfNames()[0]' + '}' + '"'
    temp4 +=  f'    {id_node_name_dict[str(i)]}_host.cmd('
    temp4 += f'{cmd_temp4_ipv6})\n'

    cmd_temp4_ipv6_default_route = 'f"' + 'ip -6 route add default dev ' + '{' + f'{id_node_name_dict[str(i)]}_host.intfNames()[0]' + '}' + '"'
    temp4 +=  f'    {id_node_name_dict[str(i)]}_host.cmd('
    temp4 += f'{cmd_temp4_ipv6_default_route})\n\n'
    tempstring4 += temp4

    # Create controller
    temp5 = '    '
    temp5 += f"{id_node_name_dict[str(i)]}_Controller"
    temp5 += f" = {id_node_name_dict[str(i)]}.add_P4Controller(net, "
    temp5 += f"switch_ip_list[{id_node_name_dict[str(i)]}.name])\n"
    tempstring5 += temp5

    temp6 = '    '
    temp6 += f"{id_node_name_dict[str(i)]}.reflect_switch_links()\n"
    tempstring6 += temp6

    # Run Simple Switch
    temp7 = '    '
    temp7 += f"{id_node_name_dict[str(i)]}.run_simple_switch_grpc()\n"
    tempstring7 += temp7

    # Set vtysh config ospf
    temp8 = '    '
    temp8 += f"{id_node_name_dict[str(i)]}_Controller.set_frr_ospf_conf()\n"
    tempstring8 += temp8

    # Run P4 runtime
    temp9 = '    '
    temp9 += f"{id_node_name_dict[str(i)]}_Controller.run_p4_runtime_shell()\n"
    tempstring9 += temp9

# ========================================================================================

    address_list = address_list | {f"s{str(i+1)}": {
        f"h{str((i+1))}": {
            "ip": f"10.{ip_host_base}.{(i % 254 + 1)}.1/24",
            "ipv6": switch_ipv6,
            "bw": 1000.0
        }
    }}
# ========================================================================================


outputstring_to_be_exported += outputstring_2a
outputstring_to_be_exported += tempstring1
outputstring_to_be_exported += outputstring_2b
outputstring_to_be_exported += tempstring2
outputstring_to_be_exported += outputstring_2c
outputstring_to_be_exported += tempstring5
outputstring_to_be_exported += outputstring_2d

tempstring3 += '\n'
outputstring_to_be_exported += tempstring3

tempstring4 += '\n'
outputstring_to_be_exported += tempstring4

tempstringController = outputstring_3c
tempstringController += tempstring8 + '\n'
tempstringController += outputstring_3d
tempstringController += tempstring9

# SECOND CALCULATE DISTANCES BETWEEN SWITCHES,
# Set global bandwidth and create the edges between switches,
# And link each single host to its corresponding switch

tempstring4 = ''
distance = 0.0
latency = 0.0
citylinknum = 0
edge_count = 0

ip_switch_link_base = 3
ip_switch_link_index = 0

for e in edge_set:

    # GET IDS FOR EASIER HANDLING
    src_id = e.attrib['source']
    dst_id = e.attrib['target']
    bandwidth_from_text = ''
    bandwidth_unit = ''
    bandwidth_temp_info = ''
    edge_data = e.findall(ns + 'data')
    edge_count = edge_count + 1

    for e_d in edge_data:

        if e_d.attrib['key'] == node_edge_bandwidth:
            bandwidth_from_text = e_d.text
        if e_d.attrib['key'] == edge_bandwidth_unit:
            bandwidth_unit = e_d.text
        if e_d.attrib['key'] == edge_bandwidth_temp_info:
            bandwidth_temp_info = e_d.text

    # CALCULATE DELAYS

    #    CALCULATION EXPLANATION
    #
    #    formula: (for distance)
    #    dist(SP,EP) = arccos{ sin(La[EP]) * sin(La[SP]) + cos(La[EP]) * cos(La[SP]) * cos(Lo[EP] - Lo[SP])} * r
    #    r = 6378.137 km
    #
    #    formula: (speed of light, not within a vacuumed box)
    #    v = 1.97 * 10**8 m/s
    #
    #    formula: (latency being calculated from distance and light speed)
    #    t = distance / speed of light
    #    t (in ms) = ( distance in km * 1000 (for meters) ) / ( speed of light / 1000 (for ms))

    #    ACTUAL CALCULATION: implementing this was no fun.

    latitude_src	= math.radians(float(id_latitude_dict[src_id]))
    latitude_dst	= math.radians(float(id_latitude_dict[dst_id]))
    longitude_src	= math.radians(float(id_longitude_dict[src_id]))
    longitude_dst	= math.radians(float(id_longitude_dict[dst_id]))

    first_product               = math.sin(latitude_dst) * math.sin(latitude_src)
    second_product_first_part   = math.cos(latitude_dst) * math.cos(latitude_src)
    second_product_second_part  = math.cos(longitude_dst - longitude_src)

    # If some latitude or longtitude data is empty, acos may fail,
    # Use random latency instead.
    try:
        distance = math.acos(first_product + (second_product_first_part * second_product_second_part)) * 6378.137
        latency = round(( distance * 1000 ) / ( 197000 ), 4)
    except ValueError as latitude_NULL:
        latency = round(random.uniform(0, 5), 4)

    # t (in ms) = ( distance in km * 1000 (for meters) ) / ( speed of light / 1000 (for ms))
    # t         = ( distance       * 1000              ) / ( 1.97 * 10**8   / 1000         )
    
    # Set the DEFAULT bandwidth first,
    # If the bandwidth data exist, change it later.
    real_bandwidth = float(bandwidth_argument) if bandwidth_argument != '' else 128.0

    # Get the edge bandwidth data from GRAPHML fields.
    if bandwidth_from_text != '':
        real_bandwidth = float(bandwidth_from_text)
        # Check whether the bandwidth unit is Gbps.
        if bandwidth_unit == 'G':
            real_bandwidth = real_bandwidth * 1024

      # if the bandwidth cannot be found in LinkSpeed, use LinkLabel instead
    elif bandwidth_from_text == '' and bandwidth_temp_info != '':
        bandwidth_digits = re.findall("\d+[.?\d+]", bandwidth_temp_info)
        for digits in range (0, len(bandwidth_digits)):
            bandwidth_digits[digits] = float(bandwidth_digits[digits])
        if len(bandwidth_digits) > 0:
            real_bandwidth = np.mean(bandwidth_digits)
        if bandwidth_temp_info.find('Gb') >= 0:
            real_bandwidth = real_bandwidth * 1024

    # Mininet does not support custom bandwidth setting that excceed 1000 Mbps.
    if real_bandwidth > 1000.0:
        real_bandwidth = 1000.0

    citylinknum = citylinknum + 1
    # Link all corresponding switches with each other
    linkname = '    CityLink' + str(citylinknum)
    value = " = {'bw':"
    value += str(real_bandwidth)
    value += ", 'delay':'"
    value += str(latency)
    value += "ms'}\n"
    tempstring4 += linkname
    tempstring4 += value
    temp4 =  '    net.addLink('
    temp4 += id_node_name_dict[src_id]
    temp4 += ', '
    temp4 += id_node_name_dict[dst_id]
    temp4 += ", cls=TCLink, **"
    temp4 += "CityLink"
    temp4 += str(citylinknum)
    temp4 += ")"
    temp4 += '\n'
    # Next line so i dont have to look up other possible settings
    # temp4 += "ms', loss=0, max_queue_size=1000, use_htb=True)"
    tempstring4 += temp4

# ========================================================================================
    # if ip_switch_link_index % 254 == 0 or ip_switch_link_index % 253 == 0:
    if ip_switch_link_index % 254 == 0:
        ip_switch_link_base = ip_switch_link_base + 1
        ip_switch_link_index = 0

    src_index = int(src_id) + 1
    dst_index = int(dst_id) + 1

    # ip_switch_link_index = ip_switch_link_index + 1

    ipv6_str1 = str(hex(ip_switch_link_base))[2:]
    ipv6_str2 = str(hex(ip_switch_link_index))[2:]

    address_list[f"s{src_index}"] = address_list[f"s{src_index}"] | {
        f"s{dst_index}": {
            "ip": f"10.{ip_switch_link_base}.{ip_switch_link_index}.1/24",
            "ipv6": f"fc00::{ipv6_str1}:{ipv6_str2}:1:0:0/80",
            "bw": real_bandwidth
        }    
    }

    # ip_switch_link_index = ip_switch_link_index + 1
    address_list[f"s{dst_index}"] = address_list[f"s{dst_index}"] | {
        f"s{src_index}": {
            "ip": f"10.{ip_switch_link_base}.{ip_switch_link_index}.2/24",
            "ipv6": f"fc00::{ipv6_str1}:{ipv6_str2}:2:0:0/80",
            "bw": real_bandwidth
        }    
    }
    ip_switch_link_index = ip_switch_link_index + 1
# ========================================================================================

outputstring_to_be_exported += tempstring4
outputstring_to_be_exported += outputstring_2e
outputstring_to_be_exported += tempstring6

if enable_ssh:

    ssh_string = '\n'

    # Create switch for ssh
    temp1 =  '    '
    temp1 += 'ssh_switch'
    temp1 += " = net.addSwitch('tmp1')\n"
    ssh_string += temp1

    for i in range(0, len(id_node_name_dict)):
        temp2 =  '    net.addLink('
        temp2 += 'ssh_switch, '
        temp2 += id_node_name_dict[str(i)]
        temp2 += "_host, "
        temp2 += "params1={'ip': '192."
        if i != 0 and i % 254 == 0:
            ip_host_base = ip_host_base + 1
        temp2 += str(ip_host_base)
        temp2 += '.'
        temp2 += str(i % 254 + 1)
        temp2 += '.1'
        temp2 += "/24'}, "
        temp2 += "params2={'ip': '192."
        temp2 += str(ip_host_base)
        temp2 += '.'
        temp2 += str(i % 254 + 1)
        temp2 += '.2'
        temp2 += "/24'}, "
        temp2 += "cls=TCLink)\n"
        ssh_string += temp2

        # temp3 =  '    '
        # temp3 += f"{id_node_name_dict[str(i)]}_host"
        # temp3 += ".cmd( '/usr/sbin/sshd -D -o UseDNS=no -u0 &' )\n"
        # ssh_string += temp3

    temp3 = '\n'
    temp3 += '    '
    temp3 += 'for host in net.hosts:\n'
    temp3 += '    '
    temp3 += '    '
    temp3 += "host.cmd( '/usr/sbin/sshd -D -o UseDNS=no -u0 &' )\n"
    ssh_string += temp3

    outputstring_ssh='''    info( '\033[1;36m*** Add ssh links\033[0m\\n')\n'''
    outputstring_to_be_exported += outputstring_ssh
    outputstring_to_be_exported += ssh_string
    
outputstring_to_be_exported += outputstring_3a
outputstring_to_be_exported += outputstring_3b
outputstring_to_be_exported += tempstring7
outputstring_to_be_exported += outputstring_write_nodes_json
outputstring_to_be_exported += tempstringController

# write switch IP to switch_ip_list.json
for i in range(0, len(id_node_name_dict)):
# ========================================================================================

    ipv6_str1 = str(hex(ip_switch_base))[2:]
    ipv6_str2 = str(hex(((i % 254) + 1)))[2:]

    address_list[f"s{i+1}"] = address_list[f"s{i+1}"] | {
        f"lo": {
            "ip": f"10.0.{ip_switch_base}.{(i % 254) + 1}/32",
            "ipv6": f"fc00::{ipv6_str1}:{ipv6_str2}:1:0:0/128",
            "bw": real_bandwidth,
            "name": id_node_name_dict[str(i)]
        }    
    }

    address_list[f"s{i+1}"] = address_list[f"s{i+1}"] | {
        f"p4rt_s{i+1}": {
            "ip": f"192.168.{i+1}.1/24"
        }    
    }

# for i, v in address_list.items():    
#     print(i, ":", v)

import json
file_path = "p4mininet/{name}_switch_ip_list.json"
with open(file_path.format(name=name), mode="wt", encoding="utf-8") as f:
        json.dump(address_list, f, ensure_ascii=False, indent=4)
# ========================================================================================

outputstring_to_be_exported += user_simulation_code_area

if enable_cli:
    outputstring_to_be_exported += outputstring_4c

outputstring_to_be_exported += outputstring_4d

# GENERATION FINISHED, WRITE STRING TO FILE
outputfile = ''
if output_file_name == '':
    # output_file_name = re.split("[\./]", input_file_name)[0] + '.py'
    names = re.split("[\./]", input_file_name)
    if names[-1] == 'graphml':
        output_file_name = 'p4mininet/' + names[-2] + '_network.py'

outputfile = open(output_file_name, 'w')
outputfile.write(outputstring_to_be_exported)
outputfile.close()

print("Generate \033[0;33m" + input_file_name + "\033[0m SUCCESSFUL! \033[0;36m" + \
      "(" + str(node_count) + " Switches, " + \
      str(edge_count) + " Links)\033[0m")

if enable_tip:
    print("")
    print("*** NEXT STEP ***")
    print("*** PLease Place Your Additional Simulation Code in the <USER SIMULATION CODE HERE> area of .py Runnable Topology File. ***")
