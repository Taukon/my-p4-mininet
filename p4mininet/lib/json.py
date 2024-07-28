from mininet.net import Mininet
import json



def decide_p4_file_path(sw_name: str):
    # Your code here.
    return f"./p4src/p4info.txt", f"./p4src/switch.json"


def write_nodes_json(net: Mininet):
    """
    After Run Mininet.start() or build() | Write nodes.json
    """
    
    switches = {}
    for sw_i, switch in enumerate(net.switches):

        if hasattr(switch, 'p4_config') and switch.p4_config is not None:

            p4_config = switch.p4_config
            p4_intfs = p4_config.get("intfs")
            intfs = {}
            p4info_path, p4file_path = decide_p4_file_path(sw_name=switch.name)

            for intf_i, intf in enumerate(switch.intfNames()):

                if intf in p4_intfs:
                    link_intf = switch.intfs[intf_i].link.intf2 if switch.intfs[intf_i].link.intf1.node.name == switch.name else switch.intfs[intf_i].link.intf1
                    link_node = link_intf.node.name
                    intfs[intf] = {"port": p4_intfs.get(intf), "mac": switch.MAC(intf), "link_node": link_node, "link_intf": link_intf.name, "link_mac": link_intf.node.MAC(link_intf.name)}

                elif intf[0:len("p4rt_")] == "p4rt_":
                    link_intf = switch.intfs[intf_i].link.intf2 if switch.intfs[intf_i].link.intf1.node.name == switch.name else switch.intfs[intf_i].link.intf1
                    link_node = link_intf.node.name
                    intfs[intf] = {"ip": switch.IP(intf), "mac": switch.MAC(intf), "link_node": link_node, "link_intf": link_intf.name, "link_mac": link_intf.node.MAC(link_intf.name)}

                elif intf != 'lo':
                    intfs[intf] = {"mac": switch.MAC(intf)}
                    

            switches[switch.name] = {
                "sw_id": p4_config.get("sw_id"),
                "device_id": p4_config.get("device_id"),
                "thrift_port": p4_config.get("thrift_port"),
                "log_file": p4_config.get("log_file"),
                "grpc_addr": p4_config.get("grpc_addr"),
                "p4info_path": p4info_path,
                "p4file_path": p4file_path,
                "intfs": intfs
                }

    hosts = {}
    for host_i, host in enumerate(net.hosts):

        intfs = {}

        for intf_i, intf in enumerate(host.intfNames()):
            if intf != 'lo':
                link_intf = host.intfs[intf_i].link.intf2 if host.intfs[intf_i].link.intf1.node.name == host.name else host.intfs[intf_i].link.intf1
                link_node = link_intf.node.name
                intfs[intf] = {"ip": host.IP(intf), "mac": host.MAC(intf), "link_node": link_node, "link_intf": link_intf.name, "link_mac": link_intf.node.MAC(link_intf.name)}
                # print(f"{host.intfs[intf_i]} | {link_node} || {host.intfs[intf_i].link.intf1.node.name} | {host.intfs[intf_i].link.intf2.node.name} | {host.intfs[intf_i].link.intf1.name} | {host.IP(intf)}")

        hosts[host.name] = {
            "host_id": host_i + 1,
            "intfs": intfs
            }
        
    nodes = switches | hosts
    file_path = "nodes.json"
    with open(file_path, mode="wt", encoding="utf-8") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=4)

    return file_path


def load_switch_ip_list(file_path: str) -> dict:
    """
    switch_ip_list.json
    """

    with open(file_path, mode="rt", encoding="utf-8") as f:
        switch_ip_list = json.load(f)

    return switch_ip_list