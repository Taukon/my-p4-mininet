import json
import os
import sys
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

# python3 -m p4runtime_sh --grpc-addr 172.23.88.64:9560 --device-id 2


def load_nodes_json(file_path: str):
    with open(file_path, mode="rt", encoding="utf-8") as f:
        nodes = json.load(f)

    return nodes


def cmd_p4runtime_sh(switch_name: str, nodes: dict):
    
    if 'sw_id' not in nodes[switch_name]:
        logger.error(f"switch {switch_name} was configured, but not found sw_id.")
        return
    
    log_handler = FileHandler(filename=f"log/{switch_name}_load.log", mode="w")
    log_handler.setLevel(DEBUG)
    logger.addHandler(log_handler)

    switch = nodes[switch_name]
    sw_id = switch['sw_id']
    device_id = switch['device_id']
    grpc_addr = switch['grpc_addr']
    p4info_path = switch['p4info_path']
    p4file_path = switch['p4file_path']

    sh.setup(
        device_id=device_id,
        grpc_addr=grpc_addr,
        # election_id=(0, 1), # (high, low)
        config=sh.FwdPipeConfig(p4info_path, p4file_path)
    )

    # multicast group 1 (all ports except dummy ports)
    mu = sh.MulticastGroupEntry(1)
    for k, v in switch['intfs'].items():
        port = v.get('port')
        if k[0:len('p4rt_')] != 'p4rt_' \
            and k[0:len('dummy_')] != 'dummy_' \
                and k != 'lo' and port is not None:
            
            mu.add(int(port), 1)

    mu.insert()

# --------------------- validate switch.json!!! ---------------------
    if p4file_path == './p4src/switch.json':

        # frr forwarding
        for k, v in switch['intfs'].items():
            if k[0:len('dummy_')] == 'dummy_' and 'port' in v:
                dummy_port = v.get('port')
                port = switch['intfs'].get(k[len('dummy_'):]).get('port')

                if port is not None and dummy_port is not None:
                    # from frr port
                    ingress_entry1 = sh.TableEntry('MyIngress.from_frr_table')(action='MyIngress.forward_from_frr')
                    ingress_entry1.match['standard_metadata.ingress_port'] = str(dummy_port)
                    ingress_entry1.action['port'] = str(port)
                    ingress_entry1.insert()
                    # logger.debug(f"from {dummy_port} to {port}: forward_from_frr")

                    # to frr port
                    ingress_entry2 = sh.TableEntry('MyIngress.to_frr_table')(action='MyIngress.forward_to_frr')
                    ingress_entry2.match['standard_metadata.ingress_port'] = str(port)
                    ingress_entry2.action['port'] = str(dummy_port)
                    ingress_entry2.insert()
                    # logger.debug(f"from {port} to {dummy_port}: forward_to_frr")

            # table_entry['MyIngress.to_frr_table'].read(function=lambda x: print(x))

    sh.teardown()
    logger.debug("complete")


if __name__ == '__main__':

    nodes = load_nodes_json("nodes.json")

    if len(sys.argv) > 1:
        if sys.argv[1] in nodes and 'sw_id' in nodes[sys.argv[1]]:
                cmd_p4runtime_sh(sys.argv[1], nodes)
        else:
            logger.error(f"switch {sys.argv[1]} not found")
    