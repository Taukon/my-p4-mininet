from time import sleep
from typing import Union
from mininet.net import Mininet
from mininet.node import Node, Host
from mininet.node import OVSKernelSwitch
from mininet.link import TCLink
from lib.frr import daemons, vtysh


"""example
net = Mininet( topo=None, build=False, ipBase='10.0.0.0/12', autoSetMacs = True)
switch_ip_list = load_switch_ip_list("switch_ip_list.json")

s1 = net.addSwitch('s1', cls=P4SimpleSwitch)
s2 = net.addSwitch('s2', cls=P4SimpleSwitch)

s1_controller = s1.add_P4Controller(net, switch_ip_list[s1.name])
s2_controller = s2.add_P4Controller(net, switch_ip_list[s2.name])

h1 = net.addHost('h1', cls=Host, ip=None)
h2 = net.addHost('h1', cls=Host, ip=None)

local_link = {'bw':1000.0, 'delay':'0ms'}
net.addLink(s1, h1, params2={'ip': '10.0.0.1/24'}, cls=TCLink, **local_link)
net.addLink(s2, h2, params2={'ip': '10.0.0.2/24'}, cls=TCLink, **local_link)

link1 = {'bw':192.0, 'delay':'5.8229ms'}
net.addLink(s1, s2, cls=TCLink, **link1)

s1.reflect_switch_links()
s2.reflect_switch_links()

net.build()
# net.start()

write_nodes_json(net)

s1.run_simple_switch_grpc()
s2.run_simple_switch_grpc()

s1_controller.vtysh_cmd("...")
s2_controller.vtysh_cmd("...")

s1_controller.run_p4_runtime_shell()
s2_controller.run_p4_runtime_shell()
# s1.p4_controller.run_p4_runtime_shell()
# s2.p4_controller.run_p4_runtime_shell()

CLI(net)
net.stop()
"""


class FRR(Node):
# class FRR(Host):
    """FRR Node"""

    PrivateDirs = ["/etc/frr", "/var/run/frr"]

    def __init__(self, name, inNamespace=True, **params):
        params.setdefault("privateDirs", [])
        params["privateDirs"].extend(self.PrivateDirs)
        super().__init__(name, inNamespace=inNamespace, **params)
        
    def config(self, **params):
        super().config(**params)

        self.cmd("ifconfig lo up")
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        self.cmd("sysctl -w net.ipv6.conf.all.forwarding=1")

        # enable proxy arp for all interfaces
        self.cmd("echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp")

        self.start_frr_service()

    def start_frr_service(self):
        """start FRR"""
        self.set_conf("/etc/frr/daemons", daemons)
        self.set_conf("/etc/frr/vtysh.conf", vtysh.format(name=self.name))
        self.set_conf("/etc/frr/frr.conf", "")
        print(self.cmd("/usr/lib/frr/frrinit.sh start"))

    def terminate(self):
        print(self.cmd("/usr/lib/frr/frrinit.sh stop"))
        super(FRR, self).terminate()

    def set_conf(self, file, conf):
        """set frr config"""
        self.cmd("""\
cat << 'EOF' | tee {}
{}
EOF""".format(file, conf))

    def vtysh_cmd(self, cmd=""):
        """exec vtysh commands"""
        cmds = cmd.split("\n")
        vtysh_cmd = "vtysh"
        for c in cmds:
            print(c)
            vtysh_cmd += " -c \"{}\"".format(c)
        return self.cmd(vtysh_cmd)



class P4Controller(FRR):
    """
    P4 Controller(run FRR)
    """
    
    """
    switch_ip_list.json
    ========================================
    link_ip_addrs = {
        's2': {
            "ip": '10.255.0.1/30',
            "bw": 1000.0,
        },
        's3': {
            "ip": '10.255.0.3/30',
            "bw": 1000.0,
        },
        'h1': {
            "ip": '10.1.1.1/24',
            "bw": 1000.0,
        }
        
    }
    """

    def __init__(
            self, name, net: Mininet, p4_switch: OVSKernelSwitch, 
            link_ip_addrs: dict[str: dict[str: Union[int, str]]], **params):

        self.net = net
        self.p4_switch = p4_switch
        self.link_ip_addrs = link_ip_addrs
        self.p4rt_intf_name = None
        super().__init__(name, **params)


    def set_frr_ospf_conf(self):
        
        ospf_network_list = ''

        for k, v in self.link_ip_addrs.items():
            # if k != 'lo' and k[0:len("p4rt_")] != "p4rt_":
            if k[0:len("p4rt_")] != "p4rt_":
                ip_addr = v.get("ip")
                if ip_addr is not None:
                    ospf_network_list += f"  network {ip_addr} area 0.0.0.0\n"
        # # ------------------------------------------------
        #         if k[0] == 'h':
        #             try:
        #                 split_ip = ip_addr.split('/')
        #                 subnet = split_ip[1]
        #                 temp_ip = split_ip[0].split('.')
        #                 ip = f'{temp_ip[0]}.{temp_ip[1]}.{temp_ip[2]}.{int(temp_ip[3])+1}/{subnet}'
        #                 ospf_network_list += f"  network {ip} area 0.0.0.0\n"

        #             except ValueError as e:
        #                 print(e)
        # # ------------------------------------------------

        # # enable proxy arp for only host interface
        # self.cmd(f"echo 1 > /proc/sys/net/ipv4/conf/{self.host_intf_name}/proxy_arp")

        
        ospf_config = 'enable\n'
        ospf_config += 'configure terminal\n'
        ospf_config += 'fpm address 127.0.0.1 port 2620\n'
        ospf_config += '!\n'
        ospf_config += f'interface {self.p4rt_intf_name}\n'
        ospf_config += '  ip ospf passive\n'
        ospf_config += '!\n'
        ospf_config += f'interface {self.host_intf_name}\n'
        ospf_config += '  ip ospf passive\n'
        ospf_config += '!\n'
        ospf_config += 'router ospf\n'
        ospf_config += '  router-info area 0.0.0.0\n'
        # ------------------------------------------------
        ospf_config += '  maximum-paths 1\n'
        # ------------------------------------------------
        ospf_config += ospf_network_list
        ospf_config += '!\n'

        
        print(f"{self.name}: vtysh ospf conf")
        self.vtysh_cmd(ospf_config)


    def _check_switch_link(self):
        switch_links = 0
        for intf in self.link_ip_addrs:
            if intf != 'lo' and intf[0:len("p4rt_")] != "p4rt_":
                switch_links += 1

        for intf in self.p4_switch.intfNames():
            if intf != 'lo':
                switch_links -= 1

        return switch_links == 0


    def set_switch_links(self) -> bool:
        """
        Called by P4SimpleSwitch.reflect_switch_links().
        At this point, the P4 switch has all the links except for dummy and p4runtime link.
        """

        if not self._check_switch_link():
            print(f"{self.name} links: {self._check_switch_link()}")
            return False

        try:
            switch_index = int(self.p4_switch.name[1:])
        except ValueError as e:
            print(e)
            return False
        
        sw_intfs = {}    
        for intf_i, intf in enumerate(self.p4_switch.intfNames()):
            if intf != 'lo':
                link_intf = self.p4_switch.intfs[intf_i].link.intf2 \
                    if self.p4_switch.intfs[intf_i].link.intf1.node.name == self.p4_switch.name \
                        else self.p4_switch.intfs[intf_i].link.intf1
                
                link_node_name = link_intf.node.name
                sw_intfs[link_node_name] = {
                    "intf": intf, 
                    "mac": self.p4_switch.MAC(intf), 
                    "link_intf": link_intf, 
                    "link_mac": link_intf.node.MAC(link_intf)
                }

        # dummy link
        for link_node_name, intf_item in sw_intfs.items():
            if link_node_name in self.link_ip_addrs:
                addr_item = self.link_ip_addrs[link_node_name]
                link_args = {}
                # if "bw" in addr_item:
                #     link_args = {"bw": addr_item["bw"]}

                self.net.addLink(self.p4_switch, self, 
                            intfName1=f"dummy_{intf_item.get('intf')}",
                            addr1=intf_item.get("link_mac"),
                            intfName2=f"{self.name}_{intf_item.get('intf')}", 
                            addr2=intf_item.get("mac"),
                            params2={'ip': addr_item.get('ip')},
                            cls=TCLink, **link_args)
                
                if link_node_name[0] == 'h':
                    self.host_intf_name = f"{self.name}_{intf_item.get('intf')}"
                
                # print(f"{self.name}_{intf_item.get('intf')}: {addr_item.get('ip')} | {addr_item.get('bw')}")
                
        # add loopback ip address
        if "ip" in self.link_ip_addrs.get("lo"):
            loopback_ip = self.link_ip_addrs["lo"]["ip"]
            self.cmd(f"ip addr add {loopback_ip} dev lo")
            # self.cmd(f"ifconfig lo {self.link_ip_addrs["lo"]["ip"]}")
                
        # p4runtime link
        self.net.addLink(self.p4_switch, self,
                    intfName1=f"p4rt_{self.p4_switch.name}",
                    intfName2=f"p4rt_{self.name}",
                    params1={"ip": f"192.168.{switch_index}.1/30"},
                    params2={"ip": f"192.168.{switch_index}.2/30"},
                    cls=TCLink)
        
        self.p4rt_intf_name = f"p4rt_{self.name}"
        
        return True


    def run_p4_runtime_shell(self):
        """
        Run after execute vtysh_cmd.
        """

        try:
            switch_index = int(self.name[1:])
        except ValueError as e:
            print(e)
            return
        
        if switch_index == 1:
            sleep(1)

        # self.cmd(f"python3 ./p4runtime/load.py {self.p4_switch.name} > ./log/{self.name}_load.txt")
        # print(f"python3 ./p4runtime/load.py {self.p4_switch.name} > ./log/{self.name}_load.txt")
        # self.cmd(f"python3 ./p4runtime/table.py {self.p4_switch.name} > ./log/{self.name}_table.txt &")
        # print(f"python3 ./p4runtime/table.py {self.p4_switch.name} > ./log/{self.name}_table.txt &")

        self.cmd(f"python3 ./p4runtime/load.py {self.p4_switch.name} > /dev/null")
        print(f"python3 ./p4runtime/load.py {self.p4_switch.name} > /dev/null")
        self.cmd(f"python3 ./p4runtime/table.py {self.p4_switch.name} > /dev/null &")
        print(f"python3 ./p4runtime/table.py {self.p4_switch.name} > /dev/null &")



class P4SimpleSwitch(OVSKernelSwitch):

    def __init__(self, name, **params):
        self.p4_controller = None
        self.is_run_simple_switch = False
        self.p4_config = None
        super().__init__(name, **params)


    def add_P4Controller(
            self, 
            net: Mininet, 
            link_ip_addrs: dict[str: dict[str: Union[int, str]]]) -> P4Controller:

        if self.p4_controller is not None:
            return self.p4_controller
        
        self.p4_controller = net.addHost(
            f"c{self.name[1:]}", 
            cls=P4Controller, 
            net=net, 
            p4_switch=self,
            link_ip_addrs=link_ip_addrs,
            ip=None
        )
        return self.p4_controller
    

    def reflect_switch_links(self) -> bool:
        """
        Run after set all P4SimpleSwitch links except for dummy and p4runtime link.
        """
        
        if self.p4_controller is None:
            return False
        
        return self.p4_controller.set_switch_links()


    def run_simple_switch_grpc(self) -> bool:
        """
        Run after execute reflect_switch_links()
        """

        if self.is_run_simple_switch:
            return False
        
        try:
            switch_index = int(self.name[1:])
        except ValueError as e:
            print(e)
            return False
        

        device_id = switch_index
        thrift_port = 9000 + switch_index - 1
        log_file = f"./log/{self.name}"
        # grpc_addr = f"192.168.{switch_index}.1:{9559 + switch_index - 1}"
        grpc_addr = f"192.168.{switch_index}.1:9559"

        cmd = "sudo simple_switch_grpc "

        intfs = {}

        for intf_i, intf in enumerate(self.intfNames()):
            if intf != 'lo' and intf[0:len("p4rt_")] != "p4rt_":
                intfs[intf] = intf_i
                cmd += f"-i {intf_i}@{intf} "

        self.p4_config = {
            "sw_id": switch_index,
            "device_id": device_id,
            "thrift_port": thrift_port,
            "log_file": log_file,
            "grpc_addr": grpc_addr,
            "intfs": intfs  
        }
        
        cmd += f" --device-id {device_id} --thrift-port {thrift_port} --log-file {log_file} --no-p4 -- --grpc-server-addr {grpc_addr} &"

        self.cmd(cmd)
        print(f"{self.name}: {cmd}")
        
        return True
