import subprocess
import os
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import output, error
import sys
import time
from multiprocessing import Process
from time import sleep
from lib import json

def set_mtu(net: Mininet):
    "Set mtu for all links"
    
    hosts_mtu = 9500
    # Trick to allow switches to add headers
    # when packets have the max MTU
    switches_mtu = 9520
    for link in net.links:

        cmd1 = "/sbin/ethtool -k {0} rx off tx off sg off"
        # cmd2 = "sysctl net.ipv6.conf.{0}.disable_ipv6=1"
        cmd3 = "ip link set {} mtu {}"

        #execute the ethtool command to remove some offloads
        link.intf1.cmd(cmd1.format(link.intf1.name))
        link.intf2.cmd(cmd1.format(link.intf2.name))

        #increase mtu to 9500 (jumbo frames) for switches we do it special
        node1_is_host = link.intf1.node in net.hosts and link.intf1.node.name[0] == "h"
        node2_is_host = link.intf2.node in net.hosts and link.intf2.node.name[0] == "h"

        if node1_is_host or node2_is_host:
            mtu = hosts_mtu
        else:
            mtu = switches_mtu

        link.intf1.cmd(cmd3.format(link.intf1.name, mtu))
        link.intf2.cmd(cmd3.format(link.intf2.name, mtu))


def get_switch_ip_list_path():
    check_str = "_network.py"
    name = ""
    for i in range(len(sys.argv)):
        if len(sys.argv[i]) > len(check_str) and \
            sys.argv[i][-len(check_str):] == check_str:
            
            name = sys.argv[i][:-len(check_str)]
            break
    
    switch_ip_list_path = f"{name}_switch_ip_list.json"
    return switch_ip_list_path


def check_has_link(src_idx, dst_idx):
    
    switch_ip_list_path = get_switch_ip_list_path()
    try:
        switch_ip_list = json.load_switch_ip_list(switch_ip_list_path)

        if f"s{src_idx}" in switch_ip_list and \
            f"s{dst_idx}" in switch_ip_list[f"s{src_idx}"]:
            output(f"Link found between s{src_idx} and s{dst_idx}\n")
            return True
        
        return False

    except:
        error(f"switch_ip_list.json not found\n")
        return False


def trace2( net: Mininet, line):
    "Trace packets"

    args = line.split()
    str_c = ""
    str_f = ""
    str_mri = ""
    str_mri_limit_hop = ""
    total = len(net.switches)
    total_check = 0
    restart_idx = 1

    for i in range(len(args)):
        if args[i] == '-c':
            str_c = args[i+1]
        
        if args[i] == '-f':
            str_f = get_switch_ip_list_path()
        
        if args[i] == '-mri':
            str_mri = args[i]
        
        if  args[i] == '-lh':
            str_mri_limit_hop = "-lh"

        if args[i] == '-t':
            total = int(args[i+1]) if args[i+1].isdecimal() else len(net.switches)
        
        if args[i] == '-r':
            restart_idx = int(args[i+1]) if args[i+1].isdecimal() else 1

    limit = total

    for host in net.hosts:
        if host.name[0] == "h":
            if limit == 0:
                break
            else:
                limit = limit - 1

            if restart_idx > 1:
                restart_idx = restart_idx - 1
                continue

            output(f"trace on {host.name} {str_mri} | {limit} nodes remaining\n")
            
            skip_idx = int(host.name[1:])

            for switch in net.switches:
                if switch.name[0] == "s" and \
                    switch.name[1:] == host.name[1:]:
                    continue

                elif switch.name[0] == "s":
                    idx = int(switch.name[1:])
                    if idx < skip_idx:
                        continue

                    if check_has_link(skip_idx, idx):
                        continue

                    total_check = total_check + 1
                    str_d = switch.name[1:]
                    cmd_str = f"python3 send.py -c {str_c} -d {str_d} -f {str_f} {str_mri} {str_mri_limit_hop}"
                    host.cmd(cmd_str)
                    sleep(0.5)
                    output(f"h{str_d} |")

            output(f"\n")

    output(f"Total checks: {total_check}\n")


def subprocess_host_exec_cmd(host, cmd_str):
    host.cmd(cmd_str)


def send_trace(net: Mininet, host, cmd_str, str_d):
    p = Process(target=subprocess_host_exec_cmd, args=(host, cmd_str,))
    p.start()

    TIMEOUT = 20
    start = time.time()
    while time.time() - start <= TIMEOUT:
        if not p.is_alive():
            output(f"h{str_d} |")
            sleep(0.5)
            break
    else:
        output(f"Timeout on {host.name}->{str_d}\n")
        p.terminate()
        p.join()
        stop_listen_mri_trace(net, f"-h {str_d}")
        sleep(1.5)
        relisten_mri_trace(net, f"-h {str_d}")
        sleep(2)
        # host.cmd(f"python3 kill_send.py")
        # Process(target=host.cmd, args=(f"python3 kill_send.py",)).start()
        result = subprocess.run(['python3', 'kill_send.py'], capture_output=True, text=True)
        output(f"{result}\n")
        
        return False

    return True


def trace(net: Mininet, line):
    "Trace packets"

    args = line.split()
    str_c = ""
    str_f = ""
    str_mri = ""
    str_mri_limit_hop = ""
    total = len(net.switches)
    total_check = 0
    restart_idx = 1

    for i in range(len(args)):
        if args[i] == '-c':
            str_c = args[i+1]
        
        if args[i] == '-f':
            str_f = get_switch_ip_list_path()
        
        if args[i] == '-mri':
            str_mri = args[i]
        
        if  args[i] == '-lh':
            str_mri_limit_hop = "-lh"

        if args[i] == '-t':
            total = int(args[i+1]) if args[i+1].isdecimal() else len(net.switches)
        
        if args[i] == '-r':
            restart_idx = int(args[i+1]) if args[i+1].isdecimal() else 1

    limit = total

    for host in net.hosts:
        if host.name[0] == "h":
            if limit == 0:
                break
            else:
                limit = limit - 1

            if restart_idx > 1:
                restart_idx = restart_idx - 1
                continue

            output(f"trace on {host.name} {str_mri} | {limit} nodes remaining\n")
            
            skip_idx = int(host.name[1:])

            for switch in net.switches:
                if switch.name[0] == "s" and \
                    switch.name[1:] == host.name[1:]:
                    continue

                elif switch.name[0] == "s":
                    idx = int(switch.name[1:])
                    if idx < skip_idx:
                        continue

                    if check_has_link(skip_idx, idx):
                        continue

                    total_check = total_check + 1
                    str_d = switch.name[1:]
                    cmd_str = f"python3 send.py -c {str_c} -d {str_d} -f {str_f} {str_mri} {str_mri_limit_hop}"

                    count = 0
                    result = send_trace(net, host, cmd_str, str_d)
                    while result == False:
                        count = count + 1
                        output(f"Retry {count} on {host.name} -> {str_d}\n")
                        result = send_trace(net, host, cmd_str, str_d)

                    # p = Process(target=subprocess_host_exec_cmd, args=(host, cmd_str,))
                    # p.start()

                    # TIMEOUT = 20
                    # start = time.time()
                    # while time.time() - start <= TIMEOUT:
                    #     if not p.is_alive():
                    #         output(f"h{str_d} |")
                    #         break
                    # else:
                    #     output(f"Timeout on {host.name} {str_d}\n")
                    #     p.terminate()
                    #     p.join()
                    #     stop_listen_mri_trace(net, f"-h {str_d}")
                    #     sleep(1.5)
                    #     relisten_mri_trace(net, f"-h {str_d}")
                    #     sleep(1.5)
                    #     host.cmd(cmd_str)
                    #     output(f"h{str_d} |")

                    # sleep(0.5)
                    

            output(f"\n")

    output(f"Total checks: {total_check}\n")


def trace_load_test(net: Mininet, line):
    "Trace packets"

    args = line.split()
    str_c = ""
    str_f = ""
    str_mri = ""
    str_mri_limit_hop = ""
    total = len(net.switches)
    total_check = 0
    restart_idx = 1

    for i in range(len(args)):
        if args[i] == '-c':
            str_c = args[i+1]
        
        if args[i] == '-f':
            str_f = get_switch_ip_list_path()
        
        if args[i] == '-mri':
            str_mri = args[i]
        
        if  args[i] == '-lh':
            str_mri_limit_hop = "-lh"

        if args[i] == '-t':
            total = int(args[i+1]) if args[i+1].isdecimal() else len(net.switches)
        
        if args[i] == '-r':
            restart_idx = int(args[i+1]) if args[i+1].isdecimal() else 1

    limit = total

    dst_switches = -1
    for i in range(len(net.switches)):
        if net.switches[i].name[0] == "s":
            dst_switches += 1

    for host in net.hosts:
        if host.name[0] == "h":
            if limit == 0:
                break
            else:
                limit = limit - 1

            if restart_idx > 1:
                restart_idx = restart_idx - 1
                continue

            output(f"trace on {host.name} {str_mri} | {limit} nodes remaining\n")
            
            skip_idx = int(host.name[1:])

            for switch in net.switches:
                if switch.name[0] == "s" and \
                    switch.name[1:] == host.name[1:]:
                    continue

                elif switch.name[0] == "s":
                    idx = int(switch.name[1:])
                    if idx < skip_idx:
                        continue

                    # if check_has_link(skip_idx, idx):
                    #     continue


                    total_check = total_check + 1
                    str_d = switch.name[1:]
                    env_str = f"RESULT_JSON_FILE=result_load_test_{dst_switches}.json"
                    cmd_str = f"{env_str} python3 send.py -c {str_c} -d {str_d} -f {str_f} {str_mri} {str_mri_limit_hop}"

                    count = 0
                    result = send_trace(net, host, cmd_str, str_d)
                    while result == False:
                        count = count + 1
                        output(f"Retry {count} on {host.name} -> {str_d}\n")
                        result = send_trace(net, host, cmd_str, str_d)
                    

            output(f"\n")

    output(f"Total checks: {total_check}\n")


def listen_mri_trace(net: Mininet):
    "Listen for mri and trace packets"
    
    for host in net.hosts:
        if host.name[0] == "h":
            host.cmd(f"python3 recieve.py {host.name} &")
            output(f"Listening on {host.name}\n")

def relisten_mri_trace(net: Mininet, line):
    "Listen for mri and trace packets again"

    args = line.split()
    host_idx = -1

    for i in range(len(args)):
        
        if args[i] == '-h' and args[i+1].isdecimal():
            host_idx = int(args[i+1])

    if host_idx == -1:
        output(f"Please provide host index\n")
        return
    
    for host in net.hosts:
        if host.name[0] == "h" and host.name[1:] == str(host_idx):
            host.cmd(f"python3 recieve.py {host.name} &")
            output(f"Relistening on {host.name}\n")
            return
        
    output(f"Host not found\n")


def stop_listen_mri_trace(net: Mininet, line):
    "Stop listening for mri and trace packets"

    args = line.split()
    host_idx = -1

    for i in range(len(args)):
        
        if args[i] == '-h' and args[i+1].isdecimal():
            host_idx = int(args[i+1])

    if host_idx == -1:
        output(f"Please provide host index\n")
        return
    
    for host in net.hosts:
        if host.name[0] == "h" and host.name[1:] == str(host_idx):
            host.cmd(f"python3 kill_recieve.py -h {host.name[1:]}")
            output(f"Killed listening on {host.name}\n")
            return

    output(f"Host not found\n")


def test(net: Mininet, line):
    
    args = line.split()
    count = 10
    init_count = 2
    t_str =""

    for i in range(len(args)):
        
        if args[i] == '-c' and args[i+1].isdecimal():
            count = int(args[i+1])
        
        if args[i] == '-i' and args[i+1].isdecimal():
            init_count = int(args[i+1])
        
        if args[i] == '-t':
            total = int(args[i+1]) if args[i+1].isdecimal() else len(net.switches)
            t_str = f"-t {total}"


    set_mtu(net)
    # listen_mri_trace(net)
    output(f"---------init count:{init_count}---------\n")
    trace(net, f"-c {init_count} -f {t_str}")

    output(f"---------trace count:{count}---------\n")
    trace(net, f"-c {count} -f {t_str}")
    
    output(f"---------mri count:{count}---------\n")
    trace(net, f"-c {count} -f {t_str} -mri -lh")


def load_test(net: Mininet, line):

    args = line.split()
    count = 10
    init_count = 2
    t_str =""

    for i in range(len(args)):
        
        if args[i] == '-c' and args[i+1].isdecimal():
            count = int(args[i+1])
        
        if args[i] == '-i' and args[i+1].isdecimal():
            init_count = int(args[i+1])
        
        if args[i] == '-t':
            total = int(args[i+1]) if args[i+1].isdecimal() else len(net.switches)
            t_str = f"-t {total}"


    set_mtu(net)
    # listen_mri_trace(net)
    output(f"---------init count:{init_count}---------\n")
    trace_load_test(net, f"-c {init_count} -f {t_str}")

    output(f"---------trace count:{count}---------\n")
    trace_load_test(net, f"-c {count} -f {t_str}")
    
    output(f"---------mri count:{count}---------\n")
    trace_load_test(net, f"-c {count} -f {t_str} -mri -lh")


def mri(net: Mininet, line):
    
    args = line.split()
    count = 10
    t_str =""

    for i in range(len(args)):
        
        if args[i] == '-c' and args[i+1].isdecimal():
            count = int(args[i+1])

        
        if args[i] == '-t':
            total = int(args[i+1]) if args[i+1].isdecimal() else len(net.switches)
            t_str = f"-t {total}"


    set_mtu(net)
    
    output(f"---------mri count:{count}---------\n")
    trace(net, f"-c {count} -f {t_str} -mri -lh")


class P4CLI(CLI):

    def do_mtu(self, line):
        "Set mtu for all links"
        set_mtu(self.mn)

    def do_listen(self, line):
        "Listen for mri and trace packets"
        listen_mri_trace(self.mn)

    def do_relisten(self, line):
        "Listen for mri and trace packets again"
        relisten_mri_trace(self.mn, line)

    def do_stoplisten(self, line):
        "Stop listening for mri and trace packets"
        stop_listen_mri_trace(self.mn, line)

    def do_trace( self, line):
        "Trace packets"
        trace(self.mn, line)

    def do_trace2( self, line):
        "Trace packets"
        trace2(self.mn, line)

    def do_test(self, line):
        "Test"
        test(self.mn, line)

    def do_mri(self, line):
        "mri"
        mri(self.mn, line)

    def do_loadtest(self, line):
        "Load test"
        load_test(self.mn, line)
        
