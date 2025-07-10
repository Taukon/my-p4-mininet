import os
import subprocess
import sys

def trace(send_count, dst_idx, dst_switches):
    
    env = os.environ.copy()
    env["RESULT_JSON_FILE"] = f"result_load_test_{dst_switches}.json"

    result = subprocess.run([\
    "python3", "load_test_explore_send.py", \
    "-f", "load_test_switch_ip_list.json", \
    "-c", str(send_count), \
    "-d", str(dst_idx), \
        ], capture_output=True, text=True, check=True, env=env).stdout

    print(result)
    print("----- Done Trace -----")

def mri(send_count, dst_idx, dst_switches):

    env = os.environ.copy()
    env["RESULT_JSON_FILE"] = f"result_load_test_{dst_switches}.json"

    result = subprocess.run([\
    "python3", "load_test_explore_send.py", \
    "-f", "load_test_switch_ip_list.json", \
    "-c", str(send_count), \
    "-d", str(dst_idx), \
    "-mri"], capture_output=True, text=True, check=True, env=env).stdout

    print(result)
    print("----- Done MRI -----")


# h1 python3 explore_test.py -c 32 -s 5
if __name__ == '__main__':
    send_count = 1
    dst_switches = 1

    for i in range(len(sys.argv)):
        if sys.argv[i] == '-c':
            send_count = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

        if sys.argv[i] == '-s':
            dst_switches = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

    for i in range(1, dst_switches + 1):
        dst_idx = i + 1
        print(f"Sending trace and mri for dst_idx: {dst_idx} with send_count: {send_count} on {dst_switches} switches")
        trace(send_count, dst_idx, dst_switches)
        mri(send_count, dst_idx, dst_switches)