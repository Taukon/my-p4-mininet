import re
import subprocess
import sys
from utils.json import write_result_load_test_delta


def run_ping_test(count, dst_idx, flow_label):

    dst_idx_hex = hex(dst_idx)[2:]
    dst_addr = f'fc00::1:{dst_idx_hex}:2:0:0'

    # Run the ping test
    result = subprocess.run(["ping", "-6", "-c", f"{count}", f"{dst_addr}", "-F", f"{flow_label}"], capture_output=True, text=True, check=True).stdout

    time_values = []
    for line in result.splitlines():
        match = re.search(r'time=([0-9.]+) ms', line)
        if match:
            time_values.append(float(match.group(1)))
    
    
    # print(time_values)

    is_mri = True if flow_label == "0xfffff" else False
    delta = sum(time_values) / len(time_values)
    write_result_load_test_delta(is_mri, dst_idx, delta, len(time_values), time_values[-1], time_values)

    return len(time_values)


if __name__ == '__main__':

    send_count = 1
    dst_idx = 2
    flow_label = "0xffff0"

    for i in range(len(sys.argv)):

        if sys.argv[i] == '-c':
            send_count = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

        if sys.argv[i] == '-d':
            dst_idx = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 2

        if sys.argv[i] == '-mri':
            flow_label = "0xfffff"

    total = run_ping_test(send_count, dst_idx, flow_label)
    # print(f"Ping test for {send_count} packets to {dst_idx} with flow label {flow_label} completed.")
    # print("----- Done -----")
    print(f"total: {total}")