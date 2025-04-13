import os
import subprocess
from sys import argv

def run_load_test(total_host, enable_auto):
    # Run the load test
    os.chdir("./load_test_env_conf")
    subprocess.run(f"python3 load_test_conf.py --h {total_host}", shell=True)

    os.chdir("..")
    subprocess.run(f"python3 load-test-mininet.py --ssh{' --auto' if enable_auto else ''}", shell=True)

    os.chdir("./p4mininet")
    subprocess.run("sudo python3 load_test_network.py", shell=True)
 

if __name__ == "__main__":
    total_host = 0
    enable_auto = False

    for i in range(len(argv)):
        if argv[i] == '--auto':
            enable_auto = True

        if argv[i] == '--h' and enable_auto == False:
            total_host = int(argv[i+1]) if argv[i+1].isdecimal() else 0

    if total_host == 0 and enable_auto == False:
        print("Please provide the number of hosts using --h <number> or use --auto for automatic configuration.")
        exit(1)

    if enable_auto:
        print("Running in automatic mode.")

        list_host = [1, 5, 10, 15, 20, 25, 30, 35]
        for i in list_host:
            print(f"Running load test for host {i}")
            run_load_test(i, enable_auto)
            os.chdir("..")
            print(f"Load test for host {i} completed.")
    
    else:
        print(f"Running load test for {total_host} hosts.")
        run_load_test(total_host, enable_auto)
        print(f"Load test for {total_host} hosts completed.")
