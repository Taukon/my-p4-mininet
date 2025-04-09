import os
import subprocess
from sys import argv
 

if __name__ == "__main__":
    total_host = 0
    for i in range(len(argv)):
        if argv[i] == '--h':
            total_host = int(argv[i+1]) if argv[i+1].isdecimal() else 0

    if total_host == 0:
        print("Please provide the number of hosts using --h <number>")
        exit(1)


    os.chdir("./load_test_env_conf")
    subprocess.run(f"python3 load_test_conf.py --h {total_host}", shell=True)


    os.chdir("..")
    subprocess.run("python3 load-test-mininet.py --ssh", shell=True)


    os.chdir("./p4mininet")
    subprocess.run("sudo python3 load_test_network.py", shell=True)