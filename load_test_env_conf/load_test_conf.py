import json
from sys import argv

switch_name = "s1"
link_file_name = "load_test_link.json"
latlong_file_name = "load_test_latlong.json"

def write_json_link(total_host):
    """
    Write link.json
    """
    link = []

    for i in range(total_host):

        to_ = "d" + str(i+1)
        capacity_ = 100

        link.append({
            "from": switch_name, 
            "to": to_, 
            "capacity": capacity_
        })
                
    with open(link_file_name, 'w') as f:
        json.dump(link, f,  ensure_ascii=False, indent=4)


def write_json_latlong(total_host):
    """
    Write latlong.json
    """
    latlong = []
    
    latlong.append({
            "node": switch_name,
        })


    for i in range(total_host):

        node_ = "d" + str(i+1)

        latlong.append({
            "node": node_,
        })

    with open(latlong_file_name, 'w') as f:
        json.dump(latlong, f,  ensure_ascii=False, indent=4)


if __name__ == "__main__":
    total_host = 0
    for i in range(len(argv)):
        if argv[i] == '--h':
            total_host = int(argv[i+1]) if argv[i+1].isdecimal() else 0

    if total_host == 0:
        print("Please provide the number of hosts using --h <number>")
        exit(1)

    write_json_link(total_host)
    write_json_latlong(total_host)
    print(f"Link and latlong JSON files have been created with {total_host} hosts.")