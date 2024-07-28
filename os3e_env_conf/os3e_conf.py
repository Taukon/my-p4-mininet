import subprocess
import json

def write_json_link():
    """
    Write link.json
    """
    link = []
    txt_cmd=["cat", "./os3e_link.txt"]
    proc = subprocess.Popen(txt_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (txt_cache, txt_err) = proc.communicate()
    txt_entries = txt_cache.decode().split("\n")
    for entry in txt_entries.copy():
        if not entry.startswith("#from"):
            if len(entry) > 0:
                from_ = entry.split()[0]
                to_ = entry.split()[1]
                capacity_ = entry.split()[2]
                metric_ = entry.split()[3]
                delay_ = entry.split()[4]
                queue_ = entry.split()[5]

                capacity_ = int(capacity_[:len(capacity_)-len("Gbps")])
                metric_ = int(metric_)
                delay_ = float(delay_[:len(delay_)-len("s")])
                queue_ = int(queue_)

                link.append({
                    "from": from_, 
                    "to": to_, 
                    "capacity": capacity_, 
                    "metric": metric_, 
                    "delay": delay_, 
                    "queue": queue_
                })
    with open('os3e_link.json', 'w') as f:
        json.dump(link, f,  ensure_ascii=False, indent=4)

def write_json_latlong():
    """
    Write latlong.json
    """
    latlong = []
    txt_cmd=["cat", "./os3e_latlong.txt"]
    proc = subprocess.Popen(txt_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (txt_cache, txt_err) = proc.communicate()
    txt_entries = txt_cache.decode().split("\n")
    for entry in txt_entries.copy():
        if not entry.startswith("#node"):
            if len(entry) > 0:
                node_ = entry.split()[0]
                longitude_ = entry.split()[1]
                latitude_ = entry.split()[2]

                longitude_ = float(longitude_)
                latitude_ = float(latitude_)

                latlong.append({
                    "node": node_, 
                    "latitude": longitude_,
                    "longitude": latitude_
                })

    with open('os3e_latlong.json', 'w') as f:
        json.dump(latlong, f,  ensure_ascii=False, indent=4)

write_json_link()
write_json_latlong()
