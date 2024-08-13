import json
import os
from utils.net import get_defalt_ifname

file_path = "result.json"

def write_result_city_list(is_seg6, dst_idx, city_list: list):

    src_idx = get_defalt_ifname().split("-")[0][1:]
    src_sw = f"s{src_idx}"
    dst_sw = f"s{dst_idx}"

    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump({}, f, ensure_ascii=False, indent=4)
            f.close()

    with open(file_path, mode="rt", encoding="utf-8") as fr:
        result = json.load(fr)

    if result.get(src_sw) is None:
        print(f"src_sw: {src_sw} is not found")
        result[src_sw] = {}

    if result[src_sw].get(dst_sw) is None:
        print(f"dst_sw: {dst_sw} is not found")
        result[src_sw][dst_sw] = {
            "trace": {},
            "mri": {}
        }
    
    if is_seg6:
        tmp_mri = result[src_sw][dst_sw]["mri"]
        result[src_sw][dst_sw]["mri"] = tmp_mri | {
            "hop_len": len(city_list),
            "city_list": city_list
        }

    else:
        tmp_trace = result[src_sw][dst_sw]["trace"]
        result[src_sw][dst_sw]["trace"] = tmp_trace | {
            "hop_len": len(city_list),
            "city_list": city_list
        }

    with open(file_path, mode="wt", encoding="utf-8") as fw:
        json.dump(result, fw, ensure_ascii=False, indent=4)

    fr.close()
    fw.close()


def  write_result_delta(is_seg6, dst_idx, delta, count, last_delta):

    src_idx = get_defalt_ifname().split("-")[0][1:]
    src_sw = f"s{src_idx}"
    dst_sw = f"s{dst_idx}"

    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump({}, f, ensure_ascii=False, indent=4)
            f.close()

    with open(file_path, mode="rt", encoding="utf-8") as fr:
        result = json.load(fr)

    if result.get(src_sw) is None:
        print(f"src_sw: {src_sw} is not found")
        result[src_sw] = {}

    if result[src_sw].get(dst_sw) is None:
        print(f"dst_sw: {dst_sw} is not found")
        result[src_sw][dst_sw] = {
            "trace": {},
            "mri": {}
        }
    
    if is_seg6:
        tmp_mri = result[src_sw][dst_sw]["mri"]
        result[src_sw][dst_sw]["mri"] = tmp_mri | {
            "count": count,
            "delta": delta,
            "last_delta": last_delta
        }

    else:
        tmp_trace = result[src_sw][dst_sw]["trace"]
        result[src_sw][dst_sw]["trace"] = tmp_trace | {
            "count": count,
            "delta": delta,
            "last_delta": last_delta
        }

    with open(file_path, mode="wt", encoding="utf-8") as fw:
        json.dump(result, fw, ensure_ascii=False, indent=4)

    fr.close()
    fw.close()


def write_compare_result():
    with open(file_path, mode="rt", encoding="utf-8") as fr:
        result = json.load(fr)

    same_path_total = 0
    fast_route_mri_total = 0
    total = 0

    for k, v in result.items():
        for k2, v2 in v.items():

            if v2.get("trace") is None or v2.get("mri") is None:
                print(f"trace is not found in {k}")
            
            elif v2["trace"].get("city_list") is not None \
                and v2["mri"].get("city_list") is not None:
                
                total = total + 1

                trace = v2["trace"]
                mri = v2["mri"]

                is_same_hop = trace["city_list"] == mri["city_list"]
                fast_route = "trace" if trace["delta"] < mri["delta"] else "mri"
                if trace["delta"] == mri["delta"]:
                    fast_route = "same"
                
                result[k][k2] = v2 | {
                    "compare": {
                        "is_same_hop": is_same_hop,
                        "fast_route": fast_route
                    }
                }

                if is_same_hop:
                    same_path_total = same_path_total + 1
                if fast_route == "mri" and not is_same_hop:
                    fast_route_mri_total = fast_route_mri_total + 1

    with open(file_path, mode="wt", encoding="utf-8") as fw:
        json.dump(result, fw, ensure_ascii=False, indent=4)

    fr.close()
    fw.close()

    return total, same_path_total, fast_route_mri_total


def check_trace_hop_len(dst_idx):
    src_idx = get_defalt_ifname().split("-")[0][1:]
    src_sw = f"s{src_idx}"
    dst_sw = f"s{dst_idx}"

    with open(file_path, mode="rt", encoding="utf-8") as fr:
        result = json.load(fr)

    try:

        if result.get(src_sw) is not None:
            if result[src_sw].get(dst_sw) is not None:
                return result[src_sw][dst_sw]["trace"]["hop_len"]
            
    except:
        print(f"trace is not found in {src_sw}")

    return -1

    fr.close()