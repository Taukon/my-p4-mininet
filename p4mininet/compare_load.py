import json
import os
import statistics

def check_max_min_delta(file_path):
    with open(file_path, mode="rt", encoding="utf-8") as fr:
        result = json.load(fr)

    total = 0
    trace_mean_list = []
    trace_median_list = []
    mri_mean_list = []
    mri_median_list = []

    for k, v in result.items():
        if k != "s1":
            break
        # print(f"src_sw: {k}")

        for k2, v2 in v.items():
            # print(f"dst_sw: {k2} | {total+1}")

            if v2.get("trace") is None or v2.get("mri") is None:
                print(f"trace or mri is not found in {k}")
            
            elif v2["trace"].get("list_delta") is not None \
                and v2["mri"].get("list_delta") is not None:
                
                total = total + 1

                trace = v2["trace"]
                mri = v2["mri"]

                if  trace.get("delta") is None or mri.get("delta") is None:
                    print(f"trace or mri 'delta' is not found in {k}-{k2} | hoplen: {len(trace['city_list'])}:{len(mri['city_list'])}")
                    continue

                trace_list = sorted(trace["list_delta"])
                trace_list.pop(0)
                trace_list.pop(-1)
                mri_list = sorted(mri["list_delta"])
                mri_list.pop(0)
                mri_list.pop(-1)

                trace_mean = sum(trace_list) / len(trace_list)
                trace_median = statistics.median(trace_list)
                mri_mean = sum(mri_list) / len(mri_list)
                mri_median = statistics.median(mri_list)

                trace_mean_list.append(trace_mean)
                trace_median_list.append(trace_median)
                mri_mean_list.append(mri_mean)
                mri_median_list.append(mri_median)

    fr.close()

    # trace_mean_list.sort()
    # trace_median_list.sort()
    # mri_mean_list.sort()
    # mri_median_list.sort()
    
    trace_items = {
        "mean": {
            "min": min(trace_mean_list),
            "max": max(trace_mean_list),
            "min_index": trace_mean_list.index(min(trace_mean_list)) + 2,
            "max_index": trace_mean_list.index(max(trace_mean_list)) + 2,
        },
        "median": {
            "min": min(trace_median_list),
            "max": max(trace_median_list),
            "min_index": trace_median_list.index(min(trace_median_list)) + 2,
            "max_index": trace_median_list.index(max(trace_median_list)) + 2,
        }
    }

    mri_items = {
        "mean": {
            "min": min(mri_mean_list),
            "max": max(mri_mean_list),
            "min_index": mri_mean_list.index(min(mri_mean_list)) + 2,
            "max_index": mri_mean_list.index(max(mri_mean_list)) + 2,
        },
        "median": {
            "min": min(mri_median_list),
            "max": max(mri_median_list),
            "min_index": mri_median_list.index(min(mri_median_list)) + 2,
            "max_index": mri_median_list.index(max(mri_median_list)) + 2,
        }
    }

    return trace_items, mri_items



def write_compare_result(file_path):
    with open(file_path, mode="rt", encoding="utf-8") as fr:
        result = json.load(fr)

    total = 0
    total_delta_trace = 0
    total_median_delta_trace = 0
    total_delta_mri = 0
    total_median_delta_mri = 0

    for k, v in result.items():
        if k != "s1":
            break
        # print(f"src_sw: {k}")

        for k2, v2 in v.items():
            # print(f"dst_sw: {k2} | {total+1}")

            if v2.get("trace") is None or v2.get("mri") is None:
                print(f"trace or mri is not found in {k}")
            
            elif v2["trace"].get("list_delta") is not None \
                and v2["mri"].get("list_delta") is not None:
                
                total = total + 1

                trace = v2["trace"]
                mri = v2["mri"]

                if  trace.get("delta") is None or mri.get("delta") is None:
                    print(f"trace or mri 'delta' is not found in {k}-{k2} | hoplen: {len(trace['city_list'])}:{len(mri['city_list'])}")
                    continue

                # total_delta_trace += trace["delta"]
                # total_median_delta_trace += trace["median_delta"]
                # total_delta_mri += mri["delta"]
                # total_median_delta_mri += mri["median_delta"]

                trace_list = sorted(trace["list_delta"])
                trace_list.pop(0)
                trace_list.pop(-1)
                mri_list = sorted(mri["list_delta"])
                mri_list.pop(0)
                mri_list.pop(-1)

                # print(f"trace: {len(trace_list)} | mri: {len(mri_list)}")

                total_delta_trace += sum(trace_list) / len(trace_list)
                total_median_delta_trace += statistics.median(trace_list)
                total_delta_mri += sum(mri_list) / len(mri_list)
                total_median_delta_mri += statistics.median(mri_list)

    fr.close()

    return total, total_delta_trace, total_median_delta_trace, total_delta_mri, total_median_delta_mri


list_host = [1, 5, 10, 15, 20, 25, 30]

def compare_load_test():
    mri_avg = []
    mri_median = []
    trace_avg = []
    trace_median = []

    for i in list_host:
        file_path = os.getenv('RESULT_JSON_FILE', f'result_load_test_{i}.json')
        rename_path = os.getenv('RESULT_JSON_FILE', f'result_load_test_{i}.json')

        # print(f"---------------load_test_{i}---------------")
        # total, total_delta_trace, total_median_delta_trace, total_delta_mri, total_median_delta_mri = write_compare_result(file_path)
        # print(f"             total: {total}")
        # print(f"         delta_mri: {total_delta_mri/total}")
        # print(f"  median_delta_mri: {total_median_delta_mri/total}")
        # print(f"       delta_trace: {total_delta_trace/total}")
        # print(f"median_delta_trace: {total_median_delta_trace/total}")
        
        print(f"=================File: {file_path}=================")
        total, total_delta_trace, total_median_delta_trace, total_delta_mri, total_median_delta_mri = write_compare_result(file_path)
        print(f" スイッチの接続数: {total}")
        print(f"----------------------------------------")
        mri_mean = total_delta_mri/total
        trace_mean = total_delta_trace/total
        print(f"提案手法　 平均値: {mri_mean}ms")
        print(f"単純ホップ 平均値: {trace_mean}ms")
        print(f"　　　　差 平均値: {(mri_mean - trace_mean)}ms")
        print(f"----------------------------------------")
        mri_median_mean = total_median_delta_mri/total
        trace_median_mean = total_median_delta_trace/total
        print(f"提案手法　 中央値: {mri_median_mean}ms")
        print(f"単純ホップ 中央値: {trace_median_mean}ms")
        print(f"　　　　差 中央値: {(mri_median_mean - trace_median_mean)}ms")

        mri_avg.append(mri_mean)
        mri_median.append(mri_median_mean)
        trace_avg.append(trace_mean)
        trace_median.append(trace_median_mean)

        os.rename(file_path, rename_path) 

    print("========================================")
    print(f"switch_counts = {list_host}")
    print(f"proposed_avg = {mri_avg}")
    print(f"simple_avg = {trace_avg}")
    print(f"proposed_median = {mri_median}")
    print(f"simple_median = {trace_median}")


def compare_each_max_min_time():

    trace_mean_max_list = []
    trace_mean_min_list = []
    trace_median_max_list = []
    trace_median_min_list = []
    mri_mean_max_list = []
    mri_mean_min_list = []
    mri_median_max_list = []
    mri_median_min_list = []

    trace_mean_max_idx_list = []
    trace_mean_min_idx_list = []
    trace_median_max_idx_list = []
    trace_median_min_idx_list = []
    mri_mean_max_idx_list = []
    mri_mean_min_idx_list = []
    mri_median_max_idx_list = []
    mri_median_min_idx_list = []

    for i in list_host:
        file_path = os.getenv('RESULT_JSON_FILE', f'result_load_test_{i}.json')
        
        print(f"=================File: {file_path}=================")
        trace_items, mri_items = check_max_min_delta(file_path)
        trace_mean_max_list.append(trace_items["mean"]["max"])
        trace_mean_min_list.append(trace_items["mean"]["min"])
        trace_median_max_list.append(trace_items["median"]["max"])
        trace_median_min_list.append(trace_items["median"]["min"])
        mri_mean_max_list.append(mri_items["mean"]["max"])
        mri_mean_min_list.append(mri_items["mean"]["min"])
        mri_median_max_list.append(mri_items["median"]["max"])
        mri_median_min_list.append(mri_items["median"]["min"])

        trace_mean_max_idx_list.append(trace_items["mean"]["max_index"])
        trace_mean_min_idx_list.append(trace_items["mean"]["min_index"])
        trace_median_max_idx_list.append(trace_items["median"]["max_index"])
        trace_median_min_idx_list.append(trace_items["median"]["min_index"])
        mri_mean_max_idx_list.append(mri_items["mean"]["max_index"])
        mri_mean_min_idx_list.append(mri_items["mean"]["min_index"])
        mri_median_max_idx_list.append(mri_items["median"]["max_index"])
        mri_median_min_idx_list.append(mri_items["median"]["min_index"])


    print("========================================")
    print(f"switch_counts = {list_host}")

    print(f"trace_mean_max = {trace_mean_max_list}")
    print(f"trace_mean_max_idx = {trace_mean_max_idx_list}")
    print(f"trace_mean_min = {trace_mean_min_list}")
    print(f"trace_mean_min_idx = {trace_mean_min_idx_list}")
    print(f"")

    print(f"trace_median_max = {trace_median_max_list}")
    print(f"trace_median_max_idx = {trace_median_max_idx_list}")
    print(f"trace_median_min = {trace_median_min_list}")
    print(f"trace_median_min_idx = {trace_median_min_idx_list}")
    print(f"")

    print(f"mri_mean_max = {mri_mean_max_list}")
    print(f"mri_mean_max_idx = {mri_mean_max_idx_list}")
    print(f"mri_mean_min = {mri_mean_min_list}")
    print(f"mri_mean_min_idx = {mri_mean_min_idx_list}")
    print(f"")

    print(f"mri_median_max = {mri_median_max_list}")
    print(f"mri_median_max_idx = {mri_median_max_idx_list}")
    print(f"mri_median_min = {mri_median_min_list}")
    print(f"mri_median_min_idx = {mri_median_min_idx_list}")

compare_load_test()
# compare_each_max_min_time()