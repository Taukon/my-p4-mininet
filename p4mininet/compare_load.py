import json
import os
import statistics

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
            
            elif v2["trace"].get("city_list") is not None \
                and v2["mri"].get("city_list") is not None:
                
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
    print(f"提案手法　 平均値: {mri_mean}s")
    print(f"単純ホップ 平均値: {trace_mean}s")
    print(f"　　　　差 平均値: {(mri_mean - trace_mean) * 1000}ms")
    print(f"----------------------------------------")
    mri_median_mean = total_median_delta_mri/total
    trace_median_mean = total_median_delta_trace/total
    print(f"提案手法　 中央値: {mri_median_mean}s")
    print(f"単純ホップ 中央値: {trace_median_mean}s")
    print(f"　　　　差 中央値: {(mri_median_mean - trace_median_mean) * 1000}ms")

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
