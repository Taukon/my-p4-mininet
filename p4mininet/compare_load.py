import json
import os
import statistics

file_path = os.getenv('RESULT_JSON_FILE', 'result_load_test_1.json')

def write_compare_result():
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
        print(f"src_sw: {k}")

        for k2, v2 in v.items():
            print(f"dst_sw: {k2} | {total+1}")

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

                print(f"trace: {len(trace_list)} | mri: {len(mri_list)}")

                total_delta_trace += sum(trace_list)
                total_median_delta_trace += statistics.median(trace_list)
                total_delta_mri += sum(mri_list)
                total_median_delta_mri += statistics.median(mri_list)

    fr.close()

    return total, total_delta_trace, total_median_delta_trace, total_delta_mri, total_median_delta_mri


total, total_delta_trace, total_median_delta_trace, total_delta_mri, total_median_delta_mri = write_compare_result()

print(f"total: {total}")
print(f"delta_mri: {total_delta_mri/total} | median_delta_mri: {total_median_delta_mri/total}")
print(f"delta_trace: {total_delta_trace/total} | median_delta_trace: {total_median_delta_trace/total}")