from utils.json import *

total, same_path_total, fast_route_mri_total = write_compare_result()

print(f"same_path_total: {same_path_total}/{total} | fast_route_mri_total: {fast_route_mri_total}/{total-same_path_total}")