import matplotlib.pyplot as plt

# データの抽出
switch_counts = [1, 5, 10, 15, 20, 25, 30]
trace_mean_max = [0.03777127265930176, 0.038753819465637204, 0.039493894577026366, 0.038934731483459474, 0.04094862937927246, 0.042418479919433594, 0.04428286552429199]
trace_mean_max_idx = [2, 6, 9, 4, 8, 17, 25]
trace_mean_min = [0.03777127265930176, 0.03299500942230225, 0.028957319259643555, 0.029507017135620116, 0.031110596656799317, 0.03264005184173584, 0.03238670825958252]
trace_mean_min_idx = [2, 4, 3, 10, 2, 25, 29]

trace_median_max = [0.03921377658843994, 0.03794276714324951, 0.03877758979797363, 0.040610432624816895, 0.041651010513305664, 0.04513239860534668, 0.045285582542419434]
trace_median_max_idx = [2, 3, 9, 4, 8, 17, 25]
trace_median_min = [0.03921377658843994, 0.03159987926483154, 0.029327034950256348, 0.028796792030334473, 0.02933526039123535, 0.029410123825073242, 0.02975773811340332]
trace_median_min_idx = [2, 4, 11, 10, 4, 25, 29]

mri_mean_max = [0.03416759967803955, 0.040006589889526364, 0.04174716472625732, 0.043546009063720706, 0.04549140930175781, 0.04670889377593994, 0.046687960624694824]
mri_mean_max_idx = [2, 2, 9, 7, 18, 19, 11]
mri_mean_min = [0.03416759967803955, 0.03257365226745605, 0.03203308582305908, 0.035641813278198244, 0.03655672073364258, 0.037491369247436526, 0.036160516738891604]
mri_mean_min_idx = [2, 6, 3, 5, 12, 2, 4]

mri_median_max = [0.03358173370361328, 0.038370370864868164, 0.04035294055938721, 0.043478965759277344, 0.045767903327941895, 0.04566240310668945, 0.04645335674285889]
mri_median_max_idx = [2, 2, 9, 7, 18, 19, 11]
mri_median_min = [0.03358173370361328, 0.0326920747756958, 0.029076695442199707, 0.03113710880279541, 0.035239458084106445, 0.037406325340270996, 0.03490877151489258]
mri_median_min_idx = [2, 6, 3, 5, 19, 22, 6]

trace_mean_max_ms = [x * 1000 for x in trace_mean_max]
trace_mean_min_ms = [x * 1000 for x in trace_mean_min]
trace_median_max_ms = [x * 1000 for x in trace_median_max]
trace_median_min_ms = [x * 1000 for x in trace_median_min]
mri_mean_max_ms = [x * 1000 for x in mri_mean_max]
mri_mean_min_ms = [x * 1000 for x in mri_mean_min]
mri_median_max_ms = [x * 1000 for x in mri_median_max]
mri_median_min_ms = [x * 1000 for x in mri_median_min]

# 平均値を表示
plt.figure(figsize=(10, 6))

plt.plot(switch_counts, trace_mean_max_ms, marker='o', label='Simple Hop (Max)')
plt.plot(switch_counts, trace_mean_min_ms, marker='o', label='Simple Hop (Min)')
plt.plot(switch_counts, mri_mean_max_ms, marker='s', label='Proposed Method (Max)')
plt.plot(switch_counts, mri_mean_min_ms, marker='s', label='Proposed Method (Min)')

plt.xlabel('Number of Switch Connections')
plt.ylabel('Time (ms)')
plt.title('Comparison of Average Time by Number of Switch Connections')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()


# 中央値を表示
plt.figure(figsize=(10, 6))

plt.plot(switch_counts, trace_median_max_ms, marker='o', label='Simple Hop (Median Max)')
plt.plot(switch_counts, trace_median_min_ms, marker='o', label='Simple Hop (Median Min)')
plt.plot(switch_counts, mri_median_max_ms, marker='s', label='Proposed Method (Median Max)')
plt.plot(switch_counts, mri_median_min_ms, marker='s', label='Proposed Method (Median Min)')

plt.xlabel('Number of Switch Connections')
plt.ylabel('Time (ms)')
plt.title('Comparison of Median Time by Number of Switch Connections')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()