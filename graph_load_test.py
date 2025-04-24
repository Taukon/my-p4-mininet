import matplotlib.pyplot as plt

# データの抽出
switch_counts = [1, 5, 10, 15, 20, 25, 30]
proposed_avg = [0.03295540809631348, 0.03367409229278564, 0.034839489459991456, 0.037291924158732094, 0.039919266700744624, 0.04124782848358154, 0.04195765813191731]
simple_avg = [0.030119919776916505, 0.034201622009277344, 0.034445543289184574, 0.034711809158325196, 0.03560165166854859, 0.03699892711639405, 0.0367926279703776]
proposed_median = [0.032698631286621094, 0.0323289155960083, 0.03403925895690918, 0.03641808032989502, 0.039549785852432254, 0.04073760032653809, 0.041563141345977786]
simple_median = [0.028197884559631348, 0.03295145034790039, 0.033152639865875244, 0.033916807174682616, 0.034715396165847776, 0.035713396072387694, 0.035801676909128825]

# 秒をミリ秒に変換
proposed_avg_ms = [x * 1000 for x in proposed_avg]
simple_avg_ms = [x * 1000 for x in simple_avg]

# # グラフの描画
# plt.figure(figsize=(10, 6))
# plt.plot(switch_counts, proposed_avg_ms, marker='o', label='Proposed Method')
# plt.plot(switch_counts, simple_avg_ms, marker='s', label='Simple Hop')
# plt.xlabel('Number of Switch Connections')
# plt.ylabel('Average Time (ms)')
# plt.title('Comparison of Time by Number of Switch Connections')
# plt.legend()
# plt.grid(True)
# plt.tight_layout()
# plt.show()



# 中央値データ（秒）
# proposed_median = []
# simple_median = []

# ミリ秒へ変換
proposed_median_ms = [x * 1000 for x in proposed_median]
simple_median_ms = [x * 1000 for x in simple_median]

# 差分（提案手法 - 単純ホップ）の計算（ミリ秒）
diff_avg_ms = [p - s for p, s in zip(proposed_avg_ms, simple_avg_ms)]
diff_median_ms = [p - s for p, s in zip(proposed_median_ms, simple_median_ms)]

# # グラフの描画（中央値）
# plt.figure(figsize=(10, 6))
# plt.plot(switch_counts, proposed_median_ms, marker='o', label='Proposed Method')
# plt.plot(switch_counts, simple_median_ms, marker='s', label='Simple Hop')
# plt.xlabel('Number of Switch Connections')
# plt.ylabel('Median Time (ms)')
# plt.title('Comparison of Median Time by Number of Switch Connections')
# plt.legend()
# plt.grid(True)
# plt.tight_layout()
# plt.show()

# 平均値と中央値ともに表示
plt.figure(figsize=(10, 6))
plt.plot(switch_counts, proposed_avg_ms, marker='o', label='Proposed Method (Average)')
plt.plot(switch_counts, simple_avg_ms, marker='s', label='Simple Hop (Average)')
plt.plot(switch_counts, proposed_median_ms, marker='o', label='Proposed Method (Median)')
plt.plot(switch_counts, simple_median_ms, marker='s', label='Simple Hop (Median)')
plt.xlabel('Number of Switch Connections')
plt.ylabel('Time (ms)')
plt.title('Comparison of Median Time by Number of Switch Connections')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# グラフの描画（差分）
plt.figure(figsize=(10, 6))
plt.plot(switch_counts, diff_avg_ms, marker='^', label='Average Time Difference (Proposed - Simple)')
plt.plot(switch_counts, diff_median_ms, marker='v', label='Median Time Difference (Proposed - Simple)')
plt.axhline(0, color='gray', linestyle='--')
plt.xlabel('Number of Switch Connections')
plt.ylabel('Time Difference (ms)')
plt.title('Difference in Time between Proposed and Simple Hop Methods')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
