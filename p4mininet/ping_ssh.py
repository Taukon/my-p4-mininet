from pexpect import pxssh
import time
import sys

send_count = 12
dst_switches = 0

server=""
username=""
password=""

for i in range(len(sys.argv)):

    if sys.argv[i] == '-c':
        send_count = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

    if sys.argv[i] == '-d':
        dst_switches = int(sys.argv[i+1]) if sys.argv[i+1].isdecimal() else 1

    if sys.argv[i] == '-s':
        server = sys.argv[i+1]
    
    if sys.argv[i] == '-u':
        username = sys.argv[i+1]
    
    if sys.argv[i] == '-p':
        password = sys.argv[i+1]

# if server == '' or username == '' or password == '':
#     print("Please provide the SSH server, username, and password using -s <server>, -u <username>, and -p <password>.")
#     exit(1)

if dst_switches == 0:
    print("Please provide the number of destination switches using -d <number>.")
    exit(1)


# ログイン情報を設定しSSHサーバーにログイン
ssh = pxssh.pxssh(timeout=60*5)
ssh.login(server, #接続したいSSHサーバーのIPを記述
          username, #SSHサーバー側のユーザー名を記述
          password) #SSHサーバー側のユーザーのパスワードを記述
print(ssh.after.decode(encoding='utf-8'), flush=True) #出力結果1

#カレントディレクトリを移動
ssh.sendline("cd ~/my-p4-mininet/p4mininet")
ssh.expect(r"\[.*\]\$ ")
print(ssh.before.decode(encoding='utf-8'), flush=True)
print(ssh.after.decode(encoding='utf-8'), flush=True)
time.sleep(1)

# カレントディレクトリのファイルを表示する
ssh.sendline("pwd")
ssh.expect(r"\[.*\]\$ ")
print(ssh.before.decode(encoding='utf-8'), flush=True)
print(ssh.after.decode(encoding='utf-8'), flush=True)
time.sleep(1)


# ssh.sendline(f"echo {password} | sudo -S python3 explore_test.py -c {send_count} -s {dst_switches}")
ssh.sendline(f"echo ubuntunk | sudo -S python3 explore_test.py -c {send_count} -s {dst_switches}")
ssh.expect(r"\[.*\]\$ ")
print(ssh.before.decode(encoding='utf-8'), flush=True)
print(ssh.after.decode(encoding='utf-8'), flush=True)
time.sleep(1)


ssh.sendline(f"echo {password} | sudo -S chown -R {username}:{username} result_load_test_{dst_switches}.json")
ssh.expect(r"\[.*\]\$ ")
print(ssh.before.decode(encoding='utf-8'), flush=True)
print(ssh.after.decode(encoding='utf-8'), flush=True)


# while True:

#     # trace
#     ssh.sendline(f"RESULT_JSON_FILE=result_load_test_{dst_switches}.json python3 load_test_ping.py -c {send_count} -d {dst_idx}")
#     ssh.expect(r"\[.*\]\$ ")
#     print(ssh.before.decode(encoding='utf-8'), flush=True)
#     trace_result = ssh.after.decode(encoding='utf-8')[15:17]
#     print(f"  trace: {correct_answer == trace_result} | {correct_answer} | {trace_result}")
#     time.sleep(1)

#     # mri
#     ssh.sendline(f"RESULT_JSON_FILE=result_load_test_{dst_switches}.json python3 load_test_ping.py -c {send_count} -d {dst_idx} -mri")
#     ssh.expect(r"\[.*\]\$ ")
#     print(ssh.before.decode(encoding='utf-8'), flush=True)
#     mri_result = ssh.after.decode(encoding='utf-8')[15:17]
#     print(f"  mri: {correct_answer == mri_result} | {correct_answer} | {mri_result}")
#     time.sleep(1)

#     if correct_answer == trace_result and correct_answer == mri_result:
#         break
#     else:
#         print("Retrying...")


# SSHサーバーからログアウト
ssh.logout()