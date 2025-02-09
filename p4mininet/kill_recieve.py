import sys
import subprocess

if __name__ == '__main__':

    has_host = False

    for i in range(len(sys.argv)):

        if sys.argv[i] == '-h' and sys.argv[i+1].isdecimal():
            host_idx = int(sys.argv[i+1])
            has_host = True

    if has_host == False:
        print("Not found arg \"-h 'host index'\"")
        exit(1)

    process_name = f"python3 recieve.py h{host_idx}"

    # psコマンドを実行
    result = subprocess.run(['sudo', 'pgrep', "-fa", process_name], capture_output=True, text=True)

    # 出力を行ごとに分割
    lines = result.stdout.splitlines()

    # 特定のプロセス名でフィルタリング
    for line in lines:
        pid_str_len = len(line)-len(process_name)
        # print(line[pid_str_len:])
        if  process_name in line[pid_str_len:]:
            pid_str_len = pid_str_len - len(' ')

            if line[:pid_str_len].isdecimal():
                pid = int(line[:pid_str_len])
                print(f"{line} | {pid}")
                subprocess.run(['sudo', 'kill', "-9", f"{pid}"])