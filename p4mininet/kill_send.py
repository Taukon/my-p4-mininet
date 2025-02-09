import subprocess

def kill_send():

    process_name = f"python3 send.py"

    # psコマンドを実行
    result = subprocess.run(['sudo', 'pgrep', "-fa", process_name], capture_output=True, text=True)

    # 出力を行ごとに分割
    lines = result.stdout.splitlines()

    # 特定のプロセス名でフィルタリング
    for line in lines:
        # print(f"{line}")
        split_line = line.split()
        pid_str = split_line[0]
        if f"{split_line[1]} {split_line[2]}" == process_name:
            print(f"{split_line}")
            subprocess.run(['sudo', 'kill', "-9", pid_str])


if __name__ == '__main__':
    kill_send()