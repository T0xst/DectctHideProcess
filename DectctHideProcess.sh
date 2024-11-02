#!/bin/bash

# 定义日志文件
LOG_DIR="/var/log/hidden_file_detection"
LOG_FILE="${LOG_DIR}/hidden_file_detection.log"

# 创建日志目录
mkdir -p $LOG_DIR

# 记录日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
    echo "$1"
}

# 检查并安装busybox
check_and_install_busybox() {
    if ! command -v busybox &> /dev/null; then
        commands=(
            "wget https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64 -O /tmp/busybox-x86_64"
            "cp /tmp/busybox-x86_64 /usr/local/bin/busybox"
            "chmod +x /usr/local/bin/busybox"
        )

        # 执行命令并检查返回值
        for cmd in "${commands[@]}"; do
            if ! $cmd; then
                echo "Failed to install busybox"
                exit 1
            fi
        done

        echo "busybox installed successfully"
    fi
}

# 检查并安装unhide
check_and_install_unhide() {
    if ! command -v unhide &> /dev/null; then
        log "unhide is not installed. Installing unhide..."
        yum install -y unhide
        if [[ $? -ne 0 ]]; then
            log "Failed to install unhide."
            exit 1
        fi
        log "unhide installed successfully."
    fi
}

# 检测隐藏进程
detect_hidden_process() {
    hidden_pids=$(unhide proc | grep -oP 'Found HIDDEN PID: \K\d+')
    if [[ -n "$hidden_pids" ]]; then
        log "Hidden process found: $hidden_pids"
    else
        log "No hidden process found."
        return 1
    fi
}

# 检测进程挂载
detect_process_mount() {
    log "[!!!]Detecting process mount..."
    # 获取 /proc/ 下的挂载点
    mounts=$(cat /proc/mounts | grep '/proc/' | grep -oP '/proc/\K\d+')
    if [[ -n "$mounts" ]]; then
        # 运行 netstat -anltp，提取出 PID
        netstat_pids=$(netstat -anltp | awk '{print $7}' | awk -F'/' '{print $1}' | grep -oE '[0-9]+' | sort -nu)
        if [[ -n "$netstat_pids" ]]; then
            for pid1 in $mounts; do
                if ! echo "$netstat_pids" | grep -q "^$pid1$"; then
                    log "PID $pid1 is Found by Process Mount !!!"
                fi
            done
        fi
    else
        log "Not Found process mount"
    fi
}

# 检测库文件劫持
detect_library_hijacking() {
    log "[!!!]Detecting Library Hijack..."

    # 检查 LD_PRELOAD 环境变量
    ld_preload_inject=$(echo $LD_PRELOAD)
    if [ -n "$ld_preload_inject" ]; then
        log "LD_PRELOAD is set to: $ld_preload_inject"
    fi

    # 检查/etc/ld.so.preload劫持
    preload_content=$(busybox cat /etc/ld.so.preload 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "Failed to read /etc/ld.so.preload."
    else
        log "Library hijacking detected:$preload_content"
    fi

    #  检查默认的动态库是否为/etc/ld.so.preload
    output=$(strace -f -e trace=file /bin/whoami 2>&1 | grep 'access("[^"]*", R_OK)' | grep -oP 'access\("\K[^"]*' | grep -q '/etc/ld.so.preload')
    if [[ -n "$output" ]]; then
        for path in $output; do
            log "Default dynamic library has been tampered with. Suspicious paths found:$path"
        done
    fi

}

# 检测 Diamorphine rootkit
detect_diamorphine_rootkit() {
    log "[!!!]Detecting Diamorphine rootkit..."

    # 检查安装后相关文件与日志是否存在
    find_output=$(busybox find / -name diamorphine 2>/dev/null)
    dmesg_output=$(dmesg | grep diamorphine 2>/dev/null)
    sys_module_output=$(ls -l /sys/module/diamorphine 2>/dev/null) 
    if [[ -n "$find_output" ]] || [[ -n "$dmesg_output" ]] || [[ -n "$sys_module_output" ]]; then
        log "Found Diamorphine Rootkit!"
        # 检查Diamorphine使用默认参数-31来隐藏进程
        pids1=$(netstat -anltp | grep -oP '\b\d+/\S+' | cut -d/ -f1 | sort -u)

        # 将 PID 存储到数组中
        IFS=$'\n' read -r -d '' -a pid1_array <<< "$pids1"

        # 检测隐藏进程
        hidden_pids=$(unhide proc | grep -oP 'Found HIDDEN PID: \K\d+')
        if [[ -n "$hidden_pids" ]]; then
            IFS=$'\n' read -r -d '' -a pid2_array <<< "$hidden_pids"
            for pid2 in "${pid2_array[@]}"; do
                kill -31 $pid2 2>/dev/null
                # 再次获取 PID 列表
                pids3=$(netstat -anltp | grep -oP '\b\d+/\S+' | cut -d/ -f1 | sort -u)
                IFS=$'\n' read -r -d '' -a pid3_array <<< "$pids3"

                # 检查 PID 是否在新的列表中
                if [[ " ${pid3_array[*]} " =~ " $pid2 " ]] && ! [[ " ${pid1_array[*]} " =~ " $pid2 " ]]; then
                    log "LKM Rootkit detected: PID $pid2" WARN
                fi
            done
        fi

        # 检查隐藏模块diamorphin
        sys_module_output=$(ls -l /sys/module/diamorphine 2>/dev/null)
        if [[ -n "$sys_module_output" ]]; then
            log "Diamorphine module detected by /sys/module/diamorphin"
        fi

        # 检查Diamorphine是否隐藏文件MAGIC_PREFIX "diamorphine_secret"
        # 创建测试文件
        test_file="diamorphine_secretx12ci"
        echo "test" > $test_file

        ls_output=$(ls -al | grep diamorphine_secretx12ci 2>/dev/null)
        if [[ -z "$ls_output" ]]; then
            cat_output=$(cat $test_file 2>/dev/null)
            if [[ "$cat_output" == "test" ]]; then
                log "Diamorphine Hidden file detected."
            fi
        fi

        # 清理测试文件
        rm -f diamorphine_secretx12ci
    else
        log "Not Found Diamorphine Rootkit"
    fi
}

# 主要函数
main() {
    # 检查并安装 unhide
    check_and_install_unhide

    # 检查并安装 busybox
    check_and_install_busybox

    # 检测隐藏进程
    if detect_hidden_process; then
        # 检测 Diamorphine rootkit
        detect_diamorphine_rootkit
        # 检测进程挂载
        detect_process_mount
        # 检测库文件劫持
        detect_library_hijacking
    fi
}

# 执行主要函数
main
