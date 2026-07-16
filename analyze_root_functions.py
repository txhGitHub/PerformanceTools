#!/usr/bin/env python3
"""
分析 output.html (Android Systrace HTML) 中的 tracing_mark_write B/E 事件，
统计所有根函数（顶层未被嵌套的函数调用）的开始时间、持续时间、线程号和进程号。

用法:
    python3 analyze_root_functions.py

输出:
    root_functions.csv  -- 所有根函数的统计信息
"""

import re
import csv
import sys
from collections import defaultdict

# ============================================================
# 正则表达式：解析 ftrace 行
# ============================================================

# 匹配 ftrace 行格式:
#   comm-tid   (   pid) [cpu] flags timestamp: tracing_mark_write: B|...
FTRACE_LINE_RE = re.compile(
    r'^\s*(.+?)\s+\(\s*(\d+|-------+)\s*\)\s+'   # task(tid) (pid)
    r'\[(\d+)\]\s+'                                 # [cpu]
    r'\S+\s+'                                       # flags
    r'([\d.]+):\s+'                                 # timestamp:
    r'tracing_mark_write:\s+([BE])\|(.+)$'           # B/E|...
)

def parse_ftrace_line(line):
    """
    解析一行 ftrace tracing_mark_write 事件。
    返回: (tid, pid_str, cpu, timestamp, be_type, be_data) 或 None
    """
    m = FTRACE_LINE_RE.match(line)
    if not m:
        return None
    
    comm_tid = m.group(1)   # e.g. ".android.camera-10083"
    pid_str = m.group(2)    # e.g. "10083" or "-------"
    cpu = int(m.group(3))
    timestamp = float(m.group(4))
    be_type = m.group(5)    # "B" or "E"
    be_data = m.group(6)    # e.g. "10083|func_name" or "10083"
    
    # 从 comm-tid 中提取 TID (最后一个 - 后面的数字)
    # comm 中可能包含 -, 取最后一个 - 后面部分
    tid_match = re.search(r'-(\d+)$', comm_tid)
    if tid_match:
        tid = int(tid_match.group(1))
    else:
        # 如果无法提取 TID，跳过
        return None
    
    # PID: 数值或 None (idle 线程)
    pid = int(pid_str) if pid_str.replace('-', '').isdigit() else None
    
    return tid, pid, cpu, timestamp, be_type, be_data


def parse_be_data(be_data):
    """
    解析 B/E 后面的数据部分。
    B 格式: "pid|func_name" 或 "pid|func_name|0"
    E 格式: "pid" 或 "pid|func_name|0"
    返回: (pid_from_data, func_name_or_None)
    """
    parts = be_data.split('|')
    if len(parts) < 1:
        return None, None
    
    pid_from_data = int(parts[0]) if parts[0].isdigit() else None
    
    if len(parts) >= 2:
        func_name = parts[1]
    else:
        func_name = None  # E 条目通常没有函数名
    
    return pid_from_data, func_name


def format_timestamp(ts, base_ts):
    """
    将时间戳转换为 HH:MM:SS.nnnnnnnnn 格式（相对于基时间）。
    输入 ts 和 base_ts 都是秒（浮点数）。
    """
    delta = ts - base_ts
    hours = int(delta // 3600)
    minutes = int((delta % 3600) // 60)
    seconds = delta % 60
    # 格式化为 9 位小数（纳秒精度）
    return f"{hours:02d}:{minutes:02d}:{seconds:018.9f}"


def analyze_root_functions(filepath):
    """
    分析 trace 文件中的所有根函数。
    
    返回:
        root_functions: [(func_name, tid, pid, start_ts, duration, start_formatted), ...]
        all_timestamps: 用于确定基时间的第一个时间戳
    """
    # 每个 TID 维护一个调用栈
    # stack[tid] = [(func_name, pid, start_ts, cpu), ...]
    stacks = defaultdict(list)
    
    root_functions = []
    first_timestamp = None
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            parsed = parse_ftrace_line(line)
            if parsed is None:
                continue
            
            tid, pid, cpu, timestamp, be_type, be_data = parsed
            
            if first_timestamp is None:
                first_timestamp = timestamp
            
            pid_from_data, func_name = parse_be_data(be_data)
            
            # 如果没有从行头部提取到 PID，使用数据中的 PID
            if pid is None:
                pid = pid_from_data
            
            if be_type == 'B':
                # 检查是否是根函数（栈为空）
                is_root = (len(stacks[tid]) == 0)
                
                if func_name is None:
                    func_name = f"B_{pid_from_data}"
                
                stacks[tid].append((func_name, pid, timestamp, cpu, line_num))
                
                if is_root:
                    root_functions.append({
                        'func_name': func_name,
                        'tid': tid,
                        'pid': pid,
                        'start_ts': timestamp,
                        'end_ts': None,
                        'duration': None,
                        'line_num': line_num,
                    })
            
            elif be_type == 'E':
                if len(stacks[tid]) == 0:
                    # 栈为空，忽略孤立的 E 事件
                    continue
                
                popped = stacks[tid].pop()
                popped_func_name, popped_pid, popped_start_ts, popped_cpu, popped_line = popped
                
                # 查找匹配的根函数
                for rf in root_functions:
                    if (rf['tid'] == tid and 
                        rf['start_ts'] == popped_start_ts and 
                        rf['end_ts'] is None):
                        rf['end_ts'] = timestamp
                        rf['duration'] = timestamp - popped_start_ts
                        break
    
    return root_functions, first_timestamp


def make_unique_names(complete_functions, first_timestamp):
    """
    同一个进程和线程中出现相同函数名时，将 pid、tid 和时间拼接到函数名末尾确保唯一。
    只对已完成的根函数（有完整 B/E 配对）进行处理。
    """
    # 统计每个 (pid, tid, func_name) 在完整函数中的出现次数
    final_count = defaultdict(int)
    for rf in complete_functions:
        key = (rf['pid'], rf['tid'], rf['func_name'])
        final_count[key] += 1
    
    # 对于有重复的，给每个实例添加后缀
    for rf in complete_functions:
        key = (rf['pid'], rf['tid'], rf['func_name'])
        if final_count[key] > 1:
            start_formatted = format_timestamp(rf['start_ts'], first_timestamp)
            rf['unique_name'] = f"{rf['func_name']}_pid{rf['pid']}_tid{rf['tid']}_{start_formatted}"
        else:
            rf['unique_name'] = rf['func_name']


def main():
    filepath = 'output.html'
    print(f"正在分析 {filepath} ...")
    
    root_functions, first_timestamp = analyze_root_functions(filepath)
    
    print(f"找到 {len(root_functions)} 个根函数")
    
    # 只保留有完整持续时间（有匹配的 E 事件）的根函数
    complete_functions = [rf for rf in root_functions if rf['duration'] is not None]
    incomplete_count = len(root_functions) - len(complete_functions)
    
    print(f"其中 {len(complete_functions)} 个有完整的开始/结束配对")
    if incomplete_count > 0:
        print(f"{incomplete_count} 个根函数缺少结束事件（trace 截断）")
    
    # 处理唯一名称
    make_unique_names(complete_functions, first_timestamp)
    
    # 统计重命名数量
    renamed = sum(1 for rf in complete_functions if rf['unique_name'] != rf['func_name'])
    print(f"其中 {renamed} 个因同名被重命名（同进程同线程中出现重复函数名）")
    
    # 输出到 CSV
    csv_filepath = 'root_functions.csv'
    with open(csv_filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            '函数名', '唯一函数名', '进程号(PID)', '线程号(TID)',
            '开始时间(原始秒)', '开始时间(格式)', '持续时间(秒)',
            '持续时间(ms)', '持续时间(us)'
        ])
        
        for rf in complete_functions:
            start_formatted = format_timestamp(rf['start_ts'], first_timestamp)
            writer.writerow([
                rf['func_name'],
                rf['unique_name'],
                rf['pid'] if rf['pid'] is not None else 'N/A',
                rf['tid'],
                f"{rf['start_ts']:.6f}",
                start_formatted,
                f"{rf['duration']:.9f}",
                f"{rf['duration'] * 1000:.3f}",
                f"{rf['duration'] * 1000000:.1f}",
            ])
    
    print(f"\n结果已保存到: {csv_filepath}")
    
    # 打印一些统计概览
    durations = [rf['duration'] for rf in complete_functions]
    if durations:
        durations.sort()
        print(f"\n=== 统计概览 ===")
        print(f"根函数总数: {len(complete_functions)}")
        print(f"最短持续时间: {durations[0]*1000000:.1f} us")
        print(f"最长持续时间: {durations[-1]*1000:.3f} ms ({durations[-1]:.6f} s)")
        print(f"平均持续时间: {sum(durations)/len(durations)*1000:.3f} ms")
        # 中位数
        mid = len(durations) // 2
        if len(durations) % 2 == 0:
            median = (durations[mid-1] + durations[mid]) / 2
        else:
            median = durations[mid]
        print(f"中位数持续时间: {median*1000:.3f} ms")
    
    # 打印前10个最长的根函数
    print(f"\n=== 持续时间最长的 20 个根函数 ===")
    sorted_functions = sorted(complete_functions, key=lambda x: x['duration'], reverse=True)
    for i, rf in enumerate(sorted_functions[:20]):
        start_formatted = format_timestamp(rf['start_ts'], first_timestamp)
        print(f"  {i+1:2d}. {rf['func_name'][:60]:60s}  "
              f"PID={rf['pid']}  TID={rf['tid']}  "
              f"开始={start_formatted}  "
              f"持续={rf['duration']*1000:.3f}ms")


if __name__ == '__main__':
    main()
