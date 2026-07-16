#!/usr/bin/env python3
"""插入 synthetic 函数标记到 trace 副本。每个标记时长 = 线程实际 running 时间。"""

import csv, sys, re, bisect
from collections import defaultdict, OrderedDict

# ------------------------------------------------------------
FTRACE_RE = re.compile(
    r'^\s*(.+?)\s+\(\s*(\d+|-------+)\s*\)\s+\[(\d+)\]\s+\S+\s+([\d.]+):\s+(.+)$')
SCHED_SWITCH_RE = re.compile(
    r'sched_switch:\s+prev_comm=.+?prev_pid=(\d+).+?==>\s+next_comm=.+?next_pid=(\d+)')

def parse_switch_intervals(filepath):
    """解析 sched_switch 事件，为每个 tid 构建 running 区间列表
    返回: {tid: [(switch_in_ts, switch_out_ts), ...]}"""
    running = defaultdict(list)  # tid -> [switch_out_time, ...] for switch_out lookup
    switch_ins = defaultdict(list)  # tid -> [switch_in_time, ...]
    switch_outs = defaultdict(list)

    print("  正在解析 sched_switch 事件...")
    count = 0
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = FTRACE_RE.match(line)
            if not m:
                continue
            ts = float(m.group(4))
            payload = m.group(5)
            sm = SCHED_SWITCH_RE.match(payload)
            if not sm:
                continue
            prev_tid = int(sm.group(1))
            next_tid = int(sm.group(2))
            count += 1
            if prev_tid != 0:
                switch_outs[prev_tid].append(ts)
            if next_tid != 0:
                switch_ins[next_tid].append(ts)

    print(f"  解析到 {count} 个 sched_switch 事件")

    # 构建区间: 对于每个 switch_in，找最近的 switch_out
    intervals = defaultdict(list)
    for tid in switch_ins:
        ins = sorted(switch_ins[tid])
        outs = sorted(switch_outs.get(tid, []))
        for ts_in in ins:
            idx = bisect.bisect_left(outs, ts_in)
            if idx < len(outs):
                intervals[tid].append((ts_in, outs[idx]))
    return intervals

# ------------------------------------------------------------

def load_synthetic_functions(csv_path):
    funcs = OrderedDict()
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if row[2] == 'synthetic':
                key = (row[3], int(row[1]), int(row[0]), float(row[4]))
                if key not in funcs:
                    funcs[key] = float(row[4])
            if row[9] == 'synthetic':
                key = (row[10], int(row[8]), int(row[7]), float(row[11]))
                if key not in funcs:
                    try:
                        ts = float(row[16]) if row[16] else float(row[11])
                    except ValueError:
                        ts = float(row[11])
                    funcs[key] = ts
    return funcs

def find_running_end(intervals, tid, start_ts):
    """找到 tid 在 start_ts 之后的 running 区间结束时间"""
    ivs = intervals.get(tid, [])
    if not ivs:
        return None
    starts = [iv[0] for iv in ivs]
    idx = bisect.bisect_left(starts, start_ts)
    if idx < len(ivs) and ivs[idx][0] >= start_ts:
        return ivs[idx][1]
    if idx > 0 and ivs[idx-1][0] <= start_ts < ivs[idx-1][1]:
        return ivs[idx-1][1]
    return None

def ftrace_line(tid, pid, ts, payload):
    comm = f"synthetic-{tid}"
    ps = f"{pid:5d}" if pid is not None else "-----"
    return f"     {comm:<16} ({ps}) [000] ..... {ts:.6f}: {payload}"

# ------------------------------------------------------------

def main():
    print("解析 sched_switch 事件...")
    intervals = parse_switch_intervals("output.html")
    total_intervals = sum(len(v) for v in intervals.values())
    print(f"  共 {total_intervals} 个 running 区间, {len(intervals)} 个线程")

    print("加载 synthetic 函数...")
    funcs = load_synthetic_functions("wakeup_functions.csv")
    print(f"  共 {len(funcs)} 个 synthetic 函数")

    inserts = []
    no_end = 0
    for (name, pid, tid, start_ts), marker_ts in funcs.items():
        end_ts = find_running_end(intervals, tid, marker_ts)
        if end_ts is None:
            no_end += 1
            end_ts = marker_ts + 0.000001  # 兜底 1us
        inserts.append(ftrace_line(tid, pid, marker_ts,
                                    f"tracing_mark_write: B|{pid}|{name}"))
        inserts.append(ftrace_line(tid, pid, end_ts,
                                    f"tracing_mark_write: E|{pid}"))

    dur_total = sum(1 for i in range(0, len(inserts), 2)
                    if 'E|' in inserts[i+1]) if inserts else 0
    print(f"  生成 {len(inserts)//2} 对 B/E (其中 {no_end} 个无 switch_out, 用 1us 兜底)")

    print("读取原始 trace...")
    with open("output.html", 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    idx = None
    for i in range(len(lines)-1, -1, -1):
        if lines[i].strip() == '</script>' and i < len(lines)-5:
            for j in range(i-1, max(i-5, 0), -1):
                if 'sched_' in lines[j] or 'tracing_mark_write' in lines[j]:
                    idx = i; break
            if idx: break

    if not idx:
        print("找不到插入位置"); sys.exit(1)

    out = lines[:idx]
    out.append('\n# ===== synthetic 函数标记 (时长 = running 时间) =====\n\n')
    for sl in inserts:
        out.append(sl + '\n')
    out.append('\n')
    out.extend(lines[idx:])

    print("写入文件...")
    with open("output_with_functions.html", 'w', encoding='utf-8') as f:
        f.writelines(out)
    print("完成！")

if __name__ == '__main__':
    main()
