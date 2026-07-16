#!/usr/bin/env python3
"""
分析 output.html 中的 sched_wakeup 事件，关联唤醒者与被唤醒者在唤醒时刻
各自执行的根函数。

对于每个 sched_wakeup 事件：
  - 唤醒者(waker)：唤醒发生时正在执行的根函数（或最近已结束的根函数）
  - 被唤醒者(wakee)：被唤醒后进入 runnable/running 状态时对应的根函数
  - 被唤醒者从 wakeup 到 running 的延迟

如果没有对应的根函数，以 "进程号_线程号_时间" 作为函数名。

用法:
    python3 analyze_wakeup_functions.py

输出:
    wakeup_functions.csv  -- 唤醒事件与根函数的关联表
"""

import re
import csv
import sys
import bisect
from collections import defaultdict

# ============================================================
# 正则表达式
# ============================================================

FTRACE_PREFIX_RE = re.compile(
    r'^\s*(.+?)\s+\(\s*(\d+|-------+)\s*\)\s+'
    r'\[(\d+)\]\s+'
    r'\S+\s+'
    r'([\d.]+):\s+'
    r'(.+)$'
)

SCHED_WAKEUP_RE = re.compile(
    r'sched_wakeup:\s+comm=(.+?)\s+pid=(\d+)\s+prio=(\d+)\s+target_cpu=(\d+)'
)

SCHED_SWITCH_RE = re.compile(
    r'sched_switch:\s+'
    r'prev_comm=(.+?)\s+prev_pid=(\d+)\s+prev_prio=(\d+)\s+prev_state=(\S+)\s+'
    r'==>\s+next_comm=(.+?)\s+next_pid=(\d+)\s+next_prio=(\d+)'
)

TRACING_MARK_RE = re.compile(
    r'tracing_mark_write:\s+([BE])\|(.+)$'
)


def extract_tid_from_comm_tid(comm_tid):
    m = re.search(r'-(\d+)$', comm_tid.strip())
    return int(m.group(1)) if m else None


def parse_ftrace_prefix(line):
    m = FTRACE_PREFIX_RE.match(line)
    if not m:
        return None
    comm_tid = m.group(1)
    pid_str = m.group(2)
    cpu = int(m.group(3))
    timestamp = float(m.group(4))
    payload = m.group(5)
    tid = extract_tid_from_comm_tid(comm_tid)
    if tid is None:
        return None
    pid = int(pid_str) if pid_str.replace('-', '').isdigit() else None
    return tid, pid, cpu, timestamp, payload


# ============================================================
# 根函数解析
# ============================================================

def parse_root_functions(filepath):
    stacks = defaultdict(list)
    root_funcs = defaultdict(list)
    first_ts = None

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            prefix = parse_ftrace_prefix(line)
            if prefix is None:
                continue
            line_tid, line_pid, cpu, timestamp, payload = prefix

            if first_ts is None:
                first_ts = timestamp

            m = TRACING_MARK_RE.match(payload)
            if not m:
                continue

            be_type = m.group(1)
            be_data = m.group(2)
            parts = be_data.split('|')

            pid_from_data = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else None
            func_name = parts[1] if len(parts) >= 2 else None
            pid = line_pid if line_pid is not None else pid_from_data

            if be_type == 'B':
                if func_name is None:
                    func_name = f"B_{pid_from_data}"
                is_root = (len(stacks[line_tid]) == 0)
                stacks[line_tid].append({
                    'func_name': func_name, 'pid': pid, 'start_ts': timestamp,
                })
                if is_root:
                    root_funcs[line_tid].append({
                        'func_name': func_name, 'pid': pid,
                        'start_ts': timestamp, 'end_ts': None,
                    })
            elif be_type == 'E':
                if len(stacks[line_tid]) == 0:
                    continue
                popped = stacks[line_tid].pop()
                for rf in reversed(root_funcs[line_tid]):
                    if rf['end_ts'] is None and abs(rf['start_ts'] - popped['start_ts']) < 1e-9:
                        rf['end_ts'] = timestamp
                        break

    result = {}
    for tid, funcs in root_funcs.items():
        complete = []
        for rf in funcs:
            if rf['end_ts'] is not None:
                complete.append((
                    rf['start_ts'], rf['end_ts'], rf['func_name'],
                    rf['pid'] if rf['pid'] is not None else 0,
                ))
        complete.sort(key=lambda x: x[0])
        result[tid] = complete

    return result, first_ts


# ============================================================
# sched_wakeup / sched_switch 解析
# ============================================================

def parse_wakeup_events(filepath):
    wakeups = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            prefix = parse_ftrace_prefix(line)
            if prefix is None:
                continue
            line_tid, line_pid, cpu, timestamp, payload = prefix
            m = SCHED_WAKEUP_RE.match(payload)
            if not m:
                continue
            wakee_tid = int(m.group(2))
            if wakee_tid == 0:
                continue
            wakeups.append((line_tid, line_pid, wakee_tid, timestamp))
    return wakeups


def parse_switch_events(filepath):
    switches = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            prefix = parse_ftrace_prefix(line)
            if prefix is None:
                continue
            line_tid, line_pid, cpu, timestamp, payload = prefix
            m = SCHED_SWITCH_RE.match(payload)
            if not m:
                continue
            prev_tid = int(m.group(2))
            prev_state = m.group(4)
            next_tid = int(m.group(6))
            switches.append((prev_tid, prev_state, next_tid, timestamp, cpu))
    return switches


# ============================================================
# 根函数查找
# ============================================================

def find_func_containing(root_funcs, tid, ts):
    funcs = root_funcs.get(tid, [])
    if not funcs:
        return None
    starts = [f[0] for f in funcs]
    idx = bisect.bisect_right(starts, ts) - 1
    if idx < 0:
        return None
    c = funcs[idx]
    if c[0] <= ts <= c[1]:
        return (c[2], c[3], c[0], c[1], 'containing')
    return None


def find_func_closest_previous(root_funcs, tid, ts):
    funcs = root_funcs.get(tid, [])
    if not funcs:
        return None
    starts = [f[0] for f in funcs]
    idx = bisect.bisect_right(starts, ts) - 1
    if idx < 0:
        return None
    c = funcs[idx]
    if c[1] <= ts:
        return (c[2], c[3], c[0], c[1], 'closest_previous')
    return None


def find_func_spanning_or_next(root_funcs, tid, ts, end_ts=None):
    """
    查找 tid 在时间 ts 附近执行的根函数。

    优先查找 spanning（函数跨越 ts），其次查找 next（函数在 ts 之后开始）。
    如果指定了 end_ts，next 匹配只有在函数开始时间 < end_ts 时才生效，
    确保函数在被唤醒者的实际 running 区间内，不会匹配到后续其他唤醒周期
    中才执行的函数。
    """
    funcs = root_funcs.get(tid, [])
    if not funcs:
        return None
    starts = [f[0] for f in funcs]
    idx = bisect.bisect_right(starts, ts) - 1
    if idx >= 0:
        c = funcs[idx]
        if c[0] < ts < c[1]:
            return (c[2], c[3], c[0], c[1], 'spanning')
    idx = bisect.bisect_left(starts, ts)
    if idx < len(funcs):
        c = funcs[idx]
        # 如果指定了 end_ts，只接受在 running 区间内开始的函数
        if end_ts is None or c[0] < end_ts:
            return (c[2], c[3], c[0], c[1], 'next')
    return None


# ============================================================
# sched_switch 查找
# ============================================================

def build_switch_lookup(switches):
    lookup = defaultdict(list)
    for prev_tid, prev_state, next_tid, ts, cpu in switches:
        if next_tid != 0:
            lookup[next_tid].append(ts)
    for tid in lookup:
        lookup[tid].sort()
    return lookup


def find_first_running_after(switch_lookup, tid, wakeup_ts):
    times = switch_lookup.get(tid, [])
    if not times:
        return None
    idx = bisect.bisect_left(times, wakeup_ts)
    if idx < len(times):
        return times[idx]
    return None


def build_switch_out_lookup(switches):
    """构建 tid -> [switch_out_times] 映射，记录线程让出 CPU 的时间"""
    lookup = defaultdict(list)
    for prev_tid, prev_state, next_tid, ts, cpu in switches:
        if prev_tid != 0:
            lookup[prev_tid].append(ts)
    for tid in lookup:
        lookup[tid].sort()
    return lookup


def find_first_running_out_after(switch_out_lookup, tid, run_in_ts):
    """找到 tid 在 run_in_ts 之后第一次让出 CPU (sched_switch out) 的时间"""
    times = switch_out_lookup.get(tid, [])
    if not times:
        return None
    idx = bisect.bisect_left(times, run_in_ts)
    if idx < len(times):
        return times[idx]
    return None


def build_tid_pid_mapping(filepath):
    """
    扫描所有 ftrace 行，从行前缀的 comm-tid (pid) 中构建 tid -> pid 映射。
    用于为没有 ATrace 标记的线程（如内核线程）获取正确的 PID (tgid)。
    """
    tid_to_pid = {}
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            prefix = parse_ftrace_prefix(line)
            if prefix is None:
                continue
            tid, pid, cpu, timestamp, payload = prefix
            if tid not in tid_to_pid and pid is not None:
                tid_to_pid[tid] = pid
    return tid_to_pid


def format_timestamp(ts, base_ts):
    delta = ts - base_ts
    hours = int(delta // 3600)
    minutes = int((delta % 3600) // 60)
    seconds = delta % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:018.9f}"


def main():
    filepath = 'output.html'

    print("正在解析根函数 (tracing_mark_write B/E) ...")
    root_funcs, first_ts = parse_root_functions(filepath)
    total_funcs = sum(len(v) for v in root_funcs.values())
    print(f"  解析到 {total_funcs} 个完整根函数，分布在 {len(root_funcs)} 个线程")

    print("正在解析 sched_switch 事件 ...")
    switches = parse_switch_events(filepath)
    switch_lookup = build_switch_lookup(switches)
    switch_out_lookup = build_switch_out_lookup(switches)
    print(f"  解析到 {len(switches)} 个调度切换事件，涉及 {len(switch_lookup)} 个线程")

    print("正在解析 sched_wakeup 事件 ...")
    wakeups = parse_wakeup_events(filepath)
    print(f"  解析到 {len(wakeups)} 个唤醒事件")

    seen = set()
    unique_wakeups = []
    for w in wakeups:
        key = (w[0], w[2], w[3])
        if key not in seen:
            seen.add(key)
            unique_wakeups.append(w)
    print(f"  去重后 {len(unique_wakeups)} 个唯一唤醒事件")

    print("正在构建 TID→PID 映射 (从所有 ftrace 行前缀) ...")
    tid_to_pid = build_tid_pid_mapping(filepath)
    print(f"  收集到 {len(tid_to_pid)} 个线程的 PID 映射")

    print("正在关联唤醒事件与根函数 ...")

    stats = {
        'waker_containing': 0, 'waker_closest_previous': 0, 'waker_synthetic': 0,
        'wakee_spanning': 0, 'wakee_next': 0, 'wakee_synthetic': 0,
        'total': 0,
    }
    results = []

    for waker_tid, waker_pid, wakee_tid, ts in unique_wakeups:
        # ---- 唤醒者 ----
        waker_result = find_func_containing(root_funcs, waker_tid, ts)
        if waker_result:
            waker_func, waker_func_pid, waker_start, waker_end, waker_match = waker_result
        else:
            waker_result = find_func_closest_previous(root_funcs, waker_tid, ts)
            if waker_result:
                waker_func, waker_func_pid, waker_start, waker_end, waker_match = waker_result
            else:
                wp = waker_pid if waker_pid is not None else 0
                waker_func = f"{wp}_{waker_tid}_{ts:.6f}"
                waker_func_pid = wp
                waker_start = waker_end = ts
                waker_match = 'synthetic'

        stats[f'waker_{waker_match}'] += 1

        # ---- 被唤醒者 ----
        # 先确定被唤醒者的实际 running 区间（switch_in ~ switch_out）
        running_ts = find_first_running_after(switch_lookup, wakee_tid, ts)
        running_out_ts = None
        if running_ts is not None:
            running_out_ts = find_first_running_out_after(switch_out_lookup, wakee_tid, running_ts)

        # 在被唤醒者的 running 窗口 [running_ts, running_out_ts) 内查找根函数
        # end_ts=running_out_ts 确保不会匹配到后续其他唤醒周期中才执行的函数
        wakee_result = find_func_spanning_or_next(root_funcs, wakee_tid, ts, end_ts=running_out_ts)
        if wakee_result:
            wakee_func, wakee_func_pid, wakee_start, wakee_end, wakee_match = wakee_result
        else:
            # 回退：先尝试 root_funcs 中的 PID，再尝试 tid_to_pid 映射
            wakee_pid = 0
            if wakee_tid in root_funcs and root_funcs[wakee_tid]:
                wakee_pid = root_funcs[wakee_tid][0][3]
            if wakee_pid == 0 and wakee_tid in tid_to_pid:
                wakee_pid = tid_to_pid[wakee_tid]
            wakee_func = f"{wakee_pid}_{wakee_tid}_{ts:.6f}"
            wakee_func_pid = wakee_pid
            wakee_start = wakee_end = ts
            wakee_match = 'synthetic'

        stats[f'wakee_{wakee_match}'] += 1
        stats['total'] += 1

        results.append({
            'waker_tid': waker_tid, 'waker_pid': waker_func_pid,
            'waker_func': waker_func, 'waker_match': waker_match,
            'waker_start': waker_start, 'waker_end': waker_end,
            'wakee_tid': wakee_tid, 'wakee_pid': wakee_func_pid,
            'wakee_func': wakee_func, 'wakee_match': wakee_match,
            'wakee_start': wakee_start, 'wakee_end': wakee_end,
            'wakeup_ts': ts, 'running_ts': running_ts,
        })

    # ---- 函数名去重 ----
    # 统计 waker 和 wakee 中同名但不同时段的根函数，为它们追加 _pid_tid_时间戳
    def _dedup_func_names(results):
        """若根函数名在多个不同时段出现，则追加 _pid_tid_时间戳 确保唯一"""
        # 收集所有非 synthetic 的函数名及其 (start_ts) 出现情况
        waker_name_starts = defaultdict(set)
        wakee_name_starts = defaultdict(set)
        for r in results:
            if r['waker_match'] != 'synthetic':
                waker_name_starts[r['waker_func']].add(r['waker_start'])
            if r['wakee_match'] != 'synthetic':
                wakee_name_starts[r['wakee_func']].add(r['wakee_start'])

        # 需要重命名的函数名（出现在 >1 个不同时段）
        waker_dup_names = {name for name, starts in waker_name_starts.items() if len(starts) > 1}
        wakee_dup_names = {name for name, starts in wakee_name_starts.items() if len(starts) > 1}

        print(f"  去重：waker 侧 {len(waker_dup_names)} 个函数名需要追加后缀")
        print(f"  去重：wakee 侧 {len(wakee_dup_names)} 个函数名需要追加后缀")

        # 重命名
        for r in results:
            if r['waker_match'] != 'synthetic' and r['waker_func'] in waker_dup_names:
                r['waker_func'] = (
                    f"{r['waker_func']}_{r['waker_pid']}_"
                    f"{r['waker_tid']}_{r['waker_start']:.6f}"
                )
            if r['wakee_match'] != 'synthetic' and r['wakee_func'] in wakee_dup_names:
                r['wakee_func'] = (
                    f"{r['wakee_func']}_{r['wakee_pid']}_"
                    f"{r['wakee_tid']}_{r['wakee_start']:.6f}"
                )

    _dedup_func_names(results)

    # ---- 输出 CSV ----
    csv_path = 'wakeup_functions.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            '唤醒者TID', '唤醒者PID', '唤醒者匹配方式', '唤醒者执行的根函数',
            '唤醒者函数开始(秒)', '唤醒者函数结束(秒)', '唤醒者函数耗时(us)',
            '被唤醒者TID', '被唤醒者PID', '被唤醒者匹配方式', '被唤醒者对应的根函数',
            '被唤醒者函数开始(秒)', '被唤醒者函数结束(秒)', '被唤醒者函数耗时(us)',
            '唤醒时间(原始秒)', '唤醒时间(格式)',
            '被唤醒者进入Running时间(秒)', '唤醒到Running延迟(us)',
        ])
        for r in results:
            ts_fmt = format_timestamp(r['wakeup_ts'], first_ts)
            waker_dur = (r['waker_end'] - r['waker_start']) * 1e6
            wakee_dur = (r['wakee_end'] - r['wakee_start']) * 1e6
            run_delay = ((r['running_ts'] - r['wakeup_ts']) * 1e6) if r['running_ts'] else ''

            writer.writerow([
                r['waker_tid'], r['waker_pid'], r['waker_match'], r['waker_func'],
                f"{r['waker_start']:.6f}", f"{r['waker_end']:.6f}", f"{waker_dur:.1f}",
                r['wakee_tid'], r['wakee_pid'], r['wakee_match'], r['wakee_func'],
                f"{r['wakee_start']:.6f}", f"{r['wakee_end']:.6f}", f"{wakee_dur:.1f}",
                f"{r['wakeup_ts']:.6f}", ts_fmt,
                f"{r['running_ts']:.6f}" if r['running_ts'] else '',
                f"{run_delay:.1f}" if run_delay != '' else '',
            ])

    # ---- 统计 ----
    t = stats['total']
    print(f"\n结果已保存到: {csv_path}")
    print(f"\n=== 唤醒者统计 (共 {t} 个唤醒事件) ===")
    print(f"  唤醒时正在执行根函数 (containing):       {stats['waker_containing']:>6} ({100*stats['waker_containing']/t:.1f}%)")
    print(f"  唤醒时上一个根函数刚结束 (closest_prev):  {stats['waker_closest_previous']:>6} ({100*stats['waker_closest_previous']/t:.1f}%)")
    print(f"  无关联根函数 (synthetic):                {stats['waker_synthetic']:>6} ({100*stats['waker_synthetic']/t:.1f}%)")

    print(f"\n=== 被唤醒者统计 ===")
    print(f"  被中断后恢复同一函数 (spanning):         {stats['wakee_spanning']:>6} ({100*stats['wakee_spanning']/t:.1f}%)")
    print(f"  唤醒后开始新函数 (next):                  {stats['wakee_next']:>6} ({100*stats['wakee_next']/t:.1f}%)")
    print(f"  无关联根函数 (synthetic):                {stats['wakee_synthetic']:>6} ({100*stats['wakee_synthetic']/t:.1f}%)")

    cross_proc = sum(1 for r in results if r['waker_pid'] != r['wakee_pid'])
    same_proc = t - cross_proc
    print(f"\n=== 进程关系 ===")
    print(f"  跨进程唤醒: {cross_proc} ({100*cross_proc/t:.1f}%)")
    print(f"  同进程唤醒: {same_proc} ({100*same_proc/t:.1f}%)")

    delays = [r['running_ts'] - r['wakeup_ts'] for r in results if r['running_ts']]
    if delays:
        d_us = sorted([d * 1e6 for d in delays])
        print(f"\n=== 被唤醒者 Run 延迟 (wakeup -> running) ===")
        print(f"  有效样本: {len(d_us)}")
        print(f"  最小: {d_us[0]:.1f} us")
        print(f"  最大: {d_us[-1]:.1f} us")
        print(f"  中位数: {d_us[len(d_us)//2]:.1f} us")
        print(f"  平均: {sum(d_us)/len(d_us):.1f} us")


if __name__ == '__main__':
    main()
