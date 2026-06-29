#!/usr/bin/env python3
"""
Android Systrace CPU Load Analyzer
从 ftrace 文本格式的 trace 中提取并统计 CPU 负载信息。

用法:
    python3 analyze_cpu_load.py [--start START_TIME] [--end END_TIME] [--interval INTERVAL]
    python3 analyze_cpu_load.py --ranges ranges.txt  # 多段查询 (读取一次，查询多次)
    
示例:
    # 统计整个 trace 期间的 CPU 负载
    python3 analyze_cpu_load.py
    
    # 统计 2977600.0 ~ 2977610.0 期间的负载
    python3 analyze_cpu_load.py --start 2977600.0 --end 2977610.0
    
    # 按 0.5 秒间隔统计各时段负载
    python3 analyze_cpu_load.py --start 2977600.0 --end 2977610.0 --interval 0.5
    
    # 多段查询 (ranges.txt 每行: start end, # 开头的行是注释)
    python3 analyze_cpu_load.py --ranges ranges.txt --top 30
"""

import re
import sys
import argparse
from collections import defaultdict

# ============================================================
# 解析 sched_switch 事件
# ============================================================

SCHED_SWITCH_RE = re.compile(
    r'^\s*.+?\s+\([^)]*\)\s+\[(\d+)\]\s+\S+\s+([\d.]+):\s+sched_switch:\s+'
    r'prev_comm=.+?\s+prev_pid=\d+\s+prev_prio=\d+\s+prev_state=\S+\s+'
    r'==>\s+next_comm=(.+?)\s+next_pid=(\d+)\s+next_prio=\d+'
)

def parse_trace_text(trace_text):
    """
    从 ftrace 文本中解析所有 sched_switch 事件。
    返回: [(cpu, timestamp, next_pid, next_comm), ...]
    """
    events = []
    for line in trace_text.split('\n'):
        m = SCHED_SWITCH_RE.match(line)
        if m:
            cpu = int(m.group(1))
            ts = float(m.group(2))
            next_comm = m.group(3)
            next_pid = int(m.group(4))
            events.append((cpu, ts, next_pid, next_comm, line.strip()))
    return events


# ============================================================
# CPU 负载计算
# ============================================================

def compute_cpu_load(events, start_time=None, end_time=None):
    """
    计算每个 CPU 的负载。

    原理: 通过 sched_switch 事件，累计每个 CPU 上非 idle 任务的运行时间。

    边界处理:
      - 窗口头部 [start_time, 第一个事件]: 用 start_time 前最后一个事件确定初始状态
      - 窗口尾部 [最后一个事件, end_time]:  用最后事件的状态延伸到 end_time
      - CPU 离线 (窗口内无事件):             标记为 offline，不计入总体分母

    返回:
        per_cpu: {cpu_id: {'busy': float, 'idle': float, 'total': float,
                           'load_pct': float, 'offline': bool}}
        overall: {..., 'window_duration': float, 'active_cpus': int}
    """
    if not events:
        return {}, {}

    # --- 获取所有 CPU 列表 ---
    all_cpus = sorted(set(e[0] for e in events))

    # --- 确定实际窗口 ---
    all_ts = [e[1] for e in events]
    trace_min = min(all_ts)
    trace_max = max(all_ts)
    window_start = start_time if start_time is not None else trace_min
    window_end = end_time if end_time is not None else trace_max
    window_duration = window_end - window_start

    # --- 对每个 CPU，找窗口内的所有 sched_switch 事件 ---
    #     同时追踪窗口前最后事件和窗口后第一个事件，用于边界判断
    per_cpu_evts = defaultdict(list)       # 窗口内的事件
    per_cpu_last_before = {}               # 窗口前最后一个事件
    per_cpu_first_after = {}               # 窗口后第一个事件

    for cpu, ts, next_pid, next_comm, _line in events:
        if ts < window_start:
            per_cpu_last_before[cpu] = (ts, next_pid, next_comm)
        elif ts <= window_end:
            per_cpu_evts[cpu].append((ts, next_pid, next_comm))
        else:  # ts > window_end
            if cpu not in per_cpu_first_after:
                per_cpu_first_after[cpu] = (ts, next_pid, next_comm)

    # --- 逐 CPU 计算，同时累加 per-task 统计 ---
    per_cpu = {}
    per_task = defaultdict(lambda: {'busy': 0.0})

    for cpu in all_cpus:
        evts = per_cpu_evts.get(cpu, [])

        if not evts:
            # 窗口内无 sched_switch 事件，需要区分"CPU 离线"和"任务横跨整个窗口"
            before = per_cpu_last_before.get(cpu)
            after = per_cpu_first_after.get(cpu)

            if after is not None:
                # 窗口后有事件 → CPU 在窗口内是活跃的，只是没发生切换
                # 整个窗口的耗时都属于窗口前最后切换到的那个任务
                if before is not None:
                    _, init_pid, init_comm = before
                    is_idle = (init_pid == 0)
                else:
                    is_idle = True
                    init_pid, init_comm = 0, "swapper"
                per_cpu[cpu] = {
                    'busy': 0.0 if is_idle else window_duration,
                    'idle': window_duration if is_idle else 0.0,
                    'total': window_duration,
                    'load_pct': 0.0 if is_idle else 100.0,
                    'offline': False,
                }
                if not is_idle:
                    per_task[(init_pid, init_comm)]['busy'] += window_duration
            elif before is not None:
                # 窗口后有事件但窗口前有 → 判断间隔是否过大
                gap = window_start - before[0]
                if gap < window_duration:
                    # 间隔合理，CPU 活跃
                    _, init_pid, init_comm = before
                    is_idle = (init_pid == 0)
                    per_cpu[cpu] = {
                        'busy': 0.0 if is_idle else window_duration,
                        'idle': window_duration if is_idle else 0.0,
                        'total': window_duration,
                        'load_pct': 0.0 if is_idle else 100.0,
                        'offline': False,
                    }
                    if not is_idle:
                        per_task[(init_pid, init_comm)]['busy'] += window_duration
                else:
                    # 间隔过大，CPU 很可能已 hotplug 离线
                    per_cpu[cpu] = {
                        'busy': 0.0, 'idle': 0.0, 'total': 0.0,
                        'load_pct': 0.0, 'offline': True,
                    }
            else:
                # 窗口前后均无事件 → 真正离线
                per_cpu[cpu] = {
                    'busy': 0.0, 'idle': 0.0, 'total': 0.0,
                    'load_pct': 0.0, 'offline': True,
                }
            continue

        evts.sort(key=lambda x: x[0])

        # 构造完整的时间段列表 (start_ts, end_ts, is_idle, pid, comm)
        segments = []

        # 1) 处理头部: [window_start, 第一个事件]
        first_ts = evts[0][0]
        if window_start < first_ts:
            # 用窗口前最后一个事件确定初始状态
            before = per_cpu_last_before.get(cpu)
            if before is not None:
                _, init_pid, init_comm = before
                is_idle = (init_pid == 0)
            else:
                # trace 中该 CPU 的第一个事件，假设之前是 idle
                is_idle = True
                init_pid, init_comm = 0, "swapper"
            segments.append((window_start, first_ts, is_idle, init_pid, init_comm))

        # 2) 处理中间: 相邻事件之间的区间
        for i in range(len(evts) - 1):
            ts, next_pid, next_comm = evts[i]
            next_ts = evts[i + 1][0]
            segments.append((ts, next_ts, next_pid == 0, next_pid, next_comm))

        # 3) 处理尾部: [最后一个事件, window_end]
        last_ts, last_pid, last_comm = evts[-1]
        if last_ts < window_end:
            segments.append((last_ts, window_end, last_pid == 0, last_pid, last_comm))

        # 累加 per-CPU 和 per-task
        busy_time = 0.0
        idle_time = 0.0
        for seg_start, seg_end, is_idle, pid, comm in segments:
            duration = seg_end - seg_start
            if duration < 0:
                continue  # 防御
            if is_idle:
                idle_time += duration
            else:
                busy_time += duration
                per_task[(pid, comm)]['busy'] += duration

        total_time = busy_time + idle_time
        per_cpu[cpu] = {
            'busy': busy_time,
            'idle': idle_time,
            'total': total_time,
            'load_pct': (busy_time / total_time * 100) if total_time > 0 else 0.0,
            'offline': False,
        }

    # --- 整体负载（仅统计活跃 CPU） ---
    active_cpus = [c for c in per_cpu.values() if not c['offline']]
    num_active = len(active_cpus)

    if num_active == 0:
        overall = {
            'busy': 0, 'idle': 0, 'total': 0,
            'load_pct': 0.0, 'window_duration': window_duration,
            'active_cpus': 0, 'total_cpus': len(all_cpus),
        }
    else:
        total_busy = sum(c['busy'] for c in active_cpus)
        total_idle = sum(c['idle'] for c in active_cpus)
        total_time = total_busy + total_idle
        overall = {
            'busy': total_busy,
            'idle': total_idle,
            'total': total_time,
            'load_pct': (total_busy / total_time * 100) if total_time > 0 else 0.0,
            'window_duration': window_duration,
            'active_cpus': num_active,
            'total_cpus': len(all_cpus),
        }

    # --- 计算 per-task 百分比 ---
    total_busy_all = overall['busy']
    for key in per_task:
        per_task[key]['load_pct'] = (per_task[key]['busy'] / total_busy_all * 100) if total_busy_all > 0 else 0.0

    return per_cpu, overall, dict(per_task)


def compute_interval_loads(events, start_time, end_time, interval):
    """按时间间隔分段计算负载"""
    results = []
    t = start_time
    while t < end_time:
        seg_end = min(t + interval, end_time)
        per_cpu, overall, per_task = compute_cpu_load(events, t, seg_end)
        results.append({
            'start': t,
            'end': seg_end,
            'per_cpu': per_cpu,
            'overall': overall,
            'per_task': per_task,
        })
        t = seg_end
    return results


# ============================================================
# 显示
# ============================================================

def print_load_report(per_cpu, overall, indent=""):
    """打印负载报告"""
    active_cpus = overall.get('active_cpus', len(per_cpu))
    total_cpus = overall.get('total_cpus', len(per_cpu))
    window_duration = overall.get('window_duration', overall.get('total', 0))

    print(f"{indent}┌─ CPU 负载详情 " + "─" * 50)
    for cpu in sorted(per_cpu.keys()):
        c = per_cpu[cpu]
        if c.get('offline'):
            # CPU 在窗口中离线（hotplug）
            print(f"{indent}│ CPU{cpu:2d}  ╔═ 离线 (hotplug) - 窗口中无调度事件")
        else:
            bar_len = 30
            filled = int(c['load_pct'] / 100 * bar_len)
            bar = '█' * filled + '░' * (bar_len - filled)
            # 验证：每个活跃 CPU 的 total 应约等于 window_duration
            diff = abs(c['total'] - window_duration)
            note = ""
            if diff > 0.001:
                note = f"  ⚠ total与窗口差{diff:.4f}s"
            print(f"{indent}│ CPU{cpu:2d} [{bar}] {c['load_pct']:5.1f}%  "
                  f"(busy: {c['busy']:.4f}s, idle: {c['idle']:.4f}s){note}")

    print(f"{indent}├─ 整体统计 " + "─" * 50)
    bar_len = 40
    load_pct = overall.get('load_pct', 0)
    filled = int(load_pct / 100 * bar_len)
    bar = '█' * filled + '░' * (bar_len - filled)
    print(f"{indent}│ 窗口长度: {window_duration:.4f}s")
    print(f"{indent}│ 活跃 CPU: {active_cpus} / {total_cpus} 核"
          + (f"  ({total_cpus - active_cpus} 核离线)" if active_cpus < total_cpus else ""))
    print(f"{indent}│ 总体负载  [{bar}] {load_pct:5.1f}%")
    print(f"{indent}│ 总 busy 时间: {overall['busy']:.4f}s")
    print(f"{indent}│ 总 idle 时间: {overall['idle']:.4f}s")
    if active_cpus > 0 and overall.get('total', 0) > 0:
        equiv = overall['busy'] / window_duration
        print(f"{indent}│ 等效满载核数: {equiv:.2f} (busy / window_duration)")
    print(f"{indent}└" + "─" * 60)


def print_task_report(per_task, overall, top_n=20, indent=""):
    """打印进程级 CPU 负载排行"""
    if not per_task:
        print(f"{indent}(无 busy 进程)")
        return

    total_busy = overall.get('busy', 0)
    window_duration = overall.get('window_duration', 0)

    # 按 busy 时间降序排列
    sorted_tasks = sorted(per_task.items(), key=lambda x: x[1]['busy'], reverse=True)
    sorted_tasks = sorted_tasks[:top_n]

    print(f"\n{indent}┌─ 进程 CPU 负载排行 (Top {min(top_n, len(per_task))}) " + "─" * 35)
    print(f"{indent}│ {'进程':>20s}  {'PID':>8s}  {'busy(s)':>12s}  {'%busy':>7s}  {'equiv':>7s}  柱状图")
    print(f"{indent}│ " + "-" * 80)

    max_busy = sorted_tasks[0][1]['busy'] if sorted_tasks else 1.0

    for (pid, comm), info in sorted_tasks:
        busy = info['busy']
        pct = info.get('load_pct', (busy / total_busy * 100) if total_busy > 0 else 0)
        equiv_cores = busy / window_duration if window_duration > 0 else 0

        bar_len = 30
        filled = int(busy / max_busy * bar_len) if max_busy > 0 else 0
        bar = '█' * filled + '░' * (bar_len - filled)

        # 截断过长的 comm
        comm_short = comm if len(comm) <= 20 else comm[:17] + "..."

        print(f"{indent}│ {comm_short:>20s}  {pid:>8d}  {busy:>12.6f}  {pct:>6.2f}%  {equiv_cores:>7.3f}  [{bar}]")

    # 汇总行
    other_tasks = len(per_task) - len(sorted_tasks)
    if other_tasks > 0:
        other_busy = sum(v['busy'] for k, v in per_task.items() if k not in dict(sorted_tasks))
        other_pct = other_busy / total_busy * 100 if total_busy > 0 else 0
        filled = int(other_pct / 100 * 30)
        bar = '█' * filled + '░' * (30 - filled)
        print(f"{indent}│ {'(其他 ' + str(other_tasks) + ' 进程)':>20s}  {'':>8s}  {other_busy:>12.6f}  {other_pct:>6.2f}%  {'':>7s}  [{bar}]")

    print(f"{indent}└" + "─" * 84)


# ============================================================
# Debug: dump 单个 CPU 的负载计算详情到 txt 文件
# ============================================================

def dump_cpu_debug(events, start_time, end_time, target_cpu, output_path):
    """
    将指定 CPU 的所有负载计算细节 dump 到 txt 文件，用于 debug。

    内容包括:
      1. 窗口信息
      2. 窗口前最后一个 sched_switch 事件（决定初始状态）
      3. 窗口内所有 sched_switch 事件
      4. 窗口后第一个 sched_switch 事件
      5. 由事件推导出的所有时间段 (segments)
      6. 最终 busy/idle 汇总
    """
    # 过滤目标 CPU 的事件
    cpu_events = [(ts, next_pid, next_comm, line) for cpu, ts, next_pid, next_comm, line in events if cpu == target_cpu]
    cpu_events.sort(key=lambda x: x[0])

    window_duration = end_time - start_time

    # 分类事件
    before_events = [(ts, pid, comm, line) for ts, pid, comm, line in cpu_events if ts < start_time]
    inside_events = [(ts, pid, comm, line) for ts, pid, comm, line in cpu_events if start_time <= ts <= end_time]
    after_events  = [(ts, pid, comm, line) for ts, pid, comm, line in cpu_events if ts > end_time]

    last_before = before_events[-1] if before_events else None
    first_after = after_events[0] if after_events else None

    # 构造 segments
    segments = []

    if not inside_events:
        # 窗口内无事件
        if last_before is not None:
            _, init_pid, init_comm, _ = last_before
            is_idle = (init_pid == 0)
        else:
            is_idle = True
            init_pid = 0
            init_comm = "swapper"
        segments.append((start_time, end_time, is_idle, init_pid, init_comm, "整个窗口无切换事件"))
    else:
        # 头部
        first_ts, _, _, _ = inside_events[0]
        if start_time < first_ts:
            if last_before is not None:
                _, init_pid, init_comm, _ = last_before
                is_idle = (init_pid == 0)
            else:
                is_idle = True
                init_pid = 0
                init_comm = "swapper(假设)"
            segments.append((start_time, first_ts, is_idle, init_pid, init_comm,
                             f"头部: window_start → 第一个事件"))

        # 中间
        for i in range(len(inside_events) - 1):
            ts, next_pid, next_comm, _ = inside_events[i]
            next_ts = inside_events[i + 1][0]
            segments.append((ts, next_ts, next_pid == 0, next_pid, next_comm,
                             f"事件#{i+1} → 事件#{i+2}"))

        # 尾部
        last_ts, last_pid, last_comm, _ = inside_events[-1]
        if last_ts < end_time:
            segments.append((last_ts, end_time, last_pid == 0, last_pid, last_comm,
                             f"尾部: 最后事件 → window_end"))

    # 累加
    busy_time = 0.0
    idle_time = 0.0
    for seg_start, seg_end, is_idle, pid, comm, desc in segments:
        duration = seg_end - seg_start
        if is_idle:
            idle_time += duration
        else:
            busy_time += duration

    # 写入文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f"  CPU{target_cpu} 负载计算 Debug Dump\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"窗口起始: {start_time:.9f}\n")
        f.write(f"窗口结束: {end_time:.9f}\n")
        f.write(f"窗口长度: {window_duration:.9f}s ({window_duration*1000:.6f}ms)\n\n")

        f.write("-" * 70 + "\n")
        f.write(f"  窗口前最后事件 (决定窗口初始状态)\n")
        f.write("-" * 70 + "\n")
        if last_before:
            ts, pid, comm, line = last_before
            f.write(f"  时间: {ts:.9f}  |  next_pid={pid}  |  next_comm={comm}\n")
            f.write(f"  原始行: {line}\n")
            gap = start_time - ts
            f.write(f"  距窗口起点: {gap:.9f}s ({gap*1000:.6f}ms)\n")
        else:
            f.write("  (无) — trace 中该 CPU 的第一个事件在窗口之后，假设初始为 idle\n")
        f.write("\n")

        f.write("-" * 70 + "\n")
        f.write(f"  窗口内 sched_switch 事件 ({len(inside_events)} 条)\n")
        f.write("-" * 70 + "\n")
        if inside_events:
            for i, (ts, pid, comm, line) in enumerate(inside_events, 1):
                f.write(f"  #{i:4d}  ts={ts:.9f}  next_pid={pid:6d}  next_comm={comm}\n")
                f.write(f"        原始行: {line}\n")
        else:
            f.write("  (无窗口内事件)\n")
        f.write("\n")

        f.write("-" * 70 + "\n")
        f.write(f"  窗口后第一个事件\n")
        f.write("-" * 70 + "\n")
        if first_after:
            ts, pid, comm, line = first_after
            f.write(f"  时间: {ts:.9f}  |  next_pid={pid}  |  next_comm={comm}\n")
            f.write(f"  原始行: {line}\n")
            gap = ts - end_time
            f.write(f"  距窗口终点: {gap:.9f}s ({gap*1000:.6f}ms)\n")
        else:
            f.write("  (无) — 窗口后该 CPU 无更多事件\n")
        f.write("\n")

        f.write("-" * 70 + "\n")
        f.write(f"  推导出的时间段 (segments) — 共 {len(segments)} 段\n")
        f.write("-" * 70 + "\n")
        f.write(f"  {'段':>3s}  {'start_ts':>16s}  {'end_ts':>16s}  {'duration(s)':>14s}  {'duration(ms)':>14s}  {'类型':>6s}  {'pid':>6s}  comm / 说明\n")
        f.write("  " + "-" * 100 + "\n")
        for i, (seg_start, seg_end, is_idle, pid, comm, desc) in enumerate(segments, 1):
            dur = seg_end - seg_start
            type_str = "idle" if is_idle else "BUSY"
            f.write(f"  {i:3d}  {seg_start:16.9f}  {seg_end:16.9f}  {dur:14.9f}  {dur*1000:14.6f}  {type_str:>6s}  {pid:6d}  {comm}  ({desc})\n")

        f.write("\n" + "=" * 70 + "\n")
        f.write(f"  汇总\n")
        f.write("=" * 70 + "\n")
        f.write(f"  busy 时间:  {busy_time:.9f}s  ({busy_time*1000:.6f}ms)\n")
        f.write(f"  idle 时间:  {idle_time:.9f}s  ({idle_time*1000:.6f}ms)\n")
        total = busy_time + idle_time
        load_pct = (busy_time / total * 100) if total > 0 else 0.0
        f.write(f"  total 时间: {total:.9f}s  ({total*1000:.6f}ms)\n")
        f.write(f"  负载百分比: {load_pct:.4f}%\n")
        f.write(f"  与窗口差:   {abs(total - window_duration):.9f}s\n")
        f.write("\n")

    print(f"CPU{target_cpu} debug dump 已写入: {output_path}")


# ============================================================
# 主程序
# ============================================================

def extract_trace_from_html(html_path):
    """从 Perfetto HTML 文件中提取 ftrace 文本数据（流式处理，避免加载整个文件）"""
    start_marker = '<script class="trace-data" type="application/text">'
    end_marker = '</script>'
    
    lines = []
    in_trace = False
    found_first = False  # 只取第一个 trace-data 标签（ftrace 文本数据）
    
    with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if not in_trace:
                if start_marker in line:
                    if not found_first:
                        in_trace = True
                        found_first = True
                        # 跳过 marker 所在行，取后面的内容
                        after_marker = line.split(start_marker, 1)[1]
                        if after_marker.strip():
                            lines.append(after_marker)
                    # 第二个 trace-data 标签（JSON metadata），跳过
                    continue
            else:
                if end_marker in line:
                    # 取结束标签之前的内容
                    before_end = line.split(end_marker, 1)[0]
                    if before_end.strip():
                        lines.append(before_end)
                    break
                lines.append(line)
    
    if not lines:
        raise ValueError("未找到 trace-data 标签或标签内无数据")
    
    return ''.join(lines)


# ============================================================
# TraceAnalyzer: 一次加载，多次查询
# ============================================================

class TraceAnalyzer:
    """
    Trace 分析器，支持一次读取数据，多次查询不同时间段的负载。

    用法:
        # 从 HTML 文件加载
        analyzer = TraceAnalyzer.from_html('output.html')

        # 或从原始 trace 文本加载
        analyzer = TraceAnalyzer(trace_text)

        # 多次查询
        r1 = analyzer.query(2977601.9, 2977602.1)
        r2 = analyzer.query(2977605.0, 2977606.0)

        # 访问元数据
        print(analyzer.trace_start, analyzer.trace_end)
        print(analyzer.cpu_list)
    """

    def __init__(self, trace_text=None):
        """
        从 ftrace 文本初始化分析器。

        参数:
            trace_text: ftrace 原始文本（含 sched_switch 行）
        """
        if trace_text is None:
            raise ValueError("需要提供 trace_text，或使用 TraceAnalyzer.from_html(path)")

        self._trace_text = trace_text
        self._events = parse_trace_text(trace_text)

        if not self._events:
            raise ValueError("未找到任何 sched_switch 事件")

        all_ts = [e[1] for e in self._events]
        self.trace_start = min(all_ts)
        self.trace_end = max(all_ts)
        self.trace_duration = self.trace_end - self.trace_start
        self.cpu_list = sorted(set(e[0] for e in self._events))
        self.event_count = len(self._events)

    @classmethod
    def from_html(cls, html_path):
        """从 Perfetto HTML 文件加载"""
        trace_text = extract_trace_from_html(html_path)
        return cls(trace_text)

    def query(self, start_time=None, end_time=None):
        """
        查询指定时间段的 CPU 负载和进程负载。

        参数:
            start_time: 起始时间戳，None 则用 trace 起始
            end_time:   结束时间戳，None 则用 trace 结束

        返回:
            dict {
                'start': float,
                'end': float,
                'per_cpu': {cpu_id: {busy, idle, total, load_pct, offline}},
                'overall': {busy, idle, total, load_pct, window_duration, active_cpus, total_cpus},
                'per_task': {(pid, comm): {busy, load_pct}},
            }
        """
        per_cpu, overall, per_task = compute_cpu_load(
            self._events, start_time, end_time
        )
        return {
            'start': start_time if start_time is not None else self.trace_start,
            'end': end_time if end_time is not None else self.trace_end,
            'per_cpu': per_cpu,
            'overall': overall,
            'per_task': per_task,
        }

    def query_intervals(self, start_time, end_time, interval):
        """
        按固定间隔分段查询。

        返回:
            list[dict]: 每段结果，格式同 query()
        """
        results = compute_interval_loads(self._events, start_time, end_time, interval)
        return [
            {
                'start': r['start'],
                'end': r['end'],
                'per_cpu': r['per_cpu'],
                'overall': r['overall'],
                'per_task': r['per_task'],
            }
            for r in results
        ]

    def debug_cpu(self, cpu_id, start_time, end_time, output_path=None):
        """
        Dump 指定 CPU 的负载计算详情到文件。

        参数:
            cpu_id:      CPU 编号
            start_time:  窗口起始时间
            end_time:    窗口结束时间
            output_path: 输出文件路径，None 则自动生成
        """
        path = output_path or f"cpu{cpu_id}_debug.txt"
        dump_cpu_debug(self._events, start_time, end_time, cpu_id, path)
        return path

    def print_report(self, result, top_n=20):
        """打印 query() 返回结果的完整报告"""
        dur = result['end'] - result['start']
        print(f"\n{'='*60}")
        print(f"  时段: {result['start']:.6f} ~ {result['end']:.6f} ({dur:.6f}s)")
        print(f"{'='*60}")
        print_load_report(result['per_cpu'], result['overall'])
        print_task_report(result['per_task'], result['overall'], top_n=top_n)

    def __repr__(self):
        return (f"TraceAnalyzer(events={self.event_count}, "
                f"cpus={len(self.cpu_list)}, "
                f"duration={self.trace_duration:.3f}s)")


# ============================================================
def main():
    parser = argparse.ArgumentParser(description='Android Systrace CPU Load Analyzer')
    parser.add_argument('--file', '-f', default='output.html',
                        help='trace HTML 文件路径 (默认: output.html)')
    parser.add_argument('--start', '-s', type=float,
                        help='起始时间戳（秒）')
    parser.add_argument('--end', '-e', type=float,
                        help='结束时间戳（秒）')
    parser.add_argument('--interval', '-i', type=float,
                        help='分段统计的时间间隔（秒）')
    parser.add_argument('--ranges', '-r', default=None,
                        help='多段查询文件: 每行 "start end", # 开头为注释')
    parser.add_argument('--top', '-t', type=int, default=20,
                        help='进程负载排行显示前 N 名 (默认: 20)')
    parser.add_argument('--list-cpus', action='store_true',
                        help='列出所有 CPU 及时间范围')
    parser.add_argument('--debug-cpu', type=int, metavar='CPU_ID',
                        help='dump 指定 CPU 的负载计算详情到 txt 文件 (如: --debug-cpu 7)')
    parser.add_argument('--debug-output', default=None,
                        help='debug dump 输出文件路径 (默认: cpu<ID>_debug.txt)')
    args = parser.parse_args()

    print("正在加载 trace 数据...")
    analyzer = TraceAnalyzer.from_html(args.file)

    print(f"\nTrace 时间范围: {analyzer.trace_start:.6f} ~ {analyzer.trace_end:.6f}")
    print(f"Trace 总时长: {analyzer.trace_duration:.4f}s ({analyzer.trace_duration/60:.2f}min)")
    print(f"CPU 核数: {len(analyzer.cpu_list)} (CPU {analyzer.cpu_list})")
    print(f"事件总数: {analyzer.event_count}")

    if args.list_cpus:
        print("\n各 CPU 事件统计:")
        for cpu in analyzer.cpu_list:
            cpu_count = sum(1 for e in analyzer._events if e[0] == cpu)
            cpu_ts = [e[1] for e in analyzer._events if e[0] == cpu]
            print(f"  CPU{cpu}: {cpu_count} 个事件, "
                  f"时间范围 {min(cpu_ts):.6f} ~ {max(cpu_ts):.6f}")
        return

    # 确定分析时间范围
    start = args.start if args.start is not None else analyzer.trace_start
    end = args.end if args.end is not None else analyzer.trace_end

    # --- 多段查询模式 ---
    if args.ranges:
        ranges_list = []
        with open(args.ranges, 'r') as rf:
            for line in rf:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ranges_list.append((float(parts[0]), float(parts[1])))

        if not ranges_list:
            print("错误: ranges 文件中没有有效的范围行")
            return

        print(f"\n多段查询模式: 共 {len(ranges_list)} 个时间段\n")
        for idx, (rs, re_) in enumerate(ranges_list, 1):
            result = analyzer.query(rs, re_)
            analyzer.print_report(result, top_n=args.top)
            print()
        return

    # --- 单段 / 间隔模式 ---
    print(f"\n分析时间范围: {start:.6f} ~ {end:.6f} ({end - start:.4f}s)")

    if args.interval:
        print(f"分段间隔: {args.interval}s\n")
        results = analyzer.query_intervals(start, end, args.interval)
        for r in results:
            analyzer.print_report(r, top_n=args.top)

        # 汇总
        print(f"\n{'='*60}")
        print(f"  【汇总】全时段 {start:.4f} ~ {end:.4f}")
        print(f"{'='*60}")

    result = analyzer.query(start, end)
    analyzer.print_report(result, top_n=args.top)

    # --- Debug dump ---
    if args.debug_cpu is not None:
        debug_output = args.debug_output or f"cpu{args.debug_cpu}_debug.txt"
        dump_cpu_debug(analyzer._events, start, end, args.debug_cpu, debug_output)


if __name__ == '__main__':
    main()
