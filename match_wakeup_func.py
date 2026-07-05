#!/usr/bin/env python3
"""
Wakeup-Function Matcher
=======================
从 Android Systrace HTML 中:
  1. 解析 tracing_mark_write (B/E) 构建每线程的函数执行时间线
     - 通过 B/E 配对识别嵌套调用，展平为栈顶函数的时间段
  2. 解析 sched_waking 提取每次唤醒关系
  3. 匹配: 唤醒发生时唤醒线程正在执行的函数 (即该时刻线程栈顶函数)
  4. 保存匹配结果，支持查询函数间是否存在调用/唤醒关系

原理:
  tracing_mark_write B|pid|func  → 函数开始 (入栈)
  tracing_mark_write E|pid       → 函数结束 (出栈)
  栈顶函数 = 最近入栈且未出栈的函数
  
  sched_waking 发生在 waker 上下文中 → 该时刻 waker 的栈顶函数即唤醒者函数
  
用法:
  python3 match_wakeup_func.py                     # 分析 output.html, 输出匹配结果
  python3 match_wakeup_func.py --query A B         # 查询函数A是否唤醒过函数B
  python3 match_wakeup_func.py --from-func A       # 查询函数A唤醒了哪些函数
  python3 match_wakeup_func.py --to-func B         # 查询哪些函数唤醒了函数B
  python3 match_wakeup_func.py --tid 10083         # 查询指定线程相关的唤醒
  python3 match_wakeup_func.py --csv -o result.csv # 导出 CSV
"""

import re
import sys
import os
import json
import argparse
import bisect
from collections import defaultdict

# ============================================================
# 正则表达式
# ============================================================

# ftrace 行头部: TASK-PID ( TID) [CPU] FLAGS TIMESTAMP: BODY
FTRACE_LINE_RE = re.compile(
    r'^\s*(.+)-(\d+)\s+\(\s*([^)]*)\)\s+\[(\d+)\]\s+\S+\s+([\d.]+):\s+(.*)$'
)

# tracing_mark_write B 事件: B|PID|func_name 或 B|PID|func_name|0
TRACE_B_RE = re.compile(r'B\|(\d+)\|(.+)')

# tracing_mark_write E 事件: E|PID 或 E|PID|func_name|0
TRACE_E_RE = re.compile(r'E\|(\d+)')

# sched_waking: comm=WAKEECOMM pid=WAKEEPID prio=PRIO target_cpu=CPU
SCHED_WAKING_RE = re.compile(
    r'sched_waking:\s+comm=(.+?)\s+pid=(\d+)\s+prio=(\d+)\s+target_cpu=(\d+)'
)

# sched_wakeup_new
SCHED_WAKEUP_NEW_RE = re.compile(
    r'sched_wakeup_new:\s+comm=(.+?)\s+pid=(\d+)\s+prio=(\d+)\s+target_cpu=(\d+)'
)

# sched_blocked_reason
SCHED_BLOCKED_REASON_RE = re.compile(
    r'sched_blocked_reason:\s+pid=(\d+)\s+iowait=(\d+)\s+caller=(.+)'
)


# ============================================================
# 从 HTML 提取 trace
# ============================================================

def extract_trace_from_html(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    pattern = re.compile(
        r'<script class="trace-data" type="application/text">(.*?)</script>',
        re.DOTALL
    )
    m = pattern.search(content)
    if m:
        return m.group(1).strip().split('\n')
    if content.strip().startswith('# tracer:'):
        return content.strip().split('\n')
    return None


# ============================================================
# 时间转换工具
# ============================================================

def ts_to_rel_time(timestamp, base_ts):
    """
    将绝对时间戳转换为相对时间格式 HH:MM:SS.nnnnnnnnn
    e.g. 2977601.641555 with base_ts 2977598.339563 → 00:00:03.301992000
    """
    rel = timestamp - base_ts
    hours = int(rel // 3600)
    minutes = int((rel % 3600) // 60)
    seconds = rel % 60
    whole_seconds = int(seconds)
    nanoseconds = int(round((seconds - whole_seconds) * 1e9))
    # 处理浮点精度导致的进位
    if nanoseconds >= 1_000_000_000:
        nanoseconds = 0
        whole_seconds += 1
        if whole_seconds >= 60:
            whole_seconds = 0
            minutes += 1
            if minutes >= 60:
                minutes = 0
                hours += 1
    return f"{hours:02d}:{minutes:02d}:{whole_seconds:02d}.{nanoseconds:09d}"


def find_base_timestamp(trace_lines):
    """找到 trace 中最小的有效时间戳"""
    min_ts = None
    for line in trace_lines:
        m = FTRACE_LINE_RE.match(line)
        if m:
            ts = float(m.group(5))
            if min_ts is None or ts < min_ts:
                min_ts = ts
    return min_ts


# ============================================================
# 步骤1: 构建每线程的函数执行时间线 (栈顶函数)
# ============================================================

def make_unique_name(func_name, pid, tid, start_ts):
    """
    生成唯一的函数名: 原始函数名 + pid + tid + 开始时间戳
    格式: funcName_pid{PID}_tid{TID}_{start_timestamp}
    
    同一进程同一线程的相同函数，因 start_ts 不同而唯一。
    """
    return f"{func_name}_pid{pid}_tid{tid}_{start_ts:.6f}"


def parse_unique_name(unique_name):
    """
    从唯一函数名中提取原始信息。
    格式: funcName_pid{PID}_tid{TID}_{start_timestamp}
    返回: (func_name, pid, tid, start_ts) 或原字符串
    """
    m = re.match(r'^(.+)_pid(\d+)_tid(\d+)_([\d.]+)$', unique_name)
    if m:
        return m.group(1), int(m.group(2)), int(m.group(3)), float(m.group(4))
    return unique_name, None, None, None


def build_function_timelines(trace_lines):
    """
    解析 tracing_mark_write B/E 事件，为每个线程构建栈顶函数时间段。
    
    函数名做唯一化处理:
      原始名_pid{PID}_tid{TID}_{start_ts}
    确保同一 pid/tid 的同名函数因时间戳不同而唯一。
    
    栈行为:
      - B 事件: 入栈 (若栈非空则暂停父函数，记录一段 segment)
      - E 事件: 栈顶出栈 (记录该函数的 segment，恢复父函数)
    
    返回值:
      thread_segments: {tid: [(start_ts, end_ts, unique_func_name, pid), ...]}
        每次栈顶切换都会产生一个 segment (用于唤醒匹配)
      
      func_spans: {unique_name: {'b_ts', 'e_ts', 'duration', 'segment_count', ...}}
        每个函数的完整 B→E 跨度 (用于时间统计，不受嵌套调用影响)
      
      func_name_map: {unique_name: (original_name, pid, tid, start_ts)}
        唯一名 → 原始信息的映射
    """
    # 每线程的函数调用栈: [(unique_func_name, start_ts, pid), ...]  (栈顶在末尾)
    thread_stack = defaultdict(list)
    # 每线程的栈顶函数时间段: [(start_ts, end_ts, unique_func_name, pid), ...]
    thread_segments = defaultdict(list)
    # 唯一名 → 原始信息
    func_name_map = {}
    # 函数完整跨度: unique_name → span 信息
    func_spans = {}
    # 函数 segment 计数
    func_seg_count = defaultdict(int)
    
    unmatched_b = 0
    unmatched_e = 0
    
    for line in trace_lines:
        m = FTRACE_LINE_RE.match(line)
        if not m:
            continue
        
        task_comm = m.group(1)
        task_pid = int(m.group(2))
        tid_str = m.group(3)
        cpu = int(m.group(4))
        timestamp = float(m.group(5))
        event_body = m.group(6)
        
        # 解析 TID
        try:
            tid = int(tid_str)
        except ValueError:
            tid = task_pid
        
        if 'tracing_mark_write' not in event_body:
            continue
        
        # --- B 事件 ---
        bm = TRACE_B_RE.search(event_body)
        if bm:
            marker_pid = int(bm.group(1))
            func_name = bm.group(2).strip()
            # 生成唯一名
            unique_name = make_unique_name(func_name, marker_pid, tid, timestamp)
            func_name_map[unique_name] = (func_name, marker_pid, tid, timestamp)
            
            stack = thread_stack[tid]
            # 如果栈非空，当前栈顶函数的时间段到此结束 (被嵌套调用暂停)
            if stack:
                prev_func, prev_start, prev_pid = stack[-1]
                if timestamp > prev_start:
                    thread_segments[tid].append(
                        (prev_start, timestamp, prev_func, prev_pid)
                    )
                    func_seg_count[prev_func] += 1
            
            # 新函数入栈
            stack.append((unique_name, timestamp, marker_pid))
            continue
        
        # --- E 事件 ---
        em = TRACE_E_RE.search(event_body)
        if em:
            stack = thread_stack[tid]
            if stack:
                unique_name, start_ts, marker_pid = stack.pop()
                if timestamp > start_ts:
                    thread_segments[tid].append(
                        (start_ts, timestamp, unique_name, marker_pid)
                    )
                    func_seg_count[unique_name] += 1
                
                # 记录完整 B→E 跨度 (B 时间戳从 unique_name 中解析，不受 resume 影响)
                if unique_name not in func_spans:
                    orig_name, spid, stid, b_ts = parse_unique_name(unique_name)
                    if b_ts is not None and timestamp > b_ts:
                        func_spans[unique_name] = {
                            'func_name': unique_name,
                            'original_name': orig_name,
                            'pid': spid,
                            'tid': stid,
                            'b_ts': b_ts,
                            'e_ts': timestamp,
                            'duration': timestamp - b_ts,
                        }
                
                # 如果栈非空，恢复上一层函数的执行
                if stack:
                    prev_func, prev_start, prev_pid = stack[-1]
                    stack[-1] = (prev_func, timestamp, prev_pid)
            else:
                unmatched_e += 1
            continue
    
    # 处理 trace 结束时仍在栈上的函数 (没有匹配的 E)
    for tid, stack in thread_stack.items():
        for func_name, start_ts, pid in stack:
            unmatched_b += 1
    
    # 对每个 tid 的 segments 按 start_ts 排序
    for tid in thread_segments:
        thread_segments[tid].sort(key=lambda x: x[0])
    
    # 补充 segment_count 到 func_spans
    for uname in func_spans:
        func_spans[uname]['segment_count'] = func_seg_count.get(uname, 0)
    # 也把未匹配 E 的函数加入 spans (只有 B 没有 E)
    for tid, stack in thread_stack.items():
        for func_name, start_ts, pid in stack:
            if func_name not in func_spans:
                orig_name, spid, stid, b_ts = parse_unique_name(func_name)
                func_spans[func_name] = {
                    'func_name': func_name,
                    'original_name': orig_name,
                    'pid': spid,
                    'tid': stid,
                    'b_ts': b_ts if b_ts else start_ts,
                    'e_ts': None,
                    'duration': None,
                    'segment_count': func_seg_count.get(func_name, 0),
                }
    
    return dict(thread_segments), func_spans, func_name_map, unmatched_b, unmatched_e


# ============================================================
# 步骤2: 提取唤醒关系
# ============================================================

def extract_wakeup_events(trace_lines):
    """
    解析 sched_waking / sched_wakeup_new 事件。
    
    同时解析 sched_blocked_reason 以获取 wakee 的阻塞函数。
    
    返回:
      wakeup_events: [{timestamp, waker_pid, waker_tid, waker_comm,
                        wakee_pid, wakee_comm, wakee_func, wakeup_type}, ...]
    """
    wakeup_events = []
    blocked_reasons = []  # [(cpu, ts, pid, caller_func), ...]
    
    for line in trace_lines:
        m = FTRACE_LINE_RE.match(line)
        if not m:
            continue
        
        task_comm = m.group(1)
        task_pid = int(m.group(2))
        tid_str = m.group(3)
        cpu = int(m.group(4))
        timestamp = float(m.group(5))
        event_body = m.group(6)
        
        try:
            tid = int(tid_str)
        except ValueError:
            tid = task_pid
        
        # sched_waking
        wm = SCHED_WAKING_RE.search(event_body)
        if wm:
            wakee_comm = wm.group(1)
            wakee_pid = int(wm.group(2))
            wakeup_events.append({
                'timestamp': timestamp,
                'cpu': cpu,
                'waker_comm': task_comm,
                'waker_pid': task_pid,
                'waker_tid': tid,
                'wakee_comm': wakee_comm,
                'wakee_pid': wakee_pid,
                'waker_func': '',  # 待步骤3匹配
                'wakee_func': '',  # 待 blocked_reason 匹配
                'wakeup_type': 'waking',
            })
            continue
        
        # sched_wakeup_new
        wnm = SCHED_WAKEUP_NEW_RE.search(event_body)
        if wnm:
            wakee_comm = wnm.group(1)
            wakee_pid = int(wnm.group(2))
            wakeup_events.append({
                'timestamp': timestamp,
                'cpu': cpu,
                'waker_comm': task_comm,
                'waker_pid': task_pid,
                'waker_tid': tid,
                'wakee_comm': wakee_comm,
                'wakee_pid': wakee_pid,
                'waker_func': '',
                'wakee_func': '',
                'wakeup_type': 'wakeup_new',
            })
            continue
        
        # sched_blocked_reason
        bm = SCHED_BLOCKED_REASON_RE.search(event_body)
        if bm:
            blocked_pid = int(bm.group(1))
            caller_func = bm.group(3)
            blocked_reasons.append({
                'cpu': cpu, 'ts': timestamp,
                'pid': blocked_pid, 'caller': caller_func,
            })
            continue
    
    # 匹配 blocked_reason 到 wakeup (同 CPU, 时间差 < 1ms, pid 匹配)
    br_by_cpu = defaultdict(list)
    for br in blocked_reasons:
        br_by_cpu[br['cpu']].append(br)
    for cpu in br_by_cpu:
        br_by_cpu[cpu].sort(key=lambda x: x['ts'])
    
    # 对每个 wakeup，用二分查找找最近的 blocked_reason
    for ev in wakeup_events:
        cpu = ev['cpu']
        ts = ev['timestamp']
        pid = ev['wakee_pid']
        candidates = br_by_cpu.get(cpu, [])
        # 二分查找 >= ts 的位置
        idx = bisect.bisect_left([b['ts'] for b in candidates], ts)
        if idx < len(candidates):
            br = candidates[idx]
            if br['ts'] - ts < 0.001 and br['pid'] == pid:
                ev['wakee_func'] = br['caller']
    
    return wakeup_events


# ============================================================
# 步骤3: 匹配唤醒 → waker 函数
# ============================================================

def match_waker_functions(wakeup_events, thread_segments):
    """
    对每次唤醒，在 thread_segments 中查找 waker_tid 在唤醒时刻正在执行的栈顶函数。
    
    使用预计算的二分查找: 预先为每个 tid 提取 starts 列表。
    """
    # 预计算: 为每个 tid 提取 starts 和 segments 的并行数组
    seg_data = {}  # {tid: (starts_list, segments_list)}
    for tid, segs in thread_segments.items():
        seg_data[tid] = ([s[0] for s in segs], segs)
    
    matched = 0
    unmatched = 0
    total = len(wakeup_events)
    report_interval = max(1, total // 10)
    
    for i, ev in enumerate(wakeup_events):
        tid = ev['waker_tid']
        ts = ev['timestamp']
        
        data = seg_data.get(tid)
        if not data:
            ev['waker_func'] = ''
            unmatched += 1
            continue
        
        starts, segments = data
        # 二分查找: 最后一个 start_ts <= ts 的段
        idx = bisect.bisect_right(starts, ts) - 1
        
        if idx >= 0:
            seg_start, seg_end, func_name, pid = segments[idx]
            if seg_start <= ts < seg_end:
                ev['waker_func'] = func_name
                ev['waker_pid'] = pid
                matched += 1
                continue
        
        ev['waker_func'] = ''
        unmatched += 1
        
        if (i + 1) % report_interval == 0:
            print(f"  进度: {i+1}/{total} (匹配 {matched})")
    
    return matched, unmatched


# ============================================================
# 输出 & 查询
# ============================================================

def display_name(unique_name):
    """从唯一函数名提取可读的短名称: funcName(pid,tid)"""
    if not unique_name:
        return ''
    orig, pid, tid, ts = parse_unique_name(unique_name)
    if orig is not None:
        return f"{orig}(pid{pid},tid{tid})"
    return unique_name


def print_table(events, top_n=None, base_ts=None):
    if top_n:
        events = events[:top_n]
    
    ts_w, rel_w, waker_w, wfunc_w, wakee_w, wkeefunc_w = 13, 16, 15, 20, 15, 28
    
    header = (f"{'Time':>{ts_w}}  {'RelTime':>{rel_w}}  {'Waker(TID)':>{waker_w}}  "
              f"{'WakerFunc':<{wfunc_w}}  {'Wakee(PID)':>{wakee_w}}  "
              f"{'WakeeFunc':<{wkeefunc_w}}")
    sep = "-" * len(header)
    
    print()
    print(sep)
    print(header)
    print(sep)
    
    for e in events:
        ts_str = f"{e['timestamp']:.6f}"
        rel_str = e.get('rel_time', '') if base_ts else ''
        waker_str = f"{e['waker_comm']}({e['waker_tid']})"
        wakee_str = f"{e['wakee_comm']}({e['wakee_pid']})"
        wf = display_name(e.get('waker_func', '') or '')
        wef = (e.get('wakee_func', '') or '')[:wkeefunc_w]
        
        if len(waker_str) > waker_w:
            waker_str = waker_str[:waker_w-1] + "~"
        if len(wakee_str) > wakee_w:
            wakee_str = wakee_str[:wakee_w-1] + "~"
        if len(wf) > wfunc_w:
            wf = wf[:wfunc_w-1] + "~"
        
        print(f"{ts_str:>{ts_w}}  {rel_str:>{rel_w}}  {waker_str:>{waker_w}}  "
              f"{wf:<{wfunc_w}}  {wakee_str:>{wakee_w}}  "
              f"{wef:<{wkeefunc_w}}")
    
    print(sep)
    print(f"共 {len(events)} 条, 已匹配 waker 函数: "
          f"{sum(1 for e in events if e.get('waker_func'))} 条")


def query_by_func_pair(events, from_func, to_func):
    """查询: 函数 from_func 是否唤醒过函数 to_func"""
    results = []
    for e in events:
        wf = e.get('waker_func', '') or ''
        wef = e.get('wakee_func', '') or ''
        if from_func in wf and to_func in wef:
            results.append(e)
    return results


def query_from_func(events, func_name):
    """查询: 函数 func_name 唤醒了哪些函数 (作为 waker)"""
    results = []
    for e in events:
        wf = e.get('waker_func', '') or ''
        if func_name in wf:
            results.append(e)
    return results


def query_to_func(events, func_name):
    """查询: 哪些函数唤醒了 func_name (作为 wakee)"""
    results = []
    for e in events:
        wef = e.get('wakee_func', '') or ''
        if func_name in wef:
            results.append(e)
    return results


def query_by_tid(events, tid):
    """查询: 指定线程相关的所有唤醒"""
    return [e for e in events if e['waker_tid'] == tid or e['wakee_pid'] == tid]


def save_results(events, filepath, func_name_map=None, thread_segments=None, 
                 func_spans=None, base_ts=None):
    """保存匹配结果到 JSON 文件，支持后续查询"""
    data = {
        'total': len(events),
        'matched_waker_func': sum(1 for e in events if e.get('waker_func')),
        'matched_wakee_func': sum(1 for e in events if e.get('wakee_func')),
        'base_timestamp': base_ts,
        'events': events,
    }
    if func_name_map:
        # 将 func_name_map 的 tuple 值转为 list (JSON 序列化)
        data['func_name_map'] = {k: list(v) if isinstance(v, tuple) else v 
                                  for k, v in func_name_map.items()}
    if thread_segments and base_ts is not None:
        segs_data = {}
        for tid, segs in thread_segments.items():
            segs_data[str(tid)] = [
                {
                    'start': s[0],
                    'end': s[1],
                    'func_name': s[2],
                    'pid': s[3],
                    'duration_ms': round((s[1] - s[0]) * 1000, 3),
                    'rel_start': ts_to_rel_time(s[0], base_ts),
                    'rel_end': ts_to_rel_time(s[1], base_ts),
                }
                for s in segs
            ]
        data['thread_segments'] = segs_data
        data['thread_count'] = len(segs_data)
        data['total_segments'] = sum(len(v) for v in segs_data.values())
    
    # 函数完整跨度: 从 B 到匹配 E 的总时间 (不受嵌套调用影响)
    if func_spans and base_ts is not None:
        spans_data = {}
        for uname, info in func_spans.items():
            tid = info.get('tid')
            if tid is None:
                continue
            tid_str = str(tid)
            if tid_str not in spans_data:
                spans_data[tid_str] = []
            
            entry = {
                'func_name': uname,
                'original_name': info.get('original_name', ''),
                'pid': info.get('pid'),
                'tid': tid,
                'b_ts': info.get('b_ts'),
                'e_ts': info.get('e_ts'),
                'duration_ms': round(info['duration'] * 1000, 3) if info.get('duration') is not None else None,
                'segment_count': info.get('segment_count', 0),
            }
            if info.get('b_ts') is not None:
                entry['rel_b'] = ts_to_rel_time(info['b_ts'], base_ts)
            if info.get('e_ts') is not None:
                entry['rel_e'] = ts_to_rel_time(info['e_ts'], base_ts)
            
            spans_data[tid_str].append(entry)
        
        # 每个 tid 内部按 b_ts 排序
        for tid_str in spans_data:
            spans_data[tid_str].sort(
                key=lambda x: x.get('b_ts') or 0
            )
        
        data['function_spans'] = spans_data
        data['total_spans'] = len(func_spans)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"已保存 {len(events)} 条匹配结果到 {filepath} (含 {len(func_spans) if func_spans else 0} 个函数跨度)")


def load_results(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    events = data['events']
    func_name_map = data.get('func_name_map', {})
    thread_segments = data.get('thread_segments', {})
    func_spans = data.get('function_spans', {})
    base_ts = data.get('base_timestamp', None)
    # 将 thread_segments key 转回 int
    thread_segments = {int(k): v for k, v in thread_segments.items()}
    return events, func_name_map, thread_segments, func_spans, base_ts


def print_stats(events, thread_segments, base_ts=None):
    total = len(events)
    if total == 0:
        print("无数据")
        return
    
    ts_all = [e['timestamp'] for e in events]
    min_ts_str = ts_to_rel_time(min(ts_all), base_ts) if base_ts else f"{min(ts_all):.6f}"
    max_ts_str = ts_to_rel_time(max(ts_all), base_ts) if base_ts else f"{max(ts_all):.6f}"
    
    print("=" * 60)
    print("  统计数据")
    print("=" * 60)
    print(f"  总唤醒次数:          {total}")
    print(f"  时间范围:            {min_ts_str} ~ {max_ts_str}")
    if base_ts:
        print(f"  基准时间戳:          {base_ts:.6f}")
    print(f"  已匹配 waker 函数:   {sum(1 for e in events if e.get('waker_func'))} "
          f"({sum(1 for e in events if e.get('waker_func'))/total*100:.1f}%)")
    print(f"  已匹配 wakee 函数:   {sum(1 for e in events if e.get('wakee_func'))} "
          f"({sum(1 for e in events if e.get('wakee_func'))/total*100:.1f}%)")
    print(f"  有 trace 标记的线程: {len(thread_segments)}")
    print(f"  唯一 waker 函数:     {len(set(e.get('waker_func','') for e in events if e.get('waker_func')))}")
    print(f"  唯一 wakee 函数:     {len(set(e.get('wakee_func','') for e in events if e.get('wakee_func')))}")
    print("=" * 60)


def print_grouped(events, by='waker_func', top_n=20):
    key_func = lambda e: display_name(e.get(by, '')) if e.get(by) else '(未匹配)'
    groups = defaultdict(lambda: {'count': 0})
    for e in events:
        key = key_func(e)
        groups[key]['count'] += 1
    
    sorted_groups = sorted(groups.items(), key=lambda x: x[1]['count'], reverse=True)[:top_n]
    
    title_map = {'waker_func': '按 Waker 函数分组', 'wakee_func': '按 Wakee 函数分组'}
    title = title_map.get(by, f'按 {by} 分组')
    
    print(f"\n{'='*70}")
    print(f"  {title} (Top {min(top_n, len(groups))})")
    print(f"{'='*70}")
    print(f"  {'排名':<5} {'函数名':<50} {'次数':>8}  {'占比':>8}")
    print(f"  {'-'*5} {'-'*50} {'-'*8} {'-'*8}")
    
    total = len(events)
    for i, (key, info) in enumerate(sorted_groups, 1):
        key_str = str(key)
        if len(key_str) > 50:
            key_str = key_str[:47] + "..."
        pct = info['count'] / total * 100
        print(f"  {i:<5} {key_str:<50} {info['count']:>8}  {pct:>7.2f}%")
    print(f"{'='*70}")


# ============================================================
# 主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Wakeup-Function Matcher - 匹配唤醒者函数',
    )
    parser.add_argument('-f', '--file', default='output.html', help='trace 文件')
    parser.add_argument('-o', '--output', default='wakeup_matched.json', help='匹配结果保存路径')
    parser.add_argument('--load', default=None, help='从已保存的 JSON 加载结果 (跳过解析)')
    parser.add_argument('--csv', action='store_true', help='CSV 格式输出')
    parser.add_argument('--top', type=int, default=None, help='显示前 N 条')
    parser.add_argument('--stats', action='store_true', help='显示统计')
    parser.add_argument('--by-waker-func', action='store_true', help='按 waker 函数分组')
    parser.add_argument('--by-wakee-func', action='store_true', help='按 wakee 函数分组')
    # 查询参数
    parser.add_argument('--query', nargs=2, metavar=('FROM_FUNC', 'TO_FUNC'),
                        help='查询函数A是否唤醒过函数B')
    parser.add_argument('--from-func', type=str, help='查询某函数唤醒了哪些函数')
    parser.add_argument('--to-func', type=str, help='查询哪些函数唤醒了某函数')
    parser.add_argument('--tid', type=int, help='查询指定线程相关的唤醒')
    # 函数跨度查询
    parser.add_argument('--list-spans', type=str, nargs='?', const='ALL', metavar='FILTER',
                        help='列出函数完整 B->E 跨度 (不受嵌套影响)。可选过滤函数名')
    parser.add_argument('--span-min-ms', type=float, default=1.0,
                        help='--list-spans 时过滤 display 的最小耗时(ms)')
    
    args = parser.parse_args()
    
    # ---- 加载或解析 ----
    base_ts = None
    func_spans = {}
    if args.load and os.path.exists(args.load):
        print(f"从缓存加载: {args.load}")
        events, func_name_map, thread_segments, func_spans, base_ts = load_results(args.load)
        # 兼容旧格式: 如果加载的数据没有 rel_time，补充之
        if base_ts and any('rel_time' not in e for e in events[:1]):
            for ev in events:
                ev['rel_time'] = ts_to_rel_time(ev['timestamp'], base_ts)
        # 兼容旧格式: 如果没有 func_spans，从 thread_segments 推算
        if not func_spans and thread_segments:
            print("  从 segments 推算函数跨度...")
            func_spans = {}
            for tid, segs in thread_segments.items():
                groups = defaultdict(list)
                for s in segs:
                    # segments 可能是 tuple (新解析) 或 dict (JSON加载)
                    if isinstance(s, dict):
                        uname = s['func_name']
                        start = s['start']
                        end = s['end']
                    else:
                        uname = s[2]
                        start = s[0]
                        end = s[1]
                    groups[uname].append((start, end))
                for uname, intervals in groups.items():
                    orig, pid, stid, b_ts = parse_unique_name(uname)
                    starts = [it[0] for it in intervals]
                    ends = [it[1] for it in intervals]
                    func_spans[uname] = {
                        'func_name': uname,
                        'original_name': orig,
                        'pid': pid,
                        'tid': stid,
                        'b_ts': min(starts),
                        'e_ts': max(ends),
                        'duration': max(ends) - min(starts),
                        'segment_count': len(intervals),
                    }
            print(f"  推算完成: {len(func_spans)} 个函数跨度")
    else:
        if not os.path.exists(args.file):
            print(f"错误: 文件不存在: {args.file}")
            sys.exit(1)
        
        print(f"读取 trace: {args.file}")
        lines = extract_trace_from_html(args.file)
        if lines is None:
            print("错误: 无法提取 trace 数据")
            sys.exit(1)
        
        # 计算基准时间戳
        print(f"计算基准时间戳...")
        base_ts = find_base_timestamp(lines)
        print(f"  基准时间戳: {base_ts:.6f}")
        
        print(f"步骤1: 构建函数执行时间线 ({len(lines)} 行)...")
        thread_segments, func_spans, func_name_map, ub, ue = build_function_timelines(lines)
        total_segs = sum(len(v) for v in thread_segments.values())
        print(f"  完成: {len(thread_segments)} 个线程, {total_segs} 个函数时间段")
        if ub or ue:
            print(f"  警告: {ub} 个 B 无匹配 E, {ue} 个 E 无匹配 B")
        
        print(f"步骤2: 提取唤醒关系...")
        events = extract_wakeup_events(lines)
        print(f"  完成: {len(events)} 次唤醒")
        
        # 为每个事件添加相对时间
        for ev in events:
            ev['rel_time'] = ts_to_rel_time(ev['timestamp'], base_ts)
        
        print(f"步骤3: 匹配 waker 函数...")
        matched, unmatched = match_waker_functions(events, thread_segments)
        print(f"  完成: {matched} 匹配, {unmatched} 未匹配")
        
        # 保存 (包含 thread_segments, func_spans 和 base_ts)
        save_results(events, args.output, func_name_map, thread_segments,
                     func_spans, base_ts)
    
    # ---- 查询 ----
    if args.query:
        from_f, to_f = args.query
        results = query_by_func_pair(events, from_f, to_f)
        print(f"\n查询: '{from_f}' → '{to_f}'")
        print(f"找到 {len(results)} 条匹配")
        if results:
            print_table(results, args.top or 20, base_ts)
        return
    
    if args.from_func:
        results = query_from_func(events, args.from_func)
        print(f"\n查询: 函数 '{args.from_func}' 唤醒了 {len(results)} 次")
        if results:
            # 按 wakee_func 分组
            by_target = defaultdict(int)
            for e in results:
                by_target[e.get('wakee_func', '') or '(无)'] += 1
            print("  唤醒目标分布:")
            for func, cnt in sorted(by_target.items(), key=lambda x: x[1], reverse=True)[:15]:
                print(f"    {func:<50s} {cnt} 次")
            print_table(results, args.top or 20, base_ts)
        return
    
    if args.to_func:
        results = query_to_func(events, args.to_func)
        print(f"\n查询: 被 '{args.to_func}' 的唤醒有 {len(results)} 次")
        if results:
            by_source = defaultdict(int)
            for e in results:
                by_source[e.get('waker_func', '') or '(无)'] += 1
            print("  唤醒来源分布:")
            for func, cnt in sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:15]:
                print(f"    {func:<50s} {cnt} 次")
            print_table(results, args.top or 20, base_ts)
        return
    
    if args.tid:
        results = query_by_tid(events, args.tid)
        as_waker = [e for e in results if e['waker_tid'] == args.tid]
        as_wakee = [e for e in results if e['wakee_pid'] == args.tid]
        print(f"\n线程 {args.tid}: 共 {len(results)} 条 (waker: {len(as_waker)}, wakee: {len(as_wakee)})")
        print_table(results, args.top or 30, base_ts)
        return
    
    # ---- 显示函数跨度 (完整的 B→E 时间，不受嵌套影响) ----
    if args.list_spans is not None:
        filter_str = args.list_spans if args.list_spans != 'ALL' else ''
        min_ms = args.span_min_ms
        
        # 收集所有 func_spans
        all_spans = []
        if func_spans:
            # func_spans 是 dict: {unique_name: {...}}
            for uname, info in func_spans.items():
                dur = info.get('duration')
                if dur is None:
                    continue
                dur_ms = dur * 1000
                if dur_ms < min_ms:
                    continue
                orig = info.get('original_name', '')
                if filter_str:
                    try:
                        if not (re.search(filter_str, orig or '') or re.search(filter_str, uname)):
                            continue
                    except re.error:
                        # 不是合法正则，fallback 到子串匹配
                        if filter_str not in (orig or '') and filter_str not in uname:
                            continue
                all_spans.append((dur_ms, orig, info))
        
        all_spans.sort(key=lambda x: x[0], reverse=True)
        top_n = args.top or 50
        
        print(f"\n{'='*90}")
        print(f"  函数完整跨度 (B→E, 不受嵌套调用影响)")
        if filter_str:
            print(f"  过滤: '{filter_str}'")
        print(f"  最小显示耗时: {min_ms}ms")
        print(f"{'='*90}")
        print(f"  {'耗时(ms)':>10}  {'段数':>5}  {'TID':>7}  {'PID':>7}  {'函数名'}")
        print(f"  {'-'*10}  {'-'*5}  {'-'*7}  {'-'*7}  {'-'*50}")
        
        shown = 0
        for dur_ms, orig, info in all_spans[:top_n]:
            seg_cnt = info.get('segment_count', 0)
            tid = info.get('tid', '?')
            pid = info.get('pid', '?')
            name = (orig or uname)[:50]
            # 被切多段时加标记
            frag = f" [{seg_cnt}段]" if seg_cnt > 1 else ""
            print(f"  {dur_ms:>10.3f}  {seg_cnt:>5}  {str(tid):>7}  {str(pid):>7}  {name}{frag}")
        
        total_shown = min(len(all_spans), top_n)
        print(f"  {'-'*10}  {'-'*5}  {'-'*7}  {'-'*7}  {'-'*50}")
        print(f"  显示 {total_shown}/{len(all_spans)} 条 (过滤条件: >={min_ms}ms)")
        return
    
    # ---- 默认: 显示概览 ----
    if args.stats or not any([args.by_waker_func, args.by_wakee_func]):
        print_stats(events, thread_segments, base_ts)
    
    if args.by_waker_func:
        print_grouped(events, 'waker_func', args.top or 20)
    if args.by_wakee_func:
        print_grouped(events, 'wakee_func', args.top or 20)
    
    if not any([args.stats, args.by_waker_func, args.by_wakee_func, args.query,
                args.from_func, args.to_func, args.tid, args.list_spans]):
        print_table(events, args.top or 20, base_ts)


if __name__ == '__main__':
    main()
