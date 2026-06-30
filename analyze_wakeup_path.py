#!/usr/bin/env python3
"""
Android Systrace Wakeup Path + State Analyzer
从函数 A 到函数 B，找到唤醒路径，并统计每跳的线程状态耗时。

状态机:
  BLOCKED(S) ──[waking]──→ RUNNABLE(R) ──[switch in]──→ RUNNING ──[switch out]──→ RUNNABLE/BLOCKED/IO

用法:
    python3 analyze_wakeup_path.py output.html --from "funcA" --to "funcB"
    python3 analyze_wakeup_path.py output.html --list-funcs              # 列出所有函数
    python3 analyze_wakeup_path.py output.html --html path.html          # 任意两函数间找路径
"""

import sys, re, json, argparse
from collections import defaultdict, Counter, deque
import bisect

# ============================================================
# 正则
# ============================================================
SCHED_WAKING_RE = re.compile(
    r'^\s*(\S+?)-(\d+)\s*\([^)]*\)\s*\[(\d+)\]\s*\S+\s+([\d.]+):\s+sched_waking:\s+'
    r'comm=(\S+)\s+pid=(\d+)\s+prio=(\d+)\s+target_cpu=(\d+)'
)
SCHED_WAKEUP_RE = re.compile(
    r'^\s*(\S+?)-(\d+)\s*\([^)]*\)\s*\[(\d+)\]\s*\S+\s+([\d.]+):\s+sched_wakeup:\s+'
    r'comm=(\S+)\s+pid=(\d+)\s+prio=(\d+)\s+target_cpu=(\d+)'
)
SCHED_WAKEUP_NEW_RE = re.compile(
    r'^\s*(\S+?)-(\d+)\s*\([^)]*\)\s*\[(\d+)\]\s*\S+\s+([\d.]+):\s+sched_wakeup_new:\s+'
    r'comm=(\S+)\s+pid=(\d+)\s+prio=(\d+)\s+target_cpu=(\d+)'
)
SCHED_SWITCH_RE = re.compile(
    r'^\s*(\S+?)-(\d+)\s*\([^)]*\)\s*\[(\d+)\]\s*\S+\s+([\d.]+):\s+sched_switch:\s+'
    r'prev_comm=(\S+)\s+prev_pid=(\d+)\s+prev_prio=(\d+)\s+prev_state=(\S+)\s+'
    r'==>\s+next_comm=(\S+)\s+next_pid=(\d+)\s+next_prio=(\d+)'
)
TRACE_B_RE = re.compile(
    r'^\s*(\S+?)-(\d+)\s*\([^)]*\)\s*\[(\d+)\]\s*\S+\s+([\d.]+):\s+tracing_mark_write:\s+B\|(\d+)\|(.+)'
)
TRACE_E_RE = re.compile(
    r'^\s*(\S+?)-(\d+)\s*\([^)]*\)\s*\[(\d+)\]\s*\S+\s+([\d.]+):\s+tracing_mark_write:\s+E\|(\d+)'
)

# 状态编码
STATE_RUNNING = 0
STATE_RUNNABLE = 1
STATE_BLOCKED = 2
STATE_IO_BLOCKED = 3
STATE_OTHER = 4

STATE_NAMES = {0: 'RUNNING', 1: 'RUNNABLE', 2: 'BLOCKED(S)', 3: 'IO_BLOCK(D)', 4: 'OTHER'}

def prev_state_to_code(s):
    if s == 'R' or s == 'R+':
        return STATE_RUNNABLE
    elif s == 'S':
        return STATE_BLOCKED
    elif s == 'D':
        return STATE_IO_BLOCKED
    else:
        return STATE_OTHER


def parse_all(filepath):
    """
    单次流式解析所有事件，构建:
      - wakeup_edges: [(waker_pid, wakee_pid, ts), ...]    (去重 waking/wakeup 对)
      - state_segs:   {pid: [(start, end, state_code), ...]}  按 start 排序
      - func_segs:    {pid: [(start, end, func_idx), ...]}   按 start 排序
      - pid_comm:     {pid: comm}
      - func_names:   ["func1", "func2", ...]
    """
    wakeup_edges = []
    state_segs = defaultdict(list)     # pid -> [(start, end, state), ...]
    func_segs = defaultdict(list)      # pid -> [(start, end, func_idx), ...]
    pid_comm = {}
    func_names = []                    # index -> name
    func_name_to_idx = {}              # name -> index
    
    # 状态跟踪: pid -> (current_state, state_start_ts)
    cur_state = {}
    
    # pending func B events: pid -> (start_ts, func_idx)
    pending_func = {}
    
    # 唤醒去重: (waker, wakee) -> (ts, type)  
    wake_pending = {}
    
    # 上一个时间戳 (用于关闭区间)
    last_ts = None
    
    def close_state(pid, ts):
        """关闭 pid 的当前状态区间"""
        if pid in cur_state:
            prev_st, prev_start = cur_state[pid]
            if ts > prev_start:
                state_segs[pid].append((prev_start, ts, prev_st))
            del cur_state[pid]
    
    def set_state(pid, ts, new_state):
        """设置 pid 的新状态, 先关闭旧区间"""
        close_state(pid, ts)
        cur_state[pid] = (new_state, ts)
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            # ── sched_switch ──
            if 'sched_switch:' in line:
                m = SCHED_SWITCH_RE.match(line)
                if not m:
                    continue
                prev_comm = m.group(1).strip()
                prev_pid = int(m.group(2))
                ts = float(m.group(4))
                prev_state_str = m.group(8).strip()
                next_comm = m.group(9).strip()
                next_pid = int(m.group(10))
                
                pid_comm[prev_pid] = prev_comm
                pid_comm[next_pid] = next_comm
                
                # prev thread: RUNNING → (prev_state)
                prev_code = prev_state_to_code(prev_state_str)
                set_state(prev_pid, ts, prev_code)
                
                # next thread: → RUNNING
                set_state(next_pid, ts, STATE_RUNNING)
                
                last_ts = ts
                continue
            
            # ── sched_waking/wakeup ──
            if 'sched_waking:' in line or 'sched_wakeup:' in line or 'sched_wakeup_new:' in line:
                m = SCHED_WAKING_RE.match(line)
                etype = 'waking'
                if not m:
                    m = SCHED_WAKEUP_RE.match(line)
                    etype = 'wakeup'
                if not m:
                    m = SCHED_WAKEUP_NEW_RE.match(line)
                    etype = 'wakeup_new'
                if not m:
                    continue
                
                waker_comm = m.group(1).strip()
                waker_pid = int(m.group(2))
                ts = float(m.group(4))
                wakee_comm = m.group(5).strip()
                wakee_pid = int(m.group(6))
                
                pid_comm[waker_pid] = waker_comm
                pid_comm[wakee_pid] = wakee_comm
                
                # 唤醒: wakee BLOCKED → RUNNABLE
                set_state(wakee_pid, ts, STATE_RUNNABLE)
                
                # 去重 waking/wakeup 对
                key = (waker_pid, wakee_pid)
                if key in wake_pending:
                    prev_ts, _ = wake_pending[key]
                    wakeup_edges.append((waker_pid, wakee_pid, min(ts, prev_ts)))
                    del wake_pending[key]
                else:
                    wake_pending[key] = (ts, etype)
                
                last_ts = ts
                continue
            
            # ── tracing_mark_write B ──
            if 'tracing_mark_write: B|' in line or 'tracing_mark_write:B|' in line:
                m = TRACE_B_RE.match(line)
                if not m:
                    continue
                ts = float(m.group(4))
                pid = int(m.group(5))
                func = m.group(6).strip()
                comm = m.group(1).strip()
                pid_comm[pid] = comm
                
                # intern func name
                if func not in func_name_to_idx:
                    func_name_to_idx[func] = len(func_names)
                    func_names.append(func)
                fidx = func_name_to_idx[func]
                
                # close previous pending B for this pid (unmatched)
                if pid in pending_func:
                    prev_start, prev_fidx = pending_func[pid]
                    if ts > prev_start:
                        func_segs[pid].append((prev_start, ts, prev_fidx))
                pending_func[pid] = (ts, fidx)
                
                last_ts = ts
                continue
            
            # ── tracing_mark_write E ──
            if 'tracing_mark_write: E|' in line or 'tracing_mark_write:E|' in line:
                m = TRACE_E_RE.match(line)
                if not m:
                    continue
                ts = float(m.group(4))
                pid = int(m.group(5))
                
                if pid in pending_func:
                    prev_start, prev_fidx = pending_func[pid]
                    if ts > prev_start:
                        func_segs[pid].append((prev_start, ts, prev_fidx))
                    del pending_func[pid]
                
                last_ts = ts
                continue
    
    # 关闭所有未完成的状态区间
    if last_ts is not None:
        for pid in list(cur_state.keys()):
            close_state(pid, last_ts + 0.001)
    
    # 未配对的唤醒也加入
    for (waker, wakee), (ts, _) in wake_pending.items():
        wakeup_edges.append((waker, wakee, ts))
    
    # 排序
    for pid in state_segs:
        state_segs[pid].sort(key=lambda x: x[0])
    for pid in func_segs:
        func_segs[pid].sort(key=lambda x: x[0])
    wakeup_edges.sort(key=lambda x: x[2])
    
    return wakeup_edges, state_segs, func_segs, pid_comm, func_names


def annotate_wakeup_edges(wakeup_edges, func_segs, pid_comm, func_names):
    """
    为每条唤醒边标注 waker 当时正在执行的函数。
    返回: [(waker_pid, wakee_pid, ts, func_name_or_None), ...]
    """
    annotated = []
    for waker, wakee, ts in wakeup_edges:
        func = None
        segs = func_segs.get(waker, [])
        if segs:
            # 二分查找 ts 所在的函数区间
            lo, hi = 0, len(segs)
            while lo < hi:
                mid = (lo + hi) // 2
                if segs[mid][0] <= ts:
                    lo = mid + 1
                else:
                    hi = mid
            # 检查前一个区间是否包含 ts
            for i in range(lo - 1, max(lo - 4, -1), -1):
                if i < 0:
                    break
                start, end, fidx = segs[i]
                if start <= ts <= end:
                    func = func_names[fidx]
                    break
        annotated.append((waker, wakee, ts, func))
    return annotated


def build_graph(annotated_edges):
    """
    构建邻接表, 用于路径搜索。
    out_edges[pid] = [(wakee_pid, ts, func), ...]
    in_edges[pid] = [(waker_pid, ts, func), ...]
    """
    out_edges = defaultdict(list)
    in_edges = defaultdict(list)
    for waker, wakee, ts, func in annotated_edges:
        out_edges[waker].append((wakee, ts, func))
        in_edges[wakee].append((waker, ts, func))
    return out_edges, in_edges


def find_path(out_edges, in_edges, start_pids, end_pids, max_depth=15):
    """
    BFS 从 start_pids 出发, 找到到达任意 end_pid 的最短路径。
    返回: [(pid1, pid2, ts, func), ...]  每跳的边信息
    """
    start_set = set(start_pids)
    end_set = set(end_pids)
    
    # BFS: 搜索跨线程唤醒路径
    visited = set(start_pids)
    q = deque()
    for pid in start_pids:
        q.append((pid, []))
    
    while q:
        pid, path = q.popleft()
        if len(path) >= max_depth:
            continue
        
        for wakee, ts, func in out_edges.get(pid, []):
            if wakee in visited:
                continue
            visited.add(wakee)
            new_path = path + [(pid, wakee, ts, func)]
            if wakee in end_set:
                return new_path
            q.append((wakee, new_path))
    
    return None  # no path found


def compute_hop_durations(path, state_segs, func_segs, pid_comm, func_names):
    """
    对于路径中的每跳, 计算 waker 和 wakee 在唤醒时刻前后的状态耗时。
    
    返回: [{
        'hop': i,
        'waker': {pid, comm, func, running_ms, runnable_ms, blocked_ms, io_ms},
        'wakee': {pid, comm, func, running_ms, runnable_ms, blocked_ms, io_ms},
        'wake_ts': ts,
        'gap_us': wakee 从 wake 到实际 run 的延迟,
    }, ...]
    """
    def get_state_duration(pid, around_ts, window_ms=50):
        """获取 pid 在 around_ts 前后 window_ms 内的状态耗时"""
        segs = state_segs.get(pid, [])
        if not segs:
            return {'running': 0, 'runnable': 0, 'blocked': 0, 'io': 0}
        
        w_start = around_ts - window_ms / 1000.0
        w_end = around_ts + window_ms / 1000.0
        
        running = runnable = blocked = io = 0.0
        
        for start, end, state in segs:
            if end < w_start:
                continue
            if start > w_end:
                break
            # 重叠区间
            overlap_start = max(start, w_start)
            overlap_end = min(end, w_end)
            if overlap_end > overlap_start:
                dur = overlap_end - overlap_start
                if state == STATE_RUNNING:
                    running += dur
                elif state == STATE_RUNNABLE:
                    runnable += dur
                elif state == STATE_BLOCKED:
                    blocked += dur
                elif state == STATE_IO_BLOCKED:
                    io += dur
        
        return {
            'running': running * 1000,    # ms
            'runnable': runnable * 1000,
            'blocked': blocked * 1000,
            'io': io * 1000,
        }
    
    def get_func_at(pid, ts):
        """获取 pid 在 ts 时刻执行的函数"""
        segs = func_segs.get(pid, [])
        lo, hi = 0, len(segs)
        while lo < hi:
            mid = (lo + hi) // 2
            if segs[mid][0] <= ts:
                lo = mid + 1
            else:
                hi = mid
        for i in range(lo - 1, max(lo - 4, -1), -1):
            if i < 0:
                break
            start, end, fidx = segs[i]
            if start <= ts <= end:
                return func_names[fidx]
        return None
    
    def find_wakee_running_ts(wakee_pid, after_ts):
        """找到 wakee 在 after_ts 之后第一次进入 RUNNING 的时间"""
        segs = state_segs.get(wakee_pid, [])
        for start, end, state in segs:
            if start >= after_ts and state == STATE_RUNNING:
                return start
            if start > after_ts + 0.1:  # 100ms 上限
                break
        return None

    def find_first_func_after(pid, after_ts, max_gap=0.02):
        """找到 pid 在 after_ts 之后第一个 atrace 函数 (20ms 内)"""
        segs = func_segs.get(pid, [])
        for start, end, fidx in segs:
            if start >= after_ts and start - after_ts <= max_gap:
                return func_names[fidx], start
            if start > after_ts + max_gap:
                break
        return None, None

    def find_last_func_before(pid, before_ts, max_gap=0.02):
        """找到 pid 在 before_ts 之前最后一个 atrace 函数 (20ms 内)"""
        segs = func_segs.get(pid, [])
        best = None
        for start, end, fidx in segs:
            if end <= before_ts and before_ts - end <= max_gap:
                best = (func_names[fidx], end)
            if start > before_ts:
                break
        return best if best else (None, None)

    results = []
    seen_pids = set()  # 去重用：每个线程只记录第一个出现时的函数
    for i, (waker_pid, wakee_pid, ts, func_on_edge) in enumerate(path):
        waker_comm = pid_comm.get(waker_pid, f'?{waker_pid}')
        wakee_comm = pid_comm.get(wakee_pid, f'?{wakee_pid}')
        
        # waker 状态 (唤醒时刻前后)
        waker_state = get_state_duration(waker_pid, ts)
        waker_func = func_on_edge or get_func_at(waker_pid, ts)
        
        # wakee 状态 (被唤醒时刻前后)
        wakee_state = get_state_duration(wakee_pid, ts)
        wakee_func_at_wake = get_func_at(wakee_pid, ts)
        
        # gap: 被唤醒 → 真正上 CPU 的延迟
        run_ts = find_wakee_running_ts(wakee_pid, ts)
        gap_us = (run_ts - ts) * 1_000_000 if run_ts else None
        
        # wakee 上 CPU 后执行的第一个函数
        wakee_func_after, wakee_func_after_ts = find_first_func_after(wakee_pid, ts)
        
        # waker 在被唤醒前执行的最后一个函数 (仅第一跳的 waker 记录)
        waker_func_before = None
        if waker_pid not in seen_pids:
            waker_func_before, _ = find_last_func_before(waker_pid, ts)
        
        seen_pids.add(waker_pid)
        seen_pids.add(wakee_pid)
        
        results.append({
            'hop': i + 1,
            'ts': ts,
            'waker': {
                'pid': waker_pid, 'comm': waker_comm,
                'func': waker_func,
                'func_before': waker_func_before,
                'running_ms': round(waker_state['running'], 3),
                'runnable_ms': round(waker_state['runnable'], 3),
                'blocked_ms': round(waker_state['blocked'], 3),
                'io_ms': round(waker_state['io'], 3),
            },
            'wakee': {
                'pid': wakee_pid, 'comm': wakee_comm,
                'func': wakee_func_at_wake,
                'func_after': wakee_func_after,
                'running_ms': round(wakee_state['running'], 3),
                'runnable_ms': round(wakee_state['runnable'], 3),
                'blocked_ms': round(wakee_state['blocked'], 3),
                'io_ms': round(wakee_state['io'], 3),
            },
            'gap_us': round(gap_us, 1) if gap_us else None,
        })
    
    return results


def find_threads_by_func(func_segs, func_names, target_func):
    """找到所有执行过 target_func 的 pid"""
    if target_func not in func_names:
        # 模糊匹配
        matches = [n for n in func_names if target_func.lower() in n.lower()]
        if not matches:
            return []
        pids = set()
        for m in matches:
            idx = func_names.index(m)
            for pid, segs in func_segs.items():
                for _, _, fidx in segs:
                    if fidx == idx:
                        pids.add(pid)
                        break
        return list(pids)
    
    idx = func_names.index(target_func)
    pids = set()
    for pid, segs in func_segs.items():
        for _, _, fidx in segs:
            if fidx == idx:
                pids.add(pid)
                break
    return list(pids)


def print_path_report(path, durations, pid_comm, t_min):
    """打印人类可读的路径报告"""
    print()
    print("=" * 80)
    print("  🔗 唤醒路径 + 线程状态耗时分析")
    print("=" * 80)
    
    if not path:
        print("  ❌ 未找到路径")
        return
    
    total_running = 0
    total_runnable = 0
    total_blocked = 0
    total_io = 0
    
    for hop in durations:
        w = hop['waker']
        e = hop['wakee']
        dt = hop['ts'] - t_min
        
        print(f"\n  ── 跳 #{hop['hop']} @ {dt:.6f}s ──")
        
        # waker
        print(f"  🔵 唤醒者: {w['comm']}({w['pid']})")
        if w.get('func_before'):
            print(f"     (之前) {w['func_before']}")
        if w['func']:
            print(f"     ⚡唤醒时: {w['func']}")
        else:
            print(f"     ⚡唤醒时: (内核线程, 无 atrace)")
        print(f"     RUNNING:  {w['running_ms']:>8.3f} ms")
        print(f"     RUNNABLE: {w['runnable_ms']:>8.3f} ms")
        print(f"     BLOCKED:  {w['blocked_ms']:>8.3f} ms")
        print(f"     IO_BLOCK: {w['io_ms']:>8.3f} ms")
        
        # arrow
        gap_str = f" 唤醒 gap: {hop['gap_us']:.1f} µs" if hop['gap_us'] else ""
        print(f"       ⬇ {gap_str}")
        
        # wakee
        print(f"  🟢 被唤醒: {e['comm']}({e['pid']})")
        if e['func']:
            print(f"     (唤醒时) {e['func']}")
        if e.get('func_after'):
            print(f"     ▶ 上CPU后: {e['func_after']}")
        print(f"     RUNNING:  {e['running_ms']:>8.3f} ms")
        print(f"     RUNNABLE: {e['runnable_ms']:>8.3f} ms")
        print(f"     BLOCKED:  {e['blocked_ms']:>8.3f} ms")
        print(f"     IO_BLOCK: {e['io_ms']:>8.3f} ms")
        
        total_running += w['running_ms'] + e['running_ms']
        total_runnable += w['runnable_ms'] + e['runnable_ms']
        total_blocked += w['blocked_ms'] + e['blocked_ms']
        total_io += w['io_ms'] + e['io_ms']
    
    # ── 函数链总结 ──
    print(f"\n  {'─' * 60}")
    print(f"  🔗 函数唤醒链 (可在 trace 中搜索核对):")
    for i, hop in enumerate(durations):
        w = hop['waker']
        e = hop['wakee']
        wf = w.get('func') or w.get('func_before') or f'({w["comm"]})'
        ef = e.get('func_after') or e.get('func') or f'({e["comm"]})'
        print(f"  {wf}  ──唤醒──→  {ef}")
    print(f"  {'─' * 60}")
    
    print(f"\n  {'─' * 60}")
    print(f"  📊 路径总计 ({len(durations)} 跳, {len(durations) + 1} 线程):")
    print(f"     RUNNING:  {total_running:>8.3f} ms")
    print(f"     RUNNABLE: {total_runnable:>8.3f} ms")
    print(f"     BLOCKED:  {total_blocked:>8.3f} ms")
    print(f"     IO_BLOCK: {total_io:>8.3f} ms")
    print(f"  {'─' * 60}")
    print()


# ============================================================
# HTML 生成
# ============================================================

PATH_HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>唤醒路径分析</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;max-width:960px;margin:0 auto}
h1{color:#58a6ff;font-size:1.1em;margin-bottom:4px}
.sub{color:#8b949e;font-size:.7em;margin-bottom:20px}

.search-row{display:flex;gap:12px;margin-bottom:16px;align-items:center;flex-wrap:wrap}
.search-row input{flex:1;min-width:160px;padding:6px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;font-size:.78em;outline:none}
.search-row input:focus{border-color:#58a6ff}
.search-row button{padding:6px 16px;background:#238636;border:none;border-radius:5px;color:#fff;font-size:.78em;cursor:pointer}
.search-row button:hover{background:#2ea043}
.suggestions{position:absolute;background:#21262d;border:1px solid #30363d;border-radius:5px;max-height:180px;overflow-y:auto;z-index:100;display:none;font-size:.7em;min-width:200px}
.suggestions.show{display:block}
.suggest-item{padding:4px 8px;cursor:pointer;border-bottom:1px solid #1c2128}
.suggest-item:hover{background:#1f6feb33}
.input-wrap{position:relative;flex:1;min-width:160px}

.path-card{border:1px solid #21262d;border-radius:8px;margin-bottom:12px;overflow:hidden}
.path-card-header{padding:8px 14px;background:#21262d;font-size:.75em;color:#8b949e;display:flex;justify-content:space-between}
.hop-row{display:flex;padding:10px 14px;border-bottom:1px solid #1c2128;gap:12px;align-items:flex-start}
.hop-row:last-child{border-bottom:none}
.hop-arrow{flex:0 0 30px;text-align:center;color:#58a6ff;font-size:1.2em;padding-top:4px}
.hop-info{flex:1;min-width:0}

.thread-block{display:inline-block;padding:3px 0}
.thread-waker{color:#f0883e;font-weight:600;font-size:.82em}
.thread-wakee{color:#7ee787;font-weight:600;font-size:.82em}
.thread-func{color:#a371f7;font-size:.75em;margin-top:2px}
.thread-no-func{color:#484f58;font-size:.75em;margin-top:2px;font-style:italic}

.state-bars{display:grid;grid-template-columns:repeat(4,1fr);gap:2px;margin-top:3px}
.state-bar-item{text-align:center;font-size:.62em}
.state-bar-item .val{font-weight:600;font-size:1.1em}
.state-bar-item .lbl{color:#8b949e}
.state-running .val{color:#3fb950}
.state-runnable .val{color:#d29922}
.state-blocked .val{color:#8b949e}
.state-io .val{color:#f85149}

.gap-info{font-size:.6em;color:#484f58;margin-top:3px}

.summary{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin-top:16px}
.summary h3{color:#58a6ff;font-size:.8em;margin-bottom:8px}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.summary-item{text-align:center}
.summary-item .val{font-size:1.1em;font-weight:600}
.summary-item .lbl{font-size:.6em;color:#8b949e}

.no-result{color:#484f58;text-align:center;padding:40px;font-size:.8em}

::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d}
</style>
</head>
<body>
<h1>⚡ 唤醒路径 + 线程状态分析</h1>
<div class="sub">从函数 A 的线程 → 逐跳唤醒链 → 函数 B 的线程 · 每跳统计 RUNNING / RUNNABLE / BLOCKED / IO_BLOCK</div>

<div class="search-row">
  <div class="input-wrap">
    <input type="text" id="from-input" placeholder="起始函数名..." autocomplete="off">
    <div class="suggestions" id="from-sug"></div>
  </div>
  <span style="color:#58a6ff">→</span>
  <div class="input-wrap">
    <input type="text" id="to-input" placeholder="目标函数名..." autocomplete="off">
    <div class="suggestions" id="to-sug"></div>
  </div>
  <button id="find-btn">🔍 找路径</button>
</div>

<div id="result"></div>
<div class="summary" id="summary" style="display:none"></div>

<script>
var FUNC_LIST = __FUNC_LIST__;
var TT = __TT__;  // {t_min}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ============ 搜索建议 ============
function setupSearch(inputId, sugId) {
  var inp = document.getElementById(inputId), sug = document.getElementById(sugId);
  inp.addEventListener('input', function() {
    var q = this.value.toLowerCase().trim();
    if (!q) { sug.classList.remove('show'); return; }
    var r = FUNC_LIST.filter(function(f) { return f.toLowerCase().indexOf(q) >= 0; }).slice(0, 12);
    if (!r.length) { sug.classList.remove('show'); return; }
    sug.innerHTML = r.map(function(f) { return '<div class="suggest-item" data-func="' + esc(f) + '">' + esc(f) + '</div>'; }).join('');
    sug.classList.add('show');
  });
  sug.addEventListener('click', function(e) {
    var it = e.target.closest('.suggest-item'); if (!it) return;
    inp.value = it.dataset.func; sug.classList.remove('show');
  });
  inp.addEventListener('blur', function() { setTimeout(function() { sug.classList.remove('show'); }, 200); });
}
setupSearch('from-input', 'from-sug');
setupSearch('to-input', 'to-sug');

// ============ 找路径 ============
document.getElementById('find-btn').addEventListener('click', function() {
  var from = document.getElementById('from-input').value.trim();
  var to = document.getElementById('to-input').value.trim();
  if (!from || !to) return;
  document.getElementById('find-btn').textContent = '⏳ 搜索中...';
  document.getElementById('find-btn').disabled = true;
  
  // 发送给父页面处理 (或自己处理如果有数据)
  fetch('?from=' + encodeURIComponent(from) + '&to=' + encodeURIComponent(to))
    .catch(function() {});
  
  // 用动态脚本方式: 无法在静态HTML中做, 改为提示
  document.getElementById('result').innerHTML = 
    '<div class="no-result">请在终端运行:<br><code>python3 analyze_wakeup_path.py output.html --from "' + esc(from) + '" --to "' + esc(to) + '" --html result.html</code></div>';
  document.getElementById('find-btn').textContent = '🔍 找路径';
  document.getElementById('find-btn').disabled = false;
});

// ============ 渲染结果 (如果嵌入了数据) ============
var PATH_DATA = __PATH_DATA__;
if (PATH_DATA) {
  renderPath(PATH_DATA);
}

function renderPath(data) {
  var html = '', total = {running:0, runnable:0, blocked:0, io:0};
  
  if (!data.hops || !data.hops.length) {
    document.getElementById('result').innerHTML = '<div class="no-result">❌ 未找到路径</div>';
    return;
  }
  
  html += '<div class="path-card"><div class="path-card-header">路径: ' + data.from + ' → ' + data.to + ' (' + data.hops.length + ' 跳, ' + (data.hops.length+1) + ' 线程)</div>';
  
  data.hops.forEach(function(hop) {
    var w = hop.waker, e = hop.wakee;
    var dt = (hop.ts - TT.t_min).toFixed(6);
    
    html += '<div class="hop-row">';
    html += '<div class="hop-arrow">' + hop.hop + '</div>';
    html += '<div class="hop-info">';
    
    // waker
    html += '<div class="thread-block"><span class="thread-waker">' + esc(w.comm) + '(' + w.pid + ')</span>';
    if (w.func_before) html += '<div class="thread-func" style="opacity:0.7">(之前) ' + esc(w.func_before) + '</div>';
    if (w.func) html += '<div class="thread-func">⚡唤醒时: ' + esc(w.func) + '</div>';
    else html += '<div class="thread-no-func">(内核线程, 无 atrace)</div>';
    html += '<div class="state-bars">';
    html += '<div class="state-bar-item state-running"><span class="val">' + w.running_ms.toFixed(2) + '</span><span class="lbl">ms RUNNING</span></div>';
    html += '<div class="state-bar-item state-runnable"><span class="val">' + w.runnable_ms.toFixed(2) + '</span><span class="lbl">ms RUNNABLE</span></div>';
    html += '<div class="state-bar-item state-blocked"><span class="val">' + w.blocked_ms.toFixed(2) + '</span><span class="lbl">ms BLOCKED</span></div>';
    html += '<div class="state-bar-item state-io"><span class="val">' + w.io_ms.toFixed(2) + '</span><span class="lbl">ms IO_BLOCK</span></div>';
    html += '</div></div>';
    
    // gap
    html += '<div class="gap-info" style="text-align:center;padding:2px 0">⬇ 唤醒 @' + dt + 's';
    if (hop.gap_us !== null) html += ' · gap: ' + hop.gap_us.toFixed(1) + ' µs';
    html += '</div>';
    
    // wakee
    html += '<div class="thread-block"><span class="thread-wakee">' + esc(e.comm) + '(' + e.pid + ')</span>';
    if (e.func) html += '<div class="thread-func" style="opacity:0.7">(唤醒时) ' + esc(e.func) + '</div>';
    if (e.func_after) html += '<div class="thread-func">▶ 上CPU后: ' + esc(e.func_after) + '</div>';
    html += '<div class="state-bars">';
    html += '<div class="state-bar-item state-running"><span class="val">' + e.running_ms.toFixed(2) + '</span><span class="lbl">ms RUNNING</span></div>';
    html += '<div class="state-bar-item state-runnable"><span class="val">' + e.runnable_ms.toFixed(2) + '</span><span class="lbl">ms RUNNABLE</span></div>';
    html += '<div class="state-bar-item state-blocked"><span class="val">' + e.blocked_ms.toFixed(2) + '</span><span class="lbl">ms BLOCKED</span></div>';
    html += '<div class="state-bar-item state-io"><span class="val">' + e.io_ms.toFixed(2) + '</span><span class="lbl">ms IO_BLOCK</span></div>';
    html += '</div></div>';
    
    html += '</div></div>';
    
    total.running += w.running_ms + e.running_ms;
    total.runnable += w.runnable_ms + e.runnable_ms;
    total.blocked += w.blocked_ms + e.blocked_ms;
    total.io += w.io_ms + e.io_ms;
  });
  
  html += '</div>';
  document.getElementById('result').innerHTML = html;
  
  // summary
  document.getElementById('summary').style.display = 'block';
  var chainHtml = '<h3>🔗 函数唤醒链 (可在 trace 中搜索核对)</h3><div style="font-size:.75em;line-height:1.8;padding:4px 0">';
  data.hops.forEach(function(hop, i) {
    var wf = hop.waker.func || hop.waker.func_before || '(' + hop.waker.comm + ')';
    var ef = hop.wakee.func_after || hop.wakee.func || '(' + hop.wakee.comm + ')';
    chainHtml += '<span style="color:#a371f7">' + esc(wf) + '</span>' +
                 ' <span style="color:#58a6ff">──唤醒──→</span> ' +
                 '<span style="color:#7ee787">' + esc(ef) + '</span>';
    if (hop.gap_us !== null) chainHtml += ' <span style="color:#484f58;font-size:.85em">(' + hop.gap_us.toFixed(0) + 'µs)</span>';
    if (i < data.hops.length - 1) chainHtml += '<br>';
  });
  chainHtml += '</div>';
  document.getElementById('summary').innerHTML = chainHtml +
    '<h3 style="margin-top:12px">📊 路径总计 (' + data.hops.length + ' 跳, ' + (data.hops.length+1) + ' 线程)</h3>' +
    '<div class="summary-grid">' +
    '<div class="summary-item"><div class="val" style="color:#3fb950">' + total.running.toFixed(2) + ' ms</div><div class="lbl">RUNNING</div></div>' +
    '<div class="summary-item"><div class="val" style="color:#d29922">' + total.runnable.toFixed(2) + ' ms</div><div class="lbl">RUNNABLE</div></div>' +
    '<div class="summary-item"><div class="val" style="color:#8b949e">' + total.blocked.toFixed(2) + ' ms</div><div class="lbl">BLOCKED</div></div>' +
    '<div class="summary-item"><div class="val" style="color:#f85149">' + total.io.toFixed(2) + ' ms</div><div class="lbl">IO_BLOCK</div></div>' +
    '</div>';
}
</script>
</body>
</html>'''


# ============================================================
# 交互式查询 HTML (自包含, 通过 PID + 函数名 找路径)
# ============================================================

EXPLORER_HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>唤醒路径查询</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;height:100vh;display:flex;flex-direction:column}
.header{background:#161b22;padding:10px 20px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:12px}
.header h1{font-size:.95em;color:#58a6ff}
.header .stats{font-size:.65em;color:#8b949e}

.main{display:flex;flex:1;min-height:0}
.left{flex:0 0 360px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column;overflow-y:auto;padding:12px}
.right{flex:1;display:flex;flex-direction:column;overflow-y:auto;padding:12px}

.section{margin-bottom:12px}
.section label{display:block;font-size:.68em;color:#8b949e;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
.search-row{display:flex;gap:6px;margin-bottom:6px}
.search-row input{flex:1;padding:6px 8px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;font-size:.75em;outline:none;min-width:0}
.search-row input:focus{border-color:#58a6ff}
.btn{padding:6px 14px;background:#21262d;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;font-size:.72em;cursor:pointer;white-space:nowrap}
.btn:hover{background:#30363d}
.btn-go{background:#238636;border-color:#238636;color:#fff;font-size:.78em;padding:8px 20px}
.btn-go:hover{background:#2ea043}

.suggestions{max-height:180px;overflow-y:auto;margin-bottom:6px;display:none}
.suggestions.show{display:block}
.suggest-item{padding:4px 8px;cursor:pointer;font-size:.7em;border-bottom:1px solid #1c2128;display:flex;justify-content:space-between}
.suggest-item:hover{background:#1f6feb22}
.s-name{color:#f0883e}
.s-detail{color:#8b949e;font-size:.9em}

.selection{font-size:.72em;padding:6px 10px;background:#0d1117;border-radius:4px;margin-bottom:8px;min-height:28px;word-break:break-all}
.selection .sel-from{color:#f0883e;font-weight:600}
.selection .sel-to{color:#7ee787;font-weight:600}
.selection .sel-pid{color:#8b949e;margin-left:4px}

.result-card{border:1px solid #21262d;border-radius:8px;overflow:hidden;margin-bottom:8px}
.result-card-header{padding:6px 10px;background:#21262d;font-size:.7em;color:#8b949e}
.hop-row{display:flex;padding:8px 10px;border-bottom:1px solid #1c2128;gap:8px;align-items:flex-start;font-size:.72em}
.hop-num{flex:0 0 16px;color:#484f58;text-align:center;padding-top:2px}
.hop-arrow{color:#58a6ff}
.hop-info{flex:1}
.hop-waker{color:#f0883e;font-weight:600}
.hop-wakee{color:#7ee787;font-weight:600}
.hop-func{color:#a371f7;font-size:.92em;margin-top:2px}
.hop-gap{color:#484f58;font-size:.85em;margin-top:1px}
.hop-no{color:#484f58;font-style:italic;font-size:.92em}

.func-chain{font-size:.72em;padding:8px 10px;background:#0d1117;border-radius:4px;margin:8px 0;line-height:2}
.func-chain .fc-from{color:#a371f7}
.func-chain .fc-arrow{color:#58a6ff;margin:0 6px}
.func-chain .fc-to{color:#7ee787}

.empty{color:#484f58;text-align:center;padding:30px;font-size:.78em}

.thread-funcs{font-size:.7em;margin-top:4px}
.thread-funcs .tf-item{display:inline-block;padding:1px 6px;margin:1px 2px;background:#21262d;border-radius:3px;cursor:pointer;font-size:.95em}
.thread-funcs .tf-item:hover{background:#1f6feb33;color:#58a6ff}

::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
</style>
</head>
<body>
<div class="header">
  <h1>🔗 唤醒路径查询</h1>
  <span class="stats" id="top-stats"></span>
</div>
<div class="main">
  <div class="left">
    <div class="section">
      <label>🔵 起点选择</label>
      <div class="search-row">
        <input type="text" id="from-search" placeholder="输入 PID 或函数名..." autocomplete="off">
        <button class="btn" id="from-clear">✕</button>
      </div>
      <div class="suggestions" id="from-sug"></div>
      <div class="selection" id="from-sel">未选择</div>
      <div class="thread-funcs" id="from-funcs"></div>
    </div>
    <div class="section">
      <label>🟢 终点选择</label>
      <div class="search-row">
        <input type="text" id="to-search" placeholder="输入 PID 或函数名..." autocomplete="off">
        <button class="btn" id="to-clear">✕</button>
      </div>
      <div class="suggestions" id="to-sug"></div>
      <div class="selection" id="to-sel">未选择</div>
      <div class="thread-funcs" id="to-funcs"></div>
    </div>
    <button class="btn-go" id="find-btn">🔍 查找唤醒路径</button>
    <div style="font-size:.62em;color:#484f58;margin-top:8px">
      提示: 先搜索 PID 选中线程，再点击函数名作为起止点
    </div>
  </div>
  <div class="right" id="result">
    <div class="empty">👈 选择起点和终点，点击查询</div>
  </div>
</div>

<script>
// ============ 内嵌数据 ============
var DATA = __DATA__;

// DATA = {
//   threads: {pid: {comm, functions: [func_name, ...]}},
//   adj: {pid: [wakee_pid, ...]},           // 唯一邻接
//   func_threads: {func_name: [pid, ...]},  // 函数→线程索引
//   func_list: ["func1", "func2", ...],
// }

var state = {fromPid: null, fromFunc: null, toPid: null, toFunc: null};

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function getThread(pid){return DATA.threads[String(pid)];}
function comm(pid){var t=getThread(pid);return t?t.comm:'?'+pid;}
function funcsOf(pid){var t=getThread(pid);return t?t.functions:[];}

// ── 统计 ──
(function(){
  var pids=Object.keys(DATA.threads);
  document.getElementById('top-stats').textContent=
    pids.length+' 线程 | '+DATA.func_list.length+' 函数 | '+pids.reduce(function(s,p){return s+(DATA.adj[p]||[]).length;},0)+' 唯一唤醒边';
})();

// ── 搜索逻辑 ──
function setupSearch(inputId, sugId, selId, funcsId, side){
  var inp=document.getElementById(inputId),
      sug=document.getElementById(sugId);
  var timer=null;

  inp.addEventListener('input', function(){
    clearTimeout(timer);
    var q=this.value.toLowerCase().trim();
    if(!q){sug.classList.remove('show');return;}
    timer=setTimeout(function(){
      var results=[];
      // 精确匹配 PID
      var t=getThread(q);
      if(t) results.push({type:'pid', pid:q, comm:t.comm, nfuncs:t.functions.length});
      // PID 包含
      Object.keys(DATA.threads).forEach(function(p){
        if(String(p).indexOf(q)>=0 && String(p)!==q)
          results.push({type:'pid', pid:p, comm:DATA.threads[p].comm, nfuncs:DATA.threads[p].functions.length});
      });
      // 函数名匹配
      DATA.func_list.forEach(function(f){
        if(f.toLowerCase().indexOf(q)>=0)
          results.push({type:'func', func:f, pids:DATA.func_threads[f]});
      });
      // 取前15条
      results=results.slice(0,15);
      if(!results.length){sug.classList.remove('show');return;}
      sug.innerHTML=results.map(function(r){
        if(r.type==='pid')
          return '<div class="suggest-item" data-pid="'+r.pid+'"><span class="s-name">'+esc(r.comm)+'</span><span class="s-detail">PID='+r.pid+' | '+r.nfuncs+' 函数</span></div>';
        else
          return '<div class="suggest-item" data-func="'+esc(r.func)+'"><span class="s-name">函数: '+esc(r.func.length>50?r.func.substring(0,49)+'…':r.func)+'</span><span class="s-detail">'+r.pids.length+' 线程</span></div>';
      }).join('');
      sug.classList.add('show');
    },150);
  });

  sug.addEventListener('click', function(e){
    var it=e.target.closest('.suggest-item');if(!it)return;
    if(it.dataset.pid){
      var pid=parseInt(it.dataset.pid);
      selectThread(side, pid);
      inp.value=comm(pid);
    }else if(it.dataset.func){
      selectFunc(side, it.dataset.func);
      inp.value=it.dataset.func;
    }
    sug.classList.remove('show');
  });

  inp.addEventListener('blur', function(){setTimeout(function(){sug.classList.remove('show');},200);});
  
  document.getElementById(inputId.replace('search','clear')).addEventListener('click',function(){
    clearSelection(side);inp.value='';
  });
}

function selectThread(side, pid){
  if(side==='from'){state.fromPid=pid;state.fromFunc=null;}
  else{state.toPid=pid;state.toFunc=null;}
  updateUI();
}

function selectFunc(side, funcName){
  var pids=DATA.func_threads[funcName]||[];
  if(side==='from'){
    state.fromFunc=funcName;
    if(pids.length===1) state.fromPid=pids[0];
  }else{
    state.toFunc=funcName;
    if(pids.length===1) state.toPid=pids[0];
  }
  updateUI();
}

function clearSelection(side){
  if(side==='from'){state.fromPid=null;state.fromFunc=null;}
  else{state.toPid=null;state.toFunc=null;}
  updateUI();
}

function updateUI(){
  ['from','to'].forEach(function(side){
    var pid=side==='from'?state.fromPid:state.toPid;
    var func=side==='from'?state.fromFunc:state.toFunc;
    var sel=document.getElementById(side+'-sel');
    var funcsDiv=document.getElementById(side+'-funcs');
    
    if(!pid&&!func){sel.innerHTML='<span style="color:#484f58">未选择</span>';funcsDiv.innerHTML='';return;}
    
    var cls=side==='from'?'sel-from':'sel-to';
    var html='';
    if(pid) html+='<span class="'+cls+'">'+esc(comm(pid))+'</span><span class="sel-pid">PID='+pid+'</span>';
    if(func) html+='<span style="margin-left:8px;color:#a371f7">⚡'+esc(func.length>60?func.substring(0,59)+'…':func)+'</span>';
    sel.innerHTML=html||'<span style="color:#484f58">未选择</span>';
    
    // 显示该线程的所有函数
    if(pid){
      var funcs=funcsOf(pid);
      if(funcs.length>0){
        var fh='';
        funcs.slice(0,30).forEach(function(f){
          fh+='<span class="tf-item" data-func="'+esc(f)+'" data-side="'+side+'" title="'+esc(f)+'">'+esc(f.length>35?f.substring(0,34)+'…':f)+'</span>';
        });
        if(funcs.length>30) fh+='<span style="color:#484f58;font-size:.85em"> ... +'+(funcs.length-30)+'</span>';
        funcsDiv.innerHTML=fh;
      }else{
        funcsDiv.innerHTML='<span style="color:#484f58;font-size:.7em">该线程无 atrace 函数</span>';
      }
    }else{
      funcsDiv.innerHTML='';
    }
  });
  
  // 绑定函数点击
  document.querySelectorAll('.tf-item').forEach(function(el){
    el.addEventListener('click', function(){
      selectFunc(this.dataset.side, this.dataset.func);
    });
  });
}

setupSearch('from-search','from-sug','from-sel','from-funcs','from');
setupSearch('to-search','to-sug','to-sel','to-funcs','to');

// ── 查找路径 ──
document.getElementById('find-btn').addEventListener('click', function(){
  var res=document.getElementById('result');
  
  // 解析起点: PID 或 函数名(自动找所有匹配线程)
  var fromPids=[];
  if(state.fromPid) fromPids=[state.fromPid];
  else if(state.fromFunc){
    fromPids=DATA.func_threads[state.fromFunc]||[];
  }
  
  var toPids=[];
  if(state.toPid) toPids=[state.toPid];
  else if(state.toFunc){
    toPids=DATA.func_threads[state.toFunc]||[];
  }
  
  if(!fromPids.length||!toPids.length){
    res.innerHTML='<div class="empty">❌ 请先选择起点和终点 (搜索 PID 或函数名后点击)</div>';
    return;
  }
  
  // 去重
  var common=[];
  fromPids.forEach(function(p){if(toPids.indexOf(p)>=0)common.push(p);});
  var fpList=fromPids.filter(function(p){return common.indexOf(p)<0;});
  var tpList=toPids.filter(function(p){return common.indexOf(p)<0;});
  
  if(!fpList.length||!tpList.length){
    res.innerHTML='<div class="empty">❌ 起点和终点只在相同线程上执行<br><br>共享线程: '+common.map(function(p){return '<b>'+esc(comm(p))+'</b> (PID='+p+')';}).join(', ')+'<br><br>💡 这些函数在<b>同一线程</b>上顺序执行，不存在跨线程唤醒。<br>请选择<b>不同线程</b>上的函数，或先指定具体 PID 再选函数。</div>';
    return;
  }
  
  // 找最短路径 (多源 BFS)
  var visited={}, parent={}, q=[], foundTp=null, foundFp=null;
  fpList.forEach(function(p){visited[p]=true;parent[p]=null;q.push(p);});
  
  while(q.length>0&&!foundTp){
    var pid=q.shift();
    var neighbors=DATA.adj[String(pid)]||[];
    for(var i=0;i<neighbors.length;i++){
      var n=neighbors[i];
      if(visited[n]) continue;
      visited[n]=true; parent[n]=pid;
      if(tpList.indexOf(n)>=0){foundTp=n;foundFp=findRoot(n);break;}
      q.push(n);
    }
  }
  
  function findRoot(p){
    while(parent[p]!==null&&fpList.indexOf(p)<0) p=parent[p];
    return p;
  }
  
  if(!foundTp){
    var reachable=Object.keys(visited).length;
    res.innerHTML='<div class="empty">❌ '+'无法到达<br><br>起点可到达 '+reachable+' 个线程 (共 '+Object.keys(DATA.threads).length+' 个)<br>目标线程不在可达范围内</div>';
    return;
  }
  
  // 回溯路径
  var path=[], cur=foundTp;
  while(parent[cur]!==null){
    path.unshift({waker:parent[cur], wakee:cur});
    cur=parent[cur];
  }
  
  // 渲染
  var sf=state.fromFunc||null, tf=state.toFunc||null;
  var html='<div class="result-card">';
  html+='<div class="result-card-header">路径: '+esc(comm(path[0].waker))+'('+path[0].waker+') → '+esc(comm(foundTp))+'('+foundTp+') &nbsp;('+path.length+' 跳)';
  if(common.length) html+='<br><span style="color:#484f58">已排除同线程: '+common.map(function(p){return esc(comm(p))+'('+p+')';}).join(', ')+'</span>';
  html+='</div>';
  
  path.forEach(function(hop,i){
    var wf=(i===0&&sf)?sf:null;
    var ef=(i===path.length-1&&tf)?tf:null;
    
    html+='<div class="hop-row">';
    html+='<div class="hop-num">'+(i+1)+'</div>';
    html+='<div class="hop-info">';
    html+='<span class="hop-waker">'+esc(comm(hop.waker))+'('+hop.waker+')</span>';
    if(wf) html+='<div class="hop-func">⚡ '+esc(wf)+'</div>';
    html+=' <span class="hop-arrow">──唤醒──→</span> ';
    html+='<span class="hop-wakee">'+esc(comm(hop.wakee))+'('+hop.wakee+')</span>';
    if(ef) html+='<div class="hop-func">▶ '+esc(ef)+'</div>';
    html+='</div></div>';
  });
  html+='</div>';
  
  // 函数链汇总
  html+='<div class="func-chain">🔗 函数唤醒链:<br>';
  html+='<span class="fc-from">'+(sf||esc(comm(path[0].waker))+'('+path[0].waker+')')+'</span>';
  path.forEach(function(hop,i){
    var ef=(i===path.length-1&&tf)?tf:null;
    html+=' <span class="fc-arrow">──唤醒──→</span> ';
    html+='<span class="fc-to">'+(ef||esc(comm(hop.wakee))+'('+hop.wakee+')')+'</span>';
  });
  html+='</div>';
  
  res.innerHTML=html;
});
</script>
</body>
</html>'''


def generate_explorer_html(wakeup_edges, func_segs, pid_comm, func_names, output_path):
    """生成自包含的交互式查询 HTML"""
    
    # ── 构建线程→函数索引 ──
    threads = {}
    for pid, segs in func_segs.items():
        func_set = set()
        for _, _, fidx in segs:
            func_set.add(func_names[fidx])
        threads[str(pid)] = {
            'comm': pid_comm.get(pid, f'?{pid}'),
            'functions': sorted(func_set),
        }
    # 补充只有唤醒关系但没有 atrace 的线程
    for waker, wakee, _ in wakeup_edges:
        for p in (waker, wakee):
            if str(p) not in threads:
                threads[str(p)] = {
                    'comm': pid_comm.get(p, f'?{p}'),
                    'functions': [],
                }
    
    # ── 构建唯一邻接表 ──
    adj = defaultdict(set)
    for waker, wakee, _ in wakeup_edges:
        adj[waker].add(wakee)
    adj_json = {str(k): sorted(list(v)) for k, v in adj.items()}
    # 确保所有线程都有邻接条目 (即使是空数组)
    for pid_str in threads:
        if pid_str not in adj_json:
            adj_json[pid_str] = []
    
    # ── 构建函数→线程反向索引 ──
    func_threads = defaultdict(set)
    for pid_str, info in threads.items():
        for f in info['functions']:
            func_threads[f].add(int(pid_str))
    func_threads_json = {k: sorted(list(v)) for k, v in func_threads.items()}
    
    # ── 组装数据 ──
    data = {
        'threads': threads,
        'adj': adj_json,
        'func_threads': func_threads_json,
        'func_list': func_names,
    }
    
    html = EXPLORER_HTML_TEMPLATE.replace('__DATA__', json.dumps(data, ensure_ascii=False))
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    embedded_kb = len(json.dumps(data, ensure_ascii=False)) / 1024
    print(f"📄 交互式查询 HTML 已生成: {output_path}")
    print(f"   内嵌数据: {embedded_kb:.0f} KB")
    print(f"   线程: {len(threads):,}  函数: {len(func_names):,}  唯一边: {sum(len(v) for v in adj_json.values()):,}")
    print(f"   浏览器打开后: 搜索 PID/函数名 → 选择起点终点 → 点击查询")


def generate_path_html(path, durations, pid_comm, func_names, t_min, from_func, to_func, output_path):
    """生成路径分析 HTML"""
    data = {
        'from': from_func,
        'to': to_func,
        'hops': durations,
        'path_len': len(durations),
    }
    html = PATH_HTML_TEMPLATE.replace('__FUNC_LIST__', json.dumps(func_names, ensure_ascii=False))
    html = html.replace('__PATH_DATA__', json.dumps(data, ensure_ascii=False))
    html = html.replace('__TT__', json.dumps({'t_min': t_min}, ensure_ascii=False))
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"📄 HTML 已生成: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Wakeup Path + State Analyzer')
    parser.add_argument('input', nargs='?', default='output.html')
    parser.add_argument('--from', '-f', dest='from_func', default=None, help='起始函数名')
    parser.add_argument('--to', '-t', dest='to_func', default=None, help='目标函数名')
    parser.add_argument('--list-funcs', '-l', action='store_true', help='列出所有 atrace 函数')
    parser.add_argument('--html', '-H', default=None, help='导出路径 HTML')
    parser.add_argument('--explorer', '-X', default=None, help='导出交互式查询 HTML (通过PID+函数名查路径)')
    parser.add_argument('--max-depth', '-d', type=int, default=15, help='最大搜索深度')
    args = parser.parse_args()
    
    print(f"📖 单次流式解析 {args.input} ...")
    print(f"   (同时解析 sched_switch + tracing_mark_write + sched_waking)")
    
    wakeup_edges, state_segs, func_segs, pid_comm, func_names = parse_all(args.input)
    
    # 计算 t_min
    t_min = float('inf')
    for segs in state_segs.values():
        if segs:
            t_min = min(t_min, segs[0][0])
    for segs in func_segs.values():
        if segs:
            t_min = min(t_min, segs[0][0])
    if t_min == float('inf'):
        t_min = 0
    
    print(f"   sched_switch 状态段: {sum(len(v) for v in state_segs.values()):,}")
    print(f"   atrace 函数段:      {sum(len(v) for v in func_segs.values()):,}")
    print(f"   去重唤醒边:         {len(wakeup_edges):,}")
    print(f"   唯一函数名:         {len(func_names):,}")
    print(f"   线程数:             {len(pid_comm):,}")
    
    if args.list_funcs:
        print(f"\n📋 所有 atrace 函数 ({len(func_names)} 个):")
        for i, name in enumerate(sorted(func_names)):
            print(f"   {i:>4}. {name}")
        return

    if args.explorer:
        print(f"\n🔧 生成交互式查询 HTML ...")
        generate_explorer_html(wakeup_edges, func_segs, pid_comm, func_names, args.explorer)
        return

    if not args.from_func or not args.to_func:
        print(f"\n💡 用法:")
        print(f"   python3 {sys.argv[0]} output.html --list-funcs          # 列出所有函数")
        print(f"   python3 {sys.argv[0]} output.html --from 'funcA' --to 'funcB'")
        print(f"   python3 {sys.argv[0]} output.html --from 'funcA' --to 'funcB' --html path.html")
        return
    
    # 标注唤醒边
    print(f"\n🔗 标注唤醒边 (匹配 waker 当时执行的函数)...")
    annotated = annotate_wakeup_edges(wakeup_edges, func_segs, pid_comm, func_names)
    matched = sum(1 for _, _, _, f in annotated if f is not None)
    print(f"   函数匹配: {matched:,} / {len(annotated):,} ({matched*100//max(len(annotated),1)}%)")
    
    # 构建图
    out_edges, in_edges = build_graph(annotated)
    
    # 查找起始/目标线程
    start_pids = find_threads_by_func(func_segs, func_names, args.from_func)
    end_pids = find_threads_by_func(func_segs, func_names, args.to_func)
    
    print(f"\n🔍 查找路径: '{args.from_func}' → '{args.to_func}'")
    
    # ── 详细列出匹配的线程 ──
    def describe_threads(pids, label):
        print(f"   {label}: {len(pids)} 个线程执行过此函数")
        for p in sorted(pids)[:8]:
            comm = pid_comm.get(p, f'?{p}')
            out_d = len(out_edges.get(p, []))
            in_d = len(in_edges.get(p, []))
            print(f"      {comm}({p})  唤醒{out_d}次 / 被唤{in_d}次")
        if len(pids) > 8:
            print(f"      ... 还有 {len(pids)-8} 个线程")
    
    describe_threads(start_pids, '起始')
    describe_threads(end_pids, '目标')
    
    if len(start_pids) > 1 or len(end_pids) > 1:
        common = set(start_pids) & set(end_pids)
        if common:
            print(f"   ⚠️  有 {len(common)} 个线程同时出现在起止集合中 (同线程), 将排除")
            start_pids = [p for p in start_pids if p not in common]
            end_pids = [p for p in end_pids if p not in common]
            if not start_pids or not end_pids:
                print(f"   ❌ 排除同线程后无可用起止点 — 该函数只在同线程中执行")
                return
            print(f"   排除后: 起始{len(start_pids)}个, 目标{len(end_pids)}个")
    
    if not start_pids:
        print(f"   ❌ 未找到执行 '{args.from_func}' 的线程")
        # 模糊搜索建议
        matches = [n for n in func_names if args.from_func.lower() in n.lower()]
        if matches:
            print(f"   💡 相似函数: {matches[:10]}")
        return
    if not end_pids:
        print(f"   ❌ 未找到执行 '{args.to_func}' 的线程")
        matches = [n for n in func_names if args.to_func.lower() in n.lower()]
        if matches:
            print(f"   💡 相似函数: {matches[:10]}")
        return
    
    # 找路径
    path = find_path(out_edges, in_edges, start_pids, end_pids, args.max_depth)
    
    if not path:
        print(f"   ❌ 在深度 {args.max_depth} 内未找到路径")
        
        # ── 可达性诊断 ──
        print(f"\n   🔬 可达性分析:")
        # 从每个 start pid 出发, 看能到达多少个节点
        for sp in start_pids[:5]:
            visited = {sp}
            q = deque([sp])
            while q:
                pid = q.popleft()
                for wakee, _, _ in out_edges.get(pid, []):
                    if wakee not in visited:
                        visited.add(wakee)
                        q.append(wakee)
            reachable_ends = visited & set(end_pids)
            sp_comm = pid_comm.get(sp, f'?{sp}')
            print(f"      {sp_comm}({sp}): 可到达 {len(visited)} 个线程, "
                  f"其中 {len(reachable_ends)} 个是目标线程")
        
        # 从每个 end pid 反向搜索
        for ep in end_pids[:5]:
            visited = {ep}
            q = deque([ep])
            while q:
                pid = q.popleft()
                for waker, _, _ in in_edges.get(pid, []):
                    if waker not in visited:
                        visited.add(waker)
                        q.append(waker)
            reachable_starts = visited & set(start_pids)
            ep_comm = pid_comm.get(ep, f'?{ep}')
            print(f"      {ep_comm}({ep}): 反向可达 {len(visited)} 个线程, "
                  f"其中 {len(reachable_starts)} 个是起始线程")
        
        print(f"\n   💡 建议:")
        print(f"      1. 增加 --max-depth (当前 {args.max_depth}, 可尝试 50)")
        print(f"      2. 该线程可能不在 sched_waking 追踪范围内 (如某些内核线程)")
        print(f"      3. 用 --list-funcs 查看目标线程上的函数, 换一个更近的函数")
        return
    
    print(f"   ✅ 找到路径! {len(path)} 跳")
    
    # 计算状态耗时
    durations = compute_hop_durations(path, state_segs, func_segs, pid_comm, func_names)
    
    # 打印报告
    print_path_report(path, durations, pid_comm, t_min)
    
    # 生成 HTML
    if args.html:
        generate_path_html(path, durations, pid_comm, func_names, t_min, 
                          args.from_func, args.to_func, args.html)


if __name__ == '__main__':
    main()
