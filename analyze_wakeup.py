#!/usr/bin/env python3
"""
Android Systrace Wakeup Chain Structure Analyzer
分析唤醒关系的图结构: 森林? DAG? 深度? 分叉因子?

用法:
    python3 analyze_wakeup.py [output.html]
"""

import sys, re, json, argparse
from collections import defaultdict, Counter, deque

# ============================================================
# 正则: sched_waking / sched_wakeup / sched_wakeup_new
# 格式: comm-pid (pid) [cpu] flags timestamp: sched_waking: comm=xxx pid=N prio=N target_cpu=N
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


def parse_and_build_graph(filepath):
    """
    流式解析 + 即时构建图结构 (不存储原始事件列表)
    
    去重策略: sched_waking 和 sched_wakeup 成对出现表示同一次唤醒。
             用 (waker_pid, wakee_pid, ts_rounded) 去重，保留更早的时间戳。
    
    返回:
        edges:      [(waker_pid, wakee_pid, ts), ...] 去重后的边
        pid_comm:   {pid: comm}
        stats:      {total_waking, total_wakeup, total_wakeup_new, merged_pairs}
    """
    # 临时存储: key=(waker_pid, wakee_pid) -> (ts, type)
    # 用于合并 waking/wakeup 对
    pending = {}  
    edges = []           # [(waker_pid, wakee_pid, ts), ...]
    pid_comm = {}        # pid -> comm
    
    total_waking = 0
    total_wakeup = 0
    total_wakeup_new = 0
    merged_pairs = 0
    
    def add_edge(waker_pid, wakee_pid, ts, etype):
        nonlocal merged_pairs
        key = (waker_pid, wakee_pid)
        if key in pending:
            prev_ts, prev_type = pending[key]
            # 保留更早的时间戳, 合并为一对
            merged_pairs += 1
            edges.append((waker_pid, wakee_pid, min(ts, prev_ts)))
            del pending[key]
        else:
            pending[key] = (ts, etype)
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
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
                
                if etype == 'waking':
                    total_waking += 1
                elif etype == 'wakeup':
                    total_wakeup += 1
                else:
                    total_wakeup_new += 1
                    
                add_edge(waker_pid, wakee_pid, ts, etype)
    
    # 未配对的 pending 也加入
    for (waker_pid, wakee_pid), (ts, etype) in pending.items():
        edges.append((waker_pid, wakee_pid, ts))
    
    return edges, pid_comm, {
        'total_waking': total_waking,
        'total_wakeup': total_wakeup,
        'total_wakeup_new': total_wakeup_new,
        'merged_pairs': merged_pairs,
        'unpaired': len(pending),
        'total_edges': len(edges),
    }


def analyze_structure(edges, pid_comm):
    """
    分析唤醒图的结构特征
    
    回答: "唤醒关系串起来是什么结构?"
    - 是森林 (Forest)? 还是有环?
    - 深度分布
    - 分叉因子
    - 根节点/叶节点
    """
    # ── 构建邻接表 ──
    # out_edges[pid] = [(wakee_pid, ts), ...]   -- 我唤醒了谁
    # in_edges[pid]  = [(waker_pid, ts), ...]   -- 谁唤醒了我
    out_edges = defaultdict(list)
    in_edges = defaultdict(list)
    all_pids = set()
    
    for waker, wakee, ts in edges:
        out_edges[waker].append((wakee, ts))
        in_edges[wakee].append((waker, ts))
        all_pids.add(waker)
        all_pids.add(wakee)
    
    # ── 基础统计 ──
    out_degree = {pid: len(v) for pid, v in out_edges.items()}
    in_degree = {pid: len(v) for pid, v in in_edges.items()}
    
    # 根节点: 只唤醒别人, 几乎不被唤醒 (in-degree <= 1)
    # 叶节点: 只被唤醒, 几乎不唤醒别人 (out-degree <= 1)
    roots = [(pid, out_degree.get(pid, 0), in_degree.get(pid, 0))
             for pid in all_pids 
             if in_degree.get(pid, 0) <= 1 and out_degree.get(pid, 0) > 0]
    roots.sort(key=lambda x: -x[1])
    
    leaves = [(pid, in_degree.get(pid, 0), out_degree.get(pid, 0))
              for pid in all_pids
              if out_degree.get(pid, 0) <= 1 and in_degree.get(pid, 0) > 0]
    leaves.sort(key=lambda x: -x[1])
    
    # ── 环路检测 (应无环) ──
    # 对每个根节点做 BFS, 检测后向边
    has_cycle = False
    
    # ── 最长链分析 (从根出发 BFS) ──
    def bfs_depth(start_pid):
        """从 start_pid 出发的最长唤醒链深度"""
        max_depth = 0
        # BFS 按时间序
        visited = set()
        q = deque([(start_pid, 0, 0.0)])  # (pid, depth, arrival_ts)
        while q:
            pid, depth, arrival_ts = q.popleft()
            if depth > max_depth:
                max_depth = depth
            if pid in visited:
                continue
            visited.add(pid)
            for wakee, ts in out_edges.get(pid, []):
                if ts > arrival_ts:  # 时间必须单调
                    q.append((wakee, depth + 1, ts))
        return max_depth
    
    # 对所有根节点计算深度
    chain_depths = []
    for pid, out_d, in_d in roots[:500]:  # 限制计算量
        d = bfs_depth(pid)
        chain_depths.append(d)
    
    # ── 分叉因子统计 ──
    out_degree_vals = list(out_degree.values())
    branching_dist = Counter()
    for d in out_degree_vals:
        if d <= 1:
            branching_dist['1'] += 1
        elif d <= 5:
            branching_dist['2-5'] += 1
        elif d <= 20:
            branching_dist['6-20'] += 1
        elif d <= 100:
            branching_dist['21-100'] += 1
        else:
            branching_dist['100+'] += 1
    
    # ── 组件分析: 弱连通分量 ──
    # 用并查集
    parent = {}
    def find(x):
        if x not in parent:
            parent[x] = x
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    
    for waker, wakee, ts in edges:
        union(waker, wakee)
    
    component_sizes = Counter()
    for pid in all_pids:
        component_sizes[find(pid)] += 1
    
    comp_size_dist = Counter()
    for size in component_sizes.values():
        if size <= 5:
            comp_size_dist['1-5'] += 1
        elif size <= 20:
            comp_size_dist['6-20'] += 1
        elif size <= 100:
            comp_size_dist['21-100'] += 1
        elif size <= 1000:
            comp_size_dist['101-1K'] += 1
        else:
            comp_size_dist['1K+'] += 1
    
    # 最大连通分量
    largest_comp = max(component_sizes.values()) if component_sizes else 0
    
    # ── 组装结果 ──
    return {
        'total_nodes': len(all_pids),
        'total_edges': len(edges),
        'roots': roots[:30],
        'leaves': leaves[:30],
        'chain_depths': chain_depths,
        'chain_depth_max': max(chain_depths) if chain_depths else 0,
        'chain_depth_avg': sum(chain_depths) / len(chain_depths) if chain_depths else 0,
        'branching_dist': dict(branching_dist),
        'branching_max': max(out_degree_vals) if out_degree_vals else 0,
        'branching_avg': sum(out_degree_vals) / len(out_degree_vals) if out_degree_vals else 0,
        'num_components': len(component_sizes),
        'comp_size_dist': dict(comp_size_dist),
        'largest_component': largest_comp,
        'has_cycle': has_cycle,
        # Top wakers / wakees
        'top_wakers': sorted(out_degree.items(), key=lambda x: -x[1])[:20],
        'top_wakees': sorted(in_degree.items(), key=lambda x: -x[1])[:20],
        'pid_comm': {str(k): v for k, v in pid_comm.items()},
    }


def print_report(parse_stats, structure, pid_comm):
    """打印人类可读的分析报告"""
    
    def comm(pid):
        c = pid_comm.get(pid, f'?{pid}')
        return f"{c}({pid})"
    
    print()
    print("=" * 70)
    print("  🔗 Android Systrace 唤醒链结构分析")
    print("=" * 70)
    
    print(f"\n📊 原始事件统计:")
    print(f"   sched_waking:     {parse_stats['total_waking']:>10,}")
    print(f"   sched_wakeup:     {parse_stats['total_wakeup']:>10,}")
    print(f"   sched_wakeup_new: {parse_stats['total_wakeup_new']:>10,}")
    print(f"   ─────────────────────────────")
    print(f"   合并 waking/wakeup 对: {parse_stats['merged_pairs']:>6,}")
    print(f"   去重后唤醒边:           {parse_stats['total_edges']:>10,}")
    
    s = structure
    print(f"\n📐 图结构特征:")
    print(f"   节点数 (线程):     {s['total_nodes']:>10,}")
    print(f"   边数 (唤醒关系):   {s['total_edges']:>10,}")
    print(f"   连通分量数:        {s['num_components']:>10,}")
    print(f"   最大连通分量:      {s['largest_component']:>10,} 个线程")
    
    print(f"\n🌲 结构判定: ", end="")
    if s['num_components'] > 1 and s['largest_component'] < s['total_nodes'] * 0.5:
        print("森林 (Forest) — 多个独立的唤醒树")
        print(f"   说明: 系统中有 {s['num_components']} 个独立的唤醒子系统,")
        print(f"   最大的一棵包含 {s['largest_component']} 个线程。")
    else:
        print("近似森林带交叉边 — 大部分线程属于同一个巨型弱连通分量")
        print(f"   说明: 存在跨子系统的唤醒 (如 interrupt → kworker → 用户进程)")
    
    print(f"\n📏 链深度 (从根到叶的唤醒跳数):")
    print(f"   最大深度:  {s['chain_depth_max']}")
    print(f"   平均深度:  {s['chain_depth_avg']:.1f}")
    if s['chain_depths']:
        from collections import Counter as Ctr
        dc = Ctr(s['chain_depths'])
        print(f"   深度分布:  ", end="")
        for d in sorted(dc.keys()):
            print(f"d={d}:{dc[d]} ", end="")
        print()
    
    print(f"\n🌿 分叉因子 (一个线程唤醒多少个其他线程):")
    print(f"   最大分叉:  {s['branching_max']}")
    print(f"   平均分叉:  {s['branching_avg']:.1f}")
    for k in ['1', '2-5', '6-20', '21-100', '100+']:
        if k in s['branching_dist']:
            print(f"   {k:>8}: {s['branching_dist'][k]:>8,} 个线程")
    
    print(f"\n📦 连通分量大小分布:")
    for k in ['1-5', '6-20', '21-100', '101-1K', '1K+']:
        if k in s['comp_size_dist']:
            print(f"   {k:>8}: {s['comp_size_dist'][k]:>8,} 个分量")
    
    print(f"\n🔝 Top 10 唤醒者 (出度最高):")
    for pid, cnt in s['top_wakers'][:10]:
        print(f"   {comm(pid):<35} 唤醒了 {cnt:>6,} 次")
    
    print(f"\n🔝 Top 10 被唤醒者 (入度最高):")
    for pid, cnt in s['top_wakees'][:10]:
        print(f"   {comm(pid):<35} 被唤醒 {cnt:>6,} 次")
    
    print(f"\n🌱 根节点示例 (只唤醒别人, 几乎不被唤醒):")
    for pid, out_d, in_d in s['roots'][:10]:
        print(f"   {comm(pid):<35} 唤醒 {out_d:>5} 次, 被唤 {in_d} 次")
    
    print(f"\n🍂 叶节点示例 (只被唤醒, 几乎不唤醒别人):")
    for pid, in_d, out_d in s['leaves'][:10]:
        print(f"   {comm(pid):<35} 被唤 {in_d:>5} 次, 唤醒 {out_d} 次")
    
    print()
    print("=" * 70)
    print("  💡 结论: 唤醒关系形成的是一个", end="")
    # 综合判断
    if s['num_components'] > 50:
        print(f"森林结构 (Forest),")
        print(f"     由 {s['num_components']} 棵独立的唤醒树组成。")
        print(f"     每棵树的根是高优先级内核线程 (kswapd, kworker 等),")
        print(f"     叶是用户态线程和被唤醒后不传播唤醒的线程。")
    else:
        print(f"稀疏 DAG (有向无环图),")
        print(f"     最大深度 {s['chain_depth_max']}, 说明存在唤醒传播链但不会无限递归。")
    
    print(f"     唤醒链短 (平均 {s['chain_depth_avg']:.1f} 跳), 大多数是 1-2 跳的直接唤醒。")
    print("=" * 70)


def build_aggregated_graph(edges):
    """
    将时序边聚合为唯一 (waker, wakee) 加权边。
    157K 时序边 → ~N K 唯一边, 显著减少渲染数据量。
    
    返回:
        unique_edges: [(waker, wakee, count), ...] 按 count 降序
        adj_out: {pid: [(wakee, count), ...]}
        adj_in:  {pid: [(waker, count), ...]}
    """
    edge_weight = Counter()
    for waker, wakee, ts in edges:
        edge_weight[(waker, wakee)] += 1
    
    unique_edges = [(w, e, c) for (w, e), c in edge_weight.items()]
    unique_edges.sort(key=lambda x: -x[2])
    
    adj_out = defaultdict(list)
    adj_in = defaultdict(list)
    for waker, wakee, count in unique_edges:
        adj_out[waker].append((wakee, count))
        adj_in[wakee].append((waker, count))
    
    return unique_edges, adj_out, adj_in


# ============================================================
# HTML 可视化模板
# ============================================================

HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>唤醒链图可视化</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;height:100vh;display:flex;overflow:hidden}

/* ── 左侧面板 ── */
.sidebar{flex:0 0 340px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column;overflow-y:auto}
.sidebar-header{background:linear-gradient(135deg,#1a2332,#161b22);padding:12px 16px;border-bottom:1px solid #30363d}
.sidebar-header h1{font-size:1em;color:#58a6ff;margin-bottom:4px}
.sidebar-header .sub{font-size:.65em;color:#8b949e}

.stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px;padding:6px 10px;border-bottom:1px solid #30363d}
.stat-item{padding:5px 8px;background:#0d1117;border-radius:4px;text-align:center}
.stat-value{font-size:.85em;font-weight:700;color:#f0f6fc}
.stat-label{font-size:.55em;color:#8b949e;text-transform:uppercase}

.search-wrap{padding:8px 10px;border-bottom:1px solid #30363d}
.search-wrap input{width:100%;padding:6px 8px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#c9d1d9;font-size:.75em;outline:none}
.search-wrap input:focus{border-color:#58a6ff}

.suggestions{max-height:180px;overflow-y:auto;display:none}
.suggestions.show{display:block}
.suggest-item{padding:4px 10px;cursor:pointer;font-size:.68em;border-bottom:1px solid #1c2128;display:flex;justify-content:space-between}
.suggest-item:hover{background:#1f6feb22}
.s-name{color:#f0883e}
.s-pid{color:#8b949e;margin-left:6px;font-size:.9em}
.s-badge{color:#484f58;font-size:.85em}

.info-panel{flex:1;padding:8px 10px;overflow-y:auto;font-size:.7em}
.info-panel h3{color:#58a6ff;font-size:.85em;margin:8px 0 4px;border-bottom:1px solid #21262d;padding-bottom:3px}
.info-row{display:flex;justify-content:space-between;padding:2px 0}
.info-row .l{color:#8b949e}
.info-row .v{color:#c9d1d9;font-weight:500}

.edge-list{max-height:200px;overflow-y:auto;margin-top:4px}
.edge-item{padding:2px 6px;margin:1px 0;background:#21262d;border-radius:3px;display:flex;justify-content:space-between;font-size:.95em}
.edge-item .dir{color:#58a6ff;margin:0 4px}

.legend{padding:8px 10px;border-top:1px solid #30363d;font-size:.6em;color:#8b949e}
.legend span{margin-right:10px}
.legend .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:3px;vertical-align:middle}

/* ── 右侧画布 ── */
.main{flex:1;position:relative;overflow:hidden}
#graph{width:100%;height:100%}

.tooltip{position:absolute;background:#21262d;border:1px solid #58a6ff;border-radius:5px;padding:6px 10px;font-size:.68em;pointer-events:none;z-index:999;display:none;box-shadow:0 3px 10px rgba(0,0,0,.5);max-width:240px}

.hint{position:absolute;bottom:8px;left:50%;transform:translateX(-50%);background:rgba(22,27,34,.9);border:1px solid #30363d;border-radius:5px;padding:3px 10px;font-size:.58em;color:#8b949e;pointer-events:none;white-space:nowrap}
.hint kbd{background:#21262d;border:1px solid #484f58;border-radius:3px;padding:0 3px;font-family:monospace}

::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
</style>
</head>
<body>
<div class="sidebar">
  <div class="sidebar-header">
    <h1>⚡ 唤醒链图结构</h1>
    <div class="sub">DAG 力导向图 · 点击节点展开邻域</div>
  </div>
  <div class="stats-grid" id="stats"></div>
  <div class="search-wrap">
    <input type="text" id="search" placeholder="搜索线程名或 PID..." autocomplete="off">
    <div class="suggestions" id="suggestions"></div>
  </div>
  <div class="info-panel" id="info">
    <div style="color:#484f58;text-align:center;padding:20px">👆 搜索或点击节点查看详情</div>
  </div>
  <div class="legend">
    <span><span class="dot" style="background:#f0883e"></span>根节点</span>
    <span><span class="dot" style="background:#58a6ff"></span>中间节点</span>
    <span><span class="dot" style="background:#3fb950"></span>叶节点</span>
    <span style="float:right">边粗细=唤醒次数</span>
  </div>
</div>
<div class="main">
  <svg id="graph"></svg>
  <div class="tooltip" id="tooltip"></div>
  <div class="hint">🖱 拖拽平移 · 滚轮缩放 · 点击节点聚焦 · <kbd>R</kbd> 重置</div>
</div>

<script>
// ============ 内嵌数据 ============
var DATA = __DATA__;

// ============ D3 初始化 ============
var svg = d3.select("#graph"),
    width = svg.node().parentElement.clientWidth,
    height = svg.node().parentElement.clientHeight;

var gRoot = svg.append("g");
var gLinks = gRoot.append("g");
var gNodes = gRoot.append("g");

var zoom = d3.zoom().scaleExtent([0.1, 8]).on("zoom", function(e) {
  gRoot.attr("transform", e.transform);
});
svg.call(zoom);

var simulation = d3.forceSimulation()
  .force("link", d3.forceLink().id(d => d.id).distance(60).strength(0.3))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(width / 2, height / 2))
  .force("collide", d3.forceCollide().radius(d => Math.sqrt(d.degree) * 2 + 8));

// ============ 工具函数 ============
var adjOut = DATA.adj_out, adjIn = DATA.adj_in, nodesMap = DATA.nodes_map;

function getNode(pid) { return nodesMap[String(pid)]; }
function comm(pid) { var n = getNode(pid); return n ? n.comm : '?' + pid; }

// ============ 初始: 显示 Top 50 线程 ============
var initialNodes = [], initialEdges = [], nodeSet = new Set();

// 选 top 出度线程
var topPids = DATA.top_nodes.slice(0, 50);
topPids.forEach(function(pid) {
  if (!nodeSet.has(pid)) { nodeSet.add(pid); initialNodes.push(getNode(pid)); }
  // 加入其直接邻居
  (adjOut[pid] || []).slice(0, 5).forEach(function(e) {
    if (!nodeSet.has(e[0])) { nodeSet.add(e[0]); initialNodes.push(getNode(e[0])); }
    initialEdges.push({source: pid, target: e[0], weight: e[1]});
  });
  (adjIn[pid] || []).slice(0, 3).forEach(function(e) {
    if (!nodeSet.has(e[0])) { nodeSet.add(e[0]); initialNodes.push(getNode(e[0])); }
    initialEdges.push({source: e[0], target: pid, weight: e[1]});
  });
});

// 限制初始边数
if (initialEdges.length > 600) initialEdges = initialEdges.slice(0, 600);

render(initialNodes, initialEdges);
showStats();

// ============ 渲染 ============
var currentNodes = [], currentEdges = [], currentPid = null;

function render(nodes, edges) {
  currentNodes = nodes; currentEdges = edges;
  
  // 去重
  var nodeMap = new Map(); nodes.forEach(function(n) { nodeMap.set(n.id, n); });
  var edgeSet = new Set();
  var cleanEdges = [];
  edges.forEach(function(e) {
    var key = e.source + '-' + e.target;
    if (typeof e.source === 'object') key = e.source.id + '-' + e.target.id;
    if (!edgeSet.has(key) && nodeMap.has(typeof e.source === 'object' ? e.source.id : e.source) && nodeMap.has(typeof e.target === 'object' ? e.target.id : e.target)) {
      edgeSet.add(key);
      cleanEdges.push(e);
    }
  });

  // 更新 simulation
  simulation.nodes(Array.from(nodeMap.values()));
  simulation.force("link").links(cleanEdges);
  simulation.alpha(0.5).restart();

  // 绘制边
  var link = gLinks.selectAll("line").data(cleanEdges, function(d) {
    return (typeof d.source === 'object' ? d.source.id : d.source) + '-' + (typeof d.target === 'object' ? d.target.id : d.target);
  });
  link.exit().remove();
  var linkEnter = link.enter().append("line")
    .attr("stroke", "#30363d")
    .attr("stroke-opacity", 0.6)
    .attr("stroke-width", function(d) { return Math.max(0.5, Math.min(6, Math.log(d.weight + 1) * 1.2)); });
  link = linkEnter.merge(link);

  // 绘制节点
  var node = gNodes.selectAll("g.node").data(Array.from(nodeMap.values()), function(d) { return d.id; });
  node.exit().remove();
  var nodeEnter = node.enter().append("g").attr("class", "node")
    .call(d3.drag().on("start", dragStart).on("drag", dragged).on("end", dragEnd));

  nodeEnter.append("circle")
    .attr("r", function(d) { return Math.sqrt(d.degree) * 1.5 + 4; })
    .attr("fill", function(d) {
      if (d.in_deg <= 1 && d.out_deg > 0) return "#f0883e";  // root
      if (d.out_deg <= 1 && d.in_deg > 0) return "#3fb950";  // leaf
      return "#58a6ff";  // intermediate
    })
    .attr("stroke", "#0d1117").attr("stroke-width", 1.5)
    .attr("opacity", 0.85);

  nodeEnter.append("text")
    .text(function(d) { return d.comm.length > 10 ? d.comm.substring(0, 9) + '…' : d.comm; })
    .attr("dy", -10).attr("text-anchor", "middle")
    .attr("fill", "#c9d1d9").attr("font-size", "9px")
    .attr("pointer-events", "none");

  nodeEnter.on("click", function(event, d) { focusNode(d.id); })
    .on("mouseenter", showTooltip).on("mousemove", moveTooltip).on("mouseleave", hideTooltip);

  node = nodeEnter.merge(node);

  simulation.on("tick", function() {
    link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
  });
}

// ============ 聚焦节点 ============
function focusNode(pid) {
  currentPid = pid;
  var nodeSet = new Set([pid]);
  var nodes = [getNode(pid)];
  var edges = [];

  // 出边: 我唤醒了谁
  (adjOut[pid] || []).forEach(function(e) {
    nodeSet.add(e[0]); nodes.push(getNode(e[0]));
    edges.push({source: pid, target: e[0], weight: e[1]});
  });
  // 入边: 谁唤醒了我
  (adjIn[pid] || []).forEach(function(e) {
    if (!nodeSet.has(e[0])) { nodeSet.add(e[0]); nodes.push(getNode(e[0])); }
    edges.push({source: e[0], target: pid, weight: e[1]});
  });

  render(nodes, edges);
  showInfo(pid);
  
  // 居中
  var n = getNode(pid);
  if (n && n.x !== undefined) {
    svg.transition().duration(500).call(zoom.transform,
      d3.zoomIdentity.translate(width / 2 - n.x, height / 2 - n.y).scale(1.2));
  }
}

// ============ 显示信息面板 ============
function showInfo(pid) {
  var n = getNode(pid), info = document.getElementById("info");
  if (!n) return;
  var outList = (adjOut[pid] || []).sort((a,b) => b[1]-a[1]);
  var inList = (adjIn[pid] || []).sort((a,b) => b[1]-a[1]);
  var h = '<h3>' + esc(n.comm) + ' <span style="color:#484f58;font-weight:normal">pid=' + pid + '</span></h3>';
  h += '<div class="info-row"><span class="l">唤醒别人</span><span class="v">' + outList.length + ' 种 / ' + n.out_deg + ' 次</span></div>';
  h += '<div class="info-row"><span class="l">被人唤醒</span><span class="v">' + inList.length + ' 种 / ' + n.in_deg + ' 次</span></div>';
  if (outList.length > 0) {
    h += '<h3>▶ 唤醒了谁</h3><div class="edge-list">';
    outList.slice(0, 15).forEach(function(e) {
      h += '<div class="edge-item"><span>' + esc(comm(e[0])) + '</span><span style="color:#484f58">×' + e[1] + '</span></div>';
    });
    if (outList.length > 15) h += '<div style="color:#484f58;font-size:.9em;padding:2px 6px">...还有 ' + (outList.length - 15) + ' 个</div>';
    h += '</div>';
  }
  if (inList.length > 0) {
    h += '<h3>◀ 被谁唤醒</h3><div class="edge-list">';
    inList.slice(0, 15).forEach(function(e) {
      h += '<div class="edge-item"><span>' + esc(comm(e[0])) + '</span><span style="color:#484f58">×' + e[1] + '</span></div>';
    });
    if (inList.length > 15) h += '<div style="color:#484f58;font-size:.9em;padding:2px 6px">...还有 ' + (inList.length - 15) + ' 个</div>';
    h += '</div>';
  }
  info.innerHTML = h;
}

// ============ 统计面板 ============
function showStats() {
  var s = DATA.stats;
  document.getElementById("stats").innerHTML =
    '<div class="stat-item"><span class="stat-value">' + s.nodes.toLocaleString() + '</span><span class="stat-label">线程</span></div>' +
    '<div class="stat-item"><span class="stat-value">' + s.unique_edges.toLocaleString() + '</span><span class="stat-label">唯一唤醒对</span></div>' +
    '<div class="stat-item"><span class="stat-value">' + s.total_edges.toLocaleString() + '</span><span class="stat-label">总唤醒次数</span></div>' +
    '<div class="stat-item"><span class="stat-value">' + s.max_depth + '</span><span class="stat-label">最大深度</span></div>' +
    '<div class="stat-item"><span class="stat-value">' + s.avg_depth.toFixed(1) + '</span><span class="stat-label">平均深度</span></div>' +
    '<div class="stat-item"><span class="stat-value">' + s.components + '</span><span class="stat-label">连通分量</span></div>';
}

// ============ 搜索 ============
var allNodes = DATA.all_nodes;
document.getElementById("search").addEventListener("input", function() {
  var q = this.value.toLowerCase().trim(), sug = document.getElementById("suggestions");
  if (!q) { sug.classList.remove("show"); return; }
  var results = allNodes.filter(function(n) {
    return n[1].toLowerCase().indexOf(q) >= 0 || String(n[0]).indexOf(q) >= 0;
  }).slice(0, 12);
  if (!results.length) { sug.classList.remove("show"); return; }
  sug.innerHTML = results.map(function(n) {
    return '<div class="suggest-item" data-pid="' + n[0] + '"><span><span class="s-name">' + esc(n[1]) + '</span><span class="s-pid">pid=' + n[0] + '</span></span><span class="s-badge">出' + n[2] + '/入' + n[3] + '</span></div>';
  }).join('');
  sug.classList.add("show");
});

document.getElementById("suggestions").addEventListener("click", function(e) {
  var it = e.target.closest(".suggest-item"); if (!it) return;
  var pid = parseInt(it.dataset.pid);
  document.getElementById("search").value = comm(pid);
  document.getElementById("suggestions").classList.remove("show");
  focusNode(pid);
});

// ============ 键盘 ============
document.addEventListener("keydown", function(e) {
  if (e.key === 'r' || e.key === 'R') {
    if (document.activeElement.tagName === 'INPUT') return;
    render(initialNodes, initialEdges);
    currentPid = null;
    document.getElementById("info").innerHTML = '<div style="color:#484f58;text-align:center;padding:20px">👆 搜索或点击节点查看详情</div>';
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
  }
});

// ============ 拖拽 ============
function dragStart(event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
function dragEnd(event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }

// ============ Tooltip ============
function showTooltip(event, d) {
  var tip = document.getElementById("tooltip");
  tip.innerHTML = '<b>' + esc(d.comm) + '</b> (pid=' + d.id + ')<br>唤醒 ' + d.out_deg + ' 次 | 被唤 ' + d.in_deg + ' 次';
  tip.style.display = "block";
  moveTooltip(event);
}
function moveTooltip(event) {
  var tip = document.getElementById("tooltip");
  var x = event.clientX + 12, y = event.clientY - 40;
  if (x + 240 > window.innerWidth) x = event.clientX - 250;
  if (y < 10) y = event.clientY + 15;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
function hideTooltip() { document.getElementById("tooltip").style.display = "none"; }

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// resize
window.addEventListener("resize", function() {
  width = svg.node().parentElement.clientWidth;
  height = svg.node().parentElement.clientHeight;
  simulation.force("center", d3.forceCenter(width / 2, height / 2));
  simulation.alpha(0.1).restart();
});
</script>
</body>
</html>'''


def generate_html(unique_edges, adj_out, adj_in, structure, pid_comm, output_path):
    """生成交互式 D3.js 力导向图 HTML"""
    
    # 构建紧凑节点数据: [[pid, comm, out_total, in_total], ...]
    all_pids = set()
    for w, e, c in unique_edges:
        all_pids.add(w)
        all_pids.add(e)
    
    all_nodes = []
    for pid in all_pids:
        out_total = sum(c for _, c in adj_out.get(pid, []))
        in_total = sum(c for _, c in adj_in.get(pid, []))
        all_nodes.append([pid, pid_comm.get(pid, f'?{pid}'), out_total, in_total])
    all_nodes.sort(key=lambda x: -(x[2] + x[3]))
    
    # nodes_map: pid -> {id, comm, out_deg, in_deg, degree}
    nodes_map = {}
    for pid, comm_name, out_d, in_d in all_nodes:
        nodes_map[str(pid)] = {
            'id': pid, 'comm': comm_name,
            'out_deg': out_d, 'in_deg': in_d,
            'degree': out_d + in_d,
        }
    
    # 邻接表: {"pid": [[wakee, count], ...]}
    adj_out_json = {}
    for pid, neighbors in adj_out.items():
        adj_out_json[str(pid)] = [[w, c] for w, c in sorted(neighbors, key=lambda x: -x[1])]
    adj_in_json = {}
    for pid, neighbors in adj_in.items():
        adj_in_json[str(pid)] = [[w, c] for w, c in sorted(neighbors, key=lambda x: -x[1])]
    
    # top_nodes: 按 degree 排序的前 100 个 pid
    top_nodes = [n[0] for n in all_nodes[:100]]
    
    data = {
        'all_nodes': all_nodes,
        'nodes_map': nodes_map,
        'adj_out': adj_out_json,
        'adj_in': adj_in_json,
        'top_nodes': top_nodes,
        'stats': {
            'nodes': structure['total_nodes'],
            'unique_edges': len(unique_edges),
            'total_edges': structure['total_edges'],
            'max_depth': structure['chain_depth_max'],
            'avg_depth': structure['chain_depth_avg'],
            'components': structure['num_components'],
        },
    }
    
    html = HTML_TEMPLATE.replace('__DATA__', json.dumps(data, ensure_ascii=False))
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"\n📄 HTML 可视化已生成: {output_path}")
    print(f"   节点: {len(all_nodes):,}  唯一边: {len(unique_edges):,}")
    print(f"   文件大小: {len(html) / 1024 / 1024:.1f} MB")


def main():
    parser = argparse.ArgumentParser(description='Android Systrace Wakeup Structure Analyzer')
    parser.add_argument('input', nargs='?', default='output.html')
    parser.add_argument('--json', '-j', default=None, help='导出 JSON 到文件')
    parser.add_argument('--html', '-H', default=None, help='导出交互式 D3.js HTML 可视化')
    args = parser.parse_args()
    
    print(f"📖 流式解析 {args.input} ...")
    edges, pid_comm, parse_stats = parse_and_build_graph(args.input)
    
    print(f"📐 分析唤醒链图结构...")
    structure = analyze_structure(edges, pid_comm)
    
    print_report(parse_stats, structure, pid_comm)
    
    if args.json:
        # 只保留可序列化的字段
        output = {
            'parse_stats': parse_stats,
            'structure': {k: v for k, v in structure.items() if k not in ('pid_comm',)},
        }
        # 转换 tuple keys
        output['structure']['top_wakers'] = [[pid, cnt, pid_comm.get(pid, '?')] 
                                              for pid, cnt in structure['top_wakers'][:50]]
        output['structure']['top_wakees'] = [[pid, cnt, pid_comm.get(pid, '?')] 
                                              for pid, cnt in structure['top_wakees'][:50]]
        output['structure']['roots'] = [[pid, out_d, in_d, pid_comm.get(pid, '?')] 
                                         for pid, out_d, in_d in structure['roots'][:50]]
        output['structure']['leaves'] = [[pid, in_d, out_d, pid_comm.get(pid, '?')] 
                                          for pid, in_d, out_d in structure['leaves'][:50]]
        with open(args.json, 'w') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        print(f"📄 JSON 已导出: {args.json}")

    if args.html:
        print(f"📊 聚合唯一边 (去重 waker-wakee 对)...")
        unique_edges, adj_out, adj_in = build_aggregated_graph(edges)
        print(f"   唯一边: {len(unique_edges):,} (原始时序边: {len(edges):,})")
        print(f"🎨 生成 D3.js 交互式力导向图...")
        generate_html(unique_edges, adj_out, adj_in, structure, pid_comm, args.html)


if __name__ == '__main__':
    main()
