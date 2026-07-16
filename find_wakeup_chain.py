#!/usr/bin/env python3
"""
从 wakeup_functions.csv 构建唤醒关系有向图，查找两个根函数之间是否存在唤醒调用链。

用法:
    python3 find_wakeup_chain.py <起始函数关键字> <目标函数关键字>

示例:
    python3 find_wakeup_chain.py "#159" "connect"

输出:
    wakeup_chain.txt  -- 若存在路径，写入完整链路；不存在则写入说明
"""

import csv
import sys
from collections import defaultdict, deque


def build_graph(csv_path):
    """
    构建有向图: out_edges[func_name] = [(wakee_name, wakeup_ts, running_ts, delay_us), ...]
    同时记录每个边的详细信息，方便输出
    """
    out_edges = defaultdict(list)  # waker -> [(wakee, wakeup_ts, running_ts, delay), ...]
    all_nodes = set()

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            waker = row[3]
            wakee = row[10]
            wakeup_ts = float(row[14])
            running_ts = row[16]
            delay = row[17]

            out_edges[waker].append((wakee, wakeup_ts, running_ts, delay))
            all_nodes.add(waker)
            all_nodes.add(wakee)

    return out_edges, all_nodes


def find_chain_bfs(out_edges, start_keyword, end_keyword):
    """
    BFS 查找从包含 start_keyword 的节点到包含 end_keyword 的节点的路径。
    返回 (path, chain_info, visited_count) 或 (None, error_msg, visited_count)
    """
    # 匹配节点：包含关键词。对 "connect" 特殊处理，排除 "disconnect"
    def _match(name, kw):
        if kw not in name:
            return False
        # 排除反义词干扰
        if kw == 'connect' and 'disconnect' in name:
            return False
        return True

    start_nodes = [n for n in out_edges if _match(n, start_keyword)]
    end_nodes = set(n for n in out_edges if _match(n, end_keyword))
    # 也要检查作为 wakee 但可能不在 out_edges key 中的节点
    all_values = set()
    for vlist in out_edges.values():
        for v, _, _, _ in vlist:
            all_values.add(v)
    end_nodes |= set(n for n in all_values if _match(n, end_keyword))

    if not start_nodes:
        return None, f"未找到包含 '{start_keyword}' 的函数", 0
    if not end_nodes:
        return None, f"未找到包含 '{end_keyword}' 的函数", 0

    print(f"起始匹配: {len(start_nodes)} 个")
    for sn in start_nodes[:3]:
        print(f"  - {sn[:100]}")
    if len(start_nodes) > 3:
        print(f"  ... 共 {len(start_nodes)} 个")
    print(f"目标匹配: {len(end_nodes)} 个")
    for en in list(end_nodes)[:3]:
        print(f"  - {en[:100]}")
    if len(end_nodes) > 3:
        print(f"  ... 共 {len(end_nodes)} 个")

    # BFS
    visited = set()
    parent = {}

    queue = deque()
    for sn in start_nodes:
        queue.append(sn)
        visited.add(sn)
        parent[sn] = None

    found_target = None
    while queue:
        current = queue.popleft()
        if current in end_nodes:
            found_target = current
            break

        for wakee, wakeup_ts, running_ts, delay in out_edges.get(current, []):
            if wakee not in visited:
                visited.add(wakee)
                parent[wakee] = (current, wakeup_ts, running_ts, delay)
                queue.append(wakee)

    if found_target is None:
        return None, (
            f"从 '{start_keyword}' 到 '{end_keyword}' 不存在直接唤醒调用链。\n"
            f"可能原因：中间步骤涉及 binder IPC、内核态调度等，\n"
            f"这些不会产生 sched_wakeup 边。BFS 已探索 {len(visited)} 个节点。"
        ), len(visited)

    # 回溯路径
    path = []
    node = found_target
    while node is not None:
        path.append(node)
        if parent[node] is None:
            break
        node = parent[node][0]
    path.reverse()

    # 构建详细信息
    chain_info = []
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        _, wakeup_ts, running_ts, delay = parent[b]
        chain_info.append((a, b, wakeup_ts, running_ts, delay))

    return path, chain_info, len(visited)


def format_output(path, chain_info, start_kw, end_kw):
    """格式化输出文本"""
    lines = []
    lines.append("=" * 80)
    lines.append(f"唤醒调用链: {start_kw} → {end_kw}")
    lines.append("=" * 80)
    lines.append(f"路径长度: {len(path)} 个节点, {len(chain_info)} 步\n")

    for i, (waker, wakee, wakeup_ts, running_ts, delay) in enumerate(chain_info, 1):
        lines.append(f"--- 第 {i} 步 ---")
        lines.append(f"  唤醒者: {waker}")
        lines.append(f"  被唤醒者: {wakee}")
        lines.append(f"  唤醒时间: {wakeup_ts:.6f} s")
        lines.append(f"  Running 时间: {running_ts} s")
        if delay:
            lines.append(f"  唤醒延迟: {delay} μs")
        lines.append("")

    lines.append("=" * 80)
    lines.append("完整节点序列:")
    for i, node in enumerate(path):
        lines.append(f"  [{i}] {node}")
    lines.append("=" * 80)

    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("用法: python3 find_wakeup_chain.py <起始函数关键字> <目标函数关键字>")
        print("示例: python3 find_wakeup_chain.py '#159' 'connect'")
        sys.exit(1)

    start_kw = sys.argv[1]
    end_kw = sys.argv[2]

    csv_path = 'wakeup_functions.csv'

    print(f"正在构建唤醒关系图...")
    out_edges, all_nodes = build_graph(csv_path)
    print(f"  节点数: {len(all_nodes)}")
    print(f"  边数: {sum(len(v) for v in out_edges.values())}")

    print(f"\n正在查找: {start_kw} → {end_kw}")

    path, result, visited_count = find_chain_bfs(out_edges, start_kw, end_kw)

    output_path = 'wakeup_chain.txt'

    if path is None:
        output_text = (
            f"唤醒调用链查询: {start_kw} → {end_kw}\n\n"
            f"结果: 不存在\n\n"
            f"{result}\n"
        )
        print(f"\n不存在。BFS 探索了 {visited_count} 个节点。")
    else:
        output_text = format_output(path, result, start_kw, end_kw)
        print(f"\n找到路径! 共 {len(path)} 个节点, {len(result)} 步")
        print(f"BFS 探索了 {visited_count} 个节点。")

    print(f"详情已写入 {output_path}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output_text)


if __name__ == '__main__':
    main()
