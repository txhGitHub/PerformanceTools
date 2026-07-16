# Android Systrace Trace 分析工具集

从 Android ftrace 格式的 trace 提取并分析系统行为。

## 前置条件

所有脚本依赖 output.html 放在当前目录。

## 脚本概览

| 脚本 | 功能 | 输入 | 输出 |
|------|------|------|------|
| analyze_cpu_load.py | CPU 负载分析 | output.html | 终端打印 |
| analyze_root_functions.py | 统计所有根函数 | output.html | root_functions.csv |
| analyze_wakeup_functions.py | 唤醒事件与根函数关联 | output.html | wakeup_functions.csv |
| insert_functions_into_trace.py | 插入 synthetic 函数到 trace | CSV + output.html | output_with_functions.html |
| find_wakeup_chain.py | 查找唤醒调用链 | wakeup_functions.csv | wakeup_chain.txt |

## 推荐执行顺序

    python3 analyze_root_functions.py
    python3 analyze_wakeup_functions.py
    python3 insert_functions_into_trace.py
    python3 find_wakeup_chain.py "#159" "connect"

---

## 1. analyze_cpu_load.py - CPU 负载分析

    python3 analyze_cpu_load.py [选项]

| 选项 | 说明 | 默认值 |
|------|------|--------|
| -f, --file | trace 文件路径 | output.html |
| -s, --start | 起始时间戳(秒) | trace 起始 |
| -e, --end | 结束时间戳(秒) | trace 结束 |
| -i, --interval | 分段间隔(秒) | 不分段 |
| -t, --top | 进程排行前 N | 20 |

---

## 2. analyze_root_functions.py - 根函数统计

解析 tracing_mark_write B/E 事件，输出 root_functions.csv。

    python3 analyze_root_functions.py

---

## 3. analyze_wakeup_functions.py - 唤醒关系关联

将 sched_wakeup 与唤端/被唤端的根函数关联。

    python3 analyze_wakeup_functions.py

输出 wakeup_functions.csv，字段:
- 唤端 TID/PID, 匹配方式(containing/closest_previous/synthetic), 根函数, 时间段
- 被唤端 TID/PID, 匹配方式(spanning/next/synthetic), 根函数
- 唤时间戳, Running 时间, 延迟(us)

函数去重: 同名不同时段追加 _pid_tid_timestamp。
Synthetic 命名: pid_tid_timestamp (如 692_1087_2977601.813548)

---

## 4. insert_functions_into_trace.py - 插入 synthetic 标记

只插入 synthetic 函数(pid_tid_timestamp 格式)到 trace 副本。
标记时长 = 线程实际 running 时间(sched_switch in->out)。

    python3 insert_functions_into_trace.py

输出: output_with_functions.html (Perfetto 中可搜索 synthetic 函数名)

---

## 5. find_wakeup_chain.py - 查找唤链

BFS 查找两个函数间的唤路径。

    python3 find_wakeup_chain.py <起始关键字> <目标关键字>

示例:
    python3 find_wakeup_chain.py "#159" "connect"
    python3 find_wakeup_chain.py "#159" "registerReceiver"

输出: wakeup_chain.txt (存在则列出路径，不存在则说明原因)

---

## 数据流

    output.html
      |
      +-- analyze_root_functions.py --> root_functions.csv
      +-- analyze_cpu_load.py --> 终端输出
      +-- analyze_wakeup_functions.py --> wakeup_functions.csv
              |
              +-- insert_functions_into_trace.py --> output_with_functions.html
              +-- find_wakeup_chain.py --> wakeup_chain.txt
