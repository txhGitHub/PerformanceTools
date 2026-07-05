# Android Systrace Trace 分析工具集

从 Android ftrace 文本格式的 trace (嵌入在 systrace HTML 中) 提取并分析系统行为。

## 工具列表

| 工具 | 说明 |
|------|------|
| `analyze_cpu_load.py` | CPU 负载分析 |
| `analyze_wakeup.py` | 唤醒操作分析 |
| `collect_wakeup.sh` | 使用 ftrace 收集唤醒事件数据 |

---

## 1. CPU 负载分析 (`analyze_cpu_load.py`)

从 ftrace 的 `sched_switch` 事件中统计各 CPU 及进程的负载信息。

### 用法

```bash
python3 analyze_cpu_load.py [选项]
```

### 选项

| 选项 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--file` | `-f` | trace HTML 文件路径 | `output.html` |
| `--start` | `-s` | 起始时间戳（秒） | 整个 trace 起始 |
| `--end` | `-e` | 结束时间戳（秒） | 整个 trace 结束 |
| `--interval` | `-i` | 分段统计的时间间隔（秒） | 不分段 |
| `--ranges` | `-r` | 多段查询文件（每行 `start end`，`#` 开头为注释） | — |
| `--top` | `-t` | 进程负载排行显示前 N 名 | 20 |
| `--list-cpus` | — | 列出所有 CPU 及时间范围 | — |
| `--debug-cpu` | — | dump 指定 CPU 的负载计算详情到 txt 文件 | — |
| `--debug-output` | — | debug dump 输出文件路径 | `cpu<ID>_debug.txt` |

### 示例

```bash
python3 analyze_cpu_load.py
python3 analyze_cpu_load.py --start 2977600.0 --end 2977610.0
python3 analyze_cpu_load.py --start 2977600.0 --end 2977610.0 --interval 0.5
python3 analyze_cpu_load.py --ranges ranges.txt --top 30
```

### 原理

通过解析 ftrace 中的 `sched_switch` 事件，累计每个 CPU 上非 idle 任务的运行时间，计算各 CPU 的负载百分比。

---

## 2. 唤醒操作分析 (`analyze_wakeup.py`)

从 ftrace 中统计每次唤醒操作，输出:
- **唤醒者 (Waker)**: 执行唤醒操作的进程/线程
- **唤醒者函数**: 唤醒者正在执行的函数 (需要 ftrace function_graph 支持，否则为空)
- **被唤醒者 (Wakee)**: 被唤醒的进程/线程
- **被唤醒者函数**: 被唤醒后将执行的函数 (来自 `sched_blocked_reason` 的 `caller` 字段)

### 用法

```bash
python3 analyze_wakeup.py [选项]
```

### 选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-f, --file` | trace HTML 文件路径 | `output.html` |
| `-o, --output` | 导出 CSV 文件路径 | 终端输出 |
| `--csv` | 以 CSV 格式输出到终端 | — |
| `--start` | 起始时间戳（秒） | 无限制 |
| `--end` | 结束时间戳（秒） | 无限制 |
| `--top N` | 只显示前 N 条记录 | 全部 |
| `--waker FUNC` | 按唤醒者函数筛选 (子串匹配) | — |
| `--wakee FUNC` | 按被唤醒者函数筛选 (子串匹配) | — |
| `--stats` | 仅显示统计摘要 | — |
| `--by-waker` | 按唤醒者分组统计 | — |
| `--by-wakee` | 按被唤醒者分组统计 | — |
| `--by-wakee-func` | 按被唤醒者函数分组统计 | — |

### 示例

```bash
# 分析 output.html 中的唤醒操作 (显示表格)
python3 analyze_wakeup.py

# 只看前 20 条
python3 analyze_wakeup.py --top 20

# 统计摘要 + 被唤醒函数排行
python3 analyze_wakeup.py --stats --by-wakee-func --top 15

# 按时间范围筛选
python3 analyze_wakeup.py --start 2977600.0 --end 2977600.5

# 导出 CSV
python3 analyze_wakeup.py --csv -o wakeup_result.csv

# 按特定函数筛选
python3 analyze_wakeup.py --wakee worker_thread
```

### 原理

1. 解析 `sched_waking` 事件 — waker 信息在事件头部，wakee 信息在事件内容中
2. 解析 `sched_blocked_reason` 事件 — wakee 阻塞时所在的函数 (`caller` 字段) 即为被唤醒后将执行的函数
3. `sched_blocked_reason` 紧随 `sched_waking` 在同一 CPU 上出现，通过 pid 和时间戳进行匹配
4. 若内核开启了 function_graph tracer，还可获取 waker 的调用栈函数

### 输出字段

| 字段 | 说明 |
|------|------|
| Timestamp | 唤醒事件时间戳 (秒) |
| Waker(TID) | 唤醒者进程名(TID) |
| Waker_Function | 唤醒者正在执行的函数 (需 function_graph，否则为空) |
| Wakee(PID) | 被唤醒者进程名(PID) |
| Wakee_Function | 被唤醒后将执行的函数 (来自 blocked_reason caller) |

---

## 3. 收集唤醒 Trace (`collect_wakeup.sh`)

在 Linux/Android 设备上使用 ftrace 收集唤醒事件数据 (需要 root 权限)。

```bash
sudo ./collect_wakeup.sh -t 30 -o wakeup_trace.txt
```
