# Android Systrace CPU Load Analyzer

从 Android ftrace 文本格式的 trace 中提取并统计 CPU 负载信息。

## 用法

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

## 示例

```bash
# 统计整个 trace 期间的 CPU 负载
python3 analyze_cpu_load.py

# 统计指定时间段的负载
python3 analyze_cpu_load.py --start 2977600.0 --end 2977610.0

# 按 0.5 秒间隔统计各时段负载
python3 analyze_cpu_load.py --start 2977600.0 --end 2977610.0 --interval 0.5

# 多段查询（ranges.txt 每行: start end）
python3 analyze_cpu_load.py --ranges ranges.txt --top 30

# 列出所有 CPU 信息
python3 analyze_cpu_load.py --list-cpus

# 调试指定 CPU 的负载计算
python3 analyze_cpu_load.py --debug-cpu 7
```

## 原理

通过解析 ftrace 中的 `sched_switch` 事件，累计每个 CPU 上非 idle 任务的运行时间，计算各 CPU 的负载百分比。
