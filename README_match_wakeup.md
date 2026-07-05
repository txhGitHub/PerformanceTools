# Wakeup-Function Matcher

从 Android Systrace HTML 中解析 `tracing_mark_write` (atrace B/E 标记) 和 `sched_waking` 事件，
匹配每次唤醒发生时唤醒者正在执行的函数，并支持函数间唤醒关系查询。

## 快速开始

```bash
# 首次运行: 解析 output.html → 匹配 → 保存结果
python3 match_wakeup_func.py

# 后续查询: 从缓存加载 (秒级)
python3 match_wakeup_func.py --load wakeup_matched.json --stats
```

## 处理流程

| 步骤 | 说明 |
|:---:|------|
| 1 | 解析 atrace B/E 标记，构建每线程的**栈顶函数**执行时间段 |
| 2 | 解析 `sched_waking` / `sched_wakeup_new`，提取所有唤醒关系 |
| 3 | 对每次唤醒，二分查找唤醒时刻 waker 线程正在执行的栈顶函数 |
| 4 | 保存 JSON，支持函数间唤醒关系查询 |

## 函数名唯一性

同一进程/线程的同名函数通过拼接 `pid`、`tid`、开始时间戳确保唯一：

```
原始格式:  queueBuffer
唯一格式:  queueBuffer_pid7735_tid7908_2977599.258233
```

## 用法

```
python3 match_wakeup_func.py [选项]
```

### 解析 & 匹配

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-f, --file` | trace HTML 文件路径 | `output.html` |
| `-o, --output` | 匹配结果 JSON 路径 | `wakeup_matched.json` |
| `--top N` | 显示前 N 条 | 全部 |
| `--stats` | 仅显示统计摘要 | — |
| `--by-waker-func` | 按 waker 函数分组排行 | — |
| `--by-wakee-func` | 按 wakee 函数分组排行 | — |

### 查询 (从缓存)

| 选项 | 说明 |
|------|------|
| `--load FILE` | 从 JSON 缓存加载 (跳过解析) |
| `--query FROM TO` | 函数 A 是否唤醒过函数 B |
| `--from-func NAME` | 某函数唤醒了哪些函数 |
| `--to-func NAME` | 哪些函数唤醒了某函数 |
| `--tid TID` | 指定线程相关的所有唤醒 |

## 示例

```bash
# 统计概览
python3 match_wakeup_func.py --stats --by-waker-func --top 10

# 显示前 30 条匹配结果
python3 match_wakeup_func.py --top 30

# queueBuffer 唤醒了谁的 worker_thread
python3 match_wakeup_func.py --load wakeup_matched.json --query queueBuffer worker_thread

# queueBuffer 唤醒了哪些函数
python3 match_wakeup_func.py --load wakeup_matched.json --from-func queueBuffer

# 线程 10083 (.android.camera) 的所有唤醒
python3 match_wakeup_func.py --load wakeup_matched.json --tid 10083
```

## 输出字段

### JSON 结构

```json
{
  "total": 166623,
  "matched_waker_func": 35173,
  "matched_wakee_func": 27330,
  "events": [
    {
      "timestamp": 2977601.604141,
      "cpu": 0,
      "waker_comm": ".android.camera",
      "waker_pid": 10083,
      "waker_tid": 10083,
      "waker_func": "ctl_done_irq|0_pid0_tid0_2977601.604117",
      "wakee_comm": "crtc_commit:204",
      "wakee_pid": 1315,
      "wakee_func": "sde_encoder_helper_wait_for_irq+0x280/0x738 [msm_drm]",
      "wakeup_type": "waking"
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `timestamp` | 唤醒时间戳 (秒) |
| `waker_comm` / `waker_pid` / `waker_tid` | 唤醒者进程名 / PID / TID |
| `waker_func` | 唤醒者正在执行的函数 (唯一名, 未匹配为空) |
| `wakee_comm` / `wakee_pid` | 被唤醒者进程名 / PID |
| `wakee_func` | 被唤醒者阻塞函数 (来自 `sched_blocked_reason`, 无则为空) |
| `wakeup_type` | `waking` (常规) / `wakeup_new` (新创建任务) |

## 原理

```
tracing_mark_write B|pid|func   →  函数入栈 (开始执行)
tracing_mark_write E|pid        →  函数出栈 (执行结束)
栈顶函数 = 最近入栈且未出栈的函数

sched_waking 在 waker 上下文中触发
→ 此时 waker 线程的栈顶函数 = 正在执行且触发了唤醒的函数
```

## 依赖

- Python 3.6+
- 无外部依赖 (仅标准库)
