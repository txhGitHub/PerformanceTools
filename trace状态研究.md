sched_waking  = 状态刚变 WAKING，还没进就绪队列  (waker 上下文中)
sched_wakeup  = 已进就绪队列，变为 RUNNABLE       (waker 上下文中)
sched_switch  = 被调度器选中，变为 "正在运行"      (CPU 上)
sched_wakeup_new 用户新创建的任务被首次唤醒



1、统计所有的调用栈，只保留第一个入栈函数，减少数据量，需要统计出函数执行的开始时间，结束时间进程id和线程id，用于匹配唤醒关系，同一个进程和线程如果出现了相同的函数名，需要确保唯一，将函数对应的进程和线程id还有执行时间拼接到函数名字末尾，唯一性
2、统计出所有的唤醒关系以及开始时间
3、匹配唤醒开始时在对应线程那个函数执行的时间内，则能找到唤醒线程对应的函数，如果无对应的函数则为空就行，但是需要记录进程id和线程id，明确唤醒的是谁
4、将匹配好的数据保存，用户查询，从一个函数到另一个函数是否存在调用关系，多个唤醒关系对应相同的函数名没问题，本身可能是那个时间段唤醒关系



我看trace里面有两个android.app.ActivityThread$H: #110，一个执行时间13ms,一个执行176ms,函数的结束时间是不是统计错了,另外我想说遇到

.android.camera-10083   (  10083) [004] ..... 2977601.635028: tracing_mark_write: B|10083|android.app.ActivityThread$H: #110
tracing_mark_write: E
遇到tracing_mark_write: B，可以先放到栈底，若是下一个函数开始执行，也进栈，遇到tracing_mark_write: E，可以把栈顶的出栈，直到android.app.ActivityThread$H: #110出栈是就是，统计时间差就是执行时间
