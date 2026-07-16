sched_waking  = 状态刚变 WAKING，还没进就绪队列  (waker 上下文中)
sched_wakeup  = 已进就绪队列，变为 RUNNABLE       (waker 上下文中)
sched_switch  = 被调度器选中，变为 "正在运行"      (CPU 上)
sched_wakeup_new 用户新创建的任务被首次唤醒





.android.camera-10083   (  10083) [002] ..... 2977601.634849: tracing_mark_write: B|10083|android.app.ActivityThread$H: #138
           <...>-10095   (  10083) [002] dn.3. 2977601.634924: sched_wakeup: comm=re-initialized> pid=10083 prio=110 target_cpu=004
		   jank-8538    (   8442) [004] d..2. 2977601.634996: sched_switch: prev_comm=jank prev_pid=8538 prev_prio=120 prev_state=S ==> next_comm=re-initialized> next_pid=10083 next_prio=110
		    .android.camera-10083   (  10083) [004] ..... 2977601.635015: tracing_mark_write: E|10083


如上面的trace,android.app.ActivityThread$H: #138开始执行后，到2977601.635015函数才执行结束，这个期间发生的唤醒操作。现在需求需要统计，根函数执行期间，根函数所在对应进程的线程唤醒情况，然后统计具体如下：


1、trace里面有很多函数的追踪新，需要统计出根函数执行的开始时间。
tracing_mark_write: B表示函数开始，tracing_mark_write: E表示执行结束差值就是执行时间。统一进程存在重复函数函数，因此需要确保同一进程和线程中函数名唯一。同一个进程和线程如果出现了相同的函数名，需要确保唯一，将函数对应的进程和线程id还有执行时间拼接到函数名字末尾，确保唯一性。时间格式入下：00:00:03.295465000 。


1、我们需要在trace里面找到唤醒者唤醒时执行的函数和被唤醒者被唤醒之后执行的函数，帮忙找几个例子，我确认你找的对不对再开始编码，trace是当前目录中的output.html

1、统计output.html trace信息中所有的根函数开始执行时间，以及持续时间，需要记录线程号和进程号


1、找出了函数开始时间和持续时间，是不是可以找出所有唤醒唤醒


所有唤醒边都有两端的节点，图是连通的

分析维度	方法	价值
关键路径	DAG 最长路径/拓扑排序	找出耗时最长的调度链
瓶颈定位	每段 wakeup→running 延迟排序	哪些唤醒等待最长
热点扇出	某节点唤醒的子节点数量	哪些函数是调度热点
时间归属	沿链累加耗时	总耗时中各线程占比
并发度	时间线重叠分析	哪些步骤可以并行
synthetic 占比	synthetic 节点耗时/总耗时	无 ATrace 的"黑盒"占多少