---
id: 6-kube-controller-code
title: ttlafterfinished-controller 代码走读
description: ttlafterfinished-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

在 Kubernetes 中，Job用于管理批处理任务。当一个Job完成后，通常会保留与该Job相关的 Pod 以供检查和调试。但是，这些 Pod 可能会占用集群资源，因此需要手动删除这些 Pod。为了简化这个过程，Kubernetes 引入了 `TTLAfterFinished` 控制器来自动删除这些 Pod。

`TTLAfterFinished` 控制器通过在Job的 `spec` 中添加 `ttlSecondsAfterFinished` 字段来实现自动删除 Pod 的功能。当Job完成后，`TTLAfterFinished` 控制器会启动一个计时器，等待 `ttlSecondsAfterFinished` 指定的时间，然后删除与该Job相关的所有 Pod。如果Job成功完成，则可以在此期间检查和调试 Pod。如果 Pod 在 `ttlSecondsAfterFinished` 时间内未能成功完成，则 `TTLAfterFinished` 控制器将立即删除它们。

## 结构体

```go

type Controller struct {
    // client-go clientset
	client   clientset.Interface
    // 记录控制器事件
	recorder record.EventRecorder

	// job lister
	jLister batchlisters.JobLister

	//  job lister时候同步完成
	jListerSynced cache.InformerSynced

	// 处理job的队列
	queue workqueue.RateLimitingInterface

	// 追踪时间
	clock clock.Clock
}

```

## New

```go
func New(jobInformer batchinformers.JobInformer, client clientset.Interface) *Controller {
    // 创建了一个事件广播器
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
    // 使用client.CoreV1().Events("")作为事件记录器的目标
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	
    // 注册metrics
	metrics.Register()

	tc := &Controller{
		client:   client,
        // 记录器
		recorder: eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "ttl-after-finished-controller"}),
        // 工作队列
		queue:    workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ttl_jobs_to_delete"),
	}
	
    // 监控job的add update
	jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    tc.addJob,
		UpdateFunc: tc.updateJob,
	})

	tc.jLister = jobInformer.Lister()
	tc.jListerSynced = jobInformer.Informer().HasSynced
	
    // 新键时钟实例，用于跟踪时间
	tc.clock = clock.RealClock{}

	return tc
}
```

```go

func (tc *Controller) addJob(obj interface{}) {
	job := obj.(*batch.Job)
	klog.V(4).Infof("Adding job %s/%s", job.Namespace, job.Name)
	
    // job删除并且需要清理 计入queue
	if job.DeletionTimestamp == nil && needsCleanup(job) {
		tc.enqueue(job)
	}
}

func (tc *Controller) updateJob(old, cur interface{}) {
	job := cur.(*batch.Job)
	klog.V(4).Infof("Updating job %s/%s", job.Namespace, job.Name)
	
    // 新的job删除并且需要清理 计入queue
	if job.DeletionTimestamp == nil && needsCleanup(job) {
		tc.enqueue(job)
	}
}

// 加入队列
func (tc *Controller) enqueue(job *batch.Job) {
	klog.V(4).Infof("Add job %s/%s to cleanup", job.Namespace, job.Name)
	key, err := controller.KeyFunc(job)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", job, err))
		return
	}

	tc.queue.Add(key)
}


// 判断是不是要清理 如果TTLSecondsAfterFinished不是空并且job完成了 就要清理了
func needsCleanup(j *batch.Job) bool {
	return j.Spec.TTLSecondsAfterFinished != nil && jobutil.IsJobFinished(j)
}

// 判断job是不是完成了 如果job的Conditions中的type有JobComplete和JobFailed就是完成了
func IsJobFinished(j *batch.Job) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batch.JobComplete || c.Type == batch.JobFailed) && c.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}
```

### metrics

性能指标，给`promethues`等工具用。

```go
const TTLAfterFinishedSubsystem = "ttl_after_finished_controller"

var (
	// JobDeletionDurationSeconds tracks the time it took to delete the job since it
	// became eligible for deletion.
	JobDeletionDurationSeconds = metrics.NewHistogram(
		&metrics.HistogramOpts{
			Subsystem:      TTLAfterFinishedSubsystem,
			Name:           "job_deletion_duration_seconds",
			Help:           "The time it took to delete the job since it became eligible for deletion",
			StabilityLevel: metrics.ALPHA,
			// Start with 100ms with the last bucket being [~27m, Inf).
			Buckets: metrics.ExponentialBuckets(0.1, 2, 14),
		},
	)
)

var registerMetrics sync.Once

// Register registers TTL after finished controller metrics.
func Register() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(JobDeletionDurationSeconds)
	})
}

```

### Clock

```go
type PassiveClock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type Clock interface {
	PassiveClock
	// After returns the channel of a new Timer.
	// This method does not allow to free/GC the backing timer before it fires. Use
	// NewTimer instead.
	After(d time.Duration) <-chan time.Time
	// NewTimer returns a new Timer.
	NewTimer(d time.Duration) Timer
	// Sleep sleeps for the provided duration d.
	// Consider making the sleep interruptible by using 'select' on a context channel and a timer channel.
	Sleep(d time.Duration)
	// Tick returns the channel of a new Ticker.
	// This method does not allow to free/GC the backing ticker. Use
	// NewTicker from WithTicker instead.
	Tick(d time.Duration) <-chan time.Time
}

// RealClock really calls time.Now()
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// Since returns time since the specified timestamp.
func (RealClock) Since(ts time.Time) time.Duration {
	return time.Since(ts)
}

// After is the same as time.After(d).
// This method does not allow to free/GC the backing timer before it fires. Use
// NewTimer instead.
func (RealClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

// NewTimer is the same as time.NewTimer(d)
func (RealClock) NewTimer(d time.Duration) Timer {
	return &realTimer{
		timer: time.NewTimer(d),
	}
}

// Tick is the same as time.Tick(d)
// This method does not allow to free/GC the backing ticker. Use
// NewTicker instead.
func (RealClock) Tick(d time.Duration) <-chan time.Time {
	return time.Tick(d)
}

func (RealClock) Sleep(d time.Duration) {
	time.Sleep(d)
}
```

## Run

```go
func (tc *Controller) Run(ctx context.Context, workers int) {
    // 退出函数处理panic和关闭queue
	defer utilruntime.HandleCrash()
	defer tc.queue.ShutDown()

	klog.Infof("Starting TTL after finished controller")
	defer klog.Infof("Shutting down TTL after finished controller")
	
    // 等待lister同步完成
	if !cache.WaitForNamedCacheSync("TTL after finished", ctx.Done(), tc.jListerSynced) {
		return
	}
	
    // 启动workers个goroutine处理worker
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, tc.worker, time.Second)
	}

	<-ctx.Done()
}
```

## worker

worker 的逻辑是监控 job 的创建并计算出它们的 TTL。如果 TTL 小于等于零，那么这意味着 job 已经过期了，会直接删除该 job，并使用 Foreground 模式进行级联删除。如果 TTL 大于零，那么会将 job 延迟加入队列，并在 TTL 时间之后再次取出。这个过程会不断重复，直到 TTL 小于等于零为止，此时会删除该 job。

```go
func (tc *Controller) worker(ctx context.Context) {
    // 循环执行processNextWorkItem 知道返回false
	for tc.processNextWorkItem(ctx) {
	}
}

func (tc *Controller) processNextWorkItem(ctx context.Context) bool {
    // 从queue中拿key 如果没有了 就返回false
	key, quit := tc.queue.Get()
	if quit {
		return false
	}
    // 拿出来 删除结束 Done掉
	defer tc.queue.Done(key)

	err := tc.processJob(ctx, key.(string))
    // 处理错误
	tc.handleErr(err, key)

	return true
}
```

### processJob

```go
func (tc *Controller) processJob(ctx context.Context, key string) error {
    // 从key中获取namespace和name（jobName）
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	klog.V(4).Infof("Checking if Job %s/%s is ready for cleanup", namespace, name)
	// 从lister获取job
    job, err := tc.jLister.Jobs(namespace).Get(name)
	if errors.IsNotFound(err) {
        // 没找到就不处理了
		return nil
	}
    // 报错返回
	if err != nil {
		return err
	}
	
    // 检查 Job 是否已经过期
	if expiredAt, err := tc.processTTL(job); err != nil {
		return err
	} else if expiredAt == nil {
        //  Job 没有过期，则返回 nil
		return nil
	}

	// 从apiserver获取job的最新对象
	fresh, err := tc.client.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
        // 没找到就不处理了
		return nil
	}
	if err != nil {
		return err
	}
	// 检查 新Job 是否已经过期 过期直接返回nil
	expiredAt, err := tc.processTTL(fresh)
	if err != nil {
		return err
	} else if expiredAt == nil {
		return nil
	}
	// 使用Foreground方式删除 如果不指定默认是Background
	policy := metav1.DeletePropagationForeground
	options := metav1.DeleteOptions{
		PropagationPolicy: &policy,
		Preconditions:     &metav1.Preconditions{UID: &fresh.UID},
	}
	klog.V(4).Infof("Cleaning up Job %s/%s", namespace, name)
    // 删除job
	if err := tc.client.BatchV1().Jobs(fresh.Namespace).Delete(ctx, fresh.Name, options); err != nil {
		return err
	}
    // 用于记录作业删除过程的持续时间
	metrics.JobDeletionDurationSeconds.Observe(time.Since(*expiredAt).Seconds())
	return nil
}
```

#### processTTL

```go
func (tc *Controller) processTTL(job *batch.Job) (expiredAt *time.Time, err error) {
	// 如果已被删除 或者不需要清理 直接返回
	if job.DeletionTimestamp != nil || !needsCleanup(job) {
		return nil, nil
	}

	now := tc.clock.Now()
    // 计算出当前 job 的 TTL 时间 t 和过期时间 e
	t, e, err := timeLeft(job, &now)
	if err != nil {
		return nil, err
	}

	// ttl<0 表示早都过期了 外面会马上清理
	if *t <= 0 {
		return e, nil
	}
	
    // 加入队列 再ttl之后执行
	tc.enqueueAfter(job, *t)
	return nil, nil
}
```

##### timeLeft

```go
func timeLeft(j *batch.Job, since *time.Time) (*time.Duration, *time.Time, error) {
    // 获取完成时间和过期时间
	finishAt, expireAt, err := getFinishAndExpireTime(j)
	if err != nil {
		return nil, nil, err
	}
	if finishAt.After(*since) {
        // 完成时间在传进来now之后 打印警告
		klog.Warningf("Warning: Found Job %s/%s finished in the future. This is likely due to time skew in the cluster. Job cleanup will be deferred.", j.Namespace, j.Name)
	}
    // 过期时间减去现在就是TTL（剩余的时间）
	remaining := expireAt.Sub(*since)
	klog.V(4).Infof("Found Job %s/%s finished at %v, remaining TTL %v since %v, TTL will expire at %v", j.Namespace, j.Name, finishAt.UTC(), remaining, since.UTC(), expireAt.UTC())
	return &remaining, expireAt, nil
}

func getFinishAndExpireTime(j *batch.Job) (*time.Time, *time.Time, error) {
    // 不要清理 直接返回报错 没有时间
	if !needsCleanup(j) {
		return nil, nil, fmt.Errorf("job %s/%s should not be cleaned up", j.Namespace, j.Name)
	}
    // 获取job的完成时间
	t, err := jobFinishTime(j)
	if err != nil {
		return nil, nil, err
	}
	finishAt := t.Time
    // 完成时间+TTLSecondsAfterFinished就是过期时间
	expireAt := finishAt.Add(time.Duration(*j.Spec.TTLSecondsAfterFinished) * time.Second)
	return &finishAt, &expireAt, nil
}

func jobFinishTime(finishedJob *batch.Job) (metav1.Time, error) {
    // 如果job的Conditions的type有JobComplete或者JobFailed 就是完成了
	for _, c := range finishedJob.Status.Conditions {
		if (c.Type == batch.JobComplete || c.Type == batch.JobFailed) && c.Status == v1.ConditionTrue {
			finishAt := c.LastTransitionTime
			if finishAt.IsZero() {
                // 完成时间是空的 报错
				return metav1.Time{}, fmt.Errorf("unable to find the time when the Job %s/%s finished", finishedJob.Namespace, finishedJob.Name)
			}
			return c.LastTransitionTime, nil
		}
	}

	// This should never happen if the Jobs has finished
	return metav1.Time{}, fmt.Errorf("unable to find the status of the finished Job %s/%s", finishedJob.Namespace, finishedJob.Name)
}

```

#### enqueueAfter

```go
func (tc *Controller) enqueueAfter(job *batch.Job, after time.Duration) {
    // 获取key
	key, err := controller.KeyFunc(job)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", job, err))
		return
	}
	
    // after时间后加入队列
	tc.queue.AddAfter(key, after)
}

```

### handleErr

```GO
func (tc *Controller) handleErr(err error, key interface{}) {
	if err == nil {
        // 将队列中这个key最后一个删除
		tc.queue.Forget(key)
		return
	}

	utilruntime.HandleError(fmt.Errorf("error cleaning up Job %v, will retry: %v", key, err))
    // 如果出错了加入重试队列
	tc.queue.AddRateLimited(key)
}
```

