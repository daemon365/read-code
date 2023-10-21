
## 简介

管理 CronJob 对象。CronJob 是一种 Kubernetes 资源对象，可以定期运行一个或多个任务。

CronJob 对象的工作方式类似于 Unix 中的 Cron 任务。CronJob 可以在指定的时间间隔内运行一个或多个 Pod。您可以使用 CronJob 创建周期性任务，例如备份、清理、报告等。Kubernetes CronJob 控制器会根据 CronJob 对象中的规范，根据预定时间表自动创建和管理 Pod。

CronJob 控制器在 Kubernetes 集群中的作用是确保 CronJob 规范中定义的任务在计划的时间内运行，并且可以在出现故障时进行自我修复。CronJob 控制器将 Pod 的状态与 CronJob 规范中定义的期望状态进行比较，并在 Pod 出现故障时自动创建新的 Pod。

此外，CronJob 控制器还提供了一些其他功能，例如：

- 控制 CronJob 对象中运行任务的数量和并发性
- 记录 CronJob 运行历史记录和日志
- 提供命令行界面和 API 接口来管理和监视 CronJob 对象

## 结构体

```go
type ControllerV2 struct {
    // 工作队列
	queue workqueue.RateLimitingInterface
	// k8s go-client clientset
	kubeClient  clientset.Interface
    // 记录事件和广播事件
	recorder    record.EventRecorder
	broadcaster record.EventBroadcaste	
	// 创建、更新、删除 Job 对象
	jobControl     jobControlInterface
    // 创建、更新、删除 CronJob 对象
	cronJobControl cjControlInterface

	jobLister     batchv1listers.JobLister
	cronJobLister batchv1listers.CronJobLister

	jobListerSynced     cache.InformerSynced
	cronJobListerSynced cache.InformerSynced

	// 当前时间
	now func() time.Time
}
```

## New

```GO
func NewControllerV2(ctx context.Context, jobInformer batchv1informers.JobInformer, cronJobsInformer batchv1informers.CronJobInformer, kubeClient clientset.Interface) (*ControllerV2, error) {
	logger := klog.FromContext(ctx)
	eventBroadcaster := record.NewBroadcaster()

	jm := &ControllerV2{
		queue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cronjob"),
		kubeClient:  kubeClient,
		broadcaster: eventBroadcaster,
		recorder:    eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "cronjob-controller"}),

		jobControl:     realJobControl{KubeClient: kubeClient},
		cronJobControl: &realCJControl{KubeClient: kubeClient},

		jobLister:     jobInformer.Lister(),
		cronJobLister: cronJobsInformer.Lister(),

		jobListerSynced:     jobInformer.Informer().HasSynced,
		cronJobListerSynced: cronJobsInformer.Informer().HasSynced,
		now:                 time.Now,
	}
	// 监控job
	jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    jm.addJob,
		UpdateFunc: jm.updateJob,
		DeleteFunc: jm.deleteJob,
	})
	// 监控 cornjob
	cronJobsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			jm.enqueueController(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			jm.updateCronJob(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			jm.enqueueController(obj)
		},
	})
	// metrics
	metrics.Register()

	return jm, nil
}
```

### 队列相关

#### job

```go
func (jm *ControllerV2) addJob(obj interface{}) {
	job := obj.(*batchv1.Job)
	if job.DeletionTimestamp != nil {
		// 在控制器重启时，可能会出现一个处于删除状态的 Job 对象已经存在的情况，
        // 这时需要避免将该 Job 对象作为创建观察对象。
		jm.deleteJob(job)
		return
	}

	// 如果该 Job 对象有 ControllerRef 字段，则说明该 Job 对象由 CronJob 创建，
    // 需要将该 CronJob 加入队列等待处理
	if controllerRef := metav1.GetControllerOf(job); controllerRef != nil {
		cronJob := jm.resolveControllerRef(job.Namespace, controllerRef)
		if cronJob == nil {
			return
		}
		jm.enqueueController(cronJob)
		return
	}
}

func (jm *ControllerV2) updateJob(old, cur interface{}) {
	curJob := cur.(*batchv1.Job)
	oldJob := old.(*batchv1.Job)
	if curJob.ResourceVersion == oldJob.ResourceVersion {
        // 如果当前 Job 对象的资源版本和旧的 Job 对象的资源版本相同，则不进行处理
		// 定期同步会向所有已知的 Job 对象发送更新事件，但是不同版本的相同 Job 对象总是具有不同的资源版本。
		return
	}
	// 获取当前 Job 对象和旧的 Job 对象的 ControllerRef 字段
	curControllerRef := metav1.GetControllerOf(curJob)
	oldControllerRef := metav1.GetControllerOf(oldJob)
    // 判断当前 Job 对象和旧的 Job 对象的 ControllerRef 字段是否相同
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		 // 如果 ControllerRef 发生了变化并且旧的 Job 对象有 ControllerRef 字段，则需要同步旧的控制器
		if cronJob := jm.resolveControllerRef(oldJob.Namespace, oldControllerRef); cronJob != nil {
			jm.enqueueController(cronJob)
		}
	}

	// 如果当前 Job 对象有 ControllerRef 字段，则需要将其对应的 CronJob 对象加入队列等待处理
	if curControllerRef != nil {
		cronJob := jm.resolveControllerRef(curJob.Namespace, curControllerRef)
		if cronJob == nil {
			return
		}
		jm.enqueueController(cronJob)
		return
	}
}

func (jm *ControllerV2) deleteJob(obj interface{}) {
	job, ok := obj.(*batchv1.Job)

	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		job, ok = tombstone.Obj.(*batchv1.Job)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Job %#v", obj))
			return
		}
	}

	controllerRef := metav1.GetControllerOf(job)
	if controllerRef == nil {
		// 任何控制器都不应该关心被删除的孤立项
		return
	}
	cronJob := jm.resolveControllerRef(job.Namespace, controllerRef)
	if cronJob == nil {
		return
	}
	jm.enqueueController(cronJob)
}
```

##### resolveControllerRef

```GO
func (jm *ControllerV2) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *batchv1.CronJob {
	if controllerRef.Kind != controllerKind.Kind {
		return nil
	}
	cronJob, err := jm.cronJobLister.CronJobs(namespace).Get(controllerRef.Name)
	if err != nil {
		return nil
	}
	if cronJob.UID != controllerRef.UID {
		return nil
	}
	return cronJob
}
```

##### enqueueController

```GO
func (jm *ControllerV2) enqueueController(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}

	jm.queue.Add(key)
}
```

#### cronjob

```go
func (jm *ControllerV2) updateCronJob(logger klog.Logger, old interface{}, curr interface{}) {
	oldCJ, okOld := old.(*batchv1.CronJob)
	newCJ, okNew := curr.(*batchv1.CronJob)

	if !okOld || !okNew {
		 // 类型转换失败，需要更好的处理方式，可以记录日志。
		return
	}
	// 如果 CronJob 对象中的 Schedule 字段发生变化，则需要重新计算下一次运行的时间，
    // 并将新的 CronJob 对象加入到队列中，以便后续处理。
	if oldCJ.Spec.Schedule != newCJ.Spec.Schedule || !pointer.StringEqual(oldCJ.Spec.TimeZone, newCJ.Spec.TimeZone) {
		// Schedule 发生变化，需要更改下一次运行的时间，并将新 CronJob 加入到队列中。
        // 此处将同步过程中可能产生的警告输出到空记录器。
		sched, err := cron.ParseStandard(formatSchedule(newCJ, nil))
		if err != nil {
			// 这可能是用户在定义规范值时的错误。
            // 我们应记录错误，并在规范更新之前不要调节此 cronjob。
			logger.V(2).Info("Unparseable schedule for cronjob", "cronjob", klog.KObj(newCJ), "schedule", newCJ.Spec.Schedule, "err", err)
			jm.recorder.Eventf(newCJ, corev1.EventTypeWarning, "UnParseableCronJobSchedule", "unparseable schedule for cronjob: %s", newCJ.Spec.Schedule)
			return
		}
		now := jm.now()
		t := nextScheduleTimeDuration(newCJ, now, sched)

		jm.enqueueControllerAfter(curr, *t)
		return
	}

	// 如果 CronJob 对象中的其它参数发生了变化，则将新的 CronJob 对象加入到队列中。
    // 如果变化在 deadline 内被触发，则同步循环将处理 CronJob 对象的更新，否则将在下一次运行时处理。
    // TODO: 需要显式地处理 spec.JobTemplate.metadata.labels 的更改，以清理具有旧标签的作业。
	jm.enqueueController(curr)
}
```

##### nextScheduleTimeDuration

```go
func nextScheduleTimeDuration(cj *batchv1.CronJob, now time.Time, schedule cron.Schedule) *time.Duration {
    // 获取当前时间下最近的CronJob的计划执行时间。如果发生错误，将会将当前时间设为最近的时间，
    // 如果没有找到最近的时间，将会将最早的时间设为最近的时间。
	earliestTime, mostRecentTime, _, err := mostRecentScheduleTime(cj, now, schedule, false)
	if err != nil {
		mostRecentTime = &now
	} else if mostRecentTime == nil {
		mostRecentTime = &earliestTime
	}
	
    // 将找到的最近时间与nextScheduleDelta（常量定义在其他地方）相加，再减去当前时间得到下一个计划执行时间
	t := schedule.Next(*mostRecentTime).Add(nextScheduleDelta).Sub(now)
	return &t
}
```

###### mostRecentScheduleTime

```go
func mostRecentScheduleTime(cj *batchv1.CronJob, now time.Time, schedule cron.Schedule, includeStartingDeadlineSeconds bool) (time.Time, *time.Time, int64, error) {
	// 获取 CronJob 的创建时间
	earliestTime := cj.ObjectMeta.CreationTimestamp.Time
	// 如果 CronJob 的最近执行时间不为空，则以其作为最早时间
	if cj.Status.LastScheduleTime != nil {
		earliestTime = cj.Status.LastScheduleTime.Time
	}
	// 如果 includeStartingDeadlineSeconds 为 true，且 CronJob 的 startingDeadlineSeconds 不为空，则计算其 deadline
	if includeStartingDeadlineSeconds && cj.Spec.StartingDeadlineSeconds != nil {
		// controller is not going to schedule anything below this point
		// 计算 schedulingDeadline，即截止时间
		schedulingDeadline := now.Add(-time.Second * time.Duration(*cj.Spec.StartingDeadlineSeconds))
		// 如果 schedulingDeadline 比 earliestTime 更晚，则更新 earliestTime
		if schedulingDeadline.After(earliestTime) {
			earliestTime = schedulingDeadline
		}
	}

	// 计算下一次执行的时间
	t1 := schedule.Next(earliestTime)
	// 计算再下一次执行的时间
	t2 := schedule.Next(t1)

	// 如果当前时间在 t1 之前，则返回最早时间
	if now.Before(t1) {
		return earliestTime, nil, 0, nil
	}
	// 如果当前时间在 t2 之前，则返回最早时间和 t1
	if now.Before(t2) {
		return earliestTime, &t1, 1, nil
	}

	// 计算两次执行的时间差，单位为秒
	timeBetweenTwoSchedules := int64(t2.Sub(t1).Round(time.Second).Seconds())
	// 如果时间差小于 1 秒，则返回最早时间和错误信息
	if timeBetweenTwoSchedules < 1 {
		return earliestTime, nil, 0, fmt.Errorf("time difference between two schedules is less than 1 second")
	}
	// 计算当前时间与 t1 的时间差，单位为秒
	timeElapsed := int64(now.Sub(t1).Seconds())
	// 计算当前已经错过了多少次执行
	numberOfMissedSchedules := (timeElapsed / timeBetweenTwoSchedules) + 1
	// 计算最近的执行时间
	mostRecentTime := time.Unix(t1.Unix()+((numberOfMissedSchedules-1)*timeBetweenTwoSchedules), 0).UTC()

	return earliestTime, &mostRecentTime, numberOfMissedSchedules, nil
}
```

##### enqueueControllerAfter

```go
func (jm *ControllerV2) enqueueControllerAfter(obj interface{}, t time.Duration) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}

	jm.queue.AddAfter(key, t)
}
```

## cjControlInterface

```GO
type cjControlInterface interface {
	UpdateStatus(ctx context.Context, cj *batchv1.CronJob) (*batchv1.CronJob, error)
	// GetCronJob retrieves a CronJob.
	GetCronJob(ctx context.Context, namespace, name string) (*batchv1.CronJob, error)
}

```

```GO
type realCJControl struct {
	KubeClient clientset.Interface
}

func (c *realCJControl) GetCronJob(ctx context.Context, namespace, name string) (*batchv1.CronJob, error) {
	return c.KubeClient.BatchV1().CronJobs(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *realCJControl) UpdateStatus(ctx context.Context, cj *batchv1.CronJob) (*batchv1.CronJob, error) {
	return c.KubeClient.BatchV1().CronJobs(cj.Namespace).UpdateStatus(ctx, cj, metav1.UpdateOptions{})
}
```

## jobControlInterface

```GO
type jobControlInterface interface {
	// GetJob
	GetJob(namespace, name string) (*batchv1.Job, error)
	// 创建job
	CreateJob(namespace string, job *batchv1.Job) (*batchv1.Job, error)
	// 更新job
	UpdateJob(namespace string, job *batchv1.Job) (*batchv1.Job, error)
	// 部分更新Job
	PatchJob(namespace string, name string, pt types.PatchType, data []byte, subresources ...string) (*batchv1.Job, error)
	// 删除job
	DeleteJob(namespace string, name string) error
}
```

```GO
type realJobControl struct {
	KubeClient clientset.Interface
	Recorder   record.EventRecorder
}

func (r realJobControl) GetJob(namespace, name string) (*batchv1.Job, error) {
	return r.KubeClient.BatchV1().Jobs(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (r realJobControl) UpdateJob(namespace string, job *batchv1.Job) (*batchv1.Job, error) {
	return r.KubeClient.BatchV1().Jobs(namespace).Update(context.TODO(), job, metav1.UpdateOptions{})
}

func (r realJobControl) PatchJob(namespace string, name string, pt types.PatchType, data []byte, subresources ...string) (*batchv1.Job, error) {
	return r.KubeClient.BatchV1().Jobs(namespace).Patch(context.TODO(), name, pt, data, metav1.PatchOptions{}, subresources...)
}

func (r realJobControl) CreateJob(namespace string, job *batchv1.Job) (*batchv1.Job, error) {
	return r.KubeClient.BatchV1().Jobs(namespace).Create(context.TODO(), job, metav1.CreateOptions{})
}

func (r realJobControl) DeleteJob(namespace string, name string) error {
	background := metav1.DeletePropagationBackground
	return r.KubeClient.BatchV1().Jobs(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{PropagationPolicy: &background})
}
```

## Run

```go
func (jm *ControllerV2) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	// Start event processing pipeline.
	jm.broadcaster.StartStructuredLogging(0)
	jm.broadcaster.StartRecordingToSink(&covev1client.EventSinkImpl{Interface: jm.kubeClient.CoreV1().Events("")})
	defer jm.broadcaster.Shutdown()

	defer jm.queue.ShutDown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting cronjob controller v2")
	defer logger.Info("Shutting down cronjob controller v2")

	if !cache.WaitForNamedCacheSync("cronjob", ctx.Done(), jm.jobListerSynced, jm.cronJobListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, jm.worker, time.Second)
	}

	<-ctx.Done()
}
```

## worker

```go
func (jm *ControllerV2) processNextWorkItem(ctx context.Context) bool {
	key, quit := jm.queue.Get()
	if quit {
		return false
	}
	defer jm.queue.Done(key)

	requeueAfter, err := jm.sync(ctx, key.(string))
	switch {
	case err != nil:
		utilruntime.HandleError(fmt.Errorf("error syncing CronJobController %v, requeuing: %v", key.(string), err))
        // 加入重试队列
		jm.queue.AddRateLimited(key)
	case requeueAfter != nil:
        // 完成key
		jm.queue.Forget(key)
        // requeueAfter时间后再加入队列
		jm.queue.AddAfter(key, *requeueAfter时间后再加入队列)
	}
	return true
}
```

## sync

```go
func (jm *ControllerV2) sync(ctx context.Context, cronJobKey string) (*time.Duration, error) {
	ns, name, err := cache.SplitMetaNamespaceKey(cronJobKey)
	if err != nil {
		return nil, err
	}
	logger := klog.FromContext(ctx)
    // 获取 CronJob 对象
	cronJob, err := jm.cronJobLister.CronJobs(ns).Get(name)
	switch {
	case errors.IsNotFound(err):
		// 如果 CronJob 不存在，则不需要重新入队
		logger.V(4).Info("CronJob not found, may be it is deleted", "cronjob", klog.KObj(cronJob), "err", err)
		return nil, nil
	case err != nil:
		// 对于其他短暂的 API 服务器错误，使用指数回退重新入队
		return nil, err
	}
	// 获取需要处理的 Job
	jobsToBeReconciled, err := jm.getJobsToBeReconciled(cronJob)
	if err != nil {
		return nil, err
	}
	
    // 同步 CronJob 对象，并返回更新后的 CronJob，需要重新排队的时间，是否需要更新状态，以及任何错误
	cronJobCopy, requeueAfter, updateStatus, err := jm.syncCronJob(ctx, cronJob, jobsToBeReconciled)
	if err != nil {
		logger.V(2).Info("Error reconciling cronjob", "cronjob", klog.KObj(cronJob), "err", err)
		if updateStatus {
            // 如果需要更新 CronJob 的状态，但更新失败，则返回错误
			if _, err := jm.cronJobControl.UpdateStatus(ctx, cronJobCopy); err != nil {
				logger.V(2).Info("Unable to update status for cronjob", "cronjob", klog.KObj(cronJob), "resourceVersion", cronJob.ResourceVersion, "err", err)
				return nil, err
			}
		}
		return nil, err
	}
	
    // 清理已完成的 Job
	if jm.cleanupFinishedJobs(ctx, cronJobCopy, jobsToBeReconciled) {
		updateStatus = true
	}

	// 如果需要更新 CronJob 的状态，则更新
	if updateStatus {
		if _, err := jm.cronJobControl.UpdateStatus(ctx, cronJobCopy); err != nil {
			logger.V(2).Info("Unable to update status for cronjob", "cronjob", klog.KObj(cronJob), "resourceVersion", cronJob.ResourceVersion, "err", err)
			return nil, err
		}
	}
	// 如果需要重新排队，则返回需要重新排队的时间
	if requeueAfter != nil {
		logger.V(4).Info("Re-queuing cronjob", "cronjob", klog.KObj(cronJob), "requeueAfter", requeueAfter)
		return requeueAfter, nil
	}
	// 这标志着密钥完成，目前只有当cronjob被挂起或spec具有无效的计划格式时才会发生
	return nil, nil
}
```

### getJobsToBeReconciled

```GO
func (jm *ControllerV2) getJobsToBeReconciled(cronJob *batchv1.CronJob) ([]*batchv1.Job, error) {
	// 获取所有job
	jobList, err := jm.jobLister.Jobs(cronJob.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	jobsToBeReconciled := []*batchv1.Job{}

	for _, job := range jobList {
		// 如果该对象有一个 ControllerRef 属性并且该属性的 Name 属性值等于当前 CronJob 的 Name 属性值，则将该 Job 对象添加到 jobsToBeReconciled 切片中
		if controllerRef := metav1.GetControllerOf(job); controllerRef != nil && controllerRef.Name == cronJob.Name {
			// this job is needs to be reconciled
			jobsToBeReconciled = append(jobsToBeReconciled, job)
		}
	}
	return jobsToBeReconciled, nil
}
```

### syncCronJob

```GO
func (jm *ControllerV2) syncCronJob(
	ctx context.Context,
	cronJob *batchv1.CronJob,
	jobs []*batchv1.Job) (*batchv1.CronJob, *time.Duration, bool, error) {

	cronJob = cronJob.DeepCopy()
	now := jm.now()
    // 是否需要更新 CronJob
	updateStatus := false
	// 创建一个 UID-bool 类型的 map
	childrenJobs := make(map[types.UID]bool)
	for _, j := range jobs {
         // 将 UID 存入 childrenJobs
		childrenJobs[j.ObjectMeta.UID] = true
         // 检查 Job 是否在 ActiveList 中
		found := inActiveList(cronJob, j.ObjectMeta.UID)
		if !found && !IsJobFinished(j) {
            // 如果 Job 没有在 ActiveList 中并且没有结束
			cjCopy, err := jm.cronJobControl.GetCronJob(ctx, cronJob.Namespace, cronJob.Name)
			if err != nil {
				return nil, nil, updateStatus, err
			}
			if inActiveList(cjCopy, j.ObjectMeta.UID) {
                // 如果新的 CronJob 中包含该 Job 更新 CronJob
				cronJob = cjCopy
				continue
			}
			jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "UnexpectedJob", "Saw a job that the controller did not create or forgot: %s", j.Name)
			// 如果找到了一个未完成的 Job，但是它没有在我们的 ActiveList 中
			// 这可能是在创建 Job 后崩溃，或者在更新状态之前，我们的 JobsList 比我们的 CJ 状态更新，或者有人有意创建了一个要我们采纳的 Job。
		} else if found && IsJobFinished(j) {
            // 如果 Job 在 ActiveList 中，并且已经结束了 
            // 获取 Job 完成的状态
			_, status := getFinishedStatus(j)
            // 从 ActiveList 中删除 Job
			deleteFromActiveList(cronJob, j.ObjectMeta.UID)
			jm.recorder.Eventf(cronJob, corev1.EventTypeNormal, "SawCompletedJob", "Saw completed job: %s, status: %v", j.Name, status)
			updateStatus = true
		} else if IsJobFinished(j) {
			// 如果 Job 已经结束了
			if cronJob.Status.LastSuccessfulTime == nil {
                 // 如果 LastSuccessfulTime 为空，则设置其为 Job 的完成时间
				cronJob.Status.LastSuccessfulTime = j.Status.CompletionTime
				updateStatus = true
			}
			if j.Status.CompletionTime != nil && j.Status.CompletionTime.After(cronJob.Status.LastSuccessfulTime.Time) {
                // 如果 Job 的完成时间晚于 LastSuccessfulTime，则将 LastSuccessfulTime 更新为 Job 的完成时间
				cronJob.Status.LastSuccessfulTime = j.Status.CompletionTime
				updateStatus = true
			}
		}
	}

	for _, j := range cronJob.Status.Active {
        // 如果在 active 列表中的 Job 不存在，则将其从 active 列表中删除，并更新 CronJob 的状态
		_, found := childrenJobs[j.UID]
		if found {
			continue
		}
		// 如果在 active 列表中的 Job 不存在，则将其从 active 列表中删除
        // 删除 Job 的原因可能是因为 Job 超时，或者 Job 已经被删除
        // 在这种情况下，需要更新 CronJob 的状态
		_, err := jm.jobControl.GetJob(j.Namespace, j.Name)
		switch {
		case errors.IsNotFound(err):
			jm.recorder.Eventf(cronJob, corev1.EventTypeNormal, "MissingJob", "Active job went missing: %v", j.Name)
			deleteFromActiveList(cronJob, j.UID)
			updateStatus = true
		case err != nil:
			return cronJob, nil, updateStatus, err
		}
		// the job is missing in the lister but found in api-server
	}

	if cronJob.DeletionTimestamp != nil {
		 // 如果 CronJob 正在被删除，则只更新状态
		return cronJob, nil, updateStatus, nil
	}

	logger := klog.FromContext(ctx)
	if cronJob.Spec.TimeZone != nil {
		timeZone := pointer.StringDeref(cronJob.Spec.TimeZone, "")
		if _, err := time.LoadLocation(timeZone); err != nil {
            // 如果 CronJob 中的时区参数不合法，则记录日志并返回
			logger.V(4).Info("Not starting job because timeZone is invalid", "cronjob", klog.KObj(cronJob), "timeZone", timeZone, "err", err)
			jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "UnknownTimeZone", "invalid timeZone: %q: %s", timeZone, err)
			return cronJob, nil, updateStatus, nil
		}
	}

	if cronJob.Spec.Suspend != nil && *cronJob.Spec.Suspend {
        // 如果被暂停了 直接返回
		logger.V(4).Info("Not starting job because the cron is suspended", "cronjob", klog.KObj(cronJob))
		return cronJob, nil, updateStatus, nil
	}
	
    // 解析出 CronJob 的定时器表达式
	sched, err := cron.ParseStandard(formatSchedule(cronJob, jm.recorder))
	if err != nil {
		// 失败了返回
		logger.V(2).Info("Unparseable schedule", "cronjob", klog.KObj(cronJob), "schedule", cronJob.Spec.Schedule, "err", err)
		jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "UnparseableSchedule", "unparseable schedule: %q : %s", cronJob.Spec.Schedule, err)
		return cronJob, nil, updateStatus, nil
	}
	
    // 计算下一次调度时间的核心函数
	scheduledTime, err := nextScheduleTime(logger, cronJob, now, sched, jm.recorder)
	if err != nil {
		// 如果计算下一次调度时间出错，则认为是用户输入有误 则返回原来的 CronJob 对象，不执行 Job
		logger.V(2).Info("Invalid schedule", "cronjob", klog.KObj(cronJob), "schedule", cronJob.Spec.Schedule, "err", err)
		jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "InvalidSchedule", "invalid schedule: %s : %s", cronJob.Spec.Schedule, err)
		return cronJob, nil, updateStatus, nil
	}
	if scheduledTime == nil {
		// 如果没有未满足的开始时间，则返回 CronJob，。
        // 这种情况应该只在重新启动后队列被填满时发生。
        // 否则，队列总是应该在预定时间触发同步函数，这将提供至少一个未满足的时间表
		logger.V(4).Info("No unmet start times", "cronjob", klog.KObj(cronJob))
		t := nextScheduleTimeDuration(cronJob, now, sched)
		return cronJob, t, updateStatus, nil
	}

	tooLate := false
	if cronJob.Spec.StartingDeadlineSeconds != nil {
        // 当前时间是否已经超过了任务开始的最后期限
		tooLate = scheduledTime.Add(time.Second * time.Duration(*cronJob.Spec.StartingDeadlineSeconds)).Before(now)
	}
	if tooLate {
        // 若任务开始的最后期限已经过期，则标记为错过启动
		logger.V(4).Info("Missed starting window", "cronjob", klog.KObj(cronJob))
		jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "MissSchedule", "Missed scheduled time to start a job: %s", scheduledTime.UTC().Format(time.RFC1123Z))
		// 计算下一次应该启动 Job 的时间，并返回
		t := nextScheduleTimeDuration(cronJob, now, sched)
		return cronJob, t, updateStatus, nil
	}
	if inActiveListByName(cronJob, &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getJobName(cronJob, *scheduledTime),
			Namespace: cronJob.Namespace,
		}}) || cronJob.Status.LastScheduleTime.Equal(&metav1.Time{Time: *scheduledTime}) {
        // 如果在活动 Job 列表中存在与当前 Job 同名的 Job 或者 CronJob 的最后一次启动时间等于当前时间，则说明已经处理过这个 Job，因此跳过这次启动。记录日志、计算下一次启动时间并返回。
		logger.V(4).Info("Not starting job because the scheduled time is already processed", "cronjob", klog.KObj(cronJob), "schedule", scheduledTime)
		t := nextScheduleTimeDuration(cronJob, now, sched)
		return cronJob, t, updateStatus, nil
	}
    // 检查并且禁止并发执行
	if cronJob.Spec.ConcurrencyPolicy == batchv1.ForbidConcurrent && len(cronJob.Status.Active) > 0 {
		// 无论我们使用哪种信息源来获取活动作业的集合，
        // 都存在某种风险，即我们在存在活动作业时可能无法看到它们
        // （因为我们还没有看到SJ的状态更新或创建的Pod）。
        // 因此在Forbid策略下并发是理论上可能的。
        // 只要调用“在时间上相隔足够远”，通常就不会发生。
        //
        // TODO：对于Forbid，我们可以使用相同的名称来表示每次执行作为锁。
        // 对于Replace，我们可以使用每次执行时间的确定性名称。
        // 但是这意味着您无法检查Forbid作业的以前成功或失败。
		logger.V(4).Info("Not starting job because prior execution is still running and concurrency policy is Forbid", "cronjob", klog.KObj(cronJob))
		jm.recorder.Eventf(cronJob, corev1.EventTypeNormal, "JobAlreadyActive", "Not starting job because prior execution is running and concurrency policy is Forbid")
		t := nextScheduleTimeDuration(cronJob, now, sched)
		return cronJob, t, updateStatus, nil
	}
    // 如果ConcurrencyPolicy是ReplaceConcurrent，那么将所有正在运行的作业都删除
	if cronJob.Spec.ConcurrencyPolicy == batchv1.ReplaceConcurrent {
		for _, j := range cronJob.Status.Active {
			logger.V(4).Info("Deleting job that was still running at next scheduled start time", "job", klog.KRef(j.Namespace, j.Name))
			job, err := jm.jobControl.GetJob(j.Namespace, j.Name)
			if err != nil {
				jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "FailedGet", "Get job: %v", err)
				return cronJob, nil, updateStatus, err
			}
			if !deleteJob(logger, cronJob, job, jm.jobControl, jm.recorder) {
				return cronJob, nil, updateStatus, fmt.Errorf("could not replace job %s/%s", job.Namespace, job.Name)
			}
			updateStatus = true
		}
	}
	
    // 从模板中获取一个新的作业
	jobReq, err := getJobFromTemplate2(cronJob, *scheduledTime)
	if err != nil {
		logger.Error(err, "Unable to make Job from template", "cronjob", klog.KObj(cronJob))
		return cronJob, nil, updateStatus, err
	}
    // 创建作业
	jobResp, err := jm.jobControl.CreateJob(cronJob.Namespace, jobReq)
	switch {
	case errors.HasStatusCause(err, corev1.NamespaceTerminatingCause):
        // 如果命名空间正在终止中，则跳过
	case errors.IsAlreadyExists(err):
		// 如果该作业已由其他Actor创建，则假定它已相应地更新了cronjob状态
		logger.Info("Job already exists", "cronjob", klog.KObj(cronJob), "job", klog.KObj(jobReq))
		return cronJob, nil, updateStatus, err
	case err != nil:
		// 其他错误直接返回
		jm.recorder.Eventf(cronJob, corev1.EventTypeWarning, "FailedCreate", "Error creating job: %v", err)
		return cronJob, nil, updateStatus, err
	}

	// 记录了 CronJob 创建时间与其计划的下一次执行时间之间的时间差
    metrics.CronJobCreationSkew.Observe(jobResp.ObjectMeta.GetCreationTimestamp().Sub(*scheduledTime).Seconds())
	logger.V(4).Info("Created Job", "job", klog.KObj(jobResp), "cronjob", klog.KObj(cronJob))
	jm.recorder.Eventf(cronJob, corev1.EventTypeNormal, "SuccessfulCreate", "Created job %v", jobResp.Name)

	// ------------------------------------------------------------------ //

	// 如果控制器在更新状态前重新启动，则可能尝试在下一次计划时间上启动任务。
    // 实际上，如果我们在 syncAll 的下一次迭代中重新列出 SJs 和 Jobs，则可能看不到我们自己的状态更新，然后再次发布。
    // 因此，我们需要使用作业名称作为锁，以防止我们使作业两次（使用其计划时间的哈希值命名作业）。

    // 将刚刚启动的作业添加到状态列表中。
	jobRef, err := getRef(jobResp)
	if err != nil {
		logger.V(2).Info("Unable to make object reference", "cronjob", klog.KObj(cronJob), "err", err)
		return cronJob, nil, updateStatus, fmt.Errorf("unable to make object reference for job for %s", klog.KObj(cronJob))
	}
	cronJob.Status.Active = append(cronJob.Status.Active, *jobRef)
	cronJob.Status.LastScheduleTime = &metav1.Time{Time: *scheduledTime}
	updateStatus = true
	// 计算下次执行时间
	t := nextScheduleTimeDuration(cronJob, now, sched)
	return cronJob, t, updateStatus, nil
}
```

#### inActiveList

```GO
func inActiveList(cj *batchv1.CronJob, uid types.UID) bool {
	for _, j := range cj.Status.Active {
		if j.UID == uid {
			return true
		}
	}
	return false
}
```

#### IsJobFinished

```GO
func IsJobFinished(j *batchv1.Job) bool {
	isFinished, _ := getFinishedStatus(j)
	return isFinished
}
```

#### getFinishedStatus

```GO
func getFinishedStatus(j *batchv1.Job) (bool, batchv1.JobConditionType) {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue {
			return true, c.Type
		}
	}
	return false, ""
}
```

#### deleteFromActiveList

```GO
func deleteFromActiveList(cj *batchv1.CronJob, uid types.UID) {
	if cj == nil {
		return
	}
	// TODO: @alpatel the memory footprint can may be reduced here by
	//  cj.Status.Active = append(cj.Status.Active[:indexToRemove], cj.Status.Active[indexToRemove:]...)
	newActive := []corev1.ObjectReference{}
	for _, j := range cj.Status.Active {
		if j.UID != uid {
			newActive = append(newActive, j)
		}
	}
	cj.Status.Active = newActive
}
```

#### formatSchedule

```GO
func formatSchedule(cj *batchv1.CronJob, recorder record.EventRecorder) string {
	if strings.Contains(cj.Spec.Schedule, "TZ") {
        // 如果 Schedule 字段中包含字符串 "TZ"
		if recorder != nil {
			recorder.Eventf(cj, corev1.EventTypeWarning, "UnsupportedSchedule", "CRON_TZ or TZ used in schedule %q is not officially supported, see https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/ for more details", cj.Spec.Schedule)
		}

		return cj.Spec.Schedule
	}

	if cj.Spec.TimeZone != nil {
        // 如果TimeZone 字段不为 nil
		if _, err := time.LoadLocation(*cj.Spec.TimeZone); err != nil {
            // 如果该函数返回的错误不为 nil，则返回原始的 Schedule 字段值
			return cj.Spec.Schedule
		}
		return fmt.Sprintf("TZ=%s %s", *cj.Spec.TimeZone, cj.Spec.Schedule)
	}

	return cj.Spec.Schedule
}
```

#### nextScheduleTime

```GO
func nextScheduleTime(logger klog.Logger, cj *batchv1.CronJob, now time.Time, schedule cron.Schedule, recorder record.EventRecorder) (*time.Time, error) {
	// 调用 mostRecentScheduleTime 函数，获取最近的调度时间、最近的调度时间、错过的调度次数和错误信息
	_, mostRecentTime, numberOfMissedSchedules, err := mostRecentScheduleTime(cj, now, schedule, true)

	// 如果最近的调度时间为 nil，或最近的调度时间在当前时间之后，则直接返回错误信息
	if mostRecentTime == nil || mostRecentTime.After(now) {
		return nil, err
	}

	// 如果错过的调度次数大于 100，则认为调度存在问题，触发告警事件并打印日志
	if numberOfMissedSchedules > 100 {
		// 一个对象可能会错过多个开始时间。例如，如果控制器在周五下午 5:01 卡住了，当所有人都离开后，星期二上午有人发现了问题并重新启动控制器，那么所有的小时级作业，
        // 一个小时级的 CronJob 就会有超过 80 个作业，都应该在没有进一步干预的情况下开始运行（如果 CronJob 允许并发和延迟启动）。
		//
		// 但是，如果出现错误，或者控制器服务器或 apiserver（用于设置 creationTimestamp）的时钟不正确，则可能错过很多的开始时间（可能会差几十年或更多），这将耗尽此控制器的所有 CPU 和内存。在这种情况下，我们不希望尝试列出所有错过的开始时间。
		//
		// 我已经相对任意地选择了 100，作为比 80 大但小于“很多”的数字。
		recorder.Eventf(cj, corev1.EventTypeWarning, "TooManyMissedTimes", "too many missed start times: %d. Set or decrease .spec.startingDeadlineSeconds or check clock skew", numberOfMissedSchedules)
		logger.Info("too many missed times", "cronjob", klog.KObj(cj), "missedTimes", numberOfMissedSchedules)
	}

	// 返回最近的调度时间和错误信息
	return mostRecentTime, err
}

```

##### mostRecentScheduleTime

```GO
// 用于计算最近的调度时间和调度周期之间的所有被错过的调度次数
func mostRecentScheduleTime(cj *batchv1.CronJob, now time.Time, schedule cron.Schedule, includeStartingDeadlineSeconds bool) (time.Time, *time.Time, int64, error) {
    // 获取CronJob的创建时间作为最早时间，若存在最后一次调度时间则更新最早时间
	earliestTime := cj.ObjectMeta.CreationTimestamp.Time
	if cj.Status.LastScheduleTime != nil {
		earliestTime = cj.Status.LastScheduleTime.Time
	}
    // 若includeStartingDeadlineSeconds为true且CronJob有设置StartingDeadlineSeconds，则将最早时间更新为当前时间减去StartingDeadlineSeconds
	if includeStartingDeadlineSeconds && cj.Spec.StartingDeadlineSeconds != nil {
		// controller is not going to schedule anything below this point
		schedulingDeadline := now.Add(-time.Second * time.Duration(*cj.Spec.StartingDeadlineSeconds))

		if schedulingDeadline.After(earliestTime) {
			earliestTime = schedulingDeadline
		}
	}
	// 计算最近的两个调度时间t1和t2
	t1 := schedule.Next(earliestTime)
	t2 := schedule.Next(t1)
	
    // 如果当前时间早于t1，则说明最近的调度时间仍是earliestTime，没有被错过的调度
	if now.Before(t1) {
		return earliestTime, nil, 0, nil
	}
    // 如果当前时间早于t2，则说明只错过了一次调度，返回earliestTime、t1和1
	if now.Before(t2) {
		return earliestTime, &t1, 1, nil
	}

	// 计算两个调度时间的时间差，若时间差小于1秒，则返回错误信息
	timeBetweenTwoSchedules := int64(t2.Sub(t1).Round(time.Second).Seconds())
	if timeBetweenTwoSchedules < 1 {
		return earliestTime, nil, 0, fmt.Errorf("time difference between two schedules is less than 1 second")
	}
    // 计算从t1到当前时间之间错过的调度次数
	timeElapsed := int64(now.Sub(t1).Seconds())
	numberOfMissedSchedules := (timeElapsed / timeBetweenTwoSchedules) + 1
    // 计算最近的调度时间
	mostRecentTime := time.Unix(t1.Unix()+((numberOfMissedSchedules-1)*timeBetweenTwoSchedules), 0).UTC()

	return earliestTime, &mostRecentTime, numberOfMissedSchedules, nil
}
```

#### inActiveListByName

```GO
func inActiveListByName(cj *batchv1.CronJob, job *batchv1.Job) bool {
	for _, j := range cj.Status.Active {
		if j.Name == job.Name && j.Namespace == job.Namespace {
			return true
		}
	}
	return false
}
```

#### getJobName

```GO
func getJobName(cj *batchv1.CronJob, scheduledTime time.Time) string {
	return fmt.Sprintf("%s-%d", cj.Name, getTimeHashInMinutes(scheduledTime))
}

func getTimeHashInMinutes(scheduledTime time.Time) int64 {
	return scheduledTime.Unix() / 60
}
```

#### deleteJob

```GO
func deleteJob(logger klog.Logger, cj *batchv1.CronJob, job *batchv1.Job, jc jobControlInterface, recorder record.EventRecorder) bool {
	// delete the job itself...
	if err := jc.DeleteJob(job.Namespace, job.Name); err != nil {
         // 如果删除 Job 失败，则记录一个警告事件，并返回 false
		recorder.Eventf(cj, corev1.EventTypeWarning, "FailedDelete", "Deleted job: %v", err)
		logger.Error(err, "Error deleting job from cronjob", "job", klog.KObj(job), "cronjob", klog.KObj(cj))
		return false
	}
	// 从 activeJobs 列表中删除 Job 的 UID
	deleteFromActiveList(cj, job.ObjectMeta.UID)
	recorder.Eventf(cj, corev1.EventTypeNormal, "SuccessfulDelete", "Deleted job %v", job.Name)
}
```

#### getJobFromTemplate2

```GO
func getJobFromTemplate2(cj *batchv1.CronJob, scheduledTime time.Time) (*batchv1.Job, error) {
	labels := copyLabels(&cj.Spec.JobTemplate)
	annotations := copyAnnotations(&cj.Spec.JobTemplate)
	name := getJobName(cj, scheduledTime)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Labels:            labels,
			Annotations:       annotations,
			Name:              name,
			CreationTimestamp: metav1.Time{Time: scheduledTime},
			OwnerReferences:   []metav1.OwnerReference{*metav1.NewControllerRef(cj, controllerKind)},
		},
	}
	cj.Spec.JobTemplate.Spec.DeepCopyInto(&job.Spec)
	return job, nil
}

func copyLabels(template *batchv1.JobTemplateSpec) labels.Set {
	l := make(labels.Set)
	for k, v := range template.Labels {
		l[k] = v
	}
	return l
}

func copyAnnotations(template *batchv1.JobTemplateSpec) labels.Set {
	a := make(labels.Set)
	for k, v := range template.Annotations {
		a[k] = v
	}
	return a
}
```

#### getRef

```GO
func getRef(object runtime.Object) (*corev1.ObjectReference, error) {
	return ref.GetReference(scheme.Scheme, object)
}
```

### cleanupFinishedJobs

```GO
func (jm *ControllerV2) cleanupFinishedJobs(ctx context.Context, cj *batchv1.CronJob, js []*batchv1.Job) bool {
	// 如果 CronJob 对象中的 FailedJobsHistoryLimit 和 SuccessfulJobsHistoryLimit 均未设置，则无需执行任何操作，直接返回 false。
	if cj.Spec.FailedJobsHistoryLimit == nil && cj.Spec.SuccessfulJobsHistoryLimit == nil {
		return false
	}

	// 定义 updateStatus 变量，表示是否需要更新 CronJob 的状态。
	updateStatus := false
	// 定义 failedJobs 和 successfulJobs 切片，分别用于存储失败的和成功的 Job 对象。
	failedJobs := []*batchv1.Job{}
	successfulJobs := []*batchv1.Job{}

	// 遍历输入的 js 切片，对于每个 Job 对象，调用 getFinishedStatus 方法获取其完成状态和状态码。
	for _, job := range js {
		isFinished, finishedStatus := jm.getFinishedStatus(job)
		// 如果当前 Job 对象已经完成，且完成状态为 JobComplete，则将其添加到 successfulJobs 切片中。
		if isFinished && finishedStatus == batchv1.JobComplete {
			successfulJobs = append(successfulJobs, job)
		// 如果当前 Job 对象已经完成，且完成状态为 JobFailed，则将其添加到 failedJobs 切片中。
		} else if isFinished && finishedStatus == batchv1.JobFailed {
			failedJobs = append(failedJobs, job)
		}
	}

	// 如果 CronJob 对象中的 SuccessfulJobsHistoryLimit 不为 nil，则调用 removeOldestJobs 方法，删除 successfulJobs 切片中最老的 Job 对象，直到 successfulJobs 切片的长度不超过 SuccessfulJobsHistoryLimit 所指定的值。如果成功删除了至少一个 Job 对象，则将 updateStatus 置为 true。
	if cj.Spec.SuccessfulJobsHistoryLimit != nil &&
		jm.removeOldestJobs(ctx, cj,
			successfulJobs,
			*cj.Spec.SuccessfulJobsHistoryLimit) {
		updateStatus = true
	}

	// 如果 CronJob 对象中的 FailedJobsHistoryLimit 不为 nil，则调用 removeOldestJobs 方法，删除 failedJobs 切片中最老的 Job 对象，直到 failedJobs 切片的长度不超过 FailedJobsHistoryLimit 所指定的值。如果成功删除了至少一个 Job 对象，则将 updateStatus 置为 true。
	if cj.Spec.FailedJobsHistoryLimit != nil &&
		jm.removeOldestJobs(ctx, cj,
			failedJobs,
			*cj.Spec.FailedJobsHistoryLimit) {
		updateStatus = true
	}

	// 返回 updateStatus 变量的值。
	return updateStatus
}

```

#### getFinishedStatus

```GO
func (jm *ControllerV2) getFinishedStatus(j *batchv1.Job) (bool, batchv1.JobConditionType) {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) && c.Status == corev1.ConditionTrue {
			return true, c.Type
		}
	}
	return false, ""
}
```

#### removeOldestJobs

```GO
// 从指定的Job列表中删除最老的Job，使Job的数量不超过指定的最大数量
func (jm *ControllerV2) removeOldestJobs(ctx context.Context, cj *batchv1.CronJob, js []*batchv1.Job, maxJobs int32) bool {
	updateStatus := false   // 标记是否更新状态
	numToDelete := len(js) - int(maxJobs)   // 计算需要删除的Job数量
	if numToDelete <= 0 {   // 如果需要删除的Job数量不大于0，直接返回不执行删除操作
		return updateStatus
	}
	logger := klog.FromContext(ctx)   // 从上下文中获取日志对象
	logger.V(4).Info("Cleaning up jobs from CronJob list", "deletejobnum", numToDelete, "jobnum", len(js), "cronjob", klog.KObj(cj))   // 输出日志，记录正在清理Job的数量
	sort.Sort(byJobStartTime(js))   // 按Job的开始时间排序
	for i := 0; i < numToDelete; i++ {   // 遍历需要删除的Job
		logger.V(4).Info("Removing job from CronJob list", "job", js[i].Name, "cronjob", klog.KObj(cj))   // 输出日志，记录正在删除的Job的名称
		if deleteJob(logger, cj, js[i], jm.jobControl, jm.recorder) {   // 调用deleteJob函数删除Job，如果删除成功，则更新状态
			updateStatus = true
		}
	}
	return updateStatus   // 返回更新状态的布尔值
}
```

