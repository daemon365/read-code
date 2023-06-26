---
id: 26-kube-controller-code
title: job-controller 代码走读
description: job-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

Kubernetes 中的job-controller是一种用于管理短暂任务（short-lived tasks）的控制器。它确保一个或多个Pod在集群中成功运行，并在任务完成后终止它们。

一个Job由一个或多个Pod组成，每个Pod都在单独的节点上运行。如果一个Pod失败或被删除，Job Controller会根据需要重新启动该Pod，直到Job成功完成或达到重试次数上限。

Job Controller还支持以下类型的任务：

- 串行任务：一个任务完成后，另一个任务才会开始。
- 并行任务：多个任务同时进行，但是可以定义最大并发数以限制同时运行的任务数量。
- CronJob：基于时间调度的任务，可以按照预定的时间间隔运行。

使用Job Controller可以方便地在Kubernetes集群中运行批处理作业、数据处理作业、定时任务等任务，同时也确保了任务的高可用性和可靠性。

## 结构体

```GO
type Controller struct {
	kubeClient clientset.Interface
	podControl controller.PodControlInterface

	// 用于更新 Job 的状态信息
	updateStatusHandler func(ctx context.Context, job *batch.Job) (*batch.Job, error)
    // 为 Job 打补丁
	patchJobHandler     func(ctx context.Context, job *batch.Job, patch []byte) error
    // 同步 Job 和 Pod
	syncHandler         func(ctx context.Context, jobKey string) error
	
    // Pod 的同步状态
	podStoreSynced cache.InformerSynced
	// job 的同步状态
	jobStoreSynced cache.InformerSynced

	//跟踪控制器的期望状态
	expectations controller.ControllerExpectationsInterface

	// 是一个 uidTrackingExpectations 类型的变量，用于跟踪 Job 的 finalizer。
	finalizerExpectations *uidTrackingExpectations

	jobLister batchv1listers.JobLister
	podStore corelisters.PodLister

	// 于存储需要更新的 Job 
	queue workqueue.RateLimitingInterface

	// 存储需要删除 finalizer 的 Job
	orphanQueue workqueue.RateLimitingInterface
	
    // 广播事件和记录事件
	broadcaster record.EventBroadcaster
	recorder    record.EventRecorder
	// Pod 更新的间隔
	podUpdateBatchPeriod time.Duration
	// 事件
	clock clock.WithTicker
	// 存储 backoff 记录
	backoffRecordStore *backoffStore
}
```

## New

```go
func NewController(podInformer coreinformers.PodInformer, jobInformer batchinformers.JobInformer, kubeClient clientset.Interface) *Controller {
	return newControllerWithClock(podInformer, jobInformer, kubeClient, &clock.RealClock{})
}

func newControllerWithClock(podInformer coreinformers.PodInformer, jobInformer batchinformers.JobInformer, kubeClient clientset.Interface, clock clock.WithTicker) *Controller {
	eventBroadcaster := record.NewBroadcaster()

	jm := &Controller{
		kubeClient: kubeClient,
		podControl: controller.RealPodControl{
			KubeClient: kubeClient,
			Recorder:   eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "job-controller"}),
		},
		expectations:          controller.NewControllerExpectations(),
		finalizerExpectations: newUIDTrackingExpectations(),
		queue:                 workqueue.NewRateLimitingQueueWithDelayingInterface(workqueue.NewDelayingQueueWithCustomClock(clock, "job"), workqueue.NewItemExponentialFailureRateLimiter(DefaultJobBackOff, MaxJobBackOff)),
		orphanQueue:           workqueue.NewRateLimitingQueueWithDelayingInterface(workqueue.NewDelayingQueueWithCustomClock(clock, "job_orphan_pod"), workqueue.NewItemExponentialFailureRateLimiter(DefaultJobBackOff, MaxJobBackOff)),
		broadcaster:           eventBroadcaster,
		recorder:              eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "job-controller"}),
		clock:                 clock,
		backoffRecordStore:    newBackoffRecordStore(),
	}
	if feature.DefaultFeatureGate.Enabled(features.JobReadyPods) {
		jm.podUpdateBatchPeriod = podUpdateBatchPeriod
	}
	
    // 处理job
	jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			jm.enqueueController(obj, true)
		},
		UpdateFunc: jm.updateJob,
		DeleteFunc: jm.deleteJob,
	})
	jm.jobLister = jobInformer.Lister()
	jm.jobStoreSynced = jobInformer.Informer().HasSynced
	
    // 处理pod
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    jm.addPod,
		UpdateFunc: jm.updatePod,
		DeleteFunc: func(obj interface{}) {
			jm.deletePod(obj, true)
		},
	})
	jm.podStore = podInformer.Lister()
	jm.podStoreSynced = podInformer.Informer().HasSynced

	jm.updateStatusHandler = jm.updateJobStatus
	jm.patchJobHandler = jm.patchJob
	jm.syncHandler = jm.syncJob

	metrics.Register()

	return jm
}
```

### metrics

```GO
func Register() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(JobSyncDurationSeconds)
		legacyregistry.MustRegister(JobSyncNum)
		legacyregistry.MustRegister(JobFinishedNum)
		legacyregistry.MustRegister(JobPodsFinished)
		legacyregistry.MustRegister(PodFailuresHandledByFailurePolicy)
		legacyregistry.MustRegister(TerminatedPodsTrackingFinalizerTotal)
	})
}
```

### 队列相关

#### Job

```go
func (jm *Controller) enqueueController(obj interface{}, immediate bool) {
	jm.enqueueControllerDelayed(obj, immediate, 0)
}

//  将给定对象推入控制器队列，并根据需要延迟一段时间执行。
func (jm *Controller) enqueueControllerDelayed(obj interface{}, immediate bool, delay time.Duration) {
    // 获得该对象的键值，如果出现错误则记录并返回
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}

    // 设置延迟时间
	backoff := delay
	if !immediate {
        // 如果需要延迟执行，则获取与该对象关联的控制器的推迟时间
		if calculatedBackoff := getBackoff(jm.queue, key); calculatedBackoff > 0 {
			backoff = calculatedBackoff
		}
	}

	// TODO: 处理重叠控制器的问题，可以在准入时禁止它们，或者确定性地避免竞争 Pod 的同步控制器。
	// 当前，我们只确保同一控制器为给定的 Pod 同步。当我们定期重新列出所有控制器时，仍将存在某些副本不稳定性。
	// 处理这个问题的一种方法是查询存储区中与该 RC 重叠的所有控制器，以及所有重叠该 RC 的控制器，并对它们进行排序。
	klog.Infof("enqueueing job %s", key)
	// 将键值和延迟时间添加到控制器队列中
	jm.queue.AddAfter(key, backoff)
}

func (jm *Controller) updateJob(old, cur interface{}) {
	// 将旧作业对象和新作业对象转换为 Job 类型
	oldJob := old.(*batch.Job)
	curJob := cur.(*batch.Job)

	// 使用当前作业对象获取其键值，如果出现错误则返回
	key, err := controller.KeyFunc(curJob)
	if err != nil {
		return
	}
	// 将当前作业对象推入控制器队列中
	jm.enqueueController(curJob, true)

	// 检查是否需要为 ActiveDeadlineSeconds 添加一个新的 rsync
	if curJob.Status.StartTime != nil {
		curADS := curJob.Spec.ActiveDeadlineSeconds
		if curADS == nil {
			return
		}
		oldADS := oldJob.Spec.ActiveDeadlineSeconds
		if oldADS == nil || *oldADS != *curADS {
			// 计算当前作业已经运行的时间和最大运行时间的差值，如果小于零则将其设为 0
			passed := jm.clock.Since(curJob.Status.StartTime.Time)
			total := time.Duration(*curADS) * time.Second
			if total < passed {
				passed = total
			}
			// 将键值和延迟时间添加到控制器队列中，以便在指定的时间后执行
			jm.queue.AddAfter(key, total-passed)
			klog.V(4).Infof("job %q ActiveDeadlineSeconds updated, will rsync after %d seconds", key, total-passed)
		}
	}
}

func (jm *Controller) deleteJob(obj interface{}) {
    // 将obj加入队列中
	jm.enqueueController(obj, true)
    // 取出job对象
	jobObj, ok := obj.(*batch.Job)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %+v", obj))
			return
		}
		jobObj, ok = tombstone.Obj.(*batch.Job)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a job %+v", obj))
			return
		}
	}
	
	selector, err := metav1.LabelSelectorAsSelector(jobObj.Spec.Selector)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("parsing deleted job selector: %v", err))
		return
	}
    // 取出这个对象下的所有pod
	pods, _ := jm.podStore.Pods(jobObj.Namespace).List(selector)
	for _, pod := range pods {
        // 如果owner是这个job 并且pod有JobTracking Finalizer 把job加入job队列处理
		if metav1.IsControlledBy(pod, jobObj) && hasJobTrackingFinalizer(pod) {
			jm.enqueueOrphanPod(pod)
		}
	}
}

```

##### IsControlledBy

```GO
func IsControlledBy(obj Object, owner Object) bool {
	ref := GetControllerOfNoCopy(obj)
	if ref == nil {
		return false
	}
	return ref.UID == owner.GetUID()
}
```

##### hasJobTrackingFinalizer

```GO
func hasJobTrackingFinalizer(pod *v1.Pod) bool {
	for _, fin := range pod.Finalizers {
		if fin == batch.JobTrackingFinalizer {
			return true
		}
	}
	return false
}
```

#### pod

```go
func (jm *Controller) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
    // 调用recordFinishedPodWithTrackingFinalizer函数，传入nil和pod作为参数
	recordFinishedPodWithTrackingFinalizer(nil, pod)
	if pod.DeletionTimestamp != nil {
		// 如果pod.DeletionTimestamp不为空，则表示该Pod已经标记为删除状态
        // 在控制器重启时，可能会出现新的Pod处于已经标记删除状态的状态
        // 为了防止该Pod成为一个创建观察对象，我们需要将其从观察列表中删除
        // 调用deletePod函数，传入pod和false作为参数，表示该Pod不是被删除操作删除的
		jm.deletePod(pod, false)
		return
	}

	// 如果Pod有控制器引用，那么就只关心这个引用
	if controllerRef := metav1.GetControllerOf(pod); controllerRef != nil {
		job := jm.resolveControllerRef(pod.Namespace, controllerRef)
		if job == nil {
			return
		}
		jobKey, err := controller.KeyFunc(job)
		if err != nil {
			return
		}
        // 将job的创建状态更新到expectations中
		jm.expectations.CreationObserved(jobKey)
        // 将job加入到Pod更新队列中
		jm.enqueueControllerPodUpdate(job, true)
		return
	}

	// 此时Pod是个孤儿Pod
    // 清理Pod的finalizer
	if hasJobTrackingFinalizer(pod) {
        // 如果Pod有finalizer
		// 将Pod加入到孤儿Pod队列中
		jm.enqueueOrphanPod(pod)
	}
	// 获取所有匹配的控制器，然后将Pod加入到它们的更新队列中
	// 不需要观察创建操作，因为没有控制器应该等待孤儿Pod的创建
	for _, job := range jm.getPodJobs(pod) {
		jm.enqueueControllerPodUpdate(job, true)
	}
}

func (jm *Controller) updatePod(old, cur interface{}) {
	curPod := cur.(*v1.Pod)
	oldPod := old.(*v1.Pod)
    // 记录旧的Pod并追踪finalizer的变化
	recordFinishedPodWithTrackingFinalizer(oldPod, curPod)
	if curPod.ResourceVersion == oldPod.ResourceVersion {
		// 如果curPod和oldPod的资源版本号相同，则说明此次更新为周期性更新事件，不做处理
		return
	}
	if curPod.DeletionTimestamp != nil {
		// 如果curPod被标记为删除
        // 对于优雅的删除方式，先修改删除时间戳，再等待kubelet进行实际删除。
        // 因此，接收到的更新事件是删除时间戳的修改，这时应该立即删除Pod
		jm.deletePod(curPod, false)
		return
	}

	 // 当Pod失败后第一次进行退避时，设置immediate变量为true，以便让新Pod尽快被创建
	immediate := !(curPod.Status.Phase == v1.PodFailed && oldPod.Status.Phase != v1.PodFailed)

	// 判断Pod是否有finalizer，如果finalizer被移除了，将finalizer的移除事件记录到期望列表中
	finalizerRemoved := !hasJobTrackingFinalizer(curPod)
     // 获取Pod的控制器引用
	curControllerRef := metav1.GetControllerOf(curPod)
	oldControllerRef := metav1.GetControllerOf(oldPod)
    // 判断控制器引用是否发生了变化
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// 如果ControllerRef发生了变化，同步旧的Controller
		if job := jm.resolveControllerRef(oldPod.Namespace, oldControllerRef); job != nil {
             // 如果finalizer被移除，将移除事件记录到期望列表中
			if finalizerRemoved {
				key, err := controller.KeyFunc(job)
				if err == nil {
					jm.finalizerExpectations.finalizerRemovalObserved(key, string(curPod.UID))
				}
			}
            // 将job加入到队列中
			jm.enqueueControllerPodUpdate(job, immediate)
		}
	}

	// 如果Pod有ControllerRef
	if curControllerRef != nil {
		job := jm.resolveControllerRef(curPod.Namespace, curControllerRef)
		if job == nil {
			return
		}
        // 如果finalizer被移除，将移除事件记录到期望列表中
		if finalizerRemoved {
			key, err := controller.KeyFunc(job)
			if err == nil {
				jm.finalizerExpectations.finalizerRemovalObserved(key, string(curPod.UID))
			}
		}
        // 将job加入到队列中
		jm.enqueueControllerPodUpdate(job, immediate)
		return
	}

	// 此时Pod是个孤儿Pod
    // 清理Pod的finalizer
	if hasJobTrackingFinalizer(curPod) {
		jm.enqueueOrphanPod(curPod)
	}
	//如果有任何更改，请同步匹配控制器
	//看看现在是否有人想收养它。
	labelChanged := !reflect.DeepEqual(curPod.Labels, oldPod.Labels)
	if labelChanged || controllerRefChanged {
		for _, job := range jm.getPodJobs(curPod) {
			jm.enqueueControllerPodUpdate(job, immediate)
		}
	}
}

// When a pod is deleted, enqueue the job that manages the pod and update its expectations.
// obj could be an *v1.Pod, or a DeleteFinalStateUnknown marker item.
func (jm *Controller) deletePod(obj interface{}, final bool) {
	pod, ok := obj.(*v1.Pod)
	if final {
        // 如果 final 标志为真，则调用 recordFinishedPodWithTrackingFinalizer 函数记录已完成的 
		recordFinishedPodWithTrackingFinalizer(pod, nil)
	}

	// 当删除被丢弃时，relist 会注意到存储中的一个 pod 不在列表中，从而导致插入一个墓碑对象，其中包含删除的键/值。
    // 请注意，此值可能已过时。如果 pod 更改了标签，则新作业直到定期重新同步后才会被唤醒
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %+v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a pod %+v", obj))
			return
		}
	}
	// 获取 pod 的控制器引用
	controllerRef := metav1.GetControllerOf(pod)
    // 检查 pod 是否具有任务追踪 finalizer
	hasFinalizer := hasJobTrackingFinalizer(pod)
	if controllerRef == nil {
		// 没有控制器应关心被删除的孤儿。但是这个 pod 可能属于一个 Job，而 GC 已经删除了引用。
		if hasFinalizer {
            // 如果 pod 具有任务追踪 finalizer，则将其放入孤儿 pod 的队列中，并返回。
			jm.enqueueOrphanPod(pod)
		}
		return
	}
    // 通过 pod 的命名空间和控制器引用获取 Job
	job := jm.resolveControllerRef(pod.Namespace, controllerRef)
	if job == nil || IsJobFinished(job) {
		// 如果 job 为 nil 或已完成，则将 pod 放入孤儿 pod 的队列中，并返回。
		if hasFinalizer {
			jm.enqueueOrphanPod(pod)
		}
		return
	}
    // 通过 Job 的 KeyFunc 计算 Job 的键，并将其从 expectations 队列中删除。
	jobKey, err := controller.KeyFunc(job)
	if err != nil {
		return
	}
	jm.expectations.DeletionObserved(jobKey)

	// 如果final为真或者没有追踪Job状态的finalizer，则认为finalizer已被移除
	if final || !hasFinalizer {
		jm.finalizerExpectations.finalizerRemovalObserved(jobKey, string(pod.UID))
	}
	
    // 根据Job对象的情况，入队Pod更新事件
	jm.enqueueControllerPodUpdate(job, true)
}
```

##### recordFinishedPodWithTrackingFinalizer

```GO
func recordFinishedPodWithTrackingFinalizer(oldPod, newPod *v1.Pod) {
	was := isFinishedPodWithTrackingFinalizer(oldPod)
	is := isFinishedPodWithTrackingFinalizer(newPod)
	if was == is {
		return
	}
	var event = metrics.Delete
	if is {
		event = metrics.Add
	}
	metrics.TerminatedPodsTrackingFinalizerTotal.WithLabelValues(event).Inc()
}
```

###### isFinishedPodWithTrackingFinalizer

```GO
func isFinishedPodWithTrackingFinalizer(pod *v1.Pod) bool {
	if pod == nil {
		return false
	}
	return (pod.Status.Phase == v1.PodFailed || pod.Status.Phase == v1.PodSucceeded) && hasJobTrackingFinalizer(pod)
}
```

##### resolveControllerRef

```GO
func (jm *Controller) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *batch.Job {
	if controllerRef.Kind != controllerKind.Kind {
		return nil
	}
	job, err := jm.jobLister.Jobs(namespace).Get(controllerRef.Name)
	if err != nil {
		return nil
	}
	if job.UID != controllerRef.UID {
		return nil
	}
	return job
}

```

##### enqueueControllerPodUpdate

```GO
func (jm *Controller) enqueueControllerPodUpdate(obj interface{}, immediate bool) {
	jm.enqueueControllerDelayed(obj, immediate, jm.podUpdateBatchPeriod)
}
```

##### enqueueOrphanPod

```GO
func (jm *Controller) enqueueOrphanPod(obj *v1.Pod) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	jm.orphanQueue.Add(key)
}

```

###### getPodJobs

```GO
func (jm *Controller) getPodJobs(pod *v1.Pod) []*batch.Job {
	jobs, err := jm.jobLister.GetPodJobs(pod)
	if err != nil {
		return nil
	}
	if len(jobs) > 1 {
		utilruntime.HandleError(fmt.Errorf("user error! more than one job is selecting pods with labels: %+v", pod.Labels))
	}
	ret := make([]*batch.Job, 0, len(jobs))
	for i := range jobs {
		ret = append(ret, &jobs[i])
	}
	return ret
}
```

### uidTrackingExpectations

```GO
type uidTrackingExpectations struct {
	store cache.Store
}

func newUIDTrackingExpectations() *uidTrackingExpectations {
	return &uidTrackingExpectations{store: cache.NewStore(uidSetKeyFunc)}
}

func (u *uidTrackingExpectations) getSet(controllerKey string) *uidSet {
	if obj, exists, err := u.store.GetByKey(controllerKey); err == nil && exists {
		return obj.(*uidSet)
	}
	return nil
}

func (u *uidTrackingExpectations) getExpectedUIDs(controllerKey string) sets.String {
	uids := u.getSet(controllerKey)
	if uids == nil {
		return nil
	}
	uids.RLock()
	set := uids.set.Clone()
	uids.RUnlock()
	return set
}

func (u *uidTrackingExpectations) finalizerRemovalObserved(jobKey, deleteKey string) {
	uids := u.getSet(jobKey)
	if uids != nil {
		uids.Lock()
		if uids.set.Has(deleteKey) {
			klog.V(4).InfoS("Observed tracking finalizer removed", "job", jobKey, "podUID", deleteKey)
			uids.set.Delete(deleteKey)
		}
		uids.Unlock()
	}
}

func (u *uidTrackingExpectations) deleteExpectations(jobKey string) {
	set := u.getSet(jobKey)
	if set != nil {
		if err := u.store.Delete(set); err != nil {
			klog.ErrorS(err, "Could not delete tracking annotation UID expectations", "job", jobKey)
		}
	}
}

func (u *uidTrackingExpectations) getSet(controllerKey string) *uidSet {
	if obj, exists, err := u.store.GetByKey(controllerKey); err == nil && exists {
		return obj.(*uidSet)
	}
	return nil
}

func (u *uidTrackingExpectations) getExpectedUIDs(controllerKey string) sets.String {
	uids := u.getSet(controllerKey)
	if uids == nil {
		return nil
	}
	uids.RLock()
	set := uids.set.Clone()
	uids.RUnlock()
	return set
}

func (u *uidTrackingExpectations) expectFinalizersRemoved(jobKey string, deletedKeys []string) error {
	klog.V(4).InfoS("Expecting tracking finalizers removed", "job", jobKey, "podUIDs", deletedKeys)

	uids := u.getSet(jobKey)
	if uids == nil {
		uids = &uidSet{
			key: jobKey,
			set: sets.NewString(),
		}
		if err := u.store.Add(uids); err != nil {
			return err
		}
	}
	uids.Lock()
	uids.set.Insert(deletedKeys...)
	uids.Unlock()
	return nil
}
```

#### uidSet

```GO
type uidSet struct {
	sync.RWMutex
	set sets.String
	key string
}

var uidSetKeyFunc = func(obj interface{}) (string, error) {
	if u, ok := obj.(*uidSet); ok {
		return u.key, nil
	}
	return "", fmt.Errorf("could not find key for obj %#v", obj)
}
```

### backoffStore

```go
type backoffStore struct {
	store cache.Store
}

func newBackoffRecordStore() *backoffStore {
	return &backoffStore{
		store: cache.NewStore(backoffRecordKeyFunc),
	}
}

var backoffRecordKeyFunc = func(obj interface{}) (string, error) {
	if u, ok := obj.(*backoffRecord); ok {
		return u.key, nil
	}
	return "", fmt.Errorf("could not find key for obj %#v", obj)
}

// 更新
func (s *backoffStore) updateBackoffRecord(record backoffRecord) error {
	b, ok, err := s.store.GetByKey(record.key)
	if err != nil {
		return err
	}

	if !ok {
		err = s.store.Add(&record)
		if err != nil {
			return err
		}
	} else {
		backoffRecord := b.(*backoffRecord)
		backoffRecord.failuresAfterLastSuccess = record.failuresAfterLastSuccess
		backoffRecord.lastFailureTime = record.lastFailureTime
	}

	return nil
}

// 删除
func (s *backoffStore) removeBackoffRecord(jobId string) error {
	b, ok, err := s.store.GetByKey(jobId)
	if err != nil {
		return err
	}

	if ok {
		err = s.store.Delete(b)
		if err != nil {
			return err
		}
	}

	return nil

}


func (backoffRecordStore *backoffStore) newBackoffRecord(clock clock.WithTicker, key string, newSucceededPods []*v1.Pod, newFailedPods []*v1.Pod) backoffRecord {
	now := clock.Now()
	var backoff *backoffRecord
	
    // // 从 store 中获取指定 key 对应的记录
	if b, exists, _ := backoffRecordStore.store.GetByKey(key); exists {
		old := b.(*backoffRecord)
        // 若存在，则使用旧记录的值来创建一个新的 backoffRecord
		backoff = &backoffRecord{
			key:                      old.key,
			failuresAfterLastSuccess: old.failuresAfterLastSuccess,
			lastFailureTime:          old.lastFailureTime,
		}
	} else {
        // 若不存在，则创建一个新的 backoffRecord
		backoff = &backoffRecord{
			key:                      key,
			failuresAfterLastSuccess: 0,
			lastFailureTime:          nil,
		}
	}
	
    // 将新成功和新失败的 Pod 根据完成时间排序
	sortByFinishedTime(newSucceededPods, now)
	sortByFinishedTime(newFailedPods, now)
	
    // 若新成功的 Pod 数量为 0，则仅更新 backoffRecord 的失败信息
	if len(newSucceededPods) == 0 {
		if len(newFailedPods) == 0 {
			return *backoff
		}

		backoff.failuresAfterLastSuccess = backoff.failuresAfterLastSuccess + int32(len(newFailedPods))
		lastFailureTime := getFinishedTime(newFailedPods[len(newFailedPods)-1], now)
		backoff.lastFailureTime = &lastFailureTime
		return *backoff

	} else {
        // 若新失败的 Pod 数量为 0，则重置 backoffRecord 的失败信息
		if len(newFailedPods) == 0 {
			backoff.failuresAfterLastSuccess = 0
			backoff.lastFailureTime = nil
			return *backoff
		}
		// 对于有新成功和新失败 Pod 的情况，需要计算新的 backoff 失败信息
		backoff.failuresAfterLastSuccess = 0
		backoff.lastFailureTime = nil

		lastSuccessTime := getFinishedTime(newSucceededPods[len(newSucceededPods)-1], now)
		for i := len(newFailedPods) - 1; i >= 0; i-- {
			failedTime := getFinishedTime(newFailedPods[i], now)
            // 若失败时间早于最近成功时间，则直接跳过
			if !failedTime.After(lastSuccessTime) {
				break
			}
			if backoff.lastFailureTime == nil {
				backoff.lastFailureTime = &failedTime
			}
			backoff.failuresAfterLastSuccess += 1
		}

		return *backoff

	}

}
```

#### backoffRecord

```GO
type backoffRecord struct {
	key                      string
	failuresAfterLastSuccess int32
	lastFailureTime          *time.Time
}

// 计算一个 backoffRecord 对象中记录的重试次数和重试时间间隔，以确定下一次重试的时间
func (backoff backoffRecord) getRemainingTime(clock clock.WithTicker, defaultBackoff time.Duration, maxBackoff time.Duration) time.Duration {
	if backoff.failuresAfterLastSuccess == 0 {
        // 如果上一次成功后没有失败，则返回 0
		return 0
	}

	backoffDuration := defaultBackoff
    // 计算重试时间间隔，使用默认的重试时间间隔 defaultBackoff 作为起始值，每次乘以 2，
    // 直到达到最大的重试时间间隔 maxBackoff 或者达到上一次成功后的失败次数。
	for i := 1; i < int(backoff.failuresAfterLastSuccess); i++ {
		backoffDuration = backoffDuration * 2
		if backoffDuration >= maxBackoff {
			backoffDuration = maxBackoff
			break
		}
	}
	// 计算自上一次失败后的经过的时间
	timeElapsedSinceLastFailure := clock.Since(*backoff.lastFailureTime)
	// 如果重试时间间隔小于自上一次失败后的经过的时间，则返回 0
	if backoffDuration < timeElapsedSinceLastFailure {
		return 0
	}
	
    // 返回剩余的重试时间间隔
	return backoffDuration - timeElapsedSinceLastFailure
}
```

#### sortByFinishedTime

```GO
func sortByFinishedTime(pods []*v1.Pod, currentTime time.Time) {
	sort.Slice(pods, func(i, j int) bool {
		p1 := pods[i]
		p2 := pods[j]
		p1FinishTime := getFinishedTime(p1, currentTime)
		p2FinishTime := getFinishedTime(p2, currentTime)

		return p1FinishTime.Before(p2FinishTime)
	})
}
```

#### getFinishedTime

```GO
func getFinishedTime(p *v1.Pod, currentTime time.Time) time.Time {
	var finishTime *time.Time
    // 遍历该Pod的所有容器状态
	for _, containerState := range p.Status.ContainerStatuses {
		if containerState.State.Terminated == nil {
            // 如果容器没有终止，则将 finishTime 设置为 nil
			finishTime = nil
			break
		}

		if finishTime == nil {
            // 如果 finishTime 为 nil，则将其指向该容器的结束时间
			finishTime = &containerState.State.Terminated.FinishedAt.Time
		} else {
			if finishTime.Before(containerState.State.Terminated.FinishedAt.Time) {
                // 如果该容器的结束时间比 finishTime 更晚，则将 finishTime 指向该容器的结束时间。
				finishTime = &containerState.State.Terminated.FinishedAt.Time
			}
		}
	}

	if finishTime == nil || finishTime.IsZero() {
		return currentTime
	}

	return *finishTime
}
```



## Run

```go
func (jm *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	// Start events processing pipeline.
	jm.broadcaster.StartStructuredLogging(0)
	jm.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: jm.kubeClient.CoreV1().Events("")})
	defer jm.broadcaster.Shutdown()

	defer jm.queue.ShutDown()
	defer jm.orphanQueue.ShutDown()

	klog.Infof("Starting job controller")
	defer klog.Infof("Shutting down job controller")

	if !cache.WaitForNamedCacheSync("job", ctx.Done(), jm.podStoreSynced, jm.jobStoreSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, jm.worker, time.Second)
	}

	go wait.UntilWithContext(ctx, jm.orphanWorker, time.Second)

	<-ctx.Done()
}
```

## worker

```go
func (jm *Controller) worker(ctx context.Context) {
	for jm.processNextWorkItem(ctx) {
	}
}

func (jm *Controller) processNextWorkItem(ctx context.Context) bool {
	key, quit := jm.queue.Get()
	if quit {
		return false
	}
	defer jm.queue.Done(key)

	err := jm.syncHandler(ctx, key.(string))
	if err == nil {
        // 成功就删除掉
		jm.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("syncing job: %w", err))
    // 失败重试
	jm.queue.AddRateLimited(key)

	return true
}
```

### syncHandler

在New时候赋值的

```go
func (jm *Controller) syncJob(ctx context.Context, key string) (rErr error) {
	startTime := jm.clock.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing job %q (%v)", key, jm.clock.Since(startTime))
	}()

	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(ns) == 0 || len(name) == 0 {
		return fmt.Errorf("invalid job key %q: either namespace or name is missing", key)
	}
    // 获取job
	sharedJob, err := jm.jobLister.Jobs(ns).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
            // 如果job不存在，删除expectations和finalizerExpectations并返回nil
			klog.V(4).Infof("Job has been deleted: %v", key)
			jm.expectations.DeleteExpectations(key)
			jm.finalizerExpectations.deleteExpectations(key)

			err := jm.backoffRecordStore.removeBackoffRecord(key)
			if err != nil {
				// re-syncing here as the record has to be removed for finished/deleted jobs
				return fmt.Errorf("error removing backoff record %w", err)
			}
			return nil
		}
		return err
	}
	// make a copy so we don't mutate the shared cache
	job := *sharedJob.DeepCopy()

	// 如果job已经完成了，则删除backoffRecord并返回nil
	if IsJobFinished(&job) {
		err := jm.backoffRecordStore.removeBackoffRecord(key)
		if err != nil {
			// re-syncing here as the record has to be removed for finished/deleted jobs
			return fmt.Errorf("error removing backoff record %w", err)
		}
		return nil
	}
	
	if job.Spec.CompletionMode != nil && *job.Spec.CompletionMode != batch.NonIndexedCompletion && *job.Spec.CompletionMode != batch.IndexedCompletion {
		jm.recorder.Event(&job, v1.EventTypeWarning, "UnknownCompletionMode", "Skipped Job sync because completion mode is unknown")
		return nil
	}
	// 获取completionMode
	completionMode := getCompletionMode(&job)
    // 设置action为reconciling
	action := metrics.JobSyncActionReconciling
	
    // 在函数返回时记录metrics
	defer func() {	
		result := "success"
		if rErr != nil {
			result = "error"
		}

		metrics.JobSyncDurationSeconds.WithLabelValues(completionMode, result, action).Observe(jm.clock.Since(startTime).Seconds())
		metrics.JobSyncNum.WithLabelValues(completionMode, result, action).Inc()
	}()
	
    // 如果job的UncountedTerminatedPods为空，则初始化为一个空的UncountedTerminatedPods对象
	if job.Status.UncountedTerminatedPods == nil {
		job.Status.UncountedTerminatedPods = &batch.UncountedTerminatedPods{}
	}
    // 创建一个新的包含终止 Pod 的计数器，使用 job.Status.UncountedTerminatedPods 的值初始化。
	uncounted := newUncountedTerminatedPods(*job.Status.UncountedTerminatedPods)
    //使用给定的键从 finalizerExpectations 中获取期望的 UID，然后返回 UID 的列表。
	expectedRmFinalizers := jm.finalizerExpectations.getExpectedUIDs(key)

	// 检查作业期望值是否满足，然后再计算活动 Pod 的数量，
	// 否则，新的 Pod 可以在我们从存储库中检索活动 Pod 之后悄悄进入并更新期望值。如果新的 Pod 在我们检查期望值之后进入存储库，则作业同步只被推迟到下一个 relist。
	satisfiedExpectations := jm.expectations.SatisfiedExpectations(key)

	pods, err := jm.getPodsForJob(ctx, &job)
	if err != nil {
		return err
	}

	activePods := controller.FilterActivePods(pods) //过滤 Pod 列表中的非活动 Pod
	active := int32(len(activePods))
    //获取新的已完成的 Pod，即已成功或已失败的 Pod
	newSucceededPods, newFailedPods := getNewFinishedPods(&job, pods, uncounted, expectedRmFinalizers)
    //计算已成功的 Pod 的总数，包括从上一次同步到现在新成功的 Pod 和未计数的终止 Pod 的数量。
	succeeded := job.Status.Succeeded + int32(len(newSucceededPods)) + int32(len(uncounted.succeeded))
    //计算已失败的 Pod 的总数，包括从上一次同步到现在新失败的 Pod 和未计数的终止 Pod 的数量。
	failed := job.Status.Failed + int32(len(newFailedPods)) + int32(len(uncounted.failed))
    //初始化一个指向 int32 类型的指针 ready，用于存储已准备好的 Pod 的数量。
	var ready *int32
	if feature.DefaultFeatureGate.Enabled(features.JobReadyPods) {
        //如果启用了 JobReadyPods 特性，则计算已准备好的 Pod 的数量。
		ready = pointer.Int32(countReadyPods(activePods))
	}

	//如果作业未处于暂停状态，并且作业没有设置开始时间，则将作业的开始时间设置为当前时间。
	if job.Status.StartTime == nil && !jobSuspended(&job) {
		now := metav1.NewTime(jm.clock.Now())
		job.Status.StartTime = &now
	}
	
    //创建一个新的后退记录，并添加到后退记录存储中。
	newBackoffInfo := jm.backoffRecordStore.newBackoffRecord(jm.clock, key, newSucceededPods, newFailedPods)

	var manageJobErr error // 存储 manageJob 函数执行时的错误信息。
	var finishedCondition *batch.JobCondition // 于存储 Job 的完成 Condition 
	// 判断是否有新的任务执行失败。
	jobHasNewFailure := failed > job.Status.Failed
	// 判断是否达到了最大重试次数
	exceedsBackoffLimit := jobHasNewFailure && (active != *job.Spec.Parallelism) &&
		(failed > *job.Spec.BackoffLimit)
	
    // 如果启用了 JobPodFailurePolicy，通过检查 job.Status.Conditions 中是否存在 batch.JobFailureTarget 类型的 condition，如果存在，则将其转换为 batch.Failed 类型的 condition。
    // 如果不存在，则获取到错误消息，并使用 jobConditionReasonPodFailurePolicy 和错误消息创建新的 batch.JobFailureTarget 类型的 condition。
	if feature.DefaultFeatureGate.Enabled(features.JobPodFailurePolicy) {
		if failureTargetCondition := findConditionByType(job.Status.Conditions, batch.JobFailureTarget); failureTargetCondition != nil {
			finishedCondition = newFailedConditionForFailureTarget(failureTargetCondition, jm.clock.Now())
		} else if failJobMessage := getFailJobMessage(&job, pods, uncounted.Failed()); failJobMessage != nil {
			// Prepare the interim FailureTarget condition to record the failure message before the finalizers (allowing removal of the pods) are removed.
			finishedCondition = newCondition(batch.JobFailureTarget, v1.ConditionTrue, jobConditionReasonPodFailurePolicy, *failJobMessage, jm.clock.Now())
		}
	}
    // 如果 Job 处于未完成状态，将会根据不同的情况创建对应的 condition 类型。
    // 首先，如果已经达到最大重试次数，则创建类型为 batch.JobFailed，reason 为 BackoffLimitExceeded 的 condition。
    // 如果超过了 Job 的执行截止时间，则创建类型为 batch.JobFailed，reason 为 DeadlineExceeded 的 condition。
    // 如果 Job 配置了 ActiveDeadlineSeconds，则计算下次同步的时间，并将其添加到 queue 中。
	if finishedCondition == nil {
		if exceedsBackoffLimit || pastBackoffLimitOnFailure(&job, pods) {
			// check if the number of pod restart exceeds backoff (for restart OnFailure only)
			// OR if the number of failed jobs increased since the last syncJob
			finishedCondition = newCondition(batch.JobFailed, v1.ConditionTrue, "BackoffLimitExceeded", "Job has reached the specified backoff limit", jm.clock.Now())
		} else if jm.pastActiveDeadline(&job) {
			finishedCondition = newCondition(batch.JobFailed, v1.ConditionTrue, "DeadlineExceeded", "Job was active longer than specified deadline", jm.clock.Now())
		} else if job.Spec.ActiveDeadlineSeconds != nil && !jobSuspended(&job) {
			syncDuration := time.Duration(*job.Spec.ActiveDeadlineSeconds)*time.Second - jm.clock.Since(job.Status.StartTime.Time)
			klog.V(2).InfoS("Job has activeDeadlineSeconds configuration. Will sync this job again", "job", key, "nextSyncIn", syncDuration)
			jm.queue.AddAfter(key, syncDuration)
		}
	}
	
    // 根据Job的类型计算已成功的索引和未成功的索引
	var prevSucceededIndexes, succeededIndexes orderedIntervals
	if isIndexedJob(&job) {
		prevSucceededIndexes, succeededIndexes = calculateSucceededIndexes(&job, pods)
		succeeded = int32(succeededIndexes.total())
	}
    // 是否需要更新Job
	suspendCondChanged := false
	if finishedCondition != nil {
        // 如果Job已经完成，将删除其活跃的Pod，并标记Job已完成。否则进入下一步。
		deleted, err := jm.deleteActivePods(ctx, &job, activePods)
		if deleted != active || !satisfiedExpectations {
			// Can't declare the Job as finished yet, as there might be remaining
			// pod finalizers or pods that are not in the informer's cache yet.
			finishedCondition = nil
		}
		active -= deleted
		manageJobErr = err
	} else {
        // 如果Job已满足其期望并且没有被删除，则调用manageJob函数对Job进行管理。
		manageJobCalled := false
		if satisfiedExpectations && job.DeletionTimestamp == nil {
			active, action, manageJobErr = jm.manageJob(ctx, &job, activePods, succeeded, succeededIndexes, newBackoffInfo)
			manageJobCalled = true
		}
		complete := false
        // 根据Job的类型计算是否已完成。
		if job.Spec.Completions == nil {
			complete = succeeded > 0 && active == 0
		} else {
			complete = succeeded >= *job.Spec.Completions && active == 0
		}
		if complete {
            // 完成了新键finishedCondition
			finishedCondition = newCondition(batch.JobComplete, v1.ConditionTrue, "", "", jm.clock.Now())
		} else if manageJobCalled {
			if job.Spec.Suspend != nil && *job.Spec.Suspend {
				// 如果任务被暂停了，则添加 batch.JobSuspended condition 到任务的状态（job.Status.Conditions）中，并记录暂停事件（jm.recorder.Event）。
				var isUpdated bool
				job.Status.Conditions, isUpdated = ensureJobConditionStatus(job.Status.Conditions, batch.JobSuspended, v1.ConditionTrue, "JobSuspended", "Job suspended", jm.clock.Now())
				if isUpdated {
					suspendCondChanged = true
					jm.recorder.Event(&job, v1.EventTypeNormal, "Suspended", "Job suspended")
				}
			} else {
				// 如果任务没有被暂停，则将 batch.JobSuspended condition 从任务状态（job.Status.Conditions）
                // 中移除，并记录恢复事件（jm.recorder.Event）。并且将任务的开始时间（job.Status.StartTime）重置为当前时间。
				var isUpdated bool
				job.Status.Conditions, isUpdated = ensureJobConditionStatus(job.Status.Conditions, batch.JobSuspended, v1.ConditionFalse, "JobResumed", "Job resumed", jm.clock.Now())
				if isUpdated {
					suspendCondChanged = true
					jm.recorder.Event(&job, v1.EventTypeNormal, "Resumed", "Job resumed")
					now := metav1.NewTime(jm.clock.Now())
					job.Status.StartTime = &now
				}
			}
		}
	}
	
	needsStatusUpdate := suspendCondChanged || active != job.Status.Active || !equalReady(ready, job.Status.Ready)
	job.Status.Active = active
	job.Status.Ready = ready
    // 跟踪作业状态并删除最终器
	err = jm.trackJobStatusAndRemoveFinalizers(ctx, &job, pods, prevSucceededIndexes, *uncounted, expectedRmFinalizers, finishedCondition, needsStatusUpdate, newBackoffInfo)
	if err != nil {
		if apierrors.IsConflict(err) {
			// we probably have a stale informer cache
			// so don't return an error to avoid backoff
			jm.enqueueController(&job, false)
			return nil
		}
		return fmt.Errorf("tracking status: %w", err)
	}
	
    // 是否已完成
	jobFinished := IsJobFinished(&job)
	if jobHasNewFailure && !jobFinished {
		// 如果作业有新的失败并且尚未完成
		return fmt.Errorf("failed pod(s) detected for job key %q", key)
	}

	return manageJobErr
}
```

#### IsJobFinished

```go
func IsJobFinished(j *batch.Job) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batch.JobComplete || c.Type == batch.JobFailed) && c.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}
```

#### getCompletionMode

```go
func getCompletionMode(job *batch.Job) string {
	if isIndexedJob(job) {
		return string(batch.IndexedCompletion)
	}
	return string(batch.NonIndexedCompletion)
}
```

##### isIndexedJob

```go
func isIndexedJob(job *batch.Job) bool {
	return job.Spec.CompletionMode != nil && *job.Spec.CompletionMode == batch.IndexedCompletion
}
```

#### newUncountedTerminatedPods

```go
func newUncountedTerminatedPods(in batch.UncountedTerminatedPods) *uncountedTerminatedPods {
	obj := uncountedTerminatedPods{
		succeeded: make(sets.String, len(in.Succeeded)),
		failed:    make(sets.String, len(in.Failed)),
	}
	for _, v := range in.Succeeded {
		obj.succeeded.Insert(string(v))
	}
	for _, v := range in.Failed {
		obj.failed.Insert(string(v))
	}
	return &obj
}

type uncountedTerminatedPods struct {
	succeeded sets.String
	failed    sets.String
}
```

#### getPodsForJob

```go
func (jm *Controller) getPodsForJob(ctx context.Context, j *batch.Job) ([]*v1.Pod, error) {
	selector, err := metav1.LabelSelectorAsSelector(j.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("couldn't convert Job selector: %v", err)
	}
	// 获取pod
	pods, err := jm.podStore.Pods(j.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}
	//如果试图收养，我们应该首先重新检查是否删除
	//在列出Pods之后的某个时间读取未缓存的quorum（参见#42639）。
	canAdoptFunc := controller.RecheckDeletionTimestamp(func(ctx context.Context) (metav1.Object, error) {
		fresh, err := jm.kubeClient.BatchV1().Jobs(j.Namespace).Get(ctx, j.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != j.UID {
			return nil, fmt.Errorf("original Job %v/%v is gone: got uid %v, wanted %v", j.Namespace, j.Name, fresh.UID, j.UID)
		}
		return fresh, nil
	})
	cm := controller.NewPodControllerRefManager(jm.podControl, j, selector, controllerKind, canAdoptFunc, batch.JobTrackingFinalizer)
	// 计算pods
	pods, err = cm.ClaimPods(ctx, pods)
	if err != nil {
		return pods, err
	}
	// 为剩余的计算在采用的pod上设置Finalizers。
	for i, p := range pods {
		adopted := true
		for _, r := range p.OwnerReferences {
			if r.UID == j.UID {
				adopted = false
				break
			}
		}
		if adopted && !hasJobTrackingFinalizer(p) {
			pods[i] = p.DeepCopy()
			pods[i].Finalizers = append(p.Finalizers, batch.JobTrackingFinalizer)
		}
	}
	return pods, err
}
```

#### FilterActivePods

```GO
func FilterActivePods(pods []*v1.Pod) []*v1.Pod {
	var result []*v1.Pod
	for _, p := range pods {
		if IsPodActive(p) {
			result = append(result, p)
		} else {
			klog.V(4).Infof("Ignoring inactive pod %v/%v in state %v, deletion time %v",
				p.Namespace, p.Name, p.Status.Phase, p.DeletionTimestamp)
		}
	}
	return result
}
```

##### IsPodActive

```GO
func IsPodActive(p *v1.Pod) bool {
	return v1.PodSucceeded != p.Status.Phase &&
		v1.PodFailed != p.Status.Phase &&
		p.DeletionTimestamp == nil
}
```

#### getNewFinishedPods

```GO
func getNewFinishedPods(job *batch.Job, pods []*v1.Pod, uncounted *uncountedTerminatedPods, expectedRmFinalizers sets.String) (succeededPods, failedPods []*v1.Pod) {
    // 获取成功的pods
	succeededPods = getValidPodsWithFilter(job, pods, uncounted.Succeeded(), expectedRmFinalizers, func(p *v1.Pod) bool {
		return p.Status.Phase == v1.PodSucceeded
	})
    // 获取失败的pods
	failedPods = getValidPodsWithFilter(job, pods, uncounted.Failed(), expectedRmFinalizers, func(p *v1.Pod) bool {
		if feature.DefaultFeatureGate.Enabled(features.JobPodFailurePolicy) && job.Spec.PodFailurePolicy != nil {
			if !isPodFailed(p, job) {
				return false
			}
			_, countFailed, _ := matchPodFailurePolicy(job.Spec.PodFailurePolicy, p)
			return countFailed
		} else {
			return isPodFailed(p, job)
		}
	})
	return succeededPods, failedPods
}
```

##### getValidPodsWithFilter

```GO
func getValidPodsWithFilter(job *batch.Job, pods []*v1.Pod, uncounted sets.String, expectedRmFinalizers sets.String, filter func(*v1.Pod) bool) []*v1.Pod {
	var result []*v1.Pod
	for _, p := range pods {
		uid := string(p.UID)

		// 如果该pod没有完成的终结器，或者在uncounted集合中，或者在expectedRmFinalizers集合中，则跳过该pod。
		if !hasJobTrackingFinalizer(p) || uncounted.Has(uid) || expectedRmFinalizers.Has(uid) {
			continue
		}
        // 如果job是一个IndexedJob 并且pod的注释中存在CompletionIndex 
		if isIndexedJob(job) {
			idx := getCompletionIndex(p.Annotations)
            // 检查该索引是否小于任务的期望完成数，并且不是未知的索引，如果是，则跳过该pod
			if idx == unknownCompletionIndex || idx >= int(*job.Spec.Completions) {
				continue
			}
		}
		if filter(p) {
			result = append(result, p)
		}
	}
	return result
}
```

###### getCompletionIndex

```GO
func getCompletionIndex(annotations map[string]string) int {
	if annotations == nil {
		return unknownCompletionIndex
	}
	v, ok := annotations[batch.JobCompletionIndexAnnotation]
	if !ok {
		return unknownCompletionIndex
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return unknownCompletionIndex
	}
	if i < 0 {
		return unknownCompletionIndex
	}
	return i
}

```

##### isPodFailed

```go
func isPodFailed(p *v1.Pod, job *batch.Job) bool {
	if feature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) && feature.DefaultFeatureGate.Enabled(features.JobPodFailurePolicy) && job.Spec.PodFailurePolicy != nil {
		return p.Status.Phase == v1.PodFailed
	}
	if p.Status.Phase == v1.PodFailed {
		return true
	}
	return p.DeletionTimestamp != nil && p.Status.Phase != v1.PodSucceeded
}
```

##### matchPodFailurePolicy

```GO
func matchPodFailurePolicy(podFailurePolicy *batch.PodFailurePolicy, failedPod *v1.Pod) (*string, bool, *batch.PodFailurePolicyAction) {
	if podFailurePolicy == nil {
		return nil, true, nil
	}
	ignore := batch.PodFailurePolicyActionIgnore
	failJob := batch.PodFailurePolicyActionFailJob
	count := batch.PodFailurePolicyActionCount
	for index, podFailurePolicyRule := range podFailurePolicy.Rules {
		if podFailurePolicyRule.OnExitCodes != nil {
			if containerStatus := matchOnExitCodes(&failedPod.Status, podFailurePolicyRule.OnExitCodes); containerStatus != nil {
				switch podFailurePolicyRule.Action {
				case batch.PodFailurePolicyActionIgnore:
					return nil, false, &ignore
				case batch.PodFailurePolicyActionCount:
					return nil, true, &count
				case batch.PodFailurePolicyActionFailJob:
					msg := fmt.Sprintf("Container %s for pod %s/%s failed with exit code %v matching %v rule at index %d",
						containerStatus.Name, failedPod.Namespace, failedPod.Name, containerStatus.State.Terminated.ExitCode, podFailurePolicyRule.Action, index)
					return &msg, true, &failJob
				}
			}
		} else if podFailurePolicyRule.OnPodConditions != nil {
			if podCondition := matchOnPodConditions(&failedPod.Status, podFailurePolicyRule.OnPodConditions); podCondition != nil {
				switch podFailurePolicyRule.Action {
				case batch.PodFailurePolicyActionIgnore:
					return nil, false, &ignore
				case batch.PodFailurePolicyActionCount:
					return nil, true, &count
				case batch.PodFailurePolicyActionFailJob:
					msg := fmt.Sprintf("Pod %s/%s has condition %v matching %v rule at index %d",
						failedPod.Namespace, failedPod.Name, podCondition.Type, podFailurePolicyRule.Action, index)
					return &msg, true, &failJob
				}
			}
		}
	}
	return nil, true, nil
}
```

#### pastBackoffLimitOnFailure

```GO
func pastBackoffLimitOnFailure(job *batch.Job, pods []*v1.Pod) bool {
	if job.Spec.Template.Spec.RestartPolicy != v1.RestartPolicyOnFailure {
		return false
	}
	result := int32(0)
	for i := range pods {
		po := pods[i]
        // 检查当前Pod的状态是否为Running或Pending，如果是，则遍历该Pod中的所有Init Container和Container，并将它们的RestartCount加到变量result中。
		if po.Status.Phase == v1.PodRunning || po.Status.Phase == v1.PodPending {
			for j := range po.Status.InitContainerStatuses {
				stat := po.Status.InitContainerStatuses[j]
				result += stat.RestartCount
			}
			for j := range po.Status.ContainerStatuses {
				stat := po.Status.ContainerStatuses[j]
				result += stat.RestartCount
			}
		}
	}
	if *job.Spec.BackoffLimit == 0 {
		return result > 0
	}
	return result >= *job.Spec.BackoffLimit
}
```

#### calculateSucceededIndexes

````GO
func calculateSucceededIndexes(job *batch.Job, pods []*v1.Pod) (orderedIntervals, orderedIntervals) {
	prevIntervals := succeededIndexesFromString(job.Status.CompletedIndexes, int(*job.Spec.Completions))
	newSucceeded := sets.NewInt()
	for _, p := range pods {
        // 获取该Pod的完成索引
		ix := getCompletionIndex(p.Annotations)
		//如果该Pod的状态为Succeeded，同时它的完成索引有效、小于Job的Completions字段的值，
        // 并且具有JobTrackingFinalizer注释，则将其完成索引加入到newSucceeded集合中。
		if p.Status.Phase == v1.PodSucceeded && ix != unknownCompletionIndex && ix < int(*job.Spec.Completions) && hasJobTrackingFinalizer(p) {
			newSucceeded.Insert(ix)
		}
	}
	// 将newSucceeded集合中的元素排序后，与prevIntervals合并生成新的orderedIntervals类型的值，存储在变量result中，并将其作为函数的第二个返回值
	result := prevIntervals.(newSucceeded.List())
	return prevIntervals, result
}

````

##### succeededIndexesFromString

- 该函数的作用是将 Job 的 completedIndexes 字符串解析为有序间隔列表。completedIndexes 字符串包含以逗号分隔的间隔列表，每个间隔由连字符分隔的两个整数表示。例如，"0-3,5,7-8" 表示三个间隔: 0 到 3，5，7 到 8。每个间隔表示一组已完成的 Pod 索引，这些索引属于同一完成序列。函数的输入参数包括完成的索引字符串和完成的总数。如果输入字符串为空，则函数返回 nil，否则将字符串解析为间隔并返回有序的间隔列表。

```GO
func succeededIndexesFromString(completedIndexes string, completions int) orderedIntervals {
	if completedIndexes == "" {
		return nil
	}
	var result orderedIntervals
	var lastInterval *interval
	for _, intervalStr := range strings.Split(completedIndexes, ",") {
		limitsStr := strings.Split(intervalStr, "-")
		var inter interval
		var err error
		inter.First, err = strconv.Atoi(limitsStr[0])
		if err != nil {
			klog.InfoS("Corrupted completed indexes interval, ignoring", "interval", intervalStr, "err", err)
			continue
		}
		if inter.First >= completions {
			break
		}
		if len(limitsStr) > 1 {
			inter.Last, err = strconv.Atoi(limitsStr[1])
			if err != nil {
				klog.InfoS("Corrupted completed indexes interval, ignoring", "interval", intervalStr, "err", err)
				continue
			}
			if inter.Last >= completions {
				inter.Last = completions - 1
			}
		} else {
			inter.Last = inter.First
		}
		if lastInterval != nil && lastInterval.Last == inter.First-1 {
			lastInterval.Last = inter.Last
		} else {
			result = append(result, inter)
			lastInterval = &result[len(result)-1]
		}
	}
	return result
}
```

##### withOrderedIndexes

将已成功的任务下标加入到一个有序的区间集合中

```GO
func (oi orderedIntervals) withOrderedIndexes(newIndexes []int) orderedIntervals {
	var result orderedIntervals
	i := 0
	j := 0
	var lastInterval *interval
	appendOrMergeWithLastInterval := func(thisInterval interval) {
		if lastInterval == nil || thisInterval.First > lastInterval.Last+1 {
			result = append(result, thisInterval)
			lastInterval = &result[len(result)-1]
		} else if lastInterval.Last < thisInterval.Last {
			lastInterval.Last = thisInterval.Last
		}
	}
	for i < len(oi) && j < len(newIndexes) {
		if oi[i].First < newIndexes[j] {
			appendOrMergeWithLastInterval(oi[i])
			i++
		} else {
			appendOrMergeWithLastInterval(interval{newIndexes[j], newIndexes[j]})
			j++
		}
	}
	for i < len(oi) {
		appendOrMergeWithLastInterval(oi[i])
		i++
	}
	for j < len(newIndexes) {
		appendOrMergeWithLastInterval(interval{newIndexes[j], newIndexes[j]})
		j++
	}
	return result
}
```

#### deleteActivePods

````GO
func (jm *Controller) deleteActivePods(ctx context.Context, job *batch.Job, pods []*v1.Pod) (int32, error) {
	errCh := make(chan error, len(pods))
	successfulDeletes := int32(len(pods))
	wg := sync.WaitGroup{}
	wg.Add(len(pods))
	for i := range pods {
		go func(pod *v1.Pod) {
			defer wg.Done()
			if err := jm.podControl.DeletePod(ctx, job.Namespace, pod.Name, job); err != nil && !apierrors.IsNotFound(err) {
				atomic.AddInt32(&successfulDeletes, -1)
				errCh <- err
				utilruntime.HandleError(err)
			}
		}(pods[i])
	}
	wg.Wait()
	return successfulDeletes, errorFromChannel(errCh)
}
````

### manageJob

```GO
func (jm *Controller) manageJob(ctx context.Context, job *batch.Job, activePods []*v1.Pod, succeeded int32, succeededIndexes []interval, backoff backoffRecord) (int32, string, error) {
	active := int32(len(activePods)) // 统计正在运行的Pod数量
	parallelism := *job.Spec.Parallelism // 获取job的并行度
	jobKey, err := controller.KeyFunc(job)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for job %#v: %v", job, err))
		return 0, metrics.JobSyncActionTracking, nil
	}

	if jobSuspended(job) {
        // 如果job已经暂停
		klog.V(4).InfoS("Deleting all active pods in suspended job", "job", klog.KObj(job), "active", active)
		podsToDelete := activePodsForRemoval(job, activePods, int(active))
		jm.expectations.ExpectDeletions(jobKey, len(podsToDelete)) // 更新期望值
		removed, err := jm.deleteJobPods(ctx, job, jobKey, podsToDelete) // 删除Pod
		active -= removed  // 更新正在运行的Pod数量
		return active, metrics.JobSyncActionPodsDeleted, err
	}

	wantActive := int32(0)
	if job.Spec.Completions == nil {
        // 如果没有指定完成次数
		if succeeded > 0 {
            //  如果已经成功过 则不需要创建新的Pod，当前运行的Pod数保持不变
			wantActive = active
		} else {
            //  如果没有成功过 则需要创建parallelism个Pod
			wantActive = parallelism
		}
	} else {
		// 如果指定了完成次数
		wantActive = *job.Spec.Completions - succeeded  // 计算需要的Pod数
		if wantActive > parallelism { // 如果需要的Pod数大于并行度
			wantActive = parallelism // 则只需要创建并行度个Pod
		}
		if wantActive < 0 { // 如果需要的Pod数为负数
			wantActive = 0 // 则不需要创建新的Pod
		}
	}

	rmAtLeast := active - wantActive // 计算需要删除的Pod数量
	if rmAtLeast < 0 { 
        // 如果需要删除的Pod数量为负数  则不需要删除Pod
		rmAtLeast = 0
	}
    // 获取需要删除的Pod
	podsToDelete := activePodsForRemoval(job, activePods, int(rmAtLeast))
	if len(podsToDelete) > MaxPodCreateDeletePerSync {
        // 如果要删除的 Pod 数量超过限制  将要删除的 Pod 数量截断到限制之内
		podsToDelete = podsToDelete[:MaxPodCreateDeletePerSync]
	}
	if len(podsToDelete) > 0 {
        // 如果有需要删除的 Pod 标记期望删除这些 Pod
		jm.expectations.ExpectDeletions(jobKey, len(podsToDelete))
		klog.V(4).InfoS("Too many pods running for job", "job", klog.KObj(job), "deleted", len(podsToDelete), "target", wantActive)
		removed, err := jm.deleteJobPods(ctx, job, jobKey, podsToDelete)
		active -= removed  // 更新当前活跃的 Pod 数量
    	// 在同一次同步周期中，我们只会进行 Pod 删除或 Pod 创建的操作，不会同时进行这两种操作。
    	// 如果需要同时进行 Pod 创建和删除（例如带有重复索引的索引 Job），我们会优先进行 Pod 删除。
		return active, metrics.JobSyncActionPodsDeleted, err
	}

	if active < wantActive {
         // 如果当前活跃的 Pod 数量小于期望的 Pod 数量
		remainingTime := backoff.getRemainingTime(jm.clock, DefaultJobBackOff, MaxJobBackOff)  // 计算等待时间
		if remainingTime > 0 {
            // 如果等待时间大于 0  将该 Job 标记为延迟处理
			jm.enqueueControllerDelayed(job, true, remainingTime)
			return 0, metrics.JobSyncActionPodsCreated, nil
		}
		diff := wantActive - active //  计算需要创建的 Pod 数量
		if diff > int32(MaxPodCreateDeletePerSync) {
             // 如果需要创建的 Pod 数量超过限制 将需要创建的 Pod 数量截断到限制之内
			diff = int32(MaxPodCreateDeletePerSync)
		}
		// 标记期望创建这些 Pod
		jm.expectations.ExpectCreations(jobKey, int(diff))
		errCh := make(chan error, diff)
		klog.V(4).Infof("Too few pods running job %q, need %d, creating %d", jobKey, wantActive, diff)

		wait := sync.WaitGroup{}
		// 定义需要创建 Pod 的索引列表
		var indexesToAdd []int
		if isIndexedJob(job) {
            // 如果该 Job 是索引 Job // 获取第一批需要创建的索引
			indexesToAdd = firstPendingIndexes(activePods, succeededIndexes, int(diff), int(*job.Spec.Completions))
            // 更新需要创建的 Pod 数量
			diff = int32(len(indexesToAdd))
		}
        // 将增量diff加到变量active中
		active += diff

		podTemplate := job.Spec.Template.DeepCopy()
		if isIndexedJob(job) {
             // 如果Job是一个索引Job 向podTemplate中添加用于完成索引的环境变量
			addCompletionIndexEnvVariables(podTemplate)
		}
        // 确保podTemplate中包含Job完成时需要执行的finalizer
		podTemplate.Finalizers = appendJobCompletionFinalizerIfNotFound(podTemplate.Finalizers)

		// 分批创建Pod。批大小从SlowStartInitialBatchSize开始，每次成功迭代都会翻倍，以一种“缓慢启动”的方式进行。
        // 这样可以处理尝试启动大量Pod的情况，这些Pod可能会因相同的错误而全部失败。
        // 例如，尝试创建大量Pod的配额较低的项目将在一个Pod失败后被阻止向API服务发送Pod创建请求。方便地，这也可以防止这些故障产生的事件垃圾邮件。
		for batchSize := int32(integer.IntMin(int(diff), controller.SlowStartInitialBatchSize)); diff > 0; batchSize = integer.Int32Min(2*batchSize, diff) {
            // 根据增量和SlowStartInitialBatchSize确定批大小，进行批处理
			errorCount := len(errCh) // 记录之前已经发生的错误数量
			wait.Add(int(batchSize)) // 向等待组中添加batchSize个任务
			for i := int32(0); i < batchSize; i++ {
				completionIndex := unknownCompletionIndex
				if len(indexesToAdd) > 0 {
                    // 如果indexesToAdd中有元素
					completionIndex = indexesToAdd[0] // 取出第一个元素
					indexesToAdd = indexesToAdd[1:]  // 将第一个元素删除
				}
                // 并发执行以下代码
				go func() {
					template := podTemplate
					generateName := ""
					if completionIndex != unknownCompletionIndex {
                        // 如果completionIndex不为默认值
						template = podTemplate.DeepCopy()
						addCompletionIndexAnnotation(template, completionIndex)
						template.Spec.Hostname = fmt.Sprintf("%s-%d", job.Name, completionIndex)
						generateName = podGenerateNameWithIndex(job.Name, completionIndex)
					}
                    // 当前任务完成时，减少等待组中的任务数
					defer wait.Done()
                    // 创建Pod
					err := jm.podControl.CreatePodsWithGenerateName(ctx, job.Namespace, template, job, metav1.NewControllerRef(job, controllerKind), generateName)
					if err != nil {
						if apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
							// If the namespace is being torn down, we can safely ignore
							// this error since all subsequent creations will fail.
							return
						}
					}
					if err != nil {
						defer utilruntime.HandleError(err)
						// 将预期的创建数量减少，因为informer不会观察到这个pod
						klog.V(2).Infof("Failed creation, decrementing expectations for job %q/%q", job.Namespace, job.Name)
						jm.expectations.CreationObserved(jobKey)
						atomic.AddInt32(&active, -1)
						errCh <- err
					}
				}()
			}
			wait.Wait()
			// 如果我们从未尝试启动的任何跳过的pod，就不应该期望它们。
			skippedPods := diff - batchSize
			if errorCount < len(errCh) && skippedPods > 0 {
				klog.V(2).Infof("Slow-start failure. Skipping creation of %d pods, decrementing expectations for job %q/%q", skippedPods, job.Namespace, job.Name)
				active -= skippedPods
				for i := int32(0); i < skippedPods; i++ {
					// 将预期的创建数量减少，因为informer不会观察到这个pod
					jm.expectations.CreationObserved(jobKey)
				}
				// 跳过的pod将稍后重试。下一个控制器重新同步时将重试慢启动过程。
				break
			}
			diff -= batchSize
		}
		return active, metrics.JobSyncActionPodsCreated, errorFromChannel(errCh)
	}

	return active, metrics.JobSyncActionTracking, nil
}
```

##### activePodsForRemoval

```go
func activePodsForRemoval(job *batch.Job, pods []*v1.Pod, rmAtLeast int) []*v1.Pod {
	var rm, left []*v1.Pod

	// 如果Job是一个具有索引的任务类型，则对其进行特殊处理。
    if isIndexedJob(job) {
        // 对rm和left进行初始化，分别表示需要删除和不需要删除的Pod对象切片。
        rm = make([]*v1.Pod, 0, rmAtLeast)
        left = make([]*v1.Pod, 0, len(pods)-rmAtLeast)

        // 调用appendDuplicatedIndexPodsForRemoval函数处理需要删除和不需要删除的Pod对象。
        rm, left = appendDuplicatedIndexPodsForRemoval(rm, left, pods, int(*job.Spec.Completions))
    } else {
        // 如果Job不是一个具有索引的任务类型，则left变量表示所有Pod都不需要删除。
        left = pods
    }

    // 如果需要删除的Pod数量小于rmAtLeast，那么需要进一步处理不需要删除的Pod对象left。
    if len(rm) < rmAtLeast {
        // 对不需要删除的Pod对象按照ActivePods函数的排序方式进行排序。
        sort.Sort(controller.ActivePods(left))
        // 将排名最靠前的一些Pod对象添加到rm中。
        rm = append(rm, left[:rmAtLeast-len(rm)]...)
    }
    // 返回需要删除的Pod对象列表。
    return rm
}
```

###### appendDuplicatedIndexPodsForRemoval

```go
func appendDuplicatedIndexPodsForRemoval(rm, left, pods []*v1.Pod, completions int) ([]*v1.Pod, []*v1.Pod) {
	// 首先按照完成索引值排序
	sort.Sort(byCompletionIndex(pods))
	// 初始的完成索引值未知
	lastIndex := unknownCompletionIndex
	// 第一个重复索引的位置
	firstRepeatPos := 0
	// 记录已经遍历的Pod数目
	countLooped := 0
	for i, p := range pods {
		// 获取Pod的完成索引值
		ix := getCompletionIndex(p.Annotations)
		// 如果索引值超过了完成数，则将后面的Pod都加入到需要删除的切片中
		if ix >= completions {
			rm = append(rm, pods[i:]...)
			break
		}
		// 如果当前Pod的索引值与上一个Pod不同，则将之前重复的索引值的Pod加入到需要删除和剩余的切片中
		if ix != lastIndex {
			rm, left = appendPodsWithSameIndexForRemovalAndRemaining(rm, left, pods[firstRepeatPos:i], lastIndex)
			firstRepeatPos = i
			lastIndex = ix
		}
		countLooped += 1
	}
	// 最后将剩余的Pod加入到需要删除和剩余的切片中
	return appendPodsWithSameIndexForRemovalAndRemaining(rm, left, pods[firstRepeatPos:countLooped], lastIndex)
}
```

###### appendPodsWithSameIndexForRemovalAndRemaining

```go
func appendPodsWithSameIndexForRemovalAndRemaining(rm, left, pods []*v1.Pod, ix int) ([]*v1.Pod, []*v1.Pod) {
	// 如果完成索引未知，将所有 Pod 添加到 rm 中，并返回 rm 和 left。
	if ix == unknownCompletionIndex {
		rm = append(rm, pods...)
		return rm, left
	}
	// 如果切片中只有一个 Pod，将其添加到 left 中，并返回 rm 和 left。
	if len(pods) == 1 {
		left = append(left, pods[0])
		return rm, left
	}
	// 对具有相同完成索引的 Pod 按照 ActivePods 排序，将前面的 Pod 添加到 rm 中，最后一个 Pod 添加到 left 中。
	sort.Sort(controller.ActivePods(pods))
	rm = append(rm, pods[:len(pods)-1]...)
	left = append(left, pods[len(pods)-1])
	return rm, left
}
```

##### deleteJobPods

```go
func (jm *Controller) deleteJobPods(ctx context.Context, job *batch.Job, jobKey string, pods []*v1.Pod) (int32, error) {
	errCh := make(chan error, len(pods))
	successfulDeletes := int32(len(pods))

	failDelete := func(pod *v1.Pod, err error) {
		// Decrement the expected number of deletes because the informer won't observe this deletion
		jm.expectations.DeletionObserved(jobKey)
		if !apierrors.IsNotFound(err) {
			klog.V(2).Infof("Failed to delete Pod", "job", klog.KObj(job), "pod", klog.KObj(pod), "err", err)
			atomic.AddInt32(&successfulDeletes, -1)
			errCh <- err
			utilruntime.HandleError(err)
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(len(pods))
	for i := range pods {
		go func(pod *v1.Pod) {
			defer wg.Done()
			if patch := removeTrackingFinalizerPatch(pod); patch != nil {
				if err := jm.podControl.PatchPod(ctx, pod.Namespace, pod.Name, patch); err != nil {
					failDelete(pod, fmt.Errorf("removing completion finalizer: %w", err))
					return
				}
			}
			if err := jm.podControl.DeletePod(ctx, job.Namespace, pod.Name, job); err != nil {
				failDelete(pod, err)
			}
		}(pods[i])
	}
	wg.Wait()
	return successfulDeletes, errorFromChannel(errCh)
}
```

###### removeTrackingFinalizerPatch

```go
func removeTrackingFinalizerPatch(pod *v1.Pod) []byte {
	if !hasJobTrackingFinalizer(pod) {
		return nil
	}
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"$deleteFromPrimitiveList/finalizers": []string{batch.JobTrackingFinalizer},
		},
	}
	patchBytes, _ := json.Marshal(patch)
	return patchBytes
}
```

##### firstPendingIndexes

```go
func firstPendingIndexes(activePods []*v1.Pod, succeededIndexes orderedIntervals, count, completions int) []int {
    // 返回未完成的任务的索引，最多返回 count 个。如果没有未完成的任务，返回 nil。
	if count == 0 {
		return nil
	}

    // 使用一个新的 int 集合 active 来存储已经完成的任务的索引。
    active := sets.NewInt()
    for _, p := range activePods {
        // 从 Pod 注解中获取完成的索引。
        ix := getCompletionIndex(p.Annotations)
        if ix != unknownCompletionIndex {
            // 如果索引未知，则不包括在 active 中。
            active.Insert(ix)
        }
    }

    // 用于存储结果的 int 切片 result。
    result := make([]int, 0, count)

    // 使用已成功的任务索引集合 succeededIndexes，移除 active 中的所有已完成任务，得到尚未完成的任务索引。
    nonPending := succeededIndexes.withOrderedIndexes(active.List())

    // 以下算法的时间复杂度由 len(nonPending) 和 count 限定。
    // 初始化候选任务索引为 0。
    candidate := 0
    for _, sInterval := range nonPending {
        // 在 nonPending 中遍历 sInterval，并将 candidate 置于 sInterval 的第一个元素的左侧，以检查是否有未完成的任务。
        for ; candidate < completions && len(result) < count && candidate < sInterval.First; candidate++ {
            result = append(result, candidate)
        }
        if candidate < sInterval.Last+1 {
            // candidate 必须是 sInterval 最后一个元素的右侧。
            candidate = sInterval.Last + 1
        }
    }

    // 处理剩下的候选索引。
    for ; candidate < completions && len(result) < count; candidate++ {
        result = append(result, candidate)
    }

    // 返回未完成的任务索引。
    return result


}
```

##### addCompletionIndexEnvVariables

````go
func addCompletionIndexEnvVariables(template *v1.PodTemplateSpec) {
	for i := range template.Spec.InitContainers {
		addCompletionIndexEnvVariable(&template.Spec.InitContainers[i])
	}
	for i := range template.Spec.Containers {
		addCompletionIndexEnvVariable(&template.Spec.Containers[i])
	}
}
````

###### addCompletionIndexEnvVariable

```go
func addCompletionIndexEnvVariable(container *v1.Container) {
	for _, v := range container.Env {
		if v.Name == completionIndexEnvName {
			return
		}
	}
	container.Env = append(container.Env, v1.EnvVar{
		Name: completionIndexEnvName,
		ValueFrom: &v1.EnvVarSource{
			FieldRef: &v1.ObjectFieldSelector{
				FieldPath: fmt.Sprintf("metadata.annotations['%s']", batch.JobCompletionIndexAnnotation),
			},
		},
	})
}
```

###### appendJobCompletionFinalizerIfNotFound

```go
func appendJobCompletionFinalizerIfNotFound(finalizers []string) []string {
	for _, fin := range finalizers {
		if fin == batch.JobTrackingFinalizer {
			return finalizers
		}
	}
	return append(finalizers, batch.JobTrackingFinalizer)
}
```

##### addCompletionIndexAnnotation

```go
func addCompletionIndexAnnotation(template *v1.PodTemplateSpec, index int) {
	if template.Annotations == nil {
		template.Annotations = make(map[string]string, 1)
	}
	template.Annotations[batch.JobCompletionIndexAnnotation] = strconv.Itoa(index)
}

```

###### podGenerateNameWithIndex

```go
func podGenerateNameWithIndex(jobName string, index int) string {
	appendIndex := "-" + strconv.Itoa(index) + "-"
	generateNamePrefix := jobName + appendIndex
	if len(generateNamePrefix) > names.MaxGeneratedNameLength {
		generateNamePrefix = generateNamePrefix[:names.MaxGeneratedNameLength-len(appendIndex)] + appendIndex
	}
	return generateNamePrefix
}
```

#### ensureJobConditionStatus

```go
func ensureJobConditionStatus(list []batch.JobCondition, cType batch.JobConditionType, status v1.ConditionStatus, reason, message string, now time.Time) ([]batch.JobCondition, bool) {
	if condition := findConditionByType(list, cType); condition != nil {
		if condition.Status != status || condition.Reason != reason || condition.Message != message {
			*condition = *newCondition(cType, status, reason, message, now)
			return list, true
		}
		return list, false
	}
	// A condition with that type doesn't exist in the list.
	if status != v1.ConditionFalse {
		return append(list, *newCondition(cType, status, reason, message, now)), true
	}
	return list, false
}
```



## orphanWorker

```go
func (jm *Controller) orphanWorker(ctx context.Context) {
	for jm.processNextOrphanPod(ctx) {
	}
}

func (jm Controller) processNextOrphanPod(ctx context.Context) bool {
	key, quit := jm.orphanQueue.Get()
	if quit {
		return false
	}
	defer jm.orphanQueue.Done(key)
	err := jm.syncOrphanPod(ctx, key.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Error syncing orphan pod: %v", err))
		jm.orphanQueue.AddRateLimited(key)
	} else {
		jm.orphanQueue.Forget(key)
	}

	return true
}
```

### syncOrphanPod

```go
func (jm Controller) syncOrphanPod(ctx context.Context, key string) error {
	startTime := jm.clock.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing orphan pod %q (%v)", key, jm.clock.Since(startTime))
	}()

	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	// 获取pod
	sharedPod, err := jm.podStore.Pods(ns).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("Orphan pod has been deleted: %v", key)
			return nil
		}
		return err
	}
	// 如果 sharedPod 的 ControllerRef 不为空，则说明该 Pod 被某个控制器采纳。
	if controllerRef := metav1.GetControllerOf(sharedPod); controllerRef != nil {
        // 解析 sharedPod 的 ControllerRef，获取其所属的 Job 对象。
		job := jm.resolveControllerRef(sharedPod.Namespace, controllerRef)
		if job != nil && !IsJobFinished(job) {
			// 如果该 Pod 被某个未完成的 Job 对象采纳，则不需要移除该 Pod 的 finalizer。
			return nil
		}
	}
    // 否则，该 Pod 已经孤立，需要将其 finalizer 移除。
	if patch := removeTrackingFinalizerPatch(sharedPod); patch != nil {
		if err := jm.podControl.PatchPod(ctx, ns, name, patch); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
```

