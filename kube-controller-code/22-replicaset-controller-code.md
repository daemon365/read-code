
## 简介

ReplicaSet Controller 是 Kubernetes 中的一种控制器对象。用于管理同一个 ReplicaSet 中的多个 Pod 副本。用于确保一个指定数量的 Pod 副本在运行时存在并可用。

ReplicaSet Controller 的主要作用是根据用户定义的副本集规格，自动调整 Pod 副本数量，以确保副本集中始终存在指定数量的 Pod 副本。如果发现某个 Pod 副本已经不可用或者被删除了，ReplicaSet Controller 会自动创建一个新的 Pod 副本来代替它。

## 结构体

```GO
type ReplicaSetController struct {
	// GroupVersionKind 用于标识 Kubernetes 中不同的控制器对象
	schema.GroupVersionKind

	kubeClient clientset.Interface
    // 创建、更新和删除 Pod 的接口
	podControl controller.PodControlInterface
	// 广播事件
	eventBroadcaster record.EventBroadcaster

	// 在创建或删除这么多个 Pod 副本后，ReplicaSet 将被暂停一段时间，以避免过度操作。默认为 10
	burstReplicas int
	// 同步 ReplicaSet 的回调函数
	syncHandler func(ctx context.Context, rsKey string) error

	//跟踪每个 ReplicaSet 期望看到的 Pod 创建和删除事件
	expectations *controller.UIDTrackingControllerExpectations

	rsLister appslisters.ReplicaSetLister
	rsListerSynced cache.InformerSynced
    // indexer缓存
	rsIndexer      cache.Indexer

	podLister corelisters.PodLister
	podListerSynced cache.InformerSynced

	// 存储需要同步
	queue workqueue.RateLimitingInterface
}
```

## New

```GO
// NewReplicaSetController configures a replica set controller with the specified event recorder
func NewReplicaSetController(logger klog.Logger, rsInformer appsinformers.ReplicaSetInformer, podInformer coreinformers.PodInformer, kubeClient clientset.Interface, burstReplicas int) *ReplicaSetController {
	eventBroadcaster := record.NewBroadcaster()
	if err := metrics.Register(legacyregistry.Register); err != nil {
		logger.Error(err, "unable to register metrics")
	}
	return NewBaseController(rsInformer, podInformer, kubeClient, burstReplicas,
		apps.SchemeGroupVersion.WithKind("ReplicaSet"),
		"replicaset_controller",
		"replicaset",
		controller.RealPodControl{
			KubeClient: kubeClient,
			Recorder:   eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "replicaset-controller"}),
		},
		eventBroadcaster,
	)
}


func NewBaseController(rsInformer appsinformers.ReplicaSetInformer, podInformer coreinformers.PodInformer, kubeClient clientset.Interface, burstReplicas int,
	gvk schema.GroupVersionKind, metricOwnerName, queueName string, podControl controller.PodControlInterface, eventBroadcaster record.EventBroadcaster) *ReplicaSetController {

	rsc := &ReplicaSetController{
		GroupVersionKind: gvk,
		kubeClient:       kubeClient,
		podControl:       podControl,
		eventBroadcaster: eventBroadcaster,
		burstReplicas:    burstReplicas,
		expectations:     controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectations()),
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), queueName),
	}
	// 监控rs事件
	rsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    rsc.addRS,
		UpdateFunc: rsc.updateRS,
		DeleteFunc: rsc.deleteRS,
	})
    // 在缓存中使用UUid再建缓存
	rsInformer.Informer().AddIndexers(cache.Indexers{
		controllerUIDIndex: func(obj interface{}) ([]string, error) {
			rs, ok := obj.(*apps.ReplicaSet)
			if !ok {
				return []string{}, nil
			}
			controllerRef := metav1.GetControllerOf(rs)
			if controllerRef == nil {
				return []string{}, nil
			}
			return []string{string(controllerRef.UID)}, nil
		},
	})
	rsc.rsIndexer = rsInformer.Informer().GetIndexer()
	rsc.rsLister = rsInformer.Lister()
	rsc.rsListerSynced = rsInformer.Informer().HasSynced
	
    // 监控pod
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: rsc.addPod,
		UpdateFunc: rsc.updatePod,
		DeleteFunc: rsc.deletePod,
	})
	rsc.podLister = podInformer.Lister()
	rsc.podListerSynced = podInformer.Informer().HasSynced

	rsc.syncHandler = rsc.syncReplicaSet

	return rsc
}
```

### 队列相关

**rs**

```go
func (rsc *ReplicaSetController) addRS(obj interface{}) {
	rs := obj.(*apps.ReplicaSet)
	klog.V(4).Infof("Adding %s %s/%s", rsc.Kind, rs.Namespace, rs.Name)
	rsc.enqueueRS(rs)
}

// callback when RS is updated
func (rsc *ReplicaSetController) updateRS(old, cur interface{}) {
	oldRS := old.(*apps.ReplicaSet)
	curRS := cur.(*apps.ReplicaSet)

	// 如果更新前和更新后的 ReplicaSet 的 UID 不同，说明这是一个新的对象，需要将更新前的对象删除。
	if curRS.UID != oldRS.UID {
		key, err := controller.KeyFunc(oldRS)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", oldRS, err))
			return
		}
		rsc.deleteRS(cache.DeletedFinalStateUnknown{
			Key: key,
			Obj: oldRS,
		})
	}

	// Replicas不同打印日志 
	if *(oldRS.Spec.Replicas) != *(curRS.Spec.Replicas) {
		klog.V(4).Infof("%v %v updated. Desired pod count change: %d->%d", rsc.Kind, curRS.Name, *(oldRS.Spec.Replicas), *(curRS.Spec.Replicas))
	}
	rsc.enqueueRS(curRS)
}

func (rsc *ReplicaSetController) deleteRS(obj interface{}) {
    // 拿出rs
	rs, ok := obj.(*apps.ReplicaSet)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		rs, ok = tombstone.Obj.(*apps.ReplicaSet)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a ReplicaSet %#v", obj))
			return
		}
	}

	key, err := controller.KeyFunc(rs)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", rs, err))
		return
	}

	klog.V(4).Infof("Deleting %s %q", rsc.Kind, key)

	//  删除 ReplicaSet 对象的预期
	rsc.expectations.DeleteExpectations(key)

	rsc.queue.Add(key)
}

// 加入queue
func (rsc *ReplicaSetController) enqueueRS(rs *apps.ReplicaSet) {
	key, err := controller.KeyFunc(rs)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", rs, err))
		return
	}

	rsc.queue.Add(key)
}

// duration秒之后加入queue
func (rsc *ReplicaSetController) enqueueRSAfter(rs *apps.ReplicaSet, duration time.Duration) {
	key, err := controller.KeyFunc(rs)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", rs, err))
		return
	}

	rsc.queue.AddAfter(key, duration)
}
```

**pod**

```GO
func (rsc *ReplicaSetController) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)

	if pod.DeletionTimestamp != nil {
		// 被删除了 
		rsc.deletePod(pod)
		return
	}

	// 获取rs bing加入expectations和队列
	if controllerRef := metav1.GetControllerOf(pod); controllerRef != nil {
		rs := rsc.resolveControllerRef(pod.Namespace, controllerRef)
		if rs == nil {
			return
		}
		rsKey, err := controller.KeyFunc(rs)
		if err != nil {
			return
		}
		klog.V(4).Infof("Pod %s created: %#v.", pod.Name, pod)
		rsc.expectations.CreationObserved(rsKey)
		rsc.queue.Add(rsKey)
		return
	}

	// 获取rs
	rss := rsc.getPodReplicaSets(pod)
	if len(rss) == 0 {
		return
	}
	klog.V(4).Infof("Orphan Pod %s created: %#v.", pod.Name, pod)
	for _, rs := range rss {
		rsc.enqueueRS(rs)
	}
}

func (rsc *ReplicaSetController) updatePod(old, cur interface{}) {
	curPod := cur.(*v1.Pod)
	oldPod := old.(*v1.Pod)
	if curPod.ResourceVersion == oldPod.ResourceVersion {
		// 没有变化
		return
	}

	labelChanged := !reflect.DeepEqual(curPod.Labels, oldPod.Labels)
	if curPod.DeletionTimestamp != nil {
		// 被删除了
		rsc.deletePod(curPod)
		if labelChanged {
			// 如果 Pod 的标签发生了变化，说明这个 Pod 不再属于之前的 ReplicaSet，也需要将其从对应的 ReplicaSet 中删除
			rsc.deletePod(oldPod)
		}
		return
	}

	curControllerRef := metav1.GetControllerOf(curPod)
	oldControllerRef := metav1.GetControllerOf(oldPod)
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// 如果更新前和更新后的 Pod 的 ControllerRef 不同，说明这个 Pod 的控制器发生了变化，需要同步旧的控制器。
		if rs := rsc.resolveControllerRef(oldPod.Namespace, oldControllerRef); rs != nil {
			rsc.enqueueRS(rs)
		}
	}

	// 当 curPod.DeletionTimestamp 不为空时，表示当前的 Pod 正在被删除
	if curControllerRef != nil {
		rs := rsc.resolveControllerRef(curPod.Namespace, curControllerRef)
		if rs == nil {
			return
		}
		klog.V(4).Infof("Pod %s updated, objectMeta %+v -> %+v.", curPod.Name, oldPod.ObjectMeta, curPod.ObjectMeta)
		rsc.enqueueRS(rs)
		// 如果一个Pod从未就绪状态变为了就绪状态，并且其所属的ReplicaSet的MinReadySeconds字段大于0，那么就将该ReplicaSet加入队列中，等待一段时间后进行可用性检查。
		if !podutil.IsPodReady(oldPod) && podutil.IsPodReady(curPod) && rs.Spec.MinReadySeconds > 0 {
			klog.V(2).Infof("%v %q will be enqueued after %ds for availability check", rsc.Kind, rs.Name, rs.Spec.MinReadySeconds)
			rsc.enqueueRSAfter(rs, (time.Duration(rs.Spec.MinReadySeconds)*time.Second)+time.Second)
		}
		return
	}

	// 如果标签变了或者ref变了
	if labelChanged || controllerRefChanged {
		rss := rsc.getPodReplicaSets(curPod)
		if len(rss) == 0 {
			return
		}
		klog.V(4).Infof("Orphan Pod %s updated, objectMeta %+v -> %+v.", curPod.Name, oldPod.ObjectMeta, curPod.ObjectMeta)
		for _, rs := range rss {
			rsc.enqueueRS(rs)
		}
	}
}

func (rsc *ReplicaSetController) deletePod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)

	// 获取pod
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %+v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a pod %#v", obj))
			return
		}
	}

	controllerRef := metav1.GetControllerOf(pod)
	if controllerRef == nil {
		// 已经空了 直接返回
		return
	}
	rs := rsc.resolveControllerRef(pod.Namespace, controllerRef)
	if rs == nil {
		return
	}
	rsKey, err := controller.KeyFunc(rs)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", rs, err))
		return
	}
    // 加入queue 并从expectations删除
	klog.V(4).Infof("Pod %s/%s deleted through %v, timestamp %+v: %#v.", pod.Namespace, pod.Name, utilruntime.GetCaller(), pod.DeletionTimestamp, pod)
	rsc.expectations.DeletionObserved(rsKey, controller.PodKey(pod))
	rsc.queue.Add(rsKey)
}

func (rsc *ReplicaSetController) getPodReplicaSets(pod *v1.Pod) []*apps.ReplicaSet {
	rss, err := rsc.rsLister.GetPodReplicaSets(pod)
	if err != nil {
		return nil
	}
	if len(rss) > 1 {
		utilruntime.HandleError(fmt.Errorf("user error! more than one %v is selecting pods with labels: %+v", rsc.Kind, pod.Labels))
	}
	return rss
}

```

## Run

```GO
func (rsc *ReplicaSetController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	// Start events processing pipeline.
	rsc.eventBroadcaster.StartStructuredLogging(0)
	rsc.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: rsc.kubeClient.CoreV1().Events("")})
	defer rsc.eventBroadcaster.Shutdown()

	defer rsc.queue.ShutDown()

	controllerName := strings.ToLower(rsc.Kind)
	klog.FromContext(ctx).Info("Starting controller", "name", controllerName)
	defer klog.FromContext(ctx).Info("Shutting down controller", "name", controllerName)

	if !cache.WaitForNamedCacheSync(rsc.Kind, ctx.Done(), rsc.podListerSynced, rsc.rsListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, rsc.worker, time.Second)
	}

	<-ctx.Done()
}
```

## worker

```go
func (rsc *ReplicaSetController) worker(ctx context.Context) {
	for rsc.processNextWorkItem(ctx) {
	}
}

func (rsc *ReplicaSetController) processNextWorkItem(ctx context.Context) bool {
	key, quit := rsc.queue.Get()
	if quit {
		return false
	}
	defer rsc.queue.Done(key)
	
    // 同步 没有错完成 出错了 加入延迟队列
	err := rsc.syncHandler(ctx, key.(string))
	if err == nil {
		rsc.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("sync %q failed with %v", key, err))
	rsc.queue.AddRateLimited(key)

	return true
}

```

### syncHandler

syncReplicaSet就是syncHandler，在New的时候赋值

```GO
func (rsc *ReplicaSetController) syncReplicaSet(ctx context.Context, key string) error {
    // 结束时打印信息 包括用时
	startTime := time.Now()
	defer func() {
		klog.FromContext(ctx).V(4).Info("Finished syncing", "kind", rsc.Kind, "key", key, "duration", time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
    // 根据namespace和name获取对应的ReplicaSet对象，如果对象已经被删除则返回
	rs, err := rsc.rsLister.ReplicaSets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		klog.FromContext(ctx).V(4).Info("deleted", "kind", rsc.Kind, "key", key)
		rsc.expectations.DeleteExpectations(key)
		return nil
	}
	if err != nil {
		return err
	}
    
	// 检查是否需要同步ReplicaSet
	rsNeedsSync := rsc.expectations.SatisfiedExpectations(key)
    // // 将ReplicaSet的selector转化为Selector对象
	selector, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error converting pod selector to selector for rs %v/%v: %v", namespace, name, err))
		return nil
	}

	// 列出namespace下的所有Pod，包括不再匹配rs的selector的Pod
	allPods, err := rsc.podLister.Pods(rs.Namespace).List(labels.Everything())
	if err != nil {
		return err
	}
	// 过滤出所有活跃的Pod
	filteredPods := controller.FilterActivePods(allPods)

	// 声明并创建属于该ReplicaSet的Pod
	filteredPods, err = rsc.claimPods(ctx, rs, selector, filteredPods)
	if err != nil {
		return err
	}

	var manageReplicasErr error
    // 如果需要同步ReplicaSet，并且ReplicaSet没有被删除，则开始管理Pod副本
	if rsNeedsSync && rs.DeletionTimestamp == nil {
		manageReplicasErr = rsc.manageReplicas(ctx, filteredPods, rs)
	}
    // 计算新的ReplicaSet状态
	rs = rs.DeepCopy()
	newStatus := calculateStatus(rs, filteredPods, manageReplicasErr)

	// 更新ReplicaSet的状态
	updatedRS, err := updateReplicaSetStatus(klog.FromContext(ctx), rsc.kubeClient.AppsV1().ReplicaSets(rs.Namespace), rs, newStatus)
	if err != nil {
		// 更新状态可能会失败，多种原因都有可能，直接返回错误并重试
		return err
	}
	// 作为一种最后的安全保护机制，如果ReplicaSet有MinReadySeconds，并且其ReadyReplicas等于Replicas且AvailableReplicas不等于Replicas，则在MinReadySeconds之后重新同步该ReplicaSet
	if manageReplicasErr == nil && updatedRS.Spec.MinReadySeconds > 0 &&
		updatedRS.Status.ReadyReplicas == *(updatedRS.Spec.Replicas) &&
		updatedRS.Status.AvailableReplicas != *(updatedRS.Spec.Replicas) {
		rsc.queue.AddAfter(key, time.Duration(updatedRS.Spec.MinReadySeconds)*time.Second)
	}
	return manageReplicasErr
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

func IsPodActive(p *v1.Pod) bool {
	return v1.PodSucceeded != p.Status.Phase &&
		v1.PodFailed != p.Status.Phase &&
		p.DeletionTimestamp == nil
}
```

#### claimPods

```GO
func (rsc *ReplicaSetController) claimPods(ctx context.Context, rs *apps.ReplicaSet, selector labels.Selector, filteredPods []*v1.Pod) ([]*v1.Pod, error) {
	// 该函数在对一个被删除的资源进行操作时，会等待一段时间后重新读取该资源以确保它已被删除，避免在资源已被删除时误认为资源仍然存在而导致的不必要错误。
	canAdoptFunc := controller.RecheckDeletionTimestamp(func(ctx context.Context) (metav1.Object, error) {
		fresh, err := rsc.kubeClient.AppsV1().ReplicaSets(rs.Namespace).Get(ctx, rs.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != rs.UID {
			return nil, fmt.Errorf("original %v %v/%v is gone: got uid %v, wanted %v", rsc.Kind, rs.Namespace, rs.Name, fresh.UID, rs.UID)
		}
		return fresh, nil
	})
	cm := controller.NewPodControllerRefManager(rsc.podControl, rs, selector, rsc.GroupVersionKind, canAdoptFunc)
	return cm.ClaimPods(ctx, filteredPods)
}
```

#### manageReplicas

```GO
// 根据过滤后的Pod列表和 ReplicaSet 的期望副本数来调整 Pod 的数量，使其达到期望副本数。
// 如果缺少 Pod，它会尝试通过创建新的 Pod 来调整数量；如果有太多的 Pod，它会尝试删除一些 Pod 来调整数量。
func (rsc *ReplicaSetController) manageReplicas(ctx context.Context, filteredPods []*v1.Pod, rs *apps.ReplicaSet) error {
    // 计算差
	diff := len(filteredPods) - int(*(rs.Spec.Replicas))
	rsKey, err := controller.KeyFunc(rs)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for %v %#v: %v", rsc.Kind, rs, err))
		return nil
	}
	if diff < 0 {
        // 如果diff小于0，意味着副本数目不足，需要创建一些Pod。
        // 取 diff 的绝对值，即需要创建的 Pod 数量
		diff *= -1
		if diff > rsc.burstReplicas {
            // 如果需要创建的 Pod 数量超过了 burstReplicas（突发创建的 Pod 的最大数量）
			diff = rsc.burstReplicas
		}
		// 记录预期创建的 Pod 的数量
		rsc.expectations.ExpectCreations(rsKey, diff)
		klog.FromContext(ctx).V(2).Info("Too few replicas", "replicaSet", klog.KObj(rs), "need", *(rs.Spec.Replicas), "creating", diff)
		// 批量创建 Pod。batch sizes 从 SlowStartInitialBatchSize 开始，每次成功迭代会翻倍，实现一种“慢启动”的方式。
		// 这种方法可以处理尝试启动大量 Pod 的情况，这些 Pod 很可能会出现相同的错误，因此这些创建请求在一次失败后就不会被发送。
		successfulCreations, err := slowStartBatch(diff, controller.SlowStartInitialBatchSize, func() error {
            // 调用 podControl 创建 Pod
			err := rsc.podControl.CreatePods(ctx, rs.Namespace, &rs.Spec.Template, rs, metav1.NewControllerRef(rs, rsc.GroupVersionKind))
			if err != nil {
                // 如果出现了 NamespaceTerminatingCause 的错误，不需要做任何操作，因为创建会失败
				if apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
					return nil
				}
			}
			return err
		})

		// 如果有 Pod 没有被创建，那么就需要将期望的数量减少
		if skippedPods := diff - successfulCreations; skippedPods > 0 {
			klog.FromContext(ctx).V(2).Info("Slow-start failure. Skipping creation of pods, decrementing expectations", "podsSkipped", skippedPods, "kind", rsc.Kind, "replicaSet", klog.KObj(rs))
			for i := 0; i < skippedPods; i++ {
				// 将期望创建的数量减少
				rsc.expectations.CreationObserved(rsKey)
			}
		}
		return err
	} else if diff > 0 {
        // 如果需要删除的 Pod 数量大于 0
		if diff > rsc.burstReplicas {
            // 如果需要删除的 Pod 数量超过了 burstReplicas（突发删除的 Pod 的最大数量）
			diff = rsc.burstReplicas
		}
		klog.FromContext(ctx).V(2).Info("Too many replicas", "replicaSet", klog.KObj(rs), "need", *(rs.Spec.Replicas), "deleting", diff)
		
        // 获取与该 ReplicaSet 间接关联的 Pod，即有相同控制器（controller）的 Pod
		relatedPods, err := rsc.getIndirectlyRelatedPods(klog.FromContext(ctx), rs)
		utilruntime.HandleError(err)

		// 选择要删除的 Pod，优先选择启动早期的 Pod
		podsToDelete := getPodsToDelete(filteredPods, relatedPods, diff)

		// 记录期望删除的 Pod 的 UID
		rsc.expectations.ExpectDeletions(rsKey, getPodKeys(podsToDelete))

		errCh := make(chan error, diff)
		var wg sync.WaitGroup
		wg.Add(diff)
		for _, pod := range podsToDelete {
			go func(targetPod *v1.Pod) {
				defer wg.Done()
				if err := rsc.podControl.DeletePod(ctx, rs.Namespace, targetPod.Name, rs); err != nil {
					// 如果删除失败，将期望的数量减少
					podKey := controller.PodKey(targetPod)
					rsc.expectations.DeletionObserved(rsKey, podKey)
					if !apierrors.IsNotFound(err) {
						klog.FromContext(ctx).V(2).Info("Failed to delete pod, decremented expectations", "pod", podKey, "kind", rsc.Kind, "replicaSet", klog.KObj(rs))
						errCh <- err
					}
				}
			}(pod)
		}
		wg.Wait()

		select {
		case err := <-errCh:
			// 所有的错误已经在之前被报告了，因此我们只需要返回第一个错误
			if err != nil {
				return err
			}
		default:
		}
	}

	return nil
}

```

##### slowStartBatch

```go
func slowStartBatch(count int, initialBatchSize int, fn func() error) (int, error) {
	// 记录剩余的待创建/删除的 Pod 数量
	remaining := count
	// 记录成功创建/删除的 Pod 的数量
	successes := 0
	// batchSize 从 initialBatchSize 开始，每次成功迭代会翻倍，直到所有 Pod 都被创建/删除完成
	for batchSize := integer.IntMin(remaining, initialBatchSize); batchSize > 0; batchSize = integer.IntMin(2*batchSize, remaining) {
		// 使用 errCh 记录创建/删除 Pod 的错误
		errCh := make(chan error, batchSize)
		var wg sync.WaitGroup
		wg.Add(batchSize)
		// 开始并行创建/删除 batchSize 个 Pod
		for i := 0; i < batchSize; i++ {
			go func() {
				defer wg.Done()
				if err := fn(); err != nil {
					// 如果创建/删除失败，将错误记录到 errCh
					errCh <- err
				}
			}()
		}
		wg.Wait()
		// 统计成功创建/删除的 Pod 的数量
		curSuccesses := batchSize - len(errCh)
		successes += curSuccesses
		if len(errCh) > 0 {
			// 如果有创建/删除 Pod 失败，返回成功创建/删除的 Pod 的数量和第一个错误
			return successes, <-errCh
		}
		// 更新剩余的待创建/删除的 Pod 的数量
		remaining -= batchSize
	}
	// 返回成功创建/删除的 Pod 的数量和 nil
	return successes, nil
}
```

##### getPodsToDelete

```go
func getPodsToDelete(filteredPods, relatedPods []*v1.Pod, diff int) []*v1.Pod {
	if diff < len(filteredPods) {
		// 如果需要删除的 Pod 的数量小于所有与该 ReplicaSet 间接关联的 Pod 的数量
		// 那么就按照与该 ReplicaSet 有相同 Node 的 Pod 的数量进行排序，优先删除在早期启动的 Pod
		podsWithRanks := getPodsRankedByRelatedPodsOnSameNode(filteredPods, relatedPods)
		sort.Sort(podsWithRanks)
		// 输出日志
		reportSortingDeletionAgeRatioMetric(filteredPods, diff)
	}
	// 返回需要删除的 Pod
	return filteredPods[:diff]
}

func getPodsRankedByRelatedPodsOnSameNode(podsToRank, relatedPods []*v1.Pod) controller.ActivePodsWithRanks {
	// 记录与该 ReplicaSet 有相同 Node 的 Pod 的数量
	podsOnNode := make(map[string]int)
	for _, pod := range relatedPods {
		if controller.IsPodActive(pod) {
			podsOnNode[pod.Spec.NodeName]++
		}
	}
	// 记录每个 Pod 在与该 ReplicaSet 有相同 Node 的 Pod 的数量中的排名
	ranks := make([]int, len(podsToRank))
	for i, pod := range podsToRank {
		ranks[i] = podsOnNode[pod.Spec.NodeName]
	}
	// 返回排序后的 Pod
	return controller.ActivePodsWithRanks{Pods: podsToRank, Rank: ranks, Now: metav1.Now()}
}

func reportSortingDeletionAgeRatioMetric(filteredPods []*v1.Pod, diff int) {
	// 获取当前时间
	now := time.Now()
	youngestTime := time.Time{}
	// 遍历所有已经准备就绪的 Pod，找出最年轻的 Pod 的创建时间
	for _, pod := range filteredPods {
		if pod.CreationTimestamp.Time.After(youngestTime) && podutil.IsPodReady(pod) {
			youngestTime = pod.CreationTimestamp.Time
		}
	}

	// 对于每个被选择删除的 Pod，报告其年龄与最年轻 Pod 年龄之比的指标
	for _, pod := range filteredPods[:diff] {
		if !podutil.IsPodReady(pod) {
			continue
		}
		ratio := float64(now.Sub(pod.CreationTimestamp.Time).Milliseconds() / now.Sub(youngestTime).Milliseconds())
		metrics.SortingDeletionAgeRatio.Observe(ratio)
	}
}
```

#### calculateStatus

```go
func calculateStatus(rs *apps.ReplicaSet, filteredPods []*v1.Pod, manageReplicasErr error) apps.ReplicaSetStatus {
	newStatus := rs.Status
	// Count the number of pods that have labels matching the labels of the pod
	// template of the replica set, the matching pods may have more
	// labels than are in the template. Because the label of podTemplateSpec is
	// a superset of the selector of the replica set, so the possible
	// matching pods must be part of the filteredPods.
	fullyLabeledReplicasCount := 0
	readyReplicasCount := 0
	availableReplicasCount := 0
	templateLabel := labels.Set(rs.Spec.Template.Labels).AsSelectorPreValidated()
	for _, pod := range filteredPods {
		if templateLabel.Matches(labels.Set(pod.Labels)) {
			fullyLabeledReplicasCount++
		}
		if podutil.IsPodReady(pod) {
			readyReplicasCount++
			if podutil.IsPodAvailable(pod, rs.Spec.MinReadySeconds, metav1.Now()) {
				availableReplicasCount++
			}
		}
	}

	failureCond := GetCondition(rs.Status, apps.ReplicaSetReplicaFailure)
	if manageReplicasErr != nil && failureCond == nil {
		var reason string
		if diff := len(filteredPods) - int(*(rs.Spec.Replicas)); diff < 0 {
			reason = "FailedCreate"
		} else if diff > 0 {
			reason = "FailedDelete"
		}
		cond := NewReplicaSetCondition(apps.ReplicaSetReplicaFailure, v1.ConditionTrue, reason, manageReplicasErr.Error())
		SetCondition(&newStatus, cond)
	} else if manageReplicasErr == nil && failureCond != nil {
		RemoveCondition(&newStatus, apps.ReplicaSetReplicaFailure)
	}

	newStatus.Replicas = int32(len(filteredPods))
	newStatus.FullyLabeledReplicas = int32(fullyLabeledReplicasCount)
	newStatus.ReadyReplicas = int32(readyReplicasCount)
	newStatus.AvailableReplicas = int32(availableReplicasCount)
	return newStatus
}
```

##### GetCondition

```go
func GetCondition(status apps.ReplicaSetStatus, condType apps.ReplicaSetConditionType) *apps.ReplicaSetCondition {
	for _, c := range status.Conditions {
		if c.Type == condType {
			return &c
		}
	}
	return nil
}
```

##### NewReplicaSetCondition

```go
func NewReplicaSetCondition(condType apps.ReplicaSetConditionType, status v1.ConditionStatus, reason, msg string) apps.ReplicaSetCondition {
	return apps.ReplicaSetCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            msg,
	}
}
```

##### SetCondition

```go
func SetCondition(status *apps.ReplicaSetStatus, condition apps.ReplicaSetCondition) {
	currentCond := GetCondition(*status, condition.Type)
	if currentCond != nil && currentCond.Status == condition.Status && currentCond.Reason == condition.Reason {
		return
	}
	newConditions := filterOutCondition(status.Conditions, condition.Type)
	status.Conditions = append(newConditions, condition)
}
```

##### RemoveCondition

```go
func RemoveCondition(status *apps.ReplicaSetStatus, condType apps.ReplicaSetConditionType) {
	status.Conditions = filterOutCondition(status.Conditions, condType)
}

func filterOutCondition(conditions []apps.ReplicaSetCondition, condType apps.ReplicaSetConditionType) []apps.ReplicaSetCondition {
	var newConditions []apps.ReplicaSetCondition
	for _, c := range conditions {
		if c.Type == condType {
			continue
		}
		newConditions = append(newConditions, c)
	}
	return newConditions
}

```

#### updateReplicaSetStatus

```go
func updateReplicaSetStatus(logger klog.Logger, c appsclient.ReplicaSetInterface, rs *apps.ReplicaSet, newStatus apps.ReplicaSetStatus) (*apps.ReplicaSet, error) {
    // 如果ReplicaSet没有任何预期，则处于稳定状态，因为每30秒我们都会进行周期性的重新列举。
    // 如果代数不同但副本数相同，则调用者可能已将大小调整为相同的副本计数。
    if rs.Status.Replicas == newStatus.Replicas &&	// 当前副本数等于期望副本数
        rs.Status.FullyLabeledReplicas == newStatus.FullyLabeledReplicas &&	// 当前完全标记的副本数等于期望完全标记的副本数
        rs.Status.ReadyReplicas == newStatus.ReadyReplicas &&	// 当前可用的副本数等于期望可用的副本数
        rs.Status.AvailableReplicas == newStatus.AvailableReplicas &&	// 当前可用的副本数等于期望可用的副本数
        rs.Generation == rs.Status.ObservedGeneration &&	// 当前代数等于观察到的代数
        reflect.DeepEqual(rs.Status.Conditions, newStatus.Conditions) {	// 当前状态的所有条件等于期望状态的所有条件
        return rs, nil
    }

    // 保存我们所作用的代数号，否则我们可能会错误地表明我们已经看到了一个规范更新，当我们重试时。
    // TODO：如果我们允许多个代理程序写入同一个状态，则可能会覆盖更新。
    newStatus.ObservedGeneration = rs.Generation

    var getErr, updateErr error
    var updatedRS *apps.ReplicaSet
    for i, rs := 0, rs; ; i++ {
        logger.V(4).Info(fmt.Sprintf("Updating status for %v: %s/%s, ", rs.Kind, rs.Namespace, rs.Name) +
            fmt.Sprintf("replicas %d->%d (need %d), ", rs.Status.Replicas, newStatus.Replicas, *(rs.Spec.Replicas)) +
            fmt.Sprintf("fullyLabeledReplicas %d->%d, ", rs.Status.FullyLabeledReplicas, newStatus.FullyLabeledReplicas) +
            fmt.Sprintf("readyReplicas %d->%d, ", rs.Status.ReadyReplicas, newStatus.ReadyReplicas) +
            fmt.Sprintf("availableReplicas %d->%d, ", rs.Status.AvailableReplicas, newStatus.AvailableReplicas) +
		fmt.Sprintf("sequence No: %v->%v", rs.Status.ObservedGeneration, newStatus.ObservedGeneration))

	rs.Status = newStatus	// 更新ReplicaSet的状态
	updatedRS, updateErr = c.UpdateStatus(context.TODO(), rs, metav1.UpdateOptions{})
	if updateErr == nil {
		return updatedRS, nil
	}
	// 如果我们超过statusUpdateRetries次数，则停止重试 - ReplicaSet将重新排队并限速。
	if i >= statusUpdateRetries {
		break
	}
	// 使用最新的资源版本更新ReplicaSet以进行下一次轮询
	if rs, getErr = c.Get(context.TODO(), rs.Name, metav1.GetOptions{}); getErr != nil {
			return nil, getErr
		}
	}

	return nil, updateErr
}
```

## PodControllerRefManager

```GO
type PodControllerRefManager struct {
	BaseControllerRefManager
	controllerKind schema.GroupVersionKind
    // 控制 Pod 的接口
	podControl     PodControlInterface
	finalizers     []string
}

func NewPodControllerRefManager(
	podControl PodControlInterface,
	controller metav1.Object,
	selector labels.Selector,
	controllerKind schema.GroupVersionKind,
	canAdopt func(ctx context.Context) error,
	finalizers ...string,
) *PodControllerRefManager {
	return &PodControllerRefManager{
		BaseControllerRefManager: BaseControllerRefManager{
			Controller:   controller,
			Selector:     selector,
			CanAdoptFunc: canAdopt,
		},
		controllerKind: controllerKind,
		podControl:     podControl,
		finalizers:     finalizers,
	}
}

```

### ClaimPods

```GO
func (m *PodControllerRefManager) ClaimPods(ctx context.Context, pods []*v1.Pod, filters ...func(*v1.Pod) bool) ([]*v1.Pod, error) {
    // 定义 claimed 和 errlist 两个变量 存储pod和err
	var claimed []*v1.Pod
	var errlist []error
	// 定义 match 函数，用于判断 Pod 是否符合条件
	match := func(obj metav1.Object) bool {
		pod := obj.(*v1.Pod)
		// 先检查选择器，以便筛选出可能匹配的 Pod，从而仅在可能匹配的 Pod 上运行过滤器
		if !m.Selector.Matches(labels.Set(pod.Labels)) {
			return false
		}
        // 遍历所有过滤器，如果有一个不符合条件则返回 false，否则返回 true
		for _, filter := range filters {
			if !filter(pod) {
				return false
			}
		}
		return true
	}
    // 定义 adopt 和 release 函数，用于将 Pod 的控制器引用设置为 m
	adopt := func(ctx context.Context, obj metav1.Object) error {
		return m.AdoptPod(ctx, obj.(*v1.Pod))
	}
	release := func(ctx context.Context, obj metav1.Object) error {
		return m.ReleasePod(ctx, obj.(*v1.Pod))
	}
    // 遍历所有 Pod，调用 ClaimObject 函数，将符合条件的 Pod 的控制器引用设置为 m
	for _, pod := range pods {
		ok, err := m.ClaimObject(ctx, pod, match, adopt, release)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}
		if ok {
			claimed = append(claimed, pod)
		}
	}
    // 返回 claimed 和 errlist，errlist 使用 NewAggregate 函数将所有错误信息合并成一个错误
	return claimed, utilerrors.NewAggregate(errlist)
}

```

### AdoptPod

```go
func (m *PodControllerRefManager) AdoptPod(ctx context.Context, pod *v1.Pod) error {
    // 检查是否能够接管该 Pod
	if err := m.CanAdopt(ctx); err != nil {
		return fmt.Errorf("can't adopt Pod %v/%v (%v): %v", pod.Namespace, pod.Name, pod.UID, err)
	}
	
	// 构建控制器引用的补丁
	patchBytes, err := ownerRefControllerPatch(m.Controller, m.controllerKind, pod.UID, m.finalizers...)
	if err != nil {
		return err
	}
    // 使用 podControl 客户端更新 Pod 的控制器引用
	return m.podControl.PatchPod(ctx, pod.Namespace, pod.Name, patchBytes)
}
```

#### ownerRefControllerPatch

```go
type objectForAddOwnerRefPatch struct {
	Metadata objectMetaForPatch `json:"metadata"`
}

type objectMetaForPatch struct {
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences"`
	UID             types.UID               `json:"uid"`
	Finalizers      []string                `json:"finalizers,omitempty"`
}

func ownerRefControllerPatch(controller metav1.Object, controllerKind schema.GroupVersionKind, uid types.UID, finalizers ...string) ([]byte, error) {
	blockOwnerDeletion := true
	isController := true
	addControllerPatch := objectForAddOwnerRefPatch{
		Metadata: objectMetaForPatch{
			UID: uid,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         controllerKind.GroupVersion().String(),
					Kind:               controllerKind.Kind,
					Name:               controller.GetName(),
					UID:                controller.GetUID(),
					Controller:         &isController,
					BlockOwnerDeletion: &blockOwnerDeletion,
				},
			},
			Finalizers: finalizers,
		},
	}
	patchBytes, err := json.Marshal(&addControllerPatch)
	if err != nil {
		return nil, err
	}
	return patchBytes, nil
}
```

### ReleasePod

```go
func (m *PodControllerRefManager) ReleasePod(ctx context.Context, pod *v1.Pod) error {
	klog.V(2).Infof("patching pod %s_%s to remove its controllerRef to %s/%s:%s",
		pod.Namespace, pod.Name, m.controllerKind.GroupVersion(), m.controllerKind.Kind, m.Controller.GetName())
	patchBytes, err := GenerateDeleteOwnerRefStrategicMergeBytes(pod.UID, []types.UID{m.Controller.GetUID()}, m.finalizers...)
	if err != nil {
		return err
	}
    // 使用 podControl 客户端更新 Pod，删除其控制器引用
	err = m.podControl.PatchPod(ctx, pod.Namespace, pod.Name, patchBytes)
	if err != nil {
		if errors.IsNotFound(err) {
			// 如果 Pod 已经不存在，则忽略错误
			return nil
		}
		if errors.IsInvalid(err) {
			// 如果错误是 "invalid" 类型，则忽略错误，因为此错误有两种情况：
			// 1. Pod 没有 OwnerReference；
			// 2. Pod 的 UID 不匹配，这意味着 Pod 被删除后重新创建。
			return nil
		}
	}
	return err
}
```

#### GenerateDeleteOwnerRefStrategicMergeBytes

```go
	Metadata objectMetaForMergePatch `json:"metadata"`
}

type objectMetaForMergePatch struct {
	UID              types.UID           `json:"uid"`
	OwnerReferences  []map[string]string `json:"ownerReferences"`
	DeleteFinalizers []string            `json:"$deleteFromPrimitiveList/finalizers,omitempty"`
}

func GenerateDeleteOwnerRefStrategicMergeBytes(dependentUID types.UID, ownerUIDs []types.UID, finalizers ...string) ([]byte, error) {
	var ownerReferences []map[string]string
	for _, ownerUID := range ownerUIDs {
		ownerReferences = append(ownerReferences, ownerReference(ownerUID, "delete"))
	}
	patch := objectForDeleteOwnerRefStrategicMergePatch{
		Metadata: objectMetaForMergePatch{
			UID:              dependentUID,
			OwnerReferences:  ownerReferences,
			DeleteFinalizers: finalizers,
		},
	}
	patchBytes, err := json.Marshal(&patch)
	if err != nil {
		return nil, err
	}
	return patchBytes, nil
}
```

### BaseControllerRefManager

```GO
type BaseControllerRefManager struct {
    // 控制器对象
	Controller metav1.Object
    // 选择器，用于选择控制器对象的子集。
	Selector   labels.Selector
	
    // 尝试采用控制器时发生的错误
	canAdoptErr  error
	canAdoptOnce sync.Once
    // 控制器对象可以被采用时应该执行的函数
	CanAdoptFunc func(ctx context.Context) error
}

func (m *BaseControllerRefManager) CanAdopt(ctx context.Context) error {
	m.canAdoptOnce.Do(func() {
		if m.CanAdoptFunc != nil {
			m.canAdoptErr = m.CanAdoptFunc(ctx)
		}
	})
	return m.canAdoptErr
}

func (m *BaseControllerRefManager) ClaimObject(ctx context.Context, obj metav1.Object, match func(metav1.Object) bool, adopt, release func(context.Context, metav1.Object) error) (bool, error) {
    //获取对象的控制器引用
	controllerRef := metav1.GetControllerOfNoCopy(obj)
	if controllerRef != nil {
     	// 如果有引用 判断是不是这个的
		if controllerRef.UID != m.Controller.GetUID() {
			return false, nil
		}
        // 匹配
		if match(obj) {
			return true, nil
		}
        // 如果该对象被删除了 不处理
		if m.Controller.GetDeletionTimestamp() != nil {
			return false, nil
		}
        // 和本对象不匹配 释放他
		if err := release(ctx, obj); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return false, nil
	}

	// 符合选择器条件
	if m.Controller.GetDeletionTimestamp() != nil || !match(obj) {
		return false, nil
	}
	if obj.GetDeletionTimestamp() != nil {
        // 该对象被删除了
		return false, nil
	}

	if len(m.Controller.GetNamespace()) > 0 && m.Controller.GetNamespace() != obj.GetNamespace() {
		// namespace不匹配
		return false, nil
	}

	// 绑定
	if err := adopt(ctx, obj); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	// Successfully adopted.
	return true, nil
}
```

## UIDTrackingControllerExpectations

### struct

```go
type UIDTrackingControllerExpectations struct {
	ControllerExpectationsInterface
	uidStoreLock sync.Mutex
	uidStore cache.Store
}
```

### 方法

```go
// GetUIDs 返回给定控制器的 UID 集合。
func (u *UIDTrackingControllerExpectations) GetUIDs(controllerKey string) sets.String {
	if uid, exists, err := u.uidStore.GetByKey(controllerKey); err == nil && exists {
		return uid.(*UIDSet).String
	}
	return nil
}

// ExpectDeletions 记录针对给定控制器和删除键的期望删除。
func (u *UIDTrackingControllerExpectations) ExpectDeletions(rcKey string, deletedKeys []string) error {
	expectedUIDs := sets.NewString()
	for _, k := range deletedKeys {
		expectedUIDs.Insert(k)
	}
	klog.V(4).Infof("Controller %v waiting on deletions for: %+v", rcKey, deletedKeys)
    // 获取锁，更新 UID 集合
	u.uidStoreLock.Lock()
	defer u.uidStoreLock.Unlock()

	if existing := u.GetUIDs(rcKey); existing != nil && existing.Len() != 0 {
		klog.Errorf("Clobbering existing delete keys: %+v", existing)
	}
	if err := u.uidStore.Add(&UIDSet{expectedUIDs, rcKey}); err != nil {
		return err
	}
    // 更新期望的删除计数
	return u.ControllerExpectationsInterface.ExpectDeletions(rcKey, expectedUIDs.Len())
}

// DeletionObserved 记录给定控制器的给定删除键已被删除。
func (u *UIDTrackingControllerExpectations) DeletionObserved(rcKey, deleteKey string) {
    // 获取锁，更新 UID 集合
	u.uidStoreLock.Lock()
	defer u.uidStoreLock.Unlock()

	uids := u.GetUIDs(rcKey)
	if uids != nil && uids.Has(deleteKey) {
		klog.V(4).Infof("Controller %v received delete for pod %v", rcKey, deleteKey)
        // 更新删除计数并从 UID 集合中删除该 UID
		u.ControllerExpectationsInterface.DeletionObserved(rcKey)
		uids.Delete(deleteKey)
	}
}

// DeleteExpectations 删除 UID 集并调用底层 ControllerExpectationsInterface 上的 DeleteExpectations。
func (u *UIDTrackingControllerExpectations) DeleteExpectations(rcKey string) {
	u.uidStoreLock.Lock()
	defer u.uidStoreLock.Unlock()

	u.ControllerExpectationsInterface.DeleteExpectations(rcKey)
	if uidExp, exists, err := u.uidStore.GetByKey(rcKey); err == nil && exists {
		if err := u.uidStore.Delete(uidExp); err != nil {
			klog.V(2).Infof("Error deleting uid expectations for controller %v: %v", rcKey, err)
		}
	}
}

type UIDSet struct {
	sets.String
	key string
}
```

## ControllerExpectationsInterface

```go
type ControllerExpectationsInterface interface {
    // GetExpectations 返回与给定控制器键关联的 ControlleeExpectations 和一个布尔值，指示是否找到了此键的预期。
	GetExpectations(controllerKey string) (*ControlleeExpectations, bool, error)
	// SatisfiedExpectations 检查是否已满足与给定控制器键关联的预期。
    SatisfiedExpectations(controllerKey string) bool
    // DeleteExpectations 删除与给定控制器键关联的预期。
    DeleteExpectations(controllerKey string)
    // SetExpectations 设置与给定控制器键关联的预期，包括添加和删除计数。
    SetExpectations(controllerKey string, add, del int) error
    // ExpectCreations 增加与给定控制器键关联的添加计数。
    ExpectCreations(controllerKey string, adds int) error
    // ExpectDeletions 增加与给定控制器键关联的删除计数。
    ExpectDeletions(controllerKey string, dels int) error
    // CreationObserved 表示与给定控制器键关联的对象已创建。
    CreationObserved(controllerKey string)
    // DeletionObserved 表示与给定控制器键关联的对象已删除。
    DeletionObserved(controllerKey string)
    // RaiseExpectations 增加与给定控制器键关联的添加和删除计数。
    RaiseExpectations(controllerKey string, add, del int)
    // LowerExpectations 减少与给定控制器键关联的添加和删除计数。
    LowerExpectations(controllerKey string, add, del int)
}
```

### 结构体实现

```GO
type ControllerExpectations struct {
	cache.Store
}
```

### 方法

```GO
func (r *ControllerExpectations) GetExpectations(controllerKey string) (*ControlleeExpectations, bool, error) {
    // 通过 controllerKey 获取 ControlleeExpectations
    exp, exists, err := r.GetByKey(controllerKey)
    if err == nil && exists {
    	return exp.(*ControlleeExpectations), true, nil
    }
    return nil, false, err
}

func (r *ControllerExpectations) DeleteExpectations(controllerKey string) {
   	//通过 controllerKey 获取 ControlleeExpectations，并从 TTLStore 中删除
	if exp, exists, err := r.GetByKey(controllerKey); err == nil && exists {
		if err := r.Delete(exp); err != nil {
			klog.V(2).Infof("Error deleting expectations for controller %v: %v", controllerKey, err)
		}
	}
}

func (r *ControllerExpectations) SatisfiedExpectations(controllerKey string) bool {
	if exp, exists, err := r.GetExpectations(controllerKey); exists {
		if exp.Fulfilled() {
            //  如果已经满足期望，则返回 true
			klog.V(4).Infof("Controller expectations fulfilled %#v", exp)
			return true
		} else if exp.isExpired() {
            // 如果期望已过期，则返回 true
			klog.V(4).Infof("Controller expectations expired %#v", exp)
			return true
		} else {
            // 如果还未满足期望，则返回 false
			klog.V(4).Infof("Controller still waiting on expectations %#v", exp)
			return false
		}
	} else if err != nil {
		klog.V(2).Infof("Error encountered while checking expectations %#v, forcing sync", err)
	} else {
		// 当创建新控制器时，它没有期望。
        // 当它未看到预期的观察事件 > TTL 时，期望会过期。
        // - 在这种情况下，它会唤醒，创建/删除控制lee，并再次设置期望。
        // 当它满足了期望并且没有需要创建/销毁的控制lee > TTL 时，期望过期。
        // - 在这种情况下，它会继续而不设置期望，直到需要创建/删除控制lee。
		klog.V(4).Infof("Controller %v either never recorded expectations, or the ttl expired.", controllerKey)
	}
	// 如果遇到错误（这不应该发生，因为我们从本地存储获取）或此控制器尚未建立期望，则触发同步。
	return true
}

func (r *ControllerExpectations) SetExpectations(controllerKey string, add, del int) error {
    // 创建 ControlleeExpectations 结构体，包含给定的 add 和 del 计数
	exp := &ControlleeExpectations{add: int64(add), del: int64(del), key: controllerKey, timestamp: clock.RealClock{}.Now()}
	klog.V(4).Infof("Setting expectations %#v", exp)
    // 将 ControlleeExpectations 添加到 TTLStore 中
	return r.Add(exp)
}

func (r *ControllerExpectations) ExpectCreations(controllerKey string, adds int) error {
	return r.SetExpectations(controllerKey, adds, 0)
}

func (r *ControllerExpectations) ExpectDeletions(controllerKey string, dels int) error {
	return r.SetExpectations(controllerKey, 0, dels)
}

func (r *ControllerExpectations) LowerExpectations(controllerKey string, add, del int) {
	if exp, exists, err := r.GetExpectations(controllerKey); err == nil && exists {
		exp.Add(int64(-add), int64(-del))
		klog.V(4).Infof("Lowered expectations %#v", exp)
	}
}

func (r *ControllerExpectations) RaiseExpectations(controllerKey string, add, del int) {
	if exp, exists, err := r.GetExpectations(controllerKey); err == nil && exists {
		exp.Add(int64(add), int64(del))
		klog.V(4).Infof("Raised expectations %#v", exp)
	}
}

func (r *ControllerExpectations) CreationObserved(controllerKey string) {
	r.LowerExpectations(controllerKey, 1, 0)
}

func (r *ControllerExpectations) DeletionObserved(controllerKey string) {
	r.LowerExpectations(controllerKey, 0, 1)
}

type ControlleeExpectations struct {
	add       int64
	del       int64
	key       string
	timestamp time.Time
}

func (exp *ControlleeExpectations) isExpired() bool {
	return clock.RealClock{}.Since(exp.timestamp) > ExpectationsTimeout
}

func (e *ControlleeExpectations) Add(add, del int64) {
	atomic.AddInt64(&e.add, add)
	atomic.AddInt64(&e.del, del)
}

func (e *ControlleeExpectations) Fulfilled() bool {
	return atomic.LoadInt64(&e.add) <= 0 && atomic.LoadInt64(&e.del) <= 0
}

func (e *ControlleeExpectations) GetExpectations() (int64, int64) {
	return atomic.LoadInt64(&e.add), atomic.LoadInt64(&e.del)
}
```



