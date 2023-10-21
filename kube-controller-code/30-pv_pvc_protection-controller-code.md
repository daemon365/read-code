
## pv-protection-controller

### 简介

pv-protection-controller是Kubernetes的一个控制器，它的作用是保护PV（持久卷）不被误删。当一个PVC（持久卷声明）被删除时，pv-protection-controller会检查该PVC是否绑定到一个PV上。如果是，则pv-protection-controller会将该PV标记为“保护”，并防止其被删除。这样，即使PVC被误删，PV也不会被删除。

### 结构体

```GO
type Controller struct {
    // CLIENTSET
	client clientset.Interface
	// pv lister
	pvLister       corelisters.PersistentVolumeLister
	pvListerSynced cache.InformerSynced
	// 工作队列
	queue workqueue.RateLimitingInterface
}
```

### New

```GO
func NewPVProtectionController(logger klog.Logger, pvInformer coreinformers.PersistentVolumeInformer, cl clientset.Interface) *Controller {
	e := &Controller{
		client: cl,
		queue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pvprotection"),
	}

	e.pvLister = pvInformer.Lister()
	e.pvListerSynced = pvInformer.Informer().HasSynced
    // 监控pv对象的添加及更新
	pvInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.pvAddedUpdated(logger, obj)
		},
		UpdateFunc: func(old, new interface{}) {
			e.pvAddedUpdated(logger, new)
		},
	})

	return e
}
```

#### pvAddedUpdated

```go
func (c *Controller) pvAddedUpdated(logger klog.Logger, obj interface{}) {
	pv, ok := obj.(*v1.PersistentVolume)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("PV informer returned non-PV object: %#v", obj))
		return
	}
	logger.V(4).Info("Got event on PV", "PV", klog.KObj(pv))
	// 检查pv是否需要添加 PVProtectionFinalizer 这个finalizer。如果需要，将pv.Name加入到队列中。
	if protectionutil.NeedToAddFinalizer(pv, volumeutil.PVProtectionFinalizer) || protectionutil.IsDeletionCandidate(pv, volumeutil.PVProtectionFinalizer) {
        // 加入队列
		c.queue.Add(pv.Name)
	}
}
```

##### NeedToAddFinalizer

```GO
func NeedToAddFinalizer(obj metav1.Object, finalizer string) bool {
    // 没有别删除 并且不存在finalizer
	return obj.GetDeletionTimestamp() == nil && !slice.ContainsString(obj.GetFinalizers(),
		finalizer, nil)
}
```

##### IsDeletionCandidate

```GO
func IsDeletionCandidate(obj metav1.Object, finalizer string) bool {
    // 被删除了 并且存在finalizer
	return obj.GetDeletionTimestamp() != nil && slice.ContainsString(obj.GetFinalizers(),
		finalizer, nil)
}
```

### Run

```GO
func (c *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting PV protection controller")
	defer logger.Info("Shutting down PV protection controller")
	
    // 等待同步完成
	if !cache.WaitForNamedCacheSync("PV protection", ctx.Done(), c.pvListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

### runWorker

```GO
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem deals with one pvcKey off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	pvKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(pvKey)

	pvName := pvKey.(string)
	// 执行函数 成功了forget key 失败了重试
	err := c.processPV(ctx, pvName)
	if err == nil {
		c.queue.Forget(pvKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("PV %v failed with : %v", pvKey, err))
	c.queue.AddRateLimited(pvKey)

	return true
}
```

### processPV

```GO
func (c *Controller) processPV(ctx context.Context, pvName string) error {
	// 从传入的上下文中获取logger对象
	logger := klog.FromContext(ctx)
	// 使用logger对象记录日志，日志级别为V(4)，输出信息为"Processing PV"，包括"PV"和pvName的引用
	logger.V(4).Info("Processing PV", "PV", klog.KRef("", pvName))
	// 记录开始处理PV的时间
	startTime := time.Now()
	// 在函数返回时执行的延迟函数，用于记录处理PV结束的日志
	defer func() {
		logger.V(4).Info("Finished processing PV", "PV", klog.KRef("", pvName), "cost", time.Since(startTime))
	}()

	// 通过pvLister从缓存中获取指定名称的PV对象
	pv, err := c.pvLister.Get(pvName)
	// 如果返回的错误为apierrors.IsNotFound(err)，表示PV不存在，则记录相应的日志并返回nil
	if apierrors.IsNotFound(err) {
		logger.V(4).Info("PV not found, ignoring", "PV", klog.KRef("", pvName))
		return nil
	}
	// 如果返回的错误不为nil且不是NotFound错误，则直接返回错误
	if err != nil {
		return err
	}

	// 检查PV是否可以被删除，如果是，则进一步判断是否正在被使用
	if protectionutil.IsDeletionCandidate(pv, volumeutil.PVProtectionFinalizer) {
		// 判断PV是否正在被使用，如果不是，则调用removeFinalizer方法移除finalizer
		isUsed := c.isBeingUsed(pv)
		if !isUsed {
			return c.removeFinalizer(ctx, pv)
		}
		// 如果PV正在被使用，则记录相应的日志并保留finalizer
		logger.V(4).Info("Keeping PV because it is being used", "PV", klog.KRef("", pvName))
	}

	// 检查PV是否需要添加finalizer，如果需要，则调用addFinalizer方法添加finalizer
	if protectionutil.NeedToAddFinalizer(pv, volumeutil.PVProtectionFinalizer) {
		// PV不是正在被删除的状态，但没有finalizer，则调用addFinalizer方法添加finalizer
		return c.addFinalizer(ctx, pv)
	}
	return nil
}
```

#### isBeingUsed

```GO
func (c *Controller) isBeingUsed(pv *v1.PersistentVolume) bool {
	// 检查PV的状态是否为VolumeBound，即是否正在被绑定到PVC
	// PV的状态将由PV控制器更新
	if pv.Status.Phase == v1.VolumeBound {
		// 如果PV的状态为VolumeBound，表示PV正在被使用
		return true
	}

	// 否则，表示PV没有被使用
	return false
}
```

#### removeFinalizer

```GO
func (c *Controller) removeFinalizer(ctx context.Context, pv *v1.PersistentVolume) error {
    // 复制一个 pv 对象
    pvClone := pv.DeepCopy()
    // 从 pvClone 对象的 Finalizers 切片中移除指定的 Finalizer
    // 使用 slice.RemoveString 方法，传入待删除的 Finalizer 字符串、切片以及比较函数（这里为 nil）
    pvClone.ObjectMeta.Finalizers = slice.RemoveString(pvClone.ObjectMeta.Finalizers, volumeutil.PVProtectionFinalizer, nil)
    // 调用 client 的 Update 方法，更新 PersistentVolume 对象
    _, err := c.client.CoreV1().PersistentVolumes().Update(ctx, pvClone, metav1.UpdateOptions{})
    // 从 context 中获取 logger
    logger := klog.FromContext(ctx)
    // 如果更新失败，记录日志并返回错误
    if err != nil {
        logger.V(3).Info("Error removing protection finalizer from PV", "PV", klog.KObj(pv), "err", err)
        return err
    }
    // 记录日志，表示成功移除 Finalizer
    logger.V(3).Info("Removed protection finalizer from PV", "PV", klog.KObj(pv))
    return nil
}
```

#### addFinalizer

```GO
func (c *Controller) addFinalizer(ctx context.Context, pv *v1.PersistentVolume) error {
    // 复制一份 PersistentVolume 对象，以便对其进行更改。
    pvClone := pv.DeepCopy()
    // 在 Finalizers 字段中添加卷保护的 finalizer。
    pvClone.ObjectMeta.Finalizers = append(pvClone.ObjectMeta.Finalizers, volumeutil.PVProtectionFinalizer)
    // 更新 PersistentVolume 对象。
    _, err := c.client.CoreV1().PersistentVolumes().Update(ctx, pvClone, metav1.UpdateOptions{})
    // 从上下文中获取日志记录器。
    logger := klog.FromContext(ctx)
    if err != nil {
    // 如果更新出现错误，则记录错误日志并返回错误。
    logger.V(3).Info("Error adding protection finalizer to PV", "PV", klog.KObj(pv), "err", err)
    return err
    }
    // 记录成功添加 finalizer 的日志。
    logger.V(3).Info("Added protection finalizer to PV", "PV", klog.KObj(pv))
    // 返回 nil，表示没有出现错误。
    return nil
}
```

## pvc-protection-controller

### 简介

pvc-protection-controller是Kubernetes的一个控制器，它的作用是保护PVC（持久卷声明）不被误删。当一个PVC被删除时，pvc-protection-controller会检查该PVC是否绑定到一个PV（持久卷）上。如果是，则pvc-protection-controller会将该PV标记为“保护”，并防止其被删除。这样，即使PVC被误删，PV也不会被删除。

### 结构体

```go
type Controller struct {
	client clientset.Interface
	
    // pvc lister
	pvcLister       corelisters.PersistentVolumeClaimLister
	pvcListerSynced cache.InformerSynced
	
    // pod lister
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced
    // indexer
	podIndexer      cache.Indexer
	// 工作队列
	queue workqueue.RateLimitingInterface
}
```

### New

```GO
func NewPVCProtectionController(logger klog.Logger, pvcInformer coreinformers.PersistentVolumeClaimInformer, podInformer coreinformers.PodInformer, cl clientset.Interface) (*Controller, error) {
	e := &Controller{
		client: cl,
		queue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pvcprotection"),
	}

	e.pvcLister = pvcInformer.Lister()
	e.pvcListerSynced = pvcInformer.Informer().HasSynced
	pvcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.pvcAddedUpdated(logger, obj)
		},
		UpdateFunc: func(old, new interface{}) {
			e.pvcAddedUpdated(logger, new)
		},
	})

	e.podLister = podInformer.Lister()
	e.podListerSynced = podInformer.Informer().HasSynced
	e.podIndexer = podInformer.Informer().GetIndexer()
	if err := common.AddIndexerIfNotPresent(e.podIndexer, common.PodPVCIndex, common.PodPVCIndexFunc()); err != nil {
		return nil, fmt.Errorf("could not initialize pvc protection controller: %w", err)
	}
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.podAddedDeletedUpdated(logger, nil, obj, false)
		},
		DeleteFunc: func(obj interface{}) {
			e.podAddedDeletedUpdated(logger, nil, obj, true)
		},
		UpdateFunc: func(old, new interface{}) {
			e.podAddedDeletedUpdated(logger, old, new, false)
		},
	})

	return e, nil
}
```

#### pvcAddedUpdated

```GO
func (c *Controller) pvcAddedUpdated(logger klog.Logger, obj interface{}) {
    // 将传入的 obj 转换为 *v1.PersistentVolumeClaim 类型的对象 pvc
    pvc, ok := obj.(*v1.PersistentVolumeClaim)
    if !ok {
        // 如果转换失败，记录错误并返回
        utilruntime.HandleError(fmt.Errorf("PVC informer returned non-PVC object: %#v", obj))
        return
    }
    // 使用 cache 包中的 MetaNamespaceKeyFunc 方法获取 pvc 对象的 key
    key, err := cache.MetaNamespaceKeyFunc(pvc)
    if err != nil {
        // 如果获取 key 失败，记录错误并返回
        utilruntime.HandleError(fmt.Errorf("couldn't get key for Persistent Volume Claim %#v: %v", pvc, err))
        return
    }
    // 记录日志，表示收到了 PVC 的事件
    logger.V(4).Info("Got event on PVC", "pvc", klog.KObj(pvc))

    // 判断是否需要添加或删除 Finalizer，并根据需要将 key 加入队列
    if protectionutil.NeedToAddFinalizer(pvc, volumeutil.PVCProtectionFinalizer) || protectionutil.IsDeletionCandidate(pvc, volumeutil.PVCProtectionFinalizer) {
        c.queue.Add(key)
    }
}
```

#### podAddedDeletedUpdated

```GO
func (c *Controller) podAddedDeletedUpdated(logger klog.Logger, old, new interface{}, deleted bool) {
	// 将 new 转换为 Pod 对象
	if pod := c.parsePod(new); pod != nil {
		// 根据 Pod 对象获取相关的 PVC 对象，并将其加入队列
		c.enqueuePVCs(logger, pod, deleted)

		// 更新通知可能会掩盖 Pod X 的删除，并且随后创建一个具有相同命名空间和名称的 Pod Y。
		// 如果是这种情况，X 也需要被处理，以处理它是否阻止了未被 Y 引用的 PVC 的删除，否则这样的 PVC 将永远不会被删除。
		if oldPod := c.parsePod(old); oldPod != nil && oldPod.UID != pod.UID {
			// 根据旧的 Pod 对象获取相关的 PVC 对象，并将其加入队列
			c.enqueuePVCs(logger, oldPod, true)
		}
	}
}
```

##### parsePod

```GO
func (*Controller) parsePod(obj interface{}) *v1.Pod {
	// 检查传入的对象是否为空，如果为空则返回 nil
	if obj == nil {
		return nil
	}
	// 尝试将传入的对象转换为 Pod 对象
	pod, ok := obj.(*v1.Pod)
	if !ok {
		// 如果传入的对象不是 Pod 对象，则检查是否为 DeletedFinalStateUnknown 对象
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			// 如果不是 DeletedFinalStateUnknown 对象，则记录错误日志并返回 nil
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return nil
		}
		// 如果是 DeletedFinalStateUnknown 对象，则从 tombstone 中提取 Pod 对象
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			// 如果提取的对象不是 Pod 对象，则记录错误日志并返回 nil
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Pod %#v", obj))
			return nil
		}
	}
	// 返回转换或提取的 Pod 对象
	return pod
}
```

### Run

```go
func (c *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting PVC protection controller")
	defer logger.Info("Shutting down PVC protection controller")
	
    // 等待同步完成
	if !cache.WaitForNamedCacheSync("PVC protection", ctx.Done(), c.pvcListerSynced, c.podListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

### runWorker

```GO
func (c *Controller) runWorker(ctx context.Context) {
    // 一直循环直到返回false
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	pvcKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(pvcKey)

	pvcNamespace, pvcName, err := cache.SplitMetaNamespaceKey(pvcKey.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error parsing PVC key %q: %v", pvcKey, err))
		return true
	}

	err = c.processPVC(ctx, pvcNamespace, pvcName)
	if err == nil {
		c.queue.Forget(pvcKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("PVC %v failed with : %v", pvcKey, err))
	c.queue.AddRateLimited(pvcKey)
}
```

### processPVC

```go
func (c *Controller) processPVC(ctx context.Context, pvcNamespace, pvcName string) error {
	// 从传入的上下文中获取 logger
	logger := klog.FromContext(ctx)
	// 记录处理 PVC 开始的日志
	logger.V(4).Info("Processing PVC", "PVC", klog.KRef(pvcNamespace, pvcName))
	// 记录处理 PVC 结束的日志，包括处理时间
	startTime := time.Now()
	defer func() {
		logger.V(4).Info("Finished processing PVC", "PVC", klog.KRef(pvcNamespace, pvcName), "duration", time.Since(startTime))
	}()

	// 获取指定命名空间和 PVC 名称的 PersistentVolumeClaim 对象
	pvc, err := c.pvcLister.PersistentVolumeClaims(pvcNamespace).Get(pvcName)
	// 如果未找到指定的 PVC，则记录日志并返回 nil
	if apierrors.IsNotFound(err) {
		logger.V(4).Info("PVC not found, ignoring", "PVC", klog.KRef(pvcNamespace, pvcName))
		return nil
	}
	// 如果获取 PVC 时发生错误，则返回错误
	if err != nil {
		return err
	}

	// 检查是否需要删除 PVC，并在不被使用时移除 finalizer
	if protectionutil.IsDeletionCandidate(pvc, volumeutil.PVCProtectionFinalizer) {
		// 检查 PVC 是否正在被使用
		isUsed, err := c.isBeingUsed(ctx, pvc)
		if err != nil {
			return err
		}
		// 如果未被使用，则移除 finalizer
		if !isUsed {
			return c.removeFinalizer(ctx, pvc)
		}
		// 如果正在被使用，则记录日志并保留 finalizer
		logger.V(2).Info("Keeping PVC because it is being used", "PVC", klog.KObj(pvc))
	}

	// 检查是否需要添加 finalizer
	if protectionutil.NeedToAddFinalizer(pvc, volumeutil.PVCProtectionFinalizer) {
		// 如果 PVC 不在删除状态中，则应添加 finalizer。
		// 此处的处理是为了在启用 admission plugin 前创建的旧 PVC 添加 finalizer。
		return c.addFinalizer(ctx, pvc)
	}
	// 如果不需要处理，则返回 nil
	return nil
}
```

#### isBeingUsed

```go
func (c *Controller) isBeingUsed(ctx context.Context, pvc *v1.PersistentVolumeClaim) (bool, error) {
	// 在 Informer 的缓存中查找是否存在正在使用 pvc 的 Pod。如果找到了，则可以根据这个结果直接决定是否保留 pvc，避免进行昂贵的实时列表操作。
	logger := klog.FromContext(ctx)
	if inUse, err := c.askInformer(logger, pvc); err != nil {
		// 如果出现错误，不需要立即返回，因为随后会执行实时列表操作。
		logger.Error(err, "")
	} else if inUse {
		return true, nil
	}

	// 即使在 Informer 的缓存中没有找到正在使用 pvc 的 Pod，也不代表这样的 Pod 不存在：可能只是尚未被缓存。为了确保可以安全删除 pvc，需要通过实时列表操作确认是否有 Pod 正在使用它。
	return c.askAPIServer(ctx, pvc)
}
```

##### askInformer

```go
func (c *Controller) askInformer(logger klog.Logger, pvc *v1.PersistentVolumeClaim) (bool, error) {
// 记录在 Informer 的缓存中查找正在使用指定 PVC 的 Pod 的操作到日志
logger.V(4).Info("Looking for Pods using PVC in the Informer's cache", "PVC", klog.KObj(pvc))
    // 使用索引器（indexer）通过索引（index）查询可能使用指定 PVC 的 Pods
    objs, err := c.podIndexer.ByIndex(common.PodPVCIndex, fmt.Sprintf("%s/%s", pvc.Namespace, pvc.Name))
    if err != nil {
        // 如果查询过程中出现错误，则返回错误信息
        return false, fmt.Errorf("cache-based list of pods failed while processing %s/%s: %s", pvc.Namespace, pvc.Name, err.Error())
    }

    // 遍历查询结果中的每个对象，判断是否是 Pod 对象，并且是否使用了指定的 PVC
    for _, obj := range objs {
        pod, ok := obj.(*v1.Pod)
        if !ok {
            continue
        }

        // 对于 volume.PersistentVolumeClaim 类型的卷，我们只需要判断一次就可以了，
        // 但对于 volume.Ephemeral 类型的卷，我们需要确保这个 PVC 是为临时卷创建的。
        if c.podUsesPVC(logger, pod, pvc) {
            // 如果找到了正在使用指定 PVC 的 Pod，则返回 true，并且没有错误
            return true, nil
        }
    }

    // 如果在 Informer 的缓存中没有找到使用指定 PVC 的 Pod，则记录到日志，并返回 false，并且没有错误
    logger.V(4).Info("No Pod using PVC was found in the Informer's cache", "PVC", klog.KObj(pvc))
    return false, nil
}
```

###### podUsesPVC

```GO
func (c *Controller) podUsesPVC(logger klog.Logger, pod *v1.Pod, pvc *v1.PersistentVolumeClaim) bool {
    // 当pod被调度后，检查它是否仅使用pvc，因为kubelet在调度后才能看到pod，并且它不会允许启动引用带有非nil deletionTimestamp的PVC的pod。
    if pod.Spec.NodeName != "" { // 如果NodeName字段不为空，说明Pod已经被调度
        for _, volume := range pod.Spec.Volumes { // 遍历Pod的所有卷
            if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == pvc.Name || // 检查该卷是否属于该PVC
            !podIsShutDown(pod) && volume.Ephemeral != nil && ephemeral.VolumeClaimName(pod, &volume) == pvc.Name && ephemeral.VolumeIsForPod(pod, pvc) == nil { // 如果该卷是临时卷，则检查是否为Pod使用的临时PVC
            logger.V(2).Info("Pod uses PVC", "pod", klog.KObj(pod), "PVC", klog.KObj(pvc)) // 记录日志，表示该Pod使用该PVC
            return true
            }
        }
    }
    return false // 如果没有找到该PVC的使用，则返回false
}
```

###### podIsShutDown

```GO
// 判断一个Pod是否已经被标记为删除，并且可以被安全删除
func podIsShutDown(pod *v1.Pod) bool {
    // 一个具有 deletionTimestamp 和 deletionGracePeriodSeconds 等于 0 的Pod：
    // a) 已经被 kubelet 处理，并被设置为删除，
    //    由 apiserver 处理：
    //    - canBeDeleted 已经验证了卷是否已经取消发布
    //      https://github.com/kubernetes/kubernetes/blob/5404b5a28a2114299608bab00e4292960dd864a0/pkg/kubelet/kubelet_pods.go#L980
    //    - deletionGracePeriodSeconds 是通过设置为 0 的 GracePeriodSeconds 的删除操作设置的
    //      https://github.com/kubernetes/kubernetes/blob/5404b5a28a2114299608bab00e4292960dd864a0/pkg/kubelet/status/status_manager.go#L580-L592
    // 或者
    // b) 被强制删除
    //
    // 现在它只等待垃圾回收。我们可以等待它被实际删除，但这可能会受到 Pod 的终结器阻塞而延迟。
    //
    // 更糟糕的是，可能存在循环依赖项
    // （Pod 终结器等待 PVC 被删除，PVC 保护控制器等待 Pod 被删除）。
    // 在这种情况下，通过认为 PVC 是未使用的，我们允许 PVC 被删除并打破这样的循环。
    //
    // 因此最好继续进行 PVC 的删除，这是安全的（情况 a）和/或理想的（情况 b）。
    return pod.DeletionTimestamp != nil && pod.DeletionGracePeriodSeconds != nil && *pod.DeletionGracePeriodSeconds == 0
}
```

##### askAPIServer

```GO
func (c *Controller) askAPIServer(ctx context.Context, pvc *v1.PersistentVolumeClaim) (bool, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Looking for Pods using PVC with a live list", "PVC", klog.KObj(pvc))  // 使用持久卷声明查询Pod的日志输出

	podsList, err := c.client.CoreV1().Pods(pvc.Namespace).List(ctx, metav1.ListOptions{})  // 使用持久卷声明的命名空间查询Pod列表
	if err != nil {
		return false, fmt.Errorf("live list of pods failed: %s", err.Error())  // 查询Pod列表失败时返回错误
	}

	for _, pod := range podsList.Items {
		if c.podUsesPVC(logger, &pod, pvc) {  // 检查Pod是否使用了指定的持久卷声明
			return true, nil
		}
	}

	logger.V(2).Info("PVC is unused", "PVC", klog.KObj(pvc))  // 持久卷声明未被使用的日志输出
	return false, nil
}
```

#### removeFinalizer

```go
func (c *Controller) removeFinalizer(ctx context.Context, pvc *v1.PersistentVolumeClaim) error {
    // 使用 DeepCopy 方法创建一个 PVC 对象的克隆
    claimClone := pvc.DeepCopy()
    // 使用 slice.RemoveString 方法从克隆的 PVC 对象的 Finalizers 切片中移除指定的 finalizer
    claimClone.ObjectMeta.Finalizers = slice.RemoveString(claimClone.ObjectMeta.Finalizers, volumeutil.PVCProtectionFinalizer, nil)
    // 调用 Kubernetes 客户端的 Update 方法更新 PVC 对象
    _, err := c.client.CoreV1().PersistentVolumeClaims(claimClone.Namespace).Update(ctx, claimClone, metav1.UpdateOptions{})
    // 从 context 中获取 logger
    logger := klog.FromContext(ctx)
    // 如果更新过程中出现错误，则记录错误信息到日志并返回错误
    if err != nil {
    logger.Error(err, "Error removing protection finalizer from PVC", "PVC", klog.KObj(pvc))
    return err
    }
    // 否则，记录移除 finalizer 的操作成功到日志，并返回 nil
    logger.V(3).Info("Removed protection finalizer from PVC", "PVC", klog.KObj(pvc))
    return nil
}
```

#### addFinalizer

```go
func (c *Controller) addFinalizer(ctx context.Context, pvc *v1.PersistentVolumeClaim) error {
	// 复制一个持久卷声明对象
	claimClone := pvc.DeepCopy()
	// 在复制对象的Finalizers字段中添加一个Finalizer
	claimClone.ObjectMeta.Finalizers = append(claimClone.ObjectMeta.Finalizers, volumeutil.PVCProtectionFinalizer)
	// 调用 Kubernetes API 更新该持久卷声明对象
	_, err := c.client.CoreV1().PersistentVolumeClaims(claimClone.Namespace).Update(ctx, claimClone, metav1.UpdateOptions{})
	// 获取一个 logger 对象
	logger := klog.FromContext(ctx)
	// 如果更新过程中发生错误，输出错误信息并返回错误
	if err != nil {
		logger.Error(err, "Error adding protection finalizer to PVC", "PVC", klog.KObj(pvc))
		return err
	}
	// 更新成功，输出日志信息并返回 nil
	logger.V(3).Info("Added protection finalizer to PVC", "PVC", klog.KObj(pvc))
	return nil
}
```

