
## 简介

用于管理ResourceClaim资源。ResourceClaim是一种自定义资源，用于声明对某种资源的需求，例如存储、网络或计算。ResourceClaim控制器的作用是根据ResourceClaim的规格和状态，分配合适的资源给它，并更新它的状态。当一个Pod或一个Deployment被创建时，它会通过声明所需的资源量（例如CPU、内存）来表达对资源的需求。然后，这些资源需求将被封装在一个资源声明（resource claim）对象中，并提交给resource claim controller进行处理。在资源声明对象被创建后，resource claim controller会监控K8s中所有的资源使用情况，然后将资源需求与可用资源进行匹配。如果有可用资源满足需求，resource claim controller会自动分配这些资源给相应的Pod或Deployment。否则，Pod或Deployment将会被阻塞，直到有足够的资源可用。

## 结构体

```go
type Controller struct {
	kubeClient clientset.Interface
	// ResourceClaim的lister
	claimLister  resourcev1alpha1listers.ResourceClaimLister
	claimsSynced cache.InformerSynced

	// pod的lister
	podLister v1listers.PodLister
	podSynced cache.InformerSynced

	// templateLister 的lister
	templateLister  resourcev1alpha1listers.ResourceClaimTemplateLister
	templatesSynced cache.InformerSynced

	// pod的索引缓存
	podIndexer cache.Indexer

	// 事件记录器，用于记录API服务器中的事件
	recorder record.EventRecorder
	// 工作队列
	queue workqueue.RateLimitingInterface

	// 已删除对象缓存，用于跟踪已知存在并已删除的Pod对象。对于这些对象，我们可以确定需要删除ReservedFor条目。
	deletedObjects *uidCache
}
```

## New

```GO
func NewController(
	kubeClient clientset.Interface,
	podInformer v1informers.PodInformer,
	claimInformer resourcev1alpha1informers.ResourceClaimInformer,
	templateInformer resourcev1alpha1informers.ResourceClaimTemplateInformer) (*Controller, error) {

	ec := &Controller{
		kubeClient:      kubeClient,
		podLister:       podInformer.Lister(),
		podIndexer:      podInformer.Informer().GetIndexer(),
		podSynced:       podInformer.Informer().HasSynced,
		claimLister:     claimInformer.Lister(),
		claimsSynced:    claimInformer.Informer().HasSynced,
		templateLister:  templateInformer.Lister(),
		templatesSynced: templateInformer.Informer().HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "resource_claim"),
		deletedObjects:  newUIDCache(maxUIDCacheEntries),
	}
	
    // 开启metrics
	metrics.RegisterMetrics()

	if _, err := podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ec.enqueuePod(obj, false)
		},
		UpdateFunc: func(old, updated interface{}) {
			ec.enqueuePod(updated, false)
		},
		DeleteFunc: func(obj interface{}) {
			ec.enqueuePod(obj, true)
		},
	}); err != nil {
		return nil, err
	}
	if _, err := claimInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: ec.onResourceClaimAddOrUpdate,
		UpdateFunc: func(old, updated interface{}) {
			ec.onResourceClaimAddOrUpdate(updated)
		},
		DeleteFunc: ec.onResourceClaimDelete,
	}); err != nil {
		return nil, err
	}
    // 使用podResourceClaimIndexFunc做indexer索引
	if err := ec.podIndexer.AddIndexers(cache.Indexers{podResourceClaimIndex: podResourceClaimIndexFunc}); err != nil {
		return nil, fmt.Errorf("could not initialize ResourceClaim controller: %w", err)
	}

	return ec, nil
}
```

### metrics

```GO

// ResourceClaimSubsystem - subsystem name used for ResourceClaim creation
const ResourceClaimSubsystem = "resourceclaim_controller"

var (
	// ResourceClaimCreateAttempts tracks the number of
	// ResourceClaims().Create calls (both successful and unsuccessful)
	ResourceClaimCreateAttempts = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem:      ResourceClaimSubsystem,
			Name:           "create_attempts_total",
			Help:           "Number of ResourceClaims creation requests",
			StabilityLevel: metrics.ALPHA,
		})
	// ResourceClaimCreateFailures tracks the number of unsuccessful
	// ResourceClaims().Create calls
	ResourceClaimCreateFailures = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem:      ResourceClaimSubsystem,
			Name:           "create_failures_total",
			Help:           "Number of ResourceClaims creation request failures",
			StabilityLevel: metrics.ALPHA,
		})
)

var registerMetrics sync.Once

// RegisterMetrics registers ResourceClaim metrics.
func RegisterMetrics() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(ResourceClaimCreateAttempts)
		legacyregistry.MustRegister(ResourceClaimCreateFailures)
	})
}

```

### enqueuePod

```GO
func (ec *Controller) enqueuePod(obj interface{}, deleted bool) {
    // 判断时候删除 如果是 还原对象
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
    // 断言pod
	pod, ok := obj.(*v1.Pod)
	if !ok {
		// Not a pod?!
		return
	}
	
    // 如果是删除event 添加到deletedObjects
	if deleted {
		ec.deletedObjects.Add(pod.UID)
	}
	
    // 没有ResourceClaims 直接返回
	if len(pod.Spec.ResourceClaims) == 0 {
		// Nothing to do for it at all.
		return
	}

	// pod被删除 或者已经完成
	if deleted ||
		podutil.IsPodTerminal(pod) ||
		// Deleted and not scheduled:
		pod.DeletionTimestamp != nil && pod.Spec.NodeName == "" {
		for _, podClaim := range pod.Spec.ResourceClaims {
            // 将 Pod 中的每一个资源声明的name与namespace组成的字符串添加到队列中
			claimName := resourceclaim.Name(pod, &podClaim)
			ec.queue.Add(claimKeyPrefix + pod.Namespace + "/" + claimName)
		}
	}

	// Create ResourceClaim for inline templates?
	if pod.DeletionTimestamp == nil {
		for _, podClaim := range pod.Spec.ResourceClaims {
			if podClaim.Source.ResourceClaimTemplateName != nil {
				// 如果没删除 只添加一次
				ec.queue.Add(podKeyPrefix + pod.Namespace + "/" + pod.Name)
				break
			}
		}
	}
}
```

### onResourceClaimAddOrUpdate

```GO

func (ec *Controller) onResourceClaimAddOrUpdate(obj interface{}) {
	claim, ok := obj.(*resourcev1alpha1.ResourceClaim)
	if !ok {
		return
	}

	// When starting up, we have to check all claims to find those with
	// stale pods in ReservedFor. During an update, a pod might get added
	// that already no longer exists.
	ec.queue.Add(claimKeyPrefix + claim.Namespace + "/" + claim.Name)
}
```

### podResourceClaimIndexFunc

```GO
func podResourceClaimIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return []string{}, nil
	}
	keys := []string{}
	for _, podClaim := range pod.Spec.ResourceClaims {
		if podClaim.Source.ResourceClaimTemplateName != nil {
            // pod和podClaim凭借
			claimName := resourceclaim.Name(pod, &podClaim)
			keys = append(keys, fmt.Sprintf("%s/%s", pod.Namespace, claimName))
		}
	}
	return keys, nil
}
```

## Run

```GO
func (ec *Controller) Run(ctx context.Context, workers int) {
    // 处理panic
	defer runtime.HandleCrash()
    // 关闭队列
	defer ec.queue.ShutDown()

	klog.Infof("Starting ephemeral volume controller")
	defer klog.Infof("Shutting down ephemeral volume controller")
	
    // 创建记录器 记录事件，并将事件同时输出到日志中
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: ec.kubeClient.CoreV1().Events("")})
	ec.recorder = eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "resource_claim"})
	defer eventBroadcaster.Shutdown()

    // 等待informer同步完成
	if !cache.WaitForNamedCacheSync("ephemeral", ctx.Done(), ec.podSynced, ec.claimsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, ec.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

## runWorker

```GO
func (ec *Controller) runWorker(ctx context.Context) {
    // 执行processNextWorkItem 直到返回false
	for ec.processNextWorkItem(ctx) {
	}
}

func (ec *Controller) processNextWorkItem(ctx context.Context) bool {
	key, shutdown := ec.queue.Get()
	if shutdown {
		return false
	}
	defer ec.queue.Done(key)
	
    // 同步对象
	err := ec.syncHandler(ctx, key.(string))
    // 如果成功Forget 如果失败加入延迟队列
	if err == nil {
		ec.queue.Forget(key)
		return true
	}

	runtime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	ec.queue.AddRateLimited(key)

	return true
}

```

#### syncHandler

```GO
func (ec *Controller) syncHandler(ctx context.Context, key string) error {
	sep := strings.Index(key, ":")
	if sep < 0 {
		return fmt.Errorf("unexpected key: %s", key)
	}
	prefix, object := key[0:sep+1], key[sep+1:]
    // 用对象的key解析 namespace和name
	namespace, name, err := cache.SplitMetaNamespaceKey(object)
	if err != nil {
		return err
	}
	// key中不同的前缀执行不同的方法
	switch prefix {
	case podKeyPrefix:
		return ec.syncPod(ctx, namespace, name)
	case claimKeyPrefix:
		return ec.syncClaim(ctx, namespace, name)
	default:
		return fmt.Errorf("unexpected key prefix: %s", prefix)
	}
}
const (
	claimKeyPrefix = "claim:"
	podKeyPrefix   = "pod:"
)
```

##### syncPod

```GO
func (ec *Controller) syncPod(ctx context.Context, namespace, name string) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "pod", klog.KRef(namespace, name))
	ctx = klog.NewContext(ctx, logger)
    // 获取pod
	pod, err := ec.podLister.Pods(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.V(5).Info("nothing to do for pod, it is gone")
			return nil
		}
		return err
	}

	// 如果被删除 就不用处理了
	if pod.DeletionTimestamp != nil {
		logger.V(5).Info("nothing to do for pod, it is marked for deletion")
		return nil
	}

	for _, podClaim := range pod.Spec.ResourceClaims {
        // pod中的每个ResourceClaims使用handleClaim处理
		if err := ec.handleClaim(ctx, pod, podClaim); err != nil {
			if ec.recorder != nil {
				ec.recorder.Event(pod, v1.EventTypeWarning, "FailedResourceClaimCreation", fmt.Sprintf("PodResourceClaim %s: %v", podClaim.Name, err))
			}
			return fmt.Errorf("pod %s/%s, PodResourceClaim %s: %v", namespace, name, podClaim.Name, err)
		}
	}

	return nil
}
```

##### handleClaim

```GO
func (ec *Controller) handleClaim(ctx context.Context, pod *v1.Pod, podClaim v1.PodResourceClaim) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "podClaim", podClaim.Name)
	ctx = klog.NewContext(ctx, logger)
	logger.V(5).Info("checking", "podClaim", podClaim.Name)
    // 获取ResourceClaimTemplate的name
	templateName := podClaim.Source.ResourceClaimTemplateName
	if templateName == nil {
		return nil
	}
	
    // 获取resourceclaim，如果出错则返回错误
	claimName := resourceclaim.Name(pod, &podClaim)
	claim, err := ec.claimLister.ResourceClaims(pod.Namespace).Get(claimName)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if claim != nil {
        // 与pod相关联返回错误 claim是空的
		if err := resourceclaim.IsForPod(pod, claim); err != nil {
			return err
		}
		// Already created, nothing more to do.
		logger.V(5).Info("claim already created", "podClaim", podClaim.Name, "resourceClaim", claimName)
		return nil
	}
	
    // 获取ResourceClaimTemplate对象
	template, err := ec.templateLister.ResourceClaimTemplates(pod.Namespace).Get(*templateName)
	if err != nil {
		return fmt.Errorf("resource claim template %q: %v", *templateName, err)
	}

	// Create the ResourceClaim with pod as owner.
	isTrue := true
    // 生成一个ResourceClaim对象
	claim = &resourcev1alpha1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: claimName,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               pod.Name,
					UID:                pod.UID,
					Controller:         &isTrue,
					BlockOwnerDeletion: &isTrue,
				},
			},
			Annotations: template.Spec.ObjectMeta.Annotations,
			Labels:      template.Spec.ObjectMeta.Labels,
		},
		Spec: template.Spec.Spec,
	}
    // 记录创建metrics
	metrics.ResourceClaimCreateAttempts.Inc()
    // 创建ResourceClaims
	_, err = ec.kubeClient.ResourceV1alpha1().ResourceClaims(pod.Namespace).Create(ctx, claim, metav1.CreateOptions{})
	if err != nil {
        // 记录失败metrics
		metrics.ResourceClaimCreateFailures.Inc()
		return fmt.Errorf("create ResourceClaim %s: %v", claimName, err)
	}
	return nil
}
```

### syncClaim

```GO
func (ec *Controller) syncClaim(ctx context.Context, namespace, name string) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "claim", klog.KRef(namespace, name))
	ctx = klog.NewContext(ctx, logger)
    // 获取ResourceClaims对象
	claim, err := ec.claimLister.ResourceClaims(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.V(5).Info("nothing to do for claim, it is gone")
			return nil
		}
		return err
	}

	// Check if the ReservedFor entries are all still valid.
	valid := make([]resourcev1alpha1.ResourceClaimConsumerReference, 0, len(claim.Status.ReservedFor))
	for _, reservedFor := range claim.Status.ReservedFor {
        // 引用的资源是 Pod，则检查该 Pod 是否仍然存在。如果 Pod 存在，则将其保留在 valid 数组中
		if reservedFor.APIGroup == "" &&
			reservedFor.Resource == "pods" {
			// A pod falls into one of three categories:
			// - we have it in our cache -> don't remove it until we are told that it got removed
			// - we don't have it in our cache anymore, but we have seen it before -> it was deleted, remove it
			// - not in our cache, not seen -> double-check with API server before removal

			keepEntry := true

			// Tracking deleted pods in the LRU cache is an
			// optimization. Without this cache, the code would
			// have to do the API call below for every deleted pod
			// to ensure that the pod really doesn't exist. With
			// the cache, most of the time the pod will be recorded
			// as deleted and the API call can be avoided.
			if ec.deletedObjects.Has(reservedFor.UID) {
				// We know that the pod was deleted. This is
				// easy to check and thus is done first.
				keepEntry = false
			} else {
				pod, err := ec.podLister.Pods(claim.Namespace).Get(reservedFor.Name)
				if err != nil && !errors.IsNotFound(err) {
					return err
				}
				if pod == nil {
					// We might not have it in our informer cache
					// yet. Removing the pod while the scheduler is
					// scheduling it would be bad. We have to be
					// absolutely sure and thus have to check with
					// the API server.
					pod, err := ec.kubeClient.CoreV1().Pods(claim.Namespace).Get(ctx, reservedFor.Name, metav1.GetOptions{})
					if err != nil && !errors.IsNotFound(err) {
						return err
					}
					if pod == nil || pod.UID != reservedFor.UID {
						keepEntry = false
					}
				} else if pod.UID != reservedFor.UID {
					// Pod exists, but is a different incarnation under the same name.
					keepEntry = false
				}
			}

			if keepEntry {
				valid = append(valid, reservedFor)
			}
			continue
		}

		// TODO: support generic object lookup
		return fmt.Errorf("unsupported ReservedFor entry: %v", reservedFor)
	}

	if len(valid) < len(claim.Status.ReservedFor) {
        // 更新ReservedFor
		claim := claim.DeepCopy()
		claim.Status.ReservedFor = valid
		_, err := ec.kubeClient.ResourceV1alpha1().ResourceClaims(claim.Namespace).UpdateStatus(ctx, claim, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}
```

