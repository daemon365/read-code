
## 简介

它的作用是帮助管理员限制在命名空间中使用的资源量，从而避免资源过度消耗或者资源耗尽导致的应用崩溃等问题。

具体来说，resourcequota-controller可以设置一些限制条件，例如：

- CPU和内存的最大使用量
- Persistent Volume Claims（PVCs）的数量和总容量
- Service和Endpoints的数量
- ConfigMaps和Secrets的数量

当namespace的资源使用量超出这些限制条件时，resourcequota-controller会阻止新的资源创建，直到已有的资源被删除或者已有的资源使用量降低到允许的范围内。

通过使用resourcequota-controller，管理员可以更好地控制Kubernetes集群的资源使用，从而保证应用程序的稳定性和可靠性。

## 结构体

```go
type Controller struct {
	// 提供访问 Kubernetes API 服务器以管理 ResourceQuota 对象的权限
    // 因为使用此结构体的用户必须具备列出系统中所有资源并更新配额状态所需的权限
	rqClient corev1client.ResourceQuotasGetter
	// ResourceQuota lister
	rqLister corelisters.ResourceQuotaLister
	// informer是否缓存完
	informerSyncedFuncs []cache.InformerSynced
	// 一个工作队列，用于保存需要同步的 ResourceQuota 对象
	queue workqueue.RateLimitingInterface
	// 一个工作队列，用于保存缺少初始使用信息的对象
	missingUsageQueue workqueue.RateLimitingInterface
	// 用于同步 ResourceQuota 对象使用信息的函数 主要用于测试
	syncHandler func(ctx context.Context, key string) error
	// 控制完全重新计算配额使用量发生的频率的函数
	resyncPeriod controller.ResyncPeriodFunc
	// 一个注册表，知道如何为不同类型的资源计算使用量
	registry quota.Registry
	// 结构体的一个实例，它知道如何监视配额跟踪的资源，并在必要时触发补充
	quotaMonitor *QuotaMonitor
	// 用于控制对监视器的访问，并确保在处理配额之前所有监视器都已同步。
    // 这用于防止在处理 ResourceQuota 时出现竞态条件
	workerLock sync.RWMutex
}
```

## New

```go
func NewController(ctx context.Context, options *ControllerOptions) (*Controller, error) {
	// build the resource quota controller
	rq := &Controller{
		rqClient:            options.QuotaClient,
		rqLister:            options.ResourceQuotaInformer.Lister(),
		informerSyncedFuncs: []cache.InformerSynced{options.ResourceQuotaInformer.Informer().HasSynced},
		queue:               workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "resourcequota_primary"),
		missingUsageQueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "resourcequota_priority"),
		resyncPeriod:        options.ResyncPeriod,
		registry:            options.Registry,
	}
	// set the synchronization handler
	rq.syncHandler = rq.syncResourceQuotaFromKey

	logger := klog.FromContext(ctx)
	
    // 获取ResourceQuota的变更做操作
	options.ResourceQuotaInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				rq.addQuota(logger, obj)
			},
			UpdateFunc: func(old, cur interface{}) {
				oldResourceQuota := old.(*v1.ResourceQuota)
				curResourceQuota := cur.(*v1.ResourceQuota)
                // 如果相等直接返回
				if quota.Equals(oldResourceQuota.Spec.Hard, curResourceQuota.Spec.Hard) {
					return
				}
				rq.addQuota(logger, curResourceQuota)
			},
			DeleteFunc: func(obj interface{}) {
				rq.enqueueResourceQuota(logger, obj)
			},
		},
		rq.resyncPeriod(),
	)
	
    // DiscoveryFunc是 用于发现集群的所有资源列表 和 namespace-controller的那个函数一样的
	if options.DiscoveryFunc != nil {
        // QuotaMonitor比较独立 文章最后介绍
		qm := &QuotaMonitor{
			informersStarted:  options.InformersStarted,
			informerFactory:   options.InformerFactory,
			ignoredResources:  options.IgnoredResourcesFunc(),
			resourceChanges:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "resource_quota_controller_resource_changes"),
			resyncPeriod:      options.ReplenishmentResyncPeriod,
			replenishmentFunc: rq.replenishQuota,
			registry:          rq.registry,
			updateFilter:      options.UpdateFilter,
		}

		rq.quotaMonitor = qm

		// do initial quota monitor setup.  If we have a discovery failure here, it's ok. We'll discover more resources when a later sync happens.
		resources, err := GetQuotableResources(options.DiscoveryFunc)
		if discovery.IsGroupDiscoveryFailedError(err) {
			utilruntime.HandleError(fmt.Errorf("initial discovery check failure, continuing and counting on future sync update: %v", err))
		} else if err != nil {
			return nil, err
		}

		if err = qm.SyncMonitors(ctx, resources); err != nil {
			utilruntime.HandleError(fmt.Errorf("initial monitor sync has error: %v", err))
		}

		// only start quota once all informers synced
		rq.informerSyncedFuncs = append(rq.informerSyncedFuncs, func() bool {
			return qm.IsSynced(ctx)
		})
	}

	return rq, nil
}

type NamespacedResourcesFunc func() ([]*metav1.APIResourceList, error)

type ControllerOptions struct {
	QuotaClient corev1client.ResourceQuotasGetter
	ResourceQuotaInformer coreinformers.ResourceQuotaInformer
	ResyncPeriod controller.ResyncPeriodFunc
	Registry quota.Registry
	DiscoveryFunc NamespacedResourcesFunc
	IgnoredResourcesFunc func() map[schema.GroupResource]struct{}
	InformersStarted <-chan struct{}
	InformerFactory informerfactory.InformerFactory
	ReplenishmentResyncPeriod controller.ResyncPeriodFunc
	UpdateFilter UpdateFilter
}

```

### 队列

```go
func (rq *Controller) addQuota(logger klog.Logger, obj interface{}) {
    // 获取对象的key
	key, err := controller.KeyFunc(obj)
	if err != nil {
		logger.Error(err, "Couldn't get key", "object", obj)
		return
	}
	
    // 断言对象
	resourceQuota := obj.(*v1.ResourceQuota)

	//  一般是相等的 不相等是出问题了 可能是刚创建还没同步
    // 通过控制器来调整配额，以使其达到预期值 加入missingUsage queue
	if !apiequality.Semantic.DeepEqual(resourceQuota.Spec.Hard, resourceQuota.Status.Hard) {
		rq.missingUsageQueue.Add(key)
		return
	}

	// 便利每个被限制的资源
	for constraint := range resourceQuota.Status.Hard {
        // 检查资源配额对象中是否存在未被使用的约束 如果不存在基本也是出问题了 如果优先处理
		if _, usageFound := resourceQuota.Status.Used[constraint]; !usageFound {
			matchedResources := []v1.ResourceName{constraint}
            // 查找注册表 检查是否有与当前资源配额对象中的约束相匹配
			for _, evaluator := range rq.registry.List() {
				if intersection := evaluator.MatchingResources(matchedResources); len(intersection) > 0 {
					rq.missingUsageQueue.Add(key)
					return
				}
			}
		}
	}

	//  加入queue
	rq.queue.Add(key)
}

```

### enqueueResourceQuota

```
func (rq *Controller) enqueueResourceQuota(logger klog.Logger, obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		logger.Error(err, "Couldn't get key", "object", obj)
		return
	}
	rq.queue.Add(key)
}
```

## Run

- quotaMonitor： 用来处理可以"create","list","watch","delete"的所有资源的, 如果发现资源和`resourceQuota`有交集，加入queue重新计算资源
- worker(rq.queue)： 监控resrouceQuota的更改和删除，重新计算资源
- rq.worker(rq.missingUsageQueue)： 整理status和spec没同步或者出问题的resrouceQuota
- enqueueAll: 拿出所有的enqueueAll 放入队列重新计算

```go
func (rq *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer rq.queue.ShutDown()
	defer rq.missingUsageQueue.ShutDown()

	logger := klog.FromContext(ctx)

	logger.Info("Starting resource quota controller")
	defer logger.Info("Shutting down resource quota controller")
	
    // 如果quotaMonitor开启了 启动一个goroutine执行
	if rq.quotaMonitor != nil {
		go rq.quotaMonitor.Run(ctx)
	}
	
    // 等待所有Lister同步完成
	if !cache.WaitForNamedCacheSync("resource quota", ctx.Done(), rq.informerSyncedFuncs...) {
		return
	}

	// 启动workers个goroutine执行 rq.worker(rq.queue) 和 
    // 启动workers个goroutine执行rq.worker(rq.missingUsageQueue) 
    // 都是每秒执行一次
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, rq.worker(rq.queue), time.Second)
		go wait.UntilWithContext(ctx, rq.worker(rq.missingUsageQueue), time.Second)
	}
	//  如果同步周期大于0 启动一个协程 没rq.resyncPeriod()执行enqueueAll
	if rq.resyncPeriod() > 0 {
		go wait.UntilWithContext(ctx, rq.enqueueAll, rq.resyncPeriod())
	} else {
		logger.Info("periodic quota controller resync disabled")
	}
	<-ctx.Done()
}
```

## worker

```go
func (rq *Controller) worker(queue workqueue.RateLimitingInterface) func(context.Context) {
    // 定义个函数
	workFunc := func(ctx context.Context) bool {
        // 从队列中拿key 没有了返回true
		key, quit := queue.Get()
		if quit {
			return true
		}
		defer queue.Done(key)
		
		// 解锁 函数退出 解锁
		rq.workerLock.RLock()
		defer rq.workerLock.RUnlock()

		logger := klog.FromContext(ctx)
		logger = klog.LoggerWithValues(logger, "queueKey", key)
		ctx = klog.NewContext(ctx, logger)
	
        // 处理对象
		err := rq.syncHandler(ctx, key.(string))
		if err == nil {
            // 成功了删除key
			queue.Forget(key)
			return false
		}
		
        // 处理错误
		utilruntime.HandleError(err)
        // 失败了 加入重试队列
		queue.AddRateLimited(key)

		return false
	}

	return func(ctx context.Context) {
		for {
            // 无限执行 知道workFunc返回true
			if quit := workFunc(ctx); quit {
				klog.FromContext(ctx).Info("resource quota controller worker shutting down")
				return
			}
		}
	}
}
```

### syncResourceQuotaFromKey

- 上面代码的`syncHandle`r就是这个, 在`NewController`的时候被赋值`rq.syncHandler = rq.syncResourceQuotaFromKey`.

```go
func (rq *Controller) syncResourceQuotaFromKey(ctx context.Context, key string) (err error) {
    // 记录开始时间
	startTime := time.Now()
	
    // 从传入的 context 中获取 logger，并加入 "key" 字段的信息。
	logger := klog.FromContext(ctx)
	logger = klog.LoggerWithValues(logger, "key", key)

	defer func() {
        // 退出时候 打印耗时日志
		logger.V(4).Info("Finished syncing resource quota", "key", key, "duration", time.Since(startTime))
	}()
	
    // 将key解析为 namespace 和 name。
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
    // 从ResourceQuota lister 中拿到resourceQuota
	resourceQuota, err := rq.rqLister.ResourceQuotas(namespace).Get(name)
	if errors.IsNotFound(err) {
        // 没找到就是被删除了 打印一直 退出
		logger.Info("Resource quota has been deleted", "key", key)
		return nil
	}
	if err != nil {
        // 其他错误返回错误
		logger.Error(err, "Unable to retrieve resource quota from store", "key", key)
		return err
	}
    // 同步处理
	return rq.syncResourceQuota(ctx, resourceQuota)
}
```

### syncResourceQuota

```go
// 同步资源配额对象的状态（Status），并且更新它的用量（Used）和硬限制（Hard）。
func (rq *Controller) syncResourceQuota(ctx context.Context, resourceQuota *v1.ResourceQuota) (err error) {
	// Spec.Hard 和 Status.Hardb不相等 已经过期了
	statusLimitsDirty := !apiequality.Semantic.DeepEqual(resourceQuota.Spec.Hard, resourceQuota.Status.Hard)

	// 如果 Status.Hard 或 Status.Used 为 nil，或者 statusLimitsDirty 为 true 表示这个配额对象的状态需要更新。
	dirty := statusLimitsDirty || resourceQuota.Status.Hard == nil || resourceQuota.Status.Used == nil
	
    // 创建used 如果Status.Used是nil 保持空对象 如果不是 把之前的赋值给used
	used := v1.ResourceList{}
	if resourceQuota.Status.Used != nil {
		used = quota.Add(v1.ResourceList{}, resourceQuota.Status.Used)
	}
    // hardLimits表示限制的 把Spec.Hard限制给hardLimits
	hardLimits := quota.Add(v1.ResourceList{}, resourceQuota.Spec.Hard)

	var errs []error
	
    // 计算新的资源使用量
    // resourceQuota.Spec.Scopes是配额的资源范围
    // resourceQuota.Spec.ScopeSelector是将 ResourceQuota 和 Pod 的 priority 关联，进而限定 Pod 的资源消耗。
	newUsage, err := quota.CalculateUsage(resourceQuota.Namespace, resourceQuota.Spec.Scopes, hardLimits, rq.registry, resourceQuota.Spec.ScopeSelector)
	if err != nil {
		// if err is non-nil, remember it to return, but continue updating status with any resources in newUsage
		errs = append(errs, err)
	}
    // 把新的使用量 赋值给used
	for key, value := range newUsage {
		used[key] = value
	}

	// 获取记录硬性资源的名称
	hardResources := quota.ResourceNames(hardLimits)
    // 与硬性限制相匹配的资源的使用量赋给 used 
	used = quota.Mask(used, hardResources)

	// deepcopy 获取原本对象 再赋值
	usage := resourceQuota.DeepCopy()
	usage.Status = v1.ResourceQuotaStatus{
		Hard: hardLimits,
		Used: used,
	}
	
    // 看是不是要更新
	dirty = dirty || !quota.Equals(usage.Status.Used, resourceQuota.Status.Used)

	// there was a change observed by this controller that requires we update quota
	if dirty {
        // 如果要更新 就更新ResourceQuota
		_, err = rq.rqClient.ResourceQuotas(usage.Namespace).UpdateStatus(ctx, usage, metav1.UpdateOptions{})
		if err != nil {
			errs = append(errs, err)
		}
	}
    // 合并错误
	return utilerrors.NewAggregate(errs)
}
```

## enqueueAll

```GO
func (rq *Controller) enqueueAll(ctx context.Context) {
	logger := klog.FromContext(ctx)
	defer logger.V(4).Info("Resource quota controller queued all resource quota for full calculation of usage")
    // 拿出是所有resourceQuota
	rqs, err := rq.rqLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to enqueue all - error listing resource quotas: %v", err))
		return
	}
	for i := range rqs {
        // 一个一个放入queue中 做同步
		key, err := controller.KeyFunc(rqs[i])
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", rqs[i], err))
			continue
		}
		rq.queue.Add(key)
	}
}
```

## quotaMonitor

### 结构体

```go
type QuotaMonitor struct {
	// 存储一组监控器 每个监控器都监视一个资源，并决定是否需要重新计算配额
	monitors    monitors
	monitorLock sync.RWMutex
	// 所有控制器初始化并运行后关闭
	informersStarted <-chan struct{}
	// 安全停止
	stopCh <-chan struct{}
	// 是否已调用 Run()
	running bool
	// 资源变更的队列
	resourceChanges workqueue.RateLimitingInterface
	// 与 Informers 交互
	informerFactory informerfactory.InformerFactory
	// 要忽略的资源列表
	ignoredResources map[schema.GroupResource]struct{}
	// 重新同步被监视的资源
	resyncPeriod controller.ResyncPeriodFunc
	// 提示可能需要重新计算配额。
	replenishmentFunc ReplenishmentFunc
	// 注册表
	registry quota.Registry
    // 更新资源变更的过滤
	updateFilter UpdateFilter
}

type monitor struct {
	controller cache.Controller

	// stopCh stops Controller. If stopCh is nil, the monitor is considered to be
	// not yet started.
	stopCh chan struct{}
}

type monitors map[schema.GroupVersionResource]*monitor
```

### New

```go
func NewMonitor(informersStarted <-chan struct{}, informerFactory informerfactory.InformerFactory, ignoredResources map[schema.GroupResource]struct{}, resyncPeriod controller.ResyncPeriodFunc, replenishmentFunc ReplenishmentFunc, registry quota.Registry) *QuotaMonitor {
	return &QuotaMonitor{
		informersStarted:  informersStarted,
		informerFactory:   informerFactory,
		ignoredResources:  ignoredResources,
		resourceChanges:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "resource_quota_controller_resource_changes"),
		resyncPeriod:      resyncPeriod,
		replenishmentFunc: replenishmentFunc,
		registry:          registry,
	}
}
```

主函数中添加`NewMonitor`的代码

```go
qm := &QuotaMonitor{
			informersStarted:  options.InformersStarted,
			informerFactory:   options.InformerFactory,
			ignoredResources:  options.IgnoredResourcesFunc(),
			resourceChanges:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "resource_quota_controller_resource_changes"),
			resyncPeriod:      options.ReplenishmentResyncPeriod,
			replenishmentFunc: rq.replenishQuota,
			registry:          rq.registry,
			updateFilter:      options.UpdateFilter,
		}

		rq.quotaMonitor = qm

		// 获取可以执行“create”、“list”、“watch”和“delete”操作的资源列表
		resources, err := GetQuotableResources(options.DiscoveryFunc)
		if discovery.IsGroupDiscoveryFailedError(err) {
			utilruntime.HandleError(fmt.Errorf("initial discovery check failure, continuing and counting on future sync update: %v", err))
		} else if err != nil {
			return nil, err
		}
	
		// 初始化 QuotaMonitor 的 monitor
		if err = qm.SyncMonitors(ctx, resources); err != nil {
			utilruntime.HandleError(fmt.Errorf("initial monitor sync has error: %v", err))
		}

		// 把时候同步完成加入列表
		rq.informerSyncedFuncs = append(rq.informerSyncedFuncs, func() bool {
			return qm.IsSynced(ctx)
		})
```

#### GetQuotableResources

```GO
func GetQuotableResources(discoveryFunc NamespacedResourcesFunc) (map[schema.GroupVersionResource]struct{}, error) {
    // 获取集群所有资源名称列表
	possibleResources, discoveryErr := discoveryFunc()
	if discoveryErr != nil && len(possibleResources) == 0 {
		return nil, fmt.Errorf("failed to discover resources: %v", discoveryErr)
	}
    // 过滤出可以支持“create”、“list”、“watch”和“delete”四种操作的资源
	quotableResources := discovery.FilteredBy(discovery.SupportsAllVerbs{Verbs: []string{"create", "list", "watch", "delete"}}, possibleResources)
    // 转化为map
	quotableGroupVersionResources, err := discovery.GroupVersionResources(quotableResources)
	if err != nil {
		return nil, fmt.Errorf("failed to parse resources: %v", err)
	}
	// return the original discovery error (if any) in addition to the list
	return quotableGroupVersionResources, discoveryErr
}
```

#### SyncMonitors

```GO
func (qm *QuotaMonitor) SyncMonitors(ctx context.Context, resources map[schema.GroupVersionResource]struct{}) error {
    // 从ctx获取logger 之前加进去的
	logger := klog.FromContext(ctx)
	
    // 加锁 退出时解锁
	qm.monitorLock.Lock()
	defer qm.monitorLock.Unlock()

	toRemove := qm.monitors
	if toRemove == nil {
        // 等于空 新键一个
		toRemove = monitors{}
	}
	current := monitors{}
	var errs []error
    // 记录已经保留的资源数量
	kept := 0
    // 记录新添加的资源数量
	added := 0
	for resource := range resources {
        // 忽略表里有这个 就跳过
		if _, ok := qm.ignoredResources[resource.GroupResource()]; ok {
			continue
		}
        // 如果当前资源已经在toRemove中，则将其从toRemove中移除
		if m, ok := toRemove[resource]; ok {
            // 放入到current
			current[resource] = m
            // 从toRemove删除
			delete(toRemove, resource)
            // 已经保留的资源数量
			kept++
			continue
		}
        // 获取当前资源的控制器
		c, err := qm.controllerFor(ctx, resource)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't start monitor for resource %q: %v", resource, err))
			continue
		}

		// 从注册表中获取当前资源的评估器
		evaluator := qm.registry.Get(resource.GroupResource())
		if evaluator == nil {
            // 评估器不存在，则创建一个新的评估器，并将其添加到注册表中
            // 当前资源创建一个列表器函数
			listerFunc := generic.ListerFuncForResourceFunc(qm.informerFactory.ForResource)
            // 当前资源创建一个列表函数
			listResourceFunc := generic.ListResourceUsingListerFunc(listerFunc, resource)
            // 新的对象计数评估器
			evaluator = generic.NewObjectCountEvaluator(resource.GroupResource(), listResourceFunc, "")
            // 将新创建的评估器添加到注册表中
			qm.registry.Add(evaluator)
			logger.Info("QuotaMonitor created object count evaluator", "resource", resource.GroupResource())
		}

		// 加入current
		current[resource] = &monitor{controller: c}
        // 新加入的数加一
		added++
	}
	qm.monitors = current
	
    // 之前需要这些资源 现在需要了 stopCh掉
	for _, monitor := range toRemove {
		if monitor.stopCh != nil {
			close(monitor.stopCh)
		}
	}

	logger.V(4).Info("quota synced monitors", "added", added, "kept", kept, "removed", len(toRemove))
	// NewAggregate returns nil if errs is 0-length
	return utilerrors.NewAggregate(errs)
}

```

##### controllerFor

```GO
func (qm *QuotaMonitor) controllerFor(ctx context.Context, resource schema.GroupVersionResource) (cache.Controller, error) {
    // 从ctx拿日志
	logger := klog.FromContext(ctx)
	// 处理handlers 监控更新和删除 处理key 加入resourceChanges
	handlers := cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			if qm.updateFilter != nil && qm.updateFilter(resource, oldObj, newObj) {
				event := &event{
					eventType: updateEvent,
					obj:       newObj,
					oldObj:    oldObj,
					gvr:       resource,
				}
				qm.resourceChanges.Add(event)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// delta fifo may wrap the object in a cache.DeletedFinalStateUnknown, unwrap it
			if deletedFinalStateUnknown, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = deletedFinalStateUnknown.Obj
			}
			event := &event{
				eventType: deleteEvent,
				obj:       obj,
				gvr:       resource,
			}
			qm.resourceChanges.Add(event)
		},
	}
    // 返回share informer
	shared, err := qm.informerFactory.ForResource(resource)
	if err == nil {
		logger.V(4).Info("QuotaMonitor using a shared informer", "resource", resource.String())
        // 注册handlers事件处理程序
		shared.Informer().AddEventHandlerWithResyncPeriod(handlers, qm.resyncPeriod())
        // 返回controller 村到Map里 之后Run等操作
		return shared.Informer().GetController(), nil
	}
    // 如果出错了 打印错误 并返回 
	logger.V(4).Error(err, "QuotaMonitor unable to use a shared informer", "resource", resource.String())

	// TODO: if we can share storage with garbage collector, it may make sense to support other resources
	// until that time, aggregated api servers will have to run their own controller to reconcile their own quota.
	return nil, fmt.Errorf("unable to monitor quota for resource %q", resource.String())
}
```

#### IsSynced

```GO
func (qm *QuotaMonitor) IsSynced(ctx context.Context) bool {
	logger := klog.FromContext(ctx)
	// 加锁 退出时解锁
	qm.monitorLock.RLock()
	defer qm.monitorLock.RUnlock()
	
    // 检查监视器列表是否为空 
	if len(qm.monitors) == 0 {
		logger.V(4).Info("quota monitor not synced: no monitors")
		return false
	}
	
   // 检查监视器列表中 有没有没同步完的
	for resource, monitor := range qm.monitors {
		if !monitor.controller.HasSynced() {
			logger.V(4).Info("quota monitor not synced", "resource", resource)
			return false
		}
	}
	return true
}
```

### Run

```GO
func (qm *QuotaMonitor) Run(ctx context.Context) {
    // 处理panic
	defer utilruntime.HandleCrash()
	// 从ctx拿日志logger
	logger := klog.FromContext(ctx)
	// 开始日志 结束日志
	logger.Info("QuotaMonitor running")
	defer logger.Info("QuotaMonitor stopping")

	// 将stopCh设置为ctx.Done()，表示在context被取消时停止quota monitor的运行。
    // running 代表开始了
	qm.monitorLock.Lock()
	qm.stopCh = ctx.Done()
	qm.running = true
	qm.monitorLock.Unlock()

	// 开始运行quota monitor的监视器，直到context被取消。
	qm.StartMonitors(ctx)

	// The following workers are hanging forever until the queue is
	// shutted down, so we need to shut it down in a separate goroutine.
	go func() {
        // 等待ctx被取消结束掉resourceChanges
		defer utilruntime.HandleCrash()
		defer qm.resourceChanges.ShutDown()

		<-ctx.Done()
	}()
    // 无限循环runProcessResourceChanges
	wait.UntilWithContext(ctx, qm.runProcessResourceChanges, 1*time.Second)

	// Stop any running monitors.
	qm.monitorLock.Lock()
	defer qm.monitorLock.Unlock()
	monitors := qm.monitors
	stopped := 0
    // 停止所有的monitors
	for _, monitor := range monitors {
		if monitor.stopCh != nil {
			stopped++
			close(monitor.stopCh)
		}
	}
	logger.Info("QuotaMonitor stopped monitors", "stopped", stopped, "total", len(monitors))
}
```

### runProcessResourceChanges

```GO
func (qm *QuotaMonitor) runProcessResourceChanges(ctx context.Context) {
    // 无限执行 知道返回false
	for qm.processResourceChanges(ctx) {
	}
}

// Dequeueing an event from resourceChanges to process
func (qm *QuotaMonitor) processResourceChanges(ctx context.Context) bool {
    // 从resourceChanges queu中拿值 没有了返回flase
	item, quit := qm.resourceChanges.Get()
	if quit {
		return false
	}
    // 结束done掉key
	defer qm.resourceChanges.Done(item)
    // 断言事件对象
	event, ok := item.(*event)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expect a *event, got %v", item))
		return true
	}
    // 取出对象
	obj := event.obj
    // 取出 name namespace uuid等metadata
	accessor, err := meta.Accessor(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("cannot access obj: %v", err))
		return true
	}
    // 记录日志
	klog.FromContext(ctx).V(4).Info("QuotaMonitor process object",
		"resource", event.gvr.String(),
		"namespace", accessor.GetNamespace(),
		"name", accessor.GetName(),
		"uid", string(accessor.GetUID()),
		"eventType", event.eventType,
	)
    // 使用gr和namespace更新已使用的资源数量
	qm.replenishmentFunc(ctx, event.gvr.GroupResource(), accessor.GetNamespace())
	return true
}
```

#### replenishQuota

- `replenishQuota`就是`replenishmentFunc`, `NewController`创建`qm`时 被赋值

```go
func (rq *Controller) replenishQuota(ctx context.Context, groupResource schema.GroupResource, namespace string) {
	// 从注册表中获取对应的计算器对象，如果没有则返回
	evaluator := rq.registry.Get(groupResource)
	if evaluator == nil {
		return
	}

	// 获取namespace下的 ResourceQuota
	resourceQuotas, err := rq.rqLister.ResourceQuotas(namespace).List(labels.Everything())
	if errors.IsNotFound(err) {
		utilruntime.HandleError(fmt.Errorf("quota controller could not find ResourceQuota associated with namespace: %s, could take up to %v before a quota replenishes", namespace, rq.resyncPeriod()))
		return
	}
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error checking to see if namespace %s has any ResourceQuota associated with it: %v", namespace, err))
		return
	}
	if len(resourceQuotas) == 0 {
		return
	}

	logger := klog.FromContext(ctx)

	// 便利资源列表
	for i := range resourceQuotas {
		resourceQuota := resourceQuotas[i]
        // 获取name
		resourceQuotaResources := quota.ResourceNames(resourceQuota.Status.Hard)
        // 与当前实际使用的资源进行比较，返回资源配额中包含的那些资源与实际使用的资源的交集
        // len(intersection) > 0 说明有至少一个资源在资源配额和评估器之间匹配，那么就需要触发评估器来计算资源使用情况
        // len(intersection) = 0 没有差异 跳过就可以了
		if intersection := evaluator.MatchingResources(resourceQuotaResources); len(intersection) > 0 {
			// TODO: make this support targeted replenishment to a specific kind, right now it does a full recalc on that quota.
			rq.enqueueResourceQuota(logger, resourceQuota)
		}
	}
}

```

