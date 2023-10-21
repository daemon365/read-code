
## 简介

Kubernetes (k8s) 的 Garbage Collector Controller 是一个控制器，用于管理 Kubernetes 集群中的资源回收。它负责删除不再需要的 Kubernetes 对象，以确保系统中只保留必要的资源，避免资源浪费和系统过载。

Garbage Collector Controller 使用标签选择器来标识哪些对象应该被删除。当一个对象被删除时，它会检查其拥有者引用的所有其他对象是否仍然存在。如果没有，它会继续删除这些对象，直到没有对象可以被删除。

Garbage Collector Controller 主要用于清理以下类型的对象：

1. 已删除的 Pod 对象所使用的卷（例如，PersistentVolumeClaim 或 ConfigMap）
2. 已删除的命名空间中的所有对象
3. 已删除的 DaemonSet、Deployment、Job、StatefulSet 等控制器对象所创建的 Pod 对象

Garbage Collector Controller 的作用是确保 Kubernetes 集群中不会出现无用的资源，从而提高系统的可靠性和性能。它可以帮助管理员自动化资源清理的过程，减少手动管理的工作量，提高集群管理的效率和可靠性。

## 结构体

```GO
type GarbageCollector struct {
    // 将资源 API 组和资源类型 map到 REST 存储
	restMapper     meta.ResettableRESTMapper
    // 与 Kubernetes API Server 交互，获取资源对象的元数据信息
	metadataClient metadata.Interface
	// 存储待删除资源对象的队列
	attemptToDelete workqueue.RateLimitingInterface
	// 存储待孤立依赖对象的队列
	attemptToOrphan        workqueue.RateLimitingInterface
    // 用于构建资源对象之间的依赖关系图
	dependencyGraphBuilder *GraphBuilder
	// 缓存已不存在的资源对象的拥有者信息
	absentOwnerCache *ReferenceCache

	kubeClient       clientset.Interface
    // 事件广播 用于记录资源对象删除事件的信息
	eventBroadcaster record.EventBroadcaster
	workerLock sync.RWMutex
}
```

## New

```GO
func NewGarbageCollector(
	kubeClient clientset.Interface,
	metadataClient metadata.Interface,
	mapper meta.ResettableRESTMapper,
	ignoredResources map[schema.GroupResource]struct{},
	sharedInformers informerfactory.InformerFactory,
	informersStarted <-chan struct{},
) (*GarbageCollector, error) {

	eventBroadcaster := record.NewBroadcaster()
	eventRecorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "garbage-collector-controller"})

	attemptToDelete := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "garbage_collector_attempt_to_delete")
	attemptToOrphan := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "garbage_collector_attempt_to_orphan")
	absentOwnerCache := NewReferenceCache(500)
	gc := &GarbageCollector{
		metadataClient:   metadataClient,
		restMapper:       mapper,
		attemptToDelete:  attemptToDelete,
		attemptToOrphan:  attemptToOrphan,
		absentOwnerCache: absentOwnerCache,
		kubeClient:       kubeClient,
		eventBroadcaster: eventBroadcaster,
	}
    // 创建 GraphBuilder
	gc.dependencyGraphBuilder = &GraphBuilder{
		eventRecorder:    eventRecorder,
		metadataClient:   metadataClient,
		informersStarted: informersStarted,
		restMapper:       mapper,
		graphChanges:     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "garbage_collector_graph_changes"),
		uidToNode: &concurrentUIDToNode{
			uidToNode: make(map[types.UID]*node),
		},
		attemptToDelete:  attemptToDelete,
		attemptToOrphan:  attemptToOrphan,
		absentOwnerCache: absentOwnerCache,
		sharedInformers:  sharedInformers,
		ignoredResources: ignoredResources,
	}
	// 开启metrics
	metrics.Register()

	return gc, nil
}
```

### metrics

```GO
const GarbageCollectorControllerSubsystem = "garbagecollector_controller"

var (
	GarbageCollectorResourcesSyncError = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem:      GarbageCollectorControllerSubsystem,
			Name:           "resources_sync_error_total",
			Help:           "Number of garbage collector resources sync errors",
			StabilityLevel: metrics.ALPHA,
		})
)

var registerMetrics sync.Once

// Register registers GarbageCollectorController metrics.
func Register() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(GarbageCollectorResourcesSyncError)
	})
}
```

这个控制器有些特殊，再kube-controller-manager中，除了开启Run，还有一个 goroutine 开启Sync。

```GO
go garbageCollector.Run(ctx, workers)
go garbageCollector.Sync(ctx, discoveryClient, 30*time.Second)
```

## Sync

```GO
func (gc *GarbageCollector) Sync(ctx context.Context, discoveryClient discovery.ServerResourcesInterface, period time.Duration) {
    // 记录上一次同步时的资源
	oldResources := make(map[schema.GroupVersionResource]struct{})
	wait.UntilWithContext(ctx, func(ctx context.Context) {
		logger := klog.FromContext(ctx)

		// 从 discoveryClient 中获取当前的资源列表，存储到 newResources 变量中
		newResources := GetDeletableResources(discoveryClient)

		// 如果 newResources 中没有任何资源，则打印一条日志和一个计数器，然后直接返回
		if len(newResources) == 0 {
			logger.V(2).Info("no resources reported by discovery, skipping garbage collector sync")
			metrics.GarbageCollectorResourcesSyncError.Inc()
			return
		}

		// 如果 newResources 中的资源和上次同步时记录的资源一样，则打印一条日志，然后直接返回
		if reflect.DeepEqual(oldResources, newResources) {
			logger.V(5).Info("no resource updates from discovery, skipping garbage collector sync")
			return
		}

		// 确保在 informer 重新同步之前，不会处理任何事件
		gc.workerLock.Lock()
		defer gc.workerLock.Unlock()

		//  第多少次
		attempt := 0
		wait.PollImmediateUntilWithContext(ctx, 100*time.Millisecond, func(ctx context.Context) (bool, error) {
            // 每次调用都+1
			attempt++

			// 如果 attempt 大于 1，则重新从 discoveryClient 中获取新的资源列表，并将其存储到 newResources 中
			if attempt > 1 {
				newResources = GetDeletableResources(discoveryClient)
				if len(newResources) == 0 {
					logger.V(2).Info("no resources reported by discovery", "attempt", attempt)
					metrics.GarbageCollectorResourcesSyncError.Inc()
					return false, nil
				}
			}

			logger.V(2).Info(
				"syncing garbage collector with updated resources from discovery",
				"attempt", attempt,
				"diff", printDiff(oldResources, newResources),
			)

			// 重置restMapper
			gc.restMapper.Reset()
			logger.V(4).Info("reset restmapper")

			// 调用 GarbageCollector 中的 resyncMonitors 方法来同步资源监视器，
			if err := gc.resyncMonitors(logger, newResources); err != nil {
				utilruntime.HandleError(fmt.Errorf("failed to sync resource monitors (attempt %d): %v", attempt, err))
				metrics.GarbageCollectorResourcesSyncError.Inc()
				return false, nil
			}
			logger.V(4).Info("resynced monitors")

			// 调用 cache.WaitForNamedCacheSync 方法来等待依赖关系图构建器同步。如果同步超时，则打印一条错误日志和一个计数器，然后返回 false
			if !cache.WaitForNamedCacheSync("garbage collector", waitForStopOrTimeout(ctx.Done(), period), func() bool {
				return gc.dependencyGraphBuilder.IsSynced(logger)
			}) {
				utilruntime.HandleError(fmt.Errorf("timed out waiting for dependency graph builder sync during GC sync (attempt %d)", attempt))
				metrics.GarbageCollectorResourcesSyncError.Inc()
				return false, nil
			}

			// success, break out of the loop
			return true, nil
		})

		// 将 newResources 中的资源列表赋值给 oldResources 变量
		oldResources = newResources
		logger.V(2).Info("synced garbage collector")
	}, period)
}
```

### GetDeletableResources

```go
func GetDeletableResources(discoveryClient discovery.ServerResourcesInterface) map[schema.GroupVersionResource]struct{} {
    // 从 discoveryClient 中获取 ServerPreferredResources
	preferredResources, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) {
			klog.Warningf("failed to discover some groups: %v", err.(*discovery.ErrGroupDiscoveryFailed).Groups)
		} else {
			klog.Warningf("failed to discover preferred resources: %v", err)
		}
	}
    // 处理空值
	if preferredResources == nil {
		return map[schema.GroupVersionResource]struct{}{}
	}

	// 只保留支持 "delete", "list", "watch" 这三个动词的资源
	deletableResources := discovery.FilteredBy(discovery.SupportsAllVerbs{Verbs: []string{"delete", "list", "watch"}}, preferredResources)
    // 将其分别解析为 GroupVersionResource，然后将其添加到 deletableGroupVersionResources map 中
	deletableGroupVersionResources := map[schema.GroupVersionResource]struct{}{}
	for _, rl := range deletableResources {
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			klog.Warningf("ignoring invalid discovered resource %q: %v", rl.GroupVersion, err)
			continue
		}
		for i := range rl.APIResources {
			deletableGroupVersionResources[schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: rl.APIResources[i].Name}] = struct{}{}
		}
	}

	return deletableGroupVersionResources
}

```

### resyncMonitors

```GO
func (gc *GarbageCollector) resyncMonitors(logger klog.Logger, deletableResources map[schema.GroupVersionResource]struct{}) error {
	if err := gc.dependencyGraphBuilder.syncMonitors(logger, deletableResources); err != nil {
		return err
	}
	gc.dependencyGraphBuilder.startMonitors(logger)
	return nil
}
```

## GraphBuilder

### 结构体

```GO
type GraphBuilder struct {
	restMapper meta.RESTMapper
	// 用于监视资源对象的变化，更新资源对象的依赖关系
	monitors    monitors
	monitorLock sync.RWMutex
	// informers是否初始化完成
	informersStarted <-chan struct{}
	// 安全退出
	stopCh <-chan struct{}
	// 跟踪 Run() 是否已被调用
	running bool
	// 记录器 用于记录资源对象变化事件的信息
	eventRecorder record.EventRecorder
	metadataClient metadata.Interface
	// 存储资源对象依赖关系图的变化
	graphChanges workqueue.RateLimitingInterface
	// 在内存中存储资源对象依赖关系图。
	uidToNode *concurrentUIDToNode
	// 存储待删除资源对象的队列
	attemptToDelete workqueue.RateLimitingInterface
    // 存储待孤立依赖对象的队列
	attemptToOrphan workqueue.RateLimitingInterface
	// 缓存已不存在的资源对象的拥有者信息
	absentOwnerCache *ReferenceCache
    // 监视资源对象的变化
	sharedInformers  informerfactory.InformerFactory
    // 存储不需要监视的资源类型
	ignoredResources map[schema.GroupResource]struct{}
}
```

#### monitors

```go
// key:GVR value:monitor
type monitors map[schema.GroupVersionResource]*monitor

type monitor struct {
    // 该接口是 k8s 中对一个资源对象的 Watcher 和 Indexer 的封装，
    // 用于监听指定资源对象的变化并且将其以指定的 IndexField  map到指定的 Indexer 中
	controller cache.Controller
    // k8s client-go的本地缓存
	store      cache.Store
	// 用于controller和store的安全退出
	stopCh chan struct{}
}

func (m *monitor) Run() {
	m.controller.Run(m.stopCh)
}
```

#### concurrentUIDToNode

```go
type concurrentUIDToNode struct {
	uidToNodeLock sync.RWMutex
	uidToNode     map[types.UID]*node
}

// 添加node
func (m *concurrentUIDToNode) Write(node *node) {
	m.uidToNodeLock.Lock()
	defer m.uidToNodeLock.Unlock()
	m.uidToNode[node.identity.UID] = node
}

// 读取node
func (m *concurrentUIDToNode) Read(uid types.UID) (*node, bool) {
	m.uidToNodeLock.RLock()
	defer m.uidToNodeLock.RUnlock()
	n, ok := m.uidToNode[uid]
	return n, ok
}

// 删除node
func (m *concurrentUIDToNode) Delete(uid types.UID) {
	m.uidToNodeLock.Lock()
	defer m.uidToNodeLock.Unlock()
	delete(m.uidToNode, uid)
}
```

### node

```go
type node struct {
    // 对象引用，用于唯一标识该node
	identity objectReference
	// 用于保护dependents字段
	dependentsLock sync.RWMutex
	// 将依赖该node的其他node指向该node 该node的identity作为metadata.ownerReference
    // 比如该node是replicaset 那这里存的是pod资源对象
	dependents map[*node]struct{}
	// 该对象是否被删除且需要删除所有依赖该node的对象
	deletingDependents     bool
    // 保护deletingDependents字段
	deletingDependentsLock sync.RWMutex
	// 指示该对象是否被删除
	beingDeleted     bool
    // 用于保护beingDeleted字段
	beingDeletedLock sync.RWMutex
	// 指示该对象是否仅在虚拟环境中构建且从未被观察到
	virtual     bool
    // 用于保护virtual字段
	virtualLock sync.RWMutex
	// 该node的所有者 在处理Update事件时，需要将更新后的OwnerReference与图中记录的所有者进行比较
	owners []metav1.OwnerReference
}

// deep clone
func (n *node) clone() *node {
	c := &node{
		identity:           n.identity,
		dependents:         make(map[*node]struct{}, len(n.dependents)),
		deletingDependents: n.deletingDependents,
		beingDeleted:       n.beingDeleted,
		virtual:            n.virtual,
		owners:             make([]metav1.OwnerReference, 0, len(n.owners)),
	}
	for dep := range n.dependents {
		c.dependents[dep] = struct{}{}
	}
	for _, owner := range n.owners {
		c.owners = append(c.owners, owner)
	}
	return c
}

// 标记该node正在被删除
func (n *node) markBeingDeleted() {
	n.beingDeletedLock.Lock()
	defer n.beingDeletedLock.Unlock()
	n.beingDeleted = true
}

// 该node是否正在被删除
func (n *node) isBeingDeleted() bool {
	n.beingDeletedLock.RLock()
	defer n.beingDeletedLock.RUnlock()
	return n.beingDeleted
}

// 标记该node已经被观察到，不再是虚拟node
func (n *node) markObserved() {
	n.virtualLock.Lock()
	defer n.virtualLock.Unlock()
	n.virtual = false
}

// 检查该node是否已经被观察到
func (n *node) isObserved() bool {
	n.virtualLock.RLock()
	defer n.virtualLock.RUnlock()
	return !n.virtual
}

// 标记该node的依赖正在被删除
func (n *node) markDeletingDependents() {
	n.deletingDependentsLock.Lock()
	defer n.deletingDependentsLock.Unlock()
	n.deletingDependents = true
}

// 检查该node的依赖是否正在被删除
func (n *node) isDeletingDependents() bool {
	n.deletingDependentsLock.RLock()
	defer n.deletingDependentsLock.RUnlock()
	return n.deletingDependents
}

// 一个依赖node添加到该node的dependents map中
func (n *node) addDependent(dependent *node) {
	n.dependentsLock.Lock()
	defer n.dependentsLock.Unlock()
	n.dependents[dependent] = struct{}{}
}

// 将一个依赖node从该node的dependents map中删除
func (n *node) deleteDependent(dependent *node) {
	n.dependentsLock.Lock()
	defer n.dependentsLock.Unlock()
	delete(n.dependents, dependent)
}

// 获取该node的dependents map的长度
func (n *node) dependentsLength() int {
	n.dependentsLock.RLock()
	defer n.dependentsLock.RUnlock()
	return len(n.dependents)
}

// 获取该node的dependents map中所有的依赖node。
func (n *node) getDependents() []*node {
	n.dependentsLock.RLock()
	defer n.dependentsLock.RUnlock()
	var ret []*node
	for dep := range n.dependents {
		ret = append(ret, dep)
	}
	return ret
}

// 获取该node的dependents map中所有阻止该node删除的依赖node。其中阻止删除是指依赖node的OwnerReference中有
// BlockOwnerDeletion为true的条目，且该条目的UID等于该node的identity中的UID。
func (n *node) blockingDependents() []*node {
	dependents := n.getDependents()
	var ret []*node
	for _, dep := range dependents {
		for _, owner := range dep.owners {
			if owner.UID == n.identity.UID && owner.BlockOwnerDeletion != nil && *owner.BlockOwnerDeletion {
				ret = append(ret, dep)
			}
		}
	}
	return ret
}
```

**objectReference**

```GO
type objectReference struct {
	metav1.OwnerReference
	// 这是动态client所需要的
	Namespace string
}

// String is used when logging an objectReference in text format.
func (s objectReference) String() string {
	return fmt.Sprintf("[%s/%s, namespace: %s, name: %s, uid: %s]", s.APIVersion, s.Kind, s.Namespace, s.Name, s.UID)
}

// MarshalLog is used when logging an objectReference in JSON format.
func (s objectReference) MarshalLog() interface{} {
	return struct {
		Name       string    `json:"name"`
		Namespace  string    `json:"namespace"`
		APIVersion string    `json:"apiVersion"`
		UID        types.UID `json:"uid"`
	}{
		Namespace:  s.Namespace,
		Name:       s.Name,
		APIVersion: s.APIVersion,
		UID:        s.UID,
	}
}
```

### syncMonitors

```GO
// syncMonitors 根据给定的 resources 列表来同步监控器 monitors，
// 可能会添加新的监控器、保留原有监控器或删除不再需要的监控器。
// logger 用于记录日志，resources 是需要监控的资源列表，以 GroupVersionResource 的形式提供。
// 返回同步过程中可能出现的错误，这些错误是聚合的，而不是单个返回。
func (gb *GraphBuilder) syncMonitors(logger klog.Logger, resources map[schema.GroupVersionResource]struct{}) error {
    // 获取监控器锁，防止多个 goroutine 并发修改监控器。
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()
	
    // 获取要删除的监控器列表 toRemove。
	// 如果 toRemove 为 nil，则创建一个新的 monitors。
	toRemove := gb.monitors
	if toRemove == nil {
		toRemove = monitors{}
	}
    // 创建一个新的 current，表示要保留的监控器列表。
	current := monitors{}
    // 创建一个空的错误列表 errs，用于记录同步过程中可能出现的错误
	errs := []error{}
    // 记录保留的监控器数量 kept 和添加的监控器数量 added。
	kept := 0
	added := 0
    // 遍历资源列表中的每个资源
	for resource := range resources {
        // 如果该资源被忽略，则跳过
		if _, ok := gb.ignoredResources[resource.GroupResource()]; ok {
			continue
		}
        // 如果该资源在 toRemove 中，则将其添加到 current 中，保留原有监控器
		if m, ok := toRemove[resource]; ok {
			current[resource] = m
			delete(toRemove, resource)
			kept++
			continue
		}
        // 否则，需要添加新的监控器。
		// 首先获取该资源的 Kind。
		kind, err := gb.restMapper.KindFor(resource)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't look up resource %q: %v", resource, err))
			continue
		}
        // 创建新的 controller 和 store，用于监控该资源
		c, s, err := gb.controllerFor(logger, resource, kind)
		if err != nil {
			errs = append(errs, fmt.Errorf("couldn't start monitor for resource %q: %v", resource, err))
			continue
		}
        // 将新创建的监控器添加到 current 中
		current[resource] = &monitor{store: s, controller: c}
		added++
	}
	gb.monitors = current
	
    // 将 toRemove 中剩余的监控器停止并删除
	for _, monitor := range toRemove {
		if monitor.stopCh != nil {
			close(monitor.stopCh)
		}
	}

	logger.V(4).Info("synced monitors", "added", added, "kept", kept, "removed", len(toRemove))
	// NewAggregate returns nil if errs is 0-length
	return utilerrors.NewAggregate(errs)
}
```

#### controllerFor

```go
// controllerFor 根据给定的 resource 和 kind 创建一个监控该资源的 controller 和 store。
// logger 用于记录日志，resource 表示需要监控的资源，kind 表示该资源的 Kind。
// 返回创建的 controller 和 store，以及可能出现的错误。
func (gb *GraphBuilder) controllerFor(logger klog.Logger, resource schema.GroupVersionResource, kind schema.GroupVersionKind) (cache.Controller, cache.Store, error) {
    // 创建 ResourceEventHandlerFuncs。
	handlers := cache.ResourceEventHandlerFuncs{
		// 将新增的对象添加到 dependencyGraphBuilder 的 graphChanges 中。
		AddFunc: func(obj interface{}) {
			event := &event{
				eventType: addEvent,
				obj:       obj,
				gvk:       kind,
			}
			gb.graphChanges.Add(event)
		},
        // 将更新的对象添加到 graphChanges 中。
		UpdateFunc: func(oldObj, newObj interface{}) {
			// TODO: 检查 ownerRefs、finalizers 和 DeletionTimestamp 是否有差异，如果没有则忽略该更新。
			event := &event{
				eventType: updateEvent,
				obj:       newObj,
				oldObj:    oldObj,
				gvk:       kind,
			}
			gb.graphChanges.Add(event)
		},
        // 将删除的对象添加到 graphChanges 中
		DeleteFunc: func(obj interface{}) {
			// 如果 obj 是 cache.DeletedFinalStateUnknown 类型，则需要将其解包。
			if deletedFinalStateUnknown, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = deletedFinalStateUnknown.Obj
			}
			event := &event{
				eventType: deleteEvent,
				obj:       obj,
				gvk:       kind,
			}
			gb.graphChanges.Add(event)
		},
	}
	// 获取共享 informer
	shared, err := gb.sharedInformers.ForResource(resource)
	if err != nil {
		logger.V(4).Error(err, "unable to use a shared informer", "resource", resource, "kind", kind)
		return nil, nil, err
	}
	logger.V(4).Info("using a shared informer", "resource", resource, "kind", kind)
	// 将 handlers 添加到共享 informer 的事件处理程序中。
	// 使用 ResourceResyncTime 作为同步周期。
	shared.Informer().AddEventHandlerWithResyncPeriod(handlers, ResourceResyncTime)
    // 返回创建的 controller 和 store。
	return shared.Informer().GetController(), shared.Informer().GetStore(), nil
}
```

### startMonitors

```go
func (gb *GraphBuilder) startMonitors(logger klog.Logger) 
	// 加锁
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()
	
	// 如果 GraphBuilder 的状态不是正在运行中，则直接返回，不做任何操作
	if !gb.running {
		return
	}

	// 等待 informer 启动，以确保所有控制器在初始化后才会收到事件
	<-gb.informersStarted

	// 获取所有的 monitors
	monitors := gb.monitors
	// 初始化已经启动的 monitor 数量
	started := 0
	// 遍历所有的 monitors
	for _, monitor := range monitors {
        // 如果该 monitor 还未启动，则启动它
		if monitor.stopCh == nil {
			monitor.stopCh = make(chan struct{})
            // 启动 informer，以确保 informer 可以正确工作
			gb.sharedInformers.Start(gb.stopCh)
            // 启动goroutine 执行每个monitor的run
			go monitor.Run()
            // 更新已经启动的 monitor 数量
			started++
		}
	}
	logger.V(4).Info("started new monitors", "new", started, "current", len(monitors))
}
```

### IsSynced

```go
// 判断所有额informer时候同步完成
func (gb *GraphBuilder) IsSynced(logger klog.Logger) bool {
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()

	if len(gb.monitors) == 0 {
		logger.V(4).Info("garbage controller monitor not synced: no monitors")
		return false
	}

	for resource, monitor := range gb.monitors {
		if !monitor.controller.HasSynced() {
			logger.V(4).Info("garbage controller monitor not yet synced", "resource", resource)
			return false
		}
	}
	return true
}
```

### enqueueVirtualDeleteEvent

````GO
func (gb *GraphBuilder) enqueueVirtualDeleteEvent(ref objectReference) {
    // 解析 APIVersion，获取 group 和 version 信息
	gv, _ := schema.ParseGroupVersion(ref.APIVersion)
    // 将事件添加到 graphChanges 中
	gb.graphChanges.Add(&event{
        // 标记事件为虚拟事件
		virtual:   true,
        // 标记事件类型为删除事件
		eventType: deleteEvent,
        // 标记事件对应的 group、version 和 kind
		gvk:       gv.WithKind(ref.Kind),
        // 创建一个 MetadataOnlyObject，包含事件对应的对象信息
		obj: &metaonly.MetadataOnlyObject{
			TypeMeta:   metav1.TypeMeta{APIVersion: ref.APIVersion, Kind: ref.Kind},
			ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, UID: ref.UID, Name: ref.Name},
		},
	})
}
````

### Run

```go
func (gb *GraphBuilder) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	logger.Info("Running", "component", "GraphBuilder")
	defer logger.Info("Stopping", "component", "GraphBuilder")

	// 设置停止通道
	gb.monitorLock.Lock()
	gb.stopCh = ctx.Done()
	gb.running = true
	gb.monitorLock.Unlock()

	// 启动监视器并开始更改处理，直到 chan 被关闭
	gb.startMonitors(logger)
    // 循环，每隔 1 秒调用 gb.runProcessGraphChanges(logger) 函数，直到 ctx.Done() 信号被发送，即 chan 被关闭。
	// runProcessGraphChanges 处理以来图表变化
	wait.Until(func() { gb.runProcessGraphChanges(logger) }, 1*time.Second, ctx.Done())
	
    // 下面都是wait.Until执行完成 被退出了 才会执行
	// 停止所有的 monitors
	gb.monitorLock.Lock()
	defer gb.monitorLock.Unlock()
	monitors := gb.monitors
	stopped := 0
    // 停止所有的monitors
	for _, monitor := range monitors {
		if monitor.stopCh != nil {
			stopped++
			close(monitor.stopCh)
		}
	}

	// 重置 monitors，以便可以安全地重新运行/同步 GraphBuilder
	gb.monitors = nil
	logger.Info("stopped monitors", "stopped", stopped, "total", len(monitors))
}

```

#### runProcessGraphChanges

```go
func (gb *GraphBuilder) runProcessGraphChanges(logger klog.Logger) {
	for gb.processGraphChanges(logger) {
	}
}
```

**processGraphChanges**

该函数的作用是处理 Kubernetes 资源对象的变化事件。函数首先从 graphChanges 队列中获取一个事件 item，并检查是否获取成功。如果获取失败，则返回 false。否则，将事件转换为 *event 类型，然后获取事件中的对象 obj，获取对象的元数据 accessor，然后记录一些调试信息到日志中。

随后，该函数根据事件的类型和 uidToNode 映射表中是否已经存在该对象，执行相应的操作：

- 如果该事件是一个新增或修改事件，且 uidToNode 映射表中不存在该对象，则创建新的节点，并将其插入到 uidToNode 映射表中。接着，函数调用 processTransitions 函数进一步处理该事件。
- 如果该事件是一个新增或修改事件，且 uidToNode 映射表中已经存在该对象，则更新现有节点的信息（例如 owners 和 beingDeleted 标识符等），并调用 addUnblockedOwnersToDeleteQueue、addDependentToOwners 和 removeDependentFromOwners 等函数更新该节点的从属关系。
- 如果该事件是一个删除事件，且 uidToNode 映射表中存在该对象，则检查该节点是否为虚拟节点，如果是，则需要根据依赖项对其进行特殊处理（例如尝试删除其依赖项，并查找其他可能的节点替代该虚拟节点）。如果该节点不是虚拟节点，或者虚拟节点的依赖项已被处理，则从 uidToNode 映射表中删除该节点，并调用 attemptToDelete.Add 和 attemptToDelete.AddRateLimited 将该节点的从属项添加到删除队列中，以及将其所有者添加到 attemptToDelete 队列中（如果该节点的所有者正在删除其从属项）。

最后，该函数返回 true。如果 graphChanges 队列中还有未处理的事件，则该函数将在下一次调用时继续处理。

```go
func (gb *GraphBuilder) processGraphChanges(logger klog.Logger) bool {
    // 从 graphChanges 中获取一个变化 item，如果 quit 为 true，则返回 false
	item, quit := gb.graphChanges.Get()
	if quit {
		return false
	}
   	// 函数结束时确保从 graphChanges 队列中删除该事件
	defer gb.graphChanges.Done(item)
	event, ok := item.(*event)
    // 检查获取到的事件是否是 event 类型
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expect a *event, got %v", item))
		return true
	}
	obj := event.obj
    // 获取对象的 accessor（可访问器），方便后续访问对象的属性
	accessor, err := meta.Accessor(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("cannot access obj: %v", err))
		return true
	}

	logger.V(5).Info("GraphBuilder process object",
		"apiVersion", event.gvk.GroupVersion().String(),
		"kind", event.gvk.Kind,
		"object", klog.KObj(accessor),
		"uid", string(accessor.GetUID()),
		"eventType", event.eventType,
		"virtual", event.virtual,
	)

	// 检查节点是否已存在
	existingNode, found := gb.uidToNode.Read(accessor.GetUID())
	if found && !event.virtual && !existingNode.isObserved() {
        // 标记节点已被观察
		// 1. 这依赖于 graphChanges 仅包含实际通知器的添加/更新事件
		// 2. 这使得跟踪虚拟节点存在性的东西停止轮询并依赖于通知器事件
		observedIdentity := identityFromEvent(event, accessor)
		if observedIdentity != existingNode.identity {
			// 找到与我们观察的不匹配的从属，添加到 attemptToDelete 队列中
			_, potentiallyInvalidDependents := partitionDependents(existingNode.getDependents(), observedIdentity)
			// 将可能无效的 dependents 添加到 attemptToDelete 队列中
            // 如果其 owners 仍然是可靠的，则 attemptToDelete 将是无操作
            // 这涵盖了错误的子 -> 好的父观察序列
            // 良好的父 -> 坏的子观察序列在 addDependentToOwners 中处理
			for _, dep := range potentiallyInvalidDependents {
				if len(observedIdentity.Namespace) > 0 && dep.identity.Namespace != observedIdentity.Namespace {
					// Namespace 不匹配，这肯定是错误的
					logger.V(2).Info("item references an owner but does not match namespaces",
						"item", dep.identity,
						"owner", observedIdentity,
					)
					gb.reportInvalidNamespaceOwnerRef(dep, observedIdentity.UID)
				}
				gb.attemptToDelete.Add(dep)
			}

			// make a copy (so we don't modify the existing node in place), store the observed identity, and replace the virtual node
			logger.V(2).Info("replacing virtual item with observed item",
				"virtual", existingNode.identity,
				"observed", observedIdentity,
			)
            // 创建一个节点的副本，存储观察到的标识符，并替换虚拟节点
			existingNode = existingNode.clone()
			existingNode.identity = observedIdentity
			gb.uidToNode.Write(existingNode)
		}
		existingNode.markObserved()
	}
	switch {
	case (event.eventType == addEvent || event.eventType == updateEvent) && !found:
        //  如果事件类型为 addEvent 或 updateEvent，且节点不存在，则进行下列操作
        // 创建新节点并插入到图中
		newNode := &node{
			identity:           identityFromEvent(event, accessor),
			dependents:         make(map[*node]struct{}),
			owners:             accessor.GetOwnerReferences(),
			deletingDependents: beingDeleted(accessor) && hasDeleteDependentsFinalizer(accessor),
			beingDeleted:       beingDeleted(accessor),
		}
		gb.insertNode(logger, newNode)
		// 如果事件中包含新的对象，进一步处理该事件
		gb.processTransitions(logger, event.oldObj, accessor, newNode)
	case (event.eventType == addEvent || event.eventType == updateEvent) && found:
		// 如果事件类型为 addEvent 或 updateEvent，且节点已存在，则进行下列操作
        // 处理 ownerReferences 的更改
		added, removed, changed := referencesDiffs(existingNode.owners, accessor.GetOwnerReferences())
		if len(added) != 0 || len(removed) != 0 || len(changed) != 0 {
			// 检查更改后的依赖关系图是否取消了正在等待其依赖项被删除的所有者的阻塞
			gb.addUnblockedOwnersToDeleteQueue(logger, removed, changed)
			// 更新节点本身
			existingNode.owners = accessor.GetOwnerReferences()
			// 将节点添加到其新所有者的从属列表中
			gb.addDependentToOwners(logger, existingNode, added)
			// 从不再在节点所有者列表中的节点的从属列表中删除该节点
			gb.removeDependentFromOwners(existingNode, removed)
		}

		if beingDeleted(accessor) {
            // 标记节点正在被删除
			existingNode.markBeingDeleted()
		}
        // 处理节点变化
		gb.processTransitions(logger, event.oldObj, accessor, existingNode)
	case event.eventType == deleteEvent:
        // 如果事件类型为 deleteEvent，则进行下列操作
		if !found {
             // 如果节点不存在，则输出日志并返回 true
			logger.V(5).Info("item doesn't exist in the graph, this shouldn't happen",
				"item", accessor.GetUID(),
			)
			return true
		}

		removeExistingNode := true

		if event.virtual {
			// 这是虚拟删除事件，不是从通知器观察到的事件
			deletedIdentity := identityFromEvent(event, accessor)
			if existingNode.virtual {
				// 现有节点也是虚拟节点，我们不确定其坐标。
				// 看看是否有任何从属以其他坐标引用此所有者。
				if matchingDependents, nonmatchingDependents := partitionDependents(existingNode.getDependents(), deletedIdentity); len(nonmatchingDependents) > 0 {
					// 一些从属在坐标上不一致，因此不要从图中删除现有虚拟节点
					removeExistingNode = false

					if len(matchingDependents) > 0 {
						// 将观察到的删除标识符标记为不存在
						gb.absentOwnerCache.Add(deletedIdentity)
						// 尝试删除与已验证的已删除标识符匹配的从属项
						for _, dep := range matchingDependents {
							gb.attemptToDelete.Add(dep)
						}
					}
					// 如果删除事件已验证 existingNode.identity 不存在...
					if existingNode.identity == deletedIdentity {
						// 找到我们的非匹配从属以其他标识
						replacementIdentity := getAlternateOwnerIdentity(nonmatchingDependents, deletedIdentity)
						if replacementIdentity != nil {
							// 用我们的其他潜在标识符之一替换现有虚拟节点
							replacementNode := existingNode.clone()
							replacementNode.identity = *replacementIdentity
							gb.uidToNode.Write(replacementNode)
							// 将新的虚拟节点添加回 attemptToDelete 队列
							gb.attemptToDelete.AddRateLimited(replacementNode)
						}
					}
				}

			} else if existingNode.identity != deletedIdentity {
				// 不要基于虚拟删除事件从图中删除现有的实际节点
				removeExistingNode = false

				// 通过通知器观察到的现有节点与虚拟删除事件的坐标不一致
				matchingDependents, _ := partitionDependents(existingNode.getDependents(), deletedIdentity)

				if len(matchingDependents) > 0 {
					// 将观察到的删除标识符标记为不存在
					gb.absentOwnerCache.Add(deletedIdentity)
					// 尝试删除与已验证的已删除标识符匹配的从属项
					for _, dep := range matchingDependents {
						gb.attemptToDelete.Add(dep)
					}
				}
			}
		}

		if removeExistingNode {
			// removeNode 更新图形
			gb.removeNode(existingNode)
			existingNode.dependentsLock.RLock()
			defer existingNode.dependentsLock.RUnlock()
			if len(existingNode.dependents) > 0 {
                // 将当前删除的节点添加到 absentOwnerCache 中
				gb.absentOwnerCache.Add(identityFromEvent(event, accessor))
			}
			for dep := range existingNode.dependents {
                // 将从属添加到 attemptToDelete 队列中
				gb.attemptToDelete.Add(dep)
			}
			for _, owner := range existingNode.owners {
				ownerNode, found := gb.uidToNode.Read(owner.UID)
				if !found || !ownerNode.isDeletingDependents() {
					continue
				}
				// 这是为了让 attemptToDeleteItem 检查所有者的所有从属项是否已删除，如果是，则将删除所有者。
				gb.attemptToDelete.Add(ownerNode)
			}
		}
	}
	return true
}
```

##### identityFromEvent

```go


func identityFromEvent(event *event, accessor metav1.Object) objectReference {
	return objectReference{
		OwnerReference: metav1.OwnerReference{
			APIVersion: event.gvk.GroupVersion().String(),
			Kind:       event.gvk.Kind,
			UID:        accessor.GetUID(),
			Name:       accessor.GetName(),
		},
		Namespace: accessor.GetNamespace(),
	
```

###### ownerReferenceMatchesCoordinates

````GO
func ownerReferenceMatchesCoordinates(a, b metav1.OwnerReference) bool {
	return a.UID == b.UID && a.Name == b.Name && a.Kind == b.Kind && a.APIVersion == b.APIVersion
}
````

##### partitionDependents

```GO
// 将依赖项列表根据其所有者的身份信息划分为两个子列表（匹配和不匹配）。传入参数为一个依赖项节点的切片 dependents 和一个 objectReference 类型的 matchOwnerIdentity 对象
func partitionDependents(dependents []*node, matchOwnerIdentity objectReference) (matching, nonmatching []*node) {
    // matchOwnerIdentity的Namespace 属性是否为空
	ownerIsNamespaced := len(matchOwnerIdentity.Namespace) > 0
	for i := range dependents {
		dep := dependents[i]
		foundMatch := false
		foundMismatch := false
		// 如果 ownerIsNamespaced 为 true 且 matchOwnerIdentity 的 Namespace 属性不等于 dep 的 Namespace 属性，则将 foundMismatch 标记为 true
		if ownerIsNamespaced && matchOwnerIdentity.Namespace != dep.identity.Namespace {
			// all references to the parent do not match, since the dependent namespace does not match the owner
			foundMismatch = true
		} else {
            // 遍历 dep 的所有者引用 ownerRef，如果找到一个 ownerRef 的 UID 属性与 matchOwnerIdentity 的 UID 属性相等，则检查 ownerRef 是否与 matchOwnerIdentity 的 OwnerReference 属性匹配。
            // 如果匹配，则将 foundMatch 标记为 true；否则将 foundMismatch 标记为 true
			for _, ownerRef := range dep.owners {
				// ... find the ownerRef with a matching uid ...
				if ownerRef.UID == matchOwnerIdentity.UID {
					// ... and check if it matches all coordinates
					if ownerReferenceMatchesCoordinates(ownerRef, matchOwnerIdentity.OwnerReference) {
						foundMatch = true
					} else {
						foundMismatch = true
					}
				}
			}
		}
		// 如果 foundMatch 为 true，则将 dep 添加到 matching 切片中；如果 foundMismatch 为 true，则将 dep 添加到 nonmatching 切片中
		if foundMatch {
			matching = append(matching, dep)
		}
		if foundMismatch {
			nonmatching = append(nonmatching, dep)
		}
	}
	return matching, nonmatching
}

```

##### reportInvalidNamespaceOwnerRef

```go
// 报告存在无效的所有者引用（即所有者引用指向不存在的命名空间）的依赖项节点 n。传入参数包括依赖项节点 n 和无效所有者引用的 UID 属性 invalidOwnerUID
func (gb *GraphBuilder) reportInvalidNamespaceOwnerRef(n *node, invalidOwnerUID types.UID) {
	var invalidOwnerRef metav1.OwnerReference
	var found = false
    // 遍历 n 的所有者引用，找到与 invalidOwnerUID 相等的 OwnerReference 对象，并将其保存在 invalidOwnerRef 变量中。
	for _, ownerRef := range n.owners {
		if ownerRef.UID == invalidOwnerUID {
			invalidOwnerRef = ownerRef
			found = true
			break
		}
	}
    // 如果无法找到相应的 OwnerReference，则直接返回。
	if !found {
		return
	}
    // 表示依赖项节点 n 的身份信息
	ref := &v1.ObjectReference{
		Kind:       n.identity.Kind,
		APIVersion: n.identity.APIVersion,
		Namespace:  n.identity.Namespace,
		Name:       n.identity.Name,
		UID:        n.identity.UID,
	}
    // 表示了一个无效的所有者引用
	invalidIdentity := objectReference{
		OwnerReference: metav1.OwnerReference{
			Kind:       invalidOwnerRef.Kind,
			APIVersion: invalidOwnerRef.APIVersion,
			Name:       invalidOwnerRef.Name,
			UID:        invalidOwnerRef.UID,
		},
		Namespace: n.identity.Namespace,
	}
    // 向事件记录器添加一个事件
	gb.eventRecorder.Eventf(ref, v1.EventTypeWarning, "OwnerRefInvalidNamespace", "ownerRef %s does not exist in namespace %q", invalidIdentity, n.identity.Namespace)
}
```

##### insertNode

```go
func (gb *GraphBuilder) insertNode(logger klog.Logger, n *node) {
	gb.uidToNode.Write(n)
	gb.addDependentToOwners(logger, n, n.owners)
}
```

##### processTransitions

```go
func (gb *GraphBuilder) processTransitions(logger klog.Logger, oldObj interface{}, newAccessor metav1.Object, n *node) {
    // 判断节点是否等待其依赖项被孤立，如果是，则将节点 n 添加到 attemptToOrphan 队列中，并立即返回
	if startsWaitingForDependentsOrphaned(oldObj, newAccessor) {
		logger.V(5).Info("add item to attemptToOrphan", "item", n.identity)
		gb.attemptToOrphan.Add(n)
		return
	}
    // 判断节点是否等待其依赖项被删除。如果是，则将节点 n 添加到 attemptToDelete 队列中，并设置 n 的 deletingDependents 标志为 true。此外，函数还将 n 所有的依赖项节点添加到 attemptToDelete 队列中
	if startsWaitingForDependentsDeleted(oldObj, newAccessor) {
		logger.V(2).Info("add item to attemptToDelete, because it's waiting for its dependents to be deleted", "item", n.identity)
		// if the n is added as a "virtual" node, its deletingDependents field is not properly set, so always set it here.
		n.markDeletingDependents()
		for dep := range n.dependents {
			gb.attemptToDelete.Add(dep)
		}
		gb.attemptToDelete.Add(n)
	}
}
```

###### startsWaitingForDependentsOrphaned

```go
func startsWaitingForDependentsOrphaned(oldObj interface{}, newAccessor metav1.Object) bool {
	return deletionStartsWithFinalizer(oldObj, newAccessor, metav1.FinalizerOrphanDependents)
}

const FinalizerOrphanDependents = "orphan"
```

**deletionStartsWithFinalizer**

```go
func deletionStartsWithFinalizer(oldObj interface{}, newAccessor metav1.Object, matchingFinalizer string) bool {
	// 判断新的对象是否正在被删除并且是否有指定的终结器 如果不是，则返回 false。
	if !beingDeleted(newAccessor) || !hasFinalizer(newAccessor, matchingFinalizer) {
		return false
	}

	// 接着，函数检查旧的对象是否为 nil，如果是，则返回 true。
	if oldObj == nil {
		return true
	}
	oldAccessor, err := meta.Accessor(oldObj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("cannot access oldObj: %v", err))
		return false
	}
    // 判断旧对象是否正在被删除并且是否有指定的终结器。如果不是，则返回 true；否则，返回 false。因此，该函数用于判断对象的删除状态和终结器的状态是否发生了变化。
	return !beingDeleted(oldAccessor) || !hasFinalizer(oldAccessor, matchingFinalizer)
}


func beingDeleted(accessor metav1.Object) bool {
	return accessor.GetDeletionTimestamp() != nil
}


func hasFinalizer(accessor metav1.Object, matchingFinalizer string) bool {
	finalizers := accessor.GetFinalizers()
	for _, finalizer := range finalizers {
		if finalizer == matchingFinalizer {
			return true
		}
	}
	return false
}
```

###### startsWaitingForDependentsDeleted

```go
func startsWaitingForDependentsDeleted(oldObj interface{}, newAccessor metav1.Object) bool {
	return deletionStartsWithFinalizer(oldObj, newAccessor, metav1.FinalizerDeleteDependents)
}

const FinalizerDeleteDependents = "foregroundDeletion"
```

##### addUnblockedOwnersToDeleteQueue

```go
// 将 ownerReferences 中 BlockOwnerDeletion 为 true 的 owner 节点添加到 attemptToDelete 队列中，以尝试删除这些节点
func (gb *GraphBuilder) addUnblockedOwnersToDeleteQueue(logger klog.Logger, removed []metav1.OwnerReference, changed []ownerRefPair) {
    // 处理被移除的 owner
	for _, ref := range removed {
        // 如果被移除的 owner 的 BlockOwnerDeletion 为 true，则将与该 owner 对应的节点添加到attemptToDelete 队列中
		if ref.BlockOwnerDeletion != nil && *ref.BlockOwnerDeletion {
			node, found := gb.uidToNode.Read(ref.UID)
			if !found {
				logger.V(5).Info("cannot find uid in uidToNode", "uid", ref.UID)
				continue
			}
			gb.attemptToDelete.Add(node)
		}
	}
    // 处理 owner 发生变化的情况
	for _, c := range changed {
        // 如果变化前的 BlockOwnerDeletion 为 true，变化后的 BlockOwnerDeletion 为 false，则将与该 owner 对应的节点添加到 attemptToDelete 队列中
		wasBlocked := c.oldRef.BlockOwnerDeletion != nil && *c.oldRef.BlockOwnerDeletion
		isUnblocked := c.newRef.BlockOwnerDeletion == nil || (c.newRef.BlockOwnerDeletion != nil && !*c.newRef.BlockOwnerDeletion)
		if wasBlocked && isUnblocked {
			node, found := gb.uidToNode.Read(c.newRef.UID)
			if !found {
				logger.V(5).Info("cannot find uid in uidToNode", "uid", c.newRef.UID)
				continue
			}
			gb.attemptToDelete.Add(node)
		}
	}
}
```

##### addDependentToOwners

```go
将一个资源的依赖关系加入到垃圾回收图中
func (gb *GraphBuilder) addDependentToOwners(logger klog.Logger, n *node, owners []metav1.OwnerReference) {
	// track if some of the referenced owners already exist in the graph and have been observed,
	// and the dependent's ownerRef does not match their observed coordinates
	hasPotentiallyInvalidOwnerReference := false
	// 遍历 owners 数组
	for _, owner := range owners {
        // 从 uidToNode 中读取 owner 对应的节点
		ownerNode, ok := gb.uidToNode.Read(owner.UID)
		if !ok {
			// 如果 owner 对应的节点不存在，则创建一个 virtual 节点
			// virtual 节点用于表示 owner 存在，但是在垃圾回收过程中需要被删除的情况
			ownerNode = &node{
				identity: objectReference{
					OwnerReference: ownerReferenceCoordinates(owner),
					Namespace:      n.identity.Namespace,
				},
				dependents: make(map[*node]struct{}),
				virtual:    true,
			}
			logger.V(5).Info("add virtual item", "identity", ownerNode.identity)
			gb.uidToNode.Write(ownerNode)
		}
        // 将 n 作为 ownerNode 的依赖加入 ownerNode 的 dependents 中
		ownerNode.addDependent(n)
        // 如果 ownerNode 是 virtual 节点
		if !ok {
			// 将 ownerNode 加入 attemptToDelete 中
			// 在后续垃圾回收的过程中，如果 owner 节点确实不存在，则会删除这个虚拟节点
			gb.attemptToDelete.Add(ownerNode)
		} else if !hasPotentiallyInvalidOwnerReference {
            // 判断 ownerNode 是否存在问题
			// 如果 ownerNode 的 namespace 和 n 不匹配，而且 ownerNode 已经被观察过，则需要删除 n
			ownerIsNamespaced := len(ownerNode.identity.Namespace) > 0
			if ownerIsNamespaced && ownerNode.identity.Namespace != n.identity.Namespace {
				if ownerNode.isObserved() {
					// The owner node has been observed via an informer
					// the dependent's namespace doesn't match the observed owner's namespace, this is definitely wrong.
					// cluster-scoped owners can be referenced as an owner from any namespace or cluster-scoped object.
					logger.V(2).Info("item references an owner but does not match namespaces", "item", n.identity, "owner", ownerNode.identity)
					gb.reportInvalidNamespaceOwnerRef(n, owner.UID)
				}
				hasPotentiallyInvalidOwnerReference = true
			} else if !ownerReferenceMatchesCoordinates(owner, ownerNode.identity.OwnerReference) {
				// 如果 ownerNode 的 ownerReference 和 owner 不匹配，而且 ownerNode 已经被观察过，则需要关注这个 ownerNode 是否存在问题
				if ownerNode.isObserved() {
					// The owner node has been observed via an informer
					// n's owner reference doesn't match the observed identity, this might be wrong.
					logger.V(2).Info("item references an owner with coordinates that do not match the observed identity", "item", n.identity, "owner", ownerNode.identity)
				}
				hasPotentiallyInvalidOwnerReference = true
			} else if !ownerIsNamespaced && ownerNode.identity.Namespace != n.identity.Namespace && !ownerNode.isObserved() {
				// 如果发现了这样的 ownerNode，就将 hasPotentiallyInvalidOwnerReference 设置为 true
				hasPotentiallyInvalidOwnerReference = true
			}
		}
	}

	if hasPotentiallyInvalidOwnerReference {
		// 将它的 dependent node 加入 attemptToDelete 以便在垃圾回收处理器中验证它的 parent references，如果所有的 owner references 都被确认不存在，则删除 dependent node
		gb.attemptToDelete.Add(n)
	}
}
```

##### removeDependentFromOwners

```GO
// 从节点的所有Owner中删除一个Dependent节点
func (gb *GraphBuilder) removeDependentFromOwners(n *node, owners []metav1.OwnerReference) {
	for _, owner := range owners {
		ownerNode, ok := gb.uidToNode.Read(owner.UID)
		if !ok {
			continue
		}
		ownerNode.deleteDependent(n)
	}
}
```

##### getAlternateOwnerIdentity

```GO
// 在给定的依赖关系中找到与已确认不存在的OwnerReference匹配的所有备选OwnerReference中最小的一个
func getAlternateOwnerIdentity(deps []*node, verifiedAbsentIdentity objectReference) *objectReference {
    // 首先判断已确认不存在的OwnerReference的命名空间是否为空，用来判断这个Owner是否是集群范围的
	absentIdentityIsClusterScoped := len(verifiedAbsentIdentity.Namespace) == 0
	// 用来存放备选的OwnerReference
	seenAlternates := map[objectReference]bool{verifiedAbsentIdentity: true}

	// 记录第一个备选OwnerReference
	var first *objectReference
	// 记录第一个比已确认不存在的OwnerReference大的备选OwnerReference
	var firstFollowing *objectReference
	// 遍历所有的依赖关系
	for _, dep := range deps {
        // 遍历每个OwnerReference
		for _, ownerRef := range dep.owners {
            // 如果UID不匹配，那么跳过该OwnerReference
			if ownerRef.UID != verifiedAbsentIdentity.UID {
				// skip references that aren't the uid we care about
				continue
			}
			// 如果OwnerReference的Kind和APIVersion都匹配，且是集群范围的，那么直接跳过
			if ownerReferenceMatchesCoordinates(ownerRef, verifiedAbsentIdentity.OwnerReference) {
				if absentIdentityIsClusterScoped || verifiedAbsentIdentity.Namespace == dep.identity.Namespace {
					// skip references that exactly match verifiedAbsentIdentity
					continue
				}
			}
			// 创建备选OwnerReference
			ref := objectReference{OwnerReference: ownerReferenceCoordinates(ownerRef), Namespace: dep.identity.Namespace}
			if absentIdentityIsClusterScoped && ref.APIVersion == verifiedAbsentIdentity.APIVersion && ref.Kind == verifiedAbsentIdentity.Kind {
				// we know this apiVersion/kind is cluster-scoped because of verifiedAbsentIdentity,
				// so clear the namespace from the alternate identity
				ref.Namespace = ""
			}
			// 如果已经存在相同的备选OwnerReference，那么直接跳过
			if seenAlternates[ref] {
				// skip references we've already seen
				continue
			}
			seenAlternates[ref] = true
			// 找到字典序最小的备选OwnerReference
			if first == nil || referenceLessThan(ref, *first) {
				// this alternate comes first lexically
				first = &ref
			}
            // 找到第一个比已确认不存在的OwnerReference大的备选OwnerReference
			if referenceLessThan(verifiedAbsentIdentity, ref) && (firstFollowing == nil || referenceLessThan(ref, *firstFollowing)) {
				// this alternate is the first following verifiedAbsentIdentity lexically
				firstFollowing = &ref
			}
		}
	}

	// 如果存在第一个比已确认不存在的OwnerReference大的备选OwnerReference，返回该备选OwnerReference
	if firstFollowing != nil {
		return firstFollowing
	}
	// 否则返回第一个备选OwnerReference
	return first
}

```

###### ownerReferenceCoordinates

```GO
func ownerReferenceCoordinates(ref metav1.OwnerReference) metav1.OwnerReference {
	return metav1.OwnerReference{
		UID:        ref.UID,
		Name:       ref.Name,
		Kind:       ref.Kind,
		APIVersion: ref.APIVersion,
	}
}
```

###### referenceLessThan

```GO
// 比较两个 objectReference 结构体的大小关系的函数 
func referenceLessThan(a, b objectReference) bool {
	// kind/apiVersion are more significant than namespace,
	// so that we get coherent ordering between kinds
	// regardless of whether they are cluster-scoped or namespaced
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.APIVersion != b.APIVersion {
		return a.APIVersion < b.APIVersion
	}
	// namespace is more significant than name
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	// name is more significant than uid
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	// uid is included for completeness, but is expected to be identical
	// when getting alternate identities for an owner since they are keyed by uid
	if a.UID != b.UID {
		return a.UID < b.UID
	}
	return false
}
```

##### removeNode

```GO
// 从构建的对象引用图中删除一个节点
func (gb *GraphBuilder) removeNode(n *node) {
    // 从 uidToNode 中删除节点 n
	gb.uidToNode.Delete(n.identity.UID)
    // 从所有拥有该节点的节点中删除该节点 n
	gb.removeDependentFromOwners(n, n.owners)
}
```

## ReferenceCache

```GO
type ReferenceCache struct {
	mutex sync.Mutex
    // lru缓存
	cache *lru.Cache
}

// 创建一个Reference 需要传入缓存中最大的条目数
func NewReferenceCache(maxCacheEntries int) *ReferenceCache {
	return &ReferenceCache{
		cache: lru.New(maxCacheEntries),
	}
}

// 向缓存中添加一个 UID
func (c *ReferenceCache) Add(reference objectReference) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache.Add(reference, nil)
}

// 判断一个 UID 是否在缓存中
func (c *ReferenceCache) Has(reference objectReference) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	_, found := c.cache.Get(reference)
	return found
}
```

## Run

```go
func (gc *GarbageCollector) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer gc.attemptToDelete.ShutDown()
	defer gc.attemptToOrphan.ShutDown()
	defer gc.dependencyGraphBuilder.graphChanges.ShutDown()

	// 开启广播器和记录器
	gc.eventBroadcaster.StartStructuredLogging(0)
	gc.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: gc.kubeClient.CoreV1().Events("")})
	defer gc.eventBroadcaster.Shutdown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting controller", "controller", "garbagecollector")
	defer logger.Info("Shutting down controller", "controller", "garbagecollector")
	
    // 执行GraphBuilder的run
	go gc.dependencyGraphBuilder.Run(ctx)
	
    // 等待同步完成
	if !cache.WaitForNamedCacheSync("garbage collector", ctx.Done(), func() bool {
		return gc.dependencyGraphBuilder.IsSynced(logger)
	}) {
		return
	}

	logger.Info("All resource monitors have synced. Proceeding to collect garbage")

	// 开启worker
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, gc.runAttemptToDeleteWorker, 1*time.Second)
		go wait.Until(func() { gc.runAttemptToOrphanWorker(logger) }, 1*time.Second, ctx.Done())
	}

	<-ctx.Done()
}

```

## runAttemptToDeleteWorker

```GO
func (gc *GarbageCollector) runAttemptToDeleteWorker(ctx context.Context) {
	for gc.processAttemptToDeleteWorker(ctx) {
	}
}

func (gc *GarbageCollector) processAttemptToDeleteWorker(ctx context.Context) bool {
	item, quit := gc.attemptToDelete.Get()
	gc.workerLock.RLock()
	defer gc.workerLock.RUnlock()
	if quit {
		return false
	}
	defer gc.attemptToDelete.Done(item)
	// 尝试删除一个工作队列项
	action := gc.attemptToDeleteWorker(ctx, item)
    // 根据处理结果选择相应的动作
	switch action {
	case forgetItem:
        // 完成item
		gc.attemptToDelete.Forget(item)
	case requeueItem:
        // 加入队列重试
		gc.attemptToDelete.AddRateLimited(item)
	}

	return true
}

type workQueueItemAction int

const (
	requeueItem = iota
	forgetItem
)
```

### attemptToDeleteWorker

```GO
func (gc *GarbageCollector) attemptToDeleteWorker(ctx context.Context, item interface{}) workQueueItemAction {
    // node 后面会介绍
	n, ok := item.(*node)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expect *node, got %#v", item))
		return forgetItem
	}

	logger := klog.FromContext(ctx)
	
    // 该node没被观察到
	if !n.isObserved() {
        // 从依赖图中读取node
		nodeFromGraph, existsInGraph := gc.dependencyGraphBuilder.uidToNode.Read(n.identity.UID)
        // 如果node已经被删除了，则跳过删除操作
		if !existsInGraph {
			// 这种情况可能会出现在 attemptToDelete 循环处理重新入队的虚拟节点时，因为 attemptToDeleteItem 返回了错误，
			// 而此时关联该 UID 的实际对象已被删除
			logger.V(5).Info("item no longer in the graph, skipping attemptToDeleteItem", "item", n.identity)
			return forgetItem
		}
        // 如果节点已经被观察，则跳过删除操作
		if nodeFromGraph.isObserved() {
            // 这可能是因为 attemptToDelete 循环处理重新排队的虚拟节点，因为 attemptToDeleteItem 返回错误，
			// 而与该 UID 关联的实际对象已经被观察到
			logger.V(5).Info("item no longer virtual in the graph, skipping attemptToDeleteItem on virtual node", "item", n.identity)
			return forgetItem
		}
	}
	
    // 尝试删除该
	err := gc.attemptToDeleteItem(ctx, n)
	if err == enqueuedVirtualDeleteEventErr {
		// 如果产生了虚拟事件，将由 processGraphChanges 处理，不需要重新排队该节点
		return forgetItem
	} else if err == namespacedOwnerOfClusterScopedObjectErr {
		// 对于引用命名空间所有者的集群范围对象，这是一个无法解决的错误，不需要重新排队该节点
		return forgetItem
	} else if err != nil {
		if _, ok := err.(*restMappingError); ok {
			// 至少有两种方式可以实现：
            // 1.该引用指向一个自定义类型的对象，该对象尚未被gc.restMapper识别（这是一个暂时错误）。
            // 2.引用的组/版本无效。我们目前无法将其与下一次发现同步后将识别的有效类型区分开来。
            // 现在，记录错误并重试。
			logger.V(5).Error(err, "error syncing item", "item", n.identity)
		} else {
			utilruntime.HandleError(fmt.Errorf("error syncing item %s: %v", n, err))
		}
		// retry if garbage collection of an object failed.
		return requeueItem
        // 如果 n 尚未被观察
	} else if !n.isObserved() {
		// requeue if item hasn't been observed via an informer event yet.
		// otherwise a virtual node for an item added AND removed during watch reestablishment can get stuck in the graph and never removed.
		// see https://issue.k8s.io/56121
		logger.V(5).Info("item hasn't been observed via informer yet", "item", n.identity)
		return requeueItem
	}

	return forgetItem
}

var namespacedOwnerOfClusterScopedObjectErr = goerrors.New("cluster-scoped objects cannot refer to namespaced owners")
```

#### attemptToDeleteItem

```go
func (gc *GarbageCollector) attemptToDeleteItem(ctx context.Context, item *node) error {
	logger := klog.FromContext(ctx)

	logger.V(2).Info("Processing item",
		"item", item.identity,
		"virtual", !item.isObserved(),
	)

	// 判断是否为即将被删除的节点，如果是，则直接返回，等待最终删除。
	if item.isBeingDeleted() && !item.isDeletingDependents() {
		logger.V(5).Info("processing item returned at once, because its DeletionTimestamp is non-nil",
			"item", item.identity,
		)
		return nil
	}
	// 获取最新的节点信息，如果找不到，则删除对应虚拟节点。
	latest, err := gc.getObject(item.identity)
	switch {
	case errors.IsNotFound(err):
		// GraphBuilder可以为尚不存在的所有者添加“虚拟”节点，因此我们需要将虚拟删除事件排队以从GraphBuilder.uidToNode中删除虚拟节点。
		logger.V(5).Info("item not found, generating a virtual delete event",
			"item", item.identity,
		)
		gc.dependencyGraphBuilder.enqueueVirtualDeleteEvent(item.identity)
		return enqueuedVirtualDeleteEventErr
	case err != nil:
		return err
	}
	
    // 如果 UID 不匹配，则将虚拟删除事件排队
	if latest.GetUID() != item.identity.UID {
		logger.V(5).Info("UID doesn't match, item not found, generating a virtual delete event",
			"item", item.identity,
		)
		gc.dependencyGraphBuilder.enqueueVirtualDeleteEvent(item.identity)
		return enqueuedVirtualDeleteEventErr
	}

	// 判断当前节点是否处于删除依赖项状态，如果是，则处理节点。
	if item.isDeletingDependents() {
		return gc.processDeletingDependentsItem(logger, item)
	}

	// 计算是否应该删除节点
	ownerReferences := latest.GetOwnerReferences()
	if len(ownerReferences) == 0 {
		logger.V(2).Info("item doesn't have an owner, continue on next item",
			"item", item.identity,
		)
		return nil
	}
	
    // 对 ownerReferences 进行分类。
	// solid：有效引用，指向具有完整所有权的对象。
	// dangling：悬挂引用，指向不存在的对象，或被删除但尚未被最终删除的对象。
	// waitingForDependentsDeletion：等待依赖项删除引用，指向有 FinalizerDeletingDependents 的对象。
	solid, dangling, waitingForDependentsDeletion, err := gc.classifyReferences(ctx, item, ownerReferences)
	if err != nil {
		return err
	}
	logger.V(5).Info("classify item's references",
		"item", item.identity,
		"solid", solid,
		"dangling", dangling,
		"waitingForDependentsDeletion", waitingForDependentsDeletion,
	)
	// 根据分类结果判断是否删除节点
	switch {
	case len(solid) != 0:
		logger.V(2).Info("item has at least one existing owner, will not garbage collect",
			"item", item.identity,
			"owner", solid,
		)
		if len(dangling) == 0 && len(waitingForDependentsDeletion) == 0 {
			return nil
		}
		logger.V(2).Info("remove dangling references and waiting references for item",
			"item", item.identity,
			"dangling", dangling,
			"waitingForDependentsDeletion", waitingForDependentsDeletion,
		)
		// 从 ownerReferences 中删除 waitingForDependentsDeletion，否则引用的对象将保留 FinalizerDeletingDependents，永远无法删除。
		ownerUIDs := append(ownerRefsToUIDs(dangling), ownerRefsToUIDs(waitingForDependentsDeletion)...)
        // 如果有等待依赖项删除的所有者，则将对象标记为等待依赖项删除，然后处理它的依赖项。
        // 如果有依赖项正在删除，则跳过此对象并返回。否则，通过与实际对象的状态进行比较，尝试获取最新版本的对象。
		p, err := c.GenerateDeleteOwnerRefStrategicMergeBytes(item.identity.UID, ownerUIDs)
		if err != nil {
			return err
		}
		_, err = gc.patch(item, p, func(n *node) ([]byte, error) {
			return gc.deleteOwnerRefJSONMergePatch(n, ownerUIDs...)
		})
		return err
	case len(waitingForDependentsDeletion) != 0 && item.dependentsLength() != 0:
        // 如果对象没有实体所有者，则根据现有的 finalizers 设置 propagationPolicy。如果对象具有孤立 finalizer，则删除对象并保留其所有子资源。
        // 如果对象具有 dependents finalizer，则等待其所有子资源被删除后再删除对象。否则，将其删除并在后台进行。
		deps := item.getDependents()
		for _, dep := range deps {
			if dep.isDeletingDependents() {
				// this circle detection has false positives, we need to
				// apply a more rigorous detection if this turns out to be a
				// problem.
				// there are multiple workers run attemptToDeleteItem in
				// parallel, the circle detection can fail in a race condition.
				logger.V(2).Info("processing item, some of its owners and its dependent have FinalizerDeletingDependents, to prevent potential cycle, its ownerReferences are going to be modified to be non-blocking, then the item is going to be deleted with Foreground",
					"item", item.identity,
					"dependent", dep.identity,
				)
				patch, err := item.unblockOwnerReferencesStrategicMergePatch()
				if err != nil {
					return err
				}
				if _, err := gc.patch(item, patch, gc.unblockOwnerReferencesJSONMergePatch); err != nil {
					return err
				}
				break
			}
		}
		logger.V(2).Info("at least one owner of item has FinalizerDeletingDependents, and the item itself has dependents, so it is going to be deleted in Foreground",
			"item", item.identity,
		)
		// the deletion event will be observed by the graphBuilder, so the item
		// will be processed again in processDeletingDependentsItem. If it
		// doesn't have dependents, the function will remove the
		// FinalizerDeletingDependents from the item, resulting in the final
		// deletion of the item.
		policy := metav1.DeletePropagationForeground
		return gc.deleteObject(item.identity, &policy)
	default:
		// 根据item最新状态中是否存在orphan finalizer或delete dependents finalizer，设置删除策略。如果存在orphan finalizer，就选择该策略。如果存在delete dependents finalizer，就选择foreground deletion。否则，就使用默认的background deletion。
		var policy metav1.DeletionPropagation
		switch {
		case hasOrphanFinalizer(latest):
			// if an existing orphan finalizer is already on the object, honor it.
			policy = metav1.DeletePropagationOrphan
		case hasDeleteDependentsFinalizer(latest):
			// if an existing foreground finalizer is already on the object, honor it.
			policy = metav1.DeletePropagationForeground
		default:
			// otherwise, default to background.
			policy = metav1.DeletePropagationBackground
		}
		logger.V(2).Info("Deleting item",
			"item", item.identity,
			"propagationPolicy", policy,
		)
		return gc.deleteObject(item.identity, &policy)
	}
}
```


##### getObject

```GO
func (gc *GarbageCollector) getObject(item objectReference) (*metav1.PartialObjectMetadata, error) {
	resource, namespaced, err := gc.apiResource(item.APIVersion, item.Kind)
	if err != nil {
		return nil, err
	}
	namespace := resourceDefaultNamespace(namespaced, item.Namespace)
	if namespaced && len(namespace) == 0 {
		// the type is namespaced, but we have no namespace coordinate.
		// the only way this can happen is if a cluster-scoped object referenced this type as an owner.
		return nil, namespacedOwnerOfClusterScopedObjectErr
	}
	return gc.metadataClient.Resource(resource).Namespace(namespace).Get(context.TODO(), item.Name, metav1.GetOptions{})
}
```

**resourceDefaultNamespace**

```GO
func resourceDefaultNamespace(namespaced bool, defaultNamespace string) string {
	if namespaced {
		return defaultNamespace
	}
	return ""
}

```

##### processDeletingDependentsItem

```GO
func (gc *GarbageCollector) processDeletingDependentsItem(logger klog.Logger, item *node) error {
    // 获取所有阻塞依赖项
	blockingDependents := item.blockingDependents()
	if len(blockingDependents) == 0 {
        // 如果没有阻塞依赖项，则从项中删除 FinalizerDeleteDependents
		logger.V(2).Info("remove DeleteDependents finalizer for item", "item", item.identity)
		return gc.removeFinalizer(logger, item, metav1.FinalizerDeleteDependents)
	}
    // 将不是正在删除依赖项的依赖项添加到 attemptToDelete 队列中
	for _, dep := range blockingDependents {
		if !dep.isDeletingDependents() {
			logger.V(2).Info("adding dependent to attemptToDelete, because its owner is deletingDependents",
				"item", item.identity,
				"dependent", dep.identity,
			)
			gc.attemptToDelete.Add(dep)
		}
	}
	return nil
}

```

###### removeFinalizer

```GO
func (gc *GarbageCollector) removeFinalizer(logger klog.Logger, owner *node, targetFinalizer string) error {
	// 使用默认的 backoff 实现重试
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// 获取 owner 对象
		ownerObject, err := gc.getObject(owner.identity)
		if errors.IsNotFound(err) {
			// 如果对象不存在，则不需要做任何事情，返回 nil
			return nil
		}
		if err != nil {
			// 如果获取对象出错，则返回一个错误，以便在稍后重试
			return fmt.Errorf("cannot finalize owner %s, because cannot get it: %v. The garbage collector will retry later", owner.identity, err)
		}
		// 获取对象的元数据访问器
		accessor, err := meta.Accessor(ownerObject)
		if err != nil {
			// 如果获取元数据访问器出错，则返回一个错误，以便在稍后重试
			return fmt.Errorf("cannot access the owner object %v: %v. The garbage collector will retry later", ownerObject, err)
		}
		// 获取 finalizers 列表
		finalizers := accessor.GetFinalizers()
		var newFinalizers []string
		found := false
		// 遍历 finalizers 列表，找到需要删除的 finalizer 并删除
		for _, f := range finalizers {
			if f == targetFinalizer {
				found = true
				continue
			}
			newFinalizers = append(newFinalizers, f)
		}
		if !found {
			// 如果需要删除的 finalizer 不存在，则返回 nil
			logger.V(5).Info("finalizer already removed from object", "finalizer", targetFinalizer, "object", owner.identity)
			return nil
		}

		// 删除该 finalizer 后，需要将更新的 finalizers 列表再次保存到对象中
		patch, err := json.Marshal(&objectForFinalizersPatch{
			ObjectMetaForFinalizersPatch: ObjectMetaForFinalizersPatch{
				ResourceVersion: accessor.GetResourceVersion(),
				Finalizers:      newFinalizers,
			},
		})
		if err != nil {
			// 如果序列化 patch 出错，则返回一个错误，以便在稍后重试
			return fmt.Errorf("unable to finalize %s due to an error serializing patch: %v", owner.identity, err)
		}
		// 执行 patch 操作
		_, err = gc.patchObject(owner.identity, patch, types.MergePatchType)
		return err
	})
	if errors.IsConflict(err) {
		// 如果遇到冲突，则返回一个错误，以便在稍后重试
		return fmt.Errorf("updateMaxRetries(%d) has reached. The garbage collector will retry later for owner %v", retry.DefaultBackoff.Steps, owner.identity)
	}
	return err
}

```

**patchObject**

````GO
func (gc *GarbageCollector) patchObject(item objectReference, patch []byte, pt types.PatchType) (*metav1.PartialObjectMetadata, error) {
	resource, namespaced, err := gc.apiResource(item.APIVersion, item.Kind)
	if err != nil {
		return nil, err
	}
	return gc.metadataClient.Resource(resource).Namespace(resourceDefaultNamespace(namespaced, item.Namespace)).Patch(context.TODO(), item.Name, pt, patch, metav1.PatchOptions{})
}
````

##### classifyReferences

```GO
func (gc *GarbageCollector) classifyReferences(ctx context.Context, item *node, latestReferences []metav1.OwnerReference) (
	solid, dangling, waitingForDependentsDeletion []metav1.OwnerReference, err error) {
	// 遍历所有的 OwnerReference
	for _, reference := range latestReferences {
		// 判断 Owner 是否存在
		isDangling, owner, err := gc.isDangling(ctx, reference, item)
		if err != nil {
			return nil, nil, nil, err
		}
		// 如果 Owner 不存在，则加入 dangling 列表
		if isDangling {
			dangling = append(dangling, reference)
			continue
		}

		// 获取 Owner 的 Accessor
		ownerAccessor, err := meta.Accessor(owner)
		if err != nil {
			return nil, nil, nil, err
		}
		// 如果 Owner 正在等待 Dependents 被删除，则加入 waitingForDependentsDeletion 列表
		if ownerAccessor.GetDeletionTimestamp() != nil && hasDeleteDependentsFinalizer(ownerAccessor) {
			waitingForDependentsDeletion = append(waitingForDependentsDeletion, reference)
		} else {
			// 否则加入 solid 列表
			solid = append(solid, reference)
		}
	}
	return solid, dangling, waitingForDependentsDeletion, nil
}
```

##### ownerRefsToUIDs

```GO
func ownerRefsToUIDs(refs []metav1.OwnerReference) []types.UID {
	var ret []types.UID
	for _, ref := range refs {
		ret = append(ret, ref.UID)
	}
	return ret
}
```

##### GenerateDeleteOwnerRefStrategicMergeBytes

```GO
// 生成删除对象 owner reference 的 merge patch 

type objectForDeleteOwnerRefStrategicMergePatch struct {
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

func ownerReference(uid types.UID, patchType string) map[string]string {
	return map[string]string{
		"$patch": patchType,
		"uid":    string(uid),
	}
}
```

##### deleteOwnerRefJSONMergePatch

```go
func (gc *GarbageCollector) deleteOwnerRefJSONMergePatch(item *node, ownerUIDs ...types.UID) ([]byte, error) {
	accessor, err := gc.getMetadata(item.identity.APIVersion, item.identity.Kind, item.identity.Namespace, item.identity.Name)
	// 获取要删除owner reference的对象元数据
	if err != nil {
		return nil, err
	}
	expectedObjectMeta := ObjectMetaForPatch{}
	expectedObjectMeta.ResourceVersion = accessor.GetResourceVersion()
	refs := accessor.GetOwnerReferences()
	// 获取对象现有的owner references
	for _, ref := range refs {
		var skip bool
		for _, ownerUID := range ownerUIDs {
			if ref.UID == ownerUID {
				skip = true
				break
			}
		}
		// 如果owner UID在要删除的UID列表中，则跳过该owner reference
		if !skip {
			expectedObjectMeta.OwnerReferences = append(expectedObjectMeta.OwnerReferences, ref)
		}
	}
	// 生成JSON Merge Patch
	return json.Marshal(objectForPatch{expectedObjectMeta})
}
```

##### unblockOwnerReferencesStrategicMergePatch

```go
func (n *node) unblockOwnerReferencesStrategicMergePatch() ([]byte, error) {
	var dummy metaonly.MetadataOnlyObject
	var blockingRefs []metav1.OwnerReference
	falseVar := false
	for _, owner := range n.owners {
		if owner.BlockOwnerDeletion != nil && *owner.BlockOwnerDeletion {
            // 如果当前 owner 的 BlockOwnerDeletion 属性不为 nil，且其值为 true。
			ref := owner
			ref.BlockOwnerDeletion = &falseVar
			blockingRefs = append(blockingRefs, ref)
		}
	}
	dummy.ObjectMeta.SetOwnerReferences(blockingRefs)
	dummy.ObjectMeta.UID = n.identity.UID
	return json.Marshal(dummy)
}
```

##### patch

```go
func (gc *GarbageCollector) patch(item *node, smp []byte, jmp jsonMergePatchFunc) (*metav1.PartialObjectMetadata, error) {
	smpResult, err := gc.patchObject(item.identity, smp, types.StrategicMergePatchType)
	if err == nil {
		return smpResult, nil
	}
	if !errors.IsUnsupportedMediaType(err) {
		return nil, err
	}
	// StrategicMergePatch is not supported, use JSON merge patch instead
	patch, err := jmp(item)
	if err != nil {
		return nil, err
	}
	return gc.patchObject(item.identity, patch, types.MergePatchType)
}
```

##### deleteObject

```go
func (gc *GarbageCollector) deleteObject(item objectReference, policy *metav1.DeletionPropagation) error {
	resource, namespaced, err := gc.apiResource(item.APIVersion, item.Kind)
	if err != nil {
		return err
	}
	uid := item.UID
	preconditions := metav1.Preconditions{UID: &uid}
	deleteOptions := metav1.DeleteOptions{Preconditions: &preconditions, PropagationPolicy: policy}
	return gc.metadataClient.Resource(resource).Namespace(resourceDefaultNamespace(namespaced, item.Namespace)).Delete(context.TODO(), item.Name, deleteOptions)
}
```

###### apiResource

```go
func (gc *GarbageCollector) apiResource(apiVersion, kind string) (schema.GroupVersionResource, bool, error) {
	fqKind := schema.FromAPIVersionAndKind(apiVersion, kind)
	mapping, err := gc.restMapper.RESTMapping(fqKind.GroupKind(), fqKind.Version)
	if err != nil {
		return schema.GroupVersionResource{}, false, newRESTMappingError(kind, apiVersion)
	}
	return mapping.Resource, mapping.Scope == meta.RESTScopeNamespace, nil
}
```

##### hasDeleteDependentsFinalizer hasOrphanFinalizer

```go
func hasDeleteDependentsFinalizer(accessor metav1.Object) bool {
	return hasFinalizer(accessor, metav1.FinalizerDeleteDependents)
}

func hasOrphanFinalizer(accessor metav1.Object) bool {
	return hasFinalizer(accessor, metav1.FinalizerOrphanDependents)
}

func hasFinalizer(accessor metav1.Object, matchingFinalizer string) bool {
	finalizers := accessor.GetFinalizers()
	for _, finalizer := range finalizers {
		if finalizer == matchingFinalizer {
			return true
		}
	}
	return false
}
```

## runAttemptToOrphanWorker

```go
func (gc *GarbageCollector) runAttemptToOrphanWorker(logger klog.Logger) {
	for gc.processAttemptToOrphanWorker(logger) {
	}
}

func (gc *GarbageCollector) processAttemptToOrphanWorker(logger klog.Logger) bool {
	item, quit := gc.attemptToOrphan.Get()
	gc.workerLock.RLock()
	defer gc.workerLock.RUnlock()
	if quit {
		return false
	}
	defer gc.attemptToOrphan.Done(item)
	// 尝试孤立一个工作队列项
	action := gc.attemptToOrphanWorker(logger, item)
    // 根据处理结果选择相应的动作
	switch action {
	case forgetItem:
		gc.attemptToOrphan.Forget(item)
	case requeueItem:
		gc.attemptToOrphan.AddRateLimited(item)
	}

	return true
}
```

### attemptToOrphanWorker

```GO
// 尝试删除对象的所有子孙对象，并从其 finalizer 中删除 "orphaningFinalizer"，然后返回 forgetItem
func (gc *GarbageCollector) attemptToOrphanWorker(logger klog.Logger, item interface{}) workQueueItemAction {
	owner, ok := item.(*node)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("expect *node, got %#v", item))
		return forgetItem
	}
	// 获取 item 所有子孙对象的列表 dependents
	owner.dependentsLock.RLock()
	dependents := make([]*node, 0, len(owner.dependents))
	for dependent := range owner.dependents {
		dependents = append(dependents, dependent)
	}
	owner.dependentsLock.RUnlock()
	// 删除 owner 的所有子孙对象
	err := gc.orphanDependents(logger, owner.identity, dependents)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("orphanDependents for %s failed with %v", owner.identity, err))
		return requeueItem
	}
	// 将 "orphaningFinalizer" 从 owner 的 finalizer 中删除
	err = gc.removeFinalizer(logger, owner, metav1.FinalizerOrphanDependents)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("removeOrphanFinalizer for %s failed with %v", owner.identity, err))
		return requeueItem
	}
	return forgetItem
}
```

#### orphanDependents

```GO
func (gc *GarbageCollector) orphanDependents(logger klog.Logger, owner objectReference, dependents []*node) error {
	errCh := make(chan error, len(dependents))
	wg := sync.WaitGroup{}
	wg.Add(len(dependents))
	// 对每一个依赖节点，启动一个 goroutine 进行删除操作
	for i := range dependents {
		go func(dependent *node) {
			defer wg.Done()
			// 生成 JSON Merge Patch 字节数组，用于将当前节点从 dependent.ownerReferences 中移除
			p, err := c.GenerateDeleteOwnerRefStrategicMergeBytes(dependent.identity.UID, []types.UID{owner.UID})
			if err != nil {
				errCh <- fmt.Errorf("orphaning %s failed, %v", dependent.identity, err)
				return
			}
			// 调用 GarbageCollector 的 patch 方法，将删除 ownerReference 的 patch 应用到 dependent 节点上
			_, err = gc.patch(dependent, p, func(n *node) ([]byte, error) {
				return gc.deleteOwnerRefJSONMergePatch(n, owner.UID)
			})
			// 注意，如果待删除的 ownerReference 在 dependent.ownerReferences 中不存在，则 strategic merge patch 不会返回错误。
			if err != nil && !errors.IsNotFound(err) {
				errCh <- fmt.Errorf("orphaning %s failed, %v", dependent.identity, err)
			}
		}(dependents[i])
	}
	wg.Wait()
	close(errCh)

	var errorsSlice []error
	for e := range errCh {
		errorsSlice = append(errorsSlice, e)
	}

	if len(errorsSlice) != 0 {
		return fmt.Errorf("failed to orphan dependents of owner %s, got errors: %s", owner, utilerrors.NewAggregate(errorsSlice).Error())
	}
	logger.V(5).Info("successfully updated all dependents", "owner", owner)
	return nil
}
```

##### deleteOwnerRefJSONMergePatch

```GO
// 生成删除对象中 ownerReference 的 JSON merge patch
func (gc *GarbageCollector) deleteOwnerRefJSONMergePatch(item *node, ownerUIDs ...types.UID) ([]byte, error) {
	accessor, err := gc.getMetadata(item.identity.APIVersion, item.identity.Kind, item.identity.Namespace, item.identity.Name)
	if err != nil {
		return nil, err
	}
	expectedObjectMeta := ObjectMetaForPatch{}
	expectedObjectMeta.ResourceVersion = accessor.GetResourceVersion()
	refs := accessor.GetOwnerReferences()
	for _, ref := range refs {
		var skip bool
		for _, ownerUID := range ownerUIDs {
			if ref.UID == ownerUID {
				skip = true
				break
			}
		}
		if !skip {
			expectedObjectMeta.OwnerReferences = append(expectedObjectMeta.OwnerReferences, ref)
		}
	}
	return json.Marshal(objectForPatch{expectedObjectMeta})
}
```

