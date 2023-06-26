---
id: 33-kube-controller-code
title: persistentvolume-controller 代码走读
description: persistentvolume-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

PersistentVolume Controller 是 Kubernetes 中的一个控制器，它的作用是将 PersistentVolumeClaim（PVC）与 PersistentVolume（PV）进行绑定。PV 是 Kubernetes 集群中的一块存储资源，可以由管理员或 StorageClass 动态分配。PVC 是 Pod 对 PV 的请求，它指定了需要的存储资源的大小和访问模式。PV 和 PVC 的生命周期是独立的，即使没有 Pod 使用 PV，它们也会一直存在于集群中。

## 结构体

```go
type PersistentVolumeController struct {
    // 用于获取 PersistentVolume 对象的 List 接口
	volumeLister       corelisters.PersistentVolumeLister
	volumeListerSynced cache.InformerSynced
    // 用于获取 PersistentVolumeClaim 对象的 List 接口
	claimLister        corelisters.PersistentVolumeClaimLister
	claimListerSynced  cache.InformerSynced
    // 用于获取 StorageClass 对象的 List 接口
	classLister        storagelisters.StorageClassLister
	classListerSynced  cache.InformerSynced
    // 用于获取 Pod 对象的 List 接口
	podLister          corelisters.PodLister
	podListerSynced    cache.InformerSynced
    // 本地pod缓存
	podIndexer         cache.Indexer
    // 用于获取 Node 对象的 List 接口
	NodeLister         corelisters.NodeLister
	NodeListerSynced   cache.InformerSynced
	
    //  与 Kubernetes API Server 通信的客户端接口
	kubeClient                clientset.Interface
    // 广播器和记录器
	eventBroadcaster          record.EventBroadcaster
	eventRecorder             record.EventRecorder
    // 云接口
	cloud                     cloudprovider.Interface
    // volume插件管理
	volumePluginMgr           vol.VolumePluginMgr
    // 是否启用动态卷创建
	enableDynamicProvisioning bool
    // 集群名称
	clusterName               string
    // 重新同步的时间间隔
	resyncPeriod              time.Duration

     // volumes和claims的最后已知版本的缓存。只要这些volumes/claims没有被修改，这个缓存就是线程安全的，修改之前必须将它们克隆。这些缓存会通过来自etcd的“xxx添加/更新/删除”事件以及控制器在将更新的版本保存到etcd时进行更新。
    // 为什么需要本地缓存：将卷绑定到声明会生成4个事件，大致按以下顺序（取决于goroutine的顺序）：
    // - 卷的Spec更新
    // - 卷的状态更新
    // - 声明的Spec更新
    // - 声明的状态更新
    // 通过这些缓存，控制器可以检查它是否已经保存了卷的状态和声明的Spec+状态，并且在例如卷的Spec更新事件在所有其他事件之前到达时，不需要执行任何操作。如果没有这个缓存，它会在informers中看到旧版本的volume.Status和claim（它们尚未从API服务器事件中进行更新），并且它会尝试修复这些对象以绑定在一起。对API服务器的任何写操作都会由于版本冲突而失败-这些对象已经被写入。
	volumes persistentVolumeOrderedIndex
    // 缓存最后已知的卷和索赔的版本s
	claims  cache.Store

	// 用于处理要处理的声明和卷的工作队列。每个队列应该有恰好一个工作线程，特别是syncClaim()不是可重入的。两个syncClaims可能会将两个不同的声明绑定到同一个卷或将一个声明绑定到两个卷。
    // 控制器将从中恢复（由于API服务器中的版本错误和此控制器中的其他检查），但是如果多个工作线程控制器的速度会比仅运行单个线程的速度慢。
    // 索赔队列
	claimQueue  *workqueue.Type
    // 卷队列
	volumeQueue *workqueue.Type

	// 已调度/正在运行的操作的映射
	runningOperations goroutinemap.GoRoutineMap

	// 异步操作开始前的钩子函数
	preOperationHook func(operationName string)
	
    // 创建已提供的持久化卷的重试次数
	createProvisionedPVRetryCount int
    // 创建已提供的持久化卷的时间间隔
	createProvisionedPVInterval   time.Duration

	// operationTimestamps 缓存操作（目前是 provision（供应）+ binding（绑定）/deletion（删除））的起始时间戳以便记录度量数据。
    // 每个操作的详细生命周期/键：
    // 1. provision + binding
    // 键：claimKey
    // 起始时间：如果用户在claim中没有提供任何卷引用，并且找不到任何现有卷与claim匹配，则调用 "provisionClaim" 来使用有效的插件/外部供应者提供卷。
    // 结束时间：当一个卷成功被供应并绑定到claim后，相应的时间戳条目将从缓存中删除。
    // 中止：如果尚未将claim绑定到卷，但已从API服务器接收到删除事件，则会中止。
    // 2. deletion
    // 键：volumeName
    // 起始时间：当 "reclaimVolume" 处理具有设置为 "PersistentVolumeReclaimDelete" 的回收策略的卷时。
    // 结束时间：在从API服务器接收到卷已删除的事件后，相应的时间戳条目将从缓存中删除。
    // 中止：无。
	operationTimestamps metrics.OperationStartTimeCache
	
    // CSI 名称转换器
	translator               CSINameTranslator
    // CSI 迁移插件管理器
	csiMigratedPluginManager CSIMigratedPluginManager

	//配置控制器所使用的 dial 选项
	filteredDialOptions *proxyutil.FilteredDialOptions
}
```

## New

```go
type ControllerParameters struct {
	KubeClient                clientset.Interface
	SyncPeriod                time.Duration
	VolumePlugins             []vol.VolumePlugin
	Cloud                     cloudprovider.Interface
	ClusterName               string
	VolumeInformer            coreinformers.PersistentVolumeInformer
	ClaimInformer             coreinformers.PersistentVolumeClaimInformer
	ClassInformer             storageinformers.StorageClassInformer
	PodInformer               coreinformers.PodInformer
	NodeInformer              coreinformers.NodeInformer
	EventRecorder             record.EventRecorder
	EnableDynamicProvisioning bool
	FilteredDialOptions       *proxyutil.FilteredDialOptions
}

func NewController(ctx context.Context, p ControllerParameters) (*PersistentVolumeController, error) {
	eventRecorder := p.EventRecorder // 从 ControllerParameters 参数中获取 EventRecorder，类型为 record.EventRecorder
	var eventBroadcaster record.EventBroadcaster // 定义一个 eventBroadcaster 变量，类型为 record.EventBroadcaster

	// 如果 eventRecorder 为空，则创建一个新的 eventBroadcaster，并使用 scheme.Scheme 和 v1.EventSource{Component: "persistentvolume-controller"} 初始化 eventRecorder
	if eventRecorder == nil {
		eventBroadcaster = record.NewBroadcaster()
		eventRecorder = eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "persistentvolume-controller"})
	}

	// 创建一个 PersistentVolumeController 实例，并初始化其各个字段
	controller := &PersistentVolumeController{
		volumes:                       newPersistentVolumeOrderedIndex(), // 初始化 volumes 字段为一个新的持久卷有序索引
		claims:                        cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc), // 初始化 claims 字段为一个新的缓存存储器
		kubeClient:                    p.KubeClient, // 从 ControllerParameters 参数中获取 KubeClient，用于与 Kubernetes API 交互
		eventBroadcaster:              eventBroadcaster, // 将 eventBroadcaster 变量赋值给 eventBroadcaster 字段
		eventRecorder:                 eventRecorder, // 将 eventRecorder 变量赋值给 eventRecorder 字段
		runningOperations:             goroutinemap.NewGoRoutineMap(true /* exponentialBackOffOnError */), // 初始化 runningOperations 字段为一个新的 goroutine 映射，设置 exponentialBackOffOnError 为 true
		cloud:                         p.Cloud, // 从 ControllerParameters 参数中获取 Cloud，用于与云平台交互
		enableDynamicProvisioning:     p.EnableDynamicProvisioning, // 从 ControllerParameters 参数中获取 EnableDynamicProvisioning，控制是否启用动态供应
		clusterName:                   p.ClusterName, // 从 ControllerParameters 参数中获取 ClusterName，表示集群名称
		createProvisionedPVRetryCount: createProvisionedPVRetryCount, // 初始化 createProvisionedPVRetryCount 字段为预定义的常量值
		createProvisionedPVInterval:   createProvisionedPVInterval, // 初始化 createProvisionedPVInterval 字段为预定义的常量值
		claimQueue:                    workqueue.NewNamed("claims"), // 初始化 claimQueue 字段为一个命名为 "claims" 的新工作队列
		volumeQueue:                   workqueue.NewNamed("volumes"), // 初始化 volumeQueue 字段为一个命名为 "volumes" 的新工作队列
		resyncPeriod:                  p.SyncPeriod, // 从 ControllerParameters 参数中获取 SyncPeriod，表示重新同步的周期
		operationTimestamps:           metrics.NewOperationStartTimeCache(), // 初始化 operationTimestamps 字段为一个新的操作时间戳缓存
	}

	// 初始化 volumePluginMgr 字段，调用 volumePluginMgr 的 InitPlugins 方法初始化持久卷插件
	// 第二个参数 prober 为空，因为 PV 不支持 Flexvolume
	if err := controller.volumePluginMgr.InitPlugins(p.VolumePlugins, nil /* prober */, controller); err != nil {
		return nil, fmt
    }
    // 监控pv
    p.VolumeInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { controller.enqueueWork(ctx, controller.volumeQueue, obj) },
			UpdateFunc: func(oldObj, newObj interface{}) { controller.enqueueWork(ctx, controller.volumeQueue, newObj) },
			DeleteFunc: func(obj interface{}) { controller.enqueueWork(ctx, controller.volumeQueue, obj) },
		},
	)
	controller.volumeLister = p.VolumeInformer.Lister()
	controller.volumeListerSynced = p.VolumeInformer.Informer().HasSynced
	
    //监控pvc
	p.ClaimInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { controller.enqueueWork(ctx, controller.claimQueue, obj) },
			UpdateFunc: func(oldObj, newObj interface{}) { controller.enqueueWork(ctx, controller.claimQueue, newObj) },
			DeleteFunc: func(obj interface{}) { controller.enqueueWork(ctx, controller.claimQueue, obj) },
		},
	)
	controller.claimLister = p.ClaimInformer.Lister()
	controller.claimListerSynced = p.ClaimInformer.Informer().HasSynced

	controller.classLister = p.ClassInformer.Lister()
	controller.classListerSynced = p.ClassInformer.Informer().HasSynced
	controller.podLister = p.PodInformer.Lister()
	controller.podIndexer = p.PodInformer.Informer().GetIndexer()
	controller.podListerSynced = p.PodInformer.Informer().HasSynced
	controller.NodeLister = p.NodeInformer.Lister()
	controller.NodeListerSynced = p.NodeInformer.Informer().HasSynced

	// This custom indexer will index pods by its PVC keys. Then we don't need
	// to iterate all pods every time to find pods which reference given PVC.
	if err := common.AddPodPVCIndexerIfNotPresent(controller.podIndexer); err != nil {
		return nil, fmt.Errorf("could not initialize attach detach controller: %w", err)
	}

	csiTranslator := csitrans.New()
	controller.translator = csiTranslator
	controller.csiMigratedPluginManager = csimigration.NewPluginManager(csiTranslator, utilfeature.DefaultFeatureGate)

	controller.filteredDialOptions = p.FilteredDialOptions

	return controller, nil
}
```

## persistentVolumeOrderedIndex

```GO
type persistentVolumeOrderedIndex struct {
	store cache.Indexer
}

func newPersistentVolumeOrderedIndex() persistentVolumeOrderedIndex {
	return persistentVolumeOrderedIndex{cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{"accessmodes": accessModesIndexFunc})}
}

// PVC的mode做缓存
func accessModesIndexFunc(obj interface{}) ([]string, error) {
	if pv, ok := obj.(*v1.PersistentVolume); ok {
		modes := v1helper.GetAccessModesAsString(pv.Spec.AccessModes)
		return []string{modes}, nil
	}
	return []string{""}, fmt.Errorf("object is not a persistent volume: %v", obj)
}
```

### listByAccessModes

```GO
func (pvIndex *persistentVolumeOrderedIndex) listByAccessModes(modes []v1.PersistentVolumeAccessMode) ([]*v1.PersistentVolume, error) {
	// 创建一个 PersistentVolume 对象，并设置其 Spec 中的 AccessModes 字段为传入的 modes 参数
	pv := &v1.PersistentVolume{
		Spec: v1.PersistentVolumeSpec{
			AccessModes: modes,
		},
	}

	// 通过 pvIndex 的 store 成员调用 Index 方法，传入 "accessmodes" 和 pv 作为参数，
	// 返回符合条件的对象数组 objs 和错误 err
	objs, err := pvIndex.store.Index("accessmodes", pv)
	if err != nil {
		return nil, err
	}

	// 创建一个 []*v1.PersistentVolume 类型的切片 volumes，长度为 objs 数组的长度
	volumes := make([]*v1.PersistentVolume, len(objs))
	
	// 遍历 objs 数组，将其转换为 []*v1.PersistentVolume 类型，并保存到 volumes 切片中
	for i, obj := range objs {
		volumes[i] = obj.(*v1.PersistentVolume)
	}

	// 返回 volumes 切片和 nil 错误
	return volumes, nil
}
```

### findByClaim

```GO
func (pvIndex *persistentVolumeOrderedIndex) findByClaim(claim *v1.PersistentVolumeClaim, delayBinding bool) (*v1.PersistentVolume, error) {
	// 持久卷（PV）通过其访问模式进行索引，以便更容易地进行搜索。每个索引都是访问模式的字符串表示形式。
	// 可能的访问模式集合是有限的，而且每个 PV 只会在其中一个索引中被索引（与 PV 的访问模式匹配的索引）。
	//
	// 资源的请求总会指定其所需的访问模式。任何匹配的 PV 必须至少具有相同数量的访问模式，但可以具有更多的访问模式。
	// 例如，用户请求 ReadWriteOnce，但存在一个 GCEPD，它是 ReadWriteOnce+ReadOnlyMany。
	//
	// 搜索是根据一组访问模式进行的，因此我们可以尝试精确匹配的访问模式，也可以尝试潜在的匹配模式（例如上面的 GCEPD 示例）。
	allPossibleModes := pvIndex.allPossibleMatchingAccessModes(claim.Spec.AccessModes)

	for _, modes := range allPossibleModes {
		// 根据访问模式列表调用 listByAccessModes 方法，获取符合条件的 PV 列表
		volumes, err := pvIndex.listByAccessModes(modes)
		if err != nil {
			return nil, err
		}

		// 调用 FindMatchingVolume 方法，根据传入的 PersistentVolumeClaim、PV 列表、节点和排除映射来查找最佳匹配的 PV
		bestVol, err := volume.FindMatchingVolume(claim, volumes, nil /* node for topology binding*/, nil /* exclusion map */, delayBinding)
		if err != nil {
			return nil, err
		}

		// 如果找到了最佳匹配的 PV，则返回该 PV 和 nil 错误
		if bestVol != nil {
			return bestVol, nil
		}
	}
	
	// 如果没有找到符合条件的 PV，则返回 nil 和 nil 错误
	return nil, nil
}
```

### findBestMatchForClaim

```GO
func (pvIndex *persistentVolumeOrderedIndex) findBestMatchForClaim(claim *v1.PersistentVolumeClaim, delayBinding bool) (*v1.PersistentVolume, error) {
	return pvIndex.findByClaim(claim, delayBinding)
}
```

### allPossibleMatchingAccessModes

```go
func (pvIndex *persistentVolumeOrderedIndex) allPossibleMatchingAccessModes(requestedModes []v1.PersistentVolumeAccessMode) [][]v1.PersistentVolumeAccessMode {
	// PV的访问模式被索引以便于更容易搜索。每个索引都是一组访问模式的字符串表示。
	// 可能的访问模式是有限的，PV只会被索引到其中一个索引中（与PV的模式匹配的索引）。
	//
	// 对资源的请求将始终指定其所需的访问模式。
	// 任何匹配的PV必须至少具有该数量的访问模式，但它可以具有更多的访问模式。
	// 例如，用户请求ReadWriteOnce，但有一个可用的GCEPD，其访问模式是ReadWriteOnce + ReadOnlyMany。
	//
	// 搜索将根据一组访问模式执行，因此我们可以尝试不仅匹配精确的访问模式，还可以尝试潜在的匹配模式
	//（例如上面的GCEPD示例）。
	matchedModes := [][]v1.PersistentVolumeAccessMode{}
	keys := pvIndex.store.ListIndexFuncValues("accessmodes") // 获取索引中所有的键值
	for _, key := range keys {
		indexedModes := v1helper.GetAccessModesFromString(key) // 将字符串表示的访问模式转换为访问模式对象
		if util.ContainsAllAccessModes(indexedModes, requestedModes) { // 检查索引中的访问模式是否包含请求的访问模式
			matchedModes = append(matchedModes, indexedModes) // 如果匹配，则将访问模式添加到匹配的访问模式数组中
		}
	}

	// 按每个数组中的访问模式数量进行排序，最少数量的访问模式排在前面。
	// 这允许通过最小数量的访问模式来搜索可能的匹配的卷。
	sort.Sort(byAccessModes{matchedModes})
	return matchedModes
}
```

## OperationStartTimeCache

```go

type OperationStartTimeCache struct {
	cache sync.Map // [string]operationTimestamp
}

// NewOperationStartTimeCache creates a operation timestamp cache
func NewOperationStartTimeCache() OperationStartTimeCache {
	return OperationStartTimeCache{
		cache: sync.Map{}, // [string]operationTimestamp {}
	}
}
```

### 方法

```go
func (c *OperationStartTimeCache) AddIfNotExist(key, pluginName, operationName string) {
	ts := newOperationTimestamp(pluginName, operationName)
	c.cache.LoadOrStore(key, ts)
}

func (c *OperationStartTimeCache) Delete(key string) {
	c.cache.Delete(key)
}

func (c *OperationStartTimeCache) Has(key string) bool {
	_, exists := c.cache.Load(key)
	return exists
}

func RecordMetric(key string, c *OperationStartTimeCache, err error) {
	obj, exists := c.cache.Load(key) // 从 c.cache 中加载 key 对应的值，并检查是否存在
	if !exists { // 如果不存在，则直接返回
		return
	}
	ts, ok := obj.(*operationTimestamp) // 将加载到的值转换为 *operationTimestamp 类型，并检查转换是否成功
	if !ok { // 如果转换不成功，则直接返回
		return
	}
	if err != nil { // 如果 err 不为空，则记录错误指标
		RecordVolumeOperationErrorMetric(ts.pluginName, ts.operation)
	} else { // 否则，记录操作延迟指标，并从缓存中删除对应的时间戳条目
		timeTaken := time.Since(ts.startTs).Seconds() // 计算操作所花费的时间
		metricutil.RecordOperationLatencyMetric(ts.pluginName, ts.operation, timeTaken) // 记录操作延迟指标
		c.Delete(key) // 从缓存中删除时间戳条目
	}
}

func RecordVolumeOperationErrorMetric(pluginName, opName string) {
	if pluginName == "" {
		pluginName = "N/A"
	}
	volumeOperationErrorsMetric.WithLabelValues(pluginName, opName).Inc()
}
```

### operationTimestamp

```GO
type operationTimestamp struct {
	pluginName string
	operation  string
	startTs    time.Time
}

func newOperationTimestamp(pluginName, operationName string) *operationTimestamp {
	return &operationTimestamp{
		pluginName: pluginName,
		operation:  operationName,
		startTs:    time.Now(),
	}
}
```

## CSINameTranslator

```GO
type CSINameTranslator interface {
	GetCSINameFromInTreeName(pluginName string) (string, error)
}
```

## CSIMigratedPluginManager

```GO
type CSIMigratedPluginManager interface {
	IsMigrationEnabledForPlugin(pluginName string) bool
}
```

## Run

```go
func (ctrl *PersistentVolumeController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash() // 延迟处理崩溃的函数调用
	defer ctrl.claimQueue.ShutDown() // 延迟关闭声明队列
	defer ctrl.volumeQueue.ShutDown() // 延迟关闭卷队列

	// 启动事件处理管道。
	if ctrl.eventBroadcaster != nil {
		ctrl.eventBroadcaster.StartStructuredLogging(0) // 开始结构化日志记录
		ctrl.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: ctrl.kubeClient.CoreV1().Events("")}) // 开始将事件记录到指定的接收器中
		defer ctrl.eventBroadcaster.Shutdown() // 延迟关闭事件广播器
	}
	logger := klog.FromContext(ctx) // 从上下文中获取日志记录器
	logger.Info("Starting persistent volume controller") // 记录日志，表示启动持久卷控制器
	defer logger.Info("Shutting down persistent volume controller") // 延迟记录日志，表示关闭持久卷控制器

	if !cache.WaitForNamedCacheSync("persistent volume", ctx.Done(), ctrl.volumeListerSynced, ctrl.claimListerSynced, ctrl.classListerSynced, ctrl.podListerSynced, ctrl.NodeListerSynced) {
		return // 等待缓存同步完成，若未完成则直接返回
	}

	ctrl.initializeCaches(logger, ctrl.volumeLister, ctrl.claimLister) // 初始化缓存

	go wait.Until(func() { ctrl.resync(ctx) }, ctrl.resyncPeriod, ctx.Done()) // 启动定时重新同步函数
	go wait.UntilWithContext(ctx, ctrl.volumeWorker, time.Second) // 启动卷工作器函数
	go wait.UntilWithContext(ctx, ctrl.claimWorker, time.Second) // 启动声明工作器函数

	metrics.Register(ctrl.volumes.store, ctrl.claims, &ctrl.volumePluginMgr) // 注册度量指标

	<-ctx.Done() // 阻塞等待上下文被取消
}
```

### metrics

```go
func Register(pvLister PVLister, pvcLister PVCLister, pluginMgr *volume.VolumePluginMgr) {
	registerMetrics.Do(func() {
		legacyregistry.CustomMustRegister(newPVAndPVCCountCollector(pvLister, pvcLister, pluginMgr))
		legacyregistry.MustRegister(volumeOperationErrorsMetric)
		legacyregistry.MustRegister(retroactiveStorageClassMetric)
		legacyregistry.MustRegister(retroactiveStorageClassErrorMetric)
	})
}
```

### resync

```go
func (ctrl *PersistentVolumeController) resync(ctx context.Context) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Resyncing PV controller")

	pvcs, err := ctrl.claimLister.List(labels.NewSelector())
	if err != nil {
		logger.Info("Cannot list claims", "err", err)
		return
	}
	for _, pvc := range pvcs {
		ctrl.enqueueWork(ctx, ctrl.claimQueue, pvc)
	}

	pvs, err := ctrl.volumeLister.List(labels.NewSelector())
	if err != nil {
		logger.Info("Cannot list persistent volumes", "err", err)
		return
	}
	for _, pv := range pvs {
		ctrl.enqueueWork(ctx, ctrl.volumeQueue, pv)
	}
}
```

#### enqueueWork

```go
func (ctrl *PersistentVolumeController) enqueueWork(ctx context.Context, queue workqueue.Interface, obj interface{}) {
	// 注意 "xxx deleted" 事件
	logger := klog.FromContext(ctx) // 从上下文中获取日志记录器
	if unknown, ok := obj.(cache.DeletedFinalStateUnknown); ok && unknown.Obj != nil { // 如果传入的对象是 cache.DeletedFinalStateUnknown 类型且其 Obj 字段不为空
		obj = unknown.Obj // 将 obj 更新为 DeletedFinalStateUnknown 中的 Obj 字段
	}
	objName, err := controller.KeyFunc(obj) // 通过控制器的 KeyFunc 方法从对象中获取键值
	if err != nil {
		logger.Error(err, "Failed to get key from object") // 记录错误日志，表示从对象中获取键值失败
		return
	}
	logger.V(5).Info("Enqueued for sync", "objName", objName) // 记录日志，表示将 objName 加入队列等待同步
	queue.Add(objName) // 将 objName 添加到队列中，等待后续处理
}

```

### volumeWorker

```go
func (ctrl *PersistentVolumeController) volumeWorker(ctx context.Context) {
	logger := klog.FromContext(ctx) // 从上下文中获取日志记录器
	workFunc := func(ctx context.Context) bool { // 定义工作函数，接收上下文作为参数，返回布尔值
		keyObj, quit := ctrl.volumeQueue.Get() // 从队列中获取键值对象和是否退出的标志
		if quit {
			return true // 如果退出标志为 true，则返回 true，表示工作函数结束
		}
		defer ctrl.volumeQueue.Done(keyObj) // 在函数结束时标记键值对象已完成处理
		key := keyObj.(string) // 将键值对象转为字符串类型

		logger.V(5).Info("volumeWorker", "volumeKey", key) // 记录日志，表示开始处理键值对象

		_, name, err := cache.SplitMetaNamespaceKey(key) // 通过 cache.SplitMetaNamespaceKey 方法解析键值对象，获取名称
		if err != nil {
			logger.V(4).Info("Error getting name of volume to get volume from informer", "volumeKey", key, "err", err) // 记录错误日志，表示解析键值对象失败
			return false
		}

		volume, err := ctrl.volumeLister.Get(name) // 通过控制器的 volumeLister 获取指定名称的持久卷对象
		if err == nil {
			// 持久卷对象在 informer 的缓存中仍存在，说明事件类型为 add/update/sync
			ctrl.updateVolume(ctx, volume) // 调用控制器的 updateVolume 方法处理持久卷的更新操作
			return false
		}

		if !errors.IsNotFound(err) {
			logger.V(2).Info("Error getting volume from informer", "volumeKey", key, "err", err) // 记录错误日志，表示从 informer 中获取持久卷对象失败
			return false
		}

		// 持久卷对象不在 informer 的缓存中，说明事件类型为 delete
		volumeObj, found, err := ctrl.volumes.store.GetByKey(key) // 通过控制器的 volumes.store 获取缓存中的持久卷对象
		if err != nil {
			logger.V(2).Info("Error getting volume from cache", "volumeKey", key, "err", err) // 记录错误日志，表示从缓存中获取持久卷对象失败
			return false
		}

		if !found {
			// 控制器已经处理过该删除事件，已从缓存中删除了持久卷对象
			logger.V(2).Info("Deletion of volume was already processed", "volumeKey", key)
			return false
		}

		volume, ok := volumeObj.(*v1.PersistentVolume)
		if !ok {
			logger.Error(nil, "Expected volume, got", "obj", volumeObj) // 记录错误日志，表示从缓存中获取的对象类型不符合预期
			return false
		}

		ctrl.deleteVolume(ctx, volume) // 调用控制器的 deleteVolume 方法
		return false
	}
	for {
		if quit := workFunc(ctx); quit {
			logger.Info("Volume worker queue shutting down")
			return
		}
	}
}
```

#### updateVolume

```GO
func (ctrl *PersistentVolumeController) updateVolume(ctx context.Context, volume *v1.PersistentVolume) {
    // 使用传入的ctx创建一个logger。
    logger := klog.FromContext(ctx)
	// 将volume更新存储到cache中，如果更新失败则输出错误日志。
    new, err := ctrl.storeVolumeUpdate(logger, volume)
    if err != nil {
        logger.Error(err, "")
    }

    // 如果存储成功，则继续执行下面的代码，否则直接返回。
    if !new {
        return
    }

    // 调用syncVolume函数同步volume，如果同步失败则输出错误日志。
    err = ctrl.syncVolume(ctx, volume)
    if err != nil {
        // 如果发生版本冲突，则输出info级别的日志，否则输出错误日志。
        if errors.IsConflict(err) {
            logger.V(3).Info("Could not sync volume", "volumeName", volume.Name, "err", err)
        } else {
            logger.Error(err, "Could not sync volume", "volumeName", volume.Name, "err", err)
        }
    }
}
```

##### storeVolumeUpdate

```GO
func (ctrl *PersistentVolumeController) storeVolumeUpdate(logger klog.Logger, volume interface{}) (bool, error) {
	return storeObjectUpdate(logger, ctrl.volumes.store, volume, "volume")
}
```

##### storeObjectUpdate

```GO
func storeObjectUpdate(logger klog.Logger, store cache.Store, obj interface{}, className string) (bool, error) {
	objName, err := controller.KeyFunc(obj) //获取对象的Key
	if err != nil {
		return false, fmt.Errorf("couldn't get key for object %+v: %w", obj, err)
	}
	oldObj, found, err := store.Get(obj) //从cache.Store中查找对象
	if err != nil {
		return false, fmt.Errorf("error finding %s %q in controller cache: %w", className, objName, err)
	}

	objAccessor, err := meta.Accessor(obj) //获取对象元数据
	if err != nil {
		return false, err
	}
	if !found { // 如果对象不存在
		// This is a new object
		logger.V(4).Info("storeObjectUpdate, adding obj", "storageClassName", className, "objName", objName, "resourceVersion", objAccessor.GetResourceVersion()) //添加新对象的日志记录
		if err = store.Add(obj); err != nil { //将新对象添加到cache.Store中
			return false, fmt.Errorf("error adding %s %q to controller cache: %w", className, objName, err)
		}
		return true, nil
	}

	oldObjAccessor, err := meta.Accessor(oldObj) //获取旧对象的元数据
	if err != nil {
		return false, err
	}

	objResourceVersion, err := strconv.ParseInt(objAccessor.GetResourceVersion(), 10, 64) //获取新对象的资源版本号
	if err != nil {
		return false, fmt.Errorf("error parsing ResourceVersion %q of %s %q: %s", objAccessor.GetResourceVersion(), className, objName, err)
	}
	oldObjResourceVersion, err := strconv.ParseInt(oldObjAccessor.GetResourceVersion(), 10, 64) //获取旧对象的资源版本号
	if err != nil {
		return false, fmt.Errorf("error parsing old ResourceVersion %q of %s %q: %s", oldObjAccessor.GetResourceVersion(), className, objName, err)
	}

	// Throw away only older version, let the same version pass - we do want to
	// get periodic sync events.
	if oldObjResourceVersion > objResourceVersion { //如果旧对象的资源版本号大于新对象的资源版本号，则忽略该更新
		logger.V(4).Info("storeObjectUpdate: ignoring obj", "storageClassName", className, "objName", objName, "resourceVersion", objAccessor.GetResourceVersion())
		return false, nil
	}

	logger.V(4).Info("storeObjectUpdate updating obj with version", "storageClassName", className, "objName", objName, "resourceVersion", objAccessor.GetResourceVersion()) //更新对象的日志记录
	if err = store.Update(obj); err != nil { //将更新后的对象存储到cache.Store中
		return false, fmt.Errorf("error updating %s %q in controller cache: %w", className, objName, err)
	}
	return true, nil
}
```

##### syncVolume

```GO
func (ctrl *PersistentVolumeController) syncVolume(ctx context.Context, volume *v1.PersistentVolume) error {
	logger := klog.FromContext(ctx) // 从上下文中获取 logger
	logger.V(4).Info("Synchronizing PersistentVolume", "volumeName", volume.Name, "volumeStatus", getVolumeStatusForLogging(volume)) // 打印日志，记录正在同步的 PersistentVolume 的名称和状态
	// 设置正确的 "migrated-to" 注解和修改 PV 的 finalizers，并在 API 服务器中更新，如果需要的话
	newVolume, err := ctrl.updateVolumeMigrationAnnotationsAndFinalizers(ctx, volume) // 更新 PV 的迁移注解和 finalizers
	if err != nil {
		// 未保存任何更改；在下一次调用此方法时，将回退到相同的条件
		return err
	}
	volume = newVolume // 更新 volume 变量

	// [单元测试设置 4]
	if volume.Spec.ClaimRef == nil {
		// Volume 未被使用
		logger.V(4).Info("Synchronizing PersistentVolume, volume is unused", "volumeName", volume.Name) // 打印日志，记录未被使用的 PersistentVolume 的名称
		if _, err := ctrl.updateVolumePhase(ctx, volume, v1.VolumeAvailable, ""); err != nil { // 更新 PV 的状态为 Available
			// 未保存任何更改；在下一次调用此方法时，将回退到相同的条件
			return err
		}
		return nil
	} else /* pv.Spec.ClaimRef != nil */ {
		// Volume 已绑定到一个 PersistentVolumeClaim。
		if volume.Spec.ClaimRef.UID == "" {
			// PV 已为 PVC 保留；但 PVC 尚未绑定到该 PV；PVC 同步将处理它。
			logger.V(4).Info("Synchronizing PersistentVolume, volume is pre-bound to claim", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name) // 打印日志，记录预先绑定的 PersistentVolume 的信息
			if _, err := ctrl.updateVolumePhase(ctx, volume, v1.VolumeAvailable, ""); err != nil { // 更新 PV 的状态为 Available
				// 未保存任何更改；在下一次调用此方法时，将回退到相同的条件
				return err
			}
			return nil
		}
		logger.V(4).Info("Synchronizing PersistentVolume, volume is bound to claim", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name) // 打印日志，记录绑定的 PersistentVolume 的信息
		// 根据名称获取 PVC
		var claim *v1.PersistentVolumeClaim
		claimName := claimrefToClaimKey(volume.Spec.ClaimRef)
		obj, found, err := ctrl.claims.GetByKey(claimName) // 通过 claimName 从 claims 中获取 PVC
		if err != nil {
			return err
		}
		if !found {
        // 如果持久卷（PV）是由外部的 PV 存储器（PV provisioner）创建的，或者由外部的 PV 绑定程序（如 kube-scheduler）绑定的，
        // 在负载较重的情况下，相应的 PVC 可能尚未同步到控制器的本地缓存中。因此，我们需要在以下两个地方进行双重检查：
        //   1）informer 缓存中
        //   2）如果在 informer 缓存中找不到，则在 apiserver 中
        // 以确保我们不会错误地回收 PV。
        // 注意，只有非已释放（Released）和非失败（Failed）状态的卷会在 PVC 不存在时更新为 Released 状态。
        if volume.Status.Phase != v1.VolumeReleased && volume.Status.Phase != v1.VolumeFailed {
            obj, err = ctrl.claimLister.PersistentVolumeClaims(volume.Spec.ClaimRef.Namespace).Get(volume.Spec.ClaimRef.Name)
            if err != nil && !apierrors.IsNotFound(err) {
                return err
            }
            found = !apierrors.IsNotFound(err)
            if !found {
                obj, err = ctrl.kubeClient.CoreV1().PersistentVolumeClaims(volume.Spec.ClaimRef.Namespace).Get(ctx, volume.Spec.ClaimRef.Name, metav1.GetOptions{})
                if err != nil && !apierrors.IsNotFound(err) {
                    return err
                }
                found = !apierrors.IsNotFound(err)
            }
        }
    }
    if !found {
			logger.V(4).Info("Synchronizing PersistentVolume, claim not found", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name)
			// Fall through with claim = nil
		} else {
			var ok bool
			claim, ok = obj.(*v1.PersistentVolumeClaim)
			if !ok {
				return fmt.Errorf("cannot convert object from volume cache to volume %q!?: %#v", claim.Spec.VolumeName, obj)
			}
			logger.V(4).Info("Synchronizing PersistentVolume, claim found", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "claimStatus", getClaimStatusForLogging(claim), "volumeName", volume.Name)
		}
    if claim != nil && claim.UID != volume.Spec.ClaimRef.UID {
        // 判断 claim 是否为 nil，并且判断 claim.UID 是否与 volume.Spec.ClaimRef.UID 不相等
        // 如果不相等，则表示 PV 指向的 PVC 已被删除，而且有一个同名的新 PVC 被创建
        // 在某些情况下，缓存的 claim 可能不是最新的，volume.Spec.ClaimRef.UID 可能比缓存的更新
        // 因此，我们应该通过调用 apiserver 获取最新的 claim，并进行比较
        logger.V(4).Info("Maybe cached claim is not the newest one, we should fetch it from apiserver", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name))

        // 从 apiserver 获取最新的 claim
        claim, err = ctrl.kubeClient.CoreV1().PersistentVolumeClaims(volume.Spec.ClaimRef.Namespace).Get(ctx, volume.Spec.ClaimRef.Name, metav1.GetOptions{})
        if err != nil && !apierrors.IsNotFound(err) {
            return err
        } else if claim != nil {
            // 如果获取到了最新的 claim
            // 将 volume 视为绑定到一个已删除的 claim
            // 判断最新的 claim.UID 是否与 volume.Spec.ClaimRef.UID 不相等
            if claim.UID != volume.Spec.ClaimRef.UID {
                logger.V(4).Info("Synchronizing PersistentVolume, claim has a newer UID than pv.ClaimRef, the old one must have been deleted", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name)
                claim = nil
            } else {
                logger.V(4).Info("Synchronizing PersistentVolume, claim has a same UID with pv.ClaimRef", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name)
            }
        }
    }
	if claim == nil {
        // If we get into this block, the claim must have been deleted;
        // NOTE: reclaimVolume may either release the PV back into the pool or
        // recycle it or do nothing (retain)
        // 如果进入这个块，表示声明(claim)可能已被删除；
        // 注意: reclaimVolume 可能会将 PV 释放回资源池(pool)、回收(recycle)或者什么都不做(retain)

        // Do not overwrite previous Failed state - let the user see that
        // something went wrong, while we still re-try to reclaim the
        // volume.
        // 不要覆盖之前的 Failed 状态 - 让用户看到出了问题，而我们仍然尝试重新取回(reclaim)这个 volume
        if volume.Status.Phase != v1.VolumeReleased && volume.Status.Phase != v1.VolumeFailed {
            // Also, log this only once:
            // 同时，只记录一次日志：
            logger.V(2).Info("Volume is released and reclaim policy will be executed", "volumeName", volume.Name, "reclaimPolicy", volume.Spec.PersistentVolumeReclaimPolicy)
            if volume, err = ctrl.updateVolumePhase(ctx, volume, v1.VolumeReleased, ""); err != nil {
                // Nothing was saved; we will fall back into the same condition
                // in the next call to this method
                // 什么都没有保存; 我们会在下一次调用该方法时回退到相同的条件
                return err
            }
        }
        if err = ctrl.reclaimVolume(ctx, volume); err != nil {
            // Release failed, we will fall back into the same condition
            // in the next call to this method
            // 释放失败，我们会在下一次调用该方法时回退到相同的条件
            return err
        }
        if volume.Spec.PersistentVolumeReclaimPolicy == v1.PersistentVolumeReclaimRetain {
            // volume is being retained, it references a claim that does not exist now.
            // volume 正在保留(retained)，它引用了一个当前不存在的声明(claim)。
            logger.V(4).Info("PersistentVolume references a claim that is not found", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "claimUID", volume.Spec.ClaimRef.UID, "volumeName", volume.Name)
        }
        return nil
    } else if claim.Spec.VolumeName == "" {
        // 若 PersistentVolumeClaim 的 Spec.VolumeName 字段为空，则执行以下操作
        if storagehelpers.CheckVolumeModeMismatches(&claim.Spec, &volume.Spec) {
            // 检查 PersistentVolumeClaim 和 PersistentVolume 的 volumeMode 是否不匹配
            // 若不匹配，则执行以下操作
            // 在 syncUnboundClaim 中不会调用绑定函数，因为由于 volumeMode 不匹配，findBestMatchForClaim 不会返回该卷
            volumeMsg := fmt.Sprintf("Cannot bind PersistentVolume to requested PersistentVolumeClaim %q due to incompatible volumeMode.", claim.Name)
            // 记录事件，事件类型为 Warning，事件原因为 VolumeMismatch，事件消息为 volumeMsg
            ctrl.eventRecorder.Event(volume, v1.EventTypeWarning, events.VolumeMismatch, volumeMsg)
            claimMsg := fmt.Sprintf("Cannot bind PersistentVolume %q to requested PersistentVolumeClaim due to incompatible volumeMode.", volume.Name)
            // 记录事件，事件类型为 Warning，事件原因为 VolumeMismatch，事件消息为 claimMsg
            ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.VolumeMismatch, claimMsg)
            // 跳过同步 PersistentVolumeClaim 的操作
            return nil
        }

        if metav1.HasAnnotation(volume.ObjectMeta, storagehelpers.AnnBoundByController) {
            // 若 PersistentVolume 的元数据中有 BoundByController 的注解，则执行以下操作
            // 绑定尚未完成，由 PersistentVolumeClaim 的同步操作处理
            logger.V(4).Info("Synchronizing PersistentVolume, volume not bound yet, waiting for syncClaim to fix it", "volumeName", volume.Name)
        } else {
            // 若 PersistentVolume 无 BoundByController 的注解，则执行以下操作
            // 悬空的 PersistentVolume，尝试在 PersistentVolumeClaim 的同步操作中重新建立关联
            logger.V(4).Info("Synchronizing PersistentVolume, volume was bound and got unbound (by user?), waiting for syncClaim to fix it", "volumeName", volume.Name)
        }
        // 在这两种情况下，卷处于 Bound 状态，而 PersistentVolumeClaim 处于 Pending 状态
        // 下一次 syncClaim 将会修复它们的关联关系。为了加快速度，将 PersistentVolumeClaim 加入控制器的队列中
        // 这会导致 syncClaim 在短时间内被调用（并在正确的工作 Goroutine 中执行）
        // 这加速了已供应卷的绑定 - 提供者只保存新的 PersistentVolume，并期望下一次 syncClaim 将其绑定到 PersistentVolumeClaim
        ctrl.claimQueue.Add(claimToClaimKey(claim))
        return nil
    } else if claim.Spec.VolumeName == volume.Name {
        // 若 PersistentVolumeClaim 的 Spec.VolumeName 字段等于 PersistentVolume 的名称，则执行以下操作
        // 卷已经正确地绑定到一个 PersistentVolume 上，如果需要则更新状态
        logger.V(4).Info("Synchronizing PersistentVolume, all is bound", "volumeName", volume.Name)
        if _, err = ctrl.updateVolumePhase(ctx, volume, v1.VolumeBound, ""); err != nil {
            // 未保存任何内容
            return err 
        }
        return nil
    } else {
        if metav1.HasAnnotation(volume.ObjectMeta, storagehelpers.AnnDynamicallyProvisioned) && volume.Spec.PersistentVolumeReclaimPolicy == v1.PersistentVolumeReclaimDelete {
            // 如果 volume 对象的元数据中包含名为 storagehelpers.AnnDynamicallyProvisioned 的注释，并且 volume 对象的 PersistentVolumeReclaimPolicy 字段等于 v1.PersistentVolumeReclaimDelete，执行以下代码块

            // 该卷是动态创建的，并且与当前的 PersistentVolumeClaim 不再绑定，因此不再需要，可以删除
            // 将卷的状态标记为 Released，以通知外部删除器和用户。不会覆盖现有的 Failed 状态！
            if volume.Status.Phase != v1.VolumeReleased && volume.Status.Phase != v1.VolumeFailed {
                // 同时，只记录一次日志：
                logger.V(2).Info("Dynamically provisioned volume is released and it will be deleted", "volumeName", volume.Name)

                // 更新卷的状态为 VolumeReleased，并清空 volume.Spec.ClaimRef.UID 字段。如果更新失败，会在下次调用此方法时再次尝试。
                if volume, err = ctrl.updateVolumePhase(ctx, volume, v1.VolumeReleased, ""); err != nil {
                    return err
                }
            }

            // 调用控制器的 reclaimVolume 方法进行卷的删除操作。如果删除失败，会在下次调用此方法时再次尝试。
            if err = ctrl.reclaimVolume(ctx, volume); err != nil {
                return err
            }

            // 返回 nil 表示执行成功
            return nil
        } else {
            // 如果以上条件不满足，执行以下代码块

            // 卷与某个 PersistentVolumeClaim 绑定，但该 PersistentVolumeClaim 已在其他地方绑定，并且该卷不是动态创建的。
            if metav1.HasAnnotation(volume.ObjectMeta, storagehelpers.AnnBoundByController) {
                // 这是控制器正常操作的一部分；控制器尝试使用此卷为某个 PersistentVolumeClaim 提供服务，但该 PersistentVolumeClaim 已由其他卷满足。现在我们需要解绑。
                logger.V(4).Info("Synchronizing PersistentVolume, volume is bound by controller to a claim that is bound to another volume, unbinding", "volumeName", volume.Name)

                // 调用控制器的 unbindVolume 方法进行卷的解绑操作。如果解绑失败，会返回错误。
                if err = ctrl.unbindVolume(ctx, volume); err != nil {
                    return err
                }

                // 返回 nil 表示执行成功
                return nil
            } else {
                // PersistentVolume 可能是由用户手动创建的，并与某个 PersistentVolumeClaim 绑定，但该 PersistentVolumeClaim 已在其他地方绑定。
                // The PV must have been created with this ptr; leave it alone.
					logger.V(4).Info("Synchronizing PersistentVolume, volume is bound by user to a claim that is bound to another volume, waiting for the claim to get unbound", "volumeName", volume.Name)
					// This just updates the volume phase and clears
					// volume.Spec.ClaimRef.UID. It leaves the volume pre-bound
					// to the claim.
					if err = ctrl.unbindVolume(ctx, volume); err != nil {
						return err
					}
					return nil

    		}
     }
	}
}
```

###### updateVolumeMigrationAnnotationsAndFinalizers

```go
func (ctrl *PersistentVolumeController) updateVolumeMigrationAnnotationsAndFinalizers(ctx context.Context,
	volume *v1.PersistentVolume) (*v1.PersistentVolume, error) {
	volumeClone := volume.DeepCopy() // 复制传入的持久卷对象，避免直接修改原对象
	logger := klog.FromContext(ctx) // 从上下文中获取日志记录器
	annModified := updateMigrationAnnotations(logger, ctrl.csiMigratedPluginManager, ctrl.translator, volumeClone.Annotations, false) // 调用updateMigrationAnnotations函数更新持久卷对象的迁移注释，并返回是否有修改
	modifiedFinalizers, finalizersModified := modifyDeletionFinalizers(logger, ctrl.csiMigratedPluginManager, volumeClone) // 调用modifyDeletionFinalizers函数修改持久卷对象的删除终结器，并返回修改后的终结器列表和是否有修改
	if !annModified && !finalizersModified { // 如果没有对迁移注释和删除终结器进行修改，则直接返回复制后的持久卷对象
		return volumeClone, nil
	}
	if finalizersModified { // 如果删除终结器有修改，则更新持久卷对象的终结器列表
		volumeClone.ObjectMeta.SetFinalizers(modifiedFinalizers)
	}
	newVol, err := ctrl.kubeClient.CoreV1().PersistentVolumes().Update(ctx, volumeClone, metav1.UpdateOptions{}) // 调用 Kubernetes 客户端接口更新持久卷对象
	if err != nil {
		return nil, fmt.Errorf("persistent Volume Controller can't anneal migration annotations or finalizer: %v", err) // 如果更新失败，则返回错误
	}
	_, err = ctrl.storeVolumeUpdate(logger, newVol) // 调用 storeVolumeUpdate 函数记录持久卷对象的更新操作
	if err != nil {
		return nil, fmt.Errorf("persistent Volume Controller can't anneal migration annotations or finalizer: %v", err) // 如果记录更新操作失败，则返回错误
	}
	return newVol, nil // 返回更新后的持久卷对象
}
```

###### updateVolumePhase

```go
func (ctrl *PersistentVolumeController) updateVolumePhase(ctx context.Context, volume *v1.PersistentVolume, phase v1.PersistentVolumePhase, message string) (*v1.PersistentVolume, error) {
	logger := klog.FromContext(ctx) // 从上下文中获取日志记录器
	logger.V(4).Info("Updating PersistentVolume", "volumeName", volume.Name, "setPhase", phase) // 记录持久卷更新操作的日志
	if volume.Status.Phase == phase {
		// 无需操作，持久卷的状态已经是目标状态
		logger.V(4).Info("Updating PersistentVolume: phase already set", "volumeName", volume.Name, "phase", phase)
		return volume, nil
	}

	volumeClone := volume.DeepCopy() // 复制传入的持久卷对象，避免直接修改原对象
	volumeClone.Status.Phase = phase // 更新持久卷对象的状态为目标状态
	volumeClone.Status.Message = message // 更新持久卷对象的状态消息

	newVol, err := ctrl.kubeClient.CoreV1().PersistentVolumes().UpdateStatus(ctx, volumeClone, metav1.UpdateOptions{}) // 调用 Kubernetes 客户端接口更新持久卷对象的状态
	if err != nil {
		logger.V(4).Info("Updating PersistentVolume: set phase failed", "volumeName", volume.Name, "phase", phase, "err", err) // 如果更新状态失败，则记录错误日志
		return newVol, err
	}
	_, err = ctrl.storeVolumeUpdate(logger, newVol) // 调用 storeVolumeUpdate 函数记录持久卷对象的更新操作
	if err != nil {
		logger.V(4).Info("Updating PersistentVolume: cannot update internal cache", "volumeName", volume.Name, "err", err) // 如果记录更新操作失败，则记录错误日志
		return newVol, err
	}
	logger.V(2).Info("Volume entered phase", "volumeName", volume.Name, "phase", phase) // 记录持久卷进入目标状态的日志
	return newVol, err
}
```

###### reclaimVolume

```go
func (ctrl *PersistentVolumeController) reclaimVolume(ctx context.Context, volume *v1.PersistentVolume) error {
	logger := klog.FromContext(ctx)  // 根据上下文创建日志记录器

	if migrated := volume.Annotations[storagehelpers.AnnMigratedTo]; len(migrated) > 0 {
		// PV 已迁移。PV 控制器应该停止操作，由外部的供应者处理这个 PV
		return nil
	}

	switch volume.Spec.PersistentVolumeReclaimPolicy {
	case v1.PersistentVolumeReclaimRetain:
		logger.V(4).Info("ReclaimVolume: policy is Retain, nothing to do", "volumeName", volume.Name)  // 持久卷回收策略为 Retain，无需处理

	case v1.PersistentVolumeReclaimRecycle:
		logger.V(4).Info("ReclaimVolume: policy is Recycle", "volumeName", volume.Name)  // 持久卷回收策略为 Recycle
		opName := fmt.Sprintf("recycle-%s[%s]", volume.Name, string(volume.UID))  // 创建操作名称
		ctrl.scheduleOperation(logger, opName, func() error {
			ctrl.recycleVolumeOperation(ctx, volume)  // 调用 recycleVolumeOperation 方法进行回收操作
			return nil
		})

	case v1.PersistentVolumeReclaimDelete:
		logger.V(4).Info("ReclaimVolume: policy is Delete", "volumeName", volume.Name)  // 持久卷回收策略为 Delete
		opName := fmt.Sprintf("delete-%s[%s]", volume.Name, string(volume.UID))  // 创建操作名称
		// 如果缓存中不存在 key = volume.Name, pluginName = provisionerName, operation = "delete" 的时间戳条目，则创建一个起始时间戳的缓存条目
		ctrl.operationTimestamps.AddIfNotExist(volume.Name, ctrl.getProvisionerNameFromVolume(volume), "delete")
		ctrl.scheduleOperation(logger, opName, func() error {
			_, err := ctrl.deleteVolumeOperation(ctx, volume)  // 调用 deleteVolumeOperation 方法进行删除操作
			if err != nil {
				// 只在最终删除持久卷并捕获到持久卷删除事件时，向 "volume_operation_total_errors" 记录错误计数
				// 操作耗时的统计会在最终删除持久卷时进行
				metrics.RecordMetric(volume.Name, &ctrl.operationTimestamps, err)
			}
			return err
		})

	default:
		// 未知的持久卷回收策略
		if _, err := ctrl.updateVolumePhaseWithEvent(ctx, volume, v1.VolumeFailed, v1.EventTypeWarning, "VolumeUnknownReclaimPolicy", "Volume has unrecognized PersistentVolumeReclaimPolicy"); err != nil {
			return err
		}
	}

	return nil
}
```

###### unbindVolume

```go
func (ctrl *PersistentVolumeController) unbindVolume(ctx context.Context, volume *v1.PersistentVolume) error {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Updating PersistentVolume: rolling back binding from claim", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name)

	// Save the PV only when any modification is necessary.
	volumeClone := volume.DeepCopy()

	if metav1.HasAnnotation(volume.ObjectMeta, storagehelpers.AnnBoundByController) {
		// 如果卷是由控制器绑定的。
		volumeClone.Spec.ClaimRef = nil
		delete(volumeClone.Annotations, storagehelpers.AnnBoundByController)
		if len(volumeClone.Annotations) == 0 {
			// 空的注释映射比空注释看起来更好（而且更容易测试）。
			volumeClone.Annotations = nil
		}
	} else {
		// 如果卷是由用户预先绑定的，则只清除绑定的UID。
		volumeClone.Spec.ClaimRef.UID = ""
	}

	newVol, err := ctrl.kubeClient.CoreV1().PersistentVolumes().Update(ctx, volumeClone, metav1.UpdateOptions{})
	if err != nil {
		logger.V(4).Info("Updating PersistentVolume: rollback failed", "volumeName", volume.Name, "err", err)
		return err
	}
	_, err = ctrl.storeVolumeUpdate(logger, newVol)
	if err != nil {
		logger.V(4).Info("Updating PersistentVolume: cannot update internal cache", "volumeName", volume.Name, "err", err)
		return err
	}
	logger.V(4).Info("Updating PersistentVolume: rolled back", "volumeName", newVol.Name)

	// 更新状态
	_, err = ctrl.updateVolumePhase(ctx, newVol, v1.VolumeAvailable, "")
	return err
}
```

#### deleteVolume

````go
func (ctrl *PersistentVolumeController) deleteVolume(ctx context.Context, volume *v1.PersistentVolume) {
	// 使用指定的上下文创建一个日志记录器
	logger := klog.FromContext(ctx)

	// 删除持久卷，如果删除过程中出错，则记录错误日志
	if err := ctrl.volumes.store.Delete(volume); err != nil {
		logger.Error(err, "Volume deletion encountered", "volumeName", volume.Name)
	} else {
		// 否则，记录删除成功的日志
		logger.V(4).Info("volume deleted", "volumeName", volume.Name)
	}

	// 如果在缓存中存在持久卷的删除时间戳，则记录删除指标
	// 如果缓存中没有该持久卷的时间戳，则以下调用将不执行任何操作
	// 时间戳缓存项生命周期结束时，"RecordMetric" 函数将进行清理
	metrics.RecordMetric(volume.Name, &ctrl.operationTimestamps, nil)

	// 如果持久卷的 ClaimRef 为空，则直接返回
	if volume.Spec.ClaimRef == nil {
		return
	}

	// 当持久卷被删除时，同步其对应的声明。在卷删除时显式地同步声明，
	// 以防止声明等待下一次同步周期来更新其 Lost 状态。
	claimKey := claimrefToClaimKey(volume.Spec.ClaimRef)
	logger.V(5).Info("deleteVolume: scheduling sync of claim", "PVC", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name), "volumeName", volume.Name)
	ctrl.claimQueue.Add(claimKey)
}

````

### claimWorker

```go
func (ctrl *PersistentVolumeController) claimWorker(ctx context.Context) {
    // 使用 context 来记录日志
    logger := klog.FromContext(ctx)
    // 定义 workFunc 函数来处理队列中的任务
    workFunc := func() bool {
        // 从队列中获取任务
        keyObj, quit := ctrl.claimQueue.Get()
        if quit {
            return true
        }
        // 处理完成后将任务从队列中删除
        defer ctrl.claimQueue.Done(keyObj)

        // 将任务 keyObj 转换为字符串类型的 key
        key := keyObj.(string)

        // 使用 V 方法记录日志，级别为 5
        logger.V(5).Info("claimWorker", "claimKey", key)

        // 解析 key，获取 namespace 和 name
        namespace, name, err := cache.SplitMetaNamespaceKey(key)
        if err != nil {
            // 如果解析 key 出错，则记录日志，级别为 4
            logger.V(4).Info("Error getting namespace & name of claim to get claim from informer", "claimKey", key, "err", err)
            return false
        }

        // 获取对应 namespace 和 name 的 claim 对象
        claim, err := ctrl.claimLister.PersistentVolumeClaims(namespace).Get(name)
        if err == nil {
            // 如果获取成功，说明事件类型为 add/update/sync，更新 claim
            ctrl.updateClaim(ctx, claim)
            return false
        }
        if !errors.IsNotFound(err) {
            // 如果获取失败，但不是因为 claim 不存在，则记录日志，级别为 2
            logger.V(2).Info("Error getting claim from informer", "claimKey", key, "err", err)
            return false
        }

        // 如果获取失败，且是因为 claim 不存在，则说明事件类型为 delete，删除 claim
        claimObj, found, err := ctrl.claims.GetByKey(key)
        if err != nil {
            logger.V(2).Info("Error getting claim from cache", "claimKey", key, "err", err)
            return false
        }
        if !found {
            // 如果在 cache 中找不到对应的 claim，说明已经处理了该事件，直接返回
            logger.V(2).Info("Deletion of claim was already processed", "claimKey", key)
            return false
        }
        claim, ok := claimObj.(*v1.PersistentVolumeClaim)
        if !ok {
            // 如果从 cache 中获取到的对象不是 PersistentVolumeClaim 类型，则记录错误日志
            logger.Error(nil, "Expected claim, got", "obj", claimObj)
            return false
        }
        ctrl.deleteClaim(ctx, claim)
        return false
    }

    // 不断循环处理队列中的任务，直到队列关闭
    for {
        if quit := workFunc(); quit {
            logger.Info("Claim worker queue shutting down")
            return
        }
    }
}
```

#### updateClaim

```go
func (ctrl *PersistentVolumeController) updateClaim(ctx context.Context, claim *v1.PersistentVolumeClaim) {
    // 将新的 PersistentVolumeClaim 存储在缓存中，并且如果这是旧版本，则不对其进行处理。
    logger := klog.FromContext(ctx)
    // 通过 ctrl.storeClaimUpdate(logger, claim) 更新缓存
    new, err := ctrl.storeClaimUpdate(logger, claim)
    if err != nil {
    	logger.Error(err, "")
    }
    if !new {
    	return
    }
    // 通过 ctrl.syncClaim(ctx, claim) 同步 PersistentVolumeClaim 到 Kubernetes API Server
    err = ctrl.syncClaim(ctx, claim)
    if err != nil {
        if errors.IsConflict(err) {
            // 版本冲突错误很常见，控制器可以很容易地从中恢复。
            logger.V(3).Info("Could not sync claim", "PVC", klog.KObj(claim), "err", err)
        } else {
            logger.Error(err, "Could not sync volume", "PVC", klog.KObj(claim))
        }
    }
}
```

##### syncClaim

```go
func (ctrl *PersistentVolumeController) syncClaim(ctx context.Context, claim *v1.PersistentVolumeClaim) error {
    // 定义了一个方法 syncClaim，接收两个参数，一个是类型为 context.Context 的 ctx，另一个是类型为 *v1.PersistentVolumeClaim 的 claim。
    logger := klog.FromContext(ctx) // 使用 klog 包中的 FromContext 方法，从 ctx 中获取 logger 对象。
logger.V(4).Info("Synchronizing PersistentVolumeClaim", "PVC", klog.KObj(claim), "claimStatus", getClaimStatusForLogging(claim))
    // 使用 logger 对象的 V 方法设置日志级别为 4，并使用 Info 方法输出日志信息。日志信息包括了 "Synchronizing PersistentVolumeClaim" 字符串以及 claim 对象的详细信息，以及通过 getClaimStatusForLogging 方法获取到的 "claimStatus" 字段的值。

    newClaim, err := ctrl.updateClaimMigrationAnnotations(ctx, claim)
    // 调用 ctrl 对象的 updateClaimMigrationAnnotations 方法，传入 ctx 和 claim 参数，并将返回的 newClaim 和 err 赋值给对应的变量。

    if err != nil {
        // 如果 err 不为空，表示在调用 updateClaimMigrationAnnotations 方法时出现了错误，则返回该错误。
        // Nothing was saved; we will fall back into the same
        // condition in the next call to this method
        return err
    }
    claim = newClaim // 将 newClaim 赋值给 claim 变量。

    if !metav1.HasAnnotation(claim.ObjectMeta, storagehelpers.AnnBindCompleted) {
        // 判断 claim 对象的 ObjectMeta 字段中是否包含名为 AnnBindCompleted 的注解，如果不包含，则调用 ctrl 对象的 syncUnboundClaim 方法处理未绑定状态的 claim 对象。
        return ctrl.syncUnboundClaim(ctx, claim)
    } else {
        // 否则，调用 ctrl 对象的 syncBoundClaim 方法处理已绑定状态的 claim 对象。
        return ctrl.syncBoundClaim(ctx, claim)
    }
}
```

###### updateClaimMigrationAnnotations

```go
func (ctrl *PersistentVolumeController) updateClaimMigrationAnnotations(ctx context.Context,
claim *v1.PersistentVolumeClaim) (*v1.PersistentVolumeClaim, error) {
    // 定义了一个方法 updateClaimMigrationAnnotations，接收两个参数，一个是类型为 context.Context 的 ctx，另一个是类型为 *v1.PersistentVolumeClaim 的 claim，并返回更新后的 claim 对象以及可能的错误。

    // TODO: update[Claim|Volume]MigrationAnnotations can be optimized to not
    // copy the claim/volume if no modifications are required. Though this
    // requires some refactoring as well as an interesting change in the
    // semantics of the function which may be undesirable. If no copy is made
    // when no modifications are required this function could sometimes return a
    // copy of the volume and sometimes return a ref to the original

    // TODO: update[Claim|Volume]MigrationAnnotations 方法可以进行优化，如果不需要进行修改，就不需要复制 claim/volume 对象。但这需要进行一些重构，并且可能会导致函数的语义变得复杂。如果不进行复制操作，那么当不需要进行修改时，该函数有时会返回一个卷对象的副本，有时会返回对原始对象的引用。

    claimClone := claim.DeepCopy() // 对 claim 对象进行深拷贝，生成一个新的 claim 对象，命名为 claimClone。

    logger := klog.FromContext(ctx) // 使用 klog 包中的 FromContext 方法，从 ctx 中获取 logger 对象。

    modified := updateMigrationAnnotations(logger, ctrl.csiMigratedPluginManager, ctrl.translator, claimClone.Annotations, true)
    // 调用 updateMigrationAnnotations 方法，传入 logger、ctrl.csiMigratedPluginManager、ctrl.translator 和 claimClone.Annotations 等参数，将返回的布尔值赋值给 modified 变量，表示是否对 claimClone 进行了修改。

    if !modified {
        // 如果 modified 为 false，表示 claimClone 没有进行修改，则直接返回 claimClone 对象和 nil 错误。
        return claimClone, nil
    }

    newClaim, err := ctrl.kubeClient.CoreV1().PersistentVolumeClaims(claimClone.Namespace).Update(ctx, claimClone, metav1.UpdateOptions{})
    // 调用 kubeClient 对象的 CoreV1().PersistentVolumeClaims().Update 方法，传入 ctx、claimClone 和 UpdateOptions 参数，将返回的更新后的 claim 对象赋值给 newClaim 变量。

    if err != nil {
        // 如果在调用 Update 方法时出现错误，则返回错误信息。
        return nil, fmt.Errorf("persistent Volume Controller can't anneal migration annotations: %v", err)
    }

    _, err = ctrl.storeClaimUpdate(logger, newClaim)
    // 调用 storeClaimUpdate 方法，传入 logger 和 newClaim 参数，并将返回的错误信息赋值给 err 变量。

    if err != nil {
        // 如果在调用 storeClaimUpdate 方法时出现错误，则返回错误信息。
        return nil, fmt.Errorf("persistent Volume Controller can't anneal migration annotations: %v", err)
    }

    return newClaim, nil // 返回更新后的 claim 对象和 nil 错误。
}
```

###### updateMigrationAnnotations

````go
func updateMigrationAnnotations(logger klog.Logger, cmpm CSIMigratedPluginManager, translator CSINameTranslator, ann map[string]string, claim bool) bool {
	// 更新迁移注释函数
	// 参数：
	// - logger: 日志记录器
	// - cmpm: CSIMigratedPluginManager接口实例
	// - translator: CSINameTranslator接口实例
	// - ann: 注释map
	// - claim: 是否为声明（PersistentVolumeClaim），true表示声明，false表示卷（PersistentVolume）

	var csiDriverName string
	var err error

	if ann == nil {
		// 如果注释为空，则无法获取存储插件，并且不知道是否已迁移，无需更改，返回false
		return false
	}
	var provisionerKey string
	if claim {
		provisionerKey = storagehelpers.AnnStorageProvisioner
	} else {
		provisionerKey = storagehelpers.AnnDynamicallyProvisioned
	}
	provisioner, ok := ann[provisionerKey]
	if !ok {
		if claim {
			// 对于声明，还需要检查beta AnnStorageProvisioner注释以确保其存在
			provisioner, ok = ann[storagehelpers.AnnBetaStorageProvisioner]
			if !ok {
				// 如果找不到存储插件注释，则返回false
				return false
			}
		} else {
			// 对于卷，如果找不到存储插件注释，则返回false
			return false
		}
	}

	migratedToDriver := ann[storagehelpers.AnnMigratedTo]
	if cmpm.IsMigrationEnabledForPlugin(provisioner) {
		// 如果存储插件支持迁移，则获取对应的CSI驱动名称
		csiDriverName, err = translator.GetCSINameFromInTreeName(provisioner)
		if err != nil {
			// 如果迁移已启用但找不到对应的驱动名称，则记录错误日志，并返回false
			logger.Error(err, "Could not update volume migration annotations. Migration enabled for plugin but could not find corresponding driver name", "plugin", provisioner)
			return false
		}
		if migratedToDriver != csiDriverName {
			// 如果当前的迁移目标驱动与获取到的CSI驱动名称不一致，则更新注释并返回true
			ann[storagehelpers.AnnMigratedTo] = csiDriverName
			return true
		}
	} else {
		if migratedToDriver != "" {
			// 如果迁移注释存在但当前驱动未迁移，则删除注释并返回true
			delete(ann, storagehelpers.AnnMigratedTo)
			return true
		}
	}
	// 默认返回false
	return false
}
````

###### syncUnboundClaim

````go
func (ctrl *PersistentVolumeController) syncUnboundClaim(ctx context.Context, claim *v1.PersistentVolumeClaim) error {
	// This is a new PVC that has not completed binding
	// OBSERVATION: pvc is "Pending"
	logger := klog.FromContext(ctx)
	if claim.Spec.VolumeName == "" {
		// User did not care which PV they get.
		delayBinding, err := storagehelpers.IsDelayBindingMode(claim, ctrl.classLister)
		if err != nil {
			return err
		}

		// [Unit test set 1]
		// 查找最佳匹配的持久卷
		volume, err := ctrl.volumes.findBestMatchForClaim(claim, delayBinding)
		if err != nil {
			// 在claim中找不到匹配的持久卷，返回错误
			logger.V(2).Info("Synchronizing unbound PersistentVolumeClaim, Error finding PV for claim", "PVC", klog.KObj(claim), "err", err)
			return fmt.Errorf("error finding PV for claim %q: %w", claimToClaimKey(claim), err)
		}
		if volume == nil {
			// 找不到匹配的持久卷
			logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, no volume found", "PVC", klog.KObj(claim))
			// OBSERVATION: pvc is "Pending", will retry

			if utilfeature.DefaultFeatureGate.Enabled(features.RetroactiveDefaultStorageClass) {
				// 如果启用了RetroactiveDefaultStorageClass特性门，尝试为未绑定的持久卷声明分配默认存储类
				logger.V(4).Info("FeatureGate is enabled, attempting to assign storage class to unbound PersistentVolumeClaim", "featureGate", features.RetroactiveDefaultStorageClass, "PVC", klog.KObj(claim))
				updated, err := ctrl.assignDefaultStorageClass(ctx, claim)
				if err != nil {
					metrics.RecordRetroactiveStorageClassMetric(false)
					return fmt.Errorf("can't update PersistentVolumeClaim[%q]: %w", claimToClaimKey(claim), err)
				}
				if updated {
					// 持久卷声明更新成功，重新开始同步
					logger.V(4).Info("PersistentVolumeClaim update successful, restarting claim sync", "PVC", klog.KObj(claim))
					metrics.RecordRetroactiveStorageClassMetric(true)
					return nil
				}
			}

			switch {
			case delayBinding && !storagehelpers.IsDelayBindingProvisioning(claim):
				// 如果启用了延迟绑定模式，但当前声明不是延迟绑定，则发出事件
				if err = ctrl.emitEventForUnboundDelayBindingClaim(claim); err != nil {
					return err
				}
			case storagehelpers.GetPersistentVolumeClaimClass(claim) != "":
				// 如果声明设置了存储类，则进行卷的预配
				if err = ctrl.provisionClaim(ctx, claim); err != nil {
					return err
				}
				return nil
			default:
				ctrl.eventRecorder.Event(claim, v1.EventTypeNormal, events.FailedBinding, "no persistent volumes available for this claim and no storage class is set")
			}
            // 更新状态
			if _, err = ctrl.updateClaimStatus(ctx, claim, v1.ClaimPending, nil); err != nil {
				return err
			}
			return nil
       } else /* pv != nil */ {
			// Found a PV for this claim
			// 观察：PVC 的状态为 "Pending"，PV 的状态为 "Available"
			claimKey := claimToClaimKey(claim)
			logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume found", "PVC", klog.KObj(claim), "volumeName", volume.Name, "volumeStatus", getVolumeStatusForLogging(volume))
			if err = ctrl.bind(ctx, volume, claim); err != nil {
				// On any error saving the volume or the claim, subsequent
				// syncClaim will finish the binding.
				// record count error for provision if exists
				// timestamp entry will remain in cache until a success binding has happened
				metrics.RecordMetric(claimKey, &ctrl.operationTimestamps, err)
				return err
			}
			// OBSERVATION: claim is "Bound", pv is "Bound"
			// if exists a timestamp entry in cache, record end to end provision latency and clean up cache
			// End of the provision + binding operation lifecycle, cache will be cleaned by "RecordMetric"
			// [Unit test 12-1, 12-2, 12-4]
			metrics.RecordMetric(claimKey, &ctrl.operationTimestamps, nil)
			return nil
		} else /* pvc.Spec.VolumeName != nil */ {
		// [Unit test set 2]
		// User asked for a specific PV.
		logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume requested", "PVC", klog.KObj(claim), "volumeName", claim.Spec.VolumeName)
		obj, found, err := ctrl.volumes.store.GetByKey(claim.Spec.VolumeName)
		if err != nil {
			return err
		}
		if !found {
			// User asked for a PV that does not exist.
			// OBSERVATION: pvc is "Pending"
			// Retry later.
			logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim， volume requested and not found, will try again next time", "PVC", klog.KObj(claim), "volumeName", claim.Spec.VolumeName)
			if _, err = ctrl.updateClaimStatus(ctx, claim, v1.ClaimPending, nil); err != nil {
				return err
			}
			return nil
		} else {
			volume, ok := obj.(*v1.PersistentVolume)
			if !ok {
				return fmt.Errorf("cannot convert object from volume cache to volume %q!?: %+v", claim.Spec.VolumeName, obj)
			}
			logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume requested and found", "PVC", klog.KObj(claim), "volumeName", claim.Spec.VolumeName, "volumeStatus", getVolumeStatusForLogging(volume))
            // 判断持久卷的 Spec.ClaimRef 是否为空，即判断持久卷是否已经被声明
			if volume.Spec.ClaimRef == nil {
				// 检查卷的 ClaimRef 是否为空
                // 用户请求的 PV 尚未被声明
                // 观察：PVC 的状态为 "Pending"，PV 的状态为 "Available"
				logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume is unbound, binding", "PVC", klog.KObj(claim))
                // 检查卷是否满足声明的要求
				if err = checkVolumeSatisfyClaim(volume, claim); err != nil {
					logger.V(4).Info("Can't bind the claim to volume", "volumeName", volume.Name, "err", err)
					// send an event
					msg := fmt.Sprintf("Cannot bind to requested volume %q: %s", volume.Name, err)
					ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.VolumeMismatch, msg)
					// 卷不满足声明的要求
					if _, err = ctrl.updateClaimStatus(ctx, claim, v1.ClaimPending, nil); err != nil {
						return err
					}
				} else if err = ctrl.bind(ctx, volume, claim); err != nil {
					// 如果保存卷和声明时出现任何错误，后续的同步操作会完成绑定
					return err
				}
				// 观察：PVC 的状态为 "Bound"，PV 的状态为 "Bound"
				return nil
			} else if storagehelpers.IsVolumeBoundToClaim(volume, claim) {
				// 检查卷是否已经被声明绑定
                // 用户请求的 PV 已经被该 PVC 声明绑定
                // 观察：PVC 的状态为 "Pending"，PV 的状态为 "Bound"
				logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume already bound, finishing the binding", "PVC", klog.KObj(claim))

				// 完成卷的绑定，添加声明的 UID
				if err = ctrl.bind(ctx, volume, claim); err != nil {
					return err
				}
				// 观察：PVC 的状态为 "Bound"，PV 的状态为 "Bound"
				return nil
			} else {
				// 用户请求的 PV 已经被其他 PVC 声明绑定
				// 观察：PVC 的状态为 "Pending"，PV 的状态为 "Bound"
				if !metav1.HasAnnotation(claim.ObjectMeta, storagehelpers.AnnBoundByController) {
                   	// 如果 PVC 对象的注释中没有 AnnBoundByController 标记
					logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume already bound to different claim by user, will retry later", "PVC", klog.KObj(claim))
					claimMsg := fmt.Sprintf("volume %q already bound to a different claim.", volume.Name)
					ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.FailedBinding, claimMsg)
					// 用户请求的是特定的 PV，稍后重试
					if _, err = ctrl.updateClaimStatus(ctx, claim, v1.ClaimPending, nil); err != nil {
						return err
					}
					return nil
				} else {
					//这不应该发生，因为有人必须删除
					//声明上的AnnBindCompleted注释。
					logger.V(4).Info("Synchronizing unbound PersistentVolumeClaim, volume already bound to different claim by controller, THIS SHOULD NEVER HAPPEN", "PVC", klog.KObj(claim), "boundClaim", klog.KRef(volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name))
					claimMsg := fmt.Sprintf("volume %q already bound to a different claim.", volume.Name)
					ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.FailedBinding, claimMsg)

					return fmt.Errorf("invalid binding of claim %q to volume %q: volume already claimed by %q", claimToClaimKey(claim), claim.Spec.VolumeName, claimrefToClaimKey(volume.Spec.ClaimRef))
				}
			}
		}
	}
}

````

###### assignDefaultStorageClass

```GO
func (ctrl *PersistentVolumeController) assignDefaultStorageClass(ctx context.Context, claim *v1.PersistentVolumeClaim) (bool, error) {
	// 从上下文中获取logger
	logger := klog.FromContext(ctx)

	// 检查 PersistentVolumeClaim 是否已经设置了 storage class，如果已经设置了则直接返回
	if storagehelpers.GetPersistentVolumeClaimClass(claim) != "" {
		return false, nil
	}

	// 获取默认的 storage class
	class, err := util.GetDefaultClass(ctrl.classLister)
	if err != nil {
		// 如果获取默认的 storage class 出错，记录日志并返回错误，但仍然返回 false，因为此错误可能是因为无法列出 storage class 或者存在多个默认的 storage class
		// TODO: 在合并以下 PR 后，不再忽略错误: https://github.com/kubernetes/kubernetes/pull/110559
		logger.V(4).Info("Failed to get default storage class", "err", err)
		return false, nil
	} else if class == nil {
		// 如果没有找到默认的 storage class，则记录日志并返回错误，但仍然返回 false
		logger.V(4).Info("Can not assign storage class to PersistentVolumeClaim: default storage class not found", "PVC", klog.KObj(claim))
		return false, nil
	}

	// 记录日志，指示正在将 storage class 分配给 PersistentVolumeClaim
	logger.V(4).Info("Assigning StorageClass to PersistentVolumeClaim", "PVC", klog.KObj(claim), "storageClassName", class.Name)
	claim.Spec.StorageClassName = &class.Name
	// 更新 PersistentVolumeClaim 的 storage class
	_, err = ctrl.kubeClient.CoreV1().PersistentVolumeClaims(claim.GetNamespace()).Update(ctx, claim, metav1.UpdateOptions{})
	if err != nil {
		return false, err
	}

	// 记录日志，指示成功将 storage class 分配给 PersistentVolumeClaim
	logger.V(4).Info("Successfully assigned StorageClass to PersistentVolumeClaim", "PVC", klog.KObj(claim), "storageClassName", class.Name)
	return true, nil
}
```

###### emitEventForUnboundDelayBindingClaim

```GO
func (ctrl *PersistentVolumeController) emitEventForUnboundDelayBindingClaim(claim *v1.PersistentVolumeClaim) error {
	// 设置事件的原因和消息
	reason := events.WaitForFirstConsumer
	message := "waiting for first consumer to be created before binding"

	// 查找与 PersistentVolumeClaim 相关的未调度的 Pod
	podNames, err := ctrl.findNonScheduledPodsByPVC(claim)
	if err != nil {
		return err
	}

	// 如果存在未调度的 Pod，则更新事件的原因和消息
	if len(podNames) > 0 {
		reason = events.WaitForPodScheduled
		if len(podNames) > 1 {
			// 尽管在卷调度时只考虑一个 Pod，但可能有多个 Pod 引用了同一个 PVC。
			// 我们无法知道哪个 Pod 用于调度，所以将所有的 Pods 都包括在等待消息中。
			message = fmt.Sprintf("waiting for pods %s to be scheduled", strings.Join(podNames, ","))
		} else {
			message = fmt.Sprintf("waiting for pod %s to be scheduled", podNames[0])
		}
	}

	// 发出事件，记录日志
	ctrl.eventRecorder.Event(claim, v1.EventTypeNormal, reason, message)
	return nil
}

```

###### findNonScheduledPodsByPVC

```GO
func (ctrl *PersistentVolumeController) findNonScheduledPodsByPVC(pvc *v1.PersistentVolumeClaim) ([]string, error) {
	// 根据 PersistentVolumeClaim 的命名空间和名称生成键值
	pvcKey := fmt.Sprintf("%s/%s", pvc.Namespace, pvc.Name)

	// 根据键值查找与之关联的 Pod 列表
	pods, err := ctrl.findPodsByPVCKey(pvcKey)
	if err != nil {
		return nil, err
	}

	// 遍历 Pod 列表，找出未调度的 Pod 的名称
	podNames := []string{}
	for _, pod := range pods {
		// 如果 Pod 处于终止状态，则跳过
		if util.IsPodTerminated(pod, pod.Status) {
			continue
		}
		// 如果 Pod 的节点名称为空，则将 Pod 的名称添加到结果列表中
		if len(pod.Spec.NodeName) == 0 {
			podNames = append(podNames, pod.Name)
		}
	}

	// 返回未调度的 Pod 的名称列表
	return podNames, nil
}
```

###### provisionClaim

````GO
func (ctrl *PersistentVolumeController) provisionClaim(ctx context.Context, claim *v1.PersistentVolumeClaim) error {
	// 如果不启用动态供应，则直接返回 nil。
	if !ctrl.enableDynamicProvisioning {
		return nil
	}
	// 记录一个 logger 以供日志记录使用。
	logger := klog.FromContext(ctx)
	// 使用 logger 记录一个 Info 级别的日志，表明 provisionClaim 方法已开始运行，并记录一些元数据。
	logger.V(4).Info("provisionClaim: started", "PVC", klog.KObj(claim))
	// 生成一个操作名称，包括 PVC 的 claimKey 和 UID。
	opName := fmt.Sprintf("provision-%s[%s]", claimToClaimKey(claim), string(claim.UID))
	// 查找可供应的插件和存储类别，如果是外部供应程序则不返回错误。
	plugin, storageClass, err := ctrl.findProvisionablePlugin(claim)
	if err != nil {
		// 如果查找插件失败，则在 PVC 上记录 ProvisioningFailed 事件，并记录错误日志。
		ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, err.Error())
		logger.Error(err, "Error finding provisioning plugin for claim", "PVC", klog.KObj(claim))
		// 直接返回 nil，以便控制器会在每个 syncUnboundClaim() 调用中重试供应。
		// 保留 provisionClaim 调用返回 nil 的原始行为。
		return nil
	}
	// 调度一个操作，这个操作会异步运行供应程序并返回一个错误。
	ctrl.scheduleOperation(logger, opName, func() error {
		// 如果之前没有为此次操作创建缓存，那么会在缓存中添加一个以 claimKey、插件名和操作名为键的新条目。
		claimKey := claimToClaimKey(claim)
		ctrl.operationTimestamps.AddIfNotExist(claimKey, ctrl.getProvisionerName(plugin, storageClass), "provision")
		var err error
		if plugin == nil {
			// 对于外部供应程序，调用 provisionClaimOperationExternal 方法。
			_, err = ctrl.provisionClaimOperationExternal(ctx, claim, storageClass)
		} else {
			// 对于内置供应程序，调用 provisionClaimOperation 方法。
			_, err = ctrl.provisionClaimOperation(ctx, claim, plugin, storageClass)
		}
		// 如果有错误发生，则记录一个错误计数度量。
		// 时间戳条目将保留在缓存中，直到发生成功绑定为止。
		if err != nil {
			metrics.RecordMetric(claimKey, &ctrl.operationTimestamps, err)
		}
		return err
	})
	// 最终返回 nil。
	return nil
}
````

###### findProvisionablePlugin

```GO
func (ctrl *PersistentVolumeController) findProvisionablePlugin(claim *v1.PersistentVolumeClaim) (vol.ProvisionableVolumePlugin, *storage.StorageClass, error) {
	// provisionClaim() which leads here is never called with claimClass=="", we
	// can save some checks.
	claimClass := storagehelpers.GetPersistentVolumeClaimClass(claim)  //获取PVC的class，如果没有class则为空字符串
	class, err := ctrl.classLister.Get(claimClass)  //根据class获取storageClass对象
	if err != nil {
		return nil, nil, err
	}

	// Find a plugin for the class
	if ctrl.csiMigratedPluginManager.IsMigrationEnabledForPlugin(class.Provisioner) {  //如果CSI migration已经启用
		// CSI migration scenario - do not depend on in-tree plugin
		return nil, class, nil
	}
	plugin, err := ctrl.volumePluginMgr.FindProvisionablePluginByName(class.Provisioner)  //查找相应的plugin
	if err != nil {
		if !strings.HasPrefix(class.Provisioner, "kubernetes.io/") {  //如果是外部provisioner
			// External provisioner is requested, do not report error
			return nil, class, nil
		}
		return nil, class, err
	}
	return plugin, class, nil
}
```

###### scheduleOperation

```GO
func (ctrl *PersistentVolumeController) scheduleOperation(logger klog.Logger, operationName string, operation func() error) {
	logger.V(4).Info("scheduleOperation", "operationName", operationName)  //输出日志信息，表示即将开始操作

	// Poke test code that an operation is just about to get started.
	if ctrl.preOperationHook != nil {
		ctrl.preOperationHook(operationName)
	}

	err := ctrl.runningOperations.Run(operationName, operation)  //运行操作
	if err != nil {
		switch {
		case goroutinemap.IsAlreadyExists(err):  //如果操作已经在运行
			logger.V(4).Info("Operation is already running, skipping", "operationName", operationName)  //输出日志信息，表示该操作已经在运行
		case exponentialbackoff.IsExponentialBackoff(err):  //如果操作被推迟
			logger.V(4).Info("Operation postponed due to exponential backoff", "operationName", operationName)  //输出日志信息，表示该操作被推迟
		default:
			logger.Error(err, "Error scheduling operation", "operationName", operationName)  //如果有错误，则输出日志信息
		}
	}
}
```

###### provisionClaimOperationExternal

```GO
func (ctrl *PersistentVolumeController) provisionClaimOperationExternal(
	ctx context.Context,
	claim *v1.PersistentVolumeClaim,
	storageClass *storage.StorageClass) (string, error) {
	// 获取 PVC 的 StorageClass，记录日志
	claimClass := storagehelpers.GetPersistentVolumeClaimClass(claim)
	logger := klog.FromContext(ctx)
	logger.V(4).Info("provisionClaimOperationExternal started", "PVC", klog.KObj(claim), "storageClassName", claimClass)
	
	// 将 ProvisionerName 设置为外部 Provisioner 的名称
	var err error
	provisionerName := storageClass.Provisioner
	if ctrl.csiMigratedPluginManager.IsMigrationEnabledForPlugin(storageClass.Provisioner) {
		// 如果 CSI 迁移启用，则更新 Provisioner 名称以使用迁移的 CSI 插件名称
		provisionerName, err = ctrl.translator.GetCSINameFromInTreeName(storageClass.Provisioner)
		if err != nil {
			strerr := fmt.Sprintf("error getting CSI name for In tree plugin %s: %v", storageClass.Provisioner, err)
			logger.V(2).Info(strerr)
			ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)
			return provisionerName, err
		}
	}
	// 将 PVC 设置 Provisioner 注释以便外部 Provisioner 知道何时开始
	newClaim, err := ctrl.setClaimProvisioner(ctx, claim, provisionerName)
	if err != nil {
		// 保存失败，控制器将在下一个同步中重试
		logger.V(2).Info("Error saving claim", "PVC", klog.KObj(claim), "err", err)
		return provisionerName, err
	}
	claim = newClaim
	// 创建等待消息，报告事件并等待外部 Provisioner 完成
	msg := fmt.Sprintf("waiting for a volume to be created, either by external provisioner %q or manually created by system administrator", provisionerName)
	ctrl.eventRecorder.Event(claim, v1.EventTypeNormal, events.ExternalProvisioning, msg)
	logger.V(3).Info("provisionClaimOperationExternal provisioning claim", "PVC", klog.KObj(claim), "msg", msg)
	// 为了指标报告，在此处返回 Provisioner 名称
	return provisionerName, nil
}
```

###### setClaimProvisioner

```GO
func (ctrl *PersistentVolumeController) setClaimProvisioner(ctx context.Context, claim *v1.PersistentVolumeClaim, provisionerName string) (*v1.PersistentVolumeClaim, error) {
    // 如果注释已经被设置，则无需进行更改
    if val, ok := claim.Annotations[storagehelpers.AnnStorageProvisioner]; ok && val == provisionerName {
        return claim, nil
    }

    // 我们必须创建副本来修改数据，以避免修改缓存中的原始数据
    claimClone := claim.DeepCopy()
    // 添加 beta 和正式注释
    logger := klog.FromContext(ctx)
    metav1.SetMetaDataAnnotation(&claimClone.ObjectMeta, storagehelpers.AnnBetaStorageProvisioner, provisionerName)
    metav1.SetMetaDataAnnotation(&claimClone.ObjectMeta, storagehelpers.AnnStorageProvisioner, provisionerName)
    // 根据配置启用 CSI 插件的迁移注释
    updateMigrationAnnotations(logger, ctrl.csiMigratedPluginManager, ctrl.translator, claimClone.Annotations, true)
    // 调用 Kubernetes API 更新对象
    newClaim, err := ctrl.kubeClient.CoreV1().PersistentVolumeClaims(claim.Namespace).Update(ctx, claimClone, metav1.UpdateOptions{})
    if err != nil {
        return newClaim, err
    }
    // 存储对象更新并返回新对象
    _, err = ctrl.storeClaimUpdate(logger, newClaim)
    if err != nil {
        return newClaim, err
    }
    return newClaim, nil
}
```



```GO
// 为PVC声明分配一个新的卷。
func (ctrl *PersistentVolumeController) provisionClaimOperation(
	ctx context.Context,
	claim *v1.PersistentVolumeClaim,
	plugin vol.ProvisionableVolumePlugin,
	storageClass *storage.StorageClass) (string, error) {
	// 获取PVC的存储类名
	claimClass := storagehelpers.GetPersistentVolumeClaimClass(claim)
	// 从上下文中获取记录器
	logger := klog.FromContext(ctx)
	// 记录日志，标识provisionClaimOperation开始执行
	logger.V(4).Info("provisionClaimOperation started", "PVC", klog.KObj(claim), "storageClassName", claimClass)

	// called from provisionClaim(), in this case, plugin MUST NOT be nil
	// NOTE: checks on plugin/storageClass has been saved

	// 获取插件的名称
	pluginName := plugin.GetPluginName()
	// 如果插件不是csi并且声明具有数据源，则操作将失败
	if pluginName != "kubernetes.io/csi" && claim.Spec.DataSource != nil {
		// 只有CSI插件可以有数据源。如果声明中的数据源不为空且不是CSI插件，则操作将失败
		strerr := fmt.Sprintf("plugin %q is not a CSI plugin. Only CSI plugin can provision a claim with a datasource", pluginName)
		logger.V(2).Info(strerr)
		// 记录事件
		ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)
		return pluginName, fmt.Errorf(strerr)

	}

	// 获取StorageClass的供应商
	provisionerName := storageClass.Provisioner
	// 记录日志
	logger.V(4).Info("provisionClaimOperation", "PVC", klog.KObj(claim), "pluginName", pluginName, "provisionerName", provisionerName)

	// 为卷添加注释，使其与外部供应商工作流程一致
	newClaim, err := ctrl.setClaimProvisioner(ctx, claim, provisionerName)
	if err != nil {
		// 保存失败，控制器将在下一次同步时重试
		logger.V(2).Info("Error saving claim", "PVC", klog.KObj(claim), "err", err)
		return pluginName, err
	}
	// 使用新的声明进行后续操作
	claim = newClaim

	// 内部供应操作

	// 上一个provisionClaimOperation可能已经完成，而我们在等待锁时。检查是否已经为PV(具有确定性名称)分配了卷。
	pvName := ctrl.getProvisionedVolumeNameForClaim(claim)
	// 获取PV并检查是否存在
	volume, err := ctrl.kubeClient.CoreV1().PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		logger.V(3).Info("Error reading persistent volume", "PV", klog.KRef("", pvName), "err", err)
		return pluginName, err
	}
	if err == nil && volume != nil {
		// Volume has been already provisioned, nothing to do.
		logger.V(4).Info("provisionClaimOperation: volume already exists, skipping", "PVC", klog.KObj(claim))
		return pluginName, err
	}

	// 创建指向要求的引用的 claimRef
	claimRef, err := ref.GetReference(scheme.Scheme, claim)
	if err != nil {
		logger.V(3).Info("Unexpected error getting claim reference", "err", err)
		return pluginName, err
	}

	// 收集卷的选项，包括持久卷的回收策略、挂载选项、云标签、集群名称、卷名称、要求的持久卷声明以及存储类的参数。
	tags := make(map[string]string)
	tags[CloudVolumeCreatedForClaimNamespaceTag] = claim.Namespace
	tags[CloudVolumeCreatedForClaimNameTag] = claim.Name
	tags[CloudVolumeCreatedForVolumeNameTag] = pvName

	options := vol.VolumeOptions{
		PersistentVolumeReclaimPolicy: *storageClass.ReclaimPolicy,
		MountOptions:                  storageClass.MountOptions,
		CloudTags:                     &tags,
		ClusterName:                   ctrl.clusterName,
		PVName:                        pvName,
		PVC:                           claim,
		Parameters:                    storageClass.Parameters,
	}

	// 如果插件不支持挂载选项，则拒绝分配卷。因为即使通过验证，PV 的创建也会被拒绝。
	if !plugin.SupportsMountOption() && len(options.MountOptions) > 0 {
		strerr := fmt.Sprintf("Mount options are not supported by the provisioner but StorageClass %q has mount options %v", storageClass.Name, options.MountOptions)
		logger.V(2).Info("Mount options are not supported by the provisioner but claim's StorageClass has mount options", "PVC", klog.KObj(claim), "storageClassName", storageClass.Name, "options", options.MountOptions)
		ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)
		return pluginName, fmt.Errorf("provisioner %q doesn't support mount options", plugin.GetPluginName())
	}

	// Provision the volume
	provisioner, err := plugin.NewProvisioner(logger, options)
	if err != nil {
		strerr := fmt.Sprintf("Failed to create provisioner: %v", err)
		logger.V(2).Info("Failed to create provisioner for claim with StorageClass", "PVC", klog.KObj(claim), "storageClassName", storageClass.Name, "err", err)
		ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)
		return pluginName, err
	}

	var selectedNode *v1.Node = nil
	if nodeName, ok := claim.Annotations[storagehelpers.AnnSelectedNode]; ok {
		selectedNode, err = ctrl.NodeLister.Get(nodeName)
		if err != nil {
			strerr := fmt.Sprintf("Failed to get target node: %v", err)
			logger.V(3).Info("Unexpected error getting target node for claim", "node", klog.KRef("", nodeName), "PVC", klog.KObj(claim), "err", err)
			ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)
			return pluginName, err
		}
	}
	allowedTopologies := storageClass.AllowedTopologies

	opComplete := util.OperationCompleteHook(plugin.GetPluginName(), "volume_provision")
	volume, err = provisioner.Provision(selectedNode, allowedTopologies)
	opComplete(volumetypes.CompleteFuncParam{Err: &err})
	if err != nil {
		// Other places of failure have nothing to do with VolumeScheduling,
		// so just let controller retry in the next sync. We'll only call func
		// rescheduleProvisioning here when the underlying provisioning actually failed.
		ctrl.rescheduleProvisioning(ctx, claim)

		strerr := fmt.Sprintf("Failed to provision volume with StorageClass %q: %v", storageClass.Name, err)
		logger.V(2).Info("Failed to provision volume for claim with StorageClass", "PVC", klog.KObj(claim), "storageClassName", storageClass.Name, "err", err)
		ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)
		return pluginName, err
	}

	logger.V(3).Info("Volume for claim created", "PVC", klog.KObj(claim), "volumeName", volume.Name)

	// Create Kubernetes PV object for the volume.
	if volume.Name == "" {
		volume.Name = pvName
	}
	// Bind it to the claim
	volume.Spec.ClaimRef = claimRef
	volume.Status.Phase = v1.VolumeBound
	volume.Spec.StorageClassName = claimClass

	// Add AnnBoundByController (used in deleting the volume)
	metav1.SetMetaDataAnnotation(&volume.ObjectMeta, storagehelpers.AnnBoundByController, "yes")
	metav1.SetMetaDataAnnotation(&volume.ObjectMeta, storagehelpers.AnnDynamicallyProvisioned, plugin.GetPluginName())

	if utilfeature.DefaultFeatureGate.Enabled(features.HonorPVReclaimPolicy) {
		if volume.Spec.PersistentVolumeReclaimPolicy == v1.PersistentVolumeReclaimDelete {
			// Add In-Tree protection finalizer here only when the reclaim policy is `Delete`
			volume.SetFinalizers([]string{storagehelpers.PVDeletionInTreeProtectionFinalizer})
		}
	}

	// Try to create the PV object several times
	for i := 0; i < ctrl.createProvisionedPVRetryCount; i++ {
		logger.V(4).Info("provisionClaimOperation: trying to save volume", "PVC", klog.KObj(claim), "volumeName", volume.Name)
		var newVol *v1.PersistentVolume
		if newVol, err = ctrl.kubeClient.CoreV1().PersistentVolumes().Create(ctx, volume, metav1.CreateOptions{}); err == nil || apierrors.IsAlreadyExists(err) {
			// Save succeeded.
			if err != nil {
				logger.V(3).Info("Volume for claim already exists, reusing", "PVC", klog.KObj(claim), "volumeName", volume.Name)
				err = nil
			} else {
				logger.V(3).Info("Volume for claim saved", "PVC", klog.KObj(claim), "volumeName", volume.Name)

				_, updateErr := ctrl.storeVolumeUpdate(logger, newVol)
				if updateErr != nil {
					// We will get an "volume added" event soon, this is not a big error
					logger.V(4).Info("provisionClaimOperation: cannot update internal cache", "volumeName", volume.Name, "err", updateErr)
				}
			}
			break
		}
		// Save failed, try again after a while.
		logger.V(3).Info("Failed to save volume for claim", "PVC", klog.KObj(claim), "volumeName", volume.Name, "err", err)
		time.Sleep(ctrl.createProvisionedPVInterval)
	}

	if err != nil {
		// Save failed. Now we have a storage asset outside of Kubernetes,
		// but we don't have appropriate PV object for it.
		// Emit some event here and try to delete the storage asset several
		// times.
		strerr := fmt.Sprintf("Error creating provisioned PV object for claim %s: %v. Deleting the volume.", claimToClaimKey(claim), err)
		logger.V(3).Info(strerr)
		ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningFailed, strerr)

		var deleteErr error
		var deleted bool
		for i := 0; i < ctrl.createProvisionedPVRetryCount; i++ {
			_, deleted, deleteErr = ctrl.doDeleteVolume(ctx, volume)
			if deleteErr == nil && deleted {
				// Delete succeeded
				logger.V(4).Info("provisionClaimOperation: cleaning volume succeeded", "PVC", klog.KObj(claim), "volumeName", volume.Name)
				break
			}
			if !deleted {
				// This is unreachable code, the volume was provisioned by an
				// internal plugin and therefore there MUST be an internal
				// plugin that deletes it.
				logger.Error(nil, "Error finding internal deleter for volume plugin", "plugin", plugin.GetPluginName())
				break
			}
			// Delete failed, try again after a while.
			logger.V(3).Info("Failed to delete volume", "volumeName", volume.Name, "err", deleteErr)
			time.Sleep(ctrl.createProvisionedPVInterval)
		}

		if deleteErr != nil {
			// Delete failed several times. There is an orphaned volume and there
			// is nothing we can do about it.
			strerr := fmt.Sprintf("Error cleaning provisioned volume for claim %s: %v. Please delete manually.", claimToClaimKey(claim), deleteErr)
			logger.V(2).Info(strerr)
			ctrl.eventRecorder.Event(claim, v1.EventTypeWarning, events.ProvisioningCleanupFailed, strerr)
		}
	} else {
		logger.V(2).Info("Volume provisioned for claim", "PVC", klog.KObj(claim), "volumeName", volume.Name)
		msg := fmt.Sprintf("Successfully provisioned volume %s using %s", volume.Name, plugin.GetPluginName())
		ctrl.eventRecorder.Event(claim, v1.EventTypeNormal, events.ProvisioningSucceeded, msg)
	}
	return pluginName, nil
}
```

##### deleteClaim

```GO
// deleteClaim 用于删除持久卷声明
func (ctrl *PersistentVolumeController) deleteClaim(ctx context.Context, claim *v1.PersistentVolumeClaim) {
	logger := klog.FromContext(ctx) // 从上下文中获取 klog.Logger 实例

	// 删除持久卷声明
	if err := ctrl.claims.Delete(claim); err != nil {
		logger.Error(err, "Claim deletion encountered", "PVC", klog.KObj(claim)) // 记录错误日志
	}

	claimKey := claimToClaimKey(claim) // 获取持久卷声明的键值

	logger.V(4).Info("Claim deleted", "PVC", klog.KObj(claim)) // 记录日志，表示已删除持久卷声明

	// 从缓存中删除未完成的提供开始时间戳
	// Unit test [5-8] [5-9]
	ctrl.operationTimestamps.Delete(claimKey)

	volumeName := claim.Spec.VolumeName // 获取持久卷声明的卷名称
	if volumeName == "" {
		logger.V(5).Info("deleteClaim: volume not bound", "PVC", klog.KObj(claim)) // 记录日志，表示卷未绑定
		return
	}

	// 当声明被删除时，同步该卷
	// 在声明删除的响应中在此处显式同步卷，可以防止卷等待其发布的下一个同步周期。
	logger.V(5).Info("deleteClaim: scheduling sync of volume", "PVC", klog.KObj(claim), "volumeName", volumeName) // 记录日志，表示将同步卷
	ctrl.volumeQueue.Add(volumeName) // 将卷名称添加到队列中，以同步卷
}S
```

