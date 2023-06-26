---
id: 2-kube-controller-code
title: namespace-controller 代码走读
description: namespace-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 介绍

`namespace-controller` 是 Kubernetes 中处理命名空间相关逻辑的控制器，它的主要工作是确保命名空间的状态与其他资源的状态保持一致。其中，当需要删除一个命名空间时，命名空间下的资源（如 Deployment、Service、Secret 等）也需要被删除，否则它们将成为 Kubernetes 集群中的"垃圾"，影响系统性能和资源管理。

代码在 `pkg/controller/namespace` 中，删除资源和更新conditions的在 `pkg/controller/namespace/delete`

## 结构体

```go
type NamespaceController struct {
	// 一个可以从共享缓存中列出命名空间的列表器
	lister corelisters.NamespaceLister
	// 当命名空间缓存就绪时返回 true 的函数。
	listerSynced cache.InformerSynced
	// 存储待处理命名空间的队列，可以限制队列中的处理速率。
	queue workqueue.RateLimitingInterface
	// 删除命名空间时删除命名空间中所有资源的帮助器。用于处理命名空间删除事件，以确保所有相关资源都被正确删除。
	namespacedResourcesDeleter deletion.NamespacedResourcesDeleterInterface
}
```

## New

```go
func NewNamespaceController(
  // client-go的 clientset 用于和apiserver交互
	kubeClient clientset.Interface,
  // 用于管理 Kubernetes 资源的元数据
	metadataClient metadata.Interface,
  // 该函数会返回一组 API 资源列表 其中是用的就是client-go的discoverclient下方会介绍
	discoverResourcesFn func() ([]*metav1.APIResourceList, error),
  // namespace informer 用于监听 Kubernetes 中命名空间的变化
	namespaceInformer coreinformers.NamespaceInformer,
  // 定义重新同步周期 默认是0 表示不定时同时
	resyncPeriod time.Duration,
  // 用于定义 NamespaceController 的 finalizer 通常是默认的。
  // 作用是它指定了需要执行的清理逻辑。如果某个 finalizer 在删除操作完成之前仍然存在，Kubernetes 将不会删除该对象。
  // 相反，它将等待在 finalizer 中指定的清理逻辑完成后再进行删除操作。
  // 使用 Finalizer 的主要目的是确保 Kubernetes 对象被删除时，相关的资源也被正确清理。
	finalizerToken v1.FinalizerName) *NamespaceController {
	// create the controller so we can inject the enqueue function
	namespaceController := &NamespaceController{
    // 初始化 NamespaceController 的 queue 字段，创建一个名为 namespace 的新队列，该队列受速率限制。
		queue:                      workqueue.NewNamedRateLimitingQueue(nsControllerRateLimiter(), "namespace"),
    // 创建namespacedResourcesDeleter对象 用于删除其他资源 之后会介绍
		namespacedResourcesDeleter: deletion.NewNamespacedResourcesDeleter(kubeClient.CoreV1().Namespaces(), metadataClient, kubeClient.CoreV1(), discoverResourcesFn, finalizerToken),
	}

	// 从Informer内拿出来的创建和更新时间添加到队列
  // 这里为什么是更新而不是删除，是因为删除时，apiserver会把ns的metadata.DeletionTimestamp设置一个值
	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				namespace := obj.(*v1.Namespace)
				namespaceController.enqueueNamespace(namespace)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				namespace := newObj.(*v1.Namespace)
				namespaceController.enqueueNamespace(namespace)
			},
		},
		resyncPeriod,
	)
  // 创建 namespace lister
	namespaceController.lister = namespaceInformer.Lister()
  // 表示已同步完成
	namespaceController.listerSynced = namespaceInformer.Informer().HasSynced

	return namespaceController
}
```

### 添加队列

```go
// 用于将指定的对象加入到队列中等待处理
func (nm *NamespaceController) enqueueNamespace(obj interface{}) {
  // 拿出唯一key
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	
	namespace := obj.(*v1.Namespace)
	// 如果 DeletionTimestamp 等于空或者零值 说明namespace还未被删除 直接返回
	if namespace.DeletionTimestamp == nil || namespace.DeletionTimestamp.IsZero() {
		return
	}

	// 把key加入队列
	nm.queue.AddAfter(key, namespaceDeletionGracePeriod)
}

// 下方是从对象中拿出唯一key 不出意外的话是: namespace/name
KeyFunc           = cache.DeletionHandlingMetaNamespaceKeyFunc

func DeletionHandlingMetaNamespaceKeyFunc(obj interface{}) (string, error) {
  // 判断传入的对象是否是 DeletedFinalStateUnknown 类型，如果是则返回该类型中的 Key 属性，表示已删除但其元数据尚未被清理的对象的键值。如果不是，则执行下面的逻辑。
	if d, ok := obj.(DeletedFinalStateUnknown); ok {
		return d.Key, nil
	}
	return MetaNamespaceKeyFunc(obj)
}

func MetaNamespaceKeyFunc(obj interface{}) (string, error) {
	if key, ok := obj.(ExplicitKey); ok {
		return string(key), nil
	}
	meta, err := meta.Accessor(obj)
	if err != nil {
		return "", fmt.Errorf("object has no meta: %v", err)
	}
	if len(meta.GetNamespace()) > 0 {
		return meta.GetNamespace() + "/" + meta.GetName(), nil
	}
	return meta.GetName(), nil
}
```

## Run

```go
// Run starts observing the system with the specified number of workers.
func (nm *NamespaceController) Run(workers int, stopCh <-chan struct{}) {
  // 处理panic 当程序 panic 时，它会打印 panic 的堆栈信息，并将 panic 的信息发送到标准错误输出
	defer utilruntime.HandleCrash()
  // 关闭队列
	defer nm.queue.ShutDown()

	klog.Infof("Starting namespace controller")
	defer klog.Infof("Shutting down namespace controller")
	
  // 等待lister同步完成 否则缓存内会缺少数据
	if !cache.WaitForNamedCacheSync("namespace", stopCh, nm.listerSynced) {
		return
	}

	klog.V(5).Info("Starting workers of namespace controller")
  // 启动特定的数量处理worker 会有workers个groutine无限执行worker 知道stopCh被close
	for i := 0; i < workers; i++ {
		go wait.Until(nm.worker, time.Second, stopCh)
	}
	<-stopCh
}

```

## worer

```go
func (nm *NamespaceController) worker() {
	workFunc := func() bool {
    // 从队列拿出一个key 如果没有了 就返回true
		key, quit := nm.queue.Get()
		if quit {
			return true
		}
		defer nm.queue.Done(key)
	
    // 调用syncNamespaceFromKey方法去同步这个namespace。如果没有错误，就使用queue.Forget(key)将这个key从队列中删除。
    // 如果有错误发生，就需要根据错误类型做出不同的处理。
		err := nm.syncNamespaceFromKey(key.(string))
		if err == nil {
			// no error, forget this entry and return
			nm.queue.Forget(key)
			return false
		}
	
    // 如果错误类型是*deletion.ResourcesRemainingError，则表示命名空间中还有一些资源没有被删除。
    // 这种情况下，worker方法会等待估计的剩余时间的一半再次尝试处理这个key。
		if estimate, ok := err.(*deletion.ResourcesRemainingError); ok {
			t := estimate.Estimate/2 + 1
			klog.V(4).Infof("Content remaining in namespace %s, waiting %d seconds", key, t)
			nm.queue.AddAfter(key, time.Duration(t)*time.Second)
		} else {
			// 如果错误类型不是*deletion.ResourcesRemainingError，则将这个key添加回队列以便重新处理，
      // 并使用utilruntime.HandleError打印错误日志。
			nm.queue.AddRateLimited(key)
			utilruntime.HandleError(fmt.Errorf("deletion of namespace %v failed: %v", key, err))
		}
    // workFunc函数返回false，表示处理完这个key后可以继续处理下一个key。
		return false
	}

	for {
    // 使用一个无限循环来不断处理队列中的元素。如果workFunc返回了true，表示应该退出整个worker方法。
		quit := workFunc()

		if quit {
			return
		}
	}
}

```

### syncNamespaceFromKey

```go
// 它的作用是从 Namespace 的存储器中获取指定 key 的 Namespace 对象，然后删除该 Namespace 对象中的所有资源。
func (nm *NamespaceController) syncNamespaceFromKey(key string) (err error) {
  // 记录开始时间
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing namespace %q (%v)", key, time.Since(startTime))
	}()
	
  // 从 lister 拿出 namespace对象
	namespace, err := nm.lister.Get(key)
  // 如果获取不到该 Namespace 对象，说明该 Namespace 已被删除，返回 nil
	if errors.IsNotFound(err) {
		klog.Infof("Namespace has been deleted %v", key)
		return nil
	}
  // 如果出现别的的错误，使用 utilruntime.HandleError 函数处理该错误，并返回错误。
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Unable to retrieve namespace %v from store: %v", key, err))
		return err
	}
  // 删除该 Namespace 中的所有资源，并返回错误（如果有的话）。
	return nm.namespacedResourcesDeleter.Delete(namespace.Name)
}
```

## namespacedResourcesDeleter

```go
type namespacedResourcesDeleter struct {
	// 用于操作命名空间的客户端接口
	nsClient v1clientset.NamespaceInterface
	// 用于列出和删除所有命名空间范围内资源的动态客户端接口
	metadataClient metadata.Interface
	// 用于获取Pod的接口
	podsGetter v1clientset.PodsGetter
	// 缓存每个API组版本资源上不支持的操作，以避免频繁的API调用
	opCache             *operationNotSupportedCache
  // 一个函数，返回集群支持的所有API资源列表 类似kubectl api-resourse
	discoverResourcesFn func() ([]*metav1.APIResourceList, error)
	// 在删除所有命名空间资源后应从命名空间中删除的终结器标记
	finalizerToken v1.FinalizerName
}

func NewNamespacedResourcesDeleter(nsClient v1clientset.NamespaceInterface,
	metadataClient metadata.Interface, podsGetter v1clientset.PodsGetter,
	discoverResourcesFn func() ([]*metav1.APIResourceList, error),
	finalizerToken v1.FinalizerName) NamespacedResourcesDeleterInterface {
	d := &namespacedResourcesDeleter{
		nsClient:       nsClient,
		metadataClient: metadataClient,
		podsGetter:     podsGetter,
		opCache: &operationNotSupportedCache{
			m: make(map[operationKey]bool),
		},
		discoverResourcesFn: discoverResourcesFn,
		finalizerToken:      finalizerToken,
	}
  // 初始化操作缓存
	d.initOpCache()
	return d
}
```

### initOpCache

```go

func (d *namespacedResourcesDeleter) initOpCache() {
	// 使用discoverResourcesFn获取k8s的所有资源
	resources, err := d.discoverResourcesFn()
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to get all supported resources from server: %v", err))
	}
	if len(resources) == 0 {
		klog.Fatalf("Unable to get any supported resources from server: %v", err)
	}

	for _, rl := range resources {
    // 解析资源的 group 和 version
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			klog.Errorf("Failed to parse GroupVersion %q, skipping: %v", rl.GroupVersion, err)
			continue
		}

		for _, r := range rl.APIResources {
      // 获取到  group、version 和 resoure
			gvr := schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: r.Name}
			verbs := sets.NewString([]string(r.Verbs)...)
			
      // 如果这个资源不支持删除 打印错误
			if !verbs.Has("delete") {
				klog.V(6).Infof("Skipping resource %v because it cannot be deleted.", gvr)
			}
			
      // 如果资源一直批量删除 就不放在缓存里 直接删除，节省资源
			for _, op := range []operation{operationList, operationDeleteCollection} {
				if !verbs.Has(string(op)) {
					d.opCache.setNotSupported(operationKey{operation: op, gvr: gvr})
				}
			}
		}
	}
}
```

### Delete

```go
func (d *namespacedResourcesDeleter) Delete(nsName string) error {
  // 获取最新的命名空间对象
	namespace, err := d.nsClient.Get(context.TODO(), nsName, metav1.GetOptions{})
	if err != nil {
    // 如果命名空间已经被删除，则返回 nil
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
  // 命名空间是否处于删除中，如果不是则返回 nil；
	if namespace.DeletionTimestamp == nil {
		return nil
	}

	klog.V(5).Infof("namespace controller - syncNamespace - namespace: %s, finalizerToken: %s", namespace.Name, d.finalizerToken)

	// 确保命名空间的状态是最新的
	namespace, err = d.retryOnConflictError(namespace, d.updateNamespaceStatusFunc)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// 如果命名空间的删除时间戳是零，则返回 nil  说明目前没在删除
	if namespace.DeletionTimestamp.IsZero() {
		return nil
	}

	// 已经被最终处理，则返回 nil
	if finalized(namespace) {
		return nil
	}

	// 试图删除命名空间中的所有内容
	estimate, err := d.deleteAllContent(namespace)
	if err != nil {
		return err
	}
  // 如果仍有资源存在，则返回 ResourcesRemainingError 类型的错误
	if estimate > 0 {
		return &ResourcesRemainingError{estimate}
	}

	// 如果已经删除了所有内容，则将命名空间标记为已最终处理
	_, err = d.retryOnConflictError(namespace, d.finalizeNamespace)
	if err != nil {
		// in normal practice, this should not be possible, but if a deployment is running
		// two controllers to do namespace deletion that share a common finalizer token it's
		// possible that a not found could occur since the other controller would have finished the delete.
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}
```

**finalizeNamespace**

- 用于清理 namespace 中的 finalizer

```go
func (d *namespacedResourcesDeleter) finalizeNamespace(namespace *v1.Namespace) (*v1.Namespace, error) {
	namespaceFinalize := v1.Namespace{}
	namespaceFinalize.ObjectMeta = namespace.ObjectMeta
	namespaceFinalize.Spec = namespace.Spec
  // 创建了一个空的字符串集合 finalizerSet，遍历传入 namespace 的所有 finalizer，将除了当前控制器指定的 finalizer 以外的 finalizer 加入到 finalizerSet 中
	finalizerSet := sets.NewString()
	for i := range namespace.Spec.Finalizers {
		if namespace.Spec.Finalizers[i] != d.finalizerToken {
			finalizerSet.Insert(string(namespace.Spec.Finalizers[i]))
		}
	}
  // 重新生成 namespaceFinalize 的 finalizer，将 finalizerSet 中的所有元素加入到 namespaceFinalize 的 finalizer 中。
	namespaceFinalize.Spec.Finalizers = make([]v1.FinalizerName, 0, len(finalizerSet))
	for _, value := range finalizerSet.List() {
		namespaceFinalize.Spec.Finalizers = append(namespaceFinalize.Spec.Finalizers, v1.FinalizerName(value))
	}
  // 使用 nsClient 对象调用 Finalize 方法，将更新后的 namespaceFinalize 对象传入，将 finalizer 从该 namespace 中删除。
  // 如果返回的错误是 NotFound，则说明该 namespace 已被删除，因此直接返回 nil 和 nil 错误；否则返回 namespace 对象和 err 错误。
	namespace, err := d.nsClient.Finalize(context.Background(), &namespaceFinalize, metav1.UpdateOptions{})
	if err != nil {
		// it was removed already, so life is good
		if errors.IsNotFound(err) {
			return namespace, nil
		}
	}
	return namespace, err
}
```



#### retryOnConflictError

该函数的作用是在更新`Namespace`对象时，处理`Conflict`错误并进行重试。函数返回更新后的`Namespace`对象及可能的错误。

`IsConflict`是当多个客户端同时尝试修改同一个资源时，可能会发生冲突

```go
func (d *namespacedResourcesDeleter) retryOnConflictError(namespace *v1.Namespace, fn updateNamespaceFunc) (result *v1.Namespace, err error) {
	latestNamespace := namespace
	for {
		result, err = fn(latestNamespace)
		if err == nil {
			return result, nil
		}
		if !errors.IsConflict(err) {
			return nil, err
		}
		prevNamespace := latestNamespace
		latestNamespace, err = d.nsClient.Get(context.TODO(), latestNamespace.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
    // 检查新旧对象的UID是否相同，以确保获取到的最新对象确实是先前正在更新的对象的最新版本
		if prevNamespace.UID != latestNamespace.UID {
			return nil, fmt.Errorf("namespace uid has changed across retries")
		}
	}
}
```

上边的函数fn为 updateNamespaceStatusFunc
```go
func (d *namespacedResourcesDeleter) updateNamespaceStatusFunc(namespace *v1.Namespace) (*v1.Namespace, error) {
  // 如果删除中是零值 或者 Phase 是 NamespaceTerminating
  // NamespaceTerminating是namespace正在删除 代表有人处理过了
	if namespace.DeletionTimestamp.IsZero() || namespace.Status.Phase == v1.NamespaceTerminating {
		return namespace, nil
	}
	newNamespace := namespace.DeepCopy()
  // 新创建的 Namespace 对象的 Status.Phase 字段设置为 v1.NamespaceTerminating
	newNamespace.Status.Phase = v1.NamespaceTerminating
  // 使用 nsClient.UpdateStatus() 方法更新 Namespace 对象的状态信息，并返回更新后的 Namespace 对象以及可能发生的错误信息。
	return d.nsClient.UpdateStatus(context.TODO(), newNamespace, metav1.UpdateOptions{})
}
```

### 删除全部资源-deleteAllContent

```go
func (d *namespacedResourcesDeleter) deleteAllContent(ns *v1.Namespace) (int64, error) {
	namespace := ns.Name
	namespaceDeletedAt := *ns.DeletionTimestamp
	var errs []error
  //  // 创建namespaceConditionUpdater结构体
	conditionUpdater := namespaceConditionUpdater{}
	estimate := int64(0)
	klog.V(4).Infof("namespace controller - deleteAllContent - namespace: %s", namespace)
	
  //  获取可操作的资源列表
	resources, err := d.discoverResourcesFn()
	if err != nil {
		// discovery errors are not fatal.  We often have some set of resources we can operate against even if we don't have a complete list
		errs = append(errs, err)
    // 更新错误状态
		conditionUpdater.ProcessDiscoverResourcesErr(err)
	}
	// 过滤支持delete操作的资源
	deletableResources := discovery.FilteredBy(discovery.SupportsAllVerbs{Verbs: []string{"delete"}}, resources)
  // 获取gvr
	groupVersionResources, err := discovery.GroupVersionResources(deletableResources)
	if err != nil {
		errs = append(errs, err)
		conditionUpdater.ProcessGroupVersionErr(err)
	}
	
  // 初始化allGVRDeletionMetadata结构体
	numRemainingTotals := allGVRDeletionMetadata{
		gvrToNumRemaining:        map[schema.GroupVersionResource]int{},
		finalizersToNumRemaining: map[string]int{},
	}
	for gvr := range groupVersionResources {
    // 删除指定组的资源
		gvrDeletionMetadata, err := d.deleteAllContentForGroupVersionResource(gvr, namespace, namespaceDeletedAt)
		if err != nil {
			// If there is an error, hold on to it but proceed with all the remaining
			// groupVersionResources.
			errs = append(errs, err)
			conditionUpdater.ProcessDeleteContentErr(err)
		}
		if gvrDeletionMetadata.finalizerEstimateSeconds > estimate {
			estimate = gvrDeletionMetadata.finalizerEstimateSeconds
		}
		if gvrDeletionMetadata.numRemaining > 0 {
			numRemainingTotals.gvrToNumRemaining[gvr] = gvrDeletionMetadata.numRemaining
			for finalizer, numRemaining := range gvrDeletionMetadata.finalizersToNumRemaining {
				if numRemaining == 0 {
					continue
				}
				numRemainingTotals.finalizersToNumRemaining[finalizer] = numRemainingTotals.finalizersToNumRemaining[finalizer] + numRemaining
			}
		}
	}
  // 更新删除状态信息
	conditionUpdater.ProcessContentTotals(numRemainingTotals)

	
	if hasChanged := conditionUpdater.Update(ns); hasChanged {
    // 如果状态信息有改变 更新Namespace的删除状态信息
		if _, err = d.nsClient.UpdateStatus(context.TODO(), ns, metav1.UpdateOptions{}); err != nil {
			utilruntime.HandleError(fmt.Errorf("couldn't update status condition for namespace %q: %v", namespace, err))
		}
	}

	//  打印日志 合并错误返回
	klog.V(4).Infof("namespace controller - deleteAllContent - namespace: %s, estimate: %v, errors: %v", namespace, estimate, utilerrors.NewAggregate(errs))
	return estimate, utilerrors.NewAggregate(errs)
}
```

**获取GVR**

```go
func GroupVersionResources(rls []*metav1.APIResourceList) (map[schema.GroupVersionResource]struct{}, error) {
	gvrs := map[schema.GroupVersionResource]struct{}{}
	for _, rl := range rls {
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			return nil, err
		}
		for i := range rl.APIResources {
			gvrs[schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: rl.APIResources[i].Name}] = struct{}{}
		}
	}
	return gvrs, nil
}

//schema.GroupVersionResource
type GroupVersionResource struct {
	Group    string
	Version  string
	Resource string
}
```

#### deleteAllContentForGroupVersionResource

```go
func (d *namespacedResourcesDeleter) deleteAllContentForGroupVersionResource(
	gvr schema.GroupVersionResource, namespace string,
	namespaceDeletedAt metav1.Time) (gvrDeletionMetadata, error) {
	klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - namespace: %s, gvr: %v", namespace, gvr)

	// 估计删除资源所需的时间（对于支持渐进式删除的对象是必需的）
	estimate, err := d.estimateGracefulTermination(gvr, namespace, namespaceDeletedAt)
	if err != nil {
		klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - unable to estimate - namespace: %s, gvr: %v, err: %v", namespace, gvr, err)
		return gvrDeletionMetadata{}, err
	}
	klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - estimate - namespace: %s, gvr: %v, estimate: %v", namespace, gvr, estimate)

	// 首先尝试一次性删除所有资源
	deleteCollectionSupported, err := d.deleteCollection(gvr, namespace)
	if err != nil {
		return gvrDeletionMetadata{finalizerEstimateSeconds: estimate}, err
	}

	// 如果删除不受支持，则逐个列出并删除每个资源
	if !deleteCollectionSupported {
		err = d.deleteEachItem(gvr, namespace)
		if err != nil {
      // 如果删除失败，则返回估计时间和错误
			return gvrDeletionMetadata{finalizerEstimateSeconds: estimate}, err
		}
	}

	// verify there are no more remaining items
	// it is not an error condition for there to be remaining items if local estimate is non-zero
	klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - checking for no more items in namespace: %s, gvr: %v", namespace, gvr)
  // 检查是否有剩余资源
	unstructuredList, listSupported, err := d.listCollection(gvr, namespace)
	if err != nil {
    // 如果出现错误，则返回估计时间和错误
		klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - error verifying no items in namespace: %s, gvr: %v, err: %v", namespace, gvr, err)
		return gvrDeletionMetadata{finalizerEstimateSeconds: estimate}, err
	}
	if !listSupported {
    // 如果不支持列出，则返回估计时间和空错误
		return gvrDeletionMetadata{finalizerEstimateSeconds: estimate}, nil
	}
	klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - items remaining - namespace: %s, gvr: %v, items: %v", namespace, gvr, len(unstructuredList.Items))
	if len(unstructuredList.Items) == 0 {
		// // 如果没有剩余资源，则返回估计时间和剩余资源数量为0
		return gvrDeletionMetadata{finalizerEstimateSeconds: 0, numRemaining: 0}, nil
	}

	// 获取每个资源的finalizer
	finalizersToNumRemaining := map[string]int{}
	for _, item := range unstructuredList.Items {
		for _, finalizer := range item.GetFinalizers() {
			finalizersToNumRemaining[finalizer] = finalizersToNumRemaining[finalizer] + 1
		}
	}

	if estimate != int64(0) {
    // 如果存在估计时间，则返回估计时间和剩余资源数量和finalizer列表
		klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - estimate is present - namespace: %s, gvr: %v, finalizers: %v", namespace, gvr, finalizersToNumRemaining)
		return gvrDeletionMetadata{
			finalizerEstimateSeconds: estimate,
			numRemaining:             len(unstructuredList.Items),
			finalizersToNumRemaining: finalizersToNumRemaining,
		}, nil
	}

	// 判断是否存在finalizer，如果存在，则会输出一条日志记录这些存在finalizer的资源，并且返回一个结构体gvrDeletionMetadata，
  // 其中包括finalizerEstimateSeconds表示等待finalizer执行完的时间预估，numRemaining表示还剩下多少个资源未删除，
  // finalizersToNumRemaining表示每个finalizer下还有多少个资源未删除。
	if len(finalizersToNumRemaining) > 0 {
		klog.V(5).Infof("namespace controller - deleteAllContentForGroupVersionResource - items remaining with finalizers - namespace: %s, gvr: %v, finalizers: %v", namespace, gvr, finalizersToNumRemaining)
		return gvrDeletionMetadata{
			finalizerEstimateSeconds: finalizerEstimateSeconds,
			numRemaining:             len(unstructuredList.Items),
			finalizersToNumRemaining: finalizersToNumRemaining,
		}, nil
	}

	// 如果不存在finalizer，则该函数会继续执行下一步，判断是否还有未被删除的资源。如果存在未被删除的资源，
  // 则会返回一个结构体gvrDeletionMetadata，其中包括finalizerEstimateSeconds表示等待未被删除资源删除的时间预估，
  // numRemaining表示还剩下多少个资源未删除，并且同时返回一个错误信息，表示仍有未被删除的资源存在。
	return gvrDeletionMetadata{
		finalizerEstimateSeconds: estimate,
		numRemaining:             len(unstructuredList.Items),
	}, fmt.Errorf("unexpected items still remain in namespace: %s for gvr: %v", namespace, gvr)
}
```

##### estimateGracefulTermination

- 用于评估某个资源在删除时需要等待多长时间才能保证其在删除过程中完成清理工作

```go
func (d *namespacedResourcesDeleter) estimateGracefulTermination(gvr schema.GroupVersionResource, ns string, namespaceDeletedAt metav1.Time) (int64, error) {
	groupResource := gvr.GroupResource()
	klog.V(5).Infof("namespace controller - estimateGracefulTermination - group %s, resource: %s", groupResource.Group, groupResource.Resource)
	estimate := int64(0)
	var err error
	switch groupResource {
	case schema.GroupResource{Group: "", Resource: "pods"}:
    // 调用estimateGracefulTerminationForPods 进行评估
		estimate, err = d.estimateGracefulTerminationForPods(ns)
	}
	if err != nil {
		return 0, err
	}
	// 首先，通过 time.Since(namespaceDeletedAt.Time) 计算出当前时间与 namespaceDeletedAt 时间之间的差值，
  // 也就是当前时间距离命名空间被删除的时间。然后，将 estimate 转换为一个时间段 time.Duration(estimate) * time.Second，
  // 并与这个时间差进行比较。如果时间差大于等于这个时间段，说明已经超过了优雅终止期限，将 estimate 设为0，
  // 表示可以立即进行删除操作。最后将这个 estimate 返回。
	duration := time.Since(namespaceDeletedAt.Time)
	allowedEstimate := time.Duration(estimate) * time.Second
	if duration >= allowedEstimate {
		estimate = int64(0)
	}
	return estimate, nil
}
```

###### estimateGracefulTerminationForPods

```go
func (d *namespacedResourcesDeleter) estimateGracefulTerminationForPods(ns string) (int64, error) {
	klog.V(5).Infof("namespace controller - estimateGracefulTerminationForPods - namespace %s", ns)
	estimate := int64(0)
  // ：从 namespacedResourcesDeleter 结构体中获取 Pod 的 getter，用于获取指定命名空间内的 Pod 列表。
	podsGetter := d.podsGetter
  // 检查 Pod getter 是否为 nil。如果是，则返回错误，因为无法计算 Pod 的优雅删除期限。
	if podsGetter == nil || reflect.ValueOf(podsGetter).IsNil() {
		return 0, fmt.Errorf("unexpected: podsGetter is nil. Cannot estimate grace period seconds for pods")
	}
  // 从 Pod getter 中获取指定命名空间内的 Pod 列表。
	items, err := podsGetter.Pods(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	for i := range items.Items {
		pod := items.Items[i]
		//  获取当前 Pod 的状态
		phase := pod.Status.Phase
    // 如果其状态为 Succeeded 或 Failed，则直接跳过，因为已经处于终止状态，不需要计算删除期限。
		if v1.PodSucceeded == phase || v1.PodFailed == phase {
			continue
		}
    // 获取当前 Pod 的优雅删除期限
		if pod.Spec.TerminationGracePeriodSeconds != nil {
      // 取每一个grace和estimate最大值
			grace := *pod.Spec.TerminationGracePeriodSeconds
			if grace > estimate {
				estimate = grace
			}
		}
	}
	return estimate, nil
}
```



##### **deleteCollection**

```go
func (d *namespacedResourcesDeleter) deleteCollection(gvr schema.GroupVersionResource, namespace string) (bool, error) {
	klog.V(5).Infof("namespace controller - deleteCollection - namespace: %s, gvr: %v", namespace, gvr)
	
  //  构建操作键
	key := operationKey{operation: operationDeleteCollection, gvr: gvr}
  // 判断是否支持该操作。如果不支持，将输出一条日志信息，并返回false和nil。
	if !d.opCache.isSupported(key) {
		klog.V(5).Infof("namespace controller - deleteCollection ignored since not supported - namespace: %s, gvr: %v", namespace, gvr)
		return false, nil
	}

	// 使用了 DeletePropagationBackground 策略，即在删除该资源的同时，自动删除该资源的所有子资源。
	background := metav1.DeletePropagationBackground
	opts := metav1.DeleteOptions{PropagationPolicy: &background}
  // // 执行批量删除
	err := d.metadataClient.Resource(gvr).Namespace(namespace).DeleteCollection(context.TODO(), opts, metav1.ListOptions{})

	if err == nil {
		return true, nil
	}

	// 如果是 MethodNotSupported 或 NotFound 错误，则返回 false 和空错误
	if errors.IsMethodNotSupported(err) || errors.IsNotFound(err) {
		klog.V(5).Infof("namespace controller - deleteCollection not supported - namespace: %s, gvr: %v", namespace, gvr)
		return false, nil
	}
  
	// 返回 true 和错误信息
	klog.V(5).Infof("namespace controller - deleteCollection unexpected error - namespace: %s, gvr: %v, error: %v", namespace, gvr, err)
	return true, err
}

type operationKey struct {
	operation operation
	gvr       schema.GroupVersionResource
}
```

##### deleteEachItem

```go
func (d *namespacedResourcesDeleter) deleteEachItem(gvr schema.GroupVersionResource, namespace string) error {
	klog.V(5).Infof("namespace controller - deleteEachItem - namespace: %s, gvr: %v", namespace, gvr)
	// 获取指定命名空间下的所有该资源类型的资源。函数返回三个值：unstructuredList 表示获取到的资源列表，
  // listSupported 表示是否支持列表查询，err 表示是否发生错误。
	unstructuredList, listSupported, err := d.listCollection(gvr, namespace)
	if err != nil {
		return err
	}
	if !listSupported {
		return nil
	}
	for _, item := range unstructuredList.Items {
    // 使用 DeletePropagationBackground 级别的删除策略，即删除资源时会将该资源相关的所有子资源都删除。
    // 如果删除过程中发生错误并且该错误不是因为资源不存在或者该资源类型不支持该操作，则直接返回该错误。
		background := metav1.DeletePropagationBackground
		opts := metav1.DeleteOptions{PropagationPolicy: &background}
		if err = d.metadataClient.Resource(gvr).Namespace(namespace).Delete(context.TODO(), item.GetName(), opts); err != nil && !errors.IsNotFound(err) && !errors.IsMethodNotSupported(err) {
			return err
		}
	}
	return nil
}

```

##### listCollection

```go
func (d *namespacedResourcesDeleter) listCollection(gvr schema.GroupVersionResource, namespace string) (*metav1.PartialObjectMetadataList, bool, error) {
	klog.V(5).Infof("namespace controller - listCollection - namespace: %s, gvr: %v", namespace, gvr)
	
  // 定义操作 key 用于缓存查询结果
	key := operationKey{operation: operationList, gvr: gvr}
  // 判断操作 key 是否支持
	if !d.opCache.isSupported(key) {
		klog.V(5).Infof("namespace controller - listCollection ignored since not supported - namespace: %s, gvr: %v", namespace, gvr)
		return nil, false, nil
	}
	
  // 获取相应资源类型的 rest client，通过该 rest client 执行 List 操作获取资源对象列表
	partialList, err := d.metadataClient.Resource(gvr).Namespace(namespace).List(context.TODO(), metav1.ListOptions{})
	if err == nil {
		return partialList, true, nil
	}

	
	if errors.IsMethodNotSupported(err) || errors.IsNotFound(err) {
		klog.V(5).Infof("namespace controller - listCollection not supported - namespace: %s, gvr: %v", namespace, gvr)
		return nil, false, nil
	}

	return nil, true, err
}
```

## condition

```go
type namespaceConditionUpdater struct {
	newConditions       []v1.NamespaceCondition
	deleteContentErrors []error
}
// 添加一个GroupVersionParsingFailed的condition
func (u *namespaceConditionUpdater) ProcessGroupVersionErr(err error) {
	d := v1.NamespaceCondition{
		Type:               v1.NamespaceDeletionGVParsingFailure,
		Status:             v1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "GroupVersionParsingFailed",
		Message:            err.Error(),
	}
	u.newConditions = append(u.newConditions, d)
}
// 添加一个DiscoveryFailed的condition
func (u *namespaceConditionUpdater) ProcessDiscoverResourcesErr(err error) {
	var msg string
	if derr, ok := err.(*discovery.ErrGroupDiscoveryFailed); ok {
		msg = fmt.Sprintf("Discovery failed for some groups, %d failing: %v", len(derr.Groups), err)
	} else {
		msg = err.Error()
	}
	d := v1.NamespaceCondition{
		Type:               v1.NamespaceDeletionDiscoveryFailure,
		Status:             v1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "DiscoveryFailed",
		Message:            msg,
	}
	u.newConditions = append(u.newConditions, d)
}
// 处理还有gvrToNumRemaining和finalizersToNumRemaining 天津爱特定错误
func (u *namespaceConditionUpdater) ProcessContentTotals(contentTotals allGVRDeletionMetadata) {
	if len(contentTotals.gvrToNumRemaining) != 0 {
		remainingResources := []string{}
		for gvr, numRemaining := range contentTotals.gvrToNumRemaining {
			if numRemaining == 0 {
				continue
			}
			remainingResources = append(remainingResources, fmt.Sprintf("%s.%s has %d resource instances", gvr.Resource, gvr.Group, numRemaining))
		}
		// sort for stable updates
		sort.Strings(remainingResources)
		u.newConditions = append(u.newConditions, v1.NamespaceCondition{
			Type:               v1.NamespaceContentRemaining,
			Status:             v1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "SomeResourcesRemain",
			Message:            fmt.Sprintf("Some resources are remaining: %s", strings.Join(remainingResources, ", ")),
		})
	}

	if len(contentTotals.finalizersToNumRemaining) != 0 {
		remainingByFinalizer := []string{}
		for finalizer, numRemaining := range contentTotals.finalizersToNumRemaining {
			if numRemaining == 0 {
				continue
			}
			remainingByFinalizer = append(remainingByFinalizer, fmt.Sprintf("%s in %d resource instances", finalizer, numRemaining))
		}
		// sort for stable updates
		sort.Strings(remainingByFinalizer)
		u.newConditions = append(u.newConditions, v1.NamespaceCondition{
			Type:               v1.NamespaceFinalizersRemaining,
			Status:             v1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "SomeFinalizersRemain",
			Message:            fmt.Sprintf("Some content in the namespace has finalizers remaining: %s", strings.Join(remainingByFinalizer, ", ")),
		})
	}
}
```

**update**

```go
func (u *namespaceConditionUpdater) Update(ns *v1.Namespace) bool {
  // 获取 type 是NamespaceDeletionContentFailure 的condition
	if c := getCondition(u.newConditions, v1.NamespaceDeletionContentFailure); c == nil {
    // 如果为空 创建一个
		if c := makeDeleteContentCondition(u.deleteContentErrors); c != nil {
			u.newConditions = append(u.newConditions, *c)
		}
	}
  // 更新
	return updateConditions(&ns.Status, u.newConditions)
}

// 创建一个  ContentDeletionFailed 的 Condition
func makeDeleteContentCondition(err []error) *v1.NamespaceCondition {
	if len(err) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(err))
	for _, e := range err {
		msgs = append(msgs, e.Error())
	}
	sort.Strings(msgs)
	return &v1.NamespaceCondition{
		Type:               v1.NamespaceDeletionContentFailure,
		Status:             v1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "ContentDeletionFailed",
		Message:            fmt.Sprintf("Failed to delete all resource types, %d remaining: %v", len(err), strings.Join(msgs, ", ")),
	}
}

func updateConditions(status *v1.NamespaceStatus, newConditions []v1.NamespaceCondition) (hasChanged bool) {
	for _, conditionType := range conditionTypes {
    // 尝试从newConditions中获取对应类型的新条件。如果不存在，则创建一个新的成功条件
		newCondition := getCondition(newConditions, conditionType)
		if newCondition == nil {
			newCondition = newSuccessfulCondition(conditionType)
		}
    // 尝试从status.Conditions中获取对应类型的旧条件。
		oldCondition := getCondition(status.Conditions, conditionType)

		if oldCondition == nil {
      // 如果oldCondition是空 将新条件添加到状态的条件列表中，并将hasChanged设置为true，表示状态已经发生了改变。
			status.Conditions = append(status.Conditions, *newCondition)
			hasChanged = true

		} else if oldCondition.Status != newCondition.Status || oldCondition.Message != newCondition.Message || oldCondition.Reason != newCondition.Reason {
      // 如果oldCondition不为nil，则比较旧条件和新条件之间的状态、消息和原因。如果有任何一个值不同，则更新旧条件，并将hasChanged设置为true。
			// old condition needs to be updated
			if oldCondition.Status != newCondition.Status {
				oldCondition.LastTransitionTime = metav1.Now()
			}
			oldCondition.Type = newCondition.Type
			oldCondition.Status = newCondition.Status
			oldCondition.Reason = newCondition.Reason
			oldCondition.Message = newCondition.Message
			hasChanged = true
		}
	}
	return
}

func newSuccessfulCondition(conditionType v1.NamespaceConditionType) *v1.NamespaceCondition {
	return &v1.NamespaceCondition{
		Type:               conditionType,
		Status:             v1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             okReasons[conditionType],
		Message:            okMessages[conditionType],
	}
}

func getCondition(conditions []v1.NamespaceCondition, conditionType v1.NamespaceConditionType) *v1.NamespaceCondition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &(conditions[i])
		}
	}
	return nil
}

```

