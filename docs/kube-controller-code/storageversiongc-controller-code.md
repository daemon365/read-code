---
id: 7-kube-controller-code
title: storageversiongc-controller 代码走读
description: storageversiongc-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

用于管理和清理不再使用的StorageVersions对象。 storageversion 是 `kubernetes API`的存储版本，也就是资源存储倒`etcd`存储结构的版本。

当某种 API 对象被删除或者停用时，它对应的 StorageVersion 对象就不再需要了，storageversiongc-controller 就会定期扫描并删除这些无用的 StorageVersion 对象，以节省 etcd 的存储空间。

## 结构体

```go
type Controller struct {
    // client-go clientset
	kubeclientset kubernetes.Interface
	
    // lease Lister
	leaseLister  coordlisters.LeaseLister
    // leaseLister是否同步完成
	leasesSynced cache.InformerSynced
	
    // StorageVersion的Informers是否已同步完成
	storageVersionSynced cache.InformerSynced
	
    // Lease 工作队列
	leaseQueue          workqueue.RateLimitingInterface
    // storageVersion 工作队列
	storageVersionQueue workqueue.RateLimitingInterface
}
```

## New

```go
func NewStorageVersionGC(ctx context.Context, clientset kubernetes.Interface, leaseInformer coordinformers.LeaseInformer, storageVersionInformer apiserverinternalinformers.StorageVersionInformer) *Controller {
	c := &Controller{
		kubeclientset:        clientset,
		leaseLister:          leaseInformer.Lister(),
		leasesSynced:         leaseInformer.Informer().HasSynced,
		storageVersionSynced: storageVersionInformer.Informer().HasSynced,
		leaseQueue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "storage_version_garbage_collector_leases"),
		storageVersionQueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "storage_version_garbage_collector_storageversions"),
	}
	logger := klog.FromContext(ctx)
    // 监控lease的删除 调用onDeleteLease处理
	leaseInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			c.onDeleteLease(logger, obj)
		},
	})
	// 监控storageVersion对象的创建更新 做处理
	storageVersionInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.onAddStorageVersion(logger, obj)
		},
		UpdateFunc: func(old, newObj interface{}) {
			c.onUpdateStorageVersion(logger, old, newObj)
		},
	})

	return c
}
```

```GO
func (c *Controller) onDeleteLease(logger klog.Logger, obj interface{}) {
    // 虎丘删除的对象 断言失败尝试从DeletedFinalStateUnknown断言 
	castObj, ok := obj.(*coordinationv1.Lease)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		castObj, ok = tombstone.Obj.(*coordinationv1.Lease)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Lease %#v", obj))
			return
		}
	}
	
    // 再kube-system namespace下 具有一个名为 "kube-apiserver" 的标签 加入队列
	if castObj.Namespace == metav1.NamespaceSystem &&
		castObj.Labels != nil &&
		castObj.Labels[controlplane.IdentityLeaseComponentLabelKey] == controlplane.KubeAPIServer {
		logger.V(4).Info("Observed lease deleted", "castObjName", castObj.Name)
		c.enqueueLease(castObj)
	}
}

// 断言新加的对象 并加入queue
func (c *Controller) onAddStorageVersion(logger klog.Logger, obj interface{}) {
	castObj := obj.(*apiserverinternalv1alpha1.StorageVersion)
	c.enqueueStorageVersion(logger, castObj)
}

// 断言新的对象 并加入queue
func (c *Controller) onUpdateStorageVersion(logger klog.Logger, oldObj, newObj interface{}) {
	castNewObj := newObj.(*apiserverinternalv1alpha1.StorageVersion)
	c.enqueueStorageVersion(logger, castNewObj)
}

func (c *Controller) enqueueStorageVersion(logger klog.Logger, obj *apiserverinternalv1alpha1.StorageVersion) {
	for _, sv := range obj.Status.StorageVersions {
        // 获取所有版本的kube-system的lease
		lease, err := c.leaseLister.Leases(metav1.NamespaceSystem).Get(sv.APIServerID)
        // 如果错误 或者没找到lease Labels是空的 标签identity不是kube-apiserver 加入队列
		if err != nil || lease == nil || lease.Labels == nil ||
			lease.Labels[controlplane.IdentityLeaseComponentLabelKey] != controlplane.KubeAPIServer {
			// we cannot find a corresponding identity lease in cache, enqueue the storageversion
			logger.V(4).Info("Observed storage version with invalid apiserver entry", "objName", obj.Name)
			c.storageVersionQueue.Add(obj.Name)
			return
		}
	}
}
```

## Run

```go
func (c *Controller) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	defer utilruntime.HandleCrash()
	defer c.leaseQueue.ShutDown()
	defer c.storageVersionQueue.ShutDown()
	defer logger.Info("Shutting down storage version garbage collector")

	logger.Info("Starting storage version garbage collector")

	if !cache.WaitForCacheSync(ctx.Done(), c.leasesSynced, c.storageVersionSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// 启动runLeaseWorker和runStorageVersionWorker
	go wait.UntilWithContext(ctx, c.runLeaseWorker, time.Second)
	go wait.UntilWithContext(ctx, c.runStorageVersionWorker, time.Second)

	<-ctx.Done()
}
```

## runLeaseWorker

```go
func (c *Controller) runLeaseWorker(ctx context.Context) {
    // 一直执行processNextLease 知道返回false
	for c.processNextLease(ctx) {
	}
}

func (c *Controller) processNextLease(ctx context.Context) bool {
    // 从queue中拿key 知道没有了
	key, quit := c.leaseQueue.Get()
	if quit {
		return false
	}
	defer c.leaseQueue.Done(key)
	
    // 查找并删除相应的身份租约
	err := c.processDeletedLease(ctx, key.(string))
	if err == nil {
        // 成功删除key
		c.leaseQueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("lease %v failed with: %v", key, err))
    // 失败加入重试队列
	c.leaseQueue.AddRateLimited(key)
	return true
}
```

### processDeletedLease

```go
func (c *Controller) processDeletedLease(ctx context.Context, name string) error {
    // 获取lease信息
	_, err := c.kubeclientset.CoordinationV1().Leases(metav1.NamespaceSystem).Get(ctx, name, metav1.GetOptions{})
	//  如果该身份租约还存在，则返回
	if err == nil {
		return nil
	}
    // 如果不是被删除了 返回错误
	if !apierrors.IsNotFound(err) {
		return err
	}
	// 获取所有的存储信息
	storageVersionList, err := c.kubeclientset.InternalV1alpha1().StorageVersions().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var errors []error
    // 遍历每个存储版本
	for _, sv := range storageVersionList.Items {
		var serverStorageVersions []apiserverinternalv1alpha1.ServerStorageVersion
		hasStaleRecord := false
        // 查找是否有与被删除的身份租约关联的记录
		for _, ssv := range sv.Status.StorageVersions {
			if ssv.APIServerID == name {
				hasStaleRecord = true
				continue
			}
			serverStorageVersions = append(serverStorageVersions, ssv)
		}
        // 如果没有 下一个
		if !hasStaleRecord {
			continue
		}
        // 删除或更新相应的存储版
		if err := c.updateOrDeleteStorageVersion(ctx, &sv, serverStorageVersions); err != nil {
			errors = append(errors, err)
		}
	}

	return utilerrors.NewAggregate(errors)
}
```

##### updateOrDeleteStorageVersion

```go
func (c *Controller) updateOrDeleteStorageVersion(ctx context.Context, sv *apiserverinternalv1alpha1.StorageVersion, serverStorageVersions []apiserverinternalv1alpha1.ServerStorageVersion) error {
    // 如果ssv是空的 直接删除
	if len(serverStorageVersions) == 0 {
		return c.kubeclientset.InternalV1alpha1().StorageVersions().Delete(
			ctx, sv.Name, metav1.DeleteOptions{})
	}
    // 重新设置version
	sv.Status.StorageVersions = serverStorageVersions
    // 是在设置给定对象的 API 编码版本
	storageversion.SetCommonEncodingVersion(sv)
    // 更新StorageVersions
	_, err := c.kubeclientset.InternalV1alpha1().StorageVersions().UpdateStatus(
		ctx, sv, metav1.UpdateOptions{})
	return err
}
```

## runStorageVersionWorker

```go
func (c *Controller) runStorageVersionWorker(ctx context.Context) {
    // 不断执行 知道返回false
	for c.processNextStorageVersion(ctx) {
	}
}

func (c *Controller) processNextStorageVersion(ctx context.Context) bool {
    // 从queu中拿key
	key, quit := c.storageVersionQueue.Get()
	if quit {
		return false
	}
	defer c.storageVersionQueue.Done(key)
	
    // 同步特定存储版本的状态
	err := c.syncStorageVersion(ctx, key.(string))
	if err == nil {
		c.storageVersionQueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("storage version %v failed with: %v", key, err))
	c.storageVersionQueue.AddRateLimited(key)
	return true
}
```

### syncStorageVersion

```GO
func (c *Controller) syncStorageVersion(ctx context.Context, name string) error {
    // 获取StorageVersions
	sv, err := c.kubeclientset.InternalV1alpha1().StorageVersions().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// 被删除了最直接返回
		return nil
	}
	if err != nil {
		return err
	}
	
    // 用于跟踪是否存在无效的 ID
	hasInvalidID := false
	var serverStorageVersions []apiserverinternalv1alpha1.ServerStorageVersion
	for _, v := range sv.Status.StorageVersions {
        // 获取lease
		lease, err := c.kubeclientset.CoordinationV1().Leases(metav1.NamespaceSystem).Get(ctx, v.APIServerID, metav1.GetOptions{})
        // 如果lease的identity不是apiserver 为有效的id
		if err != nil || lease == nil || lease.Labels == nil ||
			lease.Labels[controlplane.IdentityLeaseComponentLabelKey] != controlplane.KubeAPIServer {
			// We cannot find a corresponding identity lease from apiserver as well.
			// We need to clean up this storage version.
			hasInvalidID = true
			continue
		}
		serverStorageVersions = append(serverStorageVersions, v)
	}
    // 如果没追踪到有效的 直接返回
	if !hasInvalidID {
		return nil
	}
    // 更新或删除版本
	return c.updateOrDeleteStorageVersion(ctx, sv, serverStorageVersions)
}
```

