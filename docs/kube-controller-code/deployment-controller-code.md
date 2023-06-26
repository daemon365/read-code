---
id: 23-kube-controller-code
title: deployment-controller 代码走读
description: deployment-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

主要用于管理Pod的创建、更新和删除等操作，使得应用程序在集群中的运行更加容易和自动化，使得应用程序在Kubernetes集群中的部署更加容易、自动化和可靠。它管理着Deployment资源对象。Deployment资源对象是一种用于管理Pod副本数量、Pod更新策略和回滚策略的Kubernetes资源对象。Deployment Controller会根据Deployment资源对象的定义，控制Pod的创建和更新，确保集群中的Pod副本数量与Deployment资源对象中定义的期望数量相同。

Deployment Controller的作用主要是：

- 确保Pod的副本数量符合Deployment资源对象中定义的期望数量；
- 对Pod进行更新和回滚；
- 自动进行故障转移和自愈恢复。

## 结构体

```GO
type DeploymentController struct {
	// 用于采用/释放replicaset资源对象的控制器
	rsControl controller.RSControlInterface
	client    clientset.Interface
	// 事件广播器，用于向集群中其他组件广播事件
	eventBroadcaster record.EventBroadcaster
    // 事件记录器，用于记录事件到日志和事件存储中
	eventRecorder    record.EventRecorder

	// 同步Deployment的函数，用于更新Deployment资源对象
	syncHandler func(ctx context.Context, dKey string) error
	// Deployment资源对象加入队列
	enqueueDeployment func(deployment *apps.Deployment)

	dLister appslisters.DeploymentLister
	rsLister appslisters.ReplicaSetLister
	podLister corelisters.PodLister


	dListerSynced cache.InformerSynced
	rsListerSynced cache.InformerSynced
	podListerSynced cache.InformerSynced

	// 需要同步的Deployment资源队列
	queue workqueue.RateLimitingInterface
}

```

## New

```GO
func NewDeploymentController(ctx context.Context, dInformer appsinformers.DeploymentInformer, rsInformer appsinformers.ReplicaSetInformer, podInformer coreinformers.PodInformer, client clientset.Interface) (*DeploymentController, error) {
	eventBroadcaster := record.NewBroadcaster()
	logger := klog.FromContext(ctx)
	dc := &DeploymentController{
		client:           client,
		eventBroadcaster: eventBroadcaster,
		eventRecorder:    eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "deployment-controller"}),
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "deployment"),
	}
	dc.rsControl = controller.RealRSControl{
		KubeClient: client,
		Recorder:   dc.eventRecorder,
	}
	// 监控deployment
	dInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dc.addDeployment(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dc.updateDeployment(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			dc.deleteDeployment(logger, obj)
		},
	})
    // 监控replicaset
	rsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			dc.addReplicaSet(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			dc.updateReplicaSet(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			dc.deleteReplicaSet(logger, obj)
		},
	})
    // 监控pod
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			dc.deletePod(logger, obj)
		},
	})

	dc.syncHandler = dc.syncDeployment
	dc.enqueueDeployment = dc.enqueue

	dc.dLister = dInformer.Lister()
	dc.rsLister = rsInformer.Lister()
	dc.podLister = podInformer.Lister()
	dc.dListerSynced = dInformer.Informer().HasSynced
	dc.rsListerSynced = rsInformer.Informer().HasSynced
	dc.podListerSynced = podInformer.Informer().HasSynced
	return dc, nil
}
```

### 队列相关

#### deployment

```go
func (dc *DeploymentController) addDeployment(logger klog.Logger, obj interface{}) {
	d := obj.(*apps.Deployment)
	logger.V(4).Info("Adding deployment", "deployment", klog.KObj(d))
	dc.enqueueDeployment(d)
}

func (dc *DeploymentController) updateDeployment(logger klog.Logger, old, cur interface{}) {
	oldD := old.(*apps.Deployment)
	curD := cur.(*apps.Deployment)
	logger.V(4).Info("Updating deployment", "deployment", klog.KObj(oldD))
	dc.enqueueDeployment(curD)
}

func (dc *DeploymentController) deleteDeployment(logger klog.Logger, obj interface{}) {
    // 取出Deployment 没有从缓存取
	d, ok := obj.(*apps.Deployment)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		d, ok = tombstone.Obj.(*apps.Deployment)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Deployment %#v", obj))
			return
		}
	}
	logger.V(4).Info("Deleting deployment", "deployment", klog.KObj(d))
	dc.enqueueDeployment(d)
}
```

##### enqueueDeployment

在New的时候赋值的

```go
func (dc *DeploymentController) enqueue(deployment *apps.Deployment) {
	key, err := controller.KeyFunc(deployment)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", deployment, err))
		return
	}

	dc.queue.Add(key)
}
```

#### replicaset

```go
func (dc *DeploymentController) addReplicaSet(logger klog.Logger, obj interface{}) {
	rs := obj.(*apps.ReplicaSet)

	if rs.DeletionTimestamp != nil {
		// 如果该ReplicaSet已标记为删除，则不进行处理，直接删除
		dc.deleteReplicaSet(logger, rs)
		return
	}
	// 如果该ReplicaSet有ControllerRef，则说明其已被某个Deployment控制，将该ControllerRef解析成Deployment，并将其加入队列等待处理。
	if controllerRef := metav1.GetControllerOf(rs); controllerRef != nil {
		d := dc.resolveControllerRef(rs.Namespace, controllerRef)
		if d == nil {
			return
		}
		logger.V(4).Info("ReplicaSet added", "replicaSet", klog.KObj(rs))
		dc.enqueueDeployment(d)
		return
	}

	// 否则，该ReplicaSet是一个孤儿ReplicaSet，需要查找与之匹配的Deployment来决定是否要采用它。
	ds := dc.getDeploymentsForReplicaSet(logger, rs)
	if len(ds) == 0 {
		return
	}
	logger.V(4).Info("Orphan ReplicaSet added", "replicaSet", klog.KObj(rs))
	for _, d := range ds {
		dc.enqueueDeployment(d)
	}
}

func (dc *DeploymentController) updateReplicaSet(logger klog.Logger, old, cur interface{}) {
	curRS := cur.(*apps.ReplicaSet)
	oldRS := old.(*apps.ReplicaSet)
	if curRS.ResourceVersion == oldRS.ResourceVersion {
		// 如果ResourceVersion相同，则不进行处理
        // 定期重新同步会向所有已知的replicadet发送更新事件。
        // 同一replicadet的两个不同版本总是具有不同的RV。
		return
	}
	
    // 获取当前replicadet和旧的replicadet的ControllerRef
	curControllerRef := metav1.GetControllerOf(curRS)
	oldControllerRef := metav1.GetControllerOf(oldRS)
    // 判断ControllerRef是否发生变化
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// 如果ControllerRef发生变化且旧的ControllerRef不为空，则将旧的ControllerRef对应的Deployment加入队列等待处理。
		if d := dc.resolveControllerRef(oldRS.Namespace, oldControllerRef); d != nil {
			dc.enqueueDeployment(d)
		}
	}
	// 如果该ReplicaSet有ControllerRef，则说明其已被某个Deployment控制，将该ControllerRef解析成Deployment，并将其加入队列等待处理。
	if curControllerRef != nil {
		d := dc.resolveControllerRef(curRS.Namespace, curControllerRef)
		if d == nil {
			return
		}
		logger.V(4).Info("ReplicaSet updated", "replicaSet", klog.KObj(curRS))
		dc.enqueueDeployment(d)
		return
	}

	// 否则，该ReplicaSet是一个孤儿ReplicaSet，如果Label或ControllerRef发生变化，则需要查找与之匹配的Deployment来决定是否要采用它。
	labelChanged := !reflect.DeepEqual(curRS.Labels, oldRS.Labels)
	if labelChanged || controllerRefChanged {
		ds := dc.getDeploymentsForReplicaSet(logger, curRS)
		if len(ds) == 0 {
			return
		}
		logger.V(4).Info("Orphan ReplicaSet updated", "replicaSet", klog.KObj(curRS))
		for _, d := range ds {
			dc.enqueueDeployment(d)
		}
	}
}

func (dc *DeploymentController) deleteReplicaSet(logger klog.Logger, obj interface{}) {
	rs, ok := obj.(*apps.ReplicaSet)

	// 如果不是ReplicaSet类型，则获取其对应的ReplicaSet对象
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
	
    // 获取ReplicaSet的ControllerRef，如果为nil，则没有Deployment控制其，不进行处理。
	controllerRef := metav1.GetControllerOf(rs)
	if controllerRef == nil {
		 // 没有Deployment控制该孤儿ReplicaSet，不进行处理。
		return
	}
    // 否则，获取控制该ReplicaSet的Deployment，并将其加入队列等待处理。
	d := dc.resolveControllerRef(rs.Namespace, controllerRef)
	if d == nil {
		return
	}
	logger.V(4).Info("ReplicaSet deleted", "replicaSet", klog.KObj(rs))
	dc.enqueueDeployment(d)
}
```

##### resolveControllerRef

```go
func (dc *DeploymentController) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *apps.Deployment {
    // 如果控制该ReplicaSet的OwnerReference的Kind不是Deployment，则返回nil。
	if controllerRef.Kind != controllerKind.Kind {
		return nil
	}
    // 获取该OwnerReference对应的Deployment对象
	d, err := dc.dLister.Deployments(namespace).Get(controllerRef.Name)
	if err != nil {
		return nil
	}
    // 如果该Deployment对象的UID与OwnerReference的UID不一致，则返回nil。
	if d.UID != controllerRef.UID {
		return nil
	}
	return d
}
```

##### getDeploymentsForReplicaSet

```go
func (dc *DeploymentController) getDeploymentsForReplicaSet(logger klog.Logger, rs *apps.ReplicaSet) []*apps.Deployment {
    // 获取控制该ReplicaSet的所有Deployment对象
	deployments, err := util.GetDeploymentsForReplicaSet(dc.dLister, rs)
	if err != nil || len(deployments) == 0 {
		return nil
	}
	// 如果返回的Deployment对象数量大于1，则记录日志
	if len(deployments) > 1 {
		logger.V(4).Info("user error! more than one deployment is selecting replica set",
			"replicaSet", klog.KObj(rs), "labels", rs.Labels, "deployment", klog.KObj(deployments[0]))
	}
	return deployments
}
```

##### GetDeploymentsForReplicaSet

```go
func GetDeploymentsForReplicaSet(deploymentLister appslisters.DeploymentLister, rs *apps.ReplicaSet) ([]*apps.Deployment, error) {
	if len(rs.Labels) == 0 {
		return nil, fmt.Errorf("no deployments found for ReplicaSet %v because it has no labels", rs.Name)
	}

	dList, err := deploymentLister.Deployments(rs.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var deployments []*apps.Deployment
	for _, d := range dList {
		selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
		if err != nil {
			continue
		}
		if selector.Empty() || !selector.Matches(labels.Set(rs.Labels)) {
			continue
		}
		deployments = append(deployments, d)
	}

	if len(deployments) == 0 {
		return nil, fmt.Errorf("could not find deployments set for ReplicaSet %s in namespace %s with labels: %v", rs.Name, rs.Namespace, rs.Labels)
	}

	return deployments, nil
}
```

#### pod

如果 Deployment 的部署策略为 "RollingUpdateDeploymentStrategyType"，则不需要在 Pod 删除后触发重建，因为已经有一个 ReplicaSet 负责替换该 Pod。如果策略类型为 "RecreateDeploymentStrategyType"，则需要检查 Deployment 是否还有其他的 Pods，如果没有，则需要重新调度 Deployment 以创建一个新的 Pod。这是因为使用 "RecreateDeploymentStrategyType" 策略时，当 Pod 被删除时，Deployment 将删除所有现有的 Pods 并创建一个新的 Pods。这与 "RollingUpdateDeploymentStrategyType" 策略不同，后者将逐步替换 Pods，而不是一次性删除并创建所有 Pods。因此，在使用 "RecreateDeploymentStrategyType" 策略时，必须确保 Deployment 在删除一个 Pod 后仍然存在，以便在需要时重新创建 Pods。

```go
func (dc *DeploymentController) deletePod(logger klog.Logger, obj interface{}) {
	pod, ok := obj.(*v1.Pod)

	// 获取pod 没有就从DeletedFinalStateUnknown缓存获取
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a pod %#v", obj))
			return
		}
	}
	logger.V(4).Info("Pod deleted", "pod", klog.KObj(pod))
     // 根据Pod获取其所属的Deployment
	if d := dc.getDeploymentForPod(logger, pod); d != nil && d.Spec.Strategy.Type == apps.RecreateDeploymentStrategyType {
		// 如果该Deployment的Strategy是Recreate，则同步Deployment是否还有Pod存在。
		rsList, err := util.ListReplicaSets(d, util.RsListFromClient(dc.client.AppsV1()))
		if err != nil {
			return
		}
		podMap, err := dc.getPodMapForDeployment(d, rsList)
		if err != nil {
			return
		}
		numPods := 0
		for _, podList := range podMap {
			numPods += len(podList)
		}
		if numPods == 0 {
            // 如果该Deployment已经没有Pod存在，则将其加入队列等待处理。
			dc.enqueueDeployment(d)
		}
	}
}
```

##### getDeploymentForPod

```go
func (dc *DeploymentController) getDeploymentForPod(logger klog.Logger, pod *v1.Pod) *apps.Deployment {
    // 查找Pod所属的ReplicaSet
    var rs *apps.ReplicaSet
    var err error
    controllerRef := metav1.GetControllerOf(pod)
    if controllerRef == nil {
        // 没有控制该Pod的Controller
        return nil
    }
    if controllerRef.Kind != apps.SchemeGroupVersion.WithKind("ReplicaSet").Kind {
        // 不是由ReplicaSet控制的Pod
        return nil
    }
    rs, err = dc.rsLister.ReplicaSets(pod.Namespace).Get(controllerRef.Name)
    if err != nil || rs.UID != controllerRef.UID {
        logger.V(4).Info("Cannot get replicaset for pod", "ownerReference", controllerRef.Name, "pod", klog.KObj(pod), "err", err)
        return nil
    }

    // 查找控制该ReplicaSet的Deployment
    controllerRef = metav1.GetControllerOf(rs)
    if controllerRef == nil {
        return nil
    }
    return dc.resolveControllerRef(rs.Namespace, controllerRef)
}
```

##### ListReplicaSets

```go
func ListReplicaSets(deployment *apps.Deployment, getRSList RsListFunc) ([]*apps.ReplicaSet, error) {
    // 获取Deployment的namespace和selector
    namespace := deployment.Namespace
    selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
    if err != nil {
        return nil, err
    }
    // 获取所有符合selector的ReplicaSet
    options := metav1.ListOptions{LabelSelector: selector.String()}
    all, err := getRSList(namespace, options)
    if err != nil {
        return nil, err
    }
    // 只返回ControllerRef匹配指定Deployment的ReplicaSet
    owned := make([]*apps.ReplicaSet, 0, len(all))
    for _, rs := range all {
        if metav1.IsControlledBy(rs, deployment) {
            owned = append(owned, rs)
        }
    }
    return owned, nil
}
```

##### getPodMapForDeployment

```go
func (dc *DeploymentController) getPodMapForDeployment(d *apps.Deployment, rsList []*apps.ReplicaSet) (map[types.UID][]*v1.Pod, error) {
    // 使用 Deployment 的 selector 创建一个 Selector，用于查询所有可能属于该 Deployment 的 Pod 集合。
	selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil {
		return nil, err
	}
    // 使用 PodLister 查询所有满足 Selector 条件的 Pod 集合
	pods, err := dc.podLister.Pods(d.Namespace).List(selector)
	if err != nil {
		return nil, err
	}
	// 创建一个 map，用于存储属于每个 ReplicaSet 的 Pod 集合
	podMap := make(map[types.UID][]*v1.Pod, len(rsList))
	for _, rs := range rsList {
		podMap[rs.UID] = []*v1.Pod{}
	}
	for _, pod := range pods {
		controllerRef := metav1.GetControllerOf(pod)
		if controllerRef == nil {
			continue
		}
		if _, ok := podMap[controllerRef.UID]; ok {
			podMap[controllerRef.UID] = append(podMap[controllerRef.UID], pod)
		}
	}
	return podMap, nil
}
```

## Run

```go
func (dc *DeploymentController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	dc.eventBroadcaster.StartStructuredLogging(0)
	dc.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: dc.client.CoreV1().Events("")})
	defer dc.eventBroadcaster.Shutdown()

	defer dc.queue.ShutDown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting controller", "controller", "deployment")
	defer logger.Info("Shutting down controller", "controller", "deployment")
	
    // 等待同步完成
	if !cache.WaitForNamedCacheSync("deployment", ctx.Done(), dc.dListerSynced, dc.rsListerSynced, dc.podListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, dc.worker, time.Second)
	}

	<-ctx.Done()
}
```

## worker

```GO
func (dc *DeploymentController) worker(ctx context.Context) {
	for dc.processNextWorkItem(ctx) {
	}
}

func (dc *DeploymentController) processNextWorkItem(ctx context.Context) bool {
	key, quit := dc.queue.Get()
	if quit {
		return false
	}
	defer dc.queue.Done(key)

	err := dc.syncHandler(ctx, key.(string))
	dc.handleErr(ctx, err, key)

	return true
}
```

### handleErr

```GO
func (dc *DeploymentController) handleErr(ctx context.Context, err error, key interface{}) {
	logger := klog.FromContext(ctx)
    // 判断错误是否为 nil 或者是否为正在终止的命名空间引起的错误，如果是则将该项任务从队列中删除
	if err == nil || errors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
		dc.queue.Forget(key)
		return
	}
	ns, name, keyErr := cache.SplitMetaNamespaceKey(key.(string))
	if keyErr != nil {
		logger.Error(err, "Failed to split meta namespace cache key", "cacheKey", key)
	}
	
    // 错误次数还未达到最大重试次数，则将任务重新加入到队列中，并记录错误信息
	if dc.queue.NumRequeues(key) < maxRetries {
		logger.V(2).Info("Error syncing deployment", "deployment", klog.KRef(ns, name), "err", err)
		dc.queue.AddRateLimited(key)
		return
	}
	// 错误次数已达到最大重试次数，则处理错误，并将该项任务从队列中删除
	utilruntime.HandleError(err)
	logger.V(2).Info("Dropping deployment out of the queue", "deployment", klog.KRef(ns, name), "err", err)
	dc.queue.Forget(key)
}
```

## syncHandler

```go
func (dc *DeploymentController) syncDeployment(ctx context.Context, key string) error {
    // 从上下文中获取日志
	logger := klog.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		klog.ErrorS(err, "Failed to split meta namespace cache key", "cacheKey", key)
		return err
	}
	// 记录开始同步 Deployment 的时间 
	startTime := time.Now()
	logger.V(4).Info("Started syncing deployment", "deployment", klog.KRef(namespace, name), "startTime", startTime)
	defer func() {
        // 记录结束同步 Deployment 的时间
		logger.V(4).Info("Finished syncing deployment", "deployment", klog.KRef(namespace, name), "duration", time.Since(startTime))
	}()
	
    // 获取 Deployment 对象
	deployment, err := dc.dLister.Deployments(namespace).Get(name)
	if errors.IsNotFound(err) {
        // 如果 Deployment 不存在，则记录日志并返回 nil
		logger.V(2).Info("Deployment has been deleted", "deployment", klog.KRef(namespace, name))
		return nil
	}
	if err != nil {
        // 如果获取 Deployment 出现错误，则直接返回该错误
		return err
	}

	// 深拷贝 Deployment 对象，防止修改缓存中的对象
	d := deployment.DeepCopy()
	// 如果 Selector 为空，则记录 Event 并返回 nil
	everything := metav1.LabelSelector{}
	if reflect.DeepEqual(d.Spec.Selector, &everything) {
		dc.eventRecorder.Eventf(d, v1.EventTypeWarning, "SelectingAll", "This deployment is selecting all pods. A non-empty selector is required.")
		if d.Status.ObservedGeneration < d.Generation {
			d.Status.ObservedGeneration = d.Generation
			dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{})
		}
		return nil
	}

	// 获取 Deployment 对应的 ReplicaSet 列表，并维护 ControllerRef 关系
	rsList, err := dc.getReplicaSetsForDeployment(ctx, d)
	if err != nil {
		return err
	}
	// 获取 Deployment 对应的 Pod 列表，并按 ReplicaSet 分组
	podMap, err := dc.getPodMapForDeployment(d, rsList)
	if err != nil {
		return err
	}

	if d.DeletionTimestamp != nil {
        // 如果 Deployment 已经被删除，则只同步状态并返回 nil
		return dc.syncStatusOnly(ctx, d, rsList)
	}

	// 如果 Deployment 被暂停，则同步状态并返回 nil
	if err = dc.checkPausedConditions(ctx, d); err != nil {
		return err
	}

	if d.Spec.Paused {
		return dc.sync(ctx, d, rsList)
	}

	// 如果存在回滚，则回滚并返回 nil
	if getRollbackTo(d) != nil {
		return dc.rollback(ctx, d, rsList)
	}
	// 如果存在扩缩容事件，则同步状态并返回 nil
	scalingEvent, err := dc.isScalingEvent(ctx, d, rsList)
	if err != nil {
		return err
	}
	if scalingEvent {
		return dc.sync(ctx, d, rsList)
	}

	switch d.Spec.Strategy.Type {
	case apps.RecreateDeploymentStrategyType:
        // 如果采用 Recreate 策略，则执行 Recreate 的滚动更新并返回 nil
		return dc.rolloutRecreate(ctx, d, rsList, podMap)
	case apps.RollingUpdateDeploymentStrategyType:
        // 如果采用 RollingUpdate 策略，则执行 RollingUpdate 的滚动更新并返回 nil
		return dc.rolloutRolling(ctx, d, rsList)
	}
    // 如果策略类型不是 Recreate 或 RollingUpdate，则返回错误
	return fmt.Errorf("unexpected deployment strategy type: %s", d.Spec.Strategy.Type)
}
```

### getReplicaSetsForDeployment

```GO
func (dc *DeploymentController) getReplicaSetsForDeployment(ctx context.Context, d *apps.Deployment) ([]*apps.ReplicaSet, error) {
	// 获取指定命名空间中的所有 ReplicaSet
	rsList, err := dc.rsLister.ReplicaSets(d.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}
    // // 将 Deployment 的 Selector 转换成 LabelSelector 类型
	deploymentSelector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("deployment %s/%s has invalid label selector: %v", d.Namespace, d.Name, err)
	}
	// 定义检查删除时间戳的函数
    // 这段代码和replicaset-controller中实现方式是一样的
	canAdoptFunc := controller.RecheckDeletionTimestamp(func(ctx context.Context) (metav1.Object, error) {
		// 重新获取最新的 Deployment 对象
        fresh, err := dc.client.AppsV1().Deployments(d.Namespace).Get(ctx, d.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
        
        // 如果最新的 Deployment 对象的 UID 和之前缓存的 Deployment 对象的 UID 不一致，则表示 Deployment 已经被删除
		if fresh.UID != d.UID {
			return nil, fmt.Errorf("original Deployment %v/%v is gone: got uid %v, wanted %v", d.Namespace, d.Name, fresh.UID, d.UID)
		}
		return fresh, nil
	})
    // 创建 ReplicaSetControllerRefManager 对象，并将其用于维护 ReplicaSet 和 Deployment 之间的 ControllerRef 关系
	cm := controller.NewReplicaSetControllerRefManager(dc.rsControl, d, deploymentSelector, controllerKind, canAdoptFunc)
    // 通过 ClaimReplicaSets 方法来找到需要维护的 ReplicaSet 对象，并将它们的 ControllerRef 设置为 Deployment 对象
	return cm.ClaimReplicaSets(ctx, rsList)
}
```

**NewReplicaSetControllerRefManager**

这段和replicaset-controller中的NewPodControllerRefManager实现方式是一样的，所有不单独介绍了

```go
func NewReplicaSetControllerRefManager(
	rsControl RSControlInterface,
	controller metav1.Object,
	selector labels.Selector,
	controllerKind schema.GroupVersionKind,
	canAdopt func(ctx context.Context) error,
) *ReplicaSetControllerRefManager {
	return &ReplicaSetControllerRefManager{
		BaseControllerRefManager: BaseControllerRefManager{
			Controller:   controller,
			Selector:     selector,
			CanAdoptFunc: canAdopt,
		},
		controllerKind: controllerKind,
		rsControl:      rsControl,
	}
}

type ReplicaSetControllerRefManager struct {
	BaseControllerRefManager
	controllerKind schema.GroupVersionKind
	rsControl      RSControlInterface
}

func (m *ReplicaSetControllerRefManager) ClaimReplicaSets(ctx context.Context, sets []*apps.ReplicaSet) ([]*apps.ReplicaSet, error) {
	var claimed []*apps.ReplicaSet
	var errlist []error

	match := func(obj metav1.Object) bool {
		return m.Selector.Matches(labels.Set(obj.GetLabels()))
	}
	adopt := func(ctx context.Context, obj metav1.Object) error {
		return m.AdoptReplicaSet(ctx, obj.(*apps.ReplicaSet))
	}
	release := func(ctx context.Context, obj metav1.Object) error {
		return m.ReleaseReplicaSet(ctx, obj.(*apps.ReplicaSet))
	}

	for _, rs := range sets {
		ok, err := m.ClaimObject(ctx, rs, match, adopt, release)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}
		if ok {
			claimed = append(claimed, rs)
		}
	}
	return claimed, utilerrors.NewAggregate(errlist)
}

func (m *ReplicaSetControllerRefManager) AdoptReplicaSet(ctx context.Context, rs *apps.ReplicaSet) error {
	if err := m.CanAdopt(ctx); err != nil {
		return fmt.Errorf("can't adopt ReplicaSet %v/%v (%v): %v", rs.Namespace, rs.Name, rs.UID, err)
	}
	patchBytes, err := ownerRefControllerPatch(m.Controller, m.controllerKind, rs.UID)
	if err != nil {
		return err
	}
	return m.rsControl.PatchReplicaSet(ctx, rs.Namespace, rs.Name, patchBytes)
}

func (m *ReplicaSetControllerRefManager) ReleaseReplicaSet(ctx context.Context, replicaSet *apps.ReplicaSet) error {
	klog.V(2).Infof("patching ReplicaSet %s_%s to remove its controllerRef to %s/%s:%s",
		replicaSet.Namespace, replicaSet.Name, m.controllerKind.GroupVersion(), m.controllerKind.Kind, m.Controller.GetName())
	patchBytes, err := GenerateDeleteOwnerRefStrategicMergeBytes(replicaSet.UID, []types.UID{m.Controller.GetUID()})
	if err != nil {
		return err
	}
	err = m.rsControl.PatchReplicaSet(ctx, replicaSet.Namespace, replicaSet.Name, patchBytes)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		if errors.IsInvalid(err) {
			return nil
		}
	}
	return err
}

func (m *BaseControllerRefManager) ClaimObject(ctx context.Context, obj metav1.Object, match func(metav1.Object) bool, adopt, release func(context.Context, metav1.Object) error) (bool, error) {
	controllerRef := metav1.GetControllerOfNoCopy(obj)
	if controllerRef != nil {
		if controllerRef.UID != m.Controller.GetUID() {
			return false, nil
		}
		if match(obj) {
			return true, nil
		}

		if m.Controller.GetDeletionTimestamp() != nil {
			return false, nil
		}
		if err := release(ctx, obj); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		// Successfully released.
		return false, nil
	}

	// It's an orphan.
	if m.Controller.GetDeletionTimestamp() != nil || !match(obj) {
		// Ignore if we're being deleted or selector doesn't match.
		return false, nil
	}
	if obj.GetDeletionTimestamp() != nil {
		// Ignore if the object is being deleted
		return false, nil
	}

	if len(m.Controller.GetNamespace()) > 0 && m.Controller.GetNamespace() != obj.GetNamespace() {
		// Ignore if namespace not match
		return false, nil
	}

	// Selector matches. Try to adopt.
	if err := adopt(ctx, obj); err != nil {
		// If the pod no longer exists, ignore the error.
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	// Successfully adopted.
	return true, nil
}
```

### syncStatusOnly

```GO
func (dc *DeploymentController) syncStatusOnly(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
    // 新的 ReplicaSet、旧的 ReplicaSet 列表和最新的修订版本号
	newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, false)
	if err != nil {
		return err
	}	
    // 将新的 ReplicaSet 和旧的 ReplicaSet 列表合并为一个切片，并调用 syncDeploymentStatus 方法更新 Deployment 对象的状态信息
	allRSs := append(oldRSs, newRS)
	return dc.syncDeploymentStatus(ctx, allRSs, newRS, d)
}
```

#### getAllReplicaSetsAndSyncRevision

```GO
func (dc *DeploymentController) getAllReplicaSetsAndSyncRevision(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet, createIfNotExisted bool) (*apps.ReplicaSet, []*apps.ReplicaSet, error) {
    // 获取旧的 ReplicaSet 列表和最新的修订版本号
	_, allOldRSs := deploymentutil.FindOldReplicaSets(d, rsList)

	// 获取新的 ReplicaSet 对象
	newRS, err := dc.getNewReplicaSet(ctx, d, rsList, allOldRSs, createIfNotExisted)
	if err != nil {
		return nil, nil, err
	}

	return newRS, allOldRSs, nil
}
```

##### FindOldReplicaSets

```GO
func FindOldReplicaSets(deployment *apps.Deployment, rsList []*apps.ReplicaSet) ([]*apps.ReplicaSet, []*apps.ReplicaSet) {
	var requiredRSs []*apps.ReplicaSet
	var allRSs []*apps.ReplicaSet
    // 最新的 ReplicaSet 对象
	newRS := FindNewReplicaSet(deployment, rsList)
	for _, rs := range rsList {
		// uuid相同跳过
		if newRS != nil && rs.UID == newRS.UID {
			continue
		}
		allRSs = append(allRSs, rs)
		if *(rs.Spec.Replicas) != 0 {
			requiredRSs = append(requiredRSs, rs)
		}
	}
	return requiredRSs, allRSs
}

```

##### FindNewReplicaSet

```GO
func FindNewReplicaSet(deployment *apps.Deployment, rsList []*apps.ReplicaSet) *apps.ReplicaSet {
    // 排序
	sort.Sort(controller.ReplicaSetsByCreationTimestamp(rsList))
	for i := range rsList {
		if EqualIgnoreHash(&rsList[i].Spec.Template, &deployment.Spec.Template) {
			// 如果template hash相等 返回rs
			return rsList[i]
		}
	}
	// new ReplicaSet does not exist.
	return nil
}
```

###### ReplicaSetsByCreationTimestamp

```GO
type ReplicaSetsByCreationTimestamp []*apps.ReplicaSet

func (o ReplicaSetsByCreationTimestamp) Len() int      { return len(o) }
func (o ReplicaSetsByCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ReplicaSetsByCreationTimestamp) Less(i, j int) bool {
	if o[i].CreationTimestamp.Equal(&o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(&o[j].CreationTimestamp)
}
```

###### EqualIgnoreHash

```GO
func EqualIgnoreHash(template1, template2 *v1.PodTemplateSpec) bool {
	t1Copy := template1.DeepCopy()
	t2Copy := template2.DeepCopy()
	// Remove hash labels from template.Labels before comparing
	delete(t1Copy.Labels, apps.DefaultDeploymentUniqueLabelKey)
	delete(t2Copy.Labels, apps.DefaultDeploymentUniqueLabelKey)
	return apiequality.Semantic.DeepEqual(t1Copy, t2Copy)
}
```

##### getNewReplicaSet

```GO
func (dc *DeploymentController) getNewReplicaSet(ctx context.Context, d *apps.Deployment, rsList, oldRSs []*apps.ReplicaSet, createIfNotExisted bool) (*apps.ReplicaSet, error) {
	logger := klog.FromContext(ctx)
    // 寻找已有的新 ReplicaSet
	existingNewRS := deploymentutil.FindNewReplicaSet(d, rsList)

	// 计算所有旧 ReplicaSet 中的最大版本号
	maxOldRevision := deploymentutil.MaxRevision(oldRSs)
	// 计算新 ReplicaSet 的版本号
	newRevision := strconv.FormatInt(maxOldRevision+1, 10)

	// 若存在最新的 ReplicaSet，则更新该 ReplicaSet 的注释信息，包括从父 Deployment 复制除 annotationsToSkip 
    // 以外的所有注释，更新版本号、desiredReplicas、maxReplicas 并在 Deployment 的注释中更新最新的版本号
	if existingNewRS != nil {
		rsCopy := existingNewRS.DeepCopy()

		 // 更新存在的新 ReplicaSet 的注释
		annotationsUpdated := deploymentutil.SetNewReplicaSetAnnotations(ctx, d, rsCopy, newRevision, true, maxRevHistoryLengthInChars)
		minReadySecondsNeedsUpdate := rsCopy.Spec.MinReadySeconds != d.Spec.MinReadySeconds
		if annotationsUpdated || minReadySecondsNeedsUpdate {
			rsCopy.Spec.MinReadySeconds = d.Spec.MinReadySeconds
			return dc.client.AppsV1().ReplicaSets(rsCopy.ObjectMeta.Namespace).Update(ctx, rsCopy, metav1.UpdateOptions{})
		}

		// 应使用 existingNewRS 中的版本号，因为其已经在之前设置好了
		needsUpdate := deploymentutil.SetDeploymentRevision(d, rsCopy.Annotations[deploymentutil.RevisionAnnotation])
		 // 如果未记录其他进度条件并且需要估计此 Deployment 的进度，则可能旧用户开始关注进度。在这种情况下，需要考虑我们发现其新 ReplicaSet 的时间。
		cond := deploymentutil.GetDeploymentCondition(d.Status, apps.DeploymentProgressing)
		if deploymentutil.HasProgressDeadline(d) && cond == nil {
			msg := fmt.Sprintf("Found new replica set %q", rsCopy.Name)
			condition := deploymentutil.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionTrue, deploymentutil.FoundNewRSReason, msg)
			deploymentutil.SetDeploymentCondition(&d.Status, *condition)
			needsUpdate = true
		}

		if needsUpdate {
			var err error
			if _, err = dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{}); err != nil {
				return nil, err
			}
		}
		return rsCopy, nil
	}
	// 若不存在最新的 ReplicaSet，则根据 createIfNotExisted 参数决定是否创建一个新的 ReplicaSet
	if !createIfNotExisted {
		return nil, nil
	}

	// 创建新的 ReplicaSet
	newRSTemplate := *d.Spec.Template.DeepCopy()
	podTemplateSpecHash := controller.ComputeHash(&newRSTemplate, d.Status.CollisionCount)
	newRSTemplate.Labels = labelsutil.CloneAndAddLabel(d.Spec.Template.Labels, apps.DefaultDeploymentUniqueLabelKey, podTemplateSpecHash)
	// 添加到选择器的标签中
	newRSSelector := labelsutil.CloneSelectorAndAddLabel(d.Spec.Selector, apps.DefaultDeploymentUniqueLabelKey, podTemplateSpecHash)

	// 创建新的 ReplicaSet
	newRS := apps.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			 // 使名称确定性，以确保幂等性
			Name:            d.Name + "-" + podTemplateSpecHash,
			Namespace:       d.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(d, controllerKind)},
			Labels:          newRSTemplate.Labels,
		},
		Spec: apps.ReplicaSetSpec{
			Replicas:        new(int32),
			MinReadySeconds: d.Spec.MinReadySeconds,
			Selector:        newRSSelector,
			Template:        newRSTemplate,
		},
	}
    // 将旧 ReplicaSet 和新 ReplicaSet 合并到 allRSs 中，并计算新 ReplicaSet 所需的副本数
	allRSs := append(oldRSs, &newRS)
	newReplicasCount, err := deploymentutil.NewRSNewReplicas(d, allRSs, &newRS)
	if err != nil {
		return nil, err
	}

	*(newRS.Spec.Replicas) = newReplicasCount
	// 设置新 ReplicaSet 的注释
	deploymentutil.SetNewReplicaSetAnnotations(ctx, d, &newRS, newRevision, false, maxRevHistoryLengthInChars)
	// 创建新的 ReplicaSet。如果已经存在，则需要检查可能的哈希碰撞。如果存在其他错误，则需要在 Deployment 的状态中报告。
	alreadyExists := false
	createdRS, err := dc.client.AppsV1().ReplicaSets(d.Namespace).Create(ctx, &newRS, metav1.CreateOptions{})
	switch {
	// 可能会因为缓存慢或 Deployment 的快速同步而出现此问题
	case errors.IsAlreadyExists(err):
		alreadyExists = true

		// 获取 ReplicaSet 的副本
		rs, rsErr := dc.rsLister.ReplicaSets(newRS.Namespace).Get(newRS.Name)
		if rsErr != nil {
			return nil, rsErr
		}

		// 如果 Deployment 拥有 ReplicaSet 并且 ReplicaSet 的 PodTemplateSpec 与 Deployment 的 PodTemplateSpec 在语义上深度相等，则为 Deployment 的新 ReplicaSet。
        // 否则，这是一个哈希碰撞，我们需要在 Deployment 的状态中增加 collisionCount 字段并重新排队以在下一次同步中尝试创建它
		controllerRef := metav1.GetControllerOf(rs)
		if controllerRef != nil && controllerRef.UID == d.UID && deploymentutil.EqualIgnoreHash(&d.Spec.Template, &rs.Spec.Template) {
			createdRS = rs
			err = nil
			break
		}

		// 匹配的 ReplicaSet 不相等 - 在 DeploymentStatus 中增加 collisionCount 并重新排队
		if d.Status.CollisionCount == nil {
			d.Status.CollisionCount = new(int32)
		}
		preCollisionCount := *d.Status.CollisionCount
		*d.Status.CollisionCount++
		// 更新 Deployment 的 collisionCount 并通过返回原始错误来重新排队
		_, dErr := dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{})
		if dErr == nil {
			logger.V(2).Info("Found a hash collision for deployment - bumping collisionCount to resolve it", "deployment", klog.KObj(d), "oldCollisionCount", preCollisionCount, "newCollisionCount", *d.Status.CollisionCount)
		}
		return nil, err
	case errors.HasStatusCause(err, v1.NamespaceTerminatingCause):
		// 如果命名空间正在终止，则所有后续创建都将失败，我们可以安全地不做任何操作
		return nil, err
	case err != nil:
		msg := fmt.Sprintf("Failed to create new replica set %q: %v", newRS.Name, err)
		if deploymentutil.HasProgressDeadline(d) {
			cond := deploymentutil.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionFalse, deploymentutil.FailedRSCreateReason, msg)
			deploymentutil.SetDeploymentCondition(&d.Status, *cond)
			// 我们现在不太关心这个错误，因为我们有一个更大的问题要报告
			// TODO: 确定哪些错误是永久的，并切换 DeploymentIsFailed 以考虑这些原因。相关问题：				·				// https://github.com/kubernetes/kubernetes/issues/18568
			_, _ = dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{})
		}
		dc.eventRecorder.Eventf(d, v1.EventTypeWarning, deploymentutil.FailedRSCreateReason, msg)
		return nil, err
	}
	if !alreadyExists && newReplicasCount > 0 {
		dc.eventRecorder.Eventf(d, v1.EventTypeNormal, "ScalingReplicaSet", "Scaled up replica set %s to %d", createdRS.Name, newReplicasCount)
	}
	// 如果新 ReplicaSet 不存在且 Deployment 具有 progressDeadlineSeconds，则更新 Deployment 的 progressing 状态
	needsUpdate := deploymentutil.SetDeploymentRevision(d, newRevision)
	if !alreadyExists && deploymentutil.HasProgressDeadline(d) {
		msg := fmt.Sprintf("Created new replica set %q", createdRS.Name)
		condition := deploymentutil.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionTrue, deploymentutil.NewReplicaSetReason, msg)
		deploymentutil.SetDeploymentCondition(&d.Status, *condition)
		needsUpdate = true
	}
	if needsUpdate {
		_, err = dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{})
	}
	return createdRS, err
}
```

###### DeploymentConditionType

```go
type DeploymentConditionType string

const (
	// 表示 Deployment 可用，至少满足所需的最小可用副本数量，并且已经运行了 minReadySeconds
	DeploymentAvailable DeploymentConditionType = "Available"
	// 表示 Deployment 正在进行中。当创建或采用新的 ReplicaSet 时，以及扩容或缩容 Pod 时，
    // 都会考虑 Deployment 的进展情况。如果 Deployment 被暂停，或 progressDeadlineSeconds 未指定，则不会计算进度。
	DeploymentProgressing DeploymentConditionType = "Progressing"
	// 表示在 Deployment 中的一个 Pod 创建或删除失败。
	DeploymentReplicaFailure DeploymentConditionType = "ReplicaFailure"
)

```

###### MaxRevision

```GO
func MaxRevision(allRSs []*apps.ReplicaSet) int64 {
	max := int64(0)
	for _, rs := range allRSs {
		if v, err := Revision(rs); err != nil {
			// Skip the replica sets when it failed to parse their revision information
			klog.V(4).Info("Couldn't parse revision for replica set, deployment controller will skip it when reconciling revisions", "replicaSet", klog.KObj(rs), "err", err)
		} else if v > max {
			max = v
		}
	}
	return max
}
```

###### Revision

```GO
func Revision(obj runtime.Object) (int64, error) {
	acc, err := meta.Accessor(obj)
	if err != nil {
		return 0, err
	}
	v, ok := acc.GetAnnotations()[RevisionAnnotation]
	if !ok {
		return 0, nil
	}
	return strconv.ParseInt(v, 10, 64)
}
```

###### SetNewReplicaSetAnnotations

```GO
// SetNewReplicaSetAnnotations 将部署对象的注释复制到新的 ReplicaSet 对象中，并更新新 ReplicaSet 对象的版本注释。
// 如果新的 ReplicaSet 对象不存在，则还需要添加副本注释。该函数返回一个布尔值，指示是否更新了注释。
func SetNewReplicaSetAnnotations(ctx context.Context, deployment *apps.Deployment, newRS *apps.ReplicaSet, newRevision string, exists bool, revHistoryLimitInChars int) bool {
	logger := klog.FromContext(ctx)
	// 首先，复制部署对象的注释（不包括 apply 和版本注释）到新的 ReplicaSet 对象中。
	annotationChanged := copyDeploymentAnnotationsToReplicaSet(deployment, newRS)
	// 然后，更新新 ReplicaSet 对象的版本注释。
	if newRS.Annotations == nil {
		newRS.Annotations = make(map[string]string)
	}
	oldRevision, ok := newRS.Annotations[RevisionAnnotation]
	// 新 ReplicaSet 对象的版本应该是所有 ReplicaSet 中最大的版本。通常，它的版本号是 newRevision（所有旧 ReplicaSet 中的最大版本号 + 1）。
	// 但是，可能在更新新 ReplicaSet 对象的版本后，某些旧 ReplicaSet 被删除，导致 newRevision 变得比新 ReplicaSet 的版本小。
	// 只有在新版本小于 newRevision 时才应更新新 ReplicaSet 的版本。

	oldRevisionInt, err := strconv.ParseInt(oldRevision, 10, 64)
	if err != nil {
		if oldRevision != "" {
			logger.Info("更新 ReplicaSet 版本时，OldRevision 不是 int 类型", "err", err)
			return false
		}
		// 如果 RS 注释为空，则将其初始化为 0。
		oldRevisionInt = 0
	}
	newRevisionInt, err := strconv.ParseInt(newRevision, 10, 64)
	if err != nil {
		logger.Info("更新 ReplicaSet 版本时，NewRevision 不是 int 类型", "err", err)
		return false
	}
	if oldRevisionInt < newRevisionInt {
		newRS.Annotations[RevisionAnnotation] = newRevision
		annotationChanged = true
		logger.V(4).Info("更新 ReplicaSet 版本", "replicaSet", klog.KObj(newRS), "newRevision", newRevision)
	}
	// 如果版本注释已存在，并且此 ReplicaSet 已使用新版本更新
	// 那么意味着我们正在回滚到该 ReplicaSet。我们需要为历史信息保留旧版本。
	if ok && oldRevisionInt < newRevisionInt {
		revisionHistoryAnnotation := newRS.Annotations[RevisionHistoryAnnotation]
		oldRevisions := strings.Split(revisionHistoryAnnotation, ",")
		if len(oldRevisions[0]) == 0 {
			newRS.Annotations[RevisionHistoryAnnotation] = oldRevision
		} else {
			totalLen := len(revisionHistoryAnnotation) + len(oldRevision) + 1
			// oldRevisions 中的起始位置索引
			start := 0
			for totalLen > revHistoryLimitInChars && start < len(oldRevisions) {
				totalLen = totalLen - len(oldRevisions[start]) - 1
				start++
			}
			if totalLen <= revHistoryLimitInChars {
				oldRevisions = append(oldRevisions[start:], oldRevision)
				newRS.Annotations[RevisionHistoryAnnotation] = strings.Join(oldRevisions, ",")
			} else {
				logger.Info("Not appending revision due to revision history length limit reached", "revisionHistoryLimit", revHistoryLimitInChars)
			}
		}
	}
	// 如果即将创建新的 ReplicaSet，则需要将副本注释添加到其中。
	if !exists && SetReplicasAnnotations(newRS, *(deployment.Spec.Replicas), *(deployment.Spec.Replicas)+MaxSurge(*deployment)) {
		annotationChanged = true
	}
	return annotationChanged
}
```

**copyDeploymentAnnotationsToReplicaSet**

```go
// copyDeploymentAnnotationsToReplicaSet 函数接收一个 Deployment 指针和一个 ReplicaSet 指针作为参数，
// 将 Deployment 的注释复制到 ReplicaSet 中，并返回一个布尔值，指示 ReplicaSet 的注释是否发生了变化。
func copyDeploymentAnnotationsToReplicaSet(deployment *apps.Deployment, rs *apps.ReplicaSet) bool {
	rsAnnotationsChanged := false
    // 如果 ReplicaSet 的注释为 nil，则创建一个空的 map。
	if rs.Annotations == nil {
		rs.Annotations = make(map[string]string)
	}
    // 遍历 Deployment 的注释，将其复制到 ReplicaSet 中。
	for k, v := range deployment.Annotations {
		// newRS revision 在 getNewReplicaSet 中自动更新，然后复制其 newRS 的 revision 号来更新 deployment 的 revision 号。
		// 我们不应该将 deployment 的 revision 复制到其 newRS 中，因为更新 deployment 的 revision 可能会失败（revision 变得过时），
		// 而 newRS 中的 revision 号更可靠。
		// skipCopyAnnotation 函数用于判断是否应该跳过复制注释的某些键。
		if _, exist := rs.Annotations[k]; skipCopyAnnotation(k) || (exist && rs.Annotations[k] == v) {
			continue
		}
		rs.Annotations[k] = v
		rsAnnotationsChanged = true
	}
    // 返回 ReplicaSet 的注释是否发生了变化的布尔值。
	return rsAnnotationsChanged
}
```

**SetReplicasAnnotations**

```go
// SetReplicasAnnotations 函数接收一个 ReplicaSet 指针以及 desiredReplicas 和 maxReplicas 两个 int32 类型的参数，
// 将它们转换为字符串并存储为 ReplicaSet 的注释，如果注释有更新，则返回 true，否则返回 false。
func SetReplicasAnnotations(rs *apps.ReplicaSet, desiredReplicas, maxReplicas int32) bool {
	updated := false
    // 如果 ReplicaSet 的注释为 nil，则创建一个空的 map。
	if rs.Annotations == nil {
		rs.Annotations = make(map[string]string)
	}
    // 将 desiredReplicas 转换为字符串并与 DesiredReplicasAnnotation 一起存储在 ReplicaSet 的注释中。
	desiredString := fmt.Sprintf("%d", desiredReplicas)
	if hasString := rs.Annotations[DesiredReplicasAnnotation]; hasString != desiredString {
		rs.Annotations[DesiredReplicasAnnotation] = desiredString
		updated = true
	}
    // 将 maxReplicas 转换为字符串并与 MaxReplicasAnnotation 一起存储在 ReplicaSet 的注释中。
	maxString := fmt.Sprintf("%d", maxReplicas)
	if hasString := rs.Annotations[MaxReplicasAnnotation]; hasString != maxString {
		rs.Annotations[MaxReplicasAnnotation] = maxString
		updated = true
	}
    // 返回注释是否发生了更新的布尔值。
	return updated
}
```

###### SetDeploymentRevision

```GO
func SetDeploymentRevision(deployment *apps.Deployment, revision string) bool {
	updated := false

	if deployment.Annotations == nil {
		deployment.Annotations = make(map[string]string)
	}
	if deployment.Annotations[RevisionAnnotation] != revision {
		deployment.Annotations[RevisionAnnotation] = revision
		updated = true
	}

	return updated
}
```

###### GetDeploymentCondition

```GO
func GetDeploymentCondition(status apps.DeploymentStatus, condType apps.DeploymentConditionType) *apps.DeploymentCondition {
	for i := range status.Conditions {
		c := status.Conditions[i]
		if c.Type == condType {
			return &c
		}
	}
	return nil
}
```

###### HasProgressDeadline

```GO
func HasProgressDeadline(d *apps.Deployment) bool {
	return d.Spec.ProgressDeadlineSeconds != nil && *d.Spec.ProgressDeadlineSeconds != math.MaxInt32
}
```

###### NewDeploymentCondition

```GO
func NewDeploymentCondition(condType apps.DeploymentConditionType, status v1.ConditionStatus, reason, message string) *apps.DeploymentCondition {
	return &apps.DeploymentCondition{
		Type:               condType,
		Status:             status,
		LastUpdateTime:     metav1.Now(),
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}
```

###### SetDeploymentCondition

```GO
func SetDeploymentCondition(status *apps.DeploymentStatus, condition apps.DeploymentCondition) {
    // 获取当前 Deployment 的指定类型的条件
	currentCond := GetDeploymentCondition(*status, condition.Type)
    // 如果当前条件不为 nil 且当前条件的状态、原因与新条件相同，则无需更新，直接返回
	if currentCond != nil && currentCond.Status == condition.Status && currentCond.Reason == condition.Reason {
		return
	}
	// 如果当前条件不为 nil 且当前条件的状态与新条件相同，则更新新条件的 
	if currentCond != nil && currentCond.Status == condition.Status {
		condition.LastTransitionTime = currentCond.LastTransitionTime
	}
    // 过滤掉 status.Conditions 中指定类型的条件，得到新的条件列表
	newConditions := filterOutCondition(status.Conditions, condition.Type)
    // 将新条件追加到条件列表中
	status.Conditions = append(newConditions, condition)
}
```

###### filterOutCondition

```go
func filterOutCondition(conditions []apps.DeploymentCondition, condType apps.DeploymentConditionType) []apps.DeploymentCondition {
	var newConditions []apps.DeploymentCondition
	for _, c := range conditions {
		if c.Type == condType {
			continue
		}
		newConditions = append(newConditions, c)
	}
	return newConditions
}
```

###### ComputeHash

```go
// 计算一个 PodTemplateSpec 对象的哈希值
func ComputeHash(template *v1.PodTemplateSpec, collisionCount *int32) string {
	podTemplateSpecHasher := fnv.New32a()
	hashutil.DeepHashObject(podTemplateSpecHasher, *template)

	// Add collisionCount in the hash if it exists.
	if collisionCount != nil {
		collisionCountBytes := make([]byte, 8)
		binary.LittleEndian.PutUint32(collisionCountBytes, uint32(*collisionCount))
		podTemplateSpecHasher.Write(collisionCountBytes)
	}

	return rand.SafeEncodeString(fmt.Sprint(podTemplateSpecHasher.Sum32()))
}
```

###### CloneAndAddLabel

```GO
func CloneAndAddLabel(labels map[string]string, labelKey, labelValue string) map[string]string {
	if labelKey == "" {
		// Don't need to add a label.
		return labels
	}
	// Clone.
	newLabels := map[string]string{}
	for key, value := range labels {
		newLabels[key] = value
	}
	newLabels[labelKey] = labelValue
	return newLabels
}
```

###### CloneSelectorAndAddLabel

```GO
func CloneSelectorAndAddLabel(selector *metav1.LabelSelector, labelKey, labelValue string) *metav1.LabelSelector {
	if labelKey == "" {
		// 如果 labelKey 为空，则不需要添加标签，直接返回原始的 selector。
		return selector
	}

	// Clone.
	newSelector := new(metav1.LabelSelector)

	// TODO(madhusudancs): 检查是否可以在这里使用 deepCopy_extensions_LabelSelector。
	// 创建一个新的 map 以存储复制过来的标签键值对。
	newSelector.MatchLabels = make(map[string]string)
    // 如果原始的 selector 中存在标签，则将其复制到新的标签选择器中。
	if selector.MatchLabels != nil {
		for key, val := range selector.MatchLabels {
			newSelector.MatchLabels[key] = val
		}
	}
    // 添加新的标签键值对。
	newSelector.MatchLabels[labelKey] = labelValue
	
    // 如果原始的 selector 中存在 MatchExpressions，则将其复制到新的标签选择器中。
	if selector.MatchExpressions != nil {
		newMExps := make([]metav1.LabelSelectorRequirement, len(selector.MatchExpressions))
		for i, me := range selector.MatchExpressions {
			newMExps[i].Key = me.Key
			newMExps[i].Operator = me.Operator
			if me.Values != nil {
				newMExps[i].Values = make([]string, len(me.Values))
				copy(newMExps[i].Values, me.Values)
			} else {
				newMExps[i].Values = nil
			}
		}
		newSelector.MatchExpressions = newMExps
	} else {
		newSelector.MatchExpressions = nil
	}

	return newSelector
}
```

#### syncDeploymentStatus

```go
func (dc *DeploymentController) syncDeploymentStatus(ctx context.Context, allRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, d *apps.Deployment) error {
    // 计算新的 Deployment 状态
	newStatus := calculateStatus(allRSs, newRS, d)

	if reflect.DeepEqual(d.Status, newStatus) {
		return nil
	}

	newDeployment := d
	newDeployment.Status = newStatus
	_, err := dc.client.AppsV1().Deployments(newDeployment.Namespace).UpdateStatus(ctx, newDeployment, metav1.UpdateOptions{})
	return err
}
```

##### calculateStatus

```GO
func calculateStatus(allRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, deployment *apps.Deployment) apps.DeploymentStatus {
    // 获取所有 ReplicaSet 的可用副本数、总副本数以及不可用副本数。
	availableReplicas := deploymentutil.GetAvailableReplicaCountForReplicaSets(allRSs)
	totalReplicas := deploymentutil.GetReplicaCountForReplicaSets(allRSs)
	unavailableReplicas := totalReplicas - availableReplicas
	// 如果不可用副本数为负数，说明 Deployment 中有比期望数量更多的可用副本，例如缩容操作。这种情况下，我们应该将不可用副本数默认为零。
	if unavailableReplicas < 0 {
		unavailableReplicas = 0
	}
	
    // 创建 DeploymentStatus 对象，并初始化其中的字段。
	status := apps.DeploymentStatus{
		// TODO：确保如果我们开始重试状态更新，则不会选取新的 Generation 值。
		ObservedGeneration:  deployment.Generation,
		Replicas:            deploymentutil.GetActualReplicaCountForReplicaSets(allRSs),
		UpdatedReplicas:     deploymentutil.GetActualReplicaCountForReplicaSets([]*apps.ReplicaSet{newRS}),
		ReadyReplicas:       deploymentutil.GetReadyReplicaCountForReplicaSets(allRSs),
		AvailableReplicas:   availableReplicas,
		UnavailableReplicas: unavailableReplicas,
		CollisionCount:      deployment.Status.CollisionCount,
	}

	// 逐一复制条件，以免修改原始对象。
	conditions := deployment.Status.Conditions
	for i := range conditions {
		status.Conditions = append(status.Conditions, conditions[i])
	}
	
    // 如果可用副本数达到或超过 Deployment 中所需的最小可用副本数，则设置 DeploymentAvailable 为 True。
	if availableReplicas >= *(deployment.Spec.Replicas)-deploymentutil.MaxUnavailable(*deployment) {
		minAvailability := deploymentutil.NewDeploymentCondition(apps.DeploymentAvailable, v1.ConditionTrue, deploymentutil.MinimumReplicasAvailable, "Deployment has minimum availability.")
		deploymentutil.SetDeploymentCondition(&status, *minAvailability)
	} else {
        // 否则，将 DeploymentAvailable 设置为 False。
		noMinAvailability := deploymentutil.NewDeploymentCondition(apps.DeploymentAvailable, v1.ConditionFalse, deploymentutil.MinimumReplicasUnavailable, "Deployment does not have minimum availability.")
		deploymentutil.SetDeploymentCondition(&status, *noMinAvailability)
	}
	// 返回计算出的 DeploymentStatus 对象。
	return status
}
```



##### GetAvailableReplicaCountForReplicaSets

```go
func GetAvailableReplicaCountForReplicaSets(replicaSets []*apps.ReplicaSet) int32 {
	totalAvailableReplicas := int32(0)
	for _, rs := range replicaSets {
		if rs != nil {
			totalAvailableReplicas += rs.Status.AvailableReplicas
		}
	}
	return totalAvailableReplicas
}
```

##### GetReplicaCountForReplicaSets

```go
func GetReplicaCountForReplicaSets(replicaSets []*apps.ReplicaSet) int32 {
	totalReplicas := int32(0)
	for _, rs := range replicaSets {
		if rs != nil {
			totalReplicas += *(rs.Spec.Replicas)
		}
	}
	return totalReplicas
}
```

##### GetActualReplicaCountForReplicaSets

```go
func GetActualReplicaCountForReplicaSets(replicaSets []*apps.ReplicaSet) int32 {
	totalActualReplicas := int32(0)
	for _, rs := range replicaSets {
		if rs != nil {
			totalActualReplicas += rs.Status.Replicas
		}
	}
	return totalActualReplicas
}
```

##### GetReadyReplicaCountForReplicaSets

```go
func GetReadyReplicaCountForReplicaSets(replicaSets []*apps.ReplicaSet) int32 {
	totalReadyReplicas := int32(0)
	for _, rs := range replicaSets {
		if rs != nil {
			totalReadyReplicas += rs.Status.ReadyReplicas
		}
	}
	return totalReadyReplicas
}
```

##### MaxUnavailable

```GO
// MaxUnavailable 函数接收一个 Deployment 类型的参数 deployment，并返回一个 int32 类型的值，
// 表示可以不可用的最大 pod 数量，用于滚动更新期间的 Deployment 控制。
// 如果 deployment 不支持滚动更新，或者其 Replicas 数量为 0，则返回 0。
func MaxUnavailable(deployment apps.Deployment) int32 {
	if !IsRollingUpdate(&deployment) || *(deployment.Spec.Replicas) == 0 {
		return int32(0)
	}
	// 通过 ResolveFenceposts 函数来解析 Deployment 的 MaxSurge 和 MaxUnavailable 参数，
	// 返回 MaxUnavailable 的值，如果 MaxUnavailable 大于 Replicas 的值，则返回 Replicas 的值。
	_, maxUnavailable, _ := ResolveFenceposts(deployment.Spec.Strategy.RollingUpdate.MaxSurge, deployment.Spec.Strategy.RollingUpdate.MaxUnavailable, *(deployment.Spec.Replicas))
	if maxUnavailable > *deployment.Spec.Replicas {
		return *deployment.Spec.Replicas
	}
	return maxUnavailable
}
```

###### ResolveFenceposts

```GO
// ResolveFenceposts 函数接收两个 intstrutil.IntOrString 类型的指针 maxSurge 和 maxUnavailable，以及一个 int32 类型的 desired 参数。
// 该函数用于解析 Deployment 的 MaxSurge 和 MaxUnavailable 参数，并返回最终的 MaxSurge 和 MaxUnavailable 的值。
// 如果 maxSurge 或 maxUnavailable 无法解析，则返回错误。
func ResolveFenceposts(maxSurge, maxUnavailable *intstrutil.IntOrString, desired int32) (int32, int32, error) {
    // 通过 intstrutil 库中的 GetScaledValueFromIntOrPercent 函数来获取 MaxSurge 的值。
	// 如果出现错误，则返回 err。
	surge, err := intstrutil.GetScaledValueFromIntOrPercent(intstrutil.ValueOrDefault(maxSurge, intstrutil.FromInt(0)), int(desired), true)
	if err != nil {
		return 0, 0, err
	}
    // 通过 intstrutil 库中的 GetScaledValueFromIntOrPercent 函数来获取 MaxUnavailable 的值。
	// 如果出现错误，则返回 err。
	unavailable, err := intstrutil.GetScaledValueFromIntOrPercent(intstrutil.ValueOrDefault(maxUnavailable, intstrutil.FromInt(0)), int(desired), false)
	if err != nil {
		return 0, 0, err
	}
	// 如果 MaxSurge 和 MaxUnavailable 的值都为 0，则将 MaxUnavailable 设置为 1，因为 MaxSurge 可能由于配额而无法使用。
	if surge == 0 && unavailable == 0 {
		unavailable = 1
	}
	// 返回最终的 MaxSurge 和 MaxUnavailable 的值。
	return int32(surge), int32(unavailable), nil
}

func GetScaledValueFromIntOrPercent(intOrPercent *IntOrString, total int, roundUp bool) (int, error) {
	if intOrPercent == nil {
		return 0, errors.New("nil value for IntOrString")
	}
	value, isPercent, err := getIntOrPercentValueSafely(intOrPercent)
	if err != nil {
		return 0, fmt.Errorf("invalid value for IntOrString: %v", err)
	}
	if isPercent {
		if roundUp {
			value = int(math.Ceil(float64(value) * (float64(total)) / 100))
		} else {
			value = int(math.Floor(float64(value) * (float64(total)) / 100))
		}
	}
	return value, nil
}

func getIntOrPercentValueSafely(intOrStr *IntOrString) (int, bool, error) {
	switch intOrStr.Type {
	case Int:
		return intOrStr.IntValue(), false, nil
	case String:
		isPercent := false
		s := intOrStr.StrVal
		if strings.HasSuffix(s, "%") {
			isPercent = true
			s = strings.TrimSuffix(intOrStr.StrVal, "%")
		} else {
			return 0, false, fmt.Errorf("invalid type: string is not a percentage")
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return 0, false, fmt.Errorf("invalid value %q: %v", intOrStr.StrVal, err)
		}
		return int(v), isPercent, nil
	}
	return 0, false, fmt.Errorf("invalid type: neither int nor percentage")
}
```

#### checkPausedConditions

```GO
// checkPausedConditions 方法是 DeploymentController 结构体的一个方法，接收一个 context.Context 类型的上下文和一个 apps.Deployment 类型的指针 d 作为参数，
// 该方法用于检查 Deployment 的暂停状态并设置适当的条件。
// 如果 Deployment 没有进度截止时间，则不进行检查，直接返回。
// 如果已经报告了缺乏进展，则不覆盖它以进行暂停条件的设置。
// 如果 Deployment 处于暂停状态但尚未设置暂停条件，则设置一个 PausedDeployReason 条件。
// 如果 Deployment 不处于暂停状态但已设置了暂停条件，则设置一个 ResumedDeployReason 条件。
// 如果需要更新 Deployment 的状态，则更新它的条件并返回更新的错误，否则返回 nil。
func (dc *DeploymentController) checkPausedConditions(ctx context.Context, d *apps.Deployment) error {
	if !deploymentutil.HasProgressDeadline(d) {
        // 如果 Deployment 没有进度截止时间，则不进行检查，直接返回。
		return nil
	}
	cond := deploymentutil.GetDeploymentCondition(d.Status, apps.DeploymentProgressing)
	if cond != nil && cond.Reason == deploymentutil.TimedOutReason {
		// 如果已经报告了缺乏进展，则不覆盖它以进行暂停条件的设置。
		return nil
	}
	pausedCondExists := cond != nil && cond.Reason == deploymentutil.PausedDeployReason

	needsUpdate := false
	if d.Spec.Paused && !pausedCondExists {
        // 如果 Deployment 处于暂停状态但尚未设置暂停条件，则设置一个 PausedDeployReason 条件。
		condition := deploymentutil.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionUnknown, deploymentutil.PausedDeployReason, "Deployment is paused")
		deploymentutil.SetDeploymentCondition(&d.Status, *condition)
		needsUpdate = true
	} else if !d.Spec.Paused && pausedCondExists {
        // 如果 Deployment 不处于暂停状态但已设置了暂停条件，则设置一个 ResumedDeployReason 条件。
		condition := deploymentutil.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionUnknown, deploymentutil.ResumedDeployReason, "Deployment is resumed")
		deploymentutil.SetDeploymentCondition(&d.Status, *condition)
		needsUpdate = true
	}

	if !needsUpdate {
		return nil
	}
	// 如果需要更新 Deployment 的状态，则更新它的条件并返回更新的错误，否则返回 nil。
	var err error
	_, err = dc.client.AppsV1().Deployments(d.Namespace).UpdateStatus(ctx, d, metav1.UpdateOptions{})
	return err
}
```

### sync

```GO
func (dc *DeploymentController) sync(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
	newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, false)
	if err != nil {
		return err
	}
	if err := dc.scale(ctx, d, newRS, oldRSs); err != nil {
		// 如果在缩放过程中发生错误，则返回错误。
		// 这意味着 Deployment 将被重新排队，因此可以中止此重新同步。
		return err
	}

	// 如果 Deployment 被暂停且没有回滚在进行中，则清理 Deployment。
	if d.Spec.Paused && getRollbackTo(d) == nil {
		if err := dc.cleanupDeployment(ctx, oldRSs, d); err != nil {
			return err
		}
	}
	// 将所有 ReplicaSet 数组传递给 syncDeploymentStatus 函数来同步 Deployment 的状态，并返回错误。
	allRSs := append(oldRSs, newRS)
	return dc.syncDeploymentStatus(ctx, allRSs, newRS, d)
}
```

#### scale

```go
func (dc *DeploymentController) scale(ctx context.Context, deployment *apps.Deployment, newRS *apps.ReplicaSet, oldRSs []*apps.ReplicaSet) error {
	// 如果只有一个活动的副本集，则应该将其扩展到部署的完整数量。
	// 如果没有活动的副本集，则应该扩展到最新的副本集。
	if activeOrLatest := deploymentutil.FindActiveOrLatest(newRS, oldRSs); activeOrLatest != nil {
		if *(activeOrLatest.Spec.Replicas) == *(deployment.Spec.Replicas) {
            // 如果要扩展的副本数量等于当前的副本数量，则直接返回。
			return nil
		}
		_, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, activeOrLatest, *(deployment.Spec.Replicas), deployment)
		return err
	}

	// 如果新的副本集已饱和，则应该完全缩小旧的副本集。
	// 在饱和的新副本集期间，此情况处理副本集接管。
	if deploymentutil.IsSaturated(deployment, newRS) {
		for _, old := range controller.FilterActiveReplicaSets(oldRSs) {
			if _, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, old, 0, deployment); err != nil {
				return err
			}
		}
		return nil
	}

	// 如果有旧的副本集，并且新的副本集没有饱和，则需要按比例扩展所有副本集（包括新的和旧的）。
	// 这种情况处理滚动更新。
	if deploymentutil.IsRollingUpdate(deployment) {
		allRSs := controller.FilterActiveReplicaSets(append(oldRSs, newRS))
		allRSsReplicas := deploymentutil.GetReplicaCountForReplicaSets(allRSs)

		allowedSize := int32(0)
		if *(deployment.Spec.Replicas) > 0 {
			allowedSize = *(deployment.Spec.Replicas) + deploymentutil.MaxSurge(*deployment)
		}

		// 可以添加或删除的其他副本数量。这些副本应按比例分配到活动的副本集中。
		deploymentReplicasToAdd := allowedSize - allRSsReplicas

		// 应该在较大的副本集和较小的副本集之间按比例分配附加副本。比例分配的方式取决于缩放方向。
		// 在向上缩放时，我们应该先扩展新的副本集；在向下缩放时，我们应该先缩小旧的副本集。
		var scalingOperation string
		switch {
		case deploymentReplicasToAdd > 0:
			sort.Sort(controller.ReplicaSetsBySizeNewer(allRSs))
            // 扩展新的副本集
			scalingOperation = "up"

		case deploymentReplicasToAdd < 0:
			sort.Sort(controller.ReplicaSetsBySizeOlder(allRSs))
            // 缩小旧的副本集
			scalingOperation = "down"
		}

		// 遍历所有活动的副本集，并为每个副本集估算比例
        // deploymentReplicasToAdd 的绝对值永远不应超过 deploymentReplicasAdded 的绝对值。
		deploymentReplicasAdded := int32(0)
		nameToSize := make(map[string]int32)
		logger := klog.FromContext(ctx)
		for i := range allRSs {
			rs := allRSs[i]

			// 如果有要添加的副本，则估算比例；否则，直接使用当前的副本数量。
			if deploymentReplicasToAdd != 0 {
				proportion := deploymentutil.GetProportion(logger, rs, *deployment, deploymentReplicasToAdd, deploymentReplicasAdded)

				nameToSize[rs.Name] = *(rs.Spec.Replicas) + proportion
				deploymentReplicasAdded += proportion
			} else {
				nameToSize[rs.Name] = *(rs.Spec.Replicas)
			}
		}

		// 更新所有副本集
		for i := range allRSs {
			rs := allRSs[i]

			// 将任何剩余的副本添加到最大的副本集中。
			if i == 0 && deploymentReplicasToAdd != 0 {
				leftover := deploymentReplicasToAdd - deploymentReplicasAdded
				nameToSize[rs.Name] = nameToSize[rs.Name] + leftover
				if nameToSize[rs.Name] < 0 {
					nameToSize[rs.Name] = 0
				}
			}

			// TODO: 当我们有事务时，请使用事务。
			if _, _, err := dc.scaleReplicaSet(ctx, rs, nameToSize[rs.Name], deployment, scalingOperation); err != nil {
				// 只要有一个失败，就返回错误，然后重新排队
				return err
			}
		}
	}
	return nil
}
```

##### scaleReplicaSetAndRecordEvent

```GO
func (dc *DeploymentController) scaleReplicaSetAndRecordEvent(ctx context.Context, rs *apps.ReplicaSet, newScale int32, deployment *apps.Deployment) (bool, *apps.ReplicaSet, error) {
	// No need to scale
	if *(rs.Spec.Replicas) == newScale {
		return false, rs, nil
	}
	var scalingOperation string
	if *(rs.Spec.Replicas) < newScale {
		scalingOperation = "up" // 扩容
	} else {
		scalingOperation = "down" // 缩容
	}
	scaled, newRS, err := dc.scaleReplicaSet(ctx, rs, newScale, deployment, scalingOperation)
	return scaled, newRS, err
}
```

##### scaleReplicaSet

```go
func (dc *DeploymentController) scaleReplicaSet(ctx context.Context, rs *apps.ReplicaSet, newScale int32, deployment *apps.Deployment, scalingOperation string) (bool, *apps.ReplicaSet, error) {

	sizeNeedsUpdate := *(rs.Spec.Replicas) != newScale

	annotationsNeedUpdate := deploymentutil.ReplicasAnnotationsNeedUpdate(rs, *(deployment.Spec.Replicas), *(deployment.Spec.Replicas)+deploymentutil.MaxSurge(*deployment))

	scaled := false
	var err error
	if sizeNeedsUpdate || annotationsNeedUpdate {
		oldScale := *(rs.Spec.Replicas)
		rsCopy := rs.DeepCopy()
		*(rsCopy.Spec.Replicas) = newScale
		deploymentutil.SetReplicasAnnotations(rsCopy, *(deployment.Spec.Replicas), *(deployment.Spec.Replicas)+deploymentutil.MaxSurge(*deployment))
		rs, err = dc.client.AppsV1().ReplicaSets(rsCopy.Namespace).Update(ctx, rsCopy, metav1.UpdateOptions{})
		if err == nil && sizeNeedsUpdate {
			scaled = true
			dc.eventRecorder.Eventf(deployment, v1.EventTypeNormal, "ScalingReplicaSet", "Scaled %s replica set %s to %d from %d", scalingOperation, rs.Name, newScale, oldScale)
		}
	}
	return scaled, rs, err
}
```

##### IsSaturated

```go
// 是不是饱和了
func IsSaturated(deployment *apps.Deployment, rs *apps.ReplicaSet) bool {
	if rs == nil {
		return false
	}
	desiredString := rs.Annotations[DesiredReplicasAnnotation]
	desired, err := strconv.Atoi(desiredString)
	if err != nil {
		return false
	}
	return *(rs.Spec.Replicas) == *(deployment.Spec.Replicas) &&
		int32(desired) == *(deployment.Spec.Replicas) &&
		rs.Status.AvailableReplicas == *(deployment.Spec.Replicas)
}
```

##### FilterActiveReplicaSets

```go
func FilterActiveReplicaSets(replicaSets []*apps.ReplicaSet) []*apps.ReplicaSet {
	activeFilter := func(rs *apps.ReplicaSet) bool {
		return rs != nil && *(rs.Spec.Replicas) > 0
	}
	return FilterReplicaSets(replicaSets, activeFilter)
}

func FilterReplicaSets(RSes []*apps.ReplicaSet, filterFn filterRS) []*apps.ReplicaSet {
	var filtered []*apps.ReplicaSet
	for i := range RSes {
		if filterFn(RSes[i]) {
			filtered = append(filtered, RSes[i])
		}
	}
	return filtered
}
```

##### ReplicaSetsBySizeNewer

```go
type ReplicaSetsBySizeNewer []*apps.ReplicaSet

func (o ReplicaSetsBySizeNewer) Len() int      { return len(o) }
func (o ReplicaSetsBySizeNewer) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o ReplicaSetsBySizeNewer) Less(i, j int) bool {
	if *(o[i].Spec.Replicas) == *(o[j].Spec.Replicas) {
		return ReplicaSetsByCreationTimestamp(o).Less(j, i)
	}
	return *(o[i].Spec.Replicas) > *(o[j].Spec.Replicas)
}
```

##### GetProportion

```go
// 获取新的 Deployment Replica 数量占当前 ReplicaSet 数量的比例
func GetProportion(logger klog.Logger, rs *apps.ReplicaSet, d apps.Deployment, deploymentReplicasToAdd, deploymentReplicasAdded int32) int32 {
	if rs == nil || *(rs.Spec.Replicas) == 0 || deploymentReplicasToAdd == 0 || deploymentReplicasToAdd == deploymentReplicasAdded {
        // 如果当前 ReplicaSet 为空或数量为 0，或者 Deployment 不需要添加 Replica 或者已经添加的数量等于需要添加的数量，则返回 0
		return int32(0)
	}
	
	// 获取当前 ReplicaSet 占 Deployment 数量的比例
	rsFraction := getReplicaSetFraction(logger, *rs, d)
	allowed := deploymentReplicasToAdd - deploymentReplicasAdded

	if deploymentReplicasToAdd > 0 {
		// 在扩容时，使用当前 ReplicaSet 数量占 Deployment 数量的比例和允许添加的最大 Replica 数量的较小值
        // 这样可以确保我们不会扩容超过允许添加的最大 Replica 数量
		return integer.Int32Min(rsFraction, allowed)
	}
	// 在缩容时，使用当前 ReplicaSet 数量占 Deployment 数量的比例和允许移除的最大 Replica 数量的较大值
	// 这样可以确保我们不会缩容超过允许移除的最大 Replica 数量
	return integer.Int32Max(rsFraction, allowed)
}

func getReplicaSetFraction(logger klog.Logger, rs apps.ReplicaSet, d apps.Deployment) int32 {
	// 如果我们正在缩容到零，则这个 ReplicaSet 的比例是其整个大小（负数）
	if *(d.Spec.Replicas) == int32(0) {
		return -*(rs.Spec.Replicas)
	}
	// 获取 Deployment 的当前 Replica 数量加上最大扩容数量
	deploymentReplicas := *(d.Spec.Replicas) + MaxSurge(d)
    // 获取当前 ReplicaSet 的最大 Replica 数量
	annotatedReplicas, ok := getMaxReplicasAnnotation(logger, &rs)
	if !ok {
		// 如果找不到注释，则回退到当前 Deployment 大小
		// 注意，在其他 ReplicaSet 具有不同值的情况下，这将不是准确的比例估计，但由于 getProportion 中的最小-最大比较，
		// 我们至少会保持在限制范围内。
		annotatedReplicas = d.Status.Replicas
	}

	// 我们应该永远不会从零比例缩放，这意味着 rs.spec.replicas 和 annotatedReplicas 永远不会在此处为零。
	// 计算新的 ReplicaSet 大小，保留整数部分
	newRSsize := (float64(*(rs.Spec.Replicas) * deploymentReplicas)) / float64(annotatedReplicas)
	return integer.RoundToInt32(newRSsize) - *(rs.Spec.Replicas)
}
```



#### getRollbackTo

```GO
func getRollbackTo(d *apps.Deployment) *extensions.RollbackConfig {
	// Extract the annotation used for round-tripping the deprecated RollbackTo field.
	revision := d.Annotations[apps.DeprecatedRollbackTo]
	if revision == "" {
		return nil
	}
	revision64, err := strconv.ParseInt(revision, 10, 64)
	if err != nil {
		// If it's invalid, ignore it.
		return nil
	}
	return &extensions.RollbackConfig{
		Revision: revision64,
	}
}

const DeprecatedRollbackTo           = "deprecated.deployment.rollback.to"
```

### rollback

```go
func (dc *DeploymentController) rollback(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
	logger := klog.FromContext(ctx)
    // 获取新的 ReplicaSet，以及需要回滚的所有 ReplicaSet
	newRS, allOldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, true)
	if err != nil {
		return err
	}
	// 将所有需要回滚的 ReplicaSet 加入到 allRSs 中
	allRSs := append(allOldRSs, newRS)
	rollbackTo := getRollbackTo(d)
	// 如果回滚的版本号是 0，则回滚到最后一个版本
	if rollbackTo.Revision == 0 {
		if rollbackTo.Revision = deploymentutil.LastRevision(allRSs); rollbackTo.Revision == 0 {
			// 如果仍然找不到最后一个版本，则放弃回滚
			dc.emitRollbackWarningEvent(d, deploymentutil.RollbackRevisionNotFound, "Unable to find last revision.")
			// 放弃回滚
			return dc.updateDeploymentAndClearRollbackTo(ctx, d)
		}
	}
    // 遍历所有 ReplicaSet
	for _, rs := range allRSs {
        // 获取 ReplicaSet 的版本号
		v, err := deploymentutil.Revision(rs)
		if err != nil {
			logger.V(4).Info("Unable to extract revision from deployment's replica set", "replicaSet", klog.KObj(rs), "err", err)
			continue
		}
		if v == rollbackTo.Revision {
			logger.V(4).Info("Found replica set with desired revision", "replicaSet", klog.KObj(rs), "revision", v)
			// 根据回滚的版本号从指定的 ReplicaSet 中复制 podTemplate.Spec
			// 下次 getAllReplicaSetsAndSyncRevision 调用时将增加版本号
			// 如果 podTemplate.Spec 匹配当前 Deployment，则不执行任何操作
			performedRollback, err := dc.rollbackToTemplate(ctx, d, rs)
			if performedRollback && err == nil {
                // 发送回滚完成事件
				dc.emitRollbackNormalEvent(d, fmt.Sprintf("Rolled back deployment %q to revision %d", d.Name, rollbackTo.Revision))
			}
			return err
		}
	}
    // 找不到需要回滚的版本号，发送回滚失败事件
	dc.emitRollbackWarningEvent(d, deploymentutil.RollbackRevisionNotFound, "Unable to find the revision to rollback to.")
	// 放弃回滚
	return dc.updateDeploymentAndClearRollbackTo(ctx, d)
}

```

#### LastRevision

```go
func LastRevision(allRSs []*apps.ReplicaSet) int64 {
	max, secMax := int64(0), int64(0)
    // 遍历所有 ReplicaSet
	for _, rs := range allRSs {
        // 解析 ReplicaSet 的版本号
		if v, err := Revision(rs); err != nil {
			// 如果无法解析版本号，则跳过该 ReplicaSet
			klog.V(4).Info("Couldn't parse revision for replica set, deployment controller will skip it when reconciling revisions", "replicaSet", klog.KObj(rs), "err", err)
		} else if v >= max {
            // 找到更大的版本号，更新 max 和 secMax
			secMax = max
			max = v
		} else if v > secMax {
            // 找到更大的次大版本号，更新 secMax
			secMax = v
		}
	}
    // 返回次大版本号
	return secMax
}

```

#### emitRollbackWarningEvent

```GO
func (dc *DeploymentController) emitRollbackWarningEvent(d *apps.Deployment, reason, message string) {
	dc.eventRecorder.Eventf(d, v1.EventTypeWarning, reason, message)
}
```

#### updateDeploymentAndClearRollbackTo

```GO
func (dc *DeploymentController) updateDeploymentAndClearRollbackTo(ctx context.Context, d *apps.Deployment) error {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Cleans up rollbackTo of deployment", "deployment", klog.KObj(d))
	setRollbackTo(d, nil)
	_, err := dc.client.AppsV1().Deployments(d.Namespace).Update(ctx, d, metav1.UpdateOptions{})
	return err
}

```

#### setRollbackTo

```GO
func setRollbackTo(d *apps.Deployment, rollbackTo *extensions.RollbackConfig) {
	if rollbackTo == nil {
		delete(d.Annotations, apps.DeprecatedRollbackTo)
		return
	}
	if d.Annotations == nil {
		d.Annotations = make(map[string]string)
	}
	d.Annotations[apps.DeprecatedRollbackTo] = strconv.FormatInt(rollbackTo.Revision, 10)
}
```

#### Revision

```GO
func Revision(obj runtime.Object) (int64, error) {
	acc, err := meta.Accessor(obj)
	if err != nil {
		return 0, err
	}
	v, ok := acc.GetAnnotations()[RevisionAnnotation]
	if !ok {
		return 0, nil
	}
	return strconv.ParseInt(v, 10, 64)
}

```

#### rollbackToTemplate

```GO
func (dc *DeploymentController) rollbackToTemplate(ctx context.Context, d *apps.Deployment, rs *apps.ReplicaSet) (bool, error) {
	logger := klog.FromContext(ctx)
	performedRollback := false
    // 如果当前 Deployment 的 podTemplate.Spec 与指定的 ReplicaSet 不同，执行回滚操作
	if !deploymentutil.EqualIgnoreHash(&d.Spec.Template, &rs.Spec.Template) {
		logger.V(4).Info("Rolling back deployment to old template spec", "deployment", klog.KObj(d), "templateSpec", rs.Spec.Template.Spec)
        // 设置当前 Deployment 的 podTemplate.Spec 为指定 ReplicaSet 的 podTemplate.Spec
		deploymentutil.SetFromReplicaSetTemplate(d, rs.Spec.Template)
		// 将指定 ReplicaSet 的注释信息设置到当前 Deployment 中
		deploymentutil.SetDeploymentAnnotationsTo(d, rs)
		performedRollback = true
	} else {
        // 如果当前 Deployment 的 podTemplate.Spec 与指定 ReplicaSet 相同，不执行回滚操作
		logger.V(4).Info("Rolling back to a revision that contains the same template as current deployment, skipping rollback...", "deployment", klog.KObj(d))
		eventMsg := fmt.Sprintf("The rollback revision contains the same template as current deployment %q", d.Name)
        // 发送回滚警告事件
		dc.emitRollbackWarningEvent(d, deploymentutil.RollbackTemplateUnchanged, eventMsg)
	}

	return performedRollback, dc.updateDeploymentAndClearRollbackTo(ctx, d)
}
```

#### SetFromReplicaSetTemplate

```GO
func SetFromReplicaSetTemplate(deployment *apps.Deployment, template v1.PodTemplateSpec) *apps.Deployment {
	deployment.Spec.Template.ObjectMeta = template.ObjectMeta
	deployment.Spec.Template.Spec = template.Spec
	deployment.Spec.Template.ObjectMeta.Labels = labelsutil.CloneAndRemoveLabel(
		deployment.Spec.Template.ObjectMeta.Labels,
		apps.DefaultDeploymentUniqueLabelKey)
	return deployment
}

```

#### updateDeploymentAndClearRollbackTo

```GO
func SetDeploymentAnnotationsTo(deployment *apps.Deployment, rollbackToRS *apps.ReplicaSet) {
	deployment.Annotations = getSkippedAnnotations(deployment.Annotations)
	for k, v := range rollbackToRS.Annotations {
		if !skipCopyAnnotation(k) {
			deployment.Annotations[k] = v
		}
	}
}

func skipCopyAnnotation(key string) bool {
	return annotationsToSkip[key]
}
```

#### emitRollbackNormalEvent

```GO
func (dc *DeploymentController) emitRollbackNormalEvent(d *apps.Deployment, message string) {
	dc.eventRecorder.Eventf(d, v1.EventTypeNormal, deploymentutil.RollbackDone, message)
}
```

### isScalingEvent

```GO
func (dc *DeploymentController) isScalingEvent(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) (bool, error) {
    // 获取新的 ReplicaSet，以及所有旧的 ReplicaSet
	newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, false)
	if err != nil {
		return false, err
	}
    // 将新旧 ReplicaSet 合并到 allRSs 中
	allRSs := append(oldRSs, newRS)
	logger := klog.FromContext(ctx)
    // 遍历所有正在运行的 ReplicaSet
	for _, rs := range controller.FilterActiveReplicaSets(allRSs) {
        // 获取该 ReplicaSet 的期望副本数
		desired, ok := deploymentutil.GetDesiredReplicasAnnotation(logger, rs)
		if !ok {
			continue
		}
        // 如果期望副本数与当前 Deployment 的期望副本数不同，则发生了扩容或缩容事件
		if desired != *(d.Spec.Replicas) {
			return true, nil
		}
	}
	return false, nil
}

```

#### GetDesiredReplicasAnnotation

```GO
func GetDesiredReplicasAnnotation(logger klog.Logger, rs *apps.ReplicaSet) (int32, bool) {
	return getIntFromAnnotation(logger, rs, DesiredReplicasAnnotation)
}

const DesiredReplicasAnnotation = "deployment.kubernetes.io/desired-replicas"

func getIntFromAnnotation(logger klog.Logger, rs *apps.ReplicaSet, annotationKey string) (int32, bool) {
	annotationValue, ok := rs.Annotations[annotationKey]
	if !ok {
		return int32(0), false
	}
	intValue, err := strconv.Atoi(annotationValue)
	if err != nil {
		logger.V(2).Info("Could not convert the value with annotation key for the replica set", "annotationValue", annotationValue, "annotationKey", annotationKey, "replicaSet", klog.KObj(rs))
		return int32(0), false
	}
	return int32(intValue), true
}
```

### rolloutRecreate

```go
func (dc *DeploymentController) rolloutRecreate(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet, podMap map[types.UID][]*v1.Pod) error {
	// 如果新的 ReplicaSet 不存在，不会创建新的 ReplicaSet
	// 这样可以避免在缩容之前扩容
	newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, false)
	if err != nil {
		return err
	}
    // 将新旧 ReplicaSet 合并到 allRSs 中
	allRSs := append(oldRSs, newRS)
    // 获取所有正在运行的旧 ReplicaSet
	activeOldRSs := controller.FilterActiveReplicaSets(oldRSs)

	// 缩容旧的 ReplicaSet
	scaledDown, err := dc.scaleDownOldReplicaSetsForRecreate(ctx, activeOldRSs, d)
	if err != nil {
		return err
	}
	if scaledDown {
		// 更新 DeploymentStatus
		return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
	}

	// 如果存在正在运行的旧 Pod，则不进行滚动升级操作
	if oldPodsRunning(newRS, oldRSs, podMap) {
		return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
	}

	// 如果需要创建新的 ReplicaSet，则创建它
	if newRS == nil {
		newRS, oldRSs, err = dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, true)
		if err != nil {
			return err
		}
		allRSs = append(oldRSs, newRS)
	}

	// 扩容新的 ReplicaSet
	if _, err := dc.scaleUpNewReplicaSetForRecreate(ctx, newRS, d); err != nil {
		return err
	}
	// 如果 Deployment 完成，则清理旧的 ReplicaSet
	if util.DeploymentComplete(d, &d.Status) {
		if err := dc.cleanupDeployment(ctx, oldRSs, d); err != nil {
			return err
		}
	}

	// 同步 Deployment 状态
	return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
}
```

#### scaleDownOldReplicaSetsForRecreate

```go
func (dc *DeploymentController) scaleDownOldReplicaSetsForRecreate(ctx context.Context, oldRSs []*apps.ReplicaSet, deployment *apps.Deployment) (bool, error) {
	scaled := false
	for i := range oldRSs {
		rs := oldRSs[i]
		// 如果当前 ReplicaSet 的副本数为 0，则不需要缩容
		if *(rs.Spec.Replicas) == 0 {
			continue
		}
        // 缩容 ReplicaSet
		scaledRS, updatedRS, err := dc.scaleReplicaSetAndRecordEvent(ctx, rs, 0, deployment)
		if err != nil {
			return false, err
		}
		if scaledRS {
			oldRSs[i] = updatedRS
			scaled = true
		}
	}
	return scaled, nil
}

```

#### scaleUpNewReplicaSetForRecreate

```go
func (dc *DeploymentController) scaleUpNewReplicaSetForRecreate(ctx context.Context, newRS *apps.ReplicaSet, deployment *apps.Deployment) (bool, error) {
	scaled, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, newRS, *(deployment.Spec.Replicas), deployment)
	return scaled, err
}
```

#### DeploymentComplete

```go
func DeploymentComplete(deployment *apps.Deployment, newStatus *apps.DeploymentStatus) bool {
	return newStatus.UpdatedReplicas == *(deployment.Spec.Replicas) &&
		newStatus.Replicas == *(deployment.Spec.Replicas) &&
		newStatus.AvailableReplicas == *(deployment.Spec.Replicas) &&
		newStatus.ObservedGeneration >= deployment.Generation
}
```

#### cleanupDeployment

```go
func (dc *DeploymentController) cleanupDeployment(ctx context.Context, oldRSs []*apps.ReplicaSet, deployment *apps.Deployment) error {
	logger := klog.FromContext(ctx)
    // 如果 Deployment 的 RevisionHistoryLimit 为 0，则不需要清理旧 ReplicaSet
	if !deploymentutil.HasRevisionHistoryLimit(deployment) {
		return nil
	}

	// 过滤出未被标记删除的 ReplicaSet
	aliveFilter := func(rs *apps.ReplicaSet) bool {
		return rs != nil && rs.ObjectMeta.DeletionTimestamp == nil
	}
	cleanableRSes := controller.FilterReplicaSets(oldRSs, aliveFilter)
	// 计算需要删除的旧 ReplicaSet 的数量
	diff := int32(len(cleanableRSes)) - *deployment.Spec.RevisionHistoryLimit
	if diff <= 0 {
		return nil
	}
	// 按照 Revision 从小到大排序，依次删除旧 ReplicaSet
	sort.Sort(deploymentutil.ReplicaSetsByRevision(cleanableRSes))
	logger.V(4).Info("Looking to cleanup old replica sets for deployment", "deployment", klog.KObj(deployment))

	for i := int32(0); i < diff; i++ {
		rs := cleanableRSes[i]
		// 避免删除正在运行的 ReplicaSet，或者带有副本的 ReplicaSet
		if rs.Status.Replicas != 0 || *(rs.Spec.Replicas) != 0 || rs.Generation > rs.Status.ObservedGeneration || rs.DeletionTimestamp != nil {
			continue
		}
		logger.V(4).Info("Trying to cleanup replica set for deployment", "replicaSet", klog.KObj(rs), "deployment", klog.KObj(deployment))
		if err := dc.client.AppsV1().ReplicaSets(rs.Namespace).Delete(ctx, rs.Name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			// 如果删除失败，直接返回错误
			return err
		}
	}

	return nil
}
```

#### syncRolloutStatus

```go
// 根据 ReplicaSet 的状态更新 Deployment 对象的状态。
func (dc *DeploymentController) syncRolloutStatus(ctx context.Context, allRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, d *apps.Deployment) error {
    // 计算新的状态
	newStatus := calculateStatus(allRSs, newRS, d)

	// 如果没有设置 progressDeadlineSeconds，则删除任何正在进行的状态。
	if !util.HasProgressDeadline(d) {
		util.RemoveDeploymentCondition(&newStatus, apps.DeploymentProgressing)
	}

	// 如果只有一个处于活动状态的 ReplicaSet，那么这意味着我们不是在运行新的滚动更新，而是进行重新同步，
    // 因此不需要估计任何进度。在这种情况下，我们应该简单地不为此部署估计任何进度。
	currentCond := util.GetDeploymentCondition(d.Status, apps.DeploymentProgressing)
	isCompleteDeployment := newStatus.Replicas == newStatus.UpdatedReplicas && currentCond != nil && currentCond.Reason == util.NewRSAvailableReason
	 // 如果设置了进度截止时间并且最新的滚动更新尚未完成，则检查进度。
	if util.HasProgressDeadline(d) && !isCompleteDeployment {
		switch {
		case util.DeploymentComplete(d, &newStatus):
			// 使用消息更新部署条件，表示已成功部署新的 ReplicaSet。如果条件已经存在，则忽略此更新。
			msg := fmt.Sprintf("Deployment %q has successfully progressed.", d.Name)
			if newRS != nil {
				msg = fmt.Sprintf("ReplicaSet %q has successfully progressed.", newRS.Name)
			}
			condition := util.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionTrue, util.NewRSAvailableReason, msg)
			util.SetDeploymentCondition(&newStatus, *condition)

		case util.DeploymentProgressing(d, &newStatus):
			// 如果有任何进展，请继续而不检查部署是否失败。这种行为模拟了滚动更新程序的 progressDeadline 检查。
			msg := fmt.Sprintf("Deployment %q is progressing.", d.Name)
			if newRS != nil {
				msg = fmt.Sprintf("ReplicaSet %q is progressing.", newRS.Name)
			}
			condition := util.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionTrue, util.ReplicaSetUpdatedReason, msg)
			// 更新当前的 Progressing 条件，如果不存在，则添加一个新的条件。如果状态为 true 的 Progressing 条件已经存在，则更新除了 lastTransitionTime 以外的所有内容。
            // SetDeploymentCondition 已经执行了这项工作，但是当新条件的原因与旧条件相同时，它也不会更新条件。
            // Progressing 条件是特殊情况，因为我们希望使用相同的原因进行更新，并在注意到任何进展时仅更改 lastUpdateTime。这就是为什么我们在此处理它的原因。
			if currentCond != nil {
				if currentCond.Status == v1.ConditionTrue {
					condition.LastTransitionTime = currentCond.LastTransitionTime
				}
				util.RemoveDeploymentCondition(&newStatus, apps.DeploymentProgressing)
			}
			util.SetDeploymentCondition(&newStatus, *condition)

		case util.DeploymentTimedOut(ctx, d, &newStatus):
			// 使用超时消息更新部署。如果条件已经存在，则忽略此更新。
			msg := fmt.Sprintf("Deployment %q has timed out progressing.", d.Name)
			if newRS != nil {
				msg = fmt.Sprintf("ReplicaSet %q has timed out progressing.", newRS.Name)
			}
			condition := util.NewDeploymentCondition(apps.DeploymentProgressing, v1.ConditionFalse, util.TimedOutReason, msg)
			util.SetDeploymentCondition(&newStatus, *condition)
		}
	}

	// 将所有 ReplicaSet 的故障条件移动到部署条件中。目前，从 getReplicaFailures 返回的只有一个故障条件。
	if replicaFailureCond := dc.getReplicaFailures(allRSs, newRS); len(replicaFailureCond) > 0 {
		// 在 ReplicaSet 上只会有一个 ReplicaFailure 条件。
		util.SetDeploymentCondition(&newStatus, replicaFailureCond[0])
	} else {
		util.RemoveDeploymentCondition(&newStatus, apps.DeploymentReplicaFailure)
	}

	// 如果没有新内容添加，则不更新。
	if reflect.DeepEqual(d.Status, newStatus) {
		// 如果需要，重新排队部署。
		dc.requeueStuckDeployment(ctx, d, newStatus)
		return nil
	}
	// 更新部署的状态。
	newDeployment := d
	newDeployment.Status = newStatus
	_, err := dc.client.AppsV1().Deployments(newDeployment.Namespace).UpdateStatus(ctx, newDeployment, metav1.UpdateOptions{})
	return err
}
```

##### RemoveDeploymentCondition

```GO
func RemoveDeploymentCondition(status *apps.DeploymentStatus, condType apps.DeploymentConditionType) {
	status.Conditions = filterOutCondition(status.Conditions, condType)
}

func filterOutCondition(conditions []apps.DeploymentCondition, condType apps.DeploymentConditionType) []apps.DeploymentCondition {
	var newConditions []apps.DeploymentCondition
	for _, c := range conditions {
		if c.Type == condType {
			continue
		}
		newConditions = append(newConditions, c)
	}
	return newConditions
}
```

##### DeploymentProgressing

```GO
func DeploymentProgressing(deployment *apps.Deployment, newStatus *apps.DeploymentStatus) bool {
	oldStatus := deployment.Status

	// Old replicas that need to be scaled down
	oldStatusOldReplicas := oldStatus.Replicas - oldStatus.UpdatedReplicas
	newStatusOldReplicas := newStatus.Replicas - newStatus.UpdatedReplicas

	return (newStatus.UpdatedReplicas > oldStatus.UpdatedReplicas) ||
		(newStatusOldReplicas < oldStatusOldReplicas) ||
		newStatus.ReadyReplicas > deployment.Status.ReadyReplicas ||
		newStatus.AvailableReplicas > deployment.Status.AvailableReplicas
}
```

##### DeploymentTimedOut

```GO
// DeploymentTimedOut 检查部署是否已超时。
func DeploymentTimedOut(ctx context.Context, deployment *apps.Deployment, newStatus *apps.DeploymentStatus) bool {
    if !HasProgressDeadline(deployment) {
        return false
    }

    // 查找 Progressing 状态。如果不存在，则无法估计进度。如果已经使用 TimedOutReason 原因设置了条件，则已超时，无需再次检查。
    condition := GetDeploymentCondition(*newStatus, apps.DeploymentProgressing)
    if condition == nil {
        return false
    }
    // 如果先前的条件是成功的滚动更新，则不应尝试估计任何进度。情况如下：
    //
    // * progressDeadlineSeconds 小于现在与过去最后一次滚动更新完成时间之间的差异。
    // * 创建新的 ReplicaSet 触发了重新同步部署，此时 Deployment 的缓存副本在更新状态条件（指示新的 ReplicaSet 创建）之前。
    //
    // 部署将进行重新同步，并最终其 Progressing 状态将赶上现实世界的状态。
    if condition.Reason == NewRSAvailableReason {
        return false
    }
    if condition.Reason == TimedOutReason {
        return true
    }
    logger := klog.FromContext(ctx)
    // 查看现在与我们上次报告任何进度、尝试创建 ReplicaSet 或恢复暂停的部署之间的时间差，并与 progressDeadlineSeconds 进行比较。
    from := condition.LastUpdateTime
    now := nowFn()
    delta := time.Duration(*deployment.Spec.ProgressDeadlineSeconds) * time.Second
    timedOut := from.Add(delta).Before(now)

    logger.V(4).Info("Deployment timed out from last progress check", "deployment", klog.KObj(deployment), "timeout", timedOut, "from", from, "now", now)
    return timedOut
}
```

##### requeueStuckDeployment

```GO
// requeueStuckDeployment 重新排队被卡住的部署以进行进度检查。
func (dc *DeploymentController) requeueStuckDeployment(ctx context.Context, d *apps.Deployment, newStatus apps.DeploymentStatus) time.Duration {
    logger := klog.FromContext(ctx)
    currentCond := util.GetDeploymentCondition(d.Status, apps.DeploymentProgressing)
    // 如果规范中没有截止时间或当前状态中没有 progressing 条件，则无法估计进度。
    if !util.HasProgressDeadline(d) || currentCond == nil {
        return time.Duration(-1)
    }
    // 如果部署已完成或已超时，则无需估计进度。
    if util.DeploymentComplete(d, &newStatus) || currentCond.Reason == util.TimedOutReason {
        return time.Duration(-1)
    }
    // 如果此时没有进展迹象，则部署很可能被卡住。我们应该在未来某个时刻重新同步此部署进行进度检查[1]，并检查是否已超时。我们绝对需要这个功能，否则我们依赖于控制器的重新同步间隔。参见 https://github.com/kubernetes/kubernetes/issues/34458。
    //
    // [1] ProgressingCondition.LastUpdatedTime + progressDeadlineSeconds - time.Now()
    //
    // 例如，如果一个部署在3分钟前更新了其 Progressing 状态，并有10分钟的截止时间，则在7分钟后需要为其进行进度检查。
    //
    // lastUpdated:            00:00:00
    // now:                    00:03:00
    // progressDeadlineSeconds: 600 (10 minutes)
    //
    // lastUpdated + progressDeadlineSeconds - now => 00:00:00 + 00:10:00 - 00:03:00 => 07:00
    after := currentCond.LastUpdateTime.Time.Add(time.Duration(*d.Spec.ProgressDeadlineSeconds) * time.Second).Sub(nowFn())
    // 如果剩余时间小于1秒，则立即重新排队部署。以这种方式进行速率限制，这样我们就能保证安全了，最终部署应该转换为 Complete 或 TimedOut 条件之一。
    if after < time.Second {
        logger.V(4).Info("Queueing up deployment for a progress check now", "deployment", klog.KObj(d))
        dc.enqueueRateLimited(d)
        return time.Duration(0)
    }
    logger.V(4).Info("Queueing up deployment for a progress check", "deployment", klog.KObj(d), "queueAfter", int(after.Seconds()))
    // 添加一秒钟以避免 AddAfter 中的毫秒偏差。参见 https://github.com/kubernetes/kubernetes/issues/39785#issuecomment-279959133 以获取更多信息。
    dc.enqueueAfter(d, after+time.Second)
    return after
}

```

### rolloutRolling

```GO
func (dc *DeploymentController) rolloutRolling(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
    // 获取所有的 ReplicaSet，并同步修订版本
    newRS, oldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, true)
    if err != nil {
        return err
    }
    allRSs := append(oldRSs, newRS)

    // 如果可以，进行扩容
    scaledUp, err := dc.reconcileNewReplicaSet(ctx, allRSs, newRS, d)
    if err != nil {
        return err
    }
    if scaledUp {
        // 更新 DeploymentStatus
        return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
    }

    // 如果可以，进行缩容
    scaledDown, err := dc.reconcileOldReplicaSets(ctx, allRSs, controller.FilterActiveReplicaSets(oldRSs), newRS, d)
    if err != nil {
        return err
    }
    if scaledDown {
        // 更新 DeploymentStatus
        return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
    }

    // 如果 Deployment 完成，则清理旧的 ReplicaSet
    if deploymentutil.DeploymentComplete(d, &d.Status) {
        if err := dc.cleanupDeployment(ctx, oldRSs, d); err != nil {
            return err
        }
    }

    // 同步 Deployment 的状态
    return dc.syncRolloutStatus(ctx, allRSs, newRS, d)
}

```

#### reconcileNewReplicaSet

```GO
func (dc *DeploymentController) reconcileNewReplicaSet(ctx context.Context, allRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, deployment *apps.Deployment) (bool, error) {
    // 如果新 ReplicaSet 的副本数量与 Deployment 的副本数量相等，则无需扩容
    if *(newRS.Spec.Replicas) == *(deployment.Spec.Replicas) {
        // 不需要扩容。
        return false, nil
    }
    // 如果新 ReplicaSet 的副本数量大于 Deployment 的副本数量，则进行缩容
    if *(newRS.Spec.Replicas) > *(deployment.Spec.Replicas) {
        // 缩容。
        scaled, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, newRS, *(deployment.Spec.Replicas), deployment)
        return scaled, err
    }
    // 否则，计算新 ReplicaSet 的副本数量，并进行扩容
    newReplicasCount, err := deploymentutil.NewRSNewReplicas(deployment, allRSs, newRS)
    if err != nil {
        return false, err
    }
    scaled, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, newRS, newReplicasCount, deployment)
    return scaled, err
}

```

##### NewRSNewReplicas

```GO
func NewRSNewReplicas(deployment *apps.Deployment, allRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet) (int32, error) {
    switch deployment.Spec.Strategy.Type {
    // 对于 RollingUpdate 策略
    case apps.RollingUpdateDeploymentStrategyType:
        // 检查是否可以扩容
        maxSurge, err := intstrutil.GetScaledValueFromIntOrPercent(deployment.Spec.Strategy.RollingUpdate.MaxSurge, int(*(deployment.Spec.Replicas)), true)
        if err != nil {
            return 0, err
        }
        // 找到所有 ReplicaSet 中的 pod 总数
        currentPodCount := GetReplicaCountForReplicaSets(allRSs)
        maxTotalPods := *(deployment.Spec.Replicas) + int32(maxSurge)
        if currentPodCount >= maxTotalPods {
            // 无法扩容
            return *(newRS.Spec.Replicas), nil
        }
        // 进行扩容
        scaleUpCount := maxTotalPods - currentPodCount
        // 不超过所需副本数量
        scaleUpCount = int32(integer.IntMin(int(scaleUpCount), int(*(deployment.Spec.Replicas)-*(newRS.Spec.Replicas))))
        return *(newRS.Spec.Replicas) + scaleUpCount, nil
    // 对于 Recreate 策略
    case apps.RecreateDeploymentStrategyType:
        return *(deployment.Spec.Replicas), nil
    default:
        return 0, fmt.Errorf("deployment type %v isn't supported", deployment.Spec.Strategy.Type)
    }
}

```

#### reconcileOldReplicaSets

```GO
func (dc *DeploymentController) reconcileOldReplicaSets(ctx context.Context, allRSs []*apps.ReplicaSet, oldRSs []*apps.ReplicaSet, newRS *apps.ReplicaSet, deployment *apps.Deployment) (bool, error) {
	logger := klog.FromContext(ctx)
	oldPodsCount := deploymentutil.GetReplicaCountForReplicaSets(oldRSs)
	if oldPodsCount == 0 {
		// 无法再进行缩容
		return false, nil
	}
	allPodsCount := deploymentutil.GetReplicaCountForReplicaSets(allRSs)
	logger.V(4).Info("New replica set", "replicaSet", klog.KObj(newRS), "availableReplicas", newRS.Status.AvailableReplicas)
	maxUnavailable := deploymentutil.MaxUnavailable(*deployment)

	// 检查是否可以进行缩容。有两种情况可以进行缩容：
    // * 一些旧的 ReplicaSet 中有不健康的 pod，我们可以安全地缩小这些不健康的 pod，因为这不会进一步增加不可用性。
    // * 新 ReplicaSet 已经扩容，并且其 pod 已经准备就绪，那么我们可以进一步缩小旧的 ReplicaSet。
    //
    // maxScaledDown := allPodsCount - minAvailable - newReplicaSetPodsUnavailable
    // 考虑到不仅要考虑 maxUnavailable 和已创建的任何 surge pod，还要考虑来自 newRS 的不可用 pod，以便 newRS 中的不可用 pod 不会让我们进一步缩小旧的 ReplicaSet（这会增加不可用性）。
    //
    // 具体例子：
    //
    // * 10 个副本
    // * 2 maxUnavailable（绝对数，不是百分比）
    // * 3 maxSurge（绝对数，不是百分比）
    //
    // 情况 1：
    // * 更新 Deployment，创建新的 ReplicaSet，3 个副本，旧 ReplicaSet 缩小到 8，新 ReplicaSet 扩大到 5。
    // * 新的 ReplicaSet 的 pod 崩溃，永远无法变为可用状态。
    // * allPodsCount 是 13。minAvailable 是 8。newRSPodsUnavailable 是 5。
    // * 节点故障，导致一个旧 ReplicaSet 的 pod 不可用。然而，13-8-5 = 0，因此旧的 ReplicaSet 不会缩小。
    // * 用户注意到崩溃，并执行 kubectl rollout undo 进行回滚。
    // * newRSPodsUnavailable 为 1，因为我们回滚到了好的 ReplicaSet，所以 maxScaledDown = 13-8-1 = 4。将关闭 4 个崩溃的 pod。
    // * 然后总 pod 数将是 9，新 ReplicaSet 可以扩大到 10。
    //
    // 情况 2：
    // 与上面相同的例子，但是推送了一个新的 pod 模板而不是回滚（称为“roll over”）：
    // * 创建的新 ReplicaSet 必须从 0 个副本开始，因为 allPodsCount 已经是 13。
    // * 然而，newRSPodsUnavailable 也将为 0，因此可以将 2 个旧 ReplicaSet 缩小 5（13-8-0），然后
    // 可以将新的 ReplicaSet 扩大 5。
	minAvailable := *(deployment.Spec.Replicas) - maxUnavailable
	newRSUnavailablePodCount := *(newRS.Spec.Replicas) - newRS.Status.AvailableReplicas
	maxScaledDown := allPodsCount - minAvailable - newRSUnavailablePodCount
	if maxScaledDown <= 0 {
		return false, nil
	}

	// 首先清理不健康的 pod，否则不健康的 pod 将阻塞部署并导致超时。请参阅 	
    // https://github.com/kubernetes/kubernetes/issues/16737
	oldRSs, cleanupCount, err := dc.cleanupUnhealthyReplicas(ctx, oldRSs, deployment, maxScaledDown)
	if err != nil {
		return false, nil
	}
	logger.V(4).Info("Cleaned up unhealthy replicas from old RSes", "count", cleanupCount)

	// 缩小旧的 ReplicaSet，需要检查 maxUnavailable 以确保可以缩小
	allRSs = append(oldRSs, newRS)
	scaledDownCount, err := dc.scaleDownOldReplicaSetsForRollingUpdate(ctx, allRSs, oldRSs, deployment)
	if err != nil {
		return false, nil
	}
	logger.V(4).Info("Scaled down old RSes", "deployment", klog.KObj(deployment), "count", scaledDownCount)

	totalScaledDown := cleanupCount + scaledDownCount
	return totalScaledDown > 0, nil
}
```

##### scaleDownOldReplicaSetsForRollingUpdate

```go
func (dc *DeploymentController) scaleDownOldReplicaSetsForRollingUpdate(ctx context.Context, allRSs []*apps.ReplicaSet, oldRSs []*apps.ReplicaSet, deployment *apps.Deployment) (int32, error) {
	logger := klog.FromContext(ctx)
	maxUnavailable := deploymentutil.MaxUnavailable(*deployment)

	// 检查是否可以缩小。
	minAvailable := *(deployment.Spec.Replicas) - maxUnavailable
	// 查找可用 Pod 数量。
	availablePodCount := deploymentutil.GetAvailableReplicaCountForReplicaSets(allRSs)
	if availablePodCount <= minAvailable {
		// 不能缩小。
		return 0, nil
	}
	logger.V(4).Info("Found available pods in deployment, scaling down old RSes", "deployment", klog.KObj(deployment), "availableReplicas", availablePodCount)

	sort.Sort(controller.ReplicaSetsByCreationTimestamp(oldRSs))

	totalScaledDown := int32(0)
	totalScaleDownCount := availablePodCount - minAvailable
	for _, targetRS := range oldRSs {
		if totalScaledDown >= totalScaleDownCount {
			// 不需要进一步缩小。
			break
		}
		if *(targetRS.Spec.Replicas) == 0 {
			// 无法缩小该 ReplicaSet。
			continue
		}
		// 缩小。
		scaleDownCount := int32(integer.IntMin(int(*(targetRS.Spec.Replicas)), int(totalScaleDownCount-totalScaledDown)))
		newReplicasCount := *(targetRS.Spec.Replicas) - scaleDownCount
		if newReplicasCount > *(targetRS.Spec.Replicas) {
			return 0, fmt.Errorf("when scaling down old RS, got invalid request to scale down %s/%s %d -> %d", targetRS.Namespace, targetRS.Name, *(targetRS.Spec.Replicas), newReplicasCount)
		}
		_, _, err := dc.scaleReplicaSetAndRecordEvent(ctx, targetRS, newReplicasCount, deployment)
		if err != nil {
			return totalScaledDown, err
		}

		totalScaledDown += scaleDownCount
	}

	return totalScaledDown, nil
}
```

