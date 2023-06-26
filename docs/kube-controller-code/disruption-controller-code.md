---
id: 16-kube-controller-code
title: disruption-controller 代码走读
description: disruption-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

disruption-controller 是 Kubernetes 中的一个控制器，它负责监控和更新 PodDisruptionBudget (PDB) 的状态。PDB 是一种资源对象，用于限制在主动干扰（如节点维护、集群升级或自动缩放）时可以同时删除的 Pod 的数量或百分比。disruption-controller 的作用是保证在主动销毁应用 Pod 的时候，不会一次性销毁过多的 Pod ，导致业务中断或 SLA 降级。

### 关于disruption

[Disruptions | Kubernetes](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/)

[Specifying a Disruption Budget for your Application | Kubernetes](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)

## 结构体

```GO
type DisruptionController struct {
	kubeClient clientset.Interface
    // REST资源映射的接口
	mapper     apimeta.RESTMapper
	
    // 获取指定命名空间下的水平自动扩展器的接口
	scaleNamespacer scaleclient.ScalesGetter
    // 服务发现的接口
	discoveryClient discovery.DiscoveryInterface

	pdbLister       policylisters.PodDisruptionBudgetLister
	pdbListerSynced cache.InformerSynced

	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	rcLister       corelisters.ReplicationControllerLister
	rcListerSynced cache.InformerSynced

	rsLister       appsv1listers.ReplicaSetLister
	rsListerSynced cache.InformerSynced

	dLister       appsv1listers.DeploymentLister
	dListerSynced cache.InformerSynced

	ssLister       appsv1listers.StatefulSetLister
	ssListerSynced cache.InformerSynced

	// PodDisruptionBudget 工作queue
	queue        workqueue.RateLimitingInterface
    // 延迟重新检查 PodDisruptionBudget 资源的工作queue 
	recheckQueue workqueue.DelayingInterface

	// 缓存需要同步的 Pod 资源的 workqueue，因为 DisruptionTarget 条件已过期
	stalePodDisruptionQueue   workqueue.RateLimitingInterface
    // DisruptionTarget 条件过期的超时时间
	stalePodDisruptionTimeout time.Duration

	broadcaster record.EventBroadcaster
	recorder    record.EventRecorder
	
    // 获取 updater 接口的函数
	getUpdater func() updater
	// 获取时间的接口
	clock clock.Clock
}

type updater func(context.Context, *policy.PodDisruptionBudget) error
```

## New

```go
func NewDisruptionController(
	podInformer coreinformers.PodInformer,
	pdbInformer policyinformers.PodDisruptionBudgetInformer,
	rcInformer coreinformers.ReplicationControllerInformer,
	rsInformer appsv1informers.ReplicaSetInformer,
	dInformer appsv1informers.DeploymentInformer,
	ssInformer appsv1informers.StatefulSetInformer,
	kubeClient clientset.Interface,
	restMapper apimeta.RESTMapper,
	scaleNamespacer scaleclient.ScalesGetter,
	discoveryClient discovery.DiscoveryInterface,
) *DisruptionController {
	return NewDisruptionControllerInternal(
		podInformer,
		pdbInformer,
		rcInformer,
		rsInformer,
		dInformer,
		ssInformer,
		kubeClient,
		restMapper,
		scaleNamespacer,
		discoveryClient,
		clock.RealClock{},
		stalePodDisruptionTimeout)
}

func NewDisruptionControllerInternal(
	podInformer coreinformers.PodInformer,
	pdbInformer policyinformers.PodDisruptionBudgetInformer,
	rcInformer coreinformers.ReplicationControllerInformer,
	rsInformer appsv1informers.ReplicaSetInformer,
	dInformer appsv1informers.DeploymentInformer,
	ssInformer appsv1informers.StatefulSetInformer,
	kubeClient clientset.Interface,
	restMapper apimeta.RESTMapper,
	scaleNamespacer scaleclient.ScalesGetter,
	discoveryClient discovery.DiscoveryInterface,
	clock clock.WithTicker,
	stalePodDisruptionTimeout time.Duration,
) *DisruptionController {
	dc := &DisruptionController{
		kubeClient:                kubeClient,
		queue:                     workqueue.NewRateLimitingQueueWithDelayingInterface(workqueue.NewDelayingQueueWithCustomClock(clock, "disruption"), workqueue.DefaultControllerRateLimiter()),
		recheckQueue:              workqueue.NewDelayingQueueWithCustomClock(clock, "disruption_recheck"),
		stalePodDisruptionQueue:   workqueue.NewRateLimitingQueueWithDelayingInterface(workqueue.NewDelayingQueueWithCustomClock(clock, "stale_pod_disruption"), workqueue.DefaultControllerRateLimiter()),
		broadcaster:               record.NewBroadcaster(),
		stalePodDisruptionTimeout: stalePodDisruptionTimeout,
	}
	dc.recorder = dc.broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "controllermanager"})

	dc.getUpdater = func() updater { return dc.writePdbStatus }
	
    // 对 Pod Informer 的处理
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    dc.addPod,
		UpdateFunc: dc.updatePod,
		DeleteFunc: dc.deletePod,
	})
	dc.podLister = podInformer.Lister()
	dc.podListerSynced = podInformer.Informer().HasSynced
	
    // 对 PodDisruptionBudget Informer 的处理
	pdbInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    dc.addDb,
			UpdateFunc: dc.updateDb,
			DeleteFunc: dc.removeDb,
		},
	)
	dc.pdbLister = pdbInformer.Lister()
	dc.pdbListerSynced = pdbInformer.Informer().HasSynced

	dc.rcLister = rcInformer.Lister()
	dc.rcListerSynced = rcInformer.Informer().HasSynced

	dc.rsLister = rsInformer.Lister()
	dc.rsListerSynced = rsInformer.Informer().HasSynced

	dc.dLister = dInformer.Lister()
	dc.dListerSynced = dInformer.Informer().HasSynced

	dc.ssLister = ssInformer.Lister()
	dc.ssListerSynced = ssInformer.Informer().HasSynced

	dc.mapper = restMapper
	dc.scaleNamespacer = scaleNamespacer
	dc.discoveryClient = discoveryClient

	dc.clock = clock

	return dc
}
```

### 队列相关

**pod**

```GO
func (dc *DisruptionController) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	klog.V(4).Infof("addPod called on pod %q", pod.Name)
    // 获取与当前pod匹配的pdb对象
	pdb := dc.getPdbForPod(pod)
	if pdb == nil {
        // 没有与当前pod匹配的pdb，打印相应的日志信息
		klog.V(4).Infof("No matching pdb for pod %q", pod.Name)
	} else {
        // 将pdb对象加入到工作队列中
		klog.V(4).Infof("addPod %q -> PDB %q", pod.Name, pdb.Name)
		dc.enqueuePdb(pdb)
	}
     // 检查当前pod是否满足条件，如果满足条件，则将pod对象加入到工作队列中
	if has, cleanAfter := dc.nonTerminatingPodHasStaleDisruptionCondition(pod); has {
		dc.enqueueStalePodDisruptionCleanup(pod, cleanAfter)
	}
}

func (dc *DisruptionController) updatePod(_, cur interface{}) {
	pod := cur.(*v1.Pod)
	klog.V(4).Infof("updatePod called on pod %q", pod.Name)
    // 获取与当前pod匹配的pdb对象
	pdb := dc.getPdbForPod(pod)
	if pdb == nil {
        // 没有与当前pod匹配的pdb，打印相应的日志信息
		klog.V(4).Infof("No matching pdb for pod %q", pod.Name)
	} else {
        // 将pdb对象加入到工作队列中
		klog.V(4).Infof("updatePod %q -> PDB %q", pod.Name, pdb.Name)
		dc.enqueuePdb(pdb)
	}
    // 检查当前pod是否满足条件，如果满足条件，则将pod对象加入到工作队列中
	if has, cleanAfter := dc.nonTerminatingPodHasStaleDisruptionCondition(pod); has {
		dc.enqueueStalePodDisruptionCleanup(pod, cleanAfter)
	}
}

func (dc *DisruptionController) deletePod(obj interface{}) {
    // 判断pod如果失败尝试cache.DeletedFinalStateUnknown断言
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %+v", obj)
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			klog.Errorf("Tombstone contained object that is not a pod %+v", obj)
			return
		}
	}
	klog.V(4).Infof("deletePod called on pod %q", pod.Name)
    // 获取与当前pod匹配的pdb对象
	pdb := dc.getPdbForPod(pod)
	if pdb == nil {
		klog.V(4).Infof("No matching pdb for pod %q", pod.Name)
		return
	}
	klog.V(4).Infof("deletePod %q -> PDB %q", pod.Name, pdb.Name)
    // 将pdb对象加入到工作队列中
	dc.enqueuePdb(pdb)
}


func (dc *DisruptionController) getPdbForPod(pod *v1.Pod) *policy.PodDisruptionBudget {
	// 获取所有与该 Pod 对象相关的 PodDisruptionBudgets
	pdbs, err := dc.pdbLister.GetPodPodDisruptionBudgets(pod)
	if err != nil {
		klog.V(4).Infof("No PodDisruptionBudgets found for pod %v, PodDisruptionBudget controller will avoid syncing.", pod.Name)
		return nil
	}

	if len(pdbs) > 1 {
        // 如果有多个 同时记录一条 warning 级别的事件，表示该 Pod 匹配了多个 PodDisruptionBudgets。
		msg := fmt.Sprintf("Pod %q/%q matches multiple PodDisruptionBudgets.  Chose %q arbitrarily.", pod.Namespace, pod.Name, pdbs[0].Name)
		klog.Warning(msg)
		dc.recorder.Event(pod, v1.EventTypeWarning, "MultiplePodDisruptionBudgets", msg)
	}
    // 返回第一个
	return pdbs[0]
}

func (dc *DisruptionController) nonTerminatingPodHasStaleDisruptionCondition(pod *v1.Pod) (bool, time.Duration) {
    // 如果pod删除 无需处理
	if pod.DeletionTimestamp != nil {
		return false, 0
	}
    // Condition中与干扰相关的条件
	_, cond := apipod.GetPodCondition(&pod.Status, v1.DisruptionTarget)
    // 如果没有此类条件，或条件状态不为 True，或者该条件是由 kubelet 触发的，或者 Pod 已经处于终止阶段，则不认为有过期的条件。返回 false 和 0。
	if cond == nil || cond.Status != v1.ConditionTrue || cond.Reason == v1.PodReasonTerminationByKubelet || apipod.IsPodPhaseTerminal(pod.Status.Phase) {
		return false, 0
	}
    // 计算过期时间
	waitFor := dc.stalePodDisruptionTimeout - dc.clock.Since(cond.LastTransitionTime.Time)
	if waitFor < 0 {
		waitFor = 0
	}
	return true, waitFor
}

// 延迟d秒加入stalePodDisruptionQueue队列
func (dc *DisruptionController) enqueueStalePodDisruptionCleanup(pod *v1.Pod, d time.Duration) {
	key, err := controller.KeyFunc(pod)
	if err != nil {
		klog.ErrorS(err, "Couldn't get key for Pod object", "pod", klog.KObj(pod))
		return
	}
	dc.stalePodDisruptionQueue.AddAfter(key, d)
	klog.V(4).InfoS("Enqueued pod to cleanup stale DisruptionTarget condition", "pod", klog.KObj(pod))
}
```

**enqueuePdb**

```go
func (dc *DisruptionController) enqueuePdb(pdb *policy.PodDisruptionBudget) {
	key, err := controller.KeyFunc(pdb)
	if err != nil {
		klog.Errorf("Couldn't get key for PodDisruptionBudget object %+v: %v", pdb, err)
		return
	}
	dc.queue.Add(key)
}

```

**pdb**

```go
func (dc *DisruptionController) addDb(obj interface{}) {
	pdb := obj.(*policy.PodDisruptionBudget)
	klog.V(4).Infof("add DB %q", pdb.Name)
	dc.enqueuePdb(pdb)
}

func (dc *DisruptionController) updateDb(old, cur interface{}) {
	// TODO(mml) ignore updates where 'old' is equivalent to 'cur'.
	pdb := cur.(*policy.PodDisruptionBudget)
	klog.V(4).Infof("update DB %q", pdb.Name)
	dc.enqueuePdb(pdb)
}

func (dc *DisruptionController) removeDb(obj interface{}) {
	pdb, ok := obj.(*policy.PodDisruptionBudget)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %+v", obj)
			return
		}
		pdb, ok = tombstone.Obj.(*policy.PodDisruptionBudget)
		if !ok {
			klog.Errorf("Tombstone contained object that is not a pdb %+v", obj)
			return
		}
	}
	klog.V(4).Infof("remove DB %q", pdb.Name)
	dc.enqueuePdb(pdb)
}

```

### writePdbStatus

```go
func (dc *DisruptionController) writePdbStatus(ctx context.Context, pdb *policy.PodDisruptionBudget) error {
	// 更新pdb
	_, err := dc.kubeClient.PolicyV1().PodDisruptionBudgets(pdb.Namespace).UpdateStatus(ctx, pdb, metav1.UpdateOptions{})
	return err
}
```

## Run

```go
func (dc *DisruptionController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	// Start events processing pipeline.
	if dc.kubeClient != nil {
		klog.Infof("Sending events to api server.")
		dc.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: dc.kubeClient.CoreV1().Events("")})
	} else {
		klog.Infof("No api server defined - no events will be sent to API server.")
	}
	defer dc.broadcaster.Shutdown()

	defer dc.queue.ShutDown()
	defer dc.recheckQueue.ShutDown()
	defer dc.stalePodDisruptionQueue.ShutDown()

	klog.Infof("Starting disruption controller")
	defer klog.Infof("Shutting down disruption controller")
	
    // 等待所有informer同步lister完成
	if !cache.WaitForNamedCacheSync("disruption", ctx.Done(), dc.podListerSynced, dc.pdbListerSynced, dc.rcListerSynced, dc.rsListerSynced, dc.dListerSynced, dc.ssListerSynced) {
		return
	}
	
    // 启动三个worker
	go wait.UntilWithContext(ctx, dc.worker, time.Second)
	go wait.Until(dc.recheckWorker, time.Second, ctx.Done())
	go wait.UntilWithContext(ctx, dc.stalePodDisruptionWorker, time.Second)

	<-ctx.Done()
}
```

## worker

```GO
func (dc *DisruptionController) worker(ctx context.Context) {
	for dc.processNextWorkItem(ctx) {
	}
}

func (dc *DisruptionController) processNextWorkItem(ctx context.Context) bool {
	dKey, quit := dc.queue.Get()
	if quit {
		return false
	}
	defer dc.queue.Done(dKey)
	// 同步
	err := dc.sync(ctx, dKey.(string))
	if err == nil {
		dc.queue.Forget(dKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Error syncing PodDisruptionBudget %v, requeuing: %v", dKey.(string), err))
    // 如果失败了 加入队列重试
	dc.queue.AddRateLimited(dKey)

	return true
}
```

#### sync

```go
func (dc *DisruptionController) sync(ctx context.Context, key string) error {
	startTime := dc.clock.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing PodDisruptionBudget %q (%v)", key, dc.clock.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	pdb, err := dc.pdbLister.PodDisruptionBudgets(namespace).Get(name)
	if errors.IsNotFound(err) {
		klog.V(4).Infof("PodDisruptionBudget %q has been deleted", key)
		return nil
	}
	if err != nil {
		return err
	}

	err = dc.trySync(ctx, pdb)
	// If the reason for failure was a conflict, then allow this PDB update to be
	// requeued without triggering the failSafe logic.
	if errors.IsConflict(err) {
		return err
	}
	if err != nil {
		klog.Errorf("Failed to sync pdb %s/%s: %v", pdb.Namespace, pdb.Name, err)
		return dc.failSafe(ctx, pdb, err)
	}

	return nil
}
```

#### trySync

```go
func (dc *DisruptionController) trySync(ctx context.Context, pdb *policy.PodDisruptionBudget) error {
	// 获取pdb的pod
    pods, err := dc.getPodsForPdb(pdb)
	if err != nil {
        // 如果出错了 生成一个警告级别的事件，以指示失败的原因
		dc.recorder.Eventf(pdb, v1.EventTypeWarning, "NoPods", "Failed to get pods: %v", err)
		return err
	}
    // Pod 数组为空，生成一个正常级别的事件，以指示未找到任何匹配的 Pod
	if len(pods) == 0 {
		dc.recorder.Eventf(pdb, v1.EventTypeNormal, "NoPods", "No matching pods found")
	}
	
    // 计算期望的 Pod 数目、希望保持健康的 Pod 数目、未受管理的 Pod 数组以及任何错误。
	expectedCount, desiredHealthy, unmanagedPods, err := dc.getExpectedPodCount(ctx, pdb, pods)
	if err != nil {
		dc.recorder.Eventf(pdb, v1.EventTypeWarning, "CalculateExpectedPodCountFailed", "Failed to calculate the number of expected pods: %v", err)
		return err
	}
	// 如果未受管理的 Pod 数组不为空，则记录警告级别的消息，指出与该 PodDisruptionBudget 相关联的一组 Pod 是未受管理的，并提供建议以解决此问题
	if len(unmanagedPods) > 0 {
		klog.Warningf("found unmanaged pods associated with this PDB: %v", unmanagedPods)
		dc.recorder.Eventf(pdb, v1.EventTypeWarning, "UnmanagedPods", "Pods selected by this PodDisruptionBudget (selector: %v) were found "+
			"to be unmanaged. As a result, the status of the PDB cannot be calculated correctly, which may result in undefined behavior. "+
			"To account for these pods please set \".spec.minAvailable\" "+
			"field of the PDB to an integer value.", pdb.Spec.Selector)
	}

	currentTime := dc.clock.Now()
    // 计算被干扰的 Pod 列表及重试时间
	disruptedPods, recheckTime := dc.buildDisruptedPodMap(pods, pdb, currentTime)
    // 计算当前健康的 Pod 数量
	currentHealthy := countHealthyPods(pods, disruptedPods, currentTime)
    // 更新 PDB 的状态
	err = dc.updatePdbStatus(ctx, pdb, currentHealthy, desiredHealthy, expectedCount, disruptedPods)

	if err == nil && recheckTime != nil {
		// 如果更新成功且 recheckTime 不为空，则将 PDB 添加到重试队列中以进行重新检查
		dc.enqueuePdbForRecheck(pdb, recheckTime.Sub(currentTime))
	}
	return err
}
```

##### getPodsForPdb

```GO
// 获取pdb相关的pod
func (dc *DisruptionController) getPodsForPdb(pdb *policy.PodDisruptionBudget) ([]*v1.Pod, error) {
	sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil {
		return []*v1.Pod{}, err
	}
	pods, err := dc.podLister.Pods(pdb.Namespace).List(sel)
	if err != nil {
		return []*v1.Pod{}, err
	}
	return pods, nil
}
```

##### getExpectedPodCount

```GO
func (dc *DisruptionController) getExpectedPodCount(ctx context.Context, pdb *policy.PodDisruptionBudget, pods []*v1.Pod) (expectedCount, desiredHealthy int32, unmanagedPods []string, err error) {
	err = nil
	
    // 如果定义了MaxUnavailable
	if pdb.Spec.MaxUnavailable != nil {
        // 获取期望的pods数量和未经管理的pods的列表
		expectedCount, unmanagedPods, err = dc.getExpectedScale(ctx, pdb, pods)
		if err != nil {
			return
		}
        // 计算最大不可用Pods的数量
		var maxUnavailable int
		maxUnavailable, err = intstr.GetScaledValueFromIntOrPercent(pdb.Spec.MaxUnavailable, int(expectedCount), true)
		if err != nil {
			return
		}
        // 计算期望的健康Pods数量
		desiredHealthy = expectedCount - int32(maxUnavailable)
		if desiredHealthy < 0 {
			desiredHealthy = 0
		}
	} else if pdb.Spec.MinAvailable != nil {
        // 如果定义了MinAvailable
		if pdb.Spec.MinAvailable.Type == intstr.Int {
            // 如果MinAvailable是整数
			desiredHealthy = pdb.Spec.MinAvailable.IntVal
			expectedCount = int32(len(pods))
		} else if pdb.Spec.MinAvailable.Type == intstr.String {
            // 如果MinAvailable是字符串类型
			// 获取期望的pods数量和未经管理的pods的列表
			expectedCount, unmanagedPods, err = dc.getExpectedScale(ctx, pdb, pods)
			if err != nil {
				return
			}
			// 计算最小可用Pods的数量
			var minAvailable int
			minAvailable, err = intstr.GetScaledValueFromIntOrPercent(pdb.Spec.MinAvailable, int(expectedCount), true)
			if err != nil {
				return
			}
            // 计算期望的健康Pods数量
			desiredHealthy = int32(minAvailable)
		}
	}
	return
}
```

###### getExpectedScale

```go
func (dc *DisruptionController) getExpectedScale(ctx context.Context, pdb *policy.PodDisruptionBudget, pods []*v1.Pod) (expectedCount int32, unmanagedPods []string, err error) {
	
	controllerScale := map[types.UID]int32{}
    // 找到每个 Pod 的控制器。如果该 Pod 不受控制器控制，则将其加入未受控制 Pod 的列表中
	for _, pod := range pods {
		controllerRef := metav1.GetControllerOf(pod)
		if controllerRef == nil {
			unmanagedPods = append(unmanagedPods, pod.Name)
			continue
		}

		// 如果我们已经知道控制器的Scale，则无需执行任何操作
		if _, found := controllerScale[controllerRef.UID]; found {
			continue
		}

		// 检查所有支持的控制器以查找所需的Scale
		foundController := false
		for _, finder := range dc.finders() {
			var controllerNScale *controllerAndScale
			controllerNScale, err = finder(ctx, controllerRef, pod.Namespace)
			if err != nil {
				return
			}
			if controllerNScale != nil {
				controllerScale[controllerNScale.UID] = controllerNScale.scale
				foundController = true
				break
			}
		}
		if !foundController {
			err = fmt.Errorf("found no controllers for pod %q", pod.Name)
			return
		}
	}

	// 计算所有控制器的总数
	expectedCount = 0
	for _, count := range controllerScale {
		expectedCount += count
	}

	return
}
```

###### finders

```GO
func (dc *DisruptionController) finders() []podControllerFinder {
	return []podControllerFinder{dc.getPodReplicationController, dc.getPodDeployment, dc.getPodReplicaSet,
		dc.getPodStatefulSet, dc.getScaleController}
}

var (
	controllerKindRS  = v1beta1.SchemeGroupVersion.WithKind("ReplicaSet")
	controllerKindSS  = apps.SchemeGroupVersion.WithKind("StatefulSet")
	controllerKindRC  = v1.SchemeGroupVersion.WithKind("ReplicationController")
	controllerKindDep = v1beta1.SchemeGroupVersion.WithKind("Deployment")
)

type controllerAndScale struct {
	types.UID
	scale int32
}

func (dc *DisruptionController) getPodReplicationController(ctx context.Context, controllerRef *metav1.OwnerReference, namespace string) (*controllerAndScale, error) {
	ok, err := verifyGroupKind(controllerRef, controllerKindRC.Kind, []string{""})
	if !ok || err != nil {
		return nil, err
	}
	rc, err := dc.rcLister.ReplicationControllers(namespace).Get(controllerRef.Name)
	if err != nil {
		// The only possible error is NotFound, which is ok here.
		return nil, nil
	}
	if rc.UID != controllerRef.UID {
		return nil, nil
	}
	return &controllerAndScale{rc.UID, *(rc.Spec.Replicas)}, nil
}

func (dc *DisruptionController) getPodDeployment(ctx context.Context, controllerRef *metav1.OwnerReference, namespace string) (*controllerAndScale, error) {
	ok, err := verifyGroupKind(controllerRef, controllerKindRS.Kind, []string{"apps", "extensions"})
	if !ok || err != nil {
		return nil, err
	}
	rs, err := dc.rsLister.ReplicaSets(namespace).Get(controllerRef.Name)
	if err != nil {
		// The only possible error is NotFound, which is ok here.
		return nil, nil
	}
	if rs.UID != controllerRef.UID {
		return nil, nil
	}
	controllerRef = metav1.GetControllerOf(rs)
	if controllerRef == nil {
		return nil, nil
	}

	ok, err = verifyGroupKind(controllerRef, controllerKindDep.Kind, []string{"apps", "extensions"})
	if !ok || err != nil {
		return nil, err
	}
	deployment, err := dc.dLister.Deployments(rs.Namespace).Get(controllerRef.Name)
	if err != nil {
		// The only possible error is NotFound, which is ok here.
		return nil, nil
	}
	if deployment.UID != controllerRef.UID {
		return nil, nil
	}
	return &controllerAndScale{deployment.UID, *(deployment.Spec.Replicas)}, nil
}

func (dc *DisruptionController) getPodReplicaSet(ctx context.Context, controllerRef *metav1.OwnerReference, namespace string) (*controllerAndScale, error) {
	ok, err := verifyGroupKind(controllerRef, controllerKindRS.Kind, []string{"apps", "extensions"})
	if !ok || err != nil {
		return nil, err
	}
	rs, err := dc.rsLister.ReplicaSets(namespace).Get(controllerRef.Name)
	if err != nil {
		// The only possible error is NotFound, which is ok here.
		return nil, nil
	}
	if rs.UID != controllerRef.UID {
		return nil, nil
	}
	controllerRef = metav1.GetControllerOf(rs)
	if controllerRef != nil && controllerRef.Kind == controllerKindDep.Kind {
		// Skip RS if it's controlled by a Deployment.
		return nil, nil
	}
	return &controllerAndScale{rs.UID, *(rs.Spec.Replicas)}, nil
}

func (dc *DisruptionController) getPodStatefulSet(ctx context.Context, controllerRef *metav1.OwnerReference, namespace string) (*controllerAndScale, error) {
	ok, err := verifyGroupKind(controllerRef, controllerKindSS.Kind, []string{"apps"})
	if !ok || err != nil {
		return nil, err
	}
	ss, err := dc.ssLister.StatefulSets(namespace).Get(controllerRef.Name)
	if err != nil {
		// The only possible error is NotFound, which is ok here.
		return nil, nil
	}
	if ss.UID != controllerRef.UID {
		return nil, nil
	}

	return &controllerAndScale{ss.UID, *(ss.Spec.Replicas)}, nil
}

func (dc *DisruptionController) getScaleController(ctx context.Context, controllerRef *metav1.OwnerReference, namespace string) (*controllerAndScale, error) {
	gv, err := schema.ParseGroupVersion(controllerRef.APIVersion)
	if err != nil {
		return nil, err
	}

	gk := schema.GroupKind{
		Group: gv.Group,
		Kind:  controllerRef.Kind,
	}

	mapping, err := dc.mapper.RESTMapping(gk, gv.Version)
	if err != nil {
		return nil, err
	}
	gr := mapping.Resource.GroupResource()
	scale, err := dc.scaleNamespacer.Scales(namespace).Get(ctx, gr, controllerRef.Name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// The IsNotFound error can mean either that the resource does not exist,
			// or it exist but doesn't implement the scale subresource. We check which
			// situation we are facing so we can give an appropriate error message.
			isScale, err := dc.implementsScale(mapping.Resource)
			if err != nil {
				return nil, err
			}
			if !isScale {
				return nil, fmt.Errorf("%s does not implement the scale subresource", gr.String())
			}
			return nil, nil
		}
		return nil, err
	}
	if scale.UID != controllerRef.UID {
		return nil, nil
	}
	return &controllerAndScale{scale.UID, scale.Spec.Replicas}, nil
}


func verifyGroupKind(controllerRef *metav1.OwnerReference, expectedKind string, expectedGroups []string) (bool, error) {
	gv, err := schema.ParseGroupVersion(controllerRef.APIVersion)
	if err != nil {
		return false, err
	}

	if controllerRef.Kind != expectedKind {
		return false, nil
	}

	for _, group := range expectedGroups {
		if group == gv.Group {
			return true, nil
		}
	}

	return false, nil
}
```

##### buildDisruptedPodMap

```GO
func (dc *DisruptionController) buildDisruptedPodMap(pods []*v1.Pod, pdb *policy.PodDisruptionBudget, currentTime time.Time) (map[string]metav1.Time, *time.Time) {
    // 表示在该 PDB 对象中被认为是受到 干扰  的 Pod
	disruptedPods := pdb.Status.DisruptedPods
    // 存储受到 干扰 的 Pod 名称和时间戳
	result := make(map[string]metav1.Time)
	var recheckTime *time.Time

	if disruptedPods == nil {
		return result, recheckTime
	}
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			// 已经在被删除，直接跳过
			continue
		}
		disruptionTime, found := disruptedPods[pod.Name]
		if !found {
			// 没有收到干扰 直接跳过
			continue
		}
        // 预期删除时间 expectedDeletion
		expectedDeletion := disruptionTime.Time.Add(DeletionTimeout)
		if expectedDeletion.Before(currentTime) {
            // 如果它的预期删除时间早于当前时间 则认为该 Pod 没有被删除，
			klog.V(1).Infof("Pod %s/%s was expected to be deleted at %s but it wasn't, updating pdb %s/%s",
				pod.Namespace, pod.Name, disruptionTime.String(), pdb.Namespace, pdb.Name)
			dc.recorder.Eventf(pod, v1.EventTypeWarning, "NotDeleted", "Pod was expected by PDB %s/%s to be deleted but it wasn't",
				pdb.Namespace, pdb.Namespace)
		} else {
            // 否则将 Pod 加入结果map中，并更新检查时间。
			if recheckTime == nil || expectedDeletion.Before(*recheckTime) {
				recheckTime = &expectedDeletion
			}
			result[pod.Name] = disruptionTime
		}
	}
	return result, recheckTime
}


const DeletionTimeout = 2 * time.Minute
```

##### countHealthyPods

```GO
func countHealthyPods(pods []*v1.Pod, disruptedPods map[string]metav1.Time, currentTime time.Time) (currentHealthy int32) {
	for _, pod := range pods {
		// 如果 Pod 已经被标记为删除 跳过
		if pod.DeletionTimestamp != nil {
			continue
		}
		// 如果 disruptedPods map 中存在该 Pod 的名称，并且该 Pod 的预期删除时间还未到，则也跳过该 Pod.
		if disruptionTime, found := disruptedPods[pod.Name]; found && disruptionTime.Time.Add(DeletionTimeout).After(currentTime) {
			continue
		}
        // health +1
		if apipod.IsPodReady(pod) {
			currentHealthy++
		}
	}

	return
}
```

##### updatePdbStatus

```GO
func (dc *DisruptionController) updatePdbStatus(ctx context.Context, pdb *policy.PodDisruptionBudget, currentHealthy, desiredHealthy, expectedCount int32,
	disruptedPods map[string]metav1.Time) error {

	// 如果 expectedCount 不大于0，或者 disrupitonsAllowed 不大于0，则需要将 disrupitonsAllowed 设置为0。
	disruptionsAllowed := currentHealthy - desiredHealthy
	if expectedCount <= 0 || disruptionsAllowed <= 0 {
		disruptionsAllowed = 0
	}
	
    // // 如果 PodDisruptionBudget 的状态没有发生改变，则直接返回。
	if pdb.Status.CurrentHealthy == currentHealthy &&
		pdb.Status.DesiredHealthy == desiredHealthy &&
		pdb.Status.ExpectedPods == expectedCount &&
		pdb.Status.DisruptionsAllowed == disruptionsAllowed &&
		apiequality.Semantic.DeepEqual(pdb.Status.DisruptedPods, disruptedPods) &&
		pdb.Status.ObservedGeneration == pdb.Generation &&
		pdbhelper.ConditionsAreUpToDate(pdb) {
		return nil
	}
	
    // 深度拷贝 PodDisruptionBudget，修改它的状态，更新条件，并将其更新回 API 服务器。
	newPdb := pdb.DeepCopy()
	newPdb.Status = policy.PodDisruptionBudgetStatus{
		CurrentHealthy:     currentHealthy,
		DesiredHealthy:     desiredHealthy,
		ExpectedPods:       expectedCount,
		DisruptionsAllowed: disruptionsAllowed,
		DisruptedPods:      disruptedPods,
		ObservedGeneration: pdb.Generation,
	}
	
    // 更新pdb status
	pdbhelper.UpdateDisruptionAllowedCondition(newPdb)
	
    // 更新pdb
	return dc.getUpdater()(ctx, newPdb)
}
```

##### enqueuePdbForRecheck

```GO
// 延迟deplay秒加入recheckQueue队列
func (dc *DisruptionController) enqueuePdbForRecheck(pdb *policy.PodDisruptionBudget, delay time.Duration) {
	key, err := controller.KeyFunc(pdb)
	if err != nil {
		klog.Errorf("Couldn't get key for PodDisruptionBudget object %+v: %v", pdb, err)
		return
	}
	dc.recheckQueue.AddAfter(key, delay)
}
```

## recheckWorker

```go
// 延迟加入queue队列处理
func (dc *DisruptionController) recheckWorker() {
	for dc.processNextRecheckWorkItem() {
	}
}

func (dc *DisruptionController) processNextRecheckWorkItem() bool {
	dKey, quit := dc.recheckQueue.Get()
	if quit {
		return false
	}
	defer dc.recheckQueue.Done(dKey)
	dc.queue.AddRateLimited(dKey)
	return true
}
```

## stalePodDisruptionWorker

```go
func (dc *DisruptionController) stalePodDisruptionWorker(ctx context.Context) {
	for dc.processNextStalePodDisruptionWorkItem(ctx) {
	}
}

func (dc *DisruptionController) processNextStalePodDisruptionWorkItem(ctx context.Context) bool {
	key, quit := dc.stalePodDisruptionQueue.Get()
	if quit {
		return false
	}
	defer dc.stalePodDisruptionQueue.Done(key)
	err := dc.syncStalePodDisruption(ctx, key.(string))
	if err == nil {
		dc.stalePodDisruptionQueue.Forget(key)
		return true
	}
	utilruntime.HandleError(fmt.Errorf("error syncing Pod %v to clear DisruptionTarget condition, requeueing: %v", key.(string), err))
	dc.stalePodDisruptionQueue.AddRateLimited(key)
	return true
}
```

### syncStalePodDisruption

```go
func (dc *DisruptionController) syncStalePodDisruption(ctx context.Context, key string) error {
	startTime := dc.clock.Now()
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	defer func() {
		klog.V(4).InfoS("Finished syncing Pod to clear DisruptionTarget condition", "pod", klog.KRef(namespace, name), "duration", dc.clock.Since(startTime))
	}()
	pod, err := dc.podLister.Pods(namespace).Get(name)
	if errors.IsNotFound(err) {
        // 如果找不到 pod，则忽略
		klog.V(4).InfoS("Skipping clearing DisruptionTarget condition because pod was deleted", "pod", klog.KObj(pod))
		return nil
	}
	if err != nil {
		return err
	}
	
    // 判断 pod 是否有 stale DisruptionTarget condition
	hasCond, cleanAfter := dc.nonTerminatingPodHasStaleDisruptionCondition(pod)
	if !hasCond {
		return nil
	}
	if cleanAfter > 0 {
        // 如果 cleanAfter 大于 0，则延迟处理清除操作
		dc.enqueueStalePodDisruptionCleanup(pod, cleanAfter)
		return nil
	}
	
    // 构造 Pod 对象的 apply 版本，将 DisruptionTarget condition 置为 False
	podApply := corev1apply.Pod(pod.Name, pod.Namespace).
		WithStatus(corev1apply.PodStatus()).
		WithResourceVersion(pod.ResourceVersion)
	podApply.Status.WithConditions(corev1apply.PodCondition().
		WithType(v1.DisruptionTarget).
		WithStatus(v1.ConditionFalse).
		WithLastTransitionTime(metav1.Now()),
	)
	
    // 应用修改到 API Server
	if _, err := dc.kubeClient.CoreV1().Pods(pod.Namespace).ApplyStatus(ctx, podApply, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
		return err
	}
	klog.V(2).InfoS("Reset stale DisruptionTarget condition to False", "pod", klog.KObj(pod))
	return nil
}
```

