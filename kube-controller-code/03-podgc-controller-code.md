
## 简介

`podgc-controller`是Kubernetes中的一种控制器（controller），它的作用是根据一些规则，定期清理（删除）不再需要的Pod对象。Pod对象是Kubernetes中最基本的资源单位，它代表一个或多个容器（container）的运行环境。Pod对象一旦被创建，就会一直存在，除非被删除或者Kubernetes集群本身被关闭。

在某些情况下，Pod对象可能会因为各种原因（例如节点（node）故障、调度策略变化等）而变得不再需要，但是它们仍然会占用集群中的资源。为了避免这种资源浪费，可以使用`podgc-controller`来定期清理这些无用的Pod对象。`podgc-controller`会根据一些配置参数（例如过期时间、标签等）来判断哪些Pod需要被删除，并执行相应的操作。

需要注意的是，`podgc-controller`只会清理由它自己创建的Pod对象。如果某个Pod是手动创建的，那么它将不会被`podgc-controller`清理。此外，`podgc-controller`也不会影响处于运行中的Pod对象。

## 结构体

```go
type PodGCController struct {
  // client-go clientset接口 用来和apiserver交互
	kubeClient clientset.Interface
	
  // pod的Lister
	podLister        corelisters.PodLister
  // pod lister是否同步完毕
	podListerSynced  cache.InformerSynced
  // node的Lister
	nodeLister       corelisters.NodeLister
  // node lister是否同步完毕
	nodeListerSynced cache.InformerSynced
	
  // 工作队列，用于保存需要清理的node对象。
	nodeQueue workqueue.DelayingInterface
	
  // 表示一个节点上处于终止状态的Pod对象数量超过这个阈值时，该节点才会被加入清理队列。
  // 这个阈值的设置可以防止在某个节点上短时间内频繁创建和删除Pod对象，从而减少清理队列的负担。
	terminatedPodThreshold int
  // 定期检查节点是否需要清理的时间间隔。在每个时间间隔内，PodGCController会检查集群中所有的节点，
  // 判断是否需要将节点加入清理队列。
	gcCheckPeriod          time.Duration
  // 表示一个节点对象从加入清理队列到被真正清理的时间间隔
	quarantineTime         time.Duration
}
```

## init

init为注册一个用于监控 Kubernetes Pod 垃圾回收控制器（Pod GC Controller）性能的指标。具体来说，它使用 Prometheus Go 客户端库来定义两个计数器指标，分别是“force_delete_pods_total”（强制删除 Pod 的数量）和“force_delete_pod_errors_total”（强制删除 Pod 时出错的数量）。这些指标会被注册到 Prometheus 的默认注册表中，以便 Prometheus 可以从该注册表中拉取指标数据，并对其进行存储和查询。

```GO
func init() {
	// Register prometheus metrics
	RegisterMetrics()
}

// RegisterMetrics函数
const (
	podGCController = "pod_gc_collector"
)

var (
	deletingPodsTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      podGCController,
			Name:           "force_delete_pods_total",
			Help:           "Number of pods that are being forcefully deleted since the Pod GC Controller started.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{},
	)
	deletingPodsErrorTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      podGCController,
			Name:           "force_delete_pod_errors_total",
			Help:           "Number of errors encountered when forcefully deleting the pods since the Pod GC Controller started.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{},
	)
)

var registerMetrics sync.Once

// Register the metrics that are to be monitored.
func RegisterMetrics() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(deletingPodsTotal)
		legacyregistry.MustRegister(deletingPodsErrorTotal)
	})
}
```

## New

创建一个 `*PodGC` 结构体

```go
func NewPodGC(ctx context.Context, kubeClient clientset.Interface, podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer, terminatedPodThreshold int) *PodGCController {
	return NewPodGCInternal(ctx, kubeClient, podInformer, nodeInformer, terminatedPodThreshold, gcCheckPeriod, quarantineTime)
}

// This function is only intended for integration tests
func NewPodGCInternal(ctx context.Context, kubeClient clientset.Interface, podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer, terminatedPodThreshold int, gcCheckPeriod, quarantineTime time.Duration) *PodGCController {
	gcc := &PodGCController{
		kubeClient:             kubeClient,
		terminatedPodThreshold: terminatedPodThreshold,
		podLister:              podInformer.Lister(),
		podListerSynced:        podInformer.Informer().HasSynced,
		nodeLister:             nodeInformer.Lister(),
		nodeListerSynced:       nodeInformer.Informer().HasSynced,
		nodeQueue:              workqueue.NewNamedDelayingQueue("orphaned_pods_nodes"),
		gcCheckPeriod:          gcCheckPeriod,
		quarantineTime:         quarantineTime,
	}

	return gcc
}
```

## Run

```go
func (gcc *PodGCController) Run(ctx context.Context) {
  // 处理panic 当程序 panic 时，它会打印 panic 的堆栈信息，并将 panic 的信息发送到标准错误输出
	defer utilruntime.HandleCrash()

	klog.Infof("Starting GC controller")
  // 关闭队列
	defer gcc.nodeQueue.ShutDown()
	defer klog.Infof("Shutting down GC controller")
	
  // 等待podLister和nodeLister同步完成
	if !cache.WaitForNamedCacheSync("GC", ctx.Done(), gcc.podListerSynced, gcc.nodeListerSynced) {
		return
	}
	
  // 开启worker
	go wait.UntilWithContext(ctx, gcc.gc, gcc.gcCheckPeriod)

	<-ctx.Done()
}
```

## gc

- gcTerminated 取出不是 PodPending，PodRunning，PodUnknown的状态 如果大于terminatedPodThreshold了 杀死一些 剩下terminatedPodThreshold个默认是不开启的 也就是terminatedPodThreshold=0
- gcTerminating 回收Terminating状态的pod 默认是开启的
- gcOrphaned 删除孤儿pod 也就是没有node的pod
- gcUnscheduledTerminating 回收处于 `Unschedulable` 且正在被终止（`Terminating`）状态的 Pod

```go
func (gcc *PodGCController) gc(ctx context.Context) {
    // 从 PodLister 中列出所有的 Pod：
	pods, err := gcc.podLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("Error while listing all pods: %v", err)
		return
	}
    // 从 NodeLister 中列出所有的 Node
	nodes, err := gcc.nodeLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("Error while listing all nodes: %v", err)
		return
	}
    // 如果设置了终止 Pod 阈值（terminatedPodThreshold > 0），则调用 gcTerminated 方法回收已终止的 Pod
	if gcc.terminatedPodThreshold > 0 {
		gcc.gcTerminated(ctx, pods)
	}
    // 如果启用了 NodeOutOfServiceVolumeDetach 特性，则调用 gcTerminating 方法回收处于 Terminating 状态的 Pod
    // 启用该特性后，当节点被标记为不可用时，kubelet将会将该节点上的本地卷和静态卷挂载点进行解除挂载。
	// 这样可以防止本地卷和静态卷上的数据丢失
	if utilfeature.DefaultFeatureGate.Enabled(features.NodeOutOfServiceVolumeDetach) {
		gcc.gcTerminating(ctx, pods)
	}
    // 调用 gcOrphaned 方法回收孤立的 Pod
	gcc.gcOrphaned(ctx, pods, nodes)
    // 调用 gcUnscheduledTerminating 方法回收处于 UnscheduledTerminating 状态的 Pod
	gcc.gcUnscheduledTerminating(ctx, pods)
}
```

### gcTerminated

这个是阻止每个node上出现一些奇奇怪怪的问题，这样的pod特别多，指定数量，剩下杀死。默认是不开启的。

```GO
func (gcc *PodGCController) gcTerminated(ctx context.Context, pods []*v1.Pod) {
    // 遍历所有 Pod，将 Terminated 状态的 Pod 放入 terminatedPods 数组中
	terminatedPods := []*v1.Pod{}
	for _, pod := range pods {
		if isPodTerminated(pod) {
			terminatedPods = append(terminatedPods, pod)
		}
	}

	terminatedPodCount := len(terminatedPods)
    // 计算需要删除的 Pod 数量
	deleteCount := terminatedPodCount - gcc.terminatedPodThreshold

    // 小于等于0 代表不用清理 直接退出
	if deleteCount <= 0 {
		return
	}

	klog.InfoS("Garbage collecting pods", "numPods", deleteCount)
	// 对terminated的Pod按照创建时间进行排序 byCreationTimestamp在下方
	sort.Sort(byCreationTimestamp(terminatedPods))
	var wait sync.WaitGroup
	for i := 0; i < deleteCount; i++ {
		wait.Add(1)
		go func(pod *v1.Pod) {
			defer wait.Done()
			if err := gcc.markFailedAndDeletePod(ctx, pod); err != nil {
				// 在删除Pod的过程中，如果出现错误则忽略并记录日志
				defer utilruntime.HandleError(err)
			}
		}(terminatedPods[i])
	}
	wait.Wait()
}
```

```go
// pod的status 不是 PodPending，PodRunning，PodUnknown 就是Terminated 状态
func isPodTerminated(pod *v1.Pod) bool {
	if phase := pod.Status.Phase; phase != v1.PodPending && phase != v1.PodRunning && phase != v1.PodUnknown {
		return true
	}
	return false
}

type byCreationTimestamp []*v1.Pod

func (o byCreationTimestamp) Len() int      { return len(o) }
func (o byCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }

func (o byCreationTimestamp) Less(i, j int) bool {
	if o[i].CreationTimestamp.Equal(&o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(&o[j].CreationTimestamp)
}
```

**markFailedAndDeletePod**

```go
func (gcc *PodGCController) markFailedAndDeletePod(ctx context.Context, pod *v1.Pod) error {
	return gcc.markFailedAndDeletePodWithCondition(ctx, pod, nil)
}
func (gcc *PodGCController) markFailedAndDeletePodWithCondition(ctx context.Context, pod *v1.Pod, condition *corev1apply.PodConditionApplyConfiguration) error {
	klog.InfoS("PodGC is force deleting Pod", "pod", klog.KRef(pod.Namespace, pod.Name))
    // 通过特性门限检查，判断是否开启了 PodDisruptionConditions 特性
    // 如果开启了 PodDisruptionConditions，当 Pod 被删除时，会设置 Pod 的 disruption 状态，
    // 用于保证应用无缝地从一个节点转移到另一个节点。
	if utilfeature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
        // 判断当前 Pod 的状态是否是 Succeeded 或 Failed，如果不是，其状态为 Failed。
		if pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed {
			podApply := corev1apply.Pod(pod.Name, pod.Namespace).WithStatus(corev1apply.PodStatus())
			podApply.Status.WithPhase(v1.PodFailed)
			if condition != nil {
				podApply.Status.WithConditions(condition)
			}
			if _, err := gcc.kubeClient.CoreV1().Pods(pod.Namespace).ApplyStatus(ctx, podApply, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
				return err
			}
		}
	}
    // 删除pod
	return gcc.kubeClient.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, *metav1.NewDeleteOptions(0))
}

```

### gcTerminating

```go
func (gcc *PodGCController) gcTerminating(ctx context.Context, pods []*v1.Pod) {
	klog.V(4).Info("GC'ing terminating pods that are on out-of-service nodes")
	terminatingPods := []*v1.Pod{}
    // 便利所有的pod
	for _, pod := range pods {
        // 如果是Terminating状态
		if isPodTerminating(pod) {
            // 获取node上对应的pod
			node, err := gcc.nodeLister.Get(pod.Spec.NodeName)
			if err != nil {
				klog.Errorf("failed to get node %s : %s", pod.Spec.NodeName, err)
				continue
			}
			// 节点不可用状态 也就是节点不ready并且并打TaintNodeOutOfService污点了 加入数据
			if !nodeutil.IsNodeReady(node) && taints.TaintKeyExists(node.Spec.Taints, v1.TaintNodeOutOfService) {
				klog.V(4).Infof("garbage collecting pod %s that is terminating. Phase [%v]", pod.Name, pod.Status.Phase)
				terminatingPods = append(terminatingPods, pod)
			}
		}
	}

	deleteCount := len(terminatingPods)
    // 等于0 代表没有要处理的 返回
	if deleteCount == 0 {
		return
	}

	klog.V(4).Infof("Garbage collecting %v pods that are terminating on node tainted with node.kubernetes.io/out-of-service", deleteCount)
	// 使用时间排序
	sort.Sort(byCreationTimestamp(terminatingPods))
	var wait sync.WaitGroup
	for i := 0; i < deleteCount; i++ {
		wait.Add(1)
		go func(pod *v1.Pod) {
			defer wait.Done()
            // 使用prometheus来记录删除pod的次数，它会为deletingPodsTotal这个label值的指标增加1。
            // 具体来说，这个指标表示在某个时间段内删除pod的总数。
			deletingPodsTotal.WithLabelValues().Inc()
            // 清除pod markFailedAndDeletePod逻辑上边有
			if err := gcc.markFailedAndDeletePod(ctx, pod); err != nil {
				// 忽略错误
				utilruntime.HandleError(err)
                // 强制删除的加1
				deletingPodsErrorTotal.WithLabelValues().Inc()
			}
		}(terminatingPods[i])
	}
	wait.Wait()
}

```

```go
// pod是Terminating状态 也就是被标记删除了
func isPodTerminating(pod *v1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

// 节点的conditions有不是reading
func IsNodeReady(node *v1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == v1.NodeReady {
			return c.Status == v1.ConditionTrue
		}
	}
	return false
}

// 
TaintNodeOutOfService = "node.kubernetes.io/out-of-service"
func TaintKeyExists(taints []v1.Taint, taintKeyToMatch string) bool {
	for _, taint := range taints {
		if taint.Key == taintKeyToMatch {
			return true
		}
	}
	return false
}
```

### gcOrphaned

```GO
func (gcc *PodGCController) gcOrphaned(ctx context.Context, pods []*v1.Pod, nodes []*v1.Node) {
	klog.V(4).Infof("GC'ing orphaned")
    // set 其实是 map[string]struct{} go里 只能这么表示set 记录已存在的节点名称
	existingNodeNames := sets.NewString()
	for _, node := range nodes {
		existingNodeNames.Insert(node.Name)
	}
	// 如果有 Pod 分配给未知的节点，则添加该节点到隔离队列
	for _, pod := range pods {
		if pod.Spec.NodeName != "" && !existingNodeNames.Has(pod.Spec.NodeName) {
			gcc.nodeQueue.AddAfter(pod.Spec.NodeName, gcc.quarantineTime)
		}
	}
	// 检查隔离期过后是否仍有节点丢失
	deletedNodesNames, quit := gcc.discoverDeletedNodes(ctx, existingNodeNames)
	if quit {
		return
	}
	// 删除孤儿Pod
	for _, pod := range pods {
        // 要被删除的node里 没有这个pod的node 跳过
		if !deletedNodesNames.Has(pod.Spec.NodeName) {
			continue
		}
		klog.V(2).InfoS("Found orphaned Pod assigned to the Node, deleting.", "pod", klog.KObj(pod), "node", pod.Spec.NodeName)
		condition := corev1apply.PodCondition().
			WithType(v1.DisruptionTarget).
			WithStatus(v1.ConditionTrue).
			WithReason("DeletionByPodGC").
			WithMessage("PodGC: node no longer exists").
			WithLastTransitionTime(metav1.Now())
        // 标记并删除Pod
		if err := gcc.markFailedAndDeletePodWithCondition(ctx, pod, condition); err != nil {
			utilruntime.HandleError(err)
		} else {
			klog.InfoS("Forced deletion of orphaned Pod succeeded", "pod", klog.KObj(pod))
		}
	}
}
```

#### discoverDeletedNodes

```go
func (gcc *PodGCController) discoverDeletedNodes(ctx context.Context, existingNodeNames sets.String) (sets.String, bool) {
    // set
	deletedNodesNames := sets.NewString()
	for gcc.nodeQueue.Len() > 0 {
		item, quit := gcc.nodeQueue.Get()
        // 从nodeQueue中获取一个item 并检查是否应该退出循环
		if quit {
			return nil, true
		}
		nodeName := item.(string)
        // 检查existingNodeNames中是否包含nodeName 如果包含 就证明node存在 不用处理
		if !existingNodeNames.Has(nodeName) {
            // 检查node是不是存在
			exists, err := gcc.checkIfNodeExists(ctx, nodeName)
			switch {
			case err != nil:
				klog.ErrorS(err, "Error while getting node", "node", klog.KRef("", nodeName))
				// Node will be added back to the queue in the subsequent loop if still needed
			case !exists:
                // 如果不存在节点，则将nodeName添加到deletedNodesNames中
				deletedNodesNames.Insert(nodeName)
			}
		}
        // 使用nodeQueue的Done方法告诉队列已处理该item
		gcc.nodeQueue.Done(item)
	}
	return deletedNodesNames, false
}
```

### gcUnscheduledTerminating

```go
func (gcc *PodGCController) gcUnscheduledTerminating(ctx context.Context, pods []*v1.Pod) {
	klog.V(4).Infof("GC'ing unscheduled pods which are terminating.")

	for _, pod := range pods {
        // 如果Pod没有设置删除时间戳或者已经分配了节点，就跳过
		if pod.DeletionTimestamp == nil || len(pod.Spec.NodeName) > 0 {
			continue
		}

		klog.V(2).InfoS("Found unscheduled terminating Pod not assigned to any Node, deleting.", "pod", klog.KObj(pod))
        // 标记请删除pod
		if err := gcc.markFailedAndDeletePod(ctx, pod); err != nil {
			utilruntime.HandleError(err)
		} else {
			klog.InfoS("Forced deletion of unscheduled terminating Pod succeeded", "pod", klog.KObj(pod))
		}
	}
}
```

