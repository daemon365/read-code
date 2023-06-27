
## 简介

`TTL Controller` 的作用是根据集群大小动态向`node`对象的注释中（`metadata.annotations`）添加`node.alpha.kubernetes.io/ttl`，作用是一个调整参数，用于确定Kubelet可以缓存对象的时间。

## 结构体

```go
type Controller struct {
    // client-go clientset
	kubeClient clientset.Interface

	// node list
	nodeStore listers.NodeLister

	// 存储需要同步的节点列表
	queue workqueue.RateLimitingInterface

	// 检查lister是否同步完成
	hasSynced func() bool

	lock sync.RWMutex

	// 集群中节点的数量
	nodeCount int

	// 集群中所有节点的期望TTL
	desiredTTLSeconds int

	// 表示当前集群规模的区间
	boundaryStep int
}
```

## New

```go
func NewTTLController(nodeInformer informers.NodeInformer, kubeClient clientset.Interface) *Controller {
    ttlc := &Controller{
		kubeClient: kubeClient,
		queue:      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ttlcontroller"),
	}
	
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ttlc.addNode,
		UpdateFunc: ttlc.updateNode,
		DeleteFunc: ttlc.deleteNode,
	})

	ttlc.nodeStore = listers.NewNodeLister(nodeInformer.Informer().GetIndexer())
	ttlc.hasSynced = nodeInformer.Informer().HasSynced

	return ttlc
}
```

### Informer的操作

```go
func (ttlc *Controller) addNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}

	func() {
		ttlc.lock.Lock()
		defer ttlc.lock.Unlock()
        // 集群节点数加1
		ttlc.nodeCount++
        // 如果当前节点数超过了当前步长（boundaryStep）所对应的集群节点数的上限值（sizeMax）
		if ttlc.nodeCount > ttlBoundaries[ttlc.boundaryStep].sizeMax {
            // boundaryStep+1 并重新设置desiredTTLSeconds 
            // 永远不会越界 因为ttlBoundaries最后一个最大值是max
			ttlc.boundaryStep++
			ttlc.desiredTTLSeconds = ttlBoundaries[ttlc.boundaryStep].ttlSeconds
		}
	}()
    
	ttlc.enqueueNode(node)
}

// 是更新的话 直接加入queue
func (ttlc *Controller) updateNode(_, newObj interface{}) {
	node, ok := newObj.(*v1.Node)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	// Processing all updates of nodes guarantees that we will update
	// the ttl annotation, when cluster size changes.
	// We are relying on the fact that Kubelet is updating node status
	// every 10s (or generally every X seconds), which means that whenever
	// required, its ttl annotation should be updated within that period.
	ttlc.enqueueNode(node)
}

func (ttlc *Controller) deleteNode(obj interface{}) {
    // 转义Node 如果不行 试图转义DeletedFinalStateUnknown
	_, ok := obj.(*v1.Node)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
		_, ok = tombstone.Obj.(*v1.Node)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object types: %v", obj))
			return
		}
	}

	func() {
		ttlc.lock.Lock()
		defer ttlc.lock.Unlock()
        // node数减一
		ttlc.nodeCount--
        // 如果当前节点数超过了当前步长（boundaryStep）所对应的集群节点数的下限值（sizeMin）
		if ttlc.nodeCount < ttlBoundaries[ttlc.boundaryStep].sizeMin {
            // 重新设置desiredTTLSeconds 
			ttlc.boundaryStep--
			ttlc.desiredTTLSeconds = ttlBoundaries[ttlc.boundaryStep].ttlSeconds
		}
	}()
	// We are not processing the node, as it no longer exists.
}

type ttlBoundary struct {
	sizeMin    int
	sizeMax    int
	ttlSeconds int
}

var (
    // 0倒100个node ttlSeconds=0 90-500 ttl=15....
	ttlBoundaries = []ttlBoundary{
		{sizeMin: 0, sizeMax: 100, ttlSeconds: 0},
		{sizeMin: 90, sizeMax: 500, ttlSeconds: 15},
		{sizeMin: 450, sizeMax: 1000, ttlSeconds: 30},
		{sizeMin: 900, sizeMax: 2000, ttlSeconds: 60},
		{sizeMin: 1800, sizeMax: math.MaxInt32, ttlSeconds: 300},
	}
)
```

```go
// 拿出key 并加入queue
func (ttlc *Controller) enqueueNode(node *v1.Node) {
	key, err := controller.KeyFunc(node)
	if err != nil {
		klog.Errorf("Couldn't get key for object %+v", node)
		return
	}
	ttlc.queue.Add(key)
}
```

## Run

```go
func (ttlc *Controller) Run(ctx context.Context, workers int) {
    // 函数退出 处理panic 和关闭queue
	defer utilruntime.HandleCrash()
	defer ttlc.queue.ShutDown()

	klog.Infof("Starting TTL controller")
	defer klog.Infof("Shutting down TTL controller")
	
    // 等待list同步已完成
	if !cache.WaitForNamedCacheSync("TTL", ctx.Done(), ttlc.hasSynced) {
		return
	}
	
    // 开启workers个 goroutine处理worker
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, ttlc.worker, time.Second)
	}

	<-ctx.Done()
}
```

## worker

```go

func (ttlc *Controller) worker(ctx context.Context) {
    // 无限循环processItem 直到processItem返回false
	for ttlc.processItem(ctx) {
	}
}

func (ttlc *Controller) processItem(ctx context.Context) bool {
    // 从queue中拿key 没有了就返回false
	key, quit := ttlc.queue.Get()
	if quit {
		return false
	}
    // 函数结束Done掉key
	defer ttlc.queue.Done(key)

	err := ttlc.updateNodeIfNeeded(ctx, key.(string))
	if err == nil {
		ttlc.queue.Forget(key)
		return true
	}
	
    // 出问题了 再把key放回retry队列中
	ttlc.queue.AddRateLimited(key)
    // 记录错误日志
	utilruntime.HandleError(err)
    return true
}
```

### updateNodeIfNeeded

```go
// 判断该节点的 TTL 注释是否等于控制器当前期望的 TTL 值，如果不等，
// 则通过 API Server 提供的 patch 接口更新节点对象的 TTL 注释。
func (ttlc *Controller) updateNodeIfNeeded(ctx context.Context, key string) error {
    // 从lister获取node
	node, err := ttlc.nodeStore.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	
    // 获取期望ttl
	desiredTTL := ttlc.getDesiredTTLSeconds()
    // 并尝试从节点对象的 Annotation 中获取当前 TTL 值 currentTTL
	currentTTL, ok := getIntFromAnnotation(node, v1.ObjectTTLAnnotationKey)
    // 如果获取到了 而且和之前的期望值相等 不用处理
	if ok && currentTTL == desiredTTL {
		return nil
	}
	
    // 更新注释
	return ttlc.patchNodeWithAnnotation(ctx, node.DeepCopy(), v1.ObjectTTLAnnotationKey, desiredTTL)
}

const ObjectTTLAnnotationKey string = "node.alpha.kubernetes.io/ttl"
```

```go
func (ttlc *Controller) getDesiredTTLSeconds() int {
	ttlc.lock.RLock()
	defer ttlc.lock.RUnlock()
	return ttlc.desiredTTLSeconds
}
```

```GO
func getIntFromAnnotation(node *v1.Node, annotationKey string) (int, bool) {
	if node.Annotations == nil {
		return 0, false
	}
	annotationValue, ok := node.Annotations[annotationKey]
	if !ok {
		return 0, false
	}
	intValue, err := strconv.Atoi(annotationValue)
	if err != nil {
		klog.Warningf("Cannot convert the value %q with annotation key %q for the node %q",
			annotationValue, annotationKey, node.Name)
		return 0, false
	}
	return intValue, true
}
```

```GO
func (ttlc *Controller) patchNodeWithAnnotation(ctx context.Context, node *v1.Node, annotationKey string, value int) error {
	oldData, err := json.Marshal(node)
	if err != nil {
		return err
	}
    // 把注释设置进去
	setIntAnnotation(node, annotationKey, value)
	newData, err := json.Marshal(node)
	if err != nil {
		return err
	}
    // 创建两个对象之间patch的 就是差别的描述
	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, &v1.Node{})
	if err != nil {
		return err
	}
    // 更新对象
	_, err = ttlc.kubeClient.CoreV1().Nodes().Patch(ctx, node.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		klog.V(2).InfoS("Failed to change ttl annotation for node", "node", klog.KObj(node), "err", err)
		return err
	}
	klog.V(2).InfoS("Changed ttl annotation", "node", klog.KObj(node), "TTL", time.Duration(value)*time.Second)
	return nil
}

func setIntAnnotation(node *v1.Node, annotationKey string, value int) {
	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[annotationKey] = strconv.Itoa(value)
}
```

