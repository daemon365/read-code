---
id: 4-kube-controller-code
title: nodelifecycle-controller 代码走读
description: nodelifecycle-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

"Nodelifecycle"是一个Kubernetes控制器，它负责监视和管理集群中的节点的生命周期。它可以自动化一些节点的生命周期管理任务，例如添加、删除、替换节点以及处理节点故障和维护。

具体来说，Nodelifecycle控制器可以执行以下任务：

1. 自动添加节点：当集群需要扩展时，Nodelifecycle控制器可以自动添加新的节点到集群中，以确保集群具有所需的计算能力。
2. 自动删除节点：当节点不再需要时，例如在缩小集群规模时，Nodelifecycle控制器可以自动从集群中删除节点，并清理相关资源。
3. 故障处理：当节点发生故障时，Nodelifecycle控制器可以自动替换故障节点，确保应用程序持续运行。
4. 维护管理：当节点需要进行维护时，例如更新操作系统或应用程序时，Nodelifecycle控制器可以自动将节点从集群中删除，并在维护完成后将其重新添加到集群中。

总之，Nodelifecycle控制器可以通过自动化节点的生命周期管理来简化Kubernetes集群的管理和维护，提高集群的可靠性和稳定性。

## 结构体

```go
type Controller struct {
    // 负责处理节点污点
	taintManager *scheduler.NoExecuteTaintManager
	// pod lister
	podLister         corelisters.PodLister
    // podLister是否已同步完毕
	podInformerSynced cache.InformerSynced
    // client-go clientset
	kubeClient        clientset.Interface
	// 用于计算时间戳的函数
	now func() metav1.Time
	// 用于模拟节点部分故障的函数
	enterPartialDisruptionFunc func(nodeNum int) float32
    // 用于模拟节点全部故障的函数
	enterFullDisruptionFunc    func(nodeNum int) float32
    // 用于计算区域状态的函数
	computeZoneStateFunc       func(nodeConditions []*v1.NodeCondition) (int, ZoneState)
	
    // 已知的节点集合
	knownNodeSet map[string]*v1.Node
	// 存储每个节点的健康状况信息的map
	nodeHealthMap *nodeHealthMap

	// 用于保护区域 zonePodEvictor 和区域 zoneNoExecuteTainter 的锁 go的map不能并发
	evictorLock     sync.Mutex
    // 存储每个节点的副本集的映射，以及在该节点上运行的 Pod 的数量
	nodeEvictionMap *nodeEvictionMap
	// 从不响应的节点中驱逐 Pod 的队列map
	zonePodEvictor map[string]*scheduler.RateLimitedTimedQueue
	// 用于给不响应的节点打标记的队列map
	zoneNoExecuteTainter map[string]*scheduler.RateLimitedTimedQueue
	// 存储需要重试的节点的集合
	nodesToRetry sync.Map
	// 存储每个区域的状态
	zoneStates map[string]ZoneState
	// 用于获取守护进程集
	daemonSetStore          appsv1listers.DaemonSetLister
    //  守护进程集 Informer 是否已同步的标志
	daemonSetInformerSynced cache.InformerSynced
	// 用于获取租约的列表 lease用于选主
	leaseLister         coordlisters.LeaseLister
    // 租约 Informer 是否已同步的标志
	leaseInformerSynced cache.InformerSynced
    // node lister
	nodeLister          corelisters.NodeLister
    // 节点 Informer 是否已同步的标志
	nodeInformerSynced  cache.InformerSynced
	// 用于获取运行在指定节点上的 Pod 的函数
	getPodsAssignedToNode func(nodeName string) ([]*v1.Pod, error)
    
	// 事件广播器，用于广播事件
	broadcaster record.EventBroadcaster
    // 事件记录器，用于记录事件
	recorder    record.EventRecorder

	//  控制节点监控周期的值，即 Controller 检查来自 kubelet 发送的节点健康信号的频率。
	nodeMonitorPeriod time.Duration

	// 当节点刚刚创建时，例如在集群引导或节点创建时，我们会给它更长的宽限期。
	nodeStartupGracePeriod time.Duration

	// 控制节点监控宽限期的值，即 Controller 从 kubelet 接收到节点健康信号更新的时间间隔，
    // 如果在这段时间内没有收到更新，则开始发布“NodeReady==ConditionUnknown”。
	nodeMonitorGracePeriod time.Duration

	// Controller 用于处理节点监控健康更新的工作程序数量。
	nodeUpdateWorkerSize int
	
    // 当节点健康状态更新停止超过该时间后，控制器开始驱逐该节点上的 Pod。
	podEvictionTimeout          time.Duration
    //  控制驱逐 Pod 操作的 QPS 上限，以避免过多的请求给 API server 带来过大的负载。
	evictionLimiterQPS          float32
    //  驱逐 Pod 操作的次要 QPS 上限，用于在主 QPS 达到上限时提供备选方案。
	secondaryEvictionLimiterQPS float32
    // 当集群中的节点数超过该值时，将使用较低的 evictionLimiterQPS 和 secondaryEvictionLimiterQPS。
	largeClusterThreshold       int32
    // 指定在某个 Zone 的健康状况降低到该阈值以下时，该 Zone 被认为是不健康的。
	unhealthyZoneThreshold      float32

	// 控制器是否启动TaintManager。TaintManager用于从已标记为“不可调度”的节点上驱逐Pod，以确保集群的健康状态
	runTaintManager bool
	
    // 用于存储等待处理的节点更新请求的工作队列。当控制器从kubelet接收到节点的状态更新时，
    // 会将更新请求放入该队列中，并由nodeUpdateWorker处理。
	nodeUpdateQueue workqueue.Interface
    // 用于存储等待处理的Pod更新请求的工作队列。当节点状态更新时，可能需要对Pod进行重新调度。
    // 此时，将为每个Pod创建更新请求，并将其放入此队列中。工作队列使用速率限制，以确保请求以恒定的速度处理，从而避免对API服务器造成太大压力。
	podUpdateQueue  workqueue.RateLimitingInterface
}
```

## init

init函数定义了一些指标（metrics）和它们的注册函数。这些指标用于监控Kubernetes集群中节点（node）的健康状态和其他一些相关指标。定义了以下指标：

- zoneHealth：每个区域（zone）中健康节点的百分比。
- zoneSize：每个区域中已注册节点的数量。
- unhealthyNodes：每个区域中未准备好的节点数量。
- evictionsNumber：自当前NodeController实例启动以来发生的节点驱逐（evictions）数量（在1.24.0版本后已废弃，被evictionsTotal取代）。
- evictionsTotal：自当前NodeController实例启动以来发生的节点驱逐数量。
- updateNodeHealthDuration：NodeController更新单个节点健康状态所需的时间。
- updateAllNodesHealthDuration：NodeController更新所有节点健康状态所需的时间。

这些指标被注册到Prometheus客户端库（Prometheus client library）中，以便在Prometheus中使用。具体来说，当Kubernetes集群中的节点健康状况发生变化时，这些指标将被更新，从而可以监控和分析节点的运行状况。

```go
func init() {
	// Register prometheus metrics
	Register()
}

// Register函数
const (
	nodeControllerSubsystem = "node_collector"
	zoneHealthStatisticKey  = "zone_health"
	zoneSizeKey             = "zone_size"
	zoneNoUnhealthyNodesKey = "unhealthy_nodes_in_zone"
	evictionsNumberKey      = "evictions_number"
	evictionsTotalKey       = "evictions_total"

	updateNodeHealthKey     = "update_node_health_duration_seconds"
	updateAllNodesHealthKey = "update_all_nodes_health_duration_seconds"
)

var (
	zoneHealth = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Subsystem:      nodeControllerSubsystem,
			Name:           zoneHealthStatisticKey,
			Help:           "Gauge measuring percentage of healthy nodes per zone.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"zone"},
	)
	zoneSize = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Subsystem:      nodeControllerSubsystem,
			Name:           zoneSizeKey,
			Help:           "Gauge measuring number of registered Nodes per zones.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"zone"},
	)
	unhealthyNodes = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Subsystem:      nodeControllerSubsystem,
			Name:           zoneNoUnhealthyNodesKey,
			Help:           "Gauge measuring number of not Ready Nodes per zones.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"zone"},
	)
	evictionsNumber = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:         nodeControllerSubsystem,
			Name:              evictionsNumberKey,
			Help:              "Number of Node evictions that happened since current instance of NodeController started, This metric is replaced by node_collector_evictions_total.",
			DeprecatedVersion: "1.24.0",
			StabilityLevel:    metrics.ALPHA,
		},
		[]string{"zone"},
	)
	evictionsTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      nodeControllerSubsystem,
			Name:           evictionsTotalKey,
			Help:           "Number of Node evictions that happened since current instance of NodeController started.",
			StabilityLevel: metrics.STABLE,
		},
		[]string{"zone"},
	)

	updateNodeHealthDuration = metrics.NewHistogram(
		&metrics.HistogramOpts{
			Subsystem:      nodeControllerSubsystem,
			Name:           updateNodeHealthKey,
			Help:           "Duration in seconds for NodeController to update the health of a single node.",
			Buckets:        metrics.ExponentialBuckets(0.001, 4, 8), // 1ms -> ~15s
			StabilityLevel: metrics.ALPHA,
		},
	)
	updateAllNodesHealthDuration = metrics.NewHistogram(
		&metrics.HistogramOpts{
			Subsystem:      nodeControllerSubsystem,
			Name:           updateAllNodesHealthKey,
			Help:           "Duration in seconds for NodeController to update the health of all nodes.",
			Buckets:        metrics.ExponentialBuckets(0.01, 4, 8), // 10ms -> ~3m
			StabilityLevel: metrics.ALPHA,
		},
	)
)

var registerMetrics sync.Once

// Register the metrics that are to be monitored.
func Register() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(zoneHealth)
		legacyregistry.MustRegister(zoneSize)
		legacyregistry.MustRegister(unhealthyNodes)
		legacyregistry.MustRegister(evictionsNumber)
		legacyregistry.MustRegister(evictionsTotal)
		legacyregistry.MustRegister(updateNodeHealthDuration)
		legacyregistry.MustRegister(updateAllNodesHealthDuration)
	})
}

```

## New

```go
func NewNodeLifecycleController(
	ctx context.Context,
	leaseInformer coordinformers.LeaseInformer,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	daemonSetInformer appsv1informers.DaemonSetInformer,
	kubeClient clientset.Interface,
	nodeMonitorPeriod time.Duration,
	nodeStartupGracePeriod time.Duration,
	nodeMonitorGracePeriod time.Duration,
	podEvictionTimeout time.Duration,
	evictionLimiterQPS float32,
	secondaryEvictionLimiterQPS float32,
	largeClusterThreshold int32,
	unhealthyZoneThreshold float32,
	runTaintManager bool,
) (*Controller, error) {

	if kubeClient == nil {
		klog.Fatalf("kubeClient is nil when starting Controller")
	}
	
    // 创建事件广播器和事件记录器 
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "node-controller"})

	nc := &Controller{
		kubeClient:                  kubeClient,
		now:                         metav1.Now,
		knownNodeSet:                make(map[string]*v1.Node),
		nodeHealthMap:               newNodeHealthMap(),
		nodeEvictionMap:             newNodeEvictionMap(),
		broadcaster:                 eventBroadcaster,
		recorder:                    recorder,
		nodeMonitorPeriod:           nodeMonitorPeriod,
		nodeStartupGracePeriod:      nodeStartupGracePeriod,
		nodeMonitorGracePeriod:      nodeMonitorGracePeriod,
		nodeUpdateWorkerSize:        scheduler.UpdateWorkerSize,
		zonePodEvictor:              make(map[string]*scheduler.RateLimitedTimedQueue),
		zoneNoExecuteTainter:        make(map[string]*scheduler.RateLimitedTimedQueue),
		nodesToRetry:                sync.Map{},
		zoneStates:                  make(map[string]ZoneState),
		podEvictionTimeout:          podEvictionTimeout,
		evictionLimiterQPS:          evictionLimiterQPS,
		secondaryEvictionLimiterQPS: secondaryEvictionLimiterQPS,
		largeClusterThreshold:       largeClusterThreshold,
		unhealthyZoneThreshold:      unhealthyZoneThreshold,
		runTaintManager:             runTaintManager,
		nodeUpdateQueue:             workqueue.NewNamed("node_lifecycle_controller"),
		podUpdateQueue:              workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node_lifecycle_controller_pods"),
	}

	nc.enterPartialDisruptionFunc = nc.ReducedQPSFunc
	nc.enterFullDisruptionFunc = nc.HealthyQPSFunc
	nc.computeZoneStateFunc = nc.ComputeZoneState
	
    // 处理pod 的add delete 和 update 都是判读条件 然后加入queue
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			nc.podUpdated(nil, pod)
			if nc.taintManager != nil {
				nc.taintManager.PodUpdated(nil, pod)
			}
		},
		UpdateFunc: func(prev, obj interface{}) {
			prevPod := prev.(*v1.Pod)
			newPod := obj.(*v1.Pod)
			nc.podUpdated(prevPod, newPod)
			if nc.taintManager != nil {
                // 污点管理最后介绍
				nc.taintManager.PodUpdated(prevPod, newPod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, isPod := obj.(*v1.Pod)
			// 判断是不是pod对象
			if !isPod {
                // 尝试从cache.DeletedFinalStateUnknown对象中提取出Pod对象来
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Errorf("Received unexpected object: %v", obj)
					return
				}
                // 尝试取出pod
				pod, ok = deletedState.Obj.(*v1.Pod)
				if !ok {
					klog.Errorf("DeletedFinalStateUnknown contained non-Pod object: %v", deletedState.Obj)
					return
				}
			}
			nc.podUpdated(pod, nil)
			if nc.taintManager != nil {
				nc.taintManager.PodUpdated(pod, nil)
			}
		},
	})
	nc.podInformerSynced = podInformer.Informer().HasSynced
    // 给informer的Indexers 加索引删除 client-go那边文字有介绍
	podInformer.Informer().AddIndexers(cache.Indexers{
		nodeNameKeyIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return []string{}, nil
			}
			if len(pod.Spec.NodeName) == 0 {
				return []string{}, nil
			}
			return []string{pod.Spec.NodeName}, nil
		},
	})

	podIndexer := podInformer.Informer().GetIndexer()
    // 获取指定节点上的所有pod
	nc.getPodsAssignedToNode = func(nodeName string) ([]*v1.Pod, error) {
        // 根据nodename的索引拿出所有pod
		objs, err := podIndexer.ByIndex(nodeNameKeyIndex, nodeName)
		if err != nil {
			return nil, err
		}
		pods := make([]*v1.Pod, 0, len(objs))
		for _, obj := range objs {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				continue
			}
			pods = append(pods, pod)
		}
		return pods, nil
	}
	nc.podLister = podInformer.Lister()
	nc.nodeLister = nodeInformer.Lister()

	if nc.runTaintManager {
        // 赋值
		nc.taintManager = scheduler.NewNoExecuteTaintManager(ctx, kubeClient, nc.podLister, nc.nodeLister, nc.getPodsAssignedToNode)
        // nodeInformer监听事件
		nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: controllerutil.CreateAddNodeHandler(func(node *v1.Node) error {
                // 节点的污点更新
				nc.taintManager.NodeUpdated(nil, node)
				return nil
			}),
			UpdateFunc: controllerutil.CreateUpdateNodeHandler(func(oldNode, newNode *v1.Node) error {
				nc.taintManager.NodeUpdated(oldNode, newNode)
				return nil
			}),
			DeleteFunc: controllerutil.CreateDeleteNodeHandler(func(node *v1.Node) error {
				nc.taintManager.NodeUpdated(node, nil)
				return nil
			}),
		})
	}

	klog.Infof("Controller will reconcile labels.")
    // 监听node
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controllerutil.CreateAddNodeHandler(func(node *v1.Node) error {
            // nodeUpdateQueue 加入 node
			nc.nodeUpdateQueue.Add(node.Name)
			nc.nodeEvictionMap.registerNode(node.Name)
			return nil
		}),
		UpdateFunc: controllerutil.CreateUpdateNodeHandler(func(_, newNode *v1.Node) error {
			nc.nodeUpdateQueue.Add(newNode.Name)
			return nil
		}),
		DeleteFunc: controllerutil.CreateDeleteNodeHandler(func(node *v1.Node) error {
			nc.nodesToRetry.Delete(node.Name)
			nc.nodeEvictionMap.unregisterNode(node.Name)
			return nil
		}),
	})

	nc.leaseLister = leaseInformer.Lister()
	nc.leaseInformerSynced = leaseInformer.Informer().HasSynced

	nc.nodeInformerSynced = nodeInformer.Informer().HasSynced

	nc.daemonSetStore = daemonSetInformer.Lister()
	nc.daemonSetInformerSynced = daemonSetInformer.Informer().HasSynced

	return nc, nil
}
```

### HealthMap和EvictionMap

**newNodeHealthMap**

```go
type nodeHealthMap struct {
	lock        sync.RWMutex
	nodeHealths map[string]*nodeHealthData
}

type nodeHealthData struct {
    // 最近一次对节点进行探测的时间戳
	probeTimestamp           metav1.Time
    // 节点的就绪状态发生变化的时间戳
	readyTransitionTimestamp metav1.Time
    // 节点的状态
	status                   *v1.NodeStatus
    // 节点的租约
	lease                    *coordv1.Lease
}

func newNodeHealthMap() *nodeHealthMap {
	return &nodeHealthMap{
		nodeHealths: make(map[string]*nodeHealthData),
	}
}

// 取出node的nodeHealthData 并deepcopy
func (n *nodeHealthMap) getDeepCopy(name string) *nodeHealthData {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return n.nodeHealths[name].deepCopy()
}

// 设置
func (n *nodeHealthMap) set(name string, data *nodeHealthData) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.nodeHealths[name] = data
}
```

**newNodeEvictionMap**

```go
type evictionStatus int

const (
    // 节点未被标记
	unmarked = iota
    // 节点已被标记为待驱逐
	toBeEvicted
    // 节点已被驱逐
	evicted
)

type nodeEvictionMap struct {
	lock          sync.Mutex
    // 节点驱逐的map key:node value:evictionStatus
	nodeEvictions map[string]evictionStatus
}

func newNodeEvictionMap() *nodeEvictionMap {
	return &nodeEvictionMap{
		nodeEvictions: make(map[string]evictionStatus),
	}
}

func (n *nodeEvictionMap) registerNode(nodeName string) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.nodeEvictions[nodeName] = unmarked
}

func (n *nodeEvictionMap) unregisterNode(nodeName string) {
	n.lock.Lock()
	defer n.lock.Unlock()
	delete(n.nodeEvictions, nodeName)
}

// 设置node的状态
func (n *nodeEvictionMap) setStatus(nodeName string, status evictionStatus) bool {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, exists := n.nodeEvictions[nodeName]; !exists {
		return false
	}
	n.nodeEvictions[nodeName] = status
	return true
}

// 获取node的状态
func (n *nodeEvictionMap) getStatus(nodeName string) (evictionStatus, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, exists := n.nodeEvictions[nodeName]; !exists {
		return unmarked, false
	}
	return n.nodeEvictions[nodeName], true
}

```

### podUpdated

```go
type podUpdateItem struct {
	namespace string
	name      string
}

func (nc *Controller) podUpdated(oldPod, newPod *v1.Pod) {
	if newPod == nil {
		return
	}
    // 新pod的node不是空 并且 （oldPod为空指针，代表是新建pod 或者 新旧pod的node不一样）
	if len(newPod.Spec.NodeName) != 0 && (oldPod == nil || newPod.Spec.NodeName != oldPod.Spec.NodeName) {
		podItem := podUpdateItem{newPod.Namespace, newPod.Name}
		nc.podUpdateQueue.Add(podItem)
	}
}
```

### 函数相关

```go
// 根据节点数量返回一个减少后的 QPS 限制值。
func (nc *Controller) ReducedQPSFunc(nodeNum int) float32 {
    // 如果node数大于largeClusterThreshold 限制成secondaryEvictionLimiterQPS 复杂不做限制
	if int32(nodeNum) > nc.largeClusterThreshold {
		return nc.secondaryEvictionLimiterQPS
	}
	return 0
}
```

```go
// 节点数目对应的健康的 QPS 值
func (nc *Controller) HealthyQPSFunc(nodeNum int) float32 {
	return nc.evictionLimiterQPS
}
```

```go
// 计算节点健康状态
func (nc *Controller) ComputeZoneState(nodeReadyConditions []*v1.NodeCondition) (int, ZoneState) {
	readyNodes := 0
	notReadyNodes := 0
    // 统计其中 Ready 和 NotReady 状态的 Node 的数量
	for i := range nodeReadyConditions {
		if nodeReadyConditions[i] != nil && nodeReadyConditions[i].Status == v1.ConditionTrue {
			readyNodes++
		} else {
			notReadyNodes++
		}
	}
	switch {
	case readyNodes == 0 && notReadyNodes > 0:
		return notReadyNodes, stateFullDisruption
	case notReadyNodes > 2 && float32(notReadyNodes)/float32(notReadyNodes+readyNodes) >= nc.unhealthyZoneThreshold:
		return notReadyNodes, statePartialDisruption
	default:
		return notReadyNodes, stateNormal
	}
}

type ZoneState string

const (
	stateInitial           = ZoneState("Initial")
	stateNormal            = ZoneState("Normal")
	stateFullDisruption    = ZoneState("FullDisruption")
	statePartialDisruption = ZoneState("PartialDisruption")
)
```

## Run

```go
func (nc *Controller) Run(ctx context.Context) {
    // 处理panic
	defer utilruntime.HandleCrash()

	// 启动 Kubernetes 事件广播器（Event Broadcaster），并开始结构化日志记录
	nc.broadcaster.StartStructuredLogging(0)
	klog.Infof("Sending events to api server.")
    // 将 Kubernetes 事件广播器配置为将事件记录到 API 服务器中
	nc.broadcaster.StartRecordingToSink(
		&v1core.EventSinkImpl{
			Interface: v1core.New(nc.kubeClient.CoreV1().RESTClient()).Events(""),
		})
    // 在方法返回之前停止广播器
	defer nc.broadcaster.Shutdown()

	// 在方法返回之前，停止与节点更新和 Pod 更新相关的所有队列
	defer nc.nodeUpdateQueue.ShutDown()
	defer nc.podUpdateQueue.ShutDown()

	klog.Infof("Starting node controller")
	defer klog.Infof("Shutting down node controller")
	
    // 等待所有的 Informer 同步完毕
	if !cache.WaitForNamedCacheSync("taint", ctx.Done(), nc.leaseInformerSynced, nc.nodeInformerSynced, nc.podInformerSynced, nc.daemonSetInformerSynced) {
		return
	}
	
    // 如果 TaintManager 在运行，则启动一个 go 协程以运行 TaintManager
	if nc.runTaintManager {
		go nc.taintManager.Run(ctx)
	}

	// 启动指定数量的 goroutine，处理 Node 的更新。
	for i := 0; i < scheduler.UpdateWorkerSize; i++ {
		go wait.UntilWithContext(ctx, nc.doNodeProcessingPassWorker, time.Second)
	}
	
    // 启动指定数量的 goroutine 处理 Pod 的更新。
	for i := 0; i < podUpdateWorkerSize; i++ {
		go wait.UntilWithContext(ctx, nc.doPodProcessingWorker, time.Second)
	}

	if nc.runTaintManager {
		// 启动一个 go 协程以处理基于 taint 的驱逐
		go wait.UntilWithContext(ctx, nc.doNoExecuteTaintingPass, scheduler.NodeEvictionPeriod)
	} else {
		// 启动一个 go 协程以管理节点的驱逐
		go wait.UntilWithContext(ctx, nc.doEvictionPass, scheduler.NodeEvictionPeriod)
	}

	// 启动一个 go 协程以监视节点的健康状况
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		if err := nc.monitorNodeHealth(ctx); err != nil {
			klog.Errorf("Error monitoring node health: %v", err)
		}
	}, nc.nodeMonitorPeriod)

	<-ctx.Done()
}
```

## doNodeProcessingPassWorker

```go
func (nc *Controller) doNodeProcessingPassWorker(ctx context.Context) {
	for {
		obj, shutdown := nc.nodeUpdateQueue.Get()
		// 从queue中拿消息 如果没有了 退出
		if shutdown {
			return
		}
		nodeName := obj.(string)
		if err := nc.doNoScheduleTaintingPass(ctx, nodeName); err != nil {
			klog.Errorf("Failed to taint NoSchedule on node <%s>, requeue it: %v", nodeName, err)
			// TODO(k82cn): Add nodeName back to the queue
		}
		// TODO: re-evaluate whether there are any labels that need to be
		// reconcile in 1.19. Remove this function if it's no longer necessary.
		if err := nc.reconcileNodeLabels(nodeName); err != nil {
			klog.Errorf("Failed to reconcile labels for node <%s>, requeue it: %v", nodeName, err)
			// TODO(yujuhong): Add nodeName back to the queue
		}
		nc.nodeUpdateQueue.Done(nodeName)
	}
}
```

### doNoScheduleTaintingPass

```GO
var nodeConditionToTaintKeyStatusMap = map[v1.NodeConditionType]map[v1.ConditionStatus]string{
		v1.NodeReady: {
			v1.ConditionFalse:   v1.TaintNodeNotReady,
			v1.ConditionUnknown: v1.TaintNodeUnreachable,
		},
		v1.NodeMemoryPressure: {
			v1.ConditionTrue: v1.TaintNodeMemoryPressure,
		},
		v1.NodeDiskPressure: {
			v1.ConditionTrue: v1.TaintNodeDiskPressure,
		},
		v1.NodeNetworkUnavailable: {
			v1.ConditionTrue: v1.TaintNodeNetworkUnavailable,
		},
		v1.NodePIDPressure: {
			v1.ConditionTrue: v1.TaintNodePIDPressure,
		},
}

func (nc *Controller) doNoScheduleTaintingPass(ctx context.Context, nodeName string) error {
	node, err := nc.nodeLister.Get(nodeName)
    // 从lister找node 找不到就忽略 
	if err != nil {
		// If node not found, just ignore it.
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Map node's condition to Taints.
	var taints []v1.Taint
    // 通过遍历节点node的Status.Conditions属性，将节点状态对应的Taint信息记录到taints数组中。		
    // nodeConditionToTaintKeyStatusMap在上方，用于将节点的条件转换为Taint。
	for _, condition := range node.Status.Conditions {
		if taintMap, found := nodeConditionToTaintKeyStatusMap[condition.Type]; found {
			if taintKey, found := taintMap[condition.Status]; found {
				taints = append(taints, v1.Taint{
					Key:    taintKey,
					Effect: v1.TaintEffectNoSchedule,
				})
			}
		}
	}
    // 如果节点的Spec.Unschedulable属性为true，则添加相应的不可调度的Taint
    // Unschedulable=true 代表不接受新的pod调度这个node上
	if node.Spec.Unschedulable {
		// If unschedulable, append related taint.
		taints = append(taints, v1.Taint{
			Key:    v1.TaintNodeUnschedulable,
			Effect: v1.TaintEffectNoSchedule,
		})
	}

	// 过滤出节点node已存在的Taints，并存储到nnodeTaints数组中
	nodeTaints := taintutils.TaintSetFilter(node.Spec.Taints, func(t *v1.Taint) bool {
		// only NoSchedule taints are candidates to be compared with "taints" later
		if t.Effect != v1.TaintEffectNoSchedule {
			return false
		}
		// Find unschedulable taint of node.
		if t.Key == v1.TaintNodeUnschedulable {
			return true
		}
		// Find node condition taints of node.
		_, found := taintKeyToNodeConditionMap[t.Key]
		return found
	})
    // 找出需要添加和删除的Taints，分别存储在taintsToAdd和taintsToDel数组中。
	taintsToAdd, taintsToDel := taintutils.TaintSetDiff(taints, nodeTaints)
	// 先检查待添加和待删除的污点是否为空。
	if len(taintsToAdd) == 0 && len(taintsToDel) == 0 {
		return nil
	}
    // 交换节点的污点信息
	if !controllerutil.SwapNodeControllerTaint(ctx, nc.kubeClient, taintsToAdd, taintsToDel, node) {
		return fmt.Errorf("failed to swap taints of node %+v", node)
	}
	return nil
}

// utils
func TaintSetFilter(taints []v1.Taint, fn func(*v1.Taint) bool) []v1.Taint {
	res := []v1.Taint{}

	for _, taint := range taints {
		if fn(&taint) {
			res = append(res, taint)
		}
	}

	return res
}

// 比较差异 新的有 就当没有 就是已添加的。旧的有 新的没有 就是要删除的
func TaintSetDiff(taintsNew, taintsOld []v1.Taint) (taintsToAdd []*v1.Taint, taintsToRemove []*v1.Taint) {
	for _, taint := range taintsNew {
		if !TaintExists(taintsOld, &taint) {
			t := taint
			taintsToAdd = append(taintsToAdd, &t)
		}
	}

	for _, taint := range taintsOld {
		if !TaintExists(taintsNew, &taint) {
			t := taint
			taintsToRemove = append(taintsToRemove, &t)
		}
	}

	return
}

func TaintExists(taints []v1.Taint, taintToFind *v1.Taint) bool {
	for _, taint := range taints {
		if taint.MatchTaint(taintToFind) {
			return true
		}
	}
	return false
}
```

## doPodProcessingWorker

```GO
// 用于在 Node 出现故障或者节点调度变化时，重新调度 Pod 到其他可用的节点上。
func (nc *Controller) doPodProcessingWorker(ctx context.Context) {
	for {
        // 从queue拿出poditem 如果没有退出
		obj, shutdown := nc.podUpdateQueue.Get()
		// "podUpdateQueue" will be shutdown when "stopCh" closed;
		// we do not need to re-check "stopCh" again.
		if shutdown {
			return
		}

		podItem := obj.(podUpdateItem)
		nc.processPod(ctx, podItem)
	}
}

func (nc *Controller) processPod(ctx context.Context, podItem podUpdateItem) {
    // 函数退出queue done掉item
	defer nc.podUpdateQueue.Done(podItem)
    // 从lister取pod
	pod, err := nc.podLister.Pods(podItem.namespace).Get(podItem.name)
	if err != nil {
        // 没找到直接退出
		if apierrors.IsNotFound(err) {
			// If the pod was deleted, there is no need to requeue.
			return
		}
		klog.Warningf("Failed to read pod %v/%v: %v.", podItem.namespace, podItem.name, err)
        // 重新放回队列中等待处理
		nc.podUpdateQueue.AddRateLimited(podItem)
		return
	}

	nodeName := pod.Spec.NodeName
	// 获取node的蒋康状态 
	nodeHealth := nc.nodeHealthMap.getDeepCopy(nodeName)
	if nodeHealth == nil {
		// 尚未收集节点数据，或者在此期间节点已被删除。Pod将由doEvactionPass方法处理。
		return
	}
	
    // 从lister获取node
	node, err := nc.nodeLister.Get(nodeName)
	if err != nil {
		klog.Warningf("Failed to read node %v: %v.", nodeName, err)
		nc.podUpdateQueue.AddRateLimited(podItem)
		return
	}
	
    // 获取ready状态的Condition
	_, currentReadyCondition := controllerutil.GetNodeCondition(nodeHealth.status, v1.NodeReady)
	if currentReadyCondition == nil {
		// 缺少NodeReady条件可能只会在添加节点之后发生（或者如果它将被恶意删除）。
        // 在这两种情况下，在处理下一个节点更新事件期间，将正确处理pod（如果需要，将其逐出）。
		return
	}

	pods := []*v1.Pod{pod}
	// In taint-based eviction mode, only node updates are processed by NodeLifecycleController.
	// Pods are processed by TaintManager.
	if !nc.runTaintManager {
        // 进行驱逐操作
		if err := nc.processNoTaintBaseEviction(ctx, node, currentReadyCondition, nc.nodeMonitorGracePeriod, pods); err != nil {
			klog.Warningf("Unable to process pod %+v eviction from node %v: %v.", podItem, nodeName, err)
			nc.podUpdateQueue.AddRateLimited(podItem)
			return
		}
	}
	//  currentReadyCondition 不为空且状态不为 v1.ConditionTrue，则标记该pod为 NotReady
	if currentReadyCondition.Status != v1.ConditionTrue {
		if err := controllerutil.MarkPodsNotReady(ctx, nc.kubeClient, nc.recorder, pods, nodeName); err != nil {
			klog.Warningf("Unable to mark pod %+v NotReady on node %v: %v.", podItem, nodeName, err)
			nc.podUpdateQueue.AddRateLimited(podItem)
		}
	}
}
```

### processNoTaintBaseEviction

```go
// 用于处理没有 Taint 的情况下节点中的 Pod 被逐出的逻辑
func (nc *Controller) processNoTaintBaseEviction(ctx context.Context, node *v1.Node, observedReadyCondition *v1.NodeCondition, gracePeriod time.Duration, pods []*v1.Pod) error {
	decisionTimestamp := nc.now()
    // 获取健康数据 如果不存在 报错
	nodeHealthData := nc.nodeHealthMap.getDeepCopy(node.Name)
	if nodeHealthData == nil {
		return fmt.Errorf("health data doesn't exist for node %q", node.Name)
	}
	// Check eviction timeout against decisionTimestamp
	switch observedReadyCondition.Status {
	case v1.ConditionFalse:
        // 节点不可用 检查现在是不是在 上次ready时间+pod驱逐超时 之后 如果是要驱逐
        // 因为超时的情况下可以认为该节点失去了响应能力。
		if decisionTimestamp.After(nodeHealthData.readyTransitionTimestamp.Add(nc.podEvictionTimeout)) {
			// 如果超时了，则将该节点上的所有 pod 添加到驱逐队列
            enqueued, err := nc.evictPods(ctx, node, pods)
			if err != nil {
				return err
			}
            // 记录日志
			if enqueued {
				klog.V(2).Infof("Node is NotReady. Adding Pods on Node %s to eviction queue: %v is later than %v + %v",
					node.Name,
					decisionTimestamp,
					nodeHealthData.readyTransitionTimestamp,
					nc.podEvictionTimeout,
				)
			}
		}
	case v1.ConditionUnknown:
        // 节点处于未知状态 检查现在是不是在 上次probe时间+pod驱逐超时 之后 如果是要驱逐
        // 因为超时的情况下可以认为该节点失去了响应能力。
		if decisionTimestamp.After(nodeHealthData.probeTimestamp.Add(nc.podEvictionTimeout)) {
			enqueued, err := nc.evictPods(ctx, node, pods)
			if err != nil {
				return err
			}
			if enqueued {
				klog.V(2).Infof("Node is unresponsive. Adding Pods on Node %s to eviction queues: %v is later than %v + %v",
					node.Name,
					decisionTimestamp,
					nodeHealthData.readyTransitionTimestamp,
					nc.podEvictionTimeout-gracePeriod,
				)
			}
		}
	case v1.ConditionTrue:
        // 整除不处理
		if nc.cancelPodEviction(node) {
			klog.V(2).Infof("Node %s is ready again, cancelled pod eviction", node.Name)
		}
	}
	return nil
}
```

#### evictPods

```go
func (nc *Controller) evictPods(ctx context.Context, node *v1.Node, pods []*v1.Pod) (bool, error) {
	// 检查这个节点是否已经被标记为 evicted
    status, ok := nc.nodeEvictionMap.getStatus(node.Name)
	if ok && status == evicted {
        // 立即删除这些 Pod。我们通过调用 controllerutil.DeletePods 方法来删除这些 Pod
		// Node eviction already happened for this node.
		// Handling immediate pod deletion.
		_, err := controllerutil.DeletePods(ctx, nc.kubeClient, pods, nc.recorder, node.Name, string(node.UID), nc.daemonSetStore)
		if err != nil {
			return false, fmt.Errorf("unable to delete pods from node %q: %v", node.Name, err)
		}
		return false, nil
	}
    // 将这个节点标记为 toBeEvicted，也就是需要进行驱逐操作
	if !nc.nodeEvictionMap.setStatus(node.Name, toBeEvicted) {
		klog.V(2).Infof("node %v was unregistered in the meantime - skipping setting status", node.Name)
	}

	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	
    // 获取当前节点所在的 zone，并通过该 zone 对应的 zonePodEvictor 来将这些 Pod 加入到驱逐队列中
	return nc.zonePodEvictor[nodetopology.GetZoneKey(node)].Add(node.Name, string(node.UID)), nil
}
```

##### DeletePods

```GO
func DeletePods(ctx context.Context, kubeClient clientset.Interface, pods []*v1.Pod, recorder record.EventRecorder, nodeName, nodeUID string, daemonStore appsv1listers.DaemonSetLister) (bool, error) {
	remaining := false
	var updateErrList []error
	
    // 如果要删除的Pod不为空，则记录一个节点事件，表示正在删除该节点上的所有Pod。
	if len(pods) > 0 {
		RecordNodeEvent(recorder, nodeName, nodeUID, v1.EventTypeNormal, "DeletingAllPods", fmt.Sprintf("Deleting all Pods from Node %v.", nodeName))
	}

	for i := range pods {
		// Defensive check, also needed for tests.
		if pods[i].Spec.NodeName != nodeName {
			continue
		}

		// Pod will be modified, so making copy is required.
		pod := pods[i].DeepCopy()
        // 置Pod的终止原因和消息，如果更新Pod状态时发生冲突，则将错误记录到updateErrList中。
		if _, err := SetPodTerminationReason(ctx, kubeClient, pod, nodeName); err != nil {
			if apierrors.IsConflict(err) {
				updateErrList = append(updateErrList,
					fmt.Errorf("update status failed for pod %q: %v", format.Pod(pod), err))
				continue
			}
		}
		// 如果Pod的DeletionGracePeriodSeconds字段不为空，则将remaining设置为true，
        // 表示仍有剩余的Pod需要被删除，然后跳过当前循环。
		if pod.DeletionGracePeriodSeconds != nil {
			remaining = true
			continue
		}
		// 如果当前Pod被DaemonSet所管理，则跳过当前循环。
		if _, err := daemonStore.GetPodDaemonSets(pod); err == nil {
			// No error means at least one daemonset was found
			continue
		}

		klog.V(2).InfoS("Starting deletion of pod", "pod", klog.KObj(pod))
		recorder.Eventf(pod, v1.EventTypeNormal, "NodeControllerEviction", "Marking for deletion Pod %s from Node %s", pod.Name, nodeName)
        // 删除pod
		if err := kubeClient.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				// NotFound error means that pod was already deleted.
				// There is nothing left to do with this pod.
				continue
			}
			return false, err
		}
		remaining = true
	}

	if len(updateErrList) > 0 {
		return false, utilerrors.NewAggregate(updateErrList)
	}
	return remaining, nil
}

```

### MarkPodsNotReady

```go
// 将指定节点上的所有Pod的Ready状态设置为False的功能
func MarkPodsNotReady(ctx context.Context, kubeClient clientset.Interface, recorder record.EventRecorder, pods []*v1.Pod, nodeName string) error {
	klog.V(2).InfoS("Update ready status of pods on node", "node", klog.KRef("", nodeName))

	errs := []error{}
	for i := range pods {
		// Defensive check, also needed for tests.
		if pods[i].Spec.NodeName != nodeName {
			continue
		}

		// Pod will be modified, so making copy is required.
		pod := pods[i].DeepCopy()
		for _, cond := range pod.Status.Conditions {
			if cond.Type != v1.PodReady {
				continue
			}

			cond.Status = v1.ConditionFalse
			if !utilpod.UpdatePodCondition(&pod.Status, &cond) {
				break
			}

			klog.V(2).InfoS("Updating ready status of pod to false", "pod", pod.Name)
			if _, err := kubeClient.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
				if apierrors.IsNotFound(err) {
					// NotFound error means that pod was already deleted.
					// There is nothing left to do with this pod.
					continue
				}
				klog.InfoS("Failed to update status for pod", "pod", klog.KObj(pod), "err", err)
				errs = append(errs, err)
			}
			// record NodeNotReady event after updateStatus to make sure pod still exists
			recorder.Event(pod, v1.EventTypeWarning, "NodeNotReady", "Node is not ready")
			break
		}
	}

	return utilerrors.NewAggregate(errs)
}
```

## doNoExecuteTaintingPass

```GO
// 处理被标记为 noexecute 的 Pod
func (nc *Controller) doNoExecuteTaintingPass(ctx context.Context) {
	// Extract out the keys of the map in order to not hold
	// the evictorLock for the entire function and hold it
	// only when nescessary.
	var zoneNoExecuteTainterKeys []string
    // 取出zoneNoExecuteTainter的key 加入zoneNoExecuteTainterKeys 使用匿名函数的原因是要加锁
	func() {
		nc.evictorLock.Lock()
		defer nc.evictorLock.Unlock()

		zoneNoExecuteTainterKeys = make([]string, 0, len(nc.zoneNoExecuteTainter))
		for k := range nc.zoneNoExecuteTainter {
			zoneNoExecuteTainterKeys = append(zoneNoExecuteTainterKeys, k)
		}
	}()
	for _, k := range zoneNoExecuteTainterKeys {
        // 获取worker
		var zoneNoExecuteTainterWorker *scheduler.RateLimitedTimedQueue
		func() {
			nc.evictorLock.Lock()
			defer nc.evictorLock.Unlock()
			// Extracting the value without checking if the key
			// exists or not is safe to do here since zones do
			// not get removed, and consequently pod evictors for
			// these zones also do not get removed, only added.
			zoneNoExecuteTainterWorker = nc.zoneNoExecuteTainter[k]
		}()
		// 执行函数
		zoneNoExecuteTainterWorker.Try(func(value scheduler.TimedValue) (bool, time.Duration) {
           	// 从lister获取node
			node, err := nc.nodeLister.Get(value.Value)
			if apierrors.IsNotFound(err) {
				klog.Warningf("Node %v no longer present in nodeLister!", value.Value)
				return true, 0
			} else if err != nil {
				klog.Warningf("Failed to get Node %v from the nodeLister: %v", value.Value, err)
				// retry in 50 millisecond
				return false, 50 * time.Millisecond
			}
            // 获取node的node的contione
			_, condition := controllerutil.GetNodeCondition(&node.Status, v1.NodeReady)
			// Because we want to mimic NodeStatus.Condition["Ready"] we make "unreachable" and "not ready" taints mutually exclusive.
			taintToAdd := v1.Taint{}
			oppositeTaint := v1.Taint{}
			switch condition.Status {
			case v1.ConditionFalse:
                // 状态为“false”，则添加“not ready”污点并移除“unreachable”污点
				taintToAdd = *NotReadyTaintTemplate
				oppositeTaint = *UnreachableTaintTemplate
			case v1.ConditionUnknown:
                // 状态为"Unknown" 添加“unreachable”污点并移除“not ready”污点
				taintToAdd = *UnreachableTaintTemplate
				oppositeTaint = *NotReadyTaintTemplate
			default:
                // 节点状态为“true”，则不进行任何操作
				// It seems that the Node is ready again, so there's no need to taint it.
				klog.V(4).Infof("Node %v was in a taint queue, but it's ready now. Ignoring taint request.", value.Value)
				return true, 0
			}
            // 根据选择的污点添加或移除污点
			result := controllerutil.SwapNodeControllerTaint(ctx, nc.kubeClient, []*v1.Taint{&taintToAdd}, []*v1.Taint{&oppositeTaint}, node)
			if result {
                // 如果成功添加或移除了污点，则计算并记录相应区域的驱逐数和驱逐总数
				zone := nodetopology.GetZoneKey(node)
				evictionsNumber.WithLabelValues(zone).Inc()
				evictionsTotal.WithLabelValues(zone).Inc()
			}

			return result, 0
		})
	}
}

func GetZoneKey(node *v1.Node) string {
	labels := node.Labels
	if labels == nil {
		return ""
	}

	// TODO: "failure-domain.beta..." names are deprecated, but will
	// stick around a long time due to existing on old extant objects like PVs.
	// Maybe one day we can stop considering them (see #88493).
	zone, ok := labels[v1.LabelFailureDomainBetaZone]
	if !ok {
		zone, _ = labels[v1.LabelTopologyZone]
	}

	region, ok := labels[v1.LabelFailureDomainBetaRegion]
	if !ok {
		region, _ = labels[v1.LabelTopologyRegion]
	}

	if region == "" && zone == "" {
		return ""
	}

	// We include the null character just in case region or failureDomain has a colon
	// (We do assume there's no null characters in a region or failureDomain)
	// As a nice side-benefit, the null character is not printed by fmt.Print or glog
	return region + ":\x00:" + zone
}

```

## doEvictionPass

```go
// 节点驱逐功能
func (nc *Controller) doEvictionPass(ctx context.Context) {
	//  添加所有zone key
	var zonePodEvictorKeys []string
	func() {
		nc.evictorLock.Lock()
		defer nc.evictorLock.Unlock()

		zonePodEvictorKeys = make([]string, 0, len(nc.zonePodEvictor))
		for k := range nc.zonePodEvictor {
			zonePodEvictorKeys = append(zonePodEvictorKeys, k)
		}
	}()

	for _, k := range zonePodEvictorKeys {
		var zonePodEvictionWorker *scheduler.RateLimitedTimedQueue
		func() {
			nc.evictorLock.Lock()
			defer nc.evictorLock.Unlock()
			// Extracting the value without checking if the key
			// exists or not is safe to do here since zones do
			// not get removed, and consequently pod evictors for
			// these zones also do not get removed, only added.
			zonePodEvictionWorker = nc.zonePodEvictor[k]
		}()

		// Function should return 'false' and a time after which it should be retried, or 'true' if it shouldn't (it succeeded).
		zonePodEvictionWorker.Try(func(value scheduler.TimedValue) (bool, time.Duration) {
            // 从lister获取node
			node, err := nc.nodeLister.Get(value.Value)
			if apierrors.IsNotFound(err) {
				klog.Warningf("Node %v no longer present in nodeLister!", value.Value)
			} else if err != nil {
				klog.Warningf("Failed to get Node %v from the nodeLister: %v", value.Value, err)
			}
			nodeUID, _ := value.UID.(string)
            // 获取这个node上的所有pod
			pods, err := nc.getPodsAssignedToNode(value.Value)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to list pods from node %q: %v", value.Value, err))
				return false, 0
			}
            // 删除这些pods
			remaining, err := controllerutil.DeletePods(ctx, nc.kubeClient, pods, nc.recorder, value.Value, nodeUID, nc.daemonSetStore)
			if err != nil {
				// We are not setting eviction status here.
				// New pods will be handled by zonePodEvictor retry
				// instead of immediate pod eviction.
				utilruntime.HandleError(fmt.Errorf("unable to evict node %q: %v", value.Value, err))
				return false, 0
			}
            // 设置pod状态 已经驱逐过了
			if !nc.nodeEvictionMap.setStatus(value.Value, evicted) {
				klog.V(2).Infof("node %v was unregistered in the meantime - skipping setting status", value.Value)
			}
			if remaining {
				klog.Infof("Pods awaiting deletion due to Controller eviction")
			}

			if node != nil {
				zone := nodetopology.GetZoneKey(node)
				evictionsNumber.WithLabelValues(zone).Inc()
				evictionsTotal.WithLabelValues(zone).Inc()
			}

			return true, 0
		})
	}
}
```

## monitorNodeHealth

```GO
func (nc *Controller) monitorNodeHealth(ctx context.Context) error {
	start := nc.now()
	defer func() {
		updateAllNodesHealthDuration.Observe(time.Since(start.Time).Seconds())
	}()

	// 取出nodes
	nodes, err := nc.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
    // 获取了新添加的节点列表added，删除的节点列表deleted和代表新区域的节点列表newZoneRepresentatives。
	added, deleted, newZoneRepresentatives := nc.classifyNodes(nodes)
	
    // 对于新添加的区域，为其添加Pod驱逐器
	for i := range newZoneRepresentatives {
		nc.addPodEvictorForNewZone(newZoneRepresentatives[i])
	}

	for i := range added {
		klog.V(1).Infof("Controller observed a new Node: %#v", added[i].Name)
		controllerutil.RecordNodeEvent(nc.recorder, added[i].Name, string(added[i].UID), v1.EventTypeNormal, "RegisteredNode", fmt.Sprintf("Registered Node %v in Controller", added[i].Name))
        // 新节点添加到nc.knownNodeSet
		nc.knownNodeSet[added[i].Name] = added[i]
        // 将该节点添加到相应的分区驱逐队列中。
		nc.addPodEvictorForNewZone(added[i])
		if nc.runTaintManager {
            // 该节点可到达
			nc.markNodeAsReachable(ctx, added[i])
		} else {
            // 不对该节点进行驱逐
			nc.cancelPodEviction(added[i])
		}
	}

	for i := range deleted {
		klog.V(1).Infof("Controller observed a Node deletion: %v", deleted[i].Name)
		controllerutil.RecordNodeEvent(nc.recorder, deleted[i].Name, string(deleted[i].UID), v1.EventTypeNormal, "RemovingNode", fmt.Sprintf("Removing Node %v from Controller", deleted[i].Name))
        // 从knownNodeSet删除
		delete(nc.knownNodeSet, deleted[i].Name)
	}

	var zoneToNodeConditionsLock sync.Mutex
	zoneToNodeConditions := map[string][]*v1.NodeCondition{}
	updateNodeFunc := func(piece int) {
        // 记录开始时间并在函数执行完毕时记录更新节点健康状态的耗时
		start := nc.now()
		defer func() {
			updateNodeHealthDuration.Observe(time.Since(start.Time).Seconds())
		}()

		var gracePeriod time.Duration
		var observedReadyCondition v1.NodeCondition
		var currentReadyCondition *v1.NodeCondition
		node := nodes[piece].DeepCopy()
		// 更新节点的健康状态
		if err := wait.PollImmediate(retrySleepTime, retrySleepTime*scheduler.NodeHealthUpdateRetry, func() (bool, error) {
			var err error
			gracePeriod, observedReadyCondition, currentReadyCondition, err = nc.tryUpdateNodeHealth(ctx, node)
			if err == nil {
				return true, nil
			}
			name := node.Name
			node, err = nc.kubeClient.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
			if err != nil {
                //  如果失败了 打印日志退出
				klog.Errorf("Failed while getting a Node to retry updating node health. Probably Node %s was deleted.", name)
				return false, err
			}
			return false, nil
		}); err != nil {
			klog.Errorf("Update health of Node '%v' from Controller error: %v. "+
				"Skipping - no pods will be evicted.", node.Name, err)
			return
		}

		// 将节点加入到 zoneToNodeConditions 中，如果节点不在排除列表中。
		if !isNodeExcludedFromDisruptionChecks(node) {
			zoneToNodeConditionsLock.Lock()
			zoneToNodeConditions[nodetopology.GetZoneKey(node)] = append(zoneToNodeConditions[nodetopology.GetZoneKey(node)], currentReadyCondition)
			zoneToNodeConditionsLock.Unlock()
		}

		if currentReadyCondition != nil {
            // 没有拿到Ready 就是节点有问题了 获取节点的所有pod
			pods, err := nc.getPodsAssignedToNode(node.Name)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("unable to list pods of node %v: %v", node.Name, err))
				if currentReadyCondition.Status != v1.ConditionTrue && observedReadyCondition.Status == v1.ConditionTrue {
					// If error happened during node status transition (Ready -> NotReady)
					// we need to mark node for retry to force MarkPodsNotReady execution
					// in the next iteration.
					nc.nodesToRetry.Store(node.Name, struct{}{})
				}
				return
			}
			if nc.runTaintManager {
                // 用于处理有 Taint 的情况下节点中的 Pod 被逐出的逻辑
				nc.processTaintBaseEviction(ctx, node, &observedReadyCondition)
			} else {
                // 用于处理没有 Taint 的情况下节点中的 Pod 被逐出的逻辑
				if err := nc.processNoTaintBaseEviction(ctx, node, &observedReadyCondition, gracePeriod, pods); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to evict all pods from node %v: %v; queuing for retry", node.Name, err))
				}
			}
			
            // 从nodesToRetry拿值
			_, needsRetry := nc.nodesToRetry.Load(node.Name)
			switch {
			case currentReadyCondition.Status != v1.ConditionTrue && observedReadyCondition.Status == v1.ConditionTrue:
				// 节点的状态不是ready 并且之前的也不ready 设置成notready
				controllerutil.RecordNodeStatusChange(nc.recorder, node, "NodeNotReady")
				fallthrough
			case needsRetry && observedReadyCondition.Status != v1.ConditionTrue:
                // 节点需要重试 并且现在的状态不是ready 将所有 Pod 标记为 NotReady 
				if err = controllerutil.MarkPodsNotReady(ctx, nc.kubeClient, nc.recorder, pods, node.Name); err != nil {
					utilruntime.HandleError(fmt.Errorf("unable to mark all pods NotReady on node %v: %v; queuing for retry", node.Name, err))
                    // 出错了 再加回去继续重试
					nc.nodesToRetry.Store(node.Name, struct{}{})
					return
				}
			}
		}
		nc.nodesToRetry.Delete(node.Name)
	}

	// Marking the pods not ready on a node requires looping over them and
	// updating each pod's status one at a time. This is performed serially, and
	// can take a while if we're processing each node serially as well. So we
	// process them with bounded concurrency instead, since most of the time is
	// spent waiting on io.
	workqueue.ParallelizeUntil(ctx, nc.nodeUpdateWorkerSize, len(nodes), updateNodeFunc)

	nc.handleDisruption(ctx, zoneToNodeConditions, nodes)

	return nil
}
```

### addPodEvictorForNewZone

```go
func (nc *Controller) addPodEvictorForNewZone(node *v1.Node) {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
    // 获取节点所在的分区
	zone := nodetopology.GetZoneKey(node)
    // 如果nc.zoneStates[zone]不存在，则将stateInitial作为nc.zoneStates[zone]的值，表示当前分区的状态为初始化状态。
	if _, found := nc.zoneStates[zone]; !found {
		nc.zoneStates[zone] = stateInitial
        // 当runTaintManager为false时，将创建nc.zonePodEvictor[zone]作为分区的驱逐队列，
        // 并使用flowcontrol.NewTokenBucketRateLimiter创建速率有限的计时队列，限制分区的驱逐速率。
		if !nc.runTaintManager {
			nc.zonePodEvictor[zone] =
				scheduler.NewRateLimitedTimedQueue(
					flowcontrol.NewTokenBucketRateLimiter(nc.evictionLimiterQPS, scheduler.EvictionRateLimiterBurst))
		} else {
            // 当runTaintManager为true时，将创建nc.zoneNoExecuteTainter[zone]作为分区的驱逐队列，
            // 并使用flowcontrol.NewTokenBucketRateLimiter创建速率有限的计时队列，限制分区的驱逐速率。
			nc.zoneNoExecuteTainter[zone] =
				scheduler.NewRateLimitedTimedQueue(
					flowcontrol.NewTokenBucketRateLimiter(nc.evictionLimiterQPS, scheduler.EvictionRateLimiterBurst))
		}
		// Init the metric for the new zone.
		klog.Infof("Initializing eviction metric for zone: %v", zone)
		evictionsNumber.WithLabelValues(zone).Add(0)
		evictionsTotal.WithLabelValues(zone).Add(0)
	}
}
```

### markNodeAsReachable

```GO

func (nc *Controller) markNodeAsReachable(ctx context.Context, node *v1.Node) (bool, error) {
	// 节点上删除  UnreachableTaintTemplate 污点
    err := controller.RemoveTaintOffNode(ctx, nc.kubeClient, node.Name, node, UnreachableTaintTemplate)
	if err != nil {
		klog.Errorf("Failed to remove taint from node %v: %v", node.Name, err)
		return false, err
	}
    // 节点上删除  NotReadyTaintTemplate 污点
	err = controller.RemoveTaintOffNode(ctx, nc.kubeClient, node.Name, node, NotReadyTaintTemplate)
	if err != nil {
		klog.Errorf("Failed to remove taint from node %v: %v", node.Name, err)
		return false, err
	}
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	
    // 从nc.zoneNoExecuteTainter删除node
	return nc.zoneNoExecuteTainter[nodetopology.GetZoneKey(node)].Remove(node.Name), nil
}


```

### cancelPodEviction

```GO
func (nc *Controller) cancelPodEviction(node *v1.Node) bool {
    // 获取zone 并把状态设置成unmark
	zone := nodetopology.GetZoneKey(node)
	if !nc.nodeEvictionMap.setStatus(node.Name, unmarked) {
		klog.V(2).Infof("node %v was unregistered in the meantime - skipping setting status", node.Name)
	}
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
    // 是不是正在驱逐
	wasDeleting := nc.zonePodEvictor[zone].Remove(node.Name)
	if wasDeleting {
		klog.V(2).Infof("Cancelling pod Eviction on Node: %v", node.Name)
		return true
	}
	return false
}
```

### tryUpdateNodeHealth

```go
func (nc *Controller) tryUpdateNodeHealth(ctx context.Context, node *v1.Node) (time.Duration, v1.NodeCondition, *v1.NodeCondition, error) {
    // 获取node的健康状况的深拷贝。在函数结束时，会使用nodeHealthMap将nodeHealth更新到nodeHealthMap中。
	nodeHealth := nc.nodeHealthMap.getDeepCopy(node.Name)
	defer func() {
		nc.nodeHealthMap.set(node.Name, nodeHealth)
	}()

	var gracePeriod time.Duration
	var observedReadyCondition v1.NodeCondition
    // 获取现在node的健康状态
	_, currentReadyCondition := controllerutil.GetNodeCondition(&node.Status, v1.NodeReady)
	if currentReadyCondition == nil {
		// 如果当前是空 设置一个ready unknown
		observedReadyCondition = v1.NodeCondition{
			Type:               v1.NodeReady,
			Status:             v1.ConditionUnknown,
			LastHeartbeatTime:  node.CreationTimestamp,
			LastTransitionTime: node.CreationTimestamp,
		}
        // gracePeriod使用nodeStartupGracePeriod 不ready使用这个是因为
        // 避免在节点刚启动时就对其进行调度和驱逐操作
		gracePeriod = nc.nodeStartupGracePeriod
		if nodeHealth != nil {
            // 如果不能空 设置status
			nodeHealth.status = &node.Status
		} else {
            // 如果是空 重新赋值
			nodeHealth = &nodeHealthData{
				status:                   &node.Status,
				probeTimestamp:           node.CreationTimestamp,
				readyTransitionTimestamp: node.CreationTimestamp,
			}
		}
	} else {
		// 如果现在ready 设置observedReadyCondition gracePeriod使用nodeMonitorGracePeriod 
		observedReadyCondition = *currentReadyCondition
		gracePeriod = nc.nodeMonitorGracePeriod
	}
	
	var savedCondition *v1.NodeCondition
	var savedLease *coordv1.Lease
	if nodeHealth != nil {
        // 如果nodeHealth不是空 nodeHealth取NodeReady
		_, savedCondition = controllerutil.GetNodeCondition(nodeHealth.status, v1.NodeReady)
        // 将 Node 的租约存储在 savedLease 中
		savedLease = nodeHealth.lease
	}

	if nodeHealth == nil {
        // 如果 nodeHealth 为 nil，则表示当前节点的状态没有被记录，将其记录到 nodeHealth 中，以便后续检查节点的状态
		klog.Warningf("Missing timestamp for Node %s. Assuming now as a timestamp.", node.Name)
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: nc.now(),
		}
	} else if savedCondition == nil && currentReadyCondition != nil {
        // 如果 savedCondition 为 nil，但 currentReadyCondition 不为 nil，则创建时间戳条目
		klog.V(1).Infof("Creating timestamp entry for newly observed Node %s", node.Name)
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: nc.now(),
		}
	} else if savedCondition != nil && currentReadyCondition == nil {
        // 如果 savedCondition 不为 nil，但 currentReadyCondition 为 nil，则表示 Node 的状态已经更新。
		klog.Errorf("ReadyCondition was removed from Status of Node %s", node.Name)
		// TODO: figure out what to do in this case. For now we do the same thing as above.
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: nc.now(),
		}
	} else if savedCondition != nil && currentReadyCondition != nil && savedCondition.LastHeartbeatTime != currentReadyCondition.LastHeartbeatTime {
        // 如果 savedCondition 和 currentReadyCondition 都不为 nil，并且 savedCondition 的 LastHeartbeatTime 与 currentReadyCondition 的 LastHeartbeatTime 不同，则更新 Node 的状态条件和时间戳。
		var transitionTime metav1.Time
		// If ReadyCondition changed since the last time we checked, we update the transition timestamp to "now",
		// otherwise we leave it as it is.
		if savedCondition.LastTransitionTime != currentReadyCondition.LastTransitionTime {
			klog.V(3).Infof("ReadyCondition for Node %s transitioned from %v to %v", node.Name, savedCondition, currentReadyCondition)
			transitionTime = nc.now()
		} else {
			transitionTime = nodeHealth.readyTransitionTimestamp
		}
		if klogV := klog.V(5); klogV.Enabled() {
			klogV.Infof("Node %s ReadyCondition updated. Updating timestamp: %+v vs %+v.", node.Name, nodeHealth.status, node.Status)
		} else {
			klog.V(3).Infof("Node %s ReadyCondition updated. Updating timestamp.", node.Name)
		}
		nodeHealth = &nodeHealthData{
			status:                   &node.Status,
			probeTimestamp:           nc.now(),
			readyTransitionTimestamp: transitionTime,
		}
	}
	// 获取租约信息
	observedLease, _ := nc.leaseLister.Leases(v1.NamespaceNodeLease).Get(node.Name)
	if observedLease != nil && (savedLease == nil || savedLease.Spec.RenewTime.Before(observedLease.Spec.RenewTime)) {
        // 如果节点目前的lease不是空的 并且 之前的也是空或者 之前的RenewTime在新的之前
        // 更新lease和probeTimestamp
		nodeHealth.lease = observedLease
		nodeHealth.probeTimestamp = nc.now()
	}
	
    
	if nc.now().After(nodeHealth.probeTimestamp.Add(gracePeriod)) {
		// 当前时间晚于 nodeHealth.probeTimestamp 加上 gracePeriod probe时间到了

		nodeConditionTypes := []v1.NodeConditionType{
			v1.NodeReady,
			v1.NodeMemoryPressure,
			v1.NodeDiskPressure,
			v1.NodePIDPressure,
			// We don't change 'NodeNetworkUnavailable' condition, as it's managed on a control plane level.
			// v1.NodeNetworkUnavailable,
		}

		nowTimestamp := nc.now()
		for _, nodeConditionType := range nodeConditionTypes {
            // 判断有没有nodeConditionType得条件
			_, currentCondition := controllerutil.GetNodeCondition(&node.Status, nodeConditionType)
			if currentCondition == nil {
				klog.V(2).Infof("Condition %v of node %v was never updated by kubelet", nodeConditionType, node.Name)
                // 没有就加一个Unknown的nodeConditionType
				node.Status.Conditions = append(node.Status.Conditions, v1.NodeCondition{
					Type:               nodeConditionType,
					Status:             v1.ConditionUnknown,
					Reason:             "NodeStatusNeverUpdated",
					Message:            "Kubelet never posted node status.",
					LastHeartbeatTime:  node.CreationTimestamp,
					LastTransitionTime: nowTimestamp,
				})
			} else {
				klog.V(2).Infof("node %v hasn't been updated for %+v. Last %v is: %+v",
					node.Name, nc.now().Time.Sub(nodeHealth.probeTimestamp.Time), nodeConditionType, currentCondition)
                // 如果有就更新一些状态
				if currentCondition.Status != v1.ConditionUnknown {
					currentCondition.Status = v1.ConditionUnknown
					currentCondition.Reason = "NodeStatusUnknown"
					currentCondition.Message = "Kubelet stopped posting node status."
					currentCondition.LastTransitionTime = nowTimestamp
				}
			}
		}

        // 更新Condition 
		_, currentReadyCondition = controllerutil.GetNodeCondition(&node.Status, v1.NodeReady)

		if !apiequality.Semantic.DeepEqual(currentReadyCondition, &observedReadyCondition) {
            // 不相等了 就更新一下
			if _, err := nc.kubeClient.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{}); err != nil {
				klog.Errorf("Error updating node %s: %v", node.Name, err)
				return gracePeriod, observedReadyCondition, currentReadyCondition, err
			}
			nodeHealth = &nodeHealthData{
				status:                   &node.Status,
				probeTimestamp:           nodeHealth.probeTimestamp,
				readyTransitionTimestamp: nc.now(),
				lease:                    observedLease,
			}
			return gracePeriod, observedReadyCondition, currentReadyCondition, nil
		}
	}

	return gracePeriod, observedReadyCondition, currentReadyCondition, nil
}

```

### processTaintBaseEviction

```GO
func (nc *Controller) processTaintBaseEviction(ctx context.Context, node *v1.Node, observedReadyCondition *v1.NodeCondition) {
	decisionTimestamp := nc.now()
	// Check eviction timeout against decisionTimestamp
	switch observedReadyCondition.Status {
	case v1.ConditionFalse:
		// We want to update the taint straight away if Node is already tainted with the UnreachableTaint
		if taintutils.TaintExists(node.Spec.Taints, UnreachableTaintTemplate) {
            // 如果节点condition存在 Unreachable 标记为NotReady
			taintToAdd := *NotReadyTaintTemplate
            // 交换节点的污点信息
			if !controllerutil.SwapNodeControllerTaint(ctx, nc.kubeClient, []*v1.Taint{&taintToAdd}, []*v1.Taint{UnreachableTaintTemplate}, node) {
				klog.Errorf("Failed to instantly swap UnreachableTaint to NotReadyTaint. Will try again in the next cycle.")
			}
		} else if nc.markNodeForTainting(node, v1.NotReadyTaint) {
            // 如果没有 就标记成NotReadyTaint
			klog.V(2).Infof("Node %v is NotReady as of %v. Adding it to the Taint queue.",
				node.Name,
				decisionTimestamp,
			)
		}
	case v1.ConditionUnknown:
		// We want to update the taint straight away if Node is already tainted with the UnreachableTaint
		if taintutils.TaintExists(node.Spec.Taints, NotReadyTaintTemplate) {
            // 节点已经被标记为 NotReadyTaint，则立即将其标记为 UnreachableTaint
			taintToAdd := *UnreachableTaintTemplate
			if !controllerutil.SwapNodeControllerTaint(ctx, nc.kubeClient, []*v1.Taint{&taintToAdd}, []*v1.Taint{NotReadyTaintTemplate}, node) {
				klog.Errorf("Failed to instantly swap NotReadyTaint to UnreachableTaint. Will try again in the next cycle.")
			}
		} else if nc.markNodeForTainting(node, v1.ConditionUnknown) {
            // 将节点标记为 NotReadyTaint。
			klog.V(2).Infof("Node %v is unresponsive as of %v. Adding it to the Taint queue.",
				node.Name,
				decisionTimestamp,
			)
		}
	case v1.ConditionTrue:
        // 标记为可达状态
		removed, err := nc.markNodeAsReachable(ctx, node)
		if err != nil {
			klog.Errorf("Failed to remove taints from node %v. Will retry in next iteration.", node.Name)
		}
		if removed {
			klog.V(2).Infof("Node %s is healthy again, removing all taints", node.Name)
		}
	}
}

```

#### markNodeForTainting

```GO
func (nc *Controller) markNodeForTainting(node *v1.Node, status v1.ConditionStatus) bool {
	nc.evictorLock.Lock()
	defer nc.evictorLock.Unlock()
	if status == v1.ConditionFalse {
		if !taintutils.TaintExists(node.Spec.Taints, NotReadyTaintTemplate) {
			nc.zoneNoExecuteTainter[nodetopology.GetZoneKey(node)].Remove(node.Name)
		}
	}

	if status == v1.ConditionUnknown {
		if !taintutils.TaintExists(node.Spec.Taints, UnreachableTaintTemplate) {
			nc.zoneNoExecuteTainter[nodetopology.GetZoneKey(node)].Remove(node.Name)
		}
	}

	return nc.zoneNoExecuteTainter[nodetopology.GetZoneKey(node)].Add(node.Name, string(node.UID))
}
```

### handleDisruption

```GO
func (nc *Controller) handleDisruption(ctx context.Context, zoneToNodeConditions map[string][]*v1.NodeCondition, nodes []*v1.Node) {
	newZoneStates := map[string]ZoneState{}
    // 获取状态 只要有一个不是stateFullDisruption 就是false 代表还是有可用的 是true就没用可用的了
	allAreFullyDisrupted := true
	for k, v := range zoneToNodeConditions {
		zoneSize.WithLabelValues(k).Set(float64(len(v)))
		unhealthy, newState := nc.computeZoneStateFunc(v)
		zoneHealth.WithLabelValues(k).Set(float64(100*(len(v)-unhealthy)) / float64(len(v)))
		unhealthyNodes.WithLabelValues(k).Set(float64(unhealthy))
		if newState != stateFullDisruption {
			allAreFullyDisrupted = false
		}
		newZoneStates[k] = newState
		if _, had := nc.zoneStates[k]; !had {
			klog.Errorf("Setting initial state for unseen zone: %v", k)
			nc.zoneStates[k] = stateInitial
		}
	}
	
    // 获取上次记录状态 只要有一个不是stateFullDisruption 就是false 代表还是有可用的 是true就没用可用的了
	allWasFullyDisrupted := true
	for k, v := range nc.zoneStates {
		if _, have := zoneToNodeConditions[k]; !have {
			zoneSize.WithLabelValues(k).Set(0)
			zoneHealth.WithLabelValues(k).Set(100)
			unhealthyNodes.WithLabelValues(k).Set(0)
			delete(nc.zoneStates, k)
			continue
		}
		if v != stateFullDisruption {
			allWasFullyDisrupted = false
			break
		}
	}


    // 判断是否需要更新 limiter。如果 allAreFullyDisrupted 或 allWasFullyDisrupted 为 false，
    // 则表示之前的状态中至少有一个节点处于可用状态，此时需要更新 limiter。
	if !allAreFullyDisrupted || !allWasFullyDisrupted {
		// We're switching to full disruption mode
		if allAreFullyDisrupted {
			klog.Info("Controller detected that all Nodes are not-Ready. Entering master disruption mode.")
			for i := range nodes {
				if nc.runTaintManager {
                    // 表示所有节点都不可用，此时进入全局驱逐模式，取消所有的 Pod 驱逐操作并停止所有的驱逐操作
					_, err := nc.markNodeAsReachable(ctx, nodes[i])
					if err != nil {
						klog.Errorf("Failed to remove taints from Node %v", nodes[i].Name)
					}
				} else {
					nc.cancelPodEviction(nodes[i])
				}
			}
			// We stop all evictions.
			for k := range nc.zoneStates {
				if nc.runTaintManager {
					nc.zoneNoExecuteTainter[k].SwapLimiter(0)
				} else {
					nc.zonePodEvictor[k].SwapLimiter(0)
				}
			}
            // 将所有区域的状态更新为 stateFullDisruption。
			for k := range nc.zoneStates {
				nc.zoneStates[k] = stateFullDisruption
			}
			// All rate limiters are updated, so we can return early here.
			return
		}
		// We're exiting full disruption mode
		if allWasFullyDisrupted {
            // 所有节点都之前都不可用，此时退出全局驱逐模式，更新节点健康状态，
            // 并根据 newZoneStates 中相应区域的状态更新 limiter
			klog.Info("Controller detected that some Nodes are Ready. Exiting master disruption mode.")
			// When exiting disruption mode update probe timestamps on all Nodes.
			now := nc.now()
			for i := range nodes {
				v := nc.nodeHealthMap.getDeepCopy(nodes[i].Name)
				v.probeTimestamp = now
				v.readyTransitionTimestamp = now
				nc.nodeHealthMap.set(nodes[i].Name, v)
			}
			// We reset all rate limiters to settings appropriate for the given state.
			for k := range nc.zoneStates {
				nc.setLimiterInZone(k, len(zoneToNodeConditions[k]), newZoneStates[k])
				nc.zoneStates[k] = newZoneStates[k]
			}
			return
		}
		// 如果 allAreFullyDisrupted 和 allWasFullyDisrupted 都为 false，
        // 则需要根据 newZoneStates 中相应区域的状态更新 limiter
		for k, v := range nc.zoneStates {
			newState := newZoneStates[k]
			if v == newState {
				continue
			}
			klog.Infof("Controller detected that zone %v is now in state %v.", k, newState)
			nc.setLimiterInZone(k, len(zoneToNodeConditions[k]), newState)
			nc.zoneStates[k] = newState
		}
	}
}

const (
	stateInitial           = ZoneState("Initial")
	stateNormal            = ZoneState("Normal")
	stateFullDisruption    = ZoneState("FullDisruption")
	statePartialDisruption = ZoneState("PartialDisruption")
)

func (nc *Controller) ComputeZoneState(nodeReadyConditions []*v1.NodeCondition) (int, ZoneState) {
	readyNodes := 0
	notReadyNodes := 0
	for i := range nodeReadyConditions {
		if nodeReadyConditions[i] != nil && nodeReadyConditions[i].Status == v1.ConditionTrue {
			readyNodes++
		} else {
			notReadyNodes++
		}
	}
	switch {
	case readyNodes == 0 && notReadyNodes > 0:
		return notReadyNodes, stateFullDisruption
	case notReadyNodes > 2 && float32(notReadyNodes)/float32(notReadyNodes+readyNodes) >= nc.unhealthyZoneThreshold:
		return notReadyNodes, statePartialDisruption
	default:
		return notReadyNodes, stateNormal
	}
}
```



## 处理node污点

### SwapNodeControllerTaint

对一个节点的污点进行交换操作：

```go
func SwapNodeControllerTaint(ctx context.Context, kubeClient clientset.Interface, taintsToAdd, taintsToRemove []*v1.Taint, node *v1.Node) bool {
	for _, taintToAdd := range taintsToAdd {
		now := metav1.Now()
		taintToAdd.TimeAdded = &now
	}
	
    // 向节点添加 taint
	err := controller.AddOrUpdateTaintOnNode(ctx, kubeClient, node.Name, taintsToAdd...)
	if err != nil {
		utilruntime.HandleError(
			fmt.Errorf(
				"unable to taint %+v unresponsive Node %q: %v",
				taintsToAdd,
				node.Name,
				err))
		return false
	}
	klog.V(4).InfoS("Added taint to node", "taint", taintsToAdd, "node", node.Name)
	
    // 从节点删除 taint
	err = controller.RemoveTaintOffNode(ctx, kubeClient, node.Name, node, taintsToRemove...)
	if err != nil {
		utilruntime.HandleError(
			fmt.Errorf(
				"unable to remove %+v unneeded taint from unresponsive Node %q: %v",
				taintsToRemove,
				node.Name,
				err))
		return false
	}
	klog.V(4).InfoS("Made sure that node has no taint", "node", node.Name, "taint", taintsToRemove)

	return true
}
```

### AddOrUpdateTaintOnNode

```go
func AddOrUpdateTaintOnNode(ctx context.Context, c clientset.Interface, nodeName string, 
                            taints ...*v1.Taint) error {
	// 没有污点 要添加 直接返回
    if len(taints) == 0 {
		return nil
	}
    // 第一次尝试
	firstTry := true
    // RetryOnConflict 是发生冲突时 进行重试 之前的namespace-controller介绍过
	return clientretry.RetryOnConflict(UpdateTaintBackoff, func() error {
		var err error
		var oldNode *v1.Node
		// First we try getting node from the API server cache, as it's cheaper. If it fails
		// we get it from etcd to be sure to have fresh data.
		option := metav1.GetOptions{}
		if firstTry {
			option.ResourceVersion = "0"
			firstTry = false
		}
        // 获取node
		oldNode, err = c.CoreV1().Nodes().Get(ctx, nodeName, option)
		if err != nil {
			return err
		}

		var newNode *v1.Node
		oldNodeCopy := oldNode
		updated := false
		for _, taint := range taints {
            // 进行更新或添加
			curNewNode, ok, err := taintutils.AddOrUpdateTaint(oldNodeCopy, taint)
			if err != nil {
				return fmt.Errorf("failed to update taint of node")
			}
            // 其中有一个更新了 那就是更新了
			updated = updated || ok
            // newNode 是刚返回进行更新或添加污点的 node
			newNode = curNewNode
			oldNodeCopy = curNewNode
		}
        // 如果没有更新 直接返回
		if !updated {
			return nil
		}
        // 将一个Node上的taints更新到一个新的taints列表。
		return PatchNodeTaints(ctx, c, nodeName, oldNode, newNode)
	})
}
```

#### AddOrUpdateTaint

```GO
func AddOrUpdateTaint(node *v1.Node, taint *v1.Taint) (*v1.Node, bool, error) {
	newNode := node.DeepCopy()
	nodeTaints := newNode.Spec.Taints

	var newTaints []v1.Taint
    // 是否更新了污点信息
	updated := false
	for i := range nodeTaints {
        // 如果污点与新节点的某个现有污点匹配
		if taint.MatchTaint(&nodeTaints[i]) {
            // 新污点与现有污点相同
			if helper.Semantic.DeepEqual(*taint, nodeTaints[i]) {
				return newNode, false, nil
			}
            // 将新污点添加到新污点列表中
			newTaints = append(newTaints, *taint)
			updated = true
			continue
		}
		
        // 将现有污点添加到新污点列表中
		newTaints = append(newTaints, nodeTaints[i])
	}
	
	if !updated {
        // 将新污点添加到新污点列表中
		newTaints = append(newTaints, *taint)
	}

	newNode.Spec.Taints = newTaints
	return newNode, true, nil
}
```

#### PatchNodeTaints

```go
func PatchNodeTaints(ctx context.Context, c clientset.Interface, nodeName string, oldNode *v1.Node, newNode *v1.Node) error {
	// 深度复制旧节点，并将其版本设置为""
	oldNodeNoRV := oldNode.DeepCopy()
	oldNodeNoRV.ResourceVersion = ""
    // 将旧节点转换为 JSON 格式的字节数组
	oldDataNoRV, err := json.Marshal(&oldNodeNoRV)
	if err != nil {
		return fmt.Errorf("failed to marshal old node %#v for node %q: %v", oldNodeNoRV, nodeName, err)
	}
	
    // 从新节点中提取taints列表，并将其设置为旧节点的克隆的taints列表。将新节点转换为 JSON 格式的字节数组。
	newTaints := newNode.Spec.Taints
	newNodeClone := oldNode.DeepCopy()
	newNodeClone.Spec.Taints = newTaints
	newData, err := json.Marshal(newNodeClone)
	if err != nil {
		return fmt.Errorf("failed to marshal new node %#v for node %q: %v", newNodeClone, nodeName, err)
	}
	
    // 创建一个新的 JSON Patch 字节数组，用于将旧节点更新为新节点
	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldDataNoRV, newData, v1.Node{})
	if err != nil {
		return fmt.Errorf("failed to create patch for node %q: %v", nodeName, err)
	}
	
    // 使用Patch更新
	_, err = c.CoreV1().Nodes().Patch(ctx, nodeName, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}
```

### RemoveTaintOffNode

```go
func RemoveTaintOffNode(ctx context.Context, c clientset.Interface, nodeName string, node *v1.Node, 
                        taints ...*v1.Taint) error {
	if len(taints) == 0 {
		return nil
	}
	// 检查节点是否包含需要删除的污点，如果不包含，则直接返回
	if node != nil {
		match := false
		for _, taint := range taints {
			if taintutils.TaintExists(node.Spec.Taints, taint) {
				match = true
				break
			}
		}
		if !match {
			return nil
		}
	}

	firstTry := true
	return clientretry.RetryOnConflict(UpdateTaintBackoff, func() error {
		var err error
		var oldNode *v1.Node
		// First we try getting node from the API server cache, as it's cheaper. If it fails
		// we get it from etcd to be sure to have fresh data.
		option := metav1.GetOptions{}
		if firstTry {
            // 设置版本
			option.ResourceVersion = "0"
			firstTry = false
		}
        // 获取node
		oldNode, err = c.CoreV1().Nodes().Get(ctx, nodeName, option)
		if err != nil {
			return err
		}
		
		var newNode *v1.Node
		oldNodeCopy := oldNode
		updated := false
		for _, taint := range taints {
            // 从节点中删除污点
			curNewNode, ok, err := taintutils.RemoveTaint(oldNodeCopy, taint)
			if err != nil {
				return fmt.Errorf("failed to remove taint of node")
			}
			updated = updated || ok
			newNode = curNewNode
			oldNodeCopy = curNewNode
		}
		if !updated {
			return nil
		}
        // 将一个Node上的taints更新到一个新的taints列表。
		return PatchNodeTaints(ctx, c, nodeName, oldNode, newNode)
	})
}
```

#### RemoveTaint

```go
// DeleteTaint removes all the taints that have the same key and effect to given taintToDelete.
func DeleteTaint(taints []v1.Taint, taintToDelete *v1.Taint) ([]v1.Taint, bool) {
	newTaints := []v1.Taint{}
	deleted := false
	for i := range taints {
		if taintToDelete.MatchTaint(&taints[i]) {
			deleted = true
			continue
		}
		newTaints = append(newTaints, taints[i])
	}
	return newTaints, deleted
}

// RemoveTaint tries to remove a taint from annotations list. Returns a new copy of updated Node and true if something was updated
// false otherwise.
func RemoveTaint(node *v1.Node, taint *v1.Taint) (*v1.Node, bool, error) {
	newNode := node.DeepCopy()
	nodeTaints := newNode.Spec.Taints
    // 如果没有污点 凡会
	if len(nodeTaints) == 0 {
		return newNode, false, nil
	}
	
    // 如果没找到这个污点 返回
	if !TaintExists(nodeTaints, taint) {
		return newNode, false, nil
	}
	
    // 删除污点
	newTaints, _ := DeleteTaint(nodeTaints, taint)
	newNode.Spec.Taints = newTaints
	return newNode, true, nil
}
```

## taintManager 

### 结构体

```go
type NoExecuteTaintManager struct {
	client                clientset.Interface
	broadcaster           record.EventBroadcaster
	recorder              record.EventRecorder
	podLister             corelisters.PodLister
	nodeLister            corelisters.NodeLister
    // 获取Node的Pod列表的函数
	getPodsAssignedToNode GetPodsByNodeNameFunc
	
    // 用于执行taint清除操作的定时工作队列
	taintEvictionQueue *TimedWorkerQueue
	// keeps a map from nodeName to all noExecute taints on that Node
	taintedNodesLock sync.Mutex
    // key:nodeName value:Taints
	taintedNodes     map[string][]v1.Taint
	
    // 工作channel 切片的原因是使用多个chan 让工作平均 不至于一个堵住 全就堵住了
	nodeUpdateChannels []chan nodeUpdateItem
	podUpdateChannels  []chan podUpdateItem

	nodeUpdateQueue workqueue.Interface
	podUpdateQueue  workqueue.Interface
}

type GetPodsByNodeNameFunc func(nodeName string) ([]*v1.Pod, error)
```

### Run

```GO
func (tc *NoExecuteTaintManager) Run(ctx context.Context) {
    // 处理panic
	defer utilruntime.HandleCrash()

	klog.InfoS("Starting NoExecuteTaintManager")

	// 启动事件处理管道，开始结构化记录日志。
	tc.broadcaster.StartStructuredLogging(0)
	if tc.client != nil {
        // 如果 tc.client 不为空，启动事件记录到 api server
		klog.InfoS("Sending events to api server")
		tc.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: tc.client.CoreV1().Events("")})
	} else {
        // 崩溃退出
		klog.Fatalf("kubeClient is nil when starting NodeController")
	}
    // 在函数退出时关闭事件广播器
	defer tc.broadcaster.Shutdown()
	// 关闭queue
	defer tc.nodeUpdateQueue.ShutDown()
	defer tc.podUpdateQueue.ShutDown()
	
    // 初始化 nodeUpdateChannels 和 podUpdateChannels，它们是用于处理节点和 Pod 的更新信息的通道。
    // 循环 UpdateWorkerSize 次，每次向两个通道列表中追加一个新通道。
	for i := 0; i < UpdateWorkerSize; i++ {
		tc.nodeUpdateChannels = append(tc.nodeUpdateChannels, make(chan nodeUpdateItem, NodeUpdateChannelSize))
		tc.podUpdateChannels = append(tc.podUpdateChannels, make(chan podUpdateItem, podUpdateChannelSize))
	}

	// 启动一个协程，从 nodeUpdateQueue 中读取节点更新信息，将其发送到对应的 nodeUpdateChannels 中的一个通道。
    // 这些通道将在后续的工作协程中处理。
	go func(stopCh <-chan struct{}) {
		for {
			item, shutdown := tc.nodeUpdateQueue.Get()
			if shutdown {
				break
			}
			nodeUpdate := item.(nodeUpdateItem)
			hash := hash(nodeUpdate.nodeName, UpdateWorkerSize)
			select {
			case <-stopCh:
				tc.nodeUpdateQueue.Done(item)
				return
			case tc.nodeUpdateChannels[hash] <- nodeUpdate:
				// tc.nodeUpdateQueue.Done is called by the nodeUpdateChannels worker
			}
		}
	}(ctx.Done())
	
    // 启动一个协程，从 podUpdateQueue 中读取节点更新信息，将其发送到对应的 podUpdateChannels 中的一个通道。
    // 这些通道将在后续的工作协程中处理。
	go func(stopCh <-chan struct{}) {
		for {
			item, shutdown := tc.podUpdateQueue.Get()
			if shutdown {
				break
			}
			// The fact that pods are processed by the same worker as nodes is used to avoid races
			// between node worker setting tc.taintedNodes and pod worker reading this to decide
			// whether to delete pod.
			// It's possible that even without this assumption this code is still correct.
			podUpdate := item.(podUpdateItem)
			hash := hash(podUpdate.nodeName, UpdateWorkerSize)
			select {
			case <-stopCh:
				tc.podUpdateQueue.Done(item)
				return
			case tc.podUpdateChannels[hash] <- podUpdate:
				// tc.podUpdateQueue.Done is called by the podUpdateChannels worker
			}
		}
	}(ctx.Done())

	wg := sync.WaitGroup{}
	wg.Add(UpdateWorkerSize)
	for i := 0; i < UpdateWorkerSize; i++ {
        // 启动UpdateWorkerSize个worker
		go tc.worker(ctx, i, wg.Done, ctx.Done())
	}
	wg.Wait()
}

// hash函数
func hash(val string, max int) int {
	hasher := fnv.New32a()
	io.WriteString(hasher, val)
	return int(hasher.Sum32() % uint32(max))
}
```

### taintEvictionQueue的赋值

这段代码是延迟队列的函数 时间到了自动触发

```go
tm.taintEvictionQueue = CreateWorkerQueue(deletePodHandler(c, tm.emitPodDeletionEvent))

func deletePodHandler(c clientset.Interface, emitEventFunc func(types.NamespacedName)) func(ctx context.Context, args *WorkArgs) error {
	return func(ctx context.Context, args *WorkArgs) error {
		ns := args.NamespacedName.Namespace
		name := args.NamespacedName.Name
		klog.InfoS("NoExecuteTaintManager is deleting pod", "pod", args.NamespacedName.String())
		if emitEventFunc != nil {
            // 发送Event
			emitEventFunc(args.NamespacedName)
		}
		var err error
		for i := 0; i < retries; i++ {
			err = addConditionAndDeletePod(ctx, c, name, ns)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return err
	}
}

func addConditionAndDeletePod(ctx context.Context, c clientset.Interface, name, ns string) (err error) {
    // 如果开启了PodDisruptionConditions 添加一个DisruptionTarget 文档可以打开看看
    // https://kubernetes.io/zh-cn/docs/concepts/workloads/pods/disruptions/
	if feature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
		pod, err := c.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		podApply := corev1apply.Pod(pod.Name, pod.Namespace).WithStatus(corev1apply.PodStatus())
		podApply.Status.WithConditions(corev1apply.PodCondition().
			WithType(v1.DisruptionTarget).
			WithStatus(v1.ConditionTrue).
			WithReason("DeletionByTaintManager").
			WithMessage("Taint manager: deleting due to NoExecute taint").
			WithLastTransitionTime(metav1.Now()),
		)
		if _, err := c.CoreV1().Pods(pod.Namespace).ApplyStatus(ctx, podApply, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
			return err
		}
	}
    // 删除pod
	return c.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{})
}
```

### worker

```go
func (tc *NoExecuteTaintManager) worker(ctx context.Context, worker int, done func(), stopCh <-chan struct{}) {
    // 外面的sync waitgroup done掉
	defer done()

	// When processing events we want to prioritize Node updates over Pod updates,
	// as NodeUpdates that interest NoExecuteTaintManager should be handled as soon as possible -
	// we don't want user (or system) to wait until PodUpdate queue is drained before it can
	// start evicting Pods from tainted Nodes.
	for {
		select {
		case <-stopCh:
			return
		case nodeUpdate := <-tc.nodeUpdateChannels[worker]:
            // 从第worker个管道拿出nodeUpdate的数据 去工作
			tc.handleNodeUpdate(ctx, nodeUpdate)
			tc.nodeUpdateQueue.Done(nodeUpdate)
		case podUpdate := <-tc.podUpdateChannels[worker]:
            // 从第worker个管道拿出podUpdate的数据 去工作
            // priority的作用是如果发现pod更新 现清空node的工作管道
			// 最后操作pod的 对于 NoExecuteTaintManager 来说，NodeUpdates 的处理优先级更高
		priority:
			for {
				select {
				case nodeUpdate := <-tc.nodeUpdateChannels[worker]:
					tc.handleNodeUpdate(ctx, nodeUpdate)
                    // 从消息队列取消node
					tc.nodeUpdateQueue.Done(nodeUpdate)
				default:
					break priority
				}
			}
			// After Node queue is emptied we process podUpdate.
			tc.handlePodUpdate(ctx, podUpdate)
             // 从消息队列取消pod
			tc.podUpdateQueue.Done(podUpdate)
		}
	}
}
```

### handleNodeUpdate

```GO
func (tc *NoExecuteTaintManager) handleNodeUpdate(ctx context.Context, nodeUpdate nodeUpdateItem) {
    // 从lister拿node
	node, err := tc.nodeLister.Get(nodeUpdate.nodeName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Delete
			klog.V(4).InfoS("Noticed node deletion", "node", nodeUpdate.nodeName)
			tc.taintedNodesLock.Lock()
			defer tc.taintedNodesLock.Unlock()
            // 从taintedNodes删除node
			delete(tc.taintedNodes, nodeUpdate.nodeName)
			return
		}
		utilruntime.HandleError(fmt.Errorf("cannot get node %s: %v", nodeUpdate.nodeName, err))
		return
	}

	// Create or Update
	klog.V(4).InfoS("Noticed node update", "node", nodeUpdate)
    // 获取NoExecute的污点
	taints := getNoExecuteTaints(node.Spec.Taints)
	func() {
		tc.taintedNodesLock.Lock()
		defer tc.taintedNodesLock.Unlock()
		klog.V(4).InfoS("Updating known taints on node", "node", node.Name, "taints", taints)
		if len(taints) == 0 {
            // 如果没有执行的污点删除
			delete(tc.taintedNodes, node.Name)
		} else {
            // 记录污点
			tc.taintedNodes[node.Name] = taints
		}
	}()

    // 从node拿出所有pod
	pods, err := tc.getPodsAssignedToNode(node.Name)
	if err != nil {
		klog.ErrorS(err, "Failed to get pods assigned to node", "node", node.Name)
		return
	}
    // 一个pod没有 就返回
	if len(pods) == 0 {
		return
	}
	// Short circuit, to make this controller a bit faster.
	if len(taints) == 0 {
		klog.V(4).InfoS("All taints were removed from the node. Cancelling all evictions...", "node", node.Name)
        // 如果没有不执行的污点 就取消所有与节点相关的 evictions
		for i := range pods {
			tc.cancelWorkWithEvent(types.NamespacedName{Namespace: pods[i].Namespace, Name: pods[i].Name})
		}
		return
	}

	now := time.Now()
    // 调用 tc.processPodOnNode 处理node上的每个 pod
	for _, pod := range pods {
		podNamespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
		tc.processPodOnNode(ctx, podNamespacedName, node.Name, pod.Spec.Tolerations, taints, now)
	}
}
```

#### getNoExecuteTaints

```GO
func getNoExecuteTaints(taints []v1.Taint) []v1.Taint {
	result := []v1.Taint{}
	for i := range taints {
		if taints[i].Effect == v1.TaintEffectNoExecute {
			result = append(result, taints[i])
		}
	}
	return result
}
```

#### cancelWorkWithEvent

```go
func (tc *NoExecuteTaintManager) cancelWorkWithEvent(nsName types.NamespacedName) {
	// 从queue中取消pod的驱逐
    if tc.taintEvictionQueue.CancelWork(nsName.String()) {
        // 记录事件
		tc.emitCancelPodDeletionEvent(nsName)
	}
}

func (tc *NoExecuteTaintManager) emitCancelPodDeletionEvent(nsName types.NamespacedName) {
	if tc.recorder == nil {
		return
	}
	ref := &v1.ObjectReference{
		Kind:      "Pod",
		Name:      nsName.Name,
		Namespace: nsName.Namespace,
	}
	tc.recorder.Eventf(ref, v1.EventTypeNormal, "TaintManagerEviction", "Cancelling deletion of Pod %s", nsName.String())
}

func (q *TimedWorkerQueue) CancelWork(key string) bool {
	q.Lock()
	defer q.Unlock()
	worker, found := q.workers[key]
	result := false
	if found {
		klog.V(4).Infof("Cancelling TimedWorkerQueue item %v at %v", key, time.Now())
		if worker != nil {
			result = true
			worker.Cancel()
		}
		delete(q.workers, key)
	}
	return result

```

#### processPodOnNode

```GO
func (tc *NoExecuteTaintManager) processPodOnNode(
	ctx context.Context,
	podNamespacedName types.NamespacedName,
	nodeName string,
	tolerations []v1.Toleration,
	taints []v1.Taint,
	now time.Time,
) {
    // 没有污点 取消pod的驱逐 
	if len(taints) == 0 {
		tc.cancelWorkWithEvent(podNamespacedName)
	}
    // 获取容忍度 看能否容忍node的taints
	allTolerated, usedTolerations := v1helper.GetMatchingTolerations(taints, tolerations)
	if !allTolerated {
		klog.V(2).InfoS("Not all taints are tolerated after update for pod on node", "pod", podNamespacedName.String(), "node", klog.KRef("", nodeName))
		// We're canceling scheduled work (if any), as we're going to delete the Pod right away.
        // 不能容忍 做驱逐操作
		tc.cancelWorkWithEvent(podNamespacedName)
		tc.taintEvictionQueue.AddWork(ctx, NewWorkArgs(podNamespacedName.Name, podNamespacedName.Namespace), time.Now(), time.Now())
		return
	}
    // 获取最短的容忍时间
	minTolerationTime := getMinTolerationTime(usedTolerations)
	// getMinTolerationTime returns negative value to denote infinite toleration.
	if minTolerationTime < 0 {
        // 说明该 Pod 具有无限期的容忍时间，则立即取消任何已经计划的删除 Pod 的工作
		klog.V(4).InfoS("Current tolerations for pod tolerate forever, cancelling any scheduled deletion", "pod", podNamespacedName.String())
		tc.cancelWorkWithEvent(podNamespacedName)
		return
	}
	
    // Pod 能够被驱逐的最早时
	startTime := now
	triggerTime := startTime.Add(minTolerationTime)
    // 检查该 Pod 是否已经在 taintEvictionQueue 中被计划了工作
	scheduledEviction := tc.taintEvictionQueue.GetWorkerUnsafe(podNamespacedName.String())
	if scheduledEviction != nil {
        // 已经计划了工作，那么将 startTime 设置为计划的时间
		startTime = scheduledEviction.CreatedAt
        // 检查在当前时间加上 minTolerationTime 后，计划的工作是否早于 triggerTime
		if startTime.Add(minTolerationTime).Before(triggerTime) {
           	// 说明计划的工作将在 triggerTime之前被执行，因此不需要再次添加到队列中
			return
		}
        // 取消计划的工作，以避免添加重复的工作到队列中
		tc.cancelWorkWithEvent(podNamespacedName)
	}
	tc.taintEvictionQueue.AddWork(ctx, NewWorkArgs(podNamespacedName.Name, podNamespacedName.Namespace), startTime, triggerTime)
}

// 获取最小的容忍时间 如果是0 直接返回
func getMinTolerationTime(tolerations []v1.Toleration) time.Duration {
	minTolerationTime := int64(math.MaxInt64)
	if len(tolerations) == 0 {
		return 0
	}

	for i := range tolerations {
		if tolerations[i].TolerationSeconds != nil {
			tolerationSeconds := *(tolerations[i].TolerationSeconds)
			if tolerationSeconds <= 0 {
				return 0
			} else if tolerationSeconds < minTolerationTime {
				minTolerationTime = tolerationSeconds
			}
		}
	}

	if minTolerationTime == int64(math.MaxInt64) {
		return -1
	}
	return time.Duration(minTolerationTime) * time.Second
}

func (q *TimedWorkerQueue) GetWorkerUnsafe(key string) *TimedWorker {
	q.Lock()
	defer q.Unlock()
	return q.workers[key]
}

func (q *TimedWorkerQueue) AddWork(ctx context.Context, args *WorkArgs, createdAt time.Time, fireAt time.Time) {
	key := args.KeyFromWorkArgs()
	klog.V(4).Infof("Adding TimedWorkerQueue item %v at %v to be fired at %v", key, createdAt, fireAt)

	q.Lock()
	defer q.Unlock()
	if _, exists := q.workers[key]; exists {
		klog.Warningf("Trying to add already existing work for %+v. Skipping.", args)
		return
	}
	worker := createWorker(ctx, args, createdAt, fireAt, q.getWrappedWorkerFunc(key), q.clock)
	q.workers[key] = worker
}
```

### handlePodUpdate

```go
func (tc *NoExecuteTaintManager) handlePodUpdate(ctx context.Context, podUpdate podUpdateItem) {
    // get pod
	pod, err := tc.podLister.Pods(podUpdate.podNamespace).Get(podUpdate.podName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Delete
			podNamespacedName := types.NamespacedName{Namespace: podUpdate.podNamespace, Name: podUpdate.podName}
			klog.V(4).InfoS("Noticed pod deletion", "pod", podNamespacedName)
			tc.cancelWorkWithEvent(podNamespacedName)
			return
		}
		utilruntime.HandleError(fmt.Errorf("could not get pod %s/%s: %v", podUpdate.podName, podUpdate.podNamespace, err))
		return
	}

	// 已经换了节点了 就不处理了
	if pod.Spec.NodeName != podUpdate.nodeName {
		return
	}

	// Create or Update
	podNamespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	klog.V(4).InfoS("Noticed pod update", "pod", podNamespacedName)
	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		return
	}
    // get 污点
	taints, ok := func() ([]v1.Taint, bool) {
		tc.taintedNodesLock.Lock()
		defer tc.taintedNodesLock.Unlock()
		taints, ok := tc.taintedNodes[nodeName]
		return taints, ok
	}()
	// It's possible that Node was deleted, or Taints were removed before, which triggered
	// eviction cancelling if it was needed.
	if !ok {
        // 没有污点信息返回
		return
	}
    // 处理node上的Pod
	tc.processPodOnNode(ctx, podNamespacedName, nodeName, pod.Spec.Tolerations, taints, time.Now())
}

```

