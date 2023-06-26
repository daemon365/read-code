---
id: 2-kube-scheduler-code 
title: scheduler中quque代码走读
description: scheduler中quque代码走读
keywords:
  - kubernetes
  - kube-scheduler
slug: /
---

## 作用

在Scheduler结构体中，SchedulingQueue是一个用于存储待调度Pod的队列。当一个新的Pod需要被调度时，它会被加入到SchedulingQueue中，并按照一定的规则排序。调度器会从队列中取出一个Pod进行调度，如果调度成功，则将该Pod从队列中移除。如果调度失败，则会将该Pod重新插入队列，并等待下一次尝试调度。

SchedulingQueue的作用是实现调度器的排队机制，确保待调度的Pod可以有序地进入调度器并得到处理，同时避免过多的调度请求同时处理导致的资源争用和性能问题。此外，SchedulingQueue还可以用于实现一些高级的调度策略，例如优先级调度和预留资源调度等。

## internalqueue.SchedulingQueue

```GO
type SchedulingQueue interface {
	framework.PodNominator
    // 将Pod添加到队列中
	Add(pod *v1.Pod) error
	// 将指定的Pod移动到活动队列（activeQ），前提是它们在不可调度Pod队列（unschedulablePods）或退避队列（backoffQ）中。
	Activate(pods map[string]*v1.Pod)
	// 如果队列中不存在指定的不可调度Pod，则将其添加回队列中。参数podSchedulingCycle表示当前调度周期的编号，
    // 可以通过调用SchedulingCycle()方法返回。
	AddUnschedulableIfNotPresent(pod *framework.QueuedPodInfo, podSchedulingCycle int64) error
	// 返回当前的调度周期编号，该编号由调度队列缓存。通常，每当弹出Pod（例如，调用Pop()方法）时，会增加此编号。
	SchedulingCycle() int64
	// 删除队列头部元素并返回它。如果队列为空，则阻塞并等待直到有新的元素添加到队列中。
	Pop() (*framework.QueuedPodInfo, error)
    // 将指定的Pod从队列中更新。
	Update(oldPod, newPod *v1.Pod) error
    // 从队列中删除指定的Pod。
	Delete(pod *v1.Pod) error
    // 将所有Pod移动到活动队列或退避队列中。
	MoveAllToActiveOrBackoffQueue(event framework.ClusterEvent, preCheck PreEnqueueCheck)
    // 通知队列指定Pod已经被分配
	AssignedPodAdded(pod *v1.Pod)
    // 通知队列指定Pod已经被更新
	AssignedPodUpdated(pod *v1.Pod)
    // 返回队列中所有待处理Pod的列表和队列名称。
	PendingPods() ([]*v1.Pod, string)
	// 关闭调度队列，以便等待弹出元素的goroutine可以正常退出。
	Close()
	// 启动管理队列的goroutines。
	Run()
}
```

## PriorityQueue

```GO
type PriorityQueue struct {
    // 表示该PriorityQueue结构体也包含了nominator结构体的所有字段和方法
	*nominator
	// 用于关闭PriorityQueue的goroutine
	stop  chan struct{}
    // 用于计算时间的时钟
	clock clock.Clock

	// Pod的初始回退时间
	podInitialBackoffDuration time.Duration
	// Pod的最大回退时间
	podMaxBackoffDuration time.Duration
	// Pod在unschedulablePods中最长停留时间
	podMaxInUnschedulablePodsDuration time.Duration
	
    // 条件变量
	cond sync.Cond

	// 存储所有可调度的Pod，堆顶的Pod拥有最高的优先级
	activeQ *heap.Heap
	// 存储正在回退中的Pod，回退完成的Pod将从此堆中弹出，然后才会从activeQ中进行调度
	podBackoffQ *heap.Heap
	// 存储所有不能被调度的Pod
	unschedulablePods *UnschedulablePods
	// 当前的调度周期序列号
	schedulingCycle int64
	// 收到move request的调度周期序列号，用于判断unschedulablePods中的Pod是否应该重新加入activeQ
	moveRequestCycle int64
	
    // 存储clusterEvent及其对应的Pod名
	clusterEventMap map[framework.ClusterEvent]sets.Set[string]
	// key为插件名称，value为插件
	preEnqueuePluginMap map[string][]framework.PreEnqueuePlugin

	// 表示PriorityQueue是否已关闭
	closed bool

	nsLister listersv1.NamespaceLister

	metricsRecorder metrics.MetricAsyncRecorder
	//插件metrics的采样率
	pluginMetricsSamplePercent int
}
```

### nominator

```go
type nominator struct {
    // podLister用于验证给定的Pod是否存在
    podLister listersv1.PodLister
    // nominatedPods是一个映射，以节点名称为键，值是可以在activeQ或unschedulablePods中运行的Pod列表
    nominatedPods map[string][]*framework.PodInfo
    // nominatedPodToNode是一个映射，以Pod UID为键，值是它所提名的节点名称
    nominatedPodToNode map[types.UID]string

    // lock是一个读写锁，用于保护结构体中的字段
    lock sync.RWMutex
}
```

#### 方法

```GO
func (npm *nominator) AddNominatedPod(pi *framework.PodInfo, nominatingInfo *framework.NominatingInfo) {
	npm.lock.Lock()
	npm.addNominatedPodUnlocked(pi, nominatingInfo)
	npm.lock.Unlock()
}

func (npm *nominator) DeleteNominatedPodIfExists(pod *v1.Pod) {
	npm.lock.Lock()
	npm.deleteNominatedPodIfExistsUnlocked(pod)
	npm.lock.Unlock()
}

func (npm *nominator) UpdateNominatedPod(oldPod *v1.Pod, newPodInfo *framework.PodInfo) {
	npm.lock.Lock()
	defer npm.lock.Unlock()
	npm.updateNominatedPodUnlocked(oldPod, newPodInfo)
}

func (npm *nominator) NominatedPodsForNode(nodeName string) []*framework.PodInfo {
    npm.lock.RLock()
    defer npm.lock.RUnlock()
    // 复制一个被提名的Pod的副本，以便调用方可以安全地修改
    pods := make([]*framework.PodInfo, len(npm.nominatedPods[nodeName]))
    for i := 0; i < len(pods); i++ {
        pods[i] = npm.nominatedPods[nodeName][i].DeepCopy()
    }
    return pods
}
```

##### addNominatedPodUnlocked

```GO
func (npm *nominator) addNominatedPodUnlocked(pi *framework.PodInfo, nominatingInfo *framework.NominatingInfo) {
    // 始终删除Pod，以确保我们永远不会存储超过一个实例的Pod。
    npm.delete(pi.Pod)

    var nodeName string
    if nominatingInfo.Mode() == framework.ModeOverride {
        // 如果模式为Override，则使用指定的节点名。
        nodeName = nominatingInfo.NominatedNodeName
    } else if nominatingInfo.Mode() == framework.ModeNoop {
        // 如果模式为Noop，则检查Pod的NominatedNodeName是否为空。
        if pi.Pod.Status.NominatedNodeName == "" {
            return
        }
        // 如果不为空，则使用Pod的NominatedNodeName。
        nodeName = pi.Pod.Status.NominatedNodeName
    }

    if npm.podLister != nil {
        // 如果Pod已删除或已经被调度，不进行提名。
        updatedPod, err := npm.podLister.Pods(pi.Pod.Namespace).Get(pi.Pod.Name)
        if err != nil {
            klog.V(4).InfoS("Pod在podLister中不存在，中止将其添加到提名器", "pod", klog.KObj(pi.Pod))
            return
        }
        if updatedPod.Spec.NodeName != "" {
            klog.V(4).InfoS("Pod已经被调度到一个节点上，中止将其添加到提名器", "pod", klog.KObj(pi.Pod), "node", updatedPod.Spec.NodeName)
            return
        }
    }

    // 将Pod的UID与节点名关联并保存到map中。
    npm.nominatedPodToNode[pi.Pod.UID] = nodeName

    // 检查节点上是否已经存在相同UID的Pod，如果存在，则不进行提名。
    for _, npi := range npm.nominatedPods[nodeName] {
        if npi.Pod.UID == pi.Pod.UID {
            klog.V(4).InfoS("Pod已经存在于提名器中", "pod", klog.KObj(npi.Pod))
            return
        }
    }

    // 将Pod添加到指定节点的提名Pod列表中。
    npm.nominatedPods[nodeName] = append(npm.nominatedPods[nodeName], pi)
}
```

##### deleteNominatedPodIfExistsUnlocked

```GO
func (npm *nominator) deleteNominatedPodIfExistsUnlocked(pod *v1.Pod) {
	npm.delete(pod)
}
```

##### delete

```GO
func (npm *nominator) delete(p *v1.Pod) {
    // 获取该Pod对应的节点名。
    nnn, ok := npm.nominatedPodToNode[p.UID]
    if !ok {
        return
    }
    // 在对应节点的提名Pod列表中查找该Pod，并将其从列表中删除。
    for i, np := range npm.nominatedPods[nnn] {
        if np.Pod.UID == p.UID {
            npm.nominatedPods[nnn] = append(npm.nominatedPods[nnn][:i], npm.nominatedPods[nnn][i+1:]...)
            // 如果节点上的提名Pod列表为空，则删除该节点。
            if len(npm.nominatedPods[nnn]) == 0 {
                delete(npm.nominatedPods, nnn)
            }
            break
        }
    }
    // 从映射表中删除该Pod对应的节点名。
    delete(npm.nominatedPodToNode, p.UID)
}
```

##### updateNominatedPodUnlocked

```go
func (npm *nominator) updateNominatedPodUnlocked(oldPod *v1.Pod, newPodInfo *framework.PodInfo) {
    // 在某些情况下，会在内存中为此Pod预留节点（“NominatedNode”），并且此时收到没有“NominatedNode”信息的更新事件。
    // 在这种情况下，我们需要在更新Pod指针时继续保留NominatedNode。
    var nominatingInfo *framework.NominatingInfo
    // 如果更新事件表示：
    // (1) 添加了NominatedNode信息
    // (2) 更新了NominatedNode信息
    // (3) 删除了NominatedNode信息
    // 那么我们不会进入下面的 `if` 块。
    if NominatedNodeName(oldPod) == "" && NominatedNodeName(newPodInfo.Pod) == "" {
        if nnn, ok := npm.nominatedPodToNode[oldPod.UID]; ok {
            // 这是唯一一种我们需要继续保留NominatedNode的情况。
            nominatingInfo = &framework.NominatingInfo{
                NominatingMode:    framework.ModeOverride,
                NominatedNodeName: nnn,
            }
        }
    }
    // 不管 nominatedNodeName 是否改变，我们都会进行更新，以确保更新 Pod 指针。
    npm.delete(oldPod)
    npm.addNominatedPodUnlocked(newPodInfo, nominatingInfo)
}
```

##### NominatedNodeName

```go
func NominatedNodeName(pod *v1.Pod) string {
	return pod.Status.NominatedNodeName
}
```

### Heap

```GO
// Heap是一个生产者/消费者队列，实现了堆数据结构。
// 它可以用于实现优先队列和类似数据结构。
type Heap struct {
	// data 存储对象，并具有队列，根据堆的不变性维护它们的排序。
	data *data
	// metricRecorder 更新计数器，当堆的元素被添加或删除时，并且如果它是 nil，则什么也不做
	metricRecorder metrics.MetricRecorder
}
```

#### data

```go
// 实现了标准堆接口的内部结构体，同时存储在堆中的数据
type data struct {
	// 将对象的键映射到对象本身以及其在队列中的索引。该堆依赖于 map 中的项和队列中的项是一一对应的这一特性。
	items map[string]*heapItem
	// 根据堆的不变量维护元素的顺序。该队列存储在 items 中的对象键。
	queue []string

	// 用于生成用于排队的项目插入和检索的键，应该是确定性的。
	keyFunc KeyFunc
	// 用于比较堆中的两个对象。
	lessFunc lessFunc
}

type heapItem struct {
	obj   interface{} // The object which is stored in the heap.
	index int         // The index of the object's key in the Heap.queue.
}

type KeyFunc func(obj interface{}) (string, error)

type lessFunc = func(item1, item2 interface{}) bool


// Less 比较两个对象，如果第一个对象在堆中应该排在第二个对象之前，则返回 true。
func (h *data) Less(i, j int) bool {
	if i > len(h.queue) || j > len(h.queue) { // 如果 i 或 j 越界，则返回 false
		return false
	}
	itemi, ok := h.items[h.queue[i]] // 获取下标为 i 的元素对应的 heapItem 结构体
	if !ok { // 如果获取不到，则返回 false
		return false
	}
	itemj, ok := h.items[h.queue[j]] // 获取下标为 j 的元素对应的 heapItem 结构体
	if !ok { // 如果获取不到，则返回 false
		return false
	}
	return h.lessFunc(itemi.obj, itemj.obj) // 调用 lessFunc 比较两个元素，返回比较结果
}

// Len 返回堆中元素的个数。
func (h *data) Len() int { return len(h.queue) }

// Swap 交换堆中两个元素的位置。这是标准堆接口的一部分，不应直接调用。
func (h *data) Swap(i, j int) {
	h.queue[i], h.queue[j] = h.queue[j], h.queue[i] // 交换 i 和 j 对应元素在 queue 中的位置
	item := h.items[h.queue[i]] // 获取交换后下标为 i 的元素对应的 heapItem 结构体
	item.index = i // 更新元素在 queue 中的下标
	item = h.items[h.queue[j]] // 获取交换后下标为 j 的元素对应的 heapItem 结构体
	item.index = j // 更新元素在 queue 中的下标
}

// Push 只能由 heap.Push 调用。
func (h *data) Push(kv interface{}) {
	keyValue := kv.(*itemKeyValue) // 获取插入元素的 key 和 value
	n := len(h.queue) // 获取堆中元素个数
	h.items[keyValue.key] = &heapItem{keyValue.obj, n} // 将元素添加到 items 中
	h.queue = append(h.queue, keyValue.key) // 将元素的 key 添加到 queue 中
}

// Pop 只能由 heap.Pop 调用。
func (h *data) Pop() interface{} {
	key := h.queue[len(h.queue)-1] // 获取队列中最后一个元素的 key
	h.queue = h.queue[0 : len(h.queue)-1] // 删除最后一个元素
	item, ok := h.items[key] // 获取最后一个元素对应的 heapItem 结构体
	if !ok { // 如果获取不到，则返回 nil
		// This is an error
		return nil
	}
	delete(h.items, key) // 从 items 中删除该元素
	return item.obj // 返回元素的 value
}

// Peek 只能由 heap.Peek 调用。
func (h *data) Peek() interface{} {
	if len(h.queue) > 0 { // 如果队列不为空
		return h.items[h.queue[0]].obj // 返回队列中第一个元素的 value
	}
	return nil
}
```

#### New

```go
func New(keyFn KeyFunc, lessFn lessFunc) *Heap {
	return NewWithRecorder(keyFn, lessFn, nil)
}

// NewWithRecorder wraps an optional metricRecorder to compose a Heap object.
func NewWithRecorder(keyFn KeyFunc, lessFn lessFunc, metricRecorder metrics.MetricRecorder) *Heap {
	return &Heap{
		data: &data{
			items:    map[string]*heapItem{},
			queue:    []string{},
			keyFunc:  keyFn,
			lessFunc: lessFn,
		},
		metricRecorder: metricRecorder,
	}
}
```

#### 方法

```GO
// Update 是 Heap 结构体的一个方法，该方法的作用和 Add 方法相同。当要更新的对象不存在时，该对象将被添加到堆中。
func (h *Heap) Update(obj interface{}) error {
	return h.Add(obj)
}

// Delete 方法用于移除一个对象。
func (h *Heap) Delete(obj interface{}) error {
    key, err := h.data.keyFunc(obj) // 从对象中提取键值
    if err != nil {
    	return cache.KeyError{Obj: obj, Err: err} // 如果提取失败，则返回一个自定义的 KeyError
    }
    if item, ok := h.data.items[key]; ok { // 如果堆中存在该键值，则移除它
        heap.Remove(h.data, item.index)
        if h.metricRecorder != nil { // 如果有度量记录器，则将其值减1
        	h.metricRecorder.Dec()
        }
        return nil // 返回成功
    }
    return fmt.Errorf("object not found") // 如果堆中不存在该对象，则返回一个错误
}

// Peek 方法返回堆顶的元素，但不移除它。
func (h *Heap) Peek() interface{} {
	return h.data.Peek()
}

// Pop 方法返回堆顶的元素并移除它。
func (h *Heap) Pop() (interface{}, error) {
    obj := heap.Pop(h.data) // 从堆中弹出顶部元素
    if obj != nil {
        if h.metricRecorder != nil { // 如果有度量记录器，则将其值减1
        	h.metricRecorder.Dec()
        }
        return obj, nil // 返回弹出的元素和成功标志
    }
    return nil, fmt.Errorf("object was removed from heap data") // 如果堆为空，则返回一个错误
}

// Get 方法返回请求的对象，如果该对象不存在，则设置 exists=false。
func (h *Heap) Get(obj interface{}) (interface{}, bool, error) {
    key, err := h.data.keyFunc(obj) // 从对象中提取键值
    if err != nil {
    	return nil, false, cache.KeyError{Obj: obj, Err: err} // 如果提取失败，则返回一个自定义的 KeyError
    }
    return h.GetByKey(key) // 调用 GetByKey 方法获取对象
}

// GetByKey 方法返回请求的对象，如果该对象不存在，则设置 exists=false。
func (h *Heap) GetByKey(key string) (interface{}, bool, error) {
    item, exists := h.data.items[key] // 在堆中查找键值对应的项
    if !exists {
    	return nil, false, nil // 如果不存在，则返回 nil 和 false
    }
    return item.obj, true, nil // 如果存在，则返回对象和 true
}

// List 方法返回一个包含所有项的列表。
func (h *Heap) List() []interface{} {
    list := make([]interface{}, 0, len(h.data.items)) // 创建一个容量为堆大小的空列表
    for _, item := range h.data.items {
    	list = append(list, item.obj) // 将堆中的每个元素追加到列表中
    }
    return list // 返回列表
}

// Len 方法返回堆中的项数。
func (h *Heap) Len() int {
	return len(h.data.queue) // 返回队列中的元素数
}
```

### UnschedulablePods

```GO
// UnschedulablePods 存储无法被调度的 Pod。这个数据结构用于实现 unschedulablePods。
type UnschedulablePods struct {
    // podInfoMap 是一个映射，键是 Pod 的全名，值是一个指向 QueuedPodInfo 的指针。
    podInfoMap map[string]*framework.QueuedPodInfo
    keyFunc func(*v1.Pod) string
    // unschedulableRecorder/gatedRecorder 在向 unschedulablePodsMap 添加或删除元素时更新计数器，如果为 nil，则不执行任何操作。
    unschedulableRecorder, gatedRecorder metrics.MetricRecorder
}

func newUnschedulablePods(unschedulableRecorder, gatedRecorder metrics.MetricRecorder) *UnschedulablePods {
	return &UnschedulablePods{
		podInfoMap:            make(map[string]*framework.QueuedPodInfo),
		keyFunc:               util.GetPodFullName,
		unschedulableRecorder: unschedulableRecorder,
		gatedRecorder:         gatedRecorder,
	}
}

// addOrUpdate 将一个 Pod 添加到 unschedulable podInfoMap 中。
func (u *UnschedulablePods) addOrUpdate(pInfo *framework.QueuedPodInfo) {
    // 根据 Pod 生成一个唯一标识
    podID := u.keyFunc(pInfo.Pod)
    // 如果这个 Pod 没有在 podInfoMap 中出现过
    if _, exists := u.podInfoMap[podID]; !exists {
        // 如果这个 Pod 被阻塞，并且存在 gatedRecorder 计数器，则将其增加
        if pInfo.Gated && u.gatedRecorder != nil {
        	u.gatedRecorder.Inc()
        // 如果这个 Pod 没有被阻塞，并且存在 unschedulableRecorder 计数器，则将其增加
        } else if !pInfo.Gated && u.unschedulableRecorder != nil {
       		u.unschedulableRecorder.Inc()
        }
    }
    // 将这个 Pod 添加到 podInfoMap 中
    u.podInfoMap[podID] = pInfo
}

// delete 从 unschedulable podInfoMap 中删除一个 Pod。
// gated 参数用于确定应该减少哪个度量。
func (u *UnschedulablePods) delete(pod *v1.Pod, gated bool) {
    // 根据 Pod 生成一个唯一标识
    podID := u.keyFunc(pod)
    // 如果这个 Pod 存在于 podInfoMap 中
        if _, exists := u.podInfoMap[podID]; exists {
        // 如果这个 Pod 被阻塞，并且存在 gatedRecorder 计数器，则将其减少
        if gated && u.gatedRecorder != nil {
        	u.gatedRecorder.Dec()
        // 如果这个 Pod 没有被阻塞，并且存在 unschedulableRecorder 计数器，则将其减少
        } else if !gated && u.unschedulableRecorder != nil {
        	u.unschedulableRecorder.Dec()
        }
    }
    // 从 podInfoMap 中删除这个 Pod
    delete(u.podInfoMap, podID)
}

// get 根据给定的 "pod" 的键获取与其具有相同键的 Pod 的 QueuedPodInfo。
// 如果没有找到，则返回 nil。
func (u *UnschedulablePods) get(pod *v1.Pod) *framework.QueuedPodInfo {
    // 根据 Pod 生成一个唯一标识
    podKey := u.keyFunc(pod)
    // 如果 podInfoMap 中存在与 podKey 相同的键，则返回其对应的 QueuedPodInfo
    if pInfo, exists := u.podInfoMap[podKey]; exists {
    	return pInfo
    }
    // 否则返回 nil
    return nil
}

// clear 方法从 unschedulable podInfoMap 中移除所有条目。
func (u *UnschedulablePods) clear() {
    // 使用 make 方法创建一个新的空 map，将其分配给 podInfoMap，覆盖之前的 map。
    u.podInfoMap = make(map[string]*framework.QueuedPodInfo)
    // 如果 unschedulableRecorder 不是 nil，调用其 Clear() 方法清除所有不可调度 pod 的记录。
    if u.unschedulableRecorder != nil {
    	u.unschedulableRecorder.Clear()
    }
    // 如果 gatedRecorder 不是 nil，调用其 Clear() 方法清除所有 gated pod 的记录。
    if u.gatedRecorder != nil {
    	u.gatedRecorder.Clear()
    }
}
```

## New

```go
func NewSchedulingQueue(
	lessFn framework.LessFunc,
	informerFactory informers.SharedInformerFactory,
	opts ...Option) SchedulingQueue {
	return NewPriorityQueue(lessFn, informerFactory, opts...)
}

func NewPriorityQueue(
    lessFn framework.LessFunc,    // lessFn 是一个比较函数，用于比较两个 podInfo 排序的大小关系
    informerFactory informers.SharedInformerFactory,    // informerFactory 是用于创建 informer 的工厂对象
    opts ...Option,    // 可变参数 opts 是一个选项列表，用于指定 PriorityQueue 的一些参数
) *PriorityQueue {
    options := defaultPriorityQueueOptions    // 获取默认参数选项
    if options.podLister == nil {    // 如果 podLister 为空，则使用工厂对象创建一个
        options.podLister = informerFactory.Core().V1().Pods().Lister()
    }
    for _, opt := range opts {    // 遍历选项列表，并执行每个选项对应的函数
        opt(&options)
    }

    comp := func(podInfo1, podInfo2 interface{}) bool {    // 定义一个比较函数，用于根据 lessFn 比较 podInfo1 和 podInfo2 的大小关系
        pInfo1 := podInfo1.(*framework.QueuedPodInfo)
        pInfo2 := podInfo2.(*framework.QueuedPodInfo)
        return lessFn(pInfo1, pInfo2)
    }

    pq := &PriorityQueue{    // 创建一个 PriorityQueue 对象，并初始化其各个属性值
        nominator:                         newPodNominator(options.podLister),
        clock:                             options.clock,
        stop:                              make(chan struct{}),
        podInitialBackoffDuration:         options.podInitialBackoffDuration,
        podMaxBackoffDuration:             options.podMaxBackoffDuration,
        podMaxInUnschedulablePodsDuration: options.podMaxInUnschedulablePodsDuration,
        activeQ:                           heap.NewWithRecorder(podInfoKeyFunc, comp, metrics.NewActivePodsRecorder()),
        unschedulablePods:                 newUnschedulablePods(metrics.NewUnschedulablePodsRecorder(), metrics.NewGatedPodsRecorder()),
        moveRequestCycle:                  -1,
        clusterEventMap:                   options.clusterEventMap,
        preEnqueuePluginMap:               options.preEnqueuePluginMap,
        metricsRecorder:                   options.metricsRecorder,
        pluginMetricsSamplePercent:        options.pluginMetricsSamplePercent,
    }
    pq.cond.L = &pq.lock    // 将 pq 的条件变量设置为锁的地址
    pq.podBackoffQ = heap.NewWithRecorder(podInfoKeyFunc, pq.podsCompareBackoffCompleted, metrics.NewBackoffPodsRecorder())    // 创建一个 podBackoffQ 对象
    pq.nsLister = informerFactory.Core().V1().Namespaces().Lister()    // 获取名字空间列表

    return pq    // 返回创建的 PriorityQueue 对象
}
```

### options

```go
type priorityQueueOptions struct {
	clock                             clock.Clock
	podInitialBackoffDuration         time.Duration
	podMaxBackoffDuration             time.Duration
	podMaxInUnschedulablePodsDuration time.Duration
	podLister                         listersv1.PodLister
	metricsRecorder                   metrics.MetricAsyncRecorder
	pluginMetricsSamplePercent        int
	clusterEventMap                   map[framework.ClusterEvent]sets.Set[string]
	preEnqueuePluginMap               map[string][]framework.PreEnqueuePlugin
}

// Option configures a PriorityQueue
type Option func(*priorityQueueOptions)
```

## PodNominator

```go
type PodNominator interface {
	// AddNominatedPod将给定的Pod添加到提名器中，如果该Pod已经存在，则进行更新。
	AddNominatedPod(pod *PodInfo, nominatingInfo *NominatingInfo)
	// DeleteNominatedPodIfExists从内部缓存中删除提名的Pod。如果该Pod不存在，则此操作不会执行任何操作。
	DeleteNominatedPodIfExists(pod *v1.Pod)
	// UpdateNominatedPod使用newPodInfo更新oldPod。
	UpdateNominatedPod(oldPod *v1.Pod, newPodInfo *PodInfo)
	// NominatedPodsForNode返回给定节点上的提名Pod。
	NominatedPodsForNode(nodeName string) []*PodInfo
}
```

## Add

```go
func (p *PriorityQueue) Add(pod *v1.Pod) error {  // 声明一个方法，接收一个指向PriorityQueue结构体的指针和一个指向v1.Pod结构体的指针，返回一个error类型的值。
	p.lock.Lock()  // 获取锁。
	defer p.lock.Unlock()  // 方法结束前释放锁。

	pInfo := p.newQueuedPodInfo(pod)  // 调用PriorityQueue的newQueuedPodInfo方法，传入pod指针，返回一个PodInfo类型的指针，并将其赋值给pInfo变量。
	gated := pInfo.Gated  // 将PodInfo中的Gated字段赋值给gated变量。
	if added, err := p.addToActiveQ(pInfo); !added {  // 调用PriorityQueue的addToActiveQ方法，传入PodInfo类型的指针，返回一个bool类型的值和一个error类型的值。如果addToActiveQ返回的added为false，则返回err。
		return err  // 返回addToActiveQ方法的错误信息。
	}
	if p.unschedulablePods.get(pod) != nil {  // 调用PriorityQueue的get方法，传入pod指针，返回一个PodInfo类型的指针或nil。如果返回的指针不为nil，则表示pod已经在unschedulablePods中了。
		klog.ErrorS(nil, "Error: pod is already in the unschedulable queue", "pod", klog.KObj(pod))  // 输出错误日志。
		p.unschedulablePods.delete(pod, gated)  // 调用PriorityQueue的delete方法，传入pod指针和gated变量，从unschedulablePods中删除pod。
	}
	// 如果PodInfo在podBackoffQ中，则将其删除。
	if err := p.podBackoffQ.Delete(pInfo); err == nil {  // 调用PriorityQueue的Delete方法，传入PodInfo类型的指针，返回一个error类型的值。如果返回的error为nil，则表示PodInfo已经在podBackoffQ中。
		klog.ErrorS(nil, "Error: pod is already in the podBackoff queue", "pod", klog.KObj(pod))  // 输出错误日志。
	}
	klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pod), "event", PodAdd, "queue", activeQName)  // 输出日志，表示Pod已经被移到了一个内部调度队列中。
	metrics.SchedulerQueueIncomingPods.WithLabelValues("active", PodAdd).Inc()  // 调用metrics包中的SchedulerQueueIncomingPods方法，增加一个标签为"active"和事件为PodAdd的计数器。
	p.addNominatedPodUnlocked(pInfo.PodInfo, nil)  // 调用PriorityQueue的addNominatedPodUnlocked方法，传入PodInfo类型的指针和nil。
	p.cond.Broadcast()  // 发送广播通知。

	return nil  // 返回nil，表示方法

```

### newQueuedPodInfo

```go
func (p *PriorityQueue) newQueuedPodInfo(pod *v1.Pod, plugins ...string) *framework.QueuedPodInfo {  // 声明一个方法，接收一个指向v1.Pod结构体的指针和可变数量的string类型参数，返回一个指向framework.QueuedPodInfo结构体的指针。
	now := p.clock.Now()  // 获取当前时间，并将其赋值给now变量。
	// 忽略这个错误，因为apiserver不会正确验证亲和性术语，而我们不能为了向后兼容而修复验证。
	podInfo, _ := framework.NewPodInfo(pod)  // 调用framework包中的NewPodInfo方法，传入pod指针，返回一个PodInfo类型的指针和一个error类型的值。将PodInfo类型的指针赋值给podInfo变量，将error类型的值忽略掉。
	return &framework.QueuedPodInfo{  // 构造一个QueuedPodInfo结构体，并返回其指针。
		PodInfo:                 podInfo,  // 将podInfo变量的值赋值给QueuedPodInfo结构体中的PodInfo字段。
		Timestamp:               now,  // 将now变量的值赋值给QueuedPodInfo结构体中的Timestamp字段。
		InitialAttemptTimestamp: now,  // 将now变量的值赋值给QueuedPodInfo结构体中的InitialAttemptTimestamp字段。
		UnschedulablePlugins:    sets.New(plugins...),  // 调用sets包中的New方法，传入plugins可变参数，并将其作为元素构造一个Set类型的变量，将其赋值给QueuedPodInfo结构体中的UnschedulablePlugins字段。
	}
}
```

### addToActiveQ

```go
// addToActiveQ 试图将 pod 添加到活动队列。它返回两个参数：
// 1. 一个布尔值来指示是否成功添加了该 pod。
// 2. 供调用者采取措施的错误。
func (p *PriorityQueue) addToActiveQ(pInfo *framework.QueuedPodInfo) (bool, error) {
    // 首先运行 pre-enqueue 插件
    pInfo.Gated = !p.runPreEnqueuePlugins(context.Background(), pInfo)
    if pInfo.Gated {
        // 如果未通过 pre-enqueue 插件，则将该 pod 添加到 unschedulablePods 中
        p.unschedulablePods.addOrUpdate(pInfo)
        return false, nil
    }
    // 将 pod 添加到 activeQ 中
    if err := p.activeQ.Add(pInfo); err != nil {
        klog.ErrorS(err, "Error adding pod to the active queue", "pod", klog.KObj(pInfo.Pod))
        return false, err
    }
    return true, nil
}
```

#### runPreEnqueuePlugins

```go
// runPreEnqueuePlugins 遍历每个已注册的 PreEnqueuePlugin 的 PreEnqueue 函数。
// 如果所有 PreEnqueue 函数都成功运行，则返回 true；否则返回 false，在第一次失败时返回。
// 注意：我们需要将失败的插件与 pInfo 关联起来，以便通过相关的集群事件将 Pod 移回 activeQ。
func (p *PriorityQueue) runPreEnqueuePlugins(ctx context.Context, pInfo *framework.QueuedPodInfo) bool {
    // 定义变量 s 为指向 framework.Status 结构体的指针
    var s *framework.Status
    // 获取 Pod 对象
    pod := pInfo.Pod
    // 记录开始时间
    startTime := time.Now()
    // 在函数结束后调用 defer 函数，记录运行 PreEnqueuePlugins 函数所消耗的时间，以便进行度量
    defer func() {
        // 使用 metrics.SinceInSeconds 函数计算 PreEnqueuePlugins 函数执行时间，并将结果记录到 metrics.FrameworkExtensionPointDuration 中
        metrics.FrameworkExtensionPointDuration.WithLabelValues(preEnqueue, s.Code().String(), pod.Spec.SchedulerName).Observe(metrics.SinceInSeconds(startTime))
    }()
    // 根据一定的概率决定是否记录插件度量信息
    shouldRecordMetric := rand.Intn(100) < p.pluginMetricsSamplePercent

    // 遍历 Pod 的 SchedulerName 对应的 preEnqueuePluginMap 中的所有插件
    for _, pl := range p.preEnqueuePluginMap[pod.Spec.SchedulerName] {
        // 对当前插件运行 PreEnqueue 函数，并获取运行状态
        s = p.runPreEnqueuePlugin(ctx, pl, pod, shouldRecordMetric)
        // 如果 PreEnqueue 函数成功运行，则继续运行下一个插件
        if s.IsSuccess() {
            continue
        }
        // 如果 PreEnqueue 函数运行失败，则将该插件的名称插入到 pInfo 的 UnschedulablePlugins 中
        pInfo.UnschedulablePlugins.Insert(pl.Name())
        // 对该插件在 Pod 的 SchedulerName 中进行不可调度原因的度量
        metrics.UnschedulableReason(pl.Name(), pod.Spec.SchedulerName).Inc()
        // 如果返回的状态为 Error，则记录日志
        if s.Code() == framework.Error {
            klog.ErrorS(s.AsError(), "Unexpected error running PreEnqueue plugin", "pod", klog.KObj(pod), "plugin", pl.Name())
        } else {
            // 如果返回的状态不是 Error，则记录状态日志
            klog.V(5).InfoS("Status after running PreEnqueue plugin", "pod", klog.KObj(pod), "plugin", pl.Name(), "status", s)
        }
        // 返回 false，表示 PreEnqueue 函数运行失败
        return false
    }
    // 如果所有插件的 PreEnqueue 函数都成功运行，则返回 true
    return true
}
```

#### runPreEnqueuePlugin

```go
// runPreEnqueuePlugin 函数对单个插件运行 PreEnqueue 函数，并返回运行结果
func (p *PriorityQueue) runPreEnqueuePlugin(ctx context.Context, pl framework.PreEnqueuePlugin, pod *v1.Pod, shouldRecordMetric bool) *framework.Status {
    // 如果不需要记录插件度量信息，则直接运行 PreEnqueue 函数
    if !shouldRecordMetric {
    	return pl.PreEnqueue(ctx, pod)
    }
    // 如果需要记录插件度量信息，则记录开始时间，并运行 PreEnqueue 函数
    startTime := p.clock.Now()
    s := pl.PreEnqueue(ctx, pod)
    // 使用 p.clock.Since 函数计算 PreEnqueue 函数的执行时间，并将结果异步地记录到 metricsRecorder 中
    p.metricsRecorder.ObservePluginDurationAsync(preEnqueue, pl.Name(), s.Code().String(), p.clock.Since(startTime).Seconds())
    return s
}
```

### addNominatedPodUnlocked

```go
func (npm *nominator) addNominatedPodUnlocked(pi *framework.PodInfo, nominatingInfo *framework.NominatingInfo) {
    // 总是删除pod（如果已经存在），以确保我们从不存储超过一个该pod的实例。
    npm.delete(pi.Pod) // 删除已经存在的 pod
    var nodeName string
    if nominatingInfo.Mode() == framework.ModeOverride { // 如果 nominatingInfo 的 Mode() 是 ModeOverride
        nodeName = nominatingInfo.NominatedNodeName // 则使用 nominatingInfo.NominatedNodeName 作为 nodeName
    } else if nominatingInfo.Mode() == framework.ModeNoop { // 如果 nominatingInfo 的 Mode() 是 ModeNoop
        if pi.Pod.Status.NominatedNodeName == "" { // 如果 pod 的 NominatedNodeName 是空的
            return // 直接返回，不进行后续操作
        }
        nodeName = pi.Pod.Status.NominatedNodeName // 否则使用 pod 的 NominatedNodeName 作为 nodeName
    }

    if npm.podLister != nil { // 如果 podLister 不为空
        // 如果 pod 被删除或已经被调度，则不进行提名
        updatedPod, err := npm.podLister.Pods(pi.Pod.Namespace).Get(pi.Pod.Name) // 获取更新后的 pod
        if err != nil { // 如果获取失败
            klog.V(4).InfoS("Pod doesn't exist in podLister, aborted adding it to the nominator", "pod", klog.KObj(pi.Pod))
            return // 直接返回，不进行后续操作
        }
        if updatedPod.Spec.NodeName != "" { // 如果 pod 已经被调度到节点
            klog.V(4).InfoS("Pod is already scheduled to a node, aborted adding it to the nominator", "pod", klog.KObj(pi.Pod), "node", updatedPod.Spec.NodeName)
            return // 直接返回，不进行后续操作
        }
    }

    npm.nominatedPodToNode[pi.Pod.UID] = nodeName // 将 pod 的 UID 作为 key，nodeName 作为 value 存储到 nominatedPodToNode 中
    for _, npi := range npm.nominatedPods[nodeName] { // 遍历 nominatedPods 中 nodeName 对应的 pod 列表
        if npi.Pod.UID == pi.Pod.UID { // 如果已经存在一个 UID 相同的 pod
            klog.V(4).InfoS("Pod already exists in the nominator", "pod", klog.KObj(npi.Pod))
            return // 直接返回，不进行后续操作
        }
    }
    npm.nominatedPods[nodeName] = append(npm.nominatedPods[nodeName], pi) // 将 pi 添加到 nominatedPods 中 nodeName 对应的 pod 列表中
}
```

## Activate

```GO
// Activate方法将给定的Pods移动到ActiveQ（活动队列），如果它们在UnschedulablePods（无法调度Pod）或BackoffQ（回退队列）中。
func (p *PriorityQueue) Activate(pods map[string]*v1.Pod) {
    //获取锁，避免并发访问
    p.lock.Lock()
    defer p.lock.Unlock()
    //用于记录是否有Pod被激活
    activated := false
    //循环处理每个Pod
    for _, pod := range pods {
        //如果成功激活该Pod，则将activated标记为true
        if p.activate(pod) {
            activated = true
        }
    }

    //如果有Pod被激活，则唤醒所有等待的goroutine
    if activated {
        p.cond.Broadcast()
    }
}
```

### activate

```go
// activate方法用于激活给定的Pod，返回一个布尔值指示该Pod是否已被激活。
func (p *PriorityQueue) activate(pod *v1.Pod) bool {
    // 验证该Pod是否已在活动队列中。
    if _, exists, _ := p.activeQ.Get(newQueuedPodInfoForLookup(pod)); exists {
        // 如果该Pod已经在活动队列中，则无需再次激活。
        return false
    }
    var pInfo *framework.QueuedPodInfo
    // 验证该Pod是否在无法调度Pod或回退队列中。
    if pInfo = p.unschedulablePods.get(pod); pInfo == nil {
        // 如果该Pod不属于无法调度Pod或回退队列，则不激活该Pod。
        if obj, exists, _ := p.podBackoffQ.Get(newQueuedPodInfoForLookup(pod)); !exists {
            klog.ErrorS(nil, "To-activate pod does not exist in unschedulablePods or backoffQ", "pod", klog.KObj(pod))
            return false
        } else {
        	pInfo = obj.(*framework.QueuedPodInfo)
        }
    }
    if pInfo == nil {
        // 冗余的安全检查。我们不应该到达这里。
        klog.ErrorS(nil, "Internal error: cannot obtain pInfo")
        return false
    }

    gated := pInfo.Gated
    if added, _ := p.addToActiveQ(pInfo); !added {
        return false
    }
    // 从无法调度Pod或回退队列中删除该Pod。
    p.unschedulablePods.delete(pInfo.Pod, gated)
    p.podBackoffQ.Delete(pInfo)
    // 更新统计信息。
    metrics.SchedulerQueueIncomingPods.WithLabelValues("active", ForceActivate).Inc()
    // 添加该Pod的信息到提名Pod队列中。
    p.addNominatedPodUnlocked(pInfo.PodInfo, nil)
    return true
}
```

#### newQueuedPodInfoForLookup

```go
func newQueuedPodInfoForLookup(pod *v1.Pod, plugins ...string) *framework.QueuedPodInfo {
	// Since this is only used for a lookup in the queue, we only need to set the Pod,
	// and so we avoid creating a full PodInfo, which is expensive to instantiate frequently.
	return &framework.QueuedPodInfo{
		PodInfo:              &framework.PodInfo{Pod: pod},
		UnschedulablePlugins: sets.New(plugins...),
	}
}
```

## AddUnschedulableIfNotPresent

```go
// AddUnschedulableIfNotPresent 如果队列中没有不能调度的 Pod，则将其插入队列。
// 通常情况下，PriorityQueue会将不能调度的Pod放入unschedulablePods队列中。
// 但是如果最近有一个移动请求，那么Pod就会被放到podBackoffQ队列中。
func (p *PriorityQueue) AddUnschedulableIfNotPresent(pInfo *framework.QueuedPodInfo, podSchedulingCycle int64) error {
    // 加锁，避免多个协程同时对PriorityQueue进行操作
    p.lock.Lock()
    defer p.lock.Unlock()
    // 获取Pod对象
    pod := pInfo.Pod
    // 检查Pod是否已经在unschedulablePods队列中
    if p.unschedulablePods.get(pod) != nil {
    	return fmt.Errorf("Pod %v is already present in unschedulable queue", klog.KObj(pod))
    }
    // 检查Pod是否已经在activeQ队列中
    if _, exists, _ := p.activeQ.Get(pInfo); exists {
        return fmt.Errorf("Pod %v is already present in the active queue", klog.KObj(pod))
    }

    // 检查Pod是否已经在podBackoffQ队列中
    if _, exists, _ := p.podBackoffQ.Get(pInfo); exists {
        return fmt.Errorf("Pod %v is already present in the backoff queue", klog.KObj(pod))
    }

    // 更新Pod的时间戳
    pInfo.Timestamp = p.clock.Now()

    // 如果存在移动请求，则将Pod添加到podBackoffQ队列中；否则，将Pod添加到unschedulablePods队列中。
    for plugin := range pInfo.UnschedulablePlugins {
        metrics.UnschedulableReason(plugin, pInfo.Pod.Spec.SchedulerName).Inc()
    }
    if p.moveRequestCycle >= podSchedulingCycle {
        // 添加Pod到podBackoffQ队列中
        if err := p.podBackoffQ.Add(pInfo); err != nil {
            return fmt.Errorf("error adding pod %v to the backoff queue: %v", klog.KObj(pod), err)
        }
        // 日志记录
        klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pod), "event", ScheduleAttemptFailure, "queue", backoffQName)
        // 统计
        metrics.SchedulerQueueIncomingPods.WithLabelValues("backoff", ScheduleAttemptFailure).Inc()
    } else {
        // 添加Pod到unschedulablePods队列中
        p.unschedulablePods.addOrUpdate(pInfo)
        // 日志记录
        klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pod), "event", ScheduleAttemptFailure, "queue", unschedulablePods)
        // 统计
        metrics.SchedulerQueueIncomingPods.WithLabelValues("unschedulable", ScheduleAttemptFailure).Inc()
    }

    // 将Pod添加到nominatedPods和nominatedPodToNode映射中
    p.addNominatedPodUnlocked(pInfo.PodInfo, nil)
    return nil
}
```

## SchedulingCycle

```go
func (p *PriorityQueue) SchedulingCycle() int64 {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.schedulingCycle
}
```

## Pop

```go
// Pop 方法弹出 active queue 中最高优先级的 pod 并返回。如果 activeQ 为空，则它会阻塞等待，
// 直到有新项添加到队列中。每当弹出一个 pod 时，就会递增调度周期。
func (p *PriorityQueue) Pop() (*framework.QueuedPodInfo, error) {
    // 获取锁
    p.lock.Lock()
    defer p.lock.Unlock()
    // 当前 activeQ 队列为空时，等待
    for p.activeQ.Len() == 0 {
        // 当关闭队列时，返回错误
        if p.closed {
            return nil, fmt.Errorf(queueClosed)
        }
        // 如果队列为空，就等待条件变量的通知
        p.cond.Wait()
    }
    // 从队列中获取下一个 pod
    obj, err := p.activeQ.Pop()
    if err != nil {
    	return nil, err
    }
    // 将 obj 转换为 QueuedPodInfo 类型
    pInfo := obj.(*framework.QueuedPodInfo)
    // 增加尝试次数
    pInfo.Attempts++
    // 递增调度周期
    p.schedulingCycle++
    return pInfo, nil
}
```



```go
func (p *PriorityQueue) Update(oldPod, newPod *v1.Pod) error {
	p.lock.Lock()  // 互斥锁加锁
	defer p.lock.Unlock() // 解锁

	if oldPod != nil {
		oldPodInfo := newQueuedPodInfoForLookup(oldPod)

		// 如果pod已经在活动队列中，则直接在那里更新它。
		if oldPodInfo, exists, _ := p.activeQ.Get(oldPodInfo); exists {
			pInfo := updatePod(oldPodInfo, newPod)
			p.updateNominatedPodUnlocked(oldPod, pInfo.PodInfo)
			return p.activeQ.Update(pInfo)
		}

		// 如果pod在回退队列中，则在那里更新它。
		if oldPodInfo, exists, _ := p.podBackoffQ.Get(oldPodInfo); exists {
			pInfo := updatePod(oldPodInfo, newPod)
			p.updateNominatedPodUnlocked(oldPod, pInfo.PodInfo)
			return p.podBackoffQ.Update(pInfo)
		}
	}

	// 如果pod在不可调度队列中，则更新它可能使其可调度。
	if usPodInfo := p.unschedulablePods.get(newPod); usPodInfo != nil {
		pInfo := updatePod(usPodInfo, newPod)
		p.updateNominatedPodUnlocked(oldPod, pInfo.PodInfo)

		if isPodUpdated(oldPod, newPod) {
			gated := usPodInfo.Gated
			if p.isPodBackingoff(usPodInfo) {
				if err := p.podBackoffQ.Add(pInfo); err != nil {
					return err
				}
				p.unschedulablePods.delete(usPodInfo.Pod, gated)
				klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", PodUpdate, "queue", backoffQName)
			} else {
				if added, err := p.addToActiveQ(pInfo); !added {
					return err
				}
				p.unschedulablePods.delete(usPodInfo.Pod, gated)
				klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", BackoffComplete, "queue", activeQName)
				p.cond.Broadcast()
			}
		} else {
			// 如果更新后pod不可调度，则保留在不可调度队列中。
			p.unschedulablePods.addOrUpdate(pInfo)
		}

		return nil
	}

	// 如果pod不在任何队列中，则将其添加到活动队列中。
	pInfo := p.newQueuedPodInfo(newPod)
    // 如果将Pod添加到活动队列中成功，added的值为true，否则为false。
	// 如果无法添加Pod，则返回错误。
    if added, err := p.addToActiveQ(pInfo); !added {
		return err
	}
    // 将Pod添加到已锁定的优先级队列中的pInfo.PodInfo中
	// 这里第二个参数为nil是因为Pod是从未安排过的，所以不会有提名的节点。
	p.addNominatedPodUnlocked(pInfo.PodInfo, nil)
	klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", PodUpdate, "queue", activeQName)
	p.cond.Broadcast()
	return nil
}
```

### updatePod

```go
func updatePod(oldPodInfo interface{}, newPod *v1.Pod) *framework.QueuedPodInfo {
	pInfo := oldPodInfo.(*framework.QueuedPodInfo)
	pInfo.Update(newPod)
	return pInfo
}
```

### updateNominatedPodUnlocked

```go
// updateNominatedPodUnlocked函数实现pod更新时的提名信息的更新
func (npm *nominator) updateNominatedPodUnlocked(oldPod *v1.Pod, newPodInfo *framework.PodInfo) {
    // 在某些情况下，可能会收到没有“NominatedNode”的Update事件，
    // 这种情况下需要在内存中为该pod保留提名的节点（“NominatedNode”）。
    var nominatingInfo *framework.NominatingInfo
    // 如果Update事件表示：
    //（1）添加了NominatedNode信息
    //（2）更新了NominatedNode信息
    //（3）删除了NominatedNode信息
    // 则不会执行以下if块。
    if NominatedNodeName(oldPod) == "" && NominatedNodeName(newPodInfo.Pod) == "" {
        // 如果存在提名节点信息，则需要继续保留NominatedNode
        if nnn, ok := npm.nominatedPodToNode[oldPod.UID]; ok {
                nominatingInfo = &framework.NominatingInfo{
                    NominatingMode: framework.ModeOverride,
                    NominatedNodeName: nnn,
            }
        }
    }
    // 不管提名节点名是否更改，都要更新pod指针，因此执行更新操作
    npm.delete(oldPod)
    npm.addNominatedPodUnlocked(newPodInfo, nominatingInfo)
}
```

## Delete

```go
func (p *PriorityQueue) Delete(pod *v1.Pod) error {
    // 获取锁，防止其他 goroutine 干扰
    p.lock.Lock()
    // 函数退出时释放锁
    defer p.lock.Unlock()
    // 删除 nominatedPods 中指定的 pod，如果它存在
    p.deleteNominatedPodIfExistsUnlocked(pod)
    // 创建一个待查找 pod 的新的队列信息对象
    pInfo := newQueuedPodInfoForLookup(pod)
    // 从 activeQ 中删除指定的 pod
    if err := p.activeQ.Delete(pInfo); err != nil {
        // 可能该项未在 activeQ 中找到，尝试从 podBackoffQ 中删除
        p.podBackoffQ.Delete(pInfo)
        // 从 unschedulablePods 中获取指定 pod 的信息
        if pInfo = p.unschedulablePods.get(pod); pInfo != nil {
        	// 如果 pInfo 存在，则将 pod 从 unschedulablePods 中删除，同时将其加入 gatedPods 列表
        	p.unschedulablePods.delete(pod, pInfo.Gated)
        }
    }
    return nil
}
```

### deleteNominatedPodIfExistsUnlocked

```go
func (npm *nominator) deleteNominatedPodIfExistsUnlocked(pod *v1.Pod) {
	npm.delete(pod)
}
```

## MoveAllToActiveOrBackoffQueue

```go
// MoveAllToActiveOrBackoffQueue 将 unschedulablePods 中的所有 pod 移动到 activeQ 或 backoffQ 中。
// 此函数添加了所有的 pod 并发出条件变量信号，以确保如果 Pop() 正在等待项，则在所有 pod 都在队列中且头部是最高优先级的 pod 后接收到信号。
func (p *PriorityQueue) MoveAllToActiveOrBackoffQueue(event framework.ClusterEvent, preCheck PreEnqueueCheck) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.moveAllToActiveOrBackoffQueue(event, preCheck)
}
```

### moveAllToActiveOrBackoffQueue

```GO
// 注意：此函数假定调用者已获取锁。
// moveAllToActiveOrBackoffQueue函数将所有 pod 从 unschedulablePods 移动到 activeQ 或 backoffQ。
// 此函数添加所有 pod，然后信号条件变量以确保如果 Pop() 等待项目，则在所有 pod 都在队列中且头部为最高优先级的 pod 后收到信号。
func (p *PriorityQueue) moveAllToActiveOrBackoffQueue(event framework.ClusterEvent, preCheck PreEnqueueCheck) {
    // 创建一个空的 unschedulablePods 切片，长度为 p.unschedulablePods.podInfoMap 的长度。
    unschedulablePods := make([]*framework.QueuedPodInfo, 0, len(p.unschedulablePods.podInfoMap))
    // 遍历 p.unschedulablePods.podInfoMap 中的每一个元素
    for _, pInfo := range p.unschedulablePods.podInfoMap {
        // 如果 preCheck 为 nil 或者 preCheck(pInfo.Pod) 返回 true，则将 pInfo 加入 unschedulablePods 切片中
        if preCheck == nil || preCheck(pInfo.Pod) {
        	unschedulablePods = append(unschedulablePods, pInfo)
        }
    }
    // 将 unschedulablePods 中的所有 pod 移动到 activeQ 或 backoffQ 中
    p.movePodsToActiveOrBackoffQueue(unschedulablePods, event)
}
```

### movePodsToActiveOrBackoffQueue

```GO
// NOTE: 此函数假定锁已在调用方处被获取
func (p *PriorityQueue) movePodsToActiveOrBackoffQueue(podInfoList []*framework.QueuedPodInfo, event framework.ClusterEvent) {
	activated := false  // 是否有 Pod 被添加到 active 队列
	for _, pInfo := range podInfoList {
		// 如果事件不能使 Pod 可调度，则继续循环。
        // 注意：如果 pInfo.UnschedulablePlugins 为 nil，则表示存在异常错误，或者 Pod 的调度由 PreFilter、Filter 和 Permit 以外的插件失败。
        // 在这种情况下，仍希望将其移动到队列中。
		if len(pInfo.UnschedulablePlugins) != 0 && !p.podMatchesEvent(pInfo, event) {
			continue
		}
		pod := pInfo.Pod
		if p.isPodBackingoff(pInfo) {
			if err := p.podBackoffQ.Add(pInfo); err != nil {
				klog.ErrorS(err, "Error adding pod to the backoff queue", "pod", klog.KObj(pod))
			} else {
				klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", event, "queue", backoffQName)
				metrics.SchedulerQueueIncomingPods.WithLabelValues("backoff", event.Label).Inc()
				p.unschedulablePods.delete(pod, pInfo.Gated)
			}
		} else {
			gated := pInfo.Gated
			if added, _ := p.addToActiveQ(pInfo); added {
				klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", event, "queue", activeQName)
				activated = true
				metrics.SchedulerQueueIncomingPods.WithLabelValues("active", event.Label).Inc()
				p.unschedulablePods.delete(pod, gated)
			}
		}
	}
	p.moveRequestCycle = p.schedulingCycle // 设置 moveRequestCycle，表示此次操作已完成
	if activated {
		p.cond.Broadcast() // 通知等待在条件变量上的 goroutine
	}
}
```

#### podMatchesEvent

```GO
// 检查Pod是否可以在触发事件后调度。
// 通过查找全局的clusterEventMap注册表来实现这一点。
func (p *PriorityQueue) podMatchesEvent(podInfo *framework.QueuedPodInfo, clusterEvent framework.ClusterEvent) bool {
    // 如果事件是通配符，则返回true。
    if clusterEvent.IsWildCard() {
    	return true
    }
	for evt, nameSet := range p.clusterEventMap {
        // 首先验证两个ClusterEvents是否匹配：
        // - 要么插件方的注册事件是通配符事件，
        // - 要么两个事件具有相同的资源字段和*兼容*ActionType。
        //   注意，ActionTypes不需要*完全相同*。我们检查ANDed值是否为零或不为零。这样，很容易判断Update和Delete不兼容，但Update和All兼容。
        evtMatch := evt.IsWildCard() ||
            (evt.Resource == clusterEvent.Resource && evt.ActionType&clusterEvent.ActionType != 0)

        // 然后验证插件名称是否匹配。
        // 注意，如果不匹配，我们不应继续搜索。
        if evtMatch && intersect(nameSet, podInfo.UnschedulablePlugins) {
            return true
        }
    }

    return false
}
```

#### isPodBackingoff

```GO
// 判断当前 Pod 是否处于 Backoff 状态
func (p *PriorityQueue) isPodBackingoff(podInfo *framework.QueuedPodInfo) bool {
	if podInfo.Gated {
		return false
	}
	boTime := p.getBackoffTime(podInfo)
	return boTime.After(p.clock.Now())

}

// 用于计算 Backoff 的截止时间
func (p *PriorityQueue) getBackoffTime(podInfo *framework.QueuedPodInfo) time.Time {
	duration := p.calculateBackoffDuration(podInfo)
	backoffTime := podInfo.Timestamp.Add(duration)
	return backoffTime
}

// 根据 Pod 当前的重试次数计算 Backoff 需要的时间
func (p *PriorityQueue) calculateBackoffDuration(podInfo *framework.QueuedPodInfo) time.Duration {
	duration := p.podInitialBackoffDuration
	for i := 1; i < podInfo.Attempts; i++ {
		// Use subtraction instead of addition or multiplication to avoid overflow.
		if duration > p.podMaxBackoffDuration-duration {
			return p.podMaxBackoffDuration
		}
		duration += duration
	}
	return duration
}
```

## AssignedPodAdded

```GO
// 当添加一个已绑定的Pod时，调用AssignedPodAdded函数。
// 此Pod的创建可能会使具有匹配亲和性条件的挂起Pod可调度。
func (p *PriorityQueue) AssignedPodAdded(pod *v1.Pod) {
    // 加锁
    p.lock.Lock()
    // 将匹配亲和性条件的不可调度Pod移动到ActiveQueue或BackoffQueue
    p.movePodsToActiveOrBackoffQueue(p.getUnschedulablePodsWithMatchingAffinityTerm(pod), AssignedPodAdd)
    // 解锁
    p.lock.Unlock()
}
```

getUnschedulablePodsWithMatchingAffinityTerm

```GO
// getUnschedulablePodsWithMatchingAffinityTerm 返回那些有任何一个关联性匹配“pod”的无法调度的pod。
// 注意：此函数假定在调用方已获取锁。
func (p *PriorityQueue) getUnschedulablePodsWithMatchingAffinityTerm(pod *v1.Pod) []*framework.QueuedPodInfo {
    // 获取Pod所在命名空间的标签信息。
    nsLabels := interpodaffinity.GetNamespaceLabelsSnapshot(pod.Namespace, p.nsLister)

    // 定义一个数组用于存储需要移动的Pod信息。
    var podsToMove []*framework.QueuedPodInfo
    // 循环未调度的Pod信息
    for _, pInfo := range p.unschedulablePods.podInfoMap {
        // 循环Pod所需的所有关联性标签
        for _, term := range pInfo.RequiredAffinityTerms {
            // 如果有一个关联性标签与当前Pod匹配，就将Pod信息添加到待移动Pod的数组中
            if term.Matches(pod, nsLabels) {
                podsToMove = append(podsToMove, pInfo)
                break
            }
        }

    }
    // 返回待移动的Pod信息数组
    return podsToMove
}
```

## AssignedPodUpdated

```GO
// AssignedPodUpdated 在绑定的Pod更新时被调用。标签的更改可能会使等待调度的Pod与匹配关联性条件的Pod调度。
func (p *PriorityQueue) AssignedPodUpdated(pod *v1.Pod) {
    // 获取锁
    p.lock.Lock()
    // 如果Pod的资源被调整为更小，则将队列中的所有Pod移动到Active或Backoff队列中
    if isPodResourcesResizedDown(pod) {
        p.moveAllToActiveOrBackoffQueue(AssignedPodUpdate, nil)
    } else {
        // 获取所有匹配关联性条件的待移动Pod信息，然后将它们移动到Active或Backoff队列中
        p.movePodsToActiveOrBackoffQueue(p.getUnschedulablePodsWithMatchingAffinityTerm(pod), AssignedPodUpdate)
    }
    // 释放锁
    p.lock.Unlock()
}
```

## PendingPods

```GO
// PendingPods 返回队列中所有等待调度的Pod；并伴随一个调试字符串记录每个队列中Pod的数量。
// 此函数用于调度程序缓存转储器和比较器中的调试目的。
func (p *PriorityQueue) PendingPods() ([]*v1.Pod, string) {
    // 获取读锁
    p.lock.RLock()
    defer p.lock.RUnlock()
    var result []*v1.Pod
    // 遍历Active队列，并将队列中每个Pod添加到result中
    for _, pInfo := range p.activeQ.List() {
        result = append(result, pInfo.(*framework.QueuedPodInfo).Pod)
    }
    // 遍历Backoff队列，并将队列中每个Pod添加到result中
    for _, pInfo := range p.podBackoffQ.List() {
        result = append(result, pInfo.(*framework.QueuedPodInfo).Pod)
    }
    // 遍历UnschedulablePods队列，并将队列中每个Pod添加到result中
    for _, pInfo := range p.unschedulablePods.podInfoMap {
        result = append(result, pInfo.Pod)
    }
    // 返回result列表和一个记录队列中Pod数量的格式化字符串
    return result, fmt.Sprintf(pendingPodsSummary, p.activeQ.Len(), p.podBackoffQ.Len(), len(p.unschedulablePods.podInfoMap))
}
```

## Close

```GO
// Close 关闭优先队列。
func (p *PriorityQueue) Close() {
    // 获取写锁
    p.lock.Lock()
    defer p.lock.Unlock()
    // 关闭stop channel
    close(p.stop)
    // 将closed标记为true
    p.closed = true
    // 广播条件变量
    p.cond.Broadcast()
}

```

## Run

```go
func (p *PriorityQueue) Run() {
    // 检查是否有pod完成了 backoff 重试，如果有，则将这些pod移动到active队列中。
	go wait.Until(p.flushBackoffQCompleted, 1.0*time.Second, p.stop)
    // 检查是否有未被调度的pod超过了预设的时间阈值，如果有，则将这些pod移动到active或者backoff队列中。
	go wait.Until(p.flushUnschedulablePodsLeftover, 30*time.Second, p.stop)
}
```

### flushBackoffQCompleted

```go
func (p *PriorityQueue) flushBackoffQCompleted() {
	p.lock.Lock()
	defer p.lock.Unlock()
	activated := false // 记录是否激活了 Pod
	for {
		rawPodInfo := p.podBackoffQ.Peek() // 获取 backoff 队列中的第一个 Pod
		if rawPodInfo == nil { // 如果队列为空，则退出循环
			break
		}
		pInfo := rawPodInfo.(*framework.QueuedPodInfo) // 将 Pod 信息转换为 QueuedPodInfo
		pod := pInfo.Pod
		if p.isPodBackingoff(pInfo) { // 如果 Pod 仍在 backoff 状态中，则退出循环
			break
		}
		_, err := p.podBackoffQ.Pop() // 将 Pod 从 backoff 队列中弹出
		if err != nil { // 如果无法弹出 Pod，则输出错误日志并退出循环
			klog.ErrorS(err, "Unable to pop pod from backoff queue despite backoff completion", "pod", klog.KObj(pod))
			break
		}
		if added, _ := p.addToActiveQ(pInfo); added { // 将 Pod 添加到 active 队列中
			klog.V(5).InfoS("Pod moved to an internal scheduling queue", "pod", klog.KObj(pod), "event", BackoffComplete, "queue", activeQName) // 输出日志
			metrics.SchedulerQueueIncomingPods.WithLabelValues("active", BackoffComplete).Inc() // 记录指标
			activated = true // 设置激活标志
		}
	}

	if activated { // 如果激活了 Pod，则唤醒等待的 goroutine
		p.cond.Broadcast()
	}
}
```

### flushUnschedulablePodsLeftover

```go
func (p *PriorityQueue) flushUnschedulablePodsLeftover() {
	// 获取锁
	p.lock.Lock()
	defer p.lock.Unlock()

	// 定义需要移动的 Pods 切片和当前时间
	var podsToMove []*framework.QueuedPodInfo
	currentTime := p.clock.Now()
	// 遍历未调度队列中的 PodInfoMap
	for _, pInfo := range p.unschedulablePods.podInfoMap {
		lastScheduleTime := pInfo.Timestamp
		// 如果当前时间与 Pod 最近一次尝试调度的时间差值大于指定的时间阈值
		if currentTime.Sub(lastScheduleTime) > p.podMaxInUnschedulablePodsDuration {
			// 则将该 PodInfo 加入到需要移动的 PodInfo 切片中
			podsToMove = append(podsToMove, pInfo)
		}
	}

	// 如果有需要移动的 Pods
	if len(podsToMove) > 0 {
		// 将这些 Pods 移动到调度队列或者回退队列
		p.movePodsToActiveOrBackoffQueue(podsToMove, UnschedulableTimeout)
	}
}
```
