---
id: 4-kube-scheduler-code 
title: scheduler中cache相关代码走读
description: scheduler中cache相关代码走读
keywords:
  - kubernetes
  - kube-scheduler
slug: /
---

## 作用

在Scheduler结构体中，Cache是一个存储调度器内部状态信息的缓存，它可以被NodeLister和Algorithm使用。当调度器需要进行节点评分时，可以使用Cache中存储的节点状态信息而不必重新从Kubernetes API Server中获取。这样可以避免频繁地访问API Server，降低网络延迟和负载，并提高调度器的性能和效率。此外，Cache还可以用于存储一些调度器内部的数据结构，以便在多个函数之间共享和复用。

## Interface{}

```go
// Cache 收集 Pod 的信息并提供节点级别的聚合信息，旨在让通用调度程序进行有效的查找。
// Cache 的操作以 Pod 为中心。它基于 Pod 事件进行增量更新。
// Pod 事件通过网络发送。我们无法保证所有事件都会传送：
// 我们使用 Reflector 从远程进行列表和监视。
// Reflector 可能会很慢并进行重新列出，这会导致事件丢失。
//
// 调度器缓存中 Pod 事件的状态机：
//
//	+-------------------------------------------+  +----+
//	|                            Add            |  |    |
//	|                                           |  |    | Update
//	+      Assume                Add            v  v    |
//
// Initial +--------> Assumed +------------+---> Added <--+
//
//	^                +   +               |       +
//	|                |   |               |       |
//	|                |   |           Add |       | Remove
//	|                |   |               |       |
//	|                |   |               +       |
//	+----------------+   +-----------> Expired   +----> Deleted
//	      Forget             Expire
//
// 注意，假设的 Pod 可能会过期，因为如果我们已经很久没有收到通知我们的 Add 事件，
// 那么可能存在一些问题，我们不应该再在缓存中保留该 Pod。
//
// 请注意，“Initial”、“Expired”和“Deleted” Pod 实际上不存在于缓存中。
// 基于现有的用例，我们做出以下假设：
// - 没有 Pod 会被假设两次
// - 可以添加 Pod 而不通过调度程序。在这种情况下，我们会看到 Add 事件但不会看到 Assume 事件。
// - 如果没有添加 Pod，它将不会被删除或更新。
// - “Expired”和“Deleted”都是有效的最终状态。在某些问题的情况下，例如网络问题，
// 一个 Pod 可能已经改变了其状态（例如添加和删除），而没有向缓存发送通知。
type Cache interface {
    // NodeCount 返回缓存中节点的数量。
    // 不要在测试之外使用。
    NodeCount() int
    // PodCount 返回缓存中pod的数量（包括已删除节点上的pod）。
    // 不要在测试之外使用。
    PodCount() (int, error)

    // AssumePod 假设一个调度的pod，并将pod的信息聚合到其节点上。
    // 实现还决定了在确认之前（接收到Add事件）将pod过期的策略。
    // 过期后，pod的信息将被减去。
    AssumePod(pod *v1.Pod) error

    // FinishBinding 表示可以过期假设的pod的缓存
    FinishBinding(pod *v1.Pod) error

    // ForgetPod 从缓存中删除一个假设的pod。
    ForgetPod(pod *v1.Pod) error

    // AddPod 确认一个pod（如果它是假设的），或者在过期后重新添加它。
    // 如果重新添加，pod的信息将再次被添加。
    AddPod(pod *v1.Pod) error

    // UpdatePod 删除oldPod的信息，并添加newPod的信息。
    UpdatePod(oldPod, newPod *v1.Pod) error

    // RemovePod 删除一个pod。pod的信息将从已分配的节点中减去。
    RemovePod(pod *v1.Pod) error

    // GetPod 根据指定的pod的命名空间和名称从缓存中返回pod。
    GetPod(pod *v1.Pod) (*v1.Pod, error)

    // IsAssumedPod 如果pod是假设的并且没有过期，则返回true。
    IsAssumedPod(pod *v1.Pod) (bool, error)

    // AddNode 添加关于节点的整体信息。
    // 它返回一个添加的NodeInfo对象的克隆。
    AddNode(node *v1.Node) *framework.NodeInfo

    // UpdateNode 更新关于节点的整体信息。
    // 它返回一个更新后的NodeInfo对象的克隆。
    UpdateNode(oldNode, newNode *v1.Node) *framework.NodeInfo

    // RemoveNode 删除关于节点的整体信息。
    RemoveNode(node *v1.Node) error

    // UpdateSnapshot 更新传递的infoSnapshot以包含当前缓存的内容。
    // 节点信息包含在此节点上调度的pod的聚合信息（包括假设的pod）。
    // 快照仅包括在调用此函数时未删除的节点。
    // nodeinfo.Node() 对于快照中的所有节点保证不为空。
    UpdateSnapshot(nodeSnapshot *Snapshot) error

    // Dump 生成当前缓存的转储。
    Dump() *Dump
}

// Dump 结构体定义了一个缓存的快照，包含了当前缓存中的假设的 Pod 和节点信息。
type Dump struct {
    // AssumedPods 存储了当前缓存中所有假设的 Pod 的集合，使用字符串类型的集合实现。
    AssumedPods sets.Set[string]
    // Nodes 存储了当前缓存中所有节点的信息，使用字符串类型的键和 framework.NodeInfo 类型的值组成的映射实现。
	Nodes map[string]*framework.NodeInfo
}
```

## cacheImpl

```go
// cacheImpl 结构体实现了 Cache 接口，并且包含了一个缓存的实现。
type cacheImpl struct {
    // stop 是一个只接收通道，用于停止缓存的更新操作。
    stop <-chan struct{}
    // ttl 是缓存中信息的过期时间。
    ttl time.Duration
    // period 是缓存更新操作的时间间隔。
    period time.Duration
	// 这个互斥锁用于保护 cacheImpl 结构体内的所有字段。
    mu sync.RWMutex
    // assumedPods 是一个存储了假设的 Pod 键的集合。
    // 这些键可以进一步用于在 podStates 中获取对应的 podState。
    assumedPods sets.Set[string]
    // podStates 是一个从 Pod 键到 podState 的映射。
    podStates map[string]*podState
    // nodes 是一个从节点键到 nodeInfoListItem 的映射。
    nodes map[string]*nodeInfoListItem
    // headNode 指向 "nodes" 中最近更新的 NodeInfo，它是链表的头节点。
    headNode *nodeInfoListItem
    // nodeTree 是一个节点信息的二叉搜索树。
    nodeTree *nodeTree
    // imageStates 是一个从镜像名称到 imageState 的映射。
    imageStates map[string]*imageState
}

// nodeInfoListItem 是一个节点信息的链表节点。
type nodeInfoListItem struct {
    // info 是节点信息。
    info *framework.NodeInfo
    // next 指向链表中的下一个节点。
    next *nodeInfoListItem
    // prev 指向链表中的上一个节点。
    prev *nodeInfoListItem
}

// podState 是一个用于表示 Pod 状态的结构体。
type podState struct {
    // pod 是一个指向 v1.Pod 对象的指针，表示对应的 Pod。
    pod *v1.Pod
    // deadline 是一个时间戳，用于判断假定的 Pod 是否过期。
    // 如果 deadline 为 nil，则假定的 Pod 永远不会过期。
    deadline *time.Time
    // bindingFinished 是一个布尔值，表示是否完成了 Pod 的绑定过程。
    // 用于阻止缓存过早地删除假定的 Pod。
    bindingFinished bool
}

// imageState 是一个用于表示镜像状态的结构体。
type imageState struct {
    // size 是镜像的大小。
    size int64
    // nodes 是一个集合，包含了拥有该镜像的节点的名称。
    nodes sets.Set[string]
}
```

```GO
func newNodeInfoListItem(ni *framework.NodeInfo) *nodeInfoListItem {
	return &nodeInfoListItem{
		info: ni,
	}
}

```



## New

```GO
func New(ttl time.Duration, stop <-chan struct{}) Cache {
	cache := newCache(ttl, cleanAssumedPeriod, stop)
	cache.run()
	return cache
}

func newCache(ttl, period time.Duration, stop <-chan struct{}) *cacheImpl {
	return &cacheImpl{
		ttl:    ttl,
		period: period,
		stop:   stop,

		nodes:       make(map[string]*nodeInfoListItem),
		nodeTree:    newNodeTree(nil),
		assumedPods: sets.New[string](),
		podStates:   make(map[string]*podState),
		imageStates: make(map[string]*imageState),
	}
}
```

## 方法

```GO
func (cache *cacheImpl) NodeCount() int {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return len(cache.nodes)
}

func (cache *cacheImpl) PodCount() (int, error) {
	// 对 cache 进行读锁，确保并发安全
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	// 初始化 Pod 计数器为 0
	count := 0

	// 遍历缓存中的节点信息，统计每个节点上的 Pod 数量并累加到计数器中
	for _, n := range cache.nodes {
		count += len(n.info.Pods)
	}

	// 返回统计得到的 Pod 总数和空错误值
	return count, nil
}

func (cache *cacheImpl) AssumePod(pod *v1.Pod) error {
	// 根据传入的 Pod 对象获取 Pod 的键值（key）
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	// 对 cache 进行写锁，确保并发安全
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// 检查当前 Pod 是否已存在于缓存中，如果存在，则返回错误信息
	if _, ok := cache.podStates[key]; ok {
		return fmt.Errorf("pod %v(%v) is in the cache, so can't be assumed", key, klog.KObj(pod))
	}

	// 将 Pod 添加到缓存，并设置为假设的状态
	return cache.addPod(pod, true)
}

func (cache *cacheImpl) FinishBinding(pod *v1.Pod) error {
	return cache.finishBinding(pod, time.Now())
}

func (cache *cacheImpl) ForgetPod(pod *v1.Pod) error {
	// 获取 Pod 的缓存键值
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	// 对 cache 进行写锁，确保并发安全
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// 从缓存中获取当前 Pod 的状态
	currState, ok := cache.podStates[key]

	// 如果当前 Pod 的状态存在，并且当前 Pod 的 NodeName 和缓存中的 Pod 的 NodeName 不一致，返回错误
	if ok && currState.pod.Spec.NodeName != pod.Spec.NodeName {
		return fmt.Errorf("pod %v(%v) was assumed on %v but assigned to %v", key, klog.KObj(pod), pod.Spec.NodeName, currState.pod.Spec.NodeName)
	}

	// 只有被假定的 Pod 可以被遗忘
	if ok && cache.assumedPods.Has(key) {
		// 从缓存中移除 Pod
		return cache.removePod(pod)
	}

	// 如果当前 Pod 的状态不存在或者未被假定，则返回错误
	return fmt.Errorf("pod %v(%v) wasn't assumed so cannot be forgotten", key, klog.KObj(pod))
}

func (cache *cacheImpl) AddPod(pod *v1.Pod) error {
	// 获取 Pod 的缓存键值
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	// 对 cache 进行写锁，确保并发安全
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// 从缓存中获取当前 Pod 的状态
	currState, ok := cache.podStates[key]

	switch {
	case ok && cache.assumedPods.Has(key):
		// 当 Pod 被假定时，已经将 Pod 添加到了缓存中，
		// 这里进行更新，以确保 Pod 的状态是最新的。
		if err = cache.updatePod(currState.pod, pod); err != nil {
			klog.ErrorS(err, "Error occurred while updating pod")
		}
		if currState.pod.Spec.NodeName != pod.Spec.NodeName {
			// Pod 被添加到了一个与其假定的节点不同的节点上。
			klog.InfoS("Pod was added to a different node than it was assumed", "podKey", key, "pod", klog.KObj(pod), "assumedNode", klog.KRef("", pod.Spec.NodeName), "currentNode", klog.KRef("", currState.pod.Spec.NodeName))
			return nil
		}
	case !ok:
		// Pod 已过期，需要将其重新添加到缓存中。
		if err = cache.addPod(pod, false); err != nil {
			klog.ErrorS(err, "Error occurred while adding pod")
		}
	default:
		return fmt.Errorf("pod %v(%v) was already in added state", key, klog.KObj(pod))
	}

	return nil
}

func (cache *cacheImpl) UpdatePod(oldPod, newPod *v1.Pod) error {
	// 获取旧 Pod 的 key
	key, err := framework.GetPodKey(oldPod)
	if err != nil {
		return err
	}

	cache.mu.Lock() // 加锁
	defer cache.mu.Unlock() // 解锁

	currState, ok := cache.podStates[key] // 从缓存中获取当前 Pod 的状态
	if !ok {
		return fmt.Errorf("pod %v(%v) is not added to scheduler cache, so cannot be updated", key, klog.KObj(oldPod))
		// 如果缓存中没有当前 Pod 的状态，则返回错误，表示无法更新该 Pod
	}

	// 一个被假定的 Pod 不会有 Update/Remove 事件。在 Update 事件之前，它需要有 Add 事件，
	// 在这种情况下状态会从 Assumed 变为 Added。
	if cache.assumedPods.Has(key) {
		return fmt.Errorf("assumed pod %v(%v) should not be updated", key, klog.KObj(oldPod))
		// 如果当前 Pod 的状态为假定状态（Assumed），则返回错误，表示不能更新该 Pod
	}

	if currState.pod.Spec.NodeName != newPod.Spec.NodeName {
		// 如果当前 Pod 的节点名与新 Pod 的节点名不一致，表示 Pod 在不同的节点上进行了更新
		klog.ErrorS(nil, "Pod updated on a different node than previously added to", "podKey", key, "pod", klog.KObj(oldPod))
		klog.ErrorS(nil, "scheduler cache is corrupted and can badly affect scheduling decisions")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		// 输出错误日志，表示调度缓存已损坏，并且可能会严重影响调度决策，然后刷新日志并退出程序
	}
	return cache.updatePod(oldPod, newPod) // 调用 updatePod 方法更新 Pod 的状态
}

func (cache *cacheImpl) RemovePod(pod *v1.Pod) error {
	// 获取待删除 Pod 的 key
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock() // 加锁
	defer cache.mu.Unlock() // 解锁

	currState, ok := cache.podStates[key] // 从缓存中获取当前 Pod 的状态
	if !ok {
		return fmt.Errorf("pod %v(%v) is not found in scheduler cache, so cannot be removed from it", key, klog.KObj(pod))
		// 如果缓存中没有当前 Pod 的状态，则返回错误，表示无法从缓存中删除该 Pod
	}
	if currState.pod.Spec.NodeName != pod.Spec.NodeName {
		// 如果当前 Pod 的节点名与待删除 Pod 的节点名不一致，表示 Pod 在不同的节点上被添加
		klog.ErrorS(nil, "Pod was added to a different node than it was assumed", "podKey", key, "pod", klog.KObj(pod), "assumedNode", klog.KRef("", pod.Spec.NodeName), "currentNode", klog.KRef("", currState.pod.Spec.NodeName))
		if pod.Spec.NodeName != "" {
			// 当调度器错过了一个删除事件并从 informer 缓存中获取最后已知状态时，NodeName 可能为空。
			klog.ErrorS(nil, "scheduler cache is corrupted and can badly affect scheduling decisions")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	}
	return cache.removePod(currState.pod) // 调用 removePod 方法从缓存中删除 Pod 的状态
}

func (cache *cacheImpl) GetPod(pod *v1.Pod) (*v1.Pod, error) {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return nil, err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	podState, ok := cache.podStates[key]
	if !ok {
		return nil, fmt.Errorf("pod %v(%v) does not exist in scheduler cache", key, klog.KObj(pod))
	}

	return podState.pod, nil
}

func (cache *cacheImpl) IsAssumedPod(pod *v1.Pod) (bool, error) {
	// 获取待判断的 Pod 的 key
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return false, err
	}

	cache.mu.RLock() // 加读锁
	defer cache.mu.RUnlock() // 解读锁

	return cache.assumedPods.Has(key), nil
	// 返回缓存中是否存在待判断 Pod 的状态，以及可能的错误信息
}

func (cache *cacheImpl) AddNode(node *v1.Node) *framework.NodeInfo {
	// 向缓存中添加新的节点信息

	cache.mu.Lock() // 加写锁
	defer cache.mu.Unlock() // 解写锁

	n, ok := cache.nodes[node.Name]
	if !ok {
		// 如果节点不存在于缓存中，则创建新的节点信息并添加到缓存中
		n = newNodeInfoListItem(framework.NewNodeInfo())
		cache.nodes[node.Name] = n
	} else {
		// 如果节点已经存在于缓存中，则移除其关联的镜像状态
		cache.removeNodeImageStates(n.info.Node())
	}
	cache.moveNodeInfoToHead(node.Name) // 将节点信息移动到链表头部，以更新最近使用的节点信息

	cache.nodeTree.addNode(node) // 将节点添加到节点树中
	cache.addNodeImageStates(node, n.info) // 添加节点关联的镜像状态
	n.info.SetNode(node) // 更新节点信息
	return n.info.Clone() // 返回节点信息的克隆副本
}

func (cache *cacheImpl) UpdateNode(oldNode, newNode *v1.Node) *framework.NodeInfo {
	// 更新缓存中的节点信息

	cache.mu.Lock() // 加写锁
	defer cache.mu.Unlock() // 解写锁

	n, ok := cache.nodes[newNode.Name]
	if !ok {
		// 如果新节点信息不存在于缓存中，则创建新的节点信息并添加到缓存中
		n = newNodeInfoListItem(framework.NewNodeInfo())
		cache.nodes[newNode.Name] = n
		cache.nodeTree.addNode(newNode) // 将新节点添加到节点树中
	} else {
			// 如果新节点信息已经存在于缓存中，则移除其关联的镜像状态
		cache.removeNodeImageStates(n.info.Node())
	}
	cache.moveNodeInfoToHead(newNode.Name) // 将节点信息移动到链表头部，以更新最近使用的节点信息

	cache.nodeTree.updateNode(oldNode, newNode) // 更新节点树中的节点信息
	cache.addNodeImageStates(newNode, n.info) // 添加节点关联的镜像状态
	n.info.SetNode(newNode) // 更新节点信息
	return n.info.Clone() // 返回节点信息的克隆副本
}

func (cache *cacheImpl) RemoveNode(node *v1.Node) error {
	// 从缓存中移除节点信息

	cache.mu.Lock() // 加写锁
	defer cache.mu.Unlock() // 解写锁

	n, ok := cache.nodes[node.Name]
	if !ok {
		// 如果节点不存在于缓存中，则返回错误
		return fmt.Errorf("node %v is not found", node.Name)
	}
	n.info.RemoveNode() // 从节点信息中移除节点

	// 只有当节点上没有任何Pod时，才从链表中移除节点信息
	// 因为Pod的通知可能在不同的watch中被发送，因此可能会在节点移除之后被观察到
	if len(n.info.Pods) == 0 {
		cache.removeNodeInfoFromList(node.Name)
	} else {
		cache.moveNodeInfoToHead(node.Name) // 否则，将节点信息移动到链表头部，以更新最近使用的节点信息
	}

	if err := cache.nodeTree.removeNode(node); err != nil {
		// 从节点树中移除节点信息
		return err
	}

	cache.removeNodeImageStates(node) // 移除节点关联的镜像状态
	return nil // 返回空错误表示成功移除节点信息
}

// UpdateSnapshot函数对缓存的NodeInfo map进行快照。该函数在每个调度周期的开始时调用。
// 快照仅包括此函数调用时未删除的节点。
// 对于快照中的所有节点，nodeInfo.Node()都保证不为nil。
// 此函数跟踪NodeInfo的生成编号，并仅更新快照中已更改的现有条目。
func (cache *cacheImpl) UpdateSnapshot(nodeSnapshot *Snapshot) error {
    cache.mu.Lock() // 加锁，保证并发安全
    defer cache.mu.Unlock() // 函数执行完毕后解锁
    // 获取快照的最后一个生成编号
    snapshotGeneration := nodeSnapshot.generation

    // 如果从缓存中添加或删除节点，则必须重新创建NodeInfoList和HavePodsWithAffinityNodeInfoList
    updateAllLists := false
    // 如果节点从具有具有亲和性的Pod转换为没有具有亲和性的Pod，或者反之，则必须重新创建HavePodsWithAffinityNodeInfoList
    updateNodesHavePodsWithAffinity := false
    // 如果节点从具有所需反亲和性的Pod转换为没有具有所需反亲和性的Pod，或者反之，则必须重新创建HavePodsWithRequiredAntiAffinityNodeInfoList
    updateNodesHavePodsWithRequiredAntiAffinity := false
    // 如果头节点的生成编号大于最后快照的生成编号，则必须重新创建usedPVCSet
    updateUsedPVCSet := false

    // 从NodeInfo双向链表的头部开始，并更新在上一次快照之后更新的NodeInfos的快照
    for node := cache.headNode; node != nil; node = node.next {
        if node.info.Generation <= snapshotGeneration {
            // 所有节点都在现有快照之前更新，我们完成了。
            break
        }
        if np := node.info.Node(); np != nil {
            // 检查node是否存在于快照的nodeInfoMap中
            existing, ok := nodeSnapshot.nodeInfoMap[np.Name]
            if !ok {
                updateAllLists = true
                existing = &framework.NodeInfo{}
                nodeSnapshot.nodeInfoMap[np.Name] = existing
            }
            // 克隆NodeInfo以进行比较
            clone := node.info.Clone()
            // 我们跟踪具有Pod亲和性的节点，在此处检查该节点是否从具有Pod亲和性到不具有Pod亲和性或反之
            if (len(existing.PodsWithAffinity) > 0) != (len(clone.PodsWithAffinity) > 0) {
                updateNodesHavePodsWithAffinity = true
            }
            // 我们跟踪具有所需反亲和性Pod的节点，在此处检查该节点是否从具有所需反亲和性Pod到不具有所需反亲和性Pod或反之
            if (len(existing.PodsWithRequiredAntiAffinity) > 0) != (len(clone.PodsWithRequiredAntiAffinity) > 0) {
                updateNodesHavePodsWithRequiredAntiAffinity = true
            }
            // 如果usedPVCSet没有更新，则检查
			if !updateUsedPVCSet {
                // 如果updateUsedPVCSet为false
                if len(existing.PVCRefCounts) != len(clone.PVCRefCounts) {
                    // 如果existing.PVCRefCounts的长度不等于clone.PVCRefCounts的长度
                    updateUsedPVCSet = true
                    // 将updateUsedPVCSet设置为true
                } else {
                    // 否则
                    for pvcKey := range clone.PVCRefCounts {
                        // 遍历clone.PVCRefCounts中的所有键值
                        if _, found := existing.PVCRefCounts[pvcKey]; !found {
                            // 如果在existing.PVCRefCounts中没有找到当前键值
                            updateUsedPVCSet = true
                            // 将updateUsedPVCSet设置为true
                            break
                            // 跳出循环
                        }
                    }
                }
            }
            // 我们需要保留NodeInfo结构体的原始指针，因为它在NodeInfoList中使用，我们可能不会更新它。
            *existing = *clone
            // 将clone的值赋值给existing，这样可以保留NodeInfo结构体的原始指针
        }
    }
    if cache.headNode != nil {
        // 如果cache.headNode不为空
        nodeSnapshot.generation = cache.headNode.info.Generation
        // 将cache.headNode.info.Generation的值赋值给nodeSnapshot.generation
	}	
    if len(nodeSnapshot.nodeInfoMap) > cache.nodeTree.numNodes {
        // 如果nodeSnapshot.nodeInfoMap的长度大于cache.nodeTree.numNodes
        cache.removeDeletedNodesFromSnapshot(nodeSnapshot)
        // 从nodeSnapshot中移除已删除的节点
        updateAllLists = true
        // 将updateAllLists设置为true
	}
	if updateAllLists || updateNodesHavePodsWithAffinity || updateNodesHavePodsWithRequiredAntiAffinity || updateUsedPVCSet {
        // 如果updateAllLists为true，或者updateNodesHavePodsWithAffinity为true，或者updateNodesHavePodsWithRequiredAntiAffinity为true，或者updateUsedPVCSet为true
        cache.updateNodeInfoSnapshotList(nodeSnapshot, updateAllLists)
        // 更新nodeSnapshot的NodeInfo列表
    }
	if len(nodeSnapshot.nodeInfoList) != cache.nodeTree.numNodes {
        // 如果nodeSnapshot.nodeInfoList的长度不等于cache.nodeTree.numNodes
        errMsg := fmt.Sprintf("snapshot state is not consistent, length of NodeInfoList=%v not equal to length of nodes in tree=%v "+
            ", length of NodeInfoMap=%v, length of nodes in cache=%v"+
            ", trying to recover",
            len(nodeSnapshot.nodeInfoList), cache.nodeTree.numNodes,
            len(nodeSnapshot.nodeInfoMap), len(cache.nodes))
        // 创建错误消息
        klog.ErrorS(nil, errMsg)
        // 记录错误日志
        cache.updateNodeInfoSnapshotList(nodeSnapshot, true)
        // 更新nodeSnapshot的NodeInfo列表
        return fmt.Errorf(errMsg)
        // 返回错误消息作为错误
    }
	return nil
}

func (cache *cacheImpl) Dump() *Dump {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	nodes := make(map[string]*framework.NodeInfo, len(cache.nodes))
	for k, v := range cache.nodes {
		nodes[k] = v.info.Clone()
	}

	return &Dump{
		Nodes:       nodes,
		AssumedPods: cache.assumedPods.Union(nil),
	}
}
```

### addPod

```GO
func (cache *cacheImpl) addPod(pod *v1.Pod, assumePod bool) error {
	// 获取 pod 的 key
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	// 获取 pod 所在节点的节点信息（nodeInfoListItem）
	n, ok := cache.nodes[pod.Spec.NodeName]
	if !ok {
		// 如果该节点的信息不存在，则创建新的节点信息
		n = newNodeInfoListItem(framework.NewNodeInfo())
		// 将节点信息加入 cache 中
		cache.nodes[pod.Spec.NodeName] = n
	}
	// 将 pod 加入节点信息中
	n.info.AddPod(pod)

	// 将该节点信息移到链表头部，表示最近使用
	cache.moveNodeInfoToHead(pod.Spec.NodeName)

	// 记录 pod 的状态
	ps := &podState{
		pod: pod,
	}
	cache.podStates[key] = ps

	// 如果需要假设 pod 存在，则将其加入假设的 pod 集合中
	if assumePod {
		cache.assumedPods.Insert(key)
	}

	// 返回错误
	return nil
}
```

### moveNodeInfoToHead

```GO
func (cache *cacheImpl) moveNodeInfoToHead(name string) {
	// 根据节点名称获取节点信息
	ni, ok := cache.nodes[name]
	if !ok {
		// 如果节点信息不存在，记录错误日志并返回
		klog.ErrorS(nil, "No node info with given name found in the cache", "node", klog.KRef("", name))
		return
	}
	// 如果节点信息已经在链表头部，无需移动，直接返回
	if ni == cache.headNode {
		return
	}

	// 将节点信息从原位置断开
	if ni.prev != nil {
		ni.prev.next = ni.next
	}
	if ni.next != nil {
		ni.next.prev = ni.prev
	}

	// 将节点信息插入到链表头部
	if cache.headNode != nil {
		cache.headNode.prev = ni
	}
	ni.next = cache.headNode
	ni.prev = nil
	cache.headNode = ni
}
```

### removePod

```GO
func (cache *cacheImpl) removePod(pod *v1.Pod) error {
	// 获取 Pod 的键值
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	// 获取与 Pod 关联的节点信息
	n, ok := cache.nodes[pod.Spec.NodeName]
	if !ok {
		// 如果节点信息不存在，记录错误日志并返回
		klog.ErrorS(nil, "Node not found when trying to remove pod", "node", klog.KRef("", pod.Spec.NodeName), "podKey", key, "pod", klog.KObj(pod))
	} else {
		// 从节点信息中移除 Pod
		if err := n.info.RemovePod(pod); err != nil {
			return err
		}
		// 如果节点信息中没有其他 Pod 并且节点信息中没有节点数据，则从链表中移除该节点信息
		if len(n.info.Pods) == 0 && n.info.Node() == nil {
			cache.removeNodeInfoFromList(pod.Spec.NodeName)
		} else {
			// 否则，将节点信息移动到链表头部
			cache.moveNodeInfoToHead(pod.Spec.NodeName)
		}
	}

	// 从缓存中删除 Pod 的状态和假定 Pod 的标记
	delete(cache.podStates, key)
	delete(cache.assumedPods, key)
	return nil
}
```

### removeNodeInfoFromList

```GO
func (cache *cacheImpl) removeNodeInfoFromList(name string) {
	// 根据节点名称获取节点信息
	ni, ok := cache.nodes[name]
	if !ok {
		// 如果节点信息不存在，记录错误日志并返回
		klog.ErrorS(nil, "No node info with given name found in the cache", "node", klog.KRef("", name))
		return
	}

	// 更新链表中的前后节点的指针，将节点信息从链表中移除
	if ni.prev != nil {
		ni.prev.next = ni.next
	}
	if ni.next != nil {
		ni.next.prev = ni.prev
	}

	// 如果被移除的节点信息是链表头部节点，需要更新头部节点
	if ni == cache.headNode {
		cache.headNode = ni.next
	}

	// 从缓存中删除节点信息
	delete(cache.nodes, name)
}
```

### finishBinding

```GO
func (cache *cacheImpl) finishBinding(pod *v1.Pod, now time.Time) error {
	// 根据传入的 Pod 对象获取 Pod 的键值（key）
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	// 对 cache 进行读锁，确保并发安全
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	// 输出日志，记录完成 Pod 绑定操作，可以过期的 Pod
	klog.V(5).InfoS("Finished binding for pod, can be expired", "podKey", key, "pod", klog.KObj(pod))

	// 从缓存中获取当前 Pod 的状态
	currState, ok := cache.podStates[key]

	// 若当前 Pod 的状态存在，并且当前 Pod 被标记为假设的（assumedPods）
	if ok && cache.assumedPods.Has(key) {
		// 若缓存的 TTL 时间为 0，则将 Pod 状态中的 deadline 设置为 nil
		if cache.ttl == time.Duration(0) {
			currState.deadline = nil
		} else {
			// 否则，根据当前时间和缓存的 TTL 计算新的 deadline，并更新 Pod 状态中的 deadline
			dl := now.Add(cache.ttl)
			currState.deadline = &dl
		}
		// 将 Pod 状态中的 bindingFinished 标志设置为 true，表示完成了 Pod 绑定
		currState.bindingFinished = true
	}
	return nil
}
```

### updatePod

```GO
func (cache *cacheImpl) updatePod(oldPod, newPod *v1.Pod) error {
	if err := cache.removePod(oldPod); err != nil {
		return err
	}
	return cache.addPod(newPod, false)
}
```

### removeNodeImageStates

```GO
func (cache *cacheImpl) removeNodeImageStates(node *v1.Node) {
	// 如果节点为空，直接返回
	if node == nil {
		return
	}

	// 遍历节点的所有镜像
	for _, image := range node.Status.Images {
		for _, name := range image.Names {
			// 根据镜像名称获取状态
			state, ok := cache.imageStates[name]
			if ok {
				// 从状态中删除当前节点的信息
				state.nodes.Delete(node.Name)
				// 如果状态中不再有节点使用该镜像，则从缓存中删除该镜像的状态
				if len(state.nodes) == 0 {
					// 删除不再使用的镜像状态，以便imageStates的长度表示所有节点上不同镜像的总数
					delete(cache.imageStates, name)
				}
			}
		}
	}
}
```

### addNodeImageStates

```GO
func (cache *cacheImpl) addNodeImageStates(node *v1.Node, nodeInfo *framework.NodeInfo) {
	// 创建一个新的镜像状态总结表
	newSum := make(map[string]*framework.ImageStateSummary)

	// 遍历节点的所有镜像
	for _, image := range node.Status.Images {
		for _, name := range image.Names {
			// 更新imageStates中的镜像状态条目
			state, ok := cache.imageStates[name]
			if !ok {
				// 如果imageStates中不存在该镜像的状态，则创建一个新的状态
				state = &imageState{
					size:  image.SizeBytes,
					nodes: sets.New(node.Name),
				}
				cache.imageStates[name] = state
			} else {
				// 如果imageStates中已存在该镜像的状态，则将当前节点添加到状态的节点集合中
				state.nodes.Insert(node.Name)
			}
			// 创建镜像状态总结表中该镜像的条目
			if _, ok := newSum[name]; !ok {
				// 如果新的镜像状态总结表中不存在该镜像的条目，则创建一个新的条目
				newSum[name] = cache.createImageStateSummary(state)
			}
		}
	}
	// 将新的镜像状态总结表设置为节点信息的镜像状态
	nodeInfo.ImageStates = newSum
}
```

### createImageStateSummary

```GO
func (cache *cacheImpl) createImageStateSummary(state *imageState) *framework.ImageStateSummary {
	return &framework.ImageStateSummary{
		Size:     state.size,
		NumNodes: len(state.nodes),
	}
}
```

## run

```GO
func (cache *cacheImpl) run() {
	go wait.Until(cache.cleanupExpiredAssumedPods, cache.period, cache.stop)
}

func (cache *cacheImpl) cleanupExpiredAssumedPods() {
	cache.cleanupAssumedPods(time.Now())
}

func (cache *cacheImpl) cleanupAssumedPods(now time.Time) {
	// 获取缓存的互斥锁
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// 更新指标
	defer cache.updateMetrics()

	// 遍历所有假定的Pod
	for key := range cache.assumedPods {
		// 从podStates中获取Pod状态
		ps, ok := cache.podStates[key]
		if !ok {
			// 如果在假定的Pod集合中找到了对应的key，但在podStates中找不到对应的状态，可能存在逻辑错误
			klog.ErrorS(nil, "Key found in assumed set but not in podStates, potentially a logical error")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
		if !ps.bindingFinished {
			// 如果Pod的绑定过程仍在进行中，无法过期缓存，记录日志并继续下一个Pod
			klog.V(5).InfoS("Could not expire cache for pod as binding is still in progress", "podKey", key, "pod", klog.KObj(ps.pod))
			continue
		}
		if cache.ttl != 0 && now.After(*ps.deadline) {
			// 如果设置了过期时间，并且当前时间晚于Pod的过期时间，将Pod标记为过期并移除缓存
			klog.InfoS("Pod expired", "podKey", key, "pod", klog.KObj(ps.pod))
			if err := cache.removePod(ps.pod); err != nil {
				klog.ErrorS(err, "ExpirePod failed", "podKey", key, "pod", klog.KObj(ps.pod))
			}
		}
	}
}
```

## nodeTree

```GO
// nodeTree 是一种树状的数据结构，用于在每个区域（zone）中保存节点（node）的名称。
// 区域名称作为 "NodeTree.tree" 的键，"NodeTree.tree" 的值是该区域中节点名称的数组。
// NodeTree 不是线程安全的，任何并发的更新/读取操作都必须由调用方进行同步。
// 它只被 schedulerCache 使用，应该保持这种方式。
type nodeTree struct {
	tree     map[string][]string // 从区域 (region-zone) 到该区域中节点名称的数组的映射
	zones    []string            // 树中所有区域的列表（键）
	numNodes int                 // 节点的数量
}

func newNodeTree(nodes []*v1.Node) *nodeTree {
	nt := &nodeTree{
		tree: make(map[string][]string, len(nodes)),
	}
	for _, n := range nodes {
		nt.addNode(n)
	}
	return nt
}
```

### 方法

```go
// addNode 向树中添加一个节点及其对应的区域。如果区域已经存在，则将节点添加到该区域的节点数组中。
func (nt *nodeTree) addNode(n *v1.Node) {
	zone := utilnode.GetZoneKey(n) // 获取节点所属的区域
	if na, ok := nt.tree[zone]; ok { // 判断区域是否已存在
		for _, nodeName := range na { // 在区域的节点数组中查找是否已存在相同名称的节点
			if nodeName == n.Name {
				klog.InfoS("Node already exists in the NodeTree", "node", klog.KObj(n))
				return
			}
		}
		nt.tree[zone] = append(na, n.Name) // 将节点名称添加到区域的节点数组中
	} else {
		nt.zones = append(nt.zones, zone) // 如果区域不存在，则将区域名称添加到树的区域列表中
		nt.tree[zone] = []string{n.Name} // 并创建一个新的节点数组，并将节点名称添加到其中
	}
	klog.V(2).InfoS("Added node in listed group to NodeTree", "node", klog.KObj(n), "zone", zone)
	nt.numNodes++ // 节点数量加一
}

// removeNode 从 NodeTree 中移除一个节点。
func (nt *nodeTree) removeNode(n *v1.Node) error {
	zone := utilnode.GetZoneKey(n) // 获取节点所属的区域
	if na, ok := nt.tree[zone]; ok { // 判断区域是否存在
		for i, nodeName := range na { // 在区域的节点数组中查找节点名称
			if nodeName == n.Name { // 如果找到节点，则从节点数组中移除该节点
				nt.tree[zone] = append(na[:i], na[i+1:]...)
				if len(nt.tree[zone]) == 0 { // 如果节点数组为空，则从树中移除该区域
					nt.removeZone(zone)
				}
				klog.V(2).InfoS("Removed node in listed group from NodeTree", "node", klog.KObj(n), "zone", zone)
				nt.numNodes-- // 节点数量减一
				return nil
			}
		}
	}
	klog.ErrorS(nil, "Node in listed group was not found", "node", klog.KObj(n), "zone", zone)
	return fmt.Errorf("node %q in group %q was not found", n.Name, zone)
}

// removeZone函数用于从nodeTree中删除指定的zone。
// 这个函数在写入锁被保持的情况下调用。
func (nt *nodeTree) removeZone(zone string) {
    delete(nt.tree, zone) // 从nodeTree的映射中删除指定的zone。
    for i, z := range nt.zones { // 遍历nt.zones数组中的每一个元素。
        if z == zone { // 如果当前元素等于指定的zone。
            nt.zones = append(nt.zones[:i], nt.zones[i+1:]...) // 从nt.zones数组中删除当前元素。
            return // 返回。
        }
    }
}

// updateNode函数用于更新NodeTree中的一个节点。
func (nt *nodeTree) updateNode(old, new *v1.Node) {
    var oldZone string
    if old != nil { // 如果旧节点不为nil。
    	oldZone = utilnode.GetZoneKey(old) // 获取旧节点的区域键值。
    }
    newZone := utilnode.GetZoneKey(new) // 获取新节点的区域键值。
    // 如果节点的区域ID没有改变，我们不需要进行任何操作。节点的名称在更新中不能更改。
    if oldZone == newZone { // 如果旧节点和新节点的区域键值相等。
    	return // 返回。
    }
    nt.removeNode(old) // 从NodeTree中删除旧节点。我们忽略旧节点是否存在的错误检查。
    nt.addNode(new) // 向NodeTree中添加新节点。
}

// list函数返回节点的名称列表。NodeTree按照循环顺序在每个区域中遍历节点。
func (nt *nodeTree) list() ([]string, error) {
    if len(nt.zones) == 0 { // 如果nt.zones数组为空。
        return nil, nil // 返回nil。
    }
    nodesList := make([]string, 0, nt.numNodes) // 创建一个初始长度为0，容量为nt.numNodes的字符串切片。
    numExhaustedZones := 0 // 初始化已经遍历完的区域数为0。
    nodeIndex := 0 // 初始化节点索引为0。
    for len(nodesList) < nt.numNodes { // 如果nodesList的长度小于nt.numNodes。
        if numExhaustedZones >= len(nt.zones) { // 如果所有区域都被遍历过了。
            return nodesList, errors.New("all zones exhausted before reaching count of nodes expected") // 返回错误信息。
        }
        for zoneIndex := 0; zoneIndex < len(nt.zones); zoneIndex++ { // 遍历nt.zones数组中的每一个元素。
            na := nt.tree[nt.zones[zoneIndex]] // 获取当前区域的节点名称数组。
            if nodeIndex >= len(na) { // 如果当前节点索引已经超过当前区域节点名称数组的长度。
                if nodeIndex == len(na) { // 如果这是当前区域第一次被遍历完。
                    numExhaustedZones++ // 已经遍历完的区域数+1。
                }
                continue // 跳过当前循环，继续下一个循环。
            }
            nodesList = append(nodesList, na[nodeIndex]) // 将当前区域的节点名称数组中的第nodeIndex个元素添加到nodesList中。
        }
        nodeIndex++ // 节点索引+1。
    }
    return nodesList, nil // 返回节点名称列表和nil。
}
```

## Snapshot

```go
// Snapshot是缓存NodeInfo和NodeTree顺序的快照。调度器在每个调度周期的开始时拍摄一个快照，并在该周期内使用它进行操作。
type Snapshot struct {
    // nodeInfoMap是节点名称到其NodeInfo的快照的映射。
    nodeInfoMap map[string]*framework.NodeInfo
    // nodeInfoList是以缓存的nodeTree顺序排列的节点列表。
    nodeInfoList []*framework.NodeInfo
    // havePodsWithAffinityNodeInfoList是至少有一个声明亲和性项的Pod的节点列表。
    havePodsWithAffinityNodeInfoList []*framework.NodeInfo
    // havePodsWithRequiredAntiAffinityNodeInfoList是至少有一个声明必须反亲和项的Pod的节点列表。
    havePodsWithRequiredAntiAffinityNodeInfoList []*framework.NodeInfo
    // usedPVCSet包含一组使用它们的一个或多个已安排的Pod的PVC名称，以"namespace/name"的格式为键。
    usedPVCSet sets.Set[string]
    generation int64
}
```

### New

```go
func NewSnapshot(pods []*v1.Pod, nodes []*v1.Node) *Snapshot {
	nodeInfoMap := createNodeInfoMap(pods, nodes)
	nodeInfoList := make([]*framework.NodeInfo, 0, len(nodeInfoMap))
	havePodsWithAffinityNodeInfoList := make([]*framework.NodeInfo, 0, len(nodeInfoMap))
	havePodsWithRequiredAntiAffinityNodeInfoList := make([]*framework.NodeInfo, 0, len(nodeInfoMap))
	for _, v := range nodeInfoMap {
		nodeInfoList = append(nodeInfoList, v)
		if len(v.PodsWithAffinity) > 0 {
			havePodsWithAffinityNodeInfoList = append(havePodsWithAffinityNodeInfoList, v)
		}
		if len(v.PodsWithRequiredAntiAffinity) > 0 {
			havePodsWithRequiredAntiAffinityNodeInfoList = append(havePodsWithRequiredAntiAffinityNodeInfoList, v)
		}
	}

	s := NewEmptySnapshot()
	s.nodeInfoMap = nodeInfoMap
	s.nodeInfoList = nodeInfoList
	s.havePodsWithAffinityNodeInfoList = havePodsWithAffinityNodeInfoList
	s.havePodsWithRequiredAntiAffinityNodeInfoList = havePodsWithRequiredAntiAffinityNodeInfoList
	s.usedPVCSet = createUsedPVCSet(pods)

	return s
}

func NewEmptySnapshot() *Snapshot {
	return &Snapshot{
		nodeInfoMap: make(map[string]*framework.NodeInfo),
		usedPVCSet:  sets.New[string](),
	}
}
```

```GO
// 创建一个映射，将节点名称映射到该节点的信息结构体上
func createNodeInfoMap(pods []*v1.Pod, nodes []*v1.Node) map[string]*framework.NodeInfo {
    nodeNameToInfo := make(map[string]*framework.NodeInfo) // 用于存储节点名称和节点信息的映射，初始为空映射
    for _, pod := range pods { // 遍历每个 Pod
        nodeName := pod.Spec.NodeName // 获取 Pod 所在的节点名称
        if _, ok := nodeNameToInfo[nodeName]; !ok { // 如果 nodeNameToInfo 映射中没有该节点名称，则创建一个新的节点信息结构体
            nodeNameToInfo[nodeName] = framework.NewNodeInfo()
        }
        nodeNameToInfo[nodeName].AddPod(pod) // 将 Pod 添加到 nodeNameToInfo 映射中相应节点名称所对应的节点信息结构体中
    }
    imageExistenceMap := createImageExistenceMap(nodes) // 创建一个映射，将镜像名称映射到节点是否拥有该镜像上

    for _, node := range nodes { // 遍历每个节点
        if _, ok := nodeNameToInfo[node.Name]; !ok { // 如果 nodeNameToInfo 映射中没有该节点名称，则创建一个新的节点信息结构体
            nodeNameToInfo[node.Name] = framework.NewNodeInfo()
        }
        nodeInfo := nodeNameToInfo[node.Name] // 获取 nodeNameToInfo 映射中相应节点名称所对应的节点信息结构体
        nodeInfo.SetNode(node) // 设置节点信息结构体的 Node 属性为当前节点
        nodeInfo.ImageStates = getNodeImageStates(node, imageExistenceMap) // 获取节点所拥有的镜像，并将其添加到节点信息结构体中的 ImageStates 属性中
    }
    return nodeNameToInfo // 返回 nodeNameToInfo 映射，其中存储了所有节点名称和相应的节点信息结构体
}

// 创建一个字符串集合，用于存储所有已使用的 PVC 的名称
func createUsedPVCSet(pods []*v1.Pod) sets.Set[string] {
    usedPVCSet := sets.New[string]() // 创建一个空的字符串集合，用于存储已使用的 PVC 的名称
    for _, pod := range pods { // 遍历每个 Pod
        if pod.Spec.NodeName == "" { // 如果 Pod 没有被分配到节点上，则跳过此次循环
            continue
        }

        for _, v := range pod.Spec.Volumes { // 遍历 Pod 的每个 Volume
            if v.PersistentVolumeClaim == nil { // 如果 Volume 不是一个 PVC 类型的 Volume，则跳过此次循环
                continue
            }

            key := framework.GetNamespacedName(pod.Namespace, v.PersistentVolumeClaim.ClaimName) // 获取 PVC 的名称
            usedPVCSet.Insert(key) // 将 PVC 的名称添加到 usedPVCSet 集合中
        }
    }
    return usedPVCSet // 返回 usedPVCSet 集合，其中存储了所有已使用的 PVC 的名称
}

// 获取节点所拥有的镜像以及该镜像所存在的节点数量，并返回一个映射，将镜像名称映射到该镜像的 ImageStateSummary 结构体上
func getNodeImageStates(node *v1.Node, imageExistenceMap map[string]sets.Set[string]) map[string]*framework.ImageStateSummary {
    imageStates := make(map[string]*framework.ImageStateSummary) // 创建一个映射，用于存储镜像名称和该镜像所存在的节点数量

    for _, image := range node.Status.Images { // 遍历节点的每个镜像
        for _, name := range image.Names { // 遍历镜像的每个名称
            imageStates[name] = &framework.ImageStateSummary{ // 创建一个 ImageStateSummary 结构体，并将其添加到 imageStates 映射中
                Size:     image.SizeBytes, // 设置 ImageStateSummary 结构体的 Size 属性为镜像的大小
                NumNodes: len(imageExistenceMap[name]), // 获取该镜像所存在的节点数量，并设置 ImageStateSummary 结构体的 NumNodes 属性为该数量
            }
        }
    }
    return imageStates // 返回一个映射，将镜像名称映射到该镜像的 ImageStateSummary 结构体上
}
```

#### 方法

```GO
func (s *Snapshot) NodeInfos() framework.NodeInfoLister {
	return s
}

// StorageInfos returns a StorageInfoLister.
func (s *Snapshot) StorageInfos() framework.StorageInfoLister {
	return s
}

// NumNodes returns the number of nodes in the snapshot.
func (s *Snapshot) NumNodes() int {
	return len(s.nodeInfoList)
}

// List returns the list of nodes in the snapshot.
func (s *Snapshot) List() ([]*framework.NodeInfo, error) {
	return s.nodeInfoList, nil
}

func (s *Snapshot) HavePodsWithAffinityList() ([]*framework.NodeInfo, error) {
	return s.havePodsWithAffinityNodeInfoList, nil
}

// HavePodsWithRequiredAntiAffinityList returns the list of nodes with at least one pod with
// required inter-pod anti-affinity
func (s *Snapshot) HavePodsWithRequiredAntiAffinityList() ([]*framework.NodeInfo, error) {
	return s.havePodsWithRequiredAntiAffinityNodeInfoList, nil
}

// Get returns the NodeInfo of the given node name.
func (s *Snapshot) Get(nodeName string) (*framework.NodeInfo, error) {
	if v, ok := s.nodeInfoMap[nodeName]; ok && v.Node() != nil {
		return v, nil
	}
	return nil, fmt.Errorf("nodeinfo not found for node name %q", nodeName)
}

func (s *Snapshot) IsPVCUsedByPods(key string) bool {
	return s.usedPVCSet.Has(key)
}
```
