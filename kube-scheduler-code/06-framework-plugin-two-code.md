
## InterPodAffinity

### 作用

用于在调度Pod时根据Pod之间的关系和约束来决定它们所应该调度的节点。InterPodAffinity插件使用Pod的标签（labels）和选择器（selectors）来确定Pod之间的关系。它支持两种类型的关系：

1. Pod Affinity: 确定一个Pod应该被调度到与其他一组Pod在同一节点上。
2. Pod Anti-Affinity: 确定一个Pod不应该被调度到与其他一组Pod在同一节点上。

使用InterPodAffinity插件，可以实现以下场景：

1. 将具有相同服务或功能的Pod分配到同一节点上，以减少Pod之间的通信延迟。
2. 将具有相同或相似标签的Pod分配到同一节点上，以提高集群资源的利用率。
3. 将具有相反作用的Pod（例如，Web服务器和数据库）分配到不同的节点上，以提高可用性和可靠性。

### 结构

```go
// Name是在插件注册表和配置中使用的插件名称。
const Name = names.InterPodAffinity // 定义常量Name，值为names.InterPodAffinity

var _ framework.PreFilterPlugin = &InterPodAffinity{} // 将InterPodAffinity结构体指针赋值给_PreFilterPlugin接口变量，实现_PreFilterPlugin接口
var _ framework.FilterPlugin = &InterPodAffinity{} // 将InterPodAffinity结构体指针赋值给_FilterPlugin接口变量，实现_FilterPlugin接口
var _ framework.PreScorePlugin = &InterPodAffinity{} // 将InterPodAffinity结构体指针赋值给_PreScorePlugin接口变量，实现_PreScorePlugin接口
var _ framework.ScorePlugin = &InterPodAffinity{} // 将InterPodAffinity结构体指针赋值给_ScorePlugin接口变量，实现_ScorePlugin接口
var _ framework.EnqueueExtensions = &InterPodAffinity{} // 将InterPodAffinity结构体指针赋值给_EnqueueExtensions接口变量，实现_EnqueueExtensions接口

// InterPodAffinity是一个检查Pod之间亲和性的插件。
type InterPodAffinity struct { // 定义InterPodAffinity结构体
    parallelizer parallelize.Parallelizer // 并行器
    args config.InterPodAffinityArgs // InterPodAffinityArgs配置
    sharedLister framework.SharedLister // 共享列表
    nsLister listersv1.NamespaceLister // NamespaceLister接口
}

// Name返回插件名称，用于日志等。
func (pl *InterPodAffinity) Name() string { // 定义结构体方法Name，返回InterPodAffinity结构体的Name字段
	return Name // 返回常量Name的值
}

// New初始化新插件并返回它。
func New(plArgs runtime.Object, h framework.Handle) (framework.Plugin, error) { // 定义函数New，返回Plugin接口和错误类型
    if h.SnapshotSharedLister() == nil { // 判断SnapshotSharedLister是否为nil
    	return nil, fmt.Errorf("SnapshotSharedlister is nil") // 返回nil和错误信息
    }
    args, err := getArgs(plArgs) // 获取插件参数
    if err != nil { // 如果发生错误
    	return nil, err // 返回nil和错误信息
    }
    if err := validation.ValidateInterPodAffinityArgs(nil, &args); err != nil { // 验证InterPodAffinityArgs配置是否正确
    	return nil, err // 返回nil和错误信息
    }
    pl := &InterPodAffinity{ // 创建InterPodAffinity结构体
        parallelizer: h.Parallelizer(), // 并行器
        args: args, // InterPodAffinityArgs配置
        sharedLister: h.SnapshotSharedLister(), // 共享列表
        nsLister: h.SharedInformerFactory().Core().V1().Namespaces().Lister(), // NamespaceLister接口
    }

    return pl, nil // 返回InterPodAffinity结构体指针和nil
}
```

#### getArgs

```go
func getArgs(obj runtime.Object) (config.InterPodAffinityArgs, error) {
	ptr, ok := obj.(*config.InterPodAffinityArgs)
	if !ok {
		return config.InterPodAffinityArgs{}, fmt.Errorf("want args to be of type InterPodAffinityArgs, got %T", obj)
	}
	return *ptr, nil
}
```

### PreFilter&PreFilterExtensions

```go
// PreFilter是在prefilter扩展点上调用的函数。
func (pl *InterPodAffinity) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 获取所有节点信息以及拥有必须反亲和性Pod的节点信息
	var allNodes []*framework.NodeInfo
	var nodesWithRequiredAntiAffinityPods []*framework.NodeInfo
	var err error
	if allNodes, err = pl.sharedLister.NodeInfos().List(); err != nil {
		return nil, framework.AsStatus(fmt.Errorf("failed to list NodeInfos: %w", err))
	}
	if nodesWithRequiredAntiAffinityPods, err = pl.sharedLister.NodeInfos().HavePodsWithRequiredAntiAffinityList(); err != nil {
		return nil, framework.AsStatus(fmt.Errorf("failed to list NodeInfos with pods with affinity: %w", err))
	}

	// 构建预筛选状态
	s := &preFilterState{}

	// 解析Pod信息
	if s.podInfo, err = framework.NewPodInfo(pod); err != nil {
		return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("parsing pod: %+v", err))
	}

	// 合并Pod所需的亲和性和反亲和性Term的namespace，如果不为空
	for i := range s.podInfo.RequiredAffinityTerms {
		if err := pl.mergeAffinityTermNamespacesIfNotEmpty(&s.podInfo.RequiredAffinityTerms[i]); err != nil {
			return nil, framework.AsStatus(err)
		}
	}
	for i := range s.podInfo.RequiredAntiAffinityTerms {
		if err := pl.mergeAffinityTermNamespacesIfNotEmpty(&s.podInfo.RequiredAntiAffinityTerms[i]); err != nil {
			return nil, framework.AsStatus(err)
		}
	}
	
	// 获取Pod所属Namespace的标签
	s.namespaceLabels = GetNamespaceLabelsSnapshot(pod.Namespace, pl.nsLister)

	// 获取已经存在的反亲和性Pod的数量，并计算Pod所需的亲和性和反亲和性Term的数量
	s.existingAntiAffinityCounts = pl.getExistingAntiAffinityCounts(ctx, pod, s.namespaceLabels, nodesWithRequiredAntiAffinityPods)
	s.affinityCounts, s.antiAffinityCounts = pl.getIncomingAffinityAntiAffinityCounts(ctx, s.podInfo, allNodes)

	// 如果Pod不需要亲和性和反亲和性Term，并且不存在反亲和性Pod，则直接跳过该Pod
	if len(s.existingAntiAffinityCounts) == 0 && len(s.podInfo.RequiredAffinityTerms) == 0 && len(s.podInfo.RequiredAntiAffinityTerms) == 0 {
		return nil, framework.NewStatus(framework.Skip)
	}

	// 将预筛选状态写入CycleState
	cycleState.Write(preFilterStateKey, s)
	return nil, nil
}

// PreFilterExtensions返回预筛选扩展，即Pod添加和移除。
func (pl *InterPodAffinity) PreFilterExtensions() framework.PreFilterExtensions {
	return pl
}
```

#### preFilterState

```GO
const preFilterStateKey = "PreFilter" + Name // 定义常量 preFilterStateKey，其值为 "PreFilter" + Name

// preFilterState 在 PreFilter 阶段计算，在 Filter 阶段使用。
// 定义结构体 preFilterState，包含以下字段：
type preFilterState struct {
    // 存储匹配 "pod" 的反亲和性术语的拓扑对到现有 Pod 数量的映射。
    existingAntiAffinityCounts topologyToMatchedTermCount
    // 存储匹配 "pod" 亲和性术语的拓扑对到现有 Pod 数量的映射。
    affinityCounts topologyToMatchedTermCount
    // 存储匹配 "pod" 的反亲和性术语的拓扑对到现有 Pod 数量的映射。
    antiAffinityCounts topologyToMatchedTermCount
    // 入站 Pod 的 podInfo。
    podInfo *framework.PodInfo
    // 入站 Pod 的 namespace labels 的一个副本。
    namespaceLabels labels.Set
}

// Clone the prefilter state.
// 克隆 preFilterState 结构体。
func (s *preFilterState) Clone() framework.StateData {
    if s == nil {
    	return nil
    }
    copy := preFilterState{}
    // 克隆 preFilterState 结构体的字段。
    copy.affinityCounts = s.affinityCounts.clone()
    copy.antiAffinityCounts = s.antiAffinityCounts.clone()
    copy.existingAntiAffinityCounts = s.existingAntiAffinityCounts.clone()
    // No need to deep copy the podInfo because it shouldn't change.
    copy.podInfo = s.podInfo
    copy.namespaceLabels = s.namespaceLabels
    return &copy
}

// updateWithPod updates the preFilterState counters with the (anti)affinity matches for the given podInfo.
// 使用给定的 podInfo 更新 preFilterState 的计数器 (anti)affinity 匹配。
func (s *preFilterState) updateWithPod(pInfo *framework.PodInfo, node *v1.Node, multiplier int64) {
    if s == nil {
    	return
    }
    s.existingAntiAffinityCounts.updateWithAntiAffinityTerms(pInfo.RequiredAntiAffinityTerms, s.podInfo.Pod, s.namespaceLabels, node, multiplier)
    // 更新 affinityCounts 计数器。
    s.affinityCounts.updateWithAffinityTerms(s.podInfo.RequiredAffinityTerms, pInfo.Pod, node, multiplier)
    // 入站 Pod 的 terms 将 namespaceSelector 合并到 namespaces 中，因此此处不查找更新后的 Pod 的 namespace labels，因此将 nsLabels 传递为 nil。
    s.antiAffinityCounts.updateWithAntiAffinityTerms(s.podInfo.RequiredAntiAffinityTerms, pInfo.Pod, nil, node, multiplier)
}
```

#### topologyToMatchedTermCount

```go
// 定义一个包含两个字段 key 和 value 的结构体 topologyPair
type topologyPair struct {
	key   string
	value string
}

// 定义一个映射 topologyPair 到 int64 类型的映射表 topologyToMatchedTermCount
type topologyToMatchedTermCount map[topologyPair]int64

// 该方法会将 toAppend 映射表中的每个 topologyPair 的值累加到 m 映射表中对应 topologyPair 的值上
func (m topologyToMatchedTermCount) append(toAppend topologyToMatchedTermCount) {
	// 遍历 toAppend 映射表中所有的 topologyPair
	for pair := range toAppend {
		// 累加到 m 映射表中对应 topologyPair 的值上
		m[pair] += toAppend[pair]
	}
}

// 该方法会将调用者 topologyToMatchedTermCount 克隆一份并返回
func (m topologyToMatchedTermCount) clone() topologyToMatchedTermCount {
	// 复制一份 m 映射表，长度为 m 映射表的长度
	copy := make(topologyToMatchedTermCount, len(m))
	// 将调用者映射表的值累加到复制出的映射表中
	copy.append(m)
	// 返回复制出的映射表
	return copy
}

// 该方法会根据给定的节点 node、关键词 tk 和值 value 来更新调用者 topologyToMatchedTermCount 映射表的值
func (m topologyToMatchedTermCount) update(node *v1.Node, tk string, value int64) {
	// 如果节点的标签中存在对应关键词 tk 的标签
	if tv, ok := node.Labels[tk]; ok {
		// 创建一个 topologyPair 对象
		pair := topologyPair{key: tk, value: tv}
		// 将给定值 value 累加到 topologyPair 在映射表 m 中的值上
		m[pair] += value
		// 如果经过累加后 topologyPair 对应的值为 0，那么就从映射表 m 中删除该 topologyPair
		if m[pair] == 0 {
			delete(m, pair)
		}
	}
}

// 如果 targetPod 匹配所有的 terms 中的所有项，该方法会根据指定的值 value 来更新调用者 topologyToMatchedTermCount 映射表的值
func (m topologyToMatchedTermCount) updateWithAffinityTerms(
	terms []framework.AffinityTerm, pod *v1.Pod, node *v1.Node, value int64) {
	// 如果 targetPod 匹配所有的 terms 中的所有项
	if podMatchesAllAffinityTerms(terms, pod) {
		// 遍历所有的 terms
		for _, t := range terms {
			// 根据节点、关键词和给定值来更新 topologyToMatchedTermCount 映射表中的值
			m.update(node, t.TopologyKey, value)
		}
	}
}

// updates the topologyToMatchedTermCount map with the specified value
// for each anti-affinity term matched the target pod.
// 使用指定的值更新topologyToMatchedTermCount映射表，
// 对于每个与目标Pod匹配的反亲和性项。
func (m topologyToMatchedTermCount) updateWithAntiAffinityTerms(terms []framework.AffinityTerm, pod *v1.Pod, nsLabels labels.Set, node *v1.Node, value int64) {
    // Check anti-affinity terms.
    // 检查反亲和性项。
    for _, t := range terms {
        if t.Matches(pod, nsLabels) {
        	m.update(node, t.TopologyKey, value)
        }
    }
}
```

#### mergeAffinityTermNamespacesIfNotEmpty

```go
// 如果成功，将NamespaceSelector设置为nil，并将命名空间集合更新为NamespaceSelector选择的命名空间。
// 假设这个term是针对一个incoming pod，那么NamespaceSelector将被展开到Namespaces中（因此selector设置为Nothing()），
// 或者是Empty()，表示匹配所有命名空间。因此，在与这个term进行匹配时，没有必要显式地查找现有的pod的命名空间标签并将其与term的NamespaceSelector进行匹配。
func (pl *InterPodAffinity) mergeAffinityTermNamespacesIfNotEmpty(at *framework.AffinityTerm) error {
    if at.NamespaceSelector.Empty() { // 如果NamespaceSelector为空，则无需更新命名空间
    	return nil
    }
    ns, err := pl.nsLister.List(at.NamespaceSelector) // 获取NamespaceSelector选择的命名空间集合
    if err != nil {
   		return err
    }
    for _, n := range ns {
    	at.Namespaces.Insert(n.Name) // 更新AffinityTerm的Namespaces集合
    }
    at.NamespaceSelector = labels.Nothing() // 将NamespaceSelector设置为空
    return nil
}
```

#### GetNamespaceLabelsSnapshot

```go
// GetNamespaceLabelsSnapshot返回与命名空间相关联的标签的快照。
func GetNamespaceLabelsSnapshot(ns string, nsLister listersv1.NamespaceLister) (nsLabels labels.Set) {
    podNS, err := nsLister.Get(ns)
    if err == nil {
    	// 创建并返回标签的快照。
    	return labels.Merge(podNS.Labels, nil)
    }
    klog.V(3).InfoS("getting namespace, assuming empty set of namespace labels", "namespace", ns, "err", err)
    return // 如果获取Namespace失败，则返回一个空标签集合
}
```

#### getExistingAntiAffinityCounts

```go
// 为每个节点上的每个现有 Pod 计算以下内容：
// 1. 它是否具有 PodAntiAffinity
// 2. 任何 AntiAffinityTerm 是否与传入的 Pod 匹配
func (pl *InterPodAffinity) getExistingAntiAffinityCounts(ctx context.Context, pod *v1.Pod, nsLabels labels.Set, nodes []*framework.NodeInfo) topologyToMatchedTermCount {
    // 创建一个长度为 nodes 数组长度的 topoMaps 数组
    topoMaps := make([]topologyToMatchedTermCount, len(nodes))
    index := int32(-1) // 初始化 index 为 -1
    processNode := func(i int) { // 定义 processNode 函数，用于遍历 nodes 中的每个节点信息
        nodeInfo := nodes[i]
        node := nodeInfo.Node() // 获取节点对象
            if node == nil {
                klog.ErrorS(nil, "Node not found") // 若获取不到节点，输出错误日志
                return
            }
        topoMap := make(topologyToMatchedTermCount) // 创建一个 topologyToMatchedTermCount 对象 topoMap
        // 遍历 nodeInfo.PodsWithRequiredAntiAffinity 列表，为每个现有 Pod 更新 topoMap
        for _, existingPod := range nodeInfo.PodsWithRequiredAntiAffinity {
            topoMap.updateWithAntiAffinityTerms(existingPod.RequiredAntiAffinityTerms, pod, nsLabels, node, 1)
        }
        if len(topoMap) != 0 { // 如果 topoMap 不为空，则将其放入 topoMaps 数组中
            topoMaps[atomic.AddInt32(&index, 1)] = topoMap
        }
    }
    // 使用并发执行器 parallelizer 并行执行 processNode 函数，遍历 nodes 列表
    pl.parallelizer.Until(ctx, len(nodes), processNode, pl.Name())

    result := make(topologyToMatchedTermCount) // 创建一个 topologyToMatchedTermCount 对象 result
    // 遍历 topoMaps 数组中前 index+1 个非空 topoMap，将它们合并到 result 中
    for i := 0; i <= int(index); i++ {
        result.append(topoMaps[i])
    }

    return result // 返回 result 对象
}
```

#### getIncomingAffinityAntiAffinityCounts

```go
// 找到与传入 Pod 的 (anti)affinity terms 匹配的现有 Pods。
// 它返回一个 topologyToMatchedTermCount，稍后由亲和性谓词检查。
// 有了这个 topologyToMatchedTermCount，亲和性谓词就不需要检查集群中的所有 Pods。
func (pl *InterPodAffinity) getIncomingAffinityAntiAffinityCounts(ctx context.Context, podInfo *framework.PodInfo, allNodes []*framework.NodeInfo) (topologyToMatchedTermCount, topologyToMatchedTermCount) {
    // 初始化两个 topologyToMatchedTermCount
    affinityCounts := make(topologyToMatchedTermCount)
    antiAffinityCounts := make(topologyToMatchedTermCount)
    // 如果传入 Pod 没有指定亲和性或反亲和性，直接返回两个空的 topologyToMatchedTermCount
    if len(podInfo.RequiredAffinityTerms) == 0 && len(podInfo.RequiredAntiAffinityTerms) == 0 {
        return affinityCounts, antiAffinityCounts
    }
    // 初始化两个存放 topologyToMatchedTermCount 的列表
    affinityCountsList := make([]topologyToMatchedTermCount, len(allNodes))
    antiAffinityCountsList := make([]topologyToMatchedTermCount, len(allNodes))
    // 初始化计数器
    index := int32(-1)
    // 定义闭包函数 processNode，遍历所有节点，找到与传入 Pod 的亲和性或反亲和性匹配的现有 Pod
    processNode := func(i int) {
        nodeInfo := allNodes[i]
        node := nodeInfo.Node()
        if node == nil {
            klog.ErrorS(nil, "Node not found")
            return
        }
        // 初始化两个 topologyToMatchedTermCount，分别用于存储匹配的亲和性和反亲和性
        affinity := make(topologyToMatchedTermCount)
        antiAffinity := make(topologyToMatchedTermCount)
        // 遍历节点上的所有 Pod，计算亲和性和反亲和性的匹配数
        for _, existingPod := range nodeInfo.Pods {
            affinity.updateWithAffinityTerms(podInfo.RequiredAffinityTerms, existingPod.Pod, node, 1)
            // 传入 Pod 的 terms 中的 namespaceSelector 已经被合并到 namespaces 中，
            // 所以这里不需要查找现有 Pod 的命名空间标签，因此将 nsLabels 参数设置为 nil。
            antiAffinity.updateWithAntiAffinityTerms(podInfo.RequiredAntiAffinityTerms, existingPod.Pod, nil, node, 1)
        }
        // 如果存在匹配的亲和性或反亲和性，将其存储到 affinityCountsList 和 antiAffinityCountsList 中
        if len(affinity) > 0 || len(antiAffinity) > 0 {
			k := atomic.AddInt32(&index, 1) // 原子操作，计算索引
            affinityCountsList[k] = affinity // 将亲和条件添加到对应的 topologyToMatchedTermCount 中
            antiAffinityCountsList[k] = antiAffinity // 将反亲和条件添加到对应的 topologyToMatchedTermCount 中
		}
	}
    // 并发执行
	pl.parallelizer.Until(ctx, len(allNodes), processNode, pl.Name())

	for i := 0; i <= int(index); i++ { // 遍历所有匹配到的节点
        affinityCounts.append(affinityCountsList[i]) // 合并所有亲和条件
        antiAffinityCounts.append(antiAffinityCountsList[i]) // 合并所有反亲和条件
	}

	return affinityCounts, antiAffinityCounts // 返回亲和条件和反亲和条件
}
```

### Filter

```GO
// Filter invoked at the filter extension point.
// It checks if a pod can be scheduled on the specified node with pod affinity/anti-affinity configuration.
func (pl *InterPodAffinity) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 如果节点为空，返回错误信息。
    if nodeInfo.Node() == nil {
        return framework.NewStatus(framework.Error, "node not found")
    }

    // 从 cycleState 中获取 preFilterState 状态数据，如果获取失败则返回错误信息。
    state, err := getPreFilterState(cycleState)
    if err != nil {
        return framework.AsStatus(err)
    }

    // 判断节点是否符合 Pod 亲和规则，如果不符合则返回错误信息。
    if !satisfyPodAffinity(state, nodeInfo) {
        return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonAffinityRulesNotMatch)
    }

    // 判断节点是否符合 Pod 反亲和规则，如果不符合则返回错误信息。
    if !satisfyPodAntiAffinity(state, nodeInfo) {
        return framework.NewStatus(framework.Unschedulable, ErrReasonAntiAffinityRulesNotMatch)
    }

    // 判断节点中已经存在的 Pod 是否符合反亲和规则，如果不符合则返回错误信息。
    if !satisfyExistingPodsAntiAffinity(state, nodeInfo) {
        return framework.NewStatus(framework.Unschedulable, ErrReasonExistingAntiAffinityRulesNotMatch)
    }

    // 如果所有规则均符合，则返回 nil。
    return nil
}
```

#### getPreFilterState

```GO
// 从 CycleState 中获取 preFilterState 状态数据。
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
    // 从 cycleState 中读取 preFilterState 状态数据。
    c, err := cycleState.Read(preFilterStateKey)
    if err != nil {
        // preFilterState 数据不存在，说明 PreFilter 函数未被调用。
        return nil, fmt.Errorf("error reading %q from cycleState: %w", preFilterStateKey, err)
    }

    // 转换 preFilterState 状态数据并返回。
    s, ok := c.(*preFilterState)
    if !ok {
        return nil, fmt.Errorf("%+v  convert to interpodaffinity.state error", c)
    }
    return s, nil
}
```

#### satisfyPodAffinity

```GO
// 检查节点是否符合传入 Pod 的亲和规则。
func satisfyPodAffinity(state *preFilterState, nodeInfo *framework.NodeInfo) bool {
    // 初始化变量 podsExist，表示所有亲和性要求的 Pod 都存在于节点上。
	podsExist := true
    // 遍历所有亲和性要求的项。
	for _, term := range state.podInfo.RequiredAffinityTerms {
        // 判断节点是否具有亲和性要求的拓扑标签。
		if topologyValue, ok := nodeInfo.Node().Labels[term.TopologyKey]; ok {
            // 构造拓扑键值对。
			tp := topologyPair{key: term.TopologyKey, value: topologyValue}
            // 判断节点是否满足亲和性要求的拓扑键值对。
			if state.affinityCounts[tp] <= 0 {
				podsExist = false // 如果节点不满足，则置变量 podsExist 为 false。
			}
		} else {
			// 如果节点不具有亲和性要求的拓扑标签，则直接返回 false。
			// 因为所有的拓扑标签都必须存在于节点上才能匹配要求。
			return false
		}
	}
	// 如果节点不满足亲和性要求，则进一步检查是否是由于没有匹配的 Pod 导致的。
	if !podsExist {
		// 如果没有其他 Pod 匹配当前 Pod 的命名空间和标签选择器，并且节点具有所有请求的拓扑结构，
		// 则允许 Pod 通过亲和性检查，以免将这样的 Pod 永久挂起在等待状态。
		if len(state.affinityCounts) == 0 && podMatchesAllAffinityTerms(state.podInfo.RequiredAffinityTerms, state.podInfo.Pod) {
			return true
		}
		return false
	}
	return true // 否则返回 true。
}

```

##### podMatchesAllAffinityTerms

```GO
// 返回值为 true 当且仅当给定的 Pod 匹配所有给定的亲和性要求。
func podMatchesAllAffinityTerms(terms []framework.AffinityTerm, pod *v1.Pod) bool {
    // 如果没有亲和性要求，则返回 false。
    if len(terms) == 0 {
    	return false
    }
    // 遍历所有的亲和性要求。
    for _, t := range terms {
        // 由于传入的命名空间选择器已经合并到了命名空间集合中，
        // 所以这里不需要传递额外的命名空间标签参数。
        // 判断 Pod 是否匹配当前亲和性要求。
        if !t.Matches(pod, nil) {
        	return false // 如果不匹配，则直接返回 false。
        }
    }
    return true // 否则返回 true。
}
```

#### satisfyPodAntiAffinity

```GO
// 检查节点是否满足传入 pod 的反亲和性规则。
func satisfyPodAntiAffinity(state *preFilterState, nodeInfo *framework.NodeInfo) bool {
    // 如果 state 中有反亲和性条件，则逐个检查条件是否满足。
    if len(state.antiAffinityCounts) > 0 {
        for _, term := range state.podInfo.RequiredAntiAffinityTerms {
            if topologyValue, ok := nodeInfo.Node().Labels[term.TopologyKey]; ok {
                // 生成 topologyPair 结构体，用于后续检查
                tp := topologyPair{key: term.TopologyKey, value: topologyValue}
                // 如果节点中存在与 pod 的 anti-affinity 条件匹配的其他 pod，则返回 false。
                if state.antiAffinityCounts[tp] > 0 {
                	return false
                }
            }
        }
    }
    // 如果节点不存在满足反亲和性条件的 pod，则返回 true。
    return true
}
```

#### satisfyExistingPodsAntiAffinity

```GO
// 检查将该 pod 调度到此节点是否会破坏任何现有 pod 的反亲和性条件。
func satisfyExistingPodsAntiAffinity(state *preFilterState, nodeInfo *framework.NodeInfo) bool {
    // 如果 state 中有现有 pod 的反亲和性条件，则逐个检查条件是否满足。
    if len(state.existingAntiAffinityCounts) > 0 {
        // 遍历节点标签，获取受影响的现有 pod 的 topology pair。
        for topologyKey, topologyValue := range nodeInfo.Node().Labels {
            tp := topologyPair{key: topologyKey, value: topologyValue}
            // 如果节点中存在与现有 pod 的 anti-affinity 条件匹配的其他 pod，则返回 false。
            if state.existingAntiAffinityCounts[tp] > 0 {
            	return false
            }
        }
    }
    // 如果节点不存在满足现有 pod 的反亲和性条件的其他 pod，则返回 true。
    return true
}
```

### PreScore

```GO
// PreScore函数用于构建并写入CycleState，后续Score和NormalizeScore函数需要用到CycleState中的信息进行调度决策。
func (pl *InterPodAffinity) PreScore(
    pCtx context.Context, // 上下文对象，包含调度相关的信息。
    cycleState *framework.CycleState, // 调度周期状态，保存上一次调度的信息，用于Score和NormalizeScore函数。
    pod *v1.Pod, // 待调度的Pod对象。
    nodes []*v1.Node, // 可用于调度的Node列表。
) *framework.Status {
    if len(nodes) == 0 { // 如果没有可用于调度的Node，直接返回。
        // No nodes to score.
        return nil
    }
    if pl.sharedLister == nil { // 如果sharedLister为空，返回错误信息。
        return framework.NewStatus(framework.Error, "empty shared lister in InterPodAffinity PreScore")
    }

    // 判断Pod的Affinity规则中是否包含PreferredDuringSchedulingIgnoredDuringExecution约束。
    affinity := pod.Spec.Affinity
    hasPreferredAffinityConstraints := affinity != nil && affinity.PodAffinity != nil && len(affinity.PodAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0
    hasPreferredAntiAffinityConstraints := affinity != nil && affinity.PodAntiAffinity != nil && len(affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0

    // 如果传入的Pod对象没有亲和性规则，并且IgnorePreferredTermsOfExistingPods为true，则无需计算现有Pod对象的亲和性规则。
    if pl.args.IgnorePreferredTermsOfExistingPods && !hasPreferredAffinityConstraints && !hasPreferredAntiAffinityConstraints {
        // 如果不需要计算亲和性规则，则初始化topologyScore，并将其写入CycleState中。
        cycleState.Write(preScoreStateKey, &preScoreState{
            topologyScore: make(map[string]map[string]int64),
        })
        return nil
    }

    // 如果传入的Pod对象有PreferredDuringSchedulingIgnoredDuringExecution约束，或者有亲和性规则，则需要获取所有的Node对象。
    // 否则只需要获取已有Pod对象的Node列表。
    var allNodes []*framework.NodeInfo
    var err error
    if hasPreferredAffinityConstraints || hasPreferredAntiAffinityConstraints {
        allNodes, err = pl.sharedLister.NodeInfos().List()
        if err != nil {
            return framework.AsStatus(fmt.Errorf("failed to get all nodes from shared lister: %w", err))
        }
    } else {
        allNodes, err = pl.sharedLister.NodeInfos().HavePodsWithAffinityList()
        if err != nil {
            return framework.AsStatus(fmt.Errorf("failed to get pods with affinity list: %w", err))
        }
    }

    // 初始化preScoreState结构体。
    state := &preScoreState{
        topologyScore: make(map[string]map[string]int64),
    }

    // 根据Pod对象信息，初始化PodInfo对象。
    if state.podInfo, err = framework.NewPodInfo(pod); err != nil {
        // 理想情况下，不应该进入该分支，因为错误应该在PreFilter函数中捕获。
        return framework.AsStatus(fmt.Errorf("failed to parse pod: %w", err))
	}

	for i := range state.podInfo.PreferredAffinityTerms {
        // 如果合并首选亲和性条件的命名空间时出错，则返回一个格式化的错误信息。
		if err := pl.mergeAffinityTermNamespacesIfNotEmpty(&state.podInfo.PreferredAffinityTerms[i].AffinityTerm); err != nil {
			return framework.AsStatus(fmt.Errorf("updating PreferredAffinityTerms: %w", err))
		}
	}
	for i := range state.podInfo.PreferredAntiAffinityTerms {
        // 如果合并首选反亲和性条件的命名空间时出错，则返回一个格式化的错误信息。
		if err := pl.mergeAffinityTermNamespacesIfNotEmpty(&state.podInfo.PreferredAntiAffinityTerms[i].AffinityTerm); err != nil {
			return framework.AsStatus(fmt.Errorf("updating PreferredAntiAffinityTerms: %w", err))
		}
	}
    // 获取Pod所在命名空间的标签的快照，并将其存储在preScoreState的命名空间标签字段中。
	state.namespaceLabels = GetNamespaceLabelsSnapshot(pod.Namespace, pl.nsLister)
	
    // 创建与allNodes长度相同的空分数映射数组。
	topoScores := make([]scoreMap, len(allNodes))
    // 初始化一个带有-1值的32位有符号整数，用于原子操作。
	index := int32(-1)
    // 定义了一个匿名函数processNode，它用于计算每个节点的拓扑得分并将结果存储在topoScores数组中。
	processNode := func(i int) {
		nodeInfo := allNodes[i]
		if nodeInfo.Node() == nil {
			return
		}
		// 除非被调度的Pod有首选亲和性条件，否则我们只需要处理节点中具有亲和性的Pod。
		podsToProcess := nodeInfo.PodsWithAffinity
		if hasPreferredAffinityConstraints || hasPreferredAntiAffinityConstraints {
			// 我们需要处理所有Pod。
			podsToProcess = nodeInfo.Pods
		}
	
        // 创建一个空的分数映射，用于存储此节点的拓扑得分。
		topoScore := make(scoreMap)
		for _, existingPod := range podsToProcess {
             // 处理现有Pod，计算此节点的拓扑得分。
			pl.processExistingPod(state, existingPod, nodeInfo, pod, topoScore)
		}
		if len(topoScore) > 0 {
             // 将此节点的拓扑得分存储在topoScores数组中。
			topoScores[atomic.AddInt32(&index, 1)] = topoScore
		}
	}
    // 使用parallelizer并发地计算每个节点的拓扑得分。
	pl.parallelizer.Until(pCtx, len(allNodes), processNode, pl.Name())

	for i := 0; i <= int(index); i++ {
		state.topologyScore.append(topoScores[i])
	}
	// 写入
	cycleState.Write(preScoreStateKey, state)
	return nil
}
```

#### preScoreState

```GO
type preScoreState struct {
	topologyScore scoreMap        // 存储拓扑得分信息
	podInfo       *framework.PodInfo // 存储Pod信息
	namespaceLabels labels.Set // 存储命名空间标签
}

const preScoreStateKey = "PreScore" + Name  // 定义名为preScoreStateKey的常量字符串

type scoreMap map[string]map[string]int64  // 定义名为scoreMap的map类型

func (s *preScoreState) Clone() framework.StateData {  // 实现Clone方法
	return s
}

func (m scoreMap) processTerm(term *framework.AffinityTerm, weight int32, pod *v1.Pod, nsLabels labels.Set, node *v1.Node, multiplier int32) { // 处理单个拓扑约束的得分计算
	if term.Matches(pod, nsLabels) { // 判断Pod是否满足拓扑约束
		if tpValue, tpValueExist := node.Labels[term.TopologyKey]; tpValueExist { // 获取节点上指定拓扑约束的标签值
			if m[term.TopologyKey] == nil {
				m[term.TopologyKey] = make(map[string]int64)
				// 如果当前拓扑约束尚未记录，则初始化
			}
			m[term.TopologyKey][tpValue] += int64(weight * multiplier)  // 增加拓扑得分
		}
	}
}

func (m scoreMap) processTerms(terms []framework.WeightedAffinityTerm, pod *v1.Pod, nsLabels labels.Set, node *v1.Node, multiplier int32) { // 处理多个拓扑约束的得分计算
	for _, term := range terms {
		m.processTerm(&term.AffinityTerm, term.Weight, pod, nsLabels, node, multiplier)
	}
}

func (m scoreMap) append(other scoreMap) {  // 将other拓扑得分信息附加到当前拓扑得分信息上
	for topology, oScores := range other {
		scores := m[topology]
		if scores == nil {
			m[topology] = oScores
			continue
		}
		for k, v := range oScores {
			scores[k] += v
		}
	}
}
```

#### mergeAffinityTermNamespacesIfNotEmpty

```GO
// 使用 NamespaceSelector 识别的一组命名空间更新 Namespaces。
// 如果成功，则将 NamespaceSelector 设置为 nil。
// 假设这个术语是针对一个传入的 pod，因此 namespaceSelector 要么展开为 Namespaces（因此选择器
// 被设置为 Nothing()），要么为空（Empty()），这意味着匹配所有内容。因此，在与此术语匹配时，
// 无需查找现有 pod 的命名空间标签，以显式匹配它们与术语的 namespaceSelector。
func (pl *InterPodAffinity) mergeAffinityTermNamespacesIfNotEmpty(at *framework.AffinityTerm) error {
    if at.NamespaceSelector.Empty() { // 如果 NamespaceSelector 为空，返回 nil
    	return nil
    }
    ns, err := pl.nsLister.List(at.NamespaceSelector) // 获取 NamespaceSelector 中匹配的命名空间
    if err != nil {
    	return err
    }
    for _, n := range ns { // 遍历所有匹配的命名空间
    	at.Namespaces.Insert(n.Name) // 将命名空间的名称插入到 AffinityTerm 的 Namespaces 中
    }
    at.NamespaceSelector = labels.Nothing() // 将 NamespaceSelector 设置为 Nothing()，表示选择所有命名空间
    return nil
}
```

#### GetNamespaceLabelsSnapshot

```GO
// GetNamespaceLabelsSnapshot 返回与命名空间关联的标签的快照。
func GetNamespaceLabelsSnapshot(ns string, nsLister listersv1.NamespaceLister) (nsLabels labels.Set) {
podNS, err := nsLister.Get(ns) // 获取命名空间
    if err == nil {
    // 创建并返回标签的快照。
    	return labels.Merge(podNS.Labels, nil) // 返回命名空间的标签
    }
    klog.V(3).InfoS("getting namespace, assuming empty set of namespace labels", "namespace", ns, "err", err)
    return // 如果获取命名空间时发生错误，则返回空的标签集合
}
```

#### processExistingPod

```GO
// 对于每个已存在的 Pod，处理其节点与拓扑相关的评分计算
func (pl *InterPodAffinity) processExistingPod(
    state *preScoreState, // 先前的评分状态
    existingPod *framework.PodInfo, // 已存在的 Pod 的信息
    existingPodNodeInfo *framework.NodeInfo, // 已存在的 Pod 所在的节点的信息
    incomingPod *v1.Pod, // 待调度的 Pod
    topoScore scoreMap, // 存储拓扑相关评分的 map
) {
    existingPodNode := existingPodNodeInfo.Node()
    if len(existingPodNode.Labels) == 0 {
    	return // 如果已存在的 Pod 所在的节点没有 label，则直接返回
    }
    // 对于 <pod> 的每个 soft pod affinity term，如果 <existingPod> 符合条件，则
    // 通过该 term 的权重将集群中与 <existingPod> 节点的 <term.TopologyKey> 相同的每个节点的 <p.counts> 值增加。
    // 注意，入站 pod 的 term 已将 namespaceSelector 合并到了 Namespaces 中，因此这里不需要查找现有 pod 的命名空间标签来与 term 的 namespaceSelector 相匹配，因此 nsLabels 参数设置为 nil。
    topoScore.processTerms(state.podInfo.PreferredAffinityTerms, existingPod.Pod, nil, existingPodNode, 1)

    // 对于 <pod> 的每个 soft pod anti-affinity term，如果 <existingPod> 符合条件，则
    // 通过该 term 的权重将集群中与 <existingPod> 节点的 <term.TopologyKey> 相同的每个节点的 <p.counts> 值减少。
    // 注意，入站 pod 的 term 已将 namespaceSelector 合并到了 Namespaces 中，因此这里不需要查找现有 pod 的命名空间标签来与 term 的 namespaceSelector 相匹配，因此 nsLabels 参数设置为 nil。
    topoScore.processTerms(state.podInfo.PreferredAntiAffinityTerms, existingPod.Pod, nil, existingPodNode, -1)

    // 对于每个 hard pod affinity term of <existingPod>，如果 <pod> 符合条件，则
    // 通过常数 <args.hardPodAffinityWeight> 将集群中与 <existingPod> 节点的 <term.TopologyKey> 相同的每个节点的 <p.counts> 值增加。
    if pl.args.HardPodAffinityWeight > 0 && len(existingPodNode.Labels) != 0 {
        for _, t := range existingPod.RequiredAffinityTerms {
            topoScore.processTerm(&t, pl.args.HardPodAffinityWeight, incomingPod, state.namespaceLabels, existingPodNode, 1)
        }
    }

    // 对于每个 soft pod affinity term of <existingPod>，如果 <pod> 符合条件，则
    // 通过该 term 的权重将集群中与 <existingPod> 节点的 <term.TopologyKey> 相同的每个节点的 <p.counts> 值增加。
    topoScore.processTerms(existingPod.PreferredAffinityTerms, incomingPod, state.namespaceLabels, existingPodNode, 1)

	// 对于<existingPod>的每个软Pod反亲和性项，如果<pod>匹配该项，则将该项的权重值为负数，
    // 减去在集群中与<existingPod>的节点具有相同<term.TopologyKey>值的每个节点上的<pm.counts>值。
	topoScore.processTerms(existingPod.PreferredAntiAffinityTerms, incomingPod, state.namespaceLabels, existingPodNode, -1)
}
```

### Score&ScoreExtensions

```go
// 在Score扩展点上调用Score函数。
// 此函数返回的“score”是从cycleState中获得的与节点标签匹配的拓扑键的权重之和。
// 稍后会对其进行归一化处理。
// 注意：对于Pod亲和性，返回的“score”是正数，对于Pod反亲和性，则为负数。
func (pl *InterPodAffinity) Score(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 从共享列表中获取节点信息。
    nodeInfo, err := pl.sharedLister.NodeInfos().Get(nodeName)
    if err != nil {
    	return 0, framework.AsStatus(fmt.Errorf("failed to get node %q from Snapshot: %w", nodeName, err))
    }
    // 获取节点对象。
    node := nodeInfo.Node()
    // 从cycleState中获取预分数状态。
    s, err := getPreScoreState(cycleState)
    if err != nil {
        return 0, framework.AsStatus(err)
    }
    // 初始化分数为0。
    var score int64
    // 对于预分数中的每个拓扑键和对应的值，如果该节点的标签中有该键，则将该键的值加入分数中。
    for tpKey, tpValues := range s.topologyScore {
        if v, exist := node.Labels[tpKey]; exist {
            score += tpValues[v]
        }
    }

    return score, nil
}

// Score扩展点的ScoreExtensions函数。
func (pl *InterPodAffinity) ScoreExtensions() framework.ScoreExtensions {
	return pl
}

// NormalizeScore 对每个被筛选出来的节点对应的分数进行归一化。
func (pl *InterPodAffinity) NormalizeScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
s, err := getPreScoreState(cycleState)
    if err != nil {
    	return framework.AsStatus(err)
    }
    // 如果没有获取到拓扑分数，则直接返回。
    if len(s.topologyScore) == 0 {
        return nil
    }

    // 计算分数的最大值和最小值。
    var minCount int64 = math.MaxInt64
    var maxCount int64 = math.MinInt64
    for i := range scores {
        score := scores[i].Score
        if score > maxCount {
            maxCount = score
        }
        if score < minCount {
            minCount = score
        }
    }

    // 计算最大值和最小值之间的差距。
    maxMinDiff := maxCount - minCount

    // 对每个节点的分数进行归一化。
    for i := range scores {
        fScore := float64(0)
        if maxMinDiff > 0 {
            fScore = float64(framework.MaxNodeScore) * (float64(scores[i].Score-minCount) / float64(maxMinDiff))
        }

        scores[i].Score = int64(fScore)
    }

    return nil
}
```

#### getPreScoreState

```go
// 从给定的CycleState中获取preScoreState对象
func getPreScoreState(cycleState *framework.CycleState) (*preScoreState, error) {
    // 从cycleState中读取preScoreState对象
    c, err := cycleState.Read(preScoreStateKey)
    if err != nil {
    	return nil, fmt.Errorf("从cycleState中读取%q失败: %w", preScoreStateKey, err)
    }
    // 将读取到的对象转换为preScoreState类型，如果转换失败则返回错误
    s, ok := c.(*preScoreState)
    if !ok {
        return nil, fmt.Errorf("%+v 转换为 interpodaffinity.preScoreState 类型时出错", c)
    }

    return s, nil
}
```

#### EventsToRegister

```go
// EventsToRegister返回可能使未调度Pod可调度的可能事件
func (pl *InterPodAffinity) EventsToRegister() []framework.ClusterEvent {
    return []framework.ClusterEvent{
        // 所有ActionType都包括以下事件：
        // - Delete。 由于违反现有Pod的反亲和力约束，无法调度的Pod可能会失败，
        // 删除现有的Pod可能会使其可调度。
        // - Update。 更新现有Pod的标签（例如删除）可能会使无法调度的Pod可调度。
        // - Add。由于违反Pod亲和性约束，无法调度的Pod可能会失败，
        // 添加已分配的Pod可能会使其可调度。
        {Resource: framework.Pod, ActionType: framework.All},
        {Resource: framework.Node, ActionType: framework.Add | framework.UpdateNodeLabel},
    }
}
```

## NodeAffinity

### 作用

Kubernetes调度器中的NodeAffinity插件允许您指定在哪些节点上可以调度Pod。该插件允许您在节点标签和Pod标签之间定义匹配规则。在Pod规范中定义NodeAffinity后，调度器会在节点选择器上执行过滤器，并选择与规则匹配的节点。这使得您可以将Pod分配给特定的节点，例如只在某些节点上运行GPU工作负载，或者只在某些特定的机器上运行特定的应用程序。

### 结构

```GO
// NodeAffinity是一个插件，它检查Pod节点选择器是否与节点标签匹配。
type NodeAffinity struct {
    handle framework.Handle // 定义结构体NodeAffinity的成员变量handle，类型为framework.Handle
    addedNodeSelector nodeaffinity.NodeSelector // 定义结构体NodeAffinity的成员变量addedNodeSelector，类型为nodeaffinity.NodeSelector指针类型
    addedPrefSchedTerms nodeaffinity.PreferredSchedulingTerms // 定义结构体NodeAffinity的成员变量addedPrefSchedTerms，类型为nodeaffinity.PreferredSchedulingTerms指针类型
}

var _ framework.PreFilterPlugin = &NodeAffinity{} // 预过滤插件
var _ framework.FilterPlugin = &NodeAffinity{} // 过滤插件
var _ framework.PreScorePlugin = &NodeAffinity{} // 预评分插件
var _ framework.ScorePlugin = &NodeAffinity{} // 评分插件
var _ framework.EnqueueExtensions = &NodeAffinity{} // 扩展插件

const Name = names.NodeAffinity // 插件名称

// Name返回插件名称，用于日志等。
func (pl *NodeAffinity) Name() string {
	return Name
}

// New初始化一个新插件并返回它。
func New(plArgs runtime.Object, h framework.Handle) (framework.Plugin, error) {
    args, err := getArgs(plArgs) // 获取插件参数
    if err != nil {
    	return nil, err
    }
    pl := &NodeAffinity{ // 初始化NodeAffinity插件结构体
    	handle: h,
    }
    if args.AddedAffinity != nil { // 如果插件参数中新增了节点亲和性配置
        if ns := args.AddedAffinity.RequiredDuringSchedulingIgnoredDuringExecution; ns != nil {
            // 新增的节点选择器
            pl.addedNodeSelector, err = nodeaffinity.NewNodeSelector(ns)
            if err != nil {
             return nil, fmt.Errorf("parsing addedAffinity.requiredDuringSchedulingIgnoredDuringExecution: %w", err)
            }
        }
        // TODO: parse requiredDuringSchedulingRequiredDuringExecution when it gets added to the API.
        if terms := args.AddedAffinity.PreferredDuringSchedulingIgnoredDuringExecution; len(terms) != 0 {
            // 新增的首选调度项
            pl.addedPrefSchedTerms, err = nodeaffinity.NewPreferredSchedulingTerms(terms)
            if err != nil {
                return nil, fmt.Errorf("parsing addedAffinity.preferredDuringSchedulingIgnoredDuringExecution: %w", err)
            }
    	}
    }
    return pl, nil
}
```

#### getArgs

```GO
func getArgs(obj runtime.Object) (config.NodeAffinityArgs, error) {
	ptr, ok := obj.(*config.NodeAffinityArgs)
	if !ok {
		return config.NodeAffinityArgs{}, fmt.Errorf("args are not of type NodeAffinityArgs, got %T", obj)
	}
	return *ptr, validation.ValidateNodeAffinityArgs(nil, ptr)
}
```

### PreFilter&PreFilterExtensions

```go
// PreFilter函数用于构建并写入Filter所需的循环状态。
func (pl *NodeAffinity) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 检查Pod的亲和性是否为nil，或者NodeAffinity是否为nil，或者RequiredDuringSchedulingIgnoredDuringExecution是否为nil。
    affinity := pod.Spec.Affinity
    noNodeAffinity := (affinity == nil ||
    affinity.NodeAffinity == nil ||
    affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil)
    // 如果Pod没有nodeSelector，也没有node affinity，也没有被添加的node selector，说明NodeAffinity Filter与Pod无关。
    if noNodeAffinity && pl.addedNodeSelector == nil && pod.Spec.NodeSelector == nil {
    	return nil, framework.NewStatus(framework.Skip)
    }
    // 获取必需的NodeAffinity并保存在preFilterState中。
    state := &preFilterState{requiredNodeSelectorAndAffinity: nodeaffinity.GetRequiredNodeAffinity(pod)}
    cycleState.Write(preFilterStateKey, state)

    if noNodeAffinity || len(affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms) == 0 {
        // 如果Pod没有NodeAffinity或者没有必需的NodeSelectorTerms，则直接返回nil。
        return nil, nil
    }

    // 检查是否有亲和性与特定的node匹配，如果匹配，则返回这些节点。
    terms := affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
    var nodeNames sets.Set[string]
    for _, t := range terms {
        var termNodeNames sets.Set[string]
        for _, r := range t.MatchFields {
            if r.Key == metav1.ObjectNameField && r.Operator == v1.NodeSelectorOpIn {
                // 这里的要求代表AND约束条件，因此需要找到节点的交集。
                s := sets.New(r.Values...)
                if termNodeNames == nil {
                    termNodeNames = s
                } else {
                    termNodeNames = termNodeNames.Intersection(s)
                }
            }
        }
        if termNodeNames == nil {
            // 如果这个term没有node.Name字段的affinity，则所有节点都符合要求，因为terms是OR关系。
            return nil, nil
        }
        nodeNames = nodeNames.Union(termNodeNames)
    }
    // 如果nodeNames不为nil，但长度为0，则说明每个term都与node.Name存在冲突亲和性；因此，Pod将不会匹配任何节点。
    if nodeNames != nil && len(nodeNames) == 0 {
        return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, errReasonConflict)
    } else if len(nodeNames) > 0 {
        return &framework.PreFilterResult{NodeNames: nodeNames}, nil
    }
    return nil, nil
}

// PreFilterExtensions函数对于此插件不必要，因为状态不取决于pod的添加或删除。
func (pl *NodeAffinity) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

#### preFilterState

```go
type preFilterState struct {
	requiredNodeSelectorAndAffinity nodeaffinity.RequiredNodeAffinity
}

// Clone just returns the same state because it is not affected by pod additions or deletions.
func (s *preFilterState) Clone() framework.StateData {
	return s
}
```

### Filter

```go
// Filter 检查 Node 是否符合 Pod 的 .spec.affinity.nodeAffinity 和插件添加的亲和性。
func (pl *NodeAffinity) Filter(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    node := nodeInfo.Node()
    if node == nil {
    	return framework.NewStatus(framework.Error, "node not found")
    }
    if pl.addedNodeSelector != nil && !pl.addedNodeSelector.Match(node) {
        // 如果插件添加了 nodeSelector，但是该 Node 不符合该 selector，那么该 Node 不符合 Pod 的要求。
        return framework.NewStatus(framework.UnschedulableAndUnresolvable, errReasonEnforced)
    }
    s, err := getPreFilterState(state)
    if err != nil {
        // 如果 PreFilter 禁用了，那么在此处使用回退方法计算 requiredNodeSelector 和 requiredNodeAffinity。
        s = &preFilterState{requiredNodeSelectorAndAffinity: nodeaffinity.GetRequiredNodeAffinity(pod)}
    }

    // 忽略解析错误，以保持向后兼容性。
    // 检查该 Node 是否符合 Pod 的 requiredNodeSelectorAndAffinity。
    match, _ := s.requiredNodeSelectorAndAffinity.Match(node)
    if !match {
        // 如果该 Node 不符合 Pod 的要求，则返回一个不可调度和无法解决的状态。
        return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonPod)
    }

    return nil
}
```

#### getPreFilterState

```go
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
	c, err := cycleState.Read(preFilterStateKey)
	if err != nil {
		return nil, fmt.Errorf("reading %q from cycleState: %v", preFilterStateKey, err)
	}

	s, ok := c.(*preFilterState)
	if !ok {
		return nil, fmt.Errorf("invalid PreFilter state, got type %T", c)
	}
	return s, nil
}
```

### PreScore

```go
// PreScore 函数构建并写入周期状态，用于 Score 和 NormalizeScore。
func (pl *NodeAffinity) PreScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
    // 如果候选节点列表为空，则直接返回 nil。
    if len(nodes) == 0 {
        return nil
    }
    // 获取 Pod 的 PreferredNodeAffinity，即 Pod 对节点的偏好。
    preferredNodeAffinity, err := getPodPreferredNodeAffinity(pod)
    if err != nil {
        return framework.AsStatus(err)
    }
    // 创建 preScoreState 结构体，并初始化 preferredNodeAffinity 字段。
    state := &preScoreState{
    	preferredNodeAffinity: preferredNodeAffinity,
    }
    // 将 preScoreState 写入周期状态中。
    cycleState.Write(preScoreStateKey, state)
    return nil
}
```

#### preScoreState

```go
// preScoreState 在 PreScore 中计算，并在 Score 中使用。
type preScoreState struct {
	preferredNodeAffinity *nodeaffinity.PreferredSchedulingTerms // Pod 的 PreferredNodeAffinity
}

// Clone 实现了必需的 Clone 接口。我们并没有真正地复制数据，因为没有必要这样做。
func (s *preScoreState) Clone() framework.StateData {
	return s
}
```

### Score

```go
// Score 函数返回与节点匹配的术语权重之和。
// 术语来自 Pod 的 .spec.affinity.nodeAffinity 和插件的默认亲和性。
func (pl *NodeAffinity) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 从 SharedLister 中获取节点信息。
    nodeInfo, err := pl.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
    if err != nil {
        return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
    }
    // 获取节点对象。
    node := nodeInfo.Node()

    var count int64
    // 如果插件有添加 PreferredSchedulingTerms，则将其权重累加到 count 中。
    if pl.addedPrefSchedTerms != nil {
        count += pl.addedPrefSchedTerms.Score(node)
    }

    // 从 CycleState 中获取 preScoreState。
    s, err := getPreScoreState(state)
    if err != nil {
        // 当 PreScore 禁用时，回退到此处计算 preferredNodeAffinity。
        preferredNodeAffinity, err := getPodPreferredNodeAffinity(pod)
        if err != nil {
            return 0, framework.AsStatus(err)
        }
        s = &preScoreState{
            preferredNodeAffinity: preferredNodeAffinity,
        }
    }

    // 如果 preScoreState 中有 PreferredNodeAffinity，则将其权重累加到 count 中。
    if s.preferredNodeAffinity != nil {
        count += s.preferredNodeAffinity.Score(node)
    }

    return count, nil
}

// ScoreExtensions of the Score plugin.
func (pl *NodeAffinity) ScoreExtensions() framework.ScoreExtensions {
	return pl
}

// NormalizeScore invoked after scoring all nodes.
func (pl *NodeAffinity) NormalizeScore(ctx context.Context, state *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
	return helper.DefaultNormalizeScore(framework.MaxNodeScore, false, scores)
}
```

#### getPreScoreState

```go
// getPreScoreState 函数从 CycleState 中获取 preScoreState。
func getPreScoreState(cycleState *framework.CycleState) (*preScoreState, error) {
	c, err := cycleState.Read(preScoreStateKey)
	if err != nil {
		return nil, fmt.Errorf("reading %q from cycleState: %w", preScoreStateKey, err)
	}

	s, ok := c.(*preScoreState)
	if !ok {
		return nil, fmt.Errorf("invalid PreScore state, got type %T", c)
	}
	return s, nil
}
```

#### DefaultNormalizeScore

```go
// DefaultNormalizeScore 生成一个归一化函数，可以将得分从 [0, max(scores)] 区间映射到 [0, maxPriority] 区间内。
// 如果 reverse 设置为 true，将通过将得分从 maxPriority 中减去归一化后的分数来反转得分。
// 注意：输入的得分始终假定为非负整数。
func DefaultNormalizeScore(maxPriority int64, reverse bool, scores framework.NodeScoreList) *framework.Status {
	// 计算最大得分
	var maxCount int64
	for i := range scores {
		if scores[i].Score > maxCount {
			maxCount = scores[i].Score
		}
	}

	// 如果最大得分为 0，那么所有的节点都将得到最大的归一化得分
	if maxCount == 0 {
		if reverse {
			for i := range scores {
				scores[i].Score = maxPriority
			}
		}
		return nil
	}

	// 对所有的节点进行归一化
	for i := range scores {
		score := scores[i].Score

		// 将得分从 [0, maxCount] 区间映射到 [0, maxPriority] 区间
		score = maxPriority * score / maxCount
		if reverse {
			// 如果需要反转，那么就将得分从 maxPriority 中减去归一化后的分数
			score = maxPriority - score
		}

		scores[i].Score = score
	}
	return nil
}
```

#### EventsToRegister

```go
// EventsToRegister 返回可能导致 Pod 无法被此插件调度的事件类型列表。
func (pl *NodeAffinity) EventsToRegister() []framework.ClusterEvent {
    // 返回一个 framework.ClusterEvent 类型的数组，该数组包含了可能导致 Pod 调度失败的事件类型列表。
    return []framework.ClusterEvent{
    	{Resource: framework.Node, ActionType: framework.Add | framework.Update},
    }
}
```

## NodeVolumeLimits

### 作用

限制节点上可用的本地磁盘（Local Volume）的使用量。在Kubernetes中，使用Local Volume来申请节点本地存储，它是一种无需网络存储即可访问的本地存储卷。但是，本地磁盘在不同的节点上有不同的容量和性能，如果不对它们进行限制，可能会导致节点资源不足，从而影响Pod的可用性和性能。

### 结构

```GO
// CSILimits 是一个插件，用于检查节点的卷容量限制。
type CSILimits struct {
    // 用于从 Kubernetes API Server 获取 CSINode 列表。
    csiNodeLister storagelisters.CSINodeLister
    // 用于从 Kubernetes API Server 获取 PersistentVolume 列表。
    pvLister corelisters.PersistentVolumeLister
    // 用于从 Kubernetes API Server 获取 PersistentVolumeClaim 列表。
    pvcLister corelisters.PersistentVolumeClaimLister
    // 用于从 Kubernetes API Server 获取 StorageClass 列表。
    scLister storagelisters.StorageClassLister
    // 随机生成的 VolumeID 前缀。
    randomVolumeIDPrefix string
    // InTreeToCSITranslator 实现了 Kubernetes 的 InTree To CSI volume migration。
    translator InTreeToCSITranslator
}

// 将 CSILimits 声明为 framework.PreFilterPlugin、framework.FilterPlugin 和 framework.EnqueueExtensions 接口的实现。
var _ framework.PreFilterPlugin = &CSILimits{}
var _ framework.FilterPlugin = &CSILimits{}
var _ framework.EnqueueExtensions = &CSILimits{}

// CSIName 是插件在插件注册表和配置中使用的名称。
const CSIName = names.NodeVolumeLimits

// Name 返回插件的名称，用于日志等。
func (pl *CSILimits) Name() string {
	return CSIName
}

// NewCSI 初始化一个新的插件并返回它。
func NewCSI(_ runtime.Object, handle framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 从 framework.Handle 中获取 SharedInformerFactory。
    informerFactory := handle.SharedInformerFactory()
    // 从 informerFactory 中获取 PersistentVolumeLister。
    pvLister := informerFactory.Core().V1().PersistentVolumes().Lister()
    // 从 informerFactory 中获取 PersistentVolumeClaimLister。
    pvcLister := informerFactory.Core().V1().PersistentVolumeClaims().Lister()
    // 从 informerFactory 中获取 CSINodeLister。
    csiNodesLister := informerFactory.Storage().V1().CSINodes().Lister()
    // 从 informerFactory 中获取 StorageClassLister。
    scLister := informerFactory.Storage().V1().StorageClasses().Lister()
    // 初始化 CSITranslator。
    csiTranslator := csitrans.New()
	
    // 返回一个新的 CSILimits 插件实例。
    return &CSILimits{
        csiNodeLister:        csiNodesLister,
        pvLister:             pvLister,
        pvcLister:            pvcLister,
        scLister:             scLister,
        randomVolumeIDPrefix: rand.String(32),
        translator:           csiTranslator,
    }, nil
}

// InTreeToCSITranslator 包含了检查迁移状态和从 InTree PV 转换为 CSI 所需的方法。
type InTreeToCSITranslator interface {
    // 检查指定的 PersistentVolume 是否可迁移。
    IsPVMigratable(pv *v1.PersistentVolume) bool
    // 检查指定的 Volume 是否可迁移。
    IsInlineMigratable(vol *v1.Volume) bool
    // 检查指定的 InTree 插件名称是否可迁移。
    IsMigratableIntreePluginByName(inTreePluginName string) bool
    // 从指定的 PersistentVolume 和 Volume 中获取 InTree 插件名称。
    GetInTreePluginNameFromSpec(pv *v1.PersistentVolume, vol *v1.Volume) (string, error)
    // 根据指定的 InTree 插件名称获取 CSI 插件名称。
    GetCSINameFromInTreeName(pluginName string) (string, error)
    // 将指定的 InTree PV 转换为 CSI PV。
    TranslateInTreePVToCSI(pv *v1.PersistentVolume) (*v1.PersistentVolume, error)
    // 将指定的 InTree Inline Volume 转换为 CSI PV。
    TranslateInTreeInlineVolumeToCSI(volume *v1.Volume, podNamespace string) (*v1.PersistentVolume, error)
}
```

### PreFilter&PreFilterExtensions

```go
// PreFilter 在 PreFilter 扩展点调用。
//
// 如果 Pod 没有这些类型的 Volume，我们将跳过 Filter 阶段。
func (pl *CSILimits) PreFilter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    volumes := pod.Spec.Volumes
    for i := range volumes {
        vol := &volumes[i]
        // 如果 Volume 是 PersistentVolumeClaim、Ephemeral 或者可迁移的 Inline Volume，跳过 Filter 阶段。
        if vol.PersistentVolumeClaim != nil || vol.Ephemeral != nil || pl.translator.IsInlineMigratable(vol) {
            return nil, nil
        }
	}
    // 如果 Pod 没有这些类型的 Volume，返回 Skip 状态，跳过 Filter 阶段。
    return nil, framework.NewStatus(framework.Skip)
}

// PreFilterExtensions 返回 PreFilter 扩展，包括 Pod 的添加和移除。
func (pl *CSILimits) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

### Filter

```go
// 该函数在过滤器扩展点处被调用
func (pl *CSILimits) Filter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 如果新的 pod 没有任何附加的卷，那么谓词永远为真
    if len(pod.Spec.Volumes) == 0 {
    	return nil
    }
    // 获取 node 对象
    node := nodeInfo.Node()
    if node == nil {
        return framework.NewStatus(framework.Error, "node not found") // 如果找不到 node 对象，则返回错误
    }

    // 如果 CSINode 不存在，则谓词可能从 Node 对象中读取限制
    csiNode, err := pl.csiNodeLister.Get(node.Name) // 获取 CSINode 对象
    if err != nil {
        // TODO: 等 CSINode 默认创建后返回错误（两个版本）
        klog.V(5).InfoS("Could not get a CSINode object for the node", "node", klog.KObj(node), "err", err) // 如果获取不到 CSINode 对象，则记录错误日志
    }

    // 用于存储新卷的名称和限制信息
    newVolumes := make(map[string]string)
    if err := pl.filterAttachableVolumes(pod, csiNode, true /* new pod */, newVolumes); err != nil { // 过滤掉不可附加的卷
        return framework.AsStatus(err) // 如果有错误，则返回错误状态
    }

    // 如果 pod 没有新的 CSI 卷，则谓词永远为真
    if len(newVolumes) == 0 {
        return nil
    }

    // 如果节点没有卷限制，则谓词永远为真
    nodeVolumeLimits := getVolumeLimits(nodeInfo, csiNode)
    if len(nodeVolumeLimits) == 0 {
        return nil
    }

    // 存储附加卷的名称和限制信息
    attachedVolumes := make(map[string]string)
    for _, existingPod := range nodeInfo.Pods {
        if err := pl.filterAttachableVolumes(existingPod.Pod, csiNode, false /* existing pod */, attachedVolumes); err != nil { // 过滤掉不可附加的卷
            return framework.AsStatus(err) // 如果有错误，则返回错误状态
        }
    }

    // 统计每个卷的数量
    attachedVolumeCount := map[string]int{}
    for volumeUniqueName, volumeLimitKey := range attachedVolumes {
        // 不要多次计算在多个 pod 中使用的单个卷
        delete(newVolumes, volumeUniqueName)
        attachedVolumeCount[volumeLimitKey]++
    }

    newVolumeCount := map[string]int{}
    for _, volumeLimitKey := range newVolumes {
        newVolumeCount[volumeLimitKey]++
    }

    // 比较卷数量与节点限制，并返回相应状态
    for volumeLimitKey, count := range newVolumeCount {
		maxVolumeLimit, ok := nodeVolumeLimits[v1.ResourceName(volumeLimitKey)]
        // 如果能够获取到，则说明该限制类型的 CSI volume 的数量是有上限的，需要进行检查
		if ok {
			currentVolumeCount := attachedVolumeCount[volumeLimitKey]
			klog.V(5).InfoS("Found plugin volume limits", "node", node.Name, "volumeLimitKey", volumeLimitKey,
				"maxLimits", maxVolumeLimit, "currentVolumeCount", currentVolumeCount, "newVolumeCount", count,
				"pod", klog.KObj(pod))
            // 大于上限不可标度
			if currentVolumeCount+count > int(maxVolumeLimit) {
				return framework.NewStatus(framework.Unschedulable, ErrReasonMaxVolumeCountExceeded)
			}
		}
	}

	return nil
}
```

#### filterAttachableVolumes

```GO
// filterAttachableVolumes 方法过滤 Pod 中的所有 volume，只选择可以附加到 CSI 节点的 volume，并将结果存储在一个 map 中
func (pl *CSILimits) filterAttachableVolumes(
	pod *v1.Pod, csiNode *storagev1.CSINode, newPod bool, result map[string]string) error {
	// 对于 Pod 中的每个 volume
	for _, vol := range pod.Spec.Volumes {
		pvcName := ""      // 用于存储 PersistentVolumeClaim 的名称
		isEphemeral := false  // 用于标记这个 volume 是否是临时的

		// 根据 volume 的类型进行不同的处理
		switch {
		case vol.PersistentVolumeClaim != nil:  // PersistentVolumeClaim 类型的 volume
			// 一般的 CSI volume 必须通过 PersistentVolumeClaim 来使用
			pvcName = vol.PersistentVolumeClaim.ClaimName
		case vol.Ephemeral != nil:  // Ephemeral 类型的 volume
			// 临时的 inline volume 也使用一个 PVC，只是名称是由程序计算得到的，并且具有某些所有权。
			// 在检索到 pvc 对象之后，会在下面检查。
			pvcName = ephemeral.VolumeClaimName(pod, &vol)
			isEphemeral = true
		default:  // Inline Volume 类型的 volume
			// Inline Volume 没有 PVC。需要检查是否为此 inline volume 启用了 CSI 迁移。
			// - 如果 volume 是可迁移的，并且启用了 CSI 迁移，则需要将其计入。
			// - 如果 volume 不可迁移，则将其计入 non_csi 过滤器中。
			if err := pl.checkAttachableInlineVolume(&vol, csiNode, pod, result); err != nil {
				return err
			}
			continue  // 继续下一个 volume 的处理
		}

		// 检查 PVC 名称是否为空
		if pvcName == "" {
			return fmt.Errorf("PersistentVolumeClaim had no name")
		}

		// 从 PersistentVolumeClaim 中检索对象
		pvc, err := pl.pvcLister.PersistentVolumeClaims(pod.Namespace).Get(pvcName)
		if err != nil {
			if newPod {
				// 由于新的 Pod 在没有 PVC 的情况下无法运行，因此必须获取 PVC，以便继续进行调度。
				// 如果无法获取 PVC，则立即返回错误。
				return fmt.Errorf("looking up PVC %s/%s: %v", pod.Namespace, pvcName, err)
			}
			// 如果 PVC 无效，则不统计 volume，因为不能保证它属于运行的 predicate。
			klog.V(5).InfoS("Unable to look up PVC info", "pod", klog.KObj(pod), "PVC", klog.KRef(pod.Namespace, pvcName))
			continue
		}

		// 对于 ephemeral volume，其 PVC 必须由 Pod 拥有。
		if isEphemeral {
			if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {
				return err
			}
		}
		
        // 获取与该 PVC 相关联的 CSI 驱动程序和卷处理程序的名称
		driverName, volumeHandle := pl.getCSIDriverInfo(csiNode, pvc)
		if driverName == "" || volumeHandle == "" {
			klog.V(5).InfoS("Could not find a CSI driver name or volume handle, not counting volume")
			continue
		}

		volumeUniqueName := fmt.Sprintf("%s/%s", driverName, volumeHandle)
        // 获取 CSI 驱动程序的附加限制键，并将卷的唯一名称和附加限制键存储到 result
		volumeLimitKey := volumeutil.GetCSIAttachLimitKey(driverName)
		result[volumeUniqueName] = volumeLimitKey
	}
	return nil
}
```

##### checkAttachableInlineVolume

```GO
// checkAttachableInlineVolume函数会检查一个内联卷是否可以被附加到Pod中，并将卷的唯一名称和附加限制添加到结果map中，只有当该卷可以迁移且此插件的CSI迁移已启用时才会添加。
func (pl *CSILimits) checkAttachableInlineVolume(vol *v1.Volume, csiNode *storagev1.CSINode, pod *v1.Pod, result map[string]string) error {
    // 如果该卷不支持迁移，则直接返回。
    if !pl.translator.IsInlineMigratable(vol) {
        return nil
    }

    // 检查intree provisioner的CSI迁移是否已启用。
    inTreeProvisionerName, err := pl.translator.GetInTreePluginNameFromSpec(nil, vol)
    if err != nil {
        return fmt.Errorf("looking up provisioner name for volume %s: %w", vol.Name, err)
    }

    // 如果CSI迁移未启用，则记录一条日志并返回。
    if !isCSIMigrationOn(csiNode, inTreeProvisionerName) {
        csiNodeName := ""
        if csiNode != nil {
            csiNodeName = csiNode.Name
        }
        klog.V(5).InfoS("CSI Migration is not enabled for provisioner", "provisioner", inTreeProvisionerName,
            "pod", klog.KObj(pod), "csiNode", csiNodeName)
        return nil
    }

    // 将in-tree卷进行翻译。
    translatedPV, err := pl.translator.TranslateInTreeInlineVolumeToCSI(vol, pod.Namespace)
    if err != nil || translatedPV == nil {
        return fmt.Errorf("converting volume(%s) from inline to csi: %w", vol.Name, err)
    }

    // 获取CSI驱动程序名称。
    driverName, err := pl.translator.GetCSINameFromInTreeName(inTreeProvisionerName)
    if err != nil {
        return fmt.Errorf("looking up CSI driver name for provisioner %s: %w", inTreeProvisionerName, err)
    }

    // 如果TranslateInTreeInlineVolumeToCSI没有将内联卷翻译为CSI，则跳过计数。
    if translatedPV.Spec.PersistentVolumeSource.CSI == nil {
        return nil
    }

    // 获取该卷的唯一名称和附加限制，并将它们添加到结果map中。
    volumeUniqueName := fmt.Sprintf("%s/%s", driverName, translatedPV.Spec.PersistentVolumeSource.CSI.VolumeHandle)
    volumeLimitKey := volumeutil.GetCSIAttachLimitKey(driverName)
    result[volumeUniqueName] = volumeLimitKey
    return nil
}
```

##### getCSIDriverInfo

```GO
// getCSIDriverInfo函数返回给定PVC的CSI驱动程序名称和卷ID。
// 如果PVC来自已迁移的内部插件，则此函数将返回插件已迁移到的CSI驱动程序的信息。
func (pl *CSILimits) getCSIDriverInfo(csiNode *storagev1.CSINode, pvc *v1.PersistentVolumeClaim) (string, string) {
    // 获取PVC对应的PV名称
    pvName := pvc.Spec.VolumeName
    if pvName == "" {
        // 如果PVC没有对应的PV名称，尝试从StorageClass获取CSI驱动程序信息
        klog.V(5).InfoS("Persistent volume had no name for claim", "PVC", klog.KObj(pvc))
        return pl.getCSIDriverInfoFromSC(csiNode, pvc)
    }

    // 获取PV信息
    pv, err := pl.pvLister.Get(pvName)
    if err != nil {
        // 如果无法获取与PVC关联的PV，可能是PV已被删除或PVC预绑定到尚未创建的PVC。
        // 回退到使用StorageClass进行卷计数
        klog.V(5).InfoS("Unable to look up PV info for PVC and PV", "PVC", klog.KObj(pvc), "PV", klog.KRef("", pvName))
        return pl.getCSIDriverInfoFromSC(csiNode, pvc)
    }

    // 获取CSI卷源信息
    csiSource := pv.Spec.PersistentVolumeSource.CSI
    if csiSource == nil {
        // 对于非CSI卷和无法迁移的卷，我们进行快速处理
        if !pl.translator.IsPVMigratable(pv) {
            return "", ""
        }

        // 获取内部插件名称
        pluginName, err := pl.translator.GetInTreePluginNameFromSpec(pv, nil)
        if err != nil {
            klog.V(5).InfoS("Unable to look up plugin name from PV spec", "err", err)
            return "", ""
        }

        // 检查该插件是否支持CSI迁移
        if !isCSIMigrationOn(csiNode, pluginName) {
            klog.V(5).InfoS("CSI Migration of plugin is not enabled", "plugin", pluginName)
            return "", ""
        }

        // 将内部卷翻译为CSI卷
        csiPV, err := pl.translator.TranslateInTreePVToCSI(pv)
        if err != nil {
            klog.V(5).InfoS("Unable to translate in-tree volume to CSI", "err", err)
            return "", ""
        }

        if csiPV.Spec.PersistentVolumeSource.CSI == nil {
            klog.V(5).InfoS("Unable to get a valid volume source for translated PV", "PV", pvName)
            return "", ""
        }

        csiSource = csiPV.Spec.PersistentVolumeSource.CSI
    }

    return csiSource.Driver, csiSource.VolumeHandle
}
```

###### getCSIDriverInfoFromSC

```GO
// getCSIDriverInfoFromSC 返回给定 PVC 所属的 StorageClass 的 CSI 驱动程序名称和随机卷 ID。
func (pl *CSILimits) getCSIDriverInfoFromSC(csiNode *storagev1.CSINode, pvc *v1.PersistentVolumeClaim) (string, string) {
    // 获取 PVC 所属的 Namespace、PVC 名称和 StorageClass 名称。
    namespace := pvc.Namespace
    pvcName := pvc.Name
    scName := storagehelpers.GetPersistentVolumeClaimClass(pvc)

    // 如果 StorageClass 没有设置或者未找到，则 PVC 必须使用 immediate binding mode，并在调度前绑定。
    // 因此不计算 PVC，是安全的。
    if scName == "" {
        klog.V(5).InfoS("PVC has no StorageClass", "PVC", klog.KObj(pvc))
        return "", ""
    }

    // 根据 StorageClass 名称获取 StorageClass。
    storageClass, err := pl.scLister.Get(scName)
    if err != nil {
        klog.V(5).InfoS("Could not get StorageClass for PVC", "PVC", klog.KObj(pvc), "err", err)
        return "", ""
    }

    // 使用随机前缀来避免与卷 ID 冲突。
    // 如果在谓词执行期间绑定了 PVC，且在同一节点上有另一个使用相同卷的 Pod，则我们将过多计数该卷，
    // 并将两个卷视为不同的卷。
    volumeHandle := fmt.Sprintf("%s-%s/%s", pl.randomVolumeIDPrefix, namespace, pvcName)

    // 获取 Provisioner，如果 Provisioner 可迁移，则转换为 CSI 驱动程序。
    provisioner := storageClass.Provisioner
    if pl.translator.IsMigratableIntreePluginByName(provisioner) {
        if !isCSIMigrationOn(csiNode, provisioner) {
            klog.V(5).InfoS("CSI Migration of provisioner is not enabled", "provisioner", provisioner)
            return "", ""
        }

        driverName, err := pl.translator.GetCSINameFromInTreeName(provisioner)
        if err != nil {
            klog.V(5).InfoS("Unable to look up driver name from provisioner name", "provisioner", provisioner, "err", err)
            return "", ""
        }
        return driverName, volumeHandle
    }

    return provisioner, volumeHandle
}
```

###### isCSIMigrationOn

```GO
// isCSIMigrationOn 返回一个布尔值，表示某个存储插件是否启用了 CSI 迁移功能。
func isCSIMigrationOn(csiNode *storagev1.CSINode, pluginName string) bool {
    if csiNode == nil || len(pluginName) == 0 {
        return false
    }

    // 如果插件名称为空或 csiNode 为空，返回 false。
    switch pluginName {
    case csilibplugins.AWSEBSInTreePluginName:
        return true
        // 如果是 AWS EBS 存储插件，则返回 true。
    case csilibplugins.PortworxVolumePluginName:
        if !utilfeature.DefaultFeatureGate.Enabled(features.CSIMigrationPortworx) {
            return false
        }
        // 如果是 Portworx 存储插件，需要检查 feature gate 是否启用。
    case csilibplugins.GCEPDInTreePluginName:
        if !utilfeature.DefaultFeatureGate.Enabled(features.CSIMigrationGCE) {
            return false
        }
        // 如果是 GCE PD 存储插件，需要检查 feature gate 是否启用。
    case csilibplugins.AzureDiskInTreePluginName:
        return true
        // 如果是 Azure Disk 存储插件，则返回 true。
    case csilibplugins.CinderInTreePluginName:
        return true
        // 如果是 Cinder 存储插件，则返回 true。
    case csilibplugins.RBDVolumePluginName:
        if !utilfeature.DefaultFeatureGate.Enabled(features.CSIMigrationRBD) {
            return false
        }
        // 如果是 RBD 存储插件，需要检查 feature gate 是否启用。
    default:
        return false
        // 对于其他插件名称，返回 false。
    }

    // 下面的代码用于检查 CSINode 对象的注释是否包含了指定的存储插件名称。
    csiNodeAnn := csiNode.GetAnnotations()
    if csiNodeAnn == nil {
        return false
    }

    var mpaSet sets.Set[string]
    mpa := csiNodeAnn[v1.MigratedPluginsAnnotationKey]
    if len(mpa) == 0 {
        mpaSet = sets.New[string]()
    } else {
        tok := strings.Split(mpa, ",")
        mpaSet = sets.New(tok...)
    }

    return mpaSet.Has(pluginName)
}
```

### EventsToRegister

```GO
// EventsToRegister函数返回可能使该插件无法调度Pod的事件。
func (pl *CSILimits) EventsToRegister() []framework.ClusterEvent {
    // 返回一个包含两个ClusterEvent类型元素的切片
    return []framework.ClusterEvent{
        {Resource: framework.CSINode, ActionType: framework.Add},
        {Resource: framework.Pod, ActionType: framework.Delete},
    }
}
```

## AzureDiskLimits

### 作用

限制Azure磁盘（Azure Disk）的使用量。在Kubernetes中，使用PersistentVolumeClaim（PVC）来申请持久存储。如果PVC绑定到Azure磁盘，则可以在Pod中使用它来存储数据。但是，Azure磁盘在不同的大小和性能层次上都有不同的限制。AzureDiskLimits插件可用于确保Pod使用的Azure磁盘满足要求。

具体来说，AzureDiskLimits插件通过检查Pod中的容器配置和Azure磁盘的限制来判断是否可以将Pod调度到可用的节点上。如果Pod要求的磁盘容量或IOPS（每秒I/O操作数）超过了Azure磁盘的限制，插件将阻止该Pod被调度。

### 结构

```GO
// AzureDiskName是在插件注册表和配置中使用的插件名称常量。
const AzureDiskName = names.AzureDiskLimits

// NewAzureDisk返回一个函数，该函数初始化一个新的插件并返回它。
    func NewAzureDisk(_ runtime.Object, handle framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 获取共享的InformerFactory
    informerFactory := handle.SharedInformerFactory()
    // 创建一个新的非CSI Limits插件，并使用给定的过滤器类型和InformerFactory
    return newNonCSILimitsWithInformerFactory(azureDiskVolumeFilterType, informerFactory, fts), nil
}

// azureDiskVolumeFilterType定义了azureDiskVolumeFilter的过滤器名称。
const azureDiskVolumeFilterType = "AzureDisk"
```

### newNonCSILimitsWithInformerFactory

```go
var _ framework.PreFilterPlugin = &nonCSILimits{}
var _ framework.FilterPlugin = &nonCSILimits{}
var _ framework.EnqueueExtensions = &nonCSILimits{}

// newNonCSILimitsWithInformerFactory返回一个具有过滤器名称和informer factory的插件。
func newNonCSILimitsWithInformerFactory(
    filterName string,
    informerFactory informers.SharedInformerFactory,
    fts feature.Features,
) framework.Plugin {
    // 创建Lister对象，用于获取持久化存储卷、持久化存储卷声明、CSI节点和存储类的信息。
    pvLister := informerFactory.Core().V1().PersistentVolumes().Lister()
    pvcLister := informerFactory.Core().V1().PersistentVolumeClaims().Lister()
    csiNodesLister := informerFactory.Storage().V1().CSINodes().Lister()
    scLister := informerFactory.Storage().V1().StorageClasses().Lister()

    // 创建一个新的非CSI Limits插件，并使用给定的Lister对象和特性对象。
    return newNonCSILimits(filterName, csiNodesLister, scLister, pvLister, pvcLister, fts)
}

// newNonCSILimits 创建一个插件，用于评估 Pod 能否适合基于请求的过滤器匹配的卷的数量以及已经存在的卷。
//
// DEPRECATED
// 此处定义的所有特定于云提供程序的谓词均已被弃用，以支持 CSI 卷限制谓词 - MaxCSIVolumeCountPred。
//
// 谓词查找直接使用的卷和由相关卷支持的 PVC 卷，计算唯一卷的数量，并在总数超过最大值时拒绝新的 Pod。
func newNonCSILimits(
	filterName string,
	csiNodeLister storagelisters.CSINodeLister,
	scLister storagelisters.StorageClassLister,
	pvLister corelisters.PersistentVolumeLister,
	pvcLister corelisters.PersistentVolumeClaimLister,
	fts feature.Features,
) framework.Plugin {
	var filter VolumeFilter         // 声明变量 filter 的类型为 VolumeFilter
	var volumeLimitKey v1.ResourceName   // 声明变量 volumeLimitKey 的类型为 v1.ResourceName
	var name string                 // 声明变量 name 的类型为 string

	// 根据不同的 filterName 类型来分别赋值
	switch filterName {
	case ebsVolumeFilterType:
		name = EBSName
		filter = ebsVolumeFilter
		volumeLimitKey = v1.ResourceName(volumeutil.EBSVolumeLimitKey)
	case gcePDVolumeFilterType:
		name = GCEPDName
		filter = gcePDVolumeFilter
		volumeLimitKey = v1.ResourceName(volumeutil.GCEVolumeLimitKey)
	case azureDiskVolumeFilterType:
		name = AzureDiskName
		filter = azureDiskVolumeFilter
		volumeLimitKey = v1.ResourceName(volumeutil.AzureVolumeLimitKey)
	case cinderVolumeFilterType:
		name = CinderName
		filter = cinderVolumeFilter
		volumeLimitKey = v1.ResourceName(volumeutil.CinderVolumeLimitKey)
	default:
		klog.ErrorS(errors.New("wrong filterName"), "Cannot create nonCSILimits plugin")
		return nil
	}
	pl := &nonCSILimits{
		name:                 name,
		filter:               filter,
		volumeLimitKey:       volumeLimitKey,
		maxVolumeFunc:        getMaxVolumeFunc(filterName),
		csiNodeLister:        csiNodeLister,
		pvLister:             pvLister,
		pvcLister:            pvcLister,
		scLister:             scLister,
		randomVolumeIDPrefix: rand.String(32),
	}

	return pl
}

// Name 返回插件的名称。它在日志等中使用。
func (pl *nonCSILimits) Name() string {
	return pl.name
}
```

#### VolumeFilter

```go
// VolumeFilter 包含了筛选 PD Volume caps 时需要用到的筛选信息。
type VolumeFilter struct {
    // FilterVolume 函数用于过滤正常的 volume。
    FilterVolume func(vol *v1.Volume) (id string, relevant bool)
    // FilterPersistentVolume 函数用于过滤持久化的 volume。
    FilterPersistentVolume func(pv *v1.PersistentVolume) (id string, relevant bool)
    // MatchProvisioner 函数用于判断 StorageClass provisioner 是否与当前条件匹配。
    MatchProvisioner func(sc *storage.StorageClass) (relevant bool)
    // IsMigrated 函数用于返回一个布尔值，指明该插件是否已迁移到 CSI 驱动器。
    IsMigrated func(csiNode *storage.CSINode) bool
}

// 定义 VolumeFilter 结构体变量 ebsVolumeFilter
var ebsVolumeFilter = VolumeFilter{
    // 实现 FilterVolume 方法，用于过滤 v1.Volume 类型的数据
    FilterVolume: func(vol *v1.Volume) (string, bool) {
        if vol.AWSElasticBlockStore != nil {
            return vol.AWSElasticBlockStore.VolumeID, true
        }
        return "", false
    },
    // 实现 FilterPersistentVolume 方法，用于过滤 v1.PersistentVolume 类型的数据
    FilterPersistentVolume: func(pv *v1.PersistentVolume) (string, bool) {
        if pv.Spec.AWSElasticBlockStore != nil {
            return pv.Spec.AWSElasticBlockStore.VolumeID, true
        }
        return "", false
    },
    // 实现 MatchProvisioner 方法，用于匹配 storage.StorageClass 类型的数据中的 Provisioner 字段
    MatchProvisioner: func(sc *storage.StorageClass) bool {
        return sc.Provisioner == csilibplugins.AWSEBSInTreePluginName
    },
    // 实现 IsMigrated 方法，用于判断 csiNode 是否迁移完成
    IsMigrated: func(csiNode *storage.CSINode) bool {
        return isCSIMigrationOn(csiNode, csilibplugins.AWSEBSInTreePluginName)
    },
}

// 定义 VolumeFilter 结构体变量 gcePDVolumeFilter
var gcePDVolumeFilter = VolumeFilter{
    // 实现 FilterVolume 方法，用于过滤 v1.Volume 类型的数据
    FilterVolume: func(vol *v1.Volume) (string, bool) {
        if vol.GCEPersistentDisk != nil {
            return vol.GCEPersistentDisk.PDName, true
        }
        return "", false
    },
    // 实现 FilterPersistentVolume 方法，用于过滤 v1.PersistentVolume 类型的数据
    FilterPersistentVolume: func(pv *v1.PersistentVolume) (string, bool) {
        if pv.Spec.GCEPersistentDisk != nil {
            return pv.Spec.GCEPersistentDisk.PDName, true
        }
        return "", false
    },
    // 实现 MatchProvisioner 方法，用于匹配 storage.StorageClass 类型的数据中的 Provisioner 字段
    MatchProvisioner: func(sc *storage.StorageClass) bool {
        return sc.Provisioner == csilibplugins.GCEPDInTreePluginName
    },
    // 实现 IsMigrated 方法，用于判断 csiNode 是否迁移完成
    IsMigrated: func(csiNode *storage.CSINode) bool {
    	return isCSIMigrationOn(csiNode, csilibplugins.GCEPDInTreePluginName)
	},
}

// azureDiskVolumeFilter 是一个 VolumeFilter，用于过滤 Azure Disk Volumes。
var azureDiskVolumeFilter = VolumeFilter{
    FilterVolume: func(vol *v1.Volume) (string, bool) {
        // 如果 Volume 对象中包含 AzureDisk 字段，则返回 AzureDisk.DiskName 和 true。
        if vol.AzureDisk != nil {
            return vol.AzureDisk.DiskName, true
        }
        // 如果 Volume 对象中不包含 AzureDisk 字段，则返回空字符串和 false。
        return "", false
    },
    FilterPersistentVolume: func(pv *v1.PersistentVolume) (string, bool) {
        // 如果 PersistentVolume 对象中包含 Spec.AzureDisk 字段，则返回 Spec.AzureDisk.DiskName 和 true。
        if pv.Spec.AzureDisk != nil {
            return pv.Spec.AzureDisk.DiskName, true
        }
        // 如果 PersistentVolume 对象中不包含 Spec.AzureDisk 字段，则返回空字符串和 false。
        return "", false
    },

    MatchProvisioner: func(sc *storage.StorageClass) bool {
        // 如果 StorageClass 对象中的 Provisioner 字段等于 csilibplugins.AzureDiskInTreePluginName，则返回 true。
        return sc.Provisioner == csilibplugins.AzureDiskInTreePluginName
    },

    IsMigrated: func(csiNode *storage.CSINode) bool {
        // 调用 isCSIMigrationOn 函数，并传入 csiNode 和 csilibplugins.AzureDiskInTreePluginName 作为参数，返回其结果。
        return isCSIMigrationOn(csiNode, csilibplugins.AzureDiskInTreePluginName)
    },
}

// cinderVolumeFilter 是一个 VolumeFilter，用于过滤 cinder Volumes。
// 它将在从 in-tree 中移除 Openstack cloudprovider 后被弃用。
var cinderVolumeFilter = VolumeFilter{
    FilterVolume: func(vol *v1.Volume) (string, bool) {
        // 如果 Volume 对象中包含 Cinder 字段，则返回 Cinder.VolumeID 和 true。
        if vol.Cinder != nil {
            return vol.Cinder.VolumeID, true
        }
        // 如果 Volume 对象中不包含 Cinder 字段，则返回空字符串和 false。
        return "", false
    },
	FilterPersistentVolume: func(pv *v1.PersistentVolume) (string, bool) {
        // 如果 PersistentVolume 对象中包含 Spec.Cinder 字段，则返回 Spec.Cinder.VolumeID 和 true。
        if pv.Spec.Cinder != nil {
            return pv.Spec.Cinder.VolumeID, true
        }
        // 如果 PersistentVolume 对象中不包含 Spec.Cinder 字段，则返回空字符串和 false。
        return "", false
    },

    MatchProvisioner: func(sc *storage.StorageClass) bool {
        // 如果 StorageClass 对象中的 Provisioner 字段等于 csilibplugins.CinderInTreePluginName，则返回 true。
        return sc.Provisioner == csilibplugins.CinderInTreePluginName
    },

    IsMigrated: func(csiNode *storage.CSINode) bool {
        // 调用 isCSIMigrationOn 函数，并传入 csiNode 和 csilibplugins.CinderInTreePluginName 作为参数，返回其结果。
        return isCSIMigrationOn(csiNode, csilibplugins.CinderInTreePluginName)
    },
}
```

#### getMaxVolumeFunc

```go
// getMaxVolumeFunc 函数返回一个函数，该函数用于获取一个节点的最大 Volume 数量，具体的过滤类型由 filterName 决定。
func getMaxVolumeFunc(filterName string) func(node *v1.Node) int {
    // 返回一个匿名函数，该函数接受一个节点 node 作为参数，返回该节点的最大 Volume 数量。
    return func(node *v1.Node) int {
        // 获取环境变量中的最大 Volume 数量。
        maxVolumesFromEnv := getMaxVolLimitFromEnv()
        if maxVolumesFromEnv > 0 {
            return maxVolumesFromEnv
        }
      	// 从节点的标签中获取节点实例类型。
        var nodeInstanceType string
        for k, v := range node.ObjectMeta.Labels {
            if k == v1.LabelInstanceType || k == v1.LabelInstanceTypeStable {
                nodeInstanceType = v
                break
            }
        }

        // 根据 filterName 的不同值，返回不同的最大 Volume 数量。
        switch filterName {
        case ebsVolumeFilterType:
            return getMaxEBSVolume(nodeInstanceType)
        case gcePDVolumeFilterType:
            return defaultMaxGCEPDVolumes
        case azureDiskVolumeFilterType:
            return defaultMaxAzureDiskVolumes
        case cinderVolumeFilterType:
            return volumeutil.DefaultMaxCinderVolumes
        default:
            return -1
        }
    }
}
```

##### getMaxVolLimitFromEnv

```go
// 从环境变量中获取最大 PD 卷数限制，否则返回默认值。
func getMaxVolLimitFromEnv() int {
    // 读取环境变量 KubeMaxPDVols 的值，赋给 rawMaxVols 变量
    if rawMaxVols := os.Getenv(KubeMaxPDVols); rawMaxVols != "" {
        // 将 rawMaxVols 变量的值转换为整数类型，并赋给 parsedMaxVols 变量
        if parsedMaxVols, err := strconv.Atoi(rawMaxVols); err != nil {
            // 如果转换失败，则输出错误日志，并使用默认值
            klog.ErrorS(err, "Unable to parse maximum PD volumes value, using default")
        // 如果转换成功，继续执行
        } else if parsedMaxVols <= 0 {
            // 如果转换后的值小于等于0，则输出错误日志，并使用默认值
            klog.ErrorS(errors.New("maximum PD volumes is negative"), "Unable to parse maximum PD volumes value, using default")
        } else {
            // 如果转换后的值大于0，则返回该值
            return parsedMaxVols
        }
    }
    // 如果无法从环境变量中获取值，则返回默认值 -1
    return -1
}
```

##### getMaxEBSVolume

```go
// getMaxEBSVolume 函数用于获取指定节点的最大 EBS Volume 数量。
func getMaxEBSVolume(nodeInstanceType string) int {
    // 判断节点是否支持 EBS Nitro 实例类型。
    if ok, _ := regexp.MatchString(volumeutil.EBSNitroLimitRegex, nodeInstanceType); ok {
    	return volumeutil.DefaultMaxEBSNitroVolumeLimit
    }
    // 返回默认的最大 EBS Volume 数量。
    return volumeutil.DefaultMaxEBSVolumes
}
```

### PreFilter&**PreFilterExtensions**

```GO
// PreFilter 在预过滤器扩展点被调用
//
// 如果 Pod 没有这些类型的卷，我们将跳过过滤器阶段
func (pl *nonCSILimits) PreFilter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 获取 Pod 的所有卷
    volumes := pod.Spec.Volumes
    // 遍历所有卷
    for i := range volumes {
        vol := &volumes[i]
        // 使用过滤器检查该卷是否应该被过滤
        _, ok := pl.filter.FilterVolume(vol)
        // 如果该卷应该被过滤或者该卷是一个持久卷或临时卷，那么跳过 Filter 阶段
        if ok || vol.PersistentVolumeClaim != nil || vol.Ephemeral != nil {
        	return nil, nil
        }
    }

    // 返回 nil，表示不需要进行其他过滤器扩展点的处理，且该 Pod 可以进入 Filter 阶段
    return nil, framework.NewStatus(framework.Skip)
}

// PreFilterExtensions 返回预过滤器扩展点，即 Pod 的添加和移除
func (pl *nonCSILimits) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

### Filter

```GO
// 在过滤器扩展点处调用的过滤器。
func (pl *nonCSILimits) Filter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 如果一个Pod没有任何存储卷附加到它上面，谓词将始终为真。
    // 因此，我们对其进行快速路径处理，以避免在这种情况下进行不必要的计算。
    if len(pod.Spec.Volumes) == 0 {
    	return nil // 如果Pod没有存储卷，则直接返回 nil。
    }
    newVolumes := sets.New[string]()
    if err := pl.filterVolumes(pod, true /* new pod */, newVolumes); err != nil {
        return framework.AsStatus(err)
    }

    // 快速返回
    if len(newVolumes) == 0 {
        return nil
    }

    node := nodeInfo.Node()
    if node == nil {
        return framework.NewStatus(framework.Error, "node not found") // 节点不存在，返回错误。
    }

    var csiNode *storage.CSINode
    var err error
    if pl.csiNodeLister != nil {
        csiNode, err = pl.csiNodeLister.Get(node.Name)
        if err != nil {
            // 我们不在这里失败，因为 CSINode 对象仅用于确定迁移是否启用。
            klog.V(5).InfoS("Could not get a CSINode object for the node", "node", klog.KObj(node), "err", err) // 日志记录
        }
    }

    // 如果插件已迁移到 CSI 驱动程序，则转而使用 CSI 谓词。
    if pl.filter.IsMigrated(csiNode) {
        return nil
    }

    // 计算唯一的存储卷数量
    existingVolumes := sets.New[string]()
    for _, existingPod := range nodeInfo.Pods {
        if err := pl.filterVolumes(existingPod.Pod, false /* existing pod */, existingVolumes); err != nil {
            return framework.AsStatus(err)
        }
    }
    numExistingVolumes := len(existingVolumes)

    // 过滤掉已经挂载的存储卷
    for k := range existingVolumes {
        delete(newVolumes, k)
    }

    numNewVolumes := len(newVolumes)
    maxAttachLimit := pl.maxVolumeFunc(node) // 获取节点的最大挂载数量
    volumeLimits := volumeLimits(nodeInfo)
    if maxAttachLimitFromAllocatable, ok := volumeLimits[pl.volumeLimitKey]; ok {
        maxAttachLimit = int(maxAttachLimitFromAllocatable) // 如果节点分配的资源中指定了最大挂载数量，那么将其设为节点的最大挂载数量。
    }

    if numExistingVolumes+numNewVolumes > maxAttachLimit {
        return framework.NewStatus(framework.Unschedulable, ErrReasonMaxVolumeCountExceeded) // 如果超过了节点的最大挂载数量，返回错误。
    }
    return nil // 如果未超过节点的最大挂载数量，则返回 nil。
}
```

#### filterVolumes

```GO
func (pl *nonCSILimits) filterVolumes(pod *v1.Pod, newPod bool, filteredVolumes sets.Set[string]) error {
	// 获取 Pod 的所有 Volumes
	volumes := pod.Spec.Volumes
	// 遍历 Volumes
	for i := range volumes {
		// 获取第 i 个 Volume
		vol := &volumes[i]
		// 如果该 Volume 不符合过滤条件，则跳过
		if id, ok := pl.filter.FilterVolume(vol); ok {
			filteredVolumes.Insert(id)
			continue
		}

		pvcName := ""
		isEphemeral := false
		switch {
		// 如果 Volume 是一个持久化 Volume
		case vol.PersistentVolumeClaim != nil:
			// 获取该 Volume 对应的 PVC 的名称
			pvcName = vol.PersistentVolumeClaim.ClaimName
		// 如果 Volume 是一个临时 Volume
		case vol.Ephemeral != nil:
			// 生成一个与该 Volume 相关的 PVC 的名称
			// 在后面的代码中会根据这个 PVC 的名称获取相应的 PVC 对象
			pvcName = ephemeral.VolumeClaimName(pod, vol)
			// 标记该 Volume 为临时 Volume
			isEphemeral = true
		// 如果 Volume 既不是持久化 Volume 也不是临时 Volume，则跳过
		default:
			continue
		}
		// 如果 PVC 的名称为空，则返回一个错误
		if pvcName == "" {
			return fmt.Errorf("PersistentVolumeClaim had no name")
		}

		// 生成一个假的 Volume ID
		pvID := fmt.Sprintf("%s-%s/%s", pl.randomVolumeIDPrefix, pod.Namespace, pvcName)

		// 获取对应 PVC 的对象
		pvc, err := pl.pvcLister.PersistentVolumeClaims(pod.Namespace).Get(pvcName)
		if err != nil {
			// 如果是新 Pod，并且 PVC 不存在，则无法调度该 Pod，返回一个错误
			if newPod {
				return fmt.Errorf("looking up PVC %s/%s: %v", pod.Namespace, pvcName, err)
			}
			// 如果 PVC 不存在或无效，则跳过该 Volume 的处理
			klog.V(4).InfoS("Unable to look up PVC info, assuming PVC doesn't match predicate when counting limits", "pod", klog.KObj(pod), "PVC", klog.KRef(pod.Namespace, pvcName), "err", err)
			continue
		}

		// 如果是临时 Volume，则需要检查 PVC 是否属于该 Pod 所有
		if isEphemeral {
			if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {
				return err
			}
		}

		// 获取该 PVC 对应的 PV 的名称
		pvName := pvc.Spec.VolumeName
		if pvName == "" {
			// PVC未绑定。它可能已被删除并重新创建，或者被管理员强制解除绑定。
            // Pod仍然可以使用其绑定的原始PV，因此，如果该卷属	于正在运行的谓词，则计算该卷。
			if pl.matchProvisioner(pvc) {
				klog.V(4).InfoS("PVC is not bound, assuming PVC matches predicate when counting limits", "pod", klog.KObj(pod), "PVC", klog.KRef(pod.Namespace, pvcName))
				filteredVolumes.Insert(pvID)
			}
			continue
		}

		pv, err := pl.pvLister.Get(pvName)
		if err != nil {
			// 如果PV无效且PVC属于正在运行的谓词，则记录错误并将PV计入PV限制。
			if pl.matchProvisioner(pvc) {
				klog.V(4).InfoS("Unable to look up PV, assuming PV matches predicate when counting limits", "pod", klog.KObj(pod), "PVC", klog.KRef(pod.Namespace, pvcName), "PV", klog.KRef("", pvName), "err", err)
				filteredVolumes.Insert(pvID)
			}
			continue
		}

		if id, ok := pl.filter.FilterPersistentVolume(pv); ok {
			filteredVolumes.Insert(id)
		}
	}

	return nil
}
```

##### matchProvisioner

```go
// matchProvisioner helps identify if the given PVC belongs to the running predicate.
// matchProvisioner 帮助判断给定的 PVC 是否属于当前的筛选器。
func (pl *nonCSILimits) matchProvisioner(pvc *v1.PersistentVolumeClaim) bool {
    // If the PVC doesn't have a storage class, it can't belong to the running predicate.
    // 如果 PVC 没有存储类，则不能属于当前的筛选器。
    if pvc.Spec.StorageClassName == nil {
        return false
    }

    // Try to fetch the StorageClass object that corresponds to the PVC's storage class.
    // 尝试获取与 PVC 存储类对应的 StorageClass 对象。
    storageClass, err := pl.scLister.Get(*pvc.Spec.StorageClassName)
    if err != nil || storageClass == nil {
        // If there is an error fetching the StorageClass object, or if the object doesn't exist,
        // then the PVC can't belong to the running predicate.
        // 如果获取 StorageClass 对象时出错，或者对象不存在，则 PVC 不能属于当前的筛选器。
        return false
    }

    // If the filter's provisioner matches the storage class's provisioner, then the PVC belongs to the running predicate.
    // 如果筛选器的 provisioner 与 StorageClass 的 provisioner 匹配，则 PVC 属于当前的筛选器。
    return pl.filter.MatchProvisioner(storageClass)
}
```

#### volumeLimits

```go
// volumeLimits函数返回与节点相关的卷资源限制。
func volumeLimits(n *framework.NodeInfo) map[v1.ResourceName]int64 {
    // 初始化一个空的map，用于存储卷资源限制。
    volumeLimits := map[v1.ResourceName]int64{}
    // 遍历节点的可分配资源，过滤出卷资源。
    for k, v := range n.Allocatable.ScalarResources {
        if v1helper.IsAttachableVolumeResourceName(k) {
            volumeLimits[k] = v
        }
    }
    return volumeLimits
}
```

### EventsToRegister

```go
// EventsToRegister返回可能使该插件无法调度Pod失败的可能事件。
func (pl *nonCSILimits) EventsToRegister() []framework.ClusterEvent {
    // 返回一个包含两个元素的切片，每个元素都是一个ClusterEvent类型的结构体，
    // 分别指定了资源类型和操作类型。
    return []framework.ClusterEvent{
        {Resource: framework.Node, ActionType: framework.Add},
        {Resource: framework.Pod, ActionType: framework.Delete},
    }
}
```

## CinderLimits

### 作用

限制OpenStack Cinder卷（OpenStack Cinder Volume）的使用量。在Kubernetes中，使用PersistentVolumeClaim（PVC）来申请持久存储。如果PVC绑定到OpenStack Cinder卷，则可以在Pod中使用它来存储数据。但是，OpenStack Cinder卷在不同的大小和性能层次上都有不同的限制。CinderLimits插件可用于确保Pod使用的OpenStack Cinder卷满足要求。

### 结构

```GO
// CinderName 是插件在插件注册表和配置中使用的名称。
const CinderName = names.CinderLimits

// NewCinder 返回一个函数，该函数初始化一个新的插件并将其返回。
func NewCinder(_ runtime.Object, handle framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 获取 shared informer 工厂
    informerFactory := handle.SharedInformerFactory()
    // 使用 cinderVolumeFilterType 和 informerFactory 创建一个新的非 CSI volume 插件，并返回该插件。
    return newNonCSILimitsWithInformerFactory(cinderVolumeFilterType, informerFactory, fts), nil
}
```

## EBSLimits

### 作用

限制Amazon Elastic Block Store（EBS）卷的使用量。在Kubernetes中，使用PersistentVolumeClaim（PVC）来申请持久存储。如果PVC绑定到Amazon Elastic Block Store（EBS）卷，则可以在Pod中使用它来存储数据。但是，EBS卷在不同的大小和性能层次上都有不同的限制。EBSLimits插件可用于确保Pod使用的EBS卷满足要求。

### 结构

```GO
// EBSName 是插件在插件注册表和配置中使用的名称。
const EBSName = names.EBSLimits

// NewEBS 返回一个函数，该函数初始化一个新插件并返回它。
// _ 表示不使用此参数。
func NewEBS(_ runtime.Object, handle framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 获取共享 InformerFactory 对象。
    informerFactory := handle.SharedInformerFactory()
    // 使用 InformerFactory 创建新的插件，并返回它。
    return newNonCSILimitsWithInformerFactory(ebsVolumeFilterType, informerFactory, fts), nil
}
```

## GCEPDLimits

### 作用

限制Google Compute Engine持久磁盘（Google Compute Engine Persistent Disk）的使用量。在Kubernetes中，使用PersistentVolumeClaim（PVC）来申请持久存储。如果PVC绑定到Google Compute Engine持久磁盘，则可以在Pod中使用它来存储数据。但是，Google Compute Engine持久磁盘在不同的大小和性能层次上都有不同的限制。GCEPDLimits插件可用于确保Pod使用的Google Compute Engine持久磁盘满足要求。

### 结构

```go
// GCEPDName 是插件在插件注册表和配置中使用的名称。
const GCEPDName = names.GCEPDLimits

// NewGCEPD 返回一个函数，该函数初始化一个新插件并返回它。
// _ 表示不使用此参数。
func NewGCEPD(_ runtime.Object, handle framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 获取共享 InformerFactory 对象。
    informerFactory := handle.SharedInformerFactory()
    // 使用 InformerFactory 创建新的插件，并返回它。
    return newNonCSILimitsWithInformerFactory(gcePDVolumeFilterType, informerFactory, fts), nil
}
```

