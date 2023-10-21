
## PodTopologySpread

### 作用

在集群中的不同拓扑域（Topology Domain）之间平衡Pod的分布。

在Kubernetes集群中，节点可以被分组到拓扑域中，例如机架、区域或数据中心。这些拓扑域可能会有不同的硬件限制或故障域，因此在不同的拓扑域之间平衡Pod的分布可以提高集群的可靠性和稳定性。

PodTopologySpread插件可以通过在不同的拓扑域之间分散Pod的调度来实现这一目标。具体来说，它可以通过以下两种方式来平衡Pod的分布：

1. 在不同的拓扑域中选择合适的节点。例如，在一个由三个机架组成的集群中，PodTopologySpread可以确保Pod被分配到每个机架中的节点，而不是只集中在某一个机架中。
2. 在同一拓扑域中选择合适的节点。例如，在一个由三个区域组成的集群中，PodTopologySpread可以确保Pod被分配到每个区域中的节点，而不是只集中在某一个区域中。

通过使用PodTopologySpread插件，管理员可以有效地平衡Pod的分布，从而提高集群的可靠性和稳定性。

### 结构

```GO
// PodTopologySpread is a plugin that ensures pod's topologySpreadConstraints is satisfied.
type PodTopologySpread struct {
    // 标识该插件是否被系统默认启用
    systemDefaulted bool
    // 并行执行器
    parallelizer parallelize.Parallelizer
    // 默认的 TopologySpreadConstraint 列表
    defaultConstraints []v1.TopologySpreadConstraint
    // 共享列表
    sharedLister framework.SharedLister
    // Service 列表
    services corelisters.ServiceLister
    // ReplicationController 列表
    replicationCtrls corelisters.ReplicationControllerLister
    // ReplicaSet 列表
    replicaSets appslisters.ReplicaSetLister
    // StatefulSet 列表
    statefulSets appslisters.StatefulSetLister
    // 是否启用 PodTopologySpread 中的 MinDomains
    enableMinDomainsInPodTopologySpread bool
    // 是否启用 PodTopologySpread 中的 NodeInclusionPolicy
    enableNodeInclusionPolicyInPodTopologySpread bool
    // 是否启用 PodTopologySpread 中的 MatchLabelKeys
    enableMatchLabelKeysInPodTopologySpread bool
}

// 实现了 framework.PreFilterPlugin 接口
var _ framework.PreFilterPlugin = &PodTopologySpread{}
// 实现了 framework.FilterPlugin 接口
var _ framework.FilterPlugin = &PodTopologySpread{}
// 实现了 framework.PreScorePlugin 接口
var _ framework.PreScorePlugin = &PodTopologySpread{}
// 实现了 framework.ScorePlugin 接口
var _ framework.ScorePlugin = &PodTopologySpread{}
// 实现了 framework.EnqueueExtensions 接口
var _ framework.EnqueueExtensions = &PodTopologySpread{}

// Name 是插件在插件注册表和配置中使用的名称
const Name = names.PodTopologySpread

// 实现了 framework.Plugin 接口中的 Name() 方法，返回插件的名称
func (pl *PodTopologySpread) Name() string {
    return Name
}

// New initializes a new plugin and returns it.
func New(plArgs runtime.Object, h framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 检查是否存在 SnapshotSharedLister
    if h.SnapshotSharedLister() == nil {
        return nil, fmt.Errorf("SnapshotSharedlister is nil")
    }
    // 从参数中获取 PodTopologySpreadArgs 对象
    args, err := getArgs(plArgs)
    if err != nil {
        return nil, err
    }
    // 校验 PodTopologySpread 参数是否合法
    if err := validation.ValidatePodTopologySpreadArgs(nil, &args); err != nil {
        return nil, err
    }
    // 创建 PodTopologySpread 对象
    pl := &PodTopologySpread{
        parallelizer: h.Parallelizer(),
        sharedLister: h.SnapshotSharedLister(),
        defaultConstraints: args.DefaultConstraints,
        enableMinDomainsInPodTopologySpread: fts.EnableMinDomainsInPodTopologySpread,
        enableNodeInclusionPolicyInPodTopologySpread: fts.EnableNodeInclusionPolicyInPodTopologySpread,
        enableMatchLabelKeysInPodTopologySpread: fts.EnableMatchLabelKeysInPodTopologySpread,
    }
    // 如果 DefaultingType 为 SystemDefaulting，则使用系统默认的 TopologySpreadConstraint 列表
    if args.DefaultingType == config.SystemDefaulting {
        pl.defaultConstraints = systemDefaultConstraints
        pl.systemDefaulted = true
    }
    // 如果 defaultConstraints 不为空，就需要设置对应的 SharedInformerFactory
    if len(pl.defaultConstraints) != 0 {
        if h.SharedInformerFactory() == nil {
            return nil, fmt.Errorf("SharedInformerFactory is nil")
        }
        pl.setListers(h.SharedInformerFactory())
    }
    // 返回 PodTopologySpread 对象
    return pl, nil
}
```

```GO
// 从参数中获取 PodTopologySpreadArgs 对象
func getArgs(obj runtime.Object) (config.PodTopologySpreadArgs, error) {
    ptr, ok := obj.(*config.PodTopologySpreadArgs)
    if !ok {
        return config.PodTopologySpreadArgs{}, fmt.Errorf("want args to be of type PodTopologySpreadArgs, got %T", obj)
    }
    return *ptr, nil
}

func (pl *PodTopologySpread) setListers(factory informers.SharedInformerFactory) {
	pl.services = factory.Core().V1().Services().Lister()
	pl.replicationCtrls = factory.Core().V1().ReplicationControllers().Lister()
	pl.replicaSets = factory.Apps().V1().ReplicaSets().Lister()
	pl.statefulSets = factory.Apps().V1().StatefulSets().Lister()
}

var systemDefaultConstraints = []v1.TopologySpreadConstraint{
	{
		TopologyKey:       v1.LabelHostname,
		WhenUnsatisfiable: v1.ScheduleAnyway,
		MaxSkew:           3,
	},
	{
		TopologyKey:       v1.LabelTopologyZone,
		WhenUnsatisfiable: v1.ScheduleAnyway,
		MaxSkew:           5,
	},
}
```

### PreFilter&PreFilterExtensions

```GO
// PreFilter 在预过滤器扩展点被调用
func (pl *PodTopologySpread) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
	// 计算预过滤状态
	s, err := pl.calPreFilterState(ctx, pod)
	if err != nil {
		return nil, framework.AsStatus(err)
	}
	// 将预过滤状态写入调度周期状态
	cycleState.Write(preFilterStateKey, s)
	// 返回 nil 表示没有被拒绝，nil 表示没有状态错误
	return nil, nil
}

// PreFilterExtensions 返回预过滤器扩展，包括添加和删除 Pod。
func (pl *PodTopologySpread) PreFilterExtensions() framework.PreFilterExtensions {
	// 返回预过滤器本身作为扩展
	return pl
}

// AddPod 从 cycleState 中预计算的数据中添加 Pod。
func (pl *PodTopologySpread) AddPod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podInfoToAdd *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取 cycleState 中预计算的状态信息
    s, err := getPreFilterState(cycleState)
    if err != nil {
        // 如果获取状态信息失败，则返回一个 framework.Status 类型的错误
        return framework.AsStatus(err)
    }
    // 使用更新节点状态的方法更新状态信息
    pl.updateWithPod(s, podInfoToAdd.Pod, podToSchedule, nodeInfo.Node(), 1)
    // 添加成功，返回 nil
    return nil
}

// RemovePod 从 cycleState 中预计算的数据中移除 Pod。
func (pl *PodTopologySpread) RemovePod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podInfoToRemove *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取 cycleState 中预计算的状态信息
    s, err := getPreFilterState(cycleState)
    if err != nil {
        // 如果获取状态信息失败，则返回一个 framework.Status 类型的错误
        return framework.AsStatus(err)
    }
    // 使用更新节点状态的方法更新状态信息
    pl.updateWithPod(s, podInfoToRemove.Pod, podToSchedule, nodeInfo.Node(), -1)
    // 移除成功，返回 nil
    return nil
}
```

#### calPreFilterState

```go
// calPreFilterState计算preFilterState，描述pod在拓扑上的分布情况。
func (pl *PodTopologySpread) calPreFilterState(ctx context.Context, pod *v1.Pod) (*preFilterState, error) {
    // 获取所有节点的NodeInfo对象。
    allNodes, err := pl.sharedLister.NodeInfos().List()
    if err != nil {
    	return nil, fmt.Errorf("listing NodeInfos: %w", err)
    }
    var constraints []topologySpreadConstraint
    // 获取pod的拓扑分散约束（topologySpreadConstraints）。
    if len(pod.Spec.TopologySpreadConstraints) > 0 {
    // APIServer有功能门控，可以过滤pod的spec，因此只需要检查Constraints的长度而不需要再次检查功能门控。
        constraints, err = pl.filterTopologySpreadConstraints(
        pod.Spec.TopologySpreadConstraints, // 拓扑分散约束
        pod.Labels,
        v1.DoNotSchedule,
    )
    if err != nil {
    	return nil, fmt.Errorf("obtaining pod's hard topology spread constraints: %w", err)
    }
    } else {
        // 如果没有定义pod的拓扑分散约束，就根据pod的特征构建默认的拓扑分散约束。
        constraints, err = pl.buildDefaultConstraints(pod, v1.DoNotSchedule)
        if err != nil {
        	return nil, fmt.Errorf("setting default hard topology spread constraints: %w", err)
        }
    }
    // 如果没有任何拓扑分散约束，则直接返回空preFilterState。
    if len(constraints) == 0 {
    	return &preFilterState{}, nil
    }
    // 初始化preFilterState。
    s := preFilterState{
        Constraints:          constraints, // 拓扑分散约束
        TpKeyToCriticalPaths: make(map[string]*criticalPaths, len(constraints)),
        TpPairToMatchNum:     make(map[topologyPair]int, sizeHeuristic(len(allNodes), constraints)),
    }

    // 统计每个节点上满足约束条件的pod数目，并存储在tpCountsByNode中。
    tpCountsByNode := make([]map[topologyPair]int, len(allNodes))
    requiredNodeAffinity := nodeaffinity.GetRequiredNodeAffinity(pod) // 获取pod所需的节点亲和性（NodeAffinity）。
    logger := klog.FromContext(ctx)
    processNode := func(i int) {
        nodeInfo := allNodes[i]
        node := nodeInfo.Node()
        if node == nil {
            logger.Error(nil, "Node not found")
            return
        }

        // 如果未开启节点包含策略，就只对通过筛选条件的节点应用分散。
        if !pl.enableNodeInclusionPolicyInPodTopologySpread {
            // 忽略解析错误以保持向后兼容性。
            if match, _ := requiredNodeAffinity.Match(node); !match {
                return
            }
        }

        // 确保当前节点的标签包含所有拓扑约束中的topologyKey。
        if !nodeLabelsMatchSpreadConstraints(node.Labels, constraints) {
            return
        }
        
         // 创建一个 map，用于记录每个拓扑对应的 Pod 数量
        tpCounts := make(map[topologyPair]int, len(constraints))
		for _, c := range constraints { // 遍历 PodTopologySpread 约束条件
			if pl.enableNodeInclusionPolicyInPodTopologySpread &&
				!c.matchNodeInclusionPolicies(pod, node, requiredNodeAffinity) {
                     // 如果开启了 Node Inclusion Policy 并且 Pod 不满足约束条件，则跳过此次循环
				continue
			}
			// 创建一个拓扑对，用于记录 pod 在哪个拓扑域上
			pair := topologyPair{key: c.TopologyKey, value: node.Labels[c.TopologyKey]}
            // 计算与 Pod 匹配的 selector 的数量
			count := countPodsMatchSelector(nodeInfo.Pods, c.Selector, pod.Namespace)
            // 将拓扑对和与之匹配的 Pod 数量存储到 tpCounts 中
			tpCounts[pair] = count
		}
        // 记录每个节点上的拓扑对和 Pod 数量的映射关系
		tpCountsByNode[i] = tpCounts
	}
    // 多线程并发执行 processNode 函数，处理所有的节点
	pl.parallelizer.Until(ctx, len(allNodes), processNode, pl.Name())

	for _, tpCounts := range tpCountsByNode {  // 遍历每个节点上的拓扑对和 Pod 数量的映射关系
        for tp, count := range tpCounts {  // 遍历拓扑对和 Pod 数量的映射关系
            s.TpPairToMatchNum[tp] += count  // 将当前拓扑对和与之匹配的 Pod 数量加到 TpPairToMatchNum 中
        }
    }
    if pl.enableMinDomainsInPodTopologySpread {  // 如果开启了最小域数的限制
        s.TpKeyToDomainsNum = make(map[string]int, len(constraints))  // 创建一个 map，用于记录每个拓扑的最小域数
        for tp := range s.TpPairToMatchNum {  // 遍历 TpPairToMatchNum
            s.TpKeyToDomainsNum[tp.key]++  // 将拓扑对的 key 添加到 TpKeyToDomainsNum 中
        }
    }

    // 计算每个拓扑对的最小匹配数
    for i := 0; i < len(constraints); i++ {
        key := constraints[i].TopologyKey
        s.TpKeyToCriticalPaths[key] = newCriticalPaths()  // 创建一个关键路径对象
    }
    for pair, num := range s.TpPairToMatchNum {  // 遍历每个拓扑对和 Pod 数量的映射关系
        s.TpKeyToCriticalPaths[pair.key].update(pair.value, num)  // 更新拓扑对的关键路径
    }

    return &s, nil  // 返回计算后的结果
}
```

##### filterTopologySpreadConstraints

```go
// 过滤并处理符合条件的拓扑约束，返回处理后的拓扑约束列表
func (pl *PodTopologySpread) filterTopologySpreadConstraints(constraints []v1.TopologySpreadConstraint, podLabels map[string]string, action v1.UnsatisfiableConstraintAction) ([]topologySpreadConstraint, error) {
    // 用于存放处理后的拓扑约束
    var result []topologySpreadConstraint
    // 遍历传入的拓扑约束列表
    for _, c := range constraints {
    // 检查该约束的不满足条件是否满足期望的动作
    if c.WhenUnsatisfiable == action {
    // 将 LabelSelector 转换为 SelectorSet 类型，为后续的 Selector 处理做准备
    selector, err := metav1.LabelSelectorAsSelector(c.LabelSelector)
    if err != nil {
        // 如果转换出错，返回错误
        return nil, err
    }
    if pl.enableMatchLabelKeysInPodTopologySpread && len(c.MatchLabelKeys) > 0 {
        // 如果启用了根据标签键匹配进行拓扑约束，且 MatchLabelKeys 不为空
        matchLabels := make(labels.Set)
        // 用于存放要匹配的标签集合
        for _, labelKey := range c.MatchLabelKeys {
            if value, ok := podLabels[labelKey]; ok {
                matchLabels[labelKey] = value
                // 将 Pod 的标签中匹配 MatchLabelKeys 中的标签键的标签加入到 matchLabels 中
            }
        }
        if len(matchLabels) > 0 {
            selector = mergeLabelSetWithSelector(matchLabels, selector)
            // 将 matchLabels 和 Selector 进行合并
        }
    }

    tsc := topologySpreadConstraint{
        MaxSkew:            c.MaxSkew,
        TopologyKey:        c.TopologyKey,
        Selector:           selector,
        MinDomains:         1,                            // 如果 MinDomains 为空，我们将其视为 1。
        NodeAffinityPolicy: v1.NodeInclusionPolicyHonor,  // 如果 NodeAffinityPolicy 为空，我们将其视为 "Honor"。
        NodeTaintsPolicy:   v1.NodeInclusionPolicyIgnore, // 如果 NodeTaintsPolicy 为空，我们将其视为 "Ignore"。
    }
    if pl.enableMinDomainsInPodTopologySpread && c.MinDomains != nil {
        tsc.MinDomains = *c.MinDomains
        // 如果启用了在 Pod 拓扑分散中的最小域计算，并且 MinDomains 不为空，则将 MinDomains 赋值给 tsc.MinDomains。
    }
    if pl.enableNodeInclusionPolicyInPodTopologySpread {
        if c.NodeAffinityPolicy != nil {
            tsc.NodeAffinityPolicy = *c.NodeAffinityPolicy
            // 如果启用了在 Pod 拓扑分散中节点亲和性的策略计算，并且 NodeAffinityPolicy 不为空，则将 NodeAffinityPolicy 赋值给 tsc.NodeAffinityPolicy。
        }
        if c.NodeTaintsPolicy != nil {
					tsc.NodeTaintsPolicy = *c.NodeTaintsPolicy
				}
			}
			result = append(result, tsc)
		}
	}
	return result, nil
}
```

##### buildDefaultConstraints

```GO
// buildDefaultConstraints 函数基于 .DefaultConstraints 和与 pod 匹配的服务、
// 复制控制器、副本集、有状态副本集的选择器构建 pod 的约束。
func (pl *PodTopologySpread) buildDefaultConstraints(p *v1.Pod, action v1.UnsatisfiableConstraintAction) ([]topologySpreadConstraint, error) {
    constraints, err := pl.filterTopologySpreadConstraints(pl.defaultConstraints, p.Labels, action)
    if err != nil || len(constraints) == 0 {
    	return nil, err
    }
    selector := helper.DefaultSelector(p, pl.services, pl.replicationCtrls, pl.replicaSets, pl.statefulSets)
    if selector.Empty() {
    	return nil, nil
    }
    for i := range constraints {
    	constraints[i].Selector = selector
    }
    return constraints, nil
}
```

##### sizeHeuristic

```GO
func sizeHeuristic(nodes int, constraints []topologySpreadConstraint) int {
    for _, c := range constraints { // 遍历所有约束
        if c.TopologyKey == v1.LabelHostname { // 如果约束为按主机名分配
            return nodes // 直接返回节点数
        }
    }
    return 0 // 否则返回 0
}
```

##### nodeLabelsMatchSpreadConstraints

```GO
// nodeLabelsMatchSpreadConstraints checks if ALL topology keys in spread Constraints are present in node labels.
func nodeLabelsMatchSpreadConstraints(nodeLabels map[string]string, constraints []topologySpreadConstraint) bool {
    for _, c := range constraints { // 遍历所有约束
        if _, ok := nodeLabels[c.TopologyKey]; !ok { // 如果节点标签中不包含当前约束的拓扑键
            return false // 直接返回 false
        }
    }
    return true // 否则返回 true
}
```

##### matchNodeInclusionPolicies

```GO
func (tsc *topologySpreadConstraint) matchNodeInclusionPolicies(pod *v1.Pod, node *v1.Node, require nodeaffinity.RequiredNodeAffinity) bool {
    if tsc.NodeAffinityPolicy == v1.NodeInclusionPolicyHonor { // 如果节点亲和性策略为必须遵守
        // 忽略此处的解析错误以保证向后兼容性
        if match, _ := require.Match(node); !match { // 检查节点是否符合亲和性要求
            return false // 如果不符合则返回 false
        }
    }

    if tsc.NodeTaintsPolicy == v1.NodeInclusionPolicyHonor { // 如果节点容忍策略为必须遵守
        if _, untolerated := v1helper.FindMatchingUntoleratedTaint(node.Spec.Taints, pod.Spec.Tolerations, helper.DoNotScheduleTaintsFilterFunc()); untolerated { // 检查 Pod 是否能够容忍当前节点上的所有污点
            return false // 如果不能，则返回 false
        }
    }
    return true // 否则返回 true
}
```

##### countPodsMatchSelector

```GO
// 用于统计符合给定标签选择器条件的 Pod 数量
func countPodsMatchSelector(podInfos []*framework.PodInfo, selector labels.Selector, ns string) int {
	// 如果标签选择器为空，则直接返回 0
	if selector.Empty() {
		return 0
	}
	// 初始化计数器为 0
	count := 0
	// 遍历 PodInfo 数组中的每一个 PodInfo
	for _, p := range podInfos {
		// 忽略正在终止的 Pod（参见 #87621）和不在给定命名空间中的 Pod
		if p.Pod.DeletionTimestamp != nil || p.Pod.Namespace != ns {
			continue
		}
		// 如果 Pod 的标签集合匹配标签选择器，则增加计数器
		if selector.Matches(labels.Set(p.Pod.Labels)) {
			count++
		}
	}
	// 返回符合条件的 Pod 数量
	return count
}
```

##### newCriticalPaths

```GO
func newCriticalPaths() *criticalPaths {
	// 创建一个 criticalPaths 结构体指针，并将其初始值设置为 {{MatchNum: math.MaxInt32}, {MatchNum: math.MaxInt32}}
	return &criticalPaths{{MatchNum: math.MaxInt32}, {MatchNum: math.MaxInt32}}
}
```

#### preFilterState

```GO
// preFilterState 是在 PreFilter 阶段计算并在 Filter 阶段使用的数据结构。
// 它将 TpKeyToCriticalPaths 和 TpPairToMatchNum 组合在一起表示：
// (1) 在每个扩散约束上匹配最少 Pod 的关键路径。
// (2) 每个扩散约束上匹配的 Pod 数量。
// nil 的 preFilterState 表示在 PreFilter 阶段根本没有设置；
// 空的 preFilterState 对象表示它是一个合法状态并且在 PreFilter 阶段被设置。
// 这些字段被导出以便在测试中进行比较。
type preFilterState struct {
    Constraints []topologySpreadConstraint
    // 这里记录了 2 条关键路径，而不是所有关键路径。
    // criticalPaths[0].MatchNum 始终保存最小匹配数量。
    // criticalPaths[1].MatchNum 始终大于或等于 criticalPaths[0].MatchNum，但是它不保证是第二小的匹配数量。
    TpKeyToCriticalPaths map[string]*criticalPaths
    // TpKeyToDomainsNum 以拓扑键为键，以域的数量为值。
    TpKeyToDomainsNum map[string]int
    // TpPairToMatchNum 以拓扑键对为键，以匹配 Pod 的数量为值。
    TpPairToMatchNum map[topologyPair]int
}
```

#### getPreFilterState

```GO
// getPreFilterState fetches a pre-computed preFilterState.
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
    c, err := cycleState.Read(preFilterStateKey) // 从 CycleState 中读取 preFilterState
    if err != nil {
        // preFilterState doesn't exist, likely PreFilter wasn't invoked.
        return nil, fmt.Errorf("reading %q from cycleState: %w", preFilterStateKey, err) // 如果不存在，说明 PreFilter 还未被调用，返回错误
    }

    s, ok := c.(*preFilterState)
    if !ok {
        return nil, fmt.Errorf("%+v convert to podtopologyspread.preFilterState error", c) // 如果读取的 preFilterState 不是期望的类型，则返回错误
    }
    return s, nil // 否则返回读取到的 preFilterState
}
```

### Filter

```GO
// 在过滤器扩展点处调用的过滤器。
func (pl *PodTopologySpread) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取节点对象
    node := nodeInfo.Node()
    if node == nil {
    	return framework.AsStatus(fmt.Errorf("node not found"))
    }
    // 获取之前过滤器处理后的状态，如果有错误则返回错误信息
    s, err := getPreFilterState(cycleState)
    if err != nil {
        return framework.AsStatus(err)
    }

    // 但是，"empty" preFilterState 是合法的，它可以容忍要调度的每个 Pod。
    if len(s.Constraints) == 0 {
        return nil
    }

    logger := klog.FromContext(ctx)
    // 获取 Pod 的标签
    podLabelSet := labels.Set(pod.Labels)
    // 对于每个约束条件，检查是否满足
    for _, c := range s.Constraints {
        tpKey := c.TopologyKey
        // 获取节点上该拓扑域的标签值
        tpVal, ok := node.Labels[c.TopologyKey]
        if !ok {
            logger.V(5).Info("Node doesn't have required label", "node", klog.KObj(node), "label", tpKey)
            return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonNodeLabelNotMatch)
        }

        // 判断标准：
        // '已有匹配数量' + '是否与自身匹配（1 或 0）' - '全局最小值' <= 'maxSkew'
        // 获取最小匹配数量和可能出现的错误
        minMatchNum, err := s.minMatchNum(tpKey, c.MinDomains, pl.enableMinDomainsInPodTopologySpread)
        if err != nil {
            logger.Error(err, "Internal error occurred while retrieving value precalculated in PreFilter", "topologyKey", tpKey, "paths", s.TpKeyToCriticalPaths)
            continue
        }

        selfMatchNum := 0
        if c.Selector.Matches(podLabelSet) {
            selfMatchNum = 1
        }

        pair := topologyPair{key: tpKey, value: tpVal}
        matchNum := 0
        if tpCount, ok := s.TpPairToMatchNum[pair]; ok {
            matchNum = tpCount
        }
        skew := matchNum + selfMatchNum - minMatchNum
        if skew > int(c.MaxSkew) {
            logger.V(5).Info("Node failed spreadConstraint: matchNum + selfMatchNum - minMatchNum > maxSkew", "node", klog.KObj(node), "topologyKey", tpKey, "matchNum", matchNum, "selfMatchNum", selfMatchNum, "minMatchNum", minMatchNum, "maxSkew", c.MaxSkew)
            return framework.NewStatus(framework.Unschedulable, ErrReasonConstraintsNotMatch)
        }
    }

    return nil
}
```

#### minMatchNum

```GO
// minMatchNum returns the global minimum for the calculation of skew while taking MinDomains into account.
func (s *preFilterState) minMatchNum(tpKey string, minDomains int32, enableMinDomainsInPodTopologySpread bool) (int, error) {
    paths, ok := s.TpKeyToCriticalPaths[tpKey] // 从 preFilterState 中获取关键路径
    if !ok {
        return 0, fmt.Errorf("failed to retrieve path by topology key") // 如果获取失败，则返回错误
    }

    minMatchNum := paths[0].MatchNum // 计算全局最小匹配数
    if !enableMinDomainsInPodTopologySpread {
        return minMatchNum, nil // 如果不考虑 MinDomains，则直接返回全局最小匹配数
    }

    domainsNum, ok := s.TpKeyToDomainsNum[tpKey] // 获取与该 topology key 匹配的域的数量
    if !ok {
        return 0, fmt.Errorf("failed to retrieve the number of domains by topology key") // 如果获取失败，则返回错误
    }

    if domainsNum < int(minDomains) {
        // 如果匹配的域的数量小于 MinDomains，则全局最小匹配数为 0
        minMatchNum = 0
    }

    return minMatchNum, nil // 返回计算得到的全局最小匹配数
}
```

### PreScore

```GO
// PreScore 函数构建并写入循环状态，该状态用于 Score 和 NormalizeScore。
func (pl *PodTopologySpread) PreScore(
ctx context.Context, // 上下文
cycleState *framework.CycleState, // 循环状态
pod *v1.Pod, // 待调度的 Pod
filteredNodes []*v1.Node, // 经过过滤后的 Node 列表
) *framework.Status {
    allNodes, err := pl.sharedLister.NodeInfos().List() // 获取所有的 Node
    if err != nil {
    	return framework.AsStatus(fmt.Errorf("getting all nodes: %w", err))
    }
    if len(filteredNodes) == 0 || len(allNodes) == 0 {
        // 没有可供评分的 Node。
        return nil
    }

    state := &preScoreState{
        IgnoredNodes:            sets.New[string](),
        TopologyPairToPodCounts: make(map[topologyPair]*int64),
    }
    // 只有在使用非系统默认的扩散规则时才需要节点具有所有拓扑标签。这允许没有区域标签的节点仍然具有主机名扩散。
    requireAllTopologies := len(pod.Spec.TopologySpreadConstraints) > 0 || !pl.systemDefaulted
    err = pl.initPreScoreState(state, pod, filteredNodes, requireAllTopologies) // 初始化 preScoreState。
    if err != nil {
        return framework.AsStatus(fmt.Errorf("calculating preScoreState: %w", err))
    }

    // 如果 incoming pod 没有 soft topology spread Constraints，则返回。
    if len(state.Constraints) == 0 {
        cycleState.Write(preScoreStateKey, state)
        return nil
    }

    // 忽略向后兼容性的解析错误。
    requiredNodeAffinity := nodeaffinity.GetRequiredNodeAffinity(pod) // 获取 Pod 所需的节点亲和性
    processAllNode := func(i int) {
        nodeInfo := allNodes[i] // 获取第 i 个 NodeInfo
        node := nodeInfo.Node()
        if node == nil {
            return
        }

        if !pl.enableNodeInclusionPolicyInPodTopologySpread {
            // `node` 应满足 incoming pod 的 NodeSelector/NodeAffinity。
            if match, _ := requiredNodeAffinity.Match(node); !match {
                return
            }
        }

        // 所有的 topologyKeys 都需要存在于 `node` 中。
        if requireAllTopologies && !nodeLabelsMatchSpreadConstraints(node.Labels, state.Constraints) {
            return
        }

        for _, c := range state.Constraints {
            if pl.enableNodeInclusionPolicyInPodTopologySpread &&
                !c.matchNodeInclusionPolicies(pod, node, requiredNodeAffinity) {
                continue
            }

            pair := topologyPair{key: c.TopologyKey, value: node.Labels[c.TopologyKey]}
            // 如果当前的拓扑对没有与任何候选节点关联，则继续以避免不必要的计算。
            // 每个节点的计数也会被跳过，因为它们在 Score 时完成。
            tpCount := state.TopologyPairToPodCounts[pair]
            if tpCount == nil {
                continue
            }
             // 计算与 Pod 匹配的 selector 的数量
            count := countPodsMatchSelector(nodeInfo.Pods, c.Selector, pod.Namespace)
			atomic.AddInt64(tpCount, int64(count))
		}
	}
    // 并发执行
	pl.parallelizer.Until(ctx, len(allNodes), processAllNode, pl.Name())

	cycleState.Write(preScoreStateKey, state)
	return nil
}
```

#### initPreScoreState

```GO
// initPreScoreState函数遍历“filteredNodes”以过滤掉不具有所需拓扑关键字的节点，并初始化：
// 1）s.TopologyPairToPodCounts：以符合条件的拓扑对和节点名称为键。
// 2）s.IgnoredNodes：不应得分的节点集合。
// 3）s.TopologyNormalizingWeight：基于拓扑中值的数量为每个约束赋予的权重。
func (pl *PodTopologySpread) initPreScoreState(s *preScoreState, pod *v1.Pod, filteredNodes []*v1.Node, requireAllTopologies bool) error {
    // 初始化Constraints，包含要匹配的拓扑限制条件。
    var err error
    if len(pod.Spec.TopologySpreadConstraints) > 0 {
        s.Constraints, err = pl.filterTopologySpreadConstraints(
            pod.Spec.TopologySpreadConstraints,
            pod.Labels,
            v1.ScheduleAnyway,
        )
        if err != nil {
        	return fmt.Errorf("obtaining pod's soft topology spread constraints: %w", err)
        }
    } else {
    	s.Constraints, err = pl.buildDefaultConstraints(pod, v1.ScheduleAnyway)
        if err != nil {
        	return fmt.Errorf("setting default soft topology spread constraints: %w", err)
        }
    }
    // 如果没有需要匹配的拓扑限制条件，则返回nil。
    if len(s.Constraints) == 0 {
        return nil
    }

    // 计算要匹配的拓扑限制条件的大小，以及符合条件的节点的数量。
    topoSize := make([]int, len(s.Constraints))
    for _, node := range filteredNodes {
        if requireAllTopologies && !nodeLabelsMatchSpreadConstraints(node.Labels, s.Constraints) {
            // 当后续进行评分时，没有所有所需的拓扑关键字的节点将被忽略。
            s.IgnoredNodes.Insert(node.Name)
            continue
        }
        for i, constraint := range s.Constraints {
            // 每个节点的计数在Score中进行计算。
            if constraint.TopologyKey == v1.LabelHostname {
                continue
            }
            pair := topologyPair{key: constraint.TopologyKey, value: node.Labels[constraint.TopologyKey]}
            if s.TopologyPairToPodCounts[pair] == nil {
                s.TopologyPairToPodCounts[pair] = new(int64)
                topoSize[i]++
            }
        }
    }

    // 计算每个拓扑限制条件的权重。
    s.TopologyNormalizingWeight = make([]float64, len(s.Constraints))
    for i, c := range s.Constraints {
        sz := topoSize[i]
        if c.TopologyKey == v1.LabelHostname {
            sz = len(filteredNodes) - len(s.IgnoredNodes)
        }
        s.TopologyNormalizingWeight[i] = topologyNormalizingWeight(sz)
    }
    return nil
}
```

##### topologyNormalizingWeight

```GO
// topologyNormalizingWeight 计算拓扑结构的权重，基于拓扑结构中存在的值的数量。
// 由于<size>至少为1（通过筛选的所有节点都在相同的拓扑结构中），且k8s支持5k个节点，
// 因此结果在区间<1.09，8.52>之间。
//
// 注意: 当没有节点具有所需的拓扑结构时，<size>也可能为零，
// 但是我们在这种情况下不关心拓扑权重，因为我们为所有节点返回0分。
func topologyNormalizingWeight(size int) float64 {
	return math.Log(float64(size + 2))
}
```

#### preScoreState

```GO
// preScoreState 在 PreScore 阶段计算，在 Score 阶段使用。
// Fields are exported for comparison during testing.
type preScoreState struct {
    Constraints []topologySpreadConstraint
    // IgnoredNodes 是一个节点名称的集合，它缺少一些 Constraints[*].topologyKey。
    IgnoredNodes sets.Set[string]
    // TopologyPairToPodCounts 键入 topologyPair，其值为匹配的 Pod 数量。
    TopologyPairToPodCounts map[topologyPair]*int64
    // TopologyNormalizingWeight 是我们给予每个拓扑的权重。
    // 这允许较小拓扑的 Pod 数量不被较大拓扑所稀释。
    TopologyNormalizingWeight []float64
}
```

### Score&ScoreExtensions

```GO
// Score 函数会在 Score 扩展点调用。
// 函数返回的 "score" 是在 `nodeName` 上匹配的 Pod 数量，稍后会进行规范化。
func (pl *PodTopologySpread) Score(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	// 获取 nodeName 对应的 NodeInfo
	nodeInfo, err := pl.sharedLister.NodeInfos().Get(nodeName)
	if err != nil {
		return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
	}

	// 获取 Node 对象和 ScoreState 对象
	node := nodeInfo.Node()
	s, err := getPreScoreState(cycleState)
	if err != nil {
		return 0, framework.AsStatus(err)
	}

	// 如果节点不符合要求，直接返回 0
	if s.IgnoredNodes.Has(node.Name) {
		return 0, nil
	}

	// 对于每个存在的 <pair>，当前节点都会得到 <matchSum> 的信用。
	// 最终将所有 <matchSum> 相加并返回作为该节点的得分。
	var score float64
	for i, c := range s.Constraints {
		if tpVal, ok := node.Labels[c.TopologyKey]; ok {
			var cnt int64
			if c.TopologyKey == v1.LabelHostname {
				// 如果 topologyKey 是 hostname，则通过 countPodsMatchSelector 函数计算匹配 Pod 数量。
				cnt = int64(countPodsMatchSelector(nodeInfo.Pods, c.Selector, pod.Namespace))
			} else {
				// 如果 topologyKey 不是 hostname，则获取对应的 topologyPair，通过 TopologyPairToPodCounts 映射获取匹配 Pod 数量。
				pair := topologyPair{key: c.TopologyKey, value: tpVal}
				cnt = *s.TopologyPairToPodCounts[pair]
			}
			// 根据匹配 Pod 数量、最大偏差值和 topologyNormalizingWeight 计算当前 topologyKey 对当前节点的得分贡献。
			score += scoreForCount(cnt, c.MaxSkew, s.TopologyNormalizingWeight[i])
		}
	}
	// 对得分进行四舍五入并返回。
	return int64(math.Round(score)), nil
}

// ScoreExtensions of the Score plugin.
// ScoreExtensions 函数返回 Score 插件自身。
func (pl *PodTopologySpread) ScoreExtensions() framework.ScoreExtensions {
	return pl
}

// NormalizeScore 方法在对所有节点进行打分后调用。
func (pl *PodTopologySpread) NormalizeScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
    // 获取 getPreScoreState 返回的 s 和可能发生的错误。
    s, err := getPreScoreState(cycleState)
    if err != nil {
    	return framework.AsStatus(err)
    }
    if s == nil {
    	return nil
    }
    // 计算 <minScore> 和 <maxScore>。
    var minScore int64 = math.MaxInt64
    var maxScore int64
    for i, score := range scores {
        // 必须检查 score.Name 是否在 IgnoredNodes 中。
        if s.IgnoredNodes.Has(score.Name) {
            scores[i].Score = invalidScore
            continue
        }
        if score.Score < minScore {
            minScore = score.Score
        }
        if score.Score > maxScore {
            maxScore = score.Score
        }
    }

    // 根据 <minScore> 和 <maxScore> 对所有得分进行归一化。
    for i := range scores {
        if scores[i].Score == invalidScore {
            scores[i].Score = 0
            continue
        }
        if maxScore == 0 {
            scores[i].Score = framework.MaxNodeScore
            continue
        }
        s := scores[i].Score
        scores[i].Score = framework.MaxNodeScore * (maxScore + minScore - s) / maxScore
    }
    return nil
}
```

#### getPreScoreState

```GO
func getPreScoreState(cycleState *framework.CycleState) (*preScoreState, error) {
	c, err := cycleState.Read(preScoreStateKey)
	if err != nil {
		return nil, fmt.Errorf("error reading %q from cycleState: %w", preScoreStateKey, err)
	}

	s, ok := c.(*preScoreState)
	if !ok {
		return nil, fmt.Errorf("%+v  convert to podtopologyspread.preScoreState error", c)
	}
	return s, nil
}
```

#### scoreForCount

```GO
// scoreForCount 函数基于拓扑域中匹配 pod 数量、约束的 maxSkew 和拓扑权重计算得分。
// maxSkew-1 被添加到得分中，以便减轻拓扑域之间的差异，控制得分对偏差的容忍度。
func scoreForCount(cnt int64, maxSkew int32, tpWeight float64) float64 {
	return float64(cnt)*tpWeight + float64(maxSkew-1)
}
```

### PodTopologySpread

```GO
// EventsToRegister 返回可能使由该插件导致的 Pod 失败的事件可调度。
func (pl *PodTopologySpread) EventsToRegister() []framework.ClusterEvent {
	return []framework.ClusterEvent{
        // ActionType 包括以下事件：
        // - Add. 一个无法调度的 Pod 可能由于违反拓扑传播约束而失败，
        // 添加一个已分配的 Pod 可能使其可调度。
        // - Update. 更新现有 Pod 的标签（例如，删除标签）可能会使一个无法调度的 Pod 可调度。
        // - Delete. 一个无法调度的 Pod 可能由于违反现有 Pod 的拓扑传播约束而失败，
        // 删除现有 Pod 可能使其可调度。
        {Resource: framework.Pod, ActionType: framework.All},
        // Node add|delete|updateLabel 可能导致拓扑键发生更改，
        // 并使这些 Pod 在调度时可调度或不可调度。
        {Resource: framework.Node, ActionType: framework.Add | framework.Delete | framework.UpdateNodeLabel},
	}
```

## SchedulingGates

### 作用

Kubernetes中的SchedulingGates插件是一个Beta级别的插件，它允许用户为Pods设置条件，在这些条件满足之前，这些Pods将不会被调度到节点上。这个插件可以帮助用户实现一些高级调度策略，比如等待资源的可用性或者等待其他Pods完成等。

### 结构

```GO
// 插件在插件注册表和配置中的名称
const Name = names.SchedulingGates

// SchedulingGates 检查一个 Pod 是否携带 .spec.schedulingGates
type SchedulingGates struct {
	enablePodSchedulingReadiness bool
}

// 确保 SchedulingGates 实现了 PreEnqueuePlugin 和 EnqueueExtensions 接口
var _ framework.PreEnqueuePlugin = &SchedulingGates{}
var _ framework.EnqueueExtensions = &SchedulingGates{}

// 返回插件的名称
func (pl *SchedulingGates) Name() string {
	return Name
}

// 初始化一个新的插件并返回它
func New(_ runtime.Object, _ framework.Handle, fts feature.Features) (framework.Plugin, error) {
	return &SchedulingGates{enablePodSchedulingReadiness: fts.EnablePodSchedulingReadiness}, nil
}
```

### PreEnqueue

```GO
// 定义函数 PreEnqueue，它属于类型 SchedulingGates 的方法，接收一个 context.Context 类型的上下文对象和一个 *v1.Pod 类型的指针作为参数，返回一个 *framework.Status 类型的指针。
func (pl *SchedulingGates) PreEnqueue(ctx context.Context, p *v1.Pod) *framework.Status {
    // 如果不开启 Pod 调度准备状态检查或者 Pod 的 SchedulingGates 字段为空，则直接返回 nil。
    if !pl.enablePodSchedulingReadiness || len(p.Spec.SchedulingGates) == 0 {
    	return nil
    }
    // 定义一个字符串类型的数组 gates，用于存储 Pod 的 SchedulingGates 名称。
    var gates []string
    // 遍历 Pod 的 SchedulingGates，将每个 SchedulingGates 的名称添加到 gates 数组中。
    for _, gate := range p.Spec.SchedulingGates {
    	gates = append(gates, gate.Name)
    }
    // 返回一个 *framework.Status 类型的指针，状态为 UnschedulableAndUnresolvable，消息内容为等待调度门：gates。
    return framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("waiting for scheduling gates: %v", gates))
    }
}
```

### EventsToRegister

```GO
// 定义函数 EventsToRegister，它属于类型 SchedulingGates 的方法，返回一个 framework.ClusterEvent 类型的切片。
func (pl *SchedulingGates) EventsToRegister() []framework.ClusterEvent {
    // 返回一个 framework.ClusterEvent 类型的切片，其中仅包含一个元素，元素的 Resource 字段为 framework.Pod，ActionType 字段为 framework.Update。
    return []framework.ClusterEvent{
    	{Resource: framework.Pod, ActionType: framework.Update},
    }
}
```

## SelectorSpread

### 作用

将Pods均匀地分布在集群中的节点上，以避免单个节点上负载过重，而其他节点却处于空闲状态的情况。这个插件可以帮助用户实现负载均衡的目标，从而提高整个集群的稳定性和可靠性。

当用户创建一个Deployment、StatefulSet或者ReplicaSet时，SelectorSpread插件会根据用户指定的Pod标签选择器，计算每个节点上已经存在的、符合条件的Pod数量，并将新的Pod尽可能分布到数量较少的节点上。这个计算过程基于节点的资源利用率，以及Pod之间的亲和性和反亲和性，可以通过配置调整插件的行为。

需要注意的是，SelectorSpread插件并不考虑节点的硬件配置、网络延迟和距离等因素，因此在一些特殊的场景下，可能会出现节点之间负载不均衡的情况。在这种情况下，用户可以考虑使用其他的调度插件，或者手动指定Pod的节点亲和性和反亲和性，以实现更精细的调度策略。

### 结构

```GO
// SelectorSpread 是一个计算选择器分散优先级的插件。
type SelectorSpread struct {
    sharedLister framework.SharedLister // 共享的列表查询器，用于查询集群中的对象。
    services corelisters.ServiceLister // Service 列表查询器，用于查询 Service 对象。
    replicationControllers corelisters.ReplicationControllerLister // ReplicationController 列表查询器，用于查询 ReplicationController 对象。
    replicaSets appslisters.ReplicaSetLister // ReplicaSet 列表查询器，用于查询 ReplicaSet 对象。
    statefulSets appslisters.StatefulSetLister // StatefulSet 列表查询器，用于查询 StatefulSet 对象。
}

// 验证 SelectorSpread 实现了 framework.PreScorePlugin 接口。
var _ framework.PreScorePlugin = &SelectorSpread{}
// 验证 SelectorSpread 实现了 framework.ScorePlugin 接口。
var _ framework.ScorePlugin = &SelectorSpread{}

// 声明 Name 常量，表示插件名称。
const Name = names.SelectorSpread

// Name 返回插件的名称。
func (pl *SelectorSpread) Name() string {
	return Name
}

// New 初始化一个新的 SelectorSpread 插件并返回它。
func New(_ runtime.Object, handle framework.Handle) (framework.Plugin, error) {
    // 获取共享列表查询器。
    sharedLister := handle.SnapshotSharedLister()
    if sharedLister == nil {
   		return nil, fmt.Errorf("SnapshotSharedLister is nil")
    }
    // 获取共享信息工厂。
    sharedInformerFactory := handle.SharedInformerFactory()
    if sharedInformerFactory == nil {
    	return nil, fmt.Errorf("SharedInformerFactory is nil")
    }
    // 返回一个 SelectorSpread 实例。
    return &SelectorSpread{
        sharedLister: sharedLister,
        services: sharedInformerFactory.Core().V1().Services().Lister(),
        replicationControllers: sharedInformerFactory.Core().V1().ReplicationControllers().Lister(),
        replicaSets: sharedInformerFactory.Apps().V1().ReplicaSets().Lister(),
        statefulSets: sharedInformerFactory.Apps().V1().StatefulSets().Lister(),
    }, nil
}
```

### PreScore

```GO
// PreScore 函数用于构建并写入由 Score 和 NormalizeScore 使用的周期状态。
func (pl *SelectorSpread) PreScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
    // 如果 pod 不需要 SelectorSpread，则直接返回 nil。
    if skipSelectorSpread(pod) {
    	return nil
    }
    // 获取 Pod 的选择器，使用 pl 中的 services、replicationControllers、replicaSets、statefulSets 进行筛选。
    selector := helper.DefaultSelector(
        pod,
        pl.services,
        pl.replicationControllers,
        pl.replicaSets,
        pl.statefulSets,
    )
    // 构建 preScoreState 实例并写入 cycleState。
    state := &preScoreState{
    	selector: selector,
    }
    cycleState.Write(preScoreStateKey, state)
    return nil
}
```

#### skipSelectorSpread

```GO
// 如果 Pod 的 TopologySpreadConstraints 指定了，返回 true。
// 注意，这不考虑为 PodTopologySpread 插件定义的默认约束。
func skipSelectorSpread(pod *v1.Pod) bool {
	return len(pod.Spec.TopologySpreadConstraints) != 0
}
```

#### preScoreState

````GO
// preScoreState 在 PreScore 时计算并在 Score 时使用。
type preScoreState struct {
	selector labels.Selector
}
````

#### DefaultSelector

```GO
// DefaultSelector 函数返回一个从 Services、Replication Controllers、Replica Sets 和 Stateful Sets 中匹配给定 pod 的选择器。
func DefaultSelector(
    pod *v1.Pod,
    sl corelisters.ServiceLister,
    cl corelisters.ReplicationControllerLister,
    rsl appslisters.ReplicaSetLister,
    ssl appslisters.StatefulSetLister,
) labels.Selector {
    // 创建一个 labelSet，用于存储筛选出的标签集合。
    labelSet := make(labels.Set)
    // 通过给定的 ServiceLister 和 Pod 获取匹配的服务，然后将服务的选择器与 labelSet 合并。
    if services, err := GetPodServices(sl, pod); err == nil {
        for _, service := range services {
            labelSet = labels.Merge(labelSet, service.Spec.Selector)
        }
    }
    selector := labelSet.AsSelector()

    // 获取 Pod 所属的 owner
    owner := metav1.GetControllerOfNoCopy(pod)
    if owner == nil {
        return selector
    }

    // 解析 owner 的 GroupVersion 和 Kind
    gv, err := schema.ParseGroupVersion(owner.APIVersion)
    if err != nil {
        return selector
    }
    gvk := gv.WithKind(owner.Kind)

    // 根据 owner 的 Kind 进行不同的处理
    switch gvk {
    case rcKind:
        // 如果 owner 是 Replication Controller，则获取其 Selector 并将其与 labelSet 合并。
        if rc, err := cl.ReplicationControllers(pod.Namespace).Get(owner.Name); err == nil {
            labelSet = labels.Merge(labelSet, rc.Spec.Selector)
            selector = labelSet.AsSelector()
        }
    case rsKind:
        // 如果 owner 是 Replica Set，则将 Replica Set 的 Selector 转换为 Requirements，并将其添加到 selector 中。
        if rs, err := rsl.ReplicaSets(pod.Namespace).Get(owner.Name); err == nil {
            if other, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector); err == nil {
                if r, ok := other.Requirements(); ok {
                    selector = selector.Add(r...)
                }
            }
        }
    case ssKind:
        // 如果 owner 是 Stateful Set，则将 Stateful Set 的 Selector 转换为 Requirements，并将其添加到 selector 中。
        if ss, err := ssl.StatefulSets(pod.Namespace).Get(owner.Name); err == nil {
            if other, err := metav1.LabelSelectorAsSelector(ss.Spec.Selector); err == nil {
                if r, ok := other.Requirements(); ok {
                    selector = selector.Add(r...)
                }
            }
        }
    default:
        // 如果 owner 不是支持的控制器，则直接返回 selector。
    }

    return selector
}
```

##### GetPodServices

```GO
// GetPodServices函数获取具有与给定Pod标签匹配选择器的服务。
func GetPodServices(sl corelisters.ServiceLister, pod *v1.Pod) ([]*v1.Service, error) {
    // 通过 ServiceLister 获取 Pod 命名空间中的所有 Service
    allServices, err := sl.Services(pod.Namespace).List(labels.Everything())
    if err != nil {
    	return nil, err
    }
    // 创建一个服务列表
    var services []*v1.Service

    // 遍历所有服务
    for i := range allServices {
        // 获取当前服务
        service := allServices[i]

        // 如果当前服务的选择器为空，则不进行匹配
        if service.Spec.Selector == nil {
            // services with nil selectors match nothing, not everything.
            continue
        }

        // 根据服务的选择器创建一个预先验证过的选择器
        selector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()

        // 如果 Pod 的标签与服务的选择器匹配，则将该服务添加到服务列表中
        if selector.Matches(labels.Set(pod.Labels)) {
            services = append(services, service)
        }
    }

    // 返回服务列表和错误（如果有）
    return services, nil
}
```

### Score&ScoreExtensions

```GO
// 在 Score 扩展点中调用 Score 方法。
// 此函数返回的 "score" 是 nodeName 上匹配 pod 数量，稍后将进行归一化。
func (pl *SelectorSpread) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 如果 pod 符合跳过 selector spread 的条件，则返回 0。
    if skipSelectorSpread(pod) {
    	return 0, nil
    }
	// 从 CycleState 中读取预处理的状态。
    c, err := state.Read(preScoreStateKey)
    if err != nil {
        return 0, framework.AsStatus(fmt.Errorf("reading %q from cycleState: %w", preScoreStateKey, err))
    }

    // 将读取到的状态转换为预处理状态。
    s, ok := c.(*preScoreState)
    if !ok {
        return 0, framework.AsStatus(fmt.Errorf("cannot convert saved state to selectorspread.preScoreState"))
    }

    // 从 sharedLister 中获取 nodeName 对应的 NodeInfo。
    nodeInfo, err := pl.sharedLister.NodeInfos().Get(nodeName)
    if err != nil {
        return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
    }

    // 计算匹配 nodeName 上 pod 的数量。
    count := countMatchingPods(pod.Namespace, s.selector, nodeInfo)
    return int64(count), nil
}

func (pl *SelectorSpread) ScoreExtensions() framework.ScoreExtensions {
	return pl
}

// NormalizeScore 在对所有节点进行打分后调用。
// 对于这个插件，它根据节点上现有的匹配 pod 数量计算每个节点的得分，
// 在包含区域信息的节点上，它会优先选择已存在较少匹配 pod 的区域中的节点。
func (pl *SelectorSpread) NormalizeScore(ctx context.Context, state *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
    // 如果 Pod 不需要 SelectorSpread，则直接返回。
    if skipSelectorSpread(pod) {
    	return nil
    }
    // 用于存储每个区域中匹配 Pod 的数量。
    countsByZone := make(map[string]int64, 10)
    // 区域中匹配 Pod 数量的最大值。
    maxCountByZone := int64(0)
    // 节点中匹配 Pod 数量的最大值。
    maxCountByNodeName := int64(0)

    // 遍历节点得分列表，找到节点中匹配 Pod 数量的最大值和每个区域中匹配 Pod 的数量。
    for i := range scores {
        if scores[i].Score > maxCountByNodeName {
            maxCountByNodeName = scores[i].Score
        }
        nodeInfo, err := pl.sharedLister.NodeInfos().Get(scores[i].Name)
        if err != nil {
            return framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", scores[i].Name, err))
        }
        // 获取节点所在的区域。
        zoneID := utilnode.GetZoneKey(nodeInfo.Node())
        if zoneID == "" {
            continue
        }
        countsByZone[zoneID] += scores[i].Score
    }

    // 找到每个区域中匹配 Pod 数量的最大值。
    for zoneID := range countsByZone {
        if countsByZone[zoneID] > maxCountByZone {
            maxCountByZone = countsByZone[zoneID]
        }
    }

    // 是否有区域信息。
    haveZones := len(countsByZone) != 0

    // 强制转换为 float64。
    maxCountByNodeNameFloat64 := float64(maxCountByNodeName)
    maxCountByZoneFloat64 := float64(maxCountByZone)
    MaxNodeScoreFloat64 := float64(framework.MaxNodeScore)

    // 遍历节点得分列表，计算每个节点的得分。
    for i := range scores {
        // 初始化为默认的最大节点得分。
        fScore := MaxNodeScoreFloat64
        if maxCountByNodeName > 0 {
            fScore = MaxNodeScoreFloat64 * (float64(maxCountByNodeName-scores[i].Score) / maxCountByNodeNameFloat64)
        }
        // 如果有区域信息，则将其纳入计算。
        if haveZones {
            nodeInfo, err := pl.sharedLister.NodeInfos().Get(scores[i].Name)
            if err != nil {
                return framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", scores[i].Name, err))
            }

            // 获取节点所在的区域。
            zoneID := utilnode.GetZoneKey(nodeInfo.Node())
            if zoneID != "" {
                // 如果存在区域ID，则将区域得分考虑进去
				zoneScore := MaxNodeScoreFloat64
                // 如果最大区域计数大于零
				if maxCountByZone > 0 {
                    // 根据现有区域匹配数(countsByZone[zoneID])计算出区域得分。
					zoneScore = MaxNodeScoreFloat64 * (float64(maxCountByZone-countsByZone[zoneID]) / maxCountByZoneFloat64)
				}
                // 计算完成后，将区域权重(zoneWeighting)应用于节点分数(fScore)
				fScore = (fScore * (1.0 - zoneWeighting)) + (zoneWeighting * zoneScore)
			}
		}
        // 保存分数
		scores[i].Score = int64(fScore)
	}
	return nil
}
```

#### countMatchingPods

```GO
// countMatchingPods 根据命名空间和匹配所有选择器来计算 pod 数量。
func countMatchingPods(namespace string, selector labels.Selector, nodeInfo *framework.NodeInfo) int {
    // 如果 nodeInfo 中没有 pod，或者 selector 为空，则返回 0。
    if len(nodeInfo.Pods) == 0 || selector.Empty() {
    	return 0
    }
    count := 0
    for _, p := range nodeInfo.Pods {
        // 忽略正在删除的 pod 以进行扩散（与 SelectorSpreadPriority 中的处理方式类似）。
        if namespace == p.Pod.Namespace && p.Pod.DeletionTimestamp == nil {
            // 如果 pod 的标签与 selector 匹配，则 count 加一。
            if selector.Matches(labels.Set(p.Pod.Labels)) {
            	count++
            }
        }
    }
    return count
}
```

## TaintToleration

### 作用

用于实现Taint和Toleration机制的核心组件之一。它的作用是在节点的Taint和Pod的Toleration之间建立映射关系，从而实现节点与Pod的匹配。具体来说，TaintToleration插件会检查每个Pod的Toleration，然后根据节点上的Taint进行匹配，找到一个可以容忍Pod的节点。

通过TaintToleration插件，管理员可以对集群中的节点进行更细粒度的控制，例如限制节点上运行的Pod数量，避免故障节点被不适合的Pod占用等。同时，通过Taint和Toleration的组合使用，可以实现对不同节点的不同Pod的调度策略，从而更好地满足应用程序的需求。

### 结构

```GO
// TaintToleration是一个插件，用于检查Pod是否容忍节点的污点。
type TaintToleration struct {
	handle framework.Handle
}

// 实现 framework.FilterPlugin、framework.PreScorePlugin、framework.ScorePlugin 和 framework.EnqueueExtensions 接口
var _ framework.FilterPlugin = &TaintToleration{}
var _ framework.PreScorePlugin = &TaintToleration{}
var _ framework.ScorePlugin = &TaintToleration{}
var _ framework.EnqueueExtensions = &TaintToleration{}

// 声明常量
const (
    // Name 是在插件注册表和配置中使用的插件名称。
    Name = names.TaintToleration
    // preScoreStateKey 是 CycleState 中 TaintToleration 预计算评分数据的键。
    preScoreStateKey = "PreScore" + Name
    // ErrReasonNotMatch 是在不匹配时 Filter 的原因状态。
    ErrReasonNotMatch = "node(s) had taints that the pod didn't tolerate"
)

// Name 返回插件的名称。它在日志等中使用。
func (pl *TaintToleration) Name() string {
	return Name
}

// New 初始化一个新的插件并返回它。
func New(_ runtime.Object, h framework.Handle) (framework.Plugin, error) {
	return &TaintToleration{handle: h}, nil
}
```

### Filter

```go
// Filter 方法是 FilterPlugin 接口的方法，用于在筛选阶段调用。
func (pl *TaintToleration) Filter(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取 Node 对象
    node := nodeInfo.Node()
    if node == nil {
        // 如果获取到的 Node 对象为空，返回错误状态
        return framework.AsStatus(fmt.Errorf("invalid nodeInfo"))
    }
    // 查找该 Pod 可容忍的 Taint
    taint, isUntolerated := v1helper.FindMatchingUntoleratedTaint(node.Spec.Taints, pod.Spec.Tolerations, helper.DoNotScheduleTaintsFilterFunc())
    if !isUntolerated {
        // 如果不存在未容忍的 Taint，返回 nil，表示该 Node 可被筛选
        return nil
    }

    // 如果存在未容忍的 Taint，返回一个新的错误状态，提示无法调度
    errReason := fmt.Sprintf("node(s) had untolerated taint {%s: %s}", taint.Key, taint.Value)
    return framework.NewStatus(framework.UnschedulableAndUnresolvable, errReason)
}
```

### PreScore

```go
// PreScore 函数用于构建并写入状态，用于 Score 和 NormalizeScore 计算
func (pl *TaintToleration) PreScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
	// 如果 nodes 列表为空则直接返回 nil
	if len(nodes) == 0 {
		return nil
	}
	// 获取 pod 中所有的 PreferNoSchedule Tolerations
	tolerationsPreferNoSchedule := getAllTolerationPreferNoSchedule(pod.Spec.Tolerations)
	// 构建 preScoreState 对象，包含 PreferNoSchedule Tolerations
	state := &preScoreState{
		tolerationsPreferNoSchedule: tolerationsPreferNoSchedule,
	}
	// 写入 cycleState 状态
	cycleState.Write(preScoreStateKey, state)
	return nil
}
```

#### preScoreState

```go
// preScoreState 在 PreScore 计算后使用于 Score 计算
type preScoreState struct {
	// tolerationsPreferNoSchedule 是 v1.Toleration 类型的切片
	tolerationsPreferNoSchedule []v1.Toleration
}

// Clone 实现了必须的 Clone 接口。我们实际上并不复制数据，因为没有必要。
// Clone 方法用于实现 Clone 接口，返回当前对象的引用
func (s *preScoreState) Clone() framework.StateData {
	return s
}
```

#### getAllTolerationPreferNoSchedule

```go
// getAllTolerationPreferNoSchedule 获取所有 PreferNoSchedule 和没有 effect 的 Tolerations
func getAllTolerationPreferNoSchedule(tolerations []v1.Toleration) (tolerationList []v1.Toleration) {
	// 遍历 tolerations 切片
	for _, toleration := range tolerations {
		// 空 effect 表示包括 PreferNoSchedule，因此需要收集所有
		if len(toleration.Effect) == 0 || toleration.Effect == v1.TaintEffectPreferNoSchedule {
			tolerationList = append(tolerationList, toleration)
		}
	}
	return
}
```

### Score&NormalizeScore

```go
// 定义一个 Score 方法，该方法在 Score 扩展点被调用。
func (pl *TaintToleration) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	// 从 Snapshot 中获取 nodeName 对应的 NodeInfo。
	nodeInfo, err := pl.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
	if err != nil {
		// 如果获取 NodeInfo 失败，返回一个包含错误信息的 Status。
		return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
	}
	// 从 NodeInfo 中获取 Node。
	node := nodeInfo.Node()

	// 获取 state 的预处理状态。
	s, err := getPreScoreState(state)
	if err != nil {
		// 如果获取预处理状态失败，返回一个包含错误信息的 Status。
		return 0, framework.AsStatus(err)
	}

	// 统计 Pod 中 Effect 为 PreferNoSchedule 的 Taints 中不可容忍的 Taints 的数量。
	score := int64(countIntolerableTaintsPreferNoSchedule(node.Spec.Taints, s.tolerationsPreferNoSchedule))
	return score, nil
}

// NormalizeScore invoked after scoring all nodes.
func (pl *TaintToleration) NormalizeScore(ctx context.Context, _ *framework.CycleState, pod *v1.Pod, scores framework.NodeScoreList) *framework.Status {
	return helper.DefaultNormalizeScore(framework.MaxNodeScore, true, scores)
}

// ScoreExtensions of the Score plugin.
func (pl *TaintToleration) ScoreExtensions() framework.ScoreExtensions {
	return pl
}
```

#### getPreScoreState

```go
func getPreScoreState(cycleState *framework.CycleState) (*preScoreState, error) {
	// 从 cycleState 中读取 preScoreState 状态
	c, err := cycleState.Read(preScoreStateKey)
	if err != nil {
		// 如果读取失败则返回错误信息
		return nil, fmt.Errorf("failed to read %q from cycleState: %w", preScoreStateKey, err)
	}

	// 将读取到的状态转换为 preScoreState 类型
	s, ok := c.(*preScoreState)
	if !ok {
		// 如果转换失败则返回错误信息
		return nil, fmt.Errorf("%+v convert to tainttoleration.preScoreState error", c)
	}
	// 如果转换成功则返回状态值
	return s, nil
}
```

#### countIntolerableTaintsPreferNoSchedule

```go
// CountIntolerableTaintsPreferNoSchedule 方法用于计算 Effect 为 PreferNoSchedule 的 Taints 中不可容忍的 Taints 的数量。
func countIntolerableTaintsPreferNoSchedule(taints []v1.Taint, tolerations []v1.Toleration) (intolerableTaints int) {
	// 遍历 Pod 中所有的 Taint。
	for _, taint := range taints {
		// 只检查 Effect 为 PreferNoSchedule 的 Taint。
		if taint.Effect != v1.TaintEffectPreferNoSchedule {
			continue
		}

		// 判断当前 Taint 是否可以被 tolerations 中的 Toleration 容忍。
		if !v1helper.TolerationsTolerateTaint(tolerations, &taint) {
			intolerableTaints++
		}
	}
	return
}
```

### EventsToRegister

```go
// EventsToRegister 方法用于返回可能导致 Pod 无法被调度的事件。
func (pl *TaintToleration) EventsToRegister() []framework.ClusterEvent {
	// 返回一个包含 Node 资源的 Add 和 Update 事件的 ClusterEvent 数组。
	return []framework.ClusterEvent{
		{Resource: framework.Node, ActionType: framework.Add | framework.Update},
	}
}
```

## VolumeRestrictions

### 作用

用于实现对Pod中Volume的限制。它的作用是检查Pod中使用的Volume是否符合管理员设定的限制条件，从而避免因为Pod中Volume的使用不当导致系统资源的浪费或安全隐患。

在Kubernetes中，Volume是用于持久化容器中的数据的一种机制。Pod可以挂载多个Volume，并且可以使用不同类型的Volume，例如hostPath、emptyDir、configMap等。VolumeRestrictions插件的作用是检查Pod中使用的Volume的类型、大小、数量等限制条件，确保Pod不会超出预设的限制，保证集群的安全和稳定。

例如，管理员可以设置Pod中最多只能使用一个hostPath类型的Volume，或者Volume的大小不能超过一定的限制，或者Pod中使用的Volume必须符合一定的命名规则等。当Pod的Volume使用不符合这些限制条件时，VolumeRestrictions插件会拒绝调度该Pod，并且输出相关的警告信息。

### 结构

```GO
// VolumeRestrictions 是一个检查卷限制的插件。
type VolumeRestrictions struct {
	pvcLister              corelisters.PersistentVolumeClaimLister
	sharedLister           framework.SharedLister
	enableReadWriteOncePod bool
}

// 实现 PreFilterPlugin 接口和 FilterPlugin 接口以及 EnqueueExtensions 接口和 StateData 接口
var _ framework.PreFilterPlugin = &VolumeRestrictions{}
var _ framework.FilterPlugin = &VolumeRestrictions{}
var _ framework.EnqueueExtensions = &VolumeRestrictions{}
var _ framework.StateData = &preFilterState{}

const (
	// Name 是插件在插件注册表和配置中使用的名称。
	Name = names.VolumeRestrictions
	// preFilterStateKey is the key in CycleState to VolumeRestrictions pre-computed data for Filtering.
	// Using the name of the plugin will likely help us avoid collisions with other plugins.
	preFilterStateKey = "PreFilter" + Name

	// ErrReasonDiskConflict 是 NoDiskConflict 谓词错误的原因。
	ErrReasonDiskConflict = "node(s) had no available disk"

	// ErrReasonReadWriteOncePodConflict 是当发现使用相同 PVC 且访问模式为 ReadWriteOncePod 的 Pod 时使用的原因。
	ErrReasonReadWriteOncePodConflict = "node has pod using PersistentVolumeClaim with the same name and ReadWriteOncePod access mode"
)

// New 初始化一个新的插件并返回它。
func New(_ runtime.Object, handle framework.Handle, fts feature.Features) (framework.Plugin, error) {
	// 获取 SharedInformerFactory 和 Listers
	informerFactory := handle.SharedInformerFactory()
	pvcLister := informerFactory.Core().V1().PersistentVolumeClaims().Lister()
	sharedLister := handle.SnapshotSharedLister()

	// 返回 VolumeRestrictions 插件实例
	return &VolumeRestrictions{
		pvcLister:              pvcLister,
		sharedLister:           sharedLister,
		enableReadWriteOncePod: fts.EnableReadWriteOncePod,
	}, nil
}
```

### PreFilter

```GO
// PreFilter computes and stores cycleState containing details for enforcing ReadWriteOncePod.
func (pl *VolumeRestrictions) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
	needsCheck := false
	// 检查 Pod 使用的 Volume 是否需要进行限制检查
	for i := range pod.Spec.Volumes {
		if needsRestrictionsCheck(pod.Spec.Volumes[i]) {
			needsCheck = true
			break
		}
	}

	// 如果未启用 ReadWriteOncePod，则跳过限制检查
	if !pl.enableReadWriteOncePod {
		if needsCheck {
			return nil, nil
		}
		return nil, framework.NewStatus(framework.Skip)
	}

	// 获取 Pod 使用的 PersistentVolumeClaim 列表
	pvcs, err := pl.readWriteOncePodPVCsForPod(ctx, pod)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// 如果 Pod 使用的 PersistentVolumeClaim 不存在，则返回 UnschedulableAndUnresolvable 状态
			return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, err.Error())
		}
		// 如果出现其他错误，则返回错误状态
		return nil, framework.AsStatus(err)
	}

	// 计算 preFilterState
	s, err := pl.calPreFilterState(ctx, pod, pvcs)
	if err != nil {
		return nil, framework.AsStatus(err)
	}

	// 如果不需要限制检查且没有冲突，则跳过限制检查
	if !needsCheck && s.conflictingPVCRefCount == 0 {
		return nil, framework.NewStatus(framework.Skip)
	}
	// 将计算出的 preFilterState 存储到 cycleState 中
	cycleState.Write(preFilterStateKey, s)
	return nil, nil
}

func (pl *VolumeRestrictions) PreFilterExtensions() framework.PreFilterExtensions {
	return pl
}

// AddPod from pre-computed data in cycleState.
func (pl *VolumeRestrictions) AddPod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podInfoToAdd *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
	if !pl.enableReadWriteOncePod {
		return nil
	}
	state, err := getPreFilterState(cycleState)
	if err != nil {
		return framework.AsStatus(err)
	}
	state.updateWithPod(podInfoToAdd, 1)
	return nil
}

// RemovePod from pre-computed data in cycleState.
func (pl *VolumeRestrictions) RemovePod(ctx context.Context, cycleState *framework.CycleState, podToSchedule *v1.Pod, podInfoToRemove *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
	if !pl.enableReadWriteOncePod {
		return nil
	}
	state, err := getPreFilterState(cycleState)
	if err != nil {
		return framework.AsStatus(err)
	}
	state.updateWithPod(podInfoToRemove, -1)
	return nil
}
```

#### preFilterState

```go
// 定义了 preFilterState 结构体，用于在 PreFilter 中计算，Filter 中使用。
type preFilterState struct {
    // Names of the pod's volumes using the ReadWriteOncePod access mode.
    // 使用 ReadWriteOncePod 访问模式的 Pod 卷的名称。
    readWriteOncePodPVCs sets.Set[string]
    // The number of references to these ReadWriteOncePod volumes by scheduled pods.
    // 已调度 Pod 引用这些 ReadWriteOncePod 卷的数量。
    conflictingPVCRefCount int
}

// 在 preFilterState 结构体上定义了 updateWithPod 方法，用于更新 conflictingPVCRefCount 字段。
func (s *preFilterState) updateWithPod(podInfo *framework.PodInfo, multiplier int) {
    s.conflictingPVCRefCount += multiplier * s.conflictingPVCRefCountForPod(podInfo)
}

// 在 preFilterState 结构体上定义了 conflictingPVCRefCountForPod 方法，用于计算 podInfo 中所有卷的冲突数量。
func (s *preFilterState) conflictingPVCRefCountForPod(podInfo *framework.PodInfo) int {
    conflicts := 0
    for _, volume := range podInfo.Pod.Spec.Volumes {
        if volume.PersistentVolumeClaim == nil {
            continue
        }
        if s.readWriteOncePodPVCs.Has(volume.PersistentVolumeClaim.ClaimName) {
            conflicts += 1
        }
    }
    return conflicts
}

// 在 preFilterState 结构体上定义了 Clone 方法，用于复制 preFilterState。
func (s *preFilterState) Clone() framework.StateData {
    if s == nil {
        return nil
    }
    return &preFilterState{
        readWriteOncePodPVCs:   s.readWriteOncePodPVCs,
        conflictingPVCRefCount: s.conflictingPVCRefCount,
    }
}
```

#### needsRestrictionsCheck

```go
// 判断一个v1.Volume对象是否包含某些字段，如果包含则返回true，否则返回false。
func needsRestrictionsCheck(v v1.Volume) bool {
	return v.GCEPersistentDisk != nil || v.AWSElasticBlockStore != nil || v.RBD != nil || v.ISCSI != nil
}
```

#### readWriteOncePodPVCsForPod

```go
// 定义VolumeRestrictions类型的一个方法，用于获取Pod的ReadWriteOnce类型的PVC
func (pl *VolumeRestrictions) readWriteOncePodPVCsForPod(ctx context.Context, pod *v1.Pod) (sets.Set[string], error) {
    // 创建一个空的字符串Set，用于存储Pod使用的ReadWriteOnce类型的PVC
	pvcs := sets.New[string]()
    // 遍历Pod中的所有Volume
	for _, volume := range pod.Spec.Volumes {
        // 如果Volume不是持久化存储卷，则跳过
		if volume.PersistentVolumeClaim == nil {
			continue
		}

        // 获取PVC
		pvc, err := pl.pvcLister.PersistentVolumeClaims(pod.Namespace).Get(volume.PersistentVolumeClaim.ClaimName)
		if err != nil {
			return nil, err
		}

        // 如果PVC的访问模式不是ReadWriteOncePod，则跳过
		if !v1helper.ContainsAccessMode(pvc.Spec.AccessModes, v1.ReadWriteOncePod) {
			continue
		}
        // 将PVC的名称插入pvcs Set中
		pvcs.Insert(pvc.Name)
	}
	return pvcs, nil
}
```

#### calPreFilterState

```go
// calPreFilterState计算preFilterState，描述哪些PVC使用ReadWriteOncePod，以及集群中有哪些Pod冲突。
func (pl *VolumeRestrictions) calPreFilterState(ctx context.Context, pod *v1.Pod, pvcs sets.Set[string]) (*preFilterState, error) {
    // 定义冲突PVC的计数器
	conflictingPVCRefCount := 0
    // 遍历所有的ReadWriteOncePod类型的PVC
	for pvc := range pvcs {
        // 获取PVC的key
		key := framework.GetNamespacedName(pod.Namespace, pvc)
        // 如果PVC被其他Pod使用，则将冲突PVC的计数器加1
		if pl.sharedLister.StorageInfos().IsPVCUsedByPods(key) {
			// 只能有一个Pod使用ReadWriteOncePod类型的PVC。
			conflictingPVCRefCount += 1
		}
	}
    // 返回preFilterState结构体的指针，其中包含了使用ReadWriteOncePod类型的PVC以及冲突PVC的计数器
	return &preFilterState{
		readWriteOncePodPVCs:   pvcs,
		conflictingPVCRefCount: conflictingPVCRefCount,
	}, nil
}
```

#### getPreFilterState

```go
// getPreFilterState函数用于从cycleState中获取preFilterState状态对象，即预过滤状态对象
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
    c, err := cycleState.Read(preFilterStateKey) // 从cycleState中获取preFilterState
    if err != nil {
        // 若获取失败，则说明没有进行预过滤
        return nil, fmt.Errorf("cannot read %q from cycleState", preFilterStateKey)
    }

    s, ok := c.(*preFilterState) // 类型断言，判断获取的对象是否是preFilterState
    if !ok {
        // 如果获取的对象不是preFilterState类型，则返回错误
        return nil, fmt.Errorf("%+v convert to volumerestrictions.state error", c)
    }
    return s, nil // 如果获取成功，返回preFilterState对象
}
```

### Filter

```go
// Filter函数为过滤器的扩展点。它用于判断Pod是否可以被调度。
// 如果已经有一个卷挂载在节点上，那么另一个使用相同卷的Pod就不能在此节点上调度。
// 目前这个函数只适用于GCE，Amazon EBS，ISCSI和Ceph RBD：
// - GCE PD允许多个挂载只要它们都是只读的。
// - AWS EBS禁止任何两个Pod挂载相同的卷ID。
// - Ceph RBD禁止如果任何两个Pod共享至少一个监视器，并匹配池和映像，且映像是只读的。
// - 如果任何两个Pod共享至少一个IQN并且iSCSI卷是只读的，则ISCSI禁止。
// 如果Pod使用的PVC是ReadWriteOncePod访问模式，它会评估这些PVC是否已经被使用，以及抢占是否有所帮助。
func (pl *VolumeRestrictions) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 检查Pod是否满足卷冲突条件
    if !satisfyVolumeConflicts(pod, nodeInfo) {
    // 如果不满足卷冲突条件，则返回不可调度状态和错误信息
    	return framework.NewStatus(framework.Unschedulable, ErrReasonDiskConflict)
    }
    // 如果不支持ReadWriteOncePod访问模式，则直接返回
    if !pl.enableReadWriteOncePod {
    	return nil
    }
    // 获取预过滤状态对象
    state, err := getPreFilterState(cycleState)
    if err != nil {
    	return framework.AsStatus(err)
    }
    // 检查是否满足ReadWriteOncePod访问模式的条件
    return satisfyReadWriteOncePod(ctx, state)
}
```

#### satisfyVolumeConflicts

```go
// 判断在此节点上调度该Pod是否会与现有卷产生冲突
func satisfyVolumeConflicts(pod *v1.Pod, nodeInfo *framework.NodeInfo) bool {
    // 遍历该Pod所有的Volume
    for i := range pod.Spec.Volumes {
        v := pod.Spec.Volumes[i]
        // 如果该Volume不需要检查限制，则跳过
        if !needsRestrictionsCheck(v) {
        	continue
        }
        // 遍历该节点上已经运行的Pod
        for _, ev := range nodeInfo.Pods {
            // 判断该Pod是否与现有Pod使用的Volume产生了冲突
            if isVolumeConflict(&v, ev.Pod) {
            	return false
            }
        }
    }
    return true
}
```

#### satisfyReadWriteOncePod

```go
// 判断在此节点上调度该Pod是否会与现有ReadWriteOncePod PVC的访问模式产生冲突
func satisfyReadWriteOncePod(ctx context.Context, state *preFilterState) *framework.Status {
    if state == nil {
    	return nil
    }
    // 如果存在多个Pod使用同一个ReadWriteOncePod PVC，则该Pod无法调度到此节点
    if state.conflictingPVCRefCount > 0 {
    	return framework.NewStatus(framework.Unschedulable, ErrReasonReadWriteOncePodConflict)
    }
    return nil
}
```

### EventsToRegister

```go
// 返回可能导致由此插件导致的Pod调度失败的事件。
func (pl *VolumeRestrictions) EventsToRegister() []framework.ClusterEvent {
    return []framework.ClusterEvent{
        // Pods可能无法调度，因为其卷与同一节点上的其他Pod产生冲突。
        // 一旦运行的Pod被删除并且卷已被释放，不可调度的Pod将变为可调度。
        // 由于不可变的字段spec.volumes，因此忽略Pod更新事件。
        {Resource: framework.Pod, ActionType: framework.Delete},
        // 新的Node可能会使Pod可调度。
        {Resource: framework.Node, ActionType: framework.Add},
        // Pods可能无法调度，因为它使用的PVC尚未创建。
        // 需要确保PVC存在才能检查其访问模式。
        {Resource: framework.PersistentVolumeClaim, ActionType: framework.Add | framework.Update},
    }
}
```

## VolumeZone

### 作用

用于将节点和Volume绑定在同一可用区（Availability Zone）内，以提高Pod的可靠性和容错性。在Kubernetes中，可用区是指一个物理数据中心内部的逻辑区域，通常由不同的电源、网络和硬件组成。将节点和Volume绑定在同一可用区内可以保证在节点或Volume故障时，系统可以快速地进行故障切换，从而保证应用程序的高可用性。

具体来说，VolumeZone插件会根据管理员设定的规则将节点和Volume绑定在同一可用区内。例如，管理员可以通过标签（label）或者注解（annotation）的方式，将某个节点和某个Volume绑定在同一可用区内。然后，当调度器需要为Pod分配节点和Volume时，VolumeZone插件会检查节点和Volume是否在同一可用区内，如果不在，则会拒绝调度该Pod。

除了提高Pod的可靠性和容错性，将节点和Volume绑定在同一可用区内还可以减少数据中心内部的网络流量，提高系统的性能和稳定性。

总之，VolumeZone插件是Kubernetes调度器中的一个重要组件，用于将节点和Volume绑定在同一可用区内，从而提高Pod的可靠性和容错性，减少数据中心内部的网络流量，提高系统的性能和稳定性。

### 结构

```GO
// VolumeZone 是一个检查卷区域的插件。
type VolumeZone struct {
    pvLister corelisters.PersistentVolumeLister
    pvcLister corelisters.PersistentVolumeClaimLister
    scLister storagelisters.StorageClassLister
}

var _ framework.FilterPlugin = &VolumeZone{}
var _ framework.PreFilterPlugin = &VolumeZone{}
var _ framework.EnqueueExtensions = &VolumeZone{}

const (
    // Name 是插件在插件注册表和配置中使用的名称。
    Name = names.VolumeZone
    // preFilterStateKey 是用于在状态存储中标识 PreFilter 的键。
    preFilterStateKey framework.StateKey = "PreFilter" + Name

    // ErrReasonConflict 用于 NoVolumeZoneConflict 断言错误。
    ErrReasonConflict = "node(s) had no available volume zone"
)

// Name 返回插件的名称，用于日志等。
func (pl *VolumeZone) Name() string {
	return Name
}

// New 初始化一个新的插件并返回它。
func New(_ runtime.Object, handle framework.Handle) (framework.Plugin, error) {
    // 获取 informerFactory
    informerFactory := handle.SharedInformerFactory()
    // 获取 PersistentVolumeLister
    pvLister := informerFactory.Core().V1().PersistentVolumes().Lister()
    // 获取 PersistentVolumeClaimLister
    pvcLister := informerFactory.Core().V1().PersistentVolumeClaims().Lister()
    // 获取 StorageClassLister
    scLister := informerFactory.Storage().V1().StorageClasses().Lister()
    // 返回 VolumeZone 实例
    return &VolumeZone{
        pvLister,
        pvcLister,
        scLister,
    }, nil
}
```

### PreFilter&PreFilterExtensions

```GO
// # 它查找与 Pod 请求的卷对应的 PersistentVolumes 的拓扑结构
//
// 目前，它仅支持 PersistentVolumeClaims，并且仅查找绑定的 PersistentVolume。
func (pl *VolumeZone) PreFilter(ctx context.Context, cs *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 获取 Pod 请求的卷的拓扑结构
    podPVTopologies, status := pl.getPVbyPod(ctx, pod)
    if !status.IsSuccess() {
    	return nil, status
    }
    // 如果没有拓扑结构，则跳过
    if len(podPVTopologies) == 0 {
    	return nil, framework.NewStatus(framework.Skip)
    }
    // 将拓扑结构写入状态存储
    cs.Write(preFilterStateKey, &stateData{podPVTopologies: podPVTopologies})
	return nil, nil
}
// PreFilterExtensions returns prefilter extensions, pod add and remove.
func (pl *VolumeZone) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

#### stateData

```GO
// pvTopology 存储了一个 PV 的拓扑标签的值
type pvTopology struct {
    pvName string
    key string
    values sets.Set[string]
}

// stateData 在 PreFilter 阶段初始化状态。
// 因为我们将指针保存在 framework.CycleState 中，所以在后续阶段中我们不需要调用 Write 方法更新值。
type stateData struct {
    // podPVTopologies 保存我们需要的 PV 信息
    // 在 PreFilter 阶段初始化
    podPVTopologies []pvTopology
}

func (d *stateData) Clone() framework.StateData {
	return d
}
```



```GO
func (pl *VolumeZone) getPVbyPod(ctx context.Context, pod *v1.Pod) ([]pvTopology, *framework.Status) {
	podPVTopologies := make([]pvTopology, 0) // 创建存储PV拓扑信息的切片

	// 遍历Pod的所有Volume
	for i := range pod.Spec.Volumes {
		volume := pod.Spec.Volumes[i] // 获取Volume
		if volume.PersistentVolumeClaim == nil { // 如果Volume没有关联PVC，则跳过
			continue
		}
		pvcName := volume.PersistentVolumeClaim.ClaimName // 获取PVC名称
		if pvcName == "" { // 如果PVC没有名称，则返回错误状态
			return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, "PersistentVolumeClaim had no name")
		}
		pvc, err := pl.pvcLister.PersistentVolumeClaims(pod.Namespace).Get(pvcName) // 获取PVC对象
		if s := getErrorAsStatus(err); !s.IsSuccess() { // 如果获取PVC对象出错，则返回错误状态
			return nil, s
		}

		pvName := pvc.Spec.VolumeName // 获取PVC对应的PV名称
		if pvName == "" { // 如果PV没有名称，则需要根据PVC的StorageClass信息进行处理
			scName := storagehelpers.GetPersistentVolumeClaimClass(pvc) // 获取PVC对应的StorageClass名称
			if len(scName) == 0 { // 如果StorageClass名称为空，则返回错误状态
				return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, "PersistentVolumeClaim had no pv name and storageClass name")
			}

			class, err := pl.scLister.Get(scName) // 获取StorageClass对象
			if s := getErrorAsStatus(err); !s.IsSuccess() { // 如果获取StorageClass对象出错，则返回错误状态
				return nil, s
			}
			if class.VolumeBindingMode == nil { // 如果StorageClass中VolumeBindingMode未设置，则返回错误状态
				return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("VolumeBindingMode not set for StorageClass %q", scName))
			}
			if *class.VolumeBindingMode == storage.VolumeBindingWaitForFirstConsumer { // 如果VolumeBindingMode等于VolumeBindingWaitForFirstConsumer，则跳过未绑定的PV
				// Skip unbound volumes
				continue
			}

			return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, "PersistentVolume had no name") // 如果PV没有名称，则返回错误状态
		}

		pv, err := pl.pvLister.Get(pvName) // 获取PV对象
		if s := getErrorAsStatus(err); !s.IsSuccess() { // 如果获取PV对象出错，则返回错误状态
			return nil, s
		}

		// 遍历拓扑标签列表，获取PV的拓扑信息，并将其存储到podPVTopologies中
		for _, key := range topologyLabels {
			if value, ok := pv.ObjectMeta.Labels[key]; ok { // 如果PV的标签中包含该拓扑标签，则解析其对应的拓扑信息
				volumeVSet, err := volumehelpers.LabelZonesToSet(value)
				if err != nil {
					klog.InfoS("Failed to parse label, ignoring the label", "label", fmt.Sprintf("%s:%s", key, value), "err", err)
					continue
				}
                // 添加拓扑信息
				podPVTopologies = append(podPVTopologies, pvTopology{
					pvName: pv.Name,
					key:    key,
					values: sets.Set[string](volumeVSet),
				})
			}
		}
	}
	return podPVTopologies, nil
}
```

##### getErrorAsStatus

````GO
func getErrorAsStatus(err error) *framework.Status {
	// 如果 err 不为 nil，说明出现了错误
	if err != nil {
		// 如果错误是因为对象未找到，就返回一个特定的 framework.Status 对象
		if apierrors.IsNotFound(err) {
			return framework.NewStatus(framework.UnschedulableAndUnresolvable, err.Error())
		}
		// 否则，将错误转换为 framework.Status 对象
		return framework.AsStatus(err)
	}
	// 如果 err 为 nil，说明没有出现错误，返回 nil
	return nil
}
````

### Filter

```GO
// Filter 在 filter 扩展点被调用。
// 它评估 Pod 是否适合于所请求的卷，考虑到一些卷可能有区域调度约束。要求是任何卷区域标签必须与节点上的等效区域标签匹配。节点具有更多的区域标签约束是可以接受的（例如，一个假想的复制卷可能允许全区域访问）。
// 目前，此功能仅支持 PersistentVolumeClaims，并且只查看已绑定的 PersistentVolume 上的标签。
// 在 Pod 规范中声明内联的卷（即不使用 PersistentVolume）可能更难，因为这将需要在调度期间确定卷的区域，这可能需要调用云提供程序。无论如何，似乎我们正在摆脱内联卷声明。
func (pl *VolumeZone) Filter(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	// 如果 Pod 没有任何挂载的卷，则直接返回 nil，即不对该节点进行过滤
	// 这是为了在该情况下避免进行不必要的计算
	if len(pod.Spec.Volumes) == 0 {
		return nil
	}
	// 获取 Pod 挂载的 PV（持久化卷）的拓扑信息
	var podPVTopologies []pvTopology
	state, err := getStateData(cs)
	if err != nil {
		// 如果获取状态数据失败，则回退到计算 PV 列表的方式
		var status *framework.Status
		podPVTopologies, status = pl.getPVbyPod(ctx, pod)
		if !status.IsSuccess() {
			return status
		}
	} else {
		podPVTopologies = state.podPVTopologies
	}

	// 获取当前节点对象
	node := nodeInfo.Node()
	// 判断当前节点是否有任何拓扑约束（Topology Constraints）
	hasAnyNodeConstraint := false
	for _, topologyLabel := range topologyLabels {
		// 如果节点标签中包含任何一个拓扑约束，则认为节点有拓扑约束
		if _, ok := node.Labels[topologyLabel]; ok {
			hasAnyNodeConstraint = true
			break
		}
	}

	// 如果节点没有任何拓扑约束，则直接返回 nil，即不对该节点进行过滤
	// 这是为了处理单区域（Single Zone）的场景，即节点可能没有任何拓扑标签
	if !hasAnyNodeConstraint {
		return nil
	}

	// 遍历 Pod 挂载的 PV 列表，依次检查节点是否符合拓扑约束要求
	for _, pvTopology := range podPVTopologies {
		v, ok := node.Labels[pvTopology.key]
		// 如果当前节点没有该 PV 所需的拓扑标签，则直接返回不可调度的错误
		if !ok || !pvTopology.values.Has(v) {
			klog.V(10).InfoS("Won't schedule pod onto node due to volume (mismatch on label key)", "pod", klog.KObj(pod), "node", klog.KObj(node), "PV", klog.KRef("", pvTopology.pvName), "PVLabelKey", pvTopology.key)
			return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonConflict)
		}
	}

	return nil
}
```

#### getStateData

```GO
func getStateData(cs *framework.CycleState) (*stateData, error) {
	// 从CycleState中读取key为preFilterStateKey的状态
	state, err := cs.Read(preFilterStateKey)
	if err != nil {
		return nil, err
	}
	// 将状态转换为stateData类型，如果转换失败则返回错误
	s, ok := state.(*stateData)
	if !ok {
		return nil, errors.New("unable to convert state into stateData")
	}
	// 返回转换后的stateData类型状态
	return s, nil
}
```

### EventsToRegister

```GO
// 返回一个包含可能导致Pod被调度程序标记为失败的事件列表
func (pl *VolumeZone) EventsToRegister() []framework.ClusterEvent {
	// 返回包含四个ClusterEvent类型的切片，这四个事件可能导致Pod被调度程序标记为失败
	return []framework.ClusterEvent{
		// 如果有新的storageClass的bind mode为VolumeBindingWaitForFirstConsumer，则Pod可以被调度程序调度
		// 由于storageClass.volumeBindingMode字段是不可变的，所以忽略storageClass的update事件。
		{Resource: framework.StorageClass, ActionType: framework.Add},
		// 如果有新的Node或更新了Node的volume zone标签，则Pod可以被调度程序调度。
		{Resource: framework.Node, ActionType: framework.Add | framework.UpdateNodeLabel},
		// 如果有新的PVC，则Pod可以被调度程序调度。
		// 由于除了spec.resources之外的所有字段都是不可变的，因此忽略pvc的update事件。
		{Resource: framework.PersistentVolumeClaim, ActionType: framework.Add},
		// 如果有新的PV或更新了PV的volume zone标签，则Pod可以被调度程序调度。
		{Resource: framework.PersistentVolume, ActionType: framework.Add | framework.Update},
	}
}
```

## VolumeBinding

### 作用

Kubernetes (k8s) 调度器 VolumeBinding 插件的作用是在 Pod 调度期间为 Pod 绑定合适的持久卷（Persistent Volume，PV）。

在 Kubernetes 中，持久卷是用于存储 Pod 数据的持久化存储资源。VolumeBinding 插件负责将 Pod 中声明的持久卷声明（Persistent Volume Claim，PVC）与可用的 PV 进行匹配和绑定。

具体来说，VolumeBinding 插件执行以下操作：

1. 监听 Pod 的调度事件：当 Pod 被调度到一个节点上时，VolumeBinding 插件会监听这个事件。
2. 寻找匹配的 PV：插件会根据 Pod 中 PVC 的要求（例如存储类、大小等）和集群中可用的 PV 的属性，寻找匹配的 PV。
3. 绑定 PV 和 PVC：一旦找到匹配的 PV，VolumeBinding 插件会将其与 Pod 中的 PVC 进行绑定。这意味着 Pod 可以使用该 PV 来实现持久化存储。
4. 更新调度决策：在绑定成功后，VolumeBinding 插件会更新调度决策，以确保将 Pod 调度到支持所需 PV 的节点上。

需要注意的是，VolumeBinding 插件通常与动态卷配置（Dynamic Volume Provisioning）结合使用，以便根据需要自动创建新的 PV。这使得在 PVC 和 PV 之间的绑定更加灵活和自动化。

### 结构

```GO
// VolumeBinding是一个绑定调度中pod卷的插件。
// 在过滤阶段，为pod创建卷绑定缓存并在Reserve和PreBind阶段使用。
type VolumeBinding struct {
    Binder SchedulerVolumeBinder // Binder实现了卷绑定。
    PVCLister corelisters.PersistentVolumeClaimLister // PVCLister用于获取PersistentVolumeClaim对象的列表。
    scorer volumeCapacityScorer // scorer是一个函数，用于评分。
    fts feature.Features // fts是一个结构体，表示Kubernetes集群的特性。
}

var _ framework.PreFilterPlugin = &VolumeBinding{}
var _ framework.FilterPlugin = &VolumeBinding{}
var _ framework.ReservePlugin = &VolumeBinding{}
var _ framework.PreBindPlugin = &VolumeBinding{}
var _ framework.ScorePlugin = &VolumeBinding{}
var _ framework.EnqueueExtensions = &VolumeBinding{}

// Name是插件在注册表和配置中使用的名称。
const Name = names.VolumeBinding

// Name返回插件的名称，用于记录等。
func (pl *VolumeBinding) Name() string {
	return Name
}

// New初始化一个新的插件并返回它。
func New(plArgs runtime.Object, fh framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 从plArgs中获取VolumeBindingArgs对象，并进行类型检查。
    args, ok := plArgs.(*config.VolumeBindingArgs)
    if !ok {
    	return nil, fmt.Errorf("want args to be of type VolumeBindingArgs, got %T", plArgs)
    }
    // 对VolumeBindingArgs对象进行验证。
    if err := validation.ValidateVolumeBindingArgsWithOptions(nil, args, validation.VolumeBindingArgsValidationOptions{
    	AllowVolumeCapacityPriority: fts.EnableVolumeCapacityPriority,
    }); err != nil {
    return nil, err
    }
    // 获取informers和binder。
    podInformer := fh.SharedInformerFactory().Core().V1().Pods()
    nodeInformer := fh.SharedInformerFactory().Core().V1().Nodes()
    pvcInformer := fh.SharedInformerFactory().Core().V1().PersistentVolumeClaims()
    pvInformer := fh.SharedInformerFactory().Core().V1().PersistentVolumes()
    storageClassInformer := fh.SharedInformerFactory().Storage().V1().StorageClasses()
    csiNodeInformer := fh.SharedInformerFactory().Storage().V1().CSINodes()
    capacityCheck := CapacityCheck{
        CSIDriverInformer: fh.SharedInformerFactory().Storage().V1().CSIDrivers(),
        CSIStorageCapacityInformer: fh.SharedInformerFactory().Storage().V1().CSIStorageCapacities(),
    }
    binder := NewVolumeBinder(fh.ClientSet(), podInformer, nodeInformer, csiNodeInformer, pvcInformer, pvInformer, storageClassInformer, capacityCheck, time.Duration(args.BindTimeoutSeconds)*time.Second)
    // 构建评分函数。
    var scorer volumeCapacityScorer
    if fts.EnableVolumeCapacityPriority {
        shape := make(helper.FunctionShape, 0, len(args.Shape))
        for _, point := range args.Shape {
            shape = append(shape, helper.FunctionShapePoint{
                Utilization: int64(point.Utilization),
                Score:       int64(point.Score) * (framework.MaxNodeScore / config.MaxCustomPriorityScore),
            })
        }
        scorer = buildScorerFunction(shape)
    }
	return &VolumeBinding{
		Binder:    binder,
		PVCLister: pvcInformer.Lister(),
		scorer:    scorer,
		fts:       fts,
	}, nil
}
```

#### buildScorerFunction

```go
// classResourceMap 保存存储类到资源的映射。
type classResourceMap map[string]*StorageResource

// volumeCapacityScorer 根据存储类资源信息计算得分的函数类型。
type volumeCapacityScorer func(classResourceMap) int64

// buildScorerFunction 从评分函数的形状构建 volumeCapacityScorer。
func buildScorerFunction(scoringFunctionShape helper.FunctionShape) volumeCapacityScorer {
rawScoringFunction := helper.BuildBrokenLinearFunction(scoringFunctionShape)
    f := func(requested, capacity int64) int64 {
        if capacity == 0 || requested > capacity {
        	return rawScoringFunction(maxUtilization)
        }
    	return rawScoringFunction(requested * maxUtilization / capacity)
	}
	return func(classResources classResourceMap) int64 {
        var nodeScore int64
        // 在 alpha 阶段，所有类别的权重相同
        weightSum := len(classResources)
        if weightSum == 0 {
            return 0
        }
        for _, resource := range classResources {
            classScore := f(resource.Requested, resource.Capacity)
            nodeScore += classScore
        }
        return int64(math.Round(float64(nodeScore) / float64(weightSum)))
    }
}
```

### SchedulerVolumeBinder

```GO
// SchedulerVolumeBinder由调度器的VolumeBinding插件用于处理PVC/PV的绑定和动态供应。绑定决策与Pod的其他调度要求一起集成到Pod调度工作流中，因此还考虑了PV的节点亲和性。

// 它与现有调度器工作流集成如下：
// 1. 调度器从调度器队列中取出一个Pod并逐个处理：
// a. 调用所有的前过滤插件。在此处调用GetPodVolumeClaims()，将保存当前调度周期状态中的Pod卷信息供后续使用。如果Pod有已绑定的立即使用的PVC，则调用GetEligibleNodes()以根据已绑定PV的节点亲和性（如果有）可能减少符合条件的节点列表。
// b. 调用所有的过滤插件，跨节点并行执行。在此处调用FindPodVolumes()。
// c. 调用所有的评分插件。未来/待定。
// d. 选择最佳节点用于Pod。
// e. 调用所有的预留插件。在此处调用AssumePodVolumes()。
// i. 如果需要PVC绑定，则仅缓存在内存中：
// * 对于手动绑定：更新PV对象以预绑定到相应的PVC。
// * 对于动态供应：更新PVC对象，选择来自c)的一个节点。
// * 对于Pod，需要进行API更新的PVC和PV。
// ii. 然后，主调度器将Pod->Node绑定缓存到调度器的Pod缓存中，这是在调度器中处理的，而不是在这里。
// f. 在单独的goroutine中异步绑定卷和Pod。
// i. 首先在PreBind阶段调用BindPodVolumes()。它进行所有必要的API更新，并等待PV控制器完全绑定和提供PVC。如果绑定失败，Pod将被发送回调度器。
// ii. 在BindPodVolumes()完成后，调度器执行最终的Pod->Node绑定。
// 2. 在e)中完成所有的假设操作后，调度器处理调度器队列中的下一个Pod，同时实际的绑定操作在后台进行。
type SchedulerVolumeBinder interface {
    // GetPodVolumeClaims将Pod的PVC分为已绑定的、延迟绑定的未绑定（包括供应）、立即绑定的未绑定（包括预绑定）以及属于延迟绑定的未绑定PVC的存储类PV。
    GetPodVolumeClaims(pod *v1.Pod) (podVolumeClaims *PodVolumeClaims, err error)
    // GetEligibleNodes检查Pod的现有已绑定声明，确定节点列表是否可以根据已绑定的声明可能减少为符合条件的节点子集，然后在后续的调度阶段中使用。
    //
    // 如果eligibleNodes为'nil'，则表示无法进行这种节点减少，并且应考虑所有节点。
    GetEligibleNodes(boundClaims []*v1.PersistentVolumeClaim) (eligibleNodes sets.Set[string])

    // FindPodVolumes检查Pod的所有PVC是否可以由节点满足，并返回Pod的卷信息。
    //
    // 如果PVC已绑定，则检查PV的节点亲和性是否与节点匹配。
    // 否则，尝试找到一个可用的PV来绑定到PVC。
    //
    // 如果发生错误或节点（当前）对Pod不可用，则返回错误列表。
    //
    // 如果启用了CSIStorageCapacity功能，则还会检查仍需要创建的卷的足够存储空间。
    //
    // 此函数由调度器的VolumeBinding插件调用，可以并行调用。
    FindPodVolumes(pod *v1.Pod, podVolumeClaims *PodVolumeClaims, node *v1.Node) (podVolumes *PodVolumes, reasons ConflictReasons, err error)

    // AssumePodVolumes将：
    // 1. 获取未绑定PVC的PV匹配项，并假设PV预先绑定到PVC，并更新PV缓存。
    // 2. 获取需要供应的PVC，并更新PVC缓存中的相关注释。
    //
    // 如果所有卷都完全绑定，则返回true。
    //
    // 此函数按顺序调用。
    AssumePodVolumes(assumedPod *v1.Pod, nodeName string, podVolumes *PodVolumes) (allFullyBound bool, err error)

    // RevertAssumedPodVolumes将还原假设的PV和PVC缓存。
    RevertAssumedPodVolumes(podVolumes *PodVolumes)

    // BindPodVolumes将：
    // 1. 通过API调用启动卷绑定，将PV预绑定到其匹配的PVC。
    // 2. 通过API调用设置PVC上的相关注释，触发卷供应。
    // 3. 等待PVC被PV控制器完全绑定。
    //
    // 此函数可以并行调用。
    BindPodVolumes(ctx context.Context, assumedPod *v1.Pod, podVolumes *PodVolumes) error
}
```

#### volumeBinder

```GO
type volumeBinder struct {
    kubeClient clientset.Interface

    classLister   storagelisters.StorageClassLister
    podLister     corelisters.PodLister
    nodeLister    corelisters.NodeLister
    csiNodeLister storagelisters.CSINodeLister

    pvcCache PVCAssumeCache
    pvCache  PVAssumeCache

    // 等待绑定操作成功的时间
    bindTimeout time.Duration

    translator InTreeToCSITranslator

    csiDriverLister          storagelisters.CSIDriverLister
    csiStorageCapacityLister storagelisters.CSIStorageCapacityLister
}
```

##### AssumeCache

```GO
// AssumeCache 是在 informer 之上构建的缓存，用于更新对象，还可以还原 informer 缓存中的对象。
// 假设对象是实现了 meta.Interface 的 Kubernetes API 对象。
type AssumeCache interface {
    // Assume 仅在内存中更新对象
    Assume(obj interface{}) error
    // 还原 informer 缓存中的对象
    Restore(objName string)
    // 根据名称获取对象
    Get(objName string) (interface{}, error)
    // 根据名称获取 API 对象
    GetAPIObj(objName string) (interface{}, error)
    // 列出缓存中的所有对象
    List(indexObj interface{}) []interface{}
}

// assumeCache 存储两个指针以表示单个对象：
// - 指向 informer 对象的指针。
// - 指向最新对象的指针，可以是与 informer 对象相同的对象，也可以是内存中的对象。
//
// informer 更新始终会覆盖最新对象指针。
//
// Assume() 只会更新最新对象指针。
// Restore() 将最新对象指针设置回 informer 对象。
// Get/List() 总是返回最新对象指针。
type assumeCache struct {
    // 用于同步对存储的更新
    rwMutex sync.RWMutex
    // 描述存储的对象
    description string
    // 存储 objInfo 指针
    store cache.Indexer
    // 对象的索引函数
    indexFunc cache.IndexFunc
    indexName string
}

// NewAssumeCache 创建一个通用对象的 assume cache。
func NewAssumeCache(informer cache.SharedIndexInformer, description, indexName string, indexFunc cache.IndexFunc) AssumeCache {
    c := &assumeCache{
    description: description,
    indexFunc: indexFunc,
    indexName: indexName,
    }
    indexers := cache.Indexers{}
    if indexName != "" && indexFunc != nil {
    	indexers[indexName] = c.objInfoIndexFunc
    }
    c.store = cache.NewIndexer(objInfoKeyFunc, indexers)

    // 单元测试不使用 informers
    if informer != nil {
        informer.AddEventHandler(
            cache.ResourceEventHandlerFuncs{
                AddFunc:    c.add,
                UpdateFunc: c.update,
                DeleteFunc: c.delete,
            },
        )
    }
    return c
}

func (c *assumeCache) add(obj interface{}) {
    // 如果对象为空，则直接返回
    if obj == nil {
    	return
    }
    // 获取对象的名称
    name, err := cache.MetaNamespaceKeyFunc(obj)
    if err != nil {
        klog.ErrorS(&errObjectName{err}, "Add failed")
        return
    }

    // 加锁以进行并发保护
    c.rwMutex.Lock()
    defer c.rwMutex.Unlock()

    // 检查对象是否已存在于缓存中
    if objInfo, _ := c.getObjInfo(name); objInfo != nil {
        // 获取新对象和已存储对象的版本号
        newVersion, err := c.getObjVersion(name, obj)
        if err != nil {
            klog.ErrorS(err, "Add failed: couldn't get object version")
            return
        }

        storedVersion, err := c.getObjVersion(name, objInfo.latestObj)
        if err != nil {
            klog.ErrorS(err, "Add failed: couldn't get stored object version")
            return
        }

        // 只有在新版本较新时才更新对象
        // 这样我们就不会因为 informer 的重新同步而覆盖已假设的对象
        if newVersion <= storedVersion {
            klog.V(10).InfoS("Skip adding object to assume cache because version is not newer than storedVersion", "description", c.description, "cacheKey", name, "newVersion", newVersion, "storedVersion", storedVersion)
            return
        }
    }

    // 创建一个新的 objInfo 对象，并更新存储
    objInfo := &objInfo{name: name, latestObj: obj, apiObj: obj}
    if err = c.store.Update(objInfo); err != nil {
        klog.InfoS("Error occurred while updating stored object", "err", err)
    } else {
        klog.V(10).InfoS("Adding object to assume cache", "description", c.description, "cacheKey", name, "assumeCache", obj)
    }
}

func (c *assumeCache) update(oldObj interface{}, newObj interface{}) {
    // 调用 add 方法来处理更新的对象
    c.add(newObj)
}

func (c *assumeCache) delete(obj interface{}) {
    // 如果对象为空，则直接返回
    if obj == nil {
    	return
    }
    // 获取对象的名称
    name, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
    if err != nil {
        klog.ErrorS(&errObjectName{err}, "Failed to delete")
        return
    }

    // 加锁以进行并发保护
    c.rwMutex.Lock()
    defer c.rwMutex.Unlock()

    // 创建一个包含对象名称的 objInfo 对象，并进行删除操作
    objInfo := &objInfo{name: name}
    err = c.store.Delete(objInfo)
    if err != nil {
        klog.ErrorS(err, "Failed to delete", "description", c.description, "cacheKey", name)
    }
}

func (c *assumeCache) getObjVersion(name string, obj interface{}) (int64, error) {
    // 获取对象的访问器
    objAccessor, err := meta.Accessor(obj)
    if err != nil {
    	return -1, err
    }

    // 解析对象的资源版本号
    objResourceVersion, err := strconv.ParseInt(objAccessor.GetResourceVersion(), 10, 64)
    if err != nil {
        return -1, fmt.Errorf("error parsing ResourceVersion %q for %v %q: %s", objAccessor.GetResourceVersion(), c.description, name, err)
    }
    return objResourceVersion, nil
}

func (c *assumeCache) getObjInfo(name string) (*objInfo, error) {
    // 根据对象名称从缓存中获取对象
    obj, ok, err := c.store.GetByKey(name)
    if err != nil {
    	return nil, err
    }
    if !ok {
    	return nil, &errNotFound{c.description, name}
    }

    // 将获取到的对象转换为 objInfo 类型
    objInfo, ok := obj.(*objInfo)
    if !ok {
        return nil, &errWrongType{"objInfo", obj}
    }
    return objInfo, nil
}

func (c *assumeCache) Get(objName string) (interface{}, error) {
    // 加读锁以进行并发保护
    c.rwMutex.RLock()
    defer c.rwMutex.RUnlock()

    // 获取对象信息
    objInfo, err := c.getObjInfo(objName)
    if err != nil {
        return nil, err
    }
    return objInfo.latestObj, nil
}

func (c *assumeCache) GetAPIObj(objName string) (interface{}, error) {
    // 加读锁以进行并发保护
    c.rwMutex.RLock()
    defer c.rwMutex.RUnlock()
    // 获取对象信息
    objInfo, err := c.getObjInfo(objName)
    if err != nil {
        return nil, err
    }
    return objInfo.apiObj, nil
}

func (c *assumeCache) List(indexObj interface{}) []interface{} {
    // 加读锁以进行并发保护
    c.rwMutex.RLock()
    defer c.rwMutex.RUnlock()

    // 存储所有对象的切片
    allObjs := []interface{}{}

    // 通过索引获取匹配的对象
    objs, err := c.store.Index(c.indexName, &objInfo{latestObj: indexObj})
    if err != nil {
        klog.ErrorS(err, "List index error")
        return nil
    }

    // 遍历匹配的对象，并将 latestObj 添加到 allObjs 中
    for _, obj := range objs {
        objInfo, ok := obj.(*objInfo)
        if !ok {
            klog.ErrorS(&errWrongType{"objInfo", obj}, "List error")
            continue
        }
        allObjs = append(allObjs, objInfo.latestObj)
    }
    return allObjs
}

func (c *assumeCache) Assume(obj interface{}) error {
    // 获取对象的名称和错误
    name, err := cache.MetaNamespaceKeyFunc(obj)
    if err != nil {
    	return &errObjectName{err}
    }
    // 加写锁以进行并发保护
    c.rwMutex.Lock()
    defer c.rwMutex.Unlock()

    // 获取对象信息
    objInfo, err := c.getObjInfo(name)
    if err != nil {
        return err
    }

    // 获取对象的版本号
    newVersion, err := c.getObjVersion(name, obj)
    if err != nil {
        return err
    }

    // 获取存储的对象版本号
    storedVersion, err := c.getObjVersion(name, objInfo.latestObj)
    if err != nil {
        return err
    }

    // 如果新版本号小于存储的版本号，则表示对象不同步
    if newVersion < storedVersion {
        return fmt.Errorf("%v %q is out of sync (stored: %d, assume: %d)", c.description, name, storedVersion, newVersion)
	}

	// 只更新缓存中的对象
	objInfo.latestObj = obj
	klog.V(4).InfoS("Assumed object", "description", c.description, "cacheKey", name, "version", newVersion)
	return nil
}

func (c *assumeCache) Restore(objName string) {
    // 加写锁以进行并发保护
    c.rwMutex.Lock()
    defer c.rwMutex.Unlock()
    // 获取对象信息
    objInfo, err := c.getObjInfo(objName)
    if err != nil {
        // 如果对象已被删除，可能会出现此情况
        klog.V(5).InfoS("Restore object", "description", c.description, "cacheKey", objName, "err", err)
	} else {
        // 将 latestObj 恢复为 apiObj
		objInfo.latestObj = objInfo.apiObj
		klog.V(4).InfoS("Restored object", "description", c.description, "cacheKey", objName)
	}
}

type objInfo struct {
    // 对象的名称
    name string
    // 最新版本的对象，可以是仅存在于缓存中的对象或来自 informer 的对象
    latestObj interface{}
    // 来自 informer 的最新对象
    apiObj interface{}
}

func objInfoKeyFunc(obj interface{}) (string, error) {
    objInfo, ok := obj.(*objInfo)
    if !ok {
    	return "", &errWrongType{"objInfo", obj}
    }
    return objInfo.name, nil
}

func (c *assumeCache) objInfoIndexFunc(obj interface{}) ([]string, error) {
    objInfo, ok := obj.(*objInfo)
    if !ok {
    	return []string{""}, &errWrongType{"objInfo", obj}
    }
    return c.indexFunc(objInfo.latestObj)
}
```

##### pvcAssumeCache

```GO
// PVCAssumeCache 是用于 PersistentVolumeClaim 对象的 AssumeCache 接口
type PVCAssumeCache interface {
	AssumeCache
	// GetPVC 从缓存中返回具有给定 pvcKey 的 PVC。
    // pvcKey 是对 PVC 对象的 MetaNamespaceKeyFunc 的结果
    GetPVC(pvcKey string) (*v1.PersistentVolumeClaim, error)
    GetAPIPVC(pvcKey string) (*v1.PersistentVolumeClaim, error)
}

// 定义一个名为 pvcAssumeCache 的结构体类型，该类型包含一个 AssumeCache 类型的成员变量。
type pvcAssumeCache struct {
	AssumeCache
}

// NewPVCAssumeCache 创建一个 PVC assume cache。
// 该函数接收一个 SharedIndexInformer 对象，并返回一个 PVCAssumeCache 类型的指针。
// 具体实现是创建一个 pvcAssumeCache 类型的对象，并调用 NewAssumeCache 函数初始化其 AssumeCache 成员变量。
func NewPVCAssumeCache(informer cache.SharedIndexInformer) PVCAssumeCache {
	return &pvcAssumeCache{NewAssumeCache(informer, "v1.PersistentVolumeClaim", "", nil)}
}

func (c *pvcAssumeCache) GetPVC(pvcKey string) (*v1.PersistentVolumeClaim, error) {
    // 使用结构体类型 pvcAssumeCache 的指针 c 调用其成员函数 Get 并传入参数 pvcKey，将结果保存在变量 obj 中，同时返回错误值 err。
    obj, err := c.Get(pvcKey)
    if err != nil {
    // 如果 Get 函数返回的错误值 err 不为 nil，则直接返回 nil 和 err。
    	return nil, err
    }

    // 将变量 obj 转换为类型 v1.PersistentVolumeClaim，并将结果保存在变量 pvc 中。如果转换失败，则返回错误值 &errWrongType{"v1.PersistentVolumeClaim", obj}。
    pvc, ok := obj.(*v1.PersistentVolumeClaim)
    if !ok {
    	return nil, &errWrongType{"v1.PersistentVolumeClaim", obj}
    }
    // 返回转换成功的 pvc 和 nil。
    return pvc, nil
}

// 方法 GetAPIPVC 与 GetPVC 类似，但使用的是 c.GetAPIObj 函数，其它部分相同。
func (c *pvcAssumeCache) GetAPIPVC(pvcKey string) (*v1.PersistentVolumeClaim, error) {
    obj, err := c.GetAPIObj(pvcKey)
    if err != nil {
    	return nil, err
    }
    pvc, ok := obj.(*v1.PersistentVolumeClaim)
    if !ok {
    	return nil, &errWrongType{"v1.PersistentVolumeClaim", obj}
    }
    return pvc, nil
}
```

##### PVAssumeCache

```go
// PVAssumeCache is a AssumeCache for PersistentVolume objects
type PVAssumeCache interface {
	AssumeCache

	GetPV(pvName string) (*v1.PersistentVolume, error)
	GetAPIPV(pvName string) (*v1.PersistentVolume, error)
	ListPVs(storageClassName string) []*v1.PersistentVolume
}

type pvAssumeCache struct {
	AssumeCache
}

func pvStorageClassIndexFunc(obj interface{}) ([]string, error) {
	if pv, ok := obj.(*v1.PersistentVolume); ok {
		return []string{storagehelpers.GetPersistentVolumeClass(pv)}, nil
	}
	return []string{""}, fmt.Errorf("object is not a v1.PersistentVolume: %v", obj)
}

// NewPVAssumeCache creates a PV assume cache.
func NewPVAssumeCache(informer cache.SharedIndexInformer) PVAssumeCache {
	return &pvAssumeCache{NewAssumeCache(informer, "v1.PersistentVolume", "storageclass", pvStorageClassIndexFunc)}
}

func (c *pvAssumeCache) GetPV(pvName string) (*v1.PersistentVolume, error) {
	// 调用 `c.Get` 方法获取 `pvName` 对应的对象及错误
	obj, err := c.Get(pvName)
	if err != nil {
		return nil, err
	}

	// 将获取到的对象转换成 `*v1.PersistentVolume` 类型
	pv, ok := obj.(*v1.PersistentVolume)
	if !ok {
		return nil, &errWrongType{"v1.PersistentVolume", obj}
	}
	// 返回获取到的 `*v1.PersistentVolume` 类型的对象及错误
	return pv, nil
}

func (c *pvAssumeCache) GetAPIPV(pvName string) (*v1.PersistentVolume, error) {
	// 调用 `c.GetAPIObj` 方法获取 `pvName` 对应的 API 对象及错误
	obj, err := c.GetAPIObj(pvName)
	if err != nil {
		return nil, err
	}
	// 将获取到的 API 对象转换成 `*v1.PersistentVolume` 类型
	pv, ok := obj.(*v1.PersistentVolume)
	if !ok {
		return nil, &errWrongType{"v1.PersistentVolume", obj}
	}
	// 返回获取到的 `*v1.PersistentVolume` 类型的对象及错误
	return pv, nil
}

func (c *pvAssumeCache) ListPVs(storageClassName string) []*v1.PersistentVolume {
	// 构造一个 `*v1.PersistentVolume` 类型的对象，用来过滤符合条件的持久卷
	objs := c.List(&v1.PersistentVolume{
		Spec: v1.PersistentVolumeSpec{
			StorageClassName: storageClassName,
		},
	})
	// 创建一个空的 `[]*v1.PersistentVolume` 类型的切片，用来存储符合条件的持久卷
	pvs := []*v1.PersistentVolume{}
	// 遍历过滤后的对象列表，将符合条件的对象添加到 `pvs` 切片中
	for _, obj := range objs {
		pv, ok := obj.(*v1.PersistentVolume)
		if !ok {
            // 如果获取到的对象不是 PersistentVolume
			klog.ErrorS(&errWrongType{"v1.PersistentVolume", obj}, "ListPVs")
			continue
		}
		pvs = append(pvs, pv)
	}
	return pvs
}
```

##### InTreeToCSITranslator

```GO
// InTreeToCSITranslator 包含了检查可迁移状态和从InTree PV转换为CSI的方法。
type InTreeToCSITranslator interface {
    // IsPVMigratable 检查PV是否可迁移
    IsPVMigratable(pv *v1.PersistentVolume) bool
    // GetInTreePluginNameFromSpec 从PV的spec中获取InTree插件名称
    GetInTreePluginNameFromSpec(pv *v1.PersistentVolume, vol *v1.Volume) (string, error)

    // TranslateInTreePVToCSI 将InTree PV转换为CSI
    TranslateInTreePVToCSI(pv *v1.PersistentVolume) (*v1.PersistentVolume, error)
}
```



#### NewVolumeBinder

```GO
// NewVolumeBinder设置所有为调度器做出卷绑定决策所需的缓存。
//
// capacityCheck确定如何检查存储容量（CSIStorageCapacity功能）。
func NewVolumeBinder(
    kubeClient clientset.Interface,
    podInformer coreinformers.PodInformer,
    nodeInformer coreinformers.NodeInformer,
    csiNodeInformer storageinformers.CSINodeInformer,
    pvcInformer coreinformers.PersistentVolumeClaimInformer,
    pvInformer coreinformers.PersistentVolumeInformer,
    storageClassInformer storageinformers.StorageClassInformer,
    capacityCheck CapacityCheck,
    bindTimeout time.Duration) SchedulerVolumeBinder {
    b := &volumeBinder{
        kubeClient: kubeClient,
        podLister: podInformer.Lister(),
        classLister: storageClassInformer.Lister(),
        nodeLister: nodeInformer.Lister(),
        csiNodeLister: csiNodeInformer.Lister(),
        pvcCache: NewPVCAssumeCache(pvcInformer.Informer()),
        pvCache: NewPVAssumeCache(pvInformer.Informer()),
        bindTimeout: bindTimeout,
        translator: csitrans.New(),
	}
    b.csiDriverLister = capacityCheck.CSIDriverInformer.Lister()
	b.csiStorageCapacityLister = capacityCheck.CSIStorageCapacityInformer.Lister()

	return b
}
```

#### 方法

```GO
// GetPodVolumeClaims 返回一个Pod的PVC（永久卷声明）列表，根据绑定情况分为已绑定、延迟绑定（包括Provisioning）、立即绑定（包括预绑定）和属于延迟绑定的未绑定PVC对应的PV（按存储类分组）。
func (b *volumeBinder) GetPodVolumeClaims(pod *v1.Pod) (podVolumeClaims *PodVolumeClaims, err error) {
    podVolumeClaims = &PodVolumeClaims{
        boundClaims: []*v1.PersistentVolumeClaim{},
        unboundClaimsImmediate: []*v1.PersistentVolumeClaim{},
        unboundClaimsDelayBinding: []*v1.PersistentVolumeClaim{},
    }
    for _, vol := range pod.Spec.Volumes {
        volumeBound, pvc, err := b.isVolumeBound(pod, &vol)
        if err != nil {
            return podVolumeClaims, err
        }
        if pvc == nil {
            continue
        }
        if volumeBound {
            podVolumeClaims.boundClaims = append(podVolumeClaims.boundClaims, pvc)
        } else {
            delayBindingMode, err := volume.IsDelayBindingMode(pvc, b.classLister)
            if err != nil {
                return podVolumeClaims, err
            }
            // 预绑定的PVC被视为立即绑定的未绑定PVC
            if delayBindingMode && pvc.Spec.VolumeName == "" {
                // 调度路径
                podVolumeClaims.unboundClaimsDelayBinding = append(podVolumeClaims.unboundClaimsDelayBinding, pvc)
            } else {
                // !delayBindingMode || pvc.Spec.VolumeName != ""
                // 立即绑定的未绑定PVC应已绑定
                podVolumeClaims.unboundClaimsImmediate = append(podVolumeClaims.unboundClaimsImmediate, pvc)
            }
        }
    }

    podVolumeClaims.unboundVolumesDelayBinding = map[string][]*v1.PersistentVolume{}
    for _, pvc := range podVolumeClaims.unboundClaimsDelayBinding {
        // 从每个PVC中获取存储类名
        storageClassName := volume.GetPersistentVolumeClaimClass(pvc)
        podVolumeClaims.unboundVolumesDelayBinding[storageClassName] = b.pvCache.ListPVs(storageClassName)
    }
    return podVolumeClaims, nil
}

// GetEligibleNodes 检查Pod的已绑定PVC，根据已绑定PVC来确定节点列表是否可以被潜在地缩减为一组符合条件的节点，
// 这些节点可以在后续的调度阶段中使用。
//
// 返回 nil 表示无法进行节点缩减，应考虑所有节点。
func (b *volumeBinder) GetEligibleNodes(boundClaims []*v1.PersistentVolumeClaim) (eligibleNodes sets.Set[string]) {
    if len(boundClaims) == 0 {
    	return
    }
    var errs []error
    for _, pvc := range boundClaims {
        pvName := pvc.Spec.VolumeName
        pv, err := b.pvCache.GetPV(pvName)
        if err != nil {
            errs = append(errs, err)
            continue
        }

        // 如果 PersistentVolume 是本地卷并具有与特定节点匹配的节点亲和性，
        // 将其添加到符合条件的节点列表中
        nodeNames := util.GetLocalPersistentVolumeNodeNames(pv)
        if len(nodeNames) != 0 {
            // 对于第一个找到的本地 PersistentVolume 的符合条件的节点列表，
            // 将其插入符合条件的节点集合中。
            if eligibleNodes == nil {
                eligibleNodes = sets.New(nodeNames...)
            } else {
                // 对于后续找到的本地 PersistentVolume 的符合条件的节点列表，
                // 取现有符合条件的节点集合与当前列表的交集，
                // 以防止 PV1 与节点1具有节点亲和性，而 PV2 与节点2具有节点亲和性的情况，
                // 那么符合条件的节点列表应为空。
                eligibleNodes = eligibleNodes.Intersection(sets.New(nodeNames...))
            }
        }
    }

    if len(errs) > 0 {
        klog.V(4).InfoS("GetEligibleNodes: 找到一个或多个错误的符合条件的节点", "error", errs)
        return nil
    }

    if eligibleNodes != nil {
        klog.V(4).InfoS("GetEligibleNodes: 缩减了符合条件的节点", "nodes", eligibleNodes)
    }
    return
}

// FindPodVolumes 根据给定的 Pod 和节点，查找匹配的 PVs 用于为 PVCs 和节点提供 PVs。
// 如果节点不符合条件，则返回冲突原因。
func (b *volumeBinder) FindPodVolumes(pod *v1.Pod, podVolumeClaims *PodVolumeClaims, node *v1.Node) (podVolumes *PodVolumes, reasons ConflictReasons, err error) {
	podVolumes = &PodVolumes{}
    // 警告：由于可能多次打印该日志信息 (#60933)，因此下面的日志需要高度详细。
    klog.V(5).InfoS("FindPodVolumes", "pod", klog.KObj(pod), "node", klog.KObj(node))

    // 对于没有卷的 Pod，初始化为 true。当函数返回且没有错误时，这些布尔值会被转换为原因字符串。
    unboundVolumesSatisfied := true
    boundVolumesSatisfied := true
    sufficientStorage := true
    boundPVsFound := true
    defer func() {
        if err != nil {
            return
        }
        if !boundVolumesSatisfied {
            reasons = append(reasons, ErrReasonNodeConflict)
        }
        if !unboundVolumesSatisfied {
            reasons = append(reasons, ErrReasonBindConflict)
        }
        if !sufficientStorage {
            reasons = append(reasons, ErrReasonNotEnoughSpace)
        }
        if !boundPVsFound {
            reasons = append(reasons, ErrReasonPVNotExist)
        }
    }()

    defer func() {
        if err != nil {
            metrics.VolumeSchedulingStageFailed.WithLabelValues("predicate").Inc()
        }
    }()

    var (
        staticBindings    []*BindingInfo
        dynamicProvisions []*v1.PersistentVolumeClaim
    )
    defer func() {
        // 虽然我们在这个函数中没有区分 nil 和空值，但为了方便测试，我们将空值规范化为 nil。
        if len(staticBindings) == 0 {
            staticBindings = nil
        }
        if len(dynamicProvisions) == 0 {
            dynamicProvisions = nil
        }
        podVolumes.StaticBindings = staticBindings
        podVolumes.DynamicProvisions = dynamicProvisions
    }()

    // 检查已绑定卷上的 PV 节点亲和性
    if len(podVolumeClaims.boundClaims) > 0 {
        boundVolumesSatisfied, boundPVsFound, err = b.checkBoundClaims(podVolumeClaims.boundClaims, node, pod)
        if err != nil {
            return
        }
    }

    // 查找匹配的卷和节点以及未绑定的声明
    if len(podVolumeClaims.unboundClaimsDelayBinding) > 0 {
        var (
            claimsToFindMatching []*v1.PersistentVolumeClaim
            claimsToProvision    []*v1.PersistentVolumeClaim
        )

        // 过滤出需要 provisioning 的声明
        for _, claim := range podVolumeClaims.unboundClaimsDelayBinding {
            if selectedNode, ok := claim.Annotations[volume.AnnSelectedNode]; ok {
                if selectedNode != node.Name {
                    // 快速路径，跳过不匹配的节点。
                    unboundVolumesSatisfied = false
                    return
                }
                claimsToProvision = append(claimsToProvision, claim)
			} else {
				claimsToFindMatching = append(claimsToFindMatching, claim)
			}
		}

		// 查找匹配的卷
		if len(claimsToFindMatching) > 0 {
			var unboundClaims []*v1.PersistentVolumeClaim
			unboundVolumesSatisfied, staticBindings, unboundClaims, err = b.findMatchingVolumes(pod, claimsToFindMatching, podVolumeClaims.unboundVolumesDelayBinding, node)
			if err != nil {
				return
			}
			claimsToProvision = append(claimsToProvision, unboundClaims...)
		}

		// 检查需要 provisioning 的声明。这是第一次我们可能发现存储不足以容纳节点。
		if len(claimsToProvision) > 0 {
			unboundVolumesSatisfied, sufficientStorage, dynamicProvisions, err = b.checkVolumeProvisions(pod, claimsToProvision, node)
			if err != nil {
				return
			}
		}
	}

	return
}

// AssumePodVolumes 函数将匹配的 PV 和 PVC 按照所选节点的要求设置为 Pod 的卷信息，并进行以下操作：
// 1. 使用新的预绑定 PV 更新 pvCache。
// 2. 使用设置了注释的新 PVC 更新 pvcCache。
// 3. 使用 PV 和 PVC 的缓存 API 更新再次更新 PodVolumes。
func (b *volumeBinder) AssumePodVolumes(assumedPod *v1.Pod, nodeName string, podVolumes *PodVolumes) (allFullyBound bool, err error) {
klog.V(4).InfoS("AssumePodVolumes", "pod", klog.KObj(assumedPod), "node", klog.KRef("", nodeName))
    defer func() {
        if err != nil {
        	metrics.VolumeSchedulingStageFailed.WithLabelValues("assume").Inc()
        }
    }()
	if allBound := b.arePodVolumesBound(assumedPod); allBound {
        klog.V(4).InfoS("AssumePodVolumes: 所有 PVC 均已绑定，无需操作", "pod", klog.KObj(assumedPod), "node", klog.KRef("", nodeName))
        return true, nil
    }

    // 假设 PV
    newBindings := []*BindingInfo{}
    for _, binding := range podVolumes.StaticBindings {
        newPV, dirty, err := volume.GetBindVolumeToClaim(binding.pv, binding.pvc)
        klog.V(5).InfoS("AssumePodVolumes: GetBindVolumeToClaim",
            "pod", klog.KObj(assumedPod),
            "PV", klog.KObj(binding.pv),
            "PVC", klog.KObj(binding.pvc),
             "newPV", klog.KObj(newPV),
             "dirty", dirty,
        )
        if err != nil {
            klog.ErrorS(err, "AssumePodVolumes: 获取绑定的 PV 失败")
            b.revertAssumedPVs(newBindings)
            return false, err
        }
        // TODO: 是否每次都需要假设？
        if dirty {
            err = b.pvCache.Assume(newPV)
            if err != nil {
                b.revertAssumedPVs(newBindings)
                return false, err
            }
        }
        newBindings = append(newBindings, &BindingInfo{pv: newPV, pvc: binding.pvc})
    }

    // 假设 PVC
    newProvisionedPVCs := []*v1.PersistentVolumeClaim{}
    for _, claim := range podVolumes.DynamicProvisions {
        // 从方法参数中获取的声明可能指向观察者缓存，因此不能修改它们，因此需要创建一个副本。
        claimClone := claim.DeepCopy()
        metav1.SetMetaDataAnnotation(&claimClone.ObjectMeta, volume.AnnSelectedNode, nodeName)
        err = b.pvcCache.Assume(claimClone)
        if err != nil {
            b.revertAssumedPVs(newBindings)
            b.revertAssumedPVCs(newProvisionedPVCs)
            return
        }

        newProvisionedPVCs = append(newProvisionedPVCs, claimClone)
    }

    podVolumes.StaticBindings = newBindings
    podVolumes.DynamicProvisions = newProvisionedPVCs
    return
}

// RevertAssumedPodVolumes 函数将恢复假设的 PV 和 PVC 缓存。
func (b *volumeBinder) RevertAssumedPodVolumes(podVolumes *PodVolumes) {
    b.revertAssumedPVs(podVolumes.StaticBindings)
    b.revertAssumedPVCs(podVolumes.DynamicProvisions)
}

// BindPodVolumes 函数获取缓存的绑定和 PVC，按照 Pod 的卷信息进行 API 更新，并等待 PVC 完全绑定到 PV 控制器。
func (b *volumeBinder) BindPodVolumes(ctx context.Context, assumedPod *v1.Pod, podVolumes *PodVolumes) (err error) {
    klog.V(4).InfoS("BindPodVolumes", "pod", klog.KObj(assumedPod), "node", klog.KRef("", assumedPod.Spec.NodeName))
    defer func() {
        if err != nil {
            metrics.VolumeSchedulingStageFailed.WithLabelValues("bind").Inc()
        }
    }()

    bindings := podVolumes.StaticBindings
    claimsToProvision := podVolumes.DynamicProvisions

    // 开始 API 操作
    err = b.bindAPIUpdate(ctx, assumedPod, bindings, claimsToProvision)
    if err != nil {
        return err
    }

    err = wait.Poll(time.Second, b.bindTimeout, func() (bool, error) {
        b, err := b.checkBindings(assumedPod, bindings, claimsToProvision)
        return b, err
    })
    if err != nil {
        return fmt.Errorf("binding volumes: %w", err)
    }
    return nil
}
```

##### isVolumeBound

```go
func (b *volumeBinder) isVolumeBound(pod *v1.Pod, vol *v1.Volume) (bound bool, pvc *v1.PersistentVolumeClaim, err error) {
    pvcName := ""
    isEphemeral := false
    switch {
        case vol.PersistentVolumeClaim != nil:
        	pvcName = vol.PersistentVolumeClaim.ClaimName
        case vol.Ephemeral != nil:
            // 通用的临时内联卷也使用一个 PVC，只是具有计算得出的名称，而且...
            pvcName = ephemeral.VolumeClaimName(pod, vol)
            isEphemeral = true
        default:
        	return true, nil, nil
    }
    bound, pvc, err = b.isPVCBound(pod.Namespace, pvcName)
    // ...该 PVC 必须由该 Pod 拥有。
    if isEphemeral && err == nil && pvc != nil {
        if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {
            return false, nil, err
        }
    }
    return
}
```

###### isPVCBound

```go
func (b *volumeBinder) isPVCBound(namespace, pvcName string) (bool, *v1.PersistentVolumeClaim, error) {
	claim := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: namespace,
		},
	}
	pvcKey := getPVCName(claim)
	pvc, err := b.pvcCache.GetPVC(pvcKey)
	if err != nil || pvc == nil {
		return false, nil, fmt.Errorf("error getting PVC %q: %v", pvcKey, err)
	}

	fullyBound := b.isPVCFullyBound(pvc)
	if fullyBound {
		klog.V(5).InfoS("PVC is fully bound to PV", "PVC", klog.KObj(pvc), "PV", klog.KRef("", pvc.Spec.VolumeName))
	} else {
		if pvc.Spec.VolumeName != "" {
			klog.V(5).InfoS("PVC is not fully bound to PV", "PVC", klog.KObj(pvc), "PV", klog.KRef("", pvc.Spec.VolumeName))
		} else {
			klog.V(5).InfoS("PVC is not bound", "PVC", klog.KObj(pvc))
		}
	}
	return fullyBound, pvc, nil
}
```

##### checkBoundClaims

```GO
// 定义一个方法volumeBinder.checkBoundClaims，接收三个参数：v1.PersistentVolumeClaim类型的slice claims、v1.Node类型的node、v1.Pod类型的pod，并返回两个bool类型的值和一个error类型的值
func (b *volumeBinder) checkBoundClaims(claims []*v1.PersistentVolumeClaim, node *v1.Node, pod *v1.Pod) (bool, bool, error) {
    // 获取node对应的CSINode对象
    csiNode, err := b.csiNodeLister.Get(node.Name)
    if err != nil {
        // 如果获取CSINode对象失败，输出日志
        // TODO: return the error once CSINode is created by default
        klog.V(4).InfoS("Could not get a CSINode object for the node", "node", klog.KObj(node), "err", err)
    }

    // 遍历claims中的每一个元素pvc
    for _, pvc := range claims {
        // 获取pvc对应的pv对象
        pvName := pvc.Spec.VolumeName
        pv, err := b.pvCache.GetPV(pvName)
        if err != nil {
            // 如果获取pv对象失败，且错误类型是errNotFound，则将err设为nil，否则直接返回错误
            if _, ok := err.(*errNotFound); ok {
                err = nil
            }
            return true, false, err
        }

        // 尝试将pv对象转化为CSI类型的pv对象
        pv, err = b.tryTranslatePVToCSI(pv, csiNode)
        if err != nil {
            // 如果转化失败，则直接返回错误
            return false, true, err
        }

        // 检查pv对象的节点亲和性是否符合node的标签要求
        err = volume.CheckNodeAffinity(pv, node.Labels)
        if err != nil {
            // 如果不符合，则输出日志，并返回两个bool类型的值(false, true)和一个nil的错误
            klog.V(4).InfoS("PersistentVolume and node mismatch for pod", "PV", klog.KRef("", pvName), "node", klog.KObj(node), "pod", klog.KObj(pod), "err", err)
            return false, true, nil
        }
        // 如果符合，则输出日志，并继续下一个pvc的检查
        klog.V(5).InfoS("PersistentVolume and node matches for pod", "PV", klog.KRef("", pvName), "node", klog.KObj(node), "pod", klog.KObj(pod))
    }

    // 如果所有的pvc检查通过，则输出日志，返回两个bool类型的值(true, true)和一个nil的错误
    klog.V(4).InfoS("All bound volumes for pod match with node", "pod", klog.KObj(pod), "node", klog.KObj(node))
    return true, true, nil
}
```



```GO
// 定义一个方法volumeBinder.findMatchingVolumes，接收四个参数：v1.Pod类型的pod、[]*v1.PersistentVolumeClaim类型的slice claimsToBind、map[string][]*v1.PersistentVolume类型的unboundVolumesDelayBinding和v1.Node类型的node，并返回四个值：bool类型的foundMatches、[]*BindingInfo类型的bindings、[]*v1.PersistentVolumeClaim类型的unboundClaims和error类型的err。
func (b *volumeBinder) findMatchingVolumes(pod *v1.Pod, claimsToBind []*v1.PersistentVolumeClaim, unboundVolumesDelayBinding map[string][]*v1.PersistentVolume, node *v1.Node) (foundMatches bool, bindings []*BindingInfo, unboundClaims []*v1.PersistentVolumeClaim, err error) {
	// 按照PVC的大小请求进行升序排序，以获取最小的匹配
    sort.Sort(byPVCSize(claimsToBind))

    // chosenPVs用于存储已选择的PV，key为PV的名称，value为PV对象
    chosenPVs := map[string]*v1.PersistentVolume{}

    foundMatches = true

    for _, pvc := range claimsToBind {
        // 从每个PVC中获取存储类名称
        storageClassName := volume.GetPersistentVolumeClaimClass(pvc)
        pvs := unboundVolumesDelayBinding[storageClassName]

        // 查找匹配的PV
        pv, err := volume.FindMatchingVolume(pvc, pvs, node, chosenPVs, true)
        if err != nil {
            // 如果查找匹配的PV出错，则返回错误
            return false, nil, nil, err
        }
        if pv == nil {
            // 如果未找到匹配的PV，则输出日志，将该PVC添加到unboundClaims中，设置foundMatches为false，并继续下一个PVC的匹配
            klog.V(4).InfoS("No matching volumes for pod", "pod", klog.KObj(pod), "PVC", klog.KObj(pvc), "node", klog.KObj(node))
            unboundClaims = append(unboundClaims, pvc)
            foundMatches = false
            continue
        }

        // 将匹配的PV添加到chosenPVs中，以防止再次选择
        chosenPVs[pv.Name] = pv
        // 将匹配信息存储到bindings中
        bindings = append(bindings, &BindingInfo{pv: pv, pvc: pvc})
        klog.V(5).InfoS("Found matching PV for PVC for pod", "PV", klog.KObj(pv), "PVC", klog.KObj(pvc), "node", klog.KObj(node), "pod", klog.KObj(pod))
    }

    if foundMatches {
        // 如果找到了匹配的PV，则输出日志
        klog.V(4).InfoS("Found matching volumes for pod", "pod", klog.KObj(pod), "node", klog.KObj(node))
    }

    return
}
```

##### checkVolumeProvisions

```GO
// 定义一个方法volumeBinder.checkVolumeProvisions，接收三个参数：v1.Pod类型的pod、[]*v1.PersistentVolumeClaim类型的slice claimsToProvision和v1.Node类型的node，并返回四个值：bool类型的provisionSatisfied、sufficientStorage，[]*v1.PersistentVolumeClaim类型的slice dynamicProvisions和error类型的err。
func (b *volumeBinder) checkVolumeProvisions(pod *v1.Pod, claimsToProvision []*v1.PersistentVolumeClaim, node *v1.Node) (provisionSatisfied, sufficientStorage bool, dynamicProvisions []*v1.PersistentVolumeClaim, err error) {
	dynamicProvisions = []*v1.PersistentVolumeClaim{}
    // 如果检查失败或遇到错误，提前返回nil的provisionedClaims
    for _, claim := range claimsToProvision {
        pvcName := getPVCName(claim)
        className := volume.GetPersistentVolumeClaimClass(claim)
        if className == "" {
            // 如果claim没有指定存储类名称，返回错误
            return false, false, nil, fmt.Errorf("no class for claim %q", pvcName)
        }

        class, err := b.classLister.Get(className)
        if err != nil {
            // 如果获取存储类对象失败，返回错误
            return false, false, nil, fmt.Errorf("failed to find storage class %q", className)
        }
        provisioner := class.Provisioner
        if provisioner == "" || provisioner == volume.NotSupportedProvisioner {
            // 如果存储类的provisioner为空或为NotSupportedProvisioner，则输出日志，返回(true, false, nil, nil)
            klog.V(4).InfoS("Storage class of claim does not support dynamic provisioning", "storageClassName", className, "PVC", klog.KObj(claim))
            return false, true, nil, nil
        }

        // 检查节点是否满足存储类的拓扑要求
        if !v1helper.MatchTopologySelectorTerms(class.AllowedTopologies, labels.Set(node.Labels)) {
            // 如果节点无法满足拓扑要求，则输出日志，返回(true, false, nil, nil)
            klog.V(4).InfoS("Node cannot satisfy provisioning topology requirements of claim", "node", klog.KObj(node), "PVC", klog.KObj(claim))
            return false, true, nil, nil
        }

        // 检查存储容量
        sufficient, err := b.hasEnoughCapacity(provisioner, claim, class, node)
        if err != nil {
            // 如果检查存储容量出错，返回错误
            return false, false, nil, err
        }
        if !sufficient {
            // 如果存储容量不足，则hasEnoughCapacity函数会输出解释日志，返回(true, false, nil, nil)
            return true, false, nil, nil
        }

        // 将该claim添加到dynamicProvisions中
        dynamicProvisions = append(dynamicProvisions, claim)

    }
    // 输出日志，表示正在为没有匹配卷的pod进行配额检查
    klog.V(4).InfoS("Provisioning for claims of pod that has no matching volumes...", "claimCount", len(claimsToProvision), "pod", klog.KObj(pod), "node", klog.KObj(node))

	return true, true, dynamicProvisions, nil
}
```

##### arePodVolumesBound

```GO
// 定义一个方法volumeBinder.arePodVolumesBound，接收一个参数：v1.Pod类型的pod，并返回一个bool类型的值。
// 该方法用于判断pod的所有卷是否都已完全绑定。
func (b *volumeBinder) arePodVolumesBound(pod *v1.Pod) bool {
	for _, vol := range pod.Spec.Volumes {
        if isBound, _, _ := b.isVolumeBound(pod, &vol); !isBound {
            // Pod至少有一个需要绑定的PVC
            return false
        }
    }
    return true
}
```

##### revertAssumedPVs

```GO
// 定义一个方法volumeBinder.revertAssumedPVs，接收一个参数：[]*BindingInfo类型的bindings。
// 该方法用于还原先前假设绑定的PV。
func (b *volumeBinder) revertAssumedPVs(bindings []*BindingInfo) {
    for _, BindingInfo := range bindings {
    	b.pvCache.Restore(BindingInfo.pv.Name)
    }
}
```

##### revertAssumedPVCs

```GO
// 定义一个方法volumeBinder.revertAssumedPVCs，接收一个参数：[]*v1.PersistentVolumeClaim类型的claims。
// 该方法用于还原先前假设绑定的PVC。
func (b *volumeBinder) revertAssumedPVCs(claims []*v1.PersistentVolumeClaim) {
    for _, claim := range claims {
    	b.pvcCache.Restore(getPVCName(claim))
    }
}
```

##### bindAPIUpdate

```GO
// 定义一个方法volumeBinder.bindAPIUpdate，接收三个参数：context.Context类型的ctx，v1.Pod类型的pod，[]*BindingInfo类型的bindings，[]*v1.PersistentVolumeClaim类型的claimsToProvision，并返回一个error类型的值。
// 该方法用于执行API更新操作，绑定PVs/PVCs。
func (b *volumeBinder) bindAPIUpdate(ctx context.Context, pod *v1.Pod, bindings []*BindingInfo, claimsToProvision []*v1.PersistentVolumeClaim) error {
	podName := getPodName(pod)
	if bindings == nil {
		return fmt.Errorf("failed to get cached bindings for pod %q", podName)
	}
	if claimsToProvision == nil {
		return fmt.Errorf("failed to get cached claims to provision for pod %q", podName)
	}

	lastProcessedBinding := 0
	lastProcessedProvisioning := 0
	defer func() {
		// 只还原尚未成功绑定的PV的假设缓存更新
		if lastProcessedBinding < len(bindings) {
			b.revertAssumedPVs(bindings[lastProcessedBinding:])
		}
		// 只还原尚未成功更新的声明的假设缓存更新
		if lastProcessedProvisioning < len(claimsToProvision) {
			b.revertAssumedPVCs(claimsToProvision[lastProcessedProvisioning:])
		}
	}()

	var (
		binding *BindingInfo
		i       int
		claim   *v1.PersistentVolumeClaim
	)

	// 执行实际的预绑定操作，其他操作交给PV控制器处理
	// 如果实际绑定失败，不会进行API回滚
	for _, binding = range bindings {
		// TODO: 如果我们进行API调用但没有需要更新的内容，是否会有影响？
		klog.V(5).InfoS("Updating PersistentVolume: binding to claim", "pod", klog.KObj(pod), "PV", klog.KObj(binding.pv), "PVC", klog.KObj(binding.pvc))
		newPV, err := b.kubeClient.CoreV1().PersistentVolumes().Update(ctx, binding.pv, metav1.UpdateOptions{})
		if err != nil {
			klog.V(4).InfoS("Updating PersistentVolume: binding to claim failed", "pod", klog.KObj(pod), "PV", klog.KObj(binding.pv), "PVC", klog.KObj(binding.pvc), "err", err)
			return err
		}

		klog.V(2).InfoS("Updated PersistentVolume with claim. Waiting for binding to complete", "pod", klog.KObj(pod), "PV", klog.KObj(binding.pv), "PVC", klog.KObj(binding.pvc))
		// 保存apiserver返回的更新后的对象以供后续检查
		binding.pv = newPV
		lastProcessedBinding++
	}

	// 更新声明对象以触发卷的预配，其他操作交给PV控制器处理
	// 如果实际预配失败，PV控制器应通过删除相关注释来发出信号
	for i, claim = range claimsToProvision {
		klog.V(5).InfoS("Updating claims objects to trigger volume provisioning", "pod", klog.KObj(pod), "PVC", klog.KObj(claim))
		newClaim, err := b.kubeClient.CoreV1().PersistentVolumeClaims(claim.Namespace).Update(ctx, claim, metav1.UpdateOptions{})
		if err != nil {
			klog.V(4).InfoS("Updating PersistentVolumeClaim: binding to volume failed", "PVC", klog.KObj(claim), "err", err)
			return err
		}

		// 保存apiserver返回的更新后的对象以供后续检查
		claimsToProvision[i] = newClaim
		lastProcessedProvisioning++
	}

	return nil
}
```



```GO
// checkBindings函数用于遍历Pod中的所有PVC并进行检查：
// * PVC是否完全绑定
// * 是否存在需要失败并重试绑定的条件
//
// 当Pod的所有PVC都完全绑定时返回true，如果需要重试绑定（和调度），则返回错误
// 需要注意的是，它检查API对象而不是PV/PVC缓存，这是因为在主调度循环中可以再次假定PV/PVC缓存，我们必须检查
// 与PV控制器和提供程序共享的API服务器中的最新状态
func (b *volumeBinder) checkBindings(pod *v1.Pod, bindings []*BindingInfo, claimsToProvision []*v1.PersistentVolumeClaim) (bool, error) {
	podName := getPodName(pod)
	if bindings == nil {
		return false, fmt.Errorf("failed to get cached bindings for pod %q", podName)
	}
	if claimsToProvision == nil {
		return false, fmt.Errorf("failed to get cached claims to provision for pod %q", podName)
	}

	node, err := b.nodeLister.Get(pod.Spec.NodeName)
	if err != nil {
		return false, fmt.Errorf("failed to get node %q: %w", pod.Spec.NodeName, err)
	}

	csiNode, err := b.csiNodeLister.Get(node.Name)
	if err != nil {
		// TODO: 一旦默认创建了CSINode对象，就返回错误
		klog.V(4).InfoS("Could not get a CSINode object for the node", "node", klog.KObj(node), "err", err)
	}

	// 检查可能需要重试调度的条件
	// 当Pod被删除时，绑定操作应被取消。不再需要检查PV/PVC的绑定。
	_, err = b.podLister.Pods(pod.Namespace).Get(pod.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, fmt.Errorf("pod does not exist any more: %w", err)
		}
		klog.ErrorS(err, "Failed to get pod from the lister", "pod", klog.KObj(pod))
	}

	for _, binding := range bindings {
		pv, err := b.pvCache.GetAPIPV(binding.pv.Name)
		if err != nil {
			return false, fmt.Errorf("failed to check binding: %w", err)
		}

		pvc, err := b.pvcCache.GetAPIPVC(getPVCName(binding.pvc))
		if err != nil {
			return false, fmt.Errorf("failed to check binding: %w", err)
		}

		// 因为我们在API服务器中更新了PV，所以如果API对象较旧，则跳过并等待从API服务器传播的新API对象。
		if versioner.CompareResourceVersion(binding.pv, pv) > 0 {
			return false, nil
		}

		pv, err = b.tryTranslatePVToCSI(pv, csiNode)
		if err != nil {
			return false, fmt.Errorf("failed to translate pv to csi: %w", err)
		}

		// 检查PV的节点亲和性（节点可能没有正确的标签）
		if err := volume.CheckNodeAffinity(pv, node.Labels); err != nil {
			return false, fmt.Errorf("pv %q node affinity doesn't match node %q: %w", pv.Name, node.Name, err)
		}

		// 检查pv.ClaimRef是否被unbindVolume()函数删除
		if pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID == "" {
			return false, fmt.Errorf("ClaimRef got reset for pv %q", pv.Name)
		}

		// 检查pvc是否完全绑定
		if !b.isPVCFullyBound(pvc) {
			return false, nil
		}
	}

	for _, claim := range claimsToProvision {
		pvc, err := b.pvcCache.GetAPIPVC(getPVCName(claim))
		if err != nil {
			return false, fmt.Errorf("failed to check provisioning pvc: %w", err)
		}

		// 因为我们在API服务器中更新了PVC，所以如果API对象较旧，则跳过并等待从API服务器传播的新API对象。
		if versioner.CompareResourceVersion(claim, pvc) > 0 {
			return false, nil
		}

		// 检查selectedNode注释是否仍然设置
		if pvc.Annotations == nil {
			return false, fmt.Errorf("selectedNode annotation reset for PVC %q", pvc.Name)
		}
		selectedNode := pvc.Annotations[volume.AnnSelectedNode]
		if selectedNode != pod.Spec.NodeName {
			// 如果提供程序无法提供卷，则会删除selectedNode注释，以向调度器发出重试信号。
			return false, fmt.Errorf("provisioning failed for PVC %q", pvc.Name)
		}

		// 如果PVC绑定到了PV，检查其节点亲和性
		if pvc.Spec.VolumeName != "" {
			pv, err := b.pvCache.GetAPIPV(pvc.Spec.VolumeName)
			if err != nil {
				if _, ok := err.(*errNotFound); ok {
					// 我们在这里容忍NotFound错误，因为PV可能因为API延迟而找不到，我们可以下次再检查。
					// 如果PV不存在是因为它已被删除，PVC最终将解绑。
					return false, nil
				}
				return false, fmt.Errorf("failed to get pv %q from cache: %w", pvc.Spec.VolumeName, err)
			}

			pv, err = b.tryTranslatePVToCSI(pv, csiNode)
			if err != nil {
				return false, err
			}

			if err := volume.CheckNodeAffinity(pv, node.Labels); err != nil {
				return false, fmt.Errorf("pv %q node affinity doesn't match node %q: %w", pv.Name, node.Name, err)
			}
		}

		// 检查pvc是否完全绑定
		if !b.isPVCFullyBound(pvc) {
			return false, nil
		}
	}

	// 所有我们操作过的pvs和pvcs都已绑定
	klog.V(2).InfoS("All PVCs for pod are bound", "pod", klog.KObj(pod))
	return true, nil
}
```

### PreFilter&PreFilterExtensions

```GO
// PreFilter在预过滤扩展点调用，用于检查是否所有立即使用的PVC都已绑定。如果不是所有立即使用的PVC都已绑定，则返回UnschedulableAndUnresolvable。
func (pl *VolumeBinding) PreFilter(ctx context.Context, state *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 如果pod没有引用任何PVC，我们不需要做任何处理。
    if hasPVC, err := pl.podHasPVCs(pod); err != nil {
    	return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, err.Error())
    } else if !hasPVC {
        state.Write(stateKey, &stateData{})
        return nil, framework.NewStatus(framework.Skip)
    }
    // 获取pod的卷声明。
    podVolumeClaims, err := pl.Binder.GetPodVolumeClaims(pod)
    if err != nil {
    	return nil, framework.AsStatus(err)
    }
    if len(podVolumeClaims.unboundClaimsImmediate) > 0 {
        // 如果立即使用的声明未绑定，则返回UnschedulableAndUnresolvable错误。这些声明在PV控制器绑定后，将将Pod移至活动/退避队列。
        status := framework.NewStatus(framework.UnschedulableAndUnresolvable)
        status.AppendReason("pod has unbound immediate PersistentVolumeClaims")
        return nil, status
    }
    // 如果pod有绑定的声明，则尝试减少后续调度阶段要考虑的节点数量。
    var result *framework.PreFilterResult
    if eligibleNodes := pl.Binder.GetEligibleNodes(podVolumeClaims.boundClaims); eligibleNodes != nil {
            result = &framework.PreFilterResult{
            NodeNames: eligibleNodes,
    	}
    }
    state.Write(stateKey, &stateData{
        podVolumesByNode: make(map[string]*PodVolumes),
        podVolumeClaims: &PodVolumeClaims{
            boundClaims:                podVolumeClaims.boundClaims,
            unboundClaimsDelayBinding:  podVolumeClaims.unboundClaimsDelayBinding,
            unboundVolumesDelayBinding: podVolumeClaims.unboundVolumesDelayBinding,
        },
	})
	return result, nil
}

func (pl *VolumeBinding) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

#### podHasPVCs

```GO
// podHasPVCs 函数返回 2 个值：
// - 第一个值用于表示给定的 “pod” 是否定义了任何 PVC。
// - 第二个值用于返回任何错误，如果请求的 PVC 不合法。
func (pl *VolumeBinding) podHasPVCs(pod *v1.Pod) (bool, error) {
    hasPVC := false // 初始化变量 hasPVC 为 false
    for _, vol := range pod.Spec.Volumes { // 遍历 Pod 的 Volumes
        var pvcName string
        isEphemeral := false
        switch {
            case vol.PersistentVolumeClaim != nil: // 如果 Volume 是使用了 PersistentVolumeClaim
                pvcName = vol.PersistentVolumeClaim.ClaimName // 获取 PVC 的名称
            case vol.Ephemeral != nil: // 如果 Volume 是使用了 EphemeralVolumeSource
                pvcName = ephemeral.VolumeClaimName(pod, &vol) // 获取 Ephemeral VolumeClaim 的名称
                isEphemeral = true
            default:
                // Volume 不使用 PVC，忽略
                continue
        }
        hasPVC = true // 标记 Pod 中有 PVC
        pvc, err := pl.PVCLister.PersistentVolumeClaims(pod.Namespace).Get(pvcName) // 获取 PVC 对象
        if err != nil {
            // 错误通常已经有足够的上下文信息（"persistentvolumeclaim "myclaim" not found"），
            // 但对于普通的临时内联卷，在创建 Pod 后直接出现这种情况是正常的，
            // 因此我们可以做得更好。
            if isEphemeral && apierrors.IsNotFound(err) {
                err = fmt.Errorf("waiting for ephemeral volume controller to create the persistentvolumeclaim %q", pvcName)
            }
            return hasPVC, err // 返回错误
        }

        if pvc.Status.Phase == v1.ClaimLost {  // 如果 PVC 的状态为 ClaimLost
            return hasPVC, fmt.Errorf("persistentvolumeclaim %q bound to non-existent persistentvolume %q", pvc.Name, pvc.Spec.VolumeName)  // 返回错误
        }

        if pvc.DeletionTimestamp != nil {  // 如果 PVC 被删除
            return hasPVC, fmt.Errorf("persistentvolumeclaim %q is being deleted", pvc.Name)  // 返回错误
        }

        if isEphemeral {  // 如果是临时内联卷
            if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {  // 判断该 PVC 是否属于该 Pod
                return hasPVC, err  // 返回错误
            }
        }
    }
	return hasPVC, nil  // 返回是否存在 PVC 和错误信息（没有错误时为 nil）
}
```

#### stateData

```GO
// 状态在PreFilter阶段初始化。因为我们将指针保存在framework.CycleState中，在后续阶段中不需要调用Write方法来更新值。
type stateData struct {
    allBound bool
    // podVolumesByNode保存在过滤阶段为每个节点找到的Pod的卷信息
    // 它在PreFilter阶段进行初始化
    podVolumesByNode map[string]*PodVolumes
    podVolumeClaims *PodVolumeClaims
    sync.Mutex
}

func (d *stateData) Clone() framework.StateData {
	return d
}
```

### Filter

```GO
// Filter 在过滤器扩展点被调用。
// 它评估一个Pod是否可以适应其请求的卷，对于已绑定和未绑定的PVC都适用。
//
// 对于已绑定的PVC，它检查相应PV的节点亲和性是否满足给定的节点。
//
// 对于未绑定的PVC，它尝试找到可以满足PVC要求且PV节点亲和性满足给定节点的可用PV。
//
// 如果启用了存储容量跟踪，则必须为节点和仍需创建的卷提供足够的空间。
//
// 如果所有已绑定的PVC都有与节点兼容的PV，并且所有未绑定的PVC可以与可用且与节点兼容的PV匹配，则返回true。
func (pl *VolumeBinding) Filter(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    node := nodeInfo.Node()
    if node == nil {
    	return framework.NewStatus(framework.Error, "未找到节点")
    }
    state, err := getStateData(cs)
    if err != nil {
        return framework.AsStatus(err)
    }

    podVolumes, reasons, err := pl.Binder.FindPodVolumes(pod, state.podVolumeClaims, node)

    if err != nil {
        return framework.AsStatus(err)
    }

    if len(reasons) > 0 {
        status := framework.NewStatus(framework.UnschedulableAndUnresolvable)
        for _, reason := range reasons {
            status.AppendReason(string(reason))
        }
        return status
    }

    // 多个goroutine同时在不同的节点上调用`Filter`，`CycleState`可能会重复，因此我们必须在这里使用一个局部锁
    state.Lock()
    state.podVolumesByNode[node.Name] = podVolumes
    state.Unlock()
    return nil
}
```

#### getStateData

```GO
// getStateData 从 CycleState 中获取状态数据。
func getStateData(cs *framework.CycleState) (*stateData, error) {
    state, err := cs.Read(stateKey)
    if err != nil {
    	return nil, err
    }
    s, ok := state.(*stateData)
    if !ok {
    	return nil, errors.New("无法将状态转换为 stateData 类型")
    }
    return s, nil
}
```

### Score&ScoreExtensions

```GO
// Score 在评分扩展点被调用。
func (pl *VolumeBinding) Score(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    if pl.scorer == nil {
    	return 0, nil
    }
    state, err := getStateData(cs)
    if err != nil {
    	return 0, framework.AsStatus(err)
    }
    podVolumes, ok := state.podVolumesByNode[nodeName]
    if !ok {
   		return 0, nil
    }
    // 按存储类进行分组
    classResources := make(classResourceMap)
    for _, staticBinding := range podVolumes.StaticBindings {
        class := staticBinding.StorageClassName()
        storageResource := staticBinding.StorageResource()
        if _, ok := classResources[class]; !ok {
            classResources[class] = &StorageResource{
                Requested: 0,
                Capacity: 0,
            }
        }
        classResources[class].Requested += storageResource.Requested
    	classResources[class].Capacity += storageResource.Capacity
    }
    return pl.scorer(classResources), nil
}

// ScoreExtensions 是 Score 插件的扩展点。
func (pl *VolumeBinding) ScoreExtensions() framework.ScoreExtensions {
	return nil
}
```

### Reserve&Unreserve

```go
// Reserve 预留Pod的卷，并将绑定状态保存在循环状态中。
func (pl *VolumeBinding) Reserve(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) *framework.Status {
    state, err := getStateData(cs)
    if err != nil {
    	return framework.AsStatus(err)
    }
    // 由于给定的Pod只会预留给一个节点，因此我们不需要持有锁定
    podVolumes, ok := state.podVolumesByNode[nodeName]
    if ok {
    	allBound, err := pl.Binder.AssumePodVolumes(pod, nodeName, podVolumes)
    if err != nil {
    	return framework.AsStatus(err)
    }
    	state.allBound = allBound
    } else {
        // 如果Pod没有引用任何PVC，则可能不存在
        state.allBound = true
    }
    return nil
}

// Unreserve 清除已假设的PV和PVC缓存。
// 它是幂等的，如果没有找到给定Pod的缓存，则不执行任何操作。
func (pl *VolumeBinding) Unreserve(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) {
    s, err := getStateData(cs)
    if err != nil {
    	return
    }
    // 由于只能取消预留一个节点，因此我们不需要持有锁定
    podVolumes, ok := s.podVolumesByNode[nodeName]
    if !ok {
    	return
    }
    pl.Binder.RevertAssumedPodVolumes(podVolumes)
}
```

### PreBind

```GO
// PreBind函数会使用预先绑定的操作更新API，等待PV控制器完成绑定操作。
//
// 如果绑定出现错误、超时或被撤销，则会返回错误以便重试调度。
func (pl *VolumeBinding) PreBind(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) *framework.Status {
    s, err := getStateData(cs) // 获取CycleState对象中的状态数据
    if err != nil {
    	return framework.AsStatus(err) // 返回错误状态
    }
    if s.allBound { // 如果所有卷都已绑定，则无需再次绑定
    	return nil
    }
    // 因为只有一个节点会对给定的Pod进行预绑定，所以我们不需要持有锁
    podVolumes, ok := s.podVolumesByNode[nodeName] // 获取给定节点上Pod的所有卷
    if !ok {
    	return framework.AsStatus(fmt.Errorf("no pod volumes found for node %q", nodeName)) // 如果未找到卷，则返回错误状态
    }
    klog.V(5).InfoS("Trying to bind volumes for pod", "pod", klog.KObj(pod)) // 记录日志信息
    err = pl.Binder.BindPodVolumes(ctx, pod, podVolumes) // 绑定给定Pod的卷
    if err != nil {
    	klog.V(1).InfoS("Failed to bind volumes for pod", "pod", klog.KObj(pod), "err", err) // 记录错误日志信息
    	return framework.AsStatus(err) // 返回错误状态
    }
    klog.V(5).InfoS("Success binding volumes for pod", "pod", klog.KObj(pod)) // 记录日志信息
    return nil // 返回成功状态
}
```

### EventsToRegister

```GO
// EventsToRegister函数返回可能导致Pod无法调度的插件失败的事件列表。
func (pl *VolumeBinding) EventsToRegister() []framework.ClusterEvent {
    events := []framework.ClusterEvent{
        // Pod可能因为缺少或配置错误的存储类（例如allowedTopologies、volumeBindingMode）而失败，因此可能在StorageClass的添加或更新事件发生后变得可调度。
        {Resource: framework.StorageClass, ActionType: framework.Add | framework.Update},
        // 我们将PVC与PV绑定，因此任何更改都可能使Pod可调度。
        {Resource: framework.PersistentVolumeClaim, ActionType: framework.Add | framework.Update},
        {Resource: framework.PersistentVolume, ActionType: framework.Add | framework.Update},
        // Pod可能无法找到可用的PV，因为节点标签与存储类的允许的拓扑或PV的节点亲和性不匹配。新建或更新的节点可能会使Pod可调度。
        {Resource: framework.Node, ActionType: framework.Add | framework.UpdateNodeLabel},
        // 我们依赖CSI节点将树内PV转换为CSI。
        {Resource: framework.CSINode, ActionType: framework.Add | framework.Update},
        // 当启用CSIStorageCapacity时，Pod可能会在CSI驱动程序和存储容量变化时可调度。
        {Resource: framework.CSIDriver, ActionType: framework.Add | framework.Update},
        {Resource: framework.CSIStorageCapacity, ActionType: framework.Add | framework.Update},
    }
    return events // 返回事件列表
}
```

