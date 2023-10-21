
## Extender

### 作用

Extender可以通过添加额外的逻辑，使调度器具有更多的功能和更好的性能，从而更好地满足用户的需求。

### interface

- 用于外部进程影响 Kubernetes 的调度决策，通常用于 Kubernetes 直接未管理的资源

```GO
// Extender 是一个接口，用于外部进程影响 Kubernetes 进行调度的决策。这通常是针对 Kubernetes 未直接管理的资源。
type Extender interface {
	// Name 返回一个唯一的名称，用于标识 Extender
	Name() string

	// Filter 基于 Extender 实现的谓词函数进行筛选。筛选出的列表预期是所提供列表的子集。
    // failedNodes 和 failedAndUnresolvableNodes 可选包含失败的节点列表和失败原因，但后者中的节点是无法解决的。
    Filter(pod *v1.Pod, nodes []*v1.Node) (filteredNodes []*v1.Node, failedNodesMap extenderv1.FailedNodesMap, failedAndUnresolvable extenderv1.FailedNodesMap, err error)

	// Prioritize 基于 Extender 实现的优先级函数进行优先级排序。返回的分数和权重将用于计算 Extender 的加权得分。
    // 加权得分将添加到 Kubernetes 调度器计算的得分中。总得分将用于进行主机选择。
	Prioritize(pod *v1.Pod, nodes []*v1.Node) (hostPriorities *extenderv1.HostPriorityList, weight int64, err error)

	// Bind 将 Pod 绑定到节点。将绑定 Pod 到节点的操作委托给 Extender。
	Bind(binding *v1.Binding) error

	// IsBinder 返回此 Extender 是否配置为 Bind 方法。
	IsBinder() bool

	// IsInterested 如果此 Pod 请求的至少一个扩展资源由此 Extender 管理，则返回 true。
	IsInterested(pod *v1.Pod) bool

	// ProcessPreemption 函数返回通过 extender 处理后的具有其受影响 pod 的节点，具体根据如下给定信息进行处理：
    //  1. 要调度的 Pod
    //  2. 候选节点和受影响的 Pod（nodeNameToVictims），它们是之前调度过程中生成的
    // extender 可能做出的更改包括：
    //  1. 在 extender 的预抢占阶段之后，给定的候选节点的子集
    //  2. 在 extender 的预抢占阶段之后，每个给定的候选节点有不同的受影响 pod 集合
	ProcessPreemption(
		pod *v1.Pod,
		nodeNameToVictims map[string]*extenderv1.Victims,
		nodeInfos NodeInfoLister,
	) (map[string]*extenderv1.Victims, error)

	// SupportsPreemption 函数返回调度程序 extender 是否支持抢占。
	SupportsPreemption() bool

	// IsIgnorable 返回 true 表示当该 extender 不可用时，调度不应该失败。这使调度器能够快速失败并容忍非关键的 extender。
	IsIgnorable() bool
}
```

### HTTPExtender

```GO
// 定义一个名为 HTTPExtender 的结构体，用于存储 HTTPExtender 扩展程序的属性和方法
type HTTPExtender struct {
    // extenderURL 表示扩展程序的 URL 地址
    extenderURL string
    // preemptVerb 表示预处理操作的 HTTP 方法，如 GET、POST 等
    preemptVerb string
    // filterVerb 表示过滤操作的 HTTP 方法，如 GET、POST 等
    filterVerb string
    // prioritizeVerb 表示优先级操作的 HTTP 方法，如 GET、POST 等
    prioritizeVerb string
    // bindVerb 表示绑定操作的 HTTP 方法，如 GET、POST 等
    bindVerb string
    // weight 表示扩展程序的权重值，用于排序
    weight int64
    // client 表示 HTTP 客户端，用于发送 HTTP 请求
    client *http.Client
    // nodeCacheCapable 表示扩展程序是否支持节点缓存
    nodeCacheCapable bool
    // managedResources 表示扩展程序所管理的资源集合
    managedResources sets.Set[string]
    // ignorable 表示扩展程序是否可忽略
    ignorable bool
}
```

### New

```go
func NewHTTPExtender(config *schedulerapi.Extender) (framework.Extender, error) {
    // 判断HTTPTimeout是否设置，如果未设置则使用默认值
    if config.HTTPTimeout.Duration.Nanoseconds() == 0 {
        config.HTTPTimeout.Duration = time.Duration(DefaultExtenderTimeout)
    }

    // 创建http.RoundTripper对象
    transport, err := makeTransport(config)
    if err != nil {
        return nil, err
    }

    // 创建http.Client对象
    client := &http.Client{
        Transport: transport,
        Timeout:   config.HTTPTimeout.Duration,
    }

    // 创建一个空的字符串集合
    managedResources := sets.New[string]()
    // 遍历ManagedResources列表，并将其名称插入到集合中
    for _, r := range config.ManagedResources {
        managedResources.Insert(string(r.Name))
    }

    // 创建HTTPExtender对象，并返回
    return &HTTPExtender{
        extenderURL:      config.URLPrefix,
        preemptVerb:      config.PreemptVerb,
        filterVerb:       config.FilterVerb,
        prioritizeVerb:   config.PrioritizeVerb,
        bindVerb:         config.BindVerb,
        weight:           config.Weight,
        client:           client,
        nodeCacheCapable: config.NodeCacheCapable,
        managedResources: managedResources,
        ignorable:        config.Ignorable,
    }, nil
}

// 创建http.RoundTripper对象
func makeTransport(config *schedulerapi.Extender) (http.RoundTripper, error) {
    // 初始化restclient.Config对象
    var cfg restclient.Config
    // 如果存在TLS配置，则设置相应参数
    if config.TLSConfig != nil {
        cfg.TLSClientConfig.Insecure = config.TLSConfig.Insecure
        cfg.TLSClientConfig.ServerName = config.TLSConfig.ServerName
        cfg.TLSClientConfig.CertFile = config.TLSConfig.CertFile
        cfg.TLSClientConfig.KeyFile = config.TLSConfig.KeyFile
        cfg.TLSClientConfig.CAFile = config.TLSConfig.CAFile
        cfg.TLSClientConfig.CertData = config.TLSConfig.CertData
        cfg.TLSClientConfig.KeyData = config.TLSConfig.KeyData
        cfg.TLSClientConfig.CAData = config.TLSConfig.CAData
    }

    // 如果启用了HTTPS，则设置相应参数
    if config.EnableHTTPS {
        hasCA := len(cfg.CAFile) > 0 || len(cfg.CAData) > 0
        if !hasCA {
            cfg.Insecure = true
        }
    }

    // 根据配置创建TLS配置对象
    tlsConfig, err := restclient.TLSConfigFor(&cfg)
    if err != nil {
        return nil, err
    }

    // 根据TLS配置创建http.Transport对象，并返回http.RoundTripper对象
    if tlsConfig != nil {
        return utilnet.SetTransportDefaults(&http.Transport{
            TLSClientConfig: tlsConfig,
        }), nil
    }
    return utilnet.SetTransportDefaults(&http.Transport{}), nil
}
```

### 方法

```GO
func (h *HTTPExtender) Name() string {
	return h.extenderURL
}

// 该函数实现了基于扩展程序实现的过滤函数，它期望过滤后的节点列表是提供的节点列表的子集，否则将返回一个错误。
// 失败的节点和失败的不可解决节点可选地包含了失败节点的列表和失败原因，但不包括后者是不可解决的节点。
func (h *HTTPExtender) Filter(
    pod *v1.Pod,
    nodes []*v1.Node,
    ) (filteredList []*v1.Node, failedNodes, failedAndUnresolvableNodes extenderv1.FailedNodesMap, err error) {
    var (
        result extenderv1.ExtenderFilterResult
        nodeList *v1.NodeList
        nodeNames *[]string
        nodeResult []*v1.Node
        args *extenderv1.ExtenderArgs
    )
    // 使用字典存储提供的节点列表
    fromNodeName := make(map[string]*v1.Node)
    for _, n := range nodes {
    	fromNodeName[n.Name] = n
	}
    // 如果 filterVerb 为空，则返回全部节点列表
    if h.filterVerb == "" {
        return nodes, extenderv1.FailedNodesMap{}, extenderv1.FailedNodesMap{}, nil
    }

    // 如果扩展程序支持节点缓存，则将节点名放入 nodeNameSlice 列表中
    if h.nodeCacheCapable {
        nodeNameSlice := make([]string, 0, len(nodes))
        for _, node := range nodes {
            nodeNameSlice = append(nodeNameSlice, node.Name)
        }
        nodeNames = &nodeNameSlice
    } else {
        // 如果扩展程序不支持节点缓存，则将节点列表放入 nodeList 中
        nodeList = &v1.NodeList{}
        for _, node := range nodes {
            nodeList.Items = append(nodeList.Items, *node)
        }
    }

    args = &extenderv1.ExtenderArgs{
        Pod:       pod,
        Nodes:     nodeList,
        NodeNames: nodeNames,
    }

    // 向扩展程序发送请求并获取结果
    if err := h.send(h.filterVerb, args, &result); err != nil {
        return nil, nil, nil, err
    }
    if result.Error != "" {
        return nil, nil, nil, fmt.Errorf(result.Error)
    }

    // 如果扩展程序支持节点缓存且返回了节点名，则将节点列表转换为 nodeResult 列表
    if h.nodeCacheCapable && result.NodeNames != nil {
        nodeResult = make([]*v1.Node, len(*result.NodeNames))
        for i, nodeName := range *result.NodeNames {
            if n, ok := fromNodeName[nodeName]; ok {
                nodeResult[i] = n
            } else {
                return nil, nil, nil, fmt.Errorf(
                    "extender %q claims a filtered node %q which is not found in the input node list",
                    h.extenderURL, nodeName)
            }
        }
    } else if result.Nodes != nil {
        // 如果扩展程序不支持节点缓存且返回了节点列表，则将返回的节点列表转换为 nodeResult 列表
        nodeResult = make([]*v1.Node, len(result.Nodes.Items))
        for i := range result.Nodes.Items {
            nodeResult[i] = &result.Nodes.Items[i]
        }
    }

    return nodeResult, result.FailedNodes, result
}

func (h *HTTPExtender) Prioritize(pod *v1.Pod, nodes []*v1.Node) (*extenderv1.HostPriorityList, int64, error) {
	var (
		result    extenderv1.HostPriorityList // 定义一个类型为extenderv1.HostPriorityList的变量result，用于存放结果
		nodeList  *v1.NodeList // 定义一个类型为v1.NodeList指针的变量nodeList，用于存放Node列表
		nodeNames *[]string // 定义一个类型为字符串切片指针的变量nodeNames，用于存放Node的名称列表
		args      *extenderv1.ExtenderArgs // 定义一个类型为extenderv1.ExtenderArgs指针的变量args，用于存放调度器参数
	)

	if h.prioritizeVerb == "" { // 如果h.prioritizeVerb为空字符串
		result := extenderv1.HostPriorityList{} // 创建一个空的extenderv1.HostPriorityList类型的变量result
		for _, node := range nodes { // 遍历nodes中的每个Node
			result = append(result, extenderv1.HostPriority{Host: node.Name, Score: 0}) // 将Node的名称和分数0添加到result中
		}
		return &result, 0, nil // 返回result指针、0分数和nil错误
	}

	if h.nodeCacheCapable { // 如果h.nodeCacheCapable为真
		nodeNameSlice := make([]string, 0, len(nodes)) // 创建一个长度为0、容量为len(nodes)的字符串切片nodeNameSlice
		for _, node := range nodes { // 遍历nodes中的每个Node
			nodeNameSlice = append(nodeNameSlice, node.Name) // 将Node的名称添加到nodeNameSlice中
		}
		nodeNames = &nodeNameSlice // 将nodeNameSlice的指针赋值给nodeNames
	} else {
		nodeList = &v1.NodeList{} // 创建一个空的v1.NodeList类型的变量nodeList
		for _, node := range nodes { // 遍历nodes中的每个Node
			nodeList.Items = append(nodeList.Items, *node) // 将Node的值添加到nodeList的Items字段中
		}
	}

	args = &extenderv1.ExtenderArgs{ // 创建一个extenderv1.ExtenderArgs类型的变量args，并初始化其字段
		Pod:       pod, // 将pod参数赋值给args的Pod字段
		Nodes:     nodeList, // 将nodeList赋值给args的Nodes字段
		NodeNames: nodeNames, // 将nodeNames赋值给args的NodeNames字段
	}

	if err := h.send(h.prioritizeVerb, args, &result); err != nil { // 调用h.send方法发送请求，将h.prioritizeVerb、args和result作为参数传递，并检查返回的错误
		return nil, 0, err // 如果有错误，返回nil指针、0分数和错误
	}
	return &result, h.weight, nil // 返回result指针、h.weight字段的值和nil错误
}

// Bind 将绑定 Pod 到节点的操作委托给 Extender。
func (h *HTTPExtender) Bind(binding *v1.Binding) error {
    var result extenderv1.ExtenderBindingResult // 用于保存绑定结果的变量
    if !h.IsBinder() { // 检查当前 Extender 是否为 Binder，如果不是则返回错误
        // 这不应该发生，因为这个 Extender 不应该成为 Binder。
        return fmt.Errorf("unexpected empty bindVerb in extender")
    }
    req := &extenderv1.ExtenderBindingArgs{ // 创建用于绑定的参数对象
        PodName: binding.Name, // 设置 Pod 的名称
        PodNamespace: binding.Namespace, // 设置 Pod 的命名空间
        PodUID: binding.UID, // 设置 Pod 的 UID
        Node: binding.Target.Name, // 设置目标节点的名称
    }
    if err := h.send(h.bindVerb, req, &result); err != nil { // 调用 send 方法发送绑定请求，并将结果保存到 result 变量中
    	return err // 如果出现错误，返回错误信息
    }
    if result.Error != "" { // 检查绑定结果中是否包含错误信息，如果有，则返回错误
    	return fmt.Errorf(result.Error)
    }
    return nil // 如果没有错误，返回 nil
}

func (h *HTTPExtender) IsBinder() bool {
	return h.bindVerb != ""
}

func (h *HTTPExtender) IsInterested(pod *v1.Pod) bool {
    if h.managedResources.Len() == 0 { // 检查 Extender 是否管理的资源列表为空，如果为空，则返回 true
    	return true
    }
    if h.hasManagedResources(pod.Spec.Containers) { // 检查 Pod 中的容器是否包含 Extender 管理的资源，如果包含，则返回 true
    	return true
    }
    if h.hasManagedResources(pod.Spec.InitContainers) { // 检查 Pod 中的 Init 容器是否包含 Extender 管理的资源，如果包含，则返回 true
    	return true
    }
    return false // 如果都不满足以上条件，则返回 false
}

func (h *HTTPExtender) ProcessPreemption(
	pod *v1.Pod,                          // 输入参数1: Pod 对象
	nodeNameToVictims map[string]*extenderv1.Victims,  // 输入参数2: 节点名到受影响 Pod 列表的映射
	nodeInfos framework.NodeInfoLister,    // 输入参数3: 节点信息的列表
) (map[string]*extenderv1.Victims, error) {    // 返回值: 节点名到受影响 Pod 列表的映射和错误信息

	var (
		result extenderv1.ExtenderPreemptionResult
		args   *extenderv1.ExtenderPreemptionArgs
	)

	if !h.SupportsPreemption() {    // 判断当前 extender 是否支持抢占操作
		return nil, fmt.Errorf("preempt verb is not defined for extender %v but run into ProcessPreemption", h.extenderURL)
	}

	if h.nodeCacheCapable {    // 判断当前 extender 是否支持节点缓存
		// 如果 extender 支持节点缓存，将 nodeNameToVictims 转换为 nodeNameToMetaVictims，并传入参数 args
		nodeNameToMetaVictims := convertToMetaVictims(nodeNameToVictims)
		args = &extenderv1.ExtenderPreemptionArgs{
			Pod:                   pod,
			NodeNameToMetaVictims: nodeNameToMetaVictims,
		}
	} else {
		// 如果 extender 不支持节点缓存，直接将 nodeNameToVictims 传入参数 args
		args = &extenderv1.ExtenderPreemptionArgs{
			Pod:               pod,
			NodeNameToVictims: nodeNameToVictims,
		}
	}

	if err := h.send(h.preemptVerb, args, &result); err != nil {    // 调用 extender 的 send 方法发送请求并获取响应结果
		return nil, err
	}

	// Extender 总是返回 NodeNameToMetaVictims，因此使用 nodeInfos 将其转换为 NodeNameToVictims。
	newNodeNameToVictims, err := h.convertToVictims(result.NodeNameToMetaVictims, nodeInfos)
	if err != nil {
		return nil, err
	}
	// 不覆盖 nodeNameToVictims。
	return newNodeNameToVictims, nil    // 返回经过转换后的节点名到受影响 Pod 列表的映射和错误信息
}

// SupportsPreemption 如果 extender 支持抢占操作，则返回 true。
// 一个 extender 应该定义 preempt 动词并启用自己的节点缓存。
func (h *HTTPExtender) SupportsPreemption() bool {
	return len(h.preemptVerb) > 0
}

// IsIgnorable 当此 extender 不可用时，返回 true，表示调度不应失败。
func (h *HTTPExtender) IsIgnorable() bool {
	return h.ignorable
}
```

#### send

```go
// send 是一个辅助函数，用于向 extender 发送消息。
func (h *HTTPExtender) send(action string, args interface{}, result interface{}) error {
    out, err := json.Marshal(args)
    if err != nil {
    	return err
    }
	url := strings.TrimRight(h.extenderURL, "/") + "/" + action

    req, err := http.NewRequest("POST", url, bytes.NewReader(out))
    if err != nil {
        return err
    }

    req.Header.Set("Content-Type", "application/json")

    resp, err := h.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("failed %v with extender at URL %v, code %v", action, url, resp.StatusCode)
    }

    return json.NewDecoder(resp.Body).Decode(result)
}
```

#### hasManagedResources

```go
func (h *HTTPExtender) hasManagedResources(containers []v1.Container) bool {
// 判断容器中是否有受管理的资源
    for i := range containers {
        container := &containers[i]
        for resourceName := range container.Resources.Requests {
            if h.managedResources.Has(string(resourceName)) {
            	return true
        	}
        }
        for resourceName := range container.Resources.Limits {
            if h.managedResources.Has(string(resourceName)) {
            	return true
            }
        }
    }
    return false
}
```

#### convertToMetaVictims

```go
func convertToMetaVictims(
		nodeNameToVictims map[string]*extenderv1.Victims,
	) map[string]*extenderv1.MetaVictims {
    // 将节点名称到受害者对象的映射转换为节点名称到元受害者对象的映射
    nodeNameToMetaVictims := map[string]*extenderv1.MetaVictims{}
    for node, victims := range nodeNameToVictims {
        metaVictims := &extenderv1.MetaVictims{
            Pods: []*extenderv1.MetaPod{},
            NumPDBViolations: victims.NumPDBViolations,
        }
        for _, pod := range victims.Pods {
            metaPod := &extenderv1.MetaPod{
            	UID: string(pod.UID),
            }
        	metaVictims.Pods = append(metaVictims.Pods, metaPod)
        }
        nodeNameToMetaVictims[node] = metaVictims
    }
    return nodeNameToMetaVictims
}
```

#### convertPodUIDToPod

```go
func (h *HTTPExtender) convertPodUIDToPod(
    metaPod *extenderv1.MetaPod,
    nodeInfo *framework.NodeInfo) (*v1.Pod, error) {
    // 将元Pod对象转换为实际Pod对象
    for _, p := range nodeInfo.Pods {
        if string(p.Pod.UID) == metaPod.UID {
        	return p.Pod, nil
        }
    }
    return nil, fmt.Errorf("extender: %v claims to preempt pod (UID: %v) on node: %v, but the pod is not found on that node",
    h.extenderURL, metaPod, nodeInfo.Node().Name)
}
```

#### convertToVictims

```go
func (h *HTTPExtender) convertToVictims(
    nodeNameToMetaVictims map[string]*extenderv1.MetaVictims,
    nodeInfos framework.NodeInfoLister,
    ) (map[string]*extenderv1.Victims, error) {
    // 将节点名称到元受害者对象的映射转换为节点名称到受害者对象的映射
    nodeNameToVictims := map[string]*extenderv1.Victims{}
    for nodeName, metaVictims := range nodeNameToMetaVictims {
    	nodeInfo, err := nodeInfos.Get(nodeName)
        if err != nil {
        	return nil, err
        }
        victims := &extenderv1.Victims{
            Pods: []*v1.Pod{},
            NumPDBViolations: metaVictims.NumPDBViolations,
    	}
        for _, metaPod := range metaVictims.Pods {
            pod, err := h.convertPodUIDToPod(metaPod, nodeInfo)
            if err != nil {
            	return nil, err
            }
    		victims.Pods = append(victims.Pods, pod)
    	}
    	nodeNameToVictims[nodeName] = victims
    }
    return nodeNameToVictims, nil
}
```

## Framework

### 作用

Framework接口定义了Kubernetes调度框架的行为规范，它是Kubernetes调度器的核心接口。Kubernetes调度器将调度决策委托给一组调度器插件（scheduler plugins），这些插件实现了Framework接口中定义的方法。

通过实现Framework接口中的方法，调度器插件可以检查、过滤和打分各个节点上的Pod，然后选择最佳的节点将Pod绑定到该节点上运行。此外，Framework接口还定义了一些其他方法，例如获取已配置的插件列表、设置PodNominator等。

总之，Framework接口提供了Kubernetes调度器的基本行为规范和扩展点，使得Kubernetes调度器可以方便地与各种自定义插件集成，从而实现高效、灵活的资源调度。

### interface

```GO
// Framework 是一个接口，管理调度框架中使用的插件集。
// 配置好的插件会在调度上下文中指定的点被调用。
type Framework interface {
	Handle
    // PreEnqueuePlugins 返回已注册的 preEnqueue 插件。
    PreEnqueuePlugins() []PreEnqueuePlugin

    // QueueSortFunc 返回排序调度队列中 Pod 的函数。
    QueueSortFunc() LessFunc

    // RunPreFilterPlugins 运行已配置的 PreFilter 插件集。如果任何插件返回的状态不是 Success，则返回 *Status，状态代码设置为非成功状态。
    // 如果返回一个非成功的状态，则调度循环将被中止。
    // 它还返回一个 PreFilterResult，它可能会影响向下评估哪些或多少个节点。
    RunPreFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod) (*PreFilterResult, *Status)

    // RunPostFilterPlugins 运行已配置的 PostFilter 插件集。
    // PostFilter 插件可以是信息性的，如果是，则应配置为首先执行并返回 Unschedulable 状态；
    // 或者它们可以尝试更改集群状态，使 Pod 可以在将来的调度周期中调度。
    RunPostFilterPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, filteredNodeStatusMap NodeToStatusMap) (*PostFilterResult, *Status)

    // RunPreBindPlugins 运行已配置的 PreBind 插件集。如果任何插件返回的状态不是 Success，则返回 *Status，状态代码设置为非成功状态。
    // 如果状态代码是 "Unschedulable"，则认为它是调度检查失败，否则认为是内部错误。在任何情况下，Pod 都不会绑定。
    RunPreBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

    // RunPostBindPlugins 运行已配置的 PostBind 插件集。
    RunPostBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)

    // RunReservePluginsReserve 运行配置的 Reserve 插件集的 Reserve 方法。如果其中任何一个调用返回错误，则不会继续运行其余插件并返回错误。
    // 在这种情况下，Pod 将不会被调度。
    RunReservePluginsReserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

    // RunReservePluginsUnreserve 运行已配置的 Reserve 插件集的 Unreserve 方法。
    RunReservePluginsUnreserve(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string)

  	// RunPermitPlugins 运行配置的 Permit 插件集合。如果任何一个插件返回的状态不是 "Success" 或 "Wait"，它将不会继续运行其余的插件，并返回一个错误。
    // 否则，如果任何一个插件返回 "Wait"，则此函数将创建并添加一个等待 Pod 到当前等待 Pod 映射中，并返回带有 "Wait" 状态的结果。Pod 将保持等待状态的最小持续时间由 Permit 插件返回。
	RunPermitPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// WaitOnPermit 如果 Pod 是等待 Pod，则会阻塞，直到等待 Pod 被拒绝或允许。
	WaitOnPermit(ctx context.Context, pod *v1.Pod) *Status

	// RunBindPlugins 运行配置的 Bind 插件集合。Bind 插件可以选择是否处理给定的 Pod。如果 Bind 插件选择跳过绑定，则应返回 code=5（"skip"）状态。
    // 否则，它应返回 "Error" 或 "Success"。如果没有插件处理绑定，则 RunBindPlugins 返回 code=5（"skip"）状态。
	RunBindPlugins(ctx context.Context, state *CycleState, pod *v1.Pod, nodeName string) *Status

	// HasFilterPlugins 如果至少有一个 Filter 插件被定义，则返回 true。
	HasFilterPlugins() bool

	// HasPostFilterPlugins 如果至少有一个 PostFilter 插件被定义，则返回 true。
	HasPostFilterPlugins() bool

	// HasScorePlugins 如果至少有一个 Score 插件被定义，则返回 true。
	HasScorePlugins() bool

	// ListPlugins 返回扩展点名称到配置的插件列表的映射。
	ListPlugins() *config.Plugins

	// ProfileName 返回与配置文件相关联的配置文件名称。
	ProfileName() string

	// PercentageOfNodesToScore 返回与配置文件相关联的 percentageOfNodesToScore。
	PercentageOfNodesToScore() *int32

	// SetPodNominator 设置 PodNominator。
	SetPodNominator(nominator PodNominator)
}
```

#### Plugin

```GO
type Plugin interface {
	Name() string
}
```

#### Status

```go
// Status 表示运行插件的结果。它由一个 code，一条消息，（可选的）一个错误，以及导致失败的插件名称组成。
// 当状态码不是 Success 时，原因应该解释为什么失败。
// 当 code 是 Success 时，所有其他字段应该为空。
// 注意：nil 状态也被认为是 Success。
type Status struct {
    code Code // 描述状态码的枚举类型
    reasons []string // 保存状态码不是 Success 时的错误原因，可能有多个
    err error // 保存任何可能出现的错误
    // failedPlugin 是一个可选的字段，记录 Pod 失败的插件名称。
    // 当 code 是 Error、Unschedulable 或 UnschedulableAndUnresolvable 时，由框架设置。
    failedPlugin string
}

type Code int

// 这些是在状态中使用的预定义代码。
const (
    // Success 表示插件正确运行并找到了可被调度的 Pod。
    // 注意：一个 nil 状态也被视为“Success”。
    Success Code = iota
    // Error 用于表示内部插件错误、意外输入等情况。
    Error
    // Unschedulable 表示插件发现一个无法调度的 Pod。调度器可能会尝试运行其他 postFilter 插件，如抢占，以便将此 Pod 调度。
    // 使用 UnschedulableAndUnresolvable 来使调度器跳过其他 postFilter 插件。
    // 附带的状态消息应解释为什么该 Pod 无法调度。
    Unschedulable
    // UnschedulableAndUnresolvable 表示插件发现一个无法调度的 Pod，并且其他 postFilter 插件（如抢占）也无法改变这种情况。
    // 如果在运行其他 postFilter 插件后可能可以调度该 Pod，则插件应返回 Unschedulable。
    // 附带的状态消息应解释为什么该 Pod 无法调度。
    UnschedulableAndUnresolvable
    // Wait 表示 Permit 插件发现应等待调度 Pod。
    Wait
    // Skip 在以下情况下使用：
    // - 当 Bind 插件选择跳过绑定时。
    // - 当 PreFilter 插件返回 Skip 以跳过耦合的 Filter 插件/PreFilterExtensions()。
    // - 当 PreScore 插件返回 Skip 以跳过耦合的 Score 插件。
    Skip
)

var codes = []string{"Success", "Error", "Unschedulable", "UnschedulableAndUnresolvable", "Wait", "Skip"}

func (c Code) String() string {
	return codes[c]
}
```

#### PreEnqueuePlugin

```GO
// PreEnqueuePlugin是一个接口，必须由“PreEnqueue”插件实现。
// 这些插件在将Pod添加到activeQ之前被调用。
// 注意：预先插入插件应该是轻量级和高效的，因此不应该涉及访问外部端点等昂贵的调用；
// 否则它将阻塞事件处理程序中其他Pod的排队。
type PreEnqueuePlugin interface {
    Plugin
    // PreEnqueue在将Pod添加到activeQ之前被调用。
    PreEnqueue(ctx context.Context, p *v1.Pod) *Status
}
```

#### LessFunc

```GO
// LessFunc 是对pod信息进行排序的功能
type LessFunc func(podInfo1, podInfo2 *QueuedPodInfo) bool
```

#### PreFilterResult

```GO
// PreFilterResult 包装了调度框架在 PreFilter 阶段需要使用的一些信息。
type PreFilterResult struct {
    // 应考虑的节点集；如果为 nil，则所有节点均符合条件。
    NodeNames sets.Set[string]
}
```

#### NodeToStatusMap

```GO
type NodeToStatusMap map[string]*Status
```

#### PostFilterResult

```GO
// 定义 PostFilterResult 类型
type PostFilterResult struct {
	*NominatingInfo // 一个指向 NominatingInfo 结构体的指针
}
```

##### NominatingInfo

```GO
type NominatingInfo struct {
    NominatedNodeName string // 被提名的节点的名称
    NominatingMode NominatingMode // 提名模式
}
```

##### NominatingMode

```GO
type NominatingMode int

const (
    // 表示进行候选人提名，也就是不对集群状态进行任何修改，而是直接返回当前集群状态
	ModeNoop NominatingMode = iota
    // 表示进行候选人提名并更新集群状态，也就是会修改集群状态，以便后续操作可以基于新的集群状态进行
	ModeOverride
)
```

#### CycleState

```go
// CycleState 提供了一种机制，使得插件可以存储和检索任意数据。
// 由一个插件存储的 StateData 可以被另一个插件读取、修改或删除。
// CycleState 不提供任何数据保护，因为所有的插件都被认为是可信的。
// 注意：CycleState 使用 sync.Map 来支持存储。它旨在优化“写一次，读多次”的场景。
// 它是所有内部插件中推荐使用的模式——插件特定的状态在 PreFilter/PreScore 中写入一次，然后在 Filter/Score 中读取多次。
type CycleState struct {
	// 存储使用 StateKey 作为键，StateData 作为值。
    storage sync.Map
    // 如果 recordPluginMetrics 为 true，则为此周期记录 PluginExecutionDuration。
    recordPluginMetrics bool
    // SkipFilterPlugins 是在 Filter 扩展点中将被跳过的插件集合。
    SkipFilterPlugins sets.Set[string]
    // SkipScorePlugins 是在 Score 扩展点中将被跳过的插件集合。
	SkipScorePlugins sets.Set[string]
}

type StateKey string

func NewCycleState() *CycleState {
	return &CycleState{}
}
```

##### 方法

```GO
// ShouldRecordPluginMetrics 返回是否应该记录 PluginExecutionDuration 指标。
func (c *CycleState) ShouldRecordPluginMetrics() bool {
    if c == nil {
    	return false
    }
    return c.recordPluginMetrics
}

// SetRecordPluginMetrics 将 recordPluginMetrics 设置为给定值。
func (c *CycleState) SetRecordPluginMetrics(flag bool) {
    if c == nil {
    	return
    }
    c.recordPluginMetrics = flag
}

// Clone 创建 CycleState 的副本并返回其指针。如果要克隆的上下文为 nil，则 Clone 返回 nil。
func (c *CycleState) Clone() *CycleState {
    if c == nil {
    	return nil
    }
    copy := NewCycleState()
    c.storage.Range(func(k, v interface{}) bool {
        copy.storage.Store(k, v.(StateData).Clone())
        return true
    })
    copy.recordPluginMetrics = c.recordPluginMetrics
    copy.SkipFilterPlugins = c.SkipFilterPlugins
    copy.SkipScorePlugins = c.SkipScorePlugins
    return copy
}

// Read 从 CycleState 中检索具有给定“key”的数据。如果该键不存在，则返回错误。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Read(key StateKey) (StateData, error) {
    if v, ok := c.storage.Load(key); ok {
    	return v.(StateData), nil
    }
    return nil, ErrNotFound
}

// Write 将给定的“val”存储在 CycleState 中，并使用给定的“key”。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Write(key StateKey, val StateData) {
	c.storage.Store(key, val)
}

// Delete 从 CycleState 中删除具有给定键的数据。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Delete(key StateKey) {
	c.storage.Delete(key)
}
```

### Handle

```go
// Handle 提供数据和一些工具，供插件使用。它在插件初始化时传递给插件工厂。插件必须存储并使用此句柄来调用框架函数。
type Handle interface {
    // PodNominator 抽象了维护被提名的Pod的操作。
    PodNominator
    // PluginsRunner 抽象了运行某些插件的操作。
    PluginsRunner
    // SnapshotSharedLister 返回最新的NodeInfo快照中的Listers。该快照在调度周期开始时进行，直到Pod完成“许可”点之前保持不变。
    // 在调度绑定阶段期间，无法保证信息保持不变，因此绑定周期（pre-bind/bind/post-bind/un-reserve插件）中的插件不应使用它，否则可能会发生并发读/写错误，它们应该使用调度器缓存。
    SnapshotSharedLister() SharedLister
    // IterateOverWaitingPods 获取读锁并遍历WaitingPods映射。
    IterateOverWaitingPods(callback func(WaitingPod))

    // GetWaitingPod 根据UID返回等待的Pod。
    GetWaitingPod(uid types.UID) WaitingPod

    // RejectWaitingPod 拒绝给定UID的等待Pod。返回值指示Pod是否在等待中。
    RejectWaitingPod(uid types.UID) bool

    // ClientSet 返回一个Kubernetes ClientSet。
    ClientSet() clientset.Interface

    // KubeConfig 返回原始kube config。
    KubeConfig() *restclient.Config

    // EventRecorder 返回事件记录器。
    EventRecorder() events.EventRecorder

    SharedInformerFactory() informers.SharedInformerFactory

    // RunFilterPluginsWithNominatedPods 在给定节点上运行配置的过滤插件集以过滤被提名的Pod。
    RunFilterPluginsWithNominatedPods(ctx context.Context, state *CycleState, pod *v1.Pod, info *NodeInfo) *Status

    // Extenders 返回已注册的调度器扩展程序。
    Extenders() []Extender

    // Parallelizer 返回一个持有调度程序并行性的Parallelizer。
    Parallelizer() parallelize.Parallelizer
}
```

#### PodNominator

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

##### PluginsRunner

```go
// PluginsRunner接口抽象了运行一些插件的操作。
// 当进行某些运行中的pod被驱逐时，预选阶段后置过滤器插件用于评估在哪些节点上可以调度pod时会使用这个接口。
type PluginsRunner interface {
    // RunPreScorePlugins运行一组配置好的PreScore插件。如果这些插件中的任何一个返回除"Success"以外的任何状态，则拒绝给定的pod。
    RunPreScorePlugins(context.Context, *CycleState, *v1.Pod, []*v1.Node) Status
    // RunScorePlugins运行一组配置好的得分插件。
    // 它返回一个列表，该列表存储来自每个插件的分数以及每个Node的总分数。
    // 它还返回Status，如果任何插件返回非"Success"状态，则将其设置为非"Success"状态。
    RunScorePlugins(context.Context, *CycleState, *v1.Pod, []*v1.Node) ([]NodePluginScores, *Status)
    // RunFilterPlugins在给定节点上运行为pod配置的一组过滤插件。
    // 请注意，对于正在评估的节点，传递的nodeInfo引用可能与NodeInfoSnapshot映射中的引用不同（例如，被认为在该节点上运行的pod可能不同）。
    // 例如，在预期抢占期间，我们可能会传递原始nodeInfo对象的副本，该副本已从其中删除了一些pod，以评估抢占它们以调度目标pod的可能性。
    RunFilterPlugins(context.Context, *CycleState, *v1.Pod, *NodeInfo) *Status
    // RunPreFilterExtensionAddPod调用配置好的一组PreFilter插件的AddPod接口。
    // 如果这些插件中的任何一个返回除Success以外的任何状态，则直接返回。
    RunPreFilterExtensionAddPod(ctx context.Context, state *CycleState, podToSchedule *v1.Pod, podInfoToAdd *PodInfo, nodeInfo *NodeInfo) *Status
    // RunPreFilterExtensionRemovePod调用配置好的一组PreFilter插件的RemovePod接口。
    // 如果这些插件中的任何一个返回除Success以外的任何状态，则直接返回。
    RunPreFilterExtensionRemovePod(ctx context.Context, state *CycleState, podToSchedule *v1.Pod, podInfoToRemove *PodInfo, nodeInfo *NodeInfo) *Status
}
```

###### NodePluginScores

```go
// NodePluginScores是一个结构体，包含节点名称以及该节点的分数。
type NodePluginScores struct {
    // Name是节点名称。
    Name string
    // Scores是来自插件和扩展程序的分数。
    Scores []PluginScore
    // TotalScore是Scores中的总分数。
    TotalScore int64
}

// PluginScore是一个结构体，包含插件或扩展程序的名称和分数。
type PluginScore struct {
    // Name是插件或扩展程序的名称。
    Name string
    Score int64
}
```

#### SharedLister

```go
type SharedLister interface {
	NodeInfos() NodeInfoLister
	StorageInfos() StorageInfoLister
}

// NodeInfoLister 接口表示能够通过节点名称列表/获取 NodeInfo 对象的任何内容。
type NodeInfoLister interface {
    // List 返回 NodeInfos 的列表。
    List() ([]*NodeInfo, error)
    // HavePodsWithAffinityList 返回具有亲和性项的 Pod 的 NodeInfos 列表。
    HavePodsWithAffinityList() ([]*NodeInfo, error)
    // HavePodsWithRequiredAntiAffinityList 返回具有必需反亲和性项的 Pod 的 NodeInfos 列表。
    HavePodsWithRequiredAntiAffinityList() ([]*NodeInfo, error)
    // Get 返回给定节点名称的 NodeInfo。
    Get(nodeName string) (*NodeInfo, error)
}

// StorageInfoLister 接口表示处理存储相关操作和资源的任何内容。
type StorageInfoLister interface {
    // IsPVCUsedByPods 根据格式为 "namespace/name" 的键返回 PVC 是否被一个或多个已调度的 Pod 使用的 true/false 值。
    IsPVCUsedByPods(key string) bool
}
```

#### WaitingPod

```go
// WaitingPod表示当前处于许可阶段等待的Pod。
type WaitingPod interface {
    // GetPod返回对等待Pod的引用。
    GetPod() *v1.Pod
    // GetPendingPlugins返回挂起的Permit插件名称列表。
    GetPendingPlugins() []string
    // Allow声明允许由名为“pluginName”的插件调度等待的Pod。
    // 如果这是最后一个允许的插件，则会发送成功信号以解除Pod的阻塞。
    Allow(pluginName string)
    // Reject声明等待的Pod无法调度。
    Reject(pluginName，msg string)
}
```

## Registry

```GO
type Registry map[string]PluginFactory

type PluginFactory = func(configuration runtime.Object, f framework.Handle) (framework.Plugin, error)

// 注册
func (r Registry) Register(name string, factory PluginFactory) error {
	if _, ok := r[name]; ok {
		return fmt.Errorf("a plugin named %v already exists", name)
	}
	r[name] = factory
	return nil
}

func (r Registry) Unregister(name string) error {
	if _, ok := r[name]; !ok {
		return fmt.Errorf("no plugin named %v exists", name)
	}
	delete(r, name)
	return nil
}

// 合并
func (r Registry) Merge(in Registry) error {
	for name, factory := range in {
		if err := r.Register(name, factory); err != nil {
			return err
		}
	}
	return nil
}
```

#### FactoryAdapter

```go
type PluginFactoryWithFts func(runtime.Object, framework.Handle, plfeature.Features) (framework.Plugin, error)

// FactoryAdapter函数可以用于为需要特性门控的插件注入特性门控，
// 并且调用者期望使用旧的PluginFactory方法。
func FactoryAdapter(fts plfeature.Features, withFts PluginFactoryWithFts) PluginFactory {
    // 返回一个函数，该函数使用给定的fts和withFts参数创建framework.Plugin实例并返回。
    // 具体地说，该函数接受两个参数，分别是plArgs（runtime.Object类型）和fh（framework.Handle类型），
    // 并将它们以及fts作为参数传递给withFts函数，以创建插件实例并返回。
    return func(plArgs runtime.Object, fh framework.Handle) (framework.Plugin, error) {
    	return withFts(plArgs, fh, fts)
    }
}
```

## waitingPodsMap

```GO
// waitingPodsMap 是一个线程安全的映射，用于维护处于许可阶段的 Pod。
type waitingPodsMap struct {
    pods map[types.UID]*waitingPod // 存储 UID 到 *waitingPod 的映射
    mu sync.RWMutex // 读写锁
}

// newWaitingPodsMap 返回一个新的 waitingPodsMap。
func newWaitingPodsMap() *waitingPodsMap {
    return &waitingPodsMap{
    	pods: make(map[types.UID]*waitingPod),
    }
}

// add 将一个新的 WaitingPod 添加到映射中。
func (m *waitingPodsMap) add(wp *waitingPod) {
    m.mu.Lock() // 加写锁
    defer m.mu.Unlock() // 函数结束时释放写锁
    m.pods[wp.GetPod().UID] = wp // 在映射中添加一个新的 *waitingPod
}

// remove 从映射中删除一个 WaitingPod。
func (m *waitingPodsMap) remove(uid types.UID) {
    m.mu.Lock() // 加写锁
    defer m.mu.Unlock() // 函数结束时释放写锁
    delete(m.pods, uid) // 从映射中删除一个 UID 对应的 *waitingPod
}

// get 从映射中获取一个 WaitingPod。
func (m *waitingPodsMap) get(uid types.UID) *waitingPod {
    m.mu.RLock() // 加读锁
    defer m.mu.RUnlock() // 函数结束时释放读锁
    return m.pods[uid] // 返回映射中 UID 对应的 *waitingPod
}

// iterate 获取一个读锁并遍历 WaitingPods 映射。
func (m *waitingPodsMap) iterate(callback func(framework.WaitingPod)) {
    m.mu.RLock() // 加读锁
    defer m.mu.RUnlock() // 函数结束时释放读锁
    for _, v := range m.pods {
    	callback(v) // 对每个 *waitingPod 调用回调函数
    }
}
```



```GO
// waitingPod表示处于许可阶段等待的Pod。
type waitingPod struct {
    pod *v1.Pod // Pod对象
    pendingPlugins map[string]*time.Timer // 等待的许可插件和它们的定时器
    s chan *framework.Status // 信号通道，用于通知等待Pod状态的更改
    mu sync.RWMutex // 读写锁，保护pendingPlugins的并发访问
}

var _ framework.WaitingPod = &waitingPod{}

// newWaitingPod返回一个新的waitingPod实例。
func newWaitingPod(pod *v1.Pod, pluginsMaxWaitTime map[string]time.Duration) *waitingPod {
    wp := &waitingPod{
        pod: pod,
        // Allow() 和 Reject() 调用是非阻塞的。通过使用非阻塞的发送到这个通道来保证这个属性。
        // 这个通道有一个大小为1的缓冲区，以确保非阻塞发送不会被忽略——在接收此通道之后可能出现的情况。
        s: make(chan *framework.Status, 1),
	}
    wp.pendingPlugins = make(map[string]*time.Timer, len(pluginsMaxWaitTime))
    // time.AfterFunc调用wp.Reject，该函数遍历pendingPlugins映射。在此处获取锁定，以便time.AfterFunc
    // 只能在newWaitingPod完成后执行。
    wp.mu.Lock()
    defer wp.mu.Unlock()
    for k, v := range pluginsMaxWaitTime {
        plugin, waitTime := k, v
        wp.pendingPlugins[plugin] = time.AfterFunc(waitTime, func() {
            msg := fmt.Sprintf("rejected due to timeout after waiting %v at plugin %v",
                waitTime, plugin)
            wp.Reject(plugin, msg)
        })
    }
    return wp
}

// GetPod返回一个指向等待Pod的引用。
func (w *waitingPod) GetPod() *v1.Pod {
	return w.pod
}

// GetPendingPlugins返回一个挂起的许可插件名称列表。
func (w *waitingPod) GetPendingPlugins() []string {
    w.mu.RLock()
    defer w.mu.RUnlock()
    plugins := make([]string, 0, len(w.pendingPlugins))
    for p := range w.pendingPlugins {
    	plugins = append(plugins, p)
    }
    return plugins
}

// Allow声明等待Pod允许由插件pluginName进行调度。
// 如果这是最后一个允许的插件，则发送一个成功信号来解除Pod的阻塞。
func (w *waitingPod) Allow(pluginName string) {
    w.mu.Lock()
    defer w.mu.Unlock()
    if timer, exist := w.pendingPlugins[pluginName]; exist {
        timer.Stop()
        delete(w.pendingPlugins, pluginName)
    }
    // 仅在所有插件都允许后才发出成功状态的信号
    if len(w.pendingPlugins) != 0 {
        return
    }

    // select子句作为非阻塞发送操作
    // 如果没有接收者，它是一个无操作（默认情况）。
    select {
    case w.s <- framework.NewStatus(framework.Success, ""):
    default:
    }
}

// Reject 声明等待的 Pod 不可调度。
func (w *waitingPod) Reject(pluginName, msg string) {
    // 获取读锁以读取 pendingPlugins。
    w.mu.RLock()
    defer w.mu.RUnlock()
    // 停止所有定时器以停止后续 Permit 调用。
    for _, timer := range w.pendingPlugins {
    	timer.Stop()
    }
    // select 语句用作非阻塞发送。
    // 如果没有接收者，则是一个 no-op（默认情况）。
    select {
    // 将状态设置为不可调度，并设置错误信息和失败插件。
    case w.s <- framework.NewStatus(framework.Unschedulable, msg).WithFailedPlugin(pluginName):
    default:
    }
}
```

## Parallelizer

```GO
// Parallelizer 是一个结构体，用来保存调度程序的并行度信息。
type Parallelizer struct {
	parallelism int
}

// NewParallelizer 返回一个包含并行度信息的对象。
func NewParallelizer(p int) Parallelizer {
	return Parallelizer{parallelism: p}
}

// chunkSizeFor 返回给定项目数量的块大小，用于并行处理。此函数旨在产生良好的CPU利用率。
// 返回 max(1, min(sqrt(n), n/Parallelism))
func chunkSizeFor(n, parallelism int) int {
    // 用数学库计算平方根
    s := int(math.Sqrt(float64(n)))
    // 如果 s 大于 n/parallelism+1，则将 s 设置为 n/parallelism+1
    if r := n/parallelism + 1; s > r {
        s = r
    } else if s < 1 {
        // 如果 s 小于 1，则将 s 设置为 1
        s = 1
    }
    return s
}

// Until 是 workqueue.ParallelizeUntil 的一个包装器，用于在调度算法中使用。
// 一个给定的操作将被记录在 goroutine 指标中。
func (p Parallelizer) Until(ctx context.Context, pieces int, doWorkPiece workqueue.DoWorkPieceFunc, operation string) {
    // 获取指定操作的 goroutine 指标
    goroutinesMetric := metrics.Goroutines.WithLabelValues(operation)
    // 定义一个函数包装器
    withMetrics := func(piece int) {
        // 每当调用此函数时，goroutine 指标都会增加1
        goroutinesMetric.Inc()
        doWorkPiece(piece)
        // 当调用结束时，goroutine 指标会减少1
        goroutinesMetric.Dec()
    }

    // 调用 workqueue.ParallelizeUntil 函数，处理 pieces 个任务。
    // 并发度为 p.parallelism，使用 withMetrics 函数作为处理函数，
    // chunkSizeFor 函数用来计算分块大小。
    workqueue.ParallelizeUntil(ctx, p.parallelism, pieces, withMetrics, workqueue.WithChunkSize(chunkSizeFor(pieces, p.parallelism)))
}
```

## frameworkImpl

- 此结构体实现了Framework接口

```GO
// frameworkImpl是负责初始化和运行调度器插件的组件。
type frameworkImpl struct {
    registry Registry // 存储所有可用的调度器插件
    snapshotSharedLister framework.SharedLister // 共享列表器，用于获取共享资源的快照
    waitingPods *waitingPodsMap // 存储所有等待被调度的Pod
    scorePluginWeight map[string]int // 调度器插件权重映射表，用于计算Pod在哪个节点上运行的分数
    preEnqueuePlugins []framework.PreEnqueuePlugin // 在Pod进入调度队列前运行的插件
    queueSortPlugins []framework.QueueSortPlugin // 调度队列排序插件
    preFilterPlugins []framework.PreFilterPlugin // 在过滤Pod之前运行的插件
    filterPlugins []framework.FilterPlugin // 过滤Pod的插件
    postFilterPlugins []framework.PostFilterPlugin // 在过滤Pod之后运行的插件
    preScorePlugins []framework.PreScorePlugin // 在计算Pod分数之前运行的插件
    scorePlugins []framework.ScorePlugin // 计算Pod分数的插件
    reservePlugins []framework.ReservePlugin // 为Pod保留节点的插件
    preBindPlugins []framework.PreBindPlugin // 在绑定Pod到节点之前运行的插件
    bindPlugins []framework.BindPlugin // 将Pod绑定到节点的插件
    postBindPlugins []framework.PostBindPlugin // 在将Pod绑定到节点之后运行的插件
    permitPlugins []framework.PermitPlugin // 确定Pod是否可以运行的插件
    clientSet       clientset.Interface  // 与Kubernetes API交互的客户端
    kubeConfig      *restclient.Config  // 用于访问Kubernetes API的配置
    eventRecorder   events.EventRecorder  // 用于记录事件的组件
    informerFactory informers.SharedInformerFactory  // 用于创建informer的工厂

    metricsRecorder          *metrics.MetricAsyncRecorder  // 用于记录度量指标的组件
    profileName              string  // 框架的配置文件名称
    percentageOfNodesToScore *int32  // 用于指定将要评估的节点百分比

    extenders []framework.Extender  // 调度器插件扩展程序
    framework.PodNominator  // 用于选择候选节点的插件

    parallelizer parallelize.Parallelizer  // 用于并行处理Pod调度的组件
}
```

### Plugin

```GO
// Plugin is the parent type for all the scheduling framework plugins.
type Plugin interface {
	Name() string
}

```

#### PreEnqueuePlugin

```go
// PreEnqueuePlugin 接口必须被“PreEnqueue”插件实现。
// 这些插件在将Pod添加到 activeQ 之前调用。
// 注意：预调度插件应该是轻量级和高效的，因此不应涉及像访问外部端点这样的昂贵调用；否则将会阻塞事件处理程序中其他Pod的入队。
type PreEnqueuePlugin interface {
    Plugin
    // PreEnqueue 在将Pod添加到 activeQ 之前调用。
    PreEnqueue(ctx context.Context, p *v1.Pod) *Status
}
```

#### QueueSortPlugin

```GO
// QueueSortPlugin 接口必须被“QueueSort”插件实现。
// 这些插件用于对调度队列中的Pod进行排序。一次只能启用一个队列排序插件。
type QueueSortPlugin interface {
    Plugin
    // Less 用于对调度队列中的Pod进行排序。
    Less(*QueuedPodInfo, *QueuedPodInfo) bool
}
```

#### PreFilterPlugin

```GO
// PreFilterPlugin 接口必须被“PreFilter”插件实现。
// 这些插件在调度周期开始时调用。
type PreFilterPlugin interface {
    Plugin
    // PreFilter 在调度周期开始时调用。所有 PreFilter 插件必须返回成功，否则Pod将被拒绝。
    // PreFilter 可以选择返回 PreFilterResult 来影响后续评估哪些节点。这对于可以在 O(1) 时间内确定要处理的节点子集的情况很有用。
    // 当它返回 Skip 状态时，返回的 PreFilterResult 和状态中的其他字段将被忽略，并且配对的 Filter 插件/PreFilterExtensions() 将在此调度周期中被跳过。
    PreFilter(ctx context.Context, state *CycleState, p *v1.Pod) (*PreFilterResult, *Status)
    // PreFilterExtensions 如果插件实现，则返回 PreFilterExtensions 接口，否则返回 nil。
    // Pre-filter 插件可以提供扩展来逐步修改其预处理信息。框架保证扩展 AddPod/RemovePod 只会在 PreFilter 之后调用，可能在克隆的 CycleState 上调用，可能在特定节点上再次调用这些函数之前调用这些函数。
    PreFilterExtensions() PreFilterExtensions
}
```

##### PreFilterExtensions

```GO
// PreFilterExtensions是一个接口，包含在允许指定回调以对其预计算状态进行增量更新的插件中。
type PreFilterExtensions interface {
    // AddPod由框架调用，当调度podToSchedule时，尝试评估将podToAdd添加到节点的影响。
    AddPod(ctx context.Context, state *CycleState, podToSchedule *v1.Pod, podInfoToAdd *PodInfo, nodeInfo *NodeInfo) *Status
    // RemovePod由框架调用，当调度podToSchedule时，尝试评估从节点中删除podToRemove的影响。
    RemovePod(ctx context.Context, state *CycleState, podToSchedule *v1.Pod, podInfoToRemove *PodInfo, nodeInfo *NodeInfo) *Status
}
```

#### FilterPlugin

```GO
// FilterPlugin是过滤器插件的接口。这些插件在过滤扩展点中被调用，用于过滤无法运行pod的主机。
// 在原始调度程序中，这个概念被称为“predicate”。
// 这些插件应该在Status.code中返回“Success”、“Unschedulable”或“Error”。
// 但是，调度程序也接受其他有效的代码。
// 除了“Success”之外的任何代码都将导致该主机被排除在运行pod的范围之外。
type FilterPlugin interface {
    Plugin
    // Filter被调度框架调用。
    // 所有Filter插件应该返回“Success”来声明给定节点适合pod。如果Filter没有返回“Success”，它将返回“Unschedulable”、“UnschedulableAndUnresolvable”或“Error”。
    // 对于正在评估的节点，Filter插件应该查看传递的nodeInfo引用，以获取特定节点信息的信息（例如，在节点上运行的pod），
    // 而不是在NodeInfoSnapshot中查找它们，因为我们不能保证它们将是相同的。
    // 例如，在抢占期间，我们可能会传递一个原始nodeInfo对象的副本，其中一些pod已从中删除，以评估抢占它们以调度目标pod的可能性。
    Filter(ctx context.Context, state *CycleState, pod *v1.Pod, nodeInfo *NodeInfo) *Status
}
```

#### PostFilterPlugin

```GO
// PostFilterPlugin是“PostFilter”插件的接口。这些插件在pod无法被调度后被调用。
type PostFilterPlugin interface {
    Plugin
    // PostFilter由调度框架调用。
    // PostFilter插件应返回以下状态之一：
    // - Unschedulable：插件执行成功，但无法使pod可调度。
    // - Success：插件执行成功，pod可调度。
    // - Error：插件由于某些内部错误而中止。
    //
    // 信息插件应该在其他插件之前进行配置，并始终返回Unschedulable状态。
    // 可选地，可以在Success状态下返回非nil的PostFilterResult。例如，
    // 抢占插件可以选择返回nominatedNodeName，以便框架可以重用它来更新抢占pod的.spec.status.nominatedNodeName字段。
    PostFilter(ctx context.Context, state *CycleState, pod *v1.Pod, filteredNodeStatusMap NodeToStatusMap) (*PostFilterResult, *Status)
}
```

#### PreScorePlugin

```GO
// PreScorePlugin是“PreScore”插件的接口。PreScore是一个信息扩展点。插件将使用通过过滤阶段的节点列表调用。
// 插件可以使用此数据来更新内部状态或生成日志/指标。
type PreScorePlugin interface {
    Plugin
    // PreScore由调度框架在通过过滤阶段的节点列表后调用。所有的预分数插件必须返回成功，
    // 否则pod将被拒绝。
    // 当它返回Skip状态时，状态中的其他字段将被忽略，并且耦合的Score插件将在此调度周期中被跳过。
    PreScore(ctx context.Context, state *CycleState, pod *v1.Pod, nodes []*v1.Node) *Status
}
```

#### ScorePlugin

```GO
// ScorePlugin是“Score”插件必须实现的接口，用于对通过筛选阶段的节点进行排序。
type ScorePlugin interface {
	Plugin
    // Score在每个过滤后的节点上调用。它必须返回成功和一个表示节点排名的整数。
    // 所有的评分插件都必须返回成功，否则Pod将被拒绝。
    Score(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string) (int64, *Status)
    // ScoreExtensions如果实现了，则返回ScoreExtensions接口，否则返回nil。
    ScoreExtensions() ScoreExtensions
}
```

##### ScoreExtensions

```GO
// ScoreExtensions是Score扩展功能的接口。
type ScoreExtensions interface {
    // NormalizeScore对同一插件的“Score”方法产生的所有节点分数进行调整。
    // 成功运行NormalizeScore将更新得分列表并返回成功状态。
    NormalizeScore(ctx context.Context, state *CycleState, p *v1.Pod, scores NodeScoreList) *Status
}
```

#### ReservePlugin

```GO
// ReservePlugin是具有Reserve和Unreserve方法的插件接口。这些方法用于更新插件状态。
// 在原始调度程序中，这个概念被称为“假定”。这些插件应该只返回Status.code中的Success或Error，但是调度程序也接受其他有效的代码。
// 除了Success之外的任何代码都将导致拒绝Pod。
type ReservePlugin interface {
Plugin
    // Reserve在更新调度程序缓存时由调度框架调用。如果此方法返回失败的状态，则调度程序将为所有启用的ReservePlugins调用Unreserve方法。
    Reserve(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string) *Status
    // Unreserve由调度框架在拒绝保留的Pod、在后续插件的保留过程中发生错误或在后续阶段调用时调用。
    // Unreserve方法的实现必须是幂等的，即使相应的插件的Reserve方法没有被调用，调度程序也可能会调用Unreserve方法。
    Unreserve(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string)
}
```

#### PreBindPlugin

```GO
// PreBindPlugin是“PreBind”插件必须实现的接口。
// 这些插件在调度Pod之前被调用。
type PreBindPlugin interface {
    Plugin
    // PreBind在绑定Pod之前被调用。所有PreBind插件都必须返回Success，否则Pod将被拒绝并且不会被发送进行绑定。
    PreBind(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string) *Status
}
```

#### BindPlugin

```GO
// BindPlugin 是实现“Bind”插件必须的接口。Bind插件用于将Pod绑定到节点。
type BindPlugin interface {
    Plugin
    // Bind插件在所有预绑定插件完成之前不会被调用。每个绑定插件按照配置的顺序调用。绑定插件可以选择是否处理给定的Pod。如果绑定插件选择处理Pod，则其余绑定插件将被跳过。当绑定插件不处理Pod时，它必须在其状态代码中返回“Skip”。如果绑定插件返回“Error”，则Pod将被拒绝并且不会被绑定。
    Bind(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string) *Status
}
```

#### PostBindPlugin

```GO
// PostBindPlugin 是实现“PostBind”插件必须的接口。这些插件在成功将Pod绑定到节点后调用。
type PostBindPlugin interface {
    Plugin
    // 在成功绑定Pod到节点后，将调用PostBind。这些插件是信息性的。这个扩展点的一个常见应用是清理。如果插件需要在调度和绑定Pod之后清除其状态，则PostBind是应该注册的扩展点。
    PostBind(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string)
}
```

#### PermitPlugin

```GO
// PermitPlugin是一个接口，必须由“Permit”插件实现。
// 这些插件在一个Pod被绑定到节点之前被调用。
type PermitPlugin interface {
    Plugin
    // Permit在绑定Pod之前（以及prebind插件之前）被调用。 Permit插件用于防止或延迟Pod的绑定。
    // 允许插件必须返回成功或等待一段时间，否则Pod将被拒绝。
    // 如果等待超时或者在等待时Pod被拒绝，那么Pod也会被拒绝。
    // 注意，如果插件返回“wait”，则框架只会在运行剩余插件之后等待，
    // 前提是没有其他插件拒绝该Pod。
    Permit(ctx context.Context, state *CycleState, p *v1.Pod, nodeName string) (*Status, time.Duration)
}
```

#### QueuedPodInfo

```GO
// QueuedPodInfo 是一个 Pod 包装器，附带了与调度队列中该 Pod 状态相关的其他信息，例如加入队列时的时间戳。
type QueuedPodInfo struct {
    *PodInfo
    // Pod 加入调度队列的时间戳。
    Timestamp time.Time
    // 成功调度前的尝试次数。它用于记录尝试次数指标。
    Attempts int
    // 当 Pod 第一次添加到队列时的时间。Pod 可能在成功调度之前被多次添加到队列中。
    // 一旦初始化，就不应再更新。它用于记录 Pod 的端到端调度延迟。
    InitialAttemptTimestamp time.Time
    // 如果 Pod 在调度周期中失败，则记录其失败的插件名称。
    UnschedulablePlugins sets.Set[string]
    // Pod 是否被调度阻塞（由 PreEnqueuePlugins）。
    Gated bool
}
```

##### PodInfo

```GO
// PodInfo 是一个包装器，包装了 Pod 对象，同时还包含了一些预处理的信息，以加速处理。这些信息通常是不可变的（例如，预处理的 pod 间亲和力选择器）。
type PodInfo struct {
    // Pod 对象
    Pod *v1.Pod
    // 所需的亲和性术语（AffinityTerm）列表
    RequiredAffinityTerms []AffinityTerm
    // 所需的反亲和性术语（AffinityTerm）列表
    RequiredAntiAffinityTerms []AffinityTerm
    // 首选亲和性术语（WeightedAffinityTerm）列表
    PreferredAffinityTerms []WeightedAffinityTerm
    // 首选反亲和性术语（WeightedAffinityTerm）列表
    PreferredAntiAffinityTerms []WeightedAffinityTerm
}
```

##### AffinityTerm&WeightedAffinityTerm

```GO
// AffinityTerm 是 v1.PodAffinityTerm 的处理版本。
type AffinityTerm struct {
    // Namespaces 指定了此术语（term）的限制范围（namespace）。
    Namespaces sets.Set[string]
    // Selector 是一个对 Pods 进行匹配的标签选择器。
    Selector labels.Selector
    // TopologyKey 指定了用于考虑拓扑域的标签的键。
    TopologyKey string
    // NamespaceSelector 是一个对 Namespaces 进行匹配的标签选择器。
    NamespaceSelector labels.Selector
}

// WeightedAffinityTerm 是 v1.WeightedAffinityTerm 的“处理”表示。
type WeightedAffinityTerm struct {
    // AffinityTerm 是 AffinityTerm 的一个实例，包含此加权术语的规范。
    AffinityTerm
    // Weight 是此加权术语的权重。
    Weight int32
}
```

### NewFramework

```go
// NewFramework初始化配置和注册表中的插件
func NewFramework(r Registry, profile *config.KubeSchedulerProfile, stopCh <-chan struct{}, opts ...Option) (framework.Framework, error) {
    // 使用默认框架选项初始化选项
    options := defaultFrameworkOptions(stopCh)
    // 处理传入的可选项
    for _, opt := range opts {
    	opt(&options)
    }
    // 创建框架实例
    f := &frameworkImpl{
        registry:             r,                      // 注册表
        snapshotSharedLister: options.snapshotSharedLister,   // 共享列表
        scorePluginWeight:    make(map[string]int),  // 用于储存插件的权重
        waitingPods:          newWaitingPodsMap(),   // 等待的 Pod 队列
        clientSet:            options.clientSet,     // 客户端集合
        kubeConfig:           options.kubeConfig,    // Kubernetes 配置
        eventRecorder:        options.eventRecorder, // 事件记录器
        informerFactory:      options.informerFactory,  // 通知工厂
        metricsRecorder:      options.metricsRecorder,  // 指标记录器
        extenders:            options.extenders,        // 扩展器
        PodNominator:         options.podNominator,     // Pod 提名器
        parallelizer:         options.parallelizer,     // 并行执行器
    }

    // 如果未指定调度器配置，则直接返回框架
    if profile == nil {
        return f, nil
    }

    // 设置调度器的名称和节点评分百分比
    f.profileName = profile.SchedulerName
    f.percentageOfNodesToScore = profile.PercentageOfNodesToScore
    // 如果调度器配置中未指定插件，则直接返回框架
    if profile.Plugins == nil {
        return f, nil
    }

    // 获取需要从配置中获取的插件
    pg := f.pluginsNeeded(profile.Plugins)

    // 遍历调度器配置中的插件，将其参数加入 pluginConfig 中
    pluginConfig := make(map[string]runtime.Object, len(profile.PluginConfig))
    for i := range profile.PluginConfig {
        name := profile.PluginConfig[i].Name
        // 如果同一个插件的配置出现了多次，则返回错误
        if _, ok := pluginConfig[name]; ok {
            return nil, fmt.Errorf("重复的插件配置: %s", name)
        }
        pluginConfig[name] = profile.PluginConfig[i].Args
    }
    // 构建配置文件输出框架
    outputProfile := config.KubeSchedulerProfile{
        SchedulerName:            f.profileName,
        PercentageOfNodesToScore: f.percentageOfNodesToScore,
        Plugins:                  profile.Plugins,
        PluginConfig:             make([]config.PluginConfig, 0, len(pg)),
    }

    // 创建插件映射
    pluginsMap := make(map[string]framework.Plugin)
   	// 循环遍历map r中的键值对，其中name是键，factory是值
    for name, factory := range r {

        // 如果pg中没有键为name的元素，则跳过此次循环
        if !pg.Has(name) {
            continue
        }

        // 获取名为name的插件的配置信息
        args := pluginConfig[name]
        if args != nil {
            // 将名为name的插件的配置信息添加到outputProfile.PluginConfig中
            outputProfile.PluginConfig = append(outputProfile.PluginConfig, config.PluginConfig{
                Name: name,
                Args: args,
            })
        }

        // 调用工厂函数factory，初始化插件，并将插件实例保存到pluginsMap中
        p, err := factory(args, f)
        if err != nil {
            return nil, fmt.Errorf("initializing plugin %q: %w", name, err)
        }
        pluginsMap[name] = p

        // 将插件p与options.clusterEventMap更新
        fillEventToPluginMap(p, options.clusterEventMap)
    }

    // 初始化每个扩展点的插件
    for _, e := range f.getExtensionPoints(profile.Plugins) {
        if err := updatePluginList(e.slicePtr, *e.plugins, pluginsMap); err != nil {
            return nil, err
        }
    }

    // 初始化MultiPoint插件
    if len(profile.Plugins.MultiPoint.Enabled) > 0 {
        if err := f.expandMultiPointPlugins(profile, pluginsMap); err != nil {
            return nil, err
        }
    }

    // 检查queueSortPlugins长度是否为1
    if len(f.queueSortPlugins) != 1 {
        return nil, fmt.Errorf("only one queue sort plugin required for profile with scheduler name %q, but got %d", profile.SchedulerName, len(f.queueSortPlugins))
    }

    // 检查bindPlugins长度是否为0
    if len(f.bindPlugins) == 0 {
        return nil, fmt.Errorf("at least one bind plugin is needed for profile with scheduler name %q", profile.SchedulerName)
    }

    // 获取Score插件的权重
    if err := getScoreWeights(f, pluginsMap, append(profile.Plugins.Score.Enabled, profile.Plugins.MultiPoint.Enabled...)); err != nil {
        return nil, err
    }

    // 验证Score插件的权重
    for _, scorePlugin := range f.scorePlugins {
        if f.scorePluginWeight[scorePlugin.Name()] == 0 {
            return nil, fmt.Errorf("score plugin %q is not configured with weight", scorePlugin.Name())
        }
    }

    // 如果options.captureProfile不为空，则将outputProfile传入captureProfile中
    if options.captureProfile != nil {
        if len(outputProfile.PluginConfig) != 0 {
            sort.Slice(outputProfile.PluginConfig, func(i, j int) bool {
                return outputProfile.PluginConfig[i].Name < outputProfile.PluginConfig[j].Name
            })
        } else {
            outputProfile.PluginConfig = nil
        }
        options.captureProfile(outputProfile)
    }

    return f, nil // 返回f和nil
}
```

#### frameworkOptions

```go
type frameworkOptions struct {
	componentConfigVersion string
	clientSet              clientset.Interface
	kubeConfig             *restclient.Config
	eventRecorder          events.EventRecorder
	informerFactory        informers.SharedInformerFactory
	snapshotSharedLister   framework.SharedLister
	metricsRecorder        *metrics.MetricAsyncRecorder
	podNominator           framework.PodNominator
	extenders              []framework.Extender
	captureProfile         CaptureProfile
	clusterEventMap        map[framework.ClusterEvent]sets.Set[string]
	parallelizer           parallelize.Parallelizer
}

// defaultFrameworkOptions are applied when no option corresponding to those fields exist.
func defaultFrameworkOptions(stopCh <-chan struct{}) frameworkOptions {
	return frameworkOptions{
		metricsRecorder: metrics.NewMetricsAsyncRecorder(1000, time.Second, stopCh),
		clusterEventMap: make(map[framework.ClusterEvent]sets.Set[string]),
		parallelizer:    parallelize.NewParallelizer(parallelize.DefaultParallelism),
	}
}

type Option func(*frameworkOptions)
```

#### pluginsNeeded

```go
// pluginsNeeded 方法用于获取需要使用的插件集合
func (f *frameworkImpl) pluginsNeeded(plugins *config.Plugins) sets.Set[string] {
	// 创建一个字符串集合 pgSet
	pgSet := sets.Set[string]{}

	// 如果 plugins 是 nil，则直接返回空的 pgSet 集合
	if plugins == nil {
		return pgSet
	}

	// 定义一个名为 find 的函数，用于查找并添加插件
	find := func(pgs *config.PluginSet) {
		for _, pg := range pgs.Enabled {
			pgSet.Insert(pg.Name)
		}
	}

	// 遍历 f.getExtensionPoints(plugins) 函数返回的 extensionPoint 切片
	for _, e := range f.getExtensionPoints(plugins) {
		find(e.plugins)
	}
	// 单独解析 MultiPoint，因为它们不会在 f.getExtensionPoints() 函数中返回
	find(&plugins.MultiPoint)

	// 返回 pgSet 集合
	return pgSet
}
```

##### getExtensionPoints

```go
// getExtensionPoints 方法用于获取插件的扩展点
func (f *frameworkImpl) getExtensionPoints(plugins *config.Plugins) []extensionPoint {
	// 返回一个包含多个 extensionPoint 实例的 extensionPoint 切片
	return []extensionPoint{
		{&plugins.PreFilter, &f.preFilterPlugins},
		{&plugins.Filter, &f.filterPlugins},
		{&plugins.PostFilter, &f.postFilterPlugins},
		{&plugins.Reserve, &f.reservePlugins},
		{&plugins.PreScore, &f.preScorePlugins},
		{&plugins.Score, &f.scorePlugins},
		{&plugins.PreBind, &f.preBindPlugins},
		{&plugins.Bind, &f.bindPlugins},
		{&plugins.PostBind, &f.postBindPlugins},
		{&plugins.Permit, &f.permitPlugins},
		{&plugins.PreEnqueue, &f.preEnqueuePlugins},
		{&plugins.QueueSort, &f.queueSortPlugins},
	}
}
```

#### fillEventToPluginMap

```go
func fillEventToPluginMap(p framework.Plugin, eventToPlugins map[framework.ClusterEvent]sets.Set[string]) {
	// 将插件转换为 `EnqueueExtensions` 接口类型并判断转换是否成功
	ext, ok := p.(framework.EnqueueExtensions)
	if !ok {
		// 如果插件未实现 `EnqueueExtensions` 接口，则注册默认事件到插件中，以保证向后兼容性。
		registerClusterEvents(p.Name(), eventToPlugins, allClusterEvents)
		return
	}

	// 如果插件实现了 `EnqueueExtensions` 接口，则调用其 `EventsToRegister()` 方法获取该插件要注册的事件列表
	events := ext.EventsToRegister()
	// 如果插件返回了空的事件列表，将日志记录为插件的 `EventsToRegister()` 返回了空
	if len(events) == 0 {
		klog.InfoS("Plugin's EventsToRegister() returned nil", "plugin", p.Name())
		return
	}

	// 如果插件返回了非空的事件列表，则将这些事件注册到插件中
	registerClusterEvents(p.Name(), eventToPlugins, events)
}
```

##### registerClusterEvents

```go
// 注册事件到插件映射
func registerClusterEvents(name string, eventToPlugins map[framework.ClusterEvent]sets.Set[string], evts []framework.ClusterEvent) {
	for _, evt := range evts {
		// 如果事件列表中没有该事件，则创建一个新的集合，并将插件名称添加到集合中
		if eventToPlugins[evt] == nil {
			eventToPlugins[evt] = sets.New(name)
		} else {
			// 如果事件列表中已经存在该事件，则将插件名称添加到该事件对应的集合中
			eventToPlugins[evt].Insert(name)
		}
	}
}
```

#### updatePluginList

```GO
func updatePluginList(pluginList interface{}, pluginSet config.PluginSet, pluginsMap map[string]framework.Plugin) error {
	plugins := reflect.ValueOf(pluginList).Elem()  // 通过反射获取 pluginList 的 Value 值，并获取其指针的 Value 值
	pluginType := plugins.Type().Elem()  // 获取 plugins 的元素类型

	set := sets.New[string]()  // 创建一个新的 set，用于存储已经添加的插件名
	for _, ep := range pluginSet.Enabled {  // 遍历插件配置列表
		pg, ok := pluginsMap[ep.Name]  // 从插件字典中获取当前插件名对应的插件
		if !ok {  // 如果插件字典中不存在当前插件名对应的插件，则返回错误
			return fmt.Errorf("%s %q does not exist", pluginType.Name(), ep.Name)
		}

		if !reflect.TypeOf(pg).Implements(pluginType) {  // 判断插件是否实现了 pluginType 接口
			return fmt.Errorf("plugin %q does not extend %s plugin", ep.Name, pluginType.Name())
		}

		if set.Has(ep.Name) {  // 如果 set 中已经包含了当前插件名，则返回错误
			return fmt.Errorf("plugin %q already registered as %q", ep.Name, pluginType.Name())
		}

		set.Insert(ep.Name)  // 将当前插件名加入 set 中

		newPlugins := reflect.Append(plugins, reflect.ValueOf(pg))  // 将 pg 转换为 Value 值，并将其追加到 plugins 切片中，生成一个新的切片
		plugins.Set(newPlugins)  // 将新的切片设置回原来的 plugins 切片
	}
	return nil  // 返回成功
}
```

#### expandMultiPointPlugins

```GO
func (f *frameworkImpl) expandMultiPointPlugins(profile *config.KubeSchedulerProfile, pluginsMap map[string]framework.Plugin) error {
    // 初始化 MultiPoint 插件
    for _, e := range f.getExtensionPoints(profile.Plugins) {
        plugins := reflect.ValueOf(e.slicePtr).Elem()
        pluginType := plugins.Type().Elem()

        // 为已通过正常扩展点注册的插件构建已启用集以检查双重注册
        enabledSet := newOrderedSet()
        for _, plugin := range e.plugins.Enabled {
            enabledSet.insert(plugin.Name)
        }

        // 获取已禁用插件的集合
        disabledSet := sets.New[string]()
        for _, disabledPlugin := range e.plugins.Disabled {
            disabledSet.Insert(disabledPlugin.Name)
        }

        // 如果已禁用所有插件，则跳过 MultiPoint 扩展
        if disabledSet.Has("*") {
            klog.V(4).InfoS("all plugins disabled for extension point, skipping MultiPoint expansion", "extension", pluginType)
            continue
        }

        // 跟踪通过多点启用的插件与通过特定扩展点启用的插件不同，以便我们可以区分双重注册和显式覆盖
        multiPointEnabled := newOrderedSet()
        overridePlugins := newOrderedSet()

        // 遍历 MultiPoint 启用的插件
        for _, ep := range profile.Plugins.MultiPoint.Enabled {
            // 检查插件是否存在
            pg, ok := pluginsMap[ep.Name]
            if !ok {
                return fmt.Errorf("%s %q does not exist", pluginType.Name(), ep.Name)
            }

            // 如果此插件未实现我们要扩展的当前扩展点的类型，则跳过
            if !reflect.TypeOf(pg).Implements(pluginType) {
                continue
            }

            // 通过 MultiPoint 启用的插件仍可以针对特定扩展点禁用
            if disabledSet.Has(ep.Name) {
                klog.V(4).InfoS("plugin disabled for extension point", "plugin", ep.Name, "extension", pluginType)
                continue
            }

            // 如果该插件已通过特定扩展点启用，则用户意图是覆盖默认插件或进行其他显式设置。
            // 无论哪种方式，都会丢弃该插件的 MultiPoint 值。 这维护了覆盖默认插件的预期行为
            if enabledSet.has(ep.Name) {
                overridePlugins.insert(ep.Name)
                klog.InfoS("MultiPoint plugin is explicitly re-configured; overriding", "plugin", ep.Name)
                continue
            }

            // 如果此插件已通过 MultiPoint 注册，则这是配置中的双重注册错误
            if multiPointEnabled.has(ep.Name) {
                return fmt.Errorf("plugin %q already registered as %q", ep.Name, pluginType.Name())
            }

            // 我们只需要更新多点集，因为我们已经从上面获得了特定扩展集
            multiPointEnabled.insert(ep.Name)
        }

        // 重新排序插件。期望的顺序如下：
        // - 第1部分：overridePlugins。它们的顺序保持与常规扩展点中指定的顺序相同。
        // - 第2部分：multiPointEnabled - 即，定义在多点上但不在常规扩展点上的插件。
        // - 第3部分：其他插件（由第1部分和第2部分排除）在常规扩展点上。
        newPlugins := reflect.New(reflect.TypeOf(e.slicePtr).Elem()).Elem()
        // 第1部分
        for _, name := range enabledSet.list {
            if overridePlugins.has(name) {
                newPlugins = reflect.Append(newPlugins, reflect.ValueOf(pluginsMap[name]))
                enabledSet.delete(name)
            }
        }
        // 第2部分
        for _, name := range multiPointEnabled.list {
        	newPlugins = reflect.Append(newPlugins, reflect.ValueOf(pluginsMap[name]))
        }
        // 第3部分
        for _, name := range enabledSet.list {
        	newPlugins = reflect.Append(newPlugins, reflect.ValueOf(pluginsMap[name]))
        }
        plugins.Set(newPlugins)
	}
	return nil
}
```

#### getScoreWeights

```GO
// getScoreWeights 确保在多点得分插件权重和单个得分插件之间，不会出现 MaxTotalScore 的溢出。
func getScoreWeights(f *frameworkImpl, pluginsMap map[string]framework.Plugin, plugins []config.Plugin) error {
    var totalPriority int64
    scorePlugins := reflect.ValueOf(&f.scorePlugins).Elem()
    pluginType := scorePlugins.Type().Elem()
    for _, e := range plugins {
        pg := pluginsMap[e.Name]
        if !reflect.TypeOf(pg).Implements(pluginType) {   // 检查插件是否是得分插件类型
            continue
        }

        // 将 MultiPoint 插件添加到得分插件列表中。因此，如果已经遇到此插件，则让单个得分权重优先。
        if _, ok := f.scorePluginWeight[e.Name]; ok {
            continue
        }
        // 权重值不能为零，插件可以在配置时被明确禁用。
        f.scorePluginWeight[e.Name] = int(e.Weight)
        if f.scorePluginWeight[e.Name] == 0 {
            f.scorePluginWeight[e.Name] = 1
        }

        // 检查 totalPriority 是否超出了 MaxTotalScore，以避免溢出。
        if int64(f.scorePluginWeight[e.Name])*framework.MaxNodeScore > framework.MaxTotalScore-totalPriority {
            return fmt.Errorf("total score of Score plugins could overflow")
        }
        totalPriority += int64(f.scorePluginWeight[e.Name]) * framework.MaxNodeScore
    }
    return nil
}
```

### PreEnqueuePlugins

```GO
func (f *frameworkImpl) PreEnqueuePlugins() []framework.PreEnqueuePlugin {
	return f.preEnqueuePlugins
}
```

### QueueSortFunc

```go
// QueueSortFunc返回用于对调度队列中的Pod进行排序的函数
func (f *frameworkImpl) QueueSortFunc() framework.LessFunc {
    if f == nil {
        // 如果frameworkImpl为nil，则保持它们的顺序不变。
        // 注意：这主要是为了测试。
        return func(_, _ *framework.QueuedPodInfo) bool { return false }
    }
    if len(f.queueSortPlugins) == 0 {
        // 如果没有注册QueueSort插件，则抛出异常。
        panic("No QueueSort plugin is registered in the frameworkImpl.")
    }

    // 只能启用一个QueueSort插件。
    return f.queueSortPlugins[0].Less
}
```

### RunPreFilterPlugins

```go
// RunPreFilterPlugins 运行配置的所有 PreFilter 插件，如果有任何插件返回的状态不是 Success/Skip，则返回 *Status，其状态码设置为非成功状态码。
// 如果返回 Skip 状态，则返回的 PreFilterResult 和 status 中的其他字段将被忽略，并且在此调度周期中 Filter 插件/PreFilterExtensions() 将被跳过。
// 如果返回的状态不是成功状态，则调度周期将被中止。
func (f *frameworkImpl) RunPreFilterPlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod) (_ *framework.PreFilterResult, status *framework.Status) {
	startTime := time.Now()
    // 记录函数执行时间
	defer func() {
		metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.PreFilter, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
	}()
	var result *framework.PreFilterResult
	var pluginsWithNodes []string
    // 记录已跳过的插件
	skipPlugins := sets.New[string]()
    // 遍历所有的 PreFilter 插件
	for _, pl := range f.preFilterPlugins {
        // 运行当前 PreFilter 插件
		r, s := f.runPreFilterPlugin(ctx, pl, state, pod)
        // 如果返回 Skip，则将该插件记录到已跳过列表中并跳过该插件
		if s.IsSkip() {
			skipPlugins.Insert(pl.Name())
			continue
		}
        // 记录插件评估总数
		metrics.PluginEvaluationTotal.WithLabelValues(pl.Name(), metrics.PreFilter, f.profileName).Inc()
		// 如果返回值不是成功状态，则将失败插件记录到 status 中
        if !s.IsSuccess() {
			s.SetFailedPlugin(pl.Name())
            // 如果返回不可调度状态，则直接返回该状态
			if s.IsUnschedulable() {
				return nil, s
			}
            // 否则，返回一个包含插件名的 framework.Status 类型的错误
			return nil, framework.AsStatus(fmt.Errorf("running PreFilter plugin %q: %w", pl.Name(), s.AsError())).WithFailedPlugin(pl.Name())
		}
        // 如果返回的 PreFilterResult 不是所有节点，则将该插件名添加到 pluginsWithNodes 中
		if !r.AllNodes() {
			pluginsWithNodes = append(pluginsWithNodes, pl.Name())
		}
        // 合并 PreFilterResult
		result = result.Merge(r)
        // 如果 PreFilterResult 不是所有节点并且 NodeNames 为空，则返回错误状态
		if !result.AllNodes() && len(result.NodeNames) == 0 {
			msg := fmt.Sprintf("node(s) didn't satisfy plugin(s) %v simultaneously", pluginsWithNodes)
			if len(pluginsWithNodes) == 1 {
				msg = fmt.Sprintf("node(s) didn't satisfy plugin %v", pluginsWithNodes[0])
			}
			return nil, framework.NewStatus(framework.Unschedulable, msg)
		}
	}
    // 将跳过的插件记录到 state 中并返回 PreFilterResult
	state.SkipFilterPlugins = skipPlugins
	return result, nil
}
```

#### runPreFilterPlugin

```go
func (f *frameworkImpl) runPreFilterPlugin(ctx context.Context, pl framework.PreFilterPlugin, state *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    if !state.ShouldRecordPluginMetrics() {
        return pl.PreFilter(ctx, state, pod)
    }
    startTime := time.Now()
    result, status := pl.PreFilter(ctx, state, pod)
    f.metricsRecorder.ObservePluginDurationAsync(metrics.PreFilter, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
    return result, status
}
```

##### ShouldRecordPluginMetrics

```GO
func (c *CycleState) ShouldRecordPluginMetrics() bool {
	if c == nil {
		return false
	}
	return c.recordPluginMetrics
}
```

#### IsSuccess

```go
func (s *Status) IsSuccess() bool {
	return s.Code() == Success
}
```

#### SetFailedPlugin

```go
func (s *Status) SetFailedPlugin(plugin string) {
	s.failedPlugin = plugin
}
```

#### IsSkip

```GO
func (s *Status) IsSkip() bool {
	return s.Code() == Skip
}
```

#### IsUnschedulable

```GO
// IsUnschedulable returns true if "Status" is Unschedulable (Unschedulable or UnschedulableAndUnresolvable).
func (s *Status) IsUnschedulable() bool {
	code := s.Code()
	return code == Unschedulable || code == UnschedulableAndUnresolvable
}
```

#### AllNodes

```GO
func (p *PreFilterResult) AllNodes() bool {
	return p == nil || p.NodeNames == nil
}
```

#### Merge

```GO
func (p *PreFilterResult) Merge(in *PreFilterResult) *PreFilterResult {
	if p.AllNodes() && in.AllNodes() {
		return nil
	}

	r := PreFilterResult{}
	if p.AllNodes() {
		r.NodeNames = in.NodeNames.Clone()
		return &r
	}
	if in.AllNodes() {
		r.NodeNames = p.NodeNames.Clone()
		return &r
	}

	r.NodeNames = p.NodeNames.Intersection(in.NodeNames)
	return &r
}
```

### RunPostFilterPlugins

```GO
func (f *frameworkImpl) RunPostFilterPlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod, filteredNodeStatusMap framework.NodeToStatusMap) (_ *framework.PostFilterResult, status *framework.Status) {
startTime := time.Now()
    // 记录运行时间
    defer func() {
    	metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.PostFilter, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
    }()
    // `result` 记录最后一个有意义（非空操作）的 PostFilterResult。
    var result *framework.PostFilterResult
    var reasons []string
    var failedPlugin string
    for _, pl := range f.postFilterPlugins {
        // 运行插件
        r, s := f.runPostFilterPlugin(ctx, pl, state, pod, filteredNodeStatusMap)
        // 如果插件运行成功，则立即返回结果和状态。
        if s.IsSuccess() {
            return r, s
        // 如果无法调度且无法解决，则返回结果和状态，并指明失败的插件。
        } else if s.Code() == framework.UnschedulableAndUnresolvable {
            return r, s.WithFailedPlugin(pl.Name())
        // 如果不是无法调度，则任何状态都是错误。
        } else if !s.IsUnschedulable() {
            return nil, framework.AsStatus(s.AsError()).WithFailedPlugin(pl.Name())
        // 如果 PostFilterResult 不为空且模式不为 ModeNoop，则记录结果。
        } else if r != nil && r.Mode() != framework.ModeNoop {
            result = r
        }

        reasons = append(reasons, s.Reasons()...)
        // 记录第一个失败的插件，除非我们证明后者更相关。
        if len(failedPlugin) == 0 {
            failedPlugin = pl.Name()
        }
    }

    // 返回 PostFilterResult 和状态，并指明失败的插件。
    return result, framework.NewStatus(framework.Unschedulable, reasons...).WithFailedPlugin(failedPlugin)
}
```

#### runPostFilterPlugin

```GO
func (f *frameworkImpl) runPostFilterPlugin(ctx context.Context, pl framework.PostFilterPlugin, state *framework.CycleState, pod *v1.Pod, filteredNodeStatusMap framework.NodeToStatusMap) (*framework.PostFilterResult, *framework.Status) {
	if !state.ShouldRecordPluginMetrics() {
		return pl.PostFilter(ctx, state, pod, filteredNodeStatusMap)
	}
	startTime := time.Now()
	r, s := pl.PostFilter(ctx, state, pod, filteredNodeStatusMap)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.PostFilter, pl.Name(), s.Code().String(), metrics.SinceInSeconds(startTime))
	return r, s
}
```

### RunPreBindPlugins

```GO
// RunPreBindPlugins 运行已配置的 prebind 插件集合。
// 如果任何一个插件返回错误，则它会返回一个 failure（bool）。
// 它还返回一个错误，其中包含拒绝消息或插件中发生的错误。
func (f *frameworkImpl) RunPreBindPlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (status *framework.Status) {
    startTime := time.Now() //记录开始时间
    defer func() { // 延迟函数，用于在函数返回时记录度量指标
    	metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.PreBind, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
    }()
	// 遍历 preBindPlugins，运行插件并返回状态
    for _, pl := range f.preBindPlugins {
        status = f.runPreBindPlugin(ctx, pl, state, pod, nodeName) // 运行插件，得到状态
        if !status.IsSuccess() {  // 如果状态不是成功的，处理错误
            if status.IsUnschedulable() {  // 如果插件返回未调度的状态，记录日志并设置插件失败
                klog.V(4).InfoS("Pod rejected by PreBind plugin", "pod", klog.KObj(pod), "node", nodeName, "plugin", pl.Name(), "status", status.Message())
                status.SetFailedPlugin(pl.Name())
                return status
            }
            // 如果插件返回其他错误状态，记录日志并返回失败的状态
            err := status.AsError()
            klog.ErrorS(err, "Failed running PreBind plugin", "plugin", pl.Name(), "pod", klog.KObj(pod), "node", nodeName)
            return framework.AsStatus(fmt.Errorf("running PreBind plugin %q: %w", pl.Name(), err))
        }
    }
    return nil // 返回成功状态
}
```

#### runPreBindPlugin

```GO
func (f *frameworkImpl) runPreBindPlugin(ctx context.Context, pl framework.PreBindPlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.PreBind(ctx, state, pod, nodeName)
	}
	startTime := time.Now()
	status := pl.PreBind(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.PreBind, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
```

### RunPostBindPlugins

```GO
// RunPostBindPlugins 运行一组已配置的PostBind插件。
func (f *frameworkImpl) RunPostBindPlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) {
	startTime := time.Now()
	defer func() {
		metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.PostBind, framework.Success.String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
	}()
	for _, pl := range f.postBindPlugins {
		f.runPostBindPlugin(ctx, pl, state, pod, nodeName)
	}
}
```

#### runPostBindPlugin

```GO
func (f *frameworkImpl) runPostBindPlugin(ctx context.Context, pl framework.PostBindPlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) {
	if !state.ShouldRecordPluginMetrics() {
		pl.PostBind(ctx, state, pod, nodeName)
		return
	}
	startTime := time.Now()
	pl.PostBind(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.PostBind, pl.Name(), framework.Success.String(), metrics.SinceInSeconds(startTime))
}
```

### RunReservePluginsReserve

```GO
// RunReservePluginsReserve 运行已配置的 reserve 插件集合的 Reserve 方法。
// 如果其中任何一个插件返回错误，则它不会继续运行剩余的插件，并返回错误。
// 在这种情况下，Pod 将无法被调度，调用者需要调用 RunReservePluginsUnreserve。
func (f *frameworkImpl) RunReservePluginsReserve(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (status *framework.Status) {
    startTime := time.Now() //记录开始时间
    defer func() { // 延迟函数，用于在函数返回时记录度量指标
    	metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Reserve, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
    }()
	// 遍历 reservePlugins，运行插件的 Reserve 方法并返回状态
    for _, pl := range f.reservePlugins {
        status = f.runReservePluginReserve(ctx, pl, state, pod, nodeName)  // 运行插件，得到状态
        if !status.IsSuccess() {  // 如果状态不是成功的，记录日志并返回失败的状态
            err := status.AsError()
            klog.ErrorS(err, "Failed running Reserve plugin", "plugin", pl.Name(), "pod", klog.KObj(pod))
            return framework.AsStatus(fmt.Errorf("running Reserve plugin %q: %w", pl.Name(), err))
        }
    }
    return nil // 返回成功状态
}
```

#### runReservePluginReserve

```GO
func (f *frameworkImpl) runReservePluginReserve(ctx context.Context, pl framework.ReservePlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.Reserve(ctx, state, pod, nodeName)
	}
	startTime := time.Now()
	status := pl.Reserve(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.Reserve, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
```

### RunReservePluginsUnreserve

```GO
// RunReservePluginsUnreserve 运行已配置的 reserve 插件集合的 Unreserve 方法。
func (f *frameworkImpl) RunReservePluginsUnreserve(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) {
    startTime := time.Now() //记录开始时间
    defer func() { // 延迟函数，用于在函数返回时记录度量指标
    	metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Unreserve, framework.Success.String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
    }()
    // 按 Reserve 操作执行的相反顺序执行每个 reserve 插件的 Unreserve 操作
    for i := len(f.reservePlugins) - 1; i >= 0; i-- {
        f.runReservePluginUnreserve(ctx, f.reservePlugins[i], state, pod, nodeName)  // 运行插件的 Unreserve 方法
    }
}
```

#### runReservePluginUnreserve

```GO
func (f *frameworkImpl) runReservePluginUnreserve(ctx context.Context, pl framework.ReservePlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) {
	if !state.ShouldRecordPluginMetrics() {
		pl.Unreserve(ctx, state, pod, nodeName)
		return
	}
	startTime := time.Now()
	pl.Unreserve(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.Unreserve, pl.Name(), framework.Success.String(), metrics.SinceInSeconds(startTime))
}
```

### RunPermitPlugins

```GO
// RunPermitPlugins 运行已配置的准入插件集合。如果任何一个插件返回的状态不是 "Success" 或 "Wait"，
// 它就不会继续运行剩余的插件并返回一个错误。否则，如果任何一个插件返回 "Wait"，则此函数将创建并添加一个等待的 pod，
// 并将其添加到当前等待 pod 的映射中，并返回带有 "Wait" 代码的状态。pod 将保持等待 pod，直到准入插件返回的最短持续时间。
func (f *frameworkImpl) RunPermitPlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (status *framework.Status) {
	startTime := time.Now()
	defer func() {
        // 记录 RunPermitPlugins 函数的执行时间
		metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Permit, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
	}()
    // 创建一个字符串-时间映射，表示每个准入插件需要等待的时间
	pluginsWaitTime := make(map[string]time.Duration)
	statusCode := framework.Success // 状态码初始化为 Success
	for _, pl := range f.permitPlugins { // 遍历准入插件
		status, timeout := f.runPermitPlugin(ctx, pl, state, pod, nodeName) // 运行当前准入插件，并获取状态和等待时间
		if !status.IsSuccess() {  // 如果当前插件返回的状态不是 "Success"
			if status.IsUnschedulable() {  // 如果返回的状态为 "Unschedulable"
				klog.V(4).InfoS("Pod rejected by permit plugin", "pod", klog.KObj(pod), "plugin", pl.Name(), "status", status.Message())
				status.SetFailedPlugin(pl.Name())  // 设置插件失败的名称
				return status  // 返回插件返回的状态
			}
			if status.IsWait() {  // 如果返回的状态为 "Wait"
				// 不允许等待时间大于最大等待时间
				if timeout > maxTimeout {
					timeout = maxTimeout
				}
				pluginsWaitTime[pl.Name()] = timeout  // 添加插件等待时间
				statusCode = framework.Wait // 更新状态码为 "Wait"
			} else {
				err := status.AsError() // 如果返回的状态不是 "Unschedulable" 也不是 "Wait"
				klog.ErrorS(err, "Failed running Permit plugin", "plugin", pl.Name(), "pod", klog.KObj(pod))
				return framework.AsStatus(fmt.Errorf("running Permit plugin %q: %w", pl.Name(), err)).WithFailedPlugin(pl.Name())
			}
		}
	}
	if statusCode == framework.Wait { // 如果状态码为 "Wait"
		waitingPod := newWaitingPod(pod, pluginsWaitTime) // 创建一个等待 pod
		f.waitingPods.add(waitingPod) // 将等待 pod 添加到等待 pod 映射中
		msg := fmt.Sprintf("one or more plugins asked to wait and no plugin rejected pod %q", pod.Name)
		klog.V(4).InfoS("One or more plugins asked to wait and no plugin rejected pod", "pod", klog.KObj(pod))
		return framework.NewStatus(framework.Wait, msg)
	}
	return nil
}
```

#### runPermitPlugin

```GO
func (f *frameworkImpl) runPermitPlugin(ctx context.Context, pl framework.PermitPlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) (*framework.Status, time.Duration) {
	if !state.ShouldRecordPluginMetrics() {
		return pl.Permit(ctx, state, pod, nodeName)
	}
	startTime := time.Now()
	status, timeout := pl.Permit(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.Permit, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status, timeout
}
```

### WaitOnPermit

```GO
// WaitOnPermit会阻塞，如果该Pod是一个等待的Pod，直到该Pod被拒绝或允许。
func (f *frameworkImpl) WaitOnPermit(ctx context.Context, pod *v1.Pod) *framework.Status {
    // 获取等待中的Pod
    waitingPod := f.waitingPods.get(pod.UID)
    // 如果等待中的Pod不存在，返回nil
    if waitingPod == nil {
    return nil
    }
    // 在函数退出时删除等待中的Pod
    defer f.waitingPods.remove(pod.UID)
    // 记录等待许可的Pod
    klog.V(4).InfoS("Pod waiting on permit", "pod", klog.KObj(pod))
    // 记录等待开始时间
    startTime := time.Now()
    // 等待获取等待中的Pod的信道
    s := <-waitingPod.s
    // 统计等待时长
    metrics.PermitWaitDuration.WithLabelValues(s.Code().String()).Observe(metrics.SinceInSeconds(startTime))

    // 如果获取信道后的状态为失败
    if !s.IsSuccess() {
        // 如果是不可调度的状态
        if s.IsUnschedulable() {
            klog.V(4).InfoS("Pod rejected while waiting on permit", "pod", klog.KObj(pod), "status", s.Message())
            return s
        }
        // 如果是其它失败状态，记录错误
        err := s.AsError()
        klog.ErrorS(err, "Failed waiting on permit for pod", "pod", klog.KObj(pod))
        // 返回失败的状态和失败的插件
        return framework.AsStatus(fmt.Errorf("waiting on permit for pod: %w", err)).WithFailedPlugin(s.FailedPlugin())
    }
    // 如果获取信道后的状态为成功，返回nil
    return nil
}
```

### runBindPlugin

```GO
// RunBindPlugins运行一组已配置的绑定插件，直到其中一个返回非“跳过”状态为止。
func (f *frameworkImpl) RunBindPlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (status *framework.Status) {
    // 记录开始时间，用于计算运行时长
    startTime := time.Now()
    // 在函数退出时，记录插件运行时长
    defer func() {
    	metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Bind, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
    }()
    // 如果没有绑定插件，则返回“跳过”状态
    if len(f.bindPlugins) == 0 {
    	return framework.NewStatus(framework.Skip, "")
    }
    // 遍历所有的绑定插件
    for _, pl := range f.bindPlugins {
        // 运行该插件
        status = f.runBindPlugin(ctx, pl, state, pod, nodeName)
        // 如果插件返回“跳过”状态，继续执行下一个插件
        if status.IsSkip() {
            continue
        }
        // 如果插件返回失败状态
        if !status.IsSuccess() {
            // 如果是不可调度的状态，记录日志并返回失败插件和状态
            if status.IsUnschedulable() {
                klog.V(4).InfoS("Pod rejected by Bind plugin", "pod", klog.KObj(pod), "node", nodeName, "plugin", pl.Name(), "status", status.Message())
                status.SetFailedPlugin(pl.Name())
                return status
            }
            // 如果是其它失败状态，记录日志并返回失败信息
            err := status.AsError()
            klog.ErrorS(err, "Failed running Bind plugin", "plugin", pl.Name(), "pod", klog.KObj(pod), "node", nodeName)
            return framework.AsStatus(fmt.Errorf("running Bind plugin %q: %w", pl.Name(), err))
        }
        // 如果插件返回成功状态，直接返回成功状态
        return status
    }
    // 如果所有插件都返回“跳过”状态，则返回最后一个插件的状态
    return status
}
```

#### runBindPlugin

```GO
func (f *frameworkImpl) runBindPlugin(ctx context.Context, bp framework.BindPlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return bp.Bind(ctx, state, pod, nodeName)
	}
	startTime := time.Now()
	status := bp.Bind(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.Bind, bp.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
```

### HasFilterPlugins

```GO
func (f *frameworkImpl) HasFilterPlugins() bool {
	return len(f.filterPlugins) > 0
}
```

### HasPostFilterPlugins

```GO
func (f *frameworkImpl) HasPostFilterPlugins() bool {
	return len(f.postFilterPlugins) > 0
}
```

### HasScorePlugins

```GO
func (f *frameworkImpl) HasScorePlugins() bool {
	return len(f.scorePlugins) > 0
}
```

### ListPlugins

```GO
// ListPlugins 返回一个 map，包含每个扩展点配置的插件名称。如果没有配置插件，则返回 nil。
func (f *frameworkImpl) ListPlugins() *config.Plugins {
    // 创建一个空的 Plugins 结构体
    m := config.Plugins{}
    // 获取各扩展点并为每个扩展点上的插件生成配置
    for _, e := range f.getExtensionPoints(&m) {
        // 获取插件 slice
        plugins := reflect.ValueOf(e.slicePtr).Elem()
        // 获取扩展点的名称
        extName := plugins.Type().Elem().Name()
        var cfgs []config.Plugin
        // 遍历所有插件，生成插件配置
        for i := 0; i < plugins.Len(); i++ {
            // 获取插件名称
            name := plugins.Index(i).Interface().(framework.Plugin).Name()
            // 创建一个插件配置，其中包含插件名称
            p := config.Plugin{Name: name}
            if extName == "ScorePlugin" {
                // 权重只适用于得分插件
                p.Weight = int32(f.scorePluginWeight[name])
            }
            // 将生成的插件配置添加到插件配置列表中
            cfgs = append(cfgs, p)
        }
        // 如果存在插件，则将其添加到 Plugins 结构体中
        if len(cfgs) > 0 {
            e.plugins.Enabled = cfgs
        }
    }
    // 返回配置的插件列表
    return &m
}
```

### ProfileName

```GO
func (f *frameworkImpl) ProfileName() string {
	return f.profileName
}
```

### PercentageOfNodesToScore

```GO
func (f *frameworkImpl) PercentageOfNodesToScore() *int32 {
	return f.percentageOfNodesToScore
}
```

### Parallelizer

```GO
func (f *frameworkImpl) Parallelizer() parallelize.Parallelizer {
	return f.parallelizer
}
```

### SnapshotSharedLister

```GO
func (f *frameworkImpl) SnapshotSharedLister() framework.SharedLister {
	return f.snapshotSharedLister
}
```

#### IterateOverWaitingPods

```GO
func (f *frameworkImpl) IterateOverWaitingPods(callback func(framework.WaitingPod)) {
	f.waitingPods.iterate(callback)
}
```

### GetWaitingPod

```GO
func (f *frameworkImpl) GetWaitingPod(uid types.UID) framework.WaitingPod {
	if wp := f.waitingPods.get(uid); wp != nil {
		return wp
	}
	return nil // Returning nil instead of *waitingPod(nil).
}
```

### RejectWaitingPod

```GO
func (f *frameworkImpl) RejectWaitingPod(uid types.UID) bool {
	if waitingPod := f.waitingPods.get(uid); waitingPod != nil {
		waitingPod.Reject("", "removed")
		return true
	}
	return false
}
```

### ClientSet

```GO
func (f *frameworkImpl) ClientSet() clientset.Interface {
	return f.clientSet
}
```

### KubeConfig

```GO
// KubeConfig returns a kubernetes config.
func (f *frameworkImpl) KubeConfig() *restclient.Config {
	return f.kubeConfig
}
```

### EventRecorder

```GO
// EventRecorder returns an event recorder.
func (f *frameworkImpl) EventRecorder() events.EventRecorder {
	return f.eventRecorder
}
```

### SharedInformerFactory

```GO
func (f *frameworkImpl) SharedInformerFactory() informers.SharedInformerFactory {
	return f.informerFactory
}
```

### RunFilterPluginsWithNominatedPods

```GO
// RunFilterPluginsWithNominatedPods 运行已配置的过滤器插件，对指定节点上的已指定的 pod 进行过滤。
// 此函数从两个不同的位置调用：Schedule 和 Preempt。
// 当它从 Schedule 调用时，我们想要测试该 pod 是否可以在节点上进行调度，包括节点上的所有现有 pod 以及已指定运行在节点上的具有更高或相等优先级的 pod。
// 当它从 Preempt 调用时，我们应该删除受抢占的 pod，并添加被指定的 pod。Preempt 在调用此函数之前，从 PreFilter 状态和 NodeInfo 中删除受害者。
func (f *frameworkImpl) RunFilterPluginsWithNominatedPods(ctx context.Context, state *framework.CycleState, pod *v1.Pod, info *framework.NodeInfo) *framework.Status {
	var status *framework.Status
    podsAdded := false
    // 在某些情况下我们会运行两次过滤器。如果节点具有优先级大于或等于的指定的 pod，则在将这些 pod 添加到 PreFilter 状态和 NodeInfo 时运行它们。
    // 如果所有过滤器在这一轮中都成功通过，则在这些被指定的 pod 未添加时再次运行它们。这第二遍是必要的，因为一些过滤器，如亲和力可能无法通过没有这些被指定的 pod。
    // 如果该节点没有被指定的 pod 或第一次运行过滤器失败，则不会运行第二遍。
    // 在第一遍中，我们只考虑优先级相等或更高的 pod，因为它们当前的“pod”必须向它们让步，而不能占据为其运行而打开的空间。如果当前的“pod”使用已释放的低优先级 pod 的资源，那么也是可以的。
    // 要求新的 pod 在这两种情况下都可以调度，确保我们做出了保守的决策：例如资源和跨 pod 亲和力之类的过滤器更可能在将被指定的 pod 视为运行时失败，而像 pod 亲和力之类的过滤器更可能在将被指定的 pod 视为不运行时失败。我们不能仅仅假设被指定的 pod 正在运行，因为它们现在没有运行，事实上它们可能会被调度到另一个节点。
    for i := 0; i < 2; i++ {
		stateToUse := state
		nodeInfoToUse := info
		if i == 0 {
			var err error
			podsAdded, stateToUse, nodeInfoToUse, err = addNominatedPods(ctx, f, pod, state, info)
			if err != nil {
				return framework.AsStatus(err)
			}
		} else if !podsAdded || !status.IsSuccess() {
			break
		}

		status = f.RunFilterPlugins(ctx, stateToUse, pod, nodeInfoToUse)
		if !status.IsSuccess() && !status.IsUnschedulable() {
			return status
		}
	}

	return status
}
```

#### addNominatedPods

```GO
// 该函数用于在节点上添加具有相等或更高优先级的已被提名的 Pod，函数返回三个参数：1）是否添加了任何 Pod，2）增强的 cycleState，3）增强的 nodeInfo。
func addNominatedPods(ctx context.Context, fh framework.Handle, pod *v1.Pod, state *framework.CycleState, nodeInfo *framework.NodeInfo) (bool, *framework.CycleState, *framework.NodeInfo, error) {
    // 如果 fh 或 nodeInfo.Node() 为 nil，则返回 false，state，nodeInfo 和 nil。
    if fh == nil || nodeInfo.Node() == nil {
        // This may happen only in tests.
        return false, state, nodeInfo, nil
    }

    // 获取已被提名的 Pod 信息。
    nominatedPodInfos := fh.NominatedPodsForNode(nodeInfo.Node().Name)
    // 如果没有已被提名的 Pod，则返回 false，state，nodeInfo 和 nil。
    if len(nominatedPodInfos) == 0 {
        return false, state, nodeInfo, nil
    }

    // 克隆 nodeInfo 和 cycleState。
    nodeInfoOut := nodeInfo.Clone()
    stateOut := state.Clone()
    // 用于记录是否添加了任何 Pod。
    podsAdded := false

    // 遍历已被提名的 Pod 信息。
    for _, pi := range nominatedPodInfos {
        // 如果该 Pod 优先级大于等于 pod 的优先级并且该 Pod 的 UID 不等于 pod 的 UID，则将该 Pod 添加到 nodeInfoOut 中。
        if corev1.PodPriority(pi.Pod) >= corev1.PodPriority(pod) && pi.Pod.UID != pod.UID {
            nodeInfoOut.AddPodInfo(pi)
            // 运行 preFilter extension 添加 Pod。
            status := fh.RunPreFilterExtensionAddPod(ctx, stateOut, pod, pi, nodeInfoOut)
            if !status.IsSuccess() {
                return false, state, nodeInfo, status.AsError()
            }
            // 标记已添加 Pod。
            podsAdded = true
        }
    }
    return podsAdded, stateOut, nodeInfoOut, nil
}
```

#### RunFilterPlugins

```GO
func (f *frameworkImpl) RunFilterPlugins(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	nodeInfo *framework.NodeInfo,
) *framework.Status {
	for _, pl := range f.filterPlugins {
		if state.SkipFilterPlugins.Has(pl.Name()) {
			continue
		}
		metrics.PluginEvaluationTotal.WithLabelValues(pl.Name(), metrics.Filter, f.profileName).Inc()
		if status := f.runFilterPlugin(ctx, pl, state, pod, nodeInfo); !status.IsSuccess() {
			if !status.IsUnschedulable() {
				// Filter plugins are not supposed to return any status other than
				// Success or Unschedulable.
				status = framework.AsStatus(fmt.Errorf("running %q filter plugin: %w", pl.Name(), status.AsError()))
			}
			status.SetFailedPlugin(pl.Name())
			return status
		}
	}

	return nil
}
```

### Extenders

```GO
func (f *frameworkImpl) Extenders() []framework.Extender {
	return f.extenders
}
```

### Parallelizer

```GO
func (f *frameworkImpl) Parallelizer() parallelize.Parallelizer {
	return f.parallelizer
}
```

### RunPreScorePlugins

```GO
// RunPreScorePlugins 函数运行预配置的预分数插件集合。如果任何插件返回除 Success/Skip 以外的状态，给定的 Pod 将被拒绝。
// 当返回 Skip 状态时，状态中的其他字段将被忽略，并且耦合的 Score 插件将在此调度周期中被跳过。
func (f *frameworkImpl) RunPreScorePlugins(
ctx context.Context,
state *framework.CycleState,
pod *v1.Pod,
nodes []*v1.Node,
) (status *framework.Status) {
    // 记录函数开始时间
    startTime := time.Now()
    // 延迟执行函数结束时的监控代码
    defer func() {
    	metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.PreScore, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
    }()
    // 新建一个 set 用于存储被跳过的插件
    skipPlugins := sets.Newstring
    // 遍历预分数插件集合
    for _, pl := range f.preScorePlugins {
        // 执行当前插件并获取执行结果
        status = f.runPreScorePlugin(ctx, pl, state, pod, nodes)
        // 如果插件返回 Skip 状态，记录被跳过的插件并继续下一个插件的执行
        if status.IsSkip() {
            skipPlugins.Insert(pl.Name())
            continue
        }
        // 如果插件返回非 Success/Skip 状态，则返回错误
        if !status.IsSuccess() {
        	return framework.AsStatus(fmt.Errorf("running PreScore plugin %q: %w", pl.Name(), status.AsError()))
        }
    }
    // 将被跳过的插件集合存储在 state 中，方便其他函数使用
    state.SkipScorePlugins = skipPlugins
    return nil
}
```

#### runPreScorePlugin

```GO
func (f *frameworkImpl) runPreScorePlugin(ctx context.Context, pl framework.PreScorePlugin, state *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.PreScore(ctx, state, pod, nodes)
	}
	startTime := time.Now()
	status := pl.PreScore(ctx, state, pod, nodes)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.PreScore, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
```

### RunScorePlugins

```GO
// RunScorePlugins 运行配置的一组打分插件。
// 它返回一个列表，其中存储了每个插件的分数以及每个节点的总分数。
// 它还返回一个Status，如果任何一个插件返回了非成功状态，则该Status将被设置为非成功状态。
func (f *frameworkImpl) RunScorePlugins(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) (ns []framework.NodePluginScores, status *framework.Status) {
	startTime := time.Now()
	defer func() {
        // 记录扩展点的执行时间
		metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Score, status.Code().String(), f.profileName).Observe(metrics.SinceInSeconds(startTime))
	}()
	// 为每个节点准备一个框架.NodePluginScores结构体，存储节点打分的结果
    allNodePluginScores := make([]framework.NodePluginScores, len(nodes))

    // 计算应该运行的插件数量
    numPlugins := len(f.scorePlugins) - state.SkipScorePlugins.Len()

    // 为了避免重新分配，先预估一下需要的切片长度，避免不必要的内存分配
    plugins := make([]framework.ScorePlugin, 0, numPlugins)
    pluginToNodeScores := make(map[string]framework.NodeScoreList, numPlugins)

    // 构建一个不包括跳过插件的插件列表
    for _, pl := range f.scorePlugins {
        if state.SkipScorePlugins.Has(pl.Name()) { // 如果需要跳过这个插件
            continue // 跳过该插件
        }
        plugins = append(plugins, pl) // 将该插件添加到插件列表中
        pluginToNodeScores[pl.Name()] = make(framework.NodeScoreList, len(nodes)) // 为每个插件都准备一个框架.NodeScoreList结构体，存储该插件对每个节点的打分结果
    }

    // 准备一个可取消的上下文
    ctx, cancel := context.WithCancel(ctx)
    defer cancel() // 在函数结束后，调用取消函数

    errCh := parallelize.NewErrorChannel() // 构建一个可读写的并行处理错误的通道

	if len(plugins) > 0 {
		// 并行执行每个插件的打分方法
		f.Parallelizer().Until(ctx, len(nodes), func(index int) {
			nodeName := nodes[index].Name // 获取当前节点的名称
			for _, pl := range plugins { // 遍历每个插件
				s, status := f.runScorePlugin(ctx, pl, state, pod, nodeName) // 运行插件的打分方法
                if !status.IsSuccess() { // 如果运行失败
                    err := fmt.Errorf("plugin %q failed with: %w", pl.Name(), status.AsError()) // 构造一个包含失败信息的错误
                    errCh.SendErrorWithCancel(err, cancel) // 发送错误
                    return // 退出当前函数
                }
				pluginToNodeScores[pl.Name()][index] = framework.NodeScore{
					Name:  nodeName,
					Score: s,
				}
			}
		}, metrics.Score)
        // 是否出错
		if err := errCh.ReceiveError(); err != nil {
			return nil, framework.AsStatus(fmt.Errorf("running Score plugins: %w", err))
		}
	}

	// 对每个 ScorePlugin 并行运行 NormalizeScore 方法。
	f.Parallelizer().Until(ctx, len(plugins), func(index int) {
		pl := plugins[index]
		if pl.ScoreExtensions() == nil {
			return
		}
		nodeScoreList := pluginToNodeScores[pl.Name()]
        // 调用 runScoreExtension 方法执行每个插件的 ScoreExtension 方法，并获取其状态。
		status := f.runScoreExtension(ctx, pl, state, pod, nodeScoreList)
		if !status.IsSuccess() {
            // 如果状态不是成功的，则生成错误信息并向 errCh 发送错误信息。
			err := fmt.Errorf("plugin %q failed with: %w", pl.Name(), status.AsError())
			errCh.SendErrorWithCancel(err, cancel)
			return
		}
	}, metrics.Score)
    // 接收 errCh 中的错误，如果 err 不为空，则将其包装为 framework.Status 返回。
	if err := errCh.ReceiveError(); err != nil {
		return nil, framework.AsStatus(fmt.Errorf("running Normalize on Score plugins: %w", err))
	}

	// 对每个 ScorePlugin 并行应用其权重，并构建 allNodePluginScores。
	f.Parallelizer().Until(ctx, len(nodes), func(index int) {
		nodePluginScores := framework.NodePluginScores{
			Name:   nodes[index].Name,
			Scores: make([]framework.PluginScore, len(plugins)),
		}

		for i, pl := range plugins {
            // 获取插件的权重和分数列表。
			weight := f.scorePluginWeight[pl.Name()]
			nodeScoreList := pluginToNodeScores[pl.Name()]
			score := nodeScoreList[index].Score
			
            // 如果分数超出范围，则生成错误信息并向 errCh 发送错误信息。
			if score > framework.MaxNodeScore || score < framework.MinNodeScore {
				err := fmt.Errorf("plugin %q returns an invalid score %v, it should in the range of [%v, %v] after normalizing", pl.Name(), score, framework.MinNodeScore, framework.MaxNodeScore)
				errCh.SendErrorWithCancel(err, cancel)
				return
			}
            // 计算加权分数，并将其添加到 nodePluginScores.Scores 中。
			weightedScore := score * int64(weight)
			nodePluginScores.Scores[i] = framework.PluginScore{
				Name:  pl.Name(),
				Score: weightedScore,
			}
			nodePluginScores.TotalScore += weightedScore
		}
		allNodePluginScores[index] = nodePluginScores
	}, metrics.Score)
    // 接收 errCh 中的错误，如果 err 不为空，则将其包装为 framework.Status 返回。
	if err := errCh.ReceiveError(); err != nil {
		return nil, framework.AsStatus(fmt.Errorf("applying score defaultWeights on Score plugins: %w", err))
	}

	return allNodePluginScores, nil
}
```

#### runScorePlugin

```GO
func (f *frameworkImpl) runScorePlugin(ctx context.Context, pl framework.ScorePlugin, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	if !state.ShouldRecordPluginMetrics() {
		return pl.Score(ctx, state, pod, nodeName)
	}
	startTime := time.Now()
	s, status := pl.Score(ctx, state, pod, nodeName)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.Score, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return s, status
}
```

#### runScoreExtension

```GO
func (f *frameworkImpl) runScoreExtension(ctx context.Context, pl framework.ScorePlugin, state *framework.CycleState, pod *v1.Pod, nodeScoreList framework.NodeScoreList) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.ScoreExtensions().NormalizeScore(ctx, state, pod, nodeScoreList)
	}
	startTime := time.Now()
	status := pl.ScoreExtensions().NormalizeScore(ctx, state, pod, nodeScoreList)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.ScoreExtensionNormalize, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
```

### RunFilterPlugins

```GO
// RunFilterPlugins 方法会运行一组配置好的过滤 Filter 插件，判断该节点是否适合运行 pod。如果其中任何插件返回不为“成功”的状态，则该节点不适合运行 pod，并设置相应的失败消息和状态。
func (f *frameworkImpl) RunFilterPlugins(
        ctx context.Context, // 传入上下文
        state *framework.CycleState, // 传入周期状态
        pod *v1.Pod, // 传入需要调度的 pod
        nodeInfo *framework.NodeInfo, // 传入要评估的节点信息
    ) *framework.Status { // 返回调度状态
    // 循环遍历所有 Filter 插件
    for _, pl := range f.filterPlugins {
        // 如果已经跳过了该插件，那么就继续下一个插件
        if state.SkipFilterPlugins.Has(pl.Name()) {
            continue
        }
        // 记录插件被评估的总数
        metrics.PluginEvaluationTotal.WithLabelValues(pl.Name(), metrics.Filter, f.profileName).Inc()
        // 运行 Filter 插件，评估当前节点和 pod 是否符合调度要求
        if status := f.runFilterPlugin(ctx, pl, state, pod, nodeInfo); !status.IsSuccess() {
            if !status.IsUnschedulable() {
                // Filter 插件只会返回 Success 或 Unschedulable，如果返回其他状态，则认为是出现了错误
                status = framework.AsStatus(fmt.Errorf("running %q filter plugin: %w", pl.Name(), status.AsError()))
            }
            status.SetFailedPlugin(pl.Name())  // 设置插件的名称
            return status  // 返回状态
        }
    }
    // 如果所有 Filter 插件都运行成功，则返回 nil 表示该节点适合运行该 pod
    return nil
}
```

#### runFilterPlugin

```GO
func (f *frameworkImpl) runFilterPlugin(ctx context.Context, pl framework.FilterPlugin, state *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.Filter(ctx, state, pod, nodeInfo)
	}
	startTime := time.Now()
	status := pl.Filter(ctx, state, pod, nodeInfo)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.Filter, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
```

### RunPreFilterExtensionAddPod

```GO
// RunPreFilterExtensionAddPod 调用配置的一组 PreFilter 插件的 AddPod 接口。
// 如果任何插件返回除 Success 外的任何状态，则直接返回。
func (f *frameworkImpl) RunPreFilterExtensionAddPod(
    ctx context.Context, // 上下文
    state *framework.CycleState, // 状态
    podToSchedule *v1.Pod, // 待调度的 Pod
    podInfoToAdd *framework.PodInfo, // 待添加的 PodInfo
    nodeInfo *framework.NodeInfo, // 节点信息
) (status *framework.Status) { // 返回的状态
    for _, pl := range f.preFilterPlugins { // 遍历 PreFilter 插件
        if pl.PreFilterExtensions() == nil || state.SkipFilterPlugins.Has(pl.Name()) { // 如果插件的 PreFilterExtensions 为空或被跳过，则继续
            continue
        }
        status = f.runPreFilterExtensionAddPod(ctx, pl, state, podToSchedule, podInfoToAdd, nodeInfo) // 调用 runPreFilterExtensionAddPod 方法
        if !status.IsSuccess() { // 如果状态不是 Success
            err := status.AsError() // 将状态转化为错误
            klog.ErrorS(err, "Failed running AddPod on PreFilter plugin", "plugin", pl.Name(), "pod", klog.KObj(podToSchedule)) // 记录错误日志
            return framework.AsStatus(fmt.Errorf("running AddPod on PreFilter plugin %q: %w", pl.Name(), err)) // 返回错误状态
        }
    }
    return nil // 返回成功状态
}
```

#### runPreFilterExtensionAddPod

````GO
func (f *frameworkImpl) runPreFilterExtensionAddPod(ctx context.Context, pl framework.PreFilterPlugin, state *framework.CycleState, podToSchedule *v1.Pod, podInfoToAdd *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.PreFilterExtensions().AddPod(ctx, state, podToSchedule, podInfoToAdd, nodeInfo)
	}
	startTime := time.Now()
	status := pl.PreFilterExtensions().AddPod(ctx, state, podToSchedule, podInfoToAdd, nodeInfo)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.PreFilterExtensionAddPod, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}
````

### RunPreFilterExtensionRemovePod

```GO
// RunPreFilterExtensionRemovePod 调用配置的一组 PreFilter 插件的 RemovePod 接口。
// 如果任何插件返回除 Success 外的任何状态，则直接返回。
func (f *frameworkImpl) RunPreFilterExtensionRemovePod(
    ctx context.Context, // 上下文
    state *framework.CycleState, // 状态
    podToSchedule *v1.Pod, // 待调度的 Pod
    podInfoToRemove *framework.PodInfo, // 待移除的 PodInfo
    nodeInfo *framework.NodeInfo, // 节点信息
) (status *framework.Status) { // 返回的状态
    for _, pl := range f.preFilterPlugins { // 遍历 PreFilter 插件
        if pl.PreFilterExtensions() == nil || state.SkipFilterPlugins.Has(pl.Name()) { // 如果插件的 PreFilterExtensions 为空或被跳过，则继续
        	continue
        }
        status = f.runPreFilterExtensionRemovePod(ctx, pl, state, podToSchedule, podInfoToRemove, nodeInfo) // 调用 runPreFilterExtensionRemovePod 方法
        if !status.IsSuccess() { // 如果状态不是 Success
            err := status.AsError() // 将状态转化为错误
            klog.ErrorS(err, "Failed running RemovePod on PreFilter plugin", "plugin", pl.Name(), "pod", klog.KObj(podToSchedule)) // 记录错误日志
            return framework.AsStatus(fmt.Errorf("running RemovePod on PreFilter plugin %q: %w", pl.Name(), err)) // 返回错误状态
        }
    }
	return nil // 返回成功状态
}
```

#### runPreFilterExtensionRemovePod

```GO
func (f *frameworkImpl) runPreFilterExtensionRemovePod(ctx context.Context, pl framework.PreFilterPlugin, state *framework.CycleState, podToSchedule *v1.Pod, podInfoToRemove *framework.PodInfo, nodeInfo *framework.NodeInfo) *framework.Status {
	if !state.ShouldRecordPluginMetrics() {
		return pl.PreFilterExtensions().RemovePod(ctx, state, podToSchedule, podInfoToRemove, nodeInfo)
	}
	startTime := time.Now()
	status := pl.PreFilterExtensions().RemovePod(ctx, state, podToSchedule, podInfoToRemove, nodeInfo)
	f.metricsRecorder.ObservePluginDurationAsync(metrics.PreFilterExtensionRemovePod, pl.Name(), status.Code().String(), metrics.SinceInSeconds(startTime))
	return status
}

```

