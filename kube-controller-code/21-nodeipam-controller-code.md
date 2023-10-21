
## 简介

nodeipam-controller是Kubernetes的一个控制器，它负责为每个节点分配来自集群CIDR（集群网络的IP范围）的专用子网（podCIDR）它会从集群CIDR中为每个节点分配一个专用子网（podCIDR）。这些podCIDR是不相交的子网，它允许为每个pod分配一个唯一的IP地址。

## 结构体

```GO
type Controller struct {
    // CIDR 分配器
	allocatorType ipam.CIDRAllocatorType
	// 云服务提供商的接口
	cloud                cloudprovider.Interface
    // 集群的 CIDR 范围
	clusterCIDRs         []*net.IPNet
    // 服务的 CIDR 范围
	serviceCIDR          *net.IPNet
    // 次要服务的 CIDR 范围
	secondaryServiceCIDR *net.IPNet
	kubeClient           clientset.Interface
    // 事件广播器
	eventBroadcaster     record.EventBroadcaster
	// 查找 IP 地址的方法
	lookupIP func(host string) ([]net.IP, error)

	nodeLister         corelisters.NodeLister
	nodeInformerSynced cache.InformerSynced
	// IPAM 控制器的实例
	legacyIPAM    ipamController
    // 用于实现 IP 地址的分配和回收等操作的控制器对象
	cidrAllocator ipam.CIDRAllocator
}
```

### CIDRAllocatorType

```GO
type CIDRAllocatorType string

const (
	// 使用一个内部 CIDR 范围分配器来进行节点 CIDR 范围分配的分配器类型
	RangeAllocatorType CIDRAllocatorType = "RangeAllocator"
	// 使用一个内部 CIDR 范围分配器来进行多个节点 CIDR 范围分配的分配器类型
	MultiCIDRRangeAllocatorType CIDRAllocatorType = "MultiCIDRRangeAllocator"
	// 使用云平台的支持来进行节点 CIDR 范围分配的分配器类型
	CloudAllocatorType CIDRAllocatorType = "CloudAllocator"
	// 使用 IPAM 控制器来同步从集群到云端的节点 CIDR 范围分配的分配器类型
	IPAMFromClusterAllocatorType = "IPAMFromCluster"
	// 使用 IPAM 控制器来同步从云端到集群的节点 CIDR 范围分配的分配器类型
	IPAMFromCloudAllocatorType = "IPAMFromCloud"
)
```

## New

```go
func NewNodeIpamController(
	ctx context.Context,
	nodeInformer coreinformers.NodeInformer,
	clusterCIDRInformer networkinginformers.ClusterCIDRInformer,
	cloud cloudprovider.Interface,
	kubeClient clientset.Interface,
	clusterCIDRs []*net.IPNet,
	serviceCIDR *net.IPNet,
	secondaryServiceCIDR *net.IPNet,
	nodeCIDRMaskSizes []int,
	allocatorType ipam.CIDRAllocatorType) (*Controller, error) {

	logger := klog.FromContext(ctx)
	if kubeClient == nil {
		return nil, fmt.Errorf("kubeClient is nil when starting Controller")
	}

	// 如果 allocatorType 是 CloudAllocatorType，那么就不需要 clusterCIDRs 和 nodeCIDRMaskSizes 这两个参数
	if allocatorType != ipam.CloudAllocatorType {
        // 检查 clusterCIDRs 是否为空
		if len(clusterCIDRs) == 0 {
			return nil, fmt.Errorf("Controller: Must specify --cluster-cidr if --allocate-node-cidrs is set")
		}
		// 检查 clusterCIDRs 的掩码是否小于等于 nodeCIDRMaskSizes
		for idx, cidr := range clusterCIDRs {
			mask := cidr.Mask
			if maskSize, _ := mask.Size(); maskSize > nodeCIDRMaskSizes[idx] {
				return nil, fmt.Errorf("Controller: Invalid --cluster-cidr, mask size of cluster CIDR must be less than or equal to --node-cidr-mask-size configured for CIDR family")
			}
		}
	}

	ic := &Controller{
		cloud:                cloud,
		kubeClient:           kubeClient,
		eventBroadcaster:     record.NewBroadcaster(),
		lookupIP:             net.LookupIP,
		clusterCIDRs:         clusterCIDRs,
		serviceCIDR:          serviceCIDR,
		secondaryServiceCIDR: secondaryServiceCIDR,
		allocatorType:        allocatorType,
	}

	// 如果 allocatorType 是 IPAMFromClusterAllocatorType 或者 IPAMFromCloudAllocatorType，那么就需要创建一个 legacyIPAM 对象
	if ic.allocatorType == ipam.IPAMFromClusterAllocatorType || ic.allocatorType == ipam.IPAMFromCloudAllocatorType {
		var err error
		ic.legacyIPAM, err = createLegacyIPAM(logger, ic, nodeInformer, cloud, kubeClient, clusterCIDRs, serviceCIDR, nodeCIDRMaskSizes)
		if err != nil {
			return nil, err
		}
	} else {
		var err error

		allocatorParams := ipam.CIDRAllocatorParams{
			ClusterCIDRs:         clusterCIDRs,
			ServiceCIDR:          ic.serviceCIDR,
			SecondaryServiceCIDR: ic.secondaryServiceCIDR,
			NodeCIDRMaskSizes:    nodeCIDRMaskSizes,
		}

		ic.cidrAllocator, err = ipam.New(ctx, kubeClient, cloud, nodeInformer, clusterCIDRInformer, ic.allocatorType, allocatorParams)
		if err != nil {
			return nil, err
		}
	}

	ic.nodeLister = nodeInformer.Lister()
	ic.nodeInformerSynced = nodeInformer.Informer().HasSynced

	return ic, nil
}
```

### createLegacyIPAM

```GO
func createLegacyIPAM(
	logger klog.Logger,
	ic *Controller,
	nodeInformer coreinformers.NodeInformer,
	cloud cloudprovider.Interface,
	kubeClient clientset.Interface,
	clusterCIDRs []*net.IPNet,
	serviceCIDR *net.IPNet,
	nodeCIDRMaskSizes []int,
) (*ipam.Controller, error) {
	cfg := &ipam.Config{
		Resync:       ipamResyncInterval,
		MaxBackoff:   ipamMaxBackoff,
		InitialRetry: ipamInitialBackoff,
	}
	switch ic.allocatorType {
	case ipam.IPAMFromClusterAllocatorType:
		cfg.Mode = nodesync.SyncFromCluster
	case ipam.IPAMFromCloudAllocatorType:
		cfg.Mode = nodesync.SyncFromCloud
	}

	// we may end up here with no cidr at all in case of FromCloud/FromCluster
	var cidr *net.IPNet
	if len(clusterCIDRs) > 0 {
		cidr = clusterCIDRs[0]
	}
	if len(clusterCIDRs) > 1 {
		logger.Info("Multiple cidrs were configured with FromCluster or FromCloud. cidrs except first one were discarded")
	}
	ipamc, err := ipam.NewController(cfg, kubeClient, cloud, cidr, serviceCIDR, nodeCIDRMaskSizes[0])
	if err != nil {
		return nil, fmt.Errorf("error creating ipam controller: %w", err)
	}
	if err := ipamc.Start(logger, nodeInformer); err != nil {
		return nil, fmt.Errorf("error trying to Init(): %w", err)
	}
	return ipamc, nil
}
```

## Run

```go
func (nc *Controller) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	// Start event processing pipeline.
	nc.eventBroadcaster.StartStructuredLogging(0)
	nc.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: nc.kubeClient.CoreV1().Events("")})
	defer nc.eventBroadcaster.Shutdown()
	klog.FromContext(ctx).Info("Starting ipam controller")
	defer klog.FromContext(ctx).Info("Shutting down ipam controller")

	if !cache.WaitForNamedCacheSync("node", ctx.Done(), nc.nodeInformerSynced) {
		return
	}
	// 如果 IPAM 类型是从集群分配器或云服务商分配器
	if nc.allocatorType == ipam.IPAMFromClusterAllocatorType || nc.allocatorType == ipam.IPAMFromCloudAllocatorType {
        // 启动遗留 IPAM 控制器运行
		go nc.legacyIPAM.Run(ctx)
	} else {
         // 启动 CIDR 分配器运行
		go nc.cidrAllocator.Run(ctx)
	}

	<-ctx.Done()
}
```

## legacyIPAM

被遗弃的方式这里不介绍了

## cidrAllocator

### 接口

```GO
type CIDRAllocator interface {
	// 给定一个节点，如果它当前没有 CIDR，为其分配一个有效的 CIDR；如果节点已经有一个 CIDR，将该 CIDR 标记为已使用。
	AllocateOrOccupyCIDR(logger klog.Logger, node *v1.Node) error
	// 释放已移除节点的 CIDR。
	ReleaseCIDR(logger klog.Logger, node *v1.Node) error
	// 启动分配器的工作逻辑。
	Run(ctx context.Context)
}
```

### New

```GO
type CIDRAllocatorParams struct {
	// 集群 CIDR 列表。
	ClusterCIDRs []*net.IPNet
	// 集群的主要 Service CIDR。
	ServiceCIDR *net.IPNet
	//集群的次要 Service CIDR。
	SecondaryServiceCIDR *net.IPNet
	// 节点 CIDR 掩码大小列表。
	NodeCIDRMaskSizes []int
}

// 根据不同的type创建CIDRAllocator
func New(ctx context.Context, kubeClient clientset.Interface, cloud cloudprovider.Interface, nodeInformer informers.NodeInformer, clusterCIDRInformer networkinginformers.ClusterCIDRInformer, allocatorType CIDRAllocatorType, allocatorParams CIDRAllocatorParams) (CIDRAllocator, error) {
	logger := klog.FromContext(ctx)
	nodeList, err := listNodes(logger, kubeClient)
	if err != nil {
		return nil, err
	}

	switch allocatorType {
	case RangeAllocatorType:
		return NewCIDRRangeAllocator(logger, kubeClient, nodeInformer, allocatorParams, nodeList)
	case MultiCIDRRangeAllocatorType:
		if !utilfeature.DefaultFeatureGate.Enabled(features.MultiCIDRRangeAllocator) {
			return nil, fmt.Errorf("invalid CIDR allocator type: %v, feature gate %v must be enabled", allocatorType, features.MultiCIDRRangeAllocator)
		}
		return NewMultiCIDRRangeAllocator(ctx, kubeClient, nodeInformer, clusterCIDRInformer, allocatorParams, nodeList, nil)

	case CloudAllocatorType:
		return NewCloudCIDRAllocator(logger, kubeClient, cloud, nodeInformer)
	default:
		return nil, fmt.Errorf("invalid CIDR allocator type: %v", allocatorType)
	}
}
```

### NewCIDRRangeAllocator

#### 结构体

```GO
type rangeAllocator struct {
	client clientset.Interface
	// cluster cidrs as passed in during controller creation
	clusterCIDRs []*net.IPNet
	// for each entry in clusterCIDRs we maintain a list of what is used and what is not
	cidrSets []*cidrset.CidrSet
	// nodeLister is able to list/get nodes and is populated by the shared informer passed to controller
	nodeLister corelisters.NodeLister
	// nodesSynced returns true if the node shared informer has been synced at least once.
	nodesSynced cache.InformerSynced
	// Channel that is used to pass updating Nodes and their reserved CIDRs to the background
	// This increases a throughput of CIDR assignment by not blocking on long operations.
	nodeCIDRUpdateChannel chan nodeReservedCIDRs
	broadcaster           record.EventBroadcaster
	recorder              record.EventRecorder
	// Keep a set of nodes that are currently being processed to avoid races in CIDR allocation
	lock              sync.Mutex
	nodesInProcessing sets.String
}
```

#### new

```GO
func NewCIDRRangeAllocator(logger klog.Logger, client clientset.Interface, nodeInformer informers.NodeInformer, allocatorParams CIDRAllocatorParams, nodeList *v1.NodeList) (CIDRAllocator, error) {
	if client == nil {
		logger.Error(nil, "kubeClient is nil when starting CIDRRangeAllocator")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "cidrAllocator"})

	// 遍历集群 CIDR，使用 cidrset.NewCIDRSet 函数创建 CIDR 地址集合
	cidrSets := make([]*cidrset.CidrSet, len(allocatorParams.ClusterCIDRs))
	for idx, cidr := range allocatorParams.ClusterCIDRs {
		cidrSet, err := cidrset.NewCIDRSet(cidr, allocatorParams.NodeCIDRMaskSizes[idx])
		if err != nil {
			return nil, err
		}
		cidrSets[idx] = cidrSet
	}
	
    // 创建 rangeAllocator 实例
	ra := &rangeAllocator{
		client:                client,
		clusterCIDRs:          allocatorParams.ClusterCIDRs,
		cidrSets:              cidrSets,
		nodeLister:            nodeInformer.Lister(),
		nodesSynced:           nodeInformer.Informer().HasSynced,
		nodeCIDRUpdateChannel: make(chan nodeReservedCIDRs, cidrUpdateQueueSize),
		broadcaster:           eventBroadcaster,
		recorder:              recorder,
		nodesInProcessing:     sets.NewString(),
	}
	
    // 如果指定了 ServiceCIDR 和 SecondaryServiceCIDR，过滤这些 CIDR 地址
	if allocatorParams.ServiceCIDR != nil {
		ra.filterOutServiceRange(logger, allocatorParams.ServiceCIDR)
	} else {
		logger.Info("No Service CIDR provided. Skipping filtering out service addresses")
	}

	if allocatorParams.SecondaryServiceCIDR != nil {
		ra.filterOutServiceRange(logger, allocatorParams.SecondaryServiceCIDR)
	} else {
		logger.Info("No Secondary Service CIDR provided. Skipping filtering out secondary service addresses")
	}

	if nodeList != nil {
        // 遍历节点列表，为每个节点分配 CIDR 地址
		for _, node := range nodeList.Items {
			if len(node.Spec.PodCIDRs) == 0 {
				logger.V(4).Info("Node has no CIDR, ignoring", "node", klog.KObj(&node))
				continue
			}
			logger.V(4).Info("Node has CIDR, occupying it in CIDR map", "node", klog.KObj(&node), "podCIDR", node.Spec.PodCIDR)
			if err := ra.occupyCIDRs(&node); err != nil {.
				return nil, err
			}
		}
	}
	// 为nodeInformer注册事件处理程序
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controllerutil.CreateAddNodeHandler(func(node *v1.Node) error {
			return ra.AllocateOrOccupyCIDR(logger, node)
		}),
		UpdateFunc: controllerutil.CreateUpdateNodeHandler(func(_, newNode *v1.Node) error {
			if len(newNode.Spec.PodCIDRs) == 0 {
                // 现在还没 就分配
				return ra.AllocateOrOccupyCIDR(logger, newNode)
			}
			return nil
		}),
		DeleteFunc: controllerutil.CreateDeleteNodeHandler(func(node *v1.Node) error {
            // 释放
			return ra.ReleaseCIDR(logger, node)
		}),
	})

	return ra, nil
}
```

##### NewCIDRSet

```go
func NewCIDRSet(clusterCIDR *net.IPNet, subNetMaskSize int) (*CidrSet, error) {
    // 传入的参数 clusterCIDR 是一个 IP 地址段，subNetMaskSize 是 CIDR 格式中掩码长度。
    // clusterMask 是 IP 地址段的掩码，clusterMaskSize 是 IP 地址段掩码中1的个数（即 CIDR 格式中的长度），bits 是掩码总长度
	clusterMask := clusterCIDR.Mask
	clusterMaskSize, bits := clusterMask.Size()
	
    // 如果传入的 clusterCIDR 是 IPv6 地址段或者传入的掩码长度超过了 IP 地址段的掩码长度 clusterMaskSize 加上 clusterSubnetMaxDiff（默认为 2），就返回一个 ErrCIDRSetSubNetTooBig 的错误。
	if (clusterCIDR.IP.To4() == nil) && (subNetMaskSize-clusterMaskSize > clusterSubnetMaxDiff) {
		return nil, ErrCIDRSetSubNetTooBig
	}

	// 监控
	registerCidrsetMetrics()
	
    // 该 IP 地址段可用的子网数
	maxCIDRs := getMaxCIDRs(subNetMaskSize, clusterMaskSize)
	cidrSet := &CidrSet{
		clusterCIDR:     clusterCIDR,
		nodeMask:        net.CIDRMask(subNetMaskSize, bits),
		clusterMaskSize: clusterMaskSize,
		maxCIDRs:        maxCIDRs,
		nodeMaskSize:    subNetMaskSize,
		label:           clusterCIDR.String(),
	}
	cidrSetMaxCidrs.WithLabelValues(cidrSet.label).Set(float64(maxCIDRs))

	return cidrSet, nil
}
```

###### getMaxCIDRs

```go
func getMaxCIDRs(subNetMaskSize, clusterMaskSize int) int {
	return 1 << uint32(subNetMaskSize-clusterMaskSize)
}
```

##### filterOutServiceRange

```go
// 判断服务 CIDR 是否属于该 CIDR 的子网，或者该 CIDR 是否属于服务 CIDR 的子网。
// 如果是，将服务 CIDR 添加到该 CIDR 的 CidrSet 中，以表示该 CIDR 中的 IP 地址不应分配给节点，因为它们已经被分配给服务了。
func (r *rangeAllocator) filterOutServiceRange(logger klog.Logger, serviceCIDR *net.IPNet) {
	for idx, cidr := range r.clusterCIDRs {
		if !cidr.Contains(serviceCIDR.IP.Mask(cidr.Mask)) && !serviceCIDR.Contains(cidr.IP.Mask(serviceCIDR.Mask)) {
			continue
		}
		if err := r.cidrSets[idx].Occupy(serviceCIDR); err != nil {
			logger.Error(err, "Error filtering out service cidr out cluster cidr", "CIDR", cidr, "index", idx, "serviceCIDR", serviceCIDR)
		}
	}
}
```

##### occupyCIDRs

```go
// 给定节点占用其 PodCIDRs 中的 CIDR
func (r *rangeAllocator) occupyCIDRs(node *v1.Node) error {
	defer r.removeNodeFromProcessing(node.Name)
	if len(node.Spec.PodCIDRs) == 0 {
		return nil
	}
	for idx, cidr := range node.Spec.PodCIDRs {
		_, podCIDR, err := netutils.ParseCIDRSloppy(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse node %s, CIDR %s", node.Name, node.Spec.PodCIDR)
		}
		// If node has a pre allocate cidr that does not exist in our cidrs.
		// This will happen if cluster went from dualstack(multi cidrs) to non-dualstack
		// then we have now way of locking it
		if idx >= len(r.cidrSets) {
			return fmt.Errorf("node:%s has an allocated cidr: %v at index:%v that does not exist in cluster cidrs configuration", node.Name, cidr, idx)
		}

		if err := r.cidrSets[idx].Occupy(podCIDR); err != nil {
			return fmt.Errorf("failed to mark cidr[%v] at idx [%v] as occupied for node: %v: %v", podCIDR, idx, node.Name, err)
		}
	}
	return nil
}
```

##### AllocateOrOccupyCIDR

```go
func (r *rangeAllocator) AllocateOrOccupyCIDR(logger klog.Logger, node *v1.Node) error {
	// 如果节点为空，直接返回
	if node == nil {
		return nil
	}
	// 尝试将节点插入到处理中，如果已经在处理中则直接返回
	if !r.insertNodeToProcessing(node.Name) {
		logger.V(2).Info("Node is already in a process of CIDR assignment", "node", klog.KObj(node))
		return nil
	}

	// 如果节点已经拥有了一个或多个 CIDR，则占用这些 CIDR
	if len(node.Spec.PodCIDRs) > 0 {
		return r.occupyCIDRs(node)
	}

	// 分配并排队 CIDR 的分配
	allocated := nodeReservedCIDRs{
		nodeName:       node.Name,
		allocatedCIDRs: make([]*net.IPNet, len(r.cidrSets)),
	}

	// 为每个 CIDR Set 分配下一个 CIDR
	for idx := range r.cidrSets {
		podCIDR, err := r.cidrSets[idx].AllocateNext()
		if err != nil {
			// 如果分配失败，将节点从处理中删除，记录事件，并返回错误
			r.removeNodeFromProcessing(node.Name)
			controllerutil.RecordNodeStatusChange(r.recorder, node, "CIDRNotAvailable")
			return fmt.Errorf("failed to allocate cidr from cluster cidr at idx:%v: %v", idx, err)
		}
		// 分配成功，将分配的 CIDR 记录在分配对象中
		allocated.allocatedCIDRs[idx] = podCIDR
	}

	// 将分配对象放入队列中
	logger.V(4).Info("Putting node with CIDR into the work queue", "node", klog.KObj(node), "CIDRs", allocated.allocatedCIDRs)
	r.nodeCIDRUpdateChannel <- allocated
	return nil
}
```

##### ReleaseCIDR

```go
func (r *rangeAllocator) ReleaseCIDR(logger klog.Logger, node *v1.Node) error {
    // 如果节点为空或节点的PodCIDRs为空，则不需要释放CIDR，直接返回nil
	if node == nil || len(node.Spec.PodCIDRs) == 0 {
		return nil
	}

	for idx, cidr := range node.Spec.PodCIDRs {
        // 解析PodCIDR
		_, podCIDR, err := netutils.ParseCIDRSloppy(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse CIDR %s on Node %v: %v", cidr, node.Name, err)
		}

		// 如果节点有一个预分配的CIDR，但该CIDR不存在于我们的CIDR集合中，则返回错误
		if idx >= len(r.cidrSets) {
			return fmt.Errorf("node:%s has an allocated cidr: %v at index:%v that does not exist in cluster cidrs configuration", node.Name, cidr, idx)
		}
		
        // 输出日志，释放CIDR
		logger.V(4).Info("Release CIDR for node", "CIDR", cidr, "node", klog.KObj(node))
		if err = r.cidrSets[idx].Release(podCIDR); err != nil {
			return fmt.Errorf("error when releasing CIDR %v: %v", cidr, err)
		}
	}
	return nil
}
```

#### Run

```go
func (r *rangeAllocator) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	// Start event processing pipeline.
	r.broadcaster.StartStructuredLogging(0)
	logger := klog.FromContext(ctx)
	logger.Info("Sending events to api server")
	r.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: r.client.CoreV1().Events("")})
	defer r.broadcaster.Shutdown()

	logger.Info("Starting range CIDR allocator")
	defer logger.Info("Shutting down range CIDR allocator")

	if !cache.WaitForNamedCacheSync("cidrallocator", ctx.Done(), r.nodesSynced) {
		return
	}

	for i := 0; i < cidrUpdateWorkers; i++ {
		go r.worker(ctx)
	}

	<-ctx.Done()
}
```

##### worker

```go
func (r *rangeAllocator) worker(ctx context.Context) {
	logger := klog.FromContext(ctx)
	for {
		select {
		case workItem, ok := <-r.nodeCIDRUpdateChannel:
			if !ok {
				logger.Info("Channel nodeCIDRUpdateChannel was unexpectedly closed")
				return
			}
			if err := r.updateCIDRsAllocation(logger, workItem); err != nil {
				// Requeue the failed node for update again.
				r.nodeCIDRUpdateChannel <- workItem
			}
		case <-ctx.Done():
			return
		}
	}
}
```

##### updateCIDRsAllocation

```go
func (r *rangeAllocator) updateCIDRsAllocation(logger klog.Logger, data nodeReservedCIDRs) error {
	var err error
	var node *v1.Node
	defer r.removeNodeFromProcessing(data.nodeName)
	cidrsString := ipnetToStringList(data.allocatedCIDRs)
    // 获取data.nodeName对应的节点
	node, err = r.nodeLister.Get(data.nodeName)
	if err != nil {
		logger.Error(err, "Failed while getting node for updating Node.Spec.PodCIDRs", "node", klog.KRef("", data.nodeName))
		return err
	}

	// 如果节点已经有了分配的CIDR，且分配的CIDR数目和data.allocatedCIDRs的数目相同，则判断它们是否一一对应。如果它们一一对应，则返回nil。
	if len(node.Spec.PodCIDRs) == len(data.allocatedCIDRs) {
		match := true
		for idx, cidr := range cidrsString {
			if node.Spec.PodCIDRs[idx] != cidr {
				match = false
				break
			}
		}
		if match {
			logger.V(4).Info("Node already has allocated CIDR. It matches the proposed one", "node", klog.KObj(node), "CIDRs", data.allocatedCIDRs)
			return nil
		}
	}

	// 如果节点已经有了分配的CIDR，但是分配的CIDR数目和data.allocatedCIDRs的数目不同，则释放data.allocatedCIDRs中的CIDR，并返回nil。
	if len(node.Spec.PodCIDRs) != 0 {
		logger.Error(nil, "Node already has a CIDR allocated. Releasing the new one", "node", klog.KObj(node), "podCIDRs", node.Spec.PodCIDRs)
		for idx, cidr := range data.allocatedCIDRs {
			if releaseErr := r.cidrSets[idx].Release(cidr); releaseErr != nil {
				logger.Error(releaseErr, "Error when releasing CIDR", "index", idx, "CIDR", cidr)
			}
		}
		return nil
	}

	// 如果节点没有分配CIDR，则调用nodeutil.PatchNodeCIDRs函数为节点分配CIDR。由于该操作可能会失败，因此会尝试多次。如果成功，则记录日志并返回nil。
	for i := 0; i < cidrUpdateRetries; i++ {
		if err = nodeutil.PatchNodeCIDRs(r.client, types.NodeName(node.Name), cidrsString); err == nil {
			logger.Info("Set node PodCIDR", "node", klog.KObj(node), "podCIDRs", cidrsString)
			return nil
		}
	}
	// failed release back to the pool
	logger.Error(err, "Failed to update node PodCIDR after multiple attempts", "node", klog.KObj(node), "podCIDRs", cidrsString)
	controllerutil.RecordNodeStatusChange(r.recorder, node, "CIDRAssignmentFailed")
	// We accept the fact that we may leak CIDRs here. This is safer than releasing
	// them in case when we don't know if request went through.
	// NodeController restart will return all falsely allocated CIDRs to the pool.
	if !apierrors.IsServerTimeout(err) {
		logger.Error(err, "CIDR assignment for node failed. Releasing allocated CIDR", "node", klog.KObj(node))
		for idx, cidr := range data.allocatedCIDRs {
			if releaseErr := r.cidrSets[idx].Release(cidr); releaseErr != nil {
				logger.Error(releaseErr, "Error releasing allocated CIDR for node", "node", klog.KObj(node))
			}
		}
	}
	return err
}
```

### NewMultiCIDRRangeAllocator

#### New

```GO
func NewMultiCIDRRangeAllocator(
	ctx context.Context,
	client clientset.Interface,
	nodeInformer informers.NodeInformer,
	clusterCIDRInformer networkinginformers.ClusterCIDRInformer,
	allocatorParams CIDRAllocatorParams,
	nodeList *v1.NodeList,
	testCIDRMap map[string][]*cidrset.ClusterCIDR,
) (CIDRAllocator, error) {
	logger := klog.FromContext(ctx)
	if client == nil {
		logger.Error(nil, "kubeClient is nil when starting multi CIDRRangeAllocator")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	eventBroadcaster := record.NewBroadcaster()
	eventSource := v1.EventSource{
		Component: "multiCIDRRangeAllocator",
	}
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, eventSource)
	// 创建multiCIDRRangeAllocator对象，并初始化其属性
	ra := &multiCIDRRangeAllocator{
		client:                client,
		nodeLister:            nodeInformer.Lister(),
		nodesSynced:           nodeInformer.Informer().HasSynced,
		clusterCIDRLister:     clusterCIDRInformer.Lister(),
		clusterCIDRSynced:     clusterCIDRInformer.Informer().HasSynced,
		nodeCIDRUpdateChannel: make(chan multiCIDRNodeReservedCIDRs, cidrUpdateQueueSize),
		broadcaster:           eventBroadcaster,
		recorder:              recorder,
		cidrQueue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "multi_cidr_range_allocator_cidr"),
		nodeQueue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "multi_cidr_range_allocator_node"),
		lock:                  &sync.Mutex{},
		cidrMap:               make(map[string][]*cidrset.ClusterCIDR, 0),
	}

	// 如果testCIDRMap非空，则将其赋值给multiCIDRRangeAllocator对象的cidrMap属性
	// testCIDRMap只用于测试，如果在生产日志中看到它，那可能是配置错误或者bug
	if len(testCIDRMap) > 0 {
		ra.cidrMap = testCIDRMap
		logger.Info("TestCIDRMap should only be set for testing purposes, if this is seen in production logs, it might be a misconfiguration or a bug")
	}
	// 获取集群中已有的ClusterCIDR列表
	ccList, err := listClusterCIDRs(ctx, client)
	if err != nil {
		return nil, err
	}
	// 如果ccList为nil，则创建一个空的ClusterCIDRList对象
	if ccList == nil {
		ccList = &networkingv1alpha1.ClusterCIDRList{}
	}
    // 为ccList添加默认的ClusterCIDR
	createDefaultClusterCIDR(logger, ccList, allocatorParams)

	// 从现有的ClusterCIDRs重新生成cidrMaps
	for _, clusterCIDR := range ccList.Items {
		logger.Info("Regenerating existing ClusterCIDR", "clusterCIDR", clusterCIDR)
		// 对于无效的ClusterCIDRs，创建一个事件，但不会导致程序崩溃
		if err := ra.reconcileBootstrap(ctx, &clusterCIDR); err != nil {
			logger.Error(err, "Error while regenerating existing ClusterCIDR")
			ra.recorder.Event(&clusterCIDR, "Warning", "InvalidClusterCIDR encountered while regenerating ClusterCIDR during bootstrap.", err.Error())
		}
	}
	
    // 为clusterCIDRInformer注册事件处理函数
	clusterCIDRInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				ra.cidrQueue.Add(key)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				ra.cidrQueue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// IndexerInformer uses a delta nodeQueue, therefore for deletes we have to use this
			// key function.
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				ra.cidrQueue.Add(key)
			}
		},
	})
	
    // 如果ServiceCIDR非空，则过滤掉Service CIDR范围内的地址
	if allocatorParams.ServiceCIDR != nil {
		ra.filterOutServiceRange(logger, allocatorParams.ServiceCIDR)
	} else {
		logger.Info("No Service CIDR provided. Skipping filtering out service addresses")
	}
	
    // 如果SecondaryServiceCIDR非空，则过滤掉Secondary Service CIDR范围内的地址
	if allocatorParams.SecondaryServiceCIDR != nil {
		ra.filterOutServiceRange(logger, allocatorParams.SecondaryServiceCIDR)
	} else {
		logger.Info("No Secondary Service CIDR provided. Skipping filtering out secondary service addresses")
	}
	// 如果nodeList非空，则遍历其中的节点，并占用它们的CIDR
	if nodeList != nil {
		for _, node := range nodeList.Items {
			if len(node.Spec.PodCIDRs) == 0 {
				logger.V(4).Info("Node has no CIDR, ignoring", "node", klog.KObj(&node))
				continue
			}
			logger.Info("Node has CIDR, occupying it in CIDR map", "node", klog.KObj(&node), "podCIDRs", node.Spec.PodCIDRs)
			if err := ra.occupyCIDRs(logger, &node); err != nil {
				// 如果占用CIDR失败，则返回错误并终止程序
				// 这种情况通常是由于podCIDRs字段中存在垃圾数据，或者CIDR超出了ClusterCIDR范围导致的
				return nil, err
			}
		}
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				ra.nodeQueue.Add(key)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				ra.nodeQueue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// 释放
			ra.ReleaseCIDR(logger, obj.(*v1.Node))
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				ra.nodeQueue.Add(key)
			}
		},
	})

	return ra, nil
}
```

##### listClusterCIDRs

```GO
func listClusterCIDRs(ctx context.Context, kubeClient clientset.Interface) (*networkingv1alpha1.ClusterCIDRList, error) {
	var clusterCIDRList *networkingv1alpha1.ClusterCIDRList
	// We must poll because apiserver might not be up. This error causes
	// controller manager to restart.
	startTimestamp := time.Now()

	// start with 2s, multiply the duration by 1.6 each step, 11 steps = 9.7 minutes
	backoff := wait.Backoff{
		Duration: 2 * time.Second,
		Factor:   1.6,
		Steps:    11,
	}

	logger := klog.FromContext(ctx)
	if pollErr := wait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		clusterCIDRList, err = kubeClient.NetworkingV1alpha1().ClusterCIDRs().List(ctx, metav1.ListOptions{
			FieldSelector: fields.Everything().String(),
			LabelSelector: labels.Everything().String(),
		})
		if err != nil {
			logger.Error(err, "Failed to list all clusterCIDRs")
			return false, nil
		}
		return true, nil
	}); pollErr != nil {
		logger.Error(nil, "Failed to list clusterCIDRs", "latency", time.Now().Sub(startTimestamp))
		return nil, fmt.Errorf("failed to list all clusterCIDRs in %v, cannot proceed without updating CIDR map",
			apiserverStartupGracePeriod)
	}
	return clusterCIDRList, nil
}
```

createDefaultClusterCIDR

```GO
func createDefaultClusterCIDR(logger klog.Logger, existingConfigList *networkingv1alpha1.ClusterCIDRList,
	allocatorParams CIDRAllocatorParams) {
	// Create default ClusterCIDR only if --cluster-cidr has been configured
	if len(allocatorParams.ClusterCIDRs) == 0 {
		return
	}
	
    // 遍历existingConfigList.Items，如果已经存在名为defaultClusterCIDRName的ClusterCIDR，则不需要再创建，直接返回。
	for _, clusterCIDR := range existingConfigList.Items {
		if clusterCIDR.Name == defaultClusterCIDRName {
			// Default ClusterCIDR already exists, no further action required.
			logger.V(3).Info("Default ClusterCIDR already exists", "defaultClusterCIDRName", defaultClusterCIDRName)
			return
		}
	}

	// 创建一个新的ClusterCIDR对象defaultCIDRConfig，设置其TypeMeta、ObjectMeta和Spec字段。
	defaultCIDRConfig := &networkingv1alpha1.ClusterCIDR{
		TypeMeta: metav1.TypeMeta{
			APIVersion: defaultClusterCIDRAPIVersion,
			Kind:       "ClusterCIDR",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultClusterCIDRName,
		},
		Spec: networkingv1alpha1.ClusterCIDRSpec{
			PerNodeHostBits: minPerNodeHostBits,
		},
	}
	
    // 设置ipv4PerNodeHostBits和ipv6PerNodeHostBits的初始值为最小整数值，isDualstack为len(allocatorParams.ClusterCIDRs) == 2的结果。
	ipv4PerNodeHostBits := int32(math.MinInt32)
	ipv6PerNodeHostBits := int32(math.MinInt32)
	isDualstack := false
	if len(allocatorParams.ClusterCIDRs) == 2 {
		isDualstack = true
	}
	
    // 遍历allocatorParams.ClusterCIDRs，如果是IPv4 CIDR，则将其设置为defaultCIDRConfig.Spec.IPv4，并计算ipv4PerNodeHostBits。
    // 如果!isDualstack && ipv4PerNodeHostBits > minPerNodeHostBits，则将其设置为defaultCIDRConfig.Spec.PerNodeHostBits。
    // 如果是IPv6 CIDR，则将其设置为defaultCIDRConfig.Spec.IPv6，并计算ipv6PerNodeHostBits。
    // 如果!isDualstack && ipv6PerNodeHostBits > minPerNodeHostBits，则将其设置为defaultCIDRConfig.Spec.PerNodeHostBits。
	for i, cidr := range allocatorParams.ClusterCIDRs {
		if netutil.IsIPv4CIDR(cidr) {
			defaultCIDRConfig.Spec.IPv4 = cidr.String()
			ipv4PerNodeHostBits = ipv4MaxCIDRMask - int32(allocatorParams.NodeCIDRMaskSizes[i])
			if !isDualstack && ipv4PerNodeHostBits > minPerNodeHostBits {
				defaultCIDRConfig.Spec.PerNodeHostBits = ipv4PerNodeHostBits
			}
		} else if netutil.IsIPv6CIDR(cidr) {
			defaultCIDRConfig.Spec.IPv6 = cidr.String()
			ipv6PerNodeHostBits = ipv6MaxCIDRMask - int32(allocatorParams.NodeCIDRMaskSizes[i])
			if !isDualstack && ipv6PerNodeHostBits > minPerNodeHostBits {
				defaultCIDRConfig.Spec.PerNodeHostBits = ipv6PerNodeHostBits
			}
		}
	}
	// 如果是Dualstack CIDR，则选择最小的PerNodeHostBits作为defaultCIDRConfig.Spec.PerNodeHostBits的值，以避免IPv4 CIDR的溢出。
	if isDualstack {
		// In case of dualstack CIDRs, currently the default values for PerNodeMaskSize are
		// 24 for IPv4 (PerNodeHostBits=8) and 64 for IPv6(PerNodeHostBits=64), there is no
		// requirement for the PerNodeHostBits to be equal for IPv4 and IPv6, However with
		// the introduction of ClusterCIDRs, we enforce the requirement for a single
		// PerNodeHostBits field, thus we choose the minimum PerNodeHostBits value, to avoid
		// overflow for IPv4 CIDRs.
		if ipv4PerNodeHostBits >= minPerNodeHostBits && ipv4PerNodeHostBits <= ipv6PerNodeHostBits {
			defaultCIDRConfig.Spec.PerNodeHostBits = ipv4PerNodeHostBits
		} else if ipv6PerNodeHostBits >= minPerNodeHostBits && ipv6PerNodeHostBits <= ipv4MaxCIDRMask {
			defaultCIDRConfig.Spec.PerNodeHostBits = ipv6PerNodeHostBits
		}
	}
	// 将新创建的ClusterCIDR对象defaultCIDRConfig添加到existingConfigList.Items中。
	existingConfigList.Items = append(existingConfigList.Items, *defaultCIDRConfig)

	return
}
```

##### reconcileBootstrap

```go
func (r *multiCIDRRangeAllocator) reconcileBootstrap(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDR) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	logger := klog.FromContext(ctx)
	terminating := false
	// Create the ClusterCIDR only if the Spec has not been modified.
	if clusterCIDR.Generation > 1 {
		terminating = true
		err := fmt.Errorf("CIDRs from ClusterCIDR %s will not be used for allocation as it was modified", clusterCIDR.Name)
		logger.Error(err, "ClusterCIDR Modified")
	}

	logger.V(2).Info("Creating ClusterCIDR during bootstrap", "clusterCIDR", clusterCIDR.Name)
	if err := r.createClusterCIDR(ctx, clusterCIDR, terminating); err != nil {
		logger.Error(err, "Unable to create ClusterCIDR", "clusterCIDR", clusterCIDR.Name)
		return err
	}

	return nil
}
```

###### createClusterCIDR

```go
// 根据 ClusterCIDR 对象，创建相应的 CIDR 以及 CIDR 映射关系
func (r *multiCIDRRangeAllocator) createClusterCIDR(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDR, terminating bool) error {
	nodeSelector, err := r.nodeSelectorKey(clusterCIDR)
	if err != nil {
		return fmt.Errorf("unable to get labelSelector key: %w", err)
	}

	clusterCIDRSet, err := r.createClusterCIDRSet(clusterCIDR, terminating)
	if err != nil {
		return fmt.Errorf("invalid ClusterCIDR: %w", err)
	}

	if clusterCIDRSet.IPv4CIDRSet == nil && clusterCIDRSet.IPv6CIDRSet == nil {
		return errors.New("invalid ClusterCIDR: must provide IPv4 and/or IPv6 config")
	}

	if err := r.mapClusterCIDRSet(r.cidrMap, nodeSelector, clusterCIDRSet); err != nil {
		return fmt.Errorf("unable to map clusterCIDRSet: %w", err)
	}

	// Make a copy so we don't mutate the shared informer cache.
	updatedClusterCIDR := clusterCIDR.DeepCopy()
	if needToAddFinalizer(clusterCIDR, clusterCIDRFinalizer) {
		updatedClusterCIDR.ObjectMeta.Finalizers = append(clusterCIDR.ObjectMeta.Finalizers, clusterCIDRFinalizer)
	}

	logger := klog.FromContext(ctx)
	if updatedClusterCIDR.ResourceVersion == "" {
		// Create is only used for creating default ClusterCIDR.
		if _, err := r.client.NetworkingV1alpha1().ClusterCIDRs().Create(ctx, updatedClusterCIDR, metav1.CreateOptions{}); err != nil {
			logger.V(2).Info("Error creating ClusterCIDR", "clusterCIDR", klog.KObj(clusterCIDR), "err", err)
			return err
		}
	} else {
		// Update the ClusterCIDR object when called from reconcileCreate.
		if _, err := r.client.NetworkingV1alpha1().ClusterCIDRs().Update(ctx, updatedClusterCIDR, metav1.UpdateOptions{}); err != nil {
			logger.V(2).Info("Error creating ClusterCIDR", "clusterCIDR", clusterCIDR.Name, "err", err)
			return err
		}
	}

	return nil
}
```

#### 结构体

```GO
type multiCIDRRangeAllocator struct {
	client clientset.Interface
	nodeLister corelisters.NodeLister
	nodesSynced cache.InformerSynced
	clusterCIDRLister networkinglisters.ClusterCIDRLister
	clusterCIDRSynced cache.InformerSynced.
	nodeCIDRUpdateChannel chan multiCIDRNodeReservedCIDRs
	broadcaster           record.EventBroadcaster
	recorder              record.EventRecorder

	cidrQueue workqueue.RateLimitingInterface
	nodeQueue workqueue.RateLimitingInterface

	lock *sync.Mutex
	cidrMap map[string][]*cidrset.ClusterCIDR
}

```

#### Run

```GO
func (r *multiCIDRRangeAllocator) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	// Start event processing pipeline.
	logger := klog.FromContext(ctx)
	r.broadcaster.StartStructuredLogging(0)
	logger.Info("Started sending events to API Server")
	r.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: r.client.CoreV1().Events("")})
	defer r.broadcaster.Shutdown()

	defer r.cidrQueue.ShutDown()
	defer r.nodeQueue.ShutDown()

	logger.Info("Starting Multi CIDR Range allocator")
	defer logger.Info("Shutting down Multi CIDR Range allocator")

	if !cache.WaitForNamedCacheSync("multi_cidr_range_allocator", ctx.Done(), r.nodesSynced, r.clusterCIDRSynced) {
		return
	}

	for i := 0; i < cidrUpdateWorkers; i++ {
		go wait.UntilWithContext(ctx, r.runCIDRWorker, time.Second)
		go wait.UntilWithContext(ctx, r.runNodeWorker, time.Second)
	}

	<-ctx.Done()
}
```

#### runCIDRWorker

```GO
func (r *multiCIDRRangeAllocator) runCIDRWorker(ctx context.Context) {
	for r.processNextCIDRWorkItem(ctx) {
	}
}

// processNextWorkItem will read a single work item off the cidrQueue and
// attempt to process it, by calling the syncHandler.
func (r *multiCIDRRangeAllocator) processNextCIDRWorkItem(ctx context.Context) bool {
	obj, shutdown := r.cidrQueue.Get()
	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.cidrQueue.Done.
	err := func(ctx context.Context, obj interface{}) error {
		defer r.cidrQueue.Done(obj)
		var key string
		var ok bool

		if key, ok = obj.(string); !ok {

			r.cidrQueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in cidrQueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err := r.syncClusterCIDR(ctx, key); err != nil {
			// Put the item back on the cidrQueue to handle any transient errors.
			r.cidrQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get cidrQueued again until another change happens.
		r.cidrQueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(ctx, obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}
```

##### syncClusterCIDR

```GO
func (r *multiCIDRRangeAllocator) syncClusterCIDR(ctx context.Context, key string) error {
	startTime := time.Now()
	logger := klog.FromContext(ctx)
	defer func() {
		logger.V(4).Info("Finished syncing clusterCIDR request", "key", key, "latency", time.Since(startTime))
	}()

	clusterCIDR, err := r.clusterCIDRLister.Get(key)
	if apierrors.IsNotFound(err) {
		logger.V(3).Info("clusterCIDR has been deleted", "key", key)
		return nil
	}

	if err != nil {
		return err
	}

	// 检查DeletionTimestamp以确定对象是否处于删除状态
	if !clusterCIDR.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, clusterCIDR)
	}
	return r.reconcileCreate(ctx, clusterCIDR)
}
```

###### reconcileDelete

```GO
func (r *multiCIDRRangeAllocator) reconcileDelete(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDR) error {
    // 获取锁，防止其他线程修改 CIDR 映射
	r.lock.Lock()
	defer r.lock.Unlock()

    // 如果该 ClusterCIDR 对象有我们自己的 finalizer，则进行释放操作
	logger := klog.FromContext(ctx)
	if slice.ContainsString(clusterCIDR.GetFinalizers(), clusterCIDRFinalizer, nil) {
        // 记录释放操作的日志
		logger.V(2).Info("Releasing ClusterCIDR", "clusterCIDR", clusterCIDR.Name)
        // 从 CIDR 映射中删除该 ClusterCIDR 对象
		if err := r.deleteClusterCIDR(logger, clusterCIDR); err != nil {
			klog.V(2).Info("Error while deleting ClusterCIDR", "err", err)
			return err
		}
        // 从该 ClusterCIDR 对象的 finalizer 中移除我们自己的 finalizer
		cccCopy := clusterCIDR.DeepCopy()
		cccCopy.ObjectMeta.Finalizers = slice.RemoveString(cccCopy.ObjectMeta.Finalizers, clusterCIDRFinalizer, nil)
		if _, err := r.client.NetworkingV1alpha1().ClusterCIDRs().Update(ctx, cccCopy, metav1.UpdateOptions{}); err != nil {
			logger.V(2).Info("Error removing finalizer for ClusterCIDR", "clusterCIDR", clusterCIDR.Name, "err", err)
			return err
		}
		logger.V(2).Info("Removed finalizer for ClusterCIDR", "clusterCIDR", clusterCIDR.Name)
	}
	return nil
}

```

###### reconcileDelete

```GO
func (r *multiCIDRRangeAllocator) reconcileCreate(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDR) error {
    // 获取锁，以避免并发修改
    r.lock.Lock()
    defer r.lock.Unlock()

    logger := klog.FromContext(ctx)
    // 如果该 ClusterCIDR 对象还没有添加 finalizer，则需要添加
    if needToAddFinalizer(clusterCIDR, clusterCIDRFinalizer) {
        logger.V(3).Info("Creating ClusterCIDR", "clusterCIDR", clusterCIDR.Name)
        // 调用 createClusterCIDR 函数创建 ClusterCIDR 资源
        if err := r.createClusterCIDR(ctx, clusterCIDR, false); err != nil {
            logger.Error(err, "Unable to create ClusterCIDR", "clusterCIDR", clusterCIDR.Name)
            return err
        }
    }
    return nil
}


func needToAddFinalizer(obj metav1.Object, finalizer string) bool {
	return obj.GetDeletionTimestamp() == nil && !slice.ContainsString(obj.GetFinalizers(),
		finalizer, nil)
}

func (r *multiCIDRRangeAllocator) createClusterCIDR(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDR, terminating bool) error {
    // 获取 nodeSelector。
    nodeSelector, err := r.nodeSelectorKey(clusterCIDR)
    if err != nil {
        return fmt.Errorf("unable to get labelSelector key: %w", err)
    }

    // 创建 ClusterCIDR 集合。
    clusterCIDRSet, err := r.createClusterCIDRSet(clusterCIDR, terminating)
    if err != nil {
        return fmt.Errorf("invalid ClusterCIDR: %w", err)
    }

    // 检查 IPv4CIDRSet 和 IPv6CIDRSet 是否都为空。
    if clusterCIDRSet.IPv4CIDRSet == nil && clusterCIDRSet.IPv6CIDRSet == nil {
        return errors.New("invalid ClusterCIDR: must provide IPv4 and/or IPv6 config")
    }

    // 映射 ClusterCIDR 集合。
    if err := r.mapClusterCIDRSet(r.cidrMap, nodeSelector, clusterCIDRSet); err != nil {
        return fmt.Errorf("unable to map clusterCIDRSet: %w", err)
    }

    // 复制 ClusterCIDR，以便不会改变共享的 Informer 缓存。
    updatedClusterCIDR := clusterCIDR.DeepCopy()
    if needToAddFinalizer(clusterCIDR, clusterCIDRFinalizer) {
        updatedClusterCIDR.ObjectMeta.Finalizers = append(clusterCIDR.ObjectMeta.Finalizers, clusterCIDRFinalizer)
    }

    logger := klog.FromContext(ctx)
    // 判断 ClusterCIDR 是否已经存在。
    if updatedClusterCIDR.ResourceVersion == "" {
        // 如果不存在，则创建 ClusterCIDR，用于创建默认的 ClusterCIDR。
        if _, err := r.client.NetworkingV1alpha1().ClusterCIDRs().Create(ctx, updatedClusterCIDR, metav1.CreateOptions{}); err != nil {
            logger.V(2).Info("Error creating ClusterCIDR", "clusterCIDR", klog.KObj(clusterCIDR), "err", err)
            return err
        }
    } else {
        // 如果已经存在，则更新 ClusterCIDR 对象，用于从 reconcileCreate 中调用。
        if _, err := r.client.NetworkingV1alpha1().ClusterCIDRs().Update(ctx, updatedClusterCIDR, metav1.UpdateOptions{}); err != nil {
            logger.V(2).Info("Error creating ClusterCIDR", "clusterCIDR", clusterCIDR.Name, "err", err)
            return err
        }
    }

    return nil
}
```

#### runNodeWorker

```GO
func (r *multiCIDRRangeAllocator) runNodeWorker(ctx context.Context) {
	for r.processNextNodeWorkItem(ctx) {
	}
}

func (r *multiCIDRRangeAllocator) processNextNodeWorkItem(ctx context.Context) bool {
	obj, shutdown := r.nodeQueue.Get()
	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.cidrQueue.Done.
	err := func(logger klog.Logger, obj interface{}) error {

		defer r.nodeQueue.Done(obj)
		var key string
		var ok bool

		if key, ok = obj.(string); !ok {
			r.nodeQueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workNodeQueue but got %#v", obj))
			return nil
		}

		if err := r.syncNode(logger, key); err != nil {
			// Put the item back on the cidrQueue to handle any transient errors.
			r.nodeQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get nodeQueue again until another change happens.
		r.nodeQueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(klog.FromContext(ctx), obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}
```

##### syncNode

```GO
func (r *multiCIDRRangeAllocator) syncNode(logger klog.Logger, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Node request %q (%v)", key, time.Since(startTime))
	}()

	node, err := r.nodeLister.Get(key)
	if apierrors.IsNotFound(err) {
		klog.V(3).Infof("node has been deleted: %v", key)

		return nil
	}
	if err != nil {
		return err
	}
	// Check the DeletionTimestamp to determine if object is under deletion.
	if !node.DeletionTimestamp.IsZero() {
		klog.V(3).Infof("node is being deleted: %v", key)
		return r.ReleaseCIDR(logger, node)
	}
	return r.AllocateOrOccupyCIDR(logger, node)
}
```

###### ReleaseCIDR

```GO
func (r *multiCIDRRangeAllocator) ReleaseCIDR(logger klog.Logger, node *v1.Node) error {
	// 对 r 进行互斥锁操作，以防止多个 goroutine 同时访问和修改 r 的状态。
	r.lock.Lock()
	defer r.lock.Unlock()

	// 如果节点为空或者节点上没有分配的 PodCIDR，那么直接返回，不需要释放任何 CIDR。
	if node == nil || len(node.Spec.PodCIDRs) == 0 {
		return nil
	}

	// 获取分配给节点的 ClusterCIDR 对象。
	clusterCIDR, err := r.allocatedClusterCIDR(logger, node)
	if err != nil {
		return err
	}

	// 遍历节点上的所有 PodCIDR，释放这些 CIDR。
	for _, cidr := range node.Spec.PodCIDRs {
		_, podCIDR, err := netutil.ParseCIDRSloppy(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse CIDR %q on Node %q: %w", cidr, node.Name, err)
		}

		logger.Info("release CIDR for node", "CIDR", cidr, "node", klog.KObj(node))
		if err := r.Release(logger, clusterCIDR, podCIDR); err != nil {
			return fmt.Errorf("failed to release cidr %q from clusterCIDR %q for node %q: %w", cidr, clusterCIDR.Name, node.Name, err)
		}
	}

	// 从 ClusterCIDR 的 AssociatedNodes 字典中删除该节点。
	delete(clusterCIDR.AssociatedNodes, node.Name)

	return nil
}

```

###### AllocateOrOccupyCIDR

```GO
func (r *multiCIDRRangeAllocator) AllocateOrOccupyCIDR(logger klog.Logger, node *v1.Node) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if node == nil {
		return nil
	}

	// 如果节点已经有PodCIDR，则直接占用
	if len(node.Spec.PodCIDRs) > 0 {
		return r.occupyCIDRs(logger, node)
	}

	// 从可用的CIDR集合中选择一个CIDR用于分配给该节点
	cidrs, clusterCIDR, err := r.prioritizedCIDRs(logger, node)
	if err != nil {
		// 记录节点状态变更并返回错误
		controllerutil.RecordNodeStatusChange(r.recorder, node, "CIDRNotAvailable")
		return fmt.Errorf("failed to get cidrs for node %s", node.Name)
	}

	if len(cidrs) == 0 {
		// 记录节点状态变更并返回错误
		controllerutil.RecordNodeStatusChange(r.recorder, node, "CIDRNotAvailable")
		return fmt.Errorf("no cidrSets with matching labels found for node %s", node.Name)
	}

	// 为节点分配CIDR并将信息添加到待处理队列中
	allocated := multiCIDRNodeReservedCIDRs{
		nodeReservedCIDRs: nodeReservedCIDRs{
			nodeName:       node.Name,
			allocatedCIDRs: cidrs,
		},
		clusterCIDR: clusterCIDR,
	}

	return r.updateCIDRsAllocation(logger, allocated)
}

func (r *multiCIDRRangeAllocator) updateCIDRsAllocation(logger klog.Logger, data multiCIDRNodeReservedCIDRs) error {
    err := func(data multiCIDRNodeReservedCIDRs) error {
        cidrsString := ipnetToStringList(data.allocatedCIDRs)
        // 获取节点信息
        node, err := r.nodeLister.Get(data.nodeName)
        if err != nil {
            logger.Error(err, "Failed while getting node for updating Node.Spec.PodCIDRs", "node", klog.KRef("", data.nodeName))
            return err
        }

        // 如果cidr列表与提议的匹配，则可能已经更新了该节点，并且只是没有确认成功。
        if len(node.Spec.PodCIDRs) == len(data.allocatedCIDRs) {
            match := true
            for idx, cidr := range cidrsString {
                if node.Spec.PodCIDRs[idx] != cidr {
                    match = false
                    break
                }
            }
            if match {
                logger.V(4).Info("Node already has allocated CIDR. It matches the proposed one.", "node", klog.KObj(node), "CIDRs", data.allocatedCIDRs)
                return nil
            }
        }

        // 如果节点分配了cidr，则释放保留的cidr
        if len(node.Spec.PodCIDRs) != 0 {
            logger.Error(nil, "Node already has a CIDR allocated. Releasing the new one", "node", klog.KObj(node), "podCIDRs", node.Spec.PodCIDRs)
            for _, cidr := range data.allocatedCIDRs {
                if err := r.Release(logger, data.clusterCIDR, cidr); err != nil {
                    return fmt.Errorf("failed to release cidr %s from clusterCIDR %s for node: %s: %w", cidr, data.clusterCIDR.Name, node.Name, err)
                }
            }
            return nil
        }

        // 如果节点当前没有分配CIDR，则分配
        for i := 0; i < cidrUpdateRetries; i++ {
            if err = nodeutil.PatchNodeCIDRs(r.client, types.NodeName(node.Name), cidrsString); err == nil {
                data.clusterCIDR.AssociatedNodes[node.Name] = true
                logger.Info("Set node PodCIDR", "node", klog.KObj(node), "podCIDR", cidrsString)
                return nil
            }
        }
        // 分配失败，将CIDR释放回池中
        logger.Error(err, "Failed to update node PodCIDR after attempts", "node", klog.KObj(node), "podCIDR", cidrsString, "retries", cidrUpdateRetries)
        controllerutil.RecordNodeStatusChange(r.recorder, node, "CIDRAssignmentFailed")
        // 我们接受这里可能会泄漏CIDR。这比在我们不知道请求是否成功的情况下释放它们更安全。
        // NodeController重启将返回所有错误分配的CIDR到池中。
        if !apierrors.IsServerTimeout(err) {
            logger.Error(err, "CIDR assignment for node failed. Releasing allocated CIDR", "node", klog.KObj(node))
            for _, cidr := range data.allocatedCIDRs {
                if err := r.Release(logger, data.clusterCIDR, cidr);
 err != nil {
					return fmt.Errorf("failed to release cidr %q from clusterCIDR %q for node: %q: %w", cidr, data.clusterCIDR.Name, node.Name, err)
				}
			}
		}
		return err
	}(data)

	return err
}
```

### NewCloudCIDRAllocator

#### new

```GO
func NewCloudCIDRAllocator(logger klog.Logger, client clientset.Interface, cloud cloudprovider.Interface, nodeInformer informers.NodeInformer) (CIDRAllocator, error) {
	if client == nil {
		logger.Error(nil, "kubeClient is nil when starting cloud CIDR allocator")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "cidrAllocator"})

	gceCloud, ok := cloud.(*gce.Cloud)
	if !ok {
		err := fmt.Errorf("cloudCIDRAllocator does not support %v provider", cloud.ProviderName())
		return nil, err
	}

	ca := &cloudCIDRAllocator{
		client:            client,
		cloud:             gceCloud,
		nodeLister:        nodeInformer.Lister(),
		nodesSynced:       nodeInformer.Informer().HasSynced,
		nodeUpdateChannel: make(chan string, cidrUpdateQueueSize),
		broadcaster:       eventBroadcaster,
		recorder:          recorder,
		nodesInProcessing: map[string]*nodeProcessingInfo{},
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controllerutil.CreateAddNodeHandler(
			func(node *v1.Node) error {
				return ca.AllocateOrOccupyCIDR(logger, node)
			}),
		UpdateFunc: controllerutil.CreateUpdateNodeHandler(func(_, newNode *v1.Node) error {
            // 当节点的PodCIDR信息发生变化时，调用AllocateOrOccupyCIDR方法为该节点重新分配CIDR
			if newNode.Spec.PodCIDR == "" {
				return ca.AllocateOrOccupyCIDR(logger, newNode)
			}
			// Even if PodCIDR is assigned, but NetworkUnavailable condition is
			// set to true, we need to process the node to set the condition.
			networkUnavailableTaint := &v1.Taint{Key: v1.TaintNodeNetworkUnavailable, Effect: v1.TaintEffectNoSchedule}
			_, cond := controllerutil.GetNodeCondition(&newNode.Status, v1.NodeNetworkUnavailable)
			if cond == nil || cond.Status != v1.ConditionFalse || utiltaints.TaintExists(newNode.Spec.Taints, networkUnavailableTaint) {
				return ca.AllocateOrOccupyCIDR(logger, newNode)
			}
			return nil
		}),
		DeleteFunc: controllerutil.CreateDeleteNodeHandler(func(node *v1.Node) error {
			return ca.ReleaseCIDR(logger, node)
		}),
	})
	logger.Info("Using cloud CIDR allocator", "provider", cloud.ProviderName())
	return ca, nil
}
```

##### AllocateOrOccupyCIDR

```go
func (ca *cloudCIDRAllocator) AllocateOrOccupyCIDR(logger klog.Logger, node *v1.Node) error {
	if node == nil {
		return nil
	}
	if !ca.insertNodeToProcessing(node.Name) {
		logger.V(2).Info("Node is already in a process of CIDR assignment", "node", klog.KObj(node))
		return nil
	}

	logger.V(4).Info("Putting node into the work queue", "node", klog.KObj(node))
	ca.nodeUpdateChannel <- node.Name
	return nil
}

```

##### ReleaseCIDR

```go
func (ca *cloudCIDRAllocator) ReleaseCIDR(logger klog.Logger, node *v1.Node) error {
	logger.V(2).Info("Node's PodCIDR will be released by external cloud provider (not managed by controller)",
		"node", klog.KObj(node), "podCIDR", node.Spec.PodCIDR)
	return nil
}

```

#### 结构体

```go
type cloudCIDRAllocator struct {
	client clientset.Interface
	cloud  *gce.Cloud

	// nodeLister is able to list/get nodes and is populated by the shared informer passed to
	// NewCloudCIDRAllocator.
	nodeLister corelisters.NodeLister
	// nodesSynced returns true if the node shared informer has been synced at least once.
	nodesSynced cache.InformerSynced

	nodeUpdateChannel chan string
	broadcaster       record.EventBroadcaster
	recorder          record.EventRecorder

	// Keep a set of nodes that are currectly being processed to avoid races in CIDR allocation
	lock              sync.Mutex
	nodesInProcessing map[string]*nodeProcessingInfo
}
```

#### Run

```go
func (ca *cloudCIDRAllocator) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	// Start event processing pipeline.
	ca.broadcaster.StartStructuredLogging(0)
	logger := klog.FromContext(ctx)
	logger.Info("Sending events to api server")
	ca.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: ca.client.CoreV1().Events("")})
	defer ca.broadcaster.Shutdown()

	logger.Info("Starting cloud CIDR allocator")
	defer logger.Info("Shutting down cloud CIDR allocator")

	if !cache.WaitForNamedCacheSync("cidrallocator", ctx.Done(), ca.nodesSynced) {
		return
	}

	for i := 0; i < cidrUpdateWorkers; i++ {
		go ca.worker(ctx)
	}

	<-ctx.Done()
}

```

#### worker

```go
func (ca *cloudCIDRAllocator) worker(ctx context.Context) {
	logger := klog.FromContext(ctx) // 从上下文中获取logger

	for {
		select {
		case workItem, ok := <-ca.nodeUpdateChannel: // 从通道中获取任务
			if !ok { // 如果通道已关闭
				logger.Info("Channel nodeCIDRUpdateChannel was unexpectedly closed")
				return // 结束worker
			}
			if err := ca.updateCIDRAllocation(logger, workItem); err == nil { // 执行任务
				logger.V(3).Info("Updated CIDR", "workItem", workItem)
			} else { // 如果执行失败
				logger.Error(err, "Error updating CIDR", "workItem", workItem)
				if canRetry, timeout := ca.retryParams(logger, workItem); canRetry { // 判断是否可以重试
					logger.V(2).Info("Retrying update on next period", "workItem", workItem, "timeout", timeout)
					time.AfterFunc(timeout, func() {
						// 在超时后重新将任务放入通道
						ca.nodeUpdateChannel <- workItem
					})
					continue // 继续读取通道中的任务
				}
				logger.Error(nil, "Exceeded retry count, dropping from queue", "workItem", workItem)
			}
			ca.removeNodeFromProcessing(workItem) // 从正在处理节点的map中删除该节点

		case <-ctx.Done(): // 接收到上下文取消信号
			return // 结束worker
		}
	}
}

```

##### updateCIDRAllocation

```go
func (ca *cloudCIDRAllocator) updateCIDRAllocation(logger klog.Logger, nodeName string) error {
	node, err := ca.nodeLister.Get(nodeName)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil // node no longer available, skip processing
		}
		logger.Error(err, "Failed while getting the node for updating Node.Spec.PodCIDR", "node", klog.KRef("", nodeName))
		return err
	}
	if node.Spec.ProviderID == "" {
		return fmt.Errorf("node %s doesn't have providerID", nodeName)
	}
	
    // 根据节点的 ProviderID 属性，通过 cloud 接口获取节点的IP地址段，存储为字符串切片 cidrStrings。
	cidrStrings, err := ca.cloud.AliasRangesByProviderID(node.Spec.ProviderID)
	if err != nil {
		controllerutil.RecordNodeStatusChange(ca.recorder, node, "CIDRNotAvailable")
		return fmt.Errorf("failed to get cidr(s) from provider: %v", err)
	}
	if len(cidrStrings) == 0 {
		controllerutil.RecordNodeStatusChange(ca.recorder, node, "CIDRNotAvailable")
		return fmt.Errorf("failed to allocate cidr: Node %v has no CIDRs", node.Name)
	}
	//Can have at most 2 ips (one for v4 and one for v6)
	if len(cidrStrings) > 2 {
		logger.Info("Got more than 2 ips, truncating to 2", "cidrStrings", cidrStrings)
		cidrStrings = cidrStrings[:2]
	}

	cidrs, err := netutils.ParseCIDRs(cidrStrings)
	if err != nil {
		return fmt.Errorf("failed to parse strings %v as CIDRs: %v", cidrStrings, err)
	}

	needUpdate, err := needPodCIDRsUpdate(logger, node, cidrs)
	if err != nil {
		return fmt.Errorf("err: %v, CIDRS: %v", err, cidrStrings)
	}
	if needUpdate {
		if node.Spec.PodCIDR != "" {
			logger.Error(nil, "PodCIDR being reassigned", "node", klog.KObj(node), "podCIDRs", node.Spec.PodCIDRs, "cidrStrings", cidrStrings)
			// We fall through and set the CIDR despite this error. This
			// implements the same logic as implemented in the
			// rangeAllocator.
			//
			// See https://github.com/kubernetes/kubernetes/pull/42147#discussion_r103357248
		}
		for i := 0; i < cidrUpdateRetries; i++ {
			if err = nodeutil.PatchNodeCIDRs(ca.client, types.NodeName(node.Name), cidrStrings); err == nil {
				logger.Info("Set the node PodCIDRs", "node", klog.KObj(node), "cidrStrings", cidrStrings)
				break
			}
		}
	}
	if err != nil {
		controllerutil.RecordNodeStatusChange(ca.recorder, node, "CIDRAssignmentFailed")
		logger.Error(err, "Failed to update the node PodCIDR after multiple attempts", "node", klog.KObj(node), "cidrStrings", cidrStrings)
		return err
	}

	err = nodeutil.SetNodeCondition(ca.client, types.NodeName(node.Name), v1.NodeCondition{
		Type:               v1.NodeNetworkUnavailable,
		Status:             v1.ConditionFalse,
		Reason:             "RouteCreated",
		Message:            "NodeController create implicit route",
		LastTransitionTime: metav1.Now(),
	})
	if err != nil {
		logger.Error(err, "Error setting route status for the node", "node", klog.KObj(node))
	}
	return err
}
```

##### removeNodeFromProcessing

```GO
func (ca *cloudCIDRAllocator) removeNodeFromProcessing(nodeName string) {
	ca.lock.Lock()
	defer ca.lock.Unlock()
	delete(ca.nodesInProcessing, nodeName)
}
```

##### retryParams

```GO
func (ca *cloudCIDRAllocator) retryParams(logger klog.Logger, nodeName string) (bool, time.Duration) {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	entry, ok := ca.nodesInProcessing[nodeName]
	if !ok {
		logger.Error(nil, "Cannot get retryParams for node as entry does not exist", "node", klog.KRef("", nodeName))
		return false, 0
	}

	count := entry.retries + 1
	if count > updateMaxRetries {
		return false, 0
	}
	ca.nodesInProcessing[nodeName].retries = count

	return true, nodeUpdateRetryTimeout(count)
}
```

