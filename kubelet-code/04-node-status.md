## 简介

NodeStatus是Kubelet的一个重要属性，表示节点的当前状态信息。

NodeStatus包含了多个字段，其中一些常见的字段包括：

- Addresses：节点的IP地址列表，包括Hostname、ExternalIP和InternalIP等。
- Capacity：节点资源的总量，如CPU、内存和可用的Pod数量等。
- Allocatable：节点可用资源的数量，即Capacity减去已经使用的资源量。
- Conditions：节点状态的条件列表，如Ready、OutOfDisk、MemoryPressure等。
- DaemonEndpoints：Kubelet的守护进程地址，包括kubeletEndpoint和ReadOnlyPort等。
- NodeInfo：节点的各种信息，如操作系统、Kubernetes版本和内核版本等。

通过查看NodeStatus，可以了解节点的各种状态信息，包括节点的资源使用情况、运行状况和可用性等。这对于诊断和解决节点问题非常有帮助，也可以帮助节点管理者更好地管理和优化集群。

## fastNodeStatusUpdate

```go
】// fastNodeStatusUpdate 是 syncNodeStatus 的“轻量级”版本，除了最后一次运行时不会访问 apiserver 之外，不会访问 apiserver。
// 它与 syncNodeStatus 使用相同的锁，在并发调用 syncNodeStatus 时是线程安全的。
// 它的返回值指示循环是否应该退出（最后一次运行），它还设置 kl.containerRuntimeReadyExpected。
func (kl *Kubelet) fastNodeStatusUpdate(ctx context.Context, timeout bool) (completed bool) {
	kl.syncNodeStatusMux.Lock()
	defer func() {
		kl.syncNodeStatusMux.Unlock()

		if completed {
			// containerRuntimeReadyExpected 是由 updateRuntimeUp() 读取的。
			// 不使用更细粒度的互斥锁，因为该路径只运行一次。
			kl.updateRuntimeMux.Lock()
			defer kl.updateRuntimeMux.Unlock()
			kl.containerRuntimeReadyExpected = true
		}
	}()

	if timeout {
		klog.ErrorS(nil, "节点在启动后没有及时准备好")
		return true
	}

	originalNode, err := kl.GetNode()
	if err != nil {
		klog.ErrorS(err, "从列表中获取当前节点时出错")
		return false
	}

	readyIdx, originalNodeReady := nodeutil.GetNodeCondition(&originalNode.Status, v1.NodeReady)
	if readyIdx == -1 {
		klog.ErrorS(nil, "节点没有 NodeReady 状态", "originalNode", originalNode)
		return false
	}

	if originalNodeReady.Status == v1.ConditionTrue {
		return true
	}

	// 这是为了提前获取容器运行时状态，除了常规的 syncNodeStatus 逻辑之外。
	// 该函数本身有一个互斥锁，并且不会递归调用 fastNodeStatusUpdate 或 syncNodeStatus。
	kl.updateRuntimeUp()

	node, changed := kl.updateNode(ctx, originalNode)

	if !changed {
		// 我们不在这里执行 markVolumesFromNode(node)，而是留给常规的 syncNodeStatus() 执行。
		return false
	}

	readyIdx, nodeReady := nodeutil.GetNodeCondition(&node.Status, v1.NodeReady)
	if readyIdx == -1 {
		klog.ErrorS(nil, "节点没有 NodeReady 状态", "node", node)
		return false
	}

	if nodeReady.Status == v1.ConditionFalse {
		return false
	}

	klog.InfoS("由于节点刚刚准备好，正在快速更新节点状态")
	if _, err := kl.patchNodeStatus(originalNode, node); err != nil {
		// originalNode 可能已过时，但我们知道 kubelet 的当前状态将使节点准备就绪。
		// 使用 fetch from the apiserver 的 syncNodeStatus() 重试。
		klog.ErrorS(err, "更新节点状态时出错，将使用 syncNodeStatus 重试")

		// 下面的 kl.syncNodeStatusMux.Unlock/Lock() 是为了允许 kl.syncNodeStatus() 执行。
		kl.syncNodeStatusMux.Unlock()
		kl.syncNodeStatus()
		// 如果在解锁之前在 defer 中添加一个标志来检查，则不需要执行此锁动作，
		// 但是在此处添加它可以使逻辑更易于阅读。
		kl.syncNodeStatusMux.Lock()
	}

	// 我们不在这里执行 markVolumesFromNode(node)，而是留给常规的 syncNodeStatus() 执行。
	return true
}
```

### updateNode

```GO
// updateNode 在 originalNode 的副本上运行更新逻辑，并返回更新后的节点对象和一个指示是否有任何更改的布尔值。
func (kl *Kubelet) updateNode(ctx context.Context, originalNode *v1.Node) (*v1.Node, bool) {
	node := originalNode.DeepCopy()

	podCIDRChanged := false
	if len(node.Spec.PodCIDRs) != 0 {
		// Pod CIDR 可能在之前已经更新过，所以我们不能依赖于 node.Spec.PodCIDR 不为空。
		// 我们还需要知道 pod CIDR 是否实际发生了更改。
		var err error
		podCIDRs := strings.Join(node.Spec.PodCIDRs, ",")
		if podCIDRChanged, err = kl.updatePodCIDR(ctx, podCIDRs); err != nil {
			klog.ErrorS(err, "更新 pod CIDR 出错")
		}
	}

	areRequiredLabelsNotPresent := false
	osName, osLabelExists := node.Labels[v1.LabelOSStable]
	if !osLabelExists || osName != goruntime.GOOS {
		if len(node.Labels) == 0 {
			node.Labels = make(map[string]string)
		}
		node.Labels[v1.LabelOSStable] = goruntime.GOOS
		areRequiredLabelsNotPresent = true
	}
	// 如果存在架构不匹配，则设置架构
	arch, archLabelExists := node.Labels[v1.LabelArchStable]
	if !archLabelExists || arch != goruntime.GOARCH {
		if len(node.Labels) == 0 {
			node.Labels = make(map[string]string)
		}
		node.Labels[v1.LabelArchStable] = goruntime.GOARCH
		areRequiredLabelsNotPresent = true
	}

	kl.setNodeStatus(ctx, node)

	changed := podCIDRChanged || nodeStatusHasChanged(&originalNode.Status, &node.Status) || areRequiredLabelsNotPresent
	return node, changed
}
```

### patchNodeStatus

```GO
// patchNodeStatus 根据 originalNode 在 API 服务器上打补丁 node。
// 如果成功，返回任何潜在错误、updatedNode 并刷新 kubelet 的状态。
func (kl *Kubelet) patchNodeStatus(originalNode, node *v1.Node) (*v1.Node, error) {
	// 在 API 服务器上打补丁当前状态
	updatedNode, _, err := nodeutil.PatchNodeStatus(kl.heartbeatClient.CoreV1(), types.NodeName(kl.nodeName), originalNode, node)
	if err != nil {
		return nil, err
	}
	kl.lastStatusReportTime = kl.clock.Now()
	kl.setLastObservedNodeAddresses(updatedNode.Status.Addresses)
	return updatedNode, nil
}
```

## syncNodeStatus

```go
// syncNodeStatus 应该定期从一个 goroutine 调用。
// 如果有任何更改或上次同步之后经过足够的时间，它将节点状态同步到主服务器，并在必要时首先注册 kubelet。
func (kl *Kubelet) syncNodeStatus() {
	kl.syncNodeStatusMux.Lock()
	defer kl.syncNodeStatusMux.Unlock()
	ctx := context.Background()

	if kl.kubeClient == nil || kl.heartbeatClient == nil {
		return
	}
	if kl.registerNode {
		// 如果不需要执行任何操作，这将立即退出。
		kl.registerWithAPIServer()
	}
	if err := kl.updateNodeStatus(ctx); err != nil {
		klog.ErrorS(err, "无法更新节点状态")
	}
}
```

### registerWithAPIServer

```GO
// registerWithAPIServer函数用于将节点注册到集群主节点。可以多次调用，但不支持并发调用（kl.registrationCompleted未加锁）。
func (kl *Kubelet) registerWithAPIServer() {
	if kl.registrationCompleted {
		return
	}
	step := 100 * time.Millisecond

	for {
		time.Sleep(step)
		step = step * 2
		if step >= 7*time.Second {
			step = 7 * time.Second
		}

		node, err := kl.initialNode(context.TODO())
		if err != nil {
			klog.ErrorS(err, "Unable to construct v1.Node object for kubelet")
			continue
		}

		klog.InfoS("Attempting to register node", "node", klog.KObj(node))
		registered := kl.tryRegisterWithAPIServer(node)
		if registered {
			klog.InfoS("Successfully registered node", "node", klog.KObj(node))
			kl.registrationCompleted = true
			return
		}
	}
}
```

### initialNode

```GO
// initialNode函数用于构建Kubelet的初始v1.Node对象，其中包括节点标签、来自云提供商的信息和Kubelet配置信息。
func (kl *Kubelet) initialNode(ctx context.Context) (*v1.Node, error) {
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: string(kl.nodeName),
			Labels: map[string]string{
				v1.LabelHostname:      kl.hostname,
				v1.LabelOSStable:      goruntime.GOOS,
				v1.LabelArchStable:    goruntime.GOARCH,
				kubeletapis.LabelOS:   goruntime.GOOS,
				kubeletapis.LabelArch: goruntime.GOARCH,
			},
		},
		Spec: v1.NodeSpec{
			Unschedulable: !kl.registerSchedulable,
		},
	}

	osLabels, err := getOSSpecificLabels()
	if err != nil {
		return nil, err
	}
	for label, value := range osLabels {
		node.Labels[label] = value
	}

	nodeTaints := make([]v1.Taint, len(kl.registerWithTaints))
	copy(nodeTaints, kl.registerWithTaints)
	unschedulableTaint := v1.Taint{
		Key:    v1.TaintNodeUnschedulable,
		Effect: v1.TaintEffectNoSchedule,
	}

	// 在初始化节点时使用TaintNodeUnschedulable来为节点添加污点，以避免竞争条件；更多详细信息请参考＃63897。
	if node.Spec.Unschedulable &&
		!taintutil.TaintExists(nodeTaints, &unschedulableTaint) {
		nodeTaints = append(nodeTaints, unschedulableTaint)
	}

	if kl.externalCloudProvider {
		taint := v1.Taint{
			Key:    cloudproviderapi.TaintExternalCloudProvider,
			Value:  "true",
			Effect: v1.TaintEffectNoSchedule,
		}

		nodeTaints = append(nodeTaints, taint)
	}
	if len(nodeTaints) > 0 {
		node.Spec.Taints = nodeTaints
	}

	// 最初将NodeNetworkUnavailable设置为true。
	if kl.providerRequiresNetworkingConfiguration() {
		node.Status.Conditions = append(node.Status.Conditions, v1.NodeCondition{
			Type:               v1.NodeNetworkUnavailable,
			Status:             v1.ConditionTrue,
			Reason:             "NoRouteCreated",
			Message:            "Node created without a route",
			LastTransitionTime: metav1.NewTime(kl.clock.Now()),
		})
	}

	if kl.enableControllerAttachDetach {
		if node.Annotations == nil {
			node.Annotations = make(map[string]string)
		}

		klog.V(2).InfoS("Setting node annotation to enable volume controller attach/detach")
		node.Annotations[volutil.ControllerManagedAttachAnnotation] = "true"
	} else {
		klog.V(2).InfoS("Controller attach/detach is disabled for this node; Kubelet will attach and detach volumes")
	}

	if kl.keepTerminatedPodVolumes {
		if node.Annotations == nil {
			node.Annotations = make(map[string]string)
		}
		klog.V(2).InfoS("Setting node annotation to keep pod volumes of terminated pods attached to the node")
		node.Annotations[volutil.KeepTerminatedPodVolumesAnnotation] = "true"
	}

	// @question: 是否应该在调用云提供程序之后放置此代码块？云提供程序也应用了标签。
	for k, v := range kl.nodeLabels {
		if cv, found := node.ObjectMeta.Labels[k]; found {
			klog.InfoS("the node label will overwrite default setting", "labelKey", k, "labelValue", v, "default", cv)
		}
		node.ObjectMeta.Labels[k] = v
	}

	if kl.providerID != "" {
		node.Spec.ProviderID = kl.providerID
	}

	if kl.cloud != nil {
		instances, ok := kl.cloud.Instances()
		if !ok {
			return nil, fmt.Errorf("failed to get instances from cloud provider")
		}

		// TODO: 我们不能假设节点具有与云提供程序进行通信的凭据。最多，我们应该在此处与本地元数据服务器进行通信。
		var err error
		if node.Spec.ProviderID == "" {
			node.Spec.ProviderID, err = cloudprovider.GetInstanceProviderID(ctx, kl.cloud, kl.nodeName)
			if err != nil {
				return nil, err
			}
		}

		instanceType, err := instances.InstanceType(ctx, kl.nodeName)
		if err != nil {
			return nil, err
		}
		if instanceType != "" {
			klog.InfoS("Adding label from cloud provider", "labelKey", v1.LabelInstanceType, "labelValue", instanceType)
			node.ObjectMeta.Labels[v1.LabelInstanceType] = instanceType
			klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelInstanceTypeStable, "labelValue", instanceType)
			node.ObjectMeta.Labels[v1.LabelInstanceTypeStable] = instanceType
		}

		// 如果云提供商具有区域信息，请使用区域信息为节点添加标签。
		zones, ok := kl.cloud.Zones()
		if ok {
			zone, err := zones.GetZone(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get zone from cloud provider: %v", err)
			}
			if zone.FailureDomain != "" {
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelFailureDomainBetaZone, "labelValue", zone.FailureDomain)
				node.ObjectMeta.Labels[v1.LabelFailureDomainBetaZone] = zone.FailureDomain
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelTopologyZone, "labelValue", zone.FailureDomain)
				node.ObjectMeta.Labels[v1.LabelTopologyZone] = zone.FailureDomain
			}
			if zone.Region != "" {
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelFailureDomainBetaRegion, "labelValue", zone.Region)
				node.ObjectMeta.Labels[v1.LabelFailureDomainBetaRegion] = zone.Region
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelTopologyRegion, "labelValue", zone.Region)
				node.ObjectMeta.Labels[v1.LabelTopologyRegion] = zone.Region
			}
		}
	}

	kl.setNodeStatus(ctx, node)

	return node, nil
}
```

### tryRegisterWithAPIServer

```GO
// tryRegisterWithAPIServer尝试注册给定的节点到API服务器，返回一个布尔值，指示尝试是否成功。
// 如果具有相同名称的节点已存在，它会对节点的控制器管理的附加和分离可附加持久卷的注释的值进行协调。
func (kl *Kubelet) tryRegisterWithAPIServer(node *v1.Node) bool {
	_, err := kl.kubeClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	if err == nil {
		return true
	}

	if !apierrors.IsAlreadyExists(err) {
		klog.ErrorS(err, "Unable to register node with API server", "node", klog.KObj(node))
		return false
	}

	existingNode, err := kl.kubeClient.CoreV1().Nodes().Get(context.TODO(), string(kl.nodeName), metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "Unable to register node with API server, error getting existing node", "node", klog.KObj(node))
		return false
	}
	if existingNode == nil {
		klog.InfoS("Unable to register node with API server, no node instance returned", "node", klog.KObj(node))
		return false
	}

	originalNode := existingNode.DeepCopy()

	klog.InfoS("Node was previously registered", "node", klog.KObj(node))

	// 边缘情况：节点先前已注册；协调控制器管理的附加和分离的注释的值。
	requiresUpdate := kl.reconcileCMADAnnotationWithExistingNode(node, existingNode)
	requiresUpdate = kl.updateDefaultLabels(node, existingNode) || requiresUpdate
	requiresUpdate = kl.reconcileExtendedResource(node, existingNode) || requiresUpdate
	requiresUpdate = kl.reconcileHugePageResource(node, existingNode) || requiresUpdate
	if requiresUpdate {
		if _, _, err := nodeutil.PatchNodeStatus(kl.kubeClient.CoreV1(), types.NodeName(kl.nodeName), originalNode, existingNode); err != nil {
			klog.ErrorS(err, "Unable to reconcile node with API server,error updating node", "node", klog.KObj(node))
			return false
		}
	}

	return true
}
```

#### reconcileCMADAnnotationWithExistingNode

```GO
// reconcileCMADAnnotationWithExistingNode 函数用于协调新节点和现有节点上的控制器管理的附加和分离注释，返回现有节点是否需要更新。
func (kl *Kubelet) reconcileCMADAnnotationWithExistingNode(node, existingNode *v1.Node) bool {
	var (
		existingCMAAnnotation    = existingNode.Annotations[volutil.ControllerManagedAttachAnnotation] // 获取现有节点上的控制器管理的附加和分离注释
		newCMAAnnotation, newSet = node.Annotations[volutil.ControllerManagedAttachAnnotation]         // 获取新节点上的控制器管理的附加和分离注释以及是否存在
	)

	if newCMAAnnotation == existingCMAAnnotation { // 如果新节点和现有节点的注释相同，则无需更新现有节点
		return false
	}

	// 如果新构建的节点和现有节点的值不相同，则使用正确的注释值更新现有节点。
	if !newSet { // 如果新节点的注释不存在
		klog.InfoS("Controller attach-detach setting changed to false; updating existing Node") // 输出日志，表示控制器的附加和分离设置被更改为false，并更新现有节点
		delete(existingNode.Annotations, volutil.ControllerManagedAttachAnnotation)             // 从现有节点的注释中删除控制器管理的附加和分离注释
	} else {
		klog.InfoS("Controller attach-detach setting changed to true; updating existing Node") // 输出日志，表示控制器的附加和分离设置被更改为true，并更新现有节点
		if existingNode.Annotations == nil {                                                   // 如果现有节点的注释为空，则创建一个注释的映射
			existingNode.Annotations = make(map[string]string)
		}
		existingNode.Annotations[volutil.ControllerManagedAttachAnnotation] = newCMAAnnotation // 更新现有节点的控制器管理的附加和分离注释
	}

	return true // 返回现有节点需要更新
}
```

#### updateDefaultLabels

```GO
// updateDefaultLabels 函数将在节点上设置默认标签。
func (kl *Kubelet) updateDefaultLabels(initialNode, existingNode *v1.Node) bool {
	defaultLabels := []string{ // 定义默认标签列表
		v1.LabelHostname,
		v1.LabelTopologyZone,
		v1.LabelTopologyRegion,
		v1.LabelFailureDomainBetaZone,
		v1.LabelFailureDomainBetaRegion,
		v1.LabelInstanceTypeStable,
		v1.LabelInstanceType,
		v1.LabelOSStable,
		v1.LabelArchStable,
		v1.LabelWindowsBuild,
		kubeletapis.LabelOS,
		kubeletapis.LabelArch,
	}

	needsUpdate := false            // 标记是否需要更新节点标签
	if existingNode.Labels == nil { // 如果现有节点的标签为空，则创建一个标签的映射
		existingNode.Labels = make(map[string]string)
	}
	// 设置默认标签，但确保不设置空值的标签
	for _, label := range defaultLabels { // 遍历默认标签列表
		if _, hasInitialValue := initialNode.Labels[label]; !hasInitialValue { // 如果初始节点的标签列表中不存在该标签，则继续下一次循环
			continue
		}

		if existingNode.Labels[label] != initialNode.Labels[label] { // 如果现有节点的标签值与初始节点的标签值不同
			existingNode.Labels[label] = initialNode.Labels[label] // 更新现有节点的标签值为初始节点的标签值
			needsUpdate = true                                     // 标记需要更新
		}

		if existingNode.Labels[label] == "" { // 如果现有节点的标签值为空，则删除该标签
			delete(existingNode.Labels, label)
		}
	}

	return needsUpdate // 返回是否需要更新节点
}
```

#### reconcileExtendedResource

```GO
// reconcileExtendedResource 函数在协调过程中将扩展资源容量清零。
func (kl *Kubelet) reconcileExtendedResource(initialNode, node *v1.Node) bool {
	requiresUpdate := updateDefaultResources(initialNode, node) // 先调用updateDefaultResources函数，更新资源容量
	// 通过设备管理器检查节点是否已重新创建，如果是，则应将扩展资源容量清零，直到可用为止
	if kl.containerManager.ShouldResetExtendedResourceCapacity() { // 如果容器管理器标记需要重置扩展资源容量
		for k := range node.Status.Capacity { // 遍历节点的资源容量
			if v1helper.IsExtendedResourceName(k) { // 如果资源名称是扩展资源名称
				klog.InfoS("Zero out resource capacity in existing node", "resourceName", k, "node", klog.KObj(node)) // 输出日志，表示将现有节点的资源容量清零
				node.Status.Capacity[k] = *resource.NewQuantity(int64(0), resource.DecimalSI)                         // 将现有节点的资源容量设置为零
				node.Status.Allocatable[k] = *resource.NewQuantity(int64(0), resource.DecimalSI)                      // 将现有节点的可分配资源容量设置为零
				requiresUpdate = true                                                                                 // 标记需要更新
			}
		}
	}
	return requiresUpdate // 返回是否需要更新节点
}
```

#### reconcileHugePageResource

```GO
// reconcileHugePageResource 函数将更新每个页面大小的大页面容量，并删除不再支持的大页面大小。
func (kl *Kubelet) reconcileHugePageResource(initialNode, existingNode *v1.Node) bool {
	requiresUpdate := updateDefaultResources(initialNode, existingNode) // 先调用updateDefaultResources函数，更新资源容量
	supportedHugePageResources := sets.String{}                         // 创建一个字符串集合，用于存储支持的大页面资源名称

	for resourceName := range initialNode.Status.Capacity { // 遍历初始节点的资源容量
		if !v1helper.IsHugePageResourceName(resourceName) { // 如果资源名称不是大页面资源名称，则继续下一次循环
			continue
		}
		supportedHugePageResources.Insert(string(resourceName)) // 将支持的大页面资源名称添加到集合中

		initialCapacity := initialNode.Status.Capacity[resourceName]       // 获取初始节点的资源容量
		initialAllocatable := initialNode.Status.Allocatable[resourceName] // 获取初始节点的可分配资源容量

		capacity, resourceIsSupported := existingNode.Status.Capacity[resourceName] // 获取现有节点的资源容量以及是否支持该资源
		allocatable := existingNode.Status.Allocatable[resourceName]                // 获取现有节点的可分配资源容量

		// 如果大小以前不受支持或已更改，则添加或更新容量
		if !resourceIsSupported || capacity.Cmp(initialCapacity) != 0 { // 如果资源以前不受支持或容量发生变化
			existingNode.Status.Capacity[resourceName] = initialCapacity.DeepCopy() // 更新现有节点的资源容量为初始节点的资源容量
			requiresUpdate = true                                                   // 标记需要更新
		}

		// 如果大小以前不受支持或已更改，则添加或更新可分配容量
		if !resourceIsSupported || allocatable.Cmp(initialAllocatable) != 0 { // 如果资源以前不受支持或可分配容量发生变化
			existingNode.Status.Allocatable[resourceName] = initialAllocatable.DeepCopy() // 更新现有节点的可分配资源容量为初始节点的可分配资源容量
			requiresUpdate = true                                                         // 标记需要更新
		}

	}

	for resourceName := range existingNode.Status.Capacity { // 遍历现有节点的资源容量
		if !v1helper.IsHugePageResourceName(resourceName) { // 如果资源名称不是大页面资源名称，则继续下一次循环
			continue
		}

		// 如果不再支持大页面大小，则从节点中删除它
		if !supportedHugePageResources.Has(string(resourceName)) { // 如果不再支持该大页面资源
			delete(existingNode.Status.Capacity, resourceName)                                                   // 从现有节点的资源容量中删除该资源
			delete(existingNode.Status.Allocatable, resourceName)                                                // 从现有节点的可分配资源容量中删除该资源
			klog.InfoS("Removing huge page resource which is no longer supported", "resourceName", resourceName) // 输出日志，表示删除不再支持的大页面资源
			requiresUpdate = true                                                                                // 标记需要更新
		}
	}
	return requiresUpdate // 返回是否需要更新节点
}
```

