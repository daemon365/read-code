
## 简介

提供节点和容器的统计信息，有 `cAdvisor` 和 `CRI` 两种实现

## containerStatsProvider

```GO
// containerStatsProvider是一个接口，定义了获取由Pod管理的容器统计信息的方法。
type containerStatsProvider interface {
	// ListPodStats检索Pod的统计信息。
	ListPodStats(ctx context.Context) ([]statsapi.PodStats, error)
	// ListPodStatsAndUpdateCPUNanoCoreUsage检索Pod的统计信息，并更新CPU核心的使用情况。
	ListPodStatsAndUpdateCPUNanoCoreUsage(ctx context.Context) ([]statsapi.PodStats, error)
	// ListPodCPUAndMemoryStats检索Pod的CPU和内存统计信息。
	ListPodCPUAndMemoryStats(ctx context.Context) ([]statsapi.PodStats, error)
	// ImageFsStats检索镜像文件系统的统计信息。
	ImageFsStats(ctx context.Context) (*statsapi.FsStats, error)
	// ImageFsDevice检索镜像文件系统的设备信息。
	ImageFsDevice(ctx context.Context) (string, error)
}
```

### criStatsProvider

```GO
// criStatsProvider实现了containerStatsProvider接口，通过从CRI获取容器统计信息。
type criStatsProvider struct {
	// cadvisor用于获取节点根文件系统的统计信息（如容量/可用字节/索引节点），这些信息将填充每个容器的文件系统统计信息。
	cadvisor cadvisor.Interface
	// resourceAnalyzer用于获取Pod的卷统计信息。
	resourceAnalyzer stats.ResourceAnalyzer
	// runtimeService用于获取Pod及其管理的容器的状态和统计信息。
	runtimeService internalapi.RuntimeService
	// imageService用于获取镜像文件系统的统计信息。
	imageService internalapi.ImageManagerService
	// hostStatsProvider用于获取由Pod消耗的主机文件系统的状态。
	hostStatsProvider HostStatsProvider
	// windowsNetworkStatsProvider用于在Windows上收集网络统计信息的kubelet。
	windowsNetworkStatsProvider interface{} //nolint:unused // U1000 由于hcsshim中的构建约束，我们无法导入hcsshim
	// clock用于报告当前时间
	clock clock.Clock
	// cpuUsageCache缓存容器的CPU使用情况。
	cpuUsageCache               map[string]*cpuUsageRecord
	mutex                       sync.RWMutex
	podAndContainerStatsFromCRI bool
}
```

### cpuUsageRecord

```GO
// cpuUsageRecord保存CPU使用情况统计信息和计算得出的usageNanoCores。
type cpuUsageRecord struct {
	stats          *runtimeapi.CpuUsage
	usageNanoCores *uint64
}
```

### HostStatsProvider

```GO
// HostStatsProvider定义了与Pod关联的主机统计信息的接口。
type HostStatsProvider interface {
	// getPodLogStats获取与Pod日志使用情况相关的统计信息。
	getPodLogStats(podNamespace, podName string, podUID types.UID, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error)
	// getPodContainerLogStats获取与容器日志使用情况相关的统计信息。
	getPodContainerLogStats(podNamespace, podName string, podUID types.UID, containerName string, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error)
	// getPodEtcHostsStats获取与Pod etc-hosts使用情况相关的统计信息。
	getPodEtcHostsStats(podUID types.UID, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error)
}
```

#### hostStatsProvider

```GO
type hostStatsProvider struct {
	// osInterface是系统调用的接口。
	osInterface kubecontainer.OSInterface
	// podEtcHostsPathFunc通过UID获取Pod的etc-hosts路径。
	podEtcHostsPathFunc PodEtcHostsPathFunc
}

// NewHostStatsProvider返回一个新的HostStatsProvider类型结构。
func NewHostStatsProvider(osInterface kubecontainer.OSInterface, podEtcHostsPathFunc PodEtcHostsPathFunc) HostStatsProvider {
	return hostStatsProvider{
		osInterface:         osInterface,
		podEtcHostsPathFunc: podEtcHostsPathFunc,
	}
}
```

##### getPodLogStats

```GO
// getPodLogStats函数用于获取Pod日志的统计信息
func (h hostStatsProvider) getPodLogStats(podNamespace, podName string, podUID types.UID, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error) {
	// 调用podLogMetrics函数获取Pod日志的指标信息
	metricsByPath, err := h.podLogMetrics(podNamespace, podName, podUID)
	if err != nil {
		return nil, err
	}
	// 调用metricsByPathToFsStats函数将指标信息转换为文件系统统计信息
	return metricsByPathToFsStats(metricsByPath, rootFsInfo)
}
```

###### podLogMetrics

```GO
// podLogMetrics函数用于获取Pod日志的指标信息
func (h hostStatsProvider) podLogMetrics(podNamespace, podName string, podUID types.UID) (metricsProviderByPath, error) {
	// 构建Pod日志目录路径
	podLogsDirectoryPath := kuberuntime.BuildPodLogsDirectory(podNamespace, podName, podUID)
	// 调用fileMetricsByDir函数获取指定目录下的文件指标信息
	return h.fileMetricsByDir(podLogsDirectoryPath)
}
```

###### fileMetricsByDir

```GO
// fileMetricsByDir函数用于获取指定目录下的文件指标信息
// 返回值metricsProviderByPath是一个按路径存储的指标提供者
func (h hostStatsProvider) fileMetricsByDir(dirname string) (metricsProviderByPath, error) {
	// 读取指定目录下的文件列表
	files, err := h.osInterface.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	// 存储结果的map
	results := metricsProviderByPath{}
	// 遍历文件列表
	for _, f := range files {
		// 如果是目录，则跳过
		if f.IsDir() {
			continue
		}
		// 获取文件的完整路径
		fpath := filepath.Join(dirname, f.Name())
		// 使用文件路径创建一个指标提供者
		results[fpath] = volume.NewMetricsDu(fpath)
	}
	return results, nil
}
```

###### metricsByPathToFsStats

```GO
// metricsByPathToFsStats函数用于将按路径存储的指标提供者转换为文件系统统计信息
func metricsByPathToFsStats(metricsByPath metricsProviderByPath, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error) {
	// 将根文件系统信息转换为文件系统统计信息对象
	result := rootFsInfoToFsStats(rootFsInfo)
	// 遍历按路径存储的指标提供者
	for fpath, metrics := range metricsByPath {
		// 获取主机指标信息
		hostMetrics, err := metrics.GetMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to get fsstats for %q: %v", fpath, err)
		}
		// 获取使用的字节数和节点数，并更新文件系统统计信息对象
		usedBytes := uint64(hostMetrics.Used.Value())
		inodesUsed := uint64(hostMetrics.InodesUsed.Value())
		result.UsedBytes = addUsage(result.UsedBytes, &usedBytes)
		result.InodesUsed = addUsage(result.InodesUsed, &inodesUsed)
		result.Time = maxUpdateTime(&result.Time, &hostMetrics.Time)
	}
	return result, nil
}

```

###### rootFsInfoToFsStats

```GO
// rootFsInfoToFsStats函数用于将根文件系统信息转换为文件系统统计信息对象
func rootFsInfoToFsStats(rootFsInfo *cadvisorapiv2.FsInfo) *statsapi.FsStats {
	return &statsapi.FsStats{
		Time:           metav1.NewTime(rootFsInfo.Timestamp),
		AvailableBytes: &rootFsInfo.Available,
		CapacityBytes:  &rootFsInfo.Capacity,
		InodesFree:     rootFsInfo.InodesFree,
		Inodes:         rootFsInfo.Inodes,
	}
}
```

##### getPodContainerLogStats

```GO
// getPodContainerLogStats函数用于获取容器的日志统计信息
func (h hostStatsProvider) getPodContainerLogStats(podNamespace, podName string, podUID types.UID, containerName string, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error) {
	// 调用podContainerLogMetrics函数获取容器的日志指标信息
	metricsByPath, err := h.podContainerLogMetrics(podNamespace, podName, podUID, containerName)
	if err != nil {
		return nil, err
	}
	// 调用metricsByPathToFsStats函数将指标信息转换为文件系统统计信息
	return metricsByPathToFsStats(metricsByPath, rootFsInfo)
}
```

##### getPodEtcHostsStats

```GO
// getPodEtcHostsStats函数用于获取Pod etc hosts使用情况的统计信息
func (h hostStatsProvider) getPodEtcHostsStats(podUID types.UID, rootFsInfo *cadvisorapiv2.FsInfo) (*statsapi.FsStats, error) {
	// Runtimes may not support etc hosts file (Windows with docker)
	// 获取Pod的etc hosts文件路径
	podEtcHostsPath := h.podEtcHostsPathFunc(podUID)
	// 某些Pod具有显式的/etc/hosts挂载点，Kubelet不会为它们创建etc-hosts文件
	// 检查etc hosts文件是否存在
	if _, err := os.Stat(podEtcHostsPath); os.IsNotExist(err) {
		return nil, nil
	}

	// 创建一个指标提供者来获取etc hosts文件的指标信息
	metrics := volume.NewMetricsDu(podEtcHostsPath)
	hostMetrics, err := metrics.GetMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to get stats %v", err)
	}
	// 将根文件系统信息转换为文件系统统计信息对象
	result := rootFsInfoToFsStats(rootFsInfo)
	// 获取使用的字节数和节点数，并更新文件系统统计信息对象
	usedBytes := uint64(hostMetrics.Used.Value())
	inodesUsed := uint64(hostMetrics.InodesUsed.Value())
	result.UsedBytes = addUsage(result.UsedBytes, &usedBytes)
	result.InodesUsed = addUsage(result.InodesUsed, &inodesUsed)
	result.Time = maxUpdateTime(&result.Time, &hostMetrics.Time)
	return result, nil
}
```

### newCRIStatsProvider

```GO
// newCRIStatsProvider返回一个使用CRI提供容器统计信息的containerStatsProvider实现。
func newCRIStatsProvider(
	cadvisor cadvisor.Interface,
	resourceAnalyzer stats.ResourceAnalyzer,
	runtimeService internalapi.RuntimeService,
	imageService internalapi.ImageManagerService,
	hostStatsProvider HostStatsProvider,
	podAndContainerStatsFromCRI bool,
) containerStatsProvider {
	return &criStatsProvider{
		cadvisor:                    cadvisor,
		resourceAnalyzer:            resourceAnalyzer,
		runtimeService:              runtimeService,
		imageService:                imageService,
		hostStatsProvider:           hostStatsProvider,
		cpuUsageCache:               make(map[string]*cpuUsageRecord),
		podAndContainerStatsFromCRI: podAndContainerStatsFromCRI,
		clock:                       clock.RealClock{},
	}
}
```

### ListPodStats

```GO
// ListPodStats 返回所有由 pod 管理的容器的统计信息。
func (p *criStatsProvider) ListPodStats(ctx context.Context) ([]statsapi.PodStats, error) {
	// 不更新 CPU 纳米核心使用情况。
	return p.listPodStats(ctx, false)
}
```

#### listPodStats

```GO
func (p *criStatsProvider) listPodStats(ctx context.Context, updateCPUNanoCoreUsage bool) ([]statsapi.PodStats, error) {
	// 获取节点根文件系统的信息，将用于填充容器统计信息中的可用字节/节点数。
	rootFsInfo, err := p.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("获取 rootFs 信息失败：%v", err)
	}

	containerMap, podSandboxMap, err := p.getPodAndContainerMaps(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取 Pod 或容器映射失败：%v", err)
	}

	if p.podAndContainerStatsFromCRI {
		result, err := p.listPodStatsStrictlyFromCRI(ctx, updateCPUNanoCoreUsage, containerMap, podSandboxMap, &rootFsInfo)
		if err == nil {
			// 调用成功
			return result, nil
		}
		s, ok := status.FromError(err)
		// 正常的失败，而不是 CRI 实现不支持 ListPodSandboxStats。
		if !ok || s.Code() != codes.Unimplemented {
			return nil, err
		}
		// CRI 实现不支持 ListPodSandboxStats，发出警告并回退。
		klog.V(5).ErrorS(err,
			"如果启用了 PodAndContainerStatsFromCRI 功能门控，CRI 实现必须更新以支持 ListPodSandboxStats。正在回退到使用 cAdvisor 进行填充；这个调用在将来会失败。",
		)
	}
	return p.listPodStatsPartiallyFromCRI(ctx, updateCPUNanoCoreUsage, containerMap, podSandboxMap, &rootFsInfo)
}
```

##### getPodAndContainerMaps

```GO
func (p *criStatsProvider) getPodAndContainerMaps(ctx context.Context) (map[string]*runtimeapi.Container, map[string]*runtimeapi.PodSandbox, error) {
	containers, err := p.runtimeService.ListContainers(ctx, &runtimeapi.ContainerFilter{})
	if err != nil {
		return nil, nil, fmt.Errorf("列出所有容器失败：%v", err)
	}

	// 创建 Pod 沙箱映射，以 pod 沙箱 ID 为键，PodSandbox 对象为值。
	podSandboxMap := make(map[string]*runtimeapi.PodSandbox)
	podSandboxes, err := p.runtimeService.ListPodSandbox(ctx, &runtimeapi.PodSandboxFilter{})
	if err != nil {
		return nil, nil, fmt.Errorf("列出所有 pod 沙箱失败：%v", err)
	}
	podSandboxes = removeTerminatedPods(podSandboxes)
	for _, s := range podSandboxes {
		podSandboxMap[s.Id] = s
	}

	containers = removeTerminatedContainers(containers)
	// 创建容器映射，以容器 ID 为键，Container 对象为值。
	containerMap := make(map[string]*runtimeapi.Container)
	for _, c := range containers {
		containerMap[c.Id] = c
	}
	return containerMap, podSandboxMap, nil
}
```

###### removeTerminatedPods

```GO
// removeTerminatedPods 函数移除已终止的 PodSandbox，只保留正在运行的实例，
// 前提是存在具有相同名称和命名空间的运行中的 Pod。
// 这是因为：
// 1）PodSandbox 可能会被重新创建；
// 2）Pod 可能会使用相同的名称和命名空间重新创建。
func removeTerminatedPods(pods []*runtimeapi.PodSandbox) []*runtimeapi.PodSandbox {
	podMap := make(map[statsapi.PodReference][]*runtimeapi.PodSandbox)
	// 按创建时间排序
	sort.Slice(pods, func(i, j int) bool {
		return pods[i].CreatedAt < pods[j].CreatedAt
	})
	for _, pod := range pods {
		refID := statsapi.PodReference{
			Name:      pod.GetMetadata().GetName(),
			Namespace: pod.GetMetadata().GetNamespace(),
			// UID 故意留空。
		}
		podMap[refID] = append(podMap[refID], pod)
	}

	result := make([]*runtimeapi.PodSandbox, 0)
	for _, refs := range podMap {
		if len(refs) == 1 {
			result = append(result, refs[0])
			continue
		}
		found := false
		for i := 0; i < len(refs); i++ {
			if refs[i].State == runtimeapi.PodSandboxState_SANDBOX_READY {
				found = true
				result = append(result, refs[i])
			}
		}
		if !found {
			result = append(result, refs[len(refs)-1])
		}
	}
	return result
}
```

###### removeTerminatedContainers

```GO
// removeTerminatedContainers 函数移除所有已终止的容器，因为它们不应该用于计算资源使用情况。
func removeTerminatedContainers(containers []*runtimeapi.Container) []*runtimeapi.Container {
	containerMap := make(map[containerID][]*runtimeapi.Container)
	// 按创建时间排序
	sort.Slice(containers, func(i, j int) bool {
		return containers[i].CreatedAt < containers[j].CreatedAt
	})
	for _, container := range containers {
		refID := containerID{
			podRef:        buildPodRef(container.Labels),
			containerName: kubetypes.GetContainerName(container.Labels),
		}
		containerMap[refID] = append(containerMap[refID], container)
	}

	result := make([]*runtimeapi.Container, 0)
	for _, refs := range containerMap {
		for i := 0; i < len(refs); i++ {
			if refs[i].State == runtimeapi.ContainerState_CONTAINER_RUNNING {
				result = append(result, refs[i])
			}
		}
	}
	return result
}
```

##### listPodStatsStrictlyFromCRI

```GO
func (p *criStatsProvider) listPodStatsStrictlyFromCRI(ctx context.Context, updateCPUNanoCoreUsage bool, containerMap map[string]*runtimeapi.Container, podSandboxMap map[string]*runtimeapi.PodSandbox, rootFsInfo *cadvisorapiv2.FsInfo) ([]statsapi.PodStats, error) {
	criSandboxStats, err := p.runtimeService.ListPodSandboxStats(ctx, &runtimeapi.PodSandboxStatsFilter{})
	if err != nil {
		return nil, err
	}

	fsIDtoInfo := make(map[runtimeapi.FilesystemIdentifier]*cadvisorapiv2.FsInfo)
	summarySandboxStats := make([]statsapi.PodStats, 0, len(podSandboxMap))
	for _, criSandboxStat := range criSandboxStats {
		if criSandboxStat == nil || criSandboxStat.Attributes == nil {
			klog.V(5).InfoS("Unable to find CRI stats for sandbox")
			continue
		}
		podSandbox, found := podSandboxMap[criSandboxStat.Attributes.Id]
		if !found {
			continue
		}
		ps := buildPodStats(podSandbox)
		for _, criContainerStat := range criSandboxStat.Linux.Containers {
			container, found := containerMap[criContainerStat.Attributes.Id]
			if !found {
				continue
			}
			// 填充完整的所需 Pod 统计信息的可用统计数据
			cs := p.makeContainerStats(criContainerStat, container, rootFsInfo, fsIDtoInfo, podSandbox.GetMetadata(), updateCPUNanoCoreUsage)
			ps.Containers = append(ps.Containers, *cs)
		}
		addCRIPodNetworkStats(ps, criSandboxStat)
		addCRIPodCPUStats(ps, criSandboxStat)
		addCRIPodMemoryStats(ps, criSandboxStat)
		addCRIPodProcessStats(ps, criSandboxStat)
		makePodStorageStats(ps, rootFsInfo, p.resourceAnalyzer, p.hostStatsProvider, true)
		summarySandboxStats = append(summarySandboxStats, *ps)
	}
	return summarySandboxStats, nil
}
```

##### listPodStatsPartiallyFromCRI

```GO
func (p *criStatsProvider) listPodStatsPartiallyFromCRI(ctx context.Context, updateCPUNanoCoreUsage bool, containerMap map[string]*runtimeapi.Container, podSandboxMap map[string]*runtimeapi.PodSandbox, rootFsInfo *cadvisorapiv2.FsInfo) ([]statsapi.PodStats, error) {
	// fsIDtoInfo 是一个从文件系统 ID 到其统计信息的映射。它将用作缓存，避免多次查询具有相同文件系统 ID 的文件系统统计信息。
	fsIDtoInfo := make(map[runtimeapi.FilesystemIdentifier]*cadvisorapiv2.FsInfo)

	// sandboxIDToPodStats 是一个临时映射，从沙箱 ID 到其 pod 统计信息。
	sandboxIDToPodStats := make(map[string]*statsapi.PodStats)

	resp, err := p.runtimeService.ListContainerStats(ctx, &runtimeapi.ContainerStatsFilter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list all container stats: %v", err)
	}
	allInfos, err := getCadvisorContainerInfo(p.cadvisor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cadvisor stats: %v", err)
	}
	caInfos, allInfos := getCRICadvisorStats(allInfos)

	// 获取容器的网络统计信息。
	// 这仅在 Windows 上使用。对于其他平台，应返回 (nil, nil)。
	containerNetworkStats, err := p.listContainerNetworkStats()
	if err != nil {
		return nil, fmt.Errorf("failed to list container network stats: %v", err)
	}

	for _, stats := range resp {
		containerID := stats.Attributes.Id
		container, found := containerMap[containerID]
		if !found {
			continue
		}

		podSandboxID := container.PodSandboxId
		podSandbox, found := podSandboxMap[podSandboxID]
		if !found {
			continue
		}

		// 创建所属容器的 Pod 统计信息（如果尚未创建）。
		ps, found := sandboxIDToPodStats[podSandboxID]
		if !found {
			ps = buildPodStats(podSandbox)
			sandboxIDToPodStats[podSandboxID] = ps
		}

		// 填充完整的所需 Pod 统计信息的可用统计数据
		cs := p.makeContainerStats(stats, container, rootFsInfo, fsIDtoInfo, podSandbox.GetMetadata(), updateCPUNanoCoreUsage)
		p.addPodNetworkStats(ps, podSandboxID, caInfos, cs, containerNetworkStats[podSandboxID])
		p.addPodCPUMemoryStats(ps, types.UID(podSandbox.Metadata.Uid), allInfos, cs)
		p.addProcessStats(ps, types.UID(podSandbox.Metadata.Uid), allInfos, cs)

		// 如果容器的 cadvisor 统计信息可用，则使用它填充容器统计信息
		caStats, caFound := caInfos[containerID]
		if !caFound {
			klog.V(5).InfoS("Unable to find cadvisor stats for container", "containerID", containerID)
		} else {
			p.addCadvisorContainerStats(cs, &caStats)
		}
		ps.Containers = append(ps.Containers, *cs)
	}
}
```

### ListPodStatsAndUpdateCPUNanoCoreUsage

```GO
// ListPodStatsAndUpdateCPUNanoCoreUsage更新容器的CPU纳米核使用情况，并返回所有由Pod管理的容器的统计信息。
// 这是一个解决方案，因为CRI运行时不提供纳米核使用情况，
// 所以该函数计算当前和上次（缓存的）CPU统计信息之间的差异以计算这个指标。
// 该实现假定单个调用者会定期调用此函数来更新指标。
// 如果存在多个调用者，则用于计算CPU使用情况的周期可能会有所不同，使用情况可能不一致（例如，出现波动）。
// 如果没有调用者调用此函数，则CPU使用情况将保持为nil。
// 目前，唯一的调用者是驱逐管理器，它每10秒调用一次此函数。
func (p *criStatsProvider) ListPodStatsAndUpdateCPUNanoCoreUsage(ctx context.Context) ([]statsapi.PodStats, error) {
	// 更新CPU纳米核使用情况。
	return p.listPodStats(ctx, true)
}
```

### ListPodCPUAndMemoryStats

```GO
// ListPodCPUAndMemoryStats返回所有由Pod管理的容器的CPU和内存统计信息。
func (p *cadvisorStatsProvider) ListPodCPUAndMemoryStats(_ context.Context) ([]statsapi.PodStats, error) {
	infos, err := getCadvisorContainerInfo(p.cadvisor)
	if err != nil {
		return nil, fmt.Errorf("failed to get container info from cadvisor: %v", err)
	}
	filteredInfos, allInfos := filterTerminatedContainerInfoAndAssembleByPodCgroupKey(infos)
	// 将每个容器映射到一个Pod，并使用容器数据更新PodStats。
	podToStats := map[statsapi.PodReference]*statsapi.PodStats{}
	for key, cinfo := range filteredInfos {
		// 在使用devicemapper的systemd上，每个挂载到容器中的挂载点都有一个相关的cgroup。
		// 我们忽略它们，以确保在摘要中不会出现重复的条目。
		// 有关.mount单元的详细信息，请参见：http://man7.org/linux/man-pages/man5/systemd.mount.5.html
		if strings.HasSuffix(key, ".mount") {
			continue
		}
		// 如果此容器由Pod管理，则构建Pod键。
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		ref := buildPodRef(cinfo.Spec.Labels)

		// 使用PodRef查找PodStats。如果不存在，则初始化一个新条目。
		podStats, found := podToStats[ref]
		if !found {
			podStats = &statsapi.PodStats{PodRef: ref}
			podToStats[ref] = podStats
		}

		// 使用容器的统计信息更新PodStats条目，通过将其添加到podStats.Containers中。
		containerName := kubetypes.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// 特殊情况下的基础设施容器，对用户隐藏并具有网络统计信息。
			podStats.StartTime = metav1.NewTime(cinfo.Spec.CreationTime)
		} else {
			podStats.Containers = append(podStats.Containers, *cadvisorInfoToContainerCPUAndMemoryStats(containerName, &cinfo))
		}
	}

	// 将每个PodStats添加到结果中。
	result := make([]statsapi.PodStats, 0, len(podToStats))
	for _, podStats := range podToStats {
		podUID := types.UID(podStats.PodRef.UID)
		// 查找与Pod UID对应的Pod级cgroup的CPU和内存统计信息
		podInfo := getCadvisorPodInfoFromPodUID(podUID, allInfos)
		if podInfo != nil {
			cpu, memory := cadvisorInfoToCPUandMemoryStats(podInfo)
			podStats.CPU = cpu
			podStats.Memory = memory
		}
		result = append(result, *podStats)
	}

	return result, nil
}
```

#### filterTerminatedContainerInfoAndAssembleByPodCgroupKey

```GO
// filterTerminatedContainerInfoAndAssembleByPodCgroupKey返回指定的containerInfo，
// 但移除已终止容器的统计信息，并按Pod cgroup键将所有containerInfos组合在一起。
// 第一个返回的map是容器cgroup名称<->ContainerInfo，
// 第二个返回的map是Pod cgroup键<->ContainerInfo。
// 如果ContainerInfo的CreationTime较旧且CPU瞬时使用率和内存RSS使用量为零，则将其视为已终止容器的ContainerInfo。
func filterTerminatedContainerInfoAndAssembleByPodCgroupKey(containerInfo map[string]cadvisorapiv2.ContainerInfo) (map[string]cadvisorapiv2.ContainerInfo, map[string]cadvisorapiv2.ContainerInfo) {
	cinfoMap := make(map[containerID][]containerInfoWithCgroup)
	cinfosByPodCgroupKey := make(map[string]cadvisorapiv2.ContainerInfo)
	for key, cinfo := range containerInfo {
		var podCgroupKey string
		if cm.IsSystemdStyleName(key) {
			// 转换为内部cgroup名称，并仅取最后一个组件。
			internalCgroupName := cm.ParseSystemdToCgroupName(key)
			podCgroupKey = internalCgroupName[len(internalCgroupName)-1]
		} else {
			// 仅取最后一个组件。
			podCgroupKey = filepath.Base(key)
		}
		cinfosByPodCgroupKey[podCgroupKey] = cinfo
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		cinfoID := containerID{
			podRef:        buildPodRef(cinfo.Spec.Labels),
			containerName: kubetypes.GetContainerName(cinfo.Spec.Labels),
		}
		cinfoMap[cinfoID] = append(cinfoMap[cinfoID], containerInfoWithCgroup{
			cinfo:  cinfo,
			cgroup: key,
		})
	}
	result := make(map[string]cadvisorapiv2.ContainerInfo)
	for _, refs := range cinfoMap {
		if len(refs) == 1 {
			// 对于已终止容器的未清理的cgroups而言，它们是没有CPU/内存/网络使用情况的ContainerInfo，不应在结果中显示。
			if !isContainerTerminated(&refs[0].cinfo) {
				result[refs[0].cgroup] = refs[0].cinfo
			}
			continue
		}
		sort.Sort(ByCreationTime(refs))
		for i := len(refs) - 1; i >= 0; i-- {
			if hasMemoryAndCPUInstUsage(&refs[i].cinfo) {
				result[refs[i].cgroup] = refs[i].cinfo
				break
			}
		}
	}
	return result, cinfosByPodCgroupKey
}
```

### ImageFsStats

```GO
// ImageFsStats返回镜像文件系统的统计信息。
func (p *criStatsProvider) ImageFsStats(ctx context.Context) (*statsapi.FsStats, error) {
	resp, err := p.imageService.ImageFsInfo(ctx)
	if err != nil {
		return nil, err
	}

	// CRI可能返回多个镜像文件系统的统计信息，但我们只返回第一个。
	//
	// TODO（yguo0905）：支持返回多个镜像文件系统的统计信息。
	if len(resp) == 0 {
		return nil, fmt.Errorf("无法获取imageFs信息")
	}
	fs := resp[0]
	s := &statsapi.FsStats{
		Time:      metav1.NewTime(time.Unix(0, fs.Timestamp)),
		UsedBytes: &fs.UsedBytes.Value,
	}
	if fs.InodesUsed != nil {
		s.InodesUsed = &fs.InodesUsed.Value
	}
	imageFsInfo := p.getFsInfo(fs.GetFsId())
	if imageFsInfo != nil {
		// 本地节点未知镜像文件系统的ID或检索统计信息时出错。
		// 在这些情况下，我们省略这些统计信息，并返回尽力的部分结果。参见https://github.com/kubernetes/heapster/issues/1793。
		s.AvailableBytes = &imageFsInfo.Available
		s.CapacityBytes = &imageFsInfo.Capacity
		s.InodesFree = imageFsInfo.InodesFree
		s.Inodes = imageFsInfo.Inodes
	}
	return s, nil
}
```

### ImageFsDevice

```GO
// ImageFsDevice函数返回镜像文件系统所在设备的名称，
// 例如/dev/sda1。
func (p *criStatsProvider) ImageFsDevice(ctx context.Context) (string, error) {
	resp, err := p.imageService.ImageFsInfo(ctx) // 调用imageService的ImageFsInfo方法获取镜像文件系统的信息
	if err != nil {
		return "", err // 如果发生错误，返回空字符串和错误信息
	}
	for _, fs := range resp { // 遍历镜像文件系统信息列表
		fsInfo := p.getFsInfo(fs.GetFsId()) // 根据镜像文件系统的ID获取文件系统信息
		if fsInfo != nil {                  // 如果文件系统信息不为空
			return fsInfo.Device, nil // 返回文件系统所在设备的名称
		}
	}
	return "", errors.New("imagefs device is not found") // 如果没有找到镜像文件系统所在设备的名称，则返回错误信息
}
```

## cadvisorStatsProvider

```GO
// cadvisorStatsProvider实现了containerStatsProvider接口，通过从cAdvisor获取容器统计信息。
// 这对于不提供来自CRI的统计信息的集成是必需的。有关确定哪些集成不提供来自CRI的统计信息的逻辑，
// 请参阅pkg/kubelet/cadvisor/util.go#UsingLegacyCadvisorStats。
type cadvisorStatsProvider struct {
	// cadvisor用于获取由pod管理的容器的cgroup的统计信息。
	cadvisor cadvisor.Interface
	// resourceAnalyzer用于获取pod的卷统计信息。
	resourceAnalyzer stats.ResourceAnalyzer
	// imageService用于获取镜像文件系统的统计信息。
	imageService kubecontainer.ImageService
	// statusProvider用于获取pod元数据。
	statusProvider status.PodStatusProvider
	// hostStatsProvider用于获取pod主机统计使用情况。
	hostStatsProvider HostStatsProvider
}
```

### newCadvisorStatsProvider

```GO
// newCadvisorStatsProvider返回一个containerStatsProvider，该提供程序从cAdvisor提供容器统计信息。
func newCadvisorStatsProvider(
	cadvisor cadvisor.Interface,
	resourceAnalyzer stats.ResourceAnalyzer,
	imageService kubecontainer.ImageService,
	statusProvider status.PodStatusProvider,
	hostStatsProvider HostStatsProvider,
) containerStatsProvider {
	return &cadvisorStatsProvider{
		cadvisor:          cadvisor,
		resourceAnalyzer:  resourceAnalyzer,
		imageService:      imageService,
		statusProvider:    statusProvider,
		hostStatsProvider: hostStatsProvider,
	}
}
```

### ListPodStats

```GO
// ListPodStats返回所有由Pod管理的容器的统计信息。
func (p *cadvisorStatsProvider) ListPodStats(_ context.Context) ([]statsapi.PodStats, error) {
	// 获取节点根文件系统信息和镜像文件系统统计信息，这些信息将用于填充容器统计中的可用和容量字节/索引节点。
	rootFsInfo, err := p.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("获取rootFs信息失败：%v", err)
	}
	imageFsInfo, err := p.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("获取imageFs信息失败：%v", err)
	}
	infos, err := getCadvisorContainerInfo(p.cadvisor)
	if err != nil {
		return nil, fmt.Errorf("从cadvisor获取容器信息失败：%v", err)
	}

	filteredInfos, allInfos := filterTerminatedContainerInfoAndAssembleByPodCgroupKey(infos)
	// 将每个容器映射到一个Pod，并使用容器数据更新PodStats。
	podToStats := map[statsapi.PodReference]*statsapi.PodStats{}
	for key, cinfo := range filteredInfos {
		// 在使用devicemapper的systemd上，每个挂载到容器中的挂载点都有一个关联的cgroup。我们忽略它们以确保在摘要中没有重复的条目。有关.mount单元的详细信息：http://man7.org/linux/man-pages/man5/systemd.mount.5.html
		if strings.HasSuffix(key, ".mount") {
			continue
		}
		// 如果此容器由Pod管理，则构建Pod key
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		ref := buildPodRef(cinfo.Spec.Labels)

		// 使用PodRef查找PodStats。如果不存在，则初始化一个新条目。
		podStats, found := podToStats[ref]
		if !found {
			podStats = &statsapi.PodStats{PodRef: ref}
			podToStats[ref] = podStats
		}

		// 使用容器的统计信息更新PodStats条目，将其添加到podStats.Containers中。
		containerName := kubetypes.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// 用于基础设施容器的特殊情况，该容器对用户隐藏且具有网络统计信息。
			podStats.Network = cadvisorInfoToNetworkStats(&cinfo)
		} else {
			containerStat := cadvisorInfoToContainerStats(containerName, &cinfo, &rootFsInfo, &imageFsInfo)
			// 注意：这不支持旧的Pod日志路径“/var/log/pods/UID”。对于使用旧日志路径的容器，它们将由cadvisorInfoToContainerStats填充。
			podUID := types.UID(podStats.PodRef.UID)
			logs, err := p.hostStatsProvider.getPodContainerLogStats(podStats.PodRef.Namespace, podStats.PodRef.Name, podUID, containerName, &rootFsInfo)
			if err != nil {
				klog.ErrorS(err, "无法获取容器日志统计信息", "containerName", containerName)
			} else {
				containerStat.Logs = logs
			}
			podStats.Containers = append(podStats.Containers, *containerStat)
		}
	}

	// 将每个PodStats添加到结果中。
	result := make([]statsapi.PodStats, 0, len(podToStats))
	for _, podStats := range podToStats {
		makePodStorageStats(podStats, &rootFsInfo, p.resourceAnalyzer, p.hostStatsProvider, false)

		podUID := types.UID(podStats.PodRef.UID)
		// 查找pod级别的cgroup的CPU和内存统计信息
		podInfo := getCadvisorPodInfoFromPodUID(podUID, allInfos)
		if podInfo != nil {
			cpu, memory := cadvisorInfoToCPUandMemoryStats(podInfo)
			podStats.CPU = cpu
			podStats.Memory = memory
			podStats.ProcessStats = cadvisorInfoToProcessStats(podInfo)
		}

		status, found := p.statusProvider.GetPodStatus(podUID)
		if found && status.StartTime != nil && !status.StartTime.IsZero() {
			podStats.StartTime = *status.StartTime
			// 只有在能够获取到Pod的启动时间时才添加统计信息
			result = append(result, *podStats)
		}
	}

	return result, nil
}
```

##### getCadvisorContainerInfo

```GO
// getCadvisorContainerInfo函数从cadvisor获取容器信息。
func getCadvisorContainerInfo(ca cadvisor.Interface) (map[string]cadvisorapiv2.ContainerInfo, error) {
	// 使用cadvisor的ContainerInfoV2函数获取容器信息。
	infos, err := ca.ContainerInfoV2("/", cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2, // 需要2个样本来计算“瞬时”CPU使用率
		Recursive: true,
	})
	if err != nil {
		// 如果发生错误，并且仍然可以获取到根cgroup的部分信息，则记录错误并返回尽力的响应。
		if _, ok := infos["/"]; ok {
			klog.ErrorS(err, "部分错误：发出cadvisor.ContainerInfoV2请求")
		} else {
			return nil, fmt.Errorf("获取根cgroup统计信息失败：%v", err)
		}
	}
	return infos, nil
}
```

##### filterTerminatedContainerInfoAndAssembleByPodCgroupKey

```go
// filterTerminatedContainerInfoAndAssembleByPodCgroupKey函数过滤已终止容器的统计信息，并按照Pod的cgroup键将所有容器信息组合起来。
// 第一个返回的map是容器cgroup名称 <-> ContainerInfo的映射，
// 第二个返回的map是Pod的cgroup键 <-> ContainerInfo的映射。
// 如果ContainerInfo的CreationTime较早且CPU使用率和内存使用率均为零，则将其视为已终止的容器。
func filterTerminatedContainerInfoAndAssembleByPodCgroupKey(containerInfo map[string]cadvisorapiv2.ContainerInfo) (map[string]cadvisorapiv2.ContainerInfo, map[string]cadvisorapiv2.ContainerInfo) {
	cinfoMap := make(map[containerID][]containerInfoWithCgroup)
	cinfosByPodCgroupKey := make(map[string]cadvisorapiv2.ContainerInfo)

	// 遍历所有容器信息
	for key, cinfo := range containerInfo {
		var podCgroupKey string
		if cm.IsSystemdStyleName(key) {
			// 将容器名称转换为内部cgroup名称，并仅获取最后一个组件。
			internalCgroupName := cm.ParseSystemdToCgroupName(key)
			podCgroupKey = internalCgroupName[len(internalCgroupName)-1]
		} else {
			// 仅获取最后一个组件。
			podCgroupKey = filepath.Base(key)
		}
		// 将容器信息按照Pod的cgroup键进行组合
		cinfosByPodCgroupKey[podCgroupKey] = cinfo

		// 如果容器不是由Pod管理，则跳过
		if !isPodManagedContainer(&cinfo) {
			continue
		}

		// 构建容器的唯一标识符
		cinfoID := containerID{
			podRef:        buildPodRef(cinfo.Spec.Labels),
			containerName: kubetypes.GetContainerName(cinfo.Spec.Labels),
		}
		// 将容器信息添加到对应的cinfoMap中
		cinfoMap[cinfoID] = append(cinfoMap[cinfoID], containerInfoWithCgroup{
			cinfo:  cinfo,
			cgroup: key,
		})
	}

	result := make(map[string]cadvisorapiv2.ContainerInfo)

	// 遍历cinfoMap，处理每个容器的统计信息
	for _, refs := range cinfoMap {
		if len(refs) == 1 {
			// 对于已终止容器的未清理的cgroups，它们没有CPU/memory/network使用情况的ContainerInfo，
			// 不应在结果中显示。
			if !isContainerTerminated(&refs[0].cinfo) {
				result[refs[0].cgroup] = refs[0].cinfo
			}
			continue
		}

		// 对于多个ContainerInfo，根据CreationTime排序，选择具有CPU和内存使用率的最新的ContainerInfo。
		sort.Sort(ByCreationTime(refs))
		for i := len(refs) - 1; i >= 0; i-- {
			if hasMemoryAndCPUInstUsage(&refs[i].cinfo) {
				result[refs[i].cgroup] = refs[i].cinfo
				break
			}
		}
	}

	return result, cinfosByPodCgroupKey
}
```

##### cadvisorInfoToNetworkStats

```go
// cadvisorInfoToNetworkStats函数将cadvisor的容器信息转换为statsapi.NetworkStats。
func cadvisorInfoToNetworkStats(info *cadvisorapiv2.ContainerInfo) *statsapi.NetworkStats {
	// 如果容器没有网络信息，则返回nil。
	if !info.Spec.HasNetwork {
		return nil
	}

	// 获取最新的容器统计信息
	cstat, found := latestContainerStats(info)
	if !found {
		return nil
	}

	// 如果容器没有网络接口信息，则返回nil。
	if cstat.Network == nil {
		return nil
	}

	iStats := statsapi.NetworkStats{
		Time: metav1.NewTime(cstat.Timestamp),
	}

	// 遍历容器的网络接口信息，并转换为statsapi.InterfaceStats
	for i := range cstat.Network.Interfaces {
		inter := cstat.Network.Interfaces[i]
		iStat := statsapi.InterfaceStats{
			Name:     inter.Name,
			RxBytes:  &inter.RxBytes,
			RxErrors: &inter.RxErrors,
			TxBytes:  &inter.TxBytes,
			TxErrors: &inter.TxErrors,
		}

		// 将默认网络接口的信息保存到iStats.InterfaceStats字段中
		if inter.Name == defaultNetworkInterfaceName {
			iStats.InterfaceStats = iStat
		}

		// 将所有网络接口的信息保存到iStats.Interfaces中
		iStats.Interfaces = append(iStats.Interfaces, iStat)
	}

	return &iStats
}

// defaultNetworkInterfaceName用于收集网络统计信息。
// 此逻辑依赖于对容器运行时实现的了解，因此不可靠。
const defaultNetworkInterfaceName = "eth0"
```

##### cadvisorInfoToContainerStats

```go
// cadvisorInfoToContainerStats函数将cadvisor的容器信息转换为statsapi.ContainerStats。
func cadvisorInfoToContainerStats(name string, info *cadvisorapiv2.ContainerInfo, rootFs, imageFs *cadvisorapiv2.FsInfo) *statsapi.ContainerStats {
	result := &statsapi.ContainerStats{
		StartTime: metav1.NewTime(info.Spec.CreationTime),
		Name:      name,
	}
	cstat, found := latestContainerStats(info)
	if !found {
		return result
	}

	cpu, memory := cadvisorInfoToCPUandMemoryStats(info)
	result.CPU = cpu
	result.Memory = memory

	// 注意：如果找到日志统计信息，将由调用方覆盖，
	// 因为调用方对Pod的更多信息有所了解，需要确定日志的大小。
	if rootFs != nil {
		// 容器日志位于节点的根文件系统设备上
		result.Logs = buildLogsStats(cstat, rootFs)
	}

	if imageFs != nil {
		// 容器的根文件系统位于imageFs设备上（可能不是节点的根文件系统）
		result.Rootfs = buildRootfsStats(cstat, imageFs)
	}

	cfs := cstat.Filesystem
	if cfs != nil {
		if cfs.BaseUsageBytes != nil {
			if result.Rootfs != nil {
				rootfsUsage := *cfs.BaseUsageBytes
				result.Rootfs.UsedBytes = &rootfsUsage
			}
			if cfs.TotalUsageBytes != nil && result.Logs != nil {
				logsUsage := *cfs.TotalUsageBytes - *cfs.BaseUsageBytes
				result.Logs.UsedBytes = &logsUsage
			}
		}
		if cfs.InodeUsage != nil && result.Rootfs != nil {
			rootInodes := *cfs.InodeUsage
			result.Rootfs.InodesUsed = &rootInodes
		}
	}

	for _, acc := range cstat.Accelerators {
		result.Accelerators = append(result.Accelerators, statsapi.AcceleratorStats{
			Make:        acc.Make,
			Model:       acc.Model,
			ID:          acc.ID,
			MemoryTotal: acc.MemoryTotal,
			MemoryUsed:  acc.MemoryUsed,
			DutyCycle:   acc.DutyCycle,
		})
	}

	result.UserDefinedMetrics = cadvisorInfoToUserDefinedMetrics(info)

	return result
}
```

##### cadvisorInfoToCPUandMemoryStats

```go
// 将cadvisor的容器信息转换为CPU和内存统计信息。
func cadvisorInfoToCPUandMemoryStats(info *cadvisorapiv2.ContainerInfo) (*statsapi.CPUStats, *statsapi.MemoryStats) {
	cstat, found := latestContainerStats(info)
	if !found {
		return nil, nil
	}
	var cpuStats *statsapi.CPUStats
	var memoryStats *statsapi.MemoryStats
	cpuStats = &statsapi.CPUStats{
		Time:                 metav1.NewTime(cstat.Timestamp), // CPU统计信息的时间戳
		UsageNanoCores:       uint64Ptr(0),                    // 使用的CPU核心数（以纳秒为单位）
		UsageCoreNanoSeconds: uint64Ptr(0),                    // 使用的CPU核心纳秒数
	}
	if info.Spec.HasCpu { // 如果容器定义了CPU资源限制
		if cstat.CpuInst != nil {
			cpuStats.UsageNanoCores = &cstat.CpuInst.Usage.Total // 更新CPU使用情况（以纳秒为单位）
		}
		if cstat.Cpu != nil {
			cpuStats.UsageCoreNanoSeconds = &cstat.Cpu.Usage.Total // 更新CPU使用情况（以纳秒为单位）
		}
	}
	if info.Spec.HasMemory && cstat.Memory != nil { // 如果容器定义了内存资源限制
		pageFaults := cstat.Memory.ContainerData.Pgfault         // 容器发生的页面错误数
		majorPageFaults := cstat.Memory.ContainerData.Pgmajfault // 容器发生的重要页面错误数
		memoryStats = &statsapi.MemoryStats{
			Time:            metav1.NewTime(cstat.Timestamp), // 内存统计信息的时间戳
			UsageBytes:      &cstat.Memory.Usage,             // 内存使用量（以字节为单位）
			WorkingSetBytes: &cstat.Memory.WorkingSet,        // 工作集大小（以字节为单位）
			RSSBytes:        &cstat.Memory.RSS,               // 驻留集大小（以字节为单位）
			PageFaults:      &pageFaults,                     // 页面错误数
			MajorPageFaults: &majorPageFaults,                // 重要页面错误数
		}
		// 可用字节 = 内存限制（如果已知）- 工作集大小
		if !isMemoryUnlimited(info.Spec.Memory.Limit) {
			availableBytes := info.Spec.Memory.Limit - cstat.Memory.WorkingSet
			memoryStats.AvailableBytes = &availableBytes // 可用内存大小（以字节为单位）
		}
	} else {
		memoryStats = &statsapi.MemoryStats{
			Time:            metav1.NewTime(cstat.Timestamp), // 内存统计信息的时间戳
			WorkingSetBytes: uint64Ptr(0),                    // 工作集大小（以字节为单位）
		}
	}
	return cpuStats, memoryStats
}
```

##### cadvisorInfoToProcessStats

```go
// 将cadvisor的容器信息转换为进程统计信息。
func cadvisorInfoToProcessStats(info *cadvisorapiv2.ContainerInfo) *statsapi.ProcessStats {
	cstat, found := latestContainerStats(info)
	if !found || cstat.Processes == nil {
		return nil
	}
	num := cstat.Processes.ProcessCount
	return &statsapi.ProcessStats{ProcessCount: uint64Ptr(num)} // 进程统计信息
}
```

##### latestContainerStats

```go
// latestContainerStats从cadvisor中获取最新的容器统计信息，如果不存在则返回nil。
func latestContainerStats(info *cadvisorapiv2.ContainerInfo) (*cadvisorapiv2.ContainerStats, bool) {
	stats := info.Stats
	if len(stats) < 1 {
		return nil, false
	}
	latest := stats[len(stats)-1]
	if latest == nil {
		return nil, false
	}
	return latest, true
}s
```

### ListPodStatsAndUpdateCPUNanoCoreUsage

```go
// ListPodStatsAndUpdateCPUNanoCoreUsage更新容器的CPU纳核使用情况，并返回所有由Pod管理的容器的统计信息。
// 对于cadvisor，CPU纳核使用情况是预先计算并缓存的，因此此函数只需调用ListPodStats。
func (p *cadvisorStatsProvider) ListPodStatsAndUpdateCPUNanoCoreUsage(ctx context.Context) ([]statsapi.PodStats, error) {
	return p.ListPodStats(ctx)
}
```

#### ListPodStats

```go
// ListPodStats返回所有由Pod管理的容器的统计信息。
func (p *cadvisorStatsProvider) ListPodStats(_ context.Context) ([]statsapi.PodStats, error) {
	// 获取节点根文件系统信息和镜像文件系统统计信息，这将用于填充容器统计信息中的可用和容量字节/索引节点。
	rootFsInfo, err := p.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get rootFs info: %v", err)
	}
	imageFsInfo, err := p.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get imageFs info: %v", err)
	}
	infos, err := getCadvisorContainerInfo(p.cadvisor)
	if err != nil {
		return nil, fmt.Errorf("failed to get container info from cadvisor: %v", err)
	}

	filteredInfos, allInfos := filterTerminatedContainerInfoAndAssembleByPodCgroupKey(infos)
	// 将每个容器映射到一个Pod，并使用容器数据更新PodStats。
	podToStats := map[statsapi.PodReference]*statsapi.PodStats{}
	for key, cinfo := range filteredInfos {
		// 在使用devicemapper的systemd中，容器中的每个挂载都有一个相关联的cgroup。我们忽略它们，以确保我们的摘要中不会出现重复条目。
		// 有关.mount单位的详细信息：
		// http://man7.org/linux/man-pages/man5/systemd.mount.5.html
		if strings.HasSuffix(key, ".mount") {
			continue
		}
		// 如果此容器由Pod管理，则构建Pod键。
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		ref := buildPodRef(cinfo.Spec.Labels)

		// 使用PodRef查找PodStats。如果不存在，则初始化一个新条目。
		podStats, found := podToStats[ref]
		if !found {
			podStats = &statsapi.PodStats{PodRef: ref}
			podToStats[ref] = podStats
		}

		// 使用容器的统计信息更新PodStats条目，将其添加到podStats.Containers中。
		containerName := kubetypes.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// 基础设施容器的特殊情况，该容器对用户隐藏，并具有网络统计信息。
			podStats.Network = cadvisorInfoToNetworkStats(&cinfo)
		} else {
			containerStat := cadvisorInfoToContainerStats(containerName, &cinfo, &rootFsInfo, &imageFsInfo)
			// 注意：这不支持旧的Pod日志路径“/var/log/pods/UID”。使用旧日志路径的容器将由cadvisorInfoToContainerStats填充。
			podUID := types.UID(podStats.PodRef.UID)
			logs, err := p.hostStatsProvider.getPodContainerLogStats(podStats.PodRef.Namespace, podStats.PodRef.Name, podUID, containerName, &rootFsInfo)
			if err != nil {
				klog.ErrorS(err, "Unable to fetch container log stats", "containerName", containerName)
			} else {
				containerStat.Logs = logs
			}
			podStats.Containers = append(podStats.Containers, *containerStat)
		}
	}

	// 将每个PodStats添加到结果中。
	result := make([]statsapi.PodStats, 0, len(podToStats))
	for _, podStats := range podToStats {
		makePodStorageStats(podStats, &rootFsInfo, p.resourceAnalyzer, p.hostStatsProvider, false)

		podUID := types.UID(podStats.PodRef.UID)
		// 查找pod级别的cgroup的CPU和内存统计信息
		podInfo := getCadvisorPodInfoFromPodUID(podUID, allInfos)
		if podInfo != nil {
			cpu, memory := cadvisorInfoToCPUandMemoryStats(podInfo)
			podStats.CPU = cpu
			podStats.Memory = memory
			podStats.ProcessStats = cadvisorInfoToProcessStats(podInfo)
		}

		status, found := p.statusProvider.GetPodStatus(podUID)
		if found && status.StartTime != nil && !status.StartTime.IsZero() {
			podStats.StartTime = *status.StartTime
			// 仅在能够获取到Pod的启动时间时追加统计信息
			result = append(result, *podStats)
		}
	}

	return result, nil
}
```

### ListPodCPUAndMemoryStats

```go
// ListPodCPUAndMemoryStats返回所有由Pod管理的容器的CPU和内存统计信息。
func (p *cadvisorStatsProvider) ListPodCPUAndMemoryStats(_ context.Context) ([]statsapi.PodStats, error) {
	infos, err := getCadvisorContainerInfo(p.cadvisor)
	if err != nil {
		return nil, fmt.Errorf("failed to get container info from cadvisor: %v", err)
	}
	filteredInfos, allInfos := filterTerminatedContainerInfoAndAssembleByPodCgroupKey(infos)
	// 将每个容器映射到一个Pod，并使用容器数据更新PodStats。
	podToStats := map[statsapi.PodReference]*statsapi.PodStats{}
	for key, cinfo := range filteredInfos {
		// 在使用devicemapper的systemd中，容器中的每个挂载都有一个相关联的cgroup。我们忽略它们，以确保我们的摘要中不会出现重复条目。
		// 有关.mount单位的详细信息：
		// http://man7.org/linux/man-pages/man5/systemd.mount.5.html
		if strings.HasSuffix(key, ".mount") {
			continue
		}
		// 如果此容器由Pod管理，则构建Pod键。
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		ref := buildPodRef(cinfo.Spec.Labels)

		// 使用PodRef查找PodStats。如果不存在，则初始化一个新条目。
		podStats, found := podToStats[ref]
		if !found {
			podStats = &statsapi.PodStats{PodRef: ref}
			podToStats[ref] = podStats
		}

		// 使用容器的统计信息更新PodStats条目，将其添加到podStats.Containers中。
		containerName := kubetypes.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// 针对基础设施容器的特殊情况，该容器对用户隐藏且具有网络统计信息。
			podStats.StartTime = metav1.NewTime(cinfo.Spec.CreationTime)
		} else {
			podStats.Containers = append(podStats.Containers, *cadvisorInfoToContainerCPUAndMemoryStats(containerName, &cinfo))
		}
	}

	// 将每个PodStats添加到结果中。
	result := make([]statsapi.PodStats, 0, len(podToStats))
	for _, podStats := range podToStats {
		podUID := types.UID(podStats.PodRef.UID)
		// 查找pod级别的cgroup的CPU和内存统计信息
		podInfo := getCadvisorPodInfoFromPodUID(podUID, allInfos)
		if podInfo != nil {
			cpu, memory := cadvisorInfoToCPUandMemoryStats(podInfo)
			podStats.CPU = cpu
			podStats.Memory = memory
		}
		result = append(result, *podStats)
	}

	return result, nil
}
```

### ImageFsStats

```go
// ImageFsStats返回用于存储镜像的文件系统的统计信息。
func (p *cadvisorStatsProvider) ImageFsStats(ctx context.Context) (*statsapi.FsStats, error) {
	imageFsInfo, err := p.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get imageFs info: %v", err)
	}
	imageStats, err := p.imageService.ImageStats(ctx)
	if err != nil || imageStats == nil {
		return nil, fmt.Errorf("failed to get image stats: %v", err)
	}

	var imageFsInodesUsed *uint64
	if imageFsInfo.Inodes != nil && imageFsInfo.InodesFree != nil {
		imageFsIU := *imageFsInfo.Inodes - *imageFsInfo.InodesFree
		imageFsInodesUsed = &imageFsIU
	}

	return &statsapi.FsStats{
		Time:           metav1.NewTime(imageFsInfo.Timestamp),
		AvailableBytes: &imageFsInfo.Available,
		CapacityBytes:  &imageFsInfo.Capacity,
		UsedBytes:      &imageStats.TotalStorageBytes,
		InodesFree:     imageFsInfo.InodesFree,
		Inodes:         imageFsInfo.Inodes,
		InodesUsed:     imageFsInodesUsed,
	}, nil
}
```

### ImageFsDevice

```go
// ImageFsDevice返回镜像文件系统所在设备的名称，例如/dev/sda1。
func (p *cadvisorStatsProvider) ImageFsDevice(_ context.Context) (string, error) {
	imageFsInfo, err := p.cadvisor.ImagesFsInfo()
	if err != nil {
		return "", err
	}
	return imageFsInfo.Device, nil
}
```

## Provider

```GO
// Provider提供节点和由Pod管理的容器的统计信息。
type Provider struct {
	cadvisor               cadvisor.Interface
	podManager             PodManager
	runtimeCache           kubecontainer.RuntimeCache
	containerStatsProvider containerStatsProvider
}
```

### NewCRIStatsProvider

```GO
// NewCRIStatsProvider返回一个提供来自cAdvisor的节点统计信息和来自CRI的容器统计信息的Provider。
func NewCRIStatsProvider(
	cadvisor cadvisor.Interface,
	resourceAnalyzer stats.ResourceAnalyzer,
	podManager PodManager,
	runtimeCache kubecontainer.RuntimeCache,
	runtimeService internalapi.RuntimeService,
	imageService internalapi.ImageManagerService,
	hostStatsProvider HostStatsProvider,
	podAndContainerStatsFromCRI bool,
) *Provider {
	return newStatsProvider(cadvisor, podManager, runtimeCache, newCRIStatsProvider(cadvisor, resourceAnalyzer,
		runtimeService, imageService, hostStatsProvider, podAndContainerStatsFromCRI))
}
```

#### newStatsProvider

```GO
// newStatsProvider返回一个新的Provider，它使用containerStatsProvider提供节点统计信息和容器统计信息。
func newStatsProvider(
	cadvisor cadvisor.Interface,
	podManager PodManager,
	runtimeCache kubecontainer.RuntimeCache,
	containerStatsProvider containerStatsProvider,
) *Provider {
	return &Provider{
		cadvisor:               cadvisor,
		podManager:             podManager,
		runtimeCache:           runtimeCache,
		containerStatsProvider: containerStatsProvider,
	}
}
```

### NewCadvisorStatsProvider

```GO
// NewCadvisorStatsProvider返回一个containerStatsProvider，该提供程序提供来自cAdvisor的节点和容器统计信息。
func NewCadvisorStatsProvider(
	cadvisor cadvisor.Interface,
	resourceAnalyzer stats.ResourceAnalyzer,
	podManager PodManager,
	runtimeCache kubecontainer.RuntimeCache,
	imageService kubecontainer.ImageService,
	statusProvider status.PodStatusProvider,
	hostStatsProvider HostStatsProvider,
) *Provider {
	return newStatsProvider(cadvisor, podManager, runtimeCache, newCadvisorStatsProvider(cadvisor, resourceAnalyzer, imageService, statusProvider, hostStatsProvider))
}
```

### PodManager

```GO
// PodManager是管理器需要观察kubelet的实际状态所需的方法子集。
// 有关方法文档，请参见pkg/k8s.io/kubernetes/pkg/kubelet/pod.Manager。
type PodManager interface {
	TranslatePodUID(uid types.UID) kubetypes.ResolvedPodUID
}
```

### RlimitStats

```go
// RlimitStats函数返回有关进程计数的基本信息
func (p *Provider) RlimitStats() (*statsapi.RlimitStats, error) {
	// 调用pidlimit.Stats函数获取进程计数的信息
	return pidlimit.Stats()
}
```

#### Stats

```go
// Stats函数提供有关最大进程计数和当前进程计数的基本信息
func Stats() (*statsapi.RlimitStats, error) {
	// 创建一个statsapi.RlimitStats类型的变量rlimit
	rlimit := &statsapi.RlimitStats{}

	taskMax := int64(-1)
	// 计算kernel.pid_max和kernel.threads-max的最小值，它们都指定了系统范围内的任务数限制
	for _, file := range []string{"/proc/sys/kernel/pid_max", "/proc/sys/kernel/threads-max"} {
		// 读取文件内容
		if content, err := os.ReadFile(file); err == nil {
			// 将文件内容转换为整数
			if limit, err := strconv.ParseInt(string(content[:len(content)-1]), 10, 64); err == nil {
				// 更新taskMax为最小值
				if taskMax == -1 || taskMax > limit {
					taskMax = limit
				}
			}
		}
	}
	// 两次读取都没有失败
	if taskMax >= 0 {
		// 将taskMax赋值给rlimit的MaxPID字段
		rlimit.MaxPID = &taskMax
	}

	// 尽可能读取"/proc/loadavg"，因为sysinfo(2)在大于65538时会返回截断的数字。参考：https://github.com/kubernetes/kubernetes/issues/107107
	if procs, err := runningTaskCount(); err == nil {
		// 将procs赋值给rlimit的NumOfRunningProcesses字段
		rlimit.NumOfRunningProcesses = &procs
	} else {
		var info syscall.Sysinfo_t
		syscall.Sysinfo(&info)
		procs := int64(info.Procs)
		// 将procs赋值给rlimit的NumOfRunningProcesses字段
		rlimit.NumOfRunningProcesses = &procs
	}

	// 设置rlimit的Time字段为当前时间
	rlimit.Time = v1.NewTime(time.Now())

	// 返回rlimit和nil错误
	return rlimit, nil
}
```

##### runningTaskCount

```go
// runningTaskCount函数返回正在运行的任务数
func runningTaskCount() (int64, error) {
	// 示例：1.36 3.49 4.53 2/3518 3715089
	// 读取"/proc/loadavg"文件内容
	bytes, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	// 将文件内容拆分为字段
	fields := strings.Fields(string(bytes))
	if len(fields) < 5 {
		return 0, fmt.Errorf("not enough fields in /proc/loadavg")
	}
	// 将第四个字段按"/"进行分割
	subfields := strings.Split(fields[3], "/")
	if len(subfields) != 2 {
		return 0, fmt.Errorf("error parsing fourth field of /proc/loadavg")
	}
	// 将分割后的第二个字段转换为整数
	return strconv.ParseInt(subfields[1], 10, 64)
}
```

### GetCgroupStats

```go
// GetCgroupStats返回cgroupName对应的cgroup的统计信息。注意，此函数不生成文件系统统计信息。
func (p *Provider) GetCgroupStats(cgroupName string, updateStats bool) (*statsapi.ContainerStats, *statsapi.NetworkStats, error) {
	// 获取cgroupName对应的cgroup的信息
	info, err := getCgroupInfo(p.cadvisor, cgroupName, updateStats)
	if err != nil {
		return nil, nil, fmt.Errorf("获取%s的cgroup统计信息失败：%v", cgroupName, err)
	}
	// 对于原始的cgroup，Rootfs和imagefs没有意义
	s := cadvisorInfoToContainerStats(cgroupName, info, nil, nil) // 将cadvisor信息转换为容器统计信息
	n := cadvisorInfoToNetworkStats(info)                         // 将cadvisor信息转换为网络统计信息
	return s, n, nil
}
```

#### getCgroupInfo

```go
// getCgroupInfo从cadvisor中返回具有指定containerName的容器的信息。
func getCgroupInfo(cadvisor cadvisor.Interface, containerName string, updateStats bool) (*cadvisorapiv2.ContainerInfo, error) {
	var maxAge *time.Duration
	if updateStats {
		age := 0 * time.Second
		maxAge = &age
	}
	// 从cadvisor获取容器信息
	infoMap, err := cadvisor.ContainerInfoV2(containerName, cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2, // 需要2个样本来计算“瞬时”CPU
		Recursive: false,
		MaxAge:    maxAge,
	})
	if err != nil {
		return nil, fmt.Errorf("获取%s的容器信息失败：%v", containerName, err)
	}
	if len(infoMap) != 1 {
		return nil, fmt.Errorf("容器数量不符合预期：%v", len(infoMap))
	}
	info := infoMap[containerName]
	return &info, nil
}
```

### GetCgroupCPUAndMemoryStats

```go
// GetCgroupCPUAndMemoryStats返回cgroupName对应的cgroup的CPU和内存统计信息。注意，此函数不生成文件系统统计信息。
func (p *Provider) GetCgroupCPUAndMemoryStats(cgroupName string, updateStats bool) (*statsapi.ContainerStats, error) {
	// 获取cgroupName对应的cgroup的信息
	info, err := getCgroupInfo(p.cadvisor, cgroupName, updateStats)
	if err != nil {
		return nil, fmt.Errorf("获取%s的cgroup统计信息失败：%v", cgroupName, err)
	}
	// 对于原始的cgroup，Rootfs和imagefs没有意义
	s := cadvisorInfoToContainerCPUAndMemoryStats(cgroupName, info) // 将cadvisor信息转换为CPU和内存统计信息
	return s, nil
}
```

### RootFsStats

```go
// RootFsStats返回节点根文件系统的统计信息。
func (p *Provider) RootFsStats() (*statsapi.FsStats, error) {
	// 获取根文件系统的信息
	rootFsInfo, err := p.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("获取根文件系统信息失败：%v", err)
	}

	var nodeFsInodesUsed *uint64
	if rootFsInfo.Inodes != nil && rootFsInfo.InodesFree != nil {
		nodeFsIU := *rootFsInfo.Inodes - *rootFsInfo.InodesFree
		nodeFsInodesUsed = &nodeFsIU
	}

	// 获取根容器统计信息的时间戳，将用作imageFs统计信息的时间戳。
	// 不强制进行统计更新，因为我们只需要时间戳。
	rootStats, err := getCgroupStats(p.cadvisor, "/", false)
	if err != nil {
		return nil, fmt.Errorf("获取根容器统计信息失败：%v", err)
	}

	return &statsapi.FsStats{
		Time:           metav1.NewTime(rootStats.Timestamp),
		AvailableBytes: &rootFsInfo.Available,
		CapacityBytes:  &rootFsInfo.Capacity,
		UsedBytes:      &rootFsInfo.Usage,
		InodesFree:     rootFsInfo.InodesFree,
		Inodes:         rootFsInfo.Inodes,
		InodesUsed:     nodeFsInodesUsed,
	}, nil
}
```

#### getCgroupStats

```go
// getCgroupStats从cadvisor中返回具有指定containerName的容器的最新统计信息。
func getCgroupStats(cadvisor cadvisor.Interface, containerName string, updateStats bool) (*cadvisorapiv2.ContainerStats, error) {
	info, err := getCgroupInfo(cadvisor, containerName, updateStats)
	if err != nil {
		return nil, err
	}
	stats, found := latestContainerStats(info)
	if !found {
		return nil, fmt.Errorf("无法从容器信息中获取%s的最新统计信息", containerName)
	}
	return stats, nil
}
```

### GetContainerInfo

```go
// GetContainerInfo返回容器的统计信息（来自cAdvisor）。
func (p *Provider) GetContainerInfo(ctx context.Context, podFullName string, podUID types.UID, containerName string, req *cadvisorapiv1.ContainerInfoRequest) (*cadvisorapiv1.ContainerInfo, error) {
	// 解析并重新转换类型。
	// 我们需要静态Pod的UID，但kubecontainer API使用types.UID。
	podUID = types.UID(p.podManager.TranslatePodUID(podUID))

	pods, err := p.runtimeCache.GetPods(ctx)
	if err != nil {
		return nil, err
	}
	pod := kubecontainer.Pods(pods).FindPod(podFullName, podUID)
	container := pod.FindContainerByName(containerName)
	if container == nil {
		return nil, kubecontainer.ErrContainerNotFound
	}

	// 从cAdvisor获取容器信息
	ci, err := p.cadvisor.DockerContainer(container.ID.ID, req)
	if err != nil {
		return nil, err
	}
	return &ci, nil
}
```

### GetRawContainerInfo

```go
// GetRawContainerInfo返回非Kubernetes容器的统计信息（来自cAdvisor）。
func (p *Provider) GetRawContainerInfo(containerName string, req *cadvisorapiv1.ContainerInfoRequest, subcontainers bool) (map[string]*cadvisorapiv1.ContainerInfo, error) {
	if subcontainers {
		// 获取容器的子容器信息
		return p.cadvisor.SubcontainerInfo(containerName, req)
	}
	// 获取容器的信息
	containerInfo, err := p.cadvisor.ContainerInfo(containerName, req)
	if err != nil {
		return nil, err
	}
	return map[string]*cadvisorapiv1.ContainerInfo{
		containerInfo.Name: containerInfo,
	}, nil
}
```

### HasDedicatedImageFs

```go
// HasDedicatedImageFs如果存在用于存储镜像的专用文件系统，则返回true。
func (p *Provider) HasDedicatedImageFs(ctx context.Context) (bool, error) {
	// 获取镜像文件系统的设备信息
	device, err := p.containerStatsProvider.ImageFsDevice(ctx)
	if err != nil {
		return false, err
	}
	// 获取根文件系统的信息
	rootFsInfo, err := p.cadvisor.RootFsInfo()
	if err != nil {
		return false, err
	}
	return device != rootFsInfo.Device, nil
}
```

