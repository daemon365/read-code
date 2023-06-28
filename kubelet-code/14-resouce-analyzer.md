## 简介

kubelet ResourceAnalyzer（资源分析器）是 Kubernetes 中的一个组件，它负责收集和报告节点（Node）上的资源使用情况。kubelet是在每个节点上运行的Kubernetes代理，它负责管理节点上的容器化工作负载。

ResourceAnalyzer的主要功能是监测节点上的资源消耗，包括CPU、内存、磁盘和网络等方面。它会定期从操作系统和容器运行时获取资源使用信息，并将这些信息汇报给Kubernetes的控制平面，例如kubelet所在节点的kube-api-server。

通过ResourceAnalyzer，管理员可以了解到每个节点上容器的资源使用情况，以及节点整体的资源负载情况。这些信息对于集群的资源管理、调度和扩展等方面非常重要。例如，它可以帮助管理员判断节点是否过载，是否需要调整资源分配，或者进行自动化的弹性扩缩容操作。

## ResourceAnalyzer

```go
type ResourceAnalyzer interface {
	Start()  // 启动ResourceAnalyzer

	fsResourceAnalyzerInterface  // 嵌入fs函数到ResourceAnalyzer中
	SummaryProvider  // 提供统计信息摘要
}
```

### fsResourceAnalyzerInterface

```go
// fsResourceAnalyzerInterface用于将fs函数嵌入到ResourceAnalyzer中
type fsResourceAnalyzerInterface interface {
	GetPodVolumeStats(uid types.UID) (PodVolumeStats, bool)  // 获取特定Pod的卷统计信息
}
```

#### PodVolumeStats

```go
// PodVolumeStats封装了一个Pod的VolumeStats。
// 它由两个列表组成，分别用于本地临时卷和持久卷。
type PodVolumeStats struct {
	EphemeralVolumes  []stats.VolumeStats
	PersistentVolumes []stats.VolumeStats
}
```

#### fsResourceAnalyzer

```go
// fsResourceAnalyzer提供有关文件系统资源使用情况的统计信息
type fsResourceAnalyzer struct {
	statsProvider     Provider
	calcPeriod        time.Duration
	cachedVolumeStats atomic.Value
	startOnce         sync.Once
	eventRecorder     record.EventRecorder
}
```

##### newFsResourceAnalyzer

```go
var _ fsResourceAnalyzerInterface = &fsResourceAnalyzer{}

// newFsResourceAnalyzer返回一个新的fsResourceAnalyzer实现
func newFsResourceAnalyzer(statsProvider Provider, calcVolumePeriod time.Duration, eventRecorder record.EventRecorder) *fsResourceAnalyzer {
	r := &fsResourceAnalyzer{
		statsProvider: statsProvider,
		calcPeriod:    calcVolumePeriod,
		eventRecorder: eventRecorder,
	}
	r.cachedVolumeStats.Store(make(statCache))
	return r
}
```

##### Start

```go
// Start开始对卷统计信息进行及时的后台缓存
func (s *fsResourceAnalyzer) Start() {
	s.startOnce.Do(func() {
		if s.calcPeriod <= 0 {
			klog.InfoS("禁用卷统计信息收集")
			return
		}
		klog.InfoS("开始FS ResourceAnalyzer")
		go wait.Forever(func() { s.updateCachedPodVolumeStats() }, s.calcPeriod)
	})
}
```

##### updateCachedPodVolumeStats

```go
// updateCachedPodVolumeStats为kubelet已知的每个Pod计算并缓存PodVolumeStats
func (s *fsResourceAnalyzer) updateCachedPodVolumeStats() {
	oldCache := s.cachedVolumeStats.Load().(statCache)
	newCache := make(statCache)

	// 将现有条目复制到新映射中，为缓存中缺失的Pod创建/启动新条目
	for _, pod := range s.statsProvider.GetPods() {
		if value, found := oldCache[pod.GetUID()]; !found {
			newCache[pod.GetUID()] = newVolumeStatCalculator(s.statsProvider, s.calcPeriod, pod, s.eventRecorder).StartOnce()
		} else {
			newCache[pod.GetUID()] = value
		}
	}

	// 停止已删除的Pod的条目
	for uid, entry := range oldCache {
		if _, found := newCache[uid]; !found {
			entry.StopOnce()
		}
	}

	// 更新缓存引用
	s.cachedVolumeStats.Store(newCache)
}
```

##### GetPodVolumeStats

```go
// GetPodVolumeStats返回给定Pod的PodVolumeStats。
// 结果从在后台主动填充的缓存中查找，而不是即时计算。
func (s *fsResourceAnalyzer) GetPodVolumeStats(uid types.UID) (PodVolumeStats, bool) {
	cache := s.cachedVolumeStats.Load().(statCache)
	statCalc, found := cache[uid]
	if !found {
		// TODO: 区分统计信息为空的情况
		// 参见issue＃20679
		return PodVolumeStats{}, false
	}
	return statCalc.GetLatest()
}
```

### SummaryProvider

```go
// SummaryProvider提供来自Kubelet的统计信息摘要
type SummaryProvider interface {
	// Get从Kubelet获取带有统计信息的新摘要，
	// 如果updateStats为true，则会更新一些统计信息
	Get(ctx context.Context, updateStats bool) (*statsapi.Summary, error)

	// GetCPUAndMemoryStats从Kubelet获取带有CPU和内存统计信息的新摘要
	GetCPUAndMemoryStats(ctx context.Context) (*statsapi.Summary, error)
}
```

#### summaryProviderImpl

```go
// summaryProviderImpl实现了SummaryProvider接口。
type summaryProviderImpl struct {
	// kubeletCreationTime是summaryProvider创建的时间。
	kubeletCreationTime metav1.Time
	// systemBootTime是系统启动的时间。
	systemBootTime metav1.Time

	provider Provider
}
```

##### NewSummaryProvider

```go
var _ SummaryProvider = &summaryProviderImpl{}

// NewSummaryProvider使用指定的statsProvider提供的统计信息返回SummaryProvider。
func NewSummaryProvider(statsProvider Provider) SummaryProvider {
	kubeletCreationTime := metav1.Now()
	bootTime, err := util.GetBootTime()
	if err != nil {
		// 如果获取启动时间时发生错误，bootTime将为零。
		klog.InfoS("获取系统启动时间时出错。节点指标的开始时间将不正确", "err", err)
	}

	return &summaryProviderImpl{
		kubeletCreationTime: kubeletCreationTime,
		systemBootTime:      metav1.NewTime(bootTime),
		provider:            statsProvider,
	}
}
```

##### Get

```go
func (sp *summaryProviderImpl) Get(ctx context.Context, updateStats bool) (*statsapi.Summary, error) {
	// TODO(timstclair): 如果出现以下任何错误，考虑返回尽力而为的响应。
	node, err := sp.provider.GetNode()
	if err != nil {
		return nil, fmt.Errorf("获取节点信息失败：%v", err)
	}
	nodeConfig := sp.provider.GetNodeConfig()
	rootStats, networkStats, err := sp.provider.GetCgroupStats("/", updateStats)
	if err != nil {
		return nil, fmt.Errorf("获取根cgroup统计信息失败：%v", err)
	}
	rootFsStats, err := sp.provider.RootFsStats()
	if err != nil {
		return nil, fmt.Errorf("获取rootFs统计信息失败：%v", err)
	}
	imageFsStats, err := sp.provider.ImageFsStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取imageFs统计信息失败：%v", err)
	}
	var podStats []statsapi.PodStats
	if updateStats {
		podStats, err = sp.provider.ListPodStatsAndUpdateCPUNanoCoreUsage(ctx)
	} else {
		podStats, err = sp.provider.ListPodStats(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("列出Pod统计信息失败：%v", err)
	}

	rlimit, err := sp.provider.RlimitStats()
	if err != nil {
		return nil, fmt.Errorf("获取rlimit统计信息失败：%v", err)
	}

	nodeStats := statsapi.NodeStats{
		NodeName:         node.Name,
		CPU:              rootStats.CPU,
		Memory:           rootStats.Memory,
		Network:          networkStats,
		StartTime:        sp.systemBootTime,
		Fs:               rootFsStats,
		Runtime:          &statsapi.RuntimeStats{ImageFs: imageFsStats},
		Rlimit:           rlimit,
		SystemContainers: sp.GetSystemContainersStats(nodeConfig, podStats, updateStats),
	}
	summary := statsapi.Summary{
		Node: nodeStats,
		Pods: podStats,
	}
	return &summary, nil
}
```

###### GetSystemContainersStats

```go
func (sp *summaryProviderImpl) GetSystemContainersStats(nodeConfig cm.NodeConfig, podStats []statsapi.PodStats, updateStats bool) (stats []statsapi.ContainerStats) {
	systemContainers := map[string]struct {
		name             string
		forceStatsUpdate bool
		startTime        metav1.Time
	}{
		statsapi.SystemContainerKubelet: {name: nodeConfig.KubeletCgroupsName, forceStatsUpdate: false, startTime: sp.kubeletCreationTime},
		statsapi.SystemContainerRuntime: {name: nodeConfig.RuntimeCgroupsName, forceStatsUpdate: false},
		statsapi.SystemContainerMisc:    {name: nodeConfig.SystemCgroupsName, forceStatsUpdate: false},
		statsapi.SystemContainerPods:    {name: sp.provider.GetPodCgroupRoot(), forceStatsUpdate: updateStats},
	}

	for sys, cont := range systemContainers {
		// 如果cgroup名称未定义（并非所有系统容器都是必需的），则跳过。
		if cont.name == "" {
			continue
		}
		s, _, err := sp.provider.GetCgroupStats(cont.name, cont.forceStatsUpdate)
		if err != nil {
			klog.ErrorS(err, "获取系统容器统计信息失败", "containerName", cont.name)
			continue
		}
		// 系统容器没有与之关联的文件系统。
		s.Logs, s.Rootfs = nil, nil
		s.Name = sys

		// 如果我们知道系统容器的启动时间，则使用该时间替代cAdvisor提供的启动时间。
		if !cont.startTime.IsZero() {
			s.StartTime = cont.startTime
		}
		stats = append(stats, *s)
	}

	return stats
}
```

##### GetCPUAndMemoryStats

```go
func (sp *summaryProviderImpl) GetCPUAndMemoryStats(ctx context.Context) (*statsapi.Summary, error) {
	// TODO(timstclair): 如果出现以下任何错误，考虑返回尽力而为的响应。
	node, err := sp.provider.GetNode()
	if err != nil {
		return nil, fmt.Errorf("获取节点信息失败：%v", err)
	}
	nodeConfig := sp.provider.GetNodeConfig()
	rootStats, err := sp.provider.GetCgroupCPUAndMemoryStats("/", false)
	if err != nil {
		return nil, fmt.Errorf("获取根cgroup统计信息失败：%v", err)
	}

	podStats, err := sp.provider.ListPodCPUAndMemoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("列出Pod统计信息失败：%v", err)
	}

	nodeStats := statsapi.NodeStats{
		NodeName:         node.Name,
		CPU:              rootStats.CPU,
		Memory:           rootStats.Memory,
		StartTime:        rootStats.StartTime,
		SystemContainers: sp.GetSystemContainersCPUAndMemoryStats(nodeConfig, podStats, false),
	}
	summary := statsapi.Summary{
		Node: nodeStats,
		Pods: podStats,
	}
	return &summary, nil
}
```

###### GetSystemContainersCPUAndMemoryStats

```go
func (sp *summaryProviderImpl) GetSystemContainersCPUAndMemoryStats(nodeConfig cm.NodeConfig, podStats []statsapi.PodStats, updateStats bool) (stats []statsapi.ContainerStats) {
	systemContainers := map[string]struct {
		name             string
		forceStatsUpdate bool
		startTime        metav1.Time
	}{
		statsapi.SystemContainerKubelet: {name: nodeConfig.KubeletCgroupsName, forceStatsUpdate: false, startTime: sp.kubeletCreationTime},
		statsapi.SystemContainerRuntime: {name: nodeConfig.RuntimeCgroupsName, forceStatsUpdate: false},
		statsapi.SystemContainerMisc:    {name: nodeConfig.SystemCgroupsName, forceStatsUpdate: false},
		statsapi.SystemContainerPods:    {name: sp.provider.GetPodCgroupRoot(), forceStatsUpdate: updateStats},
	}

	for sys, cont := range systemContainers {
		// 如果cgroup名称未定义（并非所有系统容器都是必需的），则跳过。
		if cont.name == "" {
			continue
		}
		s, err := sp.provider.GetCgroupCPUAndMemoryStats(cont.name, cont.forceStatsUpdate)
		if err != nil {
			klog.ErrorS(err, "获取系统容器统计信息失败", "containerName", cont.name)
			continue
		}
		s.Name = sys

		// 如果我们知道系统容器的启动时间，则使用该时间替代cAdvisor提供的启动时间。
		if !cont.startTime.IsZero() {
			s.StartTime = cont.startTime
		}
		stats = append(stats, *s)
	}

	return stats
}
```

### NewResourceAnalyzer

```go
// resourceAnalyzer implements ResourceAnalyzer
type resourceAnalyzer struct {
	*fsResourceAnalyzer
	SummaryProvider
}

var _ ResourceAnalyzer = &resourceAnalyzer{}

// NewResourceAnalyzer returns a new ResourceAnalyzer
func NewResourceAnalyzer(statsProvider Provider, calVolumeFrequency time.Duration, eventRecorder record.EventRecorder) ResourceAnalyzer {
	fsAnalyzer := newFsResourceAnalyzer(statsProvider, calVolumeFrequency, eventRecorder)
	summaryProvider := NewSummaryProvider(statsProvider)
	return &resourceAnalyzer{fsAnalyzer, summaryProvider}
}
```

### Start

```go
// Start starts background functions necessary for the ResourceAnalyzer to function
func (ra *resourceAnalyzer) Start() {
	ra.fsResourceAnalyzer.Start()
}
```

