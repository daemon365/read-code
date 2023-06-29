## 简介

Kubelet Status Manager 是 Kubernetes 中的一个组件，它负责管理 Kubelet 的状态和生命周期。

Kubelet 是 Kubernetes 节点上运行的代理程序，负责管理节点上的容器运行时和容器。Kubelet Status Manager 监控和管理 Kubelet 的状态，确保其正常运行并与 Kubernetes 控制平面进行通信。

Kubelet Status Manager 的主要功能包括：

1. 健康检查：定期检查 Kubelet 是否正常运行，并报告其健康状态给 Kubernetes 控制平面。如果 Kubelet 不可用或出现故障，控制平面可以采取相应的措施，例如重新调度容器或通知运维人员。
2. 启动和终止：负责启动和终止 Kubelet 进程。在节点启动时，Kubelet Status Manager 会确保 Kubelet 正确启动，并与控制平面建立连接。在节点关机或 Kubelet 进程终止时，Kubelet Status Manager 会负责终止 Kubelet，并将节点状态报告给控制平面。
3. 资源管理：监控节点上的资源使用情况，例如 CPU、内存和磁盘空间。Kubelet Status Manager 可以报告节点的资源情况给控制平面，以便进行调度和资源分配决策。
4. 事件和日志：收集 Kubelet 相关的事件和日志信息，并将其发送给控制平面进行记录和分析。这有助于故障排除和性能监控。

Kubelet Status Manager 是 Kubernetes 集群中关键的组件之一，它确保节点上的 Kubelet 正常运行，并提供与控制平面的有效通信。通过监控 Kubelet 的状态和资源使用情况，它提高了集群的可靠性和稳定性。

## Manager

```GO
// Manager是kubelet pod状态的事实来源，应该与最新的v1.PodStatus保持同步。它还将更新同步回API服务器。
type Manager interface {
	PodStatusProvider

	// 启动API服务器状态同步循环。
	Start()

	// SetPodStatus更新给定pod的缓存状态，并触发状态更新。
	SetPodStatus(pod *v1.Pod, status v1.PodStatus)

	// SetContainerReadiness使用给定的准备状态更新缓存的容器状态，并触发状态更新。
	SetContainerReadiness(podUID types.UID, containerID kubecontainer.ContainerID, ready bool)

	// SetContainerStartup使用给定的启动状态更新缓存的容器状态，并触发状态更新。
	SetContainerStartup(podUID types.UID, containerID kubecontainer.ContainerID, started bool)

	// TerminatePod将提供的pod的容器状态重置为terminated，并触发状态更新。
	TerminatePod(pod *v1.Pod)

	// RemoveOrphanedStatuses扫描状态缓存并删除不在提供的podUID中的任何条目。
	RemoveOrphanedStatuses(podUIDs map[types.UID]bool)

	// GetContainerResourceAllocation返回容器的已检查点AllocatedResources值。
	GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool)

	// GetPodResizeStatus返回检查点PodStatus.Resize值。
	GetPodResizeStatus(podUID string) (v1.PodResizeStatus, bool)

	// SetPodAllocation检查点分配给pod的容器的资源。
	SetPodAllocation(pod *v1.Pod) error

	// SetPodResizeStatus检查点对于pod的最后调整大小的决策。
	SetPodResizeStatus(podUID types.UID, resize v1.PodResizeStatus) error
}
```

### PodStatusProvider

```go
// PodStatusProvider知道如何为pod提供状态。它旨在被其他需要审查pod的权威状态的组件使用。PodStatusProvider表示kubelet所看到的正在运行的pod的实际状态。
type PodStatusProvider interface {
	// GetPodStatus返回提供的pod UID的缓存状态，以及它是否是缓存命中。
	GetPodStatus(uid types.UID) (v1.PodStatus, bool)
}
```

## manager

```go
// 在apiserver中更新pod状态。仅在新状态发生更改时编写。所有方法都是线程安全的。
type manager struct {
	kubeClient clientset.Interface
	podManager PodManager
	// 映射从pod UID到相应pod的同步状态。
	podStatuses      map[types.UID]versionedPodStatus
	podStatusesLock  sync.RWMutex
	podStatusChannel chan struct{}
	// 映射从(镜像)pod UID到成功发送到API服务器的最新状态版本。
	// apiStatusVersions只能从同步线程访问。
	apiStatusVersions map[kubetypes.MirrorPodUID]uint64
	podDeletionSafety PodDeletionSafetyProvider

	podStartupLatencyHelper PodStartupLatencyStateHelper
	// state允许保存/恢复pod资源分配并容忍kubelet重启。
	state state.State
	// stateFileDirectory保存检查点状态文件的目录。
	stateFileDirectory string
}

// NewManager returns a functional Manager.
func NewManager(kubeClient clientset.Interface, podManager PodManager, podDeletionSafety PodDeletionSafetyProvider, podStartupLatencyHelper PodStartupLatencyStateHelper, stateFileDirectory string) Manager {
	return &manager{
		kubeClient:              kubeClient,
		podManager:              podManager,
		podStatuses:             make(map[types.UID]versionedPodStatus),
		podStatusChannel:        make(chan struct{}, 1),
		apiStatusVersions:       make(map[kubetypes.MirrorPodUID]uint64),
		podDeletionSafety:       podDeletionSafety,
		podStartupLatencyHelper: podStartupLatencyHelper,
		stateFileDirectory:      stateFileDirectory,
	}
}
```

### PodManager

```GO
// PodManager是管理器观察kubelet实际状态所需的方法子集。
// 有关方法的文档，请参阅pkg/k8s.io/kubernetes/pkg/kubelet/pod.Manager。
type PodManager interface {
	GetPodByUID(types.UID) (*v1.Pod, bool)
	GetMirrorPodByPod(*v1.Pod) (*v1.Pod, bool)
	TranslatePodUID(uid types.UID) kubetypes.ResolvedPodUID
	GetUIDTranslations() (podToMirror map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID, mirrorToPod map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID)
}
```

### versionedPodStatus

```go
// v1.PodStatus的包装器，包括一个版本，以确保不会将过期的pod状态发送到API服务器。
type versionedPodStatus struct {
	// 版本是一个单调递增的版本号（每个pod）。
	version uint64
	// 发送更新到API服务器的pod名称和命名空间。
	podName      string
	podNamespace string
	// at是检测到最近一次状态更新的时间
	at time.Time

	// 如果状态是在SyncTerminatedPod结束后或完成后生成的，则为true。
	podIsFinished bool

	status v1.PodStatus
}
```

### PodDeletionSafetyProvider

```go
// PodDeletionSafetyProvider提供可以安全删除pod的保证。
type PodDeletionSafetyProvider interface {
	// 如果pod可能有正在运行的容器，则返回true。
	PodCouldHaveRunningContainers(pod *v1.Pod) bool
}
```

#### PodCouldHaveRunningContainers

```GO
// PodCouldHaveRunningContainers根据给定的UID判断Pod是否可能仍然有运行的容器。
// 如果Pod尚未启动或Pod是未知的，则返回false。
func (kl *Kubelet) PodCouldHaveRunningContainers(pod *v1.Pod) bool {
	if kl.podWorkers.CouldHaveRunningContainers(pod.UID) {
		return true
	}

	// 检查Pod在终止之前是否可能需要取消准备资源
	// 注意：这是一个临时解决方案。此调用存在于此处，以避免更改状态管理器及其测试。
	// TODO: 扩展PodDeletionSafetyProvider接口并在单独的Kubelet方法中实现它。
	if utilfeature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation) {
		if kl.containerManager.PodMightNeedToUnprepareResources(pod.UID) {
			return true
		}
	}
	return false
}

```

### PodStartupLatencyStateHelper

```go
type PodStartupLatencyStateHelper interface {
	RecordStatusUpdated(pod *v1.Pod)
	DeletePodStartupState(podUID types.UID)
}
```

#### deletePodStatus

```go
// deletePodStatus 简单地从状态缓存中删除给定的Pod。
func (m *manager) deletePodStatus(uid types.UID) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	delete(m.podStatuses, uid)
	m.podStartupLatencyHelper.DeletePodStartupState(uid)
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		m.state.Delete(string(uid), "")
	}
}
```



### State

```GO
// State接口提供了跟踪和设置pod资源分配的方法
type State interface {
	Reader
	Writer
}

// Reader接口用于读取当前pod资源分配状态
type Reader interface {
	GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool)
	GetPodResourceAllocation() PodResourceAllocation
	GetPodResizeStatus(podUID string) (v1.PodResizeStatus, bool)
	GetResizeStatus() PodResizeStatus
}

// Writer接口用于写入pod资源分配状态
type Writer interface {
	SetContainerResourceAllocation(podUID string, containerName string, alloc v1.ResourceList) error
	SetPodResourceAllocation(PodResourceAllocation) error
	SetPodResizeStatus(podUID string, resizeStatus v1.PodResizeStatus) error
	SetResizeStatus(PodResizeStatus) error
	Delete(podUID string, containerName string) error
	ClearState() error
}
```

#### PodResourceAllocation

```GO
// PodResourceAllocation类型用于跟踪分配给pod容器的资源
type PodResourceAllocation map[string]map[string]v1.ResourceList

// PodResizeStatus类型用于跟踪pod的最后调整大小的决策
type PodResizeStatus map[string]v1.PodResizeStatus

// Clone返回PodResourceAllocation的副本
func (pr PodResourceAllocation) Clone() PodResourceAllocation {
	prCopy := make(PodResourceAllocation)
	for pod := range pr {
		prCopy[pod] = make(map[string]v1.ResourceList)
		for container, alloc := range pr[pod] {
			prCopy[pod][container] = alloc.DeepCopy()
		}
	}
	return prCopy
}
```

#### noopStateCheckpoint

```GO
type noopStateCheckpoint struct{}

// NewNoopStateCheckpoint创建一个虚拟的状态检查点管理器
func NewNoopStateCheckpoint() State {
	return &noopStateCheckpoint{}
}

func (sc *noopStateCheckpoint) GetContainerResourceAllocation(_ string, _ string) (v1.ResourceList, bool) {
	return nil, false
}

func (sc *noopStateCheckpoint) GetPodResourceAllocation() PodResourceAllocation {
	return nil
}

func (sc *noopStateCheckpoint) GetPodResizeStatus(_ string) (v1.PodResizeStatus, bool) {
	return "", false
}

func (sc *noopStateCheckpoint) GetResizeStatus() PodResizeStatus {
	return nil
}

func (sc *noopStateCheckpoint) SetContainerResourceAllocation(_ string, _ string, _ v1.ResourceList) error {
	return nil
}

func (sc *noopStateCheckpoint) SetPodResourceAllocation(_ PodResourceAllocation) error {
	return nil
}

func (sc *noopStateCheckpoint) SetPodResizeStatus(_ string, _ v1.PodResizeStatus) error {
	return nil
}

func (sc *noopStateCheckpoint) SetResizeStatus(_ PodResizeStatus) error {
	return nil
}

func (sc *noopStateCheckpoint) Delete(_ string, _ string) error {
	return nil
}

func (sc *noopStateCheckpoint) ClearState() error {
	return nil
}
```

#### stateCheckpoint

```GO
var _ State = &stateCheckpoint{}

// State接口的实现结构体stateCheckpoint
type stateCheckpoint struct {
	mux               sync.RWMutex                          // 读写锁，用于保护状态的并发访问
	cache             State                                 // 内部缓存的状态
	checkpointManager checkpointmanager.CheckpointManager  // 检查点管理器，用于保存和恢复状态
	checkpointName    string                                // 检查点的名称
}

// NewStateCheckpoint创建一个新的State实例，用于跟踪带有检查点后端的Pod资源分配
func NewStateCheckpoint(stateDir, checkpointName string) (State, error) {
	// 初始化检查点管理器
	checkpointManager, err := checkpointmanager.NewCheckpointManager(stateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize checkpoint manager for pod allocation tracking: %v", err)
	}

	stateCheckpoint := &stateCheckpoint{
		cache:             NewStateMemory(),  // 使用NewStateMemory函数创建一个新的内存缓存状态
		checkpointManager: checkpointManager,
		checkpointName:    checkpointName,
	}

	if err := stateCheckpoint.restoreState(); err != nil {
		// 忽略ST1005规则的lint注释，用于向用户展示错误信息
		return nil, fmt.Errorf("could not restore state from checkpoint: %v, please drain this node and delete pod allocation checkpoint file %q before restarting Kubelet", err, path.Join(stateDir, checkpointName))
	}
	return stateCheckpoint, nil
}

// 从检查点中恢复状态，如果检查点不存在则创建一个新的
func (sc *stateCheckpoint) restoreState() error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	var err error

	checkpoint := NewPodResourceAllocationCheckpoint()  // 创建一个新的Pod资源分配检查点

	if err = sc.checkpointManager.GetCheckpoint(sc.checkpointName, checkpoint); err != nil {
		if err == errors.ErrCheckpointNotFound {
			return sc.storeState()
		}
		return err
	}

	sc.cache.SetPodResourceAllocation(checkpoint.AllocationEntries)  // 将检查点中的资源分配设置到缓存中
	sc.cache.SetResizeStatus(checkpoint.ResizeStatusEntries)  // 将检查点中的调整状态设置到缓存中
	klog.V(2).InfoS("State checkpoint: restored pod resource allocation state from checkpoint")  // 记录日志，恢复了Pod资源分配的状态
	return nil
}

// 将状态保存到检查点，调用方负责加锁
func (sc *stateCheckpoint) storeState() error {
	checkpoint := NewPodResourceAllocationCheckpoint()  // 创建一个新的Pod资源分配检查点

	podAllocation := sc.cache.GetPodResourceAllocation()
	for pod := range podAllocation {
		checkpoint.AllocationEntries[pod] = make(map[string]v1.ResourceList)
		for container, alloc := range podAllocation[pod] {
			checkpoint.AllocationEntries[pod][container] = alloc
		}
	}

	podResizeStatus := sc.cache.GetResizeStatus()
	checkpoint.ResizeStatusEntries = make(map[string]v1.PodResizeStatus)
	for pUID, rStatus := range podResizeStatus {
		checkpoint.ResizeStatusEntries[pUID] = rStatus
	}

	err := sc.checkpointManager.CreateCheckpoint(sc.checkpointName, checkpoint)  // 将检查点保存到检查点管理器中
	if err != nil {
		klog.ErrorS(err, "Failed to save pod allocation checkpoint")  // 记录日志，保存Pod资源分配检查点失败
		return err
	}
	return nil
}

// 获取分配给Pod的容器的当前资源分配
func (sc *stateCheckpoint) GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool) {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetContainerResourceAllocation(podUID, containerName)
}

// 获取当前Pod资源分配
func (sc *stateCheckpoint) GetPodResourceAllocation() PodResourceAllocation {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetPodResourceAllocation()
}

// 获取Pod的最后一次调整状态
func (sc *stateCheckpoint) GetPodResizeStatus(podUID string) (v1.PodResizeStatus, bool) {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetPodResizeStatus(podUID)
}

// 获取所有的调整状态
func (sc *stateCheckpoint) GetResizeStatus() PodResizeStatus {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetResizeStatus()
}

// 设置分配给Pod的容器的资源分配
func (sc *stateCheckpoint) SetContainerResourceAllocation(podUID string, containerName string, alloc v1.ResourceList) error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetContainerResourceAllocation(podUID, containerName, alloc)
	return sc.storeState()
}

// 设置Pod的资源分配
func (sc *stateCheckpoint) SetPodResourceAllocation(a PodResourceAllocation) error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetPodResourceAllocation(a)
	return sc.storeState()
}

// 设置Pod的最后一次调整状态
func (sc *stateCheckpoint) SetPodResizeStatus(podUID string, resizeStatus v1.PodResizeStatus) error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetPodResizeStatus(podUID, resizeStatus)
	return sc.storeState()
}

// 设置调整状态
func (sc *stateCheckpoint) SetResizeStatus(rs PodResizeStatus) error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetResizeStatus(rs)
	return sc.storeState()
}

// 删除指定Pod的分配信息
func (sc *stateCheckpoint) Delete(podUID string, containerName string) error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.Delete(podUID, containerName)
	return sc.storeState()
}

// 清除状态并保存到检查点中
func (sc *stateCheckpoint) ClearState() error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.ClearState()
	return sc.storeState()
}
```

#### stateMemory

```GO
// 定义结构体stateMemory
type stateMemory struct {
	sync.RWMutex                           // 读写锁，用于保护状态的并发访问
	podAllocation   PodResourceAllocation   // 存储Pod资源分配的映射表
	podResizeStatus PodResizeStatus         // 存储Pod调整状态的映射表
}

// State接口的实现结构体stateMemory
var _ State = &stateMemory{}

// NewStateMemory创建一个新的State实例，用于跟踪分配给Pod的资源
func NewStateMemory() State {
	klog.V(2).InfoS("Initialized new in-memory state store for pod resource allocation tracking")  // 记录日志，初始化内存中的状态存储
	return &stateMemory{
		podAllocation:   PodResourceAllocation{},
		podResizeStatus: PodResizeStatus{},
	}
}

// 获取分配给Pod的容器的当前资源分配
func (s *stateMemory) GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool) {
	s.RLock()
	defer s.RUnlock()

	alloc, ok := s.podAllocation[podUID][containerName]
	return alloc.DeepCopy(), ok
}

// 获取当前Pod资源分配
func (s *stateMemory) GetPodResourceAllocation() PodResourceAllocation {
	s.RLock()
	defer s.RUnlock()
	return s.podAllocation.Clone()
}

// 获取Pod的最后一次调整状态
func (s *stateMemory) GetPodResizeStatus(podUID string) (v1.PodResizeStatus, bool) {
	s.RLock()
	defer s.RUnlock()

	resizeStatus, ok := s.podResizeStatus[podUID]
	return resizeStatus, ok
}

// 获取所有的调整状态
func (s *stateMemory) GetResizeStatus() PodResizeStatus {
	s.RLock()
	defer s.RUnlock()
	prs := make(map[string]v1.PodResizeStatus)
	for k, v := range s.podResizeStatus {
		prs[k] = v
	}
	return prs
}

// 设置分配给Pod的容器的资源分配
func (s *stateMemory) SetContainerResourceAllocation(podUID string, containerName string, alloc v1.ResourceList) error {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.podAllocation[podUID]; !ok {
		s.podAllocation[podUID] = make(map[string]v1.ResourceList)
	}

	s.podAllocation[podUID][containerName] = alloc
	klog.V(3).InfoS("Updated container resource allocation", "podUID", podUID, "containerName", containerName, "alloc", alloc)  // 记录日志，更新了容器的资源分配情况
	return nil
}

// 设置Pod的资源分配
func (s *stateMemory) SetPodResourceAllocation(a PodResourceAllocation) error {
	s.Lock()
	defer s.Unlock()

	s.podAllocation = a.Clone()
	klog.V(3).InfoS("Updated pod resource allocation", "allocation", a)  // 记录日志，更新了Pod的资源分配情况
	return nil
}

// 设置Pod的最后一次调整状态
func (s *stateMemory) SetPodResizeStatus(podUID string, resizeStatus v1.PodResizeStatus) error {
	s.Lock()
	defer s.Unlock()

	if resizeStatus != "" {
		s.podResizeStatus[podUID] = resizeStatus
	} else {
		delete(s.podResizeStatus, podUID)
	}
	klog.V(3).InfoS("Updated pod resize state", "podUID", podUID, "resizeStatus", resizeStatus)  // 记录日志，更新了Pod的调整状态
	return nil
}

// 设置调整状态
func (s *stateMemory) SetResizeStatus(rs PodResizeStatus) error {
	s.Lock()
	defer s.Unlock()
	prs := make(map[string]v1.PodResizeStatus)
	for k, v := range rs {
		prs[k] = v
	}
	s.podResizeStatus = prs
	klog.V(3).InfoS("Updated pod resize state", "resizes", rs)  // 记录日志，更新了Pod的调整状态
	return nil
}

// 删除指定Pod的容器信息
func (s *stateMemory) deleteContainer(podUID string, containerName string) {
	delete(s.podAllocation[podUID], containerName)
	if len(s.podAllocation[podUID]) == 0 {
		delete(s.podAllocation, podUID)
		delete(s.podResizeStatus, podUID)
	}
	klog.V(3).InfoS("Deleted pod resource allocation", "podUID", podUID, "containerName", containerName)  // 记录日志，删除了Pod的容器资源分配信息
}

// 删除指定Pod的分配信息
func (s *stateMemory) Delete(podUID string, containerName string) error {
	s.Lock()
	defer s.Unlock()
	if len(containerName) == 0 {
		delete(s.podAllocation, podUID)
		delete(s.podResizeStatus, podUID)
		klog.V(3).InfoS("Deleted pod resource allocation and resize state", "podUID", podUID)  // 记录日志，删除了Pod的资源分配和调整状态
		return nil
	}
	s.deleteContainer(podUID, containerName)
	return nil
}

// 清除状态
func (s *stateMemory) ClearState() error {
	s.Lock()
	defer s.Unlock()

	s.podAllocation = make(PodResourceAllocation)
	s.podResizeStatus = make(PodResizeStatus)
	klog.V(3).InfoS("Cleared state")  // 记录日志，清除了状态
	return nil
}
```



### Start

```GO
func (m *manager) Start() {
	// 将m.state初始化为无操作状态检查点管理器
	m.state = state.NewNoopStateCheckpoint()

	// 即使客户端为nil，也创建pod分配检查点管理器，以便允许本地获取/设置AllocatedResources和Resize
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		stateImpl, err := state.NewStateCheckpoint(m.stateFileDirectory, podStatusManagerStateFile)
		if err != nil {
			// 这是一个关键的、不可恢复的失败。
			klog.ErrorS(err, "无法初始化pod分配检查点管理器，请排空节点并删除策略状态文件")
			panic(err)
		}
		m.state = stateImpl
	}

	// 如果没有客户端，则不启动状态管理器。这将在主节点上发生，其中kubelet负责引导主组件的pod。
	if m.kubeClient == nil {
		klog.InfoS("Kubernetes客户端为nil，不启动状态管理器")
		return
	}

	klog.InfoS("开始与API服务器同步pod状态")

	//nolint:staticcheck // SA1015 Ticker可以泄漏，因为它仅调用一次并且不处理终止。
	syncTicker := time.NewTicker(syncPeriod).C

	// syncPod和syncBatch共享同一个goroutine，以避免同步竞争。
	go wait.Forever(func() {
		for {
			select {
			case <-m.podStatusChannel:
				klog.V(4).InfoS("同步更新的状态")
				m.syncBatch(false)
			case <-syncTicker:
				klog.V(4).InfoS("同步所有状态")
				m.syncBatch(true)
			}
		}
	}, 0)
}
```

#### syncBatch

```GO
// syncBatch将Pod的状态与API服务器同步。返回尝试同步的次数，供测试使用。
func (m *manager) syncBatch(all bool) int {
	type podSync struct {
		podUID    types.UID
		statusUID kubetypes.MirrorPodUID
		status    versionedPodStatus
	}

	var updatedStatuses []podSync
	podToMirror, mirrorToPod := m.podManager.GetUIDTranslations()
	func() { // 临界区
		m.podStatusesLock.RLock()
		defer m.podStatusesLock.RUnlock()

		// 清理孤立的版本
		if all {
			for uid := range m.apiStatusVersions {
				_, hasPod := m.podStatuses[types.UID(uid)]
				_, hasMirror := mirrorToPod[uid]
				if !hasPod && !hasMirror {
					delete(m.apiStatusVersions, uid)
				}
			}
		}

		// 决定哪些Pod需要更新状态
		for uid, status := range m.podStatuses {
			// 将Pod UID（源）转换为状态UID（API Pod）
			// 静态Pod通过Pod UID在源中标识，但通过镜像Pod的UID在API中跟踪
			uidOfStatus := kubetypes.MirrorPodUID(uid)
			if mirrorUID, ok := podToMirror[kubetypes.ResolvedPodUID(uid)]; ok {
				if mirrorUID == "" {
					klog.V(5).InfoS("Static pod does not have a corresponding mirror pod; skipping",
						"podUID", uid,
						"pod", klog.KRef(status.podNamespace, status.podName))
					continue
				}
				uidOfStatus = mirrorUID
			}

			// 如果已经传递了新的状态更新，则触发更新，否则Pod可以等待下一次批量检查（也执行协调）
			if !all {
				if m.apiStatusVersions[uidOfStatus] >= status.version {
					continue
				}
				updatedStatuses = append(updatedStatuses, podSync{uid, uidOfStatus, status})
				continue
			}

			// 确保任何新的状态、不匹配的状态或准备删除的Pod得到更新。如果状态更新失败，我们将在下次更新任何其他Pod时重试。
			if m.needsUpdate(types.UID(uidOfStatus), status) {
				updatedStatuses = append(updatedStatuses, podSync{uid, uidOfStatus, status})
			} else if m.needsReconcile(uid, status.status) {
				// 在此处删除apiStatusVersions以强制更新Pod状态
				// 在大多数情况下，此处删除的apiStatusVersions应该很快填充
				// 在下面的syncPod()之后[如果syncPod()成功同步更新]
				delete(m.apiStatusVersions, uidOfStatus)
				updatedStatuses = append(updatedStatuses, podSync{uid, uidOfStatus, status})
			}
		}
	}()

	for _, update := range updatedStatuses {
		klog.V(5).InfoS("Sync pod status", "podUID", update.podUID, "statusUID", update.statusUID, "version", update.status.version)
		m.syncPod(update.podUID, update.status)
	}

	return len(updatedStatuses)
}
```

##### needsUpdate

```GO
// needsUpdate返回给定Pod UID的状态是否过期。
// 该方法不是线程安全的，只能由同步线程访问。
func (m *manager) needsUpdate(uid types.UID, status versionedPodStatus) bool {
	latest, ok := m.apiStatusVersions[kubetypes.MirrorPodUID(uid)]
	if !ok || latest < status.version {
		return true
	}
	pod, ok := m.podManager.GetPodByUID(uid)
	if !ok {
		return false
	}
	return m.canBeDeleted(pod, status.status, status.podIsFinished)
}
```

##### canBeDeleted

```GO
func (m *manager) canBeDeleted(pod *v1.Pod, status v1.PodStatus, podIsFinished bool) bool {
	if pod.DeletionTimestamp == nil || kubetypes.IsMirrorPod(pod) {
		return false
	}
	// 根据来自Pod管理器的pod.Status，将Pod删除延迟到阶段处于终止状态。
	if !podutil.IsPodPhaseTerminal(pod.Status.Phase) {
		// 为了调试目的，当延迟删除时，我们还记录了kubelet的本地阶段。
		klog.V(3).InfoS("Delaying pod deletion as the phase is non-terminal", "phase", pod.Status.Phase, "localPhase", status.Phase, "pod", klog.KObj(pod), "podUID", pod.UID)
		return false
	}
	// 如果这是完成Pod终止的更新，我们知道Pod终止已完成。
	if podIsFinished {
		klog.V(3).InfoS("The pod termination is finished as SyncTerminatedPod completes its execution", "phase", pod.Status.Phase, "localPhase", status.Phase, "pod", klog.KObj(pod), "podUID", pod.UID)
		return true
	}
	return false
}
```

##### deletePodStatus

```go
// deletePodStatus 简单地从状态缓存中删除给定的Pod。
func (m *manager) deletePodStatus(uid types.UID) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	delete(m.podStatuses, uid)
	m.podStartupLatencyHelper.DeletePodStartupState(uid)
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		m.state.Delete(string(uid), "")
	}
}
```

##### mergePodStatus

```go
// mergePodStatus 合并 oldPodStatus 和 newPodStatus，以保留不由 kubelet 拥有的 Pod 条件，并确保只在所有运行的容器终止后发生终止阶段转换。该方法不修改旧状态。
func mergePodStatus(oldPodStatus, newPodStatus v1.PodStatus, couldHaveRunningContainers bool) v1.PodStatus {
	podConditions := make([]v1.PodCondition, 0, len(oldPodStatus.Conditions)+len(newPodStatus.Conditions))

	for _, c := range oldPodStatus.Conditions {
		if !kubetypes.PodConditionByKubelet(c.Type) {
			podConditions = append(podConditions, c)
		}
	}

	transitioningToTerminalPhase := !podutil.IsPodPhaseTerminal(oldPodStatus.Phase) && podutil.IsPodPhaseTerminal(newPodStatus.Phase)

	for _, c := range newPodStatus.Conditions {
		if kubetypes.PodConditionByKubelet(c.Type) {
			podConditions = append(podConditions, c)
		} else if kubetypes.PodConditionSharedByKubelet(c.Type) {
			// 我们替换或附加所有“由 kubelet 共享”的条件
			if c.Type == v1.DisruptionTarget {
				// 通过检查确保在所有容器终止并且阶段为终止状态之后，才更新 DisruptionTarget 条件。这样，如果实际状态阶段转换被延迟，就避免了发送不必要的补丁请求以添加条件。
				if transitioningToTerminalPhase && !couldHaveRunningContainers {
					// 再次更新 LastTransitionTime，因为在 updateStatusInternal 中设置的旧转换时间很可能已过时，因为发送条件的时间被推迟，直到所有 Pod 的容器终止为止。
					updateLastTransitionTime(&newPodStatus, &oldPodStatus, c.Type)
					if _, c := podutil.GetPodConditionFromList(newPodStatus.Conditions, c.Type); c != nil {
						// 对于共享的条件，我们在 podConditions 中更新或附加
						podConditions = statusutil.ReplaceOrAppendPodCondition(podConditions, c)
					}
				}
			}
		}
	}
	newPodStatus.Conditions = podConditions

	// 除非 Pod 真正处于终止状态，否则延迟将 Pod 转换为终止状态。Kubelet 不应将具有可能运行的容器且实际上正在使用独占资源的 Pod 转换为终止状态。注意，资源（如卷）是由 Kubelet 中的一个子系统进行协调的，如果新的 Pod 重用了独占资源（卸载 -> 释放 -> 挂载），这意味着我们不需要等待 Kubelet 分离这些资源。通常，Kubelet 独占拥有的资源必须在报告 Pod 终止状态之前释放，而在 API 之上有参与组件的资源使用 Pod 的过渡到终止阶段（或完全删除）来释放这些资源。
	if transitioningToTerminalPhase {
		if couldHaveRunningContainers {
			newPodStatus.Phase = oldPodStatus.Phase
			newPodStatus.Reason = oldPodStatus.Reason
			newPodStatus.Message = oldPodStatus.Message
		}
	}

	// 如果新的阶段是终止阶段，显式地将 v1.PodReady 和 v1.ContainersReady 的 ready 条件设置为 false。如果阶段是终止阶段，kubelet 可能需要一些时间来协调 ready 条件，因此如果阶段是终止阶段，则显式地将 ready 条件设置为 false。这样做是为了确保 kubelet 不会报告带有终止 Pod 阶段且 ready=true 的状态更新。有关更多详细信息，请参见 https://issues.k8s.io/108594。
	if podutil.IsPodPhaseTerminal(newPodStatus.Phase) {
		if podutil.IsPodReadyConditionTrue(newPodStatus) || podutil.IsContainersReadyConditionTrue(newPodStatus) {
			containersReadyCondition := generateContainersReadyConditionForTerminalPhase(newPodStatus.Phase)
			podutil.UpdatePodCondition(&newPodStatus, &containersReadyCondition)

			podReadyCondition := generatePodReadyConditionForTerminalPhase(newPodStatus.Phase)
			podutil.UpdatePodCondition(&newPodStatus, &podReadyCondition)
		}
	}

	return newPodStatus
}
```

##### needsReconcile

```go
// needsReconcile 比较给定的状态与 Pod 管理器中的状态（实际上来自 apiserver），返回是否需要将状态与 apiserver 进行调和。当 Pod 状态在 apiserver 和 kubelet 之间不一致时，kubelet 应该强制发送更新以调和不一致，因为 kubelet 应该是 Pod 状态的真实来源。
// 注意（random-liu）：当添加镜像 Pod 管理器时，通过传递镜像 Pod uid 并通过 uid 获取镜像 Pod 更简单，但是现在 Pod 管理器仅支持通过静态 Pod 获取镜像 Pod，因此我们必须在此处传递静态 Pod uid。
// TODO（random-liu）：添加镜像 Pod 管理器后，简化逻辑。
func (m *manager) needsReconcile(uid types.UID, status v1.PodStatus) bool {
	// Pod 可能是静态 Pod，因此我们应该首先进行转换。
	pod, ok := m.podManager.GetPodByUID(uid)
	if !ok {
		klog.V(4).InfoS("Pod 已被删除，无需进行调和", "podUID", string(uid))
		return false
	}
	// 如果 Pod 是静态 Pod，我们应该检查其镜像 Pod，因为只有镜像 Pod 中的状态对我们有意义。
	if kubetypes.IsStaticPod(pod) {
		mirrorPod, ok := m.podManager.GetMirrorPodByPod(pod)
		if !ok {
			klog.V(4).InfoS("静态 Pod 没有相应的镜像 Pod，无需进行调和", "pod", klog.KObj(pod))
			return false
		}
		pod = mirrorPod
	}

	podStatus := pod.Status.DeepCopy()
	normalizeStatus(pod, podStatus)

	if isPodStatusByKubeletEqual(podStatus, &status) {
		// 如果源状态与缓存状态相同，则不需要调和。直接返回。
		return false
	}
	klog.V(3).InfoS("Pod 状态与缓存状态不一致，应触发调和",
		"pod", klog.KObj(pod),
		"statusDiff", cmp.Diff(podStatus, &status))

	return true
}
```

###### normalizeStatus

```go
// normalizeStatus 将 podStatus 中的纳秒精度时间戳归一化为秒精度（RFC3339）时间戳。在将 podStatus 与 apiserver 返回的状态进行比较之前，必须执行此操作，因为 apiserver 不支持 RFC339NANO。
// 相关问题 #15262/PR #15263 将 apiserver 移至 RFC339NANO 已关闭。
func normalizeStatus(pod *v1.Pod, status *v1.PodStatus) *v1.PodStatus {
	bytesPerStatus := kubecontainer.MaxPodTerminationMessageLogLength
	if containers := len(pod.Spec.Containers) + len(pod.Spec.InitContainers); containers > 0 {
		bytesPerStatus = bytesPerStatus / containers
	}
	normalizeTimeStamp := func(t *metav1.Time) {
		*t = t.Rfc3339Copy()
	}
	normalizeContainerState := func(c *v1.ContainerState) {
		if c.Running != nil {
			normalizeTimeStamp(&c.Running.StartedAt)
		}
		if c.Terminated != nil {
			normalizeTimeStamp(&c.Terminated.StartedAt)
			normalizeTimeStamp(&c.Terminated.FinishedAt)
			if len(c.Terminated.Message) > bytesPerStatus {
				c.Terminated.Message = c.Terminated.Message[:bytesPerStatus]
			}
		}
	}

	if status.StartTime != nil {
		normalizeTimeStamp(status.StartTime)
	}
	for i := range status.Conditions {
		condition := &status.Conditions[i]
		normalizeTimeStamp(&condition.LastProbeTime)
		normalizeTimeStamp(&condition.LastTransitionTime)
	}

	// 更新容器状态
	for i := range status.ContainerStatuses {
		cstatus := &status.ContainerStatuses[i]
		normalizeContainerState(&cstatus.State)
		normalizeContainerState(&cstatus.LastTerminationState)
	}
	// 对容器状态进行排序，以确保顺序不会影响比较结果
	sort.Sort(kubetypes.SortedContainerStatuses(status.ContainerStatuses))

	// 更新初始容器状态
	for i := range status.InitContainerStatuses {
		cstatus := &status.InitContainerStatuses[i]
		normalizeContainerState(&cstatus.State)
		normalizeContainerState(&cstatus.LastTerminationState)
	}
	// 对初始容器状态进行排序，以确保顺序不会影响比较结果
	sort.Sort(kubetypes.SortedContainerStatuses(status.InitContainerStatuses))

	return status
}
```

###### isPodStatusByKubeletEqual

```go
// isPodStatusByKubeletEqual 检查状态是否匹配，排除了 “v1.KubeletManagedCondition”、“v1.PodScheduled”、
// “v1.PodInitialized” 和 “v1.ContainersReady” 条件，因为这些条件由 kubelet 管理。
func isPodStatusByKubeletEqual(status1, status2 *v1.PodStatus) bool {
	return apiequality.Semantic.DeepEqual(
		podutil.FilterOutConditionsByType(status1, kubetypes.PodConditionByKubelet),
		podutil.FilterOutConditionsByType(status2, kubetypes.PodConditionByKubelet),
	)
}
```

### SetPodStatus

```go
func (m *manager) SetPodStatus(pod *v1.Pod, status v1.PodStatus) {
	m.podStatusesLock.Lock() // 加锁，保证线程安全
	defer m.podStatusesLock.Unlock() // 解锁，延迟执行

	// 确保缓存的是深拷贝
	status = *status.DeepCopy()

	// 如果设置了删除时间戳，则强制进行状态更新。这是必要的，因为如果 Pod 处于非运行状态，Pod worker 仍然需要触发更新和/或删除。
	m.updateStatusInternal(pod, status, pod.DeletionTimestamp != nil, false)
}

```

#### updateStatusInternal

```go
// updateStatusInternal 更新内部状态缓存，并在必要时将更新排入 API 服务器的队列。
// 这个方法不是线程安全的，必须在已加锁的函数中调用。
func (m *manager) updateStatusInternal(pod *v1.Pod, status v1.PodStatus, forceUpdate, podIsFinished bool) {
	var oldStatus v1.PodStatus
	cachedStatus, isCached := m.podStatuses[pod.UID] // 检查是否有缓存的状态
	if isCached {
		oldStatus = cachedStatus.status
		// TODO: Also assign terminal phase to static pods.
		if !kubetypes.IsStaticPod(pod) { // 检查是否为静态 Pod
			if cachedStatus.podIsFinished && !podIsFinished {
				klog.InfoS("Got unexpected podIsFinished=false, while podIsFinished=true in status cache, programmer error.", "pod", klog.KObj(pod))
				podIsFinished = true
			}
		}
	} else if mirrorPod, ok := m.podManager.GetMirrorPodByPod(pod); ok { // 检查是否有镜像 Pod
		oldStatus = mirrorPod.Status
	} else {
		oldStatus = pod.Status
	}

	// 检查容器的非法状态转换
	if err := checkContainerStateTransition(oldStatus.ContainerStatuses, status.ContainerStatuses, pod.Spec.RestartPolicy); err != nil {
		klog.ErrorS(err, "Status update on pod aborted", "pod", klog.KObj(pod))
		return
	}
	if err := checkContainerStateTransition(oldStatus.InitContainerStatuses, status.InitContainerStatuses, pod.Spec.RestartPolicy); err != nil {
		klog.ErrorS(err, "Status update on pod aborted", "pod", klog.KObj(pod))
		return
	}

	// 设置 ContainersReadyCondition 的 LastTransitionTime
	updateLastTransitionTime(&status, &oldStatus, v1.ContainersReady)

	// 设置 ReadyCondition 的 LastTransitionTime
	updateLastTransitionTime(&status, &oldStatus, v1.PodReady)

	// 设置 InitializedCondition 的 LastTransitionTime
	updateLastTransitionTime(&status, &oldStatus, v1.PodInitialized)

	// 设置 PodReadyToStartContainersCondition 的 LastTransitionTime
	updateLastTransitionTime(&status, &oldStatus, kubetypes.PodReadyToStartContainers)

	// 设置 PodScheduledCondition 的 LastTransitionTime
	updateLastTransitionTime(&status, &oldStatus, v1.PodScheduled)

	if utilfeature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
		// 设置 DisruptionTarget 的 LastTransitionTime
		updateLastTransitionTime(&status, &oldStatus, v1.DisruptionTarget)
	}

	// 确保启动时间不会在更新过程中发生变化
	if oldStatus.StartTime != nil && !oldStatus.StartTime.IsZero() {
		status.StartTime = oldStatus.StartTime
	} else if status.StartTime.IsZero() {
		// 如果状态中没有启动时间，我们需要设置一个初始时间
		now := metav1.Now()
		status.StartTime = &now
	}

	normalizeStatus(pod, &status) // 规范化状态

	// 如果启用了更详细的容器终止状态日志记录，以帮助调试生产竞争（通常不需要）。
	if klogV := klog.V(5); klogV.Enabled() {
		var containers []string
		for _, s := range append(append([]v1.ContainerStatus(nil), status.InitContainerStatuses...), status.ContainerStatuses...) {
			var current, previous string
			switch {
			case s.State.Running != nil:
				current = "running"
			case s.State.Waiting != nil:
				current = "waiting"
			case s.State.Terminated != nil:
				current = fmt.Sprintf("terminated=%d", s.State.Terminated.ExitCode)
			default:
				current = "unknown"
			}
			switch {
			case s.LastTerminationState.Running != nil:
				previous = "running"
			case s.LastTerminationState.Waiting != nil:
				previous = "waiting"
			case s.LastTerminationState.Terminated != nil:
				previous = fmt.Sprintf("terminated=%d", s.LastTerminationState.Terminated.ExitCode)
			default:
				previous = "<none>"
			}
			containers = append(containers, fmt.Sprintf("(%s state=%s previous=%s)", s.Name, current, previous))
		}
		sort.Strings(containers)
		klogV.InfoS("updateStatusInternal", "version", cachedStatus.version+1, "podIsFinished", podIsFinished, "pod", klog.KObj(pod), "podUID", pod.UID, "containers", strings.Join(containers, " "))
	}

	// 目的是防止并发更新导致 Pod 的状态互相覆盖，以确保 Pod 的阶段单调递增。
	if isCached && isPodStatusByKubeletEqual(&cachedStatus.status, &status) && !forceUpdate {
		klog.V(3).InfoS("Ignoring same status for pod", "pod", klog.KObj(pod), "status", status)
		return
	}

	newStatus := versionedPodStatus{
		status:        status,
		version:       cachedStatus.version + 1,
		podName:       pod.Name,
		podNamespace:  pod.Namespace,
		podIsFinished: podIsFinished,
	}

	// 在我们更新 API 服务器之前可能会生成多个状态更新，因此我们跟踪从第一个状态更新开始到将其提交给 API 的时间。
	if cachedStatus.at.IsZero() {
		newStatus.at = time.Now()
	} else {
		newStatus.at = cachedStatus.at
	}

	m.podStatuses[pod.UID] = newStatus

	select {
	case m.podStatusChannel <- struct{}{}:
	default:
		// 已经有一个待处理的状态更新
	}
}
```

#### checkContainerStateTransition

```go
// 检查容器的状态转换是否合法，禁止从终止状态转换为非终止状态，这是非法的，表明 kubelet 中存在逻辑错误。
func checkContainerStateTransition(oldStatuses, newStatuses []v1.ContainerStatus, restartPolicy v1.RestartPolicy) error {
	// 如果应始终重启，则容器允许离开终止状态
	if restartPolicy == v1.RestartPolicyAlways {
		return nil
	}
	for _, oldStatus := range oldStatuses {
		// 跳过未终止的容器
		if oldStatus.State.Terminated == nil {
			continue
		}
		// 跳过失败但允许重新启动的容器
		if oldStatus.State.Terminated.ExitCode != 0 && restartPolicy == v1.RestartPolicyOnFailure {
			continue
		}
		for _, newStatus := range newStatuses {
			if oldStatus.Name == newStatus.Name && newStatus.State.Terminated == nil {
				return fmt.Errorf("terminated container %v attempted illegal transition to non-terminated state", newStatus.Name)
			}
		}
	}
	return nil
}
```

##### updateLastTransitionTime

```go
// 更新 Pod 条件的 LastTransitionTime。
func updateLastTransitionTime(status, oldStatus *v1.PodStatus, conditionType v1.PodConditionType) {
	_, condition := podutil.GetPodCondition(status, conditionType)
	if condition == nil {
		return
	}
	// 需要设置 LastTransitionTime。
	lastTransitionTime := metav1.Now()
	_, oldCondition := podutil.GetPodCondition(oldStatus, conditionType)
	if oldCondition != nil && condition.Status == oldCondition.Status {
		lastTransitionTime = oldCondition.LastTransitionTime
	}
	condition.LastTransitionTime = lastTransitionTime
}

```

### SetContainerReadiness

```go
func (m *manager) SetContainerReadiness(podUID types.UID, containerID kubecontainer.ContainerID, ready bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	pod, ok := m.podManager.GetPodByUID(podUID)
	if !ok {
		klog.V(4).InfoS("Pod has been deleted, no need to update readiness", "podUID", string(podUID))
		return
	}

	oldStatus, found := m.podStatuses[pod.UID]
	if !found {
		klog.InfoS("Container readiness changed before pod has synced",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// 找到要更新的容器。
	containerStatus, _, ok := findContainerStatus(&oldStatus.status, containerID.String())
	if !ok {
		klog.InfoS("Container readiness changed for unknown container",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	if containerStatus.Ready == ready {
		klog.V(4).InfoS("Container readiness unchanged",
			"ready", ready,
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// 确保我们不更新缓存的版本。
	status := *oldStatus.status.DeepCopy()
	containerStatus, _, _ = findContainerStatus(&status, containerID.String())
	containerStatus.Ready = ready

	// updateConditionFunc 更新对应类型的条件
	updateConditionFunc := func(conditionType v1.PodConditionType, condition v1.PodCondition) {
		conditionIndex := -1
		for i, condition := range status.Conditions {
			if condition.Type == conditionType {
				conditionIndex = i
				break
			}
		}
		if conditionIndex == -1 {
			// 没有找到条件，添加新的条件
			if condition.Status == v1.ConditionTrue {
				condition.LastTransitionTime = metav1.Now()
			}
			status.Conditions = append(status.Conditions, condition)
		} else {
			// 更新条件
			oldCondition := status.Conditions[conditionIndex]
			if oldCondition.Status != condition.Status {
				condition.LastTransitionTime = metav1.Now()
			} else {
				condition.LastTransitionTime = oldCondition.LastTransitionTime
			}
			status.Conditions[conditionIndex] = condition
		}
	}

	// 更新 Pod 的 Ready 条件
	updateConditionFunc(v1.PodReady, v1.PodCondition{
		Type:               v1.PodReady,
		Status:             v1.ConditionTrue,
		LastProbeTime:      metav1.Now(),
		LastTransitionTime: metav1.Now(),
	})

	newStatus := versionedPodStatus{
		status:        status,
		version:       oldStatus.version + 1,
		podName:       pod.Name,
		podNamespace:  pod.Namespace,
		podIsFinished: oldStatus.podIsFinished,
		at:            oldStatus.at,
	}

	m.podStatuses[pod.UID] = newStatus

	select {
	case m.podStatusChannel <- struct{}{}:
	default:
		// 已经有一个待处理的状态更新
	}
}
```

#### findContainerStatus

```go
// findContainerStatus 在给定的 PodStatus 中查找指定容器 ID 的状态。
func findContainerStatus(status *v1.PodStatus, containerID string) (*v1.ContainerStatus, int, bool) {
	for i, cs := range status.ContainerStatuses {
		if cs.ContainerID == containerID {
			return &status.ContainerStatuses[i], i, true
		}
	}
	for i, cs := range status.InitContainerStatuses {
		if cs.ContainerID == containerID {
			return &status.InitContainerStatuses[i], i, true
		}
	}
	return nil, -1, false
}
```

### SetContainerStartup

```go
// SetContainerStartup 根据podUID和containerID设置容器的启动状态
func (m *manager) SetContainerStartup(podUID types.UID, containerID kubecontainer.ContainerID, started bool) {
	// 锁住podStatusesLock，以便在修改pod状态时保持同步
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	// 通过podUID从podManager中获取对应的pod对象
	pod, ok := m.podManager.GetPodByUID(podUID)
	if !ok {
		// 如果无法获取到pod对象，说明该pod已被删除，不需要更新启动状态
		klog.V(4).InfoS("Pod has been deleted, no need to update startup", "podUID", string(podUID))
		return
	}

	// 从podStatuses中获取pod的旧状态
	oldStatus, found := m.podStatuses[pod.UID]
	if !found {
		// 如果找不到旧状态，说明在同步pod之前容器的启动状态发生了变化
		klog.InfoS("Container startup changed before pod has synced",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// 找到需要更新的容器
	containerStatus, _, ok := findContainerStatus(&oldStatus.status, containerID.String())
	if !ok {
		// 如果找不到需要更新的容器，说明容器的启动状态发生了变化但容器ID未知
		klog.InfoS("Container startup changed for unknown container",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	if containerStatus.Started != nil && *containerStatus.Started == started {
		// 如果容器的启动状态未发生变化，则不进行更新
		klog.V(4).InfoS("Container startup unchanged",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// 确保更新的是副本而不是缓存版本
	status := *oldStatus.status.DeepCopy()
	containerStatus, _, _ = findContainerStatus(&status, containerID.String())
	containerStatus.Started = &started

	// 更新pod的状态
	m.updateStatusInternal(pod, status, false, false)
}
```

### TerminatePod

```go
// TerminatePod 确保在pod生命周期结束时容器的状态被正确设置为默认状态
func (m *manager) TerminatePod(pod *v1.Pod) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	// 确保所有容器都具有已终止的状态，因为我们不知道容器是否成功，所以总是报告错误
	oldStatus := &pod.Status
	cachedStatus, isCached := m.podStatuses[pod.UID]
	if isCached {
		oldStatus = &cachedStatus.status
	}
	status := *oldStatus.DeepCopy()

	// 一旦pod初始化完成，任何缺失的状态都被视为失败
	if hasPodInitialized(pod) {
		for i := range status.ContainerStatuses {
			if status.ContainerStatuses[i].State.Terminated != nil {
				continue
			}
			status.ContainerStatuses[i].State = v1.ContainerState{
				Terminated: &v1.ContainerStateTerminated{
					Reason:   "ContainerStatusUnknown",
					Message:  "The container could not be located when the pod was terminated",
					ExitCode: 137,
				},
			}
		}
	}

	// 除了没有容器启动证据的最后一个init容器外，其他的都标记为失败容器
	for i := range initializedContainers(status.InitContainerStatuses) {
		if status.InitContainerStatuses[i].State.Terminated != nil {
			continue
		}
		status.InitContainerStatuses[i].State = v1.ContainerState{
			Terminated: &v1.ContainerStateTerminated{
				Reason:   "ContainerStatusUnknown",
				Message:  "The container could not be located when the pod was terminated",
				ExitCode: 137,
			},
		}
	}

	// 确保所有pod都过渡到终端阶段（Failed或Succeeded）后再进行删除
	if !kubetypes.IsStaticPod(pod) {
		switch status.Phase {
		case v1.PodSucceeded, v1.PodFailed:
			// 无需操作，已经是终端状态
		case v1.PodPending, v1.PodRunning:
			if status.Phase == v1.PodRunning && isCached {
				klog.InfoS("Terminal running pod should have already been marked as failed, programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
			}
			klog.V(3).InfoS("Marking terminal pod as failed", "oldPhase", status.Phase, "pod", klog.KObj(pod), "podUID", pod.UID)
			status.Phase = v1.PodFailed
		default:
			klog.ErrorS(fmt.Errorf("unknown phase: %v", status.Phase), "Unknown phase, programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
			status.Phase = v1.PodFailed
		}
	}

	klog.V(5).InfoS("TerminatePod calling updateStatusInternal", "pod", klog.KObj(pod), "podUID", pod.UID)
	// 更新pod的状态
	m.updateStatusInternal(pod, status, true, true)
}
```

### RemoveOrphanedStatuses

```go
// RemoveOrphanedStatuses 从状态映射中移除孤立的pod状态
func (m *manager) RemoveOrphanedStatuses(podUIDs map[types.UID]bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	for key := range m.podStatuses {
		if _, ok := podUIDs[key]; !ok {
			// 从状态映射中移除不在给定podUIDs中的pod状态
			klog.V(5).InfoS("Removing pod from status map.", "podUID", key)
			delete(m.podStatuses, key)
			if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
				// 如果启用了InPlacePodVerticalScaling特性，还需从状态中删除
				m.state.Delete(string(key), "")
			}
		}
	}
}
```

### GetContainerResourceAllocation

```go
// GetContainerResourceAllocation 返回最近的已检查点的AllocatedResources值
// 如果检查点管理器未初始化，则返回nil和false
func (m *manager) GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool) {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()
	// 获取pod的容器资源分配信息
	return m.state.GetContainerResourceAllocation(podUID, containerName)
}
```

### GetPodResizeStatus

```go
// GetPodResizeStatus 返回最近的已检查点的ResizeStatus值
// 如果检查点管理器未初始化，则返回nil和false
func (m *manager) GetPodResizeStatus(podUID string) (v1.PodResizeStatus, bool) {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()
	// 获取pod的调整大小状态信息
	return m.state.GetPodResizeStatus(podUID)
}
```

### SetPodAllocation

```go
// SetPodAllocation 检查点pod容器分配的资源
func (m *manager) SetPodAllocation(pod *v1.Pod) error {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()

	// 遍历pod的容器列表
	for _, container := range pod.Spec.Containers {
		var alloc v1.ResourceList
		if container.Resources.Requests != nil {
			// 如果容器定义了资源请求，则将其复制给alloc
			alloc = container.Resources.Requests.DeepCopy()
		}
		// 将容器的资源分配信息设置到状态中
		if err := m.state.SetContainerResourceAllocation(string(pod.UID), container.Name, alloc); err != nil {
			return err
		}
	}

	return nil
}
```

### SetPodResizeStatus

```go
// SetPodResizeStatus 检查点pod的最后一次调整大小决策
func (m *manager) SetPodResizeStatus(podUID types.UID, resizeStatus v1.PodResizeStatus) error {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()

	// 将pod的调整大小状态信息设置到状态中
	return m.state.SetPodResizeStatus(string(podUID), resizeStatus)
}
```

### GetPodStatus

```go
func (m *manager) GetPodStatus(uid types.UID) (v1.PodStatus, bool) {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()

	// 获取pod的状态信息
	status, ok := m.podStatuses[types.UID(m.podManager.TranslatePodUID(uid))]
	return status.status, ok
}
```

