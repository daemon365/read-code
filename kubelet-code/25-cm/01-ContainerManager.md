## 简介

Kubelet 是 Kubernetes 中的一个核心组件，负责在每个节点上管理容器。容器管理器是 Kubelet 的一部分，用于管理运行在节点上的容器。kubelet container manager 提供了对容器的生命周期管理、容器的资源配额管理、容器的安全性配置等功能。

kubelet container manager 可以与多个容器运行时（如 Docker、CRI-O、containerd 等）一起使用，并通过容器运行时提供的 API 操作容器。它还可以使用 cgroup 控制组，来限制容器的资源使用，包括 CPU、内存、磁盘 IO、网络带宽等。

除此之外，kubelet container manager 还支持管理容器的网络和存储，例如为每个容器分配 IP 地址、创建和管理容器的卷和数据卷等。同时，它还支持容器的安全性配置，例如为容器配置 Linux 安全模块 (LSM)、AppArmor、Seccomp 等。

## ContainerManager

```GO
// ContainerManager 管理运行在一台机器上的容器。
type ContainerManager interface {
	// Start 运行容器管理器的日常工作。
	// - 确保 Docker 守护程序在一个容器中运行。
	// - 创建系统容器，用于运行所有未容器化的进程。
	Start(*v1.Node, ActivePodsFunc, config.SourcesReady, status.PodStatusProvider, internalapi.RuntimeService, bool) error

	// SystemCgroupsLimit 返回机器上分配给系统 cgroup 的资源。
	// 这些 cgroup 包括系统和 Kubernetes 服务。
	SystemCgroupsLimit() v1.ResourceList

	// GetNodeConfig 返回容器管理器正在使用的 NodeConfig。
	GetNodeConfig() NodeConfig

	// Status 返回内部状态。
	Status() Status

	// NewPodContainerManager 是一个工厂方法，返回一个 podContainerManager 对象。
	// 如果 qos cgroup 层次结构未启用，则返回一个空实现。
	NewPodContainerManager() PodContainerManager

	// GetMountedSubsystems 返回节点上挂载的 cgroup 子系统。
	GetMountedSubsystems() *CgroupSubsystems

	// GetQOSContainersInfo 返回顶层 QoS 容器的名称。
	GetQOSContainersInfo() QOSContainersInfo

	// GetNodeAllocatableReservation 返回必须从调度中保留的计算资源量。
	GetNodeAllocatableReservation() v1.ResourceList

	// GetCapacity 返回容器管理器跟踪的在节点上可用的计算资源量。
	GetCapacity(localStorageCapacityIsolation bool) v1.ResourceList

	// GetDevicePluginResourceCapacity 返回节点容量（总设备插件资源量），
	// 节点可分配资源（设备插件报告的总健康资源量），
	// 以及先前在节点上注册的非活动设备插件资源。
	GetDevicePluginResourceCapacity() (v1.ResourceList, v1.ResourceList, []string)

	// UpdateQOSCgroups 以线程安全的方式执行 housekeeping 更新，
	// 确保顶层 QoS 容器处于其所需状态。
	UpdateQOSCgroups() error

	// GetResources 返回填充了容器所需的设备、挂载和环境字段的 RunContainerOptions。
	GetResources(pod *v1.Pod, container *v1.Container) (*kubecontainer.RunContainerOptions, error)

	// UpdatePluginResources 调用设备插件处理程序的分配方法，以处理对设备插件资源的潜在请求，并在必要时返回错误。
	// 否则，如果成功，它会更新 nodeInfo 中的可分配资源，
	// 以确保至少与 pod 的所有已注册设备插件资源的请求容量相等。
	UpdatePluginResources(*schedulerframework.NodeInfo, *lifecycle.PodAdmitAttributes) error

	InternalContainerLifecycle() InternalContainerLifecycle

	// GetPodCgroupRoot 返回包含所有 pods 的 cgroup。
	GetPodCgroupRoot() string

	// GetPluginRegistrationHandler 返回一个插件注册处理程序。
	// 插件观察者的处理程序允许有一个单独的模块处理注册。
	GetPluginRegistrationHandler() cache.PluginHandler

	// ShouldResetExtendedResourceCapacity 返回是否应将扩展资源归零，
	// 因为节点重新创建。
	ShouldResetExtendedResourceCapacity() bool

	// GetAllocateResourcesPodAdmitHandler 返回一个负责分配 pod 资源的 PodAdmitHandler 实例。
	GetAllocateResourcesPodAdmitHandler() lifecycle.PodAdmitHandler

	// GetNodeAllocatableAbsolute 返回 Node Allocatable 的绝对值，主要用于强制执行。
	GetNodeAllocatableAbsolute() v1.ResourceList

	// PrepareDynamicResource 准备动态的 pod 资源。
	PrepareDynamicResources(*v1.Pod) error

	// UnrepareDynamicResources 取消准备动态的 pod 资源。
	UnprepareDynamicResources(*v1.Pod) error

	// PodMightNeedToUnprepareResources 如果具有给定 UID 的 pod 可能需要取消准备资源，则返回 true。
	PodMightNeedToUnprepareResources(UID types.UID) bool

	// 实现 PodResourcesProvider API
	podresources.CPUsProvider
	podresources.DevicesProvider
	podresources.MemoryProvider
	podresources.DynamicResourcesProvider
}
```

### ActivePodsFunc

```GO
// ActivePodsFunc 是一个函数类型，用于返回一个包含 *v1.Pod 类型指针的切片。
type ActivePodsFunc func() []*v1.Pod
```

### NodeConfig

```GO
// NodeConfig 是节点的配置信息。
type NodeConfig struct {
	RuntimeCgroupsName    string
	SystemCgroupsName     string
	KubeletCgroupsName    string
	KubeletOOMScoreAdj    int32
	ContainerRuntime      string
	CgroupsPerQOS         bool
	CgroupRoot            string
	CgroupDriver          string
	KubeletRootDir        string
	ProtectKernelDefaults bool
	NodeAllocatableConfig
	QOSReserved                              map[v1.ResourceName]int64
	CPUManagerPolicy                         string
	CPUManagerPolicyOptions                  map[string]string
	TopologyManagerScope                     string
	CPUManagerReconcilePeriod                time.Duration
	ExperimentalMemoryManagerPolicy          string
	ExperimentalMemoryManagerReservedMemory  []kubeletconfig.MemoryReservation
	PodPidsLimit                             int64
	EnforceCPULimits                         bool
	CPUCFSQuotaPeriod                        time.Duration
	TopologyManagerPolicy                    string
	ExperimentalTopologyManagerPolicyOptions map[string]string
}
```

#### NodeAllocatableConfig

```GO
// NodeAllocatableConfig 是节点可分配资源的配置。
type NodeAllocatableConfig struct {
	KubeReservedCgroupName   string
	SystemReservedCgroupName string
	ReservedSystemCPUs       cpuset.CPUSet
	EnforceNodeAllocatable   sets.String
	KubeReserved             v1.ResourceList
	SystemReserved           v1.ResourceList
	HardEvictionThresholds   []evictionapi.Threshold
}
```

### Status

```GO
// Status 是状态信息。
type Status struct {
	// 未满足的任何软要求。
	SoftRequirements error
}
```

## containerManagerImpl

```GO
// containerManagerImpl 实现了 ContainerManager 接口。
type containerManagerImpl struct {
	sync.RWMutex
	cadvisorInterface cadvisor.Interface
	mountUtil         mount.Interface
	NodeConfig
	status             Status
	systemContainers   []*systemContainer
	periodicTasks      []func()
	subsystems         *CgroupSubsystems
	nodeInfo           *v1.Node
	cgroupManager      CgroupManager
	capacity           v1.ResourceList
	internalCapacity   v1.ResourceList
	cgroupRoot         CgroupName
	recorder           record.EventRecorder
	qosContainerManager QOSContainerManager
	deviceManager      devicemanager.Manager
	cpuManager         cpumanager.Manager
	memoryManager      memorymanager.Manager
	topologyManager    topologymanager.Manager
	draManager         dra.Manager
}

// features 定义了一些特性。
type features struct {
	cpuHardcapping bool
}

var _ ContainerManager = &containerManagerImpl{}

// validateSystemRequirements 检查所需的 cgroups subsystem 是否已挂载。
// 目前只需要 'cpu' 和 'memory'。
// cpu 的配额是一个软要求。
func validateSystemRequirements(mountUtil mount.Interface) (features, error) {
	const (
		cgroupMountType = "cgroup"
		localErr        = "系统验证失败"
	)
	var (
		cpuMountPoint string
		f             features
	)
	mountPoints, err := mountUtil.List()
	if err != nil {
		return f, fmt.Errorf("%s - %v", localErr, err)
	}

	if cgroups.IsCgroup2UnifiedMode() {
		f.cpuHardcapping = true
		return f, nil
	}

	expectedCgroups := sets.NewString("cpu", "cpuacct", "cpuset", "memory")
	for _, mountPoint := range mountPoints {
		if mountPoint.Type == cgroupMountType {
			for _, opt := range mountPoint.Opts {
				if expectedCgroups.Has(opt) {
					expectedCgroups.Delete(opt)
				}
				if opt == "cpu" {
					cpuMountPoint = mountPoint.Path
				}
			}
		}
	}

	if expectedCgroups.Len() > 0 {
		return f, fmt.Errorf("%s - 以下 cgroup subsystem 未挂载: %v", localErr, expectedCgroups.List())
	}

	// 检查 cpu 配额是否可用。
	// CPU cgroup 是必需的，所以在这个时候它应该已经挂载。
	periodExists, err := utilpath.Exists(utilpath.CheckFollowSymlink, path.Join(cpuMountPoint, "cpu.cfs_period_us"))
	if err != nil {
		klog.ErrorS(err, "无法检测到 CPU cgroup 的 cpu.cfs_period_us 是否可用")
	}
	quotaExists, err := utilpath.Exists(utilpath.CheckFollowSymlink, path.Join(cpuMountPoint, "cpu.cfs_quota_us"))
	if err != nil {
		klog.ErrorS(err, "无法检测到 CPU cgroup 的 cpu.cfs_quota_us 是否可用")
	}
	if quotaExists && periodExists {
		f.cpuHardcapping = true
	}
	return f, nil
}
```

## containerManagerImpl

```GO
// containerManagerImpl 实现了 ContainerManager 接口。
type containerManagerImpl struct {
	sync.RWMutex
	cadvisorInterface cadvisor.Interface
	mountUtil         mount.Interface
	NodeConfig
	status             Status
	systemContainers   []*systemContainer
	periodicTasks      []func()
	subsystems         *CgroupSubsystems
	nodeInfo           *v1.Node
	cgroupManager      CgroupManager
	capacity           v1.ResourceList
	internalCapacity   v1.ResourceList
	cgroupRoot         CgroupName
	recorder           record.EventRecorder
	qosContainerManager QOSContainerManager
	deviceManager      devicemanager.Manager
	cpuManager         cpumanager.Manager
	memoryManager      memorymanager.Manager
	topologyManager    topologymanager.Manager
	draManager         dra.Manager
}

// features 定义了一些特性。
type features struct {
	cpuHardcapping bool
}

var _ ContainerManager = &containerManagerImpl{}
```

### NewContainerManager

```GO
// NewContainerManager 是一个工厂方法，返回一个 ContainerManager 对象。
// 如果 qosCgroups 已启用，则返回通用的 pod 容器管理器，
// 否则返回一个空操作管理器，实际上不执行任何操作。
func NewContainerManager(mountUtil mount.Interface, cadvisorInterface cadvisor.Interface, nodeConfig NodeConfig, failSwapOn bool, recorder record.EventRecorder, kubeClient clientset.Interface) (ContainerManager, error) {
	// 获取挂载的 cgroup subsystem 信息
	subsystems, err := GetCgroupSubsystems()
	if err != nil {
		return nil, fmt.Errorf("failed to get mounted cgroup subsystems: %v", err)
	}

	if failSwapOn {
		// 检查是否启用了 swap 分区，Kubelet 不支持在启用了 swap 的情况下运行
		swapFile := "/proc/swaps"
		swapData, err := os.ReadFile(swapFile)
		if err != nil {
			if os.IsNotExist(err) {
				klog.InfoS("File does not exist, assuming that swap is disabled", "path", swapFile)
			} else {
				return nil, err
			}
		} else {
			swapData = bytes.TrimSpace(swapData) // 去除多余的换行符
			swapLines := strings.Split(string(swapData), "\n")

			// 如果 /proc/swaps 中有多于一行（表头），则表示启用了 swap，除非设置了 --fail-swap-on 标志为 false，否则报错
			if len(swapLines) > 1 {
				return nil, fmt.Errorf("running with swap on is not supported, please disable swap! or set --fail-swap-on flag to false. /proc/swaps contained: %v", swapLines)
			}
		}
	}

	var internalCapacity = v1.ResourceList{}
	// 在这里，在逻辑上初始化 cAdvisor 之前，调用 `MachineInfo` 是安全的，因为 machine info 是作为 cAdvisor 对象创建的一部分进行计算和缓存的。
	// 但是 `RootFsInfo` 和 `ImagesFsInfo` 在此时不可用，因此它们将在管理器启动时稍后调用。
	machineInfo, err := cadvisorInterface.MachineInfo()
	if err != nil {
		return nil, err
	}
	// 从 machineInfo 中获取容量信息
	capacity := cadvisor.CapacityFromMachineInfo(machineInfo)
	for k, v := range capacity {
		internalCapacity[k] = v
	}
	// 获取 PID 限制信息
	pidlimits, err := pidlimit.Stats()
	if err == nil && pidlimits != nil && pidlimits.MaxPID != nil {
		internalCapacity[pidlimit.PIDs] = *resource.NewQuantity(
			int64(*pidlimits.MaxPID),
			resource.DecimalSI)
	}

	// 将 CgroupRoot 从字符串（以 cgroupfs 路径格式）转换为内部的 CgroupName
	cgroupRoot := ParseCgroupfsToCgroupName(nodeConfig.CgroupRoot)
	// 创建 CgroupManager 对象
	cgroupManager := NewCgroupManager(subsystems, nodeConfig.CgroupDriver)
	// 检查 CgroupRoot 在节点上是否存在
	if nodeConfig.CgroupsPerQOS {
		// 当启用了 qosCgroups 时，默认为 /，但这里检查以防出现问题。
		if nodeConfig.CgroupRoot == "" {
			return nil, fmt.Errorf("invalid configuration: cgroups-per-qos was specified and cgroup-root was not specified. To enable the QoS cgroup hierarchy you need to specify a valid cgroup-root")
		}

		// 对每个子系统检查 cgroup root 是否存在
		// 注意，这里在执行检查时始终使用 cgroupfs 驱动程序，因为输入以该格式提供。
		// 这很重要，因为我们不希望进行任何名称转换。
		if err := cgroupManager.Validate(cgroupRoot); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		klog.InfoS("Container manager verified user specified cgroup-root exists", "cgroupRoot", cgroupRoot)
		// 将顶层 cgroup 包含在 cgroup-root 中，以强制分配到节点中
		// 这样，所有子模块都可以避免了解节点可分配的概念。
		cgroupRoot = NewCgroupName(cgroupRoot, defaultNodeAllocatableCgroupName)
	}
	klog.InfoS("Creating Container Manager object based on Node Config", "nodeConfig", nodeConfig)

	// 创建 QoSContainerManager 对象
	qosContainerManager, err := NewQOSContainerManager(subsystems, cgroupRoot, nodeConfig, cgroupManager)
	if err != nil {
		return nil, err
	}

	// 创建 containerManagerImpl 对象，并初始化其字段
	cm := &containerManagerImpl{
		cadvisorInterface:   cadvisorInterface,
		mountUtil:           mountUtil,
		NodeConfig:          nodeConfig,
		subsystems:          subsystems,
		cgroupManager:       cgroupManager,
		capacity:            capacity,
		internalCapacity:    internalCapacity,
		cgroupRoot:          cgroupRoot,
		recorder:            recorder,
		qosContainerManager: qosContainerManager,
	}

	// 创建 topologyManager 对象
	cm.topologyManager, err = topologymanager.NewManager(
		machineInfo.Topology,
		nodeConfig.TopologyManagerPolicy,
		nodeConfig.TopologyManagerScope,
		nodeConfig.ExperimentalTopologyManagerPolicyOptions,
	)

	if err != nil {
		return nil, err
	}

	klog.InfoS("Creating device plugin manager")
	// 创建 deviceManager 对象
	cm.deviceManager, err = devicemanager.NewManagerImpl(machineInfo.Topology, cm.topologyManager)
	if err != nil {
		return nil, err
	}
	cm.topologyManager.AddHintProvider(cm.deviceManager)

	// 初始化 DRA 管理器
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.DynamicResourceAllocation) {
		klog.InfoS("Creating Dynamic Resource Allocation (DRA) manager")
		cm.draManager, err = dra.NewManagerImpl(kubeClient, nodeConfig.KubeletRootDir)
		if err != nil {
			return nil, err
		}
	}

	// 初始化 CPU 管理器
	cm.cpuManager, err = cpumanager.NewManager(
		nodeConfig.CPUManagerPolicy,
		nodeConfig.CPUManagerPolicyOptions,
		nodeConfig.CPUManagerReconcilePeriod,
		machineInfo,
		nodeConfig.NodeAllocatableConfig.ReservedSystemCPUs,
		cm.GetNodeAllocatableReservation(),
		nodeConfig.KubeletRootDir,
		cm.topologyManager,
	)
	if err != nil {
		klog.ErrorS(err, "Failed to initialize cpu manager")
		return nil, err
	}
	cm.topologyManager.AddHintProvider(cm.cpuManager)

	// 如果启用了内存管理器，则初始化内存管理器
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.MemoryManager) {
		cm.memoryManager, err = memorymanager.NewManager(
			nodeConfig.ExperimentalMemoryManagerPolicy,
			machineInfo,
			cm.GetNodeAllocatableReservation(),
			nodeConfig.ExperimentalMemoryManagerReservedMemory,
			nodeConfig.KubeletRootDir,
			cm.topologyManager,
		)
		if err != nil {
			klog.ErrorS(err, "Failed to initialize memory manager")
			return nil, err
		}
		cm.topologyManager.AddHintProvider(cm.memoryManager)
	}

	return cm, nil
}
```

#### GetCgroupSubsystems

```GO
// GetCgroupSubsystems 返回已挂载的 cgroup subsystems 的信息
func GetCgroupSubsystems() (*CgroupSubsystems, error) {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		return getCgroupSubsystemsV2()
	}

	return getCgroupSubsystemsV1()
}
```

##### getCgroupSubsystemsV2

```GO
// getCgroupSubsystemsV2 返回启用的 cgroup v2 subsystems 的信息
func getCgroupSubsystemsV2() (*CgroupSubsystems, error) {
	// 获取所有启用的 cgroup subsystems
	controllers, err := libcontainercgroups.GetAllSubsystems()
	if err != nil {
		return nil, err
	}

	mounts := []libcontainercgroups.Mount{}
	mountPoints := make(map[string]string, len(controllers))
	for _, controller := range controllers {
		// 设置 mountPoints 的值为 cgroup 的根路径
		mountPoints[controller] = util.CgroupRoot
		m := libcontainercgroups.Mount{
			Mountpoint: util.CgroupRoot,
			Root:       util.CgroupRoot,
			Subsystems: []string{controller},
		}
		mounts = append(mounts, m)
	}

	return &CgroupSubsystems{
		Mounts:      mounts,
		MountPoints: mountPoints,
	}, nil
}
```

##### getCgroupSubsystemsV1

```GO
// getCgroupSubsystemsV1 返回已挂载的 cgroup v1 subsystems 的信息
func getCgroupSubsystemsV1() (*CgroupSubsystems, error) {
	// 获取所有 cgroup mounts
	allCgroups, err := libcontainercgroups.GetCgroupMounts(true)
	if err != nil {
		return &CgroupSubsystems{}, err
	}
	if len(allCgroups) == 0 {
		return &CgroupSubsystems{}, fmt.Errorf("failed to find cgroup mounts")
	}
	mountPoints := make(map[string]string, len(allCgroups))
	for _, mount := range allCgroups {
		// 以较短的路径选择 mount point
		for _, subsystem := range mount.Subsystems {
			previous := mountPoints[subsystem]
			if previous == "" || len(mount.Mountpoint) < len(previous) {
				mountPoints[subsystem] = mount.Mountpoint
			}
		}
	}
	return &CgroupSubsystems{
		Mounts:      allCgroups,
		MountPoints: mountPoints,
	}, nil
}
```

### Start

```GO
func (cm *containerManagerImpl) Start(node *v1.Node,
	activePods ActivePodsFunc,
	sourcesReady config.SourcesReady,
	podStatusProvider status.PodStatusProvider,
	runtimeService internalapi.RuntimeService,
	localStorageCapacityIsolation bool) error {
	ctx := context.Background()

	// 初始化 CPU 管理器
	containerMap := buildContainerMapFromRuntime(ctx, runtimeService)
	err := cm.cpuManager.Start(cpumanager.ActivePodsFunc(activePods), sourcesReady, podStatusProvider, runtimeService, containerMap)
	if err != nil {
		return fmt.Errorf("启动 CPU 管理器出错：%v", err)
	}

	// 初始化内存管理器
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.MemoryManager) {
		containerMap := buildContainerMapFromRuntime(ctx, runtimeService)
		err := cm.memoryManager.Start(memorymanager.ActivePodsFunc(activePods), sourcesReady, podStatusProvider, runtimeService, containerMap)
		if err != nil {
			return fmt.Errorf("启动内存管理器出错：%v", err)
		}
	}

	// 缓存节点信息，包括资源容量和可分配量
	cm.nodeInfo = node

	if localStorageCapacityIsolation {
		rootfs, err := cm.cadvisorInterface.RootFsInfo()
		if err != nil {
			return fmt.Errorf("获取 rootfs 信息失败：%v", err)
		}
		for rName, rCap := range cadvisor.EphemeralStorageCapacityFromFsInfo(rootfs) {
			cm.capacity[rName] = rCap
		}
	}

	// 确保节点可分配配置有效
	if err := cm.validateNodeAllocatable(); err != nil {
		return err
	}

	// 设置节点
	if err := cm.setupNode(activePods); err != nil {
		return err
	}

	// 如果没有 ensureStateFuncs，则不运行后台线程
	hasEnsureStateFuncs := false
	for _, cont := range cm.systemContainers {
		if cont.ensureStateFunc != nil {
			hasEnsureStateFuncs = true
			break
		}
	}
	if hasEnsureStateFuncs {
		// 每分钟运行 ensure state 函数
		go wait.Until(func() {
			for _, cont := range cm.systemContainers {
				if cont.ensureStateFunc != nil {
					if err := cont.ensureStateFunc(cont.manager); err != nil {
						klog.InfoS("无法确保状态", "容器名称", cont.name, "错误", err)
					}
				}
			}
		}, time.Minute, wait.NeverStop)

	}

	if len(cm.periodicTasks) > 0 {
		go wait.Until(func() {
			for _, task := range cm.periodicTasks {
				if task != nil {
					task()
				}
			}
		}, 5*time.Minute, wait.NeverStop)
	}

	// 启动设备管理器
	if err := cm.deviceManager.Start(devicemanager.ActivePodsFunc(activePods), sourcesReady); err != nil {
		return err
	}

	return nil
}
```

#### buildContainerMapFromRuntime

```GO
// 从运行时构建容器映射
func buildContainerMapFromRuntime(ctx context.Context, runtimeService internalapi.RuntimeService) containermap.ContainerMap {
	podSandboxMap := make(map[string]string)
	podSandboxList, _ := runtimeService.ListPodSandbox(ctx, nil)
	for _, p := range podSandboxList {
		podSandboxMap[p.Id] = p.Metadata.Uid
	}

	containerMap := containermap.NewContainerMap()
	containerList, _ := runtimeService.ListContainers(ctx, nil)
	for _, c := range containerList {
		if _, exists := podSandboxMap[c.PodSandboxId]; !exists {
			klog.InfoS("找不到容器的 PodSandbox", "PodSandboxId", c.PodSandboxId, "容器名称", c.Metadata.Name, "容器ID", c.Id)
			continue
		}
		containerMap.Add(podSandboxMap[c.PodSandboxId], c.Metadata.Name, c.Id)
	}

	return containerMap
}
```

#### validateNodeAllocatable

```GO
// validateNodeAllocatable 确保用户指定的节点可分配配置不超过节点容量
// 如果配置无效则返回错误，否则返回 nil
func (cm *containerManagerImpl) validateNodeAllocatable() error {
	var errors []string
	nar := cm.GetNodeAllocatableReservation()
	for k, v := range nar {
		value := cm.capacity[k].DeepCopy()
		value.Sub(v)

		if value.Sign() < 0 {
			errors = append(errors, fmt.Sprintf("资源 %q 的可分配量为 %v，容量为 %v", k, v, value))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("无效的节点可分配配置。%s", strings.Join(errors, " "))
	}
	return nil
}
```

#### setupNode

```GO
func (cm *containerManagerImpl) setupNode(activePods ActivePodsFunc) error {
	f, err := validateSystemRequirements(cm.mountUtil)
	if err != nil {
		return err
	}
	if !f.cpuHardcapping {
		cm.status.SoftRequirements = fmt.Errorf("不支持 CPU 硬限制")
	}
	b := KernelTunableModify
	if cm.GetNodeConfig().ProtectKernelDefaults {
		b = KernelTunableError
	}
	if err := setupKernelTunables(b); err != nil {
		return err
	}

	// 仅在指定 CgroupsPerQOS 标志为 true 时设置顶层 qos 容器
	if cm.NodeConfig.CgroupsPerQOS {
		if err := cm.createNodeAllocatableCgroups(); err != nil {
			return err
		}
		err = cm.qosContainerManager.Start(cm.GetNodeAllocatableAbsolute, activePods)
		if err != nil {
			return fmt.Errorf("初始化顶层 QOS 容器失败：%v", err)
		}
	}

	// 执行节点可分配的强制约束（如果需要）
	if err := cm.enforceNodeAllocatableCgroups(); err != nil {
		return err
	}

	systemContainers := []*systemContainer{}

	if cm.SystemCgroupsName != "" {
		if cm.SystemCgroupsName == "/" {
			return fmt.Errorf("系统容器不能为根（\"/\"）")
		}
		cont, err := newSystemCgroups(cm.SystemCgroupsName)
		if err != nil {
			return err
		}
		cont.ensureStateFunc = func(manager cgroups.Manager) error {
			return ensureSystemCgroups("/", manager)
		}
		systemContainers = append(systemContainers, cont)
	}

	if cm.KubeletCgroupsName != "" {
		cont, err := newSystemCgroups(cm.KubeletCgroupsName)
		if err != nil {
			return err
		}

		cont.ensureStateFunc = func(_ cgroups.Manager) error {
			return ensureProcessInContainerWithOOMScore(os.Getpid(), int(cm.KubeletOOMScoreAdj), cont.manager)
		}
		systemContainers = append(systemContainers, cont)
	} else {
		cm.periodicTasks = append(cm.periodicTasks, func() {
			if err := ensureProcessInContainerWithOOMScore(os.Getpid(), int(cm.KubeletOOMScoreAdj), nil); err != nil {
				klog.ErrorS(err, "确保进程在容器中具有 OOM 分数时失败")
				return
			}
			cont, err := getContainer(os.Getpid())
			if err != nil {
				klog.ErrorS(err, "查找 kubelet 的 cgroups 失败")
				return
			}
			cm.Lock()
			defer cm.Unlock()

			cm.KubeletCgroupsName = cont
		})
	}

	cm.systemContainers = systemContainers
	return nil
}
```

##### validateSystemRequirements

```GO
// validateSystemRequirements 检查所需的 cgroups subsystem 是否已挂载。
// 目前只需要 'cpu' 和 'memory'。
// cpu 的配额是一个软要求。
func validateSystemRequirements(mountUtil mount.Interface) (features, error) {
	const (
		cgroupMountType = "cgroup"
		localErr        = "系统验证失败"
	)
	var (
		cpuMountPoint string
		f             features
	)
	mountPoints, err := mountUtil.List()
	if err != nil {
		return f, fmt.Errorf("%s - %v", localErr, err)
	}

	if cgroups.IsCgroup2UnifiedMode() {
		f.cpuHardcapping = true
		return f, nil
	}

	expectedCgroups := sets.NewString("cpu", "cpuacct", "cpuset", "memory")
	for _, mountPoint := range mountPoints {
		if mountPoint.Type == cgroupMountType {
			for _, opt := range mountPoint.Opts {
				if expectedCgroups.Has(opt) {
					expectedCgroups.Delete(opt)
				}
				if opt == "cpu" {
					cpuMountPoint = mountPoint.Path
				}
			}
		}
	}

	if expectedCgroups.Len() > 0 {
		return f, fmt.Errorf("%s - 以下 cgroup subsystem 未挂载: %v", localErr, expectedCgroups.List())
	}

	// 检查 cpu 配额是否可用。
	// CPU cgroup 是必需的，所以在这个时候它应该已经挂载。
	periodExists, err := utilpath.Exists(utilpath.CheckFollowSymlink, path.Join(cpuMountPoint, "cpu.cfs_period_us"))
	if err != nil {
		klog.ErrorS(err, "无法检测到 CPU cgroup 的 cpu.cfs_period_us 是否可用")
	}
	quotaExists, err := utilpath.Exists(utilpath.CheckFollowSymlink, path.Join(cpuMountPoint, "cpu.cfs_quota_us"))
	if err != nil {
		klog.ErrorS(err, "无法检测到 CPU cgroup 的 cpu.cfs_quota_us 是否可用")
	}
	if quotaExists && periodExists {
		f.cpuHardcapping = true
	}
	return f, nil
}
```

#### ensureSystemCgroups

```GO
// 确保系统容器被创建，并将所有非内核线程和进程 1 移动到其中
//
// 保留内核线程在根 cgroup 的原因是我们不希望将这些线程的执行与尚未定义的 /system 配额绑定，以及创建优先级倒置。
func ensureSystemCgroups(rootCgroupPath string, manager cgroups.Manager) error {
	// 将非内核 PID 移动到系统容器
	// 仅保留最新尝试的错误。
	var finalErr error
	for i := 0; i <= 10; i++ {
		allPids, err := cmutil.GetPids(rootCgroupPath)
		if err != nil {
			finalErr = fmt.Errorf("获取根 cgroup 的 PID 列表失败：%v", err)
			continue
		}

		// 移除内核 PIDs 和其他受保护的 PIDs（pid 1，已在系统和 kubelet 容器中的 PIDs）
		pids := make([]int, 0, len(allPids))
		for _, pid := range allPids {
			if pid == 1 || isKernelPid(pid) {
				continue
			}

			pids = append(pids, pid)
		}

		// 检查是否已将所有非内核 PID 移动
		if len(pids) == 0 {
			return nil
		}

		klog.V(3).InfoS("移动非内核进程", "pids", pids)
		for _, pid := range pids {
			err := manager.Apply(pid)
			if err != nil {
				name := ""
				cgroups, err := manager.GetCgroups()
				if err == nil {
					name = cgroups.Name
				}

				finalErr = fmt.Errorf("将 PID %d 移动到系统容器 %q 失败：%v", pid, name, err)
			}
		}

	}

	return finalErr
}
```

#### SystemCgroupsLimit

```GO
func (cm *containerManagerImpl) SystemCgroupsLimit() v1.ResourceList {
    cpuLimit := int64(0)  // 初始化变量 cpuLimit 为0

    // 对所有外部容器的资源进行求和
    for _, cont := range cm.systemContainers {
        cpuLimit += cont.cpuMillicores
    }

    return v1.ResourceList{
        v1.ResourceCPU: *resource.NewMilliQuantity(
            cpuLimit,
            resource.DecimalSI),
    }
}
```

#### GetNodeConfig

```GO
func (cm *containerManagerImpl) GetNodeConfig() NodeConfig {
    cm.RLock()  // 获取读锁
    defer cm.RUnlock()  // 在函数返回前解锁
    return cm.NodeConfig  // 返回 NodeConfig
}
```

#### GetPodCgroupRoot

```GO
// GetPodCgroupRoot 返回包含所有 Pod 的 cgroup 的 cgroupfs 值。
func (cm *containerManagerImpl) GetPodCgroupRoot() string {
    return cm.cgroupManager.Name(cm.cgroupRoot)  // 返回 cgroupManager 根据 cgroupRoot 获取的名称
}
```

#### GetMountedSubsystems

```GO
func (cm *containerManagerImpl) GetMountedSubsystems() *CgroupSubsystems {
    return cm.subsystems  // 返回 subsystems
}
```

#### GetQOSContainersInfo

```GO
func (cm *containerManagerImpl) GetQOSContainersInfo() QOSContainersInfo {
    return cm.qosContainerManager.GetQOSContainersInfo()  // 返回 qosContainerManager 的 QOSContainersInfo
}
```

#### UpdateQOSCgroups

```GO
func (cm *containerManagerImpl) UpdateQOSCgroups() error {
    return cm.qosContainerManager.UpdateCgroups()  // 返回 qosContainerManager 的 UpdateCgroups 方法的结果
}
```

#### Status

```GO
func (cm *containerManagerImpl) Status() Status {
    cm.RLock()  // 获取读锁
    defer cm.RUnlock()  // 在函数返回前解锁
    return cm.status  // 返回 status
}
```

#### NewPodContainerManager

```GO
// NewPodContainerManager 是一个工厂方法，返回一个 PodContainerManager 对象
// 如果启用了 qosCgroups，则返回通用的 pod container manager
// 否则返回一个不执行任何操作的 no-op manager
func (cm *containerManagerImpl) NewPodContainerManager() PodContainerManager {
	if cm.NodeConfig.CgroupsPerQOS {
		return &podContainerManagerImpl{
			qosContainersInfo: cm.GetQOSContainersInfo(),
			subsystems:        cm.subsystems,
			cgroupManager:     cm.cgroupManager,
			podPidsLimit:      cm.PodPidsLimit,
			enforceCPULimits:  cm.EnforceCPULimits,
			// cpuCFSQuotaPeriod 的单位是微秒，cm.CPUCFSQuotaPeriod 的单位是纳秒，将其转换为微秒
			cpuCFSQuotaPeriod: uint64(cm.CPUCFSQuotaPeriod / time.Microsecond),
		}
	}
	return &podContainerManagerNoop{
		cgroupRoot: cm.cgroupRoot,
	}
}
```

#### GetNodeAllocatableReservation

```GO
// GetNodeAllocatableReservation 返回在此节点上从调度中必须保留的计算或存储资源量
func (cm *containerManagerImpl) GetNodeAllocatableReservation() v1.ResourceList {
	// 根据 HardEvictionThresholds 和 capacity 计算 evicitonReservation
	evictionReservation := hardEvictionReservation(cm.HardEvictionThresholds, cm.capacity)
	result := make(v1.ResourceList)
	// 遍历 capacity
	for k := range cm.capacity {
		value := resource.NewQuantity(0, resource.DecimalSI)
		// 如果 NodeConfig.SystemReserved 不为空，则将其添加到 value 中
		if cm.NodeConfig.SystemReserved != nil {
			value.Add(cm.NodeConfig.SystemReserved[k])
		}
		// 如果 NodeConfig.KubeReserved 不为空，则将其添加到 value 中
		if cm.NodeConfig.KubeReserved != nil {
			value.Add(cm.NodeConfig.KubeReserved[k])
		}
		// 如果 evictionReservation 不为空，则将其添加到 value 中
		if evictionReservation != nil {
			value.Add(evictionReservation[k])
		}
		// 如果 value 不为零，则将其添加到 result 中
		if !value.IsZero() {
			result[k] = *value
		}
	}
	return result
}
```

#### GetCapacity

```go
// GetCapacity 返回节点的 "cpu"、"memory"、"ephemeral-storage" 和 "huge-pages*" 的容量数据
// 目前只有在检查临时存储时才会调用此方法
func (cm *containerManagerImpl) GetCapacity(localStorageCapacityIsolation bool) v1.ResourceList {
	if localStorageCapacityIsolation {
		// 在启动容器管理器时，将可分配的临时存储存储在 capacity 属性中
		if _, ok := cm.capacity[v1.ResourceEphemeralStorage]; !ok {
			// 如果尚未存储 ephemeral-storage 的容量，则尝试直接从 cAdvisor 获取
			if cm.cadvisorInterface != nil {
				rootfs, err := cm.cadvisorInterface.RootFsInfo()
				if err != nil {
					klog.ErrorS(err, "Unable to get rootfs data from cAdvisor interface")
					// 如果从 cAdvisor 检索 rootfsinfo 失败，则返回不带 ephemeral storage 数据的 capacity 属性
					return cm.capacity
				}
				// 构造包含 ephemeral-storage 的 capacityWithEphemeralStorage，避免在这里更改 cm.capacity
				capacityWithEphemeralStorage := v1.ResourceList{}
				for rName, rQuant := range cm.capacity {
					capacityWithEphemeralStorage[rName] = rQuant
				}
				capacityWithEphemeralStorage[v1.ResourceEphemeralStorage] = cadvisor.EphemeralStorageCapacityFromFsInfo(rootfs)[v1.ResourceEphemeralStorage]
				return capacityWithEphemeralStorage
			}
		}
	}
	return cm.capacity
}
```

#### GetDevicePluginResourceCapacity

```go
func (cm *containerManagerImpl) GetDevicePluginResourceCapacity() (v1.ResourceList, v1.ResourceList, []string) {
	return cm.deviceManager.GetCapacity()
}
```

#### GetDevices

```go
func (cm *containerManagerImpl) GetDevices(podUID, containerName string) []*podresourcesapi.ContainerDevices {
	return containerDevicesFromResourceDeviceInstances(cm.deviceManager.GetDevices(podUID, containerName))
}
```

#### GetAllocatableDevices

```go
func (cm *containerManagerImpl) GetAllocatableDevices() []*podresourcesapi.ContainerDevices {
	return containerDevicesFromResourceDeviceInstances(cm.deviceManager.GetAllocatableDevices())
}
```

##### containerDevicesFromResourceDeviceInstances

```go
func containerDevicesFromResourceDeviceInstances(devs devicemanager.ResourceDeviceInstances) []*podresourcesapi.ContainerDevices {
	var respDevs []*podresourcesapi.ContainerDevices

	for resourceName, resourceDevs := range devs {
		for devID, dev := range resourceDevs {
			topo := dev.GetTopology()
			if topo == nil {
				// 有些设备插件不报告拓扑信息
				// 这是合法的，因此我们仍然报告设备，
				// 让客户端决定如何处理
				respDevs = append(respDevs, &podresourcesapi.ContainerDevices{
					ResourceName: resourceName,
					DeviceIds:    []string{devID},
				})
				continue
			}

			for _, node := range topo.GetNodes() {
				respDevs = append(respDevs, &podresourcesapi.ContainerDevices{
					ResourceName: resourceName,
					DeviceIds:    []string{devID},
					Topology: &podresourcesapi.TopologyInfo{
						Nodes: []*podresourcesapi.NUMANode{
							{
								ID: node.GetID(),
							},
						},
					},
				})
			}
		}
	}

	return respDevs
}
```

#### SystemCgroupsLimit

```GO
func (cm *containerManagerImpl) SystemCgroupsLimit() v1.ResourceList {
    cpuLimit := int64(0)  // 初始化变量 cpuLimit 为0

    // 对所有外部容器的资源进行求和
    for _, cont := range cm.systemContainers {
        cpuLimit += cont.cpuMillicores
    }

    return v1.ResourceList{
        v1.ResourceCPU: *resource.NewMilliQuantity(
            cpuLimit,
            resource.DecimalSI),
    }
}
```

#### GetNodeConfig

```GO
func (cm *containerManagerImpl) GetNodeConfig() NodeConfig {
    cm.RLock()  // 获取读锁
    defer cm.RUnlock()  // 在函数返回前解锁
    return cm.NodeConfig  // 返回 NodeConfig
}
```

#### GetPodCgroupRoot

```GO
// GetPodCgroupRoot 返回包含所有 Pod 的 cgroup 的 cgroupfs 值。
func (cm *containerManagerImpl) GetPodCgroupRoot() string {
    return cm.cgroupManager.Name(cm.cgroupRoot)  // 返回 cgroupManager 根据 cgroupRoot 获取的名称
}
```

#### GetMountedSubsystems

```GO
func (cm *containerManagerImpl) GetMountedSubsystems() *CgroupSubsystems {
    return cm.subsystems  // 返回 subsystems
}
```

#### GetQOSContainersInfo

```GO
func (cm *containerManagerImpl) GetQOSContainersInfo() QOSContainersInfo {
    return cm.qosContainerManager.GetQOSContainersInfo()  // 返回 qosContainerManager 的 QOSContainersInfo
}
```

#### UpdateQOSCgroups

```GO
func (cm *containerManagerImpl) UpdateQOSCgroups() error {
    return cm.qosContainerManager.UpdateCgroups()  // 返回 qosContainerManager 的 UpdateCgroups 方法的结果
}
```

#### Status

```GO
func (cm *containerManagerImpl) Status() Status {
    cm.RLock()  // 获取读锁
    defer cm.RUnlock()  // 在函数返回前解锁
    return cm.status  // 返回 status
}
```

