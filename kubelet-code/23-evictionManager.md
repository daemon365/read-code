## 简介

Kubelet的Eviction Manager是Kubelet的一个重要组件，用于监视节点上的资源使用情况，并在资源不足时执行容器驱逐（Eviction）操作。

Eviction Manager通过监视节点上的资源使用情况，如CPU、内存和磁盘空间等，来确定节点是否已经达到资源限制。一旦资源使用情况超过阈值，Eviction Manager会选择一个或多个容器进行驱逐操作，以释放资源并确保节点的稳定性和可用性。

驱逐操作可以分为两种类型：普通驱逐和优先级驱逐。普通驱逐是指按照容器的启动时间（即First-In-First-Out，FIFO）来选择要驱逐的容器；而优先级驱逐则是根据容器的优先级来选择要驱逐的容器，优先驱逐优先级较低的容器。

Eviction Manager还提供了一些与容器驱逐相关的配置选项，如最大容器驱逐比例、最小驱逐阈值和最大驱逐阈值等。这些选项可以帮助管理员配置驱逐策略，以确保节点的可用性和稳定性。

## Manager

```go
// Manager接口用于评估节点的稳定性是否达到驱逐阈值。
type Manager interface {
	// Start启动控制循环，以指定的时间间隔监视驱逐阈值。
	Start(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc, podCleanedUpFunc PodCleanedUpFunc, monitoringInterval time.Duration)

	// IsUnderMemoryPressure返回节点是否受内存压力影响。
	IsUnderMemoryPressure() bool

	// IsUnderDiskPressure返回节点是否受磁盘压力影响。
	IsUnderDiskPressure() bool

	// IsUnderPIDPressure返回节点是否受PID压力影响。
	IsUnderPIDPressure() bool
}
```

### DiskInfoProvider

```go
// DiskInfoProvider负责通知管理器磁盘配置信息。
type DiskInfoProvider interface {
	// HasDedicatedImageFs如果imagefs与rootfs不在同一设备上，则返回true。
	HasDedicatedImageFs(ctx context.Context) (bool, error)
}
```

### ActivePodsFunc&PodCleanedUpFunc

```go
// ActivePodsFunc返回绑定到kubelet的处于活动状态（非终止状态）的Pod。
type ActivePodsFunc func() []*v1.Pod

// PodCleanedUpFunc返回true，如果与Pod关联的所有资源都已回收。
type PodCleanedUpFunc func(*v1.Pod) bool
```

## managerImpl

```go
// managerImpl实现Manager接口
type managerImpl struct {
	// 用于跟踪时间
	clock clock.WithTicker
	// 配置是管理器的配置
	config Config
	// 调用以终止Pod的函数
	killPodFunc KillPodFunc
	// 知道如何执行图像垃圾回收的接口
	imageGC ImageGC
	// 知道如何执行容器垃圾回收的接口
	containerGC ContainerGC
	// 保护对内部状态的访问
	sync.RWMutex
	// 节点条件是存在的一组条件
	nodeConditions []v1.NodeConditionType
	// 根据达到阈值的时间记录节点条件最后被观察到的时间
	nodeConditionsLastObservedAt nodeConditionsObservedAt
	// nodeRef是对节点的引用
	nodeRef *v1.ObjectReference
	// 用于记录与节点相关的事件
	recorder record.EventRecorder
	// 用于测量系统上的使用统计信息
	summaryProvider stats.SummaryProvider
	// 记录观察到阈值的时间
	thresholdsFirstObservedAt thresholdsObservedAt
	// 记录已满足但尚未解决的阈值（包括宽限期）的集合
	thresholdsMet []evictionapi.Threshold
	// signalToRankFunc将资源映射到该资源的排序函数。
	signalToRankFunc map[evictionapi.Signal]rankFunc
	// signalToNodeReclaimFuncs将资源映射到一个有序的函数列表，这些函数知道如何回收该资源。
	signalToNodeReclaimFuncs map[evictionapi.Signal]nodeReclaimFuncs
	// 来自synchronize的最后一次观察
	lastObservations signalObservations
	// dedicatedImageFs指示imagefs是否与rootfs不在同一设备上
	dedicatedImageFs *bool
	// thresholdNotifiers是一组内存阈值通知器，每个通知器通知一个内存驱逐阈值
	thresholdNotifiers []ThresholdNotifier
	// thresholdsLastUpdated是thresholdNotifiers最后更新的时间。
	thresholdsLastUpdated time.Time
	// 是否支持本地存储容量隔离
	localStorageCapacityIsolation bool
}
```

### ImageGC

```go
// ImageGC负责执行未使用图像的垃圾回收。
type ImageGC interface {
	// DeleteUnusedImages删除未使用的图像。
	DeleteUnusedImages(ctx context.Context) error
}
```

### Config

```go
// Config保存有关如何配置驱逐的信息。
type Config struct {
	// PressureTransitionPeriod是kubelet在退出压力状态之前等待的持续时间。
	PressureTransitionPeriod time.Duration
	// 在满足软驱逐阈值时终止Pod时允许的最大宽限期（以秒为单位）。
	MaxPodGracePeriodSeconds int64
	// Thresholds定义触发驱逐的一组监视条件。
	Thresholds []evictionapi.Threshold
	// 如果为true，则将与内核memcg通知集成，以确定是否跨越了内存阈值。
	KernelMemcgNotification bool
	// PodCgroupRoot是包含所有Pod的cgroup。
	PodCgroupRoot string
}
```

### KillPodFunc

```go
// KillPodFunc终止Pod的函数。
// 更新Pod的状态，然后使用指定的宽限期将其终止。
// 此函数必须阻塞，直到Pod被终止或遇到错误。
// 参数：
// pod - 要终止的Pod
// status - 要与Pod关联的期望状态（即，为什么终止它）
// gracePeriodOverride - 要使用的宽限期覆盖，而不是Pod规范中的值
type KillPodFunc func(pod *v1.Pod, isEvicted bool, gracePeriodOverride *int64, fn func(*v1.PodStatus)) error
```

### ContainerGC

```go
// ContainerGC负责执行未使用容器的垃圾回收。
type ContainerGC interface {
	// DeleteAllUnusedContainers删除所有未使用的容器，即使它们属于已终止但未删除的Pod。
	DeleteAllUnusedContainers(ctx context.Context) error
}
```

### nodeConditionsObservedAt

```go
// nodeConditionsObservedAt将节点条件映射到其被观察到的时间
type nodeConditionsObservedAt map[v1.NodeConditionType]time.Times
```

### rankFunc

```go
// rankFunc对Pod进行驱逐顺序排序
type rankFunc func(pods []*v1.Pod, stats statsFunc)
```

### signalObservations

```go
// signalObservations将信号映射到观察到的数量
type signalObservations map[evictionapi.Signal]signalObservation

// signalObservation是观察到的资源使用情况
type signalObservation struct {
	// 资源容量
	capacity *resource.Quantity
	// 可用资源
	available *resource.Quantity
	// 观察到的时间
	time metav1.Time
}
```

### ThresholdNotifier

```go
// ThresholdNotifier基于内存驱逐阈值管理CgroupNotifiers，并在跨越内存驱逐阈值时执行函数
type ThresholdNotifier interface {
	// Start在CgroupNotifier通知ThresholdNotifier发生事件时调用通知函数
	Start()
	// UpdateThreshold基于提供的指标更新内存cgroup阈值。
	// 使用最新的指标调用UpdateThreshold可以更准确地触发驱逐阈值
	UpdateThreshold(summary *statsapi.Summary) error
	// Description生成描述内存阈值通知器的相关字符串
	Description() string
}
```

#### memoryThresholdNotifier

```go
// 定义 memoryThresholdNotifier 结构体，实现 ThresholdNotifier 接口
type memoryThresholdNotifier struct {
	threshold  evictionapi.Threshold // 阈值，用于触发通知的条件
	cgroupPath string               // cgroup 在文件系统中的路径
	events     chan struct{}        // 用于接收事件的通道
	factory    NotifierFactory      // 通知器工厂接口
	handler    func(string)         // 处理通知的回调函数
	notifier   CgroupNotifier       // Cgroup 通知器接口
}

// _ ThresholdNotifier = &memoryThresholdNotifier{} 的目的是确保 memoryThresholdNotifier 实现了 ThresholdNotifier 接口

// NewMemoryThresholdNotifier 创建一个 ThresholdNotifier，用于响应给定的阈值
// 在阈值生效之前必须先调用 UpdateThreshold
func NewMemoryThresholdNotifier(threshold evictionapi.Threshold, cgroupRoot string, factory NotifierFactory, handler func(string)) (ThresholdNotifier, error) {
	// 获取 cgroup 的子系统列表
	cgroups, err := cm.GetCgroupSubsystems()
	if err != nil {
		return nil, err
	}
	// 获取 memory cgroup 在文件系统中的路径
	cgpath, found := cgroups.MountPoints["memory"]
	if !found || len(cgpath) == 0 {
		return nil, fmt.Errorf("memory cgroup mount point not found")
	}
	if isAllocatableEvictionThreshold(threshold) {
		// 对于可分配的阈值，将 cgroup 通知器指向可分配的 cgroup
		cgpath += cgroupRoot
	}
	// 创建 memoryThresholdNotifier 实例并返回
	return &memoryThresholdNotifier{
		threshold:  threshold,
		cgroupPath: cgpath,
		events:     make(chan struct{}),
		handler:    handler,
		factory:    factory,
	}, nil
}

// Start 方法用于启动 memoryThresholdNotifier，监听事件并处理通知
func (m *memoryThresholdNotifier) Start() {
	// 记录日志，表示创建了 memoryThresholdNotifier
	klog.InfoS("Eviction manager: created memoryThresholdNotifier", "notifier", m.Description())
	// 不断循环，监听通道事件并触发处理函数
	for range m.events {
		m.handler(fmt.Sprintf("eviction manager: %s crossed", m.Description()))
	}
}

// UpdateThreshold 方法用于更新阈值，并设置相应的通知器
func (m *memoryThresholdNotifier) UpdateThreshold(summary *statsapi.Summary) error {
	// 获取内存统计信息
	memoryStats := summary.Node.Memory
	// 对于可分配的阈值，获取可分配容器的内存统计信息
	if isAllocatableEvictionThreshold(m.threshold) {
		allocatableContainer, err := getSysContainer(summary.Node.SystemContainers, statsapi.SystemContainerPods)
		if err != nil {
			return err
		}
		memoryStats = allocatableContainer.Memory
	}
	// 检查内存统计信息是否完整
	if memoryStats == nil || memoryStats.UsageBytes == nil || memoryStats.WorkingSetBytes == nil || memoryStats.AvailableBytes == nil {
		return fmt.Errorf("summary was incomplete. Expected MemoryStats and all subfields to be non-nil, but got %+v", memoryStats)
	}
	// 计算阈值
	inactiveFile := resource.NewQuantity(int64(*memoryStats.UsageBytes-*memoryStats.WorkingSetBytes), resource.BinarySI)
	capacity := resource.NewQuantity(int64(*memoryStats.AvailableBytes+*memoryStats.WorkingSetBytes), resource.BinarySI)
	evictionThresholdQuantity := evictionapi.GetThresholdQuantity(m.threshold.Value, capacity)
	memcgThreshold := capacity.DeepCopy()
	memcgThreshold.Sub(*evictionThresholdQuantity)
	memcgThreshold.Add(*inactiveFile)

	// 设置通知器的阈值
	klog.V(3).InfoS("Eviction manager: setting notifier to capacity", "notifier", m.Description(), "capacity", memcgThreshold.String())
	if m.notifier != nil {
		m.notifier.Stop()
	}
	newNotifier, err := m.factory.NewCgroupNotifier(m.cgroupPath, memoryUsageAttribute, memcgThreshold.Value())
	if err != nil {
		return err
	}
	m.notifier = newNotifier
	// 启动通知器
	go m.notifier.Start(m.events)
	return nil
}

// Description 方法返回 memoryThresholdNotifier 的描述信息
func (m *memoryThresholdNotifier) Description() string {
	var hard, allocatable string
	if isHardEvictionThreshold(m.threshold) {
		hard = "hard "
	} else {
		hard = "soft "
	}
	if isAllocatableEvictionThreshold(m.threshold) {
		allocatable = "allocatable "
	}
	return fmt.Sprintf("%s%smemory eviction threshold", hard, allocatable)
}
```

### NotifierFactory

```go
// NotifierFactory 创建 CgroupNotifer
type NotifierFactory interface {
	// NewCgroupNotifier 创建一个 CgroupNotifier，当路径指定的 cgroup 中的属性的阈值被越过时生成事件。
	NewCgroupNotifier(path, attribute string, threshold int64) (CgroupNotifier, error)
}
```

#### CgroupNotifierFactory

```go
var _ NotifierFactory = &CgroupNotifierFactory{}

// CgroupNotifierFactory 知道如何制作与内核集成的 CgroupNotifiers
type CgroupNotifierFactory struct{}

// NewCgroupNotifier 实现 NotifierFactory 接口
func (n *CgroupNotifierFactory) NewCgroupNotifier(path, attribute string, threshold int64) (CgroupNotifier, error) {
	return NewCgroupNotifier(path, attribute, threshold)
}

```

### CgroupNotifier

```go
// CgroupNotifier 从 cgroup 事件生成事件
type CgroupNotifier interface {
	// Start 使 CgroupNotifier 开始在 eventCh 上通知
	Start(eventCh chan<- struct{})
	// Stop 停止所有进程并清理与 CgroupNotifier 相关联的文件描述符
	Stop()
}
```

#### linuxCgroupNotifier

```go
type linuxCgroupNotifier struct {
	eventfd  int
	epfd     int
	stop     chan struct{}
	stopLock sync.Mutex
}

var _ CgroupNotifier = &linuxCgroupNotifier{}

// NewCgroupNotifier 返回一个 linuxCgroupNotifier，它执行从 cgroup 执行的 cgroup 控制操作，
// 当阈值在任一方向上越过时，用于接收来自 cgroup 的通知。
func NewCgroupNotifier(path, attribute string, threshold int64) (CgroupNotifier, error) {
	// cgroupv2 不支持使用 cgroup.event_control 监控 cgroup 内存阈值。
	// 长期来看，在 cgroupv2 上，kubelet 应该依靠将 root pods cgroup 上的 memory.low 与 memory.events 和/或 PSI 压力上的 inotify 通知结合起来。
	// 目前，让我们在 cgroupv2 上返回一个假的“禁用”cgroup通知器。
	// https://github.com/kubernetes/kubernetes/issues/106331
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		return &disabledThresholdNotifier{}, nil
	}

	var watchfd, eventfd, epfd, controlfd int
	var err error
	watchfd, err = unix.Open(fmt.Sprintf("%s/%s", path, attribute), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(watchfd)
	controlfd, err = unix.Open(fmt.Sprintf("%s/cgroup.event_control", path), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(controlfd)
	eventfd, err = unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	if eventfd < 0 {
		err = fmt.Errorf("eventfd 调用失败")
		return nil, err
	}
	defer func() {
		// 如果在初始化过程中后面出现错误，关闭 eventfd
		if err != nil {
			unix.Close(eventfd)
		}
	}()
	epfd, err = unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	if epfd < 0 {
		err = fmt.Errorf("EpollCreate1 调用失败")
		return nil, err
	}
	defer func() {
		// 如果在初始化过程中后面出现错误，关闭 epfd
		if err != nil {
			unix.Close(epfd)
		}
	}()
	config := fmt.Sprintf("%d %d %d", eventfd, watchfd, threshold)
	_, err = unix.Write(controlfd, []byte(config))
	if err != nil {
		return nil, err
	}
	return &linuxCgroupNotifier{
		eventfd: eventfd,
		epfd:    epfd,
		stop:    make(chan struct{}),
	}, nil
}

func (n *linuxCgroupNotifier) Start(eventCh chan<- struct{}) {
	err := unix.EpollCtl(n.epfd, unix.EPOLL_CTL_ADD, n.eventfd, &unix.EpollEvent{
		Fd:     int32(n.eventfd),
		Events: unix.EPOLLIN,
	})
	if err != nil {
		klog.InfoS("Eviction manager: 添加 epoll eventfd 错误", "err", err)
		return
	}
	buf := make([]byte, eventSize)
	for {
		select {
		case <-n.stop:
			return
		default:
		}
		event, err := wait(n.epfd, n.eventfd, notifierRefreshInterval)
		if err != nil {
			klog.InfoS("Eviction manager: 等待 memcg 事件出错", "err", err)
			return
		} else if !event {
			// 等待超时。如果没有越过阈值，这是预期的情况
			continue
		}
		// 从 eventfd 消费事件
		_, err = unix.Read(n.eventfd, buf)
		if err != nil {
			klog.InfoS("Eviction manager: 读取 memcg 事件出错", "err", err)
			return
		}
		eventCh <- struct{}{}
	}
}

// wait 在 notifierRefreshInterval 内等待 Epoll FD 上的事件，
// 以获取我们关心的 eventfd 上的事件。如果出现错误，则返回错误，如果消费者应该从 eventfd 读取，则返回 true。
func wait(epfd, eventfd int, timeout time.Duration) (bool, error) {
	events := make([]unix.EpollEvent, numFdEvents+1)
	timeoutMS := int(timeout / time.Millisecond)
	n, err := unix.EpollWait(epfd, events, timeoutMS)
	if n == -1 {
		if err == unix.EINTR {
			// 中断，忽略错误
			return false, nil
		}
		return false, err
	}
	if n == 0 {
		// 等待超时
		return false, nil
	}
	if n > numFdEvents {
		return false, fmt.Errorf("epoll_wait 返回的事件比我们知道如何处理的更多")
	}
	for _, event := range events[:n] {
		if event.Fd == int32(eventfd) {
			if event.Events&unix.EPOLLHUP != 0 || event.Events&unix.EPOLLERR != 0 || event.Events&unix.EPOLLIN != 0 {
				// EPOLLHUP: 不应该发生，但如果发生了，将其视为唤醒。

				// EPOLLERR: 如果在文件描述符上等待错误，我们应该假装有东西准备好读取，并让 unix.Read 捕捉错误。

				// EPOLLIN: 有数据可读取。
				return true, nil
			}
		}
	}
	// 发生了我们不关心的事件。
	return false, nil
}

func (n *linuxCgroupNotifier) Stop() {
	n.stopLock.Lock()
	defer n.stopLock.Unlock()
	select {
	case <-n.stop:
		// linuxCgroupNotifier 已经停止了
		return
	default:
	}
	unix.Close(n.eventfd)
	unix.Close(n.epfd)
	close(n.stop)
}
```

### Admit

```go
// Admit rejects a pod if its not safe to admit for node stability.
// Admit 方法用于检查是否可以接受一个 Pod 进行节点的稳定性。
func (m *managerImpl) Admit(attrs *lifecycle.PodAdmitAttributes) lifecycle.PodAdmitResult {
	m.RLock() // 加读锁
	defer m.RUnlock() // 解锁，确保方法结束时释放锁
	if len(m.nodeConditions) == 0 {
		return lifecycle.PodAdmitResult{Admit: true}
	}
	// 重要的 Pod 在资源压力下也会被接受，因为它们对于系统稳定性是必需的。
	if kubelettypes.IsCriticalPod(attrs.Pod) {
		return lifecycle.PodAdmitResult{Admit: true}
	}

	nodeOnlyHasMemoryPressureCondition := hasNodeCondition(m.nodeConditions, v1.NodeMemoryPressure) && len(m.nodeConditions) == 1
	if nodeOnlyHasMemoryPressureCondition {
		notBestEffort := v1.PodQOSBestEffort != v1qos.GetPodQOS(attrs.Pod)
		if notBestEffort {
			return lifecycle.PodAdmitResult{Admit: true}
		}

		if corev1helpers.TolerationsTolerateTaint(attrs.Pod.Spec.Tolerations, &v1.Taint{
			Key:    v1.TaintNodeMemoryPressure,
			Effect: v1.TaintEffectNoSchedule,
		}) {
			return lifecycle.PodAdmitResult{Admit: true}
		}
	}

	// 当节点面临内存压力（如果 Pod 是 BestEffort）或者磁盘压力时，拒绝 Pod。
	klog.InfoS("Failed to admit pod to node", "pod", klog.KObj(attrs.Pod), "nodeCondition", m.nodeConditions)
	return lifecycle.PodAdmitResult{
		Admit:   false,
		Reason:  Reason,
		Message: fmt.Sprintf(nodeConditionMessageFmt, m.nodeConditions),
	}
}
```

### Start

```go
func (m *memoryThresholdNotifier) Start() {
	klog.InfoS("Eviction manager: created memoryThresholdNotifier", "notifier", m.Description()) // 输出日志，表示创建了 memoryThresholdNotifier
	for range m.events { // 循环监听事件
		m.handler(fmt.Sprintf("eviction manager: %s crossed", m.Description())) // 调用 handler 处理事件
	}
}
```

#### UpdateThreshold

```go
func (m *memoryThresholdNotifier) UpdateThreshold(summary *statsapi.Summary) error {
	memoryStats := summary.Node.Memory
	if isAllocatableEvictionThreshold(m.threshold) { // 判断是否为可分配资源的阈值
		allocatableContainer, err := getSysContainer(summary.Node.SystemContainers, statsapi.SystemContainerPods)
		if err != nil {
			return err
		}
		memoryStats = allocatableContainer.Memory // 使用可分配容器的内存统计数据
	}
	if memoryStats == nil || memoryStats.UsageBytes == nil || memoryStats.WorkingSetBytes == nil || memoryStats.AvailableBytes == nil {
		return fmt.Errorf("summary was incomplete.  Expected MemoryStats and all subfields to be non-nil, but got %+v", memoryStats)
	}
	// 设置阈值，计算使用量和容量之间的差值
	inactiveFile := resource.NewQuantity(int64(*memoryStats.UsageBytes-*memoryStats.WorkingSetBytes), resource.BinarySI)
	capacity := resource.NewQuantity(int64(*memoryStats.AvailableBytes+*memoryStats.WorkingSetBytes), resource.BinarySI)
	evictionThresholdQuantity := evictionapi.GetThresholdQuantity(m.threshold.Value, capacity)
	memcgThreshold := capacity.DeepCopy()
	memcgThreshold.Sub(*evictionThresholdQuantity)
	memcgThreshold.Add(*inactiveFile)

	klog.V(3).InfoS("Eviction manager: setting notifier to capacity", "notifier", m.Description(), "capacity", memcgThreshold.String()) // 输出日志，设置 notifier 的容量
	if m.notifier != nil {
		m.notifier.Stop() // 停止当前的 notifier
	}
	newNotifier, err := m.factory.NewCgroupNotifier(m.cgroupPath, memoryUsageAttribute, memcgThreshold.Value()) // 创建新的 notifier
	if err != nil {
		return err
	}
	m.notifier = newNotifier
	go m.notifier.Start(m.events) // 启动新的 notifier
	return nil
}
```

#### synchronize

```go
// synchronize 是执行驱逐阈值的主要控制循环。
// 返回被杀死的 Pod 列表，如果没有 Pod 被杀死则返回 nil。
func (m *managerImpl) synchronize(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc) []*v1.Pod {
	ctx := context.Background()
	// 如果没有事情要做，直接返回
	thresholds := m.config.Thresholds
	if len(thresholds) == 0 && !m.localStorageCapacityIsolation {
		return nil
	}

	klog.V(3).InfoS("Eviction manager: synchronize housekeeping")
	// 构建排名函数（如果尚未知道）
	// TODO: 在 cadvisor 中添加一个函数，让我们知道全局 housekeeping 是否已完成
	if m.dedicatedImageFs == nil {
		hasImageFs, ok := diskInfoProvider.HasDedicatedImageFs(ctx)
		if ok != nil {
			return nil
		}
		m.dedicatedImageFs = &hasImageFs
		m.signalToRankFunc = buildSignalToRankFunc(hasImageFs)
		m.signalToNodeReclaimFuncs = buildSignalToNodeReclaimFuncs(m.imageGC, m.containerGC, hasImageFs)
	}

	activePods := podFunc()
	updateStats := true
	summary, err := m.summaryProvider.Get(ctx, updateStats)
	if err != nil {
		klog.ErrorS(err, "Eviction manager: failed to get summary stats")
		return nil
	}

	if m.clock.Since(m.thresholdsLastUpdated) > notifierRefreshInterval {
		m.thresholdsLastUpdated = m.clock.Now()
		for _, notifier := range m.thresholdNotifiers {
			if err := notifier.UpdateThreshold(summary); err != nil {
				klog.InfoS("Eviction manager: failed to update notifier", "notifier", notifier.Description(), "err", err)
			}
		}
	}

	// 进行观察，并获取一个函数来相对于这些观察推导出 Pod 的使用统计。
	observations, statsFunc := makeSignalObservations(summary)
	debugLogObservations("observations", observations)

	// 确定独立于宽限期的一组满足阈值的阈值
	thresholds = thresholdsMet(thresholds, observations, false)
	debugLogThresholdsWithObservation("thresholds - ignoring grace period", thresholds, observations)

	// 确定先前满足的但尚未满足相关最小回收的阈值集合
	if len(m.thresholdsMet) > 0 {
		thresholdsNotYetResolved := thresholdsMet(m.thresholdsMet, observations, true)
		thresholds = mergeThresholds(thresholds, thresholdsNotYetResolved)
	}
	debugLogThresholdsWithObservation("thresholds - reclaim not satisfied", thresholds, observations)

	// 跟踪首次观察到的阈值
	now := m.clock.Now()
	thresholdsFirstObservedAt := thresholdsFirstObservedAt(thresholds, m.thresholdsFirstObservedAt, now)

	// 由当前观察到的阈值触发的节点条件集合
	nodeConditions := nodeConditions(thresholds)
	if len(nodeConditions) > 0 {
		klog.V(3).InfoS("Eviction manager: node conditions - observed", "nodeCondition", nodeConditions)
	}

	// 跟踪最后观察到的节点条件
	nodeConditionsLastObservedAt := nodeConditionsLastObservedAt(nodeConditions, m.nodeConditionsLastObservedAt, now)

	// 节点条件在过渡期窗口内观察到时报告为 true
	nodeConditions = nodeConditionsObservedSince(nodeConditionsLastObservedAt, m.config.PressureTransitionPeriod, now)
	if len(nodeConditions) > 0 {
		klog.V(3).InfoS("Eviction manager: node conditions - transition period not met", "nodeCondition", nodeConditions)
	}

	// 确定我们需要驱逐行为的阈值集合（即所有宽限期均已满足）
	thresholds = thresholdsMetGracePeriod(thresholdsFirstObservedAt, now)
	debugLogThresholdsWithObservation("thresholds - grace periods satisfied", thresholds, observations)

	// 更新内部状态
	m.Lock()
	m.nodeConditions = nodeConditions
	m.thresholdsFirstObservedAt = thresholdsFirstObservedAt
	m.nodeConditionsLastObservedAt = nodeConditionsLastObservedAt
	m.thresholdsMet = thresholds

	// 确定自上次同步以来已更新统计信息的阈值集合
	thresholds = thresholdsUpdatedStats(thresholds, observations, m.lastObservations)
	debugLogThresholdsWithObservation("thresholds - updated stats", thresholds, observations)

	m.lastObservations = observations
	m.Unlock()

	// 如果存在本地存储临时存储的资源使用违规，驱逐 Pod
	// 如果在 localStorageEviction 函数中发生驱逐，请跳过驱逐操作的其余部分
	if m.localStorageCapacityIsolation {
		if evictedPods := m.localStorageEviction(activePods, statsFunc); len(evictedPods) > 0 {
			return evictedPods
		}
	}

	if len(thresholds) == 0 {
		klog.V(3).InfoS("Eviction manager: no resources are starved")
		return nil
	}

	// 根据驱逐优先级对阈值进行排名
	sort.Sort(byEvictionPriority(thresholds))
	thresholdToReclaim, resourceToReclaim, foundAny := getReclaimableThreshold(thresholds)
	if !foundAny {
		return nil
	}
	klog.InfoS("Eviction manager: attempting to reclaim", "resourceName", resourceToReclaim)

	// 记录关于正在尝试通过驱逐回收的资源的事件
	m.recorder.Eventf(m.nodeRef, v1.EventTypeWarning, "EvictionThresholdMet", "Attempting to reclaim %s", resourceToReclaim)

	// 检查是否有节点级资源可以回收，以在驱逐用户端 Pod 之前减轻压力
	if m.reclaimNodeLevelResources(ctx, thresholdToReclaim.Signal, resourceToReclaim) {
		klog.InfoS("Eviction manager: able to reduce resource pressure without evicting pods.", "resourceName", resourceToReclaim)
		return nil
	}

	klog.InfoS("Eviction manager: must evict pod(s) to reclaim", "resourceName", resourceToReclaim)

	// 对驱逐进行排名
	rank, ok := m.signalToRankFunc[thresholdToReclaim.Signal]
	if !ok {
		klog.ErrorS(nil, "Eviction manager: no ranking function for signal", "threshold", thresholdToReclaim.Signal)
		return nil
	}

	// 仅有那些有任何运行内容的 Pod 才能被驱逐
	if len(activePods) == 0 {
		klog.ErrorS(nil, "Eviction manager: eviction thresholds have been met, but no pods are active to evict")
		return nil
	}

	// 对指定资源的运行中 Pod 进行驱逐排名
	rank(activePods, statsFunc)

	klog.InfoS("Eviction manager: pods ranked for eviction", "pods", klog.KObjSlice(activePods))

	// 记录用于驱逐的已满足阈值的度量标准的年龄。
	for _, t := range thresholds {
		timeObserved := observations[t.Signal].time
		if !timeObserved.IsZero() {
			metrics.EvictionStatsAge.WithLabelValues(string(t.Signal)).Observe(metrics.SinceInSeconds(timeObserved.Time))
		}
	}

	// 在每次驱逐间隔期间最多杀死一个 Pod
	for i := range activePods {
		pod := activePods[i]
		gracePeriodOverride := int64(0)
		if !isHardEvictionThreshold(thresholdToReclaim) {
			gracePeriodOverride = m.config.MaxPodGracePeriodSeconds
		}
		message, annotations := evictionMessage(resourceToReclaim, pod, statsFunc, thresholds, observations)
		var condition *v1.PodCondition
		if utilfeature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
			condition = &v1.PodCondition{
				Type:    v1.DisruptionTarget,
				Status:  v1.ConditionTrue,
				Reason:  v1.PodReasonTerminationByKubelet,
				Message: message,
			}
		}
		if m.evictPod(pod, gracePeriodOverride, message, annotations, condition) {
			metrics.Evictions.WithLabelValues(string(thresholdToReclaim.Signal)).Inc()
			return []*v1.Pod{pod}
		}
	}
	klog.InfoS("Eviction manager: unable to evict any pods from the node")
	return nil
}
```

##### debugLogObservations

```go
// debugLogObservations 打印观察到的信号的调试日志
func debugLogObservations(logPrefix string, observations signalObservations) {
	klogV := klog.V(3)
	if !klogV.Enabled() {
		return
	}
	for k, v := range observations {
		if !v.time.IsZero() {
			klogV.InfoS("Eviction manager:", "log", logPrefix, "signal", k, "resourceName", signalToResource[k], "available", v.available, "capacity", v.capacity, "time", v.time)
		} else {
			klogV.InfoS("Eviction manager:", "log", logPrefix, "signal", k, "resourceName", signalToResource[k], "available", v.available, "capacity", v.capacity)
		}
	}
}
```

##### debugLogThresholdsWithObservation

```go
// debugLogThresholdsWithObservation 打印带有观察数据的阈值的调试日志
func debugLogThresholdsWithObservation(logPrefix string, thresholds []evictionapi.Threshold, observations signalObservations) {
	klogV := klog.V(3)
	if !klogV.Enabled() {
		return
	}
	for i := range thresholds {
		threshold := thresholds[i]
		observed, found := observations[threshold.Signal]
		if found {
			quantity := evictionapi.GetThresholdQuantity(threshold.Value, observed.capacity)
			klogV.InfoS("Eviction manager: threshold observed resource", "log", logPrefix, "signal", threshold.Signal, "resourceName", signalToResource[threshold.Signal], "quantity", quantity, "available", observed.available)
		} else {
			klogV.InfoS("Eviction manager: threshold had no observation", "log", logPrefix, "signal", threshold.Signal)
		}
	}
}
```

##### mergeThresholds

```go
// mergeThresholds 合并两个阈值列表，消除重复项
func mergeThresholds(inputsA []evictionapi.Threshold, inputsB []evictionapi.Threshold) []evictionapi.Threshold {
	results := inputsA
	for _, threshold := range inputsB {
		if !hasThreshold(results, threshold) {
			results = append(results, threshold)
		}
	}
	return results
}
```

##### thresholdsMet

```go
// thresholdsMet 返回满足条件的阈值集合，独立于宽限期
func thresholdsMet(thresholds []evictionapi.Threshold, observations signalObservations, enforceMinReclaim bool) []evictionapi.Threshold {
	results := []evictionapi.Threshold{}
	for i := range thresholds {
		threshold := thresholds[i]
		observed, found := observations[threshold.Signal]
		if !found {
			klog.InfoS("Eviction manager: no observation found for eviction signal", "signal", threshold.Signal)
			continue
		}
		// 判断是否满足指定的阈值
		thresholdMet := false
		quantity := evictionapi.GetThresholdQuantity(threshold.Value, observed.capacity)
		// 如果指定了 enforceMinReclaim，则相对于 value - minreclaim 进行比较
		if enforceMinReclaim && threshold.MinReclaim != nil {
			quantity.Add(*evictionapi.GetThresholdQuantity(*threshold.MinReclaim, observed.capacity))
		}
		thresholdResult := quantity.Cmp(*observed.available)
		switch threshold.Operator {
		case evictionapi.OpLessThan:
			thresholdMet = thresholdResult > 0
		}
		if thresholdMet {
			results = append(results, threshold)
		}
	}
	return results
}
```

##### thresholdsFirstObservedAt

```go
// thresholdsFirstObservedAt merges the input set of thresholds with the previous observation to determine when active set of thresholds were initially met.
func thresholdsFirstObservedAt(thresholds []evictionapi.Threshold, lastObservedAt thresholdsObservedAt, now time.Time) thresholdsObservedAt {
	results := thresholdsObservedAt{}
	for i := range thresholds {
		observedAt, found := lastObservedAt[thresholds[i]]
		if !found {
			observedAt = now
		}
		results[thresholds[i]] = observedAt
	}
	return results
}
```

##### nodeConditionsLastObservedAt

```go
// nodeConditionsLastObservedAt merges the input with the previous observation to determine when a condition was most recently met.
func nodeConditionsLastObservedAt(nodeConditions []v1.NodeConditionType, lastObservedAt nodeConditionsObservedAt, now time.Time) nodeConditionsObservedAt {
	results := nodeConditionsObservedAt{}
	// the input conditions were observed "now"
	for i := range nodeConditions {
		results[nodeConditions[i]] = now
	}
	// the conditions that were not observed now are merged in with their old time
	for key, value := range lastObservedAt {
		_, found := results[key]
		if !found {
			results[key] = value
		}
	}
	return results
}
```

##### nodeConditionsObservedSince

```go
// nodeConditionsObservedSince returns the set of conditions that have been observed within the specified period
func nodeConditionsObservedSince(observedAt nodeConditionsObservedAt, period time.Duration, now time.Time) []v1.NodeConditionType {
	results := []v1.NodeConditionType{}
	for nodeCondition, at := range observedAt {
		duration := now.Sub(at)
		if duration < period {
			results = append(results, nodeCondition)
		}
	}
	return results
}
```

##### thresholdsMetGracePeriod

```go
// thresholdsMetGracePeriod returns the set of thresholds that have satisfied associated grace period
func thresholdsMetGracePeriod(observedAt thresholdsObservedAt, now time.Time) []evictionapi.Threshold {
	results := []evictionapi.Threshold{}
	for threshold, at := range observedAt {
		duration := now.Sub(at)
		if duration < threshold.GracePeriod {
			klog.V(2).InfoS("Eviction manager: eviction criteria not yet met", "threshold", formatThreshold(threshold), "duration", duration)
			continue
		}
		results = append(results, threshold)
	}
	return results
}
```

##### thresholdsUpdatedStats

```go
func thresholdsUpdatedStats(thresholds []evictionapi.Threshold, observations, lastObservations signalObservations) []evictionapi.Threshold {
	results := []evictionapi.Threshold{}
	for i := range thresholds {
		threshold := thresholds[i]
		observed, found := observations[threshold.Signal]
		if !found {
			klog.InfoS("Eviction manager: no observation found for eviction signal", "signal", threshold.Signal)
			continue
		}
		last, found := lastObservations[threshold.Signal]
		if !found || observed.time.IsZero() || observed.time.After(last.time.Time) {
			results = append(results, threshold)
		}
	}
	return results
}
```

##### localStorageEviction

```go
// localStorageEviction 检查每个 Pod 的 EmptyDir 卷使用情况，判断是否超过指定的限制并需要进行驱逐。
// 还会检查 Pod 中的每个容器，如果容器的覆盖使用量超过限制，则也会驱逐该 Pod。
func (m *managerImpl) localStorageEviction(pods []*v1.Pod, statsFunc statsFunc) []*v1.Pod {
	evicted := []*v1.Pod{}
	for _, pod := range pods {
		podStats, ok := statsFunc(pod)
		if !ok {
			continue
		}

		if m.emptyDirLimitEviction(podStats, pod) {
			evicted = append(evicted, pod)
			continue
		}

		if m.podEphemeralStorageLimitEviction(podStats, pod) {
			evicted = append(evicted, pod)
			continue
		}

		if m.containerEphemeralStorageLimitEviction(podStats, pod) {
			evicted = append(evicted, pod)
		}
	}

	return evicted
}
```

##### getReclaimableThreshold

```go
// getReclaimableThreshold 找到要回收的阈值和资源
func getReclaimableThreshold(thresholds []evictionapi.Threshold) (evictionapi.Threshold, v1.ResourceName, bool) {
	for _, thresholdToReclaim := range thresholds {
		if resourceToReclaim, ok := signalToResource[thresholdToReclaim.Signal]; ok {
			return thresholdToReclaim, resourceToReclaim, true
		}
		klog.V(3).InfoS("Eviction manager: threshold was crossed, but reclaim is not implemented for this threshold.", "threshold", thresholdToReclaim.Signal)
	}
	return evictionapi.Threshold{}, "", false
}
```

##### reclaimNodeLevelResources

```go
// reclaimNodeLevelResources 尝试回收节点级别的资源。如果满足阈值并且不需要驱逐 Pod，则返回 true。
func (m *managerImpl) reclaimNodeLevelResources(ctx context.Context, signalToReclaim evictionapi.Signal, resourceToReclaim v1.ResourceName) bool {
	nodeReclaimFuncs := m.signalToNodeReclaimFuncs[signalToReclaim]
	for _, nodeReclaimFunc := range nodeReclaimFuncs {
		// 尝试回收受压资源
		if err := nodeReclaimFunc(ctx); err != nil {
			klog.InfoS("Eviction manager: unexpected error when attempting to reduce resource pressure", "resourceName", resourceToReclaim, "err", err)
		}
	}

	if len(nodeReclaimFuncs) > 0 {
		summary, err := m.summaryProvider.Get(ctx, true)
		if err != nil {
			klog.ErrorS(err, "Eviction manager: failed to get summary stats after resource reclaim")
			return false
		}

		// 创建观察结果并获取一个用于根据这些观察结果计算 Pod 使用情况统计的函数。
		observations, _ := makeSignalObservations(summary)
		debugLogObservations("observations after resource reclaim", observations)

		// 独立地评估所有阈值，不考虑它们的宽限期，以确定是否满足最小回收目标。
		thresholds := thresholdsMet(m.config.Thresholds, observations, true)
		debugLogThresholdsWithObservation("thresholds after resource reclaim - ignoring grace period", thresholds, observations)

		if len(thresholds) == 0 {
			return true
		}
	}
	return false
}
```

##### evictionMessage

```go
// evictionMessage 构建有关为何发生驱逐的有用信息，以及提供驱逐的元数据的注释。
func evictionMessage(resourceToReclaim v1.ResourceName, pod *v1.Pod, stats statsFunc, thresholds []evictionapi.Threshold, observations signalObservations) (message string, annotations map[string]string) {
	annotations = make(map[string]string)
	message = fmt.Sprintf(nodeLowMessageFmt, resourceToReclaim)
	quantity, available := getThresholdMetInfo(resourceToReclaim, thresholds, observations)
	if quantity != nil && available != nil {
		message += fmt.Sprintf(thresholdMetMessageFmt, quantity, available)
	}
	containers := []string{}
	containerUsage := []string{}
	podStats, ok := stats(pod)
	if !ok {
		return
	}
	for _, containerStats := range podStats.Containers {
		for _, container := range pod.Spec.Containers {
			if container.Name == containerStats.Name {
				requests := container.Resources.Requests[resourceToReclaim]
				if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) &&
					(resourceToReclaim == v1.ResourceMemory || resourceToReclaim == v1.ResourceCPU) {
					if cs, ok := podutil.GetContainerStatus(pod.Status.ContainerStatuses, container.Name); ok {
						requests = cs.AllocatedResources[resourceToReclaim]
					}
				}
				var usage *resource.Quantity
				switch resourceToReclaim {
				case v1.ResourceEphemeralStorage:
					if containerStats.Rootfs != nil && containerStats.Rootfs.UsedBytes != nil && containerStats.Logs != nil && containerStats.Logs.UsedBytes != nil {
						usage = resource.NewQuantity(int64(*containerStats.Rootfs.UsedBytes+*containerStats.Logs.UsedBytes), resource.BinarySI)
					}
				case v1.ResourceMemory:
					if containerStats.Memory != nil && containerStats.Memory.WorkingSetBytes != nil {
						usage = resource.NewQuantity(int64(*containerStats.Memory.WorkingSetBytes), resource.BinarySI)
					}
				}
				if usage != nil && usage.Cmp(requests) > 0 {
					message += fmt.Sprintf(containerMessageFmt, container.Name, usage.String(), requests.String(), resourceToReclaim)
					containers = append(containers, container.Name)
					containerUsage = append(containerUsage, usage.String())
				}
			}
		}
	}
	annotations[OffendingContainersKey] = strings.Join(containers, ",")
	annotations[OffendingContainersUsageKey] = strings.Join(containerUsage, ",")
	return
}
```

##### shouldEvictPod

```go
// shouldEvictPod 返回是否应该驱逐指定的 Pod。
func shouldEvictPod(pod *v1.Pod, config *evictionapi.PodEvictionConfig, annotations map[string]string, now time.Time) bool {
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	// 如果 Pod 不需要驱逐并且不包含驱逐注释，则不执行驱逐操作。
	if !config.EnablePodEviction || pod.Annotations[EvictionTimestampAnnotationKey] != "" {
		return false
	}
	// 设置驱逐注释并添加其他元数据注释。
	pod.Annotations[EvictionTimestampAnnotationKey] = now.UTC().Format(time.RFC3339)
	for k, v := range annotations {
		pod.Annotations[k] = v
	}
	return true
}
```

##### getPodsToEvict

```go
// getPodsToEvict 返回应该驱逐的 Pod 列表。
func (m *managerImpl) getPodsToEvict(ctx context.Context, nodes []*v1.Node, pods []*v1.Pod) ([]*v1.Pod, error) {
	evicted := []*v1.Pod{}
	// 获取统计信息的函数。
	statsFunc := func(pod *v1.Pod) (*SummaryStats, bool) {
		// 获取 Pod 统计信息。
		summary, err := m.summaryProvider.GetPodStats(pod.Namespace, pod.Name)
		if err != nil {
			if errors.IsNotFound(err) {
				klog.V(4).InfoS("Eviction manager: failed to get pod stats for pod", "namespace", pod.Namespace, "name", pod.Name)
			} else {
				klog.ErrorS(err, "Eviction manager: failed to get pod stats for pod", "namespace", pod.Namespace, "name", pod.Name)
			}
			return nil, false
		}
		return summary, true
	}
	// 遍历节点并检查每个节点上的 Pod 是否需要被驱逐。
	for _, node := range nodes {
		podsOnNode := getPossibleEvictablePodsOnNode(node, pods)
		// 检查节点级别资源的回收情况，如果满足阈值并且不需要驱逐 Pod，则跳过此节点。
		if m.reclaimNodeLevelResources(ctx, evictionapi.SignalNode, v1.ResourceName(node.Name)) {
			continue
		}
		// 检查每个 Pod 是否需要被驱逐。
		evictedPods := m.localStorageEviction(podsOnNode, statsFunc)
		evicted = append(evicted, evictedPods...)
	}
	return evicted, nil
}
```

##### Execute

```go
// Execute 检查是否需要进行驱逐操作，并返回应该驱逐的 Pod 列表。
func (m *managerImpl) Execute(ctx context.Context) ([]*v1.Pod, error) {
	now := m.clock.Now()
	nodes, err := m.nodeLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %v", err)
	}
	pods, err := m.podLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %v", err)
	}
	// 获取需要进行驱逐的 Pod 列表。
	evictedPods, err := m.getPodsToEvict(ctx, nodes, pods)
	if err != nil {
		return nil, fmt.Errorf("failed to get pods to evict: %v", err)
	}
	// 对需要驱逐的 Pod 进行处理，并返回驱逐的 Pod 列表。
	evicted := []*v1.Pod{}
	for _, pod := range evictedPods {
		// 构建驱逐消息和注释。
		message, annotations := evictionMessage(v1.ResourceEphemeralStorage, pod, statsFunc, m.config.Thresholds, m.observations)
		// 检查是否应该驱逐 Pod。
		if shouldEvictPod(pod, m.config.PodEviction, annotations, now) {
			// 如果 Pod 驱逐成功，则将其添加到驱逐列表中。
			if err := m.evictPod(ctx, pod.Namespace, pod.Name, message, annotations); err != nil {
				klog.ErrorS(err, "Eviction manager: failed to evict pod", "namespace", pod.Namespace, "name", pod.Name)
			} else {
				evicted = append(evicted, pod)
			}
		}
	}
	return evicted, nil
}
```

##### evictPod

```go
// 驱逐 Pod
func (m *managerImpl) evictPod(pod *v1.Pod, gracePeriodOverride int64, message string, annotations map[string]string, condition *v1.PodCondition) bool {
	podName := pod.Name
	namespace := pod.Namespace
	podUID := string(pod.UID)
	uid, err := types.UID(podUID).MarshalText()
	if err != nil {
		klog.ErrorS(err, "Eviction manager: failed to marshal pod UID", "pod", klog.KObj(pod))
		return false
	}
	gracePeriodSeconds := m.config.MaxPodGracePeriodSeconds
	if gracePeriodOverride > 0 && gracePeriodOverride < gracePeriodSeconds {
		gracePeriodSeconds = gracePeriodOverride
	}
	eviction := &v1beta1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Annotations: map[string]string{
				v1.LastProbeTimeAnnotationKey: metav1.Now().Format(time.RFC3339),
			},
		},
		DeleteOptions: &metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriodSeconds,
		},
	}
	if len(message) > 0 {
		eviction.Annotations[v1.EvictionMessageAnnotationKey] = message
	}
	if annotations != nil {
		for key, value := range annotations {
			eviction.Annotations[key] = value
		}
	}
	if condition != nil {
		eviction.DeleteOptions.Preconditions = &metav1.Preconditions{
			UID: uid,
			Conditions: []metav1.Condition{
				{
					Type:               v1.PodScheduled,
					Status:             v1.ConditionTrue,
					LastProbeTime:      metav1.Now(),
					LastTransitionTime: metav1.Now(),
					Reason:             v1.PodReasonUnschedulable,
					Message:            message,
				},
				{
					Type:               v1.PodReady,
					Status:             v1.ConditionFalse,
					LastProbeTime:      metav1.Now(),
					LastTransitionTime: metav1.Now(),
					Reason:             v1.PodReasonContainersNotReady,
					Message:            message,
				},
				{
					Type:               v1.ContainersReady,
					Status:             v1.ConditionFalse,
					LastProbeTime:      metav1.Now(),
					LastTransitionTime: metav1.Now(),
					Reason:             v1.PodReasonContainersNotReady,
					Message:            message,
				},
				*condition,
			},
		}
	}
	err = m.evictionClient.Evictions(namespace).Evict(context.TODO(), eviction)
	if err != nil {
		if apierrors.IsTooManyRequests(err) {
			klog.InfoS("Eviction manager: too many eviction requests, will retry", "pod", klog.KObj(pod), "err", err)
		} else {
			klog.ErrorS(err, "Eviction manager: failed to evict pod", "pod", klog.KObj(pod))
		}
		return false
	}
	klog.InfoS("Eviction manager: pod evicted", "pod", klog.KObj(pod))
	return true
}
```

#### Description

```go
func (m *memoryThresholdNotifier) Description() string {
	var hard, allocatable string
	if isHardEvictionThreshold(m.threshold) { // 判断是否为硬阈值
		hard = "hard "
	} else {
		hard = "soft "
	}
	if isAllocatableEvictionThreshold(m.threshold) { // 判断是否为可分配资源的阈值
		allocatable = "allocatable "
	}
	return fmt.Sprintf("%s%smemory eviction threshold", hard, allocatable) // 返回描述信息
}
```

#### waitForPodsCleanup

```go
// 等待清理 Pod
func (m *managerImpl) waitForPodsCleanup(podCleanedUpFunc PodCleanedUpFunc, pods []*v1.Pod) {
	timeout := m.clock.NewTimer(podCleanupTimeout)
	defer timeout.Stop()
	ticker := m.clock.NewTicker(podCleanupPollFreq)
	defer ticker.Stop()
	for {
		select {
		case <-timeout.C():
			klog.InfoS("Eviction manager: pod cleanup timed out")
			return
		case <-ticker.C():
			remainingPods := podCleanedUpFunc(pods)
			if len(remainingPods) == 0 {
				return
			}
		}
	}
}
```

### IsUnderMemoryPressure

```go
// IsUnderMemoryPressure 判断节点是否处于内存压力状态。
func (m *managerImpl) IsUnderMemoryPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodeMemoryPressure)
}
```

### IsUnderDiskPressure

```go
// IsUnderDiskPressure 判断节点是否处于磁盘压力状态。
func (m *managerImpl) IsUnderDiskPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodeDiskPressure)
}
```

### IsUnderPIDPressure

```go
// IsUnderPIDPressure 判断节点是否处于 PID 压力状态。
func (m *managerImpl) IsUnderPIDPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodePIDPressure)
}
```

