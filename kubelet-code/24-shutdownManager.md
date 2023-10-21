## 简介

Kubelet Shutdown Manager是Kubelet的一个重要组件，用于在节点关闭时管理容器的终止操作。

当节点关闭时，Kubelet Shutdown Manager负责协调容器的终止操作，以确保所有容器都能够正确地终止并释放资源。具体来说，Shutdown Manager会执行以下操作：

1. 停止所有正在运行的容器，并等待它们终止。
2. 如果容器无法终止，则使用强制终止方式终止它们。
3. 等待一段时间，确保所有容器都已经终止。
4. 如果还存在未终止的容器，则记录错误日志并退出。

## Manager

```go
// Manager接口提供了Kubelet用于管理节点关闭的方法。
type Manager interface {
	Admit(attrs *lifecycle.PodAdmitAttributes) lifecycle.PodAdmitResult
	Start() error
	ShutdownStatus() error
}
```

## managerImpl

```go
// managerImpl具有可用于与节点关闭管理器进行交互的函数。
type managerImpl struct {
	logger       klog.Logger
	recorder     record.EventRecorder
	nodeRef      *v1.ObjectReference
	probeManager prober.Manager

	shutdownGracePeriodByPodPriority []kubeletconfig.ShutdownGracePeriodByPodPriority

	getPods        eviction.ActivePodsFunc
	killPodFunc    eviction.KillPodFunc
	syncNodeStatus func()

	dbusCon     dbusInhibiter
	inhibitLock systemd.InhibitLock

	nodeShuttingDownMutex sync.Mutex
	nodeShuttingDownNow   bool

	clock clock.Clock

	enableMetrics bool
	storage       storage
}

// NewManager返回一个新的节点关闭管理器。
func NewManager(conf *Config) (Manager, lifecycle.PodAdmitHandler) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.GracefulNodeShutdown) {
		m := managerStub{}
		return m, m
	}

	shutdownGracePeriodByPodPriority := conf.ShutdownGracePeriodByPodPriority
	// 从原始配置进行迁移
	if !utilfeature.DefaultFeatureGate.Enabled(features.GracefulNodeShutdownBasedOnPodPriority) ||
		len(shutdownGracePeriodByPodPriority) == 0 {
		shutdownGracePeriodByPodPriority = migrateConfig(conf.ShutdownGracePeriodRequested, conf.ShutdownGracePeriodCriticalPods)
	}

	// 如果配置为空，则禁用
	if len(shutdownGracePeriodByPodPriority) == 0 {
		m := managerStub{}
		return m, m
	}

	// 按优先级从低到高排序
	sort.Slice(shutdownGracePeriodByPodPriority, func(i, j int) bool {
		return shutdownGracePeriodByPodPriority[i].Priority < shutdownGracePeriodByPodPriority[j].Priority
	})

	if conf.Clock == nil {
		conf.Clock = clock.RealClock{}
	}
	manager := &managerImpl{
		logger:                           conf.Logger,
		probeManager:                     conf.ProbeManager,
		recorder:                         conf.Recorder,
		nodeRef:                          conf.NodeRef,
		getPods:                          conf.GetPodsFunc,
		killPodFunc:                      conf.KillPodFunc,
		syncNodeStatus:                   conf.SyncNodeStatusFunc,
		shutdownGracePeriodByPodPriority: shutdownGracePeriodByPodPriority,
		clock:                            conf.Clock,
		enableMetrics:                    utilfeature.DefaultFeatureGate.Enabled(features.GracefulNodeShutdownBasedOnPodPriority),
		storage: localStorage{
			Path: filepath.Join(conf.StateDirectory, localStorageStateFile),
		},
	}
	manager.logger.Info("Creating node shutdown manager",
		"shutdownGracePeriodRequested", conf.ShutdownGracePeriodRequested,
		"shutdownGracePeriodCriticalPods", conf.ShutdownGracePeriodCriticalPods,
		"shutdownGracePeriodByPodPriority", shutdownGracePeriodByPodPriority,
	)
	return manager, manager
}
```

### dbusInhibiter

```go
// dbusInhibiter接口定义了与DBus抑制器的交互方法。
type dbusInhibiter interface {
	CurrentInhibitDelay() (time.Duration, error)
	InhibitShutdown() (systemd.InhibitLock, error)
	ReleaseInhibitLock(lock systemd.InhibitLock) error
	ReloadLogindConf() error
	MonitorShutdown() (<-chan bool, error)
	OverrideInhibitDelay(inhibitDelayMax time.Duration) error
}
```

#### DBusCon

```go
type dBusConnector interface {
	Object(dest string, path dbus.ObjectPath) dbus.BusObject // 返回指定目标和路径的 dbus.BusObject 对象
	AddMatchSignal(options ...dbus.MatchOption) error // 添加匹配信号的选项并返回错误（如果有）
	Signal(ch chan<- *dbus.Signal) // 向指定通道发送 dbus.Signal 信号
}

type DBusCon struct {
	SystemBus dBusConnector
}

// DBusCon是一个用于与DBus通信的结构体，包含了SystemBus字段。

func NewDBusCon() (*DBusCon, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	return &DBusCon{
		SystemBus: conn,
	}, nil
}

// NewDBusCon函数用于创建一个新的DBusCon对象，并返回该对象的指针和可能的错误。

func (bus *DBusCon) CurrentInhibitDelay() (time.Duration, error) {
	// CurrentInhibitDelay函数返回当前的抑制延迟时间值。

	obj := bus.SystemBus.Object(logindService, logindObject)
	res, err := obj.GetProperty(logindInterface + ".InhibitDelayMaxUSec")
	if err != nil {
		return 0, fmt.Errorf("failed reading InhibitDelayMaxUSec property from logind: %w", err)
	}

	delay, ok := res.Value().(uint64)
	if !ok {
		return 0, fmt.Errorf("InhibitDelayMaxUSec from logind is not a uint64 as expected")
	}

	// InhibitDelayMaxUSec is in microseconds
	duration := time.Duration(delay) * time.Microsecond
	return duration, nil
}

// InhibitLock是在调用InhibitShutdown()时创建的systemd抑制器后获得的锁。

func (bus *DBusCon) InhibitShutdown() (InhibitLock, error) {
	// InhibitShutdown函数通过调用logind的Inhibit()方法创建一个systemd抑制器，并返回抑制器的锁。

	obj := bus.SystemBus.Object(logindService, logindObject)
	what := "shutdown"
	who := "kubelet"
	why := "Kubelet needs time to handle node shutdown"
	mode := "delay"

	call := obj.Call("org.freedesktop.login1.Manager.Inhibit", 0, what, who, why, mode)
	if call.Err != nil {
		return InhibitLock(0), fmt.Errorf("failed creating systemd inhibitor: %w", call.Err)
	}

	var fd uint32
	err := call.Store(&fd)
	if err != nil {
		return InhibitLock(0), fmt.Errorf("failed storing inhibit lock file descriptor: %w", err)
	}

	return InhibitLock(fd), nil
}

// ReleaseInhibitLock释放底层的抑制锁，从而导致关闭操作开始。

func (bus *DBusCon) ReleaseInhibitLock(lock InhibitLock) error {
	// ReleaseInhibitLock函数释放底层的抑制锁，从而导致关闭操作开始。

	err := syscall.Close(int(lock))

	if err != nil {
		return fmt.Errorf("unable to close systemd inhibitor lock: %w", err)
	}

	return nil
}

// ReloadLogindConf使用dbus发送SIGHUP信号给systemd-logind服务，使其重新加载配置。

func (bus *DBusCon) ReloadLogindConf() error {
	// ReloadLogindConf函数使用dbus发送SIGHUP信号给systemd-logind服务，使其重新加载配置。

	systemdService := "org.freedesktop.systemd1"
	systemdObject := "/org/freedesktop/systemd1"
	systemdInterface := "org.freedesktop.systemd1.Manager"

	obj := bus.SystemBus.Object(systemdService, dbus.ObjectPath(systemdObject))
	unit := "systemd-logind.service"
	who := "all"
	var signal int32 = 1 // SIGHUP

	call := obj.Call(systemdInterface+".KillUnit", 0, unit, who, signal)
	if call.Err != nil {
		return fmt.Errorf("unable to reload logind conf: %w", call.Err)
	}

	return nil
}

// MonitorShutdown通过监听"PrepareForShutdown" logind事件来检测节点关闭。

func (bus *DBusCon) MonitorShutdown() (<-chan bool, error) {
	// MonitorShutdown函数通过监听"PrepareForShutdown" logind事件来检测节点关闭。

	err := bus.SystemBus.AddMatchSignal(dbus.WithMatchInterface(logindInterface), dbus.WithMatchMember("PrepareForShutdown"), dbus.WithMatchObjectPath("/org/freedesktop/login1"))

	if err != nil {
		return nil, err
	}

	busChan := make(chan *dbus.Signal, 1)
	bus.SystemBus.Signal(busChan)

	shutdownChan := make(chan bool, 1)

	go func() {
		for {
			event, ok := <-busChan
			if !ok {
				close(shutdownChan)
				return
			}
			if event == nil || len(event.Body) == 0 {
				klog.ErrorS(nil, "Failed obtaining shutdown event, PrepareForShutdown event was empty")
				continue
			}
			shutdownActive, ok := event.Body[0].(bool)
			if !ok {
				klog.ErrorS(nil, "Failed obtaining shutdown event, PrepareForShutdown event was not bool type as expected")
				continue
			}
			shutdownChan <- shutdownActive
		}
	}()

	return shutdownChan, nil
}

// OverrideInhibitDelay将一个配置文件写入logind，覆盖InhibitDelayMaxSec为所需的值。

func (bus *DBusCon) OverrideInhibitDelay(inhibitDelayMax time.Duration) error {
	// OverrideInhibitDelay函数将一个配置文件写入logind，覆盖InhibitDelayMaxSec为所需的值。

	err := os.MkdirAll(logindConfigDirectory, 0755)
	if err != nil {
		return fmt.Errorf("failed creating %v directory: %w", logindConfigDirectory, err)
	}

	// This attempts to set the `InhibitDelayMaxUSec` dbus property of logind which is MaxInhibitDelay measured in microseconds.
	// The corresponding logind config file property is named `InhibitDelayMaxSec` and is measured in seconds which is set via logind.conf config.
	// Refer to https://www.freedesktop.org/software/systemd/man/logind.conf.html for more details.

	inhibitOverride := fmt.Sprintf(`# Kubelet logind override
	[Login]
	InhibitDelayMaxSec=%.0f
	`, inhibitDelayMax.Seconds())

	logindOverridePath := filepath.Join(logindConfigDirectory, kubeletLogindConf)
	if err := os.WriteFile(logindOverridePath, []byte(inhibitOverride), 0644); err != nil {
		return fmt.Errorf("failed writing logind shutdown inhibit override file %v: %w", logindOverridePath, err)
	}

	return nil
}

// 一些常量定义
const (
	logindConfigDirectory = "/etc/systemd/logind.conf.d/"
	kubeletLogindConf     = "99-kubelet.conf"
)
```

### storage

```go
// 存储接口定义了存储器的方法。
type storage interface {
	Store(data interface{}) (err error)
	Load(data interface{}) (err error)
}
```

#### localStorage

```go
// localStorage是存储器的实现。
type localStorage struct {
	Path string
}

func (l localStorage) Store(data interface{}) (err error) {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return atomicWrite(l.Path, b, 0644)
}

func (l localStorage) Load(data interface{}) (err error) {
	b, err := os.ReadFile(l.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, data)
}

func timestamp(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}

// atomicWrite原子地将数据写入到由文件名指定的文件中。
func atomicWrite(filename string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(filename), ".tmp-"+filepath.Base(filename))
	if err != nil {
		return err
	}
	err = os.Chmod(f.Name(), perm)
	if err != nil {
		f.Close()
		return err
	}
	n, err := f.Write(data)
	if err != nil {
		f.Close()
		return err
	}
	if n < len(data) {
		f.Close()
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}
```

### Admit

```go
// Admit函数根据节点是否正在关闭来拒绝或接受所有Pod。
func (m *managerImpl) Admit(attrs *lifecycle.PodAdmitAttributes) lifecycle.PodAdmitResult {
	nodeShuttingDown := m.ShutdownStatus() != nil // 检查节点是否正在关闭

	if nodeShuttingDown {
		// 如果节点正在关闭，则拒绝所有Pod的调度
		return lifecycle.PodAdmitResult{
			Admit:   false,
			Reason:  nodeShutdownNotAdmittedReason,
			Message: nodeShutdownNotAdmittedMessage,
		}
	}

	// 如果节点没有正在关闭，则允许所有Pod的调度
	return lifecycle.PodAdmitResult{Admit: true}
}
```

### ShutdownStatus

```go
// ShutdownStatus在节点当前正在关闭时返回错误。
func (m *managerImpl) ShutdownStatus() error {
	m.nodeShuttingDownMutex.Lock()         // 加锁以确保并发安全性
	defer m.nodeShuttingDownMutex.Unlock() // 解锁

	if m.nodeShuttingDownNow { // 如果节点正在关闭中
		return fmt.Errorf("node is shutting down") // 返回错误
	}
	return nil
}
```

### Start

```go
// Start启动节点关机管理器并开始监视节点的关机事件。
func (m *managerImpl) Start() error {
	stop, err := m.start() // 启动管理器
	if err != nil {
		return err
	}
	go func() {
		for {
			if stop != nil {
				<-stop
			}

			time.Sleep(dbusReconnectPeriod)                                 // 等待一段时间后重新连接
			m.logger.V(1).Info("Restarting watch for node shutdown events") // 记录日志
			stop, err = m.start()                                           // 重新启动管理器
			if err != nil {
				m.logger.Error(err, "Unable to watch the node for shutdown events") // 记录错误日志
			}
		}
	}()

	m.setMetrics() // 设置度量指标
	return nil
}
```

#### start

```go
// start启动节点关机管理器并返回停止通道和错误。
func (m *managerImpl) start() (chan struct{}, error) {
	systemBus, err := systemDbus() // 获取系统DBus连接
	if err != nil {
		return nil, err
	}
	m.dbusCon = systemBus

	currentInhibitDelay, err := m.dbusCon.CurrentInhibitDelay() // 获取当前抑制延迟
	if err != nil {
		return nil, err
	}

	// 如果logind.conf中配置的InhibitDelayMaxUSec小于periodRequested，请尝试将该值更新为periodRequested。
	if periodRequested := m.periodRequested(); periodRequested > currentInhibitDelay {
		err := m.dbusCon.OverrideInhibitDelay(periodRequested) // 覆盖抑制延迟
		if err != nil {
			return nil, fmt.Errorf("unable to override inhibit delay by shutdown manager: %v", err)
		}

		err = m.dbusCon.ReloadLogindConf() // 重新加载logind.conf配置
		if err != nil {
			return nil, err
		}

		// 再次读取当前的抑制延迟，如果覆盖成功，updatedInhibitDelay将等于shutdownGracePeriodRequested。
		updatedInhibitDelay, err := m.dbusCon.CurrentInhibitDelay()
		if err != nil {
			return nil, err
		}

		if periodRequested > updatedInhibitDelay {
			return nil, fmt.Errorf("node shutdown manager was unable to update logind InhibitDelayMaxSec to %v (ShutdownGracePeriod), current value of InhibitDelayMaxSec (%v) is less than requested ShutdownGracePeriod", periodRequested, updatedInhibitDelay)
		}
	}

	err = m.aquireInhibitLock() // 获取抑制锁
	if err != nil {
		return nil, err
	}

	events, err := m.dbusCon.MonitorShutdown() // 监视关机事件
	if err != nil {
		releaseErr := m.dbusCon.ReleaseInhibitLock(m.inhibitLock) // 释放抑制锁
		if releaseErr != nil {
			return nil, fmt.Errorf("failed releasing inhibitLock: %v and failed monitoring shutdown: %v", releaseErr, err)
		}
		return nil, fmt.Errorf("failed to monitor shutdown: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		// 监视关机事件。遵循https://www.freedesktop.org/wiki/Software/systemd/inhibit/中描述的logind抑制延迟模式。
		// 1. 当关机管理器启动时，会获取抑制锁。
		// 2. 当收到关机(true)事件时，处理关机并释放抑制锁。
		// 3. 当收到关机(false)事件时，表示前一个关机已取消。在这种情况下，再次获取抑制锁。
		for {
			select {
			case isShuttingDown, ok := <-events:
				if !ok {
					m.logger.Error(err, "Ended to watching the node for shutdown events") // 记录错误日志
					close(stop)
					return
				}
				m.logger.V(1).Info("Shutdown manager detected new shutdown event, isNodeShuttingDownNow", "event", isShuttingDown)

				var shutdownType string
				if isShuttingDown {
					shutdownType = "shutdown"
				} else {
					shutdownType = "cancelled"
				}
				m.logger.V(1).Info("Shutdown manager detected new shutdown event", "event", shutdownType)

				if isShuttingDown {
					m.recorder.Event(m.nodeRef, v1.EventTypeNormal, kubeletevents.NodeShutdown, "Shutdown manager detected shutdown event") // 记录事件
				} else {
					m.recorder.Event(m.nodeRef, v1.EventTypeNormal, kubeletevents.NodeShutdown, "Shutdown manager detected shutdown cancellation") // 记录事件
				}

				m.nodeShuttingDownMutex.Lock() // 加锁
				m.nodeShuttingDownNow = isShuttingDown
				m.nodeShuttingDownMutex.Unlock() // 解锁

				if isShuttingDown {
					// 更新节点状态和就绪条件
					go m.syncNodeStatus()

					m.processShutdownEvent()
				} else {
					m.aquireInhibitLock() // 获取抑制锁
				}
			}
		}
	}()
	return stop, nil
}
```

##### periodRequested

```go
// periodRequested返回请求的时间段。
func (m *managerImpl) periodRequested() time.Duration {
	var sum int64
	for _, period := range m.shutdownGracePeriodByPodPriority {
		sum += period.ShutdownGracePeriodSeconds
	}
	return time.Duration(sum) * time.Second
}
```

##### aquireInhibitLock

```go
// aquireInhibitLock获取抑制锁。
func (m *managerImpl) aquireInhibitLock() error {
	lock, err := m.dbusCon.InhibitShutdown() // 抑制关机
	if err != nil {
		return err
	}
	if m.inhibitLock != 0 {
		m.dbusCon.ReleaseInhibitLock(m.inhibitLock) // 释放抑制锁
	}
	m.inhibitLock = lock
	return nil
}
```

##### processShutdownEvent

```go
// processShutdownEvent处理关机事件。
func (m *managerImpl) processShutdownEvent() error {
	m.logger.V(1).Info("Shutdown manager processing shutdown event") // 记录日志
	activePods := m.getPods()                                        // 获取活动的Pod列表

	defer func() {
		m.dbusCon.ReleaseInhibitLock(m.inhibitLock)                                                            // 释放抑制锁
		m.logger.V(1).Info("Shutdown manager completed processing shutdown event, node will shutdown shortly") // 记录日志
	}()

	if m.enableMetrics && m.storage != nil {
		startTime := time.Now()
		err := m.storage.Store(state{
			StartTime: startTime,
		})
		if err != nil {
			m.logger.Error(err, "Failed to store graceful shutdown state") // 记录错误日志
		}
		metrics.GracefulShutdownStartTime.Set(timestamp(startTime))
		metrics.GracefulShutdownEndTime.Set(0)

		defer func() {
			endTime := time.Now()
			err := m.storage.Store(state{
				StartTime: startTime,
				EndTime:   endTime,
			})
			if err != nil {
				m.logger.Error(err, "Failed to store graceful shutdown state") // 记录错误日志
			}
			metrics.GracefulShutdownStartTime.Set(timestamp(endTime))
		}()
	}

	groups := groupByPriority(m.shutdownGracePeriodByPodPriority, activePods) // 按优先级将Pod分组
	for _, group := range groups {
		// 如果某个范围内没有Pod，则不等待该优先级范围内的Pod。
		if len(group.Pods) == 0 {
			continue
		}

		var wg sync.WaitGroup
		wg.Add(len(group.Pods))
		for _, pod := range group.Pods {
			go func(pod *v1.Pod, group podShutdownGroup) {
				defer wg.Done()

				gracePeriodOverride := group.ShutdownGracePeriodSeconds

				// 如果Pod的规范指定的终止gracePeriod小于计算得到的gracePeriodOverride，则使用Pod规范的终止gracePeriod。
				if pod.Spec.TerminationGracePeriodSeconds != nil && *pod.Spec.TerminationGracePeriodSeconds <= gracePeriodOverride {
					gracePeriodOverride = *pod.Spec.TerminationGracePeriodSeconds
				}

				m.logger.V(1).Info("Shutdown manager killing pod with gracePeriod", "pod", klog.KObj(pod), "gracePeriod", gracePeriodOverride) // 记录日志

				if err := m.killPodFunc(pod, false, &gracePeriodOverride, func(status *v1.PodStatus) {
					// 将Pod状态设置为失败（除非它已经处于成功的终端阶段）
					if status.Phase != v1.PodSucceeded {
						status.Phase = v1.PodFailed
					}
					status.Message = nodeShutdownMessage
					status.Reason = nodeShutdownReason
					if utilfeature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
						podutil.UpdatePodCondition(status, &v1.PodCondition{
							Type:    v1.DisruptionTarget,
							Status:  v1.ConditionTrue,
							Reason:  v1.PodReasonTerminationByKubelet,
							Message: nodeShutdownMessage,
						})
					}
				}); err != nil {
					m.logger.V(1).Info("Shutdown manager failed killing pod", "pod", klog.KObj(pod), "err", err) // 记录日志
				} else {
					m.logger.V(1).Info("Shutdown manager killed pod", "pod", klog.KObj(pod)) // 记录日志
				}
			}(pod, group)
		}
		wg.Wait()
	}

	return nil
}
```

##### getPods

```go
// getPods返回当前活动的Pod列表。
func (m *managerImpl) getPods() []*v1.Pod {
	pods, err := m.podLister.List(labels.Everything())
	if err != nil {
		m.logger.Error(err, "Failed to list pods") // 记录错误日志
		return nil
	}
	return pods
}

```

##### groupByPriority

```go
// groupByPriority根据Pod的优先级将Pod分组。
func groupByPriority(podShutdownByPriority []podShutdownByPriority, pods []*v1.Pod) []podShutdownGroup {
	groups := make([]podShutdownGroup, len(podShutdownByPriority))

	for i, priorityGroup := range podShutdownByPriority {
		group := podShutdownGroup{
			ShutdownGracePeriodSeconds: priorityGroup.ShutdownGracePeriodSeconds,
		}

		for _, pod := range pods {
			if isPodInPriorityGroup(pod, priorityGroup.PriorityRange) {
				group.Pods = append(group.Pods, pod)
			}
		}

		groups[i] = group
	}

	return groups
}
```

##### isPodInPriorityGroup

```go
// isPodInPriorityGroup检查Pod是否属于给定的优先级范围。
func isPodInPriorityGroup(pod *v1.Pod, priorityRange priorityRange) bool {
	priority := getPodPriority(pod)

	if priority >= priorityRange.Min && priority <= priorityRange.Max {
		return true
	}

	return false
}
```

##### getPodPriority

```go
// getPodPriority返回Pod的优先级。
func getPodPriority(pod *v1.Pod) int32 {
	if pod.Spec.Priority != nil {
		return *pod.Spec.Priority
	}
	return 0
}
```

#### killPodFunc

```go
// killPodFunc是用于杀死Pod的函数。
type killPodFunc func(pod *v1.Pod, gracePeriodZero bool, gracePeriodOverride *int64, updateStatus func(*v1.PodStatus)) error

// killPodFunc是用于杀死Pod的默认函数。
func killPod(pod *v1.Pod, gracePeriodZero bool, gracePeriodOverride *int64, updateStatus func(*v1.PodStatus)) error {
	return kubeletapi.EvictPod(pod, gracePeriodZero, gracePeriodOverride, updateStatus)
}

// podShutdownByPriority是Pod优先级和关机优先级之间的映射。
type podShutdownByPriority struct {
	PriorityRange              priorityRange
	ShutdownGracePeriodSeconds int64
}

// priorityRange是优先级范围。
type priorityRange struct {
	Min int32
	Max int32
}

// podShutdownGroup是具有相同关机优先级的Pod组。
type podShutdownGroup struct {
	ShutdownGracePeriodSeconds int64
	Pods                       []*v1.Pod
}

// state是优雅关机状态的结构。
type state struct {
	StartTime time.Time
	EndTime   time.Time
}

// gracePeriodOverride用于覆盖Pod的终止gracePeriod。
func (m *managerImpl) killPodFunc(pod *v1.Pod, gracePeriodZero bool, gracePeriodOverride *int64, updateStatus func(*v1.PodStatus)) error {
	return killPod(pod, gracePeriodZero, gracePeriodOverride, updateStatus)
}
```

