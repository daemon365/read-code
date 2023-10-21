## 简介


kubelet是Kubernetes集群中的一个重要组件，负责在每个节点上管理容器的生命周期和资源。kubelet通过与容器运行时（如Docker、containerd等）通信来创建、启动、监视和销毁容器。它还负责监控节点上的资源使用情况，并与Kubernetes控制平面交互，确保集群中的容器状态与期望状态保持一致。

在kubelet的设计中，PluginManager是一个关键的组件，用于管理和调用各种插件。PluginManager允许用户通过自定义插件来扩展kubelet的功能，以满足不同的需求。

插件是由用户提供的可执行文件或脚本，它们与kubelet进行通信并执行特定的任务。插件可以用于各种用途，如网络插件、存储插件、设备插件等。通过插件机制，用户可以自定义容器网络、存储和其他底层资源的行为。

PluginManager负责加载、初始化和管理插件。它在kubelet启动时扫描指定目录（默认为`/usr/libexec/kubernetes/kubelet-plugins`）下的插件，并将它们注册到kubelet中。注册后，插件就可以通过特定的接口与kubelet进行通信，并根据需要执行相应的任务。

通过使用PluginManager，用户可以根据自己的需求编写插件，并将它们集成到kubelet中，以扩展和定制Kubernetes集群的功能。这为用户提供了一种灵活的方式来满足特定的需求，例如自定义网络模型、使用特定的存储后端等。

## PluginManager

```go
// PluginManager 运行一组异步循环，确定需要注册/注销的插件，并进行相应操作。
type PluginManager interface {
	// 启动插件管理器及其控制的所有异步循环
	Run(sourcesReady config.SourcesReady, stopCh <-chan struct{})

	// 为特定的插件类型添加给定的插件处理程序，将其添加到实际的世界状态缓存中，
	// 以便在插件注册/注销期间传递给期望的世界状态缓存
	AddHandler(pluginType string, pluginHandler cache.PluginHandler)
}
```





## pluginManager

```go
// pluginManager 实现 PluginManager 接口
type pluginManager struct {
	// desiredStateOfWorldPopulator（插件监听器）运行异步定期循环以填充 desiredStateOfWorld
	desiredStateOfWorldPopulator *pluginwatcher.Watcher

	// reconciler 运行异步定期循环，通过触发操作执行器的注册和注销操作，
	// 将 desiredStateOfWorld 与 actualStateOfWorld 进行协调
	reconciler reconciler.Reconciler

	// actualStateOfWorld 是一个数据结构，包含了根据管理器的实际状态的世界，
	// 即注册了哪些插件。此数据结构在成功完成协调器触发的注册和注销操作后填充。
	actualStateOfWorld cache.ActualStateOfWorld

	// desiredStateOfWorld 是一个数据结构，包含了插件管理器的期望状态的世界，
	// 即注册了哪些插件。该数据结构由期望状态世界填充器（插件监听器）填充。
	desiredStateOfWorld cache.DesiredStateOfWorld
}

var _ PluginManager = &pluginManager{}

// NewPluginManager 返回实现 PluginManager 接口的新实例。
func NewPluginManager(sockDir string, recorder record.EventRecorder) PluginManager {
	// 创建实际状态世界缓存和期望状态世界缓存
	asw := cache.NewActualStateOfWorld()
	dsw := cache.NewDesiredStateOfWorld()

	// 创建协调器，并传递操作执行器、睡眠间隔、期望状态世界缓存和实际状态世界缓存
	reconciler := reconciler.NewReconciler(
		operationexecutor.NewOperationExecutor(
			operationexecutor.NewOperationGenerator(recorder),
		),
		loopSleepDuration,
		dsw,
		asw,
	)

	// 创建插件管理器实例，包括期望状态世界填充器、协调器、期望状态世界缓存和实际状态世界缓存
	pm := &pluginManager{
		desiredStateOfWorldPopulator: pluginwatcher.NewWatcher(sockDir, dsw),
		reconciler:                   reconciler,
		desiredStateOfWorld:          dsw,
		actualStateOfWorld:           asw,
	}
	return pm
}
```

### Run

```go
func (pm *pluginManager) Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()

	// 启动期望状态世界填充器（插件监听器）
	if err := pm.desiredStateOfWorldPopulator.Start(stopCh); err != nil {
		klog.ErrorS(err, "The desired_state_of_world populator (plugin watcher) starts failed!")
		return
	}

	klog.V(2).InfoS("The desired_state_of_world populator (plugin watcher) starts")

	klog.InfoS("Starting Kubelet Plugin Manager")
	go pm.reconciler.Run(stopCh)

	// 注册度量指标
	metrics.Register(pm.actualStateOfWorld, pm.desiredStateOfWorld)

	// 等待停止信号
	<-stopCh
	klog.InfoS("Shutting down Kubelet Plugin Manager")
}
```

### AddHandler

```go
func (pm *pluginManager) AddHandler(pluginType string, handler cache.PluginHandler) {
	// 添加插件处理程序到协调器
	pm.reconciler.AddHandler(pluginType, handler)
}
```

## PluginHandler

```go
// PluginHandler 是插件监视器 API 的客户端需要实现的接口，用于消费插件
// PluginHandler 遵循以下简单的状态机：
//
//	                       +--------------------------------------+
//	                       |            ReRegistration            |
//	                       | Socket created with same plugin name |
//	                       |                                      |
//	                       |                                      |
//	  Socket Created       v                                      +        Socket Deleted
//	+------------------> Validate +---------------------------> Register +------------------> DeRegister
//	                       +                                      +                              +
//	                       |                                      |                              |
//	                       | Error                                | Error                        |
//	                       |                                      |                              |
//	                       v                                      v                              v
//	                      Out                                    Out                            Out
//
// 对于每个 *插件名称*，插件监视器模块严格按照此状态机顺序进行处理。
// 例如：如果正在注册插件 foo，则在 Register("foo") 调用返回之前，不会收到插件 foo 的 DeRegister 调用。
// 也不会收到 Validate("foo", "Different endpoint", ...) 调用，直到 Register("foo") 调用返回。
//
// ReRegistration：使用相同的插件名称创建了新的套接字，通常用于插件更新
// 例如：名称为 foo 的插件注册到 foo.com/foo-1.9.7，稍后名称为 foo 的插件注册到 foo.com/foo-1.9.9
//
// DeRegistration：当 ReRegistration 发生时，只有新套接字的删除才会触发 DeRegister 调用
type PluginHandler interface {
	// ValidatePlugin 如果由潜在插件提供的信息错误（不支持的版本等），则返回错误。
	ValidatePlugin(pluginName string, endpoint string, versions []string) error
	// RegisterPlugin 被调用以使插件可以被任何插件消费者注册。
	// 在此处遇到的错误仍然可以通知给插件。
	RegisterPlugin(pluginName, endpoint string, versions []string) error
	// DeRegisterPlugin 在插件监视器观察到套接字已被删除时调用。
	DeRegisterPlugin(pluginName string)
}
```

## Reconciler

```go
// Reconciler 运行定期循环，通过触发注册和注销操作来协调期望状态和实际状态。
// 还提供了一种添加插件类型处理程序的方式。
type Reconciler interface {
	// Run 启动协调循环，定期执行检查插件是否正确注册或注销的操作。
	// 如果不正确，则会触发注册/注销操作进行修复。
	Run(stopCh <-chan struct{})

	// AddHandler 添加给定的插件处理程序到特定的插件类型，将其添加到实际状态缓存中。
	AddHandler(pluginType string, pluginHandler cache.PluginHandler)
}
```

### reconciler

```go
// NewReconciler 返回 Reconciler 的新实例。
//
// operationExecutor - 用于安全地触发注册/注销操作（防止在同一套接字路径上触发多个操作）
//
// loopSleepDuration - 协调循环之间的睡眠时间
//
// desiredStateOfWorld - 包含期望状态的缓存
//
// actualStateOfWorld - 包含实际状态的缓存
func NewReconciler(
	operationExecutor operationexecutor.OperationExecutor,
	loopSleepDuration time.Duration,
	desiredStateOfWorld cache.DesiredStateOfWorld,
	actualStateOfWorld cache.ActualStateOfWorld) Reconciler {
	return &reconciler{
		operationExecutor:   operationExecutor,
		loopSleepDuration:   loopSleepDuration,
		desiredStateOfWorld: desiredStateOfWorld,
		actualStateOfWorld:  actualStateOfWorld,
		handlers:            make(map[string]cache.PluginHandler),
	}
}

type reconciler struct {
	operationExecutor   operationexecutor.OperationExecutor
	loopSleepDuration   time.Duration
	desiredStateOfWorld cache.DesiredStateOfWorld
	actualStateOfWorld  cache.ActualStateOfWorld
	handlers            map[string]cache.PluginHandler
	sync.RWMutex
}

var _ Reconciler = &reconciler{}
```

### Run

```go
func (rc *reconciler) Run(stopCh <-chan struct{}) {
	wait.Until(func() {
		rc.reconcile()
	},
		rc.loopSleepDuration,
		stopCh)
}
```

#### reconcile

```go
func (rc *reconciler) reconcile() {
	// 先触发注销操作，再触发注册操作

	// 确保应注销的插件已注销。
	for _, registeredPlugin := range rc.actualStateOfWorld.GetRegisteredPlugins() {
		unregisterPlugin := false
		if !rc.desiredStateOfWorld.PluginExists(registeredPlugin.SocketPath) {
			unregisterPlugin = true
		} else {
			// 还需要注销实际状态和期望状态缓存中都存在，但时间戳不匹配的插件。
			// 遍历期望状态缓存中的插件，检查是否有具有相同套接字路径但时间戳不同的插件。
			for _, dswPlugin := range rc.desiredStateOfWorld.GetPluginsToRegister() {
				if dswPlugin.SocketPath == registeredPlugin.SocketPath && dswPlugin.Timestamp != registeredPlugin.Timestamp {
					klog.V(5).InfoS("找到更新版本的插件，首先注销插件然后重新注册", "plugin", registeredPlugin)
					unregisterPlugin = true
					break
				}
			}
		}

		if unregisterPlugin {
			klog.V(5).InfoS("开始 operationExecutor.UnregisterPlugin", "plugin", registeredPlugin)
			err := rc.operationExecutor.UnregisterPlugin(registeredPlugin, rc.actualStateOfWorld)
			if err != nil &&
				!goroutinemap.IsAlreadyExists(err) &&
				!exponentialbackoff.IsExponentialBackoff(err) {
				// 忽略 goroutinemap.IsAlreadyExists 和 exponentialbackoff.IsExponentialBackoff 错误，这些错误是预期的。
				// 记录所有其他错误。
				klog.ErrorS(err, "OperationExecutor.UnregisterPlugin 失败", "plugin", registeredPlugin)
			}
			if err == nil {
				klog.V(1).InfoS("OperationExecutor.UnregisterPlugin 开始", "plugin", registeredPlugin)
			}
		}
	}

	// 确保应注册的插件已注册
	for _, pluginToRegister := range rc.desiredStateOfWorld.GetPluginsToRegister() {
		if !rc.actualStateOfWorld.PluginExistsWithCorrectTimestamp(pluginToRegister) {
			klog.V(5).InfoS("开始 operationExecutor.RegisterPlugin", "plugin", pluginToRegister)
			err := rc.operationExecutor.RegisterPlugin(pluginToRegister.SocketPath, pluginToRegister.Timestamp, rc.getHandlers(), rc.actualStateOfWorld)
			if err != nil &&
				!goroutinemap.IsAlreadyExists(err) &&
				!exponentialbackoff.IsExponentialBackoff(err) {
				// 忽略 goroutinemap.IsAlreadyExists 和 exponentialbackoff.IsExponentialBackoff 错误，这些错误是预期的。
				klog.ErrorS(err, "OperationExecutor.RegisterPlugin 失败", "plugin", pluginToRegister)
			}
			if err == nil {
				klog.V(1).InfoS("OperationExecutor.RegisterPlugin 开始", "plugin", pluginToRegister)
			}
		}
	}
}
```

##### getHandlers

```go
func (rc *reconciler) getHandlers() map[string]cache.PluginHandler {
	rc.RLock()
	defer rc.RUnlock()

	var copyHandlers = make(map[string]cache.PluginHandler)
	for pluginType, handler := range rc.handlers {
		copyHandlers[pluginType] = handler
	}
	return copyHandlers
}
```

### AddHandler

```go
func (rc *reconciler) AddHandler(pluginType string, pluginHandler cache.PluginHandler) {
	rc.Lock()
	defer rc.Unlock()

	rc.handlers[pluginType] = pluginHandler
}
```

## DesiredStateOfWorld

```go
// DesiredStateOfWorld 定义了 kubelet 插件管理器期望的世界状态缓存的一组线程安全操作。
// 该缓存包含一个映射，将插件的套接字文件路径映射到连接到该节点的所有插件的插件信息。
type DesiredStateOfWorld interface {
	// AddOrUpdatePlugin 将给定的插件添加到缓存中（如果尚不存在）。
	// 如果插件已存在于缓存中，则将更新缓存中 PluginInfo 对象的时间戳。
	// 如果 socketPath 为空，则返回错误。
	AddOrUpdatePlugin(socketPath string) error

	// RemovePlugin 从期望的世界状态中删除具有给定套接字路径的插件。
	// 如果给定套接字路径的插件不存在，则不执行任何操作。
	RemovePlugin(socketPath string)

	// GetPluginsToRegister 生成并返回当前期望的世界状态中的插件列表。
	GetPluginsToRegister() []PluginInfo

	// PluginExists 检查给定的套接字路径是否存在于当前期望的世界状态缓存中。
	PluginExists(socketPath string) bool
}
```

### desiredStateOfWorld

```go
// NewDesiredStateOfWorld 返回 DesiredStateOfWorld 的新实例。
func NewDesiredStateOfWorld() DesiredStateOfWorld {
	return &desiredStateOfWorld{
		socketFileToInfo: make(map[string]PluginInfo),
	}
}

type desiredStateOfWorld struct {
	// socketFileToInfo 是一个包含成功注册的插件集合的映射。
	// 键是插件的套接字文件路径，值是 PluginInfo 对象。
	socketFileToInfo map[string]PluginInfo
	sync.RWMutex
}

var _ DesiredStateOfWorld = &desiredStateOfWorld{}
```

### AddOrUpdatePlugin

```go
func (dsw *desiredStateOfWorld) AddOrUpdatePlugin(socketPath string) error {
	dsw.Lock()
	defer dsw.Unlock()

	if socketPath == "" {
		return fmt.Errorf("socket path is empty")
	}
	if _, ok := dsw.socketFileToInfo[socketPath]; ok {
		klog.V(2).InfoS("Plugin exists in desired state cache, timestamp will be updated", "path", socketPath)
	}

	// 更新 PluginInfo 对象。
	// 需要注意的是，我们只更新期望状态中的时间戳，而不是实际状态，
	// 因为在 reconciler 中，我们需要检查实际状态中的插件版本是否与期望状态中的插件版本相同。
	dsw.socketFileToInfo[socketPath] = PluginInfo{
		SocketPath: socketPath,
		Timestamp:  time.Now(),
	}
	return nil
}
```

### RemovePlugin

```go
func (dsw *desiredStateOfWorld) RemovePlugin(socketPath string) {
	dsw.Lock()
	defer dsw.Unlock()

	delete(dsw.socketFileToInfo, socketPath)
}
```

### GetPluginsToRegister

```go
func (dsw *desiredStateOfWorld) GetPluginsToRegister() []PluginInfo {
	dsw.RLock()
	defer dsw.RUnlock()

	pluginsToRegister := []PluginInfo{}
	for _, pluginInfo := range dsw.socketFileToInfo {
		pluginsToRegister = append(pluginsToRegister, pluginInfo)
	}
	return pluginsToRegister
}
```

### PluginExists

```go
func (dsw *desiredStateOfWorld) PluginExists(socketPath string) bool {
	dsw.RLock()
	defer dsw.RUnlock()

	_, exists := dsw.socketFileToInfo[socketPath]
	return exists
}
```

### PluginInfo

```go
// PluginInfo 存储插件的信息。
type PluginInfo struct {
    SocketPath string // 插件的套接字路径
    Timestamp time.Time // 时间戳
    Handler PluginHandler // 插件处理程序
    Name string // 插件名称
}
```

#### GenerateMsgDetailed

```go
// GenerateMsgDetailed 为要注册的插件生成详细的消息，可以在日志中使用。
// 消息的格式遵循模式 "<prefixMsg> <plugin details> <suffixMsg>"
func (plugin *PluginInfo) GenerateMsgDetailed(prefixMsg, suffixMsg string) (detailedMsg string) {
	detailedStr := fmt.Sprintf("(plugin details: %v)", plugin)
	return generatePluginMsgDetailed(prefixMsg, suffixMsg, plugin.SocketPath, detailedStr)
}
```

##### generatePluginMsgDetailed

```go
// generatePluginMsgDetailed 为日志生成详细的错误消息
func generatePluginMsgDetailed(prefixMsg, suffixMsg, socketPath, details string) (detailedMsg string) {
	return fmt.Sprintf("%v for plugin at %q %v %v", prefixMsg, socketPath, details, suffixMsg)
}
```

#### GenerateMsg

```go
// GenerateMsg 为要注册的插件生成简单和详细的消息，既用户友好又可以在日志中使用。
// 消息的格式遵循模式 "<prefixMsg> <plugin details> <suffixMsg>"。
func (plugin *PluginInfo) GenerateMsg(prefixMsg, suffixMsg string) (simpleMsg, detailedMsg string) {
	detailedStr := fmt.Sprintf("(plugin details: %v)", plugin)
	return generatePluginMsg(prefixMsg, suffixMsg, plugin.SocketPath, detailedStr)
}
```

##### generatePluginMsg

```go
// generatePluginMsg 为事件生成简化的错误消息和为日志生成详细的错误消息
func generatePluginMsg(prefixMsg, suffixMsg, socketPath, details string) (simpleMsg, detailedMsg string) {
	simpleMsg = fmt.Sprintf("%v for plugin at %q %v", prefixMsg, socketPath, suffixMsg)
	return simpleMsg, generatePluginMsgDetailed(prefixMsg, suffixMsg, socketPath, details)
}
```

#### GenerateErrorDetailed

```go
// GenerateErrorDetailed 为要注册的插件生成详细的错误，可以在日志中使用。
// 错误消息的格式遵循模式 "<prefixMsg> <plugin details>: <err> "，
func (plugin *PluginInfo) GenerateErrorDetailed(prefixMsg string, err error) (detailedErr error) {
	return fmt.Errorf(plugin.GenerateMsgDetailed(prefixMsg, errSuffix(err)))
}
```

#### GenerateError

```go
// GenerateError 为要注册的插件生成简单和详细的错误，既用户友好又可以在日志中使用。
// 错误消息的格式遵循模式 "<prefixMsg> <plugin details>: <err> "。
func (plugin *PluginInfo) GenerateError(prefixMsg string, err error) (simpleErr, detailedErr error) {
	simpleMsg, detailedMsg := plugin.GenerateMsg(prefixMsg, errSuffix(err))
	return fmt.Errorf(simpleMsg), fmt.Errorf(detailedMsg)
}
```

##### errSuffix

```go
// 如果 err 存在，则生成格式为 ": <err>" 的错误字符串
func errSuffix(err error) string {
	errStr := ""
	if err != nil {
		errStr = fmt.Sprintf(": %v", err)
	}
	return errStr
}
```

## ActualStateOfWorld

```go
// ActualStateOfWorld 定义了 kubelet 插件管理器实际状态的一组线程安全操作。
// 该缓存包含一个从套接字文件路径到插件信息的映射，其中包含连接到该节点的所有插件。
type ActualStateOfWorld interface {

	// GetRegisteredPlugins 生成并返回当前实际状态中成功注册的插件列表。
	GetRegisteredPlugins() []PluginInfo

	// AddPlugin 在缓存中添加给定的插件。
	// 如果 PluginInfo 对象的 socketPath 为空，将返回错误。
	// 需要注意的是，这与期望状态缓存的 AddOrUpdatePlugin 不同，
	// 因为在实际状态缓存中，如果时间戳不匹配，不会出现更新现有插件的情况。
	// 这是因为在 reconciler 中，应该先取消注册插件并从实际状态缓存中删除，
	// 然后再将其与新的时间戳重新添加到实际状态缓存中。
	AddPlugin(pluginInfo PluginInfo) error

	// RemovePlugin 从实际状态中删除具有给定套接字路径的插件。
	// 如果不存在具有给定套接字路径的插件，则不执行任何操作。
	RemovePlugin(socketPath string)

	// PluginExists 检查给定插件是否以正确的时间戳存在于当前实际状态的缓存中。
	PluginExistsWithCorrectTimestamp(pluginInfo PluginInfo) bool
}
```

### actualStateOfWorld

```go
func NewActualStateOfWorld() ActualStateOfWorld {
	return &actualStateOfWorld{
		socketFileToInfo: make(map[string]PluginInfo),
	}
}

type actualStateOfWorld struct {
	// socketFileToInfo 是一个包含成功注册插件的映射。
	// 键是插件的套接字文件路径，值是 PluginInfo 对象。
	socketFileToInfo map[string]PluginInfo
	sync.RWMutex
}

var _ ActualStateOfWorld = &actualStateOfWorld{}
```

### AddPlugin

```go
func (asw *actualStateOfWorld) AddPlugin(pluginInfo PluginInfo) error {
	asw.Lock()
	defer asw.Unlock()

	if pluginInfo.SocketPath == "" {
		return fmt.Errorf("socket path is empty")
	}
	if _, ok := asw.socketFileToInfo[pluginInfo.SocketPath]; ok {
		klog.V(2).InfoS("Plugin exists in actual state cache", "path", pluginInfo.SocketPath)
	}
	asw.socketFileToInfo[pluginInfo.SocketPath] = pluginInfo
	return nil
}
```

### RemovePlugin

```go
func (asw *actualStateOfWorld) RemovePlugin(socketPath string) {
	asw.Lock()
	defer asw.Unlock()

	delete(asw.socketFileToInfo, socketPath)
}
```

### GetRegisteredPlugins

```go
func (asw *actualStateOfWorld) GetRegisteredPlugins() []PluginInfo {
	asw.RLock()
	defer asw.RUnlock()

	currentPlugins := []PluginInfo{}
	for _, pluginInfo := range asw.socketFileToInfo {
		currentPlugins = append(currentPlugins, pluginInfo)
	}
	return currentPlugins
}
```

### PluginExistsWithCorrectTimestamp

```go
func (asw *actualStateOfWorld) PluginExistsWithCorrectTimestamp(pluginInfo PluginInfo) bool {
	asw.RLock()
	defer asw.RUnlock()

	// 我们需要检查套接字文件路径是否存在，并且时间戳与给定插件（来自期望状态缓存）的时间戳匹配。
	actualStatePlugin, exists := asw.socketFileToInfo[pluginInfo.SocketPath]
	return exists && (actualStatePlugin.Timestamp == pluginInfo.Timestamp)
}
```

## OperationExecutor

```go
// NewActualStateOfWorld 返回 ActualStateOfWorld 的新实例。

// OperationExecutor 定义了一组用于注册和取消注册插件的操作，
// 这些操作使用 NewGoRoutineMap 执行，该函数可防止在同一套接字路径上触发多个操作。
//
// 这些操作应该是幂等的（例如，如果插件已经注册，则 RegisterPlugin 应该仍然成功等）。
// 然而，它们依赖于插件处理程序（每种插件类型）来实现此行为。
//
// 一旦操作成功完成，将更新 actualStateOfWorld 来指示插件已注册/取消注册。
//
// 一旦操作开始，由于它是异步执行的，错误仅仅被记录下来，并且 goroutine 在不更新 actualStateOfWorld 的情况下终止。
type OperationExecutor interface {
	// RegisterPlugin 使用插件处理程序映射中的处理程序注册给定的插件。
	// 然后更新 actual state of the world 来反映这一点。
	RegisterPlugin(socketPath string, timestamp time.Time, pluginHandlers map[string]cache.PluginHandler, actualStateOfWorld ActualStateOfWorldUpdater) error

	// UnregisterPlugin 使用插件处理程序映射中的处理程序取消注册给定的插件。
	// 然后更新 actual state of the world 来反映这一点。
	UnregisterPlugin(pluginInfo cache.PluginInfo, actualStateOfWorld ActualStateOfWorldUpdater) error
}
```

### NewOperationExecutor

```go
// NewOperationExecutor 返回 OperationExecutor 的新实例。
func NewOperationExecutor(
	operationGenerator OperationGenerator) OperationExecutor {

	return &operationExecutor{
		pendingOperations:  goroutinemap.NewGoRoutineMap(true /* exponentialBackOffOnError */),
		operationGenerator: operationGenerator,
	}
}

type operationExecutor struct {
	// pendingOperations 跟踪待处理的注册和取消注册操作，
	// 以防止在同一个插件上启动多个操作。
	pendingOperations goroutinemap.GoRoutineMap

	// operationGenerator 是一个提供生成操作的接口
	operationGenerator OperationGenerator
}

var _ OperationExecutor = &operationExecutor{}
```

### IsOperationPending

```go
func (oe *operationExecutor) IsOperationPending(socketPath string) bool {
	return oe.pendingOperations.IsOperationPending(socketPath)
}
```

### RegisterPlugin

```go
func (oe *operationExecutor) RegisterPlugin(
	socketPath string,
	timestamp time.Time,
	pluginHandlers map[string]cache.PluginHandler,
	actualStateOfWorld ActualStateOfWorldUpdater) error {
	generatedOperation :=
		oe.operationGenerator.GenerateRegisterPluginFunc(socketPath, timestamp, pluginHandlers, actualStateOfWorld)

	return oe.pendingOperations.Run(
		socketPath, generatedOperation)
}
```

### UnregisterPlugin

```go
func (oe *operationExecutor) UnregisterPlugin(
	pluginInfo cache.PluginInfo,
	actualStateOfWorld ActualStateOfWorldUpdater) error {
	generatedOperation :=
		oe.operationGenerator.GenerateUnregisterPluginFunc(pluginInfo, actualStateOfWorld)

	return oe.pendingOperations.Run(
		pluginInfo.SocketPath, generatedOperation)
}
```

### ActualStateOfWorldUpdater

```go
// ActualStateOfWorldUpdater 定义了一组在成功注册/取消注册后更新实际状态的操作。
type ActualStateOfWorldUpdater interface {
	// AddPlugin 如果缓存中没有具有相同套接字路径的现有插件，则将给定的插件添加到缓存中。
	// 如果 socketPath 为空，则返回错误。
	AddPlugin(pluginInfo cache.PluginInfo) error

	// RemovePlugin 从实际状态中删除具有给定套接字路径的插件。
	// 如果不存在具有给定套接字路径的插件，则不执行任何操作。
	RemovePlugin(socketPath string)
}
```

## OperationGenerator

```go
// OperationGenerator 是一个接口，从 operation_executor 中提取出函数，使其可注入依赖。
type OperationGenerator interface {
	// 生成 RegisterPlugin 函数，用于执行插件的注册操作
	GenerateRegisterPluginFunc(
		socketPath string,
		timestamp time.Time,
		pluginHandlers map[string]cache.PluginHandler,
		actualStateOfWorldUpdater ActualStateOfWorldUpdater) func() error

	// 生成 UnregisterPlugin 函数，用于执行插件的注销操作
	GenerateUnregisterPluginFunc(
		pluginInfo cache.PluginInfo,
		actualStateOfWorldUpdater ActualStateOfWorldUpdater) func() error
}
```

### operationGenerator

```go

var _ OperationGenerator = &operationGenerator{}

type operationGenerator struct {
	// recorder 用于记录 API 服务器中的事件
	recorder record.EventRecorder
}

// NewOperationGenerator 返回 operationGenerator 的新实例
func NewOperationGenerator(recorder record.EventRecorder) OperationGenerator {
	return &operationGenerator{
		recorder: recorder,
	}
}
```



```go
func (og *operationGenerator) GenerateRegisterPluginFunc(
	socketPath string,
	timestamp time.Time,
	pluginHandlers map[string]cache.PluginHandler,
	actualStateOfWorldUpdater ActualStateOfWorldUpdater) func() error {

	registerPluginFunc := func() error {
		client, conn, err := dial(socketPath, dialTimeoutDuration)
		if err != nil {
			return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上拨号失败，错误: %v", socketPath, err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		infoResp, err := client.GetInfo(ctx, &registerapi.InfoRequest{})
		if err != nil {
			return fmt.Errorf("RegisterPlugin 错误 -- 使用 RPC GetInfo 在套接字 %s 上获取插件信息失败，错误: %v", socketPath, err)
		}

		handler, ok := pluginHandlers[infoResp.Type]
		if !ok {
			if err := og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin 错误 -- 未为插件类型 %s 在套接字 %s 上注册处理程序", infoResp.Type, socketPath)); err != nil {
				return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上发送错误失败，错误: %v", socketPath, err)
			}
			return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上未注册插件类型 %s 的处理程序", socketPath, infoResp.Type)
		}

		if infoResp.Endpoint == "" {
			infoResp.Endpoint = socketPath
		}
		if err := handler.ValidatePlugin(infoResp.Name, infoResp.Endpoint, infoResp.SupportedVersions); err != nil {
			if err = og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin 错误 -- 插件验证失败，错误: %v", err)); err != nil {
				return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上发送错误失败，错误: %v", socketPath, err)
			}
			return fmt.Errorf("RegisterPlugin 错误 -- pluginHandler.ValidatePluginFunc 失败")
		}
		// 在调用插件消费者的 Register 处理函数之前，我们将插件添加到实际状态缓存中，
		// 这样如果在 RegisterPlugin 过程中收到删除事件，我们可以将其处理为 DeRegister 调用。
		err = actualStateOfWorldUpdater.AddPlugin(cache.PluginInfo{
			SocketPath: socketPath,
			Timestamp:  timestamp,
			Handler:    handler,
			Name:       infoResp.Name,
		})
		if err != nil {
			klog.ErrorS(err, "RegisterPlugin 错误 -- 添加插件失败", "path", socketPath)
		}
		if err := handler.RegisterPlugin(infoResp.Name, infoResp.Endpoint, infoResp.SupportedVersions); err != nil {
			return og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin 错误 -- 插件注册失败，错误: %v", err))
		}

		// 在注册后调用 Notify，以确保即使 Notify 抛出错误，也始终会调用 Register
		if err := og.notifyPlugin(client, true, ""); err != nil {
			return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上发送注册状态失败，错误: %v", socketPath, err)
		}
		return nil
	}
	return registerPluginFunc
}
```

### GenerateRegisterPluginFunc

```go
func (og *operationGenerator) GenerateRegisterPluginFunc(
	socketPath string,
	timestamp time.Time,
	pluginHandlers map[string]cache.PluginHandler,
	actualStateOfWorldUpdater ActualStateOfWorldUpdater) func() error {

	registerPluginFunc := func() error {
		client, conn, err := dial(socketPath, dialTimeoutDuration)
		if err != nil {
			return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上拨号失败，错误: %v", socketPath, err)
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		infoResp, err := client.GetInfo(ctx, &registerapi.InfoRequest{})
		if err != nil {
			return fmt.Errorf("RegisterPlugin 错误 -- 使用 RPC GetInfo 在套接字 %s 上获取插件信息失败，错误: %v", socketPath, err)
		}

		handler, ok := pluginHandlers[infoResp.Type]
		if !ok {
			if err := og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin 错误 -- 未为插件类型 %s 在套接字 %s 上注册处理程序", infoResp.Type, socketPath)); err != nil {
				return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上发送错误失败，错误: %v", socketPath, err)
			}
			return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上未注册插件类型 %s 的处理程序", socketPath, infoResp.Type)
		}

		if infoResp.Endpoint == "" {
			infoResp.Endpoint = socketPath
		}
		if err := handler.ValidatePlugin(infoResp.Name, infoResp.Endpoint, infoResp.SupportedVersions); err != nil {
			if err = og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin 错误 -- 插件验证失败，错误: %v", err)); err != nil {
				return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上发送错误失败，错误: %v", socketPath, err)
			}
			return fmt.Errorf("RegisterPlugin 错误 -- pluginHandler.ValidatePluginFunc 失败")
		}
		// 在调用插件消费者的 Register 处理函数之前，我们将插件添加到实际状态缓存中，
		// 这样如果在 RegisterPlugin 过程中收到删除事件，我们可以将其处理为 DeRegister 调用。
		err = actualStateOfWorldUpdater.AddPlugin(cache.PluginInfo{
			SocketPath: socketPath,
			Timestamp:  timestamp,
			Handler:    handler,
			Name:       infoResp.Name,
		})
		if err != nil {
			klog.ErrorS(err, "RegisterPlugin 错误 -- 添加插件失败", "path", socketPath)
		}
		if err := handler.RegisterPlugin(infoResp.Name, infoResp.Endpoint, infoResp.SupportedVersions); err != nil {
			return og.notifyPlugin(client, false, fmt.Sprintf("RegisterPlugin 错误 -- 插件注册失败，错误: %v", err))
		}

		// 在注册后调用 Notify，以确保即使 Notify 抛出错误，也始终会调用 Register
		if err := og.notifyPlugin(client, true, ""); err != nil {
			return fmt.Errorf("RegisterPlugin 错误 -- 在套接字 %s 上发送注册状态失败，错误: %v", socketPath, err)
		}
		return nil
	}
	return registerPluginFunc
}
```

#### notifyPlugin

```go
func (og *operationGenerator) notifyPlugin(client registerapi.RegistrationClient, registered bool, errStr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeoutDuration)
	defer cancel()

	status := &registerapi.RegistrationStatus{
		PluginRegistered: registered,
		Error:            errStr,
	}

	if _, err := client.NotifyRegistrationStatus(ctx, status); err != nil {
		return fmt.Errorf("%s: %w", errStr, err)
	}

	if errStr != "" {
		return errors.New(errStr)
	}

	return nil
}s
```

#### dial

```go
// dial 与选定的插件套接字建立 gRPC 通信。https://godoc.org/google.golang.org/grpc#Dial
func dial(unixSocketPath string, timeout time.Duration) (registerapi.RegistrationClient, *grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c, err := grpc.DialContext(ctx, unixSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("拨号套接字 %s 失败，错误: %v", unixSocketPath, err)
	}

	return registerapi.NewRegistrationClient(c), c, nil
}
```

### GenerateUnregisterPluginFunc

```go
func (og *operationGenerator) GenerateUnregisterPluginFunc(
	pluginInfo cache.PluginInfo,
	actualStateOfWorldUpdater ActualStateOfWorldUpdater) func() error {

	unregisterPluginFunc := func() error {
		if pluginInfo.Handler == nil {
			return fmt.Errorf("UnregisterPlugin 错误 -- 未获取插件处理程序：%s", pluginInfo.SocketPath)
		}
		// 在调用插件消费者的 Unregister 处理函数之前，我们将插件从实际状态缓存中删除，
		// 这样如果在 RegisterPlugin 过程中收到注册事件，我们可以将其处理为 Register 调用。
		actualStateOfWorldUpdater.RemovePlugin(pluginInfo.SocketPath)

		pluginInfo.Handler.DeRegisterPlugin(pluginInfo.Name)

		klog.V(4).InfoS("调用 DeRegisterPlugin", "插件名称", pluginInfo.Name, "插件处理程序", pluginInfo.Handler)
		return nil
	}
	return unregisterPluginFunc
}
```

## Watcher

```go
// Watcher是插件监视器
type Watcher struct {
	path                string
	fs                  utilfs.Filesystem
	fsWatcher           *fsnotify.Watcher
	desiredStateOfWorld cache.DesiredStateOfWorld
}

// NewWatcher为插件注册提供一个新的监视器
func NewWatcher(sockDir string, desiredStateOfWorld cache.DesiredStateOfWorld) *Watcher {
	return &Watcher{
		path:                sockDir,
		fs:                  &utilfs.DefaultFs{},
		desiredStateOfWorld: desiredStateOfWorld,
	}
}
```

### init

```go
func (w *Watcher) init() error {
	klog.V(4).InfoS("Ensuring Plugin directory", "path", w.path)

	if err := w.fs.MkdirAll(w.path, 0755); err != nil {
		return fmt.Errorf("error (re-)creating root %s: %v", w.path, err)
	}

	return nil
}
```

### Start

```go
// Start监视路径下插件套接字的创建和删除
func (w *Watcher) Start(stopCh <-chan struct{}) error {
	klog.V(2).InfoS("Plugin Watcher Start", "path", w.path)

	// 如果目录不存在，则创建要监视的目录，并遍历目录以发现现有的插件
	if err := w.init(); err != nil {
		return err
	}

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to start plugin fsWatcher, err: %v", err)
	}
	w.fsWatcher = fsWatcher

	// 在启动插件处理goroutine之前，遍历插件目录并添加文件系统监视器
	if err := w.traversePluginDir(w.path); err != nil {
		klog.ErrorS(err, "Failed to traverse plugin socket path", "path", w.path)
	}

	go func(fsWatcher *fsnotify.Watcher) {
		for {
			select {
			case event := <-fsWatcher.Events:
				//TODO: 通过采取纠正措施来处理错误
				if event.Has(fsnotify.Create) {
					err := w.handleCreateEvent(event)
					if err != nil {
						klog.ErrorS(err, "Error when handling create event", "event", event)
					}
				} else if event.Has(fsnotify.Remove) {
					w.handleDeleteEvent(event)
				}
				continue
			case err := <-fsWatcher.Errors:
				if err != nil {
					klog.ErrorS(err, "FsWatcher received error")
				}
				continue
			case <-stopCh:
				w.fsWatcher.Close()
				return
			}
		}
	}(fsWatcher)

	return nil
}
```

#### traversePluginDir

```go
// 遍历插件目录以发现任何现有的插件套接字
// 忽略除根目录不可遍历之外的所有错误
func (w *Watcher) traversePluginDir(dir string) error {
	// 监视新目录
	err := w.fsWatcher.Add(dir)
	if err != nil {
		return fmt.Errorf("failed to watch %s, err: %v", w.path, err)
	}
	// 遍历目录中的现有子项
	return w.fs.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if path == dir {
				return fmt.Errorf("error accessing path: %s error: %v", path, err)
			}

			klog.ErrorS(err, "Error accessing path", "path", path)
			return nil
		}

		// 避免在根目录上两次调用fsWatcher.Add，以避免潜在问题
		if path == dir {
			return nil
		}

		mode := info.Mode()
		if mode.IsDir() {
			if err := w.fsWatcher.Add(path); err != nil {
				return fmt.Errorf("failed to watch %s, err: %v", path, err)
			}
		} else if isSocket, _ := util.IsUnixDomainSocket(path); isSocket {
			event := fsnotify.Event{
				Name: path,
				Op:   fsnotify.Create,
			}
			//TODO: 通过采取纠正措施来处理错误
			if err := w.handleCreateEvent(event); err != nil {
				klog.ErrorS(err, "Error when handling create", "event", event)
			}
		} else {
			klog.V(5).InfoS("Ignoring file", "path", path, "mode", mode)
		}

		return nil
	})
}
```

##### handleCreateEvent

```go
// 处理文件系统通知事件
// 文件名：
// - 不得以'.'开头
func (w *Watcher) handleCreateEvent(event fsnotify.Event) error {
	klog.V(6).InfoS("Handling create event", "event", event)

	fi, err := getStat(event)
	if err != nil {
		return fmt.Errorf("stat file %s failed: %v", event.Name, err)
	}

	if strings.HasPrefix(fi.Name(), ".") {
		klog.V(5).InfoS("Ignoring file (starts with '.')", "path", fi.Name())
		return nil
	}

	if !fi.IsDir() {
		isSocket, err := util.IsUnixDomainSocket(util.NormalizePath(event.Name))
		if err != nil {
			return fmt.Errorf("failed to determine if file: %s is a unix domain socket: %v", event.Name, err)
		}
		if !isSocket {
			klog.V(5).InfoS("Ignoring non socket file", "path", fi.Name())
			return nil
		}

		return w.handlePluginRegistration(event.Name)
	}

	return w.traversePluginDir(event.Name)
}
```

##### handlePluginRegistration

```go
func (w *Watcher) handlePluginRegistration(socketPath string) error {
	socketPath = getSocketPath(socketPath)
	// 更新期望状态世界的插件列表
	// 如果套接字路径在期望的世界缓存中存在，仍然有可能在从期望的世界缓存中删除之前已被删除并重新创建，因此我们仍然需要在这种情况下调用AddOrUpdatePlugin以更新时间戳
	klog.V(2).InfoS("Adding socket path or updating timestamp to desired state cache", "path", socketPath)
	err := w.desiredStateOfWorld.AddOrUpdatePlugin(socketPath)
	if err != nil {
		return fmt.Errorf("error adding socket path %s or updating timestamp to desired state cache: %v", socketPath, err)
	}
	return nil
}
```

#### handleDeleteEvent

```go
func (w *Watcher) handleDeleteEvent(event fsnotify.Event) {
	klog.V(6).InfoS("Handling delete event", "event", event)

	socketPath := event.Name
	klog.V(2).InfoS("Removing socket path from desired state cache", "path", socketPath)
	w.desiredStateOfWorld.RemovePlugin(socketPath)
}
```

