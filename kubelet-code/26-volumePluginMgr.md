## 简介

Kubernetes中的Volume插件管理器（Volume Plugin Manager）是一个用于管理Volume插件的组件。Volume插件管理器通过Kubernetes API Server与Kubelet节点通信，负责为Pod中定义的Volume选择合适的插件，并将Volume挂载到Pod所在的节点上。Volume插件管理器还负责监视Volume插件的状态，并在需要时进行重新调度。

## VolumePlugin

```GO
// VolumePlugin 是用于在 Kubernetes 节点上（例如 kubelet）实例化和管理存储卷的接口。
type VolumePlugin interface {
	// Init 初始化插件。在执行任何 New* 调用之前，此函数将被调用一次 - 插件的实现可能依赖于此函数。
	Init(host VolumeHost) error

	// Name 返回插件的名称。插件必须使用带有命名空间的名称，例如 "example.com/volume" 并且只包含一个 '/' 字符。
	// "kubernetes.io" 命名空间保留用于与 Kubernetes 捆绑的插件。
	GetPluginName() string

	// GetVolumeName 返回一个名称/ID，用于唯一标识指定卷规格所引用的实际后备设备、目录、路径等。
	// 对于可附加的存储卷，该值必须能够在需要识别设备时传递给卷的 Detach 方法。
	// 如果插件不支持给定的规格，将返回错误。
	GetVolumeName(spec *Spec) (string, error)

	// CanSupport 测试插件是否支持来自 API 的给定卷规格。规格指针应被视为 const。
	CanSupport(spec *Spec) bool

	// RequiresRemount 如果此插件需要重新执行挂载调用，则返回 true。像 Downward API 这样的原子更新卷依赖于此功能来更新卷的内容。
	RequiresRemount(spec *Spec) bool

	// NewMounter 从 API 规格中创建一个新的 volume.Mounter。*不*传递 spec 指针的所有权。
	// - spec: v1.Volume 规格
	// - pod: 封装的 Pod
	NewMounter(spec *Spec, podRef *v1.Pod, opts VolumeOptions) (Mounter, error)

	// NewUnmounter 从可恢复状态创建一个新的 volume.Unmounter。
	// - name: 卷名称，根据 v1.Volume 规格。
	// - podUID: 封装的 Pod 的 UID
	NewUnmounter(name string, podUID types.UID) (Unmounter, error)

	// ConstructVolumeSpec 根据给定的卷名称和卷路径构建一个卷规格。由于输入信息有限，规格可能具有不完整的信息。此函数由卷管理器使用，通过从磁盘读取卷目录来重建卷规格。
	ConstructVolumeSpec(volumeName, volumePath string) (ReconstructedVolume, error)

	// SupportsMountOption 如果卷插件支持挂载选项，则返回 true。在不支持用户指定挂载选项的卷插件中指定挂载选项将导致创建持久卷时出现错误。
	SupportsMountOption() bool

	// SupportsBulkVolumeVerification 检查卷插件类型是否支持启用所有节点的批量轮询。
	// 这可以加快验证已附加卷的速度，但底层插件必须支持它。
	SupportsBulkVolumeVerification() bool

	// SupportsSELinuxContextMount 如果卷插件支持给定卷的挂载 -o context=XYZ，则返回 true。
	SupportsSELinuxContextMount(spec *Spec) (bool, error)
}
```

### VolumeHost

```GO
// VolumeHost 是插件可以使用的访问 kubelet 的接口。
type VolumeHost interface {
	// GetPluginDir 返回给定插件可以存储数据的绝对路径目录。
	// 此目录可能尚不存在于磁盘上。对于每个 Pod 的插件数据，请参阅 GetPodPluginDir()。
	GetPluginDir(pluginName string) string

	// GetVolumeDevicePluginDir 返回给定插件可以存储数据的绝对路径目录。
	// 例如 plugins/kubernetes.io/{PluginName}/{DefaultKubeletVolumeDevicesDirName}/{volumePluginDependentPath}/
	GetVolumeDevicePluginDir(pluginName string) string

	// GetPodsDir 返回存储所有 Pod 信息的绝对路径目录。
	GetPodsDir() string

	// GetPodVolumeDir 返回一个目录的绝对路径，该目录代表给定 Pod 下给定插件的命名卷。
	// 如果指定的 Pod 不存在，则此调用的结果可能不存在。
	GetPodVolumeDir(podUID types.UID, pluginName string, volumeName string) string

	// GetPodPluginDir 返回给定插件可以存储数据的绝对路径目录。
	// 如果指定的 Pod 不存在，则此调用的结果可能不存在。此目录可能尚不存在于磁盘上。
	GetPodPluginDir(podUID types.UID, pluginName string) string

	// GetPodVolumeDeviceDir 返回一个目录的绝对路径，该目录代表给定 Pod 下给定插件的命名卷。
	// 如果指定的 Pod 不存在，则此调用的结果可能不存在。
	// 例如 pods/{podUid}/{DefaultKubeletVolumeDevicesDirName}/{escapeQualifiedPluginName}/
	GetPodVolumeDeviceDir(podUID types.UID, pluginName string) string

	// GetKubeClient 返回一个客户端接口。
	GetKubeClient() clientset.Interface

	// NewWrapperMounter 查找适合处理提供的规格的合适插件。这用于实现“包装”其他插件的卷插件。
	// 例如，"secret" 卷是基于 "emptyDir" 卷来实现的。
	NewWrapperMounter(volName string, spec Spec, pod *v1.Pod, opts VolumeOptions) (Mounter, error)

	// NewWrapperUnmounter 查找适合处理提供的规格的合适插件。有关更多上下文信息，请参阅 NewWrapperMounter 的注释。
	NewWrapperUnmounter(volName string, spec Spec, podUID types.UID) (Unmounter, error)

	// 从 kubelet 获取云提供者。
	GetCloudProvider() cloudprovider.Interface

	// 获取挂载器接口。
	GetMounter(pluginName string) mount.Interface

	// 返回运行 kubelet 的主机名
	GetHostName() string

	// 返回主机 IP，如果出现错误，则返回 nil。
	GetHostIP() (net.IP, error)

	// 返回节点可分配资源。
	GetNodeAllocatable() (v1.ResourceList, error)

	// 返回一个返回 secret 的函数。
	GetSecretFunc() func(namespace, name string) (*v1.Secret, error)

	// 返回一个返回 configmap 的函数。
	GetConfigMapFunc() func(namespace, name string) (*v1.ConfigMap, error)

	GetServiceAccountTokenFunc() func(namespace, name string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error)

	DeleteServiceAccountTokenFunc() func(podUID types.UID)

	// 返回一个用于在卷插件中执行任何实用程序的接口。
	GetExec(pluginName string) exec.Interface

	// 返回节点的标签
	GetNodeLabels() (map[string]string, error)

	// 返回节点名称
	GetNodeName() types.NodeName

	GetAttachedVolumesFromNodeStatus() (map[v1.UniqueVolumeName]string, error)

	// 返回 kubelet 的事件记录器。
	GetEventRecorder() record.EventRecorder

	// 返回用于执行子路径操作的接口
	GetSubpather() subpath.Interface
}
```

### Spec

```GO
// Spec 是卷的内部表示。所有 API 卷类型都会转换为 Spec。
type Spec struct {
	Volume                          *v1.Volume
	PersistentVolume                *v1.PersistentVolume
	ReadOnly                        bool
	InlineVolumeSpecForCSIMigration bool
	Migrated                        bool
}
```

### Mounter

```GO
// Mounter 接口提供了设置和挂载卷的方法。
type Mounter interface {
	// 通过接口提供 Docker 绑定的路径。
	Volume

	// SetUp 准备并将卷挂载/解压缩到自行确定的目录路径。
	// 挂载点及其内容应该由 `fsUser` 或 'fsGroup' 拥有，以便 Pod 可以访问。
	// 可能会被调用多次，因此实现必须具有幂等性。
	// 它可能返回以下类型的错误：
	//   - TransientOperationFailure（瞬态操作失败）
	//   - UncertainProgressError（不确定进度错误）
	//   - 任何其他类型的错误都应视为最终错误
	SetUp(mounterArgs MounterArgs) error

	// SetUpAt 准备并将卷挂载/解压缩到指定的目录路径，该目录路径可能已经存在，也可能不存在。
	// 挂载点及其内容应该由 `fsUser` 或 'fsGroup' 拥有，以便 Pod 可以访问。
	// 可能会被调用多次，因此实现必须具有幂等性。
	SetUpAt(dir string, mounterArgs MounterArgs) error

	// GetAttributes 返回挂载器的属性。
	// 此函数在 SetUp()/SetUpAt() 之后被调用。
	GetAttributes() Attributes
}
```

#### MounterArgs

```GO
// MounterArgs 提供了更容易扩展的 Mounter 参数。
type MounterArgs struct {
	// 当 FsUser 被设置时，卷的所有权将被修改为由 FsUser 拥有并可写入。
	// 否则，没有副作用。
	// 目前仅支持项目化服务账户令牌。
	FsUser              *int64
	FsGroup             *int64
	FSGroupChangePolicy *v1.PodFSGroupChangePolicy
	DesiredSize         *resource.Quantity
	SELinuxLabel        string
}
```

### Unmounter

```GO
// Unmounter 接口提供了清理/卸载卷的方法。
type Unmounter interface {
	Volume
	// TearDown 从自行确定的目录卸载卷，并删除 SetUp 过程的痕迹。
	TearDown() error
	// TearDownAt 从指定目录卸载卷，并删除 SetUp 过程的痕迹。
	TearDownAt(dir string) error
}
```

### ReconstructedVolume

```GO
// ReconstructedVolume 包含通过 ConstructVolumeSpec() 重建的卷信息。
type ReconstructedVolume struct {
	// Spec 是已挂载卷的卷规格
	Spec *Spec
	// SELinuxMountContext 是 -o context=XYZ 挂载选项的值。
	// 如果为空，则未使用此类挂载选项。
	SELinuxMountContext string
}
```

## VolumePluginMgr

```GO
// VolumePluginMgr 跟踪已注册的插件。
type VolumePluginMgr struct {
	mutex                     sync.RWMutex
	plugins                   map[string]VolumePlugin
	prober                    DynamicPluginProber
	probedPlugins             map[string]VolumePlugin
	loggedDeprecationWarnings sets.String
	Host                      VolumeHost
}
```

### DynamicPluginProber

```GO
type DynamicPluginProber interface {
	Init() error

	// 聚合成功驱动程序的事件和失败驱动程序的错误
	Probe() (events []ProbeEvent, err error)
}
```

### NewInitializedVolumePluginMgr

```GO
// NewInitializedVolumePluginMgr 返回一个新的 volume.VolumePluginMgr 实例，使用 kubelet 的 volume.VolumeHost 接口实现进行初始化。
//
// kubelet - 由 VolumeHost 方法用于公开 kubelet 特定参数
// plugins - 用于初始化 volumePluginMgr 的插件列表
func NewInitializedVolumePluginMgr(
	kubelet *Kubelet,
	secretManager secret.Manager,
	configMapManager configmap.Manager,
	tokenManager *token.Manager,
	plugins []volume.VolumePlugin,
	prober volume.DynamicPluginProber) (*volume.VolumePluginMgr, error) {

	// 在调用 InitPlugins 之前初始化 csiDriverLister。
	var informerFactory informers.SharedInformerFactory
	var csiDriverLister storagelisters.CSIDriverLister
	var csiDriversSynced cache.InformerSynced
	const resyncPeriod = 0
	// 如果 kubeClient 为 nil，则不进行初始化
	if kubelet.kubeClient != nil {
		informerFactory = informers.NewSharedInformerFactory(kubelet.kubeClient, resyncPeriod)
		csiDriverInformer := informerFactory.Storage().V1().CSIDrivers()
		csiDriverLister = csiDriverInformer.Lister()
		csiDriversSynced = csiDriverInformer.Informer().HasSynced

	} else {
		klog.InfoS("KubeClient is nil. Skip initialization of CSIDriverLister")
	}

	kvh := &kubeletVolumeHost{
		kubelet:          kubelet,
		volumePluginMgr:  volume.VolumePluginMgr{},
		secretManager:    secretManager,
		configMapManager: configMapManager,
		tokenManager:     tokenManager,
		informerFactory:  informerFactory,
		csiDriverLister:  csiDriverLister,
		csiDriversSynced: csiDriversSynced,
		exec:             utilexec.New(),
	}

	if err := kvh.volumePluginMgr.InitPlugins(plugins, prober, kvh); err != nil {
		return nil, fmt.Errorf(
			"could not initialize volume plugins for KubeletVolumePluginMgr: %v",
			err)
	}

	return &kvh.volumePluginMgr, nil
}
```

### InitPlugins

```GO
// InitPlugins 初始化每个插件。所有插件必须具有唯一的名称。
// 必须在任何插件上的 New* 方法之前调用此函数一次。
func (pm *VolumePluginMgr) InitPlugins(plugins []VolumePlugin, prober DynamicPluginProber, host VolumeHost) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.Host = host
	pm.loggedDeprecationWarnings = sets.NewString()

	if prober == nil {
		// 使用虚拟 prober 防止空指针 deference。
		pm.prober = &dummyPluginProber{}
	} else {
		pm.prober = prober
	}
	if err := pm.prober.Init(); err != nil {
		// Prober 初始化失败不应影响其他插件的初始化。
		klog.ErrorS(err, "Error initializing dynamic plugin prober")
		pm.prober = &dummyPluginProber{}
	}

	if pm.plugins == nil {
		pm.plugins = map[string]VolumePlugin{}
	}
	if pm.probedPlugins == nil {
		pm.probedPlugins = map[string]VolumePlugin{}
	}

	allErrs := []error{}
	for _, plugin := range plugins {
		name := plugin.GetPluginName()
		if errs := validation.IsQualifiedName(name); len(errs) != 0 {
			allErrs = append(allErrs, fmt.Errorf("volume plugin has invalid name: %q: %s", name, strings.Join(errs, ";")))
			continue
		}

		if _, found := pm.plugins[name]; found {
			allErrs = append(allErrs, fmt.Errorf("volume plugin %q was registered more than once", name))
			continue
		}
		err := plugin.Init(host)
		if err != nil {
			klog.ErrorS(err, "Failed to load volume plugin", "pluginName", name)
			allErrs = append(allErrs, err)
			continue
		}
		pm.plugins[name] = plugin
		klog.V(1).InfoS("Loaded volume plugin", "pluginName", name)
	}
	return utilerrors.NewAggregate(allErrs)
}
```

### FindPluginBySpec

```GO
// FindPluginBySpec 查找能够支持给定卷规格的插件。如果没有插件能够支持或有多个插件可以支持，返回错误。
func (pm *VolumePluginMgr) FindPluginBySpec(spec *Spec) (VolumePlugin, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	if spec == nil {
		return nil, fmt.Errorf("could not find plugin because volume spec is nil")
	}

	var match VolumePlugin
	matchedPluginNames := []string{}
	for _, v := range pm.plugins {
		if v.CanSupport(spec) {
			match = v
			matchedPluginNames = append(matchedPluginNames, v.GetPluginName())
		}
	}

	pm.refreshProbedPlugins()
	for _, plugin := range pm.probedPlugins {
		if plugin.CanSupport(spec) {
			match = plugin
			matchedPluginNames = append(matchedPluginNames, plugin.GetPluginName())
		}
	}

	if len(matchedPluginNames) == 0 {
		return nil, fmt.Errorf("no volume plugin matched")
	}
	if len(matchedPluginNames) > 1 {
		return nil, fmt.Errorf("multiple volume plugins matched: %s", strings.Join(matchedPluginNames, ","))
	}

	return match, nil
}
```

#### refreshProbedPlugins

```GO
// 检查是否需要更新 probedPlugin 缓存。
// 如果需要，初始化所有 probed 插件并用它们替换缓存。
func (pm *VolumePluginMgr) refreshProbedPlugins() {
	events, err := pm.prober.Probe()

	if err != nil {
		klog.ErrorS(err, "Error dynamically probing plugins")
	}

	// 因为 probe 函数可能返回有效插件列表，即使存在错误，我们仍必须添加这些插件，否则它们将被跳过，因为每个事件只触发一次
	for _, event := range events {
		if event.Op == ProbeAddOrUpdate {
			if err := pm.initProbedPlugin(event.Plugin); err != nil {
				klog.ErrorS(err, "Error initializing dynamically probed plugin",
					"pluginName", event.Plugin.GetPluginName())
				continue
			}
			pm.probedPlugins[event.Plugin.GetPluginName()] = event.Plugin
		} else if event.Op == ProbeRemove {
			// ProbeRemove 事件中插件不可用，只有 PluginName 信息
			delete(pm.probedPlugins, event.PluginName)
		} else {
			klog.ErrorS(nil, "Unknown Operation on PluginName.",
				"pluginName", event.Plugin.GetPluginName())
		}
	}
}
```

##### initProbedPlugin

```GO
func (pm *VolumePluginMgr) initProbedPlugin(probedPlugin VolumePlugin) error {
	name := probedPlugin.GetPluginName()
	if errs := validation.IsQualifiedName(name); len(errs) != 0 {
		return fmt.Errorf("volume plugin has invalid name: %q: %s", name, strings.Join(errs, ";"))
	}

	err := probedPlugin.Init(pm.Host)
	if err != nil {
		return fmt.Errorf("failed to load volume plugin %s, error: %s", name, err.Error())
	}

	klog.V(1).InfoS("Loaded volume plugin", "pluginName", name)
	return nil
}
```

### FindPluginByName

```GO
// FindPluginByName 根据名称获取插件。如果找不到插件，返回错误。
func (pm *VolumePluginMgr) FindPluginByName(name string) (VolumePlugin, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var match VolumePlugin
	if v, found := pm.plugins[name]; found {
		match = v
	}

	pm.refreshProbedPlugins()
	if plugin, found := pm.probedPlugins[name]; found {
		if match != nil {
			return nil, fmt.Errorf("multiple volume plugins matched: %s and %s", match.GetPluginName(), plugin.GetPluginName())
		}
		match = plugin
	}

	if match == nil {
		return nil, fmt.Errorf("no volume plugin matched name: %s", name)
	}
	return match, nil
}
```

### ListVolumePluginWithLimits

```GO
// ListVolumePluginWithLimits 返回具有节点卷限制的插件列表。
func (pm *VolumePluginMgr) ListVolumePluginWithLimits() []VolumePluginWithAttachLimits {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	matchedPlugins := []VolumePluginWithAttachLimits{}
	for _, v := range pm.plugins {
		if plugin, ok := v.(VolumePluginWithAttachLimits); ok {
			matchedPlugins = append(matchedPlugins, plugin)
		}
	}
	return matchedPlugins
}
```

### FindPersistentPluginBySpec

```GO
// FindPersistentPluginBySpec 查找能够支持给定卷规格的持久卷插件。如果找不到插件，返回错误。
func (pm *VolumePluginMgr) FindPersistentPluginBySpec(spec *Spec) (PersistentVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, fmt.Errorf("could not find volume plugin for spec: %#v", spec)
	}
	if persistentVolumePlugin, ok := volumePlugin.(PersistentVolumePlugin); ok {
		return persistentVolumePlugin, nil
	}
	return nil, fmt.Errorf("no persistent volume plugin matched")
}
```

### FindVolumePluginWithLimitsBySpec

```GO
// FindVolumePluginWithLimitsBySpec 返回具有对节点附加限制的卷插件。如果找不到插件，返回错误。
func (pm *VolumePluginMgr) FindVolumePluginWithLimitsBySpec(spec *Spec) (VolumePluginWithAttachLimits, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, fmt.Errorf("could not find volume plugin for spec : %#v", spec)
	}

	if limitedPlugin, ok := volumePlugin.(VolumePluginWithAttachLimits); ok {
		return limitedPlugin, nil
	}
	return nil, fmt.Errorf("no plugin with limits found")
}
```

### FindPersistentPluginByName

```GO
// FindPersistentPluginByName 根据名称获取持久卷插件。如果找不到插件，返回错误。
func (pm *VolumePluginMgr) FindPersistentPluginByName(name string) (PersistentVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}
	if persistentVolumePlugin, ok := volumePlugin.(PersistentVolumePlugin); ok {
		return persistentVolumePlugin, nil
	}
	return nil, fmt.Errorf("no persistent volume plugin matched")
}
```

### FindRecyclablePluginBySpec

```GO
// FindRecyclablePluginBySpec 根据规格获取可回收卷插件。如果找不到插件，返回错误。
func (pm *VolumePluginMgr) FindRecyclablePluginBySpec(spec *Spec) (RecyclableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}
	if recyclableVolumePlugin, ok := volumePlugin.(RecyclableVolumePlugin); ok {
		return recyclableVolumePlugin, nil
	}
	return nil, fmt.Errorf("no recyclable volume plugin matched")
}
```

### FindProvisionablePluginByName

```GO
// FindProvisionablePluginByName 根据名称获取可提供卷插件。如果找不到插件，返回错误。
func (pm *VolumePluginMgr) FindProvisionablePluginByName(name string) (ProvisionableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}
	if provisionableVolumePlugin, ok := volumePlugin.(ProvisionableVolumePlugin); ok {
		return provisionableVolumePlugin, nil
	}
	return nil, fmt.Errorf("no provisionable volume plugin matched")
}
```

### FindDeletablePluginBySpec

```GO
// FindDeletablePluginBySpec按照规格查找一个可删除的持久卷插件。如果找不到插件，则返回错误。
func (pm *VolumePluginMgr) FindDeletablePluginBySpec(spec *Spec) (DeletableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}
	if deletableVolumePlugin, ok := volumePlugin.(DeletableVolumePlugin); ok {
		return deletableVolumePlugin, nil
	}
	return nil, fmt.Errorf("no deletable volume plugin matched")
}
```

### FindDeletablePluginByName

```GO
// FindDeletablePluginByName按照名称查找一个可删除的持久卷插件。如果找不到插件，则返回错误。
func (pm *VolumePluginMgr) FindDeletablePluginByName(name string) (DeletableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}
	if deletableVolumePlugin, ok := volumePlugin.(DeletableVolumePlugin); ok {
		return deletableVolumePlugin, nil
	}
	return nil, fmt.Errorf("no deletable volume plugin matched")
}
```

### FindCreatablePluginBySpec

```GO
// FindCreatablePluginBySpec按照规格查找一个可创建的持久卷插件。如果找不到插件，则返回错误。
func (pm *VolumePluginMgr) FindCreatablePluginBySpec(spec *Spec) (ProvisionableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}
	if provisionableVolumePlugin, ok := volumePlugin.(ProvisionableVolumePlugin); ok {
		return provisionableVolumePlugin, nil
	}
	return nil, fmt.Errorf("no creatable volume plugin matched")
}
```

### FindAttachablePluginBySpec

```GO
// FindAttachablePluginBySpec按照规格查找一个可挂载的持久卷插件。
// 不像其他“FindPlugin”方法，如果找不到插件，这里不会返回错误。
// 所有的持久卷都需要一个挂载器和卸载器，但并不是所有的持久卷都会有一个挂载器/卸载器。
func (pm *VolumePluginMgr) FindAttachablePluginBySpec(spec *Spec) (AttachableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}
	if attachableVolumePlugin, ok := volumePlugin.(AttachableVolumePlugin); ok {
		if canAttach, err := attachableVolumePlugin.CanAttach(spec); err != nil {
			return nil, err
		} else if canAttach {
			return attachableVolumePlugin, nil
		}
	}
	return nil, nil
}
```

### FindAttachablePluginByName

```GO
// FindAttachablePluginByName按照名称查找一个可挂载的持久卷插件。
// 不像其他“FindPlugin”方法，如果找不到插件，这里不会返回错误。
// 所有的持久卷都需要一个挂载器和卸载器，但并不是所有的持久卷都会有一个挂载器/卸载器。
func (pm *VolumePluginMgr) FindAttachablePluginByName(name string) (AttachableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}
	if attachablePlugin, ok := volumePlugin.(AttachableVolumePlugin); ok {
		return attachablePlugin, nil
	}
	return nil, nil
}
```

### FindDeviceMountablePluginBySpec

```GO
// FindDeviceMountablePluginBySpec按照规格查找一个可挂载设备的持久卷插件。
func (pm *VolumePluginMgr) FindDeviceMountablePluginBySpec(spec *Spec) (DeviceMountableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}
	if deviceMountableVolumePlugin, ok := volumePlugin.(DeviceMountableVolumePlugin); ok {
		if canMount, err := deviceMountableVolumePlugin.CanDeviceMount(spec); err != nil {
			return nil, err
		} else if canMount {
			return deviceMountableVolumePlugin, nil
		}
	}
	return nil, nil
}
```

### FindDeviceMountablePluginByName

```GO
// FindDeviceMountablePluginByName按照名称查找一个可挂载设备的持久卷插件。
func (pm *VolumePluginMgr) FindDeviceMountablePluginByName(name string) (DeviceMountableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}
	if deviceMountableVolumePlugin, ok := volumePlugin.(DeviceMountableVolumePlugin); ok {
		return deviceMountableVolumePlugin, nil
	}
	return nil, nil
}
```

### FindExpandablePluginByName

```GO
// FindExpandablePluginBySpec 根据名称获取可扩展卷插件。
func (pm *VolumePluginMgr) FindExpandablePluginByName(name string) (ExpandableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}

	if expandableVolumePlugin, ok := volumePlugin.(ExpandableVolumePlugin); ok {
		return expandableVolumePlugin, nil
	}
	return nil, nil
}
```

### FindMapperPluginBySpec

```GO
// FindMapperPluginBySpec 根据规格获取块卷插件。
func (pm *VolumePluginMgr) FindMapperPluginBySpec(spec *Spec) (BlockVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}

	if blockVolumePlugin, ok := volumePlugin.(BlockVolumePlugin); ok {
		return blockVolumePlugin, nil
	}
	return nil, nil
}
```

### FindMapperPluginByName

```GO
// FindMapperPluginByName 根据名称获取块卷插件。
func (pm *VolumePluginMgr) FindMapperPluginByName(name string) (BlockVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}

	if blockVolumePlugin, ok := volumePlugin.(BlockVolumePlugin); ok {
		return blockVolumePlugin, nil
	}
	return nil, nil
}
```

### FindNodeExpandablePluginBySpec

```GO
// FindNodeExpandablePluginBySpec 根据规格获取可节点扩展卷插件。
func (pm *VolumePluginMgr) FindNodeExpandablePluginBySpec(spec *Spec) (NodeExpandableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginBySpec(spec)
	if err != nil {
		return nil, err
	}
	if fsResizablePlugin, ok := volumePlugin.(NodeExpandableVolumePlugin); ok {
		return fsResizablePlugin, nil
	}
	return nil, nil
}
```

### FindNodeExpandablePluginByName

```GO
// FindNodeExpandablePluginByName 根据名称获取可节点扩展卷插件。
func (pm *VolumePluginMgr) FindNodeExpandablePluginByName(name string) (NodeExpandableVolumePlugin, error) {
	volumePlugin, err := pm.FindPluginByName(name)
	if err != nil {
		return nil, err
	}

	if fsResizablePlugin, ok := volumePlugin.(NodeExpandableVolumePlugin); ok {
		return fsResizablePlugin, nil
	}

	return nil, nil
}
```

### Run

```GO
func (pm *VolumePluginMgr) Run(stopCh <-chan struct{}) {
	kletHost, ok := pm.Host.(KubeletVolumeHost)
	if ok {
		// start informer for CSIDriver
		informerFactory := kletHost.GetInformerFactory()
		informerFactory.Start(stopCh)
		informerFactory.WaitForCacheSync(stopCh)
	}
}
```

## PersistentVolumePlugin

```GO
// PersistentVolumePlugin是VolumePlugin的扩展接口，用于提供数据的长期持久性。
type PersistentVolumePlugin interface {
	VolumePlugin
	// GetAccessModes描述了给定卷可以被访问/挂载的方式。
	GetAccessModes() []v1.PersistentVolumeAccessMode
}
```

## RecyclableVolumePlugin

```GO
// RecyclableVolumePlugin是VolumePlugin的扩展接口，用于被持久化卷在重新供给给新的声明之前进行回收。
type RecyclableVolumePlugin interface {
	VolumePlugin

	// Recycle知道如何在持久卷从PersistentVolumeClaim释放后重新获取此资源。
	// Recycle将使用提供的记录器来写入可能对用户有趣的任何事件。预期调用方将这些事件传递给正在回收的PV。
	Recycle(pvName string, spec *Spec, eventRecorder recyclerclient.RecycleEventRecorder) error
}
```

## DeletableVolumePlugin

```GO
// DeletableVolumePlugin是VolumePlugin的扩展接口，用于被持久化卷在从PersistentVolumeClaim释放后从集群中删除。
type DeletableVolumePlugin interface {
	VolumePlugin
	// NewDeleter创建一个新的volume.Deleter，它知道如何在卷从声明中释放后按照底层存储提供程序的规定删除此资源。
	NewDeleter(logger klog.Logger, spec *Spec) (Deleter, error)
}
```

## ProvisionableVolumePlugin

```GO
// ProvisionableVolumePlugin是VolumePlugin的扩展接口，用于为集群创建卷。
type ProvisionableVolumePlugin interface {
	VolumePlugin
	// NewProvisioner创建一个新的volume.Provisioner，它知道如何根据插件的底层存储提供程序创建PersistentVolumes。
	NewProvisioner(logger klog.Logger, options VolumeOptions) (Provisioner, error)
}
```

## AttachableVolumePlugin

```GO
// AttachableVolumePlugin是VolumePlugin的扩展接口，用于需要在挂载之前将卷附加到节点的卷。
type AttachableVolumePlugin interface {
	DeviceMountableVolumePlugin
	NewAttacher() (Attacher, error)
	NewDetacher() (Detacher, error)
	// CanAttach测试提供的卷规格是否可附加
	CanAttach(spec *Spec) (bool, error)
}
```

## DeviceMountableVolumePlugin

```GO
// DeviceMountableVolumePlugin是VolumePlugin的扩展接口，用于在将卷绑定到Pod之前需要将设备挂载到节点的卷。
type DeviceMountableVolumePlugin interface {
	VolumePlugin
	NewDeviceMounter() (DeviceMounter, error)
	NewDeviceUnmounter() (DeviceUnmounter, error)
	GetDeviceMountRefs(deviceMountPath string) ([]string, error)
	// CanDeviceMount确定卷规格中的设备是否可以挂载
	CanDeviceMount(spec *Spec) (bool, error)
}
```

## ExpandableVolumePlugin

```GO
// ExpandableVolumePlugin是VolumePlugin的扩展接口，用于可以通过控制平面的ExpandVolumeDevice调用来扩展的卷。
type ExpandableVolumePlugin interface {
	VolumePlugin
	ExpandVolumeDevice(spec *Spec, newSize resource.Quantity, oldSize resource.Quantity) (resource.Quantity, error)
	RequiresFSResize() bool
}
```

## NodeExpandableVolumePlugin

```GO
// NodeExpandableVolumePlugin是VolumePlugin的扩展接口，用于需要通过NodeExpand调用在节点上进行扩展的卷。
type NodeExpandableVolumePlugin interface {
	VolumePlugin
	RequiresFSResize() bool
	// NodeExpand在给定的deviceMountPath上扩展卷，并在调整大小成功时返回true。
	NodeExpand(resizeOptions NodeResizeOptions) (bool, error)
}
```

## VolumePluginWithAttachLimits

```GO
// VolumePluginWithAttachLimits是VolumePlugin的扩展接口，限制可以附加到节点的卷的数量。
type VolumePluginWithAttachLimits interface {
	VolumePlugin
	// 返回可以附加到节点上的卷的最大数量的映射。
	// 键必须与VolumeLimitKey函数返回的字符串相同。返回的映射可能如下所示：
	// - { "storage-limits-aws-ebs": 39 }
	// - { "storage-limits-gce-pd": 10 }
	// 一个卷插件可能从此函数返回错误，如果它不能在给定的节点上使用或者在给定的环境（其中环境可能是云提供商或其他任何依赖项）不适用。
	// 例如 - 在GCE节点上调用此函数以获取EBS卷插件应该返回错误。
	// 返回的值将存储在节点的可分配属性中，并将由调度程序用于确定在给定节点上可以调度多少个带有卷的Pod。
	GetVolumeLimits() (map[string]int64, error)
	// 返回用于在节点容量约束中使用的卷限制键字符串。
	// 键必须以storage-limits-前缀开头。例如：
	// - storage-limits-aws-ebs
	// - storage-limits-csi-cinder
	// 此函数可能被kubelet或调度程序调用，以识别存储卷限制的节点可分配属性。
	VolumeLimitKey(spec *Spec) string
}
```

## BlockVolumePlugin

```GO
// BlockVolumePlugin是VolumePlugin的扩展接口，用于支持块卷。
type BlockVolumePlugin interface {
	VolumePlugin
	// NewBlockVolumeMapper从API规范创建一个新的volume.BlockVolumeMapper。
	// API规范中的spec指针的所有权不会转移。
	// - spec：v1.Volume规范
	// - pod：封闭的Pod
	NewBlockVolumeMapper(spec *Spec, podRef *v1.Pod, opts VolumeOptions) (BlockVolumeMapper, error)
	// NewBlockVolumeUnmapper从可恢复状态创建一个新的volume.BlockVolumeUnmapper。
	// - name：卷名称，与v1.Volume规范中的名称相对应。
	// - podUID：封闭Pod的UID
	NewBlockVolumeUnmapper(name string, podUID types.UID) (BlockVolumeUnmapper, error)
	// ConstructBlockVolumeSpec根据给定的podUID、卷名称和Pod设备映射路径构造卷规范。
	// 由于输入信息有限，规范可能具有不完整的信息。此函数由卷管理器使用，通过从磁盘读取卷目录重构卷规范。
	ConstructBlockVolumeSpec(podUID types.UID, volumeName, volumePath string) (*Spec, error)
}
```

