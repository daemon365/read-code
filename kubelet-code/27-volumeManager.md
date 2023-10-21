## 简介



## VolumeManager

```GO
// VolumeManager运行一组异步循环，根据调度在该节点上的Pod来确定哪些卷需要被挂载/卸载，然后进行处理。
type VolumeManager interface {
    // 启动volume manager及其控制的所有异步循环。
    Run(sourcesReady config.SourcesReady, stopCh <-chan struct{})

    // WaitForAttachAndMount处理指定Pod中引用的卷，并阻塞直到它们全部被挂载（反映在现实世界的实际状态）。
    // 如果所有卷在podAttachAndMountTimeout定义的持续时间内没有被挂载，将返回错误。
    WaitForAttachAndMount(ctx context.Context, pod *v1.Pod) error

    // WaitForUnmount处理指定Pod中引用的卷，并阻塞直到它们全部被卸载（反映在现实世界的实际状态）。
    // 如果所有卷在podAttachAndMountTimeout定义的持续时间内没有被卸载，将返回错误。
    WaitForUnmount(ctx context.Context, pod *v1.Pod) error

    // GetMountedVolumesForPod返回一个包含指定Pod引用的已成功挂载和已挂载的VolumeMap。
    // 映射中的键是OuterVolumeSpecName（即pod.Spec.Volumes[x].Name）。
    // 如果Pod没有卷，则返回一个空的VolumeMap。
    GetMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap

    // GetPossiblyMountedVolumesForPod返回一个包含指定Pod引用的已成功挂载和当前可能正在被挂载（"uncertain"）的VolumeMap。
    // 映射中的键是OuterVolumeSpecName（即pod.Spec.Volumes[x].Name）。
    // 如果Pod没有卷，则返回一个空的VolumeMap。
    GetPossiblyMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap

    // GetExtraSupplementalGroupsForPod返回Pod的额外辅助组列表。
    // 这些额外辅助组来自Pod依赖的持久卷的注释。
    GetExtraSupplementalGroupsForPod(pod *v1.Pod) []int64

    // GetVolumesInUse返回实现volume.Attacher接口且根据实际状态和期望状态的缓存当前正在使用的所有卷的列表。
    // 一旦卷被添加到期望状态，表示它应该被挂载到这个节点上，它就被视为"正在使用"，
    // 并且在从期望状态和实际状态中都被移除，或者被卸载（在实际状态中指示）之前，它将保持为"正在使用"状态。
    GetVolumesInUse() []v1.UniqueVolumeName

    // ReconcilerStatesHasBeenSynced仅在实际状态在reconciler中至少同步一次后返回true，
    // 以便可以安全地更新从实际状态检索的已挂载卷列表。
    ReconcilerStatesHasBeenSynced() bool

    // 如果给定的卷已连接到该节点，则VolumeIsAttached返回true。
    VolumeIsAttached(volumeName v1.UniqueVolumeName) bool

    // 将指定的卷标记为已成功在节点的卷状态中报告为"正在使用"。
    MarkVolumesAsReportedInUse(volumesReportedAsInUse []v1.UniqueVolumeName)
}
```

## DesiredStateOfWorld

```go
// DesiredStateOfWorld 定义了 kubelet volume 管理器所需的线程安全操作集合，用于表示期望的世界状态缓存。
// 该缓存包含 volumes->pods 的映射，即应该连接到此节点的所有卷以及引用它们并应该挂载该卷的 pods 的集合。
// 注意：这与由 attach/detach 控制器实现的 DesiredStateOfWorld 是不同的。它们分别跟踪不同的对象。
// 此接口包含了 kubelet volume 管理器特定的状态信息。
type DesiredStateOfWorld interface {
	// AddPodToVolume 将给定的 pod 添加到缓存中的给定 volume，表示指定的 pod 应该挂载指定的 volume。
	// 根据 volumeSpec 生成并返回一个唯一的 volumeName。
	// 如果没有 volume 插件能够支持给定的 volumeSpec，或者有多个插件支持它，将返回错误。
	// 如果在应该连接到此节点的卷列表中不存在名称为 volumeName 的 volume，则会隐式添加该 volume。
	// 如果指定 volume 下已经存在具有相同唯一名称的 pod，则不执行任何操作。
	AddPodToVolume(podName types.UniquePodName, pod *v1.Pod, volumeSpec *volume.Spec, outerVolumeSpecName string, volumeGidValue string, seLinuxContainerContexts []*v1.SELinuxOptions) (v1.UniqueVolumeName, error)

	// MarkVolumesReportedInUse 将 reportedVolumes 列表中的 volume 的 ReportedInUse 标志设置为 true。
	// 对于不在 reportedVolumes 列表中的 volume，ReportedInUse 标志将被重置为 false。
	// 新创建的 volume 的默认 ReportedInUse 值为 false。
	// 当该值设置为 true 时，表示该 volume 已成功添加到节点状态的 VolumesInUse 字段中。
	// 在执行挂载操作之前需要检查此值。
	// 如果在 reportedVolumes 列表中的 volume 在应该连接到此节点的卷列表中不存在，则会被跳过而不报错。
	MarkVolumesReportedInUse(reportedVolumes []v1.UniqueVolumeName)

	// DeletePodFromVolume 从缓存中的给定 volume 中移除给定的 pod，表示指定的 pod 不再需要指定的 volume。
	// 如果在指定 volume 下不存在具有相同唯一名称的 pod，则不执行任何操作。
	// 如果在附加的 volume 列表中不存在名称为 volumeName 的 volume，则不执行任何操作。
	// 如果删除 pod 后，指定的 volume 不再包含其他子 pod，则也将删除该 volume。
	DeletePodFromVolume(podName types.UniquePodName, volumeName v1.UniqueVolumeName)

	// VolumeExists 如果给定的 volume 存在于应该连接到此节点的卷列表中，则返回 true。
	// 如果在指定 volume 下不存在具有相同唯一名称的 pod，则返回 false。
	VolumeExists(volumeName v1.UniqueVolumeName, seLinuxMountContext string) bool

	// PodExistsInVolume 如果给定的 pod 存在于缓存中给定 volume 的 podsToMount 列表中，则返回 true。
	// 如果在指定 volume 下不存在具有相同唯一名称的 pod，则返回 false。
	// 如果在附加的 volume 列表中不存在名称为 volumeName 的 volume，则返回 false。
	PodExistsInVolume(podName types.UniquePodName, volumeName v1.UniqueVolumeName, seLinuxMountContext string) bool

	// GetVolumesToMount 基于当前的期望世界状态，生成并返回应该连接到此节点的 volume 列表以及它们应该挂载到的 pods。
	GetVolumesToMount() []VolumeToMount

	// GetPods 生成并返回一个包含 pods 的映射，以 pod 的唯一名称为索引。
	// 此映射可用于确定哪些 pod 目前处于期望的世界状态中。
	GetPods() map[types.UniquePodName]bool

	// VolumeExistsWithSpecName 如果给定的 volume 使用 volume spec 名称（也称为 InnerVolumeSpecName）存在于应该连接到此节点的卷列表中，则返回 true。
	// 如果在指定 volume 下不存在具有相同名称的 pod，则返回 false。
	VolumeExistsWithSpecName(podName types.UniquePodName, volumeSpecName string) bool

	// AddErrorToPod 将给定的错误添加到缓存中的给定 pod。
	// 此错误将在后续的 GetPodErrors() 调用中返回。
	// 每个错误字符串只会存储一次。
	AddErrorToPod(podName types.UniquePodName, err string)

	// PopPodErrors 返回给定 pod 上累积的错误并清除它们。
	PopPodErrors(podName types.UniquePodName) []string

	// GetPodsWithErrors 返回存储有错误的 pods 的名称列表。
	GetPodsWithErrors() []types.UniquePodName

	// MarkVolumeAttachability 更新给定 volume 的附加性（attachability）。
	MarkVolumeAttachability(volumeName v1.UniqueVolumeName, attachable bool)

	// UpdatePersistentVolumeSize 更新期望的世界状态中的持久 volume 大小。
	// 这样可以将其与实际大小进行比较，并在必要时执行 volume 扩展。
	UpdatePersistentVolumeSize(volumeName v1.UniqueVolumeName, size *resource.Quantity)
}
```

### desiredStateOfWorld

```go
type desiredStateOfWorld struct {
	// volumesToMount 是一个包含应该连接到此节点并挂载到引用它的 pods 的 volume 集合的映射。
	// 映射的键是 volume 的名称，值是一个包含有关该 volume 的更多信息的 volume 对象。
	volumesToMount map[v1.UniqueVolumeName]volumeToMount
	// volumePluginMgr 是用于创建 volume 插件对象的 volume 插件管理器。
	volumePluginMgr *volume.VolumePluginMgr
	// podErrors 是由 desiredStateOfWorldPopulator 捕获的有关给定 pod 的 volumes 的错误集合。
	podErrors map[types.UniquePodName]sets.String
	// seLinuxTranslator 将 v1.SELinuxOptions 翻译为文件 SELinux 标签。
	seLinuxTranslator util.SELinuxLabelTranslator

	sync.RWMutex
}
```

#### VolumeToMount

```go
// VolumeToMount 表示连接到此节点并需要挂载到 PodName 的卷。
type VolumeToMount struct {
	operationexecutor.VolumeToMount
}
```

#### volumeToMount

```go
// volumeToMount 表示应连接到此节点的 volume 并应挂载到 podsToMount 的 volume。
type volumeToMount struct {
	// volumeName 包含此 volume 的唯一标识符。
	volumeName v1.UniqueVolumeName

	// podsToMount 是一个包含引用该 volume 并应该在连接后挂载它的 pods 的集合的映射。
	// 映射的键是 pod 的名称，值是一个包含有关该 pod 的更多信息的 pod 对象。
	podsToMount map[types.UniquePodName]podToMount

	// pluginIsAttachable 表示该 volume 的插件实现了 volume.Attacher 接口。
	pluginIsAttachable bool

	// pluginIsDeviceMountable 表示该 volume 的插件实现了 volume.DeviceMounter 接口。
	pluginIsDeviceMountable bool

	// volumeGidValue 包含 GID 注释的值（如果存在）。
	volumeGidValue string

	// reportedInUse 表示该 volume 已成功添加到节点状态的 VolumesInUse 字段中。
	reportedInUse bool

	// desiredSizeLimit 表示 volume 的期望上限大小（如果支持）。
	desiredSizeLimit *resource.Quantity

	// persistentVolumeSize 记录期望世界状态中持久 volume 的大小。
	// 通常，该值反映在 pv.Spec.Capacity 中记录的大小。
	persistentVolumeSize *resource.Quantity

	// effectiveSELinuxMountFileLabel 是将使用挂载选项应用于 volume 的 SELinux 标签。
	// 如果为空，则：
	// - 无法确定上下文+标签（由容器运行时随机分配）
	// - 或者负责该 volume 的 volume 插件不支持使用 -o context 进行挂载
	// - 或者 volume 不支持 ReadWriteOncePod
	// - 或者操作系统不支持 SELinux
	// 在所有情况下，挂载该 volume 时 SELinux 上下文无关紧要。
	effectiveSELinuxMountFileLabel string

	// originalSELinuxLabel 是在所有访问模式下都支持 SELinux 挂载时将使用的 SELinux 标签。
	// 对于 RWOP volumes 它与 effectiveSELinuxMountFileLabel 相同。
	// 它仅用于报告潜在的 SELinux 不匹配指标。
	// 如果为空，则：
	// - 无法确定上下文+标签（由容器运行时随机分配）
	// - 或者负责该 volume 的 volume 插件不支持使用 -o context 进行挂载
	// - 或者操作系统不支持 SELinux
	originalSELinuxLabel string
}
```

#### podToMount

```go
// podToMount 表示引用底层 volume 并在连接后应挂载该 volume 的 pod。
type podToMount struct {
	// podName 包含该 pod 的名称。
	podName types.UniquePodName

	// pod 是要将 volume 挂载到的 pod。用于创建 NewMounter。
	pod *v1.Pod

	// volumeSpec 包含此 volume 的规格。用于生成 volume 插件对象，并传递给插件方法。
	// 对于非 PVC（PersistentVolumeClaim） volume，它与 pod 对象中定义的相同。对于 PVC volume，它是从解引用的 PV（PersistentVolume） 对象中获取的。
	volumeSpec *volume.Spec

	// outerVolumeSpecName 是在 pod 中直接引用的 volume 的 volume.Spec.Name()。
	// 如果通过 PersistentVolumeClaim 引用 volume，则包含 PersistentVolumeClaim 的 volume.Spec.Name()。
	outerVolumeSpecName string
	// mountRequestTime 存储请求挂载的时间。
	mountRequestTime time.Time
}
```

#### AddPodToVolume

```go
// desiredStateOfWorld结构体的AddPodToVolume方法，用于将Pod添加到Volume中
func (dsw *desiredStateOfWorld) AddPodToVolume(
	podName types.UniquePodName,
	pod *v1.Pod,
	volumeSpec *volume.Spec,
	outerVolumeSpecName string,
	volumeGidValue string,
	seLinuxContainerContexts []*v1.SELinuxOptions) (v1.UniqueVolumeName, error) {
	// 加锁，确保并发安全
	dsw.Lock()
	defer dsw.Unlock()

	// 根据volumeSpec查找对应的volumePlugin
	volumePlugin, err := dsw.volumePluginMgr.FindPluginBySpec(volumeSpec)
	if err != nil || volumePlugin == nil {
		// 如果查找失败或者找不到对应的plugin，返回错误
		return "", fmt.Errorf(
			"failed to get Plugin from volumeSpec for volume %q err=%v",
			volumeSpec.Name(),
			err)
	}

	var volumeName v1.UniqueVolumeName

	// 根据volume是否可附加或可挂载设备来确定使用唯一的volume名称
	attachable := util.IsAttachableVolume(volumeSpec, dsw.volumePluginMgr)
	deviceMountable := util.IsDeviceMountableVolume(volumeSpec, dsw.volumePluginMgr)
	if attachable || deviceMountable {
		// 对于可附加或可挂载设备的volume，使用插件报告的唯一volume名称
		volumeName, err = util.GetUniqueVolumeNameFromSpec(volumePlugin, volumeSpec)
		if err != nil {
			return "", fmt.Errorf(
				"failed to GetUniqueVolumeNameFromSpec for volumeSpec %q using volume plugin %q err=%v",
				volumeSpec.Name(),
				volumePlugin.GetPluginName(),
				err)
		}
	} else {
		// 对于不可附加且不可挂载设备的volume，基于pod的namespace、名称和volume在pod中的名称生成唯一名称
		volumeName = util.GetUniqueVolumeNameFromSpecWithPod(podName, volumePlugin, volumeSpec)
	}

	// 获取volumeSpec的SELinux标签，以及plugin是否支持SELinux上下文挂载
	seLinuxFileLabel, pluginSupportsSELinuxContextMount, err := dsw.getSELinuxLabel(volumeSpec, seLinuxContainerContexts)
	if err != nil {
		return "", err
	}
	// 记录volume的SELinux标签上下文信息
	klog.V(4).InfoS("expected volume SELinux label context", "volume", volumeSpec.Name(), "label", seLinuxFileLabel)

	// 检查volume是否已存在于volumesToMount中
	if vol, volumeExists := dsw.volumesToMount[volumeName]; !volumeExists {
		// 如果volume不存在，则添加新的volumeToMount记录
		// 并记录volume的相关属性
		var sizeLimit *resource.Quantity
		if volumeSpec.Volume != nil {
			// 如果是本地临时存储的volume，计算其限制大小
			if util.IsLocalEphemeralVolume(*volumeSpec.Volume) {
				podLimits := resourcehelper.PodLimits(pod, resourcehelper.PodResourcesOptions{})
				ephemeralStorageLimit := podLimits[v1.ResourceEphemeralStorage]
				sizeLimit = resource.NewQuantity(ephemeralStorageLimit.Value(), resource.BinarySI)
				if volumeSpec.Volume.EmptyDir != nil &&
					volumeSpec.Volume.EmptyDir.SizeLimit != nil &&
					volumeSpec.Volume.EmptyDir.SizeLimit.Value() > 0 &&
					(sizeLimit.Value() == 0 || volumeSpec.Volume.EmptyDir.SizeLimit.Value() < sizeLimit.Value()) {
					sizeLimit = resource.NewQuantity(volumeSpec.Volume.EmptyDir.SizeLimit.Value(), resource.BinarySI)
				}
			}
		}
		// 获取有效的SELinux挂载标签
		effectiveSELinuxMountLabel := seLinuxFileLabel
		if !util.VolumeSupportsSELinuxMount(volumeSpec) {
			// 对于不支持SELinux挂载的volume，清除期望的SELinux标签
			klog.V(4).InfoS("volume does not support SELinux context mount, clearing the expected label", "volume", volumeSpec.Name())
			effectiveSELinuxMountLabel = ""
		}
		// 如果SELinux标签非空，增加对应的计数器
		if seLinuxFileLabel != "" {
			seLinuxVolumesAdmitted.Add(1.0)
		}
		// 创建volumeToMount对象并记录volume的相关属性
		vmt := volumeToMount{
			volumeName:                     volumeName,
			podsToMount:                    make(map[types.UniquePodName]podToMount),
			pluginIsAttachable:             attachable,
			pluginIsDeviceMountable:        deviceMountable,
			volumeGidValue:                 volumeGidValue,
			reportedInUse:                  false,
			desiredSizeLimit:               sizeLimit,
			effectiveSELinuxMountFileLabel: effectiveSELinuxMountLabel,
			originalSELinuxLabel:           seLinuxFileLabel,
		}
		// 记录volume的期望大小
		if volumeSpec.PersistentVolume != nil {
			pvCap := volumeSpec.PersistentVolume.Spec.Capacity.Storage()
			if pvCap != nil {
				pvCapCopy := pvCap.DeepCopy()
				vmt.persistentVolumeSize = &pvCapCopy
			}
		}
		// 将新的volumeToMount对象添加到volumesToMount中
		dsw.volumesToMount[volumeName] = vmt
	} else {
		// volume已存在，检查是否支持SELinux挂载
		if pluginSupportsSELinuxContextMount {
			if seLinuxFileLabel != vol.originalSELinuxLabel {
				// TODO: 在测试后更新错误消息，例如至少添加冲突的pod名称。
				fullErr := fmt.Errorf("conflicting SELinux labels of volume %s: %q and %q", volumeSpec.Name(), vol.originalSELinuxLabel, seLinuxFileLabel)
				// 根据不同情况处理SELinux挂载错误
				supported := util.VolumeSupportsSELinuxMount(volumeSpec)
				if err := handleSELinuxMetricError(fullErr, supported, seLinuxVolumeContextMismatchWarnings, seLinuxVolumeContextMismatchErrors); err != nil {
					return "", err
				}
			}
		}
	}

	// 获取旧的PodMount对象
	oldPodMount, ok := dsw.volumesToMount[volumeName].podsToMount[podName]
	mountRequestTime := time.Now()
	if ok && !volumePlugin.RequiresRemount(volumeSpec) {
		// 如果旧的PodMount对象存在且volumePlugin不需要重新挂载volume，保留其挂载请求时间
		mountRequestTime = oldPodMount.mountRequestTime
	}

	// 创建新的podToMount对象，并添加到volumesToMount中
	dsw.volumesToMount[volumeName].podsToMount[podName] = podToMount{
		podName:             podName,
		pod:                 pod,
		volumeSpec:          volumeSpec,
		outerVolumeSpecName: outerVolumeSpecName,
		mountRequestTime:    mountRequestTime,
	}
	return volumeName, nil
}
```

#### MarkVolumesReportedInUse

```go
// desiredStateOfWorld结构体的MarkVolumesReportedInUse方法，用于标记已使用的volumes
func (dsw *desiredStateOfWorld) MarkVolumesReportedInUse(
	reportedVolumes []v1.UniqueVolumeName) {
	// 加锁，确保并发安全
	dsw.Lock()
	defer dsw.Unlock()

	// 将reportedVolumes转换成map，便于快速查找
	reportedVolumesMap := make(
		map[v1.UniqueVolumeName]bool, len(reportedVolumes) /* capacity */)

	for _, reportedVolume := range reportedVolumes {
		reportedVolumesMap[reportedVolume] = true
	}

	// 遍历volumesToMount，将在reportedVolumes中存在的volume标记为已使用
	for volumeName, volumeObj := range dsw.volumesToMount {
		_, volumeReported := reportedVolumesMap[volumeName]
		volumeObj.reportedInUse = volumeReported
		dsw.volumesToMount[volumeName] = volumeObj
	}
}
```

#### DeletePodFromVolume

```go
// desiredStateOfWorld结构体的DeletePodFromVolume方法，用于从volume中删除Pod
func (dsw *desiredStateOfWorld) DeletePodFromVolume(
	podName types.UniquePodName, volumeName v1.UniqueVolumeName) {
	// 加锁，确保并发安全
	dsw.Lock()
	defer dsw.Unlock()

	// 从podErrors中删除相关的pod错误信息
	delete(dsw.podErrors, podName)

	// 获取volume对象
	volumeObj, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return
	}

	// 检查对应的pod是否存在于volume中
	if _, podExists := volumeObj.podsToMount[podName]; !podExists {
		return
	}

	// 删除对应的pod
	delete(dsw.volumesToMount[volumeName].podsToMount, podName)

	// 如果该volume已没有child pod，从volumesToMount中删除volume记录
	if len(dsw.volumesToMount[volumeName].podsToMount) == 0 {
		delete(dsw.volumesToMount, volumeName)
	}
}
```

#### UpdatePersistentVolumeSize

```go
// desiredStateOfWorld结构体的UpdatePersistentVolumeSize方法，用于更新持久化volume的大小
func (dsw *desiredStateOfWorld) UpdatePersistentVolumeSize(volumeName v1.UniqueVolumeName, size *resource.Quantity) {
	// 加锁，确保并发安全
	dsw.Lock()
	defer dsw.Unlock()

	// 获取volume对象
	vol, volExists := dsw.volumesToMount[volumeName]
	if volExists {
		// 更新volume的持久化大小
		vol.persistentVolumeSize = size
		dsw.volumesToMount[volumeName] = vol
	}
}
```

#### VolumeExists

```go
// desiredStateOfWorld结构体的VolumeExists方法，用于检查指定的volume是否存在于volumesToMount中
func (dsw *desiredStateOfWorld) VolumeExists(
	volumeName v1.UniqueVolumeName, seLinuxMountContext string) bool {
	// 加读锁，允许并发读取
	dsw.RLock()
	defer dsw.RUnlock()

	// 获取volume对象
	vol, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return false
	}
	if feature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		// 处理具有相同名称但具有不同SELinux上下文的两个volumes作为两个*不同*的volumes
		// 因为如果使用旧的SELinux上下文挂载volume，必须先卸载旧的volume，然后使用新的上下文重新挂载
		// 这将在以下情况发生：一个使用上下文alpha_t的pod A正在由kubelet终止，其volumes正在被删除，此时一个使用上下文beta_t的pod B已经在同一个节点上调度并使用相同的volumes
		// Pod A的volumes必须完全卸载（包括UnmountDevice），然后以pod B的正确SELinux选项重新挂载
		// 如果没有SELinux，kubelet可能会（并且通常会）重用为pod A挂载的设备
		return vol.effectiveSELinuxMountFileLabel == seLinuxMountContext
	}
	return true
}
```

#### PodExistsInVolume

```go
// desiredStateOfWorld结构体的PodExistsInVolume方法，用于检查指定的pod是否存在于volume中
func (dsw *desiredStateOfWorld) PodExistsInVolume(
	podName types.UniquePodName, volumeName v1.UniqueVolumeName, seLinuxMountOption string) bool {
	// 加读锁，允许并发读取
	dsw.RLock()
	defer dsw.RUnlock()

	// 获取volume对象
	volumeObj, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return false
	}

	if feature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if volumeObj.effectiveSELinuxMountFileLabel != seLinuxMountOption {
			// volume存在，但具有不同的SELinux挂载选项
			// 将其标记为未使用，以便volume被卸载并使用正确的SELinux选项重新挂载
			return false
		}
	}

	// 检查指定的pod是否存在于volume中
	_, podExists := volumeObj.podsToMount[podName]
	return podExists
}
```

#### VolumeExistsWithSpecName

```go
// desiredStateOfWorld结构体的VolumeExistsWithSpecName方法，用于检查指定pod中是否存在具有指定名称的volume
func (dsw *desiredStateOfWorld) VolumeExistsWithSpecName(podName types.UniquePodName, volumeSpecName string) bool {
	// 加读锁，允许并发读取
	dsw.RLock()
	defer dsw.RUnlock()
	for _, volumeObj := range dsw.volumesToMount {
		if podObj, podExists := volumeObj.podsToMount[podName]; podExists {
			// 检查pod中是否存在具有指定名称的volume
			if podObj.volumeSpec.Name() == volumeSpecName {
				return true
			}
		}
	}
	return false
}
```

#### GetPods

```go
// desiredStateOfWorld结构体的GetPods方法，用于获取所有正在使用的Pod的列表
func (dsw *desiredStateOfWorld) GetPods() map[types.UniquePodName]bool {
	// 加读锁，允许并发读取
	dsw.RLock()
	defer dsw.RUnlock()

	// 创建一个map，用于存储所有正在使用的Pod的名称
	podList := make(map[types.UniquePodName]bool)
	// 遍历volumesToMount，将所有正在使用的Pod的名称添加到podList中
	for _, volumeObj := range dsw.volumesToMount {
		for podName := range volumeObj.podsToMount {
			podList[podName] = true
		}
	}
	return podList
}
```

#### GetVolumesToMount

```go
// desiredStateOfWorld结构体的GetVolumesToMount方法，用于获取正在挂载的所有volumes的信息
func (dsw *desiredStateOfWorld) GetVolumesToMount() []VolumeToMount {
	// 加读锁，允许并发读取
	dsw.RLock()
	defer dsw.RUnlock()

	// 创建一个切片，用于存储所有正在挂载的volumes的信息
	volumesToMount := make([]VolumeToMount, 0 /* len */, len(dsw.volumesToMount) /* cap */)
	// 遍历volumesToMount，将所有正在挂载的volumes的信息添加到volumesToMount中
	for volumeName, volumeObj := range dsw.volumesToMount {
		for podName, podObj := range volumeObj.podsToMount {
			vmt := VolumeToMount{
				VolumeToMount: operationexecutor.VolumeToMount{
					VolumeName:              volumeName,
					PodName:                 podName,
					Pod:                     podObj.pod,
					VolumeSpec:              podObj.volumeSpec,
					PluginIsAttachable:      volumeObj.pluginIsAttachable,
					PluginIsDeviceMountable: volumeObj.pluginIsDeviceMountable,
					OuterVolumeSpecName:     podObj.outerVolumeSpecName,
					VolumeGidValue:          volumeObj.volumeGidValue,
					ReportedInUse:           volumeObj.reportedInUse,
					MountRequestTime:        podObj.mountRequestTime,
					DesiredSizeLimit:        volumeObj.desiredSizeLimit,
					SELinuxLabel:            volumeObj.effectiveSELinuxMountFileLabel,
				},
			}
			// 如果volumeObj的persistentVolumeSize非空，则将其值赋给vmt的DesiredPersistentVolumeSize字段
			if volumeObj.persistentVolumeSize != nil {
				vmt.DesiredPersistentVolumeSize = volumeObj.persistentVolumeSize.DeepCopy()
			}
			// 将vmt添加到volumesToMount中
			volumesToMount = append(volumesToMount, vmt)
		}
	}
	return volumesToMount
}
```

#### AddErrorToPod

```go
// AddErrorToPod将错误添加到指定Pod的错误列表中。
func (dsw *desiredStateOfWorld) AddErrorToPod(podName types.UniquePodName, err string) {
	dsw.Lock()
	defer dsw.Unlock()

	// 检查是否已经存在该Pod的错误列表，如果存在则将错误添加到列表中，否则创建一个新的错误列表并添加错误。
	if errs, found := dsw.podErrors[podName]; found {
		if errs.Len() <= maxPodErrors { // 检查错误列表长度是否小于等于最大错误数
			errs.Insert(err) // 将错误添加到错误列表中
		}
		return
	}
	dsw.podErrors[podName] = sets.NewString(err) // 创建新的错误列表并添加错误
}
```

#### PopPodErrors

```go
// PopPodErrors从指定Pod的错误列表中获取所有错误，并在获取完成后从错误列表中移除该Pod的错误列表。
func (dsw *desiredStateOfWorld) PopPodErrors(podName types.UniquePodName) []string {
	dsw.Lock()
	defer dsw.Unlock()

	// 检查是否存在该Pod的错误列表，如果存在则获取所有错误并移除该Pod的错误列表，否则返回空列表。
	if errs, found := dsw.podErrors[podName]; found {
		delete(dsw.podErrors, podName) // 移除Pod的错误列表
		return errs.List()             // 获取Pod的错误列表并转换为切片返回
	}
	return []string{} // 返回空列表
}
```

#### GetPodsWithErrors

```go
// GetPodsWithErrors获取所有存在错误的Pod的名称列表。
func (dsw *desiredStateOfWorld) GetPodsWithErrors() []types.UniquePodName {
	dsw.RLock()
	defer dsw.RUnlock()

	pods := make([]types.UniquePodName, 0, len(dsw.podErrors))
	// 遍历所有存在错误的Pod并将它们的名称添加到列表中。
	for podName := range dsw.podErrors {
		pods = append(pods, podName)
	}
	return pods
}
```

#### MarkVolumeAttachability

```go
// MarkVolumeAttachability标记指定卷是否可附加到节点。
func (dsw *desiredStateOfWorld) MarkVolumeAttachability(volumeName v1.UniqueVolumeName, attachable bool) {
	dsw.Lock()
	defer dsw.Unlock()

	volumeObj, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return
	}

	// 将卷的可附加性设置为指定值，并更新卷对象。
	volumeObj.pluginIsAttachable = attachable
	dsw.volumesToMount[volumeName] = volumeObj
}
```

#### getSELinuxMountSupport

```go
// getSELinuxMountSupport获取指定卷的SELinux挂载支持。
func (dsw *desiredStateOfWorld) getSELinuxMountSupport(volumeSpec *volume.Spec) (bool, error) {
	return util.SupportsSELinuxContextMount(volumeSpec, dsw.volumePluginMgr)
}
```

#### handleSELinuxMetricError

```go
// handleSELinuxMetricError基于isRWOP参数更新相应的警告/错误指标，并根据情况处理或返回错误。
func handleSELinuxMetricError(err error, seLinuxSupported bool, warningMetric, errorMetric *metrics.Gauge) error {
	if seLinuxSupported {
		errorMetric.Add(1.0) // 如果支持SELinux，则增加错误指标并返回错误。
		return err
	}

	// 否则，增加警告指标，并输出警告日志。
	warningMetric.Add(1.0)
	klog.V(4).ErrorS(err, "Please report this error in https://github.com/kubernetes/enhancements/issues/1710, together with full Pod yaml file")
	return nil
}
```

## ActualStateOfWorld

```go
// ActualStateOfWorld 定义了 kubelet 卷管理器中实际世界缓存的一组线程安全操作。
// 该缓存包含 volumes->pods 的映射，即连接到该节点的所有卷及管理器认为已成功挂载到该卷的 pods。
// 注意：这与 attach/detach 控制器实现的 ActualStateOfWorld 是不同的。它们都跟踪不同的对象。
// 本接口包含 kubelet 卷管理器特定的状态信息。
type ActualStateOfWorld interface {
	// ActualStateOfWorld 必须实现 operationexecutor 所需的方法，以允许 operationexecutor 与其交互。
	operationexecutor.ActualStateOfWorldMounterUpdater

	// ActualStateOfWorld 必须实现 operationexecutor 所需的方法，以允许 operationexecutor 与其交互。
	operationexecutor.ActualStateOfWorldAttacherUpdater

	// AddPodToVolume 将给定的 pod 添加到缓存中的给定卷，表示指定的卷已成功挂载到指定的 pod。
	// 如果具有相同唯一名称的 pod 已存在于指定的卷下，将重置 pod 的 remountRequired 值。
	// 如果在附加的卷列表中不存在名为 volumeName 的卷，则返回错误。
	AddPodToVolume(operationexecutor.MarkVolumeOpts) error

	// MarkRemountRequired 标记每个成功附加和挂载到指定 pod 的卷为需要重新挂载（如果卷的插件指示在 pod 更新时需要重新挂载）。
	// 依赖于此操作来原子更新卷上的内容以适应 pod 更新。
	MarkRemountRequired(podName volumetypes.UniquePodName)

	// SetDeviceMountState 为给定卷设置设备挂载状态。
	// 当 deviceMountState 设置为 DeviceGloballyMounted 时，设备将被全局挂载。
	// 当设置为 DeviceMountUncertain 时，也表示该卷可能会被全局挂载。
	// 在这两种情况下，必须在分离之前从全局挂载点卸载卷。
	// 如果在附加的卷列表中不存在名为 volumeName 的卷，则返回错误。
	SetDeviceMountState(volumeName v1.UniqueVolumeName, deviceMountState operationexecutor.DeviceMountState, devicePath, deviceMountPath, seLinuxMountContext string) error

	// DeletePodFromVolume 从缓存中的给定卷中删除给定的 pod，表示该卷已成功从 pod 卸载。
	// 如果具有相同唯一名称的 pod 在指定卷下不存在，则不进行任何操作。
	// 如果在附加的卷列表中不存在名为 volumeName 的卷，则返回错误。
	DeletePodFromVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error

	// DeleteVolume 从缓存中的附加卷列表中删除给定的卷，表示该卷已成功从该节点分离。
	// 如果在附加的卷列表中不存在名为 volumeName 的卷，则不进行任何操作。
	// 如果名为 volumeName 的卷存在且其挂载的 pod 列表不为空，则返回错误。
	DeleteVolume(volumeName v1.UniqueVolumeName) error

	// PodExistsInVolume 返回 true，如果在缓存中的给定卷的 mountedPods 列表中存在给定的 pod，
	// 表示该卷已附加到该节点并且 pod 已成功挂载该卷。
	// 如果具有相同唯一名称的 pod 在指定卷下不存在，则返回 false。
	// 如果在附加的卷列表中不存在名为 volumeName 的卷，则返回 volumeNotAttachedError，表示该卷尚未附加。
	// 如果给定的 volumeName/podName 组合存在，但 remountRequired 的值为 true，则返回 remountRequiredError，
	// 表示该卷已成功挂载到该 pod，但应重新挂载以反映引用 pod 的更改。
	// 原子更新卷依赖于此操作以更新卷的内容。
	// 所有卷挂载调用应该是幂等的，因此对于不需要更新内容的卷的第二次挂载调用不应该失败。
	PodExistsInVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName, desiredVolumeSize resource.Quantity, seLinuxLabel string) (bool, string, error)

	// PodRemovedFromVolume 返回 true，如果给定的 pod 在缓存中的给定卷的 mountedPods 列表中不存在，
	// 表示 pod 已完全卸载该卷或从未挂载过该卷。
	// 如果卷已完全挂载或处于不确定的挂载状态，则认为该 pod 仍然存在于卷管理器的实际世界状态中，返回 false。
	PodRemovedFromVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) bool

	// VolumeExistsWithSpecName 返回 true，如果以 volume spec 名称（也称为 InnerVolumeSpecName）指定的卷在应附加到该节点的卷列表中存在。
	// 如果在指定卷下不存在具有相同名称的 pod，则返回 false。
	VolumeExistsWithSpecName(podName volumetypes.UniquePodName, volumeSpecName string) bool

	// VolumeExists 返回 true，如果给定卷在缓存的附加卷列表中存在，表示该卷已附加到该节点。
	VolumeExists(volumeName v1.UniqueVolumeName) bool

	// GetMountedVolumes 生成并返回基于当前实际世界状态的成功附加和挂载到 pod 的卷及对应的 pods 列表。
	GetMountedVolumes() []MountedVolume

	// GetAllMountedVolumes 返回所有可能挂载的卷列表，包括 VolumeMounted 状态和 VolumeMountUncertain 状态的卷。
	GetAllMountedVolumes() []MountedVolume

	// GetMountedVolumesForPod 生成并返回基于当前实际世界状态的成功附加和挂载到指定 pod 的卷列表。
	GetMountedVolumesForPod(podName volumetypes.UniquePodName) []MountedVolume

	// GetPossiblyMountedVolumesForPod 生成并返回基于当前实际世界状态的附加和挂载到指定 pod 的卷列表，或者处于 "不确定" 状态，
	// 即卷插件可能正在挂载该卷。
	GetPossiblyMountedVolumesForPod(podName volumetypes.UniquePodName) []MountedVolume

	// GetGloballyMountedVolumes 生成并返回所有已全局挂载的附加卷列表。
	// 该列表可用于确定哪些卷应该在节点的 VolumesInUse 状态字段中报告为 "正在使用"。
	// 这里的全局挂载指的是适用性卷的共享插件挂载点，从中创建 pod 特定挂载点（通过 bind 挂载）。
	GetGloballyMountedVolumes() []AttachedVolume

	// GetUnmountedVolumes 生成并返回已附加但没有挂载 pod 的附加卷列表。
	// 该列表可用于确定哪些卷不再被引用，可以全局卸载和分离。
	GetUnmountedVolumes() []AttachedVolume

	// GetAttachedVolumes 返回已知已附加到节点的卷列表。
	// 该列表可用于确定卷是正在使用中还是挂载/卸载操作正在等待。
	GetAttachedVolumes() []AttachedVolume

	// SyncReconstructedVolume 检查卷的 volume.outerVolumeSpecName 和从 dsw（Desired State of World） 中填充的值是否匹配，
	// 如果不匹配，则将其更新为来自 dsw 的值。
	SyncReconstructedVolume(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, outerVolumeSpecName string)

	// AddAttachUncertainReconstructedVolume 将指定的卷作为不确定地附加到 ASW 中。
	AddAttachUncertainReconstructedVolume(volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, nodeName types.NodeName, devicePath string) error

	// UpdateReconstructedDevicePath 从 Node.Status.VolumesAttached 更新重建卷的 devicePath。
	// 只有当卷仍处于不确定状态时才更新 ASW。如果卷在此期间已挂载，则其 devicePath 必须已通过此更新修复。
	UpdateReconstructedDevicePath(volumeName v1.UniqueVolumeName, devicePath string)

	// UpdateReconstructedVolumeAttachability 从 API 服务器更新卷的附加性。
	UpdateReconstructedVolumeAttachability(volumeName v1.UniqueVolumeName, volumeAttachable bool)
}
```

### MountedVolume

```go
// MountedVolume 表示已成功挂载到 pod 的卷。
type MountedVolume struct {
	operationexecutor.MountedVolume
}
```

### AttachedVolume

```go
// AttachedVolume 表示已附加到节点的卷。
type AttachedVolume struct {
	operationexecutor.AttachedVolume

	// DeviceMountState 表示设备是否已全局挂载。
	DeviceMountState operationexecutor.DeviceMountState

	// SELinuxMountContext 是卷在全局目录上挂载的上下文（通过 -o context=XYZ 挂载选项）。如果为空，则表示没有使用 "-o context=" 挂载。
	SELinuxMountContext string
}
```

### actualStateOfWorld

```go
type actualStateOfWorld struct {
	// nodeName 是该节点的名称。此值传递给 Attach/Detach。
	nodeName types.NodeName

	// attachedVolumes 是一个包含 kubelet 卷管理器认为已成功附加到该节点的卷集合的映射。
	// 默认情况下，未实现 attacher 接口的卷类型被认为处于此状态。
	// 映射的键是卷的名称，值是有关已附加卷的更多信息的对象。
	attachedVolumes map[v1.UniqueVolumeName]attachedVolume

	// foundDuringReconstruction 是从 kubelet 根目录重新启动 kubelet 时发现的卷的映射。
	foundDuringReconstruction map[v1.UniqueVolumeName]map[volumetypes.UniquePodName]types.UID

	// volumePluginMgr 是用于创建卷插件对象的卷插件管理器。
	volumePluginMgr *volume.VolumePluginMgr
	sync.RWMutex
}
```

#### mountedPod

```go
// mountedPod 对象表示 kubelet 卷管理器认为底层卷已成功挂载的 pod。
type mountedPod struct {
	// podName 是 pod 的名称。
	podName volumetypes.UniquePodName

	// podUID 是 pod 的 UID。
	podUID types.UID

	// mounter 用于挂载。
	mounter volume.Mounter

	// blockVolumeMapper 用于块卷支持。
	blockVolumeMapper volume.BlockVolumeMapper

	// spec 是包含此卷规范的卷规范。
	// 用于生成卷插件对象，并传递给插件方法。
	// 特别是 Unmount 方法使用 spec.Name() 作为挂载路径中的 volumeSpecName：
	// /var/lib/kubelet/pods/{podUID}/volumes/{escapeQualifiedPluginName}/{volumeSpecName}/
	volumeSpec *volume.Spec

	// outerVolumeSpecName 是直接在 pod 中引用的卷的 volume.Spec.Name()。
	// 如果卷通过持久卷声明进行引用，则此字段包含持久卷声明的 volume.Spec.Name()。
	outerVolumeSpecName string

	// remountRequired 表示底层卷已成功挂载到此 pod，但应重新挂载以反映引用 pod 的更改。
	// 原子更新卷依赖于此操作以更新卷的内容。
	// 所有卷挂载调用应该是幂等的，因此对于不需要更新内容的卷的第二次挂载调用不应该失败。
	remountRequired bool

	// volumeGidValue 包含 GID 注释的值（如果存在）。
	volumeGidValue string

	// volumeMountStateForPod 存储 pod 的卷挂载状态。
	// 如果为：
	//   - VolumeMounted：表示 pod 的卷已成功挂载。
	//   - VolumeMountUncertain：表示 pod 的卷可能未挂载，但必须卸载。
	volumeMountStateForPod operationexecutor.VolumeMountState

	// seLinuxMountContext 是卷在 Pod 目录中挂载的上下文（通过 -o context=XYZ 挂载选项）。
	// 如果为 nil，则表示未挂载。如果为空字符串，则表示挂载时没有使用 "-o context="。
	seLinuxMountContext string
}
```

#### NewActualStateOfWorld

```go
// NewActualStateOfWorld 返回 ActualStateOfWorld 的新实例。
func NewActualStateOfWorld(nodeName types.NodeName, volumePluginMgr *volume.VolumePluginMgr) ActualStateOfWorld {
	return &actualStateOfWorld{
		nodeName:                  nodeName,
		attachedVolumes:           make(map[v1.UniqueVolumeName]attachedVolume),
		foundDuringReconstruction: make(map[v1.UniqueVolumeName]map[volumetypes.UniquePodName]types.UID),
		volumePluginMgr:           volumePluginMgr,
	}
}
```

#### MarkVolumeAsAttached

```go
// MarkVolumeAsAttached 将卷标记为已附加状态，并将其添加到 actualStateOfWorld。
// 该函数会检查卷是否可附加，然后调用 addVolume 将卷添加到已附加卷集合中。
func (asw *actualStateOfWorld) MarkVolumeAsAttached(
	logger klog.Logger,
	volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, _ types.NodeName, devicePath string) error {

	// 检查卷是否可附加，如果可附加则将 pluginIsAttachable 设置为 volumeAttachabilityTrue。
	pluginIsAttachable := volumeAttachabilityFalse
	if attachablePlugin, err := asw.volumePluginMgr.FindAttachablePluginBySpec(volumeSpec); err == nil && attachablePlugin != nil {
		pluginIsAttachable = volumeAttachabilityTrue
	}

	// 将卷添加到已附加卷集合中。
	return asw.addVolume(volumeName, volumeSpec, devicePath, pluginIsAttachable)
}
```

#### AddAttachUncertainReconstructedVolume

```go
// AddAttachUncertainReconstructedVolume 将不确定状态的重建卷添加到 actualStateOfWorld。
func (asw *actualStateOfWorld) AddAttachUncertainReconstructedVolume(
	volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, _ types.NodeName, devicePath string) error {

	// 将卷添加到已附加卷集合中，并将 pluginIsAttachable 设置为 volumeAttachabilityUncertain。
	return asw.addVolume(volumeName, volumeSpec, devicePath, volumeAttachabilityUncertain)
}
```

#### MarkVolumeAsUncertain

```go
// MarkVolumeAsUncertain 将卷标记为不确定状态，实际上并不执行任何操作，直接返回 nil。
func (asw *actualStateOfWorld) MarkVolumeAsUncertain(
	logger klog.Logger, volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, _ types.NodeName) error {
	return nil
}
```

#### MarkVolumeAsDetached

```go
// MarkVolumeAsDetached 将卷标记为已分离状态，并从 actualStateOfWorld 中删除它。
func (asw *actualStateOfWorld) MarkVolumeAsDetached(
	volumeName v1.UniqueVolumeName, nodeName types.NodeName) {
	asw.DeleteVolume(volumeName)
}
```

#### IsVolumeReconstructed

```go
// IsVolumeReconstructed 检查卷是否处于重建状态（不确定状态）。
// 只有不确定状态的卷才会被认为是重建状态。
func (asw *actualStateOfWorld) IsVolumeReconstructed(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) bool {
	// 获取卷的挂载状态。
	volumeState := asw.GetVolumeMountState(volumeName, podName)

	// 只有不确定状态的卷才会被认为是重建状态。
	if volumeState != operationexecutor.VolumeMountUncertain {
		return false
	}

	// 检查卷是否在 actualStateOfWorld 中被发现。
	asw.RLock()
	defer asw.RUnlock()
	podMap, ok := asw.foundDuringReconstruction[volumeName]
	if !ok {
		return false
	}
	_, foundPod := podMap[podName]
	return foundPod
}
```

#### CheckAndMarkVolumeAsUncertainViaReconstruction

```go
// CheckAndMarkVolumeAsUncertainViaReconstruction 检查并标记卷为重建状态。
// 如果卷已经在 actualStateOfWorld 中被标记为重建状态，则不执行任何操作。
// 如果卷不存在于 actualStateOfWorld 中，则返回 false。
// 否则，将卷标记为重建状态，并添加到 foundDuringReconstruction 中。
func (asw *actualStateOfWorld) CheckAndMarkVolumeAsUncertainViaReconstruction(opts operationexecutor.MarkVolumeOpts) (bool, error) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[opts.VolumeName]
	if !volumeExists {
		return false, nil
	}

	podObj, podExists := volumeObj.mountedPods[opts.PodName]
	if podExists {
		// 如果卷的挂载状态为不确定，则继续尝试卸载卷。
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain {
			return false, nil
		}
		// 如果卷已挂载，则不执行任何操作。
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMounted {
			return false, nil
		}
	}

	// 创建一个新的 mountedPod 对象，表示卷处于重建状态。
	podName := opts.PodName
	podUID := opts.PodUID
	volumeName := opts.VolumeName
	mounter := opts.Mounter
	blockVolumeMapper := opts.BlockVolumeMapper
	outerVolumeSpecName := opts.OuterVolumeSpecName
	volumeGidValue := opts.VolumeGidVolume
	volumeSpec := opts.VolumeSpec

	podObj = mountedPod{
		podName:                podName,
		podUID:                 podUID,
		mounter:                mounter,
		blockVolumeMapper:      blockVolumeMapper,
		outerVolumeSpecName:    outerVolumeSpecName,
		volumeGidValue:         volumeGidValue,
		volumeSpec:             volumeSpec,
		remountRequired:        false,
		volumeMountStateForPod: operationexecutor.VolumeMountUncertain,
	}

	if mounter != nil {
		// 使用最新的 mounter 更新对象中的 mounter。
		podObj.mounter = mounter
	}

	// 将卷标记为重建状态，并添加到 foundDuringReconstruction 中。
	asw.attachedVolumes[volumeName].mountedPods[podName] = podObj

	podMap, ok := asw.foundDuringReconstruction[opts.VolumeName]
	if !ok {
		podMap = map[volumetypes.UniquePodName]types.UID{}
	}
	podMap[opts.PodName] = opts.PodUID
	asw.foundDuringReconstruction[opts.VolumeName] = podMap
	return true, nil
}
```

#### CheckAndMarkDeviceUncertainViaReconstruction

```go
// CheckAndMarkDeviceUncertainViaReconstruction 检查并标记设备为重建状态。
// 该函数要求卷已标记为已附加状态，因此如果卷不存在于 actualStateOfWorld 中，
// 或者处于除 DeviceNotMounted 之外的任何状态，则返回 false。
// 否则，将设备标记为重建状态，并将 deviceMountPath 更新为给定的值。
func (asw *actualStateOfWorld) CheckAndMarkDeviceUncertainViaReconstruction(volumeName v1.UniqueVolumeName, deviceMountPath string) bool {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	// CheckAndMarkDeviceUncertainViaReconstruction 要求卷标记为已附加状态，
	// 所以如果卷不存在于 actualStateOfWorld 中，或者处于除 DeviceNotMounted 之外的任何状态，则返回 false。
	if !volumeExists || volumeObj.deviceMountState != operationexecutor.DeviceNotMounted {
		return false
	}

	// 将设备标记为重建状态，并更新 deviceMountPath。
	volumeObj.deviceMountState = operationexecutor.DeviceMountUncertain
	volumeObj.deviceMountPath = deviceMountPath
	asw.attachedVolumes[volumeName] = volumeObj
	return true
}
```

#### MarkVolumeAsMounted

```go
// MarkVolumeAsMounted 将卷标记为已挂载状态。
// 该函数会调用 AddPodToVolume 将 pod 添加到卷的已挂载 pod 集合中。
func (asw *actualStateOfWorld) MarkVolumeAsMounted(markVolumeOpts operationexecutor.MarkVolumeOpts) error {
	return asw.AddPodToVolume(markVolumeOpts)
}
```

#### AddVolumeToReportAsAttached

```go
// AddVolumeToReportAsAttached 将卷添加到报告为已附加状态的集合中。
// 该函数对 kubelet 端不执行任何操作。
func (asw *actualStateOfWorld) AddVolumeToReportAsAttached(logger klog.Logger, volumeName v1.UniqueVolumeName, nodeName types.NodeName) {
	// no operation for kubelet side
}
```

#### RemoveVolumeFromReportAsAttached

```go
// RemoveVolumeFromReportAsAttached 从报告为已附加状态的集合中移除卷。
// 该函数对 kubelet 端不执行任何操作。
func (asw *actualStateOfWorld) RemoveVolumeFromReportAsAttached(volumeName v1.UniqueVolumeName, nodeName types.NodeName) error {
	// no operation for kubelet side
	return nil
}
```

#### MarkVolumeAsUnmounted

```go
// MarkVolumeAsUnmounted 将卷标记为已卸载状态。
// 该函数会调用 DeletePodFromVolume 从卷的已挂载 pod 集合中删除 pod。
func (asw *actualStateOfWorld) MarkVolumeAsUnmounted(
	podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error {
	return asw.DeletePodFromVolume(podName, volumeName)
}
```

#### MarkDeviceAsMounted

```go
// MarkDeviceAsMounted 将设备标记为已挂载状态。
// 该函数会调用 SetDeviceMountState 来设置设备的挂载状态为 DeviceGloballyMounted，并更新相关字段。
func (asw *actualStateOfWorld) MarkDeviceAsMounted(
	volumeName v1.UniqueVolumeName, devicePath, deviceMountPath, seLinuxMountContext string) error {
	return asw.SetDeviceMountState(volumeName, operationexecutor.DeviceGloballyMounted, devicePath, deviceMountPath, seLinuxMountContext)
}
```

#### MarkDeviceAsUncertain

```go
// MarkDeviceAsUncertain 将设备标记为不确定状态。
// 该函数会调用 SetDeviceMountState 来设置设备的挂载状态为 DeviceMountUncertain，并更新相关字段。
func (asw *actualStateOfWorld) MarkDeviceAsUncertain(
	volumeName v1.UniqueVolumeName, devicePath, deviceMountPath, seLinuxMountContext string) error {
	return asw.SetDeviceMountState(volumeName, operationexecutor.DeviceMountUncertain, devicePath, deviceMountPath, seLinuxMountContext)
}
```

#### MarkVolumeMountAsUncertain

```go
// MarkVolumeMountAsUncertain 将卷的挂载状态标记为不确定状态。
// 该函数会调用 AddPodToVolume 将 pod 添加到卷的已挂载 pod 集合中，并将挂载状态设置为 VolumeMountUncertain。
func (asw *actualStateOfWorld) MarkVolumeMountAsUncertain(markVolumeOpts operationexecutor.MarkVolumeOpts) error {
	markVolumeOpts.VolumeMountState = operationexecutor.VolumeMountUncertain
	return asw.AddPodToVolume(markVolumeOpts)
}
```

#### MarkDeviceAsUnmounted

```go
// MarkDeviceAsUnmounted 将设备标记为已卸载状态。
// 该函数会调用 SetDeviceMountState 来设置设备的挂载状态为 DeviceNotMounted，并清空相关字段。
func (asw *actualStateOfWorld) MarkDeviceAsUnmounted(
	volumeName v1.UniqueVolumeName) error {
	return asw.SetDeviceMountState(volumeName, operationexecutor.DeviceNotMounted, "", "", "")
}
```

#### UpdateReconstructedDevicePath

```go
// UpdateReconstructedDevicePath 更新重建状态下卷的设备路径。
// 该函数会检查卷是否处于重建状态，如果不是，则不执行任何操作。
// 如果卷处于重建状态，则更新设备路径为给定的设备路径。
func (asw *actualStateOfWorld) UpdateReconstructedDevicePath(volumeName v1.UniqueVolumeName, devicePath string) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return
	}
	if volumeObj.deviceMountState != operationexecutor.DeviceMountUncertain {
		// 重建器必须已更新卷的状态，即当 pod 使用该卷并成功挂载该卷时，会更新设备路径。
		// 这样的更新会修复设备路径。
		return
	}

	// 更新卷的设备路径。
	volumeObj.devicePath = devicePath
	asw.attachedVolumes[volumeName] = volumeObj
}
```

#### UpdateReconstructedVolumeAttachability

````go
// UpdateReconstructedVolumeAttachability 更新重建状态下卷的可附加性。
// 该函数会检查卷是否处于重建状态，如果不是，则不执行任何操作。
// 如果卷处于重建状态，则根据传入的 attachable 参数来更新卷的可附加性。
func (asw *actualStateOfWorld) UpdateReconstructedVolumeAttachability(volumeName v1.UniqueVolumeName, attachable bool) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return
	}
	if volumeObj.pluginIsAttachable != volumeAttachabilityUncertain {
		// 重建器必须已更新卷的状态，即当 pod 使用该卷并成功挂载该卷时，会更新卷的可附加性。
		// 这样的更新会修复卷的可附加性。
		return
	}

	// 根据传入的 attachable 参数来更新卷的可附加性。
	if attachable {
		volumeObj.pluginIsAttachable = volumeAttachabilityTrue
	} else {
		volumeObj.pluginIsAttachable = volumeAttachabilityFalse
	}
	asw.attachedVolumes[volumeName] = volumeObj
}
````

#### GetDeviceMountState

```go
// GetDeviceMountState 获取卷的设备挂载状态。
func (asw *actualStateOfWorld) GetDeviceMountState(volumeName v1.UniqueVolumeName) operationexecutor.DeviceMountState {
	asw.RLock()
	defer asw.RUnlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return operationexecutor.DeviceNotMounted
	}

	// 返回卷对象的设备挂载状态。
	return volumeObj.deviceMountState
}
```

#### MarkForInUseExpansionError

```go
// MarkForInUseExpansionError 将卷标记为正在使用的扩展错误状态。
func (asw *actualStateOfWorld) MarkForInUseExpansionError(volumeName v1.UniqueVolumeName) {
	asw.Lock()
	defer asw.Unlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, ok := asw.attachedVolumes[volumeName]
	if ok {
		// 将卷对象的 volumeInUseErrorForExpansion 标记为 true，表示正在使用扩展错误状态。
		volumeObj.volumeInUseErrorForExpansion = true
		asw.attachedVolumes[volumeName] = volumeObj
	}
}
```

#### GetVolumeMountState

````go
// GetVolumeMountState 获取卷挂载状态。
func (asw *actualStateOfWorld) GetVolumeMountState(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) operationexecutor.VolumeMountState {
	asw.RLock()
	defer asw.RUnlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return operationexecutor.VolumeNotMounted
	}

	// 通过 podName 从卷对象的 mountedPods 中查找对应的挂载的 pod 对象。
	podObj, podExists := volumeObj.mountedPods[podName]
	if !podExists {
		return operationexecutor.VolumeNotMounted
	}

	// 返回 pod 对象的 volumeMountStateForPod 字段，即卷在该 pod 中的挂载状态。
	return podObj.volumeMountStateForPod
}
````

#### IsVolumeMountedElsewhere

```go
// IsVolumeMountedElsewhere 检查卷是否在其他 pod 中挂载。
func (asw *actualStateOfWorld) IsVolumeMountedElsewhere(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) bool {
	asw.RLock()
	defer asw.RUnlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return false
	}

	// 遍历卷对象的 mountedPods，查看卷是否在其他 pod 中挂载。
	for _, podObj := range volumeObj.mountedPods {
		if podName != podObj.podName {
			// 将不确定的挂载状态视为挂载状态，直到确定为止。
			if podObj.volumeMountStateForPod != operationexecutor.VolumeNotMounted {
				return true
			}
		}
	}
	return false
}
```

#### addVolume

```go
// addVolume 将卷添加到缓存中，表示该卷已附加到此节点。
// 如果未提供卷名，则从 volumeSpec 生成唯一的卷名，并在成功后返回。
// 如果具有相同生成的名称的卷已存在，则此操作无效。
// 如果没有卷插件可以支持给定的 volumeSpec，或者多个插件可以支持它，则返回错误。
func (asw *actualStateOfWorld) addVolume(
	volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, devicePath string, attachability volumeAttachability) error {
	asw.Lock()
	defer asw.Unlock()

	// 根据 volumeSpec 查找对应的 volumePlugin。
	volumePlugin, err := asw.volumePluginMgr.FindPluginBySpec(volumeSpec)
	if err != nil || volumePlugin == nil {
		return fmt.Errorf(
			"failed to get Plugin from volumeSpec for volume %q err=%v",
			volumeSpec.Name(),
			err)
	}

	// 如果未提供卷名，则从 volumePlugin 和 volumeSpec 生成唯一的卷名。
	if len(volumeName) == 0 {
		volumeName, err = util.GetUniqueVolumeNameFromSpec(volumePlugin, volumeSpec)
		if err != nil {
			return fmt.Errorf(
				"failed to GetUniqueVolumeNameFromSpec for volumeSpec %q using volume plugin %q err=%v",
				volumeSpec.Name(),
				volumePlugin.GetPluginName(),
				err)
		}
	}

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		// 如果卷对象不存在，表示该卷是新的，创建新的 attachedVolume 对象，并设置相关字段。
		volumeObj = attachedVolume{
			volumeName:         volumeName,
			spec:               volumeSpec,
			mountedPods:        make(map[volumetypes.UniquePodName]mountedPod),
			pluginName:         volumePlugin.GetPluginName(),
			pluginIsAttachable: attachability,
			deviceMountState:   operationexecutor.DeviceNotMounted,
			devicePath:         devicePath,
		}
	} else {
		// 如果卷对象已存在，表示该卷已经被添加过，可能是在重建过程中恢复了该卷。
		// 在这种情况下，更新设备路径等相关字段。
		volumeObj.devicePath = devicePath
		klog.V(2).InfoS("Volume is already added to attachedVolume list, update device path", "volumeName", volumeName, "path", devicePath)
	}
	asw.attachedVolumes[volumeName] = volumeObj

	return nil
}
```

#### AddPodToVolume

```go
// AddPodToVolume 将 pod 添加到卷的已挂载 pod 集合中。
func (asw *actualStateOfWorld) AddPodToVolume(markVolumeOpts operationexecutor.MarkVolumeOpts) error {
	podName := markVolumeOpts.PodName
	podUID := markVolumeOpts.PodUID
	volumeName := markVolumeOpts.VolumeName
	mounter := markVolumeOpts.Mounter
	blockVolumeMapper := markVolumeOpts.BlockVolumeMapper
	outerVolumeSpecName := markVolumeOpts.OuterVolumeSpecName
	volumeGidValue := markVolumeOpts.VolumeGidVolume
	volumeSpec := markVolumeOpts.VolumeSpec
	asw.Lock()
	defer asw.Unlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return fmt.Errorf(
			"no volume with the name %q exists in the list of attached volumes",
			volumeName)
	}

	// 通过 podName 从卷对象的 mountedPods 中查找对应的挂载的 pod 对象。
	podObj, podExists := volumeObj.mountedPods[podName]

	updateUncertainVolume := false
	if podExists {
		// 更新不确定的卷挂载状态 - 新的 markVolumeOpts 可能会更新信息。
		// 特别是在重建过程中重构的卷（在重建期间标记为不确定）需要更新。
		updateUncertainVolume = utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) && podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain
	}
	if !podExists || updateUncertainVolume {
		// 如果 pod 不存在或者需要更新不确定的卷挂载状态，表示是新的挂载，需要创建新的 mountedPod 对象，并设置相关字段。
		podObj = mountedPod{
			podName:                podName,
			podUID:                 podUID,
			mounter:                mounter,
			blockVolumeMapper:      blockVolumeMapper,
			outerVolumeSpecName:    outerVolumeSpecName,
			volumeGidValue:         volumeGidValue,
			volumeSpec:             volumeSpec,
			volumeMountStateForPod: markVolumeOpts.VolumeMountState,
			seLinuxMountContext:    markVolumeOpts.SELinuxMountContext,
		}
	}

	// 如果 pod 存在，则重置 remountRequired 字段和 volumeMountStateForPod 字段。
	podObj.remountRequired = false
	podObj.volumeMountStateForPod = markVolumeOpts.VolumeMountState

	// 如果卷成功挂载，则将其从 foundDuringReconstruction 中移除。
	if markVolumeOpts.VolumeMountState == operationexecutor.VolumeMounted {
		delete(asw.foundDuringReconstruction[volumeName], podName)
	}
	if mounter != nil {
		// 使用新的 mounter 更新 podObj 中的 mounter 字段，可能 mounter 信息有更新。
		podObj.mounter = mounter
	}
	asw.attachedVolumes[volumeName].mountedPods[podName] = podObj
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		// 将 mount context 也存储在 AttachedVolume 中，以便在 PodExistsInVolume 中进行全局卷 context 的快速比较。
		if volumeObj.seLinuxMountContext == nil {
			volumeObj.seLinuxMountContext = &markVolumeOpts.SELinuxMountContext
			asw.attachedVolumes[volumeName] = volumeObj
		}
	}

	return nil
}
```

#### MarkVolumeAsResized

````go
// MarkVolumeAsResized 将卷标记为已调整大小，设置 persistentVolumeSize 字段为 claimSize。
func (asw *actualStateOfWorld) MarkVolumeAsResized(volumeName v1.UniqueVolumeName, claimSize *resource.Quantity) bool {
	asw.Lock()
	defer asw.Unlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, ok := asw.attachedVolumes[volumeName]
	if ok {
		// 设置卷对象的 persistentVolumeSize 字段为 claimSize。
		volumeObj.persistentVolumeSize = claimSize
		asw.attachedVolumes[volumeName] = volumeObj
		return true
	}
	return false
}
````

#### MarkRemountRequired

```go
// MarkRemountRequired 标记 pod 需要重新挂载卷。
func (asw *actualStateOfWorld) MarkRemountRequired(podName volumetypes.UniquePodName) {
	asw.Lock()
	defer asw.Unlock()

	// 遍历所有卷，查找与指定 podName 相关的卷，检查是否需要重新挂载。
	for volumeName, volumeObj := range asw.attachedVolumes {
		if podObj, podExists := volumeObj.mountedPods[podName]; podExists {
			// 根据 podObj 的 volumeSpec 查找对应的 volumePlugin。
			volumePlugin, err :=
				asw.volumePluginMgr.FindPluginBySpec(podObj.volumeSpec)
			if err != nil || volumePlugin == nil {
				// 日志记录并继续处理其他卷。
				klog.ErrorS(nil, "MarkRemountRequired failed to FindPluginBySpec for volume", "uniquePodName", podObj.podName, "podUID", podObj.podUID, "volumeName", volumeName, "volumeSpecName", podObj.volumeSpec.Name())
				continue
			}

			// 检查 volumePlugin 是否需要重新挂载卷。
			if volumePlugin.RequiresRemount(podObj.volumeSpec) {
				// 标记 pod 需要重新挂载。
				podObj.remountRequired = true
				asw.attachedVolumes[volumeName].mountedPods[podName] = podObj
			}
		}
	}
}
```

#### SetDeviceMountState

```go
// SetDeviceMountState 设置卷的设备挂载状态、设备路径和设备挂载路径等字段。
func (asw *actualStateOfWorld) SetDeviceMountState(
	volumeName v1.UniqueVolumeName, deviceMountState operationexecutor.DeviceMountState, devicePath, deviceMountPath, seLinuxMountContext string) error {
	asw.Lock()
	defer asw.Unlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return fmt.Errorf(
			"no volume with the name %q exists in the list of attached volumes",
			volumeName)
	}

	// 设置卷对象的设备挂载状态和设备路径等字段。
	volumeObj.deviceMountState = deviceMountState
	volumeObj.deviceMountPath = deviceMountPath
	if devicePath != "" {
		volumeObj.devicePath = devicePath
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if seLinuxMountContext != "" {
			volumeObj.seLinuxMountContext = &seLinuxMountContext
		}
	}
	asw.attachedVolumes[volumeName] = volumeObj
	return nil
}
```

#### InitializeClaimSize

```go
// InitializeClaimSize 初始化卷的声明大小。
func (asw *actualStateOfWorld) InitializeClaimSize(logger klog.Logger, volumeName v1.UniqueVolumeName, claimSize *resource.Quantity) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, ok := asw.attachedVolumes[volumeName]
	// 只有当 persistentVolumeSize 为零时才设置 volume claim size。
	// 这可能发生在 kubelet 启动后重建卷的情况。
	if ok && volumeObj.persistentVolumeSize == nil {
		volumeObj.persistentVolumeSize = claimSize
		asw.attachedVolumes[volumeName] = volumeObj
	}
}
```

#### GetClaimSize

```go
// GetClaimSize 获取卷的声明大小。
func (asw *actualStateOfWorld) GetClaimSize(volumeName v1.UniqueVolumeName) *resource.Quantity {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, ok := asw.attachedVolumes[volumeName]
	if ok {
		return volumeObj.persistentVolumeSize
	}
	return nil
}
```

#### DeletePodFromVolume

````go
// DeletePodFromVolume 从卷中删除 pod 对象。
func (asw *actualStateOfWorld) DeletePodFromVolume(
	podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error {
	asw.Lock()
	defer asw.Unlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return fmt.Errorf(
			"no volume with the name %q exists in the list of attached volumes",
			volumeName)
	}

	// 从卷对象的 mountedPods 中删除指定 podName 对应的 pod 对象。
	_, podExists := volumeObj.mountedPods[podName]
	if podExists {
		delete(asw.attachedVolumes[volumeName].mountedPods, podName)
	}

	// 如果在重建过程中找到了被删除的卷，从 foundDuringReconstruction 中移除。
	_, podExists = asw.foundDuringReconstruction[volumeName]
	if podExists {
		delete(asw.foundDuringReconstruction[volumeName], podName)
	}

	return nil
}
````

#### DeleteVolume

```go
// DeleteVolume 从 attachedVolumes 中删除指定的卷对象。
func (asw *actualStateOfWorld) DeleteVolume(volumeName v1.UniqueVolumeName) error {
	asw.Lock()
	defer asw.Unlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return nil
	}

	// 如果卷对象的 mountedPods 非空，则返回错误，表示卷仍然有 pod 在使用中。
	if len(volumeObj.mountedPods) != 0 {
		return fmt.Errorf(
			"failed to DeleteVolume %q, it still has %v mountedPods",
			volumeName,
			len(volumeObj.mountedPods))
	}

	// 从 attachedVolumes 中删除卷对象，并从 foundDuringReconstruction 中删除对应的重建卷信息。
	delete(asw.attachedVolumes, volumeName)
	delete(asw.foundDuringReconstruction, volumeName)
	return nil
}
```

#### PodExistsInVolume

````go
// PodExistsInVolume 检查卷中是否存在指定的 pod，并返回其状态及设备路径。
func (asw *actualStateOfWorld) PodExistsInVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName, desiredVolumeSize resource.Quantity, seLinuxLabel string) (bool, string, error) {
	asw.RLock()
	defer asw.RUnlock()

	// 通过卷名从 attachedVolumes 中查找对应的卷对象。
	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return false, "", newVolumeNotAttachedError(volumeName)
	}

	// 卷存在，检查其 SELinux context 挂载选项。
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if volumeObj.seLinuxMountContext != nil && *volumeObj.seLinuxMountContext != seLinuxLabel {
			// 如果卷的 SELinux context 不匹配，返回错误。
			fullErr := newSELinuxMountMismatchError(volumeName)
			return false, volumeObj.devicePath, fullErr
		}
	}

	// 通过 podName 从卷对象的 mountedPods 中查找对应的挂载的 pod 对象。
	podObj, podExists := volumeObj.mountedPods[podName]
	if podExists {
		// 如果 volumeMountStateForPod 是 VolumeMountUncertain，则继续尝试挂载该卷，返回 false。
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain {
			return false, volumeObj.devicePath, nil
		}
		// 如果 volumeMountStateForPod 是 VolumeMounted，则表示 pod 成功挂载了该卷，返回 true。
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMounted {
			return true, volumeObj.devicePath, nil
		}
		// 如果 remountRequired 为 true，则返回需要重新挂载的错误信息。
		if podObj.remountRequired {
			return true, volumeObj.devicePath, newRemountRequiredError(volumeObj.volumeName, podObj.podName)
		}
		// 检查是否需要扩展卷。
		if currentSize, expandVolume := asw.volumeNeedsExpansion(volumeObj, desiredVolumeSize); expandVolume {
			return true, volumeObj.devicePath, newFsResizeRequiredError(volumeObj.volumeName, podObj.podName, currentSize)
		}
	}

	// 返回卷中是否存在指定的 pod 以及设备路径等信息。
	return podExists, volumeObj.devicePath, nil
}
````

#### volumeNeedsExpansion

````go
// volumeNeedsExpansion 检查卷是否需要扩展，返回当前卷大小和是否需要扩展的结果。
func (asw *actualStateOfWorld) volumeNeedsExpansion(volumeObj attachedVolume, desiredVolumeSize resource.Quantity) (resource.Quantity, bool) {
	currentSize := resource.Quantity{}
	if volumeObj.persistentVolumeSize != nil {
		currentSize = volumeObj.persistentVolumeSize.DeepCopy()
	}
	if volumeObj.volumeInUseErrorForExpansion {
		return currentSize, false
	}
	if volumeObj.persistentVolumeSize == nil || desiredVolumeSize.IsZero() {
		return currentSize, false
	}

	if desiredVolumeSize.Cmp(*volumeObj.persistentVolumeSize) > 0 {
		// 根据 volumeSpec 查找可扩展的 volumePlugin。
		volumePlugin, err := asw.volumePluginMgr.FindNodeExpandablePluginBySpec(volumeObj.spec)
		if err != nil || volumePlugin == nil {
			// 日志记录并继续处理其他卷。
			klog.InfoS("PodExistsInVolume failed to find expandable plugin",
				"volume", volumeObj.volumeName,
				"volumeSpecName", volumeObj.spec.Name())
			return currentSize, false
		}
		// 如果 volumePlugin 需要进行文件系统大小调整，则返回需要扩展的结果。
		if volumePlugin.RequiresFSResize() {
			return currentSize, true
		}
	}
	return currentSize, false
}
````

#### GetMountedVolumes

```go
// GetMountedVolumes 返回所有已挂载的卷列表。
func (asw *actualStateOfWorld) GetMountedVolumes() []string {
	asw.RLock()
	defer asw.RUnlock()

	// 遍历所有卷对象，查找状态为 VolumeMounted 的卷，将卷名添加到已挂载卷列表中并返回。
	mountedVolumes := []string{}
	for _, volumeObj := range asw.attachedVolumes {
		if volumeObj.deviceMountState == operationexecutor.DeviceMounted {
			mountedVolumes = append(mountedVolumes, volumeObj.volumeName.String())
		}
	}
	return mountedVolumes
}
```

#### GetAllAttachedVolumes

```go
// GetAllAttachedVolumes 返回所有已附加的卷列表。
func (asw *actualStateOfWorld) GetAllAttachedVolumes() []string {
	asw.RLock()
	defer asw.RUnlock()

	// 遍历所有卷对象，将卷名添加到所有附加卷列表中并返回。
	attachedVolumes := []string{}
	for _, volumeObj := range asw.attachedVolumes {
		attachedVolumes = append(attachedVolumes, volumeObj.volumeName.String())
	}
	return attachedVolumes
}
```

#### GetAllVolumesAndMountPaths

````go
// GetAllVolumesAndMountPaths 返回所有已附加的卷及其对应的挂载路径的映射。
func (asw *actualStateOfWorld) GetAllVolumesAndMountPaths() map[string]string {
	asw.RLock()
	defer asw.RUnlock()

	// 创建已附加卷及其挂载路径的映射。
	volumeMountPaths := make(map[string]string)
	for _, volumeObj := range asw.attachedVolumes {
		if volumeObj.deviceMountState == operationexecutor.DeviceMounted {
			// 如果卷处于挂载状态，添加卷名及其挂载路径到映射中。
			volumeMountPaths[volumeObj.volumeName.String()] = volumeObj.deviceMountPath
		}
	}
	return volumeMountPaths
}
````



## DesiredStateOfWorldPopulator

```go
// DesiredStateOfWorldPopulator负责定期循环遍历活动Pod列表，
// 并确保每个挂载了卷的Pod存在于期望状态的世界缓存中。
// 同时，它还会验证期望状态世界缓存中的Pod是否仍然存在，
// 如果不存在则将其删除。
type DesiredStateOfWorldPopulator interface {
	Run(sourcesReady config.SourcesReady, stopCh <-chan struct{})

	// ReprocessPod将指定Pod在processedPods中的值设置为false，
	// 强制重新处理该Pod。这是为了在Pod更新时启用重新挂载卷
	// （例如Downward API卷依赖于此行为以确保卷内容更新）。
	ReprocessPod(podName volumetypes.UniquePodName)

	// HasAddedPods返回当sourcesReady完成后，
	// Populator是否已经遍历过活动Pod列表，
	// 并至少将其添加到期望状态的世界缓存中一次。
	// 在sourcesReady之前，它不会返回true，
	// 因为在此之前，活动Pod列表可能会缺少许多或全部Pod，
	// 因此可能几乎没有Pod被添加。
	HasAddedPods() bool
}
```

### PodStateProvider

```go
// PodStateProvider can determine if a pod is going to be terminated.
type PodStateProvider interface {
	ShouldPodContainersBeTerminating(types.UID) bool
	ShouldPodRuntimeBeRemoved(types.UID) bool
}
```

### desiredStateOfWorldPopulator

```go
type desiredStateOfWorldPopulator struct {
	kubeClient               clientset.Interface
	loopSleepDuration        time.Duration
	podManager               PodManager
	podStateProvider         PodStateProvider
	desiredStateOfWorld      cache.DesiredStateOfWorld
	actualStateOfWorld       cache.ActualStateOfWorld
	pods                     processedPods
	kubeContainerRuntime     kubecontainer.Runtime
	keepTerminatedPodVolumes bool
	hasAddedPods             bool
	hasAddedPodsLock         sync.RWMutex
	csiMigratedPluginManager csimigration.PluginManager
	intreeToCSITranslator    csimigration.InTreeToCSITranslator
	volumePluginMgr          *volume.VolumePluginMgr
}
```

#### processedPods

```go
type processedPods struct {
	processedPods map[volumetypes.UniquePodName]bool
	sync.RWMutex
}
```

#### Run

```go
func (dswp *desiredStateOfWorldPopulator) Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) {
	// 等待所有源都准备就绪后开始的循环完成，然后相应地设置 hasAddedPods 的值
	klog.InfoS("Desired state populator starts to run")
	wait.PollUntil(dswp.loopSleepDuration, func() (bool, error) {
		done := sourcesReady.AllReady()
		dswp.populatorLoop()
		return done, nil
	}, stopCh)
	dswp.hasAddedPodsLock.Lock()
	if !dswp.hasAddedPods {
		klog.InfoS("Finished populating initial desired state of world")
		dswp.hasAddedPods = true
	}
	dswp.hasAddedPodsLock.Unlock()
	wait.Until(dswp.populatorLoop, dswp.loopSleepDuration, stopCh)
}

func (dswp *desiredStateOfWorldPopulator) populatorLoop() {
	dswp.findAndAddNewPods()
	dswp.findAndRemoveDeletedPods()
}
```

##### findAndAddNewPods

```go
// 遍历所有的 Pod，如果它们不存在但应该存在，则添加到期望状态中
func (dswp *desiredStateOfWorldPopulator) findAndAddNewPods() {
	// 将唯一的 Pod 名称映射到外部卷名称以及 MountedVolume
	mountedVolumesForPod := make(map[volumetypes.UniquePodName]map[string]cache.MountedVolume)
	for _, mountedVolume := range dswp.actualStateOfWorld.GetMountedVolumes() {
		mountedVolumes, exist := mountedVolumesForPod[mountedVolume.PodName]
		if !exist {
			mountedVolumes = make(map[string]cache.MountedVolume)
			mountedVolumesForPod[mountedVolume.PodName] = mountedVolumes
		}
		mountedVolumes[mountedVolume.OuterVolumeSpecName] = mountedVolume
	}

	for _, pod := range dswp.podManager.GetPods() {
		// 保证在重建期间添加 Pod 的一致性
		if dswp.hasAddedPods && dswp.podStateProvider.ShouldPodContainersBeTerminating(pod.UID) {
			// 对于不能成为启动容器的 Pod，不添加其卷
			continue
		}

		if !dswp.hasAddedPods && dswp.podStateProvider.ShouldPodRuntimeBeRemoved(pod.UID) {
			// 当 kubelet 重启时，如果可能仍然有容器在运行，则需要将 Pod 添加到期望状态中
			continue
		}

		dswp.processPodVolumes(pod, mountedVolumesForPod)
	}
}
```

###### processPodVolumes

```go
// processPodVolumes 处理给定 Pod 中的卷并将其添加到期望状态中
func (dswp *desiredStateOfWorldPopulator) processPodVolumes(
	pod *v1.Pod,
	mountedVolumesForPod map[volumetypes.UniquePodName]map[string]cache.MountedVolume) {
	if pod == nil {
		return
	}

	uniquePodName := util.GetUniquePodName(pod)
	if dswp.podPreviouslyProcessed(uniquePodName) {
		return
	}

	allVolumesAdded := true
	mounts, devices, seLinuxContainerContexts := util.GetPodVolumeNames(pod)

	// 处理 Pod 中每个定义的卷的 volume spec
	for _, podVolume := range pod.Spec.Volumes {
		if !mounts.Has(podVolume.Name) && !devices.Has(podVolume.Name) {
			// 卷在 Pod 中没有使用，忽略它
			klog.V(4).InfoS("Skipping unused volume", "pod", klog.KObj(pod), "volumeName", podVolume.Name)
			continue
		}

		pvc, volumeSpec, volumeGidValue, err :=
			dswp.createVolumeSpec(podVolume, pod, mounts, devices)
		if err != nil {
			klog.ErrorS(err, "Error processing volume", "pod", klog.KObj(pod), "volumeName", podVolume.Name)
			dswp.desiredStateOfWorld.AddErrorToPod(uniquePodName, err.Error())
			allVolumesAdded = false
			continue
		}

		// 将卷添加到期望状态中
		uniqueVolumeName, err := dswp.desiredStateOfWorld.AddPodToVolume(
			uniquePodName, pod, volumeSpec, podVolume.Name, volumeGidValue, seLinuxContainerContexts[podVolume.Name])
		if err != nil {
			klog.ErrorS(err, "Failed to add volume to desiredStateOfWorld", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "volumeSpecName", volumeSpec.Name())
			dswp.desiredStateOfWorld.AddErrorToPod(uniquePodName, err.Error())
			allVolumesAdded = false
		} else {
			klog.V(4).InfoS("Added volume to desired state", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "volumeSpecName", volumeSpec.Name())
		}
		if !utilfeature.DefaultFeatureGate.Enabled(features.NewVolumeManagerReconstruction) {
			// 同步重建后的卷。仅在仍然使用旧式重建时才需要此操作。
			// 在使用 reconstruct_new.go 后，AWS.MarkVolumeAsMounted 将更新之前不确定的卷的外部规范名称。
			dswp.actualStateOfWorld.SyncReconstructedVolume(uniqueVolumeName, uniquePodName, podVolume.Name)
		}

		dswp.checkVolumeFSResize(pod, podVolume, pvc, volumeSpec, uniquePodName, mountedVolumesForPod)
	}

	// 一些卷的添加可能失败，不应标记此 Pod 为完全处理完成
	if allVolumesAdded {
		dswp.markPodProcessed(uniquePodName)
		// 同步新的 Pod。重新挂载所有需要的卷（例如 DownwardAPI）
		dswp.actualStateOfWorld.MarkRemountRequired(uniquePodName)
		// 删除此处理过程中的所有存储的错误，因为在 processPodVolumes 中一切都处理得很好
		dswp.desiredStateOfWorld.PopPodErrors(uniquePodName)
	} else if dswp.podHasBeenSeenOnce(uniquePodName) {
		// 对于至少被处理过一次的 Pod，即使此轮中有一些卷无法成功重新处理，我们仍然将其标记为已处理，以避免在非常高的频率下重新处理它。
		// 当 Volume Manager 调用 ReprocessPod() 时，它将重新处理此 Pod，该函数是由 SyncPod 触发的。
		dswp.markPodProcessed(uniquePodName)
	}

}
```

###### createVolumeSpec

```go
// createVolumeSpec 创建并返回给定卷的可变 volume.Spec 对象。
// 如果需要，它会解析任何 PVC 并获取 PV 对象。
// 如果无法在此时获取卷对象，则返回错误。
func (dswp *desiredStateOfWorldPopulator) createVolumeSpec(
	podVolume v1.Volume, pod *v1.Pod, mounts, devices sets.String) (*v1.PersistentVolumeClaim, *volume.Spec, string, error) {
	pvcSource := podVolume.VolumeSource.PersistentVolumeClaim
	isEphemeral := pvcSource == nil && podVolume.VolumeSource.Ephemeral != nil
	if isEphemeral {
		// 通用的临时内联卷与 PVC 引用处理方式相同。
		// 唯一的额外约束是该 PVC 必须由该 Pod 拥有。
		pvcSource = &v1.PersistentVolumeClaimVolumeSource{
			ClaimName: podVolume.VolumeSource.Ephemeral.ClaimName,
		}
	}
	if pvcSource == nil {
		return nil, nil, "", nil
	}

	// 获取 PodVolume 的 PVC 对象
	pvcName := pvcSource.ClaimName
	pvcNamespace := pod.Namespace
	pvc, err := dswp.pvcLister.PersistentVolumeClaims(pvcNamespace).Get(pvcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// PVC 不存在
			return nil, nil, "", fmt.Errorf("persistent volume claim %q not found in namespace %q", pvcName, pvcNamespace)
		}
		return nil, nil, "", fmt.Errorf("failed to get persistent volume claim %q in namespace %q: %w", pvcName, pvcNamespace, err)
	}

	// 获取卷的 PVC 规格大小
	pvcCap := pvc.Spec.Resources.Requests[v1.ResourceStorage]
	if pvcCap.IsZero() {
		return nil, nil, "", fmt.Errorf("persistent volume claim %q in namespace %q has no storage capacity specified", pvcName, pvcNamespace)
	}

	// 获取卷的 PV 对象
	pv, err := dswp.pvLister.Get(pvc.Spec.VolumeName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get persistent volume %q for persistent volume claim %q in namespace %q: %w", pvc.Spec.VolumeName, pvcName, pvcNamespace, err)
	}

	// 创建卷规格对象
	volumeSpec, err := dswp.createVolumeSpecForPVC(pv, pvc)
	if err != nil {
		return nil, nil, "", err
	}

	// 获取卷规格的 gid
	volumeGidValue, err := dswp.volumeGidManager.GetGidValue(volumeSpec.PersistentVolume, pod)
	if err != nil {
		return nil, nil, "", err
	}

	return pvc, volumeSpec, volumeGidValue, nil
}
```





##### findAndRemoveDeletedPods

```go
// 遍历期望状态中的所有 Pod，如果它们不再存在，则将其删除
func (dswp *desiredStateOfWorldPopulator) findAndRemoveDeletedPods() {
	podsFromCache := make(map[volumetypes.UniquePodName]struct{})
	for _, volumeToMount := range dswp.desiredStateOfWorld.GetVolumesToMount() {
		podsFromCache[volumetypes.UniquePodName(volumeToMount.Pod.UID)] = struct{}{}
		pod, podExists := dswp.podManager.GetPodByUID(volumeToMount.Pod.UID)
		if podExists {

			// 检查该卷的可附加性是否发生了变化
			if volumeToMount.PluginIsAttachable {
				attachableVolumePlugin, err := dswp.volumePluginMgr.FindAttachablePluginBySpec(volumeToMount.VolumeSpec)
				// 仅当插件真的是不可附加的时候，才表示插件已经发生了变化
				if err == nil && attachableVolumePlugin == nil {
					// 目前一个 CSI 插件不可能既是可附加的又不支持设备挂载
					// 因此，在插件附加性发生变化后，唯一的卷名称应该保持不变
					dswp.desiredStateOfWorld.MarkVolumeAttachability(volumeToMount.VolumeName, false)
					klog.InfoS("Volume changes from attachable to non-attachable", "volumeName", volumeToMount.VolumeName)
					continue
				}
			}

			// 排除我们希望继续运行的已知 Pod
			if !dswp.podStateProvider.ShouldPodRuntimeBeRemoved(pod.UID) {
				continue
			}
			if dswp.keepTerminatedPodVolumes {
				continue
			}
		}

		// 一旦 Pod 从 kubelet 的 Pod 管理器中删除，不立即从 volume manager 中删除
		// 相反，检查 kubelet 的 pod state provider 来验证该 Pod 的所有容器是否都已终止
		if !dswp.podStateProvider.ShouldPodRuntimeBeRemoved(volumeToMount.Pod.UID) {
			klog.V(4).InfoS("Pod still has one or more containers in the non-exited state and will not be removed from desired state", "pod", klog.KObj(volumeToMount.Pod))
			continue
		}
		var volumeToMountSpecName string
		if volumeToMount.VolumeSpec != nil {
			volumeToMountSpecName = volumeToMount.VolumeSpec.Name()
		}
		removed := dswp.actualStateOfWorld.PodRemovedFromVolume(volumeToMount.PodName, volumeToMount.VolumeName)
		if removed && podExists {
			klog.V(4).InfoS("Actual state does not yet have volume mount information and pod still exists in pod manager, skip removing volume from desired state", "pod", klog.KObj(volumeToMount.Pod), "podUID", volumeToMount.Pod.UID, "volumeName", volumeToMountSpecName)
			continue
		}
		klog.V(4).InfoS("Removing volume from desired state", "pod", klog.KObj(volumeToMount.Pod), "podUID", volumeToMount.Pod.UID, "volumeName", volumeToMountSpecName)
		dswp.desiredStateOfWorld.DeletePodFromVolume(
			volumeToMount.PodName, volumeToMount.VolumeName)
		dswp.deleteProcessedPod(volumeToMount.PodName)
	}

	// 清理 processedPods 中的孤立条目
	dswp.pods.Lock()
	orphanedPods := make([]volumetypes.UniquePodName, 0, len(dswp.pods.processedPods))
	for k := range dswp.pods.processedPods {
		if _, ok := podsFromCache[k]; !ok {
			orphanedPods = append(orphanedPods, k)
		}
	}
	dswp.pods.Unlock()
	for _, orphanedPod := range orphanedPods {
		uid := types.UID(orphanedPod)
		_, podExists := dswp.podManager.GetPodByUID(uid)
		if !podExists && dswp.podStateProvider.ShouldPodRuntimeBeRemoved(uid) {
			dswp.deleteProcessedPod(orphanedPod)
		}
	}

	podsWithError := dswp.desiredStateOfWorld.GetPodsWithErrors()
	for _, podName := range podsWithError {
		if _, podExists := dswp.podManager.GetPodByUID(types.UID(podName)); !podExists {
			dswp.desiredStateOfWorld.PopPodErrors(podName)
		}
	}
}
```

#### ReprocessPod

````go
func (dswp *desiredStateOfWorldPopulator) ReprocessPod(
	podName volumetypes.UniquePodName) {
	dswp.markPodProcessingFailed(podName)
}
````

### HasAddedPods

```go
func (dswp *desiredStateOfWorldPopulator) HasAddedPods() bool {
	dswp.hasAddedPodsLock.RLock()
	defer dswp.hasAddedPodsLock.RUnlock()
	return dswp.hasAddedPods
}
```

## Reconciler

```go
// Reconciler 在周期性循环中运行，通过触发 attach、detach、mount 和 unmount 操作，
// 将世界的期望状态与实际状态进行调和。
// 注意：这与 attach/detach 控制器实现的 Reconciler 是不同的。
// 这里的调谐器负责调和 kubelet 卷管理器（Volume Manager）的状态，而 attach/detach 控制器则负责调和
// attach/detach 控制器的状态。
type Reconciler interface {
	// Starts running the reconciliation loop which executes periodically, checks
	// if volumes that should be mounted are mounted and volumes that should
	// be unmounted are unmounted. If not, it will trigger mount/unmount
	// operations to rectify.
	// If attach/detach management is enabled, the manager will also check if
	// volumes that should be attached are attached and volumes that should
	// be detached are detached and trigger attach/detach operations as needed.
	// 运行调和循环，它定期执行，检查是否已挂载应该挂载的卷以及是否已卸载应该卸载的卷。
	// 如果没有，它将触发挂载/卸载操作来纠正。
	// 如果启用了 attach/detach 管理，调谐器还会检查应该附加的卷是否已附加，
	// 应该分离的卷是否已分离，并根据需要触发 attach/detach 操作。
	Run(stopCh <-chan struct{})

	// StatesHasBeenSynced returns true only after syncStates process starts to sync
	// states at least once after kubelet starts
	// StatesHasBeenSynced 返回 true，仅在 syncStates 进程在 kubelet 启动后至少同步一次状态后。
    StatesHasBeenSynced() bool
}
```

### reconciler

````go
// reconciler 是 Reconciler 接口的实现。
type reconciler struct {
	kubeClient                    clientset.Interface
	controllerAttachDetachEnabled bool
	loopSleepDuration             time.Duration
	waitForAttachTimeout          time.Duration
	nodeName                      types.NodeName
	desiredStateOfWorld           cache.DesiredStateOfWorld
	actualStateOfWorld            cache.ActualStateOfWorld
	populatorHasAddedPods         func() bool
	operationExecutor             operationexecutor.OperationExecutor
	mounter                       mount.Interface
	hostutil                      hostutil.HostUtils
	volumePluginMgr               *volumepkg.VolumePluginMgr
	skippedDuringReconstruction   map[v1.UniqueVolumeName]*globalVolumeInfo
	kubeletPodsDir                string
	// lock protects timeOfLastSync for updating and checking
	timeOfLastSyncLock              sync.Mutex
	timeOfLastSync                  time.Time
	volumesFailedReconstruction     []podVolume
	volumesNeedUpdateFromNodeStatus []v1.UniqueVolumeName
	volumesNeedReportedInUse        []v1.UniqueVolumeName
}
````

#### NewReconciler

````go
// NewReconciler 返回 Reconciler 的新实例。
//
// controllerAttachDetachEnabled - 如果为 true，则表示 attach/detach 控制器负责
// 管理此节点的 attach/detach 操作，因此卷管理器不会管理它们。
//
// loopSleepDuration - 调谐器循环在连续执行之间休眠的时间间隔。
//
// waitForAttachTimeout - Mount 函数等待卷被附加的时间间隔。
//
// nodeName - 该节点的名称，用于 Attach 和 Detach 方法。
//
// desiredStateOfWorld - 包含世界期望状态的缓存。
//
// actualStateOfWorld - 包含实际状态的缓存。
//
// populatorHasAddedPods - 用于检查填充器是否在 sources 准备好后至少完成一次向 desiredStateOfWorld 缓存添加 pods
//（在 sources 准备好之前，可能会缺少 pods）。
//
// operationExecutor - 用于安全地触发 attach/detach/mount/unmount 操作的工具（防止对同一卷触发多个操作）。
//
// mounter - 从 kubelet 传递下来的 mounter，在卸载路径中继续使用。
//
// hostutil - 从 kubelet 传递下来的 hostutil。
//
// volumePluginMgr - 从 kubelet 传递的卷插件管理器。
func NewReconciler(
	kubeClient clientset.Interface,
	controllerAttachDetachEnabled bool,
	loopSleepDuration time.Duration,
	waitForAttachTimeout time.Duration,
	nodeName types.NodeName,
	desiredStateOfWorld cache.DesiredStateOfWorld,
	actualStateOfWorld cache.ActualStateOfWorld,
	populatorHasAddedPods func() bool,
	operationExecutor operationexecutor.OperationExecutor,
	mounter mount.Interface,
	hostutil hostutil.HostUtils,
	volumePluginMgr *volumepkg.VolumePluginMgr,
	kubeletPodsDir string) Reconciler {
	return &reconciler{
		kubeClient:                      kubeClient,
		controllerAttachDetachEnabled:   controllerAttachDetachEnabled,
		loopSleepDuration:               loopSleepDuration,
		waitForAttachTimeout:            waitForAttachTimeout,
		nodeName:                        nodeName,
		desiredStateOfWorld:             desiredStateOfWorld,
		actualStateOfWorld:              actualStateOfWorld,
		populatorHasAddedPods:           populatorHasAddedPods,
		operationExecutor:               operationExecutor,
		mounter:                         mounter,
		hostutil:                        hostutil,
		skippedDuringReconstruction:     map[v1.UniqueVolumeName]*globalVolumeInfo{},
		volumePluginMgr:                 volumePluginMgr,
		kubeletPodsDir:                  kubeletPodsDir,
		timeOfLastSync:                  time.Time{},
		volumesFailedReconstruction:     make([]podVolume, 0),
		volumesNeedUpdateFromNodeStatus: make([]v1.UniqueVolumeName, 0),
		volumesNeedReportedInUse:        make([]v1.UniqueVolumeName, 0),
	}
}
````

#### Run

````go
func (rc *reconciler) Run(stopCh <-chan struct{}) {
	// 如果启用了 NewVolumeManagerReconstruction 特性，则调用 runNew 方法
	// 否则调用 runOld 方法
	if utilfeature.DefaultFeatureGate.Enabled(features.NewVolumeManagerReconstruction) {
		rc.runNew(stopCh)
		return
	}

	rc.runOld(stopCh)
}
````

#### runNew

````go
// TODO: 将此代码移动到 reconciler.go，并在 NewVolumeManagerReconstruction 成为 GA 时删除其中的旧代码

// TODO: 当 NewVolumeManagerReconstruction 成为 GA 时替换 Run() 方法
func (rc *reconciler) runNew(stopCh <-chan struct{}) {
	// 调用 reconstructVolumes 方法，尝试通过扫描所有 pod 的卷目录来重建实际状态
	rc.reconstructVolumes()
	// 输出日志，表示开始同步状态
	klog.InfoS("Reconciler: start to sync state")
	// 使用 wait.Until 方法来周期性地调用 reconcileNew 方法，间隔为 rc.loopSleepDuration，直到 stopCh 接收到信号
	wait.Until(rc.reconcileNew, rc.loopSleepDuration, stopCh)
}
````

##### reconstructVolumes

```go
// 使用重建方法 reconstructVolumes 尝试重建实际状态，通过扫描所有 pod 的卷目录来完成此操作。
// 对于不支持或重建失败的卷，它会将这些卷放入 volumesFailedReconstruction 中，
// 在 DesiredStateOfWorld 填充后稍后进行清理。
func (rc *reconciler) reconstructVolumes() {
	// 从磁盘中读取 pod 的目录以获取卷的信息
	podVolumes, err := getVolumesFromPodDir(rc.kubeletPodsDir)
	if err != nil {
		// 输出错误日志，表示无法从磁盘中获取卷信息，跳过同步状态以进行卷重建
		klog.ErrorS(err, "Cannot get volumes from disk, skip sync states for volume reconstruction")
		return
	}
	// 创建用于存储重建卷信息的映射
	reconstructedVolumes := make(map[v1.UniqueVolumeName]*globalVolumeInfo)
	reconstructedVolumeNames := []v1.UniqueVolumeName{}
	// 遍历每个卷，并尝试重建它们的状态
	for _, volume := range podVolumes {
		// 如果实际状态中已经存在具有相同名称和规格的卷，则跳过此卷的重建
		if rc.actualStateOfWorld.VolumeExistsWithSpecName(volume.podName, volume.volumeSpecName) {
			// 输出日志，表示实际状态中已存在此卷，跳过清理挂载点
			klog.V(4).InfoS("Volume exists in actual state, skip cleaning up mounts", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
			continue
		}
		// 尝试重建卷的状态
		reconstructedVolume, err := rc.reconstructVolume(volume)
		if err != nil {
			// 输出日志，表示无法重建卷的信息，将此卷添加到 volumesFailedReconstruction 中，
			// 在 DesiredStateOfWorld 填充后将会进行处理
			klog.InfoS("Could not construct volume information", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName, "err", err)
			rc.volumesFailedReconstruction = append(rc.volumesFailedReconstruction, volume)
			continue
		}
		// 输出日志，表示正在将重建的卷添加到实际状态和节点状态中
		klog.V(4).InfoS("Adding reconstructed volume to actual state and node status", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
		// 将重建的卷信息保存到全局映射中
		gvl := &globalVolumeInfo{
			volumeName:        reconstructedVolume.volumeName,
			volumeSpec:        reconstructedVolume.volumeSpec,
			devicePath:        reconstructedVolume.devicePath,
			deviceMounter:     reconstructedVolume.deviceMounter,
			blockVolumeMapper: reconstructedVolume.blockVolumeMapper,
			mounter:           reconstructedVolume.mounter,
		}
		if cachedInfo, ok := reconstructedVolumes[reconstructedVolume.volumeName]; ok {
			gvl = cachedInfo
		}
		gvl.addPodVolume(reconstructedVolume)

		reconstructedVolumeNames = append(reconstructedVolumeNames, reconstructedVolume.volumeName)
		reconstructedVolumes[reconstructedVolume.volumeName] = gvl
	}

	// 如果有重建的卷，则将其添加到 ASW (Actual State of World) 中，并更新相关状态信息
	if len(reconstructedVolumes) > 0 {
		rc.updateStatesNew(reconstructedVolumes)

		// 重建的卷已经挂载，因此之前的 kubelet 必须已将其添加到 node.status.volumesInUse 中。
		// 记得在 DesiredStateOfWorld 填充后更新 DSW 信息。
		rc.volumesNeedReportedInUse = reconstructedVolumeNames
		// 记得从 node.status.volumesAttached 中更新 devicePath 信息
		rc.volumesNeedUpdateFromNodeStatus = reconstructedVolumeNames
	}
	// 输出日志，表示卷的重建已完成
	klog.V(2).InfoS("Volume reconstruction finished")
}
```

###### getVolumesFromPodDir

```go
// getVolumesFromPodDir 通过扫描给定的 pod 目录下的所有卷目录，获取卷信息列表，包括 pod 的 uid、卷的插件名称、挂载路径以及卷规格名称。
func getVolumesFromPodDir(podDir string) ([]podVolume, error) {
	// 读取 pod 目录下的所有目录信息
	podsDirInfo, err := os.ReadDir(podDir)
	if err != nil {
		return nil, err
	}
	volumes := []podVolume{}
	for i := range podsDirInfo {
		// 遍历每个目录，判断是否为 pod 的目录
		if !podsDirInfo[i].IsDir() {
			continue
		}
		// 获取 pod 名称和目录路径
		podName := podsDirInfo[i].Name()
		podDir := filepath.Join(podDir, podName)

		// 查找文件系统卷信息
		volumesDirs := map[v1.PersistentVolumeMode]string{
			v1.PersistentVolumeFilesystem: filepath.Join(podDir, config.DefaultKubeletVolumesDirName),
		}
		// 查找块设备卷信息
		volumesDirs[v1.PersistentVolumeBlock] = filepath.Join(podDir, config.DefaultKubeletVolumeDevicesDirName)

		// 遍历 volumesDirs 中的每个卷目录
		for volumeMode, volumesDir := range volumesDirs {
			var volumesDirInfo []fs.DirEntry
			if volumesDirInfo, err = os.ReadDir(volumesDir); err != nil {
				// 如果给定的 volumesDir 不存在，则跳过此卷目录
				// 根据 volumeMode 的不同，可能不存在某些目录
				continue
			}
			// 遍历每个卷目录，获取卷信息
			for _, volumeDir := range volumesDirInfo {
				pluginName := volumeDir.Name()
				volumePluginPath := filepath.Join(volumesDir, pluginName)
				volumePluginDirs, err := utilpath.ReadDirNoStat(volumePluginPath)
				if err != nil {
					// 输出错误日志，表示无法读取卷插件目录，跳过此目录
					klog.ErrorS(err, "Could not read volume plugin directory", "volumePluginPath", volumePluginPath)
					continue
				}
				unescapePluginName := utilstrings.UnescapeQualifiedName(pluginName)
				// 遍历每个卷插件目录，获取卷名称并添加到卷列表中
				for _, volumeName := range volumePluginDirs {
					volumePath := filepath.Join(volumePluginPath, volumeName)
					// 输出日志，表示获取到卷的路径信息
					klog.V(5).InfoS("Volume path from volume plugin directory", "podName", podName, "volumePath", volumePath)
					volumes = append(volumes, podVolume{
						podName:        volumetypes.UniquePodName(podName),
						volumeSpecName: volumeName,
						volumePath:     volumePath,
						pluginName:     unescapePluginName,
						volumeMode:     volumeMode,
					})
				}
			}
		}
	}
	// 输出日志，表示从 pod 目录获取卷信息完成
	klog.V(4).InfoS("Get volumes from pod directory", "path", podDir, "volumes", volumes)
	return volumes, nil
}
```

###### reconstructVolume

````go
// 使用读取的卷目录数据重建卷的数据结构
func (rc *reconciler) reconstructVolume(volume podVolume) (rvolume *reconstructedVolume, rerr error) {
	// 输出日志，表示重建卷的操作开始
	metrics.ReconstructVolumeOperationsTotal.Inc()
	defer func() {
		if rerr != nil {
			metrics.ReconstructVolumeOperationsErrorsTotal.Inc()
		}
	}()

	// 初始化卷插件
	plugin, err := rc.volumePluginMgr.FindPluginByName(volume.pluginName)
	if err != nil {
		return nil, err
	}

	// 创建 pod 对象
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID(volume.podName),
		},
	}
	// 初始化 mapperPlugin，并检查是否找到了该插件
	mapperPlugin, err := rc.volumePluginMgr.FindMapperPluginByName(volume.pluginName)
	if err != nil {
		return nil, err
	}
	// 对于块设备卷，需要确保找到了 mapperPlugin
	if volume.volumeMode == v1.PersistentVolumeBlock && mapperPlugin == nil {
		return nil, fmt.Errorf("could not find block volume plugin %q (spec.Name: %q) pod %q (UID: %q)", volume.pluginName, volume.volumeSpecName, volume.podName, pod.UID)
	}

	// 调用 operationExecutor 的 ReconstructVolumeOperation 方法进行卷重建
	reconstructed, err := rc.operationExecutor.ReconstructVolumeOperation(
		volume.volumeMode,
		plugin,
		mapperPlugin,
		pod.UID,
		volume.podName,
		volume.volumeSpecName,
		volume.volumePath,
		volume.pluginName)
	if err != nil {
		return nil, err
	}
	// 获取重建后的卷规格
	volumeSpec := reconstructed.Spec
	if volumeSpec == nil {
		return nil, fmt.Errorf("failed to reconstruct volume for plugin %q (spec.Name: %q) pod %q (UID: %q): got nil", volume.pluginName, volume.volumeSpecName, volume.podName, pod.UID)
	}

	// 根据 volumeSpec 来查找卷插件，并确保能正确重建临时卷类型
	// 搜索时，需要检查卷是否可以附加（即是否有 PV）
	// 这样能确保重建的卷是可用的，而仅仅搜索卷插件名称只能确定插件是否支持可附加的卷。
	deviceMountablePlugin, err := rc.volumePluginMgr.FindDeviceMountablePluginBySpec(volumeSpec)
	if err != nil {
		return nil, err
	}

	// 根据卷是否可以附加（即是否可挂载）来确定卷的唯一名称
	// 对于可挂载的卷，需要从 volumeSpec 获取唯一名称
	// 否则，使用 pod 名称、卷插件和卷规格名称来确定唯一名称
	needsNameFromSpec := deviceMountablePlugin != nil
	if !needsNameFromSpec {
		// 作为备用方案，检查卷是否可挂载，以避免为 CSI 卷调用 FindAttachablePluginBySpec，它需要连接到 API 服务器，
		// 但在 kubelet 启动的这个阶段可能不可用。所有 CSI 卷都可以挂载，因此不会执行到这个代码。
		attachablePlugin, err := rc.volumePluginMgr.FindAttachablePluginBySpec(volumeSpec)
		if err != nil {
			return nil, err
		}
		needsNameFromSpec = attachablePlugin != nil
	}

	var uniqueVolumeName v1.UniqueVolumeName
	if needsNameFromSpec {
		uniqueVolumeName, err = util.GetUniqueVolumeNameFromSpec(plugin, volumeSpec)
		if err != nil {
			return nil, err
		}
	} else {
		uniqueVolumeName = util.GetUniqueVolumeNameFromSpecWithPod(volume.podName, plugin, volumeSpec)
	}

	var volumeMapper volumepkg.BlockVolumeMapper
	var volumeMounter volumepkg.Mounter
	var deviceMounter volumepkg.DeviceMounter

	if volume.volumeMode == v1.PersistentVolumeBlock {
		// 如果是块设备卷，创建新的块设备映射器
		var newMapperErr error
		volumeMapper, newMapperErr = mapperPlugin.NewBlockVolumeMapper(
			volumeSpec,
			pod,
			volumepkg.VolumeOptions{})
		if newMapperErr != nil {
			return nil, fmt.Errorf(
				"reconstructVolume.NewBlockVolumeMapper failed for volume %q (spec.Name: %q) pod %q (UID: %q) with: %v",
				uniqueVolumeName,
				volumeSpec.Name(),
				volume.podName,
				pod.UID,
				newMapperErr)
		}
	} else {
		// 如果是文件系统卷，创建新的挂载器
		var err error
		volumeMounter, err = plugin.NewMounter(
			volumeSpec,
			pod,
			volumepkg.VolumeOptions{})
		if err != nil {
			return nil, fmt.Errorf(
				"reconstructVolume.NewMounter failed for volume %q (spec.Name: %q) pod %q (UID: %q) with: %v",
				uniqueVolumeName,
				volumeSpec.Name(),
				volume.podName,
				pod.UID,
				err)
		}
		// 如果设备可挂载，创建新的设备挂载器
		if deviceMountablePlugin != nil {
			deviceMounter, err = deviceMountablePlugin.NewDeviceMounter()
			if err != nil {
				return nil, fmt.Errorf("reconstructVolume.NewDeviceMounter failed for volume %q (spec.Name: %q) pod %q (UID: %q) with: %v",
					uniqueVolumeName,
					volumeSpec.Name(),
					volume.podName,
					pod.UID,
					err)
			}
		}
	}

	// 创建重建后的卷数据结构，并返回
	reconstructedVolume := &reconstructedVolume{
		volumeName: uniqueVolumeName,
		podName:    volume.podName,
		volumeSpec: volumeSpec,
		// volume.volumeSpecName 实际上是 InnerVolumeSpecName，它不会用于卷清理。
		// 在 pod 被重新添加到 DesiredStateOfWorld 后，outerVolumeSpecName 将从 DSW 信息中更新。
		// 参见 issue #103143 及其修复详情。
		outerVolumeSpecName: volume.volumeSpecName,
		pod:                 pod,
		deviceMounter:       deviceMounter,
		volumeGidValue:      "",
		// 在 updateStates() 中会通过检查 node.status.volumesAttached 数据来更新 devicePath
		// TODO: 直接从卷的挂载路径获取设备路径。
		devicePath:          "",
		mounter:             volumeMounter,
		blockVolumeMapper:   volumeMapper,
		seLinuxMountContext: reconstructed.SELinuxMountContext,
	}
	return reconstructedVolume, nil
}
````

###### updateStatesNew

```go
func (rc *reconciler) updateStatesNew(reconstructedVolumes map[v1.UniqueVolumeName]*globalVolumeInfo) {
	// 遍历重建的卷信息，将它们添加到实际状态中，并更新相关状态信息
	for _, gvl := range reconstructedVolumes {
		err := rc.actualStateOfWorld.AddAttachUncertainReconstructedVolume(
			// TODO: 设备路径可能对于某些卷插件来说不正确，请参见 issue #54108
			gvl.volumeName, gvl.volumeSpec, rc.nodeName, gvl.devicePath)
		if err != nil {
			// 输出错误日志，表示无法将卷信息添加到实际状态中
			klog.ErrorS(err, "Could not add volume information to actual state of world", "volumeName", gvl.volumeName)
			continue
		}
		var seLinuxMountContext string
		for _, volume := range gvl.podVolumes {
			markVolumeOpts := operationexecutor.MarkVolumeOpts{
				PodName:             volume.podName,
				PodUID:              types.UID(volume.podName),
				VolumeName:          volume.volumeName,
				Mounter:             volume.mounter,
				BlockVolumeMapper:   volume.blockVolumeMapper,
				OuterVolumeSpecName: volume.outerVolumeSpecName,
				VolumeGidVolume:     volume.volumeGidValue,
				VolumeSpec:          volume.volumeSpec,
				VolumeMountState:    operationexecutor.VolumeMountUncertain,
				SELinuxMountContext: volume.seLinuxMountContext,
			}

			// 检查并标记卷为 uncertain 状态
			_, err = rc.actualStateOfWorld.CheckAndMarkVolumeAsUncertainViaReconstruction(markVolumeOpts)
			if err != nil {
				// 输出错误日志，表示无法将 pod 添加到实际状态中
				klog.ErrorS(err, "Could not add pod to volume information to actual state of world", "pod", klog.KObj(volume.pod))
				continue
			}
			seLinuxMountContext = volume.seLinuxMountContext
			// 输出日志，表示卷已被标记为 uncertain 并添加到实际状态中
			klog.V(2).InfoS("Volume is marked as uncertain and added into the actual state", "pod", klog.KObj(volume.pod), "podName", volume.podName, "volumeName", volume.volumeName, "seLinuxMountContext", volume.seLinuxMountContext)
		}
		// 如果卷有设备需要挂载，将其设备标记为 uncertain
		if gvl.deviceMounter != nil || gvl.blockVolumeMapper != nil {
			deviceMountPath, err := getDeviceMountPath(gvl)
			if err != nil {
				// 输出错误日志，表示无法找到设备挂载路径
				klog.ErrorS(err, "Could not find device mount path for volume", "volumeName", gvl.volumeName)
				continue
			}
			// 将设备标记为 uncertain
			err = rc.actualStateOfWorld.MarkDeviceAsUncertain(gvl.volumeName, gvl.devicePath, deviceMountPath, seLinuxMountContext)
			if err != nil {
				// 输出错误日志，表示无法将设备标记为 uncertain
				klog.ErrorS(err, "Could not mark device is uncertain to actual state of world", "volumeName", gvl.volumeName, "deviceMountPath", deviceMountPath)
				continue
			}
			// 输出日志，表示设备已被标记为 uncertain 并添加到实际状态中
			klog.V(2).InfoS("Volume is marked device as uncertain and added into the actual state", "volumeName", gvl.volumeName, "deviceMountPath", deviceMountPath)
		}
	}
}
```

#### runOld

```go
// 在 runOld 函数中，调用 wait.Until 函数来启动一个 reconciliationLoopFunc 循环，并且以 rc.loopSleepDuration 为间隔进行调用，直到收到停止信号 stopCh。
func (rc *reconciler) runOld(stopCh <-chan struct{}) {
	wait.Until(rc.reconciliationLoopFunc(), rc.loopSleepDuration, stopCh)
}
```

```go
// reconciliationLoopFunc 函数是一个闭包，它返回一个函数类型。该函数在每次调用时会执行 rc.reconcile() 来进行卷的调解过程。
// 在所有现有的 pod 从所有来源添加到 DesiredStateOfWorld 后，会在一次之后将状态与现实进行同步。
// 否则，重建过程可能会清理仍在使用中的 pod 的卷，因为 DesiredStateOfWorld 不包含完整的 pod 列表。
func (rc *reconciler) reconciliationLoopFunc() func() {
	return func() {
		rc.reconcile()

		if rc.populatorHasAddedPods() && !rc.StatesHasBeenSynced() {
			klog.InfoS("Reconciler: start to sync state")
			rc.sync()
		}
	}
}
```

##### reconcile

```go
// 在 reconcile 函数中，首先执行 rc.unmountVolumes() 函数来卸载应该卸载的卷。
// 接着执行 rc.mountOrAttachVolumes() 函数来挂载或附加应该挂载或附加的卷，包括处理 PVC 调整大小的情况。
// 最后执行 rc.unmountDetachDevices() 函数来确保需要分离或卸载的设备已经分离或卸载。
// 如果在重建过程中跳过的卷的数量大于0，则会调用 rc.processReconstructedVolumes() 函数来处理跳过的卷，将其标记为 uncertain 状态。
func (rc *reconciler) reconcile() {
	rc.unmountVolumes()
	rc.mountOrAttachVolumes()
	rc.unmountDetachDevices()

	if len(rc.skippedDuringReconstruction) > 0 {
		rc.processReconstructedVolumes()
	}
}

```

###### unmountVolumes

````go
// 在 unmountVolumes 函数中，会确保需要卸载的卷已经卸载。
// 遍历 rc.actualStateOfWorld.GetAllMountedVolumes() 返回的所有已挂载的卷，如果卷不在 DesiredStateOfWorld 中，
// 则卸载该卷，并输出相应的日志信息。
func (rc *reconciler) unmountVolumes() {
	for _, mountedVolume := range rc.actualStateOfWorld.GetAllMountedVolumes() {
		if !rc.desiredStateOfWorld.PodExistsInVolume(mountedVolume.PodName, mountedVolume.VolumeName, mountedVolume.SELinuxMountContext) {
			klog.V(5).InfoS(mountedVolume.GenerateMsgDetailed("Starting operationExecutor.UnmountVolume", ""))
			err := rc.operationExecutor.UnmountVolume(
				mountedVolume.MountedVolume, rc.actualStateOfWorld, rc.kubeletPodsDir)
			if err != nil && !isExpectedError(err) {
				klog.ErrorS(err, mountedVolume.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.UnmountVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error())
			}
			if err == nil {
				klog.InfoS(mountedVolume.GenerateMsgDetailed("operationExecutor.UnmountVolume started", ""))
			}
		}
	}
}
````

###### mountOrAttachVolumes

```go
// 在 mountOrAttachVolumes 函数中，会确保需要挂载或附加的卷已经挂载或附加。
// 遍历 rc.desiredStateOfWorld.GetVolumesToMount() 返回的所有需要挂载的卷，
// 检查卷的挂载状态，并根据情况执行挂载、附加、调整大小等操作，并输出相应的日志信息。
func (rc *reconciler) mountOrAttachVolumes() {
	for _, volumeToMount := range rc.desiredStateOfWorld.GetVolumesToMount() {
		volMounted, devicePath, err := rc.actualStateOfWorld.PodExistsInVolume(volumeToMount.PodName, volumeToMount.VolumeName, volumeToMount.DesiredPersistentVolumeSize, volumeToMount.SELinuxLabel)
		volumeToMount.DevicePath = devicePath
		if cache.IsSELinuxMountMismatchError(err) {
			// The volume is mounted, but with an unexpected SELinux context.
			// It will get unmounted in unmountVolumes / unmountDetachDevices and
			// then removed from actualStateOfWorld.
			rc.desiredStateOfWorld.AddErrorToPod(volumeToMount.PodName, err.Error())
			continue
		} else if cache.IsVolumeNotAttachedError(err) {
			rc.waitForVolumeAttach(volumeToMount)
		} else if !volMounted || cache.IsRemountRequiredError(err) {
			rc.mountAttachedVolumes(volumeToMount, err)
		} else if cache.IsFSResizeRequiredError(err) {
			fsResizeRequiredErr, _ := err.(cache.FsResizeRequiredError)
			rc.expandVolume(volumeToMount, fsResizeRequiredErr.CurrentSize)
		}
	}
}
```

###### unmountDetachDevices

````go
// 在 unmountDetachDevices 函数中，会确保需要分离或卸载的设备已经分离或卸载。
// 遍历 rc.actualStateOfWorld.GetUnmountedVolumes() 返回的所有需要分离或卸载的设备，
// 检查设备的状态，并根据情况执行设备的分离或卸载操作，并输出相应的日志信息。
func (rc *reconciler) unmountDetachDevices() {
	for _, attachedVolume := range rc.actualStateOfWorld.GetUnmountedVolumes() {
		// Check IsOperationPending to avoid marking a volume as detached if it's in the process of mounting.
		if !rc.desiredStateOfWorld.VolumeExists(attachedVolume.VolumeName, attachedVolume.SELinuxMountContext) &&
			!rc.operationExecutor.IsOperationPending(attachedVolume.VolumeName, nestedpendingoperations.EmptyUniquePodName, nestedpendingoperations.EmptyNodeName) {
			if attachedVolume.DeviceMayBeMounted() {
				// Volume is globally mounted to device, unmount it
				klog.V(5).InfoS(attachedVolume.GenerateMsgDetailed("Starting operationExecutor.UnmountDevice", ""))
				err := rc.operationExecutor.UnmountDevice(
					attachedVolume.AttachedVolume, rc.actualStateOfWorld, rc.hostutil)
				if err != nil && !isExpectedError(err) {
					klog.ErrorS(err, attachedVolume.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.UnmountDevice failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error())
				}
				if err == nil {
					klog.InfoS(attachedVolume.GenerateMsgDetailed("operationExecutor.UnmountDevice started", ""))
				}
			} else {
				// Volume is attached to node, detach it
				// Kubelet not responsible for detaching or this volume has a non-attachable volume plugin.
				if rc.controllerAttachDetachEnabled || !attachedVolume.PluginIsAttachable {
					rc.actualStateOfWorld.MarkVolumeAsDetached(attachedVolume.VolumeName, attachedVolume.NodeName)
					klog.InfoS(attachedVolume.GenerateMsgDetailed("Volume detached", fmt.Sprintf("DevicePath %q", attachedVolume.DevicePath)))
				} else {
					// Only detach if kubelet detach is enabled
					klog.V(5).InfoS(attachedVolume.GenerateMsgDetailed("Starting operationExecutor.DetachVolume", ""))
					err := rc.operationExecutor.DetachVolume(
						klog.TODO(), attachedVolume.AttachedVolume, false /* verifySafeToDetach */, rc.actualStateOfWorld)
					if err != nil && !isExpectedError(err) {
						klog.ErrorS(err, attachedVolume.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.DetachVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error())
					}
					if err == nil {
						klog.InfoS(attachedVolume.GenerateMsgDetailed("operationExecutor.DetachVolume started", ""))
					}
				}
			}
		}
	}
}
````

#### processReconstructedVolumes

```go
// processReconstructedVolumes 函数检查在重建过程中跳过的卷，因为假定这些卷由于存在于 DesiredStateOfWorld 中，它们将被正确挂载并进入 ActualStateOfWorld。
// 但如果由于某种原因挂载操作失败，我们仍然需要将卷标记为 uncertain 并等待下一次 reconciliationLoop 来处理。
func (rc *reconciler) processReconstructedVolumes() {
	for volumeName, glblVolumeInfo := range rc.skippedDuringReconstruction {
		// 检查卷是否标记为已附加到节点
		// 目前只处理至少已知已附加到节点的卷类型（包括 secret、configmap 等）
		if !rc.actualStateOfWorld.VolumeExists(volumeName) {
			klog.V(4).InfoS("Volume is not marked as attached to the node. Skipping processing of the volume", "volumeName", volumeName)
			continue
		}
		uncertainVolumeCount := 0
		// 只删除已标记为附加的卷。
		// 这应该确保在重建期间未标记为附加的卷在添加到 uncertain 状态之前会等待。
		delete(rc.skippedDuringReconstruction, volumeName)

		for podName, volume := range glblVolumeInfo.podVolumes {
			markVolumeOpts := operationexecutor.MarkVolumeOpts{
				PodName:             volume.podName,
				PodUID:              types.UID(podName),
				VolumeName:          volume.volumeName,
				Mounter:             volume.mounter,
				BlockVolumeMapper:   volume.blockVolumeMapper,
				OuterVolumeSpecName: volume.outerVolumeSpecName,
				VolumeGidVolume:     volume.volumeGidValue,
				VolumeSpec:          volume.volumeSpec,
				VolumeMountState:    operationexecutor.VolumeMountUncertain,
			}

			volumeAdded, err := rc.actualStateOfWorld.CheckAndMarkVolumeAsUncertainViaReconstruction(markVolumeOpts)

			// 如果卷未挂载，则在 ASOW 中将卷标记为 uncertain 并等待挂载
			if volumeAdded {
				uncertainVolumeCount += 1
				if err != nil {
					klog.ErrorS(err, "Could not add pod to volume information to actual state of world", "pod", klog.KObj(volume.pod))
					continue
				}
				klog.V(4).InfoS("Volume is marked as mounted in uncertain state and added to the actual state", "pod", klog.KObj(volume.pod), "podName", volume.podName, "volumeName", volume.volumeName)
			}
		}

		if uncertainVolumeCount > 0 {
			// 如果卷有设备需要挂载，将其设备标记为 uncertain
			if glblVolumeInfo.deviceMounter != nil || glblVolumeInfo.blockVolumeMapper != nil {
				deviceMountPath, err := getDeviceMountPath(glblVolumeInfo)
				if err != nil {
					klog.ErrorS(err, "Could not find device mount path for volume", "volumeName", glblVolumeInfo.volumeName)
					continue
				}
				deviceMounted := rc.actualStateOfWorld.CheckAndMarkDeviceUncertainViaReconstruction(glblVolumeInfo.volumeName, deviceMountPath)
				if !deviceMounted {
					klog.V(3).InfoS("Could not mark device as mounted in uncertain state", "volumeName", glblVolumeInfo.volumeName)
				}
			}
		}
	}
}
```

##### sync

````go
// sync 函数尝试通过扫描所有 pod 的卷目录从磁盘中观察真实世界。
// 如果实际状态和期望状态与观察到的世界不一致，意味着可能在 kubelet 重启期间留下了一些挂载的卷。
// 这个过程将重建卷并更新实际状态和期望状态。对于不支持重建的卷插件，它将尝试使用操作执行器清理挂载点。
func (rc *reconciler) sync() {
	defer rc.updateLastSyncTime()
	rc.syncStates(rc.kubeletPodsDir)
}
````

###### syncStates

````go
// syncStates 函数扫描给定 pod 目录下的卷目录。
// 如果卷不在 DesiredStateOfWorld 中，该函数将重建卷相关信息，并将其放入实际状态和期望状态的世界中。
// 对于一些不支持重建的卷插件，它将清理现有的挂载点，因为该卷不再需要（从 DesiredState 中删除）。
func (rc *reconciler) syncStates(kubeletPodDir string) {
	// 通过读取 pod 目录获取卷信息
	podVolumes, err := getVolumesFromPodDir(kubeletPodDir)
	if err != nil {
		klog.ErrorS(err, "Cannot get volumes from disk, skip sync states for volume reconstruction")
		return
	}
	volumesNeedUpdate := make(map[v1.UniqueVolumeName]*globalVolumeInfo)
	volumeNeedReport := []v1.UniqueVolumeName{}
	for _, volume := range podVolumes {
		if rc.actualStateOfWorld.VolumeExistsWithSpecName(volume.podName, volume.volumeSpecName) {
			klog.V(4).InfoS("Volume exists in actual state, skip cleaning up mounts", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
			// 不需要重建
			continue
		}
		volumeInDSW := rc.desiredStateOfWorld.VolumeExistsWithSpecName(volume.podName, volume.volumeSpecName)

		reconstructedVolume, err := rc.reconstructVolume(volume)
		if err != nil {
			if volumeInDSW {
				// 有一些 pod 需要这个卷，不进行清理，并希望 reconcile() 调用 SetUp 并在 ASW 中重建卷。
				klog.V(4).InfoS("Volume exists in desired state, skip cleaning up mounts", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
				continue
			}
			// 没有 pod 需要这个卷。
			klog.InfoS("Could not construct volume information, cleaning up mounts", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName, "err", err)
			rc.cleanupMounts(volume)
			continue
		}
		gvl := &globalVolumeInfo{
			volumeName:        reconstructedVolume.volumeName,
			volumeSpec:        reconstructedVolume.volumeSpec,
			devicePath:        reconstructedVolume.devicePath,
			deviceMounter:     reconstructedVolume.deviceMounter,
			blockVolumeMapper: reconstructedVolume.blockVolumeMapper,
			mounter:           reconstructedVolume.mounter,
		}
		if cachedInfo, ok := volumesNeedUpdate[reconstructedVolume.volumeName]; ok {
			gvl = cachedInfo
		}
		gvl.addPodVolume(reconstructedVolume)
		if volumeInDSW {
			// 有一些 pod 需要这个卷，并且它存在于磁盘上。某个之前的 kubelet 必须创建了该目录，因此它必须已报告卷正在使用中。
			// 在这个新的 kubelet 中，将该卷标记为使用中，这样 reconcile() 将调用 SetUp 并重新挂载卷（如果需要的话）。
			volumeNeedReport = append(volumeNeedReport, reconstructedVolume.volumeName)
			rc.skippedDuringReconstruction[reconstructedVolume.volumeName] = gvl
			klog.V(4).InfoS("Volume exists in desired state, marking as InUse", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
			continue
		}
		// 没有 pod 使用该卷。
		if rc.operationExecutor.IsOperationPending(reconstructedVolume.volumeName, nestedpendingoperations.EmptyUniquePodName, nestedpendingoperations.EmptyNodeName) {
			klog.InfoS("Volume is in pending operation, skip cleaning up mounts")
		}
		klog.V(2).InfoS("Reconciler sync states: could not find pod information in desired state, update it in actual state", "reconstructedVolume", reconstructedVolume)
		volumesNeedUpdate[reconstructedVolume.volumeName] = gvl
	}

	if len(volumesNeedUpdate) > 0 {
		if err = rc.updateStates(volumesNeedUpdate); err != nil {
			klog.ErrorS(err, "Error occurred during reconstruct volume from disk")
		}
	}
	if len(volumeNeedReport) > 0 {
		rc.desiredStateOfWorld.MarkVolumesReportedInUse(volumeNeedReport)
	}
}
````

#### StatesHasBeenSynced

````go
func (rc *reconciler) StatesHasBeenSynced() bool {
	rc.timeOfLastSyncLock.Lock()
	defer rc.timeOfLastSyncLock.Unlock()
	return !rc.timeOfLastSync.IsZero()
}
````

## volumeManager

```GO
// volumeManager实现了VolumeManager接口
type volumeManager struct {
    // kubeClient是DesiredStateOfWorldPopulator与API服务器通信以获取PV和PVC对象所使用的kube API客户端。
    kubeClient clientset.Interface

    // volumePluginMgr是用于访问卷插件的卷插件管理器。它必须预先初始化。
    volumePluginMgr *volume.VolumePluginMgr

    // desiredStateOfWorld是一个数据结构，包含了volume manager中的期望世界状态：即哪些卷应该被挂载以及哪些Pod引用了这些卷。
    // 该数据结构由DesiredStateOfWorldPopulator使用kubelet PodManager填充。
    desiredStateOfWorld cache.DesiredStateOfWorld

    // actualStateOfWorld是一个数据结构，包含了volume manager中的实际世界状态：即哪些卷被挂载到该节点上，以及哪些Pod引用了这些卷。
    // 该数据结构是由reconciler触发的attach、detach、mount和unmount操作成功完成后填充的。
    actualStateOfWorld cache.ActualStateOfWorld

    // operationExecutor用于启动异步的attach、detach、mount和unmount操作。
    operationExecutor operationexecutor.OperationExecutor

    // reconciler运行一个异步周期循环，通过使用operationExecutor触发attach、detach、mount和unmount操作，以将desiredStateOfWorld与actualStateOfWorld协调起来。
    reconciler reconciler.Reconciler

    // desiredStateOfWorldPopulator运行一个异步周期循环，使用kubelet PodManager填充desiredStateOfWorld。
    desiredStateOfWorldPopulator populator.DesiredStateOfWorldPopulator

    // csiMigratedPluginManager用于跟踪插件的CSI迁移状态
    csiMigratedPluginManager csimigration.PluginManager

    // intreeToCSITranslator将在树中的卷规范翻译为CSI
    intreeToCSITranslator csimigration.InTreeToCSITranslator
}
```







### NewVolumeManager

```GO
// NewVolumeManager返回一个实现了VolumeManager接口的新实例。
//
// kubeClient - kubeClient是DesiredStateOfWorldPopulator使用的kube API客户端，用于与API服务器通信以获取PV和PVC对象。
//
// volumePluginMgr - volumePluginMgr是用于访问卷插件的卷插件管理器。
// 必须预先初始化。
func NewVolumeManager(
    controllerAttachDetachEnabled bool,
    nodeName k8stypes.NodeName,
    podManager PodManager,
    podStateProvider PodStateProvider,
    kubeClient clientset.Interface,
    volumePluginMgr *volume.VolumePluginMgr,
    kubeContainerRuntime container.Runtime,
    mounter mount.Interface,
    hostutil hostutil.HostUtils,
    kubeletPodsDir string,
    recorder record.EventRecorder,
    keepTerminatedPodVolumes bool,
    blockVolumePathHandler volumepathhandler.BlockVolumePathHandler) VolumeManager {
    // 这里创建了一个volumeManager实例vm，并返回
    seLinuxTranslator := util.NewSELinuxLabelTranslator()
    vm := &volumeManager{
        kubeClient:          kubeClient,
        volumePluginMgr:     volumePluginMgr,
        desiredStateOfWorld: cache.NewDesiredStateOfWorld(volumePluginMgr, seLinuxTranslator),
        actualStateOfWorld:  cache.NewActualStateOfWorld(nodeName, volumePluginMgr),
        operationExecutor: operationexecutor.NewOperationExecutor(operationexecutor.NewOperationGenerator(
            kubeClient,
            volumePluginMgr,
            recorder,
            blockVolumePathHandler)),
    }

    // 创建csiMigratedPluginManager和intreeToCSITranslator实例
    intreeToCSITranslator := csitrans.New()
    csiMigratedPluginManager := csimigration.NewPluginManager(intreeToCSITranslator, utilfeature.DefaultFeatureGate)

    vm.intreeToCSITranslator = intreeToCSITranslator
    vm.csiMigratedPluginManager = csiMigratedPluginManager

    // 创建desiredStateOfWorldPopulator和reconciler实例
    vm.desiredStateOfWorldPopulator = populator.NewDesiredStateOfWorldPopulator(
        kubeClient,
        desiredStateOfWorldPopulatorLoopSleepPeriod,
        podManager,
        podStateProvider,
        vm.desiredStateOfWorld,
        vm.actualStateOfWorld,
        kubeContainerRuntime,
        keepTerminatedPodVolumes,
        csiMigratedPluginManager,
        intreeToCSITranslator,
        volumePluginMgr)
    vm.reconciler = reconciler.NewReconciler(
        kubeClient,
        controllerAttachDetachEnabled,
        reconcilerLoopSleepPeriod,
        waitForAttachTimeout,
        nodeName,
        vm.desiredStateOfWorld,
        vm.actualStateOfWorld,
        vm.desiredStateOfWorldPopulator.HasAddedPods,
        vm.operationExecutor,
        mounter,
        hostutil,
        volumePluginMgr,
        kubeletPodsDir)

    return vm
}
```

### Run

```go
// Run 函数运行卷管理器的主循环。它启动多个 goroutine 来处理卷管理的不同任务。
func (vm *volumeManager) Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()

	if vm.kubeClient != nil {
		// 启动 CSIDriver 的 Informer
		go vm.volumePluginMgr.Run(stopCh)
	}

	// 启动 desiredStateOfWorldPopulator 的主循环
	go vm.desiredStateOfWorldPopulator.Run(sourcesReady, stopCh)
	klog.V(2).InfoS("The desired_state_of_world populator starts")

	klog.InfoS("Starting Kubelet Volume Manager")
	// 启动 reconciler 的主循环
	go vm.reconciler.Run(stopCh)

	// 注册指标
	metrics.Register(vm.actualStateOfWorld, vm.desiredStateOfWorld, vm.volumePluginMgr)

	// 等待停止信号
	<-stopCh
	klog.InfoS("Shutting down Kubelet Volume Manager")
}
```

### WaitForAttachAndMount

````go
// WaitForAttachAndMount 等待 pod 的卷挂载和附加操作完成。
func (vm *volumeManager) WaitForAttachAndMount(ctx context.Context, pod *v1.Pod) error {
	if pod == nil {
		return nil
	}

	// 获取预期挂载的卷列表
	expectedVolumes := getExpectedVolumes(pod)
	if len(expectedVolumes) == 0 {
		// 没有需要验证的卷
		return nil
	}

	klog.V(3).InfoS("Waiting for volumes to attach and mount for pod", "pod", klog.KObj(pod))
	uniquePodName := util.GetUniquePodName(pod)

	// 对于一些 pod，它们希望 Setup 被反复调用以进行更新。
	// 重新挂载插件，以使这些插件可以更新卷的内容（例如 Downward API）。
	vm.desiredStateOfWorldPopulator.ReprocessPod(uniquePodName)

	// 等待卷挂载和附加完成
	err := wait.PollUntilContextTimeout(
		ctx,
		podAttachAndMountRetryInterval,
		podAttachAndMountTimeout,
		true,
		vm.verifyVolumesMountedFunc(uniquePodName, expectedVolumes))

	if err != nil {
		// 获取未挂载的卷、未附加的卷和未在 desired state 中的卷的信息，以便生成错误消息
		unmountedVolumes :=
			vm.getUnmountedVolumes(uniquePodName, expectedVolumes)
		unattachedVolumes :=
			vm.getUnattachedVolumes(uniquePodName)
		volumesNotInDSW :=
			vm.getVolumesNotInDSW(uniquePodName, expectedVolumes)

		if len(unmountedVolumes) == 0 {
			return nil
		}

		return fmt.Errorf(
			"unmounted volumes=%v, unattached volumes=%v, failed to process volumes=%v: %w",
			unmountedVolumes,
			unattachedVolumes,
			volumesNotInDSW,
			err)
	}

	klog.V(3).InfoS("All volumes are attached and mounted for pod", "pod", klog.KObj(pod))
	return nil
}
````

### WaitForUnmount

````go
// WaitForUnmount 等待 pod 的卷卸载完成。
func (vm *volumeManager) WaitForUnmount(ctx context.Context, pod *v1.Pod) error {
	if pod == nil {
		return nil
	}

	klog.V(3).InfoS("Waiting for volumes to unmount for pod", "pod", klog.KObj(pod))
	uniquePodName := util.GetUniquePodName(pod)

	vm.desiredStateOfWorldPopulator.ReprocessPod(uniquePodName)

	// 等待卷卸载完成
	err := wait.PollUntilContextTimeout(
		ctx,
		podAttachAndMountRetryInterval,
		podAttachAndMountTimeout,
		true,
		vm.verifyVolumesUnmountedFunc(uniquePodName))

	if err != nil {
		// 获取已挂载的卷列表，以便生成错误消息
		var mountedVolumes []string
		for _, v := range vm.actualStateOfWorld.GetMountedVolumesForPod(uniquePodName) {
			mountedVolumes = append(mountedVolumes, v.OuterVolumeSpecName)
		}
		sort.Strings(mountedVolumes)

		if len(mountedVolumes) == 0 {
			return nil
		}

		return fmt.Errorf(
			"mounted volumes=%v: %w",
			mountedVolumes,
			err)
	}

	klog.V(3).InfoS("All volumes are unmounted for pod", "pod", klog.KObj(pod))
	return nil
}
````

### GetMountedVolumesForPod

```go
// GetMountedVolumesForPod 获取 pod 的已挂载卷信息。
func (vm *volumeManager) GetMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap {
	podVolumes := make(container.VolumeMap)
	for _, mountedVolume := range vm.actualStateOfWorld.GetMountedVolumesForPod(podName) {
		podVolumes[mountedVolume.OuterVolumeSpecName] = container.VolumeInfo{
			Mounter:             mountedVolume.Mounter,
			BlockVolumeMapper:   mountedVolume.BlockVolumeMapper,
			ReadOnly:            mountedVolume.VolumeSpec.ReadOnly,
			InnerVolumeSpecName: mountedVolume.InnerVolumeSpecName,
		}
	}
	return podVolumes
}
```

### GetPossiblyMountedVolumesForPod

```go
// GetPossiblyMountedVolumesForPod 获取 pod 的可能已挂载卷信息。
func (vm *volumeManager) GetPossiblyMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap {
	podVolumes := make(container.VolumeMap)
	for _, mountedVolume := range vm.actualStateOfWorld.GetPossiblyMountedVolumesForPod(podName) {
		podVolumes[mountedVolume.OuterVolumeSpecName] = container.VolumeInfo{
			Mounter:             mountedVolume.Mounter,
			BlockVolumeMapper:   mountedVolume.BlockVolumeMapper,
			ReadOnly:            mountedVolume.VolumeSpec.ReadOnly,
			InnerVolumeSpecName: mountedVolume.InnerVolumeSpecName,
		}
	}
	return podVolumes
}
```

#### GetExtraSupplementalGroupsForPod

```go
// GetExtraSupplementalGroupsForPod 获取 pod 的额外附加的补充组。
func (vm *volumeManager) GetExtraSupplementalGroupsForPod(pod *v1.Pod) []int64 {
	podName := util.GetUniquePodName(pod)
	supplementalGroups := sets.NewString()

	// 获取 pod 中已挂载卷的补充组信息
	for _, mountedVolume := range vm.actualStateOfWorld.GetMountedVolumesForPod(podName) {
		if mountedVolume.VolumeGidValue != "" {
			supplementalGroups.Insert(mountedVolume.VolumeGidValue)
		}
	}

	result := make([]int64, 0, supplementalGroups.Len())
	for _, group := range supplementalGroups.List() {
		iGroup, extra := getExtraSupplementalGid(group, pod)
		if !extra {
			continue
		}

		result = append(result, int64(iGroup))
	}

	return result
}
```

#### GetVolumesInUse

````go
// GetVolumesInUse 获取正在使用的卷列表。
func (vm *volumeManager) GetVolumesInUse() []v1.UniqueVolumeName {
	// 向 desired state 和 actual state 报告需要挂载的卷，
	// 以便在决定该卷应该附加到该节点时立即标记卷为使用中，直到安全地卸载。
	desiredVolumes := vm.desiredStateOfWorld.GetVolumesToMount()
	allAttachedVolumes := vm.actualStateOfWorld.GetAttachedVolumes()
	volumesToReportInUse := make([]v1.UniqueVolumeName, 0, len(desiredVolumes)+len(allAttachedVolumes))
	desiredVolumesMap := make(map[v1.UniqueVolumeName]bool, len(desiredVolumes)+len(allAttachedVolumes))

	for _, volume := range desiredVolumes {
		if volume.PluginIsAttachable {
			if _, exists := desiredVolumesMap[volume.VolumeName]; !exists {
				desiredVolumesMap[volume.VolumeName] = true
				volumesToReportInUse = append(volumesToReportInUse, volume.VolumeName)
			}
		}
	}

	for _, volume := range allAttachedVolumes {
		if volume.PluginIsAttachable {
			if _, exists := desiredVolumesMap[volume.VolumeName]; !exists {
				volumesToReportInUse = append(volumesToReportInUse, volume.VolumeName)
			}
		}
	}

	// 将结果按卷名称排序并返回
	sort.Slice(volumesToReportInUse, func(i, j int) bool {
		return string(volumesToReportInUse[i]) < string(volumesToReportInUse[j])
	})
	return volumesToReportInUse
}
````

#### ReconcilerStatesHasBeenSynced

```go
// ReconcilerStatesHasBeenSynced 返回 reconciler 是否已经同步过状态。
func (vm *volumeManager) ReconcilerStatesHasBeenSynced() bool {
	return vm.reconciler.StatesHasBeenSynced()
}
```

#### VolumeIsAttached

```go
// VolumeIsAttached 判断指定的卷是否已经附加到该节点。
func (vm *volumeManager) VolumeIsAttached(volumeName v1.UniqueVolumeName) bool {
	return vm.actualStateOfWorld.VolumeExists(volumeName)
}
```

#### MarkVolumesAsReportedInUse

```go
// MarkVolumesAsReportedInUse 将一组卷标记为已报告正在使用中。
func (vm *volumeManager) MarkVolumesAsReportedInUse(volumesReportedAsInUse []v1.UniqueVolumeName) {
	vm.desiredStateOfWorld.MarkVolumesReportedInUse(volumesReportedAsInUse)
}
```

