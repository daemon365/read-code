
## 简介

Kubernetes中的attachdetach-controller是一个控制器，其主要作用是监控Kubernetes Pod中的Volume挂载状态，当Pod所在的节点发生故障或维护时，将Volume从原节点上卸载并重新挂载到新的节点上，以确保Pod中的Volume数据持久性和可靠性。

具体来说，attachdetach-controller会监视Pod的状态并跟踪其所使用的Volume。当Pod从原节点迁移时，attachdetach-controller会负责将Pod中的Volume从原节点上卸载，同时在新节点上重新挂载Volume。这个过程是自动化的，用户无需手动干预。

## interface

```go
type AttachDetachController interface {
	Run(ctx context.Context)
    // GetDesiredStateOfWorld方法用于获取attachdetach-controller当前的状态
	GetDesiredStateOfWorld() cache.DesiredStateOfWorld 
}
```

## 结构体

```GO
type attachDetachController struct {
	// clientset
	kubeClient clientset.Interface

	// pvc对象lister
	pvcLister  corelisters.PersistentVolumeClaimLister
	pvcsSynced kcache.InformerSynced

	// pv对象lister
	pvLister  corelisters.PersistentVolumeLister
	pvsSynced kcache.InformerSynced
	
    // pod对象lister
	podLister  corelisters.PodLister
	podsSynced kcache.InformerSynced
    // pod indexer缓存
	podIndexer kcache.Indexer
	
    // node 对象lister
	nodeLister  corelisters.NodeLister
	nodesSynced kcache.InformerSynced
	
    // 获取和存储CSINode对象的CSINode lister
	csiNodeLister storagelistersv1.CSINodeLister
	csiNodeSynced kcache.InformerSynced

	// 获取和存储CSIDriver对象的CSIDriver lister
	csiDriverLister  storagelistersv1.CSIDriverLister
	csiDriversSynced kcache.InformerSynced

	// VolumeAttachment对象lister
	volumeAttachmentLister storagelistersv1.VolumeAttachmentLister
	volumeAttachmentSynced kcache.InformerSynced

	// 云厂商接口
	cloud cloudprovider.Interface

	// 用于初始化和获取存储插件的实例
	volumePluginMgr volume.VolumePluginMgr

	// 数据结构，包含控制器期望的存储卷状态，例如控制器管理哪些节点、它希望将哪些存储卷附加到这些节点、哪些Pod会引用这些存储卷等。
    // 该数据结构由控制器使用Informer获取的节点和Pod API对象流填充
	desiredStateOfWorld cache.DesiredStateOfWorld

	// 数据结构，包含实际的存储卷状态，例如哪些存储卷附加到哪些节点上。
    // 该数据结构在控制器触发附加和分离操作并与存储提供程序进行“真实”世界的定期同步后填充。
	actualStateOfWorld cache.ActualStateOfWorld

	// 用于启动异步附加和分离操作的实例
	attacherDetacher operationexecutor.OperationExecutor

	// 用于运行异步周期性循环以通过使用attacherDetacher触发附加和分离操作，将desiredStateOfWorld与actualStateOfWorld协调一致。
	reconciler reconciler.Reconciler

	// 用于使用附加的存储卷列表更新节点状态的实例
	nodeStatusUpdater statusupdater.NodeStatusUpdater

	// 运行异步周期性循环以使用podInformer填充当前Pod的实例
	desiredStateOfWorldPopulator populator.DesiredStateOfWorldPopulator

	// 广播事件
	broadcaster record.EventBroadcaster

	// pvc队列
	pvcQueue workqueue.RateLimitingInterface

	// 检测已迁移到CSI的In-tree插件的实例
	csiMigratedPluginManager csimigration.PluginManager

	// 用于将In-tree存储卷规范翻译成CSI的实例
	intreeToCSITranslator csimigration.InTreeToCSITranslator

	// 配置控制器执行的任何拨号的过滤器拨号选项的实例
	filteredDialOptions *proxyutil.FilteredDialOptions
}
```

## New

```GO
func NewAttachDetachController(
	logger klog.Logger,
	kubeClient clientset.Interface,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	pvcInformer coreinformers.PersistentVolumeClaimInformer,
	pvInformer coreinformers.PersistentVolumeInformer,
	csiNodeInformer storageinformersv1.CSINodeInformer,
	csiDriverInformer storageinformersv1.CSIDriverInformer,
	volumeAttachmentInformer storageinformersv1.VolumeAttachmentInformer,
	cloud cloudprovider.Interface,
	plugins []volume.VolumePlugin,
	prober volume.DynamicPluginProber,
	disableReconciliationSync bool,
	reconcilerSyncDuration time.Duration,
	timerConfig TimerConfig,
	filteredDialOptions *proxyutil.FilteredDialOptions) (AttachDetachController, error) {

	adc := &attachDetachController{
		kubeClient:          kubeClient,
		pvcLister:           pvcInformer.Lister(),
		pvcsSynced:          pvcInformer.Informer().HasSynced,
		pvLister:            pvInformer.Lister(),
		pvsSynced:           pvInformer.Informer().HasSynced,
		podLister:           podInformer.Lister(),
		podsSynced:          podInformer.Informer().HasSynced,
		podIndexer:          podInformer.Informer().GetIndexer(),
		nodeLister:          nodeInformer.Lister(),
		nodesSynced:         nodeInformer.Informer().HasSynced,
		cloud:               cloud,
		pvcQueue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "pvcs"),
		filteredDialOptions: filteredDialOptions,
	}

	adc.csiNodeLister = csiNodeInformer.Lister()
	adc.csiNodeSynced = csiNodeInformer.Informer().HasSynced

	adc.csiDriverLister = csiDriverInformer.Lister()
	adc.csiDriversSynced = csiDriverInformer.Informer().HasSynced

	adc.volumeAttachmentLister = volumeAttachmentInformer.Lister()
	adc.volumeAttachmentSynced = volumeAttachmentInformer.Informer().HasSynced
	
    // 初始化插件
	if err := adc.volumePluginMgr.InitPlugins(plugins, prober, adc); err != nil {
		return nil, fmt.Errorf("could not initialize volume plugins for Attach/Detach Controller: %w", err)
	}

	adc.broadcaster = record.NewBroadcaster() // 创建一个记录广播器
	recorder := adc.broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "attachdetach-controller"}) // 为广播器创建一个记录器
	blkutil := volumepathhandler.NewBlockVolumePathHandler() // 创建一个新的 BlockVolumePathHandler
	
    // 创建一个 DesiredStateOfWorld 缓存
	adc.desiredStateOfWorld = cache.NewDesiredStateOfWorld(&adc.volumePluginMgr)
    // 创建一个 ActualStateOfWorld 缓存
	adc.actualStateOfWorld = cache.NewActualStateOfWorld(&adc.volumePluginMgr)
     // 创建一个 AttacherDetacher
	adc.attacherDetacher =
		operationexecutor.NewOperationExecutor(operationexecutor.NewOperationGenerator(
			kubeClient,
			&adc.volumePluginMgr,
			recorder,
			blkutil))
    // 创建一个节点状态更新器
	adc.nodeStatusUpdater = statusupdater.NewNodeStatusUpdater(
		kubeClient, nodeInformer.Lister(), adc.actualStateOfWorld)

	// 根据选项将这些值设置为默认值
	adc.reconciler = reconciler.NewReconciler(
		timerConfig.ReconcilerLoopPeriod,
		timerConfig.ReconcilerMaxWaitForUnmountDuration,
		reconcilerSyncDuration,
		disableReconciliationSync,
		adc.desiredStateOfWorld,
		adc.actualStateOfWorld,
		adc.attacherDetacher,
		adc.nodeStatusUpdater,
		adc.nodeLister,
		recorder)
	
     // 创建一个CSI转换器
	csiTranslator := csitrans.New()
     // 将该转换器设置为ADC的intreeToCSITranslator
	adc.intreeToCSITranslator = csiTranslator
    // 创建一个CSI迁移插件管理器
	adc.csiMigratedPluginManager = csimigration.NewPluginManager(csiTranslator, utilfeature.DefaultFeatureGate)
	
    // 创建一个StateOfWorldPopulator
	adc.desiredStateOfWorldPopulator = populator.NewDesiredStateOfWorldPopulator(
		timerConfig.DesiredStateOfWorldPopulatorLoopSleepPeriod,
		timerConfig.DesiredStateOfWorldPopulatorListPodsRetryDuration,
		podInformer.Lister(),
		adc.desiredStateOfWorld,
		&adc.volumePluginMgr,
		pvcInformer.Lister(),
		pvInformer.Lister(),
		adc.csiMigratedPluginManager,
		adc.intreeToCSITranslator)
	
    // 监控pod
	podInformer.Informer().AddEventHandler(kcache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			adc.podAdd(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			adc.podUpdate(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			adc.podDelete(logger, obj)
		},
	})

	// 这个自定义索引器将PVC键索引为Pod。这样，我们就不需要每次都遍历所有Pod，以查找引用给定PVC的Pod。
	if err := common.AddPodPVCIndexerIfNotPresent(adc.podIndexer); err != nil {
		return nil, fmt.Errorf("could not initialize attach detach controller: %w", err)
	}
	
    // 监控node
	nodeInformer.Informer().AddEventHandler(kcache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			adc.nodeAdd(logger, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			adc.nodeUpdate(logger, oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			adc.nodeDelete(logger, obj)
		},
	})
	
    // 监控pvc
	pvcInformer.Informer().AddEventHandler(kcache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			adc.enqueuePVC(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			adc.enqueuePVC(new)
		},
	})

	return adc, nil
}
```

### 队列相关

#### pod

```go
func (adc *attachDetachController) podAdd(logger klog.Logger, obj interface{}) {
	// podAdd 是 attachDetachController 结构体的一个方法，接收两个参数：logger 和 obj。

	pod, ok := obj.(*v1.Pod)
	// 将 obj 转换为 *v1.Pod 类型的变量 pod，并通过 ok 变量判断转换是否成功。

	if pod == nil || !ok {
		// 如果 pod 为 nil 或者转换不成功，则返回。
		return
	}

	if pod.Spec.NodeName == "" {
		// 如果 pod 的 Spec.NodeName 字段为空，说明该 pod 没有被调度到节点上，直接返回。
		return
	}

	volumeActionFlag := util.DetermineVolumeAction(
		pod,
		adc.desiredStateOfWorld,
		true /* default volume action */)
	// 调用 util 包中的 DetermineVolumeAction 方法，计算 pod 的卷操作标志 volumeActionFlag，传入 pod、desiredStateOfWorld 和默认卷操作标志 true。

	util.ProcessPodVolumes(logger, pod, volumeActionFlag, /* addVolumes */
		adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister, adc.csiMigratedPluginManager, adc.intreeToCSITranslator)
	// 调用 util 包中的 ProcessPodVolumes 方法，处理 pod 的卷，传入 logger、pod、volumeActionFlag、desiredStateOfWorld、volumePluginMgr、pvcLister、pvLister、csiMigratedPluginManager 和 inTreeToCSITranslator 等参数。
}

func (adc *attachDetachController) podUpdate(logger klog.Logger, oldObj, newObj interface{}) {
	// podUpdate 是 attachDetachController 结构体的一个方法，接收三个参数：logger、oldObj 和 newObj。

	pod, ok := newObj.(*v1.Pod)
	// 将 newObj 转换为 *v1.Pod 类型的变量 pod，并通过 ok 变量判断转换是否成功。

	if pod == nil || !ok {
		// 如果 pod 为 nil 或者转换不成功，则返回。
		return
	}

	if pod.Spec.NodeName == "" {
		// 如果 pod 的 Spec.NodeName 字段为空，说明该 pod 没有被调度到节点上，直接返回。
		return
	}

	volumeActionFlag := util.DetermineVolumeAction(
		pod,
		adc.desiredStateOfWorld,
		true /* default volume action */)
	// 调用 util 包中的 DetermineVolumeAction 方法，计算 pod 的卷操作标志 volumeActionFlag，传入 pod、desiredStateOfWorld 和默认卷操作标志 true。

	util.ProcessPodVolumes(logger, pod, volumeActionFlag, /* addVolumes */
		adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister, adc.csiMigratedPluginManager, adc.intreeToCSITranslator)
	// 调用 util 包中的 ProcessPodVolumes 方法，处理 pod 的卷，传入 logger、pod、volumeActionFlag、desiredStateOfWorld、volumePluginMgr、pvcLister、pvLister、csiMigratedPluginManager 和 inTreeToCSITranslator 等参数。
}

func (adc *attachDetachController) podDelete(logger klog.Logger, obj interface{}) {
	// podDelete 是 attachDetachController 结构体的一个方法，接收两个参数：logger 和 obj。

	pod, ok := obj.(*v1.Pod)
	// 将 obj 转换为 *v1.Pod 类型的变量 pod，并通过 ok 变量判断转换是否成功。

	if pod == nil || !ok {
		// 如果 pod 为 nil 或者转换不成功，则返回。
		return
	}

	util.ProcessPodVolumes(logger, pod, false, /* addVolumes */
		adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister, adc.csiMigratedPluginManager, adc.intreeToCSITranslator)
	// 调用 util 包中的 ProcessPodVolumes 方法，处理 pod 的卷，传入 logger、pod、false（表示删除卷操作）、desiredStateOfWorld、volumePluginMgr、pvcLister、pvLister、csiMigratedPluginManager 和 inTreeToCSITranslator 等参数。
}
```

##### ProcessPodVolumes

```go
func ProcessPodVolumes(logger klog.Logger, pod *v1.Pod, addVolumes bool, desiredStateOfWorld cache.DesiredStateOfWorld, volumePluginMgr *volume.VolumePluginMgr, pvcLister corelisters.PersistentVolumeClaimLister, pvLister corelisters.PersistentVolumeLister, csiMigratedPluginManager csimigration.PluginManager, csiTranslator csimigration.InTreeToCSITranslator) {
    // 处理 Pod 的卷信息
	if pod == nil {
		return
	}
	if len(pod.Spec.Volumes) <= 0 {
        // 如果 Pod 没有定义卷，跳过处理
		logger.V(10).Info("Skipping processing of pod, it has no volumes", "pod", klog.KObj(pod))
		return
	}

	nodeName := types.NodeName(pod.Spec.NodeName)
	if nodeName == "" {
        // 如果 Pod 没有分配到节点，跳过处理
		logger.V(10).Info("Skipping processing of pod, it is not scheduled to a node", "pod", klog.KObj(pod))
		return
	} else if !desiredStateOfWorld.NodeExists(nodeName) {
        // 如果 Pod 分配到的节点不在期望的状态世界数据结构中，表示该节点还未由控制器管理，因此忽略该 Pod
		logger.V(4).Info("Skipping processing of pod, it is scheduled to node which is not managed by the controller", "node", klog.KRef("", string(nodeName)), "pod", klog.KObj(pod))
		return
	}

	// 为 Pod 中的每个卷处理卷规范
	for _, podVolume := range pod.Spec.Volumes {
		volumeSpec, err := CreateVolumeSpec(logger, podVolume, pod, nodeName, volumePluginMgr, pvcLister, pvLister, csiMigratedPluginManager, csiTranslator)
		if err != nil {
            // 如果处理卷规范时出错，记录日志并继续处理下一个卷
			logger.V(10).Info("Error processing volume for pod", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "err", err)
			continue
		}

		attachableVolumePlugin, err :=
			volumePluginMgr.FindAttachablePluginBySpec(volumeSpec)
		if err != nil || attachableVolumePlugin == nil {
            // 如果卷插件不支持 attacher 接口，跳过处理
			logger.V(10).Info("Skipping volume for pod, it does not implement attacher interface", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "err", err)
			continue
		}

		uniquePodName := util.GetUniquePodName(pod)
		if addVolumes {
			// 将卷添加到期望的状态世界
			_, err := desiredStateOfWorld.AddPod(
				uniquePodName, pod, volumeSpec, nodeName)
			if err != nil {
                // 如果添加卷到期望的状态世界时出错，记录日志
				logger.V(10).Info("Failed to add volume for pod to desiredStateOfWorld", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "err", err)
			}

		} else {
			// 从期望的世界状态中移除卷
			uniqueVolumeName, err := util.GetUniqueVolumeNameFromSpec(attachableVolumePlugin, volumeSpec)
            if err != nil {
                // 如果 GetUniqueVolumeNameFromSpec 失败，则记录日志并继续下一轮循环
                logger.V(10).Info("无法从期望的世界状态中删除卷。GetUniqueVolumeNameFromSpec 失败", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "err", err)
                continue
            }
            // 从期望的世界状态中删除 Pod 和卷
            desiredStateOfWorld.DeletePod(uniquePodName, uniqueVolumeName, nodeName)
       	 }
	}
	return
}
```

##### CreateVolumeSpec

```go
func CreateVolumeSpec(logger klog.Logger, podVolume v1.Volume, pod *v1.Pod, nodeName types.NodeName, vpm *volume.VolumePluginMgr, pvcLister corelisters.PersistentVolumeClaimLister, pvLister corelisters.PersistentVolumeLister, csiMigratedPluginManager csimigration.PluginManager, csiTranslator csimigration.InTreeToCSITranslator) (*volume.Spec, error) {
	claimName := ""
	readOnly := false
	if pvcSource := podVolume.VolumeSource.PersistentVolumeClaim; pvcSource != nil {
		claimName = pvcSource.ClaimName // 提取 podVolume 的 PersistentVolumeClaim 中的 ClaimName
		readOnly = pvcSource.ReadOnly // 提取 podVolume 的 PersistentVolumeClaim 中的 ReadOnly
	}
	isEphemeral := podVolume.VolumeSource.Ephemeral != nil // 判断 podVolume 是否为 Ephemeral Volume
	if isEphemeral {
		claimName = ephemeral.VolumeClaimName(pod, &podVolume) // 若为 Ephemeral Volume，则从 podVolume 提取 Ephemeral VolumeClaimName
	}
	if claimName != "" { // 如果 claimName 不为空，说明 podVolume 为绑定了 PVC 的 Volume
		logger.V(10).Info("Found PVC", "PVC", klog.KRef(pod.Namespace, claimName)) // 输出日志，表示找到了对应的 PVC

		// 如果 podVolume 是一个 PVC，从缓存中获取与之对应的实际 PV
		pvc, err := getPVCFromCache(pod.Namespace, claimName, pvcLister)
		if err != nil {
			return nil, fmt.Errorf(
				"error processing PVC %q/%q: %v",
				pod.Namespace,
				claimName,
				err) // 如果获取 PVC 失败，则返回错误
		}
		if isEphemeral {
			if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {
				return nil, err // 如果获取的 PVC 与 Pod 不匹配，则返回错误
			}
		}

		pvName, pvcUID := pvc.Spec.VolumeName, pvc.UID // 从 PVC 中提取 PV 的名称和 UID
		logger.V(10).Info("Found bound PV for PVC", "PVC", klog.KRef(pod.Namespace, claimName), "pvcUID", pvcUID, "PV", klog.KRef("", pvName)) // 输出日志，表示找到了与 PVC 绑定的 PV

		// 从缓存中获取实际的 PV 对象
		volumeSpec, err := getPVSpecFromCache(
			pvName, readOnly, pvcUID, pvLister)
		if err != nil {
			return nil, fmt.Errorf(
				"error processing PVC %q/%q: %v",
				pod.Namespace,
				claimName,
				err) // 如果获取 PV 失败，则返回错误
		}

		volumeSpec, err = translateInTreeSpecToCSIIfNeeded(volumeSpec, nodeName, vpm, csiMigratedPluginManager, csiTranslator, pod.Namespace) // 如果需要，将 InTree 的 VolumeSpec 转换成 CSI 的 VolumeSpec
		if err != nil {
			return nil, fmt.Errorf(
				"error performing CSI migration checks and translation for PVC %q/%q: %v",
				pod.Namespace,
				claimName,
				err)
		}

		logger.V(10).Info("Extracted volumeSpec from bound PV and PVC", "PVC", klog.KRef(pod.Namespace, claimName), "pvcUID", pvcUID, "PV", klog.KRef("", pvName), "volumeSpecName", volumeSpec.Name())

		return volumeSpec, nil
}
```

###### getPVCFromCache

```go
func getPVCFromCache(namespace string, name string, pvcLister corelisters.PersistentVolumeClaimLister) (*v1.PersistentVolumeClaim, error) {
	pvc, err := pvcLister.PersistentVolumeClaims(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find PVC %s/%s in PVCInformer cache: %v", namespace, name, err)
	}

	if pvc.Status.Phase != v1.ClaimBound || pvc.Spec.VolumeName == "" {
		return nil, fmt.Errorf(
			"PVC %s/%s has non-bound phase (%q) or empty pvc.Spec.VolumeName (%q)",
			namespace,
			name,
			pvc.Status.Phase,
			pvc.Spec.VolumeName)
	}

	return pvc, nil
}
```

###### getPVSpecFromCache

```go
func getPVSpecFromCache(name string, pvcReadOnly bool, expectedClaimUID types.UID, pvLister corelisters.PersistentVolumeLister) (*volume.Spec, error) {
	// 从 PVInformer 缓存中获取 PV 对象
	pv, err := pvLister.Get(name)
	if err != nil {
		// 如果获取 PV 失败，则返回错误信息
		return nil, fmt.Errorf("failed to find PV %q in PVInformer cache: %v", name, err)
	}

	// 检查 PV 对象的 ClaimRef 字段是否为 nil，如果为 nil，则表示 PV 还未绑定到 PVC，返回错误信息
	if pv.Spec.ClaimRef == nil {
		return nil, fmt.Errorf(
			"found PV object %q but it has a nil pv.Spec.ClaimRef indicating it is not yet bound to the claim",
			name)
	}

	// 检查 PV 对象的 ClaimRef.UID 是否与期望的 Claim UID 一致，如果不一致，则返回错误信息
	if pv.Spec.ClaimRef.UID != expectedClaimUID {
		return nil, fmt.Errorf(
			"found PV object %q but its pv.Spec.ClaimRef.UID (%q) does not point to claim.UID (%q)",
			name,
			pv.Spec.ClaimRef.UID,
			expectedClaimUID)
	}

	// 由于 PVInformer 缓存是共享的，为避免对象被其他消费者修改，对 PV 对象进行深拷贝
	clonedPV := pv.DeepCopy()

	// 根据深拷贝后的 PV 对象创建 Volume Spec 对象，并返回
	return volume.NewSpecFromPersistentVolume(clonedPV, pvcReadOnly), nil
}
```

###### translateInTreeSpecToCSIIfNeeded

```go
func translateInTreeSpecToCSIIfNeeded(spec *volume.Spec, nodeName types.NodeName, vpm *volume.VolumePluginMgr, csiMigratedPluginManager csimigration.PluginManager, csiTranslator csimigration.InTreeToCSITranslator, podNamespace string) (*volume.Spec, error) {
	translatedSpec := spec // 将传入的参数 spec 赋值给 translatedSpec，用于后续的操作
	migratable, err := csiMigratedPluginManager.IsMigratable(spec) // 检查传入的 spec 是否支持 CSI 迁移
	if err != nil {
		return nil, err // 如果检查失败，则返回错误
	}
	if !migratable {
		// 如果 spec 不支持 CSI 迁移，则直接返回原始 spec，不进行翻译
		return spec, nil
	}
	migrationSupportedOnNode, err := isCSIMigrationSupportedOnNode(nodeName, spec, vpm, csiMigratedPluginManager) // 检查节点是否支持 CSI 迁移
	if err != nil {
		return nil, err // 如果检查失败，则返回错误
	}
	if migratable && migrationSupportedOnNode {
		// 如果 spec 支持 CSI 迁移且节点支持 CSI 迁移，则进行 InTree 到 CSI 的翻译
		translatedSpec, err = csimigration.TranslateInTreeSpecToCSI(spec, podNamespace, csiTranslator)
		if err != nil {
			return nil, err // 如果翻译失败，则返回错误
		}
	}
	return translatedSpec, nil // 返回翻译后的 spec，或原始 spec（如果不支持 CSI 迁移）
}
```

###### isCSIMigrationSupportedOnNode

```go
func isCSIMigrationSupportedOnNode(nodeName types.NodeName, spec *volume.Spec, vpm *volume.VolumePluginMgr, csiMigratedPluginManager csimigration.PluginManager) (bool, error) {
	pluginName, err := csiMigratedPluginManager.GetInTreePluginNameFromSpec(spec.PersistentVolume, spec.Volume) // 从 spec 中获取插件名称
	if err != nil {
		return false, err // 如果获取失败，则返回错误
	}

	if len(pluginName) == 0 {
		// 未能从翻译目录中找到插件名称，说明未翻译
		return false, nil
	}

	if csiMigratedPluginManager.IsMigrationCompleteForPlugin(pluginName) {
		// 当插件的 CSI 迁移完成标志为 true 时，说明在所有节点上都安装了并配置了 CSI 迁移插件
		// 即使控制器和 kubelet 之间存在版本差异，仍然支持 CSI 迁移
		return true, nil
	}

	if len(nodeName) == 0 {
		return false, errors.New("nodeName is empty") // 如果节点名称为空，则返回错误
	}

	kubeClient := vpm.Host.GetKubeClient()
	if kubeClient == nil {
		// 如果 kubeClient 为空，说明在独立的（无头的） kubelet 上，不进行控制器和 kubelet 版本一致性检查，直接检查 feature gates
		return true, nil
	}

	adcHost, ok := vpm.Host.(volume.AttachDetachVolumeHost)
	if !ok {
		// 如果 vpm.Host 不是 volume.AttachDetachVolumeHost 类型，说明 "enableControllerAttachDetach" 在 kubelet 上被设置为 true，不进行控制器和 kubelet 版本一致性检查，直接检查 feature gates
		return true, nil
	}

	if adcHost.CSINodeLister() == nil {
		return false, errors.New("could not find CSINodeLister in attachDetachController") // 如果 CSINodeLister 为空，则返回错误
	}

	csiNode, err := adcHost.CSINodeLister().Get(string(nodeName)) // 从 CSINodeLister 中获取指定节点的 CSINode 信息
	if err != nil {
		return false, err // 如果获取失败，则返回错误
	}

	ann := csiNode.GetAnnotations() // 获取 CSINode 的注解信息
	if ann == nil {
		return false, nil // 如果注解信息为空，则说明未迁移
	}

	mpa := ann[v1.MigratedPluginsAnnotationKey] // 从注解信息中获取迁移插件的注解值
	tok := strings.Split(mpa, ",") // 将注解值按逗号分隔为插件名称列表
	mpaSet := sets.NewString(tok...) // 将插件名称列表转换为 sets.String 类型的集合

	isMigratedOnNode := mpaSet.Has(pluginName) // 检查指定插件是否在迁移插件列表中

	return isMigratedOnNode, nil // 返回指定插件是否在迁移插件列表中的结果
}
```

#### node

```go
func (adc *attachDetachController) nodeAdd(logger klog.Logger, obj interface{}) {
	// nodeAdd 函数，处理 Node 资源的添加事件，接收一个日志记录器 logger 和一个事件对象 obj 作为参数

	node, ok := obj.(*v1.Node)
	// 尝试将事件对象转换为 *v1.Node 类型的指针，如果转换成功，则将结果赋值给 node 变量，同时将 ok 设置为 true，否则将 ok 设置为 false
	// TODO: investigate if nodeName is empty then if we can return
	// kubernetes/kubernetes/issues/37777
	if node == nil || !ok {
		// 如果 node 为空或者转换失败，则直接返回，不执行后续操作
		return
	}
	nodeName := types.NodeName(node.Name) 
	// 将 Node 的名称赋值给 nodeName 变量，使用 types.NodeName 进行类型转换，以便后续操作使用

	adc.nodeUpdate(logger, nil, obj)
	// 调用 adc 结构体的 nodeUpdate 方法，进行节点更新操作，传入日志记录器 logger、nil 和事件对象 obj 作为参数

	// kubernetes/kubernetes/issues/37586
	// This is to workaround the case when a node add causes to wipe out
	// the attached volumes field. This function ensures that we sync with
	// the actual status.
	adc.actualStateOfWorld.SetNodeStatusUpdateNeeded(logger, nodeName)
	// 调用 adc 结构体的 actualStateOfWorld 字段的 SetNodeStatusUpdateNeeded 方法，设置节点状态更新为需要更新状态，传入日志记录器 logger 和节点名称 nodeName 作为参数
}

func (adc *attachDetachController) nodeUpdate(logger klog.Logger, oldObj, newObj interface{}) {
	// nodeUpdate 函数，处理 Node 资源的更新事件，接收一个日志记录器 logger、旧的事件对象 oldObj 和新的事件对象 newObj 作为参数

	node, ok := newObj.(*v1.Node)
	// 尝试将新的事件对象转换为 *v1.Node 类型的指针，如果转换成功，则将结果赋值给 node 变量，同时将 ok 设置为 true，否则将 ok 设置为 false
	// TODO: investigate if nodeName is empty then if we can return
	if node == nil || !ok {
		// 如果 node 为空或者转换失败，则直接返回，不执行后续操作
		return
	}

	nodeName := types.NodeName(node.Name)
	// 将 Node 的名称赋值给 nodeName 变量，使用 types.NodeName 进行类型转换，以便后续操作使用

	adc.addNodeToDswp(node, nodeName)
	// 调用 adc 结构体的 addNodeToDswp 方法，将节点添加到 DesiredStateOfWorldProvider（DSWP）中进行状态同步，传入 node 和 nodeName 作为参数

	adc.processVolumesInUse(logger, nodeName, node.Status.VolumesInUse)
	// 调用 adc 结构体的 processVolumesInUse 方法，处理节点中正在使用的卷的状态更新，传入日志记录器 logger、nodeName 和 node.Status.VolumesInUse 作为参数
}

func (adc *attachDetachController) nodeDelete(logger klog.Logger, obj interface{}) {
	// nodeDelete 函数，处理 Node 资源的删除事件，接收一个日志记录器 logger 和事件对象 obj 作为参数

	node, ok := obj.(*v1.Node)
	// 尝试将事件对象转换为 *v1.Node 类型的指针，如果转换成功，则将结果赋值给 node 变量，同时将 ok 设置为 true，否则将 ok 设置为 false
	if node == nil || !ok {
		// 如果 node 为空或者转换失败，则直接返回，不执行后续操作
		return
	}

	nodeName := types.NodeName(node.Name)
	// 将 Node 的名称赋值给 nodeName 变量，使用 types.NodeName 进行类型转换，以便后续操作使用

	if err := adc.desiredStateOfWorld.DeleteNode(nodeName); err != nil {
		// 调用 adc.desiredStateOfWorld 的 DeleteNode 方法，从 DesiredStateOfWorldProvider（DSWP）中删除节点，如果返回错误，则记录日志信息
		logger.Info("Error removing node from desired-state-of-world", "node", klog.KObj(node), "err", err)
	}

	adc.processVolumesInUse(logger, nodeName, node.Status.VolumesInUse)
	// 调用 adc 结构体的 processVolumesInUse 方法，处理节点中正在使用的卷的状态更新，传入日志记录器 logger、nodeName 和 node.Status.VolumesInUse 作为参数
}
```

##### addNodeToDswp

```go
func (adc *attachDetachController) addNodeToDswp(node *v1.Node, nodeName types.NodeName) {
	// addNodeToDswp 函数，将节点添加到 DesiredStateOfWorldProvider（DSWP）中，接收一个 *v1.Node 类型的指针和 types.NodeName 类型的 nodeName 作为参数

	if _, exists := node.Annotations[volumeutil.ControllerManagedAttachAnnotation]; exists {
		// 检查节点的 Annotations 中是否存在 volumeutil.ControllerManagedAttachAnnotation 标注，如果存在则继续执行下面的操作

		keepTerminatedPodVolumes := false

		if t, ok := node.Annotations[volumeutil.KeepTerminatedPodVolumesAnnotation]; ok {
			// 检查节点的 Annotations 中是否存在 volumeutil.KeepTerminatedPodVolumesAnnotation 标注，如果存在则获取其值，并将其转换为布尔型
			keepTerminatedPodVolumes = t == "true"
		}

		// 节点指定了要由 attach-detach controller 管理的标注，将节点添加到 DesiredStateOfWorldProvider（DSWP）中
		adc.desiredStateOfWorld.AddNode(nodeName, keepTerminatedPodVolumes)
	}
}
```

##### processVolumesInUse

```go
func (adc *attachDetachController) processVolumesInUse(
	logger klog.Logger, nodeName types.NodeName, volumesInUse []v1.UniqueVolumeName) {
	// processVolumesInUse 函数，处理节点上正在使用的卷，接收一个 klog.Logger 类型的 logger，一个 types.NodeName 类型的 nodeName，和一个 []v1.UniqueVolumeName 类型的 volumesInUse 作为参数

	logger.V(4).Info("processVolumesInUse for node", "node", klog.KRef("", string(nodeName)))
	// 打印日志，记录正在处理的节点

	for _, attachedVolume := range adc.actualStateOfWorld.GetAttachedVolumesForNode(nodeName) {
		// 遍历节点已附加的卷列表

		mounted := false
		// 初始化 mounted 变量为 false，表示卷未挂载

		for _, volumeInUse := range volumesInUse {
			// 遍历传入的 volumesInUse，即节点上正在使用的卷列表

			if attachedVolume.VolumeName == volumeInUse {
				// 如果节点上已附加的卷与正在使用的卷列表中的某个卷名称匹配，则将 mounted 设置为 true，表示卷已挂载
				mounted = true
				break
			}
		}

		err := adc.actualStateOfWorld.SetVolumeMountedByNode(logger, attachedVolume.VolumeName, nodeName, mounted)
		// 调用 actualStateOfWorld 的 SetVolumeMountedByNode 方法，设置卷的挂载状态

		if err != nil {
			// 如果设置卷挂载状态时发生错误，则记录错误信息到日志
			logger.Info(
				"SetVolumeMountedByNode returned an error",
				"node", klog.KRef("", string(nodeName)),
				"volumeName", attachedVolume.VolumeName,
				"mounted", mounted,
				"err", err)
		}
	}
}
```

#### pvc

```go
func (adc *attachDetachController) enqueuePVC(obj interface{}) {
	key, err := kcache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	adc.pvcQueue.Add(key)
}
```

### NodeStatusUpdater

```go
type NodeStatusUpdater interface {
	// NodeStatusUpdater 接口定义了节点状态更新器的方法

	// Gets a list of node statuses that should be updated from the actual state
	// of the world and updates them.
	// 获取应从实际世界的状态更新的节点状态列表，并进行更新。
	UpdateNodeStatuses(logger klog.Logger) error

	// Update any pending status change for the given node
	// 更新给定节点的任何待处理状态更改。
	UpdateNodeStatusForNode(logger klog.Logger, nodeName types.NodeName) error
}

type nodeStatusUpdater struct {
	kubeClient         clientset.Interface
	nodeLister         corelisters.NodeLister
	actualStateOfWorld cache.ActualStateOfWorld
}

func NewNodeStatusUpdater(
	kubeClient clientset.Interface,
	nodeLister corelisters.NodeLister,
	actualStateOfWorld cache.ActualStateOfWorld) NodeStatusUpdater {
	return &nodeStatusUpdater{
		actualStateOfWorld: actualStateOfWorld,
		nodeLister:         nodeLister,
		kubeClient:         kubeClient,
	}
}
```

#### UpdateNodeStatuses

```go
func (nsu *nodeStatusUpdater) UpdateNodeStatuses(logger klog.Logger) error {
    // UpdateNodeStatuses 是 nodeStatusUpdater 结构体的一个方法，用于更新节点状态信息。
    // 参数 logger 是用于记录日志的 logger 对象。
    var nodeIssues int
    // 初始化一个整型变量 nodeIssues，用于记录有多少个节点出现错误。

    nodesToUpdate := nsu.actualStateOfWorld.GetVolumesToReportAttached(logger)
    // 调用 actualStateOfWorld 结构体的 GetVolumesToReportAttached 方法，获取需要报告已附加卷的节点信息，
    // 并将结果赋值给 nodesToUpdate。

    for nodeName, attachedVolumes := range nodesToUpdate {
        // 遍历 nodesToUpdate 中的每个节点和其对应的已附加卷信息。

        err := nsu.processNodeVolumes(logger, nodeName, attachedVolumes)
        // 调用 nodeStatusUpdater 结构体的 processNodeVolumes 方法，处理节点的附加卷信息，
        // 并将错误信息（如果有）赋值给 err。

        if err != nil {
            // 如果处理节点附加卷信息时出现错误（err 不为空），则将 nodeIssues 加一，
            // 表示当前节点出现了错误。
            nodeIssues += 1
        }
    }

    if nodeIssues > 0 {
        // 如果有节点出现错误（nodeIssues 大于 0），则返回一个错误，错误信息中包含有多少个节点出现了错误。
        return fmt.Errorf("unable to update %d nodes", nodeIssues)
    }

    // 如果所有节点都成功更新了状态，则返回 nil，表示没有错误。
    return nil
}
```

##### processNodeVolumes

```go
// processNodeVolumes 处理节点上挂载的卷的状态更新
func (nsu *nodeStatusUpdater) processNodeVolumes(logger klog.Logger, nodeName types.NodeName, attachedVolumes []v1.AttachedVolume) error {
	// 通过 nodeName 从 nodeLister 中获取节点对象
	nodeObj, err := nsu.nodeLister.Get(string(nodeName))
	if errors.IsNotFound(err) {
		// 如果节点不存在，无法更新其状态
		// 什么也不做，直到节点被创建，才会重试
		logger.V(2).Info(
			"Could not update node status. Failed to find node in NodeInformer cache", "node", klog.KRef("", string(nodeName)), "err", err)
		return nil
	} else if err != nil {
		// 对于其他所有错误，记录错误并将标志 statusUpdateNeeded 重置为 true，以指示需要再次更新此节点状态。
		logger.V(2).Info("Error retrieving nodes from node lister", "err", err)
		nsu.actualStateOfWorld.SetNodeStatusUpdateNeeded(logger, nodeName)
		return err
	}

	// 更新节点状态
	err = nsu.updateNodeStatus(logger, nodeName, nodeObj, attachedVolumes)
	if errors.IsNotFound(err) {
		// 如果节点不存在，无法更新其状态
		// 什么也不做，直到节点被创建，才会重试
		logger.V(2).Info(
			"Could not update node status, node does not exist - skipping", "node", klog.KObj(nodeObj))
		return nil
	} else if err != nil {
		// 如果更新节点状态失败，则将标志 statusUpdateNeeded 重置为 true，以指示需要再次更新此节点状态。
		nsu.actualStateOfWorld.SetNodeStatusUpdateNeeded(logger, nodeName)

		logger.V(2).Info("Could not update node status; re-marking for update", "node", klog.KObj(nodeObj), "err", err)

		return err
	}

	return nil
}
```

##### updateNodeStatus

```go
func (nsu *nodeStatusUpdater) updateNodeStatus(logger klog.Logger, nodeName types.NodeName, nodeObj *v1.Node, attachedVolumes []v1.AttachedVolume) error {
    // 使用传入的参数创建 node 对象的深拷贝
    node := nodeObj.DeepCopy()
    // 更新 node 对象的 VolumesAttached 字段为传入的 attachedVolumes 切片
    node.Status.VolumesAttached = attachedVolumes

    // 调用 nodeutil.PatchNodeStatus 方法生成对 nodeObj 进行状态更新的 patchBytes 字节流
    // 并返回更新后的 node 对象和 patchBytes 字节流以及可能的错误
    _, patchBytes, err := nodeutil.PatchNodeStatus(nsu.kubeClient.CoreV1(), nodeName, nodeObj, node)
    if err != nil {
        return err
    }

    // 打印更新成功的日志信息，包括更新的 node 对象、patchBytes 字节流和 attachedVolumes 切片
    logger.V(4).Info("Updating status for node succeeded", "node", klog.KObj(node), "patchBytes", patchBytes, "attachedVolumes", attachedVolumes)

    // 返回 nil 表示更新成功
    return nil
}
```

#### UpdateNodeStatusForNode

```go
// UpdateNodeStatusForNode 更新指定节点的节点状态
func (nsu *nodeStatusUpdater) UpdateNodeStatusForNode(logger klog.Logger, nodeName types.NodeName) error {
	// 获取需要更新标志和已挂载卷列表
	needsUpdate, attachedVolumes := nsu.actualStateOfWorld.GetVolumesToReportAttachedForNode(logger, nodeName)
	if !needsUpdate {
		// 如果不需要更新，则直接返回 nil
		return nil
	}
	// 处理节点上挂载的卷的状态更新
	return nsu.processNodeVolumes(logger, nodeName, attachedVolumes)
}
```

### Reconciler

```go
// Reconciler 接口定义了一个卷控制器的调谐器，用于启动周期性的卷状态调谐循环
type Reconciler interface {
	Run(ctx context.Context)
}

// reconciler 是一个卷控制器的调谐器实现，其中包含一些调谐器所需的状态和方法
type reconciler struct {
	loopPeriod                time.Duration                    // 调谐循环周期
	maxWaitForUnmountDuration time.Duration                    // 挂载点卸载等待时间上限
	syncDuration              time.Duration                    // 状态同步的最长等待时间
	desiredStateOfWorld       cache.DesiredStateOfWorld         // 期望状态
	actualStateOfWorld        cache.ActualStateOfWorld          // 实际状态
	attacherDetacher          operationexecutor.OperationExecutor // 操作执行器
	nodeStatusUpdater         statusupdater.NodeStatusUpdater      // 节点状态更新器
	nodeLister                corelisters.NodeLister               // 节点列表器
	timeOfLastSync            time.Time                          // 上一次状态同步的时间
	disableReconciliationSync bool                               // 禁用调谐同步
	recorder                  record.EventRecorder                // 事件记录器
}

func NewReconciler(
	loopPeriod time.Duration,
	maxWaitForUnmountDuration time.Duration,
	syncDuration time.Duration,
	disableReconciliationSync bool,
	desiredStateOfWorld cache.DesiredStateOfWorld,
	actualStateOfWorld cache.ActualStateOfWorld,
	attacherDetacher operationexecutor.OperationExecutor,
	nodeStatusUpdater statusupdater.NodeStatusUpdater,
	nodeLister corelisters.NodeLister,
	recorder record.EventRecorder) Reconciler {
	return &reconciler{
		loopPeriod:                loopPeriod,
		maxWaitForUnmountDuration: maxWaitForUnmountDuration,
		syncDuration:              syncDuration,
		disableReconciliationSync: disableReconciliationSync,
		desiredStateOfWorld:       desiredStateOfWorld,
		actualStateOfWorld:        actualStateOfWorld,
		attacherDetacher:          attacherDetacher,
		nodeStatusUpdater:         nodeStatusUpdater,
		nodeLister:                nodeLister,
		timeOfLastSync:            time.Now(),
		recorder:                  recorder,
	}
}
```

#### Run

```go
func (rc *reconciler) Run(ctx context.Context) {
    // 执行reconciliationLoopFunc
	wait.UntilWithContext(ctx, rc.reconciliationLoopFunc(ctx), rc.loopPeriod)
}
```

#### reconciliationLoopFunc

```go
func (rc *reconciler) reconciliationLoopFunc(ctx context.Context) func(context.Context) {
    // 返回的函数类型为 func(context.Context)。
    return func(ctx context.Context) {
        // 调用 rc 对象的 reconcile 方法。
        rc.reconcile(ctx)
        // 从上下文中获取 logger。
        logger := klog.FromContext(ctx)
        // 如果 rc 对象的 disableReconciliationSync 值为 true，则跳过卷的重建。
        if rc.disableReconciliationSync {
            logger.V(5).Info("Skipping reconciling attached volumes still attached since it is disabled via the command line")
        // 如果 rc 对象的 syncDuration 值小于 1 秒，则跳过卷的重建。
        } else if rc.syncDuration < time.Second {
            logger.V(5).Info("Skipping reconciling attached volumes still attached since it is set to less than one second via the command line")
        // 如果距离上次同步的时间大于 rc 对象的 syncDuration，则进行卷的重建。
        } else if time.Since(rc.timeOfLastSync) > rc.syncDuration {
            logger.V(5).Info("Starting reconciling attached volumes still attached")
            rc.sync()
        }
    }
}
```

#### reconcile

```go
func (rc *reconciler) reconcile(ctx context.Context) {
    logger := klog.FromContext(ctx)
    // 遍历所有已挂载的卷，检查是否需要将它们卸载。
    for _, attachedVolume := range rc.actualStateOfWorld.GetAttachedVolumes() {
        // 如果当前卷在期望的集群状态中不存在，需要卸载当前卷。
        if !rc.desiredStateOfWorld.VolumeExists(
            attachedVolume.VolumeName, attachedVolume.NodeName) {
            // 判断卸载操作是否安全，避免在操作仍在进行中时尝试重复卸载。
            if util.IsMultiAttachAllowed(attachedVolume.VolumeSpec) {
                if !rc.attacherDetacher.IsOperationSafeToRetry(attachedVolume.VolumeName, "" /* podName */, attachedVolume.NodeName, operationexecutor.DetachOperationName) {
                    logger.V(10).Info("Operation for volume is already running or still in exponential backoff for node. Can't start detach", "node", klog.KRef("", string(attachedVolume.NodeName)), "volumeName", attachedVolume.VolumeName)
                    continue
                }
            } else {
                if !rc.attacherDetacher.IsOperationSafeToRetry(attachedVolume.VolumeName, "" /* podName */, "" /* nodeName */, operationexecutor.DetachOperationName) {
                    logger.V(10).Info("Operation for volume is already running or still in exponential backoff in the cluster. Can't start detach for node", "node", klog.KRef("", string(attachedVolume.NodeName)), "volumeName", attachedVolume.VolumeName)
                    continue
                }
            }
            // 如果卸载操作更新了 ActualStateOfWorld 后才标记为完成，就有可能在 GetAttachedVolumes() 检查和 IsOperationPending() 检查之间从 ActualStateOfWorld 中删除该卷。
            // 再次检查 ActualStateOfWorld 可以避免发出不必要的卸载请求。
            attachState := rc.actualStateOfWorld.GetAttachState(attachedVolume.VolumeName, attachedVolume.NodeName)
            if attachState == cache.AttachStateDetached {
                logger.V(5).Info("Volume detached--skipping", "volume", attachedVolume)
                continue
            }
            // 设置卸载请求时间。
            elapsedTime, err := rc.actualStateOfWorld.SetDetachRequestTime(logger, attachedVolume.VolumeName, attachedVolume.NodeName)
            if err != nil {
                logger.Error(err, "Cannot trigger detach because it fails to set detach request time with error")
                continue
            }
            // 检查是否已达到最大等待时间。
            timeout := elapsedTime > rc.maxWaitForUnmountDuration
            // 检查节点是否健康。
            isHealthy, err := rc.nodeIsHealthy(attachedVolume.NodeName)
            if err != nil {
                logger.Error(err, "Failed to get health of node", "node", klog.KRef("", string(attachedVolume.NodeName)))
            }
            // 在最大等待时间后，强制从不健康的节点卸载卷。
            forceDetach := !isHealthy && timeout
            // 返回节点的污点信息以及是否有上述污点
			hasOutOfServiceTaint, err := rc.hasOutOfServiceTaint(attachedVolume.NodeName)
			if err != nil {
				logger.Error(err, "Failed to get taint specs for node", "node", klog.KRef("", string(attachedVolume.NodeName)))
			}

			// 如果卷仍然被挂载，而且没有强制卸载（forceDetach 为 false）以及节点上没有 node.kubernetes.io/out-of-service 的污点
			if attachedVolume.MountedByNode && !forceDetach && !hasOutOfServiceTaint {
				logger.V(5).Info("Cannot detach volume because it is still mounted", "volume", attachedVolume)
				continue
			}

			// 在执行卸载卷的操作之前，将卷标记为已卸载，并更新节点状态
			err = rc.actualStateOfWorld.RemoveVolumeFromReportAsAttached(attachedVolume.VolumeName, attachedVolume.NodeName)
			if err != nil {
				logger.V(5).Info("RemoveVolumeFromReportAsAttached failed while removing volume from node",
					"node", klog.KRef("", string(attachedVolume.NodeName)),
					"volumeName", attachedVolume.VolumeName,
					"err", err)
			}

			// 更新节点状态以指示卷不再可以安全装载。
			err = rc.nodeStatusUpdater.UpdateNodeStatusForNode(logger, attachedVolume.NodeName)
			if err != nil {
				// 如果无法更新节点状态，则跳过此卸载操作
				logger.Error(err, "UpdateNodeStatusForNode failed while attempting to report volume as attached", "volume", attachedVolume)
				// 如果 UpdateNodeStatusForNode 调用失败，则将卷重新添加到 ReportAsAttached 中，以便节点状态更新器将其添加回 VolumeAttached 列表中。
				// 这里也需要它，因为 DetachVolume 实际上没有被调用，我们需要为每个重建保持数据一致性。
				rc.actualStateOfWorld.AddVolumeToReportAsAttached(logger, attachedVolume.VolumeName, attachedVolume.NodeName)
				continue
			}

			// 触发卸载卷操作，需要进行验证是否安全可卸载的步骤
            // 如果 timeout 为 true，则跳过 verifySafeToDetach 检查
            // 如果节点具有带 NoExecute 效果的 node.kubernetes.io/out-of-service 污点，则跳过 verifySafeToDetach 检查
			logger.V(5).Info("Starting attacherDetacher.DetachVolume", "volume", attachedVolume)
			if hasOutOfServiceTaint {
				logger.V(4).Info("node has out-of-service taint", "node", klog.KRef("", string(attachedVolume.NodeName)))
			}
			verifySafeToDetach := !(timeout || hasOutOfServiceTaint)
			err = rc.attacherDetacher.DetachVolume(logger, attachedVolume.AttachedVolume, verifySafeToDetach, rc.actualStateOfWorld)
			if err == nil {
				if !timeout {
					logger.Info("attacherDetacher.DetachVolume started", "volume", attachedVolume)
				} else {
                    // 如果未能卸载卷且超时，则强制卸载，并记录指标
					metrics.RecordForcedDetachMetric()
					logger.Info("attacherDetacher.DetachVolume started: this volume is not safe to detach, but maxWaitForUnmountDuration expired, force detaching", "duration", rc.maxWaitForUnmountDuration, "volume", attachedVolume)
				}
			}
			if err != nil {
				// 如果 DetachVolume 调用失败，则将卷重新添加到 ReportAsAttached 中，以便节点状态更新器将其添加回 VolumeAttached 列表中。
                // 这个函数也在 operation_generoator 中执行卷卸载操作时调用。
                // 这里也需要它，因为 DetachVolume 调用可能会在执行操作执行之前失败（例如，无法找到卷插件等）。
				rc.actualStateOfWorld.AddVolumeToReportAsAttached(logger, attachedVolume.VolumeName, attachedVolume.NodeName)

				if !exponentialbackoff.IsExponentialBackoff(err) {
					// 忽略 exponentialbackoff.IsExponentialBackoff 错误，因为它们是预期的。
					// 记录其他所有错误。
					logger.Error(err, "attacherDetacher.DetachVolume failed to start", "volume", attachedVolume)
				}
			}
		}
	}
	
    // 挂载应该挂载到当前节点上的所有卷
	rc.attachDesiredVolumes(logger)

	// 更新状态
	err := rc.nodeStatusUpdater.UpdateNodeStatuses(logger)
	if err != nil {
		logger.Info("UpdateNodeStatuses failed", "err", err)
	}
}

```

##### hasOutOfServiceTaint

```GO
func (rc *reconciler) hasOutOfServiceTaint(nodeName types.NodeName) (bool, error) {
    // 判断特性门是否启用 NodeOutOfServiceVolumeDetach 特性。
    if utilfeature.DefaultFeatureGate.Enabled(features.NodeOutOfServiceVolumeDetach) {
    // 从 node 列表中获取 nodeName 对应的节点信息。
    node, err := rc.nodeLister.Get(string(nodeName))
    if err != nil {
    	return false, err
    }
    // 判断该节点的 Taints 中是否存在 NodeOutOfService Taint，并返回相应的 bool 类型。
    return taints.TaintKeyExists(node.Spec.Taints, v1.TaintNodeOutOfService), nil
    }
    // 特性门未启用，则直接返回 false 和 nil。
    return false, nil
}
```



````GO
func (rc reconciler) attachDesiredVolumes(logger klog.Logger) {
    // 遍历所有应该被挂载的卷。
    for _, volumeToAttach := range rc.desiredStateOfWorld.GetVolumesToAttach() {
    // 如果该卷支持多节点挂载。
    if util.IsMultiAttachAllowed(volumeToAttach.VolumeSpec) {
        // 如果已经有一个针对该卷和节点的挂载/卸载操作在进行，则跳过。
        if rc.attacherDetacher.IsOperationPending(volumeToAttach.VolumeName, "" / podName /, volumeToAttach.NodeName) {
            logger.V(10).Info("Operation for volume is already running for node. Can't start attach", "node", klog.KRef("", string(volumeToAttach.NodeName)), "volumeName", volumeToAttach.VolumeName)
            continue
        }
    } else { // 如果该卷不支持多节点挂载。
        // 如果已经有一个针对该卷的挂载/卸载操作在进行，则跳过。
        if rc.attacherDetacher.IsOperationPending(volumeToAttach.VolumeName, "" / podName /, "" / nodeName */) {
            logger.V(10).Info("Operation for volume is already running. Can't start attach for node", "node", klog.KRef("", string(volumeToAttach.NodeName)), "volumeNames", volumeToAttach.VolumeName)
            continue
        }
    }
		// 由于挂载操作在标记自身完成之前会更新 ActualStateOfWorld，所以必须在 GetAttachState() 之前检查 IsOperationPending()，以确保在读取 ActualStateOfWorld 时其已经是最新的。
	// 详见 https://github.com/kubernetes/kubernetes/issues/93902
	attachState := rc.actualStateOfWorld.GetAttachState(volumeToAttach.VolumeName, volumeToAttach.NodeName)
	// 如果该卷已经被成功挂载。
	if attachState == cache.AttachStateAttached {
		// 触发 Volume/Node 存在性检测以重置 detachRequestedTime。
		logger.V(10).Info("Volume attached--touching", "volume", volumeToAttach)
		rc.actualStateOfWorld.ResetDetachRequestTime(logger, volumeToAttach.VolumeName, volumeToAttach.NodeName)
		continue
	}

	// 如果该卷不支持多节点挂载。
	if !util.IsMultiAttachAllowed(volumeToAttach.VolumeSpec) {
		// 获取已经挂载该卷的所有节点。
		nodes := rc.actualStateOfWorld.GetNodesForAttachedVolume(volumeToAttach.VolumeName)
		if len(nodes) > 0 {
			// 如果之前没有报告过该卷的多节点挂载错误，则报告该错误并将 volumeToAttach.MultiAttachErrorReported 设置为 true。
			if !volumeToAttach.MultiAttachErrorReported {
				rc.reportMultiAttachError(logger, volumeToAttach, nodes)
				rc.desiredStateOfWorld.SetMultiAttachError(volumeToAttach.VolumeName, volumeToAttach.NodeName)
			}
			continue
		}
	}
    
        
    logger.V(5).Info("Starting attacherDetacher.AttachVolume", "volume", volumeToAttach)
     // 尝试使用 attacherDetacher 接口将卷附加到节点上，记录操作日志
    err := rc.attacherDetacher.AttachVolume(logger, volumeToAttach.VolumeToAttach, rc.actualStateOfWorld)
    if err == nil {
        logger.Info("attacherDetacher.AttachVolume started", "volumeName", volumeToAttach.VolumeName, "nodeName", volumeToAttach.NodeName, "scheduledPods", klog.KObjSlice(volumeToAttach.ScheduledPods))
    }
    if err != nil && !exponentialbackoff.IsExponentialBackoff(err) {
        // Ignore exponentialbackoff.IsExponentialBackoff errors, they are expected.
        // Log all other errors.
        logger.Error(err, "attacherDetacher.AttachVolume failed to start", "volumeName", volumeToAttach.VolumeName, "nodeName", volumeToAttach.NodeName, "scheduledPods", klog.KObjSlice(volumeToAttach.ScheduledPods))
    }
}
````

##### reportMultiAttachError

```go
func (rc *reconciler) reportMultiAttachError(logger klog.Logger, volumeToAttach cache.VolumeToAttach, nodes []types.NodeName) {
    // 从节点列表中过滤掉当前节点，其他节点会使用卷
    // 一些方法需要[]string，另一些需要[]NodeName，因此需要同时收集两者
    // 理论上，这些数组应该始终只有一个元素-控制器不允许多个附件。但是以数组的形式使用以防万一...
    otherNodes := []types.NodeName{}
    otherNodesStr := []string{}
    for _, node := range nodes {
        if node != volumeToAttach.NodeName {
            otherNodes = append(otherNodes, node)
            otherNodesStr = append(otherNodesStr, string(node))
        }
    }

    // 获取在其他节点上使用该卷的Pod列表
    pods := rc.desiredStateOfWorld.GetVolumePodsOnNodes(otherNodes, volumeToAttach.VolumeName)
    if len(pods) == 0 {
        // 没有找到请求该卷的任何Pod。Pod可能已被删除。
        // 生成简单的消息，通知Pods
        simpleMsg, _ := volumeToAttach.GenerateMsg("Multi-Attach error", "Volume is already exclusively attached to one node and can't be attached to another")
        for _, pod := range volumeToAttach.ScheduledPods {
            rc.recorder.Eventf(pod, v1.EventTypeWarning, kevents.FailedAttachVolume, simpleMsg)
        }
        // 记录详细的日志消息
        logger.Info("Multi-Attach error: volume is already exclusively attached and can't be attached to another node", "attachedTo", otherNodesStr, "volume", volumeToAttach)
        return
    }

    // 有Pod需要该卷并在另一个节点上运行。这通常是用户错误，例如ReplicaSet使用PVC并具有>1个副本。
    // 让用户知道哪些Pod阻止了该卷。
    for _, scheduledPod := range volumeToAttach.ScheduledPods {
        // 每个scheduledPod必须获得自定义消息。它们可以在不同的命名空间中运行，因此不同命名空间的用户不应该看到其他命名空间中的Pod名称。
        localPodNames := []string{} // scheduledPod所在命名空间中Pod的名称
        otherPods := 0              // 在其他命名空间中的Pod计数
        for _, pod := range pods {
            if pod.Namespace == scheduledPod.Namespace {
                localPodNames = append(localPodNames, pod.Name)
            } else {
                otherPods++
            }
        }

        var msg string
        if len(localPodNames) > 0 {
            msg = fmt.Sprintf("Volume is already used by pod(s) %s", strings.Join(localPodNames, ", "))
            if otherPods > 0 {
                msg = fmt.Sprintf("%s and %d pod(s) in different namespaces", msg, otherPods)
            }
        }  else {
			// 没有本地pod，只有不同namespace中的pod。
			msg = fmt.Sprintf("Volume is already used by %d pod(s) in different namespaces", otherPods)
            }
            simpleMsg, _ := volumeToAttach.GenerateMsg("Multi-Attach error", msg)
            rc.recorder.Eventf(scheduledPod, v1.EventTypeWarning, kevents.FailedAttachVolume, simpleMsg)
        }

        // Log all pods for system admin
        logger.Info("Multi-Attach error: volume is already used by pods", "pods", klog.KObjSlice(pods), "attachedTo", otherNodesStr, "volume", volumeToAttach)
}
```

#### sync

```go
func (rc *reconciler) sync() {
    // 在方法结束时调用 updateSyncTime 方法更新同步时间。
    defer rc.updateSyncTime()
    // 调用 syncStates 方法进行状态同步。
    rc.syncStates()
}
```

##### updateSyncTime

```go
func (rc *reconciler) updateSyncTime() {
	rc.timeOfLastSync = time.Now()
}
```

##### syncStates

```go
func (rc *reconciler) syncStates() {
	volumesPerNode := rc.actualStateOfWorld.GetAttachedVolumesPerNode()
	rc.attacherDetacher.VerifyVolumesAreAttached(volumesPerNode, rc.actualStateOfWorld)
}
```

## DesiredStateOfWorldPopulator

```go
type DesiredStateOfWorldPopulator interface {
	Run(ctx context.Context)
}

type desiredStateOfWorldPopulator struct {
    loopSleepDuration time.Duration // 循环休眠时长
    podLister corelisters.PodLister // Pod 列表接口
    desiredStateOfWorld cache.DesiredStateOfWorld // 期望的世界状态缓存
    volumePluginMgr *volume.VolumePluginMgr // 卷插件管理器
    pvcLister corelisters.PersistentVolumeClaimLister // PVC 列表接口
    pvLister corelisters.PersistentVolumeLister // PV 列表接口
    listPodsRetryDuration time.Duration // 列举 Pod 的重试时长
    timeOfLastListPods time.Time // 上一次列举 Pod 的时间
    csiMigratedPluginManager csimigration.PluginManager // CSI 迁移插件管理器
    intreeToCSITranslator csimigration.InTreeToCSITranslator // InTree 到 CSI 的转换器
}

func NewDesiredStateOfWorldPopulator(
	loopSleepDuration time.Duration,
	listPodsRetryDuration time.Duration,
	podLister corelisters.PodLister,
	desiredStateOfWorld cache.DesiredStateOfWorld,
	volumePluginMgr *volume.VolumePluginMgr,
	pvcLister corelisters.PersistentVolumeClaimLister,
	pvLister corelisters.PersistentVolumeLister,
	csiMigratedPluginManager csimigration.PluginManager,
	intreeToCSITranslator csimigration.InTreeToCSITranslator) DesiredStateOfWorldPopulator {
	return &desiredStateOfWorldPopulator{
		loopSleepDuration:        loopSleepDuration,
		listPodsRetryDuration:    listPodsRetryDuration,
		podLister:                podLister,
		desiredStateOfWorld:      desiredStateOfWorld,
		volumePluginMgr:          volumePluginMgr,
		pvcLister:                pvcLister,
		pvLister:                 pvLister,
		csiMigratedPluginManager: csiMigratedPluginManager,
		intreeToCSITranslator:    intreeToCSITranslator,
	}
}
```

### Run

```go
func (dswp *desiredStateOfWorldPopulator) Run(ctx context.Context) {
	wait.UntilWithContext(ctx, dswp.populatorLoopFunc(ctx), dswp.loopSleepDuration)
}
```

#### populatorLoopFunc

```go
func (dswp *desiredStateOfWorldPopulator) populatorLoopFunc(ctx context.Context) func(ctx context.Context) {
    // 返回一个函数，该函数会使用上下文和记录器，定期检查和更新 pod 的状态。
    return func(ctx context.Context) {
        // 从上下文中获取日志记录器。
        logger := klog.FromContext(ctx)
        
        // 调用 dswp.findAndRemoveDeletedPods 函数，传入 logger 作为参数。
        // 该函数用于找到并移除已删除的 pod。
        dswp.findAndRemoveDeletedPods(logger)

        // 如果时间间隔小于 listPodsRetryDuration，就跳过 findAndAddActivePods 函数的执行。
        // 否则，记录相关信息，调用 dswp.findAndAddActivePods 函数，传入 logger 作为参数。
        if time.Since(dswp.timeOfLastListPods) < dswp.listPodsRetryDuration {
            logger.V(5).Info(
                "Skipping findAndAddActivePods(). Not permitted until the retry time is reached",
                "retryTime", dswp.timeOfLastListPods.Add(dswp.listPodsRetryDuration),
                "retryDuration", dswp.listPodsRetryDuration)

            return
        }
        dswp.findAndAddActivePods(logger)
    }
}
```

##### findAndRemoveDeletedPods

```go
func (dswp *desiredStateOfWorldPopulator) findAndRemoveDeletedPods(logger klog.Logger) {
	// 遍历待添加的 Pod，找到已经被删除的 Pod 并删除
	for dswPodUID, dswPodToAdd := range dswp.desiredStateOfWorld.GetPodToAdd() {
		// 生成 Pod 的 key
		dswPodKey, err := kcache.MetaNamespaceKeyFunc(dswPodToAdd.Pod)
		if err != nil {
			logger.Error(err, "MetaNamespaceKeyFunc failed for pod", "podName", dswPodKey, "podUID", dswPodUID)
			continue
		}

		// 根据 key 从 informer 中获取 Pod 对象
		namespace, name, err := kcache.SplitMetaNamespaceKey(dswPodKey)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("error splitting dswPodKey %q: %v", dswPodKey, err))
			continue
		}
		informerPod, err := dswp.podLister.Pods(namespace).Get(name)
		// 根据错误类型判断是否需要删除 Pod
		switch {
		case errors.IsNotFound(err):
			// if we can't find the pod, we need to delete it below
		case err != nil:
			logger.Error(err, "podLister Get failed for pod", "podName", dswPodKey, "podUID", dswPodUID)
			continue
		default:
			// 如果找到了 Pod，需要检查它是否有新的 Volume Attach/Detach 操作
			volumeActionFlag := util.DetermineVolumeAction(
				informerPod,
				dswp.desiredStateOfWorld,
				true /* default volume action */)
			// 如果该 Pod 需要 Volume 操作，检查 Pod 的 UID 是否与 dsw 中保存的 UID 相同
			if volumeActionFlag {
				informerPodUID := volutil.GetUniquePodName(informerPod)
				if informerPodUID == dswPodUID {
					logger.V(10).Info("Verified pod from dsw exists in pod informer", "podName", dswPodKey, "podUID", dswPodUID)
					continue
				}
			}
		}

		// 如果找不到该 Pod，或者该 Pod 的 UID 与 dsw 中保存的不同，则从 dsw 中删除该 Pod
		logger.V(1).Info("Removing pod from dsw because it does not exist in pod informer", "podName", dswPodKey, "podUID", dswPodUID)
		dswp.desiredStateOfWorld.DeletePod(dswPodUID, dswPodToAdd.VolumeName, dswPodToAdd.NodeName)
	}

	// 检查待添加的 Volume 是否可挂载，如果不可挂载，需要将使用该 Volume 的 Pod 从 dsw 中删除
	for _, volumeToAttach := range dswp.desiredStateOfWorld.GetVolumesToAttach() {
		// IsAttachableVolume() 将会检查 volume 的可挂载性，如果插件类型为 CSI，会从 CSIDriverLister 获取该插件的信息
		volumeAttachable := volutil.IsAttachableVolume(volumeToAttach.VolumeSpec, dswp.volumePluginMgr)
        // 卷不可挂载
		if !volumeAttachable {
			logger.Info("Volume changes from attachable to non-attachable", "volumeName", volumeToAttach.VolumeName)
            // 对于每个调度的 Pod
			for _, scheduledPod := range volumeToAttach.ScheduledPods {
                // 获取 Pod 的唯一标识符
				podUID := volutil.GetUniquePodName(scheduledPod)
                // 从期望状态中删除指定卷、指定节点的 Pod
				dswp.desiredStateOfWorld.DeletePod(podUID, volumeToAttach.VolumeName, volumeToAttach.NodeName)
				logger.V(4).Info("Removing podUID and volume on node from desired state of world"+
					" because of the change of volume attachability", "node", klog.KRef("", string(volumeToAttach.NodeName)), "podUID", podUID, "volumeName", volumeToAttach.VolumeName)
			}
		}
    }
}

```

##### findAndAddActivePods

```go
func (dswp *desiredStateOfWorldPopulator) findAndAddActivePods(logger klog.Logger) {
    // 获取所有的pod
	pods, err := dswp.podLister.List(labels.Everything())
	if err != nil {
		logger.Error(err, "PodLister List failed")
		return
	}
    // 更新dswp.timeOfLastListPods的值为当前时间。
	dswp.timeOfLastListPods = time.Now()

	for _, pod := range pods {
        // 遍历pod列表，如果Pod已经终止，则跳过此Pod，不为其添加卷
		if volutil.IsPodTerminated(pod, pod.Status) {
			// Do not add volumes for terminated pods
			continue
		}
        // 使用给定的参数处理Pod的卷，如果处理过程中出现错误，则记录日志
		util.ProcessPodVolumes(logger, pod, true,
			dswp.desiredStateOfWorld, dswp.volumePluginMgr, dswp.pvcLister, dswp.pvLister, dswp.csiMigratedPluginManager, dswp.intreeToCSITranslator)

	}

}
```

## Run

```go
func (adc *attachDetachController) Run(ctx context.Context) {
	defer runtime.HandleCrash() // 在函数退出时处理可能发生的崩溃
	defer adc.pvcQueue.ShutDown() // 在函数退出时关闭 pvcQueue

	// 启动事件处理管道
	adc.broadcaster.StartStructuredLogging(0)
	adc.broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: adc.kubeClient.CoreV1().Events("")})
	defer adc.broadcaster.Shutdown() // 在函数退出时关闭事件广播器

	logger := klog.FromContext(ctx) // 从上下文中获取 logger
	logger.Info("Starting attach detach controller") // 记录日志，表示开始运行附加和分离控制器
	defer logger.Info("Shutting down attach detach controller") // 在函数退出时记录日志，表示关闭附加和分离控制器

	// 创建 InformerSynced 列表，并添加到 synced 列表中
	synced := []kcache.InformerSynced{adc.podsSynced, adc.nodesSynced, adc.pvcsSynced, adc.pvsSynced}
	if adc.csiNodeSynced != nil {
		synced = append(synced, adc.csiNodeSynced)
	}
	if adc.csiDriversSynced != nil {
		synced = append(synced, adc.csiDriversSynced)
	}
	if adc.volumeAttachmentSynced != nil {
		synced = append(synced, adc.volumeAttachmentSynced)
	}

	// 等待 InformerSynced 列表同步完成
	if !kcache.WaitForNamedCacheSync("attach detach", ctx.Done(), synced...) {
		return
	}

	// 填充实际状态
	err := adc.populateActualStateOfWorld(logger)
	if err != nil {
		logger.Error(err, "Error populating the actual state of world")
	}

	// 填充期望状态
	err = adc.populateDesiredStateOfWorld(logger)
	if err != nil {
		logger.Error(err, "Error populating the desired state of world")
	}

	// 启动协调器、期望状态填充器和 pvcWorker
	go adc.reconciler.Run(ctx)
	go adc.desiredStateOfWorldPopulator.Run(ctx)
	go wait.UntilWithContext(ctx, adc.pvcWorker, time.Second)

	// 注册 metrics
	metrics.Register(adc.pvcLister,
		adc.pvLister,
		adc.podLister,
		adc.actualStateOfWorld,
		adc.desiredStateOfWorld,
		&adc.volumePluginMgr,
		adc.csiMigratedPluginManager,
		adc.intreeToCSITranslator)

	<-ctx.Done() // 等待 ctx 被取消，函数退出
}
```

### populateActualStateOfWorld

```GO
func (adc *attachDetachController) populateActualStateOfWorld(logger klog.Logger) error {
    logger.V(5).Info("Populating ActualStateOfworld") // 记录日志，表示正在填充 ActualStateOfWorld

    nodes, err := adc.nodeLister.List(labels.Everything()) // 获取所有节点信息
    if err != nil {
        return err
    }

    for _, node := range nodes { // 遍历每个节点
        nodeName := types.NodeName(node.Name)
        for _, attachedVolume := range node.Status.VolumesAttached { // 遍历每个节点的已附加卷信息
            uniqueName := attachedVolume.Name
            // 空的 VolumeSpec 只有在卷没有被任何 Pod 使用时才是安全的
            // 在这种情况下，卷应该在第一个协调周期内被分离，并且不需要 VolumeSpec 来分离卷
            // 如果卷被 Pod 使用，其规范会在 populateDesiredStateOfWorld 中更新 ActualStateOfWorld
            err = adc.actualStateOfWorld.MarkVolumeAsAttached(logger, uniqueName, nil /* VolumeSpec */, nodeName, attachedVolume.DevicePath) // 将卷标记为已附加到节点上
            if err != nil {
                logger.Error(err, "Failed to mark the volume as attached") // 记录错误日志，表示无法将卷标记为已附加
                continue
            }
            adc.processVolumesInUse(logger, nodeName, node.Status.VolumesInUse) // 处理正在使用的卷
            adc.addNodeToDswp(node, types.NodeName(node.Name)) // 将节点添加到 DesiredStateOfWorldPopulator 的节点缓存中
        }
    }
    err = adc.processVolumeAttachments(logger) // 处理卷附件
    if err != nil {
        logger.Error(err, "Failed to process volume attachments") // 记录错误日志，表示无法处理卷附件
    }
    return err
}
```

#### processVolumeAttachments

```GO
func (adc *attachDetachController) processVolumeAttachments(logger klog.Logger) error {
	vas, err := adc.volumeAttachmentLister.List(labels.Everything()) // 获取所有的 VolumeAttachment 对象列表
	if err != nil {
		logger.Error(err, "Failed to list VolumeAttachment objects") // 如果获取失败，记录错误日志并返回错误
		return err
	}
	for _, va := range vas { // 遍历 VolumeAttachment 对象列表
		nodeName := types.NodeName(va.Spec.NodeName) // 获取节点名称
		pvName := va.Spec.Source.PersistentVolumeName // 获取持久卷名称
		if pvName == nil { // 如果持久卷名称为空，生成警告日志并跳过当前循环
			logger.Info("Skipping the va as its pvName is nil", "node", klog.KRef("", string(nodeName)), "vaName", va.Name)
			continue
		}
		pv, err := adc.pvLister.Get(*pvName) // 根据持久卷名称获取持久卷对象
		if err != nil {
			logger.Error(err, "Unable to lookup pv object", "PV", klog.KRef("", *pvName)) // 如果获取持久卷对象失败，记录错误日志并跳过当前循环
			continue
		}

		var plugin volume.AttachableVolumePlugin // 声明可附加卷插件变量
		volumeSpec := volume.NewSpecFromPersistentVolume(pv, false) // 根据持久卷对象创建卷规格对象

		// 在查询 volumePluginMgr 中注册的插件之前，首先查询 csiMigratedPluginManager 中是否有对应的 in-tree 插件
		// 注册的 in-tree 插件在迁移到 CSI 后将不再注册，一旦相应的功能门已启用
		if inTreePluginName, err := adc.csiMigratedPluginManager.GetInTreePluginNameFromSpec(pv, nil); err == nil {
			if adc.csiMigratedPluginManager.IsMigrationEnabledForPlugin(inTreePluginName) {
				// 持久卷已迁移到 CSI 插件，应该由 CSI 插件处理而不是 in-tree 插件
				plugin, _ = adc.volumePluginMgr.FindAttachablePluginByName(csi.CSIPluginName) // 根据插件名称查找可附加卷插件
				// 对于 Azurefile，这里不需要 podNamespace，因为生成的 volumeName 将在有或没有 podNamespace 的情况下相同
				volumeSpec, err = csimigration.TranslateInTreeSpecToCSI(volumeSpec, "" /* podNamespace */, adc.intreeToCSITranslator) // 将 in-tree 的卷规格转换为 CSI 的卷规格
				if err != nil {
					logger.Error(err, "Failed to translate intree volumeSpec to CSI volumeSpec for volume", "node", klog.KRef("", string(nodeName)), "inTreePluginName", inTreePluginName, "vaName", va.Name, "PV", klog.KRef("", *pvName)) // 如果转换失败，记录错误日志并跳过当前循环
					continue
				}
			}
            
            attachState := adc.actualStateOfWorld.GetAttachState(volumeName, nodeName)
            if attachState == cache.AttachStateDetached {
                // 如果卷未附加，则将其标记为不确定状态，并将此信息记录到日志中。
                logger.V(1).Info("Marking volume attachment as uncertain as volume is not attached", "node", klog.KRef("", string(nodeName)), "volumeName", volumeName, "attachState", attachState)
                err = adc.actualStateOfWorld.MarkVolumeAsUncertain(logger, volumeName, volumeSpec, nodeName)
                if err != nil {
                    logger.Error(err, "MarkVolumeAsUncertain fail to add the volume to ASW", "node", klog.KRef("", string(nodeName)), "volumeName", volumeName)
                }
            }
		}
	return nil
}
```

### populateDesiredStateOfWorld

```GO
func (adc *attachDetachController) populateDesiredStateOfWorld(logger klog.Logger) error {
	logger.V(5).Info("Populating DesiredStateOfworld") // 记录日志，输出 "Populating DesiredStateOfworld"，日志级别为 5

	pods, err := adc.podLister.List(labels.Everything()) // 获取所有的 Pod 列表
	if err != nil {
		return err // 如果获取 Pod 列表失败，返回错误
	}
	for _, pod := range pods { // 遍历 Pod 列表
		podToAdd := pod // 将当前 Pod 赋值给 podToAdd
		adc.podAdd(logger, podToAdd) // 调用 adc 的 podAdd 方法，传入日志和 podToAdd
		for _, podVolume := range podToAdd.Spec.Volumes { // 遍历 podToAdd 的 Volumes
			nodeName := types.NodeName(podToAdd.Spec.NodeName) // 获取 podToAdd 的节点名称
			// 在 ActualStateOfWorld 中的 volume specs 为 nil，将其替换为从 pod 中找到的正确的 specs。
			// 在 ActualStateOfWorld 中没有对应的 pod 的 volume specs 将被分离，并且 specs 是无关紧要的。
			volumeSpec, err := util.CreateVolumeSpec(logger, podVolume, podToAdd, nodeName, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister, adc.csiMigratedPluginManager, adc.intreeToCSITranslator)
			if err != nil { // 如果创建 volume specs 失败，记录错误日志并继续下一次循环
				logger.Error(
					err,
					"Error creating spec for volume of pod",
					"pod", klog.KObj(podToAdd),
					"volumeName", podVolume.Name)
				continue
			}
			plugin, err := adc.volumePluginMgr.FindAttachablePluginBySpec(volumeSpec) // 根据 volume specs 查找可附加的插件
			if err != nil || plugin == nil { // 如果查找插件失败或者插件为 nil，记录日志并继续下一次循环
				logger.V(10).Info(
					"Skipping volume for pod: it does not implement attacher interface",
					"pod", klog.KObj(podToAdd),
					"volumeName", podVolume.Name,
					"err", err)
				continue
			}
			volumeName, err := volumeutil.GetUniqueVolumeNameFromSpec(plugin, volumeSpec) // 根据插件和 volume specs 获取唯一的 volume 名称
			if err != nil { // 如果获取唯一的 volume 名称失败，记录错误日志并继续下一次循环
				logger.Error(
					err,
					"Failed to find unique name for volume of pod",
					"pod", klog.KObj(podToAdd),
					"volumeName", podVolume.Name)
				continue
			}
			attachState := adc.actualStateOfWorld.GetAttachState(volumeName, nodeName) // 获取 volume 在节点上的附加状态
			if attachState == cache.AttachStateAttached { // 如果 volume 已经附加到节点上
				logger.V(10).Info("Volume is attached to node. Marking as attached in ActualStateOfWorld",
					"node", klog.KRef("", string(nodeName)),
					"volumeName", volumeName)
                // 调用 getNodeVolumeDevicePath 函数来获取节点的设备路径，如果出错，则将错误信息记录到日志中，并继续下一次循环。
				devicePath, err := adc.getNodeVolumeDevicePath(volumeName, nodeName)
				if err != nil {
					logger.Error(err, "Failed to find device path")
					continue
				}
                // 调用 actualStateOfWorld.MarkVolumeAsAttached 函数，将卷标记为已附加，并将其更新到实际世界的状态中。
				err = adc.actualStateOfWorld.MarkVolumeAsAttached(logger, volumeName, volumeSpec, nodeName, devicePath)
				if err != nil {
					logger.Error(err, "Failed to update volume spec for node", "node", klog.KRef("", string(nodeName)))
				}
			}
        }
	}

	return nil
}
```

#### getNodeVolumeDevicePath

```GO
func (adc *attachDetachController) getNodeVolumeDevicePath(
	volumeName v1.UniqueVolumeName, nodeName types.NodeName) (string, error) {
	var devicePath string
	var found bool
	node, err := adc.nodeLister.Get(string(nodeName)) // 通过nodeName从nodeLister获取节点对象
	if err != nil {
		return devicePath, err
	}
	for _, attachedVolume := range node.Status.VolumesAttached { // 遍历节点上已经挂载的卷
		if volumeName == attachedVolume.Name { // 如果找到了目标卷
			devicePath = attachedVolume.DevicePath // 获取卷的设备路径
			found = true
			break
		}
	}
	if !found { // 如果没有找到目标卷，则返回错误
		err = fmt.Errorf("Volume %s not found on node %s", volumeName, nodeName)
	}

	return devicePath, err
}
```

## pvcWorker

```GO
func (adc *attachDetachController) pvcWorker(ctx context.Context) {
	for adc.processNextItem(klog.FromContext(ctx)) {
	}
}

func (adc *attachDetachController) processNextItem(logger klog.Logger) bool {
	keyObj, shutdown := adc.pvcQueue.Get()
	if shutdown {
		return false
	}
	defer adc.pvcQueue.Done(keyObj)
	
    // 同步 
	if err := adc.syncPVCByKey(logger, keyObj.(string)); err != nil {
		// Rather than wait for a full resync, re-add the key to the
		// queue to be processed.
		adc.pvcQueue.AddRateLimited(keyObj)
		runtime.HandleError(fmt.Errorf("Failed to sync pvc %q, will retry again: %v", keyObj.(string), err))
		return true
	}

	// Finally, if no error occurs we Forget this item so it does not
	// get queued again until another change happens.
	adc.pvcQueue.Forget(keyObj)
	return true
}
```

### syncPVCByKey

```GO
func (adc *attachDetachController) syncPVCByKey(logger klog.Logger, key string) error {
	logger.V(5).Info("syncPVCByKey", "pvcKey", key) // 打印日志，记录 key 值
	namespace, name, err := kcache.SplitMetaNamespaceKey(key) // 从 key 中解析出 namespace 和 name
	if err != nil {
		logger.V(4).Info("Error getting namespace & name of pvc to get pvc from informer", "pvcKey", key, "err", err) // 打印解析错误日志并返回 nil
		return nil
	}
	pvc, err := adc.pvcLister.PersistentVolumeClaims(namespace).Get(name) // 从 pvcLister 获取 PersistentVolumeClaim 对象
	if apierrors.IsNotFound(err) { // 如果获取的错误是 "Not Found" 错误，则打印日志并返回 nil
		logger.V(4).Info("Error getting pvc from informer", "pvcKey", key, "err", err)
		return nil
	}
	if err != nil { // 如果获取的错误不是 "Not Found" 错误，则返回错误
		return err
	}

	if pvc.Status.Phase != v1.ClaimBound || pvc.Spec.VolumeName == "" {
		// 跳过未绑定的 PVC
		return nil
	}

	objs, err := adc.podIndexer.ByIndex(common.PodPVCIndex, key) // 通过 podIndexer 根据 key 获取 pod 列表
	if err != nil {
		return err
	}
	for _, obj := range objs { // 遍历 pod 列表
		pod, ok := obj.(*v1.Pod) // 将对象转换为 Pod 对象
		if !ok {
			continue
		}
		// 我们只关心 nodeName 已设置且处于活动状态的 Pod
		if len(pod.Spec.NodeName) == 0 || volumeutil.IsPodTerminated(pod, pod.Status) {
			continue
		}
		volumeActionFlag := util.DetermineVolumeAction(
			pod,
			adc.desiredStateOfWorld,
			true /* default volume action */) // 根据 Pod、desiredStateOfWorld 和默认的 volume action 确定 volume action 标志位

		util.ProcessPodVolumes(logger, pod, volumeActionFlag, /* addVolumes */
			adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister, adc.csiMigratedPluginManager, adc.intreeToCSITranslator) // 处理 Pod 的卷，包括添加卷、更新卷和删除卷的操作
	}
	return nil
}
```

#### DetermineVolumeAction

```go
func DetermineVolumeAction(pod *v1.Pod, desiredStateOfWorld cache.DesiredStateOfWorld, defaultAction bool) bool {
	// 如果 Pod 为空或者没有定义任何卷，返回默认操作。
	if pod == nil || len(pod.Spec.Volumes) <= 0 {
		return defaultAction
	}

	// 如果 Pod 处于终止状态，获取 Pod 所在节点的 DesiredStateOfWorld 中的 keepTerminatedPodVolume 设置。
	if util.IsPodTerminated(pod, pod.Status) {
		nodeName := types.NodeName(pod.Spec.NodeName)
		keepTerminatedPodVolume := desiredStateOfWorld.GetKeepTerminatedPodVolumesForNode(nodeName)
		// 如果 Pod 处于终止状态，根据 kubelet 策略判断是否应该执行卷的卸载操作。
		return keepTerminatedPodVolume
	}

	// 如果 Pod 不处于终止状态，返回默认操作。
	return defaultAction
}
```

