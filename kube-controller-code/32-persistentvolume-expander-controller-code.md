
## 简介

persistentvolume-expander-controller是一个控制器，它监视PersistentVolumeClaim并自动调整PersistentVolume的大小。当PersistentVolumeClaim的大小超过了它所绑定的PersistentVolume的大小时，该控制器会自动调整PersistentVolume的大小以满足PersistentVolumeClaim的需求。

## 结构体

```GO
type expandController struct {
	// clientset
	kubeClient clientset.Interface

	// pvc对象lister
	pvcLister  corelisters.PersistentVolumeClaimLister
	pvcsSynced cache.InformerSynced
	
    // pv对象lister
	pvLister corelisters.PersistentVolumeLister
	pvSynced cache.InformerSynced

	//  云提供程序，由volume host使用
	cloud cloudprovider.Interface

	// 用于初始化和获取volume插件的VolumePluginMgr
	volumePluginMgr volume.VolumePluginMgr

	// 记录器
	recorder record.EventRecorder
	// 用于生成操作的OperationGenerators
	operationGenerator operationexecutor.OperationGenerator
	// 工作队列。
	queue workqueue.RateLimitingInterface
	// CSI名称转换器
	translator CSINameTranslator
	// CSI迁移插件管理器
	csiMigratedPluginManager csimigration.PluginManager
	// 用于建立连接的选项
	filteredDialOptions *proxyutil.FilteredDialOptions
}
```

## New

```go
func NewExpandController(
	// 传入的 Kubernetes 客户端对象
	kubeClient clientset.Interface,
	// PersistentVolumeClaimInformer 用于监视 PVC 的变化
	pvcInformer coreinformers.PersistentVolumeClaimInformer,
	// PersistentVolumeInformer 用于监视 PV 的变化
	pvInformer coreinformers.PersistentVolumeInformer,
	// 云提供商接口
	cloud cloudprovider.Interface,
	// 所有的卷插件
	plugins []volume.VolumePlugin,
	// CSI 插件名称翻译器
	translator CSINameTranslator,
	// CSI 插件管理器
	csiMigratedPluginManager csimigration.PluginManager,
	// 代理工具的过滤选项
	filteredDialOptions *proxyutil.FilteredDialOptions,
) (ExpandController, error) {

	// 创建 expandController 对象
	expc := &expandController{
		kubeClient:               kubeClient, // Kubernetes 客户端对象
		cloud:                    cloud, // 云提供商接口
		pvcLister:                pvcInformer.Lister(), // PVC 列表对象
		pvcsSynced:               pvcInformer.Informer().HasSynced, // PVC 同步状态对象
		pvLister:                 pvInformer.Lister(), // PV 列表对象
		pvSynced:                 pvInformer.Informer().HasSynced, // PV 同步状态对象
		queue:                    workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "volume_expand"), // 工作队列
		translator:               translator, // CSI 插件名称翻译器
		csiMigratedPluginManager: csiMigratedPluginManager, // CSI 插件管理器
		filteredDialOptions:      filteredDialOptions, // 代理工具的过滤选项
	}

	// 初始化卷插件
	if err := expc.volumePluginMgr.InitPlugins(plugins, nil, expc); err != nil {
		return nil, fmt.Errorf("could not initialize volume plugins for Expand Controller : %+v", err)
	}

	// 创建事件广播器
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	// 创建事件记录器
	expc.recorder = eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "volume_expand"})
	// 创建块设备路径处理器
	blkutil := volumepathhandler.NewBlockVolumePathHandler()

	// 创建操作生成器
	expc.operationGenerator = operationexecutor.NewOperationGenerator(
		kubeClient, // Kubernetes 客户端对象
		&expc.volumePluginMgr, // 卷插件管理器
		expc.recorder, // 事件记录器
		blkutil, // 块设备路径处理器
	)

	// PVC 变化事件处理函数
	pvcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: expc.enqueuePVC,
		UpdateFunc: func(old, new interface{}) {
			oldPVC, ok := old.(*v1.PersistentVolumeClaim)
			if !ok {
				return
			}
			// 获取旧的 PVC 请求容量和状态容量，新的 PVC 请求容量和状态容量
			oldReq := oldPVC.Spec.Resources.Requests[v1.ResourceStorage]
			oldCap := oldPVC.Status.Capacity[v1.ResourceStorage]
			newPVC, ok := new.(*v1.PersistentVolumeClaim)
			if !ok {
				return
			}
			newReq := newPVC.Spec.Resources.Requests[v1.ResourceStorage]
			newCap := newPVC.Status.Capacity[v1.ResourceStorage]
			// PVC会在以下两种情况下进入队列：
            // 1. 用户增加了PVC的请求容量-->需要扩展卷容量
            // 2. PVC状态容量已扩展-->该声明绑定的PV可能最近经历了文件系统调整大小，因此从PV中删除AnnPreResizeCapacity注释
			if newReq.Cmp(oldReq) > 0 || newCap.Cmp(oldCap) > 0 {
				expc.enqueuePVC(new)
			}
		},
		DeleteFunc: expc.enqueuePVC,
	})

	return expc, nil
}
```

### enqueuePVC

```GO
func (expc *expandController) enqueuePVC(obj interface{}) {
    // 将 obj 转换为 PersistentVolumeClaim 类型的指针，并检查是否转换成功
    pvc, ok := obj.(*v1.PersistentVolumeClaim)
    if !ok {
    	return
    }
	// 如果 PersistentVolumeClaim 的状态为 ClaimBound（已绑定），则将其添加到队列中
    if pvc.Status.Phase == v1.ClaimBound {
        // 使用缓存工具函数生成 key
        key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pvc)
        if err != nil {
            // 如果出现错误，则打印日志，并返回
            runtime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", pvc, err))
            return
        }
        // 将 key 添加到队列中
        expc.queue.Add(key)
    }
}
```

## Run

```go
func (expc *expandController) Run(ctx context.Context) {
	defer runtime.HandleCrash()
	defer expc.queue.ShutDown()
	logger := klog.FromContext(ctx)
	logger.Info("Starting expand controller")
	defer logger.Info("Shutting down expand controller")

	if !cache.WaitForNamedCacheSync("expand", ctx.Done(), expc.pvcsSynced, expc.pvSynced) {
		return
	}

	for i := 0; i < defaultWorkerCount; i++ {
		go wait.UntilWithContext(ctx, expc.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

## runWorker

```go
func (expc *expandController) runWorker(ctx context.Context) {
	for expc.processNextWorkItem(ctx) {
	}
}

func (expc *expandController) processNextWorkItem(ctx context.Context) bool {
	key, shutdown := expc.queue.Get()
	if shutdown {
		return false
	}
	defer expc.queue.Done(key)
	// 执行syncHandler
	err := expc.syncHandler(ctx, key.(string))
	if err == nil {
		expc.queue.Forget(key)
		return true
	}

	runtime.HandleError(fmt.Errorf("%v failed with : %v", key, err))
	expc.queue.AddRateLimited(key)

	return true
}
```

## syncHandler

```GO
func (expc *expandController) syncHandler(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key) // 解析命名空间和名称
	if err != nil {
		return err // 如果解析失败，返回错误
	}
	pvc, err := expc.pvcLister.PersistentVolumeClaims(namespace).Get(name) // 通过命名空间和名称获取 PersistentVolumeClaim（PVC）对象
	if errors.IsNotFound(err) { // 如果 PVC 不存在，则返回 nil，表示无需处理
		return nil
	}
	logger := klog.FromContext(ctx) // 从上下文中获取 logger
	if err != nil {
		logger.V(5).Info("Error getting PVC from informer", "pvcKey", key, "err", err) // 记录获取 PVC 对象错误的日志信息
		return err // 返回错误
	}

	pv, err := expc.getPersistentVolume(ctx, pvc) // 获取关联的 PersistentVolume（PV）对象
	if err != nil {
		logger.V(5).Info("Error getting Persistent Volume for PVC from informer", "pvcKey", key, "pvcUID", pvc.UID, "err", err) // 记录获取 PV 对象错误的日志信息
		return err // 返回错误
	}

	if pv.Spec.ClaimRef == nil || pvc.Namespace != pv.Spec.ClaimRef.Namespace || pvc.UID != pv.Spec.ClaimRef.UID {
		err := fmt.Errorf("persistent Volume is not bound to PVC being updated : %s", key) // 如果 PV 和 PVC 的绑定关系不匹配，则返回错误
		logger.V(4).Info("", "err", err) // 记录 PV 和 PVC 绑定关系不匹配的日志信息
		return err // 返回错误
	}

	pvcRequestSize := pvc.Spec.Resources.Requests[v1.ResourceStorage] // 获取 PVC 的请求存储大小
	pvcStatusSize := pvc.Status.Capacity[v1.ResourceStorage] // 获取 PVC 当前的存储容量

	// 只有在以下两种情况下调用扩容操作：
	// 1. PVC 的请求存储大小已经扩容且大于当前存储容量
	// 2. PV 具有预调整容量注释
	if pvcRequestSize.Cmp(pvcStatusSize) <= 0 && !metav1.HasAnnotation(pv.ObjectMeta, util.AnnPreResizeCapacity) {
		return nil // 如果不满足以上两种情况，则无需处理，返回 nil
	}

	volumeSpec := volume.NewSpecFromPersistentVolume(pv, false) // 根据 PV 创建卷规格对象
	migratable, err := expc.csiMigratedPluginManager.IsMigratable(volumeSpec) // 检查 PV 是否支持 CSI 迁移
	if err != nil {
		logger.V(4).Info("Failed to check CSI migration status for PVC with error", "pvcKey", key, "err", err) // 记录检查 CSI 迁移状态错误的日志信息
		return nil // 返回 nil
	}

	// 在调用 FindExpandablePluginBySpec 之前处理 CSI 迁移的情况
	if migratable {
        // 从持久卷和卷规格中获取内部插件（in-tree plugin）的名称，并保存在变量 inTreePluginName 中
		inTreePluginName, err := expc.csiMigratedPluginManager.GetInTreePluginNameFromSpec(volumeSpec.PersistentVolume, volumeSpec.Volume)
		if err != nil {
			logger.V(4).Info("Error getting in-tree plugin name from persistent volume", "volumeName", volumeSpec.PersistentVolume.Name, "err", err)
			return err
		}
		// 生成一个消息字符串，表示 CSI 迁移已启用，并等待外部调整大小器（resizer）扩展 PVC（Persistent Volume Claim）。然后，根据内部插件的名称获取对应的 CSI 驱动名称，并保存在变量 csiResizerName 中
		msg := fmt.Sprintf("CSI migration enabled for %s; waiting for external resizer to expand the pvc", inTreePluginName)
		expc.recorder.Event(pvc, v1.EventTypeNormal, events.ExternalExpanding, msg)
		csiResizerName, err := expc.translator.GetCSINameFromInTreeName(inTreePluginName)
		if err != nil {
			errorMsg := fmt.Sprintf("error getting CSI driver name for pvc %s, with error %v", key, err)
			expc.recorder.Event(pvc, v1.EventTypeWarning, events.ExternalExpanding, errorMsg)
			return fmt.Errorf(errorMsg)
		}
		// 调用 util 包中的 SetClaimResizer 函数，将获取到的 CSI 驱动名称设置为 PVC 的调整大小器（resizer）注解，并保存更新后的 PVC
		pvc, err := util.SetClaimResizer(pvc, csiResizerName, expc.kubeClient)
		if err != nil {
			errorMsg := fmt.Sprintf("error setting resizer annotation to pvc %s, with error %v", key, err)
			expc.recorder.Event(pvc, v1.EventTypeWarning, events.ExternalExpanding, errorMsg)
			return fmt.Errorf(errorMsg)
		}
		return nil
	}
	
    // 获取一个可扩展的插件对象
	volumePlugin, err := expc.volumePluginMgr.FindExpandablePluginBySpec(volumeSpec)
	if err != nil || volumePlugin == nil {
		msg := "waiting for an external controller to expand this PVC"
		eventType := v1.EventTypeNormal
		if err != nil {
			eventType = v1.EventTypeWarning
		}
		expc.recorder.Event(pvc, eventType, events.ExternalExpanding, msg)
		logger.Info("Waiting for an external controller to expand the PVC", "pvcKey", key, "pvcUID", pvc.UID)
		// If we are expecting that an external plugin will handle resizing this volume then
		// is no point in requeuing this PVC.
		return nil
	}

	volumeResizerName := volumePlugin.GetPluginName()
	return expc.expand(logger, pvc, pv, volumeResizerName)
}
```

### getPersistentVolume

```GO
func (expc *expandController) getPersistentVolume(ctx context.Context, pvc *v1.PersistentVolumeClaim) (*v1.PersistentVolume, error) {
	volumeName := pvc.Spec.VolumeName
	pv, err := expc.kubeClient.CoreV1().PersistentVolumes().Get(ctx, volumeName, metav1.GetOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to get PV %q: %v", volumeName, err)
	}

	return pv.DeepCopy(), nil
}
```

### expand

```GO
func (expc *expandController) expand(logger klog.Logger, pvc *v1.PersistentVolumeClaim, pv *v1.PersistentVolume, resizerName string) error {
    // 如果节点扩展已完成并且 pv 的注释可以被移除，则从 pv 中移除注释并返回
    if expc.isNodeExpandComplete(logger, pvc, pv) && metav1.HasAnnotation(pv.ObjectMeta, util.AnnPreResizeCapacity) {
    	return util.DeleteAnnPreResizeCapacity(pv, expc.GetKubeClient())
	}
    var generatedOptions volumetypes.GeneratedOperations
    var err error
    if utilfeature.DefaultFeatureGate.Enabled(features.RecoverVolumeExpansionFailure) {
        // 如果启用了 RecoverVolumeExpansionFailure 特性，生成 ExpandVolume 和 RecoverVolume 操作
        generatedOptions, err = expc.operationGenerator.GenerateExpandAndRecoverVolumeFunc(pvc, pv, resizerName)
        if err != nil {
            logger.Error(err, "Error starting ExpandVolume for pvc", "PVC", klog.KObj(pvc))
            return err
        }
    } else {
        // 如果未启用 RecoverVolumeExpansionFailure 特性，将 PVC 标记为正在进行扩展中，并生成 ExpandVolume 操作
        pvc, err := util.MarkResizeInProgressWithResizer(pvc, resizerName, expc.kubeClient)
        if err != nil {
            logger.Error(err, "Error setting PVC in progress with error", "PVC", klog.KObj(pvc), "err", err)
            return err
        }

        generatedOptions, err = expc.operationGenerator.GenerateExpandVolumeFunc(pvc, pv)
        if err != nil {
            logger.Error(err, "Error starting ExpandVolume for pvc with error", "PVC", klog.KObj(pvc), "err", err)
            return err
        }
    }

    logger.V(5).Info("Starting ExpandVolume for volume", "volumeName", util.GetPersistentVolumeClaimQualifiedName(pvc))
    _, detailedErr := generatedOptions.Run()

    return detailedErr
}
```

#### isNodeExpandComplete

```GO
func (expc *expandController) isNodeExpandComplete(logger klog.Logger, pvc *v1.PersistentVolumeClaim, pv *v1.PersistentVolume) bool {
    // 记录 PV 和 PVC 的容量信息
    logger.V(4).Info("pv and pvc capacity", "PV", klog.KObj(pv), "pvCapacity", pv.Spec.Capacity[v1.ResourceStorage], "PVC", klog.KObj(pvc), "pvcCapacity", pvc.Status.Capacity[v1.ResourceStorage])
    pvcSpecCap := pvc.Spec.Resources.Requests.Storage()  // 获取 PVC 规格中的容量信息
    pvcStatusCap, pvCap := pvc.Status.Capacity[v1.ResourceStorage], pv.Spec.Capacity[v1.ResourceStorage]  // 获取 PVC 和 PV 的容量信息

    // 由于允许缩小卷的容量，因此需要将 PVC 的状态容量和规格容量与 PV 的规格容量进行比较
    if pvcStatusCap.Cmp(*pvcSpecCap) >= 0 && pvcStatusCap.Cmp(pvCap) >= 0 {
        return true  // 如果 PVC 的状态容量和规格容量都大于等于 PV 的规格容量，则认为节点扩展已完成
    }
    return false  // 否则认为节点扩展未完成
}
```

