---
id: 31-kube-controller-code
title: ephemeral-volume-controller 代码走读
description: ephemeral-volume-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

k8s的ephemeral-volume-controller是一个控制器，它确保Kubernetes垃圾回收器在Pod退出时删除PersistentVolumeClaim。该控制器还负责提供与PVC对象关联的标签、注释和其他字段。PersistentVolumeClaims的标签和名称是确定性的，这使得搜索更容易。

## 结构体

```go
type ephemeralController struct {
	// clientset
	kubeClient clientset.Interface

	//pvc对象lister
	pvcLister  corelisters.PersistentVolumeClaimLister
	pvcsSynced cache.InformerSynced

	// pod对象lister
	podLister corelisters.PodLister
	podSynced cache.InformerSynced

	// pod对象Indexer缓存
	podIndexer cache.Indexer

	// 记录器
	recorder record.EventRecorder
	// 工作队列
	queue workqueue.RateLimitingInterface
}
```

## New

```GO
func NewController(
	kubeClient clientset.Interface,
	podInformer coreinformers.PodInformer,
	pvcInformer coreinformers.PersistentVolumeClaimInformer) (Controller, error) {

	ec := &ephemeralController{
		kubeClient: kubeClient,
		podLister:  podInformer.Lister(),
		podIndexer: podInformer.Informer().GetIndexer(),
		podSynced:  podInformer.Informer().HasSynced,
		pvcLister:  pvcInformer.Lister(),
		pvcsSynced: pvcInformer.Informer().HasSynced,
		queue:      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ephemeral_volume"),
	}
	
    // 开启Metrics
	ephemeralvolumemetrics.RegisterMetrics()
	
    // 开启记录器
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	ec.recorder = eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "ephemeral_volume"})
	
    // 监控pod的添加事件
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: ec.enqueuePod,
		// Pod规范是不可变的。因此，控制器可以忽略Pod的更新，因为不会有任何更改需要复制到生成的PVC中。
		// PVC的删除通过所有者引用和垃圾回收来处理。因此，Pod的删除也可以被忽略
	})
    // 监控pvc的删除时间
	pvcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: ec.onPVCDelete,
	})
    // 初始化pvc保护控制器时，向pod索引器(ec.podIndexer)添加索引器
	if err := common.AddPodPVCIndexerIfNotPresent(ec.podIndexer); err != nil {
		return nil, fmt.Errorf("could not initialize pvc protection controller: %w", err)
	}

	return ec, nil
}
```

### enqueuePod

```GO
func (ec *ephemeralController) enqueuePod(obj interface{}) {
    // 将传入的接口类型转换为v1.Pod类型，并判断转换是否成功。
    pod, ok := obj.(*v1.Pod)
    if !ok {
    	return
    }
    // 如果Pod的DeletionTimestamp不为空，说明Pod正在删除过程中，直接返回。
    if pod.DeletionTimestamp != nil {
        return
    }

    // 遍历Pod的Spec中的所有Volume，如果有Ephemeral字段，则将该Pod加入到队列中。
    for _, vol := range pod.Spec.Volumes {
        if vol.Ephemeral != nil {
            // 创建该Pod的DeletionHandlingMetaNamespaceKey，并将该Pod加入到队列中。
            key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(pod)
            if err != nil {
                // 如果获取key出错，打印错误信息。
                runtime.HandleError(fmt.Errorf("couldn't get key for object %#v: %v", pod, err))
                return
            }
            ec.queue.Add(key)
            // 因为只要有一个Volume是Ephemeral类型就可以加入队列了，所以找到第一个之后就退出循环。
            break
        }
    }
}
```

### onPVCDelete

```GO
func (ec *ephemeralController) onPVCDelete(obj interface{}) {
    // 将 obj 转换为 v1.PersistentVolumeClaim 类型的指针，如果类型不匹配则 ok 为 false，直接返回
    pvc, ok := obj.(*v1.PersistentVolumeClaim)
    if !ok {
        return
    }

    // 当有人删除一个 PVC 时，无论是有意还是无意，如果有 Pod 因为使用了该 PVC 的临时卷而被引用，我们就应该重新创建 PVC。
    // 通过 common.PodPVCIndex 对已经索引的 Pod 进行预过滤，只返回那些引用了该 PVC 的 Pod
    objs, err := ec.podIndexer.ByIndex(common.PodPVCIndex, fmt.Sprintf("%s/%s", pvc.Namespace, pvc.Name))
    if err != nil {
        // 如果发生错误，记录错误日志并返回
        runtime.HandleError(fmt.Errorf("listing pods from cache: %v", err))
        return
    }

    // 遍历引用了该 PVC 的 Pod，并将其加入到队列中
    for _, obj := range objs {
        ec.enqueuePod(obj)
    }
}
```

### AddPodPVCIndexerIfNotPresent

```GO
func AddPodPVCIndexerIfNotPresent(indexer cache.Indexer) error {
	return AddIndexerIfNotPresent(indexer, PodPVCIndex, PodPVCIndexFunc())
}

const (
	// PodPVCIndex is the lookup name for the index function, which is to index by pod pvcs.
	PodPVCIndex = "pod-pvc-index"
)
```

#### AddIndexerIfNotPresent

```GO
func AddIndexerIfNotPresent(indexer cache.Indexer, indexName string, indexFunc cache.IndexFunc) error {
	// 获取 indexer 中已经存在的索引
	indexers := indexer.GetIndexers()
	// 如果索引已经存在，直接返回 nil
	if _, ok := indexers[indexName]; ok {
		return nil
	}
	// 如果索引不存在，添加索引，并返回可能出现的错误
	return indexer.AddIndexers(cache.Indexers{indexName: indexFunc})
}
```

#### PodPVCIndexFunc

```GO
func PodPVCIndexFunc() func(obj interface{}) ([]string, error) {
	// 返回一个匿名函数，该函数接受一个 interface{} 类型的参数，返回一个 []string 类型的切片和一个 error
	return func(obj interface{}) ([]string, error) {
		// 将 obj 转换为 v1.Pod 类型的指针，如果类型不匹配则 ok 为 false，返回空切片和 nil
		pod, ok := obj.(*v1.Pod)
		if !ok {
			return []string{}, nil
		}

		// 存储该 Pod 所引用的 PVC 的 key 值
		keys := []string{}

		// 遍历 Pod 的 Volume，查找引用的 PVC，并获取 PVC 的名称
		for _, podVolume := range pod.Spec.Volumes {
			claimName := ""
			if pvcSource := podVolume.VolumeSource.PersistentVolumeClaim; pvcSource != nil {
				claimName = pvcSource.ClaimName
			} else if podVolume.VolumeSource.Ephemeral != nil {
				claimName = ephemeral.VolumeClaimName(pod, &podVolume)
			}
			// 如果找到 PVC 的名称，则将该 PVC 的 key 值添加到 keys 中
			if claimName != "" {
				keys = append(keys, fmt.Sprintf("%s/%s", pod.Namespace, claimName))
			}
		}
		// 返回 keys 和 nil
		return keys, nil
	}
}
```

## Run

```go
func (ec *ephemeralController) Run(ctx context.Context, workers int) {
	defer runtime.HandleCrash()
	defer ec.queue.ShutDown()
	logger := klog.FromContext(ctx)
	logger.Info("Starting ephemeral volume controller")
	defer logger.Info("Shutting down ephemeral volume controller")

	if !cache.WaitForNamedCacheSync("ephemeral", ctx.Done(), ec.podSynced, ec.pvcsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, ec.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

## runWorker

```go
func (ec *ephemeralController) runWorker(ctx context.Context) {
	for ec.processNextWorkItem(ctx) {
	}
}

func (ec *ephemeralController) processNextWorkItem(ctx context.Context) bool {
	key, shutdown := ec.queue.Get()
	if shutdown {
		return false
	}
	defer ec.queue.Done(key)
	
    // 执行同步删除 成功forget queue 失败加入queue重试
	err := ec.syncHandler(ctx, key.(string))
	if err == nil {
		ec.queue.Forget(key)
		return true
	}

	runtime.HandleError(fmt.Errorf("%v failed with: %v", key, err))
	ec.queue.AddRateLimited(key)

	return true
}
```

## syncHandler

```GO
func (ec *ephemeralController) syncHandler(ctx context.Context, key string) error {
	// 解析出 key 中的 namespace 和 name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	// 根据 namespace 和 name 获取 Pod 对象
	pod, err := ec.podLister.Pods(namespace).Get(name)

	// 获取 logger
	logger := klog.FromContext(ctx)

	if err != nil {
		if errors.IsNotFound(err) {
			logger.V(5).Info("Ephemeral: nothing to do for pod, it is gone", "podKey", key)
			return nil
		}
		logger.V(5).Info("Error getting pod from informer", "pod", klog.KObj(pod), "podUID", pod.UID, "err", err)
		return err
	}

	// 如果 Pod 被标记为删除，则忽略该 Pod
	if pod.DeletionTimestamp != nil {
		logger.V(5).Info("Ephemeral: nothing to do for pod, it is marked for deletion", "podKey", key)
		return nil
	}

	// 遍历 Pod 的 Volume，处理每个 Volume
	for _, vol := range pod.Spec.Volumes {
		if err := ec.handleVolume(ctx, pod, vol); err != nil {
			// 记录事件并返回错误
			ec.recorder.Event(pod, v1.EventTypeWarning, events.FailedBinding, fmt.Sprintf("ephemeral volume %s: %v", vol.Name, err))
			return fmt.Errorf("pod %s, ephemeral volume %s: %v", key, vol.Name, err)
		}
	}

	// 返回 nil
	return nil
}
```

#### handleVolume

```GO
func (ec *ephemeralController) handleVolume(ctx context.Context, pod *v1.Pod, vol v1.Volume) error {
	logger := klog.FromContext(ctx)

	// 输出调试信息：正在检查卷
	logger.V(5).Info("Ephemeral: checking volume", "volumeName", vol.Name)

	// 如果这个卷不是临时卷，则不做任何事情
	if vol.Ephemeral == nil {
		return nil
	}

	// 生成 PVC 名称
	pvcName := ephemeral.VolumeClaimName(pod, &vol)

	// 获取 PVC 对象
	pvc, err := ec.pvcLister.PersistentVolumeClaims(pod.Namespace).Get(pvcName)

	// 如果发生错误但这个错误不是“未找到”，则直接返回错误
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	// 如果找到了 PVC 对象，则判断它是否为该 Pod 创建的
	if pvc != nil {
		if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {
			return err
		}

		// 如果已经创建了 PVC，则输出调试信息并返回
		logger.V(5).Info("Ephemeral: PVC already created", "volumeName", vol.Name, "PVC", klog.KObj(pvc))
		return nil
	}

	// 如果没有找到 PVC，则需要创建它

	// 创建新的 PVC 对象，其 owner 引用为当前 Pod，并使用卷的模板参数
	isTrue := true
	pvc = &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: pvcName,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               pod.Name,
					UID:                pod.UID,
					Controller:         &isTrue,
					BlockOwnerDeletion: &isTrue,
				},
			},
			Annotations: vol.Ephemeral.VolumeClaimTemplate.Annotations,
			Labels:      vol.Ephemeral.VolumeClaimTemplate.Labels,
		},
		Spec: vol.Ephemeral.VolumeClaimTemplate.Spec,
	}

	// 对创建 PVC 的次数进行计数
	ephemeralvolumemetrics.EphemeralVolumeCreateAttempts.Inc()

	// 调用 Kubernetes API 创建 PVC 对象
	_, err = ec.kubeClient.CoreV1().PersistentVolumeClaims(pod.Namespace).Create(ctx, pvc, metav1.CreateOptions{})

	// 如果创建失败，则对 PVC 创建失败的次数进行计数，并返回错误信息
	if err != nil {
		ephemeralvolumemetrics.EphemeralVolumeCreateFailures.Inc()
		return fmt.Errorf("create PVC %s: %v", pvcName, err)
	}

	// 如果创建成功，则返回 nil
	return nil
}
```

