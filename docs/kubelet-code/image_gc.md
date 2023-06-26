---
id: 9-kubelet-code 
title: image gc 代码走读
description: image gc 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## 简介

Kubelet image garbage collection是 Kubernetes 中的一个特性，旨在帮助控制节点上的镜像存储空间。在 Kubernetes 中，每个节点都有一个 kubelet 进程，它负责管理节点上的 Pod。kubelet image_gc 可以自动清理节点上不再需要的镜像，以释放磁盘空间。

## ImageGCManager

```GO
// ImageGCManager是管理所有 image 生命周期的接口。
// 实现是线程安全的。
type ImageGCManager interface {
	// 应用垃圾回收策略。错误包括无法按照垃圾回收策略释放足够空间。
	GarbageCollect(ctx context.Context) error

	// 异步启动 image 的垃圾回收。
	Start()

	GetImageList() ([]container.Image, error)

	// 删除所有未使用的 image 。
	DeleteUnusedImages(ctx context.Context) error
}
```

## realImageGCManager

```GO
type realImageGCManager struct {
	// 容器运行时
	runtime container.Runtime

	//  image 及其使用记录。
	imageRecords     map[string]*imageRecord
	imageRecordsLock sync.Mutex

	// 使用中的 image 垃圾回收策略。
	policy ImageGCPolicy

	// statsProvider提供在 image 垃圾回收期间使用的统计信息。
	statsProvider StatsProvider

	// Kubernetes事件记录器。
	recorder record.EventRecorder

	// 对此节点的引用。
	nodeRef *v1.ObjectReference

	// 跟踪初始化
	initialized bool

	// 最新 image 列表的缓存。
	imageCache imageCache

	// 免受GC影响的沙箱 image 
	sandboxImage string

	// 用于记录跨度的追踪器
	tracer trace.Tracer
}
```

### StatsProvider

```GO
// StatsProvider是获取在 image 垃圾回收期间使用的统计信息的接口。
type StatsProvider interface {
	// ImageFsStats返回 image 文件系统的统计信息。
	ImageFsStats(ctx context.Context) (*statsapi.FsStats, error)
}S
```

## NewImageGCManager

```GO
// NewImageGCManager实例化一个新的ImageGCManager对象。
func NewImageGCManager(runtime container.Runtime, statsProvider StatsProvider, recorder record.EventRecorder, nodeRef *v1.ObjectReference, policy ImageGCPolicy, sandboxImage string, tracerProvider trace.TracerProvider) (ImageGCManager, error) {
	// 验证策略。
	if policy.HighThresholdPercent < 0 || policy.HighThresholdPercent > 100 {
		return nil, fmt.Errorf("invalid HighThresholdPercent %d, must be in range [0-100]", policy.HighThresholdPercent)
	}
	if policy.LowThresholdPercent < 0 || policy.LowThresholdPercent > 100 {
		return nil, fmt.Errorf("invalid LowThresholdPercent %d, must be in range [0-100]", policy.LowThresholdPercent)
	}
	if policy.LowThresholdPercent > policy.HighThresholdPercent {
		return nil, fmt.Errorf("LowThresholdPercent %d can not be higher than HighThresholdPercent %d", policy.LowThresholdPercent, policy.HighThresholdPercent)
	}
	tracer := tracerProvider.Tracer(instrumentationScope)
	im := &realImageGCManager{
		runtime:       runtime,
		policy:        policy,
		imageRecords:  make(map[string]*imageRecord),
		statsProvider: statsProvider,
		recorder:      recorder,
		nodeRef:       nodeRef,
		initialized:   false,
		sandboxImage:  sandboxImage,
		tracer:        tracer,
	}

	return im, nil
}
```

### ImageGCPolicy

```GO
// ImageGCPolicy是 image 垃圾收集的策略。策略定义了允许运行垃圾回收的范围。
type ImageGCPolicy struct {
	// 超过此阈值的任何使用都将始终触发垃圾回收。
	// 这是我们允许的最高使用率。
	HighThresholdPercent int

	// 低于此阈值的任何使用都不会触发垃圾回收。
	// 这是我们尝试进行垃圾回收的最低阈值。
	LowThresholdPercent int

	// 可以进行垃圾回收的 image 的最小年龄。
	MinAge time.Duration
}
```

## GarbageCollect

```GO
func (im *realImageGCManager) GarbageCollect(ctx context.Context) error {
	// 垃圾回收函数，用于回收不再使用的镜像

	ctx, otelSpan := im.tracer.Start(ctx, "Images/GarbageCollect") // 在上下文中开始一个追踪器 span
	defer otelSpan.End() // 在函数返回前结束追踪器 span

	// 获取存储镜像的磁盘上的磁盘使用情况
	fsStats, err := im.statsProvider.ImageFsStats(ctx)
	if err != nil {
		return err
	}

	var capacity, available int64
	if fsStats.CapacityBytes != nil {
		capacity = int64(*fsStats.CapacityBytes)
	}
	if fsStats.AvailableBytes != nil {
		available = int64(*fsStats.AvailableBytes)
	}

	if available > capacity {
		klog.InfoS("Availability is larger than capacity", "available", available, "capacity", capacity)
		available = capacity
	}

	// 检查有效的容量
	if capacity == 0 {
		err := goerrors.New("invalid capacity 0 on image filesystem")
		im.recorder.Eventf(im.nodeRef, v1.EventTypeWarning, events.InvalidDiskCapacity, err.Error())
		return err
	}

	// 如果超过最大阈值，则释放足够的空间以使我们达到较低的阈值
	usagePercent := 100 - int(available*100/capacity)
	if usagePercent >= im.policy.HighThresholdPercent {
		amountToFree := capacity*int64(100-im.policy.LowThresholdPercent)/100 - available
		klog.InfoS("Disk usage on image filesystem is over the high threshold, trying to free bytes down to the low threshold", "usage", usagePercent, "highThreshold", im.policy.HighThresholdPercent, "amountToFree", amountToFree, "lowThreshold", im.policy.LowThresholdPercent)
		freed, err := im.freeSpace(ctx, amountToFree, time.Now())
		if err != nil {
			return err
		}

		if freed < amountToFree {
			err := fmt.Errorf("Failed to garbage collect required amount of images. Attempted to free %d bytes, but only found %d bytes eligible to free.", amountToFree, freed)
			im.recorder.Eventf(im.nodeRef, v1.EventTypeWarning, events.FreeDiskSpaceFailed, err.Error())
			return err
		}
	}

	return nil
}
```

### freeSpace

```GO
// 尝试释放磁盘上的指定字节数
//
// 返回释放的字节数和发生的任何错误。总是返回已释放的字节数。
// 请注意，错误可能为nil，释放的字节数可能小于字节数 bytesToFree。
func (im *realImageGCManager) freeSpace(ctx context.Context, bytesToFree int64, freeTime time.Time) (int64, error) {
	// 检测在指定时间之前的正在使用的镜像
	imagesInUse, err := im.detectImages(ctx, freeTime)
	if err != nil {
		return 0, err
	}

	im.imageRecordsLock.Lock()
	defer im.imageRecordsLock.Unlock()

	// 按逐出顺序获取所有镜像
	images := make([]evictionInfo, 0, len(im.imageRecords))
	for image, record := range im.imageRecords {
		if isImageUsed(image, imagesInUse) {
			klog.V(5).InfoS("Image ID is being used", "imageID", image)
			continue
		}
		// 检查镜像是否被固定，防止进行垃圾回收
		if record.pinned {
			klog.V(5).InfoS("Image is pinned, skipping garbage collection", "imageID", image)
			continue

		}
		images = append(images, evictionInfo{
			id:          image,
			imageRecord: *record,
		})
	}
	sort.Sort(byLastUsedAndDetected(images))

	// 删除未使用的镜像，直到释放足够的空间
	var deletionErrors []error
	spaceFreed := int64(0)
	for _, image := range images {
		klog.V(5).InfoS("Evaluating image ID for possible garbage collection", "imageID", image.id)
		// 当前正在使用的镜像具有较新的最后使用时间
		if image.lastUsed.Equal(freeTime) || image.lastUsed.After(freeTime) {
			klog.V(5).InfoS("Image ID was used too recently, not eligible for garbage collection", "imageID", image.id, "lastUsed", image.lastUsed, "freeTime", freeTime)
			continue
		}

		// 如果镜像的年龄不够旧，则避免进行垃圾回收
		// 在这种情况下，镜像可能刚刚被下载下来，将立即被一个容器使用。
		if freeTime.Sub(image.firstDetected) < im.policy.MinAge {
			klog.V(5).InfoS("Image ID's age is less than the policy's minAge, not eligible for garbage collection", "imageID", image.id, "age", freeTime.Sub(image.firstDetected), "minAge", im.policy.MinAge)
			continue
		}

		// 删除镜像。继续处理错误。
		klog.InfoS("Removing image to free bytes", "imageID", image.id, "size", image.size)
		err := im.runtime.RemoveImage(ctx, container.ImageSpec{Image: image.id})
		if err != nil {
			deletionErrors = append(deletionErrors, err)
			continue
		}
		delete(im.imageRecords, image.id)
		spaceFreed += image.size

		if spaceFreed >= bytesToFree {
			break
		}
	}

	if len(deletionErrors) > 0 {
		return spaceFreed, fmt.Errorf("wanted to free %d bytes, but freed %d bytes space with errors in image deletion: %v", bytesToFree, spaceFreed, errors.NewAggregate(deletionErrors))
	}
	return spaceFreed, nil
}
```

## Start

```GO
func (im realImageGCManager) Start() {
	ctx := context.Background()
	go wait.Until(func() {
		// 初始检测使得检测时间 "未知" 在过去
		var ts time.Time
		if im.initialized {
			ts = time.Now()
		}
		_, err := im.detectImages(ctx, ts)
		if err != nil {
			klog.InfoS("Failed to monitor images", "err", err)
		} else {
			im.initialized = true
		}
	}, 5*time.Minute, wait.NeverStop)

	// 启动一个 goroutine 定期更新镜像缓存
	go wait.Until(func() {
		images, err := im.runtime.ListImages(ctx)
		if err != nil {
			klog.InfoS("Failed to update image list", "err", err)
		} else {
			im.imageCache.set(images)
		}
	}, 30*time.Second, wait.NeverStop)
}
```

### detectImages

```GO
func (im *realImageGCManager) detectImages(ctx context.Context, detectTime time.Time) (sets.String, error) {
	imagesInUse := sets.NewString()

	// 总是将容器运行时的 Pod 沙盒镜像视为正在使用中
	imageRef, err := im.runtime.GetImageRef(ctx, container.ImageSpec{Image: im.sandboxImage})
	if err == nil && imageRef != "" {
		imagesInUse.Insert(imageRef)
	}

	images, err := im.runtime.ListImages(ctx)
	if err != nil {
		return imagesInUse, err
	}
	pods, err := im.runtime.GetPods(ctx, true)
	if err != nil {
		return imagesInUse, err
	}

	// 构建正在被容器使用的镜像集合
	for _, pod := range pods {
		for _, container := range pod.Containers {
			klog.V(5).InfoS("Container uses image", "pod", klog.KRef(pod.Namespace, pod.Name), "containerName", container.Name, "containerImage", container.Image, "imageID", container.ImageID)
			imagesInUse.Insert(container.ImageID)
		}
	}

	// 添加新镜像并记录正在使用的镜像
	now := time.Now()
	currentImages := sets.NewString()
	im.imageRecordsLock.Lock()
	defer im.imageRecordsLock.Unlock()
	for _, image := range images {
		klog.V(5).InfoS("Adding image ID to currentImages", "imageID", image.ID)
		currentImages.Insert(image.ID)

		// 新镜像，设置为当前检测时间
		if _, ok := im.imageRecords[image.ID]; !ok {
			klog.V(5).InfoS("Image ID is new", "imageID", image.ID)
			im.imageRecords[image.ID] = &imageRecord{
				firstDetected: detectTime,
			}
		}

		// 如果镜像正在使用，则将最后使用时间设置为当前时间
		if isImageUsed(image.ID, imagesInUse) {
			klog.V(5).InfoS("Setting Image ID lastUsed", "imageID", image.ID, "lastUsed", now)
			im.imageRecords[image.ID].lastUsed = now
		}

		klog.V(5).InfoS("Image ID has size", "imageID", image.ID, "size", image.Size)
		im.imageRecords[image.ID].size = image.Size

		klog.V(5).InfoS("Image ID is pinned", "imageID", image.ID, "pinned", image.Pinned)
		im.imageRecords[image.ID].pinned = image.Pinned
	}

	// 从记录中删除旧的镜像
	for image := range im.imageRecords {
		if !currentImages.Has(image) {
			klog.V(5).InfoS("Image ID is no longer present; removing from imageRecords", "imageID", image)
			delete(im.imageRecords, image)
		}
	}

	return imagesInUse, nil
}
```

## GetImageList

```GO
// Get a list of images on this node
func (im *realImageGCManager) GetImageList() ([]container.Image, error) {
	return im.imageCache.get(), nil
}
```

## DeleteUnusedImages

```GO
func (im *realImageGCManager) DeleteUnusedImages(ctx context.Context) error {
	klog.InfoS("Attempting to delete unused images")
	_, err := im.freeSpace(ctx, math.MaxInt64, time.Now())
	return err
}
```

