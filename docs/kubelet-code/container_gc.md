---
id: 11-kubelet-code 
title: container gc manager 代码走读
description: container gc manager 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## 简介

Kubelet 的 Container GC Manager 是 Kubernetes 中的一个组件，它负责管理节点上的容器生命周期，并清理已经退出的容器，以避免占用过多的系统资源。

在 Kubernetes 中，每个节点都有一个 kubelet 进程，它负责管理节点上的 Pod，并启动和停止容器。当一个容器退出时，kubelet 会通知 Container GC Manager 进行清理工作。

Container GC Manager 会定期检查节点上所有容器的状态，如果发现某个容器已经退出，则会将其从节点上彻底删除，以释放占用的资源。同时，Container GC Manager 还会清理掉一定时间内没有被使用的容器，以避免占用过多的系统资源。

## GC

```GO
// GC负责管理废弃容器的垃圾回收。
//
// 实现是线程兼容的。
type GC interface {
	// 垃圾回收容器。
	GarbageCollect(ctx context.Context) error
	// 删除所有未使用的容器，包括属于已终止但未删除的Pod的容器
	DeleteAllUnusedContainers(ctx context.Context) error
}
```

## realContainerGC

```GO
// TODO（vmarmol）：优先删除Pod基础设施容器。
type realContainerGC struct {
	// 容器运行时
	runtime Runtime

	// 垃圾回收策略
	policy GCPolicy

	// sourcesReadyProvider提供kubelet配置源的就绪状态。
	sourcesReadyProvider SourcesReadyProvider
}
```

### GCPolicy

```GO
// GCPolicy指定容器垃圾回收的策略。
type GCPolicy struct {
	// 容器可以进行垃圾回收的最小年龄，为零表示无限制。
	MinAge time.Duration

	// 单个Pod（UID、容器名称）对允许拥有的死亡容器的最大数量，小于零表示无限制。
	MaxPerPodContainer int

	// 总的死亡容器的最大数量，小于零表示无限制。
	MaxContainers int
}
```

### SourcesReadyProvider

```GO
// SourcesReadyProvider知道如何确定配置源是否就绪。
type SourcesReadyProvider interface {
	// AllReady如果当前配置的源都已就绪，则返回true。
	AllReady() bool
}
```

## NewContainerGC

```GO
// NewContainerGC使用指定的策略创建一个新的GC实例。
func NewContainerGC(runtime Runtime, policy GCPolicy, sourcesReadyProvider SourcesReadyProvider) (GC, error) {
	if policy.MinAge < 0 {
		return nil, fmt.Errorf("invalid minimum garbage collection age: %v", policy.MinAge)
	}

	return &realContainerGC{
		runtime:              runtime,
		policy:               policy,
		sourcesReadyProvider: sourcesReadyProvider,
	}, nil
}
```

## GarbageCollect

```GO
// GarbageCollect执行垃圾回收操作。
// 调用容器运行时的GarbageCollect方法，传递上下文ctx、垃圾回收策略cgc.policy、
// 当前配置源的就绪状态cgc.sourcesReadyProvider.AllReady()以及删除未使用容器的标志false。
func (cgc *realContainerGC) GarbageCollect(ctx context.Context) error {
	return cgc.runtime.GarbageCollect(ctx, cgc.policy, cgc.sourcesReadyProvider.AllReady(), false)
}
```

### GarbageCollect

```GO
// GarbageCollect使用指定的容器GC策略删除无效的容器。
// 注意，GC策略不适用于 sandbox 。只有当 sandbox 未准备好且不包含容器时，才会删除 sandbox 。
//
// GarbageCollect包括以下步骤：
// * 获取超过gcPolicy.MinAge时间并且非活动的可驱逐容器。
// * 根据gcPolicy.MaxPerPodContainer策略删除每个Pod中最旧的无效容器。
// * 根据gcPolicy.MaxContainers策略删除最旧的无效容器。
// * 获取未准备好且不包含容器的可驱逐 sandbox 。
// * 删除可驱逐的 sandbox 。
func (cgc *containerGC) GarbageCollect(ctx context.Context, gcPolicy kubecontainer.GCPolicy, allSourcesReady bool, evictNonDeletedPods bool) error {
	ctx, otelSpan := cgc.tracer.Start(ctx, "Containers/GarbageCollect")
	defer otelSpan.End()
	errors := []error{}
	// 删除可驱逐的容器
	if err := cgc.evictContainers(ctx, gcPolicy, allSourcesReady, evictNonDeletedPods); err != nil {
		errors = append(errors, err)
	}

	// 删除没有容器的 sandbox 
	if err := cgc.evictSandboxes(ctx, evictNonDeletedPods); err != nil {
		errors = append(errors, err)
	}

	// 删除Pod sandbox 日志目录
	if err := cgc.evictPodLogsDirectories(ctx, allSourcesReady); err != nil {
		errors = append(errors, err)
	}
	return utilerrors.NewAggregate(errors)
}
```

#### evictContainers

```go
// 逐出所有可驱逐的容器
func (cgc *containerGC) evictContainers(ctx context.Context, gcPolicy kubecontainer.GCPolicy, allSourcesReady bool, evictNonDeletedPods bool) error {
	// 按驱逐单元对容器进行分组。
	evictUnits, err := cgc.evictableContainers(ctx, gcPolicy.MinAge)
	if err != nil {
		return err
	}

	// 如果所有源已就绪，则删除已删除的Pod容器。
	if allSourcesReady {
		for key, unit := range evictUnits {
			if cgc.podStateProvider.ShouldPodContentBeRemoved(key.uid) || (evictNonDeletedPods && cgc.podStateProvider.ShouldPodRuntimeBeRemoved(key.uid)) {
				cgc.removeOldestN(ctx, unit, len(unit)) // 全部删除。
				delete(evictUnits, key)
			}
		}
	}

	// 根据驱逐单元的最大容器数限制执行操作。
	if gcPolicy.MaxPerPodContainer >= 0 {
		cgc.enforceMaxContainersPerEvictUnit(ctx, evictUnits, gcPolicy.MaxPerPodContainer)
	}

	// 根据最大容器数限制执行操作。
	if gcPolicy.MaxContainers >= 0 && evictUnits.NumContainers() > gcPolicy.MaxContainers {
		// 在每个驱逐单元中保留相等数量的容器（至少为1）。
		numContainersPerEvictUnit := gcPolicy.MaxContainers / evictUnits.NumEvictUnits()
		if numContainersPerEvictUnit < 1 {
			numContainersPerEvictUnit = 1
		}
		cgc.enforceMaxContainersPerEvictUnit(ctx, evictUnits, numContainersPerEvictUnit)

		// 如果仍然需要驱逐，首先驱逐最旧的容器。
		numContainers := evictUnits.NumContainers()
		if numContainers > gcPolicy.MaxContainers {
			flattened := make([]containerGCInfo, 0, numContainers)
			for key := range evictUnits {
				flattened = append(flattened, evictUnits[key]...)
			}
			sort.Sort(byCreated(flattened))

			cgc.removeOldestN(ctx, flattened, numContainers-gcPolicy.MaxContainers)
		}
	}
	return nil
}
```

##### removeOldestN

```go
// removeOldestN删除最旧的toRemove个容器并返回结果切片。
func (cgc *containerGC) removeOldestN(ctx context.Context, containers []containerGCInfo, toRemove int) []containerGCInfo {
	// 从最旧到最新的顺序进行删除（从后向前）。
	numToKeep := len(containers) - toRemove
	if numToKeep > 0 {
		sort.Sort(byCreated(containers))
	}
	for i := len(containers) - 1; i >= numToKeep; i-- {
		if containers[i].unknown {
			// 已知状态的容器可能正在运行，我们应该在删除之前尝试停止它。
			id := kubecontainer.ContainerID{
				Type: cgc.manager.runtimeName,
				ID:   containers[i].id,
			}
			message := "容器处于未知状态，在删除之前尝试停止"
			if err := cgc.manager.killContainer(ctx, nil, id, containers[i].name, message, reasonUnknown, nil); err != nil {
				klog.ErrorS(err, "无法停止容器", "containerID", containers[i].id)
				continue
			}
		}
		if err := cgc.manager.removeContainer(ctx, containers[i].id); err != nil {
			klog.ErrorS(err, "无法删除容器", "containerID", containers[i].id)
		}
	}

	// 假设我们已经删除了容器，以免太过激进。
	return containers[:numToKeep]
}
```

#### evictSandboxes

```go
// evictSandboxes删除所有可驱逐的 sandbox 。可驱逐的 sandbox 必须满足以下要求：
// 1. 未处于准备就绪状态
// 2. 不包含任何容器
// 3. 属于不存在的（已经被删除的）Pod，或者不是Pod的最新创建的 sandbox 。
func (cgc *containerGC) evictSandboxes(ctx context.Context, evictNonDeletedPods bool) error {
	containers, err := cgc.manager.getKubeletContainers(ctx, true)
	if err != nil {
		return err
	}

	sandboxes, err := cgc.manager.getKubeletSandboxes(ctx, true)
	if err != nil {
		return err
	}

	// 收集所有容器的PodSandboxId
	sandboxIDs := sets.NewString()
	for _, container := range containers {
		sandboxIDs.Insert(container.PodSandboxId)
	}

	sandboxesByPod := make(sandboxesByPodUID, len(sandboxes))
	for _, sandbox := range sandboxes {
		podUID := types.UID(sandbox.Metadata.Uid)
		sandboxInfo := sandboxGCInfo{
			id:         sandbox.Id,
			createTime: time.Unix(0, sandbox.CreatedAt),
		}

		// 设置准备就绪的 sandbox 和仍包含容器的 sandbox 为活跃状态。
		if sandbox.State == runtimeapi.PodSandboxState_SANDBOX_READY || sandboxIDs.Has(sandbox.Id) {
			sandboxInfo.active = true
		}

		sandboxesByPod[podUID] = append(sandboxesByPod[podUID], sandboxInfo)
	}

	for podUID, sandboxes := range sandboxesByPod {
		if cgc.podStateProvider.ShouldPodContentBeRemoved(podUID) || (evictNonDeletedPods && cgc.podStateProvider.ShouldPodRuntimeBeRemoved(podUID)) {
			// 如果Pod已被删除，则删除所有可驱逐的 sandbox 。
			// 注意，如果已存在一个活跃的 sandbox ，最新的死亡 sandbox 也将被删除。
			cgc.removeOldestNSandboxes(ctx, sandboxes, len(sandboxes))
		} else {
			// 如果Pod仍然存在，则保留最新的一个 sandbox 。
			cgc.removeOldestNSandboxes(ctx, sandboxes, len(sandboxes)-1)
		}
	}
	return nil
}
```

##### removeOldestNSandboxes

```go
// removeOldestNSandboxes函数移除最旧的toRemove个非活跃的沙盒，并返回结果切片。
func (cgc *containerGC) removeOldestNSandboxes(ctx context.Context, sandboxes []sandboxGCInfo, toRemove int) {
	numToKeep := len(sandboxes) - toRemove
	if numToKeep > 0 {
		sort.Sort(sandboxByCreated(sandboxes))
	}
	// 从最旧到最新的顺序进行移除（从后往前）。
	for i := len(sandboxes) - 1; i >= numToKeep; i-- {
		if !sandboxes[i].active {
			cgc.removeSandbox(ctx, sandboxes[i].id)
		}
	}
}
```

#### evictPodLogsDirectories

```go
// evictPodLogsDirectories函数驱逐所有可驱逐的Pod日志目录。如果没有相应的Pod，Pod日志目录是可驱逐的。
func (cgc *containerGC) evictPodLogsDirectories(ctx context.Context, allSourcesReady bool) error {
	osInterface := cgc.manager.osInterface
	if allSourcesReady {
		// 当所有源都准备就绪时，只移除Pod日志目录。
		dirs, err := osInterface.ReadDir(podLogsRootDirectory)
		if err != nil {
			return fmt.Errorf("failed to read podLogsRootDirectory %q: %v", podLogsRootDirectory, err)
		}
		for _, dir := range dirs {
			name := dir.Name()
			podUID := parsePodUIDFromLogsDirectory(name)
			if !cgc.podStateProvider.ShouldPodContentBeRemoved(podUID) {
				continue
			}
			klog.V(4).InfoS("Removing pod logs", "podUID", podUID)
			err := osInterface.RemoveAll(filepath.Join(podLogsRootDirectory, name))
			if err != nil {
				klog.ErrorS(err, "Failed to remove pod logs directory", "path", name)
			}
		}
	}

	// 移除死亡容器的日志符号链接。
	// 在集群日志支持CRI容器日志路径之后，可以移除此部分。
	logSymlinks, _ := osInterface.Glob(filepath.Join(legacyContainerLogsDir, fmt.Sprintf("*.%s", legacyLogSuffix)))
	for _, logSymlink := range logSymlinks {
		if _, err := osInterface.Stat(logSymlink); os.IsNotExist(err) {
			if containerID, err := getContainerIDFromLegacyLogSymlink(logSymlink); err == nil {
				resp, err := cgc.manager.runtimeService.ContainerStatus(ctx, containerID, false)
				if err != nil {
					// TODO: 一旦解决https://github.com/kubernetes/kubernetes/issues/63336，我们应该以不同的方式处理未找到容器的情况（即容器已删除）。
					klog.InfoS("Error getting ContainerStatus for containerID", "containerID", containerID, "err", err)
				} else {
					status := resp.GetStatus()
					if status == nil {
						klog.V(4).InfoS("Container status is nil")
						continue
					}
					if status.State != runtimeapi.ContainerState_CONTAINER_EXITED {
						// 容器日志轮转的工作原理如下（请参见containerLogManager#rotateLatestLog）：
						//
						//1. 将当前日志重命名为包含当前时间戳的轮转日志文件（fmt.Sprintf("%s.%s", log, timestamp)）
						// 2. 重新打开容器日志
						// 3. 如果#2失败，则将轮转日志文件重命名回容器日志
						//
						// 在此期间，存在极小但不确定的时间段内日志文件不存在（在步骤#1和#2之间，在#1和#3之间）。
						// 因此，在该期间可能认为符号链接不健康。
						// 参见https://github.com/kubernetes/kubernetes/issues/52172
						//
						// 我们只移除已死亡容器的不健康符号链接。
						klog.V(5).InfoS("Container is still running, not removing symlink", "containerID", containerID, "path", logSymlink)
						continue
					}
				}
			} else {
				klog.V(4).InfoS("Unable to obtain container ID", "err", err)
			}
			err := osInterface.Remove(logSymlink)
			if err != nil {
				klog.ErrorS(err, "Failed to remove container log dead symlink", "path", logSymlink)
			} else {
				klog.V(4).InfoS("Removed symlink", "path", logSymlink)
			}
		}
	}
	return nil
}
```

## DeleteAllUnusedContainers

```GO
// DeleteAllUnusedContainers删除所有未使用的容器。
// 首先在日志中记录"Attempting to delete unused containers"信息，
// 然后调用容器运行时的GarbageCollect方法，传递上下文ctx、垃圾回收策略cgc.policy、
// 当前配置源的就绪状态cgc.sourcesReadyProvider.AllReady()以及删除未使用容器的标志true。
func (cgc *realContainerGC) DeleteAllUnusedContainers(ctx context.Context) error {
	klog.InfoS("Attempting to delete unused containers")
	return cgc.runtime.GarbageCollect(ctx, cgc.policy, cgc.sourcesReadyProvider.AllReady(), true)
}
```

