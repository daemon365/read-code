---
id: 25-kube-controller-code
title: statefulset-controller 代码走读
description: statefulset-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

StatefulSet是Kubernetes提供的一种类型，用于部署有状态的应用程序。与Deployment控制器不同，StatefulSet控制器允许应用程序实例具有唯一而持久的标识符。每个实例都有一个稳定的网络标识符和一个持久化的存储卷。这使得在应用程序升级或节点故障等情况下，可以更容易地管理应用程序实例的生命周期。

StatefulSet控制器适用于那些需要持久化存储和固定标识符的应用程序，例如数据库、缓存、队列等。通过使用StatefulSet控制器，可以在Kubernetes中轻松地管理这些应用程序，并保证它们的数据始终可用。

StatefulSet控制器与其他控制器类型相似，可以定义副本数、镜像、容器端口等参数。但与Deployment控制器不同的是，StatefulSet控制器还允许定义每个应用程序实例的标识符、网络标识符和持久化存储卷等参数。

总的来说，StatefulSet控制器为有状态的应用程序在Kubernetes中的部署和管理提供了更好的支持，可以使应用程序更加可靠和可扩展。

## 结构体

```GO
type StatefulSetController struct {
	kubeClient clientset.Interface
	// StatefulSet控制器接口，用于同步StatefulSet的状态
	control StatefulSetControlInterface
	// pod控制器接口，用于对Pod进行更新操作
	podControl controller.PodControlInterface

	podLister corelisters.PodLister
	podListerSynced cache.InformerSynced
    
	setLister appslisters.StatefulSetLister
	setListerSynced cache.InformerSynced

	pvcListerSynced cache.InformerSynced
	revListerSynced cache.InformerSynced
	// 存储需要同步的StatefulSet的工作队列
	queue workqueue.RateLimitingInterface
	// 广播器
	eventBroadcaster record.EventBroadcaster
}
```

## StatefulSetControlInterface

```GO
type StatefulSetControlInterface interface {
	// 实现了 Pod 的创建、更新和删除以及持久卷的创建、更新和删除的控制逻辑，并返回 StatefulSet 的状态和错误信息。
	UpdateStatefulSet(ctx context.Context, set *apps.StatefulSet, pods []*v1.Pod) (*apps.StatefulSetStatus, error)
	// 返回 StatefulSet 控制器的所有 ControllerRevisions。
	ListRevisions(set *apps.StatefulSet) ([]*apps.ControllerRevision, error)
	// 将与 StatefulSet 控制器 Selector 匹配的孤立的 ControllerRevisions 接管，并返回错误信息。
	AdoptOrphanRevisions(set *apps.StatefulSet, revisions []*apps.ControllerRevision) error
}
```

```GO
func NewDefaultStatefulSetControl(
	podControl *StatefulPodControl,
	statusUpdater StatefulSetStatusUpdaterInterface,
	controllerHistory history.Interface,
	recorder record.EventRecorder) StatefulSetControlInterface {
	return &defaultStatefulSetControl{podControl, statusUpdater, controllerHistory, recorder}
}

type defaultStatefulSetControl struct {
	podControl        *StatefulPodControl
	statusUpdater     StatefulSetStatusUpdaterInterface
	controllerHistory history.Interface
	recorder          record.EventRecorder
}
```

### UpdateStatefulSet

```go
func (ssc *defaultStatefulSetControl) UpdateStatefulSet(ctx context.Context, set *apps.StatefulSet, pods []*v1.Pod) (*apps.StatefulSetStatus, error) {
	set = set.DeepCopy() // 当在 performUpdate 中创建新版本时，会修改 set。现在进行复制以避免变异错误。

	// 列出所有版本并排序
	revisions, err := ssc.ListRevisions(set)
	if err != nil {
		return nil, err
	}
    // 对版本进行排序
	history.SortControllerRevisions(revisions)
	// 执行更新操作
	currentRevision, updateRevision, status, err := ssc.performUpdate(ctx, set, pods, revisions)
	if err != nil {
		return nil, utilerrors.NewAggregate([]error{err, ssc.truncateHistory(set, pods, revisions, currentRevision, updateRevision)})
	}

	// 维护集合的版本历史记录限制 返回状态和截断历史记录的结果
	return status, ssc.truncateHistory(set, pods, revisions, currentRevision, updateRevision)
}
```

#### ListRevisions

```GO
func (ssc *defaultStatefulSetControl) ListRevisions(set *apps.StatefulSet) ([]*apps.ControllerRevision, error) {
	selector, err := metav1.LabelSelectorAsSelector(set.Spec.Selector)
	if err != nil {
		return nil, err
	}
	return ssc.controllerHistory.ListControllerRevisions(set, selector)
}
```

#### performUpdate

```GO
func (ssc *defaultStatefulSetControl) performUpdate(
	ctx context.Context, set *apps.StatefulSet, pods []*v1.Pod, revisions []*apps.ControllerRevision) (*apps.ControllerRevision, *apps.ControllerRevision, *apps.StatefulSetStatus, error) {
    // 获取当前状态
	var currentStatus *apps.StatefulSetStatus
	logger := klog.FromContext(ctx)
	// 获取当前和更新的revisions, 以及碰撞计数
	currentRevision, updateRevision, collisionCount, err := ssc.getStatefulSetRevisions(set, revisions)
	if err != nil {
		return currentRevision, updateRevision, currentStatus, err
	}

	// 执行主要的更新函数并获取状态
	currentStatus, err = ssc.updateStatefulSet(ctx, set, currentRevision, updateRevision, collisionCount, pods)
	if err != nil && currentStatus == nil {
		return currentRevision, updateRevision, nil, err
	}

	// 即使有非零的currentStatus，也要确保更新最新的状态
	statusErr := ssc.updateStatefulSetStatus(ctx, set, currentStatus)
	if statusErr == nil {
		logger.V(4).Info("Updated status", "statefulSet", klog.KObj(set),
			"replicas", currentStatus.Replicas,
			"readyReplicas", currentStatus.ReadyReplicas,
			"currentReplicas", currentStatus.CurrentReplicas,
			"updatedReplicas", currentStatus.UpdatedReplicas)
	}

	switch {
    // 如果 err 和 statusErr 都不为 nil, 则输出错误并返回当前的currentRevision, updateRevision和currentStatus
	case err != nil && statusErr != nil:
		klog.ErrorS(statusErr, "Could not update status", "statefulSet", klog.KObj(set))
		return currentRevision, updateRevision, currentStatus, err
    // 如果只有err不为nil，则返回当前的currentRevision, updateRevision和currentStatus和err
	case err != nil:
		return currentRevision, updateRevision, currentStatus, err
    // 如果只有statusErr不为nil，则返回当前的currentRevision, updateRevision和currentStatus和statusErr
	case statusErr != nil:
		return currentRevision, updateRevision, currentStatus, statusErr
	}

	logger.V(4).Info("StatefulSet revisions", "statefulSet", klog.KObj(set),
		"currentRevision", currentStatus.CurrentRevision,
		"updateRevision", currentStatus.UpdateRevision)

	return currentRevision, updateRevision, currentStatus, nil
}
```

##### getStatefulSetRevisions

```GO
func (ssc *defaultStatefulSetControl) getStatefulSetRevisions(
	set *apps.StatefulSet,
	revisions []*apps.ControllerRevision) (*apps.ControllerRevision, *apps.ControllerRevision, int32, error) {
	var currentRevision, updateRevision *apps.ControllerRevision
	// 获取历史版本的数量
	revisionCount := len(revisions)
    // 按照revision字段排序
	history.SortControllerRevisions(revisions)

	// 使用 set.Status.CollisionCount 的本地副本避免直接修改 set.Status，该副本在 updateStatefulSet 中返回，以便将该值传递给 set.Status。
	var collisionCount int32
	if set.Status.CollisionCount != nil {
		collisionCount = *set.Status.CollisionCount
	}

	// 从当前状态创建新版本的 revision
	updateRevision, err := newRevision(set, nextRevision(revisions), &collisionCount)
	if err != nil {
		return nil, nil, collisionCount, err
	}

	// 查找所有等效的版本，即与 updateRevision 相等的版本
	equalRevisions := history.FindEqualRevisions(revisions, updateRevision)
	equalCount := len(equalRevisions)

	if equalCount > 0 && history.EqualRevision(revisions[revisionCount-1], equalRevisions[equalCount-1]) {
		// 如果等效版本与 updateRevision 相等，则 updateRevision 未更改
		updateRevision = revisions[revisionCount-1]
	} else if equalCount > 0 {
		// 如果等效版本不与 updateRevision 相等，则将等效版本的 Revision 递增以进行回滚
		updateRevision, err = ssc.controllerHistory.UpdateControllerRevision(
			equalRevisions[equalCount-1],
			updateRevision.Revision)
		if err != nil {
			return nil, nil, collisionCount, err
		}
	} else {
		// 如果没有等效版本，则创建一个新版本
		updateRevision, err = ssc.controllerHistory.CreateControllerRevision(set, updateRevision, &collisionCount)
		if err != nil {
			return nil, nil, collisionCount, err
		}
	}

	// 尝试查找与当前 revision 对应的 revision
	for i := range revisions {
		if revisions[i].Name == set.Status.CurrentRevision {
			currentRevision = revisions[i]
			break
		}
	}

	// 如果当前 revision 为空，则通过设置 updateRevision 初始化 history
	if currentRevision == nil {
		currentRevision = updateRevision
	}
	// 返回当前 revision、更新 revision、碰撞计数以及错误信息（如果有）
	return currentRevision, updateRevision, collisionCount, nil
}
```

###### newRevision

```GO
func newRevision(set *apps.StatefulSet, revision int64, collisionCount *int32) (*apps.ControllerRevision, error) {
	patch, err := getPatch(set)
	if err != nil {
		return nil, err
	}
	cr, err := history.NewControllerRevision(set,
		controllerKind,
		set.Spec.Template.Labels,
		runtime.RawExtension{Raw: patch},
		revision,
		collisionCount)
	if err != nil {
		return nil, err
	}
	if cr.ObjectMeta.Annotations == nil {
		cr.ObjectMeta.Annotations = make(map[string]string)
	}
	for key, value := range set.Annotations {
		cr.ObjectMeta.Annotations[key] = value
	}
	return cr, nil
}
```

###### getPatch

```GO
func getPatch(set *apps.StatefulSet) ([]byte, error) {
	data, err := runtime.Encode(patchCodec, set)
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}
	objCopy := make(map[string]interface{})
	specCopy := make(map[string]interface{})
	spec := raw["spec"].(map[string]interface{})
	template := spec["template"].(map[string]interface{})
	specCopy["template"] = template
	template["$patch"] = "replace"
	objCopy["spec"] = specCopy
	patch, err := json.Marshal(objCopy)
	return patch, err
}
```

##### updateStatefulSet

```GO
func (ssc *defaultStatefulSetControl) updateStatefulSet(
	ctx context.Context,
	set *apps.StatefulSet,
	currentRevision *apps.ControllerRevision,
	updateRevision *apps.ControllerRevision,
	collisionCount int32,
	pods []*v1.Pod) (*apps.StatefulSetStatus, error) {
	logger := klog.FromContext(ctx)
	// 获取 StatefulSet 的当前和更新版本。
	currentSet, err := ApplyRevision(set, currentRevision)
	if err != nil {
		return nil, err
	}
	updateSet, err := ApplyRevision(set, updateRevision)
	if err != nil {
		return nil, err
	}

	// 在返回的状态中设置当前版本、更新版本和副本数等信息。
	status := apps.StatefulSetStatus{}
	status.ObservedGeneration = set.Generation
	status.CurrentRevision = currentRevision.Name
	status.UpdateRevision = updateRevision.Name
	status.CollisionCount = new(int32)
	*status.CollisionCount = collisionCount
	
    // 将每个 Pod 分为有效的副本和被废弃的 Pod 两个列表。
	replicaCount := int(*set.Spec.Replicas)
	replicas := make([]*v1.Pod, replicaCount)

	condemned := make([]*v1.Pod, 0, len(pods))
	unhealthy := 0
	var firstUnhealthyPod *v1.Pod

	// First we partition pods into two lists valid replicas and condemned Pods
	for _, pod := range pods {
		status.Replicas++

		// count the number of running and ready replicas
		if isRunningAndReady(pod) {
			status.ReadyReplicas++
			// count the number of running and available replicas
			if isRunningAndAvailable(pod, set.Spec.MinReadySeconds) {
				status.AvailableReplicas++
			}

		}

		// count the number of current and update replicas
		if isCreated(pod) && !isTerminating(pod) {
			if getPodRevision(pod) == currentRevision.Name {
				status.CurrentReplicas++
			}
			if getPodRevision(pod) == updateRevision.Name {
				status.UpdatedReplicas++
			}
		}

		if podInOrdinalRange(pod, set) {
			// if the ordinal of the pod is within the range of the current number of replicas,
			// insert it at the indirection of its ordinal
			replicas[getOrdinal(pod)-getStartOrdinal(set)] = pod
		} else if getOrdinal(pod) >= 0 {
			// if the ordinal is valid, but not within the range add it to the condemned list
			condemned = append(condemned, pod)
		}
		// If the ordinal could not be parsed (ord < 0), ignore the Pod.
	}

	 // 对于序号范围在 [0,set.Spec.Replicas) 之间的任何空索引，创建一个新的 Pod。
	for ord := getStartOrdinal(set); ord <= getEndOrdinal(set); ord++ {
		replicaIdx := ord - getStartOrdinal(set)
		if replicas[replicaIdx] == nil {
			replicas[replicaIdx] = newVersionedStatefulSetPod(
				currentSet,
				updateSet,
				currentRevision.Name,
				updateRevision.Name, ord)
		}
	}

	// sort the condemned Pods by their ordinals
	sort.Sort(ascendingOrdinal(condemned))

	 // 寻找第一个不健康的 Pod。
	for i := range replicas {
		if !isHealthy(replicas[i]) {
			unhealthy++
			if firstUnhealthyPod == nil {
				firstUnhealthyPod = replicas[i]
			}
		}
	}

	for i := range condemned {
		if !isHealthy(condemned[i]) {
			unhealthy++
			if firstUnhealthyPod == nil {
				firstUnhealthyPod = condemned[i]
			}
		}
	}
	
     // 如果有不健康的 Pod，返回错误。
	if unhealthy > 0 {
		logger.V(4).Info("StatefulSet has unhealthy Pods", "statefulSet", klog.KObj(set), "unhealthyReplicas", unhealthy, "pod", klog.KObj(firstUnhealthyPod))
	}

	// 正在被删除直接返回
	if set.DeletionTimestamp != nil {
		return &status, nil
	}
	// 是否按顺序进行 Pod 的更新或删除。如果 StatefulSet 不允许 burst，则为 true。
	monotonic := !allowsBurst(set)

	// 对于每个 Pod，检查其状态。如果 Pod 处于失败状态，则重新创建。
    // 如果 Pod 尚未创建，则创建 Pod。如果 Pod 处于等待状态，则创建 PVC。
    // 如果 Pod 正在终止，则等待其完全终止。
    // 如果 Pod 已创建但不处于运行和就绪状态，则等待其变为运行和就绪状态。如果 Pod 已创建但不可用，则等待其变为可用状态。
	for i := range replicas {
		// delete and recreate failed pods
		if isFailed(replicas[i]) {
			ssc.recorder.Eventf(set, v1.EventTypeWarning, "RecreatingFailedPod",
				"StatefulSet %s/%s is recreating failed Pod %s",
				set.Namespace,
				set.Name,
				replicas[i].Name)
			if err := ssc.podControl.DeleteStatefulPod(set, replicas[i]); err != nil {
				return &status, err
			}
			if getPodRevision(replicas[i]) == currentRevision.Name {
				status.CurrentReplicas--
			}
			if getPodRevision(replicas[i]) == updateRevision.Name {
				status.UpdatedReplicas--
			}
			status.Replicas--
			replicaOrd := i + getStartOrdinal(set)
			replicas[i] = newVersionedStatefulSetPod(
				currentSet,
				updateSet,
				currentRevision.Name,
				updateRevision.Name,
				replicaOrd)
		}
		// If we find a Pod that has not been created we create the Pod
		if !isCreated(replicas[i]) {
			if utilfeature.DefaultFeatureGate.Enabled(features.StatefulSetAutoDeletePVC) {
				if isStale, err := ssc.podControl.PodClaimIsStale(set, replicas[i]); err != nil {
					return &status, err
				} else if isStale {
					// If a pod has a stale PVC, no more work can be done this round.
					return &status, err
				}
			}
			if err := ssc.podControl.CreateStatefulPod(ctx, set, replicas[i]); err != nil {
				return &status, err
			}
			status.Replicas++
			if getPodRevision(replicas[i]) == currentRevision.Name {
				status.CurrentReplicas++
			}
			if getPodRevision(replicas[i]) == updateRevision.Name {
				status.UpdatedReplicas++
			}
			// if the set does not allow bursting, return immediately
			if monotonic {
				return &status, nil
			}
			// pod created, no more work possible for this round
			continue
		}

		// If the Pod is in pending state then trigger PVC creation to create missing PVCs
		if isPending(replicas[i]) {
			klog.V(4).Infof(
				"StatefulSet %s/%s is triggering PVC creation for pending Pod %s",
				set.Namespace,
				set.Name,
				replicas[i].Name)
			if err := ssc.podControl.createMissingPersistentVolumeClaims(ctx, set, replicas[i]); err != nil {
				return &status, err
			}
		}
		// If we find a Pod that is currently terminating, we must wait until graceful deletion
		// completes before we continue to make progress.
		if isTerminating(replicas[i]) && monotonic {
			logger.V(4).Info("StatefulSet is waiting for Pod to Terminate",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(replicas[i]))
			return &status, nil
		}
		// If we have a Pod that has been created but is not running and ready we can not make progress.
		// We must ensure that all for each Pod, when we create it, all of its predecessors, with respect to its
		// ordinal, are Running and Ready.
		if !isRunningAndReady(replicas[i]) && monotonic {
			logger.V(4).Info("StatefulSet is waiting for Pod to be Running and Ready",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(replicas[i]))
			return &status, nil
		}
		// If we have a Pod that has been created but is not available we can not make progress.
		// We must ensure that all for each Pod, when we create it, all of its predecessors, with respect to its
		// ordinal, are Available.
		if !isRunningAndAvailable(replicas[i], set.Spec.MinReadySeconds) && monotonic {
			logger.V(4).Info("StatefulSet is waiting for Pod to be Available",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(replicas[i]))
			return &status, nil
		}
		// Enforce the StatefulSet invariants
		retentionMatch := true
		if utilfeature.	DefaultFeatureGate.Enabled(features.StatefulSetAutoDeletePVC) {
			var err error
			retentionMatch, err = ssc.podControl.ClaimsMatchRetentionPolicy(ctx, updateSet, replicas[i])
			// An error is expected if the pod is not yet fully updated, and so return is treated as matching.
			if err != nil {
				retentionMatch = true
			}
		}
		if identityMatches(set, replicas[i]) && storageMatches(set, replicas[i]) && retentionMatch {
			continue
		}
		// Make a deep copy so we don't mutate the shared cache
		replica := replicas[i].DeepCopy()
		if err := ssc.podControl.UpdateStatefulPod(ctx, updateSet, replica); err != nil {
			return &status, err
		}
	}
	
    // 如果启用了 StatefulSetAutoDeletePVC 特性，则确保有关被删除的 Pod 的 OwnerRefs 被正确设置。
	if utilfeature.DefaultFeatureGate.Enabled(features.StatefulSetAutoDeletePVC) {
		// Ensure ownerRefs are set correctly for the condemned pods.
		for i := range condemned {
			if matchPolicy, err := ssc.podControl.ClaimsMatchRetentionPolicy(ctx, updateSet, condemned[i]); err != nil {
				return &status, err
			} else if !matchPolicy {
				if err := ssc.podControl.UpdatePodClaimForRetentionPolicy(ctx, updateSet, condemned[i]); err != nil {
					return &status, err
				}
			}
		}
	}

	// 循环遍历被判定为需要被删除的 Pod 并按照从大到小的顺序进行删除，即 monotonically decreasing order
    // 如果在 monotonic 模式下，还需要检查每个 Pod 是否满足 Running 和 Ready 的条件，以及 Available 的条件，如果不满足，则会暂停删除操作并返回
    // 更新 StatefulSet 的 Replicas 和 UpdatedReplicas 字段，并将 status 返回
	for target := len(condemned) - 1; target >= 0; target-- {
		// wait for terminating pods to expire
		if isTerminating(condemned[target]) {
			logger.V(4).Info("StatefulSet is waiting for Pod to Terminate prior to scale down",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(condemned[target]))
			// block if we are in monotonic mode
			if monotonic {
				return &status, nil
			}
			continue
		}
		// if we are in monotonic mode and the condemned target is not the first unhealthy Pod block
		if !isRunningAndReady(condemned[target]) && monotonic && condemned[target] != firstUnhealthyPod {
			logger.V(4).Info("StatefulSet is waiting for Pod to be Running and Ready prior to scale down",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(firstUnhealthyPod))
			return &status, nil
		}
		// if we are in monotonic mode and the condemned target is not the first unhealthy Pod, block.
		if !isRunningAndAvailable(condemned[target], set.Spec.MinReadySeconds) && monotonic && condemned[target] != firstUnhealthyPod {
			logger.V(4).Info("StatefulSet is waiting for Pod to be Available prior to scale down",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(firstUnhealthyPod))
			return &status, nil
		}
		logger.V(2).Info("Pod of StatefulSet is terminating for scale down",
			"statefulSet", klog.KObj(set), "pod", klog.KObj(condemned[target]))

		if err := ssc.podControl.DeleteStatefulPod(set, condemned[target]); err != nil {
			return &status, err
		}
		if getPodRevision(condemned[target]) == currentRevision.Name {
			status.CurrentReplicas--
		}
		if getPodRevision(condemned[target]) == updateRevision.Name {
			status.UpdatedReplicas--
		}
		if monotonic {
			return &status, nil
		}
	}

	// 如果 UpdateStrategy.Type 属性设置为 OnDeleteStatefulSetStrategyType，则忽略更新操作，因为这意味着需要手动删除旧的 Replica 才能进行更新
	if set.Spec.UpdateStrategy.Type == apps.OnDeleteStatefulSetStrategyType {
		return &status, nil
	}
	// 如果启用了 features.MaxUnavailableStatefulSet 特性 调用 updateStatefulSetAfterInvariantEstablished 函数进行更新操作
	if utilfeature.DefaultFeatureGate.Enabled(features.MaxUnavailableStatefulSet) {
		return updateStatefulSetAfterInvariantEstablished(ctx,
			ssc,
			set,
			replicas,
			updateRevision,
			status,
		)
	}

	// 将按照一定的策略删除一些旧的 Replica 并创建一些新的 Replica。
    // 如果发现某个 Replica 不健康，则会等待一段时间，直到它变得健康或者到达最大等待时间。
	updateMin := 0
	if set.Spec.UpdateStrategy.RollingUpdate != nil {
		updateMin = int(*set.Spec.UpdateStrategy.RollingUpdate.Partition)
	}
	// we terminate the Pod with the largest ordinal that does not match the update revision.
	for target := len(replicas) - 1; target >= updateMin; target-- {

		// delete the Pod if it is not already terminating and does not match the update revision.
		if getPodRevision(replicas[target]) != updateRevision.Name && !isTerminating(replicas[target]) {
			logger.V(2).Info("Pod of StatefulSet is terminating for update",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(replicas[target]))
			if err := ssc.podControl.DeleteStatefulPod(set, replicas[target]); err != nil {
				if !errors.IsNotFound(err) {
					return &status, err
				}
			}
			status.CurrentReplicas--
			return &status, err
		}

		// wait for unhealthy Pods on update
		if !isHealthy(replicas[target]) {
			logger.V(4).Info("StatefulSet is waiting for Pod to update",
				"statefulSet", klog.KObj(set), "pod", klog.KObj(replicas[target]))
			return &status, nil
		}

	}
	return &status, nil
}
```

###### ApplyRevision

```go
func ApplyRevision(set *apps.StatefulSet, revision *apps.ControllerRevision) (*apps.StatefulSet, error) {
	clone := set.DeepCopy()
	patched, err := strategicpatch.StrategicMergePatch([]byte(runtime.EncodeOrDie(patchCodec, clone)), revision.Data.Raw, clone)
	if err != nil {
		return nil, err
	}
	restoredSet := &apps.StatefulSet{}
	err = json.Unmarshal(patched, restoredSet)
	if err != nil {
		return nil, err
	}
	return restoredSet, nil
}

```

###### 状态

```go
// isRunningAndReady returns true if pod is in the PodRunning Phase, if it has a condition of PodReady.
func isRunningAndReady(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodRunning && podutil.IsPodReady(pod)
}

func isRunningAndAvailable(pod *v1.Pod, minReadySeconds int32) bool {
	return podutil.IsPodAvailable(pod, minReadySeconds, metav1.Now())
}

// isCreated returns true if pod has been created and is maintained by the API server
func isCreated(pod *v1.Pod) bool {
	return pod.Status.Phase != ""
}

// isPending returns true if pod has a Phase of PodPending
func isPending(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodPending
}

// isFailed returns true if pod has a Phase of PodFailed
func isFailed(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodFailed
}

// isTerminating returns true if pod's DeletionTimestamp has been set
func isTerminating(pod *v1.Pod) bool {
	return pod.DeletionTimestamp != nil
}

// isHealthy returns true if pod is running and ready and has not been terminated
func isHealthy(pod *v1.Pod) bool {
	return isRunningAndReady(pod) && !isTerminating(pod)
}
```

###### podInOrdinalRange

```GO
func podInOrdinalRange(pod *v1.Pod, set *apps.StatefulSet) bool {
	ordinal := getOrdinal(pod)
	return ordinal >= getStartOrdinal(set) && ordinal <= getEndOrdinal(set)
}
```

###### getOrdinal

```GO
func getOrdinal(pod *v1.Pod) int {
	_, ordinal := getParentNameAndOrdinal(pod)
	return ordinal
}
```

###### getStartOrdinal

```GO
func getStartOrdinal(set *apps.StatefulSet) int {
	if utilfeature.DefaultFeatureGate.Enabled(features.StatefulSetStartOrdinal) {
		if set.Spec.Ordinals != nil {
			return int(set.Spec.Ordinals.Start)
		}
	}
	return 0
}
```

###### getEndOrdinal

```GO
func getEndOrdinal(set *apps.StatefulSet) int {
	return getStartOrdinal(set) + int(*set.Spec.Replicas) - 1
}
```

###### newVersionedStatefulSetPod

```GO
func newVersionedStatefulSetPod(currentSet, updateSet *apps.StatefulSet, currentRevision, updateRevision string, ordinal int) *v1.Pod {
	if currentSet.Spec.UpdateStrategy.Type == apps.RollingUpdateStatefulSetStrategyType &&
		(currentSet.Spec.UpdateStrategy.RollingUpdate == nil && ordinal < (getStartOrdinal(currentSet)+int(currentSet.Status.CurrentReplicas))) ||
		(currentSet.Spec.UpdateStrategy.RollingUpdate != nil && ordinal < (getStartOrdinal(currentSet)+int(*currentSet.Spec.UpdateStrategy.RollingUpdate.Partition))) {
		pod := newStatefulSetPod(currentSet, ordinal)
		setPodRevision(pod, currentRevision)
		return pod
	}
	pod := newStatefulSetPod(updateSet, ordinal)
	setPodRevision(pod, updateRevision)
	return pod
}
```

###### allowsBurst

````GO
func allowsBurst(set *apps.StatefulSet) bool {
	return set.Spec.PodManagementPolicy == apps.ParallelPodManagement
}
````

###### getPodRevision

```GO
func getPodRevision(pod *v1.Pod) string {
	if pod.Labels == nil {
		return ""
	}
	return pod.Labels[apps.StatefulSetRevisionLabel]
}
```

###### newVersionedStatefulSetPod

```GO
func newVersionedStatefulSetPod(currentSet, updateSet *apps.StatefulSet, currentRevision, updateRevision string, ordinal int) *v1.Pod {
	if currentSet.Spec.UpdateStrategy.Type == apps.RollingUpdateStatefulSetStrategyType &&
		(currentSet.Spec.UpdateStrategy.RollingUpdate == nil && ordinal < (getStartOrdinal(currentSet)+int(currentSet.Status.CurrentReplicas))) ||
		(currentSet.Spec.UpdateStrategy.RollingUpdate != nil && ordinal < (getStartOrdinal(currentSet)+int(*currentSet.Spec.UpdateStrategy.RollingUpdate.Partition))) {
		pod := newStatefulSetPod(currentSet, ordinal)
		setPodRevision(pod, currentRevision)
		return pod
	}
	pod := newStatefulSetPod(updateSet, ordinal)
	setPodRevision(pod, updateRevision)
	return pod
}
```

###### newStatefulSetPod

```GO
func newStatefulSetPod(set *apps.StatefulSet, ordinal int) *v1.Pod {
	pod, _ := controller.GetPodFromTemplate(&set.Spec.Template, set, metav1.NewControllerRef(set, controllerKind))
	pod.Name = getPodName(set, ordinal)
	initIdentity(set, pod)
	updateStorage(set, pod)
	return pod
}
```

###### setPodRevision

```GO
func setPodRevision(pod *v1.Pod, revision string) {
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels[apps.StatefulSetRevisionLabel] = revision
}
```

###### updateStatefulSetAfterInvariantEstablished

```GO
func updateStatefulSetAfterInvariantEstablished(
	ctx context.Context,
	ssc *defaultStatefulSetControl,
	set *apps.StatefulSet,
	replicas []*v1.Pod,
	updateRevision *apps.ControllerRevision,
	status apps.StatefulSetStatus,
) (*apps.StatefulSetStatus, error) {

	logger := klog.FromContext(ctx)
	replicaCount := int(*set.Spec.Replicas)

	// 根据策略计算破坏性更新的目标序列的最小序数
	updateMin := 0
	maxUnavailable := 1
	if set.Spec.UpdateStrategy.RollingUpdate != nil { // 如果滚动更新策略不为空
		updateMin = int(*set.Spec.UpdateStrategy.RollingUpdate.Partition) // 获取分区的最小序数

		// 如果启用了功能，然后禁用了该功能，则 MaxUnavailable 可能具有大于 1 的值。
		// 忽略传入的值，并使用 maxUnavailable 作为 1 来强制实现当功能门不可用时的预期行为。
		var err error
		maxUnavailable, err = getStatefulSetMaxUnavailable(set.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable, replicaCount)
		if err != nil {
			return &status, err
		}
	}

	// 收集位于 getStartOrdinal(set) 和 getEndOrdinal(set) 之间的所有目标。
// 计算该范围内的目标中不健康的数量（即终止或未运行和就绪的 Pod），并将其作为不可用计数。选择
// (MaxUnavailable - Unavailable) Pods，按其序数顺序进行终止。删除这些 Pod 并计算成功删除的数量。使用正确的删除数量更新状态。
	unavailablePods := 0
	for target := len(replicas) - 1; target >= 0; target-- {
		if !isHealthy(replicas[target]) {
			unavailablePods++
		}
	}

	if unavailablePods >= maxUnavailable { // 如果不可用 Pod 数量大于等于最大不可用 Pod 数量
		logger.V(2).Info("StatefulSet found unavailablePods, more than or equal to allowed maxUnavailable",
			"statefulSet", klog.KObj(set),
			"unavailablePods", unavailablePods,
			"maxUnavailable", maxUnavailable)
		return &status, nil
	}

	// 现在我们需要删除 MaxUnavailable-unavailablePods 个 Pod，从最高序数开始逐个删除
	podsToDelete := maxUnavailable - unavailablePods

	deletedPods := 0
	for target := len(replicas) - 1; target >= updateMin && deletedPods < podsToDelete; target-- {

		// 如果该 Pod 健康，并且版本号不是更新版本，且不在终止中
		if getPodRevision(replicas[target]) != updateRevision.Name && !isTerminating(replicas[target]) {
			// delete the Pod if it is healthy and the revision doesnt match the target
			logger.V(2).Info("StatefulSet terminating Pod for update",
				"statefulSet", klog.KObj(set),
				"pod", klog.KObj(replicas[target]))
            // // 调用删除 Pod 方法
			if err := ssc.podControl.DeleteStatefulPod(set, replicas[target]); err != nil {
				if !errors.IsNotFound(err) {
					return &status, err
				}
			}
			deletedPods++
			status.CurrentReplicas--
		}
	}
	return &status, nil
}
```

###### getStatefulSetMaxUnavailable

```go
func getStatefulSetMaxUnavailable(maxUnavailable *intstr.IntOrString, replicaCount int) (int, error) {
	maxUnavailableNum, err := intstr.GetScaledValueFromIntOrPercent(intstr.ValueOrDefault(maxUnavailable, intstr.FromInt(1)), replicaCount, false)
	if err != nil {
		return 0, err
	}
	// maxUnavailable might be zero for small percentage with round down.
	// So we have to enforce it not to be less than 1.
	if maxUnavailableNum < 1 {
		maxUnavailableNum = 1
	}
	return maxUnavailableNum, nil
}

```

#### truncateHistory

```GO
func (ssc *defaultStatefulSetControl) truncateHistory(
	set *apps.StatefulSet,
	pods []*v1.Pod,
	revisions []*apps.ControllerRevision,
	current *apps.ControllerRevision,
	update *apps.ControllerRevision) error {
    // 创建一个容量为 revisions 长度的空版本历史列表
	history := make([]*apps.ControllerRevision, 0, len(revisions))
	// 标记所有活动版本
	live := map[string]bool{}
	if current != nil {
		live[current.Name] = true  // 标记当前版本
	}
	if update != nil {
		live[update.Name] = true  // 标记更新版本
	}
	for i := range pods {
		live[getPodRevision(pods[i])] = true  // 标记所有活动的 Pod 版本
	}
	// 收集活动版本和历史版本
	for i := range revisions {
		if !live[revisions[i].Name] { // 如果该版本不活动
			history = append(history, revisions[i]) // 将该版本添加到历史版本列表
		}
	}
	historyLen := len(history)
	historyLimit := int(*set.Spec.RevisionHistoryLimit)
    // 如果历史版本数量小于等于限制
	if historyLen <= historyLimit {
		return nil
	}
	// delete any non-live history to maintain the revision limit.
	history = history[:(historyLen - historyLimit)]
	for i := 0; i < len(history); i++ {
		if err := ssc.controllerHistory.DeleteControllerRevision(history[i]); err != nil {
			return err
		}
	}
	return nil
}
```

### AdoptOrphanRevisions

```go
func (ssc *defaultStatefulSetControl) AdoptOrphanRevisions(
	set *apps.StatefulSet,
	revisions []*apps.ControllerRevision) error {
	for i := range revisions {
        // 采用孤儿版本
		adopted, err := ssc.controllerHistory.AdoptControllerRevision(set, controllerKind, revisions[i])
		if err != nil {
			return err
		}
        // 用采用后的版本替换原版本
		revisions[i] = adopted
	}
	return nil
}
```

## StatefulPodControl

````go
type StatefulPodControl struct {
	objectMgr StatefulPodControlObjectManager
	recorder  record.EventRecorder
}

func NewStatefulPodControl(
	client clientset.Interface,
	podLister corelisters.PodLister,
	claimLister corelisters.PersistentVolumeClaimLister,
	recorder record.EventRecorder,
) *StatefulPodControl {
	return &StatefulPodControl{&realStatefulPodControlObjectManager{client, podLister, claimLister}, recorder}
}
````

### CreateStatefulPod

````go
func (spc *StatefulPodControl) CreateStatefulPod(ctx context.Context, set *apps.StatefulSet, pod *v1.Pod) error {
	// 在创建Pod之前先创建Pod的PVCs
	if err := spc.createPersistentVolumeClaims(set, pod); err != nil {
        // 记录Pod创建事件，包括事件类型（create）、StatefulSet、Pod以及错误信息
		spc.recordPodEvent("create", set, pod, err)
		return err
	}
	// 如果我们已经创建了PVCs，则尝试创建Pod
	err := spc.objectMgr.CreatePod(ctx, pod)
	// sink already exists errors
	if apierrors.IsAlreadyExists(err) {
		return err
	}
    // 如果StatefulSetAutoDeletePVC功能已启用，则在此时尽可能设置PVC策略
	if utilfeature.DefaultFeatureGate.Enabled(features.StatefulSetAutoDeletePVC) {
		// Set PVC policy as much as is possible at this point.
		if err := spc.UpdatePodClaimForRetentionPolicy(ctx, set, pod); err != nil {
			spc.recordPodEvent("update", set, pod, err)
			return err
		}
	}
	spc.recordPodEvent("create", set, pod, err)
	return err
}
````

### UpdateStatefulPod

```go
func (spc *StatefulPodControl) UpdateStatefulPod(ctx context.Context, set *apps.StatefulSet, pod *v1.Pod) error {
	attemptedUpdate := false
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// 假设Pod是一致的
		consistent := true
		// 如果Pod不符合其标识符，则更新标识符并污染Pod
		if !identityMatches(set, pod) {
			updateIdentity(set, pod)
			consistent = false
		}
		// 如果Pod不符合StatefulSet的存储要求，则更新Pod的PVC，污染Pod，并创建任何丢失的PVC
		if !storageMatches(set, pod) {
			updateStorage(set, pod)
			consistent = false
			if err := spc.createPersistentVolumeClaims(set, pod); err != nil {
                // 记录更新Pod的PVC的事件，包括事件类型（update）、StatefulSet、Pod以及错误信息
				spc.recordPodEvent("update", set, pod, err)
				return err
			}
		}
		if utilfeature.DefaultFeatureGate.Enabled(features.StatefulSetAutoDeletePVC) {
			// 如果StatefulSetAutoDeletePVC功能已启用，则检查Pod的PVC是否与StatefulSet的PVC删除策略一致
			if match, err := spc.ClaimsMatchRetentionPolicy(ctx, set, pod); err != nil {
				spc.recordPodEvent("update", set, pod, err)
				return err
			} else if !match {
				if err := spc.UpdatePodClaimForRetentionPolicy(ctx, set, pod); err != nil {
					spc.recordPodEvent("update", set, pod, err)
					return err
				}
				consistent = false
			}
		}

		// 如果Pod不是污染的，则不做任何操作
		if consistent {
			return nil
		}

		attemptedUpdate = true
		// 提交更新，如果冲突则重试

		updateErr := spc.objectMgr.UpdatePod(pod)
		if updateErr == nil {
			return nil
		}

		if updated, err := spc.objectMgr.GetPod(set.Namespace, pod.Name); err == nil {
			// 复制Pod，以避免修改共享缓存
			pod = updated.DeepCopy()
		} else {
			utilruntime.HandleError(fmt.Errorf("error getting updated Pod %s/%s: %w", set.Namespace, pod.Name, err))
		}

		return updateErr
	})
	if attemptedUpdate {
        // 记录更新Pod的事件，包括事件类型（update）、StatefulSet、Pod以及错误信息
		spc.recordPodEvent("update", set, pod, err)
	}
	return err
}
```

### DeleteStatefulPod

```go
func (spc *StatefulPodControl) DeleteStatefulPod(set *apps.StatefulSet, pod *v1.Pod) error {
	err := spc.objectMgr.DeletePod(pod)
	spc.recordPodEvent("delete", set, pod, err)
	return err
}
```

### ClaimsMatchRetentionPolicy

```go
func (spc *StatefulPodControl) ClaimsMatchRetentionPolicy(ctx context.Context, set *apps.StatefulSet, pod *v1.Pod) (bool, error) {
	ordinal := getOrdinal(pod) // 获取 Pod 的序号，用于确定其 PVC 名称
	templates := set.Spec.VolumeClaimTemplates // 获取 StatefulSet 中声明的 PVC 模板
	for i := range templates { // 遍历 PVC 模板
		claimName := getPersistentVolumeClaimName(set, &templates[i], ordinal) // 获取当前 PVC 的名称
		claim, err := spc.objectMgr.GetClaim(set.Namespace, claimName) // 获取当前 PVC 对应的 PersistentVolumeClaim 对象
		switch {
		case apierrors.IsNotFound(err): // 如果当前 PVC 不存在
			klog.FromContext(ctx).V(4).Info("Expected claim missing, continuing to pick up in next iteration", "PVC", klog.KObj(claim))
		case err != nil: // 如果出现其他错误
			return false, fmt.Errorf("Could not retrieve claim %s for %s when checking PVC deletion policy", claimName, pod.Name)
		default: // 如果成功获取当前 PVC 对应的 PersistentVolumeClaim 对象
			if !claimOwnerMatchesSetAndPod(claim, set, pod) { // 检查 PVC 的所有者是否与 StatefulSet 和 Pod 匹配
				return false, nil
			}
		}
	}
	return true, nil // 如果所有 PVC 都满足保留策略，返回 true
}
```

### UpdatePodClaimForRetentionPolicy

```GO
func (spc *StatefulPodControl) UpdatePodClaimForRetentionPolicy(ctx context.Context, set *apps.StatefulSet, pod *v1.Pod) error {
	logger := klog.FromContext(ctx)
	ordinal := getOrdinal(pod) // 获取 Pod 的序号，用于确定其 PVC 名称
	templates := set.Spec.VolumeClaimTemplates // 获取 StatefulSet 中声明的 PVC 模板
	for i := range templates { // 遍历 PVC 模板
		claimName := getPersistentVolumeClaimName(set, &templates[i], ordinal) // 获取当前 PVC 的名称
		claim, err := spc.objectMgr.GetClaim(set.Namespace, claimName) // 获取当前 PVC 对应的 PersistentVolumeClaim 对象
		switch {
		case apierrors.IsNotFound(err): // 如果当前 PVC 不存在
			logger.V(4).Info("Expected claim missing, continuing to pick up in next iteration", "PVC", klog.KObj(claim))
		case err != nil: // 如果出现其他错误
			return fmt.Errorf("Could not retrieve claim %s not found for %s when checking PVC deletion policy: %w", claimName, pod.Name, err)
		default: // 如果成功获取当前 PVC 对应的 PersistentVolumeClaim 对象
			if !claimOwnerMatchesSetAndPod(claim, set, pod) { // 检查 PVC 的所有者是否与 StatefulSet 和 Pod 匹配
				claim = claim.DeepCopy() // 复制一份 PVC 对象，避免修改共享的缓存
				needsUpdate := updateClaimOwnerRefForSetAndPod(claim, set, pod) // 更新 PVC 的所有者引用
				if needsUpdate { // 如果需要更新
					err := spc.objectMgr.UpdateClaim(claim) // 更新 PVC 对象
					if err != nil { // 如果更新失败
						return fmt.Errorf("Could not update claim %s for delete policy ownerRefs: %w", claimName, err)
					}
				}
			}
		}
	}
	return nil // 更新成功，返回 nil
}
```

### PodClaimIsStale

```GO
func (spc *StatefulPodControl) PodClaimIsStale(set *apps.StatefulSet, pod *v1.Pod) (bool, error) {
	policy := getPersistentVolumeClaimRetentionPolicy(set) // 获取 StatefulSet 中定义的 PVC 保留策略
	if policy.WhenScaled == apps.RetainPersistentVolumeClaimRetentionPolicyType {
		// 如果 PVC 保留策略为 Retain，则 PVC 不会过时，直接返回 false
		return false, nil
	}
	for _, claim := range getPersistentVolumeClaims(set, pod) { // 获取与 Pod 关联的 PVC
		pvc, err := spc.objectMgr.GetClaim(claim.Namespace, claim.Name) // 获取当前 PVC 对应的 PersistentVolumeClaim 对象
		switch {
		case apierrors.IsNotFound(err):
			// 如果当前 PVC 不存在，则不会过时，继续检查下一个 PVC
			continue
		case err != nil:
			return false, err
		case err == nil:
			// 如果 Pod 的 UID 与 PVC 的所有者引用不匹配，则 PVC 过时
			if hasStaleOwnerRef(pvc, pod) {
				return true, nil
			}
		}
	}
	return false, nil // 所有 PVC 都不过时，返回 false
}
```

### recordPodEvent

```GO
func (spc *StatefulPodControl) recordPodEvent(verb string, set *apps.StatefulSet, pod *v1.Pod, err error) {
	if err == nil { // 如果没有错误
		reason := fmt.Sprintf("Successful%s", strings.Title(verb)) // 设置事件的原因
		message := fmt.Sprintf("%s Pod %s in StatefulSet %s successful",
			strings.ToLower(verb), pod.Name, set.Name) // 设置事件的消息
		spc.recorder.Event(set, v1.EventTypeNormal, reason, message) // 记录事件（类型为 Normal）
	} else { // 如果有错误
		reason := fmt.Sprintf("Failed%s", strings.Title(verb)) // 设置事件的原因
		message := fmt.Sprintf("%s Pod %s in StatefulSet %s failed error: %s",
			strings.ToLower(verb), pod.Name, set.Name, err) // 设置事件的消息
		spc.recorder.Event(set, v1.EventTypeWarning, reason, message) // 记录事件（类型为 Warning）
	}
}
```

### recordClaimEvent

```GO
func (spc *StatefulPodControl) recordPodEvent(verb string, set *apps.StatefulSet, pod *v1.Pod, err error) {
	if err == nil { // 如果没有错误
		reason := fmt.Sprintf("Successful%s", strings.Title(verb)) // 设置事件的原因
		message := fmt.Sprintf("%s Pod %s in StatefulSet %s successful",
			strings.ToLower(verb), pod.Name, set.Name) // 设置事件的消息
		spc.recorder.Event(set, v1.EventTypeNormal, reason, message) // 记录事件（类型为 Normal）
	} else { // 如果有错误
		reason := fmt.Sprintf("Failed%s", strings.Title(verb)) // 设置事件的原因
		message := fmt.Sprintf("%s Pod %s in StatefulSet %s failed error: %s",
			strings.ToLower(verb), pod.Name, set.Name, err) // 设置事件的消息
		spc.recorder.Event(set, v1.EventTypeWarning, reason, message) // 记录事件（类型为 Warning）
	}
}
```

### createMissingPersistentVolumeClaims

```GO
func (spc *StatefulPodControl) createMissingPersistentVolumeClaims(ctx context.Context, set *apps.StatefulSet, pod *v1.Pod) error {
	if err := spc.createPersistentVolumeClaims(set, pod); err != nil { // 调用 spc.createPersistentVolumeClaims() 方法创建 PVC，如果出错则返回错误
		return err
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.StatefulSetAutoDeletePVC) { // 如果 StatefulSetAutoDeletePVC 特性门户启用
		// Set PVC policy as much as is possible at this point.
		if err := spc.UpdatePodClaimForRetentionPolicy(ctx, set, pod); err != nil { // 更新 PVC 的保留策略
			spc.recordPodEvent("update", set, pod, err) // 记录事件
			return err
		}
	}
	return nil // 创建 PVC 成功，返回 nil
}

```

### createPersistentVolumeClaims

```GO
func (spc *StatefulPodControl) createPersistentVolumeClaims(set *apps.StatefulSet, pod *v1.Pod) error {
	var errs []error // 用于保存所有错误
	for _, claim := range getPersistentVolumeClaims(set, pod) { // 获取与 Pod 关联的 PVC
		pvc, err := spc.objectMgr.GetClaim(claim.Namespace, claim.Name) // 获取当前 PVC 对应的 PersistentVolumeClaim 对象
		switch {
		case apierrors.IsNotFound(err): // 如果对象不存在
			err := spc.objectMgr.CreateClaim(&claim) // 创建 PVC
			if err != nil { // 如果创建失败，则记录错误
				errs = append(errs, fmt.Errorf("failed to create PVC %s: %s", claim.Name, err))
			}
			if err == nil || !apierrors.IsAlreadyExists(err) { // 如果创建成功或者 PVC 已存在，则记录事件
				spc.recordClaimEvent("create", set, pod, &claim, err)
			}
		case err != nil: // 如果出现其他错误，则记录错误和事件
			errs = append(errs, fmt.Errorf("failed to retrieve PVC %s: %s", claim.Name, err))
			spc.recordClaimEvent("create", set, pod, &claim, err)
		default: // 如果 PVC 已存在
			if pvc.DeletionTimestamp != nil { // 如果 PVC 正在被删除，则记录错误
				errs = append(errs, fmt.Errorf("pvc %s is being deleted", claim.Name))
			}
		}
		// TODO: Check resource requirements and accessmodes, update if necessary
	}
	return errorutils.NewAggregate(errs) // 如果有错误，则返回一个 AggregateError，否则返回 nil
}
```

## StatefulPodControlObjectManager

```GO
type StatefulPodControlObjectManager interface {
	CreatePod(ctx context.Context, pod *v1.Pod) error
	GetPod(namespace, podName string) (*v1.Pod, error)
	UpdatePod(pod *v1.Pod) error
	DeletePod(pod *v1.Pod) error
	CreateClaim(claim *v1.PersistentVolumeClaim) error
	GetClaim(namespace, claimName string) (*v1.PersistentVolumeClaim, error)
	UpdateClaim(claim *v1.PersistentVolumeClaim) error
}
```

```GO
// NewStatefulPodControlFromManager creates a StatefulPodControl using the given StatefulPodControlObjectManager and recorder.
func NewStatefulPodControlFromManager(om StatefulPodControlObjectManager, recorder record.EventRecorder) *StatefulPodControl {
	return &StatefulPodControl{om, recorder}
}

// realStatefulPodControlObjectManager uses a clientset.Interface and listers.
type realStatefulPodControlObjectManager struct {
	client      clientset.Interface
	podLister   corelisters.PodLister
	claimLister corelisters.PersistentVolumeClaimLister
}
```

### 方法

```GO
func (om *realStatefulPodControlObjectManager) CreatePod(ctx context.Context, pod *v1.Pod) error {
	_, err := om.client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

func (om *realStatefulPodControlObjectManager) GetPod(namespace, podName string) (*v1.Pod, error) {
	return om.podLister.Pods(namespace).Get(podName)
}

func (om *realStatefulPodControlObjectManager) UpdatePod(pod *v1.Pod) error {
	_, err := om.client.CoreV1().Pods(pod.Namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
	return err
}

func (om *realStatefulPodControlObjectManager) DeletePod(pod *v1.Pod) error {
	return om.client.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
}

func (om *realStatefulPodControlObjectManager) CreateClaim(claim *v1.PersistentVolumeClaim) error {
	_, err := om.client.CoreV1().PersistentVolumeClaims(claim.Namespace).Create(context.TODO(), claim, metav1.CreateOptions{})
	return err
}

func (om *realStatefulPodControlObjectManager) GetClaim(namespace, claimName string) (*v1.PersistentVolumeClaim, error) {
	return om.claimLister.PersistentVolumeClaims(namespace).Get(claimName)
}

func (om *realStatefulPodControlObjectManager) UpdateClaim(claim *v1.PersistentVolumeClaim) error {
	_, err := om.client.CoreV1().PersistentVolumeClaims(claim.Namespace).Update(context.TODO(), claim, metav1.UpdateOptions{})
	return err
}
```

## New

```go
func NewStatefulSetController(
	ctx context.Context,
	podInformer coreinformers.PodInformer,
	setInformer appsinformers.StatefulSetInformer,
	pvcInformer coreinformers.PersistentVolumeClaimInformer,
	revInformer appsinformers.ControllerRevisionInformer,
	kubeClient clientset.Interface,
) *StatefulSetController {
	logger := klog.FromContext(ctx)
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "statefulset-controller"})
	ssc := &StatefulSetController{
		kubeClient: kubeClient,
		control: NewDefaultStatefulSetControl(
			NewStatefulPodControl(
				kubeClient,
				podInformer.Lister(),
				pvcInformer.Lister(),
				recorder),
			NewRealStatefulSetStatusUpdater(kubeClient, setInformer.Lister()),
			history.NewHistory(kubeClient, revInformer.Lister()),
			recorder,
		),
		pvcListerSynced: pvcInformer.Informer().HasSynced,
		revListerSynced: revInformer.Informer().HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "statefulset"),
		podControl:      controller.RealPodControl{KubeClient: kubeClient, Recorder: recorder},

		eventBroadcaster: eventBroadcaster,
	}
	// 监控pod
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		// lookup the statefulset and enqueue
		AddFunc: func(obj interface{}) {
			ssc.addPod(logger, obj)
		},
		// lookup current and old statefulset if labels changed
		UpdateFunc: func(oldObj, newObj interface{}) {
			ssc.updatePod(logger, oldObj, newObj)
		},
		// lookup statefulset accounting for deletion tombstones
		DeleteFunc: func(obj interface{}) {
			ssc.deletePod(logger, obj)
		},
	})
	ssc.podLister = podInformer.Lister()
	ssc.podListerSynced = podInformer.Informer().HasSynced
	// 监控statefulset
	setInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: ssc.enqueueStatefulSet,
			UpdateFunc: func(old, cur interface{}) {
				oldPS := old.(*apps.StatefulSet)
				curPS := cur.(*apps.StatefulSet)
				if oldPS.Status.Replicas != curPS.Status.Replicas {
					logger.V(4).Info("Observed updated replica count for StatefulSet", "statefulSet", klog.KObj(curPS), "oldReplicas", oldPS.Status.Replicas, "newReplicas", curPS.Status.Replicas)
				}
				ssc.enqueueStatefulSet(cur)
			},
			DeleteFunc: ssc.enqueueStatefulSet,
		},
	)
	ssc.setLister = setInformer.Lister()
	ssc.setListerSynced = setInformer.Informer().HasSynced

	// TODO: Watch volumes
	return ssc
}
```

### 队列相关

#### pod

```go
func (ssc *StatefulSetController) addPod(logger klog.Logger, obj interface{}) {
	pod := obj.(*v1.Pod)
	//检查Pod对象是否已经被标记为删除
	if pod.DeletionTimestamp != nil {
		// 如果控制器管理器重新启动，并且某个处于已挂起删除状态的 Pod 在新启动的控制器管理器上被发现，
   	    // 则会防止该 Pod 成为创建观察结果。直接调用 deletePod 方法删除 Pod
		ssc.deletePod(logger, pod)
		return
	}

	// 如果 Pod 对象已经被某个控制器所控制，则只关注其 ControllerRef
	if controllerRef := metav1.GetControllerOf(pod); controllerRef != nil {
        //根据 pod 的 namespace 和 controllerRef 获取对应的 StatefulSet 控制器
		set := ssc.resolveControllerRef(pod.Namespace, controllerRef)
		if set == nil {
			return
		}
        //如果获取到 StatefulSet 控制器，则将其加入到队列中，以便后续处理
		logger.V(4).Info("Pod created with labels", "pod", klog.KObj(pod), "labels", pod.Labels)
		ssc.enqueueStatefulSet(set)
		return
	}

	//否则，该 Pod 是孤立的，需要获取与其匹配的所有控制器，并将其加入到队列中以便后续处理
	sets := ssc.getStatefulSetsForPod(pod)
	if len(sets) == 0 {
		return
	}
	logger.V(4).Info("Orphan Pod created with labels", "pod", klog.KObj(pod), "labels", pod.Labels)
	for _, set := range sets {
		ssc.enqueueStatefulSet(set)
	}
}

func (ssc *StatefulSetController) updatePod(logger klog.Logger, old, cur interface{}) {
	curPod := cur.(*v1.Pod)
	oldPod := old.(*v1.Pod)
	if curPod.ResourceVersion == oldPod.ResourceVersion {
		// 在重新列出 Pod 时，我们可能会收到所有已知 Pod 的更新事件。
		// 两个不同版本的同一个 Pod 将始终具有不同的 ResourceVersion。
		return
	}
	//检查标签是否有变化
	labelChanged := !reflect.DeepEqual(curPod.Labels, oldPod.Labels)

	curControllerRef := metav1.GetControllerOf(curPod) //获取当前 Pod 控制器的 ControllerRef
	oldControllerRef := metav1.GetControllerOf(oldPod) //获取旧 Pod 控制器的 ControllerRef
    //检查控制器的 ControllerRef 是否有变化
	controllerRefChanged := !reflect.DeepEqual(curControllerRef, oldControllerRef)
	if controllerRefChanged && oldControllerRef != nil {
		// ControllerRef 已更改。同步旧控制器（如果有）。
		if set := ssc.resolveControllerRef(oldPod.Namespace, oldControllerRef); set != nil {
			ssc.enqueueStatefulSet(set)
		}
	}

	// 如果它有 ControllerRef，那么这就是所有重要的事情。
	if curControllerRef != nil {
		set := ssc.resolveControllerRef(curPod.Namespace, curControllerRef)
		if set == nil {
			return
		}
		logger.V(4).Info("Pod objectMeta updated", "pod", klog.KObj(curPod), "oldObjectMeta", oldPod.ObjectMeta, "newObjectMeta", curPod.ObjectMeta)
		ssc.enqueueStatefulSet(set)
		// TODO: MinReadySeconds in the Pod will generate an Available condition to be added in
		// the Pod status which in turn will trigger a requeue of the owning replica set thus
		// having its status updated with the newly available replica.
		if !podutil.IsPodReady(oldPod) && podutil.IsPodReady(curPod) && set.Spec.MinReadySeconds > 0 {
			logger.V(2).Info("StatefulSet will be enqueued after minReadySeconds for availability check", "statefulSet", klog.KObj(set), "minReadySeconds", set.Spec.MinReadySeconds)
			// 添加一秒钟以避免 AddAfter 中的毫秒偏移。
			// See https://github.com/kubernetes/kubernetes/issues/39785#issuecomment-279959133 for more info.
			ssc.enqueueSSAfter(set, (time.Duration(set.Spec.MinReadySeconds)*time.Second)+time.Second)
		}
		return
	}

	// 否则，它是一个孤立的 Pod。如果发生任何更改，则同步匹配的控制器以查看是否有任何控制器现在想要采用它。
	if labelChanged || controllerRefChanged {
        //获取与当前 Pod 匹配的 StatefulSet 控制器列表
		sets := ssc.getStatefulSetsForPod(curPod)
		if len(sets) == 0 {
			return
		}
		logger.V(4).Info("Orphan Pod objectMeta updated", "pod", klog.KObj(curPod), "oldObjectMeta", oldPod.ObjectMeta, "newObjectMeta", curPod.ObjectMeta)
		for _, set := range sets {
			ssc.enqueueStatefulSet(set)
		}
	}
}

func (ssc *StatefulSetController) deletePod(logger klog.Logger, obj interface{}) {
	pod, ok := obj.(*v1.Pod)

	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %+v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a pod %+v", obj))
			return
		}
	}

	controllerRef := metav1.GetControllerOf(pod)
	if controllerRef == nil {
		//没有控制器关心被删除的孤儿 Pod
		return
	}
    //获取对应的 StatefulSet 控制器
	set := ssc.resolveControllerRef(pod.Namespace, controllerRef)
	if set == nil {
		return
	}
	logger.V(4).Info("Pod deleted.", "pod", klog.KObj(pod), "caller", utilruntime.GetCaller())
	ssc.enqueueStatefulSet(set)
}

```

##### resolveControllerRef

```GO
func (ssc *StatefulSetController) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *apps.StatefulSet {
	//我们无法通过 UID 查找，因此先按名称查找，然后验证 UID。
	//如果 Kind 不正确，甚至不要尝试按名称查找。
	if controllerRef.Kind != controllerKind.Kind {
		return nil
	}
    //根据 namespace 和名称查找对应的 StatefulSet 控制器
	set, err := ssc.setLister.StatefulSets(namespace).Get(controllerRef.Name)
	if err != nil {
		return nil
	}
	if set.UID != controllerRef.UID {
		//我们找到的控制器与 ControllerRef 指向的控制器不同。
		return nil
	}
	return set
}
```

##### enqueueStatefulSet

```GO
func (ssc *StatefulSetController) enqueueStatefulSet(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	ssc.queue.Add(key)
}
```

##### getStatefulSetsForPod

```GO
func (ssc *StatefulSetController) getStatefulSetsForPod(pod *v1.Pod) []*apps.StatefulSet {
    //获取与当前 Pod 匹配的 StatefulSet 控制器列表
	sets, err := ssc.setLister.GetPodStatefulSets(pod)
	if err != nil {
		return nil
	}
	// 如果有多个控制器选择同一个 Pod，这将构成用户错误。
	if len(sets) > 1 {
		// ControllerRef 将确保我们不会做任何疯狂的事情，但这个列表中的多个项目仍然构成了用户错误。
		setNames := []string{}
		for _, s := range sets {
			setNames = append(setNames, s.Name)
		}
		utilruntime.HandleError(
			fmt.Errorf(
				"user error: more than one StatefulSet is selecting pods with labels: %+v. Sets: %v",
				pod.Labels, setNames))
	}
	return sets
}
```

#### statefulset

```GO
func (ssc *StatefulSetController) enqueueStatefulSet(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	ssc.queue.Add(key)
}

func (ssc *StatefulSetController) enqueueStatefulSet(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	ssc.queue.Add(key)
}
```

## Run

```go
func (ssc *StatefulSetController) worker(ctx context.Context) {
	for ssc.processNextWorkItem(ctx) {
	}
}

func (ssc *StatefulSetController) processNextWorkItem(ctx context.Context) bool {
	key, quit := ssc.queue.Get()
	if quit {
		return false
	}
	defer ssc.queue.Done(key)
	if err := ssc.sync(ctx, key.(string)); err != nil {
		utilruntime.HandleError(fmt.Errorf("error syncing StatefulSet %v, requeuing: %v", key.(string), err))
		ssc.queue.AddRateLimited(key)
	} else {
		ssc.queue.Forget(key)
	}
	return true
}
```

## sync

```go
func (ssc *StatefulSetController) sync(ctx context.Context, key string) error {
	startTime := time.Now()
	logger := klog.FromContext(ctx)
	defer func() {
		logger.V(4).Info("Finished syncing statefulset", "key", key, "time", time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	set, err := ssc.setLister.StatefulSets(namespace).Get(name)
	if errors.IsNotFound(err) {
		logger.Info("StatefulSet has been deleted", "key", key)
		return nil
	}
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to retrieve StatefulSet %v from store: %v", key, err))
		return err
	}

	selector, err := metav1.LabelSelectorAsSelector(set.Spec.Selector)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error converting StatefulSet %v selector: %v", key, err))
		// 这是一个不可恢复的错误，不要重试。
		return nil
	}
	 //处理 StatefulSet 控制器孤立的副本集
	if err := ssc.adoptOrphanRevisions(ctx, set); err != nil {
		return err
	}
	//获取与当前 StatefulSet 控制器匹配的 Pod 列表
	pods, err := ssc.getPodsForStatefulSet(ctx, set, selector)
	if err != nil {
		return err
	}
	//调用 syncStatefulSet 方法同步 StatefulSet 控制器和 Pod 列表
	return ssc.syncStatefulSet(ctx, set, pods)
}
```

#### adoptOrphanRevisions

```go
// adoptOrphanRevisions 会检查给定 StatefulSet 的所有修订版本，如果某个修订版本没有被其他控制器控制，则将该修订版本转换为当前控制器的控制下。
func (ssc *StatefulSetController) adoptOrphanRevisions(ctx context.Context, set *apps.StatefulSet) error {
    // ListRevisions 方法返回给定 StatefulSet 的所有修订版本
    revisions, err := ssc.control.ListRevisions(set)
    if err != nil {
        return err
    }
    // 用于存储孤立的修订版本
    orphanRevisions := make([]*apps.ControllerRevision, 0)
    for i := range revisions {
        // 如果当前修订版本没有被其他控制器控制，则将该修订版本添加到 orphanRevisions 列表中
        if metav1.GetControllerOf(revisions[i]) == nil {
            orphanRevisions = append(orphanRevisions, revisions[i])
        }
    }
    // 如果存在孤立的修订版本，则检查当前控制器是否能够接管它们
    if len(orphanRevisions) > 0 {
        canAdoptErr := ssc.canAdoptFunc(ctx, set)(ctx)
        if canAdoptErr != nil {
            return fmt.Errorf("can't adopt ControllerRevisions: %v", canAdoptErr)
        }
        // AdoptOrphanRevisions 方法将孤立的修订版本转换为当前控制器的控制下
        return ssc.control.AdoptOrphanRevisions(set, orphanRevisions)
    }
    return nil
}
```

##### canAdoptFunc

```GO
// canAdoptFunc 返回一个函数，用于检查给定 StatefulSet 是否可以被当前控制器接管。
func (ssc *StatefulSetController) canAdoptFunc(ctx context.Context, set *apps.StatefulSet) func(ctx2 context.Context) error {
    // 返回一个函数，该函数使用 RecheckDeletionTimestamp 函数封装，用于检查给定 StatefulSet 是否可以被当前控制器接管。
    return controller.RecheckDeletionTimestamp(func(ctx context.Context) (metav1.Object, error) {
        // 获取最新的 StatefulSet 对象
        fresh, err := ssc.kubeClient.AppsV1().StatefulSets(set.Namespace).Get(ctx, set.Name, metav1.GetOptions{})
        if err != nil {
            return nil, err
        }
        // 检查最新的 StatefulSet 对象是否与原始的 StatefulSet 对象具有相同的 UID
        if fresh.UID != set.UID {
            return nil, fmt.Errorf("original StatefulSet %v/%v is gone: got uid %v, wanted %v", set.Namespace, set.Name, fresh.UID, set.UID)
        }
        return fresh, nil
    })
}
```

#### getPodsForStatefulSet

```GO
// getPodsForStatefulSet 返回与给定 StatefulSet 相关联的 Pod 对象列表。
func (ssc *StatefulSetController) getPodsForStatefulSet(ctx context.Context, set *apps.StatefulSet, selector labels.Selector) ([]*v1.Pod, error) {
    // 获取给定 Namespace 中的所有 Pod 对象
    pods, err := ssc.podLister.Pods(set.Namespace).List(labels.Everything())
    if err != nil {
        return nil, err
    }

    // 定义一个过滤函数，用于过滤出与给定 StatefulSet 相关联的 Pod 对象
    filter := func(pod *v1.Pod) bool {
        // 只有 Pod 的 OwnerReference 包含当前 StatefulSet 的信息时才返回 true
        return isMemberOf(set, pod)
    }

    // 创建一个 PodControllerRefManager 对象，用于管理 Pod 对象的 OwnerReference
    cm := controller.NewPodControllerRefManager(ssc.podControl, set, selector, controllerKind, ssc.canAdoptFunc(ctx, set))
    // ClaimPods 方法将 Pod 对象的 OwnerReference 设置为当前 StatefulSet，同时过滤出与 StatefulSet 相关联的 Pod 对象并返回它们的列表
    return cm.ClaimPods(ctx, pods, filter)
}
```

#### syncStatefulSet

```GO
// syncStatefulSet 用于同步 StatefulSet 对象和与之相关联的 Pod 对象。
func (ssc *StatefulSetController) syncStatefulSet(ctx context.Context, set *apps.StatefulSet, pods []*v1.Pod) error {
    logger := klog.FromContext(ctx)
    logger.V(4).Info("Syncing StatefulSet with pods", "statefulSet", klog.KObj(set), "pods", len(pods))
    var status *apps.StatefulSetStatus
    var err error
    // 调用 control 包中的 UpdateStatefulSet 方法更新 StatefulSet 对象和与之相关联的 Pod 对象
    status, err = ssc.control.UpdateStatefulSet(ctx, set, pods)
    if err != nil {
        return err
    }
    logger.V(4).Info("Successfully synced StatefulSet", "statefulSet", klog.KObj(set))
    // 处理时钟偏差，如果 set.Spec.MinReadySeconds 大于 0 且 status.AvailableReplicas 不等于 set.Spec.Replicas，则再次同步 StatefulSet
    if set.Spec.MinReadySeconds > 0 && status != nil && status.AvailableReplicas != *set.Spec.Replicas {
        ssc.enqueueSSAfter(set, time.Duration(set.Spec.MinReadySeconds)*time.Second)
    }

    return nil
}
```

