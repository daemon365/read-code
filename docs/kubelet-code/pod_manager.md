---
id: 7-kubelet-code 
title: pod-manager 代码走读
description: pod-manager 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## interface

```GO
// Manager存储并管理对Pod的访问，维护静态Pod和镜像Pod之间的映射关系。
// kubelet从3个来源发现Pod更新：文件、HTTP和API服务器。来自非API服务器来源的Pod称为静态Pod，API服务器不知道静态Pod的存在。为了监视这些Pod的状态，kubelet通过API服务器为每个静态Pod创建一个镜像Pod。
// 镜像Pod与其静态对应Pod具有相同的完整名称（名称和命名空间），尽管元数据（如UID等）不同。通过利用kubelet使用Pod的完整名称报告Pod状态的事实，镜像Pod的状态始终反映静态Pod的实际状态。当删除静态Pod时，关联的孤立的镜像Pod也将被删除。
type Manager interface {
	// GetPodByFullName根据完整名称返回与之匹配的（非镜像）Pod，以及是否找到Pod的信息。
	GetPodByFullName(podFullName string) (*v1.Pod, bool)
	// GetPodByName根据命名空间和名称返回与之匹配的（非镜像）Pod，以及是否找到Pod的信息。
	GetPodByName(namespace, name string) (*v1.Pod, bool)
	// GetPodByUID根据Pod的UID返回与之匹配的（非镜像）Pod，以及是否找到Pod的信息。
	GetPodByUID(types.UID) (*v1.Pod, bool)
	// GetPodByMirrorPod返回给定镜像Pod的静态Pod和它是否为Pod管理器所知的信息。
	GetPodByMirrorPod(*v1.Pod) (*v1.Pod, bool)
	// GetMirrorPodByPod返回给定静态Pod的镜像Pod和它是否为Pod管理器所知的信息。
	GetMirrorPodByPod(*v1.Pod) (*v1.Pod, bool)
	// GetPodAndMirrorPod返回Pod的补充信息 - 如果提供了一个Pod并且能找到相应的镜像Pod，则返回它。如果提供了一个镜像Pod并且能找到相应的Pod，则返回Pod和true作为wasMirror。
	GetPodAndMirrorPod(*v1.Pod) (pod, mirrorPod *v1.Pod, wasMirror bool)
	// GetPods返回绑定到kubelet的常规Pod及其规范。
	GetPods() []*v1.Pod

	// GetPodsAndMirrorPods返回Pod集合、镜像Pod集合以及任何孤立镜像Pod的Pod完整名称。
	GetPodsAndMirrorPods() (allPods []*v1.Pod, allMirrorPods []*v1.Pod, orphanedMirrorPodFullnames []string)

	// SetPods替换内部Pod集合为新的Pod集合。
	// 目前仅用于测试。
	SetPods(pods []*v1.Pod)
	// AddPod将给定的Pod添加到管理器中。
	AddPod(pod *v1.Pod)
	// UpdatePod更新管理器中给定的Pod。
	UpdatePod(pod *v1.Pod)
	// RemovePod从管理器中删除给定的Pod。对于镜像Pod，这意味着删除与镜像Pod相关的映射关系。对于非镜像Pod，这意味着从所有非镜像Pod的索引中删除。
	RemovePod(pod *v1.Pod)

	// TranslatePodUID返回Pod的实际UID。如果UID属于镜像Pod，则返回其静态Pod的UID。否则，返回原始UID。
	//
	// 所有公共函数应对UID执行此转换，因为用户可能提供镜像Pod的UID，这在内部Kubelet函数中不被识别。
	TranslatePodUID(uid types.UID) kubetypes.ResolvedPodUID
	// GetUIDTranslations返回静态Pod UID到镜像Pod UID和镜像Pod UID到静态Pod UID的映射。
	GetUIDTranslations() (podToMirror map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID, mirrorToPod map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID)
}
```

## basicManager

```GO
// basicManager是一个功能性的Manager。
// basicManager中的所有字段都是只读的，并通过调用SetPods、AddPod、UpdatePod或RemovePod进行更新。
type basicManager struct {
	// 保护所有内部映射的锁。
	lock sync.RWMutex

	// 以UID为索引的常规Pod。
	podByUID map[kubetypes.ResolvedPodUID]*v1.Pod
	// 以UID为索引的镜像Pod。
	mirrorPodByUID map[kubetypes.MirrorPodUID]*v1.Pod

	// 以完整名称为索引的Pod，以便进行快速访问。
	podByFullName       map[string]*v1.Pod
	mirrorPodByFullName map[string]*v1.Pod

	// 镜像Pod UID到Pod UID的映射。
	translationByUID map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID
}

// NewBasicPodManager返回一个功能性的Manager。
func NewBasicPodManager() Manager {
	pm := &basicManager{}
	pm.SetPods(nil)
	return pm
}
```

### MirrorClient

```go
// MirrorClient知道如何在API服务器中创建/删除镜像Pod。
type MirrorClient interface {
	// CreateMirrorPod在API服务器中为给定的Pod创建一个镜像Pod，
	// 或者返回一个错误。镜像Pod将具有与给定Pod相同的注释，
	// 以及一个额外的注释，其中包含静态Pod的哈希值。
	CreateMirrorPod(pod *v1.Pod) error

	// DeleteMirrorPod从API服务器中删除具有给定全名的镜像Pod，
	// 或者返回一个错误。
	DeleteMirrorPod(podFullName string, uid *types.UID) (bool, error)
}
```

```go
// basicMirrorClient是一个功能性的MirrorClient。
// 镜像Pod直接存储在kubelet中，因为它们需要与内部Pod保持同步。
type basicMirrorClient struct {
	apiserverClient clientset.Interface
	nodeGetter      nodeGetter
	nodeName        string
}

// NewBasicMirrorClient返回一个新的MirrorClient。
func NewBasicMirrorClient(apiserverClient clientset.Interface, nodeName string, nodeGetter nodeGetter) MirrorClient {
	return &basicMirrorClient{
		apiserverClient: apiserverClient,
		nodeName:        nodeName,
		nodeGetter:      nodeGetter,
	}
}

// nodeGetter是NodeLister的子集，为测试简化了功能。
type nodeGetter interface {
	// Get检索给定名称的节点。
	Get(name string) (*v1.Node, error)
}
```

#### CreateMirrorPod

```go
func (mc *basicMirrorClient) CreateMirrorPod(pod *v1.Pod) error {
	if mc.apiserverClient == nil {
		return nil
	}
	// 复制Pod。
	copyPod := *pod
	copyPod.Annotations = make(map[string]string)

	for k, v := range pod.Annotations {
		copyPod.Annotations[k] = v
	}
	hash := getPodHash(pod)
	copyPod.Annotations[kubetypes.ConfigMirrorAnnotationKey] = hash

	// 使用MirrorPodNodeRestriction功能，镜像Pod需要拥有一个对所属节点的所有权引用。
	// 参见https://git.k8s.io/enhancements/keps/sig-auth/1314-node-restriction-pods/README.md
	nodeUID, err := mc.getNodeUID()
	if err != nil {
		return fmt.Errorf("failed to get node UID: %v", err)
	}
	controller := true
	copyPod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1.SchemeGroupVersion.String(),
		Kind:       "Node",
		Name:       mc.nodeName,
		UID:        nodeUID,
		Controller: &controller,
	}}

	apiPod, err := mc.apiserverClient.CoreV1().Pods(copyPod.Namespace).Create(context.TODO(), &copyPod, metav1.CreateOptions{})
	if err != nil && apierrors.IsAlreadyExists(err) {
		// 检查现有的Pod是否与要创建的Pod相同。
		if h, ok := apiPod.Annotations[kubetypes.ConfigMirrorAnnotationKey]; ok && h == hash {
			return nil
		}
	}
	return err
}
```

##### getNodeUID

```go
// getNodeUID获取节点的UID。
func (mc *basicMirrorClient) getNodeUID() (types.UID, error) {
	// 通过调用nodeGetter的Get方法获取节点对象。
	node, err := mc.nodeGetter.Get(mc.nodeName)
	if err != nil {
		return "", err
	}
	// 检查节点的UID是否为空。
	if node.UID == "" {
		return "", fmt.Errorf("UID unset for node %s", mc.nodeName)
	}
	return node.UID, nil
}
```

##### getPodHash

```go
// getPodHash获取Pod的哈希值。
func getPodHash(pod *v1.Pod) string {
    // 返回Pod的注释中的哈希值。
    return pod.Annotations[kubetypes.ConfigHashAnnotationKey]
}
```

#### DeleteMirrorPod

```go
// DeleteMirrorPod删除一个镜像Pod。
// 它接受Pod的全名和可选的UID作为参数。如果UID非nil，则仅当Pod的UID与提供的UID匹配时才删除Pod。
// 它返回是否实际删除了Pod，以及在解析Pod名称时返回的任何错误。
// 如果Pod不存在或UID不匹配，则不会将其视为错误；在这种情况下，该函数仅返回false。
func (mc *basicMirrorClient) DeleteMirrorPod(podFullName string, uid *types.UID) (bool, error) {
	if mc.apiserverClient == nil {
		return false, nil
	}
	name, namespace, err := kubecontainer.ParsePodFullName(podFullName)
	if err != nil {
		klog.ErrorS(err, "Failed to parse a pod full name", "podFullName", podFullName)
		return false, err
	}

	var uidValue types.UID
	if uid != nil {
		uidValue = *uid
	}
	klog.V(2).InfoS("Deleting a mirror pod", "pod", klog.KRef(namespace, name), "podUID", uidValue)

	var GracePeriodSeconds int64
	if err := mc.apiserverClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{GracePeriodSeconds: &GracePeriodSeconds, Preconditions: &metav1.Preconditions{UID: uid}}); err != nil {
		// 不幸的是，没有通用的错误来表示未满足的前提条件
		if !(apierrors.IsNotFound(err) || apierrors.IsConflict(err)) {
			// 在这里应该返回错误，但是根据历史，该函数仅在无法解析Pod名称时才返回错误
			klog.ErrorS(err, "Failed deleting a mirror pod", "pod", klog.KRef(namespace, name))
		}
		return false, nil
	}
	return true, nil
}
```

### GetPodByFullName

```GO
func (pm *basicManager) GetPodByFullName(podFullName string) (*v1.Pod, bool) {
	pm.lock.RLock()                          // 加读锁，保护并发读取
	defer pm.lock.RUnlock()                  // 解除读锁
	pod, ok := pm.podByFullName[podFullName] // 根据完整名称获取Pod
	return pod, ok
}
```

### GetPodByName

```GO
func (pm *basicManager) GetPodByName(namespace, name string) (*v1.Pod, bool) {
	podFullName := kubecontainer.BuildPodFullName(name, namespace) // 构建完整的Pod名称
	return pm.GetPodByFullName(podFullName)                        // 调用GetPodByFullName函数获取Pod
}
```

### GetPodByUID

```GO
func (pm *basicManager) GetPodByUID(uid types.UID) (*v1.Pod, bool) {
	pm.lock.RLock()                                       // 加读锁，保护并发读取
	defer pm.lock.RUnlock()                               // 解除读锁
	pod, ok := pm.podByUID[kubetypes.ResolvedPodUID(uid)] // 根据Pod的UID获取Pod
	return pod, ok
}
```

### GetPodByMirrorPod

```GO
func (pm *basicManager) GetPodByMirrorPod(mirrorPod *v1.Pod) (*v1.Pod, bool) {
	pm.lock.RLock()                                                      // 加读锁，保护并发读取
	defer pm.lock.RUnlock()                                              // 解除读锁
	pod, ok := pm.podByFullName[kubecontainer.GetPodFullName(mirrorPod)] // 根据镜像Pod获取对应的静态Pod
	return pod, ok
}
```

### GetMirrorPodByPod

```GO
func (pm *basicManager) GetMirrorPodByPod(pod *v1.Pod) (*v1.Pod, bool) {
	pm.lock.RLock()                                                            // 加读锁，保护并发读取
	defer pm.lock.RUnlock()                                                    // 解除读锁
	mirrorPod, ok := pm.mirrorPodByFullName[kubecontainer.GetPodFullName(pod)] // 根据静态Pod获取对应的镜像Pod
	return mirrorPod, ok
}
```

### GetPodAndMirrorPod

```GO
func (pm *basicManager) GetPodAndMirrorPod(aPod *v1.Pod) (pod, mirrorPod *v1.Pod, wasMirror bool) {
	pm.lock.RLock()         // 加读锁，保护并发读取
	defer pm.lock.RUnlock() // 解除读锁

	fullName := kubecontainer.GetPodFullName(aPod) // 获取Pod的完整名称
	if kubetypes.IsMirrorPod(aPod) {               // 判断Pod是否为镜像Pod
		return pm.podByFullName[fullName], aPod, true // 返回静态Pod、镜像Pod和true
	}
	return aPod, pm.mirrorPodByFullName[fullName], false // 返回Pod、静态Pod和false
}
```

##### IsMirrorPod

```GO
// IsMirrorPod如果传入的Pod是镜像Pod，则返回true。
func IsMirrorPod(pod *v1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	_, ok := pod.Annotations[ConfigMirrorAnnotationKey] // 判断Pod的注释中是否包含ConfigMirrorAnnotationKey
	return ok
}
```

### GetPods

```GO
func (pm *basicManager) GetPods() []*v1.Pod {
	pm.lock.RLock()                   // 加读锁，保护并发读取
	defer pm.lock.RUnlock()           // 解除读锁
	return podsMapToPods(pm.podByUID) // 将pm.podByUID映射为Pod列表并返回
}
```

### GetPodsAndMirrorPods

```GO
func (pm *basicManager) GetPodsAndMirrorPods() (allPods []*v1.Pod, allMirrorPods []*v1.Pod, orphanedMirrorPodFullnames []string) {
	pm.lock.RLock()                                              // 加读锁，保护并发读取
	defer pm.lock.RUnlock()                                      // 解除读锁
	allPods = podsMapToPods(pm.podByUID)                         // 将pm.podByUID映射为Pod列表
	allMirrorPods = mirrorPodsMapToMirrorPods(pm.mirrorPodByUID) // 将pm.mirrorPodByUID映射为镜像Pod列表

	for podFullName := range pm.mirrorPodByFullName {
		if _, ok := pm.podByFullName[podFullName]; !ok { // 检查静态Pod是否存在
			orphanedMirrorPodFullnames = append(orphanedMirrorPodFullnames, podFullName) // 将孤立的镜像Pod名称添加到列表中
		}
	}
	return allPods, allMirrorPods, orphanedMirrorPodFullnames
}
```

#### podsMapToPods

```GO
func podsMapToPods(UIDMap map[kubetypes.ResolvedPodUID]*v1.Pod) []*v1.Pod {
	pods := make([]*v1.Pod, 0, len(UIDMap))
	for _, pod := range UIDMap {
		pods = append(pods, pod) // 将Pod添加到列表中
	}
	return pods
}
```

#### mirrorPodsMapToMirrorPods

```GO
func mirrorPodsMapToMirrorPods(UIDMap map[kubetypes.MirrorPodUID]*v1.Pod) []*v1.Pod {
	pods := make([]*v1.Pod, 0, len(UIDMap))
	for _, pod := range UIDMap {
		pods = append(pods, pod) // 将镜像Pod添加到列表中
	}
	return pods
}
```

### SetPods

```GO
// SetPods根据新的Pod设置内部Pod列表。
func (pm *basicManager) SetPods(newPods []*v1.Pod) {
	pm.lock.Lock()         // 加写锁，保护并发写入
	defer pm.lock.Unlock() // 解除写锁

	pm.podByUID = make(map[kubetypes.ResolvedPodUID]*v1.Pod)                        // 清空Pod UID映射
	pm.podByFullName = make(map[string]*v1.Pod)                                     // 清空Pod完整名称映射
	pm.mirrorPodByUID = make(map[kubetypes.MirrorPodUID]*v1.Pod)                    // 清空镜像Pod UID映射
	pm.mirrorPodByFullName = make(map[string]*v1.Pod)                               // 清空镜像Pod完整名称映射
	pm.translationByUID = make(map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID) // 清空UID转换映射

	pm.updatePodsInternal(newPods...)
}
```

#### updatePodsInternal

```GO
// updatePodsInternal在管理器的当前状态中替换给定的Pod，更新各种索引。假设调用者持有锁。
func (pm *basicManager) updatePodsInternal(pods ...*v1.Pod) {
	for _, pod := range pods {
		podFullName := kubecontainer.GetPodFullName(pod) // 获取Pod的完整名称
		// 这个逻辑依赖于静态Pod和其镜像Pod具有相同的名称。
		// 由于IsMirrorPod的保护，这里进行类型转换是安全的。
		if kubetypes.IsMirrorPod(pod) { // 如果是镜像Pod
			mirrorPodUID := kubetypes.MirrorPodUID(pod.UID) // 获取镜像Pod的UID
			pm.mirrorPodByUID[mirrorPodUID] = pod           // 将镜像Pod添加到镜像Pod UID映射中
			pm.mirrorPodByFullName[podFullName] = pod       // 将镜像Pod添加到镜像Pod完整名称映射中
			if p, ok := pm.podByFullName[podFullName]; ok {
				pm.translationByUID[mirrorPodUID] = kubetypes.ResolvedPodUID(p.UID) // 更新UID转换映射
			}
		} else {
			resolvedPodUID := kubetypes.ResolvedPodUID(pod.UID) // 获取静态Pod的UID
			updateMetrics(pm.podByUID[resolvedPodUID], pod)     // 更新指标
			pm.podByUID[resolvedPodUID] = pod                   // 将Pod添加到Pod UID映射中
			pm.podByFullName[podFullName] = pod                 // 将Pod添加到Pod完整名称映射中
			if mirror, ok := pm.mirrorPodByFullName[podFullName]; ok {
				pm.translationByUID[kubetypes.MirrorPodUID(mirror.UID)] = resolvedPodUID // 更新UID转换映射
			}
		}
	}
}
```

### AddPod

```GO
func (pm *basicManager) AddPod(pod *v1.Pod) {
	pm.UpdatePod(pod) // 添加Pod时调用UpdatePod函数
}
```

### UpdatePod

```GO
func (pm *basicManager) UpdatePod(pod *v1.Pod) {
	pm.lock.Lock()             // 加写锁，保护并发写入
	defer pm.lock.Unlock()     // 解除写锁
	pm.updatePodsInternal(pod) // 更新Pod
}
```

### RemovePod

```GO
func (pm *basicManager) RemovePod(pod *v1.Pod) {
	updateMetrics(pod, nil)                          // 更新指标，传入的pod为nil表示删除
	pm.lock.Lock()                                   // 加写锁，保护并发写入
	defer pm.lock.Unlock()                           // 解除写锁
	podFullName := kubecontainer.GetPodFullName(pod) // 获取Pod的完整名称
	// 由于IsMirrorPod的保护，这里进行类型转换是安全的。
	if kubetypes.IsMirrorPod(pod) { // 如果是镜像Pod
		mirrorPodUID := kubetypes.MirrorPodUID(pod.UID) // 获取镜像Pod的UID
		delete(pm.mirrorPodByUID, mirrorPodUID)         // 从镜像Pod UID映射中删除镜像Pod
		delete(pm.mirrorPodByFullName, podFullName)     // 从镜像Pod完整名称映射中删除镜像Pod
		delete(pm.translationByUID, mirrorPodUID)       // 从UID转换映射中删除镜像Pod的UID
	} else {
		delete(pm.podByUID, kubetypes.ResolvedPodUID(pod.UID)) // 从Pod UID映射中删除Pod
		delete(pm.podByFullName, podFullName)                  // 从Pod完整名称映射中删除Pod
	}
}
```

#### updateMetrics

```GO
// updateMetrics更新Pod管理器的指标。
// oldPod或newPod可能为nil，表示创建或删除。
func updateMetrics(oldPod, newPod *v1.Pod) {
	var numEC int
	if oldPod != nil {
		numEC -= len(oldPod.Spec.EphemeralContainers) // 计算旧Pod的临时容器数量
	}
	if newPod != nil {
		numEC += len(newPod.Spec.EphemeralContainers) // 计算新Pod的临时容器数量
	}
	if numEC != 0 {
		metrics.ManagedEphemeralContainers.Add(float64(numEC)) // 更新指标
	}
}
```

### TranslatePodUID

```GO
func (pm *basicManager) TranslatePodUID(uid types.UID) kubetypes.ResolvedPodUID {
	// 将类型转换为ResolvedPodUID是安全的，因为类型转换是幂等的。
	if uid == "" {
		return kubetypes.ResolvedPodUID(uid) // 如果UID为空，则返回ResolvedPodUID(uid)，即空UID
	}

	pm.lock.RLock()         // 加读锁，保护并发读取
	defer pm.lock.RUnlock() // 解除读锁
	if translated, ok := pm.translationByUID[kubetypes.MirrorPodUID(uid)]; ok {
		return translated // 如果存在对应的转换UID，则返回该转换UID
	}
	return kubetypes.ResolvedPodUID(uid) // 否则，返回原始UID的ResolvedPodUID类型
}
```

### GetUIDTranslations

```GO
func (pm *basicManager) GetUIDTranslations() (podToMirror map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID,
	mirrorToPod map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID) {
	pm.lock.RLock()         // 加读锁，保护并发读取
	defer pm.lock.RUnlock() // 解除读锁

	podToMirror = make(map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID, len(pm.translationByUID))
	mirrorToPod = make(map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID, len(pm.translationByUID))
	// 为所有静态Pod插入空的转换映射。
	for uid, pod := range pm.podByUID {
		if !kubetypes.IsStaticPod(pod) {
			continue
		}
		podToMirror[uid] = "" // 将静态Pod的UID映射为空字符串
	}
	// 填充转换映射。注意，如果静态Pod没有对应的镜像Pod，它的UID将被转换为空字符串""。
	// 这是符合预期的，从调用方的角度，我们可以知道静态Pod没有相应的镜像Pod，而不是直接使用静态Pod的UID。
	for k, v := range pm.translationByUID {
		mirrorToPod[k] = v // 镜像Pod的UID映射为静态Pod的UID
		podToMirror[v] = k // 静态Pod的UID映射为镜像Pod的UID
	}
	return podToMirror, mirrorToPod // 返回转换映射结果
}
```

