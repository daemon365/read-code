## 简介

在Kubernetes中，kubelet是负责管理节点上容器运行的组件之一。`usernsManager`是kubelet中的一个模块，用于处理容器的用户命名空间（User Namespace）相关操作。

用户命名空间是Linux内核提供的一种机制，用于隔离不同用户的进程。在容器化环境中，用户命名空间被广泛用于增强容器的安全性和隔离性。

`usernsManager`的主要功能如下：

1. 创建和配置用户命名空间：`usernsManager`负责创建和配置容器的用户命名空间。在容器创建过程中，它会根据容器的配置和要求，创建一个独立的用户命名空间，并为容器中的进程分配相应的用户和组标识符。
2. 管理用户命名空间的映射：`usernsManager`维护着用户命名空间的映射关系，用于将容器内部的用户和组标识符映射到宿主机上的相应标识符。这样可以实现容器内外用户标识符的隔离和映射，增强了容器的安全性。
3. 处理用户命名空间相关的操作：`usernsManager`负责处理与用户命名空间相关的操作，如权限检查、用户标识符映射的更新等。它与其他kubelet模块（如容器运行时、容器监控等）进行协作，确保容器在用户命名空间方面的要求和策略得到正确执行。

通过使用`usernsManager`，kubelet能够为容器提供更强大的安全隔离性，保护宿主机上的系统资源和用户数据。它是kubelet中关键的一部分，与其他模块共同构成了容器运行和管理的基础设施。

## userNsPodsManager

```GO
// userNsPodsManager 接口定义了与用户命名空间有关的 Pod 管理函数。
type userNsPodsManager interface {
	GetPodDir(podUID types.UID) string // 根据 Pod UID 获取 Pod 目录路径
	ListPodsFromDisk() ([]types.UID, error) // 从磁盘列出所有的 Pod UIDs
}
```

### kubelet.GetPodDir

```go
// GetPodDir 返回指定 Pod 的每个 Pod 数据目录的完整路径。如果 Pod 不存在，则该目录可能不存在。
func (kl *Kubelet) GetPodDir(podUID types.UID) string {
	return kl.getPodDir(podUID)
}

// getPodDir 返回具有给定 UID 的 Pod 的每个 Pod 目录的完整路径。
func (kl *Kubelet) getPodDir(podUID types.UID) string {
	return filepath.Join(kl.getPodsDir(), string(podUID))
}

// getPodsDir 返回创建 Pod 目录的目录的完整路径。
func (kl *Kubelet) getPodsDir() string {
	return filepath.Join(kl.getRootDir(), config.DefaultKubeletPodsDirName)
}

// getRootDir 返回 kubelet 可以存储数据的目录的完整路径。这些函数对于向可能需要知道在哪里写入数据的其他模块传递接口很有用，而不需要获取整个 kubelet 实例。
func (kl *Kubelet) getRootDir() string {
	return kl.rootDirectory
}
```

### kubelet.ListPodsFromDisk

```go
// ListPodsFromDisk 获取具有数据目录的 Pod 列表。
func (kl *Kubelet) ListPodsFromDisk() ([]types.UID, error) {
	return kl.listPodsFromDisk()
}

// 获取具有数据目录的 Pod 列表。
func (kl *Kubelet) listPodsFromDisk() ([]types.UID, error) {
	podInfos, err := os.ReadDir(kl.getPodsDir())
	if err != nil {
		return nil, err
	}
	pods := []types.UID{}
	for i := range podInfos {
		if podInfos[i].IsDir() {
			pods = append(pods, types.UID(podInfos[i].Name()))
		}
	}
	return pods, nil
}
```

## UsernsManager

```GO
// UsernsManager 结构体定义了用户命名空间的管理器。
type UsernsManager struct {
	used         *allocator.AllocationBitmap
	usedBy       map[types.UID]uint32 // 将 Pod UID 映射到已使用的范围
	removed      int
	numAllocated int
	kl           userNsPodsManager
	// 该锁保护除 kl 之外的所有成员。
	lock sync.Mutex
}

func MakeUserNsManager(kl userNsPodsManager) (*UsernsManager, error) {
	m := UsernsManager{
		// 为所有的UID空间（2^32）创建一个bitArray。
		// 作为副产品，bitArray的索引参数不能超出界限（索引是uint32类型）。
		used:   allocator.NewAllocationMap((math.MaxUint32+1)/userNsLength, "user namespaces"),
		usedBy: make(map[types.UID]uint32),
		kl:     kl,
	}
	// 第一个块保留给宿主机。
	if _, err := m.used.Allocate(0); err != nil {
		return nil, err
	}

	// 如果未启用用户命名空间，请不要读取Pod列表。
	if !utilfeature.DefaultFeatureGate.Enabled(features.UserNamespacesSupport) {
		return &m, nil
	}

	// 从磁盘中读取Pod列表。
	found, err := kl.ListPodsFromDisk()
	if err != nil {
		if os.IsNotExist(err) {
			return &m, nil
		}
		return nil, fmt.Errorf("user namespace manager can't read pods from disk: %w", err)
	}

	// 为每个找到的Pod记录命名空间映射。
	for _, podUID := range found {
		klog.V(5).InfoS("reading pod from disk for user namespace", "podUID", podUID)
		if err := m.recordPodMappings(podUID); err != nil {
			return nil, err
		}
	}

	return &m, nil
}
```

### recordPodMappings

```GO
// recordPodMappings在存在pod目录中的usernsConfFile的情况下，注册用于用户命名空间的范围。
func (m *UsernsManager) recordPodMappings(pod types.UID) error {
	content, err := m.readMappingsFromFile(pod)
	if err != nil && err != utilstore.ErrKeyNotFound {
		return err
	}

	// 如果没有内容，意味着该pod没有使用用户命名空间，没有其他操作需要执行
	if len(content) == 0 {
		return nil
	}

	_, err = m.parseUserNsFileAndRecord(pod, content)
	return err
}
```

##### record

```GO
// record 将用户命名空间 [from; from+length] 存储到指定的 Pod 中。
func (m *UsernsManager) record(pod types.UID, from, length uint32) (err error) {
	if length != userNsLength {
		return fmt.Errorf("wrong user namespace length %v", length)
	}
	if from%userNsLength != 0 {
		return fmt.Errorf("wrong user namespace offset specified %v", from)
	}
	prevFrom, found := m.usedBy[pod]
	if found && prevFrom != from {
		return fmt.Errorf("different user namespace range already used by pod %q", pod)
	}
	index := int(from / userNsLength)
	// 如果 Pod 不存在，验证范围是否空闲。
	if !found && m.used.Has(index) {
		return fmt.Errorf("range picked for pod %q already taken", pod)
	}
	// 如果 Pod 已经注册，则不需要进行操作。
	if found && prevFrom == from {
		return nil
	}
	if m.numAllocated >= maxPods {
		return fmt.Errorf("limit on count of pods with user namespaces exceeded (limit is %v, current pods with userns: %v)", maxPods, m.numAllocated)
	}
	m.numAllocated++
	defer func() {
		if err != nil {
			m.numAllocated--
		}
	}()

	klog.V(5).InfoS("new pod user namespace allocation", "podUID", pod)

	// "from" 是一个 ID（UID/GID），将对应大小为 userNsLength 的用户命名空间设置到位数组中。
	m.used.Allocate(index)
	m.usedBy[pod] = from
	return nil
}
```

#### readMappingsFromFile

```GO
// readMappingsFromFile从Pod目录中读取用户命名空间配置。
func (m *UsernsManager) readMappingsFromFile(pod types.UID) ([]byte, error) {
	dir := m.kl.GetPodDir(pod)
	fstore, err := utilstore.NewFileStore(dir, &utilfs.DefaultFs{})
	if err != nil {
		return nil, err
	}
	return fstore.Read(mappingsFile)
}
```

#### parseUserNsFileAndRecord

```GO
func (m *UsernsManager) parseUserNsFileAndRecord(pod types.UID, content []byte) (userNs userNamespace, err error) {
	if err = json.Unmarshal([]byte(content), &userNs); err != nil {
		err = fmt.Errorf("can't parse file: %w", err)
		return
	}

	if len(userNs.UIDMappings) != 1 {
		err = fmt.Errorf("invalid user namespace configuration: no more than one mapping allowed.")
		return
	}

	if len(userNs.UIDMappings) != len(userNs.GIDMappings) {
		err = fmt.Errorf("invalid user namespace configuration: GID and UID mappings should be identical.")
		return
	}

	if userNs.UIDMappings[0] != userNs.GIDMappings[0] {
		err = fmt.Errorf("invalid user namespace configuration: GID and UID mapping should be identical")
		return
	}

	// 我们不会生成没有root映射的配置，而某些运行时假设它被映射。
	// 验证文件是否包含我们生成和处理的内容。
	if userNs.UIDMappings[0].ContainerId != 0 {
		err = fmt.Errorf("invalid user namespace configuration: UID 0 must be mapped")
		return
	}

	if userNs.GIDMappings[0].ContainerId != 0 {
		err = fmt.Errorf("invalid user namespace configuration: GID 0 must be mapped")
		return
	}

	hostId := userNs.UIDMappings[0].HostId
	length := userNs.UIDMappings[0].Length

	err = m.record(pod, hostId, length)
	return
}
```

## GetOrCreateUserNamespaceMappings

```GO
// GetOrCreateUserNamespaceMappings 返回沙箱用户命名空间的配置。
func (m *UsernsManager) GetOrCreateUserNamespaceMappings(pod *v1.Pod) (*runtimeapi.UserNamespace, error) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.UserNamespacesSupport) {
		return nil, nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	// 如果 Pod 指定了 HostUsers 字段为 true 或未指定该字段，则返回 NODE 模式的用户命名空间。
	if pod.Spec.HostUsers == nil || *pod.Spec.HostUsers == true {
		return &runtimeapi.UserNamespace{
			Mode: runtimeapi.NamespaceMode_NODE,
		}, nil
	}

	// 从文件中读取命名空间配置。
	content, err := m.readMappingsFromFile(pod.UID)
	if err != nil && err != utilstore.ErrKeyNotFound {
		return nil, err
	}

	var userNs userNamespace
	if string(content) != "" {
		// 如果文件内容非空，则解析文件并记录命名空间映射。
		userNs, err = m.parseUserNsFileAndRecord(pod.UID, content)
		if err != nil {
			return nil, err
		}
	} else {
		// 如果文件内容为空，则创建新的用户命名空间。
		userNs, err = m.createUserNs(pod)
		if err != nil {
			return nil, err
		}
	}

	// 构建 UID 映射和 GID 映射。
	var uids []*runtimeapi.IDMapping
	var gids []*runtimeapi.IDMapping

	for _, u := range userNs.UIDMappings {
		uids = append(uids, &runtimeapi.IDMapping{
			HostId:      u.HostId,
			ContainerId: u.ContainerId,
			Length:      u.Length,
		})
	}
	for _, g := range userNs.GIDMappings {
		gids = append(gids, &runtimeapi.IDMapping{
			HostId:      g.HostId,
			ContainerId: g.ContainerId,
			Length:      g.Length,
		})
	}

	// 返回用户命名空间配置。
	return &runtimeapi.UserNamespace{
		Mode: runtimeapi.NamespaceMode_POD,
		Uids: uids,
		Gids: gids,
	}, nil
}
```

### createUserNs

```GO
// createUserNs 创建新的用户命名空间。
func (m *UsernsManager) createUserNs(pod *v1.Pod) (userNs userNamespace, err error) {
	firstID, length, err := m.allocateOne(pod.UID)
	if err != nil {
		return
	}

	defer func() {
		if err != nil {
			m.releaseWithLock(pod.UID)
		}
	}()

	// 构建用户命名空间配置。
	userNs = userNamespace{
		UIDMappings: []idMapping{
			{
				ContainerId: 0,
				HostId:      firstID,
				Length:      length,
			},
		},
		GIDMappings: []idMapping{
			{
				ContainerId: 0,
				HostId:      firstID,
				Length:      length,
			},
		},
	}

	// 将用户命名空间配置写入文件。
	return userNs, m.writeMappingsToFile(pod.UID, userNs)
}
```

##### allocateOne

```GO
// allocateOne 查找一个空闲的用户命名空间并将其分配给指定的 Pod。
// 第一个返回值是用户命名空间中的第一个 ID，第二个返回值是用户命名空间范围的长度。
func (m *UsernsManager) allocateOne(pod types.UID) (firstID uint32, length uint32, err error) {
	if m.numAllocated >= maxPods {
		return 0, 0, fmt.Errorf("limit on count of pods with user namespaces exceeded (limit is %v, current pods with userns: %v)", maxPods, m.numAllocated)
	}
	m.numAllocated++
	defer func() {
		if err != nil {
			m.numAllocated--
		}
	}()

	firstZero, found, err := m.used.AllocateNext()
	if err != nil {
		return 0, 0, err
	}
	if !found {
		return 0, 0, fmt.Errorf("could not find an empty slot to allocate a user namespace")
	}

	klog.V(5).InfoS("new pod user namespace allocation", "podUID", pod)

	firstID = uint32(firstZero * userNsLength)
	m.usedBy[pod] = firstID
	return firstID, userNsLength, nil
}
```

### releaseWithLock

```GO
// releaseWithLock 释放用户命名空间并清理相关资源。
func (m *UsernsManager) releaseWithLock(pod types.UID) {
	v, ok := m.usedBy[pod]
	if !ok {
		klog.V(5).InfoS("pod user namespace allocation not present", "podUID", pod)
		return
	}
	delete(m.usedBy, pod)

	klog.V(5).InfoS("releasing pod user namespace allocation", "podUID", pod)
	m.numAllocated--
	m.removed++

	_ = os.Remove(filepath.Join(m.kl.GetPodDir(pod), mappingsFile))

	// 如果清理的数量达到阈值，重新初始化一些内部状态。
	if m.removed%mapReInitializeThreshold == 0 {
		n := make(map[types.UID]uint32)
		for k, v := range m.usedBy {
			n[k] = v
		}
		m.usedBy = n
		m.removed = 0
	}
	m.used.Release(int(v / userNsLength))
}
```

### writeMappingsToFile

```GO
// writeMappingsToFile将指定的用户命名空间配置写入Pod目录。
func (m *UsernsManager) writeMappingsToFile(pod types.UID, userNs userNamespace) error {
	dir := m.kl.GetPodDir(pod)

	data, err := json.Marshal(userNs)
	if err != nil {
		return err
	}

	fstore, err := utilstore.NewFileStore(dir, &utilfs.DefaultFs{})
	if err != nil {
		return err
	}
	if err := fstore.Write(mappingsFile, data); err != nil {
		return err
	}

	// 我们需要将父目录fsync以确保文件存在。
	// fstore保证原子写入，我们还需要持久性。
	parentDir, err := os.Open(dir)
	if err != nil {
		return err
	}

	if err = parentDir.Sync(); err != nil {
		// 忽略此处的返回值，因为已经报告了一个错误。
		parentDir.Close()
		return err
	}

	return parentDir.Close()
}
```

### userNamespace

```GO
// userNamespace 结构体保存了用户命名空间的配置信息。
type userNamespace struct {
	// 用户命名空间的 UID 映射。
	UIDMappings []idMapping `json:"uidMappings"`
	// 用户命名空间的 GID 映射。
	GIDMappings []idMapping `json:"gidMappings"`
}

// idMapping 结构体定义了用户命名空间的映射规则。
type idMapping struct {
	// 主机端的 ID。
	HostId uint32 `json:"hostId"`
	// 容器端的 ID。
	ContainerId uint32 `json:"containerId"`
	// 映射的长度。
	Length uint32 `json:"length"`
}

// mappingsFile 是保存用户命名空间映射配置的文件名。
const mappingsFile = "userns"
```

## CleanupOrphanedPodUsernsAllocations

```GO
// CleanupOrphanedPodUsernsAllocations 用于协调用户命名空间分配的状态与实际运行的 Pod。它会释放孤立的 Pod 的用户命名空间分配。
func (m *UsernsManager) CleanupOrphanedPodUsernsAllocations(pods []*v1.Pod, runningPods []*kubecontainer.Pod) error {
	if !utilfeature.DefaultFeatureGate.Enabled(features.UserNamespacesSupport) {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	allPods := sets.NewString()
	for _, pod := range pods {
		allPods.Insert(string(pod.UID))
	}
	for _, pod := range runningPods {
		allPods.Insert(string(pod.ID))
	}

	allFound := sets.NewString()
	found, err := m.kl.ListPodsFromDisk()
	if err != nil {
		return err
	}

	for _, podUID := range found {
		allFound.Insert(string(podUID))
	}

	// 删除所有 "found" 中未知的 Pod。
	for _, podUID := range found {
		if allPods.Has(string(podUID)) {
			continue
		}

		klog.V(5).InfoS("Clean up orphaned pod user namespace possible allocation", "podUID", podUID)
		m.releaseWithLock(podUID)
	}

	// 删除所有存在的 Pod 分配，但在 "found" 中不存在的 Pod。
	for podUID := range m.usedBy {
		if allFound.Has(string(podUID)) {
			continue
		}

		klog.V(5).InfoS("Clean up orphaned pod user namespace possible allocation", "podUID", podUID)
		m.releaseWithLock(podUID)
	}

	return nil
}
```

## Release

```GO
// Release 释放分配给指定 Pod 的用户命名空间。
func (m *UsernsManager) Release(podUID types.UID) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.UserNamespacesSupport) {
		return
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	m.releaseWithLock(podUID)
}
```

### releaseWithLock

```GO
// releaseWithLock 释放用户命名空间并清理相关资源。
func (m *UsernsManager) releaseWithLock(pod types.UID) {
	v, ok := m.usedBy[pod]
	if !ok {
		klog.V(5).InfoS("pod user namespace allocation not present", "podUID", pod)
		return
	}
	delete(m.usedBy, pod)

	klog.V(5).InfoS("releasing pod user namespace allocation", "podUID", pod)
	m.numAllocated--
	m.removed++

	_ = os.Remove(filepath.Join(m.kl.GetPodDir(pod), mappingsFile))

	if m.removed%mapReInitializeThreshold == 0 {
		n := make(map[types.UID]uint32)
		for k, v := range m.usedBy {
			n[k] = v
		}
		m.usedBy = n
		m.removed = 0
	}
	m.used.Release(int(v / userNsLength))
}
```