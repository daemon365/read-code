
## 简介

用于管理EndpointSlice资源，并确保Service和EndpointSlice之间的同步。EndpointSlice是Kubernetes中的一种资源类型，它与Service资源紧密相关，用于存储Service中的Pod地址。

**为什么有了 endpoints 还需要 EndpointSlice 呢？**

是因为如果一个service的pod太多，变更就会频繁，watch这些对象的组件（controller，kubelet等）就会不断做操作，从而影响性能。

与 Endpoints 不同，EndpointSlice 可以被拆分成更小的块，并且每个块可以仅包含一个较小的 Pod 子集，从而提高查询性能。另外，还支持更多的网络协议，如 UDP 和 SCTP。

## 结构体

```go
type Controller struct {
	client           clientset.Interface
    // 广播事件 记录事件
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	// service对象lister
	serviceLister corelisters.ServiceLister
	servicesSynced cache.InformerSynced

	// pod lister
	podLister corelisters.PodLister
	podsSynced cache.InformerSynced

	// endpointSlice 的 Lister
	endpointSliceLister discoverylisters.EndpointSliceLister
	endpointSlicesSynced cache.InformerSynced
	// 跟踪每个 Service 的 EndpointSlice 列表和关联的资源版本，帮助确定缓存的 EndpointSlice 是否过时
	endpointSliceTracker *endpointsliceutil.EndpointSliceTracker

	// node 的 Lister
	nodeLister corelisters.NodeLister
	nodesSynced cache.InformerSynced

	// 协调 EndpointSlice 变更的实用程序
	reconciler *reconciler

	// 计算和导出 EndpointsLastChangeTriggerTime 注释的实用程序 
	triggerTimeTracker *endpointutil.TriggerTimeTracker

	// 存储需要更新的 Service 的队列
	queue workqueue.RateLimitingInterface

	// 引用应添加到 EndpointSlice 中的最大数
	maxEndpointsPerSlice int32

	// 工作程序运行之间的时间间隔
	workerLoopPeriod time.Duration

	// 添加到由 Pod 变更触发的所有服务同步的人工延迟。这可以用于减少所有端点片段更新的总数
	endpointUpdatesBatchPeriod time.Duration

	// 踪节点和区域之间的分布，以启用拓扑感知提示
	topologyCache *topologycache.TopologyCache
}
```

### EndpointSliceTracker

```GO
type GenerationsBySlice map[types.UID]int64

type EndpointSliceTracker struct {
	lock sync.Mutex
	generationsByService map[types.NamespacedName]GenerationsBySlice
}

func NewEndpointSliceTracker() *EndpointSliceTracker {
	return &EndpointSliceTracker{
		generationsByService: map[types.NamespacedName]GenerationsBySlice{},
	}
}

// 确定给定的 EndpointSlice 是否存在于 EndpointSliceTracker 的内部数据结构中
func (est *EndpointSliceTracker) Has(endpointSlice *discovery.EndpointSlice) bool {
	est.lock.Lock()
	defer est.lock.Unlock()
	
    // 使用GenerationsForSliceUnsafe判断GenerationsBySlice在不在map中
	gfs, ok := est.GenerationsForSliceUnsafe(endpointSlice)
	if !ok {
		return false
	}
    // 判断uid在不在GenerationsBySlice
	_, ok = gfs[endpointSlice.UID]
	return ok
}

// 确定给定的 EndpointSlice 是否需要同步到 EndpointSliceTracker 的内部数据结构中
func (est *EndpointSliceTracker) ShouldSync(endpointSlice *discovery.EndpointSlice) bool {
	est.lock.Lock()
	defer est.lock.Unlock()

	gfs, ok := est.GenerationsForSliceUnsafe(endpointSlice)
	if !ok {
		return true
	}
	g, ok := gfs[endpointSlice.UID]
    // 如果再map找不倒uid 或者之前的比现在的要新 就同步
	return !ok || endpointSlice.Generation > g
}

// 确定给定的 Service 对象是否有陈旧的 EndpointSlice，并且应该在下一次同步时被删除。
func (est *EndpointSliceTracker) StaleSlices(service *v1.Service, endpointSlices []*discovery.EndpointSlice) bool {
	est.lock.Lock()
	defer est.lock.Unlock()

	nn := types.NamespacedName{Name: service.Name, Namespace: service.Namespace}
	gfs, ok := est.generationsByService[nn]
	if !ok {
		return false
	}
	providedSlices := map[types.UID]int64{}
    // 便利endpointSlices
	for _, endpointSlice := range endpointSlices {
        // 存储endpointSlice的Generation
		providedSlices[endpointSlice.UID] = endpointSlice.Generation
		g, ok := gfs[endpointSlice.UID]
        // 如果找到了 需要删除或者存储的版本大于现在的版本 则表示当前 EndpointSlice 对象已经过期，需要被删除
		if ok && (g == deletionExpected || g > endpointSlice.Generation) {
			return true
		}
	}
    // 判断有没新的有 存储的没有的 
	for uid, generation := range gfs {
		if generation == deletionExpected {
			continue
		}
		_, ok := providedSlices[uid]
		if !ok {
			return true
		}
	}
	return false
}

//  更新endpointSlice 没有就创建
func (est *EndpointSliceTracker) Update(endpointSlice *discovery.EndpointSlice) {
	est.lock.Lock()
	defer est.lock.Unlock()

	gfs, ok := est.GenerationsForSliceUnsafe(endpointSlice)

	if !ok {
		gfs = GenerationsBySlice{}
		est.generationsByService[getServiceNN(endpointSlice)] = gfs
	}
	gfs[endpointSlice.UID] = endpointSlice.Generation
}

// 删除整个service
func (est *EndpointSliceTracker) DeleteService(namespace, name string) {
	est.lock.Lock()
	defer est.lock.Unlock()

	serviceNN := types.NamespacedName{Name: name, Namespace: namespace}
	delete(est.generationsByService, serviceNN)
}

// 使endpointSlice过期
func (est *EndpointSliceTracker) ExpectDeletion(endpointSlice *discovery.EndpointSlice) {
	est.lock.Lock()
	defer est.lock.Unlock()

	gfs, ok := est.GenerationsForSliceUnsafe(endpointSlice)

	if !ok {
		gfs = GenerationsBySlice{}
		est.generationsByService[getServiceNN(endpointSlice)] = gfs
	}
	gfs[endpointSlice.UID] = deletionExpected
}

// 从EndpointSliceTracker中删除一个EndpointSlice，并返回是否已成功删除
func (est *EndpointSliceTracker) HandleDeletion(endpointSlice *discovery.EndpointSlice) bool {
	est.lock.Lock()
	defer est.lock.Unlock()

	gfs, ok := est.GenerationsForSliceUnsafe(endpointSlice)

	if ok {
		g, ok := gfs[endpointSlice.UID]
		delete(gfs, endpointSlice.UID)
		if ok && g != deletionExpected {
			return false
		}
	}

	return true
}

func (est *EndpointSliceTracker) GenerationsForSliceUnsafe(endpointSlice *discovery.EndpointSlice) (GenerationsBySlice, bool) {
	serviceNN := getServiceNN(endpointSlice)
	generations, ok := est.generationsByService[serviceNN]
	return generations, ok
}

func getServiceNN(endpointSlice *discovery.EndpointSlice) types.NamespacedName {
	serviceName, _ := endpointSlice.Labels[discovery.LabelServiceName]
	return types.NamespacedName{Name: serviceName, Namespace: endpointSlice.Namespace}
}
```

### reconciler

```go
type reconciler struct {
	client               clientset.Interface
	nodeLister           corelisters.NodeLister
    // 指定每个 EndpointSlice 中最大的 Endpoint 数量
	maxEndpointsPerSlice int32
    // 用于跟踪 EndpointSlice 的变化
	endpointSliceTracker *endpointsliceutil.EndpointSliceTracker
    // 缓存一些指标数据
	metricsCache         *metrics.Cache
	// 用于跟踪节点和 Endpoint 在不同分区之间的分布，以支持 TopologyAwareHints
	topologyCache *topologycache.TopologyCache
	// 用于记录和发布事件
	eventRecorder record.EventRecorder
}

// 作用是用来调Service和其对应的所有 EndpointSlice。
// 当 Service 的后端 Pod 发生变化时，Kubernetes 将自动更新其对应的 EndpointSlice 对象。
// 因此，该方法的目标是确保所有的 EndpointSlice 对象都与该 Service 对象的后端 Pod 的信息匹配，
// 并将所有不再匹配的 EndpointSlice 删除。
func (r *reconciler) reconcile(service *corev1.Service, pods []*corev1.Pod, existingSlices []*discovery.EndpointSlice, triggerTime time.Time) error {
	slicesToDelete := []*discovery.EndpointSlice{}                                 
	errs := []error{}      
    // nap hey:serviceType value:EndpointSlice对象
	slicesByAddressType := make(map[discovery.AddressType][]*discovery.EndpointSlice) 

	// 获取该 Service 支持的所有地址类型
	serviceSupportedAddressesTypes := getAddressTypesForService(service)

	// 循环遍历已存在的 EndpointSlice 对象
	for _, existingSlice := range existingSlices {
		// service no longer supports that address type, add it to deleted slices
		if _, ok := serviceSupportedAddressesTypes[existingSlice.AddressType]; !ok {
            // 如果地址类型不被service支持了
			if r.topologyCache != nil {
				svcKey, err := serviceControllerKey(existingSlice)
				if err != nil {
					klog.Warningf("Couldn't get key to remove EndpointSlice from topology cache %+v: %v", existingSlice, err)
				} else {
                    // 从拓扑中删除对应的提示
					r.topologyCache.RemoveHints(svcKey, existingSlice.AddressType)
				}
			}
			// 将其添加到 slicesToDelete 中
			slicesToDelete = append(slicesToDelete, existingSlice)
			continue
		}

		// 把existingSlice添加到对应的map的数组中
		if _, ok := slicesByAddressType[existingSlice.AddressType]; !ok {
			slicesByAddressType[existingSlice.AddressType] = make([]*discovery.EndpointSlice, 0, 1)
		}

		slicesByAddressType[existingSlice.AddressType] = append(slicesByAddressType[existingSlice.AddressType], existingSlice)
	}

	// reconcile for existing.
	for addressType := range serviceSupportedAddressesTypes {
		existingSlices := slicesByAddressType[addressType]
       	// 更新该地址类型下的所有 EndpointSlice
		err := r.reconcileByAddressType(service, pods, existingSlices, triggerTime, addressType)
		if err != nil {
			errs = append(errs, err)
		}
	}

	for _, sliceToDelete := range slicesToDelete {
        // 删除slicesToDelete中的所有
		err := r.client.DiscoveryV1().EndpointSlices(service.Namespace).Delete(context.TODO(), sliceToDelete.Name, metav1.DeleteOptions{})
		if err != nil {
			errs = append(errs, fmt.Errorf("error deleting %s EndpointSlice for Service %s/%s: %w", sliceToDelete.Name, service.Namespace, service.Name, err))
		} else {
            // 标记和指标
			r.endpointSliceTracker.ExpectDeletion(sliceToDelete)
			metrics.EndpointSliceChanges.WithLabelValues("delete").Inc()
		}
	}

	return utilerrors.NewAggregate(errs)
}

// 对指定类型的EndpointSlice（用discovery.EndpointSlice结构体表示）进行对比，
// 并在不一致的情况下将集群中的EndpointSlice对象更新到与期望状态相匹配
func (r *reconciler) reconcileByAddressType(service *corev1.Service, pods []*corev1.Pod, existingSlices []*discovery.EndpointSlice, triggerTime time.Time, addressType discovery.AddressType) error {
	errs := []error{}
	
    // 创建、更新、删除的EndpointSlice对象
	slicesToCreate := []*discovery.EndpointSlice{}
	slicesToUpdate := []*discovery.EndpointSlice{}
	slicesToDelete := []*discovery.EndpointSlice{}
	events := []*topologycache.EventBuilder{}

	// 遍历已存在的EndpointSlice对象，并根据Service对象是否拥有该EndpointSlice对象，
    // 将该对象放入已有EndpointSlice切片或需要删除EndpointSlice切片中
	existingSlicesByPortMap := map[endpointutil.PortMapKey][]*discovery.EndpointSlice{}
	for _, existingSlice := range existingSlices {
        // EndpointSlice对象输入这个service 加入map 不输入加入删除列表
		if ownedBy(existingSlice, service) {
			epHash := endpointutil.NewPortMapKey(existingSlice.Ports)
			existingSlicesByPortMap[epHash] = append(existingSlicesByPortMap[epHash], existingSlice)
		} else {
			slicesToDelete = append(slicesToDelete, existingSlice)
		}
	}

	// Build data structures for desired state.
	desiredMetaByPortMap := map[endpointutil.PortMapKey]*endpointMeta{}
	desiredEndpointsByPortMap := map[endpointutil.PortMapKey]endpointsliceutil.EndpointSet{}

	for _, pod := range pods {
        // 是否应该在endpoints中，如果不是则跳过
		if !endpointutil.ShouldPodBeInEndpoints(pod, true) {
			continue
		}
		
        // 获取的一个service的所有pod
		endpointPorts := getEndpointPorts(service, pod)
        // 生成一个hashkey
		epHash := endpointutil.NewPortMapKey(endpointPorts)
		if _, ok := desiredEndpointsByPortMap[epHash]; !ok {
			desiredEndpointsByPortMap[epHash] = endpointsliceutil.EndpointSet{}
		}

		if _, ok := desiredMetaByPortMap[epHash]; !ok {
			desiredMetaByPortMap[epHash] = &endpointMeta{
				AddressType: addressType,
				Ports:       endpointPorts,
			}
		}
		
        // 获取所有的node
		node, err := r.nodeLister.Get(pod.Spec.NodeName)
		if err != nil {
			// we are getting the information from the local informer,
			// an error different than IsNotFound should not happen
			if !errors.IsNotFound(err) {
				return err
			}
			// Service处于未就绪状态
			if !service.Spec.PublishNotReadyAddresses {
				klog.Warningf("skipping Pod %s for Service %s/%s: Node %s Not Found", pod.Name, service.Namespace, service.Name, pod.Spec.NodeName)
				errs = append(errs, fmt.Errorf("skipping Pod %s for Service %s/%s: Node %s Not Found", pod.Name, service.Namespace, service.Name, pod.Spec.NodeName))
				continue
			}
		}
		endpoint := podToEndpoint(pod, node, service, addressType)
		if len(endpoint.Addresses) > 0 {
			desiredEndpointsByPortMap[epHash].Insert(&endpoint)
		}
	}

	spMetrics := metrics.NewServicePortCache()
	totalAdded := 0
	totalRemoved := 0

	// Determine changes necessary for each group of slices by port map.
	for portMap, desiredEndpoints := range desiredEndpointsByPortMap {
        // 统计 desiredEndpoints 的长度，表示这个端口映射需要创建的 endpoint 数量
		numEndpoints := len(desiredEndpoints)
        // 协调当前端口映射下的 endpoint 列表
		pmSlicesToCreate, pmSlicesToUpdate, pmSlicesToDelete, added, removed := r.reconcileByPortMapping(
			service, existingSlicesByPortMap[portMap], desiredEndpoints, desiredMetaByPortMap[portMap])

		totalAdded += added
		totalRemoved += removed

		spMetrics.Set(portMap, metrics.EfficiencyInfo{
			Endpoints: numEndpoints,
			Slices:    len(existingSlicesByPortMap[portMap]) + len(pmSlicesToCreate) - len(pmSlicesToDelete),
		})

		slicesToCreate = append(slicesToCreate, pmSlicesToCreate...)
		slicesToUpdate = append(slicesToUpdate, pmSlicesToUpdate...)
		slicesToDelete = append(slicesToDelete, pmSlicesToDelete...)
	}

	// If there are unique sets of ports that are no longer desired, mark
	// the corresponding endpoint slices for deletion.
	for portMap, existingSlices := range existingSlicesByPortMap {
		if _, ok := desiredEndpointsByPortMap[portMap]; !ok {
			slicesToDelete = append(slicesToDelete, existingSlices...)
		}
	}

	// 需要删除的 endpoint slice 的数量等于已存在的 endpoint slice 的数量，并且没有需要创建的 slice 的情况
	if len(existingSlices) == len(slicesToDelete) && len(slicesToCreate) < 1 {
		// 检查是否存在一个称为 placeholderSlice 的占位符 endpoint slice。
        // 如果存在，代码会比较它和需要删除的 endpoint slice 的第一个元素是否相等，如果相等，就会将需要删除的 slice 数组清空，否则就将占位符 slice 加入到需要创建的 slice 数组中
		placeholderSlice := newEndpointSlice(service, &endpointMeta{Ports: []discovery.EndpointPort{}, AddressType: addressType})
		if len(slicesToDelete) == 1 && placeholderSliceCompare.DeepEqual(slicesToDelete[0], placeholderSlice) {
			// We are about to unnecessarily delete/recreate the placeholder, remove it now.
			slicesToDelete = slicesToDelete[:0]
		} else {
			slicesToCreate = append(slicesToCreate, placeholderSlice)
		}
		spMetrics.Set(endpointutil.NewPortMapKey(placeholderSlice.Ports), metrics.EfficiencyInfo{
			Endpoints: 0,
			Slices:    1,
		})
	}

	metrics.EndpointsAddedPerSync.WithLabelValues().Observe(float64(totalAdded))
	metrics.EndpointsRemovedPerSync.WithLabelValues().Observe(float64(totalRemoved))

	serviceNN := types.NamespacedName{Name: service.Name, Namespace: service.Namespace}
	r.metricsCache.UpdateServicePortCache(serviceNN, spMetrics)

	si := &topologycache.SliceInfo{
		ServiceKey:  fmt.Sprintf("%s/%s", service.Namespace, service.Name),
		AddressType: addressType,
		ToCreate:    slicesToCreate,
		ToUpdate:    slicesToUpdate,
		Unchanged:   unchangedSlices(existingSlices, slicesToUpdate, slicesToDelete),
	}
	
    // 检查是否启用了TopologyHints，并向topologyCache添加hints。如果未启用，则从slicesToUpdate中删除hints。
    // 如果TopologyAwareHints注释已更改，则从topologyCache中删除hints，并记录事件。
	if r.topologyCache != nil && hintsEnabled(service.Annotations) {
		slicesToCreate, slicesToUpdate, events = r.topologyCache.AddHints(si)
	} else {
		if r.topologyCache != nil {
			if r.topologyCache.HasPopulatedHints(si.ServiceKey) {
				klog.InfoS("TopologyAwareHints annotation has changed, removing hints", "serviceKey", si.ServiceKey, "addressType", si.AddressType)
				events = append(events, &topologycache.EventBuilder{
					EventType: corev1.EventTypeWarning,
					Reason:    "TopologyAwareHintsDisabled",
					Message:   topologycache.FormatWithAddressType(topologycache.TopologyAwareHintsDisabled, si.AddressType),
				})
			}
			r.topologyCache.RemoveHints(si.ServiceKey, addressType)
		}
		slicesToCreate, slicesToUpdate = topologycache.RemoveHintsFromSlices(si)
	}
    // 最终协调和更新Endpoint Slice，并在更新过程中记录事件和错误
	err := r.finalize(service, slicesToCreate, slicesToUpdate, slicesToDelete, triggerTime)
	if err != nil {
		errs = append(errs, err)
	}
	for _, event := range events {
		r.eventRecorder.Event(service, event.EventType, event.Reason, event.Message)
	}
	return utilerrors.NewAggregate(errs)

}

var placeholderSliceCompare = conversion.EqualitiesOrDie(
	func(a, b metav1.OwnerReference) bool {
		return a.String() == b.String()
	},
	func(a, b metav1.ObjectMeta) bool {
		if a.Namespace != b.Namespace {
			return false
		}
		for k, v := range a.Labels {
			if b.Labels[k] != v {
				return false
			}
		}
		for k, v := range b.Labels {
			if a.Labels[k] != v {
				return false
			}
		}
		return true
	},
)

func (r *reconciler) finalize(
	service *corev1.Service,
	slicesToCreate,
	slicesToUpdate,
	slicesToDelete []*discovery.EndpointSlice,
	triggerTime time.Time,
) error {
	// If there are slices to create and delete, change the creates to updates
	// of the slices that would otherwise be deleted.
	for i := 0; i < len(slicesToDelete); {
        // 如果数组 slicesToCreate 为空，循环将退出
		if len(slicesToCreate) == 0 {
			break
		}
        // 每次循环，将选择一个 sliceToDelete 和一个 slice
		sliceToDelete := slicesToDelete[i]
		slice := slicesToCreate[len(slicesToCreate)-1]
		// 只有在它们具有相同的 AddressType 和属于该 Service 时，才会更新 slice 并将其添加到 slicesToUpdate 中
        // 更新后的 slice 的名称与 sliceToDelete 的名称相同。
        // 最后，将 sliceToDelete 从 slicesToDelete 中删除并将 slice 从 slicesToCreate 中删除。
		if sliceToDelete.AddressType == slice.AddressType && ownedBy(sliceToDelete, service) {
			slice.Name = sliceToDelete.Name
			slicesToCreate = slicesToCreate[:len(slicesToCreate)-1]
			slicesToUpdate = append(slicesToUpdate, slice)
			slicesToDelete = append(slicesToDelete[:i], slicesToDelete[i+1:]...)
		} else {
			i++
		}
	}

	// 如果service没有标记为删除，则会遍历 slicesToCreate 数组中的所有 EndpointSlice 对象进行创建
	if service.DeletionTimestamp == nil {
		for _, endpointSlice := range slicesToCreate {
			addTriggerTimeAnnotation(endpointSlice, triggerTime)
			createdSlice, err := r.client.DiscoveryV1().EndpointSlices(service.Namespace).Create(context.TODO(), endpointSlice, metav1.CreateOptions{})
			if err != nil {
				// If the namespace is terminating, creates will continue to fail. Simply drop the item.
				if errors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
					return nil
				}
				return fmt.Errorf("failed to create EndpointSlice for Service %s/%s: %v", service.Namespace, service.Name, err)
			}
			r.endpointSliceTracker.Update(createdSlice)
			metrics.EndpointSliceChanges.WithLabelValues("create").Inc()
		}
	}
	
    // 更新slicesToUpdate
	for _, endpointSlice := range slicesToUpdate {
		addTriggerTimeAnnotation(endpointSlice, triggerTime)
		updatedSlice, err := r.client.DiscoveryV1().EndpointSlices(service.Namespace).Update(context.TODO(), endpointSlice, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update %s EndpointSlice for Service %s/%s: %v", endpointSlice.Name, service.Namespace, service.Name, err)
		}
		r.endpointSliceTracker.Update(updatedSlice)
		metrics.EndpointSliceChanges.WithLabelValues("update").Inc()
	}
	
    // 删除slicesToDelete
	for _, endpointSlice := range slicesToDelete {
		err := r.client.DiscoveryV1().EndpointSlices(service.Namespace).Delete(context.TODO(), endpointSlice.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete %s EndpointSlice for Service %s/%s: %v", endpointSlice.Name, service.Namespace, service.Name, err)
		}
		r.endpointSliceTracker.ExpectDeletion(endpointSlice)
		metrics.EndpointSliceChanges.WithLabelValues("delete").Inc()
	}
	
    // 记录EndpointSlice更改的拓扑标签
	topologyLabel := "Disabled"
	if r.topologyCache != nil && hintsEnabled(service.Annotations) {
		topologyLabel = "Auto"
	}

	numSlicesChanged := len(slicesToCreate) + len(slicesToUpdate) + len(slicesToDelete)
	metrics.EndpointSlicesChangedPerSync.WithLabelValues(topologyLabel).Observe(float64(numSlicesChanged))

	return nil
}

func (r *reconciler) reconcileByPortMapping(
	service *corev1.Service,
	existingSlices []*discovery.EndpointSlice,
	desiredSet endpointsliceutil.EndpointSet,
	endpointMeta *endpointMeta,
) ([]*discovery.EndpointSlice, []*discovery.EndpointSlice, []*discovery.EndpointSlice, int, int) {
	slicesByName := map[string]*discovery.EndpointSlice{}
	sliceNamesUnchanged := sets.String{}
	sliceNamesToUpdate := sets.String{}
	sliceNamesToDelete := sets.String{}
	numRemoved := 0

	// 1. 遍历现有的 endpoint slice，删除不再需要的 endpoint 并更新已更改的 endpoint。
	for _, existingSlice := range existingSlices {
		slicesByName[existingSlice.Name] = existingSlice
		newEndpoints := []discovery.Endpoint{}
		endpointUpdated := false
		for _, endpoint := range existingSlice.Endpoints {
			got := desiredSet.Get(&endpoint)
			//  如果 endpoint 仍然需要，将其添加到要保留的 endpoint 列表中。
			if got != nil {
				newEndpoints = append(newEndpoints, *got)
				// 如果现有的 endpoint 版本与期望的版本不同，则将 endpointUpdated 设置为 true，以确保将 endpoint 更改持久化。
				if !endpointutil.EndpointsEqualBeyondHash(got, &endpoint) {
					endpointUpdated = true
				}
				//// 在 slice 中找到 endpoint 后，将其从 desiredSet 中删除。
				desiredSet.Delete(&endpoint)
			}
		}

		// 生成切片标签并检查父标签是否已更改
		labels, labelsChanged := setEndpointSliceLabels(existingSlice, service)

		// 如果 endpoint 已更新或删除，则将其标记为更新或删除。
		if endpointUpdated || len(existingSlice.Endpoints) != len(newEndpoints) {
			if len(existingSlice.Endpoints) > len(newEndpoints) {
				numRemoved += len(existingSlice.Endpoints) - len(newEndpoints)
			}
			if len(newEndpoints) == 0 {
				//  如果此 slice 中不需要 endpoint，则标记为删除。
				sliceNamesToDelete.Insert(existingSlice.Name)
			} else {
				//  否则，复制 slice 并将其标记为更新。
				epSlice := existingSlice.DeepCopy()
				epSlice.Endpoints = newEndpoints
				epSlice.Labels = labels
				slicesByName[existingSlice.Name] = epSlice
				sliceNamesToUpdate.Insert(epSlice.Name)
			}
		} else if labelsChanged {
			//如果标签已更改，则复制 slice 并将其标记为更新。
			epSlice := existingSlice.DeepCopy()
			epSlice.Labels = labels
			slicesByName[existingSlice.Name] = epSlice
			sliceNamesToUpdate.Insert(epSlice.Name)
		} else {
			//  如果 slice 没有更改，则对后续处理留下一些有用的 slice。
			sliceNamesUnchanged.Insert(existingSlice.Name)
		}
	}

	numAdded := desiredSet.Len()

	// 2. 如果我们仍然有要添加的 endpoint 并且有已标记更新的 slice，则遍历这些 slice 并使用期望的 endpoint 填充它们。
	if desiredSet.Len() > 0 && sliceNamesToUpdate.Len() > 0 {
		slices := []*discovery.EndpointSlice{}
		for _, sliceName := range sliceNamesToUpdate.UnsortedList() {
			slices = append(slices, slicesByName[sliceName])
		}
		// Sort endpoint slices by length so we're filling up the fullest ones
		// first.
		sort.Sort(endpointSliceEndpointLen(slices))

		// 遍历切片并用所需的endpoint填充它们
		for _, slice := range slices {
			for desiredSet.Len() > 0 && len(slice.Endpoints) < int(r.maxEndpointsPerSlice) {
				endpoint, _ := desiredSet.PopAny()
				slice.Endpoints = append(slice.Endpoints, *endpoint)
			}
		}
	}

	// 3.如果此时仍有所需的endpoint，我们将尝试在单个现有切片中拟合endpoint。如果没有具有该容量的切片，我们将为端点创建新的切片。
	slicesToCreate := []*discovery.EndpointSlice{}

	for desiredSet.Len() > 0 {
		var sliceToFill *discovery.EndpointSlice

		// 如果剩余的endpoint数量小于每个切片的最大端点数量，并且我们有尚未填充的切片，请尝试将它们放在一个切片中。
		if desiredSet.Len() < int(r.maxEndpointsPerSlice) && sliceNamesUnchanged.Len() > 0 {
			unchangedSlices := []*discovery.EndpointSlice{}
			for _, sliceName := range sliceNamesUnchanged.UnsortedList() {
				unchangedSlices = append(unchangedSlices, slicesByName[sliceName])
			}
			sliceToFill = getSliceToFill(unchangedSlices, desiredSet.Len(), int(r.maxEndpointsPerSlice))
		}

		// 如果没有找到sliceToFill，请生成一个新的空sliceToFill。
		if sliceToFill == nil {
			sliceToFill = newEndpointSlice(service, endpointMeta)
		} else {
			// deep copy required to modify this slice.
			sliceToFill = sliceToFill.DeepCopy()
			slicesByName[sliceToFill.Name] = sliceToFill
		}

		// 用剩余的端点填充切片。
		for desiredSet.Len() > 0 && len(sliceToFill.Endpoints) < int(r.maxEndpointsPerSlice) {
			endpoint, _ := desiredSet.PopAny()
			sliceToFill.Endpoints = append(sliceToFill.Endpoints, *endpoint)
		}

		// 新切片将没有名称集，请使用该设置来确定这是更新还是创建。
		if sliceToFill.Name != "" {
			sliceNamesToUpdate.Insert(sliceToFill.Name)
			sliceNamesUnchanged.Delete(sliceToFill.Name)
		} else {
			slicesToCreate = append(slicesToCreate, sliceToFill)
		}
	}

	// Build slicesToUpdate from slice names.
	slicesToUpdate := []*discovery.EndpointSlice{}
	for _, sliceName := range sliceNamesToUpdate.UnsortedList() {
		slicesToUpdate = append(slicesToUpdate, slicesByName[sliceName])
	}

	// Build slicesToDelete from slice names.
	slicesToDelete := []*discovery.EndpointSlice{}
	for _, sliceName := range sliceNamesToDelete.UnsortedList() {
		slicesToDelete = append(slicesToDelete, slicesByName[sliceName])
	}

	return slicesToCreate, slicesToUpdate, slicesToDelete, numAdded, numRemoved
}


unc (r *reconciler) deleteService(namespace, name string) {
	r.metricsCache.DeleteService(types.NamespacedName{Namespace: namespace, Name: name})
}
```

```GO
func serviceControllerKey(endpointSlice *discovery.EndpointSlice) (string, error) {
	if endpointSlice == nil {
		return "", fmt.Errorf("nil EndpointSlice passed to serviceControllerKey()")
	}
	serviceName, ok := endpointSlice.Labels[discovery.LabelServiceName]
	if !ok || serviceName == "" {
		return "", fmt.Errorf("EndpointSlice missing %s label", discovery.LabelServiceName)
	}
	return fmt.Sprintf("%s/%s", endpointSlice.Namespace, serviceName), nil
}

func getAddressTypesForService(service *v1.Service) map[discovery.AddressType]struct{} {
	serviceSupportedAddresses := make(map[discovery.AddressType]struct{})
	
    // 便利所有支持的IPFamilies
	for _, family := range service.Spec.IPFamilies {
		if family == v1.IPv4Protocol {
			serviceSupportedAddresses[discovery.AddressTypeIPv4] = struct{}{}
		}

		if family == v1.IPv6Protocol {
			serviceSupportedAddresses[discovery.AddressTypeIPv6] = struct{}{}
		}
	}
	
    // 找到了支持的ip族 直接返回
	if len(serviceSupportedAddresses) > 0 {
		return serviceSupportedAddresses 
	}
	//  如果Service的ClusterIP不为空，则使用ClusterIP所在的IP协议族作为依据
	if len(service.Spec.ClusterIP) > 0 && service.Spec.ClusterIP != v1.ClusterIPNone { 
		addrType := discovery.AddressTypeIPv4
		if utilnet.IsIPv6String(service.Spec.ClusterIP) {
			addrType = discovery.AddressTypeIPv6
		}
		serviceSupportedAddresses[addrType] = struct{}{}
		klog.V(2).Infof("couldn't find ipfamilies for service: %v/%v. This could happen if controller manager is connected to an old apiserver that does not support ip families yet. EndpointSlices for this Service will use %s as the IP Family based on familyOf(ClusterIP:%v).", service.Namespace, service.Name, addrType, service.Spec.ClusterIP)
		return serviceSupportedAddresses
	}

	// 如果是headless service，则默认支持IPv4和IPv6两种协议族
	serviceSupportedAddresses[discovery.AddressTypeIPv4] = struct{}{}
	serviceSupportedAddresses[discovery.AddressTypeIPv6] = struct{}{}
	klog.V(2).Infof("couldn't find ipfamilies for headless service: %v/%v likely because controller manager is likely connected to an old apiserver that does not support ip families yet. The service endpoint slice will use dual stack families until api-server default it correctly", service.Namespace, service.Name)
	return serviceSupportedAddresses
}

func ownedBy(endpointSlice *discovery.EndpointSlice, svc *v1.Service) bool {
	for _, o := range endpointSlice.OwnerReferences {
		if o.UID == svc.UID && o.Kind == "Service" && o.APIVersion == "v1" {
			return true
		}
	}
	return false
}
```

### TopologyCache

```go
type TopologyCache struct {
	lock                    sync.Mutex
    // 表示是否收集了足够的节点信息
	sufficientNodeInfo      bool
    // 可用区域映射到其CPU容量
	cpuByZone               map[string]*resource.Quantity
    // 可用区域映射到其CPU使用率
	cpuRatiosByZone         map[string]float64
    // 服务名称映射到其终端点的分布信息
	endpointsByService      map[string]map[discovery.AddressType]EndpointZoneInfo
    // 哪些服务的提示信息已经填充
	hintsPopulatedByService sets.Set[string]
}

// 可用区域映射到终端点数量
type EndpointZoneInfo map[string]int

// 区域分配的终端点数量，包括最小、最大和期望值
type Allocation struct {
	Minimum int
	Maximum int
	Desired float64
}

func NewTopologyCache() *TopologyCache {
	return &TopologyCache{
		cpuByZone:               map[string]*resource.Quantity{},
		cpuRatiosByZone:         map[string]float64{},
		endpointsByService:      map[string]map[discovery.AddressType]EndpointZoneInfo{},
		hintsPopulatedByService: sets.Set[string]{},
	}
}

// 获取负载过高的服务列表
func (t *TopologyCache) GetOverloadedServices() []string {
	t.lock.Lock()
	defer t.lock.Unlock()

	svcKeys := []string{}
    // 遍历素有endpointsByService  svcKey是服务名，eziByAddrType是一个map
	for svcKey, eziByAddrType := range t.endpointsByService {
		for _, ezi := range eziByAddrType {
			if serviceOverloaded(ezi, t.cpuRatiosByZone) {
                // 表示该服务过载，需要将其服务名添加到svcKeys中
				svcKeys = append(svcKeys, svcKey)
				break
			}
		}
	}

	return svcKeys
}

// 将拓扑感知的提示（Topology Aware Hints）添加到给定的EndpointSlice中
func (t *TopologyCache) AddHints(si *SliceInfo) ([]*discovery.EndpointSlice, []*discovery.EndpointSlice, []*EventBuilder) {
    // 获取给定EndpointSlice的所有就绪的Endpoint的数量
	totalEndpoints := si.getTotalReadyEndpoints()
    // 获取可用的Hints分配并生成EventBuilder对象
	allocations, allocationsEvent := t.getAllocations(totalEndpoints)
	events := []*EventBuilder{}
    // 如果allocationsEvent不为空，说明Hints分配失败。
	if allocationsEvent != nil {
		klog.InfoS(allocationsEvent.Message+", removing hints", "serviceKey", si.ServiceKey, "addressType", si.AddressType)
		allocationsEvent.Message = FormatWithAddressType(allocationsEvent.Message, si.AddressType)
		events = append(events, allocationsEvent)
        // 从缓存中删除Hints，并调用RemoveHintsFromSlices函数从EndpointSlice对象中删除Hints
		t.RemoveHints(si.ServiceKey, si.AddressType)
		slicesToCreate, slicesToUpdate := RemoveHintsFromSlices(si)
		return slicesToCreate, slicesToUpdate, events
	}
	
    // 获取每个区域分配的Hints的数量
	allocatedHintsByZone := si.getAllocatedHintsByZone(allocations)

	allocatableSlices := si.ToCreate
	for _, slice := range si.ToUpdate {
		allocatableSlices = append(allocatableSlices, slice)
	}

	// 对于每个EndpointSlice对象和其中的每个Endpoint对象，如果Endpoint对象未准备好，则将其Hints设置为nil
	for _, slice := range allocatableSlices {
		for i, endpoint := range slice.Endpoints {
			if !endpointsliceutil.EndpointReady(endpoint) {
				endpoint.Hints = nil
				continue
			}
			if endpoint.Zone == nil || *endpoint.Zone == "" {
				klog.InfoS("Endpoint found without zone specified, removing hints", "serviceKey", si.ServiceKey, "addressType", si.AddressType)
				events = append(events, &EventBuilder{
					EventType: v1.EventTypeWarning,
					Reason:    "TopologyAwareHintsDisabled",
					Message:   FormatWithAddressType(NoZoneSpecified, si.AddressType),
				})
				t.RemoveHints(si.ServiceKey, si.AddressType)
				slicesToCreate, slicesToUpdate := RemoveHintsFromSlices(si)
				return slicesToCreate, slicesToUpdate, events
			}

			allocatedHintsByZone[*endpoint.Zone]++
			slice.Endpoints[i].Hints = &discovery.EndpointHints{ForZones: []discovery.ForZone{{Name: *endpoint.Zone}}}
		}
	}

	// 获取需要分配切片的区域和需要接收切片的区域
	givingZones, receivingZones := getGivingAndReceivingZones(allocations, allocatedHintsByZone)

	// 尝试将未使用的切片分配给需要更多切片的区域
	redistributions := redistributeHints(allocatableSlices, givingZones, receivingZones)

	for zone, diff := range redistributions {
		allocatedHintsByZone[zone] += diff
	}
	
    // 如果没有为zone分配提示，那么我们就要将其从服务中移除
	if len(allocatedHintsByZone) == 0 {
		klog.V(2).InfoS("No hints allocated for zones, removing them", "serviceKey", si.ServiceKey, "addressType", si.AddressType)
		events = append(events, &EventBuilder{
			EventType: v1.EventTypeWarning,
			Reason:    "TopologyAwareHintsDisabled",
			Message:   FormatWithAddressType(NoAllocatedHintsForZones, si.AddressType),
		})
		t.RemoveHints(si.ServiceKey, si.AddressType)
		slicesToCreate, slicesToUpdate := RemoveHintsFromSlices(si)
		return slicesToCreate, slicesToUpdate, events
	}

	hintsEnabled := t.hintsPopulatedByService.Has(si.ServiceKey)
	t.SetHints(si.ServiceKey, si.AddressType, allocatedHintsByZone)

	// 如果之前没有启用提示，我们会发布一个事件来表示我们启用了提示。
	if !hintsEnabled {
		klog.InfoS("Topology Aware Hints has been enabled, adding hints.", "serviceKey", si.ServiceKey, "addressType", si.AddressType)
		events = append(events, &EventBuilder{
			EventType: v1.EventTypeNormal,
			Reason:    "TopologyAwareHintsEnabled",
			Message:   FormatWithAddressType(TopologyAwareHintsEnabled, si.AddressType),
		})
	}
	return si.ToCreate, si.ToUpdate, events
}

// SetHints为此缓存中提供的serviceKey和addrType设置拓扑提示。
func (t *TopologyCache) SetHints(serviceKey string, addrType discovery.AddressType, allocatedHintsByZone EndpointZoneInfo) {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, ok := t.endpointsByService[serviceKey]
	if !ok {
		t.endpointsByService[serviceKey] = map[discovery.AddressType]EndpointZoneInfo{}
	}
	t.endpointsByService[serviceKey][addrType] = allocatedHintsByZone

	t.hintsPopulatedByService.Insert(serviceKey)
}

// RemoveHints删除提供的serviceKey和addrType的拓扑提示从这个缓存。
func (t *TopologyCache) RemoveHints(serviceKey string, addrType discovery.AddressType) {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, ok := t.endpointsByService[serviceKey]
	if ok {
		delete(t.endpointsByService[serviceKey], addrType)
	}
	if len(t.endpointsByService[serviceKey]) == 0 {
		delete(t.endpointsByService, serviceKey)
	}
	t.hintsPopulatedByService.Delete(serviceKey)
}

// SetNodes更新TopologyCache的节点分布
func (t *TopologyCache) SetNodes(nodes []*v1.Node) {
	cpuByZone := map[string]*resource.Quantity{}
	sufficientNodeInfo := true

	totalCPU := resource.Quantity{}

	for _, node := range nodes {
		if hasExcludedLabels(node.Labels) {
			klog.V(2).Infof("Ignoring node %s because it has an excluded label", node.Name)
			continue
		}
		if !NodeReady(node.Status) {
			klog.V(2).Infof("Ignoring node %s because it is not ready: %v", node.Name, node.Status.Conditions)
			continue
		}

		nodeCPU := node.Status.Allocatable.Cpu()
		zone, ok := node.Labels[v1.LabelTopologyZone]

		// TODO(robscott): Figure out if there's an acceptable proportion of
		// nodes with inadequate information. The current logic means that as
		// soon as we find any node without a zone or allocatable CPU specified,
		// we bail out entirely. Bailing out at this level will make our cluster
		// wide ratios nil, which would result in slices for all Services having
		// their hints removed.
		if !ok || zone == "" || nodeCPU.IsZero() {
			cpuByZone = map[string]*resource.Quantity{}
			sufficientNodeInfo = false
			klog.Warningf("Can't get CPU or zone information for %s node", node.Name)
			break
		}

		totalCPU.Add(*nodeCPU)
		if _, ok = cpuByZone[zone]; !ok {
			cpuByZone[zone] = nodeCPU
		} else {
			cpuByZone[zone].Add(*nodeCPU)
		}
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	if totalCPU.IsZero() || !sufficientNodeInfo || len(cpuByZone) < 2 {
		klog.V(2).Infof("Insufficient node info for topology hints (%d zones, %s CPU, %t)", len(cpuByZone), totalCPU.String(), sufficientNodeInfo)
		t.sufficientNodeInfo = false
		t.cpuByZone = nil
		t.cpuRatiosByZone = nil

	} else {
		t.sufficientNodeInfo = sufficientNodeInfo
		t.cpuByZone = cpuByZone

		t.cpuRatiosByZone = map[string]float64{}
		for zone, cpu := range cpuByZone {
			t.cpuRatiosByZone[zone] = float64(cpu.MilliValue()) / float64(totalCPU.MilliValue())
		}
	}
}

// HasPopulatedHints checks whether there are populated hints for a given service in the cache.
func (t *TopologyCache) HasPopulatedHints(serviceKey string) bool {
	return t.hintsPopulatedByService.Has(serviceKey)
}

// getAllocations returns a set of minimum and maximum allocations per zone. If
// it is not possible to provide allocations that are below the overload
// threshold, a nil value will be returned.
func (t *TopologyCache) getAllocations(numEndpoints int) (map[string]Allocation, *EventBuilder) {
	// it is similar to checking !t.sufficientNodeInfo
	if t.cpuRatiosByZone == nil {
		return nil, &EventBuilder{
			EventType: v1.EventTypeWarning,
			Reason:    "TopologyAwareHintsDisabled",
			Message:   InsufficientNodeInfo,
		}
	}
	if len(t.cpuRatiosByZone) < 2 {
		return nil, &EventBuilder{
			EventType: v1.EventTypeWarning,
			Reason:    "TopologyAwareHintsDisabled",
			Message:   NodesReadyInOneZoneOnly,
		}
	}
	if len(t.cpuRatiosByZone) > numEndpoints {
		return nil, &EventBuilder{
			EventType: v1.EventTypeWarning,
			Reason:    "TopologyAwareHintsDisabled",
			Message:   fmt.Sprintf("%s (%d endpoints, %d zones)", InsufficientNumberOfEndpoints, numEndpoints, len(t.cpuRatiosByZone)),
		}
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	remainingMinEndpoints := numEndpoints
	minTotal := 0
	allocations := map[string]Allocation{}

	for zone, ratio := range t.cpuRatiosByZone {
		desired := ratio * float64(numEndpoints)
		minimum := int(math.Ceil(desired * (1 / (1 + OverloadThreshold))))
		allocations[zone] = Allocation{
			Minimum: minimum,
			Desired: math.Max(desired, float64(minimum)),
		}
		minTotal += minimum
		remainingMinEndpoints -= minimum
		if remainingMinEndpoints < 0 {
			return nil, &EventBuilder{
				EventType: v1.EventTypeWarning,
				Reason:    "TopologyAwareHintsDisabled",
				Message:   fmt.Sprintf("%s (%d endpoints, %d zones)", MinAllocationExceedsOverloadThreshold, numEndpoints, len(t.cpuRatiosByZone)),
			}
		}
	}

	for zone, allocation := range allocations {
		allocation.Maximum = allocation.Minimum + numEndpoints - minTotal
		allocations[zone] = allocation
	}

	return allocations, nil
}

// Nodes with any of these labels set to any value will be excluded from
// topology capacity calculations.
func hasExcludedLabels(labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	if _, ok := labels["node-role.kubernetes.io/control-plane"]; ok {
		return true
	}
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		return true
	}
	return false
}

```



## New

```GO
func NewController(podInformer coreinformers.PodInformer,
	serviceInformer coreinformers.ServiceInformer,
	nodeInformer coreinformers.NodeInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	maxEndpointsPerSlice int32,
	client clientset.Interface,
	endpointUpdatesBatchPeriod time.Duration,
) *Controller {
    // 创建广播事件 记录事件
	broadcaster := record.NewBroadcaster()
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "endpoint-slice-controller"})
	// 开启Metrics
	endpointslicemetrics.RegisterMetrics()

	c := &Controller{
		client: client,
		// This is similar to the DefaultControllerRateLimiter, just with a
		// significantly higher default backoff (1s vs 5ms). This controller
		// processes events that can require significant EndpointSlice changes,
		// such as an update to a Service or Deployment. A more significant
		// rate limit back off here helps ensure that the Controller does not
		// overwhelm the API Server.
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
			// 10 qps, 100 bucket size. This is only for retry speed and its
			// only the overall factor (not per item).
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "endpoint_slice"),
		workerLoopPeriod: time.Second,
	}
	// 监控service 的 add update delete方法做操作
	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.onServiceUpdate,
		UpdateFunc: func(old, cur interface{}) {
			c.onServiceUpdate(cur)
		},
		DeleteFunc: c.onServiceDelete,
	})
	c.serviceLister = serviceInformer.Lister()
	c.servicesSynced = serviceInformer.Informer().HasSynced
	
    // 监控 pod 的 add update delete方法做操作
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPod,
		UpdateFunc: c.updatePod,
		DeleteFunc: c.deletePod,
	})
	c.podLister = podInformer.Lister()
	c.podsSynced = podInformer.Informer().HasSynced

	c.nodeLister = nodeInformer.Lister()
	c.nodesSynced = nodeInformer.Informer().HasSynced
	
    //  监控 endpointSlice 的 add update delete方法做操作
	endpointSliceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onEndpointSliceAdd,
		UpdateFunc: c.onEndpointSliceUpdate,
		DeleteFunc: c.onEndpointSliceDelete,
	})

	c.endpointSliceLister = endpointSliceInformer.Lister()
	c.endpointSlicesSynced = endpointSliceInformer.Informer().HasSynced
	c.endpointSliceTracker = endpointsliceutil.NewEndpointSliceTracker()

	c.maxEndpointsPerSlice = maxEndpointsPerSlice

	c.triggerTimeTracker = endpointutil.NewTriggerTimeTracker()

	c.eventBroadcaster = broadcaster
	c.eventRecorder = recorder

	c.endpointUpdatesBatchPeriod = endpointUpdatesBatchPeriod
	
    // 如果开启了拓扑感知 监控node的 add update delete方法做操作
	if utilfeature.DefaultFeatureGate.Enabled(features.TopologyAwareHints) {
		nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNode,
			UpdateFunc: c.updateNode,
			DeleteFunc: c.deleteNode,
		})

		c.topologyCache = topologycache.NewTopologyCache()
	}

	c.reconciler = &reconciler{
		client:               c.client,
		nodeLister:           c.nodeLister,
		maxEndpointsPerSlice: c.maxEndpointsPerSlice,
		endpointSliceTracker: c.endpointSliceTracker,
		metricsCache:         endpointslicemetrics.NewCache(maxEndpointsPerSlice),
		topologyCache:        c.topologyCache,
		eventRecorder:        c.eventRecorder,
	}

	return c
}
```

### 队列相关

#### **service**

```go
func (c *Controller) onServiceUpdate(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}

	c.queue.Add(key)
}
```

#### **pod**

```go
// 都是到service 然后加入队列
func (c *Controller) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	services, err := endpointutil.GetPodServiceMemberships(c.serviceLister, pod)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Unable to get pod %s/%s's service memberships: %v", pod.Namespace, pod.Name, err))
		return
	}
	for key := range services {
		c.queue.AddAfter(key, c.endpointUpdatesBatchPeriod)
	}
}

func (c *Controller) updatePod(old, cur interface{}) {
	services := endpointutil.GetServicesToUpdateOnPodChange(c.serviceLister, old, cur)
	for key := range services {
		c.queue.AddAfter(key, c.endpointUpdatesBatchPeriod)
	}
}

// When a pod is deleted, enqueue the services the pod used to be a member of
// obj could be an *v1.Pod, or a DeletionFinalStateUnknown marker item.
func (c *Controller) deletePod(obj interface{}) {
	pod := endpointutil.GetPodFromDeleteAction(obj)
	if pod != nil {
		c.addPod(pod)
	}
}
```

##### GetPodServiceMemberships,GetServicesToUpdateOnPodChange,GetPodFromDeleteAction

```go
// 根据pod获取service
func GetPodServiceMemberships(serviceLister v1listers.ServiceLister, pod *v1.Pod) (sets.String, error) {
	set := sets.String{}
    // 获取所有的services
	services, err := serviceLister.Services(pod.Namespace).List(labels.Everything())
	if err != nil {
		return set, err
	}

	for _, service := range services {
		if service.Spec.Selector == nil {
			// if the service has a nil selector this means selectors match nothing, not everything.
			continue
		}
		key, err := controller.KeyFunc(service)
		if err != nil {
			return nil, err
		}
		if labels.ValidatedSetSelector(service.Spec.Selector).Matches(labels.Set(pod.Labels)) {
			set.Insert(key)
		}
	}
	return set, nil
}

func GetServicesToUpdateOnPodChange(serviceLister v1listers.ServiceLister, old, cur interface{}) sets.String {
	newPod := cur.(*v1.Pod)
	oldPod := old.(*v1.Pod)
    // 两次的ResourceVersion说明没更新
	if newPod.ResourceVersion == oldPod.ResourceVersion {
		// Periodic resync will send update events for all known pods.
		// Two different versions of the same pod will always have different RVs
		return sets.String{}
	}
	
    // 检查 pod 和 label 是否发生了变化
	podChanged, labelsChanged := podEndpointsChanged(oldPod, newPod)

	// 如果 pod 和 label 都没有变化 直接返回
	if !podChanged && !labelsChanged {
		return sets.String{}
	}
	
    
    // 获取 newPod 对象所属的所有服务
	services, err := GetPodServiceMemberships(serviceLister, newPod)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to get pod %s/%s's service memberships: %v", newPod.Namespace, newPod.Name, err))
		return sets.String{}
	}
	
	if labelsChanged {
        // 如果 label 发生了变化，还需要获取 oldPod 对象所属的服务列表
		oldServices, err := GetPodServiceMemberships(serviceLister, oldPod)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("unable to get pod %s/%s's service memberships: %v", newPod.Namespace, newPod.Name, err))
		}
        // 判断是否更新服务
		services = determineNeededServiceUpdates(oldServices, services, podChanged)
	}

	return services
}

func GetPodFromDeleteAction(obj interface{}) *v1.Pod {
    // 断言pod 如果ok 直接返回
	if pod, ok := obj.(*v1.Pod); ok {
		return pod
	}
	// 从缓存里拿
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
		return nil
	}
	pod, ok := tombstone.Obj.(*v1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Pod: %#v", obj))
		return nil
	}
	return pod
}

```

###### podEndpointsChanged，determineNeededServiceUpdates

```GO
func podEndpointsChanged(oldPod, newPod *v1.Pod) (bool, bool) {
	// Check if the pod labels have changed, indicating a possible
	// change in the service membership
	labelsChanged := false
	if !reflect.DeepEqual(newPod.Labels, oldPod.Labels) ||
		!hostNameAndDomainAreEqual(newPod, oldPod) {
		labelsChanged = true
	}

	// If the pod's deletion timestamp is set, remove endpoint from ready address.
	if newPod.DeletionTimestamp != oldPod.DeletionTimestamp {
		return true, labelsChanged
	}
	// If the pod's readiness has changed, the associated endpoint address
	// will move from the unready endpoints set to the ready endpoints.
	// So for the purposes of an endpoint, a readiness change on a pod
	// means we have a changed pod.
	if podutil.IsPodReady(oldPod) != podutil.IsPodReady(newPod) {
		return true, labelsChanged
	}

	// Check if the pod IPs have changed
	if len(oldPod.Status.PodIPs) != len(newPod.Status.PodIPs) {
		return true, labelsChanged
	}
	for i := range oldPod.Status.PodIPs {
		if oldPod.Status.PodIPs[i].IP != newPod.Status.PodIPs[i].IP {
			return true, labelsChanged
		}
	}

	// Endpoints may also reference a pod's Name, Namespace, UID, and NodeName, but
	// the first three are immutable, and NodeName is immutable once initially set,
	// which happens before the pod gets an IP.

	return false, labelsChanged
}

func determineNeededServiceUpdates(oldServices, services sets.String, podChanged bool) sets.String {
	if podChanged {
		//  如果 Pod 变化了，那么需要更新所有的服务，因为所有的服务都与该 Pod 有关系，
        // 所以将 services 与 oldServices 的并集作为结果返回
		services = services.Union(oldServices)
	} else {
		// 如果 Pod 没有变化，则只需要更新与新旧服务集合不同的服务
		services = services.Difference(oldServices).Union(oldServices.Difference(services))
	}
	return services
}
```

#### **endpointslice**

```GO
func (c *Controller) onEndpointSliceAdd(obj interface{}) {
	endpointSlice := obj.(*discovery.EndpointSlice)
	if endpointSlice == nil {
		utilruntime.HandleError(fmt.Errorf("Invalid EndpointSlice provided to onEndpointSliceAdd()"))
		return
	}
    // 判断是不是用本控制器管理和是否需要同步EndpointSlice 如果是加入队列
	if managedByController(endpointSlice) && c.endpointSliceTracker.ShouldSync(endpointSlice) {
		c.queueServiceForEndpointSlice(endpointSlice)
	}
}

func (c *Controller) onEndpointSliceUpdate(prevObj, obj interface{}) {
	prevEndpointSlice := prevObj.(*discovery.EndpointSlice)
	endpointSlice := obj.(*discovery.EndpointSlice)
	if endpointSlice == nil || prevEndpointSlice == nil {
		utilruntime.HandleError(fmt.Errorf("Invalid EndpointSlice provided to onEndpointSliceUpdate()"))
		return
	}
	svcName := endpointSlice.Labels[discovery.LabelServiceName]
	prevSvcName := prevEndpointSlice.Labels[discovery.LabelServiceName]
    // 判断serviceName变没变化 如果变化了 要重新同步
	if svcName != prevSvcName {
		klog.Warningf("%s label changed from %s  to %s for %s", discovery.LabelServiceName, prevSvcName, svcName, endpointSlice.Name)
		c.queueServiceForEndpointSlice(endpointSlice)
		c.queueServiceForEndpointSlice(prevEndpointSlice)
		return
	}
	// 判断是不是用本控制器管理和是否需要同步EndpointSlice 如果是加入队列 或者是更新前后是不同的controller管理的
	if managedByChanged(prevEndpointSlice, endpointSlice) || (managedByController(endpointSlice) && c.endpointSliceTracker.ShouldSync(endpointSlice)) {
		c.queueServiceForEndpointSlice(endpointSlice)
	}
}

func (c *Controller) onEndpointSliceDelete(obj interface{}) {
	endpointSlice := getEndpointSliceFromDeleteAction(obj)
    // 是否由该控制器创建，并检查该对象是否被跟踪
	if endpointSlice != nil && managedByController(endpointSlice) && c.endpointSliceTracker.Has(endpointSlice) {
		// 通过 HandleDeletion 方法告知跟踪器该对象已经被删除，如果返回 false，
        // 说明该对象没有被预期删除，需要重新将对应的 Service 对象加入队列等待同步
		if !c.endpointSliceTracker.HandleDeletion(endpointSlice) {
			c.queueServiceForEndpointSlice(endpointSlice)
		}
	}
}
```

```GO
func managedByController(endpointSlice *discovery.EndpointSlice) bool {
	managedBy, _ := endpointSlice.Labels[discovery.LabelManagedBy]
	return managedBy == controllerName
}

func managedByChanged(endpointSlice1, endpointSlice2 *discovery.EndpointSlice) bool {
	return managedByController(endpointSlice1) != managedByController(endpointSlice2)
}

LabelManagedBy = "endpointslice.kubernetes.io/managed-by"
controllerName = "endpointslice-controller.k8s.io"
```



## Run

```go
func (c *Controller) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	// Start events processing pipeline.
	c.eventBroadcaster.StartLogging(klog.Infof)
	c.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: c.client.CoreV1().Events("")})
	defer c.eventBroadcaster.Shutdown()

	defer c.queue.ShutDown()

	klog.Infof("Starting endpoint slice controller")
	defer klog.Infof("Shutting down endpoint slice controller")

	if !cache.WaitForNamedCacheSync("endpoint_slice", stopCh, c.podsSynced, c.servicesSynced, c.endpointSlicesSynced, c.nodesSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, stopCh)
	}

	<-stopCh
}
```

## worker

```go
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	cKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(cKey)

	err := c.syncService(cKey.(string))
	c.handleErr(err, cKey)

	return true
}
```

### syncService

```go
func (c *Controller) syncService(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing service %q endpoint slices. (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	// get service
	service, err := c.serviceLister.Services(namespace).Get(name)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		// 删除相关信息
		c.triggerTimeTracker.DeleteService(namespace, name)
		c.reconciler.deleteService(namespace, name)
		c.endpointSliceTracker.DeleteService(namespace, name)
		// The service has been deleted, return nil so that it won't be retried.
		return nil
	}

	if service.Spec.Type == v1.ServiceTypeExternalName {
		// services with Type ExternalName receive no endpoints from this controller;
		// Ref: https://issues.k8s.io/105986
		return nil
	}

	if service.Spec.Selector == nil {
		// services without a selector receive no endpoint slices from this controller;
		// these services will receive endpoint slices that are created out-of-band via the REST API.
		return nil
	}

	klog.V(5).Infof("About to update endpoint slices for service %q", key)
	// 查找出所有匹配的pod
	podLabelSelector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()
	pods, err := c.podLister.Pods(service.Namespace).List(podLabelSelector)
	if err != nil {
		// Since we're getting stuff from a local cache, it is basically
		// impossible to get this error.
		c.eventRecorder.Eventf(service, v1.EventTypeWarning, "FailedToListPods",
			"Error listing Pods for Service %s/%s: %v", service.Namespace, service.Name, err)
		return err
	}
	
    // 查找service匹配的endpointSlices
	esLabelSelector := labels.Set(map[string]string{
		discovery.LabelServiceName: service.Name,
		discovery.LabelManagedBy:   controllerName,
	}).AsSelectorPreValidated()
	endpointSlices, err := c.endpointSliceLister.EndpointSlices(service.Namespace).List(esLabelSelector)

	if err != nil {
		// Since we're getting stuff from a local cache, it is basically
		// impossible to get this error.
		c.eventRecorder.Eventf(service, v1.EventTypeWarning, "FailedToListEndpointSlices",
			"Error listing Endpoint Slices for Service %s/%s: %v", service.Namespace, service.Name, err)
		return err
	}

	//去除已经被标记为删除的 EndpointSlice，这样可以避免控制器被卡住，因为在删除操作未完成之前，被标记为删除的 EndpointSlice 仍然存在于列表中。
	endpointSlices = dropEndpointSlicesPendingDeletion(endpointSlices)

	if c.endpointSliceTracker.StaleSlices(service, endpointSlices) {
        // 如果 EndpointSlice 不是最新的 需要更新缓存
		return endpointsliceutil.NewStaleInformerCache("EndpointSlice informer cache is out of date")
	}

	// 更新pod的操作时间
	lastChangeTriggerTime := c.triggerTimeTracker.
		ComputeEndpointLastChangeTriggerTime(namespace, service, pods)
	
    // 协调
	err = c.reconciler.reconcile(service, pods, endpointSlices, lastChangeTriggerTime)
	if err != nil {
		c.eventRecorder.Eventf(service, v1.EventTypeWarning, "FailedToUpdateEndpointSlices",
			"Error updating Endpoint Slices for Service %s/%s: %v", service.Namespace, service.Name, err)
		return err
	}

	return nil
}
```

#### dropEndpointSlicesPendingDeletion

```GO
func dropEndpointSlicesPendingDeletion(endpointSlices []*discovery.EndpointSlice) []*discovery.EndpointSlice {
	n := 0
	for _, endpointSlice := range endpointSlices {
		if endpointSlice.DeletionTimestamp == nil {
			endpointSlices[n] = endpointSlice
			n++
		}
	}
	return endpointSlices[:n]
}
```

