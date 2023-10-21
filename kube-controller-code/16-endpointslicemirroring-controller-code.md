
## 简介

负责将一个命名空间中的 Endpointslices 镜像到另一个命名空间中。它用于将源命名空间中的 Endpointslices 镜像到目标命名空间中。该控制器会监视源命名空间中 Endpoints 资源的更改，并在目标命名空间中创建或更新 Endpointslices。

## 结构体

```GO
type Controller struct {
	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	endpointsLister corelisters.EndpointsLister
	endpointsSynced cache.InformerSynced

	endpointSliceLister discoverylisters.EndpointSliceLister
	endpointSlicesSynced cache.InformerSynced
	
    // 用于跟踪每个 Endpoints 资源对应的 EndpointSlice 资源列表，以便判断缓存的 EndpointSlice 是否已过期
	endpointSliceTracker *endpointsliceutil.EndpointSliceTracker

	serviceLister corelisters.ServiceLister
	servicesSynced cache.InformerSynced

	// 用于协调 EndpointSlice 的更改。
	reconciler *reconciler

	queue workqueue.RateLimitingInterface

	// 限制每个 EndpointSubset 中最多可以包含的 Endpoint 数量
	maxEndpointsPerSubset int32

	// 控制处理队列中更改的时间间隔
	workerLoopPeriod time.Duration

	// 限制触发 EndpointSlice 更改的 Endpoints 同步操作的频率
	endpointUpdatesBatchPeriod time.Duration
}
```

## New

```go
func NewController(endpointsInformer coreinformers.EndpointsInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	serviceInformer coreinformers.ServiceInformer,
	maxEndpointsPerSubset int32,
	client clientset.Interface,
	endpointUpdatesBatchPeriod time.Duration,
) *Controller {
	broadcaster := record.NewBroadcaster()
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "endpoint-slice-mirroring-controller"})

	metrics.RegisterMetrics()

	c := &Controller{
		client: client,
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "endpoint_slice_mirroring"),
		workerLoopPeriod: time.Second,
	}
	
    // 监控endpoints资源的add update delete做处理
	endpointsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onEndpointsAdd,
		UpdateFunc: c.onEndpointsUpdate,
		DeleteFunc: c.onEndpointsDelete,
	})
	c.endpointsLister = endpointsInformer.Lister()
	c.endpointsSynced = endpointsInformer.Informer().HasSynced
    
	// 监控endpointSlice资源的add update delete做处理
	endpointSliceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onEndpointSliceAdd,
		UpdateFunc: c.onEndpointSliceUpdate,
		DeleteFunc: c.onEndpointSliceDelete,
	})
    
	c.endpointSliceLister = endpointSliceInformer.Lister()
	c.endpointSlicesSynced = endpointSliceInformer.Informer().HasSynced
	c.endpointSliceTracker = endpointsliceutil.NewEndpointSliceTracker()

	c.serviceLister = serviceInformer.Lister()
	c.servicesSynced = serviceInformer.Informer().HasSynced
    // 监控service资源的add update delete做处理
	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onServiceAdd,
		UpdateFunc: c.onServiceUpdate,
		DeleteFunc: c.onServiceDelete,
	})

	c.maxEndpointsPerSubset = maxEndpointsPerSubset
	
    // 创建reconciler
	c.reconciler = &reconciler{
		client:                c.client,
		maxEndpointsPerSubset: c.maxEndpointsPerSubset,
		endpointSliceTracker:  c.endpointSliceTracker,
		metricsCache:          metrics.NewCache(maxEndpointsPerSubset),
		eventRecorder:         recorder,
	}

	c.eventBroadcaster = broadcaster
	c.eventRecorder = recorder

	c.endpointUpdatesBatchPeriod = endpointUpdatesBatchPeriod

	return c
}
```

### 队列处理相关

**Endpoints**

```GO
func (c *Controller) onEndpointsAdd(obj interface{}) {
	endpoints := obj.(*v1.Endpoints)
	if endpoints == nil {
		utilruntime.HandleError(fmt.Errorf("onEndpointsAdd() expected type v1.Endpoints, got %T", obj))
		return
	}
    // 要进行镜像的服务
	if !c.shouldMirror(endpoints) {
		klog.V(5).Infof("Skipping mirroring for %s/%s", endpoints.Namespace, endpoints.Name)
		return
	}
	c.queueEndpoints(obj)
}

func (c *Controller) onEndpointsUpdate(prevObj, obj interface{}) {
	endpoints := obj.(*v1.Endpoints)
	prevEndpoints := prevObj.(*v1.Endpoints)
	if endpoints == nil || prevEndpoints == nil {
		utilruntime.HandleError(fmt.Errorf("onEndpointsUpdate() expected type v1.Endpoints, got %T, %T", prevObj, obj))
		return
	}
    // 更新前后要进行镜像的服务
	if !c.shouldMirror(endpoints) && !c.shouldMirror(prevEndpoints) {
		klog.V(5).Infof("Skipping mirroring for %s/%s", endpoints.Namespace, endpoints.Name)
		return
	}
	c.queueEndpoints(obj)
}

func (c *Controller) onEndpointsDelete(obj interface{}) {
	endpoints := getEndpointsFromDeleteAction(obj)
	if endpoints == nil {
		utilruntime.HandleError(fmt.Errorf("onEndpointsDelete() expected type v1.Endpoints, got %T", obj))
		return
	}
	if !c.shouldMirror(endpoints) {
		klog.V(5).Infof("Skipping mirroring for %s/%s", endpoints.Namespace, endpoints.Name)
		return
	}
	c.queueEndpoints(obj)
}

func (c *Controller) shouldMirror(endpoints *v1.Endpoints) bool {
	if endpoints == nil || skipMirror(endpoints.Labels) || hasLeaderElection(endpoints.Annotations) {
		return false
	}

	return true
}

func skipMirror(labels map[string]string) bool {
	skipMirror, _ := labels[discovery.LabelSkipMirror]
	return skipMirror == "true"
}

func hasLeaderElection(annotations map[string]string) bool {
	_, ok := annotations[resourcelock.LeaderElectionRecordAnnotationKey]
	return ok
}
```

**EndpointSlice**

```GO
func (c *Controller) onEndpointSliceAdd(obj interface{}) {
	endpointSlice := obj.(*discovery.EndpointSlice)
	if endpointSlice == nil {
		utilruntime.HandleError(fmt.Errorf("onEndpointSliceAdd() expected type discovery.EndpointSlice, got %T", obj))
		return
	}
    // 是本控制器控制的 是否需要同步
	if managedByController(endpointSlice) && c.endpointSliceTracker.ShouldSync(endpointSlice) {
		c.queueEndpointsForEndpointSlice(endpointSlice)
	}
}

func (c *Controller) onEndpointSliceUpdate(prevObj, obj interface{}) {
	prevEndpointSlice := obj.(*discovery.EndpointSlice)
	endpointSlice := prevObj.(*discovery.EndpointSlice)
	if endpointSlice == nil || prevEndpointSlice == nil {
		utilruntime.HandleError(fmt.Errorf("onEndpointSliceUpdated() expected type discovery.EndpointSlice, got %T, %T", prevObj, obj))
		return
	}
	svcName := endpointSlice.Labels[discovery.LabelServiceName]
	prevSvcName := prevEndpointSlice.Labels[discovery.LabelServiceName]
    // 如果前后的serviceName不一样 就都要加进去
	if svcName != prevSvcName {
		klog.Warningf("%s label changed from %s  to %s for %s", discovery.LabelServiceName, prevSvcName, svcName, endpointSlice.Name)
		c.queueEndpointsForEndpointSlice(endpointSlice)
		c.queueEndpointsForEndpointSlice(prevEndpointSlice)
		return
	}
    // 控制器有发生变化 或者 是本控制器而且需要同步
	if managedByChanged(prevEndpointSlice, endpointSlice) || (managedByController(endpointSlice) && c.endpointSliceTracker.ShouldSync(endpointSlice)) {
		c.queueEndpointsForEndpointSlice(endpointSlice)
	}
}


func (c *Controller) onEndpointSliceDelete(obj interface{}) {
	endpointSlice := getEndpointSliceFromDeleteAction(obj)
	if endpointSlice == nil {
		utilruntime.HandleError(fmt.Errorf("onEndpointSliceDelete() expected type discovery.EndpointSlice, got %T", obj))
		return
	}
    // 是否有本控制器管理 并且被追踪
	if managedByController(endpointSlice) && c.endpointSliceTracker.Has(endpointSlice) {
        // 删除追踪 没有成功处理
		if !c.endpointSliceTracker.HandleDeletion(endpointSlice) {
			c.queueEndpointsForEndpointSlice(endpointSlice)
		}
	}
}

func managedByController(endpointSlice *discovery.EndpointSlice) bool {
	managedBy, _ := endpointSlice.Labels[discovery.LabelManagedBy]
	return managedBy == controllerName
}

func managedByChanged(endpointSlice1, endpointSlice2 *discovery.EndpointSlice) bool {
	return managedByController(endpointSlice1) != managedByController(endpointSlice2)
}

func (c *Controller) queueEndpointsForEndpointSlice(endpointSlice *discovery.EndpointSlice) {
	key, err := endpointsControllerKey(endpointSlice)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for EndpointSlice %+v (type %T): %v", endpointSlice, endpointSlice, err))
		return
	}

	c.queue.AddAfter(key, c.endpointUpdatesBatchPeriod)
}

func endpointsControllerKey(endpointSlice *discovery.EndpointSlice) (string, error) {
	if endpointSlice == nil {
		return "", fmt.Errorf("nil EndpointSlice passed to serviceControllerKey()")
	}
	serviceName, ok := endpointSlice.Labels[discovery.LabelServiceName]
	if !ok || serviceName == "" {
		return "", fmt.Errorf("EndpointSlice missing %s label", discovery.LabelServiceName)
	}
	return fmt.Sprintf("%s/%s", endpointSlice.Namespace, serviceName), nil
}
```

**service**

```go
func (c *Controller) onServiceAdd(obj interface{}) {
	service := obj.(*v1.Service)
	if service == nil {
		utilruntime.HandleError(fmt.Errorf("onServiceAdd() expected type v1.Service, got %T", obj))
		return
	}
    //  service.Spec.Selector == nil 这个服务不会与任何 Pod 进行匹配，也就不会有对应的 Endpoints，
    // 因此需要对该 Service 所在的所有命名空间中的所有 Endpoints 进行镜像同步，以便让这个 Service 可以在集群内正常工作
	if service.Spec.Selector == nil {
		c.queueEndpoints(obj)
	}
}

func (c *Controller) onServiceUpdate(prevObj, obj interface{}) {
	service := obj.(*v1.Service)
	prevService := prevObj.(*v1.Service)
	if service == nil || prevService == nil {
		utilruntime.HandleError(fmt.Errorf("onServiceUpdate() expected type v1.Service, got %T, %T", prevObj, obj))
		return
	}
    //从有值变成了无值 或者从无值变成了有值
	if (service.Spec.Selector == nil) != (prevService.Spec.Selector == nil) {
		c.queueEndpoints(obj)
	}
}

func (c *Controller) onServiceDelete(obj interface{}) {
	service := getServiceFromDeleteAction(obj)
	if service == nil {
		utilruntime.HandleError(fmt.Errorf("onServiceDelete() expected type v1.Service, got %T", obj))
		return
	}
	if service.Spec.Selector == nil {
		c.queueEndpoints(obj)
	}
}

func (c *Controller) queueEndpoints(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v (type %T): %v", obj, obj, err))
		return
	}

	c.queue.Add(key)
}

func getServiceFromDeleteAction(obj interface{}) *corev1.Service {
	if service, ok := obj.(*corev1.Service); ok {
		return service
	}

	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
		return nil
	}
	service, ok := tombstone.Obj.(*corev1.Service)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Service resource: %#v", obj))
		return nil
	}
	return service
}
```

### reconciler

```go
type reconciler struct {
	client clientset.Interface

	endpointSliceTracker *endpointsliceutil.EndpointSliceTracker

	eventRecorder record.EventRecorder

	maxEndpointsPerSubset int32

	metricsCache *metrics.Cache
}


func (r *reconciler) reconcile(endpoints *corev1.Endpoints, existingSlices []*discovery.EndpointSlice) error {
 	// 计算期望状态
	d := newDesiredCalc()

	numInvalidAddresses := 0
	addressesSkipped := 0

	// 规范化处理 Endpoints 的 subsets
	subsets := endpointsv1.RepackSubsets(endpoints.Subsets)
	for _, subset := range subsets {
		multiKey := d.initPorts(subset.Ports)

		totalAddresses := len(subset.Addresses) + len(subset.NotReadyAddresses)
		totalAddressesAdded := 0
		// 添加 subset 中的 ready addresses
		for _, address := range subset.Addresses {
			// 如果已经添加的地址数量达到了每个 EndpointSubset 最大 mirror 的地址数量，跳出循环
			if totalAddressesAdded >= int(r.maxEndpointsPerSubset) {
				break
			}
			if ok := d.addAddress(address, multiKey, true); ok {
				totalAddressesAdded++
			} else {
                // 记录不合法地址数量并输出警告日志
				numInvalidAddresses++
				klog.Warningf("Address in %s/%s Endpoints is not a valid IP, it will not be mirrored to an EndpointSlice: %s", endpoints.Namespace, endpoints.Name, address.IP)
			}
		}
		
        // 添加 subset 中的 not ready addresses
		for _, address := range subset.NotReadyAddresses {
			// 如果已经添加的地址数量达到了每个 EndpointSubset 最大 mirror 的地址数量，跳出循环
			if totalAddressesAdded >= int(r.maxEndpointsPerSubset) {
				break
			}
			if ok := d.addAddress(address, multiKey, false); ok {
				totalAddressesAdded++
			} else {
				numInvalidAddresses++
				klog.Warningf("Address in %s/%s Endpoints is not a valid IP, it will not be mirrored to an EndpointSlice: %s", endpoints.Namespace, endpoints.Name, address.IP)
			}
		}
	
        // 记录因为地址数量超过每个 EndpointSubset 最大 mirror 的地址数量或地址不合法而被跳过的地址数量
		addressesSkipped += totalAddresses - totalAddressesAdded
	}

	// 统计并记录跳过的地址数量到 metrics 中
	metrics.AddressesSkippedPerSync.WithLabelValues().Observe(float64(addressesSkipped))

	// 如果存在不合法的 IP 地址，则记录事件到 Endpoints 资源上
	if numInvalidAddresses > 0 {
		r.eventRecorder.Eventf(endpoints, corev1.EventTypeWarning, InvalidIPAddress,
			"Skipped %d invalid IP addresses when mirroring to EndpointSlices", numInvalidAddresses)
	}

	// 如果因为地址数量超过每个 EndpointSubset 最大 mirror 的地址数量而被跳过了一些地址，则记录事件到 Endpoints 资源上
	if addressesSkipped > numInvalidAddresses {
		klog.Warningf("%d addresses in %s/%s Endpoints were skipped due to exceeding MaxEndpointsPerSubset", addressesSkipped, endpoints.Namespace, endpoints.Name)
		r.eventRecorder.Eventf(endpoints, corev1.EventTypeWarning, TooManyAddressesToMirror,
			"A max of %d addresses can be mirrored to EndpointSlices per Endpoints subset. %d addresses were skipped", r.maxEndpointsPerSubset, addressesSkipped)
	}

	// Build data structures for existing state.
	existingSlicesByKey := endpointSlicesByKey(existingSlices)

	// 根据端口映射确定每个 Slice 组的必要更改
	epMetrics := metrics.NewEndpointPortCache()
	totals := totalsByAction{} // 创建操作计数器
	slices := slicesByAction{} // 创建操作切片

	for portKey, desiredEndpoints := range d.endpointsByKey {
		numEndpoints := len(desiredEndpoints)
        // 得到对应的新的 endpoint slices
		pmSlices, pmTotals := r.reconcileByPortMapping(
			endpoints, existingSlicesByKey[portKey], desiredEndpoints, d.portsByKey[portKey], portKey.addressType())

		slices.append(pmSlices) // 将更改切片添加到要执行的切片列表中
		totals.add(pmTotals) // 更新计数器

		epMetrics.Set(endpointutil.PortMapKey(portKey), metrics.EfficiencyInfo{
			Endpoints: numEndpoints,
			Slices:    len(existingSlicesByKey[portKey]) + len(pmSlices.toCreate) - len(pmSlices.toDelete),
		}) // 更新端口缓存
	}

	// 如果有不再需要的唯一endpoints，标记相应的 EndpointSlice 以进行删除
	for portKey, existingSlices := range existingSlicesByKey {
		if _, ok := d.endpointsByKey[portKey]; !ok {
			for _, existingSlice := range existingSlices {
				slices.toDelete = append(slices.toDelete, existingSlice)
			}
		}
	}
	
    // 更新指标
	metrics.EndpointsAddedPerSync.WithLabelValues().Observe(float64(totals.added))
	metrics.EndpointsUpdatedPerSync.WithLabelValues().Observe(float64(totals.updated))
	metrics.EndpointsRemovedPerSync.WithLabelValues().Observe(float64(totals.removed))

	endpointsNN := types.NamespacedName{Name: endpoints.Name, Namespace: endpoints.Namespace}
    // 更新缓存
	r.metricsCache.UpdateEndpointPortCache(endpointsNN, epMetrics)

	return r.finalize(endpoints, slices)
}

func (r *reconciler) reconcileByPortMapping(
	endpoints *corev1.Endpoints,
	existingSlices []*discovery.EndpointSlice,
	desiredSet endpointsliceutil.EndpointSet,
	endpointPorts []discovery.EndpointPort,
	addressType discovery.AddressType,
) (slicesByAction, totalsByAction) {
	slices := slicesByAction{}
	totals := totalsByAction{}

	// 如果没有期望的 endpoints，则标记现有的 slices 以进行删除，并返回。
	if desiredSet.Len() == 0 {
		slices.toDelete = existingSlices
		for _, epSlice := range existingSlices {
			totals.removed += len(epSlice.Endpoints)
		}
		return slices, totals
	}

	if len(existingSlices) == 0 {
		// 如果没有现有的 slices，则所有期望的 endpoints 都将被添加
		totals.added = desiredSet.Len()
	} else {
		// 如果存在一个或多个现有的 slices，则标记除一个之外的所有 slice 以进行删除
		slices.toDelete = existingSlices[1:]

		// 生成的 slices 必须反映所有 endpoints 注释，但不包括 EndpointsLastChangeTriggerTime 和 LastAppliedConfigAnnotation。
		// 对现有 slice 的 label 去除 LabelManagedBy 和 LabelServiceName 后与期望的 endpoints 进行比较，如果相同，则不需要任何更改。
		compareAnnotations := cloneAndRemoveKeys(endpoints.Annotations, corev1.EndpointsLastChangeTriggerTime, corev1.LastAppliedConfigAnnotation)
		compareLabels := cloneAndRemoveKeys(existingSlices[0].Labels, discovery.LabelManagedBy, discovery.LabelServiceName)
		// 如果第一个 slice 与期望的 endpoints，标签和注释相匹配，则提前返回。
		totals = totalChanges(existingSlices[0], desiredSet)
		if totals.added == 0 && totals.updated == 0 && totals.removed == 0 &&
			apiequality.Semantic.DeepEqual(endpoints.Labels, compareLabels) &&
			apiequality.Semantic.DeepEqual(compareAnnotations, existingSlices[0].Annotations) {
			return slices, totals
		}
	}

	// 生成一个新的 slice，其中包含期望的 endpoints。
	var sliceName string
	if len(existingSlices) > 0 {
		sliceName = existingSlices[0].Name
	}
	newSlice := newEndpointSlice(endpoints, endpointPorts, addressType, sliceName)
    // 不断将期望的 endpoints 添加到新 slice 中，直到达到最大限制或期望的 endpoints 为空。
	for desiredSet.Len() > 0 && len(newSlice.Endpoints) < int(r.maxEndpointsPerSubset) {
		endpoint, _ := desiredSet.PopAny()
		newSlice.Endpoints = append(newSlice.Endpoints, *endpoint)
	}
	// 如果新 slice 存在，则将其添加到要更新的 slice 中；否则将其添加到要创建的 slice 中。
	if newSlice.Name != "" {
		slices.toUpdate = []*discovery.EndpointSlice{newSlice}
	} else { 
        // 要创建的 slice 设置 GenerateName 而不是 Name。
		slices.toCreate = []*discovery.EndpointSlice{newSlice}
	}

	return slices, totals
}

func (r *reconciler) finalize(endpoints *corev1.Endpoints, slices slicesByAction) error {
	recycleSlices(&slices)

	epsClient := r.client.DiscoveryV1().EndpointSlices(endpoints.Namespace)

	// // 如果相应的端点资源正在被删除，请不要创建更多的EndpointSlices。
	if endpoints.DeletionTimestamp == nil {
        // 遍历需要创建的切片并逐一进行创建。
		for _, endpointSlice := range slices.toCreate {
			createdSlice, err := epsClient.Create(context.TODO(), endpointSlice, metav1.CreateOptions{})
			if err != nil {
				// 如果命名空间正在终止，则创建将继续失败。只需删除该项目即可。
				if errors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
					return nil
				}
				return fmt.Errorf("failed to create EndpointSlice for Endpoints %s/%s: %v", endpoints.Namespace, endpoints.Name, err)
			}
			r.endpointSliceTracker.Update(createdSlice)
			metrics.EndpointSliceChanges.WithLabelValues("create").Inc()
		}
	}
	
    // 遍历需要更新的切片并逐一进行更新。
	for _, endpointSlice := range slices.toUpdate {
		updatedSlice, err := epsClient.Update(context.TODO(), endpointSlice, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update %s EndpointSlice for Endpoints %s/%s: %v", endpointSlice.Name, endpoints.Namespace, endpoints.Name, err)
		}
		r.endpointSliceTracker.Update(updatedSlice)
		metrics.EndpointSliceChanges.WithLabelValues("update").Inc()
	}
	
    // 遍历需要删除的切片并逐一进行删除。
	for _, endpointSlice := range slices.toDelete {
		err := epsClient.Delete(context.TODO(), endpointSlice.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete %s EndpointSlice for Endpoints %s/%s: %v", endpointSlice.Name, endpoints.Namespace, endpoints.Name, err)
		}
		r.endpointSliceTracker.ExpectDeletion(endpointSlice)
		metrics.EndpointSliceChanges.WithLabelValues("delete").Inc()
	}

	return nil
}

func (r *reconciler) deleteEndpoints(namespace, name string, endpointSlices []*discovery.EndpointSlice) error {
    // 从指标缓存中删除 Endpoints 的指标
	r.metricsCache.DeleteEndpoints(types.NamespacedName{Namespace: namespace, Name: name})
	var errs []error
    // 遍历需要删除的 EndpointSlice，依次执行删除操作
	for _, endpointSlice := range endpointSlices {
		err := r.client.DiscoveryV1().EndpointSlices(namespace).Delete(context.TODO(), endpointSlice.Name, metav1.DeleteOptions{})
		if err != nil {
            // 如果删除失败，则将错误信息加入错误列表 errs 中
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error(s) deleting %d/%d EndpointSlices for %s/%s Endpoints, including: %s", len(errs), len(endpointSlices), namespace, name, errs[0])
	}
	return nil
}

// 根据 EndpointSlice 的地址类型和端口号将 EndpointSlice 列表进行分组
func endpointSlicesByKey(existingSlices []*discovery.EndpointSlice) map[addrTypePortMapKey][]*discovery.EndpointSlice {
	slicesByKey := map[addrTypePortMapKey][]*discovery.EndpointSlice{}
    // 遍历 EndpointSlice 列表，将其按照地址类型和端口号分组
	for _, existingSlice := range existingSlices {
		epKey := newAddrTypePortMapKey(existingSlice.Ports, existingSlice.AddressType)
		slicesByKey[epKey] = append(slicesByKey[epKey], existingSlice)
	}
	return slicesByKey
}

// 计算现有 EndpointSlice 与期望的 EndpointSet 之间的变化量
func totalChanges(existingSlice *discovery.EndpointSlice, desiredSet endpointsliceutil.EndpointSet) totalsByAction {
	totals := totalsByAction{}
	existingMatches := 0
	
    // 遍历现有的 EndpointSlice 中的所有 endpoint
	for _, endpoint := range existingSlice.Endpoints {
        // 从期望的 EndpointSet 中获取相应的 endpoint
		got := desiredSet.Get(&endpoint)
		if got == nil {
			// 如果不在期望的 EndpointSet 中，增加需要删除的 endpoint 数量
			totals.removed++
		} else {
			existingMatches++

			// 如果现有的 endpoint 版本与期望的版本不同，增加需要更新的 endpoint 数量
			if !endpointutil.EndpointsEqualBeyondHash(got, &endpoint) {
				totals.updated++
			}
		}
	}

	// 所有未在现有 EndpointSlice 中找到的期望 endpoint 将被添加
	totals.added = desiredSet.Len() - existingMatches
	return totals
}
```

## Run

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

	err := c.syncEndpoints(cKey.(string))
	c.handleErr(err, cKey)

	return true
}
```

## syncEndpoints

```go
func (c *Controller) syncEndpoints(key string) error {
	startTime := time.Now()
	defer func() {
		syncDuration := float64(time.Since(startTime).Milliseconds()) / 1000
		metrics.EndpointsSyncDuration.WithLabelValues().Observe(syncDuration)
		klog.V(4).Infof("Finished syncing EndpointSlices for %q Endpoints. (%v)", key, time.Since(startTime))
	}()

	klog.V(4).Infof("syncEndpoints(%q)", key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	
    // 从lister获取endpoints
	endpoints, err := c.endpointsLister.Endpoints(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("%s/%s Endpoints not found, cleaning up any mirrored EndpointSlices", namespace, name)
			c.endpointSliceTracker.DeleteService(namespace, name)
			return c.deleteMirroredSlices(namespace, name)
		}
		return err
	}
	
    // 如果不需要同步 删除追踪 并删除endpointSlices的追踪
	if !c.shouldMirror(endpoints) {
		klog.V(4).Infof("%s/%s Endpoints should not be mirrored, cleaning up any mirrored EndpointSlices", namespace, name)
		c.endpointSliceTracker.DeleteService(namespace, name)
		return c.deleteMirroredSlices(namespace, name)
	}
	
    // 从lister获取service
	svc, err := c.serviceLister.Services(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.V(4).Infof("%s/%s Service not found, cleaning up any mirrored EndpointSlices", namespace, name)
			c.endpointSliceTracker.DeleteService(namespace, name)
			return c.deleteMirroredSlices(namespace, name)
		}
		return err
	}

	// 如果指定了选择器，请清理所有镜Slices追踪
	if svc.Spec.Selector != nil {
		klog.V(4).Infof("%s/%s Service now has selector, cleaning up any mirrored EndpointSlices", namespace, name)
		c.endpointSliceTracker.DeleteService(namespace, name)
		return c.deleteMirroredSlices(namespace, name)
	}

	endpointSlices, err := endpointSlicesMirroredForService(c.endpointSliceLister, namespace, name)
	if err != nil {
		return err
	}
	
    // 检查EndpointSlices是否过期
	if c.endpointSliceTracker.StaleSlices(svc, endpointSlices) {
		return endpointsliceutil.NewStaleInformerCache("EndpointSlice informer cache is out of date")
	}
	
    // 调整
	err = c.reconciler.reconcile(endpoints, endpointSlices)
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) deleteMirroredSlices(namespace, name string) error {
	endpointSlices, err := endpointSlicesMirroredForService(c.endpointSliceLister, namespace, name)
	if err != nil {
		return err
	}

	c.endpointSliceTracker.DeleteService(namespace, name)
	return c.reconciler.deleteEndpoints(namespace, name, endpointSlices)
}

func endpointSlicesMirroredForService(endpointSliceLister discoverylisters.EndpointSliceLister, namespace, name string) ([]*discovery.EndpointSlice, error) {
	esLabelSelector := labels.Set(map[string]string{
		discovery.LabelServiceName: name,
		discovery.LabelManagedBy:   controllerName,
	}).AsSelectorPreValidated()
	return endpointSliceLister.EndpointSlices(namespace).List(esLabelSelector)
}
```

