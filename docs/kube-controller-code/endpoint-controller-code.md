---
id: 14-kube-controller-code
title: endpoint-controller 代码走读
description: endpoint-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

负责维护 Kubernetes API 中的 Endpoint 对象。

在 Kubernetes 中，一个 Service 对象是一个虚拟的抽象层，它为一组 Pod 提供了一个统一的入口，使得外部的客户端可以通过该 Service 访问这些 Pod。而 Endpoint 则是 Service 的实际后端，即一组真实的 Pod IP 和端口。

Endpoint Controller 的作用是：

1. 监听 Service 和 Pod 对象的变化，当 Pod 有更新、删除、添加时，Endpoint Controller 就会更新对应 Service 的 Endpoint。
2. 将 Service 对象的信息转换为一组 Endpoint 对象，其中每个 Endpoint 对象都包含了一个 Pod 的 IP 和端口。
3. 将 Endpoint 对象与 Kubernetes 的 iptables 规则匹配，以便在 Pod 和 Service 之间建立网络通信。

Endpoint Controller 负责在 Kubernetes 中建立 Service 与 Pod 之间的联系，从而确保 Service 可以正确地访问其后端 Pod。

## 结构体

```GO
type Controller struct {
	client           clientset.Interface
    // 广播事件和记录事件
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder


	serviceLister corelisters.ServiceLister
	servicesSynced cache.InformerSynced

	podLister corelisters.PodLister
	podsSynced cache.InformerSynced

	endpointsLister corelisters.EndpointsLister
	endpointsSynced cache.InformerSynced

	// 存储 Service 对象
	queue workqueue.RateLimitingInterface
	// 控制 worker 处理队列的时间间隔
	workerLoopPeriod time.Duration
	// triggerTimeTracker 成员变量，它是一个用于计算和导出 EndpointsLastChangeTriggerTime 注释的工具
	triggerTimeTracker *endpointutil.TriggerTimeTracker
	// 控制 Endpoint 更新的批量操作时间间隔
	endpointUpdatesBatchPeriod time.Duration
}

```



## New

```go
func NewEndpointController(podInformer coreinformers.PodInformer, serviceInformer coreinformers.ServiceInformer,
	endpointsInformer coreinformers.EndpointsInformer, client clientset.Interface, endpointUpdatesBatchPeriod time.Duration) *Controller {
	broadcaster := record.NewBroadcaster()
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "endpoint-controller"})

	e := &Controller{
		client:           client,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "endpoint"),
		workerLoopPeriod: time.Second,
	}
    
	// 监控service的 add delete和update 做处理
	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: e.onServiceUpdate,
		UpdateFunc: func(old, cur interface{}) {
			e.onServiceUpdate(cur)
		},
		DeleteFunc: e.onServiceDelete,
	})
	e.serviceLister = serviceInformer.Lister()
	e.servicesSynced = serviceInformer.Informer().HasSynced
	
    // 监控pod的 add delete和update 做处理
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    e.addPod,
		UpdateFunc: e.updatePod,
		DeleteFunc: e.deletePod,
	})
	e.podLister = podInformer.Lister()
	e.podsSynced = podInformer.Informer().HasSynced
	
    // 监控endpoint的 delete 做处理
	endpointsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: e.onEndpointsDelete,
	})
	e.endpointsLister = endpointsInformer.Lister()
	e.endpointsSynced = endpointsInformer.Informer().HasSynced

	e.triggerTimeTracker = endpointutil.NewTriggerTimeTracker()
	e.eventBroadcaster = broadcaster
	e.eventRecorder = recorder

	e.endpointUpdatesBatchPeriod = endpointUpdatesBatchPeriod

	return e
}
```

### 队列相关

**service**

```go
// 把对象加入quque
func (e *Controller) onServiceUpdate(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	e.queue.Add(key)
}

func (e *Controller) onServiceDelete(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	e.queue.Add(key)
}
```

**pod**

```go
func (e *Controller) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	services, err := endpointutil.GetPodServiceMemberships(e.serviceLister, pod)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Unable to get pod %s/%s's service memberships: %v", pod.Namespace, pod.Name, err))
		return
	}
	for key := range services {
		e.queue.AddAfter(key, e.endpointUpdatesBatchPeriod)
	}
}

func (e *Controller) updatePod(old, cur interface{}) {
	services := endpointutil.GetServicesToUpdateOnPodChange(e.serviceLister, old, cur)
	for key := range services {
		e.queue.AddAfter(key, e.endpointUpdatesBatchPeriod)
	}
}

// When a pod is deleted, enqueue the services the pod used to be a member of.
// obj could be an *v1.Pod, or a DeletionFinalStateUnknown marker item.
func (e *Controller) deletePod(obj interface{}) {
	pod := endpointutil.GetPodFromDeleteAction(obj)
	if pod != nil {
		e.addPod(pod)
	}
}
```

**GetPodServiceMemberships**

```GO
// 根据pod获取service
func GetPodServiceMemberships(serviceLister v1listers.ServiceLister, pod *v1.Pod) (sets.String, error) {
	set := sets.String{}
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
```

**endpoint**

```go
func (e *Controller) onEndpointsDelete(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	e.queue.Add(key)
}
```

### TriggerTimeTracker

```go
// 跟踪服务和Pod的触发时间
type TriggerTimeTracker struct {
	ServiceStates map[ServiceKey]ServiceState
	mutex sync.Mutex
}

func NewTriggerTimeTracker() *TriggerTimeTracker {
	return &TriggerTimeTracker{
		ServiceStates: make(map[ServiceKey]ServiceState),
	}
}

type ServiceKey struct {
	Namespace, Name string
}


type ServiceState struct {
	lastServiceTriggerTime time.Time
	lastPodTriggerTimes map[string]time.Time
}

```

```GO
// 用于计算给定service和它关联的一组pods的最近一次更新时间。
func (t *TriggerTimeTracker) ComputeEndpointLastChangeTriggerTime(
	namespace string, service *v1.Service, pods []*v1.Pod) time.Time {

	key := ServiceKey{Namespace: namespace, Name: service.Name}
	
    // 获取 state 函数结束时候 再设置
	t.mutex.Lock()
	state, wasKnown := t.ServiceStates[key]
	t.mutex.Unlock()

	// Update the state before returning.
	defer func() {
		t.mutex.Lock()
		t.ServiceStates[key] = state
		t.mutex.Unlock()
	}()

	
    // 获取pods的最小的触发时间
	var minChangedTriggerTime time.Time
	podTriggerTimes := make(map[string]time.Time)
	for _, pod := range pods {
		if podTriggerTime := getPodTriggerTime(pod); !podTriggerTime.IsZero() {
			podTriggerTimes[pod.Name] = podTriggerTime
			if podTriggerTime.After(state.lastPodTriggerTimes[pod.Name]) {
				minChangedTriggerTime = min(minChangedTriggerTime, podTriggerTime)
			}
		}
	}
	serviceTriggerTime := getServiceTriggerTime(service)
	if serviceTriggerTime.After(state.lastServiceTriggerTime) {
		minChangedTriggerTime = min(minChangedTriggerTime, serviceTriggerTime)
	}
	
    // 最近一次的更新
	state.lastPodTriggerTimes = podTriggerTimes
	state.lastServiceTriggerTime = serviceTriggerTime

	if !wasKnown {
		// 如果这个Service是新的，那么就返回Service的创建时间戳
		return service.CreationTimestamp.Time
	}

	//否则返回minChangedTriggerTime
	return minChangedTriggerTime
}

func (t *TriggerTimeTracker) DeleteService(namespace, name string) {
	key := ServiceKey{Namespace: namespace, Name: name}
	t.mutex.Lock()
	defer t.mutex.Unlock()
	delete(t.ServiceStates, key)
}
```

```GO
func getPodTriggerTime(pod *v1.Pod) (triggerTime time.Time) {
	if readyCondition := podutil.GetPodReadyCondition(pod.Status); readyCondition != nil {
		triggerTime = readyCondition.LastTransitionTime.Time
	}
	return triggerTime
}

// getServiceTriggerTime returns the time of the service change (trigger) that
// resulted or will result in the endpoint change.
func getServiceTriggerTime(service *v1.Service) (triggerTime time.Time) {
	return service.CreationTimestamp.Time
}

// min returns minimum of the currentMin and newValue or newValue if the currentMin is not set.
func min(currentMin, newValue time.Time) time.Time {
	if currentMin.IsZero() || newValue.Before(currentMin) {
		return newValue
	}
	return currentMin
}

```

## Run

```go
func (e *Controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	// 启动事件处理管道，并开始记录事件
	e.eventBroadcaster.StartStructuredLogging(0)
	e.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: e.client.CoreV1().Events("")})
	defer e.eventBroadcaster.Shutdown()

	defer e.queue.ShutDown()

	klog.Infof("Starting endpoint controller")
	defer klog.Infof("Shutting down endpoint controller")
	
    // 等待所有的inforer同步Lister完毕
	if !cache.WaitForNamedCacheSync("endpoint", ctx.Done(), e.podsSynced, e.servicesSynced, e.endpointsSynced) {
		return
	}
	
    // 开启worker个worker
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, e.worker, e.workerLoopPeriod)
	}

	go func() {
		defer utilruntime.HandleCrash()
        // 检查是否有残留的 Endpoint 对象，并将它们删除
		e.checkLeftoverEndpoints()
	}()

	<-ctx.Done()
}
```

## worker

```go
func (e *Controller) worker(ctx context.Context) {
	for e.processNextWorkItem(ctx) {
	}
}

func (e *Controller) processNextWorkItem(ctx context.Context) bool {
	eKey, quit := e.queue.Get()
	if quit {
		return false
	}
	defer e.queue.Done(eKey)
	// 同步service
	err := e.syncService(ctx, eKey.(string))
    // 处理错误
	e.handleErr(err, eKey)

	return true
}
```

### syncService

```GO
func (e *Controller) syncService(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing service %q endpoints. (%v)", key, time.Since(startTime))
	}()
	
    // 获取key的namespace和name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
    // 获取service
	service, err := e.serviceLister.Services(namespace).Get(name)
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		// service被删除了 那就把Endpoints也删除了
		err = e.client.CoreV1().Endpoints(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
        // 记录服务吞吐量和响应时间等
		e.triggerTimeTracker.DeleteService(namespace, name)
		return nil
	}
	
    // 如果type:ExternalName  那就跳过
	if service.Spec.Type == v1.ServiceTypeExternalName {
		// services with Type ExternalName receive no endpoints from this controller;
		// Ref: https://issues.k8s.io/105986
		return nil
	}
	
    // 没有指定selector 也跳过
	if service.Spec.Selector == nil {
		// services without a selector receive no endpoints from this controller;
		// these services will receive the endpoints that are created out-of-band via the REST API.
		return nil
	}

	klog.V(5).Infof("About to update endpoints for service %q", key)
    // 获取service的所有pods
	pods, err := e.podLister.Pods(service.Namespace).List(labels.Set(service.Spec.Selector).AsSelectorPreValidated())
	if err != nil {
		// Since we're getting stuff from a local cache, it is
		// basically impossible to get this error.
		return err
	}

	// 计算 Endpoint 上次变更的触发时间，即更新 Endpoint 对象的时间，该时间将被用于触发 Endpoint 更新的周期性任务
	endpointsLastChangeTriggerTime := e.triggerTimeTracker.
		ComputeEndpointLastChangeTriggerTime(namespace, service, pods)

	subsets := []v1.EndpointSubset{}
	var totalReadyEps int
	var totalNotReadyEps int

	for _, pod := range pods {
        // 判断这个pod需不需要加 不需要就跳过
		if !endpointutil.ShouldPodBeInEndpoints(pod, service.Spec.PublishNotReadyAddresses) {
			klog.V(5).Infof("Pod %s/%s is not included on endpoints for Service %s/%s", pod.Namespace, pod.Name, service.Namespace, service.Name)
			continue
		}
	
        // 将pod转化为EndpointAddress
		ep, err := podToEndpointAddressForService(service, pod)
		if err != nil {
			klog.V(2).Infof("Failed to find endpoint for service:%s with ClusterIP:%s on pod:%s with error:%v", service.Name, service.Spec.ClusterIP, klog.KObj(pod), err)
			continue
		}

		epa := *ep
        // 如果需要设置hostname 则调用ShouldSetHostname设置
		if endpointutil.ShouldSetHostname(pod, service) {
			epa.Hostname = pod.Spec.Hostname
		}

		if len(service.Spec.Ports) == 0 {
            // 如果 Service 没有定义任何端口，则处理 headless Service 的情况
            //（即 .Spec.ClusterIP 为 api.ClusterIPNone） 将 Pod 加入到 Endpoint 集合的子集中
			if service.Spec.ClusterIP == api.ClusterIPNone {
				subsets, totalReadyEps, totalNotReadyEps = addEndpointSubset(subsets, pod, epa, nil, service.Spec.PublishNotReadyAddresses)
			}
		} else {
            // 如果 Service 定义了端口，则遍历所有的端口
			for i := range service.Spec.Ports {
				servicePort := &service.Spec.Ports[i]
                // 查找 Pod 中相应端口的编号
				portNum, err := podutil.FindPort(pod, servicePort)
				if err != nil {
					klog.V(4).Infof("Failed to find port for service %s/%s: %v", service.Namespace, service.Name, err)
					continue
				}
                
                //将 Service 端口转换为 Endpoint 端口
				epp := endpointPortFromServicePort(servicePort, portNum)

				var readyEps, notReadyEps int
                // 并将 Pod 添加到 Endpoint 集合的子集中
				subsets, readyEps, notReadyEps = addEndpointSubset(subsets, pod, epa, epp, service.Spec.PublishNotReadyAddresses)
                // 加上就绪数 和未就绪数
				totalReadyEps = totalReadyEps + readyEps
				totalNotReadyEps = totalNotReadyEps + notReadyEps
			}
		}
	}
    // 子集列表进行整理并返回新的子集列表
	subsets = endpoints.RepackSubsets(subsets)

	//  获取Endpoints 没有就创建一个
	currentEndpoints, err := e.endpointsLister.Endpoints(service.Namespace).Get(service.Name)
	if err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		currentEndpoints = &v1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:   service.Name,
				Labels: service.Labels,
			},
		}
	}
	// 是不是要添加
	createEndpoints := len(currentEndpoints.ResourceVersion) == 0

	// labels
	compareLabels := currentEndpoints.Labels
    // 如果标记为 Headless Service，则将比较标签从当前端点对象中删除。否则，将比较标签设置为当前端点对象的标签。
	if _, ok := currentEndpoints.Labels[v1.IsHeadlessService]; ok {
		compareLabels = utillabels.CloneAndRemoveLabel(currentEndpoints.Labels, v1.IsHeadlessService)
	}
	
    // 检查endpoint是否已经存在并且与新的子集和标签相同，如果是，则跳过更新，并返回 nil 以指示更新成功。
	if !createEndpoints &&
		endpointutil.EndpointSubsetsEqualIgnoreResourceVersion(currentEndpoints.Subsets, subsets) &&
		apiequality.Semantic.DeepEqual(compareLabels, service.Labels) &&
		capacityAnnotationSetCorrectly(currentEndpoints.Annotations, currentEndpoints.Subsets) {
		klog.V(5).Infof("endpoints are equal for %s/%s, skipping update", service.Namespace, service.Name)
		return nil
	}
    // deepcopy 并设置Subsets和Labels
	newEndpoints := currentEndpoints.DeepCopy()
	newEndpoints.Subsets = subsets
	newEndpoints.Labels = service.Labels
	if newEndpoints.Annotations == nil {
		newEndpoints.Annotations = make(map[string]string)
	}
	
    // 如果endpointsLastChangeTriggerTime不为零，
    // 则将该时间戳格式化后作为last-change注解。
	if !endpointsLastChangeTriggerTime.IsZero() {
		newEndpoints.Annotations[v1.EndpointsLastChangeTriggerTime] =
			endpointsLastChangeTriggerTime.UTC().Format(time.RFC3339Nano)
	} else { // No new trigger time, clear the annotation.
		delete(newEndpoints.Annotations, v1.EndpointsLastChangeTriggerTime)
	}
	
    //  如果需要截断终端节点，则将截断信息作为newEndpoints的v1.EndpointsOverCapacity注解
	if truncateEndpoints(newEndpoints) {
		newEndpoints.Annotations[v1.EndpointsOverCapacity] = truncated
	} else {
		delete(newEndpoints.Annotations, v1.EndpointsOverCapacity)
	}

	if newEndpoints.Labels == nil {
		newEndpoints.Labels = make(map[string]string)
	}
	
    // 如果服务的IP地址没有被设置，则为newEndpoints添加over-capacity标签，否则将其从标签映射中移除。
	if !helper.IsServiceIPSet(service) {
		newEndpoints.Labels = utillabels.CloneAndAddLabel(newEndpoints.Labels, v1.IsHeadlessService, "")
	} else {
		newEndpoints.Labels = utillabels.CloneAndRemoveLabel(newEndpoints.Labels, v1.IsHeadlessService)
	}

	klog.V(4).Infof("Update endpoints for %v/%v, ready: %d not ready: %d", service.Namespace, service.Name, totalReadyEps, totalNotReadyEps)
	// 如果是创建 则创建 如果不是 则更新
    if createEndpoints {
		// No previous endpoints, create them
		_, err = e.client.CoreV1().Endpoints(service.Namespace).Create(ctx, newEndpoints, metav1.CreateOptions{})
	} else {
		// Pre-existing
		_, err = e.client.CoreV1().Endpoints(service.Namespace).Update(ctx, newEndpoints, metav1.UpdateOptions{})
	}
    // 处理错误
	if err != nil {
		if createEndpoints && errors.IsForbidden(err) {
			// A request is forbidden primarily for two reasons:
			// 1. namespace is terminating, endpoint creation is not allowed by default.
			// 2. policy is misconfigured, in which case no service would function anywhere.
			// Given the frequency of 1, we log at a lower level.
			klog.V(5).Infof("Forbidden from creating endpoints: %v", err)

			// If the namespace is terminating, creates will continue to fail. Simply drop the item.
			if errors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
				return nil
			}
		}

		if createEndpoints {
			e.eventRecorder.Eventf(newEndpoints, v1.EventTypeWarning, "FailedToCreateEndpoint", "Failed to create endpoint for service %v/%v: %v", service.Namespace, service.Name, err)
		} else {
			e.eventRecorder.Eventf(newEndpoints, v1.EventTypeWarning, "FailedToUpdateEndpoint", "Failed to update endpoint %v/%v: %v", service.Namespace, service.Name, err)
		}

		return err
	}
	return nil
}
```

#### ShouldPodBeInEndpoints

```GO
func ShouldPodBeInEndpoints(pod *v1.Pod, includeTerminating bool) bool {
	// 如果是Terminal （成功的或者失败的） 返回false
	if podutil.IsPodTerminal(pod) {
		return false
	}
	// 如果没有PodIP 返回false
	if len(pod.Status.PodIP) == 0 && len(pod.Status.PodIPs) == 0 {
		return false
	}
	
    // 如果不包含Terminating的pod 再被删除 
	if !includeTerminating && pod.DeletionTimestamp != nil {
		return false
	}

	return true
}
```

#### podToEndpointAddressForService

```GO
func podToEndpointAddressForService(svc *v1.Service, pod *v1.Pod) (*v1.EndpointAddress, error) {
	var endpointIP string
	ipFamily := v1.IPv4Protocol
	// 检查 Service 的 IP 地址族（IPFamily）来决定使用 IPv4 还是 IPv6 协议。
    // 如果 IPFamily 已设置，则使用 IPFamily 中的第一个值
	if len(svc.Spec.IPFamilies) > 0 {
		// controller is connected to an api-server that correctly sets IPFamilies
		ipFamily = svc.Spec.IPFamilies[0] // this works for headful and headless
	} else {
		// 根据 Service 的 ClusterIP 和 Pod 的 PodIP 来决定 IPFamily
		if len(svc.Spec.ClusterIP) > 0 && svc.Spec.ClusterIP != v1.ClusterIPNone {
			// headful service. detect via service clusterIP
			if utilnet.IsIPv6String(svc.Spec.ClusterIP) {
				ipFamily = v1.IPv6Protocol
			}
		} else {

			if utilnet.IsIPv6String(pod.Status.PodIP) {
				ipFamily = v1.IPv6Protocol
			}
		}
	}

	// 使用 Pod 的 PodIPs 中的地址来查找与 IPFamily 匹配的 IP 地址
	for _, podIP := range pod.Status.PodIPs {
		if (ipFamily == v1.IPv6Protocol) == utilnet.IsIPv6String(podIP.IP) {
			endpointIP = podIP.IP
			break
		}
	}

	if endpointIP == "" {
		return nil, fmt.Errorf("failed to find a matching endpoint for service %v", svc.Name)
	}

	return &v1.EndpointAddress{
		IP:       endpointIP,
		NodeName: &pod.Spec.NodeName,
		TargetRef: &v1.ObjectReference{
			Kind:      "Pod",
			Namespace: pod.ObjectMeta.Namespace,
			Name:      pod.ObjectMeta.Name,
			UID:       pod.ObjectMeta.UID,
		},
	}, nil
}
```

#### ShouldSetHostname

```go
func ShouldSetHostname(pod *v1.Pod, svc *v1.Service) bool {
    // 只有当 Pod 属于指定的 Service 时，才应该为其设置hostname
	return len(pod.Spec.Hostname) > 0 && pod.Spec.Subdomain == svc.Name && svc.Namespace == pod.Namespace
}
```

#### addEndpointSubset

```GO
func addEndpointSubset(subsets []v1.EndpointSubset, pod *v1.Pod, epa v1.EndpointAddress,
	epp *v1.EndpointPort, tolerateUnreadyEndpoints bool) ([]v1.EndpointSubset, int, int) {
	var readyEps int
	var notReadyEps int
	ports := []v1.EndpointPort{}
    // 如果epp空的 加进去
	if epp != nil {
		ports = append(ports, *epp)
	}
    //  Pod 是否为ready状态，将epa和pod加进去 
	if tolerateUnreadyEndpoints || podutil.IsPodReady(pod) {
		subsets = append(subsets, v1.EndpointSubset{
			Addresses: []v1.EndpointAddress{epa},
			Ports:     ports,
		})
		readyEps++
	} else { // if it is not a ready address it has to be not ready
		klog.V(5).Infof("Pod is out of service: %s/%s", pod.Namespace, pod.Name)
		subsets = append(subsets, v1.EndpointSubset{
			NotReadyAddresses: []v1.EndpointAddress{epa},
			Ports:             ports,
		})
		notReadyEps++
	}
	return subsets, readyEps, notReadyEps
}
```

## checkLeftoverEndpoints

```GO
func (e *Controller) checkLeftoverEndpoints() {
    // 查找所有的endpoints
	list, err := e.endpointsLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Unable to list endpoints (%v); orphaned endpoints will not be cleaned up. (They're pretty harmless, but you can restart this component if you want another attempt made.)", err))
		return
	}
	for _, ep := range list {
        // 该 Endpoints 对象正在被使用，跳过
		if _, ok := ep.Annotations[resourcelock.LeaderElectionRecordAnnotationKey]; ok {
			continue
		}
		key, err := controller.KeyFunc(ep)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("Unable to get key for endpoint %#v", ep))
			continue
		}
        // 把key加入队列
		e.queue.Add(key)
	}
}
```

