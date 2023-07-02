## PodAdmitTarget

```go
// PodAdmitTarget 维护要调用的处理程序列表。
type PodAdmitTarget interface {
	// AddPodAdmitHandler 添加指定的处理程序。
	AddPodAdmitHandler(a PodAdmitHandler)
}
```

## PodAdmitHandler

```go
// PodAdmitHandler 在 Pod 准入期间进行通知。
type PodAdmitHandler interface {
	// Admit 评估是否可以准入 Pod。
	Admit(attrs *PodAdmitAttributes) PodAdmitResult
}
```

### PodAdmitAttributes

```go
// PodAdmitAttributes 是 Pod 准入决策的上下文。
// 此结构体的成员字段不应被修改。
type PodAdmitAttributes struct {
	// 要评估准入的 Pod
	Pod *v1.Pod
	// 绑定到 kubelet 的除了正在评估的 Pod 之外的所有 Pod
	OtherPods []*v1.Pod
}
```

### PodAdmitResult

```go
// PodAdmitResult 提供 Pod 准入决策的结果。
type PodAdmitResult struct {
	// 如果为 true，则应准入该 Pod。
	Admit bool
	// 为什么不能准入该 Pod 的简要单词原因。
	Reason string
	// 解释为什么不能准入该 Pod 的简要消息。
	Message string
}
```

### appArmorAdmitHandler

```GO
// appArmorAdmitHandler结构体定义了一个实现了PodAdmitHandler接口的结构体，用于处理AppArmor的接纳逻辑。
type appArmorAdmitHandler struct {
	apparmor.Validator
}

// NewAppArmorAdmitHandler函数返回一个PodAdmitHandler，用于从AppArmor的角度评估是否可以接受Pod。
func NewAppArmorAdmitHandler(validator apparmor.Validator) PodAdmitHandler {
	return &appArmorAdmitHandler{
		Validator: validator,
	}
}

// Admit方法用于评估Pod是否可以接受。
func (a *appArmorAdmitHandler) Admit(attrs *PodAdmitAttributes) PodAdmitResult {
	// 如果Pod已经在运行或已终止，无需重新检查AppArmor。
	if attrs.Pod.Status.Phase != v1.PodPending {
		return PodAdmitResult{Admit: true}
	}

	err := a.Validate(attrs.Pod)
	if err == nil {
		return PodAdmitResult{Admit: true}
	}
	return PodAdmitResult{
		Admit:   false,
		Reason:  "AppArmor",
		Message: fmt.Sprintf("无法强制执行AppArmor: %v", err),
	}
}

```

### predicateAdmitHandler

```GO
var _ PodAdmitHandler = &predicateAdmitHandler{}

// predicateAdmitHandler结构体定义了一个实现了PodAdmitHandler接口的结构体，用于处理基于predicates的接纳逻辑。
type predicateAdmitHandler struct {
	getNodeAnyWayFunc        getNodeAnyWayFuncType
	pluginResourceUpdateFunc pluginResourceUpdateFuncType
	admissionFailureHandler  AdmissionFailureHandler
}

// NewPredicateAdmitHandler函数返回一个PodAdmitHandler，用于从predicates的角度评估是否可以接受Pod。
func NewPredicateAdmitHandler(getNodeAnyWayFunc getNodeAnyWayFuncType, admissionFailureHandler AdmissionFailureHandler, pluginResourceUpdateFunc pluginResourceUpdateFuncType) PodAdmitHandler {
	return &predicateAdmitHandler{
		getNodeAnyWayFunc,
		pluginResourceUpdateFunc,
		admissionFailureHandler,
	}
}

type getNodeAnyWayFuncType func() (*v1.Node, error)

type pluginResourceUpdateFuncType func(*schedulerframework.NodeInfo, *PodAdmitAttributes) errors
```

#### Admit

```GO
// Admit方法用于评估Pod是否可以接受。
func (w *predicateAdmitHandler) Admit(attrs *PodAdmitAttributes) PodAdmitResult {
	node, err := w.getNodeAnyWayFunc()
	if err != nil {
		klog.ErrorS(err, "无法获取节点信息")
		return PodAdmitResult{
			Admit:   false,
			Reason:  "InvalidNodeInfo",
			Message: "Kubelet无法获取节点信息。",
		}
	}
	admitPod := attrs.Pod
	pods := attrs.OtherPods
	nodeInfo := schedulerframework.NewNodeInfo(pods...)
	nodeInfo.SetNode(node)

	// 确保节点具有足够的插件资源来满足Pod所需的资源
	if err = w.pluginResourceUpdateFunc(nodeInfo, attrs); err != nil {
		message := fmt.Sprintf("由于%v，更新插件资源失败，这是意外的。", err)
		klog.InfoS("无法接受Pod", "pod", klog.KObj(admitPod), "message", message)
		return PodAdmitResult{
			Admit:   false,
			Reason:  "UnexpectedAdmissionError",
			Message: message,
		}
	}

	// 移除节点信息中缺失的扩展资源的请求。这是为了支持集群级资源，这些资源是节点未知的扩展资源。
	//
	// 注意：如果一个Pod被手动绑定到一个需要的节点（例如静态Pod），而该节点上找不到所需的节点级扩展资源，那么Kubelet不会因为这个原因而拒绝接受Pod。这个问题将在将来的资源类API中解决。
	podWithoutMissingExtendedResources := removeMissingExtendedResources(admitPod, nodeInfo)

	reasons := generalFilter(podWithoutMissingExtendedResources, nodeInfo)
	fit := len(reasons) == 0
	if !fit {
		reasons, err = w.admissionFailureHandler.HandleAdmissionFailure(admitPod, reasons)
		fit = len(reasons) == 0 && err == nil
		if err != nil {
			message := fmt.Sprintf("在尝试从拒绝接受Pod中恢复时出现意外错误：%v", err)
			klog.InfoS("无法接受Pod，尝试从拒绝接受Pod中恢复时出现意外错误", "pod", klog.KObj(admitPod), "err", err)
			return PodAdmitResult{
				Admit:   fit,
				Reason:  "UnexpectedAdmissionError",
				Message: message,
			}
		}
	}
	if !fit {
		var reason string
		var message string
		if len(reasons) == 0 {
			message = fmt.Sprint("由于未知原因，GeneralPredicates失败，这是意外的。")
			klog.InfoS("无法接受Pod：由于未知原因，GeneralPredicates失败，这是意外的", "pod", klog.KObj(admitPod))
			return PodAdmitResult{
				Admit:   fit,
				Reason:  "UnknownReason",
				Message: message,
			}
		}
		// 如果存在失败的predicates，我们只返回第一个作为原因。
		r := reasons[0]
		switch re := r.(type) {
		case *PredicateFailureError:
			reason = re.PredicateName
			message = re.Error()
			klog.V(2).InfoS("Pod的Predicate失败", "pod", klog.KObj(admitPod), "err", message)
		case *InsufficientResourceError:
			reason = fmt.Sprintf("OutOf%s", re.ResourceName)
			message = re.Error()
			klog.V(2).InfoS("Pod的Predicate失败", "pod", klog.KObj(admitPod), "err", message)
		default:
			reason = "UnexpectedPredicateFailureType"
			message = fmt.Sprintf("由于%v，GeneralPredicates失败，这是意外的。", r)
			klog.InfoS("无法接受Pod", "pod", klog.KObj(admitPod), "err", message)
		}
		return PodAdmitResult{
			Admit:   fit,
			Reason:  reason,
			Message: message,
		}
	}
	if rejectPodAdmissionBasedOnOSSelector(admitPod, node) {
		return PodAdmitResult{
			Admit:   false,
			Reason:  "PodOSSelectorNodeLabelDoesNotMatch",
			Message: "无法接受Pod，因为`kubernetes.io/os`标签与节点标签不匹配",
		}
	}
	// 到这个时候，节点标签应该已经同步，这有助于识别使用的Pod。
	if rejectPodAdmissionBasedOnOSField(admitPod) {
		return PodAdmitResult{
			Admit:   false,
			Reason:  "PodOSNotSupported",
			Message: "无法接受Pod，因为OS字段与节点的OS不匹配",
		}
	}
	return PodAdmitResult{
		Admit: true,
	}
}
```

##### rejectPodAdmissionBasedOnOSSelector

```GO
// rejectPodAdmissionBasedOnOSSelector函数根据Pod的nodeSelector来拒绝Pod的接纳
// 我们期望kubelet每10秒进行一次状态协调，如果存在不匹配的情况，将更新节点标签。
func rejectPodAdmissionBasedOnOSSelector(pod *v1.Pod, node *v1.Node) bool {
	labels := node.Labels
	osName, osLabelExists := labels[v1.LabelOSStable]
	if !osLabelExists || osName != runtime.GOOS {
		if len(labels) == 0 {
			labels = make(map[string]string)
		}
		labels[v1.LabelOSStable] = runtime.GOOS
	}
	podLabelSelector, podOSLabelExists := pod.Labels[v1.LabelOSStable]
	if !podOSLabelExists {
		// 如果labelselector不存在，保持当前行为不变
		return false
	} else if podOSLabelExists && podLabelSelector != labels[v1.LabelOSStable] {
		return true
	}
	return false
}
```

##### rejectPodAdmissionBasedOnOSField

```GO
// rejectPodAdmissionBasedOnOSField函数根据Pod的OS字段来拒绝Pod的接纳，如果OS字段与runtime.GOOS不匹配。
// TODO: 当我们开始在kubernetes中支持LCOW时，放宽这个限制，因为podOS可能与节点的OS不匹配。
func rejectPodAdmissionBasedOnOSField(pod *v1.Pod) bool {
	if pod.Spec.OS == nil {
		return false
	}
	// 如果Pod的OS字段与runtime.GOOS不匹配，则返回false
	return string(pod.Spec.OS.Name) != runtime.GOOS
}
```

##### removeMissingExtendedResources

```GO
func removeMissingExtendedResources(pod *v1.Pod, nodeInfo *schedulerframework.NodeInfo) *v1.Pod {
	podCopy := pod.DeepCopy()
	for i, c := range pod.Spec.Containers {
		// 只处理Requests中的请求，而不处理Limits，因为
		// PodFitsResources predicate不使用Limits。
		podCopy.Spec.Containers[i].Resources.Requests = make(v1.ResourceList)
		for rName, rQuant := range c.Resources.Requests {
			if v1helper.IsExtendedResourceName(rName) {
				if _, found := nodeInfo.Allocatable.ScalarResources[rName]; !found {
					continue
				}
			}
			podCopy.Spec.Containers[i].Resources.Requests[rName] = rQuant
		}
	}
	return podCopy
}
```

#### AdmissionFailureHandler

```go
// AdmissionFailureHandler是一个接口，定义了如何处理无法接受Pod的失败。
// 这允许对Pod admission失败进行优雅处理。
type AdmissionFailureHandler interface {
	HandleAdmissionFailure(admitPod *v1.Pod, failureReasons []PredicateFailureReason) ([]PredicateFailureReason, error)
}

// AdmissionFailureHandlerStub是一个不执行任何admission失败处理的AdmissionFailureHandler。
// 它只是简单地将失败传递下去。
type AdmissionFailureHandlerStub struct{}

var _ AdmissionFailureHandler = &AdmissionFailureHandlerStub{}

// NewAdmissionFailureHandlerStub返回AdmissionFailureHandlerStub的实例。
func NewAdmissionFailureHandlerStub() *AdmissionFailureHandlerStub {
	return &AdmissionFailureHandlerStub{}
}

// HandleAdmissionFailure简单地将admission拒绝传递，没有特殊处理。
func (n *AdmissionFailureHandlerStub) HandleAdmissionFailure(admitPod *v1.Pod, failureReasons []PredicateFailureReason) ([]PredicateFailureReason, error) {
	return failureReasons, nil
}
```

## PodSyncLoopTarget

```go
// PodSyncLoopTarget 维护要进行 Pod 同步循环的处理程序列表。
type PodSyncLoopTarget interface {
	// AddPodSyncLoopHandler 添加指定的处理程序。
	AddPodSyncLoopHandler(a PodSyncLoopHandler)
}
```

## PodSyncLoopHandler

```go
// PodSyncLoopHandler 在每个同步循环迭代期间被调用。
type PodSyncLoopHandler interface {
	// ShouldSync 如果需要同步 Pod，则返回 true。
	// 此操作必须立即返回，因为它针对每个 Pod 调用。
	// 不应修改提供的 Pod。
	ShouldSync(pod *v1.Pod) bool
}
```

## PodSyncTarget

```go
// PodSyncTarget 维护要进行 Pod 同步的处理程序列表。
type PodSyncTarget interface {
	// AddPodSyncHandler 添加指定的处理程序。
	AddPodSyncHandler(a PodSyncHandler)
}
```

## PodSyncHandler

```go
// PodSyncHandler 在每次同步 Pod 操作期间被调用。
type PodSyncHandler interface {
	// ShouldEvict 在每个同步 Pod 操作期间调用以确定是否应将 Pod 驱逐出 kubelet。
	// 如果是这样，将更新 Pod 的状态，将其阶段标记为失败，并提供的原因和消息，
	// 并立即杀死 Pod。
	// 此操作必须立即返回，因为它针对每个同步 Pod 调用。
	// 不应修改提供的 Pod。
	ShouldEvict(pod *v1.Pod) ShouldEvictResponse
}
```

### ShouldEvictResponse

```go
// ShouldEvictResponse 提供应该驱逐请求的结果。
type ShouldEvictResponse struct {
	// 如果为 true，则应将 Pod 驱逐。
	Evict bool
	// 应该驱逐 Pod 的简要 CamelCase 原因。
	Reason string
	// 应该驱逐 Pod 的简要消息。
	Message string
}
```

### PodLifecycleTarget

```go
// PodLifecycleTarget 为方便起见，将一组生命周期接口组合在一起。
type PodLifecycleTarget interface {
	PodAdmitTarget
	PodSyncLoopTarget
	PodSyncTarget
}
```

## PodAdmitHandlers

```go
// PodAdmitHandlers 维护要进行 Pod 准入的处理程序列表。
type PodAdmitHandlers []PodAdmitHandler

// AddPodAdmitHandler 添加指定的观察者。
func (handlers *PodAdmitHandlers) AddPodAdmitHandler(a PodAdmitHandler) {
	*handlers = append(*handlers, a)
}
```

## PodSyncLoopHandlers

```go
// PodSyncLoopHandlers 维护要进行 Pod 同步循环的处理程序列表。
type PodSyncLoopHandlers []PodSyncLoopHandler

// AddPodSyncLoopHandler 添加指定的观察者。
func (handlers *PodSyncLoopHandlers) AddPodSyncLoopHandler(a PodSyncLoopHandler) {
	*handlers = append(*handlers, a)
}
```

## PodSyncHandlers

```go
// PodSyncHandlers 维护要进行 Pod 同步的处理程序列表。
type PodSyncHandlers []PodSyncHandler

// AddPodSyncHandler 添加指定的处理程序。
func (handlers *PodSyncHandlers) AddPodSyncHandler(a PodSyncHandler) {
	*handlers = append(*handlers, a)
}
```

## activeDeadlineHandler

```go
// activeDeadlineHandler知道如何对Pod强制执行活动截止时间。
type activeDeadlineHandler struct {
	// 用于截止时间强制执行的时钟
	clock clock.Clock
	// 提供Pod状态的提供者
	podStatusProvider status.PodStatusProvider
	// 当我们确定Pod超过活动截止时间时，用于发送事件的记录器
	recorder record.EventRecorder
}

// newActiveDeadlineHandler返回一个可以强制执行Pod活动截止时间的activeDeadlineHandler。
func newActiveDeadlineHandler(
	podStatusProvider status.PodStatusProvider,
	recorder record.EventRecorder,
	clock clock.Clock,
) (*activeDeadlineHandler, error) {

	// 检查所有必需的字段
	if clock == nil || podStatusProvider == nil || recorder == nil {
		return nil, fmt.Errorf("必需的参数不能为空： %v, %v, %v", clock, podStatusProvider, recorder)
	}
	return &activeDeadlineHandler{
		clock:             clock,
		podStatusProvider: podStatusProvider,
		recorder:          recorder,
	}, nil
}

// ShouldSync如果Pod已经超过其活动截止时间，则返回true。
func (m *activeDeadlineHandler) ShouldSync(pod *v1.Pod) bool {
	return m.pastActiveDeadline(pod)
}

// ShouldEvict如果Pod已经超过其活动截止时间，则返回true。
// 如果Pod已经超过截止时间，它会触发一个事件，表示Pod应该被驱逐。
func (m *activeDeadlineHandler) ShouldEvict(pod *v1.Pod) lifecycle.ShouldEvictResponse {
	if !m.pastActiveDeadline(pod) {
		return lifecycle.ShouldEvictResponse{Evict: false}
	}
	m.recorder.Eventf(pod, v1.EventTypeNormal, reason, message)
	return lifecycle.ShouldEvictResponse{Evict: true, Reason: reason, Message: message}
}

// pastActiveDeadline如果Pod的活动时间超过其ActiveDeadlineSeconds，则返回true。
func (m *activeDeadlineHandler) pastActiveDeadline(pod *v1.Pod) bool {
	// 没有指定活动截止时间
	if pod.Spec.ActiveDeadlineSeconds == nil {
		return false
	}
	// 获取最新的状态以确定是否已启动
	podStatus, ok := m.podStatusProvider.GetPodStatus(pod.UID)
	if !ok {
		podStatus = pod.Status
	}
	// 如果没有启动时间，则直接返回
	if podStatus.StartTime.IsZero() {
		return false
	}
	// 确定是否超过了截止时间
	start := podStatus.StartTime.Time
	duration := m.clock.Since(start)
	allowedDuration := time.Duration(*pod.Spec.ActiveDeadlineSeconds) * time.Second
	return duration >= allowedDuration
}
```

