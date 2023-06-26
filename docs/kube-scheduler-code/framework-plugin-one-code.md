---
id: 5-kube-scheduler-code 
title: kubernetes scheduler默认的插件代码走读(1)
description: kubernetes scheduler默认的插件代码走读(1)
keywords:
  - kubernetes
  - kube-scheduler
slug: /
---

## 插件

调度器默认的插件都有哪些，在`pkg/scheduler/framework/plugins/names/names.go`中有所有的默认插件。

```go
const (
	PrioritySort                    = "PrioritySort"
	DefaultBinder                   = "DefaultBinder"
	DefaultPreemption               = "DefaultPreemption"
	DynamicResources                = "DynamicResources"
	ImageLocality                   = "ImageLocality"
	InterPodAffinity                = "InterPodAffinity"
	NodeAffinity                    = "NodeAffinity"
	NodeName                        = "NodeName"
	NodePorts                       = "NodePorts"
	NodeResourcesBalancedAllocation = "NodeResourcesBalancedAllocation"
	NodeResourcesFit                = "NodeResourcesFit"
	NodeUnschedulable               = "NodeUnschedulable"
	NodeVolumeLimits                = "NodeVolumeLimits"
	AzureDiskLimits                 = "AzureDiskLimits"
	CinderLimits                    = "CinderLimits"
	EBSLimits                       = "EBSLimits"
	GCEPDLimits                     = "GCEPDLimits"
	PodTopologySpread               = "PodTopologySpread"
	SchedulingGates                 = "SchedulingGates"
	SelectorSpread                  = "SelectorSpread"
	TaintToleration                 = "TaintToleration"
	VolumeBinding                   = "VolumeBinding"
	VolumeRestrictions              = "VolumeRestrictions"
	VolumeZone                      = "VolumeZone"
)
```

## PrioritySort

### 作用

PrioritySort是Kubernetes的一个插件，它实现了基于优先级的排序。它是一个队列排序插件，用于将Pod按照优先级排序。Pod的优先级表示相对于其他Pod的重要性。如果一个Pod无法被调度，调度器会尝试抢占（驱逐）优先级较低的Pod，以便调度待定的Pod。

### 结构

```GO
// 定义常量 Name，表示插件名称
const Name = names.PrioritySort

// 实现了 framework.QueueSortPlugin 接口，用于实现基于优先级的排序
type PrioritySort struct{}

// 确认 PrioritySort 结构体实现了 framework.QueueSortPlugin 接口
var _ framework.QueueSortPlugin = &PrioritySort{}

// 实现 Name 方法，返回插件名称
func (pl *PrioritySort) Name() string {
	return Name
}

func New(_ runtime.Object, handle framework.Handle) (framework.Plugin, error) {
	return &PrioritySort{}, nil
}
```

### Less

```go
// 定义 Less 方法，用于在 activeQ 堆算法中对 Pod 进行排序
// 根据 Pod 的优先级进行排序，当优先级相同时，使用 PodQueueInfo.timestamp 进行排序
func (pl *PrioritySort) Less(pInfo1, pInfo2 *framework.QueuedPodInfo) bool {
    p1 := corev1helpers.PodPriority(pInfo1.Pod) // 获取第一个 Pod 的优先级
    p2 := corev1helpers.PodPriority(pInfo2.Pod) // 获取第二个 Pod 的优先级
    return (p1 > p2) || (p1 == p2 && pInfo1.Timestamp.Before(pInfo2.Timestamp)) // 根据优先级和时间戳进行排序
}
```

## DefaultBinder

### 作用

将Pod绑定到Node上。当Pod被创建时，Kubernetes调度器会将其绑定到一个Node上，以便在该Node上运行Pod。如果没有指定调度器，则使用DefaultBinder作为默认调度器。

### 结构

```GO
// 定义常量 Name，表示插件名称
const Name = names.DefaultBinder

// DefaultBinder binds pods to nodes using a k8s client.
type DefaultBinder struct {
	handle framework.Handle
}

// 检测是否实现了BindPlugin接口
var _ framework.BindPlugin = &DefaultBinder{}

func New(_ runtime.Object, handle framework.Handle) (framework.Plugin, error) {
	return &DefaultBinder{handle: handle}, nil
}

// 实现 Name 方法，返回插件名称
func (b DefaultBinder) Name() string {
	return Name
}
```

### Bind

```GO
func (b DefaultBinder) Bind(ctx context.Context, state *framework.CycleState, p *v1.Pod, nodeName string) *framework.Status {
    // 使用 klog 记录日志
    logger := klog.FromContext(ctx)
    logger.V(3).Info("Attempting to bind pod to node", "pod", klog.KObj(p), "node", klog.KRef("", nodeName))

    // 构建 Binding 对象
    binding := &v1.Binding{
        ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name, UID: p.UID},
        Target:     v1.ObjectReference{Kind: "Node", Name: nodeName},
    }

    // 发送 Bind 请求，将 Pod 绑定到 Node 上
    err := b.handle.ClientSet().CoreV1().Pods(binding.Namespace).Bind(ctx, binding, metav1.CreateOptions{})
    if err != nil {
        return framework.AsStatus(err)
    }

    // 返回空的 framework.Status，表示绑定成功
    return nil
}
```

## DefaultPreemption

### 作用

DefaultPreemption插件是Kubernetes的一个插件，它的作用是在调度器中实现Pod的抢占。当一个Pod无法被调度时，调度器会尝试抢占（驱逐）优先级较低的Pod，以便调度待定的Pod。

### 结构

```go
const Name = names.DefaultPreemption

// 定义 DefaultPreemption 结构体，实现了 PostFilter 接口，用于实现 Pod 的抢占逻辑
type DefaultPreemption struct {
	fh        framework.Handle
	fts       feature.Features
	args      config.DefaultPreemptionArgs
	podLister corelisters.PodLister
	pdbLister policylisters.PodDisruptionBudgetLister
}

var _ framework.PostFilterPlugin = &DefaultPreemption{}

func (pl *DefaultPreemption) Name() string {
	return Name
}

// 定义 New 方法，用于初始化并返回一个 DefaultPreemption 插件实例
func New(dpArgs runtime.Object, fh framework.Handle, fts feature.Features) (framework.Plugin, error) {
    // 将传入的 runtime.Object 强制类型转换为 *DefaultPreemptionArgs
    args, ok := dpArgs.(*config.DefaultPreemptionArgs)
    if !ok {
    	return nil, fmt.Errorf("got args of type %T, want *DefaultPreemptionArgs", dpArgs)
    }
    // 校验参数是否有效
    if err := validation.ValidateDefaultPreemptionArgs(nil, args); err != nil {
        return nil, err
    }

    // 构建 DefaultPreemption 结构体
    pl := DefaultPreemption{
        fh:        fh,
        fts:       fts,
        args:      *args,
        podLister: fh.SharedInformerFactory().Core().V1().Pods().Lister(),
        pdbLister: getPDBLister(fh.SharedInformerFactory()),
    }

    // 返回 DefaultPreemption 插件实例
    return &pl, nil
}

func getPDBLister(informerFactory informers.SharedInformerFactory) policylisters.PodDisruptionBudgetLister {
	return informerFactory.Policy().V1().PodDisruptionBudgets().Lister()
}
```

### PostFilter

```go
// PostFilter 在 postFilter 扩展点处被调用。
func (pl *DefaultPreemption) PostFilter(ctx context.Context, state *framework.CycleState, pod *v1.Pod, m framework.NodeToStatusMap) (*framework.PostFilterResult, *framework.Status) {
    defer func() {
        // 记录尝试迁移 Pod 的次数
        metrics.PreemptionAttempts.Inc()
    }()
    // 创建 preemption.Evaluator 实例用于判断 pod 的迁移情况
    pe := preemption.Evaluator{
        PluginName: names.DefaultPreemption,
        Handler:    pl.fh,
        PodLister:  pl.podLister,
        PdbLister:  pl.pdbLister,
        State:      state,
        Interface:  pl,
    }

    // 调用 pe.Preempt 方法，返回值是预处理结果和可能出现的错误
    result, status := pe.Preempt(ctx, pod, m)
    if status.Message() != "" {
        // 如果出现错误，则返回一个新的状态和错误信息
        return result, framework.NewStatus(status.Code(), "preemption: "+status.Message())
    }
    // 如果没有错误，则直接返回预处理结果和状态
    return result, status
}
```

### Evaluator

```go
type Evaluator struct {
    PluginName string // 插件名
    Handler    framework.Handle // framework.Handle类型，用于处理请求
    PodLister  corelisters.PodLister // 核心V1 Pod列表器
    PdbLister  policylisters.PodDisruptionBudgetLister // PodDisruptionBudget列表器
    State      *framework.CycleState // 周期状态
    Interface // Interface类型，不同的预选插件需要实现该接口
}

type Interface interface {
    GetOffsetAndNumCandidates(nodes int32) (int32, int32) // 计算候选数和偏移量
    CandidatesToVictimsMap(candidates []Candidate) map[string]*extenderv1.Victims // 构建候选节点到被预选Pods映射
    PodEligibleToPreemptOthers(pod *v1.Pod, nominatedNodeStatus *framework.Status) (bool, string) // 检查Pod是否能够抢占其他Pods
    SelectVictimsOnNode(ctx context.Context, state *framework.CycleState, pod *v1.Pod,
    nodeInfo *framework.NodeInfo, pdbs []*policy.PodDisruptionBudget) ([]*v1.Pod, int, *framework.Status) // 找到节点上应被抢占Pods的最小集合
}
```

#### Candidate

```go
// Candidate 表示一个被提名的节点，在该节点上可以调度preemptor，同时还有一个需要被驱逐的victim列表，
//以使preemptor适合该节点。
type Candidate interface {
    // Victims 包装了一组待抢占的Pod以及PDB违规数量。
    Victims() *extenderv1.Victims
    // Name 返回被提名运行preemptor的目标节点名称。
    Name() string
}

type candidate struct {
    victims *extenderv1.Victims
    name string
}

// Victims 返回s.victims。
func (s *candidate) Victims() *extenderv1.Victims {
	return s.victims
}

// Name 返回s.name。
func (s *candidate) Name() string {
	return s.name
}
```

#### Victims

```go
// Victims 表示：
//
// pods: 预计将被抢占的一组Pod。
// numPDBViolations: PodDisruptionBudget违规次数的计数。
type Victims struct {
    Pods []*v1.Pod
    NumPDBViolations int64
}
```

#### Interface实现

- DefaultPreemption实现了这个interface

```go
// GetOffsetAndNumCandidates 选择随机偏移量并计算应该选取的候选节点数，以供干运行抢占使用。
func (pl *DefaultPreemption) GetOffsetAndNumCandidates(numNodes int32) (int32, int32) {
	return rand.Int31n(numNodes), pl.calculateNumCandidates(numNodes)
}

// 该函数不适用于 out-of-tree 抢占插件，因为它们在同一被提名节点上使用不同的抢占候选节点。
func (pl *DefaultPreemption) CandidatesToVictimsMap(candidates []preemption.Candidate) map[string]*extenderv1.Victims {
	m := make(map[string]*extenderv1.Victims, len(candidates))
	for _, c := range candidates {
		m[c.Name()] = c.Victims()
	}
	return m
}

// PodEligibleToPreemptOthers 返回一个 bool 值和一个 string 值。bool 值表示该 pod 是否应该被考虑用于抢占其他 pod。
// string 值包含不符合资格的原因。
// 有几个原因：
//  1. 该 pod 具有 preemptionPolicy=Never。
//  2. 该 pod 已经抢占了其他 pod，而这些 pod 正在优雅终止阶段。
//     当前我们检查为该 pod 提名的节点，只要在该节点上有处于终止阶段的 pod，我们就不尝试再次抢占更多的 pod。
func (pl *DefaultPreemption) PodEligibleToPreemptOthers(pod *v1.Pod, nominatedNodeStatus *framework.Status) (bool, string) {
	if pod.Spec.PreemptionPolicy != nil && *pod.Spec.PreemptionPolicy == v1.PreemptNever {
		return false, "not eligible due to preemptionPolicy=Never."
	}

	nodeInfos := pl.fh.SnapshotSharedLister().NodeInfos()
	nomNodeName := pod.Status.NominatedNodeName
	if len(nomNodeName) > 0 {
		// 如果 pod 的被提名节点被过滤器视为不可调度和不可解析，则应再次考虑抢占该 pod。
		if nominatedNodeStatus.Code() == framework.UnschedulableAndUnresolvable {
			return true, ""
		}

		if nodeInfo, _ := nodeInfos.Get(nomNodeName); nodeInfo != nil {
			podPriority := corev1helpers.PodPriority(pod)
			for _, p := range nodeInfo.Pods {
				if corev1helpers.PodPriority(p.Pod) < podPriority && podTerminatingByPreemption(p.Pod, pl.fts.EnablePodDisruptionConditions) {
					// 在被提名节点上有处于终止阶段的 pod。
					return false, "not eligible due to a terminating pod on the nominated node."
				}
			}
		}
	}
	return true, ""
}

// SelectVictimsOnNode 函数通过查找在给定节点上应该抢占的最小一组 pod，以便为 “pod” 调度提供足够的空间。
func (pl *DefaultPreemption) SelectVictimsOnNode(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	nodeInfo *framework.NodeInfo,
	pdbs []*policy.PodDisruptionBudget) ([]*v1.Pod, int, *framework.Status) {
	logger := klog.FromContext(ctx)
	var potentialVictims []*framework.PodInfo
	removePod := func(rpi *framework.PodInfo) error {
        // 删除指定 pod 并更新节点信息。
		if err := nodeInfo.RemovePod(rpi.Pod); err != nil {
			return err
		}
        // 运行预过滤插件，删除 pod 后的处理。
		status := pl.fh.RunPreFilterExtensionRemovePod(ctx, state, pod, rpi, nodeInfo)
		if !status.IsSuccess() {
			return status.AsError()
		}
		return nil
	}
	addPod := func(api *framework.PodInfo) error {
        // 添加新的 pod 并更新节点信息
		nodeInfo.AddPodInfo(api)
        // 运行预过滤插件，添加 pod 后的处理。
		status := pl.fh.RunPreFilterExtensionAddPod(ctx, state, pod, api, nodeInfo)
		if !status.IsSuccess() {
			return status.AsError()
		}
		return nil
	}
	// 第一步，从节点上删除所有优先级较低的 pod，并检查是否可以安排给定的 pod。
	podPriority := corev1helpers.PodPriority(pod)
	for _, pi := range nodeInfo.Pods {
		if corev1helpers.PodPriority(pi.Pod) < podPriority {
            // 将潜在的受害者添加到 potentialVictims 中。
			potentialVictims = append(potentialVictims, pi)
			if err := removePod(pi); err != nil {
				return nil, 0, framework.AsStatus(err)
			}
		}
	}

	// 如果没有找到潜在的受害者，那么我们不需要再次评估节点，因为其状态没有改变。
	if len(potentialVictims) == 0 {
		message := fmt.Sprintf("No preemption victims found for incoming pod")
		return nil, 0, framework.NewStatus(framework.UnschedulableAndUnresolvable, message)
	}

	// 如果在删除所有优先级较低的 pod 后新的 pod 仍无法放置，
    // 我们几乎完成了，这个节点不适合预占。我们可以检查的唯一条件是，
    // 如果 “pod” 由于与一个或多个受害者之间的亲和关系而无法调度，但出于性能原因，我们已决定不支持此情况。
    // 与较低优先级的 pod 具有亲和关系也不是推荐的配置。
	if status := pl.fh.RunFilterPluginsWithNominatedPods(ctx, state, pod, nodeInfo); !status.IsSuccess() {
		return nil, 0, status
	}
	var victims []*v1.Pod
	numViolatingVictim := 0
    // 使用 sort.Slice() 函数对 potentialVictims 切片进行排序，排序规则为util.MoreImportantPod()函数返回值
	sort.Slice(potentialVictims, func(i, j int) bool { return util.MoreImportantPod(potentialVictims[i].Pod, potentialVictims[j].Pod) })
	// 将 potentialVictims 切片中的 violating 和 non-violating victims 进行分类
	violatingVictims, nonViolatingVictims := filterPodsWithPDBViolation(potentialVictims, pdbs)
	reprievePod := func(pi *framework.PodInfo) (bool, error) {
		if err := addPod(pi); err != nil {
			return false, err
		}
        // 使用 pl.fh.RunFilterPluginsWithNominatedPods() 函数运行过滤插件，并将状态赋值给 status
		status := pl.fh.RunFilterPluginsWithNominatedPods(ctx, state, pod, nodeInfo)
		fits := status.IsSuccess()
		if !fits {
            // 如果 status 不是成功状态，则从节点移除 Pod，并将其添加到 victims 切片中
			if err := removePod(pi); err != nil {
				return false, err
			}
			rpi := pi.Pod
			victims = append(victims, rpi)
			logger.V(5).Info("Pod is a potential preemption victim on node", "pod", klog.KObj(rpi), "node", klog.KObj(nodeInfo.Node()))
		}
        // 返回 fits 和错误信息
		return fits, nil
	}
    // 对 violating victims 进行处理
	for _, p := range violatingVictims {
        // 如果 reprievePod() 函数返回错误，则返回 nil、0 和错误信息
		if fits, err := reprievePod(p); err != nil {
            // 如果 reprievePod() 函数返回 fits 为 false，则 numViolatingVictim 加一
			return nil, 0, framework.AsStatus(err)
		} else if !fits {
			numViolatingVictim++
		}
	}
	// 对 non-violating victims 进行处理
	for _, p := range nonViolatingVictims {
        // 如果 reprievePod() 函数返回错误，则返回 nil、0 和错误信息
		if _, err := reprievePod(p); err != nil {
			return nil, 0, framework.AsStatus(err)
		}
	}
	return victims, numViolatingVictim, framework.NewStatus(framework.Success)
}
```

##### calculateNumCandidates

```GO
// calculateNumCandidates函数用于计算FindCandidates方法必须根据
// <minCandidateNodesPercentage>和<minCandidateNodesAbsolute>给出的限制，生成的候选数。
// 返回的候选数不会大于<numNodes>。
func (pl *DefaultPreemption) calculateNumCandidates(numNodes int32) int32 {
    // 计算百分比
    n := (numNodes * pl.args.MinCandidateNodesPercentage) / 100
    // 如果候选数小于<minCandidateNodesAbsolute>，则将n设置为<minCandidateNodesAbsolute>。
    if n < pl.args.MinCandidateNodesAbsolute {
        n = pl.args.MinCandidateNodesAbsolute
    }
    // 如果候选数大于<numNodes>，则将n设置为<numNodes>。
    if n > numNodes {
        n = numNodes
    }
    return n
}
```

##### podTerminatingByPreemption

```go
// 如果没有启用 PodDisruptionConditions 特性，则只检查 Pod 是否处于终止状态。
// 如果启用了该特性，则还需要检查 Pod 是否是由调度程序抢占导致终止。
func podTerminatingByPreemption(p *v1.Pod, enablePodDisruptionConditions bool) bool {
	// 如果 Pod 没有设置 DeletionTimestamp，说明没有处于终止状态。
	if p.DeletionTimestamp == nil {
		return false
	}

	// 如果没有启用 PodDisruptionConditions 特性，只需要检查 Pod 是否处于终止状态。
	if !enablePodDisruptionConditions {
		return true
	}

	// 如果启用了 PodDisruptionConditions 特性，则检查 Pod 是否是由调度程序抢占导致终止。
	for _, condition := range p.Status.Conditions {
		if condition.Type == v1.DisruptionTarget {
			return condition.Status == v1.ConditionTrue && condition.Reason == v1.PodReasonPreemptionByScheduler
		}
	}
	return false
}
```

##### filterPodsWithPDBViolation

```go
// filterPodsWithPDBViolation函数将给定的“podInfos”根据它们是否违反了PDB（PodDisruptionBudget）分成两组，“violatingPodInfos”和“nonViolatingPodInfos”。
// 此函数稳定且不更改接收到的pod列表的顺序。因此，如果它接收到一个已排序的列表，则分组将保留输入列表的顺序。
func filterPodsWithPDBViolation(podInfos []*framework.PodInfo, pdbs []*policy.PodDisruptionBudget) (violatingPodInfos, nonViolatingPodInfos []*framework.PodInfo) {
	pdbsAllowed := make([]int32, len(pdbs)) // 声明长度为pdbs长度的切片pdbsAllowed
    // 初始化pdbsAllowed切片
    for i, pdb := range pdbs {
        pdbsAllowed[i] = pdb.Status.DisruptionsAllowed
    }

    // 遍历podInfos切片
    for _, podInfo := range podInfos {
        pod := podInfo.Pod // 获取pod

        pdbForPodIsViolated := false // pdbForPodIsViolated为pod是否违反PDB的标志

        // 如果pod没有标签，则不会匹配任何PDB，所以不需要检查
        if len(pod.Labels) != 0 {
            // 遍历pdbs切片
            for i, pdb := range pdbs {
                if pdb.Namespace != pod.Namespace {
                    continue // 如果pdb的namespace不等于pod的namespace，则继续下一次循环
                }

                // 从pdb的Spec.Selector字段获取选择器
                selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
                if err != nil {
                    // 此对象具有无效的选择器，它不与pod匹配
                    continue
                }

                // 空的选择器匹配任何标签集。如果pdb的选择器为空或不匹配pod的标签集，则继续下一次循环
                if selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
                    continue
                }

                // 如果pod在DisruptedPods中存在，则表示它已在API服务器中处理过，因此我们不将其视为违反的情况
                if _, exist := pdb.Status.DisruptedPods[pod.Name]; exist {
                    continue
                }

                // 只有在其不在<DisruptedPods>中时才减少匹配的pdb；否则，我们可能会过度减少预算数目
                pdbsAllowed[i]--

                // 如果pdb被减少后小于0，则表示pod违反了PDB
                if pdbsAllowed[i] < 0 {
                    pdbForPodIsViolated = true
                }
            }
        }

        // 将podInfos切片中的pod分组
        if pdbForPodIsViolated {
            violatingPodInfos = append(violatingPodInfos, podInfo)
        } else {
            nonViolatingPodInfos = append(nonViolatingPodInfos, podInfo)
        }
    }
    return violatingPodInfos, nonViolatingPodInfos
}
```

#### Preempt

```go
// Preempt方法执行预选和抢占逻辑，返回PostFilterResult和Status两个结果。
// PostFilterResult携带推荐的被提名节点的名称，Status表示方法执行的状态。
// 返回结果的语义因不同场景而异：
//
// - <nil, Error>. 这表示是一种偶发的、可以在将来的周期中自动恢复的错误。
//
// - <nil, Unschedulable>. 这种状态通常表示抢占器正在等待受害者被完全终止。
//
// - 对于上述两种情况，返回一个nil的PostFilterResult以保持pod的nominatedNodeName不变。
//
// - <非nil的PostFilterResult, Unschedulable>。它表示即使进行抢占，也无法为该Pod调度。
// 在这种情况下，返回一个非nil的PostFilterResult，并且result.NominatingMode说明如何处理nominatedNodeName。
//
// - <非nil的PostFilterResult, Success>。这是正常的情况，nominatedNodeName将被应用于抢占器Pod。
func (ev *Evaluator) Preempt(ctx context.Context, pod *v1.Pod, m framework.NodeToStatusMap) (*framework.PostFilterResult, *framework.Status) {
	logger := klog.FromContext(ctx)
    // 0）获取Pod的最新版本。
    // 在创建Scheduler对象时，informer cache已经被初始化，因此可以直接获取Pod。
    // 但是，测试代码可能需要手动初始化共享的pod informer。
    podNamespace, podName := pod.Namespace, pod.Name
    pod, err := ev.PodLister.Pods(pod.Namespace).Get(pod.Name)
    if err != nil {
        logger.Error(err, "Could not get the updated preemptor pod object", "pod", klog.KRef(podNamespace, podName))
        return nil, framework.AsStatus(err)
    }

    // 1）确保抢占器有资格抢占其他Pod。
    if ok, msg := ev.PodEligibleToPreemptOthers(pod, m[pod.Status.NominatedNodeName]); !ok {
        logger.V(5).Info("Pod is not eligible for preemption", "pod", klog.KObj(pod), "reason", msg)
        return nil, framework.NewStatus(framework.Unschedulable, msg)
    }

    // 2）查找所有的抢占候选节点。
    candidates, nodeToStatusMap, err := ev.findCandidates(ctx, pod, m)
    if err != nil && len(candidates) == 0 {
        return nil, framework.AsStatus(err)
    }

    // 只有当没有候选节点可以匹配Pod时，才返回FitError。
    if len(candidates) == 0 {
        fitError := &framework.FitError{
            Pod:         pod,
            NumAllNodes: len(nodeToStatusMap),
            Diagnosis: framework.Diagnosis{
                NodeToStatusMap: nodeToStatusMap,
                // 将FailedPlugins设置为nil，因为它不会在移动Pod时使用。
            },
        }
        // 如果适用，指定nominatedNodeName以清除Pod的nominatedNodeName状态
        return framework.NewPostFilterResultWithNominatedNode(""), framework.NewStatus(framework.Unschedulable, fitError.Error())
	}
    // 3) 与已注册的 Extender 交互，如果需要的话，过滤掉一些候选节点。
    candidates, status := ev.callExtenders(logger, pod, candidates)
    if !status.IsSuccess() {
    	return nil, status
    }
    // 4) 找到最佳的候选节点。
    bestCandidate := ev.SelectCandidate(logger, candidates)
    if bestCandidate == nil || len(bestCandidate.Name()) == 0 {
        return nil, framework.NewStatus(framework.Unschedulable, "没有可用于抢占的候选节点")
    }

    // 5) 在将所选候选节点提名之前执行准备工作。
    if status := ev.prepareCandidate(ctx, bestCandidate, pod, ev.PluginName); !status.IsSuccess() {
        return nil, status
    }

    return framework.NewPostFilterResultWithNominatedNode(bestCandidate.Name()), framework.NewStatus(framework.Success)
}
```

##### findCandidates

```GO
// FindCandidates函数计算一个预emption候选列表，其中每个候选节点可执行以使给定的<pod>可调度。
func (ev *Evaluator) findCandidates(ctx context.Context, pod *v1.Pod, m framework.NodeToStatusMap) ([]Candidate, framework.NodeToStatusMap, error) {
	allNodes, err := ev.Handler.SnapshotSharedLister().NodeInfos().List()
	if err != nil {
		return nil, nil, err
	}
	if len(allNodes) == 0 {
		return nil, nil, errors.New("no nodes available")
	}
	logger := klog.FromContext(ctx)
    // 调用nodesWherePreemptionMightHelp函数筛选潜在的预emption候选节点。
	potentialNodes, unschedulableNodeStatus := nodesWherePreemptionMightHelp(allNodes, m)
	if len(potentialNodes) == 0 {
		logger.V(3).Info("Preemption will not help schedule pod on any node", "pod", klog.KObj(pod))
		// 在这种情况下，我们应该清除pod的任何现有提名节点名称。
		if err := util.ClearNominatedNodeName(ctx, ev.Handler.ClientSet(), pod); err != nil {
			logger.Error(err, "Could not clear the nominatedNodeName field of pod", "pod", klog.KObj(pod))
			// 我们不返回，因为此错误并不关键。
		}
		return nil, unschedulableNodeStatus, nil
	}

	pdbs, err := getPodDisruptionBudgets(ev.PdbLister)
	if err != nil {
		return nil, nil, err
	}
	
    // 通过调用GetOffsetAndNumCandidates函数计算所需候选者的数量。
	offset, numCandidates := ev.GetOffsetAndNumCandidates(int32(len(potentialNodes)))
	if loggerV := logger.V(5); logger.Enabled() {
		var sample []string
		for i := offset; i < offset+10 && i < int32(len(potentialNodes)); i++ {
			sample = append(sample, potentialNodes[i].Node().Name)
		}
		loggerV.Info("Selected candidates from a pool of nodes", "potentialNodesCount", len(potentialNodes), "offset", offset, "sampleLength", len(sample), "sample", sample, "candidates", numCandidates)
	}
    // 通过调用DryRunPreemption函数获取预emption候选者列表。
	candidates, nodeStatuses, err := ev.DryRunPreemption(ctx, pod, potentialNodes, pdbs, offset, numCandidates)
    // 将unschedulableNodeStatus合并到nodeStatuses中。
	for node, nodeStatus := range unschedulableNodeStatus {
		nodeStatuses[node] = nodeStatus
	}
	return candidates, nodeStatuses, err
}
```

###### nodesWherePreemptionMightHelp

```GO
// nodesWherePreemptionMightHelp 函数返回一个由已经失败的谓词筛选出来的节点列表，通过移除节点上的 pod 可能满足这些谓词。
func nodesWherePreemptionMightHelp(nodes []*framework.NodeInfo, m framework.NodeToStatusMap) ([]*framework.NodeInfo, framework.NodeToStatusMap) {
	var potentialNodes []*framework.NodeInfo
	nodeStatuses := make(framework.NodeToStatusMap)
	for _, node := range nodes {
		name := node.Node().Name // 获取节点的名称
		// 我们依赖每个插件提供的状态信息（'Unschedulable' 或 'UnschedulableAndUnresolvable'）
		// 来确定该节点上的 pod 是否可以通过抢占来解决调度问题。
		if m[name].Code() == framework.UnschedulableAndUnresolvable { // 节点已经被标记为无法解决调度问题
			nodeStatuses[node.Node().Name] = framework.NewStatus(framework.UnschedulableAndUnresolvable, "Preemption is not helpful for scheduling")  // 标记为无法通过抢占解决调度问题
			continue
		}
		potentialNodes = append(potentialNodes, node) // 记录可以尝试抢占的节点
	}
	return potentialNodes, nodeStatuses
}
```

###### ClearNominatedNodeName

```GO
// ClearNominatedNodeName 函数内部会向 API 服务器提交一个 patch 请求，将每个 pod[*].Status.NominatedNodeName 设置为 ""。
func ClearNominatedNodeName(ctx context.Context, cs kubernetes.Interface, pods ...*v1.Pod) utilerrors.Aggregate {
	var errs []error
	for _, p := range pods {
		if len(p.Status.NominatedNodeName) == 0 {  // 如果已经被清空过，则跳过
			continue
		}
		podStatusCopy := p.Status.DeepCopy()  // 复制一份 pod 的状态
		podStatusCopy.NominatedNodeName = "" // 将 pod 的 NominatedNodeName 字段清空
		if err := PatchPodStatus(ctx, cs, p, podStatusCopy); err != nil {  // 提交一个 patch 请求
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs) // 返回所有的错误
}
```

###### PatchPodStatus

```GO
// PatchPodStatus 函数计算从 <old.Status> 到 <newStatus> 的 delta bytes 变化，
// 然后向 API 服务器提交请求以修补 pod 的变化。
func PatchPodStatus(ctx context.Context, cs kubernetes.Interface, old *v1.Pod, newStatus *v1.PodStatus) error {
    if newStatus == nil {
    	return nil
    }
        oldData, err := json.Marshal(v1.Pod{Status: old.Status}) // 将旧状态的 Pod 转换为 JSON 字节
    if err != nil {
        return err
    }

    newData, err := json.Marshal(v1.Pod{Status: *newStatus}) // 将新状态的 Pod 转换为 JSON 字节
    if err != nil {
        return err
    }
    // 生成两个 JSON 字节序列之间的补丁
    patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, &v1.Pod{})
    if err != nil {
        return fmt.Errorf("failed to create merge patch for pod %q/%q: %v", old.Namespace, old.Name, err)
    }

    if "{}" == string(patchBytes) { // 如果补丁为 "{}"，则不需要进行修补操作
        return nil
    }

    // 定义 patchFn 函数用于向 API 服务器提交修补操作
    patchFn := func() error {
        _, err := cs.CoreV1().Pods(old.Namespace).Patch(ctx, old.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}, "status")
        return err
    }

    // 在遇到可重试错误的情况下进行重试，如果错误不可重试，则返回错误
    return retry.OnError(retry.DefaultBackoff, Retriable, patchFn)
}
```

###### getPodDisruptionBudgets

```GO
func getPodDisruptionBudgets(pdbLister policylisters.PodDisruptionBudgetLister) ([]*policy.PodDisruptionBudget, error) {
    if pdbLister != nil { // 如果 pdbLister 不为空，则获取 PodDisruptionBudget 对象列表
    	return pdbLister.List(labels.Everything())
    }
    return nil, nil // 如果 pdbLister 为空，则返回一个空列表和空错误
}
```

###### DryRunPreemption

```GO
// DryRunPreemption 在并行的情况下模拟对 potentialNodes 中的节点进行抢占(preemption)逻辑，返回预抢占的候选节点列表和指示过滤节点状态的映射。
// 候选节点的数量取决于插件参数中定义的约束条件。在返回的候选列表中，不违反 PodDisruptionBudget 的节点比违反它的节点更受欢迎。
// 注意: 该方法是导出的，以便在默认预抢占中更容易进行测试。
func (ev *Evaluator) DryRunPreemption(ctx context.Context, pod *v1.Pod, potentialNodes []*framework.NodeInfo,
	pdbs []*policy.PodDisruptionBudget, offset int32, numCandidates int32) ([]Candidate, framework.NodeToStatusMap, error) {
	fh := ev.Handler
    // 创建非违反 PDB 和违反 PDB 候选列表
	nonViolatingCandidates := newCandidateList(numCandidates)
	violatingCandidates := newCandidateList(numCandidates)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
    // 创建节点状态映射
	nodeStatuses := make(framework.NodeToStatusMap)
    // 创建状态锁和错误列表
	var statusesLock sync.Mutex
	var errs []error
    // 创建 checkNode 函数
	checkNode := func(i int) {
        // 克隆 potentialNodes[(int(offset)+i)%len(potentialNodes)]，stateCopy 和 pod，并返回 pod 在节点上的可抢占（可调度）受害者
		nodeInfoCopy := potentialNodes[(int(offset)+i)%len(potentialNodes)].Clone()
		stateCopy := ev.State.Clone()
		pods, numPDBViolations, status := ev.SelectVictimsOnNode(ctx, stateCopy, pod, nodeInfoCopy, pdbs)
        // 如果状态为成功，并且存在可抢占的受害者，则将受害者添加到相应的候选列表中
		if status.IsSuccess() && len(pods) != 0 {
			victims := extenderv1.Victims{
				Pods:             pods,
				NumPDBViolations: int64(numPDBViolations),
			}
			c := &candidate{
				victims: &victims,
				name:    nodeInfoCopy.Node().Name,
			}
			if numPDBViolations == 0 {
				nonViolatingCandidates.add(c)
			} else {
				violatingCandidates.add(c)
			}
            // 如果存在非违反 PDB 的候选，则尽早取消
			nvcSize, vcSize := nonViolatingCandidates.size(), violatingCandidates.size()
			if nvcSize > 0 && nvcSize+vcSize >= numCandidates {
				cancel()
			}
			return
		}
        // 如果状态为成功，并且不存在可抢占的受害者，则返回错误
		if status.IsSuccess() && len(pods) == 0 {
			status = framework.AsStatus(fmt.Errorf("expected at least one victim pod on node %q", nodeInfoCopy.Node().Name))
		}
		statusesLock.Lock()
		if status.Code() == framework.Error {
			errs = append(errs, status.AsError())
		}
        // 将状态和错误信息添加到状态map中
		nodeStatuses[nodeInfoCopy.Node().Name] = status
		statusesLock.Unlock()
	}
    // 使用 fh.Parallelizer() 方法并行执行 checkNode() 方法，每个 potentialNodes 数组中的节点依次调用 checkNode() 方法。
	// ev.PluginName 表示 Plugin 的名称。
	fh.Parallelizer().Until(ctx, len(potentialNodes), checkNode, ev.PluginName)
	return append(nonViolatingCandidates.get(), violatingCandidates.get()...), nodeStatuses, utilerrors.NewAggregate(errs)
}
```

###### candidateList

```go
// 定义一个结构体 candidateList，包含 idx 和 items 两个字段，分别表示下一个待添加元素的位置和元素切片。
type candidateList struct {
    idx int32
    items []Candidate
}

// newCandidateList() 方法返回一个新的 candidateList 实例。
// size 参数指定了 items 切片的大小。
func newCandidateList(size int32) *candidateList {
	return &candidateList{idx: -1, items: make([]Candidate, size)}
}

// add() 方法以原子方式将候选节点添加到内部的 items 数组中。
func (cl *candidateList) add(c *candidate) {
    if idx := atomic.AddInt32(&cl.idx, 1); idx < int32(len(cl.items)) {
    	cl.items[idx] = c
    }
}

// 使用 fh.Parallelizer() 方法并行执行 checkNode() 方法，每个 potentialNodes 数组中的节点依次调用 checkNode() 方法。
// ev.PluginName 表示 Plugin 的名称。
fh.Parallelizer().Until(ctx, len(potentialNodes), checkNode, ev.PluginName)

// 将 nonViolatingCandidates 和 violatingCandidates 数组中的元素合并到一起，返回一个 Candidate 切片；
// nodeStatuses 是一个映射表，其中键是节点名称，值是该节点的状态；
// errs 是一个包含所有错误的 error 切片，将这些错误聚合为一个错误返回。
return append(nonViolatingCandidates.get(), violatingCandidates.get()...), nodeStatuses, utilerrors.NewAggregate(errs)

// 定义一个结构体 candidateList，包含 idx 和 items 两个字段，分别表示下一个待添加元素的位置和元素切片。
type candidateList struct {
    idx int32
    items []Candidate
}

// newCandidateList() 方法返回一个新的 candidateList 实例。
// size 参数指定了 items 切片的大小。
func newCandidateList(size int32) *candidateList {
	return &candidateList{idx: -1, items: make([]Candidate, size)}
}

// add() 方法以原子方式将候选节点添加到内部的 items 数组中。
func (cl *candidateList) add(c *candidate) {
    if idx := atomic.AddInt32(&cl.idx, 1); idx < int32(len(cl.items)) {
    	cl.items[idx] = c
    }
}

// size() 方法返回当前存储的候选节点的数量。
// 注意，当调用该方法时，一些 add() 操作可能仍在执行中，
// 因此必须注意确保在访问列表元素之前，所有 add() 操作都已完成。
func (cl *candidateList) size() int32 {
    n := atomic.LoadInt32(&cl.idx) + 1
    if n >= int32(len(cl.items)) {
    	n = int32(len(cl.items))
    }
    return n
}

// get() 方法返回存储的候选项切片。注意，此方法不是原子的，
// 并且假定所有 add() 操作都已完成。
func (cl *candidateList) get() []Candidate {
	return cl.items[:cl.size()]
}
```

##### callExtenders

```go
// callExtenders 调用给定的 extender 来选择可行的 candidate 列表。
// 我们只会检查支持抢占的 extenders 的 candidates。
// 不支持抢占的 extenders 可能会后续阻止抢占者被调度到提名的 node 上。
// 在这种情况下，调度程序将在后续调度周期中为抢占者找到不同的主机。
func (ev *Evaluator) callExtenders(logger klog.Logger, pod *v1.Pod, candidates []Candidate) ([]Candidate, *framework.Status) {
    extenders := ev.Handler.Extenders() // 获取所有 extender
    nodeLister := ev.Handler.SnapshotSharedLister().NodeInfos() // 获取节点列表
    if len(extenders) == 0 {
    	return candidates, nil
    }
    // 将 candidate 列表迁移为 victimsMap，以适应 Extender 接口。
    // 仅适用于有唯一提名 node 名称的 candidate 列表。
    victimsMap := ev.CandidatesToVictimsMap(candidates)
    if len(victimsMap) == 0 {
        return candidates, nil
    }
    for _, extender := range extenders {
        if !extender.SupportsPreemption() || !extender.IsInterested(pod) {  // 如果 extender 不支持抢占或不关心该 pod，则跳过该 extender
            continue
        }
        nodeNameToVictims, err := extender.ProcessPreemption(pod, victimsMap, nodeLister)  // 调用 extender 的 ProcessPreemption 方法
        if err != nil {
            if extender.IsIgnorable() {  // 如果 extender 可以被忽略，则忽略该 extender 并继续执行其他 extender
                logger.Info("Skipped extender as it returned error and has ignorable flag set",
                    "extender", extender.Name(), "err", err)
                continue
            }
            return nil, framework.AsStatus(err)
        }
        // 检查返回的 victims 是否有效
        for nodeName, victims := range nodeNameToVictims {
            if victims == nil || len(victims.Pods) == 0 {
                if extender.IsIgnorable() {
                    delete(nodeNameToVictims, nodeName)
                    logger.Info("Ignored node for which the extender didn't report victims", "node", klog.KRef("", nodeName), "extender", extender.Name())
                    continue
                }
                return nil, framework.AsStatus(fmt.Errorf("expected at least one victim pod on node %q", nodeName))
			}
		}
        
        // 在抢占之后，用新的结果替换 victimsMap。这样，其他 extender 可以继续使用它作为参数。
		victimsMap = nodeNameToVictims

		// 如果 nodeNameToVictims 的长度为零，则没有可供抢占的节点，不需要在其他 Extender 中进行预处理了，跳出循环
		if len(victimsMap) == 0 {
			break
		}
	}
	
	// 根据 victimsMap 的键生成新的 Candidate 数组 newCandidates，其中每个节点对应一个 Candidate。
	var newCandidates []Candidate
	for nodeName := range victimsMap {
		newCandidates = append(newCandidates, &candidate{
			victims: victimsMap[nodeName],
			name:    nodeName,
		})
	}
	return newCandidates, nil
}
```

##### SelectCandidate

```GO
// SelectCandidate函数从给定的<candidates>中选择最佳候选项并返回它。
// 注意：这个方法是为了在默认预先调度中进行更容易的测试而导出的。
func (ev *Evaluator) SelectCandidate(logger klog.Logger, candidates []Candidate) Candidate {
    if len(candidates) == 0 {
    	return nil
    }
    if len(candidates) == 1 {
    	return candidates[0]
    }
    victimsMap := ev.CandidatesToVictimsMap(candidates)
    candidateNode := pickOneNodeForPreemption(logger, victimsMap)

    // 与candidatesToVictimsMap相同，这个逻辑对于在同一被提名节点上执行不同的候选者的out-of-tree预先调度插件是不适用的。
    if victims := victimsMap[candidateNode]; victims != nil {
        return &candidate{
            victims: victims,
            name:    candidateNode,
        }
    }

    // 我们不应该走到这里。
    logger.Error(errors.New("no candidate selected"), "Should not reach here", "candidates", candidates)
    // 为了不打断整个流程，返回第一个候选者。
    return candidates[0]
}
```

###### pickOneNodeForPreemption

```GO
// pickOneNodeForPreemption 从给定的节点中选择一个节点。它假定每个 map 条目中的 pod 按优先级降序排序。
// 它根据以下标准选择节点：
// 1. 具有最小数量 PDB 违规的节点。
// 2. 选择最小的最高优先级受害者节点。
// 3. 如果出现平局，则按所有受害者优先级之和进行分数排序。
// 4. 如果仍存在平局，则选择受害者最小数量的节点。
// 5. 如果仍存在平局，则选择最高优先级受害者中最新的启动时间节点。
// 6. 如果仍存在平局，则选择第一个节点（有点随机）。
// 'minNodes1' 和 'minNodes2' 在此处被重用以节省内存分配和垃圾收集时间。
func pickOneNodeForPreemption(logger klog.Logger, nodesToVictims map[string]*extenderv1.Victims) string {
    // 如果节点映射为空，则返回空字符串。
    if len(nodesToVictims) == 0 {
    	return ""
    }
    // 生成包含所有节点名称的切片。
    allCandidates := make([]string, 0, len(nodesToVictims))
    for node := range nodesToVictims {
        allCandidates = append(allCandidates, node)
    }

    // 定义函数以根据不同的标准对节点进行打分。
    // 每个函数将节点名称作为参数，并返回一个表示该节点得分的 int64 类型值。
    // 在所有函数中，值越小则分数越高。
    minNumPDBViolatingScoreFunc := func(node string) int64 {
        // NumPDBViolations 越小，则得分越高。
        return -nodesToVictims[node].NumPDBViolations
    }
    minHighestPriorityScoreFunc := func(node string) int64 {
        // highestPodPriority 是该节点上所有受害者中的最高优先级。
        highestPodPriority := corev1helpers.PodPriority(nodesToVictims[node].Pods[0])
        // highestPodPriority 越小，则得分越高。
        return -int64(highestPodPriority)
    }
    minSumPrioritiesScoreFunc := func(node string) int64 {
        var sumPriorities int64
        for _, pod := range nodesToVictims[node].Pods {
            // 我们将 MaxInt32+1 添加到所有优先级中，以使它们都 >= 0。
            // 这是必需的，以便不会选择具有一些负优先级的少数 pod 的节点，
            // 而是选择具有同样数量的具有相同负优先级的较小的 pod 数量的节点（类似的情况）。
            sumPriorities += int64(corev1helpers.PodPriority(pod)) + int64(math.MaxInt32+1)
        }
        // sumPriorities 越小，则得分越高。
        return -sumPriorities
    }
    // 定义函数minNumPodsScoreFunc，用于计算每个节点的得分。
    minNumPodsScoreFunc := func(node string) int64 {
        // 节点上的Pod数量越小，得分越高。
        return -int64(len(nodesToVictims[node].Pods))
    }

    // 定义函数latestStartTimeScoreFunc，用于计算每个节点的得分。
    latestStartTimeScoreFunc := func(node string) int64 {
        // 获取当前节点上所有Pod中最早的启动时间。
        earliestStartTimeOnNode := util.GetEarliestPodStartTime(nodesToVictims[node])
        // 如果最早的启动时间为nil，则返回一个非常小的负数。
        if earliestStartTimeOnNode == nil {
            logger.Error(errors.New("earliestStartTime is nil for node"), "Should not reach here", "node", node)
            return int64(math.MinInt64)
        }
        // 否则，返回最早的启动时间的UnixNano值，这个值越大，得分越高。
        return earliestStartTimeOnNode.UnixNano()
    }

    // 定义了一组函数，用于计算每个节点的得分。
    scoreFuncs := []func(string) int64{
        // 对于违反最小数量PDB的节点，优先选择。
        minNumPDBViolatingScoreFunc,
        // 对于具有最小最高优先级受害者的节点，优先选择。
        minHighestPriorityScoreFunc,
        // 对于具有最小优先级总和的节点，优先选择。
        minSumPrioritiesScoreFunc,
        // 对于具有最小Pod数量的节点，优先选择。
        minNumPodsScoreFunc,
        // 对于具有最晚最高优先级受害者的节点，优先选择。
        latestStartTimeScoreFunc,
        // 如果还存在并列的节点，则按照此顺序执行其他scoreFunc函数。
    }

    // 遍历每个函数，并计算每个节点的得分。
    for _, f := range scoreFuncs {
        // 用于存储得分最高的节点。
        selectedNodes := []string{}
        // 初始化得分为一个极小值。
        maxScore := int64(math.MinInt64)
        // 遍历所有候选节点。
        for _, node := range allCandidates {
            // 调用当前函数计算节点得分。
            score := f(node)
            // 如果得分比之前的得分更高，则更新得分和得分最高的节点。
            if score > maxScore {
                maxScore = score
                selectedNodes = []string{}
            }
            // 如果得分与之前的得分相等，则将当前节点添加到得分最高的节点列表中。
            if score == maxScore {
                selectedNodes = append(selectedNodes, node)
            }
        }
        // 如果只有一个得分最高的节点，则返回该节点。
        if len(selectedNodes) == 1 {
            return selectedNodes[0]
        }
        // 否则，更新候选节点列表。
        allCandidates = selectedNodes
    }

    // 返回所有得分最高的节点中的第一个节点。
    return allCandidates[0]
}
```

###### GetEarliestPodStartTime

```GO
// GetEarliestPodStartTime 函数返回所有受害者中优先级最高的 Pod 的最早开始时间。
func GetEarliestPodStartTime(victims *extenderv1.Victims) *metav1.Time {
    // 如果受害者中没有 Pod，则不应执行到这里。
    if len(victims.Pods) == 0 {
        klog.Background().Error(nil, "victims.Pods is empty. Should not reach here")
        return nil
    }
    // 初始化 earliestPodStartTime 为第一个 Pod 的开始时间，初始化 maxPriority 为第一个 Pod 的优先级。
    earliestPodStartTime := GetPodStartTime(victims.Pods[0])
    maxPriority := corev1helpers.PodPriority(victims.Pods[0])

    // 遍历受害者中的所有 Pod。
    for _, pod := range victims.Pods {
        // 如果当前 Pod 的优先级与最高优先级相同，则比较其开始时间与 earliestPodStartTime，更新 earliestPodStartTime。
        if podPriority := corev1helpers.PodPriority(pod); podPriority == maxPriority {
            if podStartTime := GetPodStartTime(pod); podStartTime.Before(earliestPodStartTime) {
                earliestPodStartTime = podStartTime
            }
        } else if podPriority > maxPriority { // 如果当前 Pod 的优先级高于最高优先级，则更新 maxPriority 和 earliestPodStartTime。
            maxPriority = podPriority
            earliestPodStartTime = GetPodStartTime(pod)
        }
    }

    // 返回最早开始时间。
    return earliestPodStartTime
}
```

###### GetPodStartTime

```GO
//GetPodStartTime返回给定pod的开始时间或当前时间戳
//如果还没有开始的话。
func GetPodStartTime(pod *v1.Pod) *metav1.Time {
	if pod.Status.StartTime != nil {
		return pod.Status.StartTime
	}
	// Assumed pods and bound pods that haven't started don't have a StartTime yet.
	return &metav1.Time{Time: time.Now()}
}
```

##### prepareCandidate

```GO
// prepareCandidate函数在提名被选中的候选节点之前做一些准备工作：
// - 驱逐受害者Pod
// - 如果受害者Pod在waitingPod映射中，则拒绝它们
// - 如有必要清除低优先级Pod的nominatedNodeName状态
func (ev *Evaluator) prepareCandidate(ctx context.Context, c Candidate, pod *v1.Pod, pluginName string) *framework.Status {
    fh := ev.Handler // 获取framework.Handler对象
    cs := ev.Handler.ClientSet() // 获取clientset对象
    ctx, cancel := context.WithCancel(ctx) // 使用WithCancel函数创建一个上下文
    defer cancel()
    logger := klog.FromContext(ctx) // 使用ctx创建一个logger
    errCh := parallelize.NewErrorChannel() // 创建一个用于传递错误的channel

    // 驱逐受害者Pod的函数
    preemptPod := func(index int) {
        victim := c.Victims().Pods[index] // 获取受害者Pod
        // 如果受害者是等待中的Pod，则向PermitPlugin发送拒绝消息。
        // 否则，应该删除受害者。
        if waitingPod := fh.GetWaitingPod(victim.UID); waitingPod != nil {
            waitingPod.Reject(pluginName, "preempted") // 发送reject消息
            klog.V(2).InfoS("Preemptor pod rejected a waiting pod", "preemptor", klog.KObj(pod), "waitingPod", klog.KObj(victim), "node", c.Name()) // 打印日志信息
        } else {
            // 如果PodDisruptionConditions特性被启用，则将disruption target条件添加到受害者Pod的状态中
            if feature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
                victimPodApply := corev1apply.Pod(victim.Name, victim.Namespace).WithStatus(corev1apply.PodStatus()) // 创建一个PodApply对象
                victimPodApply.Status.WithConditions(corev1apply.PodCondition().
                    WithType(v1.DisruptionTarget).
                    WithStatus(v1.ConditionTrue).
                    WithReason(v1.PodReasonPreemptionByScheduler).
                    WithMessage(fmt.Sprintf("%s: preempting to accommodate a higher priority pod", pod.Spec.SchedulerName)).
                    WithLastTransitionTime(metav1.Now()),
                )

                // 使用ApplyStatus函数将更新后的受害者Pod状态应用到集群中
                if _, err := cs.CoreV1().Pods(victim.Namespace).ApplyStatus(ctx, victimPodApply, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
                    logger.Error(err, "Could not add DisruptionTarget condition due to preemption", "pod", klog.KObj(victim), "preemptor", klog.KObj(pod))
                    errCh.SendErrorWithCancel(err, cancel) // 发送错误信息到channel
                    return
                }
            }

            // 删除受害者Pod
            if err := util.DeletePod(ctx, cs, victim); err != nil {
                logger.Error(err, "Preempted pod", "pod", klog.KObj(victim), "preemptor", klog.KObj(pod))
                errCh.SendErrorWithCancel(err, cancel) 
				return
			}
			klog.V(2).InfoS("Preemptor Pod preempted victim Pod", "preemptor", klog.KObj(pod), "victim", klog.KObj(victim), "node", c.Name())
		}

		fh.EventRecorder().Eventf(victim, pod, v1.EventTypeNormal, "Preempted", "Preempting", "Preempted by a pod on node %v", c.Name())
	}
    
    // 使用fh.Parallelizer()函数来并行处理被选中的候选人的受害者pods
    // 在上下文ctx中，直到处理完所有的受害者pod，才会执行preemptPod函数
    // ev.PluginName作为参数传递给preemptPod函数
    fh.Parallelizer().Until(ctx, len(c.Victims().Pods), preemptPod, ev.PluginName)
    // 从error channel errCh中接收错误，如果有错误，则将其转换为framework.Status并返回
	if err := errCh.ReceiveError(); err != nil {
		return framework.AsStatus(err)
	}

	metrics.PreemptionVictims.Observe(float64(len(c.Victims().Pods)))

	// 获取在本节点上被指定的低优先级pod的列表
	nominatedPods := getLowerPriorityNominatedPods(logger, fh, pod, c.Name())
	if err := util.ClearNominatedNodeName(ctx, cs, nominatedPods...); err != nil {
		logger.Error(err, "Cannot clear 'NominatedNodeName' field")
		// 这个错误不是致命的，所以不返回
	}

	return nil
}
```

###### DeletePod

```GO
func DeletePod(ctx context.Context, cs kubernetes.Interface, pod *v1.Pod) error {
	return cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
}
```

###### getLowerPriorityNominatedPods

```GO
// getLowerPriorityNominatedPods 返回在给定节点上被提名的优先级小于给定 Pod 的所有 Pod。
// 注意：我们可能会检查被提名的低优先级 Pod 是否仍适合，然后返回那些不再适合的 Pod，但这需要大量的 NodeInfo 和 PreFilter 状态的操作。这可能不值得复杂性，特别是因为我们通常希望每个节点上被提名的 Pod 的数量非常少。
func getLowerPriorityNominatedPods(logger klog.Logger, pn framework.PodNominator, pod *v1.Pod, nodeName string) []*v1.Pod {
	// 获取在给定节点上被提名的 Pod 的信息。
	podInfos := pn.NominatedPodsForNode(nodeName)

	if len(podInfos) == 0 {
		return nil
	}

	// 存储低于给定 Pod 优先级的 Pod。
	var lowerPriorityPods []*v1.Pod
	podPriority := corev1helpers.PodPriority(pod)
	for _, pi := range podInfos {
		if corev1helpers.PodPriority(pi.Pod) < podPriority {
			lowerPriorityPods = append(lowerPriorityPods, pi.Pod)
		}
	}
	return lowerPriorityPods
}
```

###### getLowerPriorityNominatedPods

```GO
// ClearNominatedNodeName 函数将会提交一个更新请求到 API server，以将每个 pod 的 .Status.NominatedNodeName 字段设置为空字符串。
func ClearNominatedNodeName(ctx context.Context, cs kubernetes.Interface, pods ...*v1.Pod) utilerrors.Aggregate {
    var errs []error
    for _, p := range pods {
        if len(p.Status.NominatedNodeName) == 0 {
        	continue
        }
        // 复制 pod 的状态并将 NominatedNodeName 字段设置为空字符串。
        podStatusCopy := p.Status.DeepCopy()
        podStatusCopy.NominatedNodeName = ""
        // 提交更新请求
        if err := PatchPodStatus(ctx, cs, p, podStatusCopy); err != nil {
        	errs = append(errs, err)
        }
    }
    // 返回可能发生的错误
    return utilerrors.NewAggregate(errs)
}
```

## DynamicResources

### 作用

Kubernetes调度器中的DynamicResources插件是一个扩展插件，它允许用户定义自己的资源类型，并将它们添加到Kubernetes调度器中以进行调度决策。

使用DynamicResources插件，用户可以定义自己的资源类型，比如“GPU”、“FPGA”或其他非标准资源。用户可以将这些资源类型与节点上的实际资源相关联，例如在节点上安装了GPU卡，然后在Kubernetes中定义一个新的资源类型“gpu”，并将它与该节点上的GPU卡相关联。

调度器使用DynamicResources插件时，会将节点的资源和任务的资源要求与用户定义的资源类型进行匹配。如果节点有足够的特定资源类型，则调度器将任务调度到该节点上。

### 结构

```go
// 定义了插件名称常量 "Name"，以及 "stateKey" 常量，用于在框架中标识插件状态。
const (
	Name = names.DynamicResources // 在 Registry 和配置中使用的插件名称。
	stateKey framework.StateKey = Name // 用于在框架中标识插件状态。
)

// dynamicResources 是一个插件，用于确保 ResourceClaims 被分配。
type dynamicResources struct {
	enabled                    bool // 是否启用该插件的标志。
	clientset                  kubernetes.Interface // Kubernetes 客户端接口。
	claimLister                resourcev1alpha2listers.ResourceClaimLister // ResourceClaim 的 ListWatcher。
	classLister                resourcev1alpha2listers.ResourceClassLister // ResourceClass 的 ListWatcher。
	podSchedulingContextLister resourcev1alpha2listers.PodSchedulingContextLister // PodSchedulingContext 的 ListWatcher。
}

// New 初始化一个新的插件并返回它。
func New(plArgs runtime.Object, fh framework.Handle, fts feature.Features) (framework.Plugin, error) {
	if !fts.EnableDynamicResourceAllocation {
		// 动态资源分配已禁用，该插件不会执行任何操作。
		return &dynamicResources{}, nil
	}

	return &dynamicResources{
		enabled:                    true, // 启用该插件。
		clientset:                  fh.ClientSet(), // 获取 Kubernetes 客户端接口。
		claimLister:                fh.SharedInformerFactory().Resource().V1alpha2().ResourceClaims().Lister(), // 获取 ResourceClaim 的 ListWatcher。
		classLister:                fh.SharedInformerFactory().Resource().V1alpha2().ResourceClasses().Lister(), // 获取 ResourceClass 的 ListWatcher。
		podSchedulingContextLister: fh.SharedInformerFactory().Resource().V1alpha2().PodSchedulingContexts().Lister(), // 获取 PodSchedulingContext 的 ListWatcher。
	}, nil
}

// dynamicResources 实现了以下接口：
var _ framework.PreFilterPlugin = &dynamicResources{}
var _ framework.FilterPlugin = &dynamicResources{}
var _ framework.PostFilterPlugin = &dynamicResources{}
var _ framework.PreScorePlugin = &dynamicResources{}
var _ framework.ReservePlugin = &dynamicResources{}
var _ framework.EnqueueExtensions = &dynamicResources{}
var _ framework.PostBindPlugin = &dynamicResources{}

// Name 返回插件名称，用于日志等。
func (pl *dynamicResources) Name() string {
	return Name
}
```

### stateData

```GO
// 状态在 PreFilter 阶段进行初始化。因为我们将指针保存在 framework.CycleState 中，所以在后面的阶段中我们不需要调用 Write 方法来更新值。
type stateData struct {
    // Pod 的所有 claims 的副本（即与 pod.Spec.ResourceClaims 一一匹配），最初具有从调度周期开始的状态。
    // 每个 claim 实例都是只读的，因为它可能来自 informer cache。当插件本身成功进行更新时，这些实例将被替换。
    //
    // 如果 Pod 没有 claims，则为空。
    claims []*resourcev1alpha2.ResourceClaim
    // 将 v1 API 转换为 nodeaffinity.NodeSelector 的 claims 的 AvailableOnNodes 节点过滤器，
    // 由 PreFilter 转换，用于在 Filter 中进行重复评估。对于没有它的 claims，为 nil。
    availableOnNodes []*nodeaffinity.NodeSelector

    // 所有 claim 的索引：
    // - 被分配
    // - 使用延迟分配
    // - 在至少一个节点上不可用
    //
    // 在 Filter 中并行设置，因此写访问必须由互斥锁保护。由 PostFilter 使用。
    unavailableClaims sets.Int

    // 如果存在，则指向 PodSchedulingContext 对象的指针。
    // 在需要时设置。
    //
    // 从概念上讲，这个对象属于调度器框架，它可能会被不同的插件共享。但在实践中，
    // 它目前只被动态分配使用，因此在此处完全管理。
    schedulingCtx *resourcev1alpha2.PodSchedulingContext

    // 如果当前副本被本地修改，则 podSchedulingDirty 为 true。
    podSchedulingDirty bool

    mutex sync.Mutex
}
```

#### Clone

```GO
func (d *stateData) Clone() framework.StateData {
	return d
}
```

#### updateClaimStatus

```GO
func (d *stateData) updateClaimStatus(ctx context.Context, clientset kubernetes.Interface, index int, claim *resourcev1alpha2.ResourceClaim) error {
    // TODO (#113700): 用 patch 操作替换。要注意，只有在没有被其他人并行修改的情况下才能成功打补丁。
    claim, err := clientset.ResourceV1alpha2().ResourceClaims(claim.Namespace).UpdateStatus(ctx, claim, metav1.UpdateOptions{})
    // TODO: 更新结果的度量，操作（“设置选择的节点”，“设置 PotentialNodes”等）作为一个维度。
    if err != nil {
    	return fmt.Errorf("update resource claim: %w", err)
    }
    // 记住新实例。这在插件必须多次更新同一个 claim 时很重要
    // （例如，首先保留 claim，然后稍后删除保留），否则第二次更新会失败，并显示“已修改”的错误。
    d.claims[index] = claim

    return nil
}
```

#### initializePodSchedulingContexts

```GO
// initializePodSchedulingContext 可以并发调用。如果已存在 PodSchedulingContext 对象，则返回该对象，
// 如果不存在，则检索一个，或者作为最后一手段从头开始创建一个。
func (d *stateData) initializePodSchedulingContexts(ctx context.Context, pod *v1.Pod, podSchedulingContextLister resourcev1alpha2listers.PodSchedulingContextLister) (*resourcev1alpha2.PodSchedulingContext, error) {
    // TODO (#113701): 检查是否可以通过在 PreFilter 期间调用 initializePodSchedulingContext 来避免此互斥锁锁定。
    d.mutex.Lock()
    defer d.mutex.Unlock()
    if d.schedulingCtx != nil {
        return d.schedulingCtx, nil
    }

    schedulingCtx, err := podSchedulingContextLister.PodSchedulingContexts(pod.Namespace).Get(pod.Name)
    switch {
    case apierrors.IsNotFound(err):
        controller := true
        schedulingCtx = &resourcev1alpha2.PodSchedulingContext{
            ObjectMeta: metav1.ObjectMeta{
                Name:      pod.Name,
                Namespace: pod.Namespace,
                OwnerReferences: []metav1.OwnerReference{
                    {
                        APIVersion: "v1",
                        Kind:       "Pod",
                        Name:       pod.Name,
                        UID:        pod.UID,
                        Controller: &controller,
                    },
                },
            },
        }
        err = nil
    case err != nil:
        return nil, err
    default:
        // 我们有一个对象，但它可能已经过时。
        if !metav1.IsControlledBy(schedulingCtx, pod) {
            return nil, fmt.Errorf("PodSchedulingContext 对象的 UID %s 不属于 Pod %s/%s", schedulingCtx.UID, pod.Namespace, pod.Name)
        }
    }
    d.schedulingCtx = schedulingCtx
    return schedulingCtx, err
}
```

#### publishPodSchedulingContexts

```GO
// publishPodSchedulingContext创建或更新PodSchedulingContext对象。
func (d *stateData) publishPodSchedulingContexts(ctx context.Context, clientset kubernetes.Interface, schedulingCtx *resourcev1alpha2.PodSchedulingContext) error {
    d.mutex.Lock() // 获取锁，以防止多个goroutine同时修改状态
    defer d.mutex.Unlock() // 解锁
    var err error
    logger := klog.FromContext(ctx)
    msg := "更新PodSchedulingContext"
    if schedulingCtx.UID == "" {
        msg = "创建PodSchedulingContext"
    }
    if loggerV := logger.V(6); loggerV.Enabled() {
        // 在高日志级别下，转储整个对象
        loggerV.Info(msg, "podSchedulingCtxDump", schedulingCtx)
    } else {
        logger.V(5).Info(msg, "podSchedulingCtx", klog.KObj(schedulingCtx))
    }
    if schedulingCtx.UID == "" {
        // 如果UID为空，则创建新的PodSchedulingContext对象
        schedulingCtx, err = clientset.ResourceV1alpha2().PodSchedulingContexts(schedulingCtx.Namespace).Create(ctx, schedulingCtx, metav1.CreateOptions{})
    } else {
        // 否则，更新现有的对象
        // TODO (#113700): 在此处打补丁，以避免与更新状态的驱动程序竞争。
        schedulingCtx, err = clientset.ResourceV1alpha2().PodSchedulingContexts(schedulingCtx.Namespace).Update(ctx, schedulingCtx, metav1.UpdateOptions{})
    }
    if err != nil {
        return err
    }
    d.schedulingCtx = schedulingCtx // 更新内部状态中的schedulingCtx
    d.podSchedulingDirty = false // 将podSchedulingDirty标记为“false”，表示已完成更新
    return nil
}
```

#### storePodSchedulingContexts

```GO
// storePodSchedulingContext将pod schedulingCtx对象替换为状态中的对象。
func (d *stateData) storePodSchedulingContexts(schedulingCtx *resourcev1alpha2.PodSchedulingContext) {
    d.mutex.Lock() // 获取锁，以防止多个goroutine同时修改状态
    defer d.mutex.Unlock() // 解锁
    d.schedulingCtx = schedulingCtx // 将传入的schedulingCtx对象存储到内部状态中的schedulingCtx
	d.podSchedulingDirty = true // 将podSchedulingDirty标记为“true”，表示状态已更改
}
```

### PreFilter&PreFilterExtensions

```GO
// PreFilter 在前置过滤器扩展点上调用以检查 pod 是否具有所有立即需求资源。
// 如果 pod 无法在任何节点上立即被调度，将返回 UnschedulableAndUnresolvable。
func (pl *dynamicResources) PreFilter(ctx context.Context, state *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
	if !pl.enabled {
		return nil, nil
	}
	logger := klog.FromContext(ctx)

	// 如果 pod 不引用任何 claim，我们不需要为其进行任何操作。
	// 我们只需初始化一个空状态以记录其他函数的观察结果。如果我们到达那里，这将在下面更新。
	s := &stateData{}
	state.Write(stateKey, s)

	claims, err := pl.podResourceClaims(pod)
	if err != nil {
		return nil, statusUnschedulable(logger, err.Error())
	}
	logger.V(5).Info("pod resource claims", "pod", klog.KObj(pod), "resourceclaims", klog.KObjSlice(claims))
	// 如果 pod 不引用任何 claim，我们不需要为其进行任何操作。
	if len(claims) == 0 {
		return nil, nil
	}

	// 为每个 claim 记录其可用的节点
	s.availableOnNodes = make([]*nodeaffinity.NodeSelector, len(claims))
	for index, claim := range claims {
		// 如果 claim 的分配模式是 Immediate，且状态中没有分配，那么将返回 UnschedulableAndUnresolvable。
		if claim.Spec.AllocationMode == resourcev1alpha2.AllocationModeImmediate &&
			claim.Status.Allocation == nil {
			// 这将由资源驱动程序解决。
			return nil, statusUnschedulable(logger, "unallocated immediate resourceclaim", "pod", klog.KObj(pod), "resourceclaim", klog.KObj(claim))
		}
		// 如果资源请求已经被回收，那么将返回 UnschedulableAndUnresolvable。
		if claim.Status.DeallocationRequested {
			// 这将由资源驱动程序解决。
			return nil, statusUnschedulable(logger, "resourceclaim must be reallocated", "pod", klog.KObj(pod), "resourceclaim", klog.KObj(claim))
		}
		// 如果资源正在被使用，那么将返回 UnschedulableAndUnresolvable。
		if claim.Status.Allocation != nil &&
			!resourceclaim.CanBeReserved(claim) &&
			!resourceclaim.IsReservedForPod(pod, claim) {
			// 资源正在使用中，Pod 必须等待。
			return nil, statusUnschedulable(logger, "resourceclaim in use", "pod", klog.KObj(pod), "resourceclaim", klog.KObj(claim))
		}
		// 如果资源请求已经被分配，且它可用的节点不为空，那么将为其创建一个 node selector。
		if claim.Status.Allocation != nil &&
			claim.Status.Allocation.AvailableOnNodes != nil {
			nodeSelector, err := nodeaffinity.NewNodeSelector(claim.Status.Allocation.AvailableOnNodes)
			if err != nil {
				return nil, statusError(logger, err)
			}
            // 设置当前资源可用的节点
			s.availableOnNodes[index] = nodeSelector
		}
	}
	// 将所有资源的状态信息写入状态循环中
	s.claims = claims
	state.Write(stateKey, s)
	return nil, nil
}

// PreFilterExtensions方法用于返回pod添加和删除的前置过滤器扩展
func (pl *dynamicResources) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

#### podResourceClaims

```GO
// podResourceClaims 函数返回 pod.Spec.ResourceClaims 中所有的 ResourceClaim。
func (pl *dynamicResources) podResourceClaims(pod *v1.Pod) ([]*resourcev1alpha2.ResourceClaim, error) {
	claims := make([]*resourcev1alpha2.ResourceClaim, 0, len(pod.Spec.ResourceClaims))
    // 对于每个 pod.Spec.ResourceClaims，获取相应的 ResourceClaim。
    for _, resource := range pod.Spec.ResourceClaims {
        claimName := resourceclaim.Name(pod, &resource) // 从 pod 和 resource 中获取 ResourceClaim 的名称
        isEphemeral := resource.Source.ResourceClaimTemplateName != nil // 判断是否为临时资源声明
        claim, err := pl.claimLister.ResourceClaims(pod.Namespace).Get(claimName) // 获取 ResourceClaim
        if err != nil {
            // 错误通常已经有足够的上下文（如“resourcevolumeclaim”myclaim“未找到”），
            // 但是对于常规的临时内联卷，在创建 Pod 之后直接出现这种情况是正常的，
            // 我们可以提供更好的上下文信息。
            if isEphemeral && apierrors.IsNotFound(err) {
                err = fmt.Errorf("等待动态资源控制器创建资源声明 %q", claimName)
            }
            return nil, err
        }

        if claim.DeletionTimestamp != nil { // 如果该资源正在被删除，则报错
            return nil, fmt.Errorf("资源声明 %q 正在被删除", claim.Name)
        }

        if isEphemeral { // 对于临时资源声明，需要检查是否是为当前 Pod 创建的
            if err := resourceclaim.IsForPod(pod, claim); err != nil {
                return nil, err
            }
        }
        // 将 ResourceClaim 的指针添加到 claims 列表中。假设如果在我们的代码运行时修改了声明，则缓存将存储一个新的指针，而不会更改此处引用的现有对象。
        claims = append(claims, claim)
    }
    return claims, nil
}
```

#### statusUnschedulable

```GO
// statusUnschedulable 确保与状态相关的日志消息存在于对应的代码行。
func statusUnschedulable(logger klog.Logger, reason string, kv ...interface{}) *framework.Status {
    // 如果 logger 的 verbosity level 大于等于 5，则记录调用堆栈信息。
    if loggerV := logger.V(5); loggerV.Enabled() {
        helper, loggerV := loggerV.WithCallStackHelper()
        helper()
        kv = append(kv, "reason", reason)
        // nolint: logcheck // warns because it cannot check key/values
        // 使用 loggerV 记录日志，附加 kv 里面的键值对。
        loggerV.Info("pod unschedulable", kv...)
    }
    // 返回一个 framework.Status 实例，代表 pod 无法调度。
    return framework.NewStatus(framework.UnschedulableAndUnresolvable, reason)
}
```

### Filter

```GO
// 在过滤器扩展点处调用的过滤器。
// 它评估一个 pod 是否可以适应由其请求的资源，
// 对于已分配和未分配的要求都适用。
//
// 对于已绑定的要求，它检查节点亲和性是否由给定节点满足。
//
// 对于未绑定的要求，它检查是否可以为节点分配要求。
func (pl *dynamicResources) Filter(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 如果没有启用动态资源分配，则直接返回。
    if !pl.enabled {
    	return nil
    }
    // 从 CycleState 中获取状态数据。
    state, err := getStateData(cs)
    if err != nil {
    	return statusError(klog.FromContext(ctx), err)
    }
    // 如果没有资源请求，则直接返回。
    if len(state.claims) == 0 {
    	return nil
    }
    logger := klog.FromContext(ctx)
    node := nodeInfo.Node()

    var unavailableClaims []int
    for index, claim := range state.claims {
        // 根据 pod 的资源请求进行过滤。
        logger.V(10).Info("filtering based on resource claims of the pod", "pod", klog.KObj(pod), "node", klog.KObj(node), "resourceclaim", klog.KObj(claim))
        switch {
        // 如果资源请求已经分配，则检查节点亲和性是否满足要求。
        case claim.Status.Allocation != nil:
            if nodeSelector := state.availableOnNodes[index]; nodeSelector != nil {
                if !nodeSelector.Match(node) {
                    logger.V(5).Info("AvailableOnNodes does not match", "pod", klog.KObj(pod), "node", klog.KObj(node), "resourceclaim", klog.KObj(claim))
                    unavailableClaims = append(unavailableClaims, index)
                }
            }
        // 如果资源请求已经申请解绑，则直接返回错误信息。
        case claim.Status.DeallocationRequested:
            // We shouldn't get here. PreFilter already checked this.
            return statusUnschedulable(logger, "resourceclaim must be reallocated", "pod", klog.KObj(pod), "node", klog.KObj(node), "resourceclaim", klog.KObj(claim))
        // 如果资源请求还没有分配，则需要进行资源的分配。
        case claim.Spec.AllocationMode == resourcev1alpha2.AllocationModeWaitForFirstConsumer:
            // The ResourceClass might have a node filter. This is
            // useful for trimming the initial set of potential
            // nodes before we ask the driver(s) for information
            // about the specific pod.
            // 如果资源请求对应的 ResourceClass 有节点筛选器，则对节点进行筛选。
            class, err := pl.classLister.Get(claim.Spec.ResourceClassName)
            if err != nil {
                // If the class does not exist, then allocation cannot proceed.
                return statusError(logger, fmt.Errorf("look up resource class: %v", err))
            }
            if class.SuitableNodes != nil {
				// TODO (#113700): 在PreFilter中一次解析class.SuitableNodes，重复使用结果。
				matches, err := corev1helpers.MatchNodeSelectorTerms(node, class.SuitableNodes)
				if err != nil {
					return statusError(logger, fmt.Errorf("potential node filter: %v", err))
				}
				if !matches {
					return statusUnschedulable(logger, "excluded by resource class node filter", "pod", klog.KObj(pod), "node", klog.KObj(node), "resourceclass", klog.KObj(class))
				}
			}

			// 现在我们需要来自驱动程序的信息。
			schedulingCtx, err := state.initializePodSchedulingContexts(ctx, pod, pl.podSchedulingContextLister)
			if err != nil {
				return statusError(logger, err)
			}
			status := statusForClaim(schedulingCtx, pod.Spec.ResourceClaims[index].Name)
			if status != nil {
				for _, unsuitableNode := range status.UnsuitableNodes {
					if node.Name == unsuitableNode {
						return statusUnschedulable(logger, "resourceclaim cannot be allocated for the node (unsuitable)", "pod", klog.KObj(pod), "node", klog.KObj(node), "resourceclaim", klog.KObj(claim), "unsuitablenodes", status.UnsuitableNodes)
					}
				}
			}
		default:
			// 这应该已经延迟分配。在PreFilter中已经检查了立即分配。
			return statusError(logger, fmt.Errorf("internal error, unexpected allocation mode %v", claim.Spec.AllocationMode))
		}
	}

	if len(unavailableClaims) > 0 {
		state.mutex.Lock()
		defer state.mutex.Unlock()
		if state.unavailableClaims == nil {
			state.unavailableClaims = sets.NewInt()
		}

		for index := range unavailableClaims {
			claim := state.claims[index]
			// 对于延迟分配的索赔来说，解除分配更有意义。
            // 立即分配的索赔会被分配到另一个随机节点，
            // 这不太可能帮助Pod。
			if claim.Spec.AllocationMode == resourcev1alpha2.AllocationModeWaitForFirstConsumer {
				state.unavailableClaims.Insert(unavailableClaims...)
			}
		}
		return statusUnschedulable(logger, "resourceclaim not available on the node", "pod", klog.KObj(pod))
	}

	return nil
}
```

#### getStateData

```GO
// getStateData返回状态数据指针。
func getStateData(cs *framework.CycleState) (*stateData, error) {
    state, err := cs.Read(stateKey) // 从循环状态中读取状态
    if err != nil {
    	return nil, err // 如果出现错误，则返回错误
    }
    s, ok := state.(*stateData) // 将状态转换为stateData类型
    if !ok {
    	return nil, errors.New("无法将状态转换为stateData") // 如果转换失败，则返回错误
    }
    return s, nil // 返回stateData指针
}
```

##### Read

```GO
// Read 从 CycleState 中检索具有给定“key”的数据。如果没有找到 key，将返回错误。
// 此函数通过使用 sync.Map 实现线程安全。
func (c *CycleState) Read(key StateKey) (StateData, error) {
	if v, ok := c.storage.Load(key); ok { // 使用 Load 方法获取指定 key 的值，ok 表示是否找到
		return v.(StateData), nil // 将值断言为 StateData 并返回
	}
	return nil, ErrNotFound // 没有找到指定 key，返回 ErrNotFound 错误
}
```

#### statusError

```GO
// statusError 确保有与错误发生的行相关联的日志消息。
func statusError(logger klog.Logger, err error, kv ...interface{}) *framework.Status {
	if loggerV := logger.V(5); loggerV.Enabled() { // 判断是否需要记录日志
		helper, loggerV := loggerV.WithCallStackHelper()
		helper() // 记录调用堆栈
		// nolint: logcheck // warns because it cannot check key/values
		loggerV.Error(err, "dynamic resource plugin failed", kv...) // 记录错误日志
	}
	return framework.AsStatus(err) // 返回错误信息
}
```

#### statusForClaim

```GO
// statusForClaim 用于获取 podClaimName 对应的 ResourceClaimSchedulingStatus。
func statusForClaim(schedulingCtx *resourcev1alpha2.PodSchedulingContext, podClaimName string) *resourcev1alpha2.ResourceClaimSchedulingStatus {
	for _, status := range schedulingCtx.Status.ResourceClaims { // 遍历 PodSchedulingContext 中的所有 ResourceClaimSchedulingStatus
		if status.Name == podClaimName { // 找到对应的 ResourceClaimSchedulingStatus
			return &status // 返回该 ResourceClaimSchedulingStatus
		}
	}
	return nil // 没有找到对应的 ResourceClaimSchedulingStatus，返回 nil
}
```

### PostFilter

```GO
// PostFilter检查是否有已分配的资源声明可以被取消分配以帮助将Pod调度。 如果是，它会选择一个并请求取消分配。
// 仅当筛选找不到合适的节点时才会调用此函数。
func (pl *dynamicResources) PostFilter(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, filteredNodeStatusMap framework.NodeToStatusMap) (*framework.PostFilterResult, *framework.Status) {
    if !pl.enabled { // 如果插件已禁用，则返回插件禁用的状态
    	return nil, framework.NewStatus(framework.Unschedulable, "plugin disabled")
    }
    logger := klog.FromContext(ctx) // 使用日志记录器从上下文中获取一个记录器
    // 从循环状态中获取状态数据
    state, err := getStateData(cs)
    if err != nil {
        return nil, statusError(logger, err) // 返回状态错误
    }

    if len(state.claims) == 0 { // 如果没有新的声明需要取消分配，则返回无法调度状态
        return nil, framework.NewStatus(framework.Unschedulable, "no new claims to deallocate")
    }

    // 遍历声明映射的不可用声明，以随机选择一个声明
    for index := range state.unavailableClaims {
        claim := state.claims[index] // 获取声明
        if len(claim.Status.ReservedFor) == 0 || // 如果声明没有保留的Pod或Pod与声明的UID相同，则选择声明
            len(claim.Status.ReservedFor) == 1 && claim.Status.ReservedFor[0].UID == pod.UID {
            claim := state.claims[index].DeepCopy() // 复制声明
            claim.Status.DeallocationRequested = true // 请求取消分配
            claim.Status.ReservedFor = nil // 取消保留
            logger.V(5).Info("Requesting deallocation of ResourceClaim", "pod", klog.KObj(pod), "resourceclaim", klog.KObj(claim)) // 记录取消分配的请求
            if err := state.updateClaimStatus(ctx, pl.clientset, index, claim); err != nil {
                return nil, statusError(logger, err) // 返回状态错误
            }
            return nil, nil
        }
    }
    return nil, framework.NewStatus(framework.Unschedulable, "still not schedulable") // 如果没有可用的声明，则返回无法调度状态
}
```



```GO
// PreScore 接收一个包含所有适合该 Pod 的节点列表。并不是所有的 ResourceClaim 都被分配，所以在这里我们可以为那些未分配的资源声明 SuitableNodes 字段。
func (pl *dynamicResources) PreScore(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
    // 如果插件未启用，则返回 nil。
    if !pl.enabled {
    	return nil
    }
    // 获取当前状态。
    state, err := getStateData(cs)
    if err != nil {
    	return statusError(klog.FromContext(ctx), err)
    }
    // 如果没有 ResourceClaim，则返回 nil。
    if len(state.claims) == 0 {
    	return nil
    }
    logger := klog.FromContext(ctx)
    // 初始化 Pod 调度上下文，这个上下文将用于将 Pod 分配到节点上。
    schedulingCtx, err := state.initializePodSchedulingContexts(ctx, pod, pl.podSchedulingContextLister)
    if err != nil {
        return statusError(logger, err)
    }
    // 是否有未分配的资源。
    pending := false
    for _, claim := range state.claims {
        if claim.Status.Allocation == nil {
            pending = true
        }
    }
    // 如果存在未分配的资源，并且 PotentialNodes 列表不包含所有节点，则执行以下操作。
    if pending && !haveAllNodes(schedulingCtx.Spec.PotentialNodes, nodes) {
        // 记录 PotentialNodes 列表。在 Reserve 方法中将创建或更新该对象。这既是优化，也可以处理 PreScore 方法未在只有一个节点的情况下调用的情况。
        logger.V(5).Info("remembering potential nodes", "pod", klog.KObj(pod), "potentialnodes", klog.KObjSlice(nodes))
        schedulingCtx = schedulingCtx.DeepCopy()
        numNodes := len(nodes)
        if numNodes > resourcev1alpha2.PodSchedulingNodeListMaxSize {
            numNodes = resourcev1alpha2.PodSchedulingNodeListMaxSize
        }
        schedulingCtx.Spec.PotentialNodes = make([]string, 0, numNodes)
        if numNodes == len(nodes) {
            // 复制所有节点名称。
            for _, node := range nodes {
                schedulingCtx.Spec.PotentialNodes = append(schedulingCtx.Spec.PotentialNodes, node.Name)
            }
        } else {
            // 随机选择节点的一个子集，以符合 PotentialNodes 长度限制。随机化由 Go 为我们完成，它随机地遍历 map 条目。
            nodeNames := map[string]struct{}{}
            for _, node := range nodes {
                nodeNames[node.Name] = struct{}{}
            }
            for nodeName := range nodeNames {
                if len(schedulingCtx.Spec.PotentialNodes) >= resourcev1alpha2.PodSchedulingNodeListMaxSize {
                    break
                }
                schedulingCtx.Spec.PotentialNodes = append(schedulingCtx.Spec.PotentialNodes, nodeName)
            }
        }
        sort.Strings(schedulingCtx.Spec.PotentialNodes)
        state.storePodSchedulingContexts(schedulingCtx)
    }
    // 如果 PotentialNodes 列表已经设置，则直接返回 nil。
    logger.V(5).Info("all potential nodes already set", "pod", klog.KObj(pod), "potentialnodes", nodes)
	return nil
}
```

#### haveAllNodes

```GO
// 判断给定的节点名数组 nodeNames 中是否包含 nodes 中的所有节点，返回布尔值。
func haveAllNodes(nodeNames []string, nodes []*v1.Node) bool {
    // 遍历节点数组 nodes
    for _, node := range nodes {
        // 判断节点名数组 nodeNames 中是否包含当前节点名 node.Name，若不包含则返回 false
        if !haveNode(nodeNames, node.Name) {
            return false
        }
    }
    // 如果节点数组 nodes 中所有节点名都包含在节点名数组 nodeNames 中，则返回 true
    return true
}
```

##### haveNode

```GO
// 判断给定的节点名数组 nodeNames 中是否包含指定节点名 nodeName，返回布尔值。
func haveNode(nodeNames []string, nodeName string) bool {
    // 遍历节点名数组 nodeNames
    for _, n := range nodeNames {
        // 如果当前节点名 n 与指定节点名 nodeName 相同，则返回 true
        if n == nodeName {
        	return true
        }
    }
    // 如果节点名数组 nodeNames 中不包含指定节点名 nodeName，则返回 false
    return false
}
```

### Reserve&Unreserve

```GO
// Reserve函数为Pod保留claims。
func (pl *dynamicResources) Reserve(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) *framework.Status {
    // 如果未启用pl，返回nil
    if !pl.enabled {
    	return nil
    }
    // 从cs中获取状态数据
    state, err := getStateData(cs)
    if err != nil {
    	return statusError(klog.FromContext(ctx), err)
    }
    // 如果没有claims，则返回nil
    if len(state.claims) == 0 {
    	return nil
    }
    // 初始化状态变量
    numDelayedAllocationPending := 0 // 延迟分配的资源数量
    numClaimsWithStatusInfo := 0 // 具有状态信息的claims数量
    logger := klog.FromContext(ctx)
    // 初始化podSchedulingContexts
    schedulingCtx, err := state.initializePodSchedulingContexts(ctx, pod, pl.podSchedulingContextLister)
    if err != nil {
        return statusError(logger, err)
    }
    // 对于每个claim，检查是否被分配并保留
    for index, claim := range state.claims {
        if claim.Status.Allocation != nil {
            // 已分配但未保留
            if resourceclaim.IsReservedForPod(pod, claim) {
                logger.V(5).Info("is reserve", "pod", klog.KObj(pod), "node", klog.ObjectRef{Name: nodeName}, "resourceclaim", klog.KObj(claim))
                continue
            }
            // 为保留更新claim
            claim := claim.DeepCopy()
            claim.Status.ReservedFor = append(claim.Status.ReservedFor,
                resourcev1alpha2.ResourceClaimConsumerReference{
                    Resource: "pods",
                    Name:     pod.Name,
                    UID:      pod.UID,
                })
            logger.V(5).Info("reserve", "pod", klog.KObj(pod), "node", klog.ObjectRef{Name: nodeName}, "resourceclaim", klog.KObj(claim))
            _, err := pl.clientset.ResourceV1alpha2().ResourceClaims(claim.Namespace).UpdateStatus(ctx, claim, metav1.UpdateOptions{})
            // TODO: metric for update errors.
            if err != nil {
                return statusError(logger, err)
            }
            // 如果成功保留claim，则可以进行后续的调度操作
        } else {
            // 说明是延迟分配的claim
            numDelayedAllocationPending++
            // 检查驱动程序是否提供了有关指向它可以支持的节点的信息
            if statusForClaim(schedulingCtx, pod.Spec.ResourceClaims[index].Name) != nil {
                numClaimsWithStatusInfo++
            }
        }
    }
    // 如果没有延迟分配的资源，就不用做什么了
    if numDelayedAllocationPending == 0 {
        return nil
    }

    // 是否已修改PodSchedulingContext
    podSchedulingDirty := state.podSchedulingDirty
    // 如果潜在节点为空，说明还没有预选，需要请求预选
    if len(schedulingCtx.Spec.PotentialNodes) == 0 {
        schedulingCtx = schedulingCtx.DeepCopy()
        schedulingCtx.Spec.PotentialNodes = []string{nodeName}
        logger.V(5).Info("asking for information about single potential node", "pod", klog.KObj(pod), "node", klog.ObjectRef{Name: nodeName})
		podSchedulingDirty = true
	}
    // 当只有一个挂起的资源时，即使我们没有来自驱动程序的信息，我们也可以继续请求分配。否则，我们会等待信息，然后再做出可能需要撤销的决定。
	if numDelayedAllocationPending == 1 || numClaimsWithStatusInfo == numDelayedAllocationPending {
		schedulingCtx = schedulingCtx.DeepCopy()
		// TODO: 我们可以增加调度程序选择之前相同节点的机会吗？
		// 假设该节点仍适合pod？选择不同的节点可能会导致为一个节点分配某些资源，为另一个节点分配另一些资源，然后需要使用解除分配来解决。
		schedulingCtx.Spec.SelectedNode = nodeName
		logger.V(5).Info("start allocation", "pod", klog.KObj(pod), "node", klog.ObjectRef{Name: nodeName})
		if err := state.publishPodSchedulingContexts(ctx, pl.clientset, schedulingCtx); err != nil {
			return statusError(logger, err)
		}
		return statusUnschedulable(logger, "waiting for resource driver to allocate resource", "pod", klog.KObj(pod), "node", klog.ObjectRef{Name: nodeName})
	}

	// 可能在PreScore或之前被修改。
	if podSchedulingDirty {
		if err := state.publishPodSchedulingContexts(ctx, pl.clientset, schedulingCtx); err != nil {
			return statusError(logger, err)
		}
	}

	// 有多个挂起的声明并且没有关于所有声明的足够信息。
	// TODO: 在触发延迟卷积提供之前，我们可以或应该确保在等待资源时中止调度上下文吗？ 一方面，目前卷的提供是不可逆的，因此最好是最后执行。 另一方面，同时触发可能更快。
	return statusUnschedulable(logger, "waiting for resource driver to provide information", "pod", klog.KObj(pod))
}
```

```go
// Unreserve函数会清除所有claims的ReservedFor字段，将其置为空。如果给定的pod没有找到对应的状态信息，则不执行任何操作。
func (pl *dynamicResources) Unreserve(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) {
    // 如果未开启dynamicResources，则不进行任何操作。
    if !pl.enabled {
    	return
    }
    // 从cycleState中获取state数据。
    state, err := getStateData(cs)
    if err != nil {
    	return
    }
    // 如果claims为空，则不进行任何操作。
    if len(state.claims) == 0 {
    	return
    }
    logger := klog.FromContext(ctx)
    // 遍历所有claims。
    for index, claim := range state.claims {
        // 如果该claim已被分配资源且被保留给该pod。
        if claim.Status.Allocation != nil &&
            resourceclaim.IsReservedForPod(pod, claim) {
            // 将pod从ReservedFor字段中移除。
            claim := claim.DeepCopy()
            reservedFor := make([]resourcev1alpha2.ResourceClaimConsumerReference, 0, len(claim.Status.ReservedFor)-1)
            for _, reserved := range claim.Status.ReservedFor {
                // TODO: UID是否可以在所有资源中被认为是唯一的，或者我们还需要比较Group/Version/Resource？
                if reserved.UID != pod.UID {
                    reservedFor = append(reservedFor, reserved)
                }
            }
            claim.Status.ReservedFor = reservedFor
            // 记录日志。
            logger.V(5).Info("unreserve", "resourceclaim", klog.KObj(claim))
            // 更新该claim的状态。
            if err := state.updateClaimStatus(ctx, pl.clientset, index, claim); err != nil {
                // 当pod的schedulingCtx重试时，我们将再次进入此处。
                logger.Error(err, "unreserve", "resourceclaim", klog.KObj(claim))
            }
        }
    }
}
```

### EventsToRegister

```go
func (pl *dynamicResources) EventsToRegister() []framework.ClusterEvent {
	if !pl.enabled {
		return nil
	}

	events := []framework.ClusterEvent{
		// Allocation is tracked in ResourceClaims, so any changes may make the pods schedulable.
		{Resource: framework.ResourceClaim, ActionType: framework.Add | framework.Update},
		// 当驱动程序提供了额外的信息时，正在等待该信息的 Pod 可能是可调度的。
		// TODO (#113702): 可以改变这样一个事件，使得这种事件不会触发 *所有* Pod 吗？
		// 可以：https://github.com/kubernetes/kubernetes/blob/abcbaed0784baf5ed2382aae9705a8918f2daa18/pkg/scheduler/eventhandlers.go#L70
		{Resource: framework.PodSchedulingContext, ActionType: framework.Add | framework.Update},
		// 一个资源可能依赖于节点标签进行拓扑筛选。
		// 新的或更新的节点可能使 Pod 可调度。
		{Resource: framework.Node, ActionType: framework.Add | framework.UpdateNodeLabel},
	}
	return events
}
```

### PostBind

```go
// PostBind在pod成功绑定到节点之后调用。现在我们确定，如果存在PodSchedulingContext对象，它肯定不再需要，并且可以删除它。这是一次性的，不会有任何重试。这没问题，因为通常情况下应该会成功，在那些不成功的情况下，垃圾回收器最终会清理它。
func (pl *dynamicResources) PostBind(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, nodeName string) {
    // 如果未启用，则返回。
    if !pl.enabled {
    	return
    }
    // 获取状态数据
    state, err := getStateData(cs)
    if err != nil {
    	return
    }
    // 如果没有绑定声明，则返回。
    if len(state.claims) == 0 {
    	return
    }
    // 我们无法确定是否存在PodSchedulingContext对象。可能我们在上一个pod schedulingCtx周期中创建了它，但尚未在我们的informer缓存中。为了安全起见，让我们尝试删除它。
    logger := klog.FromContext(ctx)
    err = pl.clientset.ResourceV1alpha2().PodSchedulingContexts(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
    switch {
    case apierrors.IsNotFound(err):
        // 如果未找到PodSchedulingContext对象，则输出信息。
        logger.V(5).Info("no PodSchedulingContext object to delete")
    case err != nil:
        // 如果出现错误，则输出错误信息。
        logger.Error(err, "delete PodSchedulingContext")
    default:
        // 删除PodSchedulingContext对象成功，则输出信息。
        logger.V(5).Info("PodSchedulingContext object deleted")
    }
}
```

## ImageLocality

### 作用

ImageLocality插件是调度器中的一个组件，它的作用是优先将已经存在于节点上的镜像用于调度Pod，从而避免网络下载镜像的延迟和带宽消耗。

### 结构

```GO
// ImageLocality是一个分数插件，它优先选择已经具有所请求的Pod容器映像的节点。
type ImageLocality struct {
	handle framework.Handle
}

var _ framework.ScorePlugin = &ImageLocality{}

// Name是插件在插件注册表和配置中使用的名称。
const Name = names.ImageLocality

// Name返回插件的名称。它用于日志等。
func (pl *ImageLocality) Name() string {
	return Name
}

// New初始化一个新的插件并返回它。
func New(_ runtime.Object, h framework.Handle) (framework.Plugin, error) {
	return &ImageLocality{handle: h}, nil
}
```

### Score&ScoreExtensions

```GO
// 在得分扩展点调用Score。
func (pl *ImageLocality) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 从SnapshotSharedLister获取节点信息
    nodeInfo, err := pl.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
    if err != nil {
    	return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
    }
    // 获取所有节点信息
    nodeInfos, err := pl.handle.SnapshotSharedLister().NodeInfos().List()
    if err != nil {
        return 0, framework.AsStatus(err)
    }
    totalNumNodes := len(nodeInfos)

    // 计算得分
    score := calculatePriority(sumImageScores(nodeInfo, pod.Spec.Containers, totalNumNodes), len(pod.Spec.Containers))

    return score, nil
}

// Score插件的ScoreExtensions。
func (pl *ImageLocality) ScoreExtensions() framework.ScoreExtensions {
	return nil
}
```

#### calculatePriority

```GO
// calculatePriority函数返回一个节点的优先级。根据节点上所请求的镜像的sumScores值，将节点的优先级通过缩放最大优先级值与与sumScores成比例的比率得到。
func calculatePriority(sumScores int64, numContainers int) int64 {
    // 计算节点容器阈值，numContainers为容器个数
    maxThreshold := maxContainerThreshold * int64(numContainers)
    // 如果sumScores小于minThreshold，则使用minThreshold
    if sumScores < minThreshold {
    	sumScores = minThreshold
    // 如果sumScores大于maxThreshold，则使用maxThreshold
    } else if sumScores > maxThreshold {
    	sumScores = maxThreshold
    }
    // 通过缩放maxNodeScore值，使用sumScores的范围与minThreshold和maxThreshold的比率来计算节点优先级
    return int64(framework.MaxNodeScore) * (sumScores - minThreshold) / (maxThreshold - minThreshold)
}
```

#### sumImageScores

```GO
// sumImageScores函数返回节点上已经存在的所有容器的镜像分数之和。每个镜像接收其大小乘以scaledImageScore的原始分数。
// 这些原始分数稍后用于计算最终得分。请注意，此计算不考虑init容器，因为用户很少部署庞大的init容器。
func sumImageScores(nodeInfo *framework.NodeInfo, containers []v1.Container, totalNumNodes int) int64 {
    var sum int64
    // 遍历pod的容器列表
    for _, container := range containers {
        // 如果节点上存在容器所使用的镜像，则计算该镜像的得分
        if state, ok := nodeInfo.ImageStates[normalizedImageName(container.Image)]; ok {
        // 计算镜像的得分，并将其加入sum中
        	sum += scaledImageScore(state, totalNumNodes)
        }
    }
    return sum
}
```

##### normalizedImageName

```GO
// normalizedImageName 函数返回给定镜像的符合 CRI 规范的名称。
// TODO：覆盖遗漏匹配的极端情况，例如：
// 1. 在 Pod 规范中使用 Docker 作为运行时并使用 docker.io/library/test:tag，但在节点状态中只有 test:tag
// 2. 在 Pod 规范中使用隐式注册表，即 test:tag 或 library/test:tag，但在节点状态中只有 docker.io/library/test:tag。
// 需要注意的是，如果用户始终使用一种注册表格式，则不应发生此类情况。
func normalizedImageName(name string) string {
    if strings.LastIndex(name, ":") <= strings.LastIndex(name, "/") {
    	name = name + ":latest"
    }
    return name
}
```

##### scaledImageScore

```GO
// scaledImageScore 函数返回给定镜像状态的自适应缩放分数。
// 镜像的大小用作基础分数，乘以一个因子进行缩放，该因子考虑镜像已经“扩散”到了多少个节点。
// 此启发式方法旨在减轻不良的“节点加热问题”，即由于镜像本地性，Pod 被分配到同一或少数几个节点的不良情况。
func scaledImageScore(imageState *framework.ImageStateSummary, totalNumNodes int) int64 {
    spread := float64(imageState.NumNodes) / float64(totalNumNodes)
    return int64(float64(imageState.Size) * spread)
}
```

## NodeName

### 作用

作用是将Pod调度到指定的节点上。当用户创建一个Pod时，可以在Pod的配置中指定NodeName字段，该字段指定了该Pod所需的节点名称，NodeName插件会将该Pod直接调度到指定的节点上，而不考虑其他的调度规则。

### 结构

```GO
// NodeName 是一个插件，用于检查 Pod spec 中指定的节点名是否与当前节点匹配。
type NodeName struct{}

// _ framework.FilterPlugin 表示 NodeName 实现了 framework.FilterPlugin 接口。
// _ framework.EnqueueExtensions 表示 NodeName 实现了 framework.EnqueueExtensions 接口。
var _ framework.FilterPlugin = &NodeName{}
var _ framework.EnqueueExtensions = &NodeName{}

const (
    // Name 是插件的名称，用于记录日志等。
    Name = names.NodeName
    // ErrReason 是当节点名与当前节点不匹配时返回的错误原因。
    ErrReason = "node(s) didn't match the requested node name"
)

// Name 返回插件的名称。
func (pl *NodeName) Name() string {
	return Name
}

// New 初始化一个新的插件并返回它。
func New(_ runtime.Object, _ framework.Handle) (framework.Plugin, error) {
	return &NodeName{}, nil
}
```

### Filter

```GO
// Filter 在过滤器扩展点调用。
func (pl *NodeName) Filter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	if nodeInfo.Node() == nil {
		return framework.NewStatus(framework.Error, "node not found") // 如果找不到节点，返回错误状态
	}
	if !Fits(pod, nodeInfo) { // 如果 Pod 不适配当前节点，返回无法调度和无法解决的错误状态
		return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReason)
	}
	return nil // 如果节点适配 Pod，则返回 nil 状态
}
```

#### Fits

```GO
// Fits 实际上检查 Pod 是否适配节点。
func Fits(pod *v1.Pod, nodeInfo *framework.NodeInfo) bool {
	return len(pod.Spec.NodeName) == 0 || pod.Spec.NodeName == nodeInfo.Node().Name // 如果节点名称为空或与 Pod 指定的节点名称匹配，则返回 true
}
```

### EventsToRegister

```GO
// EventsToRegister 返回可能导致此插件使 Pod 无法调度的可能事件。
func (pl *NodeName) EventsToRegister() []framework.ClusterEvent {
	return []framework.ClusterEvent{
		{Resource: framework.Node, ActionType: framework.Add | framework.Update}, // 返回节点添加或更新的事件
	}
}
```

## NodePorts

### 作用

作用是为NodePort类型的Service选择可用的节点端口（NodePort），并将该端口的信息更新到Service的配置中。

### 结构

```GO
// NodePorts 是一个检查节点是否有空闲端口供容器使用的调度器插件。
type NodePorts struct{}

var _ framework.PreFilterPlugin = &NodePorts{}
var _ framework.FilterPlugin = &NodePorts{}
var _ framework.EnqueueExtensions = &NodePorts{}

const (
	// 插件名称，用于在注册表和配置中标识该插件。
	Name = names.NodePorts

	// 预先计算 NodePorts 数据存储在 CycleState 中的键。
	// 使用插件名称作为键，有助于避免与其他插件的冲突。
	preFilterStateKey = "PreFilter" + Name

	// ErrReason when node ports aren't available.
	// 当节点没有可用端口时返回的错误信息。
	ErrReason = "node(s) didn't have free ports for the requested pod ports"
)

// Name 方法返回插件的名称，用于日志等。
func (pl *NodePorts) Name() string {
	return Name
}

// New 方法初始化并返回插件。
func New(_ runtime.Object, _ framework.Handle) (framework.Plugin, error) {
	return &NodePorts{}, nil
}
```

### PreFilter&PreFilterExtensions

```GO
// 在预筛选器扩展点调用的 PreFilter 函数。
func (pl *NodePorts) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 获取 Pod 的容器端口。
    s := getContainerPorts(pod)
    // 将预筛选器状态写入循环状态中。
    cycleState.Write(preFilterStateKey, preFilterState(s))
    return nil, nil
}

// 此插件没有预筛选器扩展。
func (pl *NodePorts) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

#### getContainerPorts

```GO
// getContainerPorts 函数返回 Pod 使用的主机端口：如果端口已经被使用，结果将会包含一个 "port:true" 对；但是它不会解决端口冲突。
func getContainerPorts(pods ...*v1.Pod) []*v1.ContainerPort {
    // 初始化端口列表为空。
    ports := []*v1.ContainerPort{}
    // 遍历所有 Pod。
    for _, pod := range pods {
        // 遍历每个容器。
        for j := range pod.Spec.Containers {
            container := &pod.Spec.Containers[j]
            // 遍历每个容器的端口。
            for k := range container.Ports {
            	// 将端口添加到端口列表中。
            	ports = append(ports, &container.Ports[k])
            }
        }
    }
    // 返回端口列表。
    return ports
}
```

#### preFilterState

```GO
// preFilterState 是 []*v1.ContainerPort 的类型别名。
type preFilterState []*v1.ContainerPort

// 克隆预筛选器状态。
func (s preFilterState) Clone() framework.StateData {
    // 状态不会受到添加/删除现有 Pod 的影响，因此我们不需要进行深层复制。
    return s
}
```

### Filter

```GO
// 在过滤器扩展点调用的 Filter 函数。
func (pl *NodePorts) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取预筛选器状态。
    wantPorts, err := getPreFilterState(cycleState)
    if err != nil {
   		return framework.AsStatus(err)
    }
    // 判断 Pod 是否适合调度到该节点。
    fits := fitsPorts(wantPorts, nodeInfo)
    if !fits {
        return framework.NewStatus(framework.Unschedulable, ErrReason)
    }

    return nil
}
```

#### getPreFilterState

```GO
// 定义函数 getPreFilterState，接收一个类型为 *framework.CycleState 的参数 cycleState，返回 preFilterState 和 error。
func getPreFilterState(cycleState *framework.CycleState) (preFilterState, error) {
    // 从 cycleState 中读取 preFilterStateKey 对应的值，如果出错，则返回一个 error。
    c, err := cycleState.Read(preFilterStateKey)
    if err != nil {
        // preFilterState 不存在，很可能是 PreFilter 没有被调用。
        return nil, fmt.Errorf("reading %q from cycleState: %w", preFilterStateKey, err)
    }

    // 将 c 转换为 preFilterState，如果出错，则返回一个 error。
    s, ok := c.(preFilterState)
    if !ok {
        return nil, fmt.Errorf("%+v  convert to nodeports.preFilterState error", c)
    }

    // 返回 preFilterState 和一个 nil error。
    return s, nil
}
```

#### fitsPorts

```GO
// 定义函数 fitsPorts，接收两个参数：wantPorts 和 nodeInfo，返回一个 bool 类型的值。
func fitsPorts(wantPorts []*v1.ContainerPort, nodeInfo *framework.NodeInfo) bool {
    // 尝试查看 existingPorts 和 wantPorts 是否会冲突
    existingPorts := nodeInfo.UsedPorts
    // 遍历 wantPorts 切片中的每一个元素 cp。
    for _, cp := range wantPorts {
        // 检查 existingPorts 中是否存在与 cp 相冲突的端口，如果存在，则返回 false。
        if existingPorts.CheckConflict(cp.HostIP, string(cp.Protocol), cp.HostPort) {
            return false
        }
    }

    // 若没有找到任何冲突，则返回 true。
    return true
}
```

### EventsToRegister

```GO
// 定义方法 EventsToRegister，其接收者为类型 NodePorts 的指针 pl，返回一个 framework.ClusterEvent 类型的切片。
func (pl *NodePorts) EventsToRegister() []framework.ClusterEvent {
    // 返回一个包含两个 framework.ClusterEvent 类型的元素的切片。
    // 其中第一个元素表示 Pod 被删除，第二个元素表示 Node 被添加或更新。
    return []framework.ClusterEvent{
        {Resource: framework.Pod, ActionType: framework.Delete},
        {Resource: framework.Node, ActionType: framework.Add | framework.Update},
    }
}
```

## NodeResourcesBalancedAllocation

### 作用

该插件旨在在调度容器时平衡节点资源的使用，即在节点之间分配CPU和内存资源，以确保在节点上运行的所有容器都可以获得所需的资源。它的主要工作原理是评估节点的可用资源，然后在尽可能相等地使用所有节点资源的同时，将容器调度到可用节点上。

该插件考虑以下因素来平衡节点的资源使用：

- 节点的总资源
- 节点上正在运行的容器和其资源需求
- 节点上已经被预留的资源（如果有）

该插件还考虑到节点的标签，以便将容器调度到具有特定标签的节点上。例如，如果一个容器需要特定的GPU资源，该插件将考虑到只有具有适当GPU标签的节点才能运行该容器。

### 结构

```GO
// BalancedAllocation是一个分数插件，用于计算容量的CPU和内存分数之间的差异，并根据两个度量之间的接近程度优先考虑主机。
type BalancedAllocation struct {
    handle framework.Handle
    resourceAllocationScorer
}

// _ framework.PreScorePlugin = &BalancedAllocation{}，确保BalancedAllocation实现了PreScorePlugin接口
// _ framework.ScorePlugin = &BalancedAllocation{}，确保BalancedAllocation实现了ScorePlugin接口
var _ framework.PreScorePlugin = &BalancedAllocation{}
var _ framework.ScorePlugin = &BalancedAllocation{}

const (
    // BalancedAllocationName是插件在插件注册表和配置中使用的名称。
	BalancedAllocationName = names.NodeResourcesBalancedAllocation
    // balancedAllocationPreScoreStateKey是CycleState中的键，用于NodeResourcesBalancedAllocation的预计算数据以进行评分。
	balancedAllocationPreScoreStateKey = "PreScore" + BalancedAllocationName
)

// Name返回插件的名称。它用于日志等。
func (ba *BalancedAllocation) Name() string {
	return BalancedAllocationName
}

// NewBalancedAllocation初始化一个新的插件并返回它。
func NewBalancedAllocation(baArgs runtime.Object, h framework.Handle, fts feature.Features) (framework.Plugin, error) {
    args, ok := baArgs.(*config.NodeResourcesBalancedAllocationArgs)
    if !ok {
    	return nil, fmt.Errorf("want args to be of type NodeResourcesBalancedAllocationArgs, got %T", baArgs)
    }
    // 验证参数
    if err := validation.ValidateNodeResourcesBalancedAllocationArgs(nil, args); err != nil {
        return nil, err
    }

    return &BalancedAllocation{
        handle: h,
        resourceAllocationScorer: resourceAllocationScorer{
            Name:         BalancedAllocationName,
            scorer:       balancedResourceScorer,
            useRequested: true,
            resources:    args.Resources,
        },
    }, nil
}
```

#### resourceAllocationScorer

```go
// scorer 是 resourceAllocationScorer 的装饰器。
type scorer func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer

// resourceAllocationScorer 包含计算资源分配得分所需的信息。
type resourceAllocationScorer struct {
    Name string
    // 用于决定在计算 cpu 和 memory 时使用 Requested 还是 NonZeroRequested。
    useRequested bool
    scorer func(requested, allocable []int64) int64
    resources []config.ResourceSpec
}

// score函数将使用'scorer'函数计算得分。
func (r *resourceAllocationScorer) score(
    ctx context.Context, // 上下文对象
    pod *v1.Pod, // Pod对象
    nodeInfo *framework.NodeInfo, // 节点信息对象
    podRequests []int64) (int64, *framework.Status) { // Pod资源请求列表，返回得分和状态对象
    logger := klog.FromContext(ctx) // 获取logger对象
    node := nodeInfo.Node() // 获取节点对象
    if node == nil { // 节点不存在，则返回错误状态
    	return 0, framework.NewStatus(framework.Error, "node not found")
    }
    // 如果资源未设置，则无法调度Pod，返回错误状态
    if len(r.resources) == 0 {
    	return 0, framework.NewStatus(framework.Error, "resources not found")
    }
	requested := make([]int64, len(r.resources))  // 声明一个与资源列表同长度的切片，用于存储请求的资源量
    allocatable := make([]int64, len(r.resources))  // 声明一个与资源列表同长度的切片，用于存储节点上可用的资源量
    for i := range r.resources {  // 遍历资源列表
        // 计算资源可分配和请求的数量
        alloc, req := r.calculateResourceAllocatableRequest(logger, nodeInfo, v1.ResourceName(r.resources[i].Name), podRequests[i])
        // 仅当可分配数量为0时跳过，不进行存储
        if alloc == 0 {
            continue
        }
        allocatable[i] = alloc  // 将可分配数量存储在allocatable中
        requested[i] = req  // 将请求的数量存储在requested中
    }

    // 计算资源的得分
    score := r.scorer(requested, allocatable)

    // 当logger的V方法返回值大于等于10时，输出内部信息
    if loggerV := logger.V(10); loggerV.Enabled() {
        loggerV.Info("Listed internal info for allocatable resources, requested resources and score", "pod",
            klog.KObj(pod), "node", klog.KObj(node), "resourceAllocationScorer", r.Name,
            "allocatableResource", allocatable, "requestedResource", requested, "resourceScore", score,
        )
    }

    return score, nil  // 返回资源得分和状态
}

// calculateResourceAllocatableRequest 返回2个参数：
// - 第1个参数：节点上可分配资源的数量。
// - 第2个参数：节点上请求资源的总和。
// 注意：如果它是扩展资源，且Pod不请求它，则返回(0, 0)。
func (r *resourceAllocationScorer) calculateResourceAllocatableRequest(logger klog.Logger, nodeInfo *framework.NodeInfo, resource v1.ResourceName, podRequest int64) (int64, int64) {
    requested := nodeInfo.NonZeroRequested
    // 如果 useRequested 为 true，则使用 Requested，否则使用 NonZeroRequested
    if r.useRequested {
        requested = nodeInfo.Requested
    }

    // 如果 pod 不请求该扩展资源，则返回 (0, 0) 以跳过对该资源的评分
    if podRequest == 0 && schedutil.IsScalarResourceName(resource) {
        return 0, 0
    }

    switch resource {
    // 如果请求的资源是 CPU，则返回节点可分配 CPU 数量和请求 CPU 数量之和
    case v1.ResourceCPU:
        return nodeInfo.Allocatable.MilliCPU, (requested.MilliCPU + podRequest)

    // 如果请求的资源是 Memory，则返回节点可分配内存量和请求内存量之和
    case v1.ResourceMemory:
        return nodeInfo.Allocatable.Memory, (requested.Memory + podRequest)

    // 如果请求的资源是 EphemeralStorage，则返回节点可分配临时存储量和请求临时存储量之和
    case v1.ResourceEphemeralStorage:
        return nodeInfo.Allocatable.EphemeralStorage, (nodeInfo.Requested.EphemeralStorage + podRequest)

    // 如果请求的资源是扩展资源，则返回节点可分配该扩展资源量和请求该扩展资源量之和
    default:
        if _, exists := nodeInfo.Allocatable.ScalarResources[resource]; exists {
            return nodeInfo.Allocatable.ScalarResources[resource], (nodeInfo.Requested.ScalarResources[resource] + podRequest)
        }
    }

    // 记录跳过对该资源评分的信息
    logger.V(10).Info("Requested resource is omitted for node score calculation", "resourceName", resource)

    // 如果请求的资源不属于上述任何一种类型，则返回 (0, 0)
    return 0, 0
}

// calculatePodResourceRequest函数返回总的非零资源请求量。如果Pod定义了Overhead，那么将其加到结果中。
func (r *resourceAllocationScorer) calculatePodResourceRequest(pod *v1.Pod, resourceName v1.ResourceName) int64 {
    // 定义PodResourcesOptions对象
    opts := resourcehelper.PodResourcesOptions{
        InPlacePodVerticalScalingEnabled: utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling),
    }

    // 如果不使用请求资源，则设置默认CPU和内存请求量
    if !r.useRequested {
        opts.NonMissingContainerRequests = v1.ResourceList{
            v1.ResourceCPU:    *resource.NewMilliQuantity(schedutil.DefaultMilliCPURequest, resource.DecimalSI),
            v1.ResourceMemory: *resource.NewQuantity(schedutil.DefaultMemoryRequest, resource.DecimalSI),
        }
    }

    // 获取Pod的资源请求量
    requests := resourcehelper.PodRequests(pod, opts)

    // 获取指定资源类型的请求量
    quantity := requests[resourceName]
    if resourceName == v1.ResourceCPU {
        // 如果是CPU资源，返回毫核单位的请求量
        return quantity.MilliValue()
    }
    // 如果是其他类型的资源，返回对应的值
    return quantity.Value()
}

// calculatePodResourceRequestList函数返回Pod对于资源列表中每个资源类型的请求量
func (r *resourceAllocationScorer) calculatePodResourceRequestList(pod *v1.Pod, resources []config.ResourceSpec) []int64 {
	podRequests := make([]int64, len(resources))
    for i := range resources {
        // 调用calculatePodResourceRequest计算每个资源类型的请求量
        podRequests[i] = r.calculatePodResourceRequest(pod, v1.ResourceName(resources[i].Name))
    }
    return podRequests
}
```

#### balancedResourceScorer

```go
func balancedResourceScorer(requested, allocable []int64) int64 {
	// 定义存储每个资源使用率的分数和总的使用率分数
	var resourceToFractions []float64
	var totalFraction float64
	// 遍历 requested 列表，计算每个资源的使用率
	for i := range requested {
		// 如果该资源在该节点上不可用，则跳过
		if allocable[i] == 0 {
			continue
		}
		// 计算该资源的使用率分数
		fraction := float64(requested[i]) / float64(allocable[i])
		// 如果使用率超过 1，将其设为 1，因为使用率不能超过 100%
		if fraction > 1 {
			fraction = 1
		}
		// 累加总的使用率分数，并将该资源的使用率分数加入 resourceToFractions
		totalFraction += fraction
		resourceToFractions = append(resourceToFractions, fraction)
	}

	// 初始化标准差
	std := 0.0

	// 如果资源数量只有两个，可以简化计算标准差的公式
	if len(resourceToFractions) == 2 {
		std = math.Abs((resourceToFractions[0] - resourceToFractions[1]) / 2)
	// 否则，使用常见的公式计算标准差
	} else if len(resourceToFractions) > 2 {
		// 计算平均使用率
		mean := totalFraction / float64(len(resourceToFractions))
		var sum float64
		// 计算每个使用率与平均使用率的差的平方之和
		for _, fraction := range resourceToFractions {
			sum = sum + (fraction-mean)*(fraction-mean)
		}
		// 标准差等于上述平方和除以使用率数量再开根号
		std = math.Sqrt(sum / float64(len(resourceToFractions)))
	}

	// 标准差始终是正值。1 减去标准差，可以让得分更高的节点具有更小的标准差，从而更平衡，同时将其乘以 `MaxNodeScore` 可以提供所需的缩放因子
	return int64((1 - std) * float64(framework.MaxNodeScore))
}
```

### PreScore

```GO
// PreScore函数计算传入的Pod资源请求，并将其写入用于周期状态的环境中。
func (ba *BalancedAllocation) PreScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
    // 创建一个balancedAllocationPreScoreState的结构体对象state，其中podRequests存储Pod资源请求列表
    state := &balancedAllocationPreScoreState{
    	podRequests: ba.calculatePodResourceRequestList(pod, ba.resources),
    }
    // 将state写入周期状态环境中，使用balancedAllocationPreScoreStateKey作为key
    cycleState.Write(balancedAllocationPreScoreStateKey, state)
    return nil
}
```

#### balancedAllocationPreScoreState

```GO
// balancedAllocationPreScoreState在PreScore时计算，在Score时使用。
type balancedAllocationPreScoreState struct {
    // podRequests的顺序与NodeResourcesFitArgs.Resources中定义的资源相同，在其他存储类似列表的地方也是如此。
    podRequests []int64
}

// Clone实现了必需的Clone接口。实际上并没有复制数据，因为没有必要。
func (s *balancedAllocationPreScoreState) Clone() framework.StateData {
	return s
}
```

### Score&ScoreExtensions

```GO
// Score在计算分数的扩展点被调用。
func (ba *BalancedAllocation) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 从Snapshot中获取节点的信息
    nodeInfo, err := ba.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
    if err != nil {
    	return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
    }
	// 获取balancedAllocationPreScoreState，如果获取失败则计算pod的资源请求列表并创建一个新的状态
    s, err := getBalancedAllocationPreScoreState(state)
    if err != nil {
        s = &balancedAllocationPreScoreState{podRequests: ba.calculatePodResourceRequestList(pod, ba.resources)}
    }

    // ba.score偏爱资源使用率平衡的节点。它计算这些资源的标准差，并根据这些资源的使用情况有多接近，优先选择节点。
    // 具体来说，score = (1 - std) * MaxNodeScore，其中std通过Σ((fraction(i)-mean)^2)/len(resources)的平方根计算。
    // 算法部分灵感来源于：
    // "Wei Huang等人。具有平衡资源利用率的节能虚拟机放置算法"
    return ba.score(ctx, pod, nodeInfo, s.podRequests)
}

// ScoreExtensions函数实现了Score插件的ScoreExtensions接口，返回nil。
func (ba *BalancedAllocation) ScoreExtensions() framework.ScoreExtensions {
	return nil
}
```

#### getBalancedAllocationPreScoreState

```go
// getBalancedAllocationPreScoreState从cycleState中获取balancedAllocationPreScoreState，如果获取失败则返回错误。
func getBalancedAllocationPreScoreState(cycleState *framework.CycleState) (*balancedAllocationPreScoreState, error) {
    c, err := cycleState.Read(balancedAllocationPreScoreStateKey)
    if err != nil {
    	return nil, fmt.Errorf("reading %q from cycleState: %w", balancedAllocationPreScoreStateKey, err)
    }
        s, ok := c.(*balancedAllocationPreScoreState)
    if !ok {
        return nil, fmt.Errorf("invalid PreScore state, got type %T", c)
    }
    return s, nil
}
```

## NodeResourcesFit

### 作用

用于检查要调度到节点的 Pod 所需资源是否与该节点上的可用资源相匹配。在 Kubernetes 中，Pods 可以请求 CPU、内存、存储和其他资源。这些资源必须可用于节点才能调度 Pod。`NodeResourcesFit` 功能会检查要调度的 Pod 的资源需求是否与节点上的可用资源匹配。

如果 Pod 所需的资源不匹配，调度器将不会将其调度到该节点上。调度器将尝试在其他可用的节点上找到匹配的节点以调度该 Pod。

此外，`NodeResourcesFit` 还可以考虑其他因素，例如节点上已经运行的 Pod 的资源需求，以确保节点不会过度分配资源。

### 结构

```GO
// 定义一个实现 PreFilterPlugin 接口的类型 Fit，确保 Fit 类型实现了 PreFilterPlugin 接口
var _ framework.PreFilterPlugin = &Fit{}
// 定义一个实现 FilterPlugin 接口的类型 Fit，确保 Fit 类型实现了 FilterPlugin 接口
var _ framework.FilterPlugin = &Fit{}
// 定义一个实现 EnqueueExtensions 接口的类型 Fit，确保 Fit 类型实现了 EnqueueExtensions 接口
var _ framework.EnqueueExtensions = &Fit{}
// 定义一个实现 PreScorePlugin 接口的类型 Fit，确保 Fit 类型实现了 PreScorePlugin 接口
var _ framework.PreScorePlugin = &Fit{}
// 定义一个实现 ScorePlugin 接口的类型 Fit，确保 Fit 类型实现了 ScorePlugin 接口
var _ framework.ScorePlugin = &Fit{}

const (
	// Name 是插件在插件注册表和配置中使用的名称
	Name = names.NodeResourcesFit
	// preFilterStateKey 是 CycleState 中 NodeResourcesFit 预先计算的数据的键
	// 使用插件的名称可能会帮助我们避免与其他插件发生冲突
	preFilterStateKey = "PreFilter" + Name
	// preScoreStateKey 是 CycleState 中用于评分的 NodeResourcesFit 预先计算的数据的键
	preScoreStateKey = "PreScore" + Name
)

// Fit 是一个检查节点是否具有足够资源的插件
type Fit struct {
	ignoredResources                sets.Set[string] // 忽略的资源
	ignoredResourceGroups           sets.Set[string] // 忽略的资源组
	enableInPlacePodVerticalScaling bool              // 是否启用原地 Pod 垂直扩缩容
	handle                          framework.Handle // 用于处理框架操作的句柄
	resourceAllocationScorer                             // 分配资源打分器
}

// Name 返回插件的名称，用于日志等
func (f *Fit) Name() string {
	return Name
}

// NewFit 初始化一个新的插件并返回它
func NewFit(plArgs runtime.Object, h framework.Handle, fts feature.Features) (framework.Plugin, error) {
	args, ok := plArgs.(*config.NodeResourcesFitArgs)
	if !ok {
		return nil, fmt.Errorf("want args to be of type NodeResourcesFitArgs, got %T", plArgs)
	}
	if err := validation.ValidateNodeResourcesFitArgs(nil, args); err != nil {
		return nil, err
	}

	if args.ScoringStrategy == nil {
		return nil, fmt.Errorf("scoring strategy not specified")
	}

	strategy := args.ScoringStrategy.Type
	scorePlugin, exists := nodeResourceStrategyTypeMap[strategy]
	if !exists {
		return nil, fmt.Errorf("scoring strategy %s is not supported", strategy)
	}

	return &Fit{
		ignoredResources:                sets.New(args.IgnoredResources...),
		ignoredResourceGroups:           sets.New(args.IgnoredResourceGroups...),
		enableInPlacePodVerticalScaling: fts.EnableInPlacePodVerticalScaling,
		handle:                          h,
		resourceAllocationScorer:        *scorePlugin(args),
	}, nil
}
```

#### nodeResourceStrategyTypeMap

```go
// nodeResourceStrategyTypeMap 将策略映射到得分器实现
var nodeResourceStrategyTypeMap = map[config.ScoringStrategyType]scorer{
    // 最少分配
	config.LeastAllocated: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
        // 获取得分策略资源
		resources := args.ScoringStrategy.Resources
        // 返回一个新的资源分配得分器，其名称为config.LeastAllocated，
		// 使用leastResourceScorer函数计算分数，资源为resources
		return &resourceAllocationScorer{
			Name:      string(config.LeastAllocated),
			scorer:    leastResourceScorer(resources),
			resources: resources,
		}
	},
    // 最多分配
	config.MostAllocated: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
        // 获取得分策略资源
		resources := args.ScoringStrategy.Resources
        // 返回一个新的资源分配得分器，其名称为config.MostAllocated，
		// 使用mostResourceScorer函数计算分数，资源为resources
		return &resourceAllocationScorer{
			Name:      string(config.MostAllocated),
			scorer:    mostResourceScorer(resources),
			resources: resources,
		}
	},
    // 请求容量比率
	config.RequestedToCapacityRatio: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
        // 获取得分策略资源
		resources := args.ScoringStrategy.Resources
        // 返回一个新的资源分配得分器，其名称为config.RequestedToCapacityRatio，
        // 使用requestedToCapacityRatioScorer函数计算分数，资源为resources，
        // 请求容量比率的形状为args.ScoringStrategy.RequestedToCapacityRatio.Shape。
		return &resourceAllocationScorer{
			Name:      string(config.RequestedToCapacityRatio),
			scorer:    requestedToCapacityRatioScorer(resources, args.ScoringStrategy.RequestedToCapacityRatio.Shape),
			resources: resources,
		}
	},
}

```

#### leastResourceScorer

```go
// leastResourceScorer 是一个函数，它喜欢请求资源更少的节点。
// 它计算了在节点上调度的 Pod 请求的内存、CPU 和其他资源所占比例，并根据请求到容量比例的平均值的最小值进行优先级排序。
//
// 详细信息：
// (cpu((capacity-requested)MaxNodeScorecpuWeight/capacity) + memory((capacity-requested)MaxNodeScorememoryWeight/capacity) + ...)/weightSum
func leastResourceScorer(resources []config.ResourceSpec) func([]int64, []int64) int64 {
    return func(requested, allocable []int64) int64 {
        var nodeScore, weightSum int64
        for i := range requested {
            if allocable[i] == 0 {
                continue
            }
            // 权重
            weight := resources[i].Weight
            // 计算所请求资源占总可用资源的比例，然后计算它们的最小值
            resourceScore := leastRequestedScore(requested[i], allocable[i])
            // 加权求和
            nodeScore += resourceScore * weight
            weightSum += weight
        }
        if weightSum == 0 {
        	return 0
        }
        // 返回平均加权分数
        return nodeScore / weightSum
    }
}
```

##### leastRequestedScore

```go
// leastRequestedScore 函数计算出未使用资源的分数，范围为 0-MaxNodeScore。
// 0 分最低，MaxNodeScore 分最高。
// 未使用的资源越多，得分越高。
func leastRequestedScore(requested, capacity int64) int64 {
    if capacity == 0 {
    	return 0
    }
    // 如果请求的资源量大于容量，则得分为 0
    if requested > capacity {
    	return 0
    }
    // 根据剩余容量与总容量的比例计算未使用容量得分
    return ((capacity - requested) * framework.MaxNodeScore) / capacity
}
```

### PreFilter&PreFilterExtensions

```GO
// PreFilter 在 prefilter 扩展点调用。
func (f *Fit) PreFilter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
    // 将计算出的 pod 的资源请求存入 CycleState 中以备后续使用。
    cycleState.Write(preFilterStateKey, computePodResourceRequest(pod))
    return nil, nil
}

// PreFilterExtensions 返回预筛选扩展，包括添加和删除 pod。
func (f *Fit) PreFilterExtensions() framework.PreFilterExtensions {
	return nil
}
```

#### computePodResourceRequest

```go
// computePodResourceRequest 返回覆盖每个资源维度最大宽度的 framework.Resource。
// 因为 Init 容器是按顺序运行的，我们在每个维度上迭代地收集最大值。
// 相反，对于正常容器，我们对资源向量进行求和，因为它们同时运行。
//
// # Overhead 定义的资源应添加到计算的请求总和中
//
// 示例：
//
// Pod:
//
// InitContainers
// IC1:
// CPU: 2
// Memory: 1G
// IC2:
// CPU: 2
// Memory: 3G
// Containers
// C1:
// CPU: 2
// Memory: 1G
// C2:
// CPU: 1
// Memory: 1G
//
// Result: CPU: 3, Memory: 3G
func computePodResourceRequest(pod *v1.Pod) *preFilterState {
	// pod 尚未调度，因此我们不需要担心 InPlacePodVerticalScalingEnabled。
    reqs := resource.PodRequests(pod, resource.PodResourcesOptions{})
    result := &preFilterState{}
    result.SetMaxResource(reqs)
    return result
}
```

#### preFilterState

```go
// preFilterState computed at PreFilter and used at Filter.
type preFilterState struct {
	framework.Resource
}

// Clone the prefilter state.
func (s *preFilterState) Clone() framework.StateData {
	return s
}
```

### Filter

```go
// 在 filter 扩展点处调用过滤器。
// 检查节点是否拥有足够的资源，如 cpu、内存、gpu、不透明的整数资源等，以运行 pod。
// 如果为空，则返回不足资源的列表，否则节点具有 pod 请求的所有资源。
func (f *Fit) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取先前的过滤器状态
    s, err := getPreFilterState(cycleState)
    if err != nil {
    	return framework.AsStatus(err)
    }
	// 检查资源是否足够
    insufficientResources := fitsRequest(s, nodeInfo, f.ignoredResources, f.ignoredResourceGroups)

    // 如果有不足资源，返回失败原因列表
    if len(insufficientResources) != 0 {
        failureReasons := make([]string, 0, len(insufficientResources))
        for i := range insufficientResources {
            failureReasons = append(failureReasons, insufficientResources[i].Reason)
        }
        return framework.NewStatus(framework.Unschedulable, failureReasons...)
    }
    return nil
}
```

#### getPreFilterState

```go
// 根据周期状态获取先前的过滤器状态
func getPreFilterState(cycleState *framework.CycleState) (*preFilterState, error) {
    // 从周期状态中读取 preFilterState
    c, err := cycleState.Read(preFilterStateKey)
    if err != nil {
        // preFilterState 不存在，可能 PreFilter 没有被调用。
        return nil, fmt.Errorf("error reading %q from cycleState: %w", preFilterStateKey, err)
    }
    // 将 preFilterState 类型断言为 *preFilterState
    s, ok := c.(*preFilterState)
    if !ok {
        // 如果类型断言失败，返回错误
        return nil, fmt.Errorf("%+v  convert to NodeResourcesFit.preFilterState error", c)
    }
    return s, nil
}
```

#### fitsRequest

```go
func fitsRequest(podRequest *preFilterState, nodeInfo *framework.NodeInfo, ignoredExtendedResources, ignoredResourceGroups sets.Set[string]) []InsufficientResource {
	insufficientResources := make([]InsufficientResource, 0, 4)

	allowedPodNumber := nodeInfo.Allocatable.AllowedPodNumber
	// 检查节点是否超出允许的Pod数量
	if len(nodeInfo.Pods)+1 > allowedPodNumber {
		insufficientResources = append(insufficientResources, InsufficientResource{
			ResourceName: v1.ResourcePods,
			Reason:       "Too many pods",
			Requested:    1,
			Used:         int64(len(nodeInfo.Pods)),
			Capacity:     int64(allowedPodNumber),
		})
	}

	// 如果Pod请求的CPU、Memory、EphemeralStorage以及标量资源都为0，则返回不足资源列表
	if podRequest.MilliCPU == 0 &&
		podRequest.Memory == 0 &&
		podRequest.EphemeralStorage == 0 &&
		len(podRequest.ScalarResources) == 0 {
		return insufficientResources
	}

	// 检查Pod请求的CPU是否大于节点可分配的CPU
	if podRequest.MilliCPU > 0 && podRequest.MilliCPU > (nodeInfo.Allocatable.MilliCPU-nodeInfo.Requested.MilliCPU) {
		insufficientResources = append(insufficientResources, InsufficientResource{
			ResourceName: v1.ResourceCPU,
			Reason:       "Insufficient cpu",
			Requested:    podRequest.MilliCPU,
			Used:         nodeInfo.Requested.MilliCPU,
			Capacity:     nodeInfo.Allocatable.MilliCPU,
		})
	}

	// 检查Pod请求的内存是否大于节点可分配的内存
	if podRequest.Memory > 0 && podRequest.Memory > (nodeInfo.Allocatable.Memory-nodeInfo.Requested.Memory) {
		insufficientResources = append(insufficientResources, InsufficientResource{
			ResourceName: v1.ResourceMemory,
			Reason:       "Insufficient memory",
			Requested:    podRequest.Memory,
			Used:         nodeInfo.Requested.Memory,
			Capacity:     nodeInfo.Allocatable.Memory,
		})
	}

	// 检查Pod请求的临时存储是否大于节点可分配的临时存储
	if podRequest.EphemeralStorage > 0 &&
		podRequest.EphemeralStorage > (nodeInfo.Allocatable.EphemeralStorage-nodeInfo.Requested.EphemeralStorage) {
		insufficientResources = append(insufficientResources, InsufficientResource{
			ResourceName: v1.ResourceEphemeralStorage,
			Reason:       "Insufficient ephemeral-storage",
			Requested:    podRequest.EphemeralStorage,
			Used:         nodeInfo.Requested.EphemeralStorage,
			Capacity:     nodeInfo.Allocatable.EphemeralStorage,
		})
	}

	// 检查Pod请求的标量资源是否大于节点可分配的标量资源
	for rName, rQuant := range podRequest.ScalarResources {
		// 如果请求数量为0，则跳过
		if rQuant == 0 {
			continue
		}

		if v1helper.IsExtendedResourceName(rName) {
            // 判断该资源名是否为扩展资源
			// 如果该资源是需要被忽略的扩展资源，则跳过检查
			var rNamePrefix string
			if ignoredResourceGroups.Len() > 0 {
				rNamePrefix = strings.Split(string(rName), "/")[0]
			}
			if ignoredExtendedResources.Has(string(rName)) || ignoredResourceGroups.Has(rNamePrefix) {
				continue
			}
		}

		if rQuant > (nodeInfo.Allocatable.ScalarResources[rName] - nodeInfo.Requested.ScalarResources[rName]) {
            // 如果该资源的请求量大于该节点剩余可分配量，则将该资源添加到 insufficientResources 中，同时记录该资源的名称、请求量、已使用量和总容量。
			insufficientResources = append(insufficientResources, InsufficientResource{
				ResourceName: rName,
				Reason:       fmt.Sprintf("Insufficient %v", rName),
				Requested:    podRequest.ScalarResources[rName],
				Used:         nodeInfo.Requested.ScalarResources[rName],
				Capacity:     nodeInfo.Allocatable.ScalarResources[rName],
			})
		}
	}
	// 返回不足资源列表 insufficientResources
	return insufficientResources
}
```

#### InsufficientResource

```go
// InsufficientResource结构体用于描述Pod无法适配到节点的资源限制类型。
type InsufficientResource struct {
    ResourceName v1.ResourceName //资源名
    Reason string //原因
    Requested int64 //请求的资源量
    Used int64 //已经使用的资源量
    Capacity int64 //总容量
}
```

### EventsToRegister

```go
// EventsToRegister 返回此插件可以使Pod失败的可能事件列表。
func (f *Fit) EventsToRegister() []framework.ClusterEvent {
    // 定义podActionType为删除类型
    podActionType := framework.Delete
    // 如果开启了InPlacePodVerticalScaling(KEP 1287)，则需要注册PodUpdate事件，
    // 因为Pod更新可能会释放资源，从而使其他Pod可调度。
    if f.enableInPlacePodVerticalScaling {
        podActionType |= framework.Update
    }
    // 返回包含两个ClusterEvent的列表
    return []framework.ClusterEvent{
        {Resource: framework.Pod, ActionType: podActionType},
        {Resource: framework.Node, ActionType: framework.Add | framework.Update},
    }
}
```

### PreScore

```go
// PreScore函数用于计算Pod资源请求并将其写入循环状态中。
func (f *Fit) PreScore(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodes []*v1.Node) *framework.Status {
    state := &preScoreState{
    	podRequests: f.calculatePodResourceRequestList(pod, f.resources),
    }
    cycleState.Write(preScoreStateKey, state)
    return nil
}
```

#### preScoreState

```go
// preScoreState结构体在PreScore中计算，在Score中使用。
type preScoreState struct {
	podRequests []int64 //资源请求列表，与NodeResourcesBalancedAllocationArgs.Resources定义的资源列表的顺序相同。
}

// Clone函数实现了必要的Clone接口。我们不需要实际复制数据，因为没有必要。
func (s *preScoreState) Clone() framework.StateData {
	return s
}
```

#### calculatePodResourceRequestList

```go
// calculatePodResourceRequestList函数计算Pod的资源请求，并将其存储在一个整数数组中返回。
func (r *resourceAllocationScorer) calculatePodResourceRequestList(pod *v1.Pod, resources []config.ResourceSpec) []int64 {
    podRequests := make([]int64, len(resources))
    for i := range resources {
    	podRequests[i] = r.calculatePodResourceRequest(pod, v1.ResourceName(resources[i].Name))
    }
    return podRequests
}
```

### Score

```go
// Score 在评分扩展点调用。
func (f *Fit) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
    // 获取节点信息
    nodeInfo, err := f.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
    if err != nil {
    	return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
    }
    // 获取PreScore阶段的状态信息
    s, err := getPreScoreState(state)
    if err != nil {
        // 如果没有获取到PreScore阶段的状态信息，则重新计算Pod资源请求，并创建一个新的preScoreState
        s = &preScoreState{
            podRequests: f.calculatePodResourceRequestList(pod, f.resources),
        }
    }

    // 调用score函数计算分数
    return f.score(ctx, pod, nodeInfo, s.podRequests)
}
```

#### getPreScoreState

```go
// getPreScoreState 用于获取PreScore阶段的状态信息
func getPreScoreState(cycleState *framework.CycleState) (*preScoreState, error) {
    c, err := cycleState.Read(preScoreStateKey) // 从CycleState中读取preScoreStateKey对应的状态信息
    if err != nil {
    	return nil, fmt.Errorf("reading %q from cycleState: %w", preScoreStateKey, err)
    }
    s, ok := c.(*preScoreState)
    if !ok {
        return nil, fmt.Errorf("invalid PreScore state, got type %T", c) // 如果获取到的状态信息不是*preScoreState类型，则返回错误
    }
    return s, nil
}
```

## NodeUnschedulable

### 作用

Kubernetes调度器中的NodeUnschedulable插件是一个预定义的插件，用于控制节点的调度。

当一个节点被标记为不可调度时，调度器将不会在该节点上创建新的Pod。这通常用于在节点上执行维护操作或其他不允许调度新Pod的情况下。

### 结构

```GO
// NodeUnschedulable 插件筛选设置 node.Spec.Unschedulable=true 的节点，
// 除非 pod 容忍 {key=node.kubernetes.io/unschedulable, effect:NoSchedule} 污点。
type NodeUnschedulable struct {
}

// NodeUnschedulable 实现了 framework.FilterPlugin 接口
// 和 framework.EnqueueExtensions 接口
var _ framework.FilterPlugin = &NodeUnschedulable{}
var _ framework.EnqueueExtensions = &NodeUnschedulable{}

// Name 是插件在插件注册表和配置中使用的名称。
const Name = names.NodeUnschedulable

const (
    // ErrReasonUnknownCondition 用于 NodeUnknownCondition 谓词错误。
    ErrReasonUnknownCondition = "node(s) had unknown conditions"
    // ErrReasonUnschedulable 用于 NodeUnschedulable 谓词错误。
    ErrReasonUnschedulable = "node(s) were unschedulable"
)

// Name 返回插件的名称。
func (pl *NodeUnschedulable) Name() string {
	return Name
}

// New 初始化一个新的插件并返回它。
func New(_ runtime.Object, _ framework.Handle) (framework.Plugin, error) {
	return &NodeUnschedulable{}, nil
}
```

### Filter

```GO
// 在过滤器扩展点处调用的过滤器。
func (pl *NodeUnschedulable) Filter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
    // 获取节点信息
    node := nodeInfo.Node()
    // 如果节点信息为空，则返回无法调度和无法解析的状态和错误原因。
    if node == nil {
    	return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonUnknownCondition)
    }
    // 如果 Pod 能容忍无法调度的污点，则也容忍 node.Spec.Unschedulable。
    // 通过调用 v1helper.TolerationsTolerateTaint() 函数判断 Pod 是否容忍 Taint。
    podToleratesUnschedulable := v1helper.TolerationsTolerateTaint(pod.Spec.Tolerations, &v1.Taint{
        Key: v1.TaintNodeUnschedulable,
        Effect: v1.TaintEffectNoSchedule,
    })
    // 如果节点处于无法调度状态且 Pod 无法容忍该状态，则返回无法调度和无法解析的状态和错误原因。
    if node.Spec.Unschedulable && !podToleratesUnschedulable {
    	return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReasonUnschedulable)
    }
    // 如果上述情况均不满足，则返回空。
    return nil
}
```

### EventsToRegister

```GO
// EventsToRegister 返回可能使 Pod 被此插件标记为无法调度的可能事件。
func (pl *NodeUnschedulable) EventsToRegister() []framework.ClusterEvent {
    return []framework.ClusterEvent{
    	{Resource: framework.Node, ActionType: framework.Add | framework.UpdateNodeTaint},
    }
}
```

