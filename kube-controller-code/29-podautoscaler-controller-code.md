
## 简介

Kubernetes  是一个开源的容器编排系统，可以自动化部署、扩展和管理容器化应用程序。在 Kubernetes 中，Pod 是最小的可部署对象，可以包含一个或多个容器。

Pod Autoscaler Controller 是 Kubernetes 的一个控制器，用于自动缩放 Pod 的数量。Pod Autoscaler Controller 监测指定的 Kubernetes 资源（例如 Deployment、ReplicaSet 或 StatefulSet）中的 CPU 使用率或自定义指标，并根据预定义的规则自动增加或减少 Pod 的数量。这可以确保应用程序具有所需的计算资源，而不会过度或低估分配。

Pod Autoscaler Controller 作为 Kubernetes 的一个重要组件，可以使应用程序更具弹性和稳定性，同时可以更好地利用资源，降低成本和提高效率。

## 结构体

```GO
type HorizontalController struct {
    // 与 Kubernetes API 服务器通信获取自动扩展目标资源对象的度量客户端
	scaleNamespacer scaleclient.ScalesGetter
    // 与 Kubernetes API 服务器通信获取水平自动扩展对象
	hpaNamespacer   autoscalingclient.HorizontalPodAutoscalersGetter
    // 管理 Kubernetes API 资源和 REST 端点之间的映射
	mapper          apimeta.RESTMapper
	// 用于计算目标 Pod 数量的 ReplicaCalculator 对象
	replicaCalc   *ReplicaCalculator
    // 记录事件的记录器
	eventRecorder record.EventRecorder
	// 在缩小容器数量时，为了避免过于频繁的缩小操作而添加的稳定时间窗口
	downscaleStabilisationWindow time.Duration
	// 监视节点的资源使用率
	monitor monitor.Monitor

	// HPA对象Lister
	hpaLister       autoscalinglisters.HorizontalPodAutoscalerLister
	hpaListerSynced cache.InformerSynced

	// pod对象Lister
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	// 同步需要更新的 HPA 控制器的工作队列
	queue workqueue.RateLimitingInterface

	// 最新的未稳定推荐，以每个自动扩展器为键的字典
	recommendations     map[string][]timestampedRecommendation
    // 保护 recommendations
	recommendationsLock sync.Mutex

	// 最新的自动扩展事件，用于增加容器数量
	scaleUpEvents       map[string][]timestampedScaleEvent
    // 保护 scaleUpEvents
	scaleUpEventsLock   sync.RWMutex
    // 最新的自动扩展事件，用于减少容器数量
	scaleDownEvents     map[string][]timestampedScaleEvent
	// 保护 scaleDownEvents
	scaleDownEventsLock sync.RWMutex

	// 存储 HPA 和其选择器的双向多对多映射
	hpaSelectors    *selectors.BiMultimap
    // 保护 hpaSelectors 
	hpaSelectorsMux sync.Mutex

	// 一个特性标记，指示是否启用容器资源指标
	containerResourceMetricsEnabled bool
}

type timestampedRecommendation struct {
	recommendation int32
	timestamp      time.Time
}

type timestampedScaleEvent struct {
	replicaChange int32 // absolute value, non-negative
	timestamp     time.Time
	outdated      bool
}
```

## MetricsClient

```GO
type MetricsClient interface {
	// 获取指定命名空间中匹配指定选择器的所有 Pod 的指定容器的给定资源度量值，如果 container 参数为空字符串，则返回所有容器度量值的总和。
	GetResourceMetric(ctx context.Context, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (PodMetricsInfo, time.Time, error)

	// 获取指定命名空间中匹配指定选择器的所有 Pod 的指定度量值及其最早时间戳
	GetRawMetric(metricName string, namespace string, selector labels.Selector, metricSelector labels.Selector) (PodMetricsInfo, time.Time, error)

	// 获取给定命名空间中指定对象的给定度量值及其时间戳
	GetObjectMetric(metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, metricSelector labels.Selector) (int64, time.Time, error)

	// 获取与指定选择器匹配的给定外部度量值的所有值
	GetExternalMetric(metricName string, namespace string, selector labels.Selector) ([]int64, time.Time, error)
}

type PodMetric struct {
	Timestamp time.Time
	Window    time.Duration
	Value     int64
}

// PodMetricsInfo包含pod度量，作为从pod名称到PodMetrics信息的映射
type PodMetricsInfo map[string]PodMetric
```

### restMetricsClient

```GO
type restMetricsClient struct {
	*resourceMetricsClient
	*customMetricsClient
	*externalMetricsClient
}
```

#### New

```go
func NewRESTMetricsClient(resourceClient resourceclient.PodMetricsesGetter, customClient customclient.CustomMetricsClient, externalClient externalclient.ExternalMetricsClient) MetricsClient {
	return &restMetricsClient{
		&resourceMetricsClient{resourceClient},
		&customMetricsClient{customClient},
		&externalMetricsClient{externalClient},
	}
}
```

### resourceMetricsClient

```GO
type resourceMetricsClient struct {
    // 获得 Kubernetes 核心资源度量值 可以用来获取 Pod、节点和命名空间的 CPU 和内存使用情况等度量值信息
	client resourceclient.PodMetricsesGetter
}
```

#### GetResourceMetric

```go
func (c *resourceMetricsClient) GetResourceMetric(ctx context.Context, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (PodMetricsInfo, time.Time, error) {
	// 从 API 服务器获取 Pod 的度量值
	metrics, err := c.client.PodMetricses(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		// 如果出现错误，返回错误信息
		return nil, time.Time{}, fmt.Errorf("unable to fetch metrics from resource metrics API: %v", err)
	}

	// 如果没有获取到 Pod 的度量值，返回错误信息
	if len(metrics.Items) == 0 {
		return nil, time.Time{}, fmt.Errorf("no metrics returned from resource metrics API")
	}

	var res PodMetricsInfo
	// 如果 container 参数不为空，则获取容器的度量值
	if container != "" {
		res, err = getContainerMetrics(metrics.Items, resource, container)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to get container metrics: %v", err)
		}
	} else {
		// 否则获取 Pod 的度量值
		res = getPodMetrics(ctx, metrics.Items, resource)
	}
	// 获取最新的时间戳
	timestamp := metrics.Items[0].Timestamp.Time
	return res, timestamp, nil
}

```

##### getContainerMetrics

```GO
func getContainerMetrics(rawMetrics []metricsapi.PodMetrics, resource v1.ResourceName, container string) (PodMetricsInfo, error) {
	// 使用make函数创建一个PodMetricsInfo类型的map，长度为rawMetrics的长度
	res := make(PodMetricsInfo, len(rawMetrics))
	// 遍历rawMetrics的每一个元素，使用_占位符忽略索引，m为rawMetrics的元素值
	for _, m := range rawMetrics {
		// 定义一个变量containerFound并初始化为false
		containerFound := false
		// 遍历m.Containers的每一个元素，使用_占位符忽略索引，c为m.Containers的元素值
		for _, c := range m.Containers {
			// 如果c.Name等于传入的container参数，将containerFound设为true
			if c.Name == container {
				containerFound = true
				// 如果c.Usage[resource]存在，则将值存储在val中，将resFound设为true
				if val, resFound := c.Usage[resource]; resFound {
					// 将PodMetric结构体赋值给res[m.Name]，其中Timestamp字段为m.Timestamp.Time，Window字段为m.Window.Duration，Value字段为val.MilliValue()
					res[m.Name] = PodMetric{
						Timestamp: m.Timestamp.Time,
						Window:    m.Window.Duration,
						Value:     val.MilliValue(),
					}
				}
				// 跳出循环
				break
			}
		}
		// 如果containerFound为false，返回nil和一个格式化的错误，提示container参数在m的namespace和name中不存在
		if !containerFound {
			return nil, fmt.Errorf("container %s not present in metrics for pod %s/%s", container, m.Namespace, m.Name)
		}
	}
	// 返回res和nil
	return res, nil
}

```

##### getPodMetrics

```GO
func getPodMetrics(ctx context.Context, rawMetrics []metricsapi.PodMetrics, resource v1.ResourceName) PodMetricsInfo {
	// 使用make函数创建一个PodMetricsInfo类型的map，长度为rawMetrics的长度
	res := make(PodMetricsInfo, len(rawMetrics))
	// 遍历rawMetrics的每一个元素，使用_占位符忽略索引，m为rawMetrics的元素值
	for _, m := range rawMetrics {
		// 定义一个变量podSum并初始化为0，missing初始化为true
		podSum := int64(0)
		missing := len(m.Containers) == 0
		// 遍历m.Containers的每一个元素，使用_占位符忽略索引，c为m.Containers的元素值
		for _, c := range m.Containers {
			// 如果c.Usage[resource]不存在，将missing设为true，输出日志并跳出循环
			resValue, found := c.Usage[resource]
			if !found {
				missing = true
				klog.FromContext(ctx).V(2).Info("Missing resource metric", "resourceMetric", resource, "pod", klog.KRef(m.Namespace, m.Name))
				break
			}
			// 将c.Usage[resource]的MilliValue加到podSum上
			podSum += resValue.MilliValue()
		}
		// 如果missing为false，则将PodMetric结构体赋值给res[m.Name]，其中Timestamp字段为m.Timestamp.Time，Window字段为m.Window.Duration，Value字段为podSum
		if !missing {
			res[m.Name] = PodMetric{
				Timestamp: m.Timestamp.Time,
				Window:    m.Window.Duration,
				Value:     podSum,
			}
		}
	}
	// 返回res
	return res
}

```

### customMetricsClient

```GO
type customMetricsClient struct {
	client customclient.CustomMetricsClient
}
```

#### GetRawMetric

```GO
func (c *customMetricsClient) GetRawMetric(metricName string, namespace string, selector labels.Selector, metricSelector labels.Selector) (PodMetricsInfo, time.Time, error) {
	// 调用client.NamespacedMetrics(namespace).GetForObjects方法获取metrics和err
	metrics, err := c.client.NamespacedMetrics(namespace).GetForObjects(schema.GroupKind{Kind: "Pod"}, selector, metricName, metricSelector)
	if err != nil {
		// 如果获取metrics的过程出现错误，返回nil, time.Time{}, 以err为参数调用fmt.Errorf函数构造一个错误类型的值
		return nil, time.Time{}, fmt.Errorf("unable to fetch metrics from custom metrics API: %v", err)
	}

	// 如果metrics的Items字段长度为0，返回nil, time.Time{}，以自定义的错误信息为参数调用fmt.Errorf函数构造一个错误类型的值
	if len(metrics.Items) == 0 {
		return nil, time.Time{}, fmt.Errorf("no metrics returned from custom metrics API")
	}

	// 创建一个PodMetricsInfo类型的map，长度为metrics.Items的长度
	res := make(PodMetricsInfo, len(metrics.Items))
	// 遍历metrics.Items的每一个元素，使用_占位符忽略索引，m为metrics.Items的元素值
	for _, m := range metrics.Items {
		// 如果m.WindowSeconds不为nil，则将window初始化为time.Duration类型的*m.WindowSeconds * time.Second，否则window为metricServerDefaultMetricWindow
		window := metricServerDefaultMetricWindow
		if m.WindowSeconds != nil {
			window = time.Duration(*m.WindowSeconds) * time.Second
		}
		// 将PodMetric结构体赋值给res[m.DescribedObject.Name]，其中Timestamp字段为m.Timestamp.Time，Window字段为window，Value字段为m.Value.MilliValue()
		res[m.DescribedObject.Name] = PodMetric{
			Timestamp: m.Timestamp.Time,
			Window:    window,
			Value:     int64(m.Value.MilliValue()),
		}

		// 调用m.Value.MilliValue()，但并未使用其返回值
		m.Value.MilliValue()
	}

	// 将metrics.Items的第一个元素的Timestamp.Time赋值给timestamp
	timestamp := metrics.Items[0].Timestamp.Time

	// 返回res，timestamp和nil
	return res, timestamp, nil
}
```

#### GetObjectMetric

```GO
func (c *customMetricsClient) GetObjectMetric(metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, metricSelector labels.Selector) (int64, time.Time, error) {
	// 从对象引用中获得GroupVersionKind
	gvk := schema.FromAPIVersionAndKind(objectRef.APIVersion, objectRef.Kind)
	var metricValue *customapi.MetricValue
	var err error
	if gvk.Kind == "Namespace" && gvk.Group == "" {
		// 如果对象是命名空间，那么我们需要在根级别调用RootScopedMetrics()函数
		// NB: 我们在这里忽略命名空间名称，因为CrossVersionObjectReference不应允许您逃脱您的命名空间
		metricValue, err = c.client.RootScopedMetrics().GetForObject(gvk.GroupKind(), namespace, metricName, metricSelector)
	} else {
		// 否则，对象是在特定的命名空间中，我们将使用NamespacedMetrics()函数
		metricValue, err = c.client.NamespacedMetrics(namespace).GetForObject(gvk.GroupKind(), objectRef.Name, metricName, metricSelector)
	}

	if err != nil {
		// 如果获取MetricValue失败，则返回错误
		return 0, time.Time{}, fmt.Errorf("unable to fetch metrics from custom metrics API: %v", err)
	}

	// 否则，我们将返回MetricValue中的值和时间戳
	return metricValue.Value.MilliValue(), metricValue.Timestamp.Time, nil
}
```

### externalMetricsClient

```GO
type externalMetricsClient struct {
	client externalclient.ExternalMetricsClient
}
```

### GetExternalMetric

```GO
func (c *externalMetricsClient) GetExternalMetric(metricName, namespace string, selector labels.Selector) ([]int64, time.Time, error) {
    // 使用外部的metrics API获取指定名称的metrics
    metrics, err := c.client.NamespacedMetrics(namespace).List(metricName, selector)
    if err != nil {
        // 如果获取失败，返回一个空的[]int64切片，time.Time类型的零值，和一个包含错误信息的error
        return []int64{}, time.Time{}, fmt.Errorf("unable to fetch metrics from external metrics API: %v", err)
    }

    // 如果获取到的metrics为空，返回nil，time.Time类型的零值，和一个包含错误信息的error
    if len(metrics.Items) == 0 {
        return nil, time.Time{}, fmt.Errorf("no metrics returned from external metrics API")
    }

    // 如果获取到的metrics不为空，从中提取指标值并将其添加到一个切片中
    res := make([]int64, 0)
    for _, m := range metrics.Items {
        res = append(res, m.Value.MilliValue())
    }

    // 获取第一个指标的时间戳并返回结果切片，时间戳和一个nil的error
    timestamp := metrics.Items[0].Timestamp.Time
    return res, timestamp, nil
}
```

## ReplicaCalculator

- 计算目标 Pod 数量

```go
type ReplicaCalculator struct {
	metricsClient                 metricsclient.MetricsClient
	podLister                     corelisters.PodLister
    // 指定容器指标值的允许波动范围，通常为 0.1
	tolerance                     float64
    // 指定在容器指标数据不足时计算 CPU 使用率的时间窗口，通常为 2 分钟
	cpuInitializationPeriod       time.Duration
    // 在启动 Pod 时等待一段时间以获取其就绪状态的延迟时间 通常为 10 秒
	delayOfInitialReadinessStatus time.Duration
}
```

### New

```go
func NewReplicaCalculator(metricsClient metricsclient.MetricsClient, podLister corelisters.PodLister, tolerance float64, cpuInitializationPeriod, delayOfInitialReadinessStatus time.Duration) *ReplicaCalculator {
	return &ReplicaCalculator{
		metricsClient:                 metricsClient,
		podLister:                     podLister,
		tolerance:                     tolerance,
		cpuInitializationPeriod:       cpuInitializationPeriod,
		delayOfInitialReadinessStatus: delayOfInitialReadinessStatus,
	}
}
```

### GetResourceReplicas

- 根据目标利用率、资源指标、namespace和选择器等参数计算资源的副本数和利用率

```go
func (c *ReplicaCalculator) GetResourceReplicas(ctx context.Context, currentReplicas int32, targetUtilization int32, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (replicaCount int32, utilization int32, rawUtilization int64, timestamp time.Time, err error) {
    // 获取资源的指标和时间戳
	metrics, timestamp, err := c.metricsClient.GetResourceMetric(ctx, resource, namespace, selector, container)
	if err != nil {
		return 0, 0, 0, time.Time{}, fmt.Errorf("unable to get metrics for resource %s: %v", resource, err)
	}
    // 获取pod列表
	podList, err := c.podLister.Pods(namespace).List(selector)
	if err != nil {
		return 0, 0, 0, time.Time{}, fmt.Errorf("unable to get pods while calculating replica count: %v", err)
	}
    // 如果pod列表为空，则返回错误
	if len(podList) == 0 {
		return 0, 0, 0, time.Time{}, fmt.Errorf("no pods returned by selector while calculating replica count")
	}
	// groupPods函数将pod分为已准备好的pod、未准备好的pod、缺失的pod和忽略的pod四种情况，并返回各种pod的数量
	readyPodCount, unreadyPods, missingPods, ignoredPods := groupPods(podList, metrics, resource, c.cpuInitializationPeriod, c.delayOfInitialReadinessStatus)
    // 移除忽略的pod和未准备好的pod的指标
	removeMetricsForPods(metrics, ignoredPods)
	removeMetricsForPods(metrics, unreadyPods)
    // 如果metrics为空，则返回错误
	if len(metrics) == 0 {
		return 0, 0, 0, time.Time{}, fmt.Errorf("did not receive metrics for targeted pods (pods might be unready)")
	}
	// calculatePodRequests函数计算pod的请求资源
	requests, err := calculatePodRequests(podList, container, resource)
	if err != nil {
		return 0, 0, 0, time.Time{}, err
	}
    // GetResourceUtilizationRatio函数计算资源的使用率比率、利用率和原始利用率
	usageRatio, utilization, rawUtilization, err := metricsclient.GetResourceUtilizationRatio(metrics, requests, targetUtilization)
	if err != nil {
		return 0, 0, 0, time.Time{}, err
	}
	// 如果存在未准备好的pod且使用率比率大于1，则进行扩容
	scaleUpWithUnready := len(unreadyPods) > 0 && usageRatio > 1.0
	if !scaleUpWithUnready && len(missingPods) == 0 {
		if math.Abs(1.0-usageRatio) <= c.tolerance {
			// 如果变化太小，则返回当前副本数
			return currentReplicas, utilization, rawUtilization, timestamp, nil
		}

		// 如果不存在未准备好的pod和缺失的pod，则现在可以计算新的副本数
		return int32(math.Ceil(usageRatio * float64(readyPodCount))), utilization, rawUtilization, timestamp, nil
	}

	if len(missingPods) > 0 {
		if usageRatio < 1.0 {
			// 在缩小规模时，将缺失的 Pod 视为使用其资源请求的 100%（全部）
			// 或对于大于 100% 的目标利用率，视为使用目标利用率
			fallbackUtilization := int64(max(100, targetUtilization))
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: requests[podName] * fallbackUtilization / 100}
			}
		} else if usageRatio > 1.0 {
			// 在扩容时，把缺失的 pod 视为使用 0% 的资源请求
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: 0}
			}
		}
	}

	if scaleUpWithUnready {
		// 在扩容时，把未就绪的 pod 视为使用 0% 的资源请求
		for podName := range unreadyPods {
			metrics[podName] = metricsclient.PodMetric{Value: 0}
		}
	}

	// 重新使用新的指标值运行利用率计算
	newUsageRatio, _, _, err := metricsclient.GetResourceUtilizationRatio(metrics, requests, targetUtilization)
	if err != nil {
		return 0, utilization, rawUtilization, time.Time{}, err
	}
	// 如果新的利用率变化量很小，或者新的利用率会导致扩缩容方向的改变，就返回当前的副本数和利用率
	if math.Abs(1.0-newUsageRatio) <= c.tolerance || (usageRatio < 1.0 && newUsageRatio > 1.0) || (usageRatio > 1.0 && newUsageRatio < 1.0) {
		// 如果改变太小，或新的利用率会导致扩缩容方向的改变，返回当前的副本数和利用率
		return currentReplicas, utilization, rawUtilization, timestamp, nil
	}
	// 计算新的副本数
	newReplicas := int32(math.Ceil(newUsageRatio * float64(len(metrics))))
    // 如果新的利用率导致扩缩容方向改变，就返回当前的副本数和利用率
	if (newUsageRatio < 1.0 && newReplicas > currentReplicas) || (newUsageRatio > 1.0 && newReplicas < currentReplicas) {
		// 如果新的利用率导致扩缩容方向改变，返回当前的副本数和利用率
		return currentReplicas, utilization, rawUtilization, timestamp, nil
	}

	// 返回计算所得的结果，其中考虑了计算中使用的副本数
	return newReplicas, utilization, rawUtilization, timestamp, nil
}
```

#### groupPods

```GO
// groupPods 用于按照指定条件对 Pod 列表进行分类
// 参数:
//    - pods：Pod 列表
//    - metrics: Metrics 容器，用于存储 Pod 的指标信息
//    - resource: 资源名，目前只支持 CPU
//    - cpuInitializationPeriod: 初始时间期间（Duration），CPU 指标计算中使用
//    - delayOfInitialReadinessStatus: 初始状态延迟（Duration），CPU 指标计算中使用
// 返回值:
//    - readyPodCount: 已就绪 Pod 数量
//    - unreadyPods: 未就绪 Pod 集合
//    - missingPods: 没有指标的 Pod 集合
//    - ignoredPods: 忽略的 Pod 集合（已删除或状态为 PodFailed）
func groupPods(pods []*v1.Pod, metrics metricsclient.PodMetricsInfo, resource v1.ResourceName, cpuInitializationPeriod, delayOfInitialReadinessStatus time.Duration) (readyPodCount int, unreadyPods, missingPods, ignoredPods sets.String) {
    missingPods = sets.NewString()  // 创建新的缺少指标的 Pod 集合
    unreadyPods = sets.NewString()  // 创建新的未就绪 Pod 集合
    ignoredPods = sets.NewString()  // 创建新的忽略的 Pod 集合
    for _, pod := range pods {  // 遍历 Pod 列表
        // 如果 Pod 已经被删除或状态为 PodFailed，则将其加入忽略的 Pod 集合并跳过
        if pod.DeletionTimestamp != nil || pod.Status.Phase == v1.PodFailed {
            ignoredPods.Insert(pod.Name)
            continue
        }
        // 如果 Pod 的状态为 Pending，则将其加入未就绪 Pod 集合并跳过
        if pod.Status.Phase == v1.PodPending {
            unreadyPods.Insert(pod.Name)
            continue
        }
        // 如果该 Pod 没有对应的 Metrics，将其加入缺少指标的 Pod 集合并跳过
        metric, found := metrics[pod.Name]
        if !found {
            missingPods.Insert(pod.Name)
            continue
        }
        // 如果该 Pod 未就绪，则将其加入未就绪 Pod 集合并跳过
        if resource == v1.ResourceCPU {
            var unready bool
            _, condition := podutil.GetPodCondition(&pod.Status, v1.PodReady)
            if condition == nil || pod.Status.StartTime == nil {
                unready = true
            } else {
                // 如果 Pod 仍处于可能的初始化期间，则不将其加入任何 Pod 集合
                if pod.Status.StartTime.Add(cpuInitializationPeriod).After(time.Now()) {
                    // 如果 Pod 未就绪或上一个状态转换后的时间窗口没有收集到指标，则将其加入未就绪 Pod 集合
                    unready = condition.Status == v1.ConditionFalse || metric.Timestamp.Before(condition.LastTransitionTime.Time.Add(metric.Window))
                } else {
                    // 如果 Pod 未就绪 则忽略度量
                    unready = condition.Status == v1.ConditionFalse && pod.Status.StartTime.Add(delayOfInitialReadinessStatus).After(condition.LastTransitionTime.Time)
				}
			}
			if unready {
				unreadyPods.Insert(pod.Name)
				continue
			}
		}
		readyPodCount++
	}
	return
}
```

#### removeMetricsForPods

```GO
func removeMetricsForPods(metrics metricsclient.PodMetricsInfo, pods sets.String) {
	for _, pod := range pods.UnsortedList() {
		delete(metrics, pod)
	}
}
```

#### calculatePodRequests

```GO
func calculatePodRequests(pods []*v1.Pod, container string, resource v1.ResourceName) (map[string]int64, error) {
    // 声明一个 map 类型的变量 requests，用于存储 Pod 的资源请求总量
	requests := make(map[string]int64, len(pods))
	// 遍历 pods 切片，对每个 Pod 执行以下操作
    for _, pod := range pods {
        // 初始化变量 podSum 为 0
        podSum := int64(0)

        // 遍历 Pod 中的容器，对每个容器执行以下操作
        for _, c := range pod.Spec.Containers {
            // 如果 container 为空或者容器名与 container 相同
            if container == "" || container == c.Name {
                // 检查该容器的资源请求中是否有 resource 这个资源名
                if containerRequest, ok := c.Resources.Requests[resource]; ok {
                    // 如果有，将容器的资源请求值转换为毫秒，然后加到 podSum 变量上
                    podSum += containerRequest.MilliValue()
                } else {
                    // 如果没有，返回一个错误，说明容器中缺少指定的资源请求
                    return nil, fmt.Errorf("missing request for %s in container %s of Pod %s", resource, c.Name, pod.ObjectMeta.Name)
                }
            }
        }
        // 将 Pod 的名称映射到资源请求总量
        requests[pod.Name] = podSum
    }
    // 返回 requests 映射和一个空的错误对象，表示函数执行成功
    return requests, nil
}
```

#### GetResourceUtilizationRatio

```GO
func GetResourceUtilizationRatio(metrics PodMetricsInfo, requests map[string]int64, targetUtilization int32) (utilizationRatio float64, currentUtilization int32, rawAverageValue int64, err error) {
	metricsTotal := int64(0)
	requestsTotal := int64(0)
	numEntries := 0

	// 遍历 metrics 映射，对每个 Pod 执行以下操作
    for podName, metric := range metrics {
        // 从 requests 映射中获取该 Pod 的资源请求总量
        request, hasRequest := requests[podName]
        // 如果 requests 映射中不存在该 Pod 的资源请求，则跳过该 Pod
        if !hasRequest {
            // 由于已经在其他地方检查了缺少请求的情况，所以我们认为缺少请求等同于冗余指标
            continue
        }
        // 计算 metricsTotal 和 requestsTotal，分别为所有 Pod 的指标值和请求总量之和
        metricsTotal += metric.Value
        requestsTotal += request
        numEntries++
    }

    // 如果请求的集合与指标集合完全不相交，则可能存在请求总量为零的问题
    if requestsTotal == 0 {
        return 0, 0, 0, fmt.Errorf("no metrics returned matched known pods")
    }

    // 计算当前利用率，并将其存储在 currentUtilization 变量中
    currentUtilization = int32((metricsTotal * 100) / requestsTotal)

    // 返回当前利用率与目标利用率的比率，当前利用率，每个 Pod 的平均资源利用率，以及一个空的错误对象，表示函数执行成功
    return float64(currentUtilization) / float64(targetUtilization), currentUtilization, metricsTotal / int64(numEntries), nil
}
```

### GetRawResourceReplicas

```GO
func (c *ReplicaCalculator) GetRawResourceReplicas(ctx context.Context, currentReplicas int32, targetUsage int64, resource v1.ResourceName, namespace string, selector labels.Selector, container string) (replicaCount int32, usage int64, timestamp time.Time, err error) {
	// 调用metricsClient结构体中的GetResourceMetric方法获取metrics、timestamp、err三个值
    metrics, timestamp, err := c.metricsClient.GetResourceMetric(ctx, resource, namespace, selector, container)

    // 如果有错误发生，返回错误信息
    if err != nil {
        return 0, 0, time.Time{}, fmt.Errorf("unable to get metrics for resource %s: %v", resource, err)
    }

    // 调用calcPlainMetricReplicas方法计算replicaCount、usage、err三个值
    replicaCount, usage, err = c.calcPlainMetricReplicas(metrics, currentReplicas, targetUsage, namespace, selector, resource)

    // 返回replicaCount、usage、timestamp、err四个值
    return replicaCount, usage, timestamp, err
}
```

#### calcPlainMetricReplicas

```go
func (c *ReplicaCalculator) calcPlainMetricReplicas(metrics metricsclient.PodMetricsInfo, currentReplicas int32, targetUsage int64, namespace string, selector labels.Selector, resource v1.ResourceName) (replicaCount int32, usage int64, err error) {

	// 通过 selector 和 namespace 获取 Pod 列表
	podList, err := c.podLister.Pods(namespace).List(selector)
	if err != nil {
		// 获取 Pod 列表失败
		return 0, 0, fmt.Errorf("unable to get pods while calculating replica count: %v", err)
	}

	if len(podList) == 0 {
		// Pod 列表为空
		return 0, 0, fmt.Errorf("no pods returned by selector while calculating replica count")
	}

	// 对 Pod 进行分类
	// readyPodCount 表示已经 ready 的 Pod 数量
	// unreadyPods 表示未 ready 的 Pod 数量
	// missingPods 表示不包含在 metrics 中的 Pod 数量
	// ignoredPods 表示被忽略的 Pod 数量
	readyPodCount, unreadyPods, missingPods, ignoredPods := groupPods(podList, metrics, resource, c.cpuInitializationPeriod, c.delayOfInitialReadinessStatus)
	// 从 metrics 中删除忽略和未 ready 的 Pod
	removeMetricsForPods(metrics, ignoredPods)
	removeMetricsForPods(metrics, unreadyPods)

	if len(metrics) == 0 {
		// 没有 Pod 的指标信息
		return 0, 0, fmt.Errorf("did not receive metrics for targeted pods (pods might be unready)")
	}

	// 获取 Pod 的利用率及总共的使用量
	usageRatio, usage := metricsclient.GetMetricUsageRatio(metrics, targetUsage)

	// 判断是否需要考虑未 ready 的 Pod
	scaleUpWithUnready := len(unreadyPods) > 0 && usageRatio > 1.0

	if !scaleUpWithUnready && len(missingPods) == 0 {
		if math.Abs(1.0-usageRatio) <= c.tolerance {
			// 如果变化的比例小于容差，则返回当前副本数
			return currentReplicas, usage, nil
		}

		// 如果不存在未 ready 或缺少的 Pod，则现在可以计算新的副本数
		return int32(math.Ceil(usageRatio * float64(readyPodCount))), usage, nil
	}

	if len(missingPods) > 0 {
		if usageRatio < 1.0 {
			// 在缩容时，将缺少的 Pod 视为使用目标数量
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: targetUsage}
			}
		} else {
			// 在扩容时，将缺少的 Pod 视为使用资源请求量的 0%
			for podName := range missingPods {
				metrics[podName] = metricsclient.PodMetric{Value: 0}
			}
		}
	}

	if scaleUpWithUnready {
		// 在扩容时，将未 ready 的 Pod 视为使用资源请求量的 0%
		for podName := range unreadyPods {
				metrics[podName] = metricsclient.PodMetric{Value: 0}
			}
		}
	}

	if scaleUpWithUnready {
		// 在扩容时，将未准备好的 pod 视为使用 0% 的资源请求
		for podName := range unreadyPods {
			metrics[podName] = metricsclient.PodMetric{Value: 0}
		}
	}

	// 使用新的值重新计算使用率
	newUsageRatio, _ := metricsclient.GetMetricUsageRatio(metrics, targetUsage)

	if math.Abs(1.0-newUsageRatio) <= c.tolerance || (usageRatio < 1.0 && newUsageRatio > 1.0) || (usageRatio > 1.0 && newUsageRatio < 1.0) {
		// 如果更改太小，或新的使用率会导致扩容方向的更改，则返回当前副本
		return currentReplicas, usage, nil
	}
	// 计算新的副本数
	newReplicas := int32(math.Ceil(newUsageRatio * float64(len(metrics))))
	if (newUsageRatio < 1.0 && newReplicas > currentReplicas) || (newUsageRatio > 1.0 && newReplicas < currentReplicas) {
		// 如果度量长度的更改会导致扩容方向的更改，则返回当前副本
		return currentReplicas, usage, nil
	}

	// 返回计算出的副本数，使用率及错误信息
	// 所考虑的副本数是我们的计算所涉及的副本数
	return newReplicas, usage, nil
}
```

##### GetMetricUsageRatio

```go
func GetMetricUsageRatio(metrics PodMetricsInfo, targetUsage int64) (usageRatio float64, currentUsage int64) {
	metricsTotal := int64(0)
    // 对于每个度量值计算总和
	for _, metric := range metrics {
		metricsTotal += metric.Value
	}
	// 计算当前使用量
	currentUsage = metricsTotal / int64(len(metrics))
	// 返回使用率比率和当前使用量
	return float64(currentUsage) / float64(targetUsage), currentUsage
}
```

### GetMetricReplicas

```go
func (c *ReplicaCalculator) GetMetricReplicas(currentReplicas int32, targetUsage int64, metricName string, namespace string, selector labels.Selector, metricSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 获取原始的指标数据
	metrics, timestamp, err := c.metricsClient.GetRawMetric(metricName, namespace, selector, metricSelector)
	if err != nil {
        // 获取指标数据出错时，返回错误信息
		return 0, 0, time.Time{}, fmt.Errorf("unable to get metric %s: %v", metricName, err)
	}
	// 根据原始指标数据计算Pod数量和使用情况
	replicaCount, usage, err = c.calcPlainMetricReplicas(metrics, currentReplicas, targetUsage, namespace, selector, v1.ResourceName(""))
	return replicaCount, usage, timestamp, err
}
```

### GetObjectMetricReplicas

```go
func (c *ReplicaCalculator) GetObjectMetricReplicas(currentReplicas int32, targetUsage int64, metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, selector labels.Selector, metricSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 使用指定的 metricName、namespace、objectRef 和 metricSelector 等参数获取对象指标的使用量。
	usage, _, err = c.metricsClient.GetObjectMetric(metricName, namespace, objectRef, metricSelector)
	if err != nil {
        // 如果出错，返回错误信息。
		return 0, 0, time.Time{}, fmt.Errorf("unable to get metric %s: %v on %s %s/%s", metricName, objectRef.Kind, namespace, objectRef.Name, err)
	}
	// 计算对象指标的使用率。
	usageRatio := float64(usage) / float64(targetUsage)
    // 使用当前的使用率和其他参数计算对象指标的副本数量，返回值为 replicaCount、timestamp 和 err。
	replicaCount, timestamp, err = c.getUsageRatioReplicaCount(currentReplicas, usageRatio, namespace, selector)
	return replicaCount, usage, timestamp, err
}
```

#### getUsageRatioReplicaCount

```go
func (c *ReplicaCalculator) getUsageRatioReplicaCount(currentReplicas int32, usageRatio float64, namespace string, selector labels.Selector) (replicaCount int32, timestamp time.Time, err error) {
    // 如果当前的副本数量不为 0
    if currentReplicas != 0 {
        // 如果变化太小，就返回当前的副本数量
        if math.Abs(1.0-usageRatio) <= c.tolerance {
            return currentReplicas, timestamp, nil
        }
        // 获取已经就绪的 Pod 数量
        readyPodCount := int64(0)
        readyPodCount, err = c.getReadyPodsCount(namespace, selector)
        if err != nil {
            return 0, time.Time{}, fmt.Errorf("unable to calculate ready pods: %s", err)
        }
        // 根据 usageRatio 和已就绪 Pod 数量计算新的副本数量
        replicaCount = int32(math.Ceil(usageRatio * float64(readyPodCount)))
    } else {
        // 如果当前的副本数量为 0，则根据 usageRatio 决定是缩容到 0 还是扩容到 n 个 Pod
        replicaCount = int32(math.Ceil(usageRatio))
    }

    return replicaCount, timestamp, err
}
```

#### getReadyPodsCount

```go
func (c *ReplicaCalculator) getReadyPodsCount(namespace string, selector labels.Selector) (int64, error) {
    // 根据选择器获取 Namespace 中匹配的 Pod 列表
    podList, err := c.podLister.Pods(namespace).List(selector)
    if err != nil {
        return 0, fmt.Errorf("unable to get pods while calculating replica count: %v", err)
    }

    // 如果 Pod 列表为空，则返回错误
    if len(podList) == 0 {
        return 0, fmt.Errorf("no pods returned by selector while calculating replica count")
    }

    readyPodCount := 0
    // 遍历 Pod 列表，计算准备好的 Pod 数量
    for _, pod := range podList {
        if pod.Status.Phase == v1.PodRunning && podutil.IsPodReady(pod) {
            readyPodCount++
        }
    }
    return int64(readyPodCount), nil
}
```

### GetObjectPerPodMetricReplicas

```go
func (c *ReplicaCalculator) GetObjectPerPodMetricReplicas(statusReplicas int32, targetAverageUsage int64, metricName string, namespace string, objectRef *autoscaling.CrossVersionObjectReference, metricSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 获取指定对象在指定 Namespace 中的指定指标的使用情况和时间戳
    usage, timestamp, err = c.metricsClient.GetObjectMetric(metricName, namespace, objectRef, metricSelector)
    if err != nil {
        return 0, 0, time.Time{}, fmt.Errorf("unable to get metric %s: %v on %s %s/%s", metricName, objectRef.Kind, namespace, objectRef.Name, err)
    }

    // 初始的副本数量为目前的副本数量
    replicaCount = statusReplicas

    // 计算当前使用率与目标使用率的比率
    usageRatio := float64(usage) / (float64(targetAverageUsage) * float64(replicaCount))
    // 如果变化太小，则不修改副本数量
    if math.Abs(1.0-usageRatio) > c.tolerance {
        // 否则根据使用率和目标使用率计算新的副本数量
        replicaCount = int32(math.Ceil(float64(usage) / float64(targetAverageUsage)))
    }
    // 计算每个 Pod 的使用量
    usage = int64(math.Ceil(float64(usage) / float64(statusReplicas)))
    return replicaCount, usage, timestamp, nil
}
```

### GetExternalMetricReplicas

```go
func (c *ReplicaCalculator) GetExternalMetricReplicas(currentReplicas int32, targetUsage int64, metricName, namespace string, metricSelector *metav1.LabelSelector, podSelector labels.Selector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 将 metav1.LabelSelector 转换为 labels.Selector
    metricLabelSelector, err := metav1.LabelSelectorAsSelector(metricSelector)
    if err != nil {
        return 0, 0, time.Time{}, err
    }

    // 获取外部指标的值
    metrics, _, err := c.metricsClient.GetExternalMetric(metricName, namespace, metricLabelSelector)
    if err != nil {
        return 0, 0, time.Time{}, fmt.Errorf("unable to get external metric %s/%s/%+v: %s", namespace, metricName, metricSelector, err)
    }

    // 计算使用率
    usage = 0
    for _, val := range metrics {
        usage = usage + val
    }
    usageRatio := float64(usage) / float64(targetUsage)

    // 根据使用率计算所需的副本数
    replicaCount, timestamp, err = c.getUsageRatioReplicaCount(currentReplicas, usageRatio, namespace, podSelector)
    return replicaCount, usage, timestamp, err
}

```

### GetExternalPerPodMetricReplicas

```go
func (c *ReplicaCalculator) GetExternalPerPodMetricReplicas(statusReplicas int32, targetUsagePerPod int64, metricName, namespace string, metricSelector *metav1.LabelSelector) (replicaCount int32, usage int64, timestamp time.Time, err error) {
    // 转换metricSelector标签选择器为selector
	metricLabelSelector, err := metav1.LabelSelectorAsSelector(metricSelector)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
    // 从c.metricsClient中获取外部度量信息，使用metricName，namespace和metricSelector过滤结果
	// 获取到的度量值保存在metrics变量中，时间戳保存在timestamp中
	metrics, timestamp, err := c.metricsClient.GetExternalMetric(metricName, namespace, metricLabelSelector)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("unable to get external metric %s/%s/%+v: %s", namespace, metricName, metricSelector, err)
	}
	usage = 0
    // 计算度量值的总和
	for _, val := range metrics {
		usage = usage + val
	}

	// 复制statusReplicas值到replicaCount变量
    replicaCount = statusReplicas
    // 计算当前用量与目标用量之比，使用float64类型的usageRatio变量保存
    usageRatio := float64(usage) / (float64(targetUsagePerPod) * float64(replicaCount))
    // 如果用量比例变化大于tolerance，则更新replicaCount
    if math.Abs(1.0-usageRatio) > c.tolerance {
        // 更新replicaCount以使用量符合目标用量
        replicaCount = int32(math.Ceil(float64(usage) / float64(targetUsagePerPod)))
    }
    // 计算平均用量并将其存储在usage变量中
    usage = int64(math.Ceil(float64(usage) / float64(statusReplicas)))
    return replicaCount, usage, timestamp, nil
}
```

## Monitor

```GO
type Monitor interface {
    // 监视并报告控制器的协调操作（reconciliation operation）的结果，记录操作类型（例如ScaleUp、ScaleDown、Check等）、
    // 错误类型（例如NoScale、ScaleFailed、FetchFailed等）和操作持续时间（duration）。
	ObserveReconciliationResult(action ActionLabel, err ErrorLabel, duration time.Duration)
    // 监视并报告度量计算的结果，记录计算类型（例如GetExternalMetric、GetResourceMetric等）、
    // 错误类型（例如GetMetricFailed、ParseMetricFailed等）、计算持续时间（duration）和度量源类型（metricType）。
	ObserveMetricComputationResult(action ActionLabel, err ErrorLabel, duration time.Duration, metricType v2.MetricSourceType)
}
```

```GO
// 控制器执行的操作类型
type ActionLabel string
// 控制器的错误类型
type ErrorLabel string

const (
	ActionLabelScaleUp   ActionLabel = "scale_up"
	ActionLabelScaleDown ActionLabel = "scale_down"
	ActionLabelNone      ActionLabel = "none"

	// 表示由于HPA对象的无效规范而产生的错误类型
	ErrorLabelSpec ErrorLabel = "spec"
	// 表示由于内部计算或与其他组件通信而产生的错误类型
	ErrorLabelInternal ErrorLabel = "internal"
    // 表示节点错误类型
	ErrorLabelNone     ErrorLabel = "none"
)
```

### 实现

```go
type monitor struct{}

func New() Monitor {
	return &monitor{}
}

func (r *monitor) ObserveReconciliationResult(action ActionLabel, err ErrorLabel, duration time.Duration) {
	reconciliationsTotal.WithLabelValues(string(action), string(err)).Inc()
	reconciliationsDuration.WithLabelValues(string(action), string(err)).Observe(duration.Seconds())
}

func (r *monitor) ObserveMetricComputationResult(action ActionLabel, err ErrorLabel, duration time.Duration, metricType v2.MetricSourceType) {
	metricComputationTotal.WithLabelValues(string(action), string(err), string(metricType)).Inc()
	metricComputationDuration.WithLabelValues(string(action), string(err), string(metricType)).Observe(duration.Seconds())
}
```

### metrics

```GO

const (
	// hpaControllerSubsystem - subsystem name used by HPA controller
	hpaControllerSubsystem = "horizontal_pod_autoscaler_controller"
)

var (
	reconciliationsTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "reconciliations_total",
			Help:           "Number of reconciliations of HPA controller. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. Also, the label 'error' should be either 'spec', 'internal', or 'none'. Note that if both spec and internal errors happen during a reconciliation, the first one to occur is reported in `error` label.",
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error"})

	reconciliationsDuration = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "reconciliation_duration_seconds",
			Help:           "The time(seconds) that the HPA controller takes to reconcile once. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. Also, the label 'error' should be either 'spec', 'internal', or 'none'. Note that if both spec and internal errors happen during a reconciliation, the first one to occur is reported in `error` label.",
			Buckets:        metrics.ExponentialBuckets(0.001, 2, 15),
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error"})
	metricComputationTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "metric_computation_total",
			Help:           "Number of metric computations. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. Also, the label 'error' should be either 'spec', 'internal', or 'none'. The label 'metric_type' corresponds to HPA.spec.metrics[*].type",
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error", "metric_type"})
	metricComputationDuration = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Subsystem:      hpaControllerSubsystem,
			Name:           "metric_computation_duration_seconds",
			Help:           "The time(seconds) that the HPA controller takes to calculate one metric. The label 'action' should be either 'scale_down', 'scale_up', or 'none'. The label 'error' should be either 'spec', 'internal', or 'none'. The label 'metric_type' corresponds to HPA.spec.metrics[*].type",
			Buckets:        metrics.ExponentialBuckets(0.001, 2, 15),
			StabilityLevel: metrics.ALPHA,
		}, []string{"action", "error", "metric_type"})

	metricsList = []metrics.Registerable{
		reconciliationsTotal,
		reconciliationsDuration,
		metricComputationTotal,
		metricComputationDuration,
	}
)

var register sync.Once

// Register all metrics.
func Register() {
	// Register the metrics.
	register.Do(func() {
		registerMetrics(metricsList...)
	})
}

// RegisterMetrics registers a list of metrics.
func registerMetrics(extraMetrics ...metrics.Registerable) {
	for _, metric := range extraMetrics {
		legacyregistry.MustRegister(metric)
	}
}
```

## New

```GO
func NewHorizontalController(
	evtNamespacer v1core.EventsGetter,
	scaleNamespacer scaleclient.ScalesGetter,
	hpaNamespacer autoscalingclient.HorizontalPodAutoscalersGetter,
	mapper apimeta.RESTMapper,
	metricsClient metricsclient.MetricsClient,
	hpaInformer autoscalinginformers.HorizontalPodAutoscalerInformer,
	podInformer coreinformers.PodInformer,
	resyncPeriod time.Duration,
	downscaleStabilisationWindow time.Duration,
	tolerance float64,
	cpuInitializationPeriod,
	delayOfInitialReadinessStatus time.Duration,
	containerResourceMetricsEnabled bool,
) *HorizontalController {
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: evtNamespacer.Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "horizontal-pod-autoscaler"})

	hpaController := &HorizontalController{
		eventRecorder:                   recorder,
		scaleNamespacer:                 scaleNamespacer,
		hpaNamespacer:                   hpaNamespacer,
		downscaleStabilisationWindow:    downscaleStabilisationWindow,
		monitor:                         monitor.New(),
		queue:                           workqueue.NewNamedRateLimitingQueue(NewDefaultHPARateLimiter(resyncPeriod), "horizontalpodautoscaler"),
		mapper:                          mapper,
		recommendations:                 map[string][]timestampedRecommendation{},
		recommendationsLock:             sync.Mutex{},
		scaleUpEvents:                   map[string][]timestampedScaleEvent{},
		scaleUpEventsLock:               sync.RWMutex{},
		scaleDownEvents:                 map[string][]timestampedScaleEvent{},
		scaleDownEventsLock:             sync.RWMutex{},
		hpaSelectors:                    selectors.NewBiMultimap(),
		containerResourceMetricsEnabled: containerResourceMetricsEnabled,
	}
	// 监控hoa对象
	hpaInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    hpaController.enqueueHPA,
			UpdateFunc: hpaController.updateHPA,
			DeleteFunc: hpaController.deleteHPA,
		},
		resyncPeriod,
	)
	hpaController.hpaLister = hpaInformer.Lister()
	hpaController.hpaListerSynced = hpaInformer.Informer().HasSynced

	hpaController.podLister = podInformer.Lister()
	hpaController.podListerSynced = podInformer.Informer().HasSynced

	replicaCalc := NewReplicaCalculator(
		metricsClient,
		hpaController.podLister,
		tolerance,
		cpuInitializationPeriod,
		delayOfInitialReadinessStatus,
	)
	hpaController.replicaCalc = replicaCalc

	monitor.Register()

	return hpaController
}
```

### hpa

```GO
func (a *HorizontalController) enqueueHPA(obj interface{}) {
	// 将 HPA 对象添加到队列中等待处理

	key, err := controller.KeyFunc(obj) // 获取对象的键值
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err)) // 处理获取键值错误
		return
	}

	// 请求总是以 resyncPeriod 延迟添加到队列中。如果队列中已经存在相同的 HPA 请求，则新的请求会被丢弃。
	// 请求在队列中等待 resyncPeriod 的时间，因此 HPAs 每个 resyncPeriod 都会被处理。
	a.queue.AddRateLimited(key)

	// 如果 hpaSelectors map 中不存在当前 HPA 对象的键值，则将其注册到 hpaSelectors map 中。
	// 将 Nothing 选择器附加到注册的键值，该选择器不会选择任何对象。
	// 实际的选择器会在 autoscaler 调谐过程中更新。
	a.hpaSelectorsMux.Lock()
	defer a.hpaSelectorsMux.Unlock()
	if hpaKey := selectors.Parse(key); !a.hpaSelectors.SelectorExists(hpaKey) {
		a.hpaSelectors.PutSelector(hpaKey, labels.Nothing())
	}
}

func (a *HorizontalController) updateHPA(old, cur interface{}) {
	a.enqueueHPA(cur)
}


func (a *HorizontalController) deleteHPA(obj interface{}) {
	// 删除 HPA 对象及其关联的选择器

	key, err := controller.KeyFunc(obj) // 获取对象的键值
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err)) // 处理获取键值错误
		return
	}

	// 从队列中移除 HPA 对象的键值
	// TODO: 如果获取键值失败，是否会导致资源泄漏？
	a.queue.Forget(key)

	// 从 hpaSelectors map 中删除 HPA 对象的键值及其关联的选择器
	a.hpaSelectorsMux.Lock()
	defer a.hpaSelectorsMux.Unlock()
	a.hpaSelectors.DeleteSelector(selectors.Parse(key))
}
```

### hpaSelectors

```GO
type BiMultimap struct {
	mux sync.RWMutex // 读写锁，用于保护该结构体的并发访问

	// 对象
	labeledObjects   map[Key]*labeledObject           // 存储按标签标记的对象的映射，键为 Key 类型，值为 labeledObject 指针类型
	selectingObjects map[Key]*selectingObject         // 存储按选择器标记的对象的映射，键为 Key 类型，值为 selectingObject 指针类型

	// 关联
	labeledBySelecting map[selectorKey]*labeledObjects // 存储按选择器关联的标签标记的对象的映射，键为 selectorKey 类型，值为 labeledObjects 指针类型
	selectingByLabeled map[labelsKey]*selectingObjects // 存储按标签关联的选择器标记的对象的映射，键为 labelsKey 类型，值为 selectingObjects 指针类型
}

func NewBiMultimap() *BiMultimap {
	return &BiMultimap{
		labeledObjects:     make(map[Key]*labeledObject),
		selectingObjects:   make(map[Key]*selectingObject),
		labeledBySelecting: make(map[selectorKey]*labeledObjects),
		selectingByLabeled: make(map[labelsKey]*selectingObjects),
	}
}
```

#### KeyValue

```go
type selectorKey struct {
	key       string      // 选择器的键
	namespace string      // 选择器的命名空间
}

type selectingObject struct {
	key         Key               // 选择器标记的对象的键
	selector    pkglabels.Selector // 选择器
	selectorKey selectorKey        // selectorKey 是选择器的稳定序列化形式，用于关联缓存
}

type selectingObjects struct {
	objects  map[Key]*selectingObject // 选择器标记的对象的映射，键为 Key 类型，值为 selectingObject 指针类型
	refCount int                      // 引用计数，用于记录该选择器标记的对象的引用数
}

type labelsKey struct {
	key       string      // 标签的键
	namespace string      // 标签的命名空间
}

type labeledObject struct {
	key       Key              // 标签标记的对象的键
	labels    map[string]string // 标签
	labelsKey labelsKey         // labelsKey 是标签的稳定序列化形式，用于关联缓存
}

type labeledObjects struct {
	objects  map[Key]*labeledObject // 标签标记的对象的映射，键为 Key 类型，值为 labeledObject 指针类型
	refCount int                   // 引用计数，用于记录该标签标记的对象的引用数
}
```

#### Put

```go
func (m *BiMultimap) Put(key Key, labels map[string]string) {
	m.mux.Lock() // 获取互斥锁，确保数据一致性
	defer m.mux.Unlock() // 在函数执行完毕后释放互斥锁

	labelsKey := labelsKey{
		key:       pkglabels.Set(labels).String(), // 生成 labels 的稳定序列化形式
		namespace: key.Namespace, // 使用传入的 key 参数的命名空间
	}
	if l, ok := m.labeledObjects[key]; ok { // 检查是否已存在对应的 labeledObject
		// 更新 labeled object。
		if labelsKey == l.labelsKey { // 检查 labels 是否有变化
			// 标签没有变化，无需更新
			return
		}
		// 在重新添加之前删除原有的 labeledObject
		m.delete(key)
	}
	// 添加 labeled object。
	labels = copyLabels(labels) // 复制 labels，以防止对原始 map 的修改影响到其他地方
	labeledObject := &labeledObject{
		key:       key,
		labels:    labels,
		labelsKey: labelsKey,
	}
	m.labeledObjects[key] = labeledObject // 将 labeledObject 添加到 labeledObjects map 中

	// 添加关联。
	if _, ok := m.selectingByLabeled[labelsKey]; !ok {
		// 缓存未命中，扫描 selecting objects。
		selecting := &selectingObjects{
			objects: make(map[Key]*selectingObject),
		}
		set := pkglabels.Set(labels) // 将 labels 转换为 pkglabels.Set 对象
		for _, s := range m.selectingObjects {
			if s.key.Namespace != key.Namespace { // 检查命名空间是否匹配
				continue
			}
			if s.selector.Matches(set) { // 检查 selector 是否匹配 labels
				selecting.objects[s.key] = s
			}
		}
		// 将 selectingObjects 与 labeledObjects 关联起来
		m.selectingByLabeled[labelsKey] = selecting
	}
	selecting := m.selectingByLabeled[labelsKey]
	selecting.refCount++
	for _, sObject := range selecting.objects {
		// 将 labeledObject 与 selectingObject 关联起来
		labeled := m.labeledBySelecting[sObject.selectorKey]
		labeled.objects[labeledObject.key] = labeledObject
	}
}
```

##### delete

```go
func (m *BiMultimap) delete(key Key) {
	if _, ok := m.labeledObjects[key]; !ok {
		// 不存在，无需删除
		return
	}
	labeledObject := m.labeledObjects[key]
	labelsKey := labeledObject.labelsKey
	defer delete(m.labeledObjects, key)  // 在函数结束时删除 key 对应的 labeledObject
	if _, ok := m.selectingByLabeled[labelsKey]; !ok {
		// 没有关联的 selectingObjects，无需删除
		return
	}
	// 移除关联
	for _, selectingObject := range m.selectingByLabeled[labelsKey].objects {
		selectorKey := selectingObject.selectorKey
		// 删除 selectingObject 到 labeledObject 的关联
		delete(m.labeledBySelecting[selectorKey].objects, key)
	}
	m.selectingByLabeled[labelsKey].refCount--
	// 回收 labeledObject 到 selectingObject 的关联
	if m.selectingByLabeled[labelsKey].refCount == 0 {
		delete(m.selectingByLabeled, labelsKey)
	}
}
```

##### copyLabels

```go
func copyLabels(labels map[string]string) map[string]string {
	l := make(map[string]string)
	for k, v := range labels {
		l[k] = v
	}
	return l
}
```

#### Delete

```go
func (m *BiMultimap) Delete(key Key) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.delete(key)
}
```

#### Exists

```go
func (m *BiMultimap) Exists(key Key) bool {
	m.mux.Lock()
	defer m.mux.Unlock()

	_, exists := m.labeledObjects[key]
	return exists
}
```

#### PutSelector

```go
func (m *BiMultimap) PutSelector(key Key, selector pkglabels.Selector) {
	m.mux.Lock()  // 加锁，保证并发安全
	defer m.mux.Unlock()  // 函数结束时解锁

	selectorKey := selectorKey{
		key:       selector.String(),
		namespace: key.Namespace,
	}
	if s, ok := m.selectingObjects[key]; ok {
		// 更新已存在的 selecting object。
		if selectorKey == s.selectorKey {
			// selector 没有改变，无需操作。
			return
		}
		// 先删除再添加。
		m.deleteSelector(key)
	}
	// 添加 selecting object。
	selectingObject := &selectingObject{
		key:         key,
		selector:    selector,
		selectorKey: selectorKey,
	}
	m.selectingObjects[key] = selectingObject
	// 添加关联。
	if _, ok := m.labeledBySelecting[selectorKey]; !ok {
		// 缓存未命中，扫描 labeled objects。
		labeled := &labeledObjects{
			objects: make(map[Key]*labeledObject),
		}
		for _, l := range m.labeledObjects {
			if l.key.Namespace != key.Namespace {
				continue
			}
			set := pkglabels.Set(l.labels)
			if selector.Matches(set) {
				labeled.objects[l.key] = l
			}
		}
		// 将 labeled 与 selecting 关联。
		m.labeledBySelecting[selectorKey] = labeled
	}
	labeled := m.labeledBySelecting[selectorKey]
	labeled.refCount++
	for _, labeledObject := range labeled.objects {
		// 将 selecting 与 labeled 关联。
		selecting := m.selectingByLabeled[labeledObject.labelsKey]
		selecting.objects[selectingObject.key] = selectingObject
	}
}
```

##### deleteSelector

```go
func (m *BiMultimap) deleteSelector(key Key) {
	// 删除选择对象
	if _, ok := m.selectingObjects[key]; !ok {
		// 选择对象不存在，直接返回
		return
	}
	selectingObject := m.selectingObjects[key] // 获取选择对象
	selectorKey := selectingObject.selectorKey // 获取选择对象的选择器键

	defer delete(m.selectingObjects, key) // 在函数结束时从选择对象中删除对应的键值对

	if _, ok := m.labeledBySelecting[selectorKey]; !ok {
		// 没有关联的对象
		return
	}

	// 移除关联
	for _, labeledObject := range m.labeledBySelecting[selectorKey].objects {
		labelsKey := labeledObject.labelsKey // 获取标记对象的标签键
		// 删除标记对象到选择对象的关联
		delete(m.selectingByLabeled[labelsKey].objects, key)
	}

	m.labeledBySelecting[selectorKey].refCount-- // 减少标记对象对选择对象的引用计数

	// 垃圾回收，删除无引用的关联
	if m.labeledBySelecting[selectorKey].refCount == 0 {
		delete(m.labeledBySelecting, selectorKey)
	}
}
```

#### DeleteSelector

```go
func (m *BiMultimap) DeleteSelector(key Key) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.deleteSelector(key)
}
```

#### SelectorExists

```go
func (m *BiMultimap) SelectorExists(key Key) bool {
	m.mux.Lock()
	defer m.mux.Unlock()

	_, exists := m.selectingObjects[key]
	return exists
}
```

#### KeepOnly

```go
func (m *BiMultimap) KeepOnly(keys []Key) {
	m.mux.Lock() // 对 m 进行加锁，保证并发安全
	defer m.mux.Unlock() // 在函数结束时解锁 m

	keyMap := make(map[Key]bool) // 创建一个用于存储传入的 keys 的 map
	for _, k := range keys {
		keyMap[k] = true // 将 keys 中的每个键添加到 map 中，并设置对应的值为 true
	}
	for k := range m.labeledObjects { // 遍历 labeledObjects 中的每个键
		if !keyMap[k] { // 如果键 k 不在 keyMap 中，即不在传入的 keys 中
			m.delete(k) // 则调用 delete 方法删除该键对应的关联关系
		}
	}
}
```

#### KeepOnlySelectors

```go
func (m *BiMultimap) KeepOnlySelectors(keys []Key) {
	m.mux.Lock() // 对 m 进行加锁，保证并发安全
	defer m.mux.Unlock() // 在函数结束时解锁 m

	keyMap := make(map[Key]bool) // 创建一个用于存储传入的 keys 的 map
	for _, k := range keys {
		keyMap[k] = true // 将 keys 中的每个键添加到 map 中，并设置对应的值为 true
	}
	for k := range m.selectingObjects { // 遍历 selectingObjects 中的每个键
		if !keyMap[k] { // 如果键 k 不在 keyMap 中，即不在传入的 keys 中
			m.deleteSelector(k) // 则调用 deleteSelector 方法删除该键对应的关联关系
		}
	}
}
```

#### Select

```go
func (m *BiMultimap) Select(key Key) (keys []Key, ok bool) {
	m.mux.RLock() // 对 m 进行读锁，保证并发安全
	defer m.mux.RUnlock() // 在函数结束时解锁 m

	selectingObject, ok := m.selectingObjects[key] // 获取 key 对应的 selectingObject，并判断是否存在
	if !ok { // 如果 selectingObject 不存在
		// 不存在关联关系
		return nil, false // 返回空切片和 false
	}

	keys = make([]Key, 0) // 创建一个空切片用于存储关联的 keys
	if labeled, ok := m.labeledBySelecting[selectingObject.selectorKey]; ok { // 获取 selectingObject 对应的 labeledObject，并判断是否存在
		for _, labeledObject := range labeled.objects { // 遍历 labeledObject 列表
			keys = append(keys, labeledObject.key) // 将每个 labeledObject 对应的 key 添加到 keys 切片中
		}
	}
	return keys, true // 返回关联的 keys 切片和 true，表示关联关系存在
}
```

#### ReverseSelect

```go
func (m *BiMultimap) ReverseSelect(key Key) (keys []Key, ok bool) {
	m.mux.RLock() // 对 m 进行读锁，保证并发安全
	defer m.mux.RUnlock() // 解锁 m

	labeledObject, ok := m.labeledObjects[key] // 根据 key 在 labeledObjects 中查找 labeledObject
	if !ok {
		// 不存在
		return []Key{}, false
	}
	keys = make([]Key, 0)
	if selecting, ok := m.selectingByLabeled[labeledObject.labelsKey]; ok {
		// 如果 labeledObject.labelsKey 在 selectingByLabeled 中存在
		for _, selectingObject := range selecting.objects {
			// 遍历 selectingObject，将其 key 添加到 keys 中
			keys = append(keys, selectingObject.key)
		}
	}
	return keys, true // 返回 keys 和 true 表示找到了匹配的 keys
}
```

## Run

```go
func (a *HorizontalController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer a.queue.ShutDown()

	logger := klog.FromContext(ctx)
	logger.Info("Starting HPA controller")
	defer logger.Info("Shutting down HPA controller")

	if !cache.WaitForNamedCacheSync("HPA", ctx.Done(), a.hpaListerSynced, a.podListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, a.worker, time.Second)
	}

	<-ctx.Done()
}
```

## worker

```go
func (a *HorizontalController) worker(ctx context.Context) {
	for a.processNextWorkItem(ctx) {
	}
	logger := klog.FromContext(ctx)
	logger.Info("Horizontal Pod Autoscaler controller worker shutting down")
}

func (a *HorizontalController) processNextWorkItem(ctx context.Context) bool {
	key, quit := a.queue.Get() // 从队列中获取下一个工作项
	if quit {
		return false // 如果获取到的是 quit 信号，则返回 false 表示处理结束
	}
	defer a.queue.Done(key) // 在函数结束前标记 key 为已处理

	deleted, err := a.reconcileKey(ctx, key.(string)) // 调用 reconcileKey 方法处理 key，并返回是否删除成功以及可能的错误
	if err != nil {
		utilruntime.HandleError(err) // 如果处理过程中出现错误，则处理错误
	}

	// 将新的请求加入队列，以在 resyncPeriod 后再次处理
	// 请求总是会以 resyncPeriod 的延迟加入队列。如果队列中已经存在 HPA 的请求，则新的请求会被丢弃。
	// 请求在队列中等待 resyncPeriod 的时间，以保证每个 resyncPeriod 都会处理 HPAs。
	// 在这里添加请求，是为了防止上一个 resyncPeriod 没有将请求插入队列。
	// 这种情况经常发生，因为在 resyncPeriod 后添加请求和从队列中移除请求之间存在竞争条件。
	// 请求可能在上一个请求从队列中移除之前被 resyncPeriod 添加。如果我们不在这里添加请求，
	// 那么在这种情况下会丢失一个请求，导致 HPA 在 2 倍的 resyncPeriod 后才被处理。
	if !deleted {
		a.queue.AddRateLimited(key)
	}

	return true // 返回 true 表示继续处理下一个工作项
}

```

### reconcileKey

```go
func (a *HorizontalController) reconcileKey(ctx context.Context, key string) (deleted bool, err error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key) // 从 key 中解析出 namespace 和 name
	if err != nil {
		return true, err // 如果解析出错，则返回 deleted 为 true，同时返回错误
	}

	logger := klog.FromContext(ctx) // 从 context 中获取 logger

	hpa, err := a.hpaLister.HorizontalPodAutoscalers(namespace).Get(name) // 通过 namespace 和 name 获取 HorizontalPodAutoscaler 对象
	if k8serrors.IsNotFound(err) { // 如果获取到的错误是 NotFound，则表示 HPA 已经被删除
		logger.Info("Horizontal Pod Autoscaler has been deleted", "HPA", klog.KRef(namespace, name)) // 记录日志，标记 HPA 已被删除

		a.recommendationsLock.Lock()
		delete(a.recommendations, key) // 从 recommendations 中删除对应的 key
		a.recommendationsLock.Unlock()

		a.scaleUpEventsLock.Lock()
		delete(a.scaleUpEvents, key) // 从 scaleUpEvents 中删除对应的 key
		a.scaleUpEventsLock.Unlock()

		a.scaleDownEventsLock.Lock()
		delete(a.scaleDownEvents, key) // 从 scaleDownEvents 中删除对应的 key
		a.scaleDownEventsLock.Unlock()

		return true, nil // 返回 deleted 为 true，表示 HPA 已被删除，同时返回 nil 错误
	}
	if err != nil {
		return false, err // 如果获取 HPA 对象时出现其他错误，则返回 deleted 为 false，同时返回错误
	}

	return false, a.reconcileAutoscaler(ctx, hpa, key) // 调用 reconcileAutoscaler 方法处理 HPA 对象，并返回 deleted 为 false，同时返回可能的错误
}
```

### reconcileAutoscaler

```go
func (a *HorizontalController) reconcileAutoscaler(ctx context.Context, hpaShared *autoscalingv2.HorizontalPodAutoscaler, key string) (retErr error) {
	// actionLabel is used to report which actions this reconciliation has taken.
	actionLabel := monitor.ActionLabelNone // actionLabel 用于报告此次调谐所采取的操作。
	start := time.Now() // 记录当前时间作为调谐开始时间。
	defer func() {
		errorLabel := monitor.ErrorLabelNone
		if retErr != nil {
			// In case of error, set "internal" as default.
			errorLabel = monitor.ErrorLabelInternal // 在发生错误的情况下，将错误标签设置为 "internal"。
		}
		if errors.Is(retErr, errSpec) {
			errorLabel = monitor.ErrorLabelSpec // 如果错误是 errSpec，则将错误标签设置为 "spec"。
		}

		a.monitor.ObserveReconciliationResult(actionLabel, errorLabel, time.Since(start)) // 调用监控器记录调谐结果。
	}()

	// make a copy so that we never mutate the shared informer cache (conversion can mutate the object)
	hpa := hpaShared.DeepCopy() // 复制传入的 hpaShared 对象，以便不对共享的 informer 缓存进行更改（转换可能会更改对象）。
	hpaStatusOriginal := hpa.Status.DeepCopy() // 复制 hpa 对象的状态，以便后续对比。

	reference := fmt.Sprintf("%s/%s/%s", hpa.Spec.ScaleTargetRef.Kind, hpa.Namespace, hpa.Spec.ScaleTargetRef.Name) // 根据 hpa 对象的 ScaleTargetRef 字段的值生成引用字符串。

	targetGV, err := schema.ParseGroupVersion(hpa.Spec.ScaleTargetRef.APIVersion) // 解析 hpa 对象的 APIVersion 字段的值，生成 GroupVersion 对象。
	if err != nil {
		a.eventRecorder.Event(hpa, v1.EventTypeWarning, "FailedGetScale", err.Error()) // 记录事件，标记错误类型为 "FailedGetScale"，错误消息为 err.Error()。
		setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionFalse, "FailedGetScale", "the HPA controller was unable to get the target's current scale: %v", err) // 设置 HPA 对象的 AbleToScale 条件为 false，并设置错误消息。
		if err := a.updateStatusIfNeeded(ctx, hpaStatusOriginal, hpa); err != nil { // 如果需要更新 HPA 对象的状态，调用 updateStatusIfNeeded 方法进行更新。
			utilruntime.HandleError(err) // 处理可能出现的错误。
		}
		return fmt.Errorf("invalid API version in scale target reference: %v%w", err, errSpec) // 返回错误信息，包括错误类型和错误对象。
	}

	targetGK := schema.GroupKind{
		Group: targetGV.Group, // 将 GroupVersion 对象的 Group 字段赋值给 targetGK 的 Group 字段。
		Kind:  hpa.Spec.ScaleTargetRef.Kind, // 将 hpa 对象的 ScaleTargetRef 字段的 Kind 字段赋值给 targetGK 的 Kind 字段。
	}
	
    // 获取资源的映射关系
	mappings, err := a.mapper.RESTMappings(targetGK)
	if err != nil {
		a.eventRecorder.Event(hpa, v1.EventTypeWarning, "FailedGetScale", err.Error())
		setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionFalse, "FailedGetScale", "the HPA controller was unable to get the target's current scale: %v", err)
		if err := a.updateStatusIfNeeded(ctx, hpaStatusOriginal, hpa); err != nil {
			utilruntime.HandleError(err)
		}
		return fmt.Errorf("unable to determine resource for scale target reference: %v", err)
	}
	
    // 使用scaleForResourceMappings函数获取scale资源的对象，并设置HPA状态为可缩放
	scale, targetGR, err := a.scaleForResourceMappings(ctx, hpa.Namespace, hpa.Spec.ScaleTargetRef.Name, mappings)
	if err != nil {
		a.eventRecorder.Event(hpa, v1.EventTypeWarning, "FailedGetScale", err.Error())
		setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionFalse, "FailedGetScale", "the HPA controller was unable to get the target's current scale: %v", err)
		if err := a.updateStatusIfNeeded(ctx, hpaStatusOriginal, hpa); err != nil {
			utilruntime.HandleError(err)
		}
		return fmt.Errorf("failed to query scale subresource for %s: %v", reference, err)
	}
    // 设置HPA状态为可缩放，记录当前Pod的数量。
	setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionTrue, "SucceededGetScale", "the HPA controller was able to get the target's current scale")
	currentReplicas := scale.Spec.Replicas
	a.recordInitialRecommendation(currentReplicas, key)

	var (
		metricStatuses        []autoscalingv2.MetricStatus
		metricDesiredReplicas int32
		metricName            string
	)

	desiredReplicas := int32(0)
	rescaleReason := ""

	var minReplicas int32
	
    // 如果hpa.spec.minReplicas不为空，则将其值分配给变量minReplicas，否则将其设置为默认值1。
	if hpa.Spec.MinReplicas != nil {
		minReplicas = *hpa.Spec.MinReplicas
	} else {
		// Default value
		minReplicas = 1
	}
	
    // 定义变量 rescale，表示是否需要扩缩容，默认为 true
	rescale := true
    // 从上下文中获取 logger
	logger := klog.FromContext(ctx)
	
    // 如果指定资源的副本数为 0，但最小副本数不为 0，则表示不对该资源进行自动扩缩容
	if scale.Spec.Replicas == 0 && minReplicas != 0 {
		// 禁用自动扩缩容
		desiredReplicas = 0
		rescale = false
        // 设置 HPA 的条件 ScalingActive 为 False，表示自动扩缩容已禁用
		setCondition(hpa, autoscalingv2.ScalingActive, v1.ConditionFalse, "ScalingDisabled", "scaling is disabled since the replica count of the target is zero")
	} else if currentReplicas > hpa.Spec.MaxReplicas {
        // 如果当前副本数大于 HPA 中指定的最大副本数，则缩容到最大副本数
		rescaleReason = "Current number of replicas above Spec.MaxReplicas"
		desiredReplicas = hpa.Spec.MaxReplicas
	} else if currentReplicas < minReplicas {
        // 如果当前副本数小于 HPA 中指定的最小副本数，则扩容到最小副本数
		rescaleReason = "Current number of replicas below Spec.MinReplicas"
		desiredReplicas = minReplicas
	} else {
        // 计算指标对应的期望副本数
		var metricTimestamp time.Time
		metricDesiredReplicas, metricName, metricStatuses, metricTimestamp, err = a.computeReplicasForMetrics(ctx, hpa, scale, hpa.Spec.Metrics)
		// computeReplicasForMetrics 可能返回非零的 metricDesiredReplicas 和错误 err。
    	// 这意味着一些指标仍在工作，HPA 应该根据它们进行扩缩容。
		if err != nil && metricDesiredReplicas == -1 {
            // 计算期望副本数时出错，但不能完全依赖该错误，仍需要继续扩缩容
			a.setCurrentReplicasInStatus(hpa, currentReplicas)
			if err := a.updateStatusIfNeeded(ctx, hpaStatusOriginal, hpa); err != nil {
				utilruntime.HandleError(err)
			}
            // 在事件中记录该错误
			a.eventRecorder.Event(hpa, v1.EventTypeWarning, "FailedComputeMetricsReplicas", err.Error())
			return fmt.Errorf("failed to compute desired number of replicas based on listed metrics for %s: %v", reference, err)
		}
		if err != nil {
            // 我们继续进行缩放，但最终从reconcileAutoscaler()返回此错误。
			retErr = err
		}

		logger.V(4).Info("Proposing desired replicas",
			"desiredReplicas", metricDesiredReplicas,
			"metric", metricName,
			"timestamp", metricTimestamp,
			"scaleTarget", reference)

		rescaleMetric := ""
		if metricDesiredReplicas > desiredReplicas { // 如果指标期望的Pod数量大于当前期望的Pod数量
			desiredReplicas = metricDesiredReplicas // 更新当前期望的Pod数量
			rescaleMetric = metricName // 将该指标的名称赋给“rescaleMetric”
		}
		if desiredReplicas > currentReplicas {  // 如果当前期望的Pod数量大于当前Pod数量
			rescaleReason = fmt.Sprintf("%s above target", rescaleMetric) // 更新“rescaleReason”以表明是该指标的Pod数量超过了期望的Pod数量
		}
		if desiredReplicas < currentReplicas { // 如果当前期望的Pod数量小于当前Pod数量
			rescaleReason = "All metrics below target" // 更新“rescaleReason”以表明所有指标的Pod数量都低于期望的Pod数量
		}
		if hpa.Spec.Behavior == nil { // 如果没有指定行为，即使用默认的扩展策略
			desiredReplicas = a.normalizeDesiredReplicas(hpa, key, currentReplicas, desiredReplicas, minReplicas) // 根据默认的扩展策略规则来计算期望的Pod数量
		} else { // 如果指定了行为，即使用指定的扩展策略
			desiredReplicas = a.normalizeDesiredReplicasWithBehaviors(hpa, key, currentReplicas, desiredReplicas, minReplicas) // 根据指定的扩展策略规则来计算期望的Pod数量
		}
		rescale = desiredReplicas != currentReplicas // 如果期望的Pod数量不等于当前Pod数量，则需要进行扩展或收缩
	}

	if rescale { // 如果需要进行扩展或收缩
		scale.Spec.Replicas = desiredReplicas
		_, err = a.scaleNamespacer.Scales(hpa.Namespace).Update(ctx, targetGR, scale, metav1.UpdateOptions{})
		if err != nil { // 如果更新失败
			a.eventRecorder.Eventf(hpa, v1.EventTypeWarning, "FailedRescale", "New size: %d; reason: %s; error: %v", desiredReplicas, rescaleReason, err.Error())
			setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionFalse, "FailedUpdateScale", "the HPA controller was unable to update the target scale: %v", err)
			a.setCurrentReplicasInStatus(hpa, currentReplicas) // 更新HPA的状态以反映当前Pod的数量
			if err := a.updateStatusIfNeeded(ctx, hpaStatusOriginal, hpa); err != nil { // 如果更新状态失败
				utilruntime.HandleError(err)
			}
			return fmt.Errorf("failed to rescale %s: %v", reference, err)
		}
		// 设置 HPA 的条件为 AbleToScale，设置状态为 v1.ConditionTrue，设置原因为 "SucceededRescale"，并且打印带格式的日志信息。
        setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionTrue, "SucceededRescale", "the HPA controller was able to update the target scale to %d", desiredReplicas)

        // 在 HPA 对象上记录一个事件，类型为 v1.EventTypeNormal，原因为 "SuccessfulRescale"，并且打印带格式的日志信息。
        a.eventRecorder.Eventf(hpa, v1.EventTypeNormal, "SuccessfulRescale", "New size: %d; reason: %s", desiredReplicas, rescaleReason)

        // 将 HPA 的当前状态信息保存到事件存储中。
        a.storeScaleEvent(hpa.Spec.Behavior, key, currentReplicas, desiredReplicas)

        // 打印带有多个键值对的日志信息，记录成功缩放的相关信息。
        logger.Info("Successfully rescaled",
            "HPA", klog.KObj(hpa),
            "currentReplicas", currentReplicas,
            "desiredReplicas", desiredReplicas,
            "reason", rescaleReason)

        // 根据当前副本数和期望副本数判断应该执行哪种操作，记录操作标签。
        if desiredReplicas > currentReplicas {
            actionLabel = monitor.ActionLabelScaleUp
        } else {
            actionLabel = monitor.ActionLabelScaleDown
        }

        // 如果不需要缩放，则记录日志信息，并将期望副本数设为当前副本数。
        } else {
            logger.V(4).Info("Decided not to scale",
                "scaleTarget", reference,
                "desiredReplicas", desiredReplicas,
                "lastScaleTime", hpa.Status.LastScaleTime)
            desiredReplicas = currentReplicas
        }

        // 设置 HPA 的状态信息，并保存监控指标的状态信息。
        a.setStatus(hpa, currentReplicas, desiredReplicas, metricStatuses, rescale)

        // 如果需要，更新 HPA 的状态信息，并返回错误信息。
        err = a.updateStatusIfNeeded(ctx, hpaStatusOriginal, hpa)
        if err != nil {
            // we can overwrite retErr in this case because it's an internal error.
            return err
        }

        return retErr
}
```

#### setCondition

```GO
func setCondition(hpa *autoscalingv2.HorizontalPodAutoscaler, conditionType autoscalingv2.HorizontalPodAutoscalerConditionType, status v1.ConditionStatus, reason, message string, args ...interface{}) {
	hpa.Status.Conditions = setConditionInList(hpa.Status.Conditions, conditionType, status, reason, message, args...)
}
```

##### setConditionInList

```GO
func setConditionInList(inputList []autoscalingv2.HorizontalPodAutoscalerCondition, conditionType autoscalingv2.HorizontalPodAutoscalerConditionType, status v1.ConditionStatus, reason, message string, args ...interface{}) []autoscalingv2.HorizontalPodAutoscalerCondition {
	resList := inputList // 将输入的切片赋值给 resList
    var existingCond *autoscalingv2.HorizontalPodAutoscalerCondition // 定义一个指针 existingCond，指向 autoscalingv2.HorizontalPodAutoscalerCondition 结构体类型

    // 遍历切片 resList 中的元素
    for i, condition := range resList {
        if condition.Type == conditionType { // 如果 condition 的 Type 等于 conditionType
            // can't take a pointer to an iteration variable，不能对循环变量取地址，因此需要定义一个中间变量 existingCond
            existingCond = &resList[i] // 将 resList 中第 i 个元素的地址赋值给 existingCond
            break // 跳出 for 循环
        }
    }

    if existingCond == nil { // 如果 existingCond 指针为空
        resList = append(resList, autoscalingv2.HorizontalPodAutoscalerCondition{ // 向 resList 中追加一个 autoscalingv2.HorizontalPodAutoscalerCondition 结构体
            Type: conditionType, // 指定 Type 为 conditionType
        })
        existingCond = &resList[len(resList)-1] // 将新追加的元素的地址赋值给 existingCond
    }

    if existingCond.Status != status { // 如果 existingCond 的 Status 不等于 status
        existingCond.LastTransitionTime = metav1.Now() // 更新 existingCond 的 LastTransitionTime 字段
    }

    existingCond.Status = status // 更新 existingCond 的 Status 字段
    existingCond.Reason = reason // 更新 existingCond 的 Reason 字段
    existingCond.Message = fmt.Sprintf(message, args...) // 更新 existingCond 的 Message 字段

    return resList // 返回更新后的 resList
}
```

#### updateStatusIfNeeded

```GO
func (a *HorizontalController) updateStatusIfNeeded(ctx context.Context, oldStatus *autoscalingv2.HorizontalPodAutoscalerStatus, newHPA *autoscalingv2.HorizontalPodAutoscaler) error {
	// skip a write if we wouldn't need to update
	if apiequality.Semantic.DeepEqual(oldStatus, &newHPA.Status) {
		return nil
	}
	return a.updateStatus(ctx, newHPA)
}
```

#### scaleForResourceMappings

```GO
// 根据给定的资源映射信息，查询指定名称的 Scale 对象，返回 Scale 对象、GroupResource 以及可能的错误。
func (a *HorizontalController) scaleForResourceMappings(ctx context.Context, namespace, name string, mappings []*apimeta.RESTMapping) (*autoscalingv1.Scale, schema.GroupResource, error) {
	var firstErr error
	for i, mapping := range mappings {
		// 获取 GroupResource 对象。
		targetGR := mapping.Resource.GroupResource()
		// 查询指定名称的 Scale 对象。
		scale, err := a.scaleNamespacer.Scales(namespace).Get(ctx, targetGR, name, metav1.GetOptions{})
		// 如果没有出现错误，直接返回 Scale 对象和 GroupResource。
		if err == nil {
			return scale, targetGR, nil
		}

		// 如果出现了错误，则判断是否为第一个错误。
		// 如果是第一个错误，则记录下来，继续查询其他映射资源，直到找到正确的 Scale 对象。
		if i == 0 {
			firstErr = err
		}
	}

	// 处理映射资源集合为空的情况。
	// 如果第一个错误为空，则表示没有任何资源映射与查询匹配。
	if firstErr == nil {
		firstErr = fmt.Errorf("unrecognized resource")
	}

	return nil, schema.GroupResource{}, firstErr
}
```

#### recordInitialRecommendation

````GO
func (a *HorizontalController) recordInitialRecommendation(currentReplicas int32, key string) {
	a.recommendationsLock.Lock()
	defer a.recommendationsLock.Unlock()
	if a.recommendations[key] == nil {
		a.recommendations[key] = []timestampedRecommendation{{currentReplicas, time.Now()}}
	}
}
````

#### computeReplicasForMetrics

```GO
func (a *HorizontalController) computeReplicasForMetrics(ctx context.Context, hpa *autoscalingv2.HorizontalPodAutoscaler, scale *autoscalingv1.Scale,
	metricSpecs []autoscalingv2.MetricSpec) (replicas int32, metric string, statuses []autoscalingv2.MetricStatus, timestamp time.Time, err error) {
	// 计算基于指标的自动伸缩副本数

	selector, err := a.validateAndParseSelector(hpa, scale.Status.Selector) // 验证并解析选择器
	if err != nil {
		return -1, "", nil, time.Time{}, err // 如果出错，返回错误信息
	}

	specReplicas := scale.Spec.Replicas // 获取期望副本数
	statusReplicas := scale.Status.Replicas // 获取当前副本数
	statuses = make([]autoscalingv2.MetricStatus, len(metricSpecs)) // 根据指标规格数量初始化指标状态数组

	invalidMetricsCount := 0 // 记录无效指标数量
	var invalidMetricError error // 记录无效指标错误
	var invalidMetricCondition autoscalingv2.HorizontalPodAutoscalerCondition // 记录无效指标的条件

	for i, metricSpec := range metricSpecs { // 遍历每个指标规格
		replicaCountProposal, metricNameProposal, timestampProposal, condition, err := a.computeReplicasForMetric(ctx, hpa, metricSpec, specReplicas, statusReplicas, selector, &statuses[i])

		if err != nil { // 如果计算指标出错
			if invalidMetricsCount <= 0 { // 如果是第一个无效的指标
				invalidMetricCondition = condition // 记录无效指标的条件
				invalidMetricError = err // 记录无效指标的错误
			}
			invalidMetricsCount++ // 无效指标数量加一
			continue // 继续下一个指标的计算
		}
		if replicas == 0 || replicaCountProposal > replicas { // 如果当前指标的副本数大于之前计算的副本数
			timestamp = timestampProposal // 更新时间戳
			replicas = replicaCountProposal // 更新副本数
			metric = metricNameProposal // 更新指标名称
		}
	}

	if invalidMetricError != nil { // 如果存在无效指标
		invalidMetricError = fmt.Errorf("invalid metrics (%v invalid out of %v), first error is: %v", invalidMetricsCount, len(metricSpecs), invalidMetricError) // 构造错误信息
	}

	// 如果所有指标都无效，或者存在无效指标且计算出的副本数小于期望副本数，则返回错误，并设置 HPA 的条件为第一个无效指标的条件
	// 否则设置 HPA 的条件为 ScalingActive，表示自动伸缩生效
	if invalidMetricsCount >= len(metricSpecs) || (invalidMetricsCount > 0 && replicas < specReplicas) {
		setCondition(hpa, invalidMetricCondition.Type, invalidMetricCondition.Status, invalidMetricCondition.Reason, invalidMetricCondition.Message)
		return -1, "", statuses, time.Time{}, invalidMetricError
	}
	setCondition(hpa, autoscalingv2.ScalingActive, v1.ConditionTrue, "ValidMetricFound", "the HPA was able to successfully calculate a replica count from %s", metric)

	return replicas, metric, statuses, timestamp, invalidMetricError
}
```

##### validateAndParseSelector

```go
func (a *HorizontalController) validateAndParseSelector(hpa *autoscalingv2.HorizontalPodAutoscaler, selector string) (labels.Selector, error) {
	// 校验并解析传入的 selector 参数
	if selector == "" {
		// 如果 selector 参数为空，则记录错误事件并设置 HPA 的条件
		errMsg := "selector is required" 
		a.eventRecorder.Event(hpa, v1.EventTypeWarning, "SelectorRequired", errMsg)
		setCondition(hpa, autoscalingv2.ScalingActive, v1.ConditionFalse, "InvalidSelector", "the HPA target's scale is missing a selector")
		return nil, fmt.Errorf(errMsg)
	}

	// 将 selector 字符串解析为内部的 selector 对象
	parsedSelector, err := labels.Parse(selector)
	if err != nil {
		// 如果解析失败，则记录错误事件并设置 HPA 的条件
		errMsg := fmt.Sprintf("couldn't convert selector into a corresponding internal selector object: %v", err)
		a.eventRecorder.Event(hpa, v1.EventTypeWarning, "InvalidSelector", errMsg)
		setCondition(hpa, autoscalingv2.ScalingActive, v1.ConditionFalse, "InvalidSelector", errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// 构建 HPA 的键值
	hpaKey := selectors.Key{Name: hpa.Name, Namespace: hpa.Namespace}
	a.hpaSelectorsMux.Lock()
	if a.hpaSelectors.SelectorExists(hpaKey) {
		// 如果 HPA 在 enqueueHPA 中注册，则更新 HPA 的选择器
		a.hpaSelectors.PutSelector(hpaKey, parsedSelector)
	}
	a.hpaSelectorsMux.Unlock()

	// 根据解析后的 selector 查询符合条件的 Pods
	pods, err := a.podLister.Pods(hpa.Namespace).List(parsedSelector)
	if err != nil {
		return nil, err
	}

	// 检查由 selector 控制的 Pods 是否受到多个 HPA 的控制
	selectingHpas := a.hpasControllingPodsUnderSelector(pods)
	if len(selectingHpas) > 1 {
		// 如果由 selector 控制的 Pods 受到多个 HPA 控制，则记录错误事件并设置 HPA 的条件
		errMsg := fmt.Sprintf("pods by selector %v are controlled by multiple HPAs: %v", selector, selectingHpas)
		a.eventRecorder.Event(hpa, v1.EventTypeWarning, "AmbiguousSelector", errMsg)
		setCondition(hpa, autoscalingv2.ScalingActive, v1.ConditionFalse, "AmbiguousSelector", errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// 返回解析后的 selector 对象
	return parsedSelector, nil
}
```



```go
func (a *HorizontalController) computeReplicasForMetric(ctx context.Context, hpa *autoscalingv2.HorizontalPodAutoscaler, spec autoscalingv2.MetricSpec,
	specReplicas, statusReplicas int32, selector labels.Selector, status *autoscalingv2.MetricStatus) (replicaCountProposal int32, metricNameProposal string,
	timestampProposal time.Time, condition autoscalingv2.HorizontalPodAutoscalerCondition, err error) {
	// actionLabel is used to report which actions this reconciliation has taken.
	start := time.Now()
	defer func() {
		actionLabel := monitor.ActionLabelNone
		switch {
		case replicaCountProposal > hpa.Status.CurrentReplicas:
			actionLabel = monitor.ActionLabelScaleUp
		case replicaCountProposal < hpa.Status.CurrentReplicas:
			actionLabel = monitor.ActionLabelScaleDown
		}

		errorLabel := monitor.ErrorLabelNone
		if err != nil {
			// In case of error, set "internal" as default.
			errorLabel = monitor.ErrorLabelInternal
			actionLabel = monitor.ActionLabelNone
		}
		if errors.Is(err, errSpec) {
			errorLabel = monitor.ErrorLabelSpec
		}

		a.monitor.ObserveMetricComputationResult(actionLabel, errorLabel, time.Since(start), spec.Type)
	}()

	switch spec.Type {
	case autoscalingv2.ObjectMetricSourceType: // 如果是对象型指标
		metricSelector, err := metav1.LabelSelectorAsSelector(spec.Object.Metric.Selector) // 将对象型指标的选择器转换为Selector
		if err != nil {
			condition := a.getUnableComputeReplicaCountCondition(hpa, "FailedGetObjectMetric", err)
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get object metric value: %v", err)
		}
		replicaCountProposal, timestampProposal, metricNameProposal, condition, err = a.computeStatusForObjectMetric(specReplicas, statusReplicas, spec, hpa, selector, status, metricSelector) // 计算对象型指标的副本数量
		if err != nil {
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get object metric value: %v", err)
		}
	case autoscalingv2.PodsMetricSourceType: // 如果是Pods型指标
		metricSelector, err := metav1.LabelSelectorAsSelector(spec.Pods.Metric.Selector) // 将Pods型指标的选择器转换为Selector
		if err != nil {
			condition := a.getUnableComputeReplicaCountCondition(hpa, "FailedGetPodsMetric", err)
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get pods metric value: %v", err)
		}
		replicaCountProposal, timestampProposal, metricNameProposal, condition, err = a.computeStatusForPodsMetric(specReplicas, spec, hpa, selector, status, metricSelector) // 计算Pods型指标的副本数量
		if err != nil {
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get pods metric value: %v", err)
		}
	case autoscalingv2.ResourceMetricSourceType: // 如果是资源型指标
		replicaCountProposal, timestampProposal, metricNameProposal, condition, err = a.computeStatusForResourceMetric(ctx, specReplicas, spec, hpa, selector, status) // 计算资源型指标
        if err != nil {
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get %s resource metric value: %v", spec.Resource.Name, err)
		}
  	case autoscalingv2.ContainerResourceMetricSourceType:
		if !a.containerResourceMetricsEnabled {
			// If the container resource metrics feature is disabled but the object has the one,
			// that means the user enabled the feature once,
			// created some HPAs with the container resource metrics, and disabled it finally.
			return 0, "", time.Time{}, condition, fmt.Errorf("ContainerResource metric type is not supported: disabled by the feature gate")
		}
		replicaCountProposal, timestampProposal, metricNameProposal, condition, err = a.computeStatusForContainerResourceMetric(ctx, specReplicas, spec, hpa, selector, status)
		if err != nil {
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get %s container metric value: %v", spec.ContainerResource.Container, err)
		}
	case autoscalingv2.ExternalMetricSourceType:
		replicaCountProposal, timestampProposal, metricNameProposal, condition, err = a.computeStatusForExternalMetric(specReplicas, statusReplicas, spec, hpa, selector, status)
		if err != nil {
			return 0, "", time.Time{}, condition, fmt.Errorf("failed to get %s external metric value: %v", spec.External.Metric.Name, err)
		}
	default:
		// 它不应该到达这里，因为在api服务器的验证中过滤掉了无效的度量源类型
		err = fmt.Errorf("unknown metric source type %q%w", string(spec.Type), errSpec)
		condition := a.getUnableComputeReplicaCountCondition(hpa, "InvalidMetricSourceType", err)
		return 0, "", time.Time{}, condition, err
	}
	return replicaCountProposal, metricNameProposal, timestampProposal, autoscalingv2.HorizontalPodAutoscalerCondition{}, nil
}
```

###### getUnableComputeReplicaCountCondition

```GO
func (a *HorizontalController) getUnableComputeReplicaCountCondition(hpa runtime.Object, reason string, err error) (condition autoscalingv2.HorizontalPodAutoscalerCondition) {
	a.eventRecorder.Event(hpa, v1.EventTypeWarning, reason, err.Error())
	return autoscalingv2.HorizontalPodAutoscalerCondition{
		Type:    autoscalingv2.ScalingActive,
		Status:  v1.ConditionFalse,
		Reason:  reason,
		Message: fmt.Sprintf("the HPA was unable to compute the replica count: %v", err),
	}
}
```

###### computeStatusForObjectMetric

```GO
func (a *HorizontalController) computeStatusForObjectMetric(specReplicas, statusReplicas int32, metricSpec autoscalingv2.MetricSpec, hpa *autoscalingv2.HorizontalPodAutoscaler, selector labels.Selector, status *autoscalingv2.MetricStatus, metricSelector labels.Selector) (replicas int32, timestamp time.Time, metricName string, condition autoscalingv2.HorizontalPodAutoscalerCondition, err error) {
	if metricSpec.Object.Target.Type == autoscalingv2.ValueMetricType {
		// 如果指标类型为ValueMetricType
		replicaCountProposal, usageProposal, timestampProposal, err := a.replicaCalc.GetObjectMetricReplicas(specReplicas, metricSpec.Object.Target.Value.MilliValue(), metricSpec.Object.Metric.Name, hpa.Namespace, &metricSpec.Object.DescribedObject, selector, metricSelector)
		if err != nil {
			// 如果计算指标失败，设置错误条件并返回
			condition := a.getUnableComputeReplicaCountCondition(hpa, "FailedGetObjectMetric", err)
			return 0, timestampProposal, "", condition, err
		}
		// 设置 MetricStatus 结构体的值
		*status = autoscalingv2.MetricStatus{
			Type: autoscalingv2.ObjectMetricSourceType,
			Object: &autoscalingv2.ObjectMetricStatus{
				DescribedObject: metricSpec.Object.DescribedObject,
				Metric: autoscalingv2.MetricIdentifier{
					Name:     metricSpec.Object.Metric.Name,
					Selector: metricSpec.Object.Metric.Selector,
				},
				Current: autoscalingv2.MetricValueStatus{
					Value: resource.NewMilliQuantity(usageProposal, resource.DecimalSI),
				},
			},
		}
		// 返回计算得到的结果
		return replicaCountProposal, timestampProposal, fmt.Sprintf("%s metric %s", metricSpec.Object.DescribedObject.Kind, metricSpec.Object.Metric.Name), autoscalingv2.HorizontalPodAutoscalerCondition{}, nil
	} else if metricSpec.Object.Target.Type == autoscalingv2.AverageValueMetricType {
		// 如果指标类型为AverageValueMetricType
		replicaCountProposal, usageProposal, timestampProposal, err := a.replicaCalc.GetObjectPerPodMetricReplicas(statusReplicas, metricSpec.Object.Target.AverageValue.MilliValue(), metricSpec.Object.Metric.Name, hpa.Namespace, &metricSpec.Object.DescribedObject, metricSelector)
		if err != nil {
			// 如果计算指标失败，设置错误条件并返回
			condition := a.getUnableComputeReplicaCountCondition(hpa, "FailedGetObjectMetric", err)
			return 0, time.Time{}, "", condition, fmt.Errorf("failed to get %s object metric: %v", metricSpec.Object.Metric.Name, err)
		}
		// 设置 MetricStatus 结构体的值
		*status = autoscalingv2.MetricStatus{
			Type: autoscalingv2.ObjectMetricSourceType,
			Object: &autoscalingv2.ObjectMetricStatus{
				Metric: autoscalingv2.MetricIdentifier{
					Name:     metricSpec.Object.Metric.Name,
					Selector: metricSpec.Object.Metric.Selector,
				},
				Current: autoscalingv2.MetricValueStatus{
					AverageValue: resource.NewMilliQuantity(usageProposal, resource.DecimalSI),
				},
			},
		}
		// 返回计算得到的结果
		return replicaCountProposal, timestampProposal, fmt.Sprintf("external metric %s(%+v)", metricSpec.Object.Metric.Name, metricSpec.Object.Metric.Selector), autoscalingv2.HorizontalPodAutoscalerCondition{}, nil
	}
    // 如果前面的条件不满足，则说明 object metric 源无效，将生成一个错误信息并返回相应的 condition 和错误信息
	errMsg := "invalid object metric source: neither a value target nor an average value target was set"
	err = fmt.Errorf(errMsg)
	condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetObjectMetric", err)
	return 0, time.Time{}, "", condition, err
}                                                                   
```

###### computeStatusForPodsMetric

```GO
// 定义一个名为HorizontalController的结构体，具有computeStatusForPodsMetric方法
func (a *HorizontalController) computeStatusForPodsMetric(currentReplicas int32, metricSpec autoscalingv2.MetricSpec, hpa *autoscalingv2.HorizontalPodAutoscaler, selector labels.Selector, status *autoscalingv2.MetricStatus, metricSelector labels.Selector) (replicaCountProposal int32, timestampProposal time.Time, metricNameProposal string, condition autoscalingv2.HorizontalPodAutoscalerCondition, err error) {
	
	// 调用replicaCalc结构体中的GetMetricReplicas方法，获取指标的当前副本数，使用率，时间戳和错误信息
	replicaCountProposal, usageProposal, timestampProposal, err := a.replicaCalc.GetMetricReplicas(currentReplicas, metricSpec.Pods.Target.AverageValue.MilliValue(), metricSpec.Pods.Metric.Name, hpa.Namespace, selector, metricSelector)
	if err != nil {
		// 如果获取指标失败，则返回UnableComputeReplicaCountCondition错误条件，指示无法计算副本数
		condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetPodsMetric", err)
		return 0, timestampProposal, "", condition, err
	}
	
	// 将指标状态设置为当前指标的状态
	*status = autoscalingv2.MetricStatus{
		Type: autoscalingv2.PodsMetricSourceType,
		Pods: &autoscalingv2.PodsMetricStatus{
			Metric: autoscalingv2.MetricIdentifier{
				Name:     metricSpec.Pods.Metric.Name,
				Selector: metricSpec.Pods.Metric.Selector,
			},
			Current: autoscalingv2.MetricValueStatus{
				AverageValue: resource.NewMilliQuantity(usageProposal, resource.DecimalSI),
			},
		},
	}

	// 返回计算的副本数提议、时间戳提议、指标名称提议、横向Pod自动缩放器条件和无错误
	return replicaCountProposal, timestampProposal, fmt.Sprintf("pods metric %s", metricSpec.Pods.Metric.Name), autoscalingv2.HorizontalPodAutoscalerCondition{}, nil
}
```

###### computeStatusForResourceMetric

```go
func (a *HorizontalController) computeStatusForResourceMetric(ctx context.Context, currentReplicas int32, metricSpec autoscalingv2.MetricSpec, hpa *autoscalingv2.HorizontalPodAutoscaler,
selector labels.Selector, status *autoscalingv2.MetricStatus) (replicaCountProposal int32, timestampProposal time.Time,
metricNameProposal string, condition autoscalingv2.HorizontalPodAutoscalerCondition, err error) {
    // 定义函数 computeStatusForResourceMetric，用于计算 ResourceMetric 类型的指标状态并返回建议的副本数、时间戳、度量名称、水平自动伸缩器的条件和错误
    // 函数接收的参数包括：ctx 上下文，currentReplicas 当前副本数，metricSpec 指标规范，hpa 水平自动伸缩器，selector 选择器，status 指标状态
    replicaCountProposal, metricValueStatus, timestampProposal, metricNameProposal, condition, err := a.computeStatusForResourceMetricGeneric(ctx, currentReplicas, metricSpec.Resource.Target, metricSpec.Resource.Name, hpa.Namespace, "", selector, autoscalingv2.ResourceMetricSourceType)

    // 调用 a.computeStatusForResourceMetricGeneric 函数，计算 ResourceMetric 类型的指标状态，并返回建议的副本数、度量值状态、时间戳、度量名称、水平自动伸缩器的条件和错误
    // 计算时需要传入上下文、当前副本数、度量目标值、度量名称、水平自动伸缩器的命名空间、度量描述、选择器和度量类型
    // 函数将返回的值分别赋值给 replicaCountProposal、metricValueStatus、timestampProposal、metricNameProposal、condition 和 err
    if err != nil {
        condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetResourceMetric", err)
        // 如果计算出错，调用 a.getUnableComputeReplicaCountCondition 函数，返回计算副本数无法完成的条件
        // 函数接收的参数包括：hpa 水平自动伸缩器，错误类型 FailedGetResourceMetric 和错误 err
        return replicaCountProposal, timestampProposal, metricNameProposal, condition, err
    }

    *status = autoscalingv2.MetricStatus{
        Type: autoscalingv2.ResourceMetricSourceType,
        Resource: &autoscalingv2.ResourceMetricStatus{
            Name:    metricSpec.Resource.Name,
            Current: *metricValueStatus,
        },
    }
    // 更新 status 的值为 autoscalingv2.MetricStatus 类型，其中 Type 为 ResourceMetricSourceType，Resource 中包括 Name 和 Current 两个字段，分别为度量名称和当前度量值
    // 前面计算出的 metricSpec.Resource.Name 和 metricValueStatus 分别赋值给 Name 和 Current 字段
    // 注意这里使用了指针 *metricValueStatus，因为 metricValueStatus 的类型为 *resource.Quantity
    return replicaCountProposal, timestampProposal, metricNameProposal, condition, nil
    // 返回计算出的建议副本数、时间戳、度量名称、水平自动伸缩器的条件和错误，注意此时 err 为 nil
}
```

###### computeStatusForContainerResourceMetric

```GO
func (a *HorizontalController) computeStatusForContainerResourceMetric(ctx context.Context, currentReplicas int32, metricSpec autoscalingv2.MetricSpec, hpa *autoscalingv2.HorizontalPodAutoscaler,
	selector labels.Selector, status *autoscalingv2.MetricStatus) (replicaCountProposal int32, timestampProposal time.Time,
	metricNameProposal string, condition autoscalingv2.HorizontalPodAutoscalerCondition, err error) {

	// 计算容器资源指标的状态，并返回建议的副本数量、时间戳、指标名称、条件和错误
	replicaCountProposal, metricValueStatus, timestampProposal, metricNameProposal, condition, err := a.computeStatusForResourceMetricGeneric(ctx, currentReplicas, metricSpec.ContainerResource.Target, metricSpec.ContainerResource.Name, hpa.Namespace, metricSpec.ContainerResource.Container, selector, autoscalingv2.ContainerResourceMetricSourceType)
	if err != nil {
		// 如果计算状态出现错误，则设置无法计算副本数量的条件，并返回错误
		condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetContainerResourceMetric", err)
		return replicaCountProposal, timestampProposal, metricNameProposal, condition, err
	}

	// 将计算得到的状态更新到传入的参数 status 中
	*status = autoscalingv2.MetricStatus{
		Type: autoscalingv2.ContainerResourceMetricSourceType,
		ContainerResource: &autoscalingv2.ContainerResourceMetricStatus{
			Name:      metricSpec.ContainerResource.Name,
			Container: metricSpec.ContainerResource.Container,
			Current:   *metricValueStatus,
		},
	}

	// 返回建议的副本数量、时间戳、指标名称、条件和空错误
	return replicaCountProposal, timestampProposal, metricNameProposal, condition, nil
}
```



```go
func (a *HorizontalController) computeStatusForExternalMetric(specReplicas, statusReplicas int32, metricSpec autoscalingv2.MetricSpec, hpa *autoscalingv2.HorizontalPodAutoscaler, selector labels.Selector, status *autoscalingv2.MetricStatus) (replicaCountProposal int32, timestampProposal time.Time, metricNameProposal string, condition autoscalingv2.HorizontalPodAutoscalerCondition, err error) {
	// 如果 metricSpec.External.Target.AverageValue 不为空
	if metricSpec.External.Target.AverageValue != nil {
		// 调用 replicaCalc 的 GetExternalPerPodMetricReplicas 方法，计算推荐的副本数量、使用量、时间戳和错误
		replicaCountProposal, usageProposal, timestampProposal, err := a.replicaCalc.GetExternalPerPodMetricReplicas(statusReplicas, metricSpec.External.Target.AverageValue.MilliValue(), metricSpec.External.Metric.Name, hpa.Namespace, metricSpec.External.Metric.Selector)
		// 如果计算出现错误
		if err != nil {
			// 根据错误获取无法计算副本数量的条件
			condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetExternalMetric", err)
			// 返回错误信息
			return 0, time.Time{}, "", condition, fmt.Errorf("failed to get %s external metric: %v", metricSpec.External.Metric.Name, err)
		}
		// 将计算得到的结果设置到 MetricStatus 结构体中
		*status = autoscalingv2.MetricStatus{
			Type: autoscalingv2.ExternalMetricSourceType,
			External: &autoscalingv2.ExternalMetricStatus{
				Metric: autoscalingv2.MetricIdentifier{
					Name:     metricSpec.External.Metric.Name,
					Selector: metricSpec.External.Metric.Selector,
				},
				Current: autoscalingv2.MetricValueStatus{
					AverageValue: resource.NewMilliQuantity(usageProposal, resource.DecimalSI),
				},
			},
		}
		// 返回推荐的副本数量、时间戳、度量名称和空的条件和错误
		return replicaCountProposal, timestampProposal, fmt.Sprintf("external metric %s(%+v)", metricSpec.External.Metric.Name, metricSpec.External.Metric.Selector), autoscalingv2.HorizontalPodAutoscalerCondition{}, nil
	}
	// 如果 metricSpec.External.Target.Value 不为空
	if metricSpec.External.Target.Value != nil {
		// 调用 replicaCalc 的 GetExternalMetricReplicas 方法，计算推荐的副本数量、使用量、时间戳和错误
		replicaCountProposal, usageProposal, timestampProposal, err := a.replicaCalc.GetExternalMetricReplicas(specReplicas, metricSpec.External.Target.Value.MilliValue(), metricSpec.External.Metric.Name, hpa.Namespace, metricSpec.External.Metric.Selector, selector)
		if err != nil { // 如果发生错误
        condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetExternalMetric", err) // 调用方法设置条件
        return 0, time.Time{}, "", condition, fmt.Errorf("failed to get external metric %s: %v", metricSpec.External.Metric.Name, err) // 返回错误信息
    }

    *status = autoscalingv2.MetricStatus{ // 设置 MetricStatus 结构体的字段值
        Type: autoscalingv2.ExternalMetricSourceType, // 设置 Type 字段为 ExternalMetricSourceType
        External: &autoscalingv2.ExternalMetricStatus{ // 设置 External 字段为 ExternalMetricStatus 结构体指针
            Metric: autoscalingv2.MetricIdentifier{ // 设置 Metric 字段为 MetricIdentifier 结构体
                Name:     metricSpec.External.Metric.Name, // 设置 Name 字段为外部指标的名称
                Selector: metricSpec.External.Metric.Selector, // 设置 Selector 字段为外部指标的选择器
            },
            Current: autoscalingv2.MetricValueStatus{ // 设置 Current 字段为 MetricValueStatus 结构体
                Value: resource.NewMilliQuantity(usageProposal, resource.DecimalSI), // 设置 Value 字段为外部指标的当前值
            },
        },
    }

    return replicaCountProposal, timestampProposal, fmt.Sprintf("external metric %s(%+v)", metricSpec.External.Metric.Name, metricSpec.External.Metric.Selector), autoscalingv2.HorizontalPodAutoscalerCondition{}, nil // 返回各个计算结果以及空的条件和错误

    errMsg := "invalid external metric source: neither a value target nor an average value target was set" // 设置错误消息
    err = fmt.Errorf(errMsg) // 创建错误对象
    condition = a.getUnableComputeReplicaCountCondition(hpa, "FailedGetExternalMetric", err) // 调用方法设置条件
    return 0, time.Time{}, "", condition, fmt.Errorf(errMsg) // 返回错误信息和空的计算结果
}
```

#### setCurrentReplicasInStatus

```GO
func (a *HorizontalController) setCurrentReplicasInStatus(hpa *autoscalingv2.HorizontalPodAutoscaler, currentReplicas int32) {
	a.setStatus(hpa, currentReplicas, hpa.Status.DesiredReplicas, hpa.Status.CurrentMetrics, false)
}
```

##### setStatus

```GO
func (a *HorizontalController) setStatus(hpa *autoscalingv2.HorizontalPodAutoscaler, currentReplicas, desiredReplicas int32, metricStatuses []autoscalingv2.MetricStatus, rescale bool) {
	hpa.Status = autoscalingv2.HorizontalPodAutoscalerStatus{
		CurrentReplicas: currentReplicas,
		DesiredReplicas: desiredReplicas,
		LastScaleTime:   hpa.Status.LastScaleTime,
		CurrentMetrics:  metricStatuses,
		Conditions:      hpa.Status.Conditions,
	}

	if rescale {
		now := metav1.NewTime(time.Now())
		hpa.Status.LastScaleTime = &now
	}
}
```

#### normalizeDesiredReplicas

```GO
func (a *HorizontalController) normalizeDesiredReplicas(hpa *autoscalingv2.HorizontalPodAutoscaler, key string, currentReplicas int32, prenormalizedDesiredReplicas int32, minReplicas int32) int32 {
	// stabilizedRecommendation 函数调用，返回经过稳定化处理后的建议副本数
    stabilizedRecommendation := a.stabilizeRecommendation(key, prenormalizedDesiredReplicas)

    // 如果经过稳定化处理后的建议副本数与之前的不同，表示有变化，则设置相应的 condition 和 reason
    if stabilizedRecommendation != prenormalizedDesiredReplicas {
        setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionTrue, "ScaleDownStabilized", "recent recommendations were higher than current one, applying the highest recent recommendation")
    } else {
        // 如果经过稳定化处理后的建议副本数与之前相同，则设置另一组 condition 和 reason
        setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionTrue, "ReadyForNewScale", "recommended size matches current size")
    }

    // convertDesiredReplicasWithRules 函数调用，返回经过规则处理后的期望副本数、condition 和 reason
    desiredReplicas, condition, reason := convertDesiredReplicasWithRules(currentReplicas, stabilizedRecommendation, minReplicas, hpa.Spec.MaxReplicas)

    // 如果经过规则处理后的期望副本数与经过稳定化处理后的建议副本数相同，则设置相应的 condition 和 reason
    if desiredReplicas == stabilizedRecommendation {
        setCondition(hpa, autoscalingv2.ScalingLimited, v1.ConditionFalse, condition, reason)
    } else {
        // 如果经过规则处理后的期望副本数与经过稳定化处理后的建议副本数不同，则设置相应的 condition 和 reason
        setCondition(hpa, autoscalingv2.ScalingLimited, v1.ConditionTrue, condition, reason)
    }

    // 返回经过规则处理后的期望副本数
    return desiredReplicas
}
```

##### stabilizeRecommendation

```GO
func (a *HorizontalController) stabilizeRecommendation(key string, prenormalizedDesiredReplicas int32) int32 {
	// 将 prenormalizedDesiredReplicas 设为最大值
    maxRecommendation := prenormalizedDesiredReplicas

    // foundOldSample 和 oldSampleIndex 用于记录是否找到旧的样本及其位置
    foundOldSample := false
    oldSampleIndex := 0

    // cutoff 用于计算当前时间往前推 a.downscaleStabilisationWindow 后的时间
    cutoff := time.Now().Add(-a.downscaleStabilisationWindow)

    // 加锁保护 recommendations
    a.recommendationsLock.Lock()
    defer a.recommendationsLock.Unlock()

    // 遍历 recommendations[key]
    for i, rec := range a.recommendations[key] {
        // 如果当前记录的时间早于 cutoff，则认为是旧的样本
        if rec.timestamp.Before(cutoff) {
            foundOldSample = true
            oldSampleIndex = i
        // 否则，如果当前建议副本数大于最大值，则更新最大值
        } else if rec.recommendation > maxRecommendation {
            maxRecommendation = rec.recommendation
        }
    }

    // 如果找到了旧的样本，则用新的样本替换旧的样本
    if foundOldSample {
        a.recommendations[key][oldSampleIndex] = timestampedRecommendation{prenormalizedDesiredReplicas, time.Now()}
    } else {
        // 否则，将新的样本追加到 recommendations[key] 中
        a.recommendations[key] = append(a.recommendations[key], timestampedRecommendation{prenormalizedDesiredReplicas, time.Now()})
    }

    // 返回经过稳定化处理后的最大建议副本数
    return maxRecommendation
}
```

#### normalizeDesiredReplicasWithBehaviors

```GO
func (a *HorizontalController) normalizeDesiredReplicasWithBehaviors(hpa *autoscalingv2.HorizontalPodAutoscaler, key string, currentReplicas, prenormalizedDesiredReplicas, minReplicas int32) int32 {
	// 如果需要，初始化下降缩放稳定化窗口
	a.maybeInitScaleDownStabilizationWindow(hpa)

	// 初始化归一化参数结构体
	normalizationArg := NormalizationArg{
		Key:               key,
		ScaleUpBehavior:   hpa.Spec.Behavior.ScaleUp,
		ScaleDownBehavior: hpa.Spec.Behavior.ScaleDown,
		MinReplicas:       minReplicas,
		MaxReplicas:       hpa.Spec.MaxReplicas,
		CurrentReplicas:   currentReplicas,
		DesiredReplicas:   prenormalizedDesiredReplicas,
	}

	// 调用 stabilizeRecommendationWithBehaviors 方法获取经过扩缩容行为修正后的归一化推荐值
	stabilizedRecommendation, reason, message := a.stabilizeRecommendationWithBehaviors(normalizationArg)

	// 如果 stabilizeRecommendationWithBehaviors 返回的归一化推荐值与传入的 prenormalizedDesiredReplicas 不同，则设置 AbleToScale 条件
	if stabilizedRecommendation != prenormalizedDesiredReplicas {
		// AbleToScale 条件类型取决于 scale up/down 行为修正的结果
		setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionTrue, reason, message)
	} else {
		// 如果归一化推荐值与当前副本数相同，也设置 AbleToScale 条件，表示 ready for new scale
		setCondition(hpa, autoscalingv2.AbleToScale, v1.ConditionTrue, "ReadyForNewScale", "recommended size matches current size")
	}

	// 调用 convertDesiredReplicasWithBehaviorRate 方法获取最终的归一化推荐值，并返回
	desiredReplicas, reason, message := a.convertDesiredReplicasWithBehaviorRate(normalizationArg)

	// 设置 ScalingLimited 条件类型
	if desiredReplicas == stabilizedRecommendation {
		setCondition(hpa, autoscalingv2.ScalingLimited, v1.ConditionFalse, reason, message)
	} else {
		setCondition(hpa, autoscalingv2.ScalingLimited, v1.ConditionTrue, reason, message)
	}

	return desiredReplicas
}

type NormalizationArg struct {
	Key               string
	ScaleUpBehavior   *autoscalingv2.HPAScalingRules
	ScaleDownBehavior *autoscalingv2.HPAScalingRules
	MinReplicas       int32
	MaxReplicas       int32
	CurrentReplicas   int32
	DesiredReplicas   int32
}
```

##### maybeInitScaleDownStabilizationWindow

```GO
func (a *HorizontalController) maybeInitScaleDownStabilizationWindow(hpa *autoscalingv2.HorizontalPodAutoscaler) {
	behavior := hpa.Spec.Behavior
	if behavior != nil && behavior.ScaleDown != nil && behavior.ScaleDown.StabilizationWindowSeconds == nil {
        // 计算当前水平控制器的 downscaleStabilisationWindow 时间长度（秒），并将其赋值给 
		stabilizationWindowSeconds := (int32)(a.downscaleStabilisationWindow.Seconds())
		hpa.Spec.Behavior.ScaleDown.StabilizationWindowSeconds = &stabilizationWindowSeconds
	}
}
```

##### stabilizeRecommendationWithBehaviors

```GO
func (a *HorizontalController) stabilizeRecommendationWithBehaviors(args NormalizationArg) (int32, string, string) {
	now := time.Now() // 获取当前时间

	foundOldSample := false // 定义变量，表示是否找到旧的样本
	oldSampleIndex := 0 // 定义变量，表示旧样本的索引位置

	upRecommendation := args.DesiredReplicas // 设置初始上限推荐值为期望的副本数
	upDelaySeconds := *args.ScaleUpBehavior.StabilizationWindowSeconds // 获取上升行为的稳定窗口时间
	upCutoff := now.Add(-time.Second * time.Duration(upDelaySeconds)) // 计算上限时间截止值

	downRecommendation := args.DesiredReplicas // 设置初始下限推荐值为期望的副本数
	downDelaySeconds := *args.ScaleDownBehavior.StabilizationWindowSeconds // 获取下降行为的稳定窗口时间
	downCutoff := now.Add(-time.Second * time.Duration(downDelaySeconds)) // 计算下限时间截止值

	// 计算上下限推荐值
	a.recommendationsLock.Lock() // 加锁
	defer a.recommendationsLock.Unlock() // 最后解锁
	for i, rec := range a.recommendations[args.Key] { // 遍历每个时间戳推荐值
		if rec.timestamp.After(upCutoff) { // 如果时间戳在上限时间截止值之后
			upRecommendation = min(rec.recommendation, upRecommendation) // 记录最小推荐值
		}
		if rec.timestamp.After(downCutoff) { // 如果时间戳在下限时间截止值之后
			downRecommendation = max(rec.recommendation, downRecommendation) // 记录最大推荐值
		}
		if rec.timestamp.Before(upCutoff) && rec.timestamp.Before(downCutoff) { // 如果时间戳在上限和下限时间截止值之前
			foundOldSample = true // 标记找到旧的样本
			oldSampleIndex = i // 记录旧样本的索引位置
		}
	}

	// 将推荐值限制在上下限范围内（稳定）
	recommendation := args.CurrentReplicas // 将推荐值设置为当前副本数
	if recommendation < upRecommendation { // 如果推荐值小于上限推荐值
		recommendation = upRecommendation // 推荐值设置为上限推荐值
	}
	if recommendation > downRecommendation { // 如果推荐值大于下限推荐值
		recommendation = downRecommendation // 推荐值设置为下限推荐值
	}

	// 记录未稳定的推荐值
	if foundOldSample { // 如果找到了旧的样本
        a.recommendations[args.Key][oldSampleIndex] = timestampedRecommendation{args.DesiredReplicas, time.Now()} // 更新旧的样本
    } else {
        a.recommendations[args.Key] = append(a.recommendations[args.Key], timestampedRecommendation{args.DesiredReplicas, time.Now()}) // 添加新的样本
    }

    // 确定一个人性化的消息
    var reason, message string
    if args.DesiredReplicas >= args.CurrentReplicas { // 如果期望副本数大于等于当前副本数
        reason = "ScaleUpStabilized" // 则将原因标记为 "ScaleUpStabilized"，即稳定地增加副本数
        message = "recent recommendations were lower than current one, applying the lowest recent recommendation" // 将消息标记为最近的建议低于当前建议，应用最低的最近建议
    } else {
        reason = "ScaleDownStabilized" // 否则将原因标记为 "ScaleDownStabilized"，即稳定地减少副本数
        message = "recent recommendations were higher than current one, applying the highest recent recommendation" // 将消息标记为最近的建议高于当前建议，应用最高的最近建议
    }
    return recommendation, reason, message // 返回建议、原因和消息
}
```

##### convertDesiredReplicasWithBehaviorRate

```GO
func (a *HorizontalController) convertDesiredReplicasWithBehaviorRate(args NormalizationArg) (int32, string, string) {
	var possibleLimitingReason, possibleLimitingMessage string

	if args.DesiredReplicas > args.CurrentReplicas { // 如果期望的副本数大于当前的副本数
		a.scaleUpEventsLock.RLock() // 读锁定scaleUpEvents
		defer a.scaleUpEventsLock.RUnlock()
		a.scaleDownEventsLock.RLock() // 读锁定scaleDownEvents
		defer a.scaleDownEventsLock.RUnlock()
		scaleUpLimit := calculateScaleUpLimitWithScalingRules(args.CurrentReplicas, a.scaleUpEvents[args.Key], a.scaleDownEvents[args.Key], args.ScaleUpBehavior) // 计算上限

		if scaleUpLimit < args.CurrentReplicas { // 如果上限小于当前副本数，不应继续扩容直到清理scaleUpEvents
			scaleUpLimit = args.CurrentReplicas
		}
		maximumAllowedReplicas := args.MaxReplicas // 允许的最大副本数
		if maximumAllowedReplicas > scaleUpLimit { // 如果最大副本数大于上限，则按上限调整最大副本数
			maximumAllowedReplicas = scaleUpLimit
			possibleLimitingReason = "ScaleUpLimit" // 潜在的限制原因是上限
			possibleLimitingMessage = "the desired replica count is increasing faster than the maximum scale rate" // 潜在的限制消息是期望的副本数增加速度快于最大扩容速率
		} else {
			possibleLimitingReason = "TooManyReplicas" // 潜在的限制原因是副本数过多
			possibleLimitingMessage = "the desired replica count is more than the maximum replica count" // 潜在的限制消息是期望的副本数超过最大副本数
		}
		if args.DesiredReplicas > maximumAllowedReplicas { // 如果期望的副本数大于最大允许的副本数，则返回最大允许的副本数
			return maximumAllowedReplicas, possibleLimitingReason, possibleLimitingMessage
		}
	} else if args.DesiredReplicas < args.CurrentReplicas { // 如果期望的副本数小于当前的副本数
		a.scaleUpEventsLock.RLock() // 读锁定scaleUpEvents
		defer a.scaleUpEventsLock.RUnlock()
		a.scaleDownEventsLock.RLock() // 读锁定scaleDownEvents
		defer a.scaleDownEventsLock.RUnlock()
		scaleDownLimit := calculateScaleDownLimitWithBehaviors(args.CurrentReplicas, a.scaleUpEvents[args.Key], a.scaleDownEvents[args.Key], args.ScaleDownBehavior) // 计算下限

		if scaleDownLimit > args.CurrentReplicas { // 如果下限大于当前副本数，不应继续缩容直到清理scaleDownEvents
			scaleDownLimit = args.CurrentReplicas
		}
		minimumAllowedReplicas := args.MinReplicas // 允许的最小副本数
		if minimumAllowedReplicas < scaleDownLimit { //如果最小允许实例数量小于了扩容下限，则需要进行限制，记录下限制原因和原因描述信息
			minimumAllowedReplicas = scaleDownLimit // 记录限制原因为“扩容下限”
			possibleLimitingReason = "ScaleDownLimit"
			possibleLimitingMessage = "the desired replica count is decreasing faster than the maximum scale rate"
		} else { // 如果不需要限制，则记录原因描述信息和原因
			possibleLimitingMessage = "the desired replica count is less than the minimum replica count"
			possibleLimitingReason = "TooFewReplicas"
		}
		if args.DesiredReplicas < minimumAllowedReplicas { // 如果期望的实例数量小于了最小允许实例数量，则需要进行限制，返回最小允许实例数量以及限制原因和原因描述信息
			return minimumAllowedReplicas, possibleLimitingReason, possibleLimitingMessage
		}
	}
    // 如果实例数量在合理范围内，则返回期望的实例数量以及状态“DesiredWithinRange”和状态描述信息“期望的实例数量在可接受的范围内”
	return args.DesiredReplicas, "DesiredWithinRange", "the desired count is within the acceptable range"
}
```

