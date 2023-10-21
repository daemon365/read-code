## 简介

kubelet中的ProbeManager是Kubernetes集群中的一个关键组件，它负责管理和执行容器的探针（Probes）。ProbeManager的主要功能是定期检查容器的健康状态，并根据探针的结果采取相应的行动。

在kubelet的配置中，可以定义三种类型的探针：Liveness Probe（存活性探针）、Readiness Probe（就绪性探针）和Startup Probe（启动探针）。这些探针可通过容器的配置文件（Pod Spec）进行定义。

- Liveness Probe（存活性探针）用于检测容器是否仍然运行。如果Liveness Probe失败，则kubelet会认为容器不再运行，并尝试重启该容器。
- Readiness Probe（就绪性探针）用于检测容器是否已准备好接收流量。如果Readiness Probe失败，则kubelet会将该容器从负载均衡器中剔除，直到探测成功为止。
- Startup Probe（启动探针）用于检测容器是否已启动并准备好接收流量。与Liveness Probe和Readiness Probe不同，Startup Probe只在容器启动过程中执行，并且仅在容器首次启动时生效。

ProbeManager负责按照配置定义的时间间隔执行探针，并根据探针的结果更新容器的状态。它会监测探针的成功或失败，并根据失败的情况触发相应的操作，如重启容器或从负载均衡器中移除容器。

通过使用ProbeManager，Kubernetes可以确保容器的健康状态和可用性，并在探针失败时自动采取相应的措施，以保持应用程序的稳定运行。

## Manager

```GO
// Manager 管理 Pod 探测。对于每个指定了探测的容器（通过 AddPod 方法），它创建一个探测 "worker"。
// 该 worker 定期对其分配的容器进行探测并缓存结果。当请求更新 PodStatus 时，Manager 
// 使用缓存的探测结果设置适当的 Ready 状态。目前不支持更新探测参数。
type Manager interface {
	// AddPod 为每个容器探测创建新的 worker。应在创建每个 Pod 时调用此方法。
	AddPod(pod *v1.Pod)

	// StopLivenessAndStartup 在终止期间处理停止存活性和启动探测。
	StopLivenessAndStartup(pod *v1.Pod)

	// RemovePod 处理已删除的 Pod 状态清理，包括终止探测 worker 和删除缓存结果。
	RemovePod(pod *v1.Pod)

	// CleanupPods 清理不再运行的 Pod。它接收一个“期望的 Pod”映射，这些 Pod 不应该被清理。
	CleanupPods(desiredPods map[types.UID]sets.Empty)

	// UpdatePodStatus 根据容器运行状态、缓存的探测结果和 worker 状态修改给定的 PodStatus 中的适当 Ready 状态。
	UpdatePodStatus(types.UID, *v1.PodStatus)
}
```

## manager

```GO
type manager struct {
	// 用于探测的活动 worker 映射
	workers map[probeKey]*worker
	// 访问和修改 worker 的锁
	workerLock sync.RWMutex

	// statusManager 缓存提供了用于探测的 Pod IP 和容器 ID。
	statusManager status.Manager

	// readinessManager 管理就绪性探测的结果
	readinessManager results.Manager

	// livenessManager 管理存活性探测的结果
	livenessManager results.Manager

	// startupManager 管理启动探测的结果
	startupManager results.Manager

	// prober 执行探测操作。
	prober *prober

	start time.Time
}
```

### probeKey

```GO
// probeKey 是唯一标识容器探测的键。
type probeKey struct {
    podUID types.UID
    containerName string
    probeType probeType
}

// 探测类型（存活性、就绪性或启动性）
type probeType int

const (
	liveness              probeType = iota         // 存活性探测
	readiness                                      // 就绪性探测
	startup                                        // 启动性探测
	probeResultSuccessful string    = "successful" // 探测结果：成功
	probeResultFailed     string    = "failed"     // 探测结果：失败
	probeResultUnknown    string    = "unknown"    // 探测结果：未知
)

// 用于调试的方法。
func (t probeType) String() string {
	switch t {
	case readiness:
		return "Readiness"
	case liveness:
		return "Liveness"
	case startup:
		return "Startup"
	default:
		return "UNKNOWN"
	}
}
```

## NewManager

```GO
// NewManager 创建一个用于 Pod 探测的 Manager。
func NewManager(
	statusManager status.Manager,
	livenessManager results.Manager,
	readinessManager results.Manager,
	startupManager results.Manager,
	runner kubecontainer.CommandRunner,
	recorder record.EventRecorder) Manager {

	prober := newProber(runner, recorder)
	return &manager{
		statusManager:    statusManager,
		prober:           prober,
		readinessManager: readinessManager,
		livenessManager:  livenessManager,
		startupManager:   startupManager,
		workers:          make(map[probeKey]*worker),
		start:            clock.RealClock{}.Now(),
	}
}
```

#### deepCopyPrometheusLabelsS

```GO
// 定义一个名为deepCopyPrometheusLabels的函数，接收一个metrics.Labels类型的参数m，返回一个metrics.Labels类型的值
func deepCopyPrometheusLabels(m metrics.Labels) metrics.Labels {
	// 创建一个长度为m的metrics.Labels类型的变量ret
	ret := make(metrics.Labels, len(m))
	// 遍历m中的每个键值对，将其复制到ret中
	for k, v := range m {
		ret[k] = v
	}
	// 返回ret
	return ret
}

```

#### getPodLabelName

```GO
// 定义一个名为getPodLabelName的函数，接收一个*v1.Pod类型的指针参数pod，返回一个字符串类型的值
func getPodLabelName(pod *v1.Pod) string {
	// 将pod的Name赋值给变量podName
	podName := pod.Name
	// 如果pod的GenerateName不为空
	if pod.GenerateName != "" {
		// 使用"-"将pod的Name分割成一个字符串切片podNameSlice
		podNameSlice := strings.Split(pod.Name, "-")
		// 将podNameSlice中除最后一个元素外的所有元素用"-"连接起来，并赋值给podName
		podName = strings.Join(podNameSlice[:len(podNameSlice)-1], "-")
		// 如果pod的标签中存在apps.DefaultDeploymentUniqueLabelKey键，并将对应的值赋值给label变量，ok为true
		if label, ok := pod.GetLabels()[apps.DefaultDeploymentUniqueLabelKey]; ok {
			// 将podName中的所有"-<label>"替换为空字符串，并赋值给podName
			podName = strings.ReplaceAll(podName, fmt.Sprintf("-%s", label), "")
		}
	}
	// 返回podName
	return podName
}
```

## prober

```GO
// Prober帮助检查容器的活跃性/就绪性/启动状态。
type prober struct {
	exec   execprobe.Prober
	http   httpprobe.Prober
	tcp    tcpprobe.Prober
	grpc   grpcprobe.Prober
	runner kubecontainer.CommandRunner

	recorder record.EventRecorder
}
```

### newProber

```GO
// newProber 创建一个 Prober，它接受一个命令运行器和多个容器信息管理器。
func newProber(
	runner kubecontainer.CommandRunner,
	recorder record.EventRecorder) *prober {
	const followNonLocalRedirects = false
	return &prober{
		exec:     execprobe.New(),
		http:     httpprobe.New(followNonLocalRedirects),
		tcp:      tcpprobe.New(),
		grpc:     grpcprobe.New(),
		runner:   runner,
		recorder: recorder,
	}
}
```

#### recordContainerEvent

```go
// recordContainerEvent应该被prober用于所有与容器相关的事件。
func (pb *prober) recordContainerEvent(pod *v1.Pod, container *v1.Container, eventType, reason, message string, args ...interface{}) {
	ref, err := kubecontainer.GenerateContainerRef(pod, container)
	if err != nil {
		klog.ErrorS(err, "无法创建pod和容器的引用", "pod", klog.KObj(pod), "containerName", container.Name)
		return
	}
	pb.recorder.Eventf(ref, eventType, reason, message, args...)
}
```

### probe

```GO
// probe探测容器。
func (pb *prober) probe(ctx context.Context, probeType probeType, pod *v1.Pod, status v1.PodStatus, container v1.Container, containerID kubecontainer.ContainerID) (results.Result, error) {
	var probeSpec *v1.Probe
	switch probeType {
	case readiness:
		probeSpec = container.ReadinessProbe
	case liveness:
		probeSpec = container.LivenessProbe
	case startup:
		probeSpec = container.StartupProbe
	default:
		return results.Failure, fmt.Errorf("未知的探测类型：%q", probeType)
	}

	if probeSpec == nil {
		klog.InfoS("探测为空", "probeType", probeType, "pod", klog.KObj(pod), "podUID", pod.UID, "containerName", container.Name)
		return results.Success, nil
	}

	result, output, err := pb.runProbeWithRetries(ctx, probeType, probeSpec, pod, status, container, containerID, maxProbeRetries)
	if err != nil || (result != probe.Success && result != probe.Warning) {
		// 探测以某种方式失败。
		if err != nil {
			klog.V(1).ErrorS(err, "探测发生错误", "probeType", probeType, "pod", klog.KObj(pod), "podUID", pod.UID, "containerName", container.Name)
			pb.recordContainerEvent(pod, &container, v1.EventTypeWarning, events.ContainerUnhealthy, "%s 探测发生错误：%v", probeType, err)
		} else { // result != probe.Success
			klog.V(1).InfoS("探测失败", "probeType", probeType, "pod", klog.KObj(pod), "podUID", pod.UID, "containerName", container.Name, "probeResult", result, "output", output)
			pb.recordContainerEvent(pod, &container, v1.EventTypeWarning, events.ContainerUnhealthy, "%s 探测失败：%s", probeType, output)
		}
		return results.Failure, err
	}
	if result == probe.Warning {
		pb.recordContainerEvent(pod, &container, v1.EventTypeWarning, events.ContainerProbeWarning, "%s 探测警告：%s", probeType, output)
		klog.V(3).InfoS("探测成功，但有警告", "probeType", probeType, "pod", klog.KObj(pod), "podUID", pod.UID, "containerName", container.Name, "output", output)
	} else {
		klog.V(3).InfoS("探测成功", "probeType", probeType, "pod", klog.KObj(pod), "podUID", pod.UID, "containerName", container.Name)
	}
	return results.Success, nil
}
```

### runProbeWithRetries

```GO
// runProbeWithRetries尝试在有限的循环中对容器进行探测，如果从未成功，则返回最后的结果。
func (pb *prober) runProbeWithRetries(ctx context.Context, probeType probeType, p *v1.Probe, pod *v1.Pod, status v1.PodStatus, container v1.Container, containerID kubecontainer.ContainerID, retries int) (probe.Result, string, error) {
	var err error
	var result probe.Result
	var output string
	for i := 0; i < retries; i++ {
		result, output, err = pb.runProbe(ctx, probeType, p, pod, status, container, containerID)
		if err == nil {
			return result, output, nil
		}
	}
	return result, output, err
}
```

#### runProbe

```go
func (pb *prober) runProbe(ctx context.Context, probeType probeType, p *v1.Probe, pod *v1.Pod, status v1.PodStatus, container v1.Container, containerID kubecontainer.ContainerID) (probe.Result, string, error) {
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if p.Exec != nil {
		klog.V(4).InfoS("执行探测", "pod", klog.KObj(pod), "containerName", container.Name, "execCommand", p.Exec.Command)
		command := kubecontainer.ExpandContainerCommandOnlyStatic(p.Exec.Command, container.Env)
		return pb.exec.Probe(pb.newExecInContainer(ctx, container, containerID, command, timeout))
	}
	if p.HTTPGet != nil {
		req, err := httpprobe.NewRequestForHTTPGetAction(p.HTTPGet, &container, status.PodIP, "probe")
		if err != nil {
			return probe.Unknown, "", err
		}
		if klogV4 := klog.V(4); klogV4.Enabled() {
			port := req.URL.Port()
			host := req.URL.Hostname()
			path := req.URL.Path
			scheme := req.URL.Scheme
			headers := p.HTTPGet.HTTPHeaders
			klogV4.InfoS("HTTP探测", "scheme", scheme, "host", host, "port", port, "path", path, "timeout", timeout, "headers", headers)
		}
		return pb.http.Probe(req, timeout)
	}
	if p.TCPSocket != nil {
		port, err := probe.ResolveContainerPort(p.TCPSocket.Port, &container)
		if err != nil {
			return probe.Unknown, "", err
		}
		host := p.TCPSocket.Host
		if host == "" {
			host = status.PodIP
		}
		klog.V(4).InfoS("TCP探测", "host", host, "port", port, "timeout", timeout)
		return pb.tcp.Probe(host, port, timeout)
	}

	if p.GRPC != nil {
		host := status.PodIP
		service := ""
		if p.GRPC.Service != nil {
			service = *p.GRPC.Service
		}
		klog.V(4).InfoS("GRPC探测", "host", host, "service", service, "port", p.GRPC.Port, "timeout", timeout)
		return pb.grpc.Probe(host, service, int(p.GRPC.Port), timeout)
	}

	klog.InfoS("无法找到容器的探测构建器", "containerName", container.Name)
	return probe.Unknown, "", fmt.Errorf("缺少%s的探测处理程序：%s", format.Pod(pod), container.Name)
}
```

### execInContainer

```GO
type execInContainer struct {
	// run在容器中执行命令。始终返回合并的stdout和stderr输出。如果发生错误，则返回错误。
	run    func() ([]byte, error)
	writer io.Writer
}

func (pb *prober) newExecInContainer(ctx context.Context, container v1.Container, containerID kubecontainer.ContainerID, cmd []string, timeout time.Duration) exec.Cmd {
	return &execInContainer{run: func() ([]byte, error) {
		return pb.runner.RunInContainer(ctx, containerID, cmd, timeout)
	}}
}

func (eic *execInContainer) Run() error {
	return nil
}

func (eic *execInContainer) CombinedOutput() ([]byte, error) {
	return eic.run()
}

func (eic *execInContainer) Output() ([]byte, error) {
	return nil, fmt.Errorf("未实现")
}

func (eic *execInContainer) SetDir(dir string) {
	// 未实现
}

func (eic *execInContainer) SetStdin(in io.Reader) {
	// 未实现
}

func (eic *execInContainer) SetStdout(out io.Writer) {
	eic.writer = out
}

func (eic *execInContainer) SetStderr(out io.Writer) {
	eic.writer = out
}

func (eic *execInContainer) SetEnv(env []string) {
	// 未实现
}

func (eic *execInContainer) Stop() {
	// 未实现
}

func (eic *execInContainer) Start() error {
	data, err := eic.run()
	if eic.writer != nil {
		// 仅记录写入错误，不覆盖命令运行错误
		if p, err := eic.writer.Write(data); err != nil {
			klog.ErrorS(err, "无法将execInContainer的所有字节写入", "expectedBytes", len(data), "actualBytes", p)
		}
	}
	return err
}

func (eic *execInContainer) Wait() error {
	return nil
}

func (eic *execInContainer) StdoutPipe() (io.ReadCloser, error) {
	return nil, fmt.Errorf("未实现")
}

func (eic *execInContainer) StderrPipe() (io.ReadCloser, error) {
	return nil, fmt.Errorf("未实现")
}
```

## worker

```GO
// worker用于定期探测其分配的容器。每个worker都有一个关联的go程，该go程在容器永久终止或停止通道关闭之前运行探测循环。
// worker使用probe Manager的statusManager来获取最新的容器ID。
type worker struct {
	// 用于停止探测的通道。
	stopCh chan struct{}

	// 用于手动触发探测的通道。
	manualTriggerCh chan struct{}

	// 包含此探测的Pod（只读）
	pod *v1.Pod

	// 要探测的容器（只读）
	container v1.Container

	// 描述探测配置（只读）
	spec *v1.Probe

	// worker的类型。
	probeType probeType

	// 初始延迟期间的探测结果。
	initialValue results.Result

	// 存储此worker结果的位置。
	resultsManager results.Manager
	probeManager   *manager

	// 此worker的最后已知容器ID。
	containerID kubecontainer.ContainerID
	// 此worker的最后探测结果。
	lastResult results.Result
	// 探测连续返回相同结果的次数。
	resultRun int

	// 如果设置，跳过探测。
	onHold bool

	// proberResultsMetricLabels通过结果为此worker附加标签，用于ProberResults指标。
	proberResultsSuccessfulMetricLabels metrics.Labels
	proberResultsFailedMetricLabels     metrics.Labels
	proberResultsUnknownMetricLabels    metrics.Labels
	// proberDurationMetricLabels通过结果为此worker附加标签，用于ProberDuration指标。
	proberDurationSuccessfulMetricLabels metrics.Labels
	proberDurationUnknownMetricLabels    metrics.Labels
}
```

### newWorker

```GO
// 创建并启动一个新的探测worker。
func newWorker(
	m *manager, // 管理器对象
	probeType probeType, // 探测类型：readiness、liveness、startup
	pod *v1.Pod, // Pod对象
	container v1.Container) *worker { // 容器对象
	w := &worker{
		stopCh:          make(chan struct{}, 1), // 缓冲通道，用于停止探测
		manualTriggerCh: make(chan struct{}, 1), // 缓冲通道，用于手动触发探测
		pod:             pod,
		container:       container,
		probeType:       probeType,
		probeManager:    m,
	}

	switch probeType {
	case readiness:
		w.spec = container.ReadinessProbe
		w.resultsManager = m.readinessManager
		w.initialValue = results.Failure
	case liveness:
		w.spec = container.LivenessProbe
		w.resultsManager = m.livenessManager
		w.initialValue = results.Success
	case startup:
		w.spec = container.StartupProbe
		w.resultsManager = m.startupManager
		w.initialValue = results.Unknown
	}

	podName := getPodLabelName(w.pod)

	basicMetricLabels := metrics.Labels{
		"probe_type": w.probeType.String(),
		"container":  w.container.Name,
		"pod":        podName,
		"namespace":  w.pod.Namespace,
		"pod_uid":    string(w.pod.UID),
	}

	proberDurationLabels := metrics.Labels{
		"probe_type": w.probeType.String(),
		"container":  w.container.Name,
		"pod":        podName,
		"namespace":  w.pod.Namespace,
	}

	w.proberResultsSuccessfulMetricLabels = deepCopyPrometheusLabels(basicMetricLabels)
	w.proberResultsSuccessfulMetricLabels["result"] = probeResultSuccessful

	w.proberResultsFailedMetricLabels = deepCopyPrometheusLabels(basicMetricLabels)
	w.proberResultsFailedMetricLabels["result"] = probeResultFailed

	w.proberResultsUnknownMetricLabels = deepCopyPrometheusLabels(basicMetricLabels)
	w.proberResultsUnknownMetricLabels["result"] = probeResultUnknown

	w.proberDurationSuccessfulMetricLabels = deepCopyPrometheusLabels(proberDurationLabels)
	w.proberDurationUnknownMetricLabels = deepCopyPrometheusLabels(proberDurationLabels)

	return w
}
```

### run

```GO
// 定期进行容器探测。
func (w *worker) run() {
	ctx := context.Background()
	probeTickerPeriod := time.Duration(w.spec.PeriodSeconds) * time.Second

	// 如果kubelet重新启动，则可能会快速开始探测。
	// 让worker在探测之前等待tickerPeriod的随机部分。
	// 只有在kubelet最近启动时才这样做。
	if probeTickerPeriod > time.Since(w.probeManager.start) {
		time.Sleep(time.Duration(rand.Float64() * float64(probeTickerPeriod)))
	}

	probeTicker := time.NewTicker(probeTickerPeriod)

	defer func() {
		// 清理工作
		probeTicker.Stop()
		if !w.containerID.IsEmpty() {
			w.resultsManager.Remove(w.containerID)
		}

		w.probeManager.removeWorker(w.pod.UID, w.container.Name, w.probeType)
		ProberResults.Delete(w.proberResultsSuccessfulMetricLabels)
		ProberResults.Delete(w.proberResultsFailedMetricLabels)
		ProberResults.Delete(w.proberResultsUnknownMetricLabels)
		ProberDuration.Delete(w.proberDurationSuccessfulMetricLabels)
		ProberDuration.Delete(w.proberDurationUnknownMetricLabels)
	}()

probeLoop:
	for w.doProbe(ctx) {
		// 等待下一次探测间隔。
		select {
		case <-w.stopCh:
			break probeLoop
		case <-probeTicker.C:
		case <-w.manualTriggerCh:
			// 继续
		}
	}
}
```

#### doProbe

```GO
// doProbe对容器进行一次探测并记录结果。
// 返回worker是否应继续执行。
func (w *worker) doProbe(ctx context.Context) (keepGoing bool) {
	defer func() { recover() }() // 捕获panic（HandleCrash会处理日志记录）
	defer runtime.HandleCrash(func(_ interface{}) { keepGoing = true })

	startTime := time.Now()
	status, ok := w.probeManager.statusManager.GetPodStatus(w.pod.UID)
	if !ok {
		// 要么Pod还没有被创建，要么已经被删除。
		klog.V(3).InfoS("没有Pod状态", "pod", klog.KObj(w.pod))
		return true
	}

	// 如果Pod已终止，则worker应停止。
	if status.Phase == v1.PodFailed || status.Phase == v1.PodSucceeded {
		klog.V(3).InfoS("Pod已终止，退出探测worker",
			"pod", klog.KObj(w.pod), "phase", status.Phase)
		return false
	}

	c, ok := podutil.GetContainerStatus(status.ContainerStatuses, w.container.Name)
	if !ok || len(c.ContainerID) == 0 {
		// 要么容器还没有被创建，要么已经被删除。
		klog.V(3).InfoS("找不到探测目标容器",
			"pod", klog.KObj(w.pod), "containerName", w.container.Name)
		return true // 等待更多信息。
	}

	if w.containerID.String() != c.ContainerID {
		if !w.containerID.IsEmpty() {
			w.resultsManager.Remove(w.containerID)
		}
		w.containerID = kubecontainer.ParseContainerID(c.ContainerID)
		w.resultsManager.Set(w.containerID, w.initialValue, w.pod)
		// 有一个新的容器，恢复探测。
		w.onHold = false
	}

	if w.onHold {
		// Worker在等待新容器之前暂停。
		return true
	}

	if c.State.Running == nil {
		klog.V(3).InfoS("探测非运行中的容器",
			"pod", klog.KObj(w.pod), "containerName", w.container.Name)
		if !w.containerID.IsEmpty() {
			w.resultsManager.Set(w.containerID, results.Failure, w.pod)
		}
		// 如果容器不会被重新启动，则中止。
		return c.State.Terminated == nil ||
			w.pod.Spec.RestartPolicy != v1.RestartPolicyNever
	}

	// 优雅关闭Pod。
	if w.pod.ObjectMeta.DeletionTimestamp != nil && (w.probeType == liveness || w.probeType == startup) {
		klog.V(3).InfoS("请求删除Pod，将探测结果设置为成功",
			"probeType", w.probeType, "pod", klog.KObj(w.pod), "containerName", w.container.Name)
		if w.probeType == startup {
			klog.InfoS("在容器完全启动之前请求删除Pod",
				"pod", klog.KObj(w.pod), "containerName", w.container.Name)
		}
		// 设置最后一个结果以确保安静关闭。
		w.resultsManager.Set(w.containerID, results.Success, w.pod)
		// 在此时停止探测。
		return false
	}

	// 禁用InitialDelaySeconds的探测。
	if int32(time.Since(c.State.Running.StartedAt.Time).Seconds()) < w.spec.InitialDelaySeconds {
		return true
	}

	if c.Started != nil && *c.Started {
		// 容器启动后停止启动探测。
		// 为了确保重新启动的容器也能正常工作，我们保持其运行状态。
		if w.probeType == startup {
			return true
		}
	} else {
		// 直到容器启动之前禁用其他探测。
		if w.probeType != startup {
			return true
		}
	}

	// 注意，exec探测无法访问Pod环境变量或向下API。
	result, err := w.probeManager.prober.probe(ctx, w.probeType, w.pod, status, w.container, w.containerID)
	if err != nil {
		// Prober错误，丢弃结果。
		return true
	}

	switch result {
	case results.Success:
		ProberResults.With(w.proberResultsSuccessfulMetricLabels).Inc()
		ProberDuration.With(w.proberDurationSuccessfulMetricLabels).Observe(time.Since(startTime).Seconds())
	case results.Failure:
		ProberResults.With(w.proberResultsFailedMetricLabels).Inc()
	default:
		ProberResults.With(w.proberResultsUnknownMetricLabels).Inc()
		ProberDuration.With(w.proberDurationUnknownMetricLabels).Observe(time.Since(startTime).Seconds())
	}

	if w.lastResult == result {
		w.resultRun++
	} else {
		w.lastResult = result
		w.resultRun = 1
	}

	if (result == results.Failure && w.resultRun < int(w.spec.FailureThreshold)) ||
		(result == results.Success && w.resultRun < int(w.spec.SuccessThreshold)) {
		// 成功或失败次数未达到阈值-保持探测状态不变。
		return true
	}

	w.resultsManager.Set(w.containerID, result, w.pod)

	if (w.probeType == liveness || w.probeType == startup) && result == results.Failure {
		// 容器未通过活跃性/启动性检查，需要重新启动。
		// 在看到新的容器ID之前，停止处理探测结果。
		w.onHold = true
		// 这个返回值是重要的，因为在一个ticker周期中返回false会导致此worker被删除。
		// 因此，我们在这个周期结束之前返回true，以便在处理新的容器ID之前保持worker活动状态。
		return true
	}

	return c.State.Running != nil && w.pod.Spec.RestartPolicy == v1.RestartPolicyAlways
}
```



### stop

```GO
// 停止探测worker。该worker会处理清理工作并从管理器中删除自身。
// 可以多次调用stop而不会有问题。
func (w *worker) stop() {
	select {
	case w.stopCh <- struct{}{}:
	default: // 非阻塞。
	}
}
```



## AddPod

```GO
func (m *manager) AddPod(pod *v1.Pod) {
	m.workerLock.Lock()
	defer m.workerLock.Unlock()

	key := probeKey{podUID: pod.UID}
	for _, c := range pod.Spec.Containers {
		key.containerName = c.Name

		if c.StartupProbe != nil {
			key.probeType = startup
			if _, ok := m.workers[key]; ok {
				klog.V(8).ErrorS(nil, "Startup probe already exists for container",
					"pod", klog.KObj(pod), "containerName", c.Name)
				return
			}
			w := newWorker(m, startup, pod, c)
			m.workers[key] = w
			go w.run()
		}

		if c.ReadinessProbe != nil {
			key.probeType = readiness
			if _, ok := m.workers[key]; ok {
				klog.V(8).ErrorS(nil, "Readiness probe already exists for container",
					"pod", klog.KObj(pod), "containerName", c.Name)
				return
			}
			w := newWorker(m, readiness, pod, c)
			m.workers[key] = w
			go w.run()
		}

		if c.LivenessProbe != nil {
			key.probeType = liveness
			if _, ok := m.workers[key]; ok {
				klog.V(8).ErrorS(nil, "Liveness probe already exists for container",
					"pod", klog.KObj(pod), "containerName", c.Name)
				return
			}
			w := newWorker(m, liveness, pod, c)
			m.workers[key] = w
			go w.run()
		}
	}
}
```

## StopLivenessAndStartup

```go
// 这段代码定义了一个结构体方法，用于停止指定Pod的存活检测和启动检测
func (m *manager) StopLivenessAndStartup(pod *v1.Pod) {
	// 获取读锁
	m.workerLock.RLock()
	// 延迟释放读锁
	defer m.workerLock.RUnlock()

	// 创建探测键，用于标识探测的唯一性
	key := probeKey{podUID: pod.UID}
	// 遍历Pod的所有容器
	for _, c := range pod.Spec.Containers {
		// 设置探测键的容器名称
		key.containerName = c.Name
		// 遍历探测类型列表（包括存活检测和启动检测）
		for _, probeType := range [...]probeType{liveness, startup} {
			// 设置探测键的探测类型
			key.probeType = probeType
			// 检查是否存在对应的worker，如果存在，则停止该worker
			if worker, ok := m.workers[key]; ok {
				worker.stop()
			}
		}
	}
}
```

## RemovePod

```go
// 这段代码定义了一个结构体方法，用于移除指定Pod的所有探测任务
func (m *manager) RemovePod(pod *v1.Pod) {
	// 获取读锁
	m.workerLock.RLock()
	// 延迟释放读锁
	defer m.workerLock.RUnlock()

	// 创建探测键，用于标识探测的唯一性
	key := probeKey{podUID: pod.UID}
	// 遍历Pod的所有容器
	for _, c := range pod.Spec.Containers {
		// 设置探测键的容器名称
		key.containerName = c.Name
		// 遍历探测类型列表（包括就绪检测、存活检测和启动检测）
		for _, probeType := range [...]probeType{readiness, liveness, startup} {
			// 设置探测键的探测类型
			key.probeType = probeType
			// 检查是否存在对应的worker，如果存在，则停止该worker
			if worker, ok := m.workers[key]; ok {
				worker.stop()
			}
		}
	}
}
```

### removeWorker

```go
// 这段代码定义了一个结构体方法，用于移除指定的worker
func (m *manager) removeWorker(podUID types.UID, containerName string, probeType probeType) {
	// 获取写锁
	m.workerLock.Lock()
	// 延迟释放写锁
	defer m.workerLock.Unlock()
	// 根据探测键从workers映射中移除对应的worker
	delete(m.workers, probeKey{podUID, containerName, probeType})
}
```



## CleanupPods

```go
// 这段代码定义了一个结构体方法，用于清理不在desiredPods列表中的所有探测任务
func (m *manager) CleanupPods(desiredPods map[types.UID]sets.Empty) {
	// 获取读锁
	m.workerLock.RLock()
	// 延迟释放读锁
	defer m.workerLock.RUnlock()

	// 遍历所有的worker
	for key, worker := range m.workers {
		// 检查当前worker对应的Pod UID是否存在于desiredPods列表中
		if _, ok := desiredPods[key.podUID]; !ok {
			// 如果不存在，则停止该worker
			worker.stop()
		}
	}
}
```

## UpdatePodStatus

```go
// 这段代码定义了一个结构体方法，用于更新Pod的状态信息
func (m *manager) UpdatePodStatus(podUID types.UID, podStatus *v1.PodStatus) {
	// 遍历Pod的容器状态列表
	for i, c := range podStatus.ContainerStatuses {
		var started bool
		// 检查容器是否正在运行
		if c.State.Running == nil {
			started = false
		} else if result, ok := m.startupManager.Get(kubecontainer.ParseContainerID(c.ContainerID)); ok {
			// 检查容器的启动状态是否为成功
			started = result == results.Success
		} else {
			// 检查是否存在未运行的探测任务
			_, exists := m.getWorker(podUID, c.Name, startup)
			started = !exists
		}
		// 更新容器的Started字段
		podStatus.ContainerStatuses[i].Started = &started

		if started {
			var ready bool
			// 检查容器是否正在运行
			if c.State.Running == nil {
				ready = false
			} else if result, ok := m.readinessManager.Get(kubecontainer.ParseContainerID(c.ContainerID)); ok && result == results.Success {
				// 检查容器的就绪状态是否为成功
				ready = true
			} else {
				// 检查是否存在未运行的就绪探测任务
				w, exists := m.getWorker(podUID, c.Name, readiness)
				ready = !exists // 没有就绪探测任务 -> 总是就绪
				if exists {
					// 触发立即运行就绪探测任务以更新就绪状态
					select {
					case w.manualTriggerCh <- struct{}{}:
					default: // 非阻塞方式
						klog.InfoS("Failed to trigger a manual run", "probe", w.probeType.String())
					}
				}
			}
			// 更新容器的Ready字段
			podStatus.ContainerStatuses[i].Ready = ready
		}
	}

	// 对于初始化容器，如果其已成功退出或具有成功的就绪探测任务，则认为其已就绪
	for i, c := range podStatus.InitContainerStatuses {
		var ready bool
		if c.State.Terminated != nil && c.State.Terminated.ExitCode == 0 {
			ready = true
		}
		podStatus.InitContainerStatuses[i].Ready = ready
	}
}s
```

### getWorker

```go
// 这段代码定义了一个结构体方法，用于根据Pod UID、容器名称和探测类型获取对应的worker
func (m *manager) getWorker(podUID types.UID, containerName string, probeType probeType) (*worker, bool) {
	// 获取读锁
	m.workerLock.RLock()
	// 延迟释放读锁
	defer m.workerLock.RUnlock()
	// 根据探测键从workers映射中获取对应的worker
	worker, ok := m.workers[probeKey{podUID, containerName, probeType}]
	return worker, ok
}
```

## workerCount

```go
// 这段代码定义了一个结构体方法，用于返回探测worker的总数（用于测试）
func (m *manager) workerCount() int {
	// 获取读锁
	m.workerLock.RLock()
	// 延迟释放读锁
	defer m.workerLock.RUnlock()
	// 返回workers映射中的worker数量
	return len(m.workers)
}
```

## results Manager

```go
// Manager提供了一个探测结果缓存和更新通道。
type Manager interface {
	// Get返回具有给定ID的容器的缓存结果。
	Get(kubecontainer.ContainerID) (Result, bool)
	// Set设置具有给定ID的容器的缓存结果。
	// Pod仅包含在更新时发送。
	Set(kubecontainer.ContainerID, Result, *v1.Pod)
	// Remove清除具有给定ID的容器的缓存结果。
	Remove(kubecontainer.ContainerID)
	// Updates创建一个通道，在其结果发生更改时接收Update（但不删除）。
	// 注意：当前实现仅支持单个updates通道。
	Updates() <-chan Update
}
```

### Result

```go
// Result是探测结果的类型。
type Result int

const (
	// Unknown被编码为-1（Result类型）
	Unknown Result = iota - 1
	// Success被编码为0（Result类型）
	Success
	// Failure被编码为1（Result类型）
	Failure
)

func (r Result) String() string {
	switch r {
	case Success:
		return "Success"
	case Failure:
		return "Failure"
	default:
		return "UNKNOWN"
	}
}

// ToPrometheusType将Result转换为Prometheus更好理解的形式。
func (r Result) ToPrometheusType() float64 {
	switch r {
	case Success:
		return 0
	case Failure:
		return 1
	default:
		return -1
	}
}
```

### Update

```go
// Update是在Updates通道上发送的更新类型枚举。
type Update struct {
	ContainerID kubecontainer.ContainerID
	Result      Result
	PodUID      types.UID
}
```

### manager

```go
// Manager的实现。
type manager struct {
	// 保护缓存的锁
	sync.RWMutex
	// 容器ID -> 探测结果的映射
	cache map[kubecontainer.ContainerID]Result
	// 更新通道
	updates chan Update
}

var _ Manager = &manager{}

// NewManager创建并返回一个空的结果管理器。
func NewManager() Manager {
	return &manager{
		cache:   make(map[kubecontainer.ContainerID]Result),
		updates: make(chan Update, 20),
	}
}
```

### Get

```go
func (m *manager) Get(id kubecontainer.ContainerID) (Result, bool) {
	m.RLock()
	defer m.RUnlock()
	result, found := m.cache[id]
	return result, found
}
```

### Set

```go
// set的锁定部分的内部辅助函数。返回是否应该发送更新。
func (m *manager) Set(id kubecontainer.ContainerID, result Result, pod *v1.Pod) {
	if m.setInternal(id, result) {
		m.updates <- Update{id, result, pod.UID}
	}
}
```

#### setInternal

```go
func (m *manager) setInternal(id kubecontainer.ContainerID, result Result) bool {
	m.Lock()
	defer m.Unlock()
	prev, exists := m.cache[id]
	if !exists || prev != result {
		m.cache[id] = result
		return true
	}
	return false
}
```

### Remove

```go
func (m *manager) Remove(id kubecontainer.ContainerID) {
	m.Lock()
	defer m.Unlock()
	delete(m.cache, id)
}
```

### Updates

```go
func (m *manager) Updates() <-chan Update {
	return m.updates
}
```

