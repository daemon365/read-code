
## 简介

Kubelet的Container Log Manager是一个子模块，用于管理容器的日志收集和转发。在Kubernetes中，每个Pod都可以包含一个或多个容器。当容器运行时，它们会生成日志，这些日志需要被收集和存储以供后续分析和故障排除。Kubelet的Container Log Manager就是用来解决这个问题的。

## ContainerLogManager

```GO
// ContainerLogManager是管理所有容器日志生命周期的接口。
//
// 实现是线程安全的。
type ContainerLogManager interface {
	// TODO（random-liu）：添加RotateLogs函数，并在磁盘压力下调用它。
	// 启动容器日志管理器。
	Start()
	// 清除删除指定容器的所有日志。
	Clean(ctx context.Context, containerID string) error
}
```

## containerLogManager

```GO
type containerLogManager struct {
	runtimeService internalapi.RuntimeService
	osInterface    kubecontainer.OSInterface
	policy         LogRotatePolicy
	clock          clock.Clock
	mutex          sync.Mutex
}
```

### LogRotatePolicy

```GO
// LogRotatePolicy是容器日志轮转的策略。该策略适用于kubelet管理的所有容器。
type LogRotatePolicy struct {
	// 容器日志文件在轮转之前的最大大小（以字节为单位）。负数表示禁用容器日志轮转。
	MaxSize int64
	// 最大允许存在的日志文件数。如果轮转日志导致超出文件数限制，则最旧的文件将被删除。
	MaxFiles int
}
```

## NewContainerLogManager

```GO
// NewContainerLogManager创建一个新的容器日志管理器。
func NewContainerLogManager(runtimeService internalapi.RuntimeService, osInterface kubecontainer.OSInterface, maxSize string, maxFiles int) (ContainerLogManager, error) {
	if maxFiles <= 1 {
		return nil, fmt.Errorf("invalid MaxFiles %d, must be > 1", maxFiles)
	}
	parsedMaxSize, err := parseMaxSize(maxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container log max size %q: %v", maxSize, err)
	}
	// 负数表示禁用容器日志轮转
	if parsedMaxSize < 0 {
		return NewStubContainerLogManager(), nil
	}
	// 定义policy LogRotatePolicy
	return &containerLogManager{
		osInterface:    osInterface,
		runtimeService: runtimeService,
		policy: LogRotatePolicy{
			MaxSize:  parsedMaxSize,
			MaxFiles: maxFiles,
		},
		clock: clock.RealClock{},
		mutex: sync.Mutex{},
	}, nil
}
```

### parseMaxSize

```GO
// parseMaxSize将容量字符串解析为以字节为单位的int64最大大小。
func parseMaxSize(size string) (int64, error) {
	quantity, err := resource.ParseQuantity(size)
	if err != nil {
		return 0, err
	}
	maxSize, ok := quantity.AsInt64()
	if !ok {
		return 0, fmt.Errorf("invalid max log size")
	}
	return maxSize, nil
}
```

## Start

```GO
// 启动容器日志管理器。
func (c *containerLogManager) Start() {
	ctx := context.Background()
	// 启动一个 goroutine 定期执行容器日志轮转。
	go wait.Forever(func() {
		if err := c.rotateLogs(ctx); err != nil {
			klog.ErrorS(err, "Failed to rotate container logs")
		}
	}, logMonitorPeriod)
}
```

### rotateLogs

```GO
func (c *containerLogManager) rotateLogs(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// TODO(#59998): 使用 kubelet pod 缓存。
	containers, err := c.runtimeService.ListContainers(ctx, &runtimeapi.ContainerFilter{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %v", err)
	}
	// NOTE(random-liu): 弄清楚是否需要并行旋转容器日志。
	for _, container := range containers {
		// 只为正在运行的容器轮转日志。非运行中的容器不会生成新的输出，保留空的最新日志没有意义。
		if container.GetState() != runtimeapi.ContainerState_CONTAINER_RUNNING {
			continue
		}
		id := container.GetId()
		// 注意，我们不应该因为单个容器的错误而阻塞日志轮转。
		resp, err := c.runtimeService.ContainerStatus(ctx, id, false)
		if err != nil {
			klog.ErrorS(err, "Failed to get container status", "containerID", id)
			continue
		}
		if resp.GetStatus() == nil {
			klog.ErrorS(err, "Container status is nil", "containerID", id)
			continue
		}
		path := resp.GetStatus().GetLogPath()
		info, err := c.osInterface.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				klog.ErrorS(err, "Failed to stat container log", "path", path)
				continue
			}
			// 在 rotateLatestLog 中，有几种情况下在 ReopenContainerLog 失败后我们可能会丢失原始容器日志。
			// 我们尝试通过重新打开容器日志来恢复它。
			if err := c.runtimeService.ReopenContainerLog(ctx, id); err != nil {
				klog.ErrorS(err, "Container log doesn't exist, reopen container log failed", "containerID", id, "path", path)
				continue
			}
			// 容器日志应该已经恢复。
			info, err = c.osInterface.Stat(path)
			if err != nil {
				klog.ErrorS(err, "Failed to stat container log after reopen", "path", path)
				continue
			}
		}
		if info.Size() < c.policy.MaxSize {
			continue
		}
		// 执行日志轮转。
		if err := c.rotateLog(ctx, id, path); err != nil {
			klog.ErrorS(err, "Failed to rotate log for container", "path", path, "containerID", id)
			continue
		}
	}
	return nil
}
```

#### rotateLog

```GO
func (c containerLogManager) rotateLog(ctx context.Context, id, log string) error {
	// pattern 用于匹配所有已轮转的文件。
	pattern := fmt.Sprintf("%s.", log)
	logs, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to list all log files with pattern %q: %v", pattern, err)
	}

	logs, err = c.cleanupUnusedLogs(logs)
	if err != nil {
		return fmt.Errorf("failed to cleanup logs: %v", err)
	}

	logs, err = c.removeExcessLogs(logs)
	if err != nil {
		return fmt.Errorf("failed to remove excess logs: %v", err)
	}

	// 压缩未压缩的日志文件。
	for _, l := range logs {
		if strings.HasSuffix(l, compressSuffix) {
			continue
		}
		if err := c.compressLog(l); err != nil {
			return fmt.Errorf("failed to compress log %q: %v", l, err)
		}
	}

	if err := c.rotateLatestLog(ctx, id, log); err != nil {
		return fmt.Errorf("failed to rotate log %q: %v", log, err)
	}

	return nil
}
```

##### cleanupUnusedLogs

```GO
// cleanupUnusedLogs清理由之前的日志轮转失败生成的临时或未使用的日志文件。
func (c *containerLogManager) cleanupUnusedLogs(logs []string) ([]string, error) {
	inuse, unused := filterUnusedLogs(logs)
	for _, l := range unused {
		if err := c.osInterface.Remove(l); err != nil {
			return nil, fmt.Errorf("failed to remove unused log %q: %v", l, err)
		}
	}
	return inuse, nil
}
```

##### removeExcessLogs

```GO
// removeExcessLogs删除旧的日志文件，以确保最多只有 MaxFiles 个日志文件。
func (c *containerLogManager) removeExcessLogs(logs []string) ([]string, error) {
	// 将日志文件按照从最旧到最新的顺序排序。
	sort.Strings(logs)
	// 容器将创建一个新的日志文件，我们将轮转最新的日志文件。
	// 除了这两个文件之外，我们最多可以有 MaxFiles-2 个轮转的日志文件。
	// 通过删除旧文件来保留 MaxFiles-2 个文件。
	// 我们应该从最旧到最新进行删除，以免打断正在进行的 kubectl logs。
	maxRotatedFiles := c.policy.MaxFiles - 2
	if maxRotatedFiles < 0 {
		maxRotatedFiles = 0
	}
	i := 0
	for ; i < len(logs)-maxRotatedFiles; i++ {
		if err := c.osInterface.Remove(logs[i]); err != nil {
			return nil, fmt.Errorf("failed to remove old log %q: %v", logs[i], err)
		}
	}
	logs = logs[i:]
	return logs, nil
}
```

##### compressLog

```GO
// compressLog使用gzip将日志压缩为log.gz。
func (c *containerLogManager) compressLog(log string) error {
	r, err := c.osInterface.Open(log)
	if err != nil {
		return fmt.Errorf("failed to open log %q: %v", log, err)
	}
	defer r.Close()
	tmpLog := log + tmpSuffix
	f, err := c.osInterface.OpenFile(tmpLog, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create temporary log %q: %v", tmpLog, err)
	}
	defer func() {
		// 尽力清理tmpLog。
		c.osInterface.Remove(tmpLog)
	}()
	defer f.Close()
	w := gzip.NewWriter(f)
	defer w.Close()
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("failed to compress %q to %q: %v", log, tmpLog, err)
	}
	// 在重命名之前需要关闭归档，否则在Windows上会出现错误。
	w.Close()
	f.Close()
	compressedLog := log + compressSuffix
	if err := c.osInterface.Rename(tmpLog, compressedLog); err != nil {
		return fmt.Errorf("failed to rename %q to %q: %v", tmpLog, compressedLog, err)
	}
	// 删除旧的日志文件。
	r.Close()
	if err := c.osInterface.Remove(log); err != nil {
		return fmt.Errorf("failed to remove log %q after compress: %v", log, err)
	}
	return nil
}
```

##### rotateLatestLog

```GO
// rotateLatestLog不压缩最新的日志，以便容器仍然可以写入
// 和 fluentd 可以完成读取。
func (c *containerLogManager) rotateLatestLog(ctx context.Context, id, log string) error {
	timestamp := c.clock.Now().Format(timestampFormat)
	rotated := fmt.Sprintf("%s.%s", log, timestamp)
	if err := c.osInterface.Rename(log, rotated); err != nil {
		return fmt.Errorf("failed to rotate log %q to %q: %v", log, rotated, err)
	}
	if err := c.runtimeService.ReopenContainerLog(ctx, id); err != nil {
		// 将旋转的日志重命名回来，这样我们下一轮可以尝试再次轮转它。
		// 如果此时 kubelet 被重新启动，我们将丢失原始日志。
		if renameErr := c.osInterface.Rename(rotated, log); renameErr != nil {
			// 这不应该发生。
			// 如果发生这种情况，报告一个错误，因为我们将丢失原始日志。
			klog.ErrorS(renameErr, "Failed to rename rotated log", "rotatedLog", rotated, "newLog", log, "containerID", id)
		}
		return fmt.Errorf("failed to reopen container log %q: %v", id, err)
	}
	return nil
}
```

## Clean

```GO
// Clean删除指定容器的所有日志（包括轮转的日志）。
func (c containerLogManager) Clean(ctx context.Context, containerID string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	resp, err := c.runtimeService.ContainerStatus(ctx, containerID, false)
	if err != nil {
		return fmt.Errorf("failed to get container status %q: %v", containerID, err)
	}
	if resp.GetStatus() == nil {
		return fmt.Errorf("container status is nil for %q", containerID)
	}
	pattern := fmt.Sprintf("%s", resp.GetStatus().GetLogPath())
	logs, err := c.osInterface.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to list all log files with pattern %q: %v", pattern, err)
	}

	for _, l := range logs {
		if err := c.osInterface.Remove(l); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove container %q log %q: %v", containerID, l, err)
		}
	}

	return nil
}
```

