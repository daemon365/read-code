## 简介

Kubelet OOM (Out of Memory) Watcher 是 Kubernetes 中的一个组件，它负责监控运行在节点上的容器是否发生内存不足的情况，并采取相应的处理措施。

当容器使用的内存接近或超过其限制时，Kubelet OOM Watcher 将触发相应的事件。这些事件可以由 Kubernetes 集群中的其他组件（如调度器）使用，以便采取适当的行动。例如，可以将容器重新调度到其他具有更多可用内存资源的节点上，或者可以通知运维人员进行进一步的故障排除。

OOM Watcher 的主要目标是提高集群的可靠性和稳定性。通过监控容器的内存使用情况并及时采取措施，可以避免容器由于内存不足而崩溃或影响其他容器的正常运行。

需要注意的是，Kubelet OOM Watcher 只能监控运行在节点上的容器的内存使用情况，并触发相应的事件。对于节点本身的内存使用情况，通常会使用操作系统级别的监控工具来进行监控和管理。

## Watcher

```GO
// Watcher定义了OOM监视器的接口。
type Watcher interface {
	Start(ref *v1.ObjectReference) error
}
```

## realWatcher

```GO
// realWatcher是实现Watcher接口的结构体。
type realWatcher struct {
	recorder    record.EventRecorder
	oomStreamer streamer
}

var _ Watcher = &realWatcher{}

// NewWatcher创建并初始化一个以Cadvisor作为OOM数据流的OOMWatcher。
func NewWatcher(recorder record.EventRecorder) (Watcher, error) {
	// 用于测试目的
	_, ok := recorder.(*record.FakeRecorder)
	if ok {
		return nil, nil
	}

	oomStreamer, err := oomparser.New()
	if err != nil {
		return nil, err
	}

	watcher := &realWatcher{
		recorder:    recorder,
		oomStreamer: oomStreamer,
	}

	return watcher, nil
}
```

### streamer

```GO
// streamer是OOM数据流接口。
type streamer interface {
	StreamOoms(chan<- *oomparser.OomInstance)
}

var _ streamer = &oomparser.OomParser{}
```

### Start

```GO
// Start函数用于监视系统OOM事件，并为每个遇到的系统OOM记录一个事件。
func (ow *realWatcher) Start(ref *v1.ObjectReference) error {
	outStream := make(chan *oomparser.OomInstance, 10)
	go ow.oomStreamer.StreamOoms(outStream)

	go func() {
		defer runtime.HandleCrash()

		for event := range outStream {
			if event.VictimContainerName == recordEventContainerName {
				klog.V(1).InfoS("Got sys oom event", "event", event)
				eventMsg := "System OOM encountered"
				if event.ProcessName != "" && event.Pid != 0 {
					eventMsg = fmt.Sprintf("%s, victim process: %s, pid: %d", eventMsg, event.ProcessName, event.Pid)
				}
				ow.recorder.Eventf(ref, v1.EventTypeWarning, systemOOMEvent, eventMsg)
			}
		}
		klog.ErrorS(nil, "Unexpectedly stopped receiving OOM notifications")
	}()
	return nil
}

const (
	systemOOMEvent           = "SystemOOM"
	recordEventContainerName = "/"
)
```

## OomParser

```GO
// OomParser封装了一个kmsgparser，用于从各个内核环形缓冲区消息中提取OOM事件。
type OomParser struct {
	parser kmsgparser.Parser
}
```

### OomInstance

```GO
// OomInstance是包含与OOM kill实例相关信息的结构体。
type OomInstance struct {
	Pid                 int       // 被杀死进程的进程ID
	ProcessName         string    // 被杀死进程的名称
	TimeOfDeath         time.Time // 进程被报告杀死的时间（精确到分钟）
	ContainerName       string    // OOM的容器的绝对名称
	VictimContainerName string    // 被杀死的容器的绝对名称
	Constraint          string    // 触发OOM的约束条件，其中一种：CONSTRAINT_NONE、CONSTRAINT_CPUSET、CONSTRAINT_MEMORY_POLICY、CONSTRAINT_MEMCG
}

// 初始化一个OomParser对象。返回一个OomParser对象和一个错误。
func New() (*OomParser, error) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		return nil, err
	}
	parser.SetLogger(glogAdapter{})
	return &OomParser{parser: parser}, nil
}
```

### StreamOoms

```GO
// StreamOoms向提供的输出流写入表示日志中找到的OOM事件的OomInstance对象。
// 它会阻塞，并应该从一个goroutine中调用。
func (p *OomParser) StreamOoms(outStream chan<- *OomInstance) {
	kmsgEntries := p.parser.Parse()
	defer p.parser.Close()

	for msg := range kmsgEntries {
		isOomMessage := checkIfStartOfOomMessages(msg.Message)
		if isOomMessage {
			oomCurrentInstance := &OomInstance{
				ContainerName:       "/",
				VictimContainerName: "/",
				TimeOfDeath:         msg.Timestamp,
			}
			for msg := range kmsgEntries {
				finished, err := getContainerName(msg.Message, oomCurrentInstance)
				if err != nil {
					klog.Errorf("%v", err)
				}
				if !finished {
					finished, err = getProcessNamePid(msg.Message, oomCurrentInstance)
					if err != nil {
						klog.Errorf("%v", err)
					}
				}
				if finished {
					oomCurrentInstance.TimeOfDeath = msg.Timestamp
					break
				}
			}
			outStream <- oomCurrentInstance
		}
	}
	// 不应该发生
	klog.Errorf("exiting analyzeLines. OOM events will not be reported.")
}
```

#### getLegacyContainerName

```GO
// 从一行中提取容器名称并将其添加到oomInstance中。
func getLegacyContainerName(line string, currentOomInstance *OomInstance) error {
	parsedLine := legacyContainerRegexp.FindStringSubmatch(line)
	if parsedLine == nil {
		return nil
	}
	currentOomInstance.ContainerName = path.Join("/", parsedLine[1])
	currentOomInstance.VictimContainerName = path.Join("/", parsedLine[2])
	return nil
}
```

#### getContainerName

```GO
// 从一行中提取容器名称并将其添加到oomInstance中。
func getContainerName(line string, currentOomInstance *OomInstance) (bool, error) {
	parsedLine := containerRegexp.FindStringSubmatch(line)
	if parsedLine == nil {
		// 如果在这里找不到，就退回到旧格式。
		return false, getLegacyContainerName(line, currentOomInstance)
	}
	currentOomInstance.ContainerName = parsedLine[6]
	currentOomInstance.VictimContainerName = parsedLine[5]
	currentOomInstance.Constraint = parsedLine[1]
	pid, err := strconv.Atoi(parsedLine[8])
	if err != nil {
		return false, err
	}
	currentOomInstance.Pid = pid
	currentOomInstance.ProcessName = parsedLine[7]
	return true, nil
}
```

#### getProcessNamePid

```GO
// 从一行中提取进程的PID、名称和日期，并将其添加到oomInstance中。
func getProcessNamePid(line string, currentOomInstance *OomInstance) (bool, error) {
	reList := lastLineRegexp.FindStringSubmatch(line)

	if reList == nil {
		return false, nil
	}

	pid, err := strconv.Atoi(reList[1])
	if err != nil {
		return false, err
	}
	currentOomInstance.Pid = pid
	currentOomInstance.ProcessName = reList[2]
	return true, nil
}
```

#### checkIfStartOfOomMessages

```GO
// 使用正则表达式检查一行是否为内核OOM日志的开头。
func checkIfStartOfOomMessages(line string) bool {
	potentialOomStart := firstLineRegexp.MatchString(line)
	return potentialOomStart
}
```

