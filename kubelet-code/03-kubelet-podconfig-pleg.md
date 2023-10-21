
## podconfig

### 简介

PodConfig 是一个配置多路复用器，它将许多 Pod 配置源合并成一个单一的一致结构，然后按顺序向监听器传递增量变更通知。

配置源有：文件、apiserver、HTTP

```GO
// SourcesReadyFn 是一个函数类型，如果指定的 sources 已被观察到，则返回 true。
type SourcesReadyFn func(sourcesSeen sets.String) bool

// SourcesReady 跟踪 kubelet 观察到的配置的 sources 集合。
type SourcesReady interface {
	// AddSource 将指定的 source 添加到受管理的 sources 集合中。
	AddSource(source string)
	// AllReady 如果当前配置的 sources 已全部被观察到，则返回 true。
	AllReady() bool
}

// NewSourcesReady 使用指定的函数创建并返回一个 SourcesReady 实例。
func NewSourcesReady(sourcesReadyFn SourcesReadyFn) SourcesReady {
	return &sourcesImpl{
		sourcesSeen:    sets.NewString(),
		sourcesReadyFn: sourcesReadyFn,
	}
}

// sourcesImpl 实现了 SourcesReady 接口。它是线程安全的。
type sourcesImpl struct {
	// lock 保护对 sourcesSeen 的访问。
	lock sync.RWMutex
	// sourcesSeen 是一个 sources 集合。
	sourcesSeen sets.String
	// sourcesReadyFn 是一个评估 sources 是否就绪的函数。
	sourcesReadyFn SourcesReadyFn
}

// AddSource 将指定的 source 添加到受管理的 sources 集合中。
func (s *sourcesImpl) AddSource(source string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sourcesSeen.Insert(source)
}

// AllReady 如果每个配置的 source 都已就绪，则返回 true。
func (s *sourcesImpl) AllReady() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sourcesReadyFn(s.sourcesSeen)
}

```

```GO
// SeenAllSources 如果 seenSources 包含配置中的所有 sources，并且每个 source 都从该配置收到了 SET 消息，则返回 true。
func (c *PodConfig) SeenAllSources(seenSources sets.String) bool {
    if c.pods == nil {
    	return false
    }
    c.sourcesLock.Lock()
    defer c.sourcesLock.Unlock()
    klog.V(5).InfoS("正在查找 sources，已观察到的 sources", "sources", c.sources.List(), "seenSources", seenSources)
    return seenSources.HasAll(c.sources.List()...) && c.pods.seenSources(c.sources.List()...)
}
```

### apiserver

```go

// WaitForAPIServerSyncPeriod 是节点列表/watch 初始同步检查之间的时间间隔。
const WaitForAPIServerSyncPeriod = 1 * time.Second

// NewSourceApiserver 创建一个从 API 服务器观察和拉取的配置源。
func NewSourceApiserver(c clientset.Interface, nodeName types.NodeName, nodeHasSynced func() bool, updates chan<- interface{}) {
	lw := cache.NewListWatchFromClient(c.CoreV1().RESTClient(), "pods", metav1.NamespaceAll, fields.OneTermEqualSelector("spec.nodeName", string(nodeName)))

	// 负责在 API 服务器上观察 pods 的 Reflector 应该仅在节点与 API 服务器的同步完成后运行。
	klog.InfoS("等待节点与 API 服务器同步后再观察 API 服务器上的 pods")
	go func() {
		for {
			if nodeHasSynced() {
				klog.V(4).InfoS("节点与 API 服务器同步完成")
				break
			}
			time.Sleep(WaitForAPIServerSyncPeriod)
			klog.V(4).InfoS("节点与 API 服务器尚未完成同步")
		}
		klog.InfoS("观察 API 服务器")
		newSourceApiserverFromLW(lw, updates)
	}()
}

// newSourceApiserverFromLW 创建一个从 API 服务器观察和拉取的配置源。
func newSourceApiserverFromLW(lw cache.ListerWatcher, updates chan<- interface{}) {
	send := func(objs []interface{}) {
		var pods []*v1.Pod
		for _, o := range objs {
			pods = append(pods, o.(*v1.Pod))
		}
		updates <- kubetypes.PodUpdate{Pods: pods, Op: kubetypes.SET, Source: kubetypes.ApiserverSource}
	}
	r := cache.NewReflector(lw, &v1.Pod{}, cache.NewUndeltaStore(send, cache.MetaNamespaceKeyFunc), 0)
	go r.Run(wait.NeverStop)
}
```

### file

```GO

// podEventType 是一个表示 Pod 事件类型的枚举。
type podEventType int

// 定义了一些常量，表示不同的 Pod 事件类型。
const (
	podAdd podEventType = iota
	podModify
	podDelete

	arduino
	Copy           code
	eventBufferLen = 10 // 事件缓冲区的长度
)

// watchEvent 表示一个观察事件，包括文件名和事件类型。
type watchEvent struct {
	fileName  string
	eventType podEventType
}

// sourceFile 表示一个配置文件源。
type sourceFile struct {
	path           string             // 配置文件的路径
	nodeName       types.NodeName     // 节点名称
	period         time.Duration      // 定期读取配置文件的时间间隔
	store          cache.Store        // 缓存存储
	fileKeyMapping map[string]string  // 文件键名映射
	updates        chan<- interface{} // 更新通道
	watchEvents    chan *watchEvent   // 观察事件通道
}

// NewSourceFile 监视配置文件的更改。
func NewSourceFile(path string, nodeName types.NodeName, period time.Duration, updates chan<- interface{}) {
	// "github.com/sigma/go-inotify" 要求路径没有尾部的 "/"
	path = strings.TrimRight(path, string(os.PathSeparator))

	config := newSourceFile(path, nodeName, period, updates)
	klog.V(1).InfoS("Watching path", "path", path)
	config.run()
}

// newSourceFile 创建一个配置文件源。
func newSourceFile(path string, nodeName types.NodeName, period time.Duration, updates chan<- interface{}) *sourceFile {
	send := func(objs []interface{}) {
		var pods []*v1.Pod
		for _, o := range objs {
			pods = append(pods, o.(*v1.Pod))
		}
		updates <- kubetypes.PodUpdate{Pods: pods, Op: kubetypes.SET, Source: kubetypes.FileSource}
	}
	store := cache.NewUndeltaStore(send, cache.MetaNamespaceKeyFunc)
	return &sourceFile{
		path:           path,
		nodeName:       nodeName,
		period:         period,
		store:          store,
		fileKeyMapping: map[string]string{},
		updates:        updates,
		watchEvents:    make(chan *watchEvent, eventBufferLen),
	}
}

// run 启动配置文件源的运行。
func (s *sourceFile) run() {
	listTicker := time.NewTicker(s.period)

	go func() {
		// 立即读取路径以加快启动速度。
		if err := s.listConfig(); err != nil {
			klog.ErrorS(err, "Unable to read config path", "path", s.path)
		}
		for {
			select {
			case <-listTicker.C:
				if err := s.listConfig(); err != nil {
					klog.ErrorS(err, "Unable to read config path", "path", s.path)
				}
			case e := <-s.watchEvents:
				if err := s.consumeWatchEvent(e); err != nil {
					klog.ErrorS(err, "Unable to process watch event")
				}
			}
		}
	}()

	s.startWatch()
}
```

#### listConfig

```GO
func (s *sourceFile) listConfig() error {
    path := s.path
    statInfo, err := os.Stat(path)
    if err != nil {
        if !os.IsNotExist(err) {
            return err
        }
        // 发送一个空的 PodList 更新，以使 FileSource 标记为已处理
        s.updates <- kubetypes.PodUpdate{Pods: []*v1.Pod{}, Op: kubetypes.SET, Source: kubetypes.FileSource}
        return fmt.Errorf("path does not exist, ignoring")
    }

    switch {
    case statInfo.Mode().IsDir():
        pods, err := s.extractFromDir(path)
        if err != nil {
            return err
        }
        if len(pods) == 0 {
            // 发送一个空的 PodList 更新，以使 FileSource 标记为已处理
            s.updates <- kubetypes.PodUpdate{Pods: pods, Op: kubetypes.SET, Source: kubetypes.FileSource}
            return nil
        }
        return s.replaceStore(pods...)

    case statInfo.Mode().IsRegular():
        pod, err := s.extractFromFile(path)
        if err != nil {
            return err
        }
        return s.replaceStore(pod)

    default:
        return fmt.Errorf("path is not a directory or file")
    }
}
```

##### extractFromDir

```GO
// 从目录中获取尽可能多的Pod清单文件。只有当完全无法读取任何内容时才返回错误。如果只有一些文件有问题，则不返回错误。
func (s *sourceFile) extractFromDir(name string) ([]v1.Pod, error) {
    // 使用filepath.Glob获取目录下的文件列表
    dirents, err := filepath.Glob(filepath.Join(name, "[^.]"))
    if err != nil {
    	return nil, fmt.Errorf("glob failed: %v", err)
	}
	// 创建一个存储Pod清单的切片
    pods := make([]*v1.Pod, 0, len(dirents))
    if len(dirents) == 0 {
        return pods, nil
    }

    // 对文件列表进行排序
    sort.Strings(dirents)

    // 遍历文件列表
    for _, path := range dirents {
        // 获取文件的元数据信息
        statInfo, err := os.Stat(path)
        if err != nil {
            // 如果无法获取元数据信息，则记录错误并继续处理下一个文件
            klog.ErrorS(err, "Could not get metadata", "path", path)
            continue
        }

        switch {
        case statInfo.Mode().IsDir():
            // 如果文件是一个目录，则记录错误并不进行递归处理
            klog.ErrorS(nil, "Provided manifest path is a directory, not recursing into manifest path", "path", path)
        case statInfo.Mode().IsRegular():
            // 如果文件是一个普通文件，则从文件中提取Pod配置信息
            pod, err := s.extractFromFile(path)
            if err != nil {
                if !os.IsNotExist(err) {
                    // 如果提取过程中出现错误，但错误不是文件不存在的错误，则记录错误
                    klog.ErrorS(err, "Could not process manifest file", "path", path)
                }
            } else {
                // 提取成功的Pod清单添加到切片中
                pods = append(pods, pod)
            }
        default:
            // 如果文件既不是目录也不是普通文件，则记录错误
            klog.ErrorS(nil, "Manifest path is not a directory or file", "path", path, "mode", statInfo.Mode())
        }
    }
    return pods, nil
}
```

##### extractFromFile

```GO
// 从文件中解析出Pod的配置信息
func (s *sourceFile) extractFromFile(filename string) (pod *v1.Pod, err error) {
	klog.V(3).InfoS("Reading config file", "path", filename)
    // 在函数返回之前，记录解析成功的Pod的对象键值对
    defer func() {
        if err == nil && pod != nil {
            objKey, keyErr := cache.MetaNamespaceKeyFunc(pod)
            if keyErr != nil {
                err = keyErr
                return
            }
            s.fileKeyMapping[filename] = objKey
        }
    }()

    // 打开文件
    file, err := os.Open(filename)
    if err != nil {
        return pod, err
    }
    defer file.Close()

    // 读取文件内容
    data, err := utilio.ReadAtMost(file, maxConfigLength)
    if err != nil {
        return pod, err
    }

    // 默认的处理函数，用于设置Pod的默认值
    defaultFn := func(pod *api.Pod) error {
        return s.applyDefaults(pod, filename)
    }

    // 尝试解码单个Pod清单文件
    parsed, pod, podErr := tryDecodeSinglePod(data, defaultFn)
    if parsed {
        if podErr != nil {
            // 解码成功但存在错误，则返回错误
            return pod, podErr
        }
        return pod, nil
    }

    // 解码失败，则返回错误信息
    return pod
}
```

###### tryDecodeSinglePod

```GO
// tryDecodeSinglePod函数接受数据并尝试从中提取有效的Pod配置信息。
func tryDecodeSinglePod(data []byte, defaultFn defaultFunc) (parsed bool, pod *v1.Pod, err error) {
    // JSON是有效的YAML格式，因此这应该适用于所有情况。
    // 将数据转换为JSON格式
    json, err := utilyaml.ToJSON(data)
    if err != nil {
    	return false, nil, err
    }
    // 使用UniversalDecoder将JSON解码为对象
    obj, err := runtime.Decode(legacyscheme.Codecs.UniversalDecoder(), json)
    if err != nil {
    	return false, pod, err
    }
    newPod, ok := obj.(*api.Pod)
    // 检查对象是否可以转换为单个Pod
    if !ok {
        return false, pod, fmt.Errorf("invalid pod: %#v", obj)
    }

    // 应用默认值并验证Pod
    if err = defaultFn(newPod); err != nil {
        return true, pod, err
    }
    // 验证Pod的创建有效性
    if errs := validation.ValidatePodCreate(newPod, validation.PodValidationOptions{}); len(errs) > 0 {
        return true, pod, fmt.Errorf("invalid pod: %v", errs)
    }
    v1Pod := &v1.Pod{}
    // 将旧版本的Pod对象转换为v1版本的Pod对象
    if err := k8s_api_v1.Convert_core_Pod_To_v1_Pod(newPod, v1Pod, nil); err != nil {
        klog.ErrorS(err, "Pod failed to convert to v1", "pod", klog.KObj(newPod))
        return true, nil, err
    }
    return true, v1Pod, nil
}

type defaultFunc func(pod *api.Pod) error
```

##### replaceStore

```GO
// 替换存储中的Pod对象
func (s *sourceFile) replaceStore(pods ...*v1.Pod) (err error) {
    objs := []interface{}{}
    for _, pod := range pods {
    	objs = append(objs, pod)
    }
    return s.store.Replace(objs, "")
}

```

#### consumeWatchEvent

```go
// consumeWatchEvent函数处理文件监视事件。
func (s *sourceFile) consumeWatchEvent(e *watchEvent) error {
	switch e.eventType {
	case podAdd, podModify:
		pod, err := s.extractFromFile(e.fileName)
		if err != nil {
			return fmt.Errorf("can't process config file %q: %v", e.fileName, err)
		}
		return s.store.Add(pod)
	case podDelete:
		if objKey, keyExist := s.fileKeyMapping[e.fileName]; keyExist {
			pod, podExist, err := s.store.GetByKey(objKey)
			if err != nil {
				return err
			} else if !podExist {
				return fmt.Errorf("the pod with key %s doesn't exist in cache", objKey)
			} else {
				if err = s.store.Delete(pod); err != nil {
					return fmt.Errorf("failed to remove deleted pod from cache: %v", err)
				}
				delete(s.fileKeyMapping, e.fileName)
			}
		}
	}
	return nil
}
```

#### startWatch

```go
// startWatch函数启动监视文件变化的过程。
func (s *sourceFile) startWatch() {
    backOff := flowcontrol.NewBackOff(retryPeriod, maxRetryPeriod)
    backOffID := "watch"
    go wait.Forever(func() {
        // 检查是否处于退避状态
        if backOff.IsInBackOffSinceUpdate(backOffID, time.Now()) {
            return
        }

        // 进行文件监视操作
        if err := s.doWatch(); err != nil {
            klog.ErrorS(err, "Unable to read config path", "path", s.path)
            if _, retryable := err.(*retryableError); !retryable {
                // 如果错误不可重试，则进入退避状态
                backOff.Next(backOffID, time.Now())
            }
        }
    }, retryPeriod)
}
```

##### doWatch

```go
// doWatch函数执行文件监视操作。
func (s *sourceFile) doWatch() error {
	// 检查路径是否存在
	_, err := os.Stat(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// 发送一个空的PodList更新，用于标记FileSource已被处理
		s.updates <- kubetypes.PodUpdate{Pods: []*v1.Pod{}, Op: kubetypes.SET, Source: kubetypes.FileSource}
		return &retryableError{"path does not exist, ignoring"}
	}

	// 创建文件监视器
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("unable to create inotify: %v", err)
	}
	defer w.Close()

	// 添加路径到监视器中
	err = w.Add(s.path)
	if err != nil {
		return fmt.Errorf("unable to create inotify for path %q: %v", s.path, err)
	}

	for {
		select {
		case event := <-w.Events:
			// 处理文件监视事件
			if err = s.produceWatchEvent(&event); err != nil {
				return fmt.Errorf("error while processing inotify event (%+v): %v", event, err)
			}
		case err = <-w.Errors:
			return fmt.Errorf("error while watching %q: %v", s.path, err)
		}
	}
}
```

###### produceWatchEvent

```go
// produceWatchEvent函数处理文件监视事件。
func (s *sourceFile) produceWatchEvent(e *fsnotify.Event) error {
	// 忽略以点号开头的文件
	if strings.HasPrefix(filepath.Base(e.Name), ".") {
		klog.V(4).InfoS("Ignored pod manifest, because it starts with dots", "eventName", e.Name)
		return nil
	}
	var eventType podEventType
	switch {
	case (e.Op & fsnotify.Create) > 0:
		eventType = podAdd
	case (e.Op & fsnotify.Write) > 0:
		eventType = podModify
	case (e.Op & fsnotify.Chmod) > 0:
		eventType = podModify
	case (e.Op & fsnotify.Remove) > 0:
		eventType = podDelete
	case (e.Op & fsnotify.Rename) > 0:
		eventType = podDelete
	default:
		// 忽略其他事件
		return nil
	}

	s.watchEvents <- &watchEvent{e.Name, eventType}
	return nil
}
```

### http

```go
// sourceURL结构体用于表示从URL读取Pod配置并监视其变化的信息。
type sourceURL struct {
	url         string             // 要读取Pod配置的URL
	header      http.Header        // HTTP请求的头部信息
	nodeName    types.NodeName     // 节点名称
	updates     chan<- interface{} // 更新通道，用于发送Pod更新事件
	data        []byte             // 存储从URL读取的数据
	failureLogs int                // 失败日志计数器，记录读取URL失败的次数
	client      *http.Client       // HTTP客户端，用于发送请求
}

// NewSourceURL函数用于创建sourceURL实例，指定要从中读取Pod配置的URL，并对其进行监视。
func NewSourceURL(url string, header http.Header, nodeName types.NodeName, period time.Duration, updates chan<- interface{}) {
	config := &sourceURL{
		url:      url,
		header:   header,
		nodeName: nodeName,
		updates:  updates,
		data:     nil,
		// 请求超时会导致重试。此客户端仅用于读取传递给kubelet的清单URL。
		client: &http.Client{Timeout: 10 * time.Second},
	}
	klog.V(1).InfoS("Watching URL", "URL", url)
	go wait.Until(config.run, period, wait.NeverStop)
}

// run方法是sourceURL结构体的方法，用于执行URL监视逻辑。
func (s *sourceURL) run() {
	if err := s.extractFromURL(); err != nil {
		// 每分钟只记录一次失败日志。前几次记录足以表明问题。
		if s.failureLogs < 3 {
			klog.InfoS("Failed to read pods from URL", "err", err)
		} else if s.failureLogs == 3 {
			klog.InfoS("Failed to read pods from URL. Dropping verbosity of this message to V(4)", "err", err)
		} else {
			klog.V(4).InfoS("Failed to read pods from URL", "err", err)
		}
		s.failureLogs++
	} else {
		if s.failureLogs > 0 {
			klog.InfoS("Successfully read pods from URL")
			s.failureLogs = 0
		}
	}
}
```

#### extractFromURL

```go
// extractFromURL方法用于从URL中提取Pod配置。
func (s *sourceURL) extractFromURL() error {
	req, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
	}
	req.Header = s.header
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := utilio.ReadAtMost(resp.Body, maxConfigLength)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%v: %v", s.url, resp.Status)
	}
	if len(data) == 0 {
		// 发送一个包含空PodList的更新，以便将HTTPSource标记为已处理
		s.updates <- kubetypes.PodUpdate{Pods: []*v1.Pod{}, Op: kubetypes.SET, Source: kubetypes.HTTPSource}
		return fmt.Errorf("zero-length data received from %v", s.url)
	}
	// 如果数据与上次读取的数据相同，则提前返回
	if bytes.Equal(data, s.data) {
		return nil
	}
	s.data = data
	// 首先尝试解析为单个Pod
	parsed, pod, singlePodErr := tryDecodeSinglePod(data, s.applyDefaults)
	if parsed {
		if singlePodErr != nil {
			// 解析成功但无法使用
			return singlePodErr
		}
		s.updates <- kubetypes.PodUpdate{Pods: []*v1.Pod{pod}, Op: kubetypes.SET, Source: kubetypes.HTTPSource}
		return nil
	}

	// 如果解析为单个Pod失败，则尝试解析为Pod列表
	parsed, podList, multiPodErr := tryDecodePodList(data, s.applyDefaults)
	if parsed {
		if multiPodErr != nil {
			// 解析成功但无法使用
			return multiPodErr
		}
		pods := make([]*v1.Pod, 0, len(podList.Items))
		for i := range podList.Items {
			pods = append(pods, &podList.Items[i])
		}
		s.updates <- kubetypes.PodUpdate{Pods: pods, Op: kubetypes.SET, Source: kubetypes.HTTPSource}
		return nil
	}

	return fmt.Errorf("%v: received '%v', but couldn't parse as "+
		"single (%v) or multiple pods (%v)",
		s.url, string(data), singlePodErr, multiPodErr)
}
```

##### applyDefaults

```go
// applyDefaults方法用于应用默认值到Pod上。
func (s *sourceURL) applyDefaults(pod *api.Pod) error {
	return applyDefaults(pod, s.url, false, s.nodeName)
}
```

###### applyDefaults

```go
// applyDefaults函数用于将默认值应用到Pod上。
func applyDefaults(pod *api.Pod, source string, isFile bool, nodeName types.NodeName) error {
	if len(pod.UID) == 0 {
		hasher := md5.New()
		hash.DeepHashObject(hasher, pod)
		// DeepHashObject在此之后重置了哈希，所以我们应该在此之后写入Pod的源信息。
		if isFile {
			fmt.Fprintf(hasher, "host:%s", nodeName)
			fmt.Fprintf(hasher, "file:%s", source)
		} else {
			fmt.Fprintf(hasher, "url:%s", source)
		}
		pod.UID = types.UID(hex.EncodeToString(hasher.Sum(nil)[0:]))
		klog.V(5).InfoS("生成的UID", "pod", klog.KObj(pod), "podUID", pod.UID, "source", source)
	}

	pod.Name = generatePodName(pod.Name, nodeName)
	klog.V(5).InfoS("生成的Pod名称", "pod", klog.KObj(pod), "podUID", pod.UID, "source", source)

	if pod.Namespace == "" {
		pod.Namespace = metav1.NamespaceDefault
	}
	klog.V(5).InfoS("为Pod设置命名空间", "pod", klog.KObj(pod), "source", source)

	// 设置Host字段以指示此Pod被调度到当前节点上。
	pod.Spec.NodeName = string(nodeName)

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	// 生成的UID是文件的哈希。
	pod.Annotations[kubetypes.ConfigHashAnnotationKey] = string(pod.UID)

	if isFile {
		// 对于静态Pod应用默认的Taint tolerations，以便在节点出现问题时它们不会被驱逐。
		helper.AddOrUpdateTolerationInPod(pod, &api.Toleration{
			Operator: "Exists",
			Effect:   api.TaintEffectNoExecute,
		})
	}

	// 将默认状态设置为Pending。
	pod.Status.Phase = api.PodPending
	return nil
}

// generatePodName函数通过在名称末尾添加nodeName生成一个在节点中唯一的Pod名称。
func generatePodName(name string, nodeName types.NodeName) string {
	return fmt.Sprintf("%s-%s", name, strings.ToLower(string(nodeName)))
}
```

## pleg

### 简介

PLEG（Pod Lifecycle Event Generator）是 Kubernetes 中的一个关键组件，它负责监视和处理 Pod 的生命周期事件。PLEG 运行在每个节点上，并与 kubelet 组件紧密配合工作。

PLEG 的主要功能包括：

1. 监控容器状态：PLEG 监控每个节点上正在运行的容器的状态，并根据其状态变化生成相应的事件。
2. 生成事件：当容器的状态发生变化时，PLEG 会生成相应的事件，例如容器的创建、启动、停止、退出等事件。
3. 同步状态：PLEG 通过与 kubelet 进行交互，将容器的状态信息同步给 kubelet，使 kubelet 能够了解容器的当前状态。
4. 故障处理：PLEG 检测容器的状态变化，并在发现容器失败或异常时生成相应的事件，以便 kubelet 采取适当的故障处理措施。

PLEG 的设计目标是提供高效可靠的容器生命周期事件处理。它使用操作系统的文件系统事件和容器运行时的状态查询机制来监视容器的状态变化，从而及时地生成相应的事件。这些事件对于监控、日志记录、故障排除和自动恢复等方面非常重要。

```GO
// PodLifecycleEventGenerator 包含用于生成 Pod 生命周期事件的函数。
type PodLifecycleEventGenerator interface {
	Start()
	Stop()
	Update(relistDuration *RelistDuration)
	Watch() chan *PodLifecycleEvent
	Healthy() (bool, error)
	Relist()
	UpdateCache(*kubecontainer.Pod, types.UID) (error, bool)
}

// PodLifeCycleEventType 定义了 Pod 生命周期事件的类型。
type PodLifeCycleEventType string

type RelistDuration struct {
	// 重新列举的时间周期。
	RelistPeriod time.Duration
	// 重新列举的阈值需要大于重新列举的时间周期加上重新列举时间，这个时间可能有很大的变化。
	// 设置一个保守的阈值，以避免在健康和不健康之间频繁切换。
	RelistThreshold time.Duration
}

const (
	// ContainerStarted - 容器新状态为运行时的事件类型。
	ContainerStarted PodLifeCycleEventType = "ContainerStarted"
	// ContainerDied - 容器新状态为退出时的事件类型。
	ContainerDied PodLifeCycleEventType = "ContainerDied"
	// ContainerRemoved - 容器旧状态为退出时的事件类型。
	ContainerRemoved PodLifeCycleEventType = "ContainerRemoved"
	// PodSync 用于在观察到的 pod 状态变化无法通过上述任何单个事件捕获时触发同步。
	PodSync PodLifeCycleEventType = "PodSync"
	// ContainerChanged - 容器新状态为未知时的事件类型。
	ContainerChanged PodLifeCycleEventType = "ContainerChanged"
)

// PodLifecycleEvent 是反映 Pod 状态变化的事件。
type PodLifecycleEvent struct {
	// Pod 的 ID。
	ID types.UID
	// 事件的类型。
	Type PodLifeCycleEventType
	// 伴随的数据，根据事件类型不同而变化。
	// - ContainerStarted/ContainerStopped: 容器名称 (string)。
	// - 其他事件类型：未使用。
	Data interface{}
}
```

### GenericPLEG

```GO
// GenericPLEG 是一个非常简单的通用 PLEG，仅依靠周期性的列表来发现容器变化。
// 它应该作为临时替代品使用，当容器运行时尚未支持适当的事件生成器时。
//
// 注意，GenericPLEG 假设在一个 relist 周期内不会创建、终止和回收容器。
// 如果发生这样的事件，GenericPLEG 将会错过所有与该容器相关的事件。
// 在重新列举失败的情况下，这个窗口可能会变得更长。
// 注意，这个假设并不是唯一的 -- 许多 kubelet 内部组件依赖于终止的容器作为清理工作的标记。
// 垃圾回收器是为了处理这种情况而实现的。
// 然而，为了保证 kubelet 能够处理缺失的容器事件，建议将 relist 周期设置短一些，并在 kubelet 中使用辅助的、更长周期的同步作为安全措施。
type GenericPLEG struct {
	// 容器运行时。
	runtime kubecontainer.Runtime
	// 订阅者监听事件的通道。
	eventChannel chan *PodLifecycleEvent
	// 用于存储 Pod/容器信息的内部缓存。
	podRecords podRecords
	// 最后一次重新列举的时间。
	relistTime atomic.Value
	// 用于存储需要同步的运行时状态的缓存。
	cache kubecontainer.Cache
	// 用于测试的时钟。
	clock clock.Clock
	// 重新检查的 Pods，它们在重新列举期间无法检索到其状态。
	// 这些 Pods 将在下一次重新列举时重试。
	podsToReinspect map[types.UID]*kubecontainer.Pod
	// 停止 Generic PLEG 的通道。
	stopCh chan struct{}
	// 用于锁定 Generic PLEG 的重新列举。
	relistLock sync.Mutex
	// 表示 Generic PLEG 是否正在运行。
	isRunning bool
	// 用于锁定 Generic PLEG 的启动/停止操作。
	runningMu sync.Mutex
	// 指示重新列举的相关参数。
	relistDuration *RelistDuration
	// 用于序列化 relist 与 UpdateCache 接口之间的调用的互斥锁。
	podCacheMutex sync.Mutex
}

type podRecords map[types.UID]*podRecord

// NewGenericPLEG 实例化一个新的 GenericPLEG 对象并返回。
func NewGenericPLEG(runtime kubecontainer.Runtime, eventChannel chan *PodLifecycleEvent,
	relistDuration *RelistDuration, cache kubecontainer.Cache,
	clock clock.Clock) PodLifecycleEventGenerator {
	return &GenericPLEG{
		relistDuration: relistDuration,
		runtime:        runtime,
		eventChannel:   eventChannel,
		podRecords:     make(podRecords),
		cache:          cache,
		clock:          clock,
	}
}
```

#### Start

```go
// Start方法启动一个goroutine来定期进行relist。
func (g *GenericPLEG) Start() {
	g.runningMu.Lock()
	defer g.runningMu.Unlock()
	if !g.isRunning {
		g.isRunning = true
		g.stopCh = make(chan struct{})
		go wait.Until(g.Relist, g.relistDuration.RelistPeriod, g.stopCh)
	}
}
```

#### Relist

```GO
// Relist方法查询容器运行时的Pod/容器列表，与内部的Pod/容器列表进行比较，并相应地生成事件。
func (g *GenericPLEG) Relist() {
	g.relistLock.Lock()
	defer g.relistLock.Unlock()

	ctx := context.Background()
	klog.V(5).InfoS("GenericPLEG: Relisting")

	if lastRelistTime := g.getRelistTime(); !lastRelistTime.IsZero() {
		metrics.PLEGRelistInterval.Observe(metrics.SinceInSeconds(lastRelistTime))
	}

	timestamp := g.clock.Now()
	defer func() {
		metrics.PLEGRelistDuration.Observe(metrics.SinceInSeconds(timestamp))
	}()

	// 获取所有的Pod。
	podList, err := g.runtime.GetPods(ctx, true)
	if err != nil {
		klog.ErrorS(err, "GenericPLEG: 无法获取Pod列表")
		return
	}

	g.updateRelistTime(timestamp)

	pods := kubecontainer.Pods(podList)
	// 更新正在运行的Pod和容器计数
	updateRunningPodAndContainerMetrics(pods)
	g.podRecords.setCurrent(pods)

	// 比较旧的和当前的Pod，并生成事件。
	eventsByPodID := map[types.UID][]*PodLifecycleEvent{}
	for pid := range g.podRecords {
		oldPod := g.podRecords.getOld(pid)
		pod := g.podRecords.getCurrent(pid)
		// 获取旧Pod和新Pod中的所有容器。
		allContainers := getContainersFromPods(oldPod, pod)
		for _, container := range allContainers {
			events := computeEvents(oldPod, pod, &container.ID)
			for _, e := range events {
				updateEvents(eventsByPodID, e)
			}
		}
	}

	var needsReinspection map[types.UID]*kubecontainer.Pod
	if g.cacheEnabled() {
		needsReinspection = make(map[types.UID]*kubecontainer.Pod)
	}

	// 如果有与Pod相关的事件，我们应该更新podCache。
	for pid, events := range eventsByPodID {
		pod := g.podRecords.getCurrent(pid)
		if g.cacheEnabled() {
			// updateCache()将检查Pod并更新缓存。如果在检查过程中出现错误，我们希望PLEG在下一次relist时重试。
			// 为了实现这一点，我们不更新与Pod相关联的podRecord，这样在下一次relist中将再次检测到更改。
			// TODO: 如果在同一relist周期内发生了许多Pod更改，串行地检查Pod并获取PodStatus以更新缓存可能需要一段时间。我们应该注意这一点，如果需要的话可以并行化。
			if err, updated := g.updateCache(ctx, pod, pid); err != nil {
				// 依赖于updateCache调用GetPodStatus来记录实际错误。
				klog.V(4).ErrorS(err, "PLEG: 忽略Pod的事件", "pod", klog.KRef(pod.Namespace, pod.Name))

				// 确保在下一次relist时尝试重新检查Pod
				needsReinspection[pid] = pod

				continue
			} else {
				// 此Pod在需要重新检查的列表中，并且我们已经检查过它，因为它有事件，因此将其删除
				// 列表中的项（我们不希望下面的重新检查代码在此relist执行中再次检查它）。
				delete(g.podsToReinspect, pid)
				if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
					if !updated {
						continue
					}
				}
			}
		}
		// 更新内部存储并发送事件。
		g.podRecords.update(pid)

		// 从容器ID到退出码的映射；用作查找的临时缓存
		containerExitCode := make(map[string]int)

		for i := range events {
			// 过滤掉不可靠且尚未被其他组件使用的事件。
			if events[i].Type == ContainerChanged {
				continue
			}
			select {
			case g.eventChannel <- events[i]:
			default:
				metrics.PLEGDiscardEvents.Inc()
				klog.ErrorS(nil, "事件通道已满，丢弃此relist()周期事件")
			}
			// 在容器完成特定事件时记录容器的退出码
			if events[i].Type == ContainerDied {
				// 当首次出现ContainerDied事件时，填充containerExitCode映射
				if len(containerExitCode) == 0 && pod != nil && g.cache != nil {
					// 获取更新后的PodStatus
					status, err := g.cache.Get(pod.ID)
					if err == nil {
						for _, containerStatus := range status.ContainerStatuses {
							containerExitCode[containerStatus.ID.ID] = containerStatus.ExitCode
						}
					}
				}
				if containerID, ok := events[i].Data.(string); ok {
					if exitCode, ok := containerExitCode[containerID]; ok && pod != nil {
						klog.V(2).InfoS("Generic (PLEG): 容器已完成", "podID", pod.ID, "containerID", containerID, "exitCode", exitCode)
					}
				}
			}
		}
	}

	if g.cacheEnabled() {
		// 重新检查在上一次relist期间未通过检查的任何Pod
		if len(g.podsToReinspect) > 0 {
			klog.V(5).InfoS("GenericPLEG: 重新检查先前未通过检查的Pod")
			for pid, pod := range g.podsToReinspect {
				if err, _ := g.updateCache(ctx, pod, pid); err != nil {
					// 依赖于updateCache调用GetPodStatus来记录实际错误。
					klog.V(5).ErrorS(err, "PLEG: Pod重新检查失败", "pod", klog.KRef(pod.Namespace, pod.Name))
					needsReinspection[pid] = pod
				}
			}
		}

		// 更新缓存时间戳。这需要在所有Pod都已在缓存中正确更新之后发生。
		g.cache.UpdateTime(timestamp)
	}

	// 确保我们保留需要在下一次relist时重新检查的Pod列表
	g.podsToReinspect = needsReinspection
}
```

##### cacheEnabled

```go
func (g *GenericPLEG) cacheEnabled() bool {
	return g.cache != nil
}
```

##### getOld

```go
func (pr podRecords) getOld(id types.UID) *kubecontainer.Pod {
	r, ok := pr[id]
	if !ok {
		return nil
	}
	return r.old
}
```

##### getCurrent

```go
func (pr podRecords) getCurrent(id types.UID) *kubecontainer.Pod {
	r, ok := pr[id]
	if !ok {
		return nil
	}
	return r.current
}
```

##### getContainersFromPods

```go
func getContainersFromPods(pods ...*kubecontainer.Pod) []*kubecontainer.Container {
	cidSet := sets.NewString()
	var containers []*kubecontainer.Container
	fillCidSet := func(cs []*kubecontainer.Container) {
		for _, c := range cs {
			cid := c.ID.ID
			if cidSet.Has(cid) {
				continue
			}
			cidSet.Insert(cid)
			containers = append(containers, c)
		}
	}

	for _, p := range pods {
		if p == nil {
			continue
		}
		fillCidSet(p.Containers)
		// 将Sandbox作为容器更新
		// TODO: 显式跟踪Sandbox。
		fillCidSet(p.Sandboxes)
	}
	return containers
}
```

##### computeEvents

```go
func computeEvents(oldPod, newPod *kubecontainer.Pod, cid *kubecontainer.ContainerID) []*PodLifecycleEvent {
	var pid types.UID
	if oldPod != nil {
		pid = oldPod.ID
	} else if newPod != nil {
		pid = newPod.ID
	}
	oldState := getContainerState(oldPod, cid)
	newState := getContainerState(newPod, cid)
	return generateEvents(pid, cid.ID, oldState, newState)
}
```

##### updateEvents

```go
func updateEvents(eventsByPodID map[types.UID][]*PodLifecycleEvent, e *PodLifecycleEvent) {
	if e == nil {
		return
	}
	eventsByPodID[e.ID] = append(eventsByPodID[e.ID], e)
}
```

##### cacheEnabled

```go
func (g *GenericPLEG) cacheEnabled() bool {
	return g.cache != nil
}
```

#### UpdateCache

```go
func (g *GenericPLEG) UpdateCache(pod *kubecontainer.Pod, pid types.UID) (error, bool) {
	ctx := context.Background()
	if !g.cacheEnabled() {
		return fmt.Errorf("pod cache disabled"), false
	}
	if pod == nil {
		return fmt.Errorf("pod cannot be nil"), false
	}
	return g.updateCache(ctx, pod, pid)
}
```

##### updateCache

```go
// updateCache尝试在kubelet缓存中更新pod状态，并返回一个布尔值，表示是否实际上在缓存中更新了pod状态。
// 如果缓存忽略了pod状态，则返回false。
func (g *GenericPLEG) updateCache(ctx context.Context, pod *kubecontainer.Pod, pid types.UID) (error, bool) {
	if pod == nil {
		// 当前的重列中缺少该pod。这意味着该pod没有可见的（活动或非活动的）容器。
		klog.V(4).InfoS("PLEG: Delete status for pod", "podUID", string(pid))
		g.cache.Delete(pid)
		return nil, true
	}

	g.podCacheMutex.Lock()
	defer g.podCacheMutex.Unlock()
	timestamp := g.clock.Now()

	status, err := g.runtime.GetPodStatus(ctx, pod.ID, pod.Name, pod.Namespace)
	if err != nil {
		// nolint:logcheck // 在if分支内部不使用klog.V的结果是可以的，我们只是使用它来确定是否应该添加额外的"podStatus"键及其值。
		if klog.V(6).Enabled() {
			klog.ErrorS(err, "PLEG: Write status", "pod", klog.KRef(pod.Namespace, pod.Name), "podStatus", status)
		} else {
			klog.ErrorS(err, "PLEG: Write status", "pod", klog.KRef(pod.Namespace, pod.Name))
		}
	} else {
		if klogV := klog.V(6); klogV.Enabled() {
			klogV.InfoS("PLEG: Write status", "pod", klog.KRef(pod.Namespace, pod.Name), "podStatus", status)
		} else {
			klog.V(4).InfoS("PLEG: Write status", "pod", klog.KRef(pod.Namespace, pod.Name))
		}
		// 如果新的IP为空，则在缓存更新时保留pod IP。
		// 当一个pod被关闭时，kubelet可能与PLEG竞争，在网络拆除后检索到一个pod状态，但是kubernetes API期望在pod死亡后可以访问已完成的pod的IP。
		status.IPs = g.getPodIPs(pid, status)
	}

	// 当只使用通用PLEG时，PodStatus将被保存在缓存中，而不对现有状态进行任何验证。
	// 当只有通用PLEG设置缓存中的PodStatus时，这个方法运行良好。然而，如果我们有多个实体，例如Evented PLEG，在尝试将PodStatus设置到缓存中时，
	// 我们可能会遇到每个实体都在其各自的执行流中计算时间戳的竞争条件。当通用PLEG计算这个时间戳并获取PodStatus时，我们只能在Evented PLEG中收到事件后计算相应的时间戳。
	// 更多详情请参考：
	// https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/3386-kubelet-evented-pleg#timestamp-of-the-pod-status
	if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) && isEventedPLEGInUse() {
		timestamp = status.TimeStamp
	}

	return err, g.cache.Set(pod.ID, status, err, timestamp)
}
```

###### getPodIPs

```go
// getPodIP在新状态没有pod IP且其sandbox已退出时，保留旧缓存状态的pod IP。
func (g *GenericPLEG) getPodIPs(pid types.UID, status *kubecontainer.PodStatus) []string {
	if len(status.IPs) != 0 {
		return status.IPs
	}

	oldStatus, err := g.cache.Get(pid)
	if err != nil || len(oldStatus.IPs) == 0 {
		return nil
	}

	for _, sandboxStatus := range status.SandboxStatuses {
		// 如果至少有一个sandbox准备好了，那么使用此状态更新的pod IP
		if sandboxStatus.State == runtimeapi.PodSandboxState_SANDBOX_READY {
			return status.IPs
		}
	}

	// 对于没有准备好的容器或sandbox的pod（如已退出的pod），使用旧状态的pod IP
	return oldStatus.IPs
}
```

###### isEventedPLEGInUse

```go
// isEventedPLEGInUse指示是否正在使用Evented PLEG。即使启用了Evented PLEG功能门，也可能有几个原因导致它未被使用。
// 例如，来自运行时的流式数据问题，或者运行时没有实现容器事件流。
func isEventedPLEGInUse() bool {
	eventedPLEGUsageMu.RLock()
	defer eventedPLEGUsageMu.RUnlock()
	return eventedPLEGUsage
}
```

#### Stop

```go
func (g *GenericPLEG) Stop() {
	g.runningMu.Lock()
	defer g.runningMu.Unlock()
	if g.isRunning {
		close(g.stopCh)
		g.isRunning = false
	}
}
```

#### Update

```go
func (g *GenericPLEG) Update(relistDuration *RelistDuration) {
	g.relistDuration = relistDuration
}
```

#### Watch

```go
// Watch返回一个通道，订阅者可以从中接收PodLifecycleEvent事件。
// TODO: 支持多个订阅者。
func (g *GenericPLEG) Watch() chan *PodLifecycleEvent {
	return g.eventChannel
}
```

#### Healthy

```go
// Healthy检查PLEG是否正常工作。
func (e *EventedPLEG) Healthy() (bool, error) {
	// 当重列时间超过重列阈值时，将GenericPLEG声明为不健康。如果打开了EventedPLEG，
	// relistingPeriod和relistingThreshold将调整为较高的值。因此，Generic PLEG的健康检查应该检查relistingPeriod和relistingThreshold的调整值。

	// 只有当eventChannel的容量已满时，才将EventedPLEG声明为不健康。
	if len(e.eventChannel) == cap(e.eventChannel) {
		return false, fmt.Errorf("EventedPLEG: pleg event channel capacity is full with %v events", len(e.eventChannel))
	}

	timestamp := e.clock.Now()
	metrics.PLEGLastSeen.Set(float64(timestamp.Unix()))
	return true, nil
}
```

### EventedPLEG

```go
// EventedPLEG 是一个结构体，用于处理容器的生命周期事件。
type EventedPLEG struct {
	// 容器运行时。
	runtime kubecontainer.Runtime
	// 运行时服务。
	runtimeService internalapi.RuntimeService
	// 从该通道接收订阅者监听的事件。
	eventChannel chan *PodLifecycleEvent
	// 用于存储同步 Pod 所需的运行时状态的缓存。
	cache kubecontainer.Cache
	// 用于测试的时钟。
	clock clock.Clock
	// GenericPLEG 用于在需要时强制重新列举。
	genericPleg PodLifecycleEventGenerator
	// 从运行时获取容器事件的最大重试次数。
	eventedPlegMaxStreamRetries int
	// 表示重新列举相关参数。
	relistDuration *RelistDuration
	// 关闭通道以停止 Evented PLEG。
	stopCh chan struct{}
	// 停止缓存全局时间戳的定期更新。
	stopCacheUpdateCh chan struct{}
	// 锁定 Evented PLEG 的启动/停止操作。
	runningMu sync.Mutex
}

// NewEventedPLEG 实例化一个新的 EventedPLEG 对象并返回。
func NewEventedPLEG(runtime kubecontainer.Runtime, runtimeService internalapi.RuntimeService, eventChannel chan *PodLifecycleEvent,
	cache kubecontainer.Cache, genericPleg PodLifecycleEventGenerator, eventedPlegMaxStreamRetries int,
	relistDuration *RelistDuration, clock clock.Clock) PodLifecycleEventGenerator {
	return &EventedPLEG{
		runtime:                     runtime,
		runtimeService:              runtimeService,
		eventChannel:                eventChannel,
		cache:                       cache,
		genericPleg:                 genericPleg,
		eventedPlegMaxStreamRetries: eventedPlegMaxStreamRetries,
		relistDuration:              relistDuration,
		clock:                       clock,
	}
}
```

#### Start

```go
// Start 启动 Evented PLEG
func (e *EventedPLEG) Start() {
    e.runningMu.Lock()
    defer e.runningMu.Unlock()
    if isEventedPLEGInUse() {
    	return
    }
    setEventedPLEGUsage(true)
    e.stopCh = make(chan struct{})
    e.stopCacheUpdateCh = make(chan struct{})
    go wait.Until(e.watchEventsChannel, 0, e.stopCh)
    go wait.Until(e.updateGlobalCache, globalCacheUpdatePeriod, e.stopCacheUpdateCh)
}
```

##### isEventedPLEGInUse

```go
// isEventedPLEGInUse 指示是否正在使用 Evented PLEG。即使在启用 Evented PLEG 功能标志后，可能仍然有多种原因导致其未被使用。
// 例如，来自运行时的流数据问题或运行时未实现容器事件流。
func isEventedPLEGInUse() bool {
	eventedPLEGUsageMu.RLock()
	defer eventedPLEGUsageMu.RUnlock()
	return eventedPLEGUsage
}
```

##### setEventedPLEGUsage

```go
// setEventedPLEGUsage 只能从 Evented PLEG 的启动/停止中访问。
func setEventedPLEGUsage(enable bool) {
	eventedPLEGUsageMu.Lock()
	defer eventedPLEGUsageMu.Unlock()
	eventedPLEGUsage = enable
}
```

##### watchEventsChannel

```go
func (e *EventedPLEG) watchEventsChannel() {
	containerEventsResponseCh := make(chan *runtimeapi.ContainerEventResponse, cap(e.eventChannel))
	defer close(containerEventsResponseCh)

	// 从运行时获取容器事件。
	go func() {
		numAttempts := 0
		for {
			if numAttempts >= e.eventedPlegMaxStreamRetries {
				if isEventedPLEGInUse() {
					// 由于 Evented PLEG 不起作用，回退到 Generic PLEG 重新列举。
					klog.V(4).InfoS("回退到 Generic PLEG 重新列举，因为 Evented PLEG 不起作用")
					e.Stop()
					e.genericPleg.Stop()       // 停止正在使用 Evented PLEG 时以较长的重新列举周期运行的现有 Generic PLEG。
					e.Update(e.relistDuration) // 将重新列举周期更新为 Generic PLEG 的默认值。
					e.genericPleg.Start()
					break
				}
			}

			err := e.runtimeService.GetContainerEvents(containerEventsResponseCh)
			if err != nil {
				metrics.EventedPLEGConnErr.Inc()
				numAttempts++
				e.Relist() // 强制重新列举以获取最新的容器和正在运行的 Pod 指标。
				klog.V(4).InfoS("Evented PLEG: 获取容器事件失败，正在重试: ", "err", err)
			}
		}
	}()

	if isEventedPLEGInUse() {
		e.processCRIEvents(containerEventsResponseCh)
	}
}
```

###### isEventedPLEGInUse

```go
func isEventedPLEGInUse() bool {
    eventedPLEGUsageMu.RLock() // 获取 Evented PLEG 使用情况的读锁
    defer eventedPLEGUsageMu.RUnlock() // 解锁
    return eventedPLEGUsage // 返回 Evented PLEG 使用情况
}
```

###### processCRIEvents

```go
func (e *EventedPLEG) processCRIEvents(containerEventsResponseCh chan *runtimeapi.ContainerEventResponse) {
	for event := range containerEventsResponseCh {
		// 如果 PodSandboxStatus 为 nil，则忽略事件。
		// 这可能发生在某些竞争条件下，其中 podSandbox 已被删除，
		// 因此容器运行时在生成事件时无法找到容器的 podSandbox。
		// 忽略是安全的，因为：
		// a) 已经接收到了删除沙盒的事件，
		// b) 在最坏的情况下，重新列举将最终同步 pod 的状态。
		// TODO：(#114371) 找出一种处理这种情况的方法，而不是忽略。
		if event.PodSandboxStatus == nil || event.PodSandboxStatus.Metadata == nil {
			klog.ErrorS(nil, "Evented PLEG: 收到具有空 PodSandboxStatus 或 PodSandboxStatus.Metadata 的 ContainerEventResponse", "containerEventResponse", event)
			continue
		}

		podID := types.UID(event.PodSandboxStatus.Metadata.Uid)
		shouldSendPLEGEvent := false

		status, err := e.runtime.GeneratePodStatus(event)
		if err != nil {
			// nolint:logcheck // if 分支内没有使用 klog.V 的结果是可以的，我们只是用它来确定是否应该添加额外的 "podStatus" 键及其值。
			if klog.V(6).Enabled() {
				klog.ErrorS(err, "Evented PLEG: 从收到的事件生成 Pod 状态时出错", "podUID", podID, "podStatus", status)
			} else {
				klog.ErrorS(err, "Evented PLEG: 从收到的事件生成 Pod 状态时出错", "podUID", podID, "podStatus", status)
			}
		} else {
			if klogV := klog.V(6); klogV.Enabled() {
				klogV.InfoS("Evented PLEG: 从收到的事件生成 Pod 状态", "podUID", podID, "podStatus", status)
			} else {
				klog.V(4).InfoS("Evented PLEG: 从收到的事件生成 Pod 状态", "podUID", podID)
			}
			// 如果新 IP 为空，则在缓存更新时保留 Pod 的 IP。
			// 当一个 Pod 被拆除时，kubelet 可能会与 PLEG 竞争，并在网络拆除后检索到一个 Pod 状态，
			// 但是 kubernetes API 希望在 Pod 死亡后仍然可以使用完成的 Pod 的 IP。
			status.IPs = e.getPodIPs(podID, status)
		}

		e.updateRunningPodMetric(status)
		e.updateRunningContainerMetric(status)
		e.updateLatencyMetric(event)

		if event.ContainerEventType == runtimeapi.ContainerEventType_CONTAINER_DELETED_EVENT {
			for _, sandbox := range status.SandboxStatuses {
				if sandbox.Id == event.ContainerId {
					// 当 kubelet 收到 CONTAINER_DELETED_EVENT 时，
					// 容器运行时指示该容器已被运行时移除，
					// 因此必须从 kubelet 的缓存中删除该容器。
					e.cache.Delete(podID)
				}
			}
			shouldSendPLEGEvent = true
		} else {
			if e.cache.Set(podID, status, err, time.Unix(event.GetCreatedAt(), 0)) {
				shouldSendPLEGEvent = true
			}
		}

		if shouldSendPLEGEvent {
			e.processCRIEvent(event)
		}
	}
}
```

###### updateRunningPodMetric

```go
func (e *EventedPLEG) updateRunningPodMetric(podStatus *kubecontainer.PodStatus) {
	cachedPodStatus, err := e.cache.Get(podStatus.ID)
	if err != nil {
		klog.ErrorS(err, "Evented PLEG: 获取缓存", "podID", podStatus.ID)
	}
	// 缓存未命中的条件：如果在缓存中未找到 Pod 状态对象，则状态对象将为空。
	if len(cachedPodStatus.SandboxStatuses) < 1 {
		sandboxState := getPodSandboxState(podStatus)
		if sandboxState == kubecontainer.ContainerStateRunning {
			metrics.RunningPodCount.Inc()
		}
	} else {
		oldSandboxState := getPodSandboxState(cachedPodStatus)
		currentSandboxState := getPodSandboxState(podStatus)

		if oldSandboxState == kubecontainer.ContainerStateRunning && currentSandboxState != kubecontainer.ContainerStateRunning {
			metrics.RunningPodCount.Dec()
		} else if oldSandboxState != kubecontainer.ContainerStateRunning && currentSandboxState == kubecontainer.ContainerStateRunning {
			metrics.RunningPodCount.Inc()
		}
	}
}
```

###### updateRunningContainerMetric

```go
func (e *EventedPLEG) updateRunningContainerMetric(podStatus *kubecontainer.PodStatus) {
	cachedPodStatus, err := e.cache.Get(podStatus.ID)
	if err != nil {
		klog.ErrorS(err, "Evented PLEG: 获取缓存", "podID", podStatus.ID)
	}

	// 缓存未命中的条件：如果在缓存中未找到 Pod 状态对象，则状态对象将为空。
	if len(cachedPodStatus.SandboxStatuses) < 1 {
		containerStateCount := getContainerStateCount(podStatus)
		for state, count := range containerStateCount {
			// 添加当前获取的计数
			metrics.RunningContainerCount.WithLabelValues(string(state)).Add(float64(count))
		}
	} else {
		oldContainerStateCount := getContainerStateCount(cachedPodStatus)
		currentContainerStateCount := getContainerStateCount(podStatus)

		// 旧和新的容器状态集合可能不同；
		// 获取一个将两者组合在一起的唯一容器状态集合
		containerStates := make(map[kubecontainer.State]bool)
		for state := range oldContainerStateCount {
			containerStates[state] = true
		}
		for state := range currentContainerStateCount {
			containerStates[state] = true
		}

		// 通过旧计数和当前计数的差异更新指标
		for state := range containerStates {
			diff := currentContainerStateCount[state] - oldContainerStateCount[state]
			metrics.RunningContainerCount.WithLabelValues(string(state)).Add(float64(diff))
		}
	}
}
```

###### updateLatencyMetric

```go
func (e *EventedPLEG) updateLatencyMetric(event *runtimeapi.ContainerEventResponse) {
    duration := time.Duration(time.Now().UnixNano()-event.CreatedAt) * time.Nanosecond
    metrics.EventedPLEGConnLatency.Observe(duration.Seconds())
}
```

###### getContainerStateCount

```go
func getContainerStateCount(podStatus *kubecontainer.PodStatus) map[kubecontainer.State]int {
    containerStateCount := make(map[kubecontainer.State]int)
    for _, container := range podStatus.ContainerStatuses {
    	containerStateCount[container.State]++
    }
    return containerStateCount
}
```

###### getPodSandboxState

```go
func getPodSandboxState(podStatus *kubecontainer.PodStatus) kubecontainer.State {
	// 当缓存中不包含 podID 时，增加正在运行的 pod 计数
	var sandboxId string
	for _, sandbox := range podStatus.SandboxStatuses {
		sandboxId = sandbox.Id
		// Pod 必须只包含一个沙箱
		break
	}

	for _, containerStatus := range podStatus.ContainerStatuses {
		if containerStatus.ID.ID == sandboxId {
			if containerStatus.State == kubecontainer.ContainerStateRunning {
				return containerStatus.State
			}
		}
	}
	return kubecontainer.ContainerStateExited
}
```

#### Stop

```go
// 停止Evented PLEG
func (e *EventedPLEG) Stop() {
	e.runningMu.Lock()         // 锁定runningMu，保证原子性操作
	defer e.runningMu.Unlock() // 在函数结束时解锁runningMu
	if !isEventedPLEGInUse() { // 如果Evented PLEG未在使用中，则返回
		return
	}
	setEventedPLEGUsage(false) // 将Evented PLEG的使用状态设置为false
	close(e.stopCh)            // 关闭stopCh通道
	close(e.stopCacheUpdateCh) // 关闭stopCacheUpdateCh通道
}
```

##### setEventedPLEGUsage

```go
// setEventedPLEGUsage只能从Evented PLEG的Start/Stop方法中访问
func setEventedPLEGUsage(enable bool) {
	eventedPLEGUsageMu.Lock()         // 锁定eventedPLEGUsageMu，保证原子性操作
	defer eventedPLEGUsageMu.Unlock() // 在函数结束时解锁eventedPLEGUsageMu
	eventedPLEGUsage = enable         // 设置eventedPLEGUsage的值为enable
}
```

#### Update

```go
// 更新重新列举周期和阈值
func (e *EventedPLEG) Update(relistDuration *RelistDuration) {
	e.genericPleg.Update(relistDuration) // 调用genericPleg的Update方法，更新重新列举周期和阈值
}
```

#### Watch

```go
// Watch方法返回一个通道，订阅者可以从该通道接收PodLifecycleEvent事件
func (e *EventedPLEG) Watch() chan *PodLifecycleEvent {
	return e.eventChannel // 返回eventChannel通道
}
```

#### Healthy

```go
// Healthy方法检查PLEG是否正常工作
func (e *EventedPLEG) Healthy() (bool, error) {
	// 当重新列举时间超过重新列举阈值时，GenericPLEG被声明为不健康。
	// 如果EventedPLEG已打开，重新列举周期和重新列举阈值被调整为更高的值。
	// 因此，Generic PLEG的健康检查应该检查重新列举周期和重新列举阈值的调整值。

	// 只有当eventChannel的容量已满时，EventedPLEG被声明为不健康。
	if len(e.eventChannel) == cap(e.eventChannel) {
		return false, fmt.Errorf("EventedPLEG: pleg event channel capacity is full with %v events", len(e.eventChannel))
	}

	timestamp := e.clock.Now()                          // 获取当前时间戳
	metrics.PLEGLastSeen.Set(float64(timestamp.Unix())) // 设置PLEGLastSeen指标的值为当前时间戳的Unix时间
	return true, nil
}
```

#### Relist

```go
// Relist使用GenericPLEG重新列举所有容器
func (e *EventedPLEG) Relist() {
	e.genericPleg.Relist() // 调用genericPleg的Relist方法，重新列举所有容器
}
```

#### UpdateCache

```go
func (e *EventedPLEG) UpdateCache(pod *kubecontainer.Pod, pid types.UID) (error, bool) {
	return fmt.Errorf("not implemented"), false // 返回错误信息和false，表示UpdateCache方法未实现
}
```

