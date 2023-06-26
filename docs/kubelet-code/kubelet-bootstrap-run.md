---
id: 2-kubelet-code 
title: kubelet BootStrap Run 代码走读
description: kubelet BootStrap Run 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## 简介

本文解析 Bootstrap 的 Run 函数，也是 kubelet的核心函数。

## Run

```GO
// Run函数启动kubelet以响应配置更新
func (kl *Kubelet) Run(updates <-chan kubetypes.PodUpdate) {
	ctx := context.Background()
    // 检查是否需要创建日志服务器
    if kl.logServer == nil {
        file := http.FileServer(http.Dir(nodeLogDir))

        // 如果启用了NodeLogQuery特性并且kubeletConfiguration.EnableSystemLogQuery为true，则创建日志服务器
        if utilfeature.DefaultFeatureGate.Enabled(features.NodeLogQuery) && kl.kubeletConfiguration.EnableSystemLogQuery {
            kl.logServer = http.StripPrefix("/logs/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
                // 解析URL参数并创建新的NodeLogQuery对象
                if nlq, errs := newNodeLogQuery(req.URL.Query()); len(errs) > 0 {
                    // 如果有错误发生，则返回错误响应
                    http.Error(w, errs.ToAggregate().Error(), http.StatusBadRequest)
                    return
                } else if nlq != nil {
                    if req.URL.Path != "/" && req.URL.Path != "" {
                        // 在查询模式下，不允许使用路径
                        http.Error(w, "path not allowed in query mode", http.StatusNotAcceptable)
                        return
                    }
                    if errs := nlq.validate(); len(errs) > 0 {
                        // 验证NodeLogQuery对象，如果有错误发生，则返回错误响应
                        http.Error(w, errs.ToAggregate().Error(), http.StatusNotAcceptable)
                        return
                    }
                    // 验证确保请求不同时查询服务和文件
                    if len(nlq.Services) > 0 {
                        // 如果请求查询服务，则调用journal.ServeHTTP处理请求
                        journal.ServeHTTP(w, req)
                        return
                    }
                    // 验证确保请求不会同时查询多个文件
                    if len(nlq.Files) == 1 {
                        // 如果只查询一个文件，则修改请求的URL路径
                        // 注意：对于Windows客户端使用了\作为路径分隔符，需要将其转换为/
                        req.URL.Path = filepath.ToSlash(nlq.Files[0])
                    }
                }
                // 如果以上条件都不满足，则返回文件服务器处理请求
                file.ServeHTTP(w, req)
            }))
        } else {
            // 否则，创建简单的文件服务器
            kl.logServer = http.StripPrefix("/logs/", file)
        }
    }

    // 如果kubeClient为空，则打印日志并不发送节点状态更新
    if kl.kubeClient == nil {
        klog.InfoS("No API server defined - no node status update will be sent")
    }

    // 启动云提供商同步管理器
    if kl.cloudResourceSyncManager != nil {
        go kl.cloudResourceSyncManager.Run(wait.NeverStop)
    }

    // 初始化模块，如果出错则打印日志并退出
    if err := kl.initializeModules(); err != nil {
        kl.recorder.Eventf(kl.nodeRef, v1.EventTypeWarning, events.KubeletSetupFailed, err.Error())
        klog.ErrorS(err, "Failed to initialize internal modules")
        os.Exit(1)
    }

    // 启动卷管理器
    go kl.volumeManager.Run(kl.sourcesReady, wait.NeverStop)

    if kl.kubeClient != nil {
        // 启动两个goroutine来更新节点状态
        //
        // 第一个goroutine每隔nodeStatusUpdateFrequency向apiserver报告一次节点状态，目的是提供定期的状态间隔；
        // 第二个goroutine用于在初始化期间提供更及时的状态更新，在节点准备就绪后向apiserver发送一次更新请求，然后退出。
        //
        // 引入一些小的随机性，以确保随时间的推移，由于优先级和公平性效应，请求不会在一组节点中大致同时开始累积。
        go wait.JitterUntil(kl.syncNodeStatus, kl.nodeStatusUpdateFrequency, 0.04, true, wait.NeverStop)
        go kl.fastStatusUpdateOnce()

        // 启动同步租约的goroutine
        go kl.nodeLeaseController.Run(context.Background())
    }

    // 定期更新RuntimeUp状态的goroutine
    go wait.Until(kl.updateRuntimeUp, 5*time.Second, wait.NeverStop)

    // 设置iptables规则
    if kl.makeIPTablesUtilChains {
        kl.initNetworkUtil()
    }

    // 启动组件同步循环
    kl.statusManager.Start()

    // 如果启用了RuntimeClasses，则启动RuntimeClasses同步循环
    if kl.runtimeClassManager != nil {
        kl.runtimeClassManager.Start(wait.NeverStop)
    }

    // 启动Pod Lifecycle Event Generator
    kl.pleg.Start()

    // 如果启用了EventedPLEG特性，则启动EventedPLEG
    if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
        kl.eventedPleg.Start()
    }

    // 启动同步循环
    kl.syncLoop(ctx, updates, kl)
}
```

### initializeModules

```GO
func (kl *Kubelet) initializeModules() error {
	// 初始化Prometheus指标收集器，注册VolumeStatsCollector和LogMetricsCollector
	metrics.Register(
		collectors.NewVolumeStatsCollector(kl),
		collectors.NewLogMetricsCollector(kl.StatsProvider.ListPodStats),
	)
	// 设置节点名称
	metrics.SetNodeName(kl.nodeName)
	// 注册服务器指标
	servermetrics.Register()

	// 设置文件系统目录
	if err := kl.setupDataDirs(); err != nil {
		return err
	}

	// 如果容器日志目录不存在，则创建它
	if _, err := os.Stat(ContainerLogsDir); err != nil {
		if err := kl.os.MkdirAll(ContainerLogsDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %v", ContainerLogsDir, err)
		}
	}

	// 启动镜像管理器
	kl.imageManager.Start()

	// 如果启用了证书管理器，则启动证书管理器
	if kl.serverCertificateManager != nil {
		kl.serverCertificateManager.Start()
	}

	// 启动OOM监视器
	if kl.oomWatcher != nil {
		if err := kl.oomWatcher.Start(kl.nodeRef); err != nil {
			return fmt.Errorf("failed to start OOM watcher: %w", err)
		}
	}

	// 启动资源分析器
	kl.resourceAnalyzer.Start()

	return nil
}
```

#### setupDataDirs

```GO
// setupDataDirs函数用于设置数据目录。
// 1. 创建根目录。
// 2. 创建pods目录。
// 3. 创建插件目录。
// 4. 创建pod资源目录。
// 5. 创建检查点目录。
func (kl *Kubelet) setupDataDirs() error {
    // 清理根目录路径，并检查是否符合规范。
    if cleanedRoot := filepath.Clean(kl.rootDirectory); cleanedRoot != kl.rootDirectory {
    	return fmt.Errorf("rootDirectory not in canonical form: expected %s, was %s", cleanedRoot, kl.rootDirectory)
    }
    // 获取插件注册目录。
    pluginRegistrationDir := kl.getPluginsRegistrationDir()
    // 获取插件目录。
    pluginsDir := kl.getPluginsDir()
    // 创建根目录。
    if err := os.MkdirAll(kl.getRootDir(), 0750); err != nil {
    	return fmt.Errorf("error creating root directory: %v", err)
    }
    // 将根目录配置为可共享的。
    if err := kl.hostutil.MakeRShared(kl.getRootDir()); err != nil {
    	return fmt.Errorf("error configuring root directory: %v", err)
    }
    // 创建pods目录。
    if err := os.MkdirAll(kl.getPodsDir(), 0750); err != nil {
    	return fmt.Errorf("error creating pods directory: %v", err)
    }
    // 创建插件目录。
    if err := os.MkdirAll(kl.getPluginsDir(), 0750); err != nil {
    return fmt.Errorf("error creating plugins directory: %v", err)
    }
    // 创建插件注册目录。
    if err := os.MkdirAll(kl.getPluginsRegistrationDir(), 0750); err != nil {
    	return fmt.Errorf("error creating plugins registry directory: %v", err)
    }
    // 创建pod资源目录。
    if err := os.MkdirAll(kl.getPodResourcesDir(), 0750); err != nil {
    	return fmt.Errorf("error creating podresources directory: %v", err)
    }
    // 如果启用了ContainerCheckpoint特性，则创建检查点目录。
    if utilfeature.DefaultFeatureGate.Enabled(features.ContainerCheckpoint) {
        if err := os.MkdirAll(kl.getCheckpointsDir(), 0700); err != nil {
            return fmt.Errorf("error creating checkpoint directory: %v", err)
        }
    }
    // 如果启用了SELinux，则为插件注册目录和插件目录设置SELinux标签。
    if selinux.GetEnabled() {
        err := selinux.SetFileLabel(pluginRegistrationDir, config.KubeletPluginsDirSELinuxLabel)
        if err != nil {
        	klog.InfoS("Unprivileged containerized plugins might not work, could not set selinux context on plugin registration dir", "path", pluginRegistrationDir, "err", err)
        }
        err = selinux.SetFileLabel(pluginsDir, config.KubeletPluginsDirSELinuxLabel)
        if err != nil {
        	klog.InfoS("Unprivileged containerized plugins might not work, could not set selinux context on plugins dir", "path", pluginsDir, "err", err)
        }
    }
    return nil
}
```

### syncNodeStatus

```GO
func (kl *Kubelet) syncNodeStatus() {
	kl.syncNodeStatusMux.Lock()
	defer kl.syncNodeStatusMux.Unlock()
	ctx := context.Background()

	if kl.kubeClient == nil || kl.heartbeatClient == nil {
		return
	}
	if kl.registerNode {
		kl.registerWithAPIServer()
	}
	if err := kl.updateNodeStatus(ctx); err != nil {
		klog.ErrorS(err, "Unable to update node status")
	}
}
```

#### registerWithAPIServer

```GO
// registerWithAPIServer 函数用于将节点注册到集群主节点。可以多次调用，但不能并发调用（kl.registrationCompleted 未加锁）。
func (kl *Kubelet) registerWithAPIServer() {
    if kl.registrationCompleted { // 如果已经完成注册，则返回
        return
    }
    step := 100 * time.Millisecond // 初始步长为 100 毫秒

    for {
        time.Sleep(step)  // 休眠一段时间
        step = step * 2  // 步长翻倍
        if step >= 7*time.Second {  // 如果步长超过等于 7 秒，则固定为 7 秒
            step = 7 * time.Second
        }

        node, err := kl.initialNode(context.TODO())  // 构建 v1.Node 对象
        if err != nil {
            klog.ErrorS(err, "Unable to construct v1.Node object for kubelet")  // 构建对象失败，输出错误日志并继续循环
            continue
        }

        klog.InfoS("Attempting to register node", "node", klog.KObj(node))  // 尝试注册节点，输出信息日志
        registered := kl.tryRegisterWithAPIServer(node)  // 尝试向 API 服务器注册节点
        if registered {
            klog.InfoS("Successfully registered node", "node", klog.KObj(node))  // 注册成功，输出信息日志
            kl.registrationCompleted = true  // 设置注册完成标志位
            return
        }
    }
}
```

#### updateNodeStatus

```GO
// updateNodeStatus 函数在更改或距离上次同步已经过了足够的时间时，更新节点状态到主节点，并进行重试。
func (kl *Kubelet) updateNodeStatus(ctx context.Context) error {
klog.V(5).InfoS("Updating node status") // 输出信息日志，表示正在更新节点状态
    for i := 0; i < nodeStatusUpdateRetry; i++ { // 循环指定次数
    	if err := kl.tryUpdateNodeStatus(ctx, i); err != nil { // 尝试更新节点状态
    		if i > 0 && kl.onRepeatedHeartbeatFailure != nil { // 如果不是第一次重试，并且存在 onRepeatedHeartbeatFailure 回调函数，则调用它
    			kl.onRepeatedHeartbeatFailure()
    		}
    		klog.ErrorS(err, "Error updating node status, will retry") // 更新节点状态失败，输出错误日志
    	} else {
    		return nil // 更新节点状态成功，返回 nil
    	}
    }
    return fmt.Errorf("update node status exceeds retry count") // 更新节点状态超过重试次数，返回错误
}

```

##### tryUpdateNodeStatus

````GO
// tryUpdateNodeStatus 函数在更改或距离上次同步已经过了足够的时间时，尝试更新节点状态到主节点。
func (kl *Kubelet) tryUpdateNodeStatus(ctx context.Context, tryNumber int) error {
    // 在大型集群中，对来自此处的 Node 对象的 GET 和 PUT 操作占主要负载，对 apiserver 和 etcd 造成较大负载。
    // 为了减少对 etcd 的负载，我们从 apiserver 缓存中提供 GET 操作（数据可能会稍有延迟，但不会造成更多冲突，延迟非常小）。
    // 如果引发冲突，所有重试都直接从 etcd 提供。
    opts := metav1.GetOptions{}
    if tryNumber == 0 {
        util.FromApiserverCache(&opts)
    }
    originalNode, err := kl.heartbeatClient.CoreV1().Nodes().Get(ctx, string(kl.nodeName), opts) // 获取节点对象
    if err != nil {
        return fmt.Errorf("error getting node %q: %v", kl.nodeName, err) // 获取节点对象失败，返回错误
    }
    if originalNode == nil {
        return fmt.Errorf("nil %q node object", kl.nodeName) // 获取到的节点对象为空，返回错误
    }

    node, changed := kl.updateNode(ctx, originalNode)  // 更新节点
    shouldPatchNodeStatus := changed || kl.clock.Since(kl.lastStatusReportTime) >= kl.nodeStatusReportFrequency  // 是否需要更新节点状态

    if !shouldPatchNodeStatus {
        kl.markVolumesFromNode(node)  // 不需要更新节点状态，执行其他操作
        return nil
    }

    updatedNode, err := kl.patchNodeStatus(originalNode, node)  // 更新节点状态
    if err == nil {
        kl.markVolumesFromNode(updatedNode)
    }
    return err
}
````

##### updateNode

```GO
// updateNode 函数在 originalNode 的基础上创建一个副本，并对其进行更新逻辑。
// 它返回更新后的节点对象和一个布尔值，指示是否有任何更改。
func (kl *Kubelet) updateNode(ctx context.Context, originalNode *v1.Node) (*v1.Node, bool) {
	node := originalNode.DeepCopy()
    podCIDRChanged := false
    if len(node.Spec.PodCIDRs) != 0 {
        // Pod CIDR 可能在之前已更新，因此我们不能依赖 node.Spec.PodCIDR 为非空。
        // 我们还需要知道是否实际上更改了 pod CIDR。
        var err error
        podCIDRs := strings.Join(node.Spec.PodCIDRs, ",")
        if podCIDRChanged, err = kl.updatePodCIDR(ctx, podCIDRs); err != nil {
            klog.ErrorS(err, "Error updating pod CIDR")  // 更新 Pod CIDR 失败，输出错误日志
        }
    }

    areRequiredLabelsNotPresent := false
    osName, osLabelExists := node.Labels[v1.LabelOSStable]
    if !osLabelExists || osName != goruntime.GOOS {
        if len(node.Labels) == 0 {
            node.Labels = make(map[string]string)
        }
        node.Labels[v1.LabelOSStable] = goruntime.GOOS
        areRequiredLabelsNotPresent = true
    }
    arch, archLabelExists := node.Labels[v1.LabelArchStable]
    if !archLabelExists || arch != goruntime.GOARCH {
        if len(node.Labels) == 0 {
            node.Labels = make(map[string]string)
        }
        node.Labels[v1.LabelArchStable] = goruntime.GOARCH
        areRequiredLabelsNotPresent = true
    }

    kl.setNodeStatus(ctx, node)

    changed := podCIDRChanged || nodeStatusHasChanged(&originalNode.Status, &node.Status) || areRequiredLabelsNotPresent
    return node, changed
}
```

##### patchNodeStatus

```GO
// patchNodeStatus 函数根据 originalNode，在 API 服务器上对节点进行补丁操作。
// 它返回任何潜在的错误，或者返回一个 updatedNode，并在成功时刷新 kubelet 的状态。
func (kl *Kubelet) patchNodeStatus(originalNode, node *v1.Node) (*v1.Node, error) {
    // 在 API 服务器上打补丁当前状态
    updatedNode, _, err := nodeutil.PatchNodeStatus(kl.heartbeatClient.CoreV1(), types.NodeName(kl.nodeName), originalNode, node)
    if err != nil {
    	return nil, err // 补丁操作失败，返回错误
    }
    kl.lastStatusReportTime = kl.clock.Now() // 更新最后报告状态的时间
    kl.setLastObservedNodeAddresses(updatedNode.Status.Addresses)
    return updatedNode, nil
}
```

### fastStatusUpdateOnce

```GO
func (kl *Kubelet) fastStatusUpdateOnce() {
	ctx := context.Background()
	start := kl.clock.Now()
	stopCh := make(chan struct{})

	wait.Until(func() {
		if kl.fastNodeStatusUpdate(ctx, kl.clock.Since(start) >= nodeReadyGracePeriod) {
			close(stopCh)
		}
	}, 100*time.Millisecond, stopCh)
}
```

#### fastNodeStatusUpdate

```GO
func (kl *Kubelet) fastNodeStatusUpdate(ctx context.Context, timeout bool) (completed bool) {
	kl.syncNodeStatusMux.Lock()
	defer func() {
		kl.syncNodeStatusMux.Unlock()

		if completed {
			kl.updateRuntimeMux.Lock()
			defer kl.updateRuntimeMux.Unlock()
			kl.containerRuntimeReadyExpected = true
		}
	}()

	if timeout {
		klog.ErrorS(nil, "Node not becoming ready in time after startup")
		return true
	}

	originalNode, err := kl.GetNode()
	if err != nil {
		klog.ErrorS(err, "Error getting the current node from lister")
		return false
	}

	readyIdx, originalNodeReady := nodeutil.GetNodeCondition(&originalNode.Status, v1.NodeReady)
	if readyIdx == -1 {
		klog.ErrorS(nil, "Node does not have NodeReady condition", "originalNode", originalNode)
		return false
	}

	if originalNodeReady.Status == v1.ConditionTrue {
		return true
	}

	kl.updateRuntimeUp()

	node, changed := kl.updateNode(ctx, originalNode)

	if !changed {
		return false
	}

	readyIdx, nodeReady := nodeutil.GetNodeCondition(&node.Status, v1.NodeReady)
	if readyIdx == -1 {
		klog.ErrorS(nil, "Node does not have NodeReady condition", "node", node)
		return false
	}

	if nodeReady.Status == v1.ConditionFalse {
		return false
	}

	klog.InfoS("Fast updating node status as it just became ready")
	if _, err := kl.patchNodeStatus(originalNode, node); err != nil {
		klog.ErrorS(err, "Error updating node status, will retry with syncNodeStatus")
		kl.syncNodeStatusMux.Unlock()
		kl.syncNodeStatus()
		kl.syncNodeStatusMux.Lock()
	}

	return true
}
```

### updateRuntimeUp

```GO
// updateRuntimeUp 调用容器运行时状态回调函数，在容器运行时首次启动时初始化
// 运行时相关的模块，并在状态检查失败时返回错误。如果状态检查成功，
// 则更新 kubelet 的运行时间状态中的容器运行时运行时间。
func (kl *Kubelet) updateRuntimeUp() {
    kl.updateRuntimeMux.Lock() // 获取互斥锁
    defer kl.updateRuntimeMux.Unlock() // 在函数返回时释放互斥锁
    ctx := context.Background() // 创建一个后台上下文
    s, err := kl.containerRuntime.Status(ctx)  // 获取容器运行时的状态
    if err != nil {
        klog.ErrorS(err, "Container runtime sanity check failed")  // 如果获取状态失败，则记录错误日志并返回
        return
    }
    if s == nil {
        klog.ErrorS(nil, "Container runtime status is nil")  // 如果状态为空，则记录错误日志并返回
        return
    }
    // 定期记录完整的运行时状态以便调试。
    klog.V(4).InfoS("Container runtime status", "status", s)

    klogErrorS := klog.ErrorS
    if !kl.containerRuntimeReadyExpected {
        klogErrorS = klog.V(4).ErrorS
    }

    networkReady := s.GetRuntimeCondition(kubecontainer.NetworkReady)  // 获取容器运行时网络是否准备就绪的状态
    if networkReady == nil || !networkReady.Status {
        klogErrorS(nil, "Container runtime network not ready", "networkReady", networkReady)  // 如果网络未准备就绪，则记录错误日志并设置网络状态
        kl.runtimeState.setNetworkState(fmt.Errorf("container runtime network not ready: %v", networkReady))
    } else {
        // 如果容器运行时网络已准备就绪，则设置网络状态为 nil。
        kl.runtimeState.setNetworkState(nil)
    }

    runtimeReady := s.GetRuntimeCondition(kubecontainer.RuntimeReady)  // 获取容器运行时是否准备就绪的状态
    if runtimeReady == nil || !runtimeReady.Status {
        klogErrorS(nil, "Container runtime not ready", "runtimeReady", runtimeReady)  // 如果运行时未准备就绪，则记录错误日志并设置运行时状态
        kl.runtimeState.setRuntimeState(fmt.Errorf("container runtime not ready: %v", runtimeReady))
        return
    }
    kl.runtimeState.setRuntimeState(nil)  // 如果运行时已准备就绪，则设置运行时状态为 nil。
    kl.oneTimeInitializer.Do(kl.initializeRuntimeDependentModules)  // 调用初始化运行时相关模块的函数
    kl.runtimeState.setRuntimeSync(kl.clock.Now())  // 设置运行时同步时间
}
```

### initNetworkUtil

```GO
func (kl *Kubelet) initNetworkUtil() {
	exec := utilexec.New() // 创建一个 utilexec 实例
	iptClients := []utiliptables.Interface{
		utiliptables.New(exec, utiliptables.ProtocolIPv4), // 使用 utilexec 实例创建一个 IPv4 的 utiliptables 实例
		utiliptables.New(exec, utiliptables.ProtocolIPv6), // 使用 utilexec 实例创建一个 IPv6 的 utiliptables 实例
	}

	for i := range iptClients { // 遍历 iptClients 切片
		iptClient := iptClients[i] // 获取当前循环的 iptClient
		if kl.syncIPTablesRules(iptClient) { // 调用 syncIPTablesRules 方法来同步 iptables 规则，如果成功返回 true
			klog.InfoS("Initialized iptables rules.", "protocol", iptClient.Protocol()) // 输出日志，表示成功初始化 iptables 规则，并指定协议
			go iptClient.Monitor(
				utiliptables.Chain("KUBE-KUBELET-CANARY"), // 监听指定的 iptables 链
				[]utiliptables.Table{utiliptables.TableMangle, utiliptables.TableNAT, utiliptables.TableFilter}, // 监听指定的 iptables 表
				func() { kl.syncIPTablesRules(iptClient) }, // 当有变化时，调用 syncIPTablesRules 方法同步 iptables 规则
				1*time.Minute, wait.NeverStop, // 每分钟监听一次，直到停止
			)
		} else {
			klog.InfoS("Failed to initialize iptables rules; some functionality may be missing.", "protocol", iptClient.Protocol()) // 输出日志，表示初始化 iptables 规则失败，并指定协议
		}
	}
}
```

#### syncIPTablesRules

```GO
// syncIPTablesRules 确保 KUBE-IPTABLES-HINT 链存在，并安装 martian 数据包保护规则。如果 IPTablesOwnershipCleanup 功能关闭，则还会同步其他已弃用的 iptables 规则。
func (kl *Kubelet) syncIPTablesRules(iptClient utiliptables.Interface) bool {
	// 创建一个 hint 链，以便其他组件可以查看我们是使用 iptables-legacy 还是 iptables-nft。
	if _, err := iptClient.EnsureChain(utiliptables.TableMangle, KubeIPTablesHintChain); err != nil { // 确保 iptables 中指定表和链存在
		klog.ErrorS(err, "Failed to ensure that iptables hint chain exists") // 输出日志，表示创建 hint 链失败
		return false
	}

	if !iptClient.IsIPv6() { // 如果不是 IPv6
		// 设置 KUBE-FIREWALL 链和 martian 数据包保护规则。
		//（见下文。）

		// 注意: kube-proxy（在 iptables 模式下）会创建一个与此规则完全相同的副本。
		// 如果将来要更改此规则，则必须以一种与 kube-proxy 创建的规则版本兼容的方式进行更改。

		if _, err := iptClient.EnsureChain(utiliptables.TableFilter, KubeFirewallChain); err != nil { // 确保 filter 表中的 KUBE-FIREWALL 链存在
			klog.ErrorS(err, "Failed to ensure that filter table KUBE-FIREWALL chain exists") // 输出日志，表示创建 KUBE-FIREWALL 链失败
			return false
		}

		if _, err := iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, utiliptables.ChainOutput, "-j", string(KubeFirewallChain)); err != nil { // 确保 OUTPUT 链跳转到 KUBE-FIREWALL 链
			klog.ErrorS(err, "Failed to ensure that OUTPUT chain jumps to KUBE-FIREWALL") // 输出日志，表示 OUTPUT 链跳转到 KUBE-FIREWALL 链失败
			return false
		}
		if _, err := iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, utiliptables.ChainInput, "-j", string(KubeFirewallChain)); err != nil { // 确保 INPUT 链跳转到 KUBE-FIREWALL 链
			klog.ErrorS(err, "Failed to ensure that INPUT chain jumps to KUBE-FIREWALL") // 输出日志，表示 INPUT 链跳转到 KUBE-FIREWALL 链失败
			return false
		}

		// Kube-proxy 使用 `route_localnet` 在本地主机上启用 NodePort，这会创建一个安全漏洞（https://issue.k8s.io/90259），
		// 此 iptables 规则可减轻该漏洞的影响。此规则应该添加到 kube-proxy，但错误地添加到了 kubelet 中，我们目前在 kubelet 中保留它，以防其他第三方组件依赖它。
		if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableFilter, KubeFirewallChain,
			"-m", "comment", "--comment", "block incoming localnet connections",
			"--dst", "127.0.0.0/8",
			"!", "--src", "127.0.0.0/8",
			"-m", "conntrack",
			"!", "--ctstate", "RELATED,ESTABLISHED,DNAT",
			"-j", "DROP"); err != nil { // 确保规则来丢弃无效的本地主机数据包
			klog.ErrorS(err, "Failed to ensure rule to drop invalid localhost packets in filter table KUBE-FIREWALL chain") // 输出日志，表示添加规则失败
			return false
		}
	}

	if !utilfeature.DefaultFeatureGate.Enabled(features.IPTablesOwnershipCleanup) { // 如果 IPTablesOwnershipCleanup 功能关闭
		ok := kl.syncIPTablesRulesDeprecated(iptClient) // 调用 syncIPTablesRulesDeprecated 方法来同步已弃用的 iptables 规则
		if !ok {
			return false
		}
	}

	return true
}
```

##### syncIPTablesRules

```GO
// syncIPTablesRulesDeprecated 确保过时的 iptables 规则存在：
// 1. 在 nat 表中，KUBE-MARK-DROP 规则用于标记需要丢弃的连接
// 被标记的连接将在 filter 表的 INPUT/OUTPUT 链中被丢弃
// 2. 在 nat 表中，KUBE-MARK-MASQ 规则用于标记需要进行 SNAT 的连接
// 被标记的连接将在 nat 表的 POSTROUTING 链中进行 SNAT
func (kl *Kubelet) syncIPTablesRulesDeprecated(iptClient utiliptables.Interface) bool {
    // 设置 KUBE-MARK-DROP 规则
    dropMark := getIPTablesMark(kl.iptablesDropBit)
    // 确保 KUBE-MARK-DROP 链存在
    if _, err := iptClient.EnsureChain(utiliptables.TableNAT, KubeMarkDropChain); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-MARK-DROP chain exists")
        return false
    }
    // 确保 KUBE-MARK-DROP 规则存在
    if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubeMarkDropChain, "-j", "MARK", "--or-mark", dropMark); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-MARK-DROP rule exists")
        return false
    }
    // 确保 KUBE-FIREWALL 链存在
    if _, err := iptClient.EnsureChain(utiliptables.TableFilter, KubeFirewallChain); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-FIREWALL chain exists")
        return false
    }
    // 设置 KUBE-FIREWALL 规则
    if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableFilter, KubeFirewallChain,
        "-m", "comment", "--comment", "kubernetes firewall for dropping marked packets",
        "-m", "mark", "--mark", fmt.Sprintf("%s/%s", dropMark, dropMark),
        "-j", "DROP"); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-FIREWALL rule exists")
        return false
    }
	// 设置 KUBE-MARK-MASQ 规则
    masqueradeMark := getIPTablesMark(kl.iptablesMasqueradeBit)
    // 确保 KUBE-MARK-MASQ 链存在
    if _, err := iptClient.EnsureChain(utiliptables.TableNAT, KubeMarkMasqChain); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-MARK-MASQ chain exists")
        return false
    }
    // 确保 KUBE-POSTROUTING 链存在
    if _, err := iptClient.EnsureChain(utiliptables.TableNAT, KubePostroutingChain); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-POSTROUTING chain exists")
        return false
    }
    // 确保 KUBE-MARK-MASQ 规则存在
    if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubeMarkMasqChain, "-j", "MARK", "--or-mark", masqueradeMark); err != nil {
        klog.ErrorS(err, "Failed to ensure that KUBE-MARK-MASQ rule exists")
        return false
    }
    // 确保 POSTROUTING 链跳转到 KUBE-POSTROUTING
    if _, err := iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting,
        "-m", "comment", "--comment", "kubernetes postrouting rules", "-j", string(KubePostroutingChain)); err != nil {
        klog.ErrorS(err, "Failed to ensure that POSTROUTING chain jumps to KUBE-POSTROUTING")
        return false
    }

    // 设置 KUBE-POSTROUTING 规则来取消标记和对标记的数据包进行 masquerade

    // 注意：kube-proxy（在 iptables 和 ipvs 模式下）会创建这些规则的相同副本。
    // 如果将来要更改这些规则，必须以一种与 kube-proxy 创建的不同版本规则正确地进行交互的方式进行更改。

    // 确保第一个 masquerading 规则存在
    if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubePostroutingChain,
        "-m", "mark", "!", "--mark", fmt.Sprintf("%s/%s", masqueradeMark, masqueradeMark),
        "-j", "RETURN"); err != nil {
        klog.ErrorS(err, "Failed to ensure first masquerading rule exists")
        return false
    }
    // 清除标记以避免在数据包重新遍历网络堆栈时重新进行 masquerade。
    // 我们知道标记位当前已设置，所以我们可以使用 --xor-mark 来清除它（无需再次使用 Sprintf 进行位掩码）。
    if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubePostroutingChain,
        "-j", "MARK", "--xor-mark", masqueradeMark); err != nil {
        klog.ErrorS(err, "Failed to ensure second masquerading rule exists")
        return false
    }
    masqRule := []string{
        "-m", "comment", "--comment", "kubernetes service traffic requiring SNAT",
        "-j", "MASQUERADE",
    }
    if iptClient.HasRandomFully() {
        masqRule = append(masqRule, "--random-fully")
    }
    // 确保第三个 masquerading 规则存在
    if _, err := iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubePostroutingChain, masqRule...); err != nil {
        klog.ErrorS(err, "Failed to ensure third masquerading rule exists")
        return false
    }

    return true
}
```

##### getIPTablesMark

```GO
// 根据给定的位返回 fwmark
func getIPTablesMark(bit int) string {
    value := 1 << uint(bit)
    return fmt.Sprintf("%#08x", value)
}
```

## syncLoop

```GO
// syncLoop 是处理变更的主循环。它从三个通道（文件、apiserver 和 http）中监听变更，并创建它们的并集。
// 对于每个新的变更，它会根据期望状态和运行状态运行同步操作。如果没有检测到配置的变化，
// 它会每隔 sync-frequency 秒同步最后已知的期望状态。永远不会返回。
func (kl *Kubelet) syncLoop(ctx context.Context, updates <-chan kubetypes.PodUpdate, handler SyncHandler) {
	klog.InfoS("Starting kubelet main sync loop") // 输出日志，表示开始 kubelet 的主同步循环

	// syncTicker 用于唤醒 kubelet，检查是否有需要同步的 pod workers。
	// 1 秒的周期足够，因为同步间隔默认为 10 秒。
	syncTicker := time.NewTicker(time.Second)
	defer syncTicker.Stop()

	housekeepingTicker := time.NewTicker(housekeepingPeriod)
	defer housekeepingTicker.Stop()

	plegCh := kl.pleg.Watch() // 获取 pod lifecycle event generator 的观察通道

	const (
		base   = 100 * time.Millisecond // 初始延迟时间
		max    = 5 * time.Second        // 最大延迟时间
		factor = 2                      // 延迟时间增长因子
	)

	duration := base // 当前延迟时间

	// 检查 resolv.conf 中的限制，这与个别 pod 无关。
	// 由于此处在 syncLoop 中调用，因此不需要在其他地方调用它。
	if kl.dnsConfigurer != nil && kl.dnsConfigurer.ResolverConfig != "" {
		kl.dnsConfigurer.CheckLimitsForResolvConf()
	}

	for {
		if err := kl.runtimeState.runtimeErrors(); err != nil { // 检查运行时错误
			klog.ErrorS(err, "Skipping pod synchronization") // 输出日志，表示跳过 pod 同步
			// 指数回退
			time.Sleep(duration)
			duration = time.Duration(math.Min(float64(max), factor*float64(duration)))
			continue
		}
		// 如果成功，则重置回退时间
		duration = base

		kl.syncLoopMonitor.Store(kl.clock.Now()) // 记录当前时间到 syncLoopMonitor

		if !kl.syncLoopIteration(ctx, updates, handler, syncTicker.C, housekeepingTicker.C, plegCh) { // 执行同步循环的迭代
			break // 如果返回 false，则退出循环
		}

		kl.syncLoopMonitor.Store(kl.clock.Now()) // 记录当前时间到 syncLoopMonitor
	}
}
```

### syncLoopIteration

```GO
// syncLoopIteration 函数从不同的通道中读取事件，并将 Pod 分发给给定的处理程序。

// 参数：
// 1. configCh: 用于读取配置事件的通道
// 2. handler: 用于分发 Pod 的 SyncHandler
// 3. syncCh: 用于读取周期性同步事件的通道
// 4. housekeepingCh: 用于读取清理事件的通道
// 5. plegCh: 用于读取 PLEG 更新的通道

// 同样从 kubelet 存活管理器的更新通道中读取事件。

// 工作流程是从其中一个通道读取事件，处理该事件，并更新同步循环监视器中的时间戳。

// 需要注意的是，尽管与 switch 语句在语法上相似，但在评估 select 时，如果有多个通道准备好读取，case 语句将以伪随机顺序进行评估。
// 换句话说，case 语句的评估顺序是随机的，如果多个通道都有事件，不能假设 case 语句按顺序评估。

// 在没有特定顺序的情况下，不同的通道的处理方式如下：

// - configCh: 将配置更改的 Pod 分派给适当的处理程序回调函数
// - plegCh: 更新运行时缓存；同步 Pod
// - syncCh: 同步所有等待同步的 Pod
// - housekeepingCh: 触发 Pod 的清理
// - 健康管理器：同步失败的 Pod 或其中一个或多个容器的健康检查失败的 Pod
func (kl *Kubelet) syncLoopIteration(ctx context.Context, configCh <-chan kubetypes.PodUpdate, handler SyncHandler,
	syncCh <-chan time.Time, housekeepingCh <-chan time.Time, plegCh <-chan *pleg.PodLifecycleEvent) bool {
	select {
	case u, open := <-configCh:
		// 来自配置源的更新；将其分派给正确的处理程序回调函数。
		if !open {
			klog.ErrorS(nil, "Update channel is closed, exiting the sync loop")
			return false
		}

		switch u.Op {
		case kubetypes.ADD:
			klog.V(2).InfoS("SyncLoop ADD", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			// 在重启后，kubelet 会通过 ADD 获取所有现有的 Pod，就好像它们是新的 Pod。
			// 然后这些 Pod 将经过准入过程，并且 *可能* 被拒绝。这可以通过引入检查点解决。
			handler.HandlePodAdditions(u.Pods)
		case kubetypes.UPDATE:
			klog.V(2).InfoS("SyncLoop UPDATE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			handler.HandlePodUpdates(u.Pods)
		case kubetypes.REMOVE:
			klog.V(2).InfoS("SyncLoop REMOVE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			handler.HandlePodRemoves(u.Pods)
		case kubetypes.RECONCILE:
			klog.V(4).InfoS("SyncLoop RECONCILE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			handler.HandlePodReconcile(u.Pods)
		case kubetypes.DELETE:
			klog.V(2).InfoS("SyncLoop DELETE", "source", u.Source, "pods", klog.KObjSlice(u.Pods))
			// 由于优雅删除，DELETE 被视为 UPDATE。
			handler.HandlePodUpdates(u.Pods)
		case kubetypes.SET:
			// TODO: 我们是否要支持这个？
			klog.ErrorS(nil, "Kubelet does not support snapshot update")
		default:
			klog.ErrorS(nil, "Invalid operation type received", "operation", u.Op)
		}

		kl.sourcesReady.AddSource(u.Source)

	case e := <-plegCh:
		if isSyncPodWorthy(e) {
			// Pod 的 PLEG 事件；进行同步。
			if pod, ok := kl.podManager.GetPodByUID(e.ID); ok {
				klog.V(2).InfoS("SyncLoop (PLEG): event for pod", "pod", klog.KObj(pod), "event", e)
				handler.HandlePodSyncs([]*v1.Pod{pod})
			} else {
				// 如果 Pod 不再存在，则忽略该事件。
				klog.V(4).InfoS("SyncLoop (PLEG): pod does not exist, ignore irrelevant event", "event", e)
			}
		}

		if e.Type == pleg.ContainerDied {
			if containerID, ok := e.Data.(string); ok {
				kl.cleanUpContainersInPod(e.ID, containerID)
			}
		}
	case <-syncCh:
		// 同步等待同步的 Pod
		podsToSync := kl.getPodsToSync()
		if len(podsToSync) == 0 {
			break
		}
		klog.V(4).InfoS("SyncLoop (SYNC) pods", "total", len(podsToSync), "pods", klog.KObjSlice(podsToSync))
		handler.HandlePodSyncs(podsToSync)
	case update := <-kl.livenessManager.Updates():
		if update.Result == proberesults.Failure {
			handleProbeSync(kl, update, handler, "liveness", "unhealthy")
		}
	case update := <-kl.readinessManager.Updates():
		ready := update.Result == proberesults.Success
		kl.statusManager.SetContainerReadiness(update.PodUID, update.ContainerID, ready)

		status := ""
		if ready {
			status = "ready"
		}
		handleProbeSync(kl, update, handler, "readiness", status)
	case update := <-kl.startupManager.Updates():
		started := update.Result == proberesults.Success
		kl.statusManager.SetContainerStartup(update.PodUID, update.ContainerID, started)

		status := "unhealthy"
		if started {
			status = "started"
		}
		handleProbeSync(kl, update, handler, "startup", status)
	case <-housekeepingCh:
		if !kl.sourcesReady.AllReady() {
			// 如果源未准备好或卷管理器尚未同步状态，跳过清理，因为可能会意外删除来自未准备好的源的 Pod。
			klog.V(4).InfoS("SyncLoop (housekeeping, skipped): sources aren't ready yet")
		} else {
			start := time.Now()
			klog.V(4).InfoS("SyncLoop (housekeeping)")
			if err := handler.HandlePodCleanups(ctx); err != nil {
				klog.ErrorS(err, "Failed cleaning pods")
			}
			duration := time.Since(start)
			if duration > housekeepingWarningDuration {
				klog.ErrorS(fmt.Errorf("housekeeping took too long"), "Housekeeping took longer than expected", "expected", housekeepingWarningDuration, "actual", duration.Round(time.Millisecond))
			}
			klog.V(4).InfoS("SyncLoop (housekeeping) end", "duration", duration.Round(time.Millisecond))
		}
	}
	return true
}
```

#### isSyncPodWorthy

```GO
// isSyncPodWorthy 过滤掉不值得进行 pod 同步的事件
func isSyncPodWorthy(event *pleg.PodLifecycleEvent) bool {
	// ContainerRemoved 不影响 pod 的状态
	return event.Type != pleg.ContainerRemoved
}
```

#### cleanUpContainersInPod

```GO
// cleanUpContainersInPod 清理 pod 中符合条件的已退出容器实例。根据配置的不同，最新的已退出容器可能会被保留。
func (kl *Kubelet) cleanUpContainersInPod(podID types.UID, exitedContainerID string) {
	if podStatus, err := kl.podCache.Get(podID); err == nil {
		// 当已驱逐或已删除的 pod 已经同步完成时，可以删除所有容器。
		removeAll := kl.podWorkers.ShouldPodContentBeRemoved(podID)
		kl.containerDeletor.deleteContainersInPod(exitedContainerID, podStatus, removeAll)
	}
}
```

#### getPodsToSync

```GO
// 获取需要重新同步的Pod。目前，应该重新同步以下类型的Pod：
// - 工作准备就绪的Pod。
// - 内部模块请求同步的Pod。
//
// 该方法不返回孤立的Pod（仅在Pod工作节点中已知，可能已从配置中删除）。这些Pod会作为驱动状态机完成的结果由HandlePodCleanups进行同步。
//
// TODO：考虑同步所有最近未被操作的Pod，以防止可能阻止更新传递的错误（例如以前的孤立Pod错误）。不是询问工作队列是否有待处理的工作，而是询问PodWorker哪些Pod应该进行同步。
func (kl *Kubelet) getPodsToSync() []*v1.Pod {
    allPods := kl.podManager.GetPods() // 获取所有的Pod
    podUIDs := kl.workQueue.GetWork() // 获取工作队列中的Pod UID
    podUIDSet := sets.NewString() // 创建一个字符串集合，用于存储Pod UID
    for _, podUID := range podUIDs {
    	podUIDSet.Insert(string(podUID)) // 将Pod UID添加到集合中
    }
    var podsToSync []*v1.Pod // 存储需要同步的Pod
    for _, pod := range allPods {
        if podUIDSet.Has(string(pod.UID)) { // 如果Pod的UID在集合中
            // Pod的工作准备就绪
            podsToSync = append(podsToSync, pod) // 将Pod添加到需要同步的列表中
            continue
        }
        for _, podSyncLoopHandler := range kl.PodSyncLoopHandlers {
            if podSyncLoopHandler.ShouldSync(pod) { // 如果Pod需要同步
                podsToSync = append(podsToSync, pod) // 将Pod添加到需要同步的列表中
                break
            }
		}
	}
return podsToSync // 返回需要同步的Pod列表
}
```

#### handleProbeSync

```GO
func handleProbeSync(kl *Kubelet, update proberesults.Update, handler SyncHandler, probe, status string) {
    // 我们不应使用管理器中的Pod，因为在初始化后它永远不会更新。
    pod, ok := kl.podManager.GetPodByUID(update.PodUID) // 根据Pod UID从管理器中获取Pod
    if !ok {
        // 如果Pod不再存在，则忽略该更新。
        klog.V(4).InfoS("SyncLoop (probe): ignore irrelevant update", "probe", probe, "status", status, "update", update)
        return
    }
    klog.V(1).InfoS("SyncLoop (probe)", "probe", probe, "status", status, "pod", klog.KObj(pod))
    handler.HandlePodSyncs([]*v1.Pod{pod}) // 处理Pod的同步操作
}
```

## SyncHandler

```GO
// SyncHandler 是由 Kubelet 实现的接口，用于可测试性
type SyncHandler interface {
    HandlePodAdditions(pods []*v1.Pod)
    HandlePodUpdates(pods []*v1.Pod)
    HandlePodRemoves(pods []*v1.Pod)
    HandlePodReconcile(pods []*v1.Pod)
    HandlePodSyncs(pods []*v1.Pod)
    HandlePodCleanups(ctx context.Context) error
}
```

### HandlePodAdditions

```GO
// HandlePodAdditions 是 SyncHandler 中用于处理从配置源添加的 Pod 的回调函数。
func (kl *Kubelet) HandlePodAdditions(pods []*v1.Pod) {
    start := kl.clock.Now()
    sort.Sort(sliceutils.PodsByCreationTime(pods))
    if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
        kl.podResizeMutex.Lock()
        defer kl.podResizeMutex.Unlock()
    }
    for _, pod := range pods {
        existingPods := kl.podManager.GetPods()
        // 总是将 Pod 添加到 Pod Manager 中。Kubelet 依赖于 Pod Manager 作为期望状态的真实来源。
        // 如果一个 Pod 在 Pod Manager 中不存在，意味着它已经在 API 服务器中被删除，并且不需要采取任何操作（除了清理）。
        kl.podManager.AddPod(pod)
        pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod)
        if wasMirror {
            if pod == nil {
                klog.V(2).InfoS("Unable to find pod for mirror pod, skipping", "mirrorPod", klog.KObj(mirrorPod), "mirrorPodUID", mirrorPod.UID)
                continue
            }
            kl.podWorkers.UpdatePod(UpdatePodOptions{
                Pod:        pod,
                MirrorPod:  mirrorPod,
                UpdateType: kubetypes.SyncPodUpdate,
                StartTime:  start,
            })
            continue
        }

        // 仅当 Pod 没有被 kubelet 的其他部分请求终止时，才进行准入过程。
        // 如果 Pod 已经在使用资源（之前已经准入），则 Pod Worker 将会关闭它。
        // 如果 Pod 还没有启动，我们知道当调用 Pod Worker 时，它也会避免设置 Pod，所以我们简单地避免做任何工作。
        if !kl.podWorkers.IsPodTerminationRequested(pod.UID) {
            // 我们拒绝了被拒绝的 Pod，因此 activePods 包括所有已准入且仍在运行的 Pod。
            activePods := kl.filterOutInactivePods(existingPods)

            if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
                // 使用从检查点存储中获取的 AllocatedResources 值（用于 CPU 和内存）来测试 Pod 的准入性。
                // 如果找到，那就是真实的来源。
                podCopy := pod.DeepCopy()
                for _, c := range podCopy.Spec.Containers {
                    allocatedResources, found := kl.statusManager.GetContainerResourceAllocation(string(pod.UID), c.Name)
                    if c.Resources.Requests != nil && found {
                        c.Resources.Requests[v1.ResourceCPU] = allocatedResources[v1.ResourceCPU]
                        c.Resources.Requests[v1.ResourceMemory] = allocatedResources[v1.ResourceMemory]
                    }
                }
                // 检查是否可以准入该 Pod；如果不行，则拒绝它。
                if ok, reason, message := kl.canAdmitPod(activePods, podCopy); !ok {
                    kl.rejectPod(pod, reason, message)
                    continue
                }
                // 对于新的 Pod，在准入 Pod 时，检查点当前的资源值。
                if err := kl.statusManager.SetPodAllocation(podCopy); err != nil {
                    // TODO: 能否以某种方式恢复？需要调查
                    klog.ErrorS(err, "SetPodAllocation failed", "pod", klog.KObj(pod))
                }
            } else {
                // 检查是否可以准入该 Pod；如果不行，则拒绝它。
                if ok, reason, message := kl.canAdmitPod(activePods, pod); !ok {
                    kl.rejectPod(pod, reason, message)
                    continue
                }
            }
        }
        kl.podWorkers.UpdatePod(UpdatePodOptions{
            Pod:        pod,
            MirrorPod:  mirrorPod,
            UpdateType: kubetypes.SyncPodCreate,
            StartTime:  start,
        })
    }
}
```

#### filterOutInactivePods

```GO
// filterOutInactivePods 返回不处于终止阶段或已知已完全终止的 Pod。此方法应仅在要过滤的 Pod 集合位于 Pod Worker 上游时使用，即 Pod Manager 知道的 Pod 集合。
func (kl *Kubelet) filterOutInactivePods(pods []*v1.Pod) []*v1.Pod {
    filteredPods := make([]*v1.Pod, 0, len(pods))
    for _, p := range pods {
        // 如果通过 UID 完全终止了 Pod，则应将其排除在 Pod 列表之外。
        if kl.podWorkers.IsPodKnownTerminated(p.UID) {
            continue
        }

        // 终止阶段的 Pod 被视为非活动状态，除非它们正在主动终止。
        if kl.isAdmittedPodTerminal(p) && !kl.podWorkers.IsPodTerminationRequested(p.UID) {
            continue
        }

        filteredPods = append(filteredPods, p)
    }
    return filteredPods
}
```

#### canAdmitPod

```GO
// canAdmitPod 确定是否可以准入 Pod，并在无法准入时提供原因。
// "pod" 是新的 Pod，而 "pods" 是所有已准入的 Pod。
// 该函数返回一个布尔值，指示是否可以准入 Pod，以及一个简短的单词原因和解释为什么无法准入 Pod 的消息。
func (kl *Kubelet) canAdmitPod(pods []*v1.Pod, pod *v1.Pod) (bool, string, string) {
	// kubelet 将依次调用每个 Pod 准入处理程序
	// 如果任何处理程序拒绝，则拒绝该 Pod。
	// TODO: 将磁盘检查移出并作为一个 Pod 准入器
	// TODO: 资源不足驱逐应该有一个 Pod 准入器的调用
	attrs := &lifecycle.PodAdmitAttributes{Pod: pod, OtherPods: pods}
	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		// 使用检查点存储中的分配资源值（真实来源）来确定是否适合
		otherPods := make([]*v1.Pod, 0, len(pods))
		for _, p := range pods {
			op := p.DeepCopy()
			for _, c := range op.Spec.Containers {
				allocatedResources, found := kl.statusManager.GetContainerResourceAllocation(string(p.UID), c.Name)
				if c.Resources.Requests != nil && found {
					c.Resources.Requests[v1.ResourceCPU] = allocatedResources[v1.ResourceCPU]
					c.Resources.Requests[v1.ResourceMemory] = allocatedResources[v1.ResourceMemory]
				}
			}
			otherPods = append(otherPods, op)
		}
		attrs.OtherPods = otherPods
	}
	for _, podAdmitHandler := range kl.admitHandlers {
		if result := podAdmitHandler.Admit(attrs); !result.Admit {
			return false, result.Reason, result.Message
		}
	}

	return true, "", ""
}
```

### HandlePodUpdates

```GO
// HandlePodUpdates 是 SyncHandler 接口中处理从配置源更新的 Pod 的回调函数。
func (kl *Kubelet) HandlePodUpdates(pods []*v1.Pod) {
	start := kl.clock.Now()    // 获取当前时间
	for _, pod := range pods { // 遍历 pods 列表
		kl.podManager.UpdatePod(pod) // 更新 Pod 管理器中的 Pod

		pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod) // 获取 Pod 及其镜像 Pod
		if wasMirror {                                                     // 如果是镜像 Pod
			if pod == nil {
				klog.V(2).InfoS("Unable to find pod for mirror pod, skipping", "mirrorPod", klog.KObj(mirrorPod), "mirrorPodUID", mirrorPod.UID)
				continue // 如果找不到对应的 Pod，则跳过
			}
		}

		kl.podWorkers.UpdatePod(UpdatePodOptions{
			Pod:        pod,
			MirrorPod:  mirrorPod,
			UpdateType: kubetypes.SyncPodUpdate,
			StartTime:  start,
		}) // 更新 Pod Workers 中的 Pod
	}
}
```

### HandlePodRemoves

```GO
// HandlePodRemoves 是 SyncHandler 接口中处理从配置源删除的 Pod 的回调函数。
func (kl *Kubelet) HandlePodRemoves(pods []*v1.Pod) {
	start := kl.clock.Now()    // 获取当前时间
	for _, pod := range pods { // 遍历 pods 列表
		kl.podManager.RemovePod(pod) // 从 Pod 管理器中删除 Pod

		pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod) // 获取 Pod 及其镜像 Pod
		if wasMirror {                                                     // 如果是镜像 Pod
			if pod == nil {
				klog.V(2).InfoS("Unable to find pod for mirror pod, skipping", "mirrorPod", klog.KObj(mirrorPod), "mirrorPodUID", mirrorPod.UID)
				continue // 如果找不到对应的 Pod，则跳过
			}
			kl.podWorkers.UpdatePod(UpdatePodOptions{
				Pod:        pod,
				MirrorPod:  mirrorPod,
				UpdateType: kubetypes.SyncPodUpdate,
				StartTime:  start,
			}) // 更新 Pod Workers 中的 Pod
			continue
		}

		// 允许删除失败，因为周期性的清理例程会触发再次删除。
		if err := kl.deletePod(pod); err != nil {
			klog.V(2).InfoS("Failed to delete pod", "pod", klog.KObj(pod), "err", err)
		}
	}
}
```

#### deletePod

```GO
// deletePod 从 kubelet 的内部状态中删除 Pod：
// 1. 异步停止关联的 pod worker
// 2. 通过在 podKillingCh 通道上发送信号来标记杀死该 pod
//
// 如果所有源都准备就绪或未在运行时缓存中找到 Pod，则 deletePod 返回错误。
func (kl *Kubelet) deletePod(pod *v1.Pod) error {
	if pod == nil {
		return fmt.Errorf("deletePod does not allow nil pod")
	}
	if !kl.sourcesReady.AllReady() {
		// 如果源未准备就绪，则跳过删除，因为我们可能会意外删除尚未报告的源的 Pod。
		return fmt.Errorf("skipping delete because sources aren't ready yet")
	}
	klog.V(3).InfoS("Pod has been deleted and must be killed", "pod", klog.KObj(pod), "podUID", pod.UID)
	kl.podWorkers.UpdatePod(UpdatePodOptions{
		Pod:        pod,
		UpdateType: kubetypes.SyncPodKill,
	})
	// 将卷/目录清理留给周期性清理例程处理。
	return nil
}
```

### HandlePodReconcile

```GO
// HandlePodReconcile 是 SyncHandler 接口中处理需要进行调和的 Pod 的回调函数。
// 当仅更新 Pod 的状态时，Pod 将被调和。
func (kl *Kubelet) HandlePodReconcile(pods []*v1.Pod) {
	start := kl.clock.Now()    // 获取当前时间
	for _, pod := range pods { // 遍历 pods 列表
		// 在 pod 管理器中更新 pod，状态管理器将根据 pod 管理器定期进行调和。
		kl.podManager.UpdatePod(pod)

		pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod) // 获取 Pod 及其镜像 Pod
		if wasMirror {                                                     // 如果是镜像 Pod
			if pod == nil {
				klog.V(2).InfoS("Unable to find pod for mirror pod, skipping", "mirrorPod", klog.KObj(mirrorPod), "mirrorPodUID", mirrorPod.UID)
				continue // 如果找不到对应的 Pod，则跳过
			}
			// 静态 Pod 应以与普通 Pod 相同的方式进行调和
		}

		// TODO: 计算配置管理器中的调和是否可疑，并且避免额外的同步可能不再必要。在解决下面两个 TODO 后，重新评估是否可以合并 Reconcile 和 Sync。

		// 如果需要调和 Pod 的 "Ready" 条件，则触发同步 Pod 进行调和。
		// TODO: 现在应该不再需要这样做-确定造成这个与 Sync 不同的原因是什么，或者是否有更好的位置放置它。例如，我们在 kubelet/config、这里和 status_manager 中都有 needsReconcile。
		if status.NeedToReconcilePodReadiness(pod) {
			kl.podWorkers.UpdatePod(UpdatePodOptions{
				Pod:        pod,
				MirrorPod:  mirrorPod,
				UpdateType: kubetypes.SyncPodSync,
				StartTime:  start,
			})
		}

		// 在同步被驱逐的 Pod 后，可以删除该 Pod 中的所有已停止容器。
		// TODO: 这是可疑的-状态读取是异步的，并且在驱逐过程中我们已经预计没有某些容器信息。Pod Worker 知道一个 Pod 是否已被驱逐，因此如果这是为了最小化对驱逐的反应时间，我们可以做得更好。如果这是为了保留 Pod 状态信息，我们也可以做得更好。
		if eviction.PodIsEvicted(pod.Status) {
			if podStatus, err := kl.podCache.Get(pod.UID); err == nil {
				kl.containerDeletor.deleteContainersInPod("", podStatus, true)
			}
		}
	}
}
```

### HandlePodSyncs

```GO
// HandlePodSyncs 是 syncHandler 接口中处理需要调度给 pod workers 进行同步的 Pod 的回调函数。
func (kl *Kubelet) HandlePodSyncs(pods []*v1.Pod) {
	start := kl.clock.Now()    // 获取当前时间
	for _, pod := range pods { // 遍历 pods 列表
		pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(pod) // 获取 Pod 及其镜像 Pod
		if wasMirror {                                                     // 如果是镜像 Pod
			if pod == nil {
				klog.V(2).InfoS("Unable to find pod for mirror pod, skipping", "mirrorPod", klog.KObj(mirrorPod), "mirrorPodUID", mirrorPod.UID)
				continue // 如果找不到对应的 Pod，则跳过
			}
			// 同步镜像 Pod 是程序员错误，因为同步的意图是批量通知所有待处理的工作。我们应该防止重复同步，但现在记录一个程序员错误以防止意外引入。
			klog.V(3).InfoS("Programmer error, HandlePodSyncs does not expect to receive mirror pods", "podUID", pod.UID, "mirrorPodUID", mirrorPod.UID)
			continue
		}
		kl.podWorkers.UpdatePod(UpdatePodOptions{
			Pod:        pod,
			MirrorPod:  mirrorPod,
			UpdateType: kubetypes.SyncPodSync,
			StartTime:  start,
		})
	}
}
```

### HandlePodCleanups

```GO
// HandlePodCleanups 执行一系列清理工作，包括终止
// pod workers、杀死不需要的 pods，并删除孤立的卷/ pod
// 目录。在执行此方法时，不会向 pod workers 发送配置更
// 改，这意味着不会出现新的 pods。此方法完成后，kubelet
// 的期望状态应与 pod worker 和其他与 pod 相关的组件中的
// 实际状态进行调和。
//
// 此函数由主同步循环执行，因此必须快速执行，并且所有嵌套
// 调用都应该是异步的。任何慢速的调和操作都应该由其他组件
// （如卷管理器）执行。如果使用了固定 UID 更新了静态 pods，
// 并且在运行此方法时不传递配置更新给 pod workers，则此调
// 用的持续时间是重新启动静态 pods 的最小延迟时间（大多数
// 静态 pods 应该使用动态 UID）。
func (kl *Kubelet) HandlePodCleanups(ctx context.Context) error {
    // kubelet 缺乏检查点功能，因此我们需要先检查 cgroup
    // 树中的 pods 集合，然后检查 pod 管理器中的 pods 集合。
    // 这样可以确保我们观察的 cgroup 树视图不会错误地观察到
    // 事后添加的 pods...
    var (
        cgroupPods map[types.UID]cm.CgroupName
        err error
    )
    if kl.cgroupsPerQOS {
        pcm := kl.containerManager.NewPodContainerManager()
        cgroupPods, err = pcm.GetAllPodsFromCgroups()
        if err != nil {
            return fmt.Errorf("failed to get list of pods that still exist on cgroup mounts: %v", err)
        }
    }
    // 获取所有 pods、镜像 pods 和孤立的镜像 pod 的列表
    allPods, mirrorPods, orphanedMirrorPodFullnames := kl.podManager.GetPodsAndMirrorPods()

    // Pod 的阶段是单调递增的。一旦一个 pod 达到最终状态，
    // 不论重启策略如何，它都不应该离开该状态。这些 pod 的
    // 状态不应该更改，也不需要同步它们。
    // TODO: 此处的逻辑未处理两种情况：
    //   1. 如果容器在死亡后立即被删除，kubelet 可能无法生成
    //      正确的状态，更不用说正确过滤了。
    //   2. 如果 kubelet 在将终止状态写入 api server 之前重启，
    //      它可能仍然重新启动终止的 pod（即使 api server 认
    //      为该 pod 尚未终止）。
    // 可以通过设置检查点来缓解这两种情况。
    
	// 停止未在配置源中的已终止的 pods 的 workers
	klog.V(3).InfoS("Clean up pod workers for terminated pods")
	workingPods := kl.podWorkers.SyncKnownPods(allPods)

	// 协调：此时，pod workers 的范围已经被修剪为所需的 pods 集合。
	// 由于 UID 重用而必须重新启动的 pods，以及来自上次运行的剩余 pods，都不为 pod worker 所知。
	
    // 通过 UID 将所有 pods 组织成映射，以便于后续使用
	allPodsByUID := make(map[types.UID]*v1.Pod)
	for _, pod := range allPods {
		allPodsByUID[pod.UID] = pod
	}

	// 确定具有 workers 的 pods 集合，这应该是配置中未终止的所有 pods，
    // 以及已从配置中删除的任何正在终止的 pods。正在终止的 pods 将被添加到
    // possiblyRunningPods 中，以防止过度清理 pod cgroups。
	stringIfTrue := func(t bool) string {
		if t {
			return "true"
		}
		return ""
	}
	runningPods := make(map[types.UID]sets.Empty)
	possiblyRunningPods := make(map[types.UID]sets.Empty)
	for uid, sync := range workingPods {
		switch sync.State {
		case SyncPod:
			runningPods[uid] = struct{}{}
			possiblyRunningPods[uid] = struct{}{}
		case TerminatingPod:
			possiblyRunningPods[uid] = struct{}{}
		default:
		}
	}

	// 从运行时获取正在运行的容器列表，以执行清理操作。
	// 我们需要最新的状态以避免延迟重新启动重用 UID 的静态 pods。
	if err := kl.runtimeCache.ForceUpdateIfOlder(ctx, kl.clock.Now()); err != nil {
		klog.ErrorS(err, "Error listing containers")
		return err
	}
	runningRuntimePods, err := kl.runtimeCache.GetPods(ctx)
	if err != nil {
		klog.ErrorS(err, "Error listing containers")
		return err
	}

	// 停止探测非运行的 pods
	klog.V(3).InfoS("Clean up probes for terminated pods")
	kl.probeManager.CleanupPods(possiblyRunningPods)

	// 移除在已知的配置 pods 列表中不存在的孤立 pod 状态
	klog.V(3).InfoS("Clean up orphaned pod statuses")
	kl.removeOrphanedPodStatuses(allPods, mirrorPods)

	// 移除孤立的 pod 用户命名空间分配（如果有的话）。
	klog.V(3).InfoS("Clean up orphaned pod user namespace allocations")
	if err = kl.usernsManager.CleanupOrphanedPodUsernsAllocations(allPods, runningRuntimePods); err != nil {
		klog.ErrorS(err, "Failed cleaning up orphaned pod user namespaces allocations")
	}

	// 从已知没有任何容器的 pods 中移除孤立的卷。
    // 注意，我们将所有 pods（包括已终止的 pods）传递给函数，
    // 这样我们就不会删除与已终止但尚未删除的 pods 相关联的卷。
    // TODO：将来，这个方法可以更积极地清理已终止的 pods
    // （卷、挂载目录、日志和容器可以更好地分离）
	klog.V(3).InfoS("Clean up orphaned pod directories")
	err = kl.cleanupOrphanedPodDirs(allPods, runningRuntimePods)
	if err != nil {
		// 我们希望所有清理任务都能执行，即使其中一个失败。
        // 因此，在这里只记录错误，并继续其他清理任务。
        // 这也适用于其他清理任务。
		klog.ErrorS(err, "Failed cleaning up orphaned pod directories")
	}

	// 移除任何孤立的镜像 pods（通过全名跟踪镜像 pods）
	klog.V(3).InfoS("Clean up orphaned mirror pods")
	for _, podFullname := range orphanedMirrorPodFullnames {
		if !kl.podWorkers.IsPodForMirrorPodTerminatingByFullName(podFullname) {
			_, err := kl.mirrorPodClient.DeleteMirrorPod(podFullname, nil)
			if err != nil {
				klog.ErrorS(err, "Encountered error when deleting mirror pod", "podName", podFullname)
			} else {
				klog.V(3).InfoS("Deleted mirror pod", "podName", podFullname)
			}
		}
	}

	// 在修剪已终止的 pods 的 workers 之后，获取用于指标和确定重启的活动 pods 列表。
	activePods := kl.filterOutInactivePods(allPods)
	allRegularPods, allStaticPods := splitPodsByStatic(allPods)
	activeRegularPods, activeStaticPods := splitPodsByStatic(activePods)
	metrics.DesiredPodCount.WithLabelValues("").Set(float64(len(allRegularPods)))
	metrics.DesiredPodCount.WithLabelValues("true").Set(float64(len(allStaticPods)))
	metrics.ActivePodCount.WithLabelValues("").Set(float64(len(activeRegularPods)))
	metrics.ActivePodCount.WithLabelValues("true").Set(float64(len(activeStaticPods)))
	metrics.MirrorPodCount.Set(float64(len(mirrorPods)))

	// 在此时，pod worker 知道哪些 pods 不是所需的（SyncKnownPods）。
    // 我们现在查看活动 pods 集合中 pod worker 不知道的 pods，并进行更新。
    // pod worker 不知道一个 pod 的最常见原因是，当 pod worker 在驱动其生命周期时，
    // 该 pod 被删除并以相同的 UID 重新创建（对于 API pods 非常非常罕见，对于具有固定 UID 的静态 pods 很常见）。
    // 从以前的执行中可能仍在运行的容器必须由 pod worker 的同步方法进行调和。
    // 我们必须使用 active pods，因为那是已接受的 pods 集合（podManager 包括永远不会运行的 pods，
    // 而 statusManager 跟踪已拒绝的 pods）。
	var restartCount, restartCountStatic int
	for _, desiredPod := range activePods {
		if _, knownPod := workingPods[desiredPod.UID]; knownPod {
			continue
		}

		klog.V(3).InfoS("Pod will be restarted because it is in the desired set and not known to the pod workers (likely due to UID reuse)", "podUID", desiredPod.UID)
		isStatic := kubetypes.IsStaticPod(desiredPod)
		pod, mirrorPod, wasMirror := kl.podManager.GetPodAndMirrorPod(desiredPod)
		if pod == nil || wasMirror {
			klog.V(2).InfoS("Programmer error, restartable pod was a mirror pod but activePods should never contain a mirror pod", "podUID", desiredPod.UID)
			continue
		}
		kl.podWorkers.UpdatePod(UpdatePodOptions{
			UpdateType: kubetypes.SyncPodCreate,
			Pod:        pod,
			MirrorPod:  mirrorPod,
		})

		// 现在也知道所需的 pod
		workingPods[desiredPod.UID] = PodWorkerSync{State: SyncPod, HasConfig: true, Static: isStatic}
		if isStatic {
			// 可重新启动的静态 pods 是正常情况
			restartCountStatic++
		} else {
			// 几乎肯定是有问题的，因为 API pods 在被删除和重新创建后不应该有相同的 UID
			//，除非存在重大的 API 违规行为
			restartCount++
		}
	}
	metrics.RestartedPodTotal.WithLabelValues("true").Add(float64(restartCountStatic))
	metrics.RestartedPodTotal.WithLabelValues("").Add(float64(restartCount))

	// 最后，终止运行时中观察到但不在已知的来自配置的运行中 pods 列表中的任何 pods。
	// 如果我们终止正在运行的运行时 pods，那将在后台异步进行处理，并在下一次 
	var orphanCount int
	for _, runningPod := range runningRuntimePods {
		// 如果在 CRI 中有未知于 pod worker 的孤立 pod 资源，则立即终止它们。
        // 由于 housekeeping 是独占其他 pod worker 更新的，我们知道在此期间没有添加到 pod worker 的 pod。
        // 需要注意的是，不可见于 runtime 但之前已知的 pod 会被 SyncKnownPods() 终止。
		_, knownPod := workingPods[runningPod.ID]
		if !knownPod {
			one := int64(1)
			killPodOptions := &KillPodOptions{
				PodTerminationGracePeriodSecondsOverride: &one,
			}
			klog.V(2).InfoS("Clean up containers for orphaned pod we had not seen before", "podUID", runningPod.ID, "killPodOptions", killPodOptions)
			kl.podWorkers.UpdatePod(UpdatePodOptions{
				UpdateType:     kubetypes.SyncPodKill,
				RunningPod:     runningPod,
				KillPodOptions: killPodOptions,
			})

			// 现在已知该正在运行的 pod
			workingPods[runningPod.ID] = PodWorkerSync{State: TerminatingPod, Orphan: true}
			orphanCount++
		}
	}
	metrics.OrphanedRuntimePodTotal.Add(float64(orphanCount))

	// 现在我们记录了任何正在终止的 pod，并添加了应该运行的新 pod，这里记录一个摘要。
	// 并非所有可能的 PodWorkerSync 值都是有效的。
	counts := make(map[PodWorkerSync]int)
	for _, sync := range workingPods {
		counts[sync]++
	}
	for validSync, configState := range map[PodWorkerSync]string{
		{HasConfig: true, Static: true}:                "desired",
		{HasConfig: true, Static: false}:               "desired",
		{Orphan: true, HasConfig: true, Static: true}:  "orphan",
		{Orphan: true, HasConfig: true, Static: false}: "orphan",
		{Orphan: true, HasConfig: false}:               "runtime_only",
	} {
		for _, state := range []PodWorkerState{SyncPod, TerminatingPod, TerminatedPod} {
			validSync.State = state
			count := counts[validSync]
			delete(counts, validSync)
			staticString := stringIfTrue(validSync.Static)
			if !validSync.HasConfig {
				staticString = "unknown"
			}
			metrics.WorkingPodCount.WithLabelValues(state.String(), configState, staticString).Set(float64(count))
		}
	}
	if len(counts) > 0 {
		// 如果有组合丢失
		klog.V(3).InfoS("Programmer error, did not report a kubelet_working_pods metric for a value returned by SyncKnownPods", "counts", counts)
	}

	// 删除一些绝对不再运行的 pod 的层次结构中的任何 cgroups（不在容器运行时中）。
	if kl.cgroupsPerQOS {
		pcm := kl.containerManager.NewPodContainerManager()
		klog.V(3).InfoS("Clean up orphaned pod cgroups")
		kl.cleanupOrphanedPodCgroups(pcm, cgroupPods, possiblyRunningPods)
	}

	// 清理任何回退项。
	kl.backOff.GC()
	return nil
}
```

#### removeOrphanedPodStatuses

```GO
// removeOrphanedPodStatuses函数用于移除podStatus中已不再被认为绑定到此节点的过时条目。
func (kl *Kubelet) removeOrphanedPodStatuses(pods []*v1.Pod, mirrorPods []*v1.Pod) {
	podUIDs := make(map[types.UID]bool)
	for _, pod := range pods {
		podUIDs[pod.UID] = true
	}
	for _, pod := range mirrorPods {
		podUIDs[pod.UID] = true
	}
	kl.statusManager.RemoveOrphanedStatuses(podUIDs)
}
```

#### cleanupOrphanedPodDirs

```GO
// cleanupOrphanedPodDirs函数用于清理不应运行且没有容器运行的pod的卷。注意，这里会进行日志滚动，因为它在主循环中运行。
func (kl *Kubelet) cleanupOrphanedPodDirs(pods []*v1.Pod, runningPods []*kubecontainer.Pod) error {
	allPods := sets.NewString()
	for _, pod := range pods {
		allPods.Insert(string(pod.UID))
	}
	for _, pod := range runningPods {
		allPods.Insert(string(pod.ID))
	}

	found, err := kl.listPodsFromDisk()
	if err != nil {
		return err
	}

	orphanRemovalErrors := []error{}
	orphanVolumeErrors := []error{}
	var totalPods, errorPods int

	for _, uid := range found {
		if allPods.Has(string(uid)) {
			continue
		}

		totalPods++

		// 如果卷没有被卸载/分离，不要删除目录。
		// 这样做可能会导致数据损坏。
		// TODO: getMountedVolumePathListFromDisk()的调用可能与kl.getPodVolumePathListFromDisk()多余。可以清理吗？
		if podVolumesExist := kl.podVolumesExist(uid); podVolumesExist {
			errorPods++
			klog.V(3).InfoS("找到孤立的pod，但卷未清理", "podUID", uid)
			continue
		}

		// 尝试删除pod的卷目录及其子目录
		podVolumeErrors := kl.removeOrphanedPodVolumeDirs(uid)
		if len(podVolumeErrors) > 0 {
			errorPods++
			orphanVolumeErrors = append(orphanVolumeErrors, podVolumeErrors...)
			// 如果没有删除所有卷，不要立即清理pod目录。很可能还有挂载点或文件未清理，这可能导致在下面删除pod目录时失败。
			// 所有删除操作的错误已记录，因此不需要在此处添加另一个错误。
			continue
		}

		// 调用RemoveAllOneFilesystem删除pod目录下的剩余子目录
		podDir := kl.getPodDir(uid)
		podSubdirs, err := os.ReadDir(podDir)
		if err != nil {
			errorPods++
			klog.ErrorS(err, "无法读取目录", "path", podDir)
			orphanRemovalErrors = append(orphanRemovalErrors, fmt.Errorf("找到孤立的pod %q，但在从磁盘读取pod目录时发生错误：%v", uid, err))
			continue
		}

		var cleanupFailed bool
		for _, podSubdir := range podSubdirs {
			podSubdirName := podSubdir.Name()
			podSubdirPath := filepath.Join(podDir, podSubdirName)
			// 永远不要尝试在卷目录上执行RemoveAllOneFilesystem，
			// 因为这可能会在某些情况下导致数据丢失。卷目录应该已由removeOrphanedPodVolumeDirs删除。
			if podSubdirName == "volumes" {
				cleanupFailed = true
				err := fmt.Errorf("在删除后发现卷子目录")
				klog.ErrorS(err, "找到孤立的pod，但无法删除卷子目录", "podUID", uid, "path", podSubdirPath)
				continue
			}
			if err := removeall.RemoveAllOneFilesystem(kl.mounter, podSubdirPath); err != nil {
				cleanupFailed = true
				klog.ErrorS(err, "无法删除孤立的pod子目录", "podUID", uid, "path", podSubdirPath)
				orphanRemovalErrors = append(orphanRemovalErrors, fmt.Errorf("找到孤立的pod %q，但在尝试删除子目录 %q 时发生错误：%v", uid, podSubdirPath, err))
			}
		}

		// Rmdir删除pod目录，如果上述所有操作成功，则该目录应为空
		klog.V(3).InfoS("找到孤立的pod，正在删除", "podUID", uid)
		if err := syscall.Rmdir(podDir); err != nil {
			cleanupFailed = true
			klog.ErrorS(err, "无法删除孤立的pod目录", "podUID", uid)
			orphanRemovalErrors = append(orphanRemovalErrors, fmt.Errorf("找到孤立的pod %q，但在尝试删除pod目录时发生错误：%v", uid, err))
		}
		if cleanupFailed {
			errorPods++
		}
	}

	logSpew := func(errs []error) {
		if len(errs) > 0 {
			klog.ErrorS(errs[0], "发生了许多类似的错误。提高详细程度以查看它们。", "numErrs", len(errs))
			for _, err := range errs {
				klog.V(5).InfoS("孤立的pod", "err", err)
			}
		}
	}
	logSpew(orphanVolumeErrors)
	logSpew(orphanRemovalErrors)
	metrics.OrphanPodCleanedVolumes.Set(float64(totalPods))
	metrics.OrphanPodCleanedVolumesErrors.Set(float64(errorPods))
	return utilerrors.NewAggregate(orphanRemovalErrors)
}
```

#### filterOutInactivePods

```GO
// filterOutInactivePods 返回不处于终止阶段或已知完全终止的 Pod。此方法仅应在要过滤的 Pod 集合位于 Pod Worker 上游时使用，即 Pod 管理器知道的 Pod。
func (kl *Kubelet) filterOutInactivePods(pods []*v1.Pod) []*v1.Pod {
	filteredPods := make([]*v1.Pod, 0, len(pods)) // 创建一个切片用于存储过滤后的 Pod
	for _, p := range pods {                      // 遍历 pods 列表
		// 如果通过 UID 完全终止了一个 Pod，则应将其排除在 Pod 列表之外
		if kl.podWorkers.IsPodKnownTerminated(p.UID) {
			continue // 如果 Pod 已知终止，则跳过
		}

		// 终止阶段的 Pod 被视为非活动状态，除非它们正在主动终止
		if kl.isAdmittedPodTerminal(p) && !kl.podWorkers.IsPodTerminationRequested(p.UID) {
			continue // 如果 Pod 是已批准的终止 Pod 且未请求终止，则跳过
		}

		filteredPods = append(filteredPods, p) // 将符合条件的 Pod 添加到过滤后的 Pod 列表中
	}
	return filteredPods // 返回过滤后的 Pod 列表
}
```

