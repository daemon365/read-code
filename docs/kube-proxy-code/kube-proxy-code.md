---
id: 1-kube-proxy-code 
title: kube-proxy 代码走读
description: kube-proxy 代码走读
keywords:
  - kubernetes
  - kube-proxy
slug: /
---

## 简介

kube-proxy是Kubernetes（K8s）集群中的一个核心组件之一，它运行在每个工作节点上，负责处理网络代理和负载均衡的任务。kube-proxy的主要功能是实现Kubernetes服务的网络通信和负载均衡。

下面是kube-proxy的一些主要功能和特点：

1. 服务代理：kube-proxy通过监听Kubernetes API服务器上的服务和端点资源的变化，动态地更新本地节点上的网络规则和代理配置，以确保能够将请求正确地路由到集群中的服务。它会为每个服务创建相应的iptables规则或IPVS规则，以实现流量转发和负载均衡。
2. 负载均衡：kube-proxy使用四层（TCP/UDP）负载均衡技术，将请求均匀地分发给后端服务实例。它可以根据服务的类型（ClusterIP、NodePort、LoadBalancer）以及服务选择器（Selector）来决定如何进行负载均衡。这样，客户端可以通过访问服务的虚拟IP或节点上的特定端口，来访问服务提供的功能。
3. 服务发现：kube-proxy通过监视Kubernetes API服务器上服务和端点资源的变化，自动更新本地节点上的代理配置。当服务或端点的状态发生变化时，kube-proxy会相应地更新负载均衡规则和代理配置，以确保请求能够正确地路由到可用的服务实例。
4. 代理模式：kube-proxy支持三种代理模式，包括iptables模式、IPVS模式和userspace模式。在不同的Kubernetes集群部署中，可以根据需要选择适合的代理模式。其中，iptables模式是最常用的模式，它使用iptables规则进行流量转发和负载均衡；IPVS模式使用Linux内核的IPVS（IP Virtual Server）技术提供高性能的负载均衡；userspace模式是一种较旧的模式，使用用户空间程序进行代理和负载均衡。

## main

```go
func main() {
	command := app.NewProxyCommand()
	code := cli.Run(command)
	os.Exit(code)
}

// NewProxyCommand创建一个带有默认参数的*cobra.Command对象
func NewProxyCommand() *cobra.Command {
    // 创建NewOptions实例
    opts := NewOptions()
    // 创建一个cobra.Command对象，并设置Use和Long属性
    cmd := &cobra.Command{
        Use: "kube-proxy",
            Long: `The Kubernetes network proxy runs on each node. This reflects services as defined in the Kubernetes API on each node and can do simple
        TCP, UDP, and SCTP stream forwarding or round robin TCP, UDP, and SCTP forwarding across a set of backends.
        Service cluster IPs and ports are currently found through Docker-links-compatible
        environment variables specifying ports opened by the service proxy. There is an optional
        addon that provides cluster DNS for these cluster IPs. The user must create a service
        with the apiserver API to configure the proxy.`,
        // 设置RunE属性为一个匿名函数
        RunE: func(cmd *cobra.Command, args []string) error {
            // 打印版本标志并在需要时退出
            verflag.PrintAndExitIfRequested()
            // 打印命令的标志
            cliflag.PrintFlags(cmd.Flags())
            // 根据操作系统进行初始化
            if err := initForOS(opts.WindowsService); err != nil {
                return fmt.Errorf("failed os init: %w", err)
            }

            // 完成选项的设置
            if err := opts.Complete(); err != nil {
                return fmt.Errorf("failed complete: %w", err)
            }

            // 验证选项的有效性
            if err := opts.Validate(); err != nil {
                return fmt.Errorf("failed validate: %w", err)
            }

            // 添加功能启用度量信息
            utilfeature.DefaultMutableFeatureGate.AddMetrics()

            // 运行代理服务器
            if err := opts.Run(); err != nil {
                klog.ErrorS(err, "Error running ProxyServer")
                return err
            }

            return nil
        },
        // 设置Args属性为一个匿名函数
        Args: func(cmd *cobra.Command, args []string) error {
            // 检查每个参数是否为空
            for _, arg := range args {
                if len(arg) > 0 {
                    return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
                }
            }
            return nil
        },
    }

    // 获取命令的标志集合
    fs := cmd.Flags()
    // 添加选项的标志
    opts.AddFlags(fs)
    // 添加Go标志集合（goflag.CommandLine）的标志
    fs.AddGoFlagSet(goflag.CommandLine) // for --boot-id-file and --machine-id-file

    // 将"config"标志设置为文件名类型，并支持扩展名为yaml、yml、json的文件
    _ = cmd.MarkFlagFilename("config", "yaml", "yml", "json")

    return cmd
}
```

### NewOptions

```go
// Options包含创建和运行代理服务器所需的所有内容。
type Options struct {
    // ConfigFile是代理服务器配置文件的路径。
    ConfigFile string
    // WriteConfigTo是默认配置文件将被写入的路径。
    WriteConfigTo string
    // CleanupAndExit为true时，代理服务器将清理iptables和ipvs规则，然后退出。
    CleanupAndExit bool
    // WindowsService在Windows上作为服务运行kube-proxy时应设置为true。
    // 其对应的标志只在Windows构建中注册。
    WindowsService bool
    // config是代理服务器的配置对象。
    config *kubeproxyconfig.KubeProxyConfiguration
    // watcher用于监听ConfigFile的更新更改。
    watcher filesystem.FSWatcher
    // proxyServer是运行代理服务器的接口
    proxyServer proxyRun
    // errCh是错误将被发送的通道
    errCh chan error
    // 以下字段是无法直接映射到config.KubeProxyConfiguration的标志占位符。
    //
    // TODO 移除这些字段，一旦废弃的标志被移除。

    // master用于覆盖kubeconfig的apiserver URL。
    master string
    // healthzPort是healthz服务器使用的端口。
    healthzPort int32
    // metricsPort是metrics服务器使用的端口。
    metricsPort int32

    // hostnameOverride，如果从命令行标志设置，将覆盖配置文件中的`HostnameOverride`值。
    hostnameOverride string
}

// NewOptions返回初始化的Options
func NewOptions() *Options {
    return &Options{
        config: newKubeProxyConfiguration(),
        healthzPort: ports.ProxyHealthzPort,
        metricsPort: ports.ProxyStatusPort,
        errCh: make(chan error),
    }
}
```

#### newKubeProxyConfiguration

```go
// newKubeProxyConfiguration返回具有默认值的KubeProxyConfiguration
func newKubeProxyConfiguration() *kubeproxyconfig.KubeProxyConfiguration {
    // 创建v1alpha1.KubeProxyConfiguration的实例
    versionedConfig := &v1alpha1.KubeProxyConfiguration{}
    // 使用Scheme的默认值填充versionedConfig
    proxyconfigscheme.Scheme.Default(versionedConfig)
    // 将versionedConfig转换为kubeproxyconfig.SchemeGroupVersion对应版本的对象
    internalConfig, err := proxyconfigscheme.Scheme.ConvertToVersion(versionedConfig, kubeproxyconfig.SchemeGroupVersion)
    if err != nil {
    	panic(fmt.Sprintf("Unable to create default config: %v", err))
    }
    return internalConfig.(*kubeproxyconfig.KubeProxyConfiguration)
}

// KubeProxyConfiguration包含配置Kubernetes代理服务器所需的所有内容。
type KubeProxyConfiguration struct {
	metav1.TypeMeta
    // FeatureGates是一个将功能名称映射为布尔值的映射，用于启用或禁用alpha/experimental功能。
    FeatureGates map[string]bool

    // BindAddress是代理服务器要监听的IP地址（设置为0.0.0.0表示监听所有接口）
    BindAddress string
    // HealthzBindAddress是健康检查服务器要监听的IP地址和端口，默认为0.0.0.0:10256
    HealthzBindAddress string
    // MetricsBindAddress是指标服务器要监听的IP地址和端口，默认为127.0.0.1:10249（设置为0.0.0.0表示监听所有接口）
    MetricsBindAddress string
    // BindAddressHardFail为true时，kube-proxy将无法绑定到端口视为致命错误并退出
    BindAddressHardFail bool
    // EnableProfiling启用通过/web/debug/pprof处理程序进行性能分析的功能。
    // 性能分析处理程序将由指标服务器处理。
    EnableProfiling bool
    // ClusterCIDR是集群中Pod的CIDR范围。用于处理来自集群外部的流量。如果未提供，将不执行集群外桥接。
    ClusterCIDR string
    // HostnameOverride，如果非空，将用作标识而不是实际主机名。
    HostnameOverride string
    // ClientConnection指定代理服务器在与apiserver通信时使用的kubeconfig文件和客户端连接设置。
    ClientConnection componentbaseconfig.ClientConnectionConfiguration
    // IPTables包含与iptables相关的配置选项。
    IPTables KubeProxyIPTablesConfiguration
    // IPVS包含与ipvs相关的配置选项。
    IPVS KubeProxyIPVSConfiguration
    // OOMScoreAdj是kube-proxy进程的oom-score-adj值。值必须在范围[-1000, 1000]内。
    OOMScoreAdj *int32
    // Mode指定要使用的代理模式。
    Mode ProxyMode
    // PortRange是可以用于代理服务流量的主机端口范围（包括beginPort和endPort）。如果未指定（0-0），则将随机选择端口。
    PortRange string
    // Conntrack包含与conntrack相关的配置选项。
    Conntrack KubeProxyConntrackConfiguration
    // ConfigSyncPeriod是从apiserver刷新配置的频率。必须大于0。
    ConfigSyncPeriod metav1.Duration
    // NodePortAddresses是kube-proxy进程的--nodeport-addresses值。值必须是有效的IP块。这些值作为参数选择nodeport工作的接口。
    // 如果将其设置为"127.0.0.0/8"，kube-proxy将仅选择回环接口用于NodePort。
    // 如果将其设置为非零IP块，kube-proxy将仅选择适用于节点的IP。
    // 空字符串切片表示选择所有网络接口。
    NodePortAddresses []string
    // Winkernel包含与winkernel相关的配置选项。
    Winkernel KubeProxyWinkernelConfiguration
    // ShowHiddenMetricsForVersion是您希望显示隐藏指标的版本。
    ShowHiddenMetricsForVersion string
    // DetectLocalMode确定用于检测本地流量的模式，默认为LocalModeClusterCIDR
    DetectLocalMode LocalMode
    // DetectLocal包含与DetectLocalMode相关的可选配置设置。
    DetectLocal DetectLocalConfiguration
}
```

## Run

```go
// Run运行指定的ProxyServer。
func (o *Options) Run() error {
	defer close(o.errCh)
    // 如果指定了 --write-config-to 参数，则将默认的配置文件写到指定文件并退出
    if len(o.WriteConfigTo) > 0 {
    	return o.writeConfigFile()
    }
    // 如果启动参数 --cleanup 设置为 true，则清理 iptables 和 ipvs 规则并退出
    if o.CleanupAndExit {
		return cleanupAndExit()
	}

    // 创建ProxyServer实例
    proxyServer, err := newProxyServer(o.config, o.master)
    if err != nil {
        return err
    }

    o.proxyServer = proxyServer
    return o.runLoop()
}
```

### writeConfigFile

```go
func (o *Options) writeConfigFile() (err error) {
const mediaType = runtime.ContentTypeYAML
    // 获取与媒体类型对应的序列化信息
    info, ok := runtime.SerializerInfoForMediaType(proxyconfigscheme.Codecs.SupportedMediaTypes(), mediaType)
    if !ok {
    	return fmt.Errorf("unable to locate encoder -- %q is not a supported media type", mediaType)
    }
    // 根据序列化信息创建编码器
    encoder := proxyconfigscheme.Codecs.EncoderForVersion(info.Serializer, v1alpha1.SchemeGroupVersion)

    // 创建配置文件
    configFile, err := os.Create(o.WriteConfigTo)
    if err != nil {
        return err
    }

    defer func() {
        ferr := configFile.Close()
        if ferr != nil && err == nil {
            err = ferr
        }
    }()

    // 使用编码器将配置对象编码并写入配置文件
    if err = encoder.Encode(o.config, configFile); err != nil {
        return err
    }

    klog.InfoS("Wrote configuration", "file", o.WriteConfigTo)

    return nil
}
```

### newProxyServer

```go
// newProxyServer根据给定的配置创建一个ProxyServer。
func newProxyServer(config *kubeproxyconfig.KubeProxyConfiguration, master string) (*ProxyServer, error) {
	s := &ProxyServer{Config: config}
    // 创建configz注册器并将配置对象注册到其中
    cz, err := configz.New(kubeproxyconfig.GroupName)
    if err != nil {
        return nil, fmt.Errorf("unable to register configz: %s", err)
    }
    cz.Set(config)

    if len(config.ShowHiddenMetricsForVersion) > 0 {
        // 设置显示隐藏指标
        metrics.SetShowHidden()
    }

    // 获取主机名
    s.Hostname, err = nodeutil.GetHostname(config.HostnameOverride)
    if err != nil {
        return nil, err
    }

    // 创建与API服务器的客户端连接
    s.Client, err = createClient(config.ClientConnection, master)
    if err != nil {
        return nil, err
    }

    // 检测节点IP地址
    s.NodeIP = detectNodeIP(s.Client, s.Hostname, config.BindAddress)
    klog.InfoS("Detected node IP", "address", s.NodeIP.String())

    // 创建事件广播器和事件记录器
    s.Broadcaster = events.NewBroadcaster(&events.EventSinkImpl{Interface: s.Client.EventsV1()})
    s.Recorder = s.Broadcaster.NewRecorder(proxyconfigscheme.Scheme, "kube-proxy")

    // 设置节点对象引用
    s.NodeRef = &v1.ObjectReference{
        Kind:      "Node",
        Name:      s.Hostname,
        UID:       types.UID(s.Hostname),
        Namespace: "",
    }

    if len(config.HealthzBindAddress) > 0 {
        // 创建健康检查服务器
        s.HealthzServer = healthcheck.NewProxierHealthServer(config.HealthzBindAddress, 2*config.IPTables.SyncPeriod.Duration, s.Recorder, s.NodeRef)
    }

    // 创建Proxier
    s.Proxier, err = s.createProxier(config)
    if err != nil {
        return nil, err
    }

    return s, nil
}

// ProxyServer表示启动Kubernetes代理服务器所需的所有参数。所有字段都是必需的。
type ProxyServer struct {
    Config *kubeproxyconfig.KubeProxyConfiguration
    Client clientset.Interface
    Broadcaster events.EventBroadcaster
    Recorder events.EventRecorder
    NodeRef *v1.ObjectReference
    HealthzServer healthcheck.ProxierHealthUpdater
    Hostname string
    NodeIP net.IP
    Proxier proxy.Provider
}
```

#### createProxier

```go
// createProxier创建了proxy.Provider。
func (s *ProxyServer) createProxier(config *proxyconfigapi.KubeProxyConfiguration) (proxy.Provider, error) {
    var proxier proxy.Provider
    var err error
    var nodeInfo *v1.Node
    if config.DetectLocalMode == proxyconfigapi.LocalModeNodeCIDR {
        // 如果DetectLocalMode为NodeCIDR，则等待PodCIDR分配并获取节点信息
        klog.InfoS("Watching for node, awaiting podCIDR allocation", "hostname", s.Hostname)
        nodeInfo, err = waitForPodCIDR(s.Client, s.Hostname)
        if err != nil {
            return nil, err
        }
        klog.InfoS("NodeInfo", "podCIDR", nodeInfo.Spec.PodCIDR, "podCIDRs", nodeInfo.Spec.PodCIDRs)
    }

    primaryFamily := v1.IPv4Protocol
    primaryProtocol := utiliptables.ProtocolIPv4
    if netutils.IsIPv6(s.NodeIP) {
        // 如果节点IP地址为IPv6，则设置primaryFamily和primaryProtocol为IPv6
        primaryFamily = v1.IPv6Protocol
        primaryProtocol = utiliptables.ProtocolIPv6
    }
    execer := exec.New()
    iptInterface := utiliptables.New(execer, primaryProtocol)

    var ipt [2]utiliptables.Interface
    dualStack := true // 我们假设节点支持双栈，在后面进行进一步的检查

    // 为两个地址族创建iptables处理程序，其中一个已经创建
    // 总是按IPv4、IPv6的顺序排序
    if primaryProtocol == utiliptables.ProtocolIPv4 {
        ipt[0] = iptInterface
        ipt[1] = utiliptables.New(execer, utiliptables.ProtocolIPv6)
    } else {
        ipt[0] = utiliptables.New(execer, utiliptables.ProtocolIPv4)
        ipt[1] = iptInterface
    }

    nodePortAddresses := config.NodePortAddresses

    if !ipt[0].Present() {
        // 如果第一个地址族的iptables不存在，则返回错误
        return nil, fmt.Errorf("iptables is not supported for primary IP family %q", primaryProtocol)
    } else if !ipt[1].Present() {
        // 如果第二个地址族的iptables不存在，则打印日志，设置dualStack为false，并进行相关处理
        klog.InfoS("kube-proxy running in single-stack mode: secondary ipFamily is not supported", "ipFamily", ipt[1].Protocol())
        dualStack = false

        // 验证NodePortAddresses是否为单栈
        npaByFamily := proxyutil.MapCIDRsByIPFamily(config.NodePortAddresses)
        secondaryFamily := proxyutil.OtherIPFamily(primaryFamily)
        badAddrs := npaByFamily[secondaryFamily]
        if len(badAddrs) > 0 {
            // 忽略错误地址族的NodePortAddresses，并使用主地址族的地址
            klog.InfoS("Ignoring --nodeport-addresses of the wrong family", "ipFamily", secondaryFamily, "addresses", badAddrs)
            nodePortAddresses = npaByFamily[primaryFamily]
        }
    }

    if config.Mode == proxyconfigapi.ProxyModeIPTables {
        // 如果代理模式为IPTables，则创建iptables的Proxier
        klog.InfoS("Using iptables Proxier")

        if dualStack {
            // 如果是双栈模式，则创建双栈的Proxier
            klog.InfoS("kube-proxy running in dual-stack mode", "ipFamily", iptInterface.Protocol())
            klog.InfoS("Creating dualStackProxier for iptables")
            // 总是按顺序与[]ipt匹配
            var localDetectors [2]proxyutiliptables.LocalTrafficDetector
            localDetectors, err = getDualStackLocalDetectorTuple(config.DetectLocalMode, config, ipt, nodeInfo)
            if err != nil {
                return nil, fmt.Errorf("unable to create proxier: %v", err)
            }

            // TODO 这里有一些副作用，应该只在调用Run()时发生
            proxier, err = iptables.NewDualStackProxier(
                ipt,
                utilsysctl.New(),
                execer,
                config.IPTables.SyncPeriod.Duration,
                config.IPTables.MinSyncPeriod.Duration,
                config.IPTables.MasqueradeAll,
                *config.IPTables.LocalhostNodePorts,
                int(*config.IPTables.MasqueradeBit),
                localDetectors,
                s.Hostname,
                nodeIPTuple(config.BindAddress),
                s.Recorder,
                s.HealthzServer,
                nodePortAddresses,
            )
        } else {
            // 如果节点不支持双栈（即没有iptables支持），则创建单栈的Proxier
            var localDetector proxyutiliptables.LocalTrafficDetector
            localDetector, err = getLocalDetector(config.DetectLocalMode, config, iptInterface, nodeInfo)
            if err != nil {
                return nil, fmt.Errorf("unable to create proxier: %v", err)
            }

            // TODO 这里有一些副作用，应该只在调用Run()时发生
            proxier, err = iptables.NewProxier(
                primaryFamily,
                iptInterface,
                utilsysctl.New(),
                execer,
                config.IPTables.SyncPeriod.Duration,
                config.IPTables.MinSyncPeriod.Duration,
                config.IPTables.MasqueradeAll,
                *config.IPTables.LocalhostNodePorts,
                int(*config.IPTables.MasqueradeBit),
                localDetector,
                s.Hostname,
                s.NodeIP,
                s.Recorder,
                s.HealthzServer,
                nodePortAddresses,
            )
        }

        if err != nil {
            return nil, fmt.Errorf("unable to create proxier: %v", err)
        }
    } else if config.Mode == proxyconfigapi.ProxyModeIPVS {
        // 如果代理模式为IPVS，则创建IPVS的Proxier
        kernelHandler := ipvs.NewLinuxKernelHandler()
        ipsetInterface := utilipset.New(execer)
        ipvsInterface := utilipvs.New()
        if err := ipvs.CanUseIPVSProxier(ipvsInterface, ipsetInterface, config.IPVS.Scheduler); err != nil {
            return nil, fmt.Errorf("can't use the IPVS proxier: %v", err)
        }

        klog.InfoS("Using ipvs Proxier")
        if dualStack {
            klog.InfoS("Creating dualStackProxier for ipvs")

            nodeIPs := nodeIPTuple(config.BindAddress)

            // 总是按顺序与[]ipt匹配
            var localDetectors [2]proxyutiliptables.LocalTrafficDetector
            localDetectors, err = getDualStackLocalDetectorTuple(config.DetectLocalMode, config, ipt, nodeInfo)
            if err != nil {
                return nil, fmt.Errorf("unable to create proxier: %v", err)
            }

            proxier, err = ipvs.NewDualStackProxier(
                ipt,
                ipvsInterface,
                ipsetInterface,
                utilsysctl.New(),
                execer,
                config.IPVS.SyncPeriod.Duration,
                config.IPVS.MinSyncPeriod.Duration,
                config.IPVS.ExcludeCIDRs,
                config.IPVS.StrictARP,
                config.IPVS.TCPTimeout.Duration,
                config.IPVS.TCPFinTimeout.Duration,
                config.IPVS.UDPTimeout.Duration,
                config.IPTables.MasqueradeAll,
                int(*config.IPTables.MasqueradeBit),
                localDetectors,
                s.Hostname,
                nodeIPs,
                s.Recorder,
                s.HealthzServer,
                config.IPVS.Scheduler,
                nodePortAddresses,
                kernelHandler,
            )
        } else {
            var localDetector proxyutiliptables.LocalTrafficDetector
            localDetector, err = getLocalDetector(config.DetectLocalMode, config, iptInterface, nodeInfo)
            if err != nil {
                return nil, fmt.Errorf("unable to create proxier: %v", err)
            }

                proxier, err = ipvs.NewProxier(
                    primaryFamily,
                    iptInterface,
                    ipvsInterface,
                    ipsetInterface,
                    utilsysctl.New(),
                    execer,
                    config.IPVS.SyncPeriod.Duration,
                    config.IPVS.MinSyncPeriod.Duration,
                    config.IPVS.ExcludeCIDRs,
                    config.IPVS.StrictARP,
                    config.IPVS.TCPTimeout.Duration,
                    config.IPVS.TCPFinTimeout.Duration,
                    config.IPVS.UDPTimeout.Duration,
                    config.IPTables.MasqueradeAll,
                    int(*config.IPTables.MasqueradeBit),
                    localDetector,
                    s.Hostname,
                    s.NodeIP,
                    s.Recorder,
                    s.HealthzServer,
                    config.IPVS.Scheduler,
                    nodePortAddresses,
                    kernelHandler,
                )
            }
        }
        if err != nil {
            return nil, fmt.Errorf("unable to create proxier: %v", err)
        }
    }

    return proxier, nil
}
```

##### waitForPodCIDR

```go
func waitForPodCIDR(client clientset.Interface, nodeName string) (*v1.Node, error) {
	// 等待podCIDR分配，因为分配器可以在节点注册后分配podCIDR，所以我们在这里进行观察以等待podCIDR的分配，
	// 而不是假设启动时的Get()就有podCIDR。
	ctx, cancelFunc := context.WithTimeout(context.TODO(), timeoutForNodePodCIDR)
	defer cancelFunc()

	fieldSelector := fields.OneTermEqualSelector("metadata.name", nodeName).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (object runtime.Object, e error) {
			options.FieldSelector = fieldSelector
			return client.CoreV1().Nodes().List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (i watch.Interface, e error) {
			options.FieldSelector = fieldSelector
			return client.CoreV1().Nodes().Watch(ctx, options)
		},
	}
	condition := func(event watch.Event) (bool, error) {
		// 不处理删除事件
		if event.Type != watch.Modified && event.Type != watch.Added {
			return false, nil
		}

		n, ok := event.Object.(*v1.Node)
		if !ok {
			return false, fmt.Errorf("event object not of type Node")
		}
		// 如果节点即将被删除，则不考虑该节点，继续等待
		if !n.DeletionTimestamp.IsZero() {
			return false, nil
		}
		return n.Spec.PodCIDR != "" && len(n.Spec.PodCIDRs) > 0, nil
	}

	evt, err := toolswatch.UntilWithSync(ctx, lw, &v1.Node{}, nil, condition)
	if err != nil {
		return nil, fmt.Errorf("timeout waiting for PodCIDR allocation to configure detect-local-mode %v: %v", proxyconfigapi.LocalModeNodeCIDR, err)
	}
	if n, ok := evt.Object.(*v1.Node); ok {
		return n, nil
	}
	return nil, fmt.Errorf("event object not of type node")
}
```

##### getDualStackLocalDetectorTuple

```go
func getDualStackLocalDetectorTuple(mode proxyconfigapi.LocalMode, config *proxyconfigapi.KubeProxyConfiguration, ipt [2]utiliptables.Interface, nodeInfo *v1.Node) ([2]proxyutiliptables.LocalTrafficDetector, error) {
	var err error
	localDetectors := [2]proxyutiliptables.LocalTrafficDetector{proxyutiliptables.NewNoOpLocalDetector(), proxyutiliptables.NewNoOpLocalDetector()}
	switch mode {
	case proxyconfigapi.LocalModeClusterCIDR:
		// 如果未传递--detect-local-mode参数，默认为LocalModeClusterCIDR，
		// 但--cluster-cidr是可选的。
		if len(strings.TrimSpace(config.ClusterCIDR)) == 0 {
			klog.InfoS("Detect-local-mode set to ClusterCIDR, but no cluster CIDR defined")
			break
		}

		clusterCIDRs := cidrTuple(config.ClusterCIDR)

		if len(strings.TrimSpace(clusterCIDRs[0])) == 0 {
			klog.InfoS("Detect-local-mode set to ClusterCIDR, but no IPv4 cluster CIDR defined, defaulting to no-op detect-local for IPv4")
		} else {
			localDetectors[0], err = proxyutiliptables.NewDetectLocalByCIDR(clusterCIDRs[0], ipt[0])
			if err != nil { // 不丢失原始错误
				return localDetectors, err
			}
		}

		if len(strings.TrimSpace(clusterCIDRs[1])) == 0 {
			klog.InfoS("Detect-local-mode set to ClusterCIDR, but no IPv6 cluster CIDR defined, defaulting to no-op detect-local for IPv6")
		} else {
			localDetectors[1], err = proxyutiliptables.NewDetectLocalByCIDR(clusterCIDRs[1], ipt[1])
		}
		return localDetectors, err
	case proxyconfigapi.LocalModeNodeCIDR:
		if len(strings.TrimSpace(nodeInfo.Spec.PodCIDR)) == 0 {
			klog.InfoS("No node info available to configure detect-local-mode NodeCIDR")
			break
		}
		// localDetectors和ipt需要按[IPv4，IPv6]的顺序，
		// 但PodCIDRs被设置为PodCIDRs[0] == PodCIDR。
		// 所以必须处理PodCIDR可能是IPv6的情况，并将其设置为localDetectors[1]
		if netutils.IsIPv6CIDRString(nodeInfo.Spec.PodCIDR) {
			localDetectors[1], err = proxyutiliptables.NewDetectLocalByCIDR(nodeInfo.Spec.PodCIDR, ipt[1])
			if err != nil {
				return localDetectors, err
			}
			if len(nodeInfo.Spec.PodCIDRs) > 1 {
				localDetectors[0], err = proxyutiliptables.NewDetectLocalByCIDR(nodeInfo.Spec.PodCIDRs[1], ipt[0])
			}
		} else {
			localDetectors[0], err = proxyutiliptables.NewDetectLocalByCIDR(nodeInfo.Spec.PodCIDR, ipt[0])
			if err != nil {
				return localDetectors, err
			}
			if len(nodeInfo.Spec.PodCIDRs) > 1 {
				localDetectors[1], err = proxyutiliptables.NewDetectLocalByCIDR(nodeInfo.Spec.PodCIDRs[1], ipt[1])
			}
		}
		return localDetectors, err
	case proxyconfigapi.LocalModeBridgeInterface, proxyconfigapi.LocalModeInterfaceNamePrefix:
		localDetector, err := getLocalDetector(mode, config, ipt[0], nodeInfo)
		if err == nil {
			localDetectors[0] = localDetector
			localDetectors[1] = localDetector
		}
		return localDetectors, err
	default:
		klog.InfoS("Unknown detect-local-mode", "detectLocalMode", mode)
	}
	klog.InfoS("Defaulting to no-op detect-local", "detectLocalMode", string(mode))
	return localDetectors, nil
}
```

##### getLocalDetector

```go
func getLocalDetector(mode proxyconfigapi.LocalMode, config *proxyconfigapi.KubeProxyConfiguration, ipt utiliptables.Interface, nodeInfo *v1.Node) (proxyutiliptables.LocalTrafficDetector, error) {
	switch mode {
	case proxyconfigapi.LocalModeClusterCIDR:
		// 如果没有定义集群 CIDR，则将 Detect-local-mode 设置为 ClusterCIDR 的默认值
		if len(strings.TrimSpace(config.ClusterCIDR)) == 0 {
			klog.InfoS("Detect-local-mode set to ClusterCIDR, but no cluster CIDR defined")
			break
		}
		return proxyutiliptables.NewDetectLocalByCIDR(config.ClusterCIDR, ipt)
	case proxyconfigapi.LocalModeNodeCIDR:
		// 如果节点的 PodCIDR 未定义，则将 Detect-local-mode 设置为 NodeCIDR
		if len(strings.TrimSpace(nodeInfo.Spec.PodCIDR)) == 0 {
			klog.InfoS("Detect-local-mode set to NodeCIDR, but no PodCIDR defined at node")
			break
		}
		return proxyutiliptables.NewDetectLocalByCIDR(nodeInfo.Spec.PodCIDR, ipt)
	case proxyconfigapi.LocalModeBridgeInterface:
		return proxyutiliptables.NewDetectLocalByBridgeInterface(config.DetectLocal.BridgeInterface)
	case proxyconfigapi.LocalModeInterfaceNamePrefix:
		return proxyutiliptables.NewDetectLocalByInterfaceNamePrefix(config.DetectLocal.InterfaceNamePrefix)
	}
	// 如果没有匹配到任何模式，则将 Detect-local-mode 设置为默认值（no-op detect-local）
	klog.InfoS("Defaulting to no-op detect-local", "detectLocalMode", string(mode))
	return proxyutiliptables.NewNoOpLocalDetector(), nil
}
```

### runLoop

```GO
func (o *Options) runLoop() error {
	if o.watcher != nil {
		o.watcher.Run()
	}

	// 在 goroutine 中运行代理服务器
	go func() {
		err := o.proxyServer.Run()
		o.errCh <- err
	}()

	for {
		err := <-o.errCh
		if err != nil {
			return err
		}
	}
}
```

#### FSWatcher

```GO
// FSWatcher 是一个基于回调的文件系统监视器抽象，用于 fsnotify。
type FSWatcher interface {
    // 使用给定的事件处理程序和错误处理程序初始化监视器。
    // 在所有其他方法之前调用。
    Init(FSEventHandler, FSErrorHandler) error

    // 开始监听事件和错误。
    // 当事件或错误发生时，调用相应的处理程序。
    Run()

    // 添加要监视的文件系统路径
    AddWatch(path string) error
}

// FSEventHandler 在 fsnotify 事件发生时被调用。
type FSEventHandler func(event fsnotify.Event)

// FSErrorHandler 在 fsnotify 错误发生时被调用。
type FSErrorHandler func(err error)

type fsnotifyWatcher struct {
    watcher *fsnotify.Watcher
    eventHandler FSEventHandler
    errorHandler FSErrorHandler
}

var _ FSWatcher = &fsnotifyWatcher{}

// NewFsnotifyWatcher 返回一个实现了 FSWatcher 的实例，该实例持续监听 fsnotify 事件，并在收到事件时立即调用事件处理程序。
func NewFsnotifyWatcher() FSWatcher {
	return &fsnotifyWatcher{}
}

func (w *fsnotifyWatcher) AddWatch(path string) error {
	return w.watcher.Add(path)
}

func (w *fsnotifyWatcher) Init(eventHandler FSEventHandler, errorHandler FSErrorHandler) error {
    var err error
    w.watcher, err = fsnotify.NewWatcher()
    if err != nil {
    	return err
    }
    w.eventHandler = eventHandler
    w.errorHandler = errorHandler
    return nil
}

func (w *fsnotifyWatcher) Run() {
    go func() {
        defer w.watcher.Close()
        for {
            select {
                case event := <-w.watcher.Events:
                    if w.eventHandler != nil {
                        w.eventHandler(event)
                    }
                case err := <-w.watcher.Errors:
                    if w.errorHandler != nil {
                        w.errorHandler(err)
                    }
            }
        }
    }()
}
```

#### Run

```GO
// proxyRun defines the interface to run a specified ProxyServer
type proxyRun interface {
	Run() error
}

// ProxyServer表示启动Kubernetes代理服务器所需的所有参数。所有字段都是必需的。
type ProxyServer struct {
    Config *kubeproxyconfig.KubeProxyConfiguration // KubeProxy配置
    Client clientset.Interface // 客户端
    Broadcaster events.EventBroadcaster // 事件广播器
    Recorder events.EventRecorder // 事件记录器
    NodeRef *v1.ObjectReference // 节点引用
    HealthzServer healthcheck.ProxierHealthUpdater // 健康检查服务器
    Hostname string // 主机名
    NodeIP net.IP // 节点IP
    Proxier proxy.Provider // 代理提供者
}

// Run运行指定的ProxyServer。除非设置了CleanupAndExit，否则此函数不会退出。
// TODO: 目前，Run()不能返回nil错误，否则其调用者将永远不会退出。更新调用Run的函数以处理nil错误。
func (s *ProxyServer) Run() error {
    // 用于调试的立即记录版本信息
    klog.InfoS("Version info", "version", version.Get())
    klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

    // TODO: 对于此功能，使用容器配置。
    var oomAdjuster *oom.OOMAdjuster
    if s.Config.OOMScoreAdj != nil {
        oomAdjuster = oom.NewOOMAdjuster()
        if err := oomAdjuster.ApplyOOMScoreAdj(0, int(*s.Config.OOMScoreAdj)); err != nil {
            klog.V(2).InfoS("Failed to apply OOMScore", "err", err)
        }
    }

    if s.Broadcaster != nil {
        stopCh := make(chan struct{})
        s.Broadcaster.StartRecordingToSink(stopCh)
    }

    // TODO: 允许健康检查和度量标准位于同一端口。

    var errCh chan error
    if s.Config.BindAddressHardFail {
        errCh = make(chan error)
    }

    // 如果请求了健康检查服务器，则启动它
    serveHealthz(s.HealthzServer, errCh)

    // 如果请求了度量服务器，则启动它
    serveMetrics(s.Config.MetricsBindAddress, s.Config.Mode, s.Config.EnableProfiling, errCh)

    // 执行特定于平台的设置
    err := s.platformSetup()
    if err != nil {
        return err
    }

    noProxyName, err := labels.NewRequirement(apis.LabelServiceProxyName, selection.DoesNotExist, nil)
    if err != nil {
        return err
    }

    noHeadlessEndpoints, err := labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
    if err != nil {
        return err
    }

    labelSelector := labels.NewSelector()
    labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

    // 创建筛选出要求非默认服务代理的对象的informer。
    informerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.Config.ConfigSyncPeriod.Duration,
        informers.WithTweakListOptions(func(options *metav1.ListOptions) {
            options.LabelSelector = labelSelector.String()
        }))

    // 创建配置（即服务和EndpointSlices的监视器）
    // 注意：必须在创建Sources之前调用RegisterHandler()，因为sources只会在更改时通知，如果还没有注册任何处理程序，初始更新（进程启动时）可能会丢失。
    serviceConfig := config.NewServiceConfig(informerFactory.Core().V1().Services(), s.Config.ConfigSyncPeriod.Duration)
    serviceConfig.RegisterEventHandler(s.Proxier)
    go serviceConfig.Run(wait.NeverStop)

    endpointSliceConfig := config.NewEndpointSliceConfig(informerFactory.Discovery().V1().EndpointSlices(), s.Config.ConfigSyncPeriod.Duration)
    endpointSliceConfig.RegisterEventHandler(s.Proxier)
    go endpointSliceConfig.Run(wait.NeverStop)

    // 这必须在NewServiceConfig调用之后启动，因为该函数必须首先配置其shared informer事件处理程序。
    informerFactory.Start(wait.NeverStop)

    // 创建选择我们节点名称的informers。
    currentNodeInformerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.Config.ConfigSyncPeriod.Duration,
        informers.WithTweakListOptions(func(options *metav1.ListOptions) {
            options.FieldSelector = fields.OneTermEqualSelector("metadata.name", s.NodeRef.Name).String()
        }))
    nodeConfig := config.NewNodeConfig(currentNodeInformerFactory.Core().V1().Nodes(), s.Config.ConfigSyncPeriod.Duration)
    // https://issues.k8s.io/111321
    if s.Config.DetectLocalMode == kubeproxyconfig.LocalModeNodeCIDR {
        nodeConfig.RegisterEventHandler(&proxy.NodePodCIDRHandler{})
    }
    nodeConfig.RegisterEventHandler(s.Proxier)

    go nodeConfig.Run(wait.NeverStop)

    // 这必须在NewNodeConfig调用之后启动，因为必须首先配置shared informer事件处理程序。
    currentNodeInformerFactory.Start(wait.NeverStop)

    // 诞生之后的欢呼声
    s.birthCry()

    go s.Proxier.SyncLoop()

    return <-errCh
}
```

##### platformSetup

```go
func (s *ProxyServer) platformSetup() error {
	ct := &realConntracker{} // 创建一个realConntracker对象
    max, err := getConntrackMax(s.Config.Conntrack) // 获取连接追踪的最大值
    if err != nil {
        return err
    }
    if max > 0 {
        err := ct.SetMax(max) // 设置连接追踪的最大值
        if err != nil {
            if err != errReadOnlySysFS {
                return err
            }
            // errReadOnlySysFS是由已知的Docker问题引起的（https://github.com/docker/docker/issues/24000），
            // 我们所知的唯一补救措施是重新启动Docker守护程序。
            // 在这里，我们将发送一个带有特定原因和消息的节点事件，管理员应该决定是否以及如何处理此问题，
            // 是否要排空节点并重新启动Docker。在其他容器运行时也会出现此问题。
            // TODO（random-liu）：在修复Docker错误后删除此部分。
            const message = "CRI error: /sys is read-only: " +
                "cannot modify conntrack limits, problems may arise later (If running Docker, see docker issue #24000)"
            s.Recorder.Eventf(s.NodeRef, nil, v1.EventTypeWarning, err.Error(), "StartKubeProxy", message)
        }
    }

    if s.Config.Conntrack.TCPEstablishedTimeout != nil && s.Config.Conntrack.TCPEstablishedTimeout.Duration > 0 {
        timeout := int(s.Config.Conntrack.TCPEstablishedTimeout.Duration / time.Second)
        if err := ct.SetTCPEstablishedTimeout(timeout); err != nil {
            return err
        }
    }

    if s.Config.Conntrack.TCPCloseWaitTimeout != nil && s.Config.Conntrack.TCPCloseWaitTimeout.Duration > 0 {
        timeout := int(s.Config.Conntrack.TCPCloseWaitTimeout.Duration / time.Second)
        if err := ct.SetTCPCloseWaitTimeout(timeout); err != nil {
            return err
        }
    }

    proxymetrics.RegisterMetrics() // 注册代理的度量指标
    return nil
}
```

##### ServiceConfig

```go
// ServiceConfig用于跟踪一组服务配置。
type ServiceConfig struct {
    listerSynced cache.InformerSynced
    eventHandlers []ServiceHandler
}

// NewServiceConfig创建一个新的ServiceConfig。
func NewServiceConfig(serviceInformer coreinformers.ServiceInformer, resyncPeriod time.Duration) *ServiceConfig {
    result := &ServiceConfig{
    	listerSynced: serviceInformer.Informer().HasSynced,
	}
    serviceInformer.Informer().AddEventHandlerWithResyncPeriod(
        cache.ResourceEventHandlerFuncs{
            AddFunc:    result.handleAddService,
            UpdateFunc: result.handleUpdateService,
            DeleteFunc: result.handleDeleteService,
        },
        resyncPeriod,
    )

    return result
}

```

###### ServiceHandler

```go
// ServiceHandler是接收有关服务对象更改的通知的抽象接口。
type ServiceHandler interface {
    // OnServiceAdd在观察到创建新的服务对象时被调用。
    OnServiceAdd(service *v1.Service)
    // OnServiceUpdate在观察到现有服务对象的修改时被调用。
    OnServiceUpdate(oldService, service *v1.Service)
    // OnServiceDelete在观察到删除现有服务对象时被调用。
    OnServiceDelete(service *v1.Service)
    // OnServiceSynced在初始事件处理程序被调用且状态完全传播到本地缓存时被调用。
    OnServiceSynced()
}
```

###### handleService

```go
func (c *ServiceConfig) handleAddService(obj interface{}) {
service, ok := obj.(*v1.Service)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
        return
    }
    for i := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnServiceAdd")
        c.eventHandlers[i].OnServiceAdd(service) // 调用注册的处理程序的OnServiceAdd方法
    }
}

func (c *ServiceConfig) handleUpdateService(oldObj, newObj interface{}) {
    oldService, ok := oldObj.(*v1.Service)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
        return
    }
    service, ok := newObj.(*v1.Service)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
        return
    }
    for i := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnServiceUpdate")
        c.eventHandlers[i].OnServiceUpdate(oldService, service) // 调用注册的处理程序的OnServiceUpdate方法
    }
}

func (c *ServiceConfig) handleDeleteService(obj interface{}) {
    service, ok := obj.(*v1.Service)
    if !ok {
        tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
        if !ok {
            utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
            return
        }
        if service, ok = tombstone.Obj.(*v1.Service); !ok {
            utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
            return
        }
    }
    for i := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnServiceDelete")
        c.eventHandlers[i].OnServiceDelete(service) // 调用注册的处理程序的OnServiceDelete方法
    }
}
```

###### RegisterEventHandler

```go
// RegisterEventHandler注册一个在每个服务更改时调用的处理程序。
func (c *ServiceConfig) RegisterEventHandler(handler ServiceHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}
```

###### Run

```go
// Run等待缓存同步完成，并在同步后调用处理程序。
func (c *ServiceConfig) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting service config controller")
    if !cache.WaitForNamedCacheSync("service config", stopCh, c.listerSynced) {
        return
    }

    for i := range c.eventHandlers {
        klog.V(3).InfoS("Calling handler.OnServiceSynced()")
        c.eventHandlers[i].OnServiceSynced()
    }
}
```

##### EndpointSliceConfig

```go
// EndpointSliceConfig 是跟踪一组 endpoints 配置的结构体。
type EndpointSliceConfig struct {
    listerSynced cache.InformerSynced
    eventHandlers []EndpointSliceHandler
}

// NewEndpointSliceConfig 创建一个新的 EndpointSliceConfig。
func NewEndpointSliceConfig(endpointSliceInformer discoveryinformers.EndpointSliceInformer, resyncPeriod time.Duration) *EndpointSliceConfig {
    result := &EndpointSliceConfig{
    	listerSynced: endpointSliceInformer.Informer().HasSynced,
    }
	endpointSliceInformer.Informer().AddEventHandlerWithResyncPeriod(
        cache.ResourceEventHandlerFuncs{
            AddFunc:    result.handleAddEndpointSlice,
            UpdateFunc: result.handleUpdateEndpointSlice,
            DeleteFunc: result.handleDeleteEndpointSlice,
        },
        resyncPeriod,
    )

    return result
}
```

###### EndpointSliceHandler

```go
// EndpointSliceHandler 是接收 endpoint slice 对象变化通知的抽象接口。
type EndpointSliceHandler interface {
    // OnEndpointSliceAdd 在观察到新的 endpoint slice 对象创建时调用。
    OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice)
    // OnEndpointSliceUpdate 在观察到现有的 endpoint slice 对象修改时调用。
    OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice *discovery.EndpointSlice)
    // OnEndpointSliceDelete 在观察到现有的 endpoint slice 对象删除时调用。
    OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice)
    // OnEndpointSlicesSynced 在所有初始事件处理程序被调用并且状态完全传播到本地缓存时调用。
    OnEndpointSlicesSynced()
}
```

###### handleEndpointSlice

```go
// handleAddEndpointSlice 处理添加 endpoint slice 的函数。
func (c *EndpointSliceConfig) handleAddEndpointSlice(obj interface{}) {
    endpointSlice, ok := obj.(*discovery.EndpointSlice)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %T", obj))
        return
    }
    for _, h := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnEndpointSliceAdd", "endpoints", klog.KObj(endpointSlice))
        h.OnEndpointSliceAdd(endpointSlice)
    }
}

// handleUpdateEndpointSlice 处理更新 endpoint slice 的函数。
func (c *EndpointSliceConfig) handleUpdateEndpointSlice(oldObj, newObj interface{}) {
    oldEndpointSlice, ok := oldObj.(*discovery.EndpointSlice)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %T", newObj))
        return
    }
    newEndpointSlice, ok := newObj.(*discovery.EndpointSlice)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %T", newObj))
        return
    }
    for _, h := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnEndpointSliceUpdate")
        h.OnEndpointSliceUpdate(oldEndpointSlice, newEndpointSlice)
    }
}

// handleDeleteEndpointSlice 处理删除 endpoint slice 的函数。
func (c *EndpointSliceConfig) handleDeleteEndpointSlice(obj interface{}) {
    endpointSlice, ok := obj.(*discovery.EndpointSlice)
    if !ok {
    tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
        if !ok {
            utilruntime.HandleError(fmt.Errorf("unexpected object type: %T", obj))
            return
        }
        if endpointSlice, ok = tombstone.Obj.(*discovery.EndpointSlice); !ok {
            utilruntime.HandleError(fmt.Errorf("unexpected object type: %T", obj))
            return
        }
    }
    for _, h := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnEndpointsDelete")
        h.OnEndpointSliceDelete(endpointSlice)
    }
}
```

###### RegisterEventHandler

```go
// RegisterEventHandler 注册在每次 endpoint slice 更改时调用的处理程序。
func (c *EndpointSliceConfig) RegisterEventHandler(handler EndpointSliceHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}
```

###### Run

```go
// Run 等待缓存同步并在同步后调用处理程序。
func (c *EndpointSliceConfig) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting endpoint slice config controller")
    if !cache.WaitForNamedCacheSync("endpoint slice config", stopCh, c.listerSynced) {
        return
    }

    for _, h := range c.eventHandlers {
        klog.V(3).InfoS("Calling handler.OnEndpointSlicesSynced()")
        h.OnEndpointSlicesSynced()
    }
}
```

##### NodeConfig

```go
// NodeConfig用于跟踪一组节点配置。
// 它通过通道接收节点的"set"、"add"和"remove"操作，并在发生变化时调用注册的处理程序。
type NodeConfig struct {
    listerSynced cache.InformerSynced // 用于同步缓存和底层存储的接口
    eventHandlers []NodeHandler // 节点处理程序的列表
}

// NewNodeConfig创建一个新的NodeConfig实例。
func NewNodeConfig(nodeInformer coreinformers.NodeInformer, resyncPeriod time.Duration) *NodeConfig {
    result := &NodeConfig{
   		listerSynced: nodeInformer.Informer().HasSynced, // 使用NodeInformer创建listerSynced
    }
    // 添加事件处理函数到Informer的事件处理程序中，使用指定的重新同步周期
    nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
        cache.ResourceEventHandlerFuncs{
            AddFunc:    result.handleAddNode,    // 添加节点处理函数
            UpdateFunc: result.handleUpdateNode, // 更新节点处理函数
            DeleteFunc: result.handleDeleteNode, // 删除节点处理函数
        },
        resyncPeriod,
    )

    return result
}
```

###### NodeHandler

```go
// NodeHandler是接收节点对象变化通知的抽象接口。
type NodeHandler interface {
    OnNodeAdd(node *v1.Node) // 当观察到新节点对象创建时调用
    OnNodeUpdate(oldNode, node *v1.Node) // 当观察到现有节点对象修改时调用
    OnNodeDelete(node *v1.Node) // 当观察到现有节点对象删除时调用
	OnNodeSynced() // 在所有初始事件处理程序被调用且状态完全传播到本地缓存时调用
}
```

###### handleNode

```go
func (c *NodeConfig) handleAddNode(obj interface{}) {
    node, ok := obj.(*v1.Node)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
        return
    }
    for i := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnNodeAdd") // 调用处理程序的OnNodeAdd方法
        c.eventHandlers[i].OnNodeAdd(node)
    }
}

func (c *NodeConfig) handleUpdateNode(oldObj, newObj interface{}) {
    oldNode, ok := oldObj.(*v1.Node)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
        return
    }
    node, ok := newObj.(*v1.Node)
    if !ok {
        utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
        return
    }
    for i := range c.eventHandlers {
        klog.V(5).InfoS("Calling handler.OnNodeUpdate") // 调用处理程序的OnNodeUpdate方法
        c.eventHandlers[i].OnNodeUpdate(oldNode, node)
    }
}

func (c *NodeConfig) handleDeleteNode(obj interface{}) {
    node, ok := obj.(*v1.Node)
    if !ok {
        tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
        if !ok {
            utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
            return
        }
        if node, ok = tombstone.Obj.(*v1.Node); !ok {
            utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
            return
        }
    }
    for i := range c.eventHandlers {
        klog.V(4).InfoS("Calling handler.OnNodeDelete") // 调用处理程序的OnNodeDelete方法
        c.eventHandlers[i].OnNodeDelete(node)
    }
}
```

###### RegisterEventHandler

```go
// RegisterEventHandler注册一个在每次节点更改时调用的处理程序。
func (c *NodeConfig) RegisterEventHandler(handler NodeHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}
```

###### Run

```go
// Run启动负责调用注册处理程序的goroutine。
func (c *NodeConfig) Run(stopCh <-chan struct{}) {
    klog.InfoS("Starting node config controller") // 输出日志信息，表示开始节点配置控制器
    // 等待缓存同步完成，直到收到停止信号或超时
    if !cache.WaitForNamedCacheSync("node config", stopCh, c.listerSynced) {
        return
    }

    // 调用所有处理程序的OnNodeSynced方法
    for i := range c.eventHandlers {
        klog.V(3).InfoS("Calling handler.OnNodeSynced()")
        c.eventHandlers[i].OnNodeSynced()
    }
}
```

##### Provider

```go
// Provider是proxier实现提供的接口。
type Provider interface {
    config.EndpointSliceHandler // 实现EndpointSliceHandler接口
    config.ServiceHandler // 实现ServiceHandler接口
    config.NodeHandler // 实现NodeHandler接口
    // Sync立即将Provider的当前状态与代理规则同步。
    Sync()
    // SyncLoop运行周期性工作。
    // 这通常作为一个goroutine运行，或者作为应用程序的主循环运行。
    // 它不会返回。
    SyncLoop()
}
```

