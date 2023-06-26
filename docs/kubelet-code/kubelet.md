---
id: 1-kubelet-code 
title: kubelet 代码走读
description: kubelet 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## 简介

Kubelet是Kubernetes集群中的一个核心组件，它运行在每个节点上，负责管理和维护该节点上的容器。作为Kubernetes的代理，Kubelet负责与主控平面通信，接收主控平面下发的任务，并确保节点上的容器按照规定的状态和配置运行。

Kubelet的主要职责包括：

1. 容器生命周期管理：Kubelet负责监控节点上的容器，并根据主控平面下发的指令创建、启动、停止和销毁容器。它会通过与容器运行时接口（Container Runtime Interface，CRI）进行通信，与底层容器运行时（如Docker、containerd等）交互来管理容器的生命周期。
2. 资源管理：Kubelet负责监控节点的资源使用情况，包括CPU、内存、磁盘和网络等。它会根据容器的资源需求和节点的可用资源进行调度决策，确保节点资源得到合理利用。
3. 容器健康检查：Kubelet定期检查容器的健康状态，包括容器的运行状态、资源利用情况以及应用程序的自定义健康检查。如果发现容器不健康，Kubelet会通知主控平面，由主控平面采取相应的措施，如重启容器或迁移到其他节点上。
4. 节点状态报告：Kubelet向主控平面定期报告节点的状态信息，包括节点的健康状态、资源使用情况、已运行的容器列表等。这些信息对于集群的监控和管理非常重要。
5. 安全性管理：Kubelet负责确保容器的安全性，包括通过在容器中设置正确的Linux命名空间、安全上下文和访问控制等来隔离容器之间的环境。它还会与主控平面协同工作，确保只有经过授权的镜像和容器被部署和运行。

## main

```go
func main() {
	command := app.NewKubeletCommand()
	code := cli.Run(command)
	os.Exit(code)
}

// NewKubeletCommand函数创建一个具有默认参数的*cobra.Command对象。
func NewKubeletCommand() *cobra.Command {
    // 创建FlagSet对象cleanFlagSet，用于处理kubelet组件的标志。
    cleanFlagSet := pflag.NewFlagSet(componentKubelet, pflag.ContinueOnError)
    cleanFlagSet.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	// 创建KubeletFlags对象kubeletFlags，用于存储kubelet的标志。
    kubeletFlags := options.NewKubeletFlags()

    // 创建KubeletConfiguration对象kubeletConfig，用于存储kubelet的配置信息。
    kubeletConfig, err := options.NewKubeletConfiguration()
    // 程序员错误
    if err != nil {
        // 输出错误日志并退出程序
        klog.ErrorS(err, "Failed to create a new kubelet configuration")
        os.Exit(1)
    }

    // 创建*cobra.Command对象cmd，用于定义kubelet命令的行为和参数。
    cmd := &cobra.Command{
        Use: componentKubelet,
        Long: `The kubelet is the primary "node agent" that runs on each
    node. It can register the node with the apiserver using one of: the hostname; a flag to
    override the hostname; or specific logic for a cloud provider.

    The kubelet works in terms of a PodSpec. A PodSpec is a YAML or JSON object
    that describes a pod. The kubelet takes a set of PodSpecs that are provided through
    various mechanisms (primarily through the apiserver) and ensures that the containers
    described in those PodSpecs are running and healthy. The kubelet doesn't manage
    containers which were not created by Kubernetes.

    Other than from an PodSpec from the apiserver, there are two ways that a container
    manifest can be provided to the Kubelet.

    File: Path passed as a flag on the command line. Files under this path will be monitored
    periodically for updates. The monitoring period is 20s by default and is configurable
    via a flag.

    HTTP endpoint: HTTP endpoint passed as a parameter on the command line. This endpoint
    is checked every 20 seconds (also configurable with a flag).`,
		DisableFlagParsing: true, // 禁用Cobra的标志解析
        SilenceUsage: true, // 不显示用法帮助信息
        RunE: func(cmd *cobra.Command, args []string) error {
            // 初始标志解析，因为禁用了Cobra的标志解析
            if err := cleanFlagSet.Parse(args); err != nil {
                return fmt.Errorf("failed to parse kubelet flag: %w", err)
            }
    		// 检查命令行中是否有非标志参数
            cmds := cleanFlagSet.Args()
            if len(cmds) > 0 {
                return fmt.Errorf("unknown command %+s", cmds[0])
            }

            // 检查是否有帮助标志
            help, err := cleanFlagSet.GetBool("help")
            if err != nil {
                return errors.New(`"help" flag is non-bool, programmer error, please correct`)
            }
            if help {
                return cmd.Help()
            }

            // 检查是否有版本标志
            verflag.PrintAndExitIfRequested()

            // 根据初始的标志配置设置功能门限
            if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(kubeletConfig.FeatureGates); err != nil {
                return fmt.Errorf("failed to set feature gates from initial flags-based config: %w", err)
            }

            // 验证初始的KubeletFlags
            if err := options.ValidateKubeletFlags(kubeletFlags); err != nil {
                return fmt.Errorf("failed to validate kubelet flags: %w", err)
            }

            // 如果更改了"pod-infra-container-image"标志，则打印警告信息
            if cleanFlagSet.Changed("pod-infra-container-image") {
                klog.InfoS("--pod-infra-container-image will not be pruned by the image garbage collector in kubelet and should also be set in the remote runtime")
            }

            // 加载kubelet配置文件（如果提供了）
            if configFile := kubeletFlags.KubeletConfigFile; len(configFile) > 0 {
                kubeletConfig, err = loadConfigFile(configFile)
                if err != nil {
                    return fmt.Errorf("failed to load kubelet config file, error: %w, path: %s", err, configFile)
                }
                // 必须通过重新解析命令行将新对象中的标志配置提升为优先级。
                // 这是为了保持二进制升级的向后兼容性。
                // 更多细节请参见问题＃56171。
                if err := kubeletConfigFlagPrecedence(kubeletConfig, args); err != nil {
                    return fmt.Errorf("failed to precedence kubeletConfigFlag: %w", err)
                }
                // 根据新配置更新功能门限
                if err := utilfeature.DefaultMutableFeatureGate.SetFromMap(kubeletConfig.FeatureGates); err != nil {
                    return fmt.Errorf("failed to set feature gates from initial flags-based config: %w", err)
                }
            }

            // 配置和标志解析完成，现在可以初始化日志记录。
            logs.InitLogs()
            if err := logsapi.ValidateAndApplyAsField(&kubeletConfig.Logging, utilfeature.DefaultFeatureGate, field.NewPath("logging")); err != nil {
                return fmt.Errorf("initialize logging: %v", err)
            }
            cliflag.PrintFlags(cleanFlagSet)

            // 始终验证本地配置（命令行 + 配置文件）。
            // 这是动态配置的默认“最后已知良好”配置，必须始终保持有效。
            if err := kubeletconfigvalidation.ValidateKubeletConfiguration(kubeletConfig, utilfeature.DefaultFeatureGate); err != nil {
                return fmt.Errorf("failed to validate kubelet configuration, error: %w, path: %s", err, kubeletConfig)
            }

            // 检查kubeletCgroups是否在kubeReservedCgroup之内
            if (kubeletConfig.KubeletCgroups != "" && kubeletConfig.KubeReservedCgroup != "") && (strings.Index(kubeletConfig.KubeletCgroups, kubeletConfig.KubeReservedCgroup) != 0) {
                klog.InfoS("unsupported configuration:KubeletCgroups is not within KubeReservedCgroup")
            }

            // 使用kubeletFlags和kubeletConfig构造KubeletServer对象
            kubeletServer := &options.KubeletServer{
                KubeletFlags:         *kubeletFlags,
                KubeletConfiguration: *kubeletConfig,
            }

            // 使用kubeletServer构造默认的KubeletDeps
            kubeletDeps, err := UnsecuredDependencies(kubeletServer, utilfeature.DefaultFeatureGate)
            if err != nil {
                return fmt.Errorf("failed to construct kubelet dependencies: %w", err)
            }

            // 检查权限
            if err := checkPermissions(); err != nil {
                klog.ErrorS(err, "kubelet running with insufficient permissions")
            }

            // 使kubelet的配置安全以供日志记录
            config := kubeletServer.KubeletConfiguration.DeepCopy()
            for k := range config.StaticPodURLHeader {
                config.StaticPodURLHeader[k] = []string{"<masked>"}
            }
            // 记录kubelet的配置以供检查
            klog.V(5).InfoS("KubeletConfiguration", "configuration", klog.Format(config))

            // 设置信号上下文以进行kubelet关闭
            ctx := genericapiserver.SetupSignalContext()

            utilfeature.DefaultMutableFeatureGate.AddMetrics()
            // 运行kubelet
            return Run(ctx, kubeletServer, kubeletDeps, utilfeature.DefaultFeatureGate)
        },
    }

    // 将cleanFlagSet保持独立，以免Cobra将其与全局标志混淆
    kubeletFlags.AddFlags(cleanFlagSet)
    options.AddKubeletConfigFlags(cleanFlagSet, kubeletConfig)
    options.AddGlobalFlags(cleanFlagSet)
    cleanFlagSet.BoolP("help", "h", false, fmt.Sprintf("help for %s", cmd.Name()))

    // 由于Cobra的默认UsageFunc和HelpFunc会将flagset与全局标志混淆，因此需要以下操作
    const usageFmt = "Usage:\n  %s\n\nFlags:\n%s"
    cmd.SetUsageFunc(func(cmd *cobra.Command) error {
        fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
        return nil
    })
    cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
        fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine(), cleanFlagSet.FlagUsagesWrapped(2))
    })

    return cmd
}
```

### KubeletConfiguration

```go
// KubeletConfiguration包含Kubelet的配置信息
type KubeletConfiguration struct {
	metav1.TypeMeta
    // enableServer启用Kubelet的安全服务器。
    // 注意：Kubelet的不安全端口由readOnlyPort选项控制。
    EnableServer bool
    // staticPodPath是包含本地（静态）Pod要运行的目录的路径，或者是单个静态Pod文件的路径。
    StaticPodPath string
    // syncFrequency是同步正在运行的容器和配置之间的最大时间间隔
    SyncFrequency metav1.Duration
    // fileCheckFrequency是检查配置文件是否有新数据的时间间隔
    FileCheckFrequency metav1.Duration
    // httpCheckFrequency是检查http是否有新数据的时间间隔
    HTTPCheckFrequency metav1.Duration
    // staticPodURL是访问要运行的静态Pod的URL
    StaticPodURL string
    // staticPodURLHeader是一个带有访问podURL时使用的HTTP标头的切片映射
    StaticPodURLHeader map[string][]string `datapolicy:"token"`
    // address是Kubelet要提供的IP地址（对于所有接口设置为0.0.0.0）
    Address string
    // port是Kubelet要提供的端口。
    Port int32
    // readOnlyPort是Kubelet用于提供无身份验证/授权的只读端口（设置为0以禁用）
    ReadOnlyPort int32
    // volumePluginDir是用于搜索其他第三方卷插件的目录的完整路径。
    VolumePluginDir string
    // providerID（如果设置）设置外部提供程序（即cloudprovider）用于标识特定节点的唯一ID
    ProviderID string
    // tlsCertFile是包含HTTPS的x509证书的文件。 （CA证书，
    // 如果有的话，在服务器证书之后连接在一起）。如果未提供tlsCertFile和
    // tlsPrivateKeyFile，将为公共地址生成自签名证书
    // 并将其保存到传递给Kubelet的--cert-dir标志的目录中。
    TLSCertFile string
    // tlsPrivateKeyFile是包含与tlsCertFile匹配的x509私钥的文件
    TLSPrivateKeyFile string
    // TLSCipherSuites是服务器允许的密码套件列表。
    // 请注意，TLS 1.3密码套件不可配置。
    // 值来自tls包的常量（https://golang.org/pkg/crypto/tls/#pkg-constants）。
    TLSCipherSuites []string
    // TLSMinVersion是支持的最低TLS版本。
    // 值来自tls包的常量（https://golang.org/pkg/crypto/tls/#pkg-constants）。
    TLSMinVersion string
    // rotateCertificates启用客户端证书轮换。 Kubelet将从certificates.k8s.io API请求一个
    // 新的证书。 这需要一个批准者来批准证书签名请求。
    RotateCertificates bool
    // serverTLSBootstrap启用服务器证书引导。 Kubelet将从
	// serverTLSBootstrap 启用服务器证书引导。Kubelet将从 certificates.k8s.io API 请求证书，而不是自签名的服务证书。这需要一个批准者来批准证书签名请求。RotateKubeletServerCertificate 功能必须被启用。
    ServerTLSBootstrap bool

    // authentication 指定了Kubelet服务器上的请求如何进行身份验证
    Authentication KubeletAuthentication

    // authorization 指定了Kubelet服务器上的请求如何进行授权
    Authorization KubeletAuthorization

    // registryPullQPS 是每秒钟的镜像拉取次数限制。设置为0表示没有限制。
    RegistryPullQPS int32

    // registryBurst 是突发拉取的最大大小，临时允许拉取到此数量，但仍不能超过 registryPullQPS。仅在 registryPullQPS > 0 时使用。
    RegistryBurst int32

    // eventRecordQPS 是每秒钟的事件创建次数限制。如果为0，没有强制限制。
    EventRecordQPS int32

    // eventBurst 是事件创建突发的最大大小，临时允许事件创建到此数量，但仍不能超过 eventRecordQPS。仅在 eventRecordQPS > 0 时使用。
    EventBurst int32

    // enableDebuggingHandlers 启用服务器端点，用于日志收集和本地运行容器和命令。
    EnableDebuggingHandlers bool

    // enableContentionProfiling 如果 enableDebuggingHandlers 为 true，则启用阻塞分析。
    EnableContentionProfiling bool

    // healthzPort 是本地主机 healthz 端点的端口（设置为0表示禁用）
    HealthzPort int32

    // healthzBindAddress 是 healthz 服务器要侦听的 IP 地址
    HealthzBindAddress string

    // oomScoreAdj 是 kubelet 进程的 oom-score-adj 值。值必须在 [-1000, 1000] 范围内。
    OOMScoreAdj int32

    // clusterDomain 是此集群的 DNS 域。如果设置，Kubelet 将配置所有容器以在主机的搜索域之外搜索此域。
    ClusterDomain string

    // clusterDNS 是群集 DNS 服务器的 IP 地址列表。如果设置，Kubelet 将配置所有容器使用该地址进行 DNS 解析，而不是主机的 DNS 服务器。
    ClusterDNS []string

    // streamingConnectionIdleTimeout 是流式连接在自动关闭之前可以空闲的最长时间。
    StreamingConnectionIdleTimeout metav1.Duration

    // nodeStatusUpdateFrequency 是 Kubelet 计算节点状态的频率。如果未启用节点租约功能，它还是 Kubelet 将节点状态发布到主节点的频率。在这种情况下，更改此常量时要小心，它必须与 nodecontroller 中的 nodeMonitorGracePeriod 配合使用。
    NodeStatusUpdateFrequency metav1.Duration

    // nodeStatusReportFrequency 是 kubelet 在节点状态未发生变化时向主节点发送节点状态的频率。如果检测到任何变化，kubelet 将忽略此频率并立即发送节点状态。仅在启用节点租约功能时使用。
    NodeStatusReportFrequency metav1.Duration
    // nodeLeaseDurationSeconds 是 Kubelet 将设置在其相应租约上的持续时间。
    NodeLeaseDurationSeconds int32
    // imageMinimumGCAge 是未使用的镜像在进行垃圾回收之前的最小年龄。
    ImageMinimumGCAge metav1.Duration
    // imageGCHighThresholdPercent 是磁盘使用率超过此阈值时始终运行镜像垃圾回收的百分比。百分比是根据此字段的值计算的，范围为 0-100。
    ImageGCHighThresholdPercent int32
    // imageGCLowThresholdPercent 是磁盘使用率低于此阈值时不运行镜像垃圾回收的百分比。最低磁盘使用率以进行垃圾回收。百分比是根据此字段的值计算的，范围为 0-100。
    ImageGCLowThresholdPercent int32
    // 每隔多长时间计算并缓存所有 pod 的卷磁盘使用情况。
    VolumeStatsAggPeriod metav1.Duration
    // KubeletCgroups 是用于隔离 kubelet 的 cgroups 的绝对名称。
    KubeletCgroups string
    // SystemCgroups 是放置所有非内核进程（尚未在容器中的所有进程）的 cgroups 的绝对名称。如果为空，则表示没有容器。回滚标志需要重新启动。
    SystemCgroups string
    // CgroupRoot 是用于 pod 的根 cgroup。如果启用了 CgroupsPerQOS，则这是 QoS cgroup 层次结构的根。
    CgroupRoot string
    // 启用基于 QoS 的 Cgroup 层次结构：用于 QoS 类别的顶级 cgroups，所有 Burstable 和 BestEffort pod 都在其特定的顶级 QoS cgroup 下启动。
    CgroupsPerQOS bool
    // kubelet 在主机上操作 cgroups 的驱动程序（cgroupfs 或 systemd）。
    CgroupDriver string
    // CPUManagerPolicy 是要使用的策略的名称。需要启用 CPUManager 功能门。
    CPUManagerPolicy string
    // CPUManagerPolicyOptions 是一个键值对集合，允许设置额外的选项来微调 CPU 管理器策略的行为。需要同时启用 "CPUManager" 和 "CPUManagerPolicyOptions" 功能门。
    CPUManagerPolicyOptions map[string]string
    // CPUManagerReconcilePeriod 是 CPU 管理器调谐的周期。需要启用 CPUManager 功能门。
    CPUManagerReconcilePeriod metav1.Duration
    // MemoryManagerPolicy 是要使用的策略的名称。需要启用 MemoryManager 功能门。
    MemoryManagerPolicy string
    // TopologyManagerPolicy 是要使用的策略的.
	// TopologyManagerPolicy 是要使用的策略的名称。
    TopologyManagerPolicy string

    // TopologyManagerScope 表示拓扑提示生成的范围，拓扑管理器请求和提示提供程序生成。
    // 默认值："container"
    // +optional
    TopologyManagerScope string

    // TopologyManagerPolicyOptions 是一组 key=value 键值对，允许设置额外的选项来微调拓扑管理器策略的行为。
    // 需要同时启用 "TopologyManager" 和 "TopologyManagerPolicyOptions" 功能门。
    TopologyManagerPolicyOptions map[string]string

    // QOSReserved 是 QoS 资源预留百分比的映射（目前仅限内存）。
    // 需要启用 QOSReserved 功能门。
    QOSReserved map[string]string

    // runtimeRequestTimeout 是除了长时间运行请求（如拉取、日志、执行和附加）之外所有运行时请求的超时时间。
    RuntimeRequestTimeout metav1.Duration

    // hairpinMode 指定 Kubelet 如何配置容器网桥以处理 hairpin 数据包。
    // 设置此标志允许 Service 中的端点在尝试访问自己的 Service 时进行负载均衡返回到自己。
    // 可选值："promiscuous-bridge"：使容器网桥处于混杂模式。
    // "hairpin-veth"：在容器 veth 接口上设置 hairpin 标志。
    // "none"：什么都不做。
    // 通常，必须设置 --hairpin-mode=hairpin-veth 才能实现 hairpin NAT，因为 promiscuous-bridge 假定存在名为 cbr0 的容器网桥。
    HairpinMode string

    // MaxPods 是此 Kubelet 可以运行的 Pod 数量。
    MaxPods int32

    // PodCIDR 是用于 Pod IP 地址的 CIDR，仅在独立模式下使用。
    // 在集群模式下，此值从主节点获取。
    PodCIDR string

    // PodPidsLimit 是每个 Pod 的最大进程数。如果为 -1，则 Kubelet 默认为节点可分配的 PID 容量。
    PodPidsLimit int64

    // ResolverConfig 是用作容器 DNS 解析配置基础的解析器配置文件。
    ResolverConfig string

    // RunOnce 导致 Kubelet 仅检查 API 服务器一次以获取 Pod，
    // 在静态 Pod 文件指定的 Pod 之外运行这些 Pod，并退出。
    RunOnce bool

    // cpuCFSQuota 启用对指定 CPU 限制的容器启用 CPU CFS 配额强制。
    CPUCFSQuota bool

    // CPUCFSQuotaPeriod 设置 CPU CFS 配额周期值，即 cpu.cfs_period_us，默认为 100ms。
    CPUCFSQuotaPeriod metav1.Duration

    // MaxOpenFiles 是 Kubelet 进程可以打开的文件数量。
    MaxOpenFiles int64

    // nodeStatusMaxImages 限制在 Node.Status.Images 中报告的映像数量。
    NodeStatusMaxImages int32

    // contentType 是发送到 API 服务器的请求的内容类型。
    ContentType string

    // KubeAPIQPS 是与 Kubernetes API 服务器通信时使用的 QPS。
    KubeAPIQPS int32

    // KubeAPIBurst 是与 Kubernetes API 服务器通信时允许的突发大小。
    KubeAPIBurst int32

    // serializeImagePulls 在启用时，告诉 Kubelet 一次拉取一个镜像。
    SerializeImagePulls bool

    // MaxParallelImagePulls 设置并行进行的最大镜像拉取数。
    MaxParallelImagePulls *int32

    // EvictionHard 是一个信号名称到数量的映射，定义硬驱逐阈值。
    // 例如：{"memory.available": "300Mi"}。
    // 一些默认信号仅适用于 Linux：nodefs.inodesFree。
    EvictionHard map[string]string

    // EvictionSoft 是一个信号名称到数量的映射，定义软驱逐阈值。
    // 例如：{"memory.available": "300Mi"}。
    EvictionSoft map[string]string

    // EvictionSoftGracePeriod 是一个信号名称到数量的映射，定义每个软驱逐信号的宽限期。
    // 例如：{"memory.available": "30s"}。
    EvictionSoftGracePeriod map[string]string

    // EvictionPressureTransitionPeriod 是在转换出驱逐压力条件之前 Kubelet 必须等待的持续时间。
    EvictionPressureTransitionPeriod metav1.Duration

    // EvictionMaxPodGracePeriod 是在满足软驱逐阈值时终止 Pod 的最大容忍期（以秒为单位）。
    EvictionMaxPodGracePeriod int32

    // EvictionMinimumReclaim 是一个信号名称到数量的映射，定义在资源压力下进行 Pod 驱逐时 Kubelet 将回收的最小数量。
    // 例如：{"imagefs.available": "2Gi"}。
    EvictionMinimumReclaim map[string]string

    // PodsPerCore 是每个核心的最大 Pod 数量。不能超过 MaxPods。
    // 如果为 0，则忽略此字段。
    PodsPerCore int32

    // enableControllerAttachDetach 启用 Attach/Detach 控制器以管理安排给该节点的卷的附加/分离，并禁用 Kubelet 执行任何附加/分离操作。
    EnableControllerAttachDetach bool

    // protectKernelDefaults 如果为 true，则使 Kubelet 在内核标志不符合预期时报错。否则，Kubelet 将尝试修改内核标志以与其预期相匹配。
    ProtectKernelDefaults bool

    // 如果为 true，则 Kubelet 确保主机上存在一组 iptables 规则。
    // 这些规则将作为各个组件的实用程序，如 kube-proxy，而创建。
    // 这些规则将根据 IPTablesMasqueradeBit 和 IPTablesDropBit 创建。
    MakeIPTablesUtilChains bool

    // IPTablesMasqueradeBit 是 iptables fwmark 空间中用于标记 SNAT 的位。
    // 值必须在范围 [0, 31] 内。必须与其他标记位不同。
    // 警告：请与 kube-proxy 中的相应参数的值匹配。
    // TODO：清理 kube-proxy 中的 IPTablesMasqueradeBit
    IPTablesMasqueradeBit int32

    // iptablesDropBit 是 iptables fwmark 空间中用于标记丢弃数据包的位。
    // 值必须在范围 [0, 31] 内。必须与其他标记位不同。
    IPTablesDropBit int32

    // featureGates 是一个功能名称到布尔值的映射，用于启用或禁用 alpha/experimental 功能。
    // 此字段逐个修改从 "k8s.io/kubernetes/pkg/features/kube_features.go" 中内置的默认值。
    FeatureGates map[string]bool

    // 告诉 Kubelet 如果节点上启用了交换空间，则无法启动。
    FailSwapOn bool

    // memorySwap 配置可供容器工作负载使用的交换空间内存。
    // +featureGate=NodeSwap
    // +optional
    MemorySwap MemorySwapConfiguration

    // quantity 定义容器日志文件在进行轮换之前的最大大小。例如："5Mi" 或 "256Ki"。
    ContainerLogMaxSize string

    // 可以存在于容器的最大容器日志文件数。
    ContainerLogMaxFiles int32

    // ConfigMapAndSecretChangeDetectionStrategy 是 config map 和 secret 管理器运行的模式。
    ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy

    // 一个以逗号分隔的不安全 sysctl 或 sysctl 模式（以 * 结尾）的白名单。
    // 不安全的 sysctl 组包括 kernel.shm*、kernel.msg*、kernel.sem、fs.mqueue.* 和 net.*。
    // 这些 sysctl 在命名空间中，但默认情况下不允许使用。
    // 例如："kernel.msg*,net.ipv4.route.min_pmtu"
    // +optional
    AllowedUnsafeSysctls []string

    // 如果启用，Kubelet 将与内核 memcg 通知集成，以确定是否跨越内存驱逐阈值，而不是轮询。
    KernelMemcgNotification bool
    /* 以下字段用于节点可分配资源 */

	// 一组以ResourceName=ResourceQuantity（例如cpu=200m，memory=150G，ephemeral-storage=1G，pid=100）对描述的资源
    // 用于保留给非 Kubernetes 组件的资源
    // 目前仅支持cpu、memory和本地临时存储（用于根文件系统）
    // 有关更多详细信息，请参阅 http://kubernetes.io/docs/user-guide/compute-resources
	SystemReserved map[string]string
	// 一组以ResourceName=ResourceQuantity（例如cpu=200m，memory=150G，ephemeral-storage=1G，pid=100）对描述的资源
    // 用于保留给 Kubernetes 系统组件的资源
    // 目前仅支持cpu、memory和本地临时存储（用于根文件系统）
    // 有关更多详细信息，请参阅 http://kubernetes.io/docs/user-guide/compute-resources
	KubeReserved map[string]string
	// 此标志用于帮助 kubelet 标识用于强制执行“SystemReserved”计算资源预留的操作系统系统守护程序的顶级cgroup的绝对名称
	// 有关详细信息，请参阅 [Node Allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable) 文档
	SystemReservedCgroup string
	// 此标志用于帮助 kubelet 标识用于强制执行“KubeReserved”计算资源预留的 Kubernetes 节点系统守护程序的顶级cgroup的绝对名称
	// 有关详细信息，请参阅 [Node Allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable) 文档
	KubeReservedCgroup string
	// 此标志指定 Kubelet 需要执行的各种节点可分配强制性规定
    // 此标志接受一个选项列表。可接受的选项有 `pods`、`system-reserved` 和 `kube-reserved`
    // 有关详细信息，请参阅 [Node Allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable) 文档
	EnforceNodeAllocatable []string
	// 此选项指定为主机级别系统线程和与 Kubernetes 相关的线程保留的 CPU 列表
    // 它提供了一个“静态”CPU列表，而不是由 system-reserved 和 kube-reserved 提供的“动态”列表
    // 此选项将覆盖由 system-reserved 和 kube-reserved 提供的 CPU
	ReservedSystemCPUs string
	// 要显示隐藏指标的先前版本
    // 只有先前的次要版本有意义，其他值将不被允许
    // 格式为<major>.<minor>，例如：'1.16'
    // 这种格式的目的是确保您有机会注意到下一个发布是否隐藏了其他指标，
    // 而不是在之后的发布中永久删除它们时感到惊讶
	ShowHiddenMetricsForVersion string
	// Logging 指定日志选项
	// 有关详细信息，请参阅 [Logs Options](https://github.com/kubernetes/component-base/blob/master/logs/options.go) 文档
	Logging logsapi.LoggingConfiguration
	// EnableSystemLogHandler：启用/logs处理程序。
    EnableSystemLogHandler bool

    // EnableSystemLogQuery：在/logs端点上启用节点日志查询功能。
    // 需要同时启用EnableSystemLogHandler才能正常工作。
    // +featureGate=NodeLogQuery
    // +optional
    EnableSystemLogQuery bool

    // ShutdownGracePeriod：指定节点在关机期间应延迟关机和容器终止的总持续时间。
    // 默认为0秒。
    // +featureGate=GracefulNodeShutdown
    // +optional
    ShutdownGracePeriod metav1.Duration

    // ShutdownGracePeriodCriticalPods：指定在关机期间终止关键Pod的持续时间。此时间应小于ShutdownGracePeriod。
    // 默认为0秒。
    // 例如，如果ShutdownGracePeriod=30s，ShutdownGracePeriodCriticalPods=10s，在节点关机期间，前20秒将用于优雅终止普通Pod，最后的10秒将用于终止关键Pod。
    // +featureGate=GracefulNodeShutdown
    // +optional
    ShutdownGracePeriodCriticalPods metav1.Duration

    // ShutdownGracePeriodByPodPriority：根据关联的优先级类值指定Pod的关机宽限期。
    // 当收到关机请求时，Kubelet将根据Pod的优先级启动关机，等待所有Pod退出，并具有依赖于Pod优先级的优雅终止时间间隔。
    // 数组中的每个条目表示具有在节点关闭时位于该值范围及下一个更高条目之间的优先级类值的Pod的优雅关机时间。
    ShutdownGracePeriodByPodPriority []ShutdownGracePeriodByPodPriority

    // ReservedMemory：指定NUMA节点的内存预留的逗号分隔列表。
    // 此参数仅在内存管理器功能上下文中有意义。内存管理器不会为容器工作负载分配保留的内存。
    // 例如，如果您有一个具有10Gi内存的NUMA0节点，并且指定了ReservedMemory以在NUMA0上预留1Gi内存，
    // 则内存管理器将假定可供分配的内存只有9Gi。
    // 您可以指定不同数量的NUMA节点和内存类型。
    // 您可以完全省略此参数，但是您应该知道所有NUMA节点的保留内存量应等于节点可分配特性。
    // 如果至少有一个节点可分配参数具有非零值，则需要指定至少一个NUMA节点。
    // 同时，请避免指定：
    // 1. 重复项，即相同的NUMA节点和内存类型，但具有不同的值。
    // 2. 任何内存类型的零限制。
    // 3. 不存在于机器下的NUMA节点ID。
    // 4. 内存类型（除内存和hugepages-<size>外）。
    ReservedMemory []MemoryReservation

    // EnableProfilingHandler：启用/debug/pprof处理程序。
    EnableProfilingHandler bool

    // EnableDebugFlagsHandler：启用/debug/flags/v处理程序。
    EnableDebugFlagsHandler bool

    // SeccompDefault：启用将RuntimeDefault用作所有工作负载的默认Seccomp配置文件。
    SeccompDefault bool

    // MemoryThrottlingFactor：在设置cgroupv2 memory.high值以执行MemoryQoS时，将内存限制或节点可分配内存乘以的因子。
    // 减小此因子将为容器cgroup设置较低的高限制，并施加更大的回收压力；
    // 增大此因子将施加较少的回收压力。
    // 有关更多详细信息，请参阅https://kep.k8s.io/2570。
    // 默认值为0.9。
    // +featureGate=MemoryQoS
    // +optional
    MemoryThrottlingFactor *float64

    // RegisterWithTaints：在kubelet注册时向节点对象添加的污点数组。
    // 仅当RegisterNode为true并且在节点的初始注册时生效。
    // +optional
    RegisterWithTaints []v1.Taint

    // RegisterNode：启用与apiserver的自动注册。
    // +optional
    RegisterNode bool

    // Tracing：指定OpenTelemetry跟踪客户端的版本化配置。
    // 有关更多详细信息，请参阅https://kep.k8s.io/2832。
    // +featureGate=KubeletTracing
    // +optional
    Tracing *tracingapi.TracingConfiguration

    // LocalStorageCapacityIsolation：启用本地临时存储隔离功能。默认设置为true。
    // 此功能允许用户为容器的临时存储设置请求/限制，并以类似于CPU和内存的方式进行管理。
    // 它还允许设置emptyDir卷的sizeLimit，如果卷的磁盘使用超过限制，则会触发Pod驱逐。
    // 此功能依赖于检测正确的根文件系统磁盘使用情况的能力。
    // 对于某些系统（例如kind rootless），如果无法支持此功能，则应禁用LocalStorageCapacityIsolation。
    // 一旦禁用，用户不应设置容器的临时存储的请求/限制，或者emptyDir的sizeLimit。
    // +optional
    LocalStorageCapacityIsolation bool

    // ContainerRuntimeEndpoint：容器运行时的端点。
    // 在Linux上支持Unix域套接字，而在Windows上支持npipes和tcp端点。
    // 例如：'unix:///path/to/runtime.sock'，'npipe:////./pipe/runtime'。
    ContainerRuntimeEndpoint string

    // ImageServiceEndpoint：容器镜像服务的端点。
    // 如果未指定，默认值为ContainerRuntimeEndpoint。
    // +optional
    ImageServiceEndpoint string
}
```

#### NewKubeletConfiguration

```go
// NewKubeletConfiguration will create a new KubeletConfiguration with default values
// 创建一个具有默认值的新KubeletConfiguration
func NewKubeletConfiguration() (*kubeletconfig.KubeletConfiguration, error) {
	// 创建一个新的Scheme和Codec
	scheme, _, err := kubeletscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}

	// 创建一个v1beta1版本的KubeletConfiguration对象
	versioned := &v1beta1.KubeletConfiguration{}
	// 为versioned对象设置默认值
	scheme.Default(versioned)

	// 创建一个KubeletConfiguration对象
	config := &kubeletconfig.KubeletConfiguration{}
	// 将versioned对象转换为config对象
	if err := scheme.Convert(versioned, config, nil); err != nil {
		return nil, err
	}

	// 应用遗留的默认值到KubeletConfiguration
	applyLegacyDefaults(config)

	// 返回config对象和nil作为错误值
	return config, nil
}
```

##### applyLegacyDefaults

```go
// applyLegacyDefaults将遗留的默认值应用到KubeletConfiguration中，以保留命令行API。
// 这用于在第一轮标志解析之前构造基线默认的KubeletConfiguration。
func applyLegacyDefaults(kc *kubeletconfig.KubeletConfiguration) {
	// 设置 --anonymous-auth 标志为true
	kc.Authentication.Anonymous.Enabled = true
	// 设置 --authentication-token-webhook 标志为false
	kc.Authentication.Webhook.Enabled = false
	// 设置 --authorization-mode 标志为kubeletconfig.KubeletAuthorizationModeAlwaysAllow
	kc.Authorization.Mode = kubeletconfig.KubeletAuthorizationModeAlwaysAllow
	// 设置 --read-only-port 标志为ports.KubeletReadOnlyPort
	kc.ReadOnlyPort = ports.KubeletReadOnlyPort
}
```

##### Scheme

```go
// Scheme定义了序列化和反序列化API对象的方法，用于将组、版本和类型信息与Go schemas之间进行转换，
// 以及不同版本的Go schemas之间的映射。Scheme是版本化API和版本化配置的基础。
//
// 在Scheme中，Type是特定的Go结构体，Version是表示该Type的特定时间点的标识符（通常是向后兼容的），
// Kind是该Type在Version中的唯一名称，Group标识一组随时间演变的Versions、Kinds和Types。
// Unversioned Type是尚未正式绑定到类型的Type，并承诺向后兼容（实际上是Type的“v1”，不希望在将来发生变化）。
//
// Scheme在运行时不会发生变化，并且只有在注册完成后才能线程安全。
type Scheme struct {
	// gvkToType允许根据给定的version和name找到对象的go类型。
	gvkToType map[schema.GroupVersionKind]reflect.Type

	// typeToGVK允许找到给定go对象的元数据。
	// 我们索引的reflect.Type *不*应该是指针。
	typeToGVK map[reflect.Type][]schema.GroupVersionKind

	// unversionedTypes在ConvertToVersion中无需进行转换即可进行转换。
	unversionedTypes map[reflect.Type]schema.GroupVersionKind

	// unversionedKinds是在任何组或版本上下文中创建的Kinds的名称集。
	// TODO: 解决unversioned types的状态。
	unversionedKinds map[string]reflect.Type

	// Map from version and resource to the corresponding func to convert
	// resource field labels in that version to internal version.
	fieldLabelConversionFuncs map[schema.GroupVersionKind]FieldLabelConversionFunc

	// defaulterFuncs是一个map，用于提供默认值的函数，该函数将被调用以提供默认值。
	// 提供的对象必须是指针。
	defaulterFuncs map[reflect.Type]func(interface{})

	// converter存储所有注册的转换函数。它还具有默认的转换行为。
	converter *conversion.Converter

	// versionPriority是一个map，将组映射为按优先级排序的版本列表，指示这些版本的默认优先级，
	// 这些版本在scheme中注册时的顺序
	versionPriority map[string][]string

	// observedVersions跟踪我们在类型注册过程中看到的版本的顺序
	observedVersions []schema.GroupVersion

	// schemeName是该scheme的名称。如果不指定名称，则将使用NewScheme调用者的堆栈。
	// 这对于错误报告非常有用，以指示scheme的起源。
	schemeName string
}

// NewSchemeAndCodecs是一个实用函数，返回一个理解kubeletconfig API组中类型的Scheme和CodecFactory。
// 通过传递mutators来调整CodecFactory的行为，例如启用严格解码。
func NewSchemeAndCodecs(mutators ...serializer.CodecFactoryOptionsMutator) (*runtime.Scheme, *serializer.CodecFactory, error) {
	// 创建一个新的Scheme
	scheme := runtime.NewScheme()

	// 将kubeletconfig类型添加到Scheme中
	if err := kubeletconfig.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}

	// 将kubeletconfigv1beta1类型添加到Scheme中
	if err := kubeletconfigv1beta1.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}

	// 将kubeletconfigv1类型添加到Scheme中
	if err := kubeletconfigv1.AddToScheme(scheme); err != nil {
		return nil, nil, err
	}

	// 创建一个CodecFactory，使用Scheme和mutators作为参数
	codecs := serializer.NewCodecFactory(scheme, mutators...)

	// 返回Scheme、CodecFactory和nil作为错误值
	return scheme, &codecs, nil
}
```

### Dependencies

```go
// UnsecuredDependencies返回一个适用于运行的Dependencies，如果服务器设置无效则返回错误。
// 它不会启动任何后台进程，也不包括身份验证/授权。
func UnsecuredDependencies(s *options.KubeletServer, featureGate featuregate.FeatureGate) (*kubelet.Dependencies, error) {
	// 初始化TLS选项
	tlsOptions, err := InitializeTLS(&s.KubeletFlags, &s.KubeletConfiguration)
	if err != nil {
		return nil, err
	}

	mounter := mount.New(s.ExperimentalMounterPath)
	subpather := subpath.New(mounter)
	hu := hostutil.NewHostUtil()
	var pluginRunner = exec.New()

	plugins, err := ProbeVolumePlugins(featureGate)
	if err != nil {
		return nil, err
	}
	tp := oteltrace.NewNoopTracerProvider()
	if utilfeature.DefaultFeatureGate.Enabled(features.KubeletTracing) {
		tp, err = newTracerProvider(s)
		if err != nil {
			return nil, err
		}
	}

	// 返回Dependencies结构的指针，其中包含各种依赖项对象
	return &kubelet.Dependencies{
		Auth:                nil, // 默认情况下不强制执行身份验证
		CAdvisorInterface:   nil, // cadvisor.New启动后台进程（bg http.ListenAndServe和一些bg清理器），这里没有设置
		Cloud:               nil, // 云提供商可能启动后台进程
		ContainerManager:    nil,
		KubeClient:          nil,
		HeartbeatClient:     nil,
		EventClient:         nil,
		TracerProvider:      tp,
		HostUtil:            hu,
		Mounter:             mounter,
		Subpather:           subpather,
		OOMAdjuster:         oom.NewOOMAdjuster(),
		OSInterface:         kubecontainer.RealOS{},
		VolumePlugins:       plugins,
		DynamicPluginProber: GetDynamicPluginProber(s.VolumePluginDir, pluginRunner),
		TLSOptions:          tlsOptions}, nil
}

// Dependencies是我们可能考虑为“注入依赖项”的容器，其中包含了运行Kubelet所必需的在运行时构建的对象。
// 这是一个临时解决方案，用于在我们找出更全面的Kubelet依赖注入机制之前，对这些对象进行分组。
type Dependencies struct {
	Options []Option

	// 注入的依赖项
	Auth                     server.AuthInterface
	CAdvisorInterface        cadvisor.Interface
	Cloud                    cloudprovider.Interface
	ContainerManager         cm.ContainerManager
	EventClient              v1core.EventsGetter
	HeartbeatClient          clientset.Interface
	OnHeartbeatFailure       func()
	KubeClient               clientset.Interface
	Mounter                  mount.Interface
	HostUtil                 hostutil.HostUtils
	OOMAdjuster              *oom.OOMAdjuster
	OSInterface              kubecontainer.OSInterface
	PodConfig                *config.PodConfig
	ProbeManager             prober.Manager
	Recorder                 record.EventRecorder
	Subpather                subpath.Interface
	TracerProvider           trace.TracerProvider
	VolumePlugins            []volume.VolumePlugin
	DynamicPluginProber      volume.DynamicPluginProber
	TLSOptions               *server.TLSOptions
	RemoteRuntimeService     internalapi.RuntimeService
	RemoteImageService       internalapi.ImageManagerService
	PodStartupLatencyTracker util.PodStartupLatencyTracker
	// 在cadvisor.UsingLegacyCadvisorStats被弃用后移除。
	useLegacyCadvisorStats bool
}
```

### Run

```go
// Run函数运行指定的KubeletServer和给定的Dependencies。该函数不应该退出。
// kubeDeps参数可以为nil-如果是nil，则从KubeletServer的设置中进行初始化。
// 否则，假定调用方已经设置了Dependencies对象，不会生成默认的Dependencies对象。
func Run(ctx context.Context, s *options.KubeletServer, kubeDeps *kubelet.Dependencies, featureGate featuregate.FeatureGate) error {
    // 为了帮助调试，立即记录版本信息
    klog.InfoS("Kubelet版本", "kubeletVersion", version.Get())
    // 记录Golang的设置信息
    klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

    // 如果初始化操作系统相关设置失败，则返回错误
    if err := initForOS(s.KubeletFlags.WindowsService, s.KubeletFlags.WindowsPriorityClass); err != nil {
        return fmt.Errorf("failed OS init: %w", err)
    }

    // 运行Kubelet
    if err := run(ctx, s, kubeDeps, featureGate); err != nil {
        return fmt.Errorf("failed to run Kubelet: %w", err)
    }

    return nil
}
```

#### run

```go
func run(ctx context.Context, s *options.KubeletServer, kubeDeps *kubelet.Dependencies, featureGate featuregate.FeatureGate) (err error) {
    // 根据初始的 KubeletServer 设置全局的功能门控
    err = utilfeature.DefaultMutableFeatureGate.SetFromMap(s.KubeletConfiguration.FeatureGates)
    if err != nil {
    	return err
    }
    // 验证初始的 KubeletServer（因为这个验证依赖于功能门控的设置，所以我们首先设置功能门控）
    if err := options.ValidateKubeletServer(s); err != nil {
        return err
    }

    // 如果启用了 MemoryQoS 且 cgroups v1 模式下，发出警告
    if utilfeature.DefaultFeatureGate.Enabled(features.MemoryQoS) &&
        !isCgroup2UnifiedMode() {
        klog.InfoS("Warning: MemoryQoS feature only works with cgroups v2 on Linux, but enabled with cgroups v1")
    }

    // 如果要求在文件锁争用时退出但未指定锁文件路径，返回错误
    if s.ExitOnLockContention && s.LockFilePath == "" {
        return errors.New("cannot exit on lock file contention: no lock file specified")
    }

    done := make(chan struct{})
    // 如果指定了锁文件路径，获取锁文件
    if s.LockFilePath != "" {
        klog.InfoS("Acquiring file lock", "path", s.LockFilePath)
        if err := flock.Acquire(s.LockFilePath); err != nil {
            return fmt.Errorf("unable to acquire file lock on %q: %w", s.LockFilePath, err)
        }
        // 如果要求在锁文件争用时退出，监视锁文件内容的变化
        if s.ExitOnLockContention {
            klog.InfoS("Watching for inotify events", "path", s.LockFilePath)
            if err := watchForLockfileContention(s.LockFilePath, done); err != nil {
                return err
            }
        }
    }

    // 使用初始的 Kubelet 配置在 /configz 端点注册当前配置
    err = initConfigz(&s.KubeletConfiguration)
    if err != nil {
        klog.ErrorS(err, "Failed to register kubelet configuration with configz")
    }

    // 如果设置了 ShowHiddenMetricsForVersion，显示隐藏指标
    if len(s.ShowHiddenMetricsForVersion) > 0 {
        metrics.SetShowHidden()
    }

    // 准备获取客户端等操作之前，检测是否处于独立模式
    standaloneMode := true
    if len(s.KubeConfig) > 0 {
        standaloneMode = false
    }

    // 如果未提供 kubeDeps，则构建 UnsecuredDependencies
    if kubeDeps == nil {
        kubeDeps, err = UnsecuredDependencies(s, featureGate)
        if err != nil {
            return err
        }
    }

    // 如果 kubeDeps 中的 Cloud 为 nil，则根据 CloudProvider 初始化 cloud
    if kubeDeps.Cloud == nil {
        // 如果kubeDeps.Cloud为nil，则执行以下代码块
        if !cloudprovider.IsExternal(s.CloudProvider) {
            // 如果s.CloudProvider不是外部提供商，则执行以下代码块
            cloudprovider.DeprecationWarningForProvider(s.CloudProvider)
            // 发出有关提供程序过时的警告
            cloud, err := cloudprovider.InitCloudProvider(s.CloudProvider, s.CloudConfigFile)
            // 初始化云提供程序
            if err != nil {
                return err
            }
            if cloud != nil {
                // 如果云提供程序不为nil，则记录成功初始化云提供程序的信息
                klog.V(2).InfoS("Successfully initialized cloud provider", "cloudProvider", s.CloudProvider, "cloudConfigFile", s.CloudConfigFile)
            }
            kubeDeps.Cloud = cloud
        }
    }

    hostName, err := nodeutil.GetHostname(s.HostnameOverride)
    // 获取主机名
    if err != nil {
        return err
    }
    nodeName, err := getNodeName(kubeDeps.Cloud, hostName)
    // 根据云提供程序和主机名获取节点名
    if err != nil {
        return err
    }

    // 如果在独立模式下，将所有客户端设置为nil
    switch {
    case standaloneMode:
        kubeDeps.KubeClient = nil
        kubeDeps.EventClient = nil
        kubeDeps.HeartbeatClient = nil
        klog.InfoS("Standalone mode, no API client")
    // 如果kubeDeps.KubeClient，kubeDeps.EventClient或kubeDeps.HeartbeatClient为nil
    case kubeDeps.KubeClient == nil, kubeDeps.EventClient == nil, kubeDeps.HeartbeatClient == nil:
        clientConfig, onHeartbeatFailure, err := buildKubeletClientConfig(ctx, s, kubeDeps.TracerProvider, nodeName)
        // 构建kubelet客户端配置
        if err != nil {
            return err
        }
        if onHeartbeatFailure == nil {
            return errors.New("onHeartbeatFailure must be a valid function other than nil")
        }
        kubeDeps.OnHeartbeatFailure = onHeartbeatFailure

        kubeDeps.KubeClient, err = clientset.NewForConfig(clientConfig)
        // 使用客户端配置创建kubelet客户端
        if err != nil {
            return fmt.Errorf("failed to initialize kubelet client: %w", err)
        }

        // 创建用于事件的单独客户端
        eventClientConfig := *clientConfig
        eventClientConfig.QPS = float32(s.EventRecordQPS)
        eventClientConfig.Burst = int(s.EventBurst)
        kubeDeps.EventClient, err = v1core.NewForConfig(&eventClientConfig)
        if err != nil {
            return fmt.Errorf("failed to initialize kubelet event client: %w", err)
        }

        // 创建用于心跳的单独客户端，禁用速率限制并附加超时
        heartbeatClientConfig := *clientConfig
        heartbeatClientConfig.Timeout = s.KubeletConfiguration.NodeStatusUpdateFrequency.Duration
        // 计算超时时间，取节点租约时长和状态更新频率的较小值作为超时时间
		leaseTimeout := time.Duration(s.KubeletConfiguration.NodeLeaseDurationSeconds) * time.Second
		if heartbeatClientConfig.Timeout > leaseTimeout {
			heartbeatClientConfig.Timeout = leaseTimeout
		}
		// 设置心跳客户端的QPS为-1
		heartbeatClientConfig.QPS = float32(-1)
		kubeDeps.HeartbeatClient, err = clientset.NewForConfig(&heartbeatClientConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize kubelet heartbeat client: %w", err)
		}
	}
	// 如果认证组件未初始化，则构建认证组件
	if kubeDeps.Auth == nil {
		auth, runAuthenticatorCAReload, err := BuildAuth(nodeName, kubeDeps.KubeClient, s.KubeletConfiguration)
		if err != nil {
			return err
		}
		kubeDeps.Auth = auth
		runAuthenticatorCAReload(ctx.Done())
	}

	var cgroupRoots []string
    // 根据配置获取节点可分配资源的cgroup路径，并添加到cgroupRoots中
	nodeAllocatableRoot := cm.NodeAllocatableRoot(s.CgroupRoot, s.CgroupsPerQOS, s.CgroupDriver)
	cgroupRoots = append(cgroupRoots, nodeAllocatableRoot)
	kubeletCgroup, err := cm.GetKubeletContainer(s.KubeletCgroups)
	if err != nil {
		klog.InfoS("Failed to get the kubelet's cgroup. Kubelet system container metrics may be missing.", "err", err)
	} else if kubeletCgroup != "" {
        // 如果kubeletCgroup不为空，则将其添加到cgroupRoots中
		cgroupRoots = append(cgroupRoots, kubeletCgroup)
	}

	if s.RuntimeCgroups != "" {
		// RuntimeCgroups是可选的，如果未指定则忽略
		cgroupRoots = append(cgroupRoots, s.RuntimeCgroups)
	}

	if s.SystemCgroups != "" {
		// SystemCgroups是可选的，如果未指定则忽略
		cgroupRoots = append(cgroupRoots, s.SystemCgroups)
	}
	// 如果CAdvisorInterface未初始化，则根据配置创建CAdvisorInterface
	if kubeDeps.CAdvisorInterface == nil {
		imageFsInfoProvider := cadvisor.NewImageFsInfoProvider(s.ContainerRuntimeEndpoint)
		kubeDeps.CAdvisorInterface, err = cadvisor.New(imageFsInfoProvider, s.RootDirectory, cgroupRoots, cadvisor.UsingLegacyCadvisorStats(s.ContainerRuntimeEndpoint), s.LocalStorageCapacityIsolation)
		if err != nil {
			return err
		}
	}

	// 如果需要，设置事件记录器
	makeEventRecorder(kubeDeps, nodeName)
	// 如果ContainerManager未初始化，则根据配置创建ContainerManager
	if kubeDeps.ContainerManager == nil {
		if s.CgroupsPerQOS && s.CgroupRoot == "" {
			klog.InfoS("--cgroups-per-qos enabled, but --cgroup-root was not specified.  defaulting to /")
			s.CgroupRoot = "/"
		}

		machineInfo, err := kubeDeps.CAdvisorInterface.MachineInfo()
		if err != nil {
			return err
		}
		reservedSystemCPUs, err := getReservedCPUs(machineInfo, s.ReservedSystemCPUs)
		if err != nil {
			return err
		}
		if reservedSystemCPUs.Size() > 0 {
			// 在命令行选项验证阶段已经测试了--system-reserved-cgroup或--kube-reserved-cgroup是否已指定，所以覆盖
			klog.InfoS("Option --reserved-cpus is specified, it will overwrite the cpu setting in KubeReserved and SystemReserved", "kubeReservedCPUs", s.KubeReserved, "systemReservedCPUs", s.SystemReserved)
			if s.KubeReserved != nil {
				delete(s.KubeReserved, "cpu")
			}
			if s.SystemReserved == nil {
				s.SystemReserved = make(map[string]string)
			}
			s.SystemReserved["cpu"] = strconv.Itoa(reservedSystemCPUs.Size())
			klog.InfoS("After cpu setting is overwritten", "kubeReservedCPUs", s.KubeReserved, "systemReservedCPUs", s.SystemReserved)
		}

		kubeReserved, err := parseResourceList(s.KubeReserved)
		if err != nil {
			return fmt.Errorf("--kube-reserved value failed to parse: %w", err)
		}
		systemReserved, err := parseResourceList(s.SystemReserved)
		if err != nil {
			return fmt.Errorf("--system-reserved value failed to parse: %w", err)
		}
		var hardEvictionThresholds []evictionapi.Threshold
		// 如果用户请求忽略驱逐阈值，则不在这里设置hardEvictionThresholds的有效值
		if !s.ExperimentalNodeAllocatableIgnoreEvictionThreshold {
			hardEvictionThresholds, err = eviction.ParseThresholdConfig([]string{}, s.EvictionHard, nil, nil, nil)
			if err != nil {
				return err
			}
		}
		experimentalQOSReserved, err := cm.ParseQOSReserved(s.QOSReserved)
		if err != nil {
			return fmt.Errorf("--qos-reserved value failed to parse: %w", err)
		}

		var cpuManagerPolicyOptions map[string]string
		if utilfeature.DefaultFeatureGate.Enabled(features.CPUManagerPolicyOptions) {
			cpuManagerPolicyOptions = s.CPUManagerPolicyOptions
		} else if s.CPUManagerPolicyOptions != nil {
			return fmt.Errorf("CPU Manager policy options %v require feature gates %q, %q enabled",
				s.CPUManagerPolicyOptions, features.CPUManager, features.CPUManagerPolicyOptions)
		}

		var topologyManagerPolicyOptions map[string]string
		if utilfeature.DefaultFeatureGate.Enabled(features.TopologyManagerPolicyOptions) {
			topologyManagerPolicyOptions = s.TopologyManagerPolicyOptions
		} else if s.TopologyManagerPolicyOptions != nil {
			return fmt.Errorf("topology manager policy options %v require feature gates %q enabled",
				s.TopologyManagerPolicyOptions, features.TopologyManagerPolicyOptions)
		}

		kubeDeps.ContainerManager, err = cm.NewContainerManager(
			kubeDeps.Mounter,
			kubeDeps.CAdvisorInterface,
			cm.NodeConfig{
				RuntimeCgroupsName:    s.RuntimeCgroups,
				SystemCgroupsName:     s.SystemCgroups,
				KubeletCgroupsName:    s.KubeletCgroups,
				KubeletOOMScoreAdj:    s.OOMScoreAdj,
				CgroupsPerQOS:         s.CgroupsPerQOS,
				CgroupRoot:            s.CgroupRoot,
				CgroupDriver:          s.CgroupDriver,
				KubeletRootDir:        s.RootDirectory,
				ProtectKernelDefaults: s.ProtectKernelDefaults,
				NodeAllocatableConfig: cm.NodeAllocatableConfig{
					KubeReservedCgroupName:   s.KubeReservedCgroup,
					SystemReservedCgroupName: s.SystemReservedCgroup,
					EnforceNodeAllocatable:   sets.NewString(s.EnforceNodeAllocatable...),
					KubeReserved:             kubeReserved,
					SystemReserved:           systemReserved,
					ReservedSystemCPUs:       reservedSystemCPUs,
					HardEvictionThresholds:   hardEvictionThresholds,
				},
				QOSReserved:                              *experimentalQOSReserved,
				CPUManagerPolicy:                         s.CPUManagerPolicy,
				CPUManagerPolicyOptions:                  cpuManagerPolicyOptions,
				CPUManagerReconcilePeriod:                s.CPUManagerReconcilePeriod.Duration,
				ExperimentalMemoryManagerPolicy:          s.MemoryManagerPolicy,
				ExperimentalMemoryManagerReservedMemory:  s.ReservedMemory,
				PodPidsLimit:                             s.PodPidsLimit,
				EnforceCPULimits:                         s.CPUCFSQuota,
				CPUCFSQuotaPeriod:                        s.CPUCFSQuotaPeriod.Duration,
				TopologyManagerPolicy:                    s.TopologyManagerPolicy,
				TopologyManagerScope:                     s.TopologyManagerScope,
				ExperimentalTopologyManagerPolicyOptions: topologyManagerPolicyOptions,
			},
			s.FailSwapOn,
			kubeDeps.Recorder,
			kubeDeps.KubeClient,
		)

		if err != nil {
			return err
		}
	}

	if kubeDeps.PodStartupLatencyTracker == nil {
		kubeDeps.PodStartupLatencyTracker = kubeletutil.NewPodStartupLatencyTracker()
	}

	// TODO(vmarmol): 通过容器配置完成此操作。
	oomAdjuster := kubeDeps.OOMAdjuster
	if err := oomAdjuster.ApplyOOMScoreAdj(0, int(s.OOMScoreAdj)); err != nil {
		klog.InfoS("Failed to ApplyOOMScoreAdj", "err", err)
	}

	err = kubelet.PreInitRuntimeService(&s.KubeletConfiguration, kubeDeps)
	if err != nil {
		return err
	}

	if err := RunKubelet(s, kubeDeps, s.RunOnce); err != nil {
		return err
	}

	if s.HealthzPort > 0 {
		mux := http.NewServeMux()
		healthz.InstallHandler(mux)
		go wait.Until(func() {
			err := http.ListenAndServe(net.JoinHostPort(s.HealthzBindAddress, strconv.Itoa(int(s.HealthzPort))), mux)
			if err != nil {
				klog.ErrorS(err, "Failed to start healthz server")
			}
		}, 5*time.Second, wait.NeverStop)
	}

	if s.RunOnce {
		return nil
	}

	// 如果使用systemd，通知它我们已经启动
	go daemon.SdNotify(false, "READY=1")

	select {
	case <-done:
		break
	case <-ctx.Done():
		break
	}

	return nil
}
```

##### GetHostname

```go
// GetHostname函数根据'hostnameOverride'的值返回操作系统的主机名。如果'hostnameOverride'为空，则返回操作系统的主机名。
// 无论哪种情况，返回的值都经过规范化处理（修剪空白字符并转换为小写）。
func GetHostname(hostnameOverride string) (string, error) {
    hostName := hostnameOverride
    if len(hostName) == 0 {
        nodeName, err := os.Hostname()
        if err != nil {
        	return "", fmt.Errorf("couldn't determine hostname: %w", err)
        }
        hostName = nodeName
    }

    // 首先修剪空白字符，以避免得到一个空的主机名
    // 对于Linux系统，主机名直接从文件/proc/sys/kernel/hostname中读取
    hostName = strings.TrimSpace(hostName)
    if len(hostName) == 0 {
        return "", fmt.Errorf("empty hostname is invalid")
    }

    return strings.ToLower(hostName), nil
}
```

##### getNodeName

```go
// getNodeName函数根据云提供商返回节点名称（如果指定了云提供商）。否则，返回节点的主机名。
func getNodeName(cloud cloudprovider.Interface, hostname string) (types.NodeName, error) {
    if cloud == nil {
        return types.NodeName(hostname), nil
    }

	instances, ok := cloud.Instances()
    if !ok {
        return "", fmt.Errorf("failed to get instances from cloud provider")
    }

    nodeName, err := instances.CurrentNodeName(context.TODO(), hostname)
    if err != nil {
        return "", fmt.Errorf("error fetching current node name from cloud provider: %w", err)
    }

    klog.V(2).InfoS("Cloud provider determined current node", "nodeName", klog.KRef("", string(nodeName)))

    return nodeName, nil
}
```

##### NodeAllocatableRoot

```go
// NodeAllocatableRoot函数返回节点可分配资源的cgroup路径。
func NodeAllocatableRoot(cgroupRoot string, cgroupsPerQOS bool, cgroupDriver string) string {
    // 解析cgroup根路径为cgroup名称
    nodeAllocatableRoot := ParseCgroupfsToCgroupName(cgroupRoot)
    if cgroupsPerQOS {
        // 如果启用了QoS cgroup，将默认的节点可分配资源cgroup名称添加到根路径
        nodeAllocatableRoot = NewCgroupName(nodeAllocatableRoot, defaultNodeAllocatableCgroupName)
    }
    if cgroupDriver == "systemd" {
        // 将cgroup名称转换为systemd格式
        return nodeAllocatableRoot.ToSystemd()
    }
    // 返回cgroup名称的cgroupfs形式
    return nodeAllocatableRoot.ToCgroupfs()
}
```

###### ParseCgroupfsToCgroupName

```go
// ParseCgroupfsToCgroupName函数将cgroupfs路径解析为cgroup名称
func ParseCgroupfsToCgroupName(name string) CgroupName {
    // 根据"/"分割组件，去除前缀"/"后再进行分割
    components := strings.Split(strings.TrimPrefix(name, "/"), "/")
    if len(components) == 1 && components[0] == "" {
    	components = []string{}
    }
    return CgroupName(components)
}
```

###### NewCgroupName

```go
// NewCgroupName函数组合一个新的cgroup名称。
func NewCgroupName(base CgroupName, components ...string) CgroupName {
    for , component := range components {
        // 禁止在内部名称中使用""
        // 当将内部名称重新映射到systemd cgroup驱动程序时，我们想将"-"重新映射为""，因此我们禁止""
        if strings.Contains(component, "/") || strings.Contains(component, "_") {
        	panic(fmt.Errorf("invalid character in component [%q] of CgroupName", component))
        }
    }
    return CgroupName(append(append([]string{}, base...), components...))
}
```

###### ToSystemd

```go
// cgroupName.ToSystemd将内部cgroup名称转换为systemd名称。
func (cgroupName CgroupName) ToSystemd() string {
    if len(cgroupName) == 0 || (len(cgroupName) == 1 && cgroupName[0] == "") {
    	return "/"
    }
    newparts := []string{}
    for _, part := range cgroupName {
        part = escapeSystemdCgroupName(part)
        newparts = append(newparts, part)
    }

    result, err := cgroupsystemd.ExpandSlice(strings.Join(newparts, "-") + systemdSuffix)
    if err != nil {
        // 应该不会发生...
        panic(fmt.Errorf("error converting cgroup name [%v] to systemd format: %v", cgroupName, err))
    }
    return result
}
```

###### escapeSystemdCgroupName&unescapeSystemdCgroupName&ToCgroupfs

```go
// escapeSystemdCgroupName函数对systemd cgroup名称进行转义
func escapeSystemdCgroupName(part string) string {
	return strings.Replace(part, "-", "_", -1)
}

// unescapeSystemdCgroupName函数对systemd cgroup名称进行反转义
func unescapeSystemdCgroupName(part string) string {
	return strings.Replace(part, "_", "-", -1)
}

// cgroupName.ToCgroupfs将cgroup名称转换为cgroupfs形式的路径
func (cgroupName CgroupName) ToCgroupfs() string {
	return "/" + path.Join(cgroupName...)
}
```

##### GetKubeletContainer

```go
// GetKubeletContainer函数返回kubelet将使用的cgroup。
func GetKubeletContainer(kubeletCgroups string) (string, error) {
    if kubeletCgroups == "" {
        // 如果未指定kubeletCgroups，则获取当前进程的cgroup
        cont, err := getContainer(os.Getpid())
        if err != nil {
            return "", err
        }
        return cont, nil
    }
    // 返回指定的kubeletCgroups
 	return kubeletCgroups, nil
}
```

###### getContainer

```go
// getContainer函数返回与指定pid相关联的cgroup。
// 它强制使用统一的内存和CPU cgroup层次结构。
// 在systemd环境中，它使用指定pid的name=systemd cgroup。
func getContainer(pid int) (string, error) {
    // 解析指定pid的cgroup文件
    cgs, err := cgroups.ParseCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
    if err != nil {
    	return "", err
    }
    if cgroups.IsCgroup2UnifiedMode() {
        // 在统一模式下，获取空字符串键对应的cgroup路径
        c, found := cgs[""]
        if !found {
            return "", cgroups.NewNotFoundError("unified")
        }
        return c, nil
    }

    // 获取cpu和memory cgroup路径
    cpu, found := cgs["cpu"]
    if !found {
        return "", cgroups.NewNotFoundError("cpu")
    }
    memory, found := cgs["memory"]
    if !found {
        return "", cgroups.NewNotFoundError("memory")
    }

    // 检查cpu和memory cgroup路径是否统一
    if cpu != memory {
        return "", fmt.Errorf("cpu和memory cgroup层次结构不统一。cpu: %s, memory: %s", cpu, memory)
    }

    // 在systemd环境中，每个pid都位于一个统一的cgroup层次结构中（如systemd-cgls中的name=systemd）
    // 默认情况下，CPU和内存的账户是关闭的，用户可以选择在单元或全局范围内启用它。
    // 用户可以通过/etc/systemd/system.conf（DefaultCPUAccounting=true DefaultMemoryAccounting=true）全局启用CPU和内存账户。
    // 用户也可以通过CPUAccounting=true和MemoryAccounting=true在每个单元上启用CPU和内存账户。
    // 我们只在未启用CPU或内存账户时发出警告，以避免中断在终端中启动kubelet的本地开发流程。
    // 例如，在以docker容器启动的系统上，用户会话的cgroup可能类似于/user.slice/user-X.slice/session-X.scope，
    // 但是最近的具有进行账户的CPU和内存cgroup将是cpu和memory的最近祖先（很可能是/）。
    // 因此，在这些系统上，您将无法获得kubelet的CPU或内存账户统计信息。
    // 另外，除非在其单元上启用了账户，否则也不会为运行时获得内存或CPU账户。
    if systemd, found := cgs["name=systemd"]; found {
        if systemd != cpu {
            klog.InfoS("未为进程启用CPUAccounting", "pid", pid)
        }
        if systemd != memory {
            klog.InfoS("未为进程启用MemoryAccounting", "pid", pid)
        }
        return systemd, nil
    }

    return cpu, nil
}
```

##### getReservedCPUs

````go
// getReservedCPUs 根据给定的 machineInfo 和 cpus 字符串，获取保留的 CPU 核心集合。
func getReservedCPUs(machineInfo *cadvisorapi.MachineInfo, cpus string) (cpuset.CPUSet, error) {
	emptyCPUSet := cpuset.New()

	// 如果 cpus 字符串为空，则直接返回空的 CPU 核心集合。
	if cpus == "" {
		return emptyCPUSet, nil
	}

	// 使用 topology.Discover 函数获取 CPU 拓扑信息。
	topo, err := topology.Discover(machineInfo)
	if err != nil {
		return emptyCPUSet, fmt.Errorf("unable to discover CPU topology info: %s", err)
	}

	// 解析 cpus 字符串为 reservedCPUSet，表示保留的 CPU 核心集合。
	reservedCPUSet, err := cpuset.Parse(cpus)
	if err != nil {
		return emptyCPUSet, fmt.Errorf("unable to parse reserved-cpus list: %s", err)
	}

	// 获取所有在线的 CPU 核心集合。
	allCPUSet := topo.CPUDetails.CPUs()

	// 检查 reservedCPUSet 是否是 allCPUSet 的子集。
	if !reservedCPUSet.IsSubsetOf(allCPUSet) {
		return emptyCPUSet, fmt.Errorf("reserved-cpus: %s is not a subset of online-cpus: %s", cpus, allCPUSet.String())
	}

	return reservedCPUSet, nil
}
````

##### parseResourceList

```go
// parseResourceList 将给定的配置映射解析为 API 的 ResourceList 或返回错误。
func parseResourceList(m map[string]string) (v1.ResourceList, error) {
	if len(m) == 0 {
		return nil, nil
	}

	// 创建一个 ResourceList 对象 rl。
	rl := make(v1.ResourceList)

	// 遍历配置映射 m 中的键值对。
	for k, v := range m {
		switch v1.ResourceName(k) {
		// 支持 CPU、内存、本地存储和 PID 资源。
		case v1.ResourceCPU, v1.ResourceMemory, v1.ResourceEphemeralStorage, pidlimit.PIDs:
			// 解析 v 为 Quantity 对象 q。
			q, err := resource.ParseQuantity(v)
			if err != nil {
				return nil, fmt.Errorf("failed to parse quantity %q for %q resource: %w", v, k, err)
			}

			// 检查 q 是否为负数。
			if q.Sign() == -1 {
				return nil, fmt.Errorf("resource quantity for %q cannot be negative: %v", k, v)
			}

			// 将键 k 和值 q 添加到 rl 中。
			rl[v1.ResourceName(k)] = q
		default:
			return nil, fmt.Errorf("cannot reserve %q resource", k)
		}
	}

	return rl, nil
}
```

##### ParseThresholdConfig

```go
// ParseThresholdConfig 解析阈值的标志。
func ParseThresholdConfig(allocatableConfig []string, evictionHard, evictionSoft, evictionSoftGracePeriod, evictionMinimumReclaim map[string]string) ([]evictionapi.Threshold, error) {
	results := []evictionapi.Threshold{}

	// 解析 evictionHard 标志。
	hardThresholds, err := parseThresholdStatements(evictionHard)
	if err != nil {
		return nil, err
	}
	results = append(results, hardThresholds...)

	// 解析 evictionSoft 标志。
	softThresholds, err := parseThresholdStatements(evictionSoft)
	if err != nil {
		return nil, err
	}

	// 解析 evictionSoftGracePeriod 标志。
	gracePeriods, err := parseGracePeriods(evictionSoftGracePeriod)
	if err != nil {
		return nil, err
	}

	// 解析 evictionMinimumReclaim 标志。
	minReclaims, err := parseMinimumReclaims(evictionMinimumReclaim)
	if err != nil {
		return nil, err
	}

	// 遍历 softThresholds 切片。
	for i := range softThresholds {
		signal := softThresholds[i].Signal

		// 检查是否为 signal 指定了 grace period。
		period, found := gracePeriods[signal]
		if !found {
			return nil, fmt.Errorf("grace period must be specified for the soft eviction threshold %v", signal)
		}

		// 将 grace period 添加到 softThresholds[i] 中。
		softThresholds[i].GracePeriod = period
	}

	results = append(results, softThresholds...)

	// 遍历 results 切片。
	for i := range results {
		if minReclaim, ok := minReclaims[results[i].Signal]; ok {
			results[i].MinReclaim = &minReclaim
		}
	}

	// 遍历 allocatableConfig 切片。
	for _, key := range allocatableConfig {
		if key == kubetypes.NodeAllocatableEnforcementKey {
			results = addAllocatableThresholds(results)
			break
		}
	}

	return results, nil
}
```

##### ParseQOSReserved

```go
// ParseQOSReserved 解析 --qos-reserve-requests 选项。
func ParseQOSReserved(m map[string]string) (*map[v1.ResourceName]int64, error) {
	reservations := make(map[v1.ResourceName]int64)

	// 遍历配置映射 m 中的键值对。
	for k, v := range m {
		switch v1.ResourceName(k) {
		// 仅支持内存资源。
		case v1.ResourceMemory:
			// 解析 v 为百分比 q。
			q, err := parsePercentage(v)
			if err != nil {
				return nil, fmt.Errorf("failed to parse percentage %q for %q resource: %w", v, k, err)
			}

			// 将键 k 和值 q 添加到 reservations 中。
			reservations[v1.ResourceName(k)] = q
		default:
			return nil, fmt.Errorf("cannot reserve %q resource", k)
		}
	}

	return &reservations, nil
}
```

##### PreInitRuntimeService

```go
// PreInitRuntimeService 在 RunKubelet 之前初始化运行时服务。
func PreInitRuntimeService(kubeCfg *kubeletconfiginternal.KubeletConfiguration, kubeDeps *Dependencies) error {
	remoteImageEndpoint := kubeCfg.ImageServiceEndpoint
	if remoteImageEndpoint == "" && kubeCfg.ContainerRuntimeEndpoint != "" {
		remoteImageEndpoint = kubeCfg.ContainerRuntimeEndpoint
	}

	var err error

	// 创建远程运行时服务。
	if kubeDeps.RemoteRuntimeService, err = remote.NewRemoteRuntimeService(kubeCfg.ContainerRuntimeEndpoint, kubeCfg.RuntimeRequestTimeout.Duration, kubeDeps.TracerProvider); err != nil {
		return err
	}

	// 创建远程镜像服务。
	if kubeDeps.RemoteImageService, err = remote.NewRemoteImageService(remoteImageEndpoint, kubeCfg.RuntimeRequestTimeout.Duration, kubeDeps.TracerProvider); err != nil {
		return err
	}

	// 检查是否使用旧版的 cadvisor 统计信息。
	kubeDeps.useLegacyCadvisorStats = cadvisor.UsingLegacyCadvisorStats(kubeCfg.ContainerRuntimeEndpoint)

	return nil
}
```

##### RunKubelet

```GO
// RunKubelet函数负责设置和运行一个kubelet实例。它在三个不同的应用程序中使用：
//
// 1. 集成测试
// 2. Kubelet二进制文件
// 3. 独立的'kubernetes'二进制文件
//
// 最终，#2将被#3的实例所替代。
func RunKubelet(kubeServer *options.KubeletServer, kubeDeps *kubelet.Dependencies, runOnce bool) error {
    // 获取主机名，如果kubeServer.HostnameOverride不为空则使用该值覆盖
    hostname, err := nodeutil.GetHostname(kubeServer.HostnameOverride)
    if err != nil {
    	return err
    }
    // 通过云提供商查询节点名称，如果kubeDeps.Cloud == nil则默认使用主机名
    nodeName, err := getNodeName(kubeDeps.Cloud, hostname)
    if err != nil {
        return err
    }

    // 检查是否覆盖了主机名
    hostnameOverridden := len(kubeServer.HostnameOverride) > 0

    // 如果需要，设置事件记录器
    makeEventRecorder(kubeDeps, nodeName)

    // 解析节点IP参数，如果有错误则返回
    nodeIPs, err := nodeutil.ParseNodeIPArgument(kubeServer.NodeIP, kubeServer.CloudProvider, utilfeature.DefaultFeatureGate.Enabled(features.CloudDualStackNodeIPs))
    if err != nil {
        return fmt.Errorf("bad --node-ip %q: %v", kubeServer.NodeIP, err)
    }

    // 初始化容器运行时的能力
    capabilities.Initialize(capabilities.Capabilities{
        AllowPrivileged: true,
    })

    // 设置首选的dockercfg路径
    credentialprovider.SetPreferredDockercfgPath(kubeServer.RootDirectory)
    klog.V(2).InfoS("Using root directory", "path", kubeServer.RootDirectory)

    // 如果kubeDeps.OSInterface为空，则使用kubecontainer.RealOS作为操作系统接口
    if kubeDeps.OSInterface == nil {
        kubeDeps.OSInterface = kubecontainer.RealOS{}
    }

    // 创建并初始化kubelet实例
    k, err := createAndInitKubelet(kubeServer,
        kubeDeps,
        hostname,
        hostnameOverridden,
        nodeName,
        nodeIPs)
    if err != nil {
        return fmt.Errorf("failed to create kubelet: %w", err)
    }

    // 如果在构建时NewMainKubelet没有设置pod source config，则返回错误
    if kubeDeps.PodConfig == nil {
        return fmt.Errorf("failed to create kubelet, pod source config was nil")
    }
    podCfg := kubeDeps.PodConfig

    // 设置文件句柄限制
    if err := rlimit.SetNumFiles(uint64(kubeServer.MaxOpenFiles)); err != nil {
        klog.ErrorS(err, "Failed to set rlimit on max file handles")
    }

    // 如果runOnce为true，则处理一次pod并退出
    if runOnce {
        if _, err := k.RunOnce(podCfg.Updates()); err != nil {
            return fmt.Errorf("runonce failed: %w", err)
        }
        klog.InfoS("Started kubelet as runonce")
    } else {
        // 否则启动kubelet服务
        startKubelet(k, podCfg, &kubeServer.KubeletConfiguration, kubeDeps, kubeServer.EnableServer)
        klog.InfoS("Started kubelet")
    }

    return nil
}
```

###### ParseNodeIPArgument

```go
// ParseNodeIPArgument 解析 kubelet 的 --node-ip 参数。如果 nodeIP 包含无效的值，它们将被记录并忽略。
// 如果 cloudProvider 未设置，或者设置为 "external" 并且 allowCloudDualStack 为 true，则允许使用双栈节点 IP。
func ParseNodeIPArgument(nodeIP, cloudProvider string, allowCloudDualStack bool) ([]net.IP, error) {
var allowDualStack bool
    if (cloudProvider == cloudProviderNone) || (cloudProvider == cloudProviderExternal && allowCloudDualStack) {
    	allowDualStack = true
    }
    return parseNodeIP(nodeIP, allowDualStack, true)
}
```

###### SetNumFiles

```go
// SetNumFiles函数用于设置Linux系统的最大打开文件数的rlimit值。
func SetNumFiles(maxOpenFiles uint64) error {
    // 调用unix包的Setrlimit函数设置RLIMIT_NOFILE资源的限制，即最大打开文件数。
    // 传入的参数是一个指向unix.Rlimit结构体的指针，其中Max字段和Cur字段都被设置为maxOpenFiles。
    return unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Max: maxOpenFiles, Cur: maxOpenFiles})
}
```

###### createAndInitKubelet

```go
func createAndInitKubelet(kubeServer *options.KubeletServer,
    kubeDeps *kubelet.Dependencies,
    hostname string,
    hostnameOverridden bool,
    nodeName types.NodeName,
	nodeIPs []net.IP) (k kubelet.Bootstrap, err error) {
    // TODO: 在所有数据源至少向通道传递了一个更新之前，阻塞同步循环，或将同步循环分解为“按数据源”同步
    // 这里是一个TODO标记，表示需要在这里添加一些功能。
    // 根据注释的描述，可能需要等待所有数据源都向通道传递至少一个更新，然后再继续执行下面的代码。
    // 调用kubelet包的NewMainKubelet函数创建一个新的主kubelet实例。
    // 传入的参数包括kubeServer.KubeletConfiguration等配置选项、kubeDeps依赖项、
    // hostname主机名、hostnameOverridden是否覆盖主机名、nodeName节点名称、
    // nodeIPs节点IP列表、kubeServer.ProviderID提供者ID等等。
    // 创建成功后，返回一个实现了kubelet.Bootstrap接口的对象k和一个错误err（如果有）。
    k, err = kubelet.NewMainKubelet(&kubeServer.KubeletConfiguration,
        kubeDeps,
        &kubeServer.ContainerRuntimeOptions,
        hostname,
        hostnameOverridden,
        nodeName,
        nodeIPs,
        kubeServer.ProviderID,
        kubeServer.CloudProvider,
        kubeServer.CertDirectory,
        kubeServer.RootDirectory,
        kubeServer.ImageCredentialProviderConfigFile,
        kubeServer.ImageCredentialProviderBinDir,
        kubeServer.RegisterNode,
        kubeServer.RegisterWithTaints,
        kubeServer.AllowedUnsafeSysctls,
        kubeServer.ExperimentalMounterPath,
        kubeServer.KernelMemcgNotification,
        kubeServer.ExperimentalNodeAllocatableIgnoreEvictionThreshold,
        kubeServer.MinimumGCAge,
        kubeServer.MaxPerPodContainerCount,
        kubeServer.MaxContainerCount,
        kubeServer.RegisterSchedulable,
        kubeServer.KeepTerminatedPodVolumes,
        kubeServer.NodeLabels,
        kubeServer.NodeStatusMaxImages,
        kubeServer.KubeletFlags.SeccompDefault || kubeServer.KubeletConfiguration.SeccompDefault)
    // 如果发生错误，则返回nil和错误err。
    if err != nil {
        return nil, err
    }

    // 调用k的BirthCry方法，执行kubelet实例的初始化操作。
    k.BirthCry()

    // 调用k的StartGarbageCollection方法，启动垃圾回收功能。
    k.StartGarbageCollection()

	return k, nil
}
```

## Bootstrap

```go
// Bootstrap 是 kubelet 的引导接口，用于初始化协议
type Bootstrap interface {
    // GetConfiguration 返回 kubelet 的配置
    GetConfiguration() kubeletconfiginternal.KubeletConfiguration
    // BirthCry 启动垃圾回收
    BirthCry()
    // StartGarbageCollection 启动垃圾收集
    StartGarbageCollection()
    // ListenAndServe 监听并提供服务
    ListenAndServe(kubeCfg *kubeletconfiginternal.KubeletConfiguration, tlsOptions *server.TLSOptions, auth server.AuthInterface, tp trace.TracerProvider)
    // ListenAndServeReadOnly 仅读方式监听并提供服务
    ListenAndServeReadOnly(address net.IP, port uint)
    // ListenAndServePodResources 监听并提供 pod 资源
    ListenAndServePodResources()
    // Run 运行 pod 的更新通道
    Run(<-chan kubetypes.PodUpdate)
    // RunOnce 仅运行一次 pod 的更新通道
    RunOnce(<-chan kubetypes.PodUpdate) ([]RunPodResult, error)
}
```

### Kubelet

```go
// Kubelet 是主要的 kubelet 实现。
type Kubelet struct {
    // kubeletConfiguration 是 kubelet 的配置
    kubeletConfiguration kubeletconfiginternal.KubeletConfiguration
    // hostname 是 kubelet 检测到的主机名，或通过标志/配置给出的主机名
    hostname string
    // hostnameOverridden 表示主机名是否通过标志/配置被覆盖
    hostnameOverridden bool

    nodeName        types.NodeName
    runtimeCache    kubecontainer.RuntimeCache
    kubeClient      clientset.Interface
    heartbeatClient clientset.Interface
    // mirrorPodClient 用于在 API 中创建和删除镜像 pod
    mirrorPodClient kubepod.MirrorClient

    rootDirectory string

    lastObservedNodeAddressesMux sync.RWMutex
    lastObservedNodeAddresses    []v1.NodeAddress

    // onRepeatedHeartbeatFailure 在心跳操作失败多次时调用。可选
    onRepeatedHeartbeatFailure func()

    // podManager 存储 kubelet 应该运行的已接受的 pod 和镜像 pod 的期望集合。
    // 实际运行的 pod 集合存储在 podWorkers 上。通过 kubelet 配置循环填充 podManager，
    // 该循环抽象出了从多个不同来源（常规 pod 的 API、静态 pod 的本地文件系统或 HTTP）接收配置的过程。
    // 可能会通过其他需要查看期望的 pod 集合的组件来查询 podManager。
    // 注意，并非所有期望的 pod 都在运行，也不是所有运行的 pod 都在 podManager 中——例如，从 api 服务器中强制删除一个 pod 将从 podManager 中删除该 pod，但该 pod 仍然可能处于终止状态，并由 podWorkers 跟踪。
    // 需要了解节点的实际消耗资源或由 podWorkers 驱动的组件以及 sync*Pod 方法（状态、卷、统计）推动的组件，还应在协调时咨询 podWorkers。
    //
    // TODO: 需要查看所有需要实际的 pod 集合（而不是期望的集合）的 kubelet 组件，并更新它们以使用 podWorkers 而不是 podManager。
    // 这可能会在某些方法中引入延迟，但避免了竞争条件，并正确处理已被强制删除的终止 pod 或已更新的静态 pod。
    // https://github.com/kubernetes/kubernetes/issues/116970
    podManager kubepod.Manager

    // podWorkers 负责驱动每个 pod 的生命周期状态机。worker 会接收配置更改、更新、定期对齐、容器运行时更新和所有期望的 pod 的驱逐的通知，并在单独的 goroutine 中为每个 pod 调用协调方法。
    // podWorkers 是 kubelet 中实际运行的 pod 以及它们当前状态的权威来源:
    //
    // * syncing: pod 应该正在运行（syncPod）
    // * terminating: pod 应该被停止（syncTerminatingPod）
    // * terminated: pod 应该清理所有资源（syncTerminatedPod）
    //
    // 并调用与每个状态对应的处理方法。kubelet 中的组件在设置或清理资源时需要知道 pod 的阶段，必须查询 podWorkers。
    //
    // 一旦 pod 被 pod workers 接受，将不会启动具有相同 UID（对于静态 pod，还需要相同的名称+命名空间）的其他 pod，直到第一个 pod 完全终止并被 SyncKnownPods 清理。
    // 这意味着一个 pod 可能是期望的（在 API 中），已被接受（在 podManager 中），并被请求（通过调用 UpdatePod），但由于之前的 pod 仍在终止，可能不会在任意长的时间间隔内启动。
    //
    // 作为一个事件驱动的（由 UpdatePod 触发）控制器，podWorkers 必须周期性地通过 kubelet 调用 SyncKnownPods 与期望的状态（在 podManager 中被接受的 pod）同步。
    // 由于 podManager 可能由于强制删除而不知道某些运行中的 pod，因此 podWorkers 负责触发那些不再期望但必须继续运行直到完成的 pod 的同步。
    podWorkers PodWorkers

    // evictionManager 观察节点的状态，以便检测可能影响节点稳定性的情况，并驱逐 pod（将其设置为 Failed 状态，原因为 Evicted）以减少资源压力。
    // 驱逐管理器根据节点的实际状态行动，并将 podWorker 视为权威。
    evictionManager eviction.Manager

    // probeManager 跟踪正在运行的 pod 集合，并确保运行用户定义的周期性检查以检查每个 pod 的状态。
    // 探测管理器根据节点的实际状态行动，并通过 podWorker 通知 pod。
    // 探测管理器是最新的探测状态的权威来源，并负责通知状态管理器，后者将其合成为整体的 pod 状态。
    probeManager prober.Manager

    // secretManager 缓存在该节点上正在运行的 pod 使用的秘密的集合。
    // podWorker 在 pod 启动和终止时通知 secretManager，secretManager 必须在秘密发生更改时保持所需的秘密处于最新状态。
    secretManager secret.Manager

    // configMapManager 缓存在该节点上正在运行的 pod 使用的配置映射的集合。
    // podWorker 在 pod 启动和终止时通知 configMapManager，configMapManager 必须在配置映射发生更改时保持所需的配置映射处于最新状态。
    configMapManager configmap.Manager

    // volumeManager 观察正在运行的 pod 集合，并负责在这些 pod 在其生命周期中移动时进行附加、挂载、卸载和分离。
    // 它定期将已知卷的集合与实际需要的卷的集合进行同步，并清理任何孤立的卷。
    // 对于运行中的 pod，volumeManager 将 podWorker 视为权威。
    volumeManager volumemanager.VolumeManager

    // statusManager 从 podWorker 接收更新的 pod 状态，并将这些状态更新到 API 中。
    // statusManager 是 kubelet 从其角度合成的 pod 状态的权威来源（其他组件拥有状态的各个元素），
    // 组件在组装状态时应首先查询 statusManager 而不是其他方式。
    // 注意，statusManager 位于 podWorker 的下游，需要检查 pod 是否仍在运行的组件应直接查询 podWorker。
    statusManager status.Manager

    // resyncInterval 是在该节点上进行周期性全量协调的间隔。
    resyncInterval time.Duration

    // sourcesReady 记录 kubelet 观察到的源，线程安全。
    sourcesReady config.SourcesReady

    // 可选项，默认为从 /var/log 到 /logs/
    logServer http.Handler

    // 可选项，默认为简单的 Docker 实现
    runner kubecontainer.CommandRunner

    // cadvisor 用于容器信息。
    cadvisor cadvisor.Interface

    // 设置为 true，使节点向 apiserver 注册自身。
    registerNode bool

    // 当 kubelet 注册自身时，添加到节点对象的污点列表。
    registerWithTaints []v1.Taint

    // 设置为 true，使节点将自身注册为可调度的。
    registerSchedulable bool

    // 用于在启动 pod 时设置 DNS 解析器配置。
    dnsConfigurer *dns.Configurer
    // serviceLister 知道如何列出服务。
    serviceLister serviceLister

    // serviceHasSynced 表示服务是否至少同步过一次。
    // 在信任列表器的响应之前，请先检查这一点。
    serviceHasSynced cache.InformerSynced

    // nodeLister 知道如何列出节点。
    nodeLister corelisters.NodeLister

    // nodeHasSynced 表示节点是否至少同步过一次。
    // 在信任节点列表器的响应之前，请先检查这一点。
    nodeHasSynced cache.InformerSynced

    // 要注册的节点标签列表。
    nodeLabels map[string]string

    // 上次运行时响应 ping 的时间戳。
    // 使用互斥锁保护此值。
    runtimeState *runtimeState

    // 卷插件。
    volumePluginMgr *volume.VolumePluginMgr

    // 管理容器的健康检查结果。
    livenessManager proberesults.Manager
    readinessManager proberesults.Manager
    startupManager proberesults.Manager

    // 在终止连接之前，保持空闲流式命令执行/端口转发连接的时间。
    streamingConnectionIdleTimeout time.Duration

    // 要使用的 EventRecorder。
    recorder record.EventRecorder

    // 处理死亡容器的垃圾回收策略。
    containerGC kubecontainer.GC

    // 图像垃圾回收的管理器。
    imageManager images.ImageGCManager

    // 容器日志的管理器。
    containerLogManager logs.ContainerLogManager

    // 由 cadvisor 返回的缓存的 MachineInfo。
    machineInfoLock sync.RWMutex
    machineInfo *cadvisorapi.MachineInfo

    // 处理证书轮换。
    serverCertificateManager certificate.Manager

    // 云提供商接口。
    cloud cloudprovider.Interface

    // 带超时的云提供商请求处理程序。
    cloudResourceSyncManager cloudresource.SyncManager

    // 表示节点初始化是在外部云控制器中进行的。
    externalCloudProvider bool

    // 对此节点的引用。
    nodeRef *v1.ObjectReference

    // 容器运行时。
    containerRuntime kubecontainer.Runtime

    // 流式运行时处理容器流式处理。
    streamingRuntime kubecontainer.StreamingRuntime

    // 容器运行时服务（容器运行时的 Start() 需要）。
    runtimeService internalapi.RuntimeService

    // reasonCache 缓存最后一次创建所有容器的失败原因，
    // 用于生成 ContainerStatus。
    reasonCache *ReasonCache

    // containerRuntimeReadyExpected 表示容器运行时是否准备好是预期的，
    // 因此错误会在无需详细信息的情况下记录，以避免在节点启动时产生过多的错误日志。
    // 在 nodeReadyGracePeriod 的节点初始化期间为 false，之后由 fastStatusUpdateOnce 在退出时设置为 true。
    containerRuntimeReadyExpected bool

    // nodeStatusUpdateFrequency 指定 kubelet 计算节点状态的频率。
    // 如果未启用节点租约功能，它还是 kubelet 将节点状态发布到主节点的频率。
    // 在这种情况下，更改常量时要小心，它必须与 nodecontroller 中的 nodeMonitorGracePeriod
    // 配合使用。有几个约束条件：
    // 1. nodeMonitorGracePeriod 必须是 nodeStatusUpdateFrequency 的 N 倍，其中 N 表示 kubelet
    // 发布节点状态的重试次数。如果 nodeStatusUpdateFrequency 的值太小，则 nodeMonitorGracePeriod
    // 小于 nodeStatusUpdateFrequency 是没有意义的，因为从 kubelet 获取的值只会以 nodeStatusUpdateFrequency 的间隔刷新。
    // 该常量必须小于 podEvictionTimeout。
    // 2. nodeStatusUpdateFrequency 需要足够大，以便 kubelet 生成节点状态。
    // 如果值太小，kubelet 可能无法可靠地更新节点状态，因为它需要时间来收集所有必要的节点信息。
    nodeStatusUpdateFrequency time.Duration

    // nodeStatusReportFrequency 是 kubelet 将节点状态报告给主节点的频率。
    // 仅在启用节点租约功能时使用。
    nodeStatusReportFrequency time.Duration

    // 上次报告节点状态的时间。
    lastStatusReportTime time.Time

    // syncNodeStatusMux 是在更新节点状态时对节点状态进行加锁的锁，
    // 因为该路径不是线程安全的。
    // 这个锁被 Kubelet.syncNodeStatus 和 Kubelet.fastNodeStatusUpdate 函数使用，不应该在其他任何地方使用。
    syncNodeStatusMux sync.Mutex

    // updatePodCIDRMux 是在更新 Pod CIDR 时对 Pod CIDR 进行加锁的锁，
    // 因为该路径不是线程安全的。
    // 这个锁只被 Kubelet.updatePodCIDR 函数使用，不应该在其他任何地方使用。
    updatePodCIDRMux sync.Mutex

    // updateRuntimeMux 是在更新运行时时对运行时进行加锁的锁，
    // 因为该路径不是线程安全的。
    // 这个锁被 Kubelet.updateRuntimeUp 和 Kubelet.fastNodeStatusUpdate 函数使用，不应该在其他任何地方使用。
    updateRuntimeMux sync.Mutex

    // nodeLeaseController 用于声明和续订此 Kubelet 的节点租约。
    nodeLeaseController lease.Controller

    // pleg 观察容器运行时的状态，并通知 kubelet 容器状态的更改，
    // 从而通知 podWorkers 调和 pod 的状态（例如，如果容器死亡并且需要重新启动）。
    pleg pleg.PodLifecycleEventGenerator

    // eventedPleg 用于提供低延迟的边缘驱动容器更改的 pleg 补充。
    eventedPleg pleg.PodLifecycleEventGenerator

    // 存储所有 pod 的 kubecontainer.PodStatus。
    podCache kubecontainer.Cache

    // 用于卷的挂载程序。
    mounter mount.Interface

    // 与文件系统交互的 hostutil。
    hostutil hostutil.HostUtils

    // 用于执行子路径操作的 subpather。
    subpather subpath.Interface

    // 非运行时容器的管理器。
    containerManager cm.ContainerManager
    // 此 Kubelet 可以运行的最大 Pod 数量。
    maxPods int

    // 监视 Kubelet 的同步循环。
    syncLoopMonitor atomic.Value

    // 容器重启的指数退避。
    backOff *flowcontrol.Backoff

    // 运行此 Kubelet 服务器的节点上的守护进程打开的端口的信息。
    daemonEndpoints *v1.NodeDaemonEndpoints

    // 用于触发 pod workers 的队列。
    workQueue queue.WorkQueue

    // oneTimeInitializer 用于初始化依赖于运行时已启动的模块。
    oneTimeInitializer sync.Once

    // 如果设置，则使用此 IP 地址或地址作为节点的 IP。
    nodeIPs []net.IP

    // 用于验证 kubelet nodeIP 的函数。
    nodeIPValidator func(net.IP) error

    // 如果非空，这是外部数据库中节点的唯一标识符，例如云提供商。
    providerID string

    // clock 是一个接口，提供与时间相关的功能，以便轻松测试代码。
    clock clock.WithTicker
    
    // 在 tryUpdateNodeStatus 循环期间调用的处理程序
    setNodeStatusFuncs []func(context.Context, *v1.Node) error

    lastNodeUnschedulableLock sync.Mutex
    // 从上一次 tryUpdateNodeStatus() 运行中维护的 Node.Spec.Unschedulable 值
    lastNodeUnschedulable bool

    // 在 pod 入场期间调用的处理程序列表
    admitHandlers lifecycle.PodAdmitHandlers

    // softAdmithandlers 在 Kubelet 批准 pod 后但在其运行之前应用于 pod。
    // 被 softAdmitHandler 拒绝的 pod 将无限期地保持在 Pending 状态。
    // 如果拒绝的 pod 不应重新创建，或者调度程序不知道拒绝规则，则应由 softAdmitHandler 应用拒绝规则。
    softAdmitHandlers lifecycle.PodAdmitHandlers

    // 在 pod 同步循环期间调用的处理程序列表
    lifecycle.PodSyncLoopHandlers

    // 在 pod 同步期间调用的处理程序列表
    lifecycle.PodSyncHandlers

    // 每个核心允许的 pod 数量
    podsPerCore int

    // enableControllerAttachDetach 指示 Attach/Detach 控制器是否应管理安排给此节点的卷的附加/分离，并禁止 kubelet 执行任何附加/分离操作
    enableControllerAttachDetach bool

    // 触发删除 pod 中的容器
    containerDeletor *podContainerDeletor

    // 配置 iptables 工具规则
    makeIPTablesUtilChains bool

    // 用于标记 SNAT 包的 fwmark 空间的位
    iptablesMasqueradeBit int

    // 用于标记丢弃包的 fwmark 空间的位
    iptablesDropBit int

    // 用于检查是否支持 AppArmor 的 AppArmor 验证器
    appArmorValidator apparmor.Validator

    // StatsProvider 提供节点和容器的统计信息
    StatsProvider *stats.Provider

    // 如果设置了此标志，指示 kubelet 保持已终止的 pod 的卷挂载到节点上。
    // 这对于调试与卷相关的问题很有用。
    keepTerminatedPodVolumes bool // 已弃用

    // pluginmanager 运行一组异步循环，根据此节点确定需要注册/取消注册哪些插件，并使之生效。
    pluginManager pluginmanager.PluginManager

    // 此标志设置节点状态中要报告的最大图像数。
    nodeStatusMaxImages int32

    // 处理 Kubelet 的 RuntimeClass 对象
    runtimeClassManager *runtimeclass.Manager

    // 处理节点关机事件的 Manager
    shutdownManager nodeshutdown.Manager

    // 管理用户命名空间
    usernsManager *userns.UsernsManager

    // 用于串行化新的 pod 入场和现有 pod 调整大小的互斥锁
    podResizeMutex sync.Mutex

    // OpenTelemetry Tracer
    tracer trace.Tracer
}
```

#### serviceLister

```go
type serviceLister interface {
	List(labels.Selector) ([]*v1.Service, error)
}
```

#### NewMainKubelet

```go
// NewMainKubelet 实例化一个新的 Kubelet 对象以及所有所需的内部模块。
// 不应在这里对 Kubelet 及其模块进行初始化。
func NewMainKubelet(kubeCfg *kubeletconfiginternal.KubeletConfiguration,
	kubeDeps *Dependencies,
	crOptions *config.ContainerRuntimeOptions,
	hostname string,
	hostnameOverridden bool,
	nodeName types.NodeName,
	nodeIPs []net.IP,
	providerID string,
	cloudProvider string,
	certDirectory string,
	rootDirectory string,
	imageCredentialProviderConfigFile string,
	imageCredentialProviderBinDir string,
	registerNode bool,
	registerWithTaints []v1.Taint,
	allowedUnsafeSysctls []string,
	experimentalMounterPath string,
	kernelMemcgNotification bool,
	experimentalNodeAllocatableIgnoreEvictionThreshold bool,
	minimumGCAge metav1.Duration,
	maxPerPodContainerCount int32,
	maxContainerCount int32,
	registerSchedulable bool,
	keepTerminatedPodVolumes bool,
	nodeLabels map[string]string,
	nodeStatusMaxImages int32,
	seccompDefault bool,
) (*Kubelet, error) {
	ctx := context.Background()
	logger := klog.TODO()

	if rootDirectory == "" {
		return nil, fmt.Errorf("invalid root directory %q", rootDirectory)
	}
	if kubeCfg.SyncFrequency.Duration <= 0 {
		return nil, fmt.Errorf("invalid sync frequency %d", kubeCfg.SyncFrequency.Duration)
	}

	if kubeCfg.MakeIPTablesUtilChains {
		if kubeCfg.IPTablesMasqueradeBit > 31 || kubeCfg.IPTablesMasqueradeBit < 0 {
			return nil, fmt.Errorf("iptables-masquerade-bit is not valid. Must be within [0, 31]")
		}
		if kubeCfg.IPTablesDropBit > 31 || kubeCfg.IPTablesDropBit < 0 {
			return nil, fmt.Errorf("iptables-drop-bit is not valid. Must be within [0, 31]")
		}
		if kubeCfg.IPTablesDropBit == kubeCfg.IPTablesMasqueradeBit {
			return nil, fmt.Errorf("iptables-masquerade-bit and iptables-drop-bit must be different")
		}
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.DisableCloudProviders) && cloudprovider.IsDeprecatedInternal(cloudProvider) {
		cloudprovider.DisableWarningForProvider(cloudProvider)
		return nil, fmt.Errorf("cloud provider %q was specified, but built-in cloud providers are disabled. Please set --cloud-provider=external and migrate to an external cloud provider", cloudProvider)
	}

	var nodeHasSynced cache.InformerSynced
	var nodeLister corelisters.NodeLister

	// 如果 kubeClient == nil，则我们正在独立模式下运行（即没有 API 服务器）
	// 如果不为 nil，则我们正在作为集群的一部分运行，应与 API 进行同步
	if kubeDeps.KubeClient != nil {
		kubeInformers := informers.NewSharedInformerFactoryWithOptions(kubeDeps.KubeClient, 0, informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fields.Set{metav1.ObjectNameField: string(nodeName)}.String()
		}))
		nodeLister = kubeInformers.Core().V1().Nodes().Lister()
		nodeHasSynced = func() bool {
			return kubeInformers.Core().V1().Nodes().Informer().HasSynced()
		}
		kubeInformers.Start(wait.NeverStop)
		klog.InfoS("Attempting to sync node with API server")
	} else {
		// 如果没有 kubeDeps.KubeClient，则表示我们正在独立模式下运行（即没有 API 服务器）
		nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		nodeLister = corelisters.NewNodeLister(nodeIndexer)
		nodeHasSynced = func() bool { return true }
		klog.InfoS("Kubelet is running in standalone mode, will skip API server sync")
	}
	// 如果 kubeDeps.PodConfig 为 nil，则创建 PodSourceConfig
	if kubeDeps.PodConfig == nil {
		var err error
		kubeDeps.PodConfig, err = makePodSourceConfig(kubeCfg, kubeDeps, nodeName, nodeHasSynced)
		if err != nil {
			return nil, err
		}
	}
	// 创建 kubecontainer.GCPolicy，用于控制容器的垃圾回收策略
	containerGCPolicy := kubecontainer.GCPolicy{
		MinAge:             minimumGCAge.Duration,
		MaxPerPodContainer: int(maxPerPodContainerCount),
		MaxContainers:      int(maxContainerCount),
	}
	// 创建 v1.NodeDaemonEndpoints，用于存储 kubelet 的守护进程端点信息
	daemonEndpoints := &v1.NodeDaemonEndpoints{
		KubeletEndpoint: v1.DaemonEndpoint{Port: kubeCfg.Port},
	}
	// 创建 images.ImageGCPolicy，用于控制镜像的垃圾回收策略
	imageGCPolicy := images.ImageGCPolicy{
		MinAge:               kubeCfg.ImageMinimumGCAge.Duration,
		HighThresholdPercent: int(kubeCfg.ImageGCHighThresholdPercent),
		LowThresholdPercent:  int(kubeCfg.ImageGCLowThresholdPercent),
	}
	
    // 根据实验性配置 experimentalNodeAllocatableIgnoreEvictionThreshold 决定是否提供 kubeCfg.EnforceNodeAllocatable 给 eviction threshold parsing
	enforceNodeAllocatable := kubeCfg.EnforceNodeAllocatable
	if experimentalNodeAllocatableIgnoreEvictionThreshold {
		// 如果不强制驱逐，则不向 eviction threshold parsing 提供 
		enforceNodeAllocatable = []string{}
	}
    // 解析驱逐配置
	thresholds, err := eviction.ParseThresholdConfig(enforceNodeAllocatable, kubeCfg.EvictionHard, kubeCfg.EvictionSoft, kubeCfg.EvictionSoftGracePeriod, kubeCfg.EvictionMinimumReclaim)
	if err != nil {
		return nil, err
	
    // 创建 eviction.Config，用于控制节点的驱逐策略
	evictionConfig := eviction.Config{
		PressureTransitionPeriod: kubeCfg.EvictionPressureTransitionPeriod.Duration,
		MaxPodGracePeriodSeconds: int64(kubeCfg.EvictionMaxPodGracePeriod),
		Thresholds:               thresholds,
		KernelMemcgNotification:  kernelMemcgNotification,
		PodCgroupRoot:            kubeDeps.ContainerManager.GetPodCgroupRoot(),
	}
	// 创建 serviceLister 和 serviceHasSynced 变量
	var serviceLister corelisters.ServiceLister
	var serviceHasSynced cache.InformerSynced
    // 如果 kubeDeps.KubeClient 不为 nil，则表示我们正在作为集群的一部分运行，应创建 SharedInformerFactory
	if kubeDeps.KubeClient != nil {
		kubeInformers := informers.NewSharedInformerFactory(kubeDeps.KubeClient, 0)
		serviceLister = kubeInformers.Core().V1().Services().Lister()
		serviceHasSynced = kubeInformers.Core().V1().Services().Informer().HasSynced
		kubeInformers.Start(wait.NeverStop)
	} else {
        // 如果没有 kubeDeps.KubeClient，则表示我们正在独立模式下运行（即没有 API 服务器），创建 serviceIndexer 和 serviceLister
		serviceIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		serviceLister = corelisters.NewServiceLister(serviceIndexer)
		serviceHasSynced = func() bool { return true }
	}

	// 创建一个用于事件的节点引用
	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      string(nodeName),
		UID:       types.UID(nodeName),
		Namespace: "",
	}
	// 创建 oomWatcher，用于监视 Out-Of-Memory 事件
	oomWatcher, err := oomwatcher.NewWatcher(kubeDeps.Recorder)
	if err != nil {
		if libcontaineruserns.RunningInUserNS() {
			if utilfeature.DefaultFeatureGate.Enabled(features.KubeletInUserNamespace) {
				// oomwatcher.NewWatcher 在用户命名空间中运行时会返回 "open /dev/kmsg: operation not permitted" 错误，
				klog.V(2).InfoS("Failed to create an oomWatcher (running in UserNS, ignoring)", "err", err)
				oomWatcher = nil
			} else {
				klog.ErrorS(err, "Failed to create an oomWatcher (running in UserNS, Hint: enable KubeletInUserNamespace feature flag to ignore the error)")
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	// 创建 clusterDNS 切片，用于存储集群的 DNS 地址
	clusterDNS := make([]net.IP, 0, len(kubeCfg.ClusterDNS))
	for _, ipEntry := range kubeCfg.ClusterDNS {
		ip := netutils.ParseIPSloppy(ipEntry)
		if ip == nil {
			klog.InfoS("Invalid clusterDNS IP", "IP", ipEntry)
		} else {
			clusterDNS = append(clusterDNS, ip)
		}
	}

	// 创建一个用于容器生命周期请求的不安全的 HTTP 客户端
	insecureContainerLifecycleHTTPClient := &http.Client{}
	if utilfeature.DefaultFeatureGate.Enabled(features.ConsistentHTTPGetHandlers) {
		insecureTLSTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		insecureContainerLifecycleHTTPClient.Transport = insecureTLSTransport
		insecureContainerLifecycleHTTPClient.CheckRedirect = httpprobe.RedirectChecker(false)
	}
	// 从 TracerProvider 中获取 Tracer
	tracer := kubeDeps.TracerProvider.Tracer(instrumentationScope)

	klet := &Kubelet{
		hostname:                       hostname,
		hostnameOverridden:             hostnameOverridden,
		nodeName:                       nodeName,
		kubeClient:                     kubeDeps.KubeClient,
		heartbeatClient:                kubeDeps.HeartbeatClient,
		onRepeatedHeartbeatFailure:     kubeDeps.OnHeartbeatFailure,
		rootDirectory:                  filepath.Clean(rootDirectory),
		resyncInterval:                 kubeCfg.SyncFrequency.Duration,
		sourcesReady:                   config.NewSourcesReady(kubeDeps.PodConfig.SeenAllSources),
		registerNode:                   registerNode,
		registerWithTaints:             registerWithTaints,
		registerSchedulable:            registerSchedulable,
		dnsConfigurer:                  dns.NewConfigurer(kubeDeps.Recorder, nodeRef, nodeIPs, clusterDNS, kubeCfg.ClusterDomain, kubeCfg.ResolverConfig),
		serviceLister:                  serviceLister,
		serviceHasSynced:               serviceHasSynced,
		nodeLister:                     nodeLister,
		nodeHasSynced:                  nodeHasSynced,
		streamingConnectionIdleTimeout: kubeCfg.StreamingConnectionIdleTimeout.Duration,
		recorder:                       kubeDeps.Recorder,
		cadvisor:                       kubeDeps.CAdvisorInterface,
		cloud:                          kubeDeps.Cloud,
		externalCloudProvider:          cloudprovider.IsExternal(cloudProvider),
		providerID:                     providerID,
		nodeRef:                        nodeRef,
		nodeLabels:                     nodeLabels,
		nodeStatusUpdateFrequency:      kubeCfg.NodeStatusUpdateFrequency.Duration,
		nodeStatusReportFrequency:      kubeCfg.NodeStatusReportFrequency.Duration,
		os:                             kubeDeps.OSInterface,
		oomWatcher:                     oomWatcher,
		cgroupsPerQOS:                  kubeCfg.CgroupsPerQOS,
		cgroupRoot:                     kubeCfg.CgroupRoot,
		mounter:                        kubeDeps.Mounter,
		hostutil:                       kubeDeps.HostUtil,
		subpather:                      kubeDeps.Subpather,
		maxPods:                        int(kubeCfg.MaxPods),
		podsPerCore:                    int(kubeCfg.PodsPerCore),
		syncLoopMonitor:                atomic.Value{},
		daemonEndpoints:                daemonEndpoints,
		containerManager:               kubeDeps.ContainerManager,
		nodeIPs:                        nodeIPs,
		nodeIPValidator:                validateNodeIP,
		clock:                          clock.RealClock{},
		enableControllerAttachDetach:   kubeCfg.EnableControllerAttachDetach,
		makeIPTablesUtilChains:         kubeCfg.MakeIPTablesUtilChains,
		iptablesMasqueradeBit:          int(kubeCfg.IPTablesMasqueradeBit),
		iptablesDropBit:                int(kubeCfg.IPTablesDropBit),
		keepTerminatedPodVolumes:       keepTerminatedPodVolumes,
		nodeStatusMaxImages:            nodeStatusMaxImages,
		tracer:                         tracer,
	}
	// 如果 klet.cloud 不为 nil，则创建 cloudResourceSyncManager 对象
	if klet.cloud != nil {
		klet.cloudResourceSyncManager = cloudresource.NewSyncManager(klet.cloud, nodeName, klet.nodeStatusUpdateFrequency)
	}
	// 创建 secretManager 和 configMapManager 变量
	var secretManager secret.Manager
	var configMapManager configmap.Manager
	if klet.kubeClient != nil {
        // 根据配置文件中的 ConfigMapAndSecretChangeDetectionStrategy 进行不同的处理
		switch kubeCfg.ConfigMapAndSecretChangeDetectionStrategy {
		case kubeletconfiginternal.WatchChangeDetectionStrategy:
            // 使用 WatchingSecretManager 和 WatchingConfigMapManager 进行变动检测
			secretManager = secret.NewWatchingSecretManager(klet.kubeClient, klet.resyncInterval)
			configMapManager = configmap.NewWatchingConfigMapManager(klet.kubeClient, klet.resyncInterval)
		case kubeletconfiginternal.TTLCacheChangeDetectionStrategy:
            // 使用 CachingSecretManager 和 CachingConfigMapManager 进行变动检测，同时使用 GetObjectTTLFromNodeFunc 获取 TTL
			secretManager = secret.NewCachingSecretManager(
				klet.kubeClient, manager.GetObjectTTLFromNodeFunc(klet.GetNode))
			configMapManager = configmap.NewCachingConfigMapManager(
				klet.kubeClient, manager.GetObjectTTLFromNodeFunc(klet.GetNode))
		case kubeletconfiginternal.GetChangeDetectionStrategy
            // 使用 SimpleSecretManager 和 SimpleConfigMapManager 进行变动检测
			secretManager = secret.NewSimpleSecretManager(klet.kubeClient)
			configMapManager = configmap.NewSimpleConfigMapManager(klet.kubeClient)
		default:
			return nil, fmt.Errorf("unknown configmap and secret manager mode: %v", kubeCfg.ConfigMapAndSecretChangeDetectionStrategy)
		}
		// 设置 secretManager 和 configMapManager
		klet.secretManager = secretManager
		klet.configMapManager = configMapManager
	}
	
    // 获取机器信息
	machineInfo, err := klet.cadvisor.MachineInfo()
	if err != nil {
		return nil, err
	}
	// 将机器信息的 Timestamp 设置为空时间，避免被收集为带有时间戳的指标
	machineInfo.Timestamp = time.Time{}
	klet.setCachedMachineInfo(machineInfo)
	// 创建 imageBackOff 对象
	imageBackOff := flowcontrol.NewBackOff(backOffPeriod, MaxContainerBackOff)
	
    // 创建 livenessManager、readinessManager 和 startupManager 对象
	klet.livenessManager = proberesults.NewManager()
	klet.readinessManager = proberesults.NewManager()
	klet.startupManager = proberesults.NewManager()
    // 创建 podCache 对象
	klet.podCache = kubecontainer.NewCache()
	// 创建 mirrorPodClient 对象
	klet.mirrorPodClient = kubepod.NewBasicMirrorClient(klet.kubeClient, string(nodeName), nodeLister)
	// 创建 podManager 对象
    klet.podManager = kubepod.NewBasicPodManager()
	// 创建 statusManager 对象
	klet.statusManager = status.NewManager(klet.kubeClient, klet.podManager, klet, kubeDeps.PodStartupLatencyTracker, klet.getRootDir())
	// 创建 resourceAnalyzer 对象
	klet.resourceAnalyzer = serverstats.NewResourceAnalyzer(klet, kubeCfg.VolumeStatsAggPeriod.Duration, kubeDeps.Recorder)
	// 将kubeDeps.RemoteRuntimeService赋值给klet.runtimeService
	klet.runtimeService = kubeDeps.RemoteRuntimeService
	// 如果kubeDeps.KubeClient不为nil，则创建一个runtimeclass.Manager对象并赋值给klet.runtimeClassManager
	if kubeDeps.KubeClient != nil {
		klet.runtimeClassManager = runtimeclass.NewManager(kubeDeps.KubeClient)
	}

	containerLogManager, err := logs.NewContainerLogManager(
		klet.runtimeService,
		kubeDeps.OSInterface,
		kubeCfg.ContainerLogMaxSize,
		int(kubeCfg.ContainerLogMaxFiles),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize container log manager: %v", err)
	
    // 创建一个logs.ContainerLogManager对象并将其赋值给klet.containerLogManager
	klet.containerLogManager = containerLogManager
	// 创建一个新的ReasonCache对象并赋值给klet.reasonCache
	klet.reasonCache = NewReasonCache()
    // 创建一个基本的WorkQueue对象并将其赋值给klet.workQueue，其中klet.clock是一个时钟对象
	klet.workQueue = queue.NewBasicWorkQueue(klet.clock)
    // 使用给定的参数创建一个新的PodWorkers对象并赋值给klet.podWorkers
	klet.podWorkers = newPodWorkers(
		klet,
		kubeDeps.Recorder,
		klet.workQueue,
		klet.resyncInterval,
		backOffPeriod,
		klet.podCache,
	)
	// 创建一个新的KubeGenericRuntimeManager对象并将其赋值给klet.containerRuntime、klet.streamingRuntime和klet.runner
	runtime, err := kuberuntime.NewKubeGenericRuntimeManager(
		kubecontainer.FilterEventRecorder(kubeDeps.Recorder),
		klet.livenessManager,
		klet.readinessManager,
		klet.startupManager,
		rootDirectory,
		machineInfo,
		klet.podWorkers,
		kubeDeps.OSInterface,
		klet,
		insecureContainerLifecycleHTTPClient,
		imageBackOff,
		kubeCfg.SerializeImagePulls,
		kubeCfg.MaxParallelImagePulls,
		float32(kubeCfg.RegistryPullQPS),
		int(kubeCfg.RegistryBurst),
		imageCredentialProviderConfigFile,
		imageCredentialProviderBinDir,
		kubeCfg.CPUCFSQuota,
		kubeCfg.CPUCFSQuotaPeriod,
		kubeDeps.RemoteRuntimeService,
		kubeDeps.RemoteImageService,
		kubeDeps.ContainerManager,
		klet.containerLogManager,
		klet.runtimeClassManager,
		seccompDefault,
		kubeCfg.MemorySwap.SwapBehavior,
		kubeDeps.ContainerManager.GetNodeAllocatableAbsolute,
		*kubeCfg.MemoryThrottlingFactor,
		kubeDeps.PodStartupLatencyTracker,
		kubeDeps.TracerProvider,
	)
	if err != nil {
		return nil, err
	}
	klet.containerRuntime = runtime
	klet.streamingRuntime = runtime
	klet.runner = runtime
	// 使用给定的参数创建一个新的RuntimeCache对象并将其赋值给klet.runtimeCache
	runtimeCache, err := kubecontainer.NewRuntimeCache(klet.containerRuntime, runtimeCacheRefreshPeriod)
	if err != nil {
		return nil, err
	}
	klet.runtimeCache = runtimeCache

	// 使用kubecontainer.RealOS作为操作系统接口创建一个新的HostStatsProvider对象，并指定一个函数用于获取与kubelet管理的Pod关联的主机文件系统使用情况，并将其赋值给hostStatsProvider
	hostStatsProvider := stats.NewHostStatsProvider(kubecontainer.RealOS{}, func(podUID types.UID) string {
		return getEtcHostsPath(klet.getPodDir(podUID))
	})
    // 根据kubeDeps.useLegacyCadvisorStats的值选择使用不同的统计数据提供程序，如果为true，则创建一个使用Cadvisor的统计数据提供程序并将其赋值给klet.StatsProvider；
    //否则，创建一个使用CRI的统计数据提供程序并将其赋值给klet.StatsProvider
	if kubeDeps.useLegacyCadvisorStats {
		klet.StatsProvider = stats.NewCadvisorStatsProvider(
			klet.cadvisor,
			klet.resourceAnalyzer,
			klet.podManager,
			klet.runtimeCache,
			klet.containerRuntime,
			klet.statusManager,
			hostStatsProvider)
	} else {
		klet.StatsProvider = stats.NewCRIStatsProvider(
			klet.cadvisor,
			klet.resourceAnalyzer,
			klet.podManager,
			klet.runtimeCache,
			kubeDeps.RemoteRuntimeService,
			kubeDeps.RemoteImageService,
			hostStatsProvider,
			utilfeature.DefaultFeatureGate.Enabled(features.PodAndContainerStatsFromCRI))
	}

	eventChannel := make(chan *pleg.PodLifecycleEvent, plegChannelCapacity)

	if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
		// 当启用Evented PLEG时，将Generic PLEG的重列出周期和阈值调整为较高的值
		genericRelistDuration := &pleg.RelistDuration{
			RelistPeriod:    eventedPlegRelistPeriod,
			RelistThreshold: eventedPlegRelistThreshold,
		}
		klet.pleg = pleg.NewGenericPLEG(klet.containerRuntime, eventChannel, genericRelistDuration, klet.podCache, clock.RealClock{})
		// 如果Evented PLEG被启用，创建一个新的GenericPLEG对象，并将其赋值给klet.pleg
        // 在Evented PLEG由于错误而回退到Generic PLEG时，
        // Evented PLEG应能够将Generic PLEG的重列出持续时间重置为默认值。
		eventedRelistDuration := &pleg.RelistDuration{
			RelistPeriod:    genericPlegRelistPeriod,
			RelistThreshold: genericPlegRelistThreshold,
		}
        // 创建一个新的EventedPLEG对象，并将其赋值给klet.eventedPleg
		klet.eventedPleg = pleg.NewEventedPLEG(klet.containerRuntime, klet.runtimeService, eventChannel,
			klet.podCache, klet.pleg, eventedPlegMaxStreamRetries, eventedRelistDuration, clock.RealClock{})
	} else {
		genericRelistDuration := &pleg.RelistDuration{
			RelistPeriod:    genericPlegRelistPeriod,
			RelistThreshold: genericPlegRelistThreshold,
		}
        // 如果未启用Evented PLEG，创建一个新的GenericPLEG对象，并将其赋值给klet.pleg
		klet.pleg = pleg.NewGenericPLEG(klet.containerRuntime, eventChannel, genericRelistDuration, klet.podCache, clock.RealClock{})
	}
	// 创建一个新的RuntimeState对象，并将其赋值给klet.runtimeState
	klet.runtimeState = newRuntimeState(maxWaitForContainerRuntime)
    // 向runtimeState添加一个名为"PLEG"的健康检查，检查是否klet.pleg.Healthy
	klet.runtimeState.addHealthCheck("PLEG", klet.pleg.Healthy)
    // 如果启用了EventedPLEG特性，则向runtimeState添加一个名为"EventedPLEG"的健康检查，检查是否klet.eventedPleg.Healthy
	if utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
		klet.runtimeState.addHealthCheck("EventedPLEG", klet.eventedPleg.Healthy)
	
    // 更新Pod的CIDR，并在发生错误时记录错误日志
	if _, err := klet.updatePodCIDR(ctx, kubeCfg.PodCIDR); err != nil {
		klog.ErrorS(err, "Pod CIDR update failed")
	}

	// 创建一个新的ContainerGC对象，并将其赋值给klet.containerGC
	containerGC, err := kubecontainer.NewContainerGC(klet.containerRuntime, containerGCPolicy, klet.sourcesReady)
	if err != nil {
		return nil, err
	}
	klet.containerGC = containerGC
    // 使用给定的参数创建一个新的PodContainerDeletor对象，并将其赋值给klet.containerDeletor
	klet.containerDeletor = newPodContainerDeletor(klet.containerRuntime, integer.IntMax(containerGCPolicy.MaxPerPodContainer, minDeadContainerInPod))

	// 使用给定的参数创建一个新的ImageGCManager对象，并将其赋值给klet.imageManager
	imageManager, err := images.NewImageGCManager(klet.containerRuntime, klet.StatsProvider, kubeDeps.Recorder, nodeRef, imageGCPolicy, crOptions.PodSandboxImage, kubeDeps.TracerProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize image manager: %v", err)
	}
	klet.imageManager = imageManager
	// 如果满足条件，则创建一个新的KubeletServerCertificateManager对象，并将其赋值给klet.serverCertificateManager，并设置TLSOptions的GetCertificate函数以获取当前的证书
	if kubeCfg.ServerTLSBootstrap && kubeDeps.TLSOptions != nil && utilfeature.DefaultFeatureGate.Enabled(features.RotateKubeletServerCertificate) {
		klet.serverCertificateManager, err = kubeletcertificate.NewKubeletServerCertificateManager(klet.kubeClient, kubeCfg, klet.nodeName, klet.getLastObservedNodeAddresses, certDirectory)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize certificate manager: %v", err)
		}
		kubeDeps.TLSOptions.Config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := klet.serverCertificateManager.Current()
			if cert == nil {
				return nil, fmt.Errorf("no serving certificate available for the kubelet")
			}
			return cert, nil
		}
	}
	// 如果kubeDeps.ProbeManager不为nil，则将其赋值给klet.probeManager，否则创建一个新的ProbeManager对象，并将其赋值给klet.probeManager
	if kubeDeps.ProbeManager != nil {
		klet.probeManager = kubeDeps.ProbeManager
	} else {
		klet.probeManager = prober.NewManager(
			klet.statusManager,
			klet.livenessManager,
			klet.readinessManager,
			klet.startupManager,
			klet.runner,
			kubeDeps.Recorder)
	}
	// 使用kubeDeps.KubeClient创建一个新的TokenManager对象，并将其赋值给tokenManager
	tokenManager := token.NewManager(kubeDeps.KubeClient)

	// 使用给定的参数创建一个新的InitializedVolumePluginMgr对象，并将其赋值给klet.volumePluginMgr
	klet.volumePluginMgr, err =
		NewInitializedVolumePluginMgr(klet, secretManager, configMapManager, tokenManager, kubeDeps.VolumePlugins, kubeDeps.DynamicPluginProber)
	if err != nil {
		return nil, err
	}
    // 使用klet.getPluginsRegistrationDir()和kubeDeps.Recorder创建一个新的PluginManager对象，并将其赋值给klet.pluginManager
	klet.pluginManager = pluginmanager.NewPluginManager(
		klet.getPluginsRegistrationDir(), /* sockDir */
		kubeDeps.Recorder,
	)

	// 如果experimentalMounterPath不为空，则在containerized-mounter的rootfs/etc/resolv.conf中替换nameserver为kubelet.ClusterDNS
	if len(experimentalMounterPath) != 0 {
		// Replace the nameserver in containerized-mounter's rootfs/etc/resolv.conf with kubelet.ClusterDNS
		// so that service name could be resolved
		klet.dnsConfigurer.SetupDNSinContainerizedMounter(experimentalMounterPath)
	}

	// 使用给定的参数创建一个新的VolumeManager对象，并将其赋值给klet.volumeManager
	klet.volumeManager = volumemanager.NewVolumeManager(
		kubeCfg.EnableControllerAttachDetach,
		nodeName,
		klet.podManager,
		klet.podWorkers,
		klet.kubeClient,
		klet.volumePluginMgr,
		klet.containerRuntime,
		kubeDeps.Mounter,
		kubeDeps.HostUtil,
		klet.getPodsDir(),
		kubeDeps.Recorder,
		keepTerminatedPodVolumes,
		volumepathhandler.NewBlockVolumePathHandler())
	// 使用给定的参数创建一个新的BackOff对象，并将其赋值给klet.backOff
	klet.backOff = flowcontrol.NewBackOff(backOffPeriod, MaxContainerBackOff)

	// 使用给定的参数创建一个新的EvictionManager对象，并将其赋值给klet.evictionManager，同时将evictionAdmitHandler添加到klet.admitHandlers中的PodAdmitHandler列表中
	evictionManager, evictionAdmitHandler := eviction.NewManager(klet.resourceAnalyzer, evictionConfig,
		killPodNow(klet.podWorkers, kubeDeps.Recorder), klet.imageManager, klet.containerGC, kubeDeps.Recorder, nodeRef, klet.clock, kubeCfg.LocalStorageCapacityIsolation)
	// 将evictionManager赋值给klet.evictionManager，并将evictionAdmitHandler添加到klet.admitHandlers的PodAdmitHandler列表中
	klet.evictionManager = evictionManager
	klet.admitHandlers.AddPodAdmitHandler(evictionAdmitHandler)

	// 将sysctlsAllowlist添加到klet.admitHandlers的PodAdmitHandler列表中
	safeAndUnsafeSysctls := append(sysctl.SafeSysctlAllowlist(), allowedUnsafeSysctls...)
	sysctlsAllowlist, err := sysctl.NewAllowlist(safeAndUnsafeSysctls)
	if err != nil {
		return nil, err
	}
	klet.admitHandlers.AddPodAdmitHandler(sysctlsAllowlist)

	// 创建一个ActiveDeadlineHandler对象，并将其添加为klet的PodSyncLoopHandler和PodSyncHandler
	activeDeadlineHandler, err := newActiveDeadlineHandler(klet.statusManager, kubeDeps.Recorder, klet.clock)
	if err != nil {
		return nil, err
	}
	klet.AddPodSyncLoopHandler(activeDeadlineHandler)
	klet.AddPodSyncHandler(activeDeadlineHandler)
	// 将klet.containerManager.GetAllocateResourcesPodAdmitHandler()添加到klet.admitHandlers的PodAdmitHandler列表中
	klet.admitHandlers.AddPodAdmitHandler(klet.containerManager.GetAllocateResourcesPodAdmitHandler())
	
   // 创建一个CriticalPodAdmissionHandler对象，并将其添加到klet.admitHandlers的PodAdmitHandler列表中
	criticalPodAdmissionHandler := preemption.NewCriticalPodAdmissionHandler(klet.GetActivePods, killPodNow(klet.podWorkers, kubeDeps.Recorder), kubeDeps.Recorder)
	klet.admitHandlers.AddPodAdmitHandler(lifecycle.NewPredicateAdmitHandler(klet.getNodeAnyWay, criticalPodAdmissionHandler, klet.containerManager.UpdatePluginResources))
	// 对kubeDeps.Options中的每个选项应用函数
	for _, opt := range kubeDeps.Options {
		opt(klet)
	}
	// 如果操作系统是Linux，则创建一个AppArmorValidator对象并赋值给klet.appArmorValidator，并将其添加到klet.softAdmitHandlers的PodAdmitHandler列表中
	if sysruntime.GOOS == "linux" {
		// AppArmor is a Linux kernel security module and it does not support other operating systems.
		klet.appArmorValidator = apparmor.NewValidator()
		klet.softAdmitHandlers.AddPodAdmitHandler(lifecycle.NewAppArmorAdmitHandler(klet.appArmorValidator))
	}

	leaseDuration := time.Duration(kubeCfg.NodeLeaseDurationSeconds) * time.Second
	renewInterval := time.Duration(float64(leaseDuration) * nodeLeaseRenewIntervalFraction)
    // 使用给定的参数创建一个新的NodeLeaseController对象，并将其赋值给klet.nodeLeaseController
	klet.nodeLeaseController = lease.NewController(
		klet.clock,
		klet.heartbeatClient,
		string(klet.nodeName),
		kubeCfg.NodeLeaseDurationSeconds,
		klet.onRepeatedHeartbeatFailure,
		renewInterval,
		string(klet.nodeName),
		v1.NamespaceNodeLease,
		util.SetNodeOwnerFunc(klet.heartbeatClient, string(klet.nodeName)))

	// 设置节点关闭管理器
	shutdownManager, shutdownAdmitHandler := nodeshutdown.NewManager(&nodeshutdown.Config{
		Logger:                           logger,
		ProbeManager:                     klet.probeManager,
		Recorder:                         kubeDeps.Recorder,
		NodeRef:                          nodeRef,
		GetPodsFunc:                      klet.GetActivePods,
		KillPodFunc:                      killPodNow(klet.podWorkers, kubeDeps.Recorder),
		SyncNodeStatusFunc:               klet.syncNodeStatus,
		ShutdownGracePeriodRequested:     kubeCfg.ShutdownGracePeriod.Duration,
		ShutdownGracePeriodCriticalPods:  kubeCfg.ShutdownGracePeriodCriticalPods.Duration,
		ShutdownGracePeriodByPodPriority: kubeCfg.ShutdownGracePeriodByPodPriority,
		StateDirectory:                   rootDirectory,
	})
    // 创建一个新的ShutdownManager对象，并将其赋值给shutdownManager
	klet.shutdownManager = shutdownManager
    // 使用klet创建一个UserNsManager对象，并将其赋值给klet.usernsManager。如果发生错误，返回错误和nil
	klet.usernsManager, err = userns.MakeUserNsManager(klet)
	if err != nil {
		return nil, err
	}
    // 将shutdownAdmitHandler添加到klet.admitHandlers的PodAdmitHandler列表中
	klet.admitHandlers.AddPodAdmitHandler(shutdownAdmitHandler)

	// 最后，将最新版本的配置放在Kubelet上，以便人们可以查看配置的方式
    // 将kubeCfg的值复制给klet.kubeletConfiguration
	klet.kubeletConfiguration = *kubeCfg

	// 生成状态函数应该是我们最后要做的事情，
	// 因为这依赖于Kubelet的其余部分已经构建完成。
	klet.setNodeStatusFuncs = klet.defaultNodeStatusFuncs() // 将klet.defaultNodeStatusFuncs()的返回值赋值给klet.setNodeStatusFuncs

	return klet, nil
}
```

#### GetConfiguration

```go
// GetConfiguration returns the KubeletConfiguration used to configure the kubelet.
func (kl *Kubelet) GetConfiguration() kubeletconfiginternal.KubeletConfiguration {
	return kl.kubeletConfiguration
}
```

#### BirthCry

```go
// BirthCry发送一个事件，表示kubelet已经启动。
func (kl *Kubelet) BirthCry() {
    // 创建一个kubelet重新启动的事件。
    kl.recorder.Eventf(kl.nodeRef, v1.EventTypeNormal, events.StartingKubelet, "Starting kubelet.")
}
```

#### StartGarbageCollection

```go
// StartGarbageCollection启动垃圾回收线程。
func (kl *Kubelet) StartGarbageCollection() {
	loggedContainerGCFailure := false
    // 启动一个goroutine，定期执行垃圾回收操作。
    go wait.Until(func() {
        ctx := context.Background()
        // 执行容器垃圾回收操作。
        if err := kl.containerGC.GarbageCollect(ctx); err != nil {
            klog.ErrorS(err, "容器垃圾回收失败")
            kl.recorder.Eventf(kl.nodeRef, v1.EventTypeWarning, events.ContainerGCFailed, err.Error())
            loggedContainerGCFailure = true
        } else {
            var vLevel klog.Level = 4
            if loggedContainerGCFailure {
                vLevel = 1
                loggedContainerGCFailure = false
            }

            klog.V(vLevel).InfoS("容器垃圾回收成功")
        }
    }, ContainerGCPeriod, wait.NeverStop)

    // 当高阈值设置为100时，停用镜像垃圾回收管理器。
    if kl.kubeletConfiguration.ImageGCHighThresholdPercent == 100 {
        klog.V(2).InfoS("ImageGCHighThresholdPercent设置为100，停用镜像垃圾回收")
        return
    }

    prevImageGCFailed := false

    // 启动一个goroutine，定期执行镜像垃圾回收操作。
    go wait.Until(func() {
        ctx := context.Background()
        // 执行镜像垃圾回收操作。
        if err := kl.imageManager.GarbageCollect(ctx); err != nil {
            if prevImageGCFailed {
                klog.ErrorS(err, "连续多次镜像垃圾回收失败")
                // 只在连续失败时创建一个事件。
                kl.recorder.Eventf(kl.nodeRef, v1.EventTypeWarning, events.ImageGCFailed, err.Error())
            } else {
                klog.ErrorS(err, "镜像垃圾回收失败一次。可能尚未完成统计初始化")
            }
            prevImageGCFailed = true
        } else {
            var vLevel klog.Level = 4
            if prevImageGCFailed {
                vLevel = 1
                prevImageGCFailed = false
            }

            klog.V(vLevel).InfoS("镜像垃圾回收成功")
        }
    }, ImageGCPeriod, wait.NeverStop)
}
```

#### ListenAndServe

```go
// ListenAndServe运行kubelet的HTTP服务器。
func (kl *Kubelet) ListenAndServe(kubeCfg *kubeletconfiginternal.KubeletConfiguration, tlsOptions *server.TLSOptions,
auth server.AuthInterface, tp trace.TracerProvider) {
	server.ListenAndServeKubeletServer(kl, kl.resourceAnalyzer, kubeCfg, tlsOptions, auth, tp)
}
```

##### ListenAndServeKubeletServer

```go
// ListenAndServeKubeletServer初始化一个服务器，用于响应Kubelet上的HTTP网络请求。
func ListenAndServeKubeletServer(
	host HostInterface,
	resourceAnalyzer stats.ResourceAnalyzer,
	kubeCfg *kubeletconfiginternal.KubeletConfiguration,
	tlsOptions *TLSOptions,
	auth AuthInterface,
	tp oteltrace.TracerProvider) {

	address := netutils.ParseIPSloppy(kubeCfg.Address)
	port := uint(kubeCfg.Port)
	klog.InfoS("Starting to listen", "address", address, "port", port)
	handler := NewServer(host, resourceAnalyzer, auth, tp, kubeCfg)
	s := &http.Server{
		Addr:           net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)),
		Handler:        &handler,
		IdleTimeout:    90 * time.Second,// 与http.DefaultTransport的保持活动超时时间匹配
		ReadTimeout:    4 * 60 * time.Minute,
		WriteTimeout:   4 * 60 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}

	if tlsOptions != nil {
		s.TLSConfig = tlsOptions.Config
		// 将空字符串作为证书和密钥文件传递意味着没有指定证书/密钥，应该调用TLSConfig中的GetCertificate函数。
		if err := s.ListenAndServeTLS(tlsOptions.CertFile, tlsOptions.KeyFile); err != nil {
			klog.ErrorS(err, "Failed to listen and serve")
			os.Exit(1)
		}
	} else if err := s.ListenAndServe(); err != nil {
		klog.ErrorS(err, "Failed to listen and serve")
		os.Exit(1)
	}
}
```

#### ListenAndServeReadOnly

```go
// ListenAndServeReadOnly以只读模式运行kubelet的HTTP服务器。
func (kl *Kubelet) ListenAndServeReadOnly(address net.IP, port uint) {
	server.ListenAndServeKubeletReadOnlyServer(kl, kl.resourceAnalyzer, address, port)
}
```

##### ListenAndServeKubeletReadOnlyServer

````go
// ListenAndServeKubeletReadOnlyServer初始化一个服务器，用于响应Kubelet上的HTTP网络请求。
func ListenAndServeKubeletReadOnlyServer(
	host HostInterface,
	resourceAnalyzer stats.ResourceAnalyzer,
	address net.IP,
	port uint) {
	klog.InfoS("Starting to listen read-only", "address", address, "port", port)
	// TODO: https://github.com/kubernetes/kubernetes/issues/109829 tracer should use WithPublicEndpoint
	s := NewServer(host, resourceAnalyzer, nil, oteltrace.NewNoopTracerProvider(), nil)

	server := &http.Server{
		Addr:           net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)),
		Handler:        &s,
		IdleTimeout:    90 * time.Second, // matches http.DefaultTransport keep-alive timeout
		ReadTimeout:    4 * 60 * time.Minute,
		WriteTimeout:   4 * 60 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}

	if err := server.ListenAndServe(); err != nil {
		klog.ErrorS(err, "Failed to listen and serve")
		os.Exit(1)
	}
}
````

#### ListenAndServePodResources

```go
// ListenAndServePodResources运行kubelet的podresources gRPC服务。
func (kl *Kubelet) ListenAndServePodResources() {
	endpoint, err := util.LocalEndpoint(kl.getPodResourcesDir(), podresources.Socket)
	if err != nil {
		klog.V(2).InfoS("Failed to get local endpoint for PodResources endpoint", "err", err)
		return
	}

	providers := podresources.PodResourcesProviders{
		Pods:             kl.podManager,
		Devices:          kl.containerManager,
		Cpus:             kl.containerManager,
		Memory:           kl.containerManager,
		DynamicResources: kl.containerManager,
	}

	server.ListenAndServePodResources(endpoint, providers)
}
```

##### LocalEndpoint

```go
// LocalEndpoint返回给定终端点的unix套接字的完整路径。
func LocalEndpoint(path, file string) (string, error) {
    u := url.URL{
        Scheme: unixProtocol,
        Path: path,
    }
    return filepath.Join(u.String(), file+".sock"), nil
}
```

##### getPodResourcesDir

```go
// getPodResourcesDir返回包含pod资源套接字的目录的完整路径。
func (kl *Kubelet) getPodResourcesDir() string {
	return filepath.Join(kl.getRootDir(), config.DefaultKubeletPodResourcesDirName)
}
```



```go
// ListenAndServePodResources初始化一个gRPC服务器来提供PodResources服务。
func ListenAndServePodResources(endpoint string, providers podresources.PodResourcesProviders) {
	server := grpc.NewServer(podresourcesgrpc.WithRateLimiter(podresourcesgrpc.DefaultQPS, podresourcesgrpc.DefaultBurstTokens))

	podresourcesapiv1alpha1.RegisterPodResourcesListerServer(server, podresources.NewV1alpha1PodResourcesServer(providers))
	podresourcesapi.RegisterPodResourcesListerServer(server, podresources.NewV1PodResourcesServer(providers))

	l, err := util.CreateListener(endpoint)
	if err != nil {
		klog.ErrorS(err, "Failed to create listener for podResources endpoint")
		os.Exit(1)
	}

	klog.InfoS("Starting to serve the podresources API", "endpoint", endpoint)
	if err := server.Serve(l); err != nil {
		klog.ErrorS(err, "Failed to serve")
		os.Exit(1)
	}
}
```

###### CreateListener

```go
// CreateListener在指定的终端点上创建一个监听器。
func CreateListener(endpoint string) (net.Listener, error) {
	protocol, addr, err := parseEndpointWithFallbackProtocol(endpoint, unixProtocol)
	if err != nil {
		return nil, err
	}
	if protocol != unixProtocol {
		return nil, fmt.Errorf("only support unix socket endpoint")
	}

	// 清理先前的套接字文件。
	err = unix.Unlink(addr)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to unlink socket file %q: %v", addr, err)
	}

	if err := os.MkdirAll(filepath.Dir(addr), 0750); err != nil {
		return nil, fmt.Errorf("error creating socket directory %q: %v", filepath.Dir(addr), err)
	}

	// 在临时文件上创建套接字，并将其移动到目标套接字以处理不正确的清理
	file, err := os.CreateTemp(filepath.Dir(addr), "")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %v", err)
	}

	if err := os.Remove(file.Name()); err != nil {
		return nil, fmt.Errorf("failed to remove temporary file: %v", err)
	}

	l, err := net.Listen(protocol, file.Name())
	if err != nil {
		return nil, err
	}

	if err = os.Rename(file.Name(), addr); err != nil {
		return nil, fmt.Errorf("failed to move temporary file to addr %q: %v", addr, err)
	}

	return l, nil
}
```

##### RunOnce

```go
// RunOnce函数从配置更新中获取并运行相关的Pod。
func (kl *Kubelet) RunOnce(updates <-chan kubetypes.PodUpdate) ([]RunPodResult, error) {
	ctx := context.Background()
	// 如果容器日志目录不存在，则创建它。
	if err := kl.setupDataDirs(); err != nil {
		return nil, err
	}

	// If the container logs directory does not exist, create it.
	if _, err := os.Stat(ContainerLogsDir); err != nil {
		if err := kl.os.MkdirAll(ContainerLogsDir, 0755); err != nil {
			klog.ErrorS(err, "Failed to create directory", "path", ContainerLogsDir)
		}
	}

	select {
	case u := <-updates:
		klog.InfoS("Processing manifest with pods", "numPods", len(u.Pods))
		result, err := kl.runOnce(ctx, u.Pods, runOnceRetryDelay)
		klog.InfoS("Finished processing pods", "numPods", len(u.Pods))
		return result, err
	case <-time.After(runOnceManifestDelay):
		return nil, fmt.Errorf("no pod manifest update after %v", runOnceManifestDelay)
	}
}
```

###### runOnce

```go
// runOnce函数运行给定的一组Pod，并返回它们的状态。
func (kl *Kubelet) runOnce(ctx context.Context, pods []*v1.Pod, retryDelay time.Duration) (results []RunPodResult, err error) {
	ch := make(chan RunPodResult)
	admitted := []*v1.Pod{}
	for _, pod := range pods {
		// 检查是否可以接受该Pod。
		if ok, reason, message := kl.canAdmitPod(admitted, pod); !ok {
			kl.rejectPod(pod, reason, message)
			results = append(results, RunPodResult{pod, nil})
			continue
		}

		admitted = append(admitted, pod)
		go func(pod *v1.Pod) {
			err := kl.runPod(ctx, pod, retryDelay)
			ch <- RunPodResult{pod, err}
		}(pod)
	}

	klog.InfoS("Waiting for pods", "numPods", len(admitted))
	failedPods := []string{}
	for i := 0; i < len(admitted); i++ {
		res := <-ch
		results = append(results, res)
		if res.Err != nil {
			failedContainerName, err := kl.getFailedContainers(ctx, res.Pod)
			if err != nil {
				klog.InfoS("Unable to get failed containers' names for pod", "pod", klog.KObj(res.Pod), "err", err)
			} else {
				klog.InfoS("Unable to start pod because container failed", "pod", klog.KObj(res.Pod), "containerName", failedContainerName)
			}
			failedPods = append(failedPods, format.Pod(res.Pod))
		} else {
			klog.InfoS("Started pod", "pod", klog.KObj(res.Pod))
		}
	}
	if len(failedPods) > 0 {
		return results, fmt.Errorf("error running pods: %v", failedPods)
	}
	klog.InfoS("Pods started", "numPods", len(pods))
	return results, err
}
```

