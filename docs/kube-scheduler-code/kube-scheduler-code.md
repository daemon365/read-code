---
id: 1-kube-scheduler-code 
title: kube-scheduler 启动逻辑代码走读
description: kube-scheduler 启动逻辑代码走读
keywords:
  - kubernetes
  - kube-scheduler
slug: /
---

## 介绍

Kube-scheduler是Kubernetes中的一个组件，用于将新的Pod调度到集群中的合适节点上。它监视集群中新创建的Pod，并根据指定的调度策略将其分配给可用的节点。Kube-scheduler可以自动识别节点的资源使用情况和可用性，并将Pod调度到具有足够资源的节点上，以确保Pod的高可用性和性能。

Kube-scheduler的工作流程如下：

1. Kube-scheduler通过API Server监听新创建的Pod。
2. Kube-scheduler检查每个Pod的调度要求（例如资源需求和亲和性要求）。
3. Kube-scheduler将Pod与可用的节点进行匹配。
4. Kube-scheduler选择最佳节点，并将Pod绑定到该节点上。
5. Kube-scheduler向API Server发送调度结果，将Pod的绑定信息更新到etcd中。

Kube-scheduler可以配置多种调度策略，例如默认的策略、亲和性和反亲和性策略、节点亲和性和反亲和性策略、Pod亲和性和反亲和性策略等，以适应不同的应用场景。

代码位置：`https://github.com/kubernetes/kubernetes/blob/master/cmd/kube-scheduler`

## 启动函数

```go
func main() {
	command := app.NewSchedulerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
```

`app.NewSchedulerCommand()` 函数返回一个 `cmd *cobra.Command` 对象，该对象是一个命令行参数的集合。这个对象可以让你将命令绑定到其中，以便在启动时接受各种参数。

`cmd *cobra.Command` 对象来源于 `spf13/cobra` 包，这个包是一个用于现代 Go CLI 交互的命令行工具。使用 `cmd *cobra.Command` 对象，你可以轻松地将命令行参数集成到你的应用程序中，以方便用户在启动时配置应用程序的各种选项。

在实际应用程序中，你可以将 `cmd *cobra.Command` 对象与其他应用程序逻辑相结合，以便在运行时自动执行一些操作，例如根据命令行参数初始化应用程序的配置等。这个功能非常有用，特别是当你需要在应用程序启动时进行一些特殊处理时。

`cli.Run(command)` 是一个自定义函数，它的作用是启动 `cmd *cobra.Command` 对象并执行其中的命令行参数。在这之前，它还可以进行一些初始化操作，例如初始化日志、设置日志级别、设置日志格式等。这些操作可以确保应用程序在启动时能够正确地记录日志，并且可以方便地进行故障排除和调试。

## NewSchedulerCommand

```GO
func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {
	opts := options.NewOptions() // 创建一个新的 Options 实例

	cmd := &cobra.Command{ // 创建一个 cobra.Command 实例
		Use: "kube-scheduler", // 设置命令的使用说明
		Long: `The Kubernetes scheduler is a control plane process which assigns
Pods to Nodes. The scheduler determines which Nodes are valid placements for
each Pod in the scheduling queue according to constraints and available
resources. The scheduler then ranks each valid Node and binds the Pod to a
suitable Node. Multiple different schedulers may be used within a cluster;
kube-scheduler is the reference implementation.
See [scheduling](https://kubernetes.io/docs/concepts/scheduling-eviction/)
for more information about scheduling and the kube-scheduler component.`, // 设置命令的详细说明
		RunE: func(cmd *cobra.Command, args []string) error { // 设置命令的运行函数
			return runCommand(cmd, opts, registryOptions...) // 调用 runCommand 函数并传入参数
		},
		Args: func(cmd *cobra.Command, args []string) error { // 设置命令的参数验证函数
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	nfs := opts.Flags // 获取 Options 实例的 Flags
	verflag.AddFlags(nfs.FlagSet("global")) // 添加全局标志到 Flags
	globalflag.AddGlobalFlags(nfs.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags()) // 添加全局标志到 Flags
	fs := cmd.Flags() // 获取命令的 Flags
	for _, f := range nfs.FlagSets { // 遍历 Options 实例的 FlagSets
		fs.AddFlagSet(f) // 将 FlagSet 添加到命令的 Flags
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout()) // 获取终端的大小
	cliflag.SetUsageAndHelpFunc(cmd, *nfs, cols) // 设置命令的使用和帮助函数

	if err := cmd.MarkFlagFilename("config", "yaml", "yml", "json"); err != nil { // 给命令的 "config" 标志设置文件名后缀限制
		klog.Background().Error(err, "Failed to mark flag filename")
	}

	return cmd // 返回创建的命令实例
}
```

### Options

- Options是一些一些参数

```GO
type Options struct {
	// 默认值。
	ComponentConfig *kubeschedulerconfig.KubeSchedulerConfiguration // 组件配置

	SecureServing  *apiserveroptions.SecureServingOptionsWithLoopback // 安全服务选项
	Authentication *apiserveroptions.DelegatingAuthenticationOptions // 委托认证选项
	Authorization  *apiserveroptions.DelegatingAuthorizationOptions  // 委托授权选项
	Metrics        *metrics.Options // 指标选项
	Logs           *logs.Options // 日志选项
	Deprecated     *DeprecatedOptions // 弃用选项
	LeaderElection *componentbaseconfig.LeaderElectionConfiguration // 领导选举配置

	ConfigFile string // scheduler 服务器的配置文件路径
	WriteConfigTo string // 默认配置将被写入的路径

	Master string // Kubernetes API Server 的地址

	Flags *cliflag.NamedFlagSets // 解析后的 CLI 标志
}
```

### runCommand

```GO
func runCommand(cmd *cobra.Command, opts *options.Options, registryOptions ...Option) error {
	verflag.PrintAndExitIfRequested() // 如果命令行参数中包含版本信息相关的标志，则打印版本信息并退出

	// 在日志配置生效之前，尽早地激活日志记录，并显示带有最终日志配置的标志。
	if err := logsapi.ValidateAndApply(opts.Logs, utilfeature.DefaultFeatureGate); err != nil { // 校验并应用日志配置，如果出错则打印错误信息并退出
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	cliflag.PrintFlags(cmd.Flags()) // 打印命令行标志

	ctx, cancel := context.WithCancel(context.Background()) // 创建一个带有取消功能的上下文
	defer cancel() // 在函数返回前调用取消函数，确保资源被释放

	go func() {
		stopCh := server.SetupSignalHandler() // 设置信号处理器
		<-stopCh // 等待信号处理器接收到停止信号
		cancel() // 调用取消函数以取消上下文
	}()

	cc, sched, err := Setup(ctx, opts, registryOptions...) // 调用Setup函数设置运行环境
	if err != nil {
		return err // 如果设置过程中出错，则返回错误
	}

	utilfeature.DefaultMutableFeatureGate.AddMetrics() // 添加功能启用度量

	return Run(ctx, cc, sched) // 调用Run函数运行程序
}
```

#### Setup

```GO
func Setup(ctx context.Context, opts *options.Options, outOfTreeRegistryOptions ...Option) (*schedulerserverconfig.CompletedConfig, *scheduler.Scheduler, error) {
	if cfg, err := latest.Default(); err != nil { // 获取最新的默认配置
		return nil, nil, err // 如果获取失败，则返回错误
	} else {
		opts.ComponentConfig = cfg // 将获取到的默认配置设置为组件配置选项中的配置
	}

	if errs := opts.Validate(); len(errs) > 0 { // 验证组件配置选项的有效性
		return nil, nil, utilerrors.NewAggregate(errs) // 如果验证失败，则返回错误
	}

	c, err := opts.Config(ctx) // 根据组件配置选项创建配置
	if err != nil {
		return nil, nil, err // 如果创建配置失败，则返回错误
	}

	// 获取完整的配置
	cc := c.Complete()

	outOfTreeRegistry := make(runtime.Registry) // 创建一个新的外部注册表
	for _, option := range outOfTreeRegistryOptions { // 遍历外部注册表选项
		if err := option(outOfTreeRegistry); err != nil { // 如果调用外部注册表选项时出错，则返回错误
			return nil, nil, err
		}
	}

	recorderFactory := getRecorderFactory(&cc) // 获取事件记录器工厂
	completedProfiles := make([]kubeschedulerconfig.KubeSchedulerProfile, 0) // 创建一个空的已完成的配置文件切片

	// 创建调度器
	sched, err := scheduler.New(cc.Client,
		cc.InformerFactory,
		cc.DynInformerFactory,
		recorderFactory,
		ctx.Done(),
		scheduler.WithComponentConfigVersion(cc.ComponentConfig.TypeMeta.APIVersion),
		scheduler.WithKubeConfig(cc.KubeConfig),
		scheduler.WithProfiles(cc.ComponentConfig.Profiles...),
		scheduler.WithPercentageOfNodesToScore(cc.ComponentConfig.PercentageOfNodesToScore),
		scheduler.WithFrameworkOutOfTreeRegistry(outOfTreeRegistry),
		scheduler.WithPodMaxBackoffSeconds(cc.ComponentConfig.PodMaxBackoffSeconds),
		scheduler.WithPodInitialBackoffSeconds(cc.ComponentConfig.PodInitialBackoffSeconds),
		scheduler.WithPodMaxInUnschedulablePodsDuration(cc.PodMaxInUnschedulablePodsDuration),
		scheduler.WithExtenders(cc.ComponentConfig.Extenders...),
		scheduler.WithParallelism(cc.ComponentConfig.Parallelism),
		scheduler.WithBuildFrameworkCapturer(func(profile kubeschedulerconfig.KubeSchedulerProfile) {
			// 在Framework实例化期间处理配置文件以设置默认插件和配置项，将其捕获用于日志记录
			completedProfiles = append(completedProfiles, profile)
		}),
	)
	if err != nil {
		return nil, nil, err // 如果创建调度器失败，则返回错误
	}
	if err := options.LogOrWriteConfig(klog.FromContext(ctx), opts.WriteConfigTo, &cc.ComponentConfig, completedProfiles); err != nil {
		return nil, nil, err // 如果记录或写入配置时出错，则返回错误
	}

	return &cc, sched, nil // 返回完整的配置、调度器和空错误
}
```

##### Complete

```GO
func (c *Config) Complete() CompletedConfig {
	cc := completedConfig{c}

	apiserver.AuthorizeClientBearerToken(c.LoopbackClientConfig, &c.Authentication, &c.Authorization)

	return CompletedConfig{&cc}
}

type completedConfig struct {
	*Config
}

type Config struct {
	// 调度器服务器的配置对象
	ComponentConfig kubeschedulerconfig.KubeSchedulerConfiguration

	// ：用于特权回环连接的配置信息
	LoopbackClientConfig *restclient.Config

	Authentication apiserver.AuthenticationInfo
	Authorization  apiserver.AuthorizationInfo
	SecureServing  *apiserver.SecureServingInfo

	Client             clientset.Interface
	KubeConfig         *restclient.Config
	InformerFactory    informers.SharedInformerFactory
	DynInformerFactory dynamicinformer.DynamicSharedInformerFactory

	//nolint:staticcheck // SA1019 this deprecated field still needs to be used for now. It will be removed once the migration is done.
	EventBroadcaster events.EventBroadcasterAdapter

	// LeaderElection is optional.
	LeaderElection *leaderelection.LeaderElectionConfig

	// Pod在不可调度队列中最大的停留时间。如果Pod在不可调度队列中停留的时间超过这个值，将会被移到backoff队列或active队列中。
    // 如果这个值为空，将使用默认值（5分钟），类型为time.Duration。
	PodMaxInUnschedulablePodsDuration time.Duration
}
```

#### Run

```go
func Run(ctx context.Context, cc *schedulerserverconfig.CompletedConfig, sched *scheduler.Scheduler) error {
	logger := klog.FromContext(ctx)

	// To help debugging, immediately log version
	logger.Info("Starting Kubernetes Scheduler", "version", version.Get())

	logger.Info("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

	// Configz registration.
	// 注册 Configz，用于配置信息的管理和展示
	if cz, err := configz.New("componentconfig"); err == nil {
		cz.Set(cc.ComponentConfig)
	} else {
		return fmt.Errorf("unable to register configz: %s", err)
	}

	// Start events processing pipeline.
	// 启动事件处理流程
	cc.EventBroadcaster.StartRecordingToSink(ctx.Done())
	defer cc.EventBroadcaster.Shutdown()

	// Setup healthz checks.
	// 设置健康检查
	var checks []healthz.HealthChecker
	if cc.ComponentConfig.LeaderElection.LeaderElect {
		checks = append(checks, cc.LeaderElection.WatchDog)
	}

	waitingForLeader := make(chan struct{})
	isLeader := func() bool {
		select {
		case _, ok := <-waitingForLeader:
			// if channel is closed, we are leading
			return !ok
		default:
			// channel is open, we are waiting for a leader
			return false
		}
	}

	// Start up the healthz server.
	// 启动健康检查服务器
	if cc.SecureServing != nil {
		handler := buildHandlerChain(newHealthzAndMetricsHandler(&cc.ComponentConfig, cc.InformerFactory, isLeader, checks...), cc.Authentication.Authenticator, cc.Authorization.Authorizer)
		// TODO: handle stoppedCh and listenerStoppedCh returned by c.SecureServing.Serve
		if _, _, err := cc.SecureServing.Serve(handler, 0, ctx.Done()); err != nil {
			// fail early for secure handlers, removing the old error loop from above
			return fmt.Errorf("failed to start secure server: %v", err)
		}
	}

	// Start all informers.
	// 启动所有 informer
	cc.InformerFactory.Start(ctx.Done())
	// DynInformerFactory can be nil in tests.
	if cc.DynInformerFactory != nil {
		cc.DynInformerFactory.Start(ctx.Done())
	}

	// Wait for all caches to sync before scheduling.
	// 在调度之前等待所有缓存同步
	cc.InformerFactory.WaitForCacheSync(ctx.Done())
	// DynInformerFactory can be nil in tests.
	if cc.DynInformerFactory != nil {
		cc.DynInformerFactory.WaitForCacheSync(ctx.Done())
	}

	// If leader election is enabled, runCommand via LeaderElector until done and exit.
	// 如果启用了 leader 选举，则通过 LeaderElector 运行命令，直到完成并退出
	if cc.LeaderElection != nil {
		cc.LeaderElection.Callbacks = leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				close(waitingForLeader)
				sched.Run(ctx)
			},
            // OnStoppedLeading 是 LeaderCallbacks 接口的实现函数，在失去 leader 角色时调用
			// 根据情况选择是否终止程序或者进行错误处理
			OnStoppedLeading: func() {
				select {
				case <-ctx.Done():
					// 如果收到终止信号，则退出程序并返回状态码 0
					logger.Info("Requested to terminate, exiting")
					os.Exit(0)
				default:
					// 如果失去了 leader 角色，则记录错误信息并调用 klog.FlushAndExit 终止程序
					logger.Error(nil, "Leaderelection lost")
					klog.FlushAndExit(klog.ExitFlushTimeout, 1)
				}
			},
		}
        // 创建 LeaderElector 实例，并通过 Run 方法开始进行 leader 选举
		leaderElector, err := leaderelection.NewLeaderElector(*cc.LeaderElection)
		if err != nil {
			return fmt.Errorf("couldn't create leader elector: %v", err)
		}

		leaderElector.Run(ctx)

		return fmt.Errorf("lost lease")
	}

	// 如果禁用了 leader 选举，则直接执行 sched.Run(ctx) 函数进行任务调度
	// 返回错误信息 "finished without leader elect"
	close(waitingForLeader)
	sched.Run(ctx)
	return fmt.Errorf("finished without leader elect")
}
```

## Scheduler

```go
type Scheduler struct {
	// Cache 用于存储节点和 Pod 的缓存，NodeLister 和 Algorithm 可以观察到 Cache 的变化。
	Cache internalcache.Cache

	// Extenders 是一组用于调度扩展的接口。
    Extenders []framework.Extender

    // NextPod 是一个函数，用于阻塞直到下一个 Pod 可用。
    // 我们不使用 channel 是因为调度一个 Pod 可能需要一些时间，
    // 我们不希望在 channel 中等待的期间 Pod 变得过期。
    NextPod func() *framework.QueuedPodInfo

    // FailureHandler 是在调度失败时调用的处理函数。
    FailureHandler FailureHandlerFn

    // SchedulePod 尝试将给定的 Pod 调度到节点列表中的某个节点。
    // 在成功时返回一个 ScheduleResult 结构体，其中包含建议的主机名称，
    // 否则返回一个带有失败原因的 FitError。
    SchedulePod func(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) (ScheduleResult, error)

    // StopEverything 是一个通道，用于关闭调度器。
    StopEverything <-chan struct{}

    // SchedulingQueue 用于存储待调度的 Pod。
    SchedulingQueue internalqueue.SchedulingQueue

    // Profiles 是调度器的调度配置文件。
    Profiles profile.Map

    client clientset.Interface

    // nodeInfoSnapshot 是节点信息的快照。
    nodeInfoSnapshot *internalcache.Snapshot

    // percentageOfNodesToScore 是用于评分的节点百分比。
    percentageOfNodesToScore int32

    // nextStartNodeIndex 是下一个开始评分的节点索引。
    nextStartNodeIndex int
}

type ScheduleResult struct {
	// 被选中节点的名称。
	SuggestedHost string // 被调度器选择用于运行该 pod 的节点的名称
	// 在过滤阶段及之后，调度器评估了多少个节点。
	EvaluatedNodes int // 调度器评估该 pod 时考虑的节点数目
	// 在评估的节点中有多少个节点适合运行该 pod。
	FeasibleNodes int // 在所有评估的节点中，有多少个节点符合该 pod 的需求
	// 调度循环的提名信息。
	nominatingInfo *framework.NominatingInfo // 调度循环期间使用的提名信息
}
```

### Options

```go
type schedulerOptions struct {
	componentConfigVersion string       // 调度器组件的配置版本
	kubeConfig             *restclient.Config // Kubernetes API Server 的配置信息
	// 在 v1 中，如果 profile 级别设置了 percentageOfNodesToScore，则会覆盖此处设置。
	percentageOfNodesToScore int32 // 用于计算每个节点的资源得分的 pod 占总 pod 数量的百分比
	podInitialBackoffSeconds int64 // 用于计算 pod 调度失败后第一次重试等待的秒数
	podMaxBackoffSeconds     int64 // 用于计算 pod 调度失败后最多重试等待的秒数
	podMaxInUnschedulablePodsDuration time.Duration // 未能调度的 pod 最长的持续时间
	// 包含与 in-tree 注册表合并的 out-of-tree 插件。
	frameworkOutOfTreeRegistry frameworkruntime.Registry // 调度器的插件注册表
	profiles                   []schedulerapi.KubeSchedulerProfile // 调度器配置文件
	extenders                  []schedulerapi.Extender // 扩展器列表
	frameworkCapturer          FrameworkCapturer // 用于捕获调度过程中的信息
	parallelism                int32 // 调度器并行处理的任务数
	applyDefaultProfile        bool // 是否使用默认的调度器配置文件
}

type Option func(*schedulerOptions)
```


### New

```go
func New(client clientset.Interface, // 用于与 Kubernetes API Server 通信的客户端接口
	informerFactory informers.SharedInformerFactory, // Kubernetes Informer 工厂
	dynInformerFactory dynamicinformer.DynamicSharedInformerFactory, // Kubernetes DynamicInformer 工厂
	recorderFactory profile.RecorderFactory, // 用于创建事件记录器的工厂
	stopCh <-chan struct{}, // 用于停止调度器的通道，由外部传入
	opts ...Option) (*Scheduler, error) { // 可选的调度器选项，返回调度器实例和错误

	// 如果停止通道为空，则使用 wait.NeverStop 作为默认值
	stopEverything := stopCh
	if stopEverything == nil {
		stopEverything = wait.NeverStop
	}

	// 设置调度器选项
	options := defaultSchedulerOptions
	for _, opt := range opts {
		opt(&options)
	}

	// 如果设置了应用默认配置文件，则使用默认配置文件
	if options.applyDefaultProfile {
		var versionedCfg configv1.KubeSchedulerConfiguration
		scheme.Scheme.Default(&versionedCfg)
		cfg := schedulerapi.KubeSchedulerConfiguration{}
		if err := scheme.Scheme.Convert(&versionedCfg, &cfg, nil); err != nil {
			return nil, err
		}
		options.profiles = cfg.Profiles
	}

	// 创建 InTreeRegistry，并合并 FrameworkOutOfTreeRegistry
	registry := frameworkplugins.NewInTreeRegistry()
    // 把自定义的merge进去
	if err := registry.Merge(options.frameworkOutOfTreeRegistry); err != nil {
		return nil, err
	}

	// 注册度量指标
	metrics.Register()

	// 构建 Extender
	extenders, err := buildExtenders(options.extenders, options.profiles)
	if err != nil {
		return nil, fmt.Errorf("couldn't build extenders: %w", err)
	}

	// 获取 PodLister 和 NodeLister
	podLister := informerFactory.Core().V1().Pods().Lister()
	nodeLister := informerFactory.Core().V1().Nodes().Lister()

	// 创建 Snapshot 和 ClusterEventMap，并获取 MetricsRecorder
	snapshot := internalcache.NewEmptySnapshot()
	clusterEventMap := make(map[framework.ClusterEvent]sets.Set[string])
	metricsRecorder := metrics.NewMetricsAsyncRecorder(1000, time.Second, stopCh)

	// 创建 Profiles
	profiles, err := profile.NewMap(options.profiles, registry, recorderFactory, stopCh,
		frameworkruntime.WithComponentConfigVersion(options.componentConfigVersion),
		frameworkruntime.WithClientSet(client),
		frameworkruntime.WithKubeConfig(options.kubeConfig),
		frameworkruntime.WithInformerFactory(informerFactory),
		frameworkruntime.WithSnapshotSharedLister(snapshot),
		frameworkruntime.WithCaptureProfile(frameworkruntime.CaptureProfile(options.frameworkCapturer)),
		frameworkruntime.WithClusterEventMap(clusterEventMap),
		frameworkruntime.WithParallelism(int(options.parallelism)),
		frameworkruntime.WithExtenders(extenders),
		frameworkruntime.WithMetricsRecorder(metricsRecorder),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing profiles: %v", err)
	}

	// 如果没有 Profile 则返回错误
	if len(profiles) == 0 {
		return nil, errors.New("at least one profile is required")
	}

	// 创建一个名为 preEnqueuePluginMap 的 map，用于存储预处理插件（PreEnqueuePlugin）
	preEnqueuePluginMap := make(map[string][]framework.PreEnqueuePlugin)
    // 遍历 profiles 的每个元素，其中 profileName 是 key，profile 是 value
	for profileName, profile := range profiles {
         // 将 profile 的 PreEnqueuePlugins() 返回值存储到 preEnqueuePluginMap 中，使用 profileName 作为 key
		preEnqueuePluginMap[profileName] = profile.PreEnqueuePlugins()
	}
	// 使用 NewSchedulingQueue() 函数创建一个名为 podQueue 的 SchedulingQueue 对象，同时传入一系列参数
    podQueue := internalqueue.NewSchedulingQueue(
        // 使用 options.profiles[0].SchedulerName 所对应的 profile 的 QueueSortFunc() 作为排序函数
        profiles[options.profiles[0].SchedulerName].QueueSortFunc(),
        // 传入 informerFactory 对象
        informerFactory,
        // 传入 WithPodInitialBackoffDuration() 函数返回的选项，使用 options.podInitialBackoffSeconds 作为初始 backoff 时间
        	internalqueue.WithPodInitialBackoffDuration(time.Duration(options.podInitialBackoffSeconds)*time.Second),
        // 传入 WithPodMaxBackoffDuration() 函数返回的选项，使用 options.podMaxBackoffSeconds 作为最大 backoff 时间
        internalqueue.WithPodMaxBackoffDuration(time.Duration(options.podMaxBackoffSeconds)*time.Second),
        // 传入 WithPodLister() 函数返回的选项，使用 podLister 对象作为 podLister
        internalqueue.WithPodLister(podLister),
        // 传入 WithClusterEventMap() 函数返回的选项，使用 clusterEventMap 对象作为 clusterEventMap
        internalqueue.WithClusterEventMap(clusterEventMap),
        // 传入 WithPodMaxInUnschedulablePodsDuration() 函数返回的选项，使用 options.podMaxInUnschedulablePodsDuration 作为最大等待时间
        internalqueue.WithPodMaxInUnschedulablePodsDuration(options.podMaxInUnschedulablePodsDuration),
        // 传入 WithPreEnqueuePluginMap() 函数返回的选项，使用 preEnqueuePluginMap 对象作为 preEnqueuePluginMap
        internalqueue.WithPreEnqueuePluginMap(preEnqueuePluginMap),
        // 传入 WithPluginMetricsSamplePercent() 函数返回的选项，使用 pluginMetricsSamplePercent 作为样本采集比例
        internalqueue.WithPluginMetricsSamplePercent(pluginMetricsSamplePercent),
        // 传入 WithMetricsRecorder() 函数返回的选项，使用 metricsRecorder 对象作为 metricsRecorder
        internalqueue.WithMetricsRecorder(*metricsRecorder),
    )

    // 遍历 profiles 中的每个元素，其中 fwk 是 value
    for _, fwk := range profiles {
        // 将 podQueue 设置为 fwk 的 PodNominator
        fwk.SetPodNominator(podQueue)
    }
	
    // 使用 New() 函数创建一个名为 schedulerCache 的 Cache 对象，使用 durationToExpireAssumedPod 作为缓存过期时间，stopEverything 作为 stopCh
	schedulerCache := internalcache.New(durationToExpireAssumedPod, stopEverything)

	// 设置缓存调试器
	debugger := cachedebugger.New(nodeLister, podLister, schedulerCache, podQueue)
	debugger.ListenForSignal(stopEverything)
	// 创建一个调度器实例
	sched := &Scheduler{
		Cache:                    schedulerCache,
		client:                   client,
		nodeInfoSnapshot:         snapshot,
		percentageOfNodesToScore: options.percentageOfNodesToScore,
		Extenders:                extenders,
		NextPod:                  internalqueue.MakeNextPodFunc(podQueue),
		StopEverything:           stopEverything,
		SchedulingQueue:          podQueue,
		Profiles:                 profiles,
	}
    // 应用默认的处理程序
	sched.applyDefaultHandlers()
	// 添加所有事件处理程序
	addAllEventHandlers(sched, informerFactory, dynInformerFactory, unionedGVKs(clusterEventMap))

	return sched, nil
}
```

#### schedulerOptions

```go
type schedulerOptions struct {
    // 组件配置版本
	componentConfigVersion string
    // 表示 Kubernetes 集群的配置
	kubeConfig             *restclient.Config
	// 表示节点评分的百分比，可以被 v1 版本中的 profile 级别的 percentageOfNodesToScore 字段覆盖。
	percentageOfNodesToScore          int32
    //  Pod 初始回退等待的秒数
	podInitialBackoffSeconds          int64
    // 表示 Pod 最大回退等待的秒数
	podMaxBackoffSeconds              int64
    // 表示在不可调度的 Pod 中最大等待的时间
	podMaxInUnschedulablePodsDuration time.Duration
	// 表示外部注册表中的自定义调度器插件，将与内部的注册表合并
	frameworkOutOfTreeRegistry frameworkruntime.Registry
    // 存储调度器的配置文件
	profiles                   []schedulerapi.KubeSchedulerProfile
    // 存储调度器的扩展插件
	extenders                  []schedulerapi.Extender
    // 捕获调度器的状态信息
	frameworkCapturer          FrameworkCapturer
    // 表示调度器的并行度
	parallelism                int32
    // 是否应用默认的调度器配置文件
	applyDefaultProfile        bool
}

var defaultSchedulerOptions = schedulerOptions{
	percentageOfNodesToScore:          schedulerapi.DefaultPercentageOfNodesToScore,
	podInitialBackoffSeconds:          int64(internalqueue.DefaultPodInitialBackoffDuration.Seconds()),
	podMaxBackoffSeconds:              int64(internalqueue.DefaultPodMaxBackoffDuration.Seconds()),
	podMaxInUnschedulablePodsDuration: internalqueue.DefaultPodMaxInUnschedulablePodsDuration,
	parallelism:                       int32(parallelize.DefaultParallelism),
	//理想情况下，我们会在这里静态设置默认配置文件，但我们不能，因为
    //创建默认配置文件可能需要测试功能门，这可能会
    //在测试中动态设置。因此，我们推迟创建它，直到New
    //已调用。
	applyDefaultProfile: true,
}

```

##### KubeSchedulerProfile

```go
type KubeSchedulerProfile struct {
	// 调度器的名称，与该配置文件关联。如果 pod 的 spec.schedulerName 与该字段匹配，则该 pod 将使用此配置文件进行调度。
	SchedulerName string

	// 对于所有找到的可行节点的百分比，调度器在找到一定数量的可行节点后停止在集群中继续查找可行节点，以提高性能。
    // 调度器始终尝试找到至少 "minFeasibleNodesToFind" 个可行节点，无论此标志的值如何。
    // 例如，如果集群大小为 500 个节点，此字段的值为 30，则调度器在找到 150 个可行节点后停止查找更多的可行节点。
    // 当该值为 0 时，将使用默认百分比（根据集群大小在 5% 到 50% 之间）。如果该字段为空，将使用全局的 PercentageOfNodesToScore。
	PercentageOfNodesToScore *int32

	// 指定应启用或禁用的插件集合。启用的插件是除了默认插件之外应启用的插件。禁用的插件是默认插件中应禁用的插件。
    // 对于某个扩展点未指定启用或禁用的插件时，将使用默认插件（如果有）。
    // 如果指定了 QueueSort 插件，则必须为所有配置文件指定相同的 QueueSort 插件和 PluginConfig。
	Plugins *Plugins

	// 每个插件的自定义配置参数的可选集合。对于未指定插件的配置参数，将使用该插件的默认配置。
	PluginConfig []PluginConfig
}

type PluginConfig struct {
	Name string
	Args runtime.Object
}
```

##### Plugins

```go
type Plugins struct {
	// PreEnqueue 是在将 Pod 添加到调度队列之前应该调用的插件列表。
	PreEnqueue PluginSet

	// QueueSort 是在对调度队列中的 Pod 进行排序时应该调用的插件列表。
    QueueSort PluginSet

    // PreFilter 是在调度框架的 "PreFilter" 扩展点处应该调用的插件列表。
    PreFilter PluginSet

    // Filter 是在筛选出无法运行 Pod 的节点时应该调用的插件列表。
    Filter PluginSet

    // PostFilter 是在筛选阶段后，但仅在未找到适合 Pod 的节点时调用的插件列表。
    PostFilter PluginSet

    // PreScore 是在评分之前应该调用的插件列表。
    PreScore PluginSet

    // Score 是在经过筛选阶段后，对节点进行排名时应该调用的插件列表。
    Score PluginSet

    // Reserve 是在将节点分配给运行 Pod 后，调用的保留/取消保留资源的插件列表。
    Reserve PluginSet

    // Permit 是控制 Pod 绑定的插件列表。这些插件可以阻止或延迟 Pod 的绑定。
    Permit PluginSet

    // PreBind 是在 Pod 绑定之前应该调用的插件列表。
    PreBind PluginSet

    // Bind 是在调度框架的 "Bind" 扩展点处应该调用的插件列表。
    // 调度器会按顺序调用这些插件。一旦其中一个插件返回成功，调度器将跳过后续插件的调用。
    Bind PluginSet

    // PostBind 是在 Pod 成功绑定后应该调用的插件列表。
    PostBind PluginSet

    // MultiPoint 是一个简化的配置字段，用于启用所有有效的扩展点的插件。
    MultiPoint PluginSet
}

type PluginSet struct {
	// Enabled specifies plugins that should be enabled in addition to default plugins.
	// These are called after default plugins and in the same order specified here.
	Enabled []Plugin
	// Disabled specifies default plugins that should be disabled.
	// When all default plugins need to be disabled, an array containing only one "*" should be provided.
	Disabled []Plugin
}
```





#### NewInTreeRegistry

```go
// 定义了一个名为NewInTreeRegistry的函数，返回一个类型为runtime.Registry的对象。
func NewInTreeRegistry() runtime.Registry {
	// 定义一个名为fts的plfeature.Features类型的变量
	fts := plfeature.Features{
        // 根据feature gate的状态，启用或禁用相应的特性
		EnableDynamicResourceAllocation:              feature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation),
		EnableReadWriteOncePod:                       feature.DefaultFeatureGate.Enabled(features.ReadWriteOncePod),
		EnableVolumeCapacityPriority:                 feature.DefaultFeatureGate.Enabled(features.VolumeCapacityPriority),
		EnableMinDomainsInPodTopologySpread:          feature.DefaultFeatureGate.Enabled(features.MinDomainsInPodTopologySpread),
		EnableNodeInclusionPolicyInPodTopologySpread: feature.DefaultFeatureGate.Enabled(features.NodeInclusionPolicyInPodTopologySpread),
		EnableMatchLabelKeysInPodTopologySpread:      feature.DefaultFeatureGate.Enabled(features.MatchLabelKeysInPodTopologySpread),
		EnablePodSchedulingReadiness:                 feature.DefaultFeatureGate.Enabled(features.PodSchedulingReadiness),
		EnablePodDisruptionConditions:                feature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions),
		EnableInPlacePodVerticalScaling:              feature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling),
	}
	
    // 定义一个名为registry的runtime.Registry类型的变量
	registry := runtime.Registry{
        // 给定键值对，其中键为字符串类型，值为一个函数，用于构造对象
		dynamicresources.Name:                runtime.FactoryAdapter(fts, dynamicresources.New),
		selectorspread.Name:                  selectorspread.New,
		imagelocality.Name:                   imagelocality.New,
		tainttoleration.Name:                 tainttoleration.New,
		nodename.Name:                        nodename.New,
		nodeports.Name:                       nodeports.New,
		nodeaffinity.Name:                    nodeaffinity.New,
		podtopologyspread.Name:               runtime.FactoryAdapter(fts, podtopologyspread.New),
		nodeunschedulable.Name:               nodeunschedulable.New,
		noderesources.Name:                   runtime.FactoryAdapter(fts, noderesources.NewFit),
		noderesources.BalancedAllocationName: runtime.FactoryAdapter(fts, noderesources.NewBalancedAllocation),
		volumebinding.Name:                   runtime.FactoryAdapter(fts, volumebinding.New),
		volumerestrictions.Name:              runtime.FactoryAdapter(fts, volumerestrictions.New),
		volumezone.Name:                      volumezone.New,
		nodevolumelimits.CSIName:             runtime.FactoryAdapter(fts, nodevolumelimits.NewCSI),
		nodevolumelimits.EBSName:             runtime.FactoryAdapter(fts, nodevolumelimits.NewEBS),
		nodevolumelimits.GCEPDName:           runtime.FactoryAdapter(fts, nodevolumelimits.NewGCEPD),
		nodevolumelimits.AzureDiskName:       runtime.FactoryAdapter(fts, nodevolumelimits.NewAzureDisk),
		nodevolumelimits.CinderName:          runtime.FactoryAdapter(fts, nodevolumelimits.NewCinder),
		interpodaffinity.Name:                interpodaffinity.New,
		queuesort.Name:                       queuesort.New,
		defaultbinder.Name:                   defaultbinder.New,
		defaultpreemption.Name:               runtime.FactoryAdapter(fts, defaultpreemption.New),
		schedulinggates.Name:                 runtime.FactoryAdapter(fts, schedulinggates.New),
	}

	return registry
}
```

#### buildExtenders

```go
func buildExtenders(extenders []schedulerapi.Extender, profiles []schedulerapi.KubeSchedulerProfile) ([]framework.Extender, error) {
	// 定义一个名为 buildExtenders 的函数，它接受两个参数：一个名为 extenders 的类型为 []schedulerapi.Extender 的切片和一个名为 profiles 的类型为 []schedulerapi.KubeSchedulerProfile 的切片，该函数返回两个值：类型为 []framework.Extender 的切片和一个 error 类型的变量。
	var fExtenders []framework.Extender
	// 定义一个名为 fExtenders 的类型为 []framework.Extender 的空切片。
	if len(extenders) == 0 {
		return nil, nil
		// 如果 extenders 的长度为 0，则返回两个 nil 值。
	}

	var ignoredExtendedResources []string
	// 定义一个名为 ignoredExtendedResources 的类型为 []string 的空切片。
	var ignorableExtenders []framework.Extender
	// 定义一个名为 ignorableExtenders 的类型为 []framework.Extender 的空切片。
	for i := range extenders {
		// 遍历 extenders 中的每个元素。
		klog.V(2).InfoS("Creating extender", "extender", extenders[i])
		// 记录日志，输出 "Creating extender" 和 extenders[i] 的值。
		extender, err := NewHTTPExtender(&extenders[i])
		// 调用 NewHTTPExtender 函数，将 extenders[i] 的地址作为参数传递，并将其返回值分别赋值给 extender 和 err 变量。
		if err != nil {
			return nil, err
			// 如果 err 不为 nil，则返回两个 nil 值和 err。
		}
		if !extender.IsIgnorable() {
			fExtenders = append(fExtenders, extender)
			// 如果 extender 不可忽略，则将其追加到 fExtenders 中。
		} else {
			ignorableExtenders = append(ignorableExtenders, extender)
			// 否则，将其追加到 ignorableExtenders 中。
		}
		for _, r := range extenders[i].ManagedResources {
			if r.IgnoredByScheduler {
				ignoredExtendedResources = append(ignoredExtendedResources, r.Name)
				// 遍历 extenders[i].ManagedResources 中的每个元素，如果该元素的 IgnoredByScheduler 字段为 true，则将其 Name 字段的值追加到 ignoredExtendedResources 中。
			}
		}
	}
	// 将 ignorableExtenders 追加到 fExtenders 的末尾。
	fExtenders = append(fExtenders, ignorableExtenders...)

	// 如果从 Extender 中找到任何扩展资源，则将它们附加到每个 profile 的 pluginConfig 中。
	// 这只对 ComponentConfig 产生影响，在该组件中可以配置 Extender 和插件参数（在这种情况下，Extender 忽略的资源优先）。
	if len(ignoredExtendedResources) == 0 {
		return fExtenders, nil
		// 如果 ignoredExtendedResources 的长度为 0，则返回 fExtenders
	}
	// 便利每个profiles
	for i := range profiles {
		prof := &profiles[i]
		var found = false
		for k := range prof.PluginConfig {
			if prof.PluginConfig[k].Name == noderesources.Name {
                // 如果 prof.PluginConfig[k] 的 Name 属性等于 noderesources.Name，则说明这是 NodeResourcesFitArgs 插件配置，需要对其进行更新。
				// Update the existing args
				pc := &prof.PluginConfig[k]
				args, ok := pc.Args.(*schedulerapi.NodeResourcesFitArgs)
				if !ok {
					return nil, fmt.Errorf("want args to be of type NodeResourcesFitArgs, got %T", pc.Args)
				}
                // 将 ignoredExtendedResources 中的扩展资源添加到 args.IgnoredResources 中。
				args.IgnoredResources = ignoredExtendedResources
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("can't find NodeResourcesFitArgs in plugin config")
		}
	}
	return fExtenders, nil
}
```

####  profile.NewMap

```go
type Map map[string]framework.Framework

func NewMap(cfgs []config.KubeSchedulerProfile, r frameworkruntime.Registry, recorderFact RecorderFactory,
	stopCh <-chan struct{}, opts ...frameworkruntime.Option) (Map, error) {
	m := make(Map)
	v := cfgValidator{m: m}

	for _, cfg := range cfgs {
		p, err := newProfile(cfg, r, recorderFact, stopCh, opts...)
		if err != nil {
			return nil, fmt.Errorf("creating profile for scheduler name %s: %v", cfg.SchedulerName, err)
		}
		if err := v.validate(cfg, p); err != nil {
			return nil, err
		}
		m[cfg.SchedulerName] = p
	}
	return m, nil
}
```

#### NewMap

```GO
type Map map[string]framework.Framework

func NewMap(cfgs []config.KubeSchedulerProfile, r frameworkruntime.Registry, recorderFact RecorderFactory,
	stopCh <-chan struct{}, opts ...frameworkruntime.Option) (Map, error) {
	// 创建一个 Map 对象
	m := make(Map)
	// 创建一个 cfgValidator 对象，该对象将使用 Map
	v := cfgValidator{m: m}

	// 遍历 cfgs 数组
	for _, cfg := range cfgs {
		// 为当前调度器配置创建一个新的 profile
		p, err := newProfile(cfg, r, recorderFact, stopCh, opts...)
		if err != nil {
			// 如果创建 profile 失败，返回错误
			return nil, fmt.Errorf("creating profile for scheduler name %s: %v", cfg.SchedulerName, err)
		}
		// 验证当前配置和 profile 是否合法
		if err := v.validate(cfg, p); err != nil {
			// 如果验证失败，返回错误
			return nil, err
		}
		// 将 profile 存储在 Map 中，以调度器名称为键
		m[cfg.SchedulerName] = p
	}
	// 返回 Map 和空错误对象
	return m, nil
}

type RecorderFactory func(string) events.EventRecorder
```

##### cfgValidator

```GO
type cfgValidator struct {
	m             Map
	queueSort     string
	queueSortArgs runtime.Object
}
```

##### newProfile

```GO
func newProfile(cfg config.KubeSchedulerProfile, r frameworkruntime.Registry, recorderFact RecorderFactory,
	stopCh <-chan struct{}, opts ...frameworkruntime.Option) (framework.Framework, error) {
	recorder := recorderFact(cfg.SchedulerName)
	opts = append(opts, frameworkruntime.WithEventRecorder(recorder))
	return frameworkruntime.NewFramework(r, &cfg, stopCh, opts...)
}
```

##### validate

```GO
func (v *cfgValidator) validate(cfg config.KubeSchedulerProfile, f framework.Framework) error {
	// 检查调度器名称是否为空
	if len(f.ProfileName()) == 0 {
		return errors.New("scheduler name is needed")
	}
	// 检查插件是否为空
	if cfg.Plugins == nil {
		return fmt.Errorf("plugins required for profile with scheduler name %q", f.ProfileName())
	}
	// 检查是否存在相同名称的 profile
	if v.m[f.ProfileName()] != nil {
		return fmt.Errorf("duplicate profile with scheduler name %q", f.ProfileName())
	}

	// 获取队列排序插件的名称和参数
	queueSort := f.ListPlugins().QueueSort.Enabled[0].Name
	var queueSortArgs runtime.Object
	for _, plCfg := range cfg.PluginConfig {
		if plCfg.Name == queueSort {
			queueSortArgs = plCfg.Args
			break
		}
	}
	// 如果队列排序插件名称为空，则将当前名称和参数存储在 cfgValidator 对象中，并返回 nil
	if len(v.queueSort) == 0 {
		v.queueSort = queueSort
		v.queueSortArgs = queueSortArgs
		return nil
	}
	// 如果当前队列排序插件名称和存储在 cfgValidator 对象中的不同，则返回错误
	if v.queueSort != queueSort {
		return fmt.Errorf("different queue sort plugins for profile %q: %q, first: %q", cfg.SchedulerName, queueSort, v.queueSort)
	}
	// 如果当前队列排序插件名称相同，但参数不同，则返回错误
	if !cmp.Equal(v.queueSortArgs, queueSortArgs) {
		return fmt.Errorf("different queue sort plugin args for profile %q", cfg.SchedulerName)
	}
	// 如果当前队列排序插件名称和参数都相同，则返回 nil
	return nil
}
```

#### addAllEventHandlers

```GO
// addAllEventHandlers is a helper function used in tests and in Scheduler
// to add event handlers for various informers.
func addAllEventHandlers(
	sched *Scheduler,
	informerFactory informers.SharedInformerFactory,
	dynInformerFactory dynamicinformer.DynamicSharedInformerFactory,
	gvkMap map[framework.GVK]framework.ActionType,
) {
	// scheduled pod cache
    informerFactory.Core().V1().Pods().Informer().AddEventHandler(
        cache.FilteringResourceEventHandler{
            // 事件过滤器，筛选出需要缓存的 Pod
            FilterFunc: func(obj interface{}) bool {
                switch t := obj.(type) {
                case *v1.Pod:
                    return assignedPod(t)  // 返回分配的 Pod
                case cache.DeletedFinalStateUnknown:
                    if _, ok := t.Obj.(*v1.Pod); ok {
                        // carried object 可能已过时，因此我们不使用它来检查它是否已分配。尝试清理。
                        return true
                    }
                    utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
                    return false
                default:
                    utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
                    return false
                }
            },
            // 事件处理器
            Handler: cache.ResourceEventHandlerFuncs{
                AddFunc:    sched.addPodToCache,         // 添加 Pod 到缓存
                UpdateFunc: sched.updatePodInCache,      // 更新 Pod 在缓存中的状态
                DeleteFunc: sched.deletePodFromCache,    // 从缓存中删除 Pod
            },
        },
    )

    // unscheduled pod queue
    informerFactory.Core().V1().Pods().Informer().AddEventHandler(
        cache.FilteringResourceEventHandler{
            // 事件过滤器，筛选出需要加入队列的 Pod
            FilterFunc: func(obj interface{}) bool {
                switch t := obj.(type) {
                case *v1.Pod:
                    return !assignedPod(t) && responsibleForPod(t, sched.Profiles)  // 返回未分配的 Pod 且该调度器能够负责
                case cache.DeletedFinalStateUnknown:
                    if pod, ok := t.Obj.(*v1.Pod); ok {
                        // carried object 可能已过时，因此我们不使用它来检查它是否已分配。
                        return responsibleForPod(pod, sched.Profiles)  // 返回未分配的 Pod 且该调度器能够负责
                    }
                    utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
                    return false
                default:
                    utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
                    return false
                }
            },
            // 事件处理器
            Handler: cache.ResourceEventHandlerFuncs{
                AddFunc:    sched.addPodToSchedulingQueue,      // 添加 Pod 到调度队列
                UpdateFunc: sched.updatePodInSchedulingQueue,   // 更新 Pod 在调度队列中的状态
                DeleteFunc: sched.deletePodFromSchedulingQueue, // 从调度队列中删除 Pod
            },
        },
    )

	// 监控node
	informerFactory.Core().V1().Nodes().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    sched.addNodeToCache,
			UpdateFunc: sched.updateNodeInCache,
			DeleteFunc: sched.deleteNodeFromCache,
		},
	)

	buildEvtResHandler := func(at framework.ActionType, gvk framework.GVK, shortGVK string) cache.ResourceEventHandlerFuncs {
		// 定义一个函数，该函数接收三个参数：framework.ActionType、framework.GVK 和 shortGVK，并返回 cache.ResourceEventHandlerFuncs 类型的结果。
        funcs := cache.ResourceEventHandlerFuncs{} // 创建一个空的 ResourceEventHandlerFuncs 对象。
        if at&framework.Add != 0 { // 如果 at 包含 framework.Add 标志位
            evt := framework.ClusterEvent{Resource: gvk, ActionType: framework.Add, Label: fmt.Sprintf("%vAdd", shortGVK)}
            // 创建 ClusterEvent 对象 evt，设置 Resource 属性为 gvk，ActionType 属性为 framework.Add，Label 属性为 shortGVK 加上字符串 "Add"。
            funcs.AddFunc = func(_ interface{}) {
                sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(evt, nil)
                // 定义 AddFunc 方法，该方法将所有的事件移动到活动或回退队列中。
            }
        }
        if at&framework.Update != 0 { // 如果 at 包含 framework.Update 标志位
            evt := framework.ClusterEvent{Resource: gvk, ActionType: framework.Update, Label: fmt.Sprintf("%vUpdate", shortGVK)}
            // 创建 ClusterEvent 对象 evt，设置 Resource 属性为 gvk，ActionType 属性为 framework.Update，Label 属性为 shortGVK 加上字符串 "Update"。
            funcs.UpdateFunc = func(_, _ interface{}) {
                sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(evt, nil)
                // 定义 UpdateFunc 方法，该方法将所有的事件移动到活动或回退队列中。
            }
        }
        if at&framework.Delete != 0 { // 如果 at 包含 framework.Delete 标志位
            evt := framework.ClusterEvent{Resource: gvk, ActionType: framework.Delete, Label: fmt.Sprintf("%vDelete", shortGVK)}
            // 创建 ClusterEvent 对象 evt，设置 Resource 属性为 gvk，ActionType 属性为 framework.Delete，Label 属性为 shortGVK 加上字符串 "Delete"。
            funcs.DeleteFunc = func(_ interface{}) {
                sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(evt, nil)
                // 定义 DeleteFunc 方法，该方法将所有的事件移动到活动或回退队列中。
            }
        }
        return funcs // 返回 ResourceEventHandlerFuncs 对象 funcs。
	}

	for gvk, at := range gvkMap {  // 遍历 gvkMap 中的所有 gvk
        switch gvk {
        case framework.Node, framework.Pod:  // 对于 framework.Node 和 framework.Pod 类型，不进行处理
            // Do nothing.
        case framework.CSINode:  // 对于 framework.CSINode 类型，添加事件处理程序
            informerFactory.Storage().V1().CSINodes().Informer().AddEventHandler(
                buildEvtResHandler(at, framework.CSINode, "CSINode"),
            )
        case framework.CSIDriver:  // 对于 framework.CSIDriver 类型，添加事件处理程序
            informerFactory.Storage().V1().CSIDrivers().Informer().AddEventHandler(
                buildEvtResHandler(at, framework.CSIDriver, "CSIDriver"),
            )
        case framework.CSIStorageCapacity:  // 对于 framework.CSIStorageCapacity 类型，添加事件处理程序
            informerFactory.Storage().V1().CSIStorageCapacities().Informer().AddEventHandler(
                buildEvtResHandler(at, framework.CSIStorageCapacity, "CSIStorageCapacity"),
            )
        case framework.PersistentVolume:  // 对于 framework.PersistentVolume 类型，添加事件处理程序
            informerFactory.Core().V1().PersistentVolumes().Informer().AddEventHandler(
                buildEvtResHandler(at, framework.PersistentVolume, "Pv"),
            )
        case framework.PersistentVolumeClaim:  // 对于 framework.PersistentVolumeClaim 类型，添加事件处理程序
            informerFactory.Core().V1().PersistentVolumeClaims().Informer().AddEventHandler(
                buildEvtResHandler(at, framework.PersistentVolumeClaim, "Pvc"),
            )
        case framework.PodSchedulingContext:  // 对于 framework.PodSchedulingContext 类型，添加事件处理程序
            if utilfeature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation) {
                _, _ = informerFactory.Resource().V1alpha2().PodSchedulingContexts().Informer().AddEventHandler(
                    buildEvtResHandler(at, framework.PodSchedulingContext, "PodSchedulingContext"),
                )
            }
        case framework.ResourceClaim:  // 对于 framework.ResourceClaim 类型，添加事件处理程序
            if utilfeature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation) {
                _, _ = informerFactory.Resource().V1alpha2().ResourceClaims().Informer().AddEventHandler(
                    buildEvtResHandler(at, framework.ResourceClaim, "ResourceClaim"),
                )
            }
        case framework.StorageClass:  // 对于 framework.StorageClass 类型，根据 at 指定的操作添加事件处理程序
            if at&framework.Add != 0 {  // 添加事件处理程序
                informerFactory.Storage().V1().StorageClasses().Informer().AddEventHandler(
                    cache.ResourceEventHandlerFuncs{
                        AddFunc: sched.onStorageClassAdd,  // 在存储类添加时执行 sched.onStorageClassAdd 函数
                    },
                )
            }
			if at&framework.Update != 0 { // 更新事件处理程序
				informerFactory.Storage().V1().StorageClasses().Informer().AddEventHandler(
					cache.ResourceEventHandlerFuncs{
						UpdateFunc: func(_, _ interface{}) { // 在存储类更新时执行匿名函数
							sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.StorageClassUpdate, nil) // 将所有调度队列中的存储类更新移动到活动队列或备用队列中
						},
					},
				)
			}
		default:
			// 注意：测试可能不会实例化dynInformerFactory。
			if dynInformerFactory == nil {
				continue
			}
			// GVK预期至少有三个部分，由句点分隔。
            // <kind in plural>.<version>.<group>
            // 有效示例：
            // - foos.v1.example.com
            // - bars.v1beta1.a.b.c
            // 无效示例：
            // - foos.v1（2个部分）
            // - foo.v1.example.com（第一个部分应该是复数形式）
			if strings.Count(string(gvk), ".") < 2 {
				klog.ErrorS(nil, "incorrect event registration", "gvk", gvk)
				continue
			}
			// 回退到尝试动态informer。
			gvr, _ := schema.ParseResourceArg(string(gvk))
			dynInformer := dynInformerFactory.ForResource(*gvr).Informer()
			dynInformer.AddEventHandler(
				buildEvtResHandler(at, gvk, strings.Title(gvr.Resource)),
			)
		}
	}
}
```

##### assignedPod

```GO
func assignedPod(pod *v1.Pod) bool {
	return len(pod.Spec.NodeName) != 0
}
```

##### responsibleForPod

```GO
func responsibleForPod(pod *v1.Pod, profiles profile.Map) bool {
	return profiles.HandlesSchedulerName(pod.Spec.SchedulerName)
}
```

##### pod

```GO
// 将 Pod 添加到调度器的缓存中
func (sched *Scheduler) addPodToCache(obj interface{}) {
	// 将 obj 转换为 *v1.Pod 类型，如果类型不匹配，则打印错误并返回
	pod, ok := obj.(*v1.Pod)
	if !ok {
		klog.ErrorS(nil, "Cannot convert to *v1.Pod", "obj", obj)
		return
	}
	// 打印调试日志
	klog.V(3).InfoS("Add event for scheduled pod", "pod", klog.KObj(pod))

	// 将 Pod 添加到缓存中，如果操作失败，则打印错误
	if err := sched.Cache.AddPod(pod); err != nil {
		klog.ErrorS(err, "Scheduler cache AddPod failed", "pod", klog.KObj(pod))
	}

	// 将 Pod 添加到调度队列中
	sched.SchedulingQueue.AssignedPodAdded(pod)
}

// 更新 Pod 在调度器的缓存中的信息
func (sched *Scheduler) updatePodInCache(oldObj, newObj interface{}) {
	// 将 oldObj 和 newObj 转换为 *v1.Pod 类型，如果类型不匹配，则打印错误并返回
	oldPod, ok := oldObj.(*v1.Pod)
	if !ok {
		klog.ErrorS(nil, "Cannot convert oldObj to *v1.Pod", "oldObj", oldObj)
		return
	}
	newPod, ok := newObj.(*v1.Pod)
	if !ok {
		klog.ErrorS(nil, "Cannot convert newObj to *v1.Pod", "newObj", newObj)
		return
	}
	// 打印调试日志
	klog.V(4).InfoS("Update event for scheduled pod", "pod", klog.KObj(oldPod))

	// 更新缓存中的 Pod 信息，如果操作失败，则打印错误
	if err := sched.Cache.UpdatePod(oldPod, newPod); err != nil {
		klog.ErrorS(err, "Scheduler cache UpdatePod failed", "pod", klog.KObj(oldPod))
	}

	// 将更新后的 Pod 添加到调度队列中
	sched.SchedulingQueue.AssignedPodUpdated(newPod)
}

// 从调度器的缓存中删除 Pod
func (sched *Scheduler) deletePodFromCache(obj interface{}) {
	var pod *v1.Pod
	switch t := obj.(type) {
	// 如果 obj 是 *v1.Pod 类型，则直接赋值给 pod
	case *v1.Pod:
		pod = t
	// 如果 obj 是 DeletedFinalStateUnknown 类型，则从 Obj 字段中提取 Pod 对象
	case cache.DeletedFinalStateUnknown:
		var ok bool
		pod, ok = t.Obj.(*v1.Pod)
		if !ok {
			klog.ErrorS(nil, "Cannot convert to *v1.Pod", "obj", t.Obj)
			return
		}
	default:
		klog.ErrorS(nil, "Cannot convert to *v1.Pod", "obj", t)
		return
	}
	// 打印调试日志
	klog.V(3).InfoS("Delete event for scheduled pod", "pod", klog.KObj(pod))
	// 从缓存中删除 Pod，如果操作失败，则打印错误
	if err := sched.Cache.RemovePod(pod); err != nil {
		klog.ErrorS(err, "Scheduler cache RemovePod failed", "pod", klog.KObj(pod))
	}
	// 将所有Pod移动到退避队列中
	sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.AssignedPodDelete, nil)
}

func (sched *Scheduler) addPodToSchedulingQueue(obj interface{}) {
    // 将 obj 强制类型转换为 v1.Pod 类型的指针
    pod := obj.(*v1.Pod)
    // 记录日志，表示向调度队列添加未调度的 Pod
    klog.V(3).InfoS("Add event for unscheduled pod", "pod", klog.KObj(pod))
    // 将 Pod 添加到调度队列中
    if err := sched.SchedulingQueue.Add(pod); err != nil {
        // 处理添加失败的情况，记录错误日志
        utilruntime.HandleError(fmt.Errorf("unable to queue %T: %v", obj, err))
    }
}

func (sched *Scheduler) updatePodInSchedulingQueue(oldObj, newObj interface{}) {
    // 将 oldObj 和 newObj 强制类型转换为 v1.Pod 类型的指针
    oldPod, newPod := oldObj.(*v1.Pod), newObj.(*v1.Pod)
    // 如果两个 Pod 对象的资源版本相同，则跳过更新
    if oldPod.ResourceVersion == newPod.ResourceVersion {
        return
    }

    // 检查 Pod 是否是假定的 Pod，如果是则跳过更新
    isAssumed, err := sched.Cache.IsAssumedPod(newPod)
    if err != nil {
        utilruntime.HandleError(fmt.Errorf("failed to check whether pod %s/%s is assumed: %v", newPod.Namespace, newPod.Name, err))
    }
    if isAssumed {
        return
    }

    // 更新 Pod 在调度队列中的状态
    if err := sched.SchedulingQueue.Update(oldPod, newPod); err != nil {
        utilruntime.HandleError(fmt.Errorf("unable to update %T: %v", newObj, err))
    }
}

func (sched *Scheduler) deletePodFromSchedulingQueue(obj interface{}) {
    // 定义了一个方法，接收一个 interface{} 类型的参数，表示要从调度队列中删除的对象
    var pod *v1.Pod
    // 定义了一个 *v1.Pod 类型的指针 pod，用于保存要删除的 Pod 对象
    switch t := obj.(type) {
        // 通过 switch 语句，根据传入的对象类型，判断需要删除的对象是 Pod 对象还是其他类型的对象
        case *v1.Pod:
        	pod = obj.(*v1.Pod)
        // 如果是 Pod 对象，则将传入的 obj 转换为 *v1.Pod 类型，并赋值给 pod 变量
        case cache.DeletedFinalStateUnknown:
            var ok bool
            // 如果是一个已被删除的 Pod 对象
            pod, ok = t.Obj.(*v1.Pod)
            // 尝试将 t.Obj 转换为 *v1.Pod 类型，并赋值给 pod 变量
            if !ok {
                // 如果转换失败，则打印错误信息，返回
                utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
                return
    		}
        default:
            // 如果不是 Pod 对象或已被删除的 Pod 对象，则打印错误信息，返回
            utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
            return
    }
    // 打印删除未调度 Pod 的日志信息
    klog.V(3).InfoS("Delete event for unscheduled pod", "pod", klog.KObj(pod))
    // 从调度队列中删除 pod
    if err := sched.SchedulingQueue.Delete(pod); err != nil {
        // 如果删除失败，则打印错误信息
        utilruntime.HandleError(fmt.Errorf("unable to dequeue %T: %v", obj, err))
    }
    // 获取 Pod 所属的 framework 对象
    fwk, err := sched.frameworkForPod(pod)
    if err != nil {
        // 如果获取 framework 失败，则打印错误信息，返回
        klog.ErrorS(err, "Unable to get profile", "pod", klog.KObj(pod))
    return
    }
    // 如果等待调度的 Pod 被拒绝了，则表示该 Pod 是以前被假定调度的，现在将其从调度缓存中删除。在这种情况下，发送一个 AssignedPodDelete 事件以立即重试一些未调度的 Pod。
    if fwk.RejectWaitingPod(pod.UID) {
    	sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.AssignedPodDelete, nil)
    }
}
```

##### node

```go
func (sched *Scheduler) addNodeToCache(obj interface{}) {
    // 将obj转换为*v1.Node类型
    node, ok := obj.(*v1.Node)
    if !ok {
        // 如果转换失败，则记录错误并直接返回
        klog.ErrorS(nil, "Cannot convert to *v1.Node", "obj", obj)
        return
    }

    // 将Node信息添加到调度器的缓存中
    nodeInfo := sched.Cache.AddNode(node)

    // 记录Node添加事件
    klog.V(3).InfoS("Add event for node", "node", klog.KObj(node))

    // 将当前等待调度的Pod移动到活跃或退避队列
    sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.NodeAdd, preCheckForNode(nodeInfo))
}

func (sched *Scheduler) updateNodeInCache(oldObj, newObj interface{}) {
    // 将旧对象和新对象分别转换为*v1.Node类型
    oldNode, ok := oldObj.(*v1.Node)
    if !ok {
        // 如果旧对象转换失败，则记录错误并直接返回
        klog.ErrorS(nil, "Cannot convert oldObj to *v1.Node", "oldObj", oldObj)
        return
    }
    newNode, ok := newObj.(*v1.Node)
    if !ok {
        // 如果新对象转换失败，则记录错误并直接返回
        klog.ErrorS(nil, "Cannot convert newObj to *v1.Node", "newObj", newObj)
        return
    }

    // 更新调度器的缓存中的Node信息
    nodeInfo := sched.Cache.UpdateNode(oldNode, newNode)

    // 如果节点的调度属性发生了变化，则将等待调度的Pod移动到活跃或退避队列
    if event := nodeSchedulingPropertiesChange(newNode, oldNode); event != nil {
        sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(*event, preCheckForNode(nodeInfo))
    }
}

func (sched *Scheduler) deleteNodeFromCache(obj interface{}) {
    var node *v1.Node
    switch t := obj.(type) {
    case *v1.Node:
        node = t
    case cache.DeletedFinalStateUnknown:
        var ok bool
        node, ok = t.Obj.(*v1.Node)
        if !ok {
            // 如果转换失败，则记录错误并直接返回
            klog.ErrorS(nil, "Cannot convert to *v1.Node", "obj", t.Obj)
            return
        }
    default:
        // 如果类型不匹配，则记录错误并直接返回
        klog.ErrorS(nil, "Cannot convert to *v1.Node", "obj", t)
        return
    }

    // 记录Node删除事件
    klog.V(3).InfoS("Delete event for node", "node", klog.KObj(node))

    // 从调度器的缓存中删除Node信息
    if err := sched.Cache.RemoveNode(node); err != nil {
        // 如果删除失败，则记录错误
        klog.ErrorS(err, "Scheduler cache RemoveNode failed")
    }
}
```

##### ClusterEvent

```GO
// ClusterEvent 是一个表示系统资源状态变化的抽象对象。
// Resource 表示标准 API 资源，例如 Pod、Node 等。
// ActionType 表示特定的更改类型，例如添加、更新或删除。
type ClusterEvent struct {
    Resource GVK // 资源对象的 GVK（group/version/kind），用于唯一标识 API 资源
    ActionType ActionType // 表示资源更改的类型，可通过位运算组合不同的 ActionType 实现新的语义
    Label string // 标签信息
}

// GVK 表示组/版本/种类，可唯一标识一个特定的 API 资源。
type GVK string

const (
	Pod                   GVK = "Pod"
	Node                  GVK = "Node"
	PersistentVolume      GVK = "PersistentVolume"
	PersistentVolumeClaim GVK = "PersistentVolumeClaim"
	PodSchedulingContext  GVK = "PodSchedulingContext"
	ResourceClaim         GVK = "ResourceClaim"
	StorageClass          GVK = "storage.k8s.io/StorageClass"
	CSINode               GVK = "storage.k8s.io/CSINode"
	CSIDriver             GVK = "storage.k8s.io/CSIDriver"
	CSIStorageCapacity    GVK = "storage.k8s.io/CSIStorageCapacity"
	WildCard              GVK = "*"
)

// ActionType 是一个整数，用于表示一种资源更改类型。
// 不同的 ActionType 可以通过位运算组合成新的语义。
type ActionType int64

const (
	Add    ActionType = 1 << iota // 1
	Delete                        // 10
	// UpdateNodeXYZ 仅适用于节点事件。
	UpdateNodeAllocatable // 100
	UpdateNodeLabel       // 1000
	UpdateNodeTaint       // 10000
	UpdateNodeCondition   // 100000

	All ActionType = 1<<iota - 1 // 111111

	// 如果您不知道或不关心要使用的特定子更新类型，请使用常规更新类型。
	Update = UpdateNodeAllocatable | UpdateNodeLabel | UpdateNodeTaint | UpdateNodeCondition
)
```

#### applyDefaultHandlers

```go
func (s *Scheduler) applyDefaultHandlers() {
	s.SchedulePod = s.schedulePod
	s.FailureHandler = s.handleSchedulingFailure
}
```

### Run

```go
func (sched *Scheduler) Run(ctx context.Context) {
	sched.SchedulingQueue.Run()

	// 需要在单独的 goroutine 中启动 scheduleOne 循环，
    // 因为 scheduleOne 函数在从 SchedulingQueue 获取下一个项时会阻塞。
    // 如果没有新的 pod 需要调度，它将一直阻塞在这里，
    // 如果在此 goroutine 中完成，将阻塞关闭 SchedulingQueue，
    // 导致在关闭时发生死锁。
	go wait.UntilWithContext(ctx, sched.scheduleOne, 0)

	<-ctx.Done()
	sched.SchedulingQueue.Close()
}
```

### scheduleOne

```go
// scheduleOne为单个Pod执行整个调度工作流。它在调度算法的主机适配上被序列化。
func (sched *Scheduler) scheduleOne(ctx context.Context) {
    // 从调度队列中获取下一个待调度的Pod
    podInfo := sched.NextPod()
    // 当schedulerQueue关闭或podInfo为nil时返回
    if podInfo == nil || podInfo.Pod == nil {
    	return
    }
    pod := podInfo.Pod
    // 获取Pod对应的调度框架
    fwk, err := sched.frameworkForPod(pod)
    if err != nil {
        // 这不应该发生，因为我们只接受指定了与配置文件中的调度程序名称匹配的profile的Pod进行调度。
        klog.ErrorS(err, "Error occurred")
        return
    }
    // 如果pod不需要调度，则返回
    if sched.skipPodSchedule(fwk, pod) {
    	return
    }
    
    klog.V(3).InfoS("Attempting to schedule pod", "pod", klog.KObj(pod))

    // 同步地为Pod查找合适的主机。
    start := time.Now()
    state := framework.NewCycleState()
    state.SetRecordPluginMetrics(rand.Intn(100) < pluginMetricsSamplePercent)

    // 初始化一个空的podsToActivate结构体，它将由插件填充或保持为空。
    podsToActivate := framework.NewPodsToActivate()
    state.Write(framework.PodsToActivateKey, podsToActivate)

    // 创建一个新的调度循环的上下文，并在函数结束时取消
    schedulingCycleCtx, cancel := context.WithCancel(ctx)
    defer cancel()

    // 调度循环
    scheduleResult, assumedPodInfo, status := sched.schedulingCycle(schedulingCycleCtx, state, fwk, podInfo, start, podsToActivate)
    if !status.IsSuccess() {
        // 如果调度循环失败，则使用FailureHandler处理错误
        sched.FailureHandler(schedulingCycleCtx, fwk, assumedPodInfo, status, scheduleResult.nominatingInfo, start)
        return
    }

    // 异步绑定Pod到它的主机（这是由于上面的假设步骤而可以这样做）
    go func() {
        // 创建一个新的绑定循环的上下文，并在函数结束时取消
        bindingCycleCtx, cancel := context.WithCancel(ctx)
        defer cancel()

        // 绑定循环的度量
        metrics.SchedulerGoroutines.WithLabelValues(metrics.Binding).Inc()
        defer metrics.SchedulerGoroutines.WithLabelValues(metrics.Binding).Dec()
        metrics.Goroutines.WithLabelValues(metrics.Binding).Inc()
        defer metrics.Goroutines.WithLabelValues(metrics.Binding).Dec()

        // 执行绑定循环
        status := sched.bindingCycle(bindingCycleCtx, state, fwk, scheduleResult, assumedPodInfo, start, podsToActivate)
        if !status.IsSuccess() {
            // 如果绑定循环失败，则使用handleBindingCycleError处理错误
            sched.handleBindingCycleError(bindingCycleCtx, state, fwk, assumedPodInfo, start, scheduleResult, status)
        }
    }()
}
```

#### NextPod

```go
// MakeNextPodFunc函数返回一个函数，该函数从传入的调度队列中取出下一个待调度的PodInfo并返回。
func MakeNextPodFunc(queue SchedulingQueue) func() framework.QueuedPodInfo {
    // 定义返回的函数，其返回值为framework.QueuedPodInfo类型指针
    return func() *framework.QueuedPodInfo {
        // 从队列中取出下一个PodInfo
        podInfo, err := queue.Pop()
        if err == nil {
            // 打印日志并更新指标
            klog.V(4).InfoS("About to try and schedule pod", "pod", klog.KObj(podInfo.Pod))
            for plugin := range podInfo.UnschedulablePlugins {
                metrics.UnschedulableReason(plugin, podInfo.Pod.Spec.SchedulerName).Dec()
            }
            // 返回PodInfo指针
            return podInfo
        }
        // 打印错误日志并返回nil
        klog.ErrorS(err, "Error while retrieving next pod from scheduling queue")
        return nil
    }
}
```

#### frameworkForPod

```go
// 根据schdulerName获取framework
func (sched *Scheduler) frameworkForPod(pod *v1.Pod) (framework.Framework, error) {
	fwk, ok := sched.Profiles[pod.Spec.SchedulerName]
	if !ok {
		return nil, fmt.Errorf("profile not found for scheduler name %q", pod.Spec.SchedulerName)
	}
	return fwk, nil
}
```

#### skipPodSchedule

```go
// skipPodSchedule函数返回一个布尔值，用于判断是否可以跳过指定情况下的调度该Pod。
func (sched *Scheduler) skipPodSchedule(fwk framework.Framework, pod *v1.Pod) bool {
    // Case 1: Pod正在被删除。
    if pod.DeletionTimestamp != nil {
        // 事件记录器记录“FailedScheduling”事件，表明调度失败。
        fwk.EventRecorder().Eventf(pod, nil, v1.EventTypeWarning, "FailedScheduling", "Scheduling", "skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
        // klog记录详细信息。
        klog.V(3).InfoS("Skip schedule deleting pod", "pod", klog.KObj(pod))
        	return true
    }
    // Case 2: 可以跳过已经被假设的Pod。
    // 如果假设的Pod在之前的调度周期内获得了更新事件，
    // 在被假设之前可以再次添加到调度队列中。
    isAssumed, err := sched.Cache.IsAssumedPod(pod)
    if err != nil {
        // 错误处理。
        utilruntime.HandleError(fmt.Errorf("failed to check whether pod %s/%s is assumed: %v", pod.Namespace, pod.Name, err))
        return false
    }
    return isAssumed
}
```

#### schedulingCycle

```GO
// schedulingCycle 试图调度单个 Pod。
func (sched *Scheduler) schedulingCycle(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	podInfo *framework.QueuedPodInfo,
	start time.Time,
	podsToActivate *framework.PodsToActivate,
) (ScheduleResult, *framework.QueuedPodInfo, *framework.Status) {
    // 获取 Pod
	pod := podInfo.Pod
    // 调用 SchedulePod() 函数尝试为 Pod 进行调度
	scheduleResult, err := sched.SchedulePod(ctx, fwk, state, pod)
	if err != nil {
        // 若返回 ErrNoNodesAvailable，则 Pod 没有可供调度的节点，报错
		if err == ErrNoNodesAvailable {
			status := framework.NewStatus(framework.UnschedulableAndUnresolvable).WithError(err)
			return ScheduleResult{nominatingInfo: clearNominatedNode}, podInfo, status
		}
		// 若返回的是 *framework.FitError 类型的错误，则进行后续的处理
		fitError, ok := err.(*framework.FitError)
		if !ok {
            // 若错误类型不是 *framework.FitError 类型，则记录错误日志，返回错误状态
			klog.ErrorS(err, "Error selecting node for pod", "pod", klog.KObj(pod))
			return ScheduleResult{nominatingInfo: clearNominatedNode}, podInfo, framework.AsStatus(err)
		}
		// SchedulePod() 可能失败是因为 pod 无法适配到任何一个主机，因此我们尝试使用抢占式调度，
        // 希望下次尝试调度该 pod 时，由于抢占而适配成功。也有可能会有另一个 pod 调度到了被抢占的资源上，
        // 但这是无害的。
		if !fwk.HasPostFilterPlugins() {
            // 没有PostFilter插件 报错返回
			klog.V(3).InfoS("No PostFilter plugins are registered, so no preemption will be performed")
			return ScheduleResult{}, podInfo, framework.NewStatus(framework.Unschedulable).WithError(err)
		}

		// 调用 fwk.RunPostFilterPlugins() 函数运行 PostFilter 插件，尝试在未来的调度周期中将 Pod 调度到节点上
		result, status := fwk.RunPostFilterPlugins(ctx, state, pod, fitError.Diagnosis.NodeToStatusMap)
		// 记录日志
        msg := status.Message()
		fitError.Diagnosis.PostFilterMsg = msg
		if status.Code() == framework.Error {
			klog.ErrorS(nil, "Status after running PostFilter plugins for pod", "pod", klog.KObj(pod), "status", msg)
		} else {
			klog.V(5).InfoS("Status after running PostFilter plugins for pod", "pod", klog.KObj(pod), "status", msg)
		}

		var nominatingInfo *framework.NominatingInfo
		if result != nil {
           // 如果调度器的调度结果不为 nil，即存在合适的 Node 被选中，则将其返回的提名信息保存下来。
            // 其中 framework.NominatingInfo 结构体包含了一个 Pod 提名的相关信息，例如该 Pod 可以运行在哪些 Node 上。
            // 这样在下面的运行过程中可以通过 nominatingInfo 传递这些信息。
			nominatingInfo = result.NominatingInfo
		}
        // 返回一个 ScheduleResult 结构体，包含调度结果中的 nominatingInfo 和 podInfo，以及一个带有错误信息的 Status。
        // 这里的 Status 状态为 Unschedulable，表示调度器未能为 Pod 分配到合适的 Node 上运行。
        // 同时将 err 作为错误信息存储在 Status 中。
		return ScheduleResult{nominatingInfo: nominatingInfo}, podInfo, framework.NewStatus(framework.Unschedulable).WithError(err)
	}
	
    // 在 Prometheus 指标中记录调度算法的延迟。
	metrics.SchedulingAlgorithmLatency.Observe(metrics.SinceInSeconds(start))
	
    // 深拷贝 podInfo，得到一个新的 PodInfo 对象，然后将 PodInfo 中的 Pod 赋值给 assumedPod。
	assumedPodInfo := podInfo.DeepCopy()
	assumedPod := assumedPodInfo.Pod
	// 将 assumedPod 分配给 scheduleResult.SuggestedHost 所代表的 Node 上运行，同时更新调度器内部的缓存状态。
    // 其中 sched 是调度器对象，assume 是调度器的一个方法。
    // 如果出现错误，则返回该错误对象。
	err = sched.assume(assumedPod, scheduleResult.SuggestedHost)
	if err != nil {
		// 如果 assume 方法出现错误，则进行以下操作。
        // 返回一个带有错误信息的 Status 对象，其中 clearNominatedNode 表示清除提名节点。
    	// 在这里没有更新 nominatingInfo，所以其值为 nil。
		return ScheduleResult{nominatingInfo: clearNominatedNode},
			assumedPodInfo,
			framework.AsStatus(err)
	}

	// // 运行 reserve 插件的 Reserve 方法。
	if sts := fwk.RunReservePluginsReserve(ctx, state, assumedPod, scheduleResult.SuggestedHost); !sts.IsSuccess() {
		// 如果 Reserve 方法的执行结果不是 Success，说明分配失败。
        // 这时需要进行清理工作，调用 Unreserve 方法来撤销之前的分配。
		fwk.RunReservePluginsUnreserve(ctx, state, assumedPod, scheduleResult.SuggestedHost)
		if forgetErr := sched.Cache.ForgetPod(assumedPod); forgetErr != nil {
			klog.ErrorS(forgetErr, "Scheduler cache ForgetPod failed")
		}

		return ScheduleResult{nominatingInfo: clearNominatedNode},
			assumedPodInfo,
			sts
	}

	// 运行permit插件，这些插件用于检查是否可以在节点上启动容器
	runPermitStatus := fwk.RunPermitPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost)
	if !runPermitStatus.IsWait() && !runPermitStatus.IsSuccess() {
		// 如果不是等待或者成功 调用 Unreserve 方法来撤销之前的分配 bing返回错误
		fwk.RunReservePluginsUnreserve(ctx, state, assumedPod, scheduleResult.SuggestedHost)
		if forgetErr := sched.Cache.ForgetPod(assumedPod); forgetErr != nil {
			klog.ErrorS(forgetErr, "Scheduler cache ForgetPod failed")
		}

		return ScheduleResult{nominatingInfo: clearNominatedNode},
			assumedPodInfo,
			runPermitStatus
	}

	// 在成功的调度周期结束时，如果需要，弹出和移动 Pod。
	if len(podsToActivate.Map) != 0 {
        // 将 podsToActivate.Map 中的 Pod 标记为已激活，以便它们可以开始被调度器监视。
		sched.SchedulingQueue.Activate(podsToActivate.Map)
		// 激活后清空 podsToActivate.Map。
		podsToActivate.Map = make(map[string]*v1.Pod)
	}

	return scheduleResult, assumedPodInfo, nil
}
```

##### schedulePod

```GO
// schedulePod 尝试将给定的 Pod 安排到节点列表中的某个节点上。
// 如果成功，它将返回节点的名称。
// 如果失败，它将返回一个带有原因的 FitError。
func (sched *Scheduler) schedulePod(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) {
    // 创建一个调度追踪
    trace := utiltrace.New("Scheduling", utiltrace.Field{Key: "namespace", Value: pod.Namespace}, utiltrace.Field{Key: "name", Value: pod.Name})
    defer trace.LogIfLong(100 * time.Millisecond)
    // 更新调度器快照
    if err := sched.Cache.UpdateSnapshot(sched.nodeInfoSnapshot); err != nil {
        return result, err
    }
    trace.Step("Snapshotting scheduler cache and node infos done")

    // 如果没有节点可用，则返回 ErrNoNodesAvailable
    if sched.nodeInfoSnapshot.NumNodes() == 0 {
        return result, ErrNoNodesAvailable
    }

    // 查找适合 Pod 的节点
    feasibleNodes, diagnosis, err := sched.findNodesThatFitPod(ctx, fwk, state, pod)
    if err != nil {
        return result, err
    }
    trace.Step("Computing predicates done")

    // 如果没有适合的节点，则返回 FitError
    if len(feasibleNodes) == 0 {
        return result, &framework.FitError{
            Pod:         pod,
            NumAllNodes: sched.nodeInfoSnapshot.NumNodes(),
            Diagnosis:   diagnosis,
        }
    }

    // 当只有一个节点时，直接使用该节点。
    if len(feasibleNodes) == 1 {
        return ScheduleResult{
            SuggestedHost:  feasibleNodes[0].Name,
            EvaluatedNodes: 1 + len(diagnosis.NodeToStatusMap),
            FeasibleNodes:  1,
        }, nil
    }

    // 对节点进行优先级排序
    priorityList, err := prioritizeNodes(ctx, sched.Extenders, fwk, state, pod, feasibleNodes)
    if err != nil {
        return result, err
    }

    // 选择主机节点
    host, err := selectHost(priorityList)
    trace.Step("Prioritizing done")

    return ScheduleResult{
        SuggestedHost:  host,
        EvaluatedNodes: len(feasibleNodes) + len(diagnosis.NodeToStatusMap),
        FeasibleNodes:  len(feasibleNodes),
    }, err
}
```



```GO
// 根据框架过滤器插件和过滤器扩展程序过滤节点，找到适合Pod的节点。
// Filters the nodes to find the ones that fit the pod based on the framework
// filter plugins and filter extenders.
func (sched *Scheduler) findNodesThatFitPod(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) ([]*v1.Node, framework.Diagnosis, error) {
    // 创建一个诊断对象，用于存储调度过程中的状态信息
    diagnosis := framework.Diagnosis{
        NodeToStatusMap:      make(framework.NodeToStatusMap), // 存储节点的状态信息
        UnschedulablePlugins: sets.New[string](), // 存储不能成功调度的插件的名称
    }

    // 获取所有节点的信息
    allNodes, err := sched.nodeInfoSnapshot.NodeInfos().List()
    if err != nil {
        return nil, diagnosis, err
    }

    // 运行 "prefilter" 插件
    preRes, s := fwk.RunPreFilterPlugins(ctx, state, pod)
    if !s.IsSuccess() {
        if !s.IsUnschedulable() {
            return nil, diagnosis, s.AsError()
        }
        // 记录 PreFilter 插件的信息
        msg := s.Message()
        diagnosis.PreFilterMsg = msg
        klog.V(5).InfoS("Status after running PreFilter plugins for pod", "pod", klog.KObj(pod), "status", msg)
        // 记录调用 PreFilter 插件失败的插件名称
        if s.FailedPlugin() != "" {
            diagnosis.UnschedulablePlugins.Insert(s.FailedPlugin())
        }
        return nil, diagnosis, nil
    }

    // 如果 Pod 的 NominatedNodeName 不为空，则优先选择该节点进行调度
    if len(pod.Status.NominatedNodeName) > 0 {
        feasibleNodes, err := sched.evaluateNominatedNode(ctx, pod, fwk, state, diagnosis)
        if err != nil {
            klog.ErrorS(err, "Evaluation failed on nominated node", "pod", klog.KObj(pod), "node", pod.Status.NominatedNodeName)
        }
        // 如果该节点通过了所有过滤器的检查，则将其作为唯一的候选节点
        if len(feasibleNodes) != 0 {
            return feasibleNodes, diagnosis, nil
        }
    }

    // 根据 preRes 中包含的节点列表或所有节点来过滤节点
    nodes := allNodes
    if !preRes.AllNodes() {
        nodes = make([]*framework.NodeInfo, 0, len(preRes.NodeNames))
        for n := range preRes.NodeNames {
            nInfo, err := sched.nodeInfoSnapshot.NodeInfos().Get(n)
            if err != nil {
                return nil, diagnosis, err
            }
            nodes = append(nodes, nInfo)
        }
    }

    // 在过滤器中查找符合要求的节点
    feasibleNodes, err := sched.findNodesThatPassFilters(ctx, fwk, state, pod, diagnosis, nodes)
    // 计算下一轮开始搜索的节点索引，这个索引是在所有节点中的索引，并不仅仅是已经经过筛选的节点
	// 通过计算，可以使得调度器下一次搜索时不会从已经被搜索过的节点开始，而是从接下来的节点开始搜索，确保所有节点都有被搜索到的机会
    processedNodes := len(feasibleNodes) + len(diagnosis.NodeToStatusMap)
	sched.nextStartNodeIndex = (sched.nextStartNodeIndex + processedNodes) % len(nodes)
	if err != nil {
        // 如果前面的操作出现了错误，直接返回错误信息
		return nil, diagnosis, err
	}
	// 根据 extenders 过滤节点，筛选出最终适合 Pod 的节点，可能会修改 diagnosis.NodeToStatusMap 中的节点状态信息
	feasibleNodes, err = findNodesThatPassExtenders(sched.Extenders, pod, feasibleNodes, diagnosis.NodeToStatusMap)
	if err != nil {
		return nil, diagnosis, err
	}
    // 返回筛选出的适合 Pod 的节点列表，以及状态诊断信息
	return feasibleNodes, diagnosis, nil
}
```

###### evaluateNominatedNode

```GO
// 该函数的作用是评估被提名的节点是否适合调度当前的Pod。
// 参数列表：调度器（Scheduler）、Pod对象（pod）、框架（fwk）、调度周期状态（state）、诊断信息（diagnosis）。
func (sched *Scheduler) evaluateNominatedNode(ctx context.Context, pod *v1.Pod, fwk framework.Framework, state *framework.CycleState, diagnosis framework.Diagnosis) ([]*v1.Node, error) {
    // 获取Pod的被提名节点名称。
    nnn := pod.Status.NominatedNodeName
    // 根据被提名节点名称获取节点信息。
    nodeInfo, err := sched.nodeInfoSnapshot.Get(nnn)
    if err != nil {
    	return nil, err
    }
    // 将节点信息封装成framework.NodeInfo对象并添加到节点切片中。
    node := []*framework.NodeInfo{nodeInfo}
    // 通过过滤器找到符合要求的节点。
    feasibleNodes, err := sched.findNodesThatPassFilters(ctx, fwk, state, pod, diagnosis, node)
    if err != nil {
    	return nil, err
    }

    // 使用Extender扩展器对节点进行扩展，进一步筛选符合要求的节点。
    feasibleNodes, err = findNodesThatPassExtenders(sched.Extenders, pod, feasibleNodes, diagnosis.NodeToStatusMap)
    if err != nil {
        return nil, err
    }

    // 返回符合要求的节点切片和错误信息。
    return feasibleNodes, nil
}
```

###### findNodesThatPassFilters

```go
// findNodesThatPassFilters函数找到符合筛选插件的节点。
    func (sched *Scheduler) findNodesThatPassFilters(
    ctx context.Context, // 上下文
    fwk framework.Framework, // 框架
    state *framework.CycleState, // 状态信息
    pod *v1.Pod, // pod对象
    diagnosis framework.Diagnosis, // 诊断信息
    nodes []*framework.NodeInfo, // 可用节点信息
) ([]*v1.Node, error) {
    numAllNodes := len(nodes) // 可用节点数量
    numNodesToFind := sched.numFeasibleNodesToFind(fwk.PercentageOfNodesToScore(), int32(numAllNodes)) // 需要找到的节点数量
   // 创建一个足够大的feasibleNodes切片，避免动态增长。
    feasibleNodes := make([]*v1.Node, numNodesToFind)

    // 如果没有筛选插件，直接选择前numNodesToFind个节点。
    if !fwk.HasFilterPlugins() {
        for i := range feasibleNodes {
            feasibleNodes[i] = nodes[(sched.nextStartNodeIndex+i)%numAllNodes].Node()
        }
        return feasibleNodes, nil
    }

    errCh := parallelize.NewErrorChannel() // 创建一个用于报告错误的通道
    var statusesLock sync.Mutex // 用于保护statusMap的锁
    var feasibleNodesLen int32 // 可用节点数量
    ctx, cancel := context.WithCancel(ctx) // 用于取消处理过程的上下文
    defer cancel()
    checkNode := func(i int) { // 用于遍历节点并检查可用性的函数
        // 我们从前一次调度周期结束的地方开始检查节点，这样可以确保所有节点有相同的机会被检查。
        nodeInfo := nodes[(sched.nextStartNodeIndex+i)%numAllNodes] // 取出当前要检查的节点信息
        status := fwk.RunFilterPluginsWithNominatedPods(ctx, state, pod, nodeInfo) // 运行筛选插件来检查节点可用性
        if status.Code() == framework.Error { // 如果检查出错
            errCh.SendErrorWithCancel(status.AsError(), cancel) // 报告错误并取消处理过程
            return
        }
        if status.IsSuccess() { // 如果节点可用
            length := atomic.AddInt32(&feasibleNodesLen, 1) // 增加可用节点数量并获取其长度
            if length > numNodesToFind { // 如果可用节点数量大于需要找到的数量
                cancel() // 取消处理过程
                atomic.AddInt32(&feasibleNodesLen, -1) // 减少可用节点数量
            } else {
                feasibleNodes[length-1] = nodeInfo.Node() // 将可用节点添加到feasibleNodes中
            }
        } else { // 如果节点不可用
            statusesLock.Lock()
            diagnosis.NodeToStatusMap[nodeInfo.Node().Name] = status // 添加节点的状态信息
            diagnosis.UnschedulablePlugins.Insert(status.FailedPlugin()) // 添加不可调度的插件
            statusesLock.Unlock()
        }
    }

    beginCheckNode := time.Now()
	statusCode := framework.Success
	defer func() {
		metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Filter, statusCode.String(), fwk.ProfileName()).Observe(metrics.SinceInSeconds(beginCheckNode))
	}()

	//一旦找到配置数量的可行节点，就停止搜索更多节点。
	fwk.Parallelizer().Until(ctx, numAllNodes, checkNode, metrics.Filter)
	feasibleNodes = feasibleNodes[:feasibleNodesLen]
	if err := errCh.ReceiveError(); err != nil {
		statusCode = framework.Error
		return feasibleNodes, err
	}
	return feasibleNodes, nil
}
```

###### prioritizeNodes

```GO
// prioritizeNodes通过运行评分插件对节点进行排序，
// 运行评分插件会为每个节点返回一个分数，这些插件的分数会被加在一起以得出节点的总分数，然后运行任何扩展插件。
// 最后，所有分数会被组合（相加），以获得所有节点的加权总分数
func prioritizeNodes(
    ctx context.Context, // 运行上下文
    extenders []framework.Extender, // 扩展插件
    fwk framework.Framework, // 调度框架
    state *framework.CycleState, // 调度周期状态
    pod *v1.Pod, // pod对象
    nodes []*v1.Node, // 节点数组
) ([]framework.NodePluginScores, error) { // 返回节点插件分数数组和错误

    // 如果未提供优先级配置，则所有节点的分数都为1。
    // 这是为了以所需格式生成优先级列表所必需的
    if len(extenders) == 0 && !fwk.HasScorePlugins() {
        result := make([]framework.NodePluginScores, 0, len(nodes))
        for i := range nodes {
            result = append(result, framework.NodePluginScores{
                Name:       nodes[i].Name,
                TotalScore: 1,
            })
        }
        return result, nil
    }

    // 运行PreScore插件。
    preScoreStatus := fwk.RunPreScorePlugins(ctx, state, pod, nodes)
    if !preScoreStatus.IsSuccess() {
        return nil, preScoreStatus.AsError()
    }

    // 运行Score插件。
    nodesScores, scoreStatus := fwk.RunScorePlugins(ctx, state, pod, nodes)
    if !scoreStatus.IsSuccess() {
        return nil, scoreStatus.AsError()
    }

    // 如果启用，记录级别为10的其他详细信息。
    klogV := klog.V(10)
    if klogV.Enabled() {
        for _, nodeScore := range nodesScores {
            for _, pluginScore := range nodeScore.Scores {
                klogV.InfoS("Plugin scored node for pod", "pod", klog.KObj(pod), "plugin", pluginScore.Name, "node", nodeScore.Name, "score", pluginScore.Score)
            }
        }
    }

    if len(extenders) != 0 && nodes != nil {
		// allNodeExtendersScores包含所有节点的所有扩展程序分数。
        // 它的键名为节点名称。
		allNodeExtendersScores := make(map[string]*framework.NodePluginScores, len(nodes))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := range extenders {
            // 如果extenders不关心pod 跳过
			if !extenders[i].IsInterested(pod) {
				continue
			}
			wg.Add(1)
			go func(extIndex int) {
                // 记录调度器协程数量和扩展器的数量
				metrics.SchedulerGoroutines.WithLabelValues(metrics.PrioritizingExtender).Inc()
				metrics.Goroutines.WithLabelValues(metrics.PrioritizingExtender).Inc()
				// 在函数返回时减少协程数量并完成 WaitGroup
                defer func() {
					metrics.SchedulerGoroutines.WithLabelValues(metrics.PrioritizingExtender).Dec()
					metrics.Goroutines.WithLabelValues(metrics.PrioritizingExtender).Dec()
					wg.Done()
				}()
                // 使用扩展器的 Prioritize 函数计算优先级
				prioritizedList, weight, err := extenders[extIndex].Prioritize(pod, nodes)
				if err != nil {
					// 如果计算失败则忽略此扩展器
					klog.V(5).InfoS("Failed to run extender's priority function. No score given by this extender.", "error", err, "pod", klog.KObj(pod), "extender", extenders[extIndex].Name())
					return
				}
                // 对于每个经过优先排序的节点，计算最终得分
				mu.Lock()
				defer mu.Unlock()
				for i := range *prioritizedList {
					nodename := (*prioritizedList)[i].Host
					score := (*prioritizedList)[i].Score
					if klogV.Enabled() {
						klogV.InfoS("Extender scored node for pod", "pod", klog.KObj(pod), "extender", extenders[extIndex].Name(), "node", nodename, "score", score)
					}

					 // 将扩展器得分与节点名称组合成一个新的 PluginScore 并添加到 allNodeExtendersScores 中
					finalscore := score * weight * (framework.MaxNodeScore / extenderv1.MaxExtenderPriority)

					if allNodeExtendersScores[nodename] == nil {
						allNodeExtendersScores[nodename] = &framework.NodePluginScores{
							Name:   nodename,
							Scores: make([]framework.PluginScore, 0, len(extenders)),
						}
					}
					allNodeExtendersScores[nodename].Scores = append(allNodeExtendersScores[nodename].Scores, framework.PluginScore{
						Name:  extenders[extIndex].Name(),
						Score: finalscore,
					})
					allNodeExtendersScores[nodename].TotalScore += finalscore
				}
			}(i)
		}
		// 等待所有goroutine完成
		wg.Wait()
		for i := range nodesScores {
			if score, ok := allNodeExtendersScores[nodes[i].Name]; ok {
				nodesScores[i].Scores = append(nodesScores[i].Scores, score.Scores...)
				nodesScores[i].TotalScore += score.TotalScore
			}
		}
	}
	
    // 如果开启了 打印日志
	if klogV.Enabled() {
		for i := range nodesScores {
			klogV.InfoS("Calculated node's final score for pod", "pod", klog.KObj(pod), "node", nodesScores[i].Name, "score", nodesScores[i].TotalScore)
		}
	}
	return nodesScores, nil
}
```

###### selectHost

```go
// selectHost函数从节点得分列表中以 reservoir sampling 的方式选择一个节点。
func selectHost(nodeScores []framework.NodePluginScores) (string, error) {
	// 如果列表为空，则返回错误。
	if len(nodeScores) == 0 {
		return "", fmt.Errorf("empty priorityList")
	}
	// 初始化得分最高的节点。
	maxScore := nodeScores[0].TotalScore
	selected := nodeScores[0].Name
	cntOfMaxScore := 1 // 记录得分最高的节点数目。
	// 遍历剩余的节点得分列表。
	for _, ns := range nodeScores[1:] {
		// 如果有一个节点的总得分比当前最高得分更高，则将其设为新的最高得分的节点。
		if ns.TotalScore > maxScore {
			maxScore = ns.TotalScore
			selected = ns.Name
			cntOfMaxScore = 1 // 重新计算得分最高的节点数目。
		// 如果有一个节点的总得分等于当前最高得分，则可能将其选为新的候选节点。
		} else if ns.TotalScore == maxScore {
			cntOfMaxScore++ // 增加得分最高的节点数目。
			if rand.Intn(cntOfMaxScore) == 0 {
				// 用1/cntOfMaxScore的概率用当前节点替换候选节点。
				selected = ns.Name
			}
		}
	}
	// 返回所选节点的名称。
	return selected, nil
}
```

##### assume

```go
// assume函数用于将Pod添加到缓存中，以便可以异步地进行绑定。修改了传入的参数"assumed"。
func (sched *Scheduler) assume(assumed *v1.Pod, host string) error {
    // 乐观地假设绑定将成功，并在后台将其发送到api服务器。
    // 如果绑定失败，调度程序将立即释放分配给"assumed"的资源。
    assumed.Spec.NodeName = host
    // 将Pod添加到缓存中
    if err := sched.Cache.AssumePod(assumed); err != nil {
        klog.ErrorS(err, "Scheduler cache AssumePod failed") // 如果添加失败，则记录错误日志
        return err // 返回错误
    }

    // 如果"assumed"是已提名的Pod，则应从内部缓存中删除它
    if sched.SchedulingQueue != nil {
        sched.SchedulingQueue.DeleteNominatedPodIfExists(assumed)
    }

    return nil // 返回nil表示没有错误
}
```

#### bindingCycle

```go
// bindingCycle函数尝试将一个已经假定的Pod进行绑定。
func (sched *Scheduler) bindingCycle(
    ctx context.Context, // 上下文
    state *framework.CycleState, // 周期状态
    fwk framework.Framework, // 调度框架
    scheduleResult ScheduleResult, // 调度结果
    assumedPodInfo *framework.QueuedPodInfo, // 已假定Pod的信息
    start time.Time, // 绑定开始时间
    podsToActivate *framework.PodsToActivate) *framework.Status { // 激活的Pod列表
    
    assumedPod := assumedPodInfo.Pod // 获取已假定的Pod

    // 运行"permit"插件
    if status := fwk.WaitOnPermit(ctx, assumedPod); !status.IsSuccess() {
        return status // 如果不成功则返回状态
    }

    // 运行"prebind"插件
    if status := fwk.RunPreBindPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost); !status.IsSuccess() {
        return status // 如果不成功则返回状态
    }

    // 运行"bind"插件
    if status := sched.bind(ctx, fwk, assumedPod, scheduleResult.SuggestedHost, state); !status.IsSuccess() {
        return status // 如果不成功则返回状态
    }

    // 当klog的详细程度低于2时，计算nodeResourceString可能很重。如果是这样，则避免计算。
    klog.V(2).InfoS("Successfully bound pod to node", "pod", klog.KObj(assumedPod), "node", scheduleResult.SuggestedHost, "evaluatedNodes", scheduleResult.EvaluatedNodes, "feasibleNodes", scheduleResult.FeasibleNodes)

    // 记录调度的度量指标
    metrics.PodScheduled(fwk.ProfileName(), metrics.SinceInSeconds(start))
    metrics.PodSchedulingAttempts.Observe(float64(assumedPodInfo.Attempts))
    metrics.PodSchedulingDuration.WithLabelValues(getAttemptsLabel(assumedPodInfo)).Observe(metrics.SinceInSeconds(assumedPodInfo.InitialAttemptTimestamp))

    // 运行"postbind"插件
    fwk.RunPostBindPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost)

    // 在成功绑定周期的末尾，如果需要，移动Pods。
    if len(podsToActivate.Map) != 0 {
        sched.SchedulingQueue.Activate(podsToActivate.Map)
        // 不像schedulingCycle()函数中的逻辑，我们不需要删除条目，
        // 因为"podsToActivate.Map"不再使用。
    }

    return nil // 返回nil表示没有错误
}
```

##### bind

```go
// bind函数用于将Pod绑定到给定的节点上。
// 绑定的优先级为：(1) 扩展程序，(2) 框架插件。
// 我们期望它以异步方式运行，因此我们在内部处理绑定指标。
func (sched *Scheduler) bind(ctx context.Context, fwk framework.Framework, assumed *v1.Pod, targetNode string, state *framework.CycleState) (status *framework.Status) {
    // 延迟函数在函数返回前执行
    defer func() {
    // 完成绑定时，记录绑定指标
    sched.finishBinding(fwk, assumed, targetNode, status)
    }()
    // 如果扩展程序成功绑定Pod，返回状态并携带错误信息
    bound, err := sched.extendersBinding(assumed, targetNode)
    if bound {
        return framework.AsStatus(err)
    }
    // 否则运行框架插件进行绑定
    return fwk.RunBindPlugins(ctx, state, assumed, targetNode)
}
```

###### finishBinding

```go
func (sched *Scheduler) finishBinding(fwk framework.Framework, assumed *v1.Pod, targetNode string, status *framework.Status) {
    // 在调度器的缓存中完成绑定
    if finErr := sched.Cache.FinishBinding(assumed); finErr != nil {
    klog.ErrorS(finErr, "Scheduler cache FinishBinding failed")
    }

    // 如果绑定失败，则记录日志并返回
    if !status.IsSuccess() {
        klog.V(1).InfoS("Failed to bind pod", "pod", klog.KObj(assumed))
        return
    }

    // 记录事件，表示绑定成功
    fwk.EventRecorder().Eventf(assumed, nil, v1.EventTypeNormal, "Scheduled", "Binding", "Successfully assigned %v/%v to %v", assumed.Namespace, assumed.Name, targetNode)
}
```

###### extendersBinding

```go
// TODO(#87159): 将此代码移到插件中。
func (sched *Scheduler) extendersBinding(pod *v1.Pod, node string) (bool, error) {
    // 遍历所有扩展器
    for _, extender := range sched.Extenders {
        // 如果扩展器不是绑定器或不关心该 Pod，则继续循环
        if !extender.IsBinder() || !extender.IsInterested(pod) {
        	continue
        }
        // 调用扩展器的 Bind 函数完成绑定，并返回 true 表示绑定成功
        return true, extender.Bind(&v1.Binding{
            ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID},
            Target: v1.ObjectReference{Kind: "Node", Name: node},
    	})
    }
    // 如果没有扩展器对该 Pod 进行绑定操作，则返回 false 表示未绑定
    return false, nil
}
```

#### handleBindingCycleError

```go
func (sched *Scheduler) handleBindingCycleError(
    ctx context.Context,
    state *framework.CycleState,
    fwk framework.Framework,
    podInfo *framework.QueuedPodInfo,
    start time.Time,
    scheduleResult ScheduleResult,
    status *framework.Status) {
    
    // 获取 Pod 的信息
    assumedPod := podInfo.Pod

    // 触发未预留插件进行清理与回收已预留的资源
    fwk.RunReservePluginsUnreserve(ctx, state, assumedPod, scheduleResult.SuggestedHost)

    // 将 Assumed Pod 从调度器缓存中移除
    if forgetErr := sched.Cache.ForgetPod(assumedPod); forgetErr != nil {
        klog.ErrorS(forgetErr, "scheduler cache ForgetPod failed")
    } else {
        // 在绑定周期中，从缓存中 "Forget" 掉一个 Assumed Pod 应该被视为一个 PodDelete 事件，
        // 因为该 Assumed Pod 已经占用了调度器缓存中的一定资源。
        //
        // 注意，不要移动 Assumed Pod 本身，因为 Assumed Pod 始终是不可调度的。
        // 这里有意将此操作 "defer"，否则 MoveAllToActiveOrBackoffQueue() 将更新 `q.moveRequest`，
        // 并将 Assumed Pod 移动到 backoffQ。
        if status.IsUnschedulable() {
            defer sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(internalqueue.AssignedPodDelete, func(pod *v1.Pod) bool {
                return assumedPod.UID != pod.UID
            })
        } else {
            sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(internalqueue.AssignedPodDelete, nil)
        }
    }

    // 调用 FailureHandler 处理错误
    sched.FailureHandler(ctx, fwk, podInfo, status, clearNominatedNode, start)
}
```

##### handleSchedulingFailure

```GO
// handleSchedulingFailure记录一个事件，表示Pod无法调度。如果设置了，还要更新Pod条件和被提名的节点名称。
func (sched *Scheduler) handleSchedulingFailure(ctx context.Context, fwk framework.Framework, podInfo *framework.QueuedPodInfo, status *framework.Status, nominatingInfo *framework.NominatingInfo, start time.Time) {
	// 设置 pod 的失败原因
	reason := v1.PodReasonSchedulerError
	if status.IsUnschedulable() {
		reason = v1.PodReasonUnschedulable
	}

	// 根据不同的原因进行相应的处理
	switch reason {
	case v1.PodReasonUnschedulable:
		metrics.PodUnschedulable(fwk.ProfileName(), metrics.SinceInSeconds(start))
	case v1.PodReasonSchedulerError:
		metrics.PodScheduleError(fwk.ProfileName(), metrics.SinceInSeconds(start))
	}

	pod := podInfo.Pod
	err := status.AsError()
	errMsg := status.Message()

	// 如果没有可用节点，等待
	if err == ErrNoNodesAvailable {
		klog.V(2).InfoS("Unable to schedule pod; no nodes are registered to the cluster; waiting", "pod", klog.KObj(pod), "err", err)
	} else if fitError, ok := err.(*framework.FitError); ok {
		// 如果是无法调度的错误，则将 UnschedulablePlugins 注入 PodInfo，以便稍后有效地在队列之间移动 Pod。
		podInfo.UnschedulablePlugins = fitError.Diagnosis.UnschedulablePlugins
		klog.V(2).InfoS("Unable to schedule pod; no fit; waiting", "pod", klog.KObj(pod), "err", errMsg)
	} else if apierrors.IsNotFound(err) {
		// 如果是找不到节点，则等待
		klog.V(2).InfoS("Unable to schedule pod, possibly due to node not found; waiting", "pod", klog.KObj(pod), "err", errMsg)
		if errStatus, ok := err.(apierrors.APIStatus); ok && errStatus.Status().Details.Kind == "node" {
			nodeName := errStatus.Status().Details.Name
			// 如果节点未找到，则不立即删除节点。再次尝试获取节点，如果仍然未找到，则从调度器缓存中删除该节点。
			_, err := fwk.ClientSet().CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			if err != nil && apierrors.IsNotFound(err) {
				node := v1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
				if err := sched.Cache.RemoveNode(&node); err != nil {
					klog.V(4).InfoS("Node is not found; failed to remove it from the cache", "node", node.Name)
				}
			}
		}
	} else {
		// 其他错误重试
		klog.ErrorS(err, "Error scheduling pod; retrying", "pod", klog.KObj(pod))
	}

	// 检查Pod是否存在于informer缓存中。
	podLister := fwk.SharedInformerFactory().Core().V1().Pods().Lister()
	cachedPod, e := podLister.Pods(pod.Namespace).Get(pod.Name)
	if e != nil {
        // 如果Pod不存在于informer缓存中，则打印日志并退出函数。
		klog.InfoS("Pod doesn't exist in informer cache", "pod", klog.KObj(pod), "err", e)
	} else {
		// 如果Pod存在于informer缓存中，继续判断其是否已被分配到节点上。
		if len(cachedPod.Spec.NodeName) != 0 {
            // 如果Pod已经被分配到节点上，则打印日志并退出函数。
			klog.InfoS("Pod has been assigned to node. Abort adding it back to queue.", "pod", klog.KObj(pod), "node", cachedPod.Spec.NodeName)
		} else {
			// 如果Pod存在于informer缓存中，并且没有被分配到节点上，则将其添加到调度队列中。
			// 注意，此处需要先进行DeepCopy操作，因为cachedPod是从SharedInformer中获取的，可能会在之后被修改。
			podInfo.PodInfo, _ = framework.NewPodInfo(cachedPod.DeepCopy())
			if err := sched.SchedulingQueue.AddUnschedulableIfNotPresent(podInfo, sched.SchedulingQueue.SchedulingCycle()); err != nil {
				klog.ErrorS(err, "Error occurred")
			}
		}
	}

	// 更新调度队列中被提名的Pod信息。
	if sched.SchedulingQueue != nil {
		sched.SchedulingQueue.AddNominatedPod(podInfo.PodInfo, nominatingInfo)
	}

	if err == nil {
		// 只有在测试时才会执行到这里。
		return
	}
	
    // 如果出现错误，则打印日志并更新Pod的调度状态。
	msg := truncateMessage(errMsg)
	fwk.EventRecorder().Eventf(pod, nil, v1.EventTypeWarning, "FailedScheduling", "Scheduling", msg)
	if err := updatePod(ctx, sched.client, pod, &v1.PodCondition{
		Type:    v1.PodScheduled,
		Status:  v1.ConditionFalse,
		Reason:  reason,
		Message: errMsg,
	}, nominatingInfo); err != nil {
		klog.ErrorS(err, "Error updating pod", "pod", klog.KObj(pod))
	}
}
```

###### truncateMessage

```go
// truncateMessage 是一个函数，用于截断消息以符合 NoteLengthLimit 的限制。
func truncateMessage(message string) string {
    // 将 max 设为 validation 包中 NoteLengthLimit 的值。
    max := validation.NoteLengthLimit
    // 如果消息长度小于等于限制长度，则返回原消息。
    if len(message) <= max {
    	return message
    }
    // 将 suffix 设为字符串 " ..."。
    suffix := " ..."
    // 截取消息字符串，长度为限制长度减去后缀长度，再加上后缀本身。
    return message[:max-len(suffix)] + suffix
}
```

###### updatePod

```go
// updatePod 是一个函数，用于更新 Pod 的状态。
func updatePod(ctx context.Context, client clientset.Interface, pod *v1.Pod, condition *v1.PodCondition, nominatingInfo *framework.NominatingInfo) error {
    // 打印日志，记录正在更新的 Pod 条件的类型、状态、原因等信息。
    klog.V(3).InfoS("Updating pod condition", "pod", klog.KObj(pod), "conditionType", condition.Type, "conditionStatus", condition.Status, "conditionReason", condition.Reason)
    // 复制一份 Pod 的状态。
    podStatusCopy := pod.Status.DeepCopy()
    // 如果正在尝试设置 NominatedNodeName，并且它与现有值不同，则需要更新 NominatedNodeName。
    nnnNeedsUpdate := nominatingInfo.Mode() == framework.ModeOverride && pod.Status.NominatedNodeName != nominatingInfo.NominatedNodeName
    // 如果不能更新 Pod 的条件且不需要更新 NominatedNodeName，则直接返回 nil。
    if !podutil.UpdatePodCondition(podStatusCopy, condition) && !nnnNeedsUpdate {
    	return nil
    }
    // 如果需要更新 NominatedNodeName，则将 NominatedNodeName 更新为新值。
    if nnnNeedsUpdate {
    	podStatusCopy.NominatedNodeName = nominatingInfo.NominatedNodeName
    }
    // 使用 util.PatchPodStatus 函数更新 Pod 的状态，并返回错误信息。
    return util.PatchPodStatus(ctx, client, pod, podStatusCopy)
}
```

