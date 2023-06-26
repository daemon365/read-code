---
id: 1-kube-apiserver-code 
title: kube-apiserver 启动流程及CreateServerChain 代码走读
description: kube-apiserver 启动流程及CreateServerChain 代码走读
keywords:
  - kubernetes
  - kube-apiserver
slug: /
---

## 简介

Kube-apiserver 是 Kubernetes 系统中的核心组件之一，它是 Kubernetes API 的前端组件，负责暴露 Kubernetes 集群的 API，并处理集群内外部的 API 请求。

以下是 kube-apiserver 的主要作用和功能：

1. API 暴露：kube-apiserver 为集群的各个组件（如 kube-controller-manager、kube-scheduler、kubelet 等）和用户提供了一个统一的入口点，通过 HTTP 或 HTTPS 协议暴露 Kubernetes API。其他组件和工具可以通过 kube-apiserver 与集群进行通信，执行各种操作。
2. 身份验证和授权：kube-apiserver 处理 API 请求时，会对请求进行身份验证和授权。它集成了各种身份验证机制，如基于令牌、客户端证书、用户名和密码等方式。在请求访问集群资源之前，kube-apiserver 会验证请求的身份和权限，确保只有经过授权的用户或组件才能执行相应操作。
3. 数据存储和持久化：kube-apiserver 通过与 etcd（外部键值存储系统）进行交互，将 Kubernetes 集群的各种资源配置信息（如 Pod、Service、ReplicaSet 等）持久化存储。它负责将 API 请求转换为 etcd 数据存储操作，并从 etcd 中检索数据以响应 API 请求。
4. 资源验证和默认值设置：kube-apiserver 对提交的资源配置进行验证，确保其符合 Kubernetes 的规范和限制。它会检查资源对象的结构、字段、标签等，并根据资源定义的默认值设置进行补充。这有助于保持集群中资源的一致性和正确性。
5. 请求处理和调度：kube-apiserver 接收 API 请求后，根据请求的类型和内容，将请求转发给相应的控制器或调度器进行处理。它协调集群内各个组件之间的交互，确保集群状态的一致性和可靠性。

kube-apiserver 是 Kubernetes 集群的 API 入口和核心处理组件，负责管理和维护集群的状态、配置和资源信息。通过与其他组件的交互，它实现了 Kubernetes 的核心功能，如资源管理、调度、扩展等。

## main

```go
func main() {
    // 创建一个cobra的command
	command := app.NewAPIServerCommand()
    // 启动
	code := cli.Run(command)
	os.Exit(code)
}
```

## NewAPIServerCommand

```GO
func NewAPIServerCommand() *cobra.Command {
    // 创建一个新的 ServerRunOptions 实例
    s := options.NewServerRunOptions()
    
    // 创建一个 cobra.Command 实例
    cmd := &cobra.Command{
        // 命令使用的名称
        Use: "kube-apiserver",
        
        // 命令的长描述信息
        Long: `The Kubernetes API server validates and configures data
for the api objects which include pods, services, replicationcontrollers, and
others. The API Server services REST operations and provides the frontend to the
cluster's shared state through which all other components interact.`,
        
        // 当命令发生错误时，停止打印用法信息
        SilenceUsage: true,
        
        // 在运行命令之前执行的持久性预运行函数
        PersistentPreRunE: func(*cobra.Command, []string) error {
            // 禁止 client-go 的警告输出
            // kube-apiserver 的 loopback 客户端不应该记录自己发出的警告
            rest.SetDefaultWarningHandler(rest.NoWarnings{})
            return nil
        },
        
        // 运行命令的函数
        RunE: func(cmd *cobra.Command, args []string) error {
            // 打印版本信息并在需要时退出
            verflag.PrintAndExitIfRequested()
            fs := cmd.Flags()
            
            // 在最早的时候激活日志记录，然后显示具有最终日志记录配置的标志。
            if err := logsapi.ValidateAndApply(s.Logs, utilfeature.DefaultFeatureGate); err != nil {
                return err
            }
            cliflag.PrintFlags(fs)
            
            // 设置默认选项
            completedOptions, err := Complete(s)
            if err != nil {
                return err
            }
            
            // 验证选项
            if errs := completedOptions.Validate(); len(errs) != 0 {
                return utilerrors.NewAggregate(errs)
            }
            
            // 添加功能启用度量信息
            utilfeature.DefaultMutableFeatureGate.AddMetrics()
            return Run(completedOptions, genericapiserver.SetupSignalHandler())
        },
        
        // 命令接受的参数验证函数
        Args: func(cmd *cobra.Command, args []string) error {
            for _, arg := range args {
                if len(arg) > 0 {
                    return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
                }
            }
            return nil
        },
    }
    
    // 获取命令的标志
    fs := cmd.Flags()
    
    // 获取命名标志集合
    namedFlagSets := s.Flags()
    
    // 添加全局标志
    verflag.AddFlags(namedFlagSets.FlagSet("global"))
    globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
    options.AddCustomGlobalFlags(namedFlagSets.FlagSet("generic"))
    for _, f := range namedFlagSets.FlagSets {
        fs.AddFlagSet(f)
    }
    
    // 获取终端的列数，并设置用法和帮助函数
    cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
    cliflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)
    
    return cmd
}
```

### ServerRunOptions

```go
type ServerRunOptions struct {
    // GenericServerRunOptions 定义了通用的服务器运行选项
    GenericServerRunOptions *genericoptions.ServerRunOptions
    
    // Etcd 定义了与 Etcd 相关的选项
    Etcd *genericoptions.EtcdOptions
    
    // SecureServing 定义了与安全服务相关的选项，包括循环回环
    SecureServing *genericoptions.SecureServingOptionsWithLoopback
    
    // Audit 定义了与审计相关的选项
    Audit *genericoptions.AuditOptions
    
    // Features 定义了与功能相关的选项
    Features *genericoptions.FeatureOptions
    
    // Admission 定义了与准入控制相关的选项
    Admission *kubeoptions.AdmissionOptions
    
    // Authentication 定义了与认证相关的选项
    Authentication *kubeoptions.BuiltInAuthenticationOptions
    
    // Authorization 定义了与授权相关的选项
    Authorization *kubeoptions.BuiltInAuthorizationOptions
    
    // CloudProvider 定义了与云提供商相关的选项
    CloudProvider *kubeoptions.CloudProviderOptions
    
    // APIEnablement 定义了与 API 启用相关的选项
    APIEnablement *genericoptions.APIEnablementOptions
    
    // EgressSelector 定义了与出口选择器相关的选项
    EgressSelector *genericoptions.EgressSelectorOptions
    
    // Metrics 定义了与指标相关的选项
    Metrics *metrics.Options
    
    // Logs 定义了与日志相关的选项
    Logs *logs.Options
    
    // Traces 定义了与跟踪相关的选项
    Traces *genericoptions.TracingOptions
    
    AllowPrivileged           bool
    EnableLogsHandler         bool
    EventTTL                  time.Duration
    KubeletConfig             kubeletclient.KubeletClientConfig
    KubernetesServiceNodePort int
    
    // MaxConnectionBytesPerSec 定义了每秒的最大连接字节数
    MaxConnectionBytesPerSec int64
    
    // ServiceClusterIPRange 是用户提供的输入，映射到实际值
    ServiceClusterIPRanges string
    
    // PrimaryServiceClusterIPRange 和 SecondaryServiceClusterIPRange 是将 ServiceClusterIPRange 解析为实际值的结果
    PrimaryServiceClusterIPRange   net.IPNet
    SecondaryServiceClusterIPRange net.IPNet
    
    // APIServerServiceIP 是 PrimaryServiceClusterIPRange 中的第一个有效 IP
    APIServerServiceIP net.IP
    // 定义了服务节点端口范围，用于分配给NodePort类型的服务的端口号
    ServiceNodePortRange utilnet.PortRange
    	
    // 定义了用于代理客户端的证书文件路径和密钥文件路径
    ProxyClientCertFile string
    ProxyClientKeyFile  string
    
    // 是否启用聚合器路由功能，用于将请求路由到聚合器
    EnableAggregatorRouting             bool
    // 聚合器是否拒绝转发重定向请求
    AggregatorRejectForwardingRedirects bool
    
    // 主节点的数量，用于高可用部署中的主节点选举
    MasterCount            int
    // 指定了端点协调器的类型，用于处理集群中服务和端点的变化
    EndpointReconcilerType string
    
    // 定义了用于签署服务账户令牌的密钥文件路径
    ServiceAccountSigningKeyFile     string
    // 定义了服务账户令牌的发行者，用于生成和验证令牌
    ServiceAccountIssuer             serviceaccount.TokenGenerator
    // 定义了服务账户令牌的最大有效期
    ServiceAccountTokenMaxExpiration time.Duration
    // 隐藏的指标在指定版本中是否可见
    ShowHiddenMetricsForVersion string
}

func NewServerRunOptions() *ServerRunOptions {
	s := ServerRunOptions{
		// 创建一些默认值
	}

	return &s
}

// 使用flag绑定参数
func (s *ServerRunOptions) Flags() (fss cliflag.NamedFlagSets) {
	s.GenericServerRunOptions.AddUniversalFlags(fss.FlagSet("generic"))
    // ...
	return fss
}
```

## Run

```go
// Run函数运行指定的APIServer。该函数应该永不退出。
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
    // 为了帮助调试，立即记录版本号
    klog.Infof("Version: %+v", version.Get())
    // 记录Golang的一些设置，用于调试
    klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

    // 创建一个server，并返回错误信息，如果有的话
    server, err := CreateServerChain(completeOptions)
    if err != nil {
        return err
    }

    // 准备运行server，并返回错误信息，如果有的话
    prepared, err := server.PrepareRun()
    if err != nil {
        return err
    }

    // 运行server，返回结果
    return prepared.Run(stopCh)
}
```

## CreateServerChain

```go
// CreateServerChain函数创建通过委托连接的API服务器。
func CreateServerChain(completedOptions completedServerRunOptions) (*aggregatorapiserver.APIAggregator, error) {
    // 创建kubeAPIServerConfig、serviceResolver、pluginInitializer和错误信息err
    kubeAPIServerConfig, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions)
    if err != nil {
    	return nil, err
    }
    // 如果添加了其他API服务器，则应该进行检查
    apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
        serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(kubeAPIServerConfig.ExtraConfig.ProxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig, kubeAPIServerConfig.GenericConfig.TracerProvider))
    if err != nil {
        return nil, err
    }

    // 创建notFoundHandler，并使用它创建apiExtensionsServer
    notFoundHandler := notfoundhandler.New(kubeAPIServerConfig.GenericConfig.Serializer, genericapifilters.NoMuxAndDiscoveryIncompleteKey)
    apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))
    if err != nil {
        return nil, err
    }

    // 创建kubeAPIServer
    kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)
    if err != nil {
        return nil, err
    }

    // 最后创建aggregatorConfig，并使用它创建aggregatorServer
    aggregatorConfig, err := createAggregatorConfig(*kubeAPIServerConfig.GenericConfig, completedOptions.ServerRunOptions, kubeAPIServerConfig.ExtraConfig.VersionedInformers, serviceResolver, kubeAPIServerConfig.ExtraConfig.ProxyTransport, pluginInitializer)
    if err != nil {
        return nil, err
    }
    aggregatorServer, err := createAggregatorServer(aggregatorConfig, kubeAPIServer.GenericAPIServer, apiExtensionsServer.Informers)
    if err != nil {
        // 因为aggregator服务器不创建任何goroutine，所以我们不需要特殊处理innerStopCh
        return nil, err
    }

    return aggregatorServer, nil
}
```

### CreateKubeAPIServerConfig


```go
// CreateKubeAPIServerConfig函数创建运行API服务器所需的所有资源，但不运行它们。
func CreateKubeAPIServerConfig(s completedServerRunOptions) (
    *controlplane.Config,
    aggregatorapiserver.ServiceResolver,
    []admission.PluginInitializer,
    error,
) {
    // 创建代理传输配置
    proxyTransport := CreateProxyTransport()
    // 构建通用配置、版本化Informers、serviceResolver、pluginInitializers、admissionPostStartHook和storageFactory
    genericConfig, versionedInformers, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, err := buildGenericConfig(s.ServerRunOptions, proxyTransport)
    if err != nil {
        return nil, nil, nil, err
    }

    // 设置capabilities
    capabilities.Setup(s.AllowPrivileged, s.MaxConnectionBytesPerSec)

    // 应用度量信息
    s.Metrics.Apply()
    serviceaccount.RegisterMetrics()

    // 创建配置对象
    config := &controlplane.Config{
        GenericConfig: genericConfig,
        ExtraConfig: controlplane.ExtraConfig{
            APIResourceConfigSource: storageFactory.APIResourceConfigSource,
            StorageFactory:          storageFactory,
            EventTTL:                s.EventTTL,
            KubeletClientConfig:     s.KubeletConfig,
            EnableLogsSupport:       s.EnableLogsHandler,
            ProxyTransport:          proxyTransport,

            ServiceIPRange:          s.PrimaryServiceClusterIPRange,
            APIServerServiceIP:      s.APIServerServiceIP,
            SecondaryServiceIPRange: s.SecondaryServiceClusterIPRange,

            APIServerServicePort: 443,

            ServiceNodePortRange:      s.ServiceNodePortRange,
            KubernetesServiceNodePort: s.KubernetesServiceNodePort,

            EndpointReconcilerType: reconcilers.Type(s.EndpointReconcilerType),
            MasterCount:            s.MasterCount,

            ServiceAccountIssuer:        s.ServiceAccountIssuer,
            ServiceAccountMaxExpiration: s.ServiceAccountTokenMaxExpiration,
            ExtendExpiration:            s.Authentication.ServiceAccounts.ExtendExpiration,

            VersionedInformers: versionedInformers,
        },
    }

    // 获取客户端证书的CA提供者
    clientCAProvider, err := s.Authentication.ClientCert.GetClientCAContentProvider()
    if err != nil {
        return nil, nil, nil, err
    }
    config.ExtraConfig.ClusterAuthenticationInfo.ClientCA = clientCAProvider

    // 获取请求头认证配置
    requestHeaderConfig, err := s.Authentication.RequestHeader.ToAuthenticationRequestHeaderConfig()
    if err != nil {
        return nil, nil, nil, err
    }
    if requestHeaderConfig != nil {
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderCA = requestHeaderConfig.CAContentProvider
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderAllowedNames = requestHeaderConfig.AllowedClientNames
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderExtraHeaderPrefixes = requestHeaderConfig.ExtraHeaderPrefixes
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderGroupHeaders = requestHeaderConfig.GroupHeaders
        config.ExtraConfig.ClusterAuthenticationInfo.RequestHeaderUsernameHeaders = requestHeaderConfig.UsernameHeaders
    }

    // 添加admissionPostStartHook到GenericConfig的PostStartHooks中
    if err := config.GenericConfig.AddPostStartHook("start-kube-apiserver-admission-initializer", admissionPostStartHook); err != nil {
        return nil, nil, nil, err
    }

    if config.GenericConfig.EgressSelector != nil {
		// 使用config.GenericConfig.EgressSelector查找用于连接到kubelet的拨号器
		config.ExtraConfig.KubeletClientConfig.Lookup = config.GenericConfig.EgressSelector.Lookup

		// 使用config.GenericConfig.EgressSelector查找作为"proxy"子资源使用的传输
		networkContext := egressselector.Cluster.AsNetworkContext()
		dialer, err := config.GenericConfig.EgressSelector.Lookup(networkContext)
		if err != nil {
			return nil, nil, nil, err
		}
		c := proxyTransport.Clone()
		c.DialContext = dialer
		config.ExtraConfig.ProxyTransport = c
	}

	// 加载公钥
	var pubKeys []interface{}
	for _, f := range s.Authentication.ServiceAccounts.KeyFiles {
		keys, err := keyutil.PublicKeysFromFile(f)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse key file %q: %v", f, err)
		}
		pubKeys = append(pubKeys, keys...)
	}
	// 通过ExtraConfig传递所需的元数据
	config.ExtraConfig.ServiceAccountIssuerURL = s.Authentication.ServiceAccounts.Issuers[0]
	config.ExtraConfig.ServiceAccountJWKSURI = s.Authentication.ServiceAccounts.JWKSURI
	config.ExtraConfig.ServiceAccountPublicKeys = pubKeys

	return config, serviceResolver, pluginInitializers, nil
}
```

```GO
// ServiceResolver是一个根据服务获取URL的解析器接口。
type ServiceResolver interface {
	ResolveEndpoint(namespace, name string, port int32) (*url.URL, error)
}

// PluginInitializer用于初始化入场插件之间共享的资源。
// 初始化后，需要单独设置这些资源。
type PluginInitializer interface {
	Initialize(plugin Interface)
}

// Config定义了主控节点的配置。
type Config struct {
    GenericConfig *genericapiserver.Config
    ExtraConfig ExtraConfig
}

// Config是用于配置GenericAPIServer的结构体。
// 其成员按照大致重要性的顺序进行排序。
type Config struct {
    // SecureServing用于提供HTTPS服务
    SecureServing *SecureServingInfo
	// Authentication是用于认证的配置
    Authentication AuthenticationInfo

    // Authorization是用于授权的配置
    Authorization AuthorizationInfo

    // LoopbackClientConfig是一个用于与API服务器建立特权环回连接的配置。
    // 这对于GenericAPIServer上的PostStartHooks的正确功能是必需的。
    // TODO：尽快将其移动到SecureServing（WithLoopback）中，一旦不再支持不安全的服务。
    LoopbackClientConfig *restclient.Config

    // EgressSelector根据在启动时读取的EgressSelectorConfiguration提供的信息，提供查找机制以进行外部连接。
    EgressSelector *egressselector.EgressSelector

    // RuleResolver用于获取适用于给定用户和命名空间的规则列表。
    RuleResolver authorizer.RuleResolver
    // AdmissionControl用于对给定的请求（包括内容）进行深入检查，以设置值并确定是否允许该请求。
    AdmissionControl admission.Interface
    CorsAllowedOriginList []string
    HSTSDirectives        []string
    // FlowControl（如果非nil）将优先级和公平性应用于请求处理
    FlowControl utilflowcontrol.Interface

    EnableIndex     bool
    EnableProfiling bool
    DebugSocketPath string
    EnableDiscovery bool

    // 需要启用通用分析
    EnableContentionProfiling bool
    EnableMetrics             bool

    DisabledPostStartHooks sets.String
    // 此映射中的值会被忽略。
    PostStartHooks map[string]PostStartHookConfigEntry

    // 如果非nil，Version将启用/version端点。
    Version *version.Info
    // AuditBackend用于发送审计事件。
    AuditBackend audit.Backend
    // AuditPolicyRuleEvaluator用于决定是否以及如何记录请求的审计日志。
    AuditPolicyRuleEvaluator audit.PolicyRuleEvaluator
    // ExternalAddress是用于外部（公共互联网）面向URL（例如Swagger）的主机名。
    // 将默认值设置为基于SecureServing信息和可用的IPv4地址的值。
    ExternalAddress string

    // TracerProvider可以提供一个跟踪器，用于记录分布式跟踪的跨度。
    TracerProvider tracing.TracerProvider

    //===========================================================================
    // 以下字段可能不太需要更改
    //===========================================================================

    // BuildHandlerChainFunc允许您通过装饰apiHandler来构建自定义处理程序链。
    BuildHandlerChainFunc func(apiHandler http.Handler, c *Config) (secure http.Handler)
    // NonLongRunningRequestWaitGroup允许您在服务器关闭时等待与非长时间运行请求相关的所有处理程序完成。
    NonLongRunningRequestWaitGroup *utilwaitgroup.SafeWaitGroup
    // WatchRequestWaitGroup允许我们在服务器关闭时等待与活动监视请求相关的所有处理程序完成。
    WatchRequestWaitGroup *utilwaitgroup.RateLimitedSafeWaitGroup
    // DiscoveryAddresses用于构建传递给discovery的IP地址。如果为nil，则始终报告ExternalAddress。
    DiscoveryAddresses discovery.Addresses
    // 默认的健康检查集合。可以通过AddHealthChecks动态添加更多。
    HealthzChecks []healthz.HealthChecker
	// 默认的livez检查集合。可以通过AddHealthChecks动态添加更多。
    LivezChecks []healthz.HealthChecker
    // 默认的readyz-only检查集合。可以通过AddReadyzChecks动态添加更多。
    ReadyzChecks []healthz.HealthChecker
    // LegacyAPIGroupPrefixes用于设置授权和验证请求的URL解析。新的API服务器通常根本没有传统组。
    LegacyAPIGroupPrefixes sets.String
    // RequestInfoResolver用于根据请求URL分配属性（用于admission和authorization）。
    // 像kubelets这样的用例可能需要自定义此功能。
    RequestInfoResolver apirequest.RequestInfoResolver
    // Serializer是必需的，并提供序列化和转换对象的接口。
    // 默认值（api.Codecs）通常可以正常工作。
    Serializer runtime.NegotiatedSerializer
    // OpenAPIConfig将用于生成OpenAPI规范。默认为nil。使用DefaultOpenAPIConfig获取“工作”默认值。
    OpenAPIConfig *openapicommon.Config
    // OpenAPIV3Config将用于生成OpenAPI V3规范。默认为nil。使用DefaultOpenAPIV3Config获取“工作”默认值。
    OpenAPIV3Config *openapicommon.Config
    // SkipOpenAPIInstallation如果设置为true，则避免安装OpenAPI处理程序。
    SkipOpenAPIInstallation bool
    // RESTOptionsGetter用于通过通用注册表构造RESTStorage类型。
    RESTOptionsGetter genericregistry.RESTOptionsGetter
    // 如果指定，除符合LongRunningFunc谓词的请求外，所有请求都将在此持续时间后超时。
    // 0表示没有限制。
    RequestTimeout time.Duration
    // 如果指定，诸如watch之类的长时间运行请求将分配一个在此值和两倍此值之间的随机超时时间。
    // 请注意，请求处理程序需要忽略或遵守此超时时间。以秒为单位。
    MinRequestTimeout int
    // 这表示apiserver完成启动序列并变为健康状态所需的最长时间。
    // 从apiserver的启动时间开始计算，直到经过此时间为止，/livez将假设未完成的post-start hook将成功完成，并因此返回true。
    LivezGracePeriod time.Duration
    // ShutdownDelayDuration允许阻塞关闭一段时间，例如直到指向此API服务器的端点在所有节点上收敛。
    // 在此期间，API服务器将继续提供服务，/healthz将返回200，但/readyz将返回失败。
    ShutdownDelayDuration time.Duration
    // MaxRequestBodyBytes是将在写请求中接受和解码的请求大小限制。
    // 0表示没有限制。
    MaxRequestBodyBytes int64
    // MaxRequestsInFlight是非长时间运行请求的最大并行数量。
    // 每个进一步的请求都必须等待。仅适用于非突变请求。
    MaxRequestsInFlight int
    // MaxMutatingRequestsInFlight是并行突变请求的最大数量。
    // 每个进一步的请求都必须等待。
    MaxMutatingRequestsInFlight int
     // LongRunningFunc是一个谓词，对于长时间运行的HTTP请求的路径为true。
    LongRunningFunc apirequest.LongRunningRequestCheck
   
    GoawayChance float64
    // GoawayChance是发送GOAWAY给HTTP/2客户端的概率。
    // 当客户端收到GOAWAY时，正在处理的请求不受影响，并且新请求将使用新的TCP连接触发负载平衡到其他服务器。
    // 默认值为0，表示永不发送GOAWAY。最大值为0.02，以防止破坏apiserver。

    MergedResourceConfig *serverstore.ResourceConfig
    // MergedResourceConfig指示哪个groupVersion启用，以及其资源启用/禁用的信息。
    // 这由genericapiserver的defaultAPIResourceConfig组成，并从标志解析的那些组合而成。
    // 如果在标志中未指定任何内容，则genericapiserver将仅启用defaultAPIResourceConfig。

    lifecycleSignals lifecycleSignals
    // lifecycleSignals提供对apiserver生命周期中发生的各种信号的访问。
    // 它有意标记为私有，因为它不应被覆盖。

    StorageObjectCountTracker flowcontrolrequest.StorageObjectCountTracker
    // StorageObjectCountTracker用于跟踪存储中每个资源的对象总数，
    // 以便我们可以估计传入请求的宽度。

    ShutdownSendRetryAfter bool
    // ShutdownSendRetryAfter规定何时在apiserver的优雅终止期间启动HTTP Server的关闭。
    // 如果为true，我们等待正在进行的非长时间运行的请求完成，然后启动HTTP Server的关闭。
    // 如果为false，我们在ShutdownDelayDuration经过后启动HTTP Server的关闭。
    // 如果启用，则在ShutdownDelayDuration经过后，任何传入请求都将以429状态码拒绝并返回'Retry-After'响应。

    //===========================================================================
    // 下面的值是待删除的目标
    //===========================================================================

    PublicAddress net.IP
    // PublicAddress是集群成员（kubelet、kube-proxy、服务等）可以访问GenericAPIServer的IP地址。
    // 如果为nil或0.0.0.0，则使用主机的默认接口。

    EquivalentResourceRegistry runtime.EquivalentResourceRegistry
    // EquivalentResourceRegistry提供与给定资源等效的资源信息，
    // 以及与给定资源关联的kind。随着资源的安装，它们在此处注册。
    
    APIServerID string
   	// APIServerID是此API服务器的ID
    
    // StorageVersionManager持有此服务器安装的API资源的存储版本。
    StorageVersionManager storageversion.Manager

    // Version如果非空，则启用/version端点。
    Version *version.Info

    // lifecycleSignals提供对API服务器生命周期中发生的各种信号的访问。
    lifecycleSignals lifecycleSignals

    // destroyFns包含在关闭时应调用以清理资源的函数列表。
    destroyFns []func()

    // muxAndDiscoveryCompleteSignals保存指示所有已知HTTP路径已注册的信号。
    // 它主要用于避免在资源实际存在但我们未安装到处理程序的路径时返回404响应。
    // 它暴露出来以更轻松地组合各个服务器。
    // 此字段的主要使用者是WithMuxCompleteProtection过滤器和NotFoundHandler。
    muxAndDiscoveryCompleteSignals map[string]<-chan struct{}

    // ShutdownSendRetryAfter决定在API服务器的优雅终止期间何时启动HTTP服务器的关闭。
    // 如果为true，则等待非长时间运行的请求完成后再启动HTTP服务器的关闭。
    // 如果为false，则在ShutdownDelayDuration经过后立即启动HTTP服务器的关闭。
    // 如果启用，在ShutdownDelayDuration经过后，任何传入的请求都将以429状态码和'Retry-After'响应被拒绝。
    ShutdownSendRetryAfter bool

    // ShutdownWatchTerminationGracePeriod如果设置为正值，则是API服务器等待所有活动的观察请求完成的最大持续时间。
    // 一旦此优雅期限结束，API服务器将不再等待任何活动的观察请求完成，它将继续执行优雅服务器关闭过程的下一步。
    // 如果设置为正值，API服务器将跟踪正在进行的观察请求的数量，并在关闭期间等待最长指定的持续时间，并允许这些活动的观察请求在生效的速率限制下完成。
    // 默认值为零，这意味着API服务器不会跟踪活动的观察请求并且不会等待它们完成，这保持了向后兼容性。
    // 此优雅期限与其他优雅期限无关，并且不受其他任何优雅期限的覆盖。
    ShutdownWatchTerminationGracePeriod time.Duration
}

// ExtraConfig定义了主控节点的额外配置信息
type ExtraConfig struct {
	ClusterAuthenticationInfo clusterauthenticationtrust.ClusterAuthenticationInfo // 集群认证信息
    APIResourceConfigSource  serverstorage.APIResourceConfigSource // API资源配置源
    StorageFactory           serverstorage.StorageFactory          // 存储工厂
    EndpointReconcilerConfig EndpointReconcilerConfig             // 终结点调和器配置
    EventTTL                 time.Duration                        // 事件的生存时间
    KubeletClientConfig      kubeletclient.KubeletClientConfig     // Kubelet客户端配置

    EnableLogsSupport bool              // 是否启用日志支持
    ProxyTransport    *http.Transport   // 代理传输配置

    // 用于构建发现中使用的IP地址的值
    // 分配给类型为ClusterIP或更大的服务的IP范围
    ServiceIPRange net.IPNet // 服务IP范围
    // 用于GenericAPIServer服务的IP地址（必须在ServiceIPRange内）
    APIServerServiceIP net.IP // GenericAPIServer服务的IP地址

    // 双栈服务，该范围表示服务IP的备用IP范围
    // 必须与主要的（ServiceIPRange）的地址族不同
    SecondaryServiceIPRange net.IPNet // 备用服务IP范围
    // 用于GenericAPIServer服务的备用IP地址（必须在SecondaryServiceIPRange内）
    SecondaryAPIServerServiceIP net.IP // GenericAPIServer服务的备用IP地址

    // apiserver服务的端口。
    APIServerServicePort int // apiserver服务的端口

    // TODO，可能可以将服务相关的项目分组到一个子结构中，以便更容易配置
    // API server项目和“Extra*”字段可能很好地配合在一起。

    // 分配给类型为NodePort或更大的服务的端口范围
    ServiceNodePortRange utilnet.PortRange // 服务NodePort范围
    // 如果非零，"kubernetes"服务将使用此端口作为NodePort。
    KubernetesServiceNodePort int // kubernetes服务的NodePort端口

    // 运行的主控节点数；所有主控节点必须以相同的值启动。 （未经测试的数字> 1。）
    MasterCount int // 主控节点数

    // MasterEndpointReconcileTTL设置每个主控节点记录的终结点记录的生存时间（以秒为单位）。
    // 终结点将以每个节点设置的2/3间隔进行检查，并且如果未设置此值，则该值默认为15秒。
    // 在非常大的集群中，可以增加此值以减少主控节点终结点记录过期（由于etcd服务器上的其他负载）并导致主控节点在kubernetes服务记录中出现和消失的可能性。
    // 不建议将此值设置为小于15秒。
    MasterEndpointReconcileTTL time.Duration // 主控节点终结点记录的生存时间

    EndpointReconcilerType reconcilers.Type // 选择要使用的调和器类型

    ServiceAccountIssuer serviceaccount.TokenGenerator // ServiceAccount签发者
    ServiceAccountMaxExpiration time.Duration // ServiceAccount的最大过期时间
    ExtendExpiration bool // 是否延长过期时间

    // ServiceAccountIssuerDiscovery
    ServiceAccountIssuerURL string // ServiceAccount签发者的URL
    ServiceAccountJWKSURI string // ServiceAccount的JWKS URI
    ServiceAccountPublicKeys []interface{} // ServiceAccount的公钥

    VersionedInformers informers.SharedInformerFactory // 版本化Informers共享的工厂

    // RepairServicesInterval用于修复循环的时间间隔
    // 用于修复Services NodePort和ClusterIP资源
    RepairServicesInterval time.Duration // 修复服务的时间间隔
}
```

### NewDefaultAuthenticationInfoResolverWrapper

```go
// NewDefaultAuthenticationInfoResolverWrapper 构建默认的身份验证解析器包装器
func NewDefaultAuthenticationInfoResolverWrapper(
	proxyTransport *http.Transport,
	egressSelector *egressselector.EgressSelector,
	kubeapiserverClientConfig *rest.Config,
	tp trace.TracerProvider) AuthenticationInfoResolverWrapper {

	// webhookAuthResolverWrapper 是一个函数，接受一个 AuthenticationInfoResolver 参数并返回一个 AuthenticationInfoResolver
	webhookAuthResolverWrapper := func(delegate AuthenticationInfoResolver) AuthenticationInfoResolver {
		return &AuthenticationInfoResolverDelegator{
			ClientConfigForFunc: func(hostPort string) (*rest.Config, error) {
				// 如果 hostPort 是 "kubernetes.default.svc:443"，则返回 kubeapiserverClientConfig 和 nil
				if hostPort == "kubernetes.default.svc:443" {
					return kubeapiserverClientConfig, nil
				}
				// 否则调用 delegate 的 ClientConfigFor 方法获取 rest.Config
				ret, err := delegate.ClientConfigFor(hostPort)
				if err != nil {
					return nil, err
				}
				// 如果启用了 features.APIServerTracing 特性，则在返回的 rest.Config 上执行 ret.Wrap(tracing.WrapperFor(tp))
				if feature.DefaultFeatureGate.Enabled(features.APIServerTracing) {
					ret.Wrap(tracing.WrapperFor(tp))
				}

				// 如果 egressSelector 不为 nil，则执行以下代码块
				if egressSelector != nil {
					// 将 egressselector.ControlPlane 转换为 NetworkContext，并存储在 networkContext 变量中
					networkContext := egressselector.ControlPlane.AsNetworkContext()
					var egressDialer utilnet.DialFunc
					// 通过 egressSelector.Lookup 查找对应的 egressDialer
					egressDialer, err = egressSelector.Lookup(networkContext)

					if err != nil {
						return nil, err
					}

					// 将返回的 egressDialer 赋值给 ret.Dial
					ret.Dial = egressDialer
				}
				return ret, nil
			},
			ClientConfigForServiceFunc: func(serviceName, serviceNamespace string, servicePort int) (*rest.Config, error) {
				// 如果 serviceName 是 "kubernetes"，serviceNamespace 是 corev1.NamespaceDefault，servicePort 是 443，则返回 kubeapiserverClientConfig 和 nil
				if serviceName == "kubernetes" && serviceNamespace == corev1.NamespaceDefault && servicePort == 443 {
					return kubeapiserverClientConfig, nil
				}
				// 否则调用 delegate 的 ClientConfigForService 方法获取 rest.Config
				ret, err := delegate.ClientConfigForService(serviceName, serviceNamespace, servicePort)
				if err != nil {
					return nil, err
				}
				// 如果启用了 features.APIServerTracing 特性，则在返回的 rest.Config 上执行 ret.Wrap(tracing.WrapperFor(tp))
				if feature.DefaultFeatureGate.Enabled(features.APIServerTracing) {
					ret.Wrap(tracing.WrapperFor(tp))
				}

				// 如果 egressSelector 不为 nil，则执行以下代码块
				if egressSelector != nil {
					// 将 egressselector.Cluster 转换为 NetworkContext，并存储在 networkContext 变量中
					networkContext := egressselector.Cluster.AsNetworkContext()
					var egressDialer utilnet.DialFunc
                    // 通过 egressSelector.Lookup 查找对应的 egressDialer
					egressDialer, err = egressSelector.Lookup(networkContext)
					if err != nil {
						return nil, err
					}
					// 将返回的 egressDialer 赋值给 ret.Dial
					ret.Dial = egressDialer
				} else if proxyTransport != nil && proxyTransport.DialContext != nil {
                    // 如果 proxyTransport 不为 nil，并且 proxyTransport.DialContext 不为 nil，则将 proxyTransport.DialContext 赋值给 ret.Dial
					ret.Dial = proxyTransport.DialContext
				}
				return ret, nil
			},
		}
	}
    // 返回 webhookAuthResolverWrapper 函数
	return webhookAuthResolverWrapper
}
```

### createAPIExtensionsConfig

```go
func createAPIExtensionsConfig(
    kubeAPIServerConfig genericapiserver.Config, // kube-apiserver的通用配置
    externalInformers kubeexternalinformers.SharedInformerFactory, // 外部Informers的共享工厂
    pluginInitializers []admission.PluginInitializer, // 插件初始化器列表
    commandOptions *options.ServerRunOptions, // 服务器运行选项
    masterCount int, // 主控节点数
    serviceResolver webhook.ServiceResolver, // webhook服务解析器
    authResolverWrapper webhook.AuthenticationInfoResolverWrapper, // webhook身份验证信息解析器包装器
) (*apiextensionsapiserver.Config, error) {
    // 创建通用配置的浅层副本，以便进行一些调整
    // 大部分配置实际上保持不变。我们只需要修改与apiextensions的特定内容相关的一些项目
    genericConfig := kubeAPIServerConfig
    genericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}
    genericConfig.RESTOptionsGetter = nil
	// 复制etcd选项，以免改变原始值。
    // 我们假设etcd选项已经完成。避免对StorageConfig之外的任何内容进行更改，以免在应用选项时出现意外行为。
    etcdOptions := *commandOptions.Etcd
    etcdOptions.StorageConfig.Paging = utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking)
    // 这是真正的可解码级别。
    etcdOptions.StorageConfig.Codec = apiextensionsapiserver.Codecs.LegacyCodec(v1beta1.SchemeGroupVersion, v1.SchemeGroupVersion)
    // 对于存储，优先选择更紧凑的序列化（v1beta1），直到 https://issue.k8s.io/82292 对那些v1序列化太大但v1beta1序列化可以存储的对象进行解决
    etcdOptions.StorageConfig.EncodeVersioner = runtime.NewMultiGroupVersioner(v1beta1.SchemeGroupVersion, schema.GroupKind{Group: v1beta1.GroupName})
    etcdOptions.SkipHealthEndpoints = true // 避免重复连接健康检查
    if err := etcdOptions.ApplyTo(&genericConfig); err != nil {
        return nil, err
    }

    // 使用apiextensions的默认值和注册表覆盖MergedResourceConfig
    if err := commandOptions.APIEnablement.ApplyTo(
        &genericConfig,
        apiextensionsapiserver.DefaultAPIResourceConfigSource(),
        apiextensionsapiserver.Scheme); err != nil {
        return nil, err
    }
    crdRESTOptionsGetter, err := apiextensionsoptions.NewCRDRESTOptionsGetter(etcdOptions)
    if err != nil {
        return nil, err
    }
    apiextensionsConfig := &apiextensionsapiserver.Config{
        GenericConfig: &genericapiserver.RecommendedConfig{
            Config:                genericConfig,
            SharedInformerFactory: externalInformers,
        },
        ExtraConfig: apiextensionsapiserver.ExtraConfig{
            CRDRESTOptionsGetter: crdRESTOptionsGetter,
            MasterCount:          masterCount,
            AuthResolverWrapper:  authResolverWrapper,
            ServiceResolver:      serviceResolver,
        },
    }

   // 需要清除poststarthooks，以免将它们多次添加到所有服务器（这会导致失败）
    apiextensionsConfig.GenericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}

    return apiextensionsConfig, nil
}
```

```go
type Config struct {
    GenericConfig *genericapiserver.RecommendedConfig // 通用配置
    ExtraConfig ExtraConfig // 额外配置
}

type RecommendedConfig struct {
	Config
    // SharedInformerFactory为Kubernetes资源提供共享的Informers。该值由RecommendedOptions.CoreAPI.ApplyTo在RecommendedOptions.ApplyTo中设置。
    // 默认情况下，它使用in-cluster客户端配置，或者使用kubeconfig命令行标志给定的kubeconfig。
    SharedInformerFactory informers.SharedInformerFactory

    // ClientConfig保存Kubernetes客户端配置。
    // 该值由RecommendedOptions.CoreAPI.ApplyTo在RecommendedOptions.ApplyTo中设置。
    // 默认情况下，使用in-cluster客户端配置。
    ClientConfig *restclient.Config
}
```

#### DefaultAPIResourceConfigSource

```go
func DefaultAPIResourceConfigSource() *serverstorage.ResourceConfig {
ret := serverstorage.NewResourceConfig()
    // 注意：在这里列出的GroupVersions将默认启用。不要在列表中放入alpha版本。
    ret.EnableVersions(
        v1beta1.SchemeGroupVersion,
        v1.SchemeGroupVersion,
    )
}
```

#### NewCRDRESTOptionsGetter

```go
// NewCRDRESTOptionsGetter为CustomResources创建一个RESTOptionsGetter。
// 这在etcd选项的副本上工作，以免改变原始值。
// 我们假设输入的etcd选项已经完成。
// 避免对StorageConfig之外的任何内容进行更改，以免在应用选项时出现意外行为。
func NewCRDRESTOptionsGetter(etcdOptions genericoptions.EtcdOptions) (genericregistry.RESTOptionsGetter, error) {
    etcdOptions.StorageConfig.Codec = unstructured.UnstructuredJSONScheme
    etcdOptions.WatchCacheSizes = nil // 这个控制对于自定义资源没有提供
    etcdOptions.SkipHealthEndpoints = true // 避免重复连接健康检查
	// 创建用于变异etcdOptions的通用apiserver配置
    c := genericapiserver.Config{}
    if err := etcdOptions.ApplyTo(&c); err != nil {
        return nil, err
    }
    restOptionsGetter := c.RESTOptionsGetter
    if restOptionsGetter == nil {
        return nil, fmt.Errorf("server.Config的RESTOptionsGetter不应为nil")
    }
    // 检查确保没有设置其他字段
    c.RESTOptionsGetter = nil
    if !reflect.DeepEqual(c, genericapiserver.Config{}) {
        return nil, fmt.Errorf("server.Config中只应该变异RESTOptionsGetter")
    }
    return restOptionsGetter, nil
}
```

### notfoundhandler.New

```go
// New函数返回一个HTTP处理程序，应在委托链的最后执行。
// 它检查请求是否在服务器安装了所有已知的HTTP路径之前发出。
// 如果是这种情况，它返回503响应；否则返回404。
//
// 注意，我们不希望在readyz路径上添加额外的检查，因为这可能阻止修复损坏的集群。
// 此特定处理程序旨在在路径和处理程序完全初始化之前“保护”到达的请求。
func New(serializer runtime.NegotiatedSerializer, isMuxAndDiscoveryCompleteFn func(ctx context.Context) bool) *Handler {
	return &Handler{serializer: serializer, isMuxAndDiscoveryCompleteFn: isMuxAndDiscoveryCompleteFn}
}

type Handler struct {
    serializer runtime.NegotiatedSerializer
    isMuxAndDiscoveryCompleteFn func(ctx context.Context) bool
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !h.isMuxAndDiscoveryCompleteFn(req.Context()) {
		errMsg := "the request has been made before all known HTTP paths have been installed, please try again"
		err := apierrors.NewServiceUnavailable(errMsg)
		if err.ErrStatus.Details == nil {
			err.ErrStatus.Details = &metav1.StatusDetails{}
		}
		err.ErrStatus.Details.RetryAfterSeconds = int32(5)

		gv := schema.GroupVersion{Group: "unknown", Version: "unknown"}
		requestInfo, ok := apirequest.RequestInfoFrom(req.Context())
		if ok {
			gv.Group = requestInfo.APIGroup
			gv.Version = requestInfo.APIVersion
		}
		responsewriters.ErrorNegotiated(err, h.serializer, gv, rw, req)
		return
	}
	http.NotFound(rw, req)
}
```

### createAPIExtensionsServer

```go
func createAPIExtensionsServer(apiextensionsConfig *apiextensionsapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget) (*apiextensionsapiserver.CustomResourceDefinitions, error) {
	return apiextensionsConfig.Complete().New(delegateAPIServer)
}

func (cfg *Config) Complete() CompletedConfig {
    // ... 设置一些 默认config
	return CompletedConfig{&c}
}

// New从给定的配置中返回CustomResourceDefinitions的新实例。
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
	// 从配置中创建GenericServer实例
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	// 创建一个通道hasCRDInformerSyncedSignal，当CRD informer完全同步时关闭该通道。
	// 这确保在服务器尚未安装所有已知HTTP路径时，对潜在自定义资源端点的请求会得到503错误而不是404错误。
	hasCRDInformerSyncedSignal := make(chan struct{})
	if err := genericServer.RegisterMuxAndDiscoveryCompleteSignal("CRDInformerHasNotSynced", hasCRDInformerSyncedSignal); err != nil {
		return nil, err
	}

	// 创建CustomResourceDefinitions实例
	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}

	// 获取API资源配置和API组信息
	apiResourceConfig := c.GenericConfig.MergedResourceConfig
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(apiextensions.GroupName, Scheme, metav1.ParameterCodec, Codecs)
	storage := map[string]rest.Storage{}
	
	// 处理customresourcedefinitions
	if resource := "customresourcedefinitions"; apiResourceConfig.ResourceEnabled(v1.SchemeGroupVersion.WithResource(resource)) {
		// 创建customResourceDefinitionStorage
		customResourceDefinitionStorage, err := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage[resource] = customResourceDefinitionStorage
		storage[resource+"/status"] = customresourcedefinition.NewStatusREST(Scheme, customResourceDefinitionStorage)
	}
	if len(storage) > 0 {
		apiGroupInfo.VersionedResourcesStorageMap[v1.SchemeGroupVersion.Version] = storage
	}

	// 安装API组
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	// 创建CRD客户端
	crdClient, err := clientset.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Informers = externalinformers.NewSharedInformerFactory(crdClient, 5*time.Minute)

	// 设置委托处理程序
	delegateHandler := delegationTarget.UnprotectedHandler()
	if delegateHandler == nil {
		delegateHandler = http.NotFoundHandler()
	}

	// 创建版本和组的发现处理程序
	versionDiscoveryHandler := &versionDiscoveryHandler{
		discovery: map[schema.GroupVersion]*discovery.APIVersionHandler{},
		delegate:  delegateHandler,
	}
	groupDiscoveryHandler := &groupDiscoveryHandler{
		discovery: map[string]*discovery.APIGroupHandler{},
		delegate:  delegateHandler,
	}

	// 创建establishingController和crdHandler等
	establishingController := establish.NewEstablishingController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
    // 创建crdHandler
    crdHandler, err := NewCustomResourceDefinitionHandler(
        versionDiscoveryHandler,
        groupDiscoveryHandler,
        s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
        delegateHandler,
        c.ExtraConfig.CRDRESTOptionsGetter,
        c.GenericConfig.AdmissionControl,
        establishingController,
        c.ExtraConfig.ServiceResolver,
        c.ExtraConfig.AuthResolverWrapper,
        c.ExtraConfig.MasterCount,
        s.GenericAPIServer.Authorizer,
        c.GenericConfig.RequestTimeout,
        time.Duration(c.GenericConfig.MinRequestTimeout)*time.Second,
        apiGroupInfo.StaticOpenAPISpec,
        c.GenericConfig.MaxRequestBodyBytes,
    )
    if err != nil {
        return nil, err
    }

    // 将crdHandler注册到GenericAPIServer的处理程序中
    s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", crdHandler)
    s.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/apis/", crdHandler)
    s.GenericAPIServer.RegisterDestroyFunc(crdHandler.destroy)

    // 创建aggregatedDiscoveryManager
    aggregatedDiscoveryManager := genericServer.AggregatedDiscoveryGroupManager
    if aggregatedDiscoveryManager != nil {
        aggregatedDiscoveryManager = aggregatedDiscoveryManager.WithSource(aggregated.CRDSource)
    }

    // 创建discoveryController、namingController、nonStructuralSchemaController、apiApprovalController和finalizingController
    discoveryController := NewDiscoveryController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), versionDiscoveryHandler, groupDiscoveryHandler, aggregatedDiscoveryManager)
    namingController := status.NewNamingConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
    nonStructuralSchemaController := nonstructuralschema.NewConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
    apiApprovalController := apiapproval.NewKubernetesAPIApprovalPolicyConformantConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
    finalizingController := finalizer.NewCRDFinalizer(
        s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
        crdClient.ApiextensionsV1(),
        crdHandler,
    )

    // 添加PostStartHook，用于在API server启动后执行一些操作
    s.GenericAPIServer.AddPostStartHookOrDie("start-apiextensions-informers", func(context genericapiserver.PostStartHookContext) error {
        s.Informers.Start(context.StopCh)
        return nil
    })
    s.GenericAPIServer.AddPostStartHookOrDie("start-apiextensions-controllers", func(context genericapiserver.PostStartHookContext) error {
        // OpenAPIVersionedService和StaticOpenAPISpec是在generic apiserver的PrepareRun()中设置的。
        // 它们一起在通用apiserver上为/openapi/v2端点提供服务。通用apiserver可以选择通过具有空openAPIConfig来禁用OpenAPI，
        // 因此OpenAPIVersionedService和StaticOpenAPISpec都为空。在这种情况下，我们不运行CRD OpenAPI控制器。
        if s.GenericAPIServer.StaticOpenAPISpec != nil {
            if s.GenericAPIServer.OpenAPIVersionedService != nil {
                openapiController := openapicontroller.NewController(s.Informers.Apiextensions().V1().CustomResourceDefinitions())
                go openapiController.Run(s.GenericAPIServer.StaticOpenAPISpec, s.GenericAPIServer.OpenAPIVersionedService, context.StopCh)
}
            if s.GenericAPIServer.OpenAPIV3VersionedService != nil && utilfeature.DefaultFeatureGate.Enabled(features.OpenAPIV3) {
                openapiv3Controller := openapiv3controller.NewController(s.Informers.Apiextensions().V1().CustomResourceDefinitions())
                go openapiv3Controller.Run(s.GenericAPIServer.OpenAPIV3VersionedService, context.StopCh)
            }
        }
        
        go namingController.Run(context.StopCh)
        go establishingController.Run(context.StopCh)
        go nonStructuralSchemaController.Run(5, context.StopCh)
        go apiApprovalController.Run(5, context.StopCh)
        go finalizingController.Run(5, context.StopCh)

        discoverySyncedCh := make(chan struct{})
        go discoveryController.Run(context.StopCh, discoverySyncedCh)
        select {
        case <-context.StopCh:
        case <-discoverySyncedCh:
        }

        return nil
    })
    
	// 添加PostStartHook，用于在CRD Informer同步完成后发送信号
    s.GenericAPIServer.AddPostStartHookOrDie("crd-informer-synced", func(context genericapiserver.PostStartHookContext) error {
        return wait.PollImmediateUntil(100*time.Millisecond, func() (bool, error) {
            // 等待CRD Informer完成同步
            if s.Informers.Apiextensions().V1().CustomResourceDefinitions().Informer().HasSynced() {
                close(hasCRDInformerSyncedSignal)
                return true, nil
            }
            return false, nil
        }, context.StopCh)
    })

    return s, nil
}
```

#### c.GenericConfig.New

```go
// New函数创建一个新的服务器，将处理链与传入的服务器逻辑上结合在一起。
// name用于区分日志记录。特别是处理链在开始委托时可能很复杂。
// delegationTarget不能为nil。
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
	// 检查参数是否有效
    if c.Serializer == nil {
    	return nil, fmt.Errorf("Genericapiserver.New() called with config.Serializer == nil")
    }
    if c.LoopbackClientConfig == nil {
    	return nil, fmt.Errorf("Genericapiserver.New() called with config.LoopbackClientConfig == nil")
    }
    if c.EquivalentResourceRegistry == nil {
    	return nil, fmt.Errorf("Genericapiserver.New() called with config.EquivalentResourceRegistry == nil")
    }
    // 定义一个handlerChainBuilder函数，用于构建处理器链
    handlerChainBuilder := func(handler http.Handler) http.Handler {
        return c.BuildHandlerChainFunc(handler, c.Config)
    }

    // 创建一个DebugSocket实例
    var debugSocket *routes.DebugSocket
    if c.DebugSocketPath != "" {
        debugSocket = routes.NewDebugSocket(c.DebugSocketPath)
    }

    // 创建一个APIServerHandler实例
    apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())

    // 创建GenericAPIServer实例
    s := &GenericAPIServer{
        discoveryAddresses:             c.DiscoveryAddresses,
        LoopbackClientConfig:           c.LoopbackClientConfig,
        legacyAPIGroupPrefixes:         c.LegacyAPIGroupPrefixes,
        admissionControl:               c.AdmissionControl,
        Serializer:                     c.Serializer,
        AuditBackend:                   c.AuditBackend,
        Authorizer:                     c.Authorization.Authorizer,
        delegationTarget:               delegationTarget,
        EquivalentResourceRegistry:     c.EquivalentResourceRegistry,
        NonLongRunningRequestWaitGroup: c.NonLongRunningRequestWaitGroup,
        WatchRequestWaitGroup:          c.WatchRequestWaitGroup,
        Handler:                        apiServerHandler,
        UnprotectedDebugSocket:         debugSocket,
        listedPathProvider:             apiServerHandler,
        minRequestTimeout:              time.Duration(c.MinRequestTimeout) * time.Second,
        ShutdownTimeout:                c.RequestTimeout,
        ShutdownDelayDuration:          c.ShutdownDelayDuration,
        ShutdownWatchTerminationGracePeriod: c.ShutdownWatchTerminationGracePeriod,
        SecureServingInfo:                   c.SecureServing,
        ExternalAddress:                     c.ExternalAddress,
        openAPIConfig:           c.OpenAPIConfig,
        openAPIV3Config:         c.OpenAPIV3Config,
        skipOpenAPIInstallation: c.SkipOpenAPIInstallation,
        postStartHooks:         map[string]postStartHookEntry{},
        preShutdownHooks:       map[string]preShutdownHookEntry{},
        disabledPostStartHooks: c.DisabledPostStartHooks,
        healthzChecks:          c.HealthzChecks,
        livezChecks:            c.LivezChecks,
        readyzChecks:           c.ReadyzChecks,
        livezGracePeriod:       c.LivezGracePeriod,
        DiscoveryGroupManager:  discovery.NewRootAPIsHandler(c.DiscoveryAddresses, c.Serializer),
        maxRequestBodyBytes:    c.MaxRequestBodyBytes,
        livezClock:             clock.RealClock{},
        lifecycleSignals:      c.lifecycleSignals,
        ShutdownSendRetryAfter: c.ShutdownSendRetryAfter,
        APIServerID: c.APIServerID,
        StorageVersionManager: c.StorageVersionManager,
        Version: c.Version,
        muxAndDiscoveryCompleteSignals: map[string]<-chan struct{}{},
    }

	// 如果启用了AggregatedDiscoveryEndpoint特性，则注册AggregatedDiscoveryGroupManager
    if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
        manager := c.AggregatedDiscoveryGroupManager
        if manager == nil {
            manager = discoveryendpoint.NewResourceManager("apis")
        }
        s.AggregatedDiscoveryGroupManager = manager
        s.AggregatedLegacyDiscoveryGroupManager = discoveryendpoint.NewResourceManager("api")
    }

    // 更新JSONPatchMaxCopyBytes的限制
    for {
        if c.JSONPatchMaxCopyBytes <= 0 {
            break
        }
        existing := atomic.LoadInt64(&jsonpatch.AccumulatedCopySizeLimit)
        if existing > 0 && existing < c.JSONPatchMaxCopyBytes {
            break
        }
        if atomic.CompareAndSwapInt64(&jsonpatch.AccumulatedCopySizeLimit, existing, c.JSONPatchMaxCopyBytes) {
            break
        }
    }

    // 添加委托目标的poststarthooks
    for k, v := range delegationTarget.PostStartHooks() {
        s.postStartHooks[k] = v
    }

    // 添加委托目标的PreShutdownHooks
    for k, v := range delegationTarget.PreShutdownHooks() {
        s.preShutdownHooks[k] = v
    }

    // 添加预配置的poststarthooks
    for name, preconfiguredPostStartHook := range c.PostStartHooks {
        if err := s.AddPostStartHook(name, preconfiguredPostStartHook.hook); err != nil {
            return nil, err
        }
    }

    // 注册委托服务器的mux信号
    for k, v := range delegationTarget.MuxAndDiscoveryCompleteSignals() {
        if err := s.RegisterMuxAndDiscoveryCompleteSignal(k, v); err != nil {
            return nil, err
        }
    }

    // 如果存在SharedInformerFactory，则添加名为generic-apiserver-start-informers的poststarthook
    genericApiServerHookName := "generic-apiserver-start-informers"
    if c.SharedInformerFactory != nil {
        if !s.isPostStartHookRegistered(genericApiServerHookName) {
            err := s.AddPostStartHook(genericApiServerHookName, func(context PostStartHookContext) error {
                c.SharedInformerFactory.Start(context.StopCh)
                return nil
            })
            if err != nil {
                return nil, err
            }
        }
        // 添加ReadyzChecks以确保在Informer同步之后运行
        err := s.AddReadyzChecks(healthz.NewInformerSyncHealthz(c.SharedInformerFactory))
        if err != nil {
            return nil, err
        }
    }

    // 如果存在FlowControl，则添加priority-and-fairness-config-consumer的poststarthook
    const priorityAndFairnessConfigConsumerHookName = "priority-and-fairness-config-consumer"
    if s.isPostStartHookRegistered(priorityAndFairnessConfigConsumerHookName) {
    } else if c.FlowControl != nil {
        err := s.AddPostStartHook(priorityAndFairnessConfigConsumerHookName, func(context PostStartHookContext) error {
            go c.FlowControl.Run(context.StopCh)
            return nil
        })
        if err != nil {
            return nil, err
        }
        // TODO(yue9944882): plumb pre-shutdown-hook for request-management system?
    } else {
        klog.V(3).Infof("Not requested to run hook %s", priorityAndFairnessConfigConsumerHookName)
	}
	
    // 添加PostStartHook以维护Priority-and-Fairness和Max-in-Flight过滤器的水印
    if c.FlowControl != nil {
        const priorityAndFairnessFilterHookName = "priority-and-fairness-filter"
        if !s.isPostStartHookRegistered(priorityAndFairnessFilterHookName) {
            err := s.AddPostStartHook(priorityAndFairnessFilterHookName, func(context PostStartHookContext) error {
                genericfilters.StartPriorityAndFairnessWatermarkMaintenance(context.StopCh)
                return nil
            })
            if err != nil {
                return nil, err
            }
        }
    } else {
        const maxInFlightFilterHookName = "max-in-flight-filter"
        if !s.isPostStartHookRegistered(maxInFlightFilterHookName) {
            err := s.AddPostStartHook(maxInFlightFilterHookName, func(context PostStartHookContext) error {
                genericfilters.StartMaxInFlightWatermarkMaintenance(context.StopCh)
                return nil
            })
            if err != nil {
                return nil, err
            }
        }
    }

    // 添加PostStartHook以维护对象计数追踪器
    if c.StorageObjectCountTracker != nil {
        const storageObjectCountTrackerHookName = "storage-object-count-tracker-hook"
        if !s.isPostStartHookRegistered(storageObjectCountTrackerHookName) {
            if err := s.AddPostStartHook(storageObjectCountTrackerHookName, func(context PostStartHookContext) error {
                go c.StorageObjectCountTracker.RunUntil(context.StopCh)
                return nil
            }); err != nil {
                return nil, err
            }
        }
    }

    // 将委托目标的HealthzChecks添加到GenericAPIServer中
    for _, delegateCheck := range delegationTarget.HealthzChecks() {
        skip := false
        for _, existingCheck := range c.HealthzChecks {
            if existingCheck.Name() == delegateCheck.Name() {
                skip = true
                break
            }
        }
        if skip {
            continue
        }
        s.AddHealthChecks(delegateCheck)
    }

    // 注册销毁函数，用于关闭跟踪器提供程序
    s.RegisterDestroyFunc(func() {
        if err := c.Config.TracerProvider.Shutdown(context.Background()); err != nil {
            klog.Errorf("failed to shut down tracer provider: %v", err)
        }
    })

    // 更新listedPathProvider，将委托目标添加到路径提供者列表中
    s.listedPathProvider = routes.ListedPathProviders{s.listedPathProvider, delegationTarget}

    // 安装API路由
    installAPI(s, c.Config)

    // 如果启用了委托目标的UnprotectedHandler，并且启用了索引功能，则设置NotFoundHandler为IndexLister
    if delegationTarget.UnprotectedHandler() == nil && c.EnableIndex {
        s.Handler.NonGoRestfulMux.NotFoundHandler(routes.IndexLister{
            StatusCode:   http.StatusNotFound,
            PathProvider: s.listedPathProvider,
        })
    }

    return s, nil
}
```

#### InstallAPIGroup

```go
// InstallAPIGroup 在 API 中公开给定的 API 组。
// 此函数中传入的 <apiGroupInfo> 不应在其他地方使用，因为在服务器关闭时底层存储将被销毁。
func (s *GenericAPIServer) InstallAPIGroup(apiGroupInfo *APIGroupInfo) error {
	return s.InstallAPIGroups(apiGroupInfo)
}
```

#### InstallAPIGroups

```go
// InstallAPIGroups 在 API 中公开给定的 API 组。
// 此函数中传入的 <apiGroupInfos> 不应在其他地方使用，因为在服务器关闭时底层存储将被销毁。
func (s *GenericAPIServer) InstallAPIGroups(apiGroupInfos ...*APIGroupInfo) error {
    // 检查 API 组信息的合法性
    for _, apiGroupInfo := range apiGroupInfos {
        // 不要注册空组或空版本。这样做会将 /apis/ 声明为错误实体返回。
        // 在这里捕捉这些错误可以将错误放置得更接近其源头。
        if len(apiGroupInfo.PrioritizedVersions[0].Group) == 0 {
            return fmt.Errorf("cannot register handler with an empty group for %#v", *apiGroupInfo)
        }
        if len(apiGroupInfo.PrioritizedVersions[0].Version) == 0 {
            return fmt.Errorf("cannot register handler with an empty version for %#v", *apiGroupInfo)
        }
    }
    // 获取 API 组的 OpenAPI 模型
    openAPIModels, err := s.getOpenAPIModels(APIGroupPrefix, apiGroupInfos...)
    if err != nil {
        return fmt.Errorf("unable to get openapi models: %v", err)
    }

    // 安装 API 资源
    for _, apiGroupInfo := range apiGroupInfos {
        if err := s.installAPIResources(APIGroupPrefix, apiGroupInfo, openAPIModels); err != nil {
            return fmt.Errorf("unable to install api resources: %v", err)
        }

        // 设置发现
        // 安装版本处理程序。
        // 在 /apis/<groupName> 添加一个处理程序，以枚举此组支持的所有版本。
        apiVersionsForDiscovery := []metav1.GroupVersionForDiscovery{}
        for _, groupVersion := range apiGroupInfo.PrioritizedVersions {
            // 检查配置以确保我们删除没有任何资源的版本
            if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
                continue
            }
            apiVersionsForDiscovery = append(apiVersionsForDiscovery, metav1.GroupVersionForDiscovery{
                GroupVersion: groupVersion.String(),
                Version:      groupVersion.Version,
            })
        }
        preferredVersionForDiscovery := metav1.GroupVersionForDiscovery{
            GroupVersion: apiGroupInfo.PrioritizedVersions[0].String(),
            Version:      apiGroupInfo.PrioritizedVersions[0].Version,
        }
        apiGroup := metav1.APIGroup{
            Name:             apiGroupInfo.PrioritizedVersions[0].Group,
            Versions:         apiVersionsForDiscovery,
            PreferredVersion: preferredVersionForDiscovery,
        }

        // 将 API 组添加到发现中
        s.DiscoveryGroupManager.AddGroup(apiGroup)
        // 向 GoRestful 容器中添加 APIGroupHandler
        s.Handler.GoRestfulContainer.Add(discovery.NewAPIGroupHandler(s.Serializer, apiGroup).WebService())
    }
    return nil
}
```

##### getOpenAPIModels

```go
// getOpenAPIModels 是一个用于获取 OpenAPI 模型的私有方法。
func (s *GenericAPIServer) getOpenAPIModels(apiPrefix string, apiGroupInfos ...*APIGroupInfo) (map[string]*spec.Schema, error) {
    if s.openAPIV3Config == nil {
        //!TODO: 未来的工作应该添加一个要求 OpenAPIV3 配置是必需的的规定。可能需要一些测试代码的重构。
        return nil, nil
    }
    pathsToIgnore := openapiutil.NewTrie(s.openAPIConfig.IgnorePrefixes)
    resourceNames := make([]string, 0)
    for _, apiGroupInfo := range apiGroupInfos {
        groupResources, err := getResourceNamesForGroup(apiPrefix, apiGroupInfo, pathsToIgnore)
        if err != nil {
        	return nil, err
        }
        resourceNames = append(resourceNames, groupResources...)
    }
    // 为这些资源构建 OpenAPI 定义并将其转换为 proto 模型
    openAPISpec, err := openapibuilder3.BuildOpenAPIDefinitionsForResources(s.openAPIV3Config, resourceNames...)
    if err != nil {
        return nil, err
    }
    for _, apiGroupInfo := range apiGroupInfos {
        apiGroupInfo.StaticOpenAPISpec = openAPISpec
    }
    return openAPISpec, nil
}
```

##### installAPIResources

```go
// installAPIResources 是一个私有方法，用于安装支持每个 API 组版本资源的 REST 存储。
func (s *GenericAPIServer) installAPIResources(apiPrefix string, apiGroupInfo *APIGroupInfo, openAPIModels map[string]*spec.Schema) error {
    // 创建 TypeConverter 对象，用于类型转换
    var typeConverter managedfields.TypeConverter

    // 如果存在 OpenAPI 模型，则创建 TypeConverter 对象
    if len(openAPIModels) > 0 {
        var err error
        typeConverter, err = managedfields.NewTypeConverter(openAPIModels, false)
        if err != nil {
            return err
        }
    }

    // 存储资源信息的切片
    var resourceInfos []*storageversion.ResourceInfo

    // 遍历 API 组的优先版本
    for _, groupVersion := range apiGroupInfo.PrioritizedVersions {

        // 如果该版本没有资源，则跳过
        if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
            klog.Warningf("Skipping API %v because it has no resources.", groupVersion)
            continue
        }

        // 获取 API 组版本对象
        apiGroupVersion, err := s.getAPIGroupVersion(apiGroupInfo, groupVersion, apiPrefix)
        if err != nil {
            return err
        }

        // 设置 API 组版本的选项外部版本
        if apiGroupInfo.OptionsExternalVersion != nil {
            apiGroupVersion.OptionsExternalVersion = apiGroupInfo.OptionsExternalVersion
        }

        // 设置 API 组版本的类型转换器和最大请求体大小
        apiGroupVersion.TypeConverter = typeConverter
        apiGroupVersion.MaxRequestBodyBytes = s.maxRequestBodyBytes

        // 安装 REST
        discoveryAPIResources, r, err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer)
        if err != nil {
            return fmt.Errorf("unable to setup API %v: %v", apiGroupInfo, err)
        }
        resourceInfos = append(resourceInfos, r...)

        // 如果启用了聚合发现端点特性
        if utilfeature.DefaultFeatureGate.Enabled(features.AggregatedDiscoveryEndpoint) {
            // 聚合发现只聚合/apis下的资源
            if apiPrefix == APIGroupPrefix {
                s.AggregatedDiscoveryGroupManager.AddGroupVersion(
                    groupVersion.Group,
                    apidiscoveryv2beta1.APIVersionDiscovery{
                        Freshness: apidiscoveryv2beta1.DiscoveryFreshnessCurrent,
                        Version:   groupVersion.Version,
                        Resources: discoveryAPIResources,
                    },
                )
            } else {
                // 对于遗留资源，只有一个组版本，优先级可以默认为0。
                s.AggregatedLegacyDiscoveryGroupManager.AddGroupVersion(
                    groupVersion.Group,
                    apidiscoveryv2beta1.APIVersionDiscovery{
                        Freshness: apidiscoveryv2beta1.DiscoveryFreshnessCurrent,
                        Version:   groupVersion.Version,
                        Resources: discoveryAPIResources,
                    },
                )
            }
        }
    }

    // 注册销毁函数
    s.RegisterDestroyFunc(apiGroupInfo.destroyStorage)

    // 如果启用了 StorageVersionAPI 和 APIServerIdentity 特性
    if utilfeature.DefaultFeatureGate.Enabled(features.StorageVersionAPI) && utilfeature.DefaultFeatureGate.Enabled(features.APIServerIdentity) {
        // 在开始监听处理程序之前进行 API 安装，
        // 因此在这里注册 ResourceInfos 是安全的。
        // 处理程序将阻塞写入请求，直到目标资源的存储版本被更新。
        s.StorageVersionManager.AddResourceInfo(resourceInfos...)
	}

	return nil
}
```

##### InstallREST

```go
// InstallREST 将 REST 处理程序（存储、观察、代理和重定向）注册到 restful.Container 中。
// 预期提供的路径根前缀将用于处理所有操作。根路径不得以斜杠结尾。
func (g *APIGroupVersion) InstallREST(container *restful.Container) ([]apidiscoveryv2beta1.APIResourceDiscovery, []*storageversion.ResourceInfo, error) {
    // 根据组和版本构建路径前缀
	prefix := path.Join(g.Root, g.GroupVersion.Group, g.GroupVersion.Version)

    // 创建 APIInstaller 对象
    installer := &APIInstaller{
        group:             g,
        prefix:            prefix,
        minRequestTimeout: g.MinRequestTimeout,
    }

    // 调用 Install 方法进行安装，获取 API 资源、资源信息、WebService 和注册错误
    apiResources, resourceInfos, ws, registrationErrors := installer.Install()

    // 创建 APIVersionHandler 对象，用于处理版本发现
    versionDiscoveryHandler := discovery.NewAPIVersionHandler(g.Serializer, g.GroupVersion, staticLister{apiResources})
    versionDiscoveryHandler.AddToWebService(ws)

    // 将 WebService 添加到 Container 中
    container.Add(ws)

    // 转换聚合发现资源
    aggregatedDiscoveryResources, err := ConvertGroupVersionIntoToDiscovery(apiResources)
    if err != nil {
        registrationErrors = append(registrationErrors, err)
    }

    // 返回聚合发现资源、持久化资源信息和注册错误的聚合错误
    return aggregatedDiscoveryResources, removeNonPersistedResources(resourceInfos), utilerrors.NewAggregate(registrationErrors)
}
```

##### crdHandler

```go
// crdHandler 用于处理 /apis 端点。
// 它被注册为过滤器，以确保不会与任何显式注册的端点发生冲突。
type crdHandler struct {
    versionDiscoveryHandler *versionDiscoveryHandler
    groupDiscoveryHandler *groupDiscoveryHandler
    customStorageLock sync.Mutex
    // customStorage 包含 crdStorageMap
    // 与 sync.RWMutex 相比，atomic.Value 具有非常好的读性能
    // 参考 https://gist.github.com/dim/152e6bf80e1384ea72e17ac717a5000a
    // 对于大多数读操作和很少写操作的情况来说，这是比较适合的
    customStorage atomic.Value

    crdLister listers.CustomResourceDefinitionLister

    delegate          http.Handler
    restOptionsGetter generic.RESTOptionsGetter
    admission         admission.Interface

    establishingController *establish.EstablishingController

    // MasterCount 用于实现睡眠，以改进 HA 集群的 CRD 建立过程。
    masterCount int

    converterFactory *conversion.CRConverterFactory

    // 以便我们可以在更新时进行创建。
    authorizer authorizer.Authorizer

    // 请求超时时间，我们应该延迟存储的拆除
    requestTimeout time.Duration

    // minRequestTimeout 适用于 CR 的列表/观察调用
    minRequestTimeout time.Duration

    // staticOpenAPISpec 用作管理字段结构的 CR 模式的基础，CR 处理程序通过它获取 TypeMeta 和 ObjectMeta 的结构。
    staticOpenAPISpec map[string]*spec.Schema

    // 在写入请求中接受和解码的请求大小限制
    // 0 表示无限制。
    maxRequestBodyBytes int64
}

// crdInfo 存储足够的信息来为自定义资源提供存储服务。
type crdInfo struct {
    // spec 和 acceptedNames 用于比较是否对 CRD 进行了更改。只有在这些更改之一时，我们才更新存储。
    spec *apiextensionsv1.CustomResourceDefinitionSpec
    acceptedNames *apiextensionsv1.CustomResourceDefinitionNames
        // Deprecated per version
    deprecated map[string]bool

    // Warnings per version
    warnings map[string][]string

    // Storage per version
    storages map[string]customresource.CustomResourceStorage

    // Request scope per version
    requestScopes map[string]*handlers.RequestScope

    // Scale scope per version
    scaleRequestScopes map[string]*handlers.RequestScope

    // Status scope per version
    statusRequestScopes map[string]*handlers.RequestScope

    // storageVersion 是在将对象存储到 etcd 中使用的 CRD 版本。
    storageVersion string

    waitGroup *utilwaitgroup.SafeWaitGroup
}

// crdStorageMap 将自定义资源定义映射到其存储。
type crdStorageMap map[types.UID]*crdInfo

// ServeHTTP 方法处理 HTTP 请求并提供响应。

func (r *crdHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
ctx := req.Context()
    requestInfo, ok := apirequest.RequestInfoFrom(ctx)
    if !ok {
        responsewriters.ErrorNegotiated(
            apierrors.NewInternalError(fmt.Errorf("no RequestInfo found in the context")),
            Codecs, schema.GroupVersion{}, w, req,
    	)
    	return
    }
    // 如果请求不是资源请求，则将请求转发给 delegate 处理。
    if !requestInfo.IsResourceRequest {
        pathParts := splitPath(requestInfo.Path)
        // 只匹配 /apis/<group>/<version>
        // 只注册在 /apis 下
        if len(pathParts) == 3 {
            r.versionDiscoveryHandler.ServeHTTP(w, req)
            return
        }
        // 只匹配 /apis/<group>
        if len(pathParts) == 2 {
            r.groupDiscoveryHandler.ServeHTTP(w, req)
            return
        }

        r.delegate.ServeHTTP(w, req)
        return
    }

    crdName := requestInfo.Resource + "." + requestInfo.APIGroup
    crd, err := r.crdLister.Get(crdName)

    // 如果 CRD 不存在，则将请求转发给 delegate 处理。
    if apierrors.IsNotFound(err) {
        r.delegate.ServeHTTP(w, req)
        return
    }
    if err != nil {
        utilruntime.HandleError(err)
        responsewriters.ErrorNegotiated(
            apierrors.NewInternalError(fmt.Errorf("error resolving resource")),
            Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
        )
        return
    }

    // 根据 CRD 和请求信息进行条件判断，决定是否将请求转发给 delegate 处理。
    namespacedCRD, namespacedReq := crd.Spec.Scope == apiextensionsv1.NamespaceScoped, len(requestInfo.Namespace) > 0
    if !namespacedCRD && namespacedReq {
        r.delegate.ServeHTTP(w, req)
        return
    }
    if namespacedCRD && !namespacedReq && !possiblyAcrossAllNamespacesVerbs.Has(requestInfo.Verb) {
        r.delegate.ServeHTTP(w, req)
        return
    }

    if !apiextensionshelpers.HasServedCRDVersion(crd, requestInfo.APIVersion) {
        r.delegate.ServeHTTP(w, req)
        return
    }

    // 在 CRD 建立过程中，如果 NamesAccepted 条件为 true，但由于另一个名称更新导致冲突，
    // 并且 EstablishingController 没有足够快地将 CRD 放入 Established 条件中，则可能出现“未提供”的情况。
    // 我们接受这种情况，因为问题很小并且是自我修复的。
    if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.NamesAccepted) &&
        !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
        r.delegate.ServeHTTP(w, req)
        return
    }

    terminating := apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Terminating)

    crdInfo, err := r.getOrCreateServingInfoFor(crdUID, crd.Name)
    if apierrors.IsNotFound(err) {
        r.delegate.ServeHTTP(w, req)
        return
    }
    if err != nil {
        utilruntime.HandleError(err)
        responsewriters.ErrorNegotiated(
            apierrors.NewInternalError(fmt.Errorf("error resolving resource")),
            Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
    	)
        return
    }
    // 如果请求的 APIVersion 不在 CRD 的 served 版本列表中，则将请求转发给 delegate 处理。
    if !hasServedCRDVersion(crdInfo.spec, requestInfo.APIVersion) {
        r.delegate.ServeHTTP(w, req)
        return
    }

    deprecated := crdInfo.deprecated[requestInfo.APIVersion]
    for _, w := range crdInfo.warnings[requestInfo.APIVersion] {
        warning.AddWarning(req.Context(), "", w)
    }

    verb := strings.ToUpper(requestInfo.Verb)
    resource := requestInfo.Resource
    subresource := requestInfo.Subresource
    scope := metrics.CleanScope(requestInfo)
    supportedTypes := []string{
        string(types.JSONPatchType),
        string(types.MergePatchType),
        string(types.ApplyPatchType),
    }

    var handlerFunc http.HandlerFunc
    subresources, err := apiextensionshelpers.GetSubresourcesForVersion(crd, requestInfo.APIVersion)
    if err != nil {
        utilruntime.HandleError(err)
        responsewriters.ErrorNegotiated(
            apierrors.NewInternalError(fmt.Errorf("could not properly serve the subresource")),
            Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
        )
        return
    }
    switch {
    // 如果请求的是 status 子资源，并且 CRD 的 subresources 中包含 status 子资源，则调用 serveStatus 处理函数。
    case subresource == "status" && subresources != nil && subresources.Status != nil:
        handlerFunc = r.serveStatus(w, req, requestInfo, crdInfo, terminating, supportedTypes)
    // 如果请求的是 scale 子资源，并且 CRD 的 subresources 中包含 scale 子资源，则调用 serveScale 处理函数。
    case subresource == "scale" && subresources != nil && subresources.Scale != nil:
        handlerFunc = r.serveScale(w, req, requestInfo, crdInfo, terminating, supportedTypes)
    // 如果请求没有指定子资源，则调用 serveResource 处理函数。
    case len(subresource) == 0:
        handlerFunc = r.serveResource(w, req, requestInfo, crdInfo, crd, terminating, supportedTypes)
    // 如果请求的子资源不符合上述条件，则返回 NotFound 错误。
    default:
        responsewriters.ErrorNegotiated(
            apierrors.NewNotFound(schema.GroupResource{Group: requestInfo.APIGroup, Resource: requestInfo.Resource}, requestInfo.Name),
            Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
        )
    }

    // 如果存在处理函数，则对其进行一系列操作，并最终调用 ServeHTTP 处理请求。
    if handlerFunc != nil {
        handlerFunc = metrics.InstrumentHandlerFunc(verb, requestInfo.APIGroup, requestInfo.APIVersion, resource, subresource, scope, metrics.APIServerComponent, deprecated, "", handlerFunc)
        handler := genericfilters.WithWaitGroup(handlerFunc, longRunningFilter, crdInfo.waitGroup)
        handler.ServeHTTP(w, req)
        return
	}
}
```

### CreateKubeAPIServer

```go
func CreateKubeAPIServer(kubeAPIServerConfig *controlplane.Config, delegateAPIServer genericapiserver.DelegationTarget) (*controlplane.Instance, error) {
	return kubeAPIServerConfig.Complete().New(delegateAPIServer)
}

// New 方法根据给定的配置返回一个 Master 实例。
// 如果未设置某些配置字段，则会设置为默认值。
// 必须指定某些配置字段，包括：KubeletClientConfig。
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*Instance, error) {
    if reflect.DeepEqual(c.ExtraConfig.KubeletClientConfig, kubeletclient.KubeletClientConfig{}) {
    	return nil, fmt.Errorf("Master.New() called with empty config.KubeletClientConfig")
    }
    // 调用 GenericConfig 的 New 方法创建 GenericAPIServer 实例
    s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)
    if err != nil {
        return nil, err
    }

    if c.ExtraConfig.EnableLogsSupport {
        routes.Logs{}.Install(s.Handler.GoRestfulContainer)
    }

    // 创建 serviceaccount.OpenIDMetadata 实例
    md, err := serviceaccount.NewOpenIDMetadata(
        c.ExtraConfig.ServiceAccountIssuerURL,
        c.ExtraConfig.ServiceAccountJWKSURI,
        c.GenericConfig.ExternalAddress,
        c.ExtraConfig.ServiceAccountPublicKeys,
    )
    if err != nil {
        // 如果发生错误，则跳过安装 endpoints 并记录错误日志，但继续执行。
        // 不返回错误是因为 metadata 响应需要对命令行选项进行附加的、不兼容的验证。
        msg := fmt.Sprintf("Could not construct pre-rendered responses for"+
            " ServiceAccountIssuerDiscovery endpoints. Endpoints will not be"+
            " enabled. Error: %v", err)
        if c.ExtraConfig.ServiceAccountIssuerURL != "" {
            // 如果用户期望启用该功能，则记录错误日志
            klog.Error(msg)
        } else {
            // 如果用户未设置 ServiceAccountIssuerURL，则记录信息日志
            klog.Info(msg)
        }
    } else {
        // 安装 OpenIDMetadataServer
        routes.NewOpenIDMetadataServer(md.ConfigJSON, md.PublicKeysetJSON).
            Install(s.Handler.GoRestfulContainer)
    }

    // 创建 Instance 实例
    m := &Instance{
        GenericAPIServer:          s,
        ClusterAuthenticationInfo: c.ExtraConfig.ClusterAuthenticationInfo,
    }

    // 安装传统的 REST 存储
    if err := m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter); err != nil {
        return nil, err
    }

    clientset, err := kubernetes.NewForConfig(c.GenericConfig.LoopbackClientConfig)
    if err != nil {
        return nil, err
    }

    // 获取 admissionregistration 的 discovery client
    discoveryClientForAdmissionRegistration := clientset.Discovery()

    // 定义 REST 存储提供程序的顺序
    restStorageProviders := []RESTStorageProvider{
        apiserverinternalrest.StorageProvider{},
        authenticationrest.RESTStorageProvider{Authenticator: c.GenericConfig.Authentication.Authenticator, APIAudiences: c.GenericConfig.Authentication.APIAudiences},
        authorizationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, RuleResolver: c.GenericConfig.RuleResolver},
        autoscalingrest.RESTStorageProvider{},
        batchrest.RESTStorageProvider{},
        certificatesrest.RESTStorageProvider{},
        coordinationrest.RESTStorageProvider{},
        discoveryrest.StorageProvider{},
        networkingrest.RESTStorageProvider{},
		noderest.RESTStorageProvider{},
		policyrest.RESTStorageProvider{},
		rbacrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer},
		schedulingrest.RESTStorageProvider{},
		storagerest.RESTStorageProvider{},
		flowcontrolrest.RESTStorageProvider{InformerFactory: c.GenericConfig.SharedInformerFactory},
		// 将 apps 放在 extensions 之后，以便传统客户端解析共享资源名称的扩展版本。
		// See https://github.com/kubernetes/kubernetes/issues/42392
		appsrest.StorageProvider{},
		admissionregistrationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, DiscoveryClient: discoveryClientForAdmissionRegistration},
		eventsrest.RESTStorageProvider{TTL: c.ExtraConfig.EventTTL},
		resourcerest.RESTStorageProvider{},
	}
    // 安装 API
    if err := m.InstallAPIs(c.ExtraConfig.APIResourceConfigSource, c.GenericConfig.RESTOptionsGetter, restStorageProviders...); err != nil {
        return nil, err
    }

    // 添加启动后的钩子函数 start-cluster-authentication-info-controller
    m.GenericAPIServer.AddPostStartHookOrDie("start-cluster-authentication-info-controller", func(hookContext genericapiserver.PostStartHookContext) error {
        kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
        if err != nil {
            return err
        }
        controller := clusterauthenticationtrust.NewClusterAuthenticationTrustController(m.ClusterAuthenticationInfo, kubeClient)

        // 从 stopCh 创建上下文，以避免修改依赖于 apiserver 的文件。
        // TODO: 看看是否可以将 ctx 传递给当前方法。
        ctx := wait.ContextForChannel(hookContext.StopCh)

        // 设置初始值并启动监听器
        if m.ClusterAuthenticationInfo.ClientCA != nil {
            m.ClusterAuthenticationInfo.ClientCA.AddListener(controller)
            if controller, ok := m.ClusterAuthenticationInfo.ClientCA.(dynamiccertificates.ControllerRunner); ok {
                // 运行一次以确保我们有一个值。
                if err := controller.RunOnce(ctx); err != nil {
                    runtime.HandleError(err)
                }
                go controller.Run(ctx, 1)
            }
        }
        if m.ClusterAuthenticationInfo.RequestHeaderCA != nil {
            m.ClusterAuthenticationInfo.RequestHeaderCA.AddListener(controller)
            if controller, ok := m.ClusterAuthenticationInfo.RequestHeaderCA.(dynamiccertificates.ControllerRunner); ok {
                // 运行一次以确保我们有一个值。
                if err := controller.RunOnce(ctx); err != nil {
                    runtime.HandleError(err)
                }
                go controller.Run(ctx, 1)
            }
        }

        go controller.Run(ctx, 1)
        return nil
    })

    // 如果启用了 APIServerIdentity 特性，则添加启动后的钩子函数 start-kube-apiserver-identity-lease-controller
    if utilfeature.DefaultFeatureGate.Enabled(apiserverfeatures.APIServerIdentity) {
        m.GenericAPIServer.AddPostStartHookOrDie("start-kube-apiserver-identity-lease-controller", func(hookContext genericapiserver.PostStartHookContext) error {
            kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
            if err != nil {
                return err
			}
			
            // 从 stopCh 创建上下文，以避免修改依赖于 apiserver 的文件。
            // TODO: 看看是否可以将 ctx 传递给当前方法
            ctx := wait.ContextForChannel(hookContext.StopCh)

            leaseName := m.GenericAPIServer.APIServerID
            holderIdentity := m.GenericAPIServer.APIServerID + "_" + string(uuid.NewUUID())

            controller := lease.NewController(
                clock.RealClock{},
                kubeClient,
                holderIdentity,
                int32(IdentityLeaseDurationSeconds),
                nil,
                IdentityLeaseRenewIntervalPeriod,
                leaseName,
                metav1.NamespaceSystem,
                // TODO: 在将后启动钩子移动到通用 apiserver 时，接收身份标签值作为参数
                labelAPIServerHeartbeatFunc(KubeAPIServer))
            go controller.Run(ctx)
            return nil
        })
        // 为了兼容性，在一段时间内同时垃圾回收具有两个标签的租约，其中一个是 k8s.io/component=kube-apiserver，另一个是 apiserver.kubernetes.io/identity=kube-apiserver。
        // TODO: 在 Kubernetes 1.28 中移除
        m.GenericAPIServer.AddPostStartHookOrDie("start-deprecated-kube-apiserver-identity-lease-garbage-collector", func(hookContext genericapiserver.PostStartHookContext) error {
            kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
            if err != nil {
                return err
            }
            go apiserverleasegc.NewAPIServerLeaseGC(
                kubeClient,
                IdentityLeaseGCPeriod,
                metav1.NamespaceSystem,
                DeprecatedKubeAPIServerIdentityLeaseLabelSelector,
            ).Run(hookContext.StopCh)
            return nil
        })
        // TODO: 将其移动到通用 apiserver 中，并使租约标识值可配置
        m.GenericAPIServer.AddPostStartHookOrDie("start-kube-apiserver-identity-lease-garbage-collector", func(hookContext genericapiserver.PostStartHookContext) error {
            kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
            if err != nil {
                return err
            }
            go apiserverleasegc.NewAPIServerLeaseGC(
                kubeClient,
                IdentityLeaseGCPeriod,
                metav1.NamespaceSystem,
                KubeAPIServerIdentityLeaseLabelSelector,
            ).Run(hookContext.StopCh)
            return nil
        })
    }
	// 添加启动后的钩子函数 start-legacy-token-tracking-controller
    m.GenericAPIServer.AddPostStartHookOrDie("start-legacy-token-tracking-controller", func(hookContext genericapiserver.PostStartHookContext) error {
        kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
        if err != nil {
            return err
        }
        go legacytokentracking.NewController(kubeClient).Run(hookContext.StopCh)
        return nil
    })

    return m, nil
}
```

#### GenericConfig.New

```go
// New函数创建一个新的服务器，将处理链与传递的服务器逻辑上合并。
// name用于区分日志记录。处理链特别复杂，因为它开始委托。
// delegationTarget不能为空。
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
	if c.Serializer == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.Serializer == nil")
	}
	if c.LoopbackClientConfig == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.LoopbackClientConfig == nil")
	}
	if c.EquivalentResourceRegistry == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.EquivalentResourceRegistry == nil")
	}
	// 定义handlerChainBuilder函数，该函数用于构建处理链
	handlerChainBuilder := func(handler http.Handler) http.Handler {
		return c.BuildHandlerChainFunc(handler, c.Config)
	}

	var debugSocket *routes.DebugSocket
	if c.DebugSocketPath != "" { // 如果配置了DebugSocketPath，则创建一个DebugSocket对象
		debugSocket = routes.NewDebugSocket(c.DebugSocketPath)
	}
	// 创建API服务器处理程序
	apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())
	// 创建GenericAPIServer对象
	s := &GenericAPIServer{
		discoveryAddresses:             c.DiscoveryAddresses,
		LoopbackClientConfig:           c.LoopbackClientConfig,
		legacyAPIGroupPrefixes:         c.LegacyAPIGroupPrefixes,
		admissionControl:               c.AdmissionControl,
		Serializer:                     c.Serializer,
		AuditBackend:                   c.AuditBackend,
		Authorizer:                     c.Authorization.Authorizer,
		delegationTarget:               delegationTarget,
		EquivalentResourceRegistry:     c.EquivalentResourceRegistry,
		NonLongRunningRequestWaitGroup: c.NonLongRunningRequestWaitGroup,
		WatchRequestWaitGroup:          c.WatchRequestWaitGroup,
		Handler:                        apiServerHandler,
		UnprotectedDebugSocket:         debugSocket,

		listedPathProvider: apiServerHandler,

		minRequestTimeout:                   time.Duration(c.MinRequestTimeout) * time.Second,
		ShutdownTimeout:                     c.RequestTimeout,
		ShutdownDelayDuration:               c.ShutdownDelayDuration,
		ShutdownWatchTerminationGracePeriod: c.ShutdownWatchTerminationGracePeriod,
		SecureServingInfo:                   c.SecureServing,
		ExternalAddress:                     c.ExternalAddress,

		openAPIConfig:           c.OpenAPIConfig,
		openAPIV3Config:         c.OpenAPIV3Config,
		skipOpenAPIInstallation: c.SkipOpenAPIInstallation,

		postStartHooks:         map[string]postStartHookEntry{},
		preShutdownHooks:       map[string]preShutdownHookEntry{},
		disabledPostStartHooks: c.DisabledPostStartHooks,

		healthzChecks:    c.HealthzChecks,
		livezChecks:      c.LivezChecks,
		readyzChecks:     c.ReadyzChecks,
		livezGracePeriod: c.LivezGracePeriod,

		DiscoveryGroupManager: discovery.NewRootAPIsHandler(c.DiscoveryAddresses, c.Serializer),

		maxRequestBodyBytes: c.MaxRequestBodyBytes,
		livezClock:          clock.RealClock{},

		lifecycleSignals:       c.lifecycleSignals,
		ShutdownSendRetryAfter: c.ShutdownSendRetryAfter,

		APIServerID:           c.APIServerID,
		StorageVersionManager: c.StorageVersionManager,

		Version: c.Version,

		muxAndDiscoveryCompleteSignals: map[string]<-chan struct{}{},
	}
	// 如果启用了AggregatedDiscoveryEndpoint特性，则添加聚合的发现组管理器
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
		manager := c.AggregatedDiscoveryGroupManager
		if manager == nil {
			manager = discoveryendpoint.NewResourceManager("apis")
		}
		s.AggregatedDiscoveryGroupManager = manager
		s.AggregatedLegacyDiscoveryGroupManager = discoveryendpoint.NewResourceManager("api")
	}
    // 检查JSONPatchMaxCopyBytes配置，设置jsonpatch.AccumulatedCopySizeLimit的值
	for {
		if c.JSONPatchMaxCopyBytes <= 0 {
			break
		}
		existing := atomic.LoadInt64(&jsonpatch.AccumulatedCopySizeLimit)
		if existing > 0 && existing < c.JSONPatchMaxCopyBytes {
			break
		}
		if atomic.CompareAndSwapInt64(&jsonpatch.AccumulatedCopySizeLimit, existing, c.JSONPatchMaxCopyBytes) {
			break
		}
	}

	// 从委托目标中添加poststarthooks
	for k, v := range delegationTarget.PostStartHooks() {
		s.postStartHooks[k] = v
	}
	// 从委托目标中添加preshutdownhooks
	for k, v := range delegationTarget.PreShutdownHooks() {
		s.preShutdownHooks[k] = v
	}

	// 添加预配置的poststarthooks，如果相同的名称已经注册，则返回错误
	for name, preconfiguredPostStartHook := range c.PostStartHooks {
		if err := s.AddPostStartHook(name, preconfiguredPostStartHook.hook); err != nil {
			return nil, err
		}
	}

	// 注册委托服务器的mux信号
	for k, v := range delegationTarget.MuxAndDiscoveryCompleteSignals() {
		if err := s.RegisterMuxAndDiscoveryCompleteSignal(k, v); err != nil {
			return nil, err
		}
	}

	genericApiServerHookName := "generic-apiserver-start-informers"
    // 如果SharedInformerFactory不为空，则添加一个poststarthook来启动SharedInformerFactory
	if c.SharedInformerFactory != nil {
		if !s.isPostStartHookRegistered(genericApiServerHookName) {
			err := s.AddPostStartHook(genericApiServerHookName, func(context PostStartHookContext) error {
				c.SharedInformerFactory.Start(context.StopCh)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		// TODO: 一旦我们摆脱/healthz，考虑将其更改为post-start-hook。
		err := s.AddReadyzChecks(healthz.NewInformerSyncHealthz(c.SharedInformerFactory))
		if err != nil {
			return nil, err
		}
	}

	const priorityAndFairnessConfigConsumerHookName = "priority-and-fairness-config-consumer"
    // 如果已经注册了priorityAndFairnessConfigConsumerHookName
	if s.isPostStartHookRegistered(priorityAndFairnessConfigConsumerHookName) {
	} else if c.FlowControl != nil {
		err := s.AddPostStartHook(priorityAndFairnessConfigConsumerHookName, func(context PostStartHookContext) error {
			go c.FlowControl.Run(context.StopCh)
			return nil
		})
		if err != nil {
			return nil, err
		}
		// TODO(yue9944882): plumb pre-shutdown-hook for request-management system?
	} else {
		klog.V(3).Infof("Not requested to run hook %s", priorityAndFairnessConfigConsumerHookName)
	}

	// 添加用于维护Priority-and-Fairness和Max-in-Flight过滤器水印的PostStartHooks。
	if c.FlowControl != nil {
        // 如果FlowControl配置存在，则添加一个名为"priority-and-fairness-filter"的PostStartHook来启动Priority-and-Fairness水印的维护。
		const priorityAndFairnessFilterHookName = "priority-and-fairness-filter"
		if !s.isPostStartHookRegistered(priorityAndFairnessFilterHookName) {
			err := s.AddPostStartHook(priorityAndFairnessFilterHookName, func(context PostStartHookContext) error {
				genericfilters.StartPriorityAndFairnessWatermarkMaintenance(context.StopCh)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	} else {
        // 如果FlowControl配置不存在，则添加一个名为"max-in-flight-filter"的PostStartHook来启动Max-in-Flight水印的维护。
		const maxInFlightFilterHookName = "max-in-flight-filter"
		if !s.isPostStartHookRegistered(maxInFlightFilterHookName) {
			err := s.AddPostStartHook(maxInFlightFilterHookName, func(context PostStartHookContext) error {
				genericfilters.StartMaxInFlightWatermarkMaintenance(context.StopCh)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}

	// 添加用于维护对象计数器的PostStartHook。
	if c.StorageObjectCountTracker != nil {
		const storageObjectCountTrackerHookName = "storage-object-count-tracker-hook"
		if !s.isPostStartHookRegistered(storageObjectCountTrackerHookName) {
			if err := s.AddPostStartHook(storageObjectCountTrackerHookName, func(context PostStartHookContext) error {
				go c.StorageObjectCountTracker.RunUntil(context.StopCh)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}
	// 根据委托目标的HealthzChecks添加健康检查项。
	for _, delegateCheck := range delegationTarget.HealthzChecks() {
		skip := false
		for _, existingCheck := range c.HealthzChecks {
			if existingCheck.Name() == delegateCheck.Name() {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		s.AddHealthChecks(delegateCheck)
	}
    // 注册一个DestroyFunc函数，用于在服务器销毁时关闭追踪器提供程序。	
	s.RegisterDestroyFunc(func() {
		if err := c.Config.TracerProvider.Shutdown(context.Background()); err != nil {
			klog.Errorf("failed to shut down tracer provider: %v", err)
		}
	})
	// 更新listedPathProvider，将委托目标添加到列表中。
	s.listedPathProvider = routes.ListedPathProviders{s.listedPathProvider, delegationTarget}
	// 安装API路由处理器。
	installAPI(s, c.Config)

	// 在委托目标的UnprotectedHandler为nil且配置中启用了EnableIndex选项时，使用委托目标的UnprotectedHandler，
	// 确保在委托情况下不会重复使用认证器、授权器或过滤器链的其他部分。
	if delegationTarget.UnprotectedHandler() == nil && c.EnableIndex {
		s.Handler.NonGoRestfulMux.NotFoundHandler(routes.IndexLister{
			StatusCode:   http.StatusNotFound,
			PathProvider: s.listedPathProvider,
		})
	}

	return s, nil
}
```

##### APIServerHandler

```GO
// APIServerHandlers包含API服务器使用的不同http.Handler。
// 这包括完整的处理程序链、导演（用于在gorestful和nonGoRestful之间进行选择）、gorestful处理程序（用于API），它会在未注册的路径上转到nonGoRestful处理程序，
// 以及nonGoRestful处理程序（可以包含自己的转发）。
// FullHandlerChain -> Director -> {GoRestfulContainer，NonGoRestfulMux}，基于注册的web服务进行检查
type APIServerHandler struct {
    // FullHandlerChain是最终提供的处理程序。它应包含完整的过滤器链并调用Director。
    FullHandlerChain http.Handler
    // 注册的API。InstallAPIs使用此字段。其他服务器可能不应直接访问此字段。
    GoRestfulContainer *restful.Container
    // NonGoRestfulMux是链中的最终HTTP处理程序。
    // 它位于所有过滤器和API处理程序之后。
    // 其他服务器可以将处理程序附加到链的各个部分。
    NonGoRestfulMux *mux.PathRecorderMux
    // Director是为了正确处理转发和代理情况。
    // 看起来有点疯狂，但以下是正在发生的事情。我们需要在gorestful中注册处理"/apis"，以便生成兼容的swagger文档。
    // 使用`/apis`作为web服务，意味着它会强制对非/apis或/apis/的请求返回404（不允许默认值）。
    // 我们需要这些调用在gorestful之后继续进行正确的委托。
    // 尝试注册一个包括其后面所有内容的模式无法正常工作，因为gorestful会进行动词和内容编码的协商，
    // 当gorestful实际上只需要传递时，所有这些东西都会出问题。
    // 此外，openapi强制执行唯一动词约束，我们无法符合，并且它仍然使swagger变得混乱。
    // 尝试将webservices切换到路由中也不起作用，因为包含的webservice面临着上面列出的所有问题。
    // 这导致了在这里执行的疯狂操作。我们的mux做了我们需要的事情，所以我们将它放在gorestful之前。
    // 它将内省以确定路由是否可能由gorestful处理，并在需要时将其路由到NonGoRestfulMux以处理“正常”的路径和委托。
    // 希望没有API使用者会被迫处理这种详细级别的细节。我认为我们应该考虑完全删除gorestful。
    // 其他服务器只能将其不透明地用于委托给API服务器。
    Director http.Handler
}

// HandlerChainBuilderFn用于使用提供的处理程序链包装
type HandlerChainBuilderFn func(apiHandler http.Handler) http.Handler

func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
	nonGoRestfulMux := mux.NewPathRecorderMux(name)
	if notFoundHandler != nil {
		nonGoRestfulMux.NotFoundHandler(notFoundHandler)
	}

	gorestfulContainer := restful.NewContainer()
	gorestfulContainer.ServeMux = http.NewServeMux()
	gorestfulContainer.Router(restful.CurlyRouter{}) // e.g. for proxy/{kind}/{name}/{*}
	gorestfulContainer.RecoverHandler(func(panicReason interface{}, httpWriter http.ResponseWriter) {
		logStackOnRecover(s, panicReason, httpWriter)
	})
	gorestfulContainer.ServiceErrorHandler(func(serviceErr restful.ServiceError, request *restful.Request, response *restful.Response) {
		serviceErrorHandler(s, serviceErr, request, response)
	})

	director := director{
		name:               name,
		goRestfulContainer: gorestfulContainer,
		nonGoRestfulMux:    nonGoRestfulMux,
	}

	return &APIServerHandler{
		FullHandlerChain:   handlerChainBuilder(director),
		GoRestfulContainer: gorestfulContainer,
		NonGoRestfulMux:    nonGoRestfulMux,
		Director:           director,
	}
}

// ListedPaths返回应在/下显示的路径。
func (a *APIServerHandler) ListedPaths() []string {
    var handledPaths []string
    // 提取使用restful.WebService处理的路径
    for _, ws := range a.GoRestfulContainer.RegisteredWebServices() {
    	handledPaths = append(handledPaths, ws.RootPath())
    }
    handledPaths = append(handledPaths, a.NonGoRestfulMux.ListedPaths()...)
    sort.Strings(handledPaths)
	return handledPaths
}

type director struct {
	name               string
	goRestfulContainer *restful.Container
	nonGoRestfulMux    *mux.PathRecorderMux
}

func (d director) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	// 检查我们的 WebServices 是否要求处理此路径
	for _, ws := range d.goRestfulContainer.RegisteredWebServices() {
		switch {
		case ws.RootPath() == "/apis":
			// 如果路径为 "/apis" 或 "/apis/"，则需要特殊处理。
			// 通常，这些路径会传递给 nonGoRestfulMux，但如果启用了发现功能，它将直接处理。
			// 我们不能依赖前缀匹配，因为 "/apis" 匹配所有路径（请参见上面对 Director 的详细注释）
			if path == "/apis" || path == "/apis/" {
				klog.V(5).Infof("%v: %v %q 由 gorestful 处理，使用的 webservice 是 %v", d.name, req.Method, path, ws.RootPath())
				// 这里不使用 servemux，因为当移除 webservices 时，gorestful 的 servemux 会出错
				// TODO 修复 gorestful，移除 TPRs，或者停止使用 gorestful
				d.goRestfulContainer.Dispatch(w, req)
				return
			}

		case strings.HasPrefix(path, ws.RootPath()):
			// 确保精确匹配或路径边界匹配
			if len(path) == len(ws.RootPath()) || path[len(ws.RootPath())] == '/' {
				klog.V(5).Infof("%v: %v %q 由 gorestful 处理，使用的 webservice 是 %v", d.name, req.Method, path, ws.RootPath())
				// 这里不使用 servemux，因为当移除 webservices 时，gorestful 的 servemux 会出错
				// TODO 修复 gorestful，移除 TPRs，或者停止使用 gorestful
				d.goRestfulContainer.Dispatch(w, req)
				return
			}
		}
	}

	// 如果没有找到匹配项，则直接跳过 gorestful
	klog.V(5).Infof("%v: %v %q 由 nonGoRestful 处理", d.name, req.Method, path)
	d.nonGoRestfulMux.ServeHTTP(w, req)
}
```

##### GenericAPIServer

```go
// GenericAPIServer 包含 Kubernetes 集群 API 服务器的状态。
type GenericAPIServer struct {
    // discoveryAddresses 用于构建用于发现的集群 IP。
    discoveryAddresses discovery.Addresses
    // LoopbackClientConfig 是用于与 API 服务器建立特权回环连接的配置。
    LoopbackClientConfig *restclient.Config

    // minRequestTimeout 是请求超时的最短时间。用于构建 RESTHandler。
    minRequestTimeout time.Duration

    // ShutdownTimeout 是服务器关闭的超时时间。指定服务器正常关闭返回前的超时时间。
    ShutdownTimeout time.Duration

    // legacyAPIGroupPrefixes 用于设置授权和验证 InstallLegacyAPIGroup 请求的 URL 解析。
    legacyAPIGroupPrefixes sets.String

    // admissionControl 用于构建支持 API 组的 RESTStorage。
    admissionControl admission.Interface

    // SecureServingInfo 包含 TLS 服务器的配置。
    SecureServingInfo *SecureServingInfo

    // ExternalAddress 是用于此 GenericAPIServer 的外部（公共互联网）URL 的地址（主机名或 IP 和端口）。
    ExternalAddress string

    // Serializer 控制如何对此服务器的非组/版本前缀的常见 API 对象进行序列化。
    // 各个 API 组可以定义自己的序列化程序。
    Serializer runtime.NegotiatedSerializer

    // "Outputs"
    // Handler 包含此 API 服务器使用的处理程序。
    Handler *APIServerHandler

    // UnprotectedDebugSocket 用于在 Unix 域套接字中提供 pprof 信息。此套接字不受身份验证/授权保护。
    UnprotectedDebugSocket *routes.DebugSocket

    // listedPathProvider 是一个提供要在 / 上显示的路径集合的列表。
    listedPathProvider routes.ListedPathProvider

    // DiscoveryGroupManager 以未聚合的形式提供 /apis 服务。
    DiscoveryGroupManager discovery.GroupManager

    // AggregatedDiscoveryGroupManager 以聚合的形式提供 /apis 服务。
    AggregatedDiscoveryGroupManager discoveryendpoint.ResourceManager

    // AggregatedLegacyDiscoveryGroupManager 以聚合的形式提供 /api 服务。
    AggregatedLegacyDiscoveryGroupManager discoveryendpoint.ResourceManager

    // 如果这些配置项非空，则启用 swagger 和/或 OpenAPI。
    openAPIConfig *openapicommon.Config

    // 如果这些配置项非空，则启用 swagger 和/或 OpenAPI V3。
    openAPIV3Config *openapicommon.Config

    // SkipOpenAPIInstallation 表示在 PrepareRun 期间不安装 OpenAPI 处理程序。
    // 当特定的 API 服务器具有自己的 OpenAPI 处理程序时，将其设置为 true
    //（例如 kube-aggregator）。
    skipOpenAPIInstallation bool

    // OpenAPIVersionedService 控制 /openapi/v2 端点，并可用于更新提供的规范。
    // 如果 `openAPIConfig` 非空且 `skipOpenAPIInstallation` 为 false，则在 PrepareRun 期间设置它。
    OpenAPIVersionedService *handler.OpenAPIService

   // OpenAPIV3VersionedService 控制 /openapi/v3 端点，并可用于更新提供的规范。
    // 如果 `openAPIConfig` 非空且 `skipOpenAPIInstallation` 为 false，则在 PrepareRun 期间设置它。
    OpenAPIV3VersionedService *handler3.OpenAPIService

    // StaticOpenAPISpec 是从 restful 容器端点派生的规范。
    // 在 PrepareRun 期间设置它。
    StaticOpenAPISpec *spec.Swagger

    // PostStartHooks 在服务器启动监听后每个钩子都会被调用，每个钩子都在单独的 goroutine 中执行，
    // 没有保证它们之间的顺序。映射键是用于错误报告的名称。
    // 如果希望，它可以通过返回错误来使用 panic 终止进程。
    postStartHookLock      sync.Mutex
    postStartHooks         map[string]postStartHookEntry
    postStartHooksCalled   bool
    disabledPostStartHooks sets.String

    preShutdownHookLock    sync.Mutex
    preShutdownHooks       map[string]preShutdownHookEntry
    preShutdownHooksCalled bool

    // 健康检查
    healthzLock            sync.Mutex
    healthzChecks          []healthz.HealthChecker
    healthzChecksInstalled bool
    // 存活检查
    livezLock            sync.Mutex
    livezChecks          []healthz.HealthChecker
    livezChecksInstalled bool
    // 就绪检查
    readyzLock            sync.Mutex
    readyzChecks          []healthz.HealthChecker
    readyzChecksInstalled bool
    livezGracePeriod      time.Duration
    livezClock            clock.Clock

    // 审计。后端在服务器开始侦听之前启动。
    AuditBackend audit.Backend

    // Authorizer 确定是否允许用户进行某个请求。处理程序使用请求 URI 进行初步授权检查，
    // 但可能需要进行其他检查，例如在创建-更新的情况下。
    Authorizer authorizer.Authorizer

    // EquivalentResourceRegistry 提供与给定资源等效的资源信息，
    // 以及与给定资源关联的种类。在安装资源时，将在此处注册它们。
    EquivalentResourceRegistry runtime.EquivalentResourceRegistry

    // delegationTarget 是链中的下一个委托。它永远不为空。
    delegationTarget DelegationTarget

    // NonLongRunningRequestWaitGroup 允许您在服务器关闭时等待与非长时间运行请求相关的所有链处理程序完成。
    NonLongRunningRequestWaitGroup *utilwaitgroup.SafeWaitGroup
    // WatchRequestWaitGroup 允许我们在服务器关闭时等待与活动监视请求相关的所有链处理程序完成。
    WatchRequestWaitGroup *utilwaitgroup.RateLimitedSafeWaitGroup

    // ShutdownDelayDuration 允许阻塞关闭一段时间，例如直到指向此 API 服务器的端点在所有节点上达到一致。
    // 在此期间，API 服务器继续提供服务，/healthz 将返回 200，
    // 但 /readyz 将返回失败。
    ShutdownDelayDuration time.Duration

    // 接受写请求的请求体大小限制。0 表示没有限制。
    maxRequestBodyBytes int64

    // APIServerID 是此 API 服务器的 ID
    APIServerID string

    // StorageVersionManager 包含由此服务器安装的 API 资源的存储版本。
    StorageVersionManager storageversion.Manager

    // 如果非空，Version 将启用 /version 端点
    Version *version.Info

    // lifecycleSignals 提供对 apiserver 生命周期中发生的各种信号的访问。
    lifecycleSignals lifecycleSignals

    // destroyFns 包含在关闭时应调用的清理资源的函数列表。
    destroyFns []func()

    // muxAndDiscoveryCompleteSignals 包含指示已注册所有已知 HTTP 路径的信号。
    // 它主要用于避免在资源实际存在但我们还没有安装到处理程序路径时返回 404 响应。
    // 它公开出来是为了更容易组合各个服务器。
    // 此字段的主要用户是 WithMuxCompleteProtection 过滤器和 NotFoundHandler。
    muxAndDiscoveryCompleteSignals map[string]<-chan struct{}

    // ShutdownSendRetryAfter 规定何时在 apiserver 优雅终止期间启动 HTTP 服务器的关闭。
    // 如果为 true，则等待正在进行的非长时间运行的请求被耗尽，然后启动 HTTP 服务器的关闭。
    // 如果为 false，则在 ShutdownDelayDuration 经过后立即启动 HTTP 服务器的关闭。
    // 如果启用，则在经过 ShutdownDelayDuration 之后，拒绝任何传入请求并返回 429 状态码和 'Retry-After' 响应。
    ShutdownSendRetryAfter bool

    // ShutdownWatchTerminationGracePeriod，如果设置为正值，
    // 则是 apiserver 等待所有活动 watch 请求完成的最长持续时间。
    // 一旦此优雅期限到期，apiserver 将不再等待任何活动的 watch 请求完成，
    // 它将继续进行优雅服务器关闭过程的下一步。
    // 如果设置为正值，apiserver 将跟踪活动的 watch 请求数量，并在关闭期间，
    // 至多等待指定的持续时间，并允许这些活动的 watch 请求进行一定的速率限制。
    // 默认值为零，表示 apiserver 不会跟踪活动的 watch 请求，并且不会等待它们完成，这保持了向后兼容性。
    // 这个优雅期限与其他优雅期限是相互独立的，也不受任何其他优雅期限的覆盖。
    ShutdownWatchTerminationGracePeriod time.Duration
}
```

##### installAPI

```go
func installAPI(s *GenericAPIServer, c *Config) {
	if c.EnableIndex {  // 如果启用索引
		routes.Index{}.Install(s.listedPathProvider, s.Handler.NonGoRestfulMux)  // 调用 Index 结构体的 Install 方法，传入 listedPathProvider 和 s.Handler.NonGoRestfulMux
	}
	if c.EnableProfiling {  // 如果启用性能分析
		routes.Profiling{}.Install(s.Handler.NonGoRestfulMux)  // 调用 Profiling 结构体的 Install 方法，传入 s.Handler.NonGoRestfulMux
		if c.EnableContentionProfiling {  // 如果启用争用分析
			goruntime.SetBlockProfileRate(1)  // 设置阻塞分析的频率为1
		}
		// 到目前为止，只有与日志记录相关的端点被认为是有效的，用于这些调试标志。
		routes.DebugFlags{}.Install(s.Handler.NonGoRestfulMux, "v", routes.StringFlagPutHandler(logs.GlogSetter))  // 调用 DebugFlags 结构体的 Install 方法，传入 s.Handler.NonGoRestfulMux、"v" 和 routes.StringFlagPutHandler(logs.GlogSetter)
	}
	if s.UnprotectedDebugSocket != nil {  // 如果未受保护的调试套接字不为空
		s.UnprotectedDebugSocket.InstallProfiling()  // 调用 UnprotectedDebugSocket 结构体的 InstallProfiling 方法
		s.UnprotectedDebugSocket.InstallDebugFlag("v", routes.StringFlagPutHandler(logs.GlogSetter))  // 调用 UnprotectedDebugSocket 结构体的 InstallDebugFlag 方法，传入 "v" 和 routes.StringFlagPutHandler(logs.GlogSetter)
		if c.EnableContentionProfiling {  // 如果启用争用分析
			goruntime.SetBlockProfileRate(1)  // 设置阻塞分析的频率为1
		}
	}

	if c.EnableMetrics {  // 如果启用指标
		if c.EnableProfiling {  // 如果启用性能分析
			routes.MetricsWithReset{}.Install(s.Handler.NonGoRestfulMux)  // 调用 MetricsWithReset 结构体的 Install 方法，传入 s.Handler.NonGoRestfulMux
			if utilfeature.DefaultFeatureGate.Enabled(features.ComponentSLIs) {  // 如果启用组件SLIs特性
				slis.SLIMetricsWithReset{}.Install(s.Handler.NonGoRestfulMux)  // 调用 SLIMetricsWithReset 结构体的 Install 方法，传入 s.Handler.NonGoRestfulMux
			}
		} else {
			routes.DefaultMetrics{}.Install(s.Handler.NonGoRestfulMux)  // 调用 DefaultMetrics 结构体的 Install 方法，传入 s.Handler.NonGoRestfulMux
			if utilfeature.DefaultFeatureGate.Enabled(features.ComponentSLIs) {  // 如果启用组件SLIs特性
				slis.SLIMetrics{}.Install(s.Handler.NonGoRestfulMux)  // 调用 SLIMetrics 结构体的 Install 方法，传入 s.Handler.NonGoRestfulMux
			}
		}
	}

	routes.Version{Version: c.Version}.Install(s.Handler.GoRestfulContainer)  // 调用 Version 结构体的 Install 方法，传入 s.Handler.GoRestfulContainer 和 c.Version

	if c.EnableDiscovery {  // 如果启用发现
		if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {  // 如果启用聚合发现端点
			wrapped := discoveryendpoint.WrapAggregatedDiscoveryToHandler(s.DiscoveryGroupManager, s.AggregatedDiscoveryGroupManager)  // 调用 discoveryendpoint 包的 WrapAggregatedDiscoveryToHandler 方法，传入 s.DiscoveryGroupManager 和 s.AggregatedDiscoveryGroupManager，并将返回值赋给 wrapped
			s.Handler.GoRestfulContainer.Add(wrapped.GenerateWebService("/apis", metav1.APIGroupList{}))  // 调用 wrapped 的 GenerateWebService 方法，传入 "/apis" 和 metav1.APIGroupList{}，并将返回值添加到 s.Handler.GoRestfulContainer
		} else {
			s.Handler.GoRestfulContainer.Add(s.DiscoveryGroupManager.WebService())  // 将 s.DiscoveryGroupManager.WebService() 添加到 s.Handler.GoRestfulContainer
		}
	}
	if c.FlowControl != nil && utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIPriorityAndFairness) {  // 如果 FlowControl 不为空且启用 API 优先级和公平性特性
		c.FlowControl.Install(s.Handler.NonGoRestfulMux)  // 调用 FlowControl 的 Install 方法，传入 s.Handler.NonGoRestfulMux
	}
}
```

#### InstallLegacyAPI

```go
// InstallLegacyAPI函数将为restStorageProviders安装遗留API（如果启用）。
func (m *Instance) InstallLegacyAPI(c *completedConfig, restOptionsGetter generic.RESTOptionsGetter) error {
    // 创建LegacyRESTStorageProvider实例，传入相关配置参数。
    legacyRESTStorageProvider := corerest.LegacyRESTStorageProvider{
    StorageFactory: c.ExtraConfig.StorageFactory, // 存储工厂对象
    ProxyTransport: c.ExtraConfig.ProxyTransport, // 代理传输对象
    KubeletClientConfig: c.ExtraConfig.KubeletClientConfig, // Kubelet客户端配置对象
    EventTTL: c.ExtraConfig.EventTTL, // 事件TTL（生存时间）
    ServiceIPRange: c.ExtraConfig.ServiceIPRange, // 服务IP地址范围
    SecondaryServiceIPRange: c.ExtraConfig.SecondaryServiceIPRange, // 次要服务IP地址范围
    ServiceNodePortRange: c.ExtraConfig.ServiceNodePortRange, // 服务节点端口范围
    LoopbackClientConfig: c.GenericConfig.LoopbackClientConfig, // 回环客户端配置对象
    ServiceAccountIssuer: c.ExtraConfig.ServiceAccountIssuer, // 服务账户发行方
    ExtendExpiration: c.ExtraConfig.ExtendExpiration, // 是否扩展过期时间
    ServiceAccountMaxExpiration: c.ExtraConfig.ServiceAccountMaxExpiration, // 服务账户最大过期时间
    APIAudiences: c.GenericConfig.Authentication.APIAudiences, // API观众
    Informers: c.ExtraConfig.VersionedInformers, // 告知器
    }
    // 创建遗留REST存储对象，获取API组信息和错误
    legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(c.ExtraConfig.APIResourceConfigSource, restOptionsGetter)
    if err != nil {
    	return fmt.Errorf("error building core storage: %v", err) // 返回构建核心存储错误信息
    }
    if len(apiGroupInfo.VersionedResourcesStorageMap) == 0 { // 如果所有核心存储都被禁用，则返回
    	return nil
    }
    // 定义控制器名称和客户端对象
    controllerName := "bootstrap-controller"
    client := kubernetes.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig)
    // Kubernetes集群包含以下系统名称空间：kube-system，kube-node-lease，kube-public，default
    // 在系统名称空间控制器中，新建控制器对象，传入客户端和版本化的名称空间告知器，然后在后台运行该控制器
    m.GenericAPIServer.AddPostStartHookOrDie("start-system-namespaces-controller", func(hookContext genericapiserver.PostStartHookContext) error {
        go systemnamespaces.NewController(client, c.ExtraConfig.VersionedInformers.Core().V1().Namespaces()).Run(hookContext.StopCh)
        return nil
    })

    // 创建引导控制器对象，传入遗留REST存储和客户端对象
    bootstrapController, err := c.NewBootstrapController(legacyRESTStorage, client)
    if err != nil {
        return fmt.Errorf("error creating bootstrap controller: %v", err) // 返回创建引导控制器错误信息
    }
    // 将引导控制器的PostStartHook和PreShutdownHook添加到GenericAPIServer的钩子列表中
    m.GenericAPIServer.AddPostStartHookOrDie(controllerName, bootstrapController.PostStartHook)
    m.GenericAPIServer.AddPreShutdownHookOrDie(controllerName, bootstrapController.PreShutdownHook)
	// 安装遗留API组，传入默认的遗留API前缀和API组信息
    if err := m.GenericAPIServer.InstallLegacyAPIGroup(genericapiserver.DefaultLegacyAPIPrefix, &apiGroupInfo); err != nil {
        return fmt.Errorf("error in registering group versions: %v", err) // 返回注册组版本错误信息
    }
    return nil
}
```

##### NewLegacyRESTStorage

```go
func (c LegacyRESTStorageProvider) NewLegacyRESTStorage(apiResourceConfigSource serverstorage.APIResourceConfigSource, restOptionsGetter generic.RESTOptionsGetter) (LegacyRESTStorage, genericapiserver.APIGroupInfo, error) {
	apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		Scheme:                       legacyscheme.Scheme,
		ParameterCodec:               legacyscheme.ParameterCodec,
		NegotiatedSerializer:         legacyscheme.Codecs,
	}

	podDisruptionClient, err := policyclient.NewForConfig(c.LoopbackClientConfig)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	restStorage := LegacyRESTStorage{}

	podTemplateStorage, err := podtemplatestore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	eventStorage, err := eventstore.NewREST(restOptionsGetter, uint64(c.EventTTL.Seconds()))
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	limitRangeStorage, err := limitrangestore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	resourceQuotaStorage, resourceQuotaStatusStorage, err := resourcequotastore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	secretStorage, err := secretstore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	persistentVolumeStorage, persistentVolumeStatusStorage, err := pvstore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	persistentVolumeClaimStorage, persistentVolumeClaimStatusStorage, err := pvcstore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	configMapStorage, err := configmapstore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	namespaceStorage, namespaceStatusStorage, namespaceFinalizeStorage, err := namespacestore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	endpointsStorage, err := endpointsstore.NewREST(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	nodeStorage, err := nodestore.NewStorage(restOptionsGetter, c.KubeletClientConfig, c.ProxyTransport)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	podStorage, err := podstore.NewStorage(
		restOptionsGetter,
		nodeStorage.KubeletConnectionInfo,
		c.ProxyTransport,
		podDisruptionClient,
	)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	var serviceAccountStorage *serviceaccountstore.REST
	if c.ServiceAccountIssuer != nil {
		serviceAccountStorage, err = serviceaccountstore.NewREST(restOptionsGetter, c.ServiceAccountIssuer, c.APIAudiences, c.ServiceAccountMaxExpiration, podStorage.Pod.Store, secretStorage.Store, c.ExtendExpiration)
	} else {
		serviceAccountStorage, err = serviceaccountstore.NewREST(restOptionsGetter, nil, nil, 0, nil, nil, false)
	}
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	var serviceClusterIPRegistry rangeallocation.RangeRegistry
	serviceClusterIPRange := c.ServiceIPRange
	if serviceClusterIPRange.IP == nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("service clusterIPRange is missing")
	}

	serviceStorageConfig, err := c.StorageFactory.NewConfig(api.Resource("services"))
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}
	var serviceClusterIPAllocator, secondaryServiceClusterIPAllocator ipallocator.Interface

	if !utilfeature.DefaultFeatureGate.Enabled(features.MultiCIDRServiceAllocator) {
		serviceClusterIPAllocator, err = ipallocator.New(&serviceClusterIPRange, func(max int, rangeSpec string, offset int) (allocator.Interface, error) {
			var mem allocator.Snapshottable
			mem = allocator.NewAllocationMapWithOffset(max, rangeSpec, offset)
			// TODO etcdallocator package to return a storage interface via the storageFactory
			etcd, err := serviceallocator.NewEtcd(mem, "/ranges/serviceips", serviceStorageConfig.ForResource(api.Resource("serviceipallocations")))
			if err != nil {
				return nil, err
			}
			serviceClusterIPRegistry = etcd
			return etcd, nil
		})
		if err != nil {
			return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("cannot create cluster IP allocator: %v", err)
		}
	} else {
		networkingv1alphaClient, err := networkingv1alpha1client.NewForConfig(c.LoopbackClientConfig)
		if err != nil {
			return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
		}
		serviceClusterIPAllocator, err = ipallocator.NewIPAllocator(&serviceClusterIPRange, networkingv1alphaClient, c.Informers.Networking().V1alpha1().IPAddresses())
		if err != nil {
			return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("cannot create cluster IP allocator: %v", err)
		}
	}

	serviceClusterIPAllocator.EnableMetrics()
	restStorage.ServiceClusterIPAllocator = serviceClusterIPRegistry

	// allocator for secondary service ip range
	if c.SecondaryServiceIPRange.IP != nil {
		var secondaryServiceClusterIPRegistry rangeallocation.RangeRegistry
		if !utilfeature.DefaultFeatureGate.Enabled(features.MultiCIDRServiceAllocator) {
			secondaryServiceClusterIPAllocator, err = ipallocator.New(&c.SecondaryServiceIPRange, func(max int, rangeSpec string, offset int) (allocator.Interface, error) {
				var mem allocator.Snapshottable
				mem = allocator.NewAllocationMapWithOffset(max, rangeSpec, offset)
				// TODO etcdallocator package to return a storage interface via the storageFactory
				etcd, err := serviceallocator.NewEtcd(mem, "/ranges/secondaryserviceips", serviceStorageConfig.ForResource(api.Resource("serviceipallocations")))
				if err != nil {
					return nil, err
				}
				secondaryServiceClusterIPRegistry = etcd
				return etcd, nil
			})
			if err != nil {
				return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("cannot create cluster secondary IP allocator: %v", err)
			}
		} else {
			networkingv1alphaClient, err := networkingv1alpha1client.NewForConfig(c.LoopbackClientConfig)
			if err != nil {
				return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
			}
			secondaryServiceClusterIPAllocator, err = ipallocator.NewIPAllocator(&c.SecondaryServiceIPRange, networkingv1alphaClient, c.Informers.Networking().V1alpha1().IPAddresses())
			if err != nil {
				return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("cannot create cluster secondary IP allocator: %v", err)
			}
		}
		secondaryServiceClusterIPAllocator.EnableMetrics()
		restStorage.SecondaryServiceClusterIPAllocator = secondaryServiceClusterIPRegistry
	}

	var serviceNodePortRegistry rangeallocation.RangeRegistry
	serviceNodePortAllocator, err := portallocator.New(c.ServiceNodePortRange, func(max int, rangeSpec string, offset int) (allocator.Interface, error) {
		mem := allocator.NewAllocationMapWithOffset(max, rangeSpec, offset)
		// TODO etcdallocator package to return a storage interface via the storageFactory
		etcd, err := serviceallocator.NewEtcd(mem, "/ranges/servicenodeports", serviceStorageConfig.ForResource(api.Resource("servicenodeportallocations")))
		if err != nil {
			return nil, err
		}
		serviceNodePortRegistry = etcd
		return etcd, nil
	})
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("cannot create cluster port allocator: %v", err)
	}
	serviceNodePortAllocator.EnableMetrics()
	restStorage.ServiceNodePortAllocator = serviceNodePortRegistry

	controllerStorage, err := controllerstore.NewStorage(restOptionsGetter)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	serviceIPAllocators := map[api.IPFamily]ipallocator.Interface{
		serviceClusterIPAllocator.IPFamily(): serviceClusterIPAllocator,
	}
	if secondaryServiceClusterIPAllocator != nil {
		serviceIPAllocators[secondaryServiceClusterIPAllocator.IPFamily()] = secondaryServiceClusterIPAllocator
	}

	serviceRESTStorage, serviceStatusStorage, serviceRESTProxy, err := servicestore.NewREST(
		restOptionsGetter,
		serviceClusterIPAllocator.IPFamily(),
		serviceIPAllocators,
		serviceNodePortAllocator,
		endpointsStorage,
		podStorage.Pod,
		c.ProxyTransport)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	storage := map[string]rest.Storage{}
	if resource := "pods"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = podStorage.Pod
		storage[resource+"/attach"] = podStorage.Attach
		storage[resource+"/status"] = podStorage.Status
		storage[resource+"/log"] = podStorage.Log
		storage[resource+"/exec"] = podStorage.Exec
		storage[resource+"/portforward"] = podStorage.PortForward
		storage[resource+"/proxy"] = podStorage.Proxy
		storage[resource+"/binding"] = podStorage.Binding
		if podStorage.Eviction != nil {
			storage[resource+"/eviction"] = podStorage.Eviction
		}
		storage[resource+"/ephemeralcontainers"] = podStorage.EphemeralContainers

	}
	if resource := "bindings"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = podStorage.LegacyBinding
	}

	if resource := "podtemplates"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = podTemplateStorage
	}

	if resource := "replicationcontrollers"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = controllerStorage.Controller
		storage[resource+"/status"] = controllerStorage.Status
		if legacyscheme.Scheme.IsVersionRegistered(schema.GroupVersion{Group: "autoscaling", Version: "v1"}) {
			storage[resource+"/scale"] = controllerStorage.Scale
		}
	}

	if resource := "services"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = serviceRESTStorage
		storage[resource+"/proxy"] = serviceRESTProxy
		storage[resource+"/status"] = serviceStatusStorage
	}

	if resource := "endpoints"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = endpointsStorage
	}

	if resource := "nodes"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = nodeStorage.Node
		storage[resource+"/proxy"] = nodeStorage.Proxy
		storage[resource+"/status"] = nodeStorage.Status
	}

	if resource := "events"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = eventStorage
	}

	if resource := "limitranges"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = limitRangeStorage
	}

	if resource := "resourcequotas"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = resourceQuotaStorage
		storage[resource+"/status"] = resourceQuotaStatusStorage
	}

	if resource := "namespaces"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = namespaceStorage
		storage[resource+"/status"] = namespaceStatusStorage
		storage[resource+"/finalize"] = namespaceFinalizeStorage
	}

	if resource := "secrets"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = secretStorage
	}

	if resource := "serviceaccounts"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = serviceAccountStorage
		if serviceAccountStorage.Token != nil {
			storage[resource+"/token"] = serviceAccountStorage.Token
		}
	}

	if resource := "persistentvolumes"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = persistentVolumeStorage
		storage[resource+"/status"] = persistentVolumeStatusStorage
	}

	if resource := "persistentvolumeclaims"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = persistentVolumeClaimStorage
		storage[resource+"/status"] = persistentVolumeClaimStatusStorage
	}

	if resource := "configmaps"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = configMapStorage
	}

	if resource := "componentstatuses"; apiResourceConfigSource.ResourceEnabled(corev1.SchemeGroupVersion.WithResource(resource)) {
		storage[resource] = componentstatus.NewStorage(componentStatusStorage{c.StorageFactory}.serversToValidate)
	}

	if len(storage) > 0 {
		apiGroupInfo.VersionedResourcesStorageMap["v1"] = storage
	}

	return restStorage, apiGroupInfo, nil
}
```

##### InstallLegacyAPIGroup

```go
// InstallLegacyAPIGroup 在 API 中公开给定的旧版 API 组。
// 此函数中传入的 <apiGroupInfo> 不应在其他地方使用，因为在服务器关闭时底层存储将被销毁。
func (s *GenericAPIServer) InstallLegacyAPIGroup(apiPrefix string, apiGroupInfo *APIGroupInfo) error {
    // 检查 apiPrefix 是否在允许的旧版 API 前缀列表中
    if !s.legacyAPIGroupPrefixes.Has(apiPrefix) {
    	return fmt.Errorf("%q 不在允许的旧版 API 前缀列表中：%v", apiPrefix, s.legacyAPIGroupPrefixes.List())
    }
    // 获取 openAPIModels
    openAPIModels, err := s.getOpenAPIModels(apiPrefix, apiGroupInfo)
    if err != nil {
        return fmt.Errorf("无法获取 openapi models：%v", err)
    }

    // 安装 API 资源
    if err := s.installAPIResources(apiPrefix, apiGroupInfo, openAPIModels); err != nil {
        return err
    }

    // 安装版本处理程序。
    // 在 /<apiPrefix> 上添加一个处理程序以列举支持的 API 版本。
    legacyRootAPIHandler := discovery.NewLegacyRootAPIHandler(s.discoveryAddresses, s.Serializer, apiPrefix)
    if utilfeature.DefaultFeatureGate.Enabled(features.AggregatedDiscoveryEndpoint) {
        wrapped := discoveryendpoint.WrapAggregatedDiscoveryToHandler(legacyRootAPIHandler, s.AggregatedLegacyDiscoveryGroupManager)
        s.Handler.GoRestfulContainer.Add(wrapped.GenerateWebService("/api", metav1.APIVersions{}))
    } else {
        s.Handler.GoRestfulContainer.Add(legacyRootAPIHandler.WebService())
    }

    return nil
}
```

#### InstallAPIs

```go
// 如果启用了restStorageProviders，则InstallAPIs函数将安装这些API。
func (m *Instance) InstallAPIs(apiResourceConfigSource serverstorage.APIResourceConfigSource, restOptionsGetter generic.RESTOptionsGetter, restStorageProviders ...RESTStorageProvider) error {
    // 创建一个空的APIGroupInfo切片，用于存储API组信息
    apiGroupsInfo := []*genericapiserver.APIGroupInfo{}
    // 在循环中用于通过过期日期筛选提供的资源。
    // resourceExpirationEvaluator将在后面用到，用于评估资源的过期情况。
    resourceExpirationEvaluator, err := genericapiserver.NewResourceExpirationEvaluator(*m.GenericAPIServer.Version)
    if err != nil {
        return err
    }

    // 遍历restStorageProviders切片中的每个restStorageBuilder
    for _, restStorageBuilder := range restStorageProviders {
        // 获取API组的名称
        groupName := restStorageBuilder.GroupName()
        // 调用restStorageBuilder的NewRESTStorage方法，创建API组的REST存储
        apiGroupInfo, err := restStorageBuilder.NewRESTStorage(apiResourceConfigSource, restOptionsGetter)
        if err != nil {
            return fmt.Errorf("problem initializing API group %q : %v", groupName, err)
        }
        if len(apiGroupInfo.VersionedResourcesStorageMap) == 0 {
            // 如果没有配置任何资源的存储，说明该API组被禁用了
            // 这可能发生在整个API组、版本或开发阶段（alpha、beta、GA）被禁用时
            klog.Infof("API group %q is not enabled, skipping.", groupName)
            continue
        }

        // 删除已删除的资源类型
        // 这样做是为了确保我们不会为我们不提供的资源类型的版本提供资源或openapi信息
        // 这个操作位于创建单个存储处理程序之前，以便没有sig意外忘记检查
        resourceExpirationEvaluator.RemoveDeletedKinds(groupName, apiGroupInfo.Scheme, apiGroupInfo.VersionedResourcesStorageMap)
        if len(apiGroupInfo.VersionedResourcesStorageMap) == 0 {
            klog.V(1).Infof("Removing API group %v because it is time to stop serving it because it has no versions per APILifecycle.", groupName)
            continue
        }

        klog.V(1).Infof("Enabling API group %q.", groupName)

        // 检查restStorageBuilder是否实现了genericapiserver.PostStartHookProvider接口
        if postHookProvider, ok := restStorageBuilder.(genericapiserver.PostStartHookProvider); ok {
            // 调用PostStartHook方法获取后置钩子的名称、钩子函数和错误信息
            name, hook, err := postHookProvider.PostStartHook()
            if err != nil {
                klog.Fatalf("Error building PostStartHook: %v", err)
            }
            // 将后置钩子添加到GenericAPIServer中
            m.GenericAPIServer.AddPostStartHookOrDie(name, hook)
        }

        // 将API组信息添加到apiGroupsInfo切片中
        apiGroupsInfo = append(apiGroupsInfo, &apiGroupInfo)
    }

    // 安装API组到GenericAPIServer中
    if err := m.GenericAPIServer.InstallAPIGroups(apiGroupsInfo...); err != nil {
        return fmt.Errorf("error in registering group versions: %v", err)
    }
    return nil
}

type RESTStorageProvider interface {
	GroupName() string
	NewRESTStorage(apiResourceConfigSource serverstorage.APIResourceConfigSource, restOptionsGetter generic.RESTOptionsGetter) (genericapiserver.APIGroupInfo, error)
}
```

### createAggregatorConfig

```go
func createAggregatorConfig(
kubeAPIServerConfig genericapiserver.Config,
commandOptions *options.ServerRunOptions,
externalInformers kubeexternalinformers.SharedInformerFactory,
serviceResolver aggregatorapiserver.ServiceResolver,
proxyTransport *http.Transport,
pluginInitializers []admission.PluginInitializer,
) (*aggregatorapiserver.Config, error) {
	// 创建一个聚合器配置对象aggregatorConfig
    // 创建一个泛型配置对象genericConfig，并将kubeAPIServerConfig赋值给它，以进行浅拷贝
    // 大部分配置保持不变，只需要修改与聚合器相关的几个项目
    genericConfig := kubeAPIServerConfig
    // 清空PostStartHooks，以避免将它们多次添加到所有服务器上（这样会导致失败）
    genericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}
    // 将RESTOptionsGetter设置为nil，防止泛型API服务器安装OpenAPI处理程序。
    // 聚合器服务器有自定义的OpenAPI处理程序。
    genericConfig.RESTOptionsGetter = nil
    // 设置SkipOpenAPIInstallation为true，阻止泛型API服务器安装OpenAPI处理程序。
    // 聚合器服务器有自定义的OpenAPI处理程序。
    genericConfig.SkipOpenAPIInstallation = true

    // 如果启用了StorageVersionAPI和APIServerIdentity特性
    if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.StorageVersionAPI) &&
        utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerIdentity) {
        // 向aggregator-apiserver添加StorageVersionPrecondition处理程序。
        // 该处理程序将阻止写请求到内置资源，直到目标资源的存储版本为最新。
        genericConfig.BuildHandlerChainFunc = genericapiserver.BuildHandlerChainWithStorageVersionPrecondition
    }

    // 复制etcd选项，以避免对原始选项进行修改。
    // 假设etcd选项已经完成。避免修改StorageConfig以外的任何内容，因为这可能会导致应用选项时出现意外行为。
    etcdOptions := *commandOptions.Etcd
    // 根据特性门控开启或关闭APIListChunking特性
    etcdOptions.StorageConfig.Paging = utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIListChunking)
    // 设置etcdOptions的StorageConfig.Codec为v1和v1beta1版本的LegacyCodec编解码器
    etcdOptions.StorageConfig.Codec = aggregatorscheme.Codecs.LegacyCodec(v1.SchemeGroupVersion, v1beta1.SchemeGroupVersion)
    // 设置etcdOptions的StorageConfig.EncodeVersioner为包含v1和v1beta1版本的MultiGroupVersioner编码器
    etcdOptions.StorageConfig.EncodeVersioner = runtime.NewMultiGroupVersioner(v1.SchemeGroupVersion, schema.GroupKind{Group: v1beta1.GroupName})
    // 设置SkipHealthEndpoints为true，避免重复连接健康检查
    etcdOptions.SkipHealthEndpoints = true
    // 将etcd选项应用到genericConfig中
    if err := etcdOptions.ApplyTo(&genericConfig); err != nil {
        return nil, err
    }

    // 使用聚合器的默认API资源配置和注册表，覆盖MergedResourceConfig
    if err := commandOptions.APIEnablement.ApplyTo(
        &genericConfig,
        aggregatorapiserver.DefaultAPIResourceConfigSource(),
        aggregatorscheme.Scheme); err != nil {
        return nil, err
    }

    // 创建聚合器配置对象aggregatorConfig
    aggregatorConfig := &aggregatorapiserver.Config{
        GenericConfig: &genericapiserver.RecommendedConfig{
            Config:                genericConfig,
            SharedInformerFactory: externalInformers,
        },
        ExtraConfig: aggregatorapiserver.ExtraConfig{
            ProxyClientCertFile:       commandOptions.ProxyClientCertFile,
            ProxyClientKeyFile:        commandOptions.ProxyClientKeyFile,
            ServiceResolver:           serviceResolver,
            ProxyTransport:            proxyTransport,
            RejectForwardingRedirects: commandOptions.AggregatorRejectForwardingRedirects,
        },
    }

    // 清空poststarthooks，以避免将它们多次添加到所有服务器上（这样会导致失败）
    aggregatorConfig.GenericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}

    return aggregatorConfig, nil
}

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}
```

### createAggregatorServer

```go
func createAggregatorServer(aggregatorConfig *aggregatorapiserver.Config, delegateAPIServer genericapiserver.DelegationTarget, apiExtensionInformers apiextensionsinformers.SharedInformerFactory) (*aggregatorapiserver.APIAggregator, error) {
    // 根据给定的聚合器配置、委托API服务器和API扩展Informer工厂创建聚合器服务器
    aggregatorServer, err := aggregatorConfig.Complete().NewWithDelegate(delegateAPIServer)
    if err != nil {
    	return nil, err
    }
    // 为自动注册创建控制器
    apiRegistrationClient, err := apiregistrationclient.NewForConfig(aggregatorConfig.GenericConfig.LoopbackClientConfig)
    if err != nil {
        return nil, err
    }
    autoRegistrationController := autoregister.NewAutoRegisterController(aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(), apiRegistrationClient)
    apiServices := apiServicesToRegister(delegateAPIServer, autoRegistrationController)
    crdRegistrationController := crdregistration.NewCRDRegistrationController(
        apiExtensionInformers.Apiextensions().V1().CustomResourceDefinitions(),
        autoRegistrationController)

    // 将所有内置组的优先级赋予聚合的发现
    if aggregatorConfig.GenericConfig.AggregatedDiscoveryGroupManager != nil {
        for gv, entry := range apiVersionPriorities {
            aggregatorConfig.GenericConfig.AggregatedDiscoveryGroupManager.SetGroupVersionPriority(metav1.GroupVersion(gv), int(entry.group), int(entry.version))
        }
    }

    err = aggregatorServer.GenericAPIServer.AddPostStartHook("kube-apiserver-autoregistration", func(context genericapiserver.PostStartHookContext) error {
        // 在新启动的协程中运行CRD注册控制器和自动注册控制器
        go crdRegistrationController.Run(5, context.StopCh)
        go func() {
            // 在启动自动注册控制器之前，让CRD控制器处理初始的CRD集合。
            // 这样可以防止自动注册控制器的初始同步删除仍然存在的CRD的APIServices。
            // 只有当该服务器上启用了CRD时才需要执行此操作。我们无法使用discovery，因为我们是discovery的来源。
            if aggregatorConfig.GenericConfig.MergedResourceConfig.ResourceEnabled(apiextensionsv1.SchemeGroupVersion.WithResource("customresourcedefinitions")) {
                crdRegistrationController.WaitForInitialSync()
            }
            autoRegistrationController.Run(5, context.StopCh)
        }()
        return nil
    })
    if err != nil {
        return nil, err
    }

    err = aggregatorServer.GenericAPIServer.AddBootSequenceHealthChecks(
        makeAPIServiceAvailableHealthCheck(
            "autoregister-completion",
            apiServices,
            aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(),
        ),
    )
    if err != nil {
        return nil, err
    }

    return aggregatorServer, nil
}
```

#### NewWithDelegate

```go
// NewWithDelegate根据给定的配置返回APIAggregator的新实例。
func (c completedConfig) NewWithDelegate(delegationTarget genericapiserver.DelegationTarget) (*APIAggregator, error) {
    genericServer, err := c.GenericConfig.New("kube-aggregator", delegationTarget)
    if err != nil {
    	return nil, err
    }
    apiregistrationClient, err := clientset.NewForConfig(c.GenericConfig.LoopbackClientConfig)
    if err != nil {
        return nil, err
    }
    informerFactory := informers.NewSharedInformerFactory(
        apiregistrationClient,
        5*time.Minute, // 这实际上被用作刷新间隔。以后可能需要更好的处理方式。
    )

    // apiServiceRegistrationControllerInitiated在APIServiceRegistrationController完成"安装"所有已知APIService时关闭。
    // 此时，我们知道代理处理程序知道APIService并且可以处理客户端请求。
    // 在此之前，它可能会导致404响应，这可能对一些控制器（如GC和NS）产生严重后果。
    //
    // 注意，APIServiceRegistrationController在APIServiceInformer同步之后才会开始工作。
    apiServiceRegistrationControllerInitiated := make(chan struct{})
    if err := genericServer.RegisterMuxAndDiscoveryCompleteSignal("APIServiceRegistrationControllerInitiated", apiServiceRegistrationControllerInitiated); err != nil {
        return nil, err
    }

    var proxyTransportDial *transport.DialHolder
    if c.GenericConfig.EgressSelector != nil {
        egressDialer, err := c.GenericConfig.EgressSelector.Lookup(egressselector.Cluster.AsNetworkContext())
        if err != nil {
            return nil, err
        }
        if egressDialer != nil {
            proxyTransportDial = &transport.DialHolder{Dial: egressDialer}
        }
    } else if c.ExtraConfig.ProxyTransport != nil && c.ExtraConfig.ProxyTransport.DialContext != nil {
        proxyTransportDial = &transport.DialHolder{Dial: c.ExtraConfig.ProxyTransport.DialContext}
    }

    s := &APIAggregator{
        GenericAPIServer:           genericServer,
        delegateHandler:            delegationTarget.UnprotectedHandler(),
        proxyTransportDial:         proxyTransportDial,
        proxyHandlers:              map[string]*proxyHandler{},
        handledGroups:              sets.String{},
        lister:                     informerFactory.Apiregistration().V1().APIServices().Lister(),
        APIRegistrationInformers:   informerFactory,
        serviceResolver:            c.ExtraConfig.ServiceResolver,
        openAPIConfig:              c.GenericConfig.OpenAPIConfig,
        openAPIV3Config:            c.GenericConfig.OpenAPIV3Config,
        proxyCurrentCertKeyContent: func() (bytes []byte, bytes2 []byte) { return nil, nil },
        rejectForwardingRedirects:  c.ExtraConfig.RejectForwardingRedirects,
    }

    // 以后用于根据已过期的资源进行筛选的评估器。
    resourceExpirationEvaluator, err := genericapiserver.NewResourceExpirationEvaluator(*c.GenericConfig.Version)
    if err != nil {
        return nil, err
    }

    apiGroupInfo := apiservicerest.NewRESTStorage(c.GenericConfig.MergedResourceConfig, c.GenericConfig.RESTOptionsGetter, resourceExpirationEvaluator.ShouldServeForVersion(1,
	// 安装 API Group
    if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
        return nil, err
    }

    // 创建一个集合 enabledVersions 来存储可用的版本信息
    enabledVersions := sets.NewString()
    for v := range apiGroupInfo.VersionedResourcesStorageMap {
        enabledVersions.Insert(v)
    }

    // 检查所需的版本是否已启用
    if !enabledVersions.Has(v1.SchemeGroupVersion.Version) {
        return nil, fmt.Errorf("API group/version %s must be enabled", v1.SchemeGroupVersion.String())
    }

    // 创建 apisHandler 对象
    apisHandler := &apisHandler{
        codecs:         aggregatorscheme.Codecs,
        lister:         s.lister,
        discoveryGroup: discoveryGroup(enabledVersions),
    }

    // 根据 feature gate 判断是否使用带有聚合支持的 apisHandler
    if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
        apisHandlerWithAggregationSupport := aggregated.WrapAggregatedDiscoveryToHandler(apisHandler, s.GenericAPIServer.AggregatedDiscoveryGroupManager)
        s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", apisHandlerWithAggregationSupport)
    } else {
        s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", apisHandler)
    }
    s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandle("/apis/", apisHandler)

    // 创建 apiserviceRegistrationController 对象
    apiserviceRegistrationController := NewAPIServiceRegistrationController(informerFactory.Apiregistration().V1().APIServices(), s)

    // 检查是否存在代理客户端证书和密钥文件，如果存在则创建动态证书对象
    if len(c.ExtraConfig.ProxyClientCertFile) > 0 && len(c.ExtraConfig.ProxyClientKeyFile) > 0 {
        aggregatorProxyCerts, err := dynamiccertificates.NewDynamicServingContentFromFiles("aggregator-proxy-cert", c.ExtraConfig.ProxyClientCertFile, c.ExtraConfig.ProxyClientKeyFile)
        if err != nil {
            return nil, err
        }

        // 运行一次 aggregatorProxyCerts，将证书内容存储到 s.proxyCurrentCertKeyContent 中
        ctx := context.TODO()
        if err := aggregatorProxyCerts.RunOnce(ctx); err != nil {
            return nil, err
        }
        aggregatorProxyCerts.AddListener(apiserviceRegistrationController)
        s.proxyCurrentCertKeyContent = aggregatorProxyCerts.CurrentCertKeyContent

        // 添加 aggregator-reload-proxy-client-cert 钩子函数，在启动后重新加载代理客户端证书
        s.GenericAPIServer.AddPostStartHookOrDie("aggregator-reload-proxy-client-cert", func(postStartHookContext genericapiserver.PostStartHookContext) error {
            ctx, cancel := context.WithCancel(context.Background())
            go func() {
                select {
                case <-postStartHookContext.StopCh:
                    cancel()
                case <-ctx.Done():
                }
            }()
            go aggregatorProxyCerts.Run(ctx, 1)
            return nil
        })
    }

    // 创建 availableController 对象
    availableController, err := statuscontrollers.NewAvailableConditionController(
        informerFactory.Apiregistration().V1().APIServices(),
        c.GenericConfig.SharedInformerFactory.Core().V1().Services(),
        c.GenericConfig.SharedInformerFactory.Core().V1().Endpoints(),
        apiregistrationClient.ApiregistrationV1(),
        proxyTransportDial,
        (func() ([]byte, []byte))(s.proxyCurrentCertKeyContent),
        s.serviceResolver,
    )
    if err != nil {
        return nil, err
    }

    // 添加 start-kube-aggregator-informers 钩子函数，在启动后开始 informer
    s.GenericAPIServer.AddPostStartHookOrDie("start-kube-aggregator-informers", func(context genericapiserver.PostStartHookContext) error {
        informerFactory.Start(context.StopCh)
        c.GenericConfig.SharedInformerFactory.Start(context.StopCh)
        return nil
    })

    // 添加 apiservice-registration-controller 钩子函数，在启动后运行 apiserviceRegistrationController
    s.GenericAPIServer.AddPostStartHookOrDie("apiservice-registration-controller", func(context genericapiserver.PostStartHookContext) error {
        go apiserviceRegistrationController.Run(context.StopCh, apiServiceRegistrationControllerInitiated)
        select {
        case <-context.StopCh:
        case <-apiServiceRegistrationControllerInitiated:
        }
        return nil
    })

    // 添加 apiservice-status-available-controller 钩子函数，在启动后运行 availableController
    s.GenericAPIServer.AddPostStartHookOrDie("apiservice-status-available-controller", func(context genericapiserver.PostStartHookContext) error {
        go availableController.Run(5, context.StopCh)
        return nil
    })

    // 如果启用了 StorageVersionAPI 和 APIServerIdentity，添加 StorageVersion 更新的钩子函数
    if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.StorageVersionAPI) &&
        utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerIdentity) {
        s.GenericAPIServer.AddPostStartHookOrDie(StorageVersionPostStartHookName, func(hookContext genericapiserver.PostStartHookContext) error {
            // 在更新 StorageVersion 之前先等待 apiserver-identity 存在，避免意外删除 storage versions
            kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
            if err != nil {
                return err
            }
            if err := wait.PollImmediateUntil(100*time.Millisecond, func() (bool, error) {
                _, err := kubeClient.CoordinationV1().Leases(metav1.NamespaceSystem).Get(
                    context.TODO(), s.GenericAPIServer.APIServerID, metav1.GetOptions{})
                if apierrors.IsNotFound(err) {
                    return false, nil
                }
                if err != nil {
                    return false, err
                }
                return true, nil
            }, hookContext.StopCh); err != nil {
                return fmt.Errorf("failed to wait for apiserver-identity lease %s to be created: %v",
                    s.GenericAPIServer.APIServerID, err)
            }
            // 每隔 10 分钟更新一次 StorageVersion
            go wait.PollImmediateUntil(10*time.Minute, func() (bool, error) {
                s.GenericAPIServer.StorageVersionManager.UpdateStorageVersions(hookContext.LoopbackClientConfig, s.GenericAPIServer.APIServerID)
                return false, nil
            }, hookContext.StopCh)
            // 等待 StorageVersion 更新完成
            wait.PollImmediateUntil(1*time.Second, func() (bool, error) {
                return s.GenericAPIServer.StorageVersionManager.Completed(), nil
            }, hookContext.StopCh)
            return nil
        })
    }

    return s, nil
}
```

##### APIAggregator

```go
// APIAggregator 包含 Kubernetes 集群主节点/ API 服务器的状态。
type APIAggregator struct {
	GenericAPIServer *genericapiserver.GenericAPIServer

	// 用于更容易地嵌入
	APIRegistrationInformers informers.SharedInformerFactory

	delegateHandler http.Handler

	// proxyCurrentCertKeyContent 包含用于标识此代理的客户端证书。支持的 APIServices 使用此证书确认代理的身份
	proxyCurrentCertKeyContent certKeyFunc
	proxyTransportDial         *transport.DialHolder

	// proxyHandlers 是当前注册的代理处理程序，以 apiservice.name 为键
	proxyHandlers map[string]*proxyHandler
	// handledGroups 是已处理的组的集合
	handledGroups sets.String

	// lister 用于基于控制器状态为 /apis/<group> 聚合查找添加组处理
	lister listers.APIServiceLister

	// 用于确定聚合器路由的信息
	serviceResolver ServiceResolver

	// 如果这些配置非空，则启用 swagger 和/或 OpenAPI。
	openAPIConfig *openapicommon.Config

	// 如果这些配置非空，则启用 OpenAPI V3
	openAPIV3Config *openapicommon.Config

	// openAPIAggregationController 下载并合并 OpenAPI v2 规范。
	openAPIAggregationController *openapicontroller.AggregationController

	// openAPIV3AggregationController 下载并缓存 OpenAPI v3 规范。
	openAPIV3AggregationController *openapiv3controller.AggregationController

	// discoveryAggregationController 下载并缓存来自所有聚合的 apiservices 的发现文档，
	// 这样当请求带有资源的发现时，它们将在 /apis 端点可用
	discoveryAggregationController DiscoveryAggregationController

	// rejectForwardingRedirects 表示是否允许转发重定向响应
	rejectForwardingRedirects bool
}
```

