## 介绍

在 kubernetes 中 kube-controller-master 组件中启动无数个 goroutine 做数据的同步等工作，比如检测 deployment 资源，然后去对 replicaset 资源做增删改查的 deployment-controller 等组件。
k8s 与其说他是个工具，不如说它是一个 `framework` 因为它支持高扩展性。比如他就可以支持我们自定义资源，而不是系统自带的。当然我们自定义资源还需要自己写一个 controller 的逻辑处理相关的事情。`kubebuilder` 现在是一个事实的标准，去做 crd 的创建和 controller 逻辑。
而 kubebuilder controller 部分使用的是 controller-tuntime 开源项目。

## 实例

```GO
// main.go
func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "8a83f983.haiyux.cc",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.ApplicationReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Application")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
```

```go
// controler.go
// ApplicationReconciler reconciles a Application object
type ApplicationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=apps.haiyux.cc,resources=applications,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps.haiyux.cc,resources=applications/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=apps.haiyux.cc,resources=applications/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Application object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.0/pkg/reconcile
func (r *ApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.Application{}).
		Owns(&v1.Pod{}).
		Complete(r)
}
```

## Manager

```GO
// Manager初始化共享依赖项，如Caches和Clients，并将它们提供给Runnables。
// 创建Controllers需要一个Manager。
type Manager interface {
	// Cluster包含各种与集群交互的方法。
	cluster.Cluster

	// Add会将所需的依赖项设置在组件上，并在调用Start时导致该组件启动。
	// 根据Runnable是否实现LeaderElectionRunnable接口，Runnable可以在非领导选举模式（始终运行）或领导选举模式（由启用的领导选举管理）下运行。
	Add(Runnable) error

	// Elected在此管理器被选为一组管理器的领导者时关闭，无论是因为它赢得了领导选举还是因为未配置领导选举。
	Elected() <-chan struct{}

	// AddHealthzCheck允许您添加Healthz检查器
	AddHealthzCheck(name string, check healthz.Checker) error

	// AddReadyzCheck允许您添加Readyz检查器
	AddReadyzCheck(name string, check healthz.Checker) error

	// Start启动所有已注册的Controllers，并阻塞，直到上下文被取消。
	// 如果使用LeaderElection，则必须在此返回后立即退出二进制文件，否则需要领导选举的组件可能在丢失领导锁后继续运行。
	Start(ctx context.Context) error

	// GetWebhookServer返回一个webhook.Server
	GetWebhookServer() webhook.Server

	// GetLogger返回此管理器的日志记录器。
	GetLogger() logr.Logger

	// GetControllerOptions返回控制器全局配置选项。
	GetControllerOptions() config.Controller
}
```

### controllerManager

```GO
// controllerManager是一个控制器管理器的实现
type controllerManager struct {
	sync.Mutex
	started bool

	stopProcedureEngaged *int64
	errChan              chan error
	runnables            *runnables

	// cluster包含各种与集群交互的方法。必需。
	cluster cluster.Cluster

	// recorderProvider用于生成将被注入到Controllers（以及EventHandlers、Sources和Predicates）中的事件记录器。
	recorderProvider *intrec.Provider

	// resourceLock形成领导选举的基础
	resourceLock resourcelock.Interface

	// leaderElectionReleaseOnCancel定义了管理器在关闭时是否应退回领导租约
	leaderElectionReleaseOnCancel bool

	// metricsServer用于提供Prometheus指标
	metricsServer metricsserver.Server

	// healthProbeListener用于提供活动探测
	healthProbeListener net.Listener

	// Readiness探测端点名称
	readinessEndpointName string

	// Liveness探测端点名称
	livenessEndpointName string

	// Readyz探测处理程序
	readyzHandler *healthz.Handler

	// Healthz探测处理程序
	healthzHandler *healthz.Handler

	// pprofListener用于提供pprof
	pprofListener net.Listener

	// controllerConfig是全局控制器选项。
	controllerConfig config.Controller

	// Logger是此管理器应使用的记录器。如果未设置任何记录器，则默认为log.Log全局记录器。
	logger logr.Logger

	// leaderElectionStopped是用于信号停止程序的内部通道，指示LeaderElection.Run(...)函数已返回，可以进行关闭。
	leaderElectionStopped chan struct{}

	// leaderElectionCancel用于取消领导选举。它与internalStopper不同，
	// 因为出于安全原因，当我们失去领导选举时，需要os.Exit()，这意味着必须推迟执行它，直到gracefulShutdown完成后。
	leaderElectionCancel context.CancelFunc

	// elected在此管理器成为一组管理器的领导者时关闭，无论是因为它赢得了领导选举还是因为未配置领导选举。
	elected chan struct{}

	webhookServer webhook.Server
	// webhookServerOnce将在GetWebhookServer()中调用，以可选地初始化webhookServer（如果未设置），并将其添加到controllerManager中。
	webhookServerOnce sync.Once

	// leaderElectionID是领导选举将用于保存领导者锁的资源的名称。
	leaderElectionID string
	// leaseDuration是非领导候选者等待强制获取领导权的持续时间。
	leaseDuration time.Duration
	// renewDeadline是领导者控制平面在放弃之前重试刷新领导权的持续时间。
	renewDeadline time.Duration
	// retryPeriod是LeaderElector客户端在尝试操作之间等待的持续时间。
	retryPeriod time.Duration

	// gracefulShutdownTimeout是runnable在管理器实际返回之前停止的持续时间。
	gracefulShutdownTimeout time.Duration

	// onStoppedLeading在领导选举租约丢失时调用。
	// 可以为测试重写。
	onStoppedLeading func()

	// shutdownCtx是在关闭期间使用的上下文。在gracefulShutdownTimeout结束后将被取消。
	// 在internalStop关闭之前，不能访问它，因为它将为空。
	shutdownCtx context.Context

	internalCtx    context.Context
	internalCancel context.CancelFunc

	// internalProceduresStop通道在协调管理器的适当关闭服务器时
	// 在管理器内部使用。此通道还用于依赖注入。
	internalProceduresStop chan struct{}
}
```

### Cluster

```GO
// Cluster提供与集群交互的各种方法。
type Cluster interface {
	// GetHTTPClient返回可用于与apiserver通信的HTTP客户端
	GetHTTPClient() *http.Client

	// GetConfig返回已初始化的Config
	GetConfig() *rest.Config

	// GetCache返回一个cache.Cache
	GetCache() cache.Cache

	// GetScheme返回已初始化的Scheme
	GetScheme() *runtime.Scheme

	// GetClient返回一个使用Config配置的client.Client。此客户端可能
	// 不是完全的“直接”客户端——例如，它可能会从缓存中读取。有关详细信息，请参阅Options.NewClient。
	GetClient() client.Client

	// GetFieldIndexer返回一个配置了客户端的client.FieldIndexer
	GetFieldIndexer() client.FieldIndexer

	// GetEventRecorderFor为提供的名称返回一个新的EventRecorder
	GetEventRecorderFor(name string) record.EventRecorder

	// GetRESTMapper返回一个RESTMapper
	GetRESTMapper() meta.RESTMapper

	// GetAPIReader返回一个将配置为使用API服务器的reader。仅当客户端不符合您的
	// 用例时才应谨慎使用它。
	GetAPIReader() client.Reader

	// Start启动集群
	Start(ctx context.Context) error
}
```

### runnables

```go
// runnables 通过将任务根据其类型（Webhook、缓存等）进行分组来处理管理器的所有任务。
type runnables struct {
	HTTPServers    *runnableGroup // HTTPServers 存储 HTTP 服务器任务的可运行组
	Webhooks       *runnableGroup // Webhooks 存储 Webhook 任务的可运行组
	Caches         *runnableGroup // Caches 存储缓存任务的可运行组
	LeaderElection *runnableGroup // LeaderElection 存储领导选举任务的可运行组
	Others         *runnableGroup // Others 存储其他类型任务的可运行组
}

// newRunnables 创建一个新的 runnables 对象。
func newRunnables(baseContext BaseContextFunc, errChan chan error) *runnables {
	return &runnables{
		HTTPServers:    newRunnableGroup(baseContext, errChan), // 创建 HTTP 服务器任务组
		Webhooks:       newRunnableGroup(baseContext, errChan), // 创建 Webhook 任务组
		Caches:         newRunnableGroup(baseContext, errChan), // 创建缓存任务组
		LeaderElection: newRunnableGroup(baseContext, errChan), // 创建领导选举任务组
		Others:         newRunnableGroup(baseContext, errChan), // 创建其他任务组
	}
}

// Add 将可运行任务添加到最接近其所属的可运行组中。
//
// Add 可以在 Start 之前和之后调用，但不能在 StopAndWait 调用期间调用。
// 当在 StopAndWait 调用期间调用时，Add 应返回错误。
// 在 Start 之前添加的任务在调用 Start 时启动。
// 在 Start 之后添加的任务将立即启动。
func (r *runnables) Add(fn Runnable) error {
	switch runnable := fn.(type) {
	case *server:
		return r.HTTPServers.Add(fn, nil) // 将 HTTP 服务器任务添加到组
	case hasCache:
		return r.Caches.Add(fn, func(ctx context.Context) bool {
			return runnable.GetCache().WaitForCacheSync(ctx) // 将缓存任务添加到组
		})
	case webhook.Server:
		return r.Webhooks.Add(fn, nil) // 将 Webhook 任务添加到组
	case LeaderElectionRunnable:
		if !runnable.NeedLeaderElection() {
			return r.Others.Add(fn, nil) // 将不需要领导选举的任务添加到其他组
		}
		return r.LeaderElection.Add(fn, nil) // 将需要领导选举的任务添加到领导选举组
	default:
		return r.LeaderElection.Add(fn, nil) // 默认添加到领导选举组
	}
}
```

#### runnableGroup

```go
// runnableGroup 管理一组可运行的任务，这些任务在调用 StopAndWait 之前应该一起运行。
//
// 可以在组已启动之后将可运行任务添加到组中，但不能在组已停止或正在关闭时添加。
type runnableGroup struct {
	ctx    context.Context
	cancel context.CancelFunc

	start        sync.Mutex
	startOnce    sync.Once
	started      bool
	startQueue   []*readyRunnable
	startReadyCh chan *readyRunnable

	stop     sync.RWMutex
	stopOnce sync.Once
	stopped  bool

	// errChan 是调用者传递的错误通道
	// 当发生错误时，所有错误都将转发到此通道。
	errChan chan error

	// ch 是内部通道，用于读取可运行任务。
	ch chan *readyRunnable

	// wg 是一个内部的 sync.WaitGroup，用于在返回之前正确停止
	// 并等待所有可运行任务完成。
	wg *sync.WaitGroup
}

func newRunnableGroup(baseContext BaseContextFunc, errChan chan error) *runnableGroup {
	r := &runnableGroup{
		startReadyCh: make(chan *readyRunnable),
		errChan:      errChan,
		ch:           make(chan *readyRunnable),
		wg:           new(sync.WaitGroup),
	}

	r.ctx, r.cancel = context.WithCancel(baseContext())
	return r
}

// Started 返回 true，如果组已启动。
func (r *runnableGroup) Started() bool {
	r.start.Lock()
	defer r.start.Unlock()
	return r.started
}

// Start 启动组，并等待所有最初注册的可运行任务启动。
// 只能调用一次，后续的调用不会产生影响。
func (r *runnableGroup) Start(ctx context.Context) error {
	var retErr error

	r.startOnce.Do(func() {
		defer close(r.startReadyCh)

		// 启动内部的协调器。
		go r.reconcile()

		// 启动组并排队所有之前添加的可运行任务。
		r.start.Lock()
		r.started = true
		for _, rn := range r.startQueue {
			rn.signalReady = true
			r.ch <- rn
		}
		r.start.Unlock()

		// 如果没有任务排队，直接返回。
		if len(r.startQueue) == 0 {
			return
		}

		// 等待所有可运行任务发出信号。
		for {
			select {
			case <-ctx.Done():
				if err := ctx.Err(); !errors.Is(err, context.Canceled) {
					retErr = err
				}
			case rn := <-r.startReadyCh:
				for i, existing := range r.startQueue {
					if existing == rn {
						// 从排队中删除此项。
						r.startQueue = append(r.startQueue[:i], r.startQueue[i+1:]...)
						break
					}
				}
				// 如果队列为空，结束等待并返回。
				if len(r.startQueue) == 0 {
					return
				}
			}
		}
	})

	return retErr
}

// reconcile 是添加到该组的每个可运行任务的主要入口点。
// 其主要工作是从内部通道读取可运行任务并安排它们，同时跟踪它们的状态。
func (r *runnableGroup) reconcile() {
	for runnable := range r.ch {
		// 处理停止。
		// 如果已调用停止操作，则要避免向 WaitGroup 添加新的 goroutine，
		// 因为 Wait() 在调用 Wait() 后调用 Add() 会导致恐慌。
		{
			r.stop.RLock()
			if r.stopped {
				// 如果已停止，丢弃可运行任务。
				r.errChan <- errRunnableGroupStopped
				r.stop.RUnlock()
				continue
			}

			// 为什么会有这个？
			// 当调用 StopAndWait 时，如果一个可运行任务正在添加中，
			// 我们可能会陷入这样的情况：
			// 在 StopAndWait 调用 Wait() 后调用 Add()，这将导致恐慌。
			r.wg.Add(1)
			r.stop.RUnlock()
		}

		// 启动可运行任务。
		go func(rn *readyRunnable) {
			go func() {
				if rn.Check(r.ctx) {
					if rn.signalReady {
						r.startReadyCh <- rn
					}
				}
			}()

			// 如果返回，可运行任务已干净地结束
			// 或将错误发送到通道。
			//
			// 在这里始终应减少 WaitGroup。
			defer r.wg.Done()

			// 启动可运行任务。
			if err := rn.Start(r.ctx); err != nil {
				r.errChan <- err
			}
		}(runnable)
	}
}

// Add 可以在 Start 之前和之后调用，但不能在 StopAndWait 调用期间调用。
// 在 StopAndWait 调用期间调用 Add 应返回错误。
func (r *runnableGroup) Add(rn Runnable, ready runnableCheck) error {
	r.stop.RLock()
	if r.stopped {
		r.stop.RUnlock()
		return errRunnableGroupStopped
	}
	r.stop.RUnlock()

	if ready == nil {
		ready = func(_ context.Context) bool { return true }
	}

	readyRunnable := &readyRunnable{
		Runnable: rn,
		Check:    ready,
	}

	// 处理启动。
	// 如果整个可运行组尚未启动，
	// 我们希望缓冲可运行任务并允许 Start()
	// 以后重新排队它们。
	{
		r.start.Lock()

		// 检查是否已启动。
		if !r.started {
			// 如果尚未启动，将可运行任务存储在内部。
			r.startQueue = append(r.startQueue, readyRunnable)
			r.start.Unlock()
			return nil
		}
		r.start.Unlock()
	}

	// 将可运行任务排入通道。
	r.ch <- readyRunnable
	return nil
}

// StopAndWait 在返回之前等待所有可运行任务完成。
func (r *runnableGroup) StopAndWait(ctx context.Context) {
	r.stopOnce.Do(func() {
		// 在完成后关闭协调器通道。
		defer close(r.ch)

		_ = r.Start(ctx)
		r.stop.Lock()
		// 存储 stopped 变量，以便在此期间不接受任何新的可运行任务。
		r.stopped = true
		r.stop.Unlock()

		// 取消内部通道。
		r.cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			// 等待所有可运行任务完成。
			r.wg.Wait()
		}()

		select {
		case <-done:
			// 完成，退出。
		case <-ctx.Done():
			// 调用上下文已经过期，退出。
		}
	})
}
```



### New

```GO
// New返回一个用于创建Controllers的新Manager。
// 请注意，如果给定配置中的ContentType未设置，将为Kubernetes的所有内置资源使用"application/vnd.kubernetes.protobuf"，
// 并且对于其他类型，包括所有CRD资源，将使用"application/json"。
func New(config *rest.Config, options Options) (Manager, error) {
	if config == nil {
		return nil, errors.New("必须指定Config")
	}
	// 为选项字段设置默认值
	options = setOptionsDefaults(options)

	cluster, err := cluster.New(config, func(clusterOptions *cluster.Options) {
		clusterOptions.Scheme = options.Scheme
		clusterOptions.MapperProvider = options.MapperProvider
		clusterOptions.Logger = options.Logger
		clusterOptions.NewCache = options.NewCache
		clusterOptions.NewClient = options.NewClient
		clusterOptions.Cache = options.Cache
		clusterOptions.Client = options.Client
		clusterOptions.EventBroadcaster = options.EventBroadcaster //nolint:staticcheck
	})
	if err != nil {
		return nil, err
	}

	config = rest.CopyConfig(config)
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	// 创建记录器提供程序以注入组件的事件记录器。
	// TODO（directxman12）：事件提供程序的日志应具有特定于注入的特定控制器的上下文（名称、标签等），
	// 而不是像这里一样的通用控制器。
	recorderProvider, err := options.newRecorderProvider(config, cluster.GetHTTPClient(), cluster.GetScheme(), options.Logger.WithName("events"), options.makeBroadcaster)
	if err != nil {
		return nil, err
	}

	// 创建资源锁以启用领导选举
	var leaderConfig *rest.Config
	var leaderRecorderProvider *intrec.Provider

	if options.LeaderElectionConfig == nil {
		leaderConfig = rest.CopyConfig(config)
		leaderRecorderProvider = recorderProvider
	} else {
		leaderConfig = rest.CopyConfig(options.LeaderElectionConfig)
		scheme := cluster.GetScheme()
		err := corev1.AddToScheme(scheme)
		if err != nil {
			return nil, err
		}
		err = coordinationv1.AddToScheme(scheme)
		if err != nil {
			return nil, err
		}
		httpClient, err := rest.HTTPClientFor(options.LeaderElectionConfig)
		if err != nil {
			return nil, err
		}
		leaderRecorderProvider, err = options.newRecorderProvider(leaderConfig, httpClient, scheme, options.Logger.WithName("events"), options.makeBroadcaster)
		if err != nil {
			return nil, err
		}
	}

	var resourceLock resourcelock.Interface
	if options.LeaderElectionResourceLockInterface != nil && options.LeaderElection {
		resourceLock = options.LeaderElectionResourceLockInterface
	} else {
		resourceLock, err = options.newResourceLock(leaderConfig, leaderRecorderProvider, leaderelection.Options{
			LeaderElection:             options.LeaderElection,
			LeaderElectionResourceLock: options.LeaderElectionResourceLock,
			LeaderElectionID:           options.LeaderElectionID,
			LeaderElectionNamespace:    options.LeaderElectionNamespace,
		})
		if err != nil {
			return nil, err
		}
	}

	// 创建指标服务器。
	metricsServer, err := options.newMetricsServer(options.Metrics, config, cluster.GetHTTPClient())
	if err != nil {
		return nil, err
	}

	// 创建健康探测监听器。如果绑定地址无效或已在使用中，将引发错误。
	healthProbeListener, err := options.newHealthProbeListener(options.HealthProbeBindAddress)
	if err != nil {
		return nil, err
	}

	// 创建pprof监听器。如果绑定地址无效或已在使用中，将引发错误。
	pprofListener, err := options.newPprofListener(options.PprofBindAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to new pprof listener: %w", err)
	}

	errChan := make(chan error, 1)
	runnables := newRunnables(options.BaseContext, errChan)
	return &controllerManager{
		stopProcedureEngaged:          pointer.Int64(0),
		cluster:                       cluster,
		runnables:                     runnables,
		errChan:                       errChan,
		recorderProvider:              recorderProvider,
		resourceLock:                  resourceLock,
		metricsServer:                 metricsServer,
		controllerConfig:              options.Controller,
		logger:                        options.Logger,
		elected:                       make(chan struct{}),
		webhookServer:                 options.WebhookServer,
		leaderElectionID:              options.LeaderElectionID,
		leaseDuration:                 *options.LeaseDuration,
		renewDeadline:                 *options.RenewDeadline,
		retryPeriod:                   *options.RetryPeriod,
		healthProbeListener:           healthProbeListener,
		readinessEndpointName:         options.ReadinessEndpointName,
		livenessEndpointName:          options.LivenessEndpointName,
		pprofListener:                 pprofListener,
		gracefulShutdownTimeout:       *options.GracefulShutdownTimeout,
		internalProceduresStop:        make(chan struct{}),
		leaderElectionStopped:         make(chan struct{}),
		leaderElectionReleaseOnCancel: options.LeaderElectionReleaseOnCancel,
	}, nil
}
```

### Start

```go
// Start 启动管理器并无限等待。
// 只有两种情况会导致 Start 返回：
// 在内部操作（如 leader 选举、缓存启动、Webhooks 等）中发生了错误，
// 或者上下文被取消。
func (cm *controllerManager) Start(ctx context.Context) (err error) {
	cm.Lock()
	if cm.started {
		cm.Unlock()
		return errors.New("manager already started")
	}
	cm.started = true

	var ready bool
	defer func() {
		// 只有在我们尚未达到
		// 内部准备条件时才解锁管理器。
		if !ready {
			cm.Unlock()
		}
	}()

	// 初始化内部上下文。
	cm.internalCtx, cm.internalCancel = context.WithCancel(ctx)

	// 这个通道指示停止已完成，换句话说，所有可运行任务都已返回或停止请求超时
	stopComplete := make(chan struct{})
	defer close(stopComplete)
	// 必须在关闭 stopComplete 之后延迟执行，否则会发生死锁。
	defer func() {
		// https://hips.hearstapps.com/hmg-prod.s3.amazonaws.com/images/gettyimages-459889618-1533579787.jpg
		stopErr := cm.engageStopProcedure(stopComplete)
		if stopErr != nil {
			if err != nil {
				// Utilerrors.Aggregate 允许对所有包含的错误使用 errors.Is
				// 而 fmt.Errorf 只允许包装最多一个错误，这意味着找不到另一个错误。
				err = kerrors.NewAggregate([]error{err, stopErr})
			} else {
				err = stopErr
			}
		}
	}()

	// 添加 cluster 可运行任务。
	if err := cm.add(cm.cluster); err != nil {
		return fmt.Errorf("failed to add cluster to runnables: %w", err)
	}

	// 无论控制器是否为 leader，都应该提供指标。
	// （如果我们不为非 leader 提供指标，Prometheus 仍然会抓取
	// Pod，但会收到连接被拒绝的错误）。
	if cm.metricsServer != nil {
		// 注意：我们直接将指标服务器添加到 HTTPServers 中，
		// 这是因为在 cm.runnables.Add 中匹配 metricsserver.Server 接口会非常脆弱。
		if err := cm.runnables.HTTPServers.Add(cm.metricsServer, nil); err != nil {
			return fmt.Errorf("failed to add metrics server: %w", err)
		}
	}

	// 提供健康探针。
	if cm.healthProbeListener != nil {
		if err := cm.addHealthProbeServer(); err != nil {
			return fmt.Errorf("failed to add health probe server: %w", err)
		}
	}

	// 添加 pprof 服务器。
	if cm.pprofListener != nil {
		if err := cm.addPprofServer(); err != nil {
			return fmt.Errorf("failed to add pprof server: %w", err)
		}
	}

	// 首先启动任何内部 HTTP 服务器，包括健康探针、指标和启用的分析。
	//
	// 警告：内部 HTTP 服务器必须在填充任何缓存之前启动，否则会阻塞
	// 转换 Webhooks 以用于提供服务，这使得缓存永远不会准备好。
	if err := cm.runnables.HTTPServers.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start HTTP servers: %w", err)
		}
	}

	// 启动任何 Webhook 服务器，包括注册的转换、验证和默认值
	// Webhooks。
	//
	// 警告：Webhook 必须在填充任何缓存之前启动，否则会有竞态条件
	// 在转换 Webhooks 和缓存同步（通常是初始列表）之间，这会导致 Webhooks
	// 永远不会启动，因为没有缓存可以填充。
	if err := cm.runnables.Webhooks.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start webhooks: %w", err)
		}
	}

	// 启动并等待缓存。
	if err := cm.runnables.Caches.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start caches: %w", err)
		}
	}

	// 在缓存同步后启动非 leader 选举可运行任务。
	if err := cm.runnables.Others.Start(cm.internalCtx); err != nil {
		if err != nil {
			return fmt.Errorf("failed to start other runnables: %w", err)
		}
	}

	// 启动 leader 选举和所有所需的可运行任务。
	{
		ctx, cancel := context.WithCancel(context.Background())
		cm.leaderElectionCancel = cancel
		go func() {
			if cm.resourceLock != nil {
				if err := cm.startLeaderElection(ctx); err != nil {
					cm.errChan <- err
				}
			} else {
				// 将未启用 leader 选举的情况视为已选中。
				if err := cm.startLeaderElectionRunnables(); err != nil {
					cm.errChan <- err
				}
				close(cm.elected)
			}
		}()
	}

	ready = true
	cm.Unlock()
	select {
	case <-ctx.Done():
		// 完成
		return nil
	case err := <-cm.errChan:
		// 启动或运行可运行任务时发生错误
		return err
	}
}
```

## Builder

```go
// Builder 用于构建一个 Controller。
type Builder struct {
    forInput         ForInput
    ownsInput        []OwnsInput
    watchesInput     []WatchesInput
    mgr              manager.Manager
    globalPredicates []predicate.Predicate
    ctrl             controller.Controller
    ctrlOptions      controller.Options
    name             string
}

// ControllerManagedBy 返回一个由提供的 Manager 启动的新控制器构建器。
func ControllerManagedBy(m manager.Manager) *Builder {
    return &Builder{mgr: m}
}
```

### Controller

```go
// Controller实现了一个Kubernetes API。Controller管理一个工作队列，该队列从源源不断的reconcile.Requests中获取任务。
// 工作通过reconcile.Reconciler为每个入队的项目执行。通常工作是读取和写入Kubernetes对象，以使系统状态与对象Spec中指定的状态匹配。
type Controller interface {
    // Reconciler通过Namespace/Name调用以调和对象。
    reconcile.Reconciler

    // Watch接受源提供的事件，并使用EventHandler在事件发生时排队reconcile.Requests。
    //
    // Watch可以提供一个或多个Predicates以在将事件传递给EventHandler之前对事件进行筛选。
    // 只有在所有提供的Predicates评估为true时，事件才会传递给EventHandler。
    Watch(src source.Source, eventhandler handler.EventHandler, predicates ...predicate.Predicate) error

    // Start启动Controller。Start会阻塞，直到上下文关闭或控制器启动时出现错误。
    Start(ctx context.Context) error

    // GetLogger返回带有基本信息的此控制器记录器。
    GetLogger() logr.Logger
}

// Controller实现了controller.Controller。
type Controller struct {
    // Name用于唯一标识跟踪、记录和监控中的Controller。Name是必需的。
    Name string

    // MaxConcurrentReconciles是可以并行运行的最大Reconciles数。默认为1。
    MaxConcurrentReconciles int

    // Reconciler是可以随时调用的函数，该函数具有对象的Name/Namespace，并确保系统的状态与对象中指定的状态相匹配。
    // 默认为DefaultReconcileFunc。
    Do reconcile.Reconciler

    // MakeQueue在控制器准备好启动后构建此控制器的队列。
    // 这是因为标准的Kubernetes工作队列会立即启动自身，如果重复调用controller.New，可能会导致goroutine泄漏。
    MakeQueue func() workqueue.RateLimitingInterface

    // Queue是一个listeningQueue，它从Informers监听事件并将对象键添加到队列以进行处理。
    Queue workqueue.RateLimitingInterface

    // mu用于同步Controller设置
    mu sync.Mutex

    // Started如果Controller已启动，则为true
    Started bool

    // ctx是传递给Start()并在启动监视器时使用的上下文。
    //
    // 根据文档，不应该将上下文存储在结构体中：https://golang.org/pkg/context，
    // 虽然通常我们始终努力遵循最佳实践，但我们认为这是一种遗留情况，应该进行重大重构和重新设计，以允许不在结构体中存储上下文。
    ctx context.Context

    // CacheSyncTimeout是等待缓存同步的超时时间限制
    // 如果未设置，默认为2分钟。
    CacheSyncTimeout time.Duration

    // startWatches在控制器启动时维护要启动的源、处理程序和谓词的列表。
    startWatches []watchDescription

    // LogConstructor用于构造日志记录器，然后在调和期间记录消息，或例如在启动观察时。
    // 注意：LogConstructor必须能够处理nil请求，因为我们也在调和之外使用它。
    LogConstructor func(request *reconcile.Request) logr.Logger

    // RecoverPanic指示是否应恢复由reconcile引起的panic。
    RecoverPanic *bool

    // LeaderElected指示控制器是否是领导者选举或始终运行。
    LeaderElected *bool
}

// watchDescription包含启动观察所需的所有信息。
type watchDescription struct {
    src        source.Source
    handler    handler.EventHandler
    predicates []predicate.Predicate
}
```

#### Reconcile

```go
// Reconcile implements reconcile.Reconciler.
func (c *Controller) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
    // 在函数结束时处理 panic
    defer func() {
        if r := recover(); r != nil {
            if c.RecoverPanic != nil && *c.RecoverPanic {
                for _, fn := range utilruntime.PanicHandlers {
                    fn(r)
                }
                err = fmt.Errorf("panic: %v [recovered]", r)
                return
            }

            log := logf.FromContext(ctx)
            log.Info(fmt.Sprintf("Observed a panic in reconciler: %v", r))
            panic(r)
        }
    }()
    
    // 调用控制器的 Do.Reconcile 方法来执行调谐任务
    return c.Do.Reconcile(ctx, req)
}
```

#### Watch

```go
// Watch implements controller.Controller.
func (c *Controller) Watch(src source.Source, evthdler handler.EventHandler, prct ...predicate.Predicate) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    // 如果控制器尚未启动，则将观察者（watch）存储在本地并返回。
    // 这些观察者将一直保留在控制器结构体上，直到管理器或用户调用 Start(...)。
    if !c.Started {
        c.startWatches = append(c.startWatches, watchDescription{src: src, handler: evthdler, predicates: prct})
        return nil
    }

    c.LogConstructor(nil).Info("Starting EventSource", "source", src)
    return src.Start(c.ctx, evthdler, c.Queue, prct...)
}

```

#### NeedLeaderElection

```go
// NeedLeaderElection implements the manager.LeaderElectionRunnable interface.
func (c *Controller) NeedLeaderElection() bool {
    if c.LeaderElected == nil {
        return true
    }
    return *c.LeaderElected
}
```

#### Start

```go
// Start implements controller.Controller.
func (c *Controller) Start(ctx context.Context) error {
    // 使用 IIFE（立即调用函数表达式）来获取正确的锁处理，
    // 但在外部锁定以正确处理队列关闭
    c.mu.Lock()
    if c.Started {
        return errors.New("controller was started more than once. This is likely to be caused by being added to a manager multiple times")
    }

    c.initMetrics()

    // 设置内部上下文
    c.ctx = ctx

    c.Queue = c.MakeQueue()
    go func() {
        <-ctx.Done()
        c.Queue.ShutDown()
    }()

    wg := &sync.WaitGroup{}
    err := func() error {
        defer c.mu.Unlock()

        // TODO(pwittrock): 重新考虑 HandleCrash
        defer utilruntime.HandleCrash()

        // 启动观察者（watchers）*之前*尝试等待缓存同步，以便它们有机会注册其预期的缓存
        for _, watch := range c.startWatches {
            c.LogConstructor(nil).Info("Starting EventSource", "source", fmt.Sprintf("%s", watch.src))

            if err := watch.src.Start(ctx, watch.handler, c.Queue, watch.predicates...); err != nil {
                return err
            }
        }

        // 启动 SharedIndexInformer 工厂以开始填充 SharedIndexInformer 缓存
        c.LogConstructor(nil).Info("Starting Controller")

        for _, watch := range c.startWatches {
            syncingSource, ok := watch.src.(source.SyncingSource)
            if !ok {
                continue
            }

            if err := func() error {
                // 使用具有超时的上下文来启动观察者和同步缓存
                sourceStartCtx, cancel := context.WithTimeout(ctx, c.CacheSyncTimeout)
                defer cancel()

                // WaitForSync 等待明确的超时，如果出现错误或超时，则返回
                if err := syncingSource.WaitForSync(sourceStartCtx); err != nil {
                    err := fmt.Errorf("failed to wait for %s caches to sync: %w", c.Name, err)
                    c.LogConstructor(nil).Error(err, "Could not wait for Cache to sync")
                    return err
                }

                return nil
            }(); err != nil {
                return err
            }
        }

        // 所有观察者都已经启动，我们可以重置本地切片
        // 我们不应该保留观察者超过必要的时间，每个观察者源都可以拥有一个后备缓存，
        // 如果我们保留对其的引用，它就不会被垃圾回收。
        c.startWatches = nil

        // 启动处理资源的工作线程
        c.LogConstructor(nil).Info("Starting workers", "worker count", c.MaxConcurrentReconciles)
        wg.Add(c.MaxConcurrentReconciles)
        for i := 0; i < c.MaxConcurrentReconciles; i++ {
            go func() {
                defer wg.Done()
                // 运行一个工作线程，只需出队项目、处理它们并标记为完成。
                // 它强制执行调和处理程序永远不会并发调用相同的对象。
                for c.processNextWorkItem(ctx) {
                }
            }()
        }

        c.Started = true
        return nil
    }()
    if err != nil {
        return err
    }

    <-ctx.Done()
    c.LogConstructor(nil).Info("Shutdown signal received, waiting for all workers to finish")
    wg.Wait()
    c.LogConstructor(nil).Info("All workers finished")
    return nil
}
```

##### processNextWorkItem

```go
// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the reconcileHandler.
func (c *Controller) processNextWorkItem(ctx context.Context) bool {
    obj, shutdown := c.Queue.Get()
    if shutdown {
        // 停止工作
        return false
    }

    // 我们在这里调用 Done，以便工作队列知道我们已经完成了
    // 处理此项目。如果我们不想将此工作项重新排队，我们还必须记得调用 Forget。
    // 例如，如果发生瞬态错误，我们不会调用 Forget，而是将该项放回工作队列，
    // 然后在退避期后再次尝试。
    defer c.Queue.Done(obj)

    ctrlmetrics.ActiveWorkers.WithLabelValues(c.Name).Add(1)
    defer ctrlmetrics.ActiveWorkers.WithLabelValues(c.Name).Add(-1)

    c.reconcileHandler(ctx, obj)
    return true
}
```

### ForInput

```GO
// ForInput 代表由 For 方法设置的信息。
type ForInput struct {
    object           client.Object
    predicates       []predicate.Predicate
    objectProjection objectProjection
    err              error
}

// For 定义了要 *调解* 的对象类型，并配置 ControllerManagedBy 以响应创建 / 删除 / 更新事件
// 通过 *调解对象*。
// 这相当于调用 Watches(&source.Kind{Type: apiType}, &handler.EnqueueRequestForObject{})。
func (blder *Builder) For(object client.Object, opts ...ForOption) *Builder {
    if blder.forInput.object != nil {
        blder.forInput.err = fmt.Errorf("For(...) 应该只被调用一次，无法为调解分配多个对象")
        return blder
    }
    input := ForInput{object: object}
    for _, opt := range opts {
        opt.ApplyToFor(&input)
    }

    blder.forInput = input
    return blder
}
```

### OwnsInput

```GO
// OwnsInput 代表由 Owns 方法设置的信息。
type OwnsInput struct {
    matchEveryOwner  bool
    object           client.Object
    predicates       []predicate.Predicate
    objectProjection objectProjection
}

// Owns 定义了 ControllerManagedBy 生成的对象类型，并配置 ControllerManagedBy 以响应创建 / 删除 / 更新事件
// 通过 *调解所有者对象*。
//
// 默认行为只调解给定类型的第一个控制器类型的 OwnerReference。
// 使用 Owns(object, builder.MatchEveryOwner) 来调解所有的所有者。
//
// 默认情况下，这相当于调用
// Watches(object, handler.EnqueueRequestForOwner([...], ownerType, OnlyControllerOwner())。
func (blder *Builder) Owns(object client.Object, opts ...OwnsOption) *Builder {
    input := OwnsInput{object: object}
    for _, opt := range opts {
        opt.ApplyToOwns(&input)
    }

    blder.ownsInput = append(blder.ownsInput, input)
    return blder
}
```

### WatchesInput

```GO
// WatchesInput 代表由 Watches 方法设置的信息。
type WatchesInput struct {
    src              source.Source
    eventHandler     handler.EventHandler
    predicates       []predicate.Predicate
    objectProjection objectProjection
}

// Watches 定义要观察的对象类型，并配置 ControllerManagedBy 以响应创建 / 删除 / 更新事件
// 通过给定的 EventHandler *调解对象*。
//
// 这相当于调用
// WatchesRawSource(source.Kind(cache, object), eventHandler, opts...)。
func (blder *Builder) Watches(object client.Object, eventHandler handler.EventHandler, opts ...WatchesOption) *Builder {
    src := source.Kind(blder.mgr.GetCache(), object)
    return blder.WatchesRawSource(src, eventHandler, opts...)
}
```

### WatchesMetadata

```GO
// WatchesMetadata 与 Watches 相同，但强制内部缓存仅监视 PartialObjectMetadata。
//
// 当监视大量对象、非常大的对象或只知道 GVK 而不知道结构的对象时，这很有用。
// 在调解器中获取对象时，您需要将 metav1.PartialObjectMetadata 传递给客户端，否则将得到一个重复的结构化或非结构化缓存。
//
// 当监视仅包含元数据的资源时，例如 v1.Pod，您不应该使用 v1.Pod 类型进行 Get 和 List。
// 相反，您应该使用特殊的 metav1.PartialObjectMetadata 类型。
//
// ❌ 不正确：
//
//   pod := &v1.Pod{}
//   mgr.GetClient().Get(ctx, nsAndName, pod)
//
// ✅ 正确：
//
//   pod := &metav1.PartialObjectMetadata{}
//   pod.SetGroupVersionKind(schema.GroupVersionKind{
//       Group:   "",
//       Version: "v1",
//       Kind:    "Pod",
//   })
//   mgr.GetClient().Get(ctx, nsAndName, pod)
//
// 在第一种情况下，controller-runtime 将在元数据缓存之上为具体类型创建另一个缓存；
// 这会增加内存消耗并导致缓存不同步的竞争条件。
func (blder *Builder) WatchesMetadata(object client.Object, eventHandler handler.EventHandler, opts ...WatchesOption) *Builder {
    opts = append(opts, OnlyMetadata)
    return blder.Watches(object, eventHandler, opts...)
}
```

### WatchesRawSource

```GO
// WatchesRawSource 通过构建器公开更低级别的 ControllerManagedBy Watches 函数。
// 指定的谓词仅对给定的源进行注册。
//
// 停止！请考虑使用 For(...)、Owns(...)、Watches(...)、WatchesMetadata(...) 替代。
// 该方法仅用于更高级别的用例，大多数用户应使用其中一个更高级别的功能。
func (blder *Builder) WatchesRawSource(src source.Source, eventHandler handler.EventHandler, opts ...WatchesOption) *Builder {
    input := WatchesInput{src: src, eventHandler: eventHandler}
    for _, opt := range opts {
        opt.ApplyToWatches(&input)
    }

    blder.watchesInput = append(blder.watchesInput, input)
    return blder
}
```

### WithEventFilter

```GO
// WithEventFilter 设置事件筛选器，以筛选最终触发调解的创建/更新/删除/通用事件。
// 例如，根据资源版本是否更改来进行筛选。
// 给定的谓词将添加到所有监视的对象。
// 默认为空列表。
func (blder *Builder) WithEventFilter(p predicate.Predicate) *Builder {
    blder.globalPredicates = append(blder.globalPredicates, p)
    return blder
}
```

### WithOptions

```GO
// WithOptions 覆盖了在 doController 中使用的控制器选项。默认为空。
func (blder *Builder) WithOptions(options controller.Options) *Builder {
    blder.ctrlOptions = options
    return blder
}
```

### WithLogConstructor

```GO
// WithLogConstructor 覆盖了控制器选项中的 LogConstructor。
func (blder *Builder) WithLogConstructor(logConstructor func(*reconcile.Request) logr.Logger) *Builder {
    blder.ctrlOptions.LogConstructor = logConstructor
    return blder
}
```

### Named

```GO
// Named 设置控制器的名称为给定的名称。名称显示在度量标准等中，因此应该是兼容 Prometheus 的名称
// （只包含下划线和字母数字字符）。
//
// 默认情况下，控制器的名称使用其类型的小写版本。
func (blder *Builder) Named(name string) *Builder {
    blder.name = name
    return blder
}
```

### Complete

```GO
// Complete 构建 Application 控制器。
func (blder *Builder) Complete(r reconcile.Reconciler) error {
    _, err := blder.Build(r)
    return err
}
```

### Build

```GO
// Build 构建 Application 控制器并返回创建的 Controller。
func (blder *Builder) Build(r reconcile.Reconciler) (controller.Controller, error) {
    if r == nil {
        return nil, fmt.Errorf("必须提供非 nil 的 Reconciler")
    }
    if blder.mgr == nil {
        return nil, fmt.Errorf("必须提供非 nil 的 Manager")
    }
    if blder.forInput.err != nil {
        return nil, blder.forInput.err
    }

    // 设置 ControllerManagedBy
    if err := blder.doController(r); err != nil {
        return nil, err
    }

    // 设置 Watch
    if err := blder.doWatch(); err != nil {
        return nil, err
    }

    return blder.ctrl, nil
}
```

#### doWatch

```go
func (blder *Builder) doWatch() error {
    // 调解类型
    if blder.forInput.object != nil {
        obj, err := blder.project(blder.forInput.object, blder.forInput.objectProjection)
        if err != nil {
            return err
        }
        src := source.Kind(blder.mgr.GetCache(), obj)
        hdler := &handler.EnqueueRequestForObject{}
        allPredicates := append([]predicate.Predicate(nil), blder.globalPredicates...)
        allPredicates = append(allPredicates, blder.forInput.predicates...)
        if err := blder.ctrl.Watch(src, hdler, allPredicates...); err != nil {
            return err
        }
    }

    // Watches 管理的类型
    if len(blder.ownsInput) > 0 && blder.forInput.object == nil {
        return errors.New("Owns() 只能与 For() 一起使用")
    }
    for _, own := range blder.ownsInput {
        obj, err := blder.project(own.object, own.objectProjection)
        if err != nil {
            return err
        }
        src := source.Kind(blder.mgr.GetCache(), obj)
        opts := []handler.OwnerOption{}
        if !own.matchEveryOwner {
            opts = append(opts, handler.OnlyControllerOwner())
        }
        hdler := handler.EnqueueRequestForOwner(
            blder.mgr.GetScheme(), blder.mgr.GetRESTMapper(),
            blder.forInput.object,
            opts...,
        )
        allPredicates := append([]predicate.Predicate(nil), blder.globalPredicates...)
        allPredicates = append(allPredicates, own.predicates...)
        if err := blder.ctrl.Watch(src, hdler, allPredicates...); err != nil {
            return err
        }
    }

    // 进行观察请求
    if len(blder.watchesInput) == 0 && blder.forInput.object == nil {
        return errors.New("没有配置任何观察，控制器永远不会被触发。使用 For()、Owns() 或 Watches() 来设置它们")
    }
    for _, w := range blder.watchesInput {
        // 如果此观察的源是 Kind 类型，则进行投影。
        if srcKind, ok := w.src.(*internalsource.Kind); ok {
            typeForSrc, err := blder.project(srcKind.Type, w.objectProjection)
            if err != nil {
                return err
            }
            srcKind.Type = typeForSrc
        }
        allPredicates := append([]predicate.Predicate(nil), blder.globalPredicates...)
        allPredicates = append(allPredicates, w.predicates...)
        if err := blder.ctrl.Watch(w.src, w.eventHandler, allPredicates...); err != nil {
            return err
        }
    }
    return nil
}
```

##### project

```go
func (blder *Builder) project(obj client.Object, proj objectProjection) (client.Object, error) {
    switch proj {
    case projectAsNormal:
        return obj, nil
    case projectAsMetadata:
        metaObj := &metav1.PartialObjectMetadata{}
        gvk, err := getGvk(obj, blder.mgr.GetScheme())
        if err != nil {
            return nil, fmt.Errorf("无法确定 %T 的 GVK 以进行仅元数据监视： %w", obj, err)
        }
        metaObj.SetGroupVersionKind(gvk)
        return metaObj, nil
    default:
        panic(fmt.Sprintf("类型 %T 上的意外投影类型 %v，这是不可能的，因为这是一个内部字段", proj, obj))
    }
}
```

#### doController

```go
func (blder *Builder) doController(r reconcile.Reconciler) error {
    globalOpts := blder.mgr.GetControllerOptions()

    ctrlOptions := blder.ctrlOptions
    if ctrlOptions.Reconciler != nil && r != nil {
        return errors.New("通过 WithOptions() 和 Build() 或 Complete() 设置了调解器")
    }
    if ctrlOptions.Reconciler == nil {
        ctrlOptions.Reconciler = r
    }

    // 从我们正在调解的对象中检索 GVK
    // 以预填充记录器信息，并可选地生成默认名称。
    var gvk schema.GroupVersionKind
    hasGVK := blder.forInput.object != nil
    if hasGVK {
        var err error
        gvk, err = getGvk(blder.forInput.object, blder.mgr.GetScheme())
        if err != nil {
            return err
        }
    }

    // 设置并发性。
    if ctrlOptions.MaxConcurrentReconciles == 0 && hasGVK {
        groupKind := gvk.GroupKind().String()

        if concurrency, ok := globalOpts.GroupKindConcurrency[groupKind]; ok && concurrency > 0 {
            ctrlOptions.MaxConcurrentReconciles = concurrency
        }
    }

    // 设置缓存同步超时。
    if ctrlOptions.CacheSyncTimeout == 0 && globalOpts.CacheSyncTimeout > 0 {
        ctrlOptions.CacheSyncTimeout = globalOpts.CacheSyncTimeout
    }

    controllerName, err := blder.getControllerName(gvk, hasGVK)
    if err != nil {
        return err
    }

    // 设置记录器。
    if ctrlOptions.LogConstructor == nil {
        log := blder.mgr.GetLogger().WithValues(
            "controller", controllerName,
        )
        if hasGVK {
            log = log.WithValues(
                "controllerGroup", gvk.Group,
                "controllerKind", gvk.Kind,
            )
        }

        ctrlOptions.LogConstructor = func(req *reconcile.Request) logr.Logger {
            log := log
            if req != nil {
                if hasGVK {
                    log = log.WithValues(gvk.Kind, klog.KRef(req.Namespace, req.Name))
                }
                log = log.WithValues(
                    "namespace", req.Namespace, "name", req.Name,
                )
            }
            return log
        }
    }

    // 构建控制器并返回。
    blder.ctrl, err = newController(controllerName, blder.mgr, ctrlOptions)
    return err
}
```

