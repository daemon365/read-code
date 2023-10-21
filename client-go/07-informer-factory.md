

## 简介

生成各个对象的 informer 方便使用 这篇文章以node informer举例

## SharedInformerFactory

```go
// SharedInformerFactory 提供了所有已知 API 组版本资源的共享 informers。
// 通常使用方式如下：
//
// ctx, cancel := context.Background() // 创建一个上下文和取消函数
// defer cancel() // 函数结束时调用取消函数，确保资源释放
// factory := NewSharedInformerFactory(client, resyncPeriod) // 创建 SharedInformerFactory
// defer factory.WaitForStop() // 如果没有启动任何 informer，则立即返回
// genericInformer := factory.ForResource(resource) // 获取指定资源的通用 informer
// typedInformer := factory.SomeAPIGroup().V1().SomeType() // 获取某个 API 组的特定类型 informer
// factory.Start(ctx.Done()) // 启动这些 informer 的处理
// synced := factory.WaitForCacheSync(ctx.Done()) // 等待所有启动的 informer 的缓存同步完成
// for v, ok := range synced {
// if !ok {
// fmt.Fprintf(os.Stderr, "caches failed to sync: %v", v) // 输出缓存同步失败的信息
// return
// }
// }
//
// // 创建 informer 也可以在 Start 后再创建，但是需要再次调用 Start：
// anotherGenericInformer := factory.ForResource(resource) // 获取另一个指定资源的通用 informer
// factory.Start(ctx.Done()) // 再次调用 Start 启动新创建的 informer
type SharedInformerFactory interface {
	internalinterfaces.SharedInformerFactory

	// Start 初始化所有请求的 informer。它们在运行直到停止通道关闭的 goroutine 中处理。
	Start(stopCh <-chan struct{})

	// Shutdown 标记工厂正在关闭。此时不能再启动新的 informer，并且 Start 将立即返回而不执行任何操作。
	//
	// 此外，Shutdown 会阻塞，直到所有 goroutine 终止。为了实现这一点，它们启动时使用的关闭通道必须在 Shutdown 被调用之前或者等待期间关闭。
	//
	// Shutdown 可以多次调用，甚至并发调用。所有这些调用都会阻塞，直到所有 goroutine 终止。
	Shutdown()

	// WaitForCacheSync 阻塞直到所有已启动的 informer 的缓存同步完成，或者停止通道关闭。
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool

	// ForResource 返回匹配类型的通用 informer 的通用访问。
	ForResource(resource schema.GroupVersionResource) (GenericInformer, error)

	// InformerFor 使用内部客户端为 obj 返回 SharedIndexInformer。
	InformerFor(obj runtime.Object, newFunc internalinterfaces.NewInformerFunc) cache.SharedIndexInformer

	Admissionregistration() admissionregistration.Interface
	Internal() apiserverinternal.Interface
	Apps() apps.Interface
	Autoscaling() autoscaling.Interface
	Batch() batch.Interface
	Certificates() certificates.Interface
	Coordination() coordination.Interface
	Core() core.Interface
	Discovery() discovery.Interface
	Events() events.Interface
	Extensions() extensions.Interface
	Flowcontrol() flowcontrol.Interface
	Networking() networking.Interface
	Node() node.Interface
	Policy() policy.Interface
	Rbac() rbac.Interface
	Resource() resource.Interface
	Scheduling() scheduling.Interface
	Storage() storage.Interface
}
```

#### SharedInformerFactory

```GO
// SharedInformerFactory 是一个小型接口，允许在没有导入循环的情况下添加 informer。
type SharedInformerFactory interface {
	Start(stopCh <-chan struct{})
	InformerFor(obj runtime.Object, newFunc NewInformerFunc) cache.SharedIndexInformer
}
```

## sharedInformerFactory

```GO
// SharedInformerOption 定义了 SharedInformerFactory 的函数选项类型。
type SharedInformerOption func(*sharedInformerFactory) *sharedInformerFactory

type sharedInformerFactory struct {
	client           kubernetes.Interface
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	lock             sync.Mutex
	defaultResync    time.Duration
	customResync     map[reflect.Type]time.Duration

	informers        map[reflect.Type]cache.SharedIndexInformer
	startedInformers map[reflect.Type]bool
	wg               sync.WaitGroup
	shuttingDown     bool
}
```

### Start

```GO
// Start 初始化所有已请求的 informer。它们在运行直到停止通道关闭的 goroutine 中处理。
func (f *sharedInformerFactory) Start(stopCh <-chan struct{}) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.shuttingDown {
		return
	}

	for informerType, informer := range f.informers {
		if !f.startedInformers[informerType] {
			f.wg.Add(1)
			// 我们需要在每次循环迭代中创建一个新变量，
			// 否则 goroutine 会使用循环变量，
			// 而循环变量在不断变化。
			informer := informer
			go func() {
				defer f.wg.Done()
				informer.Run(stopCh)
			}()
			f.startedInformers[informerType] = true
		}
	}
}
```

### Shutdown

```GO
// Shutdown 标记工厂正在关闭。此时不能再启动新的 informer，并且 Start 将立即返回而不执行任何操作。
// Shutdown 会阻塞，直到所有 goroutine 终止。
func (f *sharedInformerFactory) Shutdown() {
	f.lock.Lock()
	f.shuttingDown = true
	f.lock.Unlock()

	// 如果没有要等待的内容，将立即返回。
	f.wg.Wait()
}
```

### WaitForCacheSync

```GO
// WaitForCacheSync 阻塞直到所有已启动的 informer 的缓存同步完成，或者停止通道关闭。
func (f *sharedInformerFactory) WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool {
	informers := func() map[reflect.Type]cache.SharedIndexInformer {
		f.lock.Lock()
		defer f.lock.Unlock()

		informers := map[reflect.Type]cache.SharedIndexInformer{}
		for informerType, informer := range f.informers {
			if f.startedInformers[informerType] {
				informers[informerType] = informer
			}
		}
		return informers
	}()

	res := map[reflect.Type]bool{}
	for informType, informer := range informers {
		res[informType] = cache.WaitForCacheSync(stopCh, informer.HasSynced)
	}
	return res
}
```

### InformerFor

```GO
// InformerFor 使用内部客户端为 obj 返回 SharedIndexInformer。
func (f *sharedInformerFactory) InformerFor(obj runtime.Object, newFunc internalinterfaces.NewInformerFunc) cache.SharedIndexInformer {
	f.lock.Lock()
	defer f.lock.Unlock()

	informerType := reflect.TypeOf(obj)
	informer, exists := f.informers[informerType]
	if exists {
		return informer
	}

	resyncPeriod, exists := f.customResync[informerType]
	if !exists {
		resyncPeriod = f.defaultResync
	}

	informer = newFunc(f.client, resyncPeriod)
	f.informers[informerType] = informer

	return informer
}
```

### Core

node对象在 core下

```GO
func (f *sharedInformerFactory) Core() core.Interface {
	return core.New(f, f.namespace, f.tweakListOptions)
}
```

## core

```GO
// Interface定义了一个接口，提供对该组的每个版本的访问。
type Interface interface {
	// V1返回V1版本资源的共享informer的访问接口。
	V1() v1.Interface
}

// group定义了一个结构体，包含了一些字段。
type group struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New函数返回一个新的Interface实例。
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &group{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// V1返回一个新的v1.Interface实例。
func (g *group) V1() v1.Interface {
	return v1.New(g.factory, g.namespace, g.tweakListOptions)
}
```

### v1

```GO
// Interface定义了一个接口，提供对该组版本的所有informer的访问。
type Interface interface {
	// ComponentStatuses返回一个ComponentStatusInformer。
	ComponentStatuses() ComponentStatusInformer
	// ConfigMaps返回一个ConfigMapInformer。
	ConfigMaps() ConfigMapInformer
	// Endpoints返回一个EndpointsInformer。
	Endpoints() EndpointsInformer
	// Events返回一个EventInformer。
	Events() EventInformer
	// LimitRanges返回一个LimitRangeInformer。
	LimitRanges() LimitRangeInformer
	// Namespaces返回一个NamespaceInformer。
	Namespaces() NamespaceInformer
	// Nodes返回一个NodeInformer。
	Nodes() NodeInformer
	// PersistentVolumes返回一个PersistentVolumeInformer。
	PersistentVolumes() PersistentVolumeInformer
	// PersistentVolumeClaims返回一个PersistentVolumeClaimInformer。
	PersistentVolumeClaims() PersistentVolumeClaimInformer
	// Pods返回一个PodInformer。
	Pods() PodInformer
	// PodTemplates返回一个PodTemplateInformer。
	PodTemplates() PodTemplateInformer
	// ReplicationControllers返回一个ReplicationControllerInformer。
	ReplicationControllers() ReplicationControllerInformer
	// ResourceQuotas返回一个ResourceQuotaInformer。
	ResourceQuotas() ResourceQuotaInformer
	// Secrets返回一个SecretInformer。
	Secrets() SecretInformer
	// Services返回一个ServiceInformer。
	Services() ServiceInformer
	// ServiceAccounts返回一个ServiceAccountInformer。
	ServiceAccounts() ServiceAccountInformer
}

// version定义了一个结构体，包含了一些字段。
type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New函数返回一个新的Interface实例。
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// Nodes返回一个NodeInformer。
func (v *version) Nodes() NodeInformer {
	return &nodeInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
```

#### NodeInformer

```GO
// NodeInformer提供了对Nodes的共享informer和lister的访问接口。
type NodeInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.NodeLister
}

// nodeInformer定义了一个结构体，包含了一些字段。
type nodeInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewNodeInformer构造一个新的Node类型的informer。
// 始终优先使用informer工厂获取共享的informer，而不是获取独立的informer。
// 这样可以减少内存占用和与服务器的连接数。
func NewNodeInformer(client kubernetes.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredNodeInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredNodeInformer构造一个新的Node类型的informer。
// 始终优先使用informer工厂获取共享的informer，而不是获取独立的informer。
// 这样可以减少内存占用和与服务器的连接数。
func NewFilteredNodeInformer(client kubernetes.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1().Nodes().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CoreV1().Nodes().Watch(context.TODO(), options)
			},
		},
		&corev1.Node{},
		resyncPeriod,
		indexers,
	)
}

func (f *nodeInformer) defaultInformer(client kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredNodeInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *nodeInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&corev1.Node{}, f.defaultInformer)
}

func (f *nodeInformer) Lister() v1.NodeLister {
	return v1.NewNodeLister(f.Informer().GetIndexer())
}
```

