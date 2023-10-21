## 简介

client-go中的Informer是一个用于监视Kubernetes API对象的核心组件。它会在本地缓存中维护一份API对象的完整副本，并定期从Kubernetes API服务器获取最新的对象状态。当API对象发生变化时，Informer会自动更新本地缓存中的对象状态，并触发相应的事件通知。

Informer可以根据用户定义的规则来筛选需要监视的API对象，并可配置为按特定的属性进行索引，以便快速检索和访问对象。此外，Informer还提供了一些方便的方法来获取、创建、更新和删除API对象，这些方法会直接操作本地缓存中的对象，而无需向API服务器发送请求。

使用Informer可以显著提高客户端应用程序的性能和可伸缩性。因为它可以避免频繁地向API服务器发送请求，而是将对象状态缓存在本地，只有在对象发生变化时才会向API服务器请求最新状态。此外，Informer还可以根据对象状态的变化触发相应的事件通知，使得应用程序可以及时响应对象状态的变化，从而实现更加灵活和可靠的应用程序。

## SharedInformer

```GO
// SharedInformer 提供了将其客户端与给定对象集的权威状态进行最终一致性链接的功能。
// 对象通过其 API 组、种类/资源、命名空间（如果有）和名称来标识；
// 在此约定中，ObjectMeta.UID 不是对象的 ID 的一部分。
// 一个 SharedInformer 提供了与特定 API 组和种类/资源的对象关联。
// SharedInformer 的链接对象集合可以进一步通过命名空间（如果适用）、标签选择器和字段选择器进行限制。
//
// 对象的权威状态是 API 服务器提供访问的状态，并且对象经过严格的状态序列。
// 对象状态要么（1）以 ResourceVersion 和其他适当的内容存在，要么（2）处于“不存在”状态。
//
// SharedInformer 维护一个本地缓存，通过 GetStore() 或 IndexedInformer 的 GetIndexer()
// （如果是索引 informer）以及参与创建和/或访问 informer 的机制，暴露了每个相关对象的状态。
// 该缓存与权威状态最终一致。这意味着，除非由于持久通信问题而被阻止，如果特定的对象 ID X 与状态 S 相关联，
// 则对于包含（X，S）的每个 SharedInformer I，最终要么（1）I 的缓存将 X 关联到 S 或 X 的更新状态，
// 要么（2）I 停止，要么（3）X 的权威状态服务终止。为了正式完整，我们说不存在状态满足标签选择器或字段选择器的任何限制。
//
// 对于给定的 informer 和相关对象 ID X，出现在 informer 的缓存中的状态序列是与 X 关联的权威状态的子序列。
// 也就是说，一些状态可能永远不会出现在缓存中，但是出现的状态之间的顺序是正确的。但是，请注意，不保证在不同对象的状态之间的顺序。
//
// 本地缓存从空开始，并在 Run() 过程中被填充和更新。
//
// 举个简单的例子，如果一个对象集从现在开始不再改变，创建一个链接到该集合的 SharedInformer，并且运行该 SharedInformer，
// 那么该 SharedInformer 的缓存最终将持有该集合的精确副本（除非它停止太早，权威状态服务终止或两者之间存在持续的通信问题）。
//
// 另一个简单的例子是，如果本地缓存对于某个对象 ID 持有了非不存在的状态，并且该对象最终从权威状态中删除，
// 那么最终该对象将从本地缓存中删除（除非 SharedInformer 停止太早，权威状态服务终止或持久通信问题持续阻碍所需的结果）。
// Store 中的键的格式为命名空间?
type SharedInformer interface {
	// AddEventHandler将事件处理程序添加到共享informer，使用共享informer的重新同步周期。
	// 对于单个处理程序，事件按顺序传递，但不会在不同处理程序之间协调。
	// 它返回处理程序的注册句柄，可用于再次删除处理程序，或者判断处理程序是否已同步（已看到初始列表中的每个项）。
	AddEventHandler(handler ResourceEventHandler) (ResourceEventHandlerRegistration, error)
	// AddEventHandlerWithResyncPeriod使用请求的重新同步周期将事件处理程序添加到共享informer；
	// 零表示此处理程序不关心重新同步。
	// 重新同步操作包括向处理程序传递通知，针对informer的本地缓存中的每个对象进行更新；
	// 它不会添加与授权存储的任何交互。
	// 一些informers根本不重新同步，甚至不会为使用非零resyncPeriod添加的处理程序重新同步。
	// 对于进行重新同步的informer以及请求重新同步的每个处理程序，该informer会开发一个名义上的重新同步周期，该周期不会比请求的周期短，但可能更长。
	// 任意两次重新同步之间的实际时间可能比名义周期长，因为实现需要时间来执行工作，并且可能存在竞争负载和调度噪声。
	// 它返回处理程序的注册句柄，可用于再次删除处理程序，并返回一个错误（如果无法添加处理程序）。
	AddEventHandlerWithResyncPeriod(handler ResourceEventHandler, resyncPeriod time.Duration) (ResourceEventHandlerRegistration, error)
	// RemoveEventHandler通过其注册句柄删除先前添加的事件处理程序。
	// 该函数保证是幂等的，并且是线程安全的。
	RemoveEventHandler(handle ResourceEventHandlerRegistration) error
	// GetStore将informer的本地缓存作为Store返回。
	GetStore() Store
	// GetController已弃用，不起任何作用
	GetController() Controller
	// Run启动并运行共享informer，在停止通道（stopCh）关闭后返回。
	// 当stopCh关闭时，informer将停止。
	Run(stopCh <-chan struct{})
	// HasSynced如果共享informer的存储已由至少一个完整LIST的informer对象集的授权状态通知，则返回true。
	// 这与“重新同步”无关。
	//
	// 请注意，这并不告诉您单个处理程序是否已同步！
	// 对于此信息，请调用AddEventHandler返回的句柄上的HasSynced。
	HasSynced() bool
	// LastSyncResourceVersion是与底层存储同步时观察到的资源版本。
	// 返回的值未与对底层存储的访问同步，并且不是线程安全的。
	LastSyncResourceVersion() string

	// WatchErrorHandler在ListAndWatch与错误断开连接时调用。
	// 在调用此handler之后，informer将进行回退并重试。
	//
	// 默认实现会检查错误类型并尝试以适当的级别记录错误消息。
	//
	// 只有一个处理程序，因此如果多次调用此函数，最后一个将会覆盖之前的调用；
	// 在启动informer之后调用会返回错误。
	//
	// 该处理程序旨在提供可见性，而不是暂停消费者等功能。
	// 处理程序应该迅速返回，任何昂贵的处理应该在其他地方完成。
	SetWatchErrorHandler(handler WatchErrorHandler) error

	// TransformFunc在要存储的每个对象上调用。
	//
	// 此函数旨在让您有机会删除、转换或规范化字段。
	// 一个使用案例是从对象中删除未使用的元数据字段，以节省RAM成本。
	//
	// 必须在启动informer之前设置。
	//
	// 有关更多详细信息，请参阅TransformFunc的注释。
	SetTransform(handler TransformFunc) error

	// IsStopped报告informer是否已停止。
	// 无法向已停止的informer添加事件处理程序。
	// 已停止的informer将永远不会再次启动。
	IsStopped() bool
}
```

### ResourceEventHandler

```GO
// ResourceEventHandler可以处理对资源发生的事件的通知。这些事件仅作为信息提供，因此无法返回错误。处理程序不能修改接收到的对象；这不仅涉及顶层结构，还涉及从顶层结构可达的所有数据结构。
// - 当添加对象时调用OnAdd。
// - 当对象被修改时调用OnUpdate。请注意，oldObj是对象的最后已知状态-可能将多个更改合并在一起，因此不能使用它来查看每个单独的更改。在发生重新列出时也会调用OnUpdate，即使没有任何更改也会调用。这对于定期评估或同步某些内容非常有用。
// - 如果已知项的最终状态，OnDelete将获取该状态，否则将获取DeletedFinalStateUnknown类型的对象。如果监视关闭并且错过了删除事件，并且我们在后续的重新列出中没有注意到删除事件，那么就会发生这种情况。
type ResourceEventHandler interface {
	OnAdd(obj interface{}, isInInitialList bool)
	OnUpdate(oldObj, newObj interface{})
	OnDelete(obj interface{})
}
```

#### ResourceEventHandlerFuncs

```GO
// ResourceEventHandlerFuncs是一个适配器，让您可以轻松地指定所需的任意数量的通知函数，
// 同时仍实现ResourceEventHandler。该适配器不会取消对修改对象的禁止。
// 如果您的使用需要传播HasSynced，请参阅ResourceEventHandlerDetailedFuncs。
type ResourceEventHandlerFuncs struct {
	AddFunc    func(obj interface{})
	UpdateFunc func(oldObj, newObj interface{})
	DeleteFunc func(obj interface{})
}

// 如果AddFunc不为nil，则调用OnAdd。
func (r ResourceEventHandlerFuncs) OnAdd(obj interface{}, isInInitialList bool) {
	if r.AddFunc != nil {
		r.AddFunc(obj)
	}
}

// 如果UpdateFunc不为nil，则调用OnUpdate。
func (r ResourceEventHandlerFuncs) OnUpdate(oldObj, newObj interface{}) {
	if r.UpdateFunc != nil {
		r.UpdateFunc(oldObj, newObj)
	}
}

// 如果DeleteFunc不为nil，则调用OnDelete。
func (r ResourceEventHandlerFuncs) OnDelete(obj interface{}) {
	if r.DeleteFunc != nil {
		r.DeleteFunc(obj)
	}
}
```

#### ResourceEventHandlerDetailedFuncs

```GO
// ResourceEventHandlerDetailedFuncs与ResourceEventHandlerFuncs完全相同，
// 只是它的AddFunc接受isInInitialList参数，用于传播HasSynced。
type ResourceEventHandlerDetailedFuncs struct {
	AddFunc    func(obj interface{}, isInInitialList bool)
	UpdateFunc func(oldObj, newObj interface{})
	DeleteFunc func(obj interface{})
}

// 如果AddFunc不为nil，则调用OnAdd。
func (r ResourceEventHandlerDetailedFuncs) OnAdd(obj interface{}, isInInitialList bool) {
	if r.AddFunc != nil {
		r.AddFunc(obj, isInInitialList)
	}
}

// 如果UpdateFunc不为nil，则调用OnUpdate。
func (r ResourceEventHandlerDetailedFuncs) OnUpdate(oldObj, newObj interface{}) {
	if r.UpdateFunc != nil {
		r.UpdateFunc(oldObj, newObj)
	}
}

// 如果DeleteFunc不为nil，则调用OnDelete。
func (r ResourceEventHandlerDetailedFuncs) OnDelete(obj interface{}) {
	if r.DeleteFunc != nil {
		r.DeleteFunc(obj)
	}
}
```

#### FilteringResourceEventHandler

```GO
// FilteringResourceEventHandler对所有事件应用提供的过滤器，确保调用适当的嵌套处理程序方法。在更新后开始通过过滤器的对象被视为添加，
// 而在更新后停止通过过滤器的对象被视为删除。与处理程序一样，过滤器不能修改其接收到的对象。
type FilteringResourceEventHandler struct {
	FilterFunc func(obj interface{}) bool
	Handler    ResourceEventHandler
}

// 仅当过滤器成功时，才调用嵌套处理程序的OnAdd。
func (r FilteringResourceEventHandler) OnAdd(obj interface{}, isInInitialList bool) {
	if !r.FilterFunc(obj) {
		return
	}
	r.Handler.OnAdd(obj, isInInitialList)
}

// 根据过滤器是否匹配，确保调用适当的处理程序。
func (r FilteringResourceEventHandler) OnUpdate(oldObj, newObj interface{}) {
	newer := r.FilterFunc(newObj)
	older := r.FilterFunc(oldObj)
	switch {
	case newer && older:
		r.Handler.OnUpdate(oldObj, newObj)
	case newer && !older:
		r.Handler.OnAdd(newObj, false)
	case !newer && older:
		r.Handler.OnDelete(oldObj)
	default:
		// 什么都不做
	}
}

// 仅当过滤器成功时，才调用嵌套处理程序的OnDelete。
func (r FilteringResourceEventHandler) OnDelete(obj interface{}) {
	if !r.FilterFunc(obj) {
		return
	}
	r.Handler.OnDelete(obj)
}
```

### ResourceEventHandlerRegistration

```GO
// ResourceEventHandlerRegistration是代表为SharedInformer注册ResourceEventHandler的不透明接口。
// 必须将其提供回同一个SharedInformer的RemoveEventHandler以取消注册处理程序。
// 还用于判断处理程序是否已同步（已传递初始列表中的所有项）。
type ResourceEventHandlerRegistration interface {
	// HasSynced报告父级是否已同步，并且所有预同步事件都已传递。
	HasSynced() bool
}
```

### Controller

```GO
// Controller是一个低级控制器，其参数由Config参数化，并在sharedIndexInformer中使用。
type Controller interface {
	// Run执行两个操作。一是构建并运行Reflector，将对象/通知从Config的ListerWatcher传输到Config的Queue，并可能在该Queue上定期调用Resync。另一个是重复从Queue中弹出并使用Config的ProcessFunc进行处理。这两个操作会持续进行，直到stopCh被关闭。
	Run(stopCh <-chan struct{})

	// HasSynced委托给Config的Queue
	HasSynced() bool

	// LastSyncResourceVersion委托给Reflector（如果有的话），否则返回空字符串
	LastSyncResourceVersion() string
}
```

#### controller

```go
// *controller实现了Controller接口
type controller struct {
	config         Config
	reflector      *Reflector
	reflectorMutex sync.RWMutex
	clock          clock.Clock
}


```

#### Config

```go
// 该文件实现了在sharedIndexInformer中使用的低级控制器，它是SharedIndexInformer的一种实现。
// 这样的informer是构成Kubernetes控制平面的高级控制器的关键组件。查看这些控制器的示例，或者参考以下链接中的示例：
// https://github.com/kubernetes/client-go/tree/master/examples/workqueue
// Config包含一个低级控制器的所有设置。
type Config struct {
	// 用于存储对象的队列 - 由于实现中的假设，它必须是DeltaFIFO类型。
	// 您的Process()函数应该接受该队列的Pop()方法的输出。
	Queue

	// 用于列举和监视对象的工具。
	ListerWatcher

	// 用于处理弹出的Delta的函数。
	Process ProcessFunc

	// ObjectType是此控制器预期处理的示例对象类型。
	ObjectType runtime.Object

	// ObjectDescription是在记录有关此控制器的特定类型信息时使用的描述。
	ObjectDescription string

	// FullResyncPeriod是考虑ShouldResync的周期。
	FullResyncPeriod time.Duration

	// ShouldResync是周期性地由reflector使用，以确定是否重新同步队列。
	// 如果ShouldResync为`nil`或返回true，则表示reflector应该继续重新同步。
	ShouldResync ShouldResyncFunc

	// 如果为true，则在Process()返回错误时重新将对象放入队列。
	// TODO：添加接口以允许您注入延迟/退避或完全丢弃对象。
	//       将对象作为参数传递给此接口。由于此功能现在在更高级别上出现，这可能是多余的。
	RetryOnError bool

	// 当ListAndWatch由于错误而中断连接时调用。
	WatchErrorHandler WatchErrorHandler

	// WatchListPageSize是初始和重新列出监视列表的请求块大小。
	WatchListPageSize int64
}

// ShouldResyncFunc是一个指示reflector是否应执行重新同步的函数类型。
// 它可以被shared informer使用以支持具有自定义重新同步周期的多个事件处理程序。
type ShouldResyncFunc func() bool

// ProcessFunc处理单个对象。
type ProcessFunc func(obj interface{}, isInInitialList bool) error
```

#### Reflector

```go
// Reflector监视指定的资源，并使所有更改在给定的存储中反映出来。
type Reflector struct {
	// name标识此reflector。默认情况下，它将是file:line，如果可能的话。
	name string
	// 我们期望放入存储的类型的名称。名称将是expectedGVK的字符串表示形式（如果提供），
	// 否则将是expectedType的字符串表示形式。仅用于显示，不应用于解析或比较。
	typeDescription string
	// 我们期望放入存储的示例对象的类型。
	// 只需要正确的类型，但当类型为unstructured.Unstructured时，对象的"apiVersion"和"kind"也必须正确。
	expectedType reflect.Type
	// 如果未结构化，我们期望放入存储的对象的GVK。
	expectedGVK *schema.GroupVersionKind
	// 与监视源同步的目标
	store Store
	// 用于执行列表和监视操作的listerWatcher。
	listerWatcher ListerWatcher
	// backoff管理ListWatch的退避。
	backoffManager wait.BackoffManager
	resyncPeriod   time.Duration
	// 时钟允许测试操纵时间。
	clock clock.Clock
	// paginatedResult定义是否应强制对列表调用进行分页。
	// 它是基于初始列表调用的结果进行设置的。
	paginatedResult bool
	// 上次同步时观察到的资源版本令牌
	lastSyncResourceVersion string
	// 如果上一个使用lastSyncResourceVersion的列表或观察请求失败，
	// 错误是“过期”或“资源版本太大”，则isLastSyncResourceVersionUnavailable为true。
	isLastSyncResourceVersionUnavailable bool
	// lastSyncResourceVersionMutex保护对lastSyncResourceVersion的读写访问
	lastSyncResourceVersionMutex sync.RWMutex
	// 当ListAndWatch由于错误而中断连接时调用。
	watchErrorHandler WatchErrorHandler
	// WatchListPageSize是初始和重新同步监视列表的请求块大小。
	// 如果未设置，则对于一致性读取（RV=""）或选择任意旧数据的读取（RV="0"），
	// 它将默认为pager.PageSize；对于其他情况（RV != "" && RV != "0"），它将关闭分页以允许从观察缓存中提供它们。
	// 注意：需要谨慎使用，因为分页列表总是直接从etcd中提供的，
	// 这显着低效，并可能导致严重的性能和可扩展性问题。
	WatchListPageSize int64
	// ShouldResync定期调用，并在其返回true时调用Store的Resync操作。
	ShouldResync func() bool
	// MaxInternalErrorRetryDuration定义重试watch返回的内部错误的时间。
	MaxInternalErrorRetryDuration time.Duration
	// 如果打开，则指示reflector使用流来从API服务器获取数据。
	// 流具有使用较少的服务器资源获取数据的主要优势。
	//
	// 旧行为建立一个LIST请求来获取数据的块。
	// 分页列表效率较低，并且取决于实际对象的大小，
	// 可能会导致APIServer的内存消耗增加。
	//
	// 参见https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/3157-watch-list#design-details
	UseWatchList bool
}
```

##### new

```go
// NewNamespaceKeyedIndexerAndReflector创建一个基于命名空间的Indexer和Reflector。
// Indexer配置为以命名空间为键。
func NewNamespaceKeyedIndexerAndReflector(lw ListerWatcher, expectedType interface{}, resyncPeriod time.Duration) (indexer Indexer, reflector *Reflector) {
	indexer = NewIndexer(MetaNamespaceKeyFunc, Indexers{NamespaceIndex: MetaNamespaceIndexFunc})
	reflector = NewReflector(lw, expectedType, indexer, resyncPeriod)
	return indexer, reflector
}

// NewReflector创建一个带有默认名称的新Reflector，默认名称为调用堆栈中该包之外的最接近的源文件.go:line。
// 有关详细信息，请参阅NewReflectorWithOptions。
func NewReflector(lw ListerWatcher, expectedType interface{}, store Store, resyncPeriod time.Duration) *Reflector {
	return NewReflectorWithOptions(lw, expectedType, store, ReflectorOptions{ResyncPeriod: resyncPeriod})
}

// NewNamedReflector创建一个具有指定名称的新Reflector。
// 有关详细信息，请参阅NewReflectorWithOptions。
func NewNamedReflector(name string, lw ListerWatcher, expectedType interface{}, store Store, resyncPeriod time.Duration) *Reflector {
	return NewReflectorWithOptions(lw, expectedType, store, ReflectorOptions{Name: name, ResyncPeriod: resyncPeriod})
}
```

##### ReflectorOptions

```go
// ReflectorOptions配置Reflector。
type ReflectorOptions struct {
	// Name是Reflector的名称。如果未设置/未指定，则名称默认为调用堆栈中该包之外的最接近的源文件.go:line。
	Name string

	// TypeDescription是Reflector的类型描述。如果未设置/未指定，则类型描述使用以下规则进行默认设置：
	// 如果传递给NewReflectorWithOptions的expectedType为nil，则类型描述为"<未指定>"。
	// 如果expectedType是*unstructured.Unstructured的实例，并且其apiVersion和kind字段已设置，
	// 则类型描述为这两个字段的字符串编码。否则，类型描述设置为expectedType的go类型。
	TypeDescription string

	// ResyncPeriod是Reflector的重新同步周期。如果未设置/未指定，则重新同步周期默认为0（不重新同步）。
	ResyncPeriod time.Duration

	// Clock允许测试控制时间。如果未设置，默认为clock.RealClock{}。
	Clock clock.Clock
}

// NewReflectorWithOptions创建一个新的Reflector对象，该对象将使给定的存储与服务器的内容保持同步。
// Reflector保证只会将类型为expectedType的内容放入存储中，除非expectedType为nil。
// 如果resyncPeriod非零，则反射器将定期调用ShouldResync函数来确定是否调用存储的重新同步操作；
// ShouldResync==nil表示始终返回true。
// 这使您可以使用反射器定期处理所有内容，以及增量处理发生变化的内容。
func NewReflectorWithOptions(lw ListerWatcher, expectedType interface{}, store Store, options ReflectorOptions) Reflector {
	reflectorClock := options.Clock
	if reflectorClock == nil {
		reflectorClock = clock.RealClock{}
	}
	r := &Reflector{
		name:            options.Name,
		resyncPeriod:    options.ResyncPeriod,
		typeDescription: options.TypeDescription,
		listerWatcher:   lw,
		store:           store,
		backoffManager:  wait.NewExponentialBackoffManager(800*time.Millisecond, 30*time.Second, 2*time.Minute, 2.0, 1.0, reflectorClock),
		reflectorClock,
		clock:             reflectorClock,
		watchErrorHandler: WatchErrorHandler(DefaultWatchErrorHandler),
		expectedType:      reflect.TypeOf(expectedType),
	}

	if r.name == "" {
		r.name = naming.GetNameFromCallsite(internalPackages...)
	}

	if r.typeDescription == "" {
		r.typeDescription = getTypeDescriptionFromObject(expectedType)
	}

	if r.expectedGVK == nil {
		r.expectedGVK = getExpectedGVKFromObject(expectedType)
	}

	if s := os.Getenv("ENABLE_CLIENT_GO_WATCH_LIST_ALPHA"); len(s) > 0 {
		r.UseWatchList = true
	}

	return r
}
```

##### Run

```go
// Run反复使用reflector的ListAndWatch方法来获取所有对象和后续的增量。
// 当stopCh关闭时，Run将退出。
func (r *Reflector) Run(stopCh <-chan struct{}) {
	klog.V(3).Infof("Starting reflector %s (%s) from %s", r.typeDescription, r.resyncPeriod, r.name)
	wait.BackoffUntil(func() {
		if err := r.ListAndWatch(stopCh); err != nil {
			r.watchErrorHandler(r, err)
		}
	}, r.backoffManager, true, stopCh)
	klog.V(3).Infof("Stopping reflector %s (%s) from %s", r.typeDescription, r.resyncPeriod, r.name)
}
```

##### ListAndWatch

```go
// ListAndWatch首先列出所有项并获取调用时的资源版本，然后使用资源版本进行监视。
// 如果ListAndWatch甚至没有尝试初始化监视，则返回错误。
func (r *Reflector) ListAndWatch(stopCh <-chan struct{}) error {
	klog.V(3).Infof("Listing and watching %v from %s", r.typeDescription, r.name)
	var err error
	var w watch.Interface
	fallbackToList := !r.UseWatchList

	if r.UseWatchList {
		w, err = r.watchList(stopCh)
		if w == nil && err == nil {
			// stopCh被关闭
			return nil
		}
		if err != nil {
			if !apierrors.IsInvalid(err) {
				return err
			}
			klog.Warning("the watch-list feature is not supported by the server, falling back to the previous LIST/WATCH semantic")
			fallbackToList = true
			// 确保我们不会意外地传递一些垃圾下去进行监视。
			w = nil
		}
	}

	if fallbackToList {
		err = r.list(stopCh)
		if err != nil {
			return err
		}
	}

	resyncerrc := make(chan error, 1)
	cancelCh := make(chan struct{})
	defer close(cancelCh)
	go r.startResync(stopCh, cancelCh, resyncerrc)
	return r.watch(w, stopCh, resyncerrc)
}
```

###### watchList

```go
// watchList建立一个流以从服务器获取一致的数据快照，具体描述参见https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/3157-watch-list#proposal
//
// 情况1：从最近开始（RV=""，ResourceVersionMatch=ResourceVersionMatchNotOlderThan）
// 建立与服务器的一致流。
// 这意味着返回的数据是一致的，就好像通过法定读取直接从etcd提供的一样。
// 它以合成的“Added”事件开始，包括到最新的ResourceVersion为止的所有资源。
// 它以一个包含最新ResourceVersion的合成的“Bookmark”事件结束。
// 收到“Bookmark”事件后，认为reflector已经同步。
// 它使用收集到的项替换其内部存储，并重用当前的监视请求以获取进一步的事件。
//
// 情况2：从特定的ResourceVersion开始（RV>"0"，ResourceVersionMatch=ResourceVersionMatchNotOlderThan）
// 与服务器建立在提供的资源版本上的流。
// 为了建立初始状态，服务器以合成的“Added”事件开始。
// 它以一个包含提供的或更高版本的资源版本的合成的“Bookmark”事件结束。
// 收到“Bookmark”事件后，认为reflector已经同步。
// 它使用收集到的项替换其内部存储，并重用当前的监视请求以获取进一步的事件。
func (r *Reflector) watchList(stopCh <-chan struct{}) (watch.Interface, error) {
	var w watch.Interface
	var err error
	var temporaryStore Store
	var resourceVersion string
	// TODO(#115478): 查看是否可以将此函数转换为方法，并查看错误处理是否可以与r.watch方法统一
	isErrorRetriableWithSideEffectsFn := func(err error) bool {
		if canRetry := isWatchErrorRetriable(err); canRetry {
			klog.V(2).Infof("%s: watch-list of %v returned %v - backing off", r.name, r.typeDescription, err)
			<-r.backoffManager.Backoff().C()
			return true
		}
		if isExpiredError(err) || isTooLargeResourceVersionError(err) {
			// 我们尝试重新建立监视请求，但提供的RV已过期或大于服务器所知的RV。
			// 在这种情况下，我们重置RV并尝试从监视缓存中获取一致的快照（情况1）
			r.setIsLastSyncResourceVersionUnavailable(true)
			return true
		}
		return false
	}

	initTrace := trace.New("Reflector WatchList", trace.Field{Key: "name", Value: r.name})
	defer initTrace.LogIfLong(10 * time.Second)
	for {
		select {
		case <-stopCh:
			return nil, nil
		default:
		}

		resourceVersion = ""
		lastKnownRV := r.rewatchResourceVersion()
		temporaryStore = NewStore(DeletionHandlingMetaNamespaceKeyFunc)
		// TODO(#115478): 大型"list"、慢速客户端、慢速网络可能会减慢流式传输并最终失败。
		// 也许在这种情况下，我们应该尝试增加超时时间后重试？
		timeoutSeconds := int64(minWatchTimeout.Seconds() * (rand.Float64() + 1.0))
		options := metav1.ListOptions{
			ResourceVersion:      lastKnownRV,
			AllowWatchBookmarks:  true,
			SendInitialEvents:    pointer.Bool(true),
			ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
			TimeoutSeconds:       &timeoutSeconds,
		}
		start := r.clock.Now()

		w, err = r.listerWatcher.Watch(options)
		if err != nil {
			if isErrorRetriableWithSideEffectsFn(err) {
				continue
			}
			return nil, err
		}
		bookmarkReceived := pointer.Bool(false)
		err = watchHandler(start, w, temporaryStore, r.expectedType, r.expectedGVK, r.name, r.typeDescription,
			func(rv string) { resourceVersion = rv },
			bookmarkReceived,
			r.clock, make(chan error), stopCh)
		if err != nil {
			w.Stop() // 停止并使用干净的状态重试
			if err == errorStopRequested {
				return nil, nil
			}
			if isErrorRetriableWithSideEffectsFn(err) {
				continue
			}
			return nil, err
		}
		if *bookmarkReceived {
			break
		}
	}
	// 我们成功从watch-list中获取了初始状态，并通过"k8s.io/initial-events-end"书签进行了确认。
	initTrace.Step("Objects streamed", trace.Field{Key: "count", Value: len(temporaryStore.List())})
	r.setIsLastSyncResourceVersionUnavailable(false)
	if err = r.store.Replace(temporaryStore.List(), resourceVersion); err != nil {
		return nil, fmt.Errorf("unable to sync watch-list result: %v", err)
	}
	initTrace.Step("SyncWith done")
	r.setLastSyncResourceVersion(resourceVersion)

	return w, nil
}
```

###### list

```go
// list简单地列出所有项，并记录在调用时从服务器获取的资源版本。
// 资源版本可用于进一步的进展通知（即监视）。
func (r *Reflector) list(stopCh <-chan struct{}) error {
	var resourceVersion string
	options := metav1.ListOptions{ResourceVersion: r.relistResourceVersion()}

	initTrace := trace.New("Reflector ListAndWatch", trace.Field{Key: "name", Value: r.name})
	defer initTrace.LogIfLong(10 * time.Second)
	var list runtime.Object
	var paginatedResult bool
	var err error
	listCh := make(chan struct{}, 1)
	panicCh := make(chan interface{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()
		// 尝试按块收集列表，如果listerWatcher支持的话，如果不支持，则第一个
		// 列表请求将返回完整的响应。
		pager := pager.New(pager.SimplePageFunc(func(opts metav1.ListOptions) (runtime.Object, error) {
			return r.listerWatcher.List(opts)
		}))
		switch {
		case r.WatchListPageSize != 0:
			pager.PageSize = r.WatchListPageSize
		case r.paginatedResult:
			// 我们最初得到了一个分页结果。假设此资源和服务器支持
			// 分页请求（即watch缓存可能已禁用），并保持默认
			// 分页大小设置。
		case options.ResourceVersion != "" && options.ResourceVersion != "0":
			// 用户未显式请求分页。
			//
			// 对于ResourceVersion！=“”，我们有可能从watch缓存中进行列表，
			// 但我们仅在Limit未设置的情况下才这样做（对于ResourceVersion！=“0”）。
			// 为了避免对etcd造成雷电效应（例如，在主节点升级时），我们明确地
			// 关闭分页，以强制从监视缓存中进行列表（如果启用）。
			// 根据RV的现有语义（结果至少与提供的RV一样新），这是正确的，并且不会导致时间倒退。
			//
			// 对于ResourceVersion =“0”，我们也不关闭分页，因为监视缓存
			// 在这种情况下忽略了限制，如果未启用监视缓存，则不引入回归。
			pager.PageSize = 0
		}

		list, paginatedResult, err = pager.ListWithAlloc(context.Background(), options)
		if isExpiredError(err) || isTooLargeResourceVersionError(err) {
			r.setIsLastSyncResourceVersionUnavailable(true)
			// 如果用于列出的资源版本不可用，则立即重试。
			// 页码器已经在后续页上由于“过期”错误而回退到完整列表，
			// 但页码器可能未启用，完整列表可能因为它正在
			// 列出的资源版本已过期或缓存尚未同步到提供的资源版本而失败。
			// 因此，我们需要回退到resourceVersion =“”以进行恢复，并确保
			// reflector向前推进。
			list, paginatedResult, err = pager.ListWithAlloc(context.Background(), metav1.ListOptions{ResourceVersion: r.relistResourceVersion()})
		}
		close(listCh)
	}()
	select {
	case <-stopCh:
		return nil
	case r := <-panicCh:
		panic(r)
	case <-listCh:
	}
	initTrace.Step("Objects listed", trace.Field{Key: "error", Value: err})
	if err != nil {
		klog.Warningf("%s: failed to list %v: %v", r.name, r.typeDescription, err)
		return fmt.Errorf("failed to list %v: %w", r.typeDescription, err)
	}

	// 检查列表是否分页，如果是，则根据此设置paginatedResult。
	// 但是，我们只想对初始列表进行这样的设置（这是唯一的情况
	// 我们将ResourceVersion =“0”设置为）。这背后的原因是，
	// 以后，在某些情况下，我们可能会强制从etcd直接发送请求
	// （通过设置ResourceVersion =“”），即使启用了watch缓存，
	// 这将返回分页结果。但是，在这种情况下，我们仍然希望
	// 如果可能的话，优先发送请求到监视缓存。
	//
	// 为请求ResourceVersion =“0”的分页结果意味着
	// watch缓存已禁用，并且有很多给定类型的对象。
	// 在这种情况下，没有必要从监视缓存中获取列表。
	if options.ResourceVersion == "0" && paginatedResult {
		r.paginatedResult = true
	}

	r.setIsLastSyncResourceVersionUnavailable(false) // 列表成功
	listMetaInterface, err := meta.ListAccessor(list)
	if err != nil {
		return fmt.Errorf("unable to understand list result %#v: %v", list, err)
	}
	resourceVersion = listMetaInterface.GetResourceVersion()
	initTrace.Step("Resource version extracted")
	items, err := meta.ExtractListWithAlloc(list)
	if err != nil {
		return fmt.Errorf("unable to understand list result %#v (%v)", list, err)
	}
	initTrace.Step("Objects extracted")
	if err := r.syncWith(items, resourceversion); err != nil {
		return fmt.Errorf("unable to sync list result: %v", err)
	}
	initTrace.Step("SyncWith done")
	r.setLastSyncResourceVersion(resourceVersion)
	initTrace.Step("Resource version updated")
	return nil
}
```

###### startResync

```go
// startResync 周期性调用 r.store.Resync() 方法。
// 注意，此方法是阻塞的，应在单独的 goroutine 中调用。
func (r *Reflector) startResync(stopCh <-chan struct{}, cancelCh <-chan struct{}, resyncerrc chan error) {
	// 获取用于触发 resync 的通道和清理函数
	resyncCh, cleanup := r.resyncChan()
	defer func() {
		cleanup() // 调用最后一个写入 cleanup 的函数
	}()
	for {
		select {
		case <-resyncCh:
		case <-stopCh:
			return
		case <-cancelCh:
			return
		}
		// 如果 ShouldResync 为 nil 或 ShouldResync() 返回 true，则强制执行 resync
		if r.ShouldResync == nil || r.ShouldResync() {
			klog.V(4).Infof("%s: 强制执行 resync", r.name)
			if err := r.store.Resync(); err != nil {
				resyncerrc <- err
				return
			}
		}
		cleanup()
		resyncCh, cleanup = r.resyncChan()
	}
}
```

###### resyncChan

```go
// resyncChan 返回一个通道，在需要 resync 时会接收到值，以及一个清理函数。
func (r *Reflector) resyncChan() (<-chan time.Time, func() bool) {
	if r.resyncPeriod == 0 {
		return neverExitWatch, func() bool { return false }
	}
	// 清理函数是必需的：假设情况是 watch 始终失败，因此我们经常进行列表操作。
	// 然后，如果不手动停止计时器，可能会导致许多计时器同时处于活动状态。
	t := r.clock.NewTimer(r.resyncPeriod)
	return t.C(), t.Stop
}
```

###### watch

```go
// watch 简单地与服务器开始一个 watch 请求。
func (r *Reflector) watch(w watch.Interface, stopCh <-chan struct{}, resyncerrc chan error) error {
	var err error
	// 创建具有截止时间的重试对象
	retry := NewRetryWithDeadline(r.MaxInternalErrorRetryDuration, time.Minute, apierrors.IsInternalError, r.clock)

	for {
		// 给 stopCh 一个机会来停止循环，即使在出现错误后继续执行下面的 continue 语句
		select {
		case <-stopCh:
			return nil
		default:
		}

		// 在发送请求之前启动计时器，因为某些代理直到发送第一个 watch 事件后才会刷新标头
		start := r.clock.Now()

		if w == nil {
			// 如果 w 为 nil，则创建新的 watch.Interface 对象
			timeoutSeconds := int64(minWatchTimeout.Seconds() * (rand.Float64() + 1.0))
			options := metav1.ListOptions{
				ResourceVersion: r.LastSyncResourceVersion(),
				// 我们希望避免 watcher 长时间挂起的情况。停止任何在超时窗口内未收到任何事件的 watcher。
				TimeoutSeconds: &timeoutSeconds,
				// 为了减少 watch 重新启动时对 kube-apiserver 的负载，可以启用 watch bookmarks。
				// Reflector 不假定返回的是什么样的 bookmarks（如果服务器不支持 watch bookmarks，则会忽略此字段）。
				AllowWatchBookmarks: true,
			}

			w, err = r.listerWatcher.Watch(options)
			if err != nil {
				if canRetry := isWatchErrorRetriable(err); canRetry {
					klog.V(4).Infof("%s: 对 %v 的 watch 返回了 %v - 进行退避", r.name, r.typeDescription, err)
					select {
					case <-stopCh:
						return nil
					case <-r.backoffManager.Backoff().C():
						continue
					}
				}
				return err
			}
		}

		err = watchHandler(start, w, r.store, r.expectedType, r.expectedGVK, r.name, r.typeDescription, r.setLastSyncResourceVersion, nil, r.clock, resyncerrc, stopCh)
		// 确保 watch 在迭代过程中不会被重用。
		w.Stop()
		w = nil
		retry.After(err)
		if err != nil {
			if err != errorStopRequested {
				switch {
				case isExpiredError(err):
					// 不设置 LastSyncResourceVersionUnavailable - 具有 ResourceVersion=RV 的 LIST 调用已经具有至少与提供的 RV 一样新的数据。
					// 因此，首先尝试将 RV 设置为最后观察到的对象的资源版本。
					klog.V(4).Infof("%s: 对 %v 的 watch 关闭，原因：%v", r.name, r.typeDescription, err)
				case apierrors.IsTooManyRequests(err):
					klog.V(2).Infof("%s: 对 %v 的 watch 返回了 429 - 进行退避", r.name, r.typeDescription)
					select {
					case <-stopCh:
						return nil
					case <-r.backoffManager.Backoff().C():
						continue
					}
				case apierrors.IsInternalError(err) && retry.ShouldRetry():
					klog.V(2).Infof("%s: 重试对 %v 的 watch，发生了内部错误：%v", r.name, r.typeDescription, err)
					continue
				default:
					klog.Warningf("%s: 对 %v 的 watch 结束，原因：%v", r.name, r.typeDescription, err)
				}
			}
			return nil
		}
	}
}
```

###### watchHandler

```go
// watchHandler 监听 w 并设置 setLastSyncResourceVersion
func watchHandler(start time.Time,
	w watch.Interface,
	store Store,
	expectedType reflect.Type,
	expectedGVK *schema.GroupVersionKind,
	name string,
	expectedTypeName string,
	setLastSyncResourceVersion func(string),
	exitOnInitialEventsEndBookmark *bool,
	clock clock.Clock,
	errc chan error,
	stopCh <-chan struct{},
) error {
	eventCount := 0
	if exitOnInitialEventsEndBookmark != nil {
		// 将其设置为 false，以防万一有人将其设为正值
		*exitOnInitialEventsEndBookmark = false
	}

loop:
	for {
		select {
		case <-stopCh:
			return errorStopRequested
		case err := <-errc:
			return err
		case event, ok := <-w.ResultChan():
			if !ok {
				break loop
			}
			if event.Type == watch.Error {
				return apierrors.FromObject(event.Object)
			}
			if expectedType != nil {
				if e, a := expectedType, reflect.TypeOf(event.Object); e != a {
					utilruntime.HandleError(fmt.Errorf("%s: 期望类型为 %v，但 watch 事件对象类型为 %v", name, e, a))
					continue
				}
			}
			if expectedGVK != nil {
				if e, a := *expectedGVK, event.Object.GetObjectKind().GroupVersionKind(); e != a {
					utilruntime.HandleError(fmt.Errorf("%s: 期望的 GVK 为 %v，但 watch 事件对象的 GVK 为 %v", name, e, a))
					continue
				}
			}
			meta, err := meta.Accessor(event.Object)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("%s: 无法理解 watch 事件 %#v", name, event))
				continue
			}
			resourceVersion := meta.GetResourceVersion()
			switch event.Type {
			case watch.Added:
				err := store.Add(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: 无法将 watch 事件对象（%#v）添加到存储中：%v", name, event.Object, err))
				}
			case watch.Modified:
				err := store.Update(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: 无法将 watch 事件对象（%#v）更新到存储中：%v", name, event.Object, err))
				}
			case watch.Deleted:
				// TODO: 某些消费者是否需要访问“上次已知状态”（传递给 event.Object）？如果是这样，可能需要更改此处的逻辑。
				err := store.Delete(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: 无法从存储中删除 watch 事件对象（%#v）：%v", name, event.Object, err))
				}
			case watch.Bookmark:
				// Bookmark 表示 watch 已在此处同步，只需更新 resourceVersion
				if _, ok := meta.GetAnnotations()["k8s.io/initial-events-end"]; ok {
					if exitOnInitialEventsEndBookmark != nil {
						*exitOnInitialEventsEndBookmark = true
					}
				}
			default:
				utilruntime.HandleError(fmt.Errorf("%s: 无法理解 watch 事件 %#v", name, event))
			}
			setLastSyncResourceVersion(resourceVersion)
			if rvu, ok := store.(ResourceVersionUpdater); ok {
				rvu.UpdateResourceVersion(resourceVersion)
			}
			eventCount++
			if exitOnInitialEventsEndBookmark != nil && *exitOnInitialEventsEndBookmark {
				watchDuration := clock.Since(start)
				klog.V(4).Infof("退出 %v 的 Watch，因为收到标记初始事件流结束的书签，共收到 %v 个项，耗时 %v", name, eventCount, watchDuration)
				return nil
			}
		}
	}

	watchDuration := clock.Since(start)
	if watchDuration < 1*time.Second && eventCount == 0 {
		return fmt.Errorf("非常短暂的 watch：%s：意外的 watch 关闭 - watch 持续时间不到一秒，且未收到任何项", name)
	}
	klog.V(4).Infof("%s: Watch 关闭 - %v 共收到 %v 个项", name, expectedTypeName, eventCount)
	return nil
}
```

##### LastSyncResourceVersion

```go
// LastSyncResourceVersion 返回最后一次与底层存储同步时观察到的资源版本。
// 返回的值与对底层存储的访问不同步，并且不是线程安全的。
func (r *Reflector) LastSyncResourceVersion() string {
	r.lastSyncResourceVersionMutex.RLock()
	defer r.lastSyncResourceVersionMutex.RUnlock()
	return r.lastSyncResourceVersion
}
```

#### ListerWatcher

```go
// ListerWatcher 是任何能执行初始列表和启动资源 watch 的对象。
type ListerWatcher interface {
	Lister
	Watcher
}

// Lister 是任何能执行初始列表的对象。
type Lister interface {
	// List 应返回一个列表类型的对象；Items 字段将被提取，并使用 ResourceVersion 字段来开始正确的 watch。
	List(options metav1.ListOptions) (runtime.Object, error)
}

// Watcher 是任何能启动资源 watch 的对象。
type Watcher interface {
	// Watch 应在指定的版本开始一个 watch。
	Watch(options metav1.ListOptions) (watch.Interface, error)
}
```

##### ListWatch

```go
// ListFunc 知道如何列出资源。
type ListFunc func(options metav1.ListOptions) (runtime.Object, error)

// WatchFunc 知道如何监视资源。
type WatchFunc func(options metav1.ListOptions) (watch.Interface, error)

// ListWatch 知道如何列出和监视一组 apiserver 资源。它满足 ListerWatcher 接口。
// 它是 NewReflector 等用户的方便函数。
// ListFunc 和 WatchFunc 不能为空。
type ListWatch struct {
	ListFunc        ListFunc
	WatchFunc       WatchFunc
	DisableChunking bool
}


// Getter 接口知道如何从 RESTClient 访问 Get 方法。
type Getter interface {
	Get() *restclient.Request
}

// NewListWatchFromClient 从指定的 client、resource、namespace 和 field selector 创建一个新的 ListWatch。
func NewListWatchFromClient(c Getter, resource string, namespace string, fieldSelector fields.Selector) *ListWatch {
	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fieldSelector.String()
	}
	return NewFilteredListWatchFromClient(c, resource, namespace, optionsModifier)
}

// NewFilteredListWatchFromClient 从指定的 client、resource、namespace 和 option modifier 创建一个新的 ListWatch。
// Option modifier 是一个函数，接受 ListOptions 并修改消费的 ListOptions。
// 提供自定义的 modifier 函数，可以将修改应用于带有字段选择器、标签选择器或任何其他所需选项的 ListOptions。
func NewFilteredListWatchFromClient(c Getter, resource string, namespace string, optionsModifier func(options *metav1.ListOptions)) *ListWatch {
	listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
		optionsModifier(&options)
		return c.Get().
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			Do(context.TODO()).
			Get()
	}
	watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {
		options.Watch = true
		optionsModifier(&options)
		return c.Get().
			Namespace(namespace).
			Resource(resource).
			VersionedParams(&options, metav1.ParameterCodec).
			Watch(context.TODO())
	}
	return &ListWatch{ListFunc: listFunc, WatchFunc: watchFunc}
}

// 列出一组 apiserver 资源
func (lw *ListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	// ListWatch 在 Reflector 中使用，已经支持分页。
	// 不在这里进行分页以避免重复。
	return lw.ListFunc(options)
}

// 监视一组 apiserver 资源
func (lw *ListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return lw.WatchFunc(options)
}
```

#### New

```go
// New根据给定的Config创建一个新的Controller。
func New(c *Config) Controller {
	ctlr := &controller{
		config: *c,
		clock:  &clock.RealClock{},
	}
	return ctlr
}
```

#### Run

```go
// Run开始处理项目，并将一直持续到向stopCh发送一个值或关闭stopCh。
// 多次调用Run是错误的。
// Run会阻塞，需要使用go关键字调用。
func (c *controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	go func() {
		<-stopCh
		c.config.Queue.Close()
	}()
	r := NewReflectorWithOptions(
		c.config.ListerWatcher,
		c.config.ObjectType,
		c.config.Queue,
		ReflectorOptions{
			ResyncPeriod:    c.config.FullResyncPeriod,
			TypeDescription: c.config.ObjectDescription,
			Clock:           c.clock,
		},
	)
	r.ShouldResync = c.config.ShouldResync
	r.WatchListPageSize = c.config.WatchListPageSize
	if c.config.WatchErrorHandler != nil {
		r.watchErrorHandler = c.config.WatchErrorHandler
	}

	c.reflectorMutex.Lock()
	c.reflector = r
	c.reflectorMutex.Unlock()

	var wg wait.Group

	wg.StartWithChannel(stopCh, r.Run)

	wait.Until(c.processLoop, time.Second, stopCh)
	wg.Wait()
}
```

##### processLoop

```go
// processLoop循环处理工作队列。
// TODO: 考虑并行处理。这需要一些思考，以确保我们不会同时处理同一个对象多次。
//
// TODO: 在这里（以及下到队列）通过stopCh传递，以便在停止控制器时可以实际退出。
// 或者干脆放弃这个功能的停止。将整个包转换为使用Context也会很有帮助。
func (c *controller) processLoop() {
	for {
		obj, err := c.config.Queue.Pop(PopProcessFunc(c.config.Process))
		if err != nil {
			if err == ErrFIFOClosed {
				return
			}
			if c.config.RetryOnError {
				// 这是重新将对象放入队列的安全方式。
				c.config.Queue.AddIfNotPresent(obj)
			}
		}
	}
}
```

#### HasSynced

```go
// 返回true，一旦该控制器完成了初始资源列表
func (c *controller) HasSynced() bool {
	return c.config.Queue.HasSynced()
}
```

#### LastSyncResourceVersion

```go
func (c *controller) LastSyncResourceVersion() string {
	c.reflectorMutex.RLock()
	defer c.reflectorMutex.RUnlock()
	if c.reflector == nil {
		return ""
	}
	return c.reflector.LastSyncResourceVersion()
}
```

### WatchErrorHandler

```GO
// WatchErrorHandler在ListAndWatch与错误断开连接时调用。调用此处理程序后，informer将进行退避和重试。
// 默认实现会查看错误类型并尝试以适当的级别记录错误消息。
// 此处理程序的实现可以以其他方式显示错误消息。实现应尽快返回-任何昂贵的处理都应该被卸载。
type WatchErrorHandler func(r *Reflector, err error)
```

### TransformFunc

```GO
// TransformFunc允许在处理之前对对象进行转换。
// TransformFunc（类似于ResourceEventHandler函数）应该能够正确处理类型为cache.DeletedFinalStateUnknown的墓碑。
// 新的v1.27版本：在// 这种情况下，包含的对象已经单独经过转换（在删除之前添加/更新），因此TransformFunc可以安全地忽略这些对象（即只返回输入对象）。
// 最常见的用法模式是清理对象的某些部分，以减少组件的内存使用（如果某个组件不关心这些部分）。
// 新的v1.27版本：除非对象是DeletedFinalStateUnknown，否则TransformFunc在任何其他操作者之前看到对象，并且现在可以安全地就地对对象进行修改，而不必进行复制。
// 注意，TransformFunc在将对象插入到通知队列时调用，因此对性能非常敏感；请不要执行任何耗时的操作。
type TransformFunc func(interface{}) (interface{}, error)
```

### sharedProcessor

```go
// sharedProcessor 具有 processorListener 的集合，并且可以将通知对象分发给其监听器。有两种类型的分发操作。
// 同步分发仅发送给正在同步的子监听器，而非同步分发发送给每个监听器。
type sharedProcessor struct {
	listenersStarted bool
	listenersLock    sync.RWMutex
	// 监听器与它们当前是否正在同步的映射
	listeners map[*processorListener]bool
	clock     clock.Clock
	wg        wait.Group
}

// 根据 ResourceEventHandlerRegistration 对象获取 processorListener 对象
func (p *sharedProcessor) getListener(registration ResourceEventHandlerRegistration) *processorListener {
	p.listenersLock.RLock()
	defer p.listenersLock.RUnlock()

	if p.listeners == nil {
		return nil
	}

	if result, ok := registration.(*processorListener); ok {
		if _, exists := p.listeners[result]; exists {
			return result
		}
	}

	return nil
}

// 添加 processorListener 到 sharedProcessor，并返回 ResourceEventHandlerRegistration 对象
func (p *sharedProcessor) addListener(listener *processorListener) ResourceEventHandlerRegistration {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	if p.listeners == nil {
		p.listeners = make(map[*processorListener]bool)
	}

	p.listeners[listener] = true

	if p.listenersStarted {
		p.wg.Start(listener.run)
		p.wg.Start(listener.pop)
	}

	return listener
}

// 从 sharedProcessor 中移除 processorListener
func (p *sharedProcessor) removeListener(handle ResourceEventHandlerRegistration) error {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	listener, ok := handle.(*processorListener)
	if !ok {
		return fmt.Errorf("invalid key type %t", handle)
	} else if p.listeners == nil {
		// 没有已注册的监听器，不执行任何操作
		return nil
	} else if _, exists := p.listeners[listener]; !exists {
		// 未注册该监听器，不执行任何操作
		return nil
	}

	delete(p.listeners, listener)

	if p.listenersStarted {
		close(listener.addCh)
	}

	return nil
}

// 分发通知对象给监听器，根据 sync 参数决定是同步分发还是非同步分发
func (p *sharedProcessor) distribute(obj interface{}, sync bool) {
	p.listenersLock.RLock()
	defer p.listenersLock.RUnlock()

	for listener, isSyncing := range p.listeners {
		switch {
		case !sync:
			// 非同步消息发送给每个监听器
			listener.add(obj)
		case isSyncing:
			// 同步消息发送给每个正在同步的监听器
			listener.add(obj)
		default:
			// 跳过同步消息对于不在同步中的监听器
		}
	}
}

// 在 stopCh 接收到信号时执行 sharedProcessor 的运行逻辑
func (p *sharedProcessor) run(stopCh <-chan struct{}) {
	func() {
		p.listenersLock.RLock()
		defer p.listenersLock.RUnlock()
		for listener := range p.listeners {
			p.wg.Start(listener.run)
			p.wg.Start(listener.pop)
		}
		p.listenersStarted = true
	}()
	<-stopCh

	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()
	for listener := range p.listeners {
		close(listener.addCh) // 告知 .pop() 停止运行，.pop() 将告知 .run() 停止运行
	}

	// 从监听器列表中清除监听器的注册信息（processorListener 对象）
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	listener, ok := handle.(*processorListener)
	if !ok {
		return fmt.Errorf("invalid key type %t", handle)
	} else if p.listeners == nil {
		// 没有已注册的监听器，不执行任何操作
		return nil
	} else if _, exists := p.listeners[listener]; !exists {
		// 该监听器未注册，不执行任何操作
		return nil
	}

	delete(p.listeners, listener)

	if p.listenersStarted {
		close(listener.addCh)
	}

	return nil
}

// 分发通知对象给监听器，根据 sync 参数决定是同步分发还是非同步分发
func (p *sharedProcessor) distribute(obj interface{}, sync bool) {
	p.listenersLock.RLock()
	defer p.listenersLock.RUnlock()

	for listener, isSyncing := range p.listeners {
		switch {
		case !sync:
			// 非同步消息发送给每个监听器
			listener.add(obj)
		case isSyncing:
			// 同步消息发送给每个正在同步的监听器
			listener.add(obj)
		default:
			// 对于不在同步中的监听器跳过同步消息
		}
	}
}

// sharedProcessor 的运行逻辑，根据 stopCh 信号决定何时停止
func (p *sharedProcessor) run(stopCh <-chan struct{}) {
	func() {
		p.listenersLock.RLock()
		defer p.listenersLock.RUnlock()
		for listener := range p.listeners {
			p.wg.Start(listener.run)
			p.wg.Start(listener.pop)
		}
		p.listenersStarted = true
	}()
	<-stopCh

	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()
	for listener := range p.listeners {
		close(listener.addCh) // 告知 .pop() 停止运行，.pop() 将告知 .run() 停止运行
	}

	// 清除监听器列表，因为它们现在已关闭（processorListener 无法重新使用）
	p.listeners = nil

	// 设置为 false，因为没有监听器在运行
	p.listenersStarted = false

	p.wg.Wait() // 等待所有 .pop() 和 .run() 停止运行
}

// shouldResync 查询每个监听器以确定是否需要重新同步，基于每个监听器的重新同步周期
func (p *sharedProcessor) shouldResync() bool {
	p.listenersLock.Lock()
	defer p.listenersLock.Unlock()

	resyncNeeded := false
	now := p.clock.Now()
	for listener := range p.listeners {
		// 需要循环遍历所有监听器，以确定是否需要重新同步，以便准备将要重新同步的任何监听器
		shouldResync := listener.shouldResync(now)
		p.listeners[listener] = shouldResync

		if shouldResync {
			resyncNeeded = true
			listener.determineNextResync(now)
		}
	}
	return resyncNeeded
}

// 当 resyncCheckPeriod 发生变化时，更新所有监听器的重新同步周期
func (p *sharedProcessor) resyncCheckPeriodChanged(resyncCheckPeriod time.Duration) {
	p.listenersLock.RLock()
	defer p.listenersLock.RUnlock()

	for listener := range p.listeners {
		resyncPeriod := determineResyncPeriod(
			listener.requestedResyncPeriod, resyncCheckPeriod)
		listener.setResyncPeriod(resyncPeriod)
	}
}
```

### processorListener

```go
// processorListener 是一个将来自 sharedProcessor 的通知转发给一个 ResourceEventHandler 的类型。
// 它使用两个 goroutine、两个无缓冲的通道和一个无界环形缓冲区。
// 函数 add(notification) 将给定的通知发送到 addCh。
// 一个 goroutine 运行 pop()，它从 addCh 将通知推送到 nextCh，使用环形缓冲区中的存储，直到 nextCh 跟不上。
// 另一个 goroutine 运行 run()，它从 nextCh 接收通知，并同步调用适当的处理方法。

// processorListener 还跟踪侦听器的调整请求的重新同步周期。
type processorListener struct {
	nextCh                chan interface{}             // 将通知传递给处理器的通道
	addCh                 chan interface{}             // 接收通知的通道
	handler               ResourceEventHandler         // 处理通知的事件处理程序
	syncTracker           *synctrack.SingleFileTracker // 同步跟踪器
	pendingNotifications  buffer.RingGrowing           // 未分发的通知的无界环形缓冲区
	requestedResyncPeriod time.Duration                // 请求的重新同步周期
	resyncPeriod          time.Duration                // 重新同步周期
	nextResync            time.Time                    // 下次进行完全重新同步的最早时间
	resyncLock            sync.Mutex                   // 保护 resyncPeriod 和 nextResync 的访问
}

// HasSynced 返回源 Informer 是否已完成同步，并且所有相应的事件已被传递。
func (p *processorListener) HasSynced() bool {
	return p.syncTracker.HasSynced()
}

func newProcessListener(handler ResourceEventHandler, requestedResyncPeriod, resyncPeriod time.Duration, now time.Time, bufferSize int, hasSynced func() bool) *processorListener {
	ret := &processorListener{
		nextCh:                make(chan interface{}),
		addCh:                 make(chan interface{}),
		handler:               handler,
		syncTracker:           &synctrack.SingleFileTracker{UpstreamHasSynced: hasSynced},
		pendingNotifications:  *buffer.NewRingGrowing(bufferSize),
		requestedResyncPeriod: requestedResyncPeriod,
		resyncPeriod:          resyncPeriod,
	}

	ret.determineNextResync(now)

	return ret
}

// add 将通知添加到通道 addCh 中
func (p *processorListener) add(notification interface{}) {
	if a, ok := notification.(addNotification); ok && a.isInInitialList {
		p.syncTracker.Start()
	}
	p.addCh <- notification
}

// pop 将通知从 pendingNotifications 中取出并推送到 nextCh 中
func (p *processorListener) pop() {
	defer utilruntime.HandleCrash()
	defer close(p.nextCh) // 告知 run() 停止

	var nextCh chan<- interface{}
	var notification interface{}
	for {
		select {
		case nextCh <- notification:
			// 通知已分发
			var ok bool
			notification, ok = p.pendingNotifications.ReadOne()
			if !ok { // 没有需要取出的通知
				nextCh = nil // 禁用此 select case
			}
		case notificationToAdd, ok := <-p.addCh:
			if !ok {
				return
			}
			if notification == nil { // 没有需要取出的通知（并且 pendingNotifications 为空）
				// 优化情况 - 跳过添加到 pendingNotifications
				notification = notificationToAdd
				nextCh = p.nextCh
			} else { // 已经有一个等待分发的通知
				p.pendingNotifications.WriteOne(notificationToAdd)
			}
		}
	}
}

// run 运行处理通知的逻辑
func (p processorListener) run() {
	// 此调用会阻塞，直到通道被关闭。当通知期间发生 panic 时，
	// 我们将捕获它，将有问题的项跳过!，然后在短暂延迟（一秒钟）之后尝试下一个通知。
	// 这通常比永不再传递要好。
	stopCh := make(chan struct{})
	wait.Until(func() {
		for next := range p.nextCh {
			switch notification := next.(type) {
			case updateNotification:
				p.handler.OnUpdate(notification.oldObj, notification.newObj)
			case addNotification:
				p.handler.OnAdd(notification.newObj, notification.isInInitialList)
				if notification.isInInitialList {
					p.syncTracker.Finished()
				}
			case deleteNotification:
				p.handler.OnDelete(notification.oldObj)
			default:
				utilruntime.HandleError(fmt.Errorf("unrecognized notification: %T", next))
			}
		}
		// 只有当 p.nextCh 为空且已关闭时才会到达此处
		close(stopCh)
	}, 1*time.Second, stopCh)
}

// shouldResync 确定侦听器是否需要重新同步。
// 如果侦听器的 resyncPeriod 为 0，则始终返回 false。
func (p *processorListener) shouldResync(now time.Time) bool {
	p.resyncLock.Lock()
	defer p.resyncLock.Unlock()

	if p.resyncPeriod == 0 {
		return false
	}

	return now.After(p.nextResync) || now.Equal(p.nextResync)
}

// determineNextResync 确定下次重新同步的时间
func (p *processorListener) determineNextResync(now time.Time) {
	p.resyncLock.Lock()
	defer p.resyncLock.Unlock()

	p.nextResync = now.Add(p.resyncPeriod)
}

// setResyncPeriod 设置重新同步周期
func (p *processorListener) setResyncPeriod(resyncPeriod time.Duration) {
	p.resyncLock.Lock()
	defer p.resyncLock.Unlock()

	p.resyncPeriod = resyncPeriod
}
```

### AddEventHandler

```go
// 添加事件处理程序到 sharedIndexInformer 中，并返回 ResourceEventHandlerRegistration 对象和错误信息（如果有）
func (s *sharedIndexInformer) AddEventHandler(handler ResourceEventHandler) (ResourceEventHandlerRegistration, error) {
	return s.AddEventHandlerWithResyncPeriod(handler, s.defaultEventHandlerResyncPeriod)
}
```

### AddEventHandlerWithResyncPeriod

```go
// 添加具有重新同步周期的事件处理程序到 sharedIndexInformer 中，并返回 ResourceEventHandlerRegistration 对象和错误信息（如果有）
func (s *sharedIndexInformer) AddEventHandlerWithResyncPeriod(handler ResourceEventHandler, resyncPeriod time.Duration) (ResourceEventHandlerRegistration, error) {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.stopped {
		return nil, fmt.Errorf("handler %v was not added to shared informer because it has stopped already", handler)
	}

	if resyncPeriod > 0 {
		if resyncPeriod < minimumResyncPeriod {
			klog.Warningf("resyncPeriod %v is too small. Changing it to the minimum allowed value of %v", resyncPeriod, minimumResyncPeriod)
			resyncPeriod = minimumResyncPeriod
		}

		if resyncPeriod < s.resyncCheckPeriod {
			if s.started {
				klog.Warningf("resyncPeriod %v is smaller than resyncCheckPeriod %v and the informer has already started. Changing it to %v", resyncPeriod, s.resyncCheckPeriod, s.resyncCheckPeriod)
				resyncPeriod = s.resyncCheckPeriod
			} else {
				// 如果事件处理程序的重新同步周期小于当前的 resyncCheckPeriod，则更新 resyncCheckPeriod 以匹配 resyncPeriod，并相应地调整所有监听器的重新同步周期
				s.resyncCheckPeriod = resyncPeriod
				s.processor.resyncCheckPeriodChanged(resyncPeriod)
			}
		}
	}

	// 创建一个新的 processListener 对象
	listener := newProcessListener(handler, resyncPeriod, determineResyncPeriod(resyncPeriod, s.resyncCheckPeriod), s.clock.Now(), initialBufferSize, s.HasSynced)

	if !s.started {
		// 如果 sharedIndexInformer 尚未启动，则将 listener 添加到 processor 中
		return s.processor.addListener(listener), nil
	}

	// 为了安全地加入，我们需要执行以下操作：
	// 1. 停止发送添加/更新/删除通知
	// 2. 对存储进行列表操作
	// 3. 向新的处理程序发送合成的“添加”事件
	// 4. 解除阻塞
	s.blockDeltas.Lock()
	defer s.blockDeltas.Unlock()

	handle := s.processor.addListener(listener)
	for _, item := range s.indexer.List() {
		// 注意，在持有锁的情况下将这些通知入队，然后返回 handle。这意味着永远不会出现任何情况下调用 handle 的 HasSynced 方法返回 true 的机会（即 shared informer 已同步，但尚未观察到具有 isInitialList 为 true 的 Add，或者通知处理线程以某种方式比此线程更快地进行，计数器暂时为零）。
		listener.add(addNotification{newObj: item, isInInitialList: true})
	}
	return handle, nil
}
```

### RemoveEventHandler

```go
// RemoveEventHandler 从 sharedIndexInformer 中移除事件处理程序。
func (s *sharedIndexInformer) RemoveEventHandler(handle ResourceEventHandlerRegistration) error {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	// 为了安全地移除处理程序，我们需要：
	// 1. 停止发送添加/更新/删除通知
	// 2. 移除并停止监听器
	// 3. 解除阻塞
	s.blockDeltas.Lock()
	defer s.blockDeltas.Unlock()
	return s.processor.removeListener(handle)
}
```

### GetStore

```go
// GetStore 返回 sharedIndexInformer 的存储器。
func (s *sharedIndexInformer) GetStore() Store {
	return s.indexer
}
```

### GetIndexer

```go
// GetIndexer 返回 sharedIndexInformer 的索引器。
func (s *sharedIndexInformer) GetIndexer() Indexer {
	return s.indexer
}
```

### Run

```go
// Run 启动 sharedIndexInformer 的运行循环。
func (s *sharedIndexInformer) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	if s.HasStarted() {
		klog.Warningf("The sharedIndexInformer has started, run more than once is not allowed")
		return
	}

	func() {
		s.startedLock.Lock()
		defer s.startedLock.Unlock()

		fifo := NewDeltaFIFOWithOptions(DeltaFIFOOptions{
			KnownObjects:          s.indexer,
			EmitDeltaTypeReplaced: true,
			Transformer:           s.transform,
		})

		cfg := &Config{
			Queue:             fifo,
			ListerWatcher:     s.listerWatcher,
			ObjectType:        s.objectType,
			ObjectDescription: s.objectDescription,
			FullResyncPeriod:  s.resyncCheckPeriod,
			RetryOnError:      false,
			ShouldResync:      s.processor.shouldResync,

			Process:           s.HandleDeltas,
			WatchErrorHandler: s.watchErrorHandler,
		}

		s.controller = New(cfg)
		s.controller.(*controller).clock = s.clock
		s.started = true
	}()

	// 使用单独的停止通道，因为 Processor 必须在 controller 之后严格停止
	processorStopCh := make(chan struct{})
	var wg wait.Group
	defer wg.Wait()              // 等待 Processor 停止
	defer close(processorStopCh) // 告知 Processor 停止
	wg.StartWithChannel(processorStopCh, s.cacheMutationDetector.Run)
	wg.StartWithChannel(processorStopCh, s.processor.run)

	defer func() {
		s.startedLock.Lock()
		defer s.startedLock.Unlock()
		s.stopped = true // 不希望有任何新的监听器
	}()
	s.controller.Run(stopCh)
}
```

### HasStarted

```go
// HasStarted 返回 sharedIndexInformer 是否已启动。
func (s *sharedIndexInformer) HasStarted() bool {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()
	return s.started
}
```

### HasSynced

```go
// HasSynced 返回 sharedIndexInformer 是否已完成同步。
func (s *sharedIndexInformer) HasSynced() bool {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.controller == nil {
		return false
	}
	return s.controller.HasSynced()
}
```

### LastSyncResourceVersion

```go
// LastSyncResourceVersion 返回 sharedIndexInformer 最后同步的资源版本。
func (s *sharedIndexInformer) LastSyncResourceVersion() string {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.controller == nil {
		return ""
	}
	return s.controller.LastSyncResourceVersion()
}
```

### SetWatchErrorHandler

```go
// SetWatchErrorHandler 设置 watch 错误处理程序。
func (s *sharedIndexInformer) SetWatchErrorHandler(handler WatchErrorHandler) error {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.started {
		return fmt.Errorf("informer has already started")
	}

	s.watchErrorHandler = handler
	return nil
}
```

### SetTransform

```go
func (s *sharedIndexInformer) SetTransform(handler TransformFunc) error {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.started {
		return fmt.Errorf("informer has already started")
	}

	s.transform = handler
	return nil
}
```

### IsStopped

```go
// IsStopped 报告 informer 是否已经停止。
func (s *sharedIndexInformer) IsStopped() bool {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()
	return s.stopped
}
```

## SharedIndexInformer

```go
// SharedIndexInformer 在 SharedInformer 的基础上提供添加和获取 Indexers 的能力。
type SharedIndexInformer interface {
	SharedInformer
	// 在 informer 启动之前添加索引器。
	AddIndexers(indexers Indexers) error
	GetIndexer() Indexer
}
```

### AddIndexers

```go
// 添加索引器到 informer 中，在 informer 已经启动的情况下会返回错误。
func (s *sharedIndexInformer) AddIndexers(indexers Indexers) error {
	s.startedLock.Lock()
	defer s.startedLock.Unlock()

	if s.started {
		return fmt.Errorf("informer has already started")
	}

	return s.indexer.AddIndexers(indexers)
}
```

### GetIndexer

```go
// 获取 informer 中的索引器。
func (s *sharedIndexInformer) GetIndexer() Indexer {
	return s.indexer
}
```

