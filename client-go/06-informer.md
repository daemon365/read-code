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

