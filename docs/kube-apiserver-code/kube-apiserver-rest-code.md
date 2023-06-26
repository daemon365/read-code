---
id: 4-kube-apiserver-code 
title: kube-apiserver namespace代码走读
description: kube-apiserver namespace代码走读
keywords:
  - kubernetes
  - kube-apiserver
slug: /
---

## rest注册

不管是 `LegacyAPI`（历史原因，没有group的，是在 /api 路由下）还是 `APIs`  还是 `APIExtensions` ，都是创建一个REST

代码在`pkg/registry`下

```GO
// APIExtensions
customResourceDefinitionStorage, err := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
if err != nil {
    return nil, err
}

// LegacyAPI
namespaceStorage, namespaceStatusStorage, namespaceFinalizeStorage, err := namespacestore.NewREST(restOptionsGetter)
if err != nil {
    return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
}

// APIs
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
		// keep apps after extensions so legacy clients resolve the extensions versions of shared resource names.
		// See https://github.com/kubernetes/kubernetes/issues/42392
		appsrest.StorageProvider{},
		admissionregistrationrest.RESTStorageProvider{Authorizer: c.GenericConfig.Authorization.Authorizer, DiscoveryClient: discoveryClientForAdmissionRegistration},
		eventsrest.RESTStorageProvider{TTL: c.ExtraConfig.EventTTL},
		resourcerest.RESTStorageProvider{},
	}
if err := m.InstallAPIs(c.ExtraConfig.APIResourceConfigSource, c.GenericConfig.RESTOptionsGetter, restStorageProviders...); err != nil {
    return nil, err
}
```

## namespace 

代码位置： `pkg/registry/core/namespace/storage`

```GO
// rest实现了一个用于命名空间的RESTStorage
type REST struct {
    store *genericregistry.Store // 存储对象的通用注册表
    status *genericregistry.Store // 存储状态的通用注册表
}

// NewREST返回一个针对命名空间的RESTStorage对象。
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, *FinalizeREST, error) {
    // 创建一个通用注册表存储对象
    store := &genericregistry.Store{
        NewFunc: func() runtime.Object { return &api.Namespace{} }, // 创建新的命名空间对象
        NewListFunc: func() runtime.Object { return &api.NamespaceList{} }, // 创建命名空间列表对象
        PredicateFunc: namespace.MatchNamespace, // 命名空间的谓词函数
        DefaultQualifiedResource: api.Resource("namespaces"), // 默认的资源限定名称
        SingularQualifiedResource: api.Resource("namespace"), // 单数形式的资源限定名称
       	CreateStrategy:      namespace.Strategy,         // 创建命名空间的策略
        UpdateStrategy:      namespace.Strategy,         // 更新命名空间的策略
        DeleteStrategy:      namespace.Strategy,         // 删除命名空间的策略
        ResetFieldsStrategy: namespace.Strategy,         // 重置字段的策略
        ReturnDeletedObject: true,                       // 在更新时返回已删除的对象

        ShouldDeleteDuringUpdate: ShouldDeleteNamespaceDuringUpdate, // 在更新期间是否应该删除命名空间

        TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)}, // 表格转换器
    }

    options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: namespace.GetAttrs}
    if err := store.CompleteWithOptions(options); err != nil {
        return nil, nil, nil, err
    }

    statusStore := *store
    statusStore.UpdateStrategy = namespace.StatusStrategy         // 状态更新的策略
    statusStore.ResetFieldsStrategy = namespace.StatusStrategy    // 重置字段的策略

    finalizeStore := *store
    finalizeStore.UpdateStrategy = namespace.FinalizeStrategy     // 完成命名空间的策略
    finalizeStore.ResetFieldsStrategy = namespace.FinalizeStrategy // 重置字段的策略

    // 返回REST对象和相应的存储对象
    return &REST{store: store, status: &statusStore}, &StatusREST{store: &statusStore}, &FinalizeREST{store: &finalizeStore}, nil
}
```

### Store

```go
// Store实现了k8s.io/apiserver/pkg/registry/rest.StandardStorage接口。它可以嵌入到其他结构中，并允许消费者实现所需的非通用函数。此对象可复制，以便以不同的方式使用，但共享相同的基本行为。
//
// 所有字段都是必需的，除非另有说明。
//
// 此类型的预期用法是嵌入到特定Kind的RESTStorage实现中。该类型在Kubelike资源上提供CRUD语义，处理诸如使用ResourceVersion和语义进行冲突检测之类的细节。RESTCreateStrategy、RESTUpdateStrategy和RESTDeleteStrategy在所有后端之间是通用的，并封装了特定于API的逻辑。
//
// TODO: 使默认公开的方法与通用RESTStorage完全匹配
type Store struct {
    // NewFunc返回此注册表返回的类型的新实例，用于获取单个对象的GET，例如：
    //
    // curl GET /apis/group/version/namespaces/my-ns/myresource/name-of-object
    NewFunc func() runtime.Object
    // NewListFunc返回此注册表返回的类型的新列表，用于列表资源，例如：
    //
    // curl GET /apis/group/version/namespaces/my-ns/myresource
    NewListFunc func() runtime.Object

    // DefaultQualifiedResource是资源的复数名称。
    // 如果上下文中没有请求信息，将使用此字段。
    // 有关详细信息，请参阅qualifiedResourceFromContext。
    DefaultQualifiedResource schema.GroupResource

    // SingularQualifiedResource是资源的单数名称。
    SingularQualifiedResource schema.GroupResource

    // KeyRootFunc返回此资源的根etcd键；不应包含尾部的“/”。
    // 这用于在整个集合上工作的操作（列表和观察）。
    //
    // KeyRootFunc和KeyFunc必须一起提供或完全不提供。
    KeyRootFunc func(ctx context.Context) string

    // KeyFunc返回集合中特定对象的键。
    // KeyFunc在Create/Update/Get/Delete时调用。请注意，'namespace'可以从ctx中获取。
    //
    // KeyFunc和KeyRootFunc必须一起提供或完全不提供。
    KeyFunc func(ctx context.Context, name string) (string, error)

    // ObjectNameFunc返回对象的名称或错误。
    ObjectNameFunc func(obj runtime.Object) (string, error)

    // TTLFunc返回对象应该持久化的TTL（存活时间）。
    // existing参数是当前TTL或此操作的默认值。
    // update参数指示是否针对现有对象进行的操作。
    //
    // 使用TTL持久化的对象一旦TTL过期就会被逐出。
    TTLFunc func(obj runtime.Object, existing uint64, update bool) (uint64, error)

    // PredicateFunc根据提供的标签和字段返回匹配器。
    // 返回的SelectionPredicate应该在对象匹配给定的字段和标签选择器时返回true。
    PredicateFunc func(label labels.Selector, field fields.Selector) storage.SelectionPredicate

    // EnableGarbageCollection影响Update和Delete请求的处理。
    // 启用垃圾回收允许finalizer在存储删除对象之前完成对象的最终化工作。
    //
    // 如果任何存储启用了垃圾回收，则kube-controller-manager中也必须启用它。
    EnableGarbageCollection bool

    // DeleteCollectionWorkers是单个DeleteCollection调用中的最大工作者数量。
    // 针对集合中的项的删除请求将并行发出。
    DeleteCollectionWorkers int

    // Decorator是在从底层存储返回的对象上的可选出口钩子。
    // 返回的对象可以是单个对象（例如Pod）或列表类型（例如PodList）。
    // Decorator适用于在存储之上的集成，并且仅适用于值不适合存储的特定情况，因为它们无法被监视。
    Decorator func(runtime.Object)

    // CreateStrategy实现创建期间特定于资源的行为。
    CreateStrategy rest.RESTCreateStrategy
    // BeginCreate是一个可选钩子，返回一个“类似事务”的提交/回滚函数，
    // 该函数在操作结束之前但在AfterCreate和Decorator之前调用，并通过参数指示操作是否成功。
    // 如果返回错误，将不调用该函数。几乎没有人应该使用此钩子。
    BeginCreate BeginCreateFunc
    // AfterCreate实现在资源创建之后并在其装饰之前运行的进一步操作，可选。
    AfterCreate AfterCreateFunc

    // UpdateStrategy实现更新期间特定于资源的行为。
    UpdateStrategy rest.RESTUpdateStrategy
    // BeginUpdate是一个可选的钩子函数，返回一个类似"事务"的提交/回滚函数，该函数将在操作结束后但在AfterUpdate和Decorator之前被调用，通过参数指示操作是否成功。如果返回错误，将不会调用该函数。几乎没有人应该使用此钩子函数。
	BeginUpdate BeginUpdateFunc
	// AfterUpdate是在资源更新之后且在装饰之前运行的进一步操作的实现，可选的。
	AfterUpdate AfterUpdateFunc

	// DeleteStrategy实现了在删除期间的资源特定行为。
	DeleteStrategy rest.RESTDeleteStrategy
	// AfterDelete是在资源删除之后且在装饰之前运行的进一步操作的实现，可选的。
    AfterDelete AfterDeleteFunc

    // ReturnDeletedObject确定存储库是否返回已删除的对象。否则，返回一个通用的成功状态响应。
    ReturnDeletedObject bool

    // ShouldDeleteDuringUpdate是一个可选函数，用于确定从现有对象到obj的更新是否应该导致删除。
    // 如果指定了该函数，则除了标准的finalizer、deletionTimestamp和deletionGracePeriodSeconds检查之外，还将进行检查。
    ShouldDeleteDuringUpdate func(ctx context.Context, key string, obj, existing runtime.Object) bool

    // TableConvertor是一个可选的接口，用于将项目或项目列表转换为表格输出。如果未设置，则使用默认设置。
    TableConvertor rest.TableConvertor

    // ResetFieldsStrategy提供了策略重置的字段，这些字段不应由用户修改。
    ResetFieldsStrategy rest.ResetFieldsStrategy

    // Storage是资源的底层存储接口。它被包装成一个"DryRunnableStorage"，该接口将直接执行或仅进行干运行。
    Storage DryRunnableStorage

    // StorageVersioner根据对象的可能种类列表，在持久化到etcd之前输出对象将被转换为的<group/version/kind>。
    // 如果StorageVersioner为nil，则apiserver将在发现文档中将storageVersionHash保留为空。
    StorageVersioner runtime.GroupVersioner

    // DestroyFunc清理底层存储使用的客户端；可选的。
    // 如果设置了DestroyFunc，必须以线程安全的方式实现，并准备好被调用多次。
    DestroyFunc func()
}
```

### CompleteWithOptions

```GO
// CompleteWithOptions 更新存储器（Store）的选项和默认通用字段。
func (e *Store) CompleteWithOptions(options *generic.StoreOptions) error {
	// 检查 DefaultQualifiedResource 是否为空
	if e.DefaultQualifiedResource.Empty() {
		return fmt.Errorf("store %#v must have a non-empty qualified resource", e)
	}
	// 检查 SingularQualifiedResource 是否为空
	if e.SingularQualifiedResource.Empty() {
		return fmt.Errorf("store %#v must have a non-empty singular qualified resource", e)
	}
	// 检查 DefaultQualifiedResource 和 SingularQualifiedResource 的组名是否匹配
	if e.DefaultQualifiedResource.Group != e.SingularQualifiedResource.Group {
		return fmt.Errorf("store for %#v, singular and plural qualified resource's group name's must match", e)
	}
	// 检查 NewFunc 是否为nil
	if e.NewFunc == nil {
		return fmt.Errorf("store for %s must have NewFunc set", e.DefaultQualifiedResource.String())
	}
	// 检查 NewListFunc 是否为nil
	if e.NewListFunc == nil {
		return fmt.Errorf("store for %s must have NewListFunc set", e.DefaultQualifiedResource.String())
	}
	// 检查 KeyRootFunc 和 KeyFunc 是否同时为nil或同时非nil
	if (e.KeyRootFunc == nil) != (e.KeyFunc == nil) {
		return fmt.Errorf("store for %s must set both KeyRootFunc and KeyFunc or neither", e.DefaultQualifiedResource.String())
	}
	// 检查 TableConvertor 是否为nil
	if e.TableConvertor == nil {
		return fmt.Errorf("store for %s must set TableConvertor; rest.NewDefaultTableConvertor(e.DefaultQualifiedResource) can be used to output just name/creation time", e.DefaultQualifiedResource.String())
	}

	// 检查是命名空间还是集群范围的存储
	var isNamespaced bool
	switch {
	case e.CreateStrategy != nil:
		isNamespaced = e.CreateStrategy.NamespaceScoped()
	case e.UpdateStrategy != nil:
		isNamespaced = e.UpdateStrategy.NamespaceScoped()
	default:
		return fmt.Errorf("store for %s must have CreateStrategy or UpdateStrategy set", e.DefaultQualifiedResource.String())
	}

	// 检查 DeleteStrategy 是否为nil
	if e.DeleteStrategy == nil {
		return fmt.Errorf("store for %s must have DeleteStrategy set", e.DefaultQualifiedResource.String())
	}

	// 检查 options.RESTOptions 是否为nil
	if options.RESTOptions == nil {
		return fmt.Errorf("options for %s must have RESTOptions set", e.DefaultQualifiedResource.String())
	}

	// 设置 attrFunc
	attrFunc := options.AttrFunc
	if attrFunc == nil {
		if isNamespaced {
			attrFunc = storage.DefaultNamespaceScopedAttr
		} else {
			attrFunc = storage.DefaultClusterScopedAttr
		}
	}

	// 检查 PredicateFunc 是否为nil
	if e.PredicateFunc == nil {
		// 设置默认的 PredicateFunc
		e.PredicateFunc = func(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
			return storage.SelectionPredicate{
				Label:    label,
				Field:    field,
				GetAttrs: attrFunc,
			}
		}
	}

	// 验证索引器
	err := validateIndexers(options.Indexers)
	if err != nil {
		return err
	}

	// 获取 RESTOptions
	opts, err := options.RESTOptions.GetRESTOptions(e.DefaultQualifiedResource)
	if err != nil {
		return err
	}

	// 检查 ResourcePrefix
	prefix := opts.ResourcePrefix
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if prefix == "/" {
		return fmt.Errorf("store for %s has an invalid prefix %q", e.DefaultQualifiedResource.String(), opts.ResourcePrefix)
	}

	// 设置存储键生成的默认行为
	if e.KeyRootFunc == nil && e.KeyFunc == nil {
		if isNamespaced {
			// 设置命名空间范围的存储键生成函数
			e.KeyRootFunc = func(ctx context.Context) string {
				return NamespaceKeyRootFunc(ctx, prefix)
			}
			e.KeyFunc = func(ctx context.Context, name string) (string, error) {
				return NamespaceKeyFunc(ctx, prefix, name)
			}
		} else {
			// 设置集群范围的存储键生成函数
			e.KeyRootFunc = func(ctx context.Context) string {
				return prefix
			}
			e.KeyFunc = func(ctx context.Context, name string) (string, error) {
				return NoNamespaceKeyFunc(ctx, prefix, name)
			}
		}
	}

	// 适配存储器的 keyFunc，以便可以与 StorageDecorator 一起使用，而不对 etcd 中存储对象的位置做任何假设
	keyFunc := func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}

		if isNamespaced {
			return e.KeyFunc(genericapirequest.WithNamespace(genericapirequest.NewContext(), accessor.GetNamespace()), accessor.GetName())
		}

		return e.KeyFunc(genericapirequest.NewContext(), accessor.GetName())
	}

	// 设置 DeleteCollectionWorkers
	if e.DeleteCollectionWorkers == 0 {
		e.DeleteCollectionWorkers = opts.DeleteCollectionWorkers
	}

	e.EnableGarbageCollection = opts.EnableGarbageCollection

	// 检查 ObjectNameFunc 是否为nil
	if e.ObjectNameFunc == nil {
		// 设置默认的 ObjectNameFunc
		e.ObjectNameFunc = func(obj runtime.Object) (string, error) {
			accessor, err := meta.Accessor(obj)
			if err != nil {
				return "", err
			}
			return accessor.GetName(), nil
		}
	}

	// 检查 Storage.Storage 是否为nil
	if e.Storage.Storage == nil {
		e.Storage.Codec = opts.StorageConfig.Codec
		var err error
		// 设置存储器的 Storage 和 DestroyFunc
		e.Storage.Storage, e.DestroyFunc, err = opts.Decorator(
			opts.StorageConfig,
			prefix,
			keyFunc,
			e.NewFunc,
			e.NewListFunc,
			attrFunc,
			options.TriggerFunc,
			options.Indexers,
		)
		if err != nil {
			return err
		}
		e.StorageVersioner = opts.StorageConfig.EncodeVersioner

		// 如果设置了 CountMetricPollPeriod，则开始观察计数
		if opts.CountMetricPollPeriod > 0 {
			stopFunc := e.startObservingCount(opts.CountMetricPollPeriod, opts.StorageObjectCountTracker)
			previousDestroy := e.DestroyFunc
			var once sync.Once
			// 设置 DestroyFunc，当调用 DestroyFunc 时会停止观察计数并执行 previousDestroy
			e.DestroyFunc = func() {
				once.Do(func() {
					stopFunc()
					if previousDestroy != nil {
						previousDestroy()
					}
				})
			}
		}
	}

	return nil
}
```

### Get

```go
func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options) // 调用存储对象的Get方法
}

// Get从存储中检索项目。
func (e *Store) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
    // 创建一个新的对象实例
    obj := e.NewFunc()
    // 根据名称获取键值
    key, err := e.KeyFunc(ctx, name)
    if err != nil {
        return nil, err
    }

    // 使用存储接口从存储中获取对象
    // 使用给定的选项，包括资源版本号
    if err := e.Storage.Get(ctx, key, storage.GetOptions{ResourceVersion: options.ResourceVersion}, obj); err != nil {
        // 如果获取操作失败，则解释错误并返回
        return nil, storeerr.InterpretGetError(err, e.qualifiedResourceFromContext(ctx), name)
    }

    // 如果存在装饰器函数，则对对象进行装饰
    if e.Decorator != nil {
        e.Decorator(obj)
    }

    // 返回获取的对象和nil错误
    return obj, nil
}

```

#### e.Storage.Get

```go
type DryRunnableStorage struct {
	Storage storage.Interface
	Codec   runtime.Codec
}


func (s *DryRunnableStorage) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
    // 调用底层存储接口的Get方法，将结果存储在给定的对象指针中
    return s.Storage.Get(ctx, key, opts, objPtr)
}
```

Cacher

Cacker实现了storage.Interface

```go
// Cacher负责为给定的资源从其内部缓存中提供WATCH和LIST请求，并根据底层存储内容在后台更新其缓存。
// Cacher实现了storage.Interface（尽管大多数调用只是委托给底层存储）。
type Cacher struct {
    //...
}

// Get实现了storage.Interface。
func (c *Cacher) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
    if opts.ResourceVersion == "" {
        // 如果未指定resourceVersion，从底层存储中提供数据（向后兼容）。
        return c.storage.Get(ctx, key, opts, objPtr)
    }
    // 如果指定了resourceVersion，则从缓存中提供数据。
    // 可确保返回的值至少与给定的resourceVersion一样新。
    getRV, err := c.versioner.ParseResourceVersion(opts.ResourceVersion)
    if err != nil {
        return err
    }

    if getRV == 0 && !c.ready.check() {
        // 如果Cacher尚未初始化，并且不需要任何特定的最小资源版本，将请求直接转发给存储。
        return c.storage.Get(ctx, key, opts, objPtr)
    }

    // 不创建追踪 - 它不是免费的，并且有大量的Get请求。如果确实需要，我们可以添加它。
    if err := c.ready.wait(ctx); err != nil {
        return errors.NewServiceUnavailable(err.Error())
    }
    
	// 确保objPtr是一个指针类型的对象
    objVal, err := conversion.EnforcePtr(objPtr)
    if err != nil {
        return err
    }
	
    // 等待直到缓存中的数据至少与getRV一样新，并获取数据
    obj, exists, readResourceVersion, err := c.watchCache.WaitUntilFreshAndGet(ctx, getRV, key)
    if err != nil {
        return err
    }

    if exists {
        elem, ok := obj.(*storeElement)
        if !ok {
            return fmt.Errorf("non *storeElement returned from storage: %v", obj)
        }
        // 将获取的对象的值设置为objPtr指向的对象的值
        objVal.Set(reflect.ValueOf(elem.Object).Elem())
    } else {
        // 对象不存在于缓存中，将objPtr指向的对象设置为零值
        objVal.Set(reflect.Zero(objVal.Type()))
        if !opts.IgnoreNotFound {
            // 如果未设置忽略未找到的选项，则返回KeyNotFoundError
            return storage.NewKeyNotFoundError(key, int64(readResourceVersion))
        }
    }
    return nil
}
```

##### WaitUntilFreshAndGet

```GO
// WaitUntilFreshAndGet返回指向<storeElement>对象的指针。
func (w *watchCache) WaitUntilFreshAndGet(ctx context.Context, resourceVersion uint64, key string) (interface{}, bool, uint64, error) {
    err := w.waitUntilFreshAndBlock(ctx, resourceVersion)
    defer w.RUnlock()
    if err != nil {
    	return nil, false, 0, err
    }
    value, exists, err := w.store.GetByKey(key)
    return value, exists, w.resourceVersion, err
}

// waitUntilFreshAndBlock等待直到缓存至少与给定的<resourceVersion>一样新。
// 注意：此函数获取锁并且不会释放它。
// 在此函数之后，您必须显式调用w.RUnlock()。
func (w *watchCache) waitUntilFreshAndBlock(ctx context.Context, resourceVersion uint64) error {
	startTime := w.clock.Now()
    // 如果resourceVersion为0，我们接受任意旧的结果。
    // 结果是，下面的循环条件永远不会满足（w.resourceVersion永远不为负数），此调用不会触发w.cond.Wait()。
    // 因此，我们可以通过不触发唤醒函数（避免启动一个goroutine）来优化代码，尤其是因为resourceVersion=0是最常见的情况。
    if resourceVersion > 0 {
        go func() {
            // 当时间限制到期时唤醒我们。
            // 文档保证time.After（实际上是NewTimer）至少等待给定的持续时间。
            // 由于这个goroutine在我们记录开始时间后的某个时间开始，并且它会在广播后的某个时间唤醒下面的循环，
            // 我们不需要担心在时间到期之前意外唤醒它。
            <-w.clock.After(blockTimeout)
            w.cond.Broadcast()
        }()
    }

    w.RLock()
    span := tracing.SpanFromContext(ctx)
    span.AddEvent("watchCache locked acquired")
    for w.resourceVersion < resourceVersion {
        if w.clock.Since(startTime) >= blockTimeout {
            // 请求客户端在'resourceVersionTooHighRetrySeconds'秒后重试。
            return storage.NewTooLargeResourceVersionError(resourceVersion, w.resourceVersion, resourceVersionTooHighRetrySeconds)
        }
        w.cond.Wait()
    }
    span.AddEvent("watchCache fresh enough")
    return nil
}
```

##### c.storage.Get

从 etcd 拿数据

```GO
type store struct {
	client              *clientv3.Client  // 定义了一个指向clientv3.Client类型的指针变量client，用于与etcd进行通信
	codec               runtime.Codec      // 定义了一个runtime.Codec类型的变量codec，用于编码和解码对象
	versioner           storage.Versioner  // 定义了一个storage.Versioner类型的变量versioner，用于处理资源版本相关的操作
	transformer         value.Transformer  // 定义了一个value.Transformer类型的变量transformer，用于处理数据转换
	pathPrefix          string             // 定义了一个字符串类型的变量pathPrefix，表示etcd中键的前缀
	groupResource       schema.GroupResource  // 定义了一个schema.GroupResource类型的变量groupResource，表示资源的组和名称
	groupResourceString string  // 定义了一个字符串类型的变量groupResourceString，表示资源的组和名称的字符串形式
	watcher             *watcher  // 定义了一个指向watcher类型的指针变量watcher，用于监视etcd中的变化
	pagingEnabled       bool  // 定义了一个布尔类型的变量pagingEnabled，表示是否启用分页查询
	leaseManager        *leaseManager  // 定义了一个指向leaseManager类型的指针变量leaseManager，用于管理租约
}

// Get implements storage.Interface.Get.
// Get方法实现了storage.Interface接口的Get方法。
func (s *store) Get(ctx context.Context, key string, opts storage.GetOptions, out runtime.Object) error {
	preparedKey, err := s.prepareKey(key)  // 调用store结构体的prepareKey方法对键进行准备
	if err != nil {
		return err
	}
	startTime := time.Now()  // 获取当前时间
	getResp, err := s.client.KV.Get(ctx, preparedKey)  // 使用store结构体中的client对象的KV.Get方法从etcd中获取键对应的值
	metrics.RecordEtcdRequest("get", s.groupResourceString, err, startTime)  // 记录etcd请求的度量信息
	if err != nil {
		return err
	}
	if err = s.validateMinimumResourceVersion(opts.ResourceVersion, uint64(getResp.Header.Revision)); err != nil {
		return err
	}

	if len(getResp.Kvs) == 0 {  // 如果获取的键值对为空
		if opts.IgnoreNotFound {  // 如果忽略未找到错误
			return runtime.SetZeroValue(out)  // 将out对象的值设置为其类型的零值
		}
		return storage.NewKeyNotFoundError(preparedKey, 0)  // 返回一个指定键和资源版本的KeyNotFoundError
	}
	kv := getResp.Kvs[0]  // 获取第一个键值对

	data, _, err := s.transformer.TransformFromStorage(ctx, kv.Value, authenticatedDataString(preparedKey))  // 使用store结构体中的transformer对象对值进行从存储格式的转换
	if err != nil {
		return storage.NewInternalError(err.Error())  // 返回一个指定错误信息的InternalError
	}

	err = decode(s.codec, s.versioner, data, out, kv.ModRevision)  // 调用decode函数对数据进行解码
	if err != nil {
		recordDecodeError(s.groupResourceString, preparedKey)  // 记录解码错误
		return err
	}
	return nil
}
```

### Create

```go
func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	return r.store.Create(ctx, obj, createValidation, options)
}

// Create inserts a new item according to the unique key from the object.
// Note that registries may mutate the input object (e.g. in the strategy
// hooks).  Tests which call this might want to call DeepCopy if they expect to
// be able to examine the input and output objects for differences.
// Create方法根据对象中的唯一键插入一个新项目。
// 注意，注册表可能会修改输入对象（例如在策略钩子中）。
// 调用此方法的测试可能希望调用DeepCopy以便检查输入和输出对象的差异。
func (e *Store) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	var finishCreate FinishFunc = finishNothing  // 定义了一个名为finishCreate的FinishFunc变量，并初始化为finishNothing函数

	// Init metadata as early as possible.
	// 尽早初始化元数据。
	if objectMeta, err := meta.Accessor(obj); err != nil {  // 使用meta.Accessor函数获取对象的元数据访问器
		return nil, err
	} else {
		rest.FillObjectMetaSystemFields(objectMeta)  // 填充对象的元数据系统字段
		if len(objectMeta.GetGenerateName()) > 0 && len(objectMeta.GetName()) == 0 {  // 如果对象的GenerateName不为空且Name为空
			objectMeta.SetName(e.CreateStrategy.GenerateName(objectMeta.GetGenerateName()))  // 使用CreateStrategy的GenerateName方法为对象设置名称
		}
	}

	if e.BeginCreate != nil {  // 如果存在BeginCreate函数
		fn, err := e.BeginCreate(ctx, obj, options)  // 调用BeginCreate函数开始创建操作
		if err != nil {
			return nil, err
		}
		finishCreate = fn
		defer func() {
			finishCreate(ctx, false)
		}()
	}

	if err := rest.BeforeCreate(e.CreateStrategy, ctx, obj); err != nil {  // 调用BeforeCreate函数进行创建前的处理
		return nil, err
	}
	// at this point we have a fully formed object.  It is time to call the validators that the apiserver
	// handling chain wants to enforce.
	// 此时，我们已经有了一个完整的对象。现在是时候调用apiserver处理链希望执行的验证器。
	if createValidation != nil {  // 如果存在createValidation函数
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {  // 调用createValidation函数进行创建验证
			return nil, err
		}
	}

	name, err := e.ObjectNameFunc(obj)  // 调用ObjectNameFunc函数获取对象的名称
	if err != nil {
		return nil, err
	}
	key, err := e.KeyFunc(ctx, name)  // 调用KeyFunc函数获取键
	if err != nil {
		return nil, err
	}
	qualifiedResource := e.qualifiedResourceFromContext(ctx)  // 根据上下文获取限定的资源
	ttl, err := e.calculateTTL(obj, 0, false)  // 调用calculateTTL函数计算存储时间
	if err != nil {
		return nil, err
	}
	out := e.NewFunc()  // 调用NewFunc函数创建输出对象
	if err := e.Storage.Create(ctx, key, obj, out, ttl, dryrun.IsDryRun(options.DryRun)); err != nil {  // 调用Storage的Create方法进行创建操作
		err = storeerr.InterpretCreateError(err, qualifiedResource, name)  // 解释创建错误
		err = rest.CheckGeneratedNameError(ctx, e.CreateStrategy, err, obj)  // 检查生成名称错误
		if !apierrors.IsAlreadyExists(err) {  // 如果错误不是已存在错误
			return nil, err
		}
		if errGet := e.Storage.Get(ctx, key, storage.GetOptions{}, out); errGet != nil {  // 调用Storage的Get方法获取已存在的对象
			return nil, err
		}
		accessor, errGetAcc := meta.Accessor(out)  // 获取已存在对象的访问器
		if errGetAcc != nil {
			return nil, err
		}
		if accessor.GetDeletionTimestamp() != nil {  // 如果已存在对象具有删除时间戳
			msg := &err.(*apierrors.StatusError).ErrStatus.Message  // 获取错误状态的消息
			*msg = fmt.Sprintf("object is being deleted: %s", *msg)  // 修改错误消息
		}
		return nil, err
	}
	// The operation has succeeded.  Call the finish function if there is one,
	// and then make sure the defer doesn't call it again.
	// 操作成功。如果存在finish function，则调用它，然后确保defer不再调用它。
	fn := finishCreate
	finishCreate = finishNothing
	fn(ctx, true)

	if e.AfterCreate != nil {  // 如果存在AfterCreate函数
		e.AfterCreate(out, options)  // 调用AfterCreate函数进行创建后的处理
	}
	if e.Decorator != nil {  // 如果存在Decorator函数
		e.Decorator(out)  // 调用Decorator函数对输出对象进行修饰
	}
	return out, nil  // 返回输出对象和nil表示操作成功
}
```

#### e.Storage.Create

```go
func (s *DryRunnableStorage) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64, dryRun bool) error {
	if dryRun {  // 如果是DryRun模式
		if err := s.Storage.Get(ctx, key, storage.GetOptions{}, out); err == nil {  // 如果能够从存储中获取到对象
			return storage.NewKeyExistsError(key, 0)  // 返回KeyExistsError表示键已存在
		}
		return s.copyInto(obj, out)  // 否则调用copyInto函数将输入对象复制到输出对象
	}
	return s.Storage.Create(ctx, key, obj, out, ttl)  // 调用存储的Create方法进行创建操作
}

// Create implements storage.Interface.
// Create方法实现了storage.Interface接口中的Create方法。
func (c *Cacher) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	return c.storage.Create(ctx, key, obj, out, ttl)  // 调用底层存储的Create方法进行创建操作
}
```

##### c.storage.Create

操作etcd

```go
// Create implements storage.Interface.Create.
// Create方法实现了storage.Interface中的Create方法。
func (s *store) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	preparedKey, err := s.prepareKey(key)  // 准备键
	if err != nil {
		return err
	}
	ctx, span := tracing.Start(ctx, "Create etcd3",  // 开始跟踪操作
		attribute.String("audit-id", audit.GetAuditIDTruncated(ctx)),  // 添加跟踪属性
		attribute.String("key", key),
		attribute.String("type", getTypeName(obj)),
		attribute.String("resource", s.groupResourceString),
	)
	defer span.End(500 * time.Millisecond)  // 结束跟踪操作，最多持续500毫秒
	if version, err := s.versioner.ObjectResourceVersion(obj); err == nil && version != 0 {  // 检查对象的资源版本是否设置
		return errors.New("resourceVersion should not be set on objects to be created")  // 返回错误，资源版本不应该被设置
	}
	if err := s.versioner.PrepareObjectForStorage(obj); err != nil {  // 准备对象以进行存储
		return fmt.Errorf("PrepareObjectForStorage failed: %v", err)
	}
	span.AddEvent("About to Encode")  // 添加跟踪事件：即将进行编码
	data, err := runtime.Encode(s.codec, obj)  // 对象编码为字节流
	if err != nil {
		span.AddEvent("Encode failed", attribute.Int("len", len(data)), attribute.String("err", err.Error()))  // 添加跟踪事件：编码失败
		return err
	}
	span.AddEvent("Encode succeeded", attribute.Int("len", len(data)))  // 添加跟踪事件：编码成功

	opts, err := s.ttlOpts(ctx, int64(ttl))  // 获取TTL选项
	if err != nil {
		return err
	}

	newData, err := s.transformer.TransformToStorage(ctx, data, authenticatedDataString(preparedKey))  // 对数据进行转换以存储
	if err != nil {
		span.AddEvent("TransformToStorage failed", attribute.String("err", err.Error()))  // 添加跟踪事件：转换失败
		return storage.NewInternalError(err.Error())
	}
	span.AddEvent("TransformToStorage succeeded")  // 添加跟踪事件：转换成功

	startTime := time.Now()
	txnResp, err := s.client.KV.Txn(ctx).If(
		notFound(preparedKey),
	).Then(
		clientv3.OpPut(preparedKey, string(newData), opts...),
	).Commit()  // 执行事务操作，尝试放置新数据
	metrics.RecordEtcdRequest("create", s.groupResourceString, err, startTime)  // 记录Etcd请求的指标
	if err != nil {
		span.AddEvent("Txn call failed", attribute.String("err", err.Error()))  // 添加跟踪事件：事务调用失败
		return err
	}
	span.AddEvent("Txn call succeeded")  // 添加跟踪事件：事务调用成功

	if !txnResp.Succeeded {
		return storage.NewKeyExistsError(preparedKey, 0)  // 返回KeyExistsError表示键已存在
	}

	if out != nil {  // 如果有输出对象
		putResp := txnResp.Responses[0].GetResponsePut()
		err = decode(s.codec, s.versioner, data, out, putResp.Header.Revision)  // 解码并设置输出对象
		if err != nil {
			span.AddEvent("decode failed", attribute.Int("len", len(data)), attribute.String("err", err.Error()))  // 添加跟踪事件：解码失败
			recordDecodeError(s.groupResourceString, preparedKey)
			return err
		}
		span.AddEvent("decode succeeded", attribute.Int("len", len(data)))  // 添加跟踪事件：解码成功
	}
	return nil
}
```



