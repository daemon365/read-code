
## 简介

用于管理ServiceAccount资源，负责确保集群中所有的Pod都有可用的ServiceAccount。

ServiceAccount提供了一种简单而有效的身份验证和授权机制，主要用于集群内部，使得Pod可以安全地访问Kubernetes资源。

## 结构体

```GO
type ServiceAccountsController struct {
    // client-go clientset
	client                  clientset.Interface
    // 要在每个命名空间中创建的ServiceAccount对象
	serviceAccountsToEnsure []v1.ServiceAccount

	// 处理同步请求的函数
	syncHandler func(ctx context.Context, key string) error
	
    // ServiceAccount lister
	saLister       corelisters.ServiceAccountLister
    // 表示ServiceAccountLister是否已经同步完成
	saListerSynced cache.InformerSynced
	
	nsLister       corelisters.NamespaceLister
	nsListerSynced cache.InformerSynced
	
    // 工作队列
	queue workqueue.RateLimitingInterface
}

```

### Options

```GO
type ServiceAccountsControllerOptions struct {
	// 一个ServiceAccount类型的列表，表示要在每个命名空间中创建的ServiceAccount对象。
    // 这些ServiceAccount对象将由控制器自动创建和管理。
	ServiceAccounts []v1.ServiceAccount

	// 同步ServiceAccounts资源的时间间隔
	ServiceAccountResync time.Duration

	// 重新同步Namespaces资源的时间间隔
	NamespaceResync time.Duration
}

func DefaultServiceAccountsControllerOptions() ServiceAccountsControllerOptions {
	return ServiceAccountsControllerOptions{
		ServiceAccounts: []v1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		},
	}
}
```

## New

```go
func NewServiceAccountsController(saInformer coreinformers.ServiceAccountInformer, nsInformer coreinformers.NamespaceInformer, cl clientset.Interface, options ServiceAccountsControllerOptions) (*ServiceAccountsController, error) {
	e := &ServiceAccountsController{
		client:                  cl,
		serviceAccountsToEnsure: options.ServiceAccounts,
		queue:                   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "serviceaccount"),
	}
	
    // 如果sa被删除 要看下是不是默认生成的 如果是 再生成一个
	saHandler, _ := saInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		DeleteFunc: e.serviceAccountDeleted,
	}, options.ServiceAccountResync)
	e.saLister = saInformer.Lister()
	e.saListerSynced = saHandler.HasSynced

	nsHandler, _ := nsInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    e.namespaceAdded,
		UpdateFunc: e.namespaceUpdated,
	}, options.NamespaceResync)
	e.nsLister = nsInformer.Lister()
	e.nsListerSynced = nsHandler.HasSynced

	e.syncHandler = e.syncNamespace

	return e, nil
}
```

### queue

```GO
func (c *ServiceAccountsController) serviceAccountDeleted(obj interface{}) {
	sa, ok := obj.(*v1.ServiceAccount)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("Couldn't get object from tombstone %#v", obj))
			return
		}
		sa, ok = tombstone.Obj.(*v1.ServiceAccount)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("Tombstone contained object that is not a ServiceAccount %#v", obj))
			return
		}
	}
	c.queue.Add(sa.Namespace)
}

func (c *ServiceAccountsController) namespaceAdded(obj interface{}) {
	namespace := obj.(*v1.Namespace)
	c.queue.Add(namespace.Name)
}

func (c *ServiceAccountsController) namespaceUpdated(oldObj interface{}, newObj interface{}) {
	newNamespace := newObj.(*v1.Namespace)
	c.queue.Add(newNamespace.Name)
}

```

### syncNamespace

```go
func (c *ServiceAccountsController) syncNamespace(ctx context.Context, key string) error {
    // 记录开始时间 退出时打印使用时间
	startTime := time.Now()
	defer func() {
		klog.FromContext(ctx).V(4).Info("Finished syncing namespace", "namespace", key, "duration", time.Since(startTime))
	}()
	
    // 获取namespace
	ns, err := c.nsLister.Get(key)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
    // 命名空间状态不是活跃的（被删除了或者正在删除）
	if ns.Status.Phase != v1.NamespaceActive {
		// If namespace is not active, we shouldn't try to create anything
		return nil
	}

	createFailures := []error{}
    // 遍历serviceAccountsToEnsure 默认就已和default
	for _, sa := range c.serviceAccountsToEnsure {
        // 从Lister获取serviceaccount
		switch _, err := c.saLister.ServiceAccounts(ns.Name).Get(sa.Name); {
		case err == nil:
            // 如果没问题 就下一个
			continue
		case apierrors.IsNotFound(err):
		case err != nil:
			return err
		}
		// 如果没找找到就创建一个新的
		sa.Namespace = ns.Name

		if _, err := c.client.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			// we can safely ignore terminating namespace errors
			if !apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
				createFailures = append(createFailures, err)
			}
		}
	}

	return utilerrors.Flatten(utilerrors.NewAggregate(createFailures))
}
```

## Run

runWorker： 作用就是在创建namespace时自动创建serviceaccount,默认就一个`default`,当然删除serviceaccount也会重新创建

```GO
func (c *ServiceAccountsController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.FromContext(ctx).Info("Starting service account controller")
	defer klog.FromContext(ctx).Info("Shutting down service account controller")

	if !cache.WaitForNamedCacheSync("service account", ctx.Done(), c.saListerSynced, c.nsListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

## runWorker

```GO
func (c *ServiceAccountsController) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *ServiceAccountsController) processNextWorkItem(ctx context.Context) bool {
    // 获取一个key
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	
    // 调用syncHandler 没出错就Forget key 出错了就把key加到重试队列
	err := c.syncHandler(ctx, key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", key, err))
	c.queue.AddRateLimited(key)

	return true
}
```

