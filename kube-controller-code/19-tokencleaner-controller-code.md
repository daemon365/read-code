
## 简介

用于清理过期的 TokenRequest 和 TokenReview 对象。TokenRequest 和 TokenReview 是 Kubernetes 中用于身份验证和授权的 API 对象，它们用于获取和验证访问令牌。

tokencleaner-controller 监听 Kubernetes 中的 TokenRequest 和 TokenReview 对象，检查它们的过期时间，并在过期后删除它们。这样可以确保 Kubernetes 系统中不会有大量的过期身份验证和授权对象，从而提高系统的安全性和可靠性。

## 结构体

```go
type TokenCleanerOptions struct {
	// TokenSecret的namespace
	TokenSecretNamespace string

	//SecretResync是完全重新列出secret的持续时间。
	//如果为零，将尽可能延迟重新列出
	SecretResync time.Duration
}

func DefaultTokenCleanerOptions() TokenCleanerOptions {
	return TokenCleanerOptions{
		TokenSecretNamespace: api.NamespaceSystem,
	}
}

// TokenCleaner is a controller that deletes expired tokens
type TokenCleaner struct {
	tokenSecretNamespace string
	client clientset.Interface

	secretLister corelisters.SecretLister
	secretSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface
}
```

## New

```go
func NewTokenCleaner(cl clientset.Interface, secrets coreinformers.SecretInformer, options TokenCleanerOptions) (*TokenCleaner, error) {
	e := &TokenCleaner{
		client:               cl,
		secretLister:         secrets.Lister(),
		secretSynced:         secrets.Informer().HasSynced,
		tokenSecretNamespace: options.TokenSecretNamespace,
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "token_cleaner"),
	}
	// 监控secrets
	secrets.Informer().AddEventHandlerWithResyncPeriod(
		cache.FilteringResourceEventHandler{
			FilterFunc: func(obj interface{}) bool {
				switch t := obj.(type) {
				case *v1.Secret:
                    // 只监控Type是SecretTypeBootstrapToken和Namespace是tokenSecretNamespace的
					return t.Type == bootstrapapi.SecretTypeBootstrapToken && t.Namespace == e.tokenSecretNamespace
				default:
					utilruntime.HandleError(fmt.Errorf("object passed to %T that is not expected: %T", e, obj))
					return false
				}
			},
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    e.enqueueSecrets,
				UpdateFunc: func(oldSecret, newSecret interface{}) { e.enqueueSecrets(newSecret) },
			},
		},
		options.SecretResync,
	)

	return e, nil
}

```

### enqueueSecrets

```go
func (tc *TokenCleaner) enqueueSecrets(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}
	tc.queue.Add(key)
}
```

## Run

```go
func (tc *TokenCleaner) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()
	defer tc.queue.ShutDown()

	klog.Infof("Starting token cleaner controller")
	defer klog.Infof("Shutting down token cleaner controller")

	if !cache.WaitForNamedCacheSync("token_cleaner", ctx.Done(), tc.secretSynced) {
		return
	}

	go wait.UntilWithContext(ctx, tc.worker, 10*time.Second)
	<-ctx.Done()
}	
```

## worker

```go
func (tc *TokenCleaner) worker(ctx context.Context) {
	for tc.processNextWorkItem(ctx) {
	}
}

func (tc *TokenCleaner) processNextWorkItem(ctx context.Context) bool {
	key, quit := tc.queue.Get()
	if quit {
		return false
	}
	defer tc.queue.Done(key)

	if err := tc.syncFunc(ctx, key.(string)); err != nil {
		tc.queue.AddRateLimited(key)
		utilruntime.HandleError(fmt.Errorf("Sync %v failed with : %v", key, err))
		return true
	}

	tc.queue.Forget(key)
	return true
}
```

### syncFunc

```go

func (tc *TokenCleaner) syncFunc(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing secret %q (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	ret, err := tc.secretLister.Secrets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		klog.V(3).Infof("secret has been deleted: %v", key)
		return nil
	}

	if err != nil {
		return err
	}
	// 如果type是bootstrapapi.SecretTypeBootstrapToken 执行evalSecret
	if ret.Type == bootstrapapi.SecretTypeBootstrapToken {
		tc.evalSecret(ctx, ret)
	}
	return nil
}
```

### evalSecret

```go
// 检查传入的对象是否为v1.Secret类型，如果是则检查该对象是否已经过期。如果已经过期，则将其从Kubernetes API中删除。
// 如果没有过期，则将该对象添加到工作队列中，并在过期时间之后重新触发该方法的执行。
func (tc *TokenCleaner) evalSecret(ctx context.Context, o interface{}) {
	secret := o.(*v1.Secret)
    // 获取过期时间
	ttl, alreadyExpired := bootstrapsecretutil.GetExpiration(secret, time.Now())
	if alreadyExpired {
        // 如果过期了 删除
		klog.V(3).Infof("Deleting expired secret %s/%s", secret.Namespace, secret.Name)
		var options metav1.DeleteOptions
		if len(secret.UID) > 0 {
			options.Preconditions = &metav1.Preconditions{UID: &secret.UID}
		}
		err := tc.client.CoreV1().Secrets(secret.Namespace).Delete(ctx, secret.Name, options)
		// NotFound isn't a real error (it's already been deleted)
		// Conflict isn't a real error (the UID precondition failed)
		if err != nil && !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) {
			klog.V(3).Infof("Error deleting Secret: %v", err)
		}
	} else if ttl > 0 {
		key, err := controller.KeyFunc(o)
		if err != nil {
			utilruntime.HandleError(err)
			return
		}
        // 等ttl（过期）加入队列
		tc.queue.AddAfter(key, ttl)
	}
}
```

