---
id: 13-kube-controller-code
title: serviceaccount-token-controller 代码走读
description: serviceaccount-token-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

负责自动为ServiceAccount更新对应的Secret对象（如果有的话），自动删除Secret对象。

代码位置： `pkg/controller/serviceaccount/tokens_controller.go`

## 结构体

```go
type TokensController struct {
	client clientset.Interface
    // 用于生成Kubernetes服务账户令牌的接口
	token  serviceaccount.TokenGenerator
    // Kubernetes集群的根证书
	rootCA []byte
	serviceAccounts listersv1.ServiceAccountLister
	// 对共享缓存的包装器，允许记录并返回本地变异
	updatedSecrets cache.MutationCache
	// serviceAccount secret是否同步完毕
	serviceAccountSynced cache.InformerSynced
	secretSynced         cache.InformerSynced
	// 同步ServiceAccount的工作队列
	syncServiceAccountQueue workqueue.RateLimitingInterface
	// 同步Secret的工作队列
	syncSecretQueue workqueue.RateLimitingInterface
	// 失败的情况下重试的最大次数
	maxRetries int
}
```

### options

```go
type TokensControllerOptions struct {
	// TokenGenerator is the generator to use to create new tokens
	TokenGenerator serviceaccount.TokenGenerator
	// ServiceAccountResync is the time.Duration at which to fully re-list service accounts.
	// If zero, re-list will be delayed as long as possible
	ServiceAccountResync time.Duration
	// SecretResync is the time.Duration at which to fully re-list secrets.
	// If zero, re-list will be delayed as long as possible
	SecretResync time.Duration
	// This CA will be added in the secrets of service accounts
	RootCA []byte

	// MaxRetries controls the maximum number of times a particular key is retried before giving up
	// If zero, a default max is used
	MaxRetries int
}
```

## New

```go
func NewTokensController(serviceAccounts informers.ServiceAccountInformer, secrets informers.SecretInformer, cl clientset.Interface, options TokensControllerOptions) (*TokensController, error) {
	maxRetries := options.MaxRetries
	if maxRetries == 0 {
		maxRetries = 10
	}

	e := &TokensController{
		client: cl,
		token:  options.TokenGenerator,
		rootCA: options.RootCA,

		syncServiceAccountQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "serviceaccount_tokens_service"),
		syncSecretQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "serviceaccount_tokens_secret"),

		maxRetries: maxRetries,
	}
	
    // 监控serviceAccounts的add update Delete
	e.serviceAccounts = serviceAccounts.Lister()
	e.serviceAccountSynced = serviceAccounts.Informer().HasSynced
	serviceAccounts.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    e.queueServiceAccountSync,
			UpdateFunc: e.queueServiceAccountUpdateSync,
			DeleteFunc: e.queueServiceAccountSync,
		},
		options.ServiceAccountResync,
	)

	secretCache := secrets.Informer().GetIndexer()
	e.updatedSecrets = cache.NewIntegerResourceVersionMutationCache(secretCache, secretCache, 60*time.Second, true)
	e.secretSynced = secrets.Informer().HasSynced
    // 监控secrets的add update delete 不过做了过滤 只监控ServiceAccount的secret
	secrets.Informer().AddEventHandlerWithResyncPeriod(
		cache.FilteringResourceEventHandler{
			FilterFunc: func(obj interface{}) bool {
				switch t := obj.(type) {
				case *v1.Secret:
					return t.Type == v1.SecretTypeServiceAccountToken
				default:
					utilruntime.HandleError(fmt.Errorf("object passed to %T that is not expected: %T", e, obj))
					return false
				}
			},
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    e.queueSecretSync,
				UpdateFunc: e.queueSecretUpdateSync,
				DeleteFunc: e.queueSecretSync,
			},
		},
		options.SecretResync,
	)

	return e, nil
}
```

### queue

```GO
func (e *TokensController) queueServiceAccountSync(obj interface{}) {
	if serviceAccount, ok := obj.(*v1.ServiceAccount); ok {
		e.syncServiceAccountQueue.Add(makeServiceAccountKey(serviceAccount))
	}
}

func (e *TokensController) queueServiceAccountUpdateSync(oldObj interface{}, newObj interface{}) {
	if serviceAccount, ok := newObj.(*v1.ServiceAccount); ok {
		e.syncServiceAccountQueue.Add(makeServiceAccountKey(serviceAccount))
	}
}

func (e *TokensController) queueSecretSync(obj interface{}) {
	if secret, ok := obj.(*v1.Secret); ok {
		e.syncSecretQueue.Add(makeSecretQueueKey(secret))
	}
}

func (e *TokensController) queueSecretUpdateSync(oldObj interface{}, newObj interface{}) {
	if secret, ok := newObj.(*v1.Secret); ok {
		e.syncSecretQueue.Add(makeSecretQueueKey(secret))
	}
}
```

### key的处理

- 把结构体放入队列 取出时parse出来

```GO
type serviceAccountQueueKey struct {
	namespace string
	name      string
	uid       types.UID
}

func makeServiceAccountKey(sa *v1.ServiceAccount) interface{} {
	return serviceAccountQueueKey{
		namespace: sa.Namespace,
		name:      sa.Name,
		uid:       sa.UID,
	}
}

func parseServiceAccountKey(key interface{}) (serviceAccountQueueKey, error) {
	queueKey, ok := key.(serviceAccountQueueKey)
	if !ok || len(queueKey.namespace) == 0 || len(queueKey.name) == 0 || len(queueKey.uid) == 0 {
		return serviceAccountQueueKey{}, fmt.Errorf("invalid serviceaccount key: %#v", key)
	}
	return queueKey, nil
}

type secretQueueKey struct {
	namespace string
	name      string
	uid       types.UID
	saName    string
	// optional, will be blank when syncing tokens missing the service account uid annotation
	saUID types.UID
}

func makeSecretQueueKey(secret *v1.Secret) interface{} {
	return secretQueueKey{
		namespace: secret.Namespace,
		name:      secret.Name,
		uid:       secret.UID,
		saName:    secret.Annotations[v1.ServiceAccountNameKey],
		saUID:     types.UID(secret.Annotations[v1.ServiceAccountUIDKey]),
	}
}

func parseSecretQueueKey(key interface{}) (secretQueueKey, error) {
	queueKey, ok := key.(secretQueueKey)
	if !ok || len(queueKey.namespace) == 0 || len(queueKey.name) == 0 || len(queueKey.uid) == 0 || len(queueKey.saName) == 0 {
		return secretQueueKey{}, fmt.Errorf("invalid secret key: %#v", key)
	}
	return queueKey, nil
}
```

## Run

- syncServiceAccount： 在serviceaccount对象被删除了 删除与之关联的secret
- syncSecret：
  1. secret删除是删除serviceaccount的reference(新版不需要了) 
  2. 如果sa被删除了 删除这个secret
  3. 是否需要更新secret数据 需要更新则更新

```go
func (e *TokensController) Run(ctx context.Context, workers int) {
	// Shut down queues
	defer utilruntime.HandleCrash()
	defer e.syncServiceAccountQueue.ShutDown()
	defer e.syncSecretQueue.ShutDown()

	if !cache.WaitForNamedCacheSync("tokens", ctx.Done(), e.serviceAccountSynced, e.secretSynced) {
		return
	}

	klog.FromContext(ctx).V(5).Info("Starting workers")
	for i := 0; i < workers; i++ {
		go wait.Until(e.syncServiceAccount, 0, ctx.Done())
		go wait.Until(e.syncSecret, 0, ctx.Done())
	}
	<-ctx.Done()
	klog.FromContext(ctx).V(1).Info("Shutting down")
}
```

## syncServiceAccount

```go
func (e *TokensController) syncServiceAccount() {
	logger := klog.FromContext(context.TODO())
	key, quit := e.syncServiceAccountQueue.Get()
	if quit {
		return
	}
	defer e.syncServiceAccountQueue.Done(key)

	retry := false
	defer func() {
		e.retryOrForget(e.syncServiceAccountQueue, key, retry)
	}()
	
    // parse key成结构体
	saInfo, err := parseServiceAccountKey(key)
	if err != nil {
		logger.Error(err, "Parsing service account key")
		return
	}
	
    // 获取ServiceAccount
	sa, err := e.getServiceAccount(saInfo.namespace, saInfo.name, saInfo.uid, false)
	switch {
	case err != nil:
		logger.Error(err, "Getting service account")
		retry = true
	case sa == nil:
		// service account no longer exists, so delete related tokens
		logger.V(4).Info("Service account deleted, removing tokens", "namespace", saInfo.namespace, "serviceaccount", saInfo.name)
        // 如果没获取到ServiceAccount 删除和他关联的token
		sa = &v1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: saInfo.namespace, Name: saInfo.name, UID: saInfo.uid}}
		retry, err = e.deleteTokens(sa)
		if err != nil {
			logger.Error(err, "Error deleting serviceaccount tokens", "namespace", saInfo.namespace, "serviceaccount", saInfo.name)
		}
	}
}
```

### getServiceAccount

```GO
func (e *TokensController) getServiceAccount(ns string, name string, uid types.UID, fetchOnCacheMiss bool) (*v1.ServiceAccount, error) {
	// 获取sa
	sa, err := e.serviceAccounts.ServiceAccounts(ns).Get(name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
    // 如果存在 而且和之前一样 直接返回
	if sa != nil {
		// Ensure UID matches if given
		if len(uid) == 0 || uid == sa.UID {
			return sa, nil
		}
	}
	
    // 如果没开缓存未命中时获取 直接返回
	if !fetchOnCacheMiss {
		return nil, nil
	}

	// 使用client-go直接从apiserber获取
	sa, err = e.client.CoreV1().ServiceAccounts(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// 如果相等返回
	if len(uid) == 0 || uid == sa.UID {
		return sa, nil
	}
	return nil, nil
}
```

#### deleteTokens

```GO
func (e *TokensController) deleteTokens(serviceAccount *v1.ServiceAccount) ( /*retry*/ bool, error) {
    // 获取serviceAccount关联的所有secret
	tokens, err := e.listTokenSecrets(serviceAccount)
	if err != nil {
		// don't retry on cache lookup errors
		return false, err
	}
	retry := false
	errs := []error{}
    // 一个一个删除
	for _, token := range tokens {
		r, err := e.deleteToken(token.Namespace, token.Name, token.UID)
		if err != nil {
			errs = append(errs, err)
		}
		if r {
			retry = true
		}
	}
	return retry, utilerrors.NewAggregate(errs)
}


```

##### listTokenSecrets

```GO
func (e *TokensController) listTokenSecrets(serviceAccount *v1.ServiceAccount) ([]*v1.Secret, error) {
    // 获取namespace的所有secret
	namespaceSecrets, err := e.updatedSecrets.ByIndex("namespace", serviceAccount.Namespace)
	if err != nil {
		return nil, err
	}
	
    // 一个一个比对
	items := []*v1.Secret{}
	for _, obj := range namespaceSecrets {
		secret := obj.(*v1.Secret)

		if apiserverserviceaccount.IsServiceAccountToken(secret, serviceAccount) {
			items = append(items, secret)
		}
	}
	return items, nil
}S
```

##### deleteToken

```GO
func (e *TokensController) deleteToken(ns, name string, uid types.UID) ( /*retry*/ bool, error) {
	var opts metav1.DeleteOptions
	if len(uid) > 0 {
		opts.Preconditions = &metav1.Preconditions{UID: &uid}
	}
	err := e.client.CoreV1().Secrets(ns).Delete(context.TODO(), name, opts)
	// NotFound doesn't need a retry (it's already been deleted)
	// Conflict doesn't need a retry (the UID precondition failed)
	if err == nil || apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return false, nil
	}
	// Retry for any other error
	return true, err
}

```

## syncSecret

```GO

func (e *TokensController) syncSecret() {
	key, quit := e.syncSecretQueue.Get()
	if quit {
		return
	}
	defer e.syncSecretQueue.Done(key)

	// Track whether or not we should retry this sync
	retry := false
	defer func() {
		e.retryOrForget(e.syncSecretQueue, key, retry)
	}()

	logger := klog.FromContext(context.TODO())
    // parse key成结构体
	secretInfo, err := parseSecretQueueKey(key)
	if err != nil {
		logger.Error(err, "Parsing secret queue key")
		return
	}
	
    // 获取secret
	secret, err := e.getSecret(secretInfo.namespace, secretInfo.name, secretInfo.uid, false)
	switch {
	case err != nil:
		logger.Error(err, "Getting secret")
		retry = true
	case secret == nil:
        // 如果secret不存在 获取对应的ServiceAccount
		if sa, saErr := e.getServiceAccount(secretInfo.namespace, secretInfo.saName, secretInfo.saUID, false); saErr == nil && sa != nil {
			// secret no longer exists, so delete references to this secret from the service account
			if err := clientretry.RetryOnConflict(RemoveTokenBackoff, func() error {
                // 删除sa的Reference
				return e.removeSecretReference(secretInfo.namespace, secretInfo.saName, secretInfo.saUID, secretInfo.name)
			}); err != nil {
				logger.Error(err, "Removing secret reference")
			}
		}
	default:
		// 如果secret存在
		sa, saErr := e.getServiceAccount(secretInfo.namespace, secretInfo.saName, secretInfo.saUID, true)
		switch {
		case saErr != nil:
			logger.Error(saErr, "Getting service account")
			retry = true
		case sa == nil:
			// Delete token
			logger.V(4).Info("Service account does not exist, deleting token", "secret", klog.KRef(secretInfo.namespace, secretInfo.name))
            // sa被删除了 secret还在 吧secret删除了
			if retriable, err := e.deleteToken(secretInfo.namespace, secretInfo.name, secretInfo.uid); err != nil {
				logger.Error(err, "Deleting serviceaccount token", "secret", klog.KRef(secretInfo.namespace, secretInfo.name), "serviceAccount", klog.KRef(secretInfo.namespace, secretInfo.saName))
				retry = retriable
			}
		default:
			// 如果需要 生成secret
			if retriable, err := e.generateTokenIfNeeded(logger, sa, secret); err != nil {
				logger.Error(err, "Populating serviceaccount token", "secret", klog.KRef(secretInfo.namespace, secretInfo.name), "serviceAccount", klog.KRef(secretInfo.namespace, secretInfo.saName))
				retry = retriable
			}
		}
	}
}
```

### getSecret

```GO
func (e *TokensController) getSecret(ns string, name string, uid types.UID, fetchOnCacheMiss bool) (*v1.Secret, error) {
	// 从缓存获取
	obj, exists, err := e.updatedSecrets.GetByKey(makeCacheKey(ns, name))
	if err != nil {
		return nil, err
	}
	if exists {
		secret, ok := obj.(*v1.Secret)
		if !ok {
			return nil, fmt.Errorf("expected *v1.Secret, got %#v", secret)
		}
		// Ensure UID matches if given
		if len(uid) == 0 || uid == secret.UID {
			return secret, nil
		}
	}
	
	if !fetchOnCacheMiss {
		return nil, nil
	}

	// fetchOnCacheMiss=true的话 从apiserver获取
	secret, err := e.client.CoreV1().Secrets(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Ensure UID matches if given
	if len(uid) == 0 || uid == secret.UID {
		return secret, nil
	}
	return nil, nil
}

```

### removeSecretReference

```go
func (e *TokensController) removeSecretReference(saNamespace string, saName string, saUID types.UID, secretName string) error {
	// 从apiserver获取serviceAccount
	serviceAccounts := e.client.CoreV1().ServiceAccounts(saNamespace)
	serviceAccount, err := serviceAccounts.Get(context.TODO(), saName, metav1.GetOptions{})
	// Ignore NotFound errors when attempting to remove a reference
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// 如果不匹配 直接返回
	if len(saUID) > 0 && saUID != serviceAccount.UID {
		return nil
	}

	//  如果serviceAccount里的References还没secretName 就返回
	if !getSecretReferences(serviceAccount).Has(secretName) {
		return nil
	}

	// 删除给定名称的secret
	secrets := []v1.ObjectReference{}
	for _, s := range serviceAccount.Secrets {
		if s.Name != secretName {
			secrets = append(secrets, s)
		}
	}
	serviceAccount.Secrets = secrets
	_, err = serviceAccounts.Update(context.TODO(), serviceAccount, metav1.UpdateOptions{})
	// Ignore NotFound errors when attempting to remove a reference
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
```

#### getSecretReferences

```GO
func getSecretReferences(serviceAccount *v1.ServiceAccount) sets.String {
	references := sets.NewString()
	for _, secret := range serviceAccount.Secrets {
		references.Insert(secret.Name)
	}
	return references
}
```

### generateTokenIfNeeded

```go
func (e *TokensController) generateTokenIfNeeded(logger klog.Logger, serviceAccount *v1.ServiceAccount, cachedSecret *v1.Secret) ( /* retry */ bool, error) {
	// 判断需不需要更新 ca namespace token
	if needsCA, needsNamespace, needsToken := e.secretUpdateNeeded(cachedSecret); !needsCA && !needsToken && !needsNamespace {
        // 需要都不需要更新 直接返回
		return false, nil
	}

	// 获取Namespace下的 secrets
	secrets := e.client.CoreV1().Secrets(cachedSecret.Namespace)
	liveSecret, err := secrets.Get(context.TODO(), cachedSecret.Name, metav1.GetOptions{})
	if err != nil {
		// Retry for any error other than a NotFound
		return !apierrors.IsNotFound(err), err
	}
	if liveSecret.ResourceVersion != cachedSecret.ResourceVersion {
        // reversion不相同直接返回false
		logger.V(2).Info("Secret is not up to date, skipping token population", "secret", klog.KRef(liveSecret.Namespace, liveSecret.Name))
		return false, nil
	}

	needsCA, needsNamespace, needsToken := e.secretUpdateNeeded(liveSecret)
	if !needsCA && !needsToken && !needsNamespace {
		return false, nil
	}

	if liveSecret.Annotations == nil {
		liveSecret.Annotations = map[string]string{}
	}
	if liveSecret.Data == nil {
		liveSecret.Data = map[string][]byte{}
	}
	// 哪个需要更新 就设置哪个
	// Set the CA
	if needsCA {
		liveSecret.Data[v1.ServiceAccountRootCAKey] = e.rootCA
	}
	// Set the namespace
	if needsNamespace {
		liveSecret.Data[v1.ServiceAccountNamespaceKey] = []byte(liveSecret.Namespace)
	}

	// Generate the token
	if needsToken {
		token, err := e.token.GenerateToken(serviceaccount.LegacyClaims(*serviceAccount, *liveSecret))
		if err != nil {
			return false, err
		}
		liveSecret.Data[v1.ServiceAccountTokenKey] = []byte(token)
	}

	// 设置注释
	liveSecret.Annotations[v1.ServiceAccountNameKey] = serviceAccount.Name
	liveSecret.Annotations[v1.ServiceAccountUIDKey] = string(serviceAccount.UID)

	// 更新
	_, err = secrets.Update(context.TODO(), liveSecret, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		// if we got a Conflict error, the secret was updated by someone else, and we'll get an update notification later
		// if we got a NotFound error, the secret no longer exists, and we don't need to populate a token
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return false, nil
}

```

#### secretUpdateNeeded

```go
// 发布会ca和rootca相不相等 需不需要更新namespace数据 是否需要更新token数据
func (e *TokensController) secretUpdateNeeded(secret *v1.Secret) (bool, bool, bool) {
	caData := secret.Data[v1.ServiceAccountRootCAKey]
	needsCA := len(e.rootCA) > 0 && !bytes.Equal(caData, e.rootCA)

	needsNamespace := len(secret.Data[v1.ServiceAccountNamespaceKey]) == 0

	tokenData := secret.Data[v1.ServiceAccountTokenKey]
	needsToken := len(tokenData) == 0

	return needsCA, needsNamespace, needsToken
}
```

