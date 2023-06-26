---
id: 18-kube-controller-code
title: bootstrapsigner-controller 代码走读
description: bootstrapsigner-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

用于为一个特定的ConfigMap创建签名，这个ConfigMap用于在集群初始化时进行发现1。它也可以管理一些用于认证的bootstrap token。你可以通过kube-controller-manager命令来启动或停止这个控制器。

## 结构体

```GO
type SignerOptions struct {
	// ConfigMap的namespamce
	ConfigMapNamespace string
	// 表示ConfigMap的name
	ConfigMapName string
	// oken Secrets的namespamce
	TokenSecretNamespace string
	// 完全重新列出ConfigMap的时间间隔。如果为零，则重新列出将尽可能延迟
	ConfigMapResync time.Duration
	// 完全重新列出secret的时间间隔。如果为零，则重新列出将尽可能延迟
	SecretResync time.Duration
}

func DefaultSignerOptions() SignerOptions {
	return SignerOptions{
		ConfigMapNamespace:   api.NamespacePublic,
		ConfigMapName:        bootstrapapi.ConfigMapClusterInfo,
		TokenSecretNamespace: api.NamespaceSystem,
	}
}

type Signer struct {
	client             clientset.Interface
	configMapKey       string
	configMapName      string
	configMapNamespace string
	secretNamespace    string

	// 处理同步更新ConfigMap的队列。该队列只会有一个项目（命名为<ConfigMapName>）。
    // 它用于序列化和折叠更新，因为它们可能来自ConfigMap和Secrets控制器。
	syncQueue workqueue.RateLimitingInterface

	secretLister corelisters.SecretLister
	secretSynced cache.InformerSynced

	configMapLister corelisters.ConfigMapLister
	configMapSynced cache.InformerSynced
}

```

## New

```go
// NewSigner returns a new *Signer.
func NewSigner(cl clientset.Interface, secrets informers.SecretInformer, configMaps informers.ConfigMapInformer, options SignerOptions) (*Signer, error) {
	e := &Signer{
		client:             cl,
		configMapKey:       options.ConfigMapNamespace + "/" + options.ConfigMapName,
		configMapName:      options.ConfigMapName,
		configMapNamespace: options.ConfigMapNamespace,
		secretNamespace:    options.TokenSecretNamespace,
		secretLister:       secrets.Lister(),
		secretSynced:       secrets.Informer().HasSynced,
		configMapLister:    configMaps.Lister(),
		configMapSynced:    configMaps.Informer().HasSynced,
		syncQueue:          workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "bootstrap_signer_queue"),
	}
	
    // 监控configMap
	configMaps.Informer().AddEventHandlerWithResyncPeriod(
		cache.FilteringResourceEventHandler{
			FilterFunc: func(obj interface{}) bool {
				switch t := obj.(type) {
				case *v1.ConfigMap:
                    // 只监控Name是ConfigMapName namespace是ConfigMapNamespace的
					return t.Name == options.ConfigMapName && t.Namespace == options.ConfigMapNamespace
				default:
					utilruntime.HandleError(fmt.Errorf("object passed to %T that is not expected: %T", e, obj))
					return false
				}
			},
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    func(_ interface{}) { e.pokeConfigMapSync() },
				UpdateFunc: func(_, _ interface{}) { e.pokeConfigMapSync() },
			},
		},
		options.ConfigMapResync,
	)
	
    // 监控secret
	secrets.Informer().AddEventHandlerWithResyncPeriod(
		cache.FilteringResourceEventHandler{
			FilterFunc: func(obj interface{}) bool {
				switch t := obj.(type) {
				case *v1.Secret:
                    // 只监控Type是SecretTypeBootstrapToken和Namespace是tokenSecretNamespace的
					return t.Type == bootstrapapi.SecretTypeBootstrapToken && t.Namespace == e.secretNamespace
				default:
					utilruntime.HandleError(fmt.Errorf("object passed to %T that is not expected: %T", e, obj))
					return false
				}
			},
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    func(_ interface{}) { e.pokeConfigMapSync() },
				UpdateFunc: func(_, _ interface{}) { e.pokeConfigMapSync() },
				DeleteFunc: func(_ interface{}) { e.pokeConfigMapSync() },
			},
		},
		options.SecretResync,
	)

	return e, nil
}

```

### 处理队列相关

```GO
func (e *Signer) pokeConfigMapSync() {
	e.syncQueue.Add(e.configMapKey)
}
```

## Run

```go
func (e *Signer) Run(ctx context.Context) {
	// Shut down queues
	defer utilruntime.HandleCrash()
	defer e.syncQueue.ShutDown()

	if !cache.WaitForNamedCacheSync("bootstrap_signer", ctx.Done(), e.configMapSynced, e.secretSynced) {
		return
	}

	klog.V(5).Infof("Starting workers")
	go wait.UntilWithContext(ctx, e.serviceConfigMapQueue, 0)
	<-ctx.Done()
	klog.V(1).Infof("Shutting down")
}
```

## serviceConfigMapQueue

```go
func (e *Signer) serviceConfigMapQueue(ctx context.Context) {
	key, quit := e.syncQueue.Get()
	if quit {
		return
	}
	defer e.syncQueue.Done(key)

	e.signConfigMap(ctx)
}

// signConfigMap computes the signatures on our latest cached objects and writes
// back if necessary.
func (e *Signer) signConfigMap(ctx context.Context) {
    // 获取最新的配置信息 origCM
	origCM := e.getConfigMap()
	
    // 如果 origCM 为空，直接返回
	if origCM == nil {
		return
	}
	
    // 初始化 needUpdate 变量为 false
	var needUpdate = false

	newCM := origCM.DeepCopy()

	// 获取需要签名的配置信息
	content, ok := newCM.Data[bootstrapapi.KubeConfigKey]
	if !ok {
		klog.V(3).Infof("No %s key in %s/%s ConfigMap", bootstrapapi.KubeConfigKey, origCM.Namespace, origCM.Name)
		return
	}

	// 将所有已有的签名信息保存在 sigs 变量中
	sigs := map[string]string{}
	for key, value := range newCM.Data {
		if strings.HasPrefix(key, bootstrapapi.JWSSignatureKeyPrefix) {
			tokenID := strings.TrimPrefix(key, bootstrapapi.JWSSignatureKeyPrefix)
			sigs[tokenID] = value
			delete(newCM.Data, key)
		}
	}

	// 遍历 newCM 中的所有数据，并将具有 bootstrapapi.JWSSignatureKeyPrefix 前缀的键值对添加到 sigs 中，然后从 newCM 中删除这些键值对
	tokens := e.getTokens()
	for tokenID, tokenValue := range tokens {
		sig, err := jws.ComputeDetachedSignature(content, tokenID, tokenValue)
		if err != nil {
			utilruntime.HandleError(err)
		}

		// Check to see if this signature is changed or new.
		oldSig, _ := sigs[tokenID]
		if sig != oldSig {
			needUpdate = true
		}
		delete(sigs, tokenID)

		newCM.Data[bootstrapapi.JWSSignatureKeyPrefix+tokenID] = sig
	}

	// 如果签名信息改变了，就将 needUpdate 设置为 truep
	if len(sigs) != 0 {
		needUpdate = true
	}

	if needUpdate {
        // 更新newCM
		e.updateConfigMap(ctx, newCM)
	}
}
```

### getConfigMap

```go
func (e *Signer) getConfigMap() *v1.ConfigMap {
    // 从List拿configmap
	configMap, err := e.configMapLister.ConfigMaps(e.configMapNamespace).Get(e.configMapName)

	// If we can't get the configmap just return nil. The resync will eventually
	// sync things up.
	if err != nil {
		if !apierrors.IsNotFound(err) {
			utilruntime.HandleError(err)
		}
		return nil
	}

	return configMap
}
```

### getTokens

```go
func (e *Signer) getTokens() map[string]string {
	ret := map[string]string{}
    // 获取secretObjs
	secretObjs := e.listSecrets()
	for _, secret := range secretObjs {
        // 检查 secret 是否适合签名，并返回 tokenID 和 tokenSecret，
		tokenID, tokenSecret, ok := validateSecretForSigning(secret)
		if !ok {
			continue
		}

		// Check and warn for duplicate secrets. Behavior here will be undefined.
		if _, ok := ret[tokenID]; ok {
			// 如果在 ret 中已经存在相同的 tokenID，则输出一个警告信息，忽略当前的 secret，继续下一个循环。
			klog.V(1).Infof("Duplicate bootstrap tokens found for id %s, ignoring on in %s/%s", tokenID, secret.Namespace, secret.Name)
			continue
		}

		// 将当前 tokenID 和 tokenSecret 添加到 ret 中
		ret[tokenID] = tokenSecret
	}

	return ret
}

```

#### validateSecretForSigning

```GO
// 验证这个Secret对象是否可以用于签名，如果可以的话，返回对应的tokenID和tokenSecret，并将ok值设置为true，否则返回空值和false。
func validateSecretForSigning(secret *v1.Secret) (tokenID, tokenSecret string, ok bool) {
	nameTokenID, ok := bootstrapsecretutil.ParseName(secret.Name)
	if !ok {
		klog.V(3).Infof("Invalid secret name: %s. Must be of form %s<secret-id>.", secret.Name, bootstrapapi.BootstrapTokenSecretPrefix)
		return "", "", false
	}

	tokenID = bootstrapsecretutil.GetData(secret, bootstrapapi.BootstrapTokenIDKey)
	if len(tokenID) == 0 {
		klog.V(3).Infof("No %s key in %s/%s Secret", bootstrapapi.BootstrapTokenIDKey, secret.Namespace, secret.Name)
		return "", "", false
	}

	if nameTokenID != tokenID {
		klog.V(3).Infof("Token ID (%s) doesn't match secret name: %s", tokenID, nameTokenID)
		return "", "", false
	}

	tokenSecret = bootstrapsecretutil.GetData(secret, bootstrapapi.BootstrapTokenSecretKey)
	if len(tokenSecret) == 0 {
		klog.V(3).Infof("No %s key in %s/%s Secret", bootstrapapi.BootstrapTokenSecretKey, secret.Namespace, secret.Name)
		return "", "", false
	}

	// Ensure this secret hasn't expired.  The TokenCleaner should remove this
	// but if that isn't working or it hasn't gotten there yet we should check
	// here.
	if bootstrapsecretutil.HasExpired(secret, time.Now()) {
		return "", "", false
	}

	// Make sure this secret can be used for signing
	okToSign := bootstrapsecretutil.GetData(secret, bootstrapapi.BootstrapTokenUsageSigningKey)
	if okToSign != "true" {
		return "", "", false
	}

	return tokenID, tokenSecret, true
}

```

#### listSecrets

```GO
func (e *Signer) listSecrets() []*v1.Secret {
    // 拿出secretNamespace所有的secrets
	secrets, err := e.secretLister.Secrets(e.secretNamespace).List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(err)
		return nil
	}

	items := []*v1.Secret{}
	for _, secret := range secrets {
        // 查出type是SecretTypeBootstrapToken的
		if secret.Type == bootstrapapi.SecretTypeBootstrapToken {
			items = append(items, secret)
		}
	}
	return items
}

```

### updateConfigMap

```go
func (e *Signer) updateConfigMap(ctx context.Context, cm *v1.ConfigMap) {
	_, err := e.client.CoreV1().ConfigMaps(cm.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil && !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) {
		klog.V(3).Infof("Error updating ConfigMap: %v", err)
	}
}
```

