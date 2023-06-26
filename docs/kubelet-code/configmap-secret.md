---
id: 13-kubelet-code 
title: configmap manager 和 secret manager 代码走读
description: configmap manager 和 secret manager 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## configmap Manager

```go
// Manager接口为Kubelet提供管理ConfigMap的方法。
type Manager interface {
	// 通过configmap的命名空间和名称获取configmap。
	GetConfigMap(namespace, name string) (*v1.ConfigMap, error)

	// 警告：Register/UnregisterPod函数应高效，即不应阻塞在网络操作上。

	// RegisterPod从给定的Pod注册所有的configmaps。
	RegisterPod(pod *v1.Pod)

	// UnregisterPod从给定的Pod注销未被任何其他注册的Pod使用的configmaps。
	UnregisterPod(pod *v1.Pod)
}
```

## simpleConfigMapManager

```go
// simpleConfigMapManager使用简单的操作与apiserver实现了ConfigMap Manager接口。
type simpleConfigMapManager struct {
	kubeClient clientset.Interface
}

// NewSimpleConfigMapManager创建一个新的ConfigMapManager实例。
func NewSimpleConfigMapManager(kubeClient clientset.Interface) Manager {
	return &simpleConfigMapManager{kubeClient: kubeClient}
}

func (s *simpleConfigMapManager) GetConfigMap(namespace, name string) (*v1.ConfigMap, error) {
	return s.kubeClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (s *simpleConfigMapManager) RegisterPod(pod *v1.Pod) {
}

func (s *simpleConfigMapManager) UnregisterPod(pod *v1.Pod) {
}
```

## configMapManager

```go
// configMapManager保持了所有已注册的Pod所需的configmap的缓存。存储的不同实现
// 可能会导致不同的configmap新鲜度语义（例如基于TTL的实现与基于Watch的实现）。
type configMapManager struct {
	manager manager.Manager
}

func (c *configMapManager) GetConfigMap(namespace, name string) (*v1.ConfigMap, error) {
	object, err := c.manager.GetObject(namespace, name)
	if err != nil {
		return nil, err
	}
	if configmap, ok := object.(*v1.ConfigMap); ok {
		return configmap, nil
	}
	return nil, fmt.Errorf("unexpected object type: %v", object)
}

func (c *configMapManager) RegisterPod(pod *v1.Pod) {
	c.manager.RegisterPod(pod)
}

func (c *configMapManager) UnregisterPod(pod *v1.Pod) {
	c.manager.UnregisterPod(pod)
}
```

### manager.Manager

```go
// Manager是用于在底层缓存中注册和注销被Pod引用的对象以及在需要时从缓存中提取这些对象的接口。
type Manager interface {
	// 通过命名空间和名称获取对象。
	GetObject(namespace, name string) (runtime.Object, error)

	// 警告：Register/UnregisterPod函数应高效，即不应阻塞在网络操作上。

	// RegisterPod注册给定Pod引用的所有对象。
	//
	// 注意：所有RegisterPod的实现都应是幂等的。
	RegisterPod(pod *v1.Pod)

	// UnregisterPod注销给定Pod引用的不被任何其他注册的Pod使用的对象。
	//
	// 注意：所有UnregisterPod的实现都应是幂等的。
	UnregisterPod(pod *v1.Pod)
}

// cacheBasedManager保持了一个存储注册Pod所需对象的存储。存储的不同实现
// 可能会导致不同的对象新鲜度语义（例如基于TTL的实现与基于Watch的实现）。
type cacheBasedManager struct {
	objectStore          Store
	getReferencedObjects func(*v1.Pod) sets.String

	lock           sync.Mutex
	registeredPods map[objectKey]*v1.Pod
}

func (c *cacheBasedManager) GetObject(namespace, name string) (runtime.Object, error) {
	return c.objectStore.Get(namespace, name)
}

func (c *cacheBasedManager) RegisterPod(pod *v1.Pod) {
	names := c.getReferencedObjects(pod)
	c.lock.Lock()
	defer c.lock.Unlock()
	for name := range names {
		c.objectStore.AddReference(pod.Namespace, name, pod.UID)
	}
	var prev *v1.Pod
	key := objectKey{namespace: pod.Namespace, name: pod.Name, uid: pod.UID}
	prev = c.registeredPods[key]
	c.registeredPods[key] = pod
	if prev != nil {
		for name := range c.getReferencedObjects(prev) {
			// 在更新时，上面的.Add()调用将重新递增任何现有对象的引用计数，
			// 因此任何同时存在于names和prev中的对象的引用计数都需要递减。
			// 仅在prev中存在的对象需要完全删除。此无条件调用会处理这两种情况。
			c.objectStore.DeleteReference(prev.Namespace, name, prev.UID)
		}
	}
}

func (c *cacheBasedManager) UnregisterPod(pod *v1.Pod) {
	var prev *v1.Pod
	key := objectKey{namespace: pod.Namespace, name: pod.Name, uid: pod.UID}
	c.lock.Lock()
	defer c.lock.Unlock()
	prev = c.registeredPods[key]
	delete(c.registeredPods, key)
	if prev != nil {
		for name := range c.getReferencedObjects(prev) {
			c.objectStore.DeleteReference(prev.Namespace, name, prev.UID)
		}
	}
}
```

### NewCachingConfigMapManager

```go
// NewCachingConfigMapManager创建一个管理器，它保持了所有已注册的Pod所需的configmap的缓存。
// 它实现了以下逻辑：
// - 每当创建或更新Pod时，所有configmap的缓存版本都会失效
// - 每次GetObject()调用都尝试从本地缓存中获取值；如果缓存中没有，或者已失效或过时，
// 我们会从apiserver中获取它并刷新缓存中的值；否则，它将直接从缓存中获取
func NewCachingConfigMapManager(kubeClient clientset.Interface, getTTL manager.GetObjectTTLFunc) Manager {
	getConfigMap := func(namespace, name string, opts metav1.GetOptions) (runtime.Object, error) {
		return kubeClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, opts)
	}
	configMapStore := manager.NewObjectStore(getConfigMap, clock.RealClock{}, getTTL, defaultTTL)
	return &configMapManager{
		manager: manager.NewCacheBasedManager(configMapStore, getConfigMapNames),
	}
}
```

### NewWatchingConfigMapManager

```go
// NewWatchingConfigMapManager创建一个管理器，它保持了所有已注册的Pod所需的configmap的缓存。
// 它实现了以下逻辑：
// - 每当创建或更新Pod时，我们会为所有未被其他已注册Pod引用的对象启动单独的监听
// - 每次GetObject()返回通过监听传播的本地缓存中的值
func NewWatchingConfigMapManager(kubeClient clientset.Interface, resyncInterval time.Duration) Manager {
	listConfigMap := func(namespace string, opts metav1.ListOptions) (runtime.Object, error) {
		return kubeClient.CoreV1().ConfigMaps(namespace).List(context.TODO(), opts)
	}
	watchConfigMap := func(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
		return kubeClient.CoreV1().ConfigMaps(namespace).Watch(context.TODO(), opts)
	}
	newConfigMap := func() runtime.Object {
		return &v1.ConfigMap{}
	}
	isImmutable := func(object runtime.Object) bool {
		if configMap, ok := object.(*v1.ConfigMap); ok {
			return configMap.Immutable != nil && *configMap.Immutable
		}
		return false
	}
	gr := corev1.Resource("configmap")
	return &configMapManager{
		manager: manager.NewWatchBasedManager(listConfigMap, watchConfigMap, newConfigMap, isImmutable, gr, resyncInterval, getConfigMapNames),
	}
}
```

## secret Manager

```go
// Manager管理Kubernetes的Secrets。包括通过Pods检索Secrets或注册/注销Secrets。
type Manager interface {
	// 通过Secret的命名空间和名称获取Secret。
	GetSecret(namespace, name string) (*v1.Secret, error)

	// 警告：Register/UnregisterPod函数应高效，即不应阻塞在网络操作上。

	// RegisterPod注册给定Pod引用的所有Secrets。
	RegisterPod(pod *v1.Pod)

	// UnregisterPod注销给定Pod引用的不被任何其他注册的Pod使用的Secrets。
	UnregisterPod(pod *v1.Pod)
}

```

## simpleSecretManager

```go
// simpleSecretManager使用简单的操作对apiserver实现了SecretManager接口。
type simpleSecretManager struct {
	kubeClient clientset.Interface
}

// NewSimpleSecretManager创建一个新的SecretManager实例。
func NewSimpleSecretManager(kubeClient clientset.Interface) Manager {
	return &simpleSecretManager{kubeClient: kubeClient}
}

func (s *simpleSecretManager) GetSecret(namespace, name string) (*v1.Secret, error) {
	return s.kubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (s *simpleSecretManager) RegisterPod(pod *v1.Pod) {
}

func (s *simpleSecretManager) UnregisterPod(pod *v1.Pod) {
}
```

## GetSecret

```go
// secretManager保持一个存储注册的Pod所需的秘密的存储库。存储的不同实现可能导致秘密新鲜度的不同语义（例如基于TTL的实现与基于观察的实现）。
type secretManager struct {
	manager manager.Manager
}

// GetSecret方法根据命名空间和名称获取秘密。首先通过manager.GetObject方法获取对象，然后检查对象类型是否为*v1.Secret，如果是，则返回该秘密；否则返回错误。
func (s *secretManager) GetSecret(namespace, name string) (*v1.Secret, error) {
	object, err := s.manager.GetObject(namespace, name)
	if err != nil {
		return nil, err
	}
	if secret, ok := object.(*v1.Secret); ok {
		return secret, nil
	}
	return nil, fmt.Errorf("unexpected object type: %v", object)
}

// RegisterPod方法将Pod注册到管理器中。
func (s *secretManager) RegisterPod(pod *v1.Pod) {
	s.manager.RegisterPod(pod)
}

// UnregisterPod方法从管理器中注销Pod。
func (s *secretManager) UnregisterPod(pod *v1.Pod) {
	s.manager.UnregisterPod(pod)
}
```

### NewCachingSecretManager

```go
// NewCachingSecretManager创建一个保持所有注册Pod所需秘密的缓存的管理器。
// 它实现以下逻辑：
// - 每当创建或更新一个Pod时，缓存中的所有秘密的缓存版本将被失效
// - 每个GetObject()调用尝试从本地缓存获取值；如果不存在、失效或太旧，则从api服务器获取它并刷新缓存中的值；否则，直接从缓存获取
func NewCachingSecretManager(kubeClient clientset.Interface, getTTL manager.GetObjectTTLFunc) Manager {
	getSecret := func(namespace, name string, opts metav1.GetOptions) (runtime.Object, error) {
		return kubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, opts)
	}
	secretStore := manager.NewObjectStore(getSecret, clock.RealClock{}, getTTL, defaultTTL)
	return &secretManager{
		manager: manager.NewCacheBasedManager(secretStore, getSecretNames),
	}
}
```

#### getSecretNames

```go
// getSecretNames函数接受一个*v1.Pod参数，并返回一个sets.String对象，包含与Pod关联的秘密名称集合。
func getSecretNames(pod *v1.Pod) sets.String {
	result := sets.NewString()
	podutil.VisitPodSecretNames(pod, func(name string) bool {
		result.Insert(name)
		return true
	})
	return result
}
```

### NewWatchingSecretManager

```go
// NewWatchingSecretManager创建一个保持所有注册Pod所需秘密的缓存的管理器。
// 它实现以下逻辑：
// - 每当创建或更新一个Pod时，我们为所有未被其他注册的Pod引用的对象启动单独的观察器
// - 每个GetObject()返回通过观察器传播的本地缓存中的值
func NewWatchingSecretManager(kubeClient clientset.Interface, resyncInterval time.Duration) Manager {
	listSecret := func(namespace string, opts metav1.ListOptions) (runtime.Object, error) {
		return kubeClient.CoreV1().Secrets(namespace).List(context.TODO(), opts)
	}
	watchSecret := func(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
		return kubeClient.CoreV1().Secrets(namespace).Watch(context.TODO(), opts)
	}
	newSecret := func() runtime.Object {
		return &v1.Secret{}
	}
	isImmutable := func(object runtime.Object) bool {
		if secret, ok := object.(*v1.Secret); ok {
			return secret.Immutable != nil && *secret.Immutable
		}
		return false
	}
	gr := corev1.Resource("secret")
	return &secretManager{
		manager: manager.NewWatchBasedManager(listSecret, watchSecret, newSecret, isImmutable, gr, resyncInterval, getSecretNames),
	}
}
```

