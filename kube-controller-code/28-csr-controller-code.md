
## certificates-controller

### 简介

certificates-controller是Kubernetes的一个内置控制器，用于管理与证书相关的任务。

证书在Kubernetes中扮演着非常重要的角色，包括安全通信、TLS认证和访问控制等。为了确保证书的有效性和安全性，Kubernetes引入了证书控制器来管理证书的生命周期。

具体来说，certificates-controller主要负责以下任务：

1.证书签发和更新：它可以通过配置自动化证书签发和更新流程，可以自动为Kubernetes集群中的各个组件生成所需的证书，并在证书即将过期时自动更新。

2.证书分发和管理：证书控制器还负责在Kubernetes集群中分发和管理证书。它可以确保证书被正确地分发到集群中的各个节点，并在需要时自动将更新后的证书分发到相应的节点。

3.证书监控和故障排除：证书控制器还能够监控证书的有效期和状态，并在出现问题时及时发出警报。它还可以自动修复证书相关的故障，并记录故障排除过程中的日志。

### 结构体

```GO
type CertificateController struct {
	// 标识此控制器实例的名称
	name string

	kubeClient clientset.Interface

	csrLister  certificateslisters.CertificateSigningRequestLister
	csrsSynced cache.InformerSynced
	// 处理证书签发请求的函数
	handler func(context.Context, *certificates.CertificateSigningRequest) error
	// 工作队列
	queue workqueue.RateLimitingInterface
}
```

### New

```go
func NewCertificateController(
	name string,
	kubeClient clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	handler func(context.Context, *certificates.CertificateSigningRequest) error,
) *CertificateController {
	cc := &CertificateController{
		name:       name,
		kubeClient: kubeClient,
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
			// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "certificate"),
		handler: handler,
	}

	// 监控CertificateSigning对象
	csrInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			klog.V(4).Infof("Adding certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldCSR := old.(*certificates.CertificateSigningRequest)
			klog.V(4).Infof("Updating certificate request %s", oldCSR.Name)
			cc.enqueueCertificateRequest(new)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.V(2).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					klog.V(2).Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			klog.V(4).Infof("Deleting certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
	})
	cc.csrLister = csrInformer.Lister()
	cc.csrsSynced = csrInformer.Informer().HasSynced
	return cc
}
```

#### 队列相关

```go
func (cc *CertificateController) enqueueCertificateRequest(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	cc.queue.Add(key)
}
```

### Run

```GO
func (cc *CertificateController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer cc.queue.ShutDown()

	klog.Infof("Starting certificate controller %q", cc.name)
	defer klog.Infof("Shutting down certificate controller %q", cc.name)

	if !cache.WaitForNamedCacheSync(fmt.Sprintf("certificate-%s", cc.name), ctx.Done(), cc.csrsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, cc.worker, time.Second)
	}

	<-ctx.Done()
}
```

#### worker

```go
func (cc *CertificateController) worker(ctx context.Context) {
	for cc.processNextWorkItem(ctx) {
	}
}


func (cc *CertificateController) processNextWorkItem(ctx context.Context) bool {
	cKey, quit := cc.queue.Get()
	if quit {
		return false
	}
	defer cc.queue.Done(cKey)

	if err := cc.syncFunc(ctx, cKey.(string)); err != nil {
        // 出错重试
		cc.queue.AddRateLimited(cKey)
		if _, ignorable := err.(ignorableError); !ignorable {
            // 如果是ignorableError错误 处理错误
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with : %v", cKey, err))
		} else {
			klog.V(4).Infof("Sync %v failed with : %v", cKey, err)
		}
		return true
	}

	cc.queue.Forget(cKey)
	return true

}
```

##### syncFunc

```GO
func (cc *CertificateController) syncFunc(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()
	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
        // 没有找到直接返回
		klog.V(3).Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if len(csr.Status.Certificate) > 0 {
		// no need to do anything because it already has a cert
		return nil
	}

	// need to operate on a copy so we don't mutate the csr in the shared cache
	csr = csr.DeepCopy()
    // 处理证书签发请求，并返回处理结果
	return cc.handler(ctx, csr)
}
```

## Csrcleaner-controller

### 简介

Csrcleaner-controller是Kubernetes中的一个控制器，用于删除已过期的证书签发请求(CertificateSigningRequest)。

在Kubernetes中，证书签发请求通常是由kubelet生成并提交到Kubernetes API Server中的。kubelet会定期生成新的证书签发请求并提交到API Server中，而旧的证书签发请求将会被保留在API Server中。为了避免旧的证书签发请求占用过多的存储空间，Csrcleaner-controller会定期扫描证书签发请求，删除已过期的请求并释放存储空间。

### 结构体

```GO
type CSRCleanerController struct {
	csrClient csrclient.CertificateSigningRequestInterface
	csrLister certificateslisters.CertificateSigningRequestLister
}
```

### New

```go
func NewCSRCleanerController(
	csrClient csrclient.CertificateSigningRequestInterface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
) *CSRCleanerController {
	return &CSRCleanerController{
		csrClient: csrClient,
		csrLister: csrInformer.Lister(),
	}
}
```

### Run

```go
func (ccc *CSRCleanerController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	klog.Infof("Starting CSR cleaner controller")
	defer klog.Infof("Shutting down CSR cleaner controller")

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, ccc.worker, pollingInterval)
	}

	<-ctx.Done()
}
```

#### worker

```go
func (ccc *CSRCleanerController) worker(ctx context.Context) {
    // 获取所有的csr笃信
	csrs, err := ccc.csrLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("Unable to list CSRs: %v", err)
		return
	}
	for _, csr := range csrs {
        // 每个都做处理
		if err := ccc.handle(ctx, csr); err != nil {
			klog.Errorf("Error while attempting to clean CSR %q: %v", csr.Name, err)
		}
	}
}
```

##### handle

```GO
func (ccc *CSRCleanerController) handle(ctx context.Context, csr *capi.CertificateSigningRequest) error {
	if isIssuedPastDeadline(csr) || isDeniedPastDeadline(csr) || isFailedPastDeadline(csr) || isPendingPastDeadline(csr) || isIssuedExpired(csr) {
        //如果csr已过期或者未通过、已拒绝、已失败或者已超过期限，进入判断
		if err := ccc.csrClient.Delete(ctx, csr.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("unable to delete CSR %q: %v", csr.Name, err)
		}
	}
	return nil
}
```

###### Is

```go
// 判断csr是否已经被批准且已经过期，如果是，记录日志并返回true；否则返回false。
func isIssuedExpired(csr *capi.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == capi.CertificateApproved && isIssued(csr) && isExpired(csr) {
			klog.Infof("Cleaning CSR %q as the associated certificate is expired.", csr.Name)
			return true
		}
	}
	return false
}

// 判断csr是否处于Pending状态且已经超过指定的时间限制，如果是，记录日志并返回true；否则返回false。
func isPendingPastDeadline(csr *capi.CertificateSigningRequest) bool {
	// If there are no Conditions on the status, the CSR will appear via
	// `kubectl` as `Pending`.
	if len(csr.Status.Conditions) == 0 && isOlderThan(csr.CreationTimestamp, pendingExpiration) {
		klog.Infof("Cleaning CSR %q as it is more than %v old and unhandled.", csr.Name, pendingExpiration)
		return true
	}
	return false
}

// 判断csr是否被拒绝且已经超过指定的时间限制，如果是，记录日志并返回true；否则返回false。
func isDeniedPastDeadline(csr *capi.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == capi.CertificateDenied && isOlderThan(c.LastUpdateTime, deniedExpiration) {
			klog.Infof("Cleaning CSR %q as it is more than %v old and denied.", csr.Name, deniedExpiration)
			return true
		}
	}
	return false
}

// 判断csr是否失败且已经超过指定的时间限制，如果是，记录日志并返回true；否则返回false。
func isFailedPastDeadline(csr *capi.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == capi.CertificateFailed && isOlderThan(c.LastUpdateTime, deniedExpiration) {
			klog.Infof("Cleaning CSR %q as it is more than %v old and failed.", csr.Name, deniedExpiration)
			return true
		}
	}
	return false
}

// 判断csr是否已经被批准且已经超过指定的时间限制，如果是，记录日志并返回true；否则返回false。
func isIssuedPastDeadline(csr *capi.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == capi.CertificateApproved && isIssued(csr) && isOlderThan(c.LastUpdateTime, approvedExpiration) {
			klog.Infof("Cleaning CSR %q as it is more than %v old and approved.", csr.Name, approvedExpiration)
			return true
		}
	}
	return false
}


// 判断时间t是否在当前时间之前d个时间单位，如果是，返回true；否则返回false。
func isOlderThan(t metav1.Time, d time.Duration) bool {
	return !t.IsZero() && t.Sub(time.Now()) < -1*d
}


// 判断csr是否已经被签发，如果已经签发，返回true；否则返回false。
func isIssued(csr *capi.CertificateSigningRequest) bool {
	return len(csr.Status.Certificate) > 0
}

// 判断csr中的证书是否已经过期，如果已经过期，返回true；否则返回false。
func isExpired(csr *capi.CertificateSigningRequest) bool {
	if len(csr.Status.Certificate) == 0 {
		return false
	}
	block, _ := pem.Decode(csr.Status.Certificate)
	if block == nil {
		return false
	}
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return false
	}
	if len(certs) == 0 {
		return false
	}
	return time.Now().After(certs[0].NotAfter)
}
```

## csrapproving-controller

### 简介

csrapproving-controller是Kubernetes中的一个控制器，用于自动批准Kubernetes证书签名请求（CertificateSigningRequest）。当一个CSR对象被创建后，Kubernetes会将其发送到与其相关的证书签名机构（CA）进行签名。在发送到CA之前，CSR需要被管理员或其他授权实体进行审批。csrapproving-controller就是用来自动审批这些CSR对象的控制器。

其主要作用是监听Kubernetes集群中的CSR对象，当有新的CSR对象创建时，自动审批它们。这样，管理员或其他授权实体就不需要手动审批每个CSR对象，减少了审批的工作量和时间，提高了工作效率。同时，csrapproving-controller也可以确保只有经过授权的实体才能签署证书请求，从而增强了Kubernetes集群的安全性。

### 结构体

```GO
type csrRecognizer struct {
    // 识别给定的CSR对象是否符合该识别器的规则。
	recognize      func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
    // 对该CSR对象所需的权限
	permission     authorization.ResourceAttributes
    // 在审批成功时返回的消息
	successMessage string
}

type sarApprover struct {
	client      clientset.Interface
    // CSR识别器的集合
	recognizers []csrRecognizer
}
```

### New

```GO
func NewCSRApprovingController(client clientset.Interface, csrInformer certificatesinformers.CertificateSigningRequestInformer) *certificates.CertificateController {
	approver := &sarApprover{
		client:      client,
		recognizers: recognizers(),
	}
    // 调用certificates-controller 然后执行run 在woker里调用hadle
	return certificates.NewCertificateController(
		"csrapproving",
		client,
		csrInformer,
		approver.handle,
	)
}
```

#### recognizers

```GO
func recognizers() []csrRecognizer {
	recognizers := []csrRecognizer{
		{
			recognize:      isSelfNodeClientCert,
			permission:     authorization.ResourceAttributes{Group: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "create", Subresource: "selfnodeclient"},
			successMessage: "Auto approving self kubelet client certificate after SubjectAccessReview.",
		},
		{
			recognize:      isNodeClientCert,
			permission:     authorization.ResourceAttributes{Group: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "create", Subresource: "nodeclient"},
			successMessage: "Auto approving kubelet client certificate after SubjectAccessReview.",
		},
	}
	return recognizers
}

```

##### isSelfNodeClientCert

```GO
func isSelfNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if csr.Spec.Username != x509cr.Subject.CommonName {
		return false
	}
	return isNodeClientCert(csr, x509cr)
}
```

##### isNodeClientCert

```GO
func isNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if csr.Spec.SignerName != capi.KubeAPIServerClientKubeletSignerName {
		return false
	}
	return capihelper.IsKubeletClientCSR(x509cr, usagesToSet(csr.Spec.Usages))
}

```

##### usagesToSet

```GO
func usagesToSet(usages []capi.KeyUsage) sets.String {
	result := sets.NewString()
	for _, usage := range usages {
		result.Insert(string(usage))
	}
	return result
}
```

### Handle

```GO
func (a *sarApprover) handle(ctx context.Context, csr *capi.CertificateSigningRequest) error {
	if len(csr.Status.Certificate) != 0 { // 如果证书已经签发，返回 nil
		return nil
	}
	if approved, denied := certificates.GetCertApprovalCondition(&csr.Status); approved || denied { // 如果已经被批准或拒绝，返回 nil
		return nil
	}
	x509cr, err := capihelper.ParseCSR(csr.Spec.Request) // 解析 csr 请求中的 x509 证书请求
	if err != nil {
		return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
	}

	tried := []string{} // 存储已经尝试过的认证方法

	// 遍历所有认证方法
	for _, r := range a.recognizers {
		if !r.recognize(csr, x509cr) { // 判断认证方法是否匹配 csr 和 x509 证书请求
			continue
		}

		tried = append(tried, r.permission.Subresource) // 记录认证方法名称

		// 验证权限
		approved, err := a.authorize(ctx, csr, r.permission)
		if err != nil {
			return err
		}
		if approved { // 如果权限验证通过
			appendApprovalCondition(csr, r.successMessage) // 给 csr 添加批准条件
			_, err = a.client.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("error updating approval for csr: %v", err)
			}
			return nil // 返回 nil，表示已经批准了该 csr
		}
	}

	if len(tried) != 0 { // 如果尝试过一些认证方法，但是最终没有通过
		return certificates.IgnorableError("recognized csr %q as %v but subject access review was not approved", csr.Name, tried) // 返回认证失败的错误信息
	}

	return nil // 如果没有任何认证方法可以匹配 csr 和 x509 证书请求，返回 nil
}
```

#### GetCertApprovalCondition

```GO
func GetCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return
}
```

#### authorize

```GO
func (a *sarApprover) authorize(ctx context.Context, csr *capi.CertificateSigningRequest, rattrs authorization.ResourceAttributes) (bool, error) {
	extra := make(map[string]authorization.ExtraValue)
	// 遍历 csr.Spec.Extra 的键值对，并将其转化为授权操作所需要的 ExtraValue 类型
	for k, v := range csr.Spec.Extra {
		extra[k] = authorization.ExtraValue(v)
	}

	// 构造 SubjectAccessReview 对象
	sar := &authorization.SubjectAccessReview{
		Spec: authorization.SubjectAccessReviewSpec{
			User:               csr.Spec.Username,             // 请求操作的用户
			UID:                csr.Spec.UID,                  // 用户的唯一标识符
			Groups:             csr.Spec.Groups,               // 用户所属的组
			Extra:              extra,                         // 请求操作时携带的额外信息
			ResourceAttributes: &rattrs,                      // 请求操作的资源和行为
		},
	}
	// 调用 Kubernetes API server 来进行授权操作
	sar, err := a.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	// 返回授权操作的结果，即是否允许该操作
	return sar.Status.Allowed, nil
}

```

#### appendApprovalCondition

```GO
func appendApprovalCondition(csr *capi.CertificateSigningRequest, message string) {
	csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
		Type:    capi.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AutoApproved",
		Message: message,
	})
}
```

## root-ca-cert-publisher-controller

### 简介

root-ca-cert-publisher-controller是Kubernetes的一个控制器，用于将根证书添加到集群中的所有节点上，以便节点可以验证使用Kubernetes签名的证书。

在Kubernetes集群中，使用自签名证书来建立信任关系，这意味着每个节点都必须具有根证书以验证签名。root-ca-cert-publisher-controller的作用是确保根证书被添加到所有节点上，以便节点可以信任使用Kubernetes签名的证书，从而确保通信的安全性和保密性。

root-ca-cert-publisher-controller的主要任务是定期轮询Kubernetes API Server以获取当前根证书，并将其分发到集群中的每个节点上。如果根证书发生更改，则root-ca-cert-publisher-controller将在集群中的所有节点上更新证书。

该控制器使用ConfigMap来存储根证书，定期从ConfigMap中获取当前的根证书，并在集群中的所有节点上安装它。此外，root-ca-cert-publisher-controller还负责确保节点重新启动后可以自动获取根证书。

### init

```go
func init() {
	registerMetrics()
}

const RootCACertPublisher = "root_ca_cert_publisher"

var (
	syncCounter = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Subsystem:      RootCACertPublisher,
			Name:           "sync_total",
			Help:           "Number of namespace syncs happened in root ca cert publisher.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"code"},
	)
	syncLatency = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Subsystem:      RootCACertPublisher,
			Name:           "sync_duration_seconds",
			Help:           "Number of namespace syncs happened in root ca cert publisher.",
			Buckets:        metrics.ExponentialBuckets(0.001, 2, 15),
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"code"},
	)
)

func recordMetrics(start time.Time, err error) {
	code := "500"
	if err == nil {
		code = "200"
	} else if se, ok := err.(*apierrors.StatusError); ok && se.Status().Code != 0 {
		code = strconv.Itoa(int(se.Status().Code))
	}
	syncLatency.WithLabelValues(code).Observe(time.Since(start).Seconds())
	syncCounter.WithLabelValues(code).Inc()
}

var once sync.Once

func registerMetrics() {
	once.Do(func() {
		legacyregistry.MustRegister(syncCounter)
		legacyregistry.MustRegister(syncLatency)
	})
```

### 结构体

```GO
type Publisher struct {
	client clientset.Interface
    // Root CA 证书的字节数组
	rootCA []byte

	// 用于同步处理的函数
	syncHandler func(ctx context.Context, key string) error

	cmLister       corelisters.ConfigMapLister
	cmListerSynced cache.InformerSynced

	nsListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface
}
```

### New

```go
func NewPublisher(cmInformer coreinformers.ConfigMapInformer, nsInformer coreinformers.NamespaceInformer, cl clientset.Interface, rootCA []byte) (*Publisher, error) {
	e := &Publisher{
		client: cl,
		rootCA: rootCA,
		queue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "root_ca_cert_publisher"),
	}
	// 监控configMap
	cmInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: e.configMapDeleted,
		UpdateFunc: e.configMapUpdated,
	})
	e.cmLister = cmInformer.Lister()
	e.cmListerSynced = cmInformer.Informer().HasSynced
	// 监控namespace
	nsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    e.namespaceAdded,
		UpdateFunc: e.namespaceUpdated,
	})
	e.nsListerSynced = nsInformer.Informer().HasSynced

	e.syncHandler = e.syncNamespace

	return e, nil
}
```

#### 队列相关

##### configMap

```go
func (c *Publisher) configMapDeleted(obj interface{}) {
	cm, err := convertToCM(obj)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}
	if cm.Name != RootCACertConfigMapName {
		return
	}
	c.queue.Add(cm.Namespace)
}

func (c *Publisher) configMapUpdated(_, newObj interface{}) {
	cm, err := convertToCM(newObj)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}
	if cm.Name != RootCACertConfigMapName {
		return
	}
	c.queue.Add(cm.Namespace)
}
```

##### namespace

```go
func (c *Publisher) namespaceAdded(obj interface{}) {
	namespace := obj.(*v1.Namespace)
	c.queue.Add(namespace.Name)
}

func (c *Publisher) namespaceUpdated(oldObj interface{}, newObj interface{}) {
	newNamespace := newObj.(*v1.Namespace)
	if newNamespace.Status.Phase != v1.NamespaceActive {
		return
	}
	c.queue.Add(newNamespace.Name)
}
```

##### convertToCM

```GO
func convertToCM(obj interface{}) (*v1.ConfigMap, error) {
	cm, ok := obj.(*v1.ConfigMap)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %#v", obj)
		}
		cm, ok = tombstone.Obj.(*v1.ConfigMap)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a ConfigMap %#v", obj)
		}
	}
	return cm, nil
}
```

### Run

```go
func (c *Publisher) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting root CA certificate configmap publisher")
	defer klog.Infof("Shutting down root CA certificate configmap publisher")

	if !cache.WaitForNamedCacheSync("crt configmap", ctx.Done(), c.cmListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

### runWorker

```go
func (c *Publisher) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}


func (c *Publisher) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	
    // 执行同步
	if err := c.syncHandler(ctx, key.(string)); err != nil {
		utilruntime.HandleError(fmt.Errorf("syncing %q failed: %v", key, err))
        // 出错重试
		c.queue.AddRateLimited(key)
		return true
	}

	c.queue.Forget(key)
	return true
}
```

#### syncNamespace

```GO
func (c *Publisher) syncNamespace(ctx context.Context, ns string) (err error) {
	startTime := time.Now()
	defer func() {
		recordMetrics(startTime, err)
		klog.V(4).Infof("Finished syncing namespace %q (%v)", ns, time.Since(startTime))
	}()
    // 查询名为 RootCACertConfigMapName 的 ConfigMap
    cm, err := c.cmLister.ConfigMaps(ns).Get(RootCACertConfigMapName)
    switch {
    // 如果 ConfigMap 不存在，则创建一个新的 ConfigMap
    case apierrors.IsNotFound(err):
        _, err = c.client.CoreV1().ConfigMaps(ns).Create(ctx, &v1.ConfigMap{
            ObjectMeta: metav1.ObjectMeta{
                Name:        RootCACertConfigMapName,
                Annotations: map[string]string{DescriptionAnnotation: Description},
            },
            Data: map[string]string{
                "ca.crt": string(c.rootCA),
            },
        }, metav1.CreateOptions{})
        // 如果命名空间不存在或正在终止，则不重试创建
        if apierrors.IsNotFound(err) || apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
            return nil
        }
        return err
    // 如果出现错误，则返回错误
    case err != nil:
        return err
    }

    // 如果 ConfigMap 中的数据和描述其用途的注释匹配，则返回 nil
    data := map[string]string{
        "ca.crt": string(c.rootCA),
    }
    if reflect.DeepEqual(cm.Data, data) && len(cm.Annotations[DescriptionAnnotation]) > 0 {
        return nil
    }

    // 复制 ConfigMap，以便不修改缓存中的 ConfigMap 实例
    cm = cm.DeepCopy()
    cm.Data = data
    if cm.Annotations == nil {
        cm.Annotations = map[string]string{}
    }
    cm.Annotations[DescriptionAnnotation] = Description

    // 更新 ConfigMap
    _, err = c.client.CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{})
    return err
}
```

## csrsigning-controller

### 简介

CSRSigning Controller 是 Kubernetes 中的一个控制器，它负责签署 Kubernetes 集群中的证书签名请求（Certificate Signing Requests，CSR），以便为新的 TLS 证书创建签名。它是 kube-controller-manager 的一部分，并作为 Kubernetes CSR API 的一部分运行。

CSRSigning Controller 通过 kube-controller-manager 的 CSRApprover 调用 Kubernetes API Server 中的证书签名 API（certificates.k8s.io/v1）来批准和签署 CSR。此控制器使用 kubernetes.io/cluster-service=true 标签标记的 serviceaccount 运行。

CSRSigning Controller 使 Kubernetes 集群管理员能够管理证书的签名和续订，这些证书用于安全地保护集群中的各种资源。在 Kubernetes 集群中部署时，集群管理人员可以使用 CSRSigning Controller 来自动签署证书请求并更新 TLS 证书。这有助于简化管理证书的过程，并确保证书的使用得到适当的跟踪和记录。

### 结构体

```GO
type CSRSigningController struct {
	certificateController *certificates.CertificateController
	dynamicCertReloader   dynamiccertificates.ControllerRunner
}
```

### CertificateController

```GO
type CertificateController struct {
	// name is an identifier for this particular controller instance.
	name string

	kubeClient clientset.Interface

	csrLister  certificateslisters.CertificateSigningRequestLister
	csrsSynced cache.InformerSynced
	
    // 处理函数
	handler func(context.Context, *certificates.CertificateSigningRequest) error

	queue workqueue.RateLimitingInterface
}

```

#### New

```go
func NewCertificateController(
	name string,
	kubeClient clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	handler func(context.Context, *certificates.CertificateSigningRequest) error,
) *CertificateController {
	cc := &CertificateController{
		name:       name,
		kubeClient: kubeClient,
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
			// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "certificate"),
		handler: handler,
	}

	// 监控csr对象
	csrInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			klog.V(4).Infof("Adding certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldCSR := old.(*certificates.CertificateSigningRequest)
			klog.V(4).Infof("Updating certificate request %s", oldCSR.Name)
			cc.enqueueCertificateRequest(new)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.V(2).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					klog.V(2).Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			klog.V(4).Infof("Deleting certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
	})
	cc.csrLister = csrInformer.Lister()
	cc.csrsSynced = csrInformer.Informer().HasSynced
	return cc
}
```

##### enqueueCertificateRequest

```GO
func (cc *CertificateController) enqueueCertificateRequest(obj interface{}) {
	key, err := controller.KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	cc.queue.Add(key)
}
```

#### syncFunc

```GO
func (cc *CertificateController) syncFunc(ctx context.Context, key string) error {
	startTime := time.Now()
	// 记录代码执行开始时间，并在函数退出前记录度量和日志信息
	defer func() {
		klog.V(4).Infof("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()

	// 根据 key 从 csrLister 中获取对应的 CSR 对象
	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
		// 如果 CSR 不存在，则直接返回 nil，表示无需执行任何操作
		klog.V(3).Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		// 如果获取 CSR 的过程中出现错误，则直接返回该错误
		return err
	}

	if len(csr.Status.Certificate) > 0 {
		// 如果 CSR 对象已经有证书，则无需再执行任何操作，直接返回 nil
		return nil
	}

	// 需要对 csr 进行深拷贝，以便在后续操作中不会修改共享缓存中的 csr 对象
	csr = csr.DeepCopy()
	// 调用控制器的处理函数，处理 csr 对象，签署证书等操作
	return cc.handler(ctx, csr)
}
```

#### ignorableError

```GO
func IgnorableError(s string, args ...interface{}) ignorableError {
	return ignorableError(fmt.Sprintf(s, args...))
}

type ignorableError string

func (e ignorableError) Error() string {
	return string(e)
}
```

### New

```GO
func NewKubeletServingCSRSigningController(
	client clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	caFile, caKeyFile string,
	certTTL time.Duration,
) (*CSRSigningController, error) {
	return NewCSRSigningController("csrsigning-kubelet-serving", capi.KubeletServingSignerName, client, csrInformer, caFile, caKeyFile, certTTL)
}

func NewKubeletClientCSRSigningController(
	client clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	caFile, caKeyFile string,
	certTTL time.Duration,
) (*CSRSigningController, error) {
	return NewCSRSigningController("csrsigning-kubelet-client", capi.KubeAPIServerClientKubeletSignerName, client, csrInformer, caFile, caKeyFile, certTTL)
}

func NewKubeAPIServerClientCSRSigningController(
	client clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	caFile, caKeyFile string,
	certTTL time.Duration,
) (*CSRSigningController, error) {
	return NewCSRSigningController("csrsigning-kube-apiserver-client", capi.KubeAPIServerClientSignerName, client, csrInformer, caFile, caKeyFile, certTTL)
}

func NewLegacyUnknownCSRSigningController(
	client clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	caFile, caKeyFile string,
	certTTL time.Duration,
) (*CSRSigningController, error) {
	return NewCSRSigningController("csrsigning-legacy-unknown", capiv1beta1.LegacyUnknownSignerName, client, csrInformer, caFile, caKeyFile, certTTL)
}

func NewCSRSigningController(
	controllerName string,
	signerName string,
	client clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	caFile, caKeyFile string,
	certTTL time.Duration,
) (*CSRSigningController, error) {
	signer, err := newSigner(signerName, caFile, caKeyFile, client, certTTL)
	if err != nil {
		return nil, err
	}

	return &CSRSigningController{
		certificateController: certificates.NewCertificateController(
			controllerName,
			client,
			csrInformer,
			signer.handle,
		),
		dynamicCertReloader: signer.caProvider.caLoader,
	}, nil
}
```

#### signer

```go
type signer struct {
    // 用于管理 CA 证书
	caProvider *caProvider

	client  clientset.Interface
	certTTL time.Duration //证书的最大有效期

	signerName           string //签名者的名称
	isRequestForSignerFn isRequestForSignerFunc // 用于确定给定的 CSR 是否是该签名者要处理的请求的函数
}

type isRequestForSignerFunc func(req *x509.CertificateRequest, usages []capi.KeyUsage, signerName string) (bool, error)

func newSigner(signerName, caFile, caKeyFile string, client clientset.Interface, certificateDuration time.Duration) (*signer, error) {
    // 确定给定的 CSR 是否是该签名者要处理
	isRequestForSignerFn, err := getCSRVerificationFuncForSignerName(signerName)
	if err != nil {
		return nil, err
	}
    // 创建一个 caProvider 结构体的实例，用于管理 CA 证书
	caProvider, err := newCAProvider(caFile, caKeyFile)
	if err != nil {
		return nil, err
	}

	ret := &signer{
		caProvider:           caProvider,
		client:               client,
		certTTL:              certificateDuration,
		signerName:           signerName,
		isRequestForSignerFn: isRequestForSignerFn,
	}
	return ret, nil
}
```

##### getCSRVerificationFuncForSignerName

```go
func getCSRVerificationFuncForSignerName(signerName string) (isRequestForSignerFunc, error) {
	switch signerName {
	case capi.KubeletServingSignerName:
		return isKubeletServing, nil
	case capi.KubeAPIServerClientKubeletSignerName:
		return isKubeletClient, nil
	case capi.KubeAPIServerClientSignerName:
		return isKubeAPIServerClient, nil
	case capiv1beta1.LegacyUnknownSignerName:
		return isLegacyUnknown, nil
	default:
		// TODO type this error so that a different reporting loop (one without a signing cert), can mark
		//  CSRs with unknown kube signers as terminal if we wish.  This largely depends on how tightly we want to control
		//  our signerNames.
		return nil, fmt.Errorf("unrecognized signerName: %q", signerName)
	}
}

```

##### caProvider

```go
type caProvider struct {
	caValue  atomic.Value
	caLoader *dynamiccertificates.DynamicCertKeyPairContent
}

func newCAProvider(caFile, caKeyFile string) (*caProvider, error) {
	caLoader, err := dynamiccertificates.NewDynamicServingContentFromFiles("csr-controller", caFile, caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading CA cert file %q: %v", caFile, err)
	}

	ret := &caProvider{
		caLoader: caLoader,
	}
	if err := ret.setCA(); err != nil {
		return nil, err
	}

	return ret, nil
}

func (p *caProvider) setCA() error {
	certPEM, keyPEM := p.caLoader.CurrentCertKeyContent()

	certs, err := cert.ParseCertsPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error reading CA cert file %q: %v", p.caLoader.Name(), err)
	}
	if len(certs) != 1 {
		return fmt.Errorf("error reading CA cert file %q: expected 1 certificate, found %d", p.caLoader.Name(), len(certs))
	}

	key, err := keyutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("error reading CA key file %q: %v", p.caLoader.Name(), err)
	}
	priv, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("error reading CA key file %q: key did not implement crypto.Signer", p.caLoader.Name())
	}

	ca := &authority.CertificateAuthority{
		RawCert: certPEM,
		RawKey:  keyPEM,

		Certificate: certs[0],
		PrivateKey:  priv,
	}
	p.caValue.Store(ca)

	return nil
}

func (p *caProvider) currentCA() (*authority.CertificateAuthority, error) {
	certPEM, keyPEM := p.caLoader.CurrentCertKeyContent()
	currCA := p.caValue.Load().(*authority.CertificateAuthority)
	if bytes.Equal(currCA.RawCert, certPEM) && bytes.Equal(currCA.RawKey, keyPEM) {
		return currCA, nil
	}

	// the bytes weren't equal, so we have to set and then load
	if err := p.setCA(); err != nil {
		return currCA, err
	}
	return p.caValue.Load().(*authority.CertificateAuthority), nil
}

```

### Run

```go
func (c *CSRSigningController) Run(ctx context.Context, workers int) {
	go c.dynamicCertReloader.Run(ctx, workers)

	c.certificateController.Run(ctx, workers)
}
```

### handle

```go
func (s *signer) handle(ctx context.Context, csr *capi.CertificateSigningRequest) error {
	// 忽略未批准或已失败的请求
	if !certificates.IsCertificateRequestApproved(csr) || certificates.HasTrueCondition(csr, capi.CertificateFailed) {
		return nil
	}

	// 快速路径，如果 CSR 的签名器名称不匹配，则避免任何额外的处理
	if csr.Spec.SignerName != s.signerName {
		return nil
	}

	// 解析 CSR
	x509cr, err := capihelper.ParseCSR(csr.Spec.Request)
	if err != nil {
		return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
	}

	// 验证 CSR 是否适用于此签名器
	if recognized, err := s.isRequestForSignerFn(x509cr, csr.Spec.Usages, csr.Spec.SignerName); err != nil {
		// 如果不适用，则在 CSR 状态中添加一个条件，指示签名验证失败，并更新 CSR 的状态
		csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
			Type:           capi.CertificateFailed,
			Status:         v1.ConditionTrue,
			Reason:         "SignerValidationFailure",
			Message:        err.Error(),
			LastUpdateTime: metav1.Now(),
		})
		_, err = s.client.CertificatesV1().CertificateSigningRequests().UpdateStatus(ctx, csr, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("error adding failure condition for csr: %v", err)
		}
		return nil
	} else if !recognized {
		// 忽略我们不识别的 kubernetes.io 签名器名称的请求
		return nil
	}

	// 使用 CSR 请求的信息签署证书
	cert, err := s.sign(x509cr, csr.Spec.Usages, csr.Spec.ExpirationSeconds, nil)
	if err != nil {
		return fmt.Errorf("error auto signing csr: %v", err)
	}

	// 将签名后的证书更新到 CSR 的状态中，并更新 CSR 的状态
	csr.Status.Certificate = cert
	_, err = s.client.CertificatesV1().CertificateSigningRequests().UpdateStatus(ctx, csr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating signature for csr: %v", err)
	}
	return nil
}
```

#### sign

```go
func (s *signer) sign(x509cr *x509.CertificateRequest, usages []capi.KeyUsage, expirationSeconds *int32, now func() time.Time) ([]byte, error) {
	// 获取当前的CA
	currCA, err := s.caProvider.currentCA()
	if err != nil {
		return nil, err
	}
	// 使用当前的CA对x509证书请求进行签名，并指定签名策略
	der, err := currCA.Sign(x509cr.Raw, authority.PermissiveSigningPolicy{
		TTL:      s.duration(expirationSeconds), // 指定证书的过期时间
		Usages:   usages,                        // 指定证书的用途
		Backdate: 5 * time.Minute,               // 回溯5分钟，以确保签名在证书请求之前发生
		Short:    8 * time.Hour,                 // 证书的最短生命周期
		Now:      now,                           // 指定当前时间
	})
	if err != nil {
		return nil, err
	}
	// 将DER编码的证书编码为PEM格式，并返回
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
```

##### duration

```go
func (s *signer) duration(expirationSeconds *int32) time.Duration {
    // 如果过期时间为 nil，则使用 s.certTTL 作为过期时间
	if expirationSeconds == nil {
		return s.certTTL
	}

	// 如果请求的过期时间小于默认的过期时间，则使用请求的过期时间，否则使用默认的过期时间
	// 10 分钟作为最小值进行检查
	const min = 10 * time.Minute
	switch requestedDuration := csr.ExpirationSecondsToDuration(*expirationSeconds); {
	case requestedDuration > s.certTTL:
		return s.certTTL

	case requestedDuration < min:
		return min

	default:
		return requestedDuration
	}
}
```

