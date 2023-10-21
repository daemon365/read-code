## 简介

kubelet是Kubernetes集群中的一个重要组件，它运行在每个工作节点上，负责管理该节点上的容器运行时（如Docker）并维护节点的健康状态。kubelet负责与API服务器通信，接收来自控制平面的指令，并确保在节点上正确启动、停止和监控容器。

在kubelet的配置中，有一个与证书管理相关的配置项叫做`serverCertificateManager`（服务器证书管理器）。这个配置项用于定义kubelet如何管理自身所使用的TLS证书，用于与API服务器进行安全通信。

## Manager

```GO
// Manager 维护并更新该证书管理器使用的证书。在后台，它与 API 服务器通信，以获取即将过期的证书的新证书。
type Manager interface {
	// Start 启动 API 服务器状态同步循环。
	Start()
	// Stop 停止证书管理器循环。
	Stop()
	// Current 返回当前从证书管理器选择的证书，以及关联的证书和密钥数据（PEM 格式）。
	Current() *tls.Certificate
	// ServerHealthy 如果管理器能够与服务器通信，则返回 true。这允许调用者确定证书管理器是否可能与 API 服务器通信。证书管理器可能非常保守，并且只有在最近与服务器进行了通信时才返回 true。
	ServerHealthy() bool
}
```

## manager


```GO
type manager struct {
	getTemplate                  func() *x509.CertificateRequest
	lastRequestLock              sync.Mutex
	lastRequestCancel            context.CancelFunc
	lastRequest                  *x509.CertificateRequest
	dynamicTemplate              bool
	signerName                   string
	requestedCertificateLifetime *time.Duration
	getUsages                    func(privateKey interface{}) []certificates.KeyUsage
	forceRotation                bool
	certStore                    Store
	certificateRotation          Histogram
	certificateRenewFailure      Counter
	certAccessLock               sync.RWMutex
	cert                         *tls.Certificate
	serverHealth                 bool
	clientAccessLock             sync.Mutex
	clientsetFn                  ClientsetFunc
	stopCh                       chan struct{}
	stopped                      bool
	now                          func() time.Time
	name                         string
	logf                         func(format string, args ...interface{})
}
```

### NewManager

```GO
// NewManager 返回一个新的证书管理器。证书管理器负责成为 Kubelet 中证书的权威来源，并处理由于轮换而引起的更新。
func NewManager(config *Config) (Manager, error) {
	cert, forceRotation, err := getCurrentCertificateOrBootstrap(
		config.CertificateStore,
		config.BootstrapCertificatePEM,
		config.BootstrapKeyPEM)
	if err != nil {
		return nil, err
	}

	getTemplate := config.GetTemplate
	if getTemplate == nil {
		getTemplate = func() *x509.CertificateRequest { return config.Template }
	}

	if config.GetUsages != nil && config.Usages != nil {
		return nil, errors.New("cannot specify both GetUsages and Usages")
	}
	if config.GetUsages == nil && config.Usages == nil {
		return nil, errors.New("either GetUsages or Usages should be specified")
	}
	var getUsages func(interface{}) []certificates.KeyUsage
	if config.GetUsages != nil {
		getUsages = config.GetUsages
	} else {
		getUsages = func(interface{}) []certificates.KeyUsage { return config.Usages }
	}
	m := manager{
		stopCh:                       make(chan struct{}),
		clientsetFn:                  config.ClientsetFn,
		getTemplate:                  getTemplate,
		dynamicTemplate:              config.GetTemplate != nil,
		signerName:                   config.SignerName,
		requestedCertificateLifetime: config.RequestedCertificateLifetime,
		getUsages:                    getUsages,
		certStore:                    config.CertificateStore,
		cert:                         cert,
		forceRotation:                forceRotation,
		certificateRotation:          config.CertificateRotation,
		certificateRenewFailure:      config.CertificateRenewFailure,
		now:                          time.Now,
	}

	name := config.Name
	if len(name) == 0 {
		name = m.signerName
	}
	if len(name) == 0 {
		usages := getUsages(nil)
		switch {
		case hasKeyUsage(usages, certificates.UsageClientAuth):
			name = string(certificates.UsageClientAuth)
		default:
			name = "certificate"
		}
	}

	m.name = name
	m.logf = config.Logf
	if m.logf == nil {
		m.logf = func(format string, args ...interface{}) { klog.V(2).Infof(format, args...) }
	}

	return &m, nil
}
```

### Current

```go
// Current 从证书管理器返回当前选择的证书。如果管理器在没有证书的情况下初始化，并且尚未从 CertificateSigningRequestClient 接收到证书，或者当前证书已过期，则此函数可能返回 nil。
func (m *manager) Current() *tls.Certificate {
	m.certAccessLock.RLock()
	defer m.certAccessLock.RUnlock()
	if m.cert != nil && m.cert.Leaf != nil && m.now().After(m.cert.Leaf.NotAfter) {
		m.logf("%s: 当前证书已过期", m.name)
		return nil
	}
	return m.cert
}
```

### ServerHealthy

```go
// ServerHealthy 如果证书管理器认为服务器当前处于活动状态，则返回 true。
func (m *manager) ServerHealthy() bool {
	m.certAccessLock.RLock()
	defer m.certAccessLock.RUnlock()
	return m.serverHealth
}
```

### Stop

```go
// Stop 终止管理器。
func (m *manager) Stop() {
	m.clientAccessLock.Lock()
	defer m.clientAccessLock.Unlock()
	if m.stopped {
		return
	}
	close(m.stopCh)
	m.stopped = true
}
```

### Start

```go
// Start 将启动后台工作以轮换证书。
func (m *manager) Start() {
	// 证书轮换依赖于访问 API 服务器证书签名 API，因此如果没有客户端连接，则不启动证书管理器。
	if m.clientsetFn == nil {
		m.logf("%s: 证书轮换未启用，无法连接到 apiserver", m.name)
		return
	}
	m.logf("%s: 证书轮换已启用", m.name)

	templateChanged := make(chan struct{})
	go wait.Until(func() {
		deadline := m.nextRotationDeadline()
		if sleepInterval := deadline.Sub(m.now()); sleepInterval > 0 {
			m.logf("%s: 等待 %v 进行下一次证书轮换", m.name, sleepInterval)

			timer := time.NewTimer(sleepInterval)
			defer timer.Stop()

			select {
			case <-timer.C:
				// 当截止时间到达时解除阻塞
			case <-templateChanged:
				_, lastRequestTemplate := m.getLastRequest()
				if reflect.DeepEqual(lastRequestTemplate, m.getTemplate()) {
					// 如果模板与最后请求的模板匹配，重新启动轮换截止时间循环
					return
				}
				m.logf("%s: 证书模板已更改，正在进行轮换", m.name)
			}
		}

		// 如果还没有要请求的模板，不要进入 rotateCerts 并触发退避
		if m.getTemplate() == nil {
			return
		}

		backoff := wait.Backoff{
			Duration: 2 * time.Second,
			Factor:   2,
			Jitter:   0.1,
			Steps:    5,
		}
		if err := wait.ExponentialBackoff(backoff, m.rotateCerts); err != nil {
			utilruntime.HandleError(fmt.Errorf("%s: 达到退避限制，仍然无法轮换证书：%v", m.name, err))
			wait.PollInfinite(32*time.Second, m.rotateCerts)
		}
	}, time.Second, m.stopCh)

	if m.dynamicTemplate {
		go wait.Until(func() {
			// 检查当前模板是否与最后一次请求的模板匹配
			lastRequestCancel, lastRequestTemplate := m.getLastRequest()

			if !m.certSatisfiesTemplate() && !reflect.DeepEqual(lastRequestTemplate, m.getTemplate()) {
				// 如果模板不同，排队中断轮换截止时间循环。
				// 如果在处理中断时我们已经请求了与新模板匹配的 CSR，则忽略中断。
				if lastRequestCancel != nil {
					// 如果我们当前正在等待已经不再匹配我们想要的提交的请求，停止等待
					lastRequestCancel()
				}
				select {
				case templateChanged <- struct{}{}:
				case <-m.stopCh:
				}
			}
		}, time.Second, m.stopCh)
	}
}
```

