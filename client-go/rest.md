## 简介

直接使用rest 访问api-server

Example:

```go
package main

import (
	"context"
	"fmt"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)


func main() {
	// 使用kubeconfig生成配置
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err)
	}
	config.APIPath = "api"
	config.GroupVersion = &corev1.SchemeGroupVersion
	config.NegotiatedSerializer = scheme.Codecs

	// 生成restClient
	restClient, err := rest.RESTClientFor(config)
	if err != nil {
		panic(err)
	}

	rest := &corev1.PodList{}
	if err = restClient.Get().Namespace("default").Resource("pods").VersionedParams(&metav1.ListOptions{},
		scheme.ParameterCodec).Do(context.TODO()).Into(rest); err != nil {
		panic(err)
	}
	for _, v := range rest.Items {
		fmt.Printf("NameSpace: %v  Name: %v  Status: %v \n", v.Namespace, v.Name, v.Status.Phase)
	}
}

/*
结果
NameSpace: default  Name: nginx-76d6c9b8c-8ljkt  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-jqv9h  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-kr9d2  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-m4g5l  Status: Running 
NameSpace: default  Name: nginx-76d6c9b8c-n8st9  Status: Running 
*/
```

## Interface

```go
// Interface 是用于与 Kubernetes REST API 进行通用交互的操作集合的接口。
type Interface interface {
    GetRateLimiter() flowcontrol.RateLimiter // 获取速率限制器的方法
    Verb(verb string) *Request // 根据指定的 HTTP 动词创建一个请求对象
    Post() *Request // 创建一个 POST 请求对象
    Put() *Request // 创建一个 PUT 请求对象
    Patch(pt types.PatchType) *Request // 根据指定的 Patch 类型创建一个请求对象
    Get() *Request // 创建一个 GET 请求对象
    Delete() *Request // 创建一个 DELETE 请求对象
    APIVersion() schema.GroupVersion // 返回接口对应的 API 版本信息
}
```

## RESTClient

```go
// RESTClient是对一组资源路径施加常见的Kubernetes API约定的类。
// baseURL应指向一个HTTP或HTTPS路径，该路径是一个或多个资源的父级。
// 服务器应返回一个可解码的API资源对象，或一个包含有关任何失败原因的api.Status对象。
//
// 大多数使用者应该使用client.New()来获取Kubernetes API客户端。
type RESTClient struct {
	// base是客户端调用的根URL
	base *url.URL
	// versionedAPIPath是连接基本URL和资源根路径的路径段
	versionedAPIPath string

	// content描述了RESTClient如何编码和解码响应。
	content ClientContentConfig

	// 创建传递给请求的BackoffManager。
	createBackoffMgr func() BackoffManager

	// rateLimiter在此客户端创建的所有请求之间共享，除非特别指定。
	rateLimiter flowcontrol.RateLimiter

	// warningHandler在此客户端创建的所有请求之间共享。
	// 如果未设置，将使用defaultWarningHandler。
	warningHandler WarningHandler

	// 设置客户端的特定行为。如果未设置，则使用http.DefaultClient。
	Client *http.Client
}
```

### new

```go
// NewRESTClient创建一个新的RESTClient。此客户端在指定的路径上执行通用的REST功能，如Get、Put、Post和Delete。
func NewRESTClient(baseURL *url.URL, versionedAPIPath string, config ClientContentConfig, rateLimiter flowcontrol.RateLimiter, client *http.Client) (*RESTClient, error) {
	if len(config.ContentType) == 0 {
		config.ContentType = "application/json"
	}

	base := *baseURL
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.RawQuery = ""
	base.Fragment = ""

	return &RESTClient{
		base:             &base,
		versionedAPIPath: versionedAPIPath,
		content:          config,
		createBackoffMgr: readExpBackoffConfig,
		rateLimiter:      rateLimiter,

		Client: client,
	}, nil
}

// RESTClientFor返回满足客户端配置请求属性的RESTClient。
// 注意，RESTClient在初始化Client时可能需要一些可选字段。
// 此方法创建的RESTClient是通用的，它期望操作符遵循Kubernetes约定的API，但可能不是Kubernetes API。
// RESTClientFor等效于调用RESTClientForConfigAndClient(config, httpClient)，
// 其中httpClient是使用HTTPClientFor(config)生成的。
func RESTClientFor(config *Config) (*RESTClient, error) {
	if config.GroupVersion == nil {
		return nil, fmt.Errorf("初始化RESTClient时需要GroupVersion")
	}
	if config.NegotiatedSerializer == nil {
		return nil, fmt.Errorf("初始化RESTClient时需要NegotiatedSerializer")
	}

	// 在构建传输/客户端之前验证config.Host，以便我们可以快速失败。
	// ServerURL将在RESTClientForConfigAndClient()中获取
	_, _, err := DefaultServerUrlFor(config)
	if err != nil {
		return nil, err
	}

	httpClient, err := HTTPClientFor(config)
	if err != nil {
		return nil, err
	}

	return RESTClientForConfigAndClient(config, httpClient)
}

// RESTClientForConfigAndClient返回满足客户端配置请求属性的RESTClient。
// 与RESTClientFor不同，RESTClientForConfigAndClient允许传递一个在所有API组和版本之间共享的http.Client。
// 注意，http客户端优先于配置的传输值。
// 如果为nil，则http客户端默认为http.DefaultClient。
func RESTClientForConfigAndClient(config *Config, httpClient *http.Client) (*RESTClient, error) {
	if config.GroupVersion == nil {
		return nil, fmt.Errorf("初始化RESTClient时需要GroupVersion")
	}
	if config.NegotiatedSerializer == nil {
		return nil, fmt.Errorf("初始化RESTClient时需要NegotiatedSerializer")
	}

	baseURL, versionedAPIPath, err := DefaultServerUrlFor(config)
	if err != nil {
		return nil, err
	}

	rateLimiter := config.RateLimiter
	if rateLimiter == nil {
		qps := config.QPS
		if config.QPS == 0.0 {
			qps = DefaultQPS
		}
		burst := config.Burst
		if config.Burst == 0 {
			burst = DefaultBurst
		}
		if qps > 0 {
			rateLimiter = flowcontrol.NewTokenBucketRateLimiter(qps, burst)
		}
	}

	var gv schema.GroupVersion
	if config.GroupVersion != nil {
		gv = *config.GroupVersion
	}
	clientContent := ClientContentConfig{
		AcceptContentTypes: config.AcceptContentTypes,
		ContentType:        config.ContentType,
		GroupVersion:       gv,
		Negotiator:         runtime.NewClientNegotiator(config.NegotiatedSerializer, gv),
	}

	restClient, err := NewRESTClient(baseURL, versionedAPIPath, clientContent, rateLimiter, httpClient)
	if err == nil && config.WarningHandler != nil {
		restClient.warningHandler = config.WarningHandler
	}
	return restClient, err
}

// UnversionedRESTClientFor与RESTClientFor相同，只是允许config.Version为空。
func UnversionedRESTClientFor(config *Config) (*RESTClient, error) {
	if config.NegotiatedSerializer == nil {
		return nil, fmt.Errorf("初始化RESTClient时需要NegotiatedSerializer")
	}

	// 在构建传输/客户端之前验证config.Host，以便我们可以快速失败。
	// ServerURL将在UnversionedRESTClientForConfigAndClient()中获取
	_, _, err := DefaultServerUrlFor(config)
	if err != nil {
		return nil, err
	}

	httpClient, err := HTTPClientFor(config)
	if err != nil {
		return nil, err
	}

	return UnversionedRESTClientForConfigAndClient(config, httpClient)
}

// UnversionedRESTClientForConfigAndClient与RESTClientForConfigAndClient相同，
// 只是允许config.Version为空。
func UnversionedRESTClientForConfigAndClient(config *Config, httpClient *http.Client) (*RESTClient, error) {
	if config.NegotiatedSerializer == nil {
		return nil, fmt.Errorf("初始化RESTClient时需要NegotiatedSerializer")
	}

	baseURL, versionedAPIPath, err := DefaultServerUrlFor(config)
	if err != nil {
		return nil, err
	}

	rateLimiter := config.RateLimiter
	if rateLimiter == nil {
		qps := config.QPS
		if config.QPS == 0.0 {
			qps = DefaultQPS
		}
		burst := config.Burst
		if config.Burst == 0 {
			burst = DefaultBurst
		}
		if qps > 0 {
			rateLimiter = flowcontrol.NewTokenBucketRateLimiter(qps, burst)
		}
	}

	gv := metav1.SchemeGroupVersion
	if config.GroupVersion != nil {
		gv = *config.GroupVersion
	}
	clientContent := ClientContentConfig{
		AcceptContentTypes: config.AcceptContentTypes,
		ContentType:        config.ContentType,
		GroupVersion:       gv,
		Negotiator:         runtime.NewClientNegotiator(config.NegotiatedSerializer, gv),
	}

	restClient, err := NewRESTClient(baseURL, versionedAPIPath, clientContent, rateLimiter, httpClient)
	if err == nil && config.WarningHandler != nil {
		restClient.warningHandler = config.WarningHandler
	}
	return restClient, err
}
```

### GetRateLimiter

```go
// GetRateLimiter返回给定客户端的速率限制器，如果在nil客户端上调用，则返回nil。
func (c *RESTClient) GetRateLimiter() flowcontrol.RateLimiter {
	if c == nil {
		return nil
	}
	return c.rateLimiter
}
```

### Verb

```GO
// Verb使用一个动词（GET、POST、PUT、DELETE）开始一个请求。

// RESTClient请求构建接口的示例用法：
// c, err := NewRESTClient(...)
// if err != nil { ... }
// resp, err := c.Verb("GET").
// Path("pods").
// SelectorParam("labels", "area=staging").
// Timeout(10*time.Second).
// Do()

// if err != nil { ... }
// list, ok := resp.(*api.PodList)
func (c *RESTClient) Verb(verb string) *Request {
	return NewRequest(c).Verb(verb)
}
```

### Post

```GO
// Post开始一个POST请求。等同于c.Verb("POST")。
func (c *RESTClient) Post() *Request {
	return c.Verb("POST")
}
```

### Put

```GO
// Put开始一个PUT请求。等同于c.Verb("PUT")。
func (c *RESTClient) Put() *Request {
	return c.Verb("PUT")
}
```

### Patch

```GO
// Patch开始一个PATCH请求。等同于c.Verb("PATCH")。
func (c *RESTClient) Patch(pt types.PatchType) *Request {
	return c.Verb("PATCH").SetHeader("Content-Type", string(pt))
}
```

### Get

```GO
// Get开始一个GET请求。等同于c.Verb("GET")。
func (c *RESTClient) Get() *Request {
	return c.Verb("GET")
}
```

### Delete

```GO
// Delete开始一个DELETE请求。等同于c.Verb("DELETE")。
func (c *RESTClient) Delete() *Request {
	return c.Verb("DELETE")
}
```

### APIVersion

```GO
// APIVersion返回RESTClient预期使用的API版本。
func (c *RESTClient) APIVersion() schema.GroupVersion {
	return c.content.GroupVersion
}
```

## Request

```GO
// Request允许以链式方式构建发送到服务器的请求。
// 任何错误都会被存储，直到调用结束，因此您只需检查一次。
type Request struct {
	c              *RESTClient
	warningHandler WarningHandler
	rateLimiter    flowcontrol.RateLimiter
	backoff        BackoffManager
	timeout        time.Duration
	maxRetries     int

	// 通过方法设置器访问的通用组件
	verb       string
	pathPrefix string
	subpath    string
	params     url.Values
	headers    http.Header

	// 请求的结构化元素，是Kubernetes API约定的一部分
	namespace    string
	namespaceSet bool
	resource     string
	resourceName string
	subresource  string

	// 输出
	err error

	// 只能设置body和bodyBytes中的一个。使用body的请求不可重试。
	body      io.Reader
	bodyBytes []byte

	retryFn requestRetryFunc
}
```

#### NewRequest

```GO
// NewRequest为访问服务器上的runtime.Objects创建一个新的请求辅助对象。
func NewRequest(c *RESTClient) *Request {
	var backoff BackoffManager
	if c.createBackoffMgr != nil {
		backoff = c.createBackoffMgr()
	}
	if backoff == nil {
		backoff = noBackoff
	}

	var pathPrefix string
	if c.base != nil {
		pathPrefix = path.Join("/", c.base.Path, c.versionedAPIPath)
	} else {
		pathPrefix = path.Join("/", c.versionedAPIPath)
	}

	var timeout time.Duration
	if c.Client != nil {
		timeout = c.Client.Timeout
	}

	r := &Request{
		c:              c,
		rateLimiter:    c.rateLimiter,
		backoff:        backoff,
		timeout:        timeout,
		pathPrefix:     pathPrefix,
		maxRetries:     10,
		retryFn:        defaultRequestRetryFn,
		warningHandler: c.warningHandler,
	}

	switch {
	case len(c.content.AcceptContentTypes) > 0:
		r.SetHeader("Accept", c.content.AcceptContentTypes)
	case len(c.content.ContentType) > 0:
		r.SetHeader("Accept", c.content.ContentType+", */*")
	}
	return r
}
```

##### readExpBackoffConfig

```GO
// readExpBackoffConfig处理确定退避策略的内部逻辑。默认情况下，如果没有可用的信息，使用NoBackoff。
// TODO：概括化此内容，请参阅＃17727。
func readExpBackoffConfig() BackoffManager {
	backoffBase := os.Getenv(envBackoffBase)
	backoffDuration := os.Getenv(envBackoffDuration)

	backoffBaseInt, errBase := strconv.ParseInt(backoffBase, 10, 64)
	backoffDurationInt, errDuration := strconv.ParseInt(backoffDuration, 10, 64)
	if errBase != nil || errDuration != nil {
		return &NoBackoff{}
	}
	return &URLBackoff{
		Backoff: flowcontrol.NewBackOff(
			time.Duration(backoffBaseInt)*time.Second,
			time.Duration(backoffDurationInt)*time.Second)}
}

func NewRequestWithClient(base *url.URL, versionedAPIPath string, content ClientContentConfig, client *http.Client) *Request {
	return NewRequest(&RESTClient{
		base:             base,
		versionedAPIPath: versionedAPIPath,
		content:          content,
		Client:           client,
	})
}
```

### Prefix

```go
// Prefix将段添加到请求路径的相对开头。这些项将放置在可选的Namespace、Resource或Name部分之前。
// 设置AbsPath将清除先前设置的前缀段
func (r *Request) Prefix(segments ...string) *Request {
	if r.err != nil {
		return r
	}
	r.pathPrefix = path.Join(r.pathPrefix, path.Join(segments...))
	return r
}
```

### Suffix

```go
// Suffix将段追加到路径的末尾。这些项将放置在前缀和可选的Namespace、Resource或Name部分之后。
func (r *Request) Suffix(segments ...string) *Request {
	if r.err != nil {
		return r
	}
	r.subpath = path.Join(r.subpath, path.Join(segments...))
	return r
}
```

### Resource

```go
// Resource设置要访问的资源（<resource>/[ns/<namespace>/]<name>）
func (r *Request) Resource(resource string) *Request {
	if r.err != nil {
		return r
	}
	if len(r.resource) != 0 {
		r.err = fmt.Errorf("resource already set to %q, cannot change to %q", r.resource, resource)
		return r
	}
	if msgs := IsValidPathSegmentName(resource); len(msgs) != 0 {
		r.err = fmt.Errorf("invalid resource %q: %v", resource, msgs)
		return r
	}
	r.resource = resource
	return r
}
```



### BackOff

```go
// BackOff设置请求的退避管理器为指定的管理器，如果提供的是nil，则使用默认的存根实现
func (r *Request) BackOff(manager BackoffManager) *Request {
	if manager == nil {
		r.backoff = &NoBackoff{}
		return r
	}

	r.backoff = manager
	return r
}
```

### WarningHandler

```go
// WarningHandler设置此客户端在遇到警告头时使用的处理程序。
// 如果设置为nil，此客户端将使用默认的警告处理程序（参见SetDefaultWarningHandler）。
func (r *Request) WarningHandler(handler WarningHandler) *Request {
	r.warningHandler = handler
	return r
}
```

### Throttle

```go
// Throttle接收一个速率限制器，并设置或替换现有的请求限制器
func (r *Request) Throttle(limiter flowcontrol.RateLimiter) *Request {
	r.rateLimiter = limiter
	return r
}
```

### SubResource

```go
// SubResource设置子资源路径，可以是资源之后但在后缀之前的多个段
func (r *Request) SubResource(subresources ...string) *Request {
	if r.err != nil {
		return r
	}
	subresource := path.Join(subresources...)
	if len(r.subresource) != 0 {
		r.err = fmt.Errorf("subresource already set to %q, cannot change to %q", r.subresource, subresource)
		return r
	}
	for _, s := range subresources {
		if msgs := IsValidPathSegmentName(s); len(msgs) != 0 {
			r.err = fmt.Errorf("invalid subresource %q: %v", s, msgs)
			return r
		}
	}
	r.subresource = subresource
	return r
}
```

### Name

```go
// Name设置要访问的资源的名称（<resource>/[ns/<namespace>/]<name>）
func (r *Request) Name(resourceName string) *Request {
	if r.err != nil {
		return r
	}
	if len(resourceName) == 0 {
		r.err = fmt.Errorf("resource name may not be empty")
		return r
	}
	if len(r.resourceName) != 0 {
		r.err = fmt.Errorf("resource name already set to %q, cannot change to %q", r.resourceName, resourceName)
		return r
	}
	if msgs := IsValidPathSegmentName(resourceName); len(msgs) != 0 {
		r.err = fmt.Errorf("invalid resource name %q: %v", resourceName, msgs)
		return r
	}
	r.resourceName = resourceName
	return r
}
```

### Namespace

```go
// Namespace将命名空间范围应用于请求（<resource>/[ns/<namespace>/]<name>）
func (r *Request) Namespace(namespace string) *Request {
	if r.err != nil {
		return r
	}
	if r.namespaceSet {
		r.err = fmt.Errorf("namespace already set to %q, cannot change to %q", r.namespace, namespace)
		return r
	}
	if msgs := IsValidPathSegmentName(namespace); len(msgs) != 0 {
		r.err = fmt.Errorf("invalid namespace %q: %v", namespace, msgs)
		return r
	}
	r.namespaceSet = true
	r.namespace = namespace
	return r
}
```

### NamespaceIfScoped

```go
// NamespaceIfScoped是一个方便函数，如果scoped为true，则设置命名空间
func (r *Request) NamespaceIfScoped(namespace string, scoped bool) *Request {
	if scoped {
		return r.Namespace(namespace)
	}
	return r
}
```

### AbsPath

```go
// AbsPath用提供的段覆盖现有路径。当传递单个段时，尾随斜杠会保留。
func (r *Request) AbsPath(segments ...string) *Request {
	if r.err != nil {
		return r
	}
	r.pathPrefix = path.Join(r.c.base.Path, path.Join(segments...))
	if len(segments) == 1 && (len(r.c.base.Path) > 1 || len(segments[0]) > 1) && strings.HasSuffix(segments[0], "/") {
		// 保留任何尾随斜杠以保持向后兼容性
		r.pathPrefix += "/"
	}
	return r
}
```

### RequestURI

```go
// RequestURI用提供的服务器相对URI的值覆盖现有路径和参数。
func (r *Request) RequestURI(uri string) *Request {
	if r.err != nil {
		return r
	}
	locator, err := url.Parse(uri)
	if err != nil {
		r.err = err
		return r
	}
	r.pathPrefix = locator.Path
	if len(locator.Query()) > 0 {
		if r.params == nil {
			r.params = make(url.Values)
		}
		for k, v := range locator.Query() {
			r.params[k] = v
		}
	}
	return r
}
```

### Param

```go
// Param使用给定的字符串值创建查询参数。
func (r *Request) Param(paramName, s string) *Request {
	if r.err != nil {
		return r
	}
	return r.setParam(paramName, s)
}
```

#### setParam

```go
// setParam函数用于设置请求的参数。参数名为paramName，值为value。
func (r *Request) setParam(paramName, value string) *Request {
	if r.params == nil {
		r.params = make(url.Values)
	}
	r.params[paramName] = append(r.params[paramName], value)
	return r
}
```

### VersionedParams

```go
// VersionedParams函数将提供的对象序列化为map[string][]string，使用隐式的RESTClient API版本和默认参数编解码器，然后将其作为参数添加到请求中。
// 使用此函数可以从客户端库提供版本化的查询参数。
// VersionedParams函数不会写入具有omitempty标记且为空的查询参数。如果参数已经设置，它会进行追加（Params和VersionedParams是可累加的）。
func (r *Request) VersionedParams(obj runtime.Object, codec runtime.ParameterCodec) *Request {
	return r.SpecificallyVersionedParams(obj, codec, r.c.content.GroupVersion)
}
```

### SpecificallyVersionedParams

```go
// SpecificallyVersionedParams函数将提供的对象根据指定的版本进行编码，并使用提供的编解码器将其转换为参数。然后将这些参数添加到请求中。
func (r *Request) SpecificallyVersionedParams(obj runtime.Object, codec runtime.ParameterCodec, version schema.GroupVersion) *Request {
	if r.err != nil {
		return r
	}
	params, err := codec.EncodeParameters(obj, version)
	if err != nil {
		r.err = err
		return r
	}
	for k, v := range params {
		if r.params == nil {
			r.params = make(url.Values)
		}
		r.params[k] = append(r.params[k], v...)
	}
	return r
}
```

### SetHeader

```go
// SetHeader函数用于设置请求的头部信息。参数key为头部的键，参数values为头部的值（可变参数）。
func (r *Request) SetHeader(key string, values ...string) *Request {
	if r.headers == nil {
		r.headers = http.Header{}
	}
	r.headers.Del(key)
	for _, value := range values {
		r.headers.Add(key, value)
	}
	return r
}
```

### Timeout

```go
// Timeout函数用于设置请求的超时时间。参数d为持续时间。此函数还会将超时时间以"timeout"参数的形式传递给URL。
func (r *Request) Timeout(d time.Duration) *Request {
	if r.err != nil {
		return r
	}
	r.timeout = d
	return r
}
```

### MaxRetries

```go
// MaxRetries函数用于设置请求的最大重试次数。参数maxRetries为重试的上限次数。
// 如果参数maxRetries为零，则禁止重试，并立即返回错误。
func (r *Request) MaxRetries(maxRetries int) *Request {
	if maxRetries < 0 {
		maxRetries = 0
	}
	r.maxRetries = maxRetries
	return r
}
```

### Body

```go
// Body函数用于设置请求的主体。参数obj为主体的内容。
// 如果obj是字符串，则尝试读取同名的文件。
// 如果obj是[]byte，则直接发送它。
// 如果obj是io.Reader，则直接使用它。
// 如果obj是runtime.Object，则正确编组它，并设置Content-Type头部。
// 如果obj是runtime.Object并且为nil，则不执行任何操作。
// 否则，设置一个错误。
func (r *Request) Body(obj interface{}) *Request {
	if r.err != nil {
		return r
	}
	switch t := obj.(type) {
	case string:
		data, err := os.ReadFile(t)
		if err != nil {
			r.err = err
			return r
		}
		glogBody("Request Body", data)
		r.body = nil
		r.bodyBytes = data
	case []byte:
		glogBody("Request Body", t)
		r.body = nil
		r.bodyBytes = t
	case io.Reader:
		r.body = t
		r.bodyBytes = nil
	case runtime.Object:
		// callers may pass typed interface pointers, therefore we must check nil with reflection
		if reflect.ValueOf(t).IsNil() {
			return r
		}
		encoder, err := r.c.content.Negotiator.Encoder(r.c.content.ContentType, nil)
		if err != nil {
			r.err = err
			return r
		}
		data, err := runtime.Encode(encoder, t)
		if err != nil {
			r.err = err
			return r
		}
		glogBody("Request Body", data)
		r.body = nil
		r.bodyBytes = data
		r.SetHeader("Content-Type", r.c.content.ContentType)
	default:
		r.err = fmt.Errorf("unknown type used for body: %+v", obj)
	}
	return r
}
```

### Error

```go
// Error函数返回构造请求时遇到的任何错误（如果有）。
func (r *Request) Error() error {
	return r.err
}
```

### IsValidPathSegmentName

```go
// IsValidPathSegmentName验证名称是否可以安全地编码为路径段
func IsValidPathSegmentName(name string) []string {
	for _, illegalName := range NameMayNotBe {
		if name == illegalName {
			return []string{fmt.Sprintf(`may not be '%s'`, illegalName)}
		}
	}

	var errors []string
	for _, illegalContent := range NameMayNotContain {
		if strings.Contains(name, illegalContent) {
			errors = append(errors, fmt.Sprintf(`may not contain '%s'`, illegalContent))
		}
	}

	return errors
}
```

### URL

```go
// URL返回当前的工作URL。检查Error()的结果以确保返回的URL有效。
func (r *Request) URL() *url.URL {
	p := r.pathPrefix
	if r.namespaceSet && len(r.namespace) > 0 {
		p = path.Join(p, "namespaces", r.namespace)
	}
	if len(r.resource) != 0 {
		p = path.Join(p, strings.ToLower(r.resource))
	}
	// Join去除尾随斜杠，因此如果没有更改任何内容，请保留r.pathPrefix的尾随斜杠以保持向后兼容性
	if len(r.resourceName) != 0 || len(r.subpath) != 0 || len(r.subresource) != 0 {
		p = path.Join(p, r.resourceName, r.subresource, r.subpath)
	}

	finalURL := &url.URL{}
	if r.c.base != nil {
		*finalURL = *r.c.base
	}
	finalURL.Path = p

	query := url.Values{}
	for key, values := range r.params {
		for _, value := range values {
			query.Add(key, value)
		}
	}

	// timeout在这里特殊处理。
	if r.timeout != 0 {
		query.Set("timeout", r.timeout.String())
	}
	finalURL.RawQuery = query.Encode()
	return finalURL
}
```

### Do

```go
// Do 格式化并执行请求。返回一个Result对象以便轻松处理响应。
//
// 错误类型：
//   - 如果服务器以状态响应：*errors.StatusError 或 *errors.UnexpectedObjectError
//   - 直接返回http.Client.Do错误。
func (r *Request) Do(ctx context.Context) Result {
	var result Result
	err := r.request(ctx, func(req *http.Request, resp *http.Response) {
		result = r.transformResponse(resp, req)
	})
	if err != nil {
		return Result{err: err}
	}
	if result.err == nil || len(result.body) > 0 {
		metrics.ResponseSize.Observe(ctx, r.verb, r.URL().Host, float64(len(result.body)))
	}
	return result
}
```

### DoRaw

```go
// DoRaw 执行请求，但不处理响应体。
func (r *Request) DoRaw(ctx context.Context) ([]byte, error) {
	var result Result
	err := r.request(ctx, func(req *http.Request, resp *http.Response) {
		result.body, result.err = io.ReadAll(resp.Body)
		glogBody("Response Body", result.body)
		if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent {
			result.err = r.transformUnstructuredResponseError(resp, req, result.body)
		}
	})
	if err != nil {
		return nil, err
	}
	if result.err == nil || len(result.body) > 0 {
		metrics.ResponseSize.Observe(ctx, r.verb, r.URL().Host, float64(len(result.body)))
	}
	return result.body, result.err
}
```

### Watch

```go
// Watch函数尝试开始对指定位置进行监视。
// 返回一个watch.Interface接口或错误。
func (r *Request) Watch(ctx context.Context) (watch.Interface, error) {
	// 我们特意不希望对监视进行速率限制，因此这里不使用r.rateLimiter。
	if r.err != nil {
		return nil, r.err
	}

	client := r.c.Client
	if client == nil {
		client = http.DefaultClient
	}

	isErrRetryableFunc := func(request *http.Request, err error) bool {
		// 观察流机制处理许多常见的部分数据错误，因此在许多情况下可以重试关闭的连接。
		if net.IsProbableEOF(err) || net.IsTimeout(err) {
			return true
		}
		return false
	}
	retry := r.retryFn(r.maxRetries)
	url := r.URL().String()
	for {
		if err := retry.Before(ctx, r); err != nil {
			return nil, retry.WrapPreviousError(err)
		}

		req, err := r.newHTTPRequest(ctx)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		retry.After(ctx, r, resp, err)
		if err == nil && resp.StatusCode == http.StatusOK {
			return r.newStreamWatcher(resp)
		}

		done, transformErr := func() (bool, error) {
			defer readAndCloseResponseBody(resp)

			if retry.IsNextRetry(ctx, r, req, resp, err, isErrRetryableFunc) {
				return false, nil
			}

			if resp == nil {
				// 服务器必须在'err'中发送错误。
				return true, nil
			}
			if result := r.transformResponse(resp, req); result.err != nil {
				return true, result.err
			}
			return true, fmt.Errorf("对请求 %s，获得状态：%v", url, resp.StatusCode)
		}()
		if done {
			if isErrRetryableFunc(req, err) {
				return watch.NewEmptyWatch(), nil
			}
			if err == nil {
				// 如果服务器发送了一个HTTP响应对象，
				// 我们需要返回该对象中的错误对象。
				err = transformErr
			}
			return nil, retry.WrapPreviousError(err)
		}
	}
}
```

### Interface

```go
// Interface接口可以由任何知道如何监视并报告变更的对象实现。
type Interface interface {
	// Stop停止监视。将关闭ResultChan()返回的通道。释放监视使用的任何资源。
	Stop()

	// ResultChan返回一个chan，该通道将接收所有事件。如果发生错误或调用了Stop()，实现将关闭该通道并释放监视使用的任何资源。
	ResultChan() <-chan Event
}
```

#### newHTTPRequest

```go
// newHTTPRequest函数创建一个新的HTTP请求。
func (r *Request) newHTTPRequest(ctx context.Context) (*http.Request, error) {
	var body io.Reader
	switch {
	case r.body != nil && r.bodyBytes != nil:
		return nil, fmt.Errorf("不能同时设置body和bodyBytes")
	case r.body != nil:
		body = r.body
	case r.bodyBytes != nil:
		// 为该请求创建一个新的读取器。
		// 为每个请求提供专用的读取器，可以避免重试时重置请求体的竞争。
		body = bytes.NewReader(r.bodyBytes)
	}

	url := r.URL().String()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, newDNSMetricsTrace(ctx)), r.verb, url, body)
	if err != nil {
		return nil, err
	}
	req.Header = r.headers
	return req, nil
}
```

#### newStreamWatcher

```go
// newStreamWatcher函数创建一个新的流式监视器。
func (r *Request) newStreamWatcher(resp *http.Response) (watch.Interface, error) {
	contentType := resp.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		klog.V(4).Infof("从服务器获得的内容类型不正确：%q：%v", contentType, err)
	}
	objectDecoder, streamingSerializer, framer, err := r.c.content.Negotiator.StreamDecoder(mediaType, params)
	if err != nil {
		return nil, err
	}

	handleWarnings(resp.Header, r.warningHandler)

	frameReader := framer.NewFrameReader(resp.Body)
	watchEventDecoder := streaming.NewDecoder(frameReader, streamingSerializer)

	return watch.NewStreamWatcher(
		restclientwatch.NewDecoder(watchEventDecoder, objectDecoder),
		// 使用500表示错误的原因未知 - 其他错误代码
		// 更具体地指定了HTTP交互，并设置原因。
		errors.NewClientErrorReporter(http.StatusInternalServerError, r.verb, "ClientWatchDecoding"),
	), nil
}
```

#### StreamWatcher

```go
// StreamWatcher将任何可以写入Decoder接口的流转换为watch.Interface。
type StreamWatcher struct {
	sync.Mutex
	source   Decoder
	reporter Reporter
	result   chan Event
	done     chan struct{}
}

// NewStreamWatcher从给定的decoder创建一个StreamWatcher。
func NewStreamWatcher(d Decoder, r Reporter) *StreamWatcher {
	sw := &StreamWatcher{
		source:   d,
		reporter: r,
		// 对于消费者来说，通过额外的goroutine/channel可以轻松添加缓冲区，
		// 但是无法将其删除，因此非缓冲区更好。
		result: make(chan Event),
		// 如果监视程序被外部停止，就没有接收者了，
		// 并且result通道上的发送操作，特别是错误报告可能会永远阻塞。
		// 因此，使用一个专用的停止通道来解决这个阻塞问题。
		done: make(chan struct{}),
	}
	go sw.receive()
	return sw
}
```

##### receive

```go
// receive循环从解码器中读取结果并通过result通道发送。
func (sw *StreamWatcher) receive() {
	defer utilruntime.HandleCrash()
	defer close(sw.result)
	defer sw.Stop()
	for {
		action, obj, err := sw.source.Decode()
		if err != nil {
			switch err {
			case io.EOF:
			// 监视关闭正常
			case io.ErrUnexpectedEOF:
				klog.V(1).Infof("Unexpected EOF during watch stream event decoding: %v", err)
			default:
				if net.IsProbableEOF(err) || net.IsTimeout(err) {
					klog.V(5).Infof("Unable to decode an event from the watch stream: %v", err)
				} else {
					select {
					case <-sw.done:
					case sw.result <- Event{
						Type:   Error,
						Object: sw.reporter.AsObject(fmt.Errorf("unable to decode an event from the watch stream: %v", err)),
					}:
					}
				}
			}
			return
		}
		select {
		case <-sw.done:
			return
		case sw.result <- Event{
			Type:   action,
			Object: obj,
		}:
		}
	}
}
```

##### ResultChan

```go
// ResultChan实现了Interface。
func (sw *StreamWatcher) ResultChan() <-chan Event {
	return sw.result
}
```

##### Stop

```go
// Stop实现了Interface。
func (sw *StreamWatcher) Stop() {
	// 通过加锁和设置标志来确保只调用Close()一次。
	sw.Lock()
	defer sw.Unlock()
	// 关闭一个已关闭的通道会导致panic，因此在关闭之前进行检查
	select {
	case <-sw.done:
	default:
		close(sw.done)
		sw.source.Close()
	}
}
```

##### Reporter

```go
// Reporter隐藏了如何将错误转换为运行时对象以在watch流中报告的详细信息，因为该包可能不导入更高级别的报告。
type Reporter interface {
	// AsObject必须将err转换为有效的运行时对象，用于watch流。
	AsObject(err error) runtime.Object
}
```

##### Decoder

```go
// Decoder允许StreamWatcher监视任何可以写入Decoder的流。
type Decoder interface {
	// Decode应返回事件类型、解码的对象或错误。
	// 如果出现错误，Decode将导致StreamWatcher调用Close()。
	// Decode应阻塞，直到有数据或发生错误。
	Decode() (action EventType, object runtime.Object, err error)

	// Close应关闭底层io.Reader，向流的来源发出信号，表示它不再被监视。
	// Close()必须使任何未完成的Decode()调用返回某种错误。
	Close()
}
```

