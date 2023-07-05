## 简介

DynamicClient是一种动态客户端，它可以对任何资源进行RESTful操作，包括自定义资源定义（CRD）。与ClientSet不同，DynamicClient返回的对象是一个map[string]interface{}。如果一个控制器需要控制所有的API，可以使用DynamicClient。目前，DynamicClient在垃圾回收器和命名空间控制器中被广泛使用。

DynamicClient的处理过程将Resource（例如PodList）转换为unstructured类型。Kubernetes的所有资源都可以转换为这个结构类型。处理完毕后，再将其转换回PodList。整个转换过程类似于接口转换，即通过interface{}的断言实现。

DynamicClient是一种动态的客户端，它能处理Kubernetes所有的资源，但仅支持JSON

## Interface

```go
// Interface 是一个接口，定义了与动态资源相关的方法。
type Interface interface {
	Resource(resource schema.GroupVersionResource) NamespaceableResourceInterface
}

// ResourceInterface 是一个接口，定义了与指定资源类型相关的方法。
type ResourceInterface interface {
	Create(ctx context.Context, obj *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error)
	Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error)
	UpdateStatus(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error)
	Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error
	DeleteCollection(ctx context.Context, options metav1.DeleteOptions, listOptions metav1.ListOptions) error
	Get(ctx context.Context, name string, options metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error)
	List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error)
	Apply(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions, subresources ...string) (*unstructured.Unstructured, error)
	ApplyStatus(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions) (*unstructured.Unstructured, error)
}

// NamespaceableResourceInterface 是一个接口，定义了可以指定命名空间的资源类型相关的方法。
type NamespaceableResourceInterface interface {
	Namespace(string) ResourceInterface
	ResourceInterface
}
```

## DynamicClient

```GO
type DynamicClient struct {
	client rest.Interface
}

var _ Interface = &DynamicClient{}
```

### Resource

```GO
func (c *DynamicClient) Resource(resource schema.GroupVersionResource) NamespaceableResourceInterface {
	return &dynamicResourceClient{client: c, resource: resource}
}
```

## dynamicResourceClient

```GO
// dynamicResourceClient 是一个结构体，用于与动态资源进行交互。
type dynamicResourceClient struct {
	client    *DynamicClient
	namespace string
	resource  schema.GroupVersionResource
}
```

### Namespace

```GO
// Namespace 方法返回一个新的 dynamicResourceClient，该 dynamicResourceClient 与指定的命名空间相关。
func (c *dynamicResourceClient) Namespace(ns string) ResourceInterface {
	ret := *c
	ret.namespace = ns
	return &ret
}
```

### Create

```GO
// Create 方法用于创建资源。
func (c *dynamicResourceClient) Create(ctx context.Context, obj *unstructured.Unstructured, opts metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	// 对象编码为 JSON 字节
	outBytes, err := runtime.Encode(unstructured.UnstructuredJSONScheme, obj)
	if err != nil {
		return nil, err
	}
	name := ""
	if len(subresources) > 0 {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return nil, err
		}
		name = accessor.GetName()
		if len(name) == 0 {
			return nil, fmt.Errorf("name is required")
		}
	}
	// 验证命名空间和名称的有效性
	if err := validateNamespaceWithOptionalName(c.namespace, name); err != nil {
		return nil, err
	}

	// 发起 POST 请求创建资源
	result := c.client.client.
		Post().
		AbsPath(append(c.makeURLSegments(name), subresources...)...).
		SetHeader("Content-Type", runtime.ContentTypeJSON).
		Body(outBytes).
		SpecificallyVersionedParams(&opts, dynamicParameterCodec, versionV1).
		Do(ctx)
	if err := result.Error(); err != nil {
		return nil, err
	}

	// 解码响应的 JSON 字节为 unstructured.Unstructured 对象
	retBytes, err := result.Raw()
	if err != nil {
		return nil, err
	}
	uncastObj, err := runtime.Decode(unstructured.UnstructuredJSONScheme, retBytes)
	if err != nil {
		return nil, err
	}
	return uncastObj.(*unstructured.Unstructured), nil
}
```

