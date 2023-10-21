## 简介

DiscoveryClient 是一个发现客户端，它的主要作用是用于发现 API Server 支持的资源组、资源版本和资源信息。在 Kubernetes 中，API Server 支持很多资源组、资源版本和资源信息，我们可以通过使用 DiscoveryClient 来查看这些信息。此外，kubectl 的 API 版本和 API 资源也是通过 DiscoveryClient 来实现的。我们还可以将这些信息缓存到本地，以减轻 API 访问的压力。缓存文件默认存储在 `./kube/cache` 和 `./kube/http-cache` 目录下。

## DiscoveryClient

```go
// DiscoveryClient 实现了发现服务器支持的 API 组、版本和资源的函数。
type DiscoveryClient struct {
	restClient restclient.Interface

	LegacyPrefix        string
	UseLegacyDiscovery  bool
}

// _ 用于确保 DiscoveryClient 实现了 AggregatedDiscoveryInterface 接口。
var _ AggregatedDiscoveryInterface = &DiscoveryClient{}
```

### ServerGroupsAndResources

```GO
// ServerGroupsAndResources 返回所有组和版本的支持资源。
func (d *DiscoveryClient) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return withRetries(defaultRetries, func() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
		return ServerGroupsAndResources(d)
	})
}
```

## DiscoveryInterface

```GO
// DiscoveryInterface 包含了发现服务器支持的 API 组、版本和资源的方法。
type DiscoveryInterface interface {
	RESTClient() restclient.Interface
	ServerGroupsInterface
	ServerResourcesInterface
	ServerVersionInterface
	OpenAPISchemaInterface
	OpenAPIV3SchemaInterface
	WithLegacy() DiscoveryInterface
}
```

### ServerGroupsInterface

```GO
// ServerGroupsInterface 包含了获取 API 服务器上支持的组的方法。
type ServerGroupsInterface interface {
	ServerGroups() (*metav1.APIGroupList, error)
}
```

### ServerResourcesInterface

```GO
// ServerResourcesInterface 包含了获取 API 服务器上支持的资源的方法。
type ServerResourcesInterface interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
	ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error)
	ServerPreferredResources() ([]*metav1.APIResourceList, error)
	ServerPreferredNamespacedResources() ([]*metav1.APIResourceList, error)
}
```

### ServerVersionInterface

```GO
// ServerVersionInterface 包含了获取服务器版本的方法。
type ServerVersionInterface interface {
	ServerVersion() (*version.Info, error)
}
```

### OpenAPISchemaInterface

```GO
// OpenAPISchemaInterface 包含了检索 OpenAPI 模式的方法。
type OpenAPISchemaInterface interface {
	OpenAPISchema() (*openapi_v2.Document, error)
}
```

### OpenAPIV3SchemaInterface

```GO
// OpenAPIV3SchemaInterface 包含了检索 OpenAPI V3 模式的方法。
type OpenAPIV3SchemaInterface interface {
	OpenAPIV3() openapi.Client
}
```

## ServerGroupsAndResources

```GO
// ServerGroupsAndResources 函数返回所有组和版本的支持资源。
func ServerGroupsAndResources(d DiscoveryInterface) ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	var sgs *metav1.APIGroupList
	var resources []*metav1.APIResourceList
	var failedGVs map[schema.GroupVersion]error
	var err error

	// 如果传入的发现对象实现了更广泛的 AggregatedDiscoveryInterface 接口，
	// 则尝试使用组和资源进行聚合发现。
	if ad, ok := d.(AggregatedDiscoveryInterface); ok {
		var resourcesByGV map[schema.GroupVersion]*metav1.APIResourceList
		sgs, resourcesByGV, failedGVs, err = ad.GroupsAndMaybeResources()
		for _, resourceList := range resourcesByGV {
			resources = append(resources, resourceList)
		}
	} else {
		sgs, err = d.ServerGroups()
	}

	if sgs == nil {
		return nil, nil, err
	}
	resultGroups := []*metav1.APIGroup{}
	for i := range sgs.Groups {
		resultGroups = append(resultGroups, &sgs.Groups[i])
	}
	// 如果聚合发现成功，则资源不为 nil。
	if resources != nil {
		// 任何过时的组/版本返回的聚合发现
		// 必须作为失败的组/版本返回给调用者。
		var ferr error
		if len(failedGVs) > 0 {
			ferr = &ErrGroupDiscoveryFailed{Groups: failedGVs}
		}
		return resultGroups, resources, ferr
	}

	groupVersionResources, failedGroups := fetchGroupVersionResources(d, sgs)

	// 按照组/版本发现顺序排序结果
	result := []*metav1.APIResourceList{}
	for _, apiGroup := range sgs.Groups {
		for _, version := range apiGroup.Versions {
			gv := schema.GroupVersion{Group: apiGroup.Name, Version: version.Version}
			if resources, ok := groupVersionResources[gv]; ok {
				result = append(result, resources)
			}
		}
	}

	if len(failedGroups) == 0 {
		return resultGroups, result, nil
	}

	return resultGroups, result, &ErrGroupDiscoveryFailed{Groups: failedGroups}
}
```

### GroupsAndMaybeResources

```GO
// GroupsAndMaybeResources 函数返回发现的组，并且（如果是新的聚合发现格式）以组/版本为键的资源。
// 合并来自 /api 和 /apis 的发现组和资源（无论是否聚合）。
// 必须先按顺序排列旧版组。服务器将以聚合发现格式或旧版格式返回两个端点（/api、/apis）。
// 为了安全起见，只有在两个端点都返回资源的情况下才返回资源。
// 返回的 "failedGVs" 可以为空，但只有在返回错误时才为 nil。
func (d *DiscoveryClient) GroupsAndMaybeResources() (
	*metav1.APIGroupList,
	map[schema.GroupVersion]*metav1.APIResourceList,
	map[schema.GroupVersion]error,
	error) {
	// 首先是旧版组（只有一个 core/v1 组）。返回的组必须非空，但可能为空。返回的资源、apiResources map 可能为 nil。
	groups, resources, failedGVs, err := d.downloadLegacy()
	if err != nil {
		return nil, nil, nil, err
	}
	// 从 /apis 下载的发现组和（可能的）资源。
	apiGroups, apiResources, failedApisGVs, aerr := d.downloadAPIs()
	if aerr != nil {
		return nil, nil, nil, aerr
	}
	// 将 apis 组合并到旧版组中。
	for _, group := range apiGroups.Groups {
		groups.Groups = append(groups.Groups, group)
	}
	// 为了安全起见，只有在两个端点都返回资源时才返回资源。
	if resources != nil && apiResources != nil {
		for gv, resourceList := range apiResources {
			resources[gv] = resourceList
		}
	} else if resources != nil {
		resources = nil
	}
	// 合并来自 /api 和 /apis 的失败的 GroupVersion。
	for gv, err := range failedApisGVs {
		failedGVs[gv] = err
	}
	return groups, resources, failedGVs, err
}
```

### fetchGroupVersionResources

```GO
// fetchGroupVersionResources 使用发现客户端并行获取指定组的资源。
func fetchGroupVersionResources(d DiscoveryInterface, apiGroups *metav1.APIGroupList) (map[schema.GroupVersion]*metav1.APIResourceList, map[schema.GroupVersion]error) {
	groupVersionResources := make(map[schema.GroupVersion]*metav1.APIResourceList)
	failedGroups := make(map[schema.GroupVersion]error)

	wg := &sync.WaitGroup{}
	resultLock := &sync.Mutex{}
	for _, apiGroup := range apiGroups.Groups {
		for _, version := range apiGroup.Versions {
			groupVersion := schema.GroupVersion{Group: apiGroup.Name, Version: version.Version}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer utilruntime.HandleCrash()

				apiResourceList, err := d.ServerResourcesForGroupVersion(groupVersion.String())

				// 锁定以记录结果
				resultLock.Lock()
				defer resultLock.Unlock()

				if err != nil {
					// TODO: 可能只限制为 NotFound 错误
					failedGroups[groupVersion] = err
				}
				if apiResourceList != nil {
					// 即使在错误的情况下，可能返回了某些回退资源
					groupVersionResources[groupVersion] = apiResourceList
				}
			}()
		}
	}
	wg.Wait()

	return groupVersionResources, failedGroups
}
```

