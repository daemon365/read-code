## 简介

`Lister` 是 `client-go` 中的一个接口，它定义了一组方法，用于从 Kubernetes API Server 中获取资源列表。这些方法可以在同步代码中使用，而无需向 Kubernetes API 发送额外的请求。这篇文章以node lister举例

## NodeLister

```GO
// NodeLister 帮助列出节点。
// 在此返回的所有对象都必须视为只读。
type NodeLister interface {
	// List 列出索引器中的所有节点。
	// 在此返回的对象必须视为只读。
	List(selector labels.Selector) (ret []*v1.Node, err error)
	// Get 根据给定的名称从索引中检索节点。
	// 在此返回的对象必须视为只读。
	Get(name string) (*v1.Node, error)
	NodeListerExpansion
}

// NodeListerExpansion 允许将自定义方法添加到 NodeLister.
type NodeListerExpansion interface{}
```

## nodeLister

```GO
// nodeLister 实现了 NodeLister 接口。
type nodeLister struct {
	indexer cache.Indexer
}

// NewNodeLister 返回一个新的 NodeLister。
func NewNodeLister(indexer cache.Indexer) NodeLister {
	return &nodeLister{indexer: indexer}
}

// List 列出索引器中的所有节点。
func (s *nodeLister) List(selector labels.Selector) (ret []*v1.Node, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.Node))
	})
	return ret, err
}

// Get 根据给定的名称从索引中检索节点。
func (s *nodeLister) Get(name string) (*v1.Node, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("node"), name)
	}
	return obj.(*v1.Node), nil
}
```

