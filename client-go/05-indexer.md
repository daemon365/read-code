## 简介

client-go是Kubernetes官方提供的Go语言客户端库，用于与Kubernetes API服务器进行交互。其中一个核心组件是Indexer，用于在本地缓存中维护Kubernetes API对象的索引。

Indexer是一个具有查询功能的数据结构，它会在本地缓存中为每个Kubernetes API对象建立索引。可以通过指定不同的索引函数来构建不同类型的索引，例如按标签、按名称或按任意其他属性进行索引。这些索引将使客户端能够快速地从本地缓存中检索到所需的API对象，而无需每次都向API服务器发送请求。

Indexer还提供了一些便捷的方法来获取、创建、更新和删除Kubernetes API对象。这些方法可以直接在本地缓存中操作API对象，而无需向API服务器发送请求，从而提高了客户端的性能和效率。

## Indexer

```go
// Indexer接口通过多个索引扩展Store，并限制每个累加器只能保存当前对象（并在Delete后为空）。
//
// 这里有三种类型的字符串：
// 1. 存储键，如Store接口中定义的键，
// 2. 索引的名称，
// 3. "indexed value"，由IndexFunc生成，并且可以是字段值或从对象计算得到的任何其他字符串。
type Indexer interface {
	Store
	// Index返回存储的对象，其索引值集合与给定对象的索引值集合相交，用于指定的索引
	Index(indexName string, obj interface{}) ([]interface{}, error)
	// IndexKeys返回存储的对象的存储键，其中的索引值集合包括给定的索引值
	IndexKeys(indexName, indexedValue string) ([]string, error)
	// ListIndexFuncValues返回给定索引的所有索引值
	ListIndexFuncValues(indexName string) []string
	// ByIndex返回存储的对象，其指定索引的索引值集合包括给定的索引值
	ByIndex(indexName, indexedValue string) ([]interface{}, error)
	// GetIndexers返回索引器
	GetIndexers() Indexers
	// AddIndexers向此存储添加更多的索引器。如果在存储中已经有数据后调用此函数，结果是未定义的。
	AddIndexers(newIndexers Indexers) error
}
```

### Indexers

```go
// Replace将删除存储的内容，改为使用给定的列表。Store将拥有该列表，调用此函数后不应再引用它// IndexFunc知道如何计算对象的索引值集合。
type IndexFunc func(obj interface{}) ([]string, error)

// Index将索引值映射到在存储中与该值匹配的一组键
type Index map[string]sets.String

// Indexers将名称映射到IndexFunc
type Indexers map[string]IndexFunc

// Indices将名称映射到Index
type Indices map[string]Index
```

### Store

```go
// Store是一个通用的对象存储和处理接口。Store保存一个从字符串键到累加器的映射，并具有将给定对象添加、更新和从与给定键关联的累加器中删除的操作。
// Store还知道如何从给定对象中提取键，因此许多操作只需要对象作为参数。
// 在最简单的Store实现中，每个累加器只是最后给定的对象，或者在删除后为空，因此Store的行为是简单的存储。
// Reflector知道如何监视服务器并更新Store。此包提供了多种Store的实现。
type Store interface {
	// Add将给定对象添加到与给定对象的键关联的累加器中。
	Add(obj interface{}) error
	// Update更新与给定对象的键关联的累加器中的给定对象。
	Update(obj interface{}) error
	// Delete从与给定对象的键关联的累加器中删除给定对象。
	Delete(obj interface{}) error
	// List返回当前非空累加器的列表。
	List() []interface{}
	// ListKeys返回当前与非空累加器关联的所有键的列表。
	ListKeys() []string
	// Get返回与给定对象的键关联的累加器。
	Get(obj interface{}) (item interface{}, exists bool, err error)
	// GetByKey返回与给定键关联的累加器。
	GetByKey(key string) (item interface{}, exists bool, err error)
	// Replace将删除存储的内容，改为使用给定的列表。Store将拥有该列表，调用此函数后不应再引用它。
	Replace([]interface{}, string) error
	// Resync在这里出现的术语中没有意义，但在某些具有非平凡附加行为的实现中（例如DeltaFIFO），它具有意义。
	Resync() error
}
```

## cache

```go
// *cache 根据 ThreadSafeStore 和相关的 KeyFunc 实现了 Indexer 接口。
type cache struct {
	// cacheStorage 承担缓存的线程安全性
	cacheStorage ThreadSafeStore
	// keyFunc 用于生成存储在 items 中的对象的键，应该是确定性的。
	keyFunc KeyFunc
}

var _ Store = &cache{}

// Add 将项插入缓存中。
func (c *cache) Add(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return KeyError{obj, err}
	}
	c.cacheStorage.Add(key, obj)
	return nil
}

// Update 将缓存中的项设置为其更新后的状态。
func (c *cache) Update(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return KeyError{obj, err}
	}
	c.cacheStorage.Update(key, obj)
	return nil
}

// Delete 从缓存中删除项。
func (c *cache) Delete(obj interface{}) error {
	key, err := c.keyFunc(obj)
	if err != nil {
		return KeyError{obj, err}
	}
	c.cacheStorage.Delete(key)
	return nil
}

// List 返回所有项的列表。
// 只要将所有项视为不可变的，List 就是完全线程安全的。
func (c *cache) List() []interface{} {
	return c.cacheStorage.List()
}

// ListKeys 返回当前缓存中对象的所有键的列表。
func (c *cache) ListKeys() []string {
	return c.cacheStorage.ListKeys()
}

// GetIndexers 返回缓存的索引器。
func (c *cache) GetIndexers() Indexers {
	return c.cacheStorage.GetIndexers()
}

// Index 返回与索引函数匹配的项列表。
// 只要将所有项视为不可变的，Index 就是线程安全的。
func (c *cache) Index(indexName string, obj interface{}) ([]interface{}, error) {
	return c.cacheStorage.Index(indexName, obj)
}

// IndexKeys 返回存储对象的存储键，其具有给定索引名称的索引值集包含给定的索引值。
// 返回的键适合传递给 GetByKey()。
func (c *cache) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return c.cacheStorage.IndexKeys(indexName, indexedValue)
}

// ListIndexFuncValues 返回 Index 函数生成的值的列表。
func (c *cache) ListIndexFuncValues(indexName string) []string {
	return c.cacheStorage.ListIndexFuncValues(indexName)
}

// ByIndex 返回存储对象的集合，其具有给定索引名称的索引值集包含给定的索引值。
func (c *cache) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	return c.cacheStorage.ByIndex(indexName, indexedValue)
}

func (c *cache) AddIndexers(newIndexers Indexers) error {
	return c.cacheStorage.AddIndexers(newIndexers)
}

// Get 返回请求的项，或设置 exists=false。
// 只要将所有项视为不可变的，Get 就是完全线程安全的。
func (c *cache) Get(obj interface{}) (item interface{}, exists bool, err error) {
	key, err := c.keyFunc(obj)
	if err != nil {
		return nil, false, KeyError{obj, err}
	}
	return c.GetByKey(key)
}

// GetByKey 返回请求的项，或设置 exists=false。
// 只要将所有项视为不可变的，GetByKey 就是完全线程安全的。
func (c *cache) GetByKey(key string) (item interface{}, exists bool, err error) {
	item, exists = c.cacheStorage.Get(key)
	return item, exists, nil
}

// Replace 将 'c' 的内容替换为给定的列表。
// 'c' 接管列表的所有权，调用此函数后不应再引用列表。
func (c *cache) Replace(list []interface{}, resourceVersion string) error {
	items := make(map[string]interface{}, len(list))
	for _, item := range list {
		key, err := c.keyFunc(item)
		if err != nil {
			return KeyError{item, err}
		}
		items[key] = item
	}
	c.cacheStorage.Replace(items, resourceVersion)
	return nil
}

// Resync 对于此函数是无意义的。
func (c *cache) Resync() error {
	return nil
}
```

## ThreadSafeStore

```go
// ThreadSafeStore 是一个接口，允许并发地对存储后端进行索引访问。
// 它类似于 Indexer，但不一定知道如何从给定的对象中提取 Store 键。
//
// TL;DR 注意事项：不要修改 Get 或 List 返回的任何内容，否则将破坏索引功能，而且不具备线程安全性。
//
// Get 和 List 提供的线程安全性仅在调用者将返回的项视为只读时有效。
// 例如，通过 Add 将插入到存储中的指针将按原样由 Get 返回。
// 多个客户端可能对同一键调用 Get 并以非线程安全的方式修改指针。
// 还要注意，修改由索引器存储的对象（如果有）将 不会 自动重新进行索引。
// 因此，通常情况下不建议直接修改 Get/List 返回的对象。
type ThreadSafeStore interface {
	Add(key string, obj interface{})
	Update(key string, obj interface{})
	Delete(key string)
	Get(key string) (item interface{}, exists bool)
	List() []interface{}
	ListKeys() []string
	Replace(map[string]interface{}, string)
	Index(indexName string, obj interface{}) ([]interface{}, error)
	IndexKeys(indexName, indexedValue string) ([]string, error)
	ListIndexFuncValues(name string) []string
	ByIndex(indexName, indexedValue string) ([]interface{}, error)
	GetIndexers() Indexers

	// AddIndexers 向该存储添加更多的索引器。
	// 如果在存储中已经有数据后调用此函数，结果是不确定的。
	AddIndexers(newIndexers Indexers) error
	// Resync 是一个空操作，已被弃用。
	Resync() error
}
```

### threadSafeMap

````go
// threadSafeMap 实现了 ThreadSafeStore 接口
type threadSafeMap struct {
	lock  sync.RWMutex
	items map[string]interface{}
	// index 实现了索引功能
	index *storeIndex
}

func (c *threadSafeMap) Add(key string, obj interface{}) {
	c.Update(key, obj)
}

func (c *threadSafeMap) Update(key string, obj interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()
	oldObject := c.items[key]
	c.items[key] = obj
	c.index.updateIndices(oldObject, obj, key)
}

func (c *threadSafeMap) Delete(key string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if obj, exists := c.items[key]; exists {
		c.index.updateIndices(obj, nil, key)
		delete(c.items, key)
	}
}

func (c *threadSafeMap) Get(key string) (item interface{}, exists bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	item, exists = c.items[key]
	return item, exists
}

func (c *threadSafeMap) List() []interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	list := make([]interface{}, 0, len(c.items))
	for _, item := range c.items {
		list = append(list, item)
	}
	return list
}

// ListKeys 返回当前 threadSafeMap 中对象的所有键的列表。
func (c *threadSafeMap) ListKeys() []string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	list := make([]string, 0, len(c.items))
	for key := range c.items {
		list = append(list, key)
	}
	return list
}

func (c *threadSafeMap) Replace(items map[string]interface{}, resourceVersion string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.items = items

	// 重建任何索引
	c.index.reset()
	for key, item := range c.items {
		c.index.updateIndices(nil, item, key)
	}
}

// Index 返回与给定对象在索引函数上匹配的项列表。
// 只要将所有项视为不可变的，Index 就是线程安全的。
func (c *threadSafeMap) Index(indexName string, obj interface{}) ([]interface{}, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	storeKeySet, err := c.index.getKeysFromIndex(indexName, obj)
	if err != nil {
		return nil, err
	}

	list := make([]interface{}, 0, storeKeySet.Len())
	for storeKey := range storeKeySet {
		list = append(list, c.items[storeKey])
	}
	return list, nil
}

// ByIndex 返回具有给定索引名称中包含给定索引值的项列表
func (c *threadSafeMap) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	set, err := c.index.getKeysByIndex(indexName, indexedValue)
	if err != nil {
		return nil, err
	}
	list := make([]interface{}, 0, set.Len())
	for key := range set {
		list = append(list, c.items[key])
	}

	return list, nil
}

// IndexKeys 返回具有给定索引名称中包含给定索引值的对象的存储键列表。
// 只要将所有项视为不可变的，IndexKeys 就是线程安全的。
func (c *threadSafeMap) IndexKeys(indexName, indexedValue string) ([]string, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	set, err := c.index.getKeysByIndex(indexName, indexedValue)
	if err != nil {
		return nil, err
	}
	return set.List(), nil
}

func (c *threadSafeMap) ListIndexFuncValues(indexName string) []string {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.index.getIndexValues(indexName)
}

func (c *threadSafeMap) GetIndexers() Indexers {
	return c.index.indexers
}

func (c *threadSafeMap) AddIndexers(newIndexers Indexers) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.items) > 0 {
		return fmt.Errorf("cannot add indexers to running index")
	}

	return c.index.addIndexers(newIndexers)
}

func (c *threadSafeMap) Resync() error {
	// 无操作
	return nil
}

// NewThreadSafeStore 创建 ThreadSafeStore 的新实例。
func NewThreadSafeStore(indexers Indexers, indices Indices) ThreadSafeStore {
	return &threadSafeMap{
		items: map[string]interface{}{},
		index: &storeIndex{
			indexers: indexers,
			indices:  indices,
		},
	}
}
````

#### storeIndex

```go
// storeIndex 实现了 Store 接口的索引功能
type storeIndex struct {
	// indexers 将名称映射到 IndexFunc
	indexers Indexers
	// indices 将名称映射到 Index
	indices Indices
}

func (i *storeIndex) reset() {
	i.indices = Indices{}
}

// getKeysFromIndex根据索引名称和对象获取与索引匹配的键集合。
func (i *storeIndex) getKeysFromIndex(indexName string, obj interface{}) (sets.String, error) {
	indexFunc := i.indexers[indexName]
	if indexFunc == nil {
		return nil, fmt.Errorf("索引名称为%s的索引不存在", indexName)
	}

	indexedValues, err := indexFunc(obj)
	if err != nil {
		return nil, err
	}
	index := i.indices[indexName]

	var storeKeySet sets.String
	if len(indexedValues) == 1 {
		// 在大多数情况下，只有一个匹配值。
		// 优化最常见的路径-此处不需要去重。
		storeKeySet = index[indexedValues[0]]
	} else {
		// 需要对返回列表进行去重。
		// 因为允许多个键，所以可能发生这种情况。
		storeKeySet = sets.String{}
		for _, indexedValue := range indexedValues {
			for key := range index[indexedValue] {
				storeKeySet.Insert(key)
			}
		}
	}

	return storeKeySet, nil
}

// getKeysByIndex根据索引名称和索引值获取与之匹配的键集合。
func (i *storeIndex) getKeysByIndex(indexName, indexedValue string) (sets.String, error) {
	indexFunc := i.indexers[indexName]
	if indexFunc == nil {
		return nil, fmt.Errorf("索引名称为%s的索引不存在", indexName)
	}

	index := i.indices[indexName]
	return index[indexedValue], nil
}

// getIndexValues返回指定索引的所有索引值。
func (i *storeIndex) getIndexValues(indexName string) []string {
	index := i.indices[indexName]
	names := make([]string, 0, len(index))
	for key := range index {
		names = append(names, key)
	}
	return names
}

// addIndexers向存储中添加更多的索引器。
func (i *storeIndex) addIndexers(newIndexers Indexers) error {
	oldKeys := sets.StringKeySet(i.indexers)
	newKeys := sets.StringKeySet(newIndexers)

	if oldKeys.HasAny(newKeys.List()...) {
		return fmt.Errorf("索引器冲突：%v", oldKeys.Intersection(newKeys))
	}

	for k, v := range newIndexers {
		i.indexers[k] = v
	}
	return nil
}

// updateIndices修改受管理索引中的对象位置：
// - 对于创建，只需要提供newObj
// - 对于更新，需要同时提供oldObj和newObj
// - 对于删除，只需要提供oldObj
// updateIndices必须在已经锁定缓存的函数中调用
func (i *storeIndex) updateIndices(oldObj interface{}, newObj interface{}, key string) {
	var oldIndexValues, indexValues []string
	var err error
	for name, indexFunc := range i.indexers {
		if oldObj != nil {
			oldIndexValues, err = indexFunc(oldObj)
		} else {
			oldIndexValues = oldIndexValues[:0]
		}
		if err != nil {
			panic(fmt.Errorf("无法计算索引 %q 上键 %q 的索引条目：%v", name, key, err))
		}

		if newObj != nil {
			indexValues, err = indexFunc(newObj)
		} else {
			indexValues = indexValues[:0]
		}
		if err != nil {
			panic(fmt.Errorf("无法计算索引 %q 上键 %q 的索引条目：%v", name, key, err))
		}

		index := i.indices[name]
		if index == nil {
			index = Index{}
			i.indices[name] = index
		}

		if len(indexValues) == 1 && len(oldIndexValues) == 1 && indexValues[0] == oldIndexValues[0] {
			// 我们针对最常见的情况进行优化，即indexFunc返回单个值且未更改
			continue
		}

		for _, value := range oldIndexValues {
			i.deleteKeyFromIndex(key, value, index)
		}
		for _, value := range indexValues {
			i.addKeyToIndex(key, value, index)
		}
	}
}

// addKeyToIndex将键添加到索引中的索引值。
func (i *storeIndex) addKeyToIndex(key, indexValue string, index Index) {
	set := index[indexValue]
	if set == nil {
		set = sets.String{}
		index[indexValue] = set
	}
	set.Insert(key)
}

// deleteKeyFromIndex从索引中的索引值中删除键。
func (i *storeIndex) deleteKeyFromIndex(key, indexValue string, index Index) {
	set := index[indexValue]
	if set == nil {
		return
	}
	set.Delete(key)
	// 如果集合为空，则删除集合。
	// 对于高基数的索引，短时间存在的资源可能导致内存随时间增加而增加。
	// 参见kubernetes/kubernetes/issues/84959。
	if len(set) == 0 {
		delete(index, indexValue)
	}
}
```

