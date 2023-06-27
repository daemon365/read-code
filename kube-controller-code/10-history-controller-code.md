
## 简介

用于管理历史记录（history）资源的创建、更新和删除。历史记录资源是指一些状态对象的历史版本，例如ReplicaSet、Deployment等。

具体来说，当一个ReplicaSet或Deployment被更新时，history-controller会自动创建一个新的历史记录资源来记录这个更新，并保留一定数量的历史版本。这些历史记录资源可以被用来进行回滚操作，也可以用于审计和诊断等目的。

## 说明

`history-controller`是一个控制器，它与其他控制器有所不同，它的主要功能是维护和管理系统历史记录，而不是直接参与系统操作。它可以被其他控制器或模块调用，以便查询或修改历史记录。`history-controller`可以被视为一个被动的控制器，因为它不需要主动运行或执行操作，但它仍然需要在系统运行期间处于活动状态以便能够处理调用请求。

## New

创建一个`ControllerRevision`对象的函数

```GO
func NewControllerRevision(
    // 需要创建历史版本的对象
    parent metav1.Object,
    // 它的GVK
	parentKind schema.GroupVersionKind,
    // 修订版本的标签
	templateLabels map[string]string,
    // 修订版本的数据
	data runtime.RawExtension,
    // 版本号
	revision int64,
    // 修订版本的碰撞计数
	collisionCount *int32) (*apps.ControllerRevision, error) {
	labelMap := make(map[string]string)
	for k, v := range templateLabels {
		labelMap[k] = v
	}
	cr := &apps.ControllerRevision{
		ObjectMeta: metav1.ObjectMeta{
			Labels:          labelMap,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(parent, parentKind)},
		},
		Data:     data,
		Revision: revision,
	}
   	// 计算hash
	hash := HashControllerRevision(cr, collisionCount)
    // 拼接name和hash
	cr.Name = ControllerRevisionName(parent.GetName(), hash)
    // 把hash加入label
	cr.Labels[ControllerRevisionHashLabel] = hash
	return cr, nil
}

const ControllerRevisionHashLabel = "controller.kubernetes.io/hash"
```

#### HashControllerRevision

```go
func HashControllerRevision(revision *apps.ControllerRevision, probe *int32) string {
	hf := fnv.New32()
	if len(revision.Data.Raw) > 0 {
		hf.Write(revision.Data.Raw)
	}
	if revision.Data.Object != nil {
		hashutil.DeepHashObject(hf, revision.Data.Object)
	}
	if probe != nil {
		hf.Write([]byte(strconv.FormatInt(int64(*probe), 10)))
	}
	return rand.SafeEncodeString(fmt.Sprint(hf.Sum32()))
}
```

#### ControllerRevisionName

```GO
func ControllerRevisionName(prefix string, hash string) string {
	if len(prefix) > 223 {
		prefix = prefix[:223]
	}

	return fmt.Sprintf("%s-%s", prefix, hash)
}
```

#### 对Revision排序

```go
func SortControllerRevisions(revisions []*apps.ControllerRevision) {
    // 
	sort.Stable(byRevision(revisions))
}

type byRevision []*apps.ControllerRevision

func (br byRevision) Len() int {
	return len(br)
}

// Less breaks ties first by creation timestamp, then by name
func (br byRevision) Less(i, j int) bool {
	if br[i].Revision == br[j].Revision {
		if br[j].CreationTimestamp.Equal(&br[i].CreationTimestamp) {
			return br[i].Name < br[j].Name
		}
		return br[j].CreationTimestamp.After(br[i].CreationTimestamp.Time)
	}
	return br[i].Revision < br[j].Revision
}

func (br byRevision) Swap(i, j int) {
	br[i], br[j] = br[j], br[i]
}
```

#### 判断两个ControllerRevision相不相等

```go
func EqualRevision(lhs *apps.ControllerRevision, rhs *apps.ControllerRevision) bool {
	var lhsHash, rhsHash *uint32
    // 如果都是空的 就是相等
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}
    // 取出lhs的hash
	if hs, found := lhs.Labels[ControllerRevisionHashLabel]; found {
		hash, err := strconv.ParseInt(hs, 10, 32)
		if err == nil {
			lhsHash = new(uint32)
			*lhsHash = uint32(hash)
		}
	}
    // 取出rhs的hasg
	if hs, found := rhs.Labels[ControllerRevisionHashLabel]; found {
		hash, err := strconv.ParseInt(hs, 10, 32)
		if err == nil {
			rhsHash = new(uint32)
			*rhsHash = uint32(hash)
		}
	}
    // 判断
	if lhsHash != nil && rhsHash != nil && *lhsHash != *rhsHash {
		return false
	}
	return bytes.Equal(lhs.Data.Raw, rhs.Data.Raw) && apiequality.Semantic.DeepEqual(lhs.Data.Object, rhs.Data.Object)
}
```

#### 从列表中找出相等ControllerRevision

```go
func FindEqualRevisions(revisions []*apps.ControllerRevision, needle *apps.ControllerRevision) []*apps.ControllerRevision {
	var eq []*apps.ControllerRevision
	for i := range revisions {
		if EqualRevision(revisions[i], needle) {
			eq = append(eq, revisions[i])
		}
	}
	return eq
}
```

## 操作ControllerRevisions的接口

```GO
type Interface interface {
	
	ListControllerRevisions(parent metav1.Object, selector labels.Selector) ([]*apps.ControllerRevision, error)
	
	CreateControllerRevision(parent metav1.Object, revision *apps.ControllerRevision, collisionCount *int32) (*apps.ControllerRevision, error)
	
	DeleteControllerRevision(revision *apps.ControllerRevision) error

	UpdateControllerRevision(revision *apps.ControllerRevision, newRevision int64) (*apps.ControllerRevision, error)

	AdoptControllerRevision(parent metav1.Object, parentKind schema.GroupVersionKind, revision *apps.ControllerRevision) (*apps.ControllerRevision, error)

	ReleaseControllerRevision(parent metav1.Object, revision *apps.ControllerRevision) (*apps.ControllerRevision, error)
}

```

### 结构体

```go
type realHistory struct {
	client clientset.Interface
	lister appslisters.ControllerRevisionLister
}

func NewHistory(client clientset.Interface, lister appslisters.ControllerRevisionLister) Interface {
	return &realHistory{client, lister}
}
```

### ListControllerRevisions

- 获取对象的所有ControllerRevision

```GO
func (rh *realHistory) ListControllerRevisions(parent metav1.Object, selector labels.Selector) ([]*apps.ControllerRevision, error) {
    // 拿出所有的history 比较它的owned
	history, err := rh.lister.ControllerRevisions(parent.GetNamespace()).List(selector)
	if err != nil {
		return nil, err
	}
	var owned []*apps.ControllerRevision
	for i := range history {
		ref := metav1.GetControllerOfNoCopy(history[i])
		if ref == nil || ref.UID == parent.GetUID() {
			owned = append(owned, history[i])
		}

	}
	return owned, err
}
```

### CreateControllerRevision

- 创建一个ControllerRevision对象

```go
func (rh *realHistory) CreateControllerRevision(parent metav1.Object, revision *apps.ControllerRevision, collisionCount *int32) (*apps.ControllerRevision, error) {
	if collisionCount == nil {
		return nil, fmt.Errorf("collisionCount should not be nil")
	}

	// Clone the input
	clone := revision.DeepCopy()

	// Continue to attempt to create the revision updating the name with a new hash on each iteration
	for {
        // 计算hash
		hash := HashControllerRevision(revision, collisionCount)
		// 赋值name
		clone.Name = ControllerRevisionName(parent.GetName(), hash)
        // 获取namespace
		ns := parent.GetNamespace()
        // create对象
		created, err := rh.client.AppsV1().ControllerRevisions(ns).Create(context.TODO(), clone, metav1.CreateOptions{})
		if errors.IsAlreadyExists(err) {
			exists, err := rh.client.AppsV1().ControllerRevisions(ns).Get(context.TODO(), clone.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
            // 如果存在了 还相等 直接返回
			if bytes.Equal(exists.Data.Raw, clone.Data.Raw) {
				return exists, nil
			}
            // collisionCount+1 继续 下次的hash就不一样了
			*collisionCount++
			continue
		}
		return created, err
	}
}
```

### UpdateControllerRevision

- 更新ControllerRevision对象

```GO
func (rh *realHistory) UpdateControllerRevision(revision *apps.ControllerRevision, newRevision int64) (*apps.ControllerRevision, error) {
	clone := revision.DeepCopy()
    // 使用重试机制
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
        // 如果对象的修订版本号已经是新版本号，则直接返回nil，不需要更新
		if clone.Revision == newRevision {
			return nil
		}
        // 更新对象的修订版本号
		clone.Revision = newRevision
        // 调用Kubernetes API的更新控制器修订版本的方法
		updated, updateErr := rh.client.AppsV1().ControllerRevisions(clone.Namespace).Update(context.TODO(), clone, metav1.UpdateOptions{})
		if updateErr == nil {
			return nil
		}
        // 如果更新失败，则尝试从缓存中获取最新的修订版本对象
		if updated != nil {
			clone = updated
		}
		if updated, err := rh.lister.ControllerRevisions(clone.Namespace).Get(clone.Name); err == nil {
			// make a copy so we don't mutate the shared cache
			clone = updated.DeepCopy()
		}
        // 返回更新过程中出现的错误
		return updateErr
	})
	return clone, err
}
```

### DeleteControllerRevision

- 删除ControllerRevision对象

```GO
func (rh *realHistory) DeleteControllerRevision(revision *apps.ControllerRevision) error {
	// 直接调用api删除
    return rh.client.AppsV1().ControllerRevisions(revision.Namespace).Delete(context.TODO(), revision.Name, metav1.DeleteOptions{})
}

```

### AdoptControllerRevision

- 向给定的`ControllerRevision`对象添加一个owner引用

```GO
type objectForPatch struct {
	Metadata objectMetaForPatch `json:"metadata"`
}

// objectMetaForPatch define object meta struct for patch operation
type objectMetaForPatch struct {
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences"`
	UID             types.UID               `json:"uid"`
}

func (rh *realHistory) AdoptControllerRevision(parent metav1.Object, parentKind schema.GroupVersionKind, revision *apps.ControllerRevision) (*apps.ControllerRevision, error) {
	blockOwnerDeletion := true
	isController := true
	// 检查revision是不是孤儿了 如果不是他被另外对象使用 返回错误
	if owner := metav1.GetControllerOfNoCopy(revision); owner != nil {
		return nil, fmt.Errorf("attempt to adopt revision owned by %v", owner)
	}
    
    // 设置revision 的Owner bing更新
	addControllerPatch := objectForPatch{
		Metadata: objectMetaForPatch{
			UID: revision.UID,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         parentKind.GroupVersion().String(),
				Kind:               parentKind.Kind,
				Name:               parent.GetName(),
				UID:                parent.GetUID(),
				Controller:         &isController,
				BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
	}
	patchBytes, err := json.Marshal(&addControllerPatch)
	if err != nil {
		return nil, err
	}
	// Use strategic merge patch to add an owner reference indicating a controller ref
	return rh.client.AppsV1().ControllerRevisions(parent.GetNamespace()).Patch(context.TODO(), revision.GetName(),
		types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
}
```

### ReleaseControllerRevision

- 把对象的revision删除

```GO
func (rh *realHistory) ReleaseControllerRevision(parent metav1.Object, revision *apps.ControllerRevision) (*apps.ControllerRevision, error) {
    // 生成一个删除指定所有者对象引用的策略合并字节数组
	dataBytes, err := controller.GenerateDeleteOwnerRefStrategicMergeBytes(revision.UID, []types.UID{parent.GetUID()})
	if err != nil {
		return nil, err
	}

	// 更新
	released, err := rh.client.AppsV1().ControllerRevisions(revision.GetNamespace()).Patch(context.TODO(), revision.GetName(),
		types.StrategicMergePatchType, dataBytes, metav1.PatchOptions{})

	if err != nil {
		if errors.IsNotFound(err) {
			// We ignore deleted revisions
			return nil, nil
		}
		if errors.IsInvalid(err) {
			// We ignore cases where the parent no longer owns the revision or where the revision has no
			// owner.
			return nil, nil
		}
	}
	return released, err
}
```

