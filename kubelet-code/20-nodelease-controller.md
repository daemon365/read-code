## 简介

`NodeLeaseController`是Kubernetes集群中的一个控制器（Controller），用于管理节点租约（Node Lease）。节点租约是一种机制，用于定期向控制平面报告节点的健康状态和可用性信息。每个节点都会定期更新自己的租约，并将最新的信息发送给控制平面。

NodeLeaseController的主要功能是监视节点的租约状态，并根据需要进行更新和处理。它负责以下任务：

1. 创建和维护节点租约：NodeLeaseController会定期检查集群中的节点状态，并为每个节点创建或更新对应的节点租约。节点租约包含了节点的名称、健康状态、可用性信息等。
2. 监控节点租约的更新：NodeLeaseController会监视节点租约的更新情况。如果一个节点的租约长时间没有更新，NodeLeaseController会将其标记为不可用，并触发相应的处理逻辑。
3. 处理节点租约到期：当一个节点的租约到期时，NodeLeaseController会将其标记为不可用，并触发相应的处理逻辑。这可能包括通知其他控制器节点不可用的状态、重新分配该节点上的Pod等操作。

NodeLeaseController的作用在于确保节点租约的准确性和及时性。它通过定期更新和监视节点租约，向控制平面提供了关于节点的重要信息，从而帮助集群管理者和其他控制器正确地处理节点的状态变化和调度决策。

## Controller

```go
// 代码中定义了一个名为 Controller 的接口，用于管理组件的租约（lease）的创建和续约。
// 租约（lease）是用来协调不同组件之间的资源共享和竞争的机制。
// Controller 接口定义如下：
type Controller interface {
	Run(ctx context.Context)
}
```

## controller

```go
// ProcessLeaseFunc 是一个函数类型，用于处理给定的租约（lease）对象。
type ProcessLeaseFunc func(*coordinationv1.Lease) error

// controller 结构体用于实现 Controller 接口，它包含了一些属性来管理租约的创建和续约。
type controller struct {
	client                     clientset.Interface           // 用于与 Kubernetes API 交互的客户端
	leaseClient                coordclientset.LeaseInterface // 租约客户端，用于操作租约资源
	holderIdentity             string                        // 控制器的标识
	leaseName                  string                        // 租约名称
	leaseNamespace             string                        // 租约所属的命名空间
	leaseDurationSeconds       int32                         // 租约的持续时间（秒）
	renewInterval              time.Duration                 // 续约间隔时间
	clock                      clock.Clock                   // 时钟对象，用于获取当前时间
	onRepeatedHeartbeatFailure func()                        // 续约失败时的回调函数
	latestLease                *coordinationv1.Lease         // 最新的租约对象，由控制器更新或创建
	newLeasePostProcessFunc    ProcessLeaseFunc              // 允许在创建/刷新租约之前定制租约对象
}

// NewController 函数用于构建并返回一个控制器对象。
func NewController(clock clock.Clock, client clientset.Interface, holderIdentity string, leaseDurationSeconds int32, onRepeatedHeartbeatFailure func(), renewInterval time.Duration, leaseName, leaseNamespace string, newLeasePostProcessFunc ProcessLeaseFunc) Controller {
	var leaseClient coordclientset.LeaseInterface
	if client != nil {
		leaseClient = client.CoordinationV1().Leases(leaseNamespace)
	}
	return &controller{
		client:                     client,
		leaseClient:                leaseClient,
		holderIdentity:             holderIdentity,
		leaseName:                  leaseName,
		leaseNamespace:             leaseNamespace,
		leaseDurationSeconds:       leaseDurationSeconds,
		renewInterval:              renewInterval,
		clock:                      clock,
		onRepeatedHeartbeatFailure: onRepeatedHeartbeatFailure,
		newLeasePostProcessFunc:    newLeasePostProcessFunc,
	}
}
```

### Run

```go
// Run 方法用于运行控制器，主要逻辑是通过定期续约租约来确保资源的共享和竞争。
func (c *controller) Run(ctx context.Context) {
	if c.leaseClient == nil {
		klog.FromContext(ctx).Info("租约控制器没有有效的租约客户端，将不会声明或续约租约")
		return
	}
	wait.JitterUntilWithContext(ctx, c.sync, c.renewInterval, 0.04, true)
}
```

### sync

```go
// sync 方法用于定期续约租约和处理租约的逻辑。
func (c *controller) sync(ctx context.Context) {
	if c.latestLease != nil {
		// 只要租约没有被其他代理频繁更新（很少更新），我们可以乐观地认为自上次更新以来它没有改变，
		// 并尝试基于那个版本进行更新。这样可以避免进行 GET 调用并减少对 etcd 和 kube-apiserver 的负载。
		// 如果在某个时刻其他代理也频繁更新租约对象，这可能会导致性能下降，
		// 因为我们最终会调用额外的 GET/PUT 操作。在那个时候应该移除整个 "if" 语句。
		err := c.retryUpdateLease(ctx, c.latestLease)
		if err == nil {
			return
		}
		klog.FromContext(ctx).Info("使用最新的租约更新租约失败，回退到确保租约", "err", err)
	}

	lease, created := c.backoffEnsureLease(ctx)
	c.latestLease = lease
	// 只有在创建租约时才需要更新租约
	if !created && lease != nil {
		if err := c.retryUpdateLease(ctx, lease); err != nil {
			klog.FromContext(ctx).Error(err, "将重试更新租约", "interval", c.renewInterval)
		}
	}
}

```

### retryUpdateLease

````go
// retryUpdateLease 方法尝试为 maxUpdateRetries 次更新租约，
// 在确保租约已创建后调用此方法。
func (c *controller) retryUpdateLease(ctx context.Context, base *coordinationv1.Lease) error {
	for i := 0; i < maxUpdateRetries; i++ {
		leaseToUpdate, _ := c.newLease(base)
		lease, err := c.leaseClient.Update(ctx, leaseToUpdate, metav1.UpdateOptions{})
		if err == nil {
			c.latestLease = lease
			return nil
		}
		klog.FromContext(ctx).Error(err, "更新租约失败")
		// OptimisticLockError 要求获取更新的租约的较新版本。
		if apierrors.IsConflict(err) {
			base, _ = c.backoffEnsureLease(ctx)
			continue
		}
		if i > 0 && c.onRepeatedHeartbeatFailure != nil {
			c.onRepeatedHeartbeatFailure()
		}
	}
	return fmt.Errorf("尝试更新租约失败 %d 次", maxUpdateRetries)
}
````

#### newLease

```go
// newLease 方法根据基础租约构造一个新的租约，如果 base 为 nil，则创建一个新租约，
// 否则返回基于基础租约的副本，并在副本上断言所需的状态。
// 注意，错误会阻止租约创建，导致下一次迭代重试创建；
// 但错误不会阻止租约刷新（更新）。
func (c *controller) newLease(base *coordinationv1.Lease) (*coordinationv1.Lease, error) {
	// 使用最少的字段集；其他字段用于调试/遗留问题，但我们不需要使组件心跳更复杂。
	var lease *coordinationv1.Lease
	if base == nil {
		lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.leaseName,
				Namespace: c.leaseNamespace,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       pointer.StringPtr(c.holderIdentity),
				LeaseDurationSeconds: pointer.Int32Ptr(c.leaseDurationSeconds),
			},
		}
	} else {
		lease = base.DeepCopy()
	}
	lease.Spec.RenewTime = &metav1.MicroTime{Time: c.clock.Now()}

	if c.newLeasePostProcessFunc != nil {
		err := c.newLeasePostProcessFunc(lease)
		return lease, err
	}

	return lease, nil
}
```

#### backoffEnsureLease

```go
// backoffEnsureLease 方法用于在租约不存在时尝试创建租约，并使用指数增加的等待时间防止过多地重试请求 API 服务器。
// 返回租约对象以及一个 bool 值，表示此次调用是否创建了租约。
func (c *controller) backoffEnsureLease(ctx context.Context) (*coordinationv1.Lease, bool) {
	var (
		lease   coordinationv1.Lease
		created bool
		err     error
	)
	sleep := 100 * time.Millisecond
	for {
		lease, created, err = c.ensureLease(ctx)
		if err == nil {
			break
		}
		sleep = minDuration(2*sleep, maxBackoff)
		klog.FromContext(ctx).Error(err, "无法确保租约存在，将重试", "interval", sleep)
		// 如果上下文被取消，则立即返回
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(sleep):
		}
	}
	return lease, created
}
```

##### ensureLease

```go
// ensureLease 方法在租约不存在时创建租约。返回租约对象、一个 bool 值（表示此次调用是否创建了租约）和任何出现的错误。
func (c *controller) ensureLease(ctx context.Context) (*coordinationv1.Lease, bool, error) {
	lease, err := c.leaseClient.Get(ctx, c.leaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// 租约不存在，创建租约
		leaseToCreate, err := c.newLease(nil)
		// 在分配新租约时出错（可能是由于 newLeasePostProcessFunc 引起的），
		// 鉴于我们无法正确设置租约，这次不创建租约 - 我们将在下一次迭代中重试。
		if err != nil {
			return nil, false, nil
		}
		lease, err := c.leaseClient.Create(ctx, leaseToCreate, metav1.CreateOptions{})
		if err != nil {
			return nil, false, err
		}
		return lease, true, nil
	} else if err != nil {
		// 获取租约时发生意外错误
		return nil, false, err
	}
	// 租约已经存在
	return lease, false, nil
}
```

##### minDuration

```go
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
```

