---
id: 11-kube-controller-code
title: clusterroleaggregation-controller 代码走读
description: clusterroleaggregation-controller 代码走读
keywords:
  - kubernetes
  - kube-controller
slug: /
---

## 简介

聚合多个 ClusterRole 以创建一个新的 ClusterRole，该 ClusterRole 包含多个其他 ClusterRole 的权限。这样，我们可以轻松地将多个角色的权限合并到一个角色中，从而简化了访问控制的管理。

## 结构体

```GO
type ClusterRoleAggregationController struct {
    // 从 Kubernetes API Server 中获取 ClusterRole 资源对象的客户端
	clusterRoleClient  rbacclient.ClusterRolesGetter
    // 缓存 ClusterRole 资源对象并支持查询操作的 Lister 接口
	clusterRoleLister  rbaclisters.ClusterRoleLister
    // 检查是否同步完成
	clusterRolesSynced cache.InformerSynced
	
    // 在 ClusterRole 资源对象被更新时触发的处理函数，用于处理 ClusterRole 资源对象的更新操作
	syncHandler func(ctx context.Context, key string) error
    // ClusterRole 资源对象的队列
	queue       workqueue.RateLimitingInterface
}
```

## New

```GO
func NewClusterRoleAggregation(clusterRoleInformer rbacinformers.ClusterRoleInformer, clusterRoleClient rbacclient.ClusterRolesGetter) *ClusterRoleAggregationController {
	c := &ClusterRoleAggregationController{
		clusterRoleClient:  clusterRoleClient,
		clusterRoleLister:  clusterRoleInformer.Lister(),
		clusterRolesSynced: clusterRoleInformer.Informer().HasSynced,

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ClusterRoleAggregator"),
	}
	c.syncHandler = c.syncClusterRole
	
    // 监控clusterRole 在add update delete时执行enqueue
	clusterRoleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.enqueue()
		},
		UpdateFunc: func(old, cur interface{}) {
			c.enqueue()
		},
		DeleteFunc: func(uncast interface{}) {
			c.enqueue()
		},
	})
	return c
}
```

### enqueue

```GO
func (c *ClusterRoleAggregationController) enqueue() {
	// 从lister拿所有的ClusterRole
	allClusterRoles, err := c.clusterRoleLister.List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't list all objects %v", err))
		return
	}
    // 便利allClusterRoles
	for _, clusterRole := range allClusterRoles {
		//  clusterRole.AggregationRule == nil 意味着这个clusterRole资源不允许聚合 跳过
		if clusterRole.AggregationRule == nil {
			continue
		}
        // 拿出key 加入队列
		key, err := controller.KeyFunc(clusterRole)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %#v: %v", clusterRole, err))
			return
		}
		c.queue.Add(key)
	}
}
```

### syncClusterRole

```GO
func (c *ClusterRoleAggregationController) syncClusterRole(ctx context.Context, key string) error {
    // 从key中获取name
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
    // 从lister获取ClusterRole
	sharedClusterRole, err := c.clusterRoleLister.Get(name)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
    // 如果不是聚合的资源 直接返回nil
	if sharedClusterRole.AggregationRule == nil {
		return nil
	}

	newPolicyRules := []rbacv1.PolicyRule{}
    // 获取符合选择器条件的 ClusterRole 资源对象的集合，并对集合按名称进行排序
	for i := range sharedClusterRole.AggregationRule.ClusterRoleSelectors {
		selector := sharedClusterRole.AggregationRule.ClusterRoleSelectors[i]
		runtimeLabelSelector, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil {
			return err
		}
		clusterRoles, err := c.clusterRoleLister.List(runtimeLabelSelector)
		if err != nil {
			return err
		}
		sort.Sort(byName(clusterRoles))
		
        // 遍历集合中的 ClusterRole 资源对象，将它们的规则合并到一个新的策略规则中
		for i := range clusterRoles {
			if clusterRoles[i].Name == sharedClusterRole.Name {
				continue
			}

			for j := range clusterRoles[i].Rules {
				currRule := clusterRoles[i].Rules[j]
                // 如果新的不存在这个 加进去
				if !ruleExists(newPolicyRules, currRule) {
					newPolicyRules = append(newPolicyRules, currRule)
				}
			}
		}
	}
	
    // 比较新的策略规则和原有的策略规则是否相等，如果相等则直接返回
	if equality.Semantic.DeepEqual(newPolicyRules, sharedClusterRole.Rules) {
		return nil
	}
	
    // 更新新的ClusterRole对象
	err = c.applyClusterRoles(ctx, sharedClusterRole.Name, newPolicyRules)
	if errors.IsUnsupportedMediaType(err) { // TODO: Remove this fallback at least one release after ServerSideApply GA
		// When Server Side Apply is not enabled, fallback to Update. This is required when running
		// 1.21 since api-server can be 1.20 during the upgrade/downgrade.
		// Since Server Side Apply is enabled by default in Beta, this fallback only kicks in
		// if the feature has been disabled using its feature flag.
        // 如果apply出问题 update
		err = c.updateClusterRoles(ctx, sharedClusterRole, newPolicyRules)
	}
	return err
}
```

```go
type byName []*rbacv1.ClusterRole

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name < a[j].Name }
```

#### ruleExists

```GO
// 看needle在不在haystack中
func ruleExists(haystack []rbacv1.PolicyRule, needle rbacv1.PolicyRule) bool {
	for _, curr := range haystack {
		if equality.Semantic.DeepEqual(curr, needle) {
			return true
		}
	}
	return false
}

```

#### applyClusterRoles

```GO
func (c *ClusterRoleAggregationController) applyClusterRoles(ctx context.Context, name string, newPolicyRules []rbacv1.PolicyRule) error {
    // 把newPolicyRules转换成PolicyRuleApplyConfiguration对象 并加入到ClusterRole中
	clusterRoleApply := rbacv1ac.ClusterRole(name).
		WithRules(toApplyPolicyRules(newPolicyRules)...)
	
    // 设置opts 标识修改者并开启强制操作
	opts := metav1.ApplyOptions{FieldManager: "clusterrole-aggregation-controller", Force: true}
    // 执行apply
	_, err := c.clusterRoleClient.ClusterRoles().Apply(ctx, clusterRoleApply, opts)
	return err
}

// 把PolicyRules转换成PolicyRuleApplyConfigurations
func toApplyPolicyRules(rules []rbacv1.PolicyRule) []*rbacv1ac.PolicyRuleApplyConfiguration {
	var result []*rbacv1ac.PolicyRuleApplyConfiguration
	for _, rule := range rules {
		result = append(result, toApplyPolicyRule(rule))
	}
	return result
}

// 把PolicyRule转换成PolicyRuleApplyConfiguration
func toApplyPolicyRule(rule rbacv1.PolicyRule) *rbacv1ac.PolicyRuleApplyConfiguration {
	result := rbacv1ac.PolicyRule()
	result.Resources = rule.Resources
	result.ResourceNames = rule.ResourceNames
	result.APIGroups = rule.APIGroups
	result.NonResourceURLs = rule.NonResourceURLs
	result.Verbs = rule.Verbs
	return result
}
```

#### updateClusterRoles

```GO
func (c *ClusterRoleAggregationController) updateClusterRoles(ctx context.Context, sharedClusterRole *rbacv1.ClusterRole, newPolicyRules []rbacv1.PolicyRule) error {
    // 把newPolicyRules的rules加入到sharedClusterRole中 并更新
	clusterRole := sharedClusterRole.DeepCopy()
	clusterRole.Rules = nil
	for _, rule := range newPolicyRules {
		clusterRole.Rules = append(clusterRole.Rules, *rule.DeepCopy())
	}
	_, err := c.clusterRoleClient.ClusterRoles().Update(ctx, clusterRole, metav1.UpdateOptions{})
	return err
}
```

## Run

```go
func (c *ClusterRoleAggregationController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting ClusterRoleAggregator")
	defer klog.Infof("Shutting down ClusterRoleAggregator")

	if !cache.WaitForNamedCacheSync("ClusterRoleAggregator", ctx.Done(), c.clusterRolesSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	<-ctx.Done()
}
```

## runWorker

```go
func (c *ClusterRoleAggregationController) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *ClusterRoleAggregationController) processNextWorkItem(ctx context.Context) bool {
    // 获取key
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)
	
    // 调用syncHandler处理 处理完成Forget key 错误了 把key重新加入重试队列
	err := c.syncHandler(ctx, dsKey.(string))
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}
```

