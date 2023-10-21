##  简介

clientset是对rest client的封装，便于使用而且不易出错。

本文从create deployment 资源的代理分析一下原理。

## Interface

```GO
// Interface 接口定义了一组方法，用于访问不同 API 资源的接口
type Interface interface {
	Discovery() discovery.DiscoveryInterface // 访问 Discovery 接口
	AdmissionregistrationV1() admissionregistrationv1.AdmissionregistrationV1Interface // 访问 AdmissionregistrationV1 接口
	AdmissionregistrationV1alpha1() admissionregistrationv1alpha1.AdmissionregistrationV1alpha1Interface // 访问 AdmissionregistrationV1alpha1 接口
	AdmissionregistrationV1beta1() admissionregistrationv1beta1.AdmissionregistrationV1beta1Interface // 访问 AdmissionregistrationV1beta1 接口
	InternalV1alpha1() internalv1alpha1.InternalV1alpha1Interface // 访问 InternalV1alpha1 接口
	AppsV1() appsv1.AppsV1Interface // 访问 AppsV1 接口
	AppsV1beta1() appsv1beta1.AppsV1beta1Interface // 访问 AppsV1beta1 接口
	AppsV1beta2() appsv1beta2.AppsV1beta2Interface // 访问 AppsV1beta2 接口
	AuthenticationV1() authenticationv1.AuthenticationV1Interface // 访问 AuthenticationV1 接口
	AuthenticationV1alpha1() authenticationv1alpha1.AuthenticationV1alpha1Interface // 访问 AuthenticationV1alpha1 接口
	AuthenticationV1beta1() authenticationv1beta1.AuthenticationV1beta1Interface // 访问 AuthenticationV1beta1 接口
	AuthorizationV1() authorizationv1.AuthorizationV1Interface // 访问 AuthorizationV1 接口
	AuthorizationV1beta1() authorizationv1beta1.AuthorizationV1beta1Interface // 访问 AuthorizationV1beta1 接口
	AutoscalingV1() autoscalingv1.AutoscalingV1Interface // 访问 AutoscalingV1 接口
	AutoscalingV2() autoscalingv2.AutoscalingV2Interface // 访问 AutoscalingV2 接口
	AutoscalingV2beta1() autoscalingv2beta1.AutoscalingV2beta1Interface // 访问 AutoscalingV2beta1 接口
	AutoscalingV2beta2() autoscalingv2beta2.AutoscalingV2beta2Interface // 访问 AutoscalingV2beta2 接口
	BatchV1() batchv1.BatchV1Interface // 访问 BatchV1 接口
	BatchV1beta1() batchv1beta1.BatchV1beta1Interface // 访问 BatchV1beta1 接口
	CertificatesV1() certificatesv1.CertificatesV1Interface // 访问 CertificatesV1 接口
	CertificatesV1beta1() certificatesv1beta1.CertificatesV1beta1Interface // 访问 CertificatesV1beta1 接口
	CertificatesV1alpha1() certificatesv1alpha1.CertificatesV1alpha1Interface // 访问 CertificatesV1alpha1 接口
	CoordinationV1beta1() coordinationv1beta1.CoordinationV1beta1Interface // 访问 CoordinationV1beta1 接口
	CoordinationV1() coordinationv1.CoordinationV1Interface // 访问 CoordinationV1 接口
	CoreV1() corev1.CoreV1Interface // 访问 CoreV1 接口
	DiscoveryV1() discoveryv1.DiscoveryV1Interface // 访问 DiscoveryV1 接口
	DiscoveryV1beta1() discoveryv1beta1.DiscoveryV1beta1Interface // 访问 DiscoveryV1beta1 接口
	EventsV1() eventsv1.EventsV1Interface // 访问 EventsV1 接口
	EventsV1beta1() eventsv1beta1.EventsV1beta1Interface // 访问 EventsV1beta1 接口
	ExtensionsV1beta1() extensionsv1beta1.ExtensionsV1beta1Interface // 访问 ExtensionsV1beta1 接口
	FlowcontrolV1alpha1() flowcontrolv1alpha1.FlowcontrolV1alpha1Interface // 访问 FlowcontrolV1alpha1 接口
	FlowcontrolV1beta1() flowcontrolv1beta1.FlowcontrolV1beta1Interface // 访问 FlowcontrolV1beta1 接口
	FlowcontrolV1beta2() flowcontrolv1beta2.FlowcontrolV1beta2Interface // 访问 FlowcontrolV1beta2 接口
	FlowcontrolV1beta3() flowcontrolv1beta3.FlowcontrolV1beta3Interface // 访问 FlowcontrolV1beta3 接口
	NetworkingV1() networkingv1.NetworkingV1Interface // 访问 NetworkingV1 接口
	NetworkingV1alpha1() networkingv1alpha1.NetworkingV1alpha1Interface // 访问 NetworkingV1alpha1 接口
	NetworkingV1beta1() networkingv1beta1.NetworkingV1beta1Interface // 访问 NetworkingV1beta1 接口
	NodeV1() nodev1.NodeV1Interface // 访问 NodeV1 接口
	NodeV1alpha1() nodev1alpha1.NodeV1alpha1Interface // 访问 NodeV1alpha1 接口
	NodeV1beta1() nodev1beta1.NodeV1beta1Interface // 访问 NodeV1beta1 接口
	PolicyV1() policyv1.PolicyV1Interface // 访问 PolicyV1 接口
	PolicyV1beta1() policyv1beta1.PolicyV1beta1Interface // 访问 PolicyV1beta1 接口
	RbacV1() rbacv1.RbacV1Interface // 访问 RbacV1 接口
	RbacV1beta1() rbacv1beta1.RbacV1beta1Interface // 访问 RbacV1beta1 接口
	RbacV1alpha1() rbacv1alpha1.RbacV1alpha1Interface // 访问 RbacV1alpha1 接口
	ResourceV1alpha2() resourcev1alpha2.ResourceV1alpha2Interface // 访问 ResourceV1alpha2 接口
	SchedulingV1alpha1() schedulingv1alpha1.SchedulingV1alpha1Interface // 访问 SchedulingV1alpha1 接口
	SchedulingV1beta1() schedulingv1beta1.SchedulingV1beta1Interface // 访问 SchedulingV1beta1 接口
	SchedulingV1() schedulingv1.SchedulingV1Interface // 访问 SchedulingV1 接口
	StorageV1beta1() storagev1beta1.StorageV1beta1Interface // 访问 StorageV1beta1 接口
	StorageV1() storagev1.StorageV1Interface // 访问 StorageV1 接口
	StorageV1alpha1() storagev1alpha1.StorageV1alpha1Interface // 访问 StorageV1alpha1 接口
}
```

## Clientset

```GO
// Clientset contains the clients for groups.
type Clientset struct {
// ...
}
```

### AppsV1

deployment 资源在 V1 group 下

```GO
// AppsV1 retrieves the AppsV1Client
func (c *Clientset) AppsV1() appsv1.AppsV1Interface {
	return c.appsV1
}
```

## AppsV1Interface

查看 DeploymentInterface 客户端

```GO
type AppsV1Interface interface {
	RESTClient() rest.Interface
	ControllerRevisionsGetter
	DaemonSetsGetter
	DeploymentsGetter
	ReplicaSetsGetter
	StatefulSetsGetter
}

// AppsV1Client用于与apps组提供的功能进行交互。
type AppsV1Client struct {
	restClient rest.Interface
}
func (c *AppsV1Client) Deployments(namespace string) DeploymentInterface {
	return newDeployments(c, namespace)
}
```

## DeploymentInterface

```GO
// DeploymentsGetter拥有返回DeploymentInterface的方法。
// 一个API组的客户端应该实现这个接口。
type DeploymentsGetter interface {
	Deployments(namespace string) DeploymentInterface
}

// DeploymentInterface拥有操作Deployment资源的方法。
type DeploymentInterface interface {
	Create(ctx context.Context, deployment *v1.Deployment, opts metav1.CreateOptions) (*v1.Deployment, error)
	Update(ctx context.Context, deployment *v1.Deployment, opts metav1.UpdateOptions) (*v1.Deployment, error)
	UpdateStatus(ctx context.Context, deployment *v1.Deployment, opts metav1.UpdateOptions) (*v1.Deployment, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.Deployment, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.DeploymentList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Deployment, err error)
	Apply(ctx context.Context, deployment *appsv1.DeploymentApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Deployment, err error)
	ApplyStatus(ctx context.Context, deployment *appsv1.DeploymentApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Deployment, err error)
	GetScale(ctx context.Context, deploymentName string, options metav1.GetOptions) (*autoscalingv1.Scale, error)
	UpdateScale(ctx context.Context, deploymentName string, scale *autoscalingv1.Scale, opts metav1.UpdateOptions) (*autoscalingv1.Scale, error)
	ApplyScale(ctx context.Context, deploymentName string, scale *applyconfigurationsautoscalingv1.ScaleApplyConfiguration, opts metav1.ApplyOptions) (*autoscalingv1.Scale, error)

	DeploymentExpansion
}
```

### deployments

```GO
// deployments实现了DeploymentInterface
type deployments struct {
	client rest.Interface
	ns     string
}

// newDeployments返回一个Deployments
func newDeployments(c *AppsV1Client, namespace string) *deployments {
	return &deployments{
		client: c.RESTClient(),
		ns:     namespace,
	}
}
```

### Create

```GO
// Create takes the representation of a deployment and creates it.  Returns the server's representation of the deployment, and an error, if there is any.
func (c *deployments) Create(ctx context.Context, deployment *v1.Deployment, opts metav1.CreateOptions) (result *v1.Deployment, err error) {
	result = &v1.Deployment{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("deployments").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(deployment).
		Do(ctx).
		Into(result)
	return
}
```

