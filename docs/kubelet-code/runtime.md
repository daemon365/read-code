---
id: 5-kubelet-code 
title: container runtime 代码走读
description: container runtime 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## container.Runtime

```GO
// Runtime接口定义了容器运行时应该实现的接口。
// 实现该接口的类必须是线程安全的。
type Runtime interface {
    // Type返回容器运行时的类型。
    Type() string
    // Version返回容器运行时的版本信息。
    Version(ctx context.Context) (Version, error)

    // APIVersion返回容器运行时的缓存的API版本信息。
    // 实现应该定期更新此缓存。
    // 这可能与运行时引擎的版本不同。
    // TODO(random-liu): 应该将此方法合并到Version()中
    APIVersion() (Version, error)

    // Status返回运行时的状态。如果Status函数本身失败，则返回错误；否则返回nil。
    Status(ctx context.Context) (*RuntimeStatus, error)

    // GetPods返回按照Pod分组的容器列表。布尔参数指定运行时是否返回所有容器，包括已经退出和死亡的容器（用于垃圾回收）。
    GetPods(ctx context.Context, all bool) ([]*Pod, error)

    // GarbageCollect使用指定的容器垃圾回收策略删除死亡容器。
    // 如果allSourcesReady不为true，表示kubelet尚未从所有可用源（例如apiserver、http、文件）获取到完整的Pod列表。
    // 在这种情况下，垃圾收集器应该避免过于激进的行为，例如删除所有未识别Pod的容器。
    // 如果evictNonDeletedPods设置为true，将逐出属于已终止但尚未删除的Pod的容器和 sandbox 。否则，只会回收已删除的Pod。
    // TODO: 重新审视此方法并使其更清晰。
    GarbageCollect(ctx context.Context, gcPolicy GCPolicy, allSourcesReady bool, evictNonDeletedPods bool) error

    // SyncPod将正在运行的Pod与期望的Pod进行同步。
    SyncPod(ctx context.Context, pod *v1.Pod, podStatus *PodStatus, pullSecrets []v1.Secret, backOff *flowcontrol.Backoff) PodSyncResult

    // KillPod终止Pod的所有容器。Pod可能为nil，但运行中的Pod不能为nil。
    // TODO(random-liu): 在KillPod中返回PodSyncResult。
    // 如果指定了gracePeriodOverride，允许调用方覆盖Pod的默认优雅期限。
    // 仅允许硬终止路径在kubelet中指定gracePeriodOverride，以避免破坏用户数据。
    // 在硬终止场景（例如SIGKILL）或软终止场景（例如最大优雅期限）下使用时很有用。
    KillPod(ctx context.Context, pod *v1.Pod, runningPod Pod, gracePeriodOverride *int64) error

    // GetPodStatus检索Pod的状态，包括在运行时中可见的所有容器的信息。
    GetPodStatus(ctx context.Context, uid types.UID, name, namespace string) (*PodStatus, error)

    // TODO(vmarmol): 统一pod和containerID参数。
    // GetContainerLogs返回特定容器的日志。默认情况下，它返回容器日志的快照。
    // 将'follow'设置为true以流式传输日志。将'follow'设置为false并指定行数（例如"100"或"all"）以获取日志的末尾部分。
    GetContainerLogs(ctx context.Context, pod *v1.Pod, containerID ContainerID, logOptions *v1.PodLogOptions, stdout, stderr io.Writer) (err error)

    // DeleteContainer删除容器。如果容器仍在运行，则返回错误。
    DeleteContainer(ctx context.Context, containerID ContainerID) error

    // ImageService提供与镜像相关的方法。
    ImageService

    // UpdatePodCIDR向运行时发送新的podCIDR。
    // 此方法仅将带有更新后的CIDR值的新runtimeConfig代理到运行时shim。
    UpdatePodCIDR(ctx context.Context, podCIDR string) error

    // CheckpointContainer告知运行时对容器进行检查点，并将生成的存档存储到检查点目录中。
    CheckpointContainer(ctx context.Context, options *runtimeapi.CheckpointContainerRequest) error

    // 从CRI事件生成Pod的状态
    GeneratePodStatus(event *runtimeapi.ContainerEventResponse) (*PodStatus, error)

    // ListMetricDescriptors获取将在ListPodSandboxMetrics中返回的指标的描述符。
    // 此列表在启动时应该是静态的：如果在初始的ListMetricDescriptors调用中引用了一个名称，但在ListPodSandboxMetrics调用中未描述，那么该指标将不会被广播。
    ListMetricDescriptors(ctx context.Context) ([]*runtimeapi.MetricDescriptor, error)

    // ListPodSandboxMetrics检索所有Pod sandbox 的指标。
    ListPodSandboxMetrics(ctx context.Context) ([]*runtimeapi.PodSandboxMetrics, error)
}
```

### Version

```GO
// Version接口允许比较和格式化运行时版本。
type Version interface {
    // Compare比较两个运行时版本。成功时，如果版本小于另一个版本，则返回-1；如果版本大于另一个版本，则返回1；如果它们相等，则返回0。
    Compare(other string) (int, error)

    // String返回表示版本的字符串。
    String() string
}
```

### RuntimeStatus

```GO
// RuntimeStatus包含运行时的状态。
type RuntimeStatus struct {
    // Conditions是当前观察到的运行时条件数组。
    Conditions []RuntimeCondition
}

// GetRuntimeCondition从运行时状态中获取指定的运行时条件。
func (r *RuntimeStatus) GetRuntimeCondition(t RuntimeConditionType) *RuntimeCondition {
    for i := range r.Conditions {
        c := &r.Conditions[i]
        if c.Type == t {
            return c
        }
    }
    return nil
}

// String将运行时状态格式化为可读的字符串。
func (r *RuntimeStatus) String() string {
    var ss []string
    for _, c := range r.Conditions {
    	ss = append(ss, c.String())
    }
    return fmt.Sprintf("Runtime Conditions: %s", strings.Join(ss, ", "))
}
```

#### RuntimeConditionType

```GO
// RuntimeConditionType是所需运行时条件的类型。
type RuntimeConditionType string

const (
    // RuntimeReady表示运行时已启动并准备好接受基本容器。
    RuntimeReady RuntimeConditionType = "RuntimeReady"
    // NetworkReady表示运行时网络已启动并准备好接受需要网络的容器。
    NetworkReady RuntimeConditionType = "NetworkReady"
)
```

### Pod

```GO
// Pod是一组容器。
type Pod struct {
    // Pod的ID，可用于从GetPods()返回的Pod列表中检索特定的Pod。
    ID types.UID
    // Pod的名称和命名空间，可供人类阅读。
    Name string
    Namespace string
    // Pod的创建时间戳，以纳秒为单位。
    CreatedAt uint64
    // 属于此Pod的容器列表。它可能只包含运行中的容器，也可能与死亡容器混合（当GetPods（true）时）。
    Containers []*Container
    // 与此Pod关联的 sandbox 列表。为了避免对其他组件造成重大更改， sandbox 被临时转换为容器。这仅由kuberuntime填充。
    // TODO: 直接使用runtimeApi.PodSandbox类型。
    Sandboxes []*Container
}
```

### Container

```GO
// Container提供容器的运行时信息，例如ID、哈希、容器状态。
type Container struct {
    // 容器的ID，由容器运行时用于标识容器。
    ID ContainerID
    // 容器的名称，应与v1.Container中指定的名称相同。
    Name string
    // 容器的映像名称，包括映像的标签，预期的形式是"NAME:TAG"。
    Image string
    // 容器使用的映像的ID。
    ImageID string
    // 容器的哈希，用于比较。对于不由kubelet管理的容器是可选的。
    Hash uint64
    // 将Resources字段零化后的容器哈希。注意：这在alpha和beta版本中是必需的，这样在切换InPlacePodVerticalScaling功能时，使用资源的容器不会意外重新启动。
    // TODO（vinaykul，InPlacePodVerticalScaling）：在GA+1中删除此项，并使HashWithoutResources成为Hash。
    HashWithoutResources uint64
    // 容器的状态。
    State State
}
```

#### ContainerID

```GO
// ContainerID是标识容器的类型。
type ContainerID struct {
    // 容器运行时的类型，例如'docker'。
    Type string
    // 容器的标识，可以由底层容器运行时使用。（注意，容器运行时接口仍然将整个结构体作为输入。）
    ID string
}

// BuildContainerID根据类型和ID返回ContainerID。
func BuildContainerID(typ, ID string) ContainerID {
	return ContainerID{Type: typ, ID: ID}
}

// ParseContainerID是一个方便的方法，用于从ID字符串创建ContainerID。
func ParseContainerID(containerID string) ContainerID {
	var id ContainerID
	if err := id.ParseString(containerID); err != nil {
		klog.ErrorS(err, "Parsing containerID failed")
	}
	return id
}

// ParseString将给定的字符串转换为ContainerID。
func (c *ContainerID) ParseString(data string) error {
	// 去除引号并拆分类型和ID。
	parts := strings.Split(strings.Trim(data, "\""), "://")
	if len(parts) != 2 {
		return fmt.Errorf("invalid container ID: %q", data)
	}
	c.Type, c.ID = parts[0], parts[1]
	return nil
}

func (c *ContainerID) String() string {
	return fmt.Sprintf("%s://%s", c.Type, c.ID)
}

// IsEmpty返回给定的ContainerID是否为空。
func (c *ContainerID) IsEmpty() bool {
	return *c == ContainerID{}
}

// MarshalJSON将给定的ContainerID格式化为字节数组。
func (c *ContainerID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", c.String())), nil
}

// UnmarshalJSON从给定的字节数组中解析ContainerID。
func (c *ContainerID) UnmarshalJSON(data []byte) error {
	return c.ParseString(string(data))
}
```

#### Status

```GO
// Status表示容器的状态。
type Status struct {
	// 容器的ID。
	ID ContainerID
	// 容器的名称。
	Name string
	// 容器的状态。
	State State
	// 容器的创建时间。
	CreatedAt time.Time
	// 容器的启动时间。
	StartedAt time.Time
	// 容器的结束时间。
	FinishedAt time.Time
	// 容器的退出码。
	ExitCode int
	// 映像的名称，也包括映像的标签，预期的形式是"NAME:TAG"。
	Image string
	// 映像的ID。
	ImageID string
	// 容器的哈希，用于比较。
	Hash uint64
	// 不包括Resources字段的容器哈希。
	HashWithoutResources uint64
	// 容器重新启动的次数。
	RestartCount int
	// 解释容器处于此状态的字符串。
	Reason string
	// 容器退出之前由容器写入的消息（存储在TerminationMessagePath中）。
	Message string
	// 分配给此容器的CPU和内存资源。
	Resources *ContainerResources
}

// ContainerResources表示分配给运行中容器的资源。
type ContainerResources struct {
	// 为容器预留的CPU容量。
	CPURequest *resource.Quantity
	// 对容器施加的CPU限制。
	CPULimit *resource.Quantity
	// 为容器预留的内存容量。
	MemoryRequest *resource.Quantity
	// 对容器施加的内存限制。
	MemoryLimit *resource.Quantity
}
```

### GCPolicy

```GO
// GCPolicy指定容器垃圾回收的策略。
type GCPolicy struct {
    // 容器可以进行垃圾回收的最小年龄，零表示没有限制。
    MinAge time.Duration

    // 单个Pod（UID、容器名称）对允许拥有的死亡容器的最大数量，小于零表示没有限制。
    MaxPerPodContainer int

    // 总的死亡容器的最大数量，小于零表示没有限制。
    MaxContainers int
}
```

### PodStatus

```GO
// PodStatus表示Pod及其容器的状态。
// v1.PodStatus可以通过检查PodStatus和v1.Pod来推导得到。
type PodStatus struct {
	// Pod的ID。
	ID types.UID
	// Pod的名称。
	Name string
	// Pod的命名空间。
	Namespace string
	// 分配给此Pod的所有IP地址。
	IPs []string
	// Pod中容器的状态。
	ContainerStatuses []*Status
	// Pod沙盒的状态。
	// 目前仅适用于kuberuntime，其他运行时可能保持为nil。
	SandboxStatuses []*runtimeapi.PodSandboxStatus
	// 记录容器和Pod状态的时间戳。
	TimeStamp time.Time
}
```





### ImageService

```GO
// ImageService接口允许与镜像服务进行交互。
type ImageService interface {
	// PullImage从网络拉取 image 到本地存储，并在必要时使用提供的凭据（secrets）。
	// 它返回拉取的 image 的引用（摘要或ID）。
	PullImage(ctx context.Context, image ImageSpec, pullSecrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, error)
	// GetImageRef获取已经存在于本地存储中的 image 的引用（摘要或ID）。
	// 如果 image 不在本地存储中，则返回("", nil)。
	GetImageRef(ctx context.Context, image ImageSpec) (string, error)
	// ListImages获取当前机器上的所有 image 。
	ListImages(ctx context.Context) ([]Image, error)
	// RemoveImage删除指定的 image 。
	RemoveImage(ctx context.Context, image ImageSpec) error
	// ImageStats返回 image 的统计信息。
	ImageStats(ctx context.Context) (*ImageStats, error)
}
```

#### ImageSpec

```GO
// ImageSpec是 image 的内部表示方式。目前，它包装了容器的Image字段的值，
// 但将来将包含关于不同 image 类型的更详细的信息。
type ImageSpec struct {
    //  image 的ID。
    Image string
    //  image 的注释。
    // 在进行 image 拉取时应传递给CRI，并在列出 image 时返回。
    Annotations []Annotation
}

// Annotation表示注释。
type Annotation struct {
    Name string
    Value string
}
```

#### Image

```GO
// Image包含关于容器镜像的基本信息。
type Image struct {
    //  image 的ID。
    ID string
    // 此 image 已知的其他名称。
    RepoTags []string
    // 此 image 已知的摘要。
    RepoDigests []string
    //  image 的大小（以字节为单位）。
    Size int64
    // 包含 image 规范的ImageSpec，其中包括注释。
    Spec ImageSpec
    // 防止垃圾回收的固定值。
    Pinned bool
}
```

#### ImageStats

```GO
// ImageStats包含有关当前可用 image 的统计信息。
type ImageStats struct {
    // 现有 image 消耗的总存储量。
    TotalStorageBytes uint64
}
```

### StreamingRuntime

```go
// StreamingRuntime是由处理流式调用（exec/attach/port-forward）的运行时实现的接口。
// 在这种情况下，Kubelet应该重定向到运行时服务器。
type StreamingRuntime interface {
	GetExec(ctx context.Context, id ContainerID, cmd []string, stdin, stdout, stderr, tty bool) (*url.URL, error)
	GetAttach(ctx context.Context, id ContainerID, stdin, stdout, stderr, tty bool) (*url.URL, error)
	GetPortForward(ctx context.Context, podName, podNamespace string, podUID types.UID, ports []int32) (*url.URL, error)
}
```

### Attacher

```go
// Attacher接口允许附加容器。
type Attacher interface {
	AttachContainer(ctx context.Context, id ContainerID, stdin io.Reader, stdout, stderr io.WriteCloser, tty bool, resize <-chan remotecommand.TerminalSize) (err error)
}
```

### CommandRunner

```go
// CommandRunner接口允许在容器中运行命令。
type CommandRunner interface {
	// RunInContainer在容器中同步执行命令，并返回输出。
	// 如果命令以非零的退出代码完成，将返回k8s.io/utils/exec.ExitError。
	RunInContainer(ctx context.Context, id ContainerID, cmd []string, timeout time.Duration) ([]byte, error)
}
```

## cri

cri是使用protobuf定义 使用gprc协议kubelet调用本地实现这个协议的容器管理器，比如containerd, podman等

### RuntimeService

```GO
// Runtime service定义了远程容器运行时的公共API
service RuntimeService {
    // Version返回运行时的名称、版本和API版本
    rpc Version(VersionRequest) returns (VersionResponse) {}
    // RunPodSandbox创建并启动一个Pod级别的沙盒。运行时必须确保沙盒在成功时处于就绪状态。
    rpc RunPodSandbox(RunPodSandboxRequest) returns (RunPodSandboxResponse) {}

    // StopPodSandbox停止沙盒中的任何正在运行的进程，并回收分配给沙盒的网络资源（例如IP地址）。
    // 如果沙盒中有任何正在运行的容器，则必须强制终止它们。
    // 这个调用是幂等的，如果所有相关资源都已经被回收，不应该返回错误。kubelet将在调用RemovePodSandbox之前至少调用一次StopPodSandbox。
    // 它还会尽早地尝试回收资源，一旦沙盒不再需要。因此，预计会有多个StopPodSandbox调用。
    rpc StopPodSandbox(StopPodSandboxRequest) returns (StopPodSandboxResponse) {}

    // RemovePodSandbox删除沙盒。如果沙盒中有任何正在运行的容器，则必须强制删除容器。
    // 这个调用是幂等的，如果沙盒已经被删除，不应该返回错误。
    rpc RemovePodSandbox(RemovePodSandboxRequest) returns (RemovePodSandboxResponse) {}

    // PodSandboxStatus返回PodSandbox的状态。如果PodSandbox不存在，则返回错误。
    rpc PodSandboxStatus(PodSandboxStatusRequest) returns (PodSandboxStatusResponse) {}

    // ListPodSandbox返回PodSandbox的列表。
    rpc ListPodSandbox(ListPodSandboxRequest) returns (ListPodSandboxResponse) {}

    // CreateContainer在指定的PodSandbox中创建一个新的容器
    rpc CreateContainer(CreateContainerRequest) returns (CreateContainerResponse) {}

    // StartContainer启动容器。
    rpc StartContainer(StartContainerRequest) returns (StartContainerResponse) {}

    // StopContainer使用优雅期限（超时）停止运行中的容器。
    // 这个调用是幂等的，如果容器已经停止，不应该返回错误。
    // 在优雅期限达到后，运行时必须强制杀死容器。
    rpc StopContainer(StopContainerRequest) returns (StopContainerResponse) {}

    // RemoveContainer删除容器。如果容器正在运行，容器必须被强制删除。
    // 这个调用是幂等的，如果容器已经被删除，不应该返回错误。
    rpc RemoveContainer(RemoveContainerRequest) returns (RemoveContainerResponse) {}

    // ListContainers按过滤器列出所有容器。
    rpc ListContainers(ListContainersRequest) returns (ListContainersResponse) {}

    // ContainerStatus返回容器的状态。如果容器不存在，则返回错误。
    rpc ContainerStatus(ContainerStatusRequest) returns (ContainerStatusResponse) {}

    // UpdateContainerResources同步更新容器的ContainerConfig。
    // 如果运行时无法事务性地更新请求的资源，将返回错误。
    rpc UpdateContainerResources(UpdateContainerResourcesRequest) returns (UpdateContainerResourcesResponse) {}

    // ReopenContainerLog请求运行时重新打开容器的stdout/stderr日志文件。
    // 这通常在日志文件轮转后调用。如果容器未运行，容器运行时可以选择创建一个新的日志文件并返回nil，或者返回一个错误。
    // 一旦它返回错误，就不得创建新的容器日志文件。
    rpc ReopenContainerLog(ReopenContainerLogRequest) returns (ReopenContainerLogResponse) {}

    // ExecSync在容器中同步运行命令。
    rpc ExecSync(ExecSyncRequest) returns (ExecSyncResponse) {}

    // Exec准备一个流式执行容器中命令的端点。
    rpc Exec(ExecRequest) returns (ExecResponse) {}

    // Attach准备一个流式附加到正在运行的容器的端点。
    rpc Attach(AttachRequest) returns (AttachResponse) {}

    // PortForward准备一个流式转发从PodSandbox的端口。
    rpc PortForward(PortForwardRequest) returns (PortForwardResponse) {}

    // ContainerStats返回容器的统计信息。如果容器不存在，则调用返回错误。
    rpc ContainerStats(ContainerStatsRequest) returns (ContainerStatsResponse) {}

    // ListContainerStats返回所有运行容器的统计信息。
    rpc ListContainerStats(ListContainerStatsRequest) returns (ListContainerStatsResponse) {}

    // PodSandboxStats返回PodSandbox的统计信息。如果PodSandbox不存在，则调用返回错误。
    rpc PodSandboxStats(PodSandboxStatsRequest) returns (PodSandboxStatsResponse) {}

    // ListPodSandboxStats返回与过滤器匹配的PodSandbox的统计信息。
    rpc ListPodSandboxStats(ListPodSandboxStatsRequest) returns (ListPodSandboxStatsResponse) {}

    // UpdateRuntimeConfig根据给定的请求更新运行时配置。
    rpc UpdateRuntimeConfig(UpdateRuntimeConfigRequest) returns (UpdateRuntimeConfigResponse) {}

    // Status返回运行时的状态。
    rpc Status(StatusRequest) returns (StatusResponse) {}

    // CheckpointContainer检查点容器
    rpc CheckpointContainer(CheckpointContainerRequest) returns (CheckpointContainerResponse) {}

    // GetContainerEvents从CRI运行时获取容器事件
    rpc GetContainerEvents(GetEventsRequest) returns (stream ContainerEventResponse) {}

    // ListMetricDescriptors获取将在ListPodSandboxMetrics中返回的指标描述符。
    // 这个列表应该在启动时是静态的:当添加或删除指标描述符时，客户端和服务器应该一起重新启动，
    // 或者它们不应该改变。换句话说，如果ListPodSandboxMetrics引用了初始ListMetricDescriptors调用中没有描述的名称，
    // 那么该指标将不会被广播。
    rpc ListMetricDescriptors(ListMetricDescriptorsRequest) returns (ListMetricDescriptorsResponse) {}

    // ListPodSandboxMetrics从CRI Runtime获取PodSandbox的指标
    rpc ListPodSandboxMetrics(ListPodSandboxMetricsRequest) returns (ListPodSandboxMetricsResponse) {}
}
```

### ImageService

```GO
// ImageService定义了管理 image 的公共API。
service ImageService {
    // ListImages列出现有的 image 。
    rpc ListImages(ListImagesRequest) returns (ListImagesResponse) {}
    // ImageStatus返回 image 的状态。如果 image 不存在，则返回一个具有ImageStatusResponse.Image设置为nil的响应。
    rpc ImageStatus(ImageStatusRequest) returns (ImageStatusResponse) {}
    // PullImage使用身份验证配置拉取 image 。
    rpc PullImage(PullImageRequest) returns (PullImageResponse) {}
    // RemoveImage删除 image 。
    // 此调用是幂等的，如果 image 已经被删除，不能返回错误。
    rpc RemoveImage(RemoveImageRequest) returns (RemoveImageResponse) {}
    // ImageFSInfo返回用于存储 image 的文件系统的信息。
    rpc ImageFsInfo(ImageFsInfoRequest) returns (ImageFsInfoResponse) {}
}
```

### RuntimeService

```go
// RuntimeService接口应由容器运行时实现。
// 这些方法应是线程安全的。
type RuntimeService interface {
	RuntimeVersioner
	ContainerManager
	PodSandboxManager
	ContainerStatsManager

	// UpdateRuntimeConfig更新运行时配置（如果指定了）。
	UpdateRuntimeConfig(ctx context.Context, runtimeConfig *runtimeapi.RuntimeConfig) error
	// Status返回运行时的状态。
	Status(ctx context.Context, verbose bool) (*runtimeapi.StatusResponse, error)
}
```

#### RuntimeVersioner

```go
// RuntimeVersioner包含运行时名称、版本和API版本的方法。
type RuntimeVersioner interface {
	// Version返回运行时的名称、版本和API版本
	Version(ctx context.Context, apiVersion string) (*runtimeapi.VersionResponse, error)
}
```

#### ContainerManager

```go
// ContainerManager包含用于操作由容器运行时管理的容器的方法。这些方法是线程安全的。
type ContainerManager interface {
	// CreateContainer在指定的PodSandbox中创建一个新的容器。
	CreateContainer(ctx context.Context, podSandboxID string, config *runtimeapi.ContainerConfig, sandboxConfig *runtimeapi.PodSandboxConfig) (string, error)
	// StartContainer启动容器。
	StartContainer(ctx context.Context, containerID string) error
	// StopContainer停止正在运行的容器，并使用宽限期（即超时时间）。
	StopContainer(ctx context.Context, containerID string, timeout int64) error
	// RemoveContainer移除容器。
	RemoveContainer(ctx context.Context, containerID string) error
	// ListContainers按过滤器列出所有容器。
	ListContainers(ctx context.Context, filter *runtimeapi.ContainerFilter) ([]*runtimeapi.Container, error)
	// ContainerStatus返回容器的状态。
	ContainerStatus(ctx context.Context, containerID string, verbose bool) (*runtimeapi.ContainerStatusResponse, error)
	// UpdateContainerResources同步更新容器的ContainerConfig。
	// 如果运行时无法事务性地更新请求的资源，则返回错误。
	UpdateContainerResources(ctx context.Context, containerID string, resources *runtimeapi.ContainerResources) error
	// ExecSync在容器中执行命令，并返回stdout输出。
	// 如果命令以非零退出代码退出，则返回错误。
	ExecSync(ctx context.Context, containerID string, cmd []string, timeout time.Duration) (stdout []byte, stderr []byte, err error)
	// Exec准备用于在容器中执行命令的流式传输端点，并返回地址。
	Exec(context.Context, *runtimeapi.ExecRequest) (*runtimeapi.ExecResponse, error)
	// Attach准备用于连接到正在运行的容器的流式传输端点，并返回地址。
	Attach(ctx context.Context, req *runtimeapi.AttachRequest) (*runtimeapi.AttachResponse, error)
	// ReopenContainerLog要求运行时重新打开容器的stdout/stderr日志文件
	// 如果返回错误，则不得创建新的容器日志文件。
	ReopenContainerLog(ctx context.Context, ContainerID string) error
	// CheckpointContainer对容器进行检查点
	CheckpointContainer(ctx context.Context, options *runtimeapi.CheckpointContainerRequest) error
	// GetContainerEvents从CRI运行时获取容器事件
	GetContainerEvents(containerEventsCh chan *runtimeapi.ContainerEventResponse) error
}
```

#### PodSandboxManager

```go
// PodSandboxManager包含用于操作PodSandboxes的方法。这些方法是线程安全的。
type PodSandboxManager interface {
	// RunPodSandbox创建并启动一个Pod级别的 sandbox 。运行时应确保 sandbox 处于就绪状态。
	RunPodSandbox(ctx context.Context, config *runtimeapi.PodSandboxConfig, runtimeHandler string) (string, error)
	// StopPodSandbox停止 sandbox 。如果 sandbox 中有任何正在运行的容器，它们应被强制终止。
	StopPodSandbox(pctx context.Context, odSandboxID string) error
	// RemovePodSandbox删除 sandbox 。如果 sandbox 中有正在运行的容器，它们应被强制删除。
	RemovePodSandbox(ctx context.Context, podSandboxID string) error
	// PodSandboxStatus返回PodSandbox的状态。
	PodSandboxStatus(ctx context.Context, podSandboxID string, verbose bool) (*runtimeapi.PodSandboxStatusResponse, error)
	// ListPodSandbox返回 sandbox 的列表。
	ListPodSandbox(ctx context.Context, filter *runtimeapi.PodSandboxFilter) ([]*runtimeapi.PodSandbox, error)
	// PortForward准备用于从PodSandbox转发端口的流式传输端点，并返回地址。
	PortForward(context.Context, *runtimeapi.PortForwardRequest) (*runtimeapi.PortForwardResponse, error)
}
```

#### ContainerStatsManager

```go
// ContainerStatsManager包含用于检索容器统计信息的方法。
type ContainerStatsManager interface {
	// ContainerStats返回容器的统计信息。如果容器不存在，则调用返回错误。
	ContainerStats(ctx context.Context, containerID string) (*runtimeapi.ContainerStats, error)
	// ListContainerStats返回所有正在运行的容器的统计信息。
	ListContainerStats(ctx context.Context, filter *runtimeapi.ContainerStatsFilter) ([]*runtimeapi.ContainerStats, error)
	// PodSandboxStats返回Pod的统计信息。如果Pod不存在，则调用返回错误。
	PodSandboxStats(ctx context.Context, podSandboxID string) (*runtimeapi.PodSandboxStats, error)
	// ListPodSandboxStats返回所有正在运行的Pod的统计信息。
	ListPodSandboxStats(ctx context.Context, filter *runtimeapi.PodSandboxStatsFilter) ([]*runtimeapi.PodSandboxStats, error)
	// ListMetricDescriptors获取将在ListPodSandboxMetrics中返回的度量描述符。
	ListMetricDescriptors(ctx context.Context) ([]*runtimeapi.MetricDescriptor, error)
	// ListPodSandboxMetrics返回所有正在运行的Pod的指标。
	ListPodSandboxMetrics(ctx context.Context) ([]*runtimeapi.PodSandboxMetrics, error)
}
```

#### ImageManagerService

```go
// ImageManagerService接口应由容器镜像管理器实现。
// 这些方法应是线程安全的。
type ImageManagerService interface {
	// ListImages列出现有的镜像。
	ListImages(ctx context.Context, filter *runtimeapi.ImageFilter) ([]*runtimeapi.Image, error)
	// ImageStatus返回镜像的状态。
	ImageStatus(ctx context.Context, image *runtimeapi.ImageSpec, verbose bool) (*runtimeapi.ImageStatusResponse, error)
	// PullImage使用身份验证配置拉取镜像。
	PullImage(ctx context.Context, image *runtimeapi.ImageSpec, auth *runtimeapi.AuthConfig, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, error)
	// RemoveImage删除镜像。
	RemoveImage(ctx context.Context, image *runtimeapi.ImageSpec) error
	// ImageFsInfo返回用于存储镜像的文件系统的信息。
	ImageFsInfo(ctx context.Context) ([]*runtimeapi.FilesystemUsage, error)
}
```

### remoteRuntimeService

```go
// remoteRuntimeService是internalapi.RuntimeService的gRPC实现。
type remoteRuntimeService struct {
	timeout       time.Duration
	runtimeClient runtimeapi.RuntimeServiceClient
	// Cache last per-container error message to reduce log spam
	logReduction *logreduction.LogReduction
}

// NewRemoteRuntimeService创建一个新的internalapi.RuntimeService。
func NewRemoteRuntimeService(endpoint string, connectionTimeout time.Duration, tp trace.TracerProvider) (internalapi.RuntimeService, error) {
	klog.V(3).InfoS("Connecting to runtime service", "endpoint", endpoint)
	addr, dialer, err := util.GetAddressAndDialer(endpoint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	dialOpts := []grpc.DialOption{}
	dialOpts = append(dialOpts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))
	if utilfeature.DefaultFeatureGate.Enabled(features.KubeletTracing) {
		tracingOpts := []otelgrpc.Option{
			otelgrpc.WithPropagators(tracing.Propagators()),
			otelgrpc.WithTracerProvider(tp),
		}
		// 即使没有TracerProvider，otelgrpc仍然处理上下文传播。
		// 参见https://github.com/open-telemetry/opentelemetry-go/tree/main/example/passthrough
		dialOpts = append(dialOpts,
			grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor(tracingOpts...)),
			grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor(tracingOpts...)))
	}
	conn, err := grpc.DialContext(ctx, addr, dialOpts...)
	if err != nil {
		klog.ErrorS(err, "Connect remote runtime failed", "address", addr)
		return nil, err
	}

	service := &remoteRuntimeService{
		timeout:      connectionTimeout,
		logReduction: logreduction.NewLogReduction(identicalErrorDelay),
	}

	if err := service.validateServiceConnection(ctx, conn, endpoint); err != nil {
		return nil, fmt.Errorf("validate service connection: %w", err)
	}

	return service, nil
}
```

#### Version

```go
// Version返回运行时的名称、版本和API版本。
func (r *remoteRuntimeService) Version(ctx context.Context, apiVersion string) (*runtimeapi.VersionResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] Version", "apiVersion", apiVersion, "timeout", r.timeout)

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.versionV1(ctx, apiVersion)
}
```

##### versionV1

```go
func (r *remoteRuntimeService) versionV1(ctx context.Context, apiVersion string) (*runtimeapi.VersionResponse, error) {
	typedVersion, err := r.runtimeClient.Version(ctx, &runtimeapi.VersionRequest{
		Version: apiVersion,
	})
	if err != nil {
		klog.ErrorS(err, "Version from runtime service failed")
		return nil, err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] Version Response", "apiVersion", typedVersion)

	if typedVersion.Version == "" || typedVersion.RuntimeName == "" || typedVersion.RuntimeApiVersion == "" || typedVersion.RuntimeVersion == "" {
		return nil, fmt.Errorf("not all fields are set in VersionResponse (%q)", *typedVersion)
	}

	return typedVersion, err
}
```

#### RunPodSandbox

```go
// RunPodSandbox创建并启动一个Pod级别的 sandbox 。运行时应确保 sandbox 处于就绪状态。
func (r *remoteRuntimeService) RunPodSandbox(ctx context.Context, config *runtimeapi.PodSandboxConfig, runtimeHandler string) (string, error) {
	// 为 sandbox 操作使用两倍长的超时时间（默认为4分钟）
	// TODO：使Pod sandbox 超时时间可配置。
	timeout := r.timeout * 2

	klog.V(10).InfoS("[RemoteRuntimeService] RunPodSandbox", "config", config, "runtimeHandler", runtimeHandler, "timeout", timeout)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := r.runtimeClient.RunPodSandbox(ctx, &runtimeapi.RunPodSandboxRequest{
		Config:         config,
		RuntimeHandler: runtimeHandler,
	})

	if err != nil {
		klog.ErrorS(err, "RunPodSandbox from runtime service failed")
		return "", err
	}

	podSandboxID := resp.PodSandboxId

	if podSandboxID == "" {
		errorMessage := fmt.Sprintf("PodSandboxId is not set for sandbox %q", config.Metadata)
		err := errors.New(errorMessage)
		klog.ErrorS(err, "RunPodSandbox failed")
		return "", err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] RunPodSandbox Response", "podSandboxID", podSandboxID)

	return podSandboxID, nil
}
```

#### StopPodSandbox

```go
// StopPodSandbox停止 sandbox 。如果 sandbox 中有任何正在运行的容器，它们应被强制终止。
func (r *remoteRuntimeService) StopPodSandbox(ctx context.Context, podSandBoxID string) (err error) {
	klog.V(10).InfoS("[RemoteRuntimeService] StopPodSandbox", "podSandboxID", podSandBoxID, "timeout", r.timeout)

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if _, err := r.runtimeClient.StopPodSandbox(ctx, &runtimeapi.StopPodSandboxRequest{
		PodSandboxId: podSandBoxID,
	}); err != nil {
		klog.ErrorS(err, "StopPodSandbox from runtime service failed", "podSandboxID", podSandBoxID)
		return err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] StopPodSandbox Response", "podSandboxID", podSandBoxID)

	return nil
}
```

#### RemovePodSandbox

```go
// RemovePodSandbox移除 sandbox 。如果 sandbox 中有任何容器，它们应该被强制移除。
func (r *remoteRuntimeService) RemovePodSandbox(ctx context.Context, podSandBoxID string) (err error) {
	klog.V(10).InfoS("[RemoteRuntimeService] RemovePodSandbox", "podSandboxID", podSandBoxID, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if _, err := r.runtimeClient.RemovePodSandbox(ctx, &runtimeapi.RemovePodSandboxRequest{
		PodSandboxId: podSandBoxID,
	}); err != nil {
		klog.ErrorS(err, "RemovePodSandbox from runtime service failed", "podSandboxID", podSandBoxID)
		return err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] RemovePodSandbox Response", "podSandboxID", podSandBoxID)

	return nil
}
```

#### PodSandboxStatus

```go
// PodSandboxStatus返回PodSandbox的状态。
func (r *remoteRuntimeService) PodSandboxStatus(ctx context.Context, podSandBoxID string, verbose bool) (*runtimeapi.PodSandboxStatusResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] PodSandboxStatus", "podSandboxID", podSandBoxID, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.podSandboxStatusV1(ctx, podSandBoxID, verbose)
}
```



#### ListPodSandbox

```go
// ListPodSandbox返回PodSandbox的列表。
func (r *remoteRuntimeService) ListPodSandbox(ctx context.Context, filter *runtimeapi.PodSandboxFilter) ([]*runtimeapi.PodSandbox, error) {
	// 使用指定的过滤器和超时时间调用runtimeClient的ListPodSandbox方法
	resp, err := r.runtimeClient.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{
		Filter: filter,
	})
	if err != nil {
		klog.ErrorS(err, "ListPodSandbox with filter from runtime service failed", "filter", filter)
		return nil, err
	}

	// 记录日志，包括过滤器和返回的PodSandbox列表
	klog.V(10).InfoS("[RemoteRuntimeService] ListPodSandbox Response", "filter", filter, "items", resp.Items)

	return resp.Items, nil
}
```

#### PortForward

```go
// PortForward 准备用于转发来自 PodSandbox 的端口的流式传输端点，并返回地址。
func (r *remoteRuntimeService) PortForward(ctx context.Context, req *runtimeapi.PortForwardRequest) (*runtimeapi.PortForwardResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] PortForward", "podSandboxID", req.PodSandboxId, "port", req.Port, "timeout", r.timeout) // 记录信息日志
	ctx, cancel := context.WithTimeout(ctx, r.timeout)                                                                               // 使用超时时间创建新的上下文
	defer cancel()

	return r.portForwardV1(ctx, req) // 调用 portForwardV1 函数
}
```

##### portForwardV1

```go
func (r *remoteRuntimeService) portForwardV1(ctx context.Context, req *runtimeapi.PortForwardRequest) (*runtimeapi.PortForwardResponse, error) {
	resp, err := r.runtimeClient.PortForward(ctx, req) // 调用 runtimeClient 的 PortForward 方法
	if err != nil {
		klog.ErrorS(err, "PortForward from runtime service failed", "podSandboxID", req.PodSandboxId) // 记录错误日志
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] PortForward Response", "podSandboxID", req.PodSandboxId) // 记录信息日志

	if resp.Url == "" {
		errorMessage := "URL is not set"
		err := errors.New(errorMessage)
		klog.ErrorS(err, "PortForward failed") // 记录错误日志
		return nil, err
	}

	return resp, nil
}
```

#### CreateContainer

```go
// CreateContainer在指定的PodSandbox中创建一个新的容器。
func (r *remoteRuntimeService) CreateContainer(ctx context.Context, podSandBoxID string, config *runtimeapi.ContainerConfig, sandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	// 使用指定的podSandboxID、配置和超时时间调用runtimeClient的CreateContainer方法
	resp, err := r.runtimeClient.CreateContainer(ctx, &runtimeapi.CreateContainerRequest{
		PodSandboxId:  podSandBoxID,
		Config:        config,
		SandboxConfig: sandboxConfig,
	})
	if err != nil {
		klog.ErrorS(err, "CreateContainer in sandbox from runtime service failed", "podSandboxID", podSandBoxID)
		return "", err
	}

	// 记录日志，包括podSandboxID和容器ID
	klog.V(10).InfoS("[RemoteRuntimeService] CreateContainer", "podSandboxID", podSandBoxID, "containerID", resp.ContainerId)
	if resp.ContainerId == "" {
		// 如果容器ID为空，返回错误信息
		errorMessage := fmt.Sprintf("ContainerId is not set for container %q", config.Metadata)
		err := errors.New(errorMessage)
		klog.ErrorS(err, "CreateContainer failed")
		return "", err
	}

	return resp.ContainerId, nil
}
```

#### StartContainer

```go
// StartContainer启动容器。
func (r *remoteRuntimeService) StartContainer(ctx context.Context, containerID string) (err error) {
	// 使用指定的容器ID和超时时间调用runtimeClient的StartContainer方法
	if _, err := r.runtimeClient.StartContainer(ctx, &runtimeapi.StartContainerRequest{
		ContainerId: containerID,
	}); err != nil {
		klog.ErrorS(err, "StartContainer from runtime service failed", "containerID", containerID)
		return err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] StartContainer Response", "containerID", containerID)

	return nil
}
```

#### StopContainer

```go
// StopContainer使用优雅期间（即超时时间）停止运行中的容器。
func (r *remoteRuntimeService) StopContainer(ctx context.Context, containerID string, timeout int64) (err error) {
	// 使用容器ID、超时时间和默认超时时间（2分钟）计算总超时时间
	t := r.timeout + time.Duration(timeout)*time.Second
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()

	// 清除日志记录
	r.logReduction.ClearID(containerID)

	// 使用指定的容器ID和超时时间调用runtimeClient的StopContainer方法
	if _, err := r.runtimeClient.StopContainer(ctx, &runtimeapi.StopContainerRequest{
		ContainerId: containerID,
		Timeout:     timeout,
	}); err != nil {
		klog.ErrorS(err, "StopContainer from runtime service failed", "containerID", containerID)
		return err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] StopContainer Response", "containerID", containerID)

	return nil
}
```

#### RemoveContainer

```go
// RemoveContainer移除容器。如果容器正在运行，应该强制移除容器。
func (r *remoteRuntimeService) RemoveContainer(ctx context.Context, containerID string) (err error) {
	// 使用指定的容器ID和超时时间调用runtimeClient的RemoveContainer方法
	if _, err := r.runtimeClient.RemoveContainer(ctx, &runtimeapi.RemoveContainerRequest{
		ContainerId: containerID,
	}); err != nil {
		klog.ErrorS(err, "RemoveContainer from runtime service failed", "containerID", containerID)
		return err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] RemoveContainer Response", "containerID", containerID)

	return nil
}
```

#### ListContainers

```go
// ListContainers 根据过滤器列出容器。
func (r *remoteRuntimeService) ListContainers(ctx context.Context, filter *runtimeapi.ContainerFilter) ([]*runtimeapi.Container, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ListContainers", "filter", filter, "timeout", r.timeout) // 记录信息日志
	ctx, cancel := context.WithTimeout(ctx, r.timeout)                                                // 使用超时时间创建新的上下文
	defer cancel()

	return r.listContainersV1(ctx, filter) // 调用 listContainersV1 函数
}
```

##### listContainersV1

```go
func (r *remoteRuntimeService) listContainersV1(ctx context.Context, filter *runtimeapi.ContainerFilter) ([]*runtimeapi.Container, error) {
	resp, err := r.runtimeClient.ListContainers(ctx, &runtimeapi.ListContainersRequest{
		Filter: filter,
	}) // 调用 runtimeClient 的 ListContainers 方法
	if err != nil {
		klog.ErrorS(err, "ListContainers with filter from runtime service failed", "filter", filter) // 记录错误日志
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] ListContainers Response", "filter", filter, "containers", resp.Containers) // 记录信息日志

	return resp.Containers, nil
}
```

#### ContainerStatus

```go
// ContainerStatus 返回容器状态。
func (r *remoteRuntimeService) ContainerStatus(ctx context.Context, containerID string, verbose bool) (*runtimeapi.ContainerStatusResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ContainerStatus", "containerID", containerID, "timeout", r.timeout) // 记录信息日志
	ctx, cancel := context.WithTimeout(ctx, r.timeout)                                                           // 使用超时时间创建新的上下文
	defer cancel()

	return r.containerStatusV1(ctx, containerID, verbose) // 调用 containerStatusV1 函数
}
```

##### containerStatusV1

```go
func (r *remoteRuntimeService) containerStatusV1(ctx context.Context, containerID string, verbose bool) (*runtimeapi.ContainerStatusResponse, error) {
	resp, err := r.runtimeClient.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     verbose,
	}) // 调用 runtimeClient 的 ContainerStatus 方法
	if err != nil {
		// 不要无休止地记录关于相同错误的无尽消息。
		if r.logReduction.ShouldMessageBePrinted(err.Error(), containerID) {
			klog.ErrorS(err, "ContainerStatus from runtime service failed", "containerID", containerID) // 记录错误日志
		}
		return nil, err
	}
	r.logReduction.ClearID(containerID)
	klog.V(10).InfoS("[RemoteRuntimeService] ContainerStatus Response", "containerID", containerID, "status", resp.Status) // 记录信息日志

	status := resp.Status
	if resp.Status != nil {
		if err := verifyContainerStatus(status); err != nil {
			klog.ErrorS(err, "verify ContainerStatus failed", "containerID", containerID) // 记录错误日志
			return nil, err
		}
	}

	return resp, nil
}
```

#### UpdateContainerResources

```go
// UpdateContainerResources 更新容器的资源配置
func (r *remoteRuntimeService) UpdateContainerResources(ctx context.Context, containerID string, resources *runtimeapi.ContainerResources) (err error) {
	klog.V(10).InfoS("[RemoteRuntimeService] UpdateContainerResources", "containerID", containerID, "timeout", r.timeout) // 记录信息日志
	ctx, cancel := context.WithTimeout(ctx, r.timeout)                                                                    // 使用超时时间创建新的上下文
	defer cancel()

	if _, err := r.runtimeClient.UpdateContainerResources(ctx, &runtimeapi.UpdateContainerResourcesRequest{
		ContainerId: containerID,
		Linux:       resources.GetLinux(),
		Windows:     resources.GetWindows(),
	}); err != nil {
		klog.ErrorS(err, "UpdateContainerResources from runtime service failed", "containerID", containerID) // 记录错误日志
		return err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] UpdateContainerResources Response", "containerID", containerID) // 记录信息日志

	return nil
}
```

#### ExecSync

```go
// ExecSync在容器中执行命令，并返回stdout输出。
// 如果命令退出时返回非零退出码，则返回错误。
func (r *remoteRuntimeService) ExecSync(ctx context.Context, containerID string, cmd []string, timeout time.Duration) (stdout []byte, stderr []byte, err error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ExecSync", "containerID", containerID, "timeout", timeout)
	// 当timeout为0时不设置超时时间。
	var cancel context.CancelFunc
	if timeout != 0 {
		// 使用timeout + 默认超时时间（2分钟）作为超时时间，以留出一些时间供运行时进行清理。
		ctx, cancel = context.WithTimeout(ctx, r.timeout+timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	return r.execSyncV1(ctx, containerID, cmd, timeout)
}
```

##### execSyncV1

```go
// execSyncV1是ExecSync的内部实现，执行在容器中执行命令，并返回stdout输出。
// 如果命令退出时返回非零退出码，则返回错误。
func (r *remoteRuntimeService) execSyncV1(ctx context.Context, containerID string, cmd []string, timeout time.Duration) (stdout []byte, stderr []byte, err error) {
	timeoutSeconds := int64(timeout.Seconds())
	req := &runtimeapi.ExecSyncRequest{
		ContainerId: containerID,
		Cmd:         cmd,
		Timeout:     timeoutSeconds,
	}
	resp, err := r.runtimeClient.ExecSync(ctx, req)
	if err != nil {
		klog.ErrorS(err, "ExecSync cmd from runtime service failed", "containerID", containerID, "cmd", cmd)

		// 将DeadlineExceeded gRPC错误解释为超时探测。
		if status.Code(err) == codes.DeadlineExceeded {
			err = exec.NewTimeoutError(fmt.Errorf("command %q timed out", strings.Join(cmd, " ")), timeout)
		}

		return nil, nil, err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] ExecSync Response", "containerID", containerID, "exitCode", resp.ExitCode)
	err = nil
	if resp.ExitCode != 0 {
		err = utilexec.CodeExitError{
			Err:  fmt.Errorf("command '%s' exited with %d: %s", strings.Join(cmd, " "), resp.ExitCode, resp.Stderr),
			Code: int(resp.ExitCode),
		}
	}

	return resp.Stdout, resp.Stderr, err
}
```

#### Exec

```go
// Exec准备执行容器中命令的流式端点，并返回地址。
func (r *remoteRuntimeService) Exec(ctx context.Context, req *runtimeapi.ExecRequest) (*runtimeapi.ExecResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] Exec", "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.execV1(ctx, req)
}
```

##### execV1

```go
// execV1是Exec的内部实现，准备执行容器中命令的流式端点，并返回地址。
func (r *remoteRuntimeService) execV1(ctx context.Context, req *runtimeapi.ExecRequest) (*runtimeapi.ExecResponse, error) {
	resp, err := r.runtimeClient.Exec(ctx, req)
	if err != nil {
		klog.ErrorS(err, "Exec cmd from runtime service failed", "containerID", req.ContainerId, "cmd", req.Cmd)
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] Exec Response")

	if resp.Url == "" {
		errorMessage := "URL is not set"
		err := errors.New(errorMessage)
		klog.ErrorS(err, "Exec failed")
		return nil, err
	}

	return resp, nil
}
```

#### Attach

```go
// Attach准备附加到正在运行的容器的流式端点，并返回地址。
func (r *remoteRuntimeService) Attach(ctx context.Context, req *runtimeapi.AttachRequest) (*runtimeapi.AttachResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] Attach", "containerID", req.ContainerId, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.attachV1(ctx, req)
}
```

##### attachV1

```go
// attachV1是Attach的内部实现，准备附加到正在运行的容器的流式端点，并返回地址。
func (r *remoteRuntimeService) attachV1(ctx context.Context, req *runtimeapi.AttachRequest) (*runtimeapi.AttachResponse, error) {
	resp, err := r.runtimeClient.Attach(ctx, req)
	if err != nil {
		klog.ErrorS(err, "Attach container from runtime service failed", "containerID", req.ContainerId)
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] Attach Response", "containerID", req.ContainerId)

	if resp.Url == "" {
		errorMessage := "URL is not set"
		err := errors.New(errorMessage)
		klog.ErrorS(err, "Attach failed")
		return nil, err
	}
	return resp, nil
}
```

#### ReopenContainerLog

```go
// ReopenContainerLog重新打开容器日志文件。
func (r *remoteRuntimeService) ReopenContainerLog(ctx context.Context, containerID string) (err error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ReopenContainerLog", "containerID", containerID, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if _, err := r.runtimeClient.ReopenContainerLog(ctx, &runtimeapi.ReopenContainerLogRequest{ContainerId: containerID}); err != nil {
		klog.ErrorS(err, "ReopenContainerLog from runtime service failed", "containerID", containerID)
		return err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] ReopenContainerLog Response", "containerID", containerID)
	return nil
}
```

#### CheckpointContainer

```go
// CheckpointContainer触发给定CheckpointContainerRequest的检查点。
func (r *remoteRuntimeService) CheckpointContainer(ctx context.Context, options *runtimeapi.CheckpointContainerRequest) error {
	klog.V(10).InfoS(
		"[RemoteRuntimeService] CheckpointContainer",
		"options",
		options,
	)
	if options == nil {
		return errors.New("CheckpointContainer requires non-nil CheckpointRestoreOptions parameter")
	}
	if options.Timeout < 0 {
		return errors.New("CheckpointContainer requires the timeout value to be > 0")
	}

	ctx, cancel := func(ctx context.Context) (context.Context, context.CancelFunc) {
		defaultTimeout := int64(r.timeout / time.Second)
		if options.Timeout > defaultTimeout {
			// 用户请求了特定的超时时间，如果大于CRI的默认值，则使用它。
			return context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Second)
		}
		// 如果用户请求的超时时间小于CRI的默认值，则使用CRI的默认值。
		options.Timeout = defaultTimeout
		return context.WithTimeout(ctx, r.timeout)
	}(ctx)
	defer cancel()

	_, err := r.runtimeClient.CheckpointContainer(
		ctx,
		options,
	)

	if err != nil {
		klog.ErrorS(
			err,
			"CheckpointContainer from runtime service failed",
			"containerID",
			options.ContainerId,
		)
		return err
	}
	klog.V(10).InfoS(
		"[RemoteRuntimeService] CheckpointContainer Response",
		"containerID",
		options.ContainerId,
	)

	return nil
}
```

#### GetContainerEvents

```go
// GetContainerEvents从容器运行时服务获取容器事件。
func (r *remoteRuntimeService) GetContainerEvents(containerEventsCh chan *runtimeapi.ContainerEventResponse) error {
	containerEventsStreamingClient, err := r.runtimeClient.GetContainerEvents(context.Background(), &runtimeapi.GetEventsRequest{})
	if err != nil {
		klog.ErrorS(err, "GetContainerEvents failed to get streaming client")
		return err
	}

	// 成功建立连接，并准备使用流式客户端。
	metrics.EventedPLEGConn.Inc()

	for {
		resp, err := containerEventsStreamingClient.Recv()
		if err == io.EOF {
			klog.ErrorS(err, "container events stream is closed")
			return err
		}
		if err != nil {
			klog.ErrorS(err, "failed to receive streaming container event")
			return err
		}
		if resp != nil {
			containerEventsCh <- resp
			klog.V(4).InfoS("container event received", "resp", resp)
		}
	}
}
```

#### ContainerStats

```go
// ContainerStats 函数返回容器的统计信息。
func (r *remoteRuntimeService) ContainerStats(ctx context.Context, containerID string) (*runtimeapi.ContainerStats, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ContainerStats", "containerID", containerID, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.containerStatsV1(ctx, containerID)
}
```

##### containerStatsV1

```go
func (r *remoteRuntimeService) containerStatsV1(ctx context.Context, containerID string) (*runtimeapi.ContainerStats, error) {
	resp, err := r.runtimeClient.ContainerStats(ctx, &runtimeapi.ContainerStatsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		if r.logReduction.ShouldMessageBePrinted(err.Error(), containerID) {
			klog.ErrorS(err, "ContainerStats from runtime service failed", "containerID", containerID)
		}
		return nil, err
	}
	r.logReduction.ClearID(containerID)
	klog.V(10).InfoS("[RemoteRuntimeService] ContainerStats Response", "containerID", containerID, "stats", resp.GetStats())

	return resp.GetStats(), nil
}
```

#### ListContainerStats

```go
// ListContainerStats 函数返回符合筛选条件的容器统计信息列表。
func (r *remoteRuntimeService) ListContainerStats(ctx context.Context, filter *runtimeapi.ContainerStatsFilter) ([]*runtimeapi.ContainerStats, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ListContainerStats", "filter", filter)
	// 不设置超时，因为收集可写层统计信息需要时间。
	// TODO(random-liu): 我们应该假设运行时应该缓存结果，并在此处设置超时吗？
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	return r.listContainerStatsV1(ctx, filter)
}

```

##### listContainerStatsV1

```go
func (r *remoteRuntimeService) listContainerStatsV1(ctx context.Context, filter *runtimeapi.ContainerStatsFilter) ([]*runtimeapi.ContainerStats, error) {
	resp, err := r.runtimeClient.ListContainerStats(ctx, &runtimeapi.ListContainerStatsRequest{
		Filter: filter,
	})
	if err != nil {
		klog.ErrorS(err, "ListContainerStats with filter from runtime service failed", "filter", filter)
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] ListContainerStats Response", "filter", filter, "stats", resp.GetStats())

	return resp.GetStats(), nil
}
```

#### PodSandboxStats

```go
// PodSandboxStats 函数返回 Pod 的统计信息。
func (r *remoteRuntimeService) PodSandboxStats(ctx context.Context, podSandboxID string) (*runtimeapi.PodSandboxStats, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] PodSandboxStats", "podSandboxID", podSandboxID, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.podSandboxStatsV1(ctx, podSandboxID)
}
```

##### podSandboxStatsV1

```go
func (r *remoteRuntimeService) podSandboxStatsV1(ctx context.Context, podSandboxID string) (*runtimeapi.PodSandboxStats, error) {
	resp, err := r.runtimeClient.PodSandboxStats(ctx, &runtimeapi.PodSandboxStatsRequest{
		PodSandboxId: podSandboxID,
	})
	if err != nil {
		if r.logReduction.ShouldMessageBePrinted(err.Error(), podSandboxID) {
			klog.ErrorS(err, "PodSandbox from runtime service failed", "podSandboxID", podSandboxID)
		}
		return nil, err
	}
	r.logReduction.ClearID(podSandboxID)
	klog.V(10).InfoS("[RemoteRuntimeService] PodSandbox Response", "podSandboxID", podSandboxID, "stats", resp.GetStats())

	return resp.GetStats(), nil
}
```

#### ListPodSandboxStats

```go
// ListPodSandboxStats 函数返回符合筛选条件的 Pod Sandbox 统计信息列表。
func (r *remoteRuntimeService) ListPodSandboxStats(ctx context.Context, filter *runtimeapi.PodSandboxStatsFilter) ([]*runtimeapi.PodSandboxStats, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] ListPodSandboxStats", "filter", filter)
	// 设置超时，因为运行时能够缓存磁盘统计信息的结果。
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.listPodSandboxStatsV1(ctx, filter)
}
```

##### listPodSandboxStatsV1

```go
func (r *remoteRuntimeService) listPodSandboxStatsV1(ctx context.Context, filter *runtimeapi.PodSandboxStatsFilter) ([]*runtimeapi.PodSandboxStats, error) {
	resp, err := r.runtimeClient.ListPodSandboxStats(ctx, &runtimeapi.ListPodSandboxStatsRequest{
		Filter: filter,
	})
	if err != nil {
		klog.ErrorS(err, "ListPodSandboxStats with filter from runtime service failed", "filter", filter)
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] ListPodSandboxStats Response", "filter", filter, "stats", resp.GetStats())

	return resp.GetStats(), nil
}
```

#### ListMetricDescriptors

```go
// ListMetricDescriptors 函数获取将在 ListPodSandboxMetrics 中返回的指标的描述符。
func (r *remoteRuntimeService) ListMetricDescriptors(ctx context.Context) ([]*runtimeapi.MetricDescriptor, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	resp, err := r.runtimeClient.ListMetricDescriptors(ctx, &runtimeapi.ListMetricDescriptorsRequest{})
	if err != nil {
		klog.ErrorS(err, "ListMetricDescriptors from runtime service failed")
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] ListMetricDescriptors Response", "stats", resp.GetDescriptors())

	return resp.GetDescriptors(), nil
}
```

#### ListPodSandboxMetrics

```go
// ListPodSandboxMetrics 函数检索所有 Pod Sandbox 的指标。
func (r *remoteRuntimeService) ListPodSandboxMetrics(ctx context.Context) ([]*runtimeapi.PodSandboxMetrics, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	resp, err := r.runtimeClient.ListPodSandboxMetrics(ctx, &runtimeapi.ListPodSandboxMetricsRequest{})
	if err != nil {
		klog.ErrorS(err, "ListPodSandboxMetrics from runtime service failed")
		return nil, err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] ListPodSandboxMetrics Response", "stats", resp.GetPodMetrics())

	return resp.GetPodMetrics(), nil
}
```

#### UpdateRuntimeConfig

```go
// UpdateRuntimeConfig 函数更新运行时服务的配置。目前仅支持更新分配给节点的 Pod CIDR，运行时服务只是将其代理到网络插件。
func (r *remoteRuntimeService) UpdateRuntimeConfig(ctx context.Context, runtimeConfig *runtimeapi.RuntimeConfig) (err error) {
	klog.V(10).InfoS("[RemoteRuntimeService] UpdateRuntimeConfig", "runtimeConfig", runtimeConfig, "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// 响应不包含任何有趣的内容。这转换为对网络插件的事件通知，它不会失败，因此我们真正关心的是暴露目标不可达。
	if _, err := r.runtimeClient.UpdateRuntimeConfig(ctx, &runtimeapi.UpdateRuntimeConfigRequest{
		RuntimeConfig: runtimeConfig,
	}); err != nil {
		return err
	}
	klog.V(10).InfoS("[RemoteRuntimeService] UpdateRuntimeConfig Response", "runtimeConfig", runtimeConfig)

	return nil
}
```

#### Status

```go
// Status 函数返回运行时的状态。
func (r *remoteRuntimeService) Status(ctx context.Context, verbose bool) (*runtimeapi.StatusResponse, error) {
	klog.V(10).InfoS("[RemoteRuntimeService] Status", "timeout", r.timeout)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.statusV1(ctx, verbose)
}
```

##### statusV1

```go
func (r *remoteRuntimeService) statusV1(ctx context.Context, verbose bool) (*runtimeapi.StatusResponse, error) {
	resp, err := r.runtimeClient.Status(ctx, &runtimeapi.StatusRequest{
		Verbose: verbose,
	})
	if err != nil {
		klog.ErrorS(err, "Status from runtime service failed")
		return nil, err
	}

	klog.V(10).InfoS("[RemoteRuntimeService] Status Response", "status", resp.Status)

	if resp.Status == nil || len(resp.Status.Conditions) < 2 {
		errorMessage := "RuntimeReady or NetworkReady condition are not set"
		err := errors.New(errorMessage)
		klog.ErrorS(err, "Status failed")
		return nil, err
	}

	return resp, nil
}
```

#### ListImages

```go
// ListImages方法列出可用的镜像。
func (r *remoteImageService) ListImages(ctx context.Context, filter *runtimeapi.ImageFilter) ([]*runtimeapi.Image, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.listImagesV1(ctx, filter)
}
```

##### listImagesV1

```go
// listImagesV1是ListImages方法的内部实现，用于列出可用的镜像。
func (r *remoteImageService) listImagesV1(ctx context.Context, filter *runtimeapi.ImageFilter) ([]*runtimeapi.Image, error) {
	resp, err := r.imageClient.ListImages(ctx, &runtimeapi.ListImagesRequest{
		Filter: filter,
	})
	if err != nil {
		klog.ErrorS(err, "ListImages with filter from image service failed", "filter", filter)
		return nil, err
	}

	return resp.Images, nil
}
```

#### ImageStatus

```go
// ImageStatus方法返回镜像的状态。
func (r *remoteImageService) ImageStatus(ctx context.Context, image *runtimeapi.ImageSpec, verbose bool) (*runtimeapi.ImageStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.imageStatusV1(ctx, image, verbose)
}
```

##### imageStatusV1

```go
// imageStatusV1是ImageStatus方法的内部实现，用于返回镜像的状态。
func (r *remoteImageService) imageStatusV1(ctx context.Context, image *runtimeapi.ImageSpec, verbose bool) (*runtimeapi.ImageStatusResponse, error) {
	resp, err := r.imageClient.ImageStatus(ctx, &runtimeapi.ImageStatusRequest{
		Image:   image,
		Verbose: verbose,
	})
	if err != nil {
		klog.ErrorS(err, "Get ImageStatus from image service failed", "image", image.Image)
		return nil, err
	}

	if resp.Image != nil {
		if resp.Image.Id == "" || resp.Image.Size_ == 0 {
			errorMessage := fmt.Sprintf("Id or size of image %q is not set", image.Image)
			err := errors.New(errorMessage)
			klog.ErrorS(err, "ImageStatus failed", "image", image.Image)
			return nil, err
		}
	}

	return resp, nil
}
```

#### PullImage

```go
// PullImage方法使用身份验证配置拉取镜像。
func (r *remoteImageService) PullImage(ctx context.Context, image *runtimeapi.ImageSpec, auth *runtimeapi.AuthConfig, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	return r.pullImageV1(ctx, image, auth, podSandboxConfig)
}
```

##### pullImageV1

```go
// pullImageV1是PullImage方法的内部实现，用于使用身份验证配置拉取镜像。
func (r *remoteImageService) pullImageV1(ctx context.Context, image *runtimeapi.ImageSpec, auth *runtimeapi.AuthConfig, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	resp, err := r.imageClient.PullImage(ctx, &runtimeapi.PullImageRequest{
		Image:         image,
		Auth:          auth,
		SandboxConfig: podSandboxConfig,
	})
	if err != nil {
		klog.ErrorS(err, "PullImage from image service failed", "image", image.Image)

		// We can strip the code from unknown status errors since they add no value
		// and will make them easier to read in the logs/events.
		//
		// It also ensures that checking custom error types from pkg/kubelet/images/types.go
		// works in `imageManager.EnsureImageExists` (pkg/kubelet/images/image_manager.go).
		statusErr, ok := status.FromError(err)
		if ok && statusErr.Code() == codes.Unknown {
			return "", errors.New(statusErr.Message())
		}

		return "", err
	}

	if resp.ImageRef == "" {
		klog.ErrorS(errors.New("PullImage failed"), "ImageRef of image is not set", "image", image.Image)
		errorMessage := fmt.Sprintf("imageRef of image %q is not set", image.Image)
		return "", errors.New(errorMessage)
	}

	return resp.ImageRef, nil
}
```

#### RemoveImage

```go
// RemoveImage方法删除镜像。
func (r *remoteImageService) RemoveImage(ctx context.Context, image *runtimeapi.ImageSpec) (err error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if _, err = r.imageClient.RemoveImage(ctx, &runtimeapi.RemoveImageRequest{
		Image: image,
	}); err != nil {
		klog.ErrorS(err, "RemoveImage from image service failed", "image", image.Image)
		return err
	}

	return nil
}
```

#### ImageFsInfo

```go
// ImageFsInfo方法返回用于存储镜像的文件系统的信息。
func (r *remoteImageService) ImageFsInfo(ctx context.Context) ([]*runtimeapi.FilesystemUsage, error) {
	// 不设置超时，因为ImageFsInfo需要时间。
	// TODO(random-liu): 我们是否应该假设运行时应该缓存结果，并在此处设置超时？
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	return r.imageFsInfoV1(ctx)
}
```

##### imageFsInfoV1

```go
// imageFsInfoV1是ImageFsInfo方法的内部实现，用于返回用于存储镜像的文件系统的信息。
func (r *remoteImageService) imageFsInfoV1(ctx context.Context) ([]*runtimeapi.FilesystemUsage, error) {
	resp, err := r.imageClient.ImageFsInfo(ctx, &runtimeapi.ImageFsInfoRequest{})
	if err != nil {
		klog.ErrorS(err, "ImageFsInfo from image service failed")
		return nil, err
	}
	return resp.GetImageFilesystems(), nil
}
```

## KubeGenericRuntime

```go
// KubeGenericRuntime是一个接口，包含容器运行时和命令的接口。
type KubeGenericRuntime interface {
	kubecontainer.Runtime          // 容器运行时接口
	kubecontainer.StreamingRuntime // 流式容器运行时接口
	kubecontainer.CommandRunner    // 命令运行器接口
}
```

## kubeGenericRuntimeManager

```go
type kubeGenericRuntimeManager struct {
	runtimeName            string                           // 运行时名称
	recorder               record.EventRecorder             // 事件记录器
	osInterface            kubecontainer.OSInterface        // 操作系统接口
	machineInfo            *cadvisorapi.MachineInfo         // 机器信息
	containerGC            *containerGC                     // 容器垃圾回收管理器
	keyring                credentialprovider.DockerKeyring // 用于拉取镜像的密钥环
	runner                 kubecontainer.HandlerRunner      // 生命周期事件运行器
	runtimeHelper          kubecontainer.RuntimeHelper      // 包装 kubelet 以生成运行时容器选项的 RuntimeHelper
	livenessManager        proberesults.Manager             // 健康检查结果管理器
	readinessManager       proberesults.Manager             // 就绪检查结果管理器
	startupManager         proberesults.Manager             // 启动检查结果管理器
	cpuCFSQuota            bool                             // 如果为true，则使用CFS配额支持强制容器CPU限制
	cpuCFSQuotaPeriod      metav1.Duration                  // CPUCFSQuotaPeriod 设置 CPU CFS 配额周期值，cpu.cfs_period_us，默认为 100ms
	imagePuller            images.ImageManager              // 封装的镜像拉取器
	runtimeService         internalapi.RuntimeService       // gRPC服务客户端：runtimeService
	imageService           internalapi.ImageManagerService  // gRPC服务客户端：imageService
	versionCache           *cache.ObjectCache               // 运行时守护程序的版本缓存
	seccompProfileRoot     string                           // seccomp配置文件的目录路径
	containerManager       cm.ContainerManager              // Pod容器的容器管理接口
	internalLifecycle      cm.InternalContainerLifecycle    // 容器资源管理的内部生命周期事件处理程序
	logManager             logs.ContainerLogManager         // 容器日志管理器
	runtimeClassManager    *runtimeclass.Manager            // 管理 RuntimeClass 资源
	logReduction           *logreduction.LogReduction       // 缓存每个容器的最后一个错误消息，以减少日志输出
	podStateProvider       podStateProvider                 // PodState提供者实例
	seccompDefault         bool                             // 使用RuntimeDefault作为所有工作负载的默认seccomp配置文件
	memorySwapBehavior     string                           // MemorySwapBehavior 定义如何使用 swap
	getNodeAllocatable     func() v1.ResourceList           // 获取节点可分配资源的函数
	memoryThrottlingFactor float64                          // MemoryQoS 的内存限制因子
}
```

### new

```go
// NewKubeGenericRuntimeManager 创建一个新的 kubeGenericRuntimeManager。
func NewKubeGenericRuntimeManager(
	recorder record.EventRecorder, // 事件记录器
	livenessManager proberesults.Manager, // 存活性管理器
	readinessManager proberesults.Manager, // 可用性管理器
	startupManager proberesults.Manager, // 启动管理器
	rootDirectory string, // 根目录
	machineInfo *cadvisorapi.MachineInfo, // 机器信息
	podStateProvider podStateProvider, // Pod 状态提供器
	osInterface kubecontainer.OSInterface, // 操作系统接口
	runtimeHelper kubecontainer.RuntimeHelper, // 运行时助手
	insecureContainerLifecycleHTTPClient types.HTTPDoer, // 不安全的容器生命周期 HTTP 客户端
	imageBackOff *flowcontrol.Backoff, //  image 退避
	serializeImagePulls bool, // 序列化 image 拉取
	maxParallelImagePulls *int32, // 最大并行 image 拉取
	imagePullQPS float32, //  image 拉取 QPS
	imagePullBurst int, //  image 拉取突发数
	imageCredentialProviderConfigFile string, //  image 凭据提供程序配置文件
	imageCredentialProviderBinDir string, //  image 凭据提供程序二进制文件目录
	cpuCFSQuota bool, // CPU CFS 配额
	cpuCFSQuotaPeriod metav1.Duration, // CPU CFS 配额周期
	runtimeService internalapi.RuntimeService, // 运行时服务
	imageService internalapi.ImageManagerService, //  image 管理器服务
	containerManager cm.ContainerManager, // 容器管理器
	logManager logs.ContainerLogManager, // 容器日志管理器
	runtimeClassManager *runtimeclass.Manager, // 运行时类管理器
	seccompDefault bool, // Seccomp 默认值
	memorySwapBehavior string, // 内存交换行为
	getNodeAllocatable func() v1.ResourceList, // 获取可分配节点的函数
	memoryThrottlingFactor float64, // 内存限制因子
	podPullingTimeRecorder images.ImagePodPullingTimeRecorder, // Pod  image 拉取时间记录器
	tracerProvider trace.TracerProvider, // 追踪器提供者
) (KubeGenericRuntime, error) {
	ctx := context.Background()
	runtimeService = newInstrumentedRuntimeService(runtimeService)  // 使用仪表化的运行时服务
	imageService = newInstrumentedImageManagerService(imageService) // 使用仪表化的 image 管理器服务
	tracer := tracerProvider.Tracer(instrumentationScope)           // 根据仪表化作用域获取追踪器
	kubeRuntimeManager := &kubeGenericRuntimeManager{
		recorder:               recorder,                                          // 事件记录器
		cpuCFSQuota:            cpuCFSQuota,                                       // CPU CFS 配额
		cpuCFSQuotaPeriod:      cpuCFSQuotaPeriod,                                 // CPU CFS 配额周期
		seccompProfileRoot:     filepath.Join(rootDirectory, "seccomp"),           // Seccomp 配置文件根目录
		livenessManager:        livenessManager,                                   // 存活性管理器
		readinessManager:       readinessManager,                                  // 可用性管理器
		startupManager:         startupManager,                                    // 启动管理器
		machineInfo:            machineInfo,                                       // 机器信息
		osInterface:            osInterface,                                       // 操作系统接口
		runtimeHelper:          runtimeHelper,                                     // 运行时助手
		runtimeService:         runtimeService,                                    // 运行时服务
		imageService:           imageService,                                      //  image 管理器服务
		containerManager:       containerManager,                                  // 容器管理器
		internalLifecycle:      containerManager.InternalContainerLifecycle(),     // 容器管理器的内部容器生命周期
		logManager:             logManager,                                        // 容器日志管理器
		runtimeClassManager:    runtimeClassManager,                               // 运行时类管理器
		logReduction:           logreduction.NewLogReduction(identicalErrorDelay), // 日志减少器
		seccompDefault:         seccompDefault,                                    // Seccomp 默认值
		memorySwapBehavior:     memorySwapBehavior,                                // 内存交换行为
		getNodeAllocatable:     getNodeAllocatable,                                // 获取可分配节点的函数
		memoryThrottlingFactor: memoryThrottlingFactor,                            // 内存限制因子
	}

	typedVersion, err := kubeRuntimeManager.getTypedVersion(ctx) // 获取类型化版本
	if err != nil {
		klog.ErrorS(err, "Get runtime version failed") // 记录错误日志
		return nil, err
	}

	// 只支持匹配的 kubeRuntimeAPIVersion
	// TODO: Runtime API machinery 正在讨论中，详见 https://github.com/kubernetes/kubernetes/issues/28642
	if typedVersion.Version != kubeRuntimeAPIVersion {
		klog.ErrorS(err, "This runtime api version is not supported", // 记录错误日志
			"apiVersion", typedVersion.Version,
			"supportedAPIVersion", kubeRuntimeAPIVersion)
		return nil, ErrVersionNotSupported
	}

	kubeRuntimeManager.runtimeName = typedVersion.RuntimeName // 设置容器运行时名称
	klog.InfoS("Container runtime initialized",               // 记录信息日志
		"containerRuntime", typedVersion.RuntimeName,
		"version", typedVersion.RuntimeVersion,
		"apiVersion", typedVersion.RuntimeApiVersion)

	// 如果容器日志目录不存在，则创建该目录。
	// TODO: 在重构 kubelet 为新运行时接口时，在 kubelet.go 中创建 podLogsRootDirectory
	if _, err := osInterface.Stat(podLogsRootDirectory); os.IsNotExist(err) {
		if err := osInterface.MkdirAll(podLogsRootDirectory, 0755); err != nil {
			klog.ErrorS(err, "Failed to create pod log directory", "path", podLogsRootDirectory) // 记录错误日志
		}
	}

	if imageCredentialProviderConfigFile != "" || imageCredentialProviderBinDir != "" {
		if err := plugin.RegisterCredentialProviderPlugins(imageCredentialProviderConfigFile, imageCredentialProviderBinDir); err != nil {
			klog.ErrorS(err, "Failed to register CRI auth plugins") // 记录错误日志
			os.Exit(1)                                              // 退出程序
		}
	}
	kubeRuntimeManager.keyring = credentialprovider.NewDockerKeyring() // 创建 Docker 密钥环

	kubeRuntimeManager.imagePuller = images.NewImageManager(
		kubecontainer.FilterEventRecorder(recorder), // 过滤事件记录器
		kubeRuntimeManager,                          // kubeGenericRuntimeManager 实例
		imageBackOff,                                //  image 退避
		serializeImagePulls,                         // 序列化 image 拉取
		maxParallelImagePulls,                       // 最大并行 image 拉取
		imagePullQPS,                                //  image 拉取 QPS
		imagePullBurst,                              //  image 拉取突发数
		podPullingTimeRecorder)                      // Pod  image 拉取时间记录器
	kubeRuntimeManager.runner = lifecycle.NewHandlerRunner(insecureContainerLifecycleHTTPClient, kubeRuntimeManager, kubeRuntimeManager, recorder) // 创建生命周期处理程序运行器
	kubeRuntimeManager.containerGC = newContainerGC(runtimeService, podStateProvider, kubeRuntimeManager, tracer)                                  // 创建容器垃圾回收器
	kubeRuntimeManager.podStateProvider = podStateProvider                                                                                         // 设置 Pod 状态提供器

	kubeRuntimeManager.versionCache = cache.NewObjectCache(
		func() (interface{}, error) {
			return kubeRuntimeManager.getTypedVersion(ctx)
		},
		versionCacheTTL,
	) // 创建版本缓存

	return kubeRuntimeManager, nil
}
```

### Type

```go
// Type 返回容器运行时的类型。
func (m *kubeGenericRuntimeManager) Type() string {
	return m.runtimeName
}
```

### Version

```go
// Version方法返回容器运行时的版本信息。
func (m *kubeGenericRuntimeManager) Version(ctx context.Context) (kubecontainer.Version, error) {
	// 调用getTypedVersion方法获取类型化的版本信息
	typedVersion, err := m.getTypedVersion(ctx)
	if err != nil {
		return nil, err
	}

	// 根据类型化版本信息创建新的运行时版本对象并返回
	return newRuntimeVersion(typedVersion.RuntimeVersion)
}
```

#### getTypedVersion

```go
// getTypedVersion方法获取类型化的版本信息。
func (m *kubeGenericRuntimeManager) getTypedVersion(ctx context.Context) (*runtimeapi.VersionResponse, error) {
	// 调用runtimeService的Version方法获取远程运行时的类型化版本信息
	typedVersion, err := m.runtimeService.Version(ctx, kubeRuntimeAPIVersion)
	if err != nil {
		return nil, fmt.Errorf("获取远程运行时类型化版本信息失败：%v", err)
	}
	return typedVersion, nil
}
```

#### newRuntimeVersion

```go
// newRuntimeVersion根据给定的版本字符串创建运行时版本对象。
func newRuntimeVersion(version string) (*utilversion.Version, error) {
	// 尝试解析版本字符串为语义化的版本对象
	if ver, err := utilversion.ParseSemantic(version); err == nil {
		return ver, err
	}
	// 如果解析失败，则使用通用的版本解析方法
	return utilversion.ParseGeneric(version)
}
```

### APIVersion

```go
// APIVersion方法返回容器运行时的缓存的API版本信息。
// 实现预期会定期更新此缓存。
// 此版本信息可能与运行时引擎的版本不同。
func (m *kubeGenericRuntimeManager) APIVersion() (kubecontainer.Version, error) {
	// 从版本缓存中获取版本信息对象
	versionObject, err := m.versionCache.Get(m.machineInfo.MachineID)
	if err != nil {
		return nil, err
	}
	typedVersion := versionObject.(*runtimeapi.VersionResponse)

	// 根据类型化版本信息创建新的运行时版本对象并返回
	return newRuntimeVersion(typedVersion.RuntimeApiVersion)
}
```

### Status

```go
// Status方法返回运行时的状态。如果Status函数本身失败，则返回错误，否则返回nil。
func (m *kubeGenericRuntimeManager) Status(ctx context.Context) (*kubecontainer.RuntimeStatus, error) {
	// 调用runtimeService的Status方法获取运行时的状态信息
	resp, err := m.runtimeService.Status(ctx, false)
	if err != nil {
		return nil, err
	}
	if resp.GetStatus() == nil {
		return nil, errors.New("运行时状态为空")
	}
	// 将获取的状态信息转换为kubecontainer.RuntimeStatus对象并返回
	return toKubeRuntimeStatus(resp.GetStatus()), nil
}
```

### GetPods

```go
// GetPods方法返回按照Pod分组的容器列表。布尔参数指定运行时是否返回所有容器，包括已退出和已停止的容器（用于垃圾回收）。
func (m *kubeGenericRuntimeManager) GetPods(ctx context.Context, all bool) ([]*kubecontainer.Pod, error) {
	pods := make(map[kubetypes.UID]*kubecontainer.Pod)
	// 调用getKubeletSandboxes方法获取kubelet管理的 sandbox 列表
	sandboxes, err := m.getKubeletSandboxes(ctx, all)
	if err != nil {
		return nil, err
	}
	for i := range sandboxes {
		s := sandboxes[i]
		if s.Metadata == nil {
			klog.V(4).InfoS(" sandbox 没有元数据", "sandbox", s)
			continue
		}
		podUID := kubetypes.UID(s.Metadata.Uid)
		if _, ok := pods[podUID]; !ok {
			// 如果podUID不存在于pods中，则创建新的kubecontainer.Pod对象并添加到pods中
			pods[podUID] = &kubecontainer.Pod{
				ID:        podUID,
				Name:      s.Metadata.Name,
				Namespace: s.Metadata.Namespace,
			}
		}
		p := pods[podUID]
		// 将 sandbox 转换为kubecontainer.Container对象，并将其添加到对应的Pod的Sandboxes列表中
		converted, err := m.sandboxToKubeContainer(s)
		if err != nil {
			klog.V(4).InfoS("转换Pod的 sandbox 失败", "runtimeName", m.runtimeName, "sandbox", s, "podUID", podUID, "err", err)
			continue
		}
		p.Sandboxes = append(p.Sandboxes, converted)
		p.CreatedAt = uint64(s.GetCreatedAt())
	}

	// 调用getKubeletContainers方法获取kubelet管理的容器列表
	containers, err := m.getKubeletContainers(ctx, all)
	if err != nil {
		return nil, err
	}
	for i := range containers {
		c := containers[i]
		if c.Metadata == nil {
			klog.V(4).InfoS("容器没有元数据", "container", c)
			continue
		}

		// 从容器的标签中获取容器信息
		labelledInfo := getContainerInfoFromLabels(c.Labels)
		// 根据PodUID查找对应的Pod对象，如果不存在则创建新的Pod对象并添加到pods中
		pod, found := pods[labelledInfo.PodUID]
		if !found {
			pod = &kubecontainer.Pod{
				ID:        labelledInfo.PodUID,
				Name:      labelledInfo.PodName,
				Namespace: labelledInfo.PodNamespace,
			}
			pods[labelledInfo.PodUID] = pod
		}

		// 将容器转换为kubecontainer.Container对象，并将其添加到对应的Pod的Containers列表中
		converted, err := m.toKubeContainer(c)
		if err != nil {
			klog.V(4).InfoS("转换Pod的容器失败", "runtimeName", m.runtimeName, "container", c, "podUID", labelledInfo.PodUID, "err", err)
			continue
		}

		pod.Containers = append(pod.Containers, converted)
	}

	// 将map转换为列表
	var result []*kubecontainer.Pod
	for _, pod := range pods {
		result = append(result, pod)
	}

	// 由于存在多个并行运行的具有相同名称的Pod的情况，
	// 因为其中一个Pod尚未完全终止，为了避免基于容器名称的搜索出现意外行为
	//（例如通过调用*Kubelet.findContainer()而不指定pod ID），现在按照它们的创建时间顺序返回Pod列表。
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})
	klog.V(4).InfoS("从运行时获取了Pod列表", "all", all)
	return result, nil
}
```

#### getKubeletSandboxes

```go
// getKubeletSandboxes列出kubelet管理的所有（或仅运行中的） sandbox 。
func (m *kubeGenericRuntimeManager) getKubeletSandboxes(ctx context.Context, all bool) ([]*runtimeapi.PodSandbox, error) {
	var filter *runtimeapi.PodSandboxFilter
	if !all {
		readyState := runtimeapi.PodSandboxState_SANDBOX_READY
		filter = &runtimeapi.PodSandboxFilter{
			State: &runtimeapi.PodSandboxStateValue{
				State: readyState,
			},
		}
	}

	// 调用runtimeService的ListPodSandbox方法获取 sandbox 列表
	resp, err := m.runtimeService.ListPodSandbox(ctx, filter)
	if err != nil {
		klog.ErrorS(err, "列举 sandbox 失败")
		return nil, err
	}

	return resp, nil
}
```

#### sandboxToKubeContainer

```go
// sandboxToKubeContainer将runtimeapi.PodSandbox转换为kubecontainer.Container。
// 这只是为了返回 sandbox ，就好像它们是kubecontainer.Containers，以避免对PLEG进行重大更改。
// TODO：一旦它变得过时，就删除这个函数。
func (m *kubeGenericRuntimeManager) sandboxToKubeContainer(s *runtimeapi.PodSandbox) (*kubecontainer.Container, error) {
	if s == nil || s.Id == "" {
		return nil, fmt.Errorf("无法将nil指针转换为运行时容器")
	}

	return &kubecontainer.Container{
		ID:    kubecontainer.ContainerID{Type: m.runtimeName, ID: s.Id},
		State: kubecontainer.SandboxToContainerState(s.State),
	}, nil
}
```

#### getKubeletContainers

```go
// getKubeletContainers列出kubelet管理的容器。
// 布尔参数指定是否返回所有容器，包括已退出和已停止的容器（用于垃圾回收）。
func (m *kubeGenericRuntimeManager) getKubeletContainers(ctx context.Context, allContainers bool) ([]*runtimeapi.Container, error) {
	filter := &runtimeapi.ContainerFilter{}
	if !allContainers {
		filter.State = &runtimeapi.ContainerStateValue{
			State: runtimeapi.ContainerState_CONTAINER_RUNNING,
		}
	}

	// 调用runtimeService的ListContainers方法获取容器列表
	containers, err := m.runtimeService.ListContainers(ctx, filter)
	if err != nil {
		klog.ErrorS(err, "ListContainers失败")
		return nil, err
	}

	return containers, nil
}
```

#### getContainerInfoFromLabels

```go
// 从标签中获取labeledContainerInfo的函数。
func getContainerInfoFromLabels(labels map[string]string) *labeledContainerInfo {
	return &labeledContainerInfo{
		PodName:       getStringValueFromLabel(labels, types.KubernetesPodNameLabel),
		PodNamespace:  getStringValueFromLabel(labels, types.KubernetesPodNamespaceLabel),
		PodUID:        kubetypes.UID(getStringValueFromLabel(labels, types.KubernetesPodUIDLabel)),
		ContainerName: getStringValueFromLabel(labels, types.KubernetesContainerNameLabel),
	}
}
```

### GarbageCollect

```go
// GarbageCollect使用指定的容器GC策略删除死亡容器。
func (m *kubeGenericRuntimeManager) GarbageCollect(ctx context.Context, gcPolicy kubecontainer.GCPolicy, allSourcesReady bool, evictNonDeletedPods bool) error {
    // 调用containerGC的GarbageCollect方法执行垃圾回收操作
    return m.containerGC.GarbageCollect(ctx, gcPolicy, allSourcesReady, evictNonDeletedPods)
}
```

### SyncPod

```go
// SyncPod同步正在运行的Pod到期望的Pod，执行以下步骤：
//
// 1. 计算沙盒和容器的变化。
// 2. 如果需要，杀死Pod的沙盒。
// 3. 杀死不应该运行的任何容器。
// 4. 如果需要，创建沙盒。
// 5. 创建临时容器。
// 6. 创建初始化容器。
// 7. 调整正在运行的容器的大小（如果InPlacePodVerticalScaling==true）。
// 8. 创建普通容器。
func (m *kubeGenericRuntimeManager) SyncPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, pullSecrets []v1.Secret, backOff *flowcontrol.Backoff) (result kubecontainer.PodSyncResult) {
	// 第一步：计算沙盒和容器的变化。
	podContainerChanges := m.computePodActions(ctx, pod, podStatus)
	klog.V(3).InfoS("computePodActions got for pod", "podActions", podContainerChanges, "pod", klog.KObj(pod))
	if podContainerChanges.CreateSandbox {
		ref, err := ref.GetReference(legacyscheme.Scheme, pod)
		if err != nil {
			klog.ErrorS(err, "Couldn't make a ref to pod", "pod", klog.KObj(pod))
		}
		if podContainerChanges.SandboxID != "" {
			m.recorder.Eventf(ref, v1.EventTypeNormal, events.SandboxChanged, "Pod sandbox changed, it will be killed and re-created.")
		} else {
			klog.V(4).InfoS("SyncPod received new pod, will create a sandbox for it", "pod", klog.KObj(pod))
		}
	}
	// 第二步：如果沙盒发生变化，杀死Pod。
	if podContainerChanges.KillPod {
		if podContainerChanges.CreateSandbox {
			klog.V(4).InfoS("Stopping PodSandbox for pod, will start new one", "pod", klog.KObj(pod))
		} else {
			klog.V(4).InfoS("Stopping PodSandbox for pod, because all other containers are dead", "pod", klog.KObj(pod))
		}

		killResult := m.killPodWithSyncResult(ctx, pod, kubecontainer.ConvertPodStatusToRunningPod(m.runtimeName, podStatus), nil)
		result.AddPodSyncResult(killResult)
		if killResult.Error() != nil {
			klog.ErrorS(killResult.Error(), "killPodWithSyncResult failed")
			return
		}

		if podContainerChanges.CreateSandbox {
			m.purgeInitContainers(ctx, pod, podStatus)
		}
	} else {
		// 第三步：杀死不需要运行的容器。
		for containerID, containerInfo := range podContainerChanges.ContainersToKill {
			klog.V(3).InfoS("Killing unwanted container for pod", "containerName", containerInfo.name, "containerID", containerID, "pod", klog.KObj(pod))
			killContainerResult := kubecontainer.NewSyncResult(kubecontainer.KillContainer, containerInfo.name)
			result.AddSyncResult(killContainerResult)
			if err := m.killContainer(ctx, pod, containerID, containerInfo.name, containerInfo.message, containerInfo.reason, nil); err != nil {
				killContainerResult.Fail(kubecontainer.ErrKillContainer, err.Error())
				klog.ErrorS(err, "killContainer for pod failed", "containerName", containerInfo.name, "containerID", containerID, "pod", klog.KObj(pod))
				return
			}
		}
	}
	// 优化措施，对已终止的 init containers 进行相对严格的控制
	// 这是一种优化，因为容器的移除通常由容器垃圾回收器处理。
	m.pruneInitContainersBeforeStart(ctx, pod, podStatus)

	// 我们将 PRIMARY podIP 的值和 podIPs 列表传递给 generatePodSandboxConfig 和 generateContainerConfig，
	// 这些函数进一步将其传递给其他各种函数，以便实现需要这个值的功能（如主机文件和向下 API），
	// 并避免在容器需要重新启动但 podIP 尚未在状态管理器中时确定 pod IP 的竞争。
	// podIPs 列表用于生成主机文件。
	//
	// 我们默认使用传入的 pod status 中的 IPs，并在需要（重新）启动沙箱时进行覆盖。
	var podIPs []string
	if podStatus != nil {
		podIPs = podStatus.IPs
	}
	// Step 4: Create a sandbox for the pod if necessary.
	// 如果需要，为 pod 创建一个沙箱。
	podSandboxID := podContainerChanges.SandboxID
	// 如果podContainerChanges.CreateSandbox为真，则执行以下代码块
	if podContainerChanges.CreateSandbox {
		var msg string
		var err error
		// 输出日志信息，表示正在为Pod创建PodSandbox
		klog.V(4).InfoS("Creating PodSandbox for pod", "pod", klog.KObj(pod))
		// 增加已启动Pod的计数
		metrics.StartedPodsTotal.Inc()
		// 创建一个与Pod创建PodSandbox相关的同步结果对象，并将其添加到结果集中
		createSandboxResult := kubecontainer.NewSyncResult(kubecontainer.CreatePodSandbox, format.Pod(pod))
		result.AddSyncResult(createSandboxResult)

		// ConvertPodSysctlsVariableToDotsSeparator函数将Pod.Spec.SecurityContext.Sysctls切片中的sysctl变量
		// 转换为点分隔符。runc使用点作为分隔符来验证sysctl变量是否在单独的内核命名空间中是正确的，因此当使用斜杠作为sysctl变量分隔符时，
		// runc会返回错误："sysctl is not in a separate kernel namespace"，导致无法成功创建podSandBox。
		// 因此，在调用runc之前，我们需要将sysctl变量转换为使用点作为分隔符来分隔内核命名空间。
		// 当runc支持斜杠作为sysctl分隔符时，将不再需要使用此函数。
		sysctl.ConvertPodSysctlsVariableToDotsSeparator(pod.Spec.SecurityContext)

		// 如果启用了Dynamic Resource Allocation功能，则准备为Pod分配的动态资源
		if utilfeature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation) {
			if m.runtimeHelper.PrepareDynamicResources(pod) != nil {
				return
			}
		}

		// 调用createPodSandbox函数创建PodSandbox，并返回podSandboxID、msg和err
		podSandboxID, msg, err = m.createPodSandbox(ctx, pod, podContainerChanges.Attempt)
		if err != nil {
			// 如果createPodSandbox返回的错误是由于Pod已被删除而导致的（例如CNI、CSI或CRI错误），
			// 则不视为真正的错误。
			// 当我们到达这里时，SyncPod可能仍在运行，这意味着PodWorker尚未确认删除操作。
			if m.podStateProvider.IsPodTerminationRequested(pod.UID) {
				// 输出日志信息，表示Pod已被删除且无法创建sandbox
				klog.V(4).InfoS("Pod was deleted and sandbox failed to be created", "pod", klog.KObj(pod), "podUID", pod.UID)
				return
			}
			// 增加创建PodSandbox失败的计数
			metrics.StartedPodsErrorsTotal.Inc()
			// 标记createSandboxResult为失败，并设置错误信息
			createSandboxResult.Fail(kubecontainer.ErrCreatePodSandbox, msg)
			// 输出错误日志，表示创建PodSandbox失败
			klog.ErrorS(err, "CreatePodSandbox for pod failed", "pod", klog.KObj(pod))
			// 获取Pod的引用信息
			ref, referr := ref.GetReference(legacyscheme.Scheme, pod)
			if referr != nil {
				klog.ErrorS(referr, "Couldn't make a ref to pod", "pod", klog.KObj(pod))
			}
			// 记录事件，表示创建PodSandbox失败
			m.recorder.Eventf(ref, v1.EventTypeWarning, events.FailedCreatePodSandBox, "Failed to create pod sandbox: %v", err)
			return
		}
		// 输出日志信息，表示已成功创建PodSandbox
		klog.V(4).InfoS("Created PodSandbox for pod", "podSandboxID", podSandboxID, "pod", klog.KObj(pod))

		// 调用runtimeService.PodSandboxStatus获取PodSandbox的状态
		resp, err := m.runtimeService.PodSandboxStatus(ctx, podSandboxID, false)
		if err != nil {
			// 获取Pod的引用信息
			ref, referr := ref.GetReference(legacyscheme.Scheme, pod)
			if referr != nil {
				klog.ErrorS(referr, "Couldn't make a ref to pod", "pod", klog.KObj(pod))
			}
			// 记录事件，表示无法获取PodSandbox的状态
			m.recorder.Eventf(ref, v1.EventTypeWarning, events.FailedStatusPodSandBox, "Unable to get pod sandbox status: %v", err)
			// 输出错误日志，表示获取PodSandbox状态失败
			klog.ErrorS(err, "Failed to get pod sandbox status; Skipping pod", "pod", klog.KObj(pod))
			// 标记result为失败，并设置错误信息
			result.Fail(err)
			return
		}
		if resp.GetStatus() == nil {
			// 标记result为失败，并设置错误信息
			result.Fail(errors.New("pod sandbox status is nil"))
			return
		}

		// 如果Pod不是使用主机网络，则确定PodSandbox的IP，并更新podIPs
		if !kubecontainer.IsHostNetworkPod(pod) {
			// 确定PodSandbox的IP
			podIPs = m.determinePodSandboxIPs(pod.Namespace, pod.Name, resp.GetStatus())
			// 输出日志信息，表示在sandbox变更后确定了Pod的IP
			klog.V(4).InfoS("Determined the ip for pod after sandbox changed", "IPs", podIPs, "pod", klog.KObj(pod))
		}
	}
	// 创建一个与PodSandbox配置相关的同步结果对象，并将其添加到结果集中
	configPodSandboxResult := kubecontainer.NewSyncResult(kubecontainer.ConfigPodSandbox, podSandboxID)
	result.AddSyncResult(configPodSandboxResult)
	// 生成PodSandbox的配置
	podSandboxConfig, err := m.generatePodSandboxConfig(pod, podContainerChanges.Attempt)
	if err != nil {
		message := fmt.Sprintf("GeneratePodSandboxConfig for pod %q failed: %v", format.Pod(pod), err)
		// 输出错误日志，表示生成PodSandbox配置失败
		klog.ErrorS(err, "GeneratePodSandboxConfig for pod failed", "pod", klog.KObj(pod))
		// 标记configPodSandboxResult为失败，并设置错误信息
		configPodSandboxResult.Fail(kubecontainer.ErrConfigPodSandbox, message)
		return
	}

	// 定义一个名为"start"的辅助函数，用于启动各种类型的容器。
	// typeName是用于在日志消息中描述此类型容器的描述，
	// 目前有："container"、"init container"或"ephemeral container"。
	// metricLabel是用于在监控指标中描述此类型容器的标签，
	// 目前有："container"、"init_container"或"ephemeral_container"。
	start := func(ctx context.Context, typeName, metricLabel string, spec *startSpec) error {
		// 创建一个与启动容器操作相关的同步结果对象，并将其添加到结果集中
		startContainerResult := kubecontainer.NewSyncResult(kubecontainer.StartContainer, spec.container.Name)
		result.AddSyncResult(startContainerResult)
		// 检查容器是否处于退避状态，并获取退避相关的错误信息
		isInBackOff, msg, err := m.doBackOff(pod, spec.container, podStatus, backOff)
		if isInBackOff {
			// 标记startContainerResult为失败，并设置退避错误信息
			startContainerResult.Fail(err, msg)
			// 输出日志信息，表示正在退避重启容器
			klog.V(4).InfoS("Backing Off restarting container in pod", "containerType", typeName, "container", spec.container, "pod", klog.KObj(pod))
			return err
		}

		// 增加相应的容器启动计数指标
		metrics.StartedContainersTotal.WithLabelValues(metricLabel).Inc()
		if sc.HasWindowsHostProcessRequest(pod, spec.container) {
			metrics.StartedHostProcessContainersTotal.WithLabelValues(metricLabel).Inc()
		}
		// 输出日志信息，表示正在为Pod创建容器
		klog.V(4).InfoS("Creating container in pod", "containerType", typeName, "container", spec.container, "pod", klog.KObj(pod))
		// 注意：此处仅发送podIPs，适用于单栈和双栈集群
		if msg, err := m.startContainer(ctx, podSandboxID, podSandboxConfig, spec, pod, podStatus, pullSecrets, podIP, podIPs); err != nil {
			// startContainer()返回具有合理基数的良好定义的错误代码，这些错误代码对于指标有用，可以使集群管理员区分“服务器错误”和“用户错误”。
			metrics.StartedContainersErrorsTotal.WithLabelValues(metricLabel, err.Error()).Inc()
			if sc.HasWindowsHostProcessRequest(pod, spec.container) {
				metrics.StartedHostProcessContainersErrorsTotal.WithLabelValues(metricLabel, err.Error()).Inc()
			}
			// 标记startContainerResult为失败，并设置错误信息
			startContainerResult.Fail(err, msg)
			// 根据错误类型进行日志记录，避免重复日志
			switch {
			case err == images.ErrImagePullBackOff:
				klog.V(3).InfoS("Container start failed in pod", "containerType", typeName, "container", spec.container, "pod", klog.KObj(pod), "containerMessage", msg, "err", err)
			default:
				utilruntime.HandleError(fmt.Errorf("%v %+v start failed in pod %v: %v: %s", typeName, spec.container, format.Pod(pod), err, msg))
			}
			return err
		}

		return nil
	}
	// 步骤5：启动临时容器（ephemeral containers）
	// 为了在启动init容器时发生错误时仍然能够运行临时容器，先启动临时容器。
	// 实际上，init容器会先启动，因为临时容器不能在创建Pod时指定。
	for _, idx := range podContainerChanges.EphemeralContainersToStart {
		start(ctx, "ephemeral container", metrics.EphemeralContainer, ephemeralContainerStartSpec(&pod.Spec.EphemeralContainers[idx]))
	}

	// 步骤6：启动init容器
	if container := podContainerChanges.NextInitContainerToStart; container != nil {
		// 启动下一个init容器
		if err := start(ctx, "init container", metrics.InitContainer, containerStartSpec(container)); err != nil {
			return
		}
		// 成功启动容器，清除失败记录
		klog.V(4).InfoS("Completed init container for pod", "containerName", container.Name, "pod", klog.KObj(pod))
	}
	// 步骤7：对podContainerChanges.ContainersToUpdate[CPU,Memory]列表中的容器，调用UpdateContainerResources
	if isInPlacePodVerticalScalingAllowed(pod) {
		if len(podContainerChanges.ContainersToUpdate) > 0 || podContainerChanges.UpdatePodResources {
			m.doPodResizeAction(pod, podStatus, podContainerChanges, result)
		}
	}

	// 步骤8：启动podContainerChanges.ContainersToStart列表中的容器
	for _, idx := range podContainerChanges.ContainersToStart {
		start(ctx, "container", metrics.Container, containerStartSpec(&pod.Spec.Containers[idx]))
	}
	return
}
```

#### computePodActions

```go
// computePodActions函数用于检查Pod规范是否发生了变化，并在发生变化时返回相应的更改。
func (m *kubeGenericRuntimeManager) computePodActions(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) podActions {
	klog.V(5).InfoS("Syncing Pod", "pod", klog.KObj(pod)) // 打印日志，同步Pod
	createPodSandbox, attempt, sandboxID := runtimeutil.PodSandboxChanged(pod, podStatus)
	changes := podActions{
		KillPod:           createPodSandbox,
		CreateSandbox:     createPodSandbox,
		SandboxID:         sandboxID,
		Attempt:           attempt,
		ContainersToStart: []int{},
		ContainersToKill:  make(map[kubecontainer.ContainerID]containerToKillInfo),
	}

	// 如果需要（重新）创建Pod沙箱，需要杀掉并重新创建所有容器，同时清除init容器。
	if createPodSandbox {
		if !shouldRestartOnFailure(pod) && attempt != 0 && len(podStatus.ContainerStatuses) != 0 {
			// 不应重新启动Pod，直接返回。
			// 如果Pod已完成，则不应为其创建沙箱。
			// 如果所有容器都已完成且不应启动，就没有必要创建新的沙箱。
			// 这样可以避免在容器全部具有退出代码的Pod上出现混淆的日志，但是我们在终止之前重新创建沙箱。
			//
			// 如果ContainerStatuses为空，我们假设我们从未成功创建过任何容器。在这种情况下，我们应该重试创建沙箱。
			changes.CreateSandbox = false
			return changes
		}

		// 获取要启动的容器，如果RestartPolicy是OnFailure，则排除已成功的容器。
		var containersToStart []int
		for idx, c := range pod.Spec.Containers {
			if pod.Spec.RestartPolicy == v1.RestartPolicyOnFailure && containerSucceeded(&c, podStatus) {
				continue
			}
			containersToStart = append(containersToStart, idx)
		}
		// 如果没有容器要启动，则不应为Pod创建沙箱，前提是初始化已完成。
		if len(containersToStart) == 0 {
			_, _, done := findNextInitContainerToRun(pod, podStatus)
			if done {
				changes.CreateSandbox = false
				return changes
			}
		}

		if len(pod.Spec.InitContainers) != 0 {
			// Pod有init容器，返回第一个。
			changes.NextInitContainerToStart = &pod.Spec.InitContainers[0]
			return changes
		}
		changes.ContainersToStart = containersToStart
		return changes
	}

	// 即使初始化尚未完成，也可能启动临时容器。
	for i := range pod.Spec.EphemeralContainers {
		c := (*v1.Container)(&pod.Spec.EphemeralContainers[i].EphemeralContainerCommon)

		// 临时容器不会重新启动
		if podStatus.FindContainerStatusByName(c.Name) == nil {
			changes.EphemeralContainersToStart = append(changes.EphemeralContainersToStart, i)
		}
	}

	// 检查初始化进度。
	initLastStatus, next, done := findNextInitContainerToRun(pod, podStatus)
	// 检查是否还有未完成的初始化容器
	if !done {
		// 如果存在下一个要运行的初始化容器
		if next != nil {
			// 检查上一个初始化容器的状态是否是失败的
			initFailed := initLastStatus != nil && isInitContainerFailed(initLastStatus)
			// 如果上一个初始化容器失败且不应在失败时重启，则设置KillPod为true
			if initFailed && !shouldRestartOnFailure(pod) {
				changes.KillPod = true
			} else {
				// 总是先尝试停止处于未知状态的容器
				if initLastStatus != nil && initLastStatus.State == kubecontainer.ContainerStateUnknown {
					// 如果初始化容器的状态是未知的，尝试在重启之前将其杀死
					changes.ContainersToKill[initLastStatus.ID] = containerToKillInfo{
						name:      next.Name,
						container: next,
						message: fmt.Sprintf("Init container is in %q state, try killing it before restart",
							initLastStatus.State),
						reason: reasonUnknown,
					}
				}
				changes.NextInitContainerToStart = next
			}
		}
		// 初始化失败或尚未完成。跳过检查非初始化容器。
		return changes
	}

	// 如果允许原地垂直缩放Pod，则进行相关操作
	if isInPlacePodVerticalScalingAllowed(pod) {
		changes.ContainersToUpdate = make(map[v1.ResourceName][]containerToUpdateInfo)
		// 获取最新的Pod状态
		latestPodStatus, err := m.GetPodStatus(ctx, podStatus.ID, pod.Name, pod.Namespace)
		if err == nil {
			podStatus = latestPodStatus
		}
	}

	// 需要保留的运行容器数量
	keepCount := 0
	// 检查容器的状态
	for idx, container := range pod.Spec.Containers {
		containerStatus := podStatus.FindContainerStatusByName(container.Name)

		// 对于任何非运行中的容器，调用内部容器的后停止生命周期钩子，以便立即释放分配的CPU。
		// 如果容器重新启动，CPU将重新分配给它。
		if containerStatus != nil && containerStatus.State != kubecontainer.ContainerStateRunning {
			if err := m.internalLifecycle.PostStopContainer(containerStatus.ID.ID); err != nil {
				klog.ErrorS(err, "Internal container post-stop lifecycle hook failed for container in pod with error",
					"containerName", container.Name, "pod", klog.KObj(pod))
			}
		}

		// 如果容器不存在或不在运行状态，则检查是否需要重新启动它。
		if containerStatus == nil || containerStatus.State != kubecontainer.ContainerStateRunning {
			if kubecontainer.ShouldContainerBeRestarted(&container, pod, podStatus) {
				klog.V(3).InfoS("Container of pod is not in the desired state and shall be started", "containerName", container.Name, "pod", klog.KObj(pod))
				changes.ContainersToStart = append(changes.ContainersToStart, idx)
				if containerStatus != nil && containerStatus.State == kubecontainer.ContainerStateUnknown {
					// 如果容器处于未知状态，我们不知道它实际上是否正在运行，总是在重新启动之前尝试杀死它，以避免同时运行两个相同容器的实例。
					changes.ContainersToKill[containerStatus.ID] = containerToKillInfo{
						name:      containerStatus.Name,
						container: &pod.Spec.Containers[idx],
						message: fmt.Sprintf("Container is in %q state, try killing it before restart",
							containerStatus.State),
						reason: reasonUnknown,
					}
				}
			}
			continue
		}
		// 容器正在运行，但如果满足以下任一条件，则杀死容器。
		var message string
		var reason containerKillReason
		restart := shouldRestartOnFailure(pod)
		// 如果启用了InPlacePodVerticalScaling，并且只有Resources字段发生了更改
		if _, _, changed := containerChanged(&container, containerStatus); changed &&
			(!isInPlacePodVerticalScalingAllowed(pod) ||
				kubecontainer.HashContainerWithoutResources(&container) != containerStatus.HashWithoutResources) {
			message = fmt.Sprintf("Container %s definition changed", container.Name)
			// 由于容器规范发生了更改，无论重启策略如何，都要重新启动。
			restart = true
		} else if liveness, found := m.livenessManager.Get(containerStatus.ID); found && liveness == proberesults.Failure {
			// 如果容器的存活探针失败，则应该杀死它。
			message = fmt.Sprintf("Container %s failed liveness probe", container.Name)
			reason = reasonLivenessProbe
		} else if startup, found := m.startupManager.Get(containerStatus.ID); found && startup == proberesults.Failure {
			// 如果容器的启动探针失败，则应该杀死它。
			message = fmt.Sprintf("Container %s failed startup probe", container.Name)
			reason = reasonStartupProbe
		} else if isInPlacePodVerticalScalingAllowed(pod) && !m.computePodResizeAction(pod, idx, containerStatus, &changes) {
			// 如果启用了原地垂直缩放Pod，并且不需要重启该容器，则继续下一个容器的检查。
			continue
		} else {
			// 保留容器。
			keepCount++
			continue
		}

		// 我们需要杀死容器，但如果我们还想重新启动容器，请在消息中明确表明意图。
		// 并且不要杀死整个Pod，因为我们预期容器最终会运行。
		if restart {
			message = fmt.Sprintf("%s, will be restarted", message)
			changes.ContainersToStart = append(changes.ContainersToStart, idx)
		}

		changes.ContainersToKill[containerStatus.ID] = containerToKillInfo{
			name:      containerStatus.Name,
			container: &pod.Spec.Containers[idx],
			message:   message,
			reason:    reason,
		}
		klog.V(2).InfoS("Message for Container of pod", "containerName", container.Name, "containerStatusID", containerStatus.ID, "pod", klog.KObj(pod), "containerMessage", message)
	}
	// 如果保留的运行容器数量为0且没有要启动的容器，则将KillPod设置为true。
	if keepCount == 0 && len(changes.ContainersToStart) == 0 {
		changes.KillPod = true
	}
	return changes
}
```

##### findNextInitContainerToRun

```go
// findNextInitContainerToRun函数返回最后一个失败容器的状态，下一个要启动的init容器的索引，或者如果没有更多init容器，则返回done。
// 只有在init容器失败时才返回状态，此时next将指向当前容器。
func findNextInitContainerToRun(pod *v1.Pod, podStatus *kubecontainer.PodStatus) (status *kubecontainer.Status, next *v1.Container, done bool) {
	// 如果没有init容器，则直接返回
	if len(pod.Spec.InitContainers) == 0 {
		return nil, nil, true
	}
	// 如果任何主容器具有状态并且正在运行，则说明所有的init容器都已经执行过。
	// 但是，它们可能已经从容器运行时中删除了，如果我们继续执行，将会出现它们从未运行过并且将重新执行的情况。
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		status := podStatus.FindContainerStatusByName(container.Name)
		if status != nil && status.State == kubecontainer.ContainerStateRunning {
			return nil, nil, true
		}
	}

	// 如果存在失败的容器，则返回最后一个失败容器的状态。
	for i := len(pod.Spec.InitContainers) - 1; i >= 0; i-- {
		container := &pod.Spec.InitContainers[i]
		status := podStatus.FindContainerStatusByName(container.Name)
		if status != nil && isInitContainerFailed(status) {
			return status, container, false
		}
	}

	// 现在没有失败的容器。
	for i := len(pod.Spec.InitContainers) - 1; i >= 0; i-- {
		container := &pod.Spec.InitContainers[i]
		status := podStatus.FindContainerStatusByName(container.Name)
		if status == nil {
			continue
		}

		// 容器仍在运行，返回未完成。
		if status.State == kubecontainer.ContainerStateRunning {
			return nil, nil, false
		}

		if status.State == kubecontainer.ContainerStateExited {
			// 所有init容器都成功执行
			if i == (len(pod.Spec.InitContainers) - 1) {
				return nil, nil, true
			}

			// 所有容器直到索引i都成功执行，进入索引i+1
			return nil, &pod.Spec.InitContainers[i+1], false
		}
	}

	return nil, &pod.Spec.InitContainers[0], false
}
```

#### ConvertPodStatusToRunningPod

```go
// ConvertPodStatusToRunningPod函数根据PodStatus和容器运行时字符串返回Pod。
// TODO（random-liu）：将PodStatus转换为正在运行的Pod，应该很快就会被弃用。
func ConvertPodStatusToRunningPod(runtimeName string, podStatus *PodStatus) Pod {
	runningPod := Pod{
		ID:        podStatus.ID,
		Name:      podStatus.Name,
		Namespace: podStatus.Namespace,
	}

	// 遍历容器状态，将状态为ContainerStateRunning的容器添加到runningPod的Containers列表中
	for _, containerStatus := range podStatus.ContainerStatuses {
		if containerStatus.State != ContainerStateRunning {
			continue
		}
		container := &Container{
			ID:                   containerStatus.ID,
			Name:                 containerStatus.Name,
			Image:                containerStatus.Image,
			ImageID:              containerStatus.ImageID,
			Hash:                 containerStatus.Hash,
			HashWithoutResources: containerStatus.HashWithoutResources,
			State:                containerStatus.State,
		}
		runningPod.Containers = append(runningPod.Containers, container)
	}

	// 填充kubecontainer.Pod中的沙箱信息
	for _, sandbox := range podStatus.SandboxStatuses {
		runningPod.Sandboxes = append(runningPod.Sandboxes, &Container{
			ID:    ContainerID{Type: runtimeName, ID: sandbox.Id},
			State: SandboxToContainerState(sandbox.State),
		})
	}

	return runningPod
}
```

#### killPodWithSyncResult

```go
// killPodWithSyncResult函数杀死一个runningPod并返回SyncResult。
// 注意：传入的pod可能为nil，当kubelet重新启动时。
func (m *kubeGenericRuntimeManager) killPodWithSyncResult(ctx context.Context, pod *v1.Pod, runningPod kubecontainer.Pod, gracePeriodOverride *int64) (result kubecontainer.PodSyncResult) {
	// 使用killContainersWithSyncResult函数杀死所有容器，并将结果合并到result中
	killContainerResults := m.killContainersWithSyncResult(ctx, pod, runningPod, gracePeriodOverride)
	for _, containerResult := range killContainerResults {
		result.AddSyncResult(containerResult)
	}

	// 停止沙箱，沙箱将在GarbageCollect中被删除
	killSandboxResult := kubecontainer.NewSyncResult(kubecontainer.KillPodSandbox, runningPod.ID)
	result.AddSyncResult(killSandboxResult)
	// 停止所有属于同一pod的沙箱
	for _, podSandbox := range runningPod.Sandboxes {
		if err := m.runtimeService.StopPodSandbox(ctx, podSandbox.ID.ID); err != nil && !crierror.IsNotFound(err) {
			killSandboxResult.Fail(kubecontainer.ErrKillPodSandbox, err.Error())
			klog.ErrorS(nil, "Failed to stop sandbox", "podSandboxID", podSandbox.ID)
		}
	}

	return
}
```

##### killContainersWithSyncResult

```go
// killContainersWithSyncResult函数以同步的方式杀死所有pod的容器，并返回同步结果列表。
func (m *kubeGenericRuntimeManager) killContainersWithSyncResult(ctx context.Context, pod *v1.Pod, runningPod kubecontainer.Pod, gracePeriodOverride *int64) (syncResults []*kubecontainer.SyncResult) {
	containerResults := make(chan *kubecontainer.SyncResult, len(runningPod.Containers))
	wg := sync.WaitGroup{}

	wg.Add(len(runningPod.Containers))
	// 并发地杀死所有容器
	for _, container := range runningPod.Containers {
		go func(container *kubecontainer.Container) {
			defer utilruntime.HandleCrash()
			defer wg.Done()

			killContainerResult := kubecontainer.NewSyncResult(kubecontainer.KillContainer, container.Name)
			// 调用killContainer函数杀死容器，并将结果存储在killContainerResult中
			if err := m.killContainer(ctx, pod, container.ID, container.Name, "", reasonUnknown, gracePeriodOverride); err != nil {
				killContainerResult.Fail(kubecontainer.ErrKillContainer, err.Error())
				// 由于传入的pod可能为nil，因此在日志中使用runningPod进行记录。
				klog.ErrorS(err, "Kill container failed", "pod", klog.KRef(runningPod.Namespace, runningPod.Name), "podUID", runningPod.ID,
					"containerName", container.Name, "containerID", container.ID)
			}
			containerResults <- killContainerResult
		}(container)
	}
	wg.Wait()
	close(containerResults)

	// 从channel中接收容器的同步结果，并存储在syncResults中
	for containerResult := range containerResults {
		syncResults = append(syncResults, containerResult)
	}
	return
}
```

#### purgeInitContainers

```GO
// purgeInitContainers函数移除所有的初始化容器。注意，该函数不会检查容器的状态，
// 因为它假设在调用发生之前所有的初始化容器都已经停止。
func (m *kubeGenericRuntimeManager) purgeInitContainers(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) {
	// 创建一个包含初始化容器名称的集合
	initContainerNames := sets.NewString()
	for _, container := range pod.Spec.InitContainers {
		initContainerNames.Insert(container.Name)
	}

	// 遍历每个初始化容器名称
	for name := range initContainerNames {
		count := 0
		// 遍历PodStatus中的容器状态
		for _, status := range podStatus.ContainerStatuses {
			if status.Name != name {
				continue
			}
			count++
			// 删除匹配此容器名称的所有初始化容器
			klog.V(4).InfoS("Removing init container", "containerName", status.Name, "containerID", status.ID.ID, "count", count)
			if err := m.removeContainer(ctx, status.ID.ID); err != nil {
				utilruntime.HandleError(fmt.Errorf("failed to remove pod init container %q: %v; Skipping pod %q", status.Name, err, format.Pod(pod)))
				continue
			}
		}
	}
}
```

##### removeContainer

```GO
// removeContainer函数移除容器及其容器日志。
// 注意，我们先移除容器日志，以确保容器在日志移除失败时不会被移除，
// kubelet会在以后重试。这样可以保证容器日志随容器一起被移除。
// 注意，我们假设容器只能在非运行状态下移除，在那种状态下它不会再写入容器日志。
func (m *kubeGenericRuntimeManager) removeContainer(ctx context.Context, containerID string) error {
	klog.V(4).InfoS("Removing container", "containerID", containerID)
	// 调用内部容器的后停止生命周期钩子。
	if err := m.internalLifecycle.PostStopContainer(containerID); err != nil {
		return err
	}

	// 移除容器日志。
	// TODO：将日志和容器的生命周期管理分离。
	if err := m.removeContainerLog(ctx, containerID); err != nil {
		return err
	}
	// 移除容器。
	return m.runtimeService.RemoveContainer(ctx, containerID)
}
```

##### removeContainerLog

```GO
// removeContainerLog函数移除容器的日志。
func (m *kubeGenericRuntimeManager) removeContainerLog(ctx context.Context, containerID string) error {
	// 使用日志管理器移除已轮换的日志。
	err := m.logManager.Clean(ctx, containerID)
	if err != nil {
		return err
	}

	// 获取容器的状态。
	resp, err := m.runtimeService.ContainerStatus(ctx, containerID, false)
	if err != nil {
		return fmt.Errorf("failed to get container status %q: %v", containerID, err)
	}
	status := resp.GetStatus()
	if status == nil {
		return remote.ErrContainerStatusNil
	}
	// 移除旧版容器日志符号链接。
	// TODO（random-liu）：在集群日志记录支持CRI容器日志路径之后，将其移除。
	labeledInfo := getContainerInfoFromLabels(status.Labels)
	legacySymlink := legacyLogSymlink(containerID, labeledInfo.ContainerName, labeledInfo.PodName,
		labeledInfo.PodNamespace)
	if err := m.osInterface.Remove(legacySymlink); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove container %q log legacy symbolic link %q: %v",
			containerID, legacySymlink, err)
	}
	return nil
}
```

###### getContainerInfoFromLabels

```GO
// getContainerInfoFromLabels函数从标签中获取labeledContainerInfo。
func getContainerInfoFromLabels(labels map[string]string) *labeledContainerInfo {
	return &labeledContainerInfo{
		PodName:       getStringValueFromLabel(labels, types.KubernetesPodNameLabel),
		PodNamespace:  getStringValueFromLabel(labels, types.KubernetesPodNamespaceLabel),
		PodUID:        kubetypes.UID(getStringValueFromLabel(labels, types.KubernetesPodUIDLabel)),
		ContainerName: getStringValueFromLabel(labels, types.KubernetesContainerNameLabel),
	}
}
```

###### legacyLogSymlink

```GO
// legacyLogSymlink函数组合旧版容器日志路径。仅用于旧版集群日志支持。
func legacyLogSymlink(containerID string, containerName, podName, podNamespace string) string {
	return logSymlink(legacyContainerLogsDir, kubecontainer.BuildPodFullName(podName, podNamespace),
		containerName, containerID)
}
```

#### killContainer

```GO
// killContainer通过以下步骤来终止容器：
// * 运行pre-stop生命周期钩子（如果适用）。
// * 停止容器。
func (m *kubeGenericRuntimeManager) killContainer(ctx context.Context, pod *v1.Pod, containerID kubecontainer.ContainerID, containerName string, message string, reason containerKillReason, gracePeriodOverride *int64) error {
	var containerSpec *v1.Container
	if pod != nil {
		if containerSpec = kubecontainer.GetContainerSpec(pod, containerName); containerSpec == nil {
			return fmt.Errorf("failed to get containerSpec %q (id=%q) in pod %q when killing container for reason %q",
				containerName, containerID.String(), format.Pod(pod), message)
		}
	} else {
		// 如果其中一个规格为nil，则恢复所需的信息。
		restoredPod, restoredContainer, err := m.restoreSpecsFromContainerLabels(ctx, containerID)
		if err != nil {
			return err
		}
		pod, containerSpec = restoredPod, restoredContainer
	}

	// 从这个点开始，pod和container必须是非nil的。
	gracePeriod := setTerminationGracePeriod(pod, containerSpec, containerName, containerID, reason)

	if len(message) == 0 {
		message = fmt.Sprintf("Stopping container %s", containerSpec.Name)
	}
	m.recordContainerEvent(pod, containerSpec, containerID.ID, v1.EventTypeNormal, events.KillingContainer, message)

	// 如果适用且有足够的时间运行它，则运行pre-stop生命周期钩子
	if containerSpec.Lifecycle != nil && containerSpec.Lifecycle.PreStop != nil && gracePeriod > 0 {
		gracePeriod = gracePeriod - m.executePreStopHook(ctx, pod, containerID, containerSpec, gracePeriod)
	}
	// 总是给容器一个最小的关闭窗口，以避免不必要的SIGKILL信号
	if gracePeriod < minimumGracePeriodInSeconds {
		gracePeriod = minimumGracePeriodInSeconds
	}
	if gracePeriodOverride != nil {
		gracePeriod = *gracePeriodOverride
		klog.V(3).InfoS("Killing container with a grace period override", "pod", klog.KObj(pod), "podUID", pod.UID,
			"containerName", containerName, "containerID", containerID.String(), "gracePeriod", gracePeriod)
	}

	klog.V(2).InfoS("Killing container with a grace period", "pod", klog.KObj(pod), "podUID", pod.UID,
		"containerName", containerName, "containerID", containerID.String(), "gracePeriod", gracePeriod)

	err := m.runtimeService.StopContainer(ctx, containerID.ID, gracePeriod)
	if err != nil && !crierror.IsNotFound(err) {
		klog.ErrorS(err, "Container termination failed with gracePeriod", "pod", klog.KObj(pod), "podUID", pod.UID,
			"containerName", containerName, "containerID", containerID.String(), "gracePeriod", gracePeriod)
		return err
	}
	klog.V(3).InfoS("Container exited normally", "pod", klog.KObj(pod), "podUID", pod.UID,
		"containerName", containerName, "containerID", containerID.String())

	return nil
}
```

##### restoreSpecsFromContainerLabels

```GO
// restoreSpecsFromContainerLabels从容器标签中恢复杀死容器所需的所有信息。在某些情况下，
// 在杀死容器时，我们可能没有pod和容器规格，例如kubelet重启期间删除了pod。
// 为了解决这个问题，我们已经将必要的信息写入了容器标签中。在这里，我们只需要从容器标签中检索它们并恢复规格。
// TODO(random-liu): 添加一个节点端到端测试来测试这种行为。
// TODO(random-liu): 更改生命周期处理程序只接受所需的信息，这样我们就可以只传递所需的函数而不是创建虚假对象。
func (m *kubeGenericRuntimeManager) restoreSpecsFromContainerLabels(ctx context.Context, containerID kubecontainer.ContainerID) (*v1.Pod, *v1.Container, error) {
	var pod *v1.Pod
	var container *v1.Container
	resp, err := m.runtimeService.ContainerStatus(ctx, containerID.ID, false)
	if err != nil {
		return nil, nil, err
	}
	s := resp.GetStatus()
	if s == nil {
		return nil, nil, remote.ErrContainerStatusNil
	}

	l := getContainerInfoFromLabels(s.Labels)
	a := getContainerInfoFromAnnotations(s.Annotations)
	// 注意以下不是完整的规格。容器终止代码不应使用未恢复的字段。
	pod = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:                        l.PodUID,
			Name:                       l.PodName,
			Namespace:                  l.PodNamespace,
			DeletionGracePeriodSeconds: a.PodDeletionGracePeriod,
		},
		Spec: v1.PodSpec{
			TerminationGracePeriodSeconds: a.PodTerminationGracePeriod,
		},
	}
	container = &v1.Container{
		Name:                   l.ContainerName,
		Ports:                  a.ContainerPorts,
		TerminationMessagePath: a.TerminationMessagePath,
	}
	if a.PreStopHandler != nil {
		container.Lifecycle = &v1.Lifecycle{
			PreStop: a.PreStopHandler,
		}
	}
	return pod, container, nil
}
```

##### setTerminationGracePeriod

```GO
// setTerminationGracePeriod确定在杀死容器时使用的优雅期限
func setTerminationGracePeriod(pod *v1.Pod, containerSpec *v1.Container, containerName string, containerID kubecontainer.ContainerID, reason containerKillReason) int64 {
	gracePeriod := int64(minimumGracePeriodInSeconds)
	switch {
	case pod.DeletionGracePeriodSeconds != nil:
		return *pod.DeletionGracePeriodSeconds
	case pod.Spec.TerminationGracePeriodSeconds != nil:
		switch reason {
		case reasonStartupProbe:
			if isProbeTerminationGracePeriodSecondsSet(pod, containerSpec, containerSpec.StartupProbe, containerName, containerID, "StartupProbe") {
				return *containerSpec.StartupProbe.TerminationGracePeriodSeconds
			}
		case reasonLivenessProbe:
			if isProbeTerminationGracePeriodSecondsSet(pod, containerSpec, containerSpec.LivenessProbe, containerName, containerID, "LivenessProbe") {
				return *containerSpec.LivenessProbe.TerminationGracePeriodSeconds
			}
		}
		return *pod.Spec.TerminationGracePeriodSeconds
	}
	return gracePeriod
}
```

#### pruneInitContainersBeforeStart

```GO
// pruneInitContainersBeforeStart函数确保在开始创建初始化容器之前，我们已经减少了仍存在的未完成初始化容器数量。
// 这样可以减轻容器垃圾回收器的负载，只保留最近终止的初始化容器。
func (m *kubeGenericRuntimeManager) pruneInitContainersBeforeStart(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) {
	// 只保留每个初始化容器的最后一次执行，并且只在要保留的初始化容器列表中保留它。
	initContainerNames := sets.NewString()
	for _, container := range pod.Spec.InitContainers {
		initContainerNames.Insert(container.Name)
	}
	for name := range initContainerNames {
		count := 0
		for _, status := range podStatus.ContainerStatuses {
			// 如果容器名称不匹配，或者容器状态不是Exited或Unknown，则继续下一轮循环。
			if status.Name != name ||
				(status.State != kubecontainer.ContainerStateExited &&
					status.State != kubecontainer.ContainerStateUnknown) {
				continue
			}
			// 移除处于Unknown状态的初始化容器。在调用pruneInitContainersBeforeStart之前，应该已经停止了它。
			count++
			// 对于该名称的第一个初始化容器，保留它。
			if count == 1 {
				continue
			}
			// 移除与该容器名称匹配的所有其他初始化容器。
			klog.V(4).InfoS("Removing init container", "containerName", status.Name, "containerID", status.ID.ID, "count", count)
			if err := m.removeContainer(ctx, status.ID.ID); err != nil {
				utilruntime.HandleError(fmt.Errorf("failed to remove pod init container %q: %v; Skipping pod %q", status.Name, err, format.Pod(pod)))
				continue
			}
		}
	}
}
```

#### createPodSandbox

```go
// createPodSandbox函数用于创建Pod的沙箱，并返回(podSandBoxID, message, error)。
func (m *kubeGenericRuntimeManager) createPodSandbox(ctx context.Context, pod *v1.Pod, attempt uint32) (string, string, error) {
	// 通过generatePodSandboxConfig函数生成Pod的沙箱配置
	podSandboxConfig, err := m.generatePodSandboxConfig(pod, attempt)
	if err != nil {
		message := fmt.Sprintf("为Pod %q 生成沙箱配置失败：%v", format.Pod(pod), err)
		klog.ErrorS(err, "为Pod生成沙箱配置失败", "pod", klog.KObj(pod))
		return "", message, err
	}

	// 创建Pod的日志目录
	err = m.osInterface.MkdirAll(podSandboxConfig.LogDirectory, 0755)
	if err != nil {
		message := fmt.Sprintf("为Pod %q 创建日志目录失败：%v", format.Pod(pod), err)
		klog.ErrorS(err, "为Pod创建日志目录失败", "pod", klog.KObj(pod))
		return "", message, err
	}

	runtimeHandler := ""
	if m.runtimeClassManager != nil {
		// 如果存在runtimeClassManager，则通过LookupRuntimeHandler函数查找Pod的运行时处理程序
		runtimeHandler, err = m.runtimeClassManager.LookupRuntimeHandler(pod.Spec.RuntimeClassName)
		if err != nil {
			message := fmt.Sprintf("为Pod %q 创建沙箱失败：%v", format.Pod(pod), err)
			return "", message, err
		}
		if runtimeHandler != "" {
			klog.V(2).InfoS("使用运行时处理程序运行Pod", "pod", klog.KObj(pod), "runtimeHandler", runtimeHandler)
		}
	}

	// 调用runtimeService的RunPodSandbox函数创建Pod的沙箱
	podSandBoxID, err := m.runtimeService.RunPodSandbox(ctx, podSandboxConfig, runtimeHandler)
	if err != nil {
		message := fmt.Sprintf("为Pod %q 创建沙箱失败：%v", format.Pod(pod), err)
		klog.ErrorS(err, "为Pod创建沙箱失败", "pod", klog.KObj(pod))
		return "", message, err
	}

	return podSandBoxID, "", nil
}
```

##### generatePodSandboxConfig

```go
// generatePodSandboxConfig函数根据v1.Pod生成Pod的沙箱配置。
func (m *kubeGenericRuntimeManager) generatePodSandboxConfig(pod *v1.Pod, attempt uint32) (*runtimeapi.PodSandboxConfig, error) {
	// TODO: 废弃pod沙箱资源需求，采用Pod级别的cgroup
	// Refer https://github.com/kubernetes/kubernetes/issues/29871
	// 根据v1.Pod生成Pod的沙箱配置
	podUID := string(pod.UID)
	podSandboxConfig := &runtimeapi.PodSandboxConfig{
		Metadata: &runtimeapi.PodSandboxMetadata{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Uid:       podUID,
			Attempt:   attempt,
		},
		Labels:      newPodLabels(pod),
		Annotations: newPodAnnotations(pod),
	}

	// 获取Pod的DNS配置
	dnsConfig, err := m.runtimeHelper.GetPodDNS(pod)
	if err != nil {
		return nil, err
	}
	podSandboxConfig.DnsConfig = dnsConfig

	if !kubecontainer.IsHostNetworkPod(pod) {
		// TODO: 在新的运行时接口中添加域名支持
		// 生成Pod的主机名和域名
		podHostname, podDomain, err := m.runtimeHelper.GeneratePodHostNameAndDomain(pod)
		if err != nil {
			return nil, err
		}
		podHostname, err = util.GetNodenameForKernel(podHostname, podDomain, pod.Spec.SetHostnameAsFQDN)
		if err != nil {
			return nil, err
		}
		podSandboxConfig.Hostname = podHostname
	}

	// 创建Pod的日志目录
	logDir := BuildPodLogsDirectory(pod.Namespace, pod.Name, pod.UID)
	podSandboxConfig.LogDirectory = logDir

	portMappings := []*runtimeapi.PortMapping{}
	for _, c := range pod.Spec.Containers {
		// 为每个容器生成端口映射配置
		containerPortMappings := kubecontainer.MakePortMappings(&c)

		for idx := range containerPortMappings {
			port := containerPortMappings[idx]
			hostPort := int32(port.HostPort)
			containerPort := int32(port.ContainerPort)
			protocol := toRuntimeProtocol(port.Protocol)
			portMappings = append(portMappings, &runtimeapi.PortMapping{
				HostIp:        port.HostIP,
				HostPort:      hostPort,
				ContainerPort: containerPort,
				Protocol:      protocol,
			})
		}

	}
	if len(portMappings) > 0 {
		podSandboxConfig.PortMappings = portMappings
	}

	// 生成Pod的Linux沙箱配置
	lc, err := m.generatePodSandboxLinuxConfig(pod)
	if err != nil {
		return nil, err
	}
	podSandboxConfig.Linux = lc

	if runtime.GOOS == "windows" {
		// 生成Pod的Windows沙箱配置
		wc, err := m.generatePodSandboxWindowsConfig(pod)
		if err != nil {
			return nil, err
		}
		podSandboxConfig.Windows = wc
	}

	// 更新配置以包含overhead、沙箱级别的资源
	if err := m.applySandboxResources(pod, podSandboxConfig); err != nil {
		return nil, err
	}
	return podSandboxConfig, nil
}
```

##### generatePodSandboxLinuxConfig

```go
// generatePodSandboxLinuxConfig函数从v1.Pod生成LinuxPodSandboxConfig。
// 无论底层操作系统如何，我们总是要调用PodSandboxLinuxConfig，因为securityContext不是podSandboxConfig的一部分。
// 目前，它是LinuxPodSandboxConfig的一部分。将来，如果我们将securityContext从podSandboxConfig中分离出来，我们应该能够使用它。
func (m *kubeGenericRuntimeManager) generatePodSandboxLinuxConfig(pod *v1.Pod) (*runtimeapi.LinuxPodSandboxConfig, error) {
	// 获取Pod的cgroupParent配置
	cgroupParent := m.runtimeHelper.GetPodCgroupParent(pod)
	lc := &runtimeapi.LinuxPodSandboxConfig{
		CgroupParent: cgroupParent,
		SecurityContext: &runtimeapi.LinuxSandboxSecurityContext{
			Privileged: kubecontainer.HasPrivilegedContainer(pod),

			// 强制沙箱以`runtime/default`运行，允许用户在Pod级别使用最低特权的seccomp配置文件。Issue #84623
			Seccomp: &runtimeapi.SecurityProfile{
				ProfileType: runtimeapi.SecurityProfile_RuntimeDefault,
			},
		},
	}

	sysctls := make(map[string]string)
	if pod.Spec.SecurityContext != nil {
		for _, c := range pod.Spec.SecurityContext.Sysctls {
			sysctls[c.Name] = c.Value
		}
	}

	lc.Sysctls = sysctls

	if pod.Spec.SecurityContext != nil {
		sc := pod.Spec.SecurityContext
		if sc.RunAsUser != nil && runtime.GOOS != "windows" {
			lc.SecurityContext.RunAsUser = &runtimeapi.Int64Value{Value: int64(*sc.RunAsUser)}
		}
		if sc.RunAsGroup != nil && runtime.GOOS != "windows" {
			lc.SecurityContext.RunAsGroup = &runtimeapi.Int64Value{Value: int64(*sc.RunAsGroup)}
		}
		namespaceOptions, err := runtimeutil.NamespacesForPod(pod, m.runtimeHelper)
		if err != nil {
			return nil, err
		}
		lc.SecurityContext.NamespaceOptions = namespaceOptions

		if sc.FSGroup != nil && runtime.GOOS != "windows" {
			lc.SecurityContext.SupplementalGroups = append(lc.SecurityContext.SupplementalGroups, int64(*sc.FSGroup))
		}
		if groups := m.runtimeHelper.GetExtraSupplementalGroupsForPod(pod); len(groups) > 0 {
			lc.SecurityContext.SupplementalGroups = append(lc.SecurityContext.SupplementalGroups, groups...)
		}
		if sc.SupplementalGroups != nil {
			for _, sg := range sc.SupplementalGroups {
				lc.SecurityContext.SupplementalGroups = append(lc.SecurityContext.SupplementalGroups, int64(sg))
			}
		}
		if sc.SELinuxOptions != nil && runtime.GOOS != "windows" {
			lc.SecurityContext.SelinuxOptions = &runtimeapi.SELinuxOption{
				User:  sc.SELinuxOptions.User,
				Role:  sc.SELinuxOptions.Role,
				Type:  sc.SELinuxOptions.Type,
				Level: sc.SELinuxOptions.Level,
			}
		}
	}

	return lc, nil
}
```

##### applySandboxResources

```go
func (m *kubeGenericRuntimeManager) applySandboxResources(pod *v1.Pod, config *runtimeapi.PodSandboxConfig) error {
	// 如果Linux为空，直接返回
	if config.Linux == nil {
		return nil
	}
	// 计算沙箱资源
	config.Linux.Resources = m.calculateSandboxResources(pod)
	// 转换overhead为Linux资源
	config.Linux.Overhead = m.convertOverheadToLinuxResources(pod)

	return nil
}

```

###### calculateSandboxResources

```go
func (m *kubeGenericRuntimeManager) calculateSandboxResources(pod *v1.Pod) *runtimeapi.LinuxContainerResources {
	// 创建Pod资源选项，设置排除overhead
	opts := resourcehelper.PodResourcesOptions{
		ExcludeOverhead: true,
	}
	// 获取Pod的资源请求和限制
	req := resourcehelper.PodRequests(pod, opts)
	lim := resourcehelper.PodLimits(pod, opts)
	var cpuRequest *resource.Quantity
	if _, cpuRequestExists := req[v1.ResourceCPU]; cpuRequestExists {
		cpuRequest = req.Cpu()
	}
	// 计算Linux资源
	return m.calculateLinuxResources(cpuRequest, lim.Cpu(), lim.Memory())
}
```

###### calculateLinuxResources

```go
// calculateLinuxResources函数根据提供的CPU和内存资源请求、限制创建linuxContainerResources类型
func (m *kubeGenericRuntimeManager) calculateLinuxResources(cpuRequest, cpuLimit, memoryLimit *resource.Quantity) *runtimeapi.LinuxContainerResources {
	resources := runtimeapi.LinuxContainerResources{}
	var cpuShares int64

	memLimit := memoryLimit.Value()

	// 如果请求未指定，但限制已指定，我们希望请求默认为限制。
	// API服务器对新容器执行此操作，但在运行现有Kubernetes集群上的容器时，在Kubelet中重复此逻辑。
	if cpuRequest == nil && cpuLimit != nil {
		cpuShares = int64(cm.MilliCPUToShares(cpuLimit.MilliValue()))
	} else {
		// 如果cpuRequest.Amount为nil，则MilliCPUToShares将返回最小数量的CPU份额。
		cpuShares = int64(cm.MilliCPUToShares(cpuRequest.MilliValue()))
	}
	resources.CpuShares = cpuShares
	if memLimit != 0 {
		resources.MemoryLimitInBytes = memLimit
	}

	if m.cpuCFSQuota {
		// 如果cpuLimit.Amount为nil，则返回适当的默认值
		// 以允许完全使用cpu资源。
		cpuPeriod := int64(quotaPeriod)
		if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUCFSQuotaPeriod) {
			// kubeGenericRuntimeManager.cpuCFSQuotaPeriod以time.Duration形式提供，
			// 但我们需要将其转换为kernel使用的微秒数。
			cpuPeriod = int64(m.cpuCFSQuotaPeriod.Duration / time.Microsecond)
		}
		cpuQuota := milliCPUToQuota(cpuLimit.MilliValue(), cpuPeriod)
		resources.CpuQuota = cpuQuota
		resources.CpuPeriod = cpuPeriod
	}

	return &resources
}
```

###### convertOverheadToLinuxResources

```go
func (m *kubeGenericRuntimeManager) convertOverheadToLinuxResources(pod *v1.Pod) *runtimeapi.LinuxContainerResources {
	resources := &runtimeapi.LinuxContainerResources{}
	if pod.Spec.Overhead != nil {
		cpu := pod.Spec.Overhead.Cpu()
		memory := pod.Spec.Overhead.Memory()

		// 对CPU overhead进行换算
		if cpu != nil {
			cpuShares := int64(cm.MilliCPUToShares(cpu.MilliValue()))
			resources.CpuShares = cpuShares
			if m.cpuCFSQuota {
				cpuPeriod := int64(quotaPeriod)
				if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUCFSQuotaPeriod) {
					cpuPeriod = int64(m.cpuCFSQuotaPeriod.Duration / time.Microsecond)
				}
				cpuQuota := milliCPUToQuota(cpu.MilliValue(), cpuPeriod)
				resources.CpuQuota = cpuQuota
				resources.CpuPeriod = cpuPeriod
			}
		}

		// 对内存 overhead进行换算
		if memory != nil {
			memLimit := memory.Value()
			resources.MemoryLimitInBytes = memLimit
		}
	}
	return resources
}
```

#### determinePodSandboxIPs

```go
// determinePodSandboxIP函数用于确定给定pod沙箱的IP地址。
func (m *kubeGenericRuntimeManager) determinePodSandboxIPs(podNamespace, podName string, podSandbox *runtimeapi.PodSandboxStatus) []string {
	podIPs := make([]string, 0)
	if podSandbox.Network == nil {
		klog.InfoS("Pod Sandbox status doesn't have network information, cannot report IPs", "pod", klog.KRef(podNamespace, podName))
		return podIPs
	}
	// 如果网络信息为空，则无法报告IP地址
	// ip如果是空字符串，表示运行时不负责IP（例如，主机网络）。

	// 选择主要的IP地址
	if len(podSandbox.Network.Ip) != 0 {
		// 如果主要IP地址无法解析，则输出日志并返回空
		if netutils.ParseIPSloppy(podSandbox.Network.Ip) == nil {
			klog.InfoS("Pod Sandbox reported an unparseable primary IP", "pod", klog.KRef(podNamespace, podName), "IP", podSandbox.Network.Ip)
			return nil
		}
		podIPs = append(podIPs, podSandbox.Network.Ip)
	}

	// 选择额外的IP地址（如果cri报告了它们）
	for _, podIP := range podSandbox.Network.AdditionalIps {
		// 如果额外的IP地址无法解析，则输出日志并返回空
		if nil == netutils.ParseIPSloppy(podIP.Ip) {
			klog.InfoS("Pod Sandbox reported an unparseable additional IP", "pod", klog.KRef(podNamespace, podName), "IP", podIP.Ip)
			return nil
		}
		podIPs = append(podIPs, podIP.Ip)
	}

	return podIPs
}
```

#### doBackOff

```go
// doBackOff函数用于检查容器是否仍处于回退状态，并返回相应的错误信息。
func (m *kubeGenericRuntimeManager) doBackOff(pod *v1.Pod, container *v1.Container, podStatus *kubecontainer.PodStatus, backOff *flowcontrol.Backoff) (bool, string, error) {
	var cStatus *kubecontainer.Status
	for _, c := range podStatus.ContainerStatuses {
		if c.Name == container.Name && c.State == kubecontainer.ContainerStateExited {
			cStatus = c
			break
		}
	}

	if cStatus == nil {
		return false, "", nil
	}

	klog.V(3).InfoS("Checking backoff for container in pod", "containerName", container.Name, "pod", klog.KObj(pod))
	// 使用最新退出的容器的完成时间作为计算回退的起点。
	ts := cStatus.FinishedAt
	// backOff需要一个唯一的键来标识容器。
	key := getStableKey(pod, container)
	// 如果容器在回退状态中，则记录事件并返回回退错误信息。
	if backOff.IsInBackOffSince(key, ts) {
		if containerRef, err := kubecontainer.GenerateContainerRef(pod, container); err == nil {
			m.recorder.Eventf(containerRef, v1.EventTypeWarning, events.BackOffStartContainer,
				fmt.Sprintf("Back-off restarting failed container %s in pod %s", container.Name, format.Pod(pod)))
		}
		err := fmt.Errorf("back-off %s restarting failed container=%s pod=%s", backOff.Get(key), container.Name, format.Pod(pod))
		klog.V(3).InfoS("Back-off restarting failed container", "err", err.Error())
		return true, err.Error(), kubecontainer.ErrCrashLoopBackOff
	}

	backOff.Next(key, ts)
	return false, "", nil
}
```

#### startContainer

```go
// startContainer函数用于启动一个容器，并在出错时返回失败的原因。
// 它通过以下步骤启动容器：
// * 拉取镜像
// * 创建容器
// * 启动容器
// * 运行后置启动生命周期钩子（如果适用）
func (m *kubeGenericRuntimeManager) startContainer(ctx context.Context, podSandboxID string, podSandboxConfig *runtimeapi.PodSandboxConfig, spec *startSpec, pod *v1.Pod, podStatus *kubecontainer.PodStatus, pullSecrets []v1.Secret, podIP string, podIPs []string) (string, error) {
	container := spec.container

	// Step 1: 拉取镜像。
	imageRef, msg, err := m.imagePuller.EnsureImageExists(ctx, pod, container, pullSecrets, podSandboxConfig)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return msg, err
	}

	// Step 2: 创建容器。
	// 对于新容器，RestartCount应该为0。
	restartCount := 0
	containerStatus := podStatus.FindContainerStatusByName(container.Name)
	if containerStatus != nil {
		restartCount = containerStatus.RestartCount + 1
	} else {
		// 容器运行时会保持容器状态和容器重启计数的状态。
		// 当节点重新启动时，某些容器运行时会清除它们的状态，导致重启计数重置为0。
		// 这将导致日志文件从0.log开始，它将覆盖或追加到已存在的日志文件中。
		//
		// 我们检查日志目录是否存在，并通过检查日志名称（{重启计数}.log）找到最新的重启计数，并加1。
		logDir := BuildContainerLogsDirectory(pod.Namespace, pod.Name, pod.UID, container.Name)
		restartCount, err = calcRestartCountByLogDir(logDir)
		if err != nil {
			klog.InfoS("无法从日志目录计算重启计数", "logDir", logDir, "err", err)
			restartCount = 0
		}
	}

	target, err := spec.getTargetID(podStatus)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return s.Message(), ErrCreateContainerConfig
	}

	containerConfig, cleanupAction, err := m.generateContainerConfig(ctx, container, pod, restartCount, podIP, imageRef, podIPs, target)
	if cleanupAction != nil {
		defer cleanupAction()
	}
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return s.Message(), ErrCreateContainerConfig
	}

	err = m.internalLifecycle.PreCreateContainer(pod, container, containerConfig)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, "", v1.EventTypeWarning, events.FailedToCreateContainer, "Internal PreCreateContainer hook failed: %v", s.Message())
		return s.Message(), ErrPreCreateHook
	}

	containerID, err := m.runtimeService.CreateContainer(ctx, podSandboxID, containerConfig, podSandboxConfig)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, containerID, v1.EventTypeWarning, events.FailedToCreateContainer, "Error: %v", s.Message())
		return s.Message(), ErrCreateContainer
	}
	err = m.internalLifecycle.PreStartContainer(pod, container, containerID)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, containerID, v1.EventTypeWarning, events.FailedToStartContainer, "Internal PreStartContainer hook failed: %v", s.Message())
		return s.Message(), ErrPreStartHook
	}
	m.recordContainerEvent(pod, container, containerID, v1.EventTypeNormal, events.CreatedContainer, fmt.Sprintf("Created container %s", container.Name))

	// Step 3: 启动容器。
	err = m.runtimeService.StartContainer(ctx, containerID)
	if err != nil {
		s, _ := grpcstatus.FromError(err)
		m.recordContainerEvent(pod, container, containerID, v1.EventTypeWarning, events.FailedToStartContainer, "Error: %v", s.Message())
		return s.Message(), kubecontainer.ErrRunContainer
	}
	m.recordContainerEvent(pod, container, containerID, v1.EventTypeNormal, events.StartedContainer, fmt.Sprintf("Started container %s", container.Name))

	// 将容器日志建立符号链接到传统的容器日志位置，以支持集群日志记录。
	// TODO（random-liu）：在集群日志记录支持CRI容器日志路径后删除此部分。
	containerMeta := containerConfig.GetMetadata()
	sandboxMeta := podSandboxConfig.GetMetadata()
	legacySymlink := legacyLogSymlink(containerID, containerMeta.Name, sandboxMeta.Name,
		sandboxMeta.Namespace)
	containerLog := filepath.Join(podSandboxConfig.LogDirectory, containerConfig.LogPath)
	// 只有当containerLog路径存在（或错误不是IsNotExist）时才创建传统的符号链接。
	// 因为如果containerLog路径不存在，只会创建悬空的legacySymlink。
	// 此悬空的legacySymlink稍后将被容器垃圾回收器删除，因此一开始就创建它是没有意义的。
	// 当使用docker的journald日志驱动程序时，会出现这种情况。
	if _, err := m.osInterface.Stat(containerLog); !os.IsNotExist(err) {
		if err := m.osInterface.Symlink(containerLog, legacySymlink); err != nil {
			klog.ErrorS(err, "创建传统符号链接失败", "path", legacySymlink,
				"containerID", containerID, "containerLogPath", containerLog)
		}
	}

	// Step 4: 执行后置启动钩子。
	if container.Lifecycle != nil && container.Lifecycle.PostStart != nil {
		kubeContainerID := kubecontainer.ContainerID{
			Type: m.runtimeName,
			ID:   containerID,
		}
		msg, handlerErr := m.runner.Run(ctx, kubeContainerID, pod, container, container.Lifecycle.PostStart)
		if handlerErr != nil {
			klog.ErrorS(handlerErr, "执行PostStartHook失败", "pod", klog.KObj(pod),
				"podUID", pod.UID, "containerName", container.Name, "containerID", kubeContainerID.String())
			// 不要将消息记录到事件中，以防止机密信息从服务器泄漏。
			m.recordContainerEvent(pod, container, kubeContainerID.ID, v1.EventTypeWarning, events.FailedPostStartHook, "PostStartHook failed")
			if err := m.killContainer(ctx, pod, kubeContainerID, container.Name, "FailedPostStartHook", reasonFailedPostStartHook, nil); err != nil {
				klog.ErrorS(err, "杀死容器失败", "pod", klog.KObj(pod),
					"podUID", pod.UID, "containerName", container.Name, "containerID", kubeContainerID.String())
			}
			return msg, ErrPostStartHook
		}
	}

	return "", nil
}
```

#### doPodResizeAction

```go
func (m *kubeGenericRuntimeManager) doPodResizeAction(pod *v1.Pod, podStatus *kubecontainer.PodStatus, podContainerChanges podActions, result kubecontainer.PodSyncResult) {
	pcm := m.containerManager.NewPodContainerManager()

	// 获取 Pod 的资源配置
	podResources := cm.ResourceConfigForPod(pod, m.cpuCFSQuota, uint64((m.cpuCFSQuotaPeriod.Duration)/time.Microsecond), false)
	if podResources == nil {
		klog.ErrorS(nil, "无法获取资源配置", "pod", pod.Name)
		result.Fail(fmt.Errorf("无法获取资源配置以进行 Pod %s 的调整大小", pod.Name))
		return
	}

	// 设置 Pod 的 cgroup 配置
	setPodCgroupConfig := func(rName v1.ResourceName, setLimitValue bool) error {
		var err error
		switch rName {
		case v1.ResourceCPU:
			podCpuResources := &cm.ResourceConfig{CPUPeriod: podResources.CPUPeriod}
			if setLimitValue == true {
				podCpuResources.CPUQuota = podResources.CPUQuota
			} else {
				podCpuResources.CPUShares = podResources.CPUShares
			}
			err = pcm.SetPodCgroupConfig(pod, rName, podCpuResources)
		case v1.ResourceMemory:
			err = pcm.SetPodCgroupConfig(pod, rName, podResources)
		}
		if err != nil {
			klog.ErrorS(err, "设置 cgroup 配置失败", "resource", rName, "pod", pod.Name)
		}
		return err
	}

	// 根据内存和 CPU 分别更新
	// 如果调整大小导致 Pod 资源增加，则在调整容器大小之前设置 Pod 的 cgroup 配置。
	// 如果调整大小导致 Pod 资源减少，则在调整容器大小之后设置 Pod 的 cgroup 配置。
	// 如果在任何阶段出现错误，则中止操作，让未完成的任务在以后的同步中重试。
	resizeContainers := func(rName v1.ResourceName, currPodCgLimValue, newPodCgLimValue, currPodCgReqValue, newPodCgReqValue int64) error {
		var err error
		if newPodCgLimValue > currPodCgLimValue {
			if err = setPodCgroupConfig(rName, true); err != nil {
				return err
			}
		}
		if newPodCgReqValue > currPodCgReqValue {
			if err = setPodCgroupConfig(rName, false); err != nil {
				return err
			}
		}
		if len(podContainerChanges.ContainersToUpdate[rName]) > 0 {
			if err = m.updatePodContainerResources(pod, rName, podContainerChanges.ContainersToUpdate[rName]); err != nil {
				klog.ErrorS(err, "更新容器资源失败", "pod", format.Pod(pod), "resource", rName)
				return err
			}
		}
		if newPodCgLimValue < currPodCgLimValue {
			err = setPodCgroupConfig(rName, true)
		}
		if newPodCgReqValue < currPodCgReqValue {
			if err = setPodCgroupConfig(rName, false); err != nil {
				return err
			}
		}
		return err
	}

	// 处理内存调整大小
	if len(podContainerChanges.ContainersToUpdate[v1.ResourceMemory]) > 0 || podContainerChanges.UpdatePodResources {
		if podResources.Memory == nil {
			klog.ErrorS(nil, "podResources.Memory 为 nil", "pod", pod.Name)
			result.Fail(fmt.Errorf("podResources.Memory 为 nil，Pod：%s", pod.Name))
			return
		}
		currentPodMemoryConfig, err := pcm.GetPodCgroupConfig(pod, v1.ResourceMemory)
		if err != nil {
			klog.ErrorS(err, "获取内存的 Pod cgroup 配置失败", "pod", pod.Name)
			result.Fail(err)
			return
		}
		currentPodMemoryUsage, err := pcm.GetPodCgroupMemoryUsage(pod)
		if err != nil {
			klog.ErrorS(err, "获取 Pod 内存使用情况失败", "pod", pod.Name)
			result.Fail(err)
			return
		}
		// 如果当前内存使用量大于等于新的内存限制，中止操作
		if currentPodMemoryUsage >= uint64(*podResources.Memory) {
			klog.ErrorS(nil, "中止尝试将 Pod 的内存限制设置为小于当前内存使用量", "pod", pod.Name)
			result.Fail(fmt.Errorf("中止尝试将 Pod 的内存限制设置为小于当前内存使用量，Pod：%s", pod.Name))
			return
		}
		// 调整容器的内存大小
		if errResize := resizeContainers(v1.ResourceMemory, int64(*currentPodMemoryConfig.Memory), *podResources.Memory, 0, 0); errResize != nil {
			result.Fail(errResize)
			return
		}
	}

	// 处理 CPU 调整大小
	if len(podContainerChanges.ContainersToUpdate[v1.ResourceCPU]) > 0 || podContainerChanges.UpdatePodResources {
		if podResources.CPUQuota == nil || podResources.CPUShares == nil {
			klog.ErrorS(nil, "podResources.CPUQuota 或 podResources.CPUShares 为 nil", "pod", pod.Name)
			result.Fail(fmt.Errorf("podResources.CPUQuota 或 podResources.CPUShares 为 nil，Pod：%s", pod.Name))
			return
		}
		currentPodCpuConfig, err := pcm.GetPodCgroupConfig(pod, v1.ResourceCPU)
		if err != nil {
			klog.ErrorS(err, "获取 CPU 的 Pod cgroup 配置失败", "pod", pod.Name)
			result.Fail(err)
			return
		}
		// 调整容器的 CPU 大小
		if errResize := resizeContainers(v1.ResourceCPU, *currentPodCpuConfig.CPUQuota, *podResources.CPUQuota,
			int64(*currentPodCpuConfig.CPUShares), int64(*podResources.CPUShares)); errResize != nil {
			result.Fail(errResize)
			return
		}
	}
}
```

KillPod

```go
// KillPod函数用于杀死一个Pod的所有容器。Pod可能为空，但运行中的Pod不能为空。
// 如果指定了gracePeriodOverride参数，则允许调用者覆盖Pod的默认grace period。
// 只有硬kill路径允许在kubelet中指定gracePeriodOverride，以避免破坏用户数据。
// 在进行硬驱逐情况下执行SIGKILL或在进行软驱逐情况下使用最大grace period时很有用。
func (m *kubeGenericRuntimeManager) KillPod(ctx context.Context, pod *v1.Pod, runningPod kubecontainer.Pod, gracePeriodOverride *int64) error {
	err := m.killPodWithSyncResult(ctx, pod, runningPod, gracePeriodOverride)
	return err.Error()
}
```

##### killPodWithSyncResult

```go
// killPodWithSyncResult函数用于杀死一个运行中的Pod并返回SyncResult。
// 注意：传入的pod参数可能为nil，当kubelet重新启动时发生这种情况。
func (m *kubeGenericRuntimeManager) killPodWithSyncResult(ctx context.Context, pod *v1.Pod, runningPod kubecontainer.Pod, gracePeriodOverride *int64) (result kubecontainer.PodSyncResult) {
	killContainerResults := m.killContainersWithSyncResult(ctx, pod, runningPod, gracePeriodOverride)
	for _, containerResult := range killContainerResults {
		result.AddSyncResult(containerResult)
	}

	// 停止sandbox，sandbox将在GarbageCollect中被删除
	killSandboxResult := kubecontainer.NewSyncResult(kubecontainer.KillPodSandbox, runningPod.ID)
	result.AddSyncResult(killSandboxResult)
	// 停止所有属于同一个pod的sandbox
	for _, podSandbox := range runningPod.Sandboxes {
		if err := m.runtimeService.StopPodSandbox(ctx, podSandbox.ID.ID); err != nil && !crierror.IsNotFound(err) {
			killSandboxResult.Fail(kubecontainer.ErrKillPodSandbox, err.Error())
			klog.ErrorS(nil, "Failed to stop sandbox", "podSandboxID", podSandbox.ID)
		}
	}

	return
}
```

### GetPodStatus

```go
// GetPodStatus函数用于获取Pod的状态，包括Runtime中可见的所有容器的信息。
func (m *kubeGenericRuntimeManager) GetPodStatus(ctx context.Context, uid kubetypes.UID, name, namespace string) (*kubecontainer.PodStatus, error) {
	// 现在我们将重启计数保留为容器的标签。每当容器重新启动时，Pod将从已注册的死亡容器中读取重启计数，
	// 将其递增以获取新的重启计数，并在新启动的容器上添加具有新重启计数的标签。
	// 然而，这种方法存在一些限制：
	// 1. 当所有死亡容器被垃圾回收时，容器状态可能无法获取历史值，将变得不准确。幸运的是，这种情况非常罕见。
	// 2. 当与没有重启计数标签的旧版本容器一起工作时，我们只能假设它们的重启计数为0。
	// 无论如何，我们只承诺“尽力而为”地报告重启计数，现在可以忽略这些限制。
	// TODO: 将此注释移到SyncPod。
	podSandboxIDs, err := m.getSandboxIDByPodUID(ctx, uid, nil)
	if err != nil {
		return nil, err
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       uid,
		},
	}

	podFullName := format.Pod(pod)

	klog.V(4).InfoS("getSandboxIDByPodUID got sandbox IDs for pod", "podSandboxID", podSandboxIDs, "pod", klog.KObj(pod))

	sandboxStatuses := []*runtimeapi.PodSandboxStatus{}
	containerStatuses := []*kubecontainer.Status{}
	var timestamp time.Time

	podIPs := []string{}
	for idx, podSandboxID := range podSandboxIDs {
		resp, err := m.runtimeService.PodSandboxStatus(ctx, podSandboxID, false)
		// 在List（getSandboxIDByPodUID）和检查（PodSandboxStatus）之间，另一个线程可能会删除一个容器，这是正常情况。
		// 前面的调用（getSandboxIDByPodUID）永远不会因为不存在Pod沙盒而失败。
		// 因此，这个方法也不应该失败，而是应该像前面的调用失败一样处理，也就是忽略错误。
		if crierror.IsNotFound(err) {
			continue
		}
		if err != nil {
			klog.ErrorS(err, "PodSandboxStatus of sandbox for pod", "podSandboxID", podSandboxID, "pod", klog.KObj(pod))
			return nil, err
		}
		if resp.GetStatus() == nil {
			return nil, errors.New("pod sandbox status is nil")

		}
		sandboxStatuses = append(sandboxStatuses, resp.Status)
		// 仅从最新的sandbox中获取Pod IP
		if idx == 0 && resp.Status.State == runtimeapi.PodSandboxState_SANDBOX_READY {
			podIPs = m.determinePodSandboxIPs(namespace, name, resp.Status)
		}

		if idx == 0 && utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
			if resp.Timestamp == 0 {
				// 如果在kubelet中启用了Evented PLEG，但在Runtime中没有启用，
				// 那么我们得到的Pod状态将不会设置时间戳。
				// 例如，CI作业“pull-kubernetes-e2e-gce-alpha-features”将启用特性，其中包括Evented PLEG，
				// 但使用不支持Evented PLEG的Runtime。
				klog.V(4).InfoS("Runtime does not set pod status timestamp", "pod", klog.KObj(pod))
				containerStatuses, err = m.getPodContainerStatuses(ctx, uid, name, namespace)
				if err != nil {
					if m.logReduction.ShouldMessageBePrinted(err.Error(), podFullName) {
						klog.ErrorS(err, "getPodContainerStatuses for pod failed", "pod", klog.KObj(pod))
					}
					return nil, err
				}
			} else {
				// 从sandboxStatus中获取所有对Pod可见的容器的状态和时间戳。
				timestamp = time.Unix(resp.Timestamp, 0)
				for _, cs := range resp.ContainersStatuses {
					cStatus := m.convertToKubeContainerStatus(cs)
					containerStatuses = append(containerStatuses, cStatus)
				}
			}
		}
	}

	if !utilfeature.DefaultFeatureGate.Enabled(features.EventedPLEG) {
		// 获取Pod中所有可见容器的状态。
		containerStatuses, err = m.getPodContainerStatuses(ctx, uid, name, namespace)
		if err != nil {
			if m.logReduction.ShouldMessageBePrinted(err.Error(), podFullName) {
				klog.ErrorS(err, "getPodContainerStatuses for pod failed", "pod", klog.KObj(pod))
			}
			return nil, err
		}
	}

	m.logReduction.ClearID(podFullName)
	return &kubecontainer.PodStatus{
		ID:                uid,
		Name:              name,
		Namespace:         namespace,
		IPs:               podIPs,
		SandboxStatuses:   sandboxStatuses,
		ContainerStatuses: containerStatuses,
		TimeStamp:         timestamp,
	}, nil
}
```

#### getSandboxIDByPodUID

```go
// getSandboxIDByPodUID函数根据podUID获取sandbox的ID，并返回（[]sandboxID，error）。
// 参数state可以为nil，以便获取属于同一pod的所有sandbox。
func (m *kubeGenericRuntimeManager) getSandboxIDByPodUID(ctx context.Context, podUID kubetypes.UID, state *runtimeapi.PodSandboxState) ([]string, error) {
	filter := &runtimeapi.PodSandboxFilter{
		LabelSelector: map[string]string{types.KubernetesPodUIDLabel: string(podUID)},
	}
	if state != nil {
		filter.State = &runtimeapi.PodSandboxStateValue{
			State: *state,
		}
	}
	sandboxes, err := m.runtimeService.ListPodSandbox(ctx, filter)
	if err != nil {
		klog.ErrorS(err, "Failed to list sandboxes for pod", "podUID", podUID)
		return nil, err
	}

	if len(sandboxes) == 0 {
		return nil, nil
	}

	// 按照创建时间从新到旧排序。
	sandboxIDs := make([]string, len(sandboxes))
	sort.Sort(podSandboxByCreated(sandboxes))
	for i, s := range sandboxes {
		sandboxIDs[i] = s.Id
	}

	return sandboxIDs, nil
}
```

### GetContainerLogs

```go
// GetContainerLogs返回特定容器的日志。
func (m *kubeGenericRuntimeManager) GetContainerLogs(ctx context.Context, pod *v1.Pod, containerID kubecontainer.ContainerID, logOptions *v1.PodLogOptions, stdout, stderr io.Writer) (err error) {
	resp, err := m.runtimeService.ContainerStatus(ctx, containerID.ID, false)
	if err != nil {
		klog.V(4).InfoS("获取容器状态失败", "containerID", containerID.String(), "err", err)
		return fmt.Errorf("无法检索容器 %v 的日志", containerID.String())
	}
	status := resp.GetStatus()
	if status == nil {
		return remote.ErrContainerStatusNil
	}
	return m.ReadLogs(ctx, status.GetLogPath(), containerID.ID, logOptions, stdout, stderr)
}

// ReadLogs读取容器日志并重定向到stdout和stderr。
// 需要containerID仅在跟踪日志时需要，否则传入空字符串""即可。
func (m *kubeGenericRuntimeManager) ReadLogs(ctx context.Context, path, containerID string, apiOpts *v1.PodLogOptions, stdout, stderr io.Writer) error {
	// 将v1.PodLogOptions转换为内部日志选项。
	opts := logs.NewLogOptions(apiOpts, time.Now())

	return logs.ReadLogs(ctx, path, containerID, opts, m.runtimeService, stdout, stderr)
}
```

#### ReadLogs

```go
// ReadLogs读取容器日志并重定向到stdout和stderr。
// 需要containerID仅在跟踪日志时需要，否则传入空字符串""即可。
func ReadLogs(ctx context.Context, path, containerID string, opts *LogOptions, runtimeService internalapi.RuntimeService, stdout, stderr io.Writer) error {
	// 在不同的平台上，fsnotify对符号链接有不同的行为，
	// 例如，在Linux上它会跟随符号链接，但在Windows上不会，
	// 因此我们需要在读取日志之前显式解析符号链接。
	// 这不应该存在安全问题，因为容器日志路径由kubelet和容器运行时所拥有。
	evaluated, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("尝试解析路径 %q 中的符号链接失败: %v", path, err)
	}
	path = evaluated
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("无法打开日志文件 %q: %v", path, err)
	}
	defer f.Close()

	// 基于尾行搜索起始点。
	start, err := tail.FindTailLineStartIndex(f, opts.tail)
	if err != nil {
		return fmt.Errorf("无法尾部读取日志文件 %q 的 %d 行: %v", path, opts.tail, err)
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return fmt.Errorf("无法在日志文件 %q 中寻找 %d 的偏移量: %v", path, start, err)
	}

	limitedMode := (opts.tail >= 0) && (!opts.follow)
	limitedNum := opts.tail
	// 开始解析日志。
	r := bufio.NewReader(f)
	// 如果`Follow`为false，则不在此处创建观察器。
	var watcher *fsnotify.Watcher
	var parse parseFunc
	var stop bool
	isNewLine := true
	found := true
	writer := newLogWriter(stdout, stderr, opts)
	msg := &logMessage{}
	for {
		if stop || (limitedMode && limitedNum == 0) {
			klog.V(2).InfoS("完成解析日志文件", "path", path)
			return nil
		}
		l, err := r.ReadBytes(eol[0])
		if err != nil {
			if err != io.EOF { // 这是一个真正的错误
				return fmt.Errorf("无法读取日志文件 %q: %v", path, err)
			}
			if opts.follow {
				// 容器已经停止运行，已到达日志的末尾。
				if !found {
					return nil
				}
				// 重置偏移量，以便如果这是一个不完整的行，它将被重新读取。
				if _, err := f.Seek(-int64(len(l)), io.SeekCurrent); err != nil {
					return fmt.Errorf("无法重置日志文件 %q 中的偏移量: %v", path, err)
				}
				if watcher == nil {
					// 如果尚未初始化观察器，则进行初始化。
					if watcher, err = fsnotify.NewWatcher(); err != nil {
						return fmt.Errorf("无法创建fsnotify观察器: %v", err)
					}
					defer watcher.Close()
					if err := watcher.Add(f.Name()); err != nil {
						return fmt.Errorf("无法监视文件 %q: %v", f.Name(), err)
					}
					// 如果刚刚创建了观察器，则尝试再次读取，因为可能会错过事件。
					continue
				}
				var recreated bool
				// 等待下一次日志更改。
				found, recreated, err = waitLogs(ctx, containerID, watcher, runtimeService)
				if err != nil {
					return err
				}
				if recreated {
					newF, err := os.Open(path)
					if err != nil {
						if os.IsNotExist(err) {
							continue
						}
						return fmt.Errorf("无法打开日志文件 %q: %v", path, err)
					}
					defer newF.Close()
					f.Close()
					if err := watcher.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
						klog.ErrorS(err, "无法删除文件监视", "path", f.Name())
					}
					f = newF
					if err := watcher.Add(f.Name()); err != nil {
						return fmt.Errorf("无法监视文件 %q: %v", f.Name(), err)
					}
					r = bufio.NewReader(f)
				}
				// 如果容器已退出，则继续消耗数据直到下一个EOF
				continue
			}
			// 写入剩余内容后应停止。
			stop = true
			if len(l) == 0 {
				continue
			}
			klog.InfoS("日志文件中有不完整的行", "path", path, "line", l)
		}
		if parse == nil {
			// 初始化日志解析函数。
			parse, err = getParseFunc(l)
			if err != nil {
				return fmt.Errorf("无法获取解析函数: %v", err)
			}
		}
		// 解析日志行。
		msg.reset()
		if err := parse(l, msg); err != nil {
			klog.ErrorS(err, "解析日志文件中的行失败", "path", path, "line", l)
			continue
		}
		// 将日志行写入流中。
		if err := writer.write(msg, isNewLine); err != nil {
			if err == errMaximumWrite {
				klog.V(2).InfoS("完成解析日志文件，达到字节限制", "path", path, "limit", opts.bytes)
				return nil
			}
			klog.ErrorS(err, "写入日志文件中的行失败", "path", path, "line", msg)
			return err
		}
		if limitedMode {
			limitedNum--
		}
		if len(msg.log) > 0 {
			isNewLine = msg.log[len(msg.log)-1] == eol[0]
		} else {
			isNewLine = true
		}
	}
}
```

#### DeleteContainer

```go
// DeleteContainer 移除一个容器。
func (m *kubeGenericRuntimeManager) DeleteContainer(ctx context.Context, containerID kubecontainer.ContainerID) error {
	return m.removeContainer(ctx, containerID.ID)
} 
```

### removeContainer

```go
// 注意，我们先删除容器日志，这样如果容器日志删除失败，容器将不会被移除，并且kubelet会稍后重试。这确保容器日志随容器一起被移除。
// 注意，我们假设容器只能在非运行状态下被移除，在该状态下将不再写入容器日志。
func (m *kubeGenericRuntimeManager) removeContainer(ctx context.Context, containerID string) error {
	klog.V(4).InfoS("Removing container", "containerID", containerID)
	// Call internal container post-stop lifecycle hook.
	// 调用内部容器的停止后生命周期钩子。
	if err := m.internalLifecycle.PostStopContainer(containerID); err != nil {
		return err
	}

	// Remove the container log.
	// TODO: Separate log and container lifecycle management.
	// 移除容器日志。
	// TODO：分离日志和容器生命周期管理。
	if err := m.removeContainerLog(ctx, containerID); err != nil {
		return err
	}
	// Remove the container.
	// 移除容器。
	return m.runtimeService.RemoveContainer(ctx, containerID)
}
```

#### removeContainerLog

```go
// removeContainerLog removes the container log.
// removeContainerLog 移除容器日志。
func (m *kubeGenericRuntimeManager) removeContainerLog(ctx context.Context, containerID string) error {
	// Use log manager to remove rotated logs.
	// 使用日志管理器删除已轮转的日志。
	err := m.logManager.Clean(ctx, containerID)
	if err != nil {
		return err
	}

	resp, err := m.runtimeService.ContainerStatus(ctx, containerID, false)
	if err != nil {
		return fmt.Errorf("failed to get container status %q: %v", containerID, err)
	}
	status := resp.GetStatus()
	if status == nil {
		return remote.ErrContainerStatusNil
	}
	// Remove the legacy container log symlink.
	// TODO(random-liu): Remove this after cluster logging supports CRI container log path.
	// 移除旧的容器日志符号链接。
	// TODO（random-liu）：在集群日志记录支持CRI容器日志路径之后删除此部分。
	labeledInfo := getContainerInfoFromLabels(status.Labels)
	legacySymlink := legacyLogSymlink(containerID, labeledInfo.ContainerName, labeledInfo.PodName,
		labeledInfo.PodNamespace)
	if err := m.osInterface.Remove(legacySymlink); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove container %q log legacy symbolic link %q: %v",
			containerID, legacySymlink, err)
	}
	return nil
}
```

### UpdatePodCIDR

```go
// UpdatePodCIDR是一个简单的方法，通过传入的podCIDR更新shim的runtimeConfig。
func (m *kubeGenericRuntimeManager) UpdatePodCIDR(ctx context.Context, podCIDR string) error {
	// TODO(#35531): 我们真的希望为配置的每个字段在该管理器上编写一个方法吗？
	klog.InfoS("通过cri更新运行时配置，使用podcidr", "CIDR", podCIDR)
	return m.runtimeService.UpdateRuntimeConfig(ctx,
		&runtimeapi.RuntimeConfig{
			NetworkConfig: &runtimeapi.NetworkConfig{
				PodCidr: podCIDR,
			},
		})
}
```

### CheckpointContainer

```go
// CheckpointContainer将容器检查点保存到指定路径。
func (m *kubeGenericRuntimeManager) CheckpointContainer(ctx context.Context, options *runtimeapi.CheckpointContainerRequest) error {
	return m.runtimeService.CheckpointContainer(ctx, options)
}
```

### ListMetricDescriptors

```go
// ListMetricDescriptors列出可用的度量指标描述符。
func (m *kubeGenericRuntimeManager) ListMetricDescriptors(ctx context.Context) ([]*runtimeapi.MetricDescriptor, error) {
	return m.runtimeService.ListMetricDescriptors(ctx)
}
```

### ListPodSandboxMetrics

```go
// ListPodSandboxMetrics列出PodSandbox的度量信息。
func (m *kubeGenericRuntimeManager) ListPodSandboxMetrics(ctx context.Context) ([]*runtimeapi.PodSandboxMetrics, error) {
	return m.runtimeService.ListPodSandboxMetrics(ctx)
}
```

### PullImage

```go
// PullImage从网络上拉取镜像到本地存储，如果需要，使用提供的凭据。
func (m *kubeGenericRuntimeManager) PullImage(ctx context.Context, image kubecontainer.ImageSpec, pullSecrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	img := image.Image
	repoToPull, _, _, err := parsers.ParseImageName(img)
	if err != nil {
		return "", err
	}

	keyring, err := credentialprovidersecrets.MakeDockerKeyring(pullSecrets, m.keyring)
	if err != nil {
		return "", err
	}

	imgSpec := toRuntimeAPIImageSpec(image)

	creds, withCredentials := keyring.Lookup(repoToPull)
	if !withCredentials {
		klog.V(3).InfoS("没有使用凭据拉取镜像", "镜像", img)

		imageRef, err := m.imageService.PullImage(ctx, imgSpec, nil, podSandboxConfig)
		if err != nil {
			klog.ErrorS(err, "拉取镜像失败", "镜像", img)
			return "", err
		}

		return imageRef, nil
	}

	var pullErrs []error
	for _, currentCreds := range creds {
		auth := &runtimeapi.AuthConfig{
			Username:      currentCreds.Username,
			Password:      currentCreds.Password,
			Auth:          currentCreds.Auth,
			ServerAddress: currentCreds.ServerAddress,
			IdentityToken: currentCreds.IdentityToken,
			RegistryToken: currentCreds.RegistryToken,
		}

		imageRef, err := m.imageService.PullImage(ctx, imgSpec, auth, podSandboxConfig)
		// 如果没有错误，则返回成功
		if err == nil {
			return imageRef, nil
		}

		pullErrs = append(pullErrs, err)
	}

	return "", utilerrors.NewAggregate(pullErrs)
}
```

### GetImageRef

```go
// GetImageRef 获取已经存在于本地存储中的图像的ID。如果图像不在本地存储中，则返回 ("", nil)。
func (m *kubeGenericRuntimeManager) GetImageRef(ctx context.Context, image kubecontainer.ImageSpec) (string, error) {
	resp, err := m.imageService.ImageStatus(ctx, toRuntimeAPIImageSpec(image), false)
	if err != nil {
		klog.ErrorS(err, "Failed to get image status", "image", image.Image)
		return "", err
	}
	if resp.Image == nil {
		return "", nil
	}
	return resp.Image.Id, nil
}
```

### ListImages

```go
// ListImages 获取当前机器上的所有图像。
func (m *kubeGenericRuntimeManager) ListImages(ctx context.Context) ([]kubecontainer.Image, error) {
	var images []kubecontainer.Image

	allImages, err := m.imageService.ListImages(ctx, nil)
	if err != nil {
		klog.ErrorS(err, "Failed to list images")
		return nil, err
	}

	for _, img := range allImages {
		images = append(images, kubecontainer.Image{
			ID:          img.Id,
			Size:        int64(img.Size_),
			RepoTags:    img.RepoTags,
			RepoDigests: img.RepoDigests,
			Spec:        toKubeContainerImageSpec(img),
		})
	}

	return images, nil
}
```

### RemoveImage

```go
// RemoveImage 删除指定的图像。
func (m *kubeGenericRuntimeManager) RemoveImage(ctx context.Context, image kubecontainer.ImageSpec) error {
	err := m.imageService.RemoveImage(ctx, &runtimeapi.ImageSpec{Image: image.Image})
	if err != nil {
		klog.ErrorS(err, "Failed to remove image", "image", image.Image)
		return err
	}

	return nil
}
```

### ImageStats

```go
// ImageStats 返回图像的统计信息。
// 请注意，当前逻辑实际上不适用于共享层的图像（例如 Docker 图像），
// 这是一个已知问题，我们将通过直接从 CRI 获取 imagefs 统计信息来解决此问题。
// TODO: 直接从 CRI 获取 imagefs 统计信息。
func (m *kubeGenericRuntimeManager) ImageStats(ctx context.Context) (*kubecontainer.ImageStats, error) {
	allImages, err := m.imageService.ListImages(ctx, nil)
	if err != nil {
		klog.ErrorS(err, "Failed to list images")
		return nil, err
	}
	stats := &kubecontainer.ImageStats{}
	for _, img := range allImages {
		stats.TotalStorageBytes += img.Size
	}
	return stats, nil
}
```

### RunInContainer

```go
// RunInContainer 在容器中同步执行命令，并返回输出结果。
func (m *kubeGenericRuntimeManager) RunInContainer(ctx context.Context, id kubecontainer.ContainerID, cmd []string, timeout time.Duration) ([]byte, error) {
	stdout, stderr, err := m.runtimeService.ExecSync(ctx, id.ID, cmd, timeout)
	// 注意：这里没有正确地交错输出stdout和stderr，但对于日志记录目的应该足够。
	// 如果需要更精确的输出顺序，需要向ExecSyncRequest添加一个合并输出的选项。
	return append(stdout, stderr...), err
}
```

### GetExec

```go
// GetExec 获取运行时将从中提供exec请求的端点。
func (m *kubeGenericRuntimeManager) GetExec(ctx context.Context, id kubecontainer.ContainerID, cmd []string, stdin, stdout, stderr, tty bool) (*url.URL, error) {
	req := &runtimeapi.ExecRequest{
		ContainerId: id.ID,
		Cmd:         cmd,
		Tty:         tty,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
	}
	resp, err := m.runtimeService.Exec(ctx, req)
	if err != nil {
		return nil, err
	}

	return url.Parse(resp.Url)
}
```

### GetAttach

```go
// GetAttach 获取运行时将从中提供attach请求的端点。
func (m *kubeGenericRuntimeManager) GetAttach(ctx context.Context, id kubecontainer.ContainerID, stdin, stdout, stderr, tty bool) (*url.URL, error) {
	req := &runtimeapi.AttachRequest{
		ContainerId: id.ID,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		Tty:         tty,
	}
	resp, err := m.runtimeService.Attach(ctx, req)
	if err != nil {
		return nil, err
	}
	return url.Parse(resp.Url)
}
```

### GetPortForward

```go
// GetPortForward 获取运行时将从中提供端口转发请求的端点。
func (m *kubeGenericRuntimeManager) GetPortForward(ctx context.Context, podName, podNamespace string, podUID kubetypes.UID, ports []int32) (*url.URL, error) {
	sandboxIDs, err := m.getSandboxIDByPodUID(ctx, podUID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to find sandboxID for pod %s: %v", format.PodDesc(podName, podNamespace, podUID), err)
	}
	if len(sandboxIDs) == 0 {
		return nil, fmt.Errorf("failed to find sandboxID for pod %s", format.PodDesc(podName, podNamespace, podUID))
	}
	req := &runtimeapi.PortForwardRequest{
		PodSandboxId: sandboxIDs[0],
		Port:         ports,
	}
	resp, err := m.runtimeService.PortForward(ctx, req)
	if err != nil {
		return nil, err
	}
	return url.Parse(resp.Url)
}
```

