
## 简介

kubelet 中的 ImageManager 是 Kubernetes 中的一个组件，用于管理节点上的镜像。它负责拉取镜像、缓存镜像、以及清理不再需要的镜像。

ImageManager 维护了一个本地的镜像缓存，可以根据 Pod 的镜像需求来拉取镜像并缓存到本地。当 Pod 需要使用某个镜像时，ImageManager 会检查本地是否已经缓存了该镜像，如果没有则会从镜像库中拉取并缓存到本地，以便后续使用。

同时，ImageManager 还可以通过清理本地不再需要的镜像来释放磁盘空间，避免节点的镜像存储空间被耗尽。ImageManager 会定期检查本地镜像的使用情况，并清理掉没有被使用或者已经过期的镜像。

## ImageManager

```GO
// ImageManager提供了管理镜像生命周期的接口。
// 该接口的实现应处理镜像的拉取（下载）、管理和删除。
// 实现应该对底层运行时进行抽象。
// 实现应该是线程安全的。
type ImageManager interface {
	// EnsureImageExists确保container中指定的镜像存在。
	EnsureImageExists(ctx context.Context, pod *v1.Pod, container *v1.Container, pullSecrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, string, error)

	// TODO（ronl）：在此接口中合并镜像管理和删除操作
}
```

## imageManager

```GO
// imageManager提供了镜像拉取的功能。
type imageManager struct {
	recorder     record.EventRecorder
	imageService kubecontainer.ImageService
	backOff      *flowcontrol.Backoff
	// 它将检查镜像的存在，并相应地报告“正在拉取镜像”、“镜像已拉取”事件。
	puller                 imagePuller
	podPullingTimeRecorder ImagePodPullingTimeRecorder
}

var _ ImageManager = &imageManager{}
```

### ImagePodPullingTimeRecorder

```GO
type ImagePodPullingTimeRecorder interface {
	RecordImageStartedPulling(podUID types.UID)
	RecordImageFinishedPulling(podUID types.UID)
}
```

### throttledImageService

```GO
// throttleImagePulling对kubecontainer.ImageService进行包装，根据给定的QPS和突发限制来限制镜像的拉取。
// 如果QPS为零，则默认不进行限流。
func throttleImagePulling(imageService kubecontainer.ImageService, qps float32, burst int) kubecontainer.ImageService {
	if qps == 0.0 {
		return imageService
	}
	return &throttledImageService{
		ImageService: imageService,
		limiter:      flowcontrol.NewTokenBucketRateLimiter(qps, burst),
	}
}

type throttledImageService struct {
	kubecontainer.ImageService
	limiter flowcontrol.RateLimiter
}

func (ts throttledImageService) PullImage(ctx context.Context, image kubecontainer.ImageSpec, secrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	if ts.limiter.TryAccept() {
		return ts.ImageService.PullImage(ctx, image, secrets, podSandboxConfig)
	}
	return "", fmt.Errorf("pull QPS exceeded")
}
```

### imagePuller

```GO
type imagePuller interface {
	pullImage(context.Context, kubecontainer.ImageSpec, []v1.Secret, chan<- pullResult, *runtimeapi.PodSandboxConfig)
}
```

#### pullResult

```GO
// 并行和串行镜像拉取器实现了imagePuller接口。
type pullResult struct {
    imageRef string
    err error
    pullDuration time.Duration
}
```

### parallelImagePuller

```GO
// pullResult结构体用于存储拉取结果。
type parallelImagePuller struct {
	imageService kubecontainer.ImageService
	tokens       chan struct{}
}

// 并行镜像拉取器实现。
func newParallelImagePuller(imageService kubecontainer.ImageService, maxParallelImagePulls *int32) imagePuller {
	if maxParallelImagePulls == nil || *maxParallelImagePulls < 1 {
		return &parallelImagePuller{imageService, nil}
	}
	return &parallelImagePuller{imageService, make(chan struct{}, *maxParallelImagePulls)}
}

// 创建并行镜像拉取器实例。
func (pip *parallelImagePuller) pullImage(ctx context.Context, spec kubecontainer.ImageSpec, pullSecrets []v1.Secret, pullChan chan<- pullResult, podSandboxConfig *runtimeapi.PodSandboxConfig) {
	go func() {
		if pip.tokens != nil {
			pip.tokens <- struct{}{}
			defer func() { <-pip.tokens }()
		}
		startTime := time.Now()
		imageRef, err := pip.imageService.PullImage(ctx, spec, pullSecrets, podSandboxConfig)
		pullChan <- pullResult{
			imageRef:     imageRef,
			err:          err,
			pullDuration: time.Since(startTime),
		}
	}()
}
```

### serialImagePuller

```GO
// 最大可排队的镜像拉取请求数。
const maxImagePullRequests = 10

// 串行镜像拉取器实现。
type serialImagePuller struct {
	imageService kubecontainer.ImageService
	pullRequests chan *imagePullRequest
}

// 创建串行镜像拉取器实例。
func newSerialImagePuller(imageService kubecontainer.ImageService) imagePuller {
	imagePuller := &serialImagePuller{imageService, make(chan *imagePullRequest, maxImagePullRequests)}
	go wait.Until(imagePuller.processImagePullRequests, time.Second, wait.NeverStop)
	return imagePuller
}

// 镜像拉取请求结构体。
type imagePullRequest struct {
	ctx              context.Context
	spec             kubecontainer.ImageSpec
	pullSecrets      []v1.Secret
	pullChan         chan<- pullResult
	podSandboxConfig *runtimeapi.PodSandboxConfig
}


func (sip *serialImagePuller) pullImage(ctx context.Context, spec kubecontainer.ImageSpec, pullSecrets []v1.Secret, pullChan chan<- pullResult, podSandboxConfig *runtimeapi.PodSandboxConfig) {
	sip.pullRequests <- &imagePullRequest{
		ctx:              ctx,
		spec:             spec,
		pullSecrets:      pullSecrets,
		pullChan:         pullChan,
		podSandboxConfig: podSandboxConfig,
	}
}

func (sip *serialImagePuller) processImagePullRequests() {
	for pullRequest := range sip.pullRequests {
		startTime := time.Now()
		imageRef, err := sip.imageService.PullImage(pullRequest.ctx, pullRequest.spec, pullRequest.pullSecrets, pullRequest.podSandboxConfig)
		pullRequest.pullChan <- pullResult{
			imageRef:     imageRef,
			err:          err,
			pullDuration: time.Since(startTime),
		}
	}
}
```

## NewImageManager

```GO
// NewImageManager实例化一个新的ImageManager对象。
func NewImageManager(recorder record.EventRecorder, imageService kubecontainer.ImageService, imageBackOff *flowcontrol.Backoff, serialized bool, maxParallelImagePulls *int32, qps float32, burst int, podPullingTimeRecorder ImagePodPullingTimeRecorder) ImageManager {
	imageService = throttleImagePulling(imageService, qps, burst)

	var puller imagePuller
	if serialized {
		puller = newSerialImagePuller(imageService)
	} else {
		puller = newParallelImagePuller(imageService, maxParallelImagePulls)
	}
	return &imageManager{
		recorder:               recorder,
		imageService:           imageService,
		backOff:                imageBackOff,
		puller:                 puller,
		podPullingTimeRecorder: podPullingTimeRecorder,
	}
}
```

## EnsureImageExists

```GO
// EnsureImageExists函数用于获取指定Pod和容器的镜像，并返回(imageRef, 错误信息, 错误)。
func (m *imageManager) EnsureImageExists(ctx context.Context, pod *v1.Pod, container *v1.Container, pullSecrets []v1.Secret, podSandboxConfig *runtimeapi.PodSandboxConfig) (string, string, error) {
	logPrefix := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Image)
	ref, err := kubecontainer.GenerateContainerRef(pod, container)
	if err != nil {
		klog.ErrorS(err, "Couldn't make a ref to pod", "pod", klog.KObj(pod), "containerName", container.Name)
	}

	// 如果镜像没有标签或摘要，则应用默认标签。
	image, err := applyDefaultImageTag(container.Image)
	if err != nil {
		msg := fmt.Sprintf("Failed to apply default image tag %q: %v", container.Image, err)
		m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
		return "", msg, ErrInvalidImageName
	}

	var podAnnotations []kubecontainer.Annotation
	for k, v := range pod.GetAnnotations() {
		podAnnotations = append(podAnnotations, kubecontainer.Annotation{
			Name:  k,
			Value: v,
		})
	}

	spec := kubecontainer.ImageSpec{
		Image:       image,
		Annotations: podAnnotations,
	}
	imageRef, err := m.imageService.GetImageRef(ctx, spec)
	if err != nil {
		msg := fmt.Sprintf("Failed to inspect image %q: %v", container.Image, err)
		m.logIt(ref, v1.EventTypeWarning, events.FailedToInspectImage, logPrefix, msg, klog.Warning)
		return "", msg, ErrImageInspect
	}

	present := imageRef != ""
	if !shouldPullImage(container, present) {
		if present {
			msg := fmt.Sprintf("Container image %q already present on machine", container.Image)
			m.logIt(ref, v1.EventTypeNormal, events.PulledImage, logPrefix, msg, klog.Info)
			return imageRef, "", nil
		}
		msg := fmt.Sprintf("Container image %q is not present with pull policy of Never", container.Image)
		m.logIt(ref, v1.EventTypeWarning, events.ErrImageNeverPullPolicy, logPrefix, msg, klog.Warning)
		return "", msg, ErrImageNeverPull
	}

	backOffKey := fmt.Sprintf("%s_%s", pod.UID, container.Image)
	if m.backOff.IsInBackOffSinceUpdate(backOffKey, m.backOff.Clock.Now()) {
		msg := fmt.Sprintf("Back-off pulling image %q", container.Image)
		m.logIt(ref, v1.EventTypeNormal, events.BackOffPullImage, logPrefix, msg, klog.Info)
		return "", msg, ErrImagePullBackOff
	}
	m.podPullingTimeRecorder.RecordImageStartedPulling(pod.UID)
	m.logIt(ref, v1.EventTypeNormal, events.PullingImage, logPrefix, fmt.Sprintf("Pulling image %q", container.Image), klog.Info)
	startTime := time.Now()
	pullChan := make(chan pullResult)
	m.puller.pullImage(ctx, spec, pullSecrets, pullChan, podSandboxConfig)
	imagePullResult := <-pullChan
	if imagePullResult.err != nil {
		m.logIt(ref, v1.EventTypeWarning, events.FailedToPullImage, logPrefix, fmt.Sprintf("Failed to pull image %q: %v", container.Image, imagePullResult.err), klog.Warning)
		m.backOff.Next(backOffKey, m.backOff.Clock.Now())

		msg, err := evalCRIPullErr(container, imagePullResult.err)
		return "", msg, err
	}
	m.podPullingTimeRecorder.RecordImageFinishedPulling(pod.UID)
	m.logIt(ref, v1.EventTypeNormal, events.PulledImage, logPrefix, fmt.Sprintf("Successfully pulled image %q in %v (%v including waiting)",
		container.Image, imagePullResult.pullDuration.Truncate(time.Millisecond), time.Since(startTime).Truncate(time.Millisecond)), klog.Info)
	m.backOff.GC()
	return imagePullResult.imageRef, "", nil
}
```

### applyDefaultImageTag

```GO
// applyDefaultImageTag函数解析Docker镜像字符串，如果没有标签或摘要，则应用默认标签。
func applyDefaultImageTag(image string) (string, error) {
	_, tag, digest, err := parsers.ParseImageName(image)
	if err != nil {
		return "", err
	}
	// 在这里，我们只是将镜像名称与默认标签拼接起来
	if len(digest) == 0 && len(tag) > 0 && !strings.HasSuffix(image, ":"+tag) {
		// 在这里，我们只是将镜像名称与默认标签拼接起来，而不是使用dockerref.WithTag(named, ...)，
		// 因为这样会导致镜像完全合格为docker.io/$name，如果它是一个短名称（例如busybox）。
		// 我们不希望这种情况发生，以保持CRI对镜像名称和默认主机名的通用性。
		image = image + ":" + tag
	}
	return image, nil
}
```

### shouldPullImage

```GO
// shouldPullImage函数根据镜像的存在和拉取策略返回是否应该拉取镜像。
func shouldPullImage(container *v1.Container, imagePresent bool) bool {
	if container.ImagePullPolicy == v1.PullNever {
		return false
	}

	if container.ImagePullPolicy == v1.PullAlways ||
		(container.ImagePullPolicy == v1.PullIfNotPresent && (!imagePresent)) {
		return true
	}

	return false
}
```

### evalCRIPullErr

```GO
// evalCRIPullErr函数用于评估CRI拉取镜像时的错误。
func evalCRIPullErr(container *v1.Container, err error) (errMsg string, errRes error) {
	// 目前不支持使用errors.Is进行错误断言来处理gRPC（远程运行时）错误。
	// 参考：https://github.com/grpc/grpc-go/issues/3616
	if strings.HasPrefix(err.Error(), crierrors.ErrRegistryUnavailable.Error()) {
		errMsg = fmt.Sprintf(
			"image pull failed for %s because the registry is unavailable%s",
			container.Image,
			// 修整错误消息，将错误名称从消息中删除，将错误转换为形如"因为注册表不可用而失败: 具体错误说明"的格式。
			strings.TrimPrefix(err.Error(), crierrors.ErrRegistryUnavailable.Error()),
		)
		return errMsg, crierrors.ErrRegistryUnavailable
	}

	if strings.HasPrefix(err.Error(), crierrors.ErrSignatureValidationFailed.Error()) {
		errMsg = fmt.Sprintf(
			"image pull failed for %s because the signature validation failed%s",
			container.Image,
			// 修整错误消息，将错误名称从消息中删除，将错误转换为形如"因为签名验证失败而失败: 具体错误说明"的格式。
			strings.TrimPrefix(err.Error(), crierrors.ErrSignatureValidationFailed.Error()),
		)
		return errMsg, crierrors.ErrSignatureValidationFailed
	}

	// 没有特定错误时的回退
	return err.Error(), ErrImagePull
}
```

