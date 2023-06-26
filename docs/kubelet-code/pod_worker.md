---
id: 6-kubelet-code 
title: pod-worker 代码走读
description: pod-worker 代码走读
keywords:
  - kubernetes
  - kubelet
slug: /
---

## interface

```GO
// PodWorkers 是用于可测试性的抽象接口。
type PodWorkers interface {
	// UpdatePod 通知 pod worker 发生了对 pod 的更改，然后会按照 FIFO 的顺序由每个 pod UID 对应的 goroutine 进行处理。
	// pod 的状态会传递给 syncPod 方法，直到 pod 被标记为已删除、达到终止阶段（Succeeded/Failed）或被 kubelet 驱逐。
	// 一旦发生上述情况，将调用 syncTerminatingPod 方法，直到成功退出，并且在此之后对该 pod 的所有进一步的 UpdatePod() 调用将被忽略，直到由于时间过去而被遗忘。
	// 终止的 pod 将永远不会重新启动。
	UpdatePod(options UpdatePodOptions)
	// SyncKnownPods 删除不在 desiredPods 集合中且已经终止一段时间的 pod 对应的 worker。
	// 调用此方法后，假定 worker 完全初始化，并且对于未知的 pod，后续调用 ShouldPodContentBeRemoved 方法将返回 true。
	// 它返回一个描述每个已知 pod worker 状态的映射。调用者负责重新添加任何未返回的期望的 pod。
	SyncKnownPods(desiredPods []*v1.Pod) (knownPods map[types.UID]PodWorkerSync)

	// IsPodKnownTerminated 返回 true，一旦 SyncTerminatingPod 完成成功 - pod worker 已知该 pod UID 的 pod 被终止。
	// 如果 pod 被强制删除并且 pod worker 已经完成终止，则此方法将返回 false，因此此方法只应用于过滤掉 desired 集合中的 pod，例如在 admission 中。
	//
	// 用于 kubelet 配置循环，但不适用于子系统，子系统应使用 ShouldPod*()。
	IsPodKnownTerminated(uid types.UID) bool
	// CouldHaveRunningContainers 在 pod workers 同步之前返回 true，在 pod workers 看到 pod（syncPod 可能被调用）之后返回 true，并在 pod 终止后（运行的容器保证已停止）返回 false。
	//
	// 用于 kubelet 配置循环，但不适用于子系统，子系统应使用 ShouldPod*()。
	CouldHaveRunningContainers(uid types.UID) bool

	// ShouldPodBeFinished 返回 true，一旦 SyncTerminatedPod 完成成功 - pod worker 已知该 pod UID 的 pod 被终止并且资源已回收。
	// 在 pod workers 同步之前返回 false（syncPod 可能被调用）。一旦 pod workers 同步完成，如果 pod 有一个同步状态，则返回 false，直到 SyncTerminatedPod 成功完成。
	// 如果 pod workers 同步完成，但 pod 没有状态，则返回 true。
	//
	// 用于子系统同步循环，以避免在请求终止 pod 之后执行后台设置。调用者必须确保 syncPod 方法在其数据缺失时是非阻塞的。
	ShouldPodBeFinished(uid types.UID) bool
	// IsPodTerminationRequested 返回 true，当 pod 终止已被请求，直到终止完成并从配置中删除 pod。这不应该在清理循环中使用，因为如果 pod 已经被清理，它将返回 false - 使用 ShouldPodContainersBeTerminating 代替。此外，该方法在容器仍由 pod worker 初始化期间返回 true。
	//
	// 用于 kubelet sync* 方法，但不适用于子系统，子系统应使用 ShouldPod*()。
	IsPodTerminationRequested(uid types.UID) bool

	// ShouldPodContainersBeTerminating 在 pod workers 同步之前返回 false，或一旦 pod 开始终止，返回 true。
	// 这个检查类似于 ShouldPodRuntimeBeRemoved，但在请求终止后也返回 true。
	//
	// 用于子系统同步循环，以避免在请求终止 pod 之后执行后台设置。调用者必须确保 syncPod 方法在其数据缺失时是非阻塞的。
	ShouldPodContainersBeTerminating(uid types.UID) bool
	// ShouldPodRuntimeBeRemoved 返回 true，如果 Kubelet 内的运行时管理器应该主动清理与 pod 不相关的资源，如附加的卷。
	// 当 pod 在第一次同步之后尚未被 worker 观察到（意味着它可能尚未运行）或在所有运行的容器停止后为 true。
	// TODO：一旦 pod 日志与运行的容器分离，应使用此方法来控制是否保留容器。
	//
	// 用于子系统同步循环，以了解何时开始撤销正在运行的容器使用的资源。调用者应确保他们拥有的运行时内容不需要进行后续终止处理 - 例如，在删除 pod 之后，Docker 需要保留容器以保留 pod 日志。
	ShouldPodRuntimeBeRemoved(uid types.UID) bool
	// ShouldPodContentBeRemoved 如果 Kubelet 内的资源管理器应该主动清理与 pod 相关的所有内容，则返回 true。
	// 在 pod 驱逐期间为 true（我们希望删除该内容以释放资源），以及在删除 pod 的请求导致容器停止后为 true（这是一种更优雅的操作）。
	// 请注意，正在删除的 pod 仍然可以被驱逐。
	//
	// 用于子系统同步循环，以了解何时开始撤销与未删除的 pod 相关的资源。通常情况下，直到删除+从 etcd 中删除或驱逐时，内容通常都会被保留，尽管当该方法返回 false 时，垃圾回收可以释放内容。
	ShouldPodContentBeRemoved(uid types.UID) bool
	// IsPodForMirrorPodTerminatingByFullName 如果具有提供的 pod 名称的静态 pod 当前正在终止并且尚未完成，则返回 true。
	// 它仅在孤立的镜像 pod 清理期间使用，以防止我们在 pod 关闭之前从 api 服务器中删除一个终止的静态 pod。
	IsPodForMirrorPodTerminatingByFullName(podFullname string) bool
}
```

### UpdatePodOptions

```GO
// UpdatePodOptions 是传递给 UpdatePod 操作的选项结构。
type UpdatePodOptions struct {
	// 更新类型（创建、更新、同步、终止）。
	UpdateType kubetypes.SyncPodType
	// StartTime 是此更新创建的时间戳的可选参数。如果设置了，当此更新由 pod worker 完全实现时，它将记录在 PodWorkerDuration 指标中。
	StartTime time.Time
	// 要更新的 pod。必填。
	Pod *v1.Pod
	// MirrorPod 是静态 pod 的镜像 pod。当 UpdateType 是 kill 或 terminated 时可选。
	MirrorPod *v1.Pod
	// RunningPod 是在配置中不再存在的运行时 pod。如果 Pod 为 nil，则为必填项；如果 Pod 已设置，则忽略该项。
	RunningPod *kubecontainer.Pod
	// KillPodOptions 用于覆盖 pod 的默认终止行为或在操作完成后更新 pod 的状态。由于 pod 可能出于多个原因被终止，会按顺序调用 PodStatusFunc，并且稍后的终止机会可以覆盖状态（即，抢占可能后来变成驱逐）。
	KillPodOptions *KillPodOptions
}
```

#### KillPodOptions

```GO
// KillPodOptions 是执行 update pod 操作时的选项，其更新类型为 kill。
type KillPodOptions struct {
	// CompletedCh 在 kill 请求完成（syncTerminatingPod 已完成且无错误）或者如果 pod 不存在或者 pod 已经终止时关闭。这可能需要任意长的时间来关闭，但一旦 CouldHaveRunningContainers() 返回 false，它就不会保持打开状态。
	CompletedCh chan<- struct{}
	// 如果这是一个 pod 触发的驱逐，则 Evict 为 true - 一旦 pod 被驱逐，一些资源将比正常的 pod 操作更积极地被清除（停止的容器）。
	Evict bool
	// 如果设置了 PodStatusFunc，则 PodStatusFunc 被调用并覆盖 pod 在杀死 pod 时的状态。提供的状态是从最新的状态填充的。
	PodStatusFunc PodStatusFunc
	// PodTerminationGracePeriodSecondsOverride 是用于正在进行 kill 操作的 pod 的可选重写。
	PodTerminationGracePeriodSecondsOverride *int64
}

// PodStatusFunc 是在杀死 pod 时用来覆盖 pod 状态的函数。
type PodStatusFunc func(podStatus *v1.PodStatus)
```

### PodWorkerSync

```GO
// PodWorkerSync 是对同步的单个 pod worker 的摘要。除了状态之外的值用于为操作员提供度量计数。
type PodWorkerSync struct {
	// Pod 的 uid。
	PodUID types.UID
	// Pod 的当前同步状态。
	SyncState SyncState
	// Pod 的 sync 完成时间戳，或者零值时间戳如果尚未完成。
	SyncCompletionTimestamp time.Time
	// Pod 的 sync 完成时是否发生了错误。
	SyncError bool
	// Pod 的 sync 完成的错误消息，如果有的话。
	SyncErrorMessage string
}
```

#### SyncState

```GO
// SyncState 是 pod worker 的同步状态。
type SyncState int

const (
	// PodSyncStateNone 表示 pod worker 尚未同步。
	PodSyncStateNone SyncState = iota
	// PodSyncStateRunning 表示 pod worker 正在运行。
	PodSyncStateRunning
	// PodSyncStateSucceeded 表示 pod worker 同步成功。
	PodSyncStateSucceeded
	// PodSyncStateFailed 表示 pod worker 同步失败。
	PodSyncStateFailed
)
```

## podWorkers

```GO
// podWorkers 维护对 Pod 的操作，并确保每个 Pod 与容器运行时和其他子系统进行协调。该工作线程还跟踪正在启动的 Pod、正在关闭但仍有运行的容器的 Pod，以及最近终止并确保没有运行的容器的 Pod。
//
// podWorkers 是节点上任何时候应处于活动状态的 Pod 的真实状态，并通过 UpdatePod 方法与节点的期望状态（通过 kubelet pod config 循环和 kubelet 的 podManager 中的状态进行跟踪）保持最新。处理运行中 Pod 的组件应该查看 pod worker 的状态，而不是 kubelet podManager。通过 SyncKnownPods() 方法，pod worker 定期与 podManager 的状态进行协调，并负责确保所有不再存在于 podManager 中（不再是节点所需配置的一部分）的已观察到的 Pod 的完成。
//
// 传递给 pod worker 的 Pod 可能处于同步状态（预计正在运行）、终止状态（具有运行的容器，但不希望启动新的容器）、已终止状态（没有运行的容器，但仍可能有资源被使用）或清理状态（没有剩余资源）。一旦将 Pod 设置为“拆除”，在该 UID 下就不能再次启动它（对应于删除或驱逐），直到：
//
//  1. pod worker 完成（syncTerminatingPod 和 syncTerminatedPod 顺序退出，没有错误）
//  2. kubelet 的 housekeeping 调用 SyncKnownPods 方法，并且该 Pod 不属于已知配置。
//
// pod worker 为其他 kubelet 循环提供有关 Pod 状态和是否可以运行容器的一致信息。ShouldPodContentBeRemoved() 方法跟踪 Pod 的内容是否仍应存在，包括在调用 SyncKnownPods() 之后不存在的 Pod（按照契约，所有现有的 Pod 应该在调用 SyncKnownPods 之前通过 UpdatePod 提供）。一般来说，其他同步循环被期望将“设置”和“拆除”职责分开，并且此处的信息方法通过集中化状态来帮助完成这些工作。时间间隔的简单可视化可能如下所示：

// ---|                                         = kubelet config has synced at least once
// -------|                                  |- = pod exists in apiserver config
// --------|                  |---------------- = CouldHaveRunningContainers() is true
//
//	^- pod is observed by pod worker  .
//	.                                 .
//
// ----------|       |------------------------- = syncPod is running
//
//	. ^- pod worker loop sees change and invokes syncPod
//	. .                               .
//
// --------------|                     |------- = ShouldPodContainersBeTerminating() returns true
// --------------|                     |------- = IsPodTerminationRequested() returns true (pod is known)
//
//	. .   ^- Kubelet evicts pod       .
//	. .                               .
//
// -------------------|       |---------------- = syncTerminatingPod runs then exits without error
//
//	        . .        ^ pod worker loop exits syncPod, sees pod is terminating,
//					 . .          invokes syncTerminatingPod
//	        . .                               .
//
// ---|    |------------------|              .  = ShouldPodRuntimeBeRemoved() returns true (post-sync)
//
//	.                ^ syncTerminatingPod has exited successfully
//	.                               .
//
// ----------------------------|       |------- = syncTerminatedPod runs then exits without error
//
//	.                         ^ other loops can tear down
//	.                               .
//
// ------------------------------------|  |---- = status manager is waiting for SyncTerminatedPod() finished
//
//	.                         ^     .
//
// ----------|                               |- = status manager can be writing pod status
//
//	^ status manager deletes pod because no longer exists in config
//
// 其他 kubelet 中的组件可以通过 UpdatePod 方法或 killPodNow 包装器请求终止 Pod，这将确保 pod 的组件停止，直到 kubelet 重新启动或永久停止（如果 pod 的阶段在 pod 状态更改中设置为终端阶段）。
type podWorkers struct {
	// 保护所有 worker 相关字段。
	podLock sync.Mutex
	// podsSynced 表示 pod worker 至少同步一次，即所有工作中的 pod 已通过 UpdatePod() 启动。
	podsSynced bool

	// 跟踪每个 pod 的运行 goroutine，每个 pod 的 goroutine 将处理通过其对应的通道接收到的更新。在该通道上发送消息将通知相应的 goroutine 消耗 podSyncStatuses[uid].pendingUpdate（如果已设置）。
	podUpdates map[types.UID]chan struct{}
	// 按 UID 跟踪 pod 的终止状态 - 同步中、终止中、已终止和驱逐。
	podSyncStatuses map[types.UID]*podSyncStatus

	// 按完整名称跟踪已启动静态 pod 的所有 uid
	startedStaticPodsByFullname map[string]types.UID
	// 按完整名称跟踪正在等待启动的静态 pod 的所有 uid
	waitingToStartStaticPodsByFullname map[string][]types.UID

	workQueue queue.WorkQueue

	// 此函数用于同步 Pod 的期望状态。
	// 注意：此函数必须是线程安全的 - 可能会同时为不同的 Pod 调用。
	podSyncer podSyncer

	// workerChannelFn 用于测试中的通道通信，允许在通道通信中引入延迟。该函数在每次启动新 worker goroutine 时被调用一次。
	workerChannelFn func(uid types.UID, in chan struct{}) (out <-chan struct{})

	// EventRecorder 用于记录事件
	recorder record.EventRecorder

	// sync 出错时的退避周期
	backOffPeriod time.Duration

	// 下一次同步的等待间隔
	resyncInterval time.Duration

	// podCache 存储所有 Pod 的 kubecontainer.PodStatus。
	podCache kubecontainer.Cache

	// 用于测试时间的 clock
	clock clock.PassiveClock
}
```

### podSyncStatus

```go
// podSyncStatus tracks per-pod transitions through the three phases of pod
// worker sync (setup, terminating, terminated).
type podSyncStatus struct {
	ctx                      context.Context       // 当前 pod 同步相关的上下文
	cancelFn                 context.CancelFunc    // 用于取消当前 podSyncer 操作的函数
	fullname                 string                // pod 的完整名称
	working                  bool                  // 如果有待处理的更新或正在被 pod worker goroutine 处理，则为 true
	pendingUpdate            *UpdatePodOptions     // 待处理的更新状态，当 pod worker 读取它时，它会被清除并移动到 activeUpdate
	activeUpdate             *UpdatePodOptions     // 最新的 pod 状态，将传递给 sync*Pod 函数。当 worker 决定启动一个 pod 时（设置 startedAt），该 pod 将对下游组件可见
	syncedAt                 time.Time             // pod worker 首次观察到此 pod 的时间
	startedAt                time.Time             // pod worker 允许 pod 启动的时间
	terminatingAt            time.Time             // 在请求终止 pod 后设置，注意可以在 pod worker 开始终止 pod 之前设置
	terminatedAt             time.Time             // 在 pod worker 完成成功的 syncTerminatingPod 调用后设置，表示所有正在运行的容器都已停止
	gracePeriod              int64                 // 在 terminatingAt 不为零时，表示请求的 gracePeriod
	notifyPostTerminating    []chan<- struct{}     // 在 pod 进入 terminated 状态时将关闭。在 pod 进入 terminated 状态后，不应再向此列表添加任何内容
	statusPostTerminating    []PodStatusFunc       // 与 kill pod 请求相关的状态更改列表。在 pod 进入 terminated 状态后，不应再向此列表添加任何内容
	startedTerminating       bool                  // 一旦 pod worker 观察到停止 pod 的请求（退出 syncPod 并观察到 WorkType 为 TerminatingPod 的 podWork），就设置为 true。设置后，可以安全地假设 kubelet 的其他组件不会启动其他容器
	deleted                  bool                  // 如果 pod 已在 apiserver 上标记为删除或没有表示配置的内容（已在之前删除），则为 true
	evicted                  bool                  // 如果终止指示这是一次驱逐（可以更积极地清理），则为 true
	finished                 bool                  // 一旦 pod worker 完成 pod（syncTerminatedPod 无错误退出），直到调用 SyncKnownPods 以删除该 pod 之前，将设置为 true。终端 pod（Succeeded/Failed）将保留终止状态，直到删除该 pod
	restartRequested         bool                  // 如果 pod worker 被告知 pod 在被杀死后（update 类型为 create、update 或 sync）仍然存在，则为 true。在同步已知 pod 时，任何已终止且有 restartRequested 的 pod 都将其历史记录清除
	observedRuntime          bool                  // 如果观察到 pod 在运行时存在，则为 true。在运行时观察到的 pod 必须经过 SyncTerminatingRuntimePod 或 SyncTerminatingPod。否则，如果 pod 在启动之前被删除或变为孤立状态，则可以避免调用终止方法
}

func (s *podSyncStatus) IsWorking() bool { return s.working } // 是否有待处理的更新或正在被处理
func (s *podSyncStatus) IsTerminationRequested() bool { return !s.terminatingAt.IsZero() } // 是否请求终止
func (s *podSyncStatus) IsTerminationStarted() bool { return s.startedTerminating } // 是否已开始终止
func (s *podSyncStatus) IsTerminated() bool { return !s.terminatedAt.IsZero() } // 是否已终止
func (s *podSyncStatus) IsFinished() bool { return s.finished } // 是否已完成
func (s *podSyncStatus) IsEvicted() bool { return s.evicted } // 是否为驱逐状态
func (s *podSyncStatus) IsDeleted() bool { return s.deleted } // 是否已删除
func (s *podSyncStatus) IsStarted() bool { return !s.startedAt.IsZero() } // 是否已开始

// WorkType 返回此 pod 在 pod 生命周期状态机中的当前状态
func (s *podSyncStatus) WorkType() PodWorkerState {
	if s.IsTerminated() {
		return TerminatedPod
	}
	if s.IsTerminationRequested() {
		return TerminatingPod
	}
	return SyncPod
}

// mergeLastUpdate 记录新更新的最新状态。Pod 和 MirrorPod 递增。KillPodOptions 被累加。
// 如果设置了 RunningPod，则 Pod 是合成的，并且 *不会*用作最后的 pod 状态，除非不存在先前的 pod 状态
//（因为 pod worker 可能负责终止上一个 kubelet 运行的 pod，该 pod 的配置状态不可见）。
// activeUpdate 的内容用作 pod worker 下游组件的真实来源。
func (s *podSyncStatus) mergeLastUpdate(other UpdatePodOptions) {
	opts := s.activeUpdate
	if opts == nil {
		opts = &UpdatePodOptions{}
		s.activeUpdate = opts
	}

	// UpdatePodOptions 状态（并且 UpdatePod 强制执行）要么设置了 Pod，要么设置了 RunningPod，
	// 我们希望保留我们观察到的最新 Pod，因此只有在没有 Pod 或 RunningPod 为 nil 时才覆盖我们的 Pod。
	if opts.Pod == nil || other.RunningPod == nil {
		opts.Pod = other.Pod
	}
	// 运行中的 pod 不会持久化，但将被记住以进行重放
	opts.RunningPod = other.RunningPod
	// 如果未提供 MirrorPod，则记住最后一个 MirrorPod 以进行重放
	if other.MirrorPod != nil {
		opts.MirrorPod = other.MirrorPod
	}
	// 累加 kill pod 选项
	if other.KillPodOptions != nil {
		opts.KillPodOptions = &KillPodOptions{}
		if other.KillPodOptions.Evict {
			opts.KillPodOptions.Evict = true
		}
		if override := other.KillPodOptions.PodTerminationGracePeriodSecondsOverride; override != nil {
			value := *override
			opts.KillPodOptions.PodTerminationGracePeriodSecondsOverride = &value
		}
	}
	// 不复制 StartTime - 它纯粹用于跟踪配置从 kubelet 到 pod worker 的传播延迟
}
```

### podSyncer

```go
// podSyncer描述了Pod状态机的核心生命周期操作。首先，Pod被同步，直到自然进入终止状态（返回true）或外部代理决定终止Pod。
// 一旦Pod应该终止，就会调用SyncTerminatingPod方法，直到它无错误返回为止。然后，调用SyncTerminatedPod方法，直到它无错误退出，Pod被认为是终止的。
// 实现此接口的对象在同时针对多个Pod调用这些方法时必须是线程安全的。
type podSyncer interface {
	// SyncPod配置Pod并启动或重新启动所有容器。如果返回true，则Pod已达到终止状态，并且错误的存在指示成功或失败。
	// 如果返回错误，则同步未成功，应在将来重新运行。这是一个长时间运行的方法，如果上下文被取消，应提前以context.Canceled退出。
	SyncPod(ctx context.Context, updateType kubetypes.SyncPodType, pod *v1.Pod, mirrorPod *v1.Pod, podStatus *kubecontainer.PodStatus) (bool, error)

	// SyncTerminatingPod尝试确保Pod的容器不再运行，并收集任何最终状态。
	// 这个方法会根据递减的优雅期间重复调用，直到无错误退出。一旦此方法无错误退出，其他组件就可以拆除支持资源，如卷和设备。
	// 如果上下文被取消，该方法应返回context.Canceled，除非它已成功完成，这可能发生在检测到较短的优雅期间时。
	SyncTerminatingPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, gracePeriod *int64, podStatusFn func(*v1.PodStatus)) error

	// SyncTerminatingRuntimePod在发现与kubelet不再知道的Pod对应的正在运行的容器时被调用，以终止这些容器。
	// 除非已知所有容器已停止，否则它不应无错误退出。
	SyncTerminatingRuntimePod(ctx context.Context, runningPod *kubecontainer.Pod) error

	// SyncTerminatedPod在所有运行的容器停止后调用，负责释放应立即执行而不是在后台执行的资源。
	// 一旦它无错误退出，Pod在节点上被认为已完成。
	SyncTerminatedPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) error
}
```

```GO
// podSyncerFuncs实现podSyncer并接受每个方法的函数。
type podSyncerFuncs struct {
	syncPod                   syncPodFnType
	syncTerminatingPod        syncTerminatingPodFnType
	syncTerminatingRuntimePod syncTerminatingRuntimePodFnType
	syncTerminatedPod         syncTerminatedPodFnType
}

type syncPodFnType func(ctx context.Context, updateType kubetypes.SyncPodType, pod *v1.Pod, mirrorPod *v1.Pod, podStatus *kubecontainer.PodStatus) (bool, error)
type syncTerminatingPodFnType func(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, gracePeriod *int64, podStatusFn func(*v1.PodStatus)) error
type syncTerminatingRuntimePodFnType func(ctx context.Context, runningPod *kubecontainer.Pod) error
type syncTerminatedPodFnType func(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) error

func newPodSyncerFuncs(s podSyncer) podSyncerFuncs {
	return podSyncerFuncs{
		syncPod:                   s.SyncPod,
		syncTerminatingPod:        s.SyncTerminatingPod,
		syncTerminatingRuntimePod: s.SyncTerminatingRuntimePod,
		syncTerminatedPod:         s.SyncTerminatedPod,
	}
}

var _ podSyncer = podSyncerFuncs{}

func (f podSyncerFuncs) SyncPod(ctx context.Context, updateType kubetypes.SyncPodType, pod *v1.Pod, mirrorPod *v1.Pod, podStatus *kubecontainer.PodStatus) (bool, error) {
	return f.syncPod(ctx, updateType, pod, mirrorPod, podStatus)
}

func (f podSyncerFuncs) SyncTerminatingPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, gracePeriod *int64, podStatusFn func(*v1.PodStatus)) error {
	return f.syncTerminatingPod(ctx, pod, podStatus, gracePeriod, podStatusFn)
}

func (f podSyncerFuncs) SyncTerminatingRuntimePod(ctx context.Context, runningPod *kubecontainer.Pod) error {
	return f.syncTerminatingRuntimePod(ctx, runningPod)
}

func (f podSyncerFuncs) SyncTerminatedPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) error {
	return f.syncTerminatedPod(ctx, pod, podStatus)
}
```

#### SyncPod

```go
// SyncPod是同步单个Pod的事务脚本（进行设置和准备Pod）。此方法是可重入的，预期将Pod收敛到所需的规范状态。反向操作（拆除）在SyncTerminatingPod和SyncTerminatedPod中处理。如果SyncPod没有错误退出，则表示Pod的运行时状态与所需的配置状态（Pod正在运行）同步。如果SyncPod退出并出现短暂错误，则预计下一次调用SyncPod将朝着达到所需状态的方向取得进展。当由于容器退出（对于RestartNever或RestartOnFailure）而检测到Pod已达到终端生命周期阶段时，SyncPod以isTerminal退出，并将调用下一个方法SyncTerminatingPod。如果Pod因其他原因终止，则SyncPod将收到上下文取消，并应尽快退出。

// 参数：

// updateType - 表示这是创建（第一次）还是更新，仅应用于指标，因为此方法必须是可重入的

// pod - 正在设置的Pod

// mirrorPod - kubelet已知的此Pod的镜像Pod（如果有）

// podStatus - 此Pod的最新观察到的Pod状态，可用于确定在SyncPod循环中应采取的操作集

// 工作流程如下：
// - 如果正在创建Pod，则记录Pod worker的启动延迟
// - 调用generateAPIPodStatus准备Pod的v1.PodStatus
// - 如果第一次看到Pod正在运行，记录Pod的启动延迟
// - 更新状态管理器中的Pod状态
// - 如果由于软准入而不应运行Pod，则停止Pod的容器
// - 启动可运行Pod的任何后台跟踪
// - 如果Pod是静态Pod并且尚未具有镜像Pod，则创建镜像Pod
// - 如果数据目录不存在，则创建Pod的数据目录
// - 等待卷进行附加/挂载
// - 获取Pod的拉取密钥
// - 调用容器运行时的SyncPod回调
// - 更新Pod的入口和出口限制的流量整形

// 如果此工作流程的任何步骤出错，则返回错误，并在下一次SyncPod调用时重复该错误。

// 此操作按顺序写入所有分派的事件，以便提供关于错误情况的最准确信息，以帮助调试。如果此操作返回错误，则调用者不应写入事件。
func (kl *Kubelet) SyncPod(ctx context.Context, updateType kubetypes.SyncPodType, pod, mirrorPod *v1.Pod, podStatus *kubecontainer.PodStatus) (isTerminal bool, err error) {
	// 创建一个新的上下文，并开始一个 OpenTelemetry Span
	ctx, otelSpan := kl.tracer.Start(ctx, "syncPod", trace.WithAttributes(
		attribute.String("k8s.pod.uid", string(pod.UID)),             // 设置 OpenTelemetry Span 的属性
		attribute.String("k8s.pod", klog.KObj(pod).String()),         // 设置 OpenTelemetry Span 的属性
		attribute.String("k8s.pod.name", pod.Name),                   // 设置 OpenTelemetry Span 的属性
		attribute.String("k8s.pod.update_type", updateType.String()), // 设置 OpenTelemetry Span 的属性
		attribute.String("k8s.namespace.name", pod.Namespace),        // 设置 OpenTelemetry Span 的属性
	))
	klog.V(4).InfoS("SyncPod enter", "pod", klog.KObj(pod), "podUID", pod.UID) // 记录日志
	defer func() {
		klog.V(4).InfoS("SyncPod exit", "pod", klog.KObj(pod), "podUID", pod.UID, "isTerminal", isTerminal) // 记录日志
		otelSpan.End()                                                                                      // 结束 OpenTelemetry Span
	}()

	// 主要工作流程的延迟测量是相对于 kubelet 第一次看到 Pod 的时间
	var firstSeenTime time.Time
	if firstSeenTimeStr, ok := pod.Annotations[kubetypes.ConfigFirstSeenAnnotationKey]; ok {
		firstSeenTime = kubetypes.ConvertToTimestamp(firstSeenTimeStr).Get() // 获取第一次看到 Pod 的时间
	}

	// 如果是创建 Pod 的同步操作，并且 firstSeenTime 不为零，则记录 Pod worker 的启动延迟
	if updateType == kubetypes.SyncPodCreate {
		if !firstSeenTime.IsZero() {
			metrics.PodWorkerStartDuration.Observe(metrics.SinceInSeconds(firstSeenTime)) // 记录 Pod worker 的启动延迟
		} else {
			klog.V(3).InfoS("First seen time not recorded for pod", "podUID", pod.UID, "pod", klog.KObj(pod)) // 记录日志
		}
	}

	// 生成最终的 API Pod 状态，包括 Pod 和状态管理器的状态
	apiPodStatus := kl.generateAPIPodStatus(pod, podStatus, false) // 生成 API Pod 状态
	// 如果 Pod 使用主机网络，则可能会更改 Pod IP
	podStatus.IPs = make([]string, 0, len(apiPodStatus.PodIPs))
	for _, ipInfo := range apiPodStatus.PodIPs {
		podStatus.IPs = append(podStatus.IPs, ipInfo.IP) // 更新 Pod IP
	}
	if len(podStatus.IPs) == 0 && len(apiPodStatus.PodIP) > 0 {
		podStatus.IPs = []string{apiPodStatus.PodIP} // 更新 Pod IP
	}

	// 如果Pod处于终止状态，我们无需继续设置Pod
	if apiPodStatus.Phase == v1.PodSucceeded || apiPodStatus.Phase == v1.PodFailed {
		kl.statusManager.SetPodStatus(pod, apiPodStatus)
		isTerminal = true
		return isTerminal, nil
	}

	// 如果Pod不应该运行，我们请求停止Pod的容器。这不同于终止（我们想停止Pod，但如果软性准入允许的话，以后可能重新启动它）。设置状态和阶段适当
	runnable := kl.canRunPod(pod)
	if !runnable.Admit {
		// Pod不可运行；并更新Pod和容器状态为原因。
		if apiPodStatus.Phase != v1.PodFailed && apiPodStatus.Phase != v1.PodSucceeded {
			apiPodStatus.Phase = v1.PodPending
		}
		apiPodStatus.Reason = runnable.Reason
		apiPodStatus.Message = runnable.Message
		// 等待容器未创建。
		const waitingReason = "Blocked"
		for _, cs := range apiPodStatus.InitContainerStatuses {
			if cs.State.Waiting != nil {
				cs.State.Waiting.Reason = waitingReason
			}
		}
		for _, cs := range apiPodStatus.ContainerStatuses {
			if cs.State.Waiting != nil {
				cs.State.Waiting.Reason = waitingReason
			}
		}
	}

	// 记录Pod从kubelet首次看到Pod变为运行状态所需的时间（如果设置了firstSeenTime）
	existingStatus, ok := kl.statusManager.GetPodStatus(pod.UID)
	if !ok || existingStatus.Phase == v1.PodPending && apiPodStatus.Phase == v1.PodRunning &&
		!firstSeenTime.IsZero() {
		metrics.PodStartDuration.Observe(metrics.SinceInSeconds(firstSeenTime))
	}

	kl.statusManager.SetPodStatus(pod, apiPodStatus)

	// 不能运行的Pod必须停止 - 向Pod worker返回一个带有类型的错误
	if !runnable.Admit {
		klog.V(2).InfoS("Pod不可运行，必须停止正在运行的容器", "pod", klog.KObj(pod), "podUID", pod.UID, "message", runnable.Message)
		var syncErr error
		p := kubecontainer.ConvertPodStatusToRunningPod(kl.getRuntime().Type(), podStatus)
		if err := kl.killPod(ctx, pod, p, nil); err != nil {
			if !wait.Interrupted(err) {
				kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToKillPod, "杀死Pod时出错：%v", err)
				syncErr = fmt.Errorf("杀死Pod时出错：%w", err)
				utilruntime.HandleError(syncErr)
			}
		} else {
			// 没有错误杀死Pod，但是无法运行Pod。
			// 返回错误以表示同步循环应该退出。
			syncErr = fmt.Errorf("Pod无法运行：%v", runnable.Message)
		}
		return false, syncErr
	}

	// 如果网络插件未准备好，只有在Pod使用主机网络时才启动Pod
	if err := kl.runtimeState.networkErrors(); err != nil && !kubecontainer.IsHostNetworkPod(pod) {
		kl.recorder.Eventf(pod, v1.EventTypeWarning, events.NetworkNotReady, "%s: %v", NetworkNotReadyErrorMsg, err)
		return false, fmt.Errorf("%s: %v", NetworkNotReadyErrorMsg, err)
	}

	// 确保kubelet知道Pod引用的机密或配置映射
	if !kl.podWorkers.IsPodTerminationRequested(pod.UID) {
		if kl.secretManager != nil {
			kl.secretManager.RegisterPod(pod)
		}
		if kl.configMapManager != nil {
			kl.configMapManager.RegisterPod(pod)
		}
	}

	// 为Pod创建Cgroups并应用资源参数（如果启用了cgroups-per-qos标志）
	pcm := kl.containerManager.NewPodContainerManager()
	// 如果Pod已终止，则不需要创建或更新Pod的cgroup
	// TODO：一旦添加上下文取消，可以删除此检查
	if !kl.podWorkers.IsPodTerminationRequested(pod.UID) {
		// 当使用cgroups-per-qos标志重新启动kubelet时，所有正在运行的容器的Pod应周期性地被终止并在qos cgroup层次结构下重新启动。
		// 检查是否为Pod的第一个同步
		firstSync := true
		for _, containerStatus := range apiPodStatus.ContainerStatuses {
			if containerStatus.State.Running != nil {
				firstSync = false
				break
			}
		}
		// 如果Pod的cgroup不存在且不是第一次同步，则不要杀死Pod中的容器
		podKilled := false
		if !pcm.Exists(pod) && !firstSync {
			p := kubecontainer.ConvertPodStatusToRunningPod(kl.getRuntime().Type(), podStatus)
			if err := kl.killPod(ctx, pod, p, nil); err == nil {
				if wait.Interrupted(err) {
					return false, err
				}
				podKilled = true
			} else {
				klog.ErrorS(err, "KillPod failed", "pod", klog.KObj(pod), "podStatus", podStatus)
			}
		}
		// 创建并更新Pod的Cgroups
		// 如果是run once Pod且上面已经杀死，则不创建cgroups
		// 当kubelet使用新标志重新启动时，当前策略是不重新启动run once Pod，
		// 因为预计run once Pod只运行一次，如果kubelet重新启动，则不应再次运行。
		// 如果是run once Pod并且已经被杀死，并且重启策略为Never，则不创建和应用cgroup的更新
		if !(podKilled && pod.Spec.RestartPolicy == v1.RestartPolicyNever) {
			if !pcm.Exists(pod) {
				if err := kl.containerManager.UpdateQOSCgroups(); err != nil {
					klog.V(2).InfoS("Failed to update QoS cgroups while syncing pod", "pod", klog.KObj(pod), "err", err)
				}
				if err := pcm.EnsureExists(pod); err != nil {
					kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToCreatePodContainer, "unable to ensure pod container exists: %v", err)
					return false, fmt.Errorf("failed to ensure that the pod: %v cgroups exist and are correctly applied: %v", pod.UID, err)
				}
			}
		}
	}

	// 如果静态Pod没有镜像Pod，则创建镜像Pod
	if kubetypes.IsStaticPod(pod) {
		deleted := false
		if mirrorPod != nil {
			if mirrorPod.DeletionTimestamp != nil || !kubepod.IsMirrorPodOf(mirrorPod, pod) {
				// 镜像Pod与静态Pod的语义不同。删除镜像Pod。稍后将重新创建镜像Pod。
				klog.InfoS("Trying to delete pod", "pod", klog.KObj(pod), "podUID", mirrorPod.ObjectMeta.UID)
				podFullName := kubecontainer.GetPodFullName(pod)
				var err error
				deleted, err = kl.mirrorPodClient.DeleteMirrorPod(podFullName, &mirrorPod.ObjectMeta.UID)
				if deleted {
					klog.InfoS("Deleted mirror pod because it is outdated", "pod", klog.KObj(mirrorPod))
				} else if err != nil {
					klog.ErrorS(err, "Failed deleting mirror pod", "pod", klog.KObj(mirrorPod))
				}
			}
		}
		if mirrorPod == nil || deleted {
			node, err := kl.GetNode()
			if err != nil || node.DeletionTimestamp != nil {
				klog.V(4).InfoS("No need to create a mirror pod, since node has been removed from the cluster", "node", klog.KRef("", string(kl.nodeName)))
			} else {
				klog.V(4).InfoS("Creating a mirror pod for static pod", "pod", klog.KObj(pod))
				if err := kl.mirrorPodClient.CreateMirrorPod(pod); err != nil {
					klog.ErrorS(err, "Failed creating a mirror pod for", "pod", klog.KObj(pod))
				}
			}
		}
	}

	// 为Pod创建数据目录
	if err := kl.makePodDataDirs(pod); err != nil {
		kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToMakePodDataDirectories, "error making pod data directories: %v", err)
		klog.ErrorS(err, "Unable to make pod data directories for pod", "pod", klog.KObj(pod))
		return false, err
	}

	// 等待卷附加/挂载
	if err := kl.volumeManager.WaitForAttachAndMount(ctx, pod); err != nil {
		if !wait.Interrupted(err) {
			kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedMountVolume, "Unable to attach or mount volumes: %v", err)
			klog.ErrorS(err, "Unable to attach or mount volumes for pod; skipping pod", "pod", klog.KObj(pod))
		}
		return false, err
	}

	// 获取Pod的拉取机密
	pullSecrets := kl.getPullSecretsForPod(pod)

	// 确保对Pod进行探测
	kl.probeManager.AddPod(pod)

	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		// 在这里处理Pod的调整大小，而不是在HandlePodUpdates中处理，
		// 这样可以方便地重试任何延迟的调整大小请求
		// TODO（vinaykul, InPlacePodVerticalScaling）：调查在HandlePodUpdates + 周期性SyncLoop扫描中执行此操作
		// 参考：https://github.com/kubernetes/kubernetes/pull/102884#discussion_r663160060
		if kl.podWorkers.CouldHaveRunningContainers(pod.UID) && !kubetypes.IsStaticPod(pod) {
			pod = kl.handlePodResourcesResize(pod)
		}
	}

	// TODO（＃113606）：将其与传入的上下文参数连接起来，该参数来自Pod worker。
	// 目前，使用该上下文会导致测试失败。要删除此todoCtx，需要从结果中过滤掉任何wait.Interrupted错误，并绕过reasonCache，
	// 取消同步Pod的上下文是已知和故意的错误，而不是通用错误。
	todoCtx := context.TODO()
	// 调用容器运行时的SyncPod回调
	result := kl.containerRuntime.SyncPod(todoCtx, pod, podStatus, pullSecrets, kl.backOff)
	kl.reasonCache.Update(pod.UID, result)
	if err := result.Error(); err != nil {
		// 如果唯一的失败是处于backoff状态的Pod，则不返回错误
		for _, r := range result.SyncResults {
			if r.Error != kubecontainer.ErrCrashLoopBackOff && r.Error != images.ErrImagePullBackOff {
				// 在此处不记录事件，因为我们将所有与同步Pod失败相关的事件日志记录
				// 限定在容器运行时本地，以便获得更好的错误。
				return false, err
			}
		}

		return false, nil
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) && isPodResizeInProgress(pod, &apiPodStatus) {
		// 在调整大小进行中时，定期调用PLEG以更新Pod缓存
		runningPod := kubecontainer.ConvertPodStatusToRunningPod(kl.getRuntime().Type(), podStatus)
		if err, _ := kl.pleg.UpdateCache(&runningPod, pod.UID); err != nil {
			klog.ErrorS(err, "Failed to update pod cache", "pod", klog.KObj(pod))
			return false, err
		}
	}
	return false, nil
}
```

##### getPullSecretsForPod

```GO
// inspect the Pod and retrieve the referenced pull secrets
func (kl *Kubelet) getPullSecretsForPod(pod *v1.Pod) []v1.Secret {
	pullSecrets := []v1.Secret{}

	// iterate over each image pull secret reference in the Pod
	for _, secretRef := range pod.Spec.ImagePullSecrets {
		if len(secretRef.Name) == 0 {
			// empty names are permitted by API validation (https://issue.k8s.io/99454#issuecomment-787838112)
			// ignore to avoid unnecessary warnings
			continue
		}

		// retrieve the secret object from the secret manager
		secret, err := kl.secretManager.GetSecret(pod.Namespace, secretRef.Name)
		if err != nil {
			// log a message indicating the failure to retrieve the pull secret
			klog.InfoS("Unable to retrieve pull secret, the image pull may not succeed.", "pod", klog.KObj(pod), "secret", klog.KObj(secret), "err", err)
			continue
		}

		// append the retrieved secret to the list of pull secrets
		pullSecrets = append(pullSecrets, *secret)
	}

	return pullSecrets
}
```

#### SyncTerminatingPod

```GO
// SyncTerminatingPod用于终止Pod中的所有运行容器。一旦该方法返回且没有错误，Pod将被视为已终止，
// 可以安全地清理与运行容器生命周期相关的任何Pod状态。下一个调用的方法将是SyncTerminatedPod。
// 此方法预期在提供的优雅期限内返回，并且如果超过该持续时间，提供的上下文可能会被取消。如果用户或kubelet
// 缩短了优雅期限（例如在驱逐期间），此方法也可能因上下文取消而中断。如果Pod从配置中被强制删除并且kubelet重启，
// 不能保证调用此方法- SyncTerminatingRuntimePod处理这些被孤立的Pod。
func (kl *Kubelet) SyncTerminatingPod(_ context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, gracePeriod *int64, podStatusFn func(*v1.PodStatus)) error {
	// TODO（＃113606）：将此与传入的上下文参数连接起来，该参数来自Pod工作程序。目前，使用该上下文会导致测试失败。
	// ctx, otelSpan := kl.tracer.Start(context.Background(), "syncTerminatingPod", trace.WithAttributes(
	// attribute.String("k8s.pod.uid", string(pod.UID)),
	// attribute.String("k8s.pod", klog.KObj(pod).String()),
	// attribute.String("k8s.pod.name", pod.Name),
	// attribute.String("k8s.namespace.name", pod.Namespace),
	// ))
	// defer otelSpan.End()
	klog.V(4).InfoS("SyncTerminatingPod enter", "pod", klog.KObj(pod), "podUID", pod.UID)
	defer klog.V(4).InfoS("SyncTerminatingPod exit", "pod", klog.KObj(pod), "podUID", pod.UID)

	apiPodStatus := kl.generateAPIPodStatus(pod, podStatus, false)
	if podStatusFn != nil {
		podStatusFn(&apiPodStatus)
	}
	kl.statusManager.SetPodStatus(pod, apiPodStatus)

	if gracePeriod != nil {
		klog.V(4).InfoS("Pod terminating with grace period", "pod", klog.KObj(pod), "podUID", pod.UID, "gracePeriod", *gracePeriod)
	} else {
		klog.V(4).InfoS("Pod terminating with grace period", "pod", klog.KObj(pod), "podUID", pod.UID, "gracePeriod", nil)
	}

	kl.probeManager.StopLivenessAndStartup(pod)

	p := kubecontainer.ConvertPodStatusToRunningPod(kl.getRuntime().Type(), podStatus)
	if err := kl.killPod(ctx, pod, p, gracePeriod); err != nil {
		kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToKillPod, "error killing pod: %v", err)
		// there was an error killing the pod, so we return that error directly
		utilruntime.HandleError(err)
		return err
	}

	// 一旦容器停止，我们可以停止对存活性和就绪性的探测。
	// TODO：一旦一个Pod处于终态，某些探测（如活跃探测）可以在容器关闭后立即停止，
	// 在第一次失败之后停止就绪性探测。这个问题跟踪在
	// https://github.com/kubernetes/kubernetes/issues/107894，尽管可能不值得优化。
	kl.probeManager.RemovePod(pod)

	// 通过检查没有运行的容器来防止KillPod实现中的一致性问题。
	// 该方法很少被调用，因此这实际上是免费的，并且可以通过调用者按顺序更新Pod状态时捕获竞态条件。
	// TODO：使KillPod返回停止容器的终态，并立即将其写入缓存
	podStatus, err := kl.containerRuntime.GetPodStatus(ctx, pod.UID, pod.Name, pod.Namespace)
	if err != nil {
		klog.ErrorS(err, "Unable to read pod status prior to final pod termination", "pod", klog.KObj(pod), "podUID", pod.UID)
		return err
	}
	var runningContainers []string
	type container struct {
		Name       string
		State      string
		ExitCode   int
		FinishedAt string
	}
	var containers []container
	klogV := klog.V(4)
	klogVEnabled := klogV.Enabled()
	for _, s := range podStatus.ContainerStatuses {
		if s.State == kubecontainer.ContainerStateRunning {
			runningContainers = append(runningContainers, s.ID.String())
		}
		if klogVEnabled {
			containers = append(containers, container{Name: s.Name, State: string(s.State), ExitCode: s.ExitCode, FinishedAt: s.FinishedAt.UTC().Format(time.RFC3339Nano)})
		}
	}
	if klogVEnabled {
		sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
		klog.V(4).InfoS("Post-termination container state", "pod", klog.KObj(pod), "podUID", pod.UID, "containers", containers)
	}
	if len(runningContainers) > 0 {
		return fmt.Errorf("detected running containers after a successful KillPod, CRI violation: %v", runningContainers)
	}

	// 注意：资源必须在所有容器停止之后和在API服务器上更改Pod状态之前进行准备，
	// 以避免与Kubernetes核心中的资源释放代码发生竞争条件。
	if utilfeature.DefaultFeatureGate.Enabled(features.DynamicResourceAllocation) {
		if err := kl.UnprepareDynamicResources(pod); err != nil {
			return err
		}
	}

	// 一旦容器不再运行，计算并更新缓存中的状态。
	// 在此处执行计算以确保用于计算的Pod状态包含有关容器结束状态（包括退出代码）的信息，
	// 当调用SyncTerminatedPod时，容器可能已经被删除。
	apiPodStatus = kl.generateAPIPodStatus(pod, podStatus, true)
	kl.statusManager.SetPodStatus(pod, apiPodStatus)

	// 我们已经成功停止了所有容器，Pod正在终止，我们的状态为“done”。
	klog.V(4).InfoS("Pod termination stopped all running containers", "pod", klog.KObj(pod), "podUID", pod.UID)

	return nil
}
```

#### SyncTerminatingRuntimePod

```GO
// SyncTerminatingRuntimePod是用于终止正在运行的没有配置信息的Pod的方法。
// 一旦该方法无错误返回，任何剩余的本地状态都可以被各子系统的后台进程安全地清理。
// 与syncTerminatingPod不同，我们缺乏完整的Pod规范信息，因此只能确保终止运行的Pod的残留部分，并允许垃圾回收继续进行。
// 我们不会更新Pod的状态，因为在配置源被删除后，我们没有发送状态的地方。
func (kl *Kubelet) SyncTerminatingRuntimePod(_ context.Context, runningPod *kubecontainer.Pod) error {
	// TODO（＃113606）：将此与传入的上下文参数连接起来，该参数来自Pod工作程序。
	// 目前，使用该上下文会导致测试失败。
	ctx := context.Background()
	pod := runningPod.ToAPIPod()
	klog.V(4).InfoS("SyncTerminatingRuntimePod enter", "pod", klog.KObj(pod), "podUID", pod.UID)
	defer klog.V(4).InfoS("SyncTerminatingRuntimePod exit", "pod", klog.KObj(pod), "podUID", pod.UID)

	// 由于我们已经失去了有关Pod的所有其他信息，我们直接终止Pod。
	klog.V(4).InfoS("Orphaned running pod terminating without grace period", "pod", klog.KObj(pod), "podUID", pod.UID)
	// TODO：这可能应该是零，以绕过任何等待（需要容器运行时中的修复）
	gracePeriod := int64(1)
	if err := kl.killPod(ctx, pod, *runningPod, &gracePeriod); err != nil {
		kl.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedToKillPod, "error killing pod: %v", err)
		// 终止Pod时发生错误，因此直接返回该错误
		utilruntime.HandleError(err)
		return err
	}
	klog.V(4).InfoS("Pod termination stopped all running orphaned containers", "pod", klog.KObj(pod), "podUID", pod.UID)
	return nil
}
```

#### SyncTerminatedPod

```GO
// SyncTerminatedPod清理已终止的Pod（没有运行的容器）。
// 此调用中的操作预计会拆除所有Pod资源。
// 当该方法退出时，预计Pod已准备好进行清理。这种方法可以减少Pod清理的延迟，但不能保证在所有情况下都会调用它。
//
// 由于Kubelet没有信息的本地存储，因此在此方法中修改磁盘状态的所有操作必须是可重入的，并且可以被HandlePodCleanups或单独的循环进行垃圾回收。
// 这通常发生在Pod从配置（本地磁盘或API）中强制删除并且kubelet在操作中重新启动的情况下。
func (kl *Kubelet) SyncTerminatedPod(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) error {
	ctx, otelSpan := kl.tracer.Start(ctx, "syncTerminatedPod", trace.WithAttributes(
		attribute.String("k8s.pod.uid", string(pod.UID)),
		attribute.String("k8s.pod", klog.KObj(pod).String()),
		attribute.String("k8s.pod.name", pod.Name),
		attribute.String("k8s.namespace.name", pod.Namespace),
	))
	defer otelSpan.End()
	klog.V(4).InfoS("SyncTerminatedPod enter", "pod", klog.KObj(pod), "podUID", pod.UID)
	defer klog.V(4).InfoS("SyncTerminatedPod exit", "pod", klog.KObj(pod), "podUID", pod.UID)

	// 生成Pod的最终状态
	// TODO：我们应该将此合并到TerminatePod中吗？这将提供单个Pod更新
	apiPodStatus := kl.generateAPIPodStatus(pod, podStatus, true)

	kl.statusManager.SetPodStatus(pod, apiPodStatus)

	// 在Pod工作程序报告ShouldPodRuntimeBeRemoved之后（在调用syncTerminatedPod之前），卸载卷
	if err := kl.volumeManager.WaitForUnmount(ctx, pod); err != nil {
		return err
	}
	klog.V(4).InfoS("Pod termination unmounted volumes", "pod", klog.KObj(pod), "podUID", pod.UID)

	if !kl.keepTerminatedPodVolumes {
		// 该等待循环依赖于后台清理，后台清理在pod工作程序回应true，ShouldPodRuntimeBeRemoved后开始，而该回应在SyncTerminatingPod完成之后。
		if err := wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
			volumesExist := kl.podVolumesExist(pod.UID)
			if volumesExist {
				klog.V(3).InfoS("Pod is terminated, but some volumes have not been cleaned up", "pod", klog.KObj(pod), "podUID", pod.UID)
			}
			return !volumesExist, nil
		}); err != nil {
			return err
		}
		klog.V(3).InfoS("Pod termination cleaned up volume paths", "pod", klog.KObj(pod), "podUID", pod.UID)
	}

	// 卸载卷完成后，让secret和configmap管理器知道我们已完成对该pod的操作
	if kl.secretManager != nil {
		kl.secretManager.UnregisterPod(pod)
	}
	if kl.configMapManager != nil {
		kl.configMapManager.UnregisterPod(pod)
	}

	// 注意：我们在后台保留pod容器以便进行回收，因为dockershim需要容器来检索日志，我们希望确保日志在物理删除pod之前可用。

	// 删除不再运行的Pod的层次结构中的任何cgroup。
	if kl.cgroupsPerQOS {
		pcm := kl.containerManager.NewPodContainerManager()
		name, _ := pcm.GetPodContainerName(pod)
		if err := pcm.Destroy(name); err != nil {
			return err
		}
		klog.V(4).InfoS("Pod termination removed cgroups", "pod", klog.KObj(pod), "podUID", pod.UID)
	}

	kl.usernsManager.Release(pod.UID)

	// 标记最终的Pod状态
	kl.statusManager.TerminatePod(pod)
	klog.V(4).InfoS("Pod is terminated and will need no more status updates", "pod", klog.KObj(pod), "podUID", pod.UID)

	return nil
}
```

### new

```go
func newPodWorkers(
	podSyncer podSyncer,
	recorder record.EventRecorder,
	workQueue queue.WorkQueue,
	resyncInterval, backOffPeriod time.Duration,
	podCache kubecontainer.Cache,
) PodWorkers {
	return &podWorkers{
		podSyncStatuses:                    map[types.UID]*podSyncStatus{},
		podUpdates:                         map[types.UID]chan struct{}{},
		startedStaticPodsByFullname:        map[string]types.UID{},
		waitingToStartStaticPodsByFullname: map[string][]types.UID{},
		podSyncer:                          podSyncer,
		recorder:                           recorder,
		workQueue:                          workQueue,
		resyncInterval:                     resyncInterval,
		backOffPeriod:                      backOffPeriod,
		podCache:                           podCache,
		clock:                              clock.RealClock{},
	}
}
```

### UpdatePod

```go
// UpdatePod 用于将配置更改或终止状态应用到一个 Pod 上。Pod 可以是可运行的、正在终止的或已终止的状态，并且在以下情况下将转换为终止状态：从 apiserver 中删除、发现处于终止阶段（已成功或已失败）或被 kubelet 驱逐。
func (p *podWorkers) UpdatePod(options UpdatePodOptions) {
	// 处理当 Pod 是孤立的（没有配置信息）且我们只有运行时状态的情况，只运行生命周期的终止部分。运行中的 Pod 只包含有关 Pod 的最小信息集。
	var isRuntimePod bool
	var uid types.UID
	var name, ns string
	if runningPod := options.RunningPod; runningPod != nil {
		if options.Pod == nil {
			// 在这里创建的合成 Pod 仅用作占位符，不会被跟踪
			if options.UpdateType != kubetypes.SyncPodKill {
				klog.InfoS("Pod update is ignored, runtime pods can only be killed", "pod", klog.KRef(runningPod.Namespace, runningPod.Name), "podUID", runningPod.ID, "updateType", options.UpdateType)
				return
			}
			uid, ns, name = runningPod.ID, runningPod.Namespace, runningPod.Name
			isRuntimePod = true
		} else {
			options.RunningPod = nil
			uid, ns, name = options.Pod.UID, options.Pod.Namespace, options.Pod.Name
			klog.InfoS("Pod update included RunningPod which is only valid when Pod is not specified", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
		}
	} else {
		uid, ns, name = options.Pod.UID, options.Pod.Namespace, options.Pod.Name
	}

	p.podLock.Lock()
	defer p.podLock.Unlock()

	// 决定如何处理此 Pod，我们要么设置它、拆除它，或忽略它
	var firstTime bool
	now := p.clock.Now()
	status, ok := p.podSyncStatuses[uid]
	if !ok {
		klog.V(4).InfoS("Pod is being synced for the first time", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
		firstTime = true
		status = &podSyncStatus{
			syncedAt: now,
			fullname: kubecontainer.BuildPodFullName(name, ns),
		}
		// 如果这个 Pod 是第一次同步，我们需要确保它是一个活动的 Pod
		if options.Pod != nil && (options.Pod.Status.Phase == v1.PodFailed || options.Pod.Status.Phase == v1.PodSucceeded) {
			// 检查 Pod 是否不在运行状态且处于终止状态；如果是，则在 podWorker 中记录其已终止状态。
			// 这是因为在 kubelet 重启后，我们需要确保已终止的 Pod 不会被认为是活动的 Pod Admission。参见 http://issues.k8s.io/105523
			// 然而，filterOutInactivePods 认为正在终止的 Pod 是活动的。因此，IsPodKnownTerminated() 需要返回 true，并设置 terminatedAt。
			if statusCache, err := p.podCache.Get(uid); err == nil {
				if isPodStatusCacheTerminal(statusCache) {
					// 在这一点上，我们知道：
					// (1) 基于配置源，Pod 是终止的。
					// (2) 基于运行时缓存，Pod 是终止的。
					// 这意味着该 Pod 在过去的某个时间已经完成了 SyncTerminatingPod。该 Pod 可能是由于 kubelet 重启而首次同步。
					// 这些 Pod 需要完成 SyncTerminatedPod，以确保清理所有资源，并使状态管理器对该 Pod 进行最终的状态更新。
					// 因此，设置 finished: false，以确保发送 Terminated 事件并运行 SyncTerminatedPod。
					status = &podSyncStatus{
						terminatedAt:       now,
						terminatingAt:      now,
						syncedAt:           now,
						startedTerminating: true,
						finished:           false,
						fullname:           kubecontainer.BuildPodFullName(name, ns),
					}
				}
			}
		}
		p.podSyncStatuses[uid] = status

		// RunningPods 表示一个未知的 Pod 执行，不包含足够的 Pod 规范信息来执行除终止之外的任何操作。如果我们收到一个 RunningPod，在提供了真正的 Pod 之后，使用最新的规范。此外，一旦我们观察到运行时 Pod，即使不是我们启动的，也必须将其驱动到完成。
		pod := options.Pod
		if isRuntimePod {
			status.observedRuntime = true
			switch {
			case status.pendingUpdate != nil && status.pendingUpdate.Pod != nil:
				pod = status.pendingUpdate.Pod
				options.Pod = pod
				options.RunningPod = nil
			case status.activeUpdate != nil && status.activeUpdate.Pod != nil:
				pod = status.activeUpdate.Pod
				options.Pod = pod
				options.RunningPod = nil
			default:
				// 在这里将继续使用 RunningPod.ToAPIPod() 作为 pod，但 options.Pod 将为 nil，其他方法必须适当处理。
				pod = options.RunningPod.ToAPIPod()
			}
		}

		// 当我们看到已经处于终止状态的 Pod 上的创建更新时，这意味着两个具有相同 UID 的 Pod 在短时间内创建（通常是静态 Pod，但 apiserver 极少情况下也可能这样做） - 标记同步状态，以指示在 Pod 终止后将其重置为“未运行”，以便允许后续的添加/更新再次启动 Pod Worker。这不适用于第一次看到 Pod 的情况，例如当 kubelet 重启时，我们首次看到已经终止的 Pod。
		if !firstTime && status.IsTerminationRequested() {
			if options.UpdateType == kubetypes.SyncPodCreate {
				status.restartRequested = true
				klog.V(4).InfoS("Pod is terminating but has been requested to restart with same UID, will be reconciled later", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
				return
			}
		}

		// 一旦通过 UID 终止了一个 Pod，它就不能重新进入 Pod Worker（直到 UID 被清理）
		if status.IsFinished() {
			klog.V(4).InfoS("Pod is finished processing, no further updates", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
			return
		}

		// 检查是否转换为终止状态
		var becameTerminating bool
		if !status.IsTerminationRequested() {
			switch {
			case isRuntimePod:
				klog.V(4).InfoS("Pod is orphaned and must be torn down", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
				status.deleted = true
				status.terminatingAt = now
				becameTerminating = true
			case pod.DeletionTimestamp != nil:
				klog.V(4).InfoS("Pod is marked for graceful deletion, begin teardown", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
				status.deleted = true
				status.terminatingAt = now
				becameTerminating = true
			case pod.Status.Phase == v1.PodFailed, pod.Status.Phase == v1.PodSucceeded:
				klog.V(4).InfoS("Pod is in a terminal phase (success/failed), begin teardown", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
				status.terminatingAt = now
				becameTerminating = true
			case options.UpdateType == kubetypes.SyncPodKill:
				if options.KillPodOptions != nil && options.KillPodOptions.Evict {
					klog.V(4).InfoS("Pod is being evicted by the kubelet, begin teardown", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
					status.evicted = true
				} else {
					klog.V(4).InfoS("Pod is being removed by the kubelet, begin teardown", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
				}
				status.terminatingAt = now
				becameTerminating = true
			}
		}

		// 一旦一个 Pod 开始终止，所有的更新都是终止请求，优雅期只能减少
		var wasGracePeriodShortened bool
		switch {
		case status.IsTerminated():
			// 终止的 Pod 可能仍在等待清理 - 如果我们收到一个运行时 Pod 的 kill 请求，这是因为 housekeeping 看到了运行时 Pod 的旧缓存版本，就简单地忽略它，直到 Pod Worker 完全终止后再处理。
			if isRuntimePod {
				klog.V(3).InfoS("Pod is waiting for termination, ignoring runtime-only kill until after pod worker is fully terminated", "pod", klog.KRef(ns, name), "podUID", uid, "updateType", options.UpdateType)
				return
			}

			if options.KillPodOptions != nil {
				if ch := options.KillPodOptions.CompletedCh; ch != nil {
					close(ch)
				}
			}
			options.KillPodOptions = nil
		case status.IsTerminationRequested():
			if options.KillPodOptions == nil {
				options.KillPodOptions = &KillPodOptions{}
			}

			if ch := options.KillPodOptions.CompletedCh; ch != nil {
				status.notifyPostTerminating = append(status.notifyPostTerminating, ch)
			}
			if fn := options.KillPodOptions.PodStatusFunc; fn != nil {
				status.statusPostTerminating = append(status.statusPostTerminating, fn)
			}

			gracePeriod, gracePeriodShortened := calculateEffectiveGracePeriod(status, pod, options.KillPodOptions)

			wasGracePeriodShortened = gracePeriodShortened
			status.gracePeriod = gracePeriod
			// always set the grace period for syncTerminatingPod so we don't have to recalculate,
			// will never be zero.
			options.KillPodOptions.PodTerminationGracePeriodSecondsOverride = &gracePeriod
		default:
			// 在终止阶段之外的同步操作中，KillPodOptions 无效
			if options.KillPodOptions != nil {
				if ch := options.KillPodOptions.CompletedCh; ch != nil {
					close(ch)
				}
				options.KillPodOptions = nil
			}
		}

		// 如果 Pod Worker Goroutine 不存在，则启动它
		podUpdates, exists := p.podUpdates[uid]
		if !exists {
			// 为了避免阻塞此方法，缓冲通道
			podUpdates = make(chan struct{}, 1)
			p.podUpdates[uid] = podUpdates

			// 确保静态 Pod 按 UpdatePod 收到的顺序启动
			if kubetypes.IsStaticPod(pod) {
				p.waitingToStartStaticPodsByFullname[status.fullname] =
					append(p.waitingToStartStaticPodsByFullname[status.fullname], uid)
			}

			// 允许测试 pod 更新通道的延迟
			var outCh <-chan struct{}
			if p.workerChannelFn != nil {
				outCh = p.workerChannelFn(uid, podUpdates)
			} else {
				outCh = podUpdates
			}
			go func() {
				// TODO: 这应该是一个带有退避(backoff)机制的 wait.Until，用于处理 panic，并接受用于关闭的上下文。
				defer runtime.HandleCrash()
				defer klog.V(3).InfoS("Pod worker has stopped", "podUID", uid)
				p.podWorkerLoop(uid, outCh)
			}()
		}
		// 测量从调用 UpdatePod 到 pod worker 对其作出反应的最大延迟，通过保留最早的 StartTime。
		if status.pendingUpdate != nil && !status.pendingUpdate.StartTime.IsZero() && status.pendingUpdate.StartTime.Before(options.StartTime) {
			options.StartTime = status.pendingUpdate.StartTime
		}

		// 通知 pod worker 存在待处理的更新。
		status.pendingUpdate = &options
		status.working = true
		klog.V(4).InfoS("Notifying pod of pending update", "pod", klog.KRef(ns, name), "podUID", uid, "workType", status.WorkType())
		select {
		case podUpdates <- struct{}{}:
		default:
		}

		if (becameTerminating || wasGracePeriodShortened) && status.cancelFn != nil {
			klog.V(3).InfoS("Cancelling current pod sync", "pod", klog.KRef(ns, name), "podUID", uid, "workType", status.WorkType())
			status.cancelFn()
			return
		}
	}
}
```

#### isPodStatusCacheTerminal

```GO
func isPodStatusCacheTerminal(status *kubecontainer.PodStatus) bool {
	runningContainers := 0
	runningSandboxes := 0
	for _, container := range status.ContainerStatuses {
		if container.State == kubecontainer.ContainerStateRunning {
			runningContainers++
		}
	}
	for _, sb := range status.SandboxStatuses {
		if sb.State == runtimeapi.PodSandboxState_SANDBOX_READY {
			runningSandboxes++
		}
	}
	return runningContainers == 0 && runningSandboxes == 0
}
```

#### podWorkerLoop

```GO
// podWorkerLoop在goroutine中管理对pod的顺序状态更新，在达到最终状态后退出。该循环负责推动pod通过四个主要阶段：
//
// 1. 等待启动，确保同一时间没有两个具有相同UID或完整名称的pod正在运行
// 2. 同步，通过协调期望的pod规范与pod的运行时状态来组织pod的设置
// 3. 终止，确保停止pod中所有正在运行的容器
// 4. 终止后，清理必须在删除pod之前释放的任何资源
//
// podWorkerLoop由传递给UpdatePod和SyncKnownPods的更新驱动。如果特定的同步方法失败，p.workerQueue会进行更新，但触发新的UpdatePod调用是kubelet的责任。
// SyncKnownPods只会重试不再为调用者所知的pod。当pod从工作状态转换为终止状态或从终止状态转换为终止后，下一个更新将立即排队，kubelet不需要进行任何操作。
func (p *podWorkers) podWorkerLoop(podUID types.UID, podUpdates <-chan struct{}) {
	var lastSyncTime time.Time
	for range podUpdates {
		ctx, update, canStart, canEverStart, ok := p.startPodSync(podUID)
		// 如果没有等待的更新，意味着有人初始化了该通道而没有填充pendingUpdate。
		if !ok {
			continue
			// 如果pod在允许启动之前已终止，则退出循环。
		}
		if !canEverStart {
			return
		}
		// 如果pod尚未准备好启动，则继续等待更多的更新。
		if !canStart {
			continue
		}

		podUID, podRef := podUIDAndRefForUpdate(update.Options)

		klog.V(4).InfoS("处理pod事件", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
		var isTerminal bool
		err := func() error {
			// worker负责确保同步方法在重新同步时（上次同步的结果）、转换为终止时（无需等待）或终止时（最近的状态）看到适当的状态更新。
			// 只有同步和终止可以生成pod状态更改，而终止后的pod确保最近的状态传递给api server。
			var status *kubecontainer.PodStatus
			var err error
			switch {
			case update.Options.RunningPod != nil:
				// 当我们收到正在运行的pod时，我们根本不需要状态，因为我们保证正在终止，并且我们跳过对pod的更新
			default:
				// 等待我们从PLEG通过缓存看到下一个刷新（最大2秒）
				// TODO: 这将在所有从同步到终止，终止到终止的转换以及所有终止重试（包括驱逐）中增加大约1秒的延迟。
				// 我们应该通过使pleg连续运行并在发生关键事件（killPod，sync->terminating）时刷新pod状态更改来改进延迟。
				// 改进此延迟还减少了终止的容器状态在我们有机会更新api server之前可能被垃圾收集的可能性（从而丢失退出代码）。
				status, err = p.podCache.GetNewerThan(update.Options.Pod.UID, lastSyncTime)

				if err != nil {
					// 这是由manage pod loop引发的传统事件，现在所有其他事件都从syncPodFn派发
					p.recorder.Eventf(update.Options.Pod, v1.EventTypeWarning, events.FailedSync, "error determining status: %v", err)
					return err
				}
			}

			// 执行适当的操作（通过UpdatePod防止非法阶段）
			switch {
			case update.WorkType == TerminatedPod:
				err = p.podSyncer.SyncTerminatedPod(ctx, update.Options.Pod, status)

			case update.WorkType == TerminatingPod:
				var gracePeriod *int64
				if opt := update.Options.KillPodOptions; opt != nil {
					gracePeriod = opt.PodTerminationGracePeriodSecondsOverride
				}
				podStatusFn := p.acknowledgeTerminating(podUID)

				// 如果我们只有一个正在运行的pod，则直接终止它
				if update.Options.RunningPod != nil {
					err = p.podSyncer.SyncTerminatingRuntimePod(ctx, update.Options.RunningPod)
				} else {
					err = p.podSyncer.SyncTerminatingPod(ctx, update.Options.Pod, status, gracePeriod, podStatusFn)
				}

			default:
				isTerminal, err = p.podSyncer.SyncPod(ctx, update.Options.UpdateType, update.Options.Pod, update.Options.MirrorPod, status)
			}

			lastSyncTime = p.clock.Now()
			return err
		}()

		var phaseTransition bool
		switch {
		case err == context.Canceled:
			// 当上下文被取消时，我们期望已经排队了一个更新
			klog.V(2).InfoS("同步以上下文取消错误退出", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)

		case err != nil:
			// 我们将排队重试
			klog.ErrorS(err, "同步pod时发生错误，跳过", "pod", podRef, "podUID", podUID)

		case update.WorkType == TerminatedPod:
			// 我们可以关闭worker
			p.completeTerminated(podUID)
			if start := update.Options.StartTime; !start.IsZero() {
				metrics.PodWorkerDuration.WithLabelValues("terminated").Observe(metrics.SinceInSeconds(start))
			}
			klog.V(4).InfoS("处理pod事件完成", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
			return

		case update.WorkType == TerminatingPod:
			// 不在配置中存在的pod不需要被终止，其他循环将清理它们
			if update.Options.RunningPod != nil {
				p.completeTerminatingRuntimePod(podUID)
				if start := update.Options.StartTime; !start.IsZero() {
					metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
				}
				klog.V(4).InfoS("处理pod事件完成", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
				return
			}
			// 否则，我们进入终止阶段
			p.completeTerminating(podUID)
			phaseTransition = true

		case isTerminal:
			// 如果syncPod指示我们现在是终端状态，设置适当的pod状态以进入终止阶段
			klog.V(4).InfoS("Pod已终止", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
			p.completeSync(podUID)
			phaseTransition = true
		}

		// 如果需要，排队重试，然后将下一个事件放入通道（如果有的话）
		p.completeWork(podUID, phaseTransition, err)
		if start := update.Options.StartTime; !start.IsZero() {
			metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
		}
		klog.V(4).InfoS("处理pod事件完成", "pod", podRef, "podUID", podUID, "updateType", update.WorkType)
	}
}
```

##### acknowledgeTerminating

```GO
// acknowledgeTerminating函数用于在Pod工作器观察到终止状态后，在Pod状态上设置终止标志，以便其他组件知道该Pod不会启动新的容器。然后它返回适用于该Pod的状态函数（如果有）。
func (p *podWorkers) acknowledgeTerminating(podUID types.UID) PodStatusFunc {
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	status, ok := p.podSyncStatuses[podUID] // 从podSyncStatuses映射中获取指定podUID对应的状态
	if !ok {                                // 如果状态不存在，则返回nil
		return nil
	}

	// 如果终止时间戳（terminatingAt）不为零且尚未开始终止过程，则设置startedTerminating标志，并记录日志
	if !status.terminatingAt.IsZero() && !status.startedTerminating {
		klog.V(4).InfoS("Pod worker has observed request to terminate", "podUID", podUID)
		status.startedTerminating = true
	}

	// 如果statusPostTerminating切片的长度大于0，则返回最后一个状态函数
	if l := len(status.statusPostTerminating); l > 0 {
		return status.statusPostTerminating[l-1]
	}
	return nil // 否则返回nil
}
```

##### completeTerminated

```GO
// completeTerminated函数在syncTerminatedPod成功完成后被调用，表示可以停止Pod工作器。此时，Pod被最终化。
func (p *podWorkers) completeTerminated(podUID types.UID) {
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	klog.V(4).InfoS("Pod is complete and the worker can now stop", "podUID", podUID) // 记录日志，表示Pod已完成并且工作器可以停止

	p.cleanupPodUpdates(podUID) // 清理与podUID相关的Pod更新

	status, ok := p.podSyncStatuses[podUID] // 从podSyncStatuses映射中获取指定podUID对应的状态
	if !ok {
		return
	}

	if status.terminatingAt.IsZero() {
		klog.V(4).InfoS("Pod worker is complete but did not have terminatingAt set, likely programmer error", "podUID", podUID)
	}
	if status.terminatedAt.IsZero() {
		klog.V(4).InfoS("Pod worker is complete but did not have terminatedAt set, likely programmer error", "podUID", podUID)
	}
	status.finished = true
	status.working = false

	if p.startedStaticPodsByFullname[status.fullname] == podUID {
		delete(p.startedStaticPodsByFullname, status.fullname)
	}
}
```

###### cleanupPodUpdates

```GO
// cleanupPodUpdates 关闭 podUpdates 通道并从 podUpdates 映射中移除，以便对应的 pod worker 可以停止。它还会移除任何未发送的任务。必须在持有 pod 锁时调用该方法。
func (p *podWorkers) cleanupPodUpdates(uid types.UID) {
	if ch, ok := p.podUpdates[uid]; ok {
		close(ch)
	}
	delete(p.podUpdates, uid)
}
```

##### completeTerminatingRuntimePod

````GO
// completeTerminatingRuntimePod函数在syncTerminatingPod成功完成后被调用，表示一个孤立的Pod（无配置）已被终止，我们可以退出。由于孤立的Pod没有API表示，因此我们希望在此时退出循环，并确保后续没有状态存在 - 当调用此函数时，正在运行的Pod真正终止。
func (p *podWorkers) completeTerminatingRuntimePod(podUID types.UID) {
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	klog.V(4).InfoS("Pod terminated all orphaned containers successfully and worker can now stop", "podUID", podUID) // 记录日志，表示Pod成功终止所有孤立的容器，工作器可以停止

	p.cleanupPodUpdates(podUID) // 清理与podUID相关的Pod更新

	status, ok := p.podSyncStatuses[podUID] // 从podSyncStatuses映射中获取指定podUID对应的状态
	if !ok {
		return
	}
	if status.terminatingAt.IsZero() {
		klog.V(4).InfoS("Pod worker was terminated but did not have terminatingAt set, likely programmer error", "podUID", podUID)
	}
	status.terminatedAt = p.clock.Now()
	status.finished = true
	status.working = false

	if p.startedStaticPodsByFullname[status.fullname] == podUID {
		delete(p.startedStaticPodsByFullname, status.fullname)
	}

	// 运行时Pod是临时的，不属于期望的状态 - 一旦它达到终止状态，我们可以放弃对其的跟踪。
	delete(p.podSyncStatuses, podUID)
}
````

##### completeTerminating

```GO
// completeTerminating函数在syncTerminatingPod成功完成后被调用，表示没有容器正在运行，将来也不会启动任何容器，我们已准备好进行清理。这将更新终止状态，防止将来进行同步，并确保其他kubelet循环知道该Pod不再运行任何容器。
func (p *podWorkers) completeTerminating(podUID types.UID) {
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	klog.V(4).InfoS("Pod terminated all containers successfully", "podUID", podUID) // 记录日志，表示Pod成功终止所有容器

	status, ok := p.podSyncStatuses[podUID] // 从podSyncStatuses映射中获取指定podUID对应的状态
	if !ok {
		return
	}

	// 更新Pod的状态
	if status.terminatingAt.IsZero() {
		klog.V(4).InfoS("Pod worker was terminated but did not have terminatingAt set, likely programmer error", "podUID", podUID)
	}
	status.terminatedAt = p.clock.Now()
	for _, ch := range status.notifyPostTerminating {
		close(ch)
	}
	status.notifyPostTerminating = nil
	status.statusPostTerminating = nil

	// Pod现在已经过渡到终止状态，我们希望尽快运行syncTerminatedPod，因此如果没有等待的更新，就排队一个合成更新
	p.requeueLastPodUpdate(podUID, status)
}
```

##### completeSync

```GO
// completeSync在syncPod成功完成后被调用，表示Pod现在处于终止状态并应该被终止。这发生在自然的Pod生命周期完成时 - 任何非RestartAlways的Pod都会退出。不正常的完成，如驱逐、API驱动的删除或阶段转换，由UpdatePod处理。
func (p *podWorkers) completeSync(podUID types.UID) {
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	klog.V(4).InfoS("Pod indicated lifecycle completed naturally and should now terminate", "podUID", podUID) // 记录日志，表示Pod自然地完成了生命周期，并且现在应该终止

	status, ok := p.podSyncStatuses[podUID] // 从podSyncStatuses映射中获取指定podUID对应的状态
	if !ok {
		klog.V(4).InfoS("Pod had no status in completeSync, programmer error?", "podUID", podUID)
		return
	}

	// 更新Pod的状态
	if status.terminatingAt.IsZero() {
		status.terminatingAt = p.clock.Now()
	} else {
		klog.V(4).InfoS("Pod worker attempted to set terminatingAt twice, likely programmer error", "podUID", podUID)
	}
	status.startedTerminating = true

	// Pod现在已经过渡到终止状态，我们希望尽快运行syncTerminatingPod，因此如果没有等待的更新，就排队一个合成更新
	p.requeueLastPodUpdate(podUID, status)
}
```

###### requeueLastPodUpdate

```GO
// requeueLastPodUpdate 如果没有更新排队，从最近执行的更新创建一个新的待处理的 pod 更新，然后通知 pod worker 的 goroutine 进行更新。必须在持有 pod 锁时调用该方法。
func (p *podWorkers) requeueLastPodUpdate(podUID types.UID, status *podSyncStatus) {
	// 如果已经有一个更新在排队，我们可以使用该更新，或者如果没有先前执行的更新，则无法重放它。
	if status.pendingUpdate != nil || status.activeUpdate == nil {
		return
	}
	copied := *status.activeUpdate
	status.pendingUpdate = &copied

	// 通知 pod worker
	status.working = true
	select {
	case p.podUpdates[podUID] <- struct{}{}:
	default:
	}
}
```

##### completeWork

```GO
// completeWork在出现错误或下一个同步间隔时重新排队，然后立即执行任何待处理的工作。
func (p *podWorkers) completeWork(podUID types.UID, phaseTransition bool, syncErr error) {
	// 如果最后一次同步返回错误，则重新排队最后一次更新。
	switch {
	case phaseTransition:
		p.workQueue.Enqueue(podUID, 0)
	case syncErr == nil:
		// 没有错误；按照常规的重新同步间隔重新排队。
		p.workQueue.Enqueue(podUID, wait.Jitter(p.resyncInterval, workerResyncIntervalJitterFactor))
	case strings.Contains(syncErr.Error(), NetworkNotReadyErrorMsg):
		// 网络还没有准备好；等待一段时间后重试，因为网络可能很快准备好。
		p.workQueue.Enqueue(podUID, wait.Jitter(backOffOnTransientErrorPeriod, workerBackOffPeriodJitterFactor))
	default:
		// 同步过程中发生错误；进行指数退避，然后重试。
		p.workQueue.Enqueue(podUID, wait.Jitter(p.backOffPeriod, workerBackOffPeriodJitterFactor))
	}

	// 如果该工作器有一个待处理的更新，则立即重新排队；否则清除工作状态。
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁
	if status, ok := p.podSyncStatuses[podUID]; ok {
		if status.pendingUpdate != nil {
			select {
			case p.podUpdates[podUID] <- struct{}{}:
				klog.V(4).InfoS("Requeueing pod due to pending update", "podUID", podUID) // 记录日志，表示由于待处理的更新，重新排队Pod
			default:
				klog.V(4).InfoS("Pod has pending update but was not able to requeue", "podUID", podUID) // 记录日志，表示由于无法重新排队，Pod有待处理的更新
			}
		} else {
			delete(p.podSyncStatuses, podUID)
		}
	}
}
```

##### waitForSyncHandlers

```GO
// waitForSyncHandlers函数用于等待Pod同步处理程序的完成。它会一直阻塞，直到所有处理程序都已完成。
func (p *podWorkers) waitForSyncHandlers(podUID types.UID, status *podSyncStatus) {
	status.syncHandlerWaitGroup.Wait()
	p.podLock.Lock()         // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	// 移除syncHandlerWaitGroup中的所有处理程序
	for i := 0; i < len(status.syncHandlers); i++ {
		status.syncHandlers[i] = nil
	}
	status.syncHandlers = status.syncHandlers[:0]
}
```

### SyncKnownPods

```GO
// SyncKnownPods 会清除任何不在 desiredPods 列表中的完全终止的 pod，这意味着 SyncKnownPods 必须以线程安全的方式从对新 pod 的 UpdatePods 调用中调用。因为 podworker 依赖于调用 UpdatePod 来驱动 pod 的状态机，如果 desired 列表中缺少一个 pod，pod worker 必须负责传递该更新。该方法返回一个已知 worker 的映射，其值为 SyncPodTerminated、SyncPodKill 或 SyncPodSync，取决于 pod 是否终止、终止中或同步中。
func (p *podWorkers) SyncKnownPods(desiredPods []*v1.Pod) map[types.UID]PodWorkerSync {
	workers := make(map[types.UID]PodWorkerSync)
	known := make(map[types.UID]struct{})
	for _, pod := range desiredPods {
		known[pod.UID] = struct{}{}
	}

	p.podLock.Lock()
	defer p.podLock.Unlock()

	p.podsSynced = true
	for uid, status := range p.podSyncStatuses {
		// 对于仍然在 desired 列表中的 pod，我们保留其 worker 历史记录。然而，在同步期间，有两种情况会导致我们需要清除历史记录：
		//
		// 1. pod 不再 desired（本地版本已被删除）
		// 2. pod 收到 kill 更新，然后是后续的 create 更新，这意味着 UID 在源配置中被重用（API 服务器几乎不会发生，静态 pod 常见，其指定了固定 UID）
		//
		// 在前一种情况下，我们希望限制为已删除 pod 存储的信息量。在后一种情况下，我们希望最大限度地缩短重新启动静态 pod 前的时间。如果我们成功地删除了 worker，那么我们将在返回的已知 worker 映射中省略它，并且调用 SyncKnownPods 的调用方应发送一个新的 UpdatePod({UpdateType: Create})。
		_, knownPod := known[uid]
		orphan := !knownPod
		if status.restartRequested || orphan {
			if p.removeTerminatedWorker(uid, status, orphan) {
				// 没有运行的 worker，我们不会将其返回
				continue
			}
		}

		sync := PodWorkerSync{
			State:  status.WorkType(),
			Orphan: orphan,
		}
		switch {
		case status.activeUpdate != nil:
			if status.activeUpdate.Pod != nil {
				sync.HasConfig = true
				sync.Static = kubetypes.IsStaticPod(status.activeUpdate.Pod)
			}
		case status.pendingUpdate != nil:
			if status.pendingUpdate.Pod != nil {
				sync.HasConfig = true
				sync.Static = kubetypes.IsStaticPod(status.pendingUpdate.Pod)
			}
		}
		workers[uid] = sync
	}
	return workers
}
```

#### removeTerminatedWorker

```GO
// removeTerminatedWorker 清理并移除已达到 "finished" 终止状态的 worker 状态 - 成功退出 syncTerminatedPod。通过 UID "遗忘" 一个 pod，并允许使用相同的 UID 重新创建另一个 pod。kubelet 保留关于最近终止的 pod 的状态，以防止意外重启终止的 pod，这与 pod 配置中描述的 pod 数量成比例。如果 worker 被完全删除，则该方法返回 true。
func (p *podWorkers) removeTerminatedWorker(uid types.UID, status *podSyncStatus, orphaned bool) bool {
	if !status.finished {
		// 如果 pod worker 尚未达到终止状态并且 pod 仍然已知，我们等待。
		if !orphaned {
			klog.V(4).InfoS("Pod worker 已请求删除但仍未完全终止", "podUID", uid)
			return false
		}

		// 所有孤立的 pod 都被认为已删除
		status.deleted = true

		// 当 pod 不再处于 desired 集合中时，将其视为孤立 pod，pod worker 负责将其驱动到完成状态（没有其他组件通知我们更新）。
		switch {
		case !status.IsStarted() && !status.observedRuntime:
			// pod 尚未启动，这意味着我们可以安全地清理 pod - pod worker 将因此更改而关闭而不执行同步。
			klog.V(4).InfoS("Pod 是孤立的并且尚未启动", "podUID", uid)
		case !status.IsTerminationRequested():
			// pod 已启动但尚未请求终止 - 设置适当的时间戳并通知 pod worker。因为 pod 至少已同步一次，所以 status.activeUpdate 的值将成为下一次同步的回退值。
			status.terminatingAt = p.clock.Now()
			if status.activeUpdate != nil && status.activeUpdate.Pod != nil {
				status.gracePeriod, _ = calculateEffectiveGracePeriod(status, status.activeUpdate.Pod, nil)
			} else {
				status.gracePeriod = 1
			}
			p.requeueLastPodUpdate(uid, status)
			klog.V(4).InfoS("Pod 是孤立的并且仍在运行，开始终止", "podUID", uid)
			return false
		default:
			// pod 已经开始朝着终止状态前进，通知 pod worker。因为 pod 至少已同步一次，所以 status.activeUpdate 的值将成为下一次同步的回退值。
			p.requeueLastPodUpdate(uid, status)
			klog.V(4).InfoS("Pod 是孤立的并且仍在终止中，通知 pod worker", "podUID", uid)
			return false
		}
	}

	if status.restartRequested {
		klog.V(4).InfoS("Pod 已终止，但使用相同的 UID 创建了另一个 pod，删除历史记录以允许重新启动", "podUID", uid)
	} else {
		klog.V(4).InfoS("Pod 已终止并且不再为 kubelet 所知，删除所有历史记录", "podUID", uid)
	}
	delete(p.podSyncStatuses, uid)
	p.cleanupPodUpdates(uid)

	if p.startedStaticPodsByFullname[status.fullname] == uid {
		delete(p.startedStaticPodsByFullname, status.fullname)
	}
	return true
}
```

### IsPodKnownTerminated

```GO
func (p *podWorkers) IsPodKnownTerminated(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsTerminated() // 返回Pod的状态是否为已终止
	}

	// 如果Pod未知，则返回false（Pod工作器不知道该Pod）
	return false
}
```

### CouldHaveRunningContainers

```GO
func (p *podWorkers) CouldHaveRunningContainers(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		return !status.IsTerminated() // 返回Pod的状态是否不为已终止
	}

	// 一旦所有Pod都已同步，任何没有同步状态的Pod被认为不在运行。
	return !p.podsSynced
}
```

### ShouldPodBeFinished

````GO
func (p *podWorkers) ShouldPodBeFinished(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsFinished() // 返回Pod的状态是否为已完成
	}

	// 一旦所有Pod都已同步，任何没有同步状态的Pod被假设为已完成SyncTerminatedPod。
	return p.podsSynced
}
````

### IsPodTerminationRequested

```GO
func (p *podWorkers) IsPodTerminationRequested(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		// 在此时，Pod可能仍在设置过程中。
		return status.IsTerminationRequested() // 返回Pod的状态是否为已请求终止
	}

	// 未知的Pod被认为不在终止中（在清理循环中使用ShouldPodContainersBeTerminating以避免无法清理已从配置中删除的Pod）
	return false
}
```

### ShouldPodContainersBeTerminating

```GO
func (p *podWorkers) ShouldPodContainersBeTerminating(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		// 我们等待Pod工作器goroutine观察到终止，这意味着syncPod将不会再次执行，也就是说不会启动新的容器。
		return status.IsTerminationStarted() // 返回Pod的状态是否为已开始终止
	}

	// 一旦同步完成，如果Pod对工作器未知，则应该进行清除。
	return p.podsSynced
}
```

### ShouldPodRuntimeBeRemoved

```GO
func (p *podWorkers) ShouldPodRuntimeBeRemoved(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsTerminated() // 返回Pod的状态是否为已终止
	}

	// 一旦我们同步了所有内容，尚未发送给Pod工作器的Pod不应具有运行时组件。
	return p.podsSynced
}
```

### ShouldPodContentBeRemoved

```GO
func (p *podWorkers) ShouldPodContentBeRemoved(uid types.UID) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsEvicted() || (status.IsDeleted() && status.IsTerminated()) // 返回Pod的状态是否被驱逐或已删除且已终止
	}

	// 一旦我们同步了所有内容，尚未发送给Pod工作器的Pod不应在磁盘上具有任何内容。
	return p.podsSynced
}
```

### IsPodForMirrorPodTerminatingByFullName

```GO
func (p *podWorkers) IsPodForMirrorPodTerminatingByFullName(podFullName string) bool {
	p.podLock.Lock() // 对podLock进行加锁
	defer p.podLock.Unlock() // 在函数返回前解锁

	uid, started := p.startedStaticPodsByFullname[podFullName]
	if !started {
		return false
	}

	status, exists := p.podSyncStatuses[uid]
	if !exists {
		return false
	}

	if !status.IsTerminationRequested() || status.IsTerminated() {
		return false
	}

	return true
}
```

