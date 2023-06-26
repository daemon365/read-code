---
id: 3-kube-apiserver-code 
title: kube-apiserver Handlerchain 代码走读
description: kube-apiserver Handlerchain 代码走读
keywords:
  - kubernetes
  - kube-apiserver
slug: /
---

## Handlerchain做什么的？

在请求处理过程中，存在一种类似于中间件的机制，它在主逻辑之前执行。这种机制可以被看作是在请求处理中的一个环节。

因为`handler.ServeHTTP`都是在最后执行的（除非遇到特殊情况）。所以每个handlerFunc执行顺序是返回来的。

```GO
package main

import (
	"fmt"
	"net/http"
)

func main() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	}
	handler = func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "middleware1")
			handler.ServeHTTP(w, r)
		}
	}(handler)
	handler = func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "middleware2")
			handler.ServeHTTP(w, r)
		}
	}(handler)
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}

/*
curl http://127.0.0.1:8080/
middleware2
middleware1
hello
*/
```

## DefaultBuildHandlerChain

```GO
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	// 通过 filterlatency 包中的 TrackCompleted 函数对 apiHandler 进行追踪
	handler := filterlatency.TrackCompleted(apiHandler)

	// 使用 genericapifilters 包中的 WithAuthorization 函数添加授权过滤器
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "authorization"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authorization")

	// 如果存在流量控制
	if c.FlowControl != nil {
		// 创建默认的流量估算器配置
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()

		// 创建流量估算器，并使用 c.StorageObjectCountTracker.Get 和 c.FlowControl.GetInterestedWatchCount 函数作为参数
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg)

		// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
		handler = filterlatency.TrackCompleted(handler)

		// 使用 genericfilters 包中的 WithPriorityAndFairness 函数添加优先级和公平性过滤器
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator)

		// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "priorityandfairness"
		handler = filterlatency.TrackStarted(handler, c.TracerProvider, "priorityandfairness")
	} else {
		// 使用 genericfilters 包中的 WithMaxInFlightLimit 函数添加最大并发限制过滤器
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
	handler = filterlatency.TrackCompleted(handler)

	// 使用 genericapifilters 包中的 WithImpersonation 函数添加模拟身份过滤器
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "impersonation"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "impersonation")

	// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
	handler = filterlatency.TrackCompleted(handler)

	// 使用 genericapifilters 包中的 WithAudit 函数添加审计过滤器
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "audit"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

	// 创建失败处理器，并使用 genericapifilters 包中的 Unauthorized 函数初始化
	failedHandler := genericapifilters.Unauthorized(c.Serializer)

	// 使用 genericapifilters 包中的 WithFailedAuthenticationAudit 函数添加失败身份验证审计过滤器
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)

	// 使用 filterlatency 包中的 TrackCompleted 函数对 failedHandler 进行追踪
	failedHandler = filterlatency.TrackCompleted(failedHandler)

	// 使用 filterlatency 包中的 TrackCompleted 函数对 handler 进行追踪
	handler = filterlatency.TrackCompleted(handler)

	// 使用 genericapifilters 包中的 WithAuthentication 函数添加身份验证过滤器
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences, c.Authentication.RequestHeaderConfig)

	// 使用 filterlatency 包中的 TrackStarted 函数对 handler 进行追踪，并设置名称为 "authentication"
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authentication")

	// 使用 genericfilters 包中的 WithCORS 函数添加跨域资源共享过滤器
	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")

	// 使用 genericfilters 包中的 WithTimeoutForNonLongRunningRequests 函数为非长时间运行的请求设置超时处理
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc)

	// 使用 genericapifilters 包中的 WithRequestDeadline 函数为请求设置截止时间
	handler = genericapifilters.WithRequestDeadline(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator,
		c.LongRunningFunc, c.Serializer, c.RequestTimeout)

	// 使用 genericfilters 包中的 WithWaitGroup 函数添加等待组过滤器
	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.NonLongRunningRequestWaitGroup)

	// 如果存在关闭观察终止优雅期
	if c.ShutdownWatchTerminationGracePeriod > 0 {
		// 使用 genericfilters 包中的 WithWatchTerminationDuringShutdown 函数添加关闭观察期间终止过滤器
		handler = genericfilters.WithWatchTerminationDuringShutdown(handler, c.lifecycleSignals, c.WatchRequestWaitGroup)
	}

	// 如果存在 SecureServing，并且不禁用 HTTP/2，并且 GoawayChance 大于 0
	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		// 使用 genericfilters 包中的 WithProbabilisticGoaway 函数添加概率性 Goaway 过滤器
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance)
	}

	// 使用 genericapifilters 包中的 WithWarningRecorder 函数添加警告记录过滤器
	handler = genericapifilters.WithWarningRecorder(handler)

	// 使用 genericapifilters 包中的 WithCacheControl 函数添加缓存控制过滤器
	handler = genericapifilters.WithCacheControl(handler)

	// 使用 genericfilters 包中的 WithHSTS 函数添加 HTTP 严格传输安全（HSTS）过滤器
	handler = genericfilters.WithHSTS(handler, c.HSTSDirectives)

	// 如果 ShutdownSendRetryAfter 为 true
	if c.ShutdownSendRetryAfter {
		// 使用 genericfilters 包中的 WithRetryAfter 函数添加重试后过滤器
		handler = genericfilters.WithRetryAfter(handler, c.lifecycleSignals.NotAcceptingNewRequest.Signaled())
	}

	// 使用 genericfilters 包中的 WithHTTPLogging 函数添加 HTTP 日志记录过滤器
	handler = genericfilters.WithHTTPLogging(handler)

	// 如果 genericfeatures 包中的 APIServerTracing 特性启用
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		// 使用 genericapifilters 包中的 WithTracing 函数添加追踪过滤器
		handler = genericapifilters.WithTracing(handler, c.TracerProvider)
	}

	// 使用 genericapifilters 包中的 WithLatencyTrackers 函数添加延迟追踪过滤器
	handler = genericapifilters.WithLatencyTrackers(handler)

	// 使用 genericapifilters 包中的 WithRequestInfo 函数添加请求信息过滤器
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)

	// 使用 genericapifilters 包中的 WithRequestReceivedTimestamp 函数添加请求接收时间戳过滤器
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)

	// 使用 genericapifilters 包中的 WithMuxAndDiscoveryComplete 函数添加多路复用和发现完成过滤器
	handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled())

	// 使用 genericfilters 包中的 WithPanicRecovery 函数添加恢复 panic 过滤器
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver)

	// 使用 genericapifilters 包中的 WithAuditInit 函数初始化审计过滤器
	handler = genericapifilters.WithAuditInit(handler)

	return handler
}
```

## TrackCompleted&TrackStarted

metrics

```GO
// TrackCompleted 测量给定处理程序执行完成的时间戳，然后使用过滤器延迟持续时间更新相应的指标。
func TrackCompleted(handler http.Handler) http.Handler {
	// 调用 trackCompleted 函数，传入处理程序、RealClock 实例和回调函数
	return trackCompleted(handler, clock.RealClock{}, func(ctx context.Context, fr *requestFilterRecord, completedAt time.Time) {
		// 计算延迟时间
		latency := completedAt.Sub(fr.startedTimestamp)
		// 使用 metrics 包中的 RecordFilterLatency 函数记录过滤器延迟
		metrics.RecordFilterLatency(ctx, fr.name, latency)
		// 如果启用了日志级别为 3 并且延迟超过最小过滤器日志延迟时间
		if klog.V(3).Enabled() && latency > minFilterLatencyToLog {
			// 使用 httplog 包中的 AddKeyValue 函数将延迟时间添加到日志上下文中
			httplog.AddKeyValue(ctx, fmt.Sprintf("fl_%s", fr.name), latency.String())
		}
	})
}

// RecordFilterLatency 记录过滤器延迟的函数
func RecordFilterLatency(ctx context.Context, name string, elapsed time.Duration) {
	// 使用 requestFilterDuration 计时器指标记录上下文和标签值的过滤器延迟观察值
	requestFilterDuration.WithContext(ctx).WithLabelValues(name).Observe(elapsed.Seconds())
}
```

```GO
// TrackStarted 测量给定处理程序开始执行的时间戳，通过将处理程序附加到处理链中。
func TrackStarted(handler http.Handler, tp trace.TracerProvider, name string) http.Handler {
	// 调用 trackStarted 函数，传入处理程序、追踪器提供程序、名称和 RealClock 实例
	return trackStarted(handler, tp, name, clock.RealClock{})
}

func trackStarted(handler http.Handler, tp trace.TracerProvider, name string, clock clock.PassiveClock) http.Handler {
	// 如果追踪功能被禁用，NoopTracerProvider 将用于 tp，此时该函数不会进行任何操作
	tracer := tp.Tracer("k8s.op/apiserver/pkg/endpoints/filterlatency")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// 从上下文中获取请求过滤器记录
		if fr := requestFilterRecordFrom(ctx); fr != nil {
			fr.name = name
			fr.startedTimestamp = clock.Now()

			// 调用处理程序处理请求
			handler.ServeHTTP(w, r)
			return
		}

		// 创建新的请求过滤器记录
		fr := &requestFilterRecord{
			name:             name,
			startedTimestamp: clock.Now(),
		}
		// 使用追踪器开始追踪，并更新上下文和请求对象
		ctx, _ = tracer.Start(ctx, name)
		r = r.WithContext(withRequestFilterRecord(ctx, fr))
		// 调用处理程序处理请求
		handler.ServeHTTP(w, r)
	})
}
```

### requestFilterRecord

```GO
// requestFilterRecord 是请求过滤器记录的结构体类型
type requestFilterRecord struct {
	name             string        // 过滤器名称
	startedTimestamp time.Time     // 过滤器开始时间戳
}
```

## WithAuthorization

用于验证账号授权

```GO
// WithAuthorization 将所有经过授权的请求传递给处理程序，否则返回禁止访问的错误。
func WithAuthorization(handler http.Handler, auth authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
	// 调用 withAuthorization 函数，传入处理程序、授权器、序列化器和记录授权指标的函数
	return withAuthorization(handler, auth, s, recordAuthorizationMetrics)
}

func withAuthorization(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer, metrics recordAuthorizationMetricsFunc) http.Handler {
	if a == nil {
		klog.Warning("Authorization is disabled")  // 授权功能被禁用的警告日志
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		authorizationStart := time.Now()  // 授权开始时间

		attributes, err := GetAuthorizerAttributes(ctx)  // 获取授权器属性
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		authorized, reason, err := a.Authorize(ctx, attributes)  // 授权判断

		authorizationFinish := time.Now()  // 授权结束时间
		defer func() {
			metrics(ctx, authorized, err, authorizationStart, authorizationFinish)  // 记录授权指标
		}()

		// 如果授权决策为允许
		if authorized == authorizer.DecisionAllow {
			audit.AddAuditAnnotations(ctx,
				decisionAnnotationKey, decisionAllow,
				reasonAnnotationKey, reason)
			handler.ServeHTTP(w, req)  // 调用处理程序处理请求
			return
		}
		// 如果发生错误
		if err != nil {
			audit.AddAuditAnnotation(ctx, reasonAnnotationKey, reasonError)
			responsewriters.InternalError(w, req, err)
			return
		}

		klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "reason", reason)  // 输出禁止访问的日志
		audit.AddAuditAnnotations(ctx,
			decisionAnnotationKey, decisionForbid,
			reasonAnnotationKey, reason)
		responsewriters.Forbidden(ctx, attributes, w, req, reason, s)  // 返回禁止访问的响应
	})
}

func GetAuthorizerAttributes(ctx context.Context) (authorizer.Attributes, error) {
	attribs := authorizer.AttributesRecord{}

	user, ok := request.UserFrom(ctx)
	if ok {
		attribs.User = user
	}

	requestInfo, found := request.RequestInfoFrom(ctx)
	if !found {
		return nil, errors.New("no RequestInfo found in the context")
	}

	// 开始设置适用于资源和非资源请求的通用属性
	attribs.ResourceRequest = requestInfo.IsResourceRequest
	attribs.Path = requestInfo.Path
	attribs.Verb = requestInfo.Verb

	attribs.APIGroup = requestInfo.APIGroup
	attribs.APIVersion = requestInfo.APIVersion
	attribs.Resource = requestInfo.Resource
	attribs.Subresource = requestInfo.Subresource
	attribs.Namespace = requestInfo.Namespace
	attribs.Name = requestInfo.Name

	return &attribs, nil
}

type Authorizer interface {
	Authorize(ctx context.Context, a Attributes) (authorized Decision, reason string, err error)
}
```

## WithPriorityAndFairness

用于处理请求的优先级和公平性。

```GO
// WithPriorityAndFairness函数用于实现在细粒度上限制并发请求的数量。
// 参数:
// - handler: http.Handler类型，表示原始的请求处理程序。
// - longRunningRequestCheck: apirequest.LongRunningRequestCheck类型，用于检查是否为长时间运行的请求。
// - fcIfc: utilflowcontrol.Interface类型，表示流量控制的接口。
// - workEstimator: flowcontrolrequest.WorkEstimatorFunc类型，表示工作量估算函数。
func WithPriorityAndFairness(
    handler http.Handler,
    longRunningRequestCheck apirequest.LongRunningRequestCheck,
    fcIfc utilflowcontrol.Interface,
    workEstimator flowcontrolrequest.WorkEstimatorFunc,
) http.Handler {
    // 如果流量控制接口为空，则记录警告日志并返回原始的请求处理程序。
    if fcIfc == nil {
        klog.Warningf("priority and fairness support not found, skipping")
        return handler
	}
    // 初始化一次最大并发请求数量。
    initAPFOnce.Do(func() {
        initMaxInFlight(0, 0)

        // 延迟获取这些度量标，直到它们的基础度量已注册，
        // 以便与高效的实现关联起来。
        waitingMark.readOnlyObserver = fcmetrics.GetWaitingReadonlyConcurrency()
        waitingMark.mutatingObserver = fcmetrics.GetWaitingMutatingConcurrency()
    })

    // 创建priorityAndFairnessHandler实例。
    priorityAndFairnessHandler := &priorityAndFairnessHandler{
        handler:                 handler,
        longRunningRequestCheck: longRunningRequestCheck,
        fcIfc:                   fcIfc,
        workEstimator:           workEstimator,
        droppedRequests:         utilflowcontrol.NewDroppedRequestsTracker(),
    }

    // 返回一个http.Handler类型的处理程序，该处理程序调用priorityAndFairnessHandler的Handle方法。
    return http.HandlerFunc(priorityAndFairnessHandler.Handle)
}
```

### initMaxInFlight

```GO
// initMaxInFlightOnce是用于保证initMaxInFlight函数只执行一次的同步标志。
var initMaxInFlightOnce sync.Once

// initMaxInFlight函数用于初始化最大并发请求数量。
func initMaxInFlight(nonMutatingLimit, mutatingLimit int) {
    // 保证initMaxInFlight函数只执行一次。
    initMaxInFlightOnce.Do(func() {
        // 延迟获取这些度量标，直到它们的基础度量已注册，
        // 以便与高效的实现关联起来。
        watermark.readOnlyObserver = fcmetrics.GetExecutingReadonlyConcurrency()
        watermark.mutatingObserver = fcmetrics.GetExecutingMutatingConcurrency()
        // 如果非变异限制非零，则设置只读请求的分母为nonMutatingLimit，并记录日志。
        if nonMutatingLimit != 0 {
            watermark.readOnlyObserver.SetDenominator(float64(nonMutatingLimit))
            klog.V(2).InfoS("Set denominator for readonly requests", "limit", nonMutatingLimit)
        }

        // 如果变异限制非零，则设置变异请求的分母为mutatingLimit，并记录日志。
        if mutatingLimit != 0 {
            watermark.mutatingObserver.SetDenominator(float64(mutatingLimit))
            klog.V(2).InfoS("Set denominator for mutating requests", "limit", mutatingLimit)
        }
    })
}
```

### requestWatermark

```GO
// requestWatermark用于跟踪特定处理阶段的最大请求数量。
type requestWatermark struct {	
	phase string
    readOnlyObserver, mutatingObserver fcmetrics.RatioedGauge
    lock sync.Mutex
    readOnlyWatermark, mutatingWatermark int
}

// recordMutating函数用于记录可变操作的水位标记。
func (w *requestWatermark) recordMutating(mutatingVal int) {
	w.mutatingObserver.Set(float64(mutatingVal)) // 设置可变操作的观察值

	w.lock.Lock()
	defer w.lock.Unlock()

	if w.mutatingWatermark < mutatingVal {
		w.mutatingWatermark = mutatingVal // 更新可变操作的水位标记
	}
}

// recordReadOnly函数用于记录只读操作的水位标记。
func (w *requestWatermark) recordReadOnly(readOnlyVal int) {
	w.readOnlyObserver.Set(float64(readOnlyVal)) // 设置只读操作的观察值

	w.lock.Lock()
	defer w.lock.Unlock()

	if w.readOnlyWatermark < readOnlyVal {
		w.readOnlyWatermark = readOnlyVal // 更新只读操作的水位标记
	}
}
```

### priorityAndFairnessHandler

```GO
// priorityAndFairnessHandler用于处理具有优先级和公平性的请求。
type priorityAndFairnessHandler struct {
    handler http.Handler
    longRunningRequestCheck apirequest.LongRunningRequestCheck
    fcIfc utilflowcontrol.Interface
    workEstimator flowcontrolrequest.WorkEstimatorFunc

    // droppedRequests用于跟踪已丢弃请求的历史记录，以便计算RetryAfter标头以避免系统过载。
    droppedRequests utilflowcontrol.DroppedRequestsTracker
}

func (h *priorityAndFairnessHandler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestInfo, ok := apirequest.RequestInfoFrom(ctx)
	if !ok {
		handleError(w, r, fmt.Errorf("no RequestInfo found in context"))
		return
	}
	user, ok := apirequest.UserFrom(ctx)
	if !ok {
		handleError(w, r, fmt.Errorf("no User found in context"))
		return
	}

	isWatchRequest := watchVerbs.Has(requestInfo.Verb)

	// 如果是长时间运行的非watch请求，则跳过跟踪。
	if h.longRunningRequestCheck != nil && h.longRunningRequestCheck(r, requestInfo) && !isWatchRequest {
		klog.V(6).Infof("Serving RequestInfo=%#+v, user.Info=%#+v as longrunning\n", requestInfo, user)
		h.handler.ServeHTTP(w, r)
		return
	}

	var classification *PriorityAndFairnessClassification
	noteFn := func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, flowDistinguisher string) {
        // 记录请求的优先级和公平性分类信息。
		classification = &PriorityAndFairnessClassification{
			FlowSchemaName:    fs.Name,
			FlowSchemaUID:     fs.UID,
			PriorityLevelName: pl.Name,
			PriorityLevelUID:  pl.UID,
		}
		// 将分类信息记录到日志中。
		httplog.AddKeyValue(ctx, "apf_pl", truncateLogField(pl.Name))
		httplog.AddKeyValue(ctx, "apf_fs", truncateLogField(fs.Name))
	}
	// estimateWork函数用于估算请求的工作量。
	estimateWork := func() flowcontrolrequest.WorkEstimate {
		if classification == nil {
			// 在请求的分类完成之前调用了workEstimator，这通常不应该发生。
			klog.ErrorS(fmt.Errorf("workEstimator is being invoked before classification of the request has completed"),
				"Using empty FlowSchema and PriorityLevelConfiguration name", "verb", r.Method, "URI", r.RequestURI)
			return h.workEstimator(r, "", "")
		}
		// 调用工作量估算函数来获取工作量估算结果。
		workEstimate := h.workEstimator(r, classification.FlowSchemaName, classification.PriorityLevelName)
		// 观察工作量估算结果的座位数。
		fcmetrics.ObserveWorkEstimatedSeats(classification.PriorityLevelName, classification.FlowSchemaName, workEstimate.MaxSeats())
        // 将工作量估算结果的相关信息记录到日志中。
		httplog.AddKeyValue(ctx, "apf_iseats", workEstimate.InitialSeats)
		httplog.AddKeyValue(ctx, "apf_fseats", workEstimate.FinalSeats)
		httplog.AddKeyValue(ctx, "apf_additionalLatency", workEstimate.AdditionalLatency)

		return workEstimate
	}

	var served bool
	isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb)
    // noteExecutingDelta函数用于记录正在执行的请求数量的增量。
	noteExecutingDelta := func(delta int32) {
		if isMutatingRequest {
			watermark.recordMutating(int(atomic.AddInt32(&atomicMutatingExecuting, delta)))
		} else {
			watermark.recordReadOnly(int(atomic.AddInt32(&atomicReadOnlyExecuting, delta)))
		}
	}
    // noteWaitingDelta函数用于记录正在等待的请求数量的增量。
	noteWaitingDelta := func(delta int32) {
		if isMutatingRequest {
			waitingMark.recordMutating(int(atomic.AddInt32(&atomicMutatingWaiting, delta)))
		} else {
			waitingMark.recordReadOnly(int(atomic.AddInt32(&atomicReadOnlyWaiting, delta)))
		}
	}
    // queueNote函数根据是否在队列中将请求数量进行增减。
	queueNote := func(inQueue bool) {
		if inQueue {
			noteWaitingDelta(1)
		} else {
			noteWaitingDelta(-1)
		}
	}
	// 创建请求摘要对象，用于记录请求的相关信息。
	digest := utilflowcontrol.RequestDigest{
		RequestInfo: requestInfo,
		User:        user,
	}

	if isWatchRequest {
		// 创建一个用于阻塞调用handler.ServeHTTP()的通道，直到通道关闭，该通道在execute()函数中关闭。
		// 如果APF拒绝请求，则通道永远不会关闭。
		shouldStartWatchCh := make(chan struct{})

		watchInitializationSignal := newInitializationSignal()
		
		var watchReq *http.Request
		// 在执行execute()函数之前，将请求包装起来，并设置包含watchInitializationSignal的上下文，
		// 以便将其传递给存储层。
		var forgetWatch utilflowcontrol.ForgetWatchFunc
		// 在defer中确保执行一些清理操作，包括发送初始化信号和忘记watcher。
		defer func() {
			// 防止请求无法达到存储层并且初始化信号不会发送。
			if watchInitializationSignal != nil {
				watchInitializationSignal.Signal()
			}
			// 如果已注册watcher，则忘记它。
			// 这是无竞争的，因为此时已经发生以下情况之一：
			// case <-shouldStartWatchCh: execute()完成了对forgetWatch的赋值
			// case <-resultCh: Handle()完成，而Handle()在execute()运行时不返回
			if forgetWatch != nil {
				forgetWatch()
			}
		}()
		
        // execute函数用于执行watch请求。
		execute := func() {
			startedAt := time.Now()
			defer func() {
				httplog.AddKeyValue(ctx, "apf_init_latency", time.Since(startedAt))
			}()
            // 增加正在执行的请求数量。
			noteExecutingDelta(1)
			defer noteExecutingDelta(-1)
			served = true
			setResponseHeaders(classification, w)
			// 在注册watcher之前执行h.fcIfc.RegisterWatch(r)函数，并将forgetWatch赋值为返回的函数。
			forgetWatch = h.fcIfc.RegisterWatch(r)

			// 通知主线程已准备好启动watch。
			close(shouldStartWatchCh)

			// 等待请求从APF的角度完成（即初始化完成）。
			watchInitializationSignal.Wait()
		}

		// 确保可以异步将结果放入resultCh通道。
		resultCh := make(chan interface{}, 1)

		// 在单独的goroutine中调用Handle函数。
		// 之所以这样做是因为从APF的角度来看，请求处理完成的条件是watch初始化完成
		// （通常比watch请求本身快得多）。这意味着Handle()调用会更快地完成，
		// 出于性能的考虑，我们希望减少运行的goroutine数量-因此我们将较短的操作放在专用的goroutine中，
		// 将实际的watch处理程序放在主goroutine中。
		go func() {
			defer func() {
				err := recover()
				// 不包装sentinel ErrAbortHandler panic。
				if err != nil && err != http.ErrAbortHandler {
					// 与标准库http服务器代码相同。手动分配堆栈跟踪缓冲区大小以防止日志过大。
					const size = 64 << 10
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]
					err = fmt.Sprintf("%v\n%s", err, buf)
				}

				// Ensure that the result is put into resultCh independently of the panic.
				resultCh <- err
			}()

			// 使用显式的取消函数创建handleCtx。
			// 原因是Handle()在底层可能会启动额外的goroutine，
			// 该goroutine在上下文取消时被阻塞。然而，从APF的角度来看，
			// 我们不希望等待整个watch请求处理完成（也就是上下文实际上被取消）-我们希望在请求从APF的角度处理完成时解除阻塞goroutine。
			//
			// 请注意，我们明确地不使用该上下文调用实际的处理程序，
			// 以避免过早地取消请求。
			handleCtx, handleCtxCancel := context.WithCancel(ctx)
			defer handleCtxCancel()

			// 注意，Handle函数将返回，无论请求执行还是被拒绝。
			// 如果被拒绝，该函数将在不调用传递的execute函数的情况下返回。
			h.fcIfc.Handle(handleCtx, digest, noteFn, estimateWork, queueNote, execute)
		}()

		select {
		case <-shouldStartWatchCh:
            // 使用带有watchInitializationSignal的上下文创建watchCtx。
			watchCtx := utilflowcontrol.WithInitializationSignal(ctx, watchInitializationSignal)
			watchReq = r.WithContext(watchCtx)
            // 调用handler.ServeHTTP()处理watch请求。
			h.handler.ServeHTTP(w, watchReq)
			// 在等待resultCh通道时，保护免受请求处理引发的恐慌的情况。
			// 在此之前，必须确保请求不会到达存储层并且初始化信号不会发送。
			watchInitializationSignal.Signal()
			// TODO: 还有其他的清理工作需要完成吗？例如，调用忘记watcher等。
			if err := <-resultCh; err != nil {
				panic(err)
			}
		case err := <-resultCh:
			if err != nil {
				panic(err)
			}
		}
	} else {
        // execute函数用于执行非watch请求。
		execute := func() {
            // 增加正在执行的请求数量。
			noteExecutingDelta(1)
			defer noteExecutingDelta(-1)
			served = true
			setResponseHeaders(classification, w)
			// 执行实际的请求处理程序。
			h.handler.ServeHTTP(w, r)
		}
		// 使用前面定义的参数调用Handle函数。
		h.fcIfc.Handle(ctx, digest, noteFn, estimateWork, queueNote, execute)
	}
	if !served {
	// 如果请求未被服务，则执行以下操作：
        setResponseHeaders(classification, w) // 设置响应头
        epmetrics.RecordDroppedRequest(r, requestInfo, epmetrics.APIServerComponent, isMutatingRequest) // 记录已丢弃的请求
        epmetrics.RecordRequestTermination(r, requestInfo, epmetrics.APIServerComponent, http.StatusTooManyRequests) // 记录请求终止
        h.droppedRequests.RecordDroppedRequest(classification.PriorityLevelName) // 记录已丢弃的请求
        // TODO（wojtek-t）：来自deads2k的想法：我们可以考虑进行一些抖动，在非整数的情况下，只返回截断后的结果，并在服务器端休眠剩余部分。
        tooManyRequests(r, w, strconv.Itoa(int(h.droppedRequests.GetRetryAfter(classification.PriorityLevelName)))) // 返回“请求过多”的响应
    }
}
```

## WithMaxInFlightLimit

用于限制了正在处理的请求的数量

```GO
// WithMaxInFlightLimit函数限制了正在处理的请求的数量，限制为传入通道的缓冲区大小。
func WithMaxInFlightLimit(
	handler http.Handler, // 处理程序
	nonMutatingLimit int, // 非变异请求的限制
	mutatingLimit int, // 变异请求的限制
	longRunningRequestCheck apirequest.LongRunningRequestCheck, // 检查长时间运行的请求
) http.Handler {
	if nonMutatingLimit == 0 && mutatingLimit == 0 {
		return handler
	}
	var nonMutatingChan chan bool
	var mutatingChan chan bool
	if nonMutatingLimit != 0 {
		nonMutatingChan = make(chan bool, nonMutatingLimit) // 创建非变异请求的通道
		klog.V(2).InfoS("Initialized nonMutatingChan", "len", nonMutatingLimit) // 输出日志：初始化非变异请求通道，长度为nonMutatingLimit
	} else {
		klog.V(2).InfoS("Running with nil nonMutatingChan") // 输出日志：运行时使用空的非变异请求通道
	}
	if mutatingLimit != 0 {
		mutatingChan = make(chan bool, mutatingLimit) // 创建变异请求的通道
		klog.V(2).InfoS("Initialized mutatingChan", "len", mutatingLimit) // 输出日志：初始化变异请求通道，长度为mutatingLimit
	} else {
		klog.V(2).InfoS("Running with nil mutatingChan") // 输出日志：运行时使用空的变异请求通道
	}
	initMaxInFlight(nonMutatingLimit, mutatingLimit) // 初始化最大并发请求数

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		if !ok {
			handleError(w, r, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong")) // 处理错误：在上下文中未找到RequestInfo
			return
		}

		// 跳过跟踪长时间运行的事件。
		if longRunningRequestCheck != nil && longRunningRequestCheck(r, requestInfo) {
			handler.ServeHTTP(w, r) // 处理长时间运行的请求
			return
		}

		var c chan bool
		isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb) // 判断请求是否为变异请求
		if isMutatingRequest {
			c = mutatingChan
		} else {
			c = nonMutatingChan
		}

		if c == nil {
			handler.ServeHTTP(w, r) // 处理请求
		} else {
			select {
			case c <- true:
				// 我们记录请求在服务期间和完成后的并发级别，因为两种状态都对并发采样统计数据有贡献。
				if isMutatingRequest {
					watermark.recordMutating(len(c)) // 记录变异操作的水位标记
				} else {
					watermark.recordReadOnly(len(c)) // 记录只读操作的水位标记
				}
				defer func() {
					<-c
					if isMutatingRequest {
						watermark.recordMutating(len(c)) // 记录变异操作的水位标记
					} else {
						watermark.recordReadOnly(len(c)) // 记录只读操作的水位标记
					}
				}()
				handler.ServeHTTP(w, r) // 处理请求

			default:
				// 此时我们即将返回429，但并非所有角色都应受到速率限制。系统：master非常强大，他们应始终获得答案。这是超级管理员或环回连接。
				if currUser, ok := apirequest.UserFrom(ctx); ok {
					for _, group := range currUser.GetGroups() {
						if group == user.SystemPrivilegedGroup {
							handler.ServeHTTP(w, r) // 处理请求
							return
						}
					}
				}
				// 我们需要将此数据在用于限流的桶之间分割。
				metrics.RecordDroppedRequest(r, requestInfo, metrics.APIServerComponent, isMutatingRequest) // 记录已丢弃的请求
				metrics.RecordRequestTermination(r, requestInfo, metrics.APIServerComponent, http.StatusTooManyRequests) // 记录请求终止
				tooManyRequests(r, w, retryAfter) // 处理请求过多的情况
			}
		}
	})
}

// tooManyRequests函数返回状态码为429（“Too Many Requests”）的响应。
func tooManyRequests(req *http.Request, w http.ResponseWriter, retryAfter string) {
	// 设置响应头，指示重试时间
	w.Header().Set("Retry-After", retryAfter)
	http.Error(w, "Too many requests, please try again later.", http.StatusTooManyRequests) // 返回状态码为429的响应
}
```

## WithImpersonation

用于实现请求的模拟操作

```GO
// WithImpersonation 是一个过滤器，用于检查并验证请求是否尝试更改其请求的 user.Info。
func WithImpersonation(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        // 构建要模拟的请求列表
        impersonationRequests, err := buildImpersonationRequests(req.Header)
        if err != nil {
            klog.V(4).Infof("%v", err)
            responsewriters.InternalError(w, req, err)
            return
        }
        // 如果没有模拟请求，则直接调用原始处理程序
        if len(impersonationRequests) == 0 {
            handler.ServeHTTP(w, req)
            return
    	}
       	ctx := req.Context()
        // 获取当前请求的用户信息
        requestor, exists := request.UserFrom(ctx)
        if !exists {
            responsewriters.InternalError(w, req, errors.New("no user found for request"))
            return
        }

        // 如果未指定 groups，则根据用户类型以不同方式查找它们
        // 如果已指定 groups，则它们是授权的权限（包括 system:authenticated/system:unauthenticated groups）
        groupsSpecified := len(req.Header[authenticationv1.ImpersonateGroupHeader]) > 0

        // 确保我们被允许模拟每个请求的对象。在迭代过程中构建用户名和组信息
        username := ""
        groups := []string{}
        userExtra := map[string][]string{}
        uid := ""
        for _, impersonationRequest := range impersonationRequests {
            // 获取模拟请求的 GroupVersionKind
            gvk := impersonationRequest.GetObjectKind().GroupVersionKind()
            actingAsAttributes := &authorizer.AttributesRecord{
                User:            requestor,
                Verb:            "impersonate",
                APIGroup:        gvk.Group,
                APIVersion:      gvk.Version,
                Namespace:       impersonationRequest.Namespace,
                Name:            impersonationRequest.Name,
                ResourceRequest: true,
            }

            switch gvk.GroupKind() {
            case v1.SchemeGroupVersion.WithKind("ServiceAccount").GroupKind():
                actingAsAttributes.Resource = "serviceaccounts"
                // 构建 ServiceAccount 的用户名
                username = serviceaccount.MakeUsername(impersonationRequest.Namespace, impersonationRequest.Name)
                if !groupsSpecified {
                    // 如果未指定 ServiceAccount 的 groups，则根据命名空间添加它们
                    groups = serviceaccount.MakeGroupNames(impersonationRequest.Namespace)
                }

            case v1.SchemeGroupVersion.WithKind("User").GroupKind():
                actingAsAttributes.Resource = "users"
                username = impersonationRequest.Name

            case v1.SchemeGroupVersion.WithKind("Group").GroupKind():
                actingAsAttributes.Resource = "groups"
                groups = append(groups, impersonationRequest.Name)

            case authenticationv1.SchemeGroupVersion.WithKind("UserExtra").GroupKind():
                extraKey := impersonationRequest.FieldPath
                extraValue := impersonationRequest.Name
                actingAsAttributes.Resource = "userextras"
                actingAsAttributes.Subresource = extraKey
                userExtra[extraKey] = append(userExtra[extraKey], extraValue)

            case authenticationv1.SchemeGroupVersion.WithKind("UID").GroupKind():
                uid = string(impersonationRequest.Name)
                actingAsAttributes.Resource = "uids"

            default:
                klog.V(4).InfoS("unknown impersonation request type", "request", impersonationRequest)
                responsewriters.Forbidden(ctx, actingAsAttributes, w, req, fmt.Sprintf("unknown impersonation request type: %v", impersonationRequest), s)
                return
            }

            // 验证模拟请求是否被授权
            decision, reason, err := a.Authorize(ctx, actingAsAttributes)
            if err != nil || decision != authorizer.DecisionAllow {
                klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "reason", reason, "err", err)
                responsewriters.Forbidden(ctx, actingAsAttributes, w, req, reason, s)
                return
            }
        }

        // 当模拟的用户不是匿名用户时，在模拟的用户信息中包含 'system:authenticated' 组
        // 条件：
        // - 如果未指定任何组
        // - 如果指定的组不是 'system:authenticated'
        if username != user.Anonymous {
            addAuthenticated := true
            for _, group := range groups {
                if group == user.AllAuthenticated || group == user.AllUnauthenticated {
                    addAuthenticated = false
                    break
                }
            }

            if addAuthenticated {
                groups = append(groups, user.AllAuthenticated)
            }
        } else {
            // 当模拟的用户是匿名用户时，在模拟的用户信息中包含 'system:unauthenticated' 组
            addUnauthenticated := true
            for _, group := range groups {
                if group == user.AllUnauthenticated {
                    addUnauthenticated = false
                    break
                }
            }

            if addUnauthenticated {
                groups = append(groups, user.AllUnauthenticated)
            }
        }

        // 创建新的 user.Info 对象，包含模拟的用户名、组、额外信息和 UID
        newUser := &user.DefaultInfo{
            Name:   username,
            Groups: groups,
            Extra:  userExtra,
            UID:    uid,
        }
        // 将新的 user.Info 对象添加到请求的上下文中
        req = req.WithContext(request.WithUser(ctx, newUser))

        // 记录日志
        oldUser, _ := request.UserFrom(ctx)
        httplog.LogOf(req, w).Addf("%v is acting as %v", oldUser, newUser)

        ae := audit.AuditEventFrom(ctx)
        audit.LogImpersonatedUser(ae, newUser)

        // 清除请求中的所有模拟请求的标头
        req.Header.Del(authenticationv1.ImpersonateUserHeader)
        req.Header.Del(authenticationv1.ImpersonateGroupHeader)
        req.Header.Del(authenticationv1.ImpersonateUIDHeader)
        for headerName := range req.Header {
            if strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
                req.Header.Del(headerName)
            }
        }

        // 调用原始处理程序
        handler.ServeHTTP(w, req)
    })
}

// unescapeExtraKey 函数用于解码编码的键。
func unescapeExtraKey(encodedKey string) string {
	// 使用 url.PathUnescape 函数对 %-encoded 的字节进行解码。
	key, err := url.PathUnescape(encodedKey)
	if err != nil {
		return encodedKey // 即使是格式错误或未编码的字符串，也始终记录额外的字符串。
	}
	return key
}

// buildImpersonationRequests 函数返回一个表示我们请求模拟的不同事物的对象引用列表。
// 还包括一个表示 user.Info.Extra 的 map[string][]string。
// 在切换上下文之前，必须对每个请求进行当前用户的授权。
func buildImpersonationRequests(headers http.Header) ([]v1.ObjectReference, error) {
	impersonationRequests := []v1.ObjectReference{} // 创建一个空的 v1.ObjectReference 列表。

	requestedUser := headers.Get(authenticationv1.ImpersonateUserHeader) // 获取请求头中的用户。
	hasUser := len(requestedUser) > 0 // 检查是否存在用户。

	if hasUser {
		if namespace, name, err := serviceaccount.SplitUsername(requestedUser); err == nil {
			// 如果 requestedUser 是以 namespace/name 的格式，将其分割并创建一个 ServiceAccount 对象引用，然后将其添加到 impersonationRequests 列表中。
			impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "ServiceAccount", Namespace: namespace, Name: name})
		} else {
			// 否则，将 requestedUser 作为用户名创建一个 User 对象引用，然后将其添加到 impersonationRequests 列表中。
			impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "User", Name: requestedUser})
		}
	}

	hasGroups := false // 用于标记是否存在组。
	for _, group := range headers[authenticationv1.ImpersonateGroupHeader] {
		hasGroups = true // 存在组，将 hasGroups 标记为 true。
		// 创建一个 Group 对象引用，然后将其添加到 impersonationRequests 列表中。
		impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "Group", Name: group})
	}

	hasUserExtra := false // 用于标记是否存在额外的用户信息。
	for headerName, values := range headers {
		if !strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
			continue // 如果不是以指定前缀开头的请求头，跳过。
		}

		hasUserExtra = true // 存在额外的用户信息，将 hasUserExtra 标记为 true。
		extraKey := unescapeExtraKey(strings.ToLower(headerName[len(authenticationv1.ImpersonateUserExtraHeaderPrefix):]))
		// 解析额外的键并进行小写处理。

		// 为每个额外的值创建单独的请求。
		for _, value := range values {
			// 创建一个 UserExtra 对象引用，并将其添加到 impersonationRequests 列表中。
			impersonationRequests = append(impersonationRequests,
				v1.ObjectReference{
					Kind: "UserExtra",
					// 上面我们只解析了一个组，但如果没有某个版本，解析将失败，因此使用内部版本将有助于我们在有人开始使用它时失败。
					APIVersion: authenticationv1.SchemeGroupVersion.String(),
					Name:       value,
					// ObjectReference 没有 subresource 字段，FieldPath 是一个可用的字段，因此我们将使用它。
					// TODO 为 ObjectReference 引用资源和子资源进行改进。
					FieldPath: extraKey,
				})
		}
	}

	requestedUID := headers.Get(authenticationv1.ImpersonateUIDHeader) // 获取请求头中的 UID。
	hasUID := len(requestedUID) > 0 // 检查是否存在 UID。

	if hasUID {
		// 创建一个 UID 对象引用，并将其添加到 impersonationRequests 列表中。
		impersonationRequests = append(impersonationRequests, v1.ObjectReference{
			Kind:       "UID",
			Name:       requestedUID,
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
		})
	}

	if (hasGroups || hasUserExtra || hasUID) && !hasUser {
		// 如果存在组、额外的用户信息或 UID，但没有用户，则返回错误。
		return nil, fmt.Errorf("requested %v without impersonating a user", impersonationRequests)
	}

	return impersonationRequests, nil // 返回构建的 impersonationRequests 列表。
}  
```

## WithAudit

用于为所有请求到达服务器的 http.Handler 添加审计日志信息

```GO
// WithAudit 函数用于为所有请求到达服务器的 http.Handler 添加审计日志信息。
// 审计级别根据请求的属性和审计策略决定。日志会被发送到审计接收器以处理事件。
// 如果接收器或审计策略为 nil，则不进行装饰。
func WithAudit(handler http.Handler, sink audit.Sink, policy audit.PolicyRuleEvaluator, longRunningCheck request.LongRunningRequestCheck) http.Handler {
	if sink == nil || policy == nil {
		return handler // 如果接收器或审计策略为 nil，则直接返回原始 handler。
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ac, err := evaluatePolicyAndCreateAuditEvent(req, policy)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create audit event: %v", err))
			responsewriters.InternalError(w, req, errors.New("failed to create audit event"))
			return
		}

		if ac == nil || ac.Event == nil {
			handler.ServeHTTP(w, req) // 如果 ac 或 ac.Event 为 nil，则直接调用原始 handler。
			return
		}
		ev := ac.Event

		ctx := req.Context()
		omitStages := ac.RequestAuditConfig.OmitStages

		ev.Stage = auditinternal.StageRequestReceived
		if processed := processAuditEvent(ctx, sink, ev, omitStages); !processed {
			audit.ApiserverAuditDroppedCounter.WithContext(ctx).Inc()
			responsewriters.InternalError(w, req, errors.New("failed to store audit event"))
			return
		}

		// 拦截状态码
		var longRunningSink audit.Sink
		if longRunningCheck != nil {
			ri, _ := request.RequestInfoFrom(ctx)
			if longRunningCheck(req, ri) {
				longRunningSink = sink
			}
		}
		respWriter := decorateResponseWriter(ctx, w, ev, longRunningSink, omitStages)

		// 在离开该函数时发送审计事件，无论是通过 panic 还是正常完成。
		// 对于长时间运行的请求，这将是第二个审计事件。
		defer func() {
			if r := recover(); r != nil {
				defer panic(r)
				ev.Stage = auditinternal.StagePanic
				ev.ResponseStatus = &metav1.Status{
					Code:    http.StatusInternalServerError,
					Status:  metav1.StatusFailure,
					Reason:  metav1.StatusReasonInternalError,
					Message: fmt.Sprintf("APIServer panic'd: %v", r),
				}
				processAuditEvent(ctx, sink, ev, omitStages)
				return
			}

			// 如果没有发送 StageResponseStarted 事件，因为没有发送状态码或响应主体，则在这里进行伪装。
			// 但是只有在调用 http.ResponseWriter.WriteHeader 时才会发送 Audit-Id HTTP 头。
			fakedSuccessStatus := &metav1.Status{
				Code:    http.StatusOK,
				Status:  metav1.StatusSuccess,
				Message: "Connection closed early",
			}
			if ev.ResponseStatus == nil && longRunningSink != nil {
				ev.ResponseStatus = fakedSuccessStatus
				ev.Stage = auditinternal.StageResponseStarted
				processAuditEvent(ctx, longRunningSink, ev, omitStages)
			}

			ev.Stage = auditinternal.StageResponseComplete
			if ev.ResponseStatus == nil {
				ev.ResponseStatus = fakedSuccessStatus
			}
			processAuditEvent(ctx, sink, ev, omitStages)
		}()
		handler.ServeHTTP(respWriter, req) // 调用原始 handler，并将装饰后的 respWriter 作为参数传递。
	})
}

// Sink 接口定义了处理事件的方法。
type Sink interface {
	// ProcessEvents 处理事件。对于每个审计 ID，可能会调用 ProcessEvents 多达三次。
	// 错误可能由接收器自身记录。如果错误是致命的，导致内部错误，则 ProcessEvents 应该 panic。
	// 事件不能被更改，调用返回后由调用者重用，因此接收器必须进行深拷贝以保留副本（如果需要）。
	// 成功时返回 true，可能在出错时返回 false。
	ProcessEvents(events ...*auditinternal.Event) bool
}

// PolicyRuleEvaluator 接口公开了评估策略规则的方法。
type PolicyRuleEvaluator interface {
	// EvaluatePolicyRule 评估 apiserver 的审计策略与给定的授权属性相匹配的审计配置，并返回适用于给定请求的审计配置。
	EvaluatePolicyRule(authorizer.Attributes) RequestAuditConfig
}
```

### evaluatePolicyAndCreateAuditEvent

```GO
// evaluatePolicyAndCreateAuditEvent 负责评估适用于请求的审计策略配置，并创建一个新的审计事件，将其写入 API 审计日志。
// - 如果发生任何错误，则返回错误。
func evaluatePolicyAndCreateAuditEvent(req *http.Request, policy audit.PolicyRuleEvaluator) (*audit.AuditContext, error) {
	ctx := req.Context()
	ac := audit.AuditContextFrom(ctx)
	if ac == nil {
		// 审计未启用。
		return nil, nil
	}

	attribs, err := GetAuthorizerAttributes(ctx)
	if err != nil {
		return ac, fmt.Errorf("failed to GetAuthorizerAttributes: %v", err)
	}

	rac := policy.EvaluatePolicyRule(attribs)
	audit.ObservePolicyLevel(ctx, rac.Level)
	ac.RequestAuditConfig = rac
	if rac.Level == auditinternal.LevelNone {
		// 不进行审计。
		return ac, nil
	}

	requestReceivedTimestamp, ok := request.ReceivedTimestampFrom(ctx)
	if !ok {
		requestReceivedTimestamp = time.Now()
	}
	ev, err := audit.NewEventFromRequest(req, requestReceivedTimestamp, rac.Level, attribs)
	if err != nil {
		return nil, fmt.Errorf("failed to complete audit event from request: %v", err)
	}

	ac.Event = ev

	return ac, nil
}
```

#### NewEventFromRequest

```GO
// NewEventFromRequest 从请求中创建一个新的审计事件，并设置相关字段。
func NewEventFromRequest(req *http.Request, requestReceivedTimestamp time.Time, level auditinternal.Level, attribs authorizer.Attributes) (*auditinternal.Event, error) {
	ev := &auditinternal.Event{
		RequestReceivedTimestamp: metav1.NewMicroTime(requestReceivedTimestamp),
		Verb:                     attribs.GetVerb(),
		RequestURI:               req.URL.RequestURI(),
		UserAgent:                maybeTruncateUserAgent(req),
		Level:                    level,
	}

	auditID, found := AuditIDFrom(req.Context())
	if !found {
		auditID = types.UID(uuid.New().String())
	}
	ev.AuditID = auditID

	ips := utilnet.SourceIPs(req)
	ev.SourceIPs = make([]string, len(ips))
	for i := range ips {
		ev.SourceIPs[i] = ips[i].String()
	}

	if user := attribs.GetUser(); user != nil {
		ev.User.Username = user.GetName()
		ev.User.Extra = map[string]authnv1.ExtraValue{}
		for k, v := range user.GetExtra() {
			ev.User.Extra[k] = authnv1.ExtraValue(v)
		}
		ev.User.Groups = user.GetGroups()
		ev.User.UID = user.GetUID()
	}

	if attribs.IsResourceRequest() {
		ev.ObjectRef = &auditinternal.ObjectReference{
			Namespace:   attribs.GetNamespace(),
			Name:        attribs.GetName(),
			Resource:    attribs.GetResource(),
			Subresource: attribs.GetSubresource(),
			APIGroup:    attribs.GetAPIGroup(),
			APIVersion:  attribs.GetAPIVersion(),
		}
	}

	addAuditAnnotationsFrom(req.Context(), ev)

	return ev, nil
}
```

### auditResponseWriter

```GO
var _ http.ResponseWriter = &auditResponseWriter{}
var _ responsewriter.UserProvidedDecorator = &auditResponseWriter{}

// auditResponseWriter拦截WriteHeader，并在事件中设置响应状态码。如果设置了sink，则立即创建事件（适用于长时间运行的请求）。
type auditResponseWriter struct {
    http.ResponseWriter
    ctx        context.Context
    event      *auditinternal.Event
    once       sync.Once
    sink       audit.Sink
    omitStages []auditinternal.Stage
}

func (a *auditResponseWriter) Unwrap() http.ResponseWriter {
    return a.ResponseWriter
}

func (a *auditResponseWriter) processCode(code int) {
    // 使用sync.Once确保只执行一次
    a.once.Do(func() {
        // 如果事件的ResponseStatus为空，则创建一个ResponseStatus对象
        if a.event.ResponseStatus == nil {
            a.event.ResponseStatus = &metav1.Status{}
        }
        // 设置事件的响应状态码
        a.event.ResponseStatus.Code = int32(code)
        // 设置事件的Stage为StageResponseStarted
        a.event.Stage = auditinternal.StageResponseStarted

        // 如果设置了sink，则处理事件
        if a.sink != nil {
            processAuditEvent(a.ctx, a.sink, a.event, a.omitStages)
        }
    })
}

func (a *auditResponseWriter) Write(bs []byte) (int, error) {
    // Go库在没有写入状态码的情况下会在内部调用WriteHeader，但我们无法察觉到这一点
    // 处理状态码
    a.processCode(http.StatusOK)
    // 调用原始ResponseWriter的Write方法
    return a.ResponseWriter.Write(bs)
}

func (a *auditResponseWriter) WriteHeader(code int) {
    // 处理状态码
    a.processCode(code)
    // 调用原始ResponseWriter的WriteHeader方法
    a.ResponseWriter.WriteHeader(code)
}

func (a *auditResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
    // 在协议切换发生之前，伪造一个响应状态
    // 处理状态码
    a.processCode(http.StatusSwitchingProtocols)

    // 如果内部的ResponseWriter对象实现了http.Hijacker，则由WrapForHTTP1Or2返回的外部ResponseWriter对象也实现http.Hijacker
    return a.ResponseWriter.(http.Hijacker).Hijack()
}
```

#### processAuditEvent

```GO
func processAuditEvent(ctx context.Context, sink audit.Sink, ev *auditinternal.Event, omitStages []auditinternal.Stage) bool {
    // 遍历omitStages切片
    for _, stage := range omitStages {
        // 如果ev的Stage与当前遍历的stage相等
        if ev.Stage == stage {
            // 返回true
            return true
        }
    }

    // 根据ev的Stage进行不同的操作
    switch {
    // 如果ev的Stage为StageRequestReceived
    case ev.Stage == auditinternal.StageRequestReceived:
        // 将ev的StageTimestamp设置为ev的RequestReceivedTimestamp的微秒级时间
        ev.StageTimestamp = metav1.NewMicroTime(ev.RequestReceivedTimestamp.Time)
    // 如果ev的Stage为StageResponseComplete
    case ev.Stage == auditinternal.StageResponseComplete:
        // 将ev的StageTimestamp设置为当前时间的微秒级时间
        ev.StageTimestamp = metav1.NewMicroTime(time.Now())
        // 将延迟写入注释中
        writeLatencyToAnnotation(ctx, ev)
    // 默认情况
    default:
        // 将ev的StageTimestamp设置为当前时间的微秒级时间
        ev.StageTimestamp = metav1.NewMicroTime(time.Now())
    }

    // 观察事件
    audit.ObserveEvent(ctx)
    // 处理事件
    return sink.ProcessEvents(ev)
}
```

### decorateResponseWriter

```GO
func decorateResponseWriter(ctx context.Context, responseWriter http.ResponseWriter, ev *auditinternal.Event, sink audit.Sink, omitStages []auditinternal.Stage) http.ResponseWriter {
    // 创建auditResponseWriter对象
    delegate := &auditResponseWriter{
        ctx:            ctx,
        ResponseWriter: responseWriter,
        event:          ev,
        sink:           sink,
        omitStages:     omitStages,
    }

    // 包装为HTTP1或HTTP2的responsewriter
    return responsewriter.WrapForHTTP1Or2(delegate)
}
```

## Unauthorized

用于处理未经授权的请求，并在每次请求到达时返回未经授权的错误响应。

```GO
func Unauthorized(s runtime.NegotiatedSerializer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 将请求的上下文保存到变量ctx中
		ctx := req.Context()
		// 从上下文中获取RequestInfo和found标志
		requestInfo, found := genericapirequest.RequestInfoFrom(ctx)
		// 如果未找到RequestInfo，则在响应中返回内部错误，并提供错误信息"no RequestInfo found in the context"
		if !found {
			responsewriters.InternalError(w, req, errors.New("no RequestInfo found in the context"))
			return
		}

		// 根据RequestInfo的APIGroup和APIVersion创建GroupVersion对象gv
		gv := schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}
		// 使用ErrorNegotiated函数返回一个未授权的错误响应
		responsewriters.ErrorNegotiated(apierrors.NewUnauthorized("Unauthorized"), s, gv, w, req)
	})
}
```

### NewUnauthorized

```GO
// StatusError是一个用于REST API服务器消费的错误；它也可以由客户端从REST响应中重建。为了方便类型切换而设为公开。
type StatusError struct {
	ErrStatus metav1.Status
}

// NewUnauthorized返回一个表示客户端未被授权执行请求操作的错误。
func NewUnauthorized(reason string) *StatusError {
	// 如果未提供原因，将其设置为默认值"not authorized"
	message := reason
	if len(message) == 0 {
		message = "not authorized"
	}
	// 创建一个包含错误状态的StatusError对象并返回
	return &StatusError{metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusUnauthorized,
		Reason:  metav1.StatusReasonUnauthorized,
		Message: message,
	}}
}
```

### ErrorNegotiated

```GO
// ErrorNegotiated将错误渲染到响应中，并返回错误的HTTP状态码。
// 上下文是可选的，可以为nil。
func ErrorNegotiated(err error, s runtime.NegotiatedSerializer, gv schema.GroupVersion, w http.ResponseWriter, req *http.Request) int {
	// 将错误转换为API状态
	status := ErrorToAPIStatus(err)
	code := int(status.Code)
	// 当写入错误时，检查状态是否指示重试的延迟时间
	if status.Details != nil && status.Details.RetryAfterSeconds > 0 {
		// 将重试时间转换为字符串，并设置"Retry-After"响应头
		delay := strconv.Itoa(int(status.Details.RetryAfterSeconds))
		w.Header().Set("Retry-After", delay)
	}

	// 如果状态码为http.StatusNoContent，只设置响应头并返回状态码
	if code == http.StatusNoContent {
		w.WriteHeader(code)
		return code
	}

	// 使用WriteObjectNegotiated函数将对象进行序列化并写入响应
	WriteObjectNegotiated(s, negotiation.DefaultEndpointRestrictions, gv, w, req, code, status, false)
	return code
}
```

## WithFailedAuthenticationAudit

用于装饰在WithAuthentication处理程序中使用的失败的http.Handler。它仅用于记录身份验证失败的请求。

```go
// WithFailedAuthenticationAudit用于装饰在WithAuthentication处理程序中使用的失败的http.Handler。
// 它仅用于记录身份验证失败的请求。
func WithFailedAuthenticationAudit(failedHandler http.Handler, sink audit.Sink, policy audit.PolicyRuleEvaluator) http.Handler {
	// 如果sink或policy为nil，则直接返回failedHandler
	if sink == nil || policy == nil {
		return failedHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 通过评估策略并创建审核事件来获取审核上下文ac和错误err
		ac, err := evaluatePolicyAndCreateAuditEvent(req, policy)
		// 如果创建审核事件时发生错误，则记录错误并返回内部错误的响应
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create audit event: %v", err))
			responsewriters.InternalError(w, req, errors.New("failed to create audit event"))
			return
		}

		// 如果ac为nil或ac.Event为nil，则调用failedHandler处理请求并返回
		if ac == nil || ac.Event == nil {
			failedHandler.ServeHTTP(w, req)
			return
		}
		ev := ac.Event

		// 设置审核事件的响应状态和消息
		ev.ResponseStatus = &metav1.Status{}
		ev.ResponseStatus.Message = getAuthMethods(req)
		ev.Stage = auditinternal.StageResponseStarted

		// 装饰响应写入器rw，用于记录请求和响应
		rw := decorateResponseWriter(req.Context(), w, ev, sink, ac.RequestAuditConfig.OmitStages)
		// 调用failedHandler处理请求并传入装饰的响应写入器rw
		failedHandler.ServeHTTP(rw, req)
	})
}
```

### getAuthMethods

```go
// getAuthMethods返回用于身份验证的方法的字符串表示形式
func getAuthMethods(req *http.Request) string {
	authMethods := []string{}

	// 检查是否使用基本认证
	if _, _, ok := req.BasicAuth(); ok {
		authMethods = append(authMethods, "basic")
	}

	// 检查请求头中的授权信息
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	parts := strings.Split(auth, " ")
	if len(parts) > 1 && strings.ToLower(parts[0]) == "bearer" {
		authMethods = append(authMethods, "bearer")
	}

	// 检查查询参数中的访问令牌
	token := strings.TrimSpace(req.URL.Query().Get("access_token"))
	if len(token) > 0 {
		authMethods = append(authMethods, "access_token")
	}

	// 检查TLS证书
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		authMethods = append(authMethods, "x509")
	}

	// 根据存在的认证方法返回相应的消息
	if len(authMethods) > 0 {
		return fmt.Sprintf("Authentication failed, attempted: %s", strings.Join(authMethods, ", "))
	}
	return "Authentication failed, no credentials provided"
}
```

## withAuthentication

用于认证

```GO
type authenticationRecordMetricsFunc func(context.Context, *authenticator.Response, bool, error, authenticator.Audiences, time.Time, time.Time)

// WithAuthentication创建一个HTTP处理程序，尝试将给定的请求身份验证为用户，然后将找到的任何用户存储到请求的上下文中。
// 如果身份验证失败或返回错误，则使用failed处理程序。成功时，请求中的“Authorization”头将被删除，并调用处理程序来处理请求。
func WithAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, requestHeaderConfig *authenticatorfactory.RequestHeaderConfig) http.Handler {
	return withAuthentication(handler, auth, failed, apiAuds, requestHeaderConfig, recordAuthenticationMetrics)
}

func withAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, requestHeaderConfig *authenticatorfactory.RequestHeaderConfig, metrics authenticationRecordMetricsFunc) http.Handler {
	// 如果auth为nil，表示禁用了身份验证，直接返回handler
	if auth == nil {
		klog.Warning("Authentication is disabled")
		return handler
	}
	// 创建一个http.HandlerFunc处理函数
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authenticationStart := time.Now()

		// 如果apiAuds不为空，将apiAuds添加到请求的上下文中
		if len(apiAuds) > 0 {
			req = req.WithContext(authenticator.WithAudiences(req.Context(), apiAuds))
		}
		// 调用身份验证器对请求进行身份验证
		resp, ok, err := auth.AuthenticateRequest(req)
		authenticationFinish := time.Now()
		// 在函数退出之前，调用metrics函数记录身份验证的指标
		defer func() {
			metrics(req.Context(), resp, ok, err, apiAuds, authenticationStart, authenticationFinish)
		}()
		// 如果身份验证失败或返回错误，调用failed处理程序并返回
		if err != nil || !ok {
			if err != nil {
				klog.ErrorS(err, "Unable to authenticate the request")
			}
			failed.ServeHTTP(w, req)
			return
		}

		// 检查响应的受众是否与apiAuds匹配
		if !audiencesAreAcceptable(apiAuds, resp.Audiences) {
			err = fmt.Errorf("unable to match the audience: %v , accepted: %v", resp.Audiences, apiAuds)
			klog.Error(err)
			failed.ServeHTTP(w, req)
			return
		}

		// 在成功身份验证的情况下，不再需要Authorization头
		req.Header.Del("Authorization")

		// 删除标准前端代理头
		headerrequest.ClearAuthenticationHeaders(
			req.Header,
			standardRequestHeaderConfig.UsernameHeaders,
			standardRequestHeaderConfig.GroupHeaders,
			standardRequestHeaderConfig.ExtraHeaderPrefixes,
		)

		// 删除任何自定义前端代理头
		if requestHeaderConfig != nil {
			headerrequest.ClearAuthenticationHeaders(
				req.Header,
				requestHeaderConfig.UsernameHeaders,
				requestHeaderConfig.GroupHeaders,
				requestHeaderConfig.ExtraHeaderPrefixes,
			)
		}

		// 将resp.User存储到请求的上下文中，并调用handler处理请求
		req = req.WithContext(genericapirequest.WithUser(req.Context(), resp.User))
		handler.ServeHTTP(w, req)
	})
}

func Unauthorized(s runtime.NegotiatedSerializer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		requestInfo, found := genericapirequest.RequestInfoFrom(ctx)
		if !found {
			responsewriters.InternalError(w, req, errors.New("no RequestInfo found in the context"))
			return
		}

		gv := schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}
		// 返回一个未经授权的错误响应
		responsewriters.ErrorNegotiated(apierrors.NewUnauthorized("Unauthorized"), s, gv, w, req)
	})
}

func audiencesAreAcceptable(apiAuds, responseAudiences authenticator.Audiences) bool {
	if len(apiAuds) == 0 || len(responseAudiences) == 0 {
		return true
	}

	// 检查apiAuds和responseAudiences是否有交集
	return len(apiAuds.Intersect(responseAudiences)) > 0
}
```

## WithCORS

```GO
// TODO: 使用 restful.CrossOriginResourceSharing
// 参考：github.com/emicklei/go-restful/blob/master/examples/cors/restful-CORS-filter.go 和
// github.com/emicklei/go-restful/blob/master/examples/basicauth/restful-basic-authentication.go
// 或者，对于更详细的实现，请使用 https://github.com/martini-contrib/cors
// 或在代理层实现 CORS。

// WithCORS是一个简单的CORS实现，包装了一个http处理程序。
// 如果allowedOriginPatterns为空或nil，则不安装CORS支持。
// 如果allowedMethods和allowedHeaders为空或nil，则使用默认值。
func WithCORS(handler http.Handler, allowedOriginPatterns []string, allowedMethods []string, allowedHeaders []string, exposedHeaders []string, allowCredentials string) http.Handler {
	if len(allowedOriginPatterns) == 0 {
		return handler
	}
	allowedOriginPatternsREs := allowedOriginRegexps(allowedOriginPatterns)

	// 如果没有传递方法和头部，则设置默认值
	if allowedMethods == nil {
		allowedMethods = []string{"POST", "GET", "OPTIONS", "PUT", "DELETE", "PATCH"}
	}
	allowMethodsResponseHeader := strings.Join(allowedMethods, ", ")

	if allowedHeaders == nil {
		allowedHeaders = []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "X-Requested-With", "If-Modified-Since"}
	}
	allowHeadersResponseHeader := strings.Join(allowedHeaders, ", ")

	if exposedHeaders == nil {
		exposedHeaders = []string{"Date"}
	}
	exposeHeadersResponseHeader := strings.Join(exposedHeaders, ", ")

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		origin := req.Header.Get("Origin")
		if origin == "" {
			handler.ServeHTTP(w, req)
			return
		}
		if !isOriginAllowed(origin, allowedOriginPatternsREs) {
			handler.ServeHTTP(w, req)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", allowMethodsResponseHeader)
		w.Header().Set("Access-Control-Allow-Headers", allowHeadersResponseHeader)
		w.Header().Set("Access-Control-Expose-Headers", exposeHeadersResponseHeader)
		w.Header().Set("Access-Control-Allow-Credentials", allowCredentials)

		// 如果是预检请求（OPTIONS请求），则直接返回
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 转发给下一个处理程序
		handler.ServeHTTP(w, req)
	})
}

// isOriginAllowed检查请求中给定的origin头部是否允许CORS。
func isOriginAllowed(originHeader string, allowedOriginPatternsREs []*regexp.Regexp) bool {
	for _, re := range allowedOriginPatternsREs {
		if re.MatchString(originHeader) {
			return true
		}
	}
	return false
}

func allowedOriginRegexps(allowedOrigins []string) []*regexp.Regexp {
	res, err := compileRegexps(allowedOrigins)
	if err != nil {
		klog.Fatalf("Invalid CORS allowed origin, --cors-allowed-origins flag was set to %v - %v", strings.Join(allowedOrigins, ","), err)
	}
	return res
}

// 将字符串列表编译为正则表达式列表
func compileRegexps(regexpStrings []string) ([]*regexp.Regexp, error) {
	regexps := []*regexp.Regexp{}
	for _, regexpStr := range regexpStrings {
		r, err := regexp.Compile(regexpStr)
		if err != nil {
			return []*regexp.Regexp{}, err
		}
		regexps = append(regexps, r)
	}
	return regexps, nil
}
```

## WithTimeoutForNonLongRunningRequests

```GO
// WithTimeoutForNonLongRunningRequests 对非长时间运行的请求设置超时时间为 timeout 的处理程序。
func WithTimeoutForNonLongRunningRequests(handler http.Handler, longRunning apirequest.LongRunningRequestCheck) http.Handler {
    if longRunning == nil {
    	return handler
    }
    timeoutFunc := func(req *http.Request) (*http.Request, bool, func(), *apierrors.StatusError) {
        // TODO unify this with apiserver.MaxInFlightLimit
        ctx := req.Context()
        requestInfo, ok := apirequest.RequestInfoFrom(ctx)
        if !ok {
            // 如果发生这种情况，说明处理程序链的设置不正确，因为没有请求信息
            return req, false, func() {}, apierrors.NewInternalError(fmt.Errorf("no request info found for request during timeout"))
        }

        if longRunning(req, requestInfo) {
            return req, true, nil, nil
        }

        postTimeoutFn := func() {
            metrics.RecordRequestTermination(req, requestInfo, metrics.APIServerComponent, http.StatusGatewayTimeout)
        }
        return req, false, postTimeoutFn, apierrors.NewTimeoutError("request did not complete within the allotted timeout", 0)
    }
    return WithTimeout(handler, timeoutFunc)
}

// timeoutFunc 是一个函数类型，接受一个 *http.Request 类型的参数，返回一个 *http.Request 类型的结果，以及一个 bool 类型的结果和一个 func() 类型的结果和 *apierrors.StatusError 类型的结果。
type timeoutFunc = func(*http.Request) (req *http.Request, longRunning bool, postTimeoutFunc func(), err *apierrors.StatusError)

// WithTimeout 返回一个带有超时时间的 http.Handler，超时时间由 timeoutFunc 决定。
// 这个新的 http.Handler 调用 h.ServeHTTP 来处理每个请求，但如果一个调用运行时间超过其限制，处理程序将使用 504 Gateway Timeout 错误和提供的消息进行响应。
// （如果 msg 为空，则会发送一个适当的默认消息。）在处理程序超时之后，h 对其 http.ResponseWriter 的写入将返回 http.ErrHandlerTimeout。
// 如果 timeoutFunc 返回一个空的超时通道，将不会强制执行超时。recordFn 是在发生超时时调用的函数。
func WithTimeout(h http.Handler, timeoutFunc timeoutFunc) http.Handler {
	return &timeoutHandler{h, timeoutFunc}
}

// timeoutHandler 是一个实现了 http.Handler 接口的结构体，包含一个 http.Handler 类型的字段和一个 timeoutFunc 类型的字段。
type timeoutHandler struct {
    handler http.Handler
    timeout timeoutFunc
}

// ServeHTTP 实现了 http.Handler 接口的 ServeHTTP 方法。
func (t *timeoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    r, longRunning, postTimeoutFn, err := t.timeout(r)
    if longRunning {
        t.handler.ServeHTTP(w, r)
        return
    }
    timeoutCh := r.Context().Done()

    // resultCh 既用作 errCh 也用作 stopCh
    resultCh := make(chan interface{})
    var tw timeoutWriter
    tw, w = newTimeoutWriter(w)

    // 复制请求并在新的 goroutine 中处理它，以避免在访问/修改请求时出现竞争条件（例如标头）
    rCopy := r.Clone(r.Context())
    go func() {
        defer func() {
            err := recover()
            // 不包装 sentinel ErrAbortHandler 恐慌值
            if err != nil && err != http.ErrAbortHandler {
                // 与 stdlib http 服务器代码相同。手动分配堆栈跟踪缓冲区大小，以防止过大的日志
                const size = 64 << 10
                buf := make([]byte, size)
                buf = buf[:runtime.Stack(buf, false)]
                err = fmt.Sprintf("%v\n%s", err, buf)
            }
            resultCh <- err
        }()
        t.handler.ServeHTTP(w, rCopy)
    }()
    select {
    case err := <-resultCh:
        // 如果发生错误则 panic；否则停止执行
        if err != nil {
            panic(err)
        }
        return
    case <-timeoutCh:
        defer func() {
            // resultCh 需要有一个 reader，因为执行工作的函数需要向其发送。这个 defer 用于确保它运行，即使 post timeout 的工作本身引发恐慌。
            go func() {
                timedOutAt := time.Now()
                res := <-resultCh

                status := metrics.PostTimeoutHandlerOK
                if res != nil {
                    // 非 nil 的 res 表示发生了恐慌。
                    status = metrics.PostTimeoutHandlerPanic
                }

                metrics.RecordRequestPostTimeout(metrics.PostTimeoutSourceTimeoutHandler, status)
                err := fmt.Errorf("post-timeout activity - time-elapsed: %s, %v %q result: %v",
                    time.Since(timedOutAt), r.Method, r.URL.Path, res)
                utilruntime.HandleError(err)
            }()
        }()
        httplog.SetStacktracePredicate(r.Context(), func(status int) bool {
            return false
        })
        defer postTimeoutFn()
        tw.timeout(err)
    }
}

// timeoutWriter 是一个接口类型，继承自 http.ResponseWriter 接口，并添加了 timeout 方法。
type timeoutWriter interface {
    http.ResponseWriter
    timeout(*apierrors.StatusError)
}

// _ 是一个变量，用于忽略结果，这里用于忽略类型检查。
var _ http.ResponseWriter = &baseTimeoutWriter{}
var _ responsewriter.UserProvidedDecorator = &baseTimeoutWriter{}

// baseTimeoutWriter 是一个实现了 http.ResponseWriter 接口和 responsewriter.UserProvidedDecorator 接口的结构体，包含一个 http.ResponseWriter 类型的字段和一些其他字段。
type baseTimeoutWriter struct {
	w http.ResponseWriter
    // headers written by the normal handler
    handlerHeaders http.Header

    mu sync.Mutex
    // if the timeout handler has timeout
    timedOut bool
    // if this timeout writer has wrote header
    wroteHeader bool
    // if this timeout writer has been hijacked
    hijacked bool
}

// Unwrap 返回原始的 http.ResponseWriter。
func (tw *baseTimeoutWriter) Unwrap() http.ResponseWriter {
	return tw.w
}

// Header 返回基于 handlerHeaders 的 Header。
func (tw *baseTimeoutWriter) Header() http.Header {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    if tw.timedOut {
        return http.Header{}
    }

    return tw.handlerHeaders
}

// Write 将数据写入 ResponseWriter，并在超时时返回 ErrHandlerTimeout 错误。
func (tw *baseTimeoutWriter) Write(p []byte) (int, error) {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    if tw.timedOut {
        return 0, http.ErrHandlerTimeout
    }
    if tw.hijacked {
        return 0, http.ErrHijacked
    }

    if !tw.wroteHeader {
        copyHeaders(tw.w.Header(), tw.handlerHeaders)
        tw.wroteHeader = true
    }
    return tw.w.Write(p)
}

// Flush 将数据刷新到客户端。
func (tw *baseTimeoutWriter) Flush() {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    if tw.timedOut {
        return
    }

    // 如果内部的 tw.w 实现了 http.Flusher 接口，那么外部的 ResponseWriter 对象将实现 http.Flusher 接口。
    tw.w.(http.Flusher).Flush()
}

// WriteHeader 将状态码写入 ResponseWriter，并复制 handlerHeaders 到 tw.w.Header()。
func (tw *baseTimeoutWriter) WriteHeader(code int) {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    if tw.timedOut || tw.wroteHeader || tw.hijacked {
        return
    }

    copyHeaders(tw.w.Header(), tw.handlerHeaders)
    tw.wroteHeader = true
    tw.w.WriteHeader(code)
}

// copyHeaders 复制源头的 Headers 到目标 Headers。
func copyHeaders(dst, src http.Header) {
    for k, v := range src {
    	dst[k] = v
    }
}


// timeout 将请求标记为超时，并根据情况返回 504 状态码或 panic。
func (tw *baseTimeoutWriter) timeout(err *apierrors.StatusError) {
    tw.mu.Lock()
    defer tw.mu.Unlock()

    tw.timedOut = true

    // 如果超时的 timeout writer 尚未被内部 handler 使用，则可以通过发送超时 handler 来安全地超时 HTTP 请求。
    if !tw.wroteHeader && !tw.hijacked {
        tw.w.WriteHeader(http.StatusGatewayTimeout)
        enc := json.NewEncoder(tw.w)
        enc.Encode(&err.ErrStatus)
    } else {
        // 如果超时的 timeout writer 已经被内部 handler 使用，则无法在此处超时 HTTP 请求。
        // 我们必须关闭 HTTP1 的连接或重置 HTTP2 的流。
        //
        // 来自 golang 文档的注释：
        // 如果 ServeHTTP 引发了恐慌，则服务器（即 ServeHTTP 的调用者）假定恐慌的效果仅限于活动请求。
        // 它会恢复恐慌，将堆栈跟踪记录到服务器错误日志，并根据 HTTP 协议关闭网络连接或发送 HTTP/2 RST_STREAM。
        //
        // 这里我们故意抛出 http.ErrAbortHandler，以便通知客户端并在日志中抑制不必要的堆栈跟踪。
        panic(http.ErrAbortHandler)
    }
}
```

## WithRequestDeadline

```GO
// WithRequestDeadline 确定适用于给定请求的超时持续时间，并设置一个新的上下文
// 具有适当截止日期。
// auditWrapper 提供了一个处理程序，用于审核失败的请求。
// longRunning 如果给定的请求是一个长时间运行的请求，则返回true。
// requestTimeoutMaximum 指定默认请求超时值。
func WithRequestDeadline(
	handler http.Handler,
	sink audit.Sink,
	policy audit.PolicyRuleEvaluator,
	longRunning request.LongRunningRequestCheck,
	negotiatedSerializer runtime.NegotiatedSerializer,
	requestTimeoutMaximum time.Duration,
) http.Handler {
	return withRequestDeadline(
		handler,
		sink,
		policy,
		longRunning,
		negotiatedSerializer,
		requestTimeoutMaximum,
		clock.RealClock{},
	)
}

func withRequestDeadline(
	handler http.Handler,
	sink audit.Sink,
	policy audit.PolicyRuleEvaluator,
	longRunning request.LongRunningRequestCheck,
	negotiatedSerializer runtime.NegotiatedSerializer,
	requestTimeoutMaximum time.Duration,
	clock clock.PassiveClock,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		// 从上下文中获取请求信息
		requestInfo, ok := request.RequestInfoFrom(ctx)
		if !ok {
			// 如果找不到请求信息，返回内部服务器错误
			handleError(w, req, http.StatusInternalServerError, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong"))
			return
		}

		// 如果是长时间运行的请求，直接处理请求
		if longRunning(req, requestInfo) {
			handler.ServeHTTP(w, req)
			return
		}

		// 解析超时时间
		userSpecifiedTimeout, ok, err := parseTimeout(req)
		if err != nil {
			statusErr := apierrors.NewBadRequest(err.Error())

			klog.Errorf("Error - %s: %#v", err.Error(), req.RequestURI)

			// 创建处理失败的处理程序
			failed := failedErrorHandler(negotiatedSerializer, statusErr)
			// 创建带有请求审核的处理程序
			failWithAudit := withFailedRequestAudit(failed, statusErr, sink, policy)
			// 执行带有请求审核的处理程序
			failWithAudit.ServeHTTP(w, req)
			return
		}

		timeout := requestTimeoutMaximum
		if ok {
			// 我们使用 apiserver 强制执行的默认超时时间：
			// - 如果用户指定的超时时间为 0s，则表示用户没有设置超时时间。
			// - 如果用户指定的超时时间超过了 apiserver 允许的最大截止日期。
			if userSpecifiedTimeout > 0 && userSpecifiedTimeout < requestTimeoutMaximum {
				timeout = userSpecifiedTimeout
			}
		}

		started := clock.Now()
		if requestStartedTimestamp, ok := request.ReceivedTimestampFrom(ctx); ok {
			started = requestStartedTimestamp
		}

		ctx, cancel := context.WithDeadline(ctx, started.Add(timeout))
		defer cancel()

		req = req.WithContext(ctx)
		handler.ServeHTTP(w, req)
	})
}

// withFailedRequestAudit 用于装饰处理失败的 http.Handler，并用于审核失败的请求。
// statusErr 用于填充 ResponseStatus 的 Message 属性。
func withFailedRequestAudit(
	failedHandler http.Handler,
	statusErr *apierrors.StatusError,
	sink audit.Sink,
	policy audit.PolicyRuleEvaluator,
) http.Handler {
	if sink == nil || policy == nil {
		return failedHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 评估策略并创建审核事件
		ac, err := evaluatePolicyAndCreateAuditEvent(req, policy)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("failed to create audit event: %v", err))
			responsewriters.InternalError(w, req, errors.New("failed to create audit event"))
			return
		}

		if ac == nil || ac.Event == nil {
			failedHandler.ServeHTTP(w, req)
			return
		}
		ev := ac.Event

		ev.ResponseStatus = &metav1.Status{}
		ev.Stage = auditinternal.StageResponseStarted
		if statusErr != nil {
			ev.ResponseStatus.Message = statusErr.Error()
		}

		rw := decorateResponseWriter(
			req.Context(),
			w,
			ev,
			sink,
			ac.RequestAuditConfig.OmitStages,
		)
		failedHandler.ServeHTTP(rw, req)
	})
}

// failedErrorHandler 返回一个使用指定的 StatusError 对象将错误响应呈现给请求的 http.Handler。
func failedErrorHandler(
	s runtime.NegotiatedSerializer,
	statusError *apierrors.StatusError,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		requestInfo, found := request.RequestInfoFrom(ctx)
		if !found {
			responsewriters.InternalError(w, req, errors.New("no RequestInfo found in the context"))
			return
		}

		gv := schema.GroupVersion{
			Group:   requestInfo.APIGroup,
			Version: requestInfo.APIVersion,
		}
		responsewriters.ErrorNegotiated(statusError, s, gv, w, req)
	})
}

// parseTimeout 解析给定的 HTTP 请求 URL 并提取超时查询参数的值（如果用户指定）。
// 如果未指定超时时间，则函数返回 false，err 设置为 nil。
// 如果指定的值格式错误，则函数返回 false，err 设置。
func parseTimeout(req *http.Request) (time.Duration, bool, error) {
	value := req.URL.Query().Get("timeout")
	if value == "" {
		return 0, false, nil
	}

	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, false, fmt.Errorf("%s - %s", invalidTimeoutInURL, err.Error())
	}

	return timeout, true, nil
}

func handleError(w http.ResponseWriter, r *http.Request, code int, err error) {
	errorMsg := fmt.Sprintf("Error - %s: %#v", err.Error(), r.RequestURI)
	http.Error(w, errorMsg, code)
	klog.Errorf(errorMsg)
}

```

## WithWaitGroup

将所有非长时间运行的请求添加到等待组，用于优雅地关闭。

```GO
// RequestWaitGroup用于跟踪处于处理过程中的请求的计数：
// 在执行请求处理程序之前，调用方需要调用Add(1)，
// 然后在处理程序完成时调用Done()。
// 注意：实现必须确保在多个goroutine中调用时是线程安全的。
type RequestWaitGroup interface {
    // Add方法用于增加计数，delta可以是负数，类似于sync.WaitGroup。
    // 如果在Wait之后使用正数的delta调用Add，它将返回错误，防止不安全的Add操作。
    Add(delta int) error

    // Done方法用于减少计数。
    Done()
}

// WithWaitGroup函数将所有非长时间运行的请求添加到等待组，用于优雅地关闭。
func WithWaitGroup(handler http.Handler, longRunning apirequest.LongRunningRequestCheck, wg RequestWaitGroup) http.Handler {
    // 注意：WithWaitGroup和WithRetryAfter两者必须使用相同的isRequestExemptFunc 'isRequestExemptFromRetryAfter'，
    // 否则SafeWaitGroup可能会无限期等待，并阻止服务器优雅地关闭。
    return withWaitGroup(handler, longRunning, wg, isRequestExemptFromRetryAfter)
}

func withWaitGroup(handler http.Handler, longRunning apirequest.LongRunningRequestCheck, wg RequestWaitGroup, isRequestExemptFn isRequestExemptFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        ctx := req.Context()
        requestInfo, ok := apirequest.RequestInfoFrom(ctx)
        if !ok {
            // 如果出现此情况，则处理程序链未正确设置，因为上下文中没有请求信息。
            responsewriters.InternalError(w, req, errors.New("no RequestInfo found in the context"))
            return
        }
    	if longRunning(req, requestInfo) {
            handler.ServeHTTP(w, req)
            return
        }

        if err := wg.Add(1); err != nil {
            // 关闭延迟已经过去并且已调用SafeWaitGroup.Wait，
            // 这意味着'WithRetryAfter'已开始发送Retry-After响应。
            // 我们将免除与WithRetryAfter相同的请求集，
            // 这些请求被免除不会被拒绝并返回Retry-After响应。
            if isRequestExemptFn(req) {
                handler.ServeHTTP(w, req)
                return
            }

            // 当apiserver关闭时，通知客户端进行重试。
            // 客户端很可能会命中另一个服务器，因此紧密的重试对于客户端的响应性是有利的。
            waitGroupWriteRetryAfterToResponse(w)
            return
        }

        defer wg.Done()
        handler.ServeHTTP(w, req)
    })
}
```

## WithWatchTerminationDuringShutdown

监视关闭信号，并在关闭信号发出时终止请求的处理过程

```GO
// 定义函数 WithWatchTerminationDuringShutdown，该函数接收三个参数：handler http.Handler、termination apirequest.ServerShutdownSignal 和 wg RequestWaitGroup，并返回一个类型为 http.Handler 的结果。
func WithWatchTerminationDuringShutdown(handler http.Handler, termination apirequest.ServerShutdownSignal, wg RequestWaitGroup) http.Handler {
	// 检查 termination 和 wg 是否为 nil，如果是，则打印警告信息并返回原始的 handler。
	if termination == nil || wg == nil {
		klog.Warningf("watch termination during shutdown not attached to the handler chain")
		return handler
	}
	// 返回一个 http.HandlerFunc 匿名函数，该函数接收两个参数：w http.ResponseWriter 和 req *http.Request。
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 获取请求的上下文对象 ctx。
		ctx := req.Context()
		// 从 ctx 中获取 requestInfo 和 ok 标志。
		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		// 如果获取不到 requestInfo，则说明 handler 链没有正确设置，因为上下文中没有请求信息。
		if !ok {
			// 返回一个内部错误响应，状态码为 500，并打印错误信息 "no RequestInfo found in the context"。
			responsewriters.InternalError(w, req, errors.New("no RequestInfo found in the context"))
			return
		}
		// 如果请求的动作不在 watchVerbs 列表中，则调用原始的 handler 处理请求，并返回。
		if !watchVerbs.Has(requestInfo.Verb) {
			handler.ServeHTTP(w, req)
			return
		}
		// 尝试向 wg 添加一个请求计数，如果出错，则说明 apiserver 正在关闭中，需要通知客户端重试。
		if err := wg.Add(1); err != nil {
			// 当 apiserver 正在关闭时，通知客户端进行重试。
			// 由于客户端可能已经请求到了另一个服务器，因此紧密的重试可以提高客户端的响应速度。
			waitGroupWriteRetryAfterToResponse(w)
			return
		}
		// 将 termination 附加到 watch 请求的上下文中，以便在服务器发出关闭信号时，watch 处理循环能够尽快返回。
		ctx = apirequest.WithServerShutdownSignal(req.Context(), termination)
		req = req.WithContext(ctx)
		// 在函数执行完成后，从 wg 中减少一个请求计数。
		defer wg.Done()
		// 调用原始的 handler 处理请求。
		handler.ServeHTTP(w, req)
	})
}
```

## WithProbabilisticGoaway

```GO
// GoawayDecider决定服务器是否发送GOAWAY
type GoawayDecider interface {
	Goaway(r *http.Request) bool
}

var (
    // randPool用于线程安全地获取rand.Rand并生成随机数，以提高使用带锁的rand.Rand的性能
    randPool = &sync.Pool{
    	New: func() interface{} {
        	return rand.New(rand.NewSource(rand.Int63()))
        },
	}
)

// WithProbabilisticGoaway返回一个http.Handler，根据给定的概率发送GOAWAY来处理HTTP2请求。
// 客户端在接收到GOAWAY之后，正在处理中的长时间运行的请求不会受到影响，
// 新的请求将使用新的TCP连接重新平衡到负载均衡后面的另一个服务器。
func WithProbabilisticGoaway(inner http.Handler, chance float64) http.Handler {
    return &goaway{
        handler: inner,
        decider: &probabilisticGoawayDecider{
            chance: chance,
            next: func() float64 {
                rnd := randPool.Get().(*rand.Rand)
                ret := rnd.Float64()
                randPool.Put(rnd)
                return ret
        	},
        },
    }
}

// goaway根据decider发送GOAWAY以处理HTTP2请求
type goaway struct {
    handler http.Handler
    decider GoawayDecider
}

// ServeHTTP实现了HTTP处理程序
func (h *goaway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.Proto == "HTTP/2.0" && h.decider.Goaway(r) {
        // 在空闲时发送GOAWAY并关闭TCP连接。
        w.Header().Set("Connection", "close")
    }

	h.handler.ServeHTTP(w, r)
}

// probabilisticGoawayDecider根据概率发送GOAWAY
type probabilisticGoawayDecider struct {
    chance float64
    next func() float64
}

// Goaway实现了GoawayDecider
func (p *probabilisticGoawayDecider) Goaway(r *http.Request) bool {
	return p.next() < p.chance
}
```

## WithWarningRecorder

将一个警告记录器附加到请求的上下文中

```GO
// WithWarningRecorder 函数将一个 k8s.io/apiserver/pkg/warning#WarningRecorder 附加到请求的上下文中。
func WithWarningRecorder(handler http.Handler) http.Handler {
	// 返回一个 http.HandlerFunc 匿名函数，该函数接收两个参数：w http.ResponseWriter 和 req *http.Request。
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 创建一个 recorder 对象，该对象用于记录警告信息。
		recorder := &recorder{writer: w}
		// 将记录警告信息的 recorder 对象附加到请求的上下文中。
		req = req.WithContext(warning.WithWarningRecorder(req.Context(), recorder))
		// 调用原始的处理程序处理请求。
		handler.ServeHTTP(w, req)
	})
}

// 定义一些变量
var (
	truncateAtTotalRunes = 4 * 1024
	truncateItemRunes    = 256
)

// 定义 recordedWarning 结构体，用于表示记录的警告信息。
type recordedWarning struct {
	agent string
	text  string
}

// 定义 recorder 结构体，用于记录警告信息的详细信息。
type recorder struct {
	// lock 用于保护多个线程对 AddWarning 的调用
	lock sync.Mutex

	// recorded 用于记录是否已经使用给定的文本调用了 AddWarning
	recorded map[string]bool

	// ordered 用于按顺序记录添加的警告信息，以便在需要时可以回放和截断
	ordered []recordedWarning

	// written 用于记录已添加的警告信息的文本数
	written int

	// truncating 用于跟踪是否已经超过 truncateAtTotalRunes，并且正在截断警告消息
	truncating bool

	// writer 是要添加警告头的响应写入器
	writer http.ResponseWriter
}

// AddWarning 方法用于向 recorder 中添加警告信息
func (r *recorder) AddWarning(agent, text string) {
	// 如果文本为空，则直接返回
	if len(text) == 0 {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	// 如果已经超过限制且正在截断，则提前返回
	if r.written >= truncateAtTotalRunes && r.truncating {
		return
	}

	// 如果需要，进行初始化
	if r.recorded == nil {
		r.recorded = map[string]bool{}
	}

	// 如果已经警告过相同的内容，则直接返回
	if r.recorded[text] {
		return
	}
	r.recorded[text] = true
	r.ordered = append(r.ordered, recordedWarning{agent: agent, text: text})

	// 如果需要截断，则在 rune 边界上截断文本
	textRuneLength := utf8.RuneCountInString(text)
	if r.truncating && textRuneLength > truncateItemRunes {
		text = string([]rune(text)[:truncateItemRunes])
		textRuneLength = truncateItemRunes
	}

	// 计算警告头
	header, err := net.NewWarningHeader(299, agent, text)
	if err != nil {
		return
	}

	// 如果未超过限制，或者已经在截断状态下，写入并返回
	if r.written+textRuneLength <= truncateAtTotalRunes || r.truncating {
		r.written += textRuneLength
		r.writer.Header().Add("Warning", header)
		return
	}

	// 否则，启用截断，重置状态，并回放已存在的条目作为截断的警告信息
	r.truncating = true
	r.written = 0
	r.writer.Header().Del("Warning")
	utilruntime.HandleError(fmt.Errorf("exceeded max warning header size, truncating"))
	for _, w := range r.ordered {
		agent := w.agent
		text := w.text

		textRuneLength := utf8.RuneCountInString(text)
		if textRuneLength > truncateItemRunes {
			text = string([]rune(text)[:truncateItemRunes])
			textRuneLength = truncateItemRunes
		}
		if header, err := net.NewWarningHeader(299, agent, text); err == nil {
			r.written += textRuneLength
			r.writer.Header().Add("Warning", header)
		}
	}
}
```

## WithCacheControl

```GO
// WithCacheControl函数将Cache-Control标头设置为"no-cache, private"，
// 因为所有服务器都受到身份验证和授权保护。
// 参考：https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching#defining_optimal_cache-control_policy
func WithCacheControl(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        // 如果Cache-Control标头尚未设置，则设置cache-control标头
        if _, ok := w.Header()["Cache-Control"]; !ok {
            w.Header().Set("Cache-Control", "no-cache, private")
        }
        handler.ServeHTTP(w, req)
    })
}
```

## WithHSTS

```GO
// WithHSTS函数是一个简单的HSTS实现，用于包装一个http处理程序。
// 如果hstsDirectives为空或nil，则不安装HSTS支持。
func WithHSTS(handler http.Handler, hstsDirectives []string) http.Handler {
    if len(hstsDirectives) == 0 {
    	return handler
    }
    allDirectives := strings.Join(hstsDirectives, "; ")
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        // Chrome和Mozilla Firefox维护着一个HSTS预加载列表
        // 问题：golang.org/issue/26162
        // 如果Strict-Transport-Security标头尚未设置，则设置Strict-Transport-Security标头
        if _, ok := w.Header()["Strict-Transport-Security"]; !ok {
        	w.Header().Set("Strict-Transport-Security", allDirectives)
        }
        handler.ServeHTTP(w, req)
    })
}
```

## WithRetryAfter

```GO
// isRequestExemptFunc函数返回true，如果请求不应该被拒绝并回复Retry-After响应，否则返回false。
type isRequestExemptFunc func(*http.Request) bool
// retryAfterParams结构体定义了构建Retry-After响应的参数。
type retryAfterParams struct {
    // TearDownConnection为true表示在响应中发送'Connection: close'头，
    // 以便net/http可以终止TCP连接。
    TearDownConnection bool

    // Message描述了为什么服务器发送了Retry-After响应。
    Message string
}

// shouldRespondWithRetryAfterFunc函数返回true，如果满足某些条件时应拒绝请求
// 并回复Retry-After响应。返回的retryAfterParams包含构建Retry-After响应的指令。

type shouldRespondWithRetryAfterFunc func() (*retryAfterParams, bool)

// WithRetryAfter函数通过429状态码拒绝任何新的请求，如果指定的shutdownDelayDurationElapsedCh通道关闭。
//
// 它将新的请求（在新的或现有的TCP连接上）包括在内。
// 在shutdownDelayDurationElapsedCh关闭后到达的任何新的请求都将回复429和以下响应头：
// - 'Retry-After: N`（这样客户端可以在N秒后重试，希望在新的apiserver实例上）
// - 'Connection: close'：终止TCP连接
//
// TODO: 有没有办法合并WithWaitGroup和此过滤器？
func WithRetryAfter(handler http.Handler, shutdownDelayDurationElapsedCh <-chan struct{}) http.Handler {
    shutdownRetryAfterParams := &retryAfterParams{
        TearDownConnection: true,
        Message: "The apiserver is shutting down, please try again later.",
    }

    // 注意：WithRetryAfter和WithWaitGroup必须使用完全相同的isRequestExemptFunc函数'isRequestExemptFromRetryAfter'，
    // 否则SafeWaitGroup可能会无限等待并阻止服务器正常关闭。
    return withRetryAfter(handler, isRequestExemptFromRetryAfter, func() (*retryAfterParams, bool) {
        select {
        case <-shutdownDelayDurationElapsedCh:
            return shutdownRetryAfterParams, true
        default:
            return nil, false
        }
    })
}

// WithRetryAfter 拒绝任何新的请求，如果指定的 shutdownDelayDurationElapsedFn 通道关闭时返回 429
//
// 它会在新的或现有的 TCP 连接上包含新的请求
// 在 shutdownDelayDurationElapsedFn 关闭后到达的新请求将返回 429 和以下响应头：
//   - 'Retry-After: N`（这样客户端可以在 N 秒后重试，希望在新的 apiserver 实例上重试）
//   - 'Connection: close'：关闭 TCP 连接
//
// TODO: 有没有办法将 WithWaitGroup 和这个过滤器合并？
func WithRetryAfter(handler http.Handler, shutdownDelayDurationElapsedCh <-chan struct{}) http.Handler {
	shutdownRetryAfterParams := &retryAfterParams{
		TearDownConnection: true,
		Message:            "The apiserver is shutting down, please try again later.",
	}

	// 注意：WithRetryAfter 和 WithWaitGroup 必须使用完全相同的 isRequestExemptFunc 'isRequestExemptFromRetryAfter'，
	// 否则 SafeWaitGroup 可能会无限期等待并阻止服务器优雅地关闭。
	return withRetryAfter(handler, isRequestExemptFromRetryAfter, func() (*retryAfterParams, bool) {
		select {
		case <-shutdownDelayDurationElapsedCh:
			return shutdownRetryAfterParams, true
		default:
			return nil, false
		}
	})
}

func withRetryAfter(handler http.Handler, isRequestExemptFn isRequestExemptFunc, shouldRespondWithRetryAfterFn shouldRespondWithRetryAfterFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		params, send := shouldRespondWithRetryAfterFn()
		if !send || isRequestExemptFn(req) {
			handler.ServeHTTP(w, req)
			return
		}

		// 如果代码执行到这里，表示应该发送 Retry-After 响应
		//
		// 从 net/http2 库复制而来
		// 在 HTTP/2 中不允许 "Connection" 头（RFC 7540, 8.1.2.2），
		// 但是如果 "Connection" == "close"，则会发送 GOAWAY 并关闭空闲时的 TCP 连接，与 HTTP/1 一样。
		if params.TearDownConnection {
			w.Header().Set("Connection", "close")
		}

		// 返回一个 429 状态码，要求客户端在 5 秒后重试
		w.Header().Set("Retry-After", "5")
		http.Error(w, params.Message, http.StatusTooManyRequests)
	})
}

// isRequestExemptFromRetryAfter 如果给定的请求应该豁免被拒绝并返回 'Retry-After' 响应，则返回 true。
// 注意：'WithRetryAfter' 和 'WithWaitGroup' 过滤器都应该使用这个函数来豁免一组请求免受拒绝或跟踪。
func isRequestExemptFromRetryAfter(r *http.Request) bool {
	return isKubeApiserverUserAgent(r) || hasExemptPathPrefix(r)
}

func isKubeApiserverUserAgent(req *http.Request) bool {
	return strings.HasPrefix(req.UserAgent(), "kube-apiserver/")
}

func hasExemptPathPrefix(r *http.Request) bool {
	for _, whiteListedPrefix := range pathPrefixesExemptFromRetryAfter {
		if strings.HasPrefix(r.URL.Path, whiteListedPrefix) {
			return true
		}
	}
	return false
}
```

## WithHTTPLogging

```GO
// WithHTTPLogging 函数用于启用对传入请求的日志记录。
func WithHTTPLogging(handler http.Handler) http.Handler {
	// 调用 httplog.WithLogging 函数，将处理程序和默认的堆栈跟踪预测器作为参数传入，返回一个新的处理程序。
	return httplog.WithLogging(handler, httplog.DefaultStacktracePred)
}

// withPanicRecovery 函数用于处理恐慌恢复。
func withPanicRecovery(handler http.Handler, crashHandler func(http.ResponseWriter, *http.Request, interface{})) http.Handler {
	// 返回一个 http.HandlerFunc 匿名函数，该函数接收两个参数：w http.ResponseWriter 和 req *http.Request。
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 使用 defer 语句延迟执行代码块，该代码块在恐慌发生时进行恢复。
		defer runtime.HandleCrash(func(err interface{}) {
			// 在恢复时调用传入的 crashHandler 函数，将响应写入器、请求和错误信息作为参数传入。
			crashHandler(w, req, err)
		})

		// 将请求分发给内部的处理程序。
		handler.ServeHTTP(w, req)
	})
}
```

## WithTracing

```GO
// WithTracing函数在传入的请求被采样时为请求添加追踪功能
func WithTracing(handler http.Handler, tp trace.TracerProvider) http.Handler {
    opts := []otelhttp.Option{
        otelhttp.WithPropagators(tracing.Propagators()), // 使用tracing.Propagators()设置追踪的传播方式
        otelhttp.WithPublicEndpoint(), // 使用公共的终端点（endpoint）
        otelhttp.WithTracerProvider(tp), // 使用传入的TracerProvider设置追踪器提供者
    }
    // 使用Noop TracerProvider，即使没有追踪器提供者，otelhttp仍然处理上下文传播。
    // 参考链接：https://github.com/open-telemetry/opentelemetry-go/tree/main/example/passthrough
    return otelhttp.NewHandler(handler, "KubernetesAPI", opts...)
}
```

## WithLatencyTrackers

```GO
// WithLatencyTrackers函数向与请求关联的上下文中添加一个LatencyTrackers实例，以便我们可以测量apiserver内各组件产生的延迟。
func WithLatencyTrackers(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        ctx := req.Context()
        requestInfo, ok := request.RequestInfoFrom(ctx)
        if !ok {
            handleError(w, req, http.StatusInternalServerError, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong"))
            return
        }

        if watchVerbs.Has(requestInfo.Verb) {
            handler.ServeHTTP(w, req)
            return
        }

        req = req.WithContext(request.WithLatencyTrackers(ctx))    // 使用request.WithLatencyTrackers(ctx)为请求设置上下文
        w = responsewriter.WrapForHTTP1Or2(&writeLatencyTracker{    // 使用writeLatencyTracker包装响应写入器
            ResponseWriter: w,
            ctx:            req.Context(),
        })

        handler.ServeHTTP(w, req)
    })
}

var _ http.ResponseWriter = &writeLatencyTracker{} // 确认writeLatencyTracker实现了http.ResponseWriter接口
var _ responsewriter.UserProvidedDecorator = &writeLatencyTracker{} // 确认writeLatencyTracker实现了responsewriter.UserProvidedDecorator接口

type writeLatencyTracker struct {
    http.ResponseWriter
    ctx context.Context
}

func (wt *writeLatencyTracker) Unwrap() http.ResponseWriter {
	return wt.ResponseWriter
}

func (wt *writeLatencyTracker) Write(bs []byte) (int, error) {
    startedAt := time.Now() // 记录写入开始时间
    defer func() {
    	request.TrackResponseWriteLatency(wt.ctx, time.Since(startedAt)) // 测量写入延迟并进行跟踪
    }()

    return wt.ResponseWriter.Write(bs)    // 调用原始的ResponseWriter的Write方法进行写入操作
}
```

## WithRequestInfo

```GO
// WithRequestInfo函数将一个RequestInfo附加到上下文中。
func WithRequestInfo(handler http.Handler, resolver request.RequestInfoResolver) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        // 获取请求的上下文
        ctx := req.Context()

        // 使用提供的解析器解析请求并获取RequestInfo
        info, err := resolver.NewRequestInfo(req)
        if err != nil {
            // 如果解析失败，则返回一个内部错误响应
            responsewriters.InternalError(w, req, fmt.Errorf("failed to create RequestInfo: %v", err))
            return
        }

        // 将解析得到的RequestInfo附加到请求的上下文中
        req = req.WithContext(request.WithRequestInfo(ctx, info))

        // 调用传入的处理程序来处理请求
        handler.ServeHTTP(w, req)
    })
}
```

## WithRequestReceivedTimestamp

```GO
// WithRequestReceivedTimestamp函数将接收到请求的时间（ReceivedTimestamp）附加到上下文中。
func WithRequestReceivedTimestamp(handler http.Handler) http.Handler {
	return withRequestReceivedTimestampWithClock(handler, clock.RealClock{})
}

// 时钟作为参数传递，方便进行单元测试。
func withRequestReceivedTimestampWithClock(handler http.Handler, clock clock.PassiveClock) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        ctx := req.Context()
        req = req.WithContext(request.WithReceivedTimestamp(ctx, clock.Now())) // 使用clock.Now()为请求设置ReceivedTimestamp并更新上下文

        handler.ServeHTTP(w, req)
    })
}
```

## WithMuxAndDiscoveryComplete

```GO
type muxAndDiscoveryIncompleteKeyType int

const (
    // muxAndDiscoveryIncompleteKey 是一个键，用于在请求的上下文中存储在服务器安装所有已知的HTTP路径之前发出的所有请求的保护信号
    muxAndDiscoveryIncompleteKey muxAndDiscoveryIncompleteKeyType = iota
)

// NoMuxAndDiscoveryIncompleteKey 检查上下文中是否包含 muxAndDiscoveryIncompleteKey。
// 存在该键表示在安装HTTP路径之前发出了该请求。
func NoMuxAndDiscoveryIncompleteKey(ctx context.Context) bool {
    // 从上下文中获取 muxAndDiscoveryIncompleteKey 的值
    muxAndDiscoveryCompleteProtectionKeyValue, _ := ctx.Value(muxAndDiscoveryIncompleteKey).(string)
    return len(muxAndDiscoveryCompleteProtectionKeyValue) == 0
}

// WithMuxAndDiscoveryComplete 如果请求在 muxAndDiscoveryCompleteSignal 准备好之前已经被发出，则将 muxAndDiscoveryIncompleteKey 放入上下文中。
// 放入该键可以防止返回 404 响应而不是 503。
// 这对于像 GC 和 NS 这样的控制器尤为重要，因为它们对 404 做出反应。
//
// 该键的存在在 NotFoundHandler 中进行了检查 (staging/src/k8s.io/apiserver/pkg/util/notfoundhandler/not_found_handler.go)。
//
// 该过滤器存在的主要原因是为了保护客户端请求在达到 NotFoundHandler 之前和服务器变为就绪之间的潜在竞争。
// 如果没有保护键，当注册的信号状态在到达新的处理程序之前略微更改时，请求仍可能得到 404 响应。
// 在这种情况下，保护键的存在将使处理程序返回 503 而不是 404。
func WithMuxAndDiscoveryComplete(handler http.Handler, muxAndDiscoveryCompleteSignal <-chan struct{}) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        if muxAndDiscoveryCompleteSignal != nil && !isClosed(muxAndDiscoveryCompleteSignal) {
            // 将 muxAndDiscoveryIncompleteKey 放入请求的上下文中
            req = req.WithContext(context.WithValue(req.Context(), muxAndDiscoveryIncompleteKey, "MuxAndDiscoveryInstallationNotComplete"))
        }
        handler.ServeHTTP(w, req)
    })
}

// isClosed 是一个方便的函数，用于检查给定的通道是否已关闭
func isClosed(ch <-chan struct{}) bool {
    select {
    case <-ch:
    	return true
    default:
    	return false
    }
}
```

## WithPanicRecovery

```GO
// WithPanicRecovery函数包装一个http Handler以捕获和记录panic（除了特殊情况下的http.ErrAbortHandler panic，该情况下会禁止记录日志）。
func WithPanicRecovery(handler http.Handler, resolver request.RequestInfoResolver) http.Handler {
    return withPanicRecovery(handler, func(w http.ResponseWriter, req *http.Request, err interface{}) {
        if err == http.ErrAbortHandler {
            // 尊重http.ErrAbortHandler特殊值的panic
            //
            // 如果ServeHTTP发生panic，服务器（调用ServeHTTP的调用者）假设panic的影响仅限于当前请求。
            // 它会恢复panic，记录堆栈跟踪到服务器错误日志，并根据HTTP协议关闭网络连接或发送HTTP/2的RST_STREAM。
            // 要中止处理程序以使客户端看到中断的响应但服务器不记录错误，可以panic并使用ErrAbortHandler值。
            //
            // 注意，HandleCrash函数实际上是崩溃的，在调用处理程序之后。
            if info, err := resolver.NewRequestInfo(req); err != nil {
                metrics.RecordRequestAbort(req, nil)
            } else {
                metrics.RecordRequestAbort(req, info)
            }
            // 这个调用可以有不同的处理程序，但默认链路限制。
            // 在更新了度量信息之后调用，以防止链路限制延迟它。
            // 如果超过了此超时请求的速率限制，表示服务器发生了严重错误，但通常为超时设置一个日志信号是有用的。
            runtime.HandleError(fmt.Errorf("timeout or abort while handling: method=%v URI=%q audit-ID=%q", req.Method, req.RequestURI, audit.GetAuditIDTruncated(req.Context())))
            return
        }
        http.Error(w, "This request caused apiserver to panic. Look in the logs for details.", http.StatusInternalServerError)
        klog.ErrorS(nil, "apiserver panic'd", "method", req.Method, "URI", req.RequestURI, "auditID", audit.GetAuditIDTruncated(req.Context()))
    })
}

// WithHTTPLogging函数启用对传入请求的日志记录。
func WithHTTPLogging(handler http.Handler) http.Handler {
	return httplog.WithLogging(handler, httplog.DefaultStacktracePred)
}

func withPanicRecovery(handler http.Handler, crashHandler func(http.ResponseWriter, *http.Request, interface{})) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        defer runtime.HandleCrash(func(err interface{}) {
            crashHandler(w, req, err)
        })

        // 分派到内部处理程序
        handler.ServeHTTP(w, req)
    })
}
```

## WithAuditInit

```GO
// WithAuditInit函数用于初始化审计上下文并附加与请求关联的Audit-ID。
//
// a. 如果调用者在请求头中未指定Audit-ID的值，则生成一个新的Audit ID。
// b. 我们通过响应头'Audit-ID'将Audit-ID的值回显给调用者。
func WithAuditInit(handler http.Handler) http.Handler {
    return withAuditInit(handler, func() string {
    	return uuid.New().String()
    })
}

func withAuditInit(handler http.Handler, newAuditIDFunc func() string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 获取带有审计上下文的上下文对象
        ctx := audit.WithAuditContext(r.Context())
        r = r.WithContext(ctx)

        // 获取请求头中的Audit-ID值
        auditID := r.Header.Get(auditinternal.HeaderAuditID)
        if len(auditID) == 0 {
            // 如果没有指定Audit-ID值，则调用提供的函数生成一个新的Audit ID
            auditID = newAuditIDFunc()
        }

        // 注意：我们将用户指定的Audit-ID头的值保存原样，不进行截断。
        // 将Audit-ID值设置到上下文中
        audit.WithAuditID(ctx, types.UID(auditID))

        // 将Audit-ID回显到响应头中。
        // 并不是所有请求都会发送Audit-ID http头。
        // 例如，当用户运行"kubectl exec"时，apiserver会使用代理处理程序处理请求，用户只能获取kubelet节点返回的http头。
        //
        // 这个过滤器也将被其他聚合API服务器使用。对于聚合API，
        // 我们不希望同一个Audit ID出现多次。
        if value := w.Header().Get(auditinternal.HeaderAuditID); len(value) == 0 {
            w.Header().Set(auditinternal.HeaderAuditID, auditID)
        }

        // 调用传入的处理程序来处理请求
        handler.ServeHTTP(w, r)
    })
}
```

