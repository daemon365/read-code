
## Proxier

```go
// Proxier是基于ipvs的代理，用于本地主机（localhost:lport）和提供实际后端的服务之间的连接。

type Proxier struct {
    // 运行此代理的IP地址族（ipfamily）。
    ipFamily v1.IPFamily
	// endpointsChanges和serviceChanges包含自上次调用syncProxyRules以来发生的所有端点和服务更改。
    // 对于单个对象，更改是累积的，即previous是应用所有更改之前的状态，current是应用所有更改后的状态。
    endpointsChanges *proxy.EndpointChangeTracker
    serviceChanges   *proxy.ServiceChangeTracker

    mu           sync.Mutex // 保护以下字段
    svcPortMap   proxy.ServicePortMap
    endpointsMap proxy.EndpointsMap
    nodeLabels   map[string]string

    // initialSync是一个布尔值，指示proxier是否第一次进行同步。
    // 在初始化新的proxier时设置为true，然后在所有未来的同步中设置为false。
    // 这允许我们仅在代理启动期间运行特定的逻辑。
    // 例如：它使我们能够仅在启动时更新现有目标的权重，从而节省了在每次同步期间查询和更新真实服务器的成本。
    initialSync bool

    // 在启动后，当相应的对象同步时，将endpointSlicesSynced和servicesSynced设置为true。
    // 这用于避免在kube-proxy重启后使用某些部分数据更新ipvs规则。
    endpointSlicesSynced bool
    servicesSynced       bool

    initialized int32
    syncRunner  *async.BoundedFrequencyRunner // 控制对syncProxyRules的调用

    // 这些实际上是常量，不需要持有互斥锁。
    syncPeriod    time.Duration
    minSyncPeriod time.Duration

    // 要在清理IPVS规则时排除的CIDR列表。
    excludeCIDRs []*net.IPNet

    // 设置为true以设置sysctls的arp_ignore和arp_announce。
    strictARP bool

    iptables utiliptables.Interface
    ipvs     utilipvs.Interface
    ipset    utilipset.Interface
    exec     utilexec.Interface

    masqueradeAll  bool
    masqueradeMark string
    localDetector  proxyutiliptables.LocalTrafficDetector
    hostname       string
    nodeIP         net.IP
    recorder       events.EventRecorder

    serviceHealthServer healthcheck.ServiceHealthServer
    healthzServer       healthcheck.ProxierHealthUpdater

    ipvsScheduler string

    // 以下缓冲区用于重用内存并避免对性能产生重大影响的分配。
    iptablesData     *bytes.Buffer
    filterChainsData *bytes.Buffer
    natChains        proxyutil.LineBuffer
    filterChains     proxyutil.LineBuffer
    natRules         proxyutil.LineBuffer
    filterRules      proxyutil.LineBuffer

    // 添加为结构体的成员，以允许进行测试时的注入。
    netlinkHandle NetLinkHandle

    // ipsetList是ipvs proxier使用的ipset列表。
    ipsetList map[string]*IPSet

    // nodePortAddresses选择nodePort工作的接口。
    nodePortAddresses *proxyutil.NodePortAddresses

    // networkInterfacer定义了几个网络库函数的接口。
    // 用于测试目的注入。
    networkInterfacer proxyutil.NetworkInterfacer

    gracefuldeleteManager *GracefulTerminationManager

    // serviceNoLocalEndpointsInternal表示由于"Local"内部流量策略时缺少本地端点而无法应用的服务集合。
    // 它用于发布带有traffic_policy标签设置为"internal"的sync_proxy_rules_no_endpoints_total指标。
    // 在这里使用Set是因为我们为相同的Service多次计算端点拓扑，
    // 如果一个Service有多个端口，每个Service只应计数一次。
    serviceNoLocalEndpointsInternal sets.Set[string]

    // serviceNoLocalEndpointsExternal表示由于缺少任何端点而无法应用的服务集合，当外部流量策略为"Local"时。
    // 它用于发布带有traffic_policy标签设置为"external"的sync_proxy_rules_no_endpoints_total指标。
    // 在这里使用Set是因为我们为相同的Service多次计算端点拓扑，
    // 如果一个Service有多个端口，每个Service只应计数一次。
    serviceNoLocalEndpointsExternal sets.Set[string]
}

// Proxier实现了proxy.Provider接口。
var _ proxy.Provider = &Proxier{}
```

### NetLinkHandle

```GO
// NetLinkHandle 是用于撤销 netlink 接口的类型。
type NetLinkHandle interface {
	// EnsureAddressBind 检查地址是否绑定到接口上，如果没有绑定，则进行绑定。如果地址已经绑定，则返回 true。
	EnsureAddressBind(address, devName string) (exist bool, err error)
	// UnbindAddress 从接口上解绑地址。
	UnbindAddress(address, devName string) error
	// EnsureDummyDevice 检查虚拟设备是否存在，如果不存在，则创建一个。如果虚拟设备已经存在，则返回 true。
	EnsureDummyDevice(devName string) (exist bool, err error)
	// DeleteDummyDevice 根据名称删除给定的虚拟设备。
	DeleteDummyDevice(devName string) error
	// ListBindAddress 列出绑定在给定接口上的所有 IP 地址。
	ListBindAddress(devName string) ([]string, error)
	// GetAllLocalAddresses 返回节点上的所有本地地址。
	// 仅返回当前地址族的地址。
	// IPv6 的链路本地地址和环回地址被排除在外。
	GetAllLocalAddresses() (sets.Set[string], error)
	// GetLocalAddresses 返回给定接口的所有本地地址。
	// 仅返回当前地址族的地址。
	// IPv6 的链路本地地址和环回地址被排除在外。
	GetLocalAddresses(dev string) (sets.Set[string], error)
	// GetAllLocalAddressesExcept 返回节点上的所有本地地址，但排除传入的接口。
	// 这与取 GetAllLocalAddresses 和 GetLocalAddresses 的差集不同，
	// 因为一个地址可能分配给多个接口。此问题引发了
	// https://github.com/kubernetes/kubernetes/issues/114815
	GetAllLocalAddressesExcept(dev string) (sets.Set[string], error)
}
type netlinkHandle struct {
    netlink.Handle
    isIPv6 bool
}

// netlinkHandle 结构体定义了一个具有 netlink.Handle 嵌入字段和 isIPv6 字段的类型。
// NewNetLinkHandle 函数用于创建一个新的 NetLinkHandle。
func NewNetLinkHandle(isIPv6 bool) NetLinkHandle {
	return &netlinkHandle{netlink.Handle{}, isIPv6}
}

// EnsureAddressBind 函数用于检查地址是否绑定到接口上，如果没有，则进行绑定。如果地址已绑定，则返回 true。
func (h *netlinkHandle) EnsureAddressBind(address, devName string) (exist bool, err error) {
    // 通过接口名称获取接口对象
    dev, err := h.LinkByName(devName)
    if err != nil {
    	return false, fmt.Errorf("error get interface: %s, err: %v", devName, err)
    }
    // 解析 IP 地址
    addr := netutils.ParseIPSloppy(address)
    if addr == nil {
    	return false, fmt.Errorf("error parse ip address: %s", address)
    }
    // 将地址添加到接口上
    if err := h.AddrAdd(dev, &netlink.Addr{IPNet: netlink.NewIPNet(addr)}); err != nil {
   		// 如果错误码是 "EEXIST"，表示地址已经绑定到设备上
        if err == unix.EEXIST {
        	return true, nil
        }
        return false, fmt.Errorf("error bind address: %s to interface: %s, err: %v", address, devName, err)
    }
    return false, nil
}

// UnbindAddress 函数用于确保 IP 地址从网络接口上解绑。
func (h *netlinkHandle) UnbindAddress(address, devName string) error {
    // 通过接口名称获取接口对象
    dev, err := h.LinkByName(devName)
    if err != nil {
    	return fmt.Errorf("error get interface: %s, err: %v", devName, err)
    }
    // 解析 IP 地址
    addr := netutils.ParseIPSloppy(address)
    if addr == nil {
    	return fmt.Errorf("error parse ip address: %s", address)
    }
    // 从接口上删除地址
    if err := h.AddrDel(dev, &netlink.Addr{IPNet: netlink.NewIPNet(addr)}); err != nil {
        if err != unix.ENXIO {
        	return fmt.Errorf("error unbind address: %s from interface: %s, err: %v", address, devName, err)
        }
    }
    return nil
}


2 / 2

type netlinkHandle struct {
netlink.Handle
isIPv6 bool
}

// netlinkHandle 结构体定义了一个具有 netlink.Handle 嵌入字段和 isIPv6 字段的类型。

// NewNetLinkHandle 函数用于创建一个新的 NetLinkHandle。
func NewNetLinkHandle(isIPv6 bool) NetLinkHandle {
return &netlinkHandle{netlink.Handle{}, isIPv6}
}

// EnsureAddressBind 函数用于检查地址是否绑定到接口上，如果没有，则进行绑定。如果地址已绑定，则返回 true。
func (h *netlinkHandle) EnsureAddressBind(address, devName string) (exist bool, err error) {
// 通过接口名称获取接口对象
dev, err := h.LinkByName(devName)
if err != nil {
return false, fmt.Errorf("error get interface: %s, err: %v", devName, err)
}
// 解析 IP 地址
addr := netutils.ParseIPSloppy(address)
if addr == nil {
return false, fmt.Errorf("error parse ip address: %s", address)
}
// 将地址添加到接口上
if err := h.AddrAdd(dev, &netlink.Addr{IPNet: netlink.NewIPNet(addr)}); err != nil {
// 如果错误码是 "EEXIST"，表示地址已经绑定到设备上
if err == unix.EEXIST {
return true, nil
}
return false, fmt.Errorf("error bind address: %s to interface: %s, err: %v", address, devName, err)
}
return false, nil
}

// UnbindAddress 函数用于确保 IP 地址从网络接口上解绑。
func (h *netlinkHandle) UnbindAddress(address, devName string) error {
// 通过接口名称获取接口对象
dev, err := h.LinkByName(devName)
if err != nil {
return fmt.Errorf("error get interface: %s, err: %v", devName, err)
}
// 解析 IP 地址
addr := netutils.ParseIPSloppy(address)
if addr == nil {
return fmt.Errorf("error parse ip address: %s", address)
}
// 从接口上删除地址
if err := h.AddrDel(dev, &netlink.Addr{IPNet: netlink.NewIPNet(addr)}); err != nil {
if err != unix.ENXIO {
return fmt.Errorf("error unbind address: %s from interface: %s, err: %v", address, devName, err)
}
}
return nil
}

// EnsureDummyDevice 函数用于确保虚拟设备存在。
func (h *netlinkHandle) EnsureDummyDevice(devName string) (bool, error) {
    _, err := h.LinkByName(devName)
    if err == nil {
        // 找到虚拟设备
        return true, nil
    }
    dummy := &netlink.Dummy{
    	LinkAttrs: netlink.LinkAttrs{Name: devName},
    }
    return false, h.LinkAdd(dummy)
}

// DeleteDummyDevice 函数用于删除虚拟设备。
func (h *netlinkHandle) DeleteDummyDevice(devName string) error {
    link, err := h.LinkByName(devName)
    if err != nil {
        _, ok := err.(netlink.LinkNotFoundError)
        if ok {
            return nil
        }
        return fmt.Errorf("error deleting a non-exist dummy device: %s, %v", devName, err)
    }
    dummy, ok := link.(*netlink.Dummy)
    if !ok {
    	return fmt.Errorf("expect dummy device, got device type: %s", link.Type())
    }
    return h.LinkDel(dummy)
}

// ListBindAddress 函数用于列出绑定在给定接口上的所有 IP 地址。
func (h *netlinkHandle) ListBindAddress(devName string) ([]string, error) {
    // 通过接口名称获取接口对象
    dev, err := h.LinkByName(devName)
    if err != nil {
    	return nil, fmt.Errorf("error get interface: %s, err: %v", devName, err)
    }
    // 列出接口上绑定的所有地址
    addrs, err := h.AddrList(dev, 0)
    if err != nil {
    	return nil, fmt.Errorf("error list bound address of interface: %s, err: %v", devName, err)
    }
    var ips []string
    for _, addr := range addrs {
    	ips = append(ips, addr.IP.String())
    }
    return ips, nil
}

// GetAllLocalAddresses 函数返回节点上的所有本地地址。
// 只返回当前地址族的地址。
// 排除 IPv6 链路本地地址和环回地址。
func (h *netlinkHandle) GetAllLocalAddresses() (sets.Set[string], error) {
    addr, err := net.InterfaceAddrs()
    if err != nil {
    	return nil, fmt.Errorf("Could not get addresses: %v", err)
    }
    return proxyutil.AddressSet(h.isValidForSet, addr), nil
}

// GetLocalAddresses 函数返回指定接口的所有本地地址。
// 只返回当前地址族的地址。
// 排除 IPv6 链路本地地址和环回地址。
func (h *netlinkHandle) GetLocalAddresses(dev string) (sets.Set[string], error) {
ifi, err := net.InterfaceByName(dev)
    if err != nil {
    	return nil, fmt.Errorf("Could not get interface %s: %v", dev, err)
    }
    addr, err := ifi.Addrs()
        if err != nil {
        	return nil, fmt.Errorf("Can't get addresses from %s: %v", ifi.Name, err)
        }
    	return proxyutil.AddressSet(h.isValidForSet, addr), nil
    }

    func (h *netlinkHandle) isValidForSet(ip net.IP) bool {
    if h.isIPv6 != netutils.IsIPv6(ip) {
    	return false
    }
    if h.isIPv6 && ip.IsLinkLocalUnicast() {
    	return false
    }
    if ip.IsLoopback() {
   		return false
    }
    return true
}

// GetAllLocalAddressesExcept 函数返回节点上除指定接口之外的所有本地地址。
// 这与获取 GetAllLocalAddresses 和 GetLocalAddresses 的差集不同，因为一个地址可以分配给多个接口。
// 这个问题引发了 https://github.com/kubernetes/kubernetes/issues/114815
func (h *netlinkHandle) GetAllLocalAddressesExcept(dev string) (sets.Set[string], error) {
    ifaces, err := net.Interfaces()
    if err != nil {
    	return nil, err
    }
    var addr []net.Addr
    for _, iface := range ifaces {
        if iface.Name == dev {
        	continue
        }
        ifadr, err := iface.Addrs()
        if err != nil {
            // 如果接口已被删除，可能会发生此错误。忽略错误，但记录错误日志。
            klog.ErrorS(err, "Reading addresses", "interface", iface.Name)
            continue
        }
    	addr = append(addr, ifadr...)
    }
    return proxyutil.AddressSet(h.isValidForSet, addr), nil
}

```

### IPSet

```GO
const (
	MinIPSetCheckVersion = "6.0"  // 定义了最小的 ipset 版本号，需要满足 IPv6 在 ipset 6.x 中支持。

	kubeLoopBackIPSetComment = "Kubernetes endpoints dst ip:port, source ip for solving hairpin purpose"  // 定义了一个注释，描述了 kubeLoopBackIPSet 的用途。
	kubeLoopBackIPSet        = "KUBE-LOOP-BACK"  // 定义了一个常量 kubeLoopBackIPSet，表示 Kubernetes 的端点目标 IP:端口，用于解决 hairpin 目的。

	kubeClusterIPSetComment = "Kubernetes service cluster ip + port for masquerade purpose"  // 定义了一个注释，描述了 kubeClusterIPSet 的用途。
	kubeClusterIPSet        = "KUBE-CLUSTER-IP"  // 定义了一个常量 kubeClusterIPSet，表示 Kubernetes 服务的集群 IP + 端口，用于伪装。

	kubeExternalIPSetComment = "Kubernetes service external ip + port for masquerade and filter purpose"  // 定义了一个注释，描述了 kubeExternalIPSet 的用途。
	kubeExternalIPSet        = "KUBE-EXTERNAL-IP"  // 定义了一个常量 kubeExternalIPSet，表示 Kubernetes 服务的外部 IP + 端口，用于伪装和过滤。

	kubeExternalIPLocalSetComment = "Kubernetes service external ip + port with externalTrafficPolicy=local"  // 定义了一个注释，描述了 kubeExternalIPLocalSet 的用途。
	kubeExternalIPLocalSet        = "KUBE-EXTERNAL-IP-LOCAL"  // 定义了一个常量 kubeExternalIPLocalSet，表示带有 externalTrafficPolicy=local 的 Kubernetes 服务的外部 IP + 端口。

	kubeLoadBalancerSetComment = "Kubernetes service lb portal"  // 定义了一个注释，描述了 kubeLoadBalancerSet 的用途。
	kubeLoadBalancerSet        = "KUBE-LOAD-BALANCER"  // 定义了一个常量 kubeLoadBalancerSet，表示 Kubernetes 服务的负载均衡器 portal。

	kubeLoadBalancerLocalSetComment = "Kubernetes service load balancer ip + port with externalTrafficPolicy=local"  // 定义了一个注释，描述了 kubeLoadBalancerLocalSet 的用途。
	kubeLoadBalancerLocalSet        = "KUBE-LOAD-BALANCER-LOCAL"  // 定义了一个常量 kubeLoadBalancerLocalSet，表示带有 externalTrafficPolicy=local 的 Kubernetes 服务的负载均衡器 IP + 端口。

	kubeLoadBalancerFWSetComment = "Kubernetes service load balancer ip + port for load balancer with sourceRange"  // 定义了一个注释，描述了 kubeLoadBalancerFWSet 的用途。
	kubeLoadBalancerFWSet        = "KUBE-LOAD-BALANCER-FW"  // 定义了一个常量 kubeLoadBalancerFWSet，表示带有 sourceRange 的 Kubernetes 服务的负载均衡器 IP + 端口。

	kubeLoadBalancerSourceIPSetComment = "Kubernetes service load balancer ip + port + source IP for packet filter purpose"  // 定义了一个注释，描述了 kubeLoadBalancerSourceIPSet 的用途。
	kubeLoadBalancerSourceIPSet        = "KUBE-LOAD-BALANCER-SOURCE-IP"  // 定义了一个常量 kubeLoadBalancerSourceIPSet，表示用于数据包过滤目的的 Kubernetes 服务负载均衡器 IP + 端口 + 源 IP。

	kubeLoadBalancerSourceCIDRSetComment = "Kubernetes service load balancer ip + port + source cidr for packet filter purpose"  // 定义了一个注释，描述了 kubeLoadBalancerSourceCIDRSet 的用途。
	kubeLoadBalancerSourceCIDRSet        = "KUBE-LOAD-BALANCER-SOURCE-CIDR"  // 定义了一个常量 kubeLoadBalancerSourceCIDRSet，表示用于数据包过滤目的的 Kubernetes 服务负载均衡器 IP + 端口 + 源 CIDR。

	kubeNodePortSetTCPComment = "Kubernetes nodeport TCP port for masquerade purpose"  // 定义了一个注释，描述了 kubeNodePortSetTCP 的用途。
	kubeNodePortSetTCP        = "KUBE-NODE-PORT-TCP"  // 定义了一个常量 kubeNodePortSetTCP，表示用于伪装目的的 Kubernetes NodePort 的 TCP 端口。

	kubeNodePortLocalSetTCPComment = "Kubernetes nodeport TCP port with externalTrafficPolicy=local"  // 定义了一个注释，描述了 kubeNodePortLocalSetTCP 的用途。
	kubeNodePortLocalSetTCP        = "KUBE-NODE-PORT-LOCAL-TCP"  // 定义了一个常量 kubeNodePortLocalSetTCP，表示带有 externalTrafficPolicy=local 的 Kubernetes NodePort 的 TCP 端口。

	kubeNodePortSetUDPComment = "Kubernetes nodeport UDP port for masquerade purpose"  // 定义了一个注释，描述了 kubeNodePortSetUDP 的用途。
	kubeNodePortSetUDP        = "KUBE-NODE-PORT-UDP"  // 定义了一个常量 kubeNodePortSetUDP，表示用于伪装目的的 Kubernetes NodePort 的 UDP 端口。

	kubeNodePortLocalSetUDPComment = "Kubernetes nodeport UDP port with externalTrafficPolicy=local"  // 定义了一个注释，描述了 kubeNodePortLocalSetUDP 的用途。
	kubeNodePortLocalSetUDP        = "KUBE-NODE-PORT-LOCAL-UDP"  // 定义了一个常量 kubeNodePortLocalSetUDP，表示带有 externalTrafficPolicy=local 的 Kubernetes NodePort 的 UDP 端口。

	kubeNodePortSetSCTPComment = "Kubernetes nodeport SCTP port for masquerade purpose with type 'hash ip:port'"  // 定义了一个注释，描述了 kubeNodePortSetSCTP 的用途。
	kubeNodePortSetSCTP        = "KUBE-NODE-PORT-SCTP-HASH"  // 定义了一个常量 kubeNodePortSetSCTP，表示用于伪装目的的类型为 'hash ip:port' 的 Kubernetes NodePort 的 SCTP 端口。

	kubeNodePortLocalSetSCTPComment = "Kubernetes nodeport SCTP port with externalTrafficPolicy=local with type 'hash ip:port'"  // 定义了一个注释，描述了 kubeNodePortLocalSetSCTP 的用途。
	kubeNodePortLocalSetSCTP        = "KUBE-NODE-PORT-LOCAL-SCTP-HASH"  // 定义了一个常量 kubeNodePortLocalSetSCTP，表示带有 externalTrafficPolicy=local 且类型为 'hash ip:port' 的 Kubernetes NodePort 的 SCTP 端口。

	kubeHealthCheckNodePortSetComment = "Kubernetes health check node port"  // 定义了一个注释，描述了 kubeHealthCheckNodePortSet 的用途。
	kubeHealthCheckNodePortSet        = "KUBE-HEALTH-CHECK-NODE-PORT"  // 定义了一个常量 kubeHealthCheckNodePortSet，表示 Kubernetes 健康检查节点端口。

	kubeIPVSSetComment = "Addresses on the ipvs interface"  // 定义了一个注释，描述了 kubeIPVSSet 的用途。
	kubeIPVSSet        = "KUBE-IPVS-IPS"  // 定义了一个常量 kubeIPVSSet，表示 ipvs 接口上的地址。

)

// IPSetVersioner can query the current ipset version.
type IPSetVersioner interface {
	// returns "X.Y"
	GetVersion() (string, error)
}

// IPSet wraps util/ipset which is used by IPVS proxier.
type IPSet struct {
	utilipset.IPSet
	// activeEntries is the current active entries of the ipset.
	activeEntries sets.Set[string]
	// handle is the util ipset interface handle.
	handle utilipset.Interface
}

// NewIPSet initialize a new IPSet struct
func NewIPSet(handle utilipset.Interface, name string, setType utilipset.Type, isIPv6 bool, comment string) *IPSet {
	hashFamily := utilipset.ProtocolFamilyIPV4
	if isIPv6 {
		hashFamily = utilipset.ProtocolFamilyIPV6
		// In dual-stack both ipv4 and ipv6 ipset's can co-exist. To
		// ensure unique names the prefix for ipv6 is changed from
		// "KUBE-" to "KUBE-6-". The "KUBE-" prefix is kept for
		// backward compatibility. The maximum name length of an ipset
		// is 31 characters which must be taken into account.  The
		// ipv4 names are not altered to minimize the risk for
		// problems on upgrades.
		if strings.HasPrefix(name, "KUBE-") {  // 如果 name 以 "KUBE-" 开头
			name = strings.Replace(name, "KUBE-", "KUBE-6-", 1)  // 将 name 中的 "KUBE-" 替换为 "KUBE-6-"
			if len(name) > 31 {  // 如果替换后的 name 的长度大于 31
				klog.InfoS("Ipset name truncated", "ipSetName", name, "truncatedName", name[:31])  // 输出日志，表示 ipset 名称已被截断
				name = name[:31]  // 将 name 截断为 31 个字符
			}
		}
	}
	set := &IPSet{
		IPSet:  *utilipset.NewIPSet(handle, name, setType, hashFamily, comment),  // 创建一个 utilipset.IPSet 实例
		handle: handle,
	}
	return set
}

// GetVersion returns the version of the ipset.
func (s *IPSet) GetVersion() (string, error) {
	return s.handle.GetVersion()
}

// AddEntry adds an entry to the ipset.
func (s *IPSet) AddEntry(entry string) error {
	err := s.IPSet.Add(entry)
	if err != nil {
		return fmt.Errorf("failed to add entry %s to ipset %s: %v", entry, s.Name(), err)
	}
	s.activeEntries.Insert(entry)  // 将 entry 添加到 activeEntries 中
	return nil
}

// DelEntry deletes an entry from the ipset.
func (s *IPSet) DelEntry(entry string) error {
	err := s.IPSet.Del(entry)
	if err != nil {
		return fmt.Errorf("failed to delete entry %s from ipset %s: %v", entry, s.Name(), err)
	}
	s.activeEntries.Delete(entry)  // 从 activeEntries 中删除 entry
	return nil
}

// ListEntries lists the current entries in the ipset.
func (s *IPSet) ListEntries() (sets.String, error) {
	entries, err := s.IPSet.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list entries in ipset %s: %v", s.Name(), err)
	}
	return sets.NewString(entries...), nil  // 返回 entries 的 String 集合
}

// FlushEntries flushes all entries in the ipset.
func (s *IPSet) FlushEntries() error {
	err := s.IPSet.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush entries in ipset %s: %v", s.Name(), err)
	}
	s.activeEntries = sets.NewString()  // 清空 activeEntries
	return nil
}
```



```GO
const (
	rsCheckDeleteInterval = 1 * time.Minute
)

// rsCheckDeleteInterval 定义了一个常量，表示检查并删除 RS 的时间间隔。
// listItem 存储真实服务器的信息和处理时间。
// 如果没有特殊情况发生，处理时间过后将删除真实服务器。
type listItem struct {
    VirtualServer *utilipvs.VirtualServer
    RealServer *utilipvs.RealServer
}

// String 返回唯一的真实服务器名称（带有虚拟服务器信息）
func (g *listItem) String() string {
	return GetUniqueRSName(g.VirtualServer, g.RealServer)
}

// GetUniqueRSName 返回一个带有 VS 信息的唯一 RS 名称字符串
func GetUniqueRSName(vs *utilipvs.VirtualServer, rs *utilipvs.RealServer) string {
	return vs.String() + "/" + rs.String()
}

type graceTerminateRSList struct {
    lock sync.Mutex
	list map[string]*listItem
}

// add 将一个新元素推送到 rsList 中
func (q *graceTerminateRSList) add(rs *listItem) bool {
    q.lock.Lock()
    defer q.lock.Unlock()
    uniqueRS := rs.String()
    if _, ok := q.list[uniqueRS]; ok {
        return false
    }

    klog.V(5).InfoS("Adding real server to graceful delete real server list", "realServer", rs)
    q.list[uniqueRS] = rs
    return true
}

// remove 从 rsList 中删除一个元素
func (q *graceTerminateRSList) remove(rs *listItem) bool {
    q.lock.Lock()
    defer q.lock.Unlock()

    uniqueRS := rs.String()
    if _, ok := q.list[uniqueRS]; ok {
        delete(q.list, uniqueRS)
        return true
    }
    return false
}

// len 返回列表的大小
func (q *graceTerminateRSList) len() int {
    q.lock.Lock()
    defer q.lock.Unlock()

    return len(q.list)
}

func (q *graceTerminateRSList) flushList(handler func(rsToDelete *listItem) (bool, error)) bool {
    q.lock.Lock()
    defer q.lock.Unlock()
    success := true
    for name, rs := range q.list {
        deleted, err := handler(rs)
        if err != nil {
            klog.ErrorS(err, "Error in deleting real server", "realServer", name)
            success = false
        }
        if deleted {
            klog.InfoS("Removed real server from graceful delete real server list", "realServer", name)
            delete(q.list, rs.String())
        }
   }
   return success
}

    // exist 检查指定的唯一 RS 是否在 rsList 中
func (q *graceTerminateRSList) exist(uniqueRS string) (*listItem, bool) {
    q.lock.Lock()
    defer q.lock.Unlock()


    if rs, ok := q.list[uniqueRS]; ok {
        return rs, true
    }
    return nil, false
}

// GracefulTerminationManager 管理 RS 优雅终止信息并执行优雅终止工作
// rsList 是需要进行优雅终止的 RS 列表，ipvs 是用于进行 IPVS 删除/更新工作的 ipvsinterface
type GracefulTerminationManager struct {
    rsList graceTerminateRSList
    ipvs utilipvs.Interface
}

// NewGracefulTerminationManager 创建一个GracefulTerminationManager来管理ipvs rs的优雅终止工作
func NewGracefulTerminationManager(ipvs utilipvs.Interface) *GracefulTerminationManager {
    l := make(map[string]*listItem)
    return &GracefulTerminationManager{
        rsList: graceTerminateRSList{
        	list: l,
    	},
    	ipvs: ipvs,
    }
}

// InTerminationList 检查指定的唯一rs名称是否在优雅终止列表中
func (m *GracefulTerminationManager) InTerminationList(uniqueRS string) bool {
    _, exist := m.rsList.exist(uniqueRS)
    return exist
}

// GracefulDeleteRS 将rs的权重更新为0，并将rs添加到优雅终止列表中
func (m *GracefulTerminationManager) GracefulDeleteRS(vs *utilipvs.VirtualServer, rs *utilipvs.RealServer) error {
    // 在将rs添加到优雅删除列表之前尝试删除rs
    ele := &listItem{
        VirtualServer: vs,
        RealServer: rs,
    }
    deleted, err := m.deleteRsFunc(ele)
    if err != nil {
    	klog.ErrorS(err, "删除真实服务器时出错", "realServer", ele)
    }
    if deleted {
    	return nil
    }
    rs.Weight = 0
    err = m.ipvs.UpdateRealServer(vs, rs)
    if err != nil {
    	return err
    }
    klog.V(5).InfoS("将真实服务器添加到优雅删除真实服务器列表中", "realServer", ele)
    m.rsList.add(ele)
    return nil
}

func (m *GracefulTerminationManager) deleteRsFunc(rsToDelete *listItem) (bool, error) {
klog.V(5).InfoS("尝试删除真实服务器", "realServer", rsToDelete)
    rss, err := m.ipvs.GetRealServers(rsToDelete.VirtualServer)
    if err != nil {
    	return false, err
    }
    for _, rs := range rss {
        if rsToDelete.RealServer.Equal(rs) {
            // 对于UDP和SCTP流量，不进行优雅终止，我们立即删除RS
            // （现有连接将在下一个数据包上删除，因为sysctlExpireNoDestConn=1）
            // 对于其他协议，直到所有连接过期才进行删除）
            if utilipvs.IsRsGracefulTerminationNeeded(rsToDelete.VirtualServer.Protocol) && rs.ActiveConn+rs.InactiveConn != 0 {
                klog.V(5).InfoS("跳过删除真实服务器，直到所有连接都过期", "realServer", rsToDelete, "activeConnection", rs.ActiveConn, "inactiveConnection", rs.InactiveConn)
                return false, nil
            }
            klog.V(5).InfoS("删除真实服务器", "realServer", rsToDelete)
            err := m.ipvs.DeleteRealServer(rsToDelete.VirtualServer, rs)
            if err != nil {
            	return false, fmt.Errorf("删除目标 %q 出错: %w", rs.String(), err)
            }
            return true, nil
        }
    }
	return true, fmt.Errorf("无法删除rs %q，找不到真实服务器", rsToDelete.String())
}

func (m *GracefulTerminationManager) tryDeleteRs() {
    if !m.rsList.flushList(m.deleteRsFunc) {
    	klog.ErrorS(nil, "尝试刷新优雅终止列表时出错")
    }
}

// MoveRSOutofGracefulDeleteList 删除一个rs并立即从rsList中移除它
func (m *GracefulTerminationManager) MoveRSOutofGracefulDeleteList(uniqueRS string) error {
rsToDelete, find := m.rsList.exist(uniqueRS)
    if !find || rsToDelete == nil {
    	return fmt.Errorf("未找到rs：%q", uniqueRS)
    }
    err := m.ipvs.DeleteRealServer(rsToDelete.VirtualServer, rsToDelete.RealServer)
    if err != nil {
    	return err
    }
    m.rsList.remove(rsToDelete)
    return nil
}

// Run 启动一个goroutine，以每1分钟的间隔尝试删除优雅删除rsList中的rs
func (m *GracefulTerminationManager) Run() {
	go wait.Until(m.tryDeleteRs, rsCheckDeleteInterval, wait.NeverStop)
}
```

### util.Interface

```GO
// Interface 是可注入的用于运行 ipvs 命令的接口。实现必须支持并发安全。
type Interface interface {
    // Flush 清除系统中的所有虚拟服务器。立即返回发生的错误。
    Flush() error
    // AddVirtualServer 创建指定的虚拟服务器。
    AddVirtualServer(*VirtualServer) error
    // UpdateVirtualServer 更新已存在的虚拟服务器。如果虚拟服务器不存在，返回错误。
    UpdateVirtualServer(*VirtualServer) error
    // DeleteVirtualServer 删除指定的虚拟服务器。如果虚拟服务器不存在，返回错误。
    DeleteVirtualServer(*VirtualServer) error
    // GetVirtualServer 根据部分虚拟服务器信息，在系统中获取指定的虚拟服务器信息。
    GetVirtualServer(*VirtualServer) (*VirtualServer, error)
    // GetVirtualServers 列出系统中的所有虚拟服务器。
    GetVirtualServers() ([]*VirtualServer, error)
    // AddRealServer 为指定的虚拟服务器创建指定的真实服务器。
    AddRealServer(*VirtualServer, *RealServer) error
    // GetRealServers 返回指定虚拟服务器的所有真实服务器。
    GetRealServers(*VirtualServer) ([]*RealServer, error)
    // DeleteRealServer 从指定的虚拟服务器中删除指定的真实服务器。
    DeleteRealServer(*VirtualServer, *RealServer) error
    // UpdateRealServer 从指定的虚拟服务器更新指定的真实服务器。
    UpdateRealServer(*VirtualServer, *RealServer) error
    // ConfigureTimeouts 相当于运行 "ipvsadm --set" 来配置tcp、tcpfin和udp的超时时间。
    ConfigureTimeouts(time.Duration, time.Duration, time.Duration) error
}

// VirtualServer 是用户导向的完整IPVS虚拟服务器的定义。
type VirtualServer struct {
    Address net.IP
    Protocol string
    Port uint16
    Scheduler string
    Flags ServiceFlags
    Timeout uint32
}

// ServiceFlags 用于指定会话亲和性、IP哈希等。
type ServiceFlags uint32

const (
// FlagPersistent 指定IPVS服务的会话亲和性。
FlagPersistent = 0x1
// FlagHashed 指定IPVS服务的哈希标志。
FlagHashed = 0x2
// FlagSourceHash 启用IPVS服务在源端口和源IP上进行哈希。
FlagSourceHash = 0x10
)

// Equal 检查虚拟服务器的相等性。
// 我们不使用 struct ==，因为它无法处理切片。
func (svc *VirtualServer) Equal(other *VirtualServer) bool {
    return svc.Address.Equal(other.Address) &&
        svc.Protocol == other.Protocol &&
        svc.Port == other.Port &&
        svc.Scheduler == other.Scheduler &&
        svc.Flags == other.Flags &&
        svc.Timeout == other.Timeout
}

func (svc *VirtualServer) String() string {
	return net.JoinHostPort(svc.Address.String(), strconv.Itoa(int(svc.Port))) + "/" + svc.Protocol
}

// RealServer 是用户导向的完整IPVS真实服务器的定义。
type RealServer struct {
    Address net.IP
    Port uint16
    Weight int
    ActiveConn int
    InactiveConn int
}

func (rs *RealServer) String() string {
	return net.JoinHostPort(rs.Address.String(), strconv.Itoa(int(rs.Port)))
}

// Equal 检查真实服务器的相等性。
// 我们不使用 struct ==，因为它无法处理切片。
func (rs *RealServer) Equal(other *RealServer) bool {
    return rs.Address.Equal(other.Address) &&
    rs.Port == other.Port
}

// IsRsGracefulTerminationNeeded 如果协议需要对过期连接进行优雅终止，则返回true。
func IsRsGracefulTerminationNeeded(proto string) bool {
	return !strings.EqualFold(proto, "UDP") && !strings.EqualFold(proto, "SCTP")
}
```

```go
// runner implements ipvs.Interface.
type runner struct {
    ipvsHandle *libipvs.Handle // runner结构体实例化时包含一个libipvs.Handle类型的指针变量ipvsHandle，用于调用libipvs库的函数
    mu sync.Mutex // 用于保护Netlink调用的互斥锁
}

// Protocol is the IPVS service protocol type
type Protocol uint16 // 定义了一个Protocol类型，它是一个无符号16位整数

// New returns a new Interface which will call ipvs APIs.
func New() Interface {
	handle, err := libipvs.New("") // 调用libipvs库的New函数返回一个libipvs.Handle实例，同时可能会返回错误
    if err != nil { // 如果返回的错误不为空，则打印错误信息，并返回nil
        klog.ErrorS(err, "IPVS interface can't be initialized")
        return nil
    }
    return &runner{ // 返回一个runner实例，其中ipvsHandle字段被赋值为前面获取到的libipvs.Handle实例
    	ipvsHandle: handle,
    }
}

// AddVirtualServer is part of ipvs.Interface.
func (runner *runner) AddVirtualServer(vs *VirtualServer) error {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.NewService(svc) // 调用ipvsHandle的NewService方法添加一个新的服务
}

// UpdateVirtualServer is part of ipvs.Interface.
func (runner *runner) UpdateVirtualServer(vs *VirtualServer) error {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.UpdateService(svc) // 调用ipvsHandle的UpdateService方法更新服务
}

// DeleteVirtualServer is part of ipvs.Interface.
func (runner *runner) DeleteVirtualServer(vs *VirtualServer) error {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.DelService(svc) // 调用ipvsHandle的DelService方法删除服务
}

// GetVirtualServer is part of ipvs.Interface.
func (runner *runner) GetVirtualServer(vs *VirtualServer) (*VirtualServer, error) {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return nil, fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    runner.mu.Lock() // 加锁
    ipvsSvc, err := runner.ipvsHandle.GetService(svc) // 调用ipvsHandle的GetService方法获取服务信息
    runner.mu.Unlock() // 解锁

    if err != nil { // 如果返回的错误不为空，则返回错误
        return nil, fmt.Errorf("could not get IPVS service: %w", err)
    }
    vServ, err := toVirtualServer(ipvsSvc) // 调用toVirtualServer函数将libipvs.Service类型转换为VirtualServer类型
    if err != nil { // 如果返回的错误不为空，则返回错误
        return nil, fmt.Errorf("could not convert IPVS service to local virtual server: %w", err)
    }
    return vServ, nil // 返回转换后的VirtualServer实例
}

// GetVirtualServers is part of ipvs.Interface.
func (runner *runner) GetVirtualServers() ([]*VirtualServer, error) {
    runner.mu.Lock() // 加锁
    ipvsSvcs, err := runner.ipvsHandle.GetServices() // 调用ipvsHandle的GetServices方法获取所有服务信息
    runner.mu.Unlock() // 解锁
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return nil, fmt.Errorf("could not get IPVS services: %w", err)
    }
    vss := make([]*VirtualServer, 0) // 创建一个空的VirtualServer切片
    for _, ipvsSvc := range ipvsSvcs { // 遍历获取到的所有服务信息
        vs, err := toVirtualServer(ipvsSvc) // 调用toVirtualServer函数将libipvs.Service类型转换为VirtualServer类型
        if err != nil { // 如果返回的错误不为空，则返回错误
            return nil, fmt.Errorf("could not convert IPVS service to local virtual server: %w", err)
        }
        vss = append(vss, vs) // 将转换后的VirtualServer实例添加到切片中
    }
    return vss, nil // 返回转换后的VirtualServer切片
}

// Flush is part of ipvs.Interface. Currently we delete IPVS services one by one
func (runner *runner) Flush() error {
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.Flush() // 调用ipvsHandle的Flush方法清空所有服务
}

// AddRealServer is part of ipvs.Interface.
func (runner *runner) AddRealServer(vs *VirtualServer, rs *RealServer) error {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    dst, err := toIPVSDestination(rs) // 调用toIPVSDestination函数将RealServer类型转换为libipvs.Destination类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local real server to IPVS destination: %w", err)
    }
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.NewDestination(svc, dst) // 调用ipvsHandle的NewDestination方法添加目标服务器到指定服务
}

// DeleteRealServer is part of ipvs.Interface.
func (runner *runner) DeleteRealServer(vs *VirtualServer, rs *RealServer) error {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    dst, err := toIPVSDestination(rs) // 调用toIPVSDestination函数将RealServer类型转换为libipvs.Destination类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local real server to IPVS destination: %w", err)
    }
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.DelDestination(svc, dst) // 调用ipvsHandle的DelDestination方法从指定服务中删除目标服务器
}

func (runner *runner) UpdateRealServer(vs *VirtualServer, rs *RealServer) error {
    svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
    }
    dst, err := toIPVSDestination(rs) // 调用toIPVSDestination函数将RealServer类型转换为libipvs.Destination类型
    if err != nil { // 如果返回的错误不为空，则返回错误
    	return fmt.Errorf("could not convert local real server to IPVS destination: %w", err)
    }
    runner.mu.Lock() // 加锁
    defer runner.mu.Unlock() // 解锁
    return runner.ipvsHandle.UpdateDestination(svc, dst) // 调用ipvsHandle的UpdateDestination方法更新指定服务中的目标服务器信息
}


// GetRealServers is part of ipvs.Interface.
func (runner *runner) GetRealServers(vs *VirtualServer) ([]*RealServer, error) {
	svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
	if err != nil {               // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
	}
	runner.mu.Lock()                                    // 加锁
	dsts, err := runner.ipvsHandle.GetDestinations(svc) // 调用ipvsHandle的GetDestinations方法获取指定服务的目标服务器信息
	runner.mu.Unlock()                                  // 解锁
	if err != nil {                                     // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not get IPVS destination for service: %w", err)
	}
	rss := make([]*RealServer, 0) // 创建一个空的RealServer切片
	for _, dst := range dsts {    // 遍历获取到的所有目标服务器信息
		rs, err := toRealServer(dst) // 调用toRealServer函数将libipvs.Destination类型转换为RealServer类型
		if err != nil {              // 如果返回的错误不为空，则返回错误
			return nil, fmt.Errorf("could not convert IPVS destination to local real server: %w", err)
		}
		rss = append(rss, rs) // 将转换后的RealServer实例添加到切片中
	}
	return rss, nil // 返回转换后的RealServer切片
}

// FlushRealServers is part of ipvs.Interface.
func (runner *runner) FlushRealServers(vs *VirtualServer) error {
	svc, err := toIPVSService(vs) // 调用toIPVSService函数将VirtualServer类型转换为libipvs.Service类型
	if err != nil {               // 如果返回的错误不为空，则返回错误
		return fmt.Errorf("could not convert local virtual server to IPVS service: %w", err)
	}
	runner.mu.Lock()                                // 加锁
	defer runner.mu.Unlock()                        // 解锁
	return runner.ipvsHandle.FlushDestinations(svc) // 调用ipvsHandle的FlushDestinations方法清空指定服务的所有目标服务器
}


// GetStats is part of ipvs.Interface.
func (runner *runner) GetStats() (*Stats, error) {
	runner.mu.Lock()                           // 加锁
	defer runner.mu.Unlock()                   // 解锁
	stats, err := runner.ipvsHandle.GetStats() // 调用ipvsHandle的GetStats方法获取IPVS统计信息
	if err != nil {                            // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not get IPVS stats: %w", err)
	}
	return toStats(stats), nil // 调用toStats函数将libipvs.Stats类型转换为Stats类型并返回
}


// toIPVSService converts a VirtualServer to an IPVS Service.
func toIPVSService(vs *VirtualServer) (*libipvs.Service, error) {
	protocol, err := toIPVSProtocol(vs.Protocol) // 调用toIPVSProtocol函数将VirtualServer的Protocol字段转换为libipvs.Protocol类型
	if err != nil {                              // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not convert protocol: %w", err)
	}

	ip, err := parseIP(vs.Address) // 调用parseIP函数解析VirtualServer的Address字段
	if err != nil {                // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not parse IP address: %w", err)
	}

	svc := &libipvs.Service{ // 创建一个libipvs.Service实例
		Address:          ip,                                      // 使用解析后的IP地址
		Protocol:         protocol,                                // 使用转换后的协议类型
		Port:             int(vs.Port),                            // 使用VirtualServer的Port字段
		SchedName:        vs.Scheduler,                            // 使用VirtualServer的Scheduler字段
		Flags:            libipvs.ServiceFlag(vs.Flags),           // 使用VirtualServer的Flags字段转换为libipvs.ServiceFlag类型
		Timeout:          time.Duration(vs.Timeout) * time.Second, // 使用VirtualServer的Timeout字段
		Netmask:          vs.Netmask,                              // 使用VirtualServer的Netmask字段
		OpsPerRealServer: vs.OpsPerRealServer,                     // 使用VirtualServer的OpsPerRealServer字段
		Quorum:           vs.Quorum,                               // 使用VirtualServer的Quorum字段
		PEName:           vs.PEName,                               // 使用VirtualServer的PEName字段
	}

	return svc, nil // 返回转换后的libipvs.Service实例
}


// toIPVSDestination converts a RealServer to an IPVS Destination.
func toIPVSDestination(rs *RealServer) (*libipvs.Destination, error) {
	ip, err := parseIP(rs.Address) // 调用parseIP函数解析RealServer的Address字段
	if err != nil {                // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not parse IP address: %w", err)
	}

	dst := &libipvs.Destination{ // 创建一个libipvs.Destination实例
		Address:    ip,                                      // 使用解析后的IP地址
		Port:       int(rs.Port),                            // 使用RealServer的Port字段
		Weight:     rs.Weight,                               // 使用RealServer的Weight字段
		Forward:    libipvs.ForwardMethod(rs.ForwardMethod), // 使用RealServer的ForwardMethod字段转换为libipvs.ForwardMethod类型
		Flags:      libipvs.DestinationFlag(rs.Flags),       // 使用RealServer的Flags字段转换为libipvs.DestinationFlag类型
		UThreshold: rs.UThreshold,                           // 使用RealServer的UThreshold字段
		LThreshold: rs.LThreshold,                           // 使用RealServer的LThreshold字段
	}

	return dst, nil // 返回转换后的libipvs.Destination实例
}

// toVirtualServer converts an IPVS Service to a VirtualServer.
func toVirtualServer(svc *libipvs.Service) (*VirtualServer, error) {
	protocol, err := toProtocol(svc.Protocol) // 调用toProtocol函数将libipvs.Protocol类型转换为Protocol类型
	if err != nil {                           // 如果返回的错误不为空，则返回错误
		return nil, fmt.Errorf("could not convert protocol: %w", err)
	}

	vs := &VirtualServer{ // 创建一个VirtualServer实例
		Address:     svc.Address.String(),             // 使用Service的Address字段的字符串表示
		Port:        uint16(svc.Port),                 // 使用Service的Port字段
		Protocol:    protocol,                         // 使用转换后的协议类型
		Scheduler:   svc.SchedName,                    // 使用Service的SchedName字段
		Flags:       uint32(svc.Flags),                // 使用Service的Flags字段
		Timeout:     int64(svc.Timeout / time.Second), // 使用Service的Timeout字段
		Netmask:     svc.Netmask,                      // 使用Service的Netmask字段
		Persistence: svc.PeName,                       // 使用Service的PEName字段
		Quorum:      svc.Quorum,                       // 使用Service的Quorum字段
		Stats:       toVirtualServerStats(svc.Stats),  // 调用toVirtualServerStats函数将Service的Stats字段转换为VirtualServerStats类型
	}

	return vs, nil // 返回转换后的VirtualServer实例
}

// toRealServer converts an IPVS Destination to a RealServer.
func toRealServer(dst *libipvs.Destination) (*RealServer, error) {
	rs := &RealServer{ // 创建一个RealServer实例
		Address:       dst.Address.String(), // 使用Destination的Address字段的字符串表示
		Port:          uint16(dst.Port),     // 使用Destination的Port字段
		Weight:        dst.Weight,           // 使用Destination的Weight字段
		ForwardMethod: uint32(dst.Forward),  // 使用Destination的Forward字段
		Flags:         uint32(dst.Flags),    // 使用Destination的Flags字段
		UThreshold:    dst.UThreshold,       // 使用Destination的UThreshold字段
		LThreshold:    dst.LThreshold,       // 使用Destination的LThreshold字段
	}

	return rs, nil // 返回转换后的RealServer实例
}


// toIPVSProtocol converts a Protocol to an IPVS Protocol.
func toIPVSProtocol(p Protocol) (libipvs.Protocol, error) {
	switch p {
	case ProtocolTCP:
		return libipvs.ProtocolTCP, nil
	case ProtocolUDP:
		return libipvs.ProtocolUDP, nil
	case ProtocolSCTP:
		return libipvs.ProtocolSCTP, nil
	default:
		return 0, fmt.Errorf("unknown protocol: %s", p)
	}
}

// toProtocol converts an IPVS Protocol to a Protocol.
func toProtocol(p libipvs.Protocol) (Protocol, error) {
	switch p {
	case libipvs.ProtocolTCP:
		return ProtocolTCP, nil
	case libipvs.ProtocolUDP:
		return ProtocolUDP, nil
	case libipvs.ProtocolSCTP:
		return ProtocolSCTP, nil
	default:
		return "", fmt.Errorf("unknown protocol: %d", p)
	}
}
```

## NewProxier

```go
// NewProxier返回一个新的Proxier，给定一个iptables和ipvs接口实例。
// 由于iptables和ipvs逻辑，假设在一台机器上只有一个Proxier处于活动状态。
// 如果更新或获取初始锁失败，将返回错误。
// 创建proxier后，它将在后台保持iptables和ipvs规则的最新状态，并且
// 如果某个特定的iptables或ipvs调用失败，不会终止。
func NewProxier(ipFamily v1.IPFamily,
	ipt utiliptables.Interface,
	ipvs utilipvs.Interface,
	ipset utilipset.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	excludeCIDRs []string,
	strictARP bool,
	tcpTimeout time.Duration,
	tcpFinTimeout time.Duration,
	udpTimeout time.Duration,
	masqueradeAll bool,
	masqueradeBit int,
	localDetector proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	scheduler string,
	nodePortAddressStrings []string,
	kernelHandler KernelHandler,
) (*Proxier, error) {
	// 在连接到Linux桥接口时，代理需要br_netfilter和bridge-nf-call-iptables=1。
	// 在大多数插件处理这个之前，当配置丢失时记录日志
	if val, err := sysctl.GetSysctl(sysctlBridgeCallIPTables); err == nil && val != 1 {
		klog.InfoS("Missing br-netfilter module or unset sysctl br-nf-call-iptables, proxy may not work as intended")
	}

	// 设置我们需要的conntrack sysctl
	if err := proxyutil.EnsureSysctl(sysctl, sysctlVSConnTrack, 1); err != nil {
		return nil, err
	}

	// 获取内核版本号，用于检查所需的内核模块是否存在
	kernelVersionStr, err := kernelHandler.GetKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("error determining kernel version to find required kernel modules for ipvs support: %v", err)
	}
	kernelVersion, err := version.ParseGeneric(kernelVersionStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing kernel version %q: %v", kernelVersionStr, err)
	}
	if kernelVersion.LessThan(version.MustParseGeneric(connReuseMinSupportedKernelVersion)) {
		klog.ErrorS(nil, "Can't set sysctl, kernel version doesn't satisfy minimum version requirements", "sysctl", sysctlConnReuse, "minimumKernelVersion", connReuseMinSupportedKernelVersion)
	} else if kernelVersion.AtLeast(version.MustParseGeneric(connReuseFixedKernelVersion)) {
		// https://github.com/kubernetes/kubernetes/issues/93297
		klog.V(2).InfoS("Left as-is", "sysctl", sysctlConnReuse)
	} else {
		// 设置连接复用模式
		if err := proxyutil.EnsureSysctl(sysctl, sysctlConnReuse, 0); err != nil {
			return nil, err
		}
	}

	// 设置我们需要的expire_nodest_conn sysctl
	if err := proxyutil.EnsureSysctl(sysctl, sysctlExpireNoDestConn, 1); err != nil {
		return nil, err
	}

	// 设置我们需要的expire_quiescent_template sysctl
	if err := proxyutil.EnsureSysctl(sysctl, sysctlExpireQuiescentTemplate, 1); err != nil {
		return nil, err
	}

	// 设置我们需要的ip_forward sysctl
	if err := proxyutil.EnsureSysctl(sysctl, sysctlForward, 1); err != nil {
		return nil, err
	}

	if strictARP {
		// 设置我们需要的arp_ignore sysctl
		if err := proxyutil.EnsureSysctl(sysctl, sysctlArpIgnore, 1); err != nil {
			return nil, err
		}

		// 设置我们需要的arp_announce sysctl
		if err := proxyutil.EnsureSysctl(sysctl, sysctlArpAnnounce, 2); err != nil {
			return nil, err
		}
	}

	// 如果任何一个超时参数被设置，则配置IPVS的超时
	// 这相当于运行ipvsadm --set命令，值为0表示保留当前系统超时值
	if tcpTimeout > 0 || tcpFinTimeout > 0 || udpTimeout > 0 {
		if err := ipvs.ConfigureTimeouts(tcpTimeout, tcpFinTimeout, udpTimeout); err != nil {
			klog.ErrorS(err, "Failed to configure IPVS timeouts")
		}
	}

	// 生成用于SNAT规则的伪装标记
	masqueradeValue := 1 << uint(masqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)

	klog.V(2).InfoS("Record nodeIP and family", "nodeIP", nodeIP, "family", ipFamily)

	if len(scheduler) == 0 {
		klog.InfoS("IPVS scheduler not specified, use rr by default")
		scheduler = defaultScheduler
	}

	nodePortAddresses := proxyutil.NewNodePortAddresses(ipFamily, nodePortAddressStrings)

	serviceHealthServer := healthcheck.NewServiceHealthServer(hostname, recorder, nodePortAddresses, healthzServer)

	// 验证excludeCIDRs已在之前进行验证，在这里我们只是将其解析为IPNet列表
	parsedExcludeCIDRs, _ := netutils.ParseCIDRs(excludeCIDRs)

	proxier := &Proxier{
		ipFamily:              ipFamily,
		svcPortMap:            make(proxy.ServicePortMap),
		serviceChanges:        proxy.NewServiceChangeTracker(newServiceInfo, ipFamily, recorder, nil),
		endpointsMap:          make(proxy.EndpointsMap),
		endpointsChanges:      proxy.NewEndpointChangeTracker(hostname, nil, ipFamily, recorder, nil),
		initialSync:           true,
		syncPeriod:            syncPeriod,
		minSyncPeriod:         minSyncPeriod,
		excludeCIDRs:          parsedExcludeCIDRs,
		iptables:              ipt,
		masqueradeAll:         masqueradeAll,
		masqueradeMark:        masqueradeMark,
		exec:                  exec,
		localDetector:         localDetector,
		hostname:              hostname,
		nodeIP:                nodeIP,
		recorder:              recorder,
		serviceHealthServer:   serviceHealthServer,
		healthzServer:         healthzServer,
		ipvs:                  ipvs,
		ipvsScheduler:         scheduler,
		iptablesData:          bytes.NewBuffer(nil),
		filterChainsData:      bytes.NewBuffer(nil),
		natChains:             proxyutil.LineBuffer{},
		natRules:              proxyutil.LineBuffer{},
		filterChains:          proxyutil.LineBuffer{},
		filterRules:           proxyutil.LineBuffer{},
		netlinkHandle:         NewNetLinkHandle(ipFamily == v1.IPv6Protocol),
		ipset:                 ipset,
		nodePortAddresses:     nodePortAddresses,
		networkInterfacer:     proxyutil.RealNetwork{},
		gracefuldeleteManager: NewGracefulTerminationManager(ipvs),
	}
	// 使用所需的所有集合初始化ipsetList
	proxier.ipsetList = make(map[string]*IPSet)
	for _, is := range ipsetInfo {
		proxier.ipsetList[is.name] = NewIPSet(ipset, is.name, is.setType, (ipFamily == v1.IPv6Protocol), is.comment)
	}
	burstSyncs := 2
	klog.V(2).InfoS("ipvs sync params", "ipFamily", ipt.Protocol(), "minSyncPeriod", minSyncPeriod, "syncPeriod", syncPeriod, "burstSyncs", burstSyncs)
	proxier.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", proxier.syncProxyRules, minSyncPeriod, syncPeriod, burstSyncs)
	proxier.gracefuldeleteManager.Run()
	return proxier, nil
}
```

### sysctl

```go
// In IPVS proxy mode, the following flags need to be set
const (
	sysctlBridgeCallIPTables      = "net/bridge/bridge-nf-call-iptables"
	sysctlVSConnTrack             = "net/ipv4/vs/conntrack"
	sysctlConnReuse               = "net/ipv4/vs/conn_reuse_mode"
	sysctlExpireNoDestConn        = "net/ipv4/vs/expire_nodest_conn"
	sysctlExpireQuiescentTemplate = "net/ipv4/vs/expire_quiescent_template"
	sysctlForward                 = "net/ipv4/ip_forward"
	sysctlArpIgnore               = "net/ipv4/conf/all/arp_ignore"
	sysctlArpAnnounce             = "net/ipv4/conf/all/arp_announce"
)
```

### EnsureSysctl

```go
// EnsureSysctl函数用于设置内核sysctl参数的值。
func EnsureSysctl(sysctl utilsysctl.Interface, name string, newVal int) error {
    // 获取当前sysctl参数的值
    if oldVal, _ := sysctl.GetSysctl(name); oldVal != newVal {
        // 如果当前值与目标值不同，则设置sysctl参数为目标值
        if err := sysctl.SetSysctl(name, newVal); err != nil {
            return fmt.Errorf("can't set sysctl %s to %d: %v", name, newVal, err)
        }
        // 打印日志，显示修改前后的sysctl参数值
        klog.V(1).InfoS("Changed sysctl", "name", name, "before", oldVal, "after", newVal)
    }
    return nil
}
```

#### Interface

```go
// Interface是一个可注入的接口，用于运行sysctl命令。
type Interface interface {
    // GetSysctl返回指定sysctl设置的值
    GetSysctl(sysctl string) (int, error)
    // SetSysctl将指定的sysctl标志修改为新值
    SetSysctl(sysctl string, newVal int) error
}

// New返回一个用于访问sysctl的新接口
func New() Interface {
	return &procSysctl{}
}

// procSysctl通过读取和写入/proc/sys目录下的文件来实现Interface接口
type procSysctl struct {
}

// GetSysctl返回指定sysctl设置的值
func (*procSysctl) GetSysctl(sysctl string) (int, error) {
    // 读取sysctl参数文件的内容
    data, err := os.ReadFile(path.Join(sysctlBase, sysctl))
    if err != nil {
    	return -1, err
    }
    // 将文件内容转换为整数值
    val, err := strconv.Atoi(strings.Trim(string(data), " \n"))
    if err != nil {
    	return -1, err
    }
    return val, nil
}

// SetSysctl将指定的sysctl标志修改为新值
func (*procSysctl) SetSysctl(sysctl string, newVal int) error {
    // 将新值以字符串形式写入sysctl参数文件
    return os.WriteFile(path.Join(sysctlBase, sysctl), []byte(strconv.Itoa(newVal)), 0640)
}
```

## NewDualStackProxier

```go
// NewDualStackProxier返回一个用于双栈操作的新Proxier
func NewDualStackProxier(
	ipt [2]utiliptables.Interface,
	ipvs utilipvs.Interface,
	ipset utilipset.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	excludeCIDRs []string,
	strictARP bool,
	tcpTimeout time.Duration,
	tcpFinTimeout time.Duration,
	udpTimeout time.Duration,
	masqueradeAll bool,
	masqueradeBit int,
	localDetectors [2]proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP [2]net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	scheduler string,
	nodePortAddresses []string,
	kernelHandler KernelHandler,
) (proxy.Provider, error) {

	safeIpset := newSafeIpset(ipset)

	// 创建单栈Proxier的IPv4实例
	ipv4Proxier, err := NewProxier(v1.IPv4Protocol, ipt[0], ipvs, safeIpset, sysctl,
		exec, syncPeriod, minSyncPeriod, filterCIDRs(false, excludeCIDRs), strictARP,
		tcpTimeout, tcpFinTimeout, udpTimeout, masqueradeAll, masqueradeBit,
		localDetectors[0], hostname, nodeIP[0],
		recorder, healthzServer, scheduler, nodePortAddresses, kernelHandler)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
	}

	// 创建单栈Proxier的IPv6实例
	ipv6Proxier, err := NewProxier(v1.IPv6Protocol, ipt[1], ipvs, safeIpset, sysctl,
		exec, syncPeriod, minSyncPeriod, filterCIDRs(true, excludeCIDRs), strictARP,
		tcpTimeout, tcpFinTimeout, udpTimeout, masqueradeAll, masqueradeBit,
		localDetectors[1], hostname, nodeIP[1],
		recorder, healthzServer, scheduler, nodePortAddresses, kernelHandler)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 proxier: %v", err)
	}

	proxier := &dualStackProxier{
		ipv4Proxier: ipv4Proxier,
		ipv6Proxier: ipv6Proxier,
	}
	return proxier, nil
}
```

## syncProxyRules

```go
// 这里是所有的ipvs调用发生的地方。
func (proxier *Proxier) syncProxyRules() {
    proxier.mu.Lock() // 加锁
    defer proxier.mu.Unlock() // 解锁
    // 在接收到服务和端点之前不要同步规则
    if !proxier.isInitialized() {
        klog.V(2).InfoS("Not syncing ipvs rules until Services and Endpoints have been received from master")
        return
    }

    // 设置initialSync为false是安全的，因为它作为启动操作的标志，并且已经持有了互斥锁。
    defer func() {
        proxier.initialSync = false
    }()

    // 记录同步所花费的时间
    start := time.Now()
    defer func() {
        metrics.SyncProxyRulesLatency.Observe(metrics.SinceInSeconds(start))
        klog.V(4).InfoS("syncProxyRules complete", "elapsed", time.Since(start))
    }()

    // 假设如果调用了这个函数，我们确实想要同步它们，
    // 即使期间没有任何变化。换句话说，调用者负责检测无操作变化并且不调用此函数。
    serviceUpdateResult := proxier.svcPortMap.Update(proxier.serviceChanges)
    endpointUpdateResult := proxier.endpointsMap.Update(proxier.endpointsChanges)

    klog.V(3).InfoS("Syncing ipvs proxier rules")

    proxier.serviceNoLocalEndpointsInternal = sets.New[string]()
    proxier.serviceNoLocalEndpointsExternal = sets.New[string]()
    // 开始安装iptables

    // 重置所有稍后使用的缓冲区。
    // 这样可以避免内存重新分配，从而提高性能。
    proxier.natChains.Reset()
    proxier.natRules.Reset()
    proxier.filterChains.Reset()
    proxier.filterRules.Reset()

    // 写入表头。
    proxier.filterChains.Write("*filter")
    proxier.natChains.Write("*nat")

    proxier.createAndLinkKubeChain()

    // 确保在ipvs Proxier将服务地址绑定到它上面时，系统中存在虚拟接口
    _, err := proxier.netlinkHandle.EnsureDummyDevice(defaultDummyDevice)
    if err != nil {
        klog.ErrorS(err, "Failed to create dummy interface", "interface", defaultDummyDevice)
        return
    }

    // 确保在系统中存在ip sets。
    for _, set := range proxier.ipsetList {
        if err := ensureIPSet(set); err != nil {
            return
        }
        set.resetEntries()
    }

    // activeIPVSServices表示在此次同步中成功创建的IPVS服务
    activeIPVSServices := sets.New[string]()
    // activeBindAddrs表示在此次同步后我们希望在defaultDummyDevice上有的地址
    activeBindAddrs := sets.New[string]()
   // 获取除了虚拟接口以外的所有本地地址，并存储在nodeAddressSet中
    alreadyBoundAddrs, err := proxier.netlinkHandle.GetLocalAddresses(defaultDummyDevice)
    if err != nil {
        klog.ErrorS(err, "Error listing addresses binded to dummy interface")
    }
    // 判断是否存在具有NodePort的Service
	nodeAddressSet, err := proxier.netlinkHandle.GetAllLocalAddressesExcept(defaultDummyDevice)
	if err != nil {
		klog.ErrorS(err, "Error listing node addresses")
	}

	hasNodePort := false
	for _, svc := range proxier.svcPortMap {
		svcInfo, ok := svc.(*servicePortInfo)
		if ok && svcInfo.NodePort() != 0 {
			hasNodePort = true
			break
		}
	}

	// 如果存在NodePort，获取用于IPVS服务的节点IP地址列表
	var nodeIPs []net.IP
	if hasNodePort {
		if proxier.nodePortAddresses.MatchAll() {
			for _, ipStr := range nodeAddressSet.UnsortedList() {
				nodeIPs = append(nodeIPs, netutils.ParseIPSloppy(ipStr))
			}
		} else {
			allNodeIPs, err := proxier.nodePortAddresses.GetNodeIPs(proxier.networkInterfacer)
			if err != nil {
				klog.ErrorS(err, "Failed to get node IP address matching nodeport cidr")
			} else {
				for _, ip := range allNodeIPs {
					if !ip.IsLoopback() {
						nodeIPs = append(nodeIPs, ip)
					}
				}
			}
		}
	}

	// 为每个Service构建IPVS规则
	for svcPortName, svcPort := range proxier.svcPortMap {
		svcInfo, ok := svcPort.(*servicePortInfo)
		if !ok {
			klog.ErrorS(nil, "Failed to cast serviceInfo", "servicePortName", svcPortName)
			continue
		}

		protocol := strings.ToLower(string(svcInfo.Protocol()))
		// Precompute svcNameString; with many services the many calls
		// to ServicePortName.String() show up in CPU profiles.
		svcPortNameString := svcPortName.String()

		// 处理流量循环回原始发送者的情况，使用SNAT
		for _, e := range proxier.endpointsMap[svcPortName] {
			ep, ok := e.(*proxy.BaseEndpointInfo)
			if !ok {
				klog.ErrorS(nil, "Failed to cast BaseEndpointInfo", "endpoint", e)
				continue
			}
			if !ep.IsLocal {
				continue
			}
			epIP := ep.IP()
			epPort, err := ep.Port()
			// Error parsing this endpoint has been logged. Skip to next endpoint.
			if epIP == "" || err != nil {
				continue
			}
            // 捕获ClusterIP
			entry := &utilipset.Entry{
				IP:       epIP,
				Port:     epPort,
				Protocol: protocol,
				IP2:      epIP,
				SetType:  utilipset.HashIPPortIP,
			}
            // 验证是否允许将条目添加到 ipset 中，如果不允许则记录错误并继续下一次循环
			if valid := proxier.ipsetList[kubeLoopBackIPSet].validateEntry(entry); !valid {
				klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeLoopBackIPSet].Name)
				continue
			}
            // 将条目插入到 ipset 的活动条目列表中
			proxier.ipsetList[kubeLoopBackIPSet].activeEntries.Insert(entry.String())
		}

		// Capture the clusterIP.
		// ipset call
		entry := &utilipset.Entry{
			IP:       svcInfo.ClusterIP().String(),
			Port:     svcInfo.Port(),
			Protocol: protocol,
			SetType:  utilipset.HashIPPort,
		}
		// 验证是否允许将条目添加到 ipset 中，如果不允许则记录错误并继续下一次循环
		if valid := proxier.ipsetList[kubeClusterIPSet].validateEntry(entry); !valid {
			klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeClusterIPSet].Name)
			continue
		}
        // 将条目插入到 ipset 的活动条目列表中
		proxier.ipsetList[kubeClusterIPSet].activeEntries.Insert(entry.String())
		// 创建一个 utilipvs.VirtualServer 结构体，表示 IPVS 的虚拟服务器
		serv := &utilipvs.VirtualServer{
			Address:   svcInfo.ClusterIP(),
			Port:      uint16(svcInfo.Port()),
			Protocol:  string(svcInfo.Protocol()),
			Scheduler: proxier.ipvsScheduler,
		}
		// 如果服务的会话亲和类型为 v1.ServiceAffinityClientIP，则设置服务的标志和超时时间
		if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
			serv.Flags |= utilipvs.FlagPersistent
			serv.Timeout = uint32(svcInfo.StickyMaxAgeSeconds())
		}
		// 如果 IPVS 的调度算法为 "mh"，则设置服务的源哈希标志
		if proxier.ipvsScheduler == "mh" {
			serv.Flags |= utilipvs.FlagSourceHash
		}
		// 在 syncService() 中绑定 ClusterIP 到虚拟接口，并将 bindAddr 参数设置为 true
		if err := proxier.syncService(svcPortNameString, serv, true, alreadyBoundAddrs); err == nil {
            // 将服务添加到 activeIPVSServices 列表和 activeBindAddrs 列表中
			activeIPVSServices.Insert(serv.String())
			activeBindAddrs.Insert(serv.Address.String())
			// 检查服务是否为 internalNodeLocal，并根据情况同步端点
			internalNodeLocal := false
			if svcInfo.InternalPolicyLocal() {
				internalNodeLocal = true
			}
			if err := proxier.syncEndpoint(svcPortName, internalNodeLocal, serv); err != nil {
				klog.ErrorS(err, "Failed to sync endpoint for service", "servicePortName", svcPortName, "virtualServer", serv)
			}
		} else {
			klog.ErrorS(err, "Failed to sync service", "servicePortName", svcPortName, "virtualServer", serv)
		}

		// 捕获 ExternalIPs
		for _, externalIP := range svcInfo.ExternalIPStrings() {
			// 创建一个 utilipset.Entry 结构体，表示要添加到 ipset 中的条目
			entry := &utilipset.Entry{
				IP:       externalIP,
				Port:     svcInfo.Port(),
				Protocol: protocol,
				SetType:  utilipset.HashIPPort,
			}
			// 如果服务的 ExternalPolicy 为 Local，则验证是否允许将条目添加到 kubeExternalIPLocalSet 中，如果不允许则记录错误并继续下一次循环
			if svcInfo.ExternalPolicyLocal() {
				if valid := proxier.ipsetList[kubeExternalIPLocalSet].validateEntry(entry); !valid {
					klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeExternalIPLocalSet].Name)
					continue
				}
                // 将条目插入到 kubeExternalIPLocalSet 的活动条目列表中
				proxier.ipsetList[kubeExternalIPLocalSet].activeEntries.Insert(entry.String())
			} else {
				// 必须对外部 IP 进行 SNAT 处理
				if valid := proxier.ipsetList[kubeExternalIPSet].validateEntry(entry); !valid {
					klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeExternalIPSet].Name)
					continue
				}
                // 将条目插入到 kubeExternalIPSet 的活动条目列表中
				proxier.ipsetList[kubeExternalIPSet].activeEntries.Insert(entry.String())
			}

			// 创建一个 utilipvs.VirtualServer 结构体，表示 IPVS 的虚拟服务器
			serv := &utilipvs.VirtualServer{
				Address:   netutils.ParseIPSloppy(externalIP),
				Port:      uint16(svcInfo.Port()),
				Protocol:  string(svcInfo.Protocol()),
				Scheduler: proxier.ipvsScheduler,
			}
            // 如果服务的会话亲和类型为 v1.ServiceAffinityClientIP，则设置服务的标志和超时时间
			if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
				serv.Flags |= utilipvs.FlagPersistent
				serv.Timeout = uint32(svcInfo.StickyMaxAgeSeconds())
			}
			// 如果 IPVS 的调度算法为 "mh"，则设置服务的源哈希标志
			if proxier.ipvsScheduler == "mh" {
				serv.Flags |= utilipvs.FlagSourceHash
			}
			// 如果地址在其他接口中存在，我们就不应该将地址添加到虚拟设备（dummy device）中
			shouldBind := !nodeAddressSet.Has(serv.Address.String())
			if err := proxier.syncService(svcPortNameString, serv, shouldBind, alreadyBoundAddrs); err == nil {
				activeIPVSServices.Insert(serv.String())
				if shouldBind {
					activeBindAddrs.Insert(serv.Address.String())
				}
				if err := proxier.syncEndpoint(svcPortName, svcInfo.ExternalPolicyLocal(), serv); err != nil {
					klog.ErrorS(err, "Failed to sync endpoint for service", "servicePortName", svcPortName, "virtualServer", serv)
				}
			} else {
				klog.ErrorS(err, "Failed to sync service", "servicePortName", svcPortName, "virtualServer", serv)
			}
		}

		// 捕获负载均衡器的入口（ingress）
		for _, ingress := range svcInfo.LoadBalancerIPStrings() {
			// ipset调用
			entry = &utilipset.Entry{
				IP:       ingress,
				Port:     svcInfo.Port(),
				Protocol: protocol,
				SetType:  utilipset.HashIPPort,
			}
			// 将服务负载均衡器的入口IP:端口添加到kubeServiceAccess ip set，以解决hairpin问题。
            // proxier.kubeServiceAccessSet.activeEntries.Insert(entry.String())
            // 如果我们在全局范围内进行代理，则需要进行伪装以防跨节点。
            // 如果我们仅在本地进行代理，则可以保留源IP。
			if valid := proxier.ipsetList[kubeLoadBalancerSet].validateEntry(entry); !valid {
				klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeLoadBalancerSet].Name)
				continue
			}
			proxier.ipsetList[kubeLoadBalancerSet].activeEntries.Insert(entry.String())
			// 如果服务的externaltrafficpolicy=local，将负载均衡器入口添加到lbIngressLocalSet
			if svcInfo.ExternalPolicyLocal() {
				if valid := proxier.ipsetList[kubeLoadBalancerLocalSet].validateEntry(entry); !valid {
					klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeLoadBalancerLocalSet].Name)
					continue
				}
				proxier.ipsetList[kubeLoadBalancerLocalSet].activeEntries.Insert(entry.String())
			}
			if len(svcInfo.LoadBalancerSourceRanges()) != 0 {
				// 服务防火墙规则基于ServiceSpec.loadBalancerSourceRanges字段创建。
                // 这仅适用于保留源IP的负载均衡器。
                // 对于将流量定向到服务NodePort的负载均衡器，防火墙规则不适用。
				if valid := proxier.ipsetList[kubeLoadBalancerFWSet].validateEntry(entry); !valid {
					klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeLoadBalancerFWSet].Name)
					continue
				}
				proxier.ipsetList[kubeLoadBalancerFWSet].activeEntries.Insert(entry.String())
				allowFromNode := false
                // 初始化变量allowFromNode为false，用于判断是否需要从节点访问
				for _, src := range svcInfo.LoadBalancerSourceRanges() {
					// 遍历负载均衡器的源范围
					entry = &utilipset.Entry{
						IP:       ingress,
						Port:     svcInfo.Port(),
						Protocol: protocol,
						Net:      src,
						SetType:  utilipset.HashIPPortNet,
					}
					// 创建ipset.Entry对象，用于添加到ipset中
					if valid := proxier.ipsetList[kubeLoadBalancerSourceCIDRSet].validateEntry(entry); !valid {
						klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeLoadBalancerSourceCIDRSet].Name)
						continue
					}
                    // 验证entry是否有效，并添加到ipset中
					proxier.ipsetList[kubeLoadBalancerSourceCIDRSet].activeEntries.Insert(entry.String())

					// 将entry转换为字符串，并添加到ipset中
					_, cidr, _ := netutils.ParseCIDRSloppy(src)
                    // 解析源范围的CIDR
					if cidr.Contains(proxier.nodeIP) {
						allowFromNode = true
					} 
                    // 判断节点IP是否在源范围内，如果是，则设置allowFromNode为true
				}
				// generally, ip route rule was added to intercept request to loadbalancer vip from the
				// loadbalancer's backend hosts. In this case, request will not hit the loadbalancer but loop back directly.
				// Need to add the following rule to allow request on host.
				if allowFromNode {
					entry = &utilipset.Entry{
						IP:       ingress,
						Port:     svcInfo.Port(),
						Protocol: protocol,
						IP2:      ingress,
						SetType:  utilipset.HashIPPortIP,
					}
					// 创建ipset.Entry对象，用于添加到ipset中
					if valid := proxier.ipsetList[kubeLoadBalancerSourceIPSet].validateEntry(entry); !valid {
						klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", proxier.ipsetList[kubeLoadBalancerSourceIPSet].Name)
						continue
					}
                    // 验证entry是否有效，并添加到ipset中
					proxier.ipsetList[kubeLoadBalancerSourceIPSet].activeEntries.Insert(entry.String())
                    // 将entry转换为字符串，并添加到ipset中
				}
			}
            // 创建utilipvs.VirtualServer对象，用于添加到IPVS中
			serv := &utilipvs.VirtualServer{
				Address:   netutils.ParseIPSloppy(ingress),
				Port:      uint16(svcInfo.Port()),
				Protocol:  string(svcInfo.Protocol()),
				Scheduler: proxier.ipvsScheduler,
			}
            // 如果服务的会话亲和类型为ClientIP，则设置IPVS的标志和超时时间
			if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
				serv.Flags |= utilipvs.FlagPersistent
				serv.Timeout = uint32(svcInfo.StickyMaxAgeSeconds())
			}
			// 如果IPVS的调度器为"mh"，则设置IPVS的标志为SourceHash
			if proxier.ipvsScheduler == "mh" {
				serv.Flags |= utilipvs.FlagSourceHash
			}
			// 判断IPVS的地址是否存在于其他接口中，如果不存在则为true
			shouldBind := !nodeAddressSet.Has(serv.Address.String())
            // 同步服务到IPVS
			if err := proxier.syncService(svcPortNameString, serv, shouldBind, alreadyBoundAddrs); err == nil {	
                // 将服务添加到活动的IPVS服务集合中
				activeIPVSServices.Insert(serv.String())
				if shouldBind {
                    // 如果需要绑定，则将地址添加到活动绑定地址集合中
					activeBindAddrs.Insert(serv.Address.String())
				}
                // 同步服务的端点
				if err := proxier.syncEndpoint(svcPortName, svcInfo.ExternalPolicyLocal(), serv); err != nil {
					klog.ErrorS(err, "Failed to sync endpoint for service", "servicePortName", svcPortName, "virtualServer", serv)
				}
			} else {
				klog.ErrorS(err, "Failed to sync service", "servicePortName", svcPortName, "virtualServer", serv)
			}
		}
		// 如果服务有NodePort
		if svcInfo.NodePort() != 0 {
			if len(nodeIPs) == 0 {
				// 如果节点IP列表为空，则跳过NodePort配置
				continue
			}

			// Nodeports need SNAT, unless they're local.
			// ipset call

			var (
				nodePortSet *IPSet
				entries     []*utilipset.Entry
			)
			// 根据协议类型设置nodePortSet和entries
			switch protocol {
			case utilipset.ProtocolTCP:
				nodePortSet = proxier.ipsetList[kubeNodePortSetTCP]
				entries = []*utilipset.Entry{{
					// No need to provide ip info
					Port:     svcInfo.NodePort(),
					Protocol: protocol,
					SetType:  utilipset.BitmapPort,
				}}
			case utilipset.ProtocolUDP:
				nodePortSet = proxier.ipsetList[kubeNodePortSetUDP]
				entries = []*utilipset.Entry{{
					// No need to provide ip info
					Port:     svcInfo.NodePort(),
					Protocol: protocol,
					SetType:  utilipset.BitmapPort,
				}}
			case utilipset.ProtocolSCTP:
				nodePortSet = proxier.ipsetList[kubeNodePortSetSCTP]
				// Since hash ip:port is used for SCTP, all the nodeIPs to be used in the SCTP ipset entries.
				entries = []*utilipset.Entry{}
				for _, nodeIP := range nodeIPs {
					entries = append(entries, &utilipset.Entry{
						IP:       nodeIP.String(),
						Port:     svcInfo.NodePort(),
						Protocol: protocol,
						SetType:  utilipset.HashIPPort,
					})
				}
			default:
				// It should never hit
				klog.ErrorS(nil, "Unsupported protocol type", "protocol", protocol)
			}
            // 验证entry是否有效，并添加到ipset中
			if nodePortSet != nil {
				entryInvalidErr := false
				for _, entry := range entries {
					if valid := nodePortSet.validateEntry(entry); !valid {
						klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", nodePortSet.Name)
						entryInvalidErr = true
						break
					}
					nodePortSet.activeEntries.Insert(entry.String())
				}
				if entryInvalidErr {
					continue
				}
			}

			// 如果服务的 externalTrafficPolicy 为 local，则为 local 类型的 NodePort 添加 ipset entry
			if svcInfo.ExternalPolicyLocal() {
				var nodePortLocalSet *IPSet
				switch protocol {
				case utilipset.ProtocolTCP:
					nodePortLocalSet = proxier.ipsetList[kubeNodePortLocalSetTCP]
				case utilipset.ProtocolUDP:
					nodePortLocalSet = proxier.ipsetList[kubeNodePortLocalSetUDP]
				case utilipset.ProtocolSCTP:
					nodePortLocalSet = proxier.ipsetList[kubeNodePortLocalSetSCTP]
				default:
					// 不应该执行到这里
					klog.ErrorS(nil, "Unsupported protocol type", "protocol", protocol)
				}
				if nodePortLocalSet != nil {
					entryInvalidErr := false
					for _, entry := range entries {
						if valid := nodePortLocalSet.validateEntry(entry); !valid {
							klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", nodePortLocalSet.Name)
							entryInvalidErr = true
							break
						}
						nodePortLocalSet.activeEntries.Insert(entry.String())
					}
					if entryInvalidErr {
						continue
					}
				}
			}

			// 为每个节点 IP 地址构建 ipvs 内核路由
			for _, nodeIP := range nodeIPs {
				// 创建 ipvs.VirtualServer 对象
				serv := &utilipvs.VirtualServer{
					Address:   nodeIP,
					Port:      uint16(svcInfo.NodePort()),
					Protocol:  string(svcInfo.Protocol()),
					Scheduler: proxier.ipvsScheduler,
				}
                // 如果服务的会话亲和类型为 ClientIP，则设置相应的标志和超时时间
				if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
					serv.Flags |= utilipvs.FlagPersistent
					serv.Timeout = uint32(svcInfo.StickyMaxAgeSeconds())
				}
				// 如果 ipvsScheduler 为 "mh"，则设置源哈希标志
				if proxier.ipvsScheduler == "mh" {
					serv.Flags |= utilipvs.FlagSourceHash
				}
				// 不需要将节点 IP 绑定到虚拟网卡上，因此将 bindAddr 参数设置为 false
				if err := proxier.syncService(svcPortNameString, serv, false, alreadyBoundAddrs); err == nil {
                    // 将服务同步到 IPVS
					activeIPVSServices.Insert(serv.String())
                    // 同步服务的端点
					if err := proxier.syncEndpoint(svcPortName, svcInfo.ExternalPolicyLocal(), serv); err != nil {
						klog.ErrorS(err, "Failed to sync endpoint for service", "servicePortName", svcPortName, "virtualServer", serv)
					}
				} else {
					klog.ErrorS(err, "Failed to sync service", "servicePortName", svcPortName, "virtualServer", serv)
				}
			}
		}
		// 如果服务有 HealthCheckNodePort，则为其添加 ipset entry
		if svcInfo.HealthCheckNodePort() != 0 {
			nodePortSet := proxier.ipsetList[kubeHealthCheckNodePortSet]
			entry := &utilipset.Entry{
				// 无需提供 IP 信息
				Port:     svcInfo.HealthCheckNodePort(),
				Protocol: "tcp",
				SetType:  utilipset.BitmapPort,
			}

			if valid := nodePortSet.validateEntry(entry); !valid {
				klog.ErrorS(nil, "Error adding entry to ipset", "entry", entry, "ipset", nodePortSet.Name)
				continue
			}
			nodePortSet.activeEntries.Insert(entry.String())
		}
	}

	// 将 "activeBindAddrs" 设置为 KUBE-IPVS-IPS 集合的 activeEntries
	proxier.ipsetList[kubeIPVSSet].activeEntries = activeBindAddrs

	// 同步 ipset entries
	for _, set := range proxier.ipsetList {
		set.syncIPSetEntries()
	}

	// 为 ipset 的规则调用 iptables，确保每个 ip set 的循环中只调用一次 iptables
	proxier.writeIptablesRules()

	// 同步 iptables 规则
	// 注意：使用 NoFlushTables，以免刷新表中的非 Kubernetes 链
	proxier.iptablesData.Reset()
	proxier.iptablesData.Write(proxier.natChains.Bytes())
	proxier.iptablesData.Write(proxier.natRules.Bytes())
	proxier.iptablesData.Write(proxier.filterChains.Bytes())
	proxier.iptablesData.Write(proxier.filterRules.Bytes())

	klog.V(5).InfoS("Restoring iptables", "rules", proxier.iptablesData.Bytes())
	err = proxier.iptables.RestoreAll(proxier.iptablesData.Bytes(), utiliptables.NoFlushTables, utiliptables.RestoreCounters)
	if err != nil {
		if pErr, ok := err.(utiliptables.ParseError); ok {
			lines := utiliptables.ExtractLines(proxier.iptablesData.Bytes(), pErr.Line(), 3)
			klog.ErrorS(pErr, "Failed to execute iptables-restore", "rules", lines)
		} else {
			klog.ErrorS(err, "Failed to execute iptables-restore", "rules", proxier.iptablesData.Bytes())
		}
		metrics.IptablesRestoreFailuresTotal.Inc()
		return
	}
    // 更新 endpoint 的最后更改触发时间
	for name, lastChangeTriggerTimes := range endpointUpdateResult.LastChangeTriggerTimes {
		for _, lastChangeTriggerTime := range lastChangeTriggerTimes {
			latency := metrics.SinceInSeconds(lastChangeTriggerTime)
			metrics.NetworkProgrammingLatency.Observe(latency)
			klog.V(4).InfoS("Network programming", "endpoint", klog.KRef(name.Namespace, name.Name), "elapsed", latency)
		}
	}

	// 从虚拟网卡中移除多余的地址
	superfluousAddresses := alreadyBoundAddrs.Difference(activeBindAddrs)
	if superfluousAddresses.Len() > 0 {
		klog.V(2).InfoS("Removing addresses", "interface", defaultDummyDevice, "addresses", superfluousAddresses)
		for adr := range superfluousAddresses {
			if err := proxier.netlinkHandle.UnbindAddress(adr, defaultDummyDevice); err != nil {
				klog.ErrorS(err, "UnbindAddress", "interface", defaultDummyDevice, "address", adr)
			}
		}
	}

	// 获取当前系统中的 IPVS 服务列表
	currentIPVSServices := make(map[string]*utilipvs.VirtualServer)
	appliedSvcs, err := proxier.ipvs.GetVirtualServers()
	if err == nil {
		for _, appliedSvc := range appliedSvcs {
			currentIPVSServices[appliedSvc.String()] = appliedSvc
		}
	} else {
		klog.ErrorS(err, "Failed to get ipvs service")
	}
    // 清理过时的 IPVS 服务
	proxier.cleanLegacyService(activeIPVSServices, currentIPVSServices)
	// 更新健康检查服务
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated()
	}
	metrics.SyncProxyRulesLastTimestamp.SetToCurrentTime()

	// 同步服务的健康检查
	if err := proxier.serviceHealthServer.SyncServices(proxier.svcPortMap.HealthCheckNodePorts()); err != nil {
		klog.ErrorS(err, "Error syncing healthcheck services")
	}
	if err := proxier.serviceHealthServer.SyncEndpoints(proxier.endpointsMap.LocalReadyEndpoints()); err != nil {
		klog.ErrorS(err, "Error syncing healthcheck endpoints")
	}

	metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("internal").Set(float64(proxier.serviceNoLocalEndpointsInternal.Len()))
	metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("external").Set(float64(proxier.serviceNoLocalEndpointsExternal.Len()))

	// 清理 UDP 服务的过时连接跟踪条目
	conntrack.CleanStaleEntries(proxier.ipFamily == v1.IPv6Protocol, proxier.exec, proxier.svcPortMap, serviceUpdateResult, endpointUpdateResult)
}
```

#### syncService

```go
func (proxier *Proxier) syncService(svcName string, vs *utilipvs.VirtualServer, bindAddr bool, alreadyBoundAddrs sets.Set[string]) error {
	appliedVirtualServer, _ := proxier.ipvs.GetVirtualServer(vs)
	// 获取当前应用的虚拟服务器配置
	if appliedVirtualServer == nil || !appliedVirtualServer.Equal(vs) {
		// 如果当前应用的虚拟服务器配置为空或者不等于传入的虚拟服务器配置
		if appliedVirtualServer == nil {
			// 如果当前应用的虚拟服务器配置为空，则创建一个新的服务
			klog.V(3).InfoS("Adding new service", "serviceName", svcName, "virtualServer", vs)
			// 添加 IPVS 服务
			if err := proxier.ipvs.AddVirtualServer(vs); err != nil {
				klog.ErrorS(err, "Failed to add IPVS service", "serviceName", svcName)
				return err
			}
		} else {
			// 如果当前应用的虚拟服务器配置不为空，则更新现有的服务
			// 在更新期间，服务 VIP 不会下线
			klog.V(3).InfoS("IPVS service was changed", "serviceName", svcName)
			// 更新 IPVS 服务
			if err := proxier.ipvs.UpdateVirtualServer(vs); err != nil {
				klog.ErrorS(err, "Failed to update IPVS service")
				return err
			}
		}
	}

	// 将服务地址绑定到虚拟接口
	if bindAddr {
		// 如果需要绑定地址
		// 如果 alreadyBoundAddrs 为空，始终尝试绑定
		// 否则，检查是否已经绑定，并提前返回
		if alreadyBoundAddrs != nil && alreadyBoundAddrs.Has(vs.Address.String()) {
			return nil
		}

		klog.V(4).InfoS("Bind address", "address", vs.Address)
		_, err := proxier.netlinkHandle.EnsureAddressBind(vs.Address.String(), defaultDummyDevice)
		if err != nil {
			klog.ErrorS(err, "Failed to bind service address to dummy device", "serviceName", svcName)
			return err
		}
	}

	return nil
}
```

#### syncEndpoint

```go
func (proxier *Proxier) syncEndpoint(svcPortName proxy.ServicePortName, onlyNodeLocalEndpoints bool, vs *utilipvs.VirtualServer) error {
	// 获取已应用的虚拟服务器配置
	appliedVirtualServer, err := proxier.ipvs.GetVirtualServer(vs)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPVS service")
		return err
	}
	if appliedVirtualServer == nil {
		return errors.New("IPVS virtual service does not exist")
	}

	// curEndpoints 用于存储当前系统中的 IPVS 目的地址
	curEndpoints := sets.New[string]()
	curDests, err := proxier.ipvs.GetRealServers(appliedVirtualServer)
	if err != nil {
		klog.ErrorS(err, "Failed to list IPVS destinations")
		return err
	}
	for _, des := range curDests {
		curEndpoints.Insert(des.String())
	}

	endpoints := proxier.endpointsMap[svcPortName]

	// 过滤拓扑感知的端点。只有在适当的特性开关启用且 Service 没有冲突的配置（如 externalTrafficPolicy=Local）时，才会过滤端点。
	svcInfo, ok := proxier.svcPortMap[svcPortName]
	if !ok {
		klog.InfoS("Unable to filter endpoints due to missing service info", "servicePortName", svcPortName)
	} else {
		clusterEndpoints, localEndpoints, _, hasAnyEndpoints := proxy.CategorizeEndpoints(endpoints, svcInfo, proxier.nodeLabels)
		if onlyNodeLocalEndpoints {
			if len(localEndpoints) > 0 {
				endpoints = localEndpoints
			} else {
				// https://github.com/kubernetes/kubernetes/pull/97081
				// Allow access from local PODs even if no local endpoints exist.
				// Traffic from an external source will be routed but the reply
				// will have the POD address and will be discarded.
				endpoints = clusterEndpoints

				if hasAnyEndpoints && svcInfo.InternalPolicyLocal() {
					proxier.serviceNoLocalEndpointsInternal.Insert(svcPortName.NamespacedName.String())
				}

				if hasAnyEndpoints && svcInfo.ExternalPolicyLocal() {
					proxier.serviceNoLocalEndpointsExternal.Insert(svcPortName.NamespacedName.String())
				}
			}
		} else {
			endpoints = clusterEndpoints
		}
	}

	newEndpoints := sets.New[string]()
	for _, epInfo := range endpoints {
		newEndpoints.Insert(epInfo.String())
	}

	// 创建新的端点
	for _, ep := range sets.List(newEndpoints) {
		ip, port, err := net.SplitHostPort(ep)
		if err != nil {
			klog.ErrorS(err, "Failed to parse endpoint", "endpoint", ep)
			continue
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			klog.ErrorS(err, "Failed to parse endpoint port", "port", port)
			continue
		}

		newDest := &utilipvs.RealServer{
			Address: netutils.ParseIPSloppy(ip),
			Port:    uint16(portNum),
			Weight:  1,
		}

		if curEndpoints.Has(ep) {
			// 如果是首次同步，循环遍历所有当前目的地址并重置其权重。
			if proxier.initialSync {
				for _, dest := range curDests {
					if dest.Weight != newDest.Weight {
						err = proxier.ipvs.UpdateRealServer(appliedVirtualServer, newDest)
						if err != nil {
							klog.ErrorS(err, "Failed to update destination", "newDest", newDest)
							continue
						}
					}
				}
			}
			// 检查新的端点是否在优雅删除列表中，如果是，则立即删除该端点。
			uniqueRS := GetUniqueRSName(vs, newDest)
			if !proxier.gracefuldeleteManager.InTerminationList(uniqueRS) {
				continue
			}
			klog.V(5).InfoS("new ep is in graceful delete list", "uniqueRealServer", uniqueRS)
			err := proxier.gracefuldeleteManager.MoveRSOutofGracefulDeleteList(uniqueRS)
			if err != nil {
				klog.ErrorS(err, "Failed to delete endpoint in gracefulDeleteQueue", "endpoint", ep)
				continue
			}
		}
		err = proxier.ipvs.AddRealServer(appliedVirtualServer, newDest)
		if err != nil {
			klog.ErrorS(err, "Failed to add destination", "newDest", newDest)
			continue
		}
	}

	// 删除旧的端点
	for _, ep := range curEndpoints.Difference(newEndpoints).UnsortedList() {
		// 如果当前端点在优雅删除列表中，则跳过
		uniqueRS := vs.String() + "/" + ep
		if proxier.gracefuldeleteManager.InTerminationList(uniqueRS) {
			continue
		}
		ip, port, err := net.SplitHostPort(ep)
		if err != nil {
			klog.ErrorS(err, "Failed to parse endpoint", "endpoint", ep)
			continue
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			klog.ErrorS(err, "Failed to parse endpoint port", "port", port)
			continue
		}

		delDest := &utilipvs.RealServer{
			Address: netutils.ParseIPSloppy(ip),
			Port:    uint16(portNum),
		}

		klog.V(5).InfoS("Using graceful delete", "uniqueRealServer", uniqueRS)
		err = proxier.gracefuldeleteManager.GracefulDeleteRS(appliedVirtualServer, delDest)
		if err != nil {
			klog.ErrorS(err, "Failed to delete destination", "uniqueRealServer", uniqueRS)
			continue
		}
	}
	return nil
}
```

#### cleanLegacyService

```go
func (proxier *Proxier) cleanLegacyService(activeServices sets.Set[string], currentServices map[string]*utilipvs.VirtualServer) {
	// 清理过期的服务
	for cs, svc := range currentServices {
		if proxier.isIPInExcludeCIDRs(svc.Address) {
			// 如果服务的地址在排除的CIDR范围内，则跳过
			continue
		}
		if getIPFamily(svc.Address) != proxier.ipFamily {
			// 如果地址族与指定的地址族不匹配，则跳过
			continue
		}
		if !activeServices.Has(cs) {
			klog.V(4).InfoS("Delete service", "virtualServer", svc)
			// 删除服务
			if err := proxier.ipvs.DeleteVirtualServer(svc); err != nil {
				klog.ErrorS(err, "Failed to delete service", "virtualServer", svc)
			}
		}
	}
}
```

## OnEndpointSliceAdd

```GO
// OnEndpointSliceAdd 是在观察到创建新的 endpoint slice 对象时调用的函数。
func (proxier *Proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

### EndpointSliceUpdate

```GO
// EndpointSliceUpdate 根据<previous, current>端点对更新给定服务的端点更改映射。
// 如果有更改，返回true；否则返回false。将添加/更新/删除 EndpointsChangeMap 的项。
// 如果 removeSlice 为 true，则删除该 slice，否则添加或更新它。
func (ect *EndpointChangeTracker) EndpointSliceUpdate(endpointSlice *discovery.EndpointSlice, removeSlice bool) bool {
	if !supportedEndpointSliceAddressTypes.Has(string(endpointSlice.AddressType)) {
		klog.V(4).InfoS("EndpointSlice 的地址类型不被 kube-proxy 支持", "addressType", endpointSlice.AddressType)
		return false
	}

	// 这应该永远不会发生
	if endpointSlice == nil {
		klog.ErrorS(nil, "传递给 EndpointSliceUpdate 的 endpointSlice 为 nil")
		return false
	}

	namespacedName, _, err := endpointSliceCacheKeys(endpointSlice)
	if err != nil {
		klog.InfoS("获取 endpoint slice 缓存键时发生错误", "err", err)
		return false
	}

	metrics.EndpointChangesTotal.Inc()

	ect.lock.Lock()
	defer ect.lock.Unlock()

	changeNeeded := ect.endpointSliceCache.updatePending(endpointSlice, removeSlice)

	if changeNeeded {
		metrics.EndpointChangesPending.Inc()
		// 对于 Endpoints 的删除情况，LastChangeTriggerTime 注解是从最后一次更新的时间开始的，
		// 这不是我们想要测量的。因此，在这种情况下我们只是简单地忽略它。
		// TODO（wojtek-t，robscott）：处理 EndpointSlice 删除的问题，即使仍存在该服务的其他 EndpointSlice。
		if removeSlice {
			delete(ect.lastChangeTriggerTimes, namespacedName)
		} else if t := getLastChangeTriggerTime(endpointSlice.Annotations); !t.IsZero() && t.After(ect.trackerStartTime) {
			ect.lastChangeTriggerTimes[namespacedName] =
				append(ect.lastChangeTriggerTimes[namespacedName], t)
		}
	}

	return changeNeeded
}
```

#### endpointSliceCacheKeys

```GO
// endpointSliceCacheKeys 返回给定 EndpointSlice 的缓存键。
func endpointSliceCacheKeys(endpointSlice *discovery.EndpointSlice) (types.NamespacedName, string, error) {
	var err error
	serviceName, ok := endpointSlice.Labels[discovery.LabelServiceName]
	if !ok || serviceName == "" {
		err = fmt.Errorf("在 endpoint slice 上未设置 %s 标签： %s", discovery.LabelServiceName, endpointSlice.Name)
	} else if endpointSlice.Namespace == "" || endpointSlice.Name == "" {
		err = fmt.Errorf("期望设置 EndpointSlice 的名称和命名空间： %v", endpointSlice)
	}
	return types.NamespacedName{Namespace: endpointSlice.Namespace, Name: serviceName}, endpointSlice.Name, err
}
```

##### getLastChangeTriggerTime

```GO
// getLastChangeTriggerTime 返回给定 endpoints 对象中存储的 EndpointsLastChangeTriggerTime 注解的 time.Time 值，
// 如果未设置或设置不正确，则返回“零”时间。
func getLastChangeTriggerTime(annotations map[string]string) time.Time {
	// TODO（#81360）：忽略删除 Endpoint 的情况。
	if _, ok := annotations[v1.EndpointsLastChangeTriggerTime]; !ok {
		// 可能 Endpoints 对象没有设置 EndpointsLastChangeTriggerTime 注解。在这种情况下返回“零值”，在上游代码中被忽略。
		return time.Time{}
	}
	val, err := time.Parse(time.RFC3339Nano, annotations[v1.EndpointsLastChangeTriggerTime])
	if err != nil {
		klog.ErrorS(err, "解析 EndpointsLastChangeTriggerTime 注解时发生错误",
			"value", annotations[v1.EndpointsLastChangeTriggerTime])
		// 如果发生错误，val = time.Zero，这在上游代码中被忽略。
	}
	return val
}
```

## OnEndpointSliceUpdate

```GO
// OnEndpointSliceUpdate 是在观察到修改现有的 endpoint slice 对象时调用的函数。
func (proxier *Proxier) OnEndpointSliceUpdate(_, endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

## OnEndpointSliceDelete

```GO
// OnEndpointSliceDelete 是在观察到删除现有的 endpoint slice 对象时调用的函数。
func (proxier *Proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, true) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

## OnEndpointSlicesSynced

```GO
// OnEndpointSlicesSynced 在所有初始事件处理程序被调用且状态完全传播到本地缓存之后调用。
func (proxier *Proxier) OnEndpointSlicesSynced() {
	proxier.mu.Lock()
	proxier.endpointSlicesSynced = true
	proxier.setInitialized(proxier.servicesSynced)
	proxier.mu.Unlock()

	// 无条件同步 - 这是一次性调用。
	proxier.syncProxyRules()
}
```

## OnServiceAdd

```GO
// OnServiceAdd 在观察到创建新的 service 对象时调用。
func (proxier *Proxier) OnServiceAdd(service *v1.Service) {
	proxier.OnServiceUpdate(nil, service)
}
```

### Update

```GO
// Update 根据<previous, current>服务对更新给定服务的更改映射。
// 如果有更改，返回true；否则返回false。将添加/更新/删除 ServiceChangeMap 的项。
// 例如，
// 添加项
//   - 将 <nil, service> 作为 <previous, current> 对传递。
//
// 更新项
//   - 将 <oldService, service> 作为 <previous, current> 对传递。
//
// 删除项
//   - 将 <service, nil> 作为 <previous, current> 对传递。
func (sct *ServiceChangeTracker) Update(previous, current *v1.Service) bool {
	// 这是意外情况，直接返回false。
	if previous == nil && current == nil {
		return false
	}

	svc := current
	if svc == nil {
		svc = previous
	}
	metrics.ServiceChangesTotal.Inc()
	namespacedName := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}

	sct.lock.Lock()
	defer sct.lock.Unlock()

	change, exists := sct.items[namespacedName]
	if !exists {
		change = &serviceChange{}
		change.previous = sct.serviceToServiceMap(previous)
		sct.items[namespacedName] = change
	}
	change.current = sct.serviceToServiceMap(current)
	// 如果 change.previous 等于 change.current，则表示没有更改
	if reflect.DeepEqual(change.previous, change.current) {
		delete(sct.items, namespacedName)
	} else {
		klog.V(4).InfoS("Service updated ports", "service", klog.KObj(svc), "portCount", len(change.current))
	}
	metrics.ServiceChangesPending.Set(float64(len(sct.items)))
	return len(sct.items) > 0
}
```

#### serviceToServiceMap

```GO
// serviceToServiceMap 将单个 Service 对象转换为 ServicePortMap。
//
// 注意：不应修改 service 对象。
func (sct *ServiceChangeTracker) serviceToServiceMap(service *v1.Service) ServicePortMap {
	if service == nil {
		return nil
	}

	if proxyutil.ShouldSkipService(service) {
		return nil
	}

	clusterIP := proxyutil.GetClusterIPByFamily(sct.ipFamily, service)
	if clusterIP == "" {
		return nil
	}

	svcPortMap := make(ServicePortMap)
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	for i := range service.Spec.Ports {
		servicePort := &service.Spec.Ports[i]
		svcPortName := ServicePortName{NamespacedName: svcName, Port: servicePort.Name, Protocol: servicePort.Protocol}
		baseSvcInfo := sct.newBaseServiceInfo(servicePort, service)
		if sct.makeServiceInfo != nil {
			svcPortMap[svcPortName] = sct.makeServiceInfo(servicePort, service, baseSvcInfo)
		} else {
			svcPortMap[svcPortName] = baseSvcInfo
		}
	}
	return svcPortMap
}
```

## OnServiceUpdate

```GO
// OnServiceUpdate 在观察到修改现有的 service 对象时调用。
func (proxier *Proxier) OnServiceUpdate(oldService, service *v1.Service) {
	if proxier.serviceChanges.Update(oldService, service) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

## OnServiceDelete

```GO
// OnServiceDelete 在观察到删除现有的 service 对象时调用。
func (proxier *Proxier) OnServiceDelete(service *v1.Service) {
	proxier.OnServiceUpdate(service, nil)
}
```

## OnServiceSynced

```GO
// OnServiceSynced 在所有初始事件处理程序被调用且状态完全传播到本地缓存之后调用。
func (proxier *Proxier) OnServiceSynced() {
	proxier.mu.Lock()
	proxier.servicesSynced = true
	proxier.setInitialized(proxier.endpointSlicesSynced)
	proxier.mu.Unlock()

	// 无条件同步 - 这是一次性调用。
	proxier.syncProxyRules()
}
```

## OnNodeAdd

```GO
// OnNodeAdd 在观察到创建新的节点对象时调用。
func (proxier *Proxier) OnNodeAdd(node *v1.Node) {
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node", "eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	if reflect.DeepEqual(proxier.nodeLabels, node.Labels) {
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = map[string]string{}
	for k, v := range node.Labels {
		proxier.nodeLabels[k] = v
	}
	proxier.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node labels", "labels", node.Labels)

	proxier.Sync()
}
```

## OnNodeUpdate

```GO
// OnNodeUpdate 在观察到修改现有节点对象时调用。
func (proxier *Proxier) OnNodeUpdate(oldNode, node *v1.Node) {
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node", "eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	if reflect.DeepEqual(proxier.nodeLabels, node.Labels) {
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = map[string]string{}
	for k, v := range node.Labels {
		proxier.nodeLabels[k] = v
	}
	proxier.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node labels", "labels", node.Labels)

	proxier.Sync()
}
```

## OnNodeDelete

```GO
// OnNodeDelete 在观察到删除现有节点对象时调用。
func (proxier *Proxier) OnNodeDelete(node *v1.Node) {
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node", "eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}
	proxier.mu.Lock()
	proxier.nodeLabels = nil
	proxier.mu.Unlock()

	proxier.Sync()
}
```

## OnNodeSynced

```GO
// OnNodeSynced 在所有初始事件处理程序被调用且状态完全传播到本地缓存之后调用。
func (proxier *Proxier) OnNodeSynced() {
}
```

## Sync

```GO
// Sync 在最快时间内将 proxier 的状态与 iptables 和 ipvs 同步。
func (proxier *Proxier) Sync() {
	if proxier.healthzServer != nil {
		proxier.healthzServer.QueuedUpdate()
	}
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	proxier.syncRunner.Run()
}
```

## SyncLoop

```GO
// SyncLoop 运行周期性的工作。预计作为 goroutine 或应用程序的主循环运行。它不返回。
func (proxier *Proxier) SyncLoop() {
	// 在开始时更新健康检查时间戳，以防 Sync() 永远不成功。
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated()
	}
	// 在 informers 同步时合成 "上次更改排队" 时间。
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	proxier.syncRunner.Loop(wait.NeverStop)
}
```

