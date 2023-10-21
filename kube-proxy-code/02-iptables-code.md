
## utiliptables.Interface

```go
// Interface是一个可注入的接口，用于运行iptables命令。实现必须是协程安全的。
type Interface interface {
    // EnsureChain检查指定的链是否存在，如果不存在，则创建它。如果链存在，则返回true。
    EnsureChain(table Table, chain Chain) (bool, error)
    // FlushChain清除指定的链。如果链不存在，则返回错误。
    FlushChain(table Table, chain Chain) error

    // DeleteChain删除指定的链。如果链不存在，则返回错误。
    DeleteChain(table Table, chain Chain) error

    // ChainExists测试指定的链是否存在，如果不存在或无法检查，则返回错误。
    ChainExists(table Table, chain Chain) (bool, error)

    // EnsureRule检查指定的规则是否存在，如果不存在，则创建它。如果规则存在，则返回true。
    EnsureRule(position RulePosition, table Table, chain Chain, args ...string) (bool, error)

    // DeleteRule检查指定的规则是否存在，如果存在，则删除它。
    DeleteRule(table Table, chain Chain, args ...string) error

    // IsIPv6如果管理ipv6表，则返回true。
    IsIPv6() bool

    // Protocol返回此实例正在管理的IP系列。
    Protocol() Protocol

    // SaveInto调用`iptables-save`来保存表的数据，并将结果存储在给定的缓冲区中。
    SaveInto(table Table, buffer *bytes.Buffer) error

    // Restore运行`iptables-restore`并通过[]byte传递数据。
    // table是要还原的表
    // data应该格式化为SaveInto()的输出格式
    // flush设置"--noflush"标志的存在。参见：FlushFlag
    // counters设置"--counters"标志的存在。参见：RestoreCountersFlag
    Restore(table Table, data []byte, flush FlushFlag, counters RestoreCountersFlag) error

    // RestoreAll与Restore相同，只是不指定表。
    RestoreAll(data []byte, flush FlushFlag, counters RestoreCountersFlag) error

    // Monitor通过创建标记链并轮询以检查它们是否已被删除来检测给定的iptables表是否已被外部工具（例如防火墙重新加载）清空。
    // （具体来说，它每隔一段时间轮询tables[0]，直到canary从那里被删除，然后再等待一段时间，等待canary从剩余的表中被删除。您可以通过在tables[0]中列出一个相对较空的表来优化轮询）。当检测到清空时，调用reloadFunc，以便调用者可以重新加载自己的iptables规则。
    // 如果无法创建canary链（初始或重新加载后），它将记录错误并停止监视。
    // （此函数应从goroutine中调用。）
    Monitor(canary Chain, tables []Table, reloadFunc func(), interval time.Duration, stopCh <-chan struct{})

    // HasRandomFully揭示`-j MASQUERADE`是否接受`--random-fully`选项。这对于解决Linux内核中的一个错误很有帮助，该错误有时会导致多个流映射到相同的IP:PORT，从而导致某些数据包丢失。
    HasRandomFully() bool

    // Present检查内核是否支持iptables接口
    Present() bool
}
```

### Table

```go
// Table表示不同的iptables表，如filter、nat、mangle和raw
type Table string

const (
    // TableNAT表示内置的nat表
    TableNAT Table = "nat"
    // TableFilter表示内置的filter表
    TableFilter Table = "filter"
    // TableMangle表示内置的mangle表
    TableMangle Table = "mangle"
)
```

### Chain

```go
// Chain表示不同的规则
type Chain string

const (
    // ChainPostrouting用于nat表中的源地址转换
    ChainPostrouting Chain = "POSTROUTING"
    // ChainPrerouting用于nat表中的目标地址转换
    ChainPrerouting Chain = "PREROUTING"
    // ChainOutput用于从本地发送的数据包
    ChainOutput Chain = "OUTPUT"
    // ChainInput用于传入的数据包
    ChainInput Chain = "INPUT"
    // ChainForward用于另一个网卡的数据包
    ChainForward Chain = "FORWARD"
)
```

### RulePosition

```go
// RulePosition保存iptables的-I/-A标志
type RulePosition string

const (
    // Prepend是iptables的插入标志
    Prepend RulePosition = "-I"
    // Append是iptables的追加标志
    Append RulePosition = "-A"
)
```

### FlushFlag

```go
// FlushFlag是Flush的选项标志
type FlushFlag bool

// FlushTables是FlushFlag选项标志的布尔值为true的常量
const FlushTables FlushFlag = true

// NoFlushTables是FlushFlag选项标志的布尔值为false的常量
const NoFlushTables FlushFlag = false

// RestoreCountersFlag是Restore的选项标志
type RestoreCountersFlag bool

// RestoreCounters是RestoreCountersFlag选项标志的布尔值为true的常量
const RestoreCounters RestoreCountersFlag = true

// NoRestoreCounters是RestoreCountersFlag选项标志的布尔值为false的常量
const NoRestoreCounters RestoreCountersFlag = false
```

### Protocol

```go
// Protocol定义IP协议，可以是IPv4或IPv6
type Protocol string

const (
    // ProtocolIPv4表示iptables中的IPv4协议
    ProtocolIPv4 Protocol = "IPv4"
    // ProtocolIPv6表示iptables中的IPv6协议
    ProtocolIPv6 Protocol = "IPv6"
)
```

### operation

```go
type operation string

// 定义操作类型常量
const (
	opCreateChain operation = "-N"
	opFlushChain  operation = "-F"
	opDeleteChain operation = "-X"
	opListChain   operation = "-S"
	opCheckRule   operation = "-C"
	opDeleteRule  operation = "-D"
)
```

### oether

```go
const (
    cmdIPTablesSave string = "iptables-save"
    cmdIPTablesRestore string = "iptables-restore"
    cmdIPTables string = "iptables"
    cmdIP6TablesRestore string = "ip6tables-restore"
    cmdIP6TablesSave string = "ip6tables-save"
    cmdIP6Tables string = "ip6tables"
)

// MinCheckVersion 是需要检查的最低版本。
// 低于此版本的 iptables 不支持 -C / --check 标志（用于测试规则是否存在）。
var MinCheckVersion = utilversion.MustParseGeneric("1.4.11")

// RandomFullyMinVersion 是支持 --random-fully 标志的最低版本，
// 用于完全随机化端口映射。
var RandomFullyMinVersion = utilversion.MustParseGeneric("1.6.2")

// WaitMinVersion 是支持 -w 和 -w<seconds> 标志的最低 iptables 版本。
var WaitMinVersion = utilversion.MustParseGeneric("1.4.20")

// WaitIntervalMinVersion 是支持等待间隔 useconds 的最低 iptables 版本。
var WaitIntervalMinVersion = utilversion.MustParseGeneric("1.6.1")

// WaitSecondsMinVersion 是支持等待秒数的最低 iptables 版本。
var WaitSecondsMinVersion = utilversion.MustParseGeneric("1.4.22")

// WaitRestoreMinVersion 是支持等待恢复秒数的最低 iptables 版本。
var WaitRestoreMinVersion = utilversion.MustParseGeneric("1.6.2")

// WaitString 是用于指定等待标志的常量。
const WaitString = "-w"

// WaitSecondsValue 是用于指定默认等待秒数的常量。
const WaitSecondsValue = "5"

// WaitIntervalString 是用于指定等待间隔标志的常量。
const WaitIntervalString = "-W"

// WaitIntervalUsecondsValue 是用于指定默认等待间隔微秒数的常量。
const WaitIntervalUsecondsValue = "100000"

// LockfilePath16x 是 iptables 1.6.x 版本的锁文件路径，由对 iptable 规则进行更改的任何进程获取。
const LockfilePath16x = "/run/xtables.lock"

// LockfilePath14x 是 iptables 1.4.x 版本的锁文件路径，由对 iptable 规则进行更改的任何进程获取。
const LockfilePath14x = "@xtables"
```

## runner

```go
// runner通过执行"iptables"命令实现了Interface接口。
type runner struct {
    mu sync.Mutex // 使用互斥锁来保证并发安全
    exec utilexec.Interface // 执行命令的接口
    protocol Protocol // 协议类型
    hasCheck bool // 是否支持iptables的-C选项（检查规则是否存在）
    hasRandomFully bool // 是否支持iptables的--random-fully选项
    waitFlag []string // 执行iptables命令时的等待选项
    restoreWaitFlag []string // 执行iptables-restore命令时的等待选项
    lockfilePath14x string // iptables-restore的锁文件路径（适用于iptables 1.4.x版本）
    lockfilePath16x string // iptables-restore的锁文件路径（适用于iptables 1.6.x版本）
}
```

### New

```go

// newInternal返回一个新的Interface，它将执行iptables命令，并允许调用者更改iptables-restore的锁文件路径。
func newInternal(exec utilexec.Interface, protocol Protocol, lockfilePath14x, lockfilePath16x string) Interface {
    version, err := getIPTablesVersion(exec, protocol) // 获取iptables的版本信息
    if err != nil {
        klog.InfoS("Error checking iptables version, assuming version at least", "version", MinCheckVersion, "err", err)
        version = MinCheckVersion // 如果获取版本信息失败，则假设版本至少为MinCheckVersion
    }
	if lockfilePath16x == "" {
        lockfilePath16x = LockfilePath16x  // 如果lockfilePath16x为空，则使用默认的锁文件路径
    } 
    if lockfilePath14x == "" {
        lockfilePath14x = LockfilePath14x  // 如果lockfilePath14x为空，则使用默认的锁文件路径
    }

    runner := &runner{
        exec:            exec,
        protocol:        protocol,
        hasCheck:        version.AtLeast(MinCheckVersion), // 检查是否支持-C选项
        hasRandomFully:  version.AtLeast(RandomFullyMinVersion), // 检查是否支持--random-fully选项
        waitFlag:        getIPTablesWaitFlag(version),  // 获取iptables命令的等待选项
        restoreWaitFlag: getIPTablesRestoreWaitFlag(version, exec, protocol),  // 获取iptables-restore的wait标志参数
        lockfilePath14x: lockfilePath14x,
        lockfilePath16x: lockfilePath16x,
    }
    return runner
}

// New返回一个新的Interface，它将执行iptables命令。
func New(exec utilexec.Interface, protocol Protocol) Interface {
	return newInternal(exec, protocol, "", "")
}
```

#### utilexec.Interface

```go
// Interface 是一个接口，它提供了一组 os/exec API 的子集。在需要注入可伪造/可模拟的 exec 行为时使用该接口。
type Interface interface {
    // Command 返回一个 Cmd 实例，用于运行单个命令。遵循 package os/exec 的模式。
    Command(cmd string, args ...string) Cmd
	// CommandContext 返回一个 Cmd 实例，用于运行单个命令。
    //
    // 如果上下文在命令完成之前变为完成状态，将使用提供的上下文来终止进程。例如，可以在上下文中设置超时。
    CommandContext(ctx context.Context, cmd string, args ...string) Cmd

    // LookPath 包装了 os/exec.LookPath
    LookPath(file string) (string, error)
}

// executor 在真正执行 exec() 的情况下实现了 Interface 接口。
type executor struct{}

// New 返回一个新的 Interface，它将使用 os/exec 来运行命令。
func New() Interface {
	return &executor{}
}

// Command 是 Interface 接口的一部分。
func (executor *executor) Command(cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.Command(cmd, args...)))
}

// CommandContext 是 Interface 接口的一部分。
func (executor *executor) CommandContext(ctx context.Context, cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.CommandContext(ctx, cmd, args...)))
}

// LookPath 是 Interface 接口的一部分。
func (executor *executor) LookPath(file string) (string, error) {
	path, err := osexec.LookPath(file)
	return path, handleError(maskErrDot(err))
}
```

##### Cmd

```GO
// Cmd 是一个接口，它提供了与 os/exec 中的 Cmd 非常相似的 API。随着需要更多功能，它可以扩展。由于 Cmd 是一个结构体，我们将使用 get/set 方法对来替换字段。
type Cmd interface {
    // Run 运行命令直到完成。
    Run() error
    // CombinedOutput 运行命令并返回其合并的标准输出和标准错误。遵循 package os/exec 的模式。
    CombinedOutput() ([]byte, error)
    // Output 运行命令并返回标准输出，但不返回标准错误。
    Output() ([]byte, error)
    SetDir(dir string)
    SetStdin(in io.Reader)
    SetStdout(out io.Writer)
    SetStderr(out io.Writer)
    SetEnv(env []string)

    // StdoutPipe 和 StderrPipe 用于获取进程的 Stdout 和 Stderr 作为读取器。
    StdoutPipe() (io.ReadCloser, error)
    StderrPipe() (io.ReadCloser, error)

    // Start 和 Wait 用于非阻塞地运行进程。
    Start() error
    Wait() error

    // Stop 通过发送 SIGTERM 来停止命令。无法保证进程在此函数返回之前停止。如果进程不响应，内部计时器函数将在10秒后发送 SIGKILL 强制终止。
    Stop()
}

// executor 在真正执行 exec() 的情况下实现了 Interface 接口。
type executor struct{}

// New 返回一个新的 Interface，它将使用 os/exec 来运行命令。
func New() Interface {
	return &executor{}
}

// Command 是 Interface 接口的一部分。
func (executor *executor) Command(cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.Command(cmd, args...)))
}

// CommandContext 是 Interface 接口的一部分。
func (executor *executor) CommandContext(ctx context.Context, cmd string, args ...string) Cmd {
	return (*cmdWrapper)(maskErrDotCmd(osexec.CommandContext(ctx, cmd, args...)))
}

// LookPath 是 Interface 接口的一部分。
func (executor *executor) LookPath(file string) (string, error) {
    path, err := osexec.LookPath(file)
    return path, handleError(maskErrDot(err))
}

// cmdWrapper 包装了 exec.Cmd，以便我们可以捕获错误。
type cmdWrapper osexec.Cmd

var _ Cmd = &cmdWrapper{}

func (cmd *cmdWrapper) SetDir(dir string) {
	cmd.Dir = dir
}

func (cmd *cmdWrapper) SetStdin(in io.Reader) {
	cmd.Stdin = in
}

func (cmd *cmdWrapper) SetStdout(out io.Writer) {
	cmd.Stdout = out
}

func (cmd *cmdWrapper) SetStderr(out io.Writer) {
	cmd.Stderr = out
}

func (cmd *cmdWrapper) SetEnv(env []string) {
	cmd.Env = env
}

func (cmd *cmdWrapper) StdoutPipe() (io.ReadCloser, error) {
    r, err := (*osexec.Cmd)(cmd).StdoutPipe()
    return r, handleError(err)
}

func (cmd *cmdWrapper) StderrPipe() (io.ReadCloser, error) {
    r, err := (*osexec.Cmd)(cmd).StderrPipe()
    return r, handleError(err)
}

func (cmd *cmdWrapper) Start() error {
    err := (*osexec.Cmd)(cmd).Start()
    return handleError(err)
}

func (cmd *cmdWrapper) Wait() error {
    err := (*osexec.Cmd)(cmd).Wait()
    return handleError(err)
}

// Run 是 Cmd 接口的一部分。
func (cmd *cmdWrapper) Run() error {
    err := (*osexec.Cmd)(cmd).Run()
    return handleError(err)
}

// CombinedOutput 是 Cmd 接口的一部分。
func (cmd *cmdWrapper) CombinedOutput() ([]byte, error) {
    out, err := (*osexec.Cmd)(cmd).CombinedOutput()
    return out, handleError(err)
}

func (cmd *cmdWrapper) Output() ([]byte, error) {
    out, err := (*osexec.Cmd)(cmd).Output()
    return out, handleError(err)
}

// Stop 是 Cmd 接口的一部分。
func (cmd *cmdWrapper) Stop() {
    c := (*osexec.Cmd)(cmd)

    if c.Process == nil {
        return
    }

    c.Process.Signal(syscall.SIGTERM)

    time.AfterFunc(10*time.Second, func() {
        if !c.ProcessState.Exited() {
            c.Process.Signal(syscall.SIGKILL)
        }
    })
}

func handleError(err error) error {
    if err == nil {
        return nil
    }

    switch e := err.(type) {
    case *osexec.ExitError:
        return &ExitErrorWrapper{e}
    case *fs.PathError:
        return ErrExecutableNotFound
    case *osexec.Error:
        if e.Err == osexec.ErrNotFound {
            return ErrExecutableNotFound
        }
    }

    return err
}
```

##### handleError

```GO
func handleError(err error) error {
    // 如果 err 为 nil，则返回 nil，表示没有错误。
    if err == nil {
        return nil
    }

    switch e := err.(type) {
    case *osexec.ExitError:
        // 如果 err 类型为 *osexec.ExitError，则返回一个 ExitErrorWrapper，将 err 包装起来。
        return &ExitErrorWrapper{e}
    case *fs.PathError:
        // 如果 err 类型为 *fs.PathError，则返回 ErrExecutableNotFound，表示可执行文件未找到。
        return ErrExecutableNotFound
    case *osexec.Error:
        if e.Err == osexec.ErrNotFound {
            // 如果 err 的内部错误为 osexec.ErrNotFound，则返回 ErrExecutableNotFound，表示可执行文件未找到。
            return ErrExecutableNotFound
        }
    }

    return err
}
```

###### ExitError

```go
// ExitError 是一个接口，提供了与 os.ProcessState 类似的 API，os/exec 中的 ExitError 就是这样的类型。
// 这个接口设计得更易于测试，可能会失去底层库的某些跨平台特性。
type ExitError interface {
    String() string
    Error() string
    Exited() bool
    ExitStatus() int
}
```

###### ExitErrorWrapper&ErrExecutableNotFound

```go
// ExitErrorWrapper 是基于 os/exec.ExitError 实现的 ExitError。
// 注意：标准的 exec.ExitError 是类型 *os.ProcessState，而它已经实现了 Exited()。
type ExitErrorWrapper struct {
	*osexec.ExitError
}

var _ ExitError = &ExitErrorWrapper{}

// ExitStatus 是 ExitError 接口的一部分。
func (eew ExitErrorWrapper) ExitStatus() int {
    ws, ok := eew.Sys().(syscall.WaitStatus)
    if !ok {
    	panic("can't call ExitStatus() on a non-WaitStatus exitErrorWrapper")
    }
    return ws.ExitStatus()
}

// ErrExecutableNotFound 表示未找到可执行文件时返回的错误。
var ErrExecutableNotFound = osexec.ErrNotFound
```

#### getIPTablesVersion

```go
// getIPTablesVersion 运行 "iptables --version" 命令并解析返回的版本信息。
const iptablesVersionPattern = v([0-9]+(\.[0-9]+)+)

func getIPTablesVersion(exec utilexec.Interface, protocol Protocol) (*utilversion.Version, error) {
    // 这里不访问可变状态，因此不需要使用接口/运行器。
    iptablesCmd := iptablesCommand(protocol)
    bytes, err := exec.Command(iptablesCmd, "--version").CombinedOutput()
    if err != nil {
    	return nil, err
    }
    versionMatcher := regexp.MustCompile(iptablesVersionPattern)
    match := versionMatcher.FindStringSubmatch(string(bytes))
    if match == nil {
    	return nil, fmt.Errorf("no iptables version found in string: %s", bytes)
    }
    version, err := utilversion.ParseGeneric(match[1])
    if err != nil {
    	return nil, fmt.Errorf("iptables version %q is not a valid version string: %v", match[1], err)
    }

    return version, nil
}
```

#### iptablesCommand

```go
func iptablesCommand(protocol Protocol) string {
    if protocol == ProtocolIPv6 {
    	return cmdIP6Tables
    }
    return cmdIPTables
}
```

#### getIPTablesWaitFlag

```go
// getIPTablesWaitFlag 检查 iptables 版本是否具有 "wait" 标志。
func getIPTablesWaitFlag(version *utilversion.Version) []string {
    switch {
        case version.AtLeast(WaitIntervalMinVersion):
        	return []string{WaitString, WaitSecondsValue, WaitIntervalString, WaitIntervalUsecondsValue}
        case version.AtLeast(WaitSecondsMinVersion):
        	return []string{WaitString, WaitSecondsValue}
        case version.AtLeast(WaitMinVersion):
        	return []string{WaitString}
        default:
        	return nil
    }
}
```

#### getIPTablesRestoreWaitFlag

```GO
// getIPTablesRestoreWaitFlag 检查 iptables-restore 版本是否具有 "wait" 标志。
func getIPTablesRestoreWaitFlag(version *utilversion.Version, exec utilexec.Interface, protocol Protocol) []string {
    if version.AtLeast(WaitRestoreMinVersion) {
    	return []string{WaitString, WaitSecondsValue, WaitIntervalString, WaitIntervalUsecondsValue}
    }

    // 较旧的版本可能已经反向移植了一些功能；如果 iptables-restore 支持 --version，
    // 假设它也支持 --wait。
    vstring, err := getIPTablesRestoreVersionString(exec, protocol)
    if err != nil || vstring == "" {
        klog.V(3).InfoS("Couldn't get iptables-restore version; assuming it doesn't support --wait")
        return nil
    }
    if _, err := utilversion.ParseGeneric(vstring); err != nil {
        klog.V(3).InfoS("Couldn't parse iptables-restore version; assuming it doesn't support --wait")
        return nil
    }
    return []string{WaitString}
}
```

##### getIPTablesRestoreVersionString

```GO
// getIPTablesRestoreVersionString 运行 "iptables-restore --version" 命令获取版本字符串，
// 格式为 "X.X.X"。
func getIPTablesRestoreVersionString(exec utilexec.Interface, protocol Protocol) (string, error) {
    // 这里不访问可变状态，因此不需要使用接口/运行器。

    // iptables-restore 并不总是有 --version，更糟糕的是，在遇到无法识别的命令时，它不会退出。
    // 通过将 stdin 设置为无内容来解决该问题，这样它会立即退出。
    iptablesRestoreCmd := iptablesRestoreCommand(protocol)
    cmd := exec.Command(iptablesRestoreCmd, "--version")
    cmd.SetStdin(bytes.NewReader([]byte{}))
    bytes, err := cmd.CombinedOutput()
    if err != nil {
        return "", err
    }
    versionMatcher := regexp.MustCompile(iptablesVersionPattern)
    match := versionMatcher.FindStringSubmatch(string(bytes))
    if match == nil {
        return "", fmt.Errorf("no iptables version found in string: %s", bytes)
    }
    return match[1], nil
}
```

### EnsureChain

```GO
// 确保链表存在的函数，属于Interface接口的一部分。
func (runner *runner) EnsureChain(table Table, chain Chain) (bool, error) {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opCreateChain，传入参数fullArgs
	out, err := runner.run(opCreateChain, fullArgs)
	if err != nil {
		// 如果发生错误，并且错误是ExitError类型的
		if ee, ok := err.(utilexec.ExitError); ok {
			// 如果进程已退出且退出状态为1，则表示链表已存在，直接返回true和nil
			if ee.Exited() && ee.ExitStatus() == 1 {
				return true, nil
			}
		}
		// 否则返回false，以及格式化后的错误信息
		return false, fmt.Errorf("error creating chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回false和nil
	return false, nil
}

```

#### makeFullArgs

```go
// 创建完整的参数列表
func makeFullArgs(table Table, chain Chain, args ...string) []string {
	return append([]string{string(chain), "-t", string(table)}, args...)
}
```

#### run

```go
// 调用runner的run函数执行操作op，传入参数args
func (runner *runner) run(op operation, args []string) ([]byte, error) {
	return runner.runContext(context.TODO(), op, args)
}

// 调用runner的runContext函数执行操作op，传入参数args
func (runner *runner) runContext(ctx context.Context, op operation, args []string) ([]byte, error) {
	// 获取iptables命令
	iptablesCmd := iptablesCommand(runner.protocol)
	// 创建完整的参数列表
	fullArgs := append(runner.waitFlag, string(op))
	fullArgs = append(fullArgs, args...)
	klog.V(5).InfoS("Running", "command", iptablesCmd, "arguments", fullArgs)
	if ctx == nil {
		// 在当前上下文中执行命令并返回输出
		return runner.exec.Command(iptablesCmd, fullArgs...).CombinedOutput()
	}
	// 在指定上下文中执行命令并返回输出
	return runner.exec.CommandContext(ctx, iptablesCmd, fullArgs...).CombinedOutput()
	// 不要在这里记录错误 - 调用者可能不认为这是一个错误。
}
```

### FlushChain

```go
// 清空链表的函数，属于Interface接口的一部分。
func (runner *runner) FlushChain(table Table, chain Chain) error {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opFlushChain，传入参数fullArgs
	out, err := runner.run(opFlushChain, fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return fmt.Errorf("error flushing chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回nil
	return nil
}
```

### DeleteChain

```go
// 删除链表的函数，属于Interface接口的一部分。
func (runner *runner) DeleteChain(table Table, chain Chain) error {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opDeleteChain，传入参数fullArgs
	out, err := runner.run(opDeleteChain, fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return fmt.Errorf("error deleting chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回nil
	return nil
}
```

### DeleteChain

```go
// 删除链表的函数，属于Interface接口的一部分。
func (runner *runner) DeleteChain(table Table, chain Chain) error {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 调用runner的run函数执行操作opDeleteChain，传入参数fullArgs
	out, err := runner.run(opDeleteChain, fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return fmt.Errorf("error deleting chain %q: %v: %s", chain, err, out)
	}
	// 没有发生错误，返回nil
	return nil
}
```

### EnsureRule

```go
// 确保规则存在的函数，属于Interface接口的一部分。
func (runner *runner) EnsureRule(position RulePosition, table Table, chain Chain, args ...string) (bool, error) {
	// 创建完整的参数列表
	fullArgs := makeFullArgs(table, chain, args...)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 检查规则是否已存在
	exists, err := runner.checkRule(table, chain, args...)
	if err != nil {
		return false, err
	}
	// 如果规则已存在，则返回true和nil
	if exists {
		return true, nil
	}
	// 规则不存在，则调用runner的run函数执行相应操作，传入参数position和fullArgs
	out, err := runner.run(operation(position), fullArgs)
	if err != nil {
		// 返回格式化后的错误信息
		return false, fmt.Errorf("error appending rule: %v: %s", err, out)
	}
	// 没有发生错误，返回false和nil
	return false, nil
}
```

#### checkRule

```go
// checkRule函数用于检查规则是否存在
// 如果能够检查规则的存在性，则返回(bool, nil)
// 如果检查过程失败，则返回(<undefined>, error)
func (runner *runner) checkRule(table Table, chain Chain, args ...string) (bool, error) {
	if runner.hasCheck {
		// 使用"-C"标志执行规则检查
		return runner.checkRuleUsingCheck(makeFullArgs(table, chain, args...))
	}
	// 否则，执行无检查的规则检查
	return runner.checkRuleWithoutCheck(table, chain, args...)
}
```

##### checkRuleUsingCheck

```go
// 使用"-C"标志执行规则检查
func (runner *runner) checkRuleUsingCheck(args []string) (bool, error) {
	// 设置超时时间为5分钟
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 调用runner的runContext函数执行操作opCheckRule，传入参数args
	out, err := runner.runContext(ctx, opCheckRule, args)
	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Errorf("timed out while checking rules")
	}
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// iptables使用exit(1)来表示操作失败，与命令行格式错误等不同。
		if ee.Exited() && ee.ExitStatus() == 1 {
			return false, nil
		}
	}
	return false, fmt.Errorf("error checking rule: %v: %s", err, out)
}
```

### DeleteRule

```go
// DeleteRule 是 Interface 接口的一部分。
func (runner *runner) DeleteRule(table Table, chain Chain, args ...string) error {
	fullArgs := makeFullArgs(table, chain, args...) // 根据给定的 table、chain 和 args 创建完整的参数列表

	runner.mu.Lock() // 加锁
	defer runner.mu.Unlock() // 解锁

	exists, err := runner.checkRule(table, chain, args...) // 检查规则是否存在
	if err != nil {
		return err
	}
	if !exists { // 如果规则不存在，则直接返回
		return nil
	}
	out, err := runner.run(opDeleteRule, fullArgs) // 执行删除规则的操作
	if err != nil {
		return fmt.Errorf("error deleting rule: %v: %s", err, out) // 如果出错，则返回带有错误信息的错误
	}
	return nil
}
```

### IsIPv6

```go
func (runner *runner) IsIPv6() bool {
	return runner.protocol == ProtocolIPv6 // 判断是否为 IPv6 协议
}
```

### Protocol

```go
func (runner *runner) Protocol() Protocol {
	return runner.protocol // 返回协议类型
}
```

### SaveInto

```go
// SaveInto 是 Interface 接口的一部分。
func (runner *runner) SaveInto(table Table, buffer *bytes.Buffer) error {
	runner.mu.Lock() // 加锁
	defer runner.mu.Unlock() // 解锁

	trace := utiltrace.New("iptables save") // 创建追踪日志
	defer trace.LogIfLong(2 * time.Second) // 在 2 秒钟后记录日志

	iptablesSaveCmd := iptablesSaveCommand(runner.protocol) // 获取 iptables 保存命令
	args := []string{"-t", string(table)} // 创建参数列表
	klog.V(4).InfoS("Running", "command", iptablesSaveCmd, "arguments", args) // 记录日志

	cmd := runner.exec.Command(iptablesSaveCmd, args...) // 创建命令对象
	cmd.SetStdout(buffer) // 设置标准输出为给定的 buffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.SetStderr(stderrBuffer) // 设置标准错误输出为新的缓冲区

	err := cmd.Run() // 运行命令
	if err != nil {
		stderrBuffer.WriteTo(buffer) // 将标准错误输出写入 buffer，忽略错误，因为需要返回原始错误
	}
	return err // 返回错误
}
```

### Restore

```go
// Restore 是 Interface 接口的一部分。
func (runner *runner) Restore(table Table, data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	args := []string{"-T", string(table)} // 设置参数列表
	return runner.restoreInternal(args, data, flush, counters) // 调用 restoreInternal 方法进行恢复
}
```

#### restoreInternal

```go
// restoreInternal 是 Restore 和 RestoreAll 的共享部分
func (runner *runner) restoreInternal(args []string, data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	runner.mu.Lock() // 加锁
	defer runner.mu.Unlock() // 解锁

	trace := utiltrace.New("iptables restore") // 创建追踪日志
	defer trace.LogIfLong(2 * time.Second) // 在 2 秒钟后记录日志

	if !flush { // 如果不需要清空规则，则在参数列表中添加 --noflush 标志
		args = append(args, "--noflush")
	}
	if counters { // 如果需要恢复计数器，则在参数列表中添加 --counters 标志
		args = append(args, "--counters")
	}

	if len(runner.restoreWaitFlag) == 0 { // 如果没有设置 restoreWaitFlag，则需要获取 iptables 锁
		locker, err := grabIptablesLocks(runner.lockfilePath14x, runner.lockfilePath16x) // 获取 iptables 锁
		if err != nil {
			return err
		}
		trace.Step("Locks grabbed") // 记录日志
		defer func(locker iptablesLocker) { // 在函数返回前关闭锁
			if err := locker.Close(); err != nil {
				klog.ErrorS(err, "Failed to close iptables locks") // 如果关闭锁时发生错误，则记录日志
			}
		}(locker)
	}

	fullArgs := append(runner.restoreWaitFlag, args...) // 创建完整的参数列表
	iptablesRestoreCmd := iptablesRestoreCommand(runner.protocol) // 获取 iptables 恢复命令
	klog.V(4).InfoS("Running", "command", iptablesRestoreCmd, "arguments", fullArgs) // 记录日志

	cmd := runner.exec.Command(iptablesRestoreCmd, fullArgs...) // 创建命令对象
	cmd.SetStdin(bytes.NewBuffer(data)) // 设置标准输入为给定的数据
	b, err := cmd.CombinedOutput() // 运行命令并返回输出
	if err != nil {
		pErr, ok := parseRestoreError(string(b)) // 解析错误信息
		if ok {
			return pErr
		}
		return fmt.Errorf("%w: %s", err, b) // 返回带有错误信息的错误
	}
	return nil // 返回 nil 表示没有错误发生
}
```

##### grabIptablesLocks

```go
func grabIptablesLocks(lockfilePath14x, lockfilePath16x string) (iptablesLocker, error) {
	var err error
	var success bool

	l := &locker{} // 创建 locker 对象
	defer func(l *locker) {
		if !success { // 如果不成功，则立即清理资源
			l.Close()
		}
	}(l)

	l.lock16, err = os.OpenFile(lockfilePath16x, os.O_CREATE, 0600) // 打开 1.6.x 样式的锁
	if err != nil {
		return nil, fmt.Errorf("failed to open iptables lock %s: %v", lockfilePath16x, err)
	}

	if err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (bool, error) {
		if err := grabIptablesFileLock(l.lock16); err != nil { // 获取文件锁
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to acquire new iptables lock: %v", err)
	}

	if err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (bool, error) {
		l.lock14, err = net.ListenUnix("unix", &net.UnixAddr{Name: lockfilePath14x, Net: "unix"}) // 监听 1.4.x 样式的锁
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to acquire old iptables lock: %v", err)
	}

	success = true
	return l, nil // 返回 locker 对象和错误
}
```

###### parseRestoreError

```go
// parseRestoreError 提取错误信息中的行号，并返回 parseError 结构体和是否成功的标志
func parseRestoreError(str string) (ParseError, bool) {
	errors := strings.Split(str, ":")
	if len(errors) != 2 {
		return nil, false
	}
	cmd := errors[0]
	matches := regexpParseError.FindStringSubmatch(errors[1]) // 使用正则表达式匹配行号
	if len(matches) != 2 {
		return nil, false
	}
	line, errMsg := strconv.Atoi(matches[1])
	if errMsg != nil {
		return nil, false
	}
	return parseError{cmd: cmd, line: line}, true // 返回 parseError 结构体和成功标志
}
```

###### parseError

```go
type parseError struct {
	cmd  string
	line int
}

func (e parseError) Line() int {
	return e.line // 返回行号
}

func (e parseError) Error() string {
	return fmt.Sprintf("%s: input error on line %d: ", e.cmd, e.line) // 返回错误信息字符串
}
```

### RestoreAll

```go
// RestoreAll 是 Interface 接口的一部分。
func (runner *runner) RestoreAll(data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	args := make([]string, 0) // 创建空的参数列表
	return runner.restoreInternal(args, data, flush, counters) // 调用 restoreInternal 方法进行恢复
}
```

### Monitor

```go
// Monitor is part of Interface
// 监视器函数，实现了Interface接口的一部分
func (runner *runner) Monitor(canary Chain, tables []Table, reloadFunc func(), interval time.Duration, stopCh <-chan struct{}) {
	// 进入无限循环，用于持续监视iptables状态
	for {
		// 使用utilwait包的PollImmediateUntil函数，每隔一定时间执行一次回调函数，直到回调函数返回true或者stopCh被关闭
		_ = utilwait.PollImmediateUntil(interval, func() (bool, error) {
			// 遍历所有的tables，确保每个table中的canary链存在
			for _, table := range tables {
				if _, err := runner.EnsureChain(table, canary); err != nil {
					// 如果设置canary链失败，记录错误日志并返回false
					klog.ErrorS(err, "Could not set up iptables canary", "table", table, "chain", canary)
					return false, nil
				}
			}
			// 所有canary链都设置成功，返回true
			return true, nil
		}, stopCh)

		// 使用utilwait包的PollUntil函数，每隔一定时间执行一次回调函数，直到回调函数返回true或者stopCh被关闭
		err := utilwait.PollUntil(interval, func() (bool, error) {
			// 检查tables[0]中的canary链是否存在
			if exists, err := runner.ChainExists(tables[0], canary); exists {
				return false, nil
			} else if isResourceError(err) {
				// 如果发生资源错误，记录错误日志并返回false
				klog.ErrorS(err, "Could not check for iptables canary", "table", tables[0], "chain", canary)
				return false, nil
			}
			// canary链已被删除，记录日志
			klog.V(2).InfoS("IPTables canary deleted", "table", tables[0], "chain", canary)
			
			// 使用utilwait包的PollImmediate函数，每隔一定时间执行一次回调函数，直到回调函数返回true或者超时
			err := utilwait.PollImmediate(iptablesFlushPollTime, iptablesFlushTimeout, func() (bool, error) {
				// 遍历除了tables[0]之外的其他tables中的canary链，检查它们是否存在
				for i := 1; i < len(tables); i++ {
					if exists, err := runner.ChainExists(tables[i], canary); exists || isResourceError(err) {
						return false, nil
					}
				}
				// 所有其他tables中的canary链都不存在，返回true
				return true, nil
			})
			if err != nil {
				// 检测到iptables状态不一致，记录日志
				klog.InfoS("Inconsistent iptables state detected")
			}
			// 返回true，表示iptables状态已恢复正常
			return true, nil
		}, stopCh)

		if err != nil {
			// stopCh被关闭，执行清理操作并返回
			for _, table := range tables {
				_ = runner.DeleteChain(table, canary)
			}
			return
		}

		// iptables状态已恢复正常，执行重新加载操作
		klog.V(2).InfoS("Reloading after iptables flush")
		reloadFunc()
	}
}
```

### ChainExists

```go
// ChainExists函数，实现了Interface接口的一部分
func (runner *runner) ChainExists(table Table, chain Chain) (bool, error) {
	// 构造完整的参数
	fullArgs := makeFullArgs(table, chain)

	// 获取锁
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// 使用utiltrace包创建一个跟踪器
	trace := utiltrace.New("iptables ChainExists")
	defer trace.LogIfLong(2 * time.Second)

	// 调用runner的run方法执行iptables的ListChain命令，并检查返回结果
	_, err := runner.run(opListChain, fullArgs)
	return err == nil, err
}
```

### Present

```go
// Present函数用于检测当前内核是否支持iptables，通过检查默认表和链的存在来判断
func (runner *runner) Present() bool {
	// 检查TableNAT和ChainPostrouting是否存在
	if _, err := runner.ChainExists(TableNAT, ChainPostrouting); err != nil {
		return false
	}

	return true
}
```





## Proxier

```go
// Proxier是基于iptables的代理，用于在本地主机（localhost:lport）和提供实际后端服务的服务之间进行连接。
type Proxier struct {
	endpointsChanges *proxy.EndpointChangeTracker // endpointsChanges用于跟踪endpoints的变化
	serviceChanges   *proxy.ServiceChangeTracker  // serviceChanges用于跟踪services的变化

	mu           sync.Mutex        // 保护以下字段的互斥锁
	svcPortMap   proxy.ServicePortMap    // 服务端口映射表
	endpointsMap proxy.EndpointsMap      // Endpoints映射表
	nodeLabels   map[string]string     // 节点标签映射表
	// endpointSlicesSynced和servicesSynced在启动后同步相应对象后设置为true。
	// 这用于避免在kube-proxy重启后使用一些部分数据更新iptables。
	endpointSlicesSynced bool    // EndpointSlice同步标志
	servicesSynced       bool    // Service同步标志
	needFullSync         bool    // 需要进行完全同步的标志
	initialized          int32   // 初始化标志，用于同步初始化过程
	syncRunner           *async.BoundedFrequencyRunner    // 控制对syncProxyRules的调用频率
	syncPeriod           time.Duration    // 同步周期
	lastIPTablesCleanup  time.Time    // 上次清理iptables的时间

	// 以下字段在实际运行中相当于常量，无需互斥锁。
	iptables       utiliptables.Interface    // iptables接口
	masqueradeAll  bool    // 是否对所有流量进行masquerade
	masqueradeMark string    // masquerade规则的标记
	exec           utilexec.Interface    // 执行命令的接口
	localDetector  proxyutiliptables.LocalTrafficDetector    // 本地流量检测器
	hostname       string    // 主机名
	nodeIP         net.IP    // 节点IP地址
	recorder       events.EventRecorder    // 事件记录器

	serviceHealthServer healthcheck.ServiceHealthServer    // 服务健康检查服务器
	healthzServer       healthcheck.ProxierHealthUpdater    // 健康检查服务器

	precomputedProbabilities []string    // 预计算的概率字符串缓存

	// 以下缓冲区用于重用内存并避免对性能产生显著影响的分配。
	iptablesData             *bytes.Buffer    // iptables数据缓冲区
	existingFilterChainsData *bytes.Buffer    // 现有过滤链数据缓冲区
	filterChains             utilproxy.LineBuffer    // 过滤链缓冲区
	filterRules              utilproxy.LineBuffer    // 过滤规则缓冲区
	natChains                utilproxy.LineBuffer    // NAT链缓冲区
	natRules                 utilproxy.LineBuffer    // NAT规则缓冲区

	largeClusterMode bool    // 是否处于大集群模式

	localhostNodePorts bool    // 是否允许通过localhost访问NodePort服务
	nodePortAddresses *utilproxy.NodePortAddresses    // NodePort工作的网络接口
	networkInterfacer utilproxy.NetworkInterfacer    // 网络接口
}

// Proxier实现了proxy.Provider接口
var _ proxy.Provider = &Proxier{}
```

### EndpointChangeTracker

```GO
type makeEndpointFunc func(info *BaseEndpointInfo, svcPortName *ServicePortName) Endpoint
// makeEndpointFunc 是一个函数类型，接受 BaseEndpointInfo 和 ServicePortName 作为参数，返回 Endpoint。

type processEndpointsMapChangeFunc func(oldEndpointsMap, newEndpointsMap EndpointsMap)
// processEndpointsMapChangeFunc 是一个函数类型，接受旧的 EndpointsMap 和新的 EndpointsMap 作为参数。

type EndpointChangeTracker struct {
	// lock 用于保护 lastChangeTriggerTimes
	lock sync.Mutex

	processEndpointsMapChange processEndpointsMapChangeFunc
	// endpointSliceCache 保存了 EndpointSlice 的简化版本。
	endpointSliceCache *EndpointSliceCache
	// lastChangeTriggerTimes 是一个从 Endpoints 的命名空间和名称到触发 Endpoints 对象改变的时间的映射。
	// 用于计算网络编程延迟。
	lastChangeTriggerTimes map[types.NamespacedName][]time.Time
	// trackerStartTime 记录了 EndpointChangeTracker 创建的时间，
	// 用于忽略在创建之前生成的 Endpoints，因为我们无法估计这些 Endpoints 的网络编程延迟。
	// 在重新启动时，这尤其成为问题，因为我们会处理可能在数小时或数天前创建的所有 Endpoints。
	trackerStartTime time.Time
}

// NewEndpointChangeTracker 初始化 EndpointChangeTracker。
func NewEndpointChangeTracker(hostname string, makeEndpointInfo makeEndpointFunc, ipFamily v1.IPFamily, recorder events.EventRecorder, processEndpointsMapChange processEndpointsMapChangeFunc) *EndpointChangeTracker {
	return &EndpointChangeTracker{
		lastChangeTriggerTimes:    make(map[types.NamespacedName][]time.Time),
		trackerStartTime:          time.Now(),
		processEndpointsMapChange: processEndpointsMapChange,
		endpointSliceCache:        NewEndpointSliceCache(hostname, ipFamily, recorder, makeEndpointInfo),
	}
}
```

#### EndpointSliceCache

```GO
// EndpointSliceCache is used as a cache of EndpointSlice information.
type EndpointSliceCache struct {
	// lock protects trackerByServiceMap.
	lock sync.Mutex

	// trackerByServiceMap is the basis of this cache. It contains endpoint
	// slice trackers grouped by service name and endpoint slice name. The first
	// key represents a namespaced service name while the second key represents
	// an endpoint slice name. Since endpoints can move between slices, we
	// require slice specific caching to prevent endpoints being removed from
	// the cache when they may have just moved to a different slice.
	trackerByServiceMap map[types.NamespacedName]*endpointSliceTracker

	makeEndpointInfo makeEndpointFunc
	hostname         string
	ipFamily         v1.IPFamily
	recorder         events.EventRecorder
}



// spToEndpointMap 按照 ServicePortName 和 endpoint 字符串（由 Endpoint.String() 返回）对 Endpoint 对象进行分组。
type spToEndpointMap map[ServicePortName]map[string]Endpoint

// NewEndpointSliceCache 初始化 EndpointSliceCache。
func NewEndpointSliceCache(hostname string, ipFamily v1.IPFamily, recorder events.EventRecorder, makeEndpointInfo makeEndpointFunc) *EndpointSliceCache {
	if makeEndpointInfo == nil {
		makeEndpointInfo = standardEndpointInfo
	}
	return &EndpointSliceCache{
		trackerByServiceMap: map[types.NamespacedName]*endpointSliceTracker{},
		hostname:            hostname,
		ipFamily:            ipFamily,
		makeEndpointInfo:    makeEndpointInfo,
		recorder:            recorder,
	}
}

// endpointInfo 只包含 kube-proxy 关心的属性。
// 用于缓存。故意保持较小以限制内存使用。
// Addresses、NodeName 和 Zone 是从 EndpointSlice 的 Endpoints 复制而来。
type EndpointSliceCache struct {
	Addresses []string
	NodeName  *string
	Zone      *string
	ZoneHints sets.Set[string]

	Ready       bool
	Serving     bool
	Terminating bool
}
```

### ServiceChangeTracker

```GO
// 定义一个函数类型makeServicePortFunc，接收三个参数：*v1.ServicePort、*v1.Service和*BaseServicePortInfo，并返回ServicePort对象。
type makeServicePortFunc func(*v1.ServicePort, *v1.Service, *BaseServicePortInfo) ServicePort

// 此处理程序在每次更改时由apply函数调用。此函数不应修改ServicePortMap，只需使用更改进行任何特定于Proxier的清理。
type processServiceMapChangeFunc func(previous, current ServicePortMap)

// serviceChange包含自代理规则同步以来发生的所有服务更改。对于单个对象，更改是累积的，即previous是应用更改之前的状态，current是应用所有更改之后的状态。
type serviceChange struct {
	previous ServicePortMap
	current  ServicePortMap
}

// ServiceChangeTracker存储关于任意数量未提交更改的Service的状态，按其命名空间和名称进行键控。
type ServiceChangeTracker struct {
	// lock用于保护items。
	lock sync.Mutex
	// items将服务映射到其serviceChange。
	items map[types.NamespacedName]*serviceChange
	// makeServiceInfo允许proxier在处理服务时注入定制信息。
	makeServiceInfo         makeServicePortFunc
	processServiceMapChange processServiceMapChangeFunc
	ipFamily                v1.IPFamily

	recorder events.EventRecorder
}

// NewServiceChangeTracker初始化一个ServiceChangeTracker。
func NewServiceChangeTracker(makeServiceInfo makeServicePortFunc, ipFamily v1.IPFamily, recorder events.EventRecorder, processServiceMapChange processServiceMapChangeFunc) *ServiceChangeTracker {
	return &ServiceChangeTracker{
		items:                   make(map[types.NamespacedName]*serviceChange),
		makeServiceInfo:         makeServiceInfo,
		recorder:                recorder,
		ipFamily:                ipFamily,
		processServiceMapChange: processServiceMapChange,
	}
}

// ServicePortMap将服务映射到其ServicePort。
type ServicePortMap map[ServicePortName]ServicePort

```

### LocalTrafficDetector

```GO
// LocalTrafficDetector是一个接口，根据流量是否在本地节点上发起来采取操作（跳转）。
type LocalTrafficDetector interface {
	// IsImplemented返回true表示实现有具体功能，返回false表示没有具体功能。
	IsImplemented() bool

	// IfLocal返回iptables参数，用于匹配来自Pod的流量。
	IfLocal() []string

	// IfNotLocal返回iptables参数，用于匹配不是来自Pod的流量。
	IfNotLocal() []string
}

type noOpLocalDetector struct{}

// NewNoOpLocalDetector是LocalTrafficDetector的空实现。
func NewNoOpLocalDetector() LocalTrafficDetector {
	return &noOpLocalDetector{}
}

func (n *noOpLocalDetector) IsImplemented() bool {
	return false
}

func (n *noOpLocalDetector) IfLocal() []string {
	return nil // 空实现，匹配所有流量
}

func (n *noOpLocalDetector) IfNotLocal() []string {
	return nil // 空实现，匹配所有流量
}

type detectLocalByCIDR struct {
	ifLocal    []string
	ifNotLocal []string
}

// NewDetectLocalByCIDR使用CIDR实现了LocalTrafficDetector接口。当一个单独的CIDR范围可以用来捕获本地流量时，可以使用此方法。
func NewDetectLocalByCIDR(cidr string, ipt utiliptables.Interface) (LocalTrafficDetector, error) {
	if netutils.IsIPv6CIDRString(cidr) != ipt.IsIPv6() {
		return nil, fmt.Errorf("CIDR %s has incorrect IP version: expect isIPv6=%t", cidr, ipt.IsIPv6())
	}
	_, _, err := netutils.ParseCIDRSloppy(cidr)
	if err != nil {
		return nil, err
	}
	return &detectLocalByCIDR{
		ifLocal:    []string{"-s", cidr},
		ifNotLocal: []string{"!", "-s", cidr},
	}, nil
}

func (d *detectLocalByCIDR) IsImplemented() bool {
	return true
}

func (d *detectLocalByCIDR) IfLocal() []string {
	return d.ifLocal
}

func (d *detectLocalByCIDR) IfNotLocal() []string {
	return d.ifNotLocal
}

// detectLocalByBridgeInterface 类型定义了一个使用桥接口名称实现 LocalTrafficDetector 接口的结构体。
// 当一个桥接口可以用来捕获来自 pod 的本地流量时，可以使用这个类型。
type detectLocalByBridgeInterface struct {
    ifLocal []string // 用于本地流量的参数列表
    ifNotLocal []string // 用于非本地流量的参数列表
}

// NewDetectLocalByBridgeInterface 使用桥接口名称创建一个 detectLocalByBridgeInterface 实例，实现 LocalTrafficDetector 接口。
// 当桥接口名称未设置时，返回错误。
func NewDetectLocalByBridgeInterface(interfaceName string) (LocalTrafficDetector, error) {
    if len(interfaceName) == 0 {
    	return nil, fmt.Errorf("no bridge interface name set")
    }
    return &detectLocalByBridgeInterface{
        ifLocal: []string{"-i", interfaceName},
        ifNotLocal: []string{"!", "-i", interfaceName},
    }, nil
}

func (d *detectLocalByBridgeInterface) IsImplemented() bool {
	return true
}

func (d *detectLocalByBridgeInterface) IfLocal() []string {
	return d.ifLocal
}

func (d *detectLocalByBridgeInterface) IfNotLocal() []string {
	return d.ifNotLocal
}

// detectLocalByInterfaceNamePrefix 类型定义了一个使用接口名称前缀实现 LocalTrafficDetector 接口的结构体。
// 当一个 pod 接口名称前缀可以用来捕获本地流量的概念时，可以使用这个类型。注意，这将匹配所有以给定前缀开头的接口。
type detectLocalByInterfaceNamePrefix struct {
    ifLocal []string // 用于本地流量的参数列表
    ifNotLocal []string // 用于非本地流量的参数列表
}

// NewDetectLocalByInterfaceNamePrefix 使用接口名称前缀创建一个 detectLocalByInterfaceNamePrefix 实例，实现 LocalTrafficDetector 接口。
// 当接口名称前缀未设置时，返回错误。
func NewDetectLocalByInterfaceNamePrefix(interfacePrefix string) (LocalTrafficDetector, error) {
	if len(interfacePrefix) == 0 {
		return nil, fmt.Errorf("no interface prefix set")
	}
	return &detectLocalByInterfaceNamePrefix{
		ifLocal:    []string{"-i", interfacePrefix + "+"},
		ifNotLocal: []string{"!", "-i", interfacePrefix + "+"},
	}, nil
}

func (d *detectLocalByInterfaceNamePrefix) IsImplemented() bool {
	return true
}

func (d *detectLocalByInterfaceNamePrefix) IfLocal() []string {
	return d.ifLocal
}

func (d *detectLocalByInterfaceNamePrefix) IfNotLocal() []string {
	return d.ifNotLocal
}
```

### NodePortAddresses

```GO
// NodePortAddresses是用于处理--nodeport-addresses标志的结构体。
type NodePortAddresses struct {
    cidrStrings []string
    cidrs []*net.IPNet
    containsIPv4Loopback bool
    matchAll bool
}

// RFC 5735 127.0.0.0/8 - 该块用于作为Internet主机环回地址的分配
var ipv4LoopbackStart = net.IPv4(127, 0, 0, 0)

// NewNodePortAddresses接受一个IP族和--nodeport-addresses值（假设该值仅包含有效的CIDR，可能是两个IP族的CIDR），并返回给定IP族的NodePortAddresses对象。如果给定IP族没有CIDR，则将添加CIDR "0.0.0.0/0"或"::/0"（即使存在另一个IP族的CIDR）。
func NewNodePortAddresses(family v1.IPFamily, cidrStrings []string) *NodePortAddresses {
    npa := &NodePortAddresses{}
    // 根据IP族过滤CIDR
    for _, str := range cidrStrings {
        if (family == v1.IPv4Protocol) == netutils.IsIPv4CIDRString(str) {
            npa.cidrStrings = append(npa.cidrStrings, str)
        }
    }
    if len(npa.cidrStrings) == 0 {
        if family == v1.IPv4Protocol {
            npa.cidrStrings = []string{IPv4ZeroCIDR}
        } else {
            npa.cidrStrings = []string{IPv6ZeroCIDR}
        }
    }

    // 现在解析CIDR
    for _, str := range npa.cidrStrings {
        _, cidr, _ := netutils.ParseCIDRSloppy(str)

        if netutils.IsIPv4CIDR(cidr) {
            if cidr.IP.IsLoopback() || cidr.Contains(ipv4LoopbackStart) {
                npa.containsIPv4Loopback = true
            }
        }

        if IsZeroCIDR(str) {
            // 忽略其他所有内容
            npa.cidrs = []*net.IPNet{cidr}
            npa.matchAll = true
            break
        }

        npa.cidrs = append(npa.cidrs, cidr)
    }

    return npa
}

func (npa *NodePortAddresses) String() string {
	return fmt.Sprintf("%v", npa.cidrStrings)
}

// MatchAll如果npa匹配所有节点IP（npa的给定IP族）则返回true。
func (npa *NodePortAddresses) MatchAll() bool {
	return npa.matchAll
}

// GetNodeIPs返回npa的CIDR的所有匹配节点IP地址。如果找不到匹配的IP，则返回空列表。
// NetworkInterfacer用于测试目的注入。
func (npa *NodePortAddresses) GetNodeIPs(nw NetworkInterfacer) ([]net.IP, error) {
    addrs, err := nw.InterfaceAddrs()
    if err != nil {
    	return nil, fmt.Errorf("error listing all interfaceAddrs from host, error: %v", err)
    }
    // 使用映射来去重匹配项
    addresses := make(map[string]net.IP)
    for _, cidr := range npa.cidrs {
        for _, addr := range addrs {
            var ip net.IP
            // nw.InterfaceAddrs可能在Windows上返回net.IPAddr或net.IPNet，在Linux上返回net.IPNet。
            switch v := addr.(type) {
            case *net.IPAddr:
                ip = v.IP
            case *net.IPNet:
                ip = v.IP
            default:
                continue
            }

            if cidr.Contains(ip) {
                addresses[ip.String()] = ip
            }
        }
    }

    ips := make([]net.IP, 0, len(addresses))
    for _, ip := range addresses {
        ips = append(ips, ip)
    }

    return ips, nil
}

// ContainsIPv4Loopback如果npa的CIDR包含IPv4环回地址，则返回true。
func (npa *NodePortAddresses) ContainsIPv4Loopback() bool {
	return npa.containsIPv4Loopback
}
```

### NetworkInterfacer

```GO
// NetworkInterfacer为多个net库函数定义了一个接口。生产代码将转发到net库函数，单元测试将重写这些方法以进行测试。
type NetworkInterfacer interface {
	InterfaceAddrs() ([]net.Addr, error)
}

// RealNetwork为生产代码实现了NetworkInterfacer接口，只是包装了底层的net库函数调用。
type RealNetwork struct{}

// InterfaceAddrs包装了net.InterfaceAddrs()，它是NetworkInterfacer接口的一部分。
func (RealNetwork) InterfaceAddrs() ([]net.Addr, error) {
	return net.InterfaceAddrs()
}

// 确保RealNetwork实现了NetworkInterfacer接口
var _ NetworkInterfacer = &RealNetwork{}
```

### NewProxier

```go
// NewProxier根据iptables Interface实例返回一个新的Proxier。
// 由于iptables的逻辑，假定在机器上只有一个活动的Proxier。
// 如果iptables在更新或获取初始锁时失败，将返回错误。
// 创建proxier后，它将在后台保持iptables的最新状态，并且如果某个iptables调用失败，不会终止。
func NewProxier(ipFamily v1.IPFamily,
	ipt utiliptables.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	localhostNodePorts bool,
	masqueradeBit int,
	localDetector proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddressStrings []string,
) (*Proxier, error) {
	nodePortAddresses := utilproxy.NewNodePortAddresses(ipFamily, nodePortAddressStrings)

	if !nodePortAddresses.ContainsIPv4Loopback() {
		localhostNodePorts = false
	}
	if localhostNodePorts {
		// 设置route_localnet sysctl，以允许在localhost上公开NodePort
		// 参考https://issues.k8s.io/90259
		klog.InfoS("Setting route_localnet=1 to allow node-ports on localhost; to change this either disable iptables.localhostNodePorts (--iptables-localhost-nodeports) or set nodePortAddresses (--nodeport-addresses) to filter loopback addresses")
		if err := utilproxy.EnsureSysctl(sysctl, sysctlRouteLocalnet, 1); err != nil {
			return nil, err
		}
	}

	// 当容器连接到Linux桥时（但不适用于SDN桥），代理需要br_netfilter和bridge-nf-call-iptables=1。
	// 直到大多数插件处理此问题，当配置缺失时记录日志。
	if val, err := sysctl.GetSysctl(sysctlBridgeCallIPTables); err == nil && val != 1 {
		klog.InfoS("Missing br-netfilter module or unset sysctl br-nf-call-iptables, proxy may not work as intended")
	}

	// 生成用于SNAT规则的masquerade标记。
	masqueradeValue := 1 << uint(masqueradeBit)
	masqueradeMark := fmt.Sprintf("%#08x", masqueradeValue)
	klog.V(2).InfoS("Using iptables mark for masquerade", "ipFamily", ipt.Protocol(), "mark", masqueradeMark)

	serviceHealthServer := healthcheck.NewServiceHealthServer(hostname, recorder, nodePortAddresses, healthzServer)

	proxier := &Proxier{
		svcPortMap:               make(proxy.ServicePortMap),
		serviceChanges:           proxy.NewServiceChangeTracker(newServiceInfo, ipFamily, recorder, nil),
		endpointsMap:             make(proxy.EndpointsMap),
		endpointsChanges:         proxy.NewEndpointChangeTracker(hostname, newEndpointInfo, ipFamily, recorder, nil),
		needFullSync:             true,
		syncPeriod:               syncPeriod,
		iptables:                 ipt,
		masqueradeAll:            masqueradeAll,
		masqueradeMark:           masqueradeMark,
		exec:                     exec,
		localDetector:            localDetector,
		hostname:                 hostname,
		nodeIP:                   nodeIP,
		recorder:                 recorder,
		serviceHealthServer:      serviceHealthServer,
		healthzServer:            healthzServer,
		precomputedProbabilities: make([]string, 0, 1001),
		iptablesData:             bytes.NewBuffer(nil),
		existingFilterChainsData: bytes.NewBuffer(nil),
		filterChains:             utilproxy.LineBuffer{},
		filterRules:              utilproxy.LineBuffer{},
		natChains:                utilproxy.LineBuffer{},
		natRules:                 utilproxy.LineBuffer{},
		localhostNodePorts:       localhostNodePorts,
		nodePortAddresses:        nodePortAddresses,
		networkInterfacer:        utilproxy.RealNetwork{},
	}

	burstSyncs := 2
	klog.V(2).InfoS("Iptables sync params", "ipFamily", ipt.Protocol(), "minSyncPeriod", minSyncPeriod, "syncPeriod", syncPeriod, "burstSyncs", burstSyncs)
	// 我们将syncPeriod传递给ipt.Monitor，只有在需要时才会调用我们。
	// 无论如何，我们仍然需要传递*某个*maxInterval给NewBoundedFrequencyRunner。
	// time.Hour是任意的。
	proxier.syncRunner = async.NewBoundedFrequencyRunner("sync-runner", proxier.syncProxyRules, minSyncPeriod, time.Hour, burstSyncs)

	go ipt.Monitor(kubeProxyCanaryChain, []utiliptables.Table{utiliptables.TableMangle, utiliptables.TableNAT, utiliptables.TableFilter},
		proxier.forceSyncProxyRules, syncPeriod, wait.NeverStop)

	if ipt.HasRandomFully() {
		klog.V(2).InfoS("Iptables supports --random-fully", "ipFamily", ipt.Protocol())
	} else {
		klog.V(2).InfoS("Iptables does not support --random-fully", "ipFamily", ipt.Protocol())
	}

	return proxier, nil
}
```

### NewDualStackProxier

```go
// NewDualStackProxier创建一个MetaProxier实例，包含IPv4和IPv6代理。
func NewDualStackProxier(
	ipt [2]utiliptables.Interface,
	sysctl utilsysctl.Interface,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	masqueradeAll bool,
	localhostNodePorts bool,
	masqueradeBit int,
	localDetectors [2]proxyutiliptables.LocalTrafficDetector,
	hostname string,
	nodeIP [2]net.IP,
	recorder events.EventRecorder,
	healthzServer healthcheck.ProxierHealthUpdater,
	nodePortAddresses []string,
) (proxy.Provider, error) {
	// 创建单栈proxier的ipv4实例
	ipv4Proxier, err := NewProxier(v1.IPv4Protocol, ipt[0], sysctl,
		exec, syncPeriod, minSyncPeriod, masqueradeAll, localhostNodePorts, masqueradeBit, localDetectors[0], hostname,
		nodeIP[0], recorder, healthzServer, nodePortAddresses)
	if err != nil {
		return nil, err
	}
	// 创建单栈proxier的ipv6实例
	ipv6Proxier, err := NewProxier(v1.IPv6Protocol, ipt[1], sysctl,
		exec, syncPeriod, minSyncPeriod, masqueradeAll, localhostNodePorts, masqueradeBit, localDetectors[1], hostname,
		nodeIP[1], recorder, healthzServer, nodePortAddresses)
	if err != nil {
		return nil, err
	}

	proxier := &proxy.MetaProxier{
		IPv4Proxier: ipv4Proxier,
		IPv6Proxier: ipv6Proxier,
	}

	return proxier, nil
}
```

### syncProxyRules

```GO
// 这是所有 iptables-save/restore 调用发生的地方。
// 其他的 iptables 规则只有在 iptablesInit() 中设置。
// 这里假设没有持有 proxier.mu。
func (proxier *Proxier) syncProxyRules() {
    proxier.mu.Lock() // 加锁，获取互斥锁
    defer proxier.mu.Unlock() // 在函数返回时解锁，释放互斥锁
    // 在收到服务和端点之前不要同步规则
    if !proxier.isInitialized() { // 检查 proxier 的 initialized 属性是否为 true，如果不是则返回
        klog.V(2).InfoS("Not syncing iptables until Services and Endpoints have been received from master")
        return
    }

    // proxier.needFullSync 的值可能在 defer 函数运行之前发生变化，因此我们需要追踪它在同步开始时是否已设置。
    tryPartialSync := !proxier.needFullSync // 如果 proxier.needFullSync 为 false，则 tryPartialSync 设置为 true

    // 记录同步所需的时间。
    start := time.Now() // 获取当前时间
    defer func() {
        metrics.SyncProxyRulesLatency.Observe(metrics.SinceInSeconds(start)) // 记录同步规则的延迟
        if tryPartialSync {
            metrics.SyncPartialProxyRulesLatency.Observe(metrics.SinceInSeconds(start)) // 记录部分同步规则的延迟
        } else {
            metrics.SyncFullProxyRulesLatency.Observe(metrics.SinceInSeconds(start)) // 记录完整同步规则的延迟
        }
        klog.V(2).InfoS("SyncProxyRules complete", "elapsed", time.Since(start)) // 输出同步完成的日志信息
    }()

    var serviceChanged, endpointsChanged sets.Set[string] // 定义两个 sets.Set[string] 类型的变量 serviceChanged 和 endpointsChanged
    if tryPartialSync {
        serviceChanged = proxier.serviceChanges.PendingChanges() // 获取服务变化的集合
        endpointsChanged = proxier.endpointsChanges.PendingChanges() // 获取端点变化的集合
    }
    serviceUpdateResult := proxier.svcPortMap.Update(proxier.serviceChanges) // 更新服务端口映射表
    endpointUpdateResult := proxier.endpointsMap.Update(proxier.endpointsChanges) // 更新端点映射表
    klog.V(2).InfoS("Syncing iptables rules")

	success := false
	defer func() {
		if !success {
			klog.InfoS("Sync failed", "retryingTime", proxier.syncPeriod)
			proxier.syncRunner.RetryAfter(proxier.syncPeriod) // 调用proxier.syncRunner的RetryAfter方法，设定重试时间为proxier.syncPeriod
			if tryPartialSync {
				metrics.IptablesPartialRestoreFailuresTotal.Inc()
			}
			// proxier.serviceChanges和proxier.endpointChanges已经被刷新，因此我们丢失了进行部分同步所需的状态。
			proxier.needFullSync = true
		}
	}()

	if !tryPartialSync {
		// 如果tryPartialSync为false
        // 确保我们的跳转规则（例如从PREROUTING到KUBE-SERVICES）存在。
        // 我们不能将其作为iptables-restore的一部分来执行，因为我们不希望指定/替换PREROUTING等中的*所有*规则。
        //
        // 当kube-proxy首次启动时，我们需要创建这些规则，并且如果utiliptables Monitor检测到iptables已被刷新，我们需要重新创建它们。
        // 在这两种情况下，代码将强制执行完全同步。在所有其他情况下，我们可以安全地假设规则已经存在，
        // 因此在进行部分同步时跳过此步骤，以免在每次同步时执行20次/sbin/iptables（在具有大量iptables规则的主机上会非常慢）。
		for _, jump := range append(iptablesJumpChains, iptablesKubeletJumpChains...) {
            // 遍历jump数组，其中包括iptablesJumpChains和iptablesKubeletJumpChains的内容
            for _, jump := range append(iptablesJumpChains, iptablesKubeletJumpChains...) { // 调用proxier.iptables的EnsureChain方法，确保链存在
                if _, err := proxier.iptables.EnsureChain(jump.table, jump.dstChain); err != nil {
                    klog.ErrorS(err, "Failed to ensure chain exists", "table", jump.table, "chain", jump.dstChain)
                    return
                }
                // 将args设置为jump.extraArgs
                args := jump.extraArgs
                if jump.comment != "" {
                    args = append(args, "-m", "comment", "--comment", jump.comment)
                }
                args = append(args, "-j", string(jump.dstChain))
                if _, err := proxier.iptables.EnsureRule(utiliptables.Prepend, jump.table, jump.srcChain, args...); err != nil {
                    klog.ErrorS(err, "Failed to ensure chain jumps", "table", jump.table, "srcChain", jump.srcChain, "dstChain", jump.dstChain)
                    return
                }
            }
        }
    }

    // 以下是在我们尝试编写iptables规则之前的代码，执行到这里后将不会返回。
    // 重置后续使用的所有缓冲区。
    // 这是为了避免内存重新分配，从而提高性能。
	proxier.filterChains.Reset()
	proxier.filterRules.Reset()
	proxier.natChains.Reset()
	proxier.natRules.Reset()

	// 为我们将填充的所有“顶级”链写入链行
	for _, chainName := range []utiliptables.Chain{kubeServicesChain, kubeExternalServicesChain, kubeForwardChain, kubeNodePortsChain, kubeProxyFirewallChain} {
		proxier.filterChains.Write(utiliptables.MakeChainLine(chainName))
	}
	for _, chainName := range []utiliptables.Chain{kubeServicesChain, kubeNodePortsChain, kubePostroutingChain, kubeMarkMasqChain} {
		proxier.natChains.Write(utiliptables.MakeChainLine(chainName))
	}

	// 安装特定于Kubernetes的postrouting规则。我们使用一个完整的链来进行安装，
    // 这样可以更容易地清除和更改规则，例如如果标记值发生变化。
    // 注意：kubelet创建了这些规则的相同副本。如果您以后想要更改这些规则，
    // 必须以一种与kubelet创建的规则的不同版本正确互操作的方式进行更改。（一旦IPTablesOwnershipCleanup成为GA，删除此注释。）
	proxier.natRules.Write(
		"-A", string(kubePostroutingChain),
		"-m", "mark", "!", "--mark", fmt.Sprintf("%s/%s", proxier.masqueradeMark, proxier.masqueradeMark),
		"-j", "RETURN",
	)
	// 清除标记，以防止数据包重新遍历网络堆栈时重新执行masquerading。
	proxier.natRules.Write(
		"-A", string(kubePostroutingChain),
		"-j", "MARK", "--xor-mark", proxier.masqueradeMark,
	)
	masqRule := []string{
		"-A", string(kubePostroutingChain),
		"-m", "comment", "--comment", `"kubernetes service traffic requiring SNAT"`,
		"-j", "MASQUERADE",
	}
	if proxier.iptables.HasRandomFully() {
		masqRule = append(masqRule, "--random-fully")
	}
	proxier.natRules.Write(masqRule)

	// 安装特定于Kubernetes的masquerade标记规则。我们使用一个完整的链进行安装，
	// 这样可以更容易地清除和更改规则，例如如果标记值发生变化
	proxier.natRules.Write(
		"-A", string(kubeMarkMasqChain),
		"-j", "MARK", "--or-mark", proxier.masqueradeMark,
	)

	isIPv6 := proxier.iptables.IsIPv6()
	if !isIPv6 && proxier.localhostNodePorts {
        // Kube-proxy使用`route_localnet`来在localhost上启用NodePorts，
        // 这会创建一个安全漏洞（https://issue.k8s.io/90259），
        // 这个iptables规则用于缓解该问题。

        // 注意：kubelet会创建与此规则完全相同的副本。
        // 如果将来要更改此规则，必须以与kubelet创建的规则相互操作的方式进行更改。
        //（实际上，kubelet使用"--dst"/"--src"而不是"-d"/"-s"，
        // 但这只是一个命令行的事情，并且会在内核中创建相同的规则。）
		proxier.filterChains.Write(utiliptables.MakeChainLine(kubeletFirewallChain))
		proxier.filterRules.Write(
			"-A", string(kubeletFirewallChain),
			"-m", "comment", "--comment", `"block incoming localnet connections"`,
			"-d", "127.0.0.0/8",
			"!", "-s", "127.0.0.0/8",
			"-m", "conntrack",
			"!", "--ctstate", "RELATED,ESTABLISHED,DNAT",
			"-j", "DROP",
		)
	}

	// Accumulate NAT chains to keep.
	activeNATChains := map[utiliptables.Chain]bool{} // 使用map作为集合来存储活动的NAT链

	// 为了避免增长过多，我们将其大小任意设置为64，
    // 因为单行代码的参数数目永远不会超过64个。
    // 需要注意的是，即使超过64个，它仍然是正确的，
    // 这只是为了提高效率，而不是正确性。
	args := make([]string, 64)

	// 计算所有服务的端点链的总数，以了解集群的规模。
	totalEndpoints := 0
	for svcName := range proxier.svcPortMap {
		totalEndpoints += len(proxier.endpointsMap[svcName])
	}
    // 根据端点链的总数判断集群规模是否大。
	proxier.largeClusterMode = (totalEndpoints > largeClusterEndpointsThreshold)

	// 这两个变量用于发布sync_proxy_rules_no_endpoints_total指标。
	serviceNoLocalEndpointsTotalInternal := 0
	serviceNoLocalEndpointsTotalExternal := 0

	// 为每个服务端口构建规则。
	for svcName, svc := range proxier.svcPortMap {
		svcInfo, ok := svc.(*servicePortInfo)
		if !ok {
			klog.ErrorS(nil, "Failed to cast serviceInfo", "serviceName", svcName)
			continue
		}
		protocol := strings.ToLower(string(svcInfo.Protocol()))
		svcPortNameString := svcInfo.nameString

		// 确定Cluster和Local流量策略的端点。
        // allLocallyReachableEndpoints是可以从该节点路由到的所有端点的集合，
        // 给定服务的流量策略。hasEndpoints为true表示服务在任何节点上都有可用的端点，
		// 而不仅仅是当前节点。
		allEndpoints := proxier.endpointsMap[svcName]
		clusterEndpoints, localEndpoints, allLocallyReachableEndpoints, hasEndpoints := proxy.CategorizeEndpoints(allEndpoints, svcInfo, proxier.nodeLabels)

		// 记录将使用的端点链
		for _, ep := range allLocallyReachableEndpoints {
			if epInfo, ok := ep.(*endpointsInfo); ok {
				activeNATChains[epInfo.ChainName] = true
			}
		}

		// clusterPolicyChain包含与"Cluster"流量策略一起使用的端点
		clusterPolicyChain := svcInfo.clusterPolicyChainName
		usesClusterPolicyChain := len(clusterEndpoints) > 0 && svcInfo.UsesClusterEndpoints()
		if usesClusterPolicyChain {
			activeNATChains[clusterPolicyChain] = true
		}

		// localPolicyChain包含与"Local"流量策略一起使用的端点
		localPolicyChain := svcInfo.localPolicyChainName
		usesLocalPolicyChain := len(localEndpoints) > 0 && svcInfo.UsesLocalEndpoints()
		if usesLocalPolicyChain {
			activeNATChains[localPolicyChain] = true
		}

		// internalPolicyChain是包含"internal"（ClusterIP）流量的链。
        // internalTrafficChain是内部流量路由到的链（始终与internalPolicyChain相同）。
        // hasInternalEndpoints为true表示应生成指向internalTrafficChain的规则，
        // 或false表示没有可用的内部端点。
		internalPolicyChain := clusterPolicyChain
		hasInternalEndpoints := hasEndpoints
		if svcInfo.InternalPolicyLocal() {
			internalPolicyChain = localPolicyChain
			if len(localEndpoints) == 0 {
				hasInternalEndpoints = false
			}
		}
		internalTrafficChain := internalPolicyChain

		// 类似地，externalPolicyChain包含"external"（NodePort、LoadBalancer和ExternalIP）流量的端点。
        // externalTrafficChain是外部流量路由到的链（始终是服务的"EXT"链）。
        // hasExternalEndpoints为true表示存在外部流量将到达的端点。
        // （但即使没有外部端点，我们仍然需要生成externalTrafficChain，
        // 以确保设置了用于本地流量的短路规则。）
		externalPolicyChain := clusterPolicyChain
		hasExternalEndpoints := hasEndpoints
		if svcInfo.ExternalPolicyLocal() {
			externalPolicyChain = localPolicyChain
			if len(localEndpoints) == 0 {
				hasExternalEndpoints = false
			}
		}
		externalTrafficChain := svcInfo.externalChainName // 最终跳转到externalPolicyChain

		// usesExternalTrafficChain基于hasEndpoints而不是hasExternalEndpoints，
        // 因为即使没有可用的外部端点，我们仍然需要本地流量的短路规则。
		usesExternalTrafficChain := hasEndpoints && svcInfo.ExternallyAccessible()
		if usesExternalTrafficChain {
			activeNATChains[externalTrafficChain] = true
		}

		// 可以直接将LoadBalancer IP的流量发送到externalTrafficChain，
		// 除非LoadBalancerSourceRanges在使用中，此时我们将创建一个防火墙链。	
		loadBalancerTrafficChain := externalTrafficChain
		fwChain := svcInfo.firewallChainName
		usesFWChain := hasEndpoints && len(svcInfo.LoadBalancerIPStrings()) > 0 && len(svcInfo.LoadBalancerSourceRanges()) > 0
		if usesFWChain {
			activeNATChains[fwChain] = true
			loadBalancerTrafficChain = fwChain
		}

		var internalTrafficFilterTarget, internalTrafficFilterComment string
		var externalTrafficFilterTarget, externalTrafficFilterComment string
		if !hasEndpoints {
			// 服务没有任何端点；hasInternalEndpoints和hasExternalEndpoints也将为false，
			// 我们不会为服务在"nat"表中生成任何链；只会在"filter"表中为服务的IP拒绝传入的数据包规则。
			internalTrafficFilterTarget = "REJECT"
			internalTrafficFilterComment = fmt.Sprintf(`"%s has no endpoints"`, svcPortNameString)
			externalTrafficFilterTarget = "REJECT"
			externalTrafficFilterComment = internalTrafficFilterComment
		} else {
			if !hasInternalEndpoints {
				// internalTrafficPolicy为"Local"，但没有本地端点。将丢弃对ClusterIP的流量，但仍然可以接受外部流量。
				internalTrafficFilterTarget = "DROP"
				internalTrafficFilterComment = fmt.Sprintf(`"%s has no local endpoints"`, svcPortNameString)
				serviceNoLocalEndpointsTotalInternal++
			}
			if !hasExternalEndpoints {
				// externalTrafficPolicy为"Local"，但没有本地端点。将丢弃来自集群外部的"external" IP的流量，但仍然可以接受来自集群内部的流量。
				externalTrafficFilterTarget = "DROP"
				externalTrafficFilterComment = fmt.Sprintf(`"%s has no local endpoints"`, svcPortNameString)
				serviceNoLocalEndpointsTotalExternal++
			}
		}

		// 捕获ClusterIP。
		if hasInternalEndpoints {
			proxier.natRules.Write(
				"-A", string(kubeServicesChain),
				"-m", "comment", "--comment", fmt.Sprintf(`"%s cluster IP"`, svcPortNameString),
				"-m", protocol, "-p", protocol,
				"-d", svcInfo.ClusterIP().String(),
				"--dport", strconv.Itoa(svcInfo.Port()),
				"-j", string(internalTrafficChain))
		} else {
			// 没有端点。
			proxier.filterRules.Write(
				"-A", string(kubeServicesChain),
				"-m", "comment", "--comment", internalTrafficFilterComment,
				"-m", protocol, "-p", protocol,
				"-d", svcInfo.ClusterIP().String(),
				"--dport", strconv.Itoa(svcInfo.Port()),
				"-j", internalTrafficFilterTarget,
			)
		}

		// 捕获ExternalIPs。
		for _, externalIP := range svcInfo.ExternalIPStrings() {
			if hasEndpoints {
				// 将流量发送到"external destinations"链。
				proxier.natRules.Write(
					"-A", string(kubeServicesChain),
					"-m", "comment", "--comment", fmt.Sprintf(`"%s external IP"`, svcPortNameString),
					"-m", protocol, "-p", protocol,
					"-d", externalIP,
					"--dport", strconv.Itoa(svcInfo.Port()),
					"-j", string(externalTrafficChain))
			}
			if !hasExternalEndpoints {
				// 没有端点（REJECT）或没有外部流量的端点（DROP任何未被EXT链短路的流量）。
				proxier.filterRules.Write(
					"-A", string(kubeExternalServicesChain),
					"-m", "comment", "--comment", externalTrafficFilterComment,
					"-m", protocol, "-p", protocol,
					"-d", externalIP,
					"--dport", strconv.Itoa(svcInfo.Port()),
					"-j", externalTrafficFilterTarget,
				)
			}
		}

		// 捕获负载均衡器的入口。
		for _, lbip := range svcInfo.LoadBalancerIPStrings() {
			if hasEndpoints {
				proxier.natRules.Write(
					"-A", string(kubeServicesChain),
					"-m", "comment", "--comment", fmt.Sprintf(`"%s loadbalancer IP"`, svcPortNameString),
					"-m", protocol, "-p", protocol,
					"-d", lbip,
					"--dport", strconv.Itoa(svcInfo.Port()),
					"-j", string(loadBalancerTrafficChain))

			}
			if usesFWChain {
				proxier.filterRules.Write(
					"-A", string(kubeProxyFirewallChain),
					"-m", "comment", "--comment", fmt.Sprintf(`"%s traffic not accepted by %s"`, svcPortNameString, svcInfo.firewallChainName),
					"-m", protocol, "-p", protocol,
					"-d", lbip,
					"--dport", strconv.Itoa(svcInfo.Port()),
					"-j", "DROP")
			}
		}
		if !hasExternalEndpoints {
			// 没有端点（REJECT）或没有外部流量的端点（DROP任何未被EXT链短路的流量）。
			for _, lbip := range svcInfo.LoadBalancerIPStrings() {
				proxier.filterRules.Write(
					"-A", string(kubeExternalServicesChain),
					"-m", "comment", "--comment", externalTrafficFilterComment,
					"-m", protocol, "-p", protocol,
					"-d", lbip,
					"--dport", strconv.Itoa(svcInfo.Port()),
					"-j", externalTrafficFilterTarget,
				)
			}
		}

		// 捕获NodePort。
		if svcInfo.NodePort() != 0 {
			if hasEndpoints {
				// 跳转到外部目标链。不管好坏如何，nodeports不受loadBalancerSourceRanges的限制，我们无法更改它。
				proxier.natRules.Write(
					"-A", string(kubeNodePortsChain),
					"-m", "comment", "--comment", svcPortNameString,
					"-m", protocol, "-p", protocol,
					"--dport", strconv.Itoa(svcInfo.NodePort()),
					"-j", string(externalTrafficChain))
			}
			if !hasExternalEndpoints {
				// 没有端点（REJECT）或没有外部流量的端点（DROP任何未被EXT链短路的流量）。
				proxier.filterRules.Write(
					"-A", string(kubeExternalServicesChain),
					"-m", "comment", "--comment", externalTrafficFilterComment,
					"-m", "addrtype", "--dst-type", "LOCAL",
					"-m", protocol, "-p", protocol,
					"--dport", strconv.Itoa(svcInfo.NodePort()),
					"-j", externalTrafficFilterTarget,
				)
			}
		}

		// 捕获healthCheckNodePorts。
		if svcInfo.HealthCheckNodePort() != 0 {
			// 无论节点是否有本地端点，healthCheckNodePorts都需要添加一个接受传入连接的规则。
			proxier.filterRules.Write(
				"-A", string(kubeNodePortsChain),
				"-m", "comment", "--comment", fmt.Sprintf(`"%s health check node port"`, svcPortNameString),
				"-m", "tcp", "-p", "tcp",
				"--dport", strconv.Itoa(svcInfo.HealthCheckNodePort()),
				"-j", "ACCEPT",
			)
		}

		// 如果自上次同步以来SVC/SVL/EXT/FW/SEP链没有发生变化
		// 我们可以在恢复输入中省略它们（我们已经在activeNATChains中标记了它们，因此它们不会被删除）。
		if tryPartialSync && !serviceChanged.Has(svcName.NamespacedName.String()) && !endpointsChanged.Has(svcName.NamespacedName.String()) {
			continue
		}

		// 设置内部流量处理。
		if hasInternalEndpoints {
			args = append(args[:0],
				"-m", "comment", "--comment", fmt.Sprintf(`"%s cluster IP"`, svcPortNameString),
				"-m", protocol, "-p", protocol,
				"-d", svcInfo.ClusterIP().String(),
				"--dport", strconv.Itoa(svcInfo.Port()),
			)

			if proxier.masqueradeAll {
				proxier.natRules.Write(
					"-A", string(internalTrafficChain),
					args,
					"-j", string(kubeMarkMasqChain))
			} else if proxier.localDetector.IsImplemented() {
				// 这里对流量进行伪装，将其视为离开集群并返回到外部负载均衡器。
				proxier.natRules.Write(
					"-A", string(internalTrafficChain),
					args,
					proxier.localDetector.IfNotLocal(),
					"-j", string(kubeMarkMasqChain))
			}
		}

		// 设置外部流量处理（如果启用了任何“external”目标）。
		// 所有捕获到的外部目标的流量都应该跳转到externalTrafficChain，该链将处理一些特殊情况，然后跳转到externalPolicyChain。
		if usesExternalTrafficChain {
			proxier.natChains.Write(utiliptables.MakeChainLine(externalTrafficChain))

			if !svcInfo.ExternalPolicyLocal() {
				// 如果我们使用非本地端点，需要进行伪装，以防我们跨节点。
				proxier.natRules.Write(
					"-A", string(externalTrafficChain),
					"-m", "comment", "--comment", fmt.Sprintf(`"masquerade traffic for %s external destinations"`, svcPortNameString),
					"-j", string(kubeMarkMasqChain))
			} else {
				// 如果我们只使用同一节点的端点，则在大多数情况下可以保留源IP。
				if proxier.localDetector.IsImplemented() {
					// 将所有本地源的pod -> 外部目标流量视为特殊情况。
					// 它不受任何形式的流量策略限制，模拟到外部负载均衡器并返回。
					proxier.natRules.Write(
						"-A", string(externalTrafficChain),
						"-m", "comment", "--comment", fmt.Sprintf(`"pod traffic for %s external destinations"`, svcPortNameString),
						proxier.localDetector.IfLocal(),
						"-j", string(clusterPolicyChain))
				}

				// 由主机节点发起的本地源流量仍然需要伪装，因为LBIP本身是本地地址，因此将成为选择的源IP。
				proxier.natRules.Write(
					"-A", string(externalTrafficChain),
					"-m", "comment", "--comment", fmt.Sprintf(`"masquerade LOCAL traffic for %s external destinations"`, svcPortNameString),
					"-m", "addrtype", "--src-type", "LOCAL",
					"-j", string(kubeMarkMasqChain))

				// 将所有src-type=LOCAL -> 外部目标的流量重定向到策略=cluster链。
				// 这允许从主机发起的流量正确地重定向到服务。
				proxier.natRules.Write(
					"-A", string(externalTrafficChain),
					"-m", "comment", "--comment", fmt.Sprintf(`"route LOCAL traffic for %s external destinations"`, svcPortNameString),
					"-m", "addrtype", "--src-type", "LOCAL",
					"-j", string(clusterPolicyChain))
			}

			// 其他情况将继续执行相应的策略链。
			if hasExternalEndpoints {
				proxier.natRules.Write(
					"-A", string(externalTrafficChain),
					"-j", string(externalPolicyChain))
			}
		}

		// 设置防火墙链，如果需要的话。
		if usesFWChain {
			proxier.natChains.Write(utiliptables.MakeChainLine(fwChain))

			// 根据loadBalancerSourceRanges字段创建服务防火墙规则。
			// 这仅适用于保留源IP的VIP类似负载均衡器。对于将流量定向到服务的负载均衡器，防火墙规则将不适用。
			args = append(args[:0],
				"-A", string(fwChain),
				"-m", "comment", "--comment", fmt.Sprintf(`"%s loadbalancer IP"`, svcPortNameString),
			)

			// 基于每个源范围的防火墙过滤
			allowFromNode := false
			for _, src := range svcInfo.LoadBalancerSourceRanges() {
				proxier.natRules.Write(args, "-s", src, "-j", string(externalTrafficChain))
				_, cidr, err := netutils.ParseCIDRSloppy(src)
				if err != nil {
					klog.ErrorS(err, "Error parsing CIDR in LoadBalancerSourceRanges, dropping it", "cidr", cidr)
				} else if cidr.Contains(proxier.nodeIP) {
					allowFromNode = true
				}
			}
			// 对于VIP类似的LB，VIP通常会作为本地地址添加（通过IP路由规则）。
            // 在这种情况下，从节点到VIP的请求不会经过负载均衡器，而是以源IP设置为VIP回路。
            // 我们需要以下规则来允许此节点发起的请求。
			if allowFromNode {
				for _, lbip := range svcInfo.LoadBalancerIPStrings() {
					proxier.natRules.Write(
						args,
						"-s", lbip,
						"-j", string(externalTrafficChain))
				}
			}
			// 如果数据包能够到达防火墙链的末尾，说明它没有被DNAT，因此它将匹配相应的KUBE-PROXY-FIREWALL规则。
			proxier.natRules.Write(
				"-A", string(fwChain),
				"-m", "comment", "--comment", fmt.Sprintf(`"other traffic to %s will be dropped by KUBE-PROXY-FIREWALL"`, svcPortNameString),
			)
		}

		// 如果使用 Cluster 策略链，则创建该链，并创建从 clusterPolicyChain 跳转到 clusterEndpoints 的规则
		if usesClusterPolicyChain {
			proxier.natChains.Write(utiliptables.MakeChainLine(clusterPolicyChain))
			proxier.writeServiceToEndpointRules(svcPortNameString, svcInfo, clusterPolicyChain, clusterEndpoints, args)
		}

		// 如果使用 Local 策略链，则创建该链，并创建从 localPolicyChain 跳转到 localEndpoints 的规则
		if usesLocalPolicyChain {
			proxier.natChains.Write(utiliptables.MakeChainLine(localPolicyChain))
			proxier.writeServiceToEndpointRules(svcPortNameString, svcInfo, localPolicyChain, localEndpoints, args)
		}

		// 生成每个端点的链
		for _, ep := range allLocallyReachableEndpoints {
			epInfo, ok := ep.(*endpointsInfo)
			if !ok {
				klog.ErrorS(nil, "Failed to cast endpointsInfo", "endpointsInfo", ep)
				continue
			}

			endpointChain := epInfo.ChainName

			// 创建端点链
			proxier.natChains.Write(utiliptables.MakeChainLine(endpointChain))
			activeNATChains[endpointChain] = true

			args = append(args[:0], "-A", string(endpointChain))
			args = proxier.appendServiceCommentLocked(args, svcPortNameString)
			// 处理回路到原始发起者的流量，使用 SNAT
			proxier.natRules.Write(
				args,
				"-s", epInfo.IP(),
				"-j", string(kubeMarkMasqChain))
			// 更新客户端亲和性列表
			if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
				args = append(args, "-m", "recent", "--name", string(endpointChain), "--set")
			}
			// DNAT 到最终目标
			args = append(args, "-m", protocol, "-p", protocol, "-j", "DNAT", "--to-destination", epInfo.Endpoint)
			proxier.natRules.Write(args)
		}
	}

	// 删除不再使用的链。由于在具有大量 iptables 规则的主机上，“iptables-save”可能需要几秒钟的时间，
    // 我们不会在大型集群的每次同步中执行此操作。（过时的链将不会被任何活动规则引用，因此除了占用内存外，
    // 它们是无害的。）
	if !proxier.largeClusterMode || time.Since(proxier.lastIPTablesCleanup) > proxier.syncPeriod {
		var existingNATChains map[utiliptables.Chain]struct{}

		proxier.iptablesData.Reset()
		if err := proxier.iptables.SaveInto(utiliptables.TableNAT, proxier.iptablesData); err == nil {
			existingNATChains = utiliptables.GetChainsFromTable(proxier.iptablesData.Bytes())

			for chain := range existingNATChains {
				if !activeNATChains[chain] {
					chainString := string(chain)
					if !isServiceChainName(chainString) {
						// 忽略不属于我们的链
						continue
					}
					// 我们必须（根据 iptables 规则）为其编写一个链行，这样可以刷新该链。然后我们可以删除该链。
					proxier.natChains.Write(utiliptables.MakeChainLine(chain))
					proxier.natRules.Write("-X", chainString)
				}
			}
			proxier.lastIPTablesCleanup = time.Now()
		} else {
			klog.ErrorS(err, "Failed to execute iptables-save: stale chains will not be deleted")
		}
	}

	// 最后，尾调用到 nodePorts 链。这需要在所有其他服务入口规则之后。
	if proxier.nodePortAddresses.MatchAll() {
		destinations := []string{"-m", "addrtype", "--dst-type", "LOCAL"}
		// 如果不支持本地主机的 NodePorts，则阻止本地主机的 NodePorts。（对于 IPv6，它们永远不起作用，
		// 对于 IPv4，只有在之前设置了 `route_localnet` 时才起作用。）
		if isIPv6 {
			destinations = append(destinations, "!", "-d", "::1/128")
		} else if !proxier.localhostNodePorts {
			destinations = append(destinations, "!", "-d", "127.0.0.0/8")
		}

		proxier.natRules.Write(
			"-A", string(kubeServicesChain),
			"-m", "comment", "--comment", `"kubernetes service nodeports; NOTE: this must be the last rule in this chain"`,
			destinations,
			"-j", string(kubeNodePortsChain))
	} else {
		nodeIPs, err := proxier.nodePortAddresses.GetNodeIPs(proxier.networkInterfacer)
		if err != nil {
			klog.ErrorS(err, "Failed to get node ip address matching nodeport cidrs, services with nodeport may not work as intended", "CIDRs", proxier.nodePortAddresses)
		}
		for _, ip := range nodeIPs {
			if ip.IsLoopback() {
				if isIPv6 {
					klog.ErrorS(nil, "--nodeport-addresses includes localhost but localhost NodePorts are not supported on IPv6", "address", ip.String())
					continue
				} else if !proxier.localhostNodePorts {
					klog.ErrorS(nil, "--nodeport-addresses includes localhost but --iptables-localhost-nodeports=false was passed", "address", ip.String())
					continue
				}
			}

			// 逐个为每个 IP 创建 NodePort 规则
			proxier.natRules.Write(
				"-A", string(kubeServicesChain),
				"-m", "comment", "--comment", `"kubernetes service nodeports; NOTE: this must be the last rule in this chain"`,
				"-d", ip.String(),
				"-j", string(kubeNodePortsChain))
		}
	}

	// 丢弃处于 INVALID 状态的数据包，这可能会导致意外的连接重置。
	// https://github.com/kubernetes/kubernetes/issues/74839
	proxier.filterRules.Write(
		"-A", string(kubeForwardChain),
		"-m", "conntrack",
		"--ctstate", "INVALID",
		"-j", "DROP",
	)

	// 如果已添加 masqueradeMark，则我们希望转发相同的流量，这允许 NodePort 流量在默认的 FORWARD 策略不是接受时也能转发。
	proxier.filterRules.Write(
		"-A", string(kubeForwardChain),
		"-m", "comment", "--comment", `"kubernetes forwarding rules"`,
		"-m", "mark", "--mark", fmt.Sprintf("%s/%s", proxier.masqueradeMark, proxier.masqueradeMark),
		"-j", "ACCEPT",
	)

	// 以下规则确保通过“kubernetes forwarding rules”规则接受的初始数据包之后的流量也会被接受。
	proxier.filterRules.Write(
		"-A", string(kubeForwardChain),
		"-m", "comment", "--comment", `"kubernetes forwarding conntrack rule"`,
		"-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	)

	metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableFilter)).Set(float64(proxier.filterRules.Lines()))
	metrics.IptablesRulesTotal.WithLabelValues(string(utiliptables.TableNAT)).Set(float64(proxier.natRules.Lines()))

	// 同步规则。
	// 重置iptablesData缓冲区。
	proxier.iptablesData.Reset()
	proxier.iptablesData.WriteString("*filter\n")
	proxier.iptablesData.Write(proxier.filterChains.Bytes())
	proxier.iptablesData.Write(proxier.filterRules.Bytes())
	proxier.iptablesData.WriteString("COMMIT\n")
	proxier.iptablesData.WriteString("*nat\n")
	proxier.iptablesData.Write(proxier.natChains.Bytes())
	proxier.iptablesData.Write(proxier.natRules.Bytes())
	proxier.iptablesData.WriteString("COMMIT\n")

	klog.V(2).InfoS("Reloading service iptables data",
		"numServices", len(proxier.svcPortMap),
		"numEndpoints", totalEndpoints,
		"numFilterChains", proxier.filterChains.Lines(),
		"numFilterRules", proxier.filterRules.Lines(),
		"numNATChains", proxier.natChains.Lines(),
		"numNATRules", proxier.natRules.Lines(),
	)
	klog.V(9).InfoS("Restoring iptables", "rules", proxier.iptablesData.Bytes())

	// 使用iptables.RestoreAll方法将iptablesData中的规则恢复到iptables中。
    // 使用NoFlushTables选项以防止清除表中的非Kubernetes链。
    // 使用RestoreCounters选项以恢复规则计数器。
	err := proxier.iptables.RestoreAll(proxier.iptablesData.Bytes(), utiliptables.NoFlushTables, utiliptables.RestoreCounters)
	if err != nil {
        // 如果发生错误，根据错误类型进行不同的处理。
		if pErr, ok := err.(utiliptables.ParseError); ok {
			lines := utiliptables.ExtractLines(proxier.iptablesData.Bytes(), pErr.Line(), 3)
			klog.ErrorS(pErr, "Failed to execute iptables-restore", "rules", lines)
		} else {
			klog.ErrorS(err, "Failed to execute iptables-restore")
		}
		metrics.IptablesRestoreFailuresTotal.Inc()
		return
	}
	success = true
	proxier.needFullSync = false
	// 遍历endpointUpdateResult.LastChangeTriggerTimes的每个键值对
	for name, lastChangeTriggerTimes := range endpointUpdateResult.LastChangeTriggerTimes {
        // 遍历lastChangeTriggerTimes的每个元素
		for _, lastChangeTriggerTime := range lastChangeTriggerTimes {
            // 计算从lastChangeTriggerTime到当前时间的延迟
			latency := metrics.SinceInSeconds(lastChangeTriggerTime)
			metrics.NetworkProgrammingLatency.Observe(latency)
			klog.V(4).InfoS("Network programming", "endpoint", klog.KRef(name.Namespace, name.Name), "elapsed", latency)
		}
	}

	metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("internal").Set(float64(serviceNoLocalEndpointsTotalInternal))
	metrics.SyncProxyRulesNoLocalEndpointsTotal.WithLabelValues("external").Set(float64(serviceNoLocalEndpointsTotalExternal))
    // 如果proxier.healthzServer不为nil，则调用其Updated()方法
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated()
	}
	metrics.SyncProxyRulesLastTimestamp.SetToCurrentTime()

	// 更新服务的健康检查状态。endpoints列表可能包含非"OnlyLocal"的服务，但services列表不会包含这些服务，serviceHealthServer会将这些服务忽略掉。
	// 使用proxier.svcPortMap.HealthCheckNodePorts()获取服务端口映射表的健康检查Node端口信息。
	if err := proxier.serviceHealthServer.SyncServices(proxier.svcPortMap.HealthCheckNodePorts()); err != nil {
		klog.ErrorS(err, "Error syncing healthcheck services")
	}
    // 同步更新健康检查的endpoints。使用proxier.endpointsMap.LocalReadyEndpoints()获取本地已准备好的endpoints列表。
	if err := proxier.serviceHealthServer.SyncEndpoints(proxier.endpointsMap.LocalReadyEndpoints()); err != nil {
		klog.ErrorS(err, "Error syncing healthcheck endpoints")
	}

	// 完成清理工作，清除UDP服务的陈旧的conntrack条目
	conntrack.CleanStaleEntries(proxier.iptables.IsIPv6(), proxier.exec, proxier.svcPortMap, serviceUpdateResult, endpointUpdateResult)
}
```

#### writeServiceToEndpointRules

```go
func (proxier *Proxier) writeServiceToEndpointRules(svcPortNameString string, svcInfo proxy.ServicePort, svcChain utiliptables.Chain, endpoints []proxy.Endpoint, args []string) {
	// 首先写入会话亲和规则，如果适用。
	if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
		for _, ep := range endpoints {
			epInfo, ok := ep.(*endpointsInfo)
			if !ok {
				continue
			}
			comment := fmt.Sprintf(`"%s -> %s"`, svcPortNameString, epInfo.Endpoint)

			args = append(args[:0],
				"-A", string(svcChain),
			)
			args = proxier.appendServiceCommentLocked(args, comment)
			args = append(args,
				"-m", "recent", "--name", string(epInfo.ChainName),
				"--rcheck", "--seconds", strconv.Itoa(svcInfo.StickyMaxAgeSeconds()), "--reap",
				"-j", string(epInfo.ChainName),
			)
			proxier.natRules.Write(args)
		}
	}

	// 现在写入负载均衡规则。
	numEndpoints := len(endpoints)
	for i, ep := range endpoints {
		epInfo, ok := ep.(*endpointsInfo)
		if !ok {
			continue
		}
		comment := fmt.Sprintf(`"%s -> %s"`, svcPortNameString, epInfo.Endpoint)

		args = append(args[:0], "-A", string(svcChain))
		args = proxier.appendServiceCommentLocked(args, comment)
		if i < (numEndpoints - 1) {
			// 每个规则是一次性匹配。
			args = append(args,
				"-m", "statistic",
				"--mode", "random",
				"--probability", proxier.probability(numEndpoints-i))
		}
		// 最后一个规则（或者当 n == 1 时是唯一的规则）是一个保证匹配。
		proxier.natRules.Write(args, "-j", string(epInfo.ChainName))
	}
}
```

### Chain

```GO
const (
    // 服务链
    kubeServicesChain utiliptables.Chain = "KUBE-SERVICES"

    // 外部服务链
    kubeExternalServicesChain utiliptables.Chain = "KUBE-EXTERNAL-SERVICES"

    // NodePort链
    kubeNodePortsChain utiliptables.Chain = "KUBE-NODEPORTS"

    // Kubernetes出口链
    kubePostroutingChain utiliptables.Chain = "KUBE-POSTROUTING"

    // kubeMarkMasqChain是用于标记伪装的链
    kubeMarkMasqChain utiliptables.Chain = "KUBE-MARK-MASQ"

    // Kubernetes转发链
    kubeForwardChain utiliptables.Chain = "KUBE-FORWARD"

    // kubeProxyFirewallChain是kube-proxy防火墙链
    kubeProxyFirewallChain utiliptables.Chain = "KUBE-PROXY-FIREWALL"

    // kube proxy canary chain用于监控规则重新加载
    kubeProxyCanaryChain utiliptables.Chain = "KUBE-PROXY-CANARY"

    // kubeletFirewallChain是kubelet的防火墙的副本，包含了反火星数据包规则。
    // 不应该用于其他规则。
    kubeletFirewallChain utiliptables.Chain = "KUBE-FIREWALL"

    // largeClusterEndpointsThreshold是切换到“大型集群模式”的端点数，优化iptables性能而不是可调试性。
    largeClusterEndpointsThreshold = 1000
)
```

### iptablesJumpChain

```GO
type iptablesJumpChain struct {
	table     utiliptables.Table  // 表示iptables规则所属的表
	dstChain  utiliptables.Chain  // 表示iptables规则的目标链
	srcChain  utiliptables.Chain  // 表示iptables规则的源链
	comment   string              // 注释，用于描述iptables规则的作用
	extraArgs []string            // 额外的参数，用于配置iptables规则
}

var iptablesJumpChains = []iptablesJumpChain{
	{utiliptables.TableFilter, kubeExternalServicesChain, utiliptables.ChainInput, "kubernetes externally-visible service portals", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableFilter, kubeExternalServicesChain, utiliptables.ChainForward, "kubernetes externally-visible service portals", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableFilter, kubeNodePortsChain, utiliptables.ChainInput, "kubernetes health check service ports", nil},
	{utiliptables.TableFilter, kubeServicesChain, utiliptables.ChainForward, "kubernetes service portals", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableFilter, kubeServicesChain, utiliptables.ChainOutput, "kubernetes service portals", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableFilter, kubeForwardChain, utiliptables.ChainForward, "kubernetes forwarding rules", nil},
	{utiliptables.TableFilter, kubeProxyFirewallChain, utiliptables.ChainInput, "kubernetes load balancer firewall", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableFilter, kubeProxyFirewallChain, utiliptables.ChainOutput, "kubernetes load balancer firewall", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableFilter, kubeProxyFirewallChain, utiliptables.ChainForward, "kubernetes load balancer firewall", []string{"-m", "conntrack", "--ctstate", "NEW"}},
	{utiliptables.TableNAT, kubeServicesChain, utiliptables.ChainOutput, "kubernetes service portals", nil},
	{utiliptables.TableNAT, kubeServicesChain, utiliptables.ChainPrerouting, "kubernetes service portals", nil},
}
```

### OnEndpointSliceAdd

```GO
// OnEndpointSliceAdd 是在观察到创建新的端点切片对象时调用的方法。
func (proxier *Proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

#### EndpointSliceUpdate

```GO
// EndpointSliceUpdate 根据<先前的端点，当前的端点>对更新给定服务的端点更改映射。
// 如果有更改，返回true；否则返回false。将添加/更新/删除EndpointsChangeMap中的项目。
// 如果removeSlice为true，则删除切片；否则将添加或更新切片。
func (ect *EndpointChangeTracker) EndpointSliceUpdate(endpointSlice *discovery.EndpointSlice, removeSlice bool) bool {
	if !supportedEndpointSliceAddressTypes.Has(string(endpointSlice.AddressType)) {
		klog.V(4).InfoS("EndpointSlice的地址类型不被kube-proxy支持", "addressType", endpointSlice.AddressType)
		return false
	}

	// 这不应该发生
	if endpointSlice == nil {
		klog.ErrorS(nil, "传递给EndpointSliceUpdate的endpointSlice为空")
		return false
	}

	namespacedName, _, err := endpointSliceCacheKeys(endpointSlice)
	if err != nil {
		klog.InfoS("获取端点切片缓存键时出错", "err", err)
		return false
	}

	metrics.EndpointChangesTotal.Inc()

	ect.lock.Lock()
	defer ect.lock.Unlock()

	changeNeeded := ect.endpointSliceCache.updatePending(endpointSlice, removeSlice)

	if changeNeeded {
		metrics.EndpointChangesPending.Inc()
		// 在删除Endpoints时，LastChangeTriggerTime注释按定义来自上次更新的时间，
		// 这不是我们想要测量的。所以在这种情况下，我们简单地忽略它。
		// TODO（wojtek-t，robscott）：在删除EndpointSlice时，解决该服务的其他EndpointSlice仍然存在的问题。
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

#### isInitialized

```GO
// 返回proxier.initialized的原子加载结果是否大于0，即是否已初始化。
func (proxier *Proxier) isInitialized() bool {
	return atomic.LoadInt32(&proxier.initialized) > 0
}
```

#### Sync

```GO
// Sync 尽快将proxier的状态与iptables同步。
func (proxier *Proxier) Sync() {
	if proxier.healthzServer != nil {
		proxier.healthzServer.QueuedUpdate()
	}
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	proxier.syncRunner.Run()
}
```

### OnEndpointSliceUpdate

```GO
// OnEndpointSliceUpdate 在观察到对现有的 endpoint slice 对象进行修改时调用。
func (proxier *Proxier) OnEndpointSliceUpdate(_, endpointSlice *discovery.EndpointSlice) {
    if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
    	proxier.Sync()
    }
}
```

### OnEndpointSliceDelete

```GO
// OnEndpointSliceDelete 在观察到删除现有的 endpoint slice 对象时调用。
func (proxier *Proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, true) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

### OnEndpointSlicesSynced

```GO
func (proxier *Proxier) OnEndpointSlicesSynced() {
    proxier.mu.Lock() // 加锁，获取互斥锁
    proxier.endpointSlicesSynced = true // 将 endpointSlicesSynced 设置为 true，表示同步完成
    proxier.setInitialized(proxier.servicesSynced) // 调用 setInitialized 函数，设置 proxier 的 initialized 属性为 proxier.servicesSynced 的值
    proxier.mu.Unlock() // 解锁，释放互斥锁

    // 无条件地进行同步 - 每次生命周期调用一次。
    proxier.syncProxyRules()
}
```

### OnServiceAdd

```go
// 当观察到新建服务对象时，调用OnServiceAdd函数。
func (proxier *Proxier) OnServiceAdd(service *v1.Service) {
	// 调用OnServiceUpdate函数，传入nil作为oldService，service作为新的service对象。
	proxier.OnServiceUpdate(nil, service)
}
```

### OnServiceUpdate

```go
// 当观察到现有服务对象的修改时，调用OnServiceUpdate函数。
func (proxier *Proxier) OnServiceUpdate(oldService, service *v1.Service) {
	// 如果proxier.serviceChanges.Update(oldService, service)返回true，并且proxier已初始化，则执行同步操作。
	if proxier.serviceChanges.Update(oldService, service) && proxier.isInitialized() {
		proxier.Sync()
	}
}
```

#### Update

```go
// 根据<previous, current>服务对，更新给定服务的变化映射。如果有变化返回true，否则返回false。
// Update可用于添加/更新/删除ServiceChangeMap的项目。例如：
// 添加项目：
//   - 将<nil, service>作为<previous, current>对传入。
//
// 更新项目：
//   - 将<oldService, service>作为<previous, current>对传入。
//
// 删除项目：
//   - 将<service, nil>作为<previous, current>对传入。
func (sct *ServiceChangeTracker) Update(previous, current *v1.Service) bool {
	// 如果previous和current都为nil，这是意外情况，直接返回false。
	if previous == nil && current == nil {
		return false
	}

	svc := current
	if svc == nil {
		svc = previous
	}
	// 增加metrics.ServiceChangesTotal计数器的值。
	metrics.ServiceChangesTotal.Inc()
	namespacedName := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}

	sct.lock.Lock()
	defer sct.lock.Unlock()

	change, exists := sct.items[namespacedName]
	if !exists {
		change = &serviceChange{}
		// 将previous服务对象转换为ServicePortMap，并赋值给change.previous。
		change.previous = sct.serviceToServiceMap(previous)
		sct.items[namespacedName] = change
	}
	// 将current服务对象转换为ServicePortMap，并赋值给change.current。
	change.current = sct.serviceToServiceMap(current)
	// 如果change.previous等于change.current，表示没有变化，删除该项。
	if reflect.DeepEqual(change.previous, change.current) {
		delete(sct.items, namespacedName)
	} else {
		klog.V(4).InfoS("Service updated ports", "service", klog.KObj(svc), "portCount", len(change.current))
	}
	// 设置metrics.ServiceChangesPending为当前items的长度。
	metrics.ServiceChangesPending.Set(float64(len(sct.items)))
	return len(sct.items) > 0
}
```

##### serviceToServiceMap

```go
// serviceToServiceMap将单个Service对象转换为ServicePortMap。
//
// 注意：不应修改service对象。
func (sct *ServiceChangeTracker) serviceToServiceMap(service *v1.Service) ServicePortMap {
	if service == nil {
		return nil
	}

	if utilproxy.ShouldSkipService(service) {
		return nil
	}

	// 根据sct.ipFamily和service获取集群IP。
	clusterIP := utilproxy.GetClusterIPByFamily(sct.ipFamily, service)
	if clusterIP == "" {
		return nil
	}

	// 创建ServicePortMap。
	svcPortMap := make(ServicePortMap)
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	for i := range service.Spec.Ports {
		servicePort := &service.Spec.Ports[i]
		svcPortName := ServicePortName{NamespacedName: svcName, Port: servicePort.Name, Protocol: servicePort.Protocol}
		baseSvcInfo := sct.newBaseServiceInfo(servicePort, service)
		if sct.makeServiceInfo != nil {
			// 如果sct.makeServiceInfo不为nil，则使用它创建ServiceInfo，并将其添加到svcPortMap中。
			svcPortMap[svcPortName] = sct.makeServiceInfo(servicePort, service, baseSvcInfo)
		} else {
			// 否则，将baseSvcInfo直接添加到svcPortMap中。
			svcPortMap[svcPortName] = baseSvcInfo
		}
	}
	return svcPortMap
}
```

### OnServiceDelete

```go
// 当观察到现有服务对象的删除时，调用OnServiceDelete函数。
func (proxier *Proxier) OnServiceDelete(service *v1.Service) {
	// 调用OnServiceUpdate函数，传入service作为oldService，nil作为新的service对象。
	proxier.OnServiceUpdate(service, nil)
}

```





### OnServiceSynced

```GO
// OnServiceSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *Proxier) OnServiceSynced() {
    proxier.mu.Lock() // 加锁，防止并发访问
    proxier.servicesSynced = true // 标记服务同步完成
    proxier.setInitialized(proxier.endpointSlicesSynced) // 设置初始化完成状态
    proxier.mu.Unlock() // 解锁

    // Sync unconditionally - this is called once per lifetime.
    proxier.syncProxyRules()  // 调用syncProxyRules()函数进行iptables规则同步
}
```

### OnNodeAdds

```go
// 当观察到新建节点对象时，调用OnNodeAdd函数。
func (proxier *Proxier) OnNodeAdd(node *v1.Node) {
	// 如果节点的名称与当前节点的名称不匹配，记录错误并返回。
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node",
			"eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	// 如果proxier.nodeLabels与节点的标签相等，表示没有变化，直接返回。
	if reflect.DeepEqual(proxier.nodeLabels, node.Labels) {
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = map[string]string{}
	// 将节点的标签复制给proxier.nodeLabels。
	for k, v := range node.Labels {
		proxier.nodeLabels[k] = v
	}
	proxier.needFullSync = true
	proxier.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node labels", "labels", node.Labels)

	proxier.Sync()
}
```

### OnNodeUpdate

```go
// 当观察到现有节点对象的修改时，调用OnNodeUpdate函数。
func (proxier *Proxier) OnNodeUpdate(oldNode, node *v1.Node) {
	// 如果节点的名称与当前节点的名称不匹配，记录错误并返回。
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node",
			"eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}

	// 如果proxier.nodeLabels与节点的标签相等，表示没有变化，直接返回。
	if reflect.DeepEqual(proxier.nodeLabels, node.Labels) {
		return
	}

	proxier.mu.Lock()
	proxier.nodeLabels = map[string]string{}
	// 将节点的标签复制给proxier.nodeLabels。
	for k, v := range node.Labels {
		proxier.nodeLabels[k] = v
	}
	proxier.needFullSync = true
	proxier.mu.Unlock()
	klog.V(4).InfoS("Updated proxier node labels", "labels", node.Labels)

	proxier.Sync()
}
```

### OnNodeDelete

```go
// 当观察到现有节点对象的删除时，调用OnNodeDelete函数。
func (proxier *Proxier) OnNodeDelete(node *v1.Node) {
	// 如果节点的名称与当前节点的名称不匹配，记录错误并返回。
	if node.Name != proxier.hostname {
		klog.ErrorS(nil, "Received a watch event for a node that doesn't match the current node",
			"eventNode", node.Name, "currentNode", proxier.hostname)
		return
	}
	proxier.mu.Lock()
	// 将proxier.nodeLabels设置为nil，表示节点标签为空。
	proxier.nodeLabels = nil
	proxier.needFullSync = true
	proxier.mu.Unlock()

	proxier.Sync()
}
```

### OnNodeSynced

```go
// 当所有初始事件处理程序都被调用并且状态完全传播到本地缓存时，调用OnNodeSynced函数。
func (proxier *Proxier) OnNodeSynced() {
}
```

### Sync

```go
// Sync被调用以尽快将proxier的状态与iptables同步。
func (proxier *Proxier) Sync() {
	// 如果proxier.healthzServer不为nil，则调用QueuedUpdate()方法更新健康检查时间戳。
	if proxier.healthzServer != nil {
		proxier.healthzServer.QueuedUpdate()
	}
	// 设置SyncProxyRulesLastQueuedTimestamp为当前时间。
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	// 运行syncRunner来执行同步操作。
	proxier.syncRunner.Run()
}
```

### SyncLoop

```go
// SyncLoop运行周期性的工作。这通常作为一个goroutine或应用程序的主循环运行，不会返回。
func (proxier *Proxier) SyncLoop() {
	// 在开始时更新健康检查时间戳，以防Sync()永远不成功。
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated()
	}

	// 合成"上次更改排队"的时间，因为informers正在同步中。
	metrics.SyncProxyRulesLastQueuedTimestamp.SetToCurrentTime()
	// 调用syncRunner的Loop方法，使用wait.NeverStop作为停止条件，使其持续运行。
	proxier.syncRunner.Loop(wait.NeverStop)
}
```

