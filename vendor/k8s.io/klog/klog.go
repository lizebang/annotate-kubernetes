// Go support for leveled logs, analogous to https://code.google.com/p/google-glog/
//
// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package klog implements logging analogous to the Google-internal C++ INFO/ERROR/V setup.
// It provides functions Info, Warning, Error, Fatal, plus formatting variants such as
// Infof. It also provides V-style logging controlled by the -v and -vmodule=file=2 flags.
//
// Basic examples:
//
//	glog.Info("Prepare to repel boarders")
//
//	glog.Fatalf("Initialization failed: %s", err)
//
// See the documentation for the V function for an explanation of these examples:
//
//	if glog.V(2) {
//		glog.Info("Starting transaction...")
//	}
//
//	glog.V(2).Infoln("Processed", nItems, "elements")
//
// Log output is buffered and written periodically using Flush. Programs
// should call Flush before exiting to guarantee all log output is written.
//
// By default, all log statements write to files in a temporary directory.
// This package provides several flags that modify this behavior.
// As a result, flag.Parse must be called before any logging is done.
//
//	-logtostderr=false
//		Logs are written to standard error instead of to files.
//	-alsologtostderr=false
//		Logs are written to standard error as well as to files.
//	-stderrthreshold=ERROR
//		Log events at or above this severity are logged to standard
//		error as well as to files.
//	-log_dir=""
//		Log files will be written to this directory instead of the
//		default temporary directory.
//
//	Other flags provide aids to debugging.
//
//	-log_backtrace_at=""
//		When set to a file and line number holding a logging statement,
//		such as
//			-log_backtrace_at=gopherflakes.go:234
//		a stack trace will be written to the Info log whenever execution
//		hits that statement. (Unlike with -vmodule, the ".go" must be
//		present.)
//	-v=0
//		Enable V-leveled logging at the specified level.
//	-vmodule=""
//		The syntax of the argument is a comma-separated list of pattern=N,
//		where pattern is a literal file name (minus the ".go" suffix) or
//		"glob" pattern and N is a V level. For instance,
//			-vmodule=gopher*=3
//		sets the V level to 3 in all Go files whose names begin "gopher".
//
// klog 包实现了类似 Google 内部 C++ INFO/ERROR/V 方案对日志。
// 它提供了函数 Info、Warning、Error、Fatel，以及诸如 Infof 的格式化版本。
// 它还提供了由 -v 和 -vmodule=file=2 标志控制的 V-style 日志。
//
// 基础示例：
//
//	glog.Info("Prepare to repel boarders")
//
//	glog.Fatalf("Initialization failed: %s", err)
//
// 有关这些示例的说明，请查看 V 函数的文档。
//
//	if glog.V(2) {
//		glog.Info("Starting transaction...")
//	}
//
//	glog.V(2).Infoln("Processed", nItems, "elements")
//
// 日志是被缓冲的，并且周期性的使用 Flush 写入。
// 程序应该在退出之前调用 Flush 以保证写入所有日志。
//
// 默认情况下，所有日志都写入临时目录中的文件。
// 此包提供了几个用于改变此默认操作的标志。
// 因此，flag.Parse 必须在所有日志完全前调用。
//
//	-logtostderr=false
//		日志被写入到标准错误输出而不是文件。
//	-alsologtostderr=false
//		日志被同时写入到标准错误输出和文件。
//	-stderrthreshold=ERROR
//		日志事件处于此等级或以上时同时写入到标准输出和文件。
//	-log_dir=""
//		日志文件将被写入到此目录而不是默认的临时目录。
//
// 其他标志提供了调试帮助。
//
//	-log_backtrace_at=""
//		当设置某文件的某行持有日志声明，
//		例如
//			-log_backtrace_at=gopherflakes.go:234
//		每当执行触发此声明时，栈追踪数据将被写入到 Info 日志。（与 -vmodule 不同，
//		".go" 必须被指明。）
//	-v=0
//		在指定等级启用 V-级 日志。
//	-vmodule=""
//		参数的语法是一个类似 pattern=N 的逗号分隔的列表，其中 pattern 是文件名
//		（除去 ".go" 后缀）或 "glob" 模式，N 是 V 的等级。例如：
//			-vmodule=gopher*=3
//		将名称以 "gopher" 开头的所有 Go 文件 V 的等级设置为 3。
package klog

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	stdLog "log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// severity identifies the sort of log: info, warning etc. It also implements
// the flag.Value interface. The -stderrthreshold flag is of type severity and
// should be modified only through the flag.Value interface. The values match
// the corresponding constants in C++.
//
// severity 标识出日志的类别：info、warning 等。
// 它还实现 flag.Value 接口。
// -stderrthreshold 标志是 severity 类型，并且应该只能通过 flag.Value 接口修改。
// 值与 C++ 中的对应常量相匹配。
type severity int32 // sync/atomic int32

// These constants identify the log levels in order of increasing severity.
// A message written to a high-severity log file is also written to each
// lower-severity log file.
//
// 这些常量是按严重等级递增的顺序标示日志等级。
// 一个写入到高严重等级日志文件的消息也会被写入到每一个低严重等级日志文件中。
const (
	infoLog severity = iota
	warningLog
	errorLog
	fatalLog
	numSeverity = 4
)

const severityChar = "IWEF"

var severityName = []string{
	infoLog:    "INFO",
	warningLog: "WARNING",
	errorLog:   "ERROR",
	fatalLog:   "FATAL",
}

// get returns the value of the severity.
//
// get 返回 severity 的值。
func (s *severity) get() severity {
	return severity(atomic.LoadInt32((*int32)(s)))
}

// set sets the value of the severity.
//
// set 设置 severity 的值。
func (s *severity) set(val severity) {
	atomic.StoreInt32((*int32)(s), int32(val))
}

// String is part of the flag.Value interface.
//
// String 是 flag.Value 接口的一部分。
func (s *severity) String() string {
	return strconv.FormatInt(int64(*s), 10)
}

// Get is part of the flag.Value interface.
//
// Get 是 flag.Value 接口的一部分。
func (s *severity) Get() interface{} {
	return *s
}

// Set is part of the flag.Value interface.
//
// Set flag.Value 接口的一部分。
func (s *severity) Set(value string) error {
	var threshold severity
	// Is it a known name?
	//
	// 它是否为已知等级的名称。
	if v, ok := severityByName(value); ok {
		threshold = v
	} else {
		v, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		threshold = severity(v)
	}
	logging.stderrThreshold.set(threshold)
	return nil
}

func severityByName(s string) (severity, bool) {
	s = strings.ToUpper(s)
	for i, name := range severityName {
		if name == s {
			return severity(i), true
		}
	}
	return 0, false
}

// OutputStats tracks the number of output lines and bytes written.
//
// OutputStats 追踪写入的行号和字节数。
type OutputStats struct {
	lines int64
	bytes int64
}

// Lines returns the number of lines written.
//
// Lines 返回写入的行号。
func (s *OutputStats) Lines() int64 {
	return atomic.LoadInt64(&s.lines)
}

// Bytes returns the number of bytes written.
//
// Bytes 返回写入的字节数。
func (s *OutputStats) Bytes() int64 {
	return atomic.LoadInt64(&s.bytes)
}

// Stats tracks the number of lines of output and number of bytes
// per severity level. Values must be read with atomic.LoadInt64.
//
// Stats 跟踪每个日志严重等级的行号和字节数。值必须通过 atomic.LoadInt64 读取。
// IMP: 匿名结构体，类似于注释，且保持灵活性，便于修改。
var Stats struct {
	Info, Warning, Error OutputStats
}

var severityStats = [numSeverity]*OutputStats{
	infoLog:    &Stats.Info,
	warningLog: &Stats.Warning,
	errorLog:   &Stats.Error,
}

// Level is exported because it appears in the arguments to V and is
// the type of the v flag, which can be set programmatically.
// It's a distinct type because we want to discriminate it from logType.
// Variables of type level are only changed under logging.mu.
// The -v flag is read only with atomic ops, so the state of the logging
// module is consistent.

// Level is treated as a sync/atomic int32.

// Level specifies a level of verbosity for V logs. *Level implements
// flag.Value; the -v flag is of type Level and should be modified
// only through the flag.Value interface.
//
// Level 被导出，因为它出现在 V 的参数中并且是 v 标志的类型，可以通过编程方式设置。
// 它是另一种类型，因为我们希望将它与 logType 去区分开。
// Leval 的值只能在 logging.mu 上锁时被改变。
// -v 标志只能使用原子操作读取，所以日志模块的状态是一致的。
//
// Level 被视为 sync/atomic int32。
//
// Level 指定 V 日志的详细等级。*Level 实现了 flag.Value。-v 标志是 Level 类型，
// 并且应该只能通过 flag.Value 接口被修改。
type Level int32

// get returns the value of the Level.
//
// get 返回 Level 的值。
func (l *Level) get() Level {
	return Level(atomic.LoadInt32((*int32)(l)))
}

// set sets the value of the Level.
//
// set 设置 Level 的值。
func (l *Level) set(val Level) {
	atomic.StoreInt32((*int32)(l), int32(val))
}

// String is part of the flag.Value interface.
//
// String 是 flag.Value 接口的一部分。
func (l *Level) String() string {
	return strconv.FormatInt(int64(*l), 10)
}

// Get is part of the flag.Value interface.
//
// Get 是 flag.Value 接口的一部分。
func (l *Level) Get() interface{} {
	return *l
}

// Set is part of the flag.Value interface.
//
// Set 是 flag.Value 接口的一部分。
func (l *Level) Set(value string) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	logging.setVState(Level(v), logging.vmodule.filter, false)
	return nil
}

// moduleSpec represents the setting of the -vmodule flag.
//
// moduleSpec 代表 -vmodule 标志的设置。
type moduleSpec struct {
	filter []modulePat
}

// modulePat contains a filter for the -vmodule flag.
// It holds a verbosity level and a file pattern to match.
//
// modulePat 包含 -vmodule 标志的过滤器。
// 它包含日志详细等级和匹配文件的模式。
type modulePat struct {
	pattern string
	// pattern 是一个文字串。（即不含元字符，非正则匹配）
	literal bool // The pattern is a literal string
	level   Level
}

// match reports whether the file matches the pattern. It uses a string
// comparison if the pattern contains no metacharacters.
//
// match 检测是否有文件与 pattern 匹配。如果 pattern 不包含元字符，将直接比较字符串。
func (m *modulePat) match(file string) bool {
	if m.literal {
		return file == m.pattern
	}
	match, _ := filepath.Match(m.pattern, file)
	return match
}

func (m *moduleSpec) String() string {
	// Lock because the type is not atomic. TODO: clean this up.
	//
	// 上锁是因为不是原子操作。TODO: 将此清除。
	logging.mu.Lock()
	defer logging.mu.Unlock()
	var b bytes.Buffer
	for i, f := range m.filter {
		if i > 0 {
			b.WriteRune(',')
		}
		fmt.Fprintf(&b, "%s=%d", f.pattern, f.level)
	}
	return b.String()
}

// Get is part of the (Go 1.2) flag.Getter interface. It always returns nil for this flag type since the
// struct is not exported.
//
// Get 是（Go 1.2）flag.Getter 接口的一部分。它始终返回空，因为结构未导出。
func (m *moduleSpec) Get() interface{} {
	return nil
}

var errVmoduleSyntax = errors.New("syntax error: expect comma-separated list of filename=N")

// Syntax: -vmodule=recordio=2,file=1,gfs*=3
//
// 语法：-vmodule=recordio=2,file=1,gfs*=3
func (m *moduleSpec) Set(value string) error {
	var filter []modulePat
	for _, pat := range strings.Split(value, ",") {
		if len(pat) == 0 {
			// Empty strings such as from a trailing comma can be ignored.
			//
			// 尾随逗号的空字符串可以被忽略。
			continue
		}
		patLev := strings.Split(pat, "=")
		if len(patLev) != 2 || len(patLev[0]) == 0 || len(patLev[1]) == 0 {
			return errVmoduleSyntax
		}
		pattern := patLev[0]
		v, err := strconv.Atoi(patLev[1])
		if err != nil {
			return errors.New("syntax error: expect comma-separated list of filename=N")
		}
		if v < 0 {
			return errors.New("negative value for vmodule level")
		}
		if v == 0 {
			continue // Ignore. It's harmless but no point in paying the overhead.
		}
		// TODO: check syntax of filter?
		//
		// TODO: 检查过滤器的语法？
		filter = append(filter, modulePat{pattern, isLiteral(pattern), Level(v)})
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	logging.setVState(logging.verbosity, filter, true)
	return nil
}

// isLiteral reports whether the pattern is a literal string, that is, has no metacharacters
// that require filepath.Match to be called to match the pattern.
//
// isLiteral 检测 pattern 是否是一个文字串，即没有元字符需要调用 filepath.Match 来匹配 pattern。
func isLiteral(pattern string) bool {
	return !strings.ContainsAny(pattern, `\*?[]`)
}

// traceLocation represents the setting of the -log_backtrace_at flag.
//
// traceLocation 代表 -log_backtrace_at 标志的设置。
type traceLocation struct {
	file string
	line int
}

// isSet reports whether the trace location has been specified.
// logging.mu is held.
//
// isSet 检测是否已指定跟踪位置。
// logging.mu 已上锁。
func (t *traceLocation) isSet() bool {
	return t.line > 0
}

// match reports whether the specified file and line matches the trace location.
// The argument file name is the full path, not the basename specified in the flag.
// logging.mu is held.
//
// match 检测指定的文件和行是否与跟踪位置匹配。
// 参数中的文件名可能是完整路径，而不非标志中指定的基本名称。
// logging.mu 已上锁。
func (t *traceLocation) match(file string, line int) bool {
	if t.line != line {
		return false
	}
	if i := strings.LastIndex(file, "/"); i >= 0 {
		file = file[i+1:]
	}
	return t.file == file
}

func (t *traceLocation) String() string {
	// Lock because the type is not atomic. TODO: clean this up.
	//
	// 上锁因为不是原子操作。TODO: 将此清除。
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return fmt.Sprintf("%s:%d", t.file, t.line)
}

// Get is part of the (Go 1.2) flag.Getter interface. It always returns nil for this flag type since the
// struct is not exported
//
// Get 是（Go 1.2）flag.Getter 接口的一部分。它始终返回空，因为结构未导出。
func (t *traceLocation) Get() interface{} {
	return nil
}

var errTraceSyntax = errors.New("syntax error: expect file.go:234")

// Syntax: -log_backtrace_at=gopherflakes.go:234
// Note that unlike vmodule the file extension is included here.
//
// 语法：-log_backtrace_at=gopherflakes.go:234
// 注意，与 vmodule 不同，此处包含文件扩展名。
func (t *traceLocation) Set(value string) error {
	if value == "" {
		// Unset.
		//
		// 不设置。
		t.line = 0
		t.file = ""
	}
	fields := strings.Split(value, ":")
	if len(fields) != 2 {
		return errTraceSyntax
	}
	file, line := fields[0], fields[1]
	if !strings.Contains(file, ".") {
		return errTraceSyntax
	}
	v, err := strconv.Atoi(line)
	if err != nil {
		return errTraceSyntax
	}
	if v <= 0 {
		return errors.New("negative or zero value for level")
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	t.line = v
	t.file = file
	return nil
}

// flushSyncWriter is the interface satisfied by logging destinations.
//
// flushSyncWriter 是记录器所满足的接口。
type flushSyncWriter interface {
	Flush() error
	Sync() error
	io.Writer
}

func init() {
	// Default stderrThreshold is ERROR.
	//
	// 默认的 stderrThreshold 等级为 ERROR。
	logging.stderrThreshold = errorLog

	logging.setVState(0, nil, false)
	go logging.flushDaemon()
}

// InitFlags is for explicitly initializing the flags
//
// InitFlags 用于显式初始化标志
func InitFlags(flagset *flag.FlagSet) {
	if flagset == nil {
		flagset = flag.CommandLine
	}
	flagset.StringVar(&logging.logDir, "log_dir", "", "If non-empty, write log files in this directory")
	flagset.StringVar(&logging.logFile, "log_file", "", "If non-empty, use this log file")
	flagset.BoolVar(&logging.toStderr, "logtostderr", false, "log to standard error instead of files")
	flagset.BoolVar(&logging.alsoToStderr, "alsologtostderr", false, "log to standard error as well as files")
	flagset.Var(&logging.verbosity, "v", "log level for V logs")
	flagset.BoolVar(&logging.skipHeaders, "skip_headers", false, "If true, avoid header prefixes in the log messages")
	flagset.Var(&logging.stderrThreshold, "stderrthreshold", "logs at or above this threshold go to stderr")
	flagset.Var(&logging.vmodule, "vmodule", "comma-separated list of pattern=N settings for file-filtered logging")
	flagset.Var(&logging.traceLocation, "log_backtrace_at", "when logging hits line file:N, emit a stack trace")
}

// Flush flushes all pending log I/O.
//
// Flush 刷新所有挂起的日志 I/O。
func Flush() {
	logging.lockAndFlushAll()
}

// loggingT collects all the global state of the logging setup.
//
// loggingT 包含日志设置的所有全局状态。
type loggingT struct {
	// Boolean flags. Not handled atomically because the flag.Value interface
	// does not let us avoid the =true, and that shorthand is necessary for
	// compatibility. TODO: does this matter enough to fix? Seems unlikely.
	//
	// 布尔标志。因为 flag.Value 接口让我们使用 -name 而避免使用 -name=true 的方式，所以没有以原子的
	// 方式处理，而对于兼容性这种简写的方式是必要的。TODO: 这件事能解决吗？似乎不太可能。
	// -logtostderr 标志。
	toStderr bool // The -logtostderr flag.
	// -alsologtostderr 标志。
	alsoToStderr bool // The -alsologtostderr flag.

	// Level flag. Handled atomically.
	//
	// 日志等级标志。以原子的方式处理。
	// -stderrthreshold 标志。
	stderrThreshold severity // The -stderrthreshold flag.

	// freeList is a list of byte buffers, maintained under freeListMu.
	//
	// freeList 一个在 freeListMu 维护下的 buffer 列表。
	freeList *buffer
	// freeListMu maintains the free list. It is separate from the main mutex
	// so buffers can be grabbed and printed to without holding the main lock,
	// for better parallelization.
	//
	// freeListMu 维护着空闲列表。为了更好的并行，它与主互斥锁分开，因此可以抓住并打印缓冲区而无需控制主锁。
	freeListMu sync.Mutex

	// mu protects the remaining elements of this structure and is
	// used to synchronize logging.
	//
	// mu 保护这个结构的剩余元素，它用于同步日志记录。
	mu sync.Mutex
	// file holds writer for each of the log types.
	//
	// file 保存每种类型日志的 writer。
	file [numSeverity]flushSyncWriter
	// pcs is used in V to avoid an allocation when computing the caller's PC.
	//
	// 在 V 中所以 pcs 来避免计算调用者 PC 时进行的分配。
	pcs [1]uintptr
	// vmap is a cache of the V Level for each V() call site, identified by PC.
	// It is wiped whenever the vmodule flag changes state.
	//
	// vmap 是每个 V() 调用点的 V Level 的缓存，由 PC 来标识。
	// 只要 vmodule 标志改变状态，它就会被清除。
	vmap map[uintptr]Level
	// filterLength stores the length of the vmodule filter chain. If greater
	// than zero, it means vmodule is enabled. It may be read safely
	// using sync.LoadInt32, but is only modified under mu.
	//
	// filterLength 存储 vmodule 过滤器链的长度。如果大于 0，就表明启用了 vmodule。
	// 它可以使用 sync.LoadInt32 进行安全地读取，但是仅在 mu 上锁的情况下进行修改。
	filterLength int32
	// traceLocation is the state of the -log_backtrace_at flag.
	//
	// traceLocation 是 -log_backtrace_at 标志的状态。
	traceLocation traceLocation
	// These flags are modified only under lock, although verbosity may be fetched
	// safely using atomic.LoadInt32.
	//
	// 虽然详细等级可以使用 atomic.LoadInt32 安全地获取到，但是这些标志仅在上锁的情况下进行修改。
	// -vmodule 标志的状态。
	vmodule moduleSpec // The state of the -vmodule flag.
	// V 日志等级，-v 标志的值
	verbosity Level // V logging level, the value of the -v flag

	// If non-empty, overrides the choice of directory in which to write logs.
	// See createLogDirs for the full list of possible destinations.
	//
	// 如果不为空，覆盖选择写入日志的目录。
	// 有关可能目标的完整列表，请参阅 createLogDirs。
	logDir string

	// If non-empty, specifies the path of the file to write logs. mutually exclusive
	// with the log-dir option.
	//
	// 如果不为空，则指定要写入日志的文件路径。与 log-dir 选项互斥。
	logFile string

	// If true, do not add the prefix headers, useful when used with SetOutput
	//
	// 如果为 true，将不会添加前缀日志头，与 SetOutput 一起使用时非常有用。
	skipHeaders bool
}

// buffer holds a byte Buffer for reuse. The zero value is ready for use.
//
// buffer 重用 bytes.Buffer 的方法。零值是可以使用的。
type buffer struct {
	bytes.Buffer
	// 用于创建日志头的临时字节数组。
	tmp  [64]byte // temporary byte array for creating headers.
	next *buffer
}

var logging loggingT

// setVState sets a consistent state for V logging.
// l.mu is held.
//
// setVState 为 V 日志记录设置一致状态。
// l.mu 已上锁。
func (l *loggingT) setVState(verbosity Level, filter []modulePat, setFilter bool) {
	// Turn verbosity off so V will not fire while we are in transition.
	//
	// 关闭详细等级以便在过渡期不触发 V。
	logging.verbosity.set(0)
	// Ditto for filter length.
	//
	// 过滤器长度同上。
	atomic.StoreInt32(&logging.filterLength, 0)

	// Set the new filters and wipe the pc->Level map if the filter has changed.
	//
	// 设置新的过滤器，并且如果过滤器更改，将清除 pc->Level 的映射。
	if setFilter {
		logging.vmodule.filter = filter
		logging.vmap = make(map[uintptr]Level)
	}

	// Things are consistent now, so enable filtering and verbosity.
	// They are enabled in order opposite to that in V.
	//
	// 现在事情是一致的，所以启用过滤器和消息记录。
	// 以相反的顺序启用它们。
	// TSK: 为什么以相反的顺序启用。
	atomic.StoreInt32(&logging.filterLength, int32(len(filter)))
	logging.verbosity.set(verbosity)
}

// getBuffer returns a new, ready-to-use buffer.
//
// getBuffer 返回一个新的、可立即使用的缓冲区。
func (l *loggingT) getBuffer() *buffer {
	l.freeListMu.Lock()
	b := l.freeList
	if b != nil {
		l.freeList = b.next
	}
	l.freeListMu.Unlock()
	if b == nil {
		b = new(buffer)
	} else {
		b.next = nil
		b.Reset()
	}
	return b
}

// putBuffer returns a buffer to the free list.
//
// putBuffer 将一个 buffer 放回空闲列表。
func (l *loggingT) putBuffer(b *buffer) {
	if b.Len() >= 256 {
		// Let big buffers die a natural death.
		//
		// 让大的缓冲区被 GC 自动回收。
		return
	}
	l.freeListMu.Lock()
	b.next = l.freeList
	l.freeList = b
	l.freeListMu.Unlock()
}

// 用于测试的存根。
var timeNow = time.Now // Stubbed out for testing.

/*
header formats a log header as defined by the C++ implementation.
It returns a buffer containing the formatted header and the user's file and line number.
The depth specifies how many stack frames above lives the source line to be identified in the log message.

Log lines have this form:
	Lmmdd hh:mm:ss.uuuuuu threadid file:line] msg...
where the fields are defined as follows:
	L                A single character, representing the log level (eg 'I' for INFO)
	mm               The month (zero padded; ie May is '05')
	dd               The day (zero padded)
	hh:mm:ss.uuuuuu  Time in hours, minutes and fractional seconds
	threadid         The space-padded thread ID as returned by GetTID()
	file             The file name
	line             The line number
	msg              The user-supplied message
*/
/*
header 格式化 C++ 实现定义的日志头。
它返回一个缓冲区，它包含格式化的日志头以及用户文件和行号。
depth 指明在日志信息中要标识出的文件和行号相对调用函数所在行上面的堆栈层数。

日志行具有以下形式：
	Lmmdd hh:mm:ss.uuuuuu threadid file:line] msg...
字段定义如下：
	L                单个字符，表示日志级别（例如，"I" 表示 INFO）
	mm               月份（零填充，例如五月是 "05"）
	dd               日期（零填充）
	hh:mm:ss.uuuuuu  以小时、分钟、微秒表示的时间
	threadid         由 GetTID() 返回的空格填充的线程 ID
	file             文件名
	line             行号
	msg              用户提供的信息
*/
func (l *loggingT) header(s severity, depth int) (*buffer, string, int) {
	_, file, line, ok := runtime.Caller(3 + depth)
	if !ok {
		file = "???"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		if slash >= 0 {
			file = file[slash+1:]
		}
	}
	return l.formatHeader(s, file, line), file, line
}

// formatHeader formats a log header using the provided file name and line number.
//
// formatHeader 使用提供的文件名和行号格式化日志头。
func (l *loggingT) formatHeader(s severity, file string, line int) *buffer {
	now := timeNow()
	if line < 0 {
		// 不是真正的行号，但是某些数字是可以接受的。
		line = 0 // not a real line number, but acceptable to someDigits
	}
	if s > fatalLog {
		// 为了安全
		s = infoLog // for safety.
	}
	buf := l.getBuffer()
	if l.skipHeaders {
		return buf
	}

	// Avoid Fprintf, for speed. The format is so simple that we can do it quickly by hand.
	// It's worth about 3X. Fprintf is hard.
	//
	// 为了提高速度，避免使用 Fprintf。格式非常简单，我们可以手动快速完成。
	// 它的速度大约是 Fprintf 的三倍。Fprintf 很慢。
	_, month, day := now.Date()
	hour, minute, second := now.Clock()
	// Lmmdd hh:mm:ss.uuuuuu threadid file:line]
	buf.tmp[0] = severityChar[s]
	buf.twoDigits(1, int(month))
	buf.twoDigits(3, day)
	buf.tmp[5] = ' '
	buf.twoDigits(6, hour)
	buf.tmp[8] = ':'
	buf.twoDigits(9, minute)
	buf.tmp[11] = ':'
	buf.twoDigits(12, second)
	buf.tmp[14] = '.'
	buf.nDigits(6, 15, now.Nanosecond()/1000, '0')
	buf.tmp[21] = ' '
	// TODO: 应该是 TID
	buf.nDigits(7, 22, pid, ' ') // TODO: should be TID
	buf.tmp[29] = ' '
	buf.Write(buf.tmp[:30])
	buf.WriteString(file)
	buf.tmp[0] = ':'
	n := buf.someDigits(1, line)
	buf.tmp[n+1] = ']'
	buf.tmp[n+2] = ' '
	buf.Write(buf.tmp[:n+3])
	return buf
}

// Some custom tiny helper functions to print the log header efficiently.
//
// 一些自定义的小辅助函数用于有效地打印日志头。

const digits = "0123456789"

// twoDigits formats a zero-prefixed two-digit integer at buf.tmp[i].
//
// twoDigits 将 buf.tmp[i:i+1] 赋值为两位整数，不足两位左填充零。
func (buf *buffer) twoDigits(i, d int) {
	buf.tmp[i+1] = digits[d%10]
	d /= 10
	buf.tmp[i] = digits[d%10]
}

// nDigits formats an n-digit integer at buf.tmp[i],
// padding with pad on the left.
// It assumes d >= 0.
//
// nDigits 将 buf.tmp[i:i+n-1] 赋值为 n 位整数，不足 n 位左填充 pad。
// 假定 d >= 0。
func (buf *buffer) nDigits(n, i, d int, pad byte) {
	j := n - 1
	for ; j >= 0 && d > 0; j-- {
		buf.tmp[i+j] = digits[d%10]
		d /= 10
	}
	for ; j >= 0; j-- {
		buf.tmp[i+j] = pad
	}
}

// someDigits formats a zero-prefixed variable-width integer at buf.tmp[i].
//
// someDigits 将 buf.tmp[i:] 赋值为不定常整数 d。
func (buf *buffer) someDigits(i, d int) int {
	// Print into the top, then copy down. We know there's space for at least
	// a 10-digit number.
	//
	// 先将 d 存放到 buf.tmp 的最后，然后复制到 i 后。
	// 我们知道这里至少有 10 位数字的空间。
	j := len(buf.tmp)
	for {
		j--
		buf.tmp[j] = digits[d%10]
		d /= 10
		if d == 0 {
			break
		}
	}
	return copy(buf.tmp[i:], buf.tmp[j:])
}

func (l *loggingT) println(s severity, args ...interface{}) {
	buf, file, line := l.header(s, 0)
	fmt.Fprintln(buf, args...)
	l.output(s, buf, file, line, false)
}

func (l *loggingT) print(s severity, args ...interface{}) {
	// printDepth 的参数 depth 为 1，是因为 Info 等较 InfoDepth 多了 print 这一步调用。
	l.printDepth(s, 1, args...)
}

func (l *loggingT) printDepth(s severity, depth int, args ...interface{}) {
	buf, file, line := l.header(s, depth)
	fmt.Fprint(buf, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, false)
}

func (l *loggingT) printf(s severity, format string, args ...interface{}) {
	buf, file, line := l.header(s, 0)
	fmt.Fprintf(buf, format, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, false)
}

// printWithFileLine behaves like print but uses the provided file and line number. If
// alsoLogToStderr is true, the log message always appears on standard error; it
// will also appear in the log file unless --logtostderr is set.
//
// printWithFileLine 的行为类似与 print，但是提供的的文件和行号。如果 alsoLogToStderr 为 true，
// 日志消息始终显示在标准错误中。除非设置了 --logtostderr，否则它也会出现在日志文件中。
func (l *loggingT) printWithFileLine(s severity, file string, line int, alsoToStderr bool, args ...interface{}) {
	buf := l.formatHeader(s, file, line)
	fmt.Fprint(buf, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, alsoToStderr)
}

// redirectBuffer is used to set an alternate destination for the logs
//
// redirectBuffer 用于设置日志的备用位置。
type redirectBuffer struct {
	w io.Writer
}

func (rb *redirectBuffer) Sync() error {
	return nil
}

func (rb *redirectBuffer) Flush() error {
	return nil
}

func (rb *redirectBuffer) Write(bytes []byte) (n int, err error) {
	return rb.w.Write(bytes)
}

// SetOutput sets the output destination for all severities
//
// SetOutput 设置所有严重日志的输出位置。
func SetOutput(w io.Writer) {
	for s := fatalLog; s >= infoLog; s-- {
		rb := &redirectBuffer{
			w: w,
		}
		logging.file[s] = rb
	}
}

// SetOutputBySeverity sets the output destination for specific severity
//
// SetOutputBySeverity 为指定日志严重等级设置输出目标
func SetOutputBySeverity(name string, w io.Writer) {
	sev, ok := severityByName(name)
	if !ok {
		panic(fmt.Sprintf("SetOutputBySeverity(%q): unrecognized severity name", name))
	}
	rb := &redirectBuffer{
		w: w,
	}
	logging.file[sev] = rb
}

// output writes the data to the log files and releases the buffer.
//
// output 将数据写入到日志文件中，并释放缓冲区。
func (l *loggingT) output(s severity, buf *buffer, file string, line int, alsoToStderr bool) {
	l.mu.Lock()
	if l.traceLocation.isSet() {
		if l.traceLocation.match(file, line) {
			buf.Write(stacks(false))
		}
	}
	data := buf.Bytes()
	if l.toStderr {
		os.Stderr.Write(data)
	} else {
		if alsoToStderr || l.alsoToStderr || s >= l.stderrThreshold.get() {
			os.Stderr.Write(data)
		}
		if l.file[s] == nil {
			if err := l.createFiles(s); err != nil {
				// 确保消息出现在某处。
				os.Stderr.Write(data) // Make sure the message appears somewhere.
				l.exit(err)
			}
		}
		// IMP: fallthrough 高严重等级的日志也将写入到低严重等级的日志文件中。
		switch s {
		case fatalLog:
			l.file[fatalLog].Write(data)
			fallthrough
		case errorLog:
			l.file[errorLog].Write(data)
			fallthrough
		case warningLog:
			l.file[warningLog].Write(data)
			fallthrough
		case infoLog:
			l.file[infoLog].Write(data)
		}
	}
	if s == fatalLog {
		// If we got here via Exit rather than Fatal, print no stacks.
		//
		// 如果我们通过 Exit 而不是 Fatal 到这里，则不打印堆栈信息。
		if atomic.LoadUint32(&fatalNoStacks) > 0 {
			l.mu.Unlock()
			timeoutFlush(10 * time.Second)
			os.Exit(1)
		}
		// Dump all goroutine stacks before exiting.
		// First, make sure we see the trace for the current goroutine on standard error.
		// If -logtostderr has been specified, the loop below will do that anyway
		// as the first stack in the full dump.
		//
		// 在退出之前转储所有 goroutine 的堆栈信息。
		// 首先，确保我们可以在标准错误输出中看到当前 goroutine 的堆栈信息。
		// 如果指定了 -logtostderr，则下面的循环将作为完整转储过程中第一个执行此操作的堆栈。
		if !l.toStderr {
			os.Stderr.Write(stacks(false))
		}
		// Write the stack trace for all goroutines to the files.
		//
		// 将所有 goroutines 的堆栈跟踪信息写入到文件中。
		trace := stacks(true)
		// 如果我们收到一个写入错误，我们仍然会在下面退出。
		logExitFunc = func(error) {} // If we get a write error, we'll still exit below.
		for log := fatalLog; log >= infoLog; log-- {
			// 如果设置了 -logtostderr，则可以为 nil。
			if f := l.file[log]; f != nil { // Can be nil if -logtostderr is set.
				f.Write(trace)
			}
		}
		l.mu.Unlock()
		timeoutFlush(10 * time.Second)
		// C++ 使用 -1，这很愚蠢，因为无论如何它会与 255 进行 & 运算。
		os.Exit(255) // C++ uses -1, which is silly because it's anded with 255 anyway.
	}
	l.putBuffer(buf)
	l.mu.Unlock()
	if stats := severityStats[s]; stats != nil {
		atomic.AddInt64(&stats.lines, 1)
		atomic.AddInt64(&stats.bytes, int64(len(data)))
	}
}

// timeoutFlush calls Flush and returns when it completes or after timeout
// elapses, whichever happens first. This is needed because the hooks invoked
// by Flush may deadlock when glog.Fatal is called from a hook that holds
// a lock.
//
// timeoutFlush 调用 Flush 并在完成或超时后返回（无论哪个先发生）。这是必须的，因为当上锁
// 的钩子函数调用 glog.Fatal 时，Flush 调用钩子函数就可能会导致死锁。
func timeoutFlush(timeout time.Duration) {
	done := make(chan bool, 1)
	go func() {
		// 调用 logging.lockAndFlushAll()
		Flush() // calls logging.lockAndFlushAll()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		fmt.Fprintln(os.Stderr, "glog: Flush took longer than", timeout)
	}
}

// stacks is a wrapper for runtime.Stack that attempts to recover the data for all goroutines.
//
// stacks 是 runtime.Stack 的封装，它试图恢复所有 goroutines 的数据。
func stacks(all bool) []byte {
	// We don't know how big the traces are, so grow a few times if they don't fit. Start large, though.
	//
	// 我们不知道跟踪的数据量有多大，所以 n 不够大会增长它几次。虽然开始很大。
	n := 10000
	if all {
		n = 100000
	}
	var trace []byte
	for i := 0; i < 5; i++ {
		trace = make([]byte, n)
		nbytes := runtime.Stack(trace, all)
		if nbytes < len(trace) {
			return trace[:nbytes]
		}
		n *= 2
	}
	return trace
}

// logExitFunc provides a simple mechanism to override the default behavior
// of exiting on error. Used in testing and to guarantee we reach a required exit
// for fatal logs. Instead, exit could be a function rather than a method but that
// would make its use clumsier.
//
// logExitFunc 提供了一种简单的机制去覆盖错误退出的默认行为。它被用于测试和保证我们达到崩溃日志
// 所需的出口。相反，退出可以是一个函数不是一个方法，但那会使它的使用变得更笨拙。
var logExitFunc func(error)

// exit is called if there is trouble creating or writing log files.
// It flushes the logs and exits the program; there's no point in hanging around.
// l.mu is held.
//
// 如果创建或写入日志文件时出错，则会调用 exit。
// 它会刷新日志并退出程序，此时将程序挂起没有意义。
// l.mu 已上锁。
func (l *loggingT) exit(err error) {
	fmt.Fprintf(os.Stderr, "log: exiting because of error: %s\n", err)
	// If logExitFunc is set, we do that instead of exiting.
	//
	// 如果设置了 logExitFunc，我们将会调用 logExitFunc 而不是退出。
	if logExitFunc != nil {
		logExitFunc(err)
		return
	}
	l.flushAll()
	os.Exit(2)
}

// syncBuffer joins a bufio.Writer to its underlying file, providing access to the
// file's Sync method and providing a wrapper for the Write method that provides log
// file rotation. There are conflicting methods, so the file cannot be embedded.
// l.mu is held for all its methods.
//
// syncBuffer 将 bufio.Writer 连接到其底层文件，提供对文件访问的 Sync 方法，并为 Write 方法
// 提供包装以进行日志文件的轮询。因为存在冲突的方法，所以文件不能被内嵌。
// 它的所有方法 l.mu 需要上锁。
type syncBuffer struct {
	logger *loggingT
	*bufio.Writer
	file *os.File
	sev  severity
	// 写入此文件的字节数
	nbytes uint64 // The number of bytes written to this file
}

func (sb *syncBuffer) Sync() error {
	return sb.file.Sync()
}

func (sb *syncBuffer) Write(p []byte) (n int, err error) {
	if sb.nbytes+uint64(len(p)) >= MaxSize {
		if err := sb.rotateFile(time.Now()); err != nil {
			sb.logger.exit(err)
		}
	}
	n, err = sb.Writer.Write(p)
	sb.nbytes += uint64(n)
	if err != nil {
		sb.logger.exit(err)
	}
	return
}

// rotateFile closes the syncBuffer's file and starts a new one.
//
// rotateFile 关闭 syncBuffer 的文件并启动一个新的文件。
func (sb *syncBuffer) rotateFile(now time.Time) error {
	if sb.file != nil {
		sb.Flush()
		sb.file.Close()
	}
	var err error
	sb.file, _, err = create(severityName[sb.sev], now)
	sb.nbytes = 0
	if err != nil {
		return err
	}

	sb.Writer = bufio.NewWriterSize(sb.file, bufferSize)

	// Write header.
	//
	// 写入日志头。
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Log file created at: %s\n", now.Format("2006/01/02 15:04:05"))
	fmt.Fprintf(&buf, "Running on machine: %s\n", host)
	fmt.Fprintf(&buf, "Binary: Built with %s %s for %s/%s\n", runtime.Compiler, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&buf, "Log line format: [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg\n")
	n, err := sb.file.Write(buf.Bytes())
	sb.nbytes += uint64(n)
	return err
}

// bufferSize sizes the buffer associated with each log file. It's large
// so that log records can accumulate without the logging thread blocking
// on disk I/O. The flushDaemon will block instead.
//
// bufferSize 调整与每个日志文件关联的缓冲区的大小。它很大，因此日志记录可以在没有日志
// 记录线程阻塞在磁盘 I/O 上时积累。TSK: 相反，flushDaemon 将会阻塞。
const bufferSize = 256 * 1024

// createFiles creates all the log files for severity from sev down to infoLog.
// l.mu is held.
//
// createFiles 创建参数所示严重等级到 infoLog 级的所有日志文件。
// l.mu 已上锁。
func (l *loggingT) createFiles(sev severity) error {
	now := time.Now()
	// Files are created in decreasing severity order, so as soon as we find one
	// has already been created, we can stop.
	//
	// 文件按照日志严重等级递增的顺序创建，因此一旦我们发现有的已经创建了，我们就可以停下来了。
	for s := sev; s >= infoLog && l.file[s] == nil; s-- {
		sb := &syncBuffer{
			logger: l,
			sev:    s,
		}
		if err := sb.rotateFile(now); err != nil {
			return err
		}
		l.file[s] = sb
	}
	return nil
}

const flushInterval = 30 * time.Second

// flushDaemon periodically flushes the log file buffers.
//
// flushDaemon 定期刷新日志文件缓冲区。
// 刷新间隔时间 flushInterval = 30 * time.Second
func (l *loggingT) flushDaemon() {
	for range time.NewTicker(flushInterval).C {
		l.lockAndFlushAll()
	}
}

// lockAndFlushAll is like flushAll but locks l.mu first.
//
// lockAndFlushAll 同 flushAll 一样，但是会先对 l.mu 上锁。
func (l *loggingT) lockAndFlushAll() {
	l.mu.Lock()
	l.flushAll()
	l.mu.Unlock()
}

// flushAll flushes all the logs and attempts to "sync" their data to disk.
// l.mu is held.
//
// flushAll 刷新所有日志并尝试将其数据同步到磁盘。
// l.mu 已被上锁。
func (l *loggingT) flushAll() {
	// Flush from fatal down, in case there's trouble flushing.
	//
	// Flush 从 fatal 级别开始然后递减，以防刷新和同步过程出错。
	for s := fatalLog; s >= infoLog; s-- {
		file := l.file[s]
		if file != nil {
			// 忽略错误
			file.Flush() // ignore error
			// 忽略错误
			file.Sync() // ignore error
		}
	}
}

// CopyStandardLogTo arranges for messages written to the Go "log" package's
// default logs to also appear in the Google logs for the named and lower
// severities. Subsequent changes to the standard log's default output location
// or format may break this behavior.
//
// Valid names are "INFO", "WARNING", "ERROR", and "FATAL".  If the name is not
// recognized, CopyStandardLogTo panics.
//
// CopyStandardLogTo 写入到 Go "log" 包的默认日志消息也将出现在 Google 日志中，使用命名的
// 方式和较低的日志严重等级。对标准日志的默认输出位置或格式的后续修改可能会破环此行为。
func CopyStandardLogTo(name string) {
	sev, ok := severityByName(name)
	if !ok {
		panic(fmt.Sprintf("log.CopyStandardLogTo(%q): unrecognized severity name", name))
	}
	// Set a log format that captures the user's file and line:
	//   d.go:23: message
	//
	// 设置所获取的用户文件和行号的格式：
	//   d.go:23: message
	stdLog.SetFlags(stdLog.Lshortfile)
	stdLog.SetOutput(logBridge(sev))
}

// logBridge provides the Write method that enables CopyStandardLogTo to connect
// Go's standard logs to the logs provided by this package.
//
// logBridge 提供 Write 方法，使 CopyStandardLogTo 连接到 Go 标准包 log 并记录此包提供到日志。
type logBridge severity

// Write parses the standard logging line and passes its components to the
// logger for severity(lb).
//
// Write 解析标志日志行号并将其组成传给 logger。
func (lb logBridge) Write(b []byte) (n int, err error) {
	var (
		file = "???"
		line = 1
		text string
	)
	// Split "d.go:23: message" into "d.go", "23", and "message".
	//
	// 将 "d.go:23: message" 分割成 "d.go"、"23" 和 "message"。
	if parts := bytes.SplitN(b, []byte{':'}, 3); len(parts) != 3 || len(parts[0]) < 1 || len(parts[2]) < 1 {
		text = fmt.Sprintf("bad log format: %s", b)
	} else {
		file = string(parts[0])
		text = string(parts[2][1:]) // skip leading space
		line, err = strconv.Atoi(string(parts[1]))
		if err != nil {
			text = fmt.Sprintf("bad line number: %s", b)
			line = 1
		}
	}
	// printWithFileLine with alsoToStderr=true, so standard log messages
	// always appear on standard error.
	//
	// 使用 printWithFileLine 时 alsoToStderr=true，因此标准日志消息总是出现在标
	// 准错误中。
	logging.printWithFileLine(severity(lb), file, line, true, text)
	return len(b), nil
}

// setV computes and remembers the V level for a given PC
// when vmodule is enabled.
// File pattern matching takes the basename of the file, stripped
// of its .go suffix, and uses filepath.Match, which is a little more
// general than the *? matching used in C++.
// l.mu is held.
//
// setV 在启用 vmodule 时，计算并储存给定 PC 的 V 等级。
// 文件模式匹配采用文件的基本名称，去掉了 .go 后缀，并使用了 filepath.Match 函数，这比
// C++ 中使用的 *? 匹配更加通用。
// l.mu 已上锁。
func (l *loggingT) setV(pc uintptr) Level {
	fn := runtime.FuncForPC(pc)
	file, _ := fn.FileLine(pc)
	// The file is something like /a/b/c/d.go. We want just the d.
	//
	// 该文件类似于 /a/b/c/d.go。我们只想要 d。
	if strings.HasSuffix(file, ".go") {
		file = file[:len(file)-3]
	}
	if slash := strings.LastIndex(file, "/"); slash >= 0 {
		file = file[slash+1:]
	}
	for _, filter := range l.vmodule.filter {
		if filter.match(file) {
			l.vmap[pc] = filter.level
			return filter.level
		}
	}
	l.vmap[pc] = 0
	return 0
}

// Verbose is a boolean type that implements Infof (like Printf) etc.
// See the documentation of V for more information.
//
// Verbose 是一个布尔类型，它实现了 Infof（像 Printf）等。
// 更多信息请查阅 V 的文档。
type Verbose bool

// V reports whether verbosity at the call site is at least the requested level.
// The returned value is a boolean of type Verbose, which implements Info, Infoln
// and Infof. These methods will write to the Info log if called.
// Thus, one may write either
//	if glog.V(2) { glog.Info("log this") }
// or
//	glog.V(2).Info("log this")
// The second form is shorter but the first is cheaper if logging is off because it does
// not evaluate its arguments.
//
// Whether an individual call to V generates a log record depends on the setting of
// the -v and --vmodule flags; both are off by default. If the level in the call to
// V is at least the value of -v, or of -vmodule for the source file containing the
// call, the V call will log.
//
// V 检测在调用点的详细等级是否至少是要求的级别。
// 返回的值是 Verbose 类型的布尔值，它实现了 Info、Infoln、Infof。如果调用这些方法，将写入 Info 日志中。
// 因此，我们可以使用下面的任何一种形式：
//	if glog.V(2) { glog.Info("log this") }
// 或者
//	glog.V(2).Info("log this")
// TSK: 第二种形式更短，但是如果没有开启 V 日志第一种形式的开销更小，因为它不会评测参数。
//
// 单个 V 的调用是否生成日志记录取决于 -v 和 -vmodule 标志的设置，两者都默认关闭。如果 V 的调用级别至少是
// -v 的值或 -vmodule 源文件包含此调用，则 V 调用将记录。
func V(level Level) Verbose {
	// This function tries hard to be cheap unless there's work to do.
	// The fast path is two atomic loads and compares.
	//
	// 除非对此处进行修改，否则此函数的开销很难变小。
	// 快速途径是两次原子加载并比较。

	// Here is a cheap but safe test to see if V logging is enabled globally.
	//
	// 这是一个低开销且安全的测试，用于查看是否全局开启了 V 日志。
	if logging.verbosity.get() >= level {
		return Verbose(true)
	}

	// It's off globally but it vmodule may still be set.
	// Here is another cheap but safe test to see if vmodule is enabled.
	//
	// 它可能没有开启全局的，但是仍然可能设置了 vmodule。
	// 这是另一个低开销且安全的测试，用于查看是否开启了 vmodule。
	if atomic.LoadInt32(&logging.filterLength) > 0 {
		// Now we need a proper lock to use the logging structure. The pcs field
		// is shared so we must lock before accessing it. This is fairly expensive,
		// but if V logging is enabled we're slow anyway.
		//
		// 现在我们需要一个适当的锁来使用日志记录结构。pcs 字段是共享的，所以我们在访问它之前必须
		// 上锁。此时开销相当大，但是如果启用了 V 日志记录，我们无论如何都很慢。
		logging.mu.Lock()
		defer logging.mu.Unlock()
		// TSK:
		if runtime.Callers(2, logging.pcs[:]) == 0 {
			return Verbose(false)
		}
		v, ok := logging.vmap[logging.pcs[0]]
		if !ok {
			v = logging.setV(logging.pcs[0])
		}
		return Verbose(v >= level)
	}
	return Verbose(false)
}

// Info is equivalent to the global Info function, guarded by the value of v.
// See the documentation of V for usage.
//
// Info 等同于全局的 Info 功能，由 v 的值保护。
// 有关用法，请参阅 V 的文档。
func (v Verbose) Info(args ...interface{}) {
	if v {
		logging.print(infoLog, args...)
	}
}

// Infoln is equivalent to the global Infoln function, guarded by the value of v.
// See the documentation of V for usage.
//
// Infoln 等同于全局的 Infoln 功能，由 v 的值保护。
// 有关用法，请参阅 V 的文档。
func (v Verbose) Infoln(args ...interface{}) {
	if v {
		logging.println(infoLog, args...)
	}
}

// Infof is equivalent to the global Infof function, guarded by the value of v.
// See the documentation of V for usage.
//
// Infof 等同于全局的 Infof 功能，由 v 的值保护。
// 有关用法，请参阅 V 的文档。
func (v Verbose) Infof(format string, args ...interface{}) {
	if v {
		logging.printf(infoLog, format, args...)
	}
}

// Info logs to the INFO log.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
//
// Info 记录到 INFO 日志中。
// 参数以 fmt.Print 的方式处理，如果没有参数，则附加换行符。
func Info(args ...interface{}) {
	logging.print(infoLog, args...)
}

// InfoDepth acts as Info but uses depth to determine which call frame to log.
// InfoDepth(0, "msg") is the same as Info("msg").
//
// InfoDepth 做的处理同 Info 一样，但是使用 depth 来确定要记录到调用帧。
// InfoDepth(0, "msg") 同 Info("msg") 一样。
func InfoDepth(depth int, args ...interface{}) {
	logging.printDepth(infoLog, depth, args...)
}

// Infoln logs to the INFO log.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
//
// Infoln 记录到 INFO 日志中。
// 参数以 fmt.Println 的方式处理，如果没有参数，则附加换行符。
func Infoln(args ...interface{}) {
	logging.println(infoLog, args...)
}

// Infof logs to the INFO log.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
//
// Infof 记录到 INFO 日志中。
// 参数以 fmt.Printf 的方式处理，如果没有参数，则附加换行符。
func Infof(format string, args ...interface{}) {
	logging.printf(infoLog, format, args...)
}

// Warning logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
//
// Warning 记录到 WARNING 和 INFO 日志中。
// 参数以 fmt.Print 的方式处理，如果没有参数，则附加换行符。
func Warning(args ...interface{}) {
	logging.print(warningLog, args...)
}

// WarningDepth acts as Warning but uses depth to determine which call frame to log.
// WarningDepth(0, "msg") is the same as Warning("msg").
//
// WarningDepth 做的处理同 Warning 一样，但是使用 depth 来确定要记录到调用帧。
// WarningDepth(0, "msg") 同 Warning("msg") 一样。
func WarningDepth(depth int, args ...interface{}) {
	logging.printDepth(warningLog, depth, args...)
}

// Warningln logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
//
// Warningln 记录到 WARNING 和 INFO 日志中。
// 参数以 fmt.Println 的方式处理，如果没有参数，则附加换行符。
func Warningln(args ...interface{}) {
	logging.println(warningLog, args...)
}

// Warningf logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
//
// Warningf 记录到 WARNING 和 INFO 日志中。
// 参数以 fmt.Printf 的方式处理，如果没有参数，则附加换行符。
func Warningf(format string, args ...interface{}) {
	logging.printf(warningLog, format, args...)
}

// Error logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
//
// Error 记录到 Error、WARNING 和 INFO 日志中。
// 参数以 fmt.Print 的方式处理，如果没有参数，则附加换行符。
func Error(args ...interface{}) {
	logging.print(errorLog, args...)
}

// ErrorDepth acts as Error but uses depth to determine which call frame to log.
// ErrorDepth(0, "msg") is the same as Error("msg").
//
// ErrorDepth 做的处理同 Error 一样，但是使用 depth 来确定要记录到调用帧。
// ErrorDepth(0, "msg") 同 Error("msg") 一样。
func ErrorDepth(depth int, args ...interface{}) {
	logging.printDepth(errorLog, depth, args...)
}

// Errorln logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
//
// Errorln 记录到 Error、WARNING 和 INFO 日志中。
// 参数以 fmt.Println 的方式处理，如果没有参数，则附加换行符。
func Errorln(args ...interface{}) {
	logging.println(errorLog, args...)
}

// Errorf logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
//
// Errorf 记录到 Error、WARNING 和 INFO 日志中。
// 参数以 fmt.Printf 的方式处理，如果没有参数，则附加换行符。
func Errorf(format string, args ...interface{}) {
	logging.printf(errorLog, format, args...)
}

// Fatal logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
//
// Fatal 记录到 Fatal、Error、WARNING 和 INFO 日志中，包括所有正在运行的 goroutines 的堆栈跟踪消息
// ，然后调用 os.Exit(255)。
// 参数以 fmt.Print 的方式处理，如果没有参数，则附加换行符。
func Fatal(args ...interface{}) {
	logging.print(fatalLog, args...)
}

// FatalDepth acts as Fatal but uses depth to determine which call frame to log.
// FatalDepth(0, "msg") is the same as Fatal("msg").
//
// FatalDepth 做的处理同 Fatal 一样，但是使用 depth 来确定要记录到调用帧。
// FatalDepth(0, "msg") 同 Fatal("msg") 一样。
func FatalDepth(depth int, args ...interface{}) {
	logging.printDepth(fatalLog, depth, args...)
}

// Fatalln logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
//
// Fatalln 记录到 Fatal、Error、WARNING 和 INFO 日志中，包括所有正在运行的 goroutines 的堆栈跟踪消息
// ，然后调用 os.Exit(255)。
// 参数以 fmt.Println 的方式处理，如果没有参数，则附加换行符。
func Fatalln(args ...interface{}) {
	logging.println(fatalLog, args...)
}

// Fatalf logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
//
// Fatalf 记录到 Fatal、Error、WARNING 和 INFO 日志中，包括所有正在运行的 goroutines 的堆栈跟踪消息
// ，然后调用 os.Exit(255)。
// 参数以 fmt.Printf 的方式处理，如果没有参数，则附加换行符。
func Fatalf(format string, args ...interface{}) {
	logging.printf(fatalLog, format, args...)
}

// fatalNoStacks is non-zero if we are to exit without dumping goroutine stacks.
// It allows Exit and relatives to use the Fatal logs.
//
// 如果我们要退出而不转储 goroutine 的堆栈信息，fatalNoStacks 将不为零。
// 它允许 Exit 访问，并且与 Fatal 日志有关系。
var fatalNoStacks uint32

// Exit logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
//
// Exit 记录到 Fatal、Error、WARNING 和 INFO 日志中，然后调用 os.Exit(1)。
// 参数以 fmt.Print 的方式处理，如果没有参数，则附加换行符。
func Exit(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.print(fatalLog, args...)
}

// ExitDepth acts as Exit but uses depth to determine which call frame to log.
// ExitDepth(0, "msg") is the same as Exit("msg").
//
// ExitDepth 做的处理同 Exit 一样，但是使用 depth 来确定要记录到调用帧。
// ExitDepth(0, "msg") 同 Exit("msg") 一样。
func ExitDepth(depth int, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printDepth(fatalLog, depth, args...)
}

// Exitln logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
//
// Exitln 记录到 Fatal、Error、WARNING 和 INFO 日志中，然后调用 os.Exit(1)。
// 参数以 fmt.Println 的方式处理，如果没有参数，则附加换行符。
func Exitln(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.println(fatalLog, args...)
}

// Exitf logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
//
// Exitf 记录到 Fatal、Error、WARNING 和 INFO 日志中，然后调用 os.Exit(1)。
// 参数以 fmt.Printf 的方式处理，如果没有参数，则附加换行符。
func Exitf(format string, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printf(fatalLog, format, args...)
}
