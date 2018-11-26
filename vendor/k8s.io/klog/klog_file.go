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

// File I/O for logs.
//
// 日志文件 I/O

package klog

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxSize is the maximum size of a log file in bytes.
//
// MaxSize 是一个日志文件的最大字节数。
var MaxSize uint64 = 1024 * 1024 * 1800

// logDirs lists the candidate directories for new log files.
//
// logDirs 列出新日志文件的候选目录。
var logDirs []string

func createLogDirs() {
	if logging.logDir != "" {
		logDirs = append(logDirs, logging.logDir)
	}
	logDirs = append(logDirs, os.TempDir())
}

var (
	pid      = os.Getpid()
	program  = filepath.Base(os.Args[0])
	host     = "unknownhost"
	userName = "unknownuser"
)

func init() {
	h, err := os.Hostname()
	if err == nil {
		host = shortHostname(h)
	}

	current, err := user.Current()
	if err == nil {
		userName = current.Username
	}

	// Sanitize userName since it may contain filepath separators on Windows.
	//
	// 清理 userName 因为在 Windows 上它可能包含文件路径分隔符。
	userName = strings.Replace(userName, `\`, "_", -1)
}

// shortHostname returns its argument, truncating at the first period.
// For instance, given "www.google.com" it returns "www".
//
// shortHostname 返回其参数在第一个句点处的截断。
// 例如，给定 "www.google.com" 它将返回 "www"。
func shortHostname(hostname string) string {
	if i := strings.Index(hostname, "."); i >= 0 {
		return hostname[:i]
	}
	return hostname
}

// logName returns a new log file name containing tag, with start time t, and
// the name for the symlink for tag.
//
// logName 返回一个新的包日志文件名，其含标签、开始时间 t 和用于标签符号链接的名字。
func logName(tag string, t time.Time) (name, link string) {
	name = fmt.Sprintf("%s.%s.%s.log.%s.%04d%02d%02d-%02d%02d%02d.%d",
		program,
		host,
		userName,
		tag,
		t.Year(),
		t.Month(),
		t.Day(),
		t.Hour(),
		t.Minute(),
		t.Second(),
		pid)
	return name, program + "." + tag
}

var onceLogDirs sync.Once

// create creates a new log file and returns the file and its filename, which
// contains tag ("INFO", "FATAL", etc.) and t. If the file is created
// successfully, create also attempts to update the symlink for that tag, ignoring
// errors.
//
// create 创建一个新的日志文件并返回文件和它的文件名，文件名包含标签（例如，"INFO"、"FATAL"）和
// 时间。如果文件成功创建，create 也会尝试更新标签的符号链接（忽略错误）。
// IMP: 使用符号链接就可以不更新文件名变量就指向最新的文件。
func create(tag string, t time.Time) (f *os.File, filename string, err error) {
	if logging.logFile != "" {
		f, err := os.Create(logging.logFile)
		if err == nil {
			return f, logging.logFile, nil
		}
		return nil, "", fmt.Errorf("log: unable to create log: %v", err)
	}
	onceLogDirs.Do(createLogDirs)
	if len(logDirs) == 0 {
		return nil, "", errors.New("log: no log dirs")
	}
	name, link := logName(tag, t)
	var lastErr error
	for _, dir := range logDirs {
		fname := filepath.Join(dir, name)
		f, err := os.Create(fname)
		if err == nil {
			symlink := filepath.Join(dir, link)
			// 忽略错误
			os.Remove(symlink) // ignore err
			// 忽略错误
			os.Symlink(name, symlink) // ignore err
			return f, fname, nil
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("log: cannot create log: %v", lastErr)
}
