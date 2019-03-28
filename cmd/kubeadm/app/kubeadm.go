/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"flag"
	"os"

	"github.com/spf13/pflag"
	_ "k8s.io/klog"

	utilflag "k8s.io/apiserver/pkg/util/flag"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd"
)

// Run creates and executes new kubeadm command
//
// Run 创建并执行新的 kubeadm 命令
func Run() error {
	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	pflag.Set("logtostderr", "true")
	// We do not want these flags to show up in --help
	// These MarkHidden calls must be after the lines above
	//
	// 我们不希望这些标志显示在 --help 中
	// 这些 MarkHidden 调用必须在上面的调用之后
	// IMP: 这些标志由 klog.InitFlags(nil) 添加，并由 pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	// 进行处理。
	pflag.CommandLine.MarkHidden("version")
	pflag.CommandLine.MarkHidden("log-flush-frequency")
	pflag.CommandLine.MarkHidden("alsologtostderr")
	pflag.CommandLine.MarkHidden("log-backtrace-at")
	pflag.CommandLine.MarkHidden("log-dir")
	pflag.CommandLine.MarkHidden("logtostderr")
	pflag.CommandLine.MarkHidden("stderrthreshold")
	pflag.CommandLine.MarkHidden("vmodule")

	cmd := cmd.NewKubeadmCommand(os.Stdin, os.Stdout, os.Stderr)
	return cmd.Execute()
}
