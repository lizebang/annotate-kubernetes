# Annotate Kubernetes

Kubernetes 版本 release-1.13 [KUBERNETES LICENSE](./KUBERNETES-LICENSE)

```
git clone git@github.com:lizebang/annotate-kubernetes.git $GOPATH/src/k8s.io/kubernetes
```

## Prepare

我使用的是 vscode，你们也可以使用它，同时推荐安装 [Go](https://marketplace.visualstudio.com/items?itemName=ms-vscode.Go) 和 [todo-tree](https://marketplace.visualstudio.com/items?itemName=Gruntfuggly.todo-tree) 这两个插件。

## Settings

`todo-tree` 设置如下：

```settings
  // todo-tree
  "todo-tree.tags": ["TODO:", "FIXME:", "BUG:", "NOTE:", "TS:", "IMP:", "TSK:"],
  "todo-tree.customHighlight": {
    "BUG:": {
      "icon": "bug",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#e11d21",
      "iconColour": "#e11d21"
    },
    "FIXME:": {
      "icon": "tools",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#fbca04",
      "iconColour": "#fbca04"
    },
    "TODO:": {
      "icon": "check",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#0ffa16",
      "iconColour": "#0ffa16"
    },
    "NOTE:": {
      "icon": "note",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#0052cc",
      "iconColour": "#0052cc"
    },
    "TSK:": {
      "icon": "tasklist",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#d455d0",
      "iconColour": "#d455d0"
    },
    "IMP:": {
      "icon": "issue-opened",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#aa00aa",
      "iconColour": "#aa00aa"
    },
    "TS:": {
      "icon": "sync",
      "type": "tag",
      "opacity": 100,
      "foreground": "#000000",
      "background": "#d2b48c",
      "iconColour": "#d2b48c"
    }
  },
```
