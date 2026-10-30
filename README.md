# loon-parser

Loon 相关脚本工具集。

## 文件

| 文件 | 用途 |
|---|---|
| `loon-node-prefix-parser.js` | 节点前缀解析器（Loon resource-parser），把 ss/vmess/vless/trojan/hy2/Clash/Base64/QX 等格式转成 Loon 节点 |
| `jq2js.js` | jq → JS 转换器，把 QX 的 `jsonjq-response-body` 表达式翻译成 Loon 可执行的 JS |

## jq2js

Loon 不支持 QX 的 `jsonjq-response-body`，迁移插件时这部分规则会全部失效。`jq2js` 把它翻译成等效 JS。

```js
const { jqToJs } = require('./jq2js');
jqToJs('.data |= map(select(.keyName | test("config\\.(ad|search)") | not))');
// → d.data=(d.data||[]).filter(x=>!new RegExp("config\\.(ad|search)").test(x.keyName));
```

支持的语法：赋值、管道、`map(select())`、`test()`、`IN()`、`del()`、`and`/`or`。

命令行：

```bash
node jq2js.js '.data=[]'
```

测试：`node jq2js.test.js`（8/8 通过）
