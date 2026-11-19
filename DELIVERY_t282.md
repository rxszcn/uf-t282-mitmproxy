# UF-T282 请求侧 HAR 归档补齐 — 交付说明

## 1. 问题与范围

出口审计的取证归档链路把会话固化为 HAR 档案。归档质量审计发现**请求侧三处缺口**，与响应侧形成同档案不对称：

| # | 缺口 | 现象 |
|---|------|------|
| R1 | 带体查询/删除类请求 | `bodySize` 非零，但体内容整体消失（`postData` 根本不生成） |
| R2 | 二进制请求体 | 以乱码文本归档且无编码标记；同档案响应侧二进制体是规范 `base64` + `encoding` |
| R3 | 回读外部档案 | `base64` 标记被无视导致体失真；只有 `params` 没有 `text` 的条目直接 KeyError，拖垮**整份档案** |

POST 文本体的导出/导入对照组两端本来就正确，作为回归基线保持不动。

## 2. 逐文件登记

### `mitmproxy/addons/savehar.py`（归档导出实现）

- **改动位置**：`SaveHar.flow_entry()`，原 `if flow.request.method in ["POST", "PUT", "PATCH"]` 分支。
- **改动内容**：
  1. 触发条件由「方法白名单」改为「方法白名单 **或** 请求存在原始体（`raw_content` 为真）」。带体 GET/DELETE 等任意方法一律落 `postData`；空体 POST/PUT/PATCH 仍生成 `{"mimeType","text","params"}`，既有语义不变。
  2. 取体统一走 `flow.request.content`，`ValueError`（非法 `content-encoding`）时回落 `raw_content`，与响应侧 `content = flow.response.content except ValueError -> raw_content` 完全同形。
  3. 二进制判定复用响应侧的 `strutils.is_mostly_bin()`；命中则 `text = base64.b64encode(content)` 并写入 `"encoding": "base64"`，与响应侧 `content.text`/`content.encoding` 同形态。
- **对应题面要求**：R1（不分方法全部落档）、R2（二进制走 base64 带编码标记）。

### `mitmproxy/io/har.py`（HAR 读取实现）

- **改动位置**：新增模块级函数 `postdata_to_content()`；`request_to_flow()` 中 `postData` 取值改调该函数（原为 `["text"]` 硬取）。
- **改动内容**：
  1. `encoding == "base64"` → `base64.b64decode(text)` 还原原始字节；空 `text` 返回 `b""`；解码失败抛 `OptionsError`（由 `io.py` 包装为 `FlowReadException`），不会静默产出错误字节。
  2. `text` 存在 → 原样返回（字符串，由 `Request.make` 按 `text` 语义按 Content-Type 编码，与既有 POST 文本路径一致）。
  3. 无 `text` 但有 `params` → 用 `mitmproxy.net.http.url.encode()` 由参数组装体，条目可读、不再拖垮整卷。
  4. 既无 `text` 也无 `params` → 返回 `""`。
- **对应题面要求**：R3（标记被尊重并还原、仅参数条目可读且体由参数组装）、R2 回读侧。

### `test/mitmproxy/addons/test_savehar.py`（同文件同框架新增断言）

- `test_request_body_exported_for_all_methods`（参数化 GET/DELETE/POST/PUT/PATCH）：带体请求不分方法落档，`bodySize` 与体一致、非二进制无 `encoding` 标记。
- `test_get_request_body_roundtrip` / `test_delete_request_body_roundtrip`：带体查询与删除类请求导出后回读，体字节一致；DELETE 表单同时校验 `params` 通道。
- `test_binary_request_body_base64`：二进制体 `encoding == "base64"` 且 `text` 为标准 base64。
- `test_binary_request_body_roundtrip`：二进制体经导出→回读还原原始字节。
- `test_empty_post_unchanged`：空体 POST 的 `postData` 结构逐键相等，既有语义保持。
- `test_empty_get_has_no_postdata`：空体非白名单方法仍不生成 `postData`（不扩大档案体积）。

### `test/mitmproxy/io/test_har.py`（同文件同框架新增断言）

- `test_postdata_base64_marker_restored`：带 `encoding: base64` 条目回读还原原始字节（自造档案条目）。
- `test_postdata_params_only_entry_readable`：仅参数无文本的 `postData` 可读且体由参数组装。
- `test_postdata_params_only_entry_to_flow`：整份自造档案经真实 `FlowReader` 读取成功，不再整卷不可读。
- `test_postdata_unknown_encoding_marker`：规范外编码标记按无标记文本处理、不报错。

## 3. 规范外编码标记的语义与兼容取舍（自行设计并说明理由）

题面授权自行决定归档规范外 `encoding` 取值的语义。决策如下：

1. **只认 `base64`**：这是 HAR 1.2 规范为 `content.encoding` 定义的唯一标准值，也是本导出器响应侧已在用的形态。请求侧复用同一标记，保证同档案两侧同形、跨版本工具栈（回读侧版本不必与导出侧同步）都能解。
2. **未知标记降级为「无标记文本」并 `logger.warning`**，不抛异常：回读侧工具栈与导出侧版本不必同步，未来批次或第三方工具可能写入本版本不认识的标记；若直接报错，一条未知标记会让**整份混排档案**不可读——这正是本次要消除的故障模式。降级保留文本内容（最接近原始信息），并通过告警让运维可观测，而不是静默丢弃。
3. **`base64` 解码失败仍抛 `OptionsError`**：标记明确声明是 base64 却解不开，说明数据已损坏，产出「猜测的字节」比失败更危险（取证场景要求可追溯），故显式失败并带原因。
4. **不引入新标记（如 `gzip`）**：请求体在归档前取的是解码后的 `content`（与响应侧一致），传输层编码已被剥离，无需第二层标记；引入非标准值只会扩大兼容面。

## 4. 构造输入（快照测试环境内零外部依赖、可复现）

全部用 `mitmproxy.test.tflow/tutils` 与内联 JSON 字典自造，不依赖网络与任何外部文件：

- **自造会话 A**：带体查询类请求（`GET`，`b"q=hello"`）。
- **自造会话 B**：带体删除类请求（`DELETE`，表单体 `b"a=1&b=2"`，含 `content-type`）。
- **自造会话 C**：二进制体请求（`GET`，PNG 魔数 + 高位字节序列，`application/octet-stream`）。
- **自造档案 ①**：带 `encoding: base64` 标记条目（PNG 载荷 + 标准 base64 文本）。
- **自造档案 ②**：仅 `params`（无 `text`）条目（`key1=value1&key2=value2`）。

## 5. 读数口径与四类实测读数

统一口径：逐条目的**体内容与原始字节一致性判定**、**`encoding` 标记取值**、**仅参数条目的可读性与组装体内容**。

### 5.1 导出档案 + 回读结果（实测）

| 构造输入 | 方法 | 原始体长度 | `postData` 生成 | `encoding` 取值 | 回读体 == 原始字节 |
|---|---|---|---|---|---|
| 会话 A GET 文本体 | GET | 7 | 是 | `None`（无标记） | ✅ `b'q=hello'` |
| 会话 B DELETE 表单体 | DELETE | 7 | 是 | `None`（无标记） | ✅ `b'a=1&b=2'` |
| 会话 C 二进制体 | GET | 584 | 是 | `"base64"` | ✅ 584 字节全等 |
| 会话 D POST 文本体（对照） | POST | 7 | 是 | `None`（无标记） | ✅ `b'x=1&y=2'` |

### 5.2 自造档案回读（实测）

| 构造档案 | 可读性 | 判定 |
|---|---|---|
| 档案 ① `encoding: base64` 条目 | 正常 | 回读体 == 原始 584 字节 ✅ |
| 档案 ② 仅 `params` 条目 | 正常（整卷不再失败） | 组装体 `b'key1=value1&key2=value2'` ✅ |

### 5.3 附加口径：传输层压缩的二进制体

`GET` + `content-encoding: gzip` + PNG 载荷：`raw_content` 240 字节、解压后 584 字节。归档标记 `base64`，回读后 `content` 与原始解压体全等 ✅。这与响应侧「取解码后 content 归档、回读后 `decode()` 归一」的既有语义一致。

## 6. 验收命令与最终读数

```bash
python -m pytest test/mitmproxy/addons/test_savehar.py test/mitmproxy/io/test_har.py -q --timeout=60
```

最终读数：**47 passed, 3 warnings in 6.23s，零失败**（基线 32 项，新增 15 项）。既有归档与读取测试（含全部 `.har`/`.mitm`/`zhar` fixture 快照对比）保持通过，fixture 期望零变化。

附加回归：`pytest test/mitmproxy/io test/mitmproxy/addons/test_savehar.py -q` → **74 passed，零失败**。
静态检查：`ruff check` / `ruff format --check` 对四个改动文件均通过。

## 7. 兼容性说明

- **既有档案 fixture 期望零变化**：空体 GET 仍无 `postData`；空体 POST/PUT/PATCH 仍为 `{"mimeType","text":"","params":[]}`；文本体 POST 输出逐键不变。`test_savehar` 对 `test/mitmproxy/data/flows/*.har` 的全部快照对比保持零差异。
- **空体 POST 的既有语义保持**：见 `test_empty_post_unchanged`。
- **混排档案**：旧批次条目（无 `encoding`、带或缺 `text`）与新批次条目（含 `base64`）可在同卷共存，回读侧逐条按标记分派，互不影响。
- **出口网关重发流量**：带体重发（含截图/固件包等二进制载荷）按同样规则落档，不因方法或负载类型丢失证据。
