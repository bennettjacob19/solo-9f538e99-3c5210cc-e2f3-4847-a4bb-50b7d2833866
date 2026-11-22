# 双出口站点路由排障 / 变更预检 API（route-precheck）

两种用途，共用一个符号化选路引擎：

1. **排障（troubleshoot）**：值班员记录两台 Linux 路由器的入口、两端互指出口
   （网卡 + 网关），补交各自的 IPv4 路由快照，然后按源、目的 CIDR 逐跳诊断
   “流量停在哪一跳”。报告按不重叠 CIDR 对分段，区分离开设备 / 黑洞 / 无路由 /
   回环 / 待补快照。
2. **变更预检（precheck）**：改动 Linux 双出口策略路由前，把**变更前后**两份
   `ip -j -4 rule show` 和 `ip -j -4 route show table all` 的 JSON，连同源、目的
   IPv4 CIDR 一起提交；返回**转发结果有变化的地址对**，按（变更前 → 变更后）
   分组。

两种计算都是**符号化**的：把 源CIDR × 目的CIDR 的地址空间递归切成“结果恒定”
的矩形 / CIDR 对，再按面积（2 的幂）求和或分段。计算量只取决于策略规模，与地址
数量无关，`0.0.0.0/0 × 0.0.0.0/0`（2^64 对）也能秒出。

## 启动

```bash
docker compose up --build      # 监听 0.0.0.0:8000
# 或本地： pip install -r requirements.txt && uvicorn app.main:app --port 8000
```

打开 <http://localhost:8000/docs>（Swagger UI），排障接口与 `POST /precheck`
都已预填示例。`GET /` 重定向到 `/docs`，`GET /healthz` 用于健康检查。
记录保存在进程内存中，重启即清空。

## 排障：双出口站点断流

### 1. 建记录：选定入口，填两端互指出口

`POST /troubleshoot/records`

```json
{
  "name": "site-a 2026-11-22 断流",
  "entry_device": "rtr-a",
  "devices": [
    {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": "192.0.2.2"},
    {"name": "rtr-b", "egress_dev": "eth0", "egress_gateway": "192.0.2.1"}
  ]
}
```

* 必须恰好两台设备；`entry_device` 必须是其中之一。
* `egress_dev` / `egress_gateway` 是**该设备通往另一台设备**的出口参数，必须
  显式给出；对端在链路上（on-link）时 `egress_gateway` 写 `null`。
  链路判定规则：路由结果的 `dev` 等于 `egress_dev`，且
  `egress_gateway` 为 `null` 或与路由 `gateway` 完全一致，才算“发往对端”。
* 返回 `record_id` 与 `version`（版次，初始 0）。

### 2. 按设备补交 / 更正路由快照

`PUT /troubleshoot/records/{record_id}/devices/{device}/snapshot`

```json
{
  "rules":  [/* 该设备 `ip -j -4 rule show` 的 JSON 数组 */],
  "routes": [/* 该设备 `ip -j -4 route show table all` 的 JSON 数组 */]
}
```

* 格式与 precheck 完全一致；非法内容（multipath、fwmark、prohibit 等）返回
  400，**且不改变已有快照和版次**。
* 首次提交与后续更正走同一接口；每次成功提交把记录的 `version` 加一并成为
  该设备的新 `snapshot_version`。某设备从未提交过快照时，其状态为待补。

### 3. 逐跳诊断

`POST /troubleshoot/records/{record_id}/diagnose?source_cidr=...&destination_cidr=...`
（两个 CIDR 都可以是 `0.0.0.0/0`，也接受 `all`/`default`）

报告结构：

```json
{
  "record_id": "...", "version": 2, "entry_device": "rtr-a",
  "query": {"source_cidr": "10.0.0.0/8", "destination_cidr": "198.51.100.0/24"},
  "devices": [{"name": "rtr-a", "entry": true,
               "egress_to_peer": {"dev": "eth1", "gateway": "192.0.2.2"},
               "has_snapshot": true, "snapshot_version": 1}, "..."],
  "summary": {"total_pairs": "...", "covered_pairs": "...", "segment_count": 2,
              "conclusions": {"left_devices": "..."}},
  "segments": [{
    "source_cidr": "...", "destination_cidr": "...", "address_pairs": "...",
    "example": {"source": "...", "destination": "..."},
    "conclusion": "left_devices", "terminal_device": "rtr-b",
    "detail": "traffic leaves the two devices at rtr-b",
    "hops": [{"device": "rtr-a", "action": "transit_to_peer",
              "result": {"type": "unicast", "dev": "eth1", "gateway": "192.0.2.2"},
              "basis": {"rule_priority": 32766, "table": "main",
                        "route_prefix": "0.0.0.0/0", "route_type": "unicast"},
              "snapshot_version": 1,
              "note": "forwarded to rtr-b over eth1 via 192.0.2.2"},
             {"device": "rtr-b", "action": "exit_pair", "..."}]
  }]
}
```

* 结论 `conclusion`：
  * `left_devices` —— 流量从其中一台设备经**非对端链路**转发出去（含入口直接
    外发、以及经对端后再外发），列出所经设备、每跳选路依据与出口。
  * `blackhole` —— 某设备命中 blackhole 路由，立即丢弃。
  * `no_route` —— 某设备上所有规则 / 表都查不到可用路由（含 throw / 查无路由
    继续查后仍未命中）。
  * `loop` —— 两台设备互相把流量指回对方（对端链路形成环路）。
  * `pending_snapshot` —— 流量**确实到达**某台尚无快照的设备；只有这种情况标
    待补。若流量在到达该设备前已外发 / 黑洞 / 无路由，则不标待补。
* `segments` 是**互不重叠**的（源 CIDR, 目的 CIDR）对，并集恰好覆盖查询范围
  （`covered_pairs == total_pairs`，服务端会校验）；按 CIDR 分段而非逐地址。
  段内每跳的 `snapshot_version` 指出使用了哪一版快照。
* `basis` 只记录最终决策点（规则优先级、表、前缀、类型、出口），与 precheck
  一致；中途 `throw` / 查无路由跳过的表不逐个列出。
* 两台设备都未提交快照时，报告立即以 `pending_snapshot` 结束——无需任何快照
  即可定位“流量到达入口，但入口快照未交”。

### 4. 版次与并发约定

* 诊断开始时对记录做**一次性采集**（设备配置 + 各设备最新快照 + 版次），之后
  的计算只读这份冻结数据，因此**整份报告来自同一采集版次**，并在 `version`
  中注明。
* 诊断运行期间仍可 `PUT` 更正：成功则版次加一，**之后的查询**使用新版；正在
  运行的报告不受影响。提交无效（400）则版次不变，后续查询沿用旧版。
* 记录以不可变值保存，读写由同一把锁串行化；诊断计算在锁外进行。

## 变更预检（原有功能）

### 输入

```json
{
  "source_cidr": "10.0.0.0/8",
  "destination_cidr": "198.51.100.0/24",
  "before": {"rules": [/* ip -j -4 rule show 的 JSON 数组 */],
             "routes": [/* ip -j -4 route show table all 的 JSON 数组 */]},
  "after":  {"rules": ["..."], "routes": ["..."]}
}
```

* 两个 CIDR 都可以是 `0.0.0.0/0`（也接受 `all`/`default` 写法；带主机位会被归一化）。
* `rules`/`routes` 直接粘贴两条 `ip -j` 命令解析后的 JSON 数组即可。

## 选路语义（与任务约定一致）

* **略过 local 表和指向它的规则**；其余规则按**互异的优先级从小到大**依次查表。
* 规则只用 `src`/`dst` 选择器匹配源和目的。
* 表内前缀唯一，按**最长前缀**匹配；支持单路径 `unicast`（`dev` + 可选
  `gateway`）、`throw`、`blackhole`。
* 查无路由或命中 `throw` → 继续查下一条规则；`blackhole` → 立即丢弃；
  所有规则耗尽 → 结果记为 `no_route`。
* 转发结果的同一性 = 出口网卡 + 下一跳的组合（`dev`, `gateway`），另有
  `blackhole` 与 `no_route` 两类；不比较 preferred-src、metric 等属性。
* 排障时把上述结果与记录的 `egress_dev`/`egress_gateway` 比对，决定是否发往
  对端（见上）。

## 预检输出

```json
{
  "summary": {"total_pairs": "...", "changed_pairs": "...", "unchanged_pairs": "...",
              "group_count": 2, "source_cidr": "...", "destination_cidr": "..."},
  "groups": [{
    "before": {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"},
    "after":  {"type": "blackhole"},
    "count": "2147483648",
    "example": {"source": "10.0.0.0", "destination": "198.51.100.128"},
    "basis_before": {"rule_priority": 100, "table": "100",
                     "route_prefix": "0.0.0.0/0", "route_type": "unicast",
                     "dev": "eth1", "gateway": "198.51.100.1"},
    "basis_after":  {"rule_priority": 100, "table": "100",
                     "route_prefix": "198.51.100.128/25",
                     "route_type": "blackhole"}
  }]
}
```

只报告结果有变化的地址对；未变化的只体现在 `summary.unchanged_pairs` 总数里。

## 错误处理

* `400`：输入合法 JSON 但超出支持模型，或记录定义 / 查询 CIDR 非法，`detail`
  说明原因与位置（如 `before route #3: unsupported route type 'prohibit' ...`）。
* `404`：排障记录或设备不存在。
* `422`：请求体不符合 schema（缺字段、类型错误等）。

## 已实现

* FastAPI 服务：`/precheck`、排障记录 4 个接口、`GET /`（跳转 /docs）、
  `GET /healthz`，/docs 预填示例。
* 符号化决策引擎 `app/routing.py`（纯标准库）：规则排序与 src/dst 匹配、
  最长前缀、unicast/throw/blackhole、throw/查无路由继续查、blackhole 立即丢弃、
  local 表及指向它的规则跳过、表名/表号归一（`main`/`253`、`100`/`"100"`、
  自定义名按名匹配）；`partition_rectangles` 可同时切分多份策略。
* 排障模块 `app/troubleshoot.py`：记录 / 版次 / 快照的线程安全内存存储、原子
  采集、逐跳跟踪、五种结论、CIDR 对合并、覆盖性自校验。
* 输入校验：多路径（`nexthops`）、`nhid`、encap、非 unicast/throw/blackhole 路由、
  规则带 fwmark/iif/tos 等额外属性或非 lookup 动作、优先级重复、同表前缀重复、
  IPv6、非法 gateway、unicast 缺 `dev` 等一律报 400。
* Dockerfile + docker-compose.yml（`docker compose up --build` 即可启动）。
* 测试：`tests/`（pytest，60 例）。

## 已验证

* `python3 -m pytest`：60 例全部通过（Python 3.11，fastapi 0.165 / pydantic 2.14）。
  原有 32 例覆盖 precheck；新增 28 例（含参数化）覆盖排障：
  * 记录生命周期、入参校验、非法快照不改版次；
  * 五种结论各自的可复现场景（含入口直接外发、经对端外发、两端回环、
    入口待补 vs 对端待补、blackhole 与 no_route 区分、网关不同即非对端）；
  * `/0 × /0` 符号化分段、段间互不重叠、并集覆盖查询范围；
  * **随机对拍**：随机双路由器策略（含规则 src/dst 选择器、throw、blackhole、
    待补快照）在 64×64 地址空间上把逐跳分段结论与独立的逐地址跟踪器逐一比对；
  * **查询期间更正**：用线程阻塞符号切分，确认诊断中途提交的更正成为新版次，
    在飞报告仍来自采集时的旧版次，后续查询使用新版次；非法更正后版次与结果
    不变。
* 端到端冒烟：uvicorn 起服后 curl 建记录 → 只交一台快照 → 诊断得
  `pending_snapshot` → 补交后诊断得 `left_devices`、版次 2 → 提交 prohibit
  返回 400 且版次仍为 2 → `/0 × /0` 约 30 ms。`/docs`、`/openapi.json` 正常。

## 未完成 / 限制

* 仅 IPv4；规则仅支持 src/dst 选择器 + 查表动作（fwmark/iif/oif/tos/uidrange/
  sport/dport/ipproto/not/goto 等提交即 400）。
* 路由仅支持单路径 unicast/throw/blackhole；multipath、nexthop 对象（nhid）、
  unreachable/prohibit/nat、encap 等提交即 400。
* 规则优先级必须互异、同表前缀必须唯一（违反即 400，不猜测语义）。
* 结果同一性不看 preferred-src、metric、MTU 等；经 throw/查无路由继续查找时，
  “选路依据”只记录最终决策点（规则/表/前缀），不记录中间跳过的表。
* 排障模型假设两台设备之间是二层直连 / 固定下一跳：只看“出口网卡 + 网关”是否
  等于记录中的互指出口，不模拟对端接口的 ARP / 链路状态，也不追踪两台设备之外
  的路由器（离开设备即结束）。`egress_gateway=null` 时按接口通配，可能把同一
  网卡上的其他直连结果也当作对端跳。
* 记录仅保存在内存中，进程重启即丢失；不做持久化与多副本共享。
* 决策单元格上限 100,000（防御病态碎化输入，超限报 400）。
* 本环境无 docker，Dockerfile/compose 未实际构建过，仅经过静态核对。
