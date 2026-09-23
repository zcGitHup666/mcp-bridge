# qcn-mcp-bridge

把企采蜂巢 (qcn-dev) 的 4 个高频查询 HTTP 接口包装成 MCP 工具，让 WorkBuddy 直接调用。

## 为什么需要 Bridge

qcn-dev 后端是 **Java 8 + Spring Boot 2.2.0**（CLAUDE.md §2.1 硬约束）。
MCP 官方 Python / Java SDK 都需要 **Python 3.10+ / JDK 17+**。

直接塞 MCP server 进 qcn-dev 工程会触碰 Java 版本红线，所以独立部署。

## 暴露的 3 个 MCP Tool

| MCP tool 名 | qcn-dev endpoint | HTTP | 入参 DTO |
| --- | --- | --- | --- |
| `qcn_demand_get_newest` | `/user/demand/getNewest` | POST JSON | `RequirementPoolVo` |
| `qcn_supply_get_newest` | `/user/supply/getNewest` | POST JSON | `SearchSupply` |
| `qcn_supply_get_list` | `/user/supply/getSupplyList` | POST JSON | `SearchSupply`（`recommendType` 默认 `0`） |

> 全部 3 个接口均为**只读查询**，写改删接口先不进 MVP（CLAUDE.md §7 「改动可控」原则）。
> 备注：`/user/demand/searchDemandPool` 之前在内测名单但 service 层慢（30s 超时），本次不进 MCP。

## 返回格式

每个 tool 返回**结构化 JSON 字符串**（MCP TextContent 协议要求）：

```jsonc
// 成功
{"ok": true, "endpoint": "/user/demand/getNewest", "data": <SysResult.data>}

// qcn-dev 业务错误（code != 1）
{"ok": false, "kind": "business_error", "endpoint": "...", "code": 0, "message": "参数错误", "data": {...}}

// 网络 / 5xx / JSON 解析失败
{"ok": false, "kind": "transport_error", "endpoint": "...", "message": "..."}
```

调用方（WorkBuddy / Claude）解析 `ok` 字段判断成败。
> 当前实现走**返回值 JSON**标识错误而非 MCP 协议层 `isError=true`，因为 FastMCP 的 `@tool` 装饰器不暴露该字段。
> 若 WorkBuddy 严格要求协议层 `isError`，可在后续迁移到 mcp `Server` 低层 API。

## 凭证管理（CLAUDE.md §6 红线）

- JWT 从环境变量 `QCN_JWT` 读取，**.env 文件不入仓库**（`.gitignore` 已配置）
- 启动日志回显配置时，JWT 字段一律 `<REDACTED>`
- service-account JWT 的注入方式由平台 owner 决定：本地用 `.env`、容器用 K8s Secret、CI 用环境变量

## 启动

```bash
# 1. 装依赖（需要 Python 3.10+，mcp SDK 不支持 3.9 以下）
cd C:\whg\mcp-bridge
python -m pip install -r requirements.txt

# 2. 复制并填配置
cp .env.example .env
# 编辑 .env, 把 QCN_JWT=<REDACTED_PLEASE_FILL_SERVICE_ACCOUNT_JWT> 替换为真实值

# 3. stdio 模式（WorkBuddy 用 stdio 启动本进程时）
python -m qcn_mcp_bridge

# 4. streamable-http 模式（WorkBuddy 通过 HTTP 调本服务时）
MCP_TRANSPORT=streamable-http python -m qcn_mcp_bridge
# 监听 127.0.0.1:8765, 路径 /mcp
```

## 调 WorkBuddy 时

如果 WorkBuddy 是 stdio client，启动命令直接是 `python -m qcn_mcp_bridge`；
如果是 HTTP client，配 `http://127.0.0.1:8765/mcp`。

## 跑测试

```bash
python -m pytest tests/ -v
```

测试用 `httpx.MockTransport`，不需要真实 qcn-dev。

## 后续待办

- [ ] 跑通 MCP Inspector (`@modelcontextprotocol/inspector`) 验证 4 个 tool 的 schema 与 qcn-dev DTO 字段对齐
- [ ] service-account JWT 由平台 owner 提供，注入 `.env` 或 K8s Secret
- [ ] 后续若 WorkBuddy 严格要求 MCP `isError=true`，迁移到 `mcp.server.Server` 低层 API
- [ ] 审计日志：Bridge 侧加 access log 透出 WorkBuddy 用户标识（避免 qcn-dev 看到的是同一 service-account，无法追责）