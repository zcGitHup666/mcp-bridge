"""MCP Bridge OAuth 2.1 + PKCE 授权层。

按 qcn-dev-接入方案.md §三 + RFC 6749 / 7636 / 7591 / 8414 / 8707 / 9728。

M1A 范围 (Phase 1A): 5 个 OAuth 端点 + JWT 签发 + PKCE 校验。
不含登录/注册页 UI (Phase 2) / /mcp Bearer 校验 (Phase 1B) / qcn-dev 业务凭证缓存 (Phase 3)。
"""