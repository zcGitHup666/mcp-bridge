"""MCP tool 注册入口。

每个子模块 (demand / supply) 导出一个 ``register(mcp, client)`` 函数,
由 server.py 启动时一次性挂到 FastMCP 实例上。
"""