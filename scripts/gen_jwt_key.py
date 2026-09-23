"""生成 MCP Bridge 自己的 RSA 私钥 (用于签发 access_token)。

按 CLAUDE §6.3.2 / §6.3.5:
- 私钥绝不进仓库
- 存 ~/.qcn-mcp-bridge/jwt-signing.pem (600 权限)
- 公钥可分享 (存 jwt-signing.pub 644)

跑一次即可, 私钥丢了 access_token 全部失效需重新签发 (MCP client 重新走 OAuth)。
"""
from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> int:
    target_dir = Path.home() / ".qcn-mcp-bridge"
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    priv_path = target_dir / "jwt-signing.pem"
    pub_path = target_dir / "jwt-signing.pub"

    if priv_path.exists():
        print(f"私钥已存在: {priv_path}")
        print("如需重新生成, 请先手动删除该文件 (会令已签发 token 全部失效)")
        return 0

    print(f"生成 RSA 2048 私钥...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 写私钥 (PKCS8 PEM, 无加密 - 服务端持有, 不分发)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path.write_bytes(priv_pem)
    priv_path.chmod(0o600)
    print(f"✓ 私钥: {priv_path} (600 权限)")

    # 写公钥 (SubjectPublicKeyInfo PEM, 给 MCP client 验签用 — 暂不发布, 留接口)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path.write_bytes(pub_pem)
    pub_path.chmod(0o644)
    print(f"✓ 公钥: {pub_path} (644 权限)")

    # kid (key id) = 公钥 SHA256 摘要前 8 hex (RFC 7517)
    import hashlib
    kid = hashlib.sha256(pub_pem).hexdigest()[:16]
    print(f"✓ kid: {kid}")
    print(f"\n下一步: 把 ~/.qcn-mcp-bridge/jwt-signing.pem 的 kid {kid}")
    print(f"        配置到环境变量 QCN_BRIDGE_JWT_KID")

    return 0


if __name__ == "__main__":
    sys.exit(main())