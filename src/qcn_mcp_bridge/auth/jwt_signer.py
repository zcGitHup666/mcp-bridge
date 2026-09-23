"""JWT 签发 / 校验 (MCP access_token).

按 CLAUDE §6.3.2: 私钥从 ~/.qcn-mcp-bridge/jwt-signing.pem 读 (600 权限), 绝不展示明文 / 日志。
按 CLAUDE §6.3.5: 不进代码 / 注释 / commit / 文档。

JWT claims:
- iss: bridge issuer (https://cc.qicainiu.com)
- aud: bridge resource (https://cc.qicainiu.com/mcp)
- sub: qcn-dev user_id (Bridge 主键, 调 qcn-dev 时拿这个查 bindings)
- iat / exp: 签发 / 过期时间
- jti: 唯一 ID (用于撤销)
- scope: 空格分隔的 scope 列表 (RFC 6749 §3.3)
- kid: key id (用于公钥分发)
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from pathlib import Path
from typing import Any

import jwt  # pyjwt[crypto]
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
)

DEFAULT_KEY_PATH = Path.home() / ".qcn-mcp-bridge" / "jwt-signing.pem"
DEFAULT_ALG = "RS256"  # RSA-SHA256
DEFAULT_TTL_SECONDS = 3600  # 1 小时


class JWTSigner:
    """MCP access_token 签发 / 校验 (RS256)."""

    def __init__(
        self,
        key_path: Path = DEFAULT_KEY_PATH,
        *,
        issuer: str,
        audience: str,
        key_id: str | None = None,
        algorithm: str = DEFAULT_ALG,
    ) -> None:
        if not key_path.exists():
            raise FileNotFoundError(
                f"私钥不存在: {key_path}. 先跑 scripts/gen_jwt_key.py 生成。"
            )
        # mode='r' 读文本 PEM; pyjwt 自动解析 PKCS8 / PKCS1
        self._private_key_pem: str = key_path.read_text(encoding="utf-8")
        # 公钥从私钥派生 (PyJWT 2.x + cryptography 库需要 RSAPublicKey 对象,
        # 不能直接传 PEM 字符串, 否则 AttributeError 'RSA' object has no attribute 'verify')
        priv = load_pem_private_key(
            self._private_key_pem.encode("utf-8"), password=None
        )
        self._public_key = priv.public_key()
        # sign() 仍然需要 PEM 字符串 (PyJWT 签 RS256 OK)
        # kid: 公钥 SHA256 摘要前 16 hex (RFC 7517); 用于公钥分发
        self._key_id: str = key_id or self._compute_kid_bytes(
            self._public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )
        )
        self._issuer = issuer
        self._audience = audience
        self._algorithm = algorithm

    @staticmethod
    def _compute_kid_bytes(public_pem_bytes: bytes) -> str:
        # 公钥 SHA256 摘要前 16 hex (RFC 7517); 用于公钥分发
        return hashlib.sha256(public_pem_bytes).hexdigest()[:16]

    def sign(
        self,
        *,
        sub: int | str,
        scope: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """签发 access_token (JWS Compact)."""
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(sub),
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": hashlib.sha256(
                f"{sub}-{time.time_ns()}-{secrets.token_hex(8)}-{self._key_id}".encode("utf-8")
            ).hexdigest()[:32],
            "scope": scope,
        }
        if extra_claims:
            payload.update(extra_claims)
        # PyJWT sign() 可以直接吃 PEM 字符串 (跟 verify 不同)
        return jwt.encode(
            payload,
            self._private_key_pem,
            algorithm=self._algorithm,
            headers={"kid": self._key_id},
        )

    def verify(self, token: str) -> dict[str, Any] | None:
        """校验 access_token. 返回 claims 字典 (成功) 或 None (失败 / 过期 / 签名错)."""
        try:
            # RFC 7519 §4.1.3: aud 必须匹配 (MCP §A8 必做).
            # 必须传 RSAPublicKey 对象 (不是 PEM 字符串), 否则 PyJWT 2.x 抛
            # AttributeError: 'RSA' object has no attribute 'verify'
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            return claims
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:  # noqa: BLE001 — 任何 JWT 校验失败都返回 None
            return None

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_pem(self) -> str:
        """导出公钥 PEM (给 MCP client 验签用)."""
        return self._public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")