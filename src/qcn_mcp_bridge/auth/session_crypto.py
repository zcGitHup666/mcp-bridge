"""AES-GCM 加密 qcn-dev session 存 bindings 表 (Phase 2B1 Step 2).

按接入方案 §B7: bindings.qcn_dev_session_encrypted (BLOB) 存 qcn-dev JWT.
按 CLAUDE §6.3.2: 不展示明文 session / 加密密钥. 不写日志.

格式: nonce (12B) || ciphertext (含 GCM tag).
key: 部署从 QCN_BRIDGE_SESSION_ENCRYPT_KEY 环境变量读 (base64, 32B);
     测试用进程内随机 (重启即失效, 不可逆生产用 — 必须 Phase 2B1 Step 3 配 env).
"""
from __future__ import annotations

import base64
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_key(env_name: str = "QCN_BRIDGE_SESSION_ENCRYPT_KEY") -> bytes:
    """从环境变量读 base64(32B); 缺则用进程内随机 (仅测试)."""
    raw = os.environ.get(env_name)
    if raw:
        try:
            key = base64.b64decode(raw)
            if len(key) != 32:
                raise ValueError(f"{env_name} must decode to 32 bytes, got {len(key)}")
            return key
        except Exception:  # noqa: BLE001 - 测试期不挂
            pass
    return secrets.token_bytes(32)


_SESSION_KEY: bytes | None = None  # lazy load


def _get_key() -> bytes:
    global _SESSION_KEY
    if _SESSION_KEY is None:
        _SESSION_KEY = _load_key()
    return _SESSION_KEY


def encrypt_session(plaintext: str | bytes) -> bytes:
    """AES-GCM 加密 qcn-dev session string."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    nonce = os.urandom(12)
    ct = AESGCM(_get_key()).encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct


def decrypt_session(blob: bytes) -> bytes:
    """AES-GCM 解密."""
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(_get_key()).decrypt(nonce, ct, associated_data=None)