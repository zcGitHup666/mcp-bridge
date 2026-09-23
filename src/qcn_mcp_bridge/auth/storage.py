"""OAuth storage 仓库函数 — 4 张表的 CRUD.

按 CLAUDE §4.5 出参类型: 全部返回 dict, 不暴露 ORM Entity 给 controller。
按 CLAUDE §6.3.2: 敏感字段 (secret/code/token) 全部 SHA256 哈希后存。
按 §7 "KISS": 函数粒度按操作拆, 一个函数做一件事。
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from qcn_mcp_bridge.auth.models import Base, Binding, OAuthAuthCode, OAuthClient, OAuthToken


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _to_naive(dt: datetime) -> datetime:
    """aware → naive UTC.

SQLite DateTime 列默认 naive (无时区), 但 now_utc() 返回 aware. 比较前需统一.
"""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def hash_secret(value: str) -> str:
    """SHA256 摘要 (hex 64 字符). 用于存 client_secret/code/access_token/refresh_token (§B4)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def init_engine(db_path: str) -> tuple[Engine, sessionmaker[Session]]:
    """初始化 SQLite 引擎 + 创建表."""
    engine = create_engine(
        f"sqlite:///{db_path}",
        future=True,
        # SQLite 单进程, 多写需要锁
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


# =============================================================================
# OAuthClient
# =============================================================================

def create_client(
    session: Session,
    *,
    client_name: str,
    redirect_uris: list[str],
    scopes: list[str],
    client_secret: str | None = None,
) -> dict[str, Any]:
    """RFC 7591 动态客户端注册. 返回 client_id (明文, 给 MCP client).

    client_id 格式: "qcn_mcp_" + 22 字符 base64url (足够 entropy).
    """
    client_id = "qcn_mcp_" + secrets.token_urlsafe(16)
    client_secret_hash = hash_secret(client_secret) if client_secret else None
    now = now_utc()
    obj = OAuthClient(
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        client_name=client_name,
        redirect_uris=redirect_uris,
        scopes=scopes,
        created_at=now,
        updated_at=now,
    )
    session.add(obj)
    session.commit()
    return _client_to_dict(obj)


def find_client(session: Session, client_id: str) -> dict[str, Any] | None:
    obj = session.query(OAuthClient).filter_by(client_id=client_id).one_or_none()
    return _client_to_dict(obj) if obj else None


def _client_to_dict(obj: OAuthClient) -> dict[str, Any]:
    return {
        "id": obj.id,
        "client_id": obj.client_id,
        "client_name": obj.client_name,
        "redirect_uris": obj.redirect_uris,
        "scopes": obj.scopes,
        "created_at": obj.created_at.isoformat() if obj.created_at else None,
    }


# =============================================================================
# OAuthAuthCode (一次性)
# =============================================================================

def save_auth_code(
    session: Session,
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: str,
    resource: str | None,
    state: str | None,
    ttl_seconds: int = 600,
) -> str:
    """保存 auth code. 返回明文 code (只返回一次, 数据库存哈希 §B4).

    ttl 默认 600 秒 (接入方案 §B3).
    """
    code = secrets.token_urlsafe(32)
    now = now_utc()
    obj = OAuthAuthCode(
        code_hash=hash_secret(code),
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        resource=resource,
        state=state,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )
    session.add(obj)
    session.commit()
    return code


def consume_auth_code(
    session: Session,
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
) -> dict[str, Any] | None:
    """消费 code (§B2 一次性): 找到 + 删除 + 校验一致性.

    返回 None 表示无效 (找不到 / 过期). 同时校验 client_id + redirect_uri 一致 (§B5).
    """
    code_hash = hash_secret(code)
    obj = (
        session.query(OAuthAuthCode)
        .filter_by(code_hash=code_hash, client_id=client_id, redirect_uri=redirect_uri)
        .one_or_none()
    )
    if obj is None:
        return None
    # 一次性: 立即删除 (即使后续步骤失败, code 也不再能用)
    session.delete(obj)
    session.commit()
    if _to_naive(obj.expires_at) < _to_naive(now_utc()):
        return None
    return {
        "client_id": obj.client_id,
        "scope": obj.scope,
        "resource": obj.resource,
        "state": obj.state,
        "user_id": obj.user_id,
        "tenant_id": obj.tenant_id,
        "product": obj.product,
        # Phase 1A: PKCE 校验需要这两个字段 (token 端点用)
        "code_challenge": obj.code_challenge,
        "code_challenge_method": obj.code_challenge_method,
    }


def update_auth_code_user(
    session: Session,
    *,
    code_hash: str,
    user_id: int,
    tenant_id: int,
    product: str,
) -> None:
    """登录完成后, 把 user 信息写回 auth code (Phase 2 用)."""
    obj = session.query(OAuthAuthCode).filter_by(code_hash=code_hash).one_or_none()
    if obj is None:
        return
    obj.user_id = user_id
    obj.tenant_id = tenant_id
    obj.product = product
    session.commit()


# =============================================================================
# OAuthToken (只存哈希 §B4)
# =============================================================================

def save_token(
    session: Session,
    *,
    access_token: str,
    refresh_token: str | None,
    client_id: str,
    user_id: int,
    tenant_id: int | None,
    product: str,
    scope: str,
    access_ttl_seconds: int,
    refresh_ttl_seconds: int | None,
) -> None:
    now = now_utc()
    obj = OAuthToken(
        access_token_hash=hash_secret(access_token),
        refresh_token_hash=hash_secret(refresh_token) if refresh_token else None,
        client_id=client_id,
        user_id=user_id,
        tenant_id=tenant_id,
        product=product,
        scope=scope,
        issued_at=now,
        access_token_expires_at=now + timedelta(seconds=access_ttl_seconds),
        refresh_token_expires_at=(
            now + timedelta(seconds=refresh_ttl_seconds) if refresh_ttl_seconds else None
        ),
        revoked=False,
    )
    session.add(obj)
    session.commit()


def find_token_by_access(
    session: Session, *, access_token: str
) -> dict[str, Any] | None:
    """通过 access_token 查记录. 校验 revoked + expires_at."""
    obj = (
        session.query(OAuthToken)
        .filter_by(access_token_hash=hash_secret(access_token))
        .one_or_none()
    )
    if obj is None or obj.revoked or _to_naive(obj.access_token_expires_at) < _to_naive(now_utc()):
        return None
    return _token_to_dict(obj)


def find_token_by_refresh(
    session: Session, *, refresh_token: str
) -> dict[str, Any] | None:
    obj = (
        session.query(OAuthToken)
        .filter_by(refresh_token_hash=hash_secret(refresh_token))
        .one_or_none()
    )
    if obj is None or obj.revoked or (
        obj.refresh_token_expires_at and _to_naive(obj.refresh_token_expires_at) < _to_naive(now_utc())
    ):
        return None
    return _token_to_dict(obj)


def revoke_token(session: Session, *, access_token: str) -> bool:
    """RFC 7009 撤销. 返回是否成功撤销."""
    obj = (
        session.query(OAuthToken)
        .filter_by(access_token_hash=hash_secret(access_token))
        .one_or_none()
    )
    if obj is None:
        return False
    obj.revoked = True
    session.commit()
    return True


def revoke_by_refresh_token(session: Session, *, refresh_token: str) -> bool:
    """refresh_token grant rotation: 撤销旧 token 行. (RFC 6819 §5.2.2.1)."""
    obj = (
        session.query(OAuthToken)
        .filter_by(refresh_token_hash=hash_secret(refresh_token))
        .one_or_none()
    )
    if obj is None:
        return False
    obj.revoked = True
    session.commit()
    return True


def _token_to_dict(obj: OAuthToken) -> dict[str, Any]:
    return {
        "client_id": obj.client_id,
        "user_id": obj.user_id,
        "tenant_id": obj.tenant_id,
        "product": obj.product,
        "scope": obj.scope,
        "access_token_expires_at": obj.access_token_expires_at.isoformat(),
        "refresh_token_expires_at": (
            obj.refresh_token_expires_at.isoformat() if obj.refresh_token_expires_at else None
        ),
    }


# =============================================================================
# Binding (多租户映射 §B7)
# =============================================================================

def upsert_binding(
    session: Session,
    *,
    user_id: int,
    tenant_id: int,
    product: str,
    qcn_dev_session_encrypted: bytes,
    expires_at: datetime,
    status: str = "BOUND",
) -> dict[str, Any]:
    """§B7 三元组 (user_id, tenant_id, product) 唯一. upsert 模式."""
    obj = (
        session.query(Binding)
        .filter_by(user_id=user_id, tenant_id=tenant_id, product=product)
        .one_or_none()
    )
    now = now_utc()
    if obj is None:
        obj = Binding(
            user_id=user_id,
            tenant_id=tenant_id,
            product=product,
            qcn_dev_session_encrypted=qcn_dev_session_encrypted,
            qcn_dev_session_expires_at=expires_at,
            status=status,
            created_at=now,
            updated_at=now,
        )
        session.add(obj)
    else:
        obj.qcn_dev_session_encrypted = qcn_dev_session_encrypted
        obj.qcn_dev_session_expires_at = expires_at
        obj.status = status
        obj.updated_at = now
    session.commit()
    return _binding_to_dict(obj)


def find_binding(
    session: Session, *, user_id: int, tenant_id: int, product: str = "qcn"
) -> dict[str, Any] | None:
    obj = (
        session.query(Binding)
        .filter_by(user_id=user_id, tenant_id=tenant_id, product=product)
        .one_or_none()
    )
    return _binding_to_dict(obj) if obj else None


def _binding_to_dict(obj: Binding) -> dict[str, Any]:
    return {
        "id": obj.id,
        "user_id": obj.user_id,
        "tenant_id": obj.tenant_id,
        "product": obj.product,
        "qcn_dev_session_expires_at": (
            obj.qcn_dev_session_expires_at.isoformat()
            if obj.qcn_dev_session_expires_at
            else None
        ),
        "status": obj.status,
    }