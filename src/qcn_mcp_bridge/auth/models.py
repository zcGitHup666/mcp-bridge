"""OAuth 4 张表 ORM (SQLAlchemy 2.0)。

按接入方案 §B1-B7:
- oauth_clients (DCR 注册信息)
- oauth_auth_codes (一次性, B2)
- oauth_tokens (只存哈希, B4)
- bindings (多租户映射, B7)

按 CLAUDE §4.5: 不暴露内部类名给 controller, controller 拿到的是 dict。
按 CLAUDE §6.3.2: 敏感字段 (secret/code/token) 全部哈希后存。
"""
from __future__ import annotations

from sqlalchemy import (
    Boolean, Column, DateTime, Index, Integer, JSON, LargeBinary,
    String, UniqueConstraint,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class OAuthClient(Base):
    """RFC 7591 动态注册的 OAuth client (接入方案 §B1)."""
    __tablename__ = "oauth_clients"

    id = Column(Integer, primary_key=True)
    client_id = Column(String(64), unique=True, nullable=False)
    # SHA256 hex (64 字符)。public client (MCP WorkBuddy) 不用 secret, 存 NULL
    client_secret_hash = Column(String(64), nullable=True)
    client_name = Column(String(128), nullable=False)
    redirect_uris = Column(JSON, nullable=False)   # list[str]
    scopes = Column(JSON, nullable=False)         # list[str]
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class OAuthAuthCode(Base):
    """一次性 authorization code (RFC 6749 §4.1.2 + §B2).

    code 存 SHA256 哈希 (B4: token 只存哈希). 消费时立刻删除 (B2: 一次性).
    """
    __tablename__ = "oauth_auth_codes"

    id = Column(Integer, primary_key=True)
    code_hash = Column(String(64), unique=True, nullable=False)
    client_id = Column(String(64), nullable=False)
    # 登录完成前为 NULL, 登录后写入 qcn-dev uid (Phase 2 接入)
    user_id = Column(Integer, nullable=True)
    tenant_id = Column(Integer, nullable=True)
    product = Column(String(32), nullable=True)
    redirect_uri = Column(String(512), nullable=False)
    code_challenge = Column(String(128), nullable=False)
    code_challenge_method = Column(String(16), nullable=False, default="S256")
    scope = Column(String(512), nullable=False, default="")
    # RFC 8707 Resource Indicators
    resource = Column(String(256), nullable=True)
    # CSRF 防伪 (授权请求原样回传, callback 校验)
    state = Column(String(128), nullable=True)
    created_at = Column(DateTime, nullable=False)
    # 默认 10 分钟 (接入方案 §B3)
    expires_at = Column(DateTime, nullable=False)


class OAuthToken(Base):
    """已签发的 access/refresh token. 只存哈希 (§B4)."""
    __tablename__ = "oauth_tokens"

    id = Column(Integer, primary_key=True)
    access_token_hash = Column(String(64), unique=True, nullable=False)
    refresh_token_hash = Column(String(64), unique=True, nullable=True)
    client_id = Column(String(64), nullable=False)
    # qcn-dev uid (Phase 1A 用 qcn-dev 业务接口的 user_id)
    user_id = Column(Integer, nullable=False)
    tenant_id = Column(Integer, nullable=True)
    product = Column(String(32), nullable=False, default="qcn")
    scope = Column(String(512), nullable=False, default="")
    issued_at = Column(DateTime, nullable=False)
    access_token_expires_at = Column(DateTime, nullable=False)
    refresh_token_expires_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)


class Binding(Base):
    """多租户映射 (§B7): (user_id, tenant_id, product) 三元组唯一.

    qcn_dev_session_encrypted: AES-GCM 密文 (Phase 3 写, §B6 加密落库)
    """
    __tablename__ = "bindings"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    tenant_id = Column(Integer, nullable=False)
    product = Column(String(32), nullable=False, default="qcn")
    qcn_dev_session_encrypted = Column(LargeBinary, nullable=True)
    qcn_dev_session_expires_at = Column(DateTime, nullable=True)
    # UNBOUND / IN_PROGRESS / BOUND / REFRESHING / REVOKED
    status = Column(String(16), nullable=False, default="UNBOUND")
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", "product", name="uq_binding_triplet"),
        Index("ix_binding_user", "user_id"),
    )