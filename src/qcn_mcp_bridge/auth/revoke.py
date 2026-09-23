"""RFC 7009 Token Revocation — POST /oauth/revoke.

按 CLAUDE §4.5: 出参类型 JSONResponse / dict.
按 CLAUDE §6.3.2: 不打印 token 明文 / client_id 明文 (token=<REDACTED>).

按 RFC 7009:
- §2.1: 请求体必填 token, 可选 token_type_hint ∈ {access_token, refresh_token}
- §2.2: 不论 token 是否存在 / 已过期, 一律返回 200 (避免泄露 token 存在性)

Phase 2B2 Step 1 补: 接入方案 §A11 (Token Revocation).
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from qcn_mcp_bridge.auth.errors import oauth_error
from qcn_mcp_bridge.auth.storage import (
    revoke_by_refresh_token,
    revoke_token,
)

log = logging.getLogger(__name__)


def handle_revoke(session: Session, *, form: dict[str, str]) -> JSONResponse:
    """处理 POST /oauth/revoke.

    Body (application/x-www-form-urlencoded 或 application/json):
      - token: 必填
      - token_type_hint: 可选 ('access_token' | 'refresh_token'), bridge 双查找兜底

    返回:
      - 缺 token → 400 invalid_request (RFC 7009 §2.2.1)
      - 任意 token 输入 → 200 (RFC 7009 §2.2 一律成功语义)
    """
    token = form.get("token", "").strip()
    if not token:
        return oauth_error("invalid_request", "token is required")

    hint = form.get("token_type_hint", "").strip().lower()

    # 不论 hint, 双查找兜底 (一次 revoke 同时废掉 token 行上两端)
    access_hit = revoke_token(session, access_token=token)
    refresh_hit = revoke_by_refresh_token(session, refresh_token=token)

    log.info(
        "revoke: 200 hint=%s access_hit=%s refresh_hit=%s (token=<REDACTED>)",
        hint or "n/a", access_hit, refresh_hit,
    )
    return JSONResponse({}, status_code=200)
