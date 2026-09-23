"""Phase 2B1 Step 2: 4 个 form POST handler factory (登录/注册/同意/发码).

调用 qcn-dev 真实接口 (替换 Step 1 mock) + AES-GCM 加密 session 写 bindings (§B7).

按 CLAUDE §4.5 出参类型 dict / RedirectResponse / JSONResponse.
按 CLAUDE §6.3.2: 不打印 token / session / 手机号验证码.
按 CLAUDE §4.1: 单文件 ≤ 300 行.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from qcn_mcp_bridge.auth.authorize import handle_authorize
from qcn_mcp_bridge.auth.dynamic_client import verify_client_redirect
from qcn_mcp_bridge.auth.qcn_dev_client import (
    QcnDevBusinessError,
    QcnDevClient,
    QcnDevError,
    QcnDevTransportError,
)
from qcn_mcp_bridge.auth.session_crypto import encrypt_session
from qcn_mcp_bridge.auth.storage import find_binding, upsert_binding


SESSION_COOKIE_NAME = "qcn_bridge_session"


def _set_session_cookie(response: Response, user_id: int) -> None:
    """写 Bridge 自己的 session cookie (含 qcn-dev user_id, 不含 qcn-dev session 明文)."""
    response.set_cookie(
        SESSION_COOKIE_NAME,
        f"user_id={user_id}",
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=7 * 24 * 3600,
    )


def _redirect_to_authorize(form: dict[str, Any]) -> RedirectResponse:
    """PKCE state 透传 + 303 重定向回 /oauth/authorize (走 consent 页)."""
    params = urlencode({
        "state": form.get("state", ""),
        "code_challenge": form.get("code_challenge", ""),
        "code_challenge_method": form.get("code_challenge_method", ""),
        "redirect_uri": form.get("redirect_uri", ""),
        "client_id": form.get("client_id", ""),
    })
    return RedirectResponse(url=f"/oauth/authorize?{params}", status_code=303)


def _redirect_with_error(form: dict[str, Any], error_msg: str) -> RedirectResponse:
    """带 error query 跳回 /oauth/authorize (authorize_get 会把 error 渲染到 login.html)."""
    qs = {
        "state": form.get("state", ""),
        "code_challenge": form.get("code_challenge", ""),
        "code_challenge_method": form.get("code_challenge_method", ""),
        "redirect_uri": form.get("redirect_uri", ""),
        "client_id": form.get("client_id", ""),
        "error": error_msg,
    }
    return RedirectResponse(url=f"/oauth/authorize?{urlencode(qs)}", status_code=303)


def _persist_session(
    *,
    SessionLocal: sessionmaker,
    user_id: int,
    tenant_id: int | None,
    auth_token: str,
) -> None:
    """AES-GCM 加密 qcn-dev session + 写 bindings (status=BOUND)."""
    expires_at = datetime.utcnow() + timedelta(hours=12)
    encrypted = encrypt_session(auth_token)
    session = SessionLocal()
    try:
        upsert_binding(
            session,
            user_id=user_id,
            tenant_id=tenant_id,
            product="qcn",
            qcn_dev_session_encrypted=encrypted,
            expires_at=expires_at,
            status="BOUND",
        )
    finally:
        session.close()


def make_send_code_handler(qcn_dev: QcnDevClient):
    async def send_code_post(request: Request):
        body = await request.json()
        phone = body.get("phone", "")
        try:
            await qcn_dev.send_code(phone)
            return JSONResponse({"ok": True, "message": "验证码已发送"})
        except QcnDevBusinessError as exc:
            return JSONResponse(
                {"ok": False, "error": "business_error", "error_description": exc.message},
                status_code=400,
            )
        except QcnDevTransportError as exc:
            return JSONResponse(
                {"ok": False, "error": "transport_error", "error_description": str(exc)},
                status_code=502,
            )

    return send_code_post


def make_login_form_handler(
    *, qcn_dev: QcnDevClient, SessionLocal: sessionmaker
):
    async def login_form_post(request: Request):
        form = await request.form()
        phone = form.get("phone", "")
        code = form.get("code", "")

        # 1) 调 qcn-dev /login 拿 auth_token + user_id
        try:
            login_result = await qcn_dev.login(phone, code)
        except QcnDevBusinessError as exc:
            return _redirect_with_error(form, exc.message[:80] if exc.message else "登录失败")
        except QcnDevTransportError:
            return _redirect_with_error(form, "登录服务暂时不可用")

        # 2) AES-GCM 加密 session + 写 bindings (Phase 2B1 Step 2 简化: 单 user_id)
        _persist_session(
            SessionLocal=SessionLocal,
            user_id=login_result["user_id"],
            tenant_id=login_result.get("tenant_id"),
            auth_token=login_result["auth_token"] or "",
        )

        # 3) Set Bridge session cookie + 303 redirect /oauth/authorize (走 consent 页)
        response = _redirect_to_authorize(form)
        _set_session_cookie(response, login_result["user_id"])
        return response

    return login_form_post


def make_register_form_handler(
    *, qcn_dev: QcnDevClient, SessionLocal: sessionmaker
):
    async def register_form_post(request: Request):
        form = await request.form()
        phone = form.get("phone", "")
        code = form.get("code", "")
        company_select = form.get("company_select", "")
        company_new = form.get("company_new", "")
        eim_name = (
            company_new if company_select == "__new__" or not company_select
            else company_select
        )
        password = form.get("password", "")
        password_confirm = form.get("password_confirm", "")
        agreed = form.get("agree", "")

        # 校验
        if not phone or not code or not eim_name:
            return _redirect_with_error(form, "手机号/验证码/公司不能为空")
        if password != password_confirm:
            return _redirect_with_error(form, "两次密码不一致")
        if not agreed:
            return _redirect_with_error(form, "请阅读并同意协议")

        # 1) 调 qcn-dev /regist 注册
        try:
            await qcn_dev.register(
                phone=phone, eim_name=eim_name, password=password, invite_code=""
            )
        except QcnDevBusinessError as exc:
            return _redirect_with_error(form, exc.message[:80] if exc.message else "注册失败")
        except QcnDevTransportError:
            return _redirect_with_error(form, "注册服务暂时不可用")

        # 2) 注册成功 → 立即 /login 拿 qcn-dev session
        try:
            login_result = await qcn_dev.login(phone, code)
        except QcnDevError as exc:
            return _redirect_with_error(
                form, f"注册成功但登录失败: {str(exc)[:60]}"
            )

        # 3) AES-GCM + bindings
        _persist_session(
            SessionLocal=SessionLocal,
            user_id=login_result["user_id"],
            tenant_id=login_result.get("tenant_id"),
            auth_token=login_result["auth_token"] or "",
        )

        response = _redirect_to_authorize(form)
        _set_session_cookie(response, login_result["user_id"])
        return response

    return register_form_post


def make_authorize_post_handler(
    *, SessionLocal: sessionmaker
):
    """POST /oauth/authorize — 用户点同意/拒绝."""
    async def authorize_post(request: Request):
        form = await request.form()
        decision = form.get("decision", "")
        state = form.get("state", "")
        client_id = form.get("client_id", "")
        redirect_uri = form.get("redirect_uri", "")

        if decision == "approve":
            # 从 cookie 拿 user_id
            cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
            if not cookie.startswith("user_id="):
                # 没登录 → 重定向回 authorize (走 login 页)
                return RedirectResponse(url="/oauth/authorize", status_code=303)
            try:
                user_id = int(cookie.split("=", 1)[1])
            except (ValueError, IndexError):
                return RedirectResponse(url="/oauth/authorize", status_code=303)

            # Phase 2B1 Step 2: 从 bindings 取 tenant_id (默认 42 mock)
            session = SessionLocal()
            try:
                binding = find_binding(session, user_id=user_id, tenant_id=42)
            finally:
                session.close()
            tenant_id = (binding or {}).get("tenant_id") or 42

            # 签发 code → 302 redirect_uri
            query = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": form.get("code_challenge", ""),
                "code_challenge_method": form.get("code_challenge_method", "S256"),
                "state": state,
                "scope": form.get("scope", ""),
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
                "product": "qcn",
            }
            sess = SessionLocal()
            try:
                redirect, err = handle_authorize(sess, query=query)
            finally:
                sess.close()
            if err is not None:
                return err
            return redirect

        # deny: 302 redirect_uri?error=access_denied&state=...
        parsed = urlparse(redirect_uri)
        qs = parse_qs(parsed.query)
        qs["error"] = ["access_denied"]
        if state:
            qs["state"] = [state]
        new_q = urlencode(qs, doseq=True)
        return RedirectResponse(
            url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_q}",
            status_code=302,
        )

    return authorize_post