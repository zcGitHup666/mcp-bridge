"""pytest 共享配置 + fixture.

- 让 pytest 找到 src/qcn_mcp_bridge 包 (无需 pip install -e)
- OAuth 测试需要的临时 RSA 私钥 + 临时 SQLite

按 CLAUDE §6.3.2: 临时私钥放在 tmp_path (测试结束自动清), 不写入仓库.
按 CLAUDE §7: KISS — fixture 复用, 测试代码只关注业务逻辑.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# === OAuth 测试 fixture (Phase 1A) ===

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import sessionmaker

from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
from qcn_mcp_bridge.auth.storage import init_engine


@pytest.fixture
def tmp_db(tmp_path: Path) -> tuple[str, sessionmaker]:
    """临时 SQLite 数据库 + sessionmaker.

    yield (db_path, SessionLocal). 测试结束自动清理 tmp_path.
    """
    db_path = str(tmp_path / "test_oauth.sqlite3")
    engine, SessionLocal = init_engine(db_path)
    yield db_path, SessionLocal
    # tmp_path 自动清理


@pytest.fixture
def tmp_jwt_key(tmp_path: Path) -> Path:
    """临时 RSA 私钥 (PKCS8 PEM). 测试结束随 tmp_path 自动清."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "jwt-signing.pem"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    return key_path


@pytest.fixture
def jwt_signer(tmp_jwt_key: Path) -> JWTSigner:
    """JWTSigner 实例 (绑定临时私钥 + 测试 issuer/resource)."""
    return JWTSigner(
        tmp_jwt_key,
        issuer="https://test.bridge",
        audience="https://test.bridge/mcp",
    )