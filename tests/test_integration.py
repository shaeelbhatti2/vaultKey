import pytest

from vaultkey.api.app import create_app
from vaultkey.crypto.envelope import EnvelopeCrypto
from vaultkey.shared.domain import RoleName, SecretPath
from vaultkey.shared.value_objects import EncryptedBlob


def test_create_app_has_health_route() -> None:
    app = create_app()
    paths = [route.path for route in app.routes if hasattr(route, "path")]
    assert "/health" in paths


def test_secret_path_rejects_traversal() -> None:
    with pytest.raises(ValueError):
        SecretPath(value="../etc/passwd")


def test_encrypted_blob_roundtrip() -> None:
    import base64

    key = base64.b64encode(b"k" * 40).decode()
    crypto = EnvelopeCrypto(key)
    blob = crypto.encrypt_payload(b"test", b"secret-id-bytes-123456789012")
    restored = EncryptedBlob.from_dict(blob.as_dict())
    assert crypto.decrypt_payload(restored, b"secret-id-bytes-123456789012") == b"test"


def test_role_hierarchy() -> None:
    from vaultkey.auth.rbac import role_at_least

    assert role_at_least(RoleName.ADMIN, RoleName.OPERATOR)
    assert not role_at_least(RoleName.READONLY, RoleName.OPERATOR)


@pytest.mark.asyncio
async def test_rotation_policy_service_attach() -> None:
    import uuid
    from unittest.mock import AsyncMock, MagicMock

    from vaultkey.jobs.rotation import RotationPolicyService

    session = AsyncMock()
    empty = MagicMock()
    empty.scalar_one_or_none.return_value = None
    session.execute.return_value = empty
    svc = RotationPolicyService()
    policy = await svc.attach_policy(session, uuid.uuid4(), 30, 7)
    assert policy.interval_days == 30
    session.add.assert_called_once()
