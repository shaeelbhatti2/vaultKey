import base64
import uuid

import pytest

from vaultkey.crypto.envelope import CryptoError, EnvelopeCrypto


MASTER_KEY = base64.b64encode(b"0" * 32 + b"1" * 8).decode("ascii")


def test_encrypt_decrypt_roundtrip() -> None:
    crypto = EnvelopeCrypto(MASTER_KEY)
    secret_id = uuid.uuid4().bytes
    plaintext = b"super-secret-api-key-value"
    blob = crypto.encrypt_payload(plaintext, secret_id)
    recovered = crypto.decrypt_payload(blob, secret_id)
    assert recovered == plaintext


def test_unique_nonces_per_encryption() -> None:
    crypto = EnvelopeCrypto(MASTER_KEY)
    secret_id = uuid.uuid4().bytes
    blob_a = crypto.encrypt_payload(b"same", secret_id)
    blob_b = crypto.encrypt_payload(b"same", secret_id)
    assert blob_a.nonce != blob_b.nonce
    assert blob_a.ciphertext != blob_b.ciphertext


def test_wrong_secret_id_fails_decrypt() -> None:
    crypto = EnvelopeCrypto(MASTER_KEY)
    secret_id = uuid.uuid4().bytes
    blob = crypto.encrypt_payload(b"data", secret_id)
    with pytest.raises(CryptoError):
        crypto.decrypt_payload(blob, uuid.uuid4().bytes)


def test_blob_dict_serialization() -> None:
    crypto = EnvelopeCrypto(MASTER_KEY)
    secret_id = uuid.uuid4().bytes
    blob = crypto.encrypt_payload(b"payload", secret_id)
    restored = type(blob).from_dict(blob.as_dict())
    assert crypto.decrypt_payload(restored, secret_id) == b"payload"


def test_rewrap_dek_with_new_master() -> None:
    old = EnvelopeCrypto(MASTER_KEY, key_version=1)
    new_key = base64.b64encode(b"2" * 40).decode("ascii")
    new = EnvelopeCrypto(new_key, key_version=2)
    secret_id = uuid.uuid4().bytes
    blob = old.encrypt_payload(b"rotate-me", secret_id)
    rewrapped = old.rewrap_dek(blob, secret_id, new)
    assert rewrapped.key_version == 2
    assert new.decrypt_payload(rewrapped, secret_id) == b"rotate-me"
