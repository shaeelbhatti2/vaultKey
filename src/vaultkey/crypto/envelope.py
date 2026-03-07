import base64
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from vaultkey.shared.value_objects import EncryptedBlob


class CryptoError(Exception):
    pass


class EnvelopeCrypto:
    def __init__(self, master_key_b64: str, key_version: int = 1) -> None:
        try:
            self._master_key = base64.b64decode(master_key_b64)
        except Exception as exc:
            raise CryptoError("invalid master key encoding") from exc
        if len(self._master_key) < 32:
            raise CryptoError("master key must be at least 32 bytes")
        self._key_version = key_version

    @property
    def key_version(self) -> int:
        return self._key_version

    def _derive_kek(self, context: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"vaultkey-kek-v1",
            info=context,
        )
        return hkdf.derive(self._master_key)

    def generate_dek(self) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def wrap_dek(self, dek: bytes, secret_id: bytes) -> bytes:
        kek = self._derive_kek(b"wrap:" + secret_id)
        aesgcm = AESGCM(kek)
        nonce = os.urandom(12)
        wrapped = aesgcm.encrypt(nonce, dek, secret_id)
        return nonce + wrapped

    def unwrap_dek(self, wrapped: bytes, secret_id: bytes) -> bytes:
        if len(wrapped) < 13:
            raise CryptoError("invalid wrapped dek")
        nonce = wrapped[:12]
        payload = wrapped[12:]
        kek = self._derive_kek(b"wrap:" + secret_id)
        aesgcm = AESGCM(kek)
        try:
            return aesgcm.decrypt(nonce, payload, secret_id)
        except Exception as exc:
            raise CryptoError("dek unwrap failed") from exc

    def encrypt_payload(self, plaintext: bytes, secret_id: bytes) -> EncryptedBlob:
        dek = self.generate_dek()
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, secret_id)
        wrapped_dek = self.wrap_dek(dek, secret_id)
        dek_zero = bytearray(dek)
        for i in range(len(dek_zero)):
            dek_zero[i] = 0
        return EncryptedBlob(
            ciphertext=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            key_version=self._key_version,
        )

    def decrypt_payload(self, blob: EncryptedBlob, secret_id: bytes) -> bytes:
        dek = self.unwrap_dek(blob.wrapped_dek, secret_id)
        aesgcm = AESGCM(dek)
        try:
            plaintext = aesgcm.decrypt(blob.nonce, blob.ciphertext, secret_id)
        except Exception as exc:
            raise CryptoError("payload decrypt failed") from exc
        finally:
            dek_zero = bytearray(dek)
            for i in range(len(dek_zero)):
                dek_zero[i] = 0
        return plaintext

    def rewrap_dek(self, blob: EncryptedBlob, secret_id: bytes, new_master: "EnvelopeCrypto") -> EncryptedBlob:
        dek = self.unwrap_dek(blob.wrapped_dek, secret_id)
        wrapped = new_master.wrap_dek(dek, secret_id)
        dek_zero = bytearray(dek)
        for i in range(len(dek_zero)):
            dek_zero[i] = 0
        return EncryptedBlob(
            ciphertext=blob.ciphertext,
            nonce=blob.nonce,
            wrapped_dek=wrapped,
            algorithm=blob.algorithm,
            key_version=new_master.key_version,
        )


def secure_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
