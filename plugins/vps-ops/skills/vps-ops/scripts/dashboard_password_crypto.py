"""Protect typed passwords while the dashboard relays local requests."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
import json
import os
from pathlib import Path
import sys


def prepare_password_dependencies():
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        directory = Path(os.environ["LOCALAPPDATA"]) / "VPS Ops" / "python-deps"
        if directory.is_dir() and str(directory) not in sys.path:
            sys.path.append(str(directory))


def password_context(draft, action):
    return json.dumps([draft.get("host"), draft.get("username", ""), draft.get("port"),
                       draft.get("auth_mode"), draft.get("known_hosts", ""), action],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class PasswordEnvelope:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        prepare_password_dependencies()
        try:
            import paramiko  # noqa: F401  Password support requires both libraries.
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except (ImportError, OSError):
            return
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = b64encode(self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )).decode("ascii")

    def decrypt(self, draft, action):
        from dashboard_credentials import validate_password
        return validate_password(self._decrypt(draft, action))

    def decrypt_json(self, draft, action):
        try:
            value = json.loads(self._decrypt(draft, action))
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("无法读取加密的连接设置。") from None
        if not isinstance(value, dict):
            raise ValueError("加密的连接设置格式无效。")
        return value

    def _decrypt(self, draft, action):

        if self.private_key is None:
            raise ValueError("本机缺少密码登录组件，请先安装星图的 SSH 依赖。")
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        envelope = draft.get("password_box")
        try:
            if not isinstance(envelope, dict) or set(envelope) != {"wrapped_key", "iv", "ciphertext"}:
                raise ValueError
            sizes = {"wrapped_key": (256, 256), "iv": (12, 12), "ciphertext": (17, 4096)}
            fields = {}
            for field, (minimum, maximum) in sizes.items():
                value = envelope[field]
                if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
                    raise ValueError
                decoded = b64decode(value, validate=True)
                if not minimum <= len(decoded) <= maximum:
                    raise ValueError
                fields[field] = decoded
            key = self.private_key.decrypt(fields["wrapped_key"], padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None,
            ))
            if len(key) != 32:
                raise ValueError
            password = AESGCM(key).decrypt(fields["iv"], fields["ciphertext"], password_context(draft, action)).decode("utf-8")
        except (ValueError, TypeError, InvalidTag, Base64Error):
            raise ValueError("无法读取加密的凭据，请刷新面板后重试。") from None
        return password
