from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from codex_preflight_mcp.remote_policy import RemoteTarget, ResourceLimits


@dataclass(frozen=True)
class ConfirmationError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class RemoteChallenge:
    challenge_id: str
    token: str
    issued_at: float
    expires_at: float
    key_id: str


@dataclass
class _ChallengeRecord:
    fingerprint: str
    expires_at: float
    consumed: bool = False


class RemoteConfirmationManager:
    def __init__(
        self,
        *,
        secret: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._clock = clock
        self._key_id = hashlib.sha256(self._secret).hexdigest()[:16]
        self._records: dict[str, _ChallengeRecord] = {}
        self._lock = threading.Lock()

    def issue(self, target: RemoteTarget, requested_ref: str, limits: ResourceLimits) -> RemoteChallenge:
        now = self._clock()
        challenge_id = uuid4().hex
        expires_at = now + limits.confirmation_expiry_seconds
        fingerprint = _fingerprint(target, requested_ref, limits)
        payload = {
            "challengeId": challenge_id,
            "nonce": secrets.token_urlsafe(24),
            "fingerprint": fingerprint,
            "issuedAt": now,
            "expiresAt": expires_at,
            "keyId": self._key_id,
        }
        encoded = _encode_json(payload)
        signature = _encode_bytes(hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest())
        with self._lock:
            self._records[challenge_id] = _ChallengeRecord(fingerprint, expires_at)
        return RemoteChallenge(challenge_id, f"{encoded}.{signature}", now, expires_at, self._key_id)

    def consume(
        self,
        token: str,
        target: RemoteTarget,
        requested_ref: str,
        limits: ResourceLimits,
    ) -> str:
        payload = self._decode_and_verify(token)
        challenge_id = payload.get("challengeId")
        if not isinstance(challenge_id, str):
            raise _invalid()
        expected_fingerprint = _fingerprint(target, requested_ref, limits)
        with self._lock:
            record = self._records.get(challenge_id)
            if record is None or payload.get("keyId") != self._key_id:
                raise _invalid()
            if record.consumed:
                raise ConfirmationError(
                    "MCP_REMOTE_CONFIRMATION_REPLAYED",
                    "The remote confirmation token has already been consumed.",
                )
            if self._clock() > record.expires_at:
                raise ConfirmationError(
                    "MCP_REMOTE_CONFIRMATION_EXPIRED",
                    "The remote confirmation token has expired.",
                )
            if payload.get("fingerprint") != expected_fingerprint or record.fingerprint != expected_fingerprint:
                raise _invalid()
            record.consumed = True
        return challenge_id

    def _decode_and_verify(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token or token.count(".") != 1:
            raise _invalid()
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = _encode_bytes(
            hmac.new(self._secret, encoded.encode("ascii", "strict"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise _invalid()
        try:
            payload = json.loads(_decode_bytes(encoded))
        except (UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise _invalid() from error
        if not isinstance(payload, dict):
            raise _invalid()
        return payload


def _fingerprint(target: RemoteTarget, requested_ref: str, limits: ResourceLimits) -> str:
    bound = {
        "operation": "static-scan",
        "tool": "remote_repository_scan",
        "canonicalUrl": target.canonical_url,
        "requestedRef": requested_ref,
        "hostPolicyVersion": "github-public-v1",
        "resourceLimitProfile": limits.to_dict(),
    }
    serialized = json.dumps(bound, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _encode_json(value: dict[str, Any]) -> str:
    return _encode_bytes(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_bytes(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8")


def _invalid() -> ConfirmationError:
    return ConfirmationError(
        "MCP_REMOTE_CONFIRMATION_INVALID",
        "The remote confirmation token is invalid for this operation.",
    )
