from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from uuid import uuid4

CONFIRMATION_EXPIRY_SECONDS = 300
ISSUE_WINDOW_SECONDS = 60
MAX_CANONICAL_JSON_BYTES = 4096
MAX_ISSUES_PER_WINDOW = 32
MAX_LIVE_CHALLENGES = 128
MAX_TOKEN_BYTES = 1024

_TOKEN_FIELDS = {
    "bindingDigest",
    "challengeId",
    "expiresAt",
    "issuedAt",
    "keyId",
    "nonce",
    "version",
}
_TOKEN_VERSION = "trust-mutation-confirmation/v1"


class TrustMutationConfirmationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class TrustMutationChallenge:
    challenge_id: str
    token: str
    issued_at: float
    expires_at: float
    binding_digest: str
    display: Mapping[str, object]
    proposed_entry_id: str


@dataclass(frozen=True)
class ConsumedMutationChallenge:
    challenge_id: str
    operation: str
    issued_at: float
    expires_at: float
    binding_digest: str
    binding: Mapping[str, object]
    display: Mapping[str, object]
    proposed_entry_id: str


@dataclass
class _ChallengeRecord:
    operation: str
    issued_at: float
    expires_at: float
    binding_digest: str
    binding: Mapping[str, object]
    display: Mapping[str, object]
    proposed_entry_id: str
    consumed: bool = False


class TrustMutationConfirmationManager:
    def __init__(
        self,
        *,
        secret: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if secret is None:
            secret = secrets.token_bytes(32)
        elif type(secret) is not bytes or len(secret) != 32:
            raise ValueError("secret must be exactly 32 bytes")
        self._secret = secret
        self._clock = clock
        self._key_id = hashlib.sha256(self._secret).hexdigest()[:16]
        self._issued_at: list[float] = []
        self._lock = threading.Lock()
        self._records: dict[str, _ChallengeRecord] = {}

    def issue(
        self,
        operation: str,
        binding: Mapping[str, object],
        display: Mapping[str, object],
        *,
        proposed_entry_id: str,
    ) -> TrustMutationChallenge:
        if not isinstance(operation, str) or not operation or len(operation.encode("utf-8")) > 128:
            raise _invalid()
        if (
            not isinstance(proposed_entry_id, str)
            or not proposed_entry_id
            or len(proposed_entry_id.encode("utf-8")) > 256
        ):
            raise _invalid()

        canonical_binding = _canonical_mapping(binding)
        canonical_display = _canonical_mapping(display)
        binding_digest = hashlib.sha256(canonical_binding).hexdigest()
        frozen_binding = _freeze(json.loads(canonical_binding))
        frozen_display = _freeze(json.loads(canonical_display))
        if not isinstance(frozen_binding, Mapping) or not isinstance(frozen_display, Mapping):
            raise _invalid()

        with self._lock:
            now = _timestamp(self._clock())
            self._prune_expired(now)
            self._prune_issue_window(now)
            if len(self._records) >= MAX_LIVE_CHALLENGES:
                raise _capacity()
            if len(self._issued_at) >= MAX_ISSUES_PER_WINDOW:
                raise _rate_limited()

            challenge_id = uuid4().hex
            expires_at = now + CONFIRMATION_EXPIRY_SECONDS
            payload = {
                "bindingDigest": binding_digest,
                "challengeId": challenge_id,
                "expiresAt": _serialize_timestamp(expires_at),
                "issuedAt": _serialize_timestamp(now),
                "keyId": self._key_id,
                "nonce": secrets.token_urlsafe(16),
                "version": _TOKEN_VERSION,
            }
            token = _sign(payload, self._secret)
            if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
                raise _invalid()
            self._records[challenge_id] = _ChallengeRecord(
                operation=operation,
                issued_at=now,
                expires_at=expires_at,
                binding_digest=binding_digest,
                binding=frozen_binding,
                display=frozen_display,
                proposed_entry_id=proposed_entry_id,
            )
            self._issued_at.append(now)

        return TrustMutationChallenge(
            challenge_id=challenge_id,
            token=token,
            issued_at=now,
            expires_at=expires_at,
            binding_digest=binding_digest,
            display=frozen_display,
            proposed_entry_id=proposed_entry_id,
        )

    def authenticate_and_consume(self, token: object) -> ConsumedMutationChallenge:
        payload = _verify(token, self._secret)
        challenge_id = payload["challengeId"]
        if not isinstance(challenge_id, str):
            raise _invalid()

        with self._lock:
            record = self._records.get(challenge_id)
            if record is None or payload.get("keyId") != self._key_id:
                raise _invalid()
            now = _timestamp(self._clock())
            if now >= record.expires_at:
                self._prune_expired(now)
                raise _expired()
            self._prune_expired(now)
            if record.consumed:
                raise _invalid()
            if (
                payload.get("issuedAt") != _serialize_timestamp(record.issued_at)
                or payload.get("expiresAt") != _serialize_timestamp(record.expires_at)
                or payload.get("bindingDigest") != record.binding_digest
            ):
                raise _invalid()
            record.consumed = True

            return ConsumedMutationChallenge(
                challenge_id=challenge_id,
                operation=record.operation,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
                binding_digest=record.binding_digest,
                binding=record.binding,
                display=record.display,
                proposed_entry_id=record.proposed_entry_id,
            )

    def invalidate_all(self) -> None:
        with self._lock:
            self._records.clear()
            self._issued_at.clear()

    def _prune_expired(self, now: float) -> None:
        self._records = {
            challenge_id: record
            for challenge_id, record in self._records.items()
            if record.expires_at > now
        }

    def _prune_issue_window(self, now: float) -> None:
        self._issued_at = [issued_at for issued_at in self._issued_at if issued_at > now - ISSUE_WINDOW_SECONDS]


def _canonical_mapping(value: Mapping[str, object]) -> bytes:
    if not isinstance(value, Mapping):
        raise _invalid()
    try:
        serialized = json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        parsed = json.loads(serialized)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise _invalid() from error
    if not isinstance(parsed, dict) or len(serialized) > MAX_CANONICAL_JSON_BYTES:
        raise _invalid()
    return serialized


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _sign(payload: dict[str, object], secret: bytes) -> str:
    encoded = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _encode(hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def _verify(token: object, secret: bytes) -> dict[str, Any]:
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or len(token.encode("utf-8")) > MAX_TOKEN_BYTES
        or token.count(".") != 1
    ):
        raise _invalid()
    encoded, supplied_signature = token.split(".", 1)
    expected_signature = _encode(hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise _invalid()
    try:
        payload = json.loads(_decode(encoded))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise _invalid() from error
    if (
        not isinstance(payload, dict)
        or set(payload) != _TOKEN_FIELDS
        or payload.get("version") != _TOKEN_VERSION
        or not isinstance(payload.get("challengeId"), str)
        or not isinstance(payload.get("bindingDigest"), str)
        or not isinstance(payload.get("keyId"), str)
        or not isinstance(payload.get("nonce"), str)
        or not payload["nonce"]
    ):
        raise _invalid()
    issued_at = _deserialize_timestamp(payload.get("issuedAt"))
    expires_at = _deserialize_timestamp(payload.get("expiresAt"))
    if expires_at != issued_at + CONFIRMATION_EXPIRY_SECONDS:
        raise _invalid()
    return payload


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> str:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "strict")


def _serialize_timestamp(value: float) -> str:
    return value.hex()


def _deserialize_timestamp(value: object) -> float:
    if not isinstance(value, str):
        raise _invalid()
    try:
        timestamp = float.fromhex(value)
    except ValueError as error:
        raise _invalid() from error
    if not math.isfinite(timestamp) or timestamp.hex() != value:
        raise _invalid()
    return timestamp


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _invalid()
    try:
        timestamp = float(value)
    except OverflowError as error:
        raise _invalid() from error
    if not math.isfinite(timestamp):
        raise _invalid()
    return timestamp


def _invalid() -> TrustMutationConfirmationError:
    return TrustMutationConfirmationError(
        "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
        "CONFIRMATION_INVALID: The trust mutation confirmation token is invalid.",
    )


def _expired() -> TrustMutationConfirmationError:
    return TrustMutationConfirmationError(
        "MCP_TRUST_MUTATION_CONFIRMATION_EXPIRED",
        "CONFIRMATION_EXPIRED: The trust mutation confirmation token has expired.",
    )


def _capacity() -> TrustMutationConfirmationError:
    return TrustMutationConfirmationError(
        "MCP_TRUST_MUTATION_CONFIRMATION_CAPACITY",
        "CONFIRMATION_CAPACITY: Too many live trust mutation confirmation challenges exist.",
    )


def _rate_limited() -> TrustMutationConfirmationError:
    return TrustMutationConfirmationError(
        "MCP_TRUST_MUTATION_CONFIRMATION_RATE_LIMITED",
        "CONFIRMATION_RATE_LIMITED: Trust mutation confirmation issuance is temporarily limited.",
    )
