"""Encryption format for job and result files.

File = MAGIC (6 bytes) | nonce (12 bytes) | AES-256-GCM ciphertext+tag.
Each run uses its own fresh 32-byte key (64 hex characters), destroyed after the results are
collected, so old ciphertext in the git history cannot be opened later. AAD binds each file to
its purpose (job or result), run id and shard. Plaintext is length-prefixed and zero-padded to a
multiple of PAD bytes so file sizes reveal little.
"""
import hashlib
import os
import re
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"BJOB1\n"
NONCE_LEN = 12
PAD = 1 << 20
RID_RE = re.compile(r"^[0-9a-f]{16}$")


def parse_key(text):
    text = text.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError("key must be 64 lowercase hex characters")
    return bytes.fromhex(text)


def new_key_hex():
    return secrets.token_bytes(32).hex()


def check_rid(rid):
    if not RID_RE.fullmatch(rid):
        raise ValueError("bad run id")


def job_aad(rid):
    check_rid(rid)
    return b"batch/job/v1|" + rid.encode()


def result_aad(rid, shard):
    check_rid(rid)
    return b"batch/result/v1|" + rid.encode() + b"|" + str(int(shard)).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encrypt(key, plaintext, aad):
    if len(key) != 32:
        raise ValueError("bad key")
    body = struct.pack(">Q", len(plaintext)) + plaintext
    body += b"\0" * (-len(body) % PAD)
    nonce = os.urandom(NONCE_LEN)  # fresh for every message
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, body, aad)


def decrypt(key, blob, aad):
    """Authenticates the whole file before returning anything."""
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_LEN + 16 + 8:
        raise ValueError("not a job file")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_LEN]
    body = AESGCM(key).decrypt(nonce, blob[len(MAGIC) + NONCE_LEN:], aad)
    (n,) = struct.unpack(">Q", body[:8])
    if n > len(body) - 8:
        raise ValueError("bad length")
    return body[8:8 + n]


def is_ciphertext(blob):
    return blob.startswith(MAGIC) and len(blob) > len(MAGIC) + NONCE_LEN + 16
