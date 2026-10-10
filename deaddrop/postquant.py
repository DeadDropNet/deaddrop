"""Post-quantum channel key agreement: X25519 + ML-KEM-768 (Kyber) hybrid.

A circuit\'s channel key is derived from the *combination* of a classical
ephemeral ECDH (X25519) and an ML-KEM-768 encapsulation. Security is the
AND of both: an adversary recovering the key must break BOTH the
post-quantum lattice problem (ML-KEM-768) AND the classical Diffie-Hellman
(X25519). That means a future quantum adversary holding years of captured
traffic cannot run harvest-now-decrypt-later on this circuit — a quantum
machine breaks the lattice half, but the X25519 share can only be recovered
if it also solved X25519 at capture time, which it couldn\'t.

KEM (key-encapsulation) semantics:
  - Receiver: long-term identity = an X25519 keypair + an ML-KEM-768
    keypair. It publishes both public keys.
  - Sender:   generates an ephemeral X25519 keypair, encapsulates a random
    lattice key under the receiver\'s ML-KEM public key, and sends
    (ephemeral_x25519_pk, mlkem_ciphertext).
  - Both sides derive:   channel_key = HKDF( mlkem_ss || x25519_ss )

The X25519 half is an ephemeral-static ECDH (sender ephemeral, receiver
long-term); the ML-KEM half is a genuine KEM. All primitives come from the
`cryptography` package (Rust/OpenSSL ML-KEM + standard X25519), so this is
a real implementation, not a sketch.
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def _hkdf(shared: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(shared)


class ChannelReceiver:
    """Long-term identity for one endpoint of a channel."""

    def __init__(self, seed: bytes = None):
        seed = seed or os.urandom(32)
        # long-term X25519 key (deterministic from seed for reproducible tests)
        self.x25519 = X25519PrivateKey.from_private_bytes(seed[:32])
        # ML-KEM-768 keypair (fresh random; the public key is what ships)
        self.mlkem = MLKEM768PrivateKey.generate()

    def public(self):
        return {
            "x25519": self.x25519.public_key().public_bytes_raw(),
            "mlkem": self.mlkem.public_key().public_bytes_raw(),
        }


class ChannelSender:
    """Initiates a channel to a receiver\'s public key."""

    def __init__(self, receiver_public: dict):
        # the receiver\'s long-term X25519 public key (for the ECDH)
        self.r_x_pk = X25519PublicKey.from_public_bytes(receiver_public["x25519"])
        # the receiver\'s ML-KEM public key (for the encapsulation)
        self.r_m_pk = MLKEM768PublicKey.from_public_bytes(receiver_public["mlkem"])
        # ephemeral X25519 for this channel
        self.e_x = X25519PrivateKey.generate()
        # encapsulate the lattice half under the receiver\'s ML-KEM public key
        self.mlkem_ss, self.mlkem_ct = self.r_m_pk.encapsulate()

    def transcript(self):
        """What goes on the wire: ephemeral X25519 pk + ML-KEM ciphertext."""
        return {
            "eph_x25519": self.e_x.public_key().public_bytes_raw(),
            "mlkem_ct": self.mlkem_ct,
        }


def _x25519_shared(e_x_pk_bytes: bytes, r_x_private: X25519PrivateKey) -> bytes:
    """Ephemeral-static X25519 shared secret (computed on the receiver side)."""
    e_pk = X25519PublicKey.from_public_bytes(e_x_pk_bytes)
    return r_x_private.exchange(e_pk)


def receiver_derive(receiver: ChannelReceiver, sender_transcript: dict) -> bytes:
    """Receiver side of key derivation."""
    x25519_ss = _x25519_shared(sender_transcript["eph_x25519"], receiver.x25519)
    mlkem_ss = receiver.mlkem.decapsulate(sender_transcript["mlkem_ct"])
    return _hkdf(mlkem_ss + x25519_ss, b"deaddrop-channel-key")


def sender_derive(sender: ChannelSender) -> bytes:
    """Sender side of key derivation (must equal the receiver\'s)."""
    x25519_ss = sender.e_x.exchange(sender.r_x_pk)
    return _hkdf(sender.mlkem_ss + x25519_ss, b"deaddrop-channel-key")


def hybrid_selftest() -> bool:
    """Prove sender and receiver derive the same channel key, and that a
    tampered transcript yields a different key (integrity)."""
    rx = ChannelReceiver(seed=os.urandom(32))
    tx = ChannelSender(rx.public())
    k_sender = sender_derive(tx)
    k_receiver = receiver_derive(rx, tx.transcript())
    match = (k_sender == k_receiver) and len(k_sender) == 32
    # tamper the ML-KEM ciphertext -> receiver\'s lattice share changes,
    # so the derived key must diverge
    bad = dict(tx.transcript())
    ct = tx.transcript()["mlkem_ct"]
    bad["mlkem_ct"] = bytes(1 if i == 0 else c for i, c in enumerate(ct))
    k_tamper = receiver_derive(rx, bad)
    return match and (k_tamper != k_receiver)


def hybrid_security_note() -> str:
    return (
        "Hybrid X25519 + ML-KEM-768: an adversary recovering the channel key "
        "must solve BOTH ML-KEM-768 (post-quantum lattice) AND X25519 ECDH. "
        "A quantum machine breaks the lattice half, but cannot retroactively "
        "break X25519 on already-captured traffic — defeating "
        "harvest-now-decrypt-later on this circuit."
    )
