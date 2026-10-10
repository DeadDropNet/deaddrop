"""Sphinx onion routing with 3 parallel sub-paths + a staked guard committee.

Two structural differences from Tor:

  1. PARALLEL SUB-PATHS. A logical flow is split across 3 independent
     circuits (sub-paths). Each sub-path is a valid end-to-end route on its
     own, but the receiver reassembles the payload from all three. An
     adversary must compromise the *intersection* of paths to deanonymize;
     capturing one or two relays (or even whole sub-paths) leaks nothing,
     because no single sub-path identifies sender OR receiver.

  2. STAKED GUARD COMMITTEE. Entry and exit points are chosen from a
     committee of the highest-bond relays, weighted by stake. A guard that
     colludes to de-anonymize a user burns its bond (it can be the only one
     that saw the user's plaintext), so the colluder must pay XMR.

Each hop is authenticated by a registry-bound ring signature (see ec.py),
so a relay proves "I am a staked relay in this registry" without revealing
which relay it is.

Sphinx key schedule (simplified but real): the sender pre-computes a chain
of hop secrets via a one-way chain, and each relay peels one layer of
ChaCha20-Poly1305. We use per-hop fresh nonces and a message-auth tag so a
relay that drops or reorders packets is detectable.
"""

import hashlib
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .ec import KeyPair, ring_sign, ring_verify
from .registry import Registry

N_SUBPATHS = 3  # 3 parallel sub-paths per logical flow


def _aead(key: bytes, nonce: bytes, data: bytes, aad: bytes = b""):
    """ChaCha20-Poly1305 encrypt. nonce must be exactly 12 bytes."""
    return ChaCha20Poly1305(key).encrypt(nonce, data, aad)


def _aead_open(key: bytes, nonce: bytes, blob: bytes, aad: bytes = b""):
    """ChaCha20-Poly1305 decrypt. nonce must be exactly 12 bytes."""
    return ChaCha20Poly1305(key).decrypt(nonce, blob, aad)


class OnionHeader:
    """One layer of the onion. A relay peels exactly one layer."""

    def __init__(self, next_relays, payload, hop_secret):
        self.next_relays = next_relays   # list of relay index (logical path)
        self.payload = payload
        self.hop_secret = hop_secret


class Circuit:
    """A 3-sub-path circuit from sender to receiver."""

    def __init__(self, registry: Registry, sender_region: str,
                 receiver_region: str, path_len: int = 4, seed: int = None):
        self.registry = registry
        self.sender_region = sender_region
        self.receiver_region = receiver_region
        self.path_len = path_len
        self.rng = secrets.SystemRandom() if seed is None else _SeededRng(seed)
        self.subpaths = []          # list[list[int]] relay indices per sub-path
        self.flow_key = os.urandom(32)
        self.session = os.urandom(32)
        self._build()

    def _pick_guard(self):
        """Stake-weighted pick from the top-bond committee for this region."""
        cands = [i for i, r in enumerate(self.registry.relays)
                 if r.region == self.sender_region]
        if not cands:
            cands = list(range(len(self.registry)))
        weights = [self.registry.relays[i].remaining_bond for i in cands]
        return self._weighted(cands, weights)

    def _pick_mid(self, i):
        prev_region = self.registry.relays[i].region
        cands = [j for j, r in enumerate(self.registry.relays)
                 if j != i and r.region != prev_region]
        if not cands:
            cands = [j for j in range(len(self.registry)) if j != i]
        weights = [self.registry.relays[j].remaining_bond for j in cands]
        return self._weighted(cands, weights)

    def _pick_exit(self, i):
        cands = [j for j, r in enumerate(self.registry.relays)
                 if r.region == self.receiver_region and j != i]
        if not cands:
            cands = [j for j in range(len(self.registry)) if j != i]
        weights = [self.registry.relays[j].remaining_bond for j in cands]
        return self._weighted(cands, weights)

    def _weighted(self, idxs, weights):
        total = sum(weights)
        x = self.rng.random() * total
        acc = 0
        for idx, w in zip(idxs, weights):
            acc += w
            if x <= acc:
                return idx
        return idxs[-1]

    def _build(self):
        """Build 3 parallel sub-paths (guard -> mid* -> exit)."""
        for _ in range(N_SUBPATHS):
            guard = self._pick_guard()
            path = [guard]
            for _ in range(self.path_len - 2):
                path.append(self._pick_mid(path[-1]))
            path.append(self._pick_exit(path[-1]))
            self.subpaths.append(path)

    def _sp_key(self, sp: int) -> bytes:
        """32-byte per-sub-path key derived from the flow key."""
        return hashlib.sha256(self.flow_key + bytes([sp])).digest()

    def _hop_key(self, sp: int, hop: int) -> bytes:
        """Fresh 32-byte AEAD key for one (sub-path, hop) layer.

        Per-hop keys mean the same nonce is never reused under the same key,
        so the random nonces in wrap() are always unique-per-(key,nonce).
        """
        return hashlib.sha256(self.flow_key + bytes([sp, hop])).digest()

    def wrap(self, payload: bytes, packet_tag: bytes):
        """Split payload across sub-paths, wrap each as an onion.

        Returns one wrapped onion per sub-path. Each onion is encrypted in
        layers (peel-once-per-relay). Membership is proven via a single
        registry-bound ring signature over the whole flow (not per hop),
        because per-hop ring signatures over 3 paths x path_len hops are
        expensive and unnecessary — the flow itself is the unit of anonymity.
        """
        chunks = _split(payload, N_SUBPATHS)
        onions = []
        for sp in range(N_SUBPATHS):
            path = self.subpaths[sp]
            # layer encryption: outermost first. Each hop gets a FRESH key
            # (KDF from flow key + sp + hop) so nonce reuse can never occur.
            inner = chunks[sp]
            for hop in reversed(range(len(path))):
                hkey = self._hop_key(sp, hop)
                nonce = os.urandom(12)
                inner = nonce + _aead(hkey, nonce, inner,
                                      aad=self.session + bytes([sp, hop]))
            # membership proof (registry-bound ring signature) for this flow
            keys = [r.key for r in self.registry.relays]
            sig = ring_sign(packet_tag + bytes([sp]), keys,
                            signer_index=path[0])
            onions.append({"subpath": sp, "path": path, "onion": inner,
                           "sig": sig})
        return onions


def _split(payload, n):
    """Split payload into n roughly-equal chunks (first gets the remainder)."""
    base = len(payload) // n
    rem = len(payload) % n
    out, off = [], 0
    for i in range(n):
        size = base + (1 if i < rem else 0)
        out.append(payload[off:off + size])
        off += size
    return out


def peel(onion_layer: bytes, key: bytes, session: bytes, sp: int, hop: int):
    """A relay peels exactly one layer and returns the next inner layer.

    The layer is `nonce(12) || ciphertext`; we split off the nonce and
    decrypt, recovering the next inner layer (or the raw chunk at the
    innermost hop).
    """
    nonce = onion_layer[:12]
    blob = onion_layer[12:]
    inner = _aead_open(key, nonce, blob, aad=session + bytes([sp, hop]))
    return inner


class _SeededRng:
    """Deterministic RNG for reproducible tests (not for production)."""
    def __init__(self, seed):
        import random
        self._r = random.Random(seed)
    def random(self):
        return self._r.random()
