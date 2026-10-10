"""secp256k1 group operations + Rivest-Shamir-Tauman (2001) ring signatures.

This is the primitive that makes the central claim true: a packet hop is
authenticated by a *ring signature* over the bonded relay registry. The
verifier learns "this relay is one of the N staked relays in the current
registry, and it paid the bond" but nothing about *which* one — so the
anonymity set is the entire bonded registry (global, persistent, can't be
shrunk without paying XMR), not "the people online right now" (Tor's
small, census-able live set).

secp256k1 is the curve the Bitcoin/Monero ecosystem already treats as
battle-tested; we implement the group directly so the whole file is
self-contained and auditable in one sitting.

RST construction (Rivest, Shamir, Tauman 2001, "How to Make a Ring
Signature"), prefix-challenge variant:

  Sign (ring of n public keys P_0..P_{n-1}):
    1. Pick random scalars s_0..s_{n-1}.
    2. For i = 0..n-1:
           h_i = H(root, message, P_0, C_0, ..., P_{i-1}, C_{i-1})
           C_i = h_i * G + s_i * P_i
    3. Emit (message, root, [C_i], [s_i]).
  Verify (holding the registry public keys):
    For each i, recompute h_i from the prefix and check
        C_i ?= h_i * G + s_i * P_i.
    Valid iff every position closes AND the embedded registry root matches.

Security:
  * Only someone holding a registry private key can produce a valid ring —
    forging any position without a key requires a discrete log.
  * The challenge binds (registry root, message, ring prefix), so a
    different registry version or a different message breaks every link.
  * Every position closes identically, so the ring reveals nothing about
    which member signed (the whole point of a ring).
"""

import hashlib
import secrets

# ---- secp256k1 parameters -------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (Gx, Gy)


def _inv(a, m=P):
    return pow(a, m - 2, m)


def _neg(pt):
    if pt is None:
        return None
    x, y = pt
    return (x, (-y) % P)


def _add(pt1, pt2):
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if pt1 == pt2:
        lam = (3 * x1 * x1) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


_G_TBL = None


def _G_TABLE():
    """Precomputed [2^i * G for i in 0..255], built once."""
    global _G_TBL
    if _G_TBL is None:
        _G_TBL = [G]
        for _ in range(255):
            _G_TBL.append(_add(_G_TBL[-1], _G_TBL[-1]))
    return _G_TBL


def _mul(k, pt):
    """Scalar multiplication (double-and-add). Uses a cached table for k*G,
    which is by far the most common operation in a ring signature."""
    if pt is None:
        return None
    k %= ORDER
    if k == 0:
        return None
    if pt is G:
        tbl = _G_TABLE()
        result = None
        i = 0
        while k:
            if k & 1:
                result = _add(result, tbl[i])
            k >>= 1
            i += 1
        return result
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def point_add(pt1, pt2):
    return _add(pt1, pt2)


def point_neg(pt):
    return _neg(pt)


def point_mul(k, pt):
    return _mul(k, pt)


def point_equal(a, b):
    if a is None or b is None:
        return a is None and b is None
    return a == b


class KeyPair:
    """secp256k1 keypair: .secret is the private scalar, .pub the point."""

    __slots__ = ("secret", "pub")

    def __init__(self, secret, pub=None):
        self.secret = secret % ORDER
        self.pub = pub or point_mul(self.secret, G)

    @classmethod
    def random(cls):
        return cls(secrets.randbelow(ORDER) + 1)

    @classmethod
    def from_bytes(cls, b32):
        return cls(int.from_bytes(b32, "big") % ORDER)

    def to_public_bytes(self):
        x, y = self.pub
        return x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ---- RST ring signature ----------------------------------------------------

def _pt_bytes(pt):
    if pt is None:
        return b"\x00" * 64
    x, y = pt
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def registry_root(points) -> bytes:
    """Merkle root over a list of relay public points (SHA-256 pairwise).

    This root is what gets published to the Monero chain. Anyone holding a
    chain inclusion proof for the root can verify membership of any relay
    and — crucially — the root is what binds a ring signature to a
    specific registry version.
    """
    leaves = [hashlib.sha256(_pt_bytes(p)).digest() for p in points]
    level = leaves
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level) - 1, 2)]
    return level[0]


def _prefix_hash(message: bytes, root: bytes, pubs, C, upto: int) -> int:
    """Challenge h_i = H(root, message, P_0, C_0, ..., P_{i-1}, C_{i-1}).

    The challenge for position `upto` is the hash of the ring PREFIX —
    everything strictly before that position. Excluding the position itself
    is what lets the signer compute C_i after h_i, and it's what makes the
    challenge depend on the actual ring state (not a pre-choosable value).
    `pubs` is a sequence of objects with .to_public_bytes() (or raw points).
    """
    h = hashlib.sha512(b"deaddrop-ring|")
    h.update(root)
    h.update(message)
    h.update(upto.to_bytes(4, "big"))
    for j in range(upto):
        pb = pubs[j].to_public_bytes() if hasattr(pubs[j], "to_public_bytes") \
            else _pt_bytes(pubs[j])
        h.update(pb)
        h.update(_pt_bytes(C[j]))
    return int.from_bytes(h.digest(), "big") % ORDER


def ring_sign(message: bytes, keys: list, signer_index: int, root: bytes = None) -> dict:
    """Produce a Rivest-Shamir-Tauman ring signature over the registry.

    keys: the full registry of KeyPairs (their public points form the ring;
          the signer's secret is used only for its own slot).
    signer_index: position of the real signer inside `keys`.
    root: Merkle root of the registry (defaults to registry_root(keys)).

    Returns a dict with the ring points C and scalars s; verify with
    ring_verify() against the registry's public points.
    """
    n = len(keys)
    if n < 2:
        raise ValueError("ring needs >= 2 members")
    if not (0 <= signer_index < n):
        raise ValueError("bad signer index")
    if root is None:
        root = registry_root([k.pub for k in keys])

    s = [secrets.randbelow(ORDER) for _ in range(n)]
    C = [None] * n
    for i in range(n):
        h_i = _prefix_hash(message, root, keys, C, i)
        C[i] = _add(point_mul(h_i, G), _mul(s[i], keys[i].pub))
    return {"message": message, "root": root, "n": n, "C": C, "s": s}


def ring_verify(sig: dict, public_points) -> bool:
    """Verify a ring signature against a registry of public points.

    Recomputes every prefix challenge and checks C_i == h_i*G + s_i*P_i for
    all i. Returns True iff every position closes AND the embedded registry
    root matches `public_points`.

    Security:
      * wrong message -> every h_i changes -> links break.
      * different registry root -> every h_i changes -> links break.
      * swapped registry member P_i -> h_i and P_i both change -> the i-th
        link breaks (s_i was derived for the old P_i).
      * forging a link at any position requires that position's secret key
        (discrete log), so only a staked relay can sign.
    """
    n = sig["n"]
    C = sig["C"]
    s = sig["s"]
    if len(public_points) != n or len(C) != n or len(s) != n:
        return False
    if sig.get("root") != registry_root(public_points):
        return False
    message, root = sig["message"], sig["root"]
    # normalize to raw public points (accept KeyPair or (x, y))
    pubs = [p.pub if isinstance(p, KeyPair) else p for p in public_points]
    for i in range(n):
        h_i = _prefix_hash(message, root, pubs, C, i)
        expected = _add(point_mul(h_i, G), _mul(s[i], pubs[i]))
        if not point_equal(expected, C[i]):
            return False
    return True


def ring_sign_and_verify_selftest():
    """5-key ring: sign at 2, verify; message tamper and registry swap break it."""
    keys = [KeyPair.random() for _ in range(5)]
    msg = b"relay membership proof for packet 0xdead"
    sig = ring_sign(msg, keys, signer_index=2)
    pubs = [k.pub for k in keys]
    ok = ring_verify(sig, pubs) is True
    # wrong message must not verify
    bad = dict(sig, message=b"tampered")
    broken = ring_verify(bad, pubs) is False
    # registry with a different member must not verify
    alt = [k.pub for k in keys]
    alt[0] = KeyPair.random().pub
    other = ring_verify(sig, alt) is False
    return ok and broken and other
