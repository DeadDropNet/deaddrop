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

RST ring signature (Rivest, Shamir, Tauman 2001, "How to Make a Ring
Signature"), implemented as a *cyclic* challenge chain in the CryptoNote /
Monero style (which is what a Monero-anchored network would actually use).
A commitment V_i and a response s_i are chained around a circle; the chain
only closes on itself if the real signer spends their secret key once:

  Sign (ring of n public keys P_0..P_{n-1}), signer is index `pi`:
    1. Pick a fresh nonce u. Seed the ring at the signer's own slot:
           V_seed = u * G
       and take the challenge that follows it as the seed of the circle:
           c_seed = H(root, message, V_seed)
       (This challenge lands at index j = pi+1 mod n.)
    2. Walk the ring from j back around to pi, faking every non-signer slot:
           s_i  = random
           V_i  = s_i * G + c_i * P_i
           c_{i+1} = H(root, message, V_i)          (indices mod n)
    3. Close the circle at the signer. The challenge that arrives back at pi
       is now fixed; choose the signer's response so their slot matches the
       seed commitment:
           s_pi = u - k_pi * c_pi        (mod ORDER),  where P_pi = k_pi * G
       Then V_pi = s_pi*G + c_pi*P_pi = u*G - k_pi*c_pi*G + c_pi*P_pi
                = u*G - c_pi*P_pi + c_pi*P_pi = u*G,
       exactly the seed — so the chain returns to itself.
    4. Emit (message, root, n, c0, [V_i], [s_i]) where c0 = the challenge
       entering index 0.
  Verify (holding the registry public points + the registry root):
    Start c = c0. For each i = 0..n-1: check V_i == s_i*G + c*P_i, then
    c = H(root, message, V_i). Valid iff after the full circle c == c0 AND
    the embedded registry root matches.

Why this is a real ring (and the difference from a naive "prefix hash"):
  * Each c_{i+1} is derived from V_i, and V_i depends on c_i — a genuine
    cycle. A valid signature exists iff the product of all links composes to
    the identity. A non-signer can only pick *random* s_i, so with
    overwhelming probability the circle does NOT close.
  * Only a holder of a registry secret key can close it: they set their own
    s_pi so their link is consistent, absorbing the mismatch the random links
    elsewhere leave behind.
  * The registry root is bound into every challenge, so a different message,
    a different registry version, or a swapped member P_i breaks the circle.

Security:
  * Forging a valid ring without any registry secret key requires inverting
    the challenge hash or solving a discrete log — i.e. the attacker must
    hold a staked relay's key. That's the whole "you must pay XMR" claim.
  * Every position is indistinguishable, so the ring reveals nothing about
    which member signed (the anonymity set is the whole bonded registry).
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


def merkle_root(leaves) -> bytes:
    """Merkle root over a list of 32-byte leaf digests (SHA-256 pairwise).

    Odd-sized levels duplicate the last leaf so every level pairs up cleanly.
    Returns 32 bytes. This is the generic pairwise-HASH tree used for both
    the relay-registry root and the content-store root.
    """
    if not leaves:
        return b"\x00" * 32
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level) - 1, 2)]
    return level[0]


def registry_root(points) -> bytes:
    """Merkle root over relay public points (the anonymity-set root).

    This is the root a ring signature binds to when it is produced over a
    bare list of public points (e.g. in the unit tests). A full relay registry
    uses the richer root in registry.Registry.merkle_root(), which also binds
    each relay's bond, region, and capabilities — that is the value published
    to the Monero chain. Both change whenever the relay set changes, which is
    what pins a ring signature to a specific registry version.
    """
    return merkle_root([hashlib.sha256(_pt_bytes(p)).digest() for p in points])


def _challenge(message: bytes, root: bytes, V) -> int:
    """Next challenge c = H(root, message, V_i) in [0, ORDER).

    Binding the registry `root` into every challenge is what pins the ring to
    a specific registry version AND ordering: `root` is a Merkle root over the
    full list of relay public points, so any stake, unstake, or member swap
    changes `root`, changes every challenge, and breaks the circle. `V` is the
    commitment at the position being hashed. (The registry root already binds
    every public key, so hashing each P_i separately would be redundant.)
    """
    h = hashlib.sha512(b"deaddrop-ring|")
    h.update(root)
    h.update(message)
    h.update(_pt_bytes(V))
    return int.from_bytes(h.digest(), "big") % ORDER


def ring_sign(message: bytes, keys: list, signer_index: int, root: bytes = None) -> dict:
    """Produce a Rivest-Shamir-Tauman ring signature over the registry.

    keys: the full registry of KeyPairs (their public points form the ring;
          the signer's secret is used only for its own slot).
    signer_index: position of the real signer inside `keys` — the one ring
          member whose response is derived from a real secret key.
    root: Merkle root of the registry (defaults to registry_root(keys)).

    CryptoNote/LSAG-style circular ring. Commitments V_i = s_i*G + c_i*P_i
    are chained by c_{i+1} = H(root, message, V_i) until the chain returns to
    itself. The signer seeds the ring just after their own slot with a fresh
    nonce (V = u*G), walks the circle faking every other slot with random
    responses, then closes the loop by choosing their own response from their
    secret key so their slot is consistent with the seed.

    The emitted `c0` is the challenge entering index 0, so a verifier walking
    0..n-1 and closing back to c0 accepts exactly the signatures a real signer
    can produce — and rejects everything else (wrong message, wrong registry,
    or a forgery that holds no registry secret key).
    """
    n = len(keys)
    if n < 2:
        raise ValueError("ring needs >= 2 members")
    if not (0 <= signer_index < n):
        raise ValueError("bad signer index")
    if root is None:
        root = registry_root([k.pub for k in keys])

    # 1) Seed the ring just after the real signer with a fresh nonce u.
    u = secrets.randbelow(ORDER)
    c = [None] * n
    s = [None] * n
    V = [None] * n
    j = (signer_index + 1) % n
    V[signer_index] = _mul(u, G)                       # the seed commitment
    c[j] = _challenge(message, root, V[signer_index])  # first real challenge

    # 2) Walk the ring, faking every non-signer slot with a random response.
    i = j
    while i != signer_index:
        s[i] = secrets.randbelow(ORDER)
        V[i] = _add(_mul(s[i], G), _mul(c[i], keys[i].pub))
        c[(i + 1) % n] = _challenge(message, root, V[i])
        i = (i + 1) % n

    # 3) Close the loop at the signer: V[pi] = s[pi]*G + c[pi]*P[pi] must equal
    #    the seed u*G, so  s[pi] = u - secret*c[pi]  (mod ORDER).
    s[signer_index] = (u - keys[signer_index].secret * c[signer_index]) % ORDER
    V[signer_index] = _add(_mul(s[signer_index], G),
                           _mul(c[signer_index], keys[signer_index].pub))

    return {"message": message, "root": root, "n": n,
            "c0": c[0], "V": V, "s": s}


def ring_verify(sig: dict, public_points, root: bytes = None) -> bool:
    """Verify a ring signature against a registry of public points.

    Walks the challenge chain from the stored starting challenge c0 over
    indices 0..n-1, recomputing V_i = s_i*G + c_i*P_i at each position and the
    next challenge from it. Valid iff the chain closes back to c0 AND the
    root the signature was bound to matches the authoritative `root` — which
    also pins the ring to the current registry version, so a replay against a
    different registry fails.

    `root` is the authoritative registry root to check against. When omitted
    it defaults to the root over the given public points (the anonymity-set
    root), which is correct for bare-point verification. The live registry
    passes its FULL on-chain root (pub | bond | region | capabilities), so a
    hop is tied to the exact anchored state — including the XMR bonds.

    Security:
      * wrong message -> every challenge changes -> the circle won't close.
      * different registry root -> every challenge changes -> won't close.
      * swapped registry member P_i -> its commitment and challenge change.
      * closing the circle at any position requires that position's secret
        key (discrete log), so only a staked relay can sign.
    """
    n = sig["n"]
    V = sig.get("V", sig.get("C"))
    s = sig["s"]
    if V is None or len(public_points) != n or len(V) != n or len(s) != n:
        return False
    if sig.get("c0") is None:
        return False
    # normalize to raw public points (accept KeyPair or (x, y))
    pubs = [p.pub if isinstance(p, KeyPair) else p for p in public_points]
    # the authoritative root to bind to: full registry root if provided, else
    # the root over these exact public points
    authoritative = registry_root(pubs) if root is None else root
    if sig.get("root") != authoritative:
        return False
    message, root_used = sig["message"], sig["root"]
    c = sig["c0"]
    for i in range(n):
        expected = _add(_mul(s[i], G), _mul(c, pubs[i]))
        if not point_equal(V[i], expected):
            return False
        c = _challenge(message, root_used, V[i])
    # the cycle must return to the emitted starting challenge
    return c == sig["c0"]


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
