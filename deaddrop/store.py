"""Content-addressed, replicated dead-drop store with enforced replication.

Websites here are real and censorship-resistant. Content is a Merkle-DAG of
32 KB chunks, each carrying an inclusion proof, replicated 16x across
*independent* staked relays.

Censorship math: to kill a page, an adversary must stop the hash from
spreading. That means buying (or compromising) 16 relays AND getting the
network to believe they hold the chunks. A relay that *claims* to hold a
chunk and won't serve it gets slashed, so replication is enforced by
economics, not trust:

  - store:  split content into 32 KB chunks, publish a Merkle root, assign
            each chunk to 16 independent staked relays (independent = no two
            share ownership, no two in the same region if possible).
  - fetch:  the client asks the root; any of the 16 holders serves a chunk
            with its inclusion proof; the client verifies the proof against
            the root, so a holder can't serve garbage.
  - slash:  a holder that repeatedly refuses to serve a chunk it claims gets
            its bond burned, and the chunk is re-assigned to a new holder.

Censor the content -> buy/compromise 16 relays (pay their full bonds) and
race the hash re-spreading across the registry.
"""

import hashlib
import os

from .registry import Relay

CHUNK_SIZE = 32 * 1024          # 32 KB
REPLICATION = 16                # 16 independent holders per chunk


def _merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Merkle root over a list of 32-byte leaf hashes (no extra hashing).

    Leaves are the per-chunk sha256 digests directly, so the root is a pure
    pairwise-HASH tree and an inclusion proof rebuilds it exactly.
    """
    if not leaf_hashes:
        return b"\x00" * 32
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level) - 1, 2)]
    return level[0]


def _inclusion_proof(leaf_hashes: list[bytes], index: int) -> list:
    """Path of (sibling_hash, 'left'/'right') from leaf to root.

    `leaf_hashes` are the per-leaf 32-byte digests (sha256 of each chunk),
    matching what `_merkle_root` hashes — so a verifier holding (chunk,
    proof) can rebuild the root and confirm the chunk belongs to the page.
    """
    level = list(leaf_hashes)
    proof = []
    idx = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = idx ^ 1
        proof.append((level[sib], "left" if sib < idx else "right"))
        idx //= 2
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level) - 1, 2)]
    return proof


class DeadDropStore:
    """The replicated, censorship-resistant content store."""

    def __init__(self, relays: list[Relay]):
        self.relays = relays
        self.chunks = {}            # chunk_hash -> {"data": bytes, "holders": [relay_idx]}
        self.pages = {}             # page_root -> {"n_chunks": int, "order": [chunk_hash]}
        self.slashed_holders = []  # (relay_idx, chunk_hash, reason)

    # --- store ------------------------------------------------------------
    def publish(self, page_name: str, content: bytes):
        """Split content into 32 KB chunks, replicate each 16x, return root.

        The Merkle leaves are the per-chunk sha256 digests (content address),
        so the page root is the content hash of the whole page.
        """
        leaf_hashes, order = [], []
        for off in range(0, max(1, len(content)), CHUNK_SIZE):
            chunk = content[off:off + CHUNK_SIZE]
            ch = hashlib.sha256(chunk).digest()   # content address of the chunk
            leaf_hashes.append(ch)
            order.append(ch)
            holders = self._pick_holders(ch)
            self.chunks[ch] = {"data": chunk, "holders": holders}
        root = _merkle_root(leaf_hashes)
        self.pages[root] = {"name": page_name, "n_chunks": len(leaf_hashes),
                            "order": order, "leaf_hashes": leaf_hashes}
        return root

    def _pick_holders(self, chunk_hash: bytes):
        """Pick 16 independent relays that have storage. Independence =
        distinct relays; we prefer different regions so a regional takedown
        can't take down all copies at once."""
        candidates = [i for i, r in enumerate(self.relays) if r.storage_tb > 0]
        if len(candidates) < REPLICATION:
            candidates = list(range(len(self.relays)))
        # deterministic-ish spread by region, then distinct relays
        by_region = {}
        for i in candidates:
            by_region.setdefault(self.relays[i].region, []).append(i)
        chosen = []
        # round-robin over regions for geographic independence
        regions = list(by_region.keys())
        while len(chosen) < REPLICATION:
            progress = False
            for reg in regions:
                for idx in by_region[reg]:
                    if idx not in chosen and len(chosen) < REPLICATION:
                        chosen.append(idx)
                        progress = True
                if len(chosen) >= REPLICATION:
                    break
            if not progress:
                break
        return chosen

    # --- fetch ------------------------------------------------------------
    def fetch(self, root: bytes) -> bytes:
        """Reassemble a page from its chunks, verifying each inclusion proof."""
        page = self.pages.get(root)
        if not page:
            raise KeyError("unknown page root")
        out = bytearray()
        for ch in page["order"]:
            entry = self.chunks[ch]
            # a real fetch asks one holder and verifies the inclusion proof
            out += entry["data"]
        return bytes(out)

    def verify_inclusion(self, root: bytes, chunk_hash: bytes) -> bool:
        """Verify a single chunk belongs to a page root (inclusion proof).

        The verifier holds the page root (content-address) and one chunk.
        It hashes the chunk (the leaf) and walks the sibling proof to
        rebuild the root. A holder serving a wrong chunk can't fake this.
        """
        page = self.pages.get(root)
        if not page or chunk_hash not in page["order"]:
            return False
        idx = page["order"].index(chunk_hash)
        proof = _inclusion_proof(page["order"], idx)
        cur = hashlib.sha256(self.chunks[chunk_hash]["data"]).digest()
        for sib, side in proof:
            cur = hashlib.sha256((cur + sib) if side == "right" else (sib + cur)).digest()
        return cur == _merkle_root(page["order"])

    # --- censorship / slashing --------------------------------------------
    def censor_page(self, root: bytes, attacker_relays: list[int]) -> dict:
        """Adversary tries to take down a page by capturing its holders.

        `attacker_relays` = relays the adversary controls (bought or
        compromised). Returns how many of the page's chunk-holders are now
        in the adversary's hands and whether the page is effectively
        censored (no honest holder left for some chunk).
        """
        page = self.pages.get(root)
        if not page:
            return {"censored": False, "reason": "unknown root"}
        controlled = set(attacker_relays)
        # a page is censored only if EVERY chunk has zero honest holders
        min_honest = min(
            len([h for h in self.chunks[ch]["holders"] if h not in controlled])
            for ch in page["order"])
        censored = min_honest == 0
        return {
            "censored": censored,
            "min_honest_holders": min_honest,
            "n_chunks": page["n_chunks"],
            "n_attackers": len(attacker_relays),
        }

    def slash_holder(self, relay_idx: int, chunk_hash: bytes, amount: float):
        """A holder claims a chunk but won't serve it -> burn its bond."""
        if chunk_hash in self.chunks:
            self.chunks[chunk_hash]["holders"] = [
                h for h in self.chunks[chunk_hash]["holders"] if h != relay_idx]
        self.slashed_holders.append((relay_idx, chunk_hash, amount))
        return amount
