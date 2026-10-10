"""Stake-bonded relay registry, anchored to the Monero chain.

Every relay locks a refundable XMR bond to enter. The registry is a Merkle
tree over (relay_pubkey, bond_amount, region, capabilities); its root is
published on-chain (see ``anchor.py`` for the real Monero transaction that
carries it). Staking/unstaking is an on-chain event, so the set of "real"
relays is a *fact the chain records* — not an operator's claim.

This is what converts the anonymity set from "who is online right now"
(Tor's small, census-able live set) into "the entire bonded registry"
(global, persistent, and it can't be shrunk or flooded without paying XMR).
"""

import hashlib
import os
import time

from .ec import KeyPair, merkle_root, ring_sign, ring_verify

# 1 XMR = 1e6 XMR-dust units
XMR_DUST = 1_000_000


class Relay:
    """A staked relay in the bonded registry."""

    def __init__(self, key: KeyPair = None, bond_xmr: float = 100.0,
                 region: str = "us-east", bandwidth_gbps: float = 1.0,
                 storage_tb: float = 0.0, staked_at: float = None):
        self.key = key or KeyPair.random()
        self.bond_xmr = bond_xmr
        self.region = region
        self.bandwidth_gbps = bandwidth_gbps
        self.storage_tb = storage_tb
        self.staked_at = staked_at or time.time()
        self.slashed = 0.0            # XMR burned from this relay's bond
        self.served_chunks = 0        # chunks it has actually served (for slashing)
        self.malicious_events = 0

    @property
    def remaining_bond(self):
        return max(0.0, self.bond_xmr - self.slashed)

    def bond_units(self):
        return int(self.bond_xmr * XMR_DUST)

    def leaf(self):
        """Merkle leaf = H(pub | bond | region | bandwidth | storage).

        Everything the on-chain root promises to bind: the relay's public key,
        its XMR bond, its region, and its advertised capabilities. Floats are
        serialized deterministically (scaled to an integer) so the digest is
        exact and platform-independent.
        """
        h = hashlib.sha256()
        h.update(self.key.to_public_bytes())
        # bond in XMR, scaled to 1e6 sub-units (1e-6 XMR precision)
        h.update(int(round(self.bond_xmr * 1_000_000)).to_bytes(8, "big"))
        h.update(self.region.encode())
        # bandwidth and storage scaled to 1e6 sub-units of their units
        h.update(int(round(self.bandwidth_gbps * 1_000_000)).to_bytes(8, "big"))
        h.update(int(round(self.storage_tb * 1_000_000)).to_bytes(8, "big"))
        return h.digest()


class Registry:
    """The live bonded relay set + on-chain anchor."""

    def __init__(self):
        self.relays = []             # list[Relay], insertion-ordered
        self.chain_root = None       # last published on-chain root
        self.chain_height = 0        # block height of last anchor
        self.epoch = 0               # registry version counter

    # --- membership ------------------------------------------------------
    def stake(self, relay: Relay):
        self.relays.append(relay)
        self.epoch += 1

    def unstake(self, idx: int):
        self.relays.pop(idx)
        self.epoch += 1

    def __len__(self):
        return len(self.relays)

    def points(self):
        return [r.key.pub for r in self.relays]

    # --- on-chain anchor --------------------------------------------------
    def merkle_root(self):
        """The registry root published to the Monero chain (via ``anchor.py``).

        A Merkle root over the *full* relay leaf of every staked relay:
        H(pub | bond | region | bandwidth | storage). That is exactly what the
        write-up claims the on-chain anchor commits to — the relay set AND the
        XMR bonds, so a stake, unstake, bond change, or region change moves
        the root.
        """
        if not self.relays:
            return b"\x00" * 32
        return merkle_root([r.leaf() for r in self.relays])

    def publish_to_chain(self, height: int):
        """Record the current registry root on the Monero chain.

        In the reference build this stores the root + height in-process;
        ``anchor.py`` produces the actual transaction bytes that carry the
        root to a real node.
        """
        self.chain_root = self.merkle_root()
        self.chain_height = height
        return self.chain_root

    def is_anchored(self, height: int):
        """True if the registry's root is provable on-chain at/before `height`."""
        return self.chain_root is not None and height >= self.chain_height

    # --- membership proof / membership signing ---------------------------
    def membership_sign(self, idx: int, packet_tag: bytes):
        """Ring-sign a packet hop as registry member `idx` (anon to observer).

        The signature binds to the registry's FULL on-chain root (the Merkle
        root over pub | bond | region | capabilities), so a valid hop proof is
        tied to the exact registry state — including the XMR bonds — that is
        currently anchored on-chain.
        """
        keys = [r.key for r in self.relays]
        return ring_sign(packet_tag, keys, signer_index=idx,
                         root=self.merkle_root())

    def verify_hop(self, sig: dict):
        """Verify a packet hop is signed by SOME staked relay (anon).

        Rebinds against the current full registry root, so a hop signed for an
        older registry version (different bond set) does not verify.
        """
        return ring_verify(sig, self.points(), root=self.merkle_root()) is True

    # --- economics --------------------------------------------------------
    def total_bond(self):
        return sum(r.remaining_bond for r in self.relays)

    def total_stake_weight(self):
        """Stake-weighted pool (pro-rata yield denominator)."""
        return sum(r.remaining_bond for r in self.relays)

    def slash(self, idx: int, amount_xmr: float, reason: str):
        """Burn `amount` of a relay's bond (refund lost). Returns XMR burned."""
        r = self.relays[idx]
        burn = min(amount_xmr, r.remaining_bond)
        r.slashed += burn
        r.malicious_events += 1
        return burn

    def full_registry_snapshot(self):
        """Serializable state for a 'here is the whole registry' dump."""
        return {
            "epoch": self.epoch,
            "chain_root": self.chain_root.hex() if self.chain_root else None,
            "chain_height": self.chain_height,
            "relay_count": len(self.relays),
            "total_bond_xmr": round(self.total_bond(), 2),
            "regions": sorted({r.region for r in self.relays}),
            "relays": [
                {
                    "pub": r.key.to_public_bytes().hex()[:32] + "...",
                    "bond_xmr": r.bond_xmr,
                    "remaining_bond": round(r.remaining_bond, 2),
                    "region": r.region,
                    "bandwidth_gbps": r.bandwidth_gbps,
                    "storage_tb": r.storage_tb,
                }
                for r in self.relays
            ],
        }
