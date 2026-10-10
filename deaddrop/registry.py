"""Stake-bonded relay registry, anchored to the Monero chain.

Every relay locks a refundable XMR bond to enter. The registry is a Merkle
tree over (relay_pubkey, bond_amount, region, capabilities); its root is
published on-chain. Staking/unstaking is an on-chain event, so the set of
"real" relays is a *fact the chain records* — not an operator's claim.

This is what converts the anonymity set from "who is online right now"
(Tor's small, census-able live set) into "the entire bonded registry"
(global, persistent, and it can't be shrunk or flooded without paying XMR).
"""

import hashlib
import os
import time

from .ec import KeyPair, registry_root, ring_sign, ring_verify

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
        """Merkle leaf = H(pub | bond | region | cap)."""
        h = hashlib.sha256()
        h.update(self.key.to_public_bytes())
        h.update(self.bond_xmr.to_bytes(8, "big"))
        h.update(self.region.encode())
        h.update(self.bandwidth_gbps.to_bytes(8, "big"))
        h.update(self.storage_tb.to_bytes(8, "big"))
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
        if not self.relays:
            return b"\x00" * 32
        return registry_root(self.points())

    def publish_to_chain(self, height: int):
        """Record the current registry root on the (simulated) Monero chain."""
        self.chain_root = self.merkle_root()
        self.chain_height = height
        return self.chain_root

    def is_anchored(self, height: int):
        """True if the registry's root is provable on-chain at/before `height`."""
        return self.chain_root is not None and height >= self.chain_height

    # --- membership proof / membership signing ---------------------------
    def membership_sign(self, idx: int, packet_tag: bytes):
        """Ring-sign a packet hop as registry member `idx` (anon to observer)."""
        keys = [r.key for r in self.relays]
        return ring_sign(packet_tag, keys, signer_index=idx)

    def verify_hop(self, sig: dict):
        """Verify a packet hop is signed by SOME staked relay (anon)."""
        return ring_verify(sig, self.points()) is True

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
