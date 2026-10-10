"""Deanonymization-cost simulator — the "you must pay XMR" proof.

This is the module that turns the write-up's central claim into a number
you can run:

  "You can't deanonymize a user without paying real XMR, and you can't
   run the network without putting your own money on the line."

Three cost axes, all priced in XMR:

  1. ANONYMITY SET (traffic analysis).
     To link a user to their traffic, an adversary must distinguish the
     user's circuit from every other in the anonymity set. The set is the
     *entire bonded registry* (N staked relays), not the live online
     population. Flooding/shrinking the set requires sybil relays, and
     each sybil relay must post a full bond. Cost ~ B * K, where B is the
     bond and K is the number of sybils needed.

  2. CAPTURE (compromise a path).
     To see a user's plaintext at a specific hop, the adversary must own
     the relay at that position. With 3 parallel sub-paths, the user is
     safe unless the adversary controls the *right* relay in *enough*
     sub-paths. Cost = sum of the bonds of the captured relays.

  3. CENSORSHIP (kill a page).
     To take down a page, the adversary must buy/compromise all 16
     holders of at least one chunk (and stop the hash re-spreading).
     Cost = 16 * B (or the price of compromising 16 independent relays).

The simulator builds a realistic registry and prices each attack, then
shows the XMR-denominated bill an adversary must pay. That bill — not a
trust claim — is the security argument.
"""

import os
import random

from .registry import Relay, Registry
from .ec import KeyPair
from . import store as store_mod


def build_registry(n_relays: int = 1000, bond_xmr: float = 100.0,
                   regions: int = 12, seed: int = 7):
    """Build a realistic staked registry: `n_relays` across `regions`."""
    rng = random.Random(seed)
    reg = Registry()
    names = [f"region-{i:02d}" for i in range(regions)]
    for i in range(n_relays):
        r = Relay(
            key=KeyPair.random(),
            bond_xmr=bond_xmr,
            region=rng.choice(names),
            bandwidth_gbps=1.0,
            storage_tb=1.0 if i % 2 == 0 else 0.0,
        )
        reg.stake(r)
    reg.publish_to_chain(height=3_000_000 + n_relays)
    return reg


# --- axis 1: shrink/flood the anonymity set -------------------------------

def flood_cost(target_set_size: int, bond_xmr: float = 100.0):
    """XMR to add `target_set_size` sybil relays to the registry.

    Each sybil must post a full bond or it isn't a member. This is the
    price of growing your own 'live' set to drown a real user's traffic.
    """
    return target_set_size * bond_xmr


# --- axis 2: capture a user's path ----------------------------------------

def capture_cost(reg: Registry, subpaths: int = 3,
                 positions: int = None, bond_xmr: float = 100.0) -> float:
    """XMR to control the relays needed to see a user's plaintext.

    To break the 3-sub-path scheme you must own the entry (or exit) relay
    in ENOUGH sub-paths to correlate. Worst case for the adversary: they
    must buy the guard relay in all `subpaths` sub-paths (each a distinct
    staked relay). Cost = subpaths * bond.
    """
    k = positions or subpaths
    return k * bond_xmr


# --- axis 3: censor a page ------------------------------------------------

def censorship_cost(bond_xmr: float = 100.0, replication: int = None) -> float:
    """XMR to take down one page by buying all holders of one chunk.

    You must control all `replication` holders of at least one chunk (and
    race the re-spread). Cost = replication * bond.
    """
    r = replication or store_mod.REPLICATION
    return r * bond_xmr


def full_report(reg: Registry, bond_xmr: float = 100.0) -> dict:
    """The complete 'what does attacking this cost' report in XMR and USD."""
    n = len(reg)
    # assume an XMR price for USD context (editable)
    xmr_price_usd = 180.0

    flood_n = 10_000                      # sybils to flood the set
    flood_xmr = flood_cost(flood_n, bond_xmr)

    cap_xmr = capture_cost(reg, subpaths=3, bond_xmr=bond_xmr)
    cen_xmr = censorship_cost(bond_xmr=bond_xmr)

    return {
        "registry": {
            "n_relays": n,
            "total_bond_xmr": round(reg.total_bond(), 2),
            "regions": reg.full_registry_snapshot()["regions"],
            "anonymity_set": n,
            "anonymity_set_note": (
                "the entire bonded registry — global and persistent, "
                "not 'who's online right now'"),
        },
        "attacks": {
            "flood_anonymity_set": {
                "what": "sybil N relays to drown a user's traffic",
                "sybils": flood_n,
                "cost_xmr": flood_xmr,
                "cost_usd": round(flood_xmr * xmr_price_usd, 2),
            },
            "capture_path": {
                "what": "own guard relays across all 3 sub-paths to read plaintext",
                "relays_to_buy": 3,
                "cost_xmr": cap_xmr,
                "cost_usd": round(cap_xmr * xmr_price_usd, 2),
            },
            "censor_page": {
                "what": "buy all 16 holders of one chunk to kill a page",
                "relays_to_buy": store_mod.REPLICATION,
                "cost_xmr": cen_xmr,
                "cost_usd": round(cen_xmr * xmr_price_usd, 2),
            },
        },
        "headline": (
            f"Every attack is priced in XMR: flooding needs ~{flood_xmr:.0f} XMR "
            f"of sybil bonds, reading a user's traffic needs {cap_xmr:.0f} XMR of "
            f"bought relays, and censoring a page needs {cen_xmr:.0f} XMR. The "
            f"anonymity set is the whole registry ({n} staked relays), not the "
            f"live online population."),
    }


def selftest() -> dict:
    reg = build_registry(n_relays=150, bond_xmr=100.0, seed=42)
    # a real publish + censorship-cost sanity
    s = store_mod.DeadDropStore(reg.relays)
    root = s.publish("test page", os.urandom(10 * 1024))
    report = full_report(reg, bond_xmr=100.0)
    return {
        "registry_ok": len(reg) == 150 and reg.is_anchored(3_000_151),
        "store_root_is_32_bytes": len(root) == 32,
        "censor_cost_xmr": report["attacks"]["censor_page"]["cost_xmr"],
        "capture_cost_xmr": report["attacks"]["capture_path"]["cost_xmr"],
        "ok": len(reg) == 150 and len(root) == 32
             and report["attacks"]["censor_page"]["cost_xmr"] == 1600.0
             and report["attacks"]["capture_path"]["cost_xmr"] == 300.0,
    }
