"""Test suite for the Deaddrop reference implementation.

Run:  python -m pytest tests/ -q     (or)  python tests/test_all.py

Each test maps to a specific claim in the public write-up, so passing the
suite is a direct check that the claims are backed by working code.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deaddrop import ec, registry as reg_mod, circuit as circ, mixnet as mix
from deaddrop import postquant as pq, cell as cell_mod, store as store_mod, sim as sim_mod


# ---- ec.py : ring signatures + registry anchor ---------------------------

def test_ring_signature_core():
    """Claim: a hop is signed 'I am a staked relay', never 'I am relay #42'."""
    assert ec.ring_sign_and_verify_selftest() is True

def test_ring_signature_binds_to_registry():
    """Claim: the signature can't be replayed against a different registry."""
    keys = [ec.KeyPair.random() for _ in range(8)]
    sig = ec.ring_sign(b"hop", keys, 3)
    pubs = [k.pub for k in keys]
    assert ec.ring_verify(sig, pubs) is True
    pubs[5] = ec.KeyPair.random().pub
    assert ec.ring_verify(sig, pubs) is False

def test_registry_root_stable_and_changes_on_stake():
    reg = reg_mod.Registry()
    for _ in range(5):
        reg.stake(reg_mod.Relay())
    r1 = reg.merkle_root()
    reg.stake(reg_mod.Relay())
    assert reg.merkle_root() != r1
    assert len(r1) == 32


# ---- registry.py : stake-bonded, on-chain-anchored -----------------------

def test_stake_unstake_and_bond():
    reg = reg_mod.Registry()
    a = reg_mod.Relay(bond_xmr=500.0)
    reg.stake(a)
    assert reg.total_bond() == 500.0
    reg.slash(0, 200.0, "malicious relay")
    assert reg.relays[0].remaining_bond == 300.0

def test_on_chain_anchor():
    reg = reg_mod.Registry()
    for _ in range(3):
        reg.stake(reg_mod.Relay())
    reg.publish_to_chain(height=100)
    assert reg.is_anchored(100)
    assert not reg.is_anchored(99)

def test_membership_sign_verify():
    reg = reg_mod.Registry()
    for _ in range(6):
        reg.stake(reg_mod.Relay())
    sig = reg.membership_sign(2, b"packet")
    assert reg.verify_hop(sig) is True


# ---- circuit.py : Sphinx + 3 sub-paths + guard committee ------------------

def test_circuit_three_subpaths():
    reg = _sample_registry()
    c = circ.Circuit(reg, "region-00", "region-03", seed=1)
    assert len(c.subpaths) == circ.N_SUBPATHS
    for path in c.subpaths:
        assert len(path) == c.path_len
        # guard is from the sender's region, exit from the receiver's
        assert reg.relays[path[0]].region == "region-00"
        assert reg.relays[path[-1]].region == "region-03"

def test_wrap_and_reassemble():
    reg = _sample_registry()
    c = circ.Circuit(reg, "region-00", "region-03", seed=2)
    payload = os.urandom(300)
    onions = c.wrap(payload, b"tag")
    assert len(onions) == 3
    # peel each onion layer by layer, then reassemble the 3 inner chunks
    inner_chunks = []
    for sp in range(3):
        onion = onions[sp]["onion"]
        for hop in range(len(c.subpaths[sp])):
            onion = circ.peel(onion, c._hop_key(sp, hop), c.session, sp, hop)
        inner_chunks.append(onion)
    # reassembling in sub-path order must equal the original payload
    assert b"".join(inner_chunks) == payload
    # the membership ring signature on each onion verifies against the registry
    for o in onions:
        assert c.registry.verify_hop(o["sig"]) is True

def test_guard_is_staked():
    """Claim: entry/exit are staked relays (not arbitrary peers)."""
    reg = _sample_registry()
    c = circ.Circuit(reg, "region-00", "region-03", seed=3)
    for path in c.subpaths:
        for idx in path:
            assert reg.relays[idx].bond_xmr > 0


# ---- mixnet.py : shape hiding --------------------------------------------

def test_mixnet_shape_indistinguishable():
    res = mix.shape_test(n_real=40, seed=1337)
    assert res["indistinguishable"] is True
    assert res["active_cells"] == res["target_cells"]
    assert res["silent_cells"] == res["target_cells"]

def test_mixnet_padding_to_target():
    m = mix.MixNode(batch_ms=250.0, target_cells_per_batch=64)
    m.add(os.urandom(32), 10.0)
    out = m.release(0)
    assert len(out) == 64  # padded up to target


# ---- postquant.py : hybrid KEM -------------------------------------------

def test_hybrid_kem_matches_and_tamper_breaks():
    assert pq.hybrid_selftest() is True

def test_channel_key_is_32_bytes():
    rx = pq.ChannelReceiver(seed=os.urandom(32))
    tx = pq.ChannelSender(rx.public())
    k = pq.sender_derive(tx)
    assert len(k) == 32


# ---- cell.py : deterministic fingerprint slots ----------------------------

def test_cell_slot_determinism_and_separation():
    r = cell_mod.selftest()
    assert r["ok"] is True
    assert r["deterministic"] and r["slots_differ"]
    assert r["no_per_user_variance"] and r["distinct_slots"]

def test_cell_ten_slots():
    ids = {cell_mod.slot_fingerprint_id(i, "https://x.test") for i in range(10)}
    assert len(ids) == 10


# ---- store.py : censorship-resistant replicated hosting -------------------

def test_store_publish_fetch_roundtrip():
    reg = _sample_registry()
    s = store_mod.DeadDropStore(reg.relays)
    content = os.urandom(200 * 1024)
    root = s.publish("test", content)
    assert len(root) == 32
    assert s.fetch(root) == content

def test_store_inclusion_proof():
    reg = _sample_registry()
    s = store_mod.DeadDropStore(reg.relays)
    root = s.publish("p", os.urandom(70 * 1024))
    page = s.pages[root]
    for ch in page["order"]:
        assert s.verify_inclusion(root, ch) is True

def test_store_replication_16x_independent():
    reg = _sample_registry()
    s = store_mod.DeadDropStore(reg.relays)
    root = s.publish("p", os.urandom(33 * 1024))
    for ch in s.pages[root]["order"]:
        holders = s.chunks[ch]["holders"]
        assert len(holders) == store_mod.REPLICATION
        assert len(set(holders)) == store_mod.REPLICATION  # distinct relays

def test_censor_page_needs_all_16_holders():
    reg = _sample_registry()
    s = store_mod.DeadDropStore(reg.relays)
    root = s.publish("p", os.urandom(33 * 1024))
    # capture 15 of 16 holders of the first chunk -> page survives
    first = s.pages[root]["order"][0]
    fifteen = s.chunks[first]["holders"][:15]
    res = s.censor_page(root, fifteen)
    assert res["censored"] is False
    assert res["min_honest_holders"] == 1
    # capture all 16 -> page censored
    res = s.censor_page(root, s.chunks[first]["holders"])
    assert res["censored"] is True


# ---- sim.py : the "you must pay XMR" proof --------------------------------

def test_deanon_costs():
    r = sim_mod.selftest()
    assert r["ok"] is True
    assert r["censor_cost_xmr"] == 1600.0
    assert r["capture_cost_xmr"] == 300.0

def test_flood_cost_scales_with_bond():
    assert sim_mod.flood_cost(10_000, bond_xmr=100.0) == 1_000_000.0


# ---- helpers --------------------------------------------------------------

def _sample_registry():
    reg = reg_mod.Registry()
    names = [f"region-{i:02d}" for i in range(4)]
    for i in range(40):
        reg.stake(reg_mod.Relay(
            key=ec.KeyPair.random(), bond_xmr=100.0,
            region=names[i % 4],
            bandwidth_gbps=1.0, storage_tb=1.0 if i % 2 == 0 else 0.0))
    reg.publish_to_chain(height=1000)
    return reg
