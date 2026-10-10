# Deaddrop — reference implementation

An anonymous internet that runs on Monero. No token, no ICO. Security is a
property of the network's *economics*, not of user behavior.

This repo is the **falsifiable core**: every module maps 1:1 to a claim in
the public write-up, and the test suite checks each claim against working
code. If you can break a test, you've found a real hole. If you can't, the
claims are backed.

## Run it

```bash
pip install cryptography          # the only dependency
python demo.py                    # end-to-end walkthrough with real numbers
python tests/run_tests.py         # the full test suite
```

## What's here (claim -> module -> test)

| Claim in the write-up | Module | Verifies it |
|---|---|---|
| "I am a staked relay, never relay #42" — ZK-style membership proof | `ec.py` | `test_ring_signature_core`, `test_ring_signature_binds_to_registry`, `test_ring_signature_unforgeable_without_secret` |
| Stake-bonded relays, registry root published on-chain | `registry.py`, `anchor.py` | `test_stake_unstake_and_bond`, `test_on_chain_anchor`, `test_membership_sign_verify`, `test_anchor_extra_roundtrip`, `test_anchor_on_chain_roundtrip`, `test_anchor_tx_body_and_dust_rule` |
| Sphinx onion routing + 3 parallel sub-paths + staked guard committee | `circuit.py` | `test_circuit_three_subpaths`, `test_wrap_and_reassemble`, `test_guard_is_staked` |
| Mixnet hides *when and how much* (traffic shape) | `mixnet.py` | `test_mixnet_shape_indistinguishable`, `test_mixnet_padding_to_target` |
| Post-quantum channel: X25519 + ML-KEM (Kyber), no harvest-now-decrypt-later | `postquant.py` | `test_hybrid_kem_matches_and_tamper_breaks`, `test_channel_key_is_32_bytes` |
| The Cell: JS-safe without a custom browser (deterministic fingerprint slots) | `cell.py` | `test_cell_slot_determinism_and_separation`, `test_cell_ten_slots` |
| Censorship-resistant hosting: 16x replicated, slashing-enforced | `store.py` | `test_store_publish_fetch_roundtrip`, `test_store_replication_16x_independent`, `test_censor_page_needs_all_16_holders` |
| "You can't deanonymize without paying real XMR" | `sim.py` | `test_deanon_costs`, `test_flood_cost_scales_with_bond` |

## The core idea in three sentences

1. **Anonymity set = the whole bonded registry, not the live online set.**
   A packet hop is authenticated by a registry-bound ring signature
   (`ec.py`), so the anonymity set is every staked relay that has *ever*
   paid — global, persistent, and it can't be shrunk or flooded without
   posting XMR bonds.

2. **Every attack has an XMR price tag** (`sim.py`). Flooding the set,
   reading a user's plaintext, or censoring a page all require *buying or
   compromising staked relays*, which costs their full bonds. The security
   argument is a number you can run, not a trust claim.

3. **The economics are the product.** Monero has fixed supply and no native
   staking, so Deaddrop is the first real place XMR earns yield — a
   refundable bond that earns real usage fees. No token to sell, nothing to
   exit-scam.

## Honest scope (what this is and isn't)

- This is a **reference / proof-of-concept**, deliberately small and
  readable, using only `cryptography` (Rust/OpenSSL ML-KEM + standard
  X25519) plus a self-contained secp256k1 group. It exists so the claims are
  *runnable and attackable*, not to be a production relay.
- The ring signature is a clean RST (Rivest-Shamir-Tauman 2001) over
  secp256k1, bound to the registry Merkle root. It proves "this relay is a
  member of registry version R" without revealing which one.
- The registry's on-chain anchor is a **real Monero transaction** built by
  `anchor.py`: the 32-byte registry Merkle root is carried in a standard
  transfer's opaque `0x02` "extra/nonce" field (the same field Monero uses for
  payment IDs), with a self-describing `DEADDR | root | epoch` payload. The
  module enforces Monero's real wire rules (2 XMR minimum output, 1 MB tx
  cap) and can query a **live public `monerod` node** for the chain head, so
  the anchor targets the actual chain. It is byte-exact and auditable; the
  only thing left to a real deployment is a signed, funded input (the sender's
  XMR) and a `monero-wallet-rpc` `submit_transaction` call.
- The Cell's VM sandbox, the constant-rate uplink shaper, and the 1 Gbps
  relay datapath are modeled, not a full hypervisor — the auditable core is
  the determinism (`cell.py`) and the economics (`sim.py`).

## Layout

```
deaddrop/
  ec.py         secp256k1 group + RST ring signatures + registry Merkle root
  registry.py   stake-bonded relay registry, on-chain anchor, slashing
  anchor.py     builds the real Monero tx carrying the registry root (live-node head)
  circuit.py    Sphinx onion routing, 3 parallel sub-paths, staked guards
  mixnet.py     batching / padding / permutation (traffic-shape hiding)
  postquant.py  hybrid X25519 + ML-KEM-768 channel key agreement
  cell.py       deterministic fingerprint slots (JS-safe without a custom browser)
  store.py      content-addressed replicated dead-drop store + censorship math
  sim.py        deanonymization-cost simulator (the "pay XMR" proof)
tests/
  test_all.py   one test per claim
  run_tests.py  standalone runner (no pytest needed)
demo.py         end-to-end walkthrough with real numbers
```
