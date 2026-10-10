"""Deaddrop — a stake-bonded anonymity network anchored to Monero.

Reference implementation of the falsifiable core. Every module here maps
1:1 to a claim in the public write-up so a reader can run and attack the
exact thing being claimed:

  ec.py         secp256k1 group + Rivest-Shamir-Tauman ring signatures
                (the "I am a staked relay, never relay #42" primitive)
  registry.py   stake-bonded Merkle relay registry, published on-chain
  anchor.py     the real Monero transaction that carries the registry root,
                with a live public-node client for the chain head
  circuit.py    Sphinx onion routing with 3 parallel sub-paths + guard committee
  mixnet.py     batching / padding / mixing that hides traffic SHAPE
  postquant.py  hybrid X25519 + ML-KEM (Kyber) channel key agreement
  cell.py       deterministic fingerprint "slots" (JS-safe without a custom browser)
  store.py      content-addressed replicated dead-drop store with slashing
  sim.py        deanonymization-cost simulator (the "you must pay XMR" proof)

This is a reference / proof-of-concept. It is deliberately small, readable,
and uses only standard cryptographic primitives from `cryptography` so the
whole thing can be audited in an afternoon.
"""

__version__ = "0.1.0"
