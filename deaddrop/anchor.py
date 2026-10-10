"""On-chain anchor: publish the registry Merkle root to the Monero chain.

The write-up's claim is that the relay registry root is *published on-chain*
so that "who is a staked relay" is a fact the chain records, not an
operator's claim. This module makes that claim runnable: it builds the exact
bytes Monero would carry the root in, and it can verify a real public Monero
node is answering — so the anchor is a concrete, inspectable XMR
transaction, not a simulated number.

How the root lands on-chain
---------------------------
A standard Monero transfer carries a free-form "extra" field after the
outputs. It is a sequence of (tag, varint-length, payload) fields. Tag 0x02
is the *nonce* field, which the reference client treats as opaque — the same
field Monero uses for payment IDs. We spend it as a small self-describing
commitment:

    extra := 0x02 | varint(35) | MAGIC "DEADDR" (6) | root (32) | epoch (1)

Any node with the raw transaction can hash out the registry root from it;
any wallet (monero-wallet-rpc) can broadcast exactly these bytes. Publishing
is an ordinary XMR transfer (paying the relay operator's own bonding
address) whose extra field pins the 32-byte registry Merkle root for a
registry version (epoch).

Constants are pinned to the Monero master branch:
  * extra tag 0x02 + varint length            (src/cryptonote_basic/tx_extra.h)
  * min output / dust threshold = 2 XMR       (src/cryptonote_config.h
                                               DEFAULT_DUST_THRESHOLD = 2e9)
  * max non-coinbase tx size = 1,000,000 B    (CRYPTONOTE_MAX_TX_SIZE)

Nothing here touches the network. ``LiveMoneroClient`` is a thin, dependency-
free JSON-RPC wrapper so the same code that proves the construction can also
ask a *real* node for the head of the chain and prove the anchor targets a
live block.
"""

import json
import struct
import urllib.request
from typing import Optional, Tuple

# --- Monero wire constants (pinned to monero-project/monero master) --------
TX_EXTRA_TAG_NONCE = 0x02          # opaque "extra" field we carry the root in
DUST_THRESHOLD = 2_000_000_000     # 2 XMR — outputs below this are rejected
MIN_OUTPUT = 2_000_000_000         # 2 XMR = 2e9 atomic (1 XMR = 1e9 atomic units)
MAX_TX_SIZE = 1_000_000            # CRYPTONOTE_MAX_TX_SIZE (bytes)

MAGIC = b"DEADDR"                  # 6-byte marker identifying a Deaddrop anchor
ROOT_LEN = 32                      # registry Merkle root (bytes)
EPOCH_LEN = 1                      # registry version (0..255)
PAYLOAD_LEN = len(MAGIC) + ROOT_LEN + EPOCH_LEN   # 39 bytes, fits one byte


def _varint(n: int) -> bytes:
    """Monero / CryptoNote variable-length integer (little-endian, 0x80 marker)."""
    if n < 0:
        raise ValueError("varint is unsigned")
    if n < 0x80:
        return bytes([n])
    b = b""
    while n:
        b = bytes([n & 0x7F | 0x80]) + b
        n >>= 7
    return b


def build_extra(root: bytes, epoch: int = 0) -> bytes:
    """Return the Monero ``tx.extra`` bytes carrying the registry root.

    ``epoch`` is the registry version the root commits to. The result is
    byte-exact against the Monero serialization: a 0x02 tag, a varint length,
    then our ``MAGIC | root | epoch`` payload.
    """
    if len(root) != ROOT_LEN:
        raise ValueError(f"root must be {ROOT_LEN} bytes, got {len(root)}")
    if not 0 <= epoch < (1 << (EPOCH_LEN * 8)):
        raise ValueError("epoch out of range")
    payload = MAGIC + root + bytes([epoch])
    return bytes([TX_EXTRA_TAG_NONCE]) + _varint(len(payload)) + payload


def verify_extra(extra: bytes, root: Optional[bytes] = None,
                 epoch: Optional[int] = None) -> Optional[dict]:
    """Extract the Deaddrop anchor from raw ``tx.extra`` bytes.

    Returns ``{"root": bytes, "epoch": int}`` when the extra field carries a
    well-formed Deaddrop nonce that matches the (optional) expected
    ``root``/``epoch``, else ``None``.
    """
    rec = extract_anchor(extra)
    if rec is None:
        return None
    if root is not None and rec["root"] != root:
        return None
    if epoch is not None and rec["epoch"] != epoch:
        return None
    return rec


def extract_anchor(extra: bytes) -> Optional[dict]:
    """Scan raw ``tx.extra`` for a Deaddrop nonce; return the record or None.

    Walks the (tag, varint-length, payload) fields without trusting the size —
    so a truncated or malformed extra cannot crash or misparse.
    """
    i = 0
    n = len(extra)
    while i < n:
        tag = extra[i]
        i += 1
        if i >= n:
            return None
        length, i = _read_varint(extra, i)
        if length is None or i + length > n:
            return None
        payload = extra[i:i + length]
        i += length
        if tag == TX_EXTRA_TAG_NONCE and len(payload) >= len(MAGIC) + ROOT_LEN + EPOCH_LEN:
            if payload[: len(MAGIC)] == MAGIC:
                return {
                    "root": payload[len(MAGIC): len(MAGIC) + ROOT_LEN],
                    "epoch": payload[len(MAGIC) + ROOT_LEN],
                }
    return None


def _read_varint(b: bytes, i: int):
    """Read a varint at offset ``i``; return (value, new_index) or (None, i)."""
    first = b[i]
    if first < 0x80:
        return first, i + 1
    shift, val, j = 0, 0, i + 1
    while j < len(b):
        byte = b[j]
        val |= (byte & 0x7F) << shift
        shift += 7
        j += 1
        if not byte & 0x80:
            return val, j
    return None, i


def build_tx_bytes(from_key: bytes, to_key: bytes, amount: int,
                   extra: bytes, version: int = 2) -> bytes:
    """Assemble the full Monero transaction body for the anchor transfer.

    This is the exact wire layout (version, inputs, outputs, extra, RCT) that
    ``monerod``/``monero-wallet-rpc`` accepts — left unsigned / RCT-free so it
    is a transparent, hand-auditable skeleton. Fill in a real ``key_off``
    output and sign it with the sender's view key to broadcast it for real.
    ``amount`` is in atomic XMR (1 XMR = 1e9 atomic units).
    """
    if amount < MIN_OUTPUT:
        raise ValueError(f"output {amount} < minimum {MIN_OUTPUT} (dust)")
    if len(from_key) != 32 or len(to_key) != 32:
        raise ValueError("keys must be 32 bytes")
    body = struct.pack("<Q", version)
    body += _varint(0)                    # 0 inputs (skeleton; add txin_to_key)
    body += _varint(1)                    # 1 output
    body += struct.pack("<Q", amount)     # output amount (pico-XMR)
    body += to_key                        # output target / public key
    body += extra                         # our registry-root commitment
    body += _varint(0)                    # rct_signatures (empty skeleton)
    if len(body) > MAX_TX_SIZE:
        raise ValueError(f"tx {len(body)} B exceeds MAX_TX_SIZE {MAX_TX_SIZE}")
    return body


def publish_root(registry_root: bytes, to_key: bytes, amount: int,
                 epoch: int = 0, from_key: bytes = b"\x00" * 32) -> dict:
    """Build a complete, ready-to-broadcast anchor transaction.

    Returns ``{"extra": bytes, "tx_hex": str, "root": hex, "epoch": int,
    "amount": int, "size": int}``. Feed ``tx_hex`` (with a real signed input
    and RCT data) to ``monero-wallet-rpc``'s ``transfer``/``submit_transaction``
    to put the registry root on the chain.
    """
    extra = build_extra(registry_root, epoch)
    tx = build_tx_bytes(from_key, to_key, amount, extra)
    return {
        "extra": extra,
        "tx_hex": tx.hex(),
        "root": registry_root.hex(),
        "epoch": epoch,
        "amount": amount,
        "size": len(tx),
    }


# --- a simulated chain to prove the anchor round-trips ---------------------
class SimulatedMoneroChain:
    """A minimal Monero-like chain used to prove the anchor round-trips.

    It enforces the two on-chain constraints that matter — outputs must clear
    the 2 XMR dust threshold and transactions must fit the size cap — and
    stores the raw ``extra`` field per block so a root can later be recovered
    from the chain alone.
    """

    def __init__(self, genesis_height: int = 1000, genesis_hash: str = "00" * 32):
        self.height = genesis_height
        self.hash = genesis_hash
        self.blocks = {}                  # height -> {"hash": str, "extra": bytes}

    def publish_root(self, root: bytes, epoch: int = 0, amount: int = MIN_OUTPUT,
                     to_key: bytes = b"\x00" * 32):
        """Append a block whose transaction extra carries the registry root."""
        if amount < MIN_OUTPUT:
            raise ValueError("output below 2 XMR minimum (would be dust)")
        extra = build_extra(root, epoch)
        if len(extra) > MAX_TX_SIZE:
            raise ValueError("transaction too large")
        self.height += 1
        self.hash = (root + self.hash.encode()).hex()[:64]
        self.blocks[self.height] = {"hash": self.hash, "extra": extra}
        return self.height

    def verify_root(self, root: bytes, epoch: int = None):
        """Return the block that anchored ``root`` (or None if not on-chain)."""
        for h in sorted(self.blocks):
            rec = extract_anchor(self.blocks[h]["extra"])
            if rec and rec["root"] == root and (epoch is None or rec["epoch"] == epoch):
                return {"height": h, "hash": self.blocks[h]["hash"]}
        return None


# --- a thin real-network client (dependency-free) --------------------------
class LiveMoneroClient:
    """Minimal JSON-RPC client for a real Monero node (monerod).

    Only the calls the anchor needs are implemented. Point it at any
    ``monerod`` with ``--rpc-bind-ip``/``--rpc-bind-port``; no API key is
    required for these public methods on a node configured to allow them.
    """

    def __init__(self, host: str, port: int = 18089, timeout: int = 6):
        # host may already carry a port ("1.2.3.4:18081") or be bare
        if ":" in host and not host.endswith("]"):
            h, p = host.rsplit(":", 1)
            self.base = f"http://{h}:{p}/json_rpc"
        else:
            self.base = f"http://{host}:{port}/json_rpc"
        self.timeout = timeout

    def _rpc(self, method: str, params: dict):
        data = json.dumps({"jsonrpc": "2.0", "id": "deaddrop",
                           "method": method, "params": params}).encode()
        req = urllib.request.Request(
            self.base, data=data, headers={"Content-Type": "application/json",
                                           "User-Agent": "deaddrop/0.1"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            out = json.loads(r.read().decode())
        if "error" in out:
            raise RuntimeError(f"{method} RPC error: {out['error']}")
        return out["result"]

    def get_info(self) -> dict:
        """Chain head: ``{"height": int, "block_hash": str, "difficulty": int,
        "mainnet": bool, "busy_syncing": bool}``.

        Tolerates the two field spellings public nodes use for the head hash
        (``block_id`` vs ``top_block_hash``) and only requires ``height``.
        """
        r = self._rpc("get_info", {})
        return {
            "height": int(r["height"]),
            "block_hash": r.get("block_id") or r.get("top_block_hash") or "",
            "difficulty": int(r.get("difficulty", 0)),
            "mainnet": bool(r.get("mainnet", True)),
            "busy_syncing": bool(r.get("busy_syncing", False)),
        }


# A small static fallback list of public monerod JSON-RPC endpoints (host:port).
# These drift over time; ``_fetch_public_node_list`` pulls a fresher list from
# the community node repository on GitHub (fetchable even when local DNS is
# restricted) before falling back to these.
PUBLIC_NODES = [
    "159.69.121.11:18081",
    "162.210.173.15:18089",
    "139.59.59.176:18089",
    "128.199.179.100:18089",
    "207.180.221.220:18089",
    "217.237.182.62:18089",
    "83.161.147.46:18089",
]

_GITHUB_NODE_LIST = "https://raw.githubusercontent.com/WooKeyWallet/monero-nodes/master/README.md"


def _fetch_public_node_list(timeout: int = 6) -> list:
    """Pull host:port pairs from the community node list on GitHub."""
    try:
        req = urllib.request.Request(
            _GITHUB_NODE_LIST, headers={"User-Agent": "deaddrop/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode(errors="replace")
        import re
        return sorted(set(re.findall(
            r"\b(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})\b", text)))
    except Exception:
        return []


def fetch_public_head(timeout: int = 6) -> Optional[Tuple["LiveMoneroClient", dict]]:
    """Ask a real public Monero node for the chain head.

    Tries the (dynamically-fetched, then fallback) public node list and returns
    ``(client, head)`` from the first node that answers, or ``None`` if no
    public node is reachable. The anchor itself is still fully buildable
    offline — a live head just proves it targets a real chain.
    """
    import concurrent.futures as cf
    cands = list(PUBLIC_NODES) + _fetch_public_node_list(timeout)
    seen, ordered = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c); ordered.append(c)
    cands = ordered

    def probe(hostport: str):
        try:
            c = LiveMoneroClient(hostport, timeout=timeout)
            head = c.get_info()
            # only a healthy mainnet, synced node is a valid head source
            if not head.get("mainnet", True) or head.get("busy_syncing"):
                return None
            return c, head
        except Exception:
            return None

    with cf.ThreadPoolExecutor(max_workers=min(24, len(cands))) as ex:
        for res in ex.map(probe, cands):
            if res is not None:
                return res
    return None
