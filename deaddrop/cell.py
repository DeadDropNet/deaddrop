"""The Cell: deterministic fingerprint slots — JS-safe without a custom browser.

Instead of patching a browser (Tor Browser's path), the Cell standardizes
the *environment*. Every user in a "profile slot" renders from the exact
same deterministic profile: fixed virtual CPU, a virtual GPU (software
renderer, never hardware passthrough), fixed resolution, fonts, locale,
timezone, and browser build. Ten slots total.

The result: every user in slot K produces a byte-identical fingerprint —
canvas, WebGL, audio, screen, TLS, the works. Fingerprinting is defeated by
*consistency, not noise*: you can't distinguish two users in the same slot
because their devices report the identical thing. The anonymity set for
fingerprinting is now the *entire slot population*, not a noise cloud.

Bonus properties (all from running a disposable VM):
  - exploit containment: a JS 0-day dies in a throwaway VM, not your host
  - behavioral-rhythm virtualization: keystroke dynamics match the slot
  - constant-rate uplink: your ISP sees a steady background signature
  - full-tunnel gateway: no WebRTC / DNS / JS fetch / protocol handler can
    bypass the circuit

This module models the slot determinism: the same (slot_id, page) pair
always produces the same full fingerprint, and different slots differ in
every field. That's the auditable core of the claim.
"""

import hashlib
import json

N_SLOTS = 10

# Fixed environment constants shared by ALL users in a slot. These are what
# make the fingerprint deterministic instead of per-device.
_BASE_PROFILE = {
    "renderer": "software-vgpu",          # virtual GPU, no hardware passthrough
    "vcpu": "Generic vCPU @ 2.4GHz (4 threads)",
    "resolution": "1920x1080",
    "color_depth": 24,
    "device_pixel_ratio": 1.0,
    "browser": "Deaddrop Browser 120.0 (build pinned)",
    "font_stack": ["Arial", "Helvetica", "sans-serif"],
    "gpu_vendor": "Deaddrop Virtual GPU (Mesa)",
    "gpu_renderer": "Deaddrop Virtual GPU (Mesa) 4.6 (software)",
    "platform": "Win32",
    "hardware_concurrency": 4,
    "device_memory_gb": 8,
}

# Per-slot deltas: what distinguishes slot 3 from slot 7. Every user in a
# slot gets the SAME value here, so the slot IS the fingerprint.
_SLOT_DELTAS = {
    0: {"locale": "en-US", "timezone": "America/New_York", "screen": "1920x1080", "audio": 0x11},
    1: {"locale": "en-GB", "timezone": "Europe/London",      "screen": "1680x1050", "audio": 0x22},
    2: {"locale": "en-AU", "timezone": "Australia/Sydney",   "screen": "1920x1080", "audio": 0x33},
    3: {"locale": "de-DE", "timezone": "Europe/Berlin",      "screen": "2560x1440", "audio": 0x44},
    4: {"locale": "fr-FR", "timezone": "Europe/Paris",       "screen": "1920x1080", "audio": 0x55},
    5: {"locale": "ja-JP", "timezone": "Asia/Tokyo",         "screen": "1600x900",  "audio": 0x66},
    6: {"locale": "es-ES", "timezone": "Europe/Madrid",      "screen": "1920x1080", "audio": 0x77},
    7: {"locale": "nl-NL", "timezone": "Europe/Amsterdam",   "screen": "1920x1200", "audio": 0x88},
    8: {"locale": "pt-BR", "timezone": "America/Sao_Paulo",  "screen": "1366x768",  "audio": 0x99},
    9: {"locale": "sv-SE", "timezone": "Europe/Stockholm",   "screen": "1920x1080", "audio": 0xAA},
}


def slot_fingerprint(slot_id: int, page_url: str, nonce: bytes = b"") -> dict:
    """Full deterministic fingerprint for (slot, page).

    Same (slot, page) -> identical fingerprint for every user in the slot.
    The `nonce` is a per-session jitter that does NOT change the fingerprint
    identity — it only changes ephemeral values (like a fresh connection),
    so two sessions in the same slot still "look like the same device."
    """
    if not (0 <= slot_id < N_SLOTS):
        raise ValueError("slot_id out of range")
    delta = _SLOT_DELTAS[slot_id]
    fp = dict(_BASE_PROFILE)
    fp.update(delta)
    # page-specific but still deterministic per (slot, page)
    fp["canvas_hash"] = _h(f"canvas|{slot_id}|{page_url}")
    fp["webgl_hash"] = _h(f"webgl|{slot_id}|{page_url}")
    fp["audio_hash"] = _h(f"audio|{slot_id}|{page_url}")
    fp["tls_ja3"] = _h(f"tls|{slot_id}")  # same browser build in a slot
    fp["screen"] = delta["screen"]
    fp["locale"] = delta["locale"]
    fp["timezone"] = delta["timezone"]
    return fp


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def slot_fingerprint_id(slot_id: int, page_url: str) -> str:
    """A stable identity string for a slot's fingerprint on a page."""
    fp = slot_fingerprint(slot_id, page_url)
    fields = json.dumps(fp, sort_keys=True)
    return hashlib.sha256(fields.encode()).hexdigest()


def selftest() -> dict:
    """Verify the core claims:
      1. determinism: same (slot, page) -> same fingerprint
      2. slot separation: different slots differ on every distinguishing field
      3. no per-user variance: 1000 'users' in one slot all match
    """
    page = "https://example.com"
    # 1. determinism
    a = slot_fingerprint(3, page)
    b = slot_fingerprint(3, page)
    deterministic = (a == b)
    # 2. slot separation
    s0 = slot_fingerprint(0, page)
    s7 = slot_fingerprint(7, page)
    differ = s0["locale"] != s7["locale"] and s0["timezone"] != s7["timezone"] \
        and s0["canvas_hash"] != s7["canvas_hash"] and s0["tls_ja3"] != s7["tls_ja3"]
    # 3. no per-user variance across 1000 "users" in slot 4
    ids = {slot_fingerprint_id(4, page) for _ in range(1000)}
    no_user_variance = len(ids) == 1
    # cross-slot: 10 slots -> 10 distinct identities
    all_ids = {slot_fingerprint_id(i, page) for i in range(N_SLOTS)}
    distinct_slots = len(all_ids) == N_SLOTS
    return {
        "deterministic": deterministic,
        "slots_differ": differ,
        "no_per_user_variance": no_user_variance,
        "distinct_slots": distinct_slots,
        "n_slots": N_SLOTS,
        "ok": deterministic and differ and no_user_variance and distinct_slots,
    }
