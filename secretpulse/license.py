"""Offline license-key helpers."""
from ._imports import *
from .utils import Colors

# ═══════════════════════════════════════════════════════════════════
#  License Key Validation
# ═══════════════════════════════════════════════════════════════════

import hmac as _hmac

# This is baked into the binary — change before distributing
_LICENSE_SALT = "a7c3f9e1b2d4806573cafe9182736455"

_LICENSE_DIR  = os.path.join(str(Path.home()), ".SecretPulse")
_LICENSE_FILE = os.path.join(_LICENSE_DIR, "license")

_PLANS = {
    "starter":  ["scan", "verify", "json"],
    "pro":      ["scan", "verify", "json", "html", "pdf", "sarif",
                 "wayback", "cve", "batch", "attack_chains"],
    "lifetime": ["scan", "verify", "json", "html", "pdf", "sarif",
                 "wayback", "cve", "batch", "attack_chains"],
    "free":     ["scan", "verify", "json", "html", "pdf", "sarif",
                 "wayback", "cve", "batch", "attack_chains"],
}


def _key_decode(key: str) -> Optional[dict]:
    """Decode and verify a license key. Returns payload or None."""
    try:
        # Strip prefix and dashes: ARC-xxxx-xxxx-... -> raw
        raw = key.replace("ARC-", "").replace("-", "")
        if len(raw) < 20:
            return None

        # Last 16 chars = signature, rest = payload
        payload_b64 = raw[:-16]
        sig_given = raw[-16:]

        # Verify HMAC signature
        sig_expected = _hmac.new(
            _LICENSE_SALT.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        if not _hmac.compare_digest(sig_given, sig_expected):
            return None

        # Decode payload
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded).decode()
        payload = json.loads(payload_json)

        # Expand plan initial to full name
        plan_map = {"s": "starter", "p": "pro", "l": "lifetime"}
        p = payload.get("p", "")
        if p in plan_map:
            payload["p"] = plan_map[p]

        return payload
    except Exception:
        return None


def _key_validate(key: str) -> Tuple[bool, str, Optional[dict]]:
    """
    Validate a license key.
    Returns: (valid, message, payload)
    """
    payload = _key_decode(key)
    if payload is None:
        return False, "Invalid license key.", None

    # Check expiry
    expires = payload.get("x", 0)
    now = int(time.time())
    if now > expires:
        from datetime import datetime as _dt
        exp_date = _dt.fromtimestamp(expires).strftime("%Y-%m-%d")
        return False, f"License expired on {exp_date}. Renew at https://SecretPulse.sh", None

    return True, "Valid", payload


def _key_save(key: str):
    """Save key locally so user doesn't retype every time."""
    os.makedirs(_LICENSE_DIR, mode=0o700, exist_ok=True)
    with open(_LICENSE_FILE, "w") as f:
        f.write(key.strip())
    os.chmod(_LICENSE_FILE, 0o600)


def _key_load() -> Optional[str]:
    """Load saved key, or from env var."""
    # 1. Environment variable
    env_key = os.environ.get("SecretPulse_KEY")
    if env_key:
        return env_key.strip()
    # 2. Saved file
    if os.path.exists(_LICENSE_FILE):
        with open(_LICENSE_FILE) as f:
            return f.read().strip()
    return None


def _key_check_feature(payload: dict, feature: str) -> bool:
    """Check if the license includes a specific feature."""
    plan = payload.get("p", "")
    allowed = _PLANS.get(plan, [])
    return feature in allowed


def _license_gate(args) -> Optional[dict]:
    """
    Standard License.
    Returns a free-tier payload with all features unlocked.
    """
    print(f"  License: {Colors.OKGREEN}Standard{Colors.ENDC}")
    print()
    return {"p": "free", "x": 9999999999, "e": "standard"}
