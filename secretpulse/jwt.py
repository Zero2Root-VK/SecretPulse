"""JWT analysis and decoding helpers."""
from ._imports import *

class JWTAnalyzer:
    """
    Deep JWT analysis: decode + security scoring + vulnerability detection.
    Risk score 0-100 based on algorithm, claims, lifetime, permissions.
    """

    # Algorithm risk: higher = worse
    ALG_RISK = {
        'none': 50, '': 50,
        'hs256': 15, 'hs384': 10, 'hs512': 5,
        'rs256': 0, 'rs384': 0, 'rs512': 0,
        'es256': 0, 'es384': 0, 'es512': 0,
        'ps256': 0, 'ps384': 0, 'ps512': 0,
        'eddsa': 0,
    }

    REQUIRED_CLAIMS = ['iss', 'exp', 'aud', 'nbf', 'jti']

    PERMISSION_KEYS = [
        'scope', 'scopes', 'permissions', 'roles', 'role',
        'authorities', 'grants', 'access', 'entitlements',
    ]

    SENSITIVE_SCOPES = [
        'admin', 'write', 'delete', 'manage', 'superuser', 'root',
        'full_access', 'read_write', 'owner', '*',
    ]

    @staticmethod
    def analyze(token: str) -> Optional[Dict]:
        """Full JWT analysis with security scoring."""
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return None

            def _b64(s):
                s += '=' * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))

            header = _b64(parts[0])
            payload = _b64(parts[1])
        except Exception:
            return None

        analysis = {
            'algorithm': header.get('alg', 'unknown'),
            'type': header.get('typ', 'unknown'),
            'issuer': payload.get('iss', 'N/A'),
            'subject': payload.get('sub', 'N/A'),
            'audience': payload.get('aud', 'N/A'),
        }

        vulns = []
        risk_score = 0

        # ── Algorithm check ──
        alg = header.get('alg', '').lower()
        alg_risk = JWTAnalyzer.ALG_RISK.get(alg, 5)
        risk_score += alg_risk
        if alg in ('none', 'nonce', ''):
            vulns.append('ALG_NONE — JWT accepts unsigned tokens!')
            analysis['algorithm_rating'] = 'CRITICAL'
        elif alg in ('hs256',):
            vulns.append('WEAK_ALG — HS256 is vulnerable to brute-force if key is short')
            analysis['algorithm_rating'] = 'MEDIUM'
        elif alg.startswith('hs'):
            analysis['algorithm_rating'] = 'LOW'
        else:
            analysis['algorithm_rating'] = 'OK'

        # ── Missing claims check ──
        missing = [c for c in JWTAnalyzer.REQUIRED_CLAIMS if c not in payload]
        if missing:
            risk_score += len(missing) * 5
            analysis['missing_claims'] = missing
            if 'exp' in missing:
                vulns.append(f'NO_EXPIRY — Token never expires (missing exp claim)')
                risk_score += 15
            if 'aud' in missing:
                vulns.append('NO_AUDIENCE — Token valid for any service (missing aud)')

        # ── Expiration analysis ──
        now = datetime.now(timezone.utc)
        exp = payload.get('exp')
        iat = payload.get('iat')
        if exp:
            try:
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                analysis['expires'] = exp_dt.isoformat()
                analysis['expired'] = exp_dt < now
                if exp_dt < now:
                    analysis['expired_since'] = str(now - exp_dt)
                else:
                    analysis['expires_in'] = str(exp_dt - now)
            except (OSError, ValueError):
                pass
        if iat:
            try:
                iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
                analysis['issued_at'] = iat_dt.isoformat()
                # Long-lived token check
                if exp:
                    try:
                        lifetime = datetime.fromtimestamp(exp, tz=timezone.utc) - iat_dt
                        lifetime_days = lifetime.total_seconds() / 86400
                        analysis['lifetime_days'] = round(lifetime_days, 1)
                        if lifetime_days > 365:
                            vulns.append(f'EXTREME_LIFETIME — Token valid for {lifetime_days:.0f} days')
                            risk_score += 20
                        elif lifetime_days > 30:
                            vulns.append(f'LONG_LIFETIME — Token valid for {lifetime_days:.0f} days')
                            risk_score += 10
                    except (OSError, ValueError):
                        pass
            except (OSError, ValueError):
                pass

        # ── Permission/scope extraction ──
        permissions = []
        for key in JWTAnalyzer.PERMISSION_KEYS:
            val = payload.get(key)
            if val:
                if isinstance(val, str):
                    permissions.extend(val.split())
                elif isinstance(val, list):
                    permissions.extend([str(v) for v in val])
        if permissions:
            analysis['permissions'] = permissions
            sensitive = [p for p in permissions
                         if any(s in p.lower() for s in JWTAnalyzer.SENSITIVE_SCOPES)]
            if sensitive:
                vulns.append(f'ELEVATED_PERMISSIONS — {", ".join(sensitive[:5])}')
                risk_score += 15
                analysis['sensitive_permissions'] = sensitive

        # ── Custom claims of interest ──
        interesting_keys = ['email', 'name', 'preferred_username', 'groups',
                            'tenant', 'org', 'organization', 'team']
        extra_claims = {k: payload[k] for k in interesting_keys if k in payload}
        if extra_claims:
            analysis['pii_claims'] = extra_claims

        # ── Final scoring ──
        risk_score = min(risk_score, 100)
        analysis['risk_score'] = risk_score
        analysis['risk_grade'] = (
            'CRITICAL' if risk_score >= 60 else
            'HIGH' if risk_score >= 40 else
            'MEDIUM' if risk_score >= 20 else
            'LOW'
        )
        analysis['vulnerabilities'] = vulns

        return {'header': header, 'payload': payload, 'analysis': analysis}


def decode_jwt(token: str) -> Optional[Dict]:
    """Wrapper for backward compatibility."""
    return JWTAnalyzer.analyze(token)
