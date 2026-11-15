"""Terminal colors, progress, rate limiting, entropy, and evidence helpers."""
from ._imports import *

class Colors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKCYAN    = '\033[96m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM       = '\033[2m'


# ═══════════════════════════════════════════════════════════════════
#  Progress Bar
# ═══════════════════════════════════════════════════════════════════

class ProgressBar:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self._lock = threading.Lock()
        self.urls_total = 0
        self.urls_done = 0
        self.js_scanned = 0
        self.secrets_found = 0
        self.waf_blocked = 0
        self.verified = 0
        self.retries_used = 0
        self._last_len = 0
        self._start_time = time.time()

    def set_total(self, total: int):
        self.urls_total = total
        self._start_time = time.time()

    def increment(self, field: str, amount: int = 1):
        with self._lock:
            setattr(self, field, getattr(self, field) + amount)
            self._render()

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if v is not None:
                    setattr(self, k, v)
            self._render()

    def _format_eta(self):
        """Calculate and format estimated time remaining."""
        if self.urls_done <= 0 or self.urls_total <= 0:
            return ""
        elapsed = time.time() - self._start_time
        if elapsed < 3:
            return ""  # Too early to estimate
        rate = self.urls_done / elapsed  # URLs per second
        remaining = self.urls_total - self.urls_done
        if rate > 0 and remaining > 0:
            eta_secs = remaining / rate
            if eta_secs < 60:
                return f" ETA:{int(eta_secs)}s"
            elif eta_secs < 3600:
                return f" ETA:{int(eta_secs/60)}m{int(eta_secs%60)}s"
            else:
                return f" ETA:{int(eta_secs/3600)}h{int((eta_secs%3600)/60)}m"
        elif remaining <= 0:
            return " done"
        return ""

    def _render(self):
        if not self.enabled:
            return
        total = max(self.urls_total, 1)
        pct = min(self.urls_done / total, 1.0)
        filled = int(20 * pct)
        bar = '█' * filled + '░' * (20 - filled)
        eta = self._format_eta()
        # Show retry/WAF stats in real-time (Feature #4)
        extra = ""
        if self.retries_used > 0 or self.waf_blocked > 0:
            extra = f" · ↻{self.retries_used}"
            if self.waf_blocked > 0:
                extra += f" · 🛡{self.waf_blocked}"
        line = (f"\r{Colors.DIM}[{bar}] {self.urls_done}/{self.urls_total} URLs"
                f" · {self.js_scanned} JS · {self.secrets_found} secrets"
                f" · {self.verified} verified{extra}{eta}{Colors.ENDC}")
        pad = max(0, self._last_len - len(line))
        sys.stderr.write(line + ' ' * pad)
        sys.stderr.flush()
        self._last_len = len(line)

    def finish(self):
        if self.enabled:
            elapsed = time.time() - self._start_time
            if elapsed >= 60:
                time_str = f"{int(elapsed/60)}m{int(elapsed%60)}s"
            else:
                time_str = f"{elapsed:.1f}s"
            # Print final summary line before clearing
            sys.stderr.write(f"\r{Colors.DIM}[{'█'*20}] Complete in {time_str} "
                             f"· {self.urls_done} URLs · {self.js_scanned} JS "
                             f"· {self.secrets_found} secrets{Colors.ENDC}")
            sys.stderr.write('\n')
            sys.stderr.flush()
            self._last_len = 0


# ═══════════════════════════════════════════════════════════════════
#  Rate Limiter
# ═══════════════════════════════════════════════════════════════════

class RateLimiter:
    """Token-bucket rate limiter for HTTP requests."""
    def __init__(self, rps: float = 0):
        self.rps = rps
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.rps <= 0:
            return
        with self._lock:
            now = time.time()
            interval = 1.0 / self.rps
            elapsed = now - self._last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last = time.time()


# ═══════════════════════════════════════════════════════════════════
#  Entropy calculator
# ═══════════════════════════════════════════════════════════════════

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def line_context(content: str, start: int, end: int = None, radius: int = 120):
    """Return (1-based line number, bounded snippet) for a match."""
    end = start if end is None else end
    line_start = content.rfind('\n', 0, start) + 1
    line_end = content.find('\n', end)
    if line_end < 0:
        line_end = len(content)
    snippet_start = max(line_start, start - radius)
    snippet_end = min(line_end, end + radius)
    return content.count('\n', 0, start) + 1, content[snippet_start:snippet_end].strip()[:500]


def mask_secret(value: str) -> str:
    """Mask a credential for logs and error details."""
    value = str(value or '')
    if len(value) <= 8:
        return '***'
    return value[:4] + '***' + value[-4:]
