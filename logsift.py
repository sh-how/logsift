#!/usr/bin/env python3
"""
logsift - a terminal UI for searching and filtering many CSV log files at once.

Run:       python logsift.py [folder-or-file ...]
           (first run sets itself up automatically; needs internet once)

Adding files
    Drag folders or CSV files from your file manager onto the terminal window.
    (The terminal pastes the path; logsift picks it up. If your terminal types
    the path into the filter box instead, just press Enter.)
    Folders are searched recursively for *.csv.

Filter syntax (space-separated terms are ANDed together)
    src=10.1.1.5              exact match (case-insensitive)
    action=drop|reject        any of several values
    dst=192.168.0.0/16        CIDR match on IP columns
    src=10.1.*                wildcards (* and ?)
    service!=443              not equal
    fw_message~timeout        contains
    fw_message!~keepalive     does not contain
    dst~/^10\\.(1|2)\\./        regular expression (wrap in slashes)
    s_port>=1024  date>=1Oct2026   numeric / date comparison
    "ICMP Type"=8             quote column names or values that contain spaces
    scheme=IKE                trailing colons in column names are optional
    vpn-gw-01                 bare word: any column contains it
    !keepalive                no column contains it

Suggestions
    As you type, the filter box suggests column names, and after "column="
    it suggests values seen in that column (sampled from the start of each
    file, most common first). Tab or Right-arrow accepts the suggestion; the
    line under the box lists other candidates - keep typing to narrow them.

Keys
    Enter   run the filter / open row details (when the table is focused)
    Tab     accept suggestion, otherwise switch between filter box and results
    F1 help   F2 toggle all columns   F3 list files   F5 export matches
    F4 values: type a column name to list its distinct values with counts
       (within the current filter); Enter on a value adds it to the filter
    F8 clear files   Esc back to filter   Ctrl+Q quit

Editing the filter
    Ctrl+U  clear the filter box (deletes everything before the cursor);
            then press Enter to show all rows again
    Ctrl+K  delete everything after the cursor
    Ctrl+W  delete the word before the cursor
    Home / End   jump to the start / end of the filter

Large files
    Files are scanned in pieces by several worker processes (one per CPU core,
    up to 8), so the window stays responsive while a search runs, and a new
    search replaces a running one. Terms like src=10.1.1.5 or fw_message~timeout
    are fastest: lines without that text are rejected before being parsed.
    Comparisons (>, <), regular expressions and "not" terms have to parse every
    line and are slower. Result rows are added to the table as you scroll.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import difflib
import fnmatch
import ipaddress
import multiprocessing
import os
import re
import shutil
import signal
import sys
import tempfile
import time
from collections import Counter, deque
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlparse

def _bootstrap() -> None:
    """First run: install textual into a private environment, then restart."""
    import subprocess
    import venv
    home = Path.home() / ".logsift" / "venv"
    py = home / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if Path(sys.prefix).resolve() == home.resolve():
        sys.exit("logsift: setup finished but 'textual' still won't import. "
                 f"Delete {home.parent} and run again.")
    try:
        if not py.exists():
            print("logsift: first run - setting up (about a minute, one time only)...")
            venv.create(home, with_pip=True)
        probe = subprocess.run([str(py), "-c", "import textual"], capture_output=True)
        if probe.returncode != 0:
            print("logsift: downloading the 'textual' package...")
            subprocess.check_call([str(py), "-m", "pip", "install", "--quiet",
                                   "--disable-pip-version-check", "textual"])
    except Exception as e:
        sys.exit(f"logsift: automatic setup failed ({e}).\n"
                 "Check your internet connection, or install manually:  pip install textual")
    args = [str(py), str(Path(__file__).resolve()), *sys.argv[1:]]
    if os.name == "nt":
        sys.exit(subprocess.call(args))
    os.execv(str(py), args)


try:
    import textual  # noqa: F401
except ImportError:
    _bootstrap()

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList, Suggester
from textual.widgets import DataTable, Footer, Header, Input, Static
from textual.worker import get_current_worker

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

# Columns shown by default (when present). F2 switches to every column.
PREFERRED = [
    "date", "time", "orig", "action", "src", "dst", "proto", "service",
    "s_port", "rule", "i/f_name", "i/f_dir", "xlatesrc", "xlatedst", "user",
]
PAGE = 200               # result rows added to the table ahead of the cursor
CELL_WIDTH = 48          # long cells are truncated in the table (not in details)
CHUNK = 16 << 20         # bytes of a file handed to one worker process at a time


# --------------------------------------------------------------------------
# Paths and files
# --------------------------------------------------------------------------

def split_tokens(text: str, escapes: bool) -> list[str]:
    """Split on whitespace outside quotes. Quotes are removed."""
    out, cur, quote, started = [], [], None, False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            else:
                cur.append(ch)
        elif ch in "\"'":
            quote, started = ch, True
        elif escapes and ch == "\\" and i + 1 < len(text):
            i += 1
            cur.append(text[i])
        elif ch.isspace():
            if cur or started:
                out.append("".join(cur))
            cur, started = [], False
        else:
            cur.append(ch)
        i += 1
    if cur or started:
        out.append("".join(cur))
    return out


def _clean_path(s: str) -> Path:
    s = s.strip().strip("\"'")
    if s.startswith("file://"):
        s = unquote(urlparse(s).path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:", s):
            s = s[1:]
    return Path(s).expanduser()


def parse_dropped(text: str) -> list[Path]:
    """Return paths if `text` looks like dragged-in file/folder paths, else []."""
    text = text.strip()
    if not text or not ("/" in text or "\\" in text):
        return []
    try:
        whole = _clean_path(text)
        if whole.exists():
            return [whole]
        parts: list[str] = []
        for line in text.splitlines():
            parts += split_tokens(line, escapes=os.name != "nt")
        paths = [_clean_path(p) for p in parts]
        if paths and all(p.exists() for p in paths):
            return paths
    except (OSError, ValueError):
        pass
    return []


def norm(name: str) -> str:
    return name.strip().lower().rstrip(":").strip()


class CsvFile:
    def __init__(self, path: Path):
        self.path = path
        self.size = path.stat().st_size
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            first = fh.readline()
        self.delim = max(",;\t|", key=lambda d: first.count(d)) if first.strip() else ","
        self.header = next(csv.reader([first], delimiter=self.delim), [])
        self.header = [h.strip() for h in self.header]
        self.colmap: dict[str, int] = {}
        for i, h in enumerate(self.header):
            self.colmap.setdefault(norm(h), i)
        self.plan = None          # AsyncResult of plan_file(), set by the app


# --------------------------------------------------------------------------
# Filter language
# --------------------------------------------------------------------------

class QueryError(Exception):
    pass


OP_RE = re.compile(r"!=|!~|>=|<=|=|~|>|<")
DATE_FMTS = ("%d%b%Y", "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y", "%Y/%m/%d", "%d %b %Y")


@lru_cache(maxsize=8192)
def cmp_key(s: str):
    s = s.strip()
    try:
        return (0, float(s))
    except ValueError:
        pass
    for fmt in DATE_FMTS:
        try:
            return (1, dt.datetime.strptime(s, fmt).toordinal())
        except ValueError:
            pass
    return (2, s.lower())


@lru_cache(maxsize=65536)
def _ip(s: str):
    try:
        return ipaddress.ip_address(s.strip())
    except ValueError:
        return None


def _ip4(s: str) -> int:
    """IPv4 address as an integer, or -1 if s is not one."""
    p = s.split(".")
    if len(p) != 4:
        return -1
    v = 0
    for x in p:
        if not x.isdigit() or len(x) > 3 or (len(x) > 1 and x[0] == "0") or not x.isascii():
            return -1
        n = int(x)
        if n > 255:
            return -1
        v = v << 8 | n
    return v


def build_test(op: str, raw: str):
    """Return a function cell -> bool for a (non-negated) operator."""
    if len(raw) > 2 and raw.startswith("/") and raw.endswith("/") and op in "=~":
        try:
            return re.compile(raw[1:-1], re.I).search
        except re.error as e:
            raise QueryError(f"bad regex {raw}: {e}")

    if op == "~":
        alts = [a.lower() for a in raw.split("|")]
        if len(alts) == 1:
            a = alts[0]
            return lambda c: a in c.lower()
        return lambda c: any(a in c.lower() for a in alts)

    if op == "=":
        exact, tests = set(), []
        for a in raw.split("|"):
            a = a.strip()
            net = None
            if "/" in a:
                try:
                    net = ipaddress.ip_network(a, strict=False)
                except ValueError:
                    pass
            if net is not None and net.version == 4:
                lo, hi = int(net.network_address), int(net.broadcast_address)
                tests.append(lambda c, lo=lo, hi=hi: lo <= _ip4(c) <= hi)
            elif net is not None:
                tests.append(lambda c, n=net: (ip := _ip(c)) is not None
                             and ip.version == n.version and ip in n)
            elif "*" in a or "?" in a:
                tests.append(re.compile(fnmatch.translate(a), re.I).match)
            else:
                exact.add(a.lower())
        if not tests:
            return lambda c: c.strip().lower() in exact
        return lambda c: c.strip().lower() in exact or any(t(c.strip()) for t in tests)

    want = cmp_key(raw)
    cmpf = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
            "<": lambda a, b: a < b, "<=": lambda a, b: a <= b}[op]

    def compare(c: str) -> bool:
        if not c.strip():
            return False
        have = cmp_key(c)
        if have[0] != want[0]:
            return cmpf(c.strip().lower(), raw.lower())
        return cmpf(have[1], want[1])
    return compare


def find_needles(op: str, raw: str):
    """Text that must appear in the raw line for the term to match, or None.

    Lets the scanner reject most lines with a substring check instead of
    parsing them. One entry per '|' alternative; the line needs any of them.
    """
    if op not in ("=", "~") or (len(raw) > 2 and raw.startswith("/") and raw.endswith("/")):
        return None
    out = []
    for a in raw.split("|"):
        a = (a.strip() if op == "=" else a).lower()
        if op == "=" and "/" in a:
            try:
                net = ipaddress.ip_network(a, strict=False)
            except ValueError:
                net = None
            if net is not None:
                keep = net.prefixlen // 8
                if net.version != 4 or keep == 0:
                    return None
                a = ".".join(str(net.network_address).split(".")[:keep]) + ("." if keep < 4 else "")
        elif op == "=" and ("*" in a or "?" in a):
            if "[" in a:
                return None
            a = max(re.split(r"[*?]+", a), key=len)
        if not a or '"' in a or not a.isascii():
            return None
        out.append(a)
    return tuple(out)


class Cond:
    """One filter term. col is a normalised column name, or None for 'any column'."""

    def __init__(self, col: str | None, op: str, raw: str):
        self.col = col
        self.negate = op.startswith("!")
        self.test = build_test(op.lstrip("!") or "~", raw)
        found = find_needles(op.lstrip("!") or "~", raw)
        self.needles = None if self.negate else found
        self.anti = found if self.negate and col is None else None


def parse_query(text: str, known: dict[str, str]) -> list[Cond]:
    conds = []
    for tok in split_tokens(text, escapes=False):
        if not tok:
            continue
        found = None
        first_left = None
        for m in OP_RE.finditer(tok):
            left = tok[:m.start()]
            if first_left is None:
                first_left = left
            if norm(left) in known and left.strip():
                found = (norm(left), m.group(), tok[m.end():])
                break
        if found:
            conds.append(Cond(*found))
        elif tok.startswith("~") and len(tok) > 1:
            conds.append(Cond(None, "~", tok[1:]))
        elif tok.startswith("!") and len(tok) > 1 and not tok.startswith(("!=", "!~")):
            conds.append(Cond(None, "!~", tok[1:]))
        elif first_left and re.fullmatch(r"[\w /.:\-]+", first_left):
            near = difflib.get_close_matches(norm(first_left), list(known), n=3, cutoff=0.5)
            hint = "  Did you mean: " + ", ".join(known[n] for n in near) if near else ""
            raise QueryError(f"Unknown column '{first_left}'.{hint}  (F1 lists columns)")
        else:
            conds.append(Cond(None, "~", tok))
    return conds


# --------------------------------------------------------------------------
# Scanning engine
#
# Files are cut into CHUNK-sized byte ranges and scanned by a pool of worker
# processes, so the UI process never does heavy work and all cores are used.
# Everything in this section runs inside the workers except Engine itself.
# --------------------------------------------------------------------------

SLOT_SCAN, SLOT_VALUES, SLOT_EXPORT = 0, 1, 2
_GENS = None              # shared job counters; a task whose number is stale is skipped
_COMPILED: dict = {}


def _pool_init(gens) -> None:
    global _GENS
    _GENS = gens
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass
    try:
        os.nice(5)            # let the UI process win when all cores are busy
    except (AttributeError, OSError):
        pass


def _stale(task) -> bool:
    return _GENS is not None and _GENS[task["slot"]] != task["gen"]


def split_records(text: str) -> list[str]:
    """Split a block of CSV text into records (a quoted field may span lines)."""
    lines = text.split("\n")
    if '"' in text:
        out, buf = [], None
        for line in lines:
            if buf is None:
                if line.count('"') & 1:
                    buf = [line]
                else:
                    out.append(line)
            else:
                buf.append(line)
                if line.count('"') & 1:
                    out.append("\n".join(buf))
                    buf = None
        if buf:
            out.append("\n".join(buf))
        lines = out
    return [r for r in lines if r]


def parse_records(recs: list[str], delim: str) -> list[list[str]]:
    out = []
    for r in recs:
        if '"' in r:
            out.append(next(csv.reader([r], delimiter=delim), []))
        else:
            out.append(r.split(delim))
    return out


def plan_file(path: str, delim: str) -> dict:
    """Find safe places to cut a file into chunks, and sample its values.

    A cut is only made at a newline that is outside any quoted field, which is
    tracked by counting quote characters from the start of the file.
    """
    try:
        size = os.path.getsize(path)
        offsets = []
        with open(path, "rb") as fh:
            fh.readline()
            pos = start = fh.tell()
            head = fh.read(min(size - start, 4 << 20))
            fh.seek(start)
            offsets.append(start)
            target, parity = start + CHUNK, 0
            while True:
                block = fh.read(4 << 20)
                if not block:
                    break
                cur = 0
                while target < pos + len(block):
                    rel = max(target - pos, cur)
                    parity ^= block.count(b'"', cur, rel) & 1
                    cur = rel
                    found = False
                    while True:
                        nl = block.find(b"\n", cur)
                        if nl < 0:
                            break
                        parity ^= block.count(b'"', cur, nl) & 1
                        cur = nl + 1
                        if parity == 0:
                            found = True
                            break
                    if not found:
                        target = pos + len(block)      # keep looking in the next block
                        break
                    if pos + cur < size:
                        offsets.append(pos + cur)
                    target = pos + cur + CHUNK
                parity ^= block.count(b'"', cur) & 1
                pos += len(block)
        offsets.append(size)
        offsets = sorted(set(o for o in offsets if o <= size))

        text = head.decode("utf-8", "replace").replace("\r\n", "\n")
        if len(head) < size - start:
            text = text[:text.rfind("\n") + 1]
        counts: dict[int, Counter] = {}
        for row in parse_records(split_records(text)[:INDEX_ROWS], delim):
            for i, v in enumerate(row):
                v = v.strip()
                if v and len(v) <= 60:
                    counts.setdefault(i, Counter())[v] += 1
        sample = {i: c.most_common(300) for i, c in counts.items()}
        return {"offsets": offsets, "sample": sample}
    except OSError as e:
        return {"error": str(e)}


def _compile(task):
    """(tests, needle groups, anti-needle groups, colmap) for this query against this file's header; cached."""
    key = (task["query"], task["header"])
    hit = _COMPILED.get(key)
    if hit is None:
        if len(_COMPILED) > 256:
            _COMPILED.clear()
        colmap: dict[str, int] = {}
        for i, h in enumerate(task["header"]):
            colmap.setdefault(norm(h), i)
        tests, groups, anti = [], [], []
        for c in parse_query(task["query"], dict(task["known"])):
            idx = None if c.col is None else colmap.get(c.col, -1)
            if idx == -1:
                if c.negate:
                    continue                  # column absent: "not X" is trivially true
                tests = None                  # column absent: nothing can match
                break
            if idx is None and c.negate and c.anti:
                anti.append(c.anti)           # "!word": handled on the raw line
                continue
            tests.append((idx, c.test, c.negate))
            if c.needles:
                groups.append(c.needles)
        groups.sort(key=lambda g: -min(map(len, g)))
        hit = _COMPILED[key] = (tests, groups, anti, colmap)
    return hit


def scan_chunk(task: dict):
    """Scan one byte range of one file. Returns (records, matches, payload)."""
    if _stale(task):
        return None
    with open(task["path"], "rb") as fh:
        fh.seek(task["start"])
        data = fh.read(task["end"] - task["start"])
    text = data.decode("utf-8", "replace")
    del data
    if "\r" in text:
        text = text.replace("\r\n", "\n")
    recs = split_records(text)
    del text
    total = len(recs)
    tests, groups, anti, colmap = _compile(task)
    mode, delim, limit = task["mode"], task["delim"], task["limit"]
    if tests is None:
        return total, 0, Counter() if mode == "values" else []
    for g in groups:                          # cheap rejection before any parsing
        if len(g) == 1:
            a = g[0]
            recs = [r for r in recs if a in r.lower()]
        else:
            recs = [r for r in recs if _any_in(g, r.lower())]
    for g in anti:
        if delim not in "".join(g):
            recs = [r for r in recs if not _any_in(g, r.lower())]
        else:                                 # needle could span two cells: test per cell
            tests = tests + [(None, build_test("~", "|".join(g)), True)]
    if _stale(task):
        return None

    col = colmap[task["col"]] if mode == "values" else -1
    counts: Counter = Counter()
    rows: list = []
    if not tests and mode != "values":
        matched = len(recs)
        rows = parse_records(recs[:limit] if mode == "rows" else recs, delim)
    else:
        # Split only as far as the last column needed; rows to return are re-split in full.
        cut = -1 if any(t[0] is None for t in tests) else max([t[0] for t in tests] + [col]) + 1
        keep = limit if mode == "rows" else (0 if mode == "values" else len(recs))
        matched = 0
        for r in recs:
            if '"' in r:
                row = next(csv.reader([r], delimiter=delim), [])
                n, partial = len(row), False
            else:
                row = r.split(delim, cut)
                partial = cut >= 0
                n = min(len(row), cut) if partial else len(row)
            for idx, test, neg in tests:
                if idx is None:
                    hit = any(test(c) for c in row)
                else:
                    hit = idx < n and bool(test(row[idx]))
                if hit == neg:
                    break
            else:
                matched += 1
                if col >= 0:
                    counts[row[col].strip() if col < n else ""] += 1
                elif len(rows) < keep:
                    rows.append(r.split(delim) if partial else row)
    if mode == "rows":
        return total, matched, rows
    if mode == "values":
        return total, matched, counts
    idx = [colmap.get(c) for c in task["cols"]]             # mode == "export"
    name = task["name"]
    with open(task["part"], "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(
            [name] + [r[i] if i is not None and i < len(r) else "" for i in idx] for r in rows)
    return total, matched, None


def _any_in(alts, low: str) -> bool:
    for a in alts:
        if a in low:
            return True
    return False


class Engine:
    """Owns the worker processes. Lives in the UI process; does no heavy work itself."""

    def __init__(self, procs: int | None = None):
        n = procs or max(1, min(os.cpu_count() or 2, 8))
        try:
            self.gens = multiprocessing.Array("q", 3, lock=False)
            self.pool = multiprocessing.Pool(n, _pool_init, (self.gens,))
            self.procs = n
        except Exception:                     # no multiprocessing here: use threads
            from multiprocessing.pool import ThreadPool
            self.gens = [0, 0, 0]
            self.pool = ThreadPool(1, _pool_init, (self.gens,))
            self.procs = 0

    def close(self) -> None:
        try:
            self.pool.terminate()
        except Exception:
            pass

    def bump(self, slot: int) -> int:
        """Start a new job in this slot; queued work of the previous one is dropped."""
        self.gens[slot] += 1
        return self.gens[slot]

    def plan(self, f: CsvFile) -> None:
        f.plan = self.pool.apply_async(plan_file, (str(f.path), f.delim))

    @staticmethod
    def _wait(result, cancelled):
        while not result.ready():
            if cancelled():
                return None
            result.wait(0.05)
        try:
            return result.get()
        except Exception as e:
            return e

    def run(self, files, base: dict, cancelled, per_task=None):
        """Scan files chunk by chunk; yields (file, result, bytes) in file order.

        result is scan_chunk()'s tuple, or an Exception / error string.
        """
        window = max(2, 2 * max(1, self.procs))
        pending: deque = deque()

        def take():
            f, ar, nbytes = pending.popleft()
            res = self._wait(ar, cancelled)
            return None if res is None else (f, res, nbytes)

        for f in files:
            plan = self._wait(f.plan, cancelled)
            if plan is None:
                return
            if isinstance(plan, Exception) or "error" in plan:
                yield f, str(plan if isinstance(plan, Exception) else plan["error"]), f.size
                continue
            offs = plan["offsets"]
            for a, b in zip(offs, offs[1:]):
                while len(pending) >= window:
                    got = take()
                    if got is None:
                        return
                    yield got
                task = dict(base, path=str(f.path), name=f.path.name, start=a, end=b,
                            delim=f.delim, header=tuple(f.header))
                if per_task:
                    per_task(task)
                pending.append((f, self.pool.apply_async(scan_chunk, (task,)), b - a))
        while pending:
            got = take()
            if got is None:
                return
            yield got


INDEX_ROWS = 5_000       # rows per file sampled for value suggestions
INDEX_DISTINCT = 5_000   # distinct values remembered per column
MAX_HINTS = 8


class TabInput(Input):
    """Input where Tab accepts the inline suggestion (if there is one)."""

    async def _on_key(self, event) -> None:
        if (event.key == "tab" and self._suggestion
                and self._suggestion != self.value
                and self.cursor_position >= len(self.value)):
            event.stop()
            event.prevent_default()
            self.value = self._suggestion
            self.cursor_position = len(self.value)
            return
        await super()._on_key(event)


class FilterSuggester(Suggester):
    def __init__(self, owner) -> None:
        super().__init__(use_cache=False, case_sensitive=True)
        self.owner = owner

    async def get_suggestion(self, value: str):
        found = self.owner.suggest(value)
        return found[0][0] if found else None


class FilterInput(TabInput):
    """Filter box that turns dropped/pasted paths into 'add files'."""

    def _on_paste(self, event) -> None:
        paths = parse_dropped(event.text)
        if paths:
            event.stop()
            event.prevent_default()
            self.app.add_paths(paths)
            return
        return super()._on_paste(event)


class TextScreen(ModalScreen):
    BINDINGS = [Binding("escape,enter,q,f1,f3", "dismiss", "Close")]
    DEFAULT_CSS = """
    TextScreen { align: center middle; }
    TextScreen > VerticalScroll {
        width: 90%; height: 85%; border: round $accent;
        background: $surface; padding: 1 2;
    }
    """

    def __init__(self, body: Text):
        super().__init__()
        self.body = body

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(self.body)

    def on_mount(self) -> None:
        self.query_one(VerticalScroll).focus()

    def action_dismiss(self) -> None:
        self.dismiss()


MAX_VALUES = 1000        # distinct values listed by F4


def make_term(col: str, value: str) -> str:
    """Filter term that exactly matches `value` in column `col`."""
    if re.search(r"[|*?]", value) or value.startswith("/"):
        value = "/^\\s*" + re.escape(value).replace("\\ ", " ") + "\\s*$/"
    term = f"{col}={value}"
    if re.search(r"\s", term):
        q = "'" if '"' in term else '"'
        term = f"{q}{term}{q}"
    return term


class ValuesScreen(ModalScreen):
    """Distinct values of one column, with counts, within the current filter."""
    BINDINGS = [Binding("escape", "close", "Close"), Binding("f4", "close", "Close")]
    DEFAULT_CSS = """
    ValuesScreen { align: center middle; }
    ValuesScreen > Vertical {
        width: 90%; height: 85%; border: round $accent;
        background: $surface; padding: 1 2;
    }
    ValuesScreen #vstatus { height: 1; color: $text-muted; }
    ValuesScreen DataTable { height: 1fr; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.col: str | None = None
        self.values: list[str] = []

    def compose(self) -> ComposeResult:
        names = list(self.app.known.values())
        with Vertical():
            yield TabInput(id="vcol", placeholder="column name, then Enter  (e.g. action)",
                        suggester=SuggestFromList(names, case_sensitive=False))
            yield Static("Type a column name. Tab accepts the suggestion.", id="vstatus")
            yield DataTable(zebra_stripes=True, cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#vcol").focus()

    def action_close(self) -> None:
        self.workers.cancel_group(self, "values")
        self.app.engine.bump(SLOT_VALUES)
        self.dismiss(None)

    def status(self, msg: str) -> None:
        self.query_one("#vstatus", Static).update(Text(msg, no_wrap=True, overflow="ellipsis"))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        known = self.app.known
        col = norm(event.value)
        if col not in known:
            starts = [n for n in known if n.startswith(col)] if col else []
            if len(starts) == 1:
                col = starts[0]
            else:
                near = starts[:6] or difflib.get_close_matches(col, list(known), n=5, cutoff=0.4)
                self.status(f"Unknown column '{event.value}'."
                            + ("  Did you mean: " + ", ".join(known[n] for n in near) if near else ""))
                return
        event.input.value = known[col]
        self.col = col
        table = self.query_one(DataTable)
        table.clear(columns=True)
        table.add_columns(known[col], "count", "%")
        self.values = []
        self.count(col)

    @work(thread=True, exclusive=True, group="values")
    def count(self, col: str) -> None:
        worker = get_current_worker()
        app = self.app
        files = [f for f in app.files.values() if col in f.colmap]
        base = app.task_base(SLOT_VALUES, "values", app.query_text, col=col)
        counts: Counter = Counter()
        scanned, last = 0, 0.0
        for f, res, _ in app.engine.run(files, base, lambda: worker.is_cancelled):
            if isinstance(res, tuple):
                scanned += res[0]
                counts.update(res[2])
            if time.monotonic() - last > 0.2 and not worker.is_cancelled:
                last = time.monotonic()
                app.call_from_thread(self.status, f"counting… {scanned:,} rows scanned")
        if not worker.is_cancelled:
            app.call_from_thread(self.show, col, counts, len(files))

    def show(self, col: str, counts: Counter, nfiles: int) -> None:
        if col != self.col:
            return
        total = sum(counts.values())
        top = counts.most_common(MAX_VALUES)
        self.values = [v for v, _ in top]
        table = self.query_one(DataTable)
        table.add_rows([
            (v if len(v) <= 80 else v[:79] + "…") if v else Text("(empty)", style="dim"),
             Text(f"{n:,}", justify="right"), Text(f"{100 * n / total:.1f}", justify="right")]
            for v, n in top)
        msg = f"{len(counts):,} distinct values in {total:,} rows from {nfiles} file(s)"
        if self.app.query_text.strip():
            msg += " matching the current filter"
        if len(counts) > MAX_VALUES:
            msg += f" · showing top {MAX_VALUES:,}"
        self.status(msg + " · Enter on a value filters by it")
        if top:
            table.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        if self.col and 0 <= event.cursor_row < len(self.values):
            self.dismiss((self.app.known[self.col], self.values[event.cursor_row]))


class LogSift(App):
    TITLE = "logsift"
    CSS = """
    #status { height: 1; padding: 0 1; color: $text-muted; }
    #hint { height: 1; padding: 0 1; color: $accent; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        Binding("f1", "help", "Help", priority=True),
        Binding("f2", "toggle_cols", "All/key columns", priority=True),
        Binding("f3", "files", "Files", priority=True),
        Binding("f4", "values", "Values", priority=True),
        Binding("f5", "export", "Export", priority=True),
        Binding("f8", "clear_files", "Clear files", priority=True),
        Binding("escape", "focus_filter", "Filter"),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    def __init__(self, paths: list[Path], max_rows: int, engine: Engine | None = None):
        super().__init__()
        self.engine = engine or Engine()
        self.query_text = ""                 # the filter as last run
        self.initial_paths = paths
        self.max_rows = max_rows
        self.files: dict[Path, CsvFile] = {}
        self.known: dict[str, str] = {}      # normalised name -> display name
        self.conds: list[Cond] = []
        self.show_all = False
        self.shown: list[tuple[CsvFile, list[str]]] = []   # results, up to max_rows
        self.loaded = 0                                     # how many are in the table
        self.gen = 0
        self.value_index: dict[str, list[str]] = {}   # column -> values, commonest first
        self._value_counts: dict[str, Counter] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        self.w_filter = FilterInput(
            id="filter",
            suggester=FilterSuggester(self),
            placeholder="src=10.1.1.5 action=drop|reject dst=192.168.0.0/16 "
                        "fw_message~timeout   |   drop files/folders here   |   F1 help",
        )
        self.w_status = Static(id="status")
        self.w_table = DataTable(zebra_stripes=True, cursor_type="row")
        self.w_hint = Static(id="hint")
        yield self.w_filter
        yield self.w_hint
        yield self.w_status
        yield self.w_table
        yield Footer()

    def on_mount(self) -> None:
        self.w_filter.focus()
        self.watch(self.w_table, "scroll_y", lambda *_: self._fill(), init=False)
        if self.initial_paths:
            self.add_paths(self.initial_paths)
        else:
            self.set_status("Drag a folder or CSV files onto this window "
                            "(or paste a path and press Enter).")

    # ---- status -----------------------------------------------------------

    def set_status(self, msg: str, error: bool = False) -> None:
        self.w_status.update(
            Text(msg, style="bold red" if error else "", no_wrap=True, overflow="ellipsis"))

    # ---- suggestions ------------------------------------------------------

    def suggest(self, text: str) -> list[tuple[str, str]]:
        """Completions for the term being typed: [(full filter text, label), ...]."""
        start, quote = 0, None
        for i, ch in enumerate(text):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch.isspace():
                start = i + 1
        tok = text[start:]
        if not tok:
            return []
        lead = tok[0] if tok[0] in "\"'" else ""
        body = tok[len(lead):]
        if lead and quote is None:               # token already closed its quote
            return []
        out: list[tuple[str, str]] = []

        for m in OP_RE.finditer(body):
            left = body[:m.start()]
            if not (left.strip() and norm(left) in self.known):
                continue
            rest = body[m.end():]
            if m.group() not in ("=", "!=", "~", "!~") or rest.startswith("/"):
                return []
            vq = ""
            if not lead and rest[:1] in ("\"", "'"):
                vq, rest = rest[0], rest[1:]
            closing = lead or vq
            if (quote is not None) != bool(closing):
                return []
            partial = rest.rpartition("|")[2]
            low = partial.lower()
            for v in self.value_index.get(norm(left), ()):
                if len(v) <= len(partial) or not v.lower().startswith(low):
                    continue
                if '"' in v or "'" in v or (not closing and re.search(r"[\s|]", v)):
                    continue
                out.append((text + v[len(partial):] + closing, v))
                if len(out) >= MAX_HINTS:
                    break
            return out

        if quote and not lead or body[:1] in ("!", "~"):
            return []
        low = body.lower()
        names = []
        for disp in self.known.values():
            name = disp.rstrip(":").strip()
            if name.lower().startswith(low) and (lead or " " not in name):
                names.append(name)
        names.sort(key=lambda n: (len(n) != len(body), n not in PREFERRED, n.lower()))
        return [(text + n[len(body):] + "=", n) for n in names[:MAX_HINTS]]

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input is not self.w_filter:
            return
        found = self.suggest(event.value)
        hint = Text(no_wrap=True, overflow="ellipsis")
        if found:
            hint.append("Tab ", style="bold")
            hint.append(found[0][1])
            if len(found) > 1:
                hint.append("   also: " + " · ".join(label for _, label in found[1:]), style="dim")
        self.w_hint.update(hint)

    @work(thread=True, group="index")
    def build_index(self, files: list[CsvFile]) -> None:
        """Collect the value samples the worker processes took of each new file."""
        worker = get_current_worker()
        for f in files:
            plan = Engine._wait(f.plan, lambda: worker.is_cancelled)
            if plan is None:
                return
            if isinstance(plan, Exception) or "error" in plan:
                continue
            for i, pairs in plan["sample"].items():
                if i < len(f.header) and f.header[i]:
                    c = self._value_counts.setdefault(norm(f.header[i]), Counter())
                    for v, n in pairs:
                        if v in c or len(c) < INDEX_DISTINCT:
                            c[v] += n
        self.value_index = {k: [v for v, _ in c.most_common()]
                            for k, c in list(self._value_counts.items())}

    # ---- files ------------------------------------------------------------

    def on_paste(self, event) -> None:          # paste while the table is focused
        paths = parse_dropped(event.text)
        if paths:
            event.stop()
            self.add_paths(paths)

    def add_paths(self, paths: list[Path]) -> None:
        added, bad, new = 0, [], []
        for p in paths:
            try:
                p = p.resolve()
                if p.is_dir():
                    found = sorted(q for q in p.rglob("*")
                                   if q.is_file() and q.suffix.lower() == ".csv")
                else:
                    found = [p]
                for q in found:
                    if q not in self.files:
                        f = self.files[q] = CsvFile(q)
                        self.engine.plan(f)
                        new.append(f)
                        added += 1
            except OSError as e:
                bad.append(f"{p.name}: {e}")
        self.known = {}
        for f in self.files.values():
            for h in f.header:
                if h:
                    self.known.setdefault(norm(h), h)
        if bad:
            self.notify("\n".join(bad[:5]), severity="error")
        self.notify(f"Added {added} file(s); {len(self.files)} loaded.")
        self.build_index(new)
        self.start_search()

    def action_clear_files(self) -> None:
        self.gen += 1
        self.workers.cancel_group(self, "scan")
        self.workers.cancel_group(self, "index")
        self.engine.bump(SLOT_SCAN)
        self.value_index, self._value_counts = {}, {}
        self.files, self.known, self.shown, self.loaded = {}, {}, [], 0
        self.w_table.clear(columns=True)
        self.set_status("No files loaded. Drag a folder or CSV files onto this window.")

    # ---- searching --------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        paths = parse_dropped(event.value)
        if paths:                                # path typed/dropped without paste
            event.input.value = ""
            self.add_paths(paths)
        else:
            self.start_search()

    def visible_columns(self) -> list[str]:
        if self.show_all:
            return list(self.known)
        cols = [c for c in PREFERRED if c in self.known]
        for c in self.conds:                     # always show what you filter on
            if c.col and c.col not in cols:
                cols.append(c.col)
        return cols or list(self.known)[:15]

    def task_base(self, slot: int, mode: str, query: str, **extra) -> dict:
        return dict(slot=slot, gen=self.engine.bump(slot), mode=mode, query=query,
                    known=tuple(self.known.items()), limit=self.max_rows, **extra)

    def usable_files(self, conds: list[Cond]) -> tuple[list[CsvFile], int]:
        """Files that have every column the filter needs, and how many do not."""
        need = {c.col for c in conds if c.col and not c.negate}
        files = [f for f in self.files.values() if need <= f.colmap.keys()]
        return files, len(self.files) - len(files)

    def start_search(self) -> None:
        if not self.files:
            self.set_status("No files loaded. Drag a folder or CSV files onto this window.")
            return
        text = self.w_filter.value
        try:
            self.conds = parse_query(text, self.known)
        except QueryError as e:
            self.set_status(str(e), error=True)
            return
        self.query_text = text
        self.gen += 1
        cols = self.visible_columns()
        table = self.w_table
        table.clear(columns=True)
        table.add_column("file")
        for c in cols:
            table.add_column(self.known[c])
        self.shown, self.loaded = [], 0
        files, skipped = self.usable_files(self.conds)
        self.scan(self.gen, files, skipped, self.task_base(SLOT_SCAN, "rows", text))

    @work(thread=True, exclusive=True, group="scan")
    def scan(self, gen: int, files: list[CsvFile], skipped: int, base: dict) -> None:
        worker = get_current_worker()
        total_bytes = sum(f.size for f in files) or 1
        scanned = matched = done_bytes = shown = 0
        errors: list[str] = []
        batch: list = []
        t0 = last = time.monotonic()

        def status(done: bool = False) -> str:
            msg = f"{len(files):,} files · {scanned:,} rows scanned · {matched:,} matches"
            if matched > self.max_rows:
                msg += f" (showing first {self.max_rows:,}; F5 exports all)"
            if done:
                msg += f" · {time.monotonic() - t0:.1f}s"
                if skipped:
                    msg += f" · {skipped} file(s) lack a filtered column"
                if errors:
                    msg += f" · {len(errors)} read error(s): {errors[0]}"
            else:
                msg += f" · {min(99, 100 * done_bytes // total_bytes)}%…"
            return msg

        def flush(done: bool = False) -> None:
            nonlocal batch, last
            rows, batch = batch, []
            last = time.monotonic()
            if not worker.is_cancelled:
                self.call_from_thread(self._apply, gen, rows, status(done))

        def per_task(task: dict) -> None:
            task["limit"] = max(0, self.max_rows - matched)

        for f, res, nbytes in self.engine.run(files, base, lambda: worker.is_cancelled, per_task):
            done_bytes += nbytes
            if isinstance(res, tuple):
                scanned += res[0]
                matched += res[1]
                room = self.max_rows - shown
                if room > 0 and res[2]:
                    rows = res[2][:room]
                    shown += len(rows)
                    batch.extend((f, r) for r in rows)
            else:
                errors.append(f"{f.path.name}: {res}")
            if batch or time.monotonic() - last > 0.15:
                flush()
        if not worker.is_cancelled:
            flush(done=True)

    def _apply(self, gen: int, rows, msg: str) -> None:
        if gen != self.gen:
            return
        if rows:
            self.shown.extend(rows)
            self._fill()
        self.set_status(msg)

    def _fill(self) -> None:
        """Put result rows into the table a page at a time, as the user nears them.

        Filling the table is the costly part of showing results, so only rows
        near the cursor / scroll position are added; the rest wait in self.shown.
        """
        table = self.w_table
        if isinstance(self.screen, ModalScreen) and self.loaded >= PAGE:
            return
        cols = self._current_cols
        ahead = max(2 * table.size.height, min(PAGE, 6000 // (len(cols) + 1)))
        want = max(table.cursor_row, int(table.scroll_y) + table.size.height) + ahead
        want = min(want, len(self.shown))
        if self.loaded >= want:
            return
        step = max(5, 1000 // (len(cols) + 1))
        chunk = self.shown[self.loaded:min(want, self.loaded + step)]
        out = []
        for f, row in chunk:
            cells = [Text(f.path.name)]
            for c in cols:
                i = f.colmap.get(c)
                v = row[i] if i is not None and i < len(row) else ""
                cells.append(Text(v if len(v) <= CELL_WIDTH else v[:CELL_WIDTH - 1] + "…"))
            out.append(cells)
        table.add_rows(out)
        self.loaded += len(chunk)
        if self.loaded < want:
            self.set_timer(0.02, self._fill)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table is self.w_table:
            self._fill()

    @property
    def _current_cols(self) -> list[str]:
        # column labels on screen, minus the leading "file" column
        table = self.w_table
        return [norm(str(c.label)) for c in table.columns.values()][1:]

    # ---- actions ----------------------------------------------------------

    def action_focus_filter(self) -> None:
        self.w_filter.focus()

    def check_action(self, action: str, parameters) -> bool:
        if action in ("toggle_cols", "export", "clear_files", "help", "files"):
            return not isinstance(self.screen, ModalScreen)
        return True

    def action_toggle_cols(self) -> None:
        self.show_all = not self.show_all
        self.start_search()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not 0 <= event.cursor_row < len(self.shown):
            return
        f, row = self.shown[event.cursor_row]
        body = Text()
        body.append(f"{f.path}\n\n", style="bold")
        width = max((len(h) for h in f.header), default=0)
        for h, v in zip(f.header, row):
            if v.strip():
                body.append(f"{h:>{width}}  ", style="cyan")
                body.append(v + "\n")
        body.append("\n(empty fields hidden · Esc to close)", style="dim")
        self.push_screen(TextScreen(body))

    def action_help(self) -> None:
        body = Text(__doc__.strip() + "\n\n")
        body.append(f"Columns in loaded files ({len(self.known)})\n", style="bold")
        body.append("  " + "\n  ".join(self.known.values()) if self.known else "  (no files loaded)")
        self.push_screen(TextScreen(body))

    def action_files(self) -> None:
        body = Text()
        body.append(f"{len(self.files)} file(s) loaded\n\n", style="bold")
        for f in self.files.values():
            body.append(f"{f.path}  ", style="cyan")
            body.append(f"({len(f.header)} columns)\n", style="dim")
        self.push_screen(TextScreen(body))

    def action_values(self) -> None:
        if isinstance(self.screen, ValuesScreen):
            self.screen.action_close()
            return
        if not self.files:
            self.set_status("No files loaded. Drag a folder or CSV files onto this window.")
            return

        def picked(result) -> None:
            if result:
                inp = self.w_filter
                inp.value = (inp.value.strip() + " " + make_term(*result)).strip()
                self.start_search()

        self.push_screen(ValuesScreen(), picked)

    def action_export(self) -> None:
        if not self.files:
            return
        text = self.w_filter.value
        try:
            conds = parse_query(text, self.known)
        except QueryError as e:
            self.set_status(str(e), error=True)
            return
        out = Path.cwd() / f"logsift_export_{dt.datetime.now():%Y%m%d_%H%M%S}.csv"
        self.notify(f"Exporting to {out.name}…")
        cols = list(self.known)
        files, _ = self.usable_files(conds)
        self.export(files, self.task_base(SLOT_EXPORT, "export", text, cols=cols), cols, out)

    @work(thread=True, exclusive=True, group="export")
    def export(self, files, base: dict, cols, out: Path) -> None:
        """Workers write each chunk's matches to a part file; parts are joined in order."""
        worker = get_current_worker()
        n, parts, tmp = 0, 0, None
        try:
            tmp = Path(tempfile.mkdtemp(prefix=".logsift_export_", dir=out.parent))

            queued: deque = deque()

            def per_task(task: dict) -> None:
                nonlocal parts
                parts += 1
                task["part"] = str(tmp / f"{parts:08d}.csv")
                queued.append(task["part"])

            with open(out, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(["source_file"] + [self.known[c] for c in cols])
            with open(out, "ab") as fh:
                for f, res, _ in self.engine.run(files, base, lambda: worker.is_cancelled, per_task):
                    if isinstance(res, str):          # file could not be read at all
                        continue
                    part = queued.popleft()
                    if not isinstance(res, tuple):
                        continue
                    n += res[1]
                    with open(part, "rb") as src:
                        shutil.copyfileobj(src, fh, 1 << 20)
                    os.unlink(part)
        except OSError as e:
            self.call_from_thread(self.notify, f"Export failed: {e}", severity="error")
            return
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
        if not worker.is_cancelled:
            self.call_from_thread(self.notify, f"Exported {n:,} rows to {out}", timeout=10)


def main() -> None:
    ap = argparse.ArgumentParser(description="TUI to search/filter many CSV log files.")
    ap.add_argument("paths", nargs="*", type=Path, help="CSV files or folders to load")
    ap.add_argument("--max-rows", type=int, default=2000,
                    help="max matching rows shown in the table (default 2000)")
    args = ap.parse_args()
    missing = [p for p in args.paths if not p.exists()]
    if missing:
        sys.exit("Not found: " + ", ".join(map(str, missing)))
    engine = Engine()             # start worker processes before the UI takes the terminal
    try:
        LogSift(args.paths, args.max_rows, engine).run()
    finally:
        engine.close()


if __name__ == "__main__":
    main()
