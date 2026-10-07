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
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import difflib
import fnmatch
import ipaddress
import os
import re
import sys
import time
from collections import Counter
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
CELL_WIDTH = 48          # long cells are truncated in the table (not in details)
TICK = 20_000            # rows between progress updates / cancel checks


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
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            first = fh.readline()
        self.delim = max(",;\t|", key=lambda d: first.count(d)) if first.strip() else ","
        self.header = next(csv.reader([first], delimiter=self.delim), [])
        self.header = [h.strip() for h in self.header]
        self.colmap: dict[str, int] = {}
        for i, h in enumerate(self.header):
            self.colmap.setdefault(norm(h), i)

    def rows(self):
        with open(self.path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            rd = csv.reader(fh, delimiter=self.delim)
            next(rd, None)
            yield from rd


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
            if net is not None:
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


class Cond:
    """One filter term. col is a normalised column name, or None for 'any column'."""

    def __init__(self, col: str | None, op: str, raw: str):
        self.col = col
        self.negate = op.startswith("!")
        self.test = build_test(op.lstrip("!") or "~", raw)


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


def iter_matches(files, conds, cancelled, stats, tick=None):
    """Yield (file, row) for every row matching all conds. Updates stats['scanned']."""
    for f in files:
        compiled, skip = [], False
        for c in conds:
            idx = None if c.col is None else f.colmap.get(c.col, -1)
            if idx == -1:
                if c.negate:
                    continue          # column absent: "not X" is trivially true
                skip = True           # column absent: positive test can't match
                break
            compiled.append((idx, c.test, c.negate))
        stats["file"] = f.path.name
        if skip:
            stats["skipped"] += 1
            continue
        n = 0
        try:
            for row in f.rows():
                n += 1
                if n % TICK == 0:
                    stats["scanned"] += TICK
                    if cancelled():
                        return
                    if tick:
                        tick()
                ok = True
                for idx, test, neg in compiled:
                    if idx is None:
                        hit = any(test(c) for c in row)
                    else:
                        hit = idx < len(row) and bool(test(row[idx]))
                    if hit == neg:
                        ok = False
                        break
                if ok:
                    yield f, row
        except (OSError, csv.Error) as e:
            stats["errors"].append(f"{f.path.name}: {e}")
        stats["scanned"] += n % TICK


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

INDEX_ROWS = 20_000      # rows per file sampled for value suggestions
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
        stats = {"scanned": 0, "skipped": 0, "errors": [], "file": ""}
        counts: Counter = Counter()

        def tick() -> None:
            app.call_from_thread(self.status, f"counting… {stats['scanned']:,} rows scanned")

        for f, row in iter_matches(files, list(app.conds), lambda: worker.is_cancelled, stats, tick):
            i = f.colmap[col]
            counts[row[i].strip() if i < len(row) else ""] += 1
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
        if self.app.conds:
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

    def __init__(self, paths: list[Path], max_rows: int):
        super().__init__()
        self.initial_paths = paths
        self.max_rows = max_rows
        self.files: dict[Path, CsvFile] = {}
        self.known: dict[str, str] = {}      # normalised name -> display name
        self.conds: list[Cond] = []
        self.show_all = False
        self.shown: list[tuple[CsvFile, list[str]]] = []
        self.gen = 0
        self.value_index: dict[str, list[str]] = {}   # column -> values, commonest first

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

    @work(thread=True, exclusive=True, group="index")
    def build_index(self, files: list[CsvFile]) -> None:
        """Sample each file to learn which values occur in which column."""
        worker = get_current_worker()
        counts: dict[str, Counter] = {}
        for f in files:
            cols = [(i, counts.setdefault(norm(h), Counter()))
                    for i, h in enumerate(f.header) if h]
            try:
                for n, row in enumerate(f.rows()):
                    if n >= INDEX_ROWS:
                        break
                    if n % 2000 == 0 and worker.is_cancelled:
                        return
                    for i, c in cols:
                        if i < len(row):
                            v = row[i].strip()
                            if v and len(v) <= 60 and (v in c or len(c) < INDEX_DISTINCT):
                                c[v] += 1
            except (OSError, csv.Error):
                pass
            self.value_index = {k: [v for v, _ in c.most_common()] for k, c in counts.items()}

    # ---- files ------------------------------------------------------------

    def on_paste(self, event) -> None:          # paste while the table is focused
        paths = parse_dropped(event.text)
        if paths:
            event.stop()
            self.add_paths(paths)

    def add_paths(self, paths: list[Path]) -> None:
        added, bad = 0, []
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
                        self.files[q] = CsvFile(q)
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
        self.build_index(list(self.files.values()))
        self.start_search()

    def action_clear_files(self) -> None:
        self.gen += 1
        self.workers.cancel_group(self, "scan")
        self.workers.cancel_group(self, "index")
        self.value_index = {}
        self.files, self.known, self.shown = {}, {}, []
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

    def start_search(self) -> None:
        if not self.files:
            self.set_status("No files loaded. Drag a folder or CSV files onto this window.")
            return
        try:
            self.conds = parse_query(self.w_filter.value, self.known)
        except QueryError as e:
            self.set_status(str(e), error=True)
            return
        self.gen += 1
        cols = self.visible_columns()
        table = self.w_table
        table.clear(columns=True)
        table.add_column("file")
        for c in cols:
            table.add_column(self.known[c])
        self.shown = []
        self.scan(self.gen, list(self.files.values()), list(self.conds), cols)

    @work(thread=True, exclusive=True, group="scan")
    def scan(self, gen: int, files: list[CsvFile], conds: list[Cond], cols: list[str]) -> None:
        worker = get_current_worker()
        stats = {"scanned": 0, "skipped": 0, "errors": [], "file": ""}
        matched, batch, t0 = 0, [], time.monotonic()

        def flush(done: bool = False) -> None:
            nonlocal batch
            rows, batch = batch, []
            msg = f"{len(files):,} files · {stats['scanned']:,} rows scanned · {matched:,} matches"
            if matched > self.max_rows:
                msg += f" (showing first {self.max_rows:,}; F5 exports all)"
            if done:
                msg += f" · {time.monotonic() - t0:.1f}s"
                if stats["skipped"]:
                    msg += f" · {stats['skipped']} file(s) lack a filtered column"
                if stats["errors"]:
                    msg += f" · {len(stats['errors'])} read error(s)"
            else:
                msg += f" · scanning {stats['file']}…"
            if not worker.is_cancelled:
                self.call_from_thread(self._apply, gen, rows, msg)

        for f, row in iter_matches(files, conds, lambda: worker.is_cancelled, stats, flush):
            matched += 1
            if matched <= self.max_rows:
                batch.append((f, row))
                if len(batch) >= 500:
                    flush()
        if not worker.is_cancelled:
            flush(done=True)

    def _apply(self, gen: int, rows, msg: str) -> None:
        if gen != self.gen:
            return
        if rows:
            cols = self._current_cols
            table = self.w_table
            out = []
            for f, row in rows:
                cells = [f.path.name]
                for c in cols:
                    i = f.colmap.get(c)
                    v = row[i] if i is not None and i < len(row) else ""
                    cells.append(v if len(v) <= CELL_WIDTH else v[:CELL_WIDTH - 1] + "…")
                out.append(cells)
            table.add_rows(out)
            self.shown.extend(rows)
        self.set_status(msg)

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
        try:
            conds = parse_query(self.w_filter.value, self.known)
        except QueryError as e:
            self.set_status(str(e), error=True)
            return
        out = Path.cwd() / f"logsift_export_{dt.datetime.now():%Y%m%d_%H%M%S}.csv"
        self.notify(f"Exporting to {out.name}…")
        self.export(list(self.files.values()), conds, list(self.known), out)

    @work(thread=True, exclusive=True, group="export")
    def export(self, files, conds, cols, out: Path) -> None:
        worker = get_current_worker()
        stats = {"scanned": 0, "skipped": 0, "errors": [], "file": ""}
        n = 0
        try:
            with open(out, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["source_file"] + [self.known[c] for c in cols])
                proj: dict[Path, list] = {}
                for f, row in iter_matches(files, conds, lambda: worker.is_cancelled, stats):
                    idx = proj.get(f.path)
                    if idx is None:
                        idx = proj[f.path] = [f.colmap.get(c) for c in cols]
                    w.writerow([f.path.name] + [
                        row[i] if i is not None and i < len(row) else "" for i in idx])
                    n += 1
        except OSError as e:
            self.call_from_thread(self.notify, f"Export failed: {e}", severity="error")
            return
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
    LogSift(args.paths, args.max_rows).run()


if __name__ == "__main__":
    main()
