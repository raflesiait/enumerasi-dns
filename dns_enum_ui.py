#!/usr/bin/env python3
import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Tuple, List

import dns.resolver
import dns.exception
import dns.message
import dns.query
import dns.rdatatype

from rich.console import Console
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    SpinnerColumn,
)
from rich.table import Table

console = Console()


def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        raise FileNotFoundError(f"Wordlist not found or empty: {path}")
    lines = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # keep only the left-most label (dnsenum wordlists sometimes include dots)
            s = s.strip(".")
            lines.append(s)
    return lines


def make_resolver(nameserver: str, timeout: float) -> dns.resolver.Resolver:
    """
    Create a fresh resolver instance (avoid sharing between threads).
    """
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [nameserver]
    r.timeout = timeout
    r.lifetime = timeout
    r.search = []  # no search domains
    return r


def udp_tcp_query(
    nameserver: str,
    fqdn: str,
    rdtype: str,
    timeout: float,
    use_tcp_fallback: bool = True,
) -> List[str]:
    """
    Raw query (UDP first, optional TCP fallback) to reduce false negatives on throttled servers.
    Returns list of answer strings.
    """
    q = dns.message.make_query(fqdn, rdtype)
    # UDP
    try:
        resp = dns.query.udp(q, nameserver, timeout=timeout)
        if resp.answer:
            out = []
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                    out.extend([r.to_text() for r in rrset])
            return out
        return []
    except Exception:
        if not use_tcp_fallback:
            return []
    # TCP fallback
    try:
        resp = dns.query.tcp(q, nameserver, timeout=timeout)
        if resp.answer:
            out = []
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                    out.extend([r.to_text() for r in rrset])
            return out
        return []
    except Exception:
        return []


def resolve_host(
    nameserver: str,
    fqdn: str,
    timeout: float,
    retries: int,
    tcp_fallback: bool,
    record_types: List[str],
) -> Tuple[str, Optional[str]]:
    """
    Try to resolve fqdn for given record types (default A).
    Adds retry + backoff + UDP/TCP fallback + CNAME handling.
    Returns (fqdn, "TYPE:value | TYPE:value ...") or None if not found.
    """
    fqdn_abs = fqdn.rstrip(".") + "."
    results = []

    # simple retry with small backoff; helps a LOT on lab DNS
    for attempt in range(retries + 1):
        try:
            for rtype in record_types:
                ans = udp_tcp_query(nameserver, fqdn_abs, rtype, timeout, use_tcp_fallback=tcp_fallback)
                for v in ans:
                    results.append(f"{rtype}:{v}")

            # If no A but has CNAME, try resolve target A (common pattern)
            if ("A" in record_types) and not any(x.startswith("A:") for x in results):
                cnames = udp_tcp_query(nameserver, fqdn_abs, "CNAME", timeout, use_tcp_fallback=tcp_fallback)
                for c in cnames:
                    results.append(f"CNAME:{c}")
                    # resolve A for cname target
                    a2 = udp_tcp_query(nameserver, c.rstrip(".") + ".", "A", timeout, use_tcp_fallback=tcp_fallback)
                    for v in a2:
                        results.append(f"A:{v}")

            if results:
                # de-dup but keep order
                seen = set()
                dedup = []
                for x in results:
                    if x not in seen:
                        seen.add(x)
                        dedup.append(x)
                return fqdn.rstrip("."), " | ".join(dedup)

            return fqdn.rstrip("."), None

        except Exception:
            # backoff and retry
            if attempt < retries:
                time.sleep(0.15 * (attempt + 1))
                continue
            return fqdn.rstrip("."), None

    return fqdn.rstrip("."), None


def main():
    ap = argparse.ArgumentParser(
        description="Fast DNS brute-force enumerator with realtime output + progress UI (dnsenum-like reliability)."
    )
    ap.add_argument("--dns", required=True, help="DNS server IP (authoritative), e.g. 10.129.22.65")
    ap.add_argument("--domain", required=True, help="Target domain, e.g. dev.inlanefreight.htb")
    ap.add_argument("--wordlist", required=True, help="Path to wordlist (one label per line)")
    ap.add_argument("--threads", type=int, default=60, help="Concurrency (default: 60) - too high can cause misses")
    ap.add_argument("--timeout", type=float, default=2.0, help="Timeout per query seconds (default: 2.0)")
    ap.add_argument("--retries", type=int, default=2, help="Retry count on timeouts/throttle (default: 2)")
    ap.add_argument("--tcp-fallback", action="store_true", help="Fallback to TCP if UDP fails (recommended)")
    ap.add_argument("--suffix", default="", help="Only show IPs ending with this suffix, e.g. .203")
    ap.add_argument("--out", default="", help="Save hits to file (optional)")
    ap.add_argument("--show-all", action="store_true", help="Print all resolved hosts (not just filtered)")
    ap.add_argument("--types", default="A", help="Record types to query, comma-separated. Default: A. Example: A,NS,MX")
    args = ap.parse_args()

    try:
        socket.inet_aton(args.dns)
    except OSError:
        console.print(f"[red]Invalid DNS server IP:[/red] {args.dns}")
        sys.exit(1)

    try:
        words = load_wordlist(args.wordlist)
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    record_types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    if not record_types:
        record_types = ["A"]

    total = len(words)
    hits: list[Tuple[str, str]] = []

    if args.out:
        Path(args.out).write_text("", encoding="utf-8")

    console.print(
        f"[bold]DNS Enum UI[/bold]  dns={args.dns}  domain={args.domain}  words={total}  threads={args.threads}  timeout={args.timeout}s  retries={args.retries}"
    )
    console.print(f"Types: {', '.join(record_types)}  | TCP fallback: {'ON' if args.tcp_fallback else 'OFF'}")
    if args.suffix:
        console.print(f"Filter: only IP ending with [bold]{args.suffix}[/bold]")
    console.print()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]progress[/bold]"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("•"),
        TextColumn("[cyan]{task.fields[rps]}[/cyan] q/s"),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
    )

    start = time.time()
    done = 0
    last_t = start
    last_done = 0

    with progress:
        task_id = progress.add_task("dns", total=total, rps="0.0")

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {}
            for w in words:
                fqdn = f"{w}.{args.domain}".strip(".")
                futures[ex.submit(
                    resolve_host,
                    args.dns,
                    fqdn,
                    args.timeout,
                    args.retries,
                    args.tcp_fallback,
                    record_types
                )] = fqdn

            for fut in as_completed(futures):
                fqdn, recs = fut.result()
                done += 1

                now = time.time()
                if now - last_t >= 0.5 or done == total:
                    interval = now - last_t
                    interval_done = done - last_done
                    rps = (interval_done / interval) if interval > 0 else 0.0
                    progress.update(task_id, completed=done, rps=f"{rps:.1f}")
                    last_t = now
                    last_done = done
                else:
                    progress.update(task_id, completed=done)

                if not recs:
                    continue

                # Suffix filter applies to A records only
                matched = True
                if args.suffix:
                    matched = any(part.startswith("A:") and part.split("A:", 1)[1].strip().endswith(args.suffix)
                                  for part in recs.split("|"))

                if args.show_all or matched:
                    hits.append((fqdn, recs))
                    progress.console.print(f"[green][+][/green] {fqdn} -> {recs}")
                    if args.out:
                        with open(args.out, "a", encoding="utf-8") as f:
                            f.write(f"{fqdn}\t{recs}\n")

    elapsed = time.time() - start
    table = Table(title="Summary")
    table.add_column("Resolved hosts", justify="right")
    table.add_column("Elapsed", justify="right")
    table.add_column("DNS", justify="left")
    table.add_row(str(len(hits)), f"{elapsed:.1f}s", args.dns)
    console.print()
    console.print(table)

    if args.out:
        console.print(f"[bold]Saved hits:[/bold] {args.out}")


if __name__ == "__main__":
    main()
