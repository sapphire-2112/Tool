#!/usr/bin/env python3
"""
PS's tool - mini-netcat + threaded port scanner + simple recon/fingerprinting

Save as PS_tool.py and run:
  python3 PS_tool.py --man
  python3 PS_tool.py --scan 127.0.0.1
  python3 PS_tool.py --scan-range 127.0.0.1:1-200
  python3 PS_tool.py 127.0.0.1 5000        # client connect
  python3 PS_tool.py -l 5000               # listen server
Or run without args to enter interactive REPL.
"""
import argparse
import socket
import threading
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import time

BUFFER_SIZE = 4096

# ------------------------------------------------------------------
# Banner & Manual
# ------------------------------------------------------------------
def print_banner():
    banner = r"""
  ____  ____    _____           _ 
|  _ \/ ___|  |_   _|__   ___ | |
| |_) \___ \    | |/ _ \ / _ \| |
|  __/ ___) |   | | (_) | (_) | |
|_|   |____/    |_|\___/ \___/|_|

 (PS's tool - mini-netcat + scanner)
"""
    print(banner)

def print_man():
    man = r"""
NAME
    PS's tool - netcat-like client/server + threaded port scanner + simple recon

SYNOPSIS
    python3 PS_tool.py [OPTIONS] [host] [port]
    python3 PS_tool.py --scan HOST
    python3 PS_tool.py --scan-range HOST:START-END
    python3 PS_tool.py -l PORT
    python3 PS_tool.py               # enters interactive REPL

DESCRIPTION
    PS's tool is a lightweight TCP client/server and port scanner with basic
    banner grabbing and service fingerprinting.

OPTIONS
    -h, --help
        Show short help and exit.

    --man
        Show this manual page and exit.

    --verbose
        Print debug/verbose messages.

    -l, --listen
        Listen mode (server). Provide port as positional after -l.

    -k, --keep
        Keep listening after client disconnect (server stays up).

    --send-file, -sf FILE
        (client) Send FILE and exit.

    --output-file, -of FILE
        (server) Append received bytes to FILE.

    --scan, -s HOST
        Quick scan of common ports on HOST.

    --scan-range HOST:START-END
        Scan HOST for ports in the numeric range START-END (inclusive).

    --scan-timeout N
        Timeout per port in seconds. Default 0.5.

    --scan-threads N
        Number of concurrent threads for scanning. Default 100.

EXAMPLES
    # server
    python3 PS_tool.py -l 5000

    # client (connect)
    python3 PS_tool.py 127.0.0.1 5000

    # send file
    python3 PS_tool.py 127.0.0.1 5000 --send-file secret.bin

    # quick common ports scan
    python3 PS_tool.py --scan 192.168.1.10

    # range scan
    python3 PS_tool.py --scan-range 192.168.1.10:1-1024

    # interactive REPL
    python3 PS_tool.py

SAFETY
    Only scan hosts and networks you own or have explicit permission to test.
"""
    print(man)


# ------------------------------------------------------------------
# Low-level forwarding functions (client/server chat)
# ------------------------------------------------------------------
def forward_sock_to_stdout(sock):
    try:
        while True:
            data = sock.recv(BUFFER_SIZE)
            if not data:
                print("\n[!] Remote closed connection.")
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except Exception as e:
        print(f"[!] Read error: {e}")


def forward_stdin_to_sock(sock):
    try:
        while True:
            msg = sys.stdin.readline()
            if not msg:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                break
            sock.sendall(msg.encode())
    except (BrokenPipeError, OSError):
        print("[!] Connection lost.")


# ------------------------------------------------------------------
# Client/Server
# ------------------------------------------------------------------
def client_mode(host, port, send_file=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"[+] Connected to {host}:{port}")
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return

    try:
        if send_file:
            with open(send_file, "rb") as f:
                sent = 0
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    sent += len(chunk)
                    print(f"\r[+] Sent {sent} bytes", end="", flush=True)
            print("\n[+] File send complete.")
            sock.close()
            return

        t_recv = threading.Thread(target=forward_sock_to_stdout, args=(sock,), daemon=True)
        t_recv.start()
        forward_stdin_to_sock(sock)
        t_recv.join()

    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[*] Disconnected from server.")


def handle_client_connection(client_sock, addr, output_file=None):
    print(f"[+] Handling connection from {addr[0]}:{addr[1]}")
    if output_file:
        outpath = Path(output_file)
        with outpath.open("ab") as f:
            while True:
                data = client_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                f.write(data)
        print(f"[+] Data written to {output_file}")
    else:
        t_recv = threading.Thread(target=forward_sock_to_stdout, args=(client_sock,), daemon=True)
        t_recv.start()
        forward_stdin_to_sock(client_sock)
        t_recv.join()

    try:
        client_sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        client_sock.close()
    except Exception:
        pass
    print(f"[*] Connection closed with {addr[0]}:{addr[1]}")


def server_mode(port, keep=False, output_file=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[+] Listening on 0.0.0.0:{port}")

    try:
        while True:
            client_sock, addr = server.accept()
            print(f"[+] Connection from {addr}")
            t = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, addr, output_file),
                daemon=True
            )
            t.start()
            if not keep:
                t.join()
                break
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    finally:
        try:
            server.close()
        except Exception:
            pass


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        prog="PS_tool",
        description="PS's tool - netcat + scanner + recon"
    )
    p.add_argument("-l", "--listen", action="store_true", help="listen mode (server)")
    p.add_argument("-k", "--keep", action="store_true", help="keep listening after client disconnect")
    p.add_argument("--send-file", "-sf", dest="send_file", help="(client) send this file and exit")
    p.add_argument("--output-file", "-of", dest="output_file", help="(server) write received bytes to this file (append)")
    p.add_argument("host", nargs="?", help="host (client mode) or port (listen mode if -l)")
    p.add_argument("port", nargs="?", type=int, help="port (client mode)")
    # scanner flags
    p.add_argument("--scan", "-s", metavar="HOST", help="quick scan common ports on HOST")
    p.add_argument("--scan-range", metavar="HOST:START-END", help="scan HOST for ports in START-END (example: 192.168.1.10:1-1024)")
    p.add_argument("--scan-timeout", type=float, default=0.5, help="socket timeout (seconds) for scanning")
    p.add_argument("--scan-threads", type=int, default=100, help="threads to use for concurrent port scanning")
    p.add_argument("--man", action="store_true", help="show the manual page and exit")
    p.add_argument("--verbose", action="store_true", help="print debug/verbose messages")
    return p.parse_args()


# ------------------------------------------------------------------
# Port scanner: connect-based checks
# ------------------------------------------------------------------
COMMON_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080]

def is_port_open(host: str, port: int, timeout: float = 0.5) -> str:
    """Return 'open', 'closed', or 'filtered'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_ports(host: str, ports=None, start: int = None, end: int = None, timeout: float = 0.5, threads: int = 100):
    """
    Unified scanner:
      - if ports is provided (iterable of ints) it scans those ports.
      - otherwise start and end define an inclusive range.
    Returns dict: {"open": [...], "closed": [...], "filtered": [...]}
    """
    if ports is not None:
        port_iter = list(ports)
    else:
        if start is None or end is None:
            raise ValueError("Either ports or (start and end) must be provided.")
        port_iter = range(start, end + 1)

    results = {"open": [], "closed": [], "filtered": []}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_port = {ex.submit(is_port_open, host, p, timeout): p for p in port_iter}
        for future in as_completed(future_to_port):
            p = future_to_port[future]
            try:
                status = future.result()
            except Exception:
                status = "filtered"
            results[status].append(p)

    for k in results:
        results[k].sort()
    return results

def scan_common_ports(host: str, timeout: float = 0.5, threads: int = 50):
    return scan_ports(host, ports=COMMON_PORTS, timeout=timeout, threads=threads)

def parse_range_arg(s: str):
    """Parse 'host:1-1024' or '1-1024' -> (host_or_none, start, end)"""
    if ":" in s:
        host, rng = s.split(":", 1)
    else:
        host, rng = None, s
    start_s, end_s = rng.split("-", 1)
    return host, int(start_s), int(end_s)


# ------------------------------------------------------------------
# Banner grabbing, fingerprinting & enrichment
# ------------------------------------------------------------------
def grab_banner(host, port, timeout=0.6, recv_bytes=1024):
    """
    Connect to host:port, attempt to recv immediate banner.
    If nothing received quickly, send a tiny HTTP probe and try recv again.
    Returns decoded string or empty string on failure.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # try passive banner
        try:
            b = s.recv(recv_bytes)
            if b:
                return b.decode(errors='replace').strip()
        except socket.timeout:
            pass

        # try light HTTP probe (safe on most web servers)
        try:
            req = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
            s.sendall(req)
            b = s.recv(recv_bytes)
            return b.decode(errors='replace').strip() if b else ""
        except Exception:
            return ""
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass

# simple fingerprint rules and port hints
FINGERPRINT_RULES = [
    (r"^SSH-", "ssh"),
    (r"^220 .*smtp", "smtp"),
    (r"^220 .*ftp", "ftp"),
    (r"^HTTP/1\.", "http"),
    (r"^HTTP/2", "http"),
    (r"nginx", "nginx"),
    (r"apache", "apache"),
    (r"iis", "iis"),
    (r"mysql", "mysql"),
    (r"postgresql", "postgresql"),
    (r"RFB", "vnc"),
    (r"^250-STARTTLS", "smtp"),
]

PORT_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "smb",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-alt",
}

def fingerprint_banner(banner: str, port: int = None) -> str:
    """Return likely service name from banner text and optional port hint."""
    if not banner:
        return PORT_HINTS.get(port, "unknown")
    # use regex rules first
    for patt, svc in FINGERPRINT_RULES:
        try:
            if re.search(patt, banner, flags=re.I):
                return svc
        except re.error:
            continue
    # port hint fallback
    if port in PORT_HINTS:
        return PORT_HINTS[port]
    # substring heuristics
    b = banner.lower()
    if "ssh" in b:
        return "ssh"
    if "smtp" in b:
        return "smtp"
    if "http" in b or "html" in b:
        return "http"
    if "nginx" in b:
        return "nginx"
    if "mysql" in b:
        return "mysql"
    return "unknown"

def enrich_open_ports_with_services(host: str, open_ports: list, timeout: float = 0.8, threads: int = 20):
    """
    For each port in open_ports, run grab_banner(host, port) concurrently,
    then fingerprint the banner and return dict: port -> {"banner": ..., "service": ...}
    """
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_port = {ex.submit(grab_banner, host, p, timeout): p for p in open_ports}
        for future in as_completed(future_to_port):
            p = future_to_port[future]
            try:
                banner = future.result()
            except Exception:
                banner = ""
            svc = fingerprint_banner(banner or "", p)
            results[p] = {"banner": banner, "service": svc}
    return results


# ------------------------------------------------------------------
# Interactive REPL
# ------------------------------------------------------------------
def repl():
    help_text = """
PS's tool interactive REPL commands:
  help
      Show this help.

  scan common <host>
      Quick scan common ports on <host>.

  scan range <host> <start> <end>
      Scan a numeric range on <host>.

  enrich <host> <p1,p2,p3>
      Grab banners & fingerprint given comma-separated ports.

  enrich-open <host>
      Run quick common scan then enrich the open ports.

  connect <host> <port>
      Connect as client (interactive).

  listen <port>
      Start server listener on port.

  quit / exit
      Exit the REPL.
"""
    print(help_text)
    while True:
        try:
            cmd = input("PS> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        parts = cmd.split()
        if parts[0] in ("quit", "exit"):
            break
        if parts[0] == "help":
            print(help_text); continue
        if parts[0] == "scan" and len(parts) >= 3:
            mode = parts[1]
            if mode == "common" and len(parts) == 3:
                host = parts[2]
                print(f"[+] Scanning common ports on {host}...")
                res = scan_common_ports(host)
                print("Open:", res["open"])
                print("Closed:", res["closed"])
                print("Filtered:", res["filtered"])
            elif mode == "range" and len(parts) == 5:
                _, _, host, start_s, end_s = parts
                try:
                    start = int(start_s); end = int(end_s)
                except ValueError:
                    print("[!] start/end must be integers"); continue
                print(f"[+] Scanning {host}:{start}-{end} ...")
                res = scan_ports(host, start=start, end=end)
                print("Open:", res["open"])
            else:
                print("[!] Invalid scan command. See 'help'.")
            continue
        if parts[0] == "enrich" and len(parts) == 3:
            host = parts[1]
            ports = [int(x.strip()) for x in parts[2].split(",") if x.strip().isdigit()]
            if not ports:
                print("[!] No valid ports provided.")
                continue
            print(f"[+] Enriching {host} ports {ports} ...")
            info = enrich_open_ports_with_services(host, ports)
            for p in sorted(info):
                print(f"{host}:{p} -> {info[p]['service']}  banner: {info[p]['banner']!r}")
            continue
        if parts[0] == "enrich-open" and len(parts) == 2:
            host = parts[1]
            print(f"[+] Scanning common ports on {host} ...")
            res = scan_common_ports(host)
            open_ports = res["open"]
            print("[+] Enriching open ports:", open_ports)
            info = enrich_open_ports_with_services(host, open_ports)
            for p in sorted(info):
                print(f"{host}:{p} -> {info[p]['service']}  banner: {info[p]['banner']!r}")
            continue
        if parts[0] == "connect" and len(parts) == 3:
            host = parts[1]; port = int(parts[2])
            print(f"[+] Connecting to {host}:{port} (type Ctrl-D to end input) ...")
            client_mode(host, port)
            continue
        if parts[0] == "listen" and len(parts) == 2:
            port = int(parts[1])
            print(f"[+] Starting server on 0.0.0.0:{port} (Ctrl-C to stop)")
            server_mode(port)
            continue
        print("[!] Unknown command. Type 'help' for commands.")


# ------------------------------------------------------------------
# Main (CLI + scan integration)
# ------------------------------------------------------------------
def main():
    print_banner()
    args = parse_args()

    if args.man:
        print_man()
        return

    if args.verbose:
        print("[DEBUG] parsed args:", args)

    # if no args and no options provided, enter REPL
    # detect only if script invoked without positional host/port and no scan/listen flags
    invoked_with_no_action = not any([args.scan, args.scan_range, args.listen, args.host, args.port, args.send_file, args.output_file])
    if invoked_with_no_action:
        print("[*] No CLI action requested — entering interactive REPL (type 'help').")
        repl()
        return

    # Scanning options (run first if requested)
    if args.scan:
        host = args.scan
        if args.verbose:
            print("[DEBUG] running --scan on host:", host)
        print(f"[+] Scanning common ports on {host} (timeout={args.scan_timeout}, threads={args.scan_threads}) ...")
        res = scan_common_ports(host, timeout=args.scan_timeout, threads=args.scan_threads)
        print("[+] Scan finished. Results:")
        print("  Open:    ", res["open"])
        print("  Closed:  ", res["closed"])
        print("  Filtered:", res["filtered"])

        # enrich automatically for convenience
        if res["open"]:
            print("[+] Enriching open ports (banner grab + fingerprint)...")
            info = enrich_open_ports_with_services(host, res["open"], timeout=max(0.8, args.scan_timeout), threads=min(30, args.scan_threads))
            for p in sorted(info):
                print(f"{host}:{p} -> {info[p]['service']}  banner: {info[p]['banner']!r}")
        return

    if args.scan_range:
        try:
            host_part, start, end = parse_range_arg(args.scan_range)
            if host_part is None:
                print("error: scan-range requires host:START-END or provide host separately")
                return
            if args.verbose:
                print(f"[DEBUG] running --scan-range on {host_part}:{start}-{end}")
            print(f"[+] Scanning {host_part}:{start}-{end} (timeout={args.scan_timeout}, threads={args.scan_threads}) ...")
            res = scan_ports(host_part, start=start, end=end, timeout=args.scan_timeout, threads=args.scan_threads)
            print("[+] Scan finished. Results:")
            print("  Open:    ", res["open"])
            print("  Closed:  ", res["closed"])
            print("  Filtered:", res["filtered"])

            if res["open"]:
                print("[+] Enriching open ports...")
                info = enrich_open_ports_with_services(host_part, res["open"], timeout=max(0.8, args.scan_timeout), threads=min(40, args.scan_threads))
                for p in sorted(info):
                    print(f"{host_part}:{p} -> {info[p]['service']}  banner: {info[p]['banner']!r}")
        except Exception as e:
            print(f"[!] scan-range parse/error: {e}")
        return

    # Normal netcat behavior
    if args.listen:
        if not args.host:
            print("error: port required in listen mode")
            sys.exit(1)
        server_mode(int(args.host), keep=args.keep, output_file=args.output_file)
    else:
        if not args.host or not args.port:
            print("error: host and port required for client mode")
            sys.exit(1)
        client_mode(args.host, args.port, send_file=args.send_file)


if __name__ == "__main__":
    main()
