#!/usr/bin/env python3
import argparse
import socket
import threading
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BUFFER_SIZE = 4096

# ─────────────────────────────
# Banner & Manual
# ─────────────────────────────
def print_banner():
    banner = r"""
  ____ 
 |  _ \
 | |_) |
 |  __/
 |_|    
 (Creating something...)
"""
    print(banner)

def print_man():
    man = r"""
NAME
    mini_nc - minimal netcat-like tool + port scanner

SYNOPSIS
    mini_nc [OPTIONS] [host] [port]
    mini_nc --scan HOST
    mini_nc --scan-range HOST:START-END
    mini_nc -l PORT [--keep] [--output-file FILE]

DESCRIPTION
    mini_nc is a small TCP client/server program with an integrated threaded port scanner.
    It supports:
      • interactive TCP client (stdin -> socket -> stdout)
      • TCP server (listen and accept clients; optional file receive)
      • file send / receive
      • quick common-ports scan and numeric-range scan

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
    python3 mini_nc.py -l 5000
    python3 mini_nc.py 127.0.0.1 5000
    python3 mini_nc.py 127.0.0.1 5000 --send-file file.bin
    python3 mini_nc.py --scan 192.168.1.10
    python3 mini_nc.py --scan-range 192.168.1.10:1-1024

SAFETY
    Only scan hosts/networks you own or have explicit permission to test.
    Unauthorized scanning may be illegal and may trigger intrusion detection.
"""
    print(man)


# ─────────────────────────────
# Forward socket → stdout
# ─────────────────────────────
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


# ─────────────────────────────
# Forward stdin → socket
# ─────────────────────────────
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


# ─────────────────────────────
# CLIENT MODE
# ─────────────────────────────
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

        # interactive chat mode
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


# ─────────────────────────────
# SERVER MODE: handle one client
# ─────────────────────────────
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


# ─────────────────────────────
# SERVER MODE: listen & accept clients
# ─────────────────────────────
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


# ─────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="mini_nc",
        description="mini netcat (safe) - send/receive data over TCP and scan ports"
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


# ─────────────────────────────
# Port Scanner (unified)
# ─────────────────────────────
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


# ─────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────
def main():
    print_banner()
    args = parse_args()

    if args.man:
        print_man()
        return

    if args.verbose:
        print("[DEBUG] parsed args:", args)

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
