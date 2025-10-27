#!/usr/bin/env python3
import argparse
import socket
import threading
import sys
from pathlib import Path

BUFFER_SIZE = 4096

# ─────────────────────────────
# Banner
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
                while chunk := f.read(BUFFER_SIZE):
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
        sock.close()
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
    client_sock.close()
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
        server.close()


# ─────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="mini_nc",
        description="mini netcat (safe) - send/receive data over TCP"
    )
    p.add_argument("-l", "--listen", action="store_true", help="listen mode (server)")
    p.add_argument("-k", "--keep", action="store_true", help="keep listening after client disconnect")
    p.add_argument("--send-file", "-sf", dest="send_file", help="(client) send this file and exit")
    p.add_argument("--output-file", "-of", dest="output_file", help="(server) write received bytes to this file (append)")
    p.add_argument("host", nargs="?", help="host (client mode) or port (listen mode if -l)")
    p.add_argument("port", nargs="?", type=int, help="port (client mode)")
    return p.parse_args()
#Port Scanner:-

def is_port_open(host:str,port:int,timeout:float=0.5)-> str:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host,port))
        return "open :)"
    except ConnectionRefusedError:
        return "closed :("
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"
    finally:
        try:
            s.close()
        except Exception:
            pass

from concurrent.futures import ThreadPoolExecutor, as_completed
def scan_port_range(host:str,start:int,end:int,timeout:float=0.5,threads:int=100):
    results={"open":[],"closed":[],"filtered":[]}
    port=range(start,end+1)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_port={ex.submit(is_port_open,host,p,timeout):p for p in port}
        for future in as_completed(future_to_port):
            port=future_to_port[future]
            try:
                status=future.result()
            except Exception as e:
                status="filtered"

            results[status].append(port)
        
    for k in results:
        results[k].sort()
    return results

COMMON_PORTS=[21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080]

def scan_common_ports(host,timeout=0.5,threads=50):
    return scan_port_list(host,COMMON_PORTS,timeout,threads)



## I will include everything in Main function at last.
# ─────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────
def main():
    print_banner()
    args = parse_args()

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
