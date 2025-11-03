import socket
def grab_banner(host, port, timeout=0.5, recv_bytes=1024):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            b = s.recv(recv_bytes)
            if b:
                return b.decode(errors='replace').strip()
        except socket.timeout:
            pass
        # HTTP probe
        try:
            s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            b = s.recv(recv_bytes)
            return b.decode(errors='replace').strip() if b else ""
        except Exception:
            return ""
    except Exception:
        return ""
    finally:
        try: s.close()
        except: pass
