#!/usr/bin/env python3
"""
Minimal DNS (UDP) lab server: parses RFC 1035-style queries and logs QNAME.
Responds with NOERROR + empty answer so resolvers do not retry indefinitely.
For authorized security testing / lab pairing with 1.py DNS tunnel client only.
"""
from __future__ import annotations

import argparse
import socket
import struct
from typing import Optional, Tuple


def _read_name(buf: bytes, off: int) -> Tuple[str, int]:
    labels = []
    jumped = False
    jump = off
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        length = buf[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                jump = off + 2
                jumped = True
            off = ptr
            continue
        off += 1
        labels.append(buf[off : off + length].decode("ascii", errors="replace"))
        off += length
    return ".".join(labels), jump if jumped else off


def parse_query(data: bytes) -> Optional[Tuple[int, str, int, int]]:
    """Return (transaction_id, qname, qtype, qclass) or None."""
    if len(data) < 12:
        return None
    tid, flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount < 1:
        return None
    off = 12
    qname, off = _read_name(data, off)
    if off + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[off : off + 4])
    return tid, qname, qtype, qclass


def build_response(request: bytes) -> bytes:
    """Echo question section; NOERROR with zero answers (valid minimal response)."""
    if len(request) < 12:
        return b""
    tid, _flags_in, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", request[:12])
    flags_out = 0x8180
    header = struct.pack("!HHHHHH", tid, flags_out, qd, 0, 0, 0)
    return header + request[12:]


def main() -> None:
    ap = argparse.ArgumentParser(description="Lab DNS UDP listener")
    ap.add_argument("--bind", default="127.0.0.1", help="Bind address")
    ap.add_argument("--port", type=int, default=5353, help="UDP port")
    args = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print(f"[dns_tunnel_server] listening on udp://{args.bind}:{args.port}")
    while True:
        data, addr = sock.recvfrom(4096)
        parsed = parse_query(data)
        if parsed is None:
            print(f"[dns_tunnel_server] short/invalid packet from {addr} len={len(data)}")
            continue
        tid, qname, qtype, qclass = parsed
        print(f"[dns_tunnel_server] from={addr} id={tid:#06x} QNAME={qname!r} QTYPE={qtype} QCLASS={qclass}")
        sock.sendto(build_response(data), addr)


if __name__ == "__main__":
    main()
